// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use pm_crypto::KdfProfile;
use pm_vault::{HumanChannel, HumanCommitError, HumanVault, PasswordRecord, PendingVault};
use rusqlite::Connection;

const PASSWORD: &[u8] = b"synthetic ticket 04 master password";
const SECRET_ONE: &[u8] = b"synthetic ticket 04 password one";
const SECRET_TWO: &[u8] = b"synthetic ticket 04 password two";
const DEVICE: [u8; 16] = [0x44; 16];
static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
fn password_crud_uses_signed_prepare_commit_and_durable_receipts() {
    let directory = TestDir::new();
    let path = directory.vault();
    persist_test_vault(&path);
    let (mut vault, _peer) = open_human(&path);

    let create = vault
        .prepare_create(&record("Synthetic account", SECRET_ONE))
        .expect("prepare encrypted create");
    assert!(vault.read_password(*create.item_id()).is_err());
    let signature = vault.sign(&create).expect("sign create with SK_H");
    let created = vault
        .commit(create.command(), &signature, create.body())
        .expect("atomic create");
    assert_eq!(created, vault.receipt(*create.transaction_id()).unwrap());

    let opened = vault.read_password(*create.item_id()).expect("human read");
    assert_eq!(opened.title(), "Synthetic account");
    assert_eq!(opened.username(), "synthetic-user");
    assert_eq!(opened.password(), SECRET_ONE);
    assert_eq!(opened.destination(), "https://synthetic.invalid/login");

    let edit = vault
        .prepare_edit(
            *create.item_id(),
            &record("Synthetic account 2", SECRET_TWO),
        )
        .expect("prepare encrypted edit");
    let edited = vault
        .commit(edit.command(), &vault.sign(&edit).unwrap(), edit.body())
        .expect("atomic edit");
    assert_eq!(edited.outcome(), "committed");
    let opened = vault.read_password(*create.item_id()).unwrap();
    assert_eq!(opened.title(), "Synthetic account 2");
    assert_eq!(opened.password(), SECRET_TWO);

    let delete = vault.prepare_delete(*create.item_id()).unwrap();
    vault
        .commit(
            delete.command(),
            &vault.sign(&delete).unwrap(),
            delete.body(),
        )
        .expect("atomic delete");
    assert!(matches!(
        vault.read_password(*create.item_id()),
        Err(HumanCommitError::ItemNotFound)
    ));

    let connection = Connection::open(&path).unwrap();
    assert_eq!(count(&connection, "human_receipts"), 3);
    assert_eq!(count(&connection, "authority_events"), 3);
    assert_eq!(count(&connection, "outbox"), 3);
    assert_eq!(count(&connection, "encrypted_audit_records"), 3);
    assert_eq!(count(&connection, "audit_keys"), 1);
    drop(connection);

    for entry in fs::read_dir(&directory.0).unwrap() {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        assert!(!contains(&bytes, SECRET_ONE));
        assert!(!contains(&bytes, SECRET_TWO));
    }
}

#[test]
fn changed_body_expired_challenge_false_peer_and_replay_are_rejected() {
    let directory = TestDir::new();
    let path = directory.vault();
    persist_test_vault(&path);

    let (server, _client) = UnixStream::pair().unwrap();
    let false_uid = unsafe { libc::geteuid() }.wrapping_add(1);
    assert!(HumanChannel::authenticate(server, false_uid).is_err());
    let (server, client) = UnixStream::pair().unwrap();
    let uid = unsafe { libc::geteuid() };
    let channel = HumanChannel::authenticate(server, uid).unwrap();
    let mut disconnected = HumanVault::unlock(&path, PASSWORD, DEVICE, channel).unwrap();
    drop(client);
    assert!(matches!(
        disconnected.prepare_create(&record("Disconnected", SECRET_ONE)),
        Err(HumanCommitError::WrongChannel)
    ));

    let (mut vault, _peer) = open_human(&path);
    let prepare_started_us = now_us();
    let prepared = vault
        .prepare_create(&record("Changed body", SECRET_ONE))
        .unwrap();
    let expires_at_us: i64 = Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT expires_at_us FROM human_challenges WHERE transaction_id=?1",
            [prepared.transaction_id().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(expires_at_us >= prepare_started_us + 60_000_000);
    assert!(expires_at_us <= now_us() + 60_000_000);
    let signature = vault.sign(&prepared).unwrap();
    let mut changed_body = prepared.body().to_vec();
    *changed_body.last_mut().unwrap() ^= 1;
    assert!(matches!(
        vault.commit(prepared.command(), &signature, &changed_body),
        Err(HumanCommitError::BodyChanged)
    ));
    assert!(vault.read_password(*prepared.item_id()).is_err());

    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE human_challenges SET expires_at_us = 0 WHERE transaction_id = ?1",
            [prepared.transaction_id().as_slice()],
        )
        .unwrap();
    assert!(matches!(
        vault.commit(prepared.command(), &signature, prepared.body()),
        Err(HumanCommitError::ChallengeExpired)
    ));

    let fresh = vault.prepare_create(&record("Replay", SECRET_TWO)).unwrap();
    let signature = vault.sign(&fresh).unwrap();
    let first = vault
        .commit(fresh.command(), &signature, fresh.body())
        .unwrap();
    let replay = vault
        .commit(fresh.command(), &signature, fresh.body())
        .expect("same transaction and body recovers receipt");
    assert_eq!(first, replay);
    assert_eq!(count(&Connection::open(&path).unwrap(), "vault_items"), 1);
}

#[test]
fn audit_failure_rolls_back_every_commit_part_and_lost_response_recovers_receipt() {
    let directory = TestDir::new();
    let path = directory.vault();
    persist_test_vault(&path);
    let (mut vault, _peer) = open_human(&path);
    let prepared = vault.prepare_create(&record("Atomic", SECRET_ONE)).unwrap();
    let signature = vault.sign(&prepared).unwrap();

    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_audit BEFORE INSERT ON encrypted_audit_records
             BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END;",
        )
        .unwrap();
    assert!(matches!(
        vault.commit(prepared.command(), &signature, prepared.body()),
        Err(HumanCommitError::Storage(_))
    ));
    let connection = Connection::open(&path).unwrap();
    for table in [
        "vault_items",
        "revision_parts",
        "authority_events",
        "outbox",
        "human_receipts",
        "audit_keys",
        "audit_state",
        "encrypted_audit_records",
    ] {
        assert_eq!(count(&connection, table), 0, "partial write in {table}");
    }
    assert_eq!(count_where_consumed(&connection), 0);
    connection.execute("DROP TRIGGER fail_audit", []).unwrap();
    drop(connection);

    let receipt = vault
        .commit(prepared.command(), &signature, prepared.body())
        .expect("retry after no-op failure");
    drop(vault); // models response loss after SQLite committed durably
    let (vault, _peer) = open_human(&path);
    assert_eq!(vault.receipt(*prepared.transaction_id()).unwrap(), receipt);
}

#[test]
fn invalid_signature_and_stale_expected_state_cannot_publish_staging() {
    let directory = TestDir::new();
    let path = directory.vault();
    persist_test_vault(&path);
    let (mut vault, _peer) = open_human(&path);
    let stale = vault.prepare_create(&record("Stale", SECRET_ONE)).unwrap();
    let winner = vault.prepare_create(&record("Winner", SECRET_TWO)).unwrap();

    let mut invalid_signature = vault.sign(&winner).unwrap();
    invalid_signature[0] ^= 1;
    assert!(matches!(
        vault.commit(winner.command(), &invalid_signature, winner.body()),
        Err(HumanCommitError::InvalidSignature)
    ));
    vault
        .commit(
            winner.command(),
            &vault.sign(&winner).unwrap(),
            winner.body(),
        )
        .unwrap();
    assert!(matches!(
        vault.commit(stale.command(), &vault.sign(&stale).unwrap(), stale.body()),
        Err(HumanCommitError::StateChanged)
    ));
    assert!(vault.read_password(*stale.item_id()).is_err());
}

fn record(title: &str, password: &[u8]) -> PasswordRecord {
    PasswordRecord::new(
        title,
        "synthetic-user",
        password,
        "https://synthetic.invalid/login",
        "synthetic note",
    )
    .unwrap()
}

fn open_human(path: &Path) -> (HumanVault, UnixStream) {
    let (server, client) = UnixStream::pair().unwrap();
    let uid = unsafe { libc::geteuid() };
    let channel = HumanChannel::authenticate(server, uid).expect("kernel-authenticated peer");
    (
        HumanVault::unlock(path, PASSWORD, DEVICE, channel).expect("unlock human vault"),
        client,
    )
}

fn persist_test_vault(path: &Path) {
    let pending =
        PendingVault::new(PASSWORD, KdfProfile::confirmed(64, 3).unwrap()).expect("prepare vault");
    let confirmation = pending.recovery_code().to_string().parse().unwrap();
    pending.persist(path, &confirmation).expect("persist vault");
}

fn count(connection: &Connection, table: &str) -> i64 {
    connection
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn count_where_consumed(connection: &Connection) -> i64 {
    connection
        .query_row(
            "SELECT count(*) FROM human_challenges WHERE consumed = 1",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn now_us() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "pm-ticket-04-{}-{}",
            process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn vault(&self) -> PathBuf {
        self.0.join("vault.sqlite3")
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
