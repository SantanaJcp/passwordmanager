// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use pm_crypto::KdfProfile;
use pm_vault::{
    AuditAction, AuditActorKind, AuditDeviceCustody, AuditEvent, AuditOutcome,
    AutonomousAuditVault, HumanChannel, HumanVault, PasswordRecord, PendingVault,
};
use rusqlite::Connection;

const PASSWORD: &[u8] = b"synthetic ticket 06 master password";
const SECRET: &[u8] = b"synthetic ticket 06 credential payload";
const DEVICE: [u8; 16] = [0x66; 16];
const AGENT: [u8; 16] = [0xa6; 16];
const ATTEMPT: [u8; 16] = [0x16; 16];
static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
fn empty_vault_unlock_initializes_audit_once_and_enables_autonomous_lock() {
    let directory = StrictAuditTestDir::new();
    let path = directory.vault();
    persist_test_vault(&path);
    let custody = Arc::new(AuditDeviceCustody::generate().unwrap());

    let (wrong_server, wrong_peer) = UnixStream::pair().unwrap();
    let uid = unsafe { libc::geteuid() };
    let wrong_channel = HumanChannel::authenticate(wrong_server, uid).unwrap();
    assert!(
        HumanVault::unlock_with_audit_custody(
            &path,
            b"synthetic definitely wrong",
            DEVICE,
            wrong_channel,
            Arc::clone(&custody),
        )
        .is_err()
    );
    drop(wrong_peer);
    for table in [
        "audit_keys",
        "audit_state",
        "audit_segments",
        "audit_manifests",
        "encrypted_audit_records",
    ] {
        assert_eq!(count(&path, table), 0, "wrong password wrote {table}");
    }

    let (human, peer) = open_human(&path, Arc::clone(&custody));
    let query = human.query_audit(DEVICE, 1, 1, 16).unwrap();
    assert_eq!(query.records().len(), 1);
    assert_eq!(query.records()[0].actor_kind(), AuditActorKind::Human);
    assert_eq!(query.records()[0].action(), AuditAction::HumanUnlock);
    assert_eq!(query.records()[0].outcome(), AuditOutcome::Succeeded);
    assert_eq!(count(&path, "audit_keys"), 1);

    let replacement_custody = Arc::new(AuditDeviceCustody::generate().unwrap());
    let (replacement_server, replacement_peer) = UnixStream::pair().unwrap();
    let replacement_channel = HumanChannel::authenticate(replacement_server, uid).unwrap();
    assert!(
        HumanVault::unlock_with_audit_custody(
            &path,
            PASSWORD,
            DEVICE,
            replacement_channel,
            replacement_custody,
        )
        .is_err(),
        "custody mismatch rotated the audit key during unlock"
    );
    drop(replacement_peer);
    assert_eq!(count(&path, "audit_keys"), 1);

    drop(human);
    drop(peer);
    let mut autonomous = AutonomousAuditVault::open(&path, DEVICE, Arc::clone(&custody)).unwrap();
    autonomous
        .append(&AuditEvent::new(
            AuditActorKind::System,
            None,
            AuditAction::HumanLock,
            AuditOutcome::Succeeded,
        ))
        .unwrap();
    drop(autonomous);

    let (human, _peer) = open_human(&path, custody);
    let query = human.query_audit(DEVICE, 1, 1, 16).unwrap();
    let actions: Vec<_> = query
        .records()
        .iter()
        .map(|record| record.action())
        .collect();
    assert_eq!(
        actions,
        [
            AuditAction::HumanUnlock,
            AuditAction::HumanLock,
            AuditAction::HumanUnlock,
        ]
    );
    assert!(
        query
            .records()
            .iter()
            .all(|record| record.outcome() == AuditOutcome::Succeeded)
    );
}

#[test]
fn first_unlock_audit_failure_rolls_back_initial_package_and_session() {
    let directory = StrictAuditTestDir::new();
    let path = directory.vault();
    persist_test_vault(&path);
    let custody = Arc::new(AuditDeviceCustody::generate().unwrap());
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER reject_first_unlock_audit BEFORE INSERT ON encrypted_audit_records
             BEGIN SELECT RAISE(ABORT, 'synthetic first unlock audit failure'); END;",
        )
        .unwrap();
    drop(connection);

    let (server, peer) = UnixStream::pair().unwrap();
    let uid = unsafe { libc::geteuid() };
    let channel = HumanChannel::authenticate(server, uid).unwrap();
    assert!(
        HumanVault::unlock_with_audit_custody(&path, PASSWORD, DEVICE, channel, custody).is_err(),
        "unlock returned a session without its required audit record"
    );
    drop(peer);
    for table in [
        "audit_keys",
        "audit_state",
        "audit_segments",
        "audit_manifests",
        "encrypted_audit_records",
    ] {
        assert_eq!(count(&path, table), 0, "failed unlock left {table}");
    }
}

#[test]
fn device_custody_writes_signed_encrypted_audit_without_human_root() {
    let directory = TestDir::new();
    let path = directory.vault();
    persist_test_vault(&path);
    let custody = Arc::new(AuditDeviceCustody::generate().expect("device custody"));

    let (mut human, peer) = open_human(&path, Arc::clone(&custody));
    let prepared = human.prepare_create(&record()).unwrap();
    let item = *prepared.item_id();
    human
        .commit(
            prepared.command(),
            &human.sign(&prepared).unwrap(),
            prepared.body(),
        )
        .unwrap();
    drop(human);
    drop(peer);

    let mut autonomous = AutonomousAuditVault::open(&path, DEVICE, Arc::clone(&custody)).unwrap();
    autonomous
        .append(
            &AuditEvent::new(
                AuditActorKind::Agent,
                Some(AGENT),
                AuditAction::AuthUse,
                AuditOutcome::Indeterminate,
            )
            .with_item(item, None)
            .with_attempt(ATTEMPT),
        )
        .expect("autonomous audit with device-held KAUD/SK_SD");
    drop(autonomous);

    let (human, _peer) = open_human(&path, custody);
    let query = human.query_audit(DEVICE, 1, 1, 16).unwrap();
    assert_eq!(query.records().len(), 2);
    assert_eq!(query.records()[0].actor_kind(), AuditActorKind::Human);
    assert_eq!(query.records()[0].action(), AuditAction::ItemChange);
    assert_eq!(query.records()[0].item_id(), Some(&item));
    assert_eq!(query.records()[1].actor_kind(), AuditActorKind::Agent);
    assert_eq!(query.records()[1].actor_id(), Some(&AGENT));
    assert_eq!(query.records()[1].action(), AuditAction::AuthUse);
    assert_eq!(query.records()[1].outcome(), AuditOutcome::Indeterminate);
    assert_eq!(query.records()[1].item_id(), Some(&item));
    assert_eq!(query.records()[1].attempt_id(), Some(&ATTEMPT));

    for entry in fs::read_dir(&directory.0).unwrap() {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        assert!(!contains(&bytes, SECRET));
    }
}

#[test]
fn failure_is_atomic_and_human_purge_leaves_a_visible_gap_without_erasing_authority() {
    let directory = TestDir::new();
    let path = directory.vault();
    persist_test_vault(&path);
    let custody = Arc::new(AuditDeviceCustody::generate().unwrap());
    let (mut human, _peer) = open_human(&path, Arc::clone(&custody));
    let prepared = human.prepare_create(&record()).unwrap();
    human
        .commit(
            prepared.command(),
            &human.sign(&prepared).unwrap(),
            prepared.body(),
        )
        .unwrap();
    drop(human);

    let mut autonomous = AutonomousAuditVault::open(&path, DEVICE, Arc::clone(&custody)).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER reject_ticket06_audit BEFORE INSERT ON encrypted_audit_records
             BEGIN SELECT RAISE(ABORT, 'synthetic audit storage failure'); END;",
        )
        .unwrap();
    let state_before: (i64, Vec<u8>) = connection
        .query_row(
            "SELECT seq,last_hash FROM audit_state WHERE device_id=?1",
            [DEVICE.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert!(
        autonomous
            .append(&AuditEvent::new(
                AuditActorKind::Custodian,
                None,
                AuditAction::ProfileFault,
                AuditOutcome::Failed,
            ))
            .is_err()
    );
    let state_after: (i64, Vec<u8>) = connection
        .query_row(
            "SELECT seq,last_hash FROM audit_state WHERE device_id=?1",
            [DEVICE.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(state_before, state_after);
    connection
        .execute("DROP TRIGGER reject_ticket06_audit", [])
        .unwrap();
    drop(connection);
    autonomous
        .append(&AuditEvent::new(
            AuditActorKind::Agent,
            Some(AGENT),
            AuditAction::AuthAccepted,
            AuditOutcome::Accepted,
        ))
        .unwrap();
    drop(autonomous);

    let (mut human, _peer) = open_human(&path, custody);
    let authority_before = count(&path, "authority_events");
    let outbox_before = count(&path, "outbox");
    let purge = human.prepare_audit_purge(DEVICE, 1, 1).unwrap();
    assert_eq!(purge.scope().first_seq(), 1);
    assert_eq!(purge.scope().last_seq(), 1);
    assert_eq!(purge.scope().record_count(), 1);
    let prepared = purge.prepared();
    human
        .commit(
            prepared.command(),
            &human.sign(prepared).unwrap(),
            prepared.body(),
        )
        .unwrap();

    let query = human.query_audit(DEVICE, 1, 1, 16).unwrap();
    assert_eq!(query.discontinuities().len(), 1);
    assert_eq!(query.discontinuities()[0].first_seq(), 1);
    assert_eq!(query.discontinuities()[0].last_seq(), 1);
    assert!(
        query
            .records()
            .iter()
            .any(|record| record.action() == AuditAction::AuditPurge)
    );
    assert_eq!(count(&path, "authority_events"), authority_before + 1);
    assert_eq!(count(&path, "outbox"), outbox_before + 1);
    assert_eq!(count(&path, "vault_items"), 1);
}

#[test]
fn segment_rollover_occurs_before_the_257th_record() {
    let directory = TestDir::new();
    let path = directory.vault();
    persist_test_vault(&path);
    let custody = Arc::new(AuditDeviceCustody::generate().unwrap());
    let (mut human, _peer) = open_human(&path, Arc::clone(&custody));
    let prepared = human.prepare_create(&record()).unwrap();
    human
        .commit(
            prepared.command(),
            &human.sign(&prepared).unwrap(),
            prepared.body(),
        )
        .unwrap();
    drop(human);

    let mut autonomous = AutonomousAuditVault::open(&path, DEVICE, Arc::clone(&custody)).unwrap();
    for _ in 1..257 {
        autonomous
            .append(&AuditEvent::new(
                AuditActorKind::System,
                None,
                AuditAction::Startup,
                AuditOutcome::Succeeded,
            ))
            .unwrap();
    }
    drop(autonomous);
    let (human, _peer) = open_human(&path, custody);
    let query = human.query_audit(DEVICE, 1, 1, 4096).unwrap();
    assert_eq!(query.records().len(), 257);
    assert_eq!(query.segment_count(), 2);
    assert_eq!(query.closed_segment_count(), 1);
}

#[test]
fn query_rejects_a_locally_rolled_back_record_and_head() {
    let directory = TestDir::new();
    let path = directory.vault();
    persist_test_vault(&path);
    let custody = Arc::new(AuditDeviceCustody::generate().unwrap());
    let (mut human, _peer) = open_human(&path, Arc::clone(&custody));
    let prepared = human.prepare_create(&record()).unwrap();
    human
        .commit(
            prepared.command(),
            &human.sign(&prepared).unwrap(),
            prepared.body(),
        )
        .unwrap();
    drop(human);
    let mut autonomous = AutonomousAuditVault::open(&path, DEVICE, Arc::clone(&custody)).unwrap();
    autonomous
        .append(&AuditEvent::new(
            AuditActorKind::System,
            None,
            AuditAction::Startup,
            AuditOutcome::Succeeded,
        ))
        .unwrap();
    drop(autonomous);

    let connection = Connection::open(&path).unwrap();
    let first_hash: Vec<u8> = connection
        .query_row(
            "SELECT record_hash FROM encrypted_audit_records WHERE device_id=?1 AND generation=1 AND seq=1",
            [DEVICE.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute(
            "DELETE FROM encrypted_audit_records WHERE device_id=?1 AND generation=1 AND seq=2",
            [DEVICE.as_slice()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE audit_state SET seq=1,last_hash=?1 WHERE device_id=?2",
            rusqlite::params![first_hash, DEVICE.as_slice()],
        )
        .unwrap();
    drop(connection);

    let (human, _peer) = open_human(&path, custody);
    assert!(human.query_audit(DEVICE, 1, 1, 16).is_err());
}

#[test]
fn replacing_device_custody_opens_a_linked_audit_generation() {
    let directory = TestDir::new();
    let path = directory.vault();
    persist_test_vault(&path);
    let first_custody = Arc::new(AuditDeviceCustody::generate().unwrap());
    let (mut human, _peer) = open_human(&path, Arc::clone(&first_custody));
    let prepared = human.prepare_create(&record()).unwrap();
    human
        .commit(
            prepared.command(),
            &human.sign(&prepared).unwrap(),
            prepared.body(),
        )
        .unwrap();
    let prepared = human.prepare_create(&record()).unwrap();
    human
        .commit(
            prepared.command(),
            &human.sign(&prepared).unwrap(),
            prepared.body(),
        )
        .unwrap();
    drop(human);

    let second_custody = Arc::new(AuditDeviceCustody::generate().unwrap());
    let (mut human, _peer) = open_human(&path, second_custody);
    let prepared = human.prepare_create(&record()).unwrap();
    human
        .commit(
            prepared.command(),
            &human.sign(&prepared).unwrap(),
            prepared.body(),
        )
        .unwrap();

    let query = human.query_audit(DEVICE, 2, 1, 16).unwrap();
    assert_eq!(query.records().len(), 1);
    assert_eq!(query.records()[0].seq(), 1);
    let historical = human.query_audit(DEVICE, 1, 1, 16).unwrap();
    assert_eq!(historical.records().len(), 2);
    let purge = human.prepare_audit_purge(DEVICE, 1, 1).unwrap();
    human
        .commit(
            purge.prepared().command(),
            &human.sign(purge.prepared()).unwrap(),
            purge.prepared().body(),
        )
        .unwrap();
    let historical = human.query_audit(DEVICE, 1, 1, 16).unwrap();
    assert_eq!(historical.records().len(), 1);
    assert_eq!(historical.discontinuities().len(), 1);
    let connection = Connection::open(&path).unwrap();
    assert_eq!(count(&directory.vault(), "audit_keys"), 2);
    assert_eq!(count(&directory.vault(), "audit_manifests"), 2);
    assert_eq!(
        connection
            .query_row(
                "SELECT seq FROM audit_state WHERE device_id=?1 AND generation=2",
                [DEVICE.as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        2
    );
    assert!(AutonomousAuditVault::open(&path, DEVICE, first_custody).is_err());
}

#[test]
fn query_rejects_a_device_signing_key_not_bound_by_the_human_package() {
    let directory = TestDir::new();
    let path = directory.vault();
    persist_test_vault(&path);
    let custody = Arc::new(AuditDeviceCustody::generate().unwrap());
    let (mut human, _peer) = open_human(&path, custody);
    let prepared = human.prepare_create(&record()).unwrap();
    human
        .commit(
            prepared.command(),
            &human.sign(&prepared).unwrap(),
            prepared.body(),
        )
        .unwrap();

    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE audit_keys SET signing_public_key=?1 WHERE device_id=?2 AND generation=1",
            rusqlite::params![[0x91_u8; 32].as_slice(), DEVICE.as_slice()],
        )
        .unwrap();
    assert!(human.query_audit(DEVICE, 1, 1, 16).is_err());
}

fn record() -> PasswordRecord {
    PasswordRecord::new(
        "Synthetic ticket 06 account",
        "synthetic-ticket-06-user",
        SECRET,
        "https://ticket06.invalid/login",
        "synthetic ticket 06 note",
    )
    .unwrap()
}

fn open_human(path: &Path, custody: Arc<AuditDeviceCustody>) -> (HumanVault, UnixStream) {
    let (server, client) = UnixStream::pair().unwrap();
    let uid = unsafe { libc::geteuid() };
    let channel = HumanChannel::authenticate(server, uid).unwrap();
    (
        HumanVault::unlock_with_audit_custody(path, PASSWORD, DEVICE, channel, custody).unwrap(),
        client,
    )
}

fn persist_test_vault(path: &Path) {
    let pending = PendingVault::new(PASSWORD, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    let confirmation = pending.recovery_code().to_string().parse().unwrap();
    pending.persist(path, &confirmation).unwrap();
}

fn count(path: &Path, table: &str) -> i64 {
    Connection::open(path)
        .unwrap()
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

struct TestDir(PathBuf);

struct StrictAuditTestDir(PathBuf);

impl StrictAuditTestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "pm-ticket-27-audit-{}-{}",
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

impl Drop for StrictAuditTestDir {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("STRICT_TEST_CLEANUP_FAILED component=ticket27-audit-root error={error}");
            if std::thread::panicking() {
                process::abort();
            }
            panic!("ticket 27 audit fixture cleanup failed: {error}");
        }
    }
}

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "pm-ticket-06-{}-{}",
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
