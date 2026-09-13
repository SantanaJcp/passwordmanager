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
    AgentEnrollment, AgentPeer, AuditDeviceCustody, AuthorizationError, AuthorizationReason,
    DelegatedVault, HumanChannel, HumanVault, LogicalRecord, PendingVault, RecordKind,
};
use rusqlite::Connection;

const MASTER: &[u8] = b"synthetic ticket 07 master";
const DEVICE: [u8; 16] = [0x77; 16];
const AGENT_A: [u8; 16] = [0xa1; 16];
const AGENT_B: [u8; 16] = [0xb2; 16];
const REQUEST_A: [u8; 16] = [0x31; 16];
const REQUEST_B: [u8; 16] = [0x32; 16];
const RPK_A: [u8; 44] = [0x41; 44];
const RPK_A2: [u8; 44] = [0x42; 44];
const RPK_B: [u8; 44] = [0x51; 44];
const SECRET: &[u8] = b"synthetic-ticket-07-secret-canary";
const TITLE: &str = "Synthetic shared account";
static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
fn two_real_peer_identities_share_one_causal_enabled_set_after_human_lock_and_restart() {
    let directory = TestDir::new();
    let path = directory.vault();
    persist_test_vault(&path);
    let custody = Arc::new(AuditDeviceCustody::generate().unwrap());
    let (mut human, _peer) = open_human(&path, Arc::clone(&custody));

    let password = commit_create(&mut human, &password_record());
    let note = commit_create(&mut human, &note_record());
    enroll(&mut human, &enrollment(AGENT_A, REQUEST_A, &RPK_A), 1);
    enroll(&mut human, &enrollment(AGENT_B, REQUEST_B, &RPK_B), 1);
    let prepared = human.prepare_delegated_resume().unwrap();
    commit(&mut human, &prepared);
    let prepared = human.prepare_enable(password).unwrap();
    commit(&mut human, &prepared);
    assert!(matches!(
        human.prepare_enable(note),
        Err(AuthorizationError::CredentialUnavailable)
    ));
    drop(human); // locking the human root is not delegated suspension

    let agent_a = AgentPeer::from_transport_rpk(&RPK_A).unwrap();
    let agent_b = AgentPeer::from_transport_rpk(&RPK_B).unwrap();
    let delegated = DelegatedVault::open(&path, DEVICE, Arc::clone(&custody)).unwrap();
    let set_a = delegated.discover(&agent_a).unwrap();
    let set_b = delegated.discover(&agent_b).unwrap();
    assert_eq!(set_a, set_b);
    assert_eq!(set_a.len(), 1);
    assert_eq!(set_a[0].item_id(), &password);
    assert_eq!(set_a[0].title(), TITLE);
    assert_eq!(set_a[0].kind(), RecordKind::Password);
    assert_eq!(set_a[0].account(), Some("synthetic-ticket-07-user"));
    assert_eq!(
        set_a[0].destination(),
        Some("https://ticket-07.invalid/login")
    );
    assert_eq!(delegated.authorize(&agent_a, password).unwrap(), set_a[0]);
    assert!(matches!(
        delegated.authorize(&agent_a, note),
        Err(AuthorizationError::CredentialUnavailable)
    ));

    let connection = Connection::open(&path).unwrap();
    let package: Vec<u8> = connection
        .query_row(
            "SELECT control_package FROM credential_authorizations WHERE item_id=?1",
            [password.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let mut altered = package.clone();
    *altered.last_mut().unwrap() ^= 1;
    connection
        .execute(
            "UPDATE credential_authorizations SET control_package=?2 WHERE item_id=?1",
            rusqlite::params![password.as_slice(), altered],
        )
        .unwrap();
    assert!(matches!(
        delegated.authorize(&agent_a, password),
        Err(AuthorizationError::Integrity)
    ));
    connection
        .execute(
            "UPDATE credential_authorizations SET control_package=?2 WHERE item_id=?1",
            rusqlite::params![password.as_slice(), package],
        )
        .unwrap();
    drop(connection);

    let headers = delegated.authority_headers().unwrap();
    assert!(headers.len() >= 6);
    for (index, header) in headers.iter().enumerate() {
        assert_eq!(header.seq(), u64::try_from(index + 1).unwrap());
        if index == 0 {
            assert!(header.previous().is_none());
        } else {
            assert_eq!(header.previous(), Some(headers[index - 1].digest()));
            assert!(header.parents().contains(headers[index - 1].digest()));
        }
    }

    drop(delegated);
    let restarted = DelegatedVault::open(&path, DEVICE, custody).unwrap();
    assert_eq!(restarted.discover(&agent_a).unwrap(), set_a);
    for candidate in directory.files() {
        let bytes = fs::read(candidate).unwrap();
        assert!(!contains(&bytes, TITLE.as_bytes()));
        assert!(!contains(&bytes, SECRET));
    }
}

#[test]
fn suspension_and_individual_revocation_are_rechecked_and_generations_are_terminal() {
    let directory = TestDir::new();
    let path = directory.vault();
    persist_test_vault(&path);
    let custody = Arc::new(AuditDeviceCustody::generate().unwrap());
    let (mut human, _peer) = open_human(&path, Arc::clone(&custody));
    let item = commit_create(&mut human, &password_record());
    enroll(&mut human, &enrollment(AGENT_A, REQUEST_A, &RPK_A), 1);
    enroll(&mut human, &enrollment(AGENT_B, REQUEST_B, &RPK_B), 1);
    let prepared = human.prepare_delegated_resume().unwrap();
    commit(&mut human, &prepared);
    let prepared = human.prepare_enable(item).unwrap();
    commit(&mut human, &prepared);
    drop(human);

    let agent_a = AgentPeer::from_transport_rpk(&RPK_A).unwrap();
    let agent_b = AgentPeer::from_transport_rpk(&RPK_B).unwrap();
    let delegated = DelegatedVault::open(&path, DEVICE, Arc::clone(&custody)).unwrap();
    assert!(delegated.authorize(&agent_a, item).is_ok());

    let (mut human, _peer) = open_human(&path, Arc::clone(&custody));
    let prepared = human
        .prepare_delegated_suspend(AuthorizationReason::OwnerRequest)
        .unwrap();
    commit(&mut human, &prepared);
    assert!(matches!(
        delegated.authorize(&agent_a, item),
        Err(AuthorizationError::AccessSuspended)
    ));
    let prepared = human.prepare_delegated_resume().unwrap();
    commit(&mut human, &prepared);
    let prepared = human
        .prepare_agent_revocation(AGENT_A, AuthorizationReason::OwnerRequest)
        .unwrap();
    commit(&mut human, &prepared);
    assert!(matches!(
        delegated.discover(&agent_a),
        Err(AuthorizationError::AgentRevoked)
    ));
    assert_eq!(delegated.discover(&agent_b).unwrap().len(), 1);

    let replacement = enrollment(AGENT_A, [0x33; 16], &RPK_A2);
    enroll(&mut human, &replacement, 2);
    drop(human);
    assert!(matches!(
        delegated.discover(&agent_a),
        Err(AuthorizationError::AgentRevoked)
    ));
    let agent_a2 = AgentPeer::from_transport_rpk(&RPK_A2).unwrap();
    assert_eq!(delegated.discover(&agent_a2).unwrap().len(), 1);
    assert!(matches!(
        delegated.discover(&AgentPeer::from_transport_rpk(&[0x61; 44]).unwrap()),
        Err(AuthorizationError::Unauthorized)
    ));

    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT group_concat(generation, ',') FROM agent_authorizations \
                 WHERE subject_id=?1 ORDER BY generation",
                [AGENT_A.as_slice()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "1,2"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT status FROM agent_authorizations WHERE subject_id=?1 AND generation=1",
                [AGENT_A.as_slice()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "revoked"
    );
}

#[test]
fn failed_atomic_audit_write_cannot_publish_an_agent_grant() {
    let directory = TestDir::new();
    let path = directory.vault();
    persist_test_vault(&path);
    let custody = Arc::new(AuditDeviceCustody::generate().unwrap());
    let (mut human, _peer) = open_human(&path, custody);
    let prepared = human
        .prepare_agent_enrollment(&enrollment(AGENT_A, REQUEST_A, &RPK_A))
        .unwrap();
    let signature = human.sign(prepared.prepared()).unwrap();
    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_ticket07_audit BEFORE INSERT ON encrypted_audit_records
             BEGIN SELECT RAISE(ABORT, 'synthetic ticket 07 audit failure'); END;",
        )
        .unwrap();
    assert!(
        human
            .commit(
                prepared.prepared().command(),
                &signature,
                prepared.prepared().body()
            )
            .is_err()
    );
    let connection = Connection::open(&path).unwrap();
    assert_eq!(count(&connection, "agent_authorizations"), 0);
    assert_eq!(count(&connection, "authority_events"), 0);
    assert_eq!(count(&connection, "outbox"), 0);
    assert_eq!(count(&connection, "human_receipts"), 0);
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM human_challenges WHERE consumed=1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
}

fn enrollment(id: [u8; 16], request: [u8; 16], rpk: &[u8; 44]) -> AgentEnrollment {
    AgentEnrollment::new(
        id,
        request,
        rpk,
        "Synthetic agent",
        "synthetic-ticket-07-environment",
    )
    .unwrap()
}

fn enroll(human: &mut HumanVault, enrollment: &AgentEnrollment, generation: u64) {
    let prepared = human.prepare_agent_enrollment(enrollment).unwrap();
    assert_eq!(prepared.generation(), generation);
    commit(human, &prepared.into_prepared());
}

fn commit(human: &mut HumanVault, prepared: &pm_vault::PreparedHumanCommand) {
    let signature = human.sign(prepared).unwrap();
    human
        .commit(prepared.command(), &signature, prepared.body())
        .unwrap();
}

fn commit_create(human: &mut HumanVault, record: &LogicalRecord) -> [u8; 16] {
    let prepared = human.prepare_create_record(record).unwrap();
    let item = *prepared.item_id();
    commit(human, &prepared);
    item
}

fn password_record() -> LogicalRecord {
    use pm_vault::{AuthRecord, Destination, HumanMetadata};
    LogicalRecord::new(
        RecordKind::Password,
        HumanMetadata {
            title: TITLE.to_owned(),
            destinations: vec![Destination {
                label: "login".to_owned(),
                value: "https://ticket-07.invalid/login".to_owned(),
            }],
            tags: Vec::new(),
            favorite: false,
            notes: String::new(),
            fields: Vec::new(),
            source_fields: Vec::new(),
        },
        vec![AuthRecord::Password {
            username: "synthetic-ticket-07-user".to_owned(),
            password: SECRET.to_vec(),
            destination_refs: vec![0],
        }],
        Vec::new(),
    )
    .unwrap()
}

fn note_record() -> LogicalRecord {
    use pm_vault::HumanMetadata;
    LogicalRecord::new(
        RecordKind::Note,
        HumanMetadata {
            title: "Synthetic non-auth note".to_owned(),
            destinations: Vec::new(),
            tags: Vec::new(),
            favorite: false,
            notes: "not delegated".to_owned(),
            fields: Vec::new(),
            source_fields: Vec::new(),
        },
        Vec::new(),
        Vec::new(),
    )
    .unwrap()
}

fn open_human(path: &Path, custody: Arc<AuditDeviceCustody>) -> (HumanVault, UnixStream) {
    let (server, peer) = UnixStream::pair().unwrap();
    let channel = HumanChannel::authenticate(server, unsafe { libc::geteuid() }).unwrap();
    (
        HumanVault::unlock_with_audit_custody(path, MASTER, DEVICE, channel, custody).unwrap(),
        peer,
    )
}

fn persist_test_vault(path: &Path) {
    let pending = PendingVault::new(MASTER, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    let recovery = pending.recovery_code().to_string().parse().unwrap();
    pending.persist(path, &recovery).unwrap();
}

fn count(connection: &Connection, table: &str) -> i64 {
    connection
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

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "pm-ticket-07-{}-{}",
            process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn vault(&self) -> PathBuf {
        self.0.join("vault.sqlite3")
    }

    fn files(&self) -> impl Iterator<Item = PathBuf> {
        fs::read_dir(&self.0)
            .unwrap()
            .map(|entry| entry.unwrap().path())
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
