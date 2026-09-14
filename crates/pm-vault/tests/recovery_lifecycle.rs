// SPDX-License-Identifier: AGPL-3.0-only
#![cfg(target_os = "linux")]

use std::{
    fs,
    io::Cursor,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use pm_crypto::KdfProfile;
use pm_vault::{
    AgentEnrollment, AuditAction, AuthorizationReason, HumanChannel, HumanVault, PasswordRecord,
    PendingVault, open_vault,
};
use rusqlite::Connection;

const SOURCE_PASSWORD: &[u8] = b"synthetic ticket22 source master";
const TARGET_PASSWORD: &[u8] = b"synthetic ticket22 target master";
const ROTATED_PASSWORD: &[u8] = b"synthetic ticket22 rotated master";
const DEVICE: [u8; 16] = [0x22; 16];
static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
fn external_key_recovers_into_fresh_lineage_without_the_source_keyring() {
    let audit_custody = test_audit_custody();
    let dir = TestDir::new();
    let (source_path, source_recovery) = persist(&dir.0.join("source.sqlite3"), SOURCE_PASSWORD);
    let (mut source, _peer) = open_human(&source_path, SOURCE_PASSWORD, &audit_custody);
    let created = source
        .prepare_create(
            &PasswordRecord::new(
                "recovered",
                "human",
                b"ticket22-recovery-canary",
                "https://recovery.invalid",
                "",
            )
            .unwrap(),
        )
        .unwrap();
    commit(&mut source, &created);
    let mut archive = Vec::new();
    source.write_native_backup(&mut archive).unwrap();
    let source_root = *open_vault(&source_path, SOURCE_PASSWORD)
        .unwrap()
        .trusted_root();
    drop(source);
    fs::remove_file(&source_path).unwrap();

    let (target_path, target_recovery) = persist(&dir.0.join("target.sqlite3"), TARGET_PASSWORD);
    let target_root = *open_vault(&target_path, TARGET_PASSWORD)
        .unwrap()
        .trusted_root();
    assert_ne!(source_root, target_root);
    let (mut target, _peer) = open_human(&target_path, TARGET_PASSWORD, &audit_custody);
    let prepared = target
        .prepare_native_recovery(
            &mut Cursor::new(&archive),
            &source_recovery.parse().unwrap(),
        )
        .unwrap();
    let restored = prepared.item_ids()[0];
    commit(&mut target, prepared.prepared());
    assert_eq!(
        target.read_password(restored).unwrap().password(),
        b"ticket22-recovery-canary"
    );
    assert!(open_vault(&target_path, TARGET_PASSWORD).is_ok());
    assert!(
        pm_vault::BackupArchive::verify_with_recovery(
            &mut Cursor::new(&archive),
            &target_recovery.parse().unwrap(),
        )
        .is_err()
    );
}

#[test]
fn recovery_into_existing_vault_preserves_current_revocations_and_rejects_damage_atomically() {
    let audit_custody = test_audit_custody();
    let dir = TestDir::new();
    let (source_path, source_recovery) = persist(&dir.0.join("source.sqlite3"), SOURCE_PASSWORD);
    let (mut source, _peer) = open_human(&source_path, SOURCE_PASSWORD, &audit_custody);
    let created = source
        .prepare_create(
            &PasswordRecord::new(
                "source",
                "human",
                b"ticket22-source-canary",
                "https://source.invalid",
                "",
            )
            .unwrap(),
        )
        .unwrap();
    commit(&mut source, &created);
    let mut archive = Vec::new();
    source.write_native_backup(&mut archive).unwrap();

    let (target_path, _) = persist(&dir.0.join("target.sqlite3"), TARGET_PASSWORD);
    let (mut target, _peer) = open_human(&target_path, TARGET_PASSWORD, &audit_custody);
    let enrollment =
        AgentEnrollment::new([0x41; 16], [0x42; 16], &[0x43; 44], "revoked", "synthetic").unwrap();
    let prepared = target.prepare_agent_enrollment(&enrollment).unwrap();
    commit(&mut target, prepared.prepared());
    let revoked = target
        .prepare_agent_revocation([0x41; 16], AuthorizationReason::SuspectedCompromise)
        .unwrap();
    commit(&mut target, &revoked);
    let before = authority_snapshot(&target_path);

    let mut damaged = archive.clone();
    let middle = damaged.len() / 2;
    damaged[middle] ^= 1;
    assert!(
        target
            .prepare_native_recovery(&mut Cursor::new(damaged), &source_recovery.parse().unwrap())
            .is_err()
    );
    assert_eq!(authority_snapshot(&target_path), before);

    let prepared = target
        .prepare_native_recovery(&mut Cursor::new(archive), &source_recovery.parse().unwrap())
        .unwrap();
    commit(&mut target, prepared.prepared());
    let after = authority_snapshot(&target_path);
    assert_eq!(after.0, before.0);
    assert!(after.1 > before.1);
}

#[test]
#[allow(clippy::too_many_lines)]
fn signed_atomic_master_and_recovery_rotation_keep_access_and_invalidate_current_old_paths() {
    let audit_custody = test_audit_custody();
    let dir = TestDir::new();
    let (path, old_recovery) = persist(&dir.0.join("vault.sqlite3"), TARGET_PASSWORD);
    let trusted = *open_vault(&path, TARGET_PASSWORD).unwrap().trusted_root();
    let (mut vault, _peer) = open_human(&path, TARGET_PASSWORD, &audit_custody);
    let mut historical_backup = Vec::new();
    vault.write_native_backup(&mut historical_backup).unwrap();
    let stale_recovery = vault.begin_recovery_rotation().unwrap();
    let stale_code = stale_recovery.recovery_code().to_string();

    let password_change = vault
        .prepare_master_password_rotation(ROTATED_PASSWORD, KdfProfile::confirmed(64, 3).unwrap())
        .unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TRIGGER ticket22_fail_rotation_audit
         BEFORE INSERT ON encrypted_audit_records
         BEGIN SELECT raise(abort,'synthetic ticket22 audit failure'); END;",
    )
    .unwrap();
    drop(db);
    let signature = vault.sign(&password_change).unwrap();
    assert!(
        vault
            .commit(
                password_change.command(),
                &signature,
                password_change.body()
            )
            .is_err()
    );
    assert!(open_vault(&path, TARGET_PASSWORD).is_ok());
    assert!(open_vault(&path, ROTATED_PASSWORD).is_err());
    let db = Connection::open(&path).unwrap();
    db.execute_batch("DROP TRIGGER ticket22_fail_rotation_audit")
        .unwrap();
    drop(db);
    commit(&mut vault, &password_change);
    assert!(
        stale_recovery
            .confirm(&mut vault, &stale_code.parse().unwrap())
            .is_err()
    );
    assert!(open_vault(&path, TARGET_PASSWORD).is_err());
    assert_eq!(
        *open_vault(&path, ROTATED_PASSWORD).unwrap().trusted_root(),
        trusted
    );

    let pending = vault.begin_recovery_rotation().unwrap();
    let new_code = pending.recovery_code().to_string();
    let recovery_change = pending
        .confirm(&mut vault, &new_code.parse().unwrap())
        .unwrap();
    commit(&mut vault, &recovery_change);
    assert!(
        vault
            .verify_current_recovery(&old_recovery.parse().unwrap())
            .is_err()
    );
    assert!(
        vault
            .verify_current_recovery(&new_code.parse().unwrap())
            .is_ok()
    );
    assert_eq!(
        *open_vault(&path, ROTATED_PASSWORD).unwrap().trusted_root(),
        trusted
    );
    assert!(
        pm_vault::BackupArchive::verify_with_recovery(
            &mut Cursor::new(&historical_backup),
            &old_recovery.parse().unwrap(),
        )
        .is_ok()
    );
    assert!(
        pm_vault::BackupArchive::verify_with_recovery(
            &mut Cursor::new(&historical_backup),
            &new_code.parse().unwrap(),
        )
        .is_err()
    );
    assert!(
        pm_vault::BackupArchive::verify_with_password(
            &mut Cursor::new(&historical_backup),
            TARGET_PASSWORD,
        )
        .is_ok()
    );
    assert!(
        pm_vault::BackupArchive::verify_with_password(
            &mut Cursor::new(&historical_backup),
            ROTATED_PASSWORD,
        )
        .is_err()
    );
    let mut current_backup = Vec::new();
    vault.write_native_backup(&mut current_backup).unwrap();
    assert!(
        pm_vault::BackupArchive::verify_with_recovery(
            &mut Cursor::new(&current_backup),
            &old_recovery.parse().unwrap(),
        )
        .is_err()
    );
    assert!(
        pm_vault::BackupArchive::verify_with_recovery(
            &mut Cursor::new(&current_backup),
            &new_code.parse().unwrap(),
        )
        .is_ok()
    );

    let audit = vault.query_audit(DEVICE, 1, 1, 32).unwrap();
    assert_eq!(
        audit
            .records()
            .iter()
            .filter(|record| record.action() == AuditAction::Recovery)
            .count(),
        2
    );
}

#[test]
fn backup_rejects_a_malformed_existing_authority_frontier_instead_of_substituting_zero() {
    let audit_custody = test_audit_custody();
    let dir = TestDir::new();
    let (path, _) = persist(&dir.0.join("vault.sqlite3"), TARGET_PASSWORD);
    let (mut vault, _peer) = open_human(&path, TARGET_PASSWORD, &audit_custody);
    let enrollment =
        AgentEnrollment::new([0x51; 16], [0x52; 16], &[0x53; 44], "agent", "synthetic").unwrap();
    let prepared = vault.prepare_agent_enrollment(&enrollment).unwrap();
    commit(&mut vault, prepared.prepared());

    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "PRAGMA ignore_check_constraints=ON;
         UPDATE authority_events SET event_digest=x'00';",
    )
    .unwrap();
    drop(db);

    let mut output = Vec::new();
    assert!(matches!(
        vault.write_native_backup(&mut output),
        Err(pm_vault::HumanCommitError::Integrity)
    ));
}

fn authority_snapshot(path: &Path) -> (Vec<(Vec<u8>, i64, String)>, i64) {
    let db = Connection::open(path).unwrap();
    let mut statement = db.prepare("select subject_id,generation,status from agent_authorizations order by subject_id,generation").unwrap();
    let agents = statement
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let events = db
        .query_row("select count(*) from authority_events", [], |r| r.get(0))
        .unwrap();
    (agents, events)
}

fn commit(vault: &mut HumanVault, prepared: &pm_vault::PreparedHumanCommand) {
    let signature = vault.sign(prepared).unwrap();
    let committed = vault
        .commit(prepared.command(), &signature, prepared.body())
        .unwrap();
    let replayed = vault
        .commit(prepared.command(), &signature, prepared.body())
        .unwrap();
    assert_eq!(replayed.to_bytes(), committed.to_bytes());
    assert_eq!(
        vault
            .receipt(*prepared.transaction_id())
            .unwrap()
            .to_bytes(),
        committed.to_bytes()
    );
}

fn persist(path: &Path, password: &[u8]) -> (PathBuf, String) {
    let pending = PendingVault::new(password, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    let recovery = pending.recovery_code().to_string();
    pending.persist(path, &recovery.parse().unwrap()).unwrap();
    (path.to_owned(), recovery)
}

fn open_human(
    path: &Path,
    password: &[u8],
    audit_custody: &std::sync::Arc<pm_vault::AuditDeviceCustody>,
) -> (HumanVault, UnixStream) {
    let (server, peer) = UnixStream::pair().unwrap();
    let channel = HumanChannel::authenticate(server, unsafe { libc::geteuid() }).unwrap();
    (
        HumanVault::unlock(
            path,
            password,
            DEVICE,
            channel,
            std::sync::Arc::clone(audit_custody),
        )
        .unwrap(),
        peer,
    )
}

fn test_audit_custody() -> std::sync::Arc<pm_vault::AuditDeviceCustody> {
    std::sync::Arc::new(
        pm_vault::AuditDeviceCustody::generate().expect("synthetic device audit custody"),
    )
}

struct TestDir(PathBuf);
impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "pm-ticket22-{}-{}",
            process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
