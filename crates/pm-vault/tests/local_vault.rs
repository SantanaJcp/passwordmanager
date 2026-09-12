// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    fs,
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use pm_crypto::KdfProfile;
use pm_vault::{PendingVault, open_vault};
use rusqlite::Connection;

const PASSWORD: &[u8] = b"synthetic ticket 02 vault password";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "pm-ticket-02-{}-{}",
            process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create isolated test directory");
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

#[test]
fn persists_only_enveloped_roots_and_reopens_read_only_after_restart() {
    let directory = TestDir::new();
    let path = directory.vault();
    let pending =
        PendingVault::new(PASSWORD, KdfProfile::confirmed(64, 3).unwrap()).expect("prepare vault");
    let recovery = pending.recovery_code().to_string();
    let confirmation = recovery.parse().expect("reintroduce recovery code");
    let expected = *pending.trusted_root();

    pending
        .persist(&path, &confirmation)
        .expect("atomic persist");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let opened = open_vault(&path, PASSWORD).expect("open persisted vault");
    assert_eq!(opened.trusted_root(), &expected);

    let connection = Connection::open(&path).expect("inspect test database");
    assert_eq!(
        connection
            .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "wal"
    );
    let (kind, value): (String, Vec<u8>) = connection
        .query_row("SELECT kind, value FROM encrypted_objects", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    assert_eq!(kind, "human-root-bundle-v1");
    assert!(!contains(&value, PASSWORD));
    assert!(!contains(&value, recovery.as_bytes()));
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM encrypted_objects", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    for entry in fs::read_dir(&directory.0).unwrap() {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        assert!(!contains(&bytes, PASSWORD));
        assert!(!contains(&bytes, recovery.as_bytes()));
    }
}

#[test]
fn failures_and_a_second_create_never_modify_the_existing_bytes() {
    let directory = TestDir::new();
    let path = directory.vault();
    persist_test_vault(&path);

    let original = fs::read(&path).unwrap();
    assert!(open_vault(&path, b"synthetic wrong password").is_err());
    assert_eq!(fs::read(&path).unwrap(), original);

    let replacement = PendingVault::new(PASSWORD, KdfProfile::confirmed(64, 3).unwrap())
        .expect("prepare replacement");
    let confirmation = replacement.recovery_code().to_string().parse().unwrap();
    assert!(replacement.persist(&path, &confirmation).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);

    set_format_version(&path, 2);
    let incompatible = fs::read(&path).unwrap();
    assert!(open_vault(&path, PASSWORD).is_err());
    assert_eq!(fs::read(&path).unwrap(), incompatible);
}

#[test]
fn recovery_confirmation_and_ciphertext_integrity_fail_without_partial_publication() {
    let directory = TestDir::new();
    let rejected_path = directory.0.join("rejected.sqlite3");
    let pending = PendingVault::new(PASSWORD, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    let other = PendingVault::new(PASSWORD, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    let wrong_confirmation = other.recovery_code().to_string().parse().unwrap();
    assert!(
        pending
            .persist(&rejected_path, &wrong_confirmation)
            .is_err()
    );
    assert!(!rejected_path.exists());

    let path = directory.vault();
    persist_test_vault(&path);
    let connection = Connection::open(&path).unwrap();
    let mut encrypted: Vec<u8> = connection
        .query_row(
            "SELECT value FROM encrypted_objects WHERE kind = 'human-root-bundle-v1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    *encrypted.last_mut().unwrap() ^= 1;
    connection
        .execute(
            "UPDATE encrypted_objects SET value = ?1 WHERE kind = 'human-root-bundle-v1'",
            [&encrypted],
        )
        .unwrap();
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    drop(connection);
    let altered = fs::read(&path).unwrap();
    assert!(open_vault(&path, PASSWORD).is_err());
    assert_eq!(fs::read(&path).unwrap(), altered);
}

fn persist_test_vault(path: &Path) {
    let pending =
        PendingVault::new(PASSWORD, KdfProfile::confirmed(64, 3).unwrap()).expect("prepare vault");
    let confirmation = pending.recovery_code().to_string().parse().unwrap();
    pending.persist(path, &confirmation).expect("persist vault");
}

fn set_format_version(path: &Path, version: u64) {
    let connection = Connection::open(path).unwrap();
    connection
        .execute(
            "UPDATE vault_metadata SET format_version = ?1",
            [i64::try_from(version).unwrap()],
        )
        .unwrap();
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
