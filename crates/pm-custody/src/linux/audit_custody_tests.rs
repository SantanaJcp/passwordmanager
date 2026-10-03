// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use pm_vault::{HumanChannel, PendingVault};
use rusqlite::Connection;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

const DEVICE: [u8; 16] = [0x28; 16];
const MASTER: &[u8] = b"PM28_SYNTHETIC_FUNCTION_MASTER";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    vault: PathBuf,
    custody: PathBuf,
}

fn with_fixture(run: impl FnOnce(&Fixture)) {
    let root = std::env::temp_dir().join(format!(
        "pm28-audit-function-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).expect("exclusive fixture root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private fixture root");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fixture = Fixture {
            vault: root.join("vault.sqlite3"),
            custody: root.join("vault.sqlite3.audit-custody"),
        };
        let pending = PendingVault::new(MASTER, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
        let recovery = pending.recovery_code().to_string().parse().unwrap();
        pending.persist(&fixture.vault, &recovery).unwrap();
        run(&fixture);
    }));
    fs::remove_dir_all(&root).expect("checked cleanup of this fixture only");
    assert!(!root.exists());
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

fn initialize(fixture: &Fixture) {
    let custody = Arc::new(
        load_or_create_audit_custody(&fixture.custody, &fixture.vault, DEVICE)
            .expect("first custody initialization"),
    );
    let (server, _peer) = UnixStream::pair().unwrap();
    let channel = HumanChannel::authenticate(server, current_uid()).unwrap();
    let mut human = HumanVault::unlock(&fixture.vault, MASTER, DEVICE, channel, custody).unwrap();
    let prepared = human.prepare_delegated_resume().unwrap();
    let signature = human.sign(&prepared).unwrap();
    human
        .commit(prepared.command(), &signature, prepared.body())
        .unwrap();
    let connection = Connection::open(&fixture.vault).unwrap();
    let initialized: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM audit_keys WHERE device_id=?1)",
            [DEVICE.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(initialized);
    println!("PM28_AUDIT_FUNCTION_INITIALIZED_CONTROL_READY");
}

#[test]
fn initialized_missing_custody_is_unavailable_without_replacement() {
    with_fixture(|fixture| {
        initialize(fixture);
        fs::remove_file(&fixture.custody).unwrap();
        assert!(matches!(
            load_or_create_audit_custody(&fixture.custody, &fixture.vault, DEVICE),
            Err(Failure::Unavailable)
        ));
        assert!(!fixture.custody.exists());
    });
}

#[test]
fn initialized_unreadable_custody_is_unavailable_without_changes() {
    with_fixture(|fixture| {
        initialize(fixture);
        let original = Zeroizing::new(fs::read(&fixture.custody).unwrap());
        fs::set_permissions(&fixture.custody, fs::Permissions::from_mode(0o000)).unwrap();
        assert!(matches!(
            load_or_create_audit_custody(&fixture.custody, &fixture.vault, DEVICE),
            Err(Failure::Unavailable)
        ));
        fs::set_permissions(&fixture.custody, fs::Permissions::from_mode(0o400)).unwrap();
        let unchanged = Zeroizing::new(fs::read(&fixture.custody).unwrap());
        assert!(original.as_slice().eq(unchanged.as_slice()));
    });
}

#[test]
fn first_initialization_creates_and_reuses_exact_custody() {
    with_fixture(|fixture| {
        let first = load_or_create_audit_custody(&fixture.custody, &fixture.vault, DEVICE).unwrap();
        let original = Zeroizing::new(first.to_protected_bytes());
        let second =
            load_or_create_audit_custody(&fixture.custody, &fixture.vault, DEVICE).unwrap();
        let reused = Zeroizing::new(second.to_protected_bytes());
        assert!(original.as_slice().eq(reused.as_slice()));
        assert_eq!(
            fs::metadata(&fixture.custody).unwrap().mode() & 0o777,
            0o400
        );
    });
}

#[test]
fn exact_original_restoration_keeps_previous_authority() {
    with_fixture(|fixture| {
        initialize(fixture);
        let before = fs::read(&fixture.vault).unwrap();
        let retained = fixture.custody.with_extension("owned-original");
        fs::rename(&fixture.custody, &retained).unwrap();
        assert!(matches!(
            load_or_create_audit_custody(&fixture.custody, &fixture.vault, DEVICE),
            Err(Failure::Unavailable)
        ));
        assert!(!fixture.custody.exists());
        fs::rename(&retained, &fixture.custody).unwrap();
        let restored = Arc::new(
            load_or_create_audit_custody(&fixture.custody, &fixture.vault, DEVICE).unwrap(),
        );
        let delegated = DelegatedVault::open(&fixture.vault, DEVICE, restored).unwrap();
        assert_eq!(delegated.authority_headers().unwrap().len(), 1);
        assert!(before.eq(&fs::read(&fixture.vault).unwrap()));
    });
}

#[test]
fn missing_or_unclassifiable_vault_never_creates_audit_custody() {
    with_fixture(|fixture| {
        fs::remove_file(&fixture.vault).unwrap();
        assert!(matches!(
            load_or_create_audit_custody(&fixture.custody, &fixture.vault, DEVICE),
            Err(Failure::Unavailable)
        ));
        assert!(!fixture.vault.exists() && !fixture.custody.exists());
        fs::write(&fixture.vault, b"PM28_SYNTHETIC_INVALID_SQLITE").unwrap();
        assert!(matches!(
            load_or_create_audit_custody(&fixture.custody, &fixture.vault, DEVICE),
            Err(Failure::Unavailable)
        ));
        assert!(!fixture.custody.exists());
    });
}
