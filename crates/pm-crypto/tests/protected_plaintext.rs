// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(target_os = "linux")]

use std::process::Command;

use pm_crypto::{
    BackupOpener, CryptoError, ItemKind, KdfProfile, ProtectedBytes, RevisionPackageInput,
    create_human_root, open_human_root,
};

const PASSWORD: &[u8] = b"synthetic ticket28 protected-output password";
const HUMAN: &[u8] = b"synthetic ticket28 human plaintext";
const AUTH: &[u8] = b"synthetic ticket28 auth plaintext";

#[test]
fn revision_plaintext_requires_locked_output_before_decrypt() {
    run_helper("revision_plaintext_memlock_helper");
}

#[test]
fn streamed_plaintext_requires_locked_output_before_decrypt() {
    run_helper("streamed_plaintext_memlock_helper");
}

fn run_helper(name: &str) {
    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .args(["--ignored", "--exact", name, "--nocapture"])
        .env_clear()
        .output()
        .expect("start isolated memlock helper");
    assert!(
        output.status.success(),
        "{name} did not reject plaintext before unlocked output (status={:?})",
        output.status.code()
    );
}

#[test]
#[ignore = "executed in an isolated subprocess by revision_plaintext_requires_locked_output_before_decrypt"]
fn revision_plaintext_memlock_helper() {
    let created = create_human_root(PASSWORD, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    let unlocked = open_human_root(created.bundle(), PASSWORD).unwrap();
    let small = unlocked
        .seal_revision_package(RevisionPackageInput {
            item: [0x28; 16],
            revision: [0x29; 16],
            issuer_device: [0x2a; 16],
            modified_at: 1,
            kind: ItemKind::Password,
            human_plaintext: HUMAN,
            auth_plaintext: Some(AUTH),
        })
        .unwrap()
        .to_bytes();
    let mut large_plaintext = vec![0x28; 4 * 1024 * 1024];
    let large = unlocked
        .seal_revision_package(RevisionPackageInput {
            item: [0x2b; 16],
            revision: [0x2c; 16],
            issuer_device: [0x2d; 16],
            modified_at: 2,
            kind: ItemKind::Note,
            human_plaintext: &large_plaintext,
            auth_plaintext: None,
        })
        .unwrap()
        .to_bytes();
    large_plaintext.fill(0);
    drop(large_plaintext);
    let pressure = reserve_all_but_one_mebibyte();
    let small_opened = unlocked
        .open_revision_package(&small)
        .expect("key path and small protected outputs must fit reserved margin");
    assert_eq!(small_opened.human_plaintext(), HUMAN);
    assert_eq!(small_opened.auth_plaintext(), Some(AUTH));
    drop(small_opened);
    assert!(matches!(
        unlocked.open_revision_package(&large),
        Err(CryptoError::ResourceUnavailable)
    ));
    drop(pressure);
}

#[test]
#[ignore = "executed in an isolated subprocess by streamed_plaintext_requires_locked_output_before_decrypt"]
fn streamed_plaintext_memlock_helper() {
    let created = create_human_root(PASSWORD, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    let unlocked = open_human_root(created.bundle(), PASSWORD).unwrap();
    let backup_id = [0x2b; 16];
    let mut sealer = unlocked.start_backup(backup_id).unwrap();
    let ciphertext = sealer.seal_chunk(HUMAN, true).unwrap();
    let mut opener = BackupOpener::with_password(
        &created.bundle().backup_root_envelopes(),
        backup_id,
        sealer.key_envelope(),
        sealer.pmf1_header(),
        PASSWORD,
    )
    .unwrap();
    deny_future_locks();
    assert!(matches!(
        opener.open_chunk(&ciphertext, true),
        Err(CryptoError::ResourceUnavailable)
    ));
}

fn deny_future_locks() {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: the limit is a valid immutable rlimit owned by this isolated
    // helper; the parent test process retains its original limits.
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const limit) },
        0
    );
}

fn reserve_all_but_one_mebibyte() -> Vec<ProtectedBytes> {
    const CHUNK: usize = 1024 * 1024;
    let mut owners = Vec::new();
    while let Ok(owner) = ProtectedBytes::zeroed(CHUNK) {
        owners.push(owner);
    }
    assert!(
        owners.len() > 1,
        "fixture could not establish bounded pressure"
    );
    drop(owners.pop());
    owners
}
