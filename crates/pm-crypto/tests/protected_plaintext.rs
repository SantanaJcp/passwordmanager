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
    if name == "inline_file_memlock_helper" {
        assert!(
            output
                .stdout
                .windows(b"PM28_INLINE_FILE_CONTROL_READY".len())
                .any(|v| v == b"PM28_INLINE_FILE_CONTROL_READY"),
            "inline file control missing"
        );
    }
    if !output.status.success() {
        let marker = format!("PM28_RED:{name}:UNLOCKED_OUTPUT_ACCEPTED");
        if output
            .stderr
            .windows(marker.len())
            .any(|bytes| bytes == marker.as_bytes())
        {
            panic!("{name} reached the plaintext destination and accepted unlocked output");
        }
        panic!(
            "{name} failed before the plaintext destination (status={:?})",
            output.status.code()
        );
    }
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
    match unlocked.open_revision_package(&large) {
        Err(CryptoError::ResourceUnavailable) => {}
        Ok(_) => {
            eprintln!("PM28_RED:revision_plaintext_memlock_helper:UNLOCKED_OUTPUT_ACCEPTED");
            panic!("large revision opened without a protected plaintext owner");
        }
        Err(error) => panic!("unexpected large revision error: {error}"),
    }
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
    match opener.open_chunk(&ciphertext, true) {
        Err(CryptoError::ResourceUnavailable) => {}
        Ok(_) => {
            eprintln!("PM28_RED:streamed_plaintext_memlock_helper:UNLOCKED_OUTPUT_ACCEPTED");
            panic!("stream chunk opened without a protected plaintext owner");
        }
        Err(error) => panic!("unexpected stream open error: {error}"),
    }
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

#[test]
fn inline_file_plaintext_requires_locked_output() {
    run_helper("inline_file_memlock_helper");
}

#[test]
#[ignore = "executed by inline_file_plaintext_requires_locked_output"]
fn inline_file_memlock_helper() {
    static CANARY: [u8; 4 * 1024 * 1024] = [0x5a; 4 * 1024 * 1024];
    let created = create_human_root(PASSWORD, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    let unlocked = open_human_root(created.bundle(), PASSWORD).unwrap();
    let small = unlocked
        .seal_file([28; 16], [29; 16], HUMAN)
        .unwrap()
        .to_bytes();
    let large = unlocked
        .seal_file([30; 16], [31; 16], &CANARY)
        .unwrap()
        .to_bytes();
    let pressure = reserve_all_but_one_mebibyte();
    let control = unlocked
        .open_file([28; 16], [29; 16], &small)
        .expect("small inline file control");
    assert_eq!(&control[..], HUMAN);
    drop(control);
    println!("PM28_INLINE_FILE_CONTROL_READY");
    match unlocked.open_file([30; 16], [31; 16], &large) {
        Err(CryptoError::ResourceUnavailable) => {}
        Ok(_) => {
            eprintln!("PM28_RED:inline_file_memlock_helper:UNLOCKED_OUTPUT_ACCEPTED");
            panic!("ordinary inline file destination accepted");
        }
        Err(error) => panic!("unexpected inline file error: {error}"),
    }
    drop(pressure);
}
