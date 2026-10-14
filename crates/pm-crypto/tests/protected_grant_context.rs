// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(target_os = "linux")]

use pm_crypto::{
    AuditDeviceKeyPair, CryptoError, DeviceKeyPair, GrantVectorInput, KdfProfile,
    create_human_root, open_human_root,
};
use std::process::Command;

#[test]
fn device_grant_context_requires_locked_destination() {
    run_helper("device_grant_memlock_helper");
}

#[test]
fn audit_device_grant_context_requires_locked_destination() {
    run_helper("audit_device_grant_memlock_helper");
}

fn run_helper(name: &str) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", name, "--nocapture"])
        .env_clear()
        .output()
        .expect("isolated grant process");
    assert!(
        output
            .stdout
            .windows(b"GRANT_CONTROL_OK".len())
            .any(|v| v == b"GRANT_CONTROL_OK"),
        "valid grant control missing"
    );
    assert!(
        output.status.success(),
        "grant context accepted without available locks: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "isolated child of device_grant_context_requires_locked_destination"]
fn device_grant_memlock_helper() {
    grant_helper(false);
}

#[test]
#[ignore = "isolated child of audit_device_grant_context_requires_locked_destination"]
fn audit_device_grant_memlock_helper() {
    grant_helper(true);
}

fn grant_helper(audit: bool) {
    let password = b"synthetic chef protected grant password";
    let created = create_human_root(password, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    let unlocked = open_human_root(created.bundle(), password).unwrap();
    let device = DeviceKeyPair::generate().unwrap();
    let audit_device = AuditDeviceKeyPair::generate().unwrap();
    let recipient = [0x71; 16];
    let event = [0x75; 32];
    let digest = [0x74; 32];
    let pending = unlocked
        .prepare_grant_vector(
            GrantVectorInput {
                item: [0x72; 16],
                revision: [0x73; 16],
                recipient,
                authorization_generation: 9,
                payload_sha256: digest,
            },
            if audit {
                audit_device.encryption_public_key()
            } else {
                device.public_key()
            },
        )
        .unwrap();
    let commitment = pending.commitment();
    let signed = unlocked
        .finish_grant_vector(pending, event)
        .unwrap()
        .to_bytes();
    let verify = || {
        if audit {
            audit_device
                .verify_grant_vector(
                    &signed,
                    created.bundle().trusted_root(),
                    recipient,
                    event,
                    commitment,
                )
                .map(|actual| {
                    assert_eq!(actual, digest);
                })
        } else {
            device.verify_grant_vector(
                &signed,
                created.bundle().trusted_root(),
                recipient,
                event,
                commitment,
            )
        }
    };
    verify().unwrap();
    println!("GRANT_CONTROL_OK");
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: only this isolated child loses permission to create future locks.
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const limit) },
        0
    );
    assert_eq!(
        verify(),
        Err(CryptoError::ResourceUnavailable),
        "unlocked sealed grant context accepted"
    );
}
