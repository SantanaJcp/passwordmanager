// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(target_os = "linux")]

use pm_crypto::CryptoError;
use pm_vault::{
    Attachment, AuthRecord, HumanCommitError, HumanMetadata, LogicalRecord, PasswordRecord,
    RecordKind,
};
use std::process::Command;

static CANARY: [u8; 512 * 1024] = [b'Z'; 512 * 1024];

fn passkey_with_seed_size(size: usize) -> Result<LogicalRecord, HumanCommitError> {
    LogicalRecord::new(
        RecordKind::Passkey,
        HumanMetadata {
            title: "PM28 synthetic passkey".into(),
            destinations: Vec::new(),
            tags: Vec::new(),
            favorite: false,
            notes: pm_crypto::ProtectedText::copy_from_str("").unwrap(),
            fields: Vec::new(),
            source_fields: Vec::new(),
        },
        vec![AuthRecord::Passkey {
            rp_id: "pm28.invalid".into(),
            user_handle: b"PM28_SYNTHETIC".to_vec(),
            credential_id: b"PM28_SYNTHETIC".to_vec(),
            cose_alg: -8,
            private_key: pm_crypto::ProtectedBytes::zeroed(size).unwrap(),
            public_key: [28; 32],
            user_name: "synthetic".into(),
            display_name: "synthetic".into(),
            sign_count: 0,
            backup_eligible: false,
            backup_state: false,
        }],
        Vec::new(),
    )
}

#[test]
fn protected_passkey_seed_preserves_exact_32_byte_invariant() {
    let control = passkey_with_seed_size(32).expect("valid seed control");
    assert!(!control.to_descriptor_bytes().unwrap().is_empty());
    drop(control);
    println!("PM28_PASSKEY_SEED_CONTROL_READY");
    for size in [0, 31, 33] {
        assert!(
            matches!(
                passkey_with_seed_size(size),
                Err(HumanCommitError::InvalidInput)
            ),
            "non-32-byte protected seed accepted"
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn records_require_locked_destinations_before_copying() {
    if let Some(case) = std::env::var_os("PM28_RECORD_CHILD") {
        let limit = libc::rlimit {
            rlim_cur: 128 * 1024,
            rlim_max: 128 * 1024,
        };
        // SAFETY: this isolated child changes only its own memlock limit.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const limit) },
            0
        );
        let control = PasswordRecord::new(
            "PM28 synthetic",
            "synthetic",
            b"PM28_SMALL",
            "https://pm28.invalid",
            "PM28_NOTE",
        )
        .expect("small record control");
        assert_eq!(control.password(), b"PM28_SMALL");
        assert_eq!(control.notes(), "PM28_NOTE");
        drop(control);
        let control = Attachment::new(
            [28; 16],
            "synthetic.bin",
            "application/octet-stream",
            b"PM28_SMALL",
        )
        .expect("small attachment control");
        assert_eq!(control.content(), b"PM28_SMALL");
        drop(control);
        println!("PM28_RECORD_CONTROL_READY");
        let denied = match case.to_str().expect("public test case") {
            "password" => PasswordRecord::new(
                "PM28 synthetic",
                "synthetic",
                &CANARY,
                "https://pm28.invalid",
                "",
            )
            .err(),
            "notes" => PasswordRecord::new(
                "PM28 synthetic",
                "synthetic",
                b"PM28_SMALL",
                "https://pm28.invalid",
                std::str::from_utf8(&CANARY).expect("synthetic ASCII"),
            )
            .err(),
            "attachment" => Attachment::new(
                [28; 16],
                "synthetic.bin",
                "application/octet-stream",
                &CANARY,
            )
            .err(),
            _ => panic!("unknown public test case"),
        };
        assert!(
            matches!(
                denied,
                Some(HumanCommitError::Crypto(CryptoError::ResourceUnavailable))
            ),
            "ordinary record destination accepted under denied memlock"
        );
        println!("PM28_RECORD_LOCK_DENIED");
        return;
    }
    let mut failures = Vec::new();
    for case in ["password", "notes", "attachment"] {
        let output = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "records_require_locked_destinations_before_copying",
                "--nocapture",
            ])
            .env("PM28_RECORD_CHILD", case)
            .output()
            .expect("isolated record child");
        assert!(
            output
                .stdout
                .windows(b"PM28_RECORD_CONTROL_READY".len())
                .any(|v| v == b"PM28_RECORD_CONTROL_READY"),
            "record control missing"
        );
        println!("PM28_RECORD_CONTROL_READY case={case}");
        if output.status.success() {
            assert!(
                output
                    .stdout
                    .windows(b"PM28_RECORD_LOCK_DENIED".len())
                    .any(|v| v == b"PM28_RECORD_LOCK_DENIED"),
                "denial marker missing"
            );
        } else {
            failures.push(case);
        }
    }
    assert!(
        failures.is_empty(),
        "ordinary destinations accepted: {failures:?}"
    );
}
