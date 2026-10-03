// SPDX-License-Identifier: AGPL-3.0-only
#![cfg(target_os = "linux")]
use pm_crypto::{CryptoError, ProtectedBytes};
use pm_vault::{HumanCommitError, HumanMetadata, LogicalRecord, RecordKind};
use std::process::Command;
static CANARY: [u8; 512 * 1024] = [b'Z'; 512 * 1024];
fn note(value: &str) -> LogicalRecord {
    LogicalRecord::new(
        RecordKind::Note,
        HumanMetadata {
            title: "PM28 synthetic".into(),
            destinations: Vec::new(),
            tags: Vec::new(),
            favorite: false,
            notes: pm_crypto::ProtectedText::copy_from_str(value).expect("synthetic notes"),
            fields: Vec::new(),
            source_fields: Vec::new(),
        },
        Vec::new(),
        Vec::new(),
    )
    .expect("synthetic note")
}
#[test]
fn record_serializers_require_exact_locked_destinations() {
    if let Some(case) = std::env::var_os("PM28_SERIALIZER_CHILD") {
        let small = note("PM28_SMALL");
        let large = note(std::str::from_utf8(&CANARY).expect("synthetic ASCII"));
        let mut pressure = Vec::new();
        while let Ok(owner) = ProtectedBytes::zeroed(128 * 1024) {
            pressure.push(owner);
        }
        assert!(pressure.len() > 1, "pressure precondition");
        drop(pressure.pop());
        let control = small
            .to_descriptor_bytes()
            .expect("small serializer control");
        assert!(!control.is_empty());
        drop(control);
        println!("PM28_SERIALIZER_CONTROL_READY");
        let result = match case.to_str().expect("public case") {
            "descriptor" => large.to_descriptor_bytes(),
            "complete" => large.to_bytes(),
            _ => panic!("unknown case"),
        };
        assert!(
            matches!(
                result,
                Err(HumanCommitError::Crypto(CryptoError::ResourceUnavailable))
            ),
            "ordinary serializer output accepted"
        );
        println!("PM28_SERIALIZER_LOCK_DENIED");
        return;
    }
    let mut failures = Vec::new();
    for case in ["descriptor", "complete"] {
        let output = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "record_serializers_require_exact_locked_destinations",
                "--nocapture",
            ])
            .env("PM28_SERIALIZER_CHILD", case)
            .output()
            .expect("isolated serializer child");
        assert!(
            output
                .stdout
                .windows(b"PM28_SERIALIZER_CONTROL_READY".len())
                .any(|v| v == b"PM28_SERIALIZER_CONTROL_READY"),
            "serializer control marker missing"
        );
        println!("PM28_SERIALIZER_CONTROL_READY case={case}");
        if output.status.success() {
            assert!(
                output
                    .stdout
                    .windows(b"PM28_SERIALIZER_LOCK_DENIED".len())
                    .any(|v| v == b"PM28_SERIALIZER_LOCK_DENIED"),
                "denial marker missing"
            );
        } else {
            failures.push(case);
        }
    }
    assert!(
        failures.is_empty(),
        "ordinary outputs accepted: {failures:?}"
    );
}
