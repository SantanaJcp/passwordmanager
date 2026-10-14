// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use std::process::Command;

const REFERENCE: &str = "PM_CHEF_SYNTHETIC_REFERENCE";
const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const USERNAME: &str = "pm_synthetic_user";
const JSON: &[u8] = br#"{"kind":"ssh_authenticated_connection","consumer_ref":"PM_CHEF_SYNTHETIC_REFERENCE","host_key_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","username":"pm_synthetic_user"}"#;

#[test]
fn own_wire_encoders_require_locked_destinations() {
    let name = "wire_memory_tests::own_wire_encoders_require_locked_destinations";
    if std::env::var("PM_CHEF_SSH_WIRE_CHILD").as_deref() == Ok(name) {
        for opcode in [1, 6] {
            let frame = field_frame(opcode, REFERENCE.as_bytes()).unwrap();
            assert_eq!(frame[0], opcode);
            assert_eq!(&frame[1..5], &[0, 0, 0, 27]);
            assert_eq!(&frame[5..], REFERENCE.as_bytes());
        }
        let response = authentication_response(REFERENCE, HASH, USERNAME).unwrap();
        assert_eq!(response[0], 0);
        assert_eq!(
            &response[1..5],
            &u32::try_from(JSON.len()).unwrap().to_be_bytes()
        );
        assert_eq!(&response[5..], JSON);
        drop(response);
        println!("PM_CHEF_SSH_WIRE_CONTROL_READY");
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: only this isolated child lowers its own memlock limit.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const limit) },
            0
        );
        let mode = std::env::var("PM_CHEF_SSH_WIRE_MODE").unwrap();
        if mode == "request" {
            for opcode in [1, 6] {
                assert!(
                    matches!(
                        field_frame(opcode, REFERENCE.as_bytes()),
                        Err(Error::Memory(pm_crypto::CryptoError::ResourceUnavailable))
                    ),
                    "ordinary SSH wire owner accepted with memlock=0"
                );
            }
        } else {
            assert!(
                matches!(
                    authentication_response(REFERENCE, HASH, USERNAME),
                    Err(Error::Memory(pm_crypto::CryptoError::ResourceUnavailable))
                ),
                "ordinary SSH presentation owner accepted with memlock=0"
            );
        }
        println!("PM_CHEF_SSH_WIRE_LOCK_DENIED");
        return;
    }
    let mut passed = true;
    for mode in ["request", "response"] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("PM_CHEF_SSH_WIRE_CHILD", name)
            .env("PM_CHEF_SSH_WIRE_MODE", mode)
            .output()
            .unwrap();
        assert!(
            output
                .stdout
                .windows(b"PM_CHEF_SSH_WIRE_CONTROL_READY".len())
                .any(|bytes| bytes == b"PM_CHEF_SSH_WIRE_CONTROL_READY"),
            "wire compatibility control missing"
        );
        println!(
            "PM_CHEF_SSH_WIRE_OBSERVED mode={mode} success={}",
            output.status.success()
        );
        passed &= output.status.success()
            && output
                .stdout
                .windows(b"PM_CHEF_SSH_WIRE_LOCK_DENIED".len())
                .any(|bytes| bytes == b"PM_CHEF_SSH_WIRE_LOCK_DENIED");
    }
    assert!(
        passed,
        "SSH wire encoders accepted an unlocked owner after the control"
    );
}

#[test]
fn consumer_decode_borrows_the_protected_input() {
    let request = field_frame(1, REFERENCE.as_bytes()).unwrap();
    let decoded = parse_consumer_reference(&request).unwrap();
    assert_eq!(decoded.as_bytes(), REFERENCE.as_bytes());
    assert_eq!(
        decoded.as_ptr(),
        request[5..].as_ptr(),
        "consumer decode duplicated plaintext outside its protected frame"
    );
    let malformed = field_parts(1, &[REFERENCE.as_bytes(), &[0]]).unwrap();
    // Append trailing bytes after the declared field, not inside it.
    let mut malformed = malformed;
    malformed[1..5].copy_from_slice(&[0, 0, 0, 27]);
    assert!(matches!(
        parse_consumer_reference(&malformed),
        Err(Error::Protocol)
    ));
}
