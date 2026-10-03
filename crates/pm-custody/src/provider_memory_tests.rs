// SPDX-License-Identifier: AGPL-3.0-only

use super::encode_provider_message;
use std::process::Command;

#[test]
fn provider_requests_require_locked_destination() {
    const CHILD: &str = "PM28P4_PROVIDER_REQUEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let password = b"PM28P4_SYNTHETIC_PASSWORD";
        let message = encode_provider_message(&[5], &[password], &[]).unwrap();
        assert_eq!(message[0], 5);
        assert_eq!(
            u32::from_be_bytes(message[1..5].try_into().unwrap()) as usize,
            password.len()
        );
        assert!((&message[5..]).eq(password));
        drop(message);
        let metadata = encode_provider_message(
            &[4; 33],
            &[
                b"ssh-server",
                b"password",
                b"PM28P4_HOST",
                b"PM28P4_CONTEXT",
                b"PM28P4_USER",
                b"",
            ],
            &[0; 24],
        )
        .unwrap();
        assert!((&metadata[..33]).eq(&[4; 33]) && metadata.ends_with(&[0; 24]));
        drop(metadata);
        println!("PM28P4_PROVIDER_REQUEST_CONTROL_READY");
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: only this isolated child changes its own memlock limit.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const limit) },
            0
        );
        assert!(
            encode_provider_message(&[5], &[password], &[]).is_err(),
            "ordinary late SSH password request accepted"
        );
        assert!(
            encode_provider_message(
                &[3; 33],
                &[
                    b"PM28P4_CONTEXT",
                    password,
                    b"PM28P4_SYNTHETIC_SEED",
                    b"SHA1"
                ],
                &[0; 11]
            )
            .is_err(),
            "ordinary controlled request accepted"
        );
        println!("PM28P4_PROVIDER_REQUEST_LOCK_DENIED");
        return;
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "linux::provider_memory_tests::provider_requests_require_locked_destination",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        output
            .stdout
            .windows(b"PM28P4_PROVIDER_REQUEST_CONTROL_READY".len())
            .any(|v| v == b"PM28P4_PROVIDER_REQUEST_CONTROL_READY"),
        "request control missing"
    );
    println!("PM28P4_PROVIDER_REQUEST_CONTROL_READY");
    assert!(
        output.status.success(),
        "ordinary provider request accepted after control"
    );
    assert!(
        output
            .stdout
            .windows(b"PM28P4_PROVIDER_REQUEST_LOCK_DENIED".len())
            .any(|v| v == b"PM28P4_PROVIDER_REQUEST_LOCK_DENIED"),
        "request denial missing"
    );
}
