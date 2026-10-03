// SPDX-License-Identifier: AGPL-3.0-only

use super::response;
use std::process::Command;

const CHILD: &str = "PM28_WEB_RESPONSE_CHILD";
static CANARY: [u8; 64 * 1024] = [0x28; 64 * 1024];

#[test]
fn provider_response_requires_locked_destination() {
    if std::env::var_os(CHILD).is_some() {
        let limit = libc::rlimit {
            rlim_cur: 32 * 1024,
            rlim_max: 32 * 1024,
        };
        // SAFETY: only this isolated child changes its own memlock limit.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const limit) },
            0
        );
        let small = response(0, b"PM28_SYNTHETIC_SMALL").unwrap();
        assert_eq!(&small[5..], b"PM28_SYNTHETIC_SMALL");
        drop(small);
        println!("PM28_WEB_RESPONSE_CONTROL_READY");
        assert!(
            response(0, &CANARY).is_err(),
            "unlocked provider response was accepted"
        );
        println!("PM28_WEB_RESPONSE_LOCK_DENIED");
        return;
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "provider::protected_response_tests::provider_response_requires_locked_destination",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        output
            .stdout
            .windows(b"PM28_WEB_RESPONSE_CONTROL_READY".len())
            .any(|bytes| bytes == b"PM28_WEB_RESPONSE_CONTROL_READY"),
        "provider response control missing"
    );
    println!("PM28_WEB_RESPONSE_CONTROL_READY");
    assert!(
        output.status.success(),
        "unlocked provider response was accepted after control"
    );
    assert!(
        output
            .stdout
            .windows(b"PM28_WEB_RESPONSE_LOCK_DENIED".len())
            .any(|bytes| bytes == b"PM28_WEB_RESPONSE_LOCK_DENIED"),
        "provider response denial missing"
    );
}
