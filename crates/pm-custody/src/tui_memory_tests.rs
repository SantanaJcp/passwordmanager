// SPDX-License-Identifier: AGPL-3.0-only

use super::{encode_secret_request, split_exact};

fn isolated(name: &str, run: impl FnOnce()) {
    const CHILD: &str = "PM28P4_TUI_MEMORY_CHILD";
    if std::env::var(CHILD).as_deref() == Ok(name) {
        run();
        println!("PM28P4_TUI_LOCK_DENIED");
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env(CHILD, name)
        .output()
        .unwrap();
    assert!(
        output
            .stdout
            .windows(b"PM28P4_TUI_CONTROL_READY".len())
            .any(|v| v == b"PM28P4_TUI_CONTROL_READY"),
        "TUI control missing"
    );
    println!("PM28P4_TUI_CONTROL_READY seam={name}");
    assert!(
        output.status.success(),
        "ordinary TUI owner accepted after control"
    );
    assert!(
        output
            .stdout
            .windows(b"PM28P4_TUI_LOCK_DENIED".len())
            .any(|v| v == b"PM28P4_TUI_LOCK_DENIED"),
        "TUI denial missing"
    );
}

fn deny_memlock() {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: only the isolated test child lowers its own memlock limit.
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const limit) },
        0
    );
}

#[test]
fn split_secret_fields_require_locked_destination() {
    isolated(
        "tui::memory_tests::split_secret_fields_require_locked_destination",
        || {
            const INPUT: &str = r"PM28P4_SYNTHETIC_界\|pw\\x|ROTATE";
            let [password, confirmation] = split_exact::<2>(INPUT).unwrap();
            assert!(
                password
                    .as_bytes()
                    .eq("PM28P4_SYNTHETIC_界|pw\\x".as_bytes())
                    && confirmation.as_bytes().eq(b"ROTATE")
            );
            drop(password);
            drop(confirmation);
            println!("PM28P4_TUI_CONTROL_READY");
            deny_memlock();
            assert!(
                split_exact::<2>(INPUT).is_err(),
                "ordinary secret split accepted"
            );
        },
    );
}

#[test]
fn master_password_request_requires_locked_destination() {
    isolated(
        "tui::memory_tests::master_password_request_requires_locked_destination",
        || {
            let password = b"PM28P4_SYNTHETIC_MASTER";
            for opcode in [34, 43] {
                let request = encode_secret_request(opcode, password).unwrap();
                assert_eq!(request[0], opcode);
                assert_eq!(
                    u32::from_be_bytes(request[1..5].try_into().unwrap()) as usize,
                    password.len()
                );
                assert!((&request[5..]).eq(password));
            }
            println!("PM28P4_TUI_CONTROL_READY");
            deny_memlock();
            assert!(
                encode_secret_request(43, password).is_err(),
                "ordinary master rotation request accepted"
            );
            assert!(
                encode_secret_request(34, password).is_err(),
                "ordinary native restore request accepted"
            );
        },
    );
}
