// SPDX-License-Identifier: AGPL-3.0-only

use std::process::Command;

pub(super) fn isolated(name: &str, run: impl FnOnce()) {
    const CHILD: &str = "PM28P4_MEMORY_CHILD";
    if std::env::var(CHILD).as_deref() == Ok(name) {
        run();
        println!("PM28P4_LOCK_DENIED");
        return;
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env(CHILD, name)
        .output()
        .unwrap();
    assert!(
        output
            .stdout
            .windows(b"PM28P4_CONTROL_READY".len())
            .any(|v| v == b"PM28P4_CONTROL_READY"),
        "control did not reach the real seam"
    );
    println!("PM28P4_CONTROL_READY seam={name}");
    assert!(
        output.status.success(),
        "ordinary secret owner accepted after positive control: {name}"
    );
    assert!(
        output
            .stdout
            .windows(b"PM28P4_LOCK_DENIED".len())
            .any(|v| v == b"PM28P4_LOCK_DENIED"),
        "denial missing"
    );
}

pub(super) fn limit(bytes: libc::rlim_t) {
    let limit = libc::rlimit {
        rlim_cur: bytes,
        rlim_max: bytes,
    };
    // SAFETY: only the isolated test child lowers its own memlock limit.
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const limit) },
        0
    );
}

pub(super) const fn filled<const N: usize>(prefix: &[u8], suffix: &[u8]) -> [u8; N] {
    let mut value = [b'P'; N];
    let mut i = 0;
    while i < prefix.len() {
        value[i] = prefix[i];
        i += 1;
    }
    i = 0;
    while i < suffix.len() {
        value[N - suffix.len() + i] = suffix[i];
        i += 1;
    }
    value
}
