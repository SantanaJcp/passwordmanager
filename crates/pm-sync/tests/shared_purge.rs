// SPDX-License-Identifier: AGPL-3.0-only
#![cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../examples/shared_purge_probe.rs"]
mod reproducer;
#[test]
fn shared_purge_probe() {
    assert!(reproducer::probe::run(std::path::Path::new(env!(
        "CARGO_BIN_EXE_pm-sync"
    ))));
}
