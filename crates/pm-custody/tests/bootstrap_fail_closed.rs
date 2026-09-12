// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
fn missing_damaged_or_permissive_bootstrap_is_custody_unavailable() {
    let directory = std::env::temp_dir().join(format!(
        "pm-custody-bootstrap-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&directory).unwrap();
    let bootstrap = directory.join("bootstrap.bin");
    let agent_socket = directory.join("agent.sock");
    let human_socket = directory.join("human.sock");

    assert_unavailable(&bootstrap, &agent_socket, &human_socket);
    fs::write(&bootstrap, b"synthetic damaged bootstrap").unwrap();
    fs::set_permissions(&bootstrap, fs::Permissions::from_mode(0o400)).unwrap();
    assert_unavailable(&bootstrap, &agent_socket, &human_socket);
    fs::set_permissions(&bootstrap, fs::Permissions::from_mode(0o600)).unwrap();
    assert_unavailable(&bootstrap, &agent_socket, &human_socket);

    let _ = fs::remove_dir_all(directory);
}

fn assert_unavailable(
    bootstrap: &std::path::Path,
    agent: &std::path::Path,
    human: &std::path::Path,
) {
    let output = Command::new(env!("CARGO_BIN_EXE_pm-custody"))
        .args(["serve", "--bootstrap"])
        .arg(bootstrap)
        .arg("--agent-socket")
        .arg(agent)
        .arg("--human-socket")
        .arg(human)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"CUSTODY_UNAVAILABLE\n");
}
