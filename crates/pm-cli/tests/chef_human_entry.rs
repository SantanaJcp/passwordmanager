// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Write;
use std::process::{Command, Stdio};

fn failure(arguments: &[&str], code: i32, category: &str) {
    let output = Command::new(env!("CARGO_BIN_EXE_pm"))
        .args(arguments)
        .output()
        .expect("start real CLI");
    assert_eq!(output.status.code(), Some(code), "{arguments:?}");
    assert!(output.stdout.is_empty(), "{arguments:?}");
    assert_eq!(output.stderr, format!("error: {category}\n").as_bytes());
}

#[test]
fn human_entry_invalid_arguments_never_enter_delegated_transport() {
    for arguments in [
        vec!["tui"],
        vec!["tui", "serve-vault"],
        vec!["tui", "--profile"],
        vec!["tui", "--human"],
        vec![
            "tui",
            "--profile",
            "synthetic",
            "--private",
            "synthetic",
            "--socket",
            "synthetic",
        ],
    ] {
        failure(&arguments, 2, "INVALID_ARGUMENT");
    }
}

#[test]
fn machine_stream_and_delegated_secret_commands_remain_unauthorized() {
    for arguments in [
        vec!["tui", "--json"],
        vec!["--json", "tui"],
        vec!["tui", "--profile", "synthetic", "--json"],
        vec!["reveal"],
        vec!["export"],
        vec!["sign"],
        vec!["generic-sign"],
    ] {
        failure(&arguments, 3, "UNAUTHORIZED");
    }
}

#[test]
fn mcp_cannot_call_tui_or_other_human_operations() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pm"))
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    for name in ["tui", "reveal", "export", "generic-sign"] {
        writeln!(input, "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{{\"name\":\"{name}\",\"arguments\":{{}}}}}}")
            .unwrap();
    }
    drop(input);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(text.lines().count(), 4);
    assert!(
        text.lines()
            .all(|line| line.contains("NOT_FOUND") && line.contains("\"error\""))
    );
}
