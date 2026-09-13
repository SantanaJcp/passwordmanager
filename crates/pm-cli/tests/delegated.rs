// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn mcp_stdio_publishes_exactly_the_five_delegated_tools() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pm"))
        .args(["mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start MCP adapter");
    let mut input = child.stdin.take().expect("MCP stdin");
    writeln!(
        input,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
    )
    .unwrap();
    writeln!(
        input,
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{{}}}}"#
    )
    .unwrap();
    drop(input);
    let output = child.wait_with_output().expect("wait for MCP adapter");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("2025-11-25"));
    for tool in [
        "get_capabilities",
        "discover_credentials",
        "start_authentication",
        "get_authentication",
        "cancel_authentication",
    ] {
        assert!(stdout.contains(tool), "missing {tool}");
    }
    for forbidden in ["reveal", "export", "generic-sign", "sign_bytes"] {
        assert!(!stdout.contains(forbidden), "forbidden tool {forbidden}");
    }
    assert!(output.stderr.is_empty());
}

#[test]
fn delegated_json_failure_keeps_diagnostics_out_of_stdout() {
    let output = Command::new(env!("CARGO_BIN_EXE_pm"))
        .args(["--json", "capabilities"])
        .output()
        .expect("start delegated CLI");
    assert_eq!(output.status.code(), Some(4));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("CUSTODY_UNAVAILABLE"));
    assert!(!stdout.contains("error:"));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("CUSTODY_UNAVAILABLE")
    );
}
