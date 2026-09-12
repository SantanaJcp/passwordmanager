// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

const PASSWORD: &str = "synthetic ticket 02 CLI password";
static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
fn human_cli_creates_offline_and_a_second_process_opens_the_vault() {
    let directory = TestDir::new();
    let path = directory.0.join("human-vault.sqlite3");
    let mut child = Command::new(env!("CARGO_BIN_EXE_pm"))
        .args(["vault", "create"])
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start create process");
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());

    assert_line(&mut output, "Master password (read from stdin):\n");
    writeln!(input, "{PASSWORD}").unwrap();
    input.flush().unwrap();
    assert_line(&mut output, "Confirm master password:\n");
    writeln!(input, "{PASSWORD}").unwrap();
    input.flush().unwrap();

    let mut recovery_line = String::new();
    output.read_line(&mut recovery_line).unwrap();
    let recovery = recovery_line
        .strip_prefix("Recovery code (store externally): ")
        .and_then(|line| line.strip_suffix('\n'))
        .expect("recovery line");
    assert!(recovery.starts_with("PMR1-"));
    assert_line(
        &mut output,
        "Reintroduce recovery code to confirm the external copy:\n",
    );
    writeln!(input, "{recovery}").unwrap();
    drop(input);

    let mut remaining = String::new();
    output.read_to_string(&mut remaining).unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(remaining.starts_with("Vault created: "));
    assert!(!remaining.contains(PASSWORD));
    assert!(result.stderr.is_empty());

    let mut opener = Command::new(env!("CARGO_BIN_EXE_pm"))
        .args(["vault", "open"])
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start a distinct open process");
    writeln!(opener.stdin.take().unwrap(), "{PASSWORD}").unwrap();
    let open_result = opener.wait_with_output().unwrap();
    assert!(
        open_result.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&open_result.stderr)
    );
    let stdout = String::from_utf8(open_result.stdout).unwrap();
    assert!(stdout.starts_with("Master password (read from stdin):\nVault opened: "));
    assert!(!stdout.contains(PASSWORD));
    assert!(open_result.stderr.is_empty());
}

fn assert_line(reader: &mut impl BufRead, expected: &str) {
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!(line, expected);
}

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "pm-cli-ticket-02-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

use std::io::Read as _;
