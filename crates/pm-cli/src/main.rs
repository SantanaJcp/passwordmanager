// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    ffi::OsString,
    io::{self, BufRead, Read, Write},
    path::Path,
};

use pm_crypto::{KdfProfile, RecoveryCode};
use pm_vault::{PendingVault, open_vault};

fn main() {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if let Err(error) = run(&arguments) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run(arguments: &[OsString]) -> Result<(), String> {
    match arguments {
        [flag] if flag == "--version" => {
            println!(
                "passwordmanager {} (libsodium {})",
                env!("CARGO_PKG_VERSION"),
                pm_crypto::linked_libsodium_version().to_string_lossy()
            );
            Ok(())
        }
        [group, command, path] if group == "vault" && command == "create" => {
            create(Path::new(path))
        }
        [group, command, path] if group == "vault" && command == "open" => open(Path::new(path)),
        _ => Err("usage: pm --version | pm vault create PATH | pm vault open PATH".to_owned()),
    }
}

fn create(path: &Path) -> Result<(), String> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    prompt("Master password (read from stdin):")?;
    let password = read_limited_line(&mut input, 1024)?;
    prompt("Confirm master password:")?;
    let confirmation = read_limited_line(&mut input, 1024)?;
    if password != confirmation {
        return Err("master password confirmation does not match".to_owned());
    }

    let pending =
        PendingVault::new(&password, KdfProfile::DEFAULT).map_err(|error| error.to_string())?;
    let trusted_root = *pending.trusted_root();
    println!(
        "Recovery code (store externally): {}",
        pending.recovery_code()
    );
    prompt("Reintroduce recovery code to confirm the external copy:")?;
    let reintroduced = read_limited_line(&mut input, 512)?;
    let reintroduced: RecoveryCode = std::str::from_utf8(&reintroduced)
        .map_err(|_| "recovery code is not UTF-8".to_owned())?
        .parse()
        .map_err(|_| "recovery code is invalid".to_owned())?;
    pending
        .persist(path, &reintroduced)
        .map_err(|error| error.to_string())?;
    println!("Vault created: {}", hex(trusted_root.vault_id()));
    Ok(())
}

fn open(path: &Path) -> Result<(), String> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    prompt("Master password (read from stdin):")?;
    let password = read_limited_line(&mut input, 1024)?;
    let opened = open_vault(path, &password).map_err(|error| error.to_string())?;
    println!("Vault opened: {}", hex(opened.trusted_root().vault_id()));
    Ok(())
}

fn prompt(message: &str) -> Result<(), String> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "{message}").map_err(|error| error.to_string())?;
    output.flush().map_err(|error| error.to_string())
}

fn read_limited_line(input: &mut impl BufRead, maximum: usize) -> Result<Vec<u8>, String> {
    let mut value = Vec::with_capacity(maximum.min(128));
    let mut limited = Read::by_ref(input)
        .take(u64::try_from(maximum + 2).map_err(|_| "input limit overflow".to_owned())?);
    let bytes = limited
        .read_until(b'\n', &mut value)
        .map_err(|error| error.to_string())?;
    if bytes == 0 {
        return Err("unexpected end of input".to_owned());
    }
    if value.last() == Some(&b'\n') {
        value.pop();
        if value.last() == Some(&b'\r') {
            value.pop();
        }
    }
    if value.len() > maximum {
        return Err(format!("input exceeds {maximum} bytes"));
    }
    Ok(value)
}

fn hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(ALPHABET[usize::from(byte >> 4)]));
        encoded.push(char::from(ALPHABET[usize::from(byte & 0x0f)]));
    }
    encoded
}
