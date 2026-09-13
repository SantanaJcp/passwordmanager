// SPDX-License-Identifier: AGPL-3.0-only

use std::{path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(command) = args.next() else {
        return ExitCode::from(2);
    };
    if command != "serve" {
        return ExitCode::from(2);
    }
    let mut profile = None;
    let mut socket = None;
    let mut uid = None;
    while let (Some(flag), Some(value)) = (args.next(), args.next()) {
        match flag.to_str() {
            Some("--profile") => profile = Some(PathBuf::from(value)),
            Some("--socket") => socket = Some(PathBuf::from(value)),
            Some("--custodian-uid") => {
                uid = value.to_str().and_then(|text| text.parse::<u32>().ok());
            }
            _ => return ExitCode::from(2),
        }
    }
    let (Some(profile), Some(socket), Some(uid)) = (profile, socket, uid) else {
        return ExitCode::from(2);
    };
    match pm_web_auth::serve(&profile, &socket, uid) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(4),
    }
}
