// SPDX-License-Identifier: AGPL-3.0-only

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::{ffi::OsString, path::PathBuf, process::ExitCode};

mod failure;
#[cfg(target_os = "linux")]
mod linux;

use failure::{CleanupFailureKind, Failure, PrimaryFailure};

const CUSTODY_UNAVAILABLE: &str = "CUSTODY_UNAVAILABLE";

fn main() -> ExitCode {
    #[cfg(unix)]
    {
        if pm_crypto::harden_unix_process().is_err() {
            eprintln!("{CUSTODY_UNAVAILABLE}");
            return ExitCode::from(4);
        }
    }
    match run(std::env::args_os().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            let code = match failure.primary() {
                PrimaryFailure::Usage => {
                    eprintln!("INVALID_ARGUMENT");
                    2
                }
                PrimaryFailure::Unavailable => {
                    eprintln!("{CUSTODY_UNAVAILABLE}");
                    4
                }
            };
            if !failure.cleanups().is_empty() {
                for cleanup in failure.cleanups() {
                    match cleanup.kind {
                        CleanupFailureKind::OwnedPathRemoval => {}
                    }
                    let _ = cleanup.source.kind();
                }
                eprintln!("CLEANUP_FAILED");
            }
            ExitCode::from(code)
        }
    }
}

fn run(arguments: Vec<OsString>) -> Result<(), Failure> {
    #[cfg(target_os = "linux")]
    {
        linux::run(arguments)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = arguments;
        Err(Failure::Unavailable)
    }
}

fn take_path(
    arguments: &mut impl Iterator<Item = OsString>,
    flag: &str,
) -> Result<PathBuf, Failure> {
    match (arguments.next(), arguments.next()) {
        (Some(actual), Some(value)) if actual == flag => Ok(PathBuf::from(value)),
        _ => Err(Failure::Usage),
    }
}
