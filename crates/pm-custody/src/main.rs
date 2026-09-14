// SPDX-License-Identifier: AGPL-3.0-only

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::{ffi::OsString, path::PathBuf, process::ExitCode};

#[cfg(any(target_os = "linux", target_os = "windows"))]
mod agent_wire;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod tui;
#[cfg(target_os = "windows")]
mod windows;

const CUSTODY_UNAVAILABLE: &str = "CUSTODY_UNAVAILABLE";

fn main() -> ExitCode {
    match run(std::env::args_os().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage) => {
            eprintln!("INVALID_ARGUMENT");
            ExitCode::from(2)
        }
        Err(Failure::Unavailable) => {
            eprintln!("{CUSTODY_UNAVAILABLE}");
            ExitCode::from(4)
        }
    }
}

#[derive(Clone, Copy)]
enum Failure {
    Usage,
    Unavailable,
}

fn run(arguments: Vec<OsString>) -> Result<(), Failure> {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        #[cfg(target_os = "linux")]
        return linux::run(arguments);
        #[cfg(target_os = "windows")]
        return windows::run(arguments);
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
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
