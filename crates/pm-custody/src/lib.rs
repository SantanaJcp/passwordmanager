// SPDX-License-Identifier: AGPL-3.0-only

#![allow(dead_code)]

//! Native custody capabilities shared with vault-domain handlers.

extern crate self as pm_custody;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod agent_wire;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod connection_dispatch;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod custody_admission;

#[cfg(unix)]
pub use pm_native_channel::unix_peer_uid;
pub use pm_native_channel::{AuthenticatedHumanChannel, ChannelAuthenticationError};
#[cfg(target_os = "windows")]
pub use pm_native_channel::{WindowsClientPipe, WindowsEndpoint, WindowsServerPipe};

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod failure;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod human_wire;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod linux;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod sync_job;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod tui;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use failure::Failure;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn take_path(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
    flag: &str,
) -> Result<std::path::PathBuf, Failure> {
    match (arguments.next(), arguments.next()) {
        (Some(actual), Some(value)) if actual == flag => Ok(std::path::PathBuf::from(value)),
        _ => Err(Failure::Usage),
    }
}

/// Client-side authenticated delegated request. This is intentionally a
/// narrow binary bridge used by the shared CLI/MCP engine; the caller cannot
/// select a role or bypass the TLS/RPK profile.
///
/// # Errors
/// Returns a stable public category when profile, key, TLS, framing, or peer
/// authentication validation fails.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn agent_rpc(
    profile: &std::path::Path,
    private: &std::path::Path,
    socket: &std::path::Path,
    request: Option<&[u8]>,
) -> Result<pm_crypto::ProtectedBytes, String> {
    linux::agent_rpc(profile, private, socket, request)
}

#[cfg(target_os = "windows")]
pub fn agent_rpc(
    profile: &std::path::Path,
    private: &std::path::Path,
    vault: &std::path::Path,
    request: Option<&[u8]>,
) -> Result<pm_crypto::ProtectedBytes, String> {
    windows::agent_rpc(profile, private, vault, request)
}

/// Fixed public failure categories for the existing native human TUI.
#[derive(Debug)]
pub struct HumanTuiError {
    category: &'static str,
    exit_code: u8,
    cleanup_failed: bool,
}

impl HumanTuiError {
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        self.exit_code
    }
}

impl std::fmt::Display for HumanTuiError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.category)?;
        if self.cleanup_failed {
            formatter.write_str("\nCLEANUP_FAILED")?;
        }
        Ok(())
    }
}

impl std::error::Error for HumanTuiError {}

/// Opens the existing TUI in this process. Arguments select its installed
/// profile/key/endpoint and bounded timers; they never grant human authority.
/// The command is fixed here, so no custody administration command is exposed.
///
/// # Errors
/// Fails closed with fixed categories for invalid input, machine output mode,
/// missing native resources, authentication failure, or failed restoration.
pub fn human_tui(arguments: &[std::ffi::OsString]) -> Result<(), HumanTuiError> {
    if arguments.iter().any(|argument| argument == "--json") {
        return Err(HumanTuiError {
            category: "UNAUTHORIZED",
            exit_code: 3,
            cleanup_failed: false,
        });
    }
    #[cfg(unix)]
    pm_crypto::harden_unix_process().map_err(|_| HumanTuiError {
        category: "CUSTODY_UNAVAILABLE",
        exit_code: 4,
        cleanup_failed: false,
    })?;
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        let fixed_arguments = std::iter::once(std::ffi::OsString::from("tui"))
            .chain(arguments.iter().cloned())
            .collect();
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let result = linux::run(fixed_arguments);
        #[cfg(target_os = "windows")]
        let result = windows::run(fixed_arguments);
        result.map_err(|failure| {
            let (category, exit_code) = match failure.primary() {
                failure::PrimaryFailure::Usage => ("INVALID_ARGUMENT", 2),
                failure::PrimaryFailure::Unavailable => ("CUSTODY_UNAVAILABLE", 4),
                failure::PrimaryFailure::DestinationExists => ("DESTINATION_EXISTS", 4),
            };
            HumanTuiError {
                category,
                exit_code,
                cleanup_failed: !failure.cleanups().is_empty(),
            }
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    Err(HumanTuiError {
        category: "CUSTODY_UNAVAILABLE",
        exit_code: 4,
        cleanup_failed: false,
    })
}
