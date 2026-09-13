// SPDX-License-Identifier: AGPL-3.0-only

#![allow(dead_code)]

//! Native custody capabilities shared with vault-domain handlers.

extern crate self as pm_custody;

#[cfg(any(target_os = "linux", target_os = "windows"))]
mod agent_wire;

#[cfg(unix)]
pub use pm_native_channel::unix_peer_uid;
pub use pm_native_channel::{AuthenticatedHumanChannel, ChannelAuthenticationError};
#[cfg(target_os = "windows")]
pub use pm_native_channel::{WindowsClientPipe, WindowsEndpoint, WindowsServerPipe};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(any(target_os = "linux", target_os = "windows"))]
#[derive(Clone, Copy)]
enum Failure {
    Usage,
    Unavailable,
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
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
#[cfg(target_os = "linux")]
pub fn agent_rpc(
    profile: &std::path::Path,
    private: &std::path::Path,
    socket: &std::path::Path,
    request: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    linux::agent_rpc(profile, private, socket, request)
}

#[cfg(target_os = "windows")]
pub fn agent_rpc(
    profile: &std::path::Path,
    private: &std::path::Path,
    vault: &std::path::Path,
    request: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    windows::agent_rpc(profile, private, vault, request)
}
