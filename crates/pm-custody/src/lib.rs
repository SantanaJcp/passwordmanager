// SPDX-License-Identifier: AGPL-3.0-only

#![allow(dead_code)]

//! Native custody capabilities shared with vault-domain handlers.

extern crate self as pm_custody;

pub use pm_native_channel::{AuthenticatedHumanChannel, ChannelAuthenticationError, unix_peer_uid};

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod linux;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Clone, Copy)]
enum Failure {
    Usage,
    Unavailable,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
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
) -> Result<Vec<u8>, String> {
    linux::agent_rpc(profile, private, socket, request)
}
