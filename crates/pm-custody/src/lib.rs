// SPDX-License-Identifier: AGPL-3.0-only

//! Native custody capabilities shared with vault-domain handlers.

use std::fmt;

#[cfg(unix)]
use std::os::{fd::AsRawFd, unix::net::UnixStream};

/// A native channel whose peer matches the human endpoint configuration.
pub struct AuthenticatedHumanChannel {
    #[cfg(unix)]
    stream: UnixStream,
    expected_uid: u32,
}

impl AuthenticatedHumanChannel {
    /// Binds a live Unix connection to the kernel-observed configured human UID.
    /// Request bodies do not supply a role or peer identity.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel credential differs from `expected_uid`.
    #[cfg(unix)]
    pub fn authenticate(
        stream: UnixStream,
        expected_uid: u32,
    ) -> Result<Self, ChannelAuthenticationError> {
        if unix_peer_uid(&stream)? != expected_uid {
            return Err(ChannelAuthenticationError);
        }
        Ok(Self {
            stream,
            expected_uid,
        })
    }

    /// Revalidates the bound credential and rejects a disconnected peer.
    ///
    /// # Errors
    ///
    /// Returns an error if the channel is no longer the configured live peer.
    pub fn verify(&self) -> Result<(), ChannelAuthenticationError> {
        #[cfg(unix)]
        {
            if unix_peer_uid(&self.stream)? != self.expected_uid || !peer_is_connected(&self.stream)
            {
                return Err(ChannelAuthenticationError);
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = self.expected_uid;
            Err(ChannelAuthenticationError)
        }
    }
}

/// Deliberately opaque public failure for an untrusted local channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelAuthenticationError;

impl fmt::Display for ChannelAuthenticationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("local peer is not authenticated")
    }
}

impl std::error::Error for ChannelAuthenticationError {}

/// Returns the peer UID supplied by the kernel, never by a request.
///
/// # Errors
///
/// Returns an opaque error when native peer credentials are unavailable.
#[cfg(unix)]
pub fn unix_peer_uid(stream: &UnixStream) -> Result<u32, ChannelAuthenticationError> {
    #[cfg(target_os = "linux")]
    {
        let mut credentials = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut length = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
            .map_err(|_| ChannelAuthenticationError)?;
        let result = unsafe {
            // SAFETY: credentials and length are valid writable buffers and the
            // descriptor belongs to the live Unix stream.
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&raw mut credentials).cast(),
                &raw mut length,
            )
        };
        if result != 0 || usize::try_from(length).ok() != Some(std::mem::size_of::<libc::ucred>()) {
            return Err(ChannelAuthenticationError);
        }
        Ok(credentials.uid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = stream;
        Err(ChannelAuthenticationError)
    }
}

#[cfg(target_os = "linux")]
fn peer_is_connected(stream: &UnixStream) -> bool {
    let mut byte = 0_u8;
    let result = unsafe {
        // SAFETY: `byte` is valid for one byte and MSG_PEEK does not consume
        // application data from the authenticated transport.
        libc::recv(
            stream.as_raw_fd(),
            (&raw mut byte).cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if result > 0 {
        return true;
    }
    result < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock
}

#[cfg(all(unix, not(target_os = "linux")))]
fn peer_is_connected(_stream: &UnixStream) -> bool {
    false
}
