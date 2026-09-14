// SPDX-License-Identifier: AGPL-3.0-only

//! Kernel-authenticated native channel capabilities.

use std::fmt;

mod native_file;
pub use native_file::{create_private_file, open_regular_file, sync_directory};

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::{
    ConPty, OwnedClipboard, WindowsClientPipe, WindowsServerPipe, WindowsStopEvent,
    dpapi_protect_machine, dpapi_unprotect, windows_named_pipe_available,
};

/// One of the two Windows named-pipe endpoints. Roles are fixed by the
/// installed endpoint rather than supplied by a request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsEndpoint {
    Agent,
    Human,
}

impl WindowsEndpoint {
    /// Constructs the fixed local pipe name for an installed vault identifier.
    ///
    /// # Errors
    /// Rejects identifiers outside the closed lowercase hexadecimal form.
    pub fn pipe_name(self, vault: &str) -> Result<String, ChannelAuthenticationError> {
        if vault.len() != 32
            || !vault
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ChannelAuthenticationError);
        }
        let role = match self {
            Self::Agent => "agent",
            Self::Human => "human",
        };
        Ok(format!(r"\\.\pipe\PasswordManager-{vault}-{role}"))
    }
}

/// Builds the protected DACL used for one Windows pipe. SYSTEM and the
/// service SID own/control it; the one configured client SID gets read/write.
///
/// # Errors
/// Rejects aliases, broad principals and malformed SID text.
pub fn windows_pipe_sddl(
    service_sid: &str,
    client_sid: &str,
) -> Result<String, ChannelAuthenticationError> {
    if !valid_specific_sid(service_sid, "S-1-5-80-") || !valid_specific_sid(client_sid, "S-1-5-21-")
    {
        return Err(ChannelAuthenticationError);
    }
    Ok(format!(
        "O:{service_sid}G:{service_sid}D:P(A;;GA;;;SY)(A;;GA;;;{service_sid})(A;;GRGW;;;{client_sid})"
    ))
}

fn valid_specific_sid(value: &str, prefix: &str) -> bool {
    value.starts_with(prefix)
        && value.len() > prefix.len()
        && value
            .split('-')
            .skip(1)
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

#[cfg(unix)]
use std::os::{fd::AsRawFd, unix::net::UnixStream};

/// A native channel whose peer matches the human endpoint configuration.
pub struct AuthenticatedHumanChannel {
    #[cfg(all(unix, not(target_os = "windows")))]
    stream: UnixStream,
    #[cfg(target_os = "windows")]
    pipe: WindowsServerPipe,
    #[cfg(all(unix, not(target_os = "windows")))]
    expected_uid: u32,
}

impl AuthenticatedHumanChannel {
    /// Binds a live Unix connection to the kernel-observed configured human UID.
    /// Request bodies do not supply a role or peer identity.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel credential differs from `expected_uid`.
    #[cfg(all(unix, not(target_os = "windows")))]
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

    /// Accepts and binds the configured Windows human pipe to its
    /// kernel-observed client SID and process.
    ///
    /// # Errors
    /// Returns an error if connection, impersonation or SID validation fails.
    #[cfg(target_os = "windows")]
    pub fn authenticate_windows(
        mut pipe: WindowsServerPipe,
    ) -> Result<Self, ChannelAuthenticationError> {
        pipe.accept()?;
        Ok(Self { pipe })
    }

    /// Revalidates the bound credential and rejects a disconnected peer.
    ///
    /// # Errors
    ///
    /// Returns an error if the channel is no longer the configured live peer.
    pub fn verify(&self) -> Result<(), ChannelAuthenticationError> {
        #[cfg(all(unix, not(target_os = "windows")))]
        {
            if unix_peer_uid(&self.stream)? != self.expected_uid || !peer_is_connected(&self.stream)
            {
                return Err(ChannelAuthenticationError);
            }
            Ok(())
        }
        #[cfg(any(not(unix), target_os = "windows"))]
        {
            #[cfg(target_os = "windows")]
            {
                self.pipe.verify()
            }
            #[cfg(not(target_os = "windows"))]
            {
                Err(ChannelAuthenticationError)
            }
        }
    }

    /// Claims a regular file handle from the already-authenticated Windows
    /// human process without reopening its path.
    ///
    /// # Errors
    /// Returns an opaque error if the peer changed or the handle is not a
    /// regular, non-reparse file.
    #[cfg(target_os = "windows")]
    pub fn duplicate_client_file(
        &self,
        source_value: u64,
    ) -> Result<std::fs::File, ChannelAuthenticationError> {
        self.pipe.verify()?;
        self.pipe.duplicate_client_file(source_value)
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

#[cfg(all(target_os = "linux", not(target_os = "windows")))]
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
