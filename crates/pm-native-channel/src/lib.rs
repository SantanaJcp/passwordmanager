// SPDX-License-Identifier: AGPL-3.0-only

//! Kernel-authenticated native channel capabilities.

use std::fmt;

#[cfg(target_os = "macos")]
mod macos_clipboard {
    unsafe extern "C" {
        fn pm_macos_clipboard_copy(bytes: *const u8, length: usize, change_count: *mut i64) -> i32;
        fn pm_macos_clipboard_clear_if_owned(change_count: i64) -> i32;
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct OwnedClipboard {
        change_count: i64,
    }

    impl OwnedClipboard {
        /// Copies explicit UTF-8 bytes to the macOS general pasteboard and
        /// records AppKit ownership through its change count.
        ///
        /// # Errors
        /// Rejects empty/invalid UTF-8 or an unavailable pasteboard.
        pub fn copy(value: &[u8]) -> Result<Self, super::ChannelAuthenticationError> {
            if value.is_empty() || std::str::from_utf8(value).is_err() {
                return Err(super::ChannelAuthenticationError);
            }
            let mut change_count = 0_i64;
            let result = unsafe {
                // SAFETY: value remains live for the synchronous bridge call
                // and change_count is a valid writable output.
                pm_macos_clipboard_copy(value.as_ptr(), value.len(), &raw mut change_count)
            };
            if result != 0 {
                return Err(super::ChannelAuthenticationError);
            }
            Ok(Self { change_count })
        }

        /// Clears the pasteboard only while this lease still owns it.
        ///
        /// # Errors
        /// Returns an error if AppKit cannot inspect or clear the pasteboard.
        pub fn clear_if_owned(self) -> Result<bool, super::ChannelAuthenticationError> {
            let result = unsafe {
                // SAFETY: the bridge accepts the scalar change count captured
                // from the same public NSPasteboard instance.
                pm_macos_clipboard_clear_if_owned(self.change_count)
            };
            match result {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(super::ChannelAuthenticationError),
            }
        }
    }
}

#[cfg(target_os = "macos")]
pub use macos_clipboard::OwnedClipboard;

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
    #[cfg(target_os = "macos")]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        let result = unsafe {
            // SAFETY: uid and gid are valid writable outputs and the descriptor
            // belongs to a connected Unix stream. getpeereid returns the
            // effective credentials captured by the Darwin kernel.
            libc::getpeereid(stream.as_raw_fd(), &raw mut uid, &raw mut gid)
        };
        if result != 0 {
            return Err(ChannelAuthenticationError);
        }
        Ok(uid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = stream;
        Err(ChannelAuthenticationError)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
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

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn peer_is_connected(_stream: &UnixStream) -> bool {
    false
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn getpeereid_is_bilateral_and_clipboard_clear_respects_new_owner() {
        let (left, right) = UnixStream::pair().unwrap();
        let uid = unsafe { libc::geteuid() };
        assert_eq!(unix_peer_uid(&left).unwrap(), uid);
        assert_eq!(unix_peer_uid(&right).unwrap(), uid);
        let first = OwnedClipboard::copy(b"ticket26-first-synthetic-canary").unwrap();
        let second = OwnedClipboard::copy(b"ticket26-new-owner-synthetic-canary").unwrap();
        assert!(!first.clear_if_owned().unwrap());
        assert!(second.clear_if_owned().unwrap());
    }
}
