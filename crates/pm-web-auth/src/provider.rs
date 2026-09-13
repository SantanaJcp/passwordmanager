// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::Path,
    time::Duration,
};

use zeroize::{Zeroize, Zeroizing};

use crate::{Profile, browser};

const MAX_FRAME: usize = 128 * 1024;

#[derive(Debug)]
pub struct ServeError;

impl From<()> for ServeError {
    fn from((): ()) -> Self {
        Self
    }
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("web authentication provider unavailable")
    }
}

impl std::error::Error for ServeError {}

/// Serves the authenticated custodian-only provider socket.
///
/// # Errors
/// Returns `Err(())` when installed profile permissions, the socket directory,
/// framing, or a provider operation fails closed.
pub fn serve(
    profile_path: &Path,
    socket_path: &Path,
    custodian_uid: u32,
) -> Result<(), ServeError> {
    let bytes = read_private(profile_path)?;
    let profile = Profile::parse(&bytes).map_err(|_| ())?;
    let parent = socket_path.parent().ok_or(())?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| ())?;
    // The adapter owns its private runtime directory. The public socket is
    // connectable only so the separate custodian UID can reach it; SO_PEERCRED
    // rejects every other caller before reading a request.
    if !metadata.is_dir()
        || metadata.uid() != current_uid()
        || metadata.permissions().mode() & 0o066 != 0
    {
        return Err(ServeError);
    }
    if let Ok(existing) = fs::symlink_metadata(socket_path) {
        if !existing.file_type().is_socket() || existing.uid() != current_uid() {
            return Err(ServeError);
        }
        fs::remove_file(socket_path).map_err(|_| ())?;
    }
    let listener = UnixListener::bind(socket_path).map_err(|_| ())?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o666)).map_err(|_| ())?;
    let mut waiting = BTreeSet::new();
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        if peer_uid(&stream)? != custodian_uid {
            continue;
        }
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| ())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(|_| ())?;
        let Ok(mut request) = read_frame(&mut stream) else {
            continue;
        };
        let response = handle(&profile, &request, &mut waiting);
        request.zeroize();
        let _ = write_frame(&mut stream, &response);
    }
    Err(ServeError)
}

fn handle(profile: &Profile, request: &[u8], waiting: &mut BTreeSet<[u8; 16]>) -> Vec<u8> {
    let mut cursor = Cursor::new(request);
    let Ok(opcode) = cursor.byte() else {
        return response(4, b"");
    };
    let Ok(attempt) = cursor.fixed::<16>() else {
        return response(4, b"");
    };
    let Ok(_revision) = cursor.fixed::<16>() else {
        return response(4, b"");
    };
    if opcode == 2 {
        return if cursor.finish().is_ok() && waiting.contains(&attempt) {
            response(1, b"KEYCLOAK_HUMAN_REQUIRED")
        } else {
            response(3, b"")
        };
    }
    if opcode != 3 {
        return response(4, b"");
    }
    let parsed = (|| {
        let integration = cursor.text()?;
        let method = cursor.text()?;
        let destination = cursor.text()?;
        let context = cursor.text()?;
        let username = cursor.text()?.to_owned();
        let password = Zeroizing::new(cursor.bytes()?.to_vec());
        let secret = Zeroizing::new(cursor.bytes()?.to_vec());
        let algorithm = cursor.text()?.to_owned();
        let digits = cursor.byte()?;
        let period = u16::from_be_bytes(cursor.fixed::<2>()?);
        let t0 = u64::from_be_bytes(cursor.fixed::<8>()?);
        cursor.finish()?;
        if integration != "keycloak-browser-oidc"
            || !matches!(method, "password" | "password_totp")
            || destination != profile.profile_id()
            || context != profile.profile_id()
            || username != profile.value("expected_username")
            || password.is_empty()
        {
            return Err(());
        }
        let totp = if method == "password_totp" {
            if secret.is_empty()
                || !matches!(algorithm.as_str(), "SHA1" | "SHA256" | "SHA512")
                || !matches!(digits, 6 | 8)
                || !(15..=120).contains(&period)
                || t0 != 0
            {
                return Err(());
            }
            Some(browser::Totp {
                secret,
                algorithm,
                digits,
                period,
                t0,
            })
        } else {
            if !secret.is_empty() || !algorithm.is_empty() || digits != 0 || period != 0 || t0 != 0
            {
                return Err(());
            }
            None
        };
        Ok(browser::Credentials {
            username,
            password,
            totp,
        })
    })();
    let Ok(credentials) = parsed else {
        return response(4, b"");
    };
    match browser::authenticate(profile, &credentials) {
        Ok(browser::BrowserOutcome::Succeeded(result)) => response(0, &result),
        Ok(browser::BrowserOutcome::Waiting) => {
            waiting.insert(attempt);
            response(1, b"KEYCLOAK_HUMAN_REQUIRED")
        }
        Ok(browser::BrowserOutcome::Rejected) => response(2, b""),
        Ok(browser::BrowserOutcome::IntegrityFailure) => response(5, b""),
        Err(()) => response(4, b""),
    }
}

fn read_private(path: &Path) -> Result<Zeroizing<Vec<u8>>, ()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.file_type().is_file()
        || metadata.uid() != current_uid()
        || metadata.permissions().mode() & 0o177 != 0
    {
        return Err(());
    }
    let bytes = fs::read(path).map_err(|_| ())?;
    if bytes.len() > 16 * 1024 {
        return Err(());
    }
    Ok(Zeroizing::new(bytes))
}

fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

fn peer_uid(stream: &UnixStream) -> Result<u32, ()> {
    let mut credential = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length =
        libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>()).map_err(|_| ())?;
    // SAFETY: credential and length are valid writable buffers for SO_PEERCRED.
    let result = unsafe {
        libc::getsockopt(
            std::os::fd::AsRawFd::as_raw_fd(stream),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(credential).cast(),
            std::ptr::addr_of_mut!(length),
        )
    };
    if result != 0 || length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(());
    }
    Ok(credential.uid)
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, ()> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).map_err(|_| ())?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(());
    }
    let mut value = vec![0; length];
    stream.read_exact(&mut value).map_err(|_| ())?;
    Ok(value)
}

fn write_frame(stream: &mut UnixStream, value: &[u8]) -> Result<(), ()> {
    if value.is_empty() || value.len() > MAX_FRAME {
        return Err(());
    }
    stream
        .write_all(&u32::try_from(value.len()).map_err(|_| ())?.to_be_bytes())
        .and_then(|()| stream.write_all(value))
        .and_then(|()| stream.flush())
        .map_err(|_| ())
}

fn response(status: u8, value: &[u8]) -> Vec<u8> {
    let mut response = vec![status];
    response.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
    response.extend_from_slice(value);
    response
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn byte(&mut self) -> Result<u8, ()> {
        let value = *self.bytes.get(self.at).ok_or(())?;
        self.at += 1;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], ()> {
        let end = self.at.checked_add(N).ok_or(())?;
        let value = self.bytes.get(self.at..end).ok_or(())?;
        self.at = end;
        value.try_into().map_err(|_| ())
    }

    fn bytes(&mut self) -> Result<&'a [u8], ()> {
        let length = u32::from_be_bytes(self.fixed::<4>()?) as usize;
        let end = self.at.checked_add(length).ok_or(())?;
        let value = self.bytes.get(self.at..end).ok_or(())?;
        self.at = end;
        Ok(value)
    }

    fn text(&mut self) -> Result<&'a str, ()> {
        std::str::from_utf8(self.bytes()?).map_err(|_| ())
    }

    fn finish(&self) -> Result<(), ()> {
        (self.at == self.bytes.len()).then_some(()).ok_or(())
    }
}
