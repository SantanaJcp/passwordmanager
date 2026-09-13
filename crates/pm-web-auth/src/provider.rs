// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    collections::{BTreeMap, BTreeSet},
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

use crate::{ExchangeProfile, GithubProfile, Profile, browser, exchange, github};

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
    let profile = match (
        Profile::parse(&bytes),
        ExchangeProfile::parse(&bytes),
        GithubProfile::parse(&bytes),
    ) {
        (Ok(profile), Err(_), Err(_)) => InstalledProfile::Browser(profile),
        (Err(_), Ok(profile), Err(_)) => InstalledProfile::Exchange(profile),
        (Err(_), Err(_), Ok(profile)) => InstalledProfile::Github(profile),
        _ => return Err(ServeError),
    };
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
    let mut passkey_sessions = BTreeMap::new();
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
        let response = Zeroizing::new(handle(
            &profile,
            &request,
            &mut waiting,
            &mut passkey_sessions,
        ));
        request.zeroize();
        let _ = write_frame(&mut stream, &response);
    }
    Err(ServeError)
}

enum InstalledProfile {
    Browser(Profile),
    Exchange(ExchangeProfile),
    Github(GithubProfile),
}

fn handle(
    profile: &InstalledProfile,
    request: &[u8],
    waiting: &mut BTreeSet<[u8; 16]>,
    passkey_sessions: &mut BTreeMap<[u8; 16], browser::PasskeySession>,
) -> Vec<u8> {
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
        if cursor.finish().is_err() {
            return response(4, b"");
        }
        return match profile {
            InstalledProfile::Browser(profile) if profile.is_passkey() => {
                reconcile(profile, attempt, waiting, passkey_sessions)
            }
            InstalledProfile::Browser(_) if waiting.contains(&attempt) => {
                response(1, b"KEYCLOAK_HUMAN_REQUIRED")
            }
            InstalledProfile::Browser(_)
            | InstalledProfile::Exchange(_)
            | InstalledProfile::Github(_) => response(3, b""),
        };
    }
    match (profile, opcode) {
        (InstalledProfile::Browser(profile), 3) if !profile.is_passkey() => {
            handle_browser(profile, cursor, attempt, waiting)
        }
        (InstalledProfile::Browser(profile), 4) if profile.is_passkey() => {
            handle_passkey(profile, attempt, &mut cursor, passkey_sessions)
        }
        (InstalledProfile::Exchange(profile), 4) => handle_exchange(profile, cursor),
        (InstalledProfile::Github(profile), 5) => handle_github(profile, cursor),
        _ => response(4, b""),
    }
}

fn handle_github(profile: &GithubProfile, mut cursor: Cursor<'_>) -> Vec<u8> {
    let parsed = (|| {
        let integration = cursor.text()?;
        let method = cursor.text()?;
        let destination = cursor.text()?;
        let context = cursor.bytes()?;
        let token = Zeroizing::new(cursor.bytes()?.to_vec());
        cursor.finish()?;
        if integration != "github-rest-bearer"
            || method != "bearer"
            || destination != profile.profile_id()
        {
            return Err(());
        }
        Ok((context, token))
    })();
    let Ok((context, token)) = parsed else {
        return response(4, b"");
    };
    match github::perform(profile, &token, context) {
        Ok(github::GithubOutcome::Succeeded(result)) => response(0, &result),
        Ok(github::GithubOutcome::WaitingForSso) => response(1, b"GITHUB_SSO_REQUIRED"),
        Ok(github::GithubOutcome::Rejected) => response(2, b""),
        Ok(github::GithubOutcome::Indeterminate) => response(3, b""),
        Ok(github::GithubOutcome::IntegrityFailure) | Err(()) => response(5, b""),
        Ok(github::GithubOutcome::RateLimited) => response(6, b""),
    }
}

fn handle_browser(
    profile: &Profile,
    mut cursor: Cursor<'_>,
    attempt: [u8; 16],
    waiting: &mut BTreeSet<[u8; 16]>,
) -> Vec<u8> {
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

fn handle_exchange(profile: &ExchangeProfile, mut cursor: Cursor<'_>) -> Vec<u8> {
    let parsed = (|| {
        let integration = cursor.text()?;
        let method = cursor.text()?;
        let destination = cursor.text()?;
        let context = cursor.text()?;
        let requester_client_id = cursor.text()?.to_owned();
        let requester_client_secret = Zeroizing::new(cursor.bytes()?.to_vec());
        let subject_token = Zeroizing::new(cursor.bytes()?.to_vec());
        cursor.finish()?;
        if integration != "keycloak-token-exchange"
            || method != "token_exchange"
            || destination != profile.profile_id()
            || context != profile.profile_id()
            || requester_client_id != profile.requester_client_id()
        {
            return Err(());
        }
        Ok((requester_client_id, requester_client_secret, subject_token))
    })();
    let Ok((requester_client_id, requester_client_secret, subject_token)) = parsed else {
        return response(4, b"");
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_secs()).ok());
    let Some(now) = now else {
        return response(3, b"");
    };
    let credential = exchange::ExchangeCredential {
        subject_token: &subject_token,
        requester_client_id: &requester_client_id,
        requester_client_secret: &requester_client_secret,
    };
    match exchange::perform(profile, &credential, now) {
        Ok(result) => response(0, &result.encode()),
        Err(exchange::ExchangeError::Network) => response(3, b""),
        Err(exchange::ExchangeError::InvalidResponse) => response(2, b""),
        Err(exchange::ExchangeError::InvalidToken | exchange::ExchangeError::SecretReflection) => {
            response(5, b"")
        }
    }
}

fn reconcile(
    profile: &Profile,
    attempt: [u8; 16],
    waiting: &BTreeSet<[u8; 16]>,
    sessions: &mut BTreeMap<[u8; 16], browser::PasskeySession>,
) -> Vec<u8> {
    let Some(session) = sessions.get_mut(&attempt) else {
        return if waiting.contains(&attempt) {
            response(1, b"KEYCLOAK_HUMAN_REQUIRED")
        } else {
            response(5, b"")
        };
    };
    let outcome = session.poll(profile);
    if matches!(outcome, Ok(browser::BrowserOutcome::Waiting)) {
        return response(1, b"PASSKEY_HUMAN_CONFIRMATION");
    }
    sessions.remove(&attempt);
    match outcome {
        Ok(browser::BrowserOutcome::Succeeded(result)) => response(0, &result),
        Ok(browser::BrowserOutcome::Rejected) => response(2, b""),
        Ok(browser::BrowserOutcome::IntegrityFailure) | Err(()) => response(5, b""),
        Ok(browser::BrowserOutcome::Waiting) => unreachable!(),
    }
}

fn handle_passkey(
    profile: &Profile,
    attempt: [u8; 16],
    cursor: &mut Cursor<'_>,
    sessions: &mut BTreeMap<[u8; 16], browser::PasskeySession>,
) -> Vec<u8> {
    let parsed = (|| {
        let integration = cursor.text()?;
        let method = cursor.text()?;
        let destination = cursor.text()?;
        let context = cursor.text()?;
        let username = cursor.text()?.to_owned();
        let password = cursor.bytes()?;
        let item = cursor.fixed::<16>()?;
        cursor.finish()?;
        let issuer = profile.url("issuer").map_err(|_| ())?;
        let origin = format!("https://{}:{}", issuer.host(), issuer.port());
        if !profile.is_passkey()
            || integration != "keycloak-webauthn"
            || method != "webauthn"
            || destination != origin
            || context != profile.profile_id()
            || username != profile.value("expected_username")
            || !password.is_empty()
        {
            return Err(());
        }
        Ok((username, item))
    })();
    let Ok((username, item)) = parsed else {
        eprintln!("WEB_AUTH_FAIL stage=passkey-request");
        return response(4, b"");
    };
    match browser::authenticate_passkey(profile, &username, item) {
        Ok((browser::BrowserOutcome::Waiting, Some(session))) => {
            sessions.insert(attempt, session);
            response(1, b"PASSKEY_HUMAN_CONFIRMATION")
        }
        Ok((browser::BrowserOutcome::Succeeded(result), None)) => response(0, &result),
        Ok((browser::BrowserOutcome::Rejected, None)) => response(2, b""),
        Ok((browser::BrowserOutcome::IntegrityFailure, None)) => response(5, b""),
        _ => {
            eprintln!("WEB_AUTH_FAIL stage=passkey-browser-start");
            response(4, b"")
        }
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
    #[cfg(target_os = "linux")]
    {
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
    #[cfg(target_os = "macos")]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        let result = unsafe {
            // SAFETY: outputs are valid and stream is a connected Unix socket.
            libc::getpeereid(
                std::os::fd::AsRawFd::as_raw_fd(stream),
                &raw mut uid,
                &raw mut gid,
            )
        };
        (result == 0).then_some(uid).ok_or(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = stream;
        Err(())
    }
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
