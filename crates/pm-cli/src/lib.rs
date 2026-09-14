// SPDX-License-Identifier: AGPL-3.0-only

//! Human vault bootstrap and delegated CLI/MCP presentation adapters.

use pm_crypto::{KdfProfile, ProtectedBytes, RecoveryCode};
use pm_custody::agent_rpc;
use pm_interface::{
    Engine, ErrorCode, Json, Request, capabilities_result, dispatch, encode_json,
    github_request_context, parse_mcp_request, public_attempt_result,
};
use pm_vault::{PendingVault, open_vault};
use std::{
    ffi::OsString,
    fmt::Write as FmtWrite,
    io::{self, BufRead, Read, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
struct NativeStdin {
    descriptor: std::os::fd::RawFd,
}

#[cfg(unix)]
impl NativeStdin {
    fn open() -> io::Result<Self> {
        let descriptor = libc::STDIN_FILENO;
        // SAFETY: F_GETFD only inspects the process-owned descriptor number.
        if unsafe { libc::fcntl(descriptor, libc::F_GETFD) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { descriptor })
    }
}

#[cfg(unix)]
impl Read for NativeStdin {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        // SAFETY: `buffer` is writable for its length and this type borrows,
        // but never closes or transfers ownership of, the stdin descriptor.
        let bytes =
            unsafe { libc::read(self.descriptor, buffer.as_mut_ptr().cast(), buffer.len()) };
        if bytes < 0 {
            Err(io::Error::last_os_error())
        } else {
            usize::try_from(bytes).map_err(|_| io::Error::other("invalid native stdin length"))
        }
    }
}

#[cfg(windows)]
struct NativeStdin {
    handle: windows_sys::Win32::Foundation::HANDLE,
    kind: NativeStdinKind,
}

#[cfg(windows)]
enum NativeStdinKind {
    Missing,
    Raw,
    Console {
        wide: ProtectedBytes,
        wide_prefix: usize,
        pending: ProtectedBytes,
        pending_start: usize,
        pending_len: usize,
    },
}

#[cfg(windows)]
impl NativeStdin {
    fn open() -> io::Result<Self> {
        use windows_sys::Win32::{
            Foundation::INVALID_HANDLE_VALUE,
            System::Console::{GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE},
        };

        // SAFETY: GetStdHandle returns a borrowed process standard handle.
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if handle.is_null() {
            return Ok(Self {
                handle,
                kind: NativeStdinKind::Missing,
            });
        }
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let mut mode = 0_u32;
        // SAFETY: `mode` is writable and a successful call classifies the
        // borrowed standard handle as a Windows console rather than pipe/file.
        let console = unsafe { GetConsoleMode(handle, &raw mut mode) } != 0;
        let kind = if console {
            NativeStdinKind::Console {
                wide: ProtectedBytes::zeroed(4).map_err(io::Error::other)?,
                wide_prefix: 0,
                pending: ProtectedBytes::zeroed(8).map_err(io::Error::other)?,
                pending_start: 0,
                pending_len: 0,
            }
        } else {
            NativeStdinKind::Raw
        };
        Ok(Self { handle, kind })
    }
}

#[cfg(windows)]
impl Read for NativeStdin {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match &mut self.kind {
            NativeStdinKind::Missing => Ok(0),
            NativeStdinKind::Raw => read_windows_raw(self.handle, buffer),
            NativeStdinKind::Console {
                wide,
                wide_prefix,
                pending,
                pending_start,
                pending_len,
            } => read_windows_console(
                self.handle,
                wide,
                wide_prefix,
                pending,
                pending_start,
                pending_len,
                buffer,
            ),
        }
    }
}

#[cfg(windows)]
fn read_windows_raw(
    handle: windows_sys::Win32::Foundation::HANDLE,
    buffer: &mut [u8],
) -> io::Result<usize> {
    use windows_sys::Win32::Storage::FileSystem::ReadFile;

    let requested = u32::try_from(buffer.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "native stdin read is too large",
        )
    })?;
    let mut bytes = 0_u32;
    // SAFETY: `handle` is borrowed and valid, `buffer` is writable for the
    // requested length, and the synchronous call does not use OVERLAPPED.
    let result = unsafe {
        ReadFile(
            handle,
            buffer.as_mut_ptr(),
            requested,
            &raw mut bytes,
            std::ptr::null_mut(),
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        usize::try_from(bytes).map_err(|_| io::Error::other("invalid native stdin length"))
    }
}

#[cfg(windows)]
fn read_windows_console(
    handle: windows_sys::Win32::Foundation::HANDLE,
    wide: &mut ProtectedBytes,
    wide_prefix: &mut usize,
    pending: &mut ProtectedBytes,
    pending_start: &mut usize,
    pending_len: &mut usize,
    buffer: &mut [u8],
) -> io::Result<usize> {
    use windows_sys::Win32::{
        Foundation::{ERROR_OPERATION_ABORTED, GetLastError, SetLastError},
        Globalization::{CP_UTF8, WC_ERR_INVALID_CHARS, WideCharToMultiByte},
        System::Console::{CONSOLE_READCONSOLE_CONTROL, ReadConsoleW},
    };

    if buffer.is_empty() {
        return Ok(0);
    }
    loop {
        if *pending_start < *pending_len {
            let available = *pending_len - *pending_start;
            let copied = available.min(buffer.len());
            for (destination, source) in buffer[..copied]
                .iter_mut()
                .zip(&mut pending[*pending_start..*pending_start + copied])
            {
                *destination = *source;
                *source = 0;
            }
            *pending_start += copied;
            return Ok(copied);
        }

        *pending_start = 0;
        *pending_len = 0;
        let mut control = CONSOLE_READCONSOLE_CONTROL {
            nLength: u32::try_from(std::mem::size_of::<CONSOLE_READCONSOLE_CONTROL>())
                .map_err(|_| io::Error::other("invalid console control size"))?,
            nInitialChars: 0,
            dwCtrlWakeupMask: 1 << 0x1a,
            dwControlKeyState: 0,
        };
        let mut units = 0_u32;
        // SAFETY: the locked `wide` allocation is aligned and writable at
        // `wide_prefix` for one UTF-16 unit; the borrowed handle and control
        // remain valid for the synchronous call.
        unsafe { SetLastError(0) };
        let result = unsafe {
            ReadConsoleW(
                handle,
                wide.as_mut_ptr().add(*wide_prefix * 2).cast(),
                1,
                &raw mut units,
                &raw mut control,
            )
        };
        if result == 0 {
            wide.fill(0);
            return Err(io::Error::last_os_error());
        }
        if units == 0 {
            if unsafe { GetLastError() } == ERROR_OPERATION_ABORTED {
                continue;
            }
            return Ok(0);
        }
        let units =
            usize::try_from(units).map_err(|_| io::Error::other("invalid console input length"))?;
        if units != 1 {
            wide.fill(0);
            *wide_prefix = 0;
            return Err(io::Error::other("invalid console input length"));
        }
        // SAFETY: ReadConsoleW initialized the one unit at `wide_prefix`.
        let unit = unsafe { *wide.as_ptr().cast::<u16>().add(*wide_prefix) };
        if *wide_prefix == 0 && unit == 0x1a {
            wide.fill(0);
            return Ok(0);
        }
        if *wide_prefix == 0 && (0xd800..=0xdbff).contains(&unit) {
            *wide_prefix = 1;
            continue;
        }
        let unit_count = *wide_prefix + 1;
        let unit_count_i32 = i32::try_from(unit_count)
            .map_err(|_| io::Error::other("invalid console input length"))?;
        // SAFETY: input names initialized locked UTF-16 units; output names an
        // eight-byte locked buffer, enough for two UTF-16 units as UTF-8.
        let converted = unsafe {
            WideCharToMultiByte(
                CP_UTF8,
                WC_ERR_INVALID_CHARS,
                wide.as_ptr().cast(),
                unit_count_i32,
                pending.as_mut_ptr(),
                8,
                std::ptr::null(),
                std::ptr::null_mut(),
            )
        };
        wide.fill(0);
        *wide_prefix = 0;
        if converted == 0 {
            pending.fill(0);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows console input contains invalid UTF-16",
            ));
        }
        *pending_len = usize::try_from(converted)
            .map_err(|_| io::Error::other("invalid console UTF-8 length"))?;
    }
}

#[derive(Debug)]
pub struct CliError {
    message: String,
    code: u8,
}
impl CliError {
    fn new(message: impl Into<String>, code: u8) -> Self {
        Self {
            message: message.into(),
            code,
        }
    }
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        self.code
    }
}
impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for CliError {}

/// # Errors
/// Returns a category-safe error for invalid arguments or unavailable custody.
pub fn run(arguments: &[OsString]) -> Result<(), CliError> {
    #[cfg(unix)]
    pm_crypto::harden_unix_process().map_err(|_| CliError::new("RESOURCE_UNAVAILABLE", 5))?;
    match arguments {
        [flag] if flag == "--version" => {
            println!(
                "passwordmanager {} (libsodium {})",
                env!("CARGO_PKG_VERSION"),
                pm_crypto::linked_libsodium_version().to_string_lossy()
            );
            Ok(())
        }
        [group, command, path] if group == "vault" && command == "create" => {
            create(Path::new(path)).map_err(|e| CliError::new(e, 5))
        }
        [group, command, path] if group == "vault" && command == "open" => {
            open(Path::new(path)).map_err(|e| CliError::new(e, 5))
        }
        _ => delegated(arguments),
    }
}

fn delegated(arguments: &[OsString]) -> Result<(), CliError> {
    let json = arguments.iter().any(|value| value == "--json");
    let (values, config) = parse_transport_options(arguments)?;
    if values.iter().any(|value| {
        matches!(
            value.to_str(),
            Some("tui" | "reveal" | "export" | "generic-sign" | "sign")
        )
    }) {
        return Err(CliError::new("UNAUTHORIZED", 3));
    }
    let method = match (
        values.first().and_then(|v| v.to_str()),
        values.get(1).and_then(|v| v.to_str()),
    ) {
        (Some("capabilities"), None) => "pm.v1.capabilities",
        (Some("credentials"), Some("list")) => "pm.v1.credentials.discover",
        (Some("auth"), Some("start")) => "pm.v1.authentication.start",
        (Some("auth"), Some("status")) => "pm.v1.authentication.get",
        (Some("auth"), Some("cancel")) => "pm.v1.authentication.cancel",
        (Some("mcp"), None) => return run_mcp(),
        _ => return Err(CliError::new("INVALID_ARGUMENT", 2)),
    };
    let request = Request {
        id: "cli-1".into(),
        method: method.into(),
        params: params_for_cli(&values)?,
    };
    let response = if let Some(config) = config {
        dispatch(&request, &AgentEngine { config })
    } else if let Ok(engine) = AgentEngine::from_environment() {
        dispatch(&request, &engine)
    } else {
        dispatch(&request, &UnavailableEngine)
    };
    if json {
        println!(
            "{}",
            String::from_utf8(encode_json(&response)).expect("JSON encoder emits UTF-8")
        );
        if response.field("error").is_some() {
            Err(CliError::new("CUSTODY_UNAVAILABLE", 4))
        } else {
            Ok(())
        }
    } else {
        Err(CliError::new("CUSTODY_UNAVAILABLE", 4))
    }
}

struct UnavailableEngine;
impl Engine for UnavailableEngine {
    fn call(&self, _method: &str, _params: &Json) -> Result<Json, ErrorCode> {
        Err(ErrorCode::CustodyUnavailable)
    }
}

#[derive(Clone)]
struct TransportConfig {
    profile: PathBuf,
    private: PathBuf,
    socket: PathBuf,
}
impl TransportConfig {
    fn missing() -> Self {
        Self {
            profile: PathBuf::new(),
            private: PathBuf::new(),
            socket: PathBuf::new(),
        }
    }
    fn valid(&self) -> bool {
        !self.profile.as_os_str().is_empty()
            && !self.private.as_os_str().is_empty()
            && !self.socket.as_os_str().is_empty()
    }
}

fn parse_transport_options(
    arguments: &[OsString],
) -> Result<(Vec<OsString>, Option<TransportConfig>), CliError> {
    let mut values = Vec::new();
    let mut profile = None;
    let mut private = None;
    let mut socket = None;
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] == "--json" {
            index += 1;
            continue;
        }
        let target = match arguments[index].to_str() {
            Some("--profile") => &mut profile,
            Some("--private") => &mut private,
            Some("--socket") => &mut socket,
            _ => {
                values.push(arguments[index].clone());
                index += 1;
                continue;
            }
        };
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| CliError::new("INVALID_ARGUMENT", 2))?;
        *target = Some(PathBuf::from(value));
        index += 2;
    }
    let config = match (profile, private, socket) {
        (Some(profile), Some(private), Some(socket)) => Some(TransportConfig {
            profile,
            private,
            socket,
        }),
        (None, None, None) => None,
        _ => return Err(CliError::new("INVALID_ARGUMENT", 2)),
    };
    Ok((values, config))
}

fn params_for_cli(values: &[OsString]) -> Result<Json, CliError> {
    if values.len() <= 2 {
        return Ok(Json::Object(Vec::new()));
    }
    let mut fields = Vec::new();
    let mut github_context = Vec::new();
    let mut index = 2;
    while index < values.len() {
        let key = values[index]
            .to_str()
            .and_then(|value| value.strip_prefix("--"))
            .ok_or_else(|| CliError::new("INVALID_ARGUMENT", 2))?;
        let value = values
            .get(index + 1)
            .and_then(|value| value.to_str())
            .ok_or_else(|| CliError::new("INVALID_ARGUMENT", 2))?;
        let json = if matches!(key, "integration-version" | "page" | "per-page") {
            Json::Number(
                value
                    .parse::<u64>()
                    .map_err(|_| CliError::new("INVALID_ARGUMENT", 2))?
                    .to_string(),
            )
        } else {
            Json::String(value.to_owned())
        };
        if ![
            "credential-id",
            "attempt-id",
            "attempt",
            "integration-id",
            "integration-version",
            "method",
            "destination",
            "context",
            "request-profile",
            "filter",
            "state",
            "sort",
            "direction",
            "page",
            "per-page",
            "issued-at",
            "nonce",
        ]
        .contains(&key)
        {
            return Err(CliError::new("INVALID_ARGUMENT", 2));
        }
        let normalized = if key == "attempt" {
            "attempt_id".to_owned()
        } else {
            key.replace('-', "_")
        };
        if matches!(
            normalized.as_str(),
            "request_profile" | "filter" | "state" | "sort" | "direction" | "page" | "per_page"
        ) {
            github_context.push((normalized, json));
        } else if normalized == "issued_at" || normalized == "nonce" {
            // these belong to the nested idempotency object below
            let idempotency = fields
                .iter_mut()
                .find(|(name, _)| name == "idempotency_key");
            if let Some((_, Json::Object(values))) = idempotency {
                values.push((normalized, json));
            } else {
                fields.push((
                    "idempotency_key".into(),
                    Json::Object(vec![(normalized, json)]),
                ));
            }
        } else {
            fields.push((normalized, json));
        }
        index += 2;
    }
    if !github_context.is_empty() {
        let integration = fields
            .iter()
            .find(|(name, _)| name == "integration_id")
            .and_then(|(_, value)| value.string());
        if integration != Some("github-rest-bearer")
            || fields.iter().any(|(name, _)| name == "context")
        {
            return Err(CliError::new("INVALID_ARGUMENT", 2));
        }
        let profile = github_context
            .iter()
            .position(|(name, _)| name == "request_profile")
            .ok_or_else(|| CliError::new("INVALID_ARGUMENT", 2))?;
        let (_, profile) = github_context.remove(profile);
        fields.push((
            "context".into(),
            Json::Object(vec![
                ("request_profile_id".into(), profile),
                ("query".into(), Json::Object(github_context)),
            ]),
        ));
    }
    Ok(Json::Object(fields))
}

struct AgentEngine {
    config: TransportConfig,
}
impl AgentEngine {
    fn from_environment() -> Result<Self, ()> {
        let config = TransportConfig {
            profile: PathBuf::from(std::env::var_os("PM_PROFILE").ok_or(())?),
            private: PathBuf::from(std::env::var_os("PM_PRIVATE").ok_or(())?),
            socket: PathBuf::from(std::env::var_os("PM_SOCKET").ok_or(())?),
        };
        if config.valid() {
            Ok(Self { config })
        } else {
            Err(())
        }
    }
}
impl Engine for AgentEngine {
    fn call(&self, method: &str, params: &Json) -> Result<Json, ErrorCode> {
        if method == "pm.v1.capabilities" {
            return capabilities_result();
        }
        let request = match method {
            "pm.v1.credentials.discover" => None,
            "pm.v1.authentication.get" => Some(prefixed_request(31, id_param(params)?)),
            "pm.v1.authentication.cancel" => Some(prefixed_request(32, id_param(params)?)),
            "pm.v1.authentication.start" => Some(start_request(params)?),
            _ => return Err(ErrorCode::NotFound),
        };
        let raw = agent_rpc(
            &self.config.profile,
            &self.config.private,
            &self.config.socket,
            request.as_deref(),
        )
        .map_err(|_| ErrorCode::CustodyUnavailable)?;
        if request.is_none() {
            return decode_discovery(&raw);
        }
        decode_attempt(&raw)
    }
}

fn id_param(params: &Json) -> Result<[u8; 16], ErrorCode> {
    decode_hex(
        params
            .field("attempt_id")
            .and_then(Json::string)
            .ok_or(ErrorCode::InvalidArgument)?,
    )
}
fn prefixed_request(opcode: u8, id: [u8; 16]) -> Vec<u8> {
    let mut value = vec![opcode];
    value.extend_from_slice(&id);
    value
}
fn start_request(params: &Json) -> Result<Vec<u8>, ErrorCode> {
    let item = decode_hex(
        params
            .field("credential_id")
            .and_then(Json::string)
            .ok_or(ErrorCode::InvalidArgument)?,
    )?;
    let issued = params
        .field("idempotency_key")
        .and_then(|v| v.field("issued_at"))
        .and_then(Json::string)
        .ok_or(ErrorCode::InvalidArgument)?
        .parse::<u64>()
        .map_err(|_| ErrorCode::InvalidArgument)?;
    let nonce = decode_hex(
        params
            .field("idempotency_key")
            .and_then(|v| v.field("nonce"))
            .and_then(Json::string)
            .ok_or(ErrorCode::InvalidArgument)?,
    )?;
    let integration = params
        .field("integration_id")
        .and_then(Json::string)
        .ok_or(ErrorCode::InvalidArgument)?;
    let context = if integration == "github-rest-bearer" {
        github_request_context(params.field("context").ok_or(ErrorCode::InvalidArgument)?)?
    } else {
        params
            .field("context")
            .and_then(Json::string)
            .unwrap_or("")
            .as_bytes()
            .to_vec()
    };
    let version = params
        .field("integration_version")
        .and_then(Json::number)
        .ok_or(ErrorCode::InvalidArgument)?
        .parse::<u32>()
        .map_err(|_| ErrorCode::InvalidArgument)?;
    let method = params
        .field("method")
        .and_then(Json::string)
        .ok_or(ErrorCode::InvalidArgument)?;
    let destination = params
        .field("destination")
        .and_then(Json::string)
        .ok_or(ErrorCode::InvalidArgument)?;
    let mut value = vec![33];
    value.extend_from_slice(&item);
    value.extend_from_slice(&issued.to_be_bytes());
    value.extend_from_slice(&nonce);
    push_wire_bytes(&mut value, integration.as_bytes())?;
    value.extend_from_slice(&version.to_be_bytes());
    push_wire_bytes(&mut value, method.as_bytes())?;
    push_wire_bytes(&mut value, destination.as_bytes())?;
    push_wire_bytes(&mut value, &context)?;
    Ok(value)
}

fn push_wire_bytes(value: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ErrorCode> {
    let len = u32::try_from(bytes.len()).map_err(|_| ErrorCode::InvalidArgument)?;
    value.extend_from_slice(&len.to_be_bytes());
    value.extend_from_slice(bytes);
    Ok(())
}

fn decode_discovery(raw: &[u8]) -> Result<Json, ErrorCode> {
    if raw.first() != Some(&0) {
        return Err(ErrorCode::Unauthorized);
    }
    let mut at = 1;
    let count = u16::from_be_bytes(
        raw.get(at..at + 2)
            .ok_or(ErrorCode::Internal)?
            .try_into()
            .map_err(|_| ErrorCode::Internal)?,
    ) as usize;
    at += 2;
    let mut values = Vec::new();
    for _ in 0..count {
        let id = raw.get(at..at + 16).ok_or(ErrorCode::Internal)?;
        at += 16;
        at += 16;
        let kind = take_bytes(raw, &mut at)?;
        let title = take_bytes(raw, &mut at)?;
        let destination = take_bytes(raw, &mut at)?;
        let account = take_bytes(raw, &mut at)?;
        values.push(Json::Object(vec![
            ("id".into(), Json::String(hex(id))),
            (
                "title".into(),
                Json::String(String::from_utf8_lossy(title).into()),
            ),
            (
                "type".into(),
                Json::String(String::from_utf8_lossy(kind).into()),
            ),
            (
                "destination".into(),
                Json::String(String::from_utf8_lossy(destination).into()),
            ),
            (
                "account".into(),
                Json::String(String::from_utf8_lossy(account).into()),
            ),
            (
                "integrations".into(),
                credential_integrations(kind, destination),
            ),
        ]));
    }
    Ok(Json::Object(vec![
        ("credentials".into(), Json::Array(values)),
        ("next_cursor".into(), Json::Null),
    ]))
}
fn credential_integrations(kind: &[u8], destination: &[u8]) -> Json {
    let mut integrations = vec![Json::String("controlled.external".into())];
    if destination == b"ssh-lab" {
        integrations.push(Json::String("ssh-server".into()));
        integrations.push(Json::String("linux-system-ssh".into()));
    } else if destination == b"keycloak-lab" {
        integrations.push(Json::String("keycloak-browser-oidc".into()));
    } else if destination == b"keycloak-exchange-lab" {
        integrations.push(Json::String("keycloak-token-exchange".into()));
    } else if destination == b"github-assigned-issues/1" {
        integrations.push(Json::String("github-rest-bearer".into()));
    }
    if kind == b"passkey" {
        integrations.push(Json::String("keycloak-webauthn".into()));
    }
    Json::Array(integrations)
}
fn decode_attempt(raw: &[u8]) -> Result<Json, ErrorCode> {
    if raw.first() != Some(&0) {
        return Err(match raw.first().copied().unwrap_or(1) {
            2 => ErrorCode::NotFound,
            3 => ErrorCode::IdempotencyConflict,
            4 => ErrorCode::AccessSuspended,
            5 => ErrorCode::AgentRevoked,
            6 => ErrorCode::CredentialUnavailable,
            7 => ErrorCode::ClockUntrusted,
            8 => ErrorCode::RateLimited,
            9 => ErrorCode::IdempotencyExpired,
            _ => ErrorCode::Internal,
        });
    }
    let mut at = 1;
    let attempt = take_fixed(raw, &mut at)?;
    let credential = take_fixed(raw, &mut at)?;
    let revision = take_fixed(raw, &mut at)?;
    let state = take_bytes(raw, &mut at)?;
    let reason = take_bytes(raw, &mut at)?;
    let result = take_bytes(raw, &mut at)?;
    let integration = take_bytes(raw, &mut at)?;
    let version = raw
        .get(at..at + 4)
        .ok_or(ErrorCode::Internal)?
        .try_into()
        .map(u32::from_be_bytes)
        .map_err(|_| ErrorCode::Internal)?;
    at += 4;
    if at != raw.len() {
        return Err(ErrorCode::Internal);
    }
    let integration = std::str::from_utf8(integration).map_err(|_| ErrorCode::Internal)?;
    let public_result = public_attempt_result(integration, (!result.is_empty()).then_some(result))?;
    Ok(Json::Object(vec![
        ("attempt_id".into(), Json::String(hex(attempt))),
        ("credential_id".into(), Json::String(hex(credential))),
        ("revision_id".into(), Json::String(hex(revision))),
        ("integration_id".into(), Json::String(integration.into())),
        (
            "integration_version".into(),
            Json::Number(version.to_string()),
        ),
        (
            "state".into(),
            Json::String(String::from_utf8_lossy(state).into()),
        ),
        ("created_at".into(), Json::String("0".into())),
        ("expires_at".into(), Json::String("0".into())),
        (
            "reason".into(),
            if reason.is_empty() {
                Json::Null
            } else {
                Json::String(String::from_utf8_lossy(reason).into())
            },
        ),
        ("result".into(), public_result),
    ]))
}

fn take_fixed<'a>(raw: &'a [u8], at: &mut usize) -> Result<&'a [u8], ErrorCode> {
    let end = at.checked_add(16).ok_or(ErrorCode::Internal)?;
    let value = raw.get(*at..end).ok_or(ErrorCode::Internal)?;
    *at = end;
    Ok(value)
}
fn take_bytes<'a>(raw: &'a [u8], at: &mut usize) -> Result<&'a [u8], ErrorCode> {
    let end = at.checked_add(4).ok_or(ErrorCode::Internal)?;
    let len = u32::from_be_bytes(
        raw.get(*at..end)
            .ok_or(ErrorCode::Internal)?
            .try_into()
            .map_err(|_| ErrorCode::Internal)?,
    ) as usize;
    *at = end;
    let end = at.checked_add(len).ok_or(ErrorCode::Internal)?;
    let value = raw.get(*at..end).ok_or(ErrorCode::Internal)?;
    *at = end;
    Ok(value)
}
fn decode_hex(value: &str) -> Result<[u8; 16], ErrorCode> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|v| v.is_ascii_hexdigit() && !v.is_ascii_uppercase())
    {
        return Err(ErrorCode::InvalidArgument);
    }
    let mut output = [0_u8; 16];
    for (index, output_byte) in output.iter_mut().enumerate() {
        let chunk = &value.as_bytes()[index * 2..index * 2 + 2];
        *output_byte = (digit(chunk[0])? << 4) | digit(chunk[1])?;
    }
    Ok(output)
}
fn digit(value: u8) -> Result<u8, ErrorCode> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ErrorCode::InvalidArgument),
    }
}

fn run_mcp() -> Result<(), CliError> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let engine = AgentEngine::from_environment().unwrap_or_else(|()| AgentEngine {
        config: TransportConfig::missing(),
    });
    let mut line = String::new();
    while input
        .read_line(&mut line)
        .map_err(|_| CliError::new("CUSTODY_UNAVAILABLE", 4))?
        != 0
    {
        let bytes = line.trim_end_matches(['\r', '\n']).as_bytes();
        if bytes.is_empty() {
            line.clear();
            continue;
        }
        if !bytes
            .windows(b"\"id\"".len())
            .any(|window| window == b"\"id\"")
            && bytes
                .windows(b"initialized".len())
                .any(|window| window == b"initialized")
        {
            line.clear();
            continue;
        }
        let request = parse_mcp_request(bytes).map_err(|_| CliError::new("INVALID_JSON", 2))?;
        if request.method != "initialized" {
            let response = mcp_dispatch(&request, &engine);
            output
                .write_all(&encode_json(&response))
                .and_then(|()| output.write_all(b"\n"))
                .and_then(|()| output.flush())
                .map_err(|_| CliError::new("CUSTODY_UNAVAILABLE", 4))?;
        }
        line.clear();
    }
    Ok(())
}

fn mcp_dispatch(request: &Request, engine: &impl Engine) -> Json {
    match request.method.as_str() {
        "initialize" => Json::Object(vec![
            ("jsonrpc".into(), Json::String("2.0".into())),
            ("id".into(), Json::String(request.id.clone())),
            (
                "result".into(),
                Json::Object(vec![
                    ("protocolVersion".into(), Json::String("2025-11-25".into())),
                    (
                        "capabilities".into(),
                        Json::Object(vec![("tools".into(), Json::Object(Vec::new()))]),
                    ),
                    (
                        "serverInfo".into(),
                        Json::Object(vec![
                            ("name".into(), Json::String("passwordmanager".into())),
                            (
                                "version".into(),
                                Json::String(env!("CARGO_PKG_VERSION").into()),
                            ),
                        ]),
                    ),
                ]),
            ),
        ]),
        "tools/list" => tools_list(request),
        "tools/call" => {
            let tool = request.params.field("name").and_then(Json::string);
            let params = request
                .params
                .field("arguments")
                .cloned()
                .unwrap_or(Json::Object(Vec::new()));
            let method = match tool {
                Some("get_capabilities") => "pm.v1.capabilities",
                Some("discover_credentials") => "pm.v1.credentials.discover",
                Some("start_authentication") => "pm.v1.authentication.start",
                Some("get_authentication") => "pm.v1.authentication.get",
                Some("cancel_authentication") => "pm.v1.authentication.cancel",
                _ => return error_response(request, ErrorCode::NotFound),
            };
            let internal = Request {
                id: request.id.clone(),
                method: method.into(),
                params,
            };
            let response = dispatch(&internal, engine);
            tool_response(request, &response)
        }
        _ => error_response(request, ErrorCode::NotFound),
    }
}

fn tools_list(request: &Request) -> Json {
    let tools = [
        "get_capabilities",
        "discover_credentials",
        "start_authentication",
        "get_authentication",
        "cancel_authentication",
    ]
    .into_iter()
    .map(|name| {
        Json::Object(vec![
            ("name".into(), Json::String(name.into())),
            (
                "description".into(),
                Json::String("Delegated passwordmanager operation".into()),
            ),
            (
                "inputSchema".into(),
                Json::Object(vec![
                    ("type".into(), Json::String("object".into())),
                    ("additionalProperties".into(), Json::Bool(false)),
                ]),
            ),
        ])
    })
    .collect();
    Json::Object(vec![
        ("jsonrpc".into(), Json::String("2.0".into())),
        ("id".into(), Json::String(request.id.clone())),
        (
            "result".into(),
            Json::Object(vec![("tools".into(), Json::Array(tools))]),
        ),
    ])
}
fn tool_response(request: &Request, response: &Json) -> Json {
    if let Some(error) = response.field("error") {
        let text = String::from_utf8(encode_json(error)).expect("JSON encoder emits UTF-8");
        return Json::Object(vec![
            ("jsonrpc".into(), Json::String("2.0".into())),
            ("id".into(), Json::String(request.id.clone())),
            (
                "result".into(),
                Json::Object(vec![
                    ("isError".into(), Json::Bool(true)),
                    (
                        "content".into(),
                        Json::Array(vec![Json::Object(vec![
                            ("type".into(), Json::String("text".into())),
                            ("text".into(), Json::String(text)),
                        ])]),
                    ),
                ]),
            ),
        ]);
    }
    let value = response.field("result").cloned().unwrap_or(Json::Null);
    let text = String::from_utf8(encode_json(&value)).expect("JSON encoder emits UTF-8");
    Json::Object(vec![
        ("jsonrpc".into(), Json::String("2.0".into())),
        ("id".into(), Json::String(request.id.clone())),
        (
            "result".into(),
            Json::Object(vec![
                ("isError".into(), Json::Bool(false)),
                ("structuredContent".into(), value),
                (
                    "content".into(),
                    Json::Array(vec![Json::Object(vec![
                        ("type".into(), Json::String("text".into())),
                        ("text".into(), Json::String(text)),
                    ])]),
                ),
            ]),
        ),
    ])
}
fn error_response(request: &Request, code: ErrorCode) -> Json {
    Json::Object(vec![
        ("jsonrpc".into(), Json::String("2.0".into())),
        ("id".into(), Json::String(request.id.clone())),
        (
            "error".into(),
            Json::Object(vec![
                ("code".into(), Json::String(code.name().into())),
                ("message".into(), Json::String(code.name().into())),
            ]),
        ),
    ])
}

fn create(path: &Path) -> Result<(), String> {
    prompt("Master password (read from stdin):")?;
    let mut input = NativeStdin::open().map_err(|error| error.to_string())?;
    let password = read_protected_line(&mut input, 1024)?;
    prompt("Confirm master password:")?;
    let confirmation = read_protected_line(&mut input, 1024)?;
    if password.as_ref() != confirmation.as_ref() {
        return Err("master password confirmation does not match".into());
    }
    let pending = PendingVault::new(password.as_ref(), KdfProfile::DEFAULT)
        .map_err(|error| error.to_string())?;
    let trusted_root = *pending.trusted_root();
    println!(
        "Recovery code (store externally): {}",
        pending.recovery_code()
    );
    prompt("Reintroduce recovery code to confirm the external copy:")?;
    let reintroduced = read_protected_line(&mut input, 512)?;
    let reintroduced: RecoveryCode = std::str::from_utf8(reintroduced.as_ref())
        .map_err(|_| "recovery code is not UTF-8".to_owned())?
        .parse()
        .map_err(|_| "recovery code is invalid".to_owned())?;
    pending
        .persist(path, &reintroduced)
        .map_err(|e| e.to_string())?;
    println!("Vault created: {}", hex(trusted_root.vault_id()));
    Ok(())
}
fn open(path: &Path) -> Result<(), String> {
    prompt("Master password (read from stdin):")?;
    let mut input = NativeStdin::open().map_err(|error| error.to_string())?;
    let password = read_protected_line(&mut input, 1024)?;
    let opened = open_vault(path, password.as_ref()).map_err(|e| e.to_string())?;
    println!("Vault opened: {}", hex(opened.trusted_root().vault_id()));
    Ok(())
}
fn prompt(message: &str) -> Result<(), String> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "{message}").map_err(|e| e.to_string())?;
    output.flush().map_err(|e| e.to_string())
}
fn read_protected_line(input: &mut impl Read, maximum: usize) -> Result<ProtectedBytes, String> {
    let capacity = maximum
        .checked_add(2)
        .ok_or_else(|| "input limit overflow".to_owned())?;
    let mut value = ProtectedBytes::zeroed(capacity).map_err(|error| error.to_string())?;
    let mut len = 0;
    loop {
        let bytes = input
            .read(&mut value[len..=len])
            .map_err(|error| error.to_string())?;
        if bytes == 0 {
            if len == 0 {
                return Err("unexpected end of input".into());
            }
            if len > maximum {
                return Err(format!("input exceeds {maximum} bytes"));
            }
            value.truncate(len);
            return Ok(value);
        }
        if value[len] == b'\n' {
            let mut content_len = len;
            if content_len != 0 && value[content_len - 1] == b'\r' {
                content_len -= 1;
            }
            if content_len > maximum {
                return Err(format!("input exceeds {maximum} bytes"));
            }
            value.truncate(content_len);
            return Ok(value);
        }
        len += 1;
        if len == capacity {
            return Err(format!("input exceeds {maximum} bytes"));
        }
    }
}
fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{params_for_cli, read_protected_line, start_request};
    use std::{ffi::OsString, io::Cursor};

    #[cfg(windows)]
    #[test]
    fn missing_windows_stdin_preserves_the_public_eof_failure() {
        use super::{NativeStdin, NativeStdinKind};

        let mut input = NativeStdin {
            handle: std::ptr::null_mut(),
            kind: NativeStdinKind::Missing,
        };
        let Err(error) = read_protected_line(&mut input, 32) else {
            panic!("missing stdin was accepted");
        };
        assert!(matches!(error.as_str(), "unexpected end of input"));
    }

    #[test]
    fn protected_line_preserves_public_line_parsing() {
        let lf = read_protected_line(&mut Cursor::new(b"ticket28-lf\n"), 32).unwrap();
        assert!(matches!(lf.as_ref(), b"ticket28-lf"));

        let crlf = read_protected_line(&mut Cursor::new(b"ticket28-crlf\r\n"), 32).unwrap();
        assert!(matches!(crlf.as_ref(), b"ticket28-crlf"));

        let eof_after_bytes = read_protected_line(&mut Cursor::new(b"ticket28-eof"), 32).unwrap();
        assert!(matches!(eof_after_bytes.as_ref(), b"ticket28-eof"));

        let lone_cr = read_protected_line(&mut Cursor::new(b"ticket28-cr\r"), 32).unwrap();
        assert!(matches!(lone_cr.as_ref(), b"ticket28-cr\r"));

        let exact_limit = read_protected_line(&mut Cursor::new(b"1234\n"), 4).unwrap();
        assert!(matches!(exact_limit.as_ref(), b"1234"));

        let Err(empty) = read_protected_line(&mut Cursor::new(b""), 32) else {
            panic!("empty input was accepted");
        };
        assert!(matches!(empty.as_str(), "unexpected end of input"));

        let Err(over_limit) = read_protected_line(&mut Cursor::new(b"12345\n"), 4) else {
            panic!("over-limit input was accepted");
        };
        assert!(matches!(over_limit.as_str(), "input exceeds 4 bytes"));
    }

    #[test]
    fn github_cli_builds_the_closed_typed_query_context() {
        let values = [
            "auth",
            "start",
            "--credential-id",
            "11111111111111111111111111111111",
            "--integration-id",
            "github-rest-bearer",
            "--integration-version",
            "1",
            "--method",
            "bearer",
            "--destination",
            "github-assigned-issues/1",
            "--request-profile",
            "github-assigned-issues/1",
            "--filter",
            "assigned",
            "--state",
            "open",
            "--sort",
            "updated",
            "--direction",
            "desc",
            "--page",
            "2",
            "--per-page",
            "50",
            "--issued-at",
            "42",
            "--nonce",
            "22222222222222222222222222222222",
        ]
        .map(OsString::from);
        let params = params_for_cli(&values).unwrap();
        let request = start_request(&params).unwrap();
        let profile = b"github-assigned-issues/1\nfilter=";
        let pagination = b"per_page=50\n";
        assert!(
            request
                .windows(profile.len())
                .any(|window| window == profile)
        );
        assert!(
            request
                .windows(pagination.len())
                .any(|window| window == pagination)
        );
        assert!(!request.windows(4).any(|window| window == b"url="));
    }
}
