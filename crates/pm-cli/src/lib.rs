// SPDX-License-Identifier: AGPL-3.0-only

//! Human vault bootstrap and delegated CLI/MCP presentation adapters.

use pm_crypto::{KdfProfile, RecoveryCode};
use pm_custody::agent_rpc;
use pm_interface::{
    Engine, ErrorCode, Json, Request, capabilities_result, dispatch, encode_json,
    parse_mcp_request, public_attempt_result,
};
use pm_vault::{PendingVault, open_vault};
use std::{
    ffi::OsString,
    fmt::Write as FmtWrite,
    io::{self, BufRead, Read, Write},
    path::{Path, PathBuf},
};

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
        let json = if key == "integration-version" {
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
        if normalized == "issued_at" || normalized == "nonce" {
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
    let context = params
        .field("context")
        .and_then(Json::string)
        .unwrap_or("")
        .as_bytes();
    let integration = params
        .field("integration_id")
        .and_then(Json::string)
        .ok_or(ErrorCode::InvalidArgument)?;
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
    push_wire_bytes(&mut value, context)?;
    Ok(value)
}
fn push_wire_bytes(value: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ErrorCode> {
    value.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| ErrorCode::InvalidArgument)?
            .to_be_bytes(),
    );
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
            ("integrations".into(), credential_integrations(destination)),
        ]));
    }
    Ok(Json::Object(vec![
        ("credentials".into(), Json::Array(values)),
        ("next_cursor".into(), Json::Null),
    ]))
}
fn credential_integrations(destination: &[u8]) -> Json {
    let mut integrations = vec![Json::String("controlled.external".into())];
    if destination == b"ssh-lab" {
        integrations.push(Json::String("ssh-server".into()));
        integrations.push(Json::String("linux-system-ssh".into()));
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
    let integration =
        std::str::from_utf8(take_bytes(raw, &mut at)?).map_err(|_| ErrorCode::Internal)?;
    let end = at.checked_add(4).ok_or(ErrorCode::Internal)?;
    let version = u32::from_be_bytes(
        raw.get(at..end)
            .ok_or(ErrorCode::Internal)?
            .try_into()
            .map_err(|_| ErrorCode::Internal)?,
    );
    at = end;
    if at != raw.len() {
        return Err(ErrorCode::Internal);
    }
    let public = public_attempt_result(integration, (!result.is_empty()).then_some(result))?;
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
        ("result".into(), public),
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
    let stdin = io::stdin();
    let mut input = stdin.lock();
    prompt("Master password (read from stdin):")?;
    let password = read_limited_line(&mut input, 1024)?;
    prompt("Confirm master password:")?;
    let confirmation = read_limited_line(&mut input, 1024)?;
    if password != confirmation {
        return Err("master password confirmation does not match".into());
    }
    let pending = PendingVault::new(&password, KdfProfile::DEFAULT).map_err(|e| e.to_string())?;
    let trusted_root = *pending.trusted_root();
    println!(
        "Recovery code (store externally): {}",
        pending.recovery_code()
    );
    prompt("Reintroduce recovery code to confirm the external copy:")?;
    let reintroduced = read_limited_line(&mut input, 512)?;
    let reintroduced: RecoveryCode = std::str::from_utf8(&reintroduced)
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
    let stdin = io::stdin();
    let mut input = stdin.lock();
    prompt("Master password (read from stdin):")?;
    let password = read_limited_line(&mut input, 1024)?;
    let opened = open_vault(path, &password).map_err(|e| e.to_string())?;
    println!("Vault opened: {}", hex(opened.trusted_root().vault_id()));
    Ok(())
}
fn prompt(message: &str) -> Result<(), String> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "{message}").map_err(|e| e.to_string())?;
    output.flush().map_err(|e| e.to_string())
}
fn read_limited_line(input: &mut impl BufRead, maximum: usize) -> Result<Vec<u8>, String> {
    let mut value = Vec::with_capacity(maximum.min(128));
    let mut limited = Read::by_ref(input)
        .take(u64::try_from(maximum + 2).map_err(|_| "input limit overflow".to_owned())?);
    let bytes = limited
        .read_until(b'\n', &mut value)
        .map_err(|e| e.to_string())?;
    if bytes == 0 {
        return Err("unexpected end of input".into());
    }
    if value.last() == Some(&b'\n') {
        value.pop();
        if value.last() == Some(&b'\r') {
            value.pop();
        }
    }
    if value.len() > maximum {
        return Err(format!("input exceeds {maximum} bytes"));
    }
    Ok(value)
}
fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}
