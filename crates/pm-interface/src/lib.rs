// SPDX-License-Identifier: AGPL-3.0-only

#![allow(clippy::all, clippy::pedantic)]

//! The single, deliberately small contract used by the delegated CLI and MCP
//! adapters.  This crate contains no vault policy and no provider code: both
//! adapters hand validated requests to the same engine supplied by the
//! caller.  Keeping framing and validation here prevents the two front doors
//! from slowly acquiring different security semantics.

use std::{
    fmt,
    io::{self, Read, Write},
    path::Path,
    sync::Arc,
};

use pm_vault::{
    AgentPeer, AttemptError, AttemptVault, DelegatedVault, IdempotencyKey, StartAttempt,
};

pub const PROTOCOL: u64 = 1;
pub const MAX_FRAME: usize = 1024 * 1024;
pub const MAX_DEPTH: usize = 16;
pub const MAX_RESULT: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    #[must_use]
    pub const fn object(fields: Vec<(String, Json)>) -> Self {
        Self::Object(fields)
    }
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&Json> {
        match self {
            Self::Object(fields) => fields.iter().find(|(key, _)| key == name).map(|(_, v)| v),
            _ => None,
        }
    }
    #[must_use]
    pub fn string(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }
    #[must_use]
    pub fn number(&self) -> Option<&str> {
        match self {
            Self::Number(value) => Some(value),
            _ => None,
        }
    }
    #[must_use]
    pub fn bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }
    #[must_use]
    pub fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    TooLarge,
    Empty,
    InvalidUtf8,
    InvalidJson,
    DuplicateKey,
    TooDeep,
    TrailingBytes,
    InvalidRequest,
    InvalidId,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "FRAME_TOO_LARGE",
            Self::Empty => "INVALID_ARGUMENT",
            Self::InvalidUtf8 | Self::InvalidJson | Self::TrailingBytes => "INVALID_JSON",
            Self::DuplicateKey => "DUPLICATE_KEY",
            Self::TooDeep => "JSON_TOO_DEEP",
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::InvalidId => "INVALID_ID",
        })
    }
}
impl std::error::Error for ParseError {}

/// A private-RPC request. IDs are strings intentionally; numbers would permit
/// lossy handling by adapters and are not part of this wire contract.
#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    pub id: String,
    pub method: String,
    pub params: Json,
}

pub fn parse_json(bytes: &[u8]) -> Result<Json, ParseError> {
    if bytes.is_empty() {
        return Err(ParseError::Empty);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ParseError::InvalidUtf8)?;
    let mut parser = Parser {
        bytes: text.as_bytes(),
        at: 0,
    };
    let value = parser.value(0)?;
    parser.space();
    if parser.at != parser.bytes.len() {
        return Err(ParseError::TrailingBytes);
    }
    Ok(value)
}

pub fn parse_request(bytes: &[u8]) -> Result<Request, ParseError> {
    let value = parse_json(bytes)?;
    let object = match value {
        Json::Object(fields) => fields,
        _ => return Err(ParseError::InvalidRequest),
    };
    if object
        .iter()
        .any(|(key, _)| !["jsonrpc", "id", "method", "params"].contains(&key.as_str()))
    {
        return Err(ParseError::InvalidRequest);
    }
    let get = |name: &str| {
        object
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
    };
    if get("jsonrpc").and_then(Json::string) != Some("2.0") {
        return Err(ParseError::InvalidRequest);
    }
    let id = get("id")
        .and_then(Json::string)
        .ok_or(ParseError::InvalidId)?;
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii() && !byte.is_ascii_control())
    {
        return Err(ParseError::InvalidId);
    }
    let method = get("method")
        .and_then(Json::string)
        .ok_or(ParseError::InvalidRequest)?;
    let params = get("params")
        .cloned()
        .unwrap_or_else(|| Json::Object(Vec::new()));
    if !params.is_object() {
        return Err(ParseError::InvalidRequest);
    }
    Ok(Request {
        id: id.to_owned(),
        method: method.to_owned(),
        params,
    })
}

/// MCP permits string or number request IDs, unlike the private RPC. Numeric
/// IDs are retained canonically as text and never converted to floating point.
pub fn parse_mcp_request(bytes: &[u8]) -> Result<Request, ParseError> {
    let value = parse_json(bytes)?;
    let object = match value {
        Json::Object(fields) => fields,
        _ => return Err(ParseError::InvalidRequest),
    };
    if object
        .iter()
        .any(|(key, _)| !["jsonrpc", "id", "method", "params"].contains(&key.as_str()))
    {
        return Err(ParseError::InvalidRequest);
    }
    let get = |name: &str| {
        object
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
    };
    if get("jsonrpc").and_then(Json::string) != Some("2.0") {
        return Err(ParseError::InvalidRequest);
    }
    let id = match get("id") {
        Some(Json::String(value)) | Some(Json::Number(value)) => value.clone(),
        _ => return Err(ParseError::InvalidId),
    };
    if id.is_empty() || id.len() > 64 {
        return Err(ParseError::InvalidId);
    }
    let method = get("method")
        .and_then(Json::string)
        .ok_or(ParseError::InvalidRequest)?;
    let params = get("params")
        .cloned()
        .unwrap_or_else(|| Json::Object(Vec::new()));
    if !params.is_object() {
        return Err(ParseError::InvalidRequest);
    }
    Ok(Request {
        id,
        method: method.to_owned(),
        params,
    })
}

pub fn encode_json(value: &Json) -> Vec<u8> {
    let mut output = String::new();
    encode_into(value, &mut output);
    output.into_bytes()
}

pub fn read_frame(input: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut header = [0_u8; 4];
    input.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds private RPC limit",
        ));
    }
    let mut frame = vec![0_u8; length];
    input.read_exact(&mut frame)?;
    Ok(frame)
}

pub fn write_frame(output: &mut impl Write, value: &[u8]) -> io::Result<()> {
    if value.is_empty() || value.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame exceeds private RPC limit",
        ));
    }
    let length = u32::try_from(value.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame length overflow"))?;
    output.write_all(&length.to_be_bytes())?;
    output.write_all(value)?;
    output.flush()
}

/// Public error categories deliberately contain no provider text.  Adapters
/// map these to their own error envelope/exit status without changing policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    Unauthorized,
    AgentRevoked,
    AccessSuspended,
    CredentialUnavailable,
    InvalidArgument,
    UnsupportedVersion,
    NotFound,
    IdempotencyConflict,
    IdempotencyExpired,
    ResultExpired,
    RateLimited,
    ClockUntrusted,
    CustodyUnavailable,
    Internal,
}

impl ErrorCode {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unauthorized => "UNAUTHORIZED",
            Self::AgentRevoked => "AGENT_REVOKED",
            Self::AccessSuspended => "AGENT_ACCESS_SUSPENDED",
            Self::CredentialUnavailable => "CREDENTIAL_UNAVAILABLE",
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Self::NotFound => "NOT_FOUND",
            Self::IdempotencyConflict => "IDEMPOTENCY_CONFLICT",
            Self::IdempotencyExpired => "IDEMPOTENCY_EXPIRED",
            Self::ResultExpired => "RESULT_EXPIRED",
            Self::RateLimited => "RATE_LIMITED",
            Self::ClockUntrusted => "CLOCK_UNTRUSTED",
            Self::CustodyUnavailable => "CUSTODY_UNAVAILABLE",
            Self::Internal => "INTERNAL_ERROR",
        }
    }
}

pub trait Engine {
    fn call(&self, method: &str, params: &Json) -> Result<Json, ErrorCode>;
}

/// Dispatches the common JSON-RPC envelope. Both CLI and MCP call this
/// function; neither adapter gets a second authorization implementation.
pub fn dispatch<E: Engine>(request: &Request, engine: &E) -> Json {
    let result = engine.call(&request.method, &request.params);
    let mut response = vec![
        ("jsonrpc".to_owned(), Json::String("2.0".to_owned())),
        ("id".to_owned(), Json::String(request.id.clone())),
    ];
    match result {
        Ok(value) => response.push(("result".to_owned(), value)),
        Err(code) => response.push((
            "error".to_owned(),
            Json::Object(vec![
                ("code".to_owned(), Json::String(code.name().to_owned())),
                ("message".to_owned(), Json::String(code.name().to_owned())),
            ]),
        )),
    }
    Json::Object(response)
}

/// The real vault-backed engine used by both adapters. It opens device
/// custody only and receives identity from the already authenticated RPK
/// peer; no caller-supplied role or agent id is trusted.
pub struct VaultEngine {
    delegated: DelegatedVault,
    attempts: AttemptVault,
    peer: AgentPeer,
}

impl VaultEngine {
    pub fn open(
        path: &Path,
        device: [u8; 16],
        custody: Arc<pm_vault::AuditDeviceCustody>,
        peer: AgentPeer,
    ) -> Result<Self, ErrorCode> {
        let delegated = DelegatedVault::open(path, device, Arc::clone(&custody))
            .map_err(|_| ErrorCode::CustodyUnavailable)?;
        let attempts = AttemptVault::open(
            DelegatedVault::open(path, device, custody)
                .map_err(|_| ErrorCode::CustodyUnavailable)?,
        )
        .map_err(|_| ErrorCode::CustodyUnavailable)?;
        Ok(Self {
            delegated,
            attempts,
            peer,
        })
    }
}

impl Engine for VaultEngine {
    fn call(&self, method: &str, params: &Json) -> Result<Json, ErrorCode> {
        match method {
            "pm.v1.hello" => Ok(Json::Object(vec![(
                "protocol".into(),
                Json::Number("1".into()),
            )])),
            "pm.v1.capabilities" => capabilities_result(),
            "pm.v1.credentials.discover" => self.discover(params),
            "pm.v1.authentication.start" => self.start(params),
            "pm.v1.authentication.get" => self.get(params),
            "pm.v1.authentication.cancel" => self.cancel(params),
            _ => Err(ErrorCode::NotFound),
        }
    }
}

pub fn capabilities_result() -> Result<Json, ErrorCode> {
    // controlled.external is the only integration with an executed provider
    // laboratory in this release; designs without evidence are not listed.
    Ok(Json::Object(vec![
        ("protocol".into(), Json::Number("1".into())),
        (
            "integrations".into(),
            Json::Array(vec![Json::Object(vec![
                ("id".into(), Json::String("controlled.external".into())),
                ("version".into(), Json::Number("1".into())),
                (
                    "methods".into(),
                    Json::Array(vec![Json::String("password".into())]),
                ),
                ("availability".into(), Json::String("verified".into())),
                ("input_schema".into(), schema_start()),
                (
                    "result_schema".into(),
                    Json::Object(vec![("type".into(), Json::String("object".into()))]),
                ),
            ])]),
        ),
        (
            "limits".into(),
            Json::Object(vec![
                ("max_frame".into(), Json::Number(MAX_FRAME.to_string())),
                ("max_context".into(), Json::Number((64 * 1024).to_string())),
                ("max_result".into(), Json::Number(MAX_RESULT.to_string())),
            ]),
        ),
    ]))
}

fn schema_start() -> Json {
    Json::Object(vec![
        ("type".into(), Json::String("object".into())),
        ("additionalProperties".into(), Json::Bool(false)),
    ])
}

impl VaultEngine {
    fn discover(&self, params: &Json) -> Result<Json, ErrorCode> {
        reject_unknown(params, &["filter", "limit", "cursor"])?;
        let limit = optional_uint(params, "limit")?.unwrap_or(50);
        if !(1..=100).contains(&limit) {
            return Err(ErrorCode::InvalidArgument);
        }
        if let Some(cursor) = optional_string(params, "cursor")? {
            if !cursor.is_empty() || cursor.len() > 512 {
                return Err(ErrorCode::InvalidArgument);
            }
        }
        let text = params
            .field("filter")
            .and_then(|v| v.field("text"))
            .and_then(Json::string);
        if let Some(value) = text {
            if value.len() > 256 {
                return Err(ErrorCode::InvalidArgument);
            }
        }
        let mut credentials = self
            .delegated
            .discover(&self.peer)
            .map_err(map_authorization)?;
        if let Some(filter) = text {
            credentials.retain(|credential| {
                credential.title().contains(filter)
                    || credential
                        .account()
                        .is_some_and(|account| account.contains(filter))
            });
        }
        credentials.truncate(limit as usize);
        let values = credentials
            .into_iter()
            .map(|credential| {
                Json::Object(vec![
                    ("id".into(), Json::String(hex(credential.item_id()))),
                    ("title".into(), Json::String(credential.title().into())),
                    (
                        "type".into(),
                        Json::String(record_type(credential.kind()).into()),
                    ),
                    (
                        "destination".into(),
                        credential
                            .destination()
                            .map_or(Json::Null, |v| Json::String(v.into())),
                    ),
                    (
                        "account".into(),
                        credential
                            .account()
                            .map_or(Json::Null, |v| Json::String(v.into())),
                    ),
                    (
                        "integrations".into(),
                        Json::Array(vec![Json::String("controlled.external".into())]),
                    ),
                ])
            })
            .collect();
        Ok(Json::Object(vec![
            ("credentials".into(), Json::Array(values)),
            ("next_cursor".into(), Json::Null),
        ]))
    }
    fn start(&self, params: &Json) -> Result<Json, ErrorCode> {
        reject_unknown(
            params,
            &[
                "credential_id",
                "integration_id",
                "integration_version",
                "method",
                "destination",
                "context",
                "idempotency_key",
            ],
        )?;
        let item = decode_hex(
            optional_string(params, "credential_id")?.ok_or(ErrorCode::InvalidArgument)?,
        )?;
        let integration =
            optional_string(params, "integration_id")?.ok_or(ErrorCode::InvalidArgument)?;
        let method = optional_string(params, "method")?.ok_or(ErrorCode::InvalidArgument)?;
        let destination =
            optional_string(params, "destination")?.ok_or(ErrorCode::InvalidArgument)?;
        let version =
            optional_uint(params, "integration_version")?.ok_or(ErrorCode::InvalidArgument)?;
        let context = optional_string(params, "context")?
            .unwrap_or("")
            .as_bytes()
            .to_vec();
        let key = params
            .field("idempotency_key")
            .ok_or(ErrorCode::InvalidArgument)?;
        let issued = key
            .field("issued_at")
            .and_then(Json::string)
            .ok_or(ErrorCode::InvalidArgument)?
            .parse::<i64>()
            .map_err(|_| ErrorCode::InvalidArgument)?;
        let nonce = decode_hex(
            key.field("nonce")
                .and_then(Json::string)
                .ok_or(ErrorCode::InvalidArgument)?,
        )?;
        let request = StartAttempt::new(
            item,
            integration,
            u32::try_from(version).map_err(|_| ErrorCode::InvalidArgument)?,
            method,
            destination,
            context,
            IdempotencyKey::new(issued, nonce).map_err(|_| ErrorCode::InvalidArgument)?,
        )
        .map_err(map_attempt)?;
        self.attempts
            .start(&self.peer, &request)
            .map_err(map_attempt)
            .map(snapshot)
    }
    fn get(&self, params: &Json) -> Result<Json, ErrorCode> {
        reject_unknown(params, &["attempt_id"])?;
        let id =
            decode_hex(optional_string(params, "attempt_id")?.ok_or(ErrorCode::InvalidArgument)?)?;
        self.attempts
            .get(&self.peer, id)
            .map_err(map_attempt)
            .map(snapshot)
    }
    fn cancel(&self, params: &Json) -> Result<Json, ErrorCode> {
        reject_unknown(params, &["attempt_id"])?;
        let id =
            decode_hex(optional_string(params, "attempt_id")?.ok_or(ErrorCode::InvalidArgument)?)?;
        self.attempts
            .cancel(&self.peer, id)
            .map_err(map_attempt)
            .map(snapshot)
    }
}

fn snapshot(value: pm_vault::AttemptSnapshot) -> Json {
    Json::Object(vec![
        ("attempt_id".into(), Json::String(hex(value.attempt_id()))),
        (
            "credential_id".into(),
            Json::String(hex(value.credential_id())),
        ),
        ("revision_id".into(), Json::String(hex(value.revision_id()))),
        (
            "integration_id".into(),
            Json::String(value.integration_id().into()),
        ),
        (
            "integration_version".into(),
            Json::Number(value.integration_version().to_string()),
        ),
        ("state".into(), Json::String(state(value.state()).into())),
        (
            "created_at".into(),
            Json::String(value.created_at_us().to_string()),
        ),
        (
            "expires_at".into(),
            Json::String(value.expires_at_us().to_string()),
        ),
        (
            "reason".into(),
            value
                .reason()
                .map_or(Json::Null, |v| Json::String(v.into())),
        ),
        // Provider bytes never cross the delegated interface without a typed G3 schema.
        ("result".into(), Json::Null),
    ])
}

fn optional_string<'a>(params: &'a Json, name: &str) -> Result<Option<&'a str>, ErrorCode> {
    match params.field(name) {
        None | Some(Json::Null) => Ok(None),
        Some(value) => value.string().map(Some).ok_or(ErrorCode::InvalidArgument),
    }
}
fn optional_uint(params: &Json, name: &str) -> Result<Option<u64>, ErrorCode> {
    match params.field(name) {
        None => Ok(None),
        Some(Json::Number(value)) => value
            .parse()
            .map(Some)
            .map_err(|_| ErrorCode::InvalidArgument),
        _ => Err(ErrorCode::InvalidArgument),
    }
}
fn reject_unknown(params: &Json, allowed: &[&str]) -> Result<(), ErrorCode> {
    if let Json::Object(fields) = params {
        if fields
            .iter()
            .any(|(key, _)| !allowed.contains(&key.as_str()))
        {
            return Err(ErrorCode::InvalidArgument);
        }
        Ok(())
    } else {
        Err(ErrorCode::InvalidArgument)
    }
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
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_digit(chunk[0])? << 4) | hex_digit(chunk[1])?;
    }
    Ok(output)
}
fn hex_digit(value: u8) -> Result<u8, ErrorCode> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ErrorCode::InvalidArgument),
    }
}
fn hex(value: &[u8; 16]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn state(value: pm_vault::AttemptState) -> &'static str {
    match value {
        pm_vault::AttemptState::Created => "CREATED",
        pm_vault::AttemptState::Running => "RUNNING",
        pm_vault::AttemptState::WaitingForHuman => "WAITING_FOR_HUMAN",
        pm_vault::AttemptState::Succeeded => "SUCCEEDED",
        pm_vault::AttemptState::Failed => "FAILED",
        pm_vault::AttemptState::Cancelled => "CANCELLED",
        pm_vault::AttemptState::Expired => "EXPIRED",
        pm_vault::AttemptState::Indeterminate => "INDETERMINATE",
    }
}
fn record_type(value: pm_vault::RecordKind) -> &'static str {
    match value {
        pm_vault::RecordKind::Password => "password",
        pm_vault::RecordKind::Totp => "totp",
        pm_vault::RecordKind::Passkey => "passkey",
        pm_vault::RecordKind::Ssh => "ssh",
        pm_vault::RecordKind::Token => "token",
        pm_vault::RecordKind::Note => "note",
        pm_vault::RecordKind::File => "file",
    }
}
fn map_attempt(value: AttemptError) -> ErrorCode {
    match value {
        AttemptError::AccessSuspended => ErrorCode::AccessSuspended,
        AttemptError::AgentRevoked => ErrorCode::AgentRevoked,
        AttemptError::CredentialUnavailable => ErrorCode::CredentialUnavailable,
        AttemptError::IdempotencyConflict => ErrorCode::IdempotencyConflict,
        AttemptError::IdempotencyExpired => ErrorCode::IdempotencyExpired,
        AttemptError::ResultExpired => ErrorCode::ResultExpired,
        AttemptError::InvalidArgument => ErrorCode::InvalidArgument,
        AttemptError::NotFound => ErrorCode::NotFound,
        AttemptError::RateLimited => ErrorCode::RateLimited,
        AttemptError::ClockUntrusted => ErrorCode::ClockUntrusted,
        AttemptError::Integrity | AttemptError::Storage(_) | AttemptError::Vault(_) => {
            ErrorCode::Internal
        }
    }
}
fn map_authorization(value: pm_vault::AuthorizationError) -> ErrorCode {
    match value {
        pm_vault::AuthorizationError::AccessSuspended => ErrorCode::AccessSuspended,
        pm_vault::AuthorizationError::AgentRevoked => ErrorCode::AgentRevoked,
        pm_vault::AuthorizationError::CredentialUnavailable => ErrorCode::CredentialUnavailable,
        pm_vault::AuthorizationError::Unauthorized => ErrorCode::Unauthorized,
        _ => ErrorCode::Internal,
    }
}

fn encode_into(value: &Json, output: &mut String) {
    match value {
        Json::Null => output.push_str("null"),
        Json::Bool(true) => output.push_str("true"),
        Json::Bool(false) => output.push_str("false"),
        Json::Number(number) => output.push_str(number),
        Json::String(string) => encode_string(string, output),
        Json::Array(values) => {
            output.push('[');
            for (index, item) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                encode_into(item, output);
            }
            output.push(']');
        }
        Json::Object(fields) => {
            output.push('{');
            for (index, (key, item)) in fields.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                encode_string(key, output);
                output.push(':');
                encode_into(item, output);
            }
            output.push('}');
        }
    }
}

fn encode_string(value: &str, output: &mut String) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            c if c.is_control() => output.push_str(&format!("\\u{:04x}", c as u32)),
            c => output.push(c),
        }
    }
    output.push('"');
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl Parser<'_> {
    fn value(&mut self, depth: usize) -> Result<Json, ParseError> {
        if depth > MAX_DEPTH {
            return Err(ParseError::TooDeep);
        }
        self.space();
        let byte = *self.bytes.get(self.at).ok_or(ParseError::InvalidJson)?;
        match byte {
            b'n' => self.literal(b"null", Json::Null),
            b't' => self.literal(b"true", Json::Bool(true)),
            b'f' => self.literal(b"false", Json::Bool(false)),
            b'"' => Ok(Json::String(self.string()?)),
            b'[' => self.array(depth),
            b'{' => self.object(depth),
            b'-' | b'0'..=b'9' => Ok(Json::Number(self.number()?)),
            _ => Err(ParseError::InvalidJson),
        }
    }
    fn literal(&mut self, literal: &[u8], value: Json) -> Result<Json, ParseError> {
        if self.bytes.get(self.at..self.at + literal.len()) != Some(literal) {
            return Err(ParseError::InvalidJson);
        }
        self.at += literal.len();
        Ok(value)
    }
    fn string(&mut self) -> Result<String, ParseError> {
        self.at += 1;
        let mut result = String::new();
        loop {
            let byte = *self.bytes.get(self.at).ok_or(ParseError::InvalidJson)?;
            self.at += 1;
            match byte {
                b'"' => return Ok(result),
                b'\\' => {
                    let escaped = *self.bytes.get(self.at).ok_or(ParseError::InvalidJson)?;
                    self.at += 1;
                    match escaped {
                        b'"' => result.push('"'),
                        b'\\' => result.push('\\'),
                        b'/' => result.push('/'),
                        b'b' => result.push('\u{0008}'),
                        b'f' => result.push('\u{000c}'),
                        b'n' => result.push('\n'),
                        b'r' => result.push('\r'),
                        b't' => result.push('\t'),
                        b'u' => {
                            let digits = self
                                .bytes
                                .get(self.at..self.at + 4)
                                .ok_or(ParseError::InvalidJson)?;
                            let text =
                                std::str::from_utf8(digits).map_err(|_| ParseError::InvalidJson)?;
                            let code = u16::from_str_radix(text, 16)
                                .map_err(|_| ParseError::InvalidJson)?;
                            self.at += 4;
                            let character =
                                char::from_u32(u32::from(code)).ok_or(ParseError::InvalidJson)?;
                            if (0xd800..=0xdfff).contains(&code) {
                                return Err(ParseError::InvalidJson);
                            }
                            result.push(character);
                        }
                        _ => return Err(ParseError::InvalidJson),
                    }
                }
                b if b < 0x20 => return Err(ParseError::InvalidJson),
                _b => {
                    let start = self.at - 1;
                    while self.at < self.bytes.len()
                        && self.bytes[self.at] >= 0x20
                        && self.bytes[self.at] != b'"'
                        && self.bytes[self.at] != b'\\'
                    {
                        self.at += 1;
                    }
                    let text = std::str::from_utf8(&self.bytes[start..self.at])
                        .map_err(|_| ParseError::InvalidUtf8)?;
                    result.push_str(text);
                }
            }
        }
    }
    fn number(&mut self) -> Result<String, ParseError> {
        let start = self.at;
        if self.bytes[self.at] == b'-' {
            self.at += 1;
        }
        match self.bytes.get(self.at) {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => {
                self.at += 1;
                while matches!(self.bytes.get(self.at), Some(b'0'..=b'9')) {
                    self.at += 1;
                }
            }
            _ => return Err(ParseError::InvalidJson),
        }
        if self.bytes.get(self.at) == Some(&b'.') {
            self.at += 1;
            let begin = self.at;
            while matches!(self.bytes.get(self.at), Some(b'0'..=b'9')) {
                self.at += 1;
            }
            if self.at == begin {
                return Err(ParseError::InvalidJson);
            }
        }
        if matches!(self.bytes.get(self.at), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.bytes.get(self.at), Some(b'+' | b'-')) {
                self.at += 1;
            }
            let begin = self.at;
            while matches!(self.bytes.get(self.at), Some(b'0'..=b'9')) {
                self.at += 1;
            }
            if self.at == begin {
                return Err(ParseError::InvalidJson);
            }
        }
        Ok(String::from_utf8(self.bytes[start..self.at].to_vec())
            .map_err(|_| ParseError::InvalidJson)?)
    }
    fn array(&mut self, depth: usize) -> Result<Json, ParseError> {
        self.at += 1;
        let mut values = Vec::new();
        self.space();
        if self.bytes.get(self.at) == Some(&b']') {
            self.at += 1;
            return Ok(Json::Array(values));
        }
        loop {
            values.push(self.value(depth + 1)?);
            self.space();
            match self.bytes.get(self.at) {
                Some(b',') => {
                    self.at += 1;
                }
                Some(b']') => {
                    self.at += 1;
                    return Ok(Json::Array(values));
                }
                _ => return Err(ParseError::InvalidJson),
            }
        }
    }
    fn object(&mut self, depth: usize) -> Result<Json, ParseError> {
        self.at += 1;
        let mut fields = Vec::new();
        self.space();
        if self.bytes.get(self.at) == Some(&b'}') {
            self.at += 1;
            return Ok(Json::Object(fields));
        }
        loop {
            self.space();
            if self.bytes.get(self.at) != Some(&b'"') {
                return Err(ParseError::InvalidJson);
            }
            let key = self.string()?;
            if fields.iter().any(|(known, _)| known == &key) {
                return Err(ParseError::DuplicateKey);
            }
            self.space();
            if self.bytes.get(self.at) != Some(&b':') {
                return Err(ParseError::InvalidJson);
            }
            self.at += 1;
            fields.push((key, self.value(depth + 1)?));
            self.space();
            match self.bytes.get(self.at) {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Json::Object(fields));
                }
                _ => return Err(ParseError::InvalidJson),
            }
        }
    }
    fn space(&mut self) {
        while matches!(self.bytes.get(self.at), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.at += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_framing_is_bounded_and_big_endian() {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, b"{}").unwrap();
        assert_eq!(&bytes[..4], &[0, 0, 0, 2]);
        assert_eq!(read_frame(&mut bytes.as_slice()).unwrap(), b"{}");
        let oversized = vec![0_u8; MAX_FRAME + 1];
        assert!(write_frame(&mut Vec::new(), &oversized).is_err());
    }
    #[test]
    fn hostile_json_is_rejected_without_lenient_fallback() {
        for value in [
            br#"{"a":1,"a":2}"#.as_slice(),
            br#"{"a":NaN}"#.as_slice(),
            br#"{"a":1} trailing"#.as_slice(),
        ] {
            assert!(matches!(
                parse_json(value),
                Err(ParseError::DuplicateKey | ParseError::InvalidJson | ParseError::TrailingBytes)
            ));
        }
    }
}
