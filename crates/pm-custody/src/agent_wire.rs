// SPDX-License-Identifier: AGPL-3.0-only

//! One delegated wire engine shared by every native transport.

use std::{
    io::{Read, Write},
    path::Path,
    sync::Arc,
};

use pm_vault::{
    AgentPeer, AttemptState, AttemptVault, AuditDeviceCustody, DelegatedVault, IdempotencyKey,
    PasskeyProvider, PasskeyRequest, PasskeyStatus, RecordKind, StartAttempt,
};

use crate::Failure;

const MAX_FRAME: usize = 18 * 1024 * 1024;

pub(crate) struct AgentService<'a> {
    pub path: &'a Path,
    pub device: [u8; 16],
    pub audit_custody: &'a Arc<AuditDeviceCustody>,
}

pub(crate) fn serve_agent(
    tls: &mut (impl Read + Write),
    service: &AgentService<'_>,
    observed_rpk: &[u8],
) -> Result<(), Failure> {
    let peer = AgentPeer::from_transport_rpk(observed_rpk).map_err(|_| Failure::Unavailable)?;
    let vault = DelegatedVault::open(
        service.path,
        service.device,
        Arc::clone(service.audit_custody),
    )
    .map_err(|_| Failure::Unavailable)?;
    let credentials = vault.discover(&peer);
    let mut response = if credentials.is_ok() {
        vec![0]
    } else {
        vec![1]
    };
    if let Ok(credentials) = credentials {
        response.extend_from_slice(
            &u16::try_from(credentials.len())
                .map_err(|_| Failure::Unavailable)?
                .to_be_bytes(),
        );
        for credential in credentials {
            response.extend_from_slice(credential.item_id());
            response.extend_from_slice(credential.revision_id());
            push_bytes(
                &mut response,
                record_kind_name(credential.kind()).as_bytes(),
            )?;
            push_bytes(&mut response, credential.title().as_bytes())?;
            push_bytes(
                &mut response,
                credential.destination().unwrap_or("").as_bytes(),
            )?;
            push_bytes(&mut response, credential.account().unwrap_or("").as_bytes())?;
        }
    }
    write_frame(tls, &response)?;
    loop {
        let Ok(request) = read_frame(tls) else {
            return Ok(());
        };
        write_frame(tls, &handle_attempt_request(service, &peer, &request)?)?;
    }
}

#[allow(clippy::too_many_lines)]
fn handle_attempt_request(
    service: &AgentService<'_>,
    peer: &AgentPeer,
    request: &[u8],
) -> Result<Vec<u8>, Failure> {
    let (&opcode, rest) = request.split_first().ok_or(Failure::Unavailable)?;
    let attempts = AttemptVault::open(
        DelegatedVault::open(
            service.path,
            service.device,
            Arc::clone(service.audit_custody),
        )
        .map_err(|_| Failure::Unavailable)?,
    )
    .map_err(|_| Failure::Unavailable)?;
    if opcode == 41 {
        let request = PasskeyRequest::from_bytes(rest).map_err(|_| Failure::Unavailable)?;
        let provider = PasskeyProvider::open(attempts).map_err(|_| Failure::Unavailable)?;
        return match provider.begin_for_peer(peer, &request) {
            Ok(status) => encode_passkey_status(Some(status)),
            Err(_) => Ok(vec![1]),
        };
    }
    if opcode == 42 {
        let request_id = rest.try_into().map_err(|_| Failure::Unavailable)?;
        let provider = PasskeyProvider::open(attempts).map_err(|_| Failure::Unavailable)?;
        return match provider.response_for_peer(peer, request_id) {
            Ok(status) => encode_passkey_status(status),
            Err(_) => Ok(vec![1]),
        };
    }
    let outcome = match opcode {
        30 => {
            let mut c = Cursor::new(rest);
            let item = c.fixed(16)?.try_into().map_err(|_| Failure::Unavailable)?;
            let issued = i64::try_from(c.u64()?).map_err(|_| Failure::Unavailable)?;
            let nonce = c.fixed(16)?.try_into().map_err(|_| Failure::Unavailable)?;
            let context = c.bytes()?;
            c.finish()?;
            let key = IdempotencyKey::new(issued, nonce).map_err(|_| Failure::Unavailable)?;
            let start = StartAttempt::new(
                item,
                "controlled.external",
                1,
                "password",
                "https://ticket07.invalid/login",
                context,
                key,
            )
            .map_err(|_| Failure::Unavailable)?;
            attempts.start(peer, &start)
        }
        33 => {
            let mut c = Cursor::new(rest);
            let item = c.fixed(16)?.try_into().map_err(|_| Failure::Unavailable)?;
            let issued = i64::try_from(c.u64()?).map_err(|_| Failure::Unavailable)?;
            let nonce = c.fixed(16)?.try_into().map_err(|_| Failure::Unavailable)?;
            let integration = String::from_utf8(c.bytes()?).map_err(|_| Failure::Unavailable)?;
            let version = c.u32()?;
            let method = String::from_utf8(c.bytes()?).map_err(|_| Failure::Unavailable)?;
            let destination = String::from_utf8(c.bytes()?).map_err(|_| Failure::Unavailable)?;
            let context = c.bytes()?;
            c.finish()?;
            let key = IdempotencyKey::new(issued, nonce).map_err(|_| Failure::Unavailable)?;
            let start = StartAttempt::new(
                item,
                &integration,
                version,
                &method,
                &destination,
                context,
                key,
            )
            .map_err(|_| Failure::Unavailable)?;
            attempts.start(peer, &start)
        }
        31 => attempts.get(peer, rest.try_into().map_err(|_| Failure::Unavailable)?),
        32 => attempts.cancel(peer, rest.try_into().map_err(|_| Failure::Unavailable)?),
        40 => {
            let mut c = Cursor::new(rest);
            let item = c.fixed(16)?.try_into().map_err(|_| Failure::Unavailable)?;
            let issued = i64::try_from(c.u64()?).map_err(|_| Failure::Unavailable)?;
            let nonce = c.fixed(16)?.try_into().map_err(|_| Failure::Unavailable)?;
            let origin = String::from_utf8(c.bytes()?).map_err(|_| Failure::Unavailable)?;
            c.finish()?;
            let key = IdempotencyKey::new(issued, nonce).map_err(|_| Failure::Unavailable)?;
            let start = StartAttempt::new(
                item,
                "vault-webauthn-provider",
                1,
                "webauthn",
                &origin,
                b"keycloak-webauthn/1".to_vec(),
                key,
            )
            .map_err(|_| Failure::Unavailable)?;
            attempts.start(peer, &start)
        }
        _ => return Err(Failure::Unavailable),
    };
    match outcome {
        Ok(snapshot) => encode_attempt_snapshot(&snapshot),
        Err(error) => Ok(vec![attempt_error_status(&error)]),
    }
}

fn read_frame(input: &mut impl Read) -> Result<Vec<u8>, Failure> {
    let mut header = [0_u8; 4];
    input
        .read_exact(&mut header)
        .map_err(|_| Failure::Unavailable)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(Failure::Unavailable);
    }
    let mut value = vec![0; length];
    input
        .read_exact(&mut value)
        .map_err(|_| Failure::Unavailable)?;
    Ok(value)
}

fn write_frame(output: &mut impl Write, value: &[u8]) -> Result<(), Failure> {
    if value.is_empty() || value.len() > MAX_FRAME {
        return Err(Failure::Unavailable);
    }
    output
        .write_all(
            &u32::try_from(value.len())
                .map_err(|_| Failure::Unavailable)?
                .to_be_bytes(),
        )
        .map_err(|_| Failure::Unavailable)?;
    output.write_all(value).map_err(|_| Failure::Unavailable)?;
    output.flush().map_err(|_| Failure::Unavailable)
}

fn push_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), Failure> {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| Failure::Unavailable)?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    fn fixed(&mut self, length: usize) -> Result<&'a [u8], Failure> {
        let end = self.at.checked_add(length).ok_or(Failure::Unavailable)?;
        let value = self.bytes.get(self.at..end).ok_or(Failure::Unavailable)?;
        self.at = end;
        Ok(value)
    }
    fn u32(&mut self) -> Result<u32, Failure> {
        Ok(u32::from_be_bytes(
            self.fixed(4)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, Failure> {
        Ok(u64::from_be_bytes(
            self.fixed(8)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?,
        ))
    }
    fn bytes(&mut self) -> Result<Vec<u8>, Failure> {
        let length = usize::try_from(self.u32()?).map_err(|_| Failure::Unavailable)?;
        Ok(self.fixed(length)?.to_vec())
    }
    fn finish(self) -> Result<(), Failure> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(Failure::Unavailable)
        }
    }
}

fn encode_passkey_status(status: Option<PasskeyStatus>) -> Result<Vec<u8>, Failure> {
    let mut response = vec![0];
    let encoded = status.map(|value| value.to_bytes()).unwrap_or_default();
    push_bytes(&mut response, &encoded)?;
    Ok(response)
}

fn encode_attempt_snapshot(snapshot: &pm_vault::AttemptSnapshot) -> Result<Vec<u8>, Failure> {
    let mut out = vec![0];
    out.extend_from_slice(snapshot.attempt_id());
    out.extend_from_slice(snapshot.credential_id());
    out.extend_from_slice(snapshot.revision_id());
    push_bytes(&mut out, attempt_state_name(snapshot.state()).as_bytes())?;
    push_bytes(&mut out, snapshot.reason().unwrap_or("").as_bytes())?;
    push_bytes(&mut out, snapshot.result().unwrap_or(&[]))?;
    push_bytes(&mut out, snapshot.integration_id().as_bytes())?;
    out.extend_from_slice(&snapshot.integration_version().to_be_bytes());
    Ok(out)
}

fn attempt_state_name(state: AttemptState) -> &'static str {
    match state {
        AttemptState::Created => "CREATED",
        AttemptState::Running => "RUNNING",
        AttemptState::WaitingForHuman => "WAITING_FOR_HUMAN",
        AttemptState::Succeeded => "SUCCEEDED",
        AttemptState::Failed => "FAILED",
        AttemptState::Cancelled => "CANCELLED",
        AttemptState::Expired => "EXPIRED",
        AttemptState::Indeterminate => "INDETERMINATE",
    }
}

fn attempt_error_status(error: &pm_vault::AttemptError) -> u8 {
    use pm_vault::AttemptError::{
        AccessSuspended, AgentRevoked, ClockUntrusted, CredentialUnavailable, IdempotencyConflict,
        IdempotencyExpired, NotFound, RateLimited,
    };
    match error {
        NotFound => 2,
        IdempotencyConflict => 3,
        AccessSuspended => 4,
        AgentRevoked => 5,
        CredentialUnavailable => 6,
        ClockUntrusted => 7,
        RateLimited => 8,
        IdempotencyExpired => 9,
        _ => 1,
    }
}

fn record_kind_name(kind: RecordKind) -> &'static str {
    match kind {
        RecordKind::Password => "password",
        RecordKind::Totp => "totp",
        RecordKind::Passkey => "passkey",
        RecordKind::Ssh => "ssh",
        RecordKind::Token => "token",
        RecordKind::Note => "note",
        RecordKind::File => "file",
    }
}
