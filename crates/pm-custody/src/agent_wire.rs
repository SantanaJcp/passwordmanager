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
use crate::human_wire::{Cursor, write_frame};

pub(crate) struct AgentService<'a> {
    pub path: &'a Path,
    pub device: [u8; 16],
    pub audit_custody: &'a Arc<AuditDeviceCustody>,
    pub admission: &'a crate::custody_admission::CustodyAdmission,
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
    serve_agent_requests(tls, service, &peer)
}

fn serve_agent_requests(
    tls: &mut (impl Read + Write),
    service: &AgentService<'_>,
    peer: &AgentPeer,
) -> Result<(), Failure> {
    loop {
        let request = read_agent_frame(tls).map_err(AgentReadFailure::public_failure)?;
        write_frame(tls, &handle_attempt_request(service, peer, &request)?)?;
    }
}

// Preserve the existing shared reader's bound; changing it is outside (5).
const MAX_AGENT_FRAME: usize = 18 * 1024 * 1024;

#[derive(Debug)]
enum ReadPhase {
    Header,
    Body,
}

enum AgentReadFailure {
    Io {
        phase: ReadPhase,
        source: std::io::Error,
    },
    Memory(pm_crypto::CryptoError),
    MalformedFrame,
}

impl AgentReadFailure {
    fn public_failure(self) -> Failure {
        // Only fixed categories, phase, OS code and ErrorKind reach diagnostics.
        // The original I/O/crypto cause remains owned by this typed boundary.
        match &self {
            Self::Io { phase, source } => eprintln!(
                "PM_AGENT_READ_FAILURE category=CUSTODY_UNAVAILABLE cause=io phase={phase:?} kind={:?} os_code={:?}",
                source.kind(),
                source.raw_os_error()
            ),
            Self::Memory(source) => eprintln!(
                "PM_AGENT_READ_FAILURE category=RESOURCE_UNAVAILABLE cause=protected-memory source={source:?}"
            ),
            Self::MalformedFrame => {
                eprintln!("PM_AGENT_READ_FAILURE category=INVALID_ARGUMENT cause=malformed-frame");
            }
        }
        Failure::Unavailable
    }
}

fn read_agent_frame(input: &mut impl Read) -> Result<pm_crypto::ProtectedBytes, AgentReadFailure> {
    let mut header = [0_u8; 4];
    input
        .read_exact(&mut header)
        .map_err(|source| AgentReadFailure::Io {
            phase: ReadPhase::Header,
            source,
        })?;
    let length = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| AgentReadFailure::MalformedFrame)?;
    if length == 0 || length > MAX_AGENT_FRAME {
        return Err(AgentReadFailure::MalformedFrame);
    }
    let mut frame = pm_crypto::ProtectedBytes::zeroed(length).map_err(AgentReadFailure::Memory)?;
    input
        .read_exact(&mut frame)
        .map_err(|source| AgentReadFailure::Io {
            phase: ReadPhase::Body,
            source,
        })?;
    Ok(frame)
}

#[allow(clippy::too_many_lines)]
fn handle_attempt_request(
    service: &AgentService<'_>,
    peer: &AgentPeer,
    request: &[u8],
) -> Result<Vec<u8>, Failure> {
    let (&opcode, rest) = request.split_first().ok_or(Failure::Unavailable)?;
    verify_admission_custody(service, opcode)?;
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
            let issued =
                u64::from_be_bytes(c.fixed(8)?.try_into().map_err(|_| Failure::Unavailable)?);
            let issued = i64::try_from(issued).map_err(|_| Failure::Unavailable)?;
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
                context.to_vec(),
                key,
            )
            .map_err(|_| Failure::Unavailable)?;
            attempts.start(peer, &start)
        }
        33 => {
            let mut c = Cursor::new(rest);
            let item = c.fixed(16)?.try_into().map_err(|_| Failure::Unavailable)?;
            let issued =
                u64::from_be_bytes(c.fixed(8)?.try_into().map_err(|_| Failure::Unavailable)?);
            let issued = i64::try_from(issued).map_err(|_| Failure::Unavailable)?;
            let nonce = c.fixed(16)?.try_into().map_err(|_| Failure::Unavailable)?;
            let integration = c.public_string()?;
            let version =
                u32::from_be_bytes(c.fixed(4)?.try_into().map_err(|_| Failure::Unavailable)?);
            let method = c.public_string()?;
            let destination = c.public_string()?;
            let context = c.bytes()?;
            c.finish()?;
            let key = IdempotencyKey::new(issued, nonce).map_err(|_| Failure::Unavailable)?;
            let start = StartAttempt::new(
                item,
                &integration,
                version,
                &method,
                &destination,
                context.to_vec(),
                key,
            )
            .map_err(|_| Failure::Unavailable)?;
            attempts.start(peer, &start)
        }
        31 => attempts.get(peer, rest.try_into().map_err(|_| Failure::Unavailable)?),
        32 => attempts.cancel(peer, rest.try_into().map_err(|_| Failure::Unavailable)?),
        40 => {
            let mut cursor = Cursor::new(rest);
            let item = cursor
                .fixed(16)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            let issued = i64::try_from(cursor.u64()?).map_err(|_| Failure::Unavailable)?;
            let nonce = cursor
                .fixed(16)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            let origin = cursor.public_string()?;
            cursor.finish()?;
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

// A narrow seam shared by all transports. W4 can change dispatch/identity
// admission independently; every new authentication still crosses this check.
fn verify_admission_custody(service: &AgentService<'_>, opcode: u8) -> Result<(), Failure> {
    if matches!(opcode, 30 | 33 | 40 | 41) {
        service.admission.verify()?;
    }
    Ok(())
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

#[cfg(test)]
mod error_propagation_tests {
    use super::*;

    struct BrokenWire {
        input: std::io::Cursor<Vec<u8>>,
        kind: Option<std::io::ErrorKind>,
    }
    impl Read for BrokenWire {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if let Some(kind) = self.kind {
                return Err(std::io::Error::new(
                    kind,
                    "PMW3C_SYNTHETIC_PRIVATE_PATH_PAYLOAD",
                ));
            }
            self.input.read(output)
        }
    }
    impl Write for BrokenWire {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            panic!("response after read failure")
        }
        fn flush(&mut self) -> std::io::Result<()> {
            panic!("flush after read failure")
        }
    }
    #[test]
    fn failed_agent_read_is_never_a_successful_connection() {
        let custody = Arc::new(AuditDeviceCustody::generate().unwrap());
        let unused = Path::new("PMW3C_UNUSED_SYNTHETIC_PATH");
        let admission = crate::custody_admission::CustodyAdmission::load(
            unused,
            unused,
            |_| Ok([0; 32]),
            |_| Ok([0; 32]),
        )
        .unwrap();
        let service = AgentService {
            path: unused,
            device: [0x28; 16],
            audit_custody: &custody,
            admission: &admission,
        };
        let peer = AgentPeer::from_transport_rpk(&[0x28; 44]).unwrap();
        for (name, bytes, kind) in [
            ("timeout", vec![], Some(std::io::ErrorKind::TimedOut)),
            ("io", vec![], Some(std::io::ErrorKind::BrokenPipe)),
            ("eof", vec![], None),
            ("partial-header", vec![0, 0], None),
            ("partial-body", vec![0, 0, 0, 2, 1], None),
            ("malformed", vec![0, 0, 0, 0], None),
        ] {
            let mut tls = BrokenWire {
                input: std::io::Cursor::new(bytes),
                kind,
            };
            let result = serve_agent_requests(&mut tls, &service, &peer);
            println!(
                "PMW3C_AGENT_READ_OBSERVED mode={name} success={}",
                result.is_ok()
            );
            assert!(
                matches!(result, Err(Failure::Unavailable)),
                "read failure became successful connection: {name}"
            );
        }
    }
    #[test]
    fn classified_agent_reader_preserves_io_phase_and_original_cause() {
        let marker = "PMW3C_SYNTHETIC_PRIVATE_PATH_PAYLOAD";
        let mut wire = BrokenWire {
            input: std::io::Cursor::new(vec![]),
            kind: Some(std::io::ErrorKind::TimedOut),
        };
        let Err(failure) = read_agent_frame(&mut wire) else {
            panic!("read accepted")
        };
        assert!(
            matches!(&failure, AgentReadFailure::Io { phase: ReadPhase::Header, source } if source.kind() == std::io::ErrorKind::TimedOut && source.to_string() == marker)
        );
        assert!(matches!(failure.public_failure(), Failure::Unavailable));
        let mut body = [0, 0, 0, 2, 1].as_slice();
        assert!(
            matches!(read_agent_frame(&mut body), Err(AgentReadFailure::Io { phase: ReadPhase::Body, source }) if source.kind() == std::io::ErrorKind::UnexpectedEof)
        );
        let mut valid = [0, 0, 0, 1, 0x28].as_slice();
        let Ok(frame) = read_agent_frame(&mut valid) else {
            panic!("valid frame rejected")
        };
        assert_eq!(&*frame, &[0x28]);
        let too_large = u32::try_from(MAX_AGENT_FRAME + 1)
            .unwrap()
            .to_be_bytes()
            .as_slice()
            .to_owned();
        assert!(matches!(
            read_agent_frame(&mut too_large.as_slice()),
            Err(AgentReadFailure::MalformedFrame)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn agent_memory_failure_retains_its_internal_category() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "agent_wire::error_propagation_tests::agent_memory_child",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stdout.contains("PMW3C_AGENT_MEMORY_CONTROL_READY"));
        assert!(output.status.success(), "{stderr}");
        assert!(stderr.contains("category=RESOURCE_UNAVAILABLE"));
        assert!(!stderr.contains("PMW3C_SYNTHETIC_PRIVATE_PATH_PAYLOAD"));
        println!("{stdout}{stderr}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "isolated RLIMIT_MEMLOCK child, invoked by the parent"]
    fn agent_memory_child() {
        let mut control = [0, 0, 0, 1, 0x28].as_slice();
        assert!(read_agent_frame(&mut control).is_ok());
        println!("PMW3C_AGENT_MEMORY_CONTROL_READY");
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: only the isolated child changes its limit.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const limit) },
            0
        );
        let mut header_only = [0, 0, 0, 1].as_slice();
        let Err(error) = read_agent_frame(&mut header_only) else {
            panic!("unlocked frame accepted")
        };
        assert!(matches!(
            &error,
            AgentReadFailure::Memory(pm_crypto::CryptoError::ResourceUnavailable)
        ));
        assert!(matches!(error.public_failure(), Failure::Unavailable));
    }
}
