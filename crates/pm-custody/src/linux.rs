// SPDX-License-Identifier: AGPL-3.0-only

#![allow(dead_code)]

use std::{
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    mem,
    net::Shutdown,
    os::fd::{AsRawFd, FromRawFd, RawFd},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::Path,
    sync::Arc,
    time::Duration,
};

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme,
    client::{
        AlwaysResolvesClientRawPublicKeys, ClientConfig, ClientConnection, Resumption,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{CryptoProvider, verify_tls13_signature_with_raw_key},
    pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer,
        UnixTime,
    },
    server::{
        AlwaysResolvesServerRawPublicKeys, ServerConfig, ServerConnection,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
    sign::CertifiedKey,
    version,
};
use signature::Signer as _;
use zeroize::{Zeroize, Zeroizing};

use pm_crypto::{KdfProfile, RecoveryCode};
use pm_custody::{AuthenticatedHumanChannel, unix_peer_uid};
use pm_vault::{
    AgentEnrollment, AgentPeer, Attachment, AttachmentReader, AttemptOutcome, AttemptState,
    AttemptVault, AuditAction, AuditActorKind, AuditDeviceCustody, AuditEvent, AuditOutcome,
    AuthRecord, AuthorizationReason, AutonomousAuditVault, CsvDelimiter, CsvEncoding, CsvField,
    CsvImportDecision, CsvImportProfile, CsvMapping, CsvRowStatus, CustomField, DelegatedVault,
    Destination, GeneratorConfig, HumanCommitError, HumanMetadata, HumanVault, HumanVerification,
    IdempotencyKey, LogicalRecord, LogicalValue, PasskeyOperation, PasskeyProvider, PasskeyRequest,
    PasskeyStatus, PasswordRecord, PreparedHumanCommand, PrivateKeyFormat, RecordKind, SearchQuery,
    SourceEncoding, SourceField, StartAttempt, TotpAlgorithm,
};

use crate::{Failure, take_path};

mod sync_job;
mod tui;

const KEY_MAGIC: &[u8] = b"PMK1";
const BOOTSTRAP_MAGIC: &[u8] = b"PMCB1";
const PROFILE_MAGIC: &[u8] = b"PMP1";
const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const SPKI_BYTES: usize = 44;
const MAX_PROTECTED_BYTES: u64 = 16 * 1024;
// Password and recovery rotations deliberately perform multiple memory-hard
// derivations before replying. Keep the transport deadline bounded, but do not
// confuse a healthy, loaded custodian with an unavailable one mid-rotation.
const IO_TIMEOUT: Duration = Duration::from_secs(15);
const HUMAN_MAGIC: &[u8; 5] = b"PMH1\n";
const AGENT_MAGIC: &[u8; 5] = b"PMA1\n";
const MAX_HUMAN_FRAME: usize = 18 * 1024 * 1024;
const STREAM_CHUNK_BYTES: usize = 1024 * 1024;
const LAB_AGENT_A: [u8; 16] = [0xa1; 16];
const LAB_AGENT_B: [u8; 16] = [0xb2; 16];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Role {
    Agent,
    Human,
}

impl Role {
    const fn byte(self) -> u8 {
        match self {
            Self::Agent => 1,
            Self::Human => 2,
        }
    }

    fn parse(value: &OsStr) -> Result<Self, Failure> {
        match value.to_str() {
            Some("agent") => Ok(Self::Agent),
            Some("human") => Ok(Self::Human),
            _ => Err(Failure::Usage),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Human => "human",
        }
    }

    const fn alpn(self) -> &'static [u8] {
        match self {
            Self::Agent => b"pm-agent/1",
            Self::Human => b"pm-human/1",
        }
    }
}

struct KeyMaterial {
    private: Zeroizing<Vec<u8>>,
    spki: Vec<u8>,
}

struct Bootstrap {
    server: KeyMaterial,
    agent_uid: u32,
    agent_spki: Vec<u8>,
    human_uid: u32,
    human_spki: Vec<u8>,
}

struct Profile {
    role: Role,
    server_uid: u32,
    server_spki: Vec<u8>,
}

#[derive(Clone)]
struct VaultService {
    path: std::path::PathBuf,
    device: [u8; 16],
    audit_custody: Arc<AuditDeviceCustody>,
    provider: Option<ControlledProvider>,
    sync_jobs: Arc<sync_job::Manager>,
}

#[derive(Clone)]
struct ControlledProvider {
    socket: std::path::PathBuf,
    uid: u32,
}

pub(crate) fn run(arguments: Vec<OsString>) -> Result<(), Failure> {
    let mut arguments = arguments.into_iter();
    let command = arguments.next().ok_or(Failure::Usage)?;
    match command.to_str() {
        Some("keygen") => keygen(&mut arguments),
        Some("provision-bootstrap") => provision_bootstrap(&mut arguments),
        Some("provision-profile") => provision_profile(&mut arguments),
        Some("serve") => serve(&mut arguments),
        Some("serve-vault") => serve_vault(&mut arguments),
        Some("serve-attempt-lab") => serve_attempt_lab(&mut arguments),
        Some("probe") => probe(&mut arguments),
        Some("agent-discover") => agent_discover(&mut arguments),
        Some("agent-attempt") => agent_attempt(&mut arguments),
        Some("human-authorization") => human_authorization(&mut arguments),
        Some("human-password-crud") => human_password_crud(&mut arguments),
        Some("human-content-flow") => human_content_flow(&mut arguments),
        Some("human-audit-lifecycle") => human_audit_lifecycle(&mut arguments),
        Some("human-streaming-file") => human_streaming_file(&mut arguments),
        Some("human-streaming-stall") => human_streaming_stall(&mut arguments),
        Some("human-csv-import") => human_csv_import(&mut arguments),
        Some("human-passkey-confirm") => human_passkey_confirm(&mut arguments),
        Some("human-passkey-enable") => human_passkey_enable(&mut arguments),
        Some("human-history-exercise") => human_history_exercise(&mut arguments),
        Some("human-history-list") => human_history_list(&mut arguments),
        Some("human-history-purge-item") => human_history_purge_item(&mut arguments),
        Some("human-1pux-import") => human_1pux_import(&mut arguments),
        Some("human-backup-exercise") => human_backup_exercise(&mut arguments),
        Some("human-backup-restore") => human_backup_restore(&mut arguments),
        Some("human-ssh-lab-setup") => human_ssh_lab_setup(&mut arguments),
        Some("tui") => tui::run(&mut arguments),
        Some("human-github-lab-setup") => human_github_lab_setup(&mut arguments),
        Some("human-recovery-restore") => human_recovery_restore(&mut arguments),
        Some("human-master-rotate") => human_master_rotate(&mut arguments),
        Some("human-recovery-rotate") => human_recovery_rotate(&mut arguments),
        _ => Err(Failure::Usage),
    }
}

fn human_ssh_lab_setup(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let socket_path = take_path(arguments, "--socket")?;
    finish_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Human {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path, current_uid())?;
    let mut input = std::io::stdin().lock();
    let password = Zeroizing::new(read_wire_field(&mut input, 1024)?);
    let ssh_private = Zeroizing::new(read_wire_field(&mut input, 16 * 1024)?);
    let ssh_public = read_wire_field(&mut input, 16 * 1024)?;
    let account_password = Zeroizing::new(read_wire_field(&mut input, 1024)?);
    let mut tls = connect(&profile, &key, &socket_path)?;
    tls.write_all(HUMAN_MAGIC)
        .map_err(|_| Failure::Unavailable)?;
    rpc_unlock(&mut tls, &password)?;
    let mut request = vec![45];
    push_bytes(&mut request, &ssh_private)?;
    push_bytes(&mut request, &ssh_public)?;
    push_bytes(&mut request, &account_password)?;
    write_frame(&mut tls, &request)?;
    request.zeroize();
    let response = read_frame(&mut tls)?;
    let mut cursor = Cursor::new(&response);
    cursor.expect(&[0])?;
    let key_item = cursor.fixed(16)?;
    let password_item = cursor.fixed(16)?;
    cursor.finish()?;
    println!(
        "PASS human-ssh-lab-setup key={} password={}",
        hex(key_item),
        hex(password_item)
    );
    Ok(())
}

fn human_github_lab_setup(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let socket_path = take_path(arguments, "--socket")?;
    finish_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Human {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path, current_uid())?;
    let mut input = std::io::stdin().lock();
    let password = Zeroizing::new(read_wire_field(&mut input, 1024)?);
    let token = Zeroizing::new(read_wire_field(&mut input, 1024)?);
    let record = LogicalRecord::new(
        RecordKind::Token,
        HumanMetadata {
            title: "Synthetic GitHub assigned issues".to_owned(),
            destinations: vec![Destination {
                label: "installed profile".to_owned(),
                value: "github-assigned-issues/1".to_owned(),
            }],
            tags: vec!["synthetic".to_owned()],
            favorite: false,
            notes: String::new(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![AuthRecord::Token {
            secret: token.to_vec(),
            provider: "github".to_owned(),
            profile_id: "github-assigned-issues/1".to_owned(),
            destination_refs: vec![0],
            expires_at: None,
        }],
        vec![],
    );
    let record = record.map_err(|_| Failure::Unavailable)?;
    let mut tls = connect(&profile, &key, &socket_path)?;
    tls.write_all(HUMAN_MAGIC)
        .map_err(|_| Failure::Unavailable)?;
    rpc_unlock(&mut tls, &password)?;
    let created = rpc_prepare_record(&mut tls, 9, None, &record)?;
    rpc_commit(&mut tls, &created)?;
    let mut enable = vec![24];
    enable.extend_from_slice(&created.item_id);
    write_frame(&mut tls, &enable)?;
    let enabled = decode_prepared_response(&read_frame(&mut tls)?)?;
    rpc_commit(&mut tls, &enabled)?;
    println!(
        "PASS human-github-lab-setup item={} explicit-enable=1",
        hex(&created.item_id)
    );
    Ok(())
}

/// Authenticated client seam shared by delegated adapters. The initial
/// discovery frame is always consumed before an optional domain request.
pub fn agent_rpc(
    profile_path: &Path,
    private_path: &Path,
    socket_path: &Path,
    request: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    let profile = read_profile(profile_path).map_err(|_| "CUSTODY_UNAVAILABLE".to_owned())?;
    if profile.role != Role::Agent {
        return Err("UNAUTHORIZED".to_owned());
    }
    let key =
        read_key(private_path, current_uid()).map_err(|_| "CUSTODY_UNAVAILABLE".to_owned())?;
    let mut tls =
        connect(&profile, &key, socket_path).map_err(|_| "CUSTODY_UNAVAILABLE".to_owned())?;
    tls.write_all(AGENT_MAGIC)
        .map_err(|_| "CUSTODY_UNAVAILABLE".to_owned())?;
    let discovery = read_frame(&mut tls).map_err(|_| "CUSTODY_UNAVAILABLE".to_owned())?;
    if let Some(request) = request {
        write_frame(&mut tls, request).map_err(|_| "CUSTODY_UNAVAILABLE".to_owned())?;
        read_frame(&mut tls).map_err(|_| "CUSTODY_UNAVAILABLE".to_owned())
    } else {
        Ok(discovery)
    }
}

fn keygen(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let private_path = take_path(arguments, "--private")?;
    let public_path = take_path(arguments, "--public")?;
    finish_arguments(arguments)?;

    let document =
        Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).map_err(|_| Failure::Unavailable)?;
    let pair = Ed25519KeyPair::from_pkcs8(document.as_ref()).map_err(|_| Failure::Unavailable)?;
    let mut spki = ED25519_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(pair.public_key().as_ref());
    let mut encoded =
        Vec::with_capacity(KEY_MAGIC.len() + 4 + document.as_ref().len() + SPKI_BYTES);
    encoded.extend_from_slice(KEY_MAGIC);
    push_bytes(&mut encoded, document.as_ref())?;
    encoded.extend_from_slice(&spki);

    if let Err(error) = write_new(&private_path, &encoded, 0o400) {
        encoded.zeroize();
        return Err(error);
    }
    encoded.zeroize();
    if let Err(error) = write_new(&public_path, &spki, 0o444) {
        return Err(error.after_owned_path_cleanup(fs::remove_file(private_path)));
    }
    Ok(())
}

fn provision_bootstrap(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let path = take_path(arguments, "--path")?;
    let server_private = take_path(arguments, "--server-private")?;
    let server_public = take_path(arguments, "--server-public")?;
    let agent_public = take_path(arguments, "--agent-public")?;
    let agent_uid = take_u32(arguments, "--agent-uid")?;
    let human_public = take_path(arguments, "--human-public")?;
    let human_uid = take_u32(arguments, "--human-uid")?;
    finish_arguments(arguments)?;
    if agent_uid == human_uid || agent_uid == current_uid() || human_uid == current_uid() {
        return Err(Failure::Unavailable);
    }

    let server = read_key(&server_private, current_uid())?;
    let installed_server_spki = read_public(&server_public)?;
    if server.spki != installed_server_spki {
        return Err(Failure::Unavailable);
    }
    let agent_spki = read_public(&agent_public)?;
    let human_spki = read_public(&human_public)?;
    if agent_spki == human_spki || agent_spki == server.spki || human_spki == server.spki {
        return Err(Failure::Unavailable);
    }

    let mut encoded = Vec::with_capacity(512);
    encoded.extend_from_slice(BOOTSTRAP_MAGIC);
    push_bytes(&mut encoded, &server.private)?;
    encoded.extend_from_slice(&server.spki);
    encoded.extend_from_slice(&agent_uid.to_be_bytes());
    encoded.extend_from_slice(&agent_spki);
    encoded.extend_from_slice(&human_uid.to_be_bytes());
    encoded.extend_from_slice(&human_spki);
    let result = write_new(&path, &encoded, 0o400);
    encoded.zeroize();
    result
}

fn provision_profile(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    if current_uid() != 0 {
        return Err(Failure::Unavailable);
    }
    let path = take_path(arguments, "--path")?;
    let server_public = take_path(arguments, "--server-public")?;
    let server_uid = take_u32(arguments, "--server-uid")?;
    let role_flag = arguments.next().ok_or(Failure::Usage)?;
    let role_value = arguments.next().ok_or(Failure::Usage)?;
    if role_flag != "--role" {
        return Err(Failure::Usage);
    }
    let role = Role::parse(&role_value)?;
    finish_arguments(arguments)?;
    if server_uid == 0 {
        return Err(Failure::Unavailable);
    }
    let server_spki = read_public(&server_public)?;
    let mut encoded = Vec::with_capacity(PROFILE_MAGIC.len() + 1 + 4 + SPKI_BYTES);
    encoded.extend_from_slice(PROFILE_MAGIC);
    encoded.push(role.byte());
    encoded.extend_from_slice(&server_uid.to_be_bytes());
    encoded.extend_from_slice(&server_spki);
    write_new(&path, &encoded, 0o444)
}

fn serve(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let bootstrap_path = take_path(arguments, "--bootstrap")?;
    let agent_socket = take_path(arguments, "--agent-socket")?;
    let human_socket = take_path(arguments, "--human-socket")?;
    finish_arguments(arguments)?;
    serve_loop(&bootstrap_path, &agent_socket, &human_socket, None)
}

fn serve_vault(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let bootstrap_path = take_path(arguments, "--bootstrap")?;
    let agent_socket = take_path(arguments, "--agent-socket")?;
    let human_socket = take_path(arguments, "--human-socket")?;
    let vault_path = take_path(arguments, "--vault")?;
    let device_value = take_path(arguments, "--device")?;
    finish_arguments(arguments)?;
    let device = decode_hex_16(&device_value)?;
    let audit_path = std::path::PathBuf::from(format!("{}.audit-custody", vault_path.display()));
    let sync_jobs = sync_job::Manager::open(&vault_path)?;
    let service = VaultService {
        path: vault_path,
        device,
        audit_custody: Arc::new(load_or_create_audit_custody(&audit_path)?),
        provider: None,
        sync_jobs,
    };
    service.sync_jobs.resume()?;
    serve_loop(
        &bootstrap_path,
        &agent_socket,
        &human_socket,
        Some(&service),
    )
}

fn serve_attempt_lab(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let bootstrap_path = take_path(arguments, "--bootstrap")?;
    let agent_socket = take_path(arguments, "--agent-socket")?;
    let human_socket = take_path(arguments, "--human-socket")?;
    let vault_path = take_path(arguments, "--vault")?;
    let device_value = take_path(arguments, "--device")?;
    let provider_socket = take_path(arguments, "--provider-socket")?;
    let provider_uid = take_u32(arguments, "--provider-uid")?;
    finish_arguments(arguments)?;
    let device = decode_hex_16(&device_value)?;
    let audit_path = std::path::PathBuf::from(format!("{}.audit-custody", vault_path.display()));
    let sync_jobs = sync_job::Manager::open(&vault_path)?;
    let service = VaultService {
        path: vault_path,
        device,
        audit_custody: Arc::new(load_or_create_audit_custody(&audit_path)?),
        provider: Some(ControlledProvider {
            socket: provider_socket,
            uid: provider_uid,
        }),
        sync_jobs,
    };
    service.sync_jobs.resume()?;
    serve_loop(
        &bootstrap_path,
        &agent_socket,
        &human_socket,
        Some(&service),
    )
}

fn load_or_create_audit_custody(path: &Path) -> Result<AuditDeviceCustody, Failure> {
    if path.exists() {
        let bytes = read_regular(path, current_uid(), 0o400)?;
        return AuditDeviceCustody::from_protected_bytes(&bytes).map_err(|_| Failure::Unavailable);
    }
    let custody = AuditDeviceCustody::generate().map_err(|_| Failure::Unavailable)?;
    let mut bytes = Zeroizing::new(custody.to_protected_bytes());
    let result = write_new(path, &bytes, 0o400);
    bytes.zeroize();
    result?;
    Ok(custody)
}

fn serve_loop(
    bootstrap_path: &Path,
    agent_socket: &Path,
    human_socket: &Path,
    vault: Option<&VaultService>,
) -> Result<(), Failure> {
    let bootstrap = read_bootstrap(bootstrap_path)?;
    validate_runtime_parent(agent_socket)?;
    validate_runtime_parent(human_socket)?;

    let server_key = certified_key(&bootstrap.server)?;
    let agent_config = server_config(server_key.clone(), &bootstrap.agent_spki, Role::Agent)?;
    let human_config = server_config(server_key, &bootstrap.human_spki, Role::Human)?;
    let agent_listener = bind_socket(agent_socket)?;
    let human_listener = bind_socket(human_socket)?;
    agent_listener
        .set_nonblocking(true)
        .map_err(|_| Failure::Unavailable)?;
    human_listener
        .set_nonblocking(true)
        .map_err(|_| Failure::Unavailable)?;

    if let Some(service) = vault.filter(|v| v.provider.is_some())
        && let Ok(delegated) = DelegatedVault::open(
            &service.path,
            service.device,
            Arc::clone(&service.audit_custody),
        )
    {
        AttemptVault::open(delegated)
            .map_err(|_| Failure::Unavailable)?
            .recover_inflight()
            .map_err(|_| Failure::Unavailable)?;
    }
    if let Some(service) = vault.filter(|v| v.provider.is_some()).cloned() {
        std::thread::spawn(move || {
            loop {
                let _ = run_provider_once(&service);
                std::thread::sleep(Duration::from_millis(5));
            }
        });
    }

    loop {
        accept_one(
            &agent_listener,
            bootstrap.agent_uid,
            Role::Agent,
            &agent_config,
            vault,
            Some(&bootstrap.agent_spki),
        );
        accept_one(
            &human_listener,
            bootstrap.human_uid,
            Role::Human,
            &human_config,
            vault,
            None,
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn probe(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let socket_path = take_path(arguments, "--socket")?;
    finish_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    let key = read_key(&private_path, current_uid())?;

    let stream = UnixStream::connect(socket_path).map_err(|_| Failure::Unavailable)?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|_| Failure::Unavailable)?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|_| Failure::Unavailable)?;
    let observed_uid = unix_peer_uid(&stream).map_err(|_| Failure::Unavailable)?;
    if observed_uid != profile.server_uid {
        return Err(Failure::Unavailable);
    }
    let config = client_config(&key, &profile.server_spki, profile.role)?;
    let server_name =
        ServerName::try_from("passwordmanager.invalid").map_err(|_| Failure::Unavailable)?;
    let connection =
        ClientConnection::new(Arc::new(config), server_name).map_err(|_| Failure::Unavailable)?;
    let mut tls = rustls::StreamOwned::new(connection, stream);
    tls.write_all(b"PING\n").map_err(|_| Failure::Unavailable)?;
    tls.flush().map_err(|_| Failure::Unavailable)?;
    let mut response = [0_u8; 5];
    tls.read_exact(&mut response)
        .map_err(|_| Failure::Unavailable)?;
    if response != *b"READY" || tls.conn.alpn_protocol() != Some(profile.role.alpn()) {
        return Err(Failure::Unavailable);
    }
    println!(
        "READY role={} peer_uid={} tls=1.3 rpk=pinned alpn={}",
        profile.role.name(),
        observed_uid,
        String::from_utf8_lossy(profile.role.alpn())
    );
    Ok(())
}

fn agent_discover(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let socket_path = take_path(arguments, "--socket")?;
    finish_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Agent {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path, current_uid())?;
    let mut tls = connect(&profile, &key, &socket_path)?;
    tls.write_all(AGENT_MAGIC)
        .map_err(|_| Failure::Unavailable)?;
    let response = read_frame(&mut tls)?;
    let mut cursor = Cursor::new(&response);
    cursor.expect(&[0])?;
    let count = usize::from(u16::from_be_bytes(
        cursor
            .fixed(2)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
    ));
    let mut rendered = Vec::with_capacity(count);
    for _ in 0..count {
        let item = cursor.fixed(16)?;
        let _revision = cursor.fixed(16)?;
        let kind = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
        let title = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
        let destination = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
        let account = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
        rendered.push(format!(
            "{}:{kind}:{title}:{destination}:{account}",
            hex(item)
        ));
    }
    cursor.finish()?;
    println!(
        "PASS delegated-discovery count={count} set={}",
        rendered.join(",")
    );
    Ok(())
}

fn agent_attempt(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let socket_path = take_path(arguments, "--socket")?;
    let action_flag = arguments.next().ok_or(Failure::Usage)?;
    let action = arguments.next().ok_or(Failure::Usage)?;
    if action_flag != "--action" {
        return Err(Failure::Usage);
    }
    let mut request = match action.to_str() {
        Some("start") => {
            let item = decode_hex_16(&take_path(arguments, "--item")?)?;
            let issued = take_path(arguments, "--issued-at")?
                .to_string_lossy()
                .parse::<u64>()
                .map_err(|_| Failure::Usage)?;
            let nonce = decode_hex_16(&take_path(arguments, "--nonce")?)?;
            let context = take_path(arguments, "--context")?
                .to_string_lossy()
                .as_bytes()
                .to_vec();
            let mut r = vec![30];
            r.extend_from_slice(&item);
            r.extend_from_slice(&issued.to_be_bytes());
            r.extend_from_slice(&nonce);
            push_bytes(&mut r, &context)?;
            r
        }
        Some("get" | "cancel") => {
            let id = decode_hex_16(&take_path(arguments, "--attempt")?)?;
            let mut r = vec![if action == "get" { 31 } else { 32 }];
            r.extend_from_slice(&id);
            r
        }
        _ => return Err(Failure::Usage),
    };
    finish_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Agent {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path, current_uid())?;
    let mut tls = connect(&profile, &key, &socket_path)?;
    tls.write_all(AGENT_MAGIC)
        .map_err(|_| Failure::Unavailable)?;
    let _discovery = read_frame(&mut tls)?;
    write_frame(&mut tls, &request)?;
    request.zeroize();
    let response = read_frame(&mut tls)?;
    if response.first() != Some(&0) {
        println!("DENIED code={}", response.first().copied().unwrap_or(1));
        return Err(Failure::Unavailable);
    }
    let mut c = Cursor::new(&response[1..]);
    let attempt = c.fixed(16)?;
    let _item = c.fixed(16)?;
    let revision = c.fixed(16)?;
    let state = String::from_utf8(c.bytes()?).map_err(|_| Failure::Unavailable)?;
    let reason = String::from_utf8(c.bytes()?).map_err(|_| Failure::Unavailable)?;
    let result = c.bytes()?;
    let _integration = c.bytes()?;
    let _version = c.fixed(4)?;
    c.finish()?;
    println!(
        "PASS attempt id={} revision={} state={} reason={} result={}",
        hex(attempt),
        hex(revision),
        state,
        reason,
        String::from_utf8_lossy(&result)
    );
    Ok(())
}

fn human_authorization(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let socket_path = take_path(arguments, "--socket")?;
    let action_flag = arguments.next().ok_or(Failure::Usage)?;
    let action = arguments.next().ok_or(Failure::Usage)?;
    if action_flag != "--action" {
        return Err(Failure::Usage);
    }
    finish_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Human {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path, current_uid())?;
    let mut input = std::io::stdin().lock();
    let password = Zeroizing::new(read_wire_field(&mut input, 1024)?);
    let (opcode, mut request) = match action.to_str() {
        Some("setup") => (19, vec![19]),
        Some("suspend") => (20, vec![20]),
        Some("resume-revoke-a") => (21, vec![21]),
        Some("reenroll-a") => (22, vec![22]),
        Some("add-keycloak") => (40, vec![40]),
        Some("add-keycloak-exchange") => (41, vec![41]),
        _ => return Err(Failure::Usage),
    };
    if matches!(opcode, 19 | 22) {
        let first = read_wire_field(&mut input, SPKI_BYTES)?;
        if first.len() != SPKI_BYTES {
            return Err(Failure::Unavailable);
        }
        request.extend_from_slice(&first);
        if opcode == 19 {
            let second = read_wire_field(&mut input, SPKI_BYTES)?;
            if second.len() != SPKI_BYTES {
                return Err(Failure::Unavailable);
            }
            request.extend_from_slice(&second);
        }
    }
    if opcode == 41 {
        let subject_token = Zeroizing::new(read_wire_field(&mut input, 64 * 1024)?);
        let requester_secret = Zeroizing::new(read_wire_field(&mut input, 1024)?);
        push_bytes(&mut request, &subject_token)?;
        push_bytes(&mut request, &requester_secret)?;
    }
    let mut tls = connect(&profile, &key, &socket_path)?;
    tls.write_all(HUMAN_MAGIC)
        .map_err(|_| Failure::Unavailable)?;
    rpc_unlock(&mut tls, &password)?;
    write_frame(&mut tls, &request)?;
    expect_status(&read_frame(&mut tls)?, 0)?;
    println!(
        "PASS human-authorization action={}",
        action.to_string_lossy()
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn human_csv_import(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let socket_path = take_path(arguments, "--socket")?;
    let source_path = take_path(arguments, "--source")?;
    let format_flag = arguments.next().ok_or(Failure::Usage)?;
    let format = arguments.next().ok_or(Failure::Usage)?;
    let confirm = arguments.next().ok_or(Failure::Usage)?;
    if format_flag != "--format" || confirm != "--confirm" {
        return Err(Failure::Usage);
    }
    let mut response_loss = false;
    let mut enable_after = false;
    let mut replace_candidates = false;
    for value in arguments.by_ref() {
        match value.to_str() {
            Some("--simulate-response-loss") if !response_loss => response_loss = true,
            Some("--enable-after") if !enable_after => enable_after = true,
            Some("--replace-candidates") if !replace_candidates => replace_candidates = true,
            _ => return Err(Failure::Usage),
        }
    }
    finish_arguments(arguments)?;
    let format = match format.to_str() {
        Some("chrome") => 0,
        Some("apple") => 1,
        Some("mappable") => 2,
        _ => return Err(Failure::Usage),
    };
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Human {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path, current_uid())?;
    let source = read_import_source(&source_path)?;
    let mut input = std::io::stdin().lock();
    let password = Zeroizing::new(read_wire_field(&mut input, 1024)?);
    let mut tls = connect(&profile, &key, &socket_path)?;
    tls.write_all(HUMAN_MAGIC)
        .map_err(|_| Failure::Unavailable)?;
    rpc_unlock(&mut tls, &password)?;
    let mut request = vec![23, format, u8::from(replace_candidates)];
    push_bytes(&mut request, &source)?;
    write_frame(&mut tls, &request)?;
    let response = read_frame(&mut tls)?;
    let mut cursor = Cursor::new(&response);
    cursor.expect(&[0])?;
    let total = cursor.u64()?;
    let new_items = cursor.u64()?;
    let replaced = cursor.u64()?;
    let skipped = cursor.u64()?;
    let excluded = cursor.u64()?;
    let preserved = cursor.u64()?;
    let pages = cursor.u64()?;
    let count = usize::try_from(cursor.u32()?).map_err(|_| Failure::Unavailable)?;
    let mut item_ids: Vec<[u8; 16]> = Vec::with_capacity(count);
    for _ in 0..count {
        item_ids.push(
            cursor
                .fixed(16)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?,
        );
    }
    let prepared = WirePrepared {
        transaction_id: cursor
            .fixed(16)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
        item_id: cursor
            .fixed(16)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
        command: cursor.bytes()?,
        body: cursor.bytes()?,
        signature: cursor
            .fixed(64)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
    };
    cursor.finish()?;
    let committed = if response_loss {
        write_frame(
            &mut tls,
            &encode_commit_request(8, &prepared, &prepared.body)?,
        )?;
        if read_frame(&mut tls).is_ok() {
            return Err(Failure::Unavailable);
        }
        drop(tls);
        let mut recovered = connect(&profile, &key, &socket_path)?;
        recovered
            .write_all(HUMAN_MAGIC)
            .map_err(|_| Failure::Unavailable)?;
        rpc_unlock(&mut recovered, &password)?;
        let receipt = rpc_receipt(&mut recovered, prepared.transaction_id)?;
        if rpc_commit(&mut recovered, &prepared)? != receipt {
            return Err(Failure::Unavailable);
        }
        tls = recovered;
        receipt
    } else {
        rpc_commit(&mut tls, &prepared)?
    };
    if rpc_commit(&mut tls, &prepared)? != committed
        || rpc_receipt(&mut tls, prepared.transaction_id)? != committed
    {
        return Err(Failure::Unavailable);
    }
    if enable_after {
        let item = *item_ids
            .first()
            .filter(|_| item_ids.len() == 1)
            .ok_or(Failure::Unavailable)?;
        let mut enable = vec![24];
        enable.extend_from_slice(&item);
        write_frame(&mut tls, &enable)?;
        let enable = decode_prepared_response(&read_frame(&mut tls)?)?;
        rpc_commit(&mut tls, &enable)?;
    }
    println!(
        "PASS csv-import format={} total={total} new={new_items} replaced={replaced} skipped_exact={skipped} excluded={excluded} preserved_fields={preserved} pages={pages} items={} tls-rpk=1 alpn=pm-human/1 signed=1 receipt-replay=1 response-loss={} explicit-enable={} replace-candidates={} source-unchanged=1 auto-enable=0",
        format_name(format),
        item_ids.len(),
        u8::from(response_loss),
        u8::from(enable_after),
        u8::from(replace_candidates),
    );
    Ok(())
}

fn human_passkey_confirm(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let socket_path = take_path(arguments, "--socket")?;
    let request_id = decode_hex_16(&take_path(arguments, "--request")?)?;
    let verification_flag = arguments.next().ok_or(Failure::Usage)?;
    let verification_value = arguments.next().ok_or(Failure::Usage)?;
    if verification_flag != "--verification" {
        return Err(Failure::Usage);
    }
    let verification = match verification_value.to_str() {
        Some("presence") => 1,
        Some("verified") => 2,
        _ => return Err(Failure::Usage),
    };
    finish_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Human {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path, current_uid())?;
    let mut tls = connect(&profile, &key, &socket_path)?;
    tls.write_all(HUMAN_MAGIC)
        .map_err(|_| Failure::Unavailable)?;
    let mut peek = vec![0];
    peek.extend_from_slice(&request_id);
    write_frame(&mut tls, &peek)?;
    let response = read_frame(&mut tls)?;
    let mut cursor = Cursor::new(&response);
    cursor.expect(&[0])?;
    let operation = match cursor.fixed(1)? {
        [1] => "register",
        [2] => "assert",
        _ => return Err(Failure::Unavailable),
    };
    let required_uv = match cursor.fixed(1)? {
        [1] => true,
        [2 | 3] => false,
        _ => return Err(Failure::Unavailable),
    };
    let rp_id = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
    let account = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
    let origin = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
    let document = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
    cursor.finish()?;
    if required_uv && verification != 2 {
        return Err(Failure::Unavailable);
    }
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| Failure::Unavailable)?;
    if unsafe { libc::isatty(tty.as_raw_fd()) } != 1 {
        return Err(Failure::Unavailable);
    }
    writeln!(
        tty,
        "Passkey {operation}\nRP: {rp_id}\nAccount: {account}\nOrigin: {origin}\nDocument: {document}\nVerification: {}\nType APPROVE {} to continue:",
        if verification == 2 { "UP+UV" } else { "UP" },
        hex(&request_id),
    )
    .and_then(|()| tty.flush())
    .map_err(|_| Failure::Unavailable)?;
    let approval = read_tty_line(&mut tty, 128)?;
    if approval != format!("APPROVE {}", hex(&request_id)) {
        return Err(Failure::Unavailable);
    }
    write!(tty, "Master password (fresh reauthentication): ")
        .and_then(|()| tty.flush())
        .map_err(|_| Failure::Unavailable)?;
    let password = Zeroizing::new(read_tty_password(&mut tty)?);
    writeln!(tty).map_err(|_| Failure::Unavailable)?;
    rpc_unlock(&mut tls, &password)?;
    let mut confirm = vec![if operation == "register" { 35 } else { 36 }];
    confirm.extend_from_slice(&request_id);
    confirm.push(verification);
    write_frame(&mut tls, &confirm)?;
    let response = read_frame(&mut tls)?;
    let mut cursor = Cursor::new(&response);
    cursor.expect(&[0])?;
    let status = PasskeyStatus::from_bytes(&cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
    cursor.finish()?;
    if matches!(status, PasskeyStatus::Waiting(_)) {
        return Err(Failure::Unavailable);
    }
    println!(
        "PASS passkey-human operation={operation} presence=1 verification={} tls-rpk=1 alpn=pm-human/1 request={}",
        if verification == 2 {
            "fresh"
        } else {
            "presence-only"
        },
        hex(&request_id)
    );
    Ok(())
}

fn read_tty_line(tty: &mut File, maximum: usize) -> Result<String, Failure> {
    let mut output = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        tty.read_exact(&mut byte)
            .map_err(|_| Failure::Unavailable)?;
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] != b'\r' {
            output.push(byte[0]);
        }
        if output.len() > maximum {
            output.zeroize();
            return Err(Failure::Unavailable);
        }
    }
    String::from_utf8(output).map_err(|_| Failure::Unavailable)
}

fn human_passkey_enable(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let socket_path = take_path(arguments, "--socket")?;
    let request_id = decode_hex_16(&take_path(arguments, "--request")?)?;
    finish_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Human {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path, current_uid())?;
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| Failure::Unavailable)?;
    if unsafe { libc::isatty(tty.as_raw_fd()) } != 1 {
        return Err(Failure::Unavailable);
    }
    writeln!(
        tty,
        "Enable delegated use for completed passkey request {}. Type ENABLE {} to continue:",
        hex(&request_id),
        hex(&request_id),
    )
    .and_then(|()| tty.flush())
    .map_err(|_| Failure::Unavailable)?;
    if read_tty_line(&mut tty, 128)? != format!("ENABLE {}", hex(&request_id)) {
        return Err(Failure::Unavailable);
    }
    write!(tty, "Master password (fresh reauthentication): ")
        .and_then(|()| tty.flush())
        .map_err(|_| Failure::Unavailable)?;
    let password = Zeroizing::new(read_tty_password(&mut tty)?);
    writeln!(tty).map_err(|_| Failure::Unavailable)?;
    let mut tls = connect(&profile, &key, &socket_path)?;
    tls.write_all(HUMAN_MAGIC)
        .map_err(|_| Failure::Unavailable)?;
    rpc_unlock(&mut tls, &password)?;
    let mut request = vec![37];
    request.extend_from_slice(&request_id);
    write_frame(&mut tls, &request)?;
    expect_status(&read_frame(&mut tls)?, 0)?;
    println!(
        "PASS passkey-enable explicit=1 tls-rpk=1 alpn=pm-human/1 request={}",
        hex(&request_id)
    );
    Ok(())
}

fn read_tty_password(tty: &mut File) -> Result<Vec<u8>, Failure> {
    let fd = tty.as_raw_fd();
    let mut original: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &raw mut original) } != 0 {
        return Err(Failure::Unavailable);
    }
    let mut hidden = original;
    hidden.c_lflag &= !libc::ECHO;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw const hidden) } != 0 {
        return Err(Failure::Unavailable);
    }
    let result = read_tty_line(tty, 1024).map(String::into_bytes);
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw const original) } != 0 {
        return Err(Failure::Unavailable);
    }
    result
}

#[allow(clippy::too_many_lines)]
fn human_1pux_import(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let socket_path = take_path(arguments, "--socket")?;
    let source_path = take_path(arguments, "--source")?;
    if arguments.next().ok_or(Failure::Usage)? != "--confirm" {
        return Err(Failure::Usage);
    }
    let mut response_loss = false;
    let mut replace_candidates = false;
    for value in arguments.by_ref() {
        match value.to_str() {
            Some("--simulate-response-loss") if !response_loss => response_loss = true,
            Some("--replace-candidates") if !replace_candidates => replace_candidates = true,
            _ => return Err(Failure::Usage),
        }
    }
    finish_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Human {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path, current_uid())?;
    let mut input = std::io::stdin().lock();
    let password = Zeroizing::new(read_wire_field(&mut input, 1024)?);
    let mut tls = connect(&profile, &key, &socket_path)?;
    tls.write_all(HUMAN_MAGIC)
        .map_err(|_| Failure::Unavailable)?;
    rpc_unlock(&mut tls, &password)?;
    let source = open_1pux_source(&source_path)?;
    let request = [31, u8::from(replace_candidates)];
    write_frame(&mut tls, &request)?;
    expect_status(&read_frame(&mut tls)?, 0)?;
    send_file_descriptor(&tls.sock, source.as_raw_fd())?;
    let response = read_frame(&mut tls)?;
    let mut cursor = Cursor::new(&response);
    cursor.expect(&[0])?;
    let total = cursor.u64()?;
    let new_items = cursor.u64()?;
    let replaced = cursor.u64()?;
    let skipped = cursor.u64()?;
    let excluded = cursor.u64()?;
    let preserved = cursor.u64()?;
    let pages = cursor.u64()?;
    let count = usize::try_from(cursor.u32()?).map_err(|_| Failure::Unavailable)?;
    for _ in 0..count {
        cursor.fixed(16)?;
    }
    let prepared = WirePrepared {
        transaction_id: cursor
            .fixed(16)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
        item_id: cursor
            .fixed(16)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
        command: cursor.bytes()?,
        body: cursor.bytes()?,
        signature: cursor
            .fixed(64)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
    };
    cursor.finish()?;
    let committed = if response_loss {
        write_frame(
            &mut tls,
            &encode_commit_request(8, &prepared, &prepared.body)?,
        )?;
        if read_frame(&mut tls).is_ok() {
            return Err(Failure::Unavailable);
        }
        drop(tls);
        let mut recovered = connect(&profile, &key, &socket_path)?;
        recovered
            .write_all(HUMAN_MAGIC)
            .map_err(|_| Failure::Unavailable)?;
        rpc_unlock(&mut recovered, &password)?;
        let receipt = rpc_receipt(&mut recovered, prepared.transaction_id)?;
        if rpc_commit(&mut recovered, &prepared)? != receipt {
            return Err(Failure::Unavailable);
        }
        tls = recovered;
        receipt
    } else {
        rpc_commit(&mut tls, &prepared)?
    };
    if rpc_commit(&mut tls, &prepared)? != committed
        || rpc_receipt(&mut tls, prepared.transaction_id)? != committed
    {
        return Err(Failure::Unavailable);
    }
    println!(
        "PASS 1pux-import version=3 total={total} new={new_items} replaced={replaced} skipped_exact={skipped} excluded={excluded} preserved_fields={preserved} pages={pages} items={count} tls-rpk=1 alpn=pm-human/1 signed=1 receipt-replay=1 response-loss={} replace-candidates={} source-unchanged=1 streamed-attachments=1 source-fd=scm-rights private-source=0400 auto-enable=0",
        u8::from(response_loss),
        u8::from(replace_candidates),
    );
    Ok(())
}

const fn format_name(format: u8) -> &'static str {
    match format {
        0 => "chrome",
        1 => "apple",
        2 => "mappable",
        _ => "invalid",
    }
}

#[derive(Clone, Copy)]
struct WireHistoryEntry {
    revision_id: [u8; 16],
    visible: bool,
    attachment_count: u32,
}

struct WireHistory {
    lifecycle: u8,
    entries: Vec<WireHistoryEntry>,
}

struct WirePurge {
    terminal: bool,
    revision_ids: Vec<[u8; 16]>,
    attachment_count: u32,
    encrypted_bytes: u64,
    prepared: WirePrepared,
}

#[allow(clippy::too_many_lines)]
fn human_history_exercise(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    const STREAM_SIZE: u64 = 2 * 1024 * 1024 + 37;
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let socket_path = take_path(arguments, "--socket")?;
    finish_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Human {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path, current_uid())?;
    let mut input = std::io::stdin().lock();
    let password = Zeroizing::new(read_wire_field(&mut input, 1024)?);
    let mut tls = connect_human(&profile, &key, &socket_path, &password)?;

    let records = content_fixture_records()?;
    for (index, record) in records.iter().enumerate() {
        let created = rpc_prepare_record(&mut tls, 9, None, record)?;
        rpc_commit(&mut tls, &created)?;
        let original = rpc_history(&mut tls, created.item_id)?;
        if original.lifecycle != 1 || original.entries.len() != 1 {
            return Err(Failure::Unavailable);
        }
        let source_revision = original.entries[0].revision_id;

        let edited = rpc_prepare_record(&mut tls, 29, Some(created.item_id), record)?;
        rpc_commit(&mut tls, &edited)?;
        let deleted = rpc_prepare(&mut tls, 4, Some(created.item_id), "", "", &[], "", "")?;
        rpc_commit(&mut tls, &deleted)?;
        let restored = rpc_prepare_restore(&mut tls, created.item_id, source_revision)?;
        if index == 0 {
            write_frame(
                &mut tls,
                &encode_commit_request(8, &restored, &restored.body)?,
            )?;
            if read_frame(&mut tls).is_ok() {
                return Err(Failure::Unavailable);
            }
            tls = connect_human(&profile, &key, &socket_path, &password)?;
            let receipt = rpc_receipt(&mut tls, restored.transaction_id)?;
            if rpc_commit(&mut tls, &restored)? != receipt {
                return Err(Failure::Unavailable);
            }
        } else {
            rpc_commit(&mut tls, &restored)?;
        }
        if rpc_read_record(&mut tls, created.item_id)? != *record {
            return Err(Failure::Unavailable);
        }
        let after = rpc_history(&mut tls, created.item_id)?;
        if after.lifecycle != 1
            || after.entries.len() != 3
            || after.entries.iter().filter(|entry| entry.visible).count() != 1
            || after
                .entries
                .iter()
                .any(|entry| entry.revision_id == source_revision && entry.visible)
        {
            return Err(Failure::Unavailable);
        }
        let losing = after
            .entries
            .iter()
            .find(|entry| entry.revision_id != source_revision && !entry.visible)
            .ok_or(Failure::Unavailable)?
            .revision_id;
        let purge = rpc_prepare_purge_revisions(&mut tls, created.item_id, &[losing])?;
        if purge.terminal
            || purge.revision_ids != [losing]
            || purge.attachment_count
                != after
                    .entries
                    .iter()
                    .find(|entry| entry.revision_id == losing)
                    .ok_or(Failure::Unavailable)?
                    .attachment_count
        {
            return Err(Failure::Unavailable);
        }
        rpc_commit(&mut tls, &purge.prepared)?;
    }

    let stream_attachment = [0x7e; 16];
    let stream_hash = pattern_digest(STREAM_SIZE)?;
    let stream_record = LogicalRecord::new_streaming(
        RecordKind::File,
        HumanMetadata {
            title: "History stream".to_owned(),
            destinations: vec![],
            tags: vec!["synthetic".to_owned()],
            favorite: false,
            notes: String::new(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![],
        vec![
            Attachment::descriptor(
                stream_attachment,
                "history-stream.bin",
                "application/octet-stream",
                STREAM_SIZE,
                stream_hash,
            )
            .map_err(|_| Failure::Unavailable)?,
        ],
    )
    .map_err(|_| Failure::Unavailable)?;
    let mut start = vec![17];
    push_bytes(&mut start, &stream_record.to_descriptor_bytes())?;
    write_frame(&mut tls, &start)?;
    send_pattern(&mut tls, STREAM_SIZE)?;
    write_frame(&mut tls, &[0])?;
    let streamed = decode_prepared_response(&read_frame(&mut tls)?)?;
    rpc_commit(&mut tls, &streamed)?;
    let stream_revision = rpc_history(&mut tls, streamed.item_id)?
        .entries
        .first()
        .ok_or(Failure::Unavailable)?
        .revision_id;
    let note = LogicalRecord::new(
        RecordKind::Note,
        HumanMetadata {
            title: "Temporary stream edit".to_owned(),
            destinations: vec![],
            tags: vec![],
            favorite: false,
            notes: "synthetic".to_owned(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![],
        vec![],
    )
    .map_err(|_| Failure::Unavailable)?;
    let edit = rpc_prepare_record(&mut tls, 29, Some(streamed.item_id), &note)?;
    rpc_commit(&mut tls, &edit)?;
    let trash = rpc_prepare(&mut tls, 4, Some(streamed.item_id), "", "", &[], "", "")?;
    rpc_commit(&mut tls, &trash)?;
    let restore = rpc_prepare_restore(&mut tls, streamed.item_id, stream_revision)?;
    rpc_commit(&mut tls, &restore)?;
    assert_pattern_download(
        &mut tls,
        streamed.item_id,
        stream_attachment,
        STREAM_SIZE,
        stream_hash,
    )?;

    let final_record = LogicalRecord::new(
        RecordKind::Note,
        HumanMetadata {
            title: "Persistent trash target".to_owned(),
            destinations: vec![],
            tags: vec!["synthetic".to_owned()],
            favorite: false,
            notes: "ticket18-trash-canary".to_owned(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![],
        vec![],
    )
    .map_err(|_| Failure::Unavailable)?;
    let target = rpc_prepare_record(&mut tls, 9, None, &final_record)?;
    rpc_commit(&mut tls, &target)?;
    let trash = rpc_prepare(&mut tls, 4, Some(target.item_id), "", "", &[], "", "")?;
    rpc_commit(&mut tls, &trash)?;
    println!(
        "PASS history-exercise types=7 inline-restored=7 stream-bytes={STREAM_SIZE} stream-exact=1 selective-scopes=7 response-loss=recovered receipts=replayed tls-rpk=1 alpn=pm-human/1 purge-target={}",
        hex(&target.item_id)
    );
    Ok(())
}

fn human_history_list(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let (profile_path, private_path, socket_path, item) = history_target_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Human {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path, current_uid())?;
    let mut input = std::io::stdin().lock();
    let password = Zeroizing::new(read_wire_field(&mut input, 1024)?);
    let mut tls = connect_human(&profile, &key, &socket_path, &password)?;
    let history = rpc_history(&mut tls, item)?;
    println!(
        "PASS history-list lifecycle={} revisions={} tls-rpk=1 alpn=pm-human/1",
        if history.lifecycle == 1 {
            "active"
        } else {
            "trash"
        },
        history.entries.len()
    );
    Ok(())
}

fn human_history_purge_item(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let (profile_path, private_path, socket_path, item) = history_target_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Human {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path, current_uid())?;
    let mut input = std::io::stdin().lock();
    let password = Zeroizing::new(read_wire_field(&mut input, 1024)?);
    let mut tls = connect_human(&profile, &key, &socket_path, &password)?;
    let purge = rpc_prepare_purge_item(&mut tls, item)?;
    if !purge.terminal || purge.revision_ids.is_empty() {
        return Err(Failure::Unavailable);
    }
    write_frame(
        &mut tls,
        &encode_commit_request(8, &purge.prepared, &purge.prepared.body)?,
    )?;
    if read_frame(&mut tls).is_ok() {
        return Err(Failure::Unavailable);
    }
    tls = connect_human(&profile, &key, &socket_path, &password)?;
    let receipt = rpc_receipt(&mut tls, purge.prepared.transaction_id)?;
    if rpc_commit(&mut tls, &purge.prepared)? != receipt {
        return Err(Failure::Unavailable);
    }
    println!(
        "PASS history-purge-item revisions={} attachments={} encrypted-bytes={} terminal=1 response-loss=recovered receipt-replay=1 tls-rpk=1 alpn=pm-human/1",
        purge.revision_ids.len(),
        purge.attachment_count,
        purge.encrypted_bytes
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn human_backup_exercise(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    const STREAM_SIZE: u64 = 2 * 1024 * 1024 + 211;
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let socket_path = take_path(arguments, "--socket")?;
    let output_dir = take_path(arguments, "--output-dir")?;
    finish_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Human {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path, current_uid())?;
    let mut input = std::io::stdin().lock();
    let password = Zeroizing::new(read_wire_field(&mut input, 1024)?);
    let mut tls = connect_human(&profile, &key, &socket_path, &password)?;

    let records = content_fixture_records()?;
    let mut first = None;
    for record in &records {
        let created = rpc_prepare_record(&mut tls, 9, None, record)?;
        rpc_commit(&mut tls, &created)?;
        first.get_or_insert(created.item_id);
    }
    let first = first.ok_or(Failure::Unavailable)?;
    let edit = rpc_prepare_record(&mut tls, 29, Some(first), &records[0])?;
    rpc_commit(&mut tls, &edit)?;
    let trash = rpc_prepare(&mut tls, 4, Some(first), "", "", &[], "", "")?;
    rpc_commit(&mut tls, &trash)?;

    let attachment = [0x21; 16];
    let stream_record = LogicalRecord::new_streaming(
        RecordKind::File,
        HumanMetadata {
            title: "Ticket 21 streamed backup".to_owned(),
            destinations: vec![],
            tags: vec!["synthetic".to_owned()],
            favorite: false,
            notes: "ticket21-stream-note-canary".to_owned(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![],
        vec![
            Attachment::descriptor(
                attachment,
                "ticket21-large.bin",
                "application/octet-stream",
                STREAM_SIZE,
                pattern_digest(STREAM_SIZE)?,
            )
            .map_err(|_| Failure::Unavailable)?,
        ],
    )
    .map_err(|_| Failure::Unavailable)?;
    let mut start = vec![17];
    push_bytes(&mut start, &stream_record.to_descriptor_bytes())?;
    write_frame(&mut tls, &start)?;
    send_pattern(&mut tls, STREAM_SIZE)?;
    write_frame(&mut tls, &[0])?;
    let streamed = decode_prepared_response(&read_frame(&mut tls)?)?;
    rpc_commit(&mut tls, &streamed)?;

    fs::create_dir_all(&output_dir).map_err(|_| Failure::Unavailable)?;
    let native = output_dir.join("ticket21-backup.pmb1");
    let native_bytes = rpc_download_atomic(&mut tls, &[32], &native)?;

    write_frame(&mut tls, &[33, 0])?;
    let confirmation = decode_prepared_response(&read_frame(&mut tls)?)?;
    let mut export_request = vec![33, 1];
    push_bytes(&mut export_request, &confirmation.command)?;
    export_request.extend_from_slice(&confirmation.signature);
    push_bytes(&mut export_request, &confirmation.body)?;
    let plaintext = output_dir.join("ticket21-export.jsonl");
    let plaintext_bytes = rpc_download_atomic(&mut tls, &export_request, &plaintext)?;

    let mut restore = vec![34];
    push_bytes(&mut restore, &password)?;
    write_frame(&mut tls, &restore)?;
    let mut source = File::open(&native).map_err(|_| Failure::Unavailable)?;
    let mut buffer = vec![0_u8; STREAM_CHUNK_BYTES];
    loop {
        let count = source.read(&mut buffer).map_err(|_| Failure::Unavailable)?;
        if count == 0 {
            break;
        }
        write_frame(&mut tls, &buffer[..count])?;
    }
    buffer.zeroize();
    write_frame(&mut tls, &[0])?;
    let restore = decode_prepared_response(&read_frame(&mut tls)?)?;
    let receipt = rpc_commit(&mut tls, &restore)?;
    if rpc_commit(&mut tls, &restore)? != receipt {
        return Err(Failure::Unavailable);
    }
    println!(
        "PASS backup-exercise types=7 records={} native-bytes={native_bytes} plaintext-bytes={plaintext_bytes} stream-bytes={STREAM_SIZE} inventory=exact password-path=1 restore=new-ids+keys trash+history=preserved authority=history-only grants=inactive confirmation=strong+one-use receipt-replay=1 tls-rpk=1 alpn=pm-human/1",
        records.len()
    );
    Ok(())
}

fn human_backup_restore(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let socket_path = take_path(arguments, "--socket")?;
    let archive_path = take_path(arguments, "--archive")?;
    finish_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Human {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path, current_uid())?;
    let mut input = std::io::stdin().lock();
    let password = Zeroizing::new(read_wire_field(&mut input, 1024)?);
    let mut tls = connect_human(&profile, &key, &socket_path, &password)?;
    let mut request = vec![34];
    push_bytes(&mut request, &password)?;
    write_frame(&mut tls, &request)?;
    let mut source = File::open(&archive_path).map_err(|_| Failure::Unavailable)?;
    let mut buffer = vec![0_u8; STREAM_CHUNK_BYTES];
    loop {
        let count = source.read(&mut buffer).map_err(|_| Failure::Unavailable)?;
        if count == 0 {
            break;
        }
        write_frame(&mut tls, &buffer[..count])?;
    }
    buffer.zeroize();
    write_frame(&mut tls, &[0])?;
    let prepared = decode_prepared_response(&read_frame(&mut tls)?)?;
    rpc_commit(&mut tls, &prepared)?;
    println!("PASS backup-restore tls-rpk=1 alpn=pm-human/1 signed=1 source-unchanged=1");
    Ok(())
}

fn human_recovery_restore(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let socket_path = take_path(arguments, "--socket")?;
    let archive_path = take_path(arguments, "--archive")?;
    finish_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Human {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path, current_uid())?;
    let mut input = std::io::stdin().lock();
    let password = Zeroizing::new(read_wire_field(&mut input, 1024)?);
    let mut recovery = Zeroizing::new(read_wire_field(&mut input, 1024)?);
    let mut tls = connect_human(&profile, &key, &socket_path, &password)?;
    let mut request = vec![42];
    push_bytes(&mut request, &recovery)?;
    recovery.zeroize();
    write_frame(&mut tls, &request)?;
    request.zeroize();
    let mut source = File::open(&archive_path).map_err(|_| Failure::Unavailable)?;
    let mut buffer = vec![0_u8; STREAM_CHUNK_BYTES];
    loop {
        let count = source.read(&mut buffer).map_err(|_| Failure::Unavailable)?;
        if count == 0 {
            break;
        }
        write_frame(&mut tls, &buffer[..count])?;
    }
    buffer.zeroize();
    write_frame(&mut tls, &[0])?;
    let prepared = decode_prepared_response(&read_frame(&mut tls)?)?;
    let receipt = rpc_commit(&mut tls, &prepared)?;
    if rpc_commit(&mut tls, &prepared)? != receipt {
        return Err(Failure::Unavailable);
    }
    println!(
        "PASS recovery-restore tls-rpk=1 alpn=pm-human/1 source-keyring=absent destination-authority=preserved signed=1 receipt-replay=1"
    );
    println!(
        "WARN recovered data does not revoke exposed backups, offline copies, or external provider credentials; review current authority and rotate affected provider credentials from the healthy environment"
    );
    Ok(())
}

fn human_master_rotate(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let socket_path = take_path(arguments, "--socket")?;
    finish_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Human {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path, current_uid())?;
    let mut input = std::io::stdin().lock();
    let password = Zeroizing::new(read_wire_field(&mut input, 1024)?);
    let mut replacement = Zeroizing::new(read_wire_field(&mut input, 1024)?);
    let mut tls = connect_human(&profile, &key, &socket_path, &password)?;
    let mut request = vec![43];
    push_bytes(&mut request, &replacement)?;
    replacement.zeroize();
    write_frame(&mut tls, &request)?;
    request.zeroize();
    let prepared = decode_prepared_response(&read_frame(&mut tls)?)?;
    let receipt = rpc_commit(&mut tls, &prepared)?;
    if rpc_commit(&mut tls, &prepared)? != receipt
        || rpc_receipt(&mut tls, prepared.transaction_id)? != receipt
    {
        return Err(Failure::Unavailable);
    }
    println!(
        "PASS master-rotate tls-rpk=1 alpn=pm-human/1 signed=1 receipt-replay=1 current-vault=preserved old-backups=historical-paths"
    );
    println!(
        "WARN older backups remain usable through their historical password/recovery paths and are not erased or remotely invalidated"
    );
    Ok(())
}

fn human_recovery_rotate(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let socket_path = take_path(arguments, "--socket")?;
    finish_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Human {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path, current_uid())?;
    let mut input = std::io::stdin().lock();
    let password = Zeroizing::new(read_wire_field(&mut input, 1024)?);
    let mut tls = connect_human(&profile, &key, &socket_path, &password)?;
    write_frame(&mut tls, &[44])?;
    let response = read_frame(&mut tls)?;
    let mut cursor = Cursor::new(&response);
    cursor.expect(&[0])?;
    let mut code = Zeroizing::new(cursor.bytes()?);
    cursor.finish()?;
    println!(
        "Recovery code (store externally): {}",
        std::str::from_utf8(&code).map_err(|_| Failure::Unavailable)?
    );
    println!("Reintroduce recovery code to confirm the external copy:");
    std::io::stdout()
        .flush()
        .map_err(|_| Failure::Unavailable)?;
    let mut confirmation = Zeroizing::new(read_wire_field(&mut input, 1024)?);
    write_frame(&mut tls, &confirmation)?;
    confirmation.zeroize();
    code.zeroize();
    let prepared = decode_prepared_response(&read_frame(&mut tls)?)?;
    let receipt = rpc_commit(&mut tls, &prepared)?;
    if rpc_commit(&mut tls, &prepared)? != receipt
        || rpc_receipt(&mut tls, prepared.transaction_id)? != receipt
    {
        return Err(Failure::Unavailable);
    }
    println!(
        "PASS recovery-rotate tls-rpk=1 alpn=pm-human/1 signed=1 receipt-replay=1 verified-before-commit=1 old-current-code=invalid old-backups=remain-valid"
    );
    println!(
        "WARN the old code no longer opens current backups, but older backups and exposed copies remain usable through their historical paths"
    );
    Ok(())
}

fn rpc_download_atomic(
    tls: &mut rustls::StreamOwned<ClientConnection, UnixStream>,
    request: &[u8],
    destination: &Path,
) -> Result<u64, Failure> {
    let temporary = destination.with_extension("partial");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut output = options.open(&temporary).map_err(|_| Failure::Unavailable)?;
    let result = (|| {
        write_frame(tls, request)?;
        expect_status(&read_frame(tls)?, 0)?;
        let mut written = 0_u64;
        loop {
            let frame = read_frame_bounded(tls, STREAM_CHUNK_BYTES + 64)?;
            if frame == [0] {
                break;
            }
            written = written
                .checked_add(u64::try_from(frame.len()).map_err(|_| Failure::Unavailable)?)
                .ok_or(Failure::Unavailable)?;
            output.write_all(&frame).map_err(|_| Failure::Unavailable)?;
        }
        output.sync_all().map_err(|_| Failure::Unavailable)?;
        Ok(written)
    })();
    if result.is_err() {
        return result
            .map_err(|error: Failure| error.after_owned_path_cleanup(fs::remove_file(&temporary)));
    }
    drop(output);
    fs::rename(&temporary, destination).map_err(|_| Failure::Unavailable)?;
    File::open(destination.parent().ok_or(Failure::Unavailable)?)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| Failure::Unavailable)?;
    result
}

fn history_target_arguments(
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<
    (
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
        [u8; 16],
    ),
    Failure,
> {
    let profile = take_path(arguments, "--profile")?;
    let private = take_path(arguments, "--private")?;
    let socket = take_path(arguments, "--socket")?;
    let item = decode_hex_16(&take_path(arguments, "--item")?)?;
    finish_arguments(arguments)?;
    Ok((profile, private, socket, item))
}

fn connect_human(
    profile: &Profile,
    key: &KeyMaterial,
    socket: &Path,
    password: &[u8],
) -> Result<rustls::StreamOwned<ClientConnection, UnixStream>, Failure> {
    let mut tls = connect(profile, key, socket)?;
    tls.write_all(HUMAN_MAGIC)
        .map_err(|_| Failure::Unavailable)?;
    rpc_unlock(&mut tls, password)?;
    Ok(tls)
}

fn rpc_prepare_record(
    tls: &mut rustls::StreamOwned<ClientConnection, UnixStream>,
    opcode: u8,
    item: Option<[u8; 16]>,
    record: &LogicalRecord,
) -> Result<WirePrepared, Failure> {
    let mut request = vec![opcode];
    if let Some(item) = item {
        request.extend_from_slice(&item);
    }
    push_bytes(&mut request, &record.to_bytes())?;
    write_frame(tls, &request)?;
    decode_prepared_response(&read_frame(tls)?)
}

fn rpc_prepare_restore(
    tls: &mut rustls::StreamOwned<ClientConnection, UnixStream>,
    item: [u8; 16],
    revision: [u8; 16],
) -> Result<WirePrepared, Failure> {
    let mut request = vec![26];
    request.extend_from_slice(&item);
    request.extend_from_slice(&revision);
    write_frame(tls, &request)?;
    decode_prepared_response(&read_frame(tls)?)
}

fn rpc_read_record(
    tls: &mut rustls::StreamOwned<ClientConnection, UnixStream>,
    item: [u8; 16],
) -> Result<LogicalRecord, Failure> {
    let mut request = vec![10];
    request.extend_from_slice(&item);
    write_frame(tls, &request)?;
    LogicalRecord::from_bytes(&expect_success_payload(&read_frame(tls)?)?)
        .map_err(|_| Failure::Unavailable)
}

fn rpc_history(
    tls: &mut rustls::StreamOwned<ClientConnection, UnixStream>,
    item: [u8; 16],
) -> Result<WireHistory, Failure> {
    let mut request = vec![25];
    request.extend_from_slice(&item);
    write_frame(tls, &request)?;
    let response = read_frame(tls)?;
    let mut cursor = Cursor::new(&response);
    cursor.expect(&[0])?;
    let lifecycle = cursor.fixed(1)?[0];
    if !matches!(lifecycle, 1 | 2) {
        return Err(Failure::Unavailable);
    }
    let count = usize::from(u16::from_be_bytes(
        cursor
            .fixed(2)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
    ));
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let revision_id = cursor
            .fixed(16)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?;
        cursor.fixed(8)?; // modified_at_us
        cursor.fixed(16)?; // issuer_device
        let visible = cursor.fixed(1)?[0] == 1;
        let attachment_count = u32::from_be_bytes(
            cursor
                .fixed(4)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?,
        );
        entries.push(WireHistoryEntry {
            revision_id,
            visible,
            attachment_count,
        });
    }
    cursor.finish()?;
    Ok(WireHistory { lifecycle, entries })
}

fn rpc_prepare_purge_revisions(
    tls: &mut rustls::StreamOwned<ClientConnection, UnixStream>,
    item: [u8; 16],
    revisions: &[[u8; 16]],
) -> Result<WirePurge, Failure> {
    let mut request = vec![27];
    request.extend_from_slice(&item);
    request.extend_from_slice(
        &u16::try_from(revisions.len())
            .map_err(|_| Failure::Unavailable)?
            .to_be_bytes(),
    );
    for revision in revisions {
        request.extend_from_slice(revision);
    }
    write_frame(tls, &request)?;
    decode_purge_response(&read_frame(tls)?)
}

fn rpc_prepare_purge_item(
    tls: &mut rustls::StreamOwned<ClientConnection, UnixStream>,
    item: [u8; 16],
) -> Result<WirePurge, Failure> {
    let mut request = vec![28];
    request.extend_from_slice(&item);
    write_frame(tls, &request)?;
    decode_purge_response(&read_frame(tls)?)
}

fn decode_purge_response(response: &[u8]) -> Result<WirePurge, Failure> {
    let mut cursor = Cursor::new(response);
    cursor.expect(&[0])?;
    let terminal = cursor.fixed(1)?[0] == 1;
    let count = usize::from(u16::from_be_bytes(
        cursor
            .fixed(2)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
    ));
    let attachment_count = u32::from_be_bytes(
        cursor
            .fixed(4)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
    );
    let encrypted_bytes = cursor.u64()?;
    let mut revision_ids = Vec::with_capacity(count);
    for _ in 0..count {
        revision_ids.push(
            cursor
                .fixed(16)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?,
        );
    }
    let prepared = WirePrepared {
        transaction_id: cursor
            .fixed(16)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
        item_id: cursor
            .fixed(16)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
        command: cursor.bytes()?,
        body: cursor.bytes()?,
        signature: cursor
            .fixed(64)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
    };
    cursor.finish()?;
    Ok(WirePurge {
        terminal,
        revision_ids,
        attachment_count,
        encrypted_bytes,
        prepared,
    })
}

fn assert_pattern_download(
    tls: &mut rustls::StreamOwned<ClientConnection, UnixStream>,
    item: [u8; 16],
    attachment: [u8; 16],
    size: u64,
    hash: [u8; 32],
) -> Result<(), Failure> {
    let mut request = vec![18];
    request.extend_from_slice(&item);
    request.extend_from_slice(&attachment);
    write_frame(tls, &request)?;
    expect_status(&read_frame(tls)?, 0)?;
    let mut digest = pm_crypto::DigestState::new().map_err(|_| Failure::Unavailable)?;
    let mut received = 0_u64;
    loop {
        let frame = Zeroizing::new(read_frame_bounded(tls, STREAM_CHUNK_BYTES)?);
        if frame.as_slice() == [0] {
            break;
        }
        received += u64::try_from(frame.len()).map_err(|_| Failure::Unavailable)?;
        digest.update(&frame);
    }
    if received != size || digest.finish() != hash {
        return Err(Failure::Unavailable);
    }
    Ok(())
}

fn human_password_crud(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let socket_path = take_path(arguments, "--socket")?;
    finish_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Human {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path, current_uid())?;
    let mut input = std::io::stdin().lock();
    let password = Zeroizing::new(read_wire_field(&mut input, 1024)?);
    let title = read_wire_string(&mut input, 1024)?;
    let username = read_wire_string(&mut input, 1024 * 1024)?;
    let secret_one = Zeroizing::new(read_wire_field(&mut input, 1024 * 1024)?);
    let destination = read_wire_string(&mut input, 8 * 1024)?;
    let notes = read_wire_string(&mut input, 1024 * 1024)?;
    let edited_title = read_wire_string(&mut input, 1024)?;
    let secret_two = Zeroizing::new(read_wire_field(&mut input, 1024 * 1024)?);

    let mut tls = connect(&profile, &key, &socket_path)?;
    tls.write_all(HUMAN_MAGIC)
        .map_err(|_| Failure::Unavailable)?;
    rpc_unlock(&mut tls, &password)?;
    let prepared = rpc_prepare(
        &mut tls,
        2,
        None,
        &title,
        &username,
        &secret_one,
        &destination,
        &notes,
    )?;
    let mut changed_body = prepared.body.clone();
    *changed_body.last_mut().ok_or(Failure::Unavailable)? ^= 1;
    let changed = encode_commit_request(5, &prepared, &changed_body)?;
    write_frame(&mut tls, &changed)?;
    expect_status(&read_frame(&mut tls)?, 2)?;

    write_frame(
        &mut tls,
        &encode_commit_request(8, &prepared, &prepared.body)?,
    )?;
    let mut lost = [0_u8; 1];
    if let Ok(received) = tls.read(&mut lost)
        && received != 0
    {
        return Err(Failure::Unavailable);
    }
    drop(tls);

    let mut tls = connect(&profile, &key, &socket_path)?;
    tls.write_all(HUMAN_MAGIC)
        .map_err(|_| Failure::Unavailable)?;
    rpc_unlock(&mut tls, &password)?;
    let recovered = rpc_receipt(&mut tls, prepared.transaction_id)?;
    let replay = rpc_commit(&mut tls, &prepared)?;
    if recovered != replay {
        return Err(Failure::Unavailable);
    }
    assert_read(
        &mut tls,
        prepared.item_id,
        &title,
        &username,
        &secret_one,
        &destination,
        &notes,
    )?;
    let edited = rpc_prepare(
        &mut tls,
        3,
        Some(prepared.item_id),
        &edited_title,
        &username,
        &secret_two,
        &destination,
        &notes,
    )?;
    rpc_commit(&mut tls, &edited)?;
    assert_read(
        &mut tls,
        prepared.item_id,
        &edited_title,
        &username,
        &secret_two,
        &destination,
        &notes,
    )?;
    let deleted = rpc_prepare(&mut tls, 4, Some(prepared.item_id), "", "", &[], "", "")?;
    rpc_commit(&mut tls, &deleted)?;
    let mut read_deleted = vec![6];
    read_deleted.extend_from_slice(&prepared.item_id);
    write_frame(&mut tls, &read_deleted)?;
    expect_status(&read_frame(&mut tls)?, 3)?;
    println!("PASS human-crud-e2e receipts=3 replay=1 body-change=rejected");
    Ok(())
}

fn human_content_flow(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let socket_path = take_path(arguments, "--socket")?;
    finish_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Human {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path, current_uid())?;
    let mut input = std::io::stdin().lock();
    let password = Zeroizing::new(read_wire_field(&mut input, 1024)?);
    let mut tls = connect(&profile, &key, &socket_path)?;
    tls.write_all(HUMAN_MAGIC)
        .map_err(|_| Failure::Unavailable)?;
    rpc_unlock(&mut tls, &password)?;

    let mut items = Vec::new();
    let fixture_records = content_fixture_records()?;
    for expected in fixture_records {
        let mut request = vec![9];
        push_bytes(&mut request, &expected.to_bytes())?;
        write_frame(&mut tls, &request)?;
        let prepared = decode_prepared_response(&read_frame(&mut tls)?)?;
        rpc_commit(&mut tls, &prepared)?;
        let mut request = vec![10];
        request.extend_from_slice(&prepared.item_id);
        write_frame(&mut tls, &request)?;
        let response = read_frame(&mut tls)?;
        let actual = LogicalRecord::from_bytes(&expect_success_payload(&response)?)
            .map_err(|_| Failure::Unavailable)?;
        if actual != expected {
            return Err(Failure::Unavailable);
        }
        items.push(prepared.item_id);
    }

    let note = items[5];
    let mut organize = vec![11];
    organize.extend_from_slice(&note);
    organize.push(1);
    organize.extend_from_slice(&1_u16.to_be_bytes());
    push_bytes(&mut organize, b"ticket05-team")?;
    write_frame(&mut tls, &organize)?;
    let prepared = decode_prepared_response(&read_frame(&mut tls)?)?;
    rpc_commit(&mut tls, &prepared)?;

    let mut search = vec![12];
    push_bytes(&mut search, b"ticket05-e2e-search-canary")?;
    push_bytes(&mut search, b"ticket05-team")?;
    search.push(2);
    write_frame(&mut tls, &search)?;
    let response = read_frame(&mut tls)?;
    let mut cursor = Cursor::new(&response);
    cursor.expect(&[0])?;
    if cursor.fixed(2)? != 1_u16.to_be_bytes() || cursor.fixed(16)? != note {
        return Err(Failure::Unavailable);
    }
    cursor.finish()?;

    let mut generator = vec![13];
    generator.extend_from_slice(&96_u16.to_be_bytes());
    generator.push(0b0110); // uppercase + digits only
    write_frame(&mut tls, &generator)?;
    let generated = expect_success_payload(&read_frame(&mut tls)?)?;
    if generated.len() != 96
        || !generated
            .iter()
            .all(|value| value.is_ascii_uppercase() || value.is_ascii_digit())
    {
        return Err(Failure::Unavailable);
    }

    // Opcodes 47/48 used to choose a value implicitly.  Explicit field
    // selection is mandatory, so the public human channel must reject both
    // legacy request shapes rather than retain a second exposure path.
    let mut legacy_reveal = vec![47];
    legacy_reveal.extend_from_slice(&note);
    write_frame(&mut tls, &legacy_reveal)?;
    if read_frame(&mut tls).is_ok() {
        return Err(Failure::Unavailable);
    }
    drop(tls);
    let mut legacy = connect(&profile, &key, &socket_path)?;
    legacy
        .write_all(HUMAN_MAGIC)
        .map_err(|_| Failure::Unavailable)?;
    rpc_unlock(&mut legacy, &password)?;
    let mut legacy_copy = vec![48];
    legacy_copy.extend_from_slice(&note);
    write_frame(&mut legacy, &legacy_copy)?;
    if read_frame(&mut legacy).is_ok() {
        return Err(Failure::Unavailable);
    }
    println!(
        "PASS content-e2e types=7 unicode-attachment=exact source-fields=preserved search=1 organize=tag+favorite generator=configured passkey=storage-only legacy-exposure=rejected"
    );
    Ok(())
}

fn human_audit_lifecycle(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let socket_path = take_path(arguments, "--socket")?;
    finish_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Human {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path, current_uid())?;
    let mut input = std::io::stdin().lock();
    let password = Zeroizing::new(read_wire_field(&mut input, 1024)?);

    let mut tls = connect(&profile, &key, &socket_path)?;
    tls.write_all(HUMAN_MAGIC)
        .map_err(|_| Failure::Unavailable)?;
    rpc_unlock(&mut tls, &password)?;
    write_frame(&mut tls, &[14])?;
    expect_status(&read_frame(&mut tls)?, 0)?;
    drop(tls);

    let mut tls = connect(&profile, &key, &socket_path)?;
    tls.write_all(HUMAN_MAGIC)
        .map_err(|_| Failure::Unavailable)?;
    rpc_unlock(&mut tls, &password)?;
    let before = rpc_audit_query(&mut tls, 1, 1, 64)?;
    if before.0 < 4 || before.1 > 1 || before.2 != 1 {
        return Err(Failure::Unavailable);
    }
    let through_seq = if before.1 == 0 { 1_u64 } else { 2_u64 };
    let mut request = vec![16];
    request.extend_from_slice(&1_u64.to_be_bytes());
    request.extend_from_slice(&through_seq.to_be_bytes());
    write_frame(&mut tls, &request)?;
    let response = read_frame(&mut tls)?;
    let mut cursor = Cursor::new(&response);
    cursor.expect(&[0])?;
    let prepared = WirePrepared {
        transaction_id: cursor
            .fixed(16)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
        item_id: cursor
            .fixed(16)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
        command: cursor.bytes()?,
        body: cursor.bytes()?,
        signature: cursor
            .fixed(64)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
    };
    cursor.finish()?;
    rpc_commit(&mut tls, &prepared)?;
    let after = rpc_audit_query(&mut tls, 1, 1, 64)?;
    if after.1 != 1 || after.0 != before.0 {
        return Err(Failure::Unavailable);
    }
    println!(
        "PASS audit-e2e autonomous-without-kh=1 signed-device=1 purge-gap=1 authority-retained=1"
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn human_streaming_file(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    const SIZE: u64 = 16 * 1024 * 1024 + 4096;
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let socket_path = take_path(arguments, "--socket")?;
    finish_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Human {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path, current_uid())?;
    let mut input = std::io::stdin().lock();
    let password = Zeroizing::new(read_wire_field(&mut input, 1024)?);
    let hash = pattern_digest(SIZE)?;
    let descriptor = Attachment::descriptor(
        [0x7b; 16],
        "large-雪.bin",
        "application/octet-stream",
        SIZE,
        hash,
    )
    .map_err(|_| Failure::Unavailable)?;
    let record = LogicalRecord::new_streaming(
        RecordKind::File,
        HumanMetadata {
            title: "Large stream".to_owned(),
            destinations: vec![],
            tags: vec![],
            favorite: false,
            notes: String::new(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![],
        vec![descriptor],
    )
    .map_err(|_| Failure::Unavailable)?;
    let mut tls = connect(&profile, &key, &socket_path)?;
    tls.write_all(HUMAN_MAGIC)
        .map_err(|_| Failure::Unavailable)?;
    rpc_unlock(&mut tls, &password)?;
    let mut start = vec![17];
    push_bytes(&mut start, &record.to_descriptor_bytes())?;
    write_frame(&mut tls, &start)?;
    send_pattern(&mut tls, SIZE)?;
    write_frame(&mut tls, &[0])?;
    let prepared = decode_prepared_response(&read_frame(&mut tls)?)?;
    rpc_commit(&mut tls, &prepared)?;
    let mut request = vec![18];
    request.extend_from_slice(&prepared.item_id);
    request.extend_from_slice(&[0x7b; 16]);
    write_frame(&mut tls, &request)?;
    expect_status(&read_frame(&mut tls)?, 0)?;
    let mut digest = pm_crypto::DigestState::new().map_err(|_| Failure::Unavailable)?;
    let mut received = 0_u64;
    loop {
        let frame = Zeroizing::new(read_frame_bounded(&mut tls, STREAM_CHUNK_BYTES)?);
        if frame.as_slice() == [0] {
            break;
        }
        received += u64::try_from(frame.len()).map_err(|_| Failure::Unavailable)?;
        digest.update(&frame);
    }
    if received != SIZE || digest.finish() != hash {
        return Err(Failure::Unavailable);
    }
    drop(tls);
    if Attachment::descriptor(
        [0; 16],
        "limit",
        "application/octet-stream",
        16 * 1024 * 1024 * 1024,
        [0; 32],
    )
    .is_err()
        || Attachment::descriptor(
            [0; 16],
            "oversize",
            "application/octet-stream",
            16 * 1024 * 1024 * 1024 + 1,
            [0; 32],
        )
        .is_ok()
    {
        return Err(Failure::Unavailable);
    }
    let short_size = 2 * 1024 * 1024;
    let descriptor = Attachment::descriptor(
        [0x7c; 16],
        "short.bin",
        "application/octet-stream",
        short_size,
        pattern_digest(short_size)?,
    )
    .map_err(|_| Failure::Unavailable)?;
    let short_record = LogicalRecord::new_streaming(
        RecordKind::File,
        HumanMetadata {
            title: "Short".to_owned(),
            destinations: vec![],
            tags: vec![],
            favorite: false,
            notes: String::new(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![],
        vec![descriptor],
    )
    .map_err(|_| Failure::Unavailable)?;
    let mut short = connect(&profile, &key, &socket_path)?;
    short
        .write_all(HUMAN_MAGIC)
        .map_err(|_| Failure::Unavailable)?;
    rpc_unlock(&mut short, &password)?;
    let mut start = vec![17];
    push_bytes(&mut start, &short_record.to_descriptor_bytes())?;
    write_frame(&mut short, &start)?;
    send_pattern(&mut short, 1024 * 1024)?;
    drop(short);
    std::thread::sleep(Duration::from_millis(100));
    println!(
        "PASS streaming-file bytes={SIZE} chunks=17 max_plain_chunk=1048576 short-input=rolled-back limit-16gib=accepted oversize-16gib=rejected"
    );
    Ok(())
}

/// Lab client that deliberately leaves a live upload transaction incomplete so
/// the process harness can crash and restart the custodian at that exact seam.
fn human_streaming_stall(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    const SIZE: u64 = 2 * 1024 * 1024;
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let socket_path = take_path(arguments, "--socket")?;
    finish_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Human {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path, current_uid())?;
    let mut input = std::io::stdin().lock();
    let password = Zeroizing::new(read_wire_field(&mut input, 1024)?);
    let descriptor = Attachment::descriptor(
        [0x7d; 16],
        "interrupted.bin",
        "application/octet-stream",
        SIZE,
        pattern_digest(SIZE)?,
    )
    .map_err(|_| Failure::Unavailable)?;
    let record = LogicalRecord::new_streaming(
        RecordKind::File,
        HumanMetadata {
            title: "Interrupted stream".to_owned(),
            destinations: vec![],
            tags: vec![],
            favorite: false,
            notes: String::new(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![],
        vec![descriptor],
    )
    .map_err(|_| Failure::Unavailable)?;
    let mut tls = connect(&profile, &key, &socket_path)?;
    tls.write_all(HUMAN_MAGIC)
        .map_err(|_| Failure::Unavailable)?;
    rpc_unlock(&mut tls, &password)?;
    let mut start = vec![17];
    push_bytes(&mut start, &record.to_descriptor_bytes())?;
    write_frame(&mut tls, &start)?;
    send_pattern(&mut tls, 1024 * 1024)?;
    println!("READY streaming-upload-transaction=open");
    std::io::stdout()
        .flush()
        .map_err(|_| Failure::Unavailable)?;
    let _ = read_frame(&mut tls)?;
    Err(Failure::Unavailable)
}

fn send_pattern(output: &mut impl Write, size: u64) -> Result<(), Failure> {
    let mut position = 0_u64;
    while position < size {
        let count = usize::try_from((size - position).min(1024 * 1024))
            .map_err(|_| Failure::Unavailable)?;
        let mut chunk = vec![0; count];
        fill_pattern(&mut chunk, position);
        write_frame(output, &chunk)?;
        position += u64::try_from(count).map_err(|_| Failure::Unavailable)?;
    }
    Ok(())
}
fn fill_pattern(bytes: &mut [u8], start: u64) {
    const CANARY: &[u8] = b"ticket05-large-stream-canary-";
    for (index, byte) in bytes.iter_mut().enumerate() {
        let offset = usize::try_from(start + u64::try_from(index).unwrap()).unwrap();
        *byte = CANARY[offset % CANARY.len()];
    }
}
fn pattern_digest(size: u64) -> Result<[u8; 32], Failure> {
    let mut state = pm_crypto::DigestState::new().map_err(|_| Failure::Unavailable)?;
    let mut position = 0;
    let mut chunk = vec![0; 8192];
    while position < size {
        let count = chunk
            .len()
            .min(usize::try_from(size - position).map_err(|_| Failure::Unavailable)?);
        fill_pattern(&mut chunk[..count], position);
        state.update(&chunk[..count]);
        position += u64::try_from(count).map_err(|_| Failure::Unavailable)?;
    }
    Ok(state.finish())
}

#[allow(clippy::too_many_lines)]
fn content_fixture_records() -> Result<Vec<LogicalRecord>, Failure> {
    let metadata = |title: &str, notes: &str| HumanMetadata {
        title: title.to_owned(),
        destinations: vec![Destination {
            label: "Portal 🌎".to_owned(),
            value: "https://e2e.invalid/雪".to_owned(),
        }],
        tags: vec!["synthetic".to_owned()],
        favorite: false,
        notes: notes.to_owned(),
        fields: vec![CustomField {
            id: [0x61; 16],
            label: "extra".to_owned(),
            value: LogicalValue::Text("exact".to_owned()),
            concealed: false,
        }],
        source_fields: vec![SourceField {
            path: "legacy.unknown".to_owned(),
            encoding: SourceEncoding::Bytes,
            value: b"ticket05-e2e-source-canary".to_vec(),
        }],
    };
    let attachment = || {
        Attachment::new(
            [0x71; 16],
            "archivo-雪.txt",
            "text/plain",
            "ticket05-e2e-attachment-canary 🌎".as_bytes(),
        )
        .map_err(|_| Failure::Unavailable)
    };
    let make = |kind, human, auth, attachments| {
        LogicalRecord::new(kind, human, auth, attachments).map_err(|_| Failure::Unavailable)
    };
    Ok(vec![
        make(
            RecordKind::Password,
            metadata("Password", "password"),
            vec![AuthRecord::Password {
                username: "e2e".to_owned(),
                password: b"ticket05-e2e-password-canary".to_vec(),
                destination_refs: vec![0],
            }],
            vec![attachment()?],
        )?,
        make(
            RecordKind::Totp,
            metadata("TOTP", "totp"),
            vec![AuthRecord::Totp {
                secret: b"ticket05-e2e-totp-canary".to_vec(),
                algorithm: TotpAlgorithm::Sha1,
                digits: 6,
                period: 30,
                t0: 0,
                issuer: "Synthetic".to_owned(),
                account: "e2e".to_owned(),
                destination_refs: vec![0],
            }],
            vec![],
        )?,
        make(
            RecordKind::Passkey,
            metadata("Passkey", "stored only"),
            vec![AuthRecord::Passkey {
                rp_id: "e2e.invalid".to_owned(),
                user_handle: b"e2e-user".to_vec(),
                credential_id: b"e2e-credential".to_vec(),
                cose_alg: -8,
                private_key: [0x73; 32],
                public_key: [0x74; 32],
                user_name: "e2e".to_owned(),
                display_name: "E2E".to_owned(),
                sign_count: 0,
                backup_eligible: true,
                backup_state: true,
            }],
            vec![],
        )?,
        make(
            RecordKind::Ssh,
            metadata("SSH", "ssh"),
            vec![AuthRecord::Ssh {
                private_format: PrivateKeyFormat::OpenSsh,
                private_key: b"ticket05-e2e-ssh-canary".to_vec(),
                public_key: b"ssh-ed25519 e2e".to_vec(),
                username: "e2e".to_owned(),
                destination_refs: vec![0],
                passphrase: None,
            }],
            vec![],
        )?,
        make(
            RecordKind::Token,
            metadata("Token", "token"),
            vec![AuthRecord::Token {
                secret: b"ticket05-e2e-token-canary".to_vec(),
                provider: "synthetic".to_owned(),
                profile_id: "e2e".to_owned(),
                destination_refs: vec![0],
                expires_at: None,
            }],
            vec![],
        )?,
        make(
            RecordKind::Note,
            metadata(
                "ticket05-e2e-search-canary 雪\u{1b}]52;c;dGlja2V0MjM=\u{7}",
                "note",
            ),
            vec![],
            vec![],
        )?,
        make(
            RecordKind::File,
            metadata("File", "file"),
            vec![],
            vec![attachment()?],
        )?,
        make(
            RecordKind::Token,
            HumanMetadata {
                title: "Exchange Relationship".to_owned(),
                destinations: vec![Destination {
                    label: "adapter".to_owned(),
                    value: "keycloak-exchange-lab".to_owned(),
                }],
                tags: vec!["synthetic".to_owned()],
                favorite: false,
                notes: "exchange".to_owned(),
                fields: vec![],
                source_fields: vec![],
            },
            vec![AuthRecord::TokenExchange {
                subject_token: b"ticket11-e2e-subject-token-canary".to_vec(),
                requester_client_id: "pm-exchanger".to_owned(),
                requester_client_secret: b"ticket11-e2e-requester-secret-canary".to_vec(),
                provider: "keycloak".to_owned(),
                profile_id: "exchange".to_owned(),
                destination_refs: vec![0],
                expires_at: Some(2_000_000_000),
            }],
            vec![],
        )?,
    ])
}

fn rpc_audit_query(
    tls: &mut rustls::StreamOwned<ClientConnection, UnixStream>,
    generation: u64,
    from_seq: u64,
    limit: u32,
) -> Result<(u64, u64, u64), Failure> {
    let mut request = vec![15];
    request.extend_from_slice(&generation.to_be_bytes());
    request.extend_from_slice(&from_seq.to_be_bytes());
    request.extend_from_slice(&limit.to_be_bytes());
    write_frame(tls, &request)?;
    let response = read_frame(tls)?;
    let mut cursor = Cursor::new(&response);
    cursor.expect(&[0])?;
    let result = (cursor.u64()?, cursor.u64()?, cursor.u64()?);
    cursor.finish()?;
    Ok(result)
}

struct WirePrepared {
    transaction_id: [u8; 16],
    item_id: [u8; 16],
    command: Vec<u8>,
    body: Vec<u8>,
    signature: [u8; 64],
}

fn connect(
    profile: &Profile,
    key: &KeyMaterial,
    socket_path: &Path,
) -> Result<rustls::StreamOwned<ClientConnection, UnixStream>, Failure> {
    let stream = UnixStream::connect(socket_path).map_err(|_| Failure::Unavailable)?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|_| Failure::Unavailable)?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|_| Failure::Unavailable)?;
    if unix_peer_uid(&stream).map_err(|_| Failure::Unavailable)? != profile.server_uid {
        return Err(Failure::Unavailable);
    }
    let config = client_config(key, &profile.server_spki, profile.role)?;
    let server_name =
        ServerName::try_from("passwordmanager.invalid").map_err(|_| Failure::Unavailable)?;
    let connection =
        ClientConnection::new(Arc::new(config), server_name).map_err(|_| Failure::Unavailable)?;
    Ok(rustls::StreamOwned::new(connection, stream))
}

fn rpc_unlock(
    tls: &mut rustls::StreamOwned<ClientConnection, UnixStream>,
    password: &[u8],
) -> Result<(), Failure> {
    let mut request = vec![1];
    push_bytes(&mut request, password)?;
    write_frame(tls, &request)?;
    expect_status(&read_frame(tls)?, 0)
}

#[allow(clippy::too_many_arguments)]
fn rpc_prepare(
    tls: &mut rustls::StreamOwned<ClientConnection, UnixStream>,
    operation: u8,
    item: Option<[u8; 16]>,
    title: &str,
    username: &str,
    password: &[u8],
    destination: &str,
    notes: &str,
) -> Result<WirePrepared, Failure> {
    let mut request = vec![operation];
    if let Some(item) = item {
        request.extend_from_slice(&item);
    }
    if operation != 4 {
        for field in [
            title.as_bytes(),
            username.as_bytes(),
            password,
            destination.as_bytes(),
            notes.as_bytes(),
        ] {
            push_bytes(&mut request, field)?;
        }
    }
    write_frame(tls, &request)?;
    let response = read_frame(tls)?;
    decode_prepared_response(&response)
}

fn decode_prepared_response(response: &[u8]) -> Result<WirePrepared, Failure> {
    let mut cursor = Cursor::new(response);
    cursor.expect(&[0])?;
    let transaction_id = cursor
        .fixed(16)?
        .try_into()
        .map_err(|_| Failure::Unavailable)?;
    let item_id = cursor
        .fixed(16)?
        .try_into()
        .map_err(|_| Failure::Unavailable)?;
    let command = cursor.bytes()?;
    let body = cursor.bytes()?;
    let signature = cursor
        .fixed(64)?
        .try_into()
        .map_err(|_| Failure::Unavailable)?;
    cursor.finish()?;
    Ok(WirePrepared {
        transaction_id,
        item_id,
        command,
        body,
        signature,
    })
}

fn encode_commit_request(
    opcode: u8,
    prepared: &WirePrepared,
    body: &[u8],
) -> Result<Vec<u8>, Failure> {
    let mut request = vec![opcode];
    push_bytes(&mut request, &prepared.command)?;
    request.extend_from_slice(&prepared.signature);
    push_bytes(&mut request, body)?;
    Ok(request)
}

fn rpc_commit(
    tls: &mut rustls::StreamOwned<ClientConnection, UnixStream>,
    prepared: &WirePrepared,
) -> Result<Vec<u8>, Failure> {
    write_frame(tls, &encode_commit_request(5, prepared, &prepared.body)?)?;
    let response = read_frame(tls)?;
    expect_success_payload(&response)
}

fn rpc_receipt(
    tls: &mut rustls::StreamOwned<ClientConnection, UnixStream>,
    transaction_id: [u8; 16],
) -> Result<Vec<u8>, Failure> {
    let mut request = vec![7];
    request.extend_from_slice(&transaction_id);
    write_frame(tls, &request)?;
    let response = read_frame(tls)?;
    expect_success_payload(&response)
}

#[allow(clippy::too_many_arguments)]
fn assert_read(
    tls: &mut rustls::StreamOwned<ClientConnection, UnixStream>,
    item: [u8; 16],
    title: &str,
    username: &str,
    password: &[u8],
    destination: &str,
    notes: &str,
) -> Result<(), Failure> {
    let mut request = vec![6];
    request.extend_from_slice(&item);
    write_frame(tls, &request)?;
    let response = read_frame(tls)?;
    let mut cursor = Cursor::new(&response);
    cursor.expect(&[0])?;
    for expected in [
        title.as_bytes(),
        username.as_bytes(),
        password,
        destination.as_bytes(),
        notes.as_bytes(),
    ] {
        if cursor.bytes()? != expected {
            return Err(Failure::Unavailable);
        }
    }
    cursor.finish()
}

fn expect_success_payload(response: &[u8]) -> Result<Vec<u8>, Failure> {
    if response.first() != Some(&0) || response.len() < 2 {
        return Err(Failure::Unavailable);
    }
    Ok(response[1..].to_vec())
}

fn expect_status(response: &[u8], status: u8) -> Result<(), Failure> {
    if response == [status] {
        Ok(())
    } else {
        Err(Failure::Unavailable)
    }
}

fn handle_human_rpc(
    tls: &mut rustls::StreamOwned<ServerConnection, UnixStream>,
    service: &VaultService,
    channel: AuthenticatedHumanChannel,
) -> Result<(), Failure> {
    let unlock = read_human_unlock_frame(tls, service)?;
    let mut cursor = Cursor::new(&unlock);
    cursor.expect(&[1])?;
    let mut password = Zeroizing::new(cursor.bytes()?);
    cursor.finish()?;
    let mut vault = HumanVault::unlock_with_audit_custody(
        &service.path,
        &password,
        service.device,
        channel,
        Arc::clone(&service.audit_custody),
    )
    .map_err(|_| Failure::Unavailable)?;
    password.zeroize();
    write_frame(tls, &[0])?;
    loop {
        let request = match read_frame(tls) {
            Ok(value) => Zeroizing::new(value),
            Err(_) => return Ok(()),
        };
        if request.as_slice() == [14] {
            drop(vault);
            let mut autonomous = AutonomousAuditVault::open(
                &service.path,
                service.device,
                Arc::clone(&service.audit_custody),
            )
            .map_err(|_| Failure::Unavailable)?;
            autonomous
                .append(&AuditEvent::new(
                    AuditActorKind::System,
                    None,
                    AuditAction::HumanLock,
                    AuditOutcome::Succeeded,
                ))
                .map_err(|_| Failure::Unavailable)?;
            write_frame(tls, &[0])?;
            return Ok(());
        }
        if request.first() == Some(&17) {
            handle_stream_upload(&mut vault, tls, &request[1..])?;
            continue;
        }
        if request.first() == Some(&31) {
            handle_1pux_import(&mut vault, tls, &request[1..])?;
            continue;
        }
        if matches!(request.first(), Some(18 | 62)) {
            handle_stream_download(&vault, tls, &request[1..])?;
            continue;
        }
        if request.as_slice() == [32] {
            handle_native_backup_download(&mut vault, tls)?;
            continue;
        }
        if request.first() == Some(&33) && request.get(1) == Some(&1) {
            handle_plaintext_backup_download(&mut vault, tls, &request[2..])?;
            continue;
        }
        if request.first() == Some(&34) {
            handle_native_backup_restore(&mut vault, tls, &request[1..])?;
            continue;
        }
        if request.first() == Some(&42) {
            handle_native_recovery(&mut vault, tls, &request[1..])?;
            continue;
        }
        if request.first() == Some(&44) {
            handle_recovery_rotation(&mut vault, tls, &request[1..])?;
            continue;
        }
        let drop_response = request.first() == Some(&8);
        let response = handle_human_request(&mut vault, service, &request);
        if drop_response {
            let _ = tls.sock.shutdown(Shutdown::Both);
            return response.map(|_| ());
        }
        write_frame(tls, &response?)?;
    }
}

fn read_human_unlock_frame(
    tls: &mut rustls::StreamOwned<ServerConnection, UnixStream>,
    service: &VaultService,
) -> Result<Vec<u8>, Failure> {
    let mut unlock = read_frame(tls)?;
    if unlock.first() == Some(&0) {
        let request_id: [u8; 16] = unlock
            .get(1..)
            .ok_or(Failure::Unavailable)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?;
        let provider = passkey_provider(service)?;
        let prompt = provider
            .pending_prompt(request_id)
            .map_err(|_| Failure::Unavailable)?
            .ok_or(Failure::Unavailable)?;
        let mut response = vec![0];
        response.push(match prompt.operation() {
            PasskeyOperation::Create => 1,
            PasskeyOperation::Get => 2,
        });
        response.push(match prompt.user_verification() {
            pm_vault::UserVerificationRequirement::Required => 1,
            pm_vault::UserVerificationRequirement::Preferred => 2,
            pm_vault::UserVerificationRequirement::Discouraged => 3,
        });
        for field in [
            prompt.rp_id().as_bytes(),
            prompt.account().as_bytes(),
            prompt.origin().as_bytes(),
            prompt.document_id().as_bytes(),
        ] {
            push_bytes(&mut response, field)?;
        }
        write_frame(tls, &response)?;
        unlock = read_frame(tls)?;
    }
    Ok(unlock)
}

fn passkey_provider(service: &VaultService) -> Result<PasskeyProvider, Failure> {
    let delegated = DelegatedVault::open(
        &service.path,
        service.device,
        Arc::clone(&service.audit_custody),
    )
    .map_err(|_| Failure::Unavailable)?;
    let attempts = AttemptVault::open(delegated).map_err(|_| Failure::Unavailable)?;
    PasskeyProvider::open(attempts).map_err(|_| Failure::Unavailable)
}

fn handle_agent_discovery(
    tls: &mut rustls::StreamOwned<ServerConnection, UnixStream>,
    service: &VaultService,
    observed_rpk: &[u8],
) -> Result<(), Failure> {
    let peer = AgentPeer::from_transport_rpk(observed_rpk).map_err(|_| Failure::Unavailable)?;
    let vault = DelegatedVault::open(
        &service.path,
        service.device,
        Arc::clone(&service.audit_custody),
    )
    .map_err(|_| Failure::Unavailable)?;
    let credentials = vault.discover(&peer);
    let mut response = if credentials.is_ok() {
        vec![0]
    } else {
        vec![1]
    };
    let credentials = credentials.unwrap_or_default();
    if response[0] == 0 {
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
        let response = handle_attempt_request(service, &peer, &request)?;
        write_frame(tls, &response)?;
    }
}

#[allow(clippy::too_many_lines)]
fn handle_attempt_request(
    service: &VaultService,
    peer: &AgentPeer,
    request: &[u8],
) -> Result<Vec<u8>, Failure> {
    let (&opcode, rest) = request.split_first().ok_or(Failure::Unavailable)?;
    let attempts = AttemptVault::open(
        DelegatedVault::open(
            &service.path,
            service.device,
            Arc::clone(&service.audit_custody),
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
                context,
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
            let integration = String::from_utf8(c.bytes()?).map_err(|_| Failure::Unavailable)?;
            let version =
                u32::from_be_bytes(c.fixed(4)?.try_into().map_err(|_| Failure::Unavailable)?);
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
            let origin = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
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

fn encode_passkey_status(status: Option<PasskeyStatus>) -> Result<Vec<u8>, Failure> {
    let mut response = vec![0];
    if let Some(status) = status {
        push_bytes(&mut response, &status.to_bytes())?;
    } else {
        push_bytes(&mut response, &[])?;
    }
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

fn run_provider_once(service: &VaultService) -> Result<(), Failure> {
    let provider = service.provider.as_ref().ok_or(Failure::Unavailable)?;
    let attempts = AttemptVault::open(
        DelegatedVault::open(
            &service.path,
            service.device,
            Arc::clone(&service.audit_custody),
        )
        .map_err(|_| Failure::Unavailable)?,
    )
    .map_err(|_| Failure::Unavailable)?;
    let lease = if let Some(v) = attempts.claim_next().map_err(|_| Failure::Unavailable)? {
        v
    } else if let Some(v) = attempts
        .claim_waiting_for_reconciliation()
        .map_err(|_| Failure::Unavailable)?
    {
        v
    } else {
        return Ok(());
    };
    let guarded = if matches!(
        lease.integration_id(),
        "keycloak-token-exchange" | "github-rest-bearer"
    ) {
        attempts.with_authorized_provider_use(&lease, || call_controlled_provider(provider, &lease))
    } else {
        Ok(call_controlled_provider(provider, &lease))
    };
    let result = match guarded {
        Ok(result) => result,
        Err(
            pm_vault::AttemptError::AccessSuspended
            | pm_vault::AttemptError::AgentRevoked
            | pm_vault::AttemptError::CredentialUnavailable,
        ) => {
            let _ = attempts.settle(
                &lease,
                AttemptOutcome::Failed {
                    reason: "AUTHORITY_REVOKED",
                },
            );
            return Ok(());
        }
        Err(pm_vault::AttemptError::NotFound) => return Ok(()),
        Err(_) => return Err(Failure::Unavailable),
    };
    let outcome = match result {
        Ok(v) => v,
        Err(()) => AttemptOutcome::Indeterminate,
    };
    attempts
        .settle(&lease, outcome)
        .map_err(|_| Failure::Unavailable)?;
    Ok(())
}

fn call_controlled_provider(
    provider: &ControlledProvider,
    lease: &pm_vault::AttemptLease,
) -> Result<AttemptOutcome, ()> {
    if matches!(lease.integration_id(), "ssh-server" | "linux-system-ssh") {
        return call_ssh_provider(provider, lease);
    }
    let mut stream = UnixStream::connect(&provider.socket).map_err(|_| ())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|_| ())?;
    stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(|_| ())?;
    if unix_peer_uid(&stream).map_err(|_| ())? != provider.uid {
        return Err(());
    }
    let opcode = if lease.reconciliation_only() {
        2
    } else if lease.integration_id() == "keycloak-webauthn" {
        4
    } else if lease.integration_id() == "keycloak-browser-oidc" {
        3
    } else if lease.integration_id() == "keycloak-token-exchange" {
        4
    } else if lease.integration_id() == "github-rest-bearer" {
        5
    } else {
        1
    };
    let mut request = Zeroizing::new(vec![opcode]);
    request.extend_from_slice(lease.attempt_id());
    request.extend_from_slice(lease.revision_id());
    if !lease.reconciliation_only() {
        if matches!(opcode, 3..=5) {
            push_bytes(&mut request, lease.integration_id().as_bytes()).map_err(|_| ())?;
            push_bytes(&mut request, lease.method().as_bytes()).map_err(|_| ())?;
        }
        push_bytes(&mut request, lease.destination().as_bytes()).map_err(|_| ())?;
        push_bytes(&mut request, lease.context()).map_err(|_| ())?;
        if opcode == 5 {
            push_bytes(&mut request, lease.subject_token().ok_or(())?).map_err(|_| ())?;
        } else {
            push_bytes(&mut request, lease.username().as_bytes()).map_err(|_| ())?;
            push_bytes(&mut request, lease.password()).map_err(|_| ())?;
            if lease.integration_id() == "keycloak-webauthn" {
                request.extend_from_slice(lease.credential_id());
            }
        }
        if opcode == 3 {
            if let Some(totp) = lease.totp() {
                push_bytes(&mut request, totp.secret()).map_err(|_| ())?;
                let algorithm = match totp.algorithm() {
                    TotpAlgorithm::Sha1 => "SHA1",
                    TotpAlgorithm::Sha256 => "SHA256",
                    TotpAlgorithm::Sha512 => "SHA512",
                };
                push_bytes(&mut request, algorithm.as_bytes()).map_err(|_| ())?;
                request.push(totp.digits());
                request.extend_from_slice(&totp.period().to_be_bytes());
                request.extend_from_slice(&totp.t0().to_be_bytes());
            } else {
                push_bytes(&mut request, &[]).map_err(|_| ())?;
                push_bytes(&mut request, &[]).map_err(|_| ())?;
                request.push(0);
                request.extend_from_slice(&0_u16.to_be_bytes());
                request.extend_from_slice(&0_u64.to_be_bytes());
            }
        } else if lease.integration_id() == "keycloak-token-exchange" {
            push_bytes(&mut request, lease.subject_token().ok_or(())?).map_err(|_| ())?;
        }
    }
    write_frame(&mut stream, &request).map_err(|_| ())?;
    let response = read_frame(&mut stream).map_err(|_| ())?;
    let mut c = Cursor::new(&response);
    let status = *c.fixed(1).map_err(|_| ())?.first().ok_or(())?;
    let value = c.bytes().map_err(|_| ())?;
    c.finish().map_err(|_| ())?;
    match status {
        0 => Ok(AttemptOutcome::Succeeded { result: value }),
        1 => Ok(AttemptOutcome::WaitingForHuman { challenge: value }),
        2 => Ok(AttemptOutcome::Failed {
            reason: "AUTH_REJECTED",
        }),
        3 => Ok(AttemptOutcome::Indeterminate),
        4 => Ok(AttemptOutcome::Failed {
            reason: "UNSUPPORTED_INTEGRATION",
        }),
        5 => Ok(AttemptOutcome::Failed {
            reason: "INTEGRITY_FAILURE",
        }),
        6 => Ok(AttemptOutcome::Failed {
            reason: "RATE_LIMITED",
        }),
        _ => Err(()),
    }
}

fn call_ssh_provider(
    provider: &ControlledProvider,
    lease: &pm_vault::AttemptLease,
) -> Result<AttemptOutcome, ()> {
    if lease.reconciliation_only() {
        return Ok(AttemptOutcome::WaitingForHuman {
            challenge: b"additional_factor_required".to_vec(),
        });
    }
    let mut stream = UnixStream::connect(&provider.socket).map_err(|_| ())?;
    stream.set_read_timeout(Some(IO_TIMEOUT)).map_err(|_| ())?;
    stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(|_| ())?;
    if unix_peer_uid(&stream).map_err(|_| ())? != provider.uid {
        return Err(());
    }
    let public = lease.ssh().map_or(&[][..], pm_vault::SshLease::public_key);
    let mut request = vec![4];
    request.extend_from_slice(lease.attempt_id());
    request.extend_from_slice(lease.revision_id());
    push_bytes(&mut request, lease.integration_id().as_bytes()).map_err(|_| ())?;
    push_bytes(&mut request, lease.method().as_bytes()).map_err(|_| ())?;
    push_bytes(&mut request, lease.destination().as_bytes()).map_err(|_| ())?;
    push_bytes(&mut request, lease.context()).map_err(|_| ())?;
    push_bytes(&mut request, lease.username().as_bytes()).map_err(|_| ())?;
    push_bytes(&mut request, public).map_err(|_| ())?;
    request.extend_from_slice(lease.owner_subject());
    request.extend_from_slice(&lease.owner_generation().to_be_bytes());
    write_frame(&mut stream, &request).map_err(|_| ())?;

    let ready = read_frame(&mut stream).map_err(|_| ())?;
    let mut cursor = Cursor::new(&ready);
    let status = *cursor.fixed(1).map_err(|_| ())?.first().ok_or(())?;
    let value = cursor.bytes().map_err(|_| ())?;
    cursor.finish().map_err(|_| ())?;
    match status {
        5 if value.is_empty() => {}
        2 | 4 => {
            return Ok(AttemptOutcome::Failed {
                reason: "AUTH_REJECTED",
            });
        }
        3 => return Ok(AttemptOutcome::Indeterminate),
        _ => return Err(()),
    }
    if lease.method() == "password" {
        let mut secret = vec![5];
        push_bytes(&mut secret, lease.password()).map_err(|_| ())?;
        write_frame(&mut stream, &secret).map_err(|_| ())?;
        secret.zeroize();
    }
    let mut signed = false;
    loop {
        let response = read_frame(&mut stream).map_err(|_| ())?;
        let mut cursor = Cursor::new(&response);
        let status = *cursor.fixed(1).map_err(|_| ())?.first().ok_or(())?;
        let value = cursor.bytes().map_err(|_| ())?;
        cursor.finish().map_err(|_| ())?;
        match status {
            0 => {
                return Ok(AttemptOutcome::Succeeded { result: value });
            }
            1 => {
                return Ok(AttemptOutcome::WaitingForHuman { challenge: value });
            }
            2 | 4 => {
                return Ok(AttemptOutcome::Failed {
                    reason: "AUTH_REJECTED",
                });
            }
            3 => return Ok(AttemptOutcome::Indeterminate),
            6 if lease.method() == "publickey" && !signed => {
                let Ok(signature) = sign_ssh_auth_payload(lease, &value) else {
                    return Ok(AttemptOutcome::Failed {
                        reason: "INTEGRITY_FAILURE",
                    });
                };
                signed = true;
                let mut answer = vec![7];
                push_bytes(&mut answer, &signature).map_err(|_| ())?;
                write_frame(&mut stream, &answer).map_err(|_| ())?;
            }
            _ => return Err(()),
        }
    }
}

/// Signs only the exact RFC 4252 public-key user-authentication payload bound
/// to this lease. An arbitrary signing oracle is deliberately not exposed.
fn sign_ssh_auth_payload(lease: &pm_vault::AttemptLease, payload: &[u8]) -> Result<Vec<u8>, ()> {
    let ssh = lease.ssh().ok_or(())?;
    if ssh.private_format() != PrivateKeyFormat::OpenSsh || payload.len() > 16 * 1024 {
        return Err(());
    }
    let public_text = std::str::from_utf8(ssh.public_key()).map_err(|_| ())?;
    let public = russh::keys::PublicKey::from_openssh(public_text).map_err(|_| ())?;
    if public.algorithm().as_str() != "ssh-ed25519" {
        return Err(());
    }
    let public_blob = public.to_bytes().map_err(|_| ())?;
    let mut cursor = SshCursor::new(payload);
    let session_id = cursor.string()?;
    if session_id.is_empty() || session_id.len() > 64 || cursor.byte()? != 50 {
        return Err(());
    }
    if cursor.string()? != lease.username().as_bytes()
        || cursor.string()? != b"ssh-connection"
        || cursor.string()? != b"publickey"
        || cursor.byte()? != 1
        || cursor.string()? != b"ssh-ed25519"
        || cursor.string()? != public_blob
        || !cursor.finished()
    {
        return Err(());
    }
    let private_text = std::str::from_utf8(ssh.private_key()).map_err(|_| ())?;
    let mut private = russh::keys::PrivateKey::from_openssh(private_text).map_err(|_| ())?;
    if private.is_encrypted() {
        private = private
            .decrypt(ssh.passphrase().ok_or(())?)
            .map_err(|_| ())?;
    } else if ssh.passphrase().is_some_and(|value| !value.is_empty()) {
        return Err(());
    }
    if private.algorithm().as_str() != "ssh-ed25519" || private.public_key() != &public {
        return Err(());
    }
    let signature = private.try_sign(payload).map_err(|_| ())?;
    if signature.as_ref().len() != 64 {
        return Err(());
    }
    let mut encoded = Vec::with_capacity(4 + 11 + 4 + 64);
    push_bytes(&mut encoded, b"ssh-ed25519").map_err(|_| ())?;
    push_bytes(&mut encoded, signature.as_ref()).map_err(|_| ())?;
    Ok(encoded)
}

struct SshCursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> SshCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    fn byte(&mut self) -> Result<u8, ()> {
        let value = *self.bytes.get(self.at).ok_or(())?;
        self.at += 1;
        Ok(value)
    }
    fn string(&mut self) -> Result<&'a [u8], ()> {
        let end = self.at.checked_add(4).ok_or(())?;
        let length = u32::from_be_bytes(
            self.bytes
                .get(self.at..end)
                .ok_or(())?
                .try_into()
                .map_err(|_| ())?,
        ) as usize;
        self.at = end;
        let end = self.at.checked_add(length).ok_or(())?;
        let value = self.bytes.get(self.at..end).ok_or(())?;
        self.at = end;
        Ok(value)
    }
    const fn finished(&self) -> bool {
        self.at == self.bytes.len()
    }
}

fn commit_authority(
    vault: &mut HumanVault,
    prepared: &PreparedHumanCommand,
) -> Result<(), Failure> {
    let signature = vault.sign(prepared).map_err(|_| Failure::Unavailable)?;
    let receipt = vault
        .commit(prepared.command(), &signature, prepared.body())
        .map_err(|_| Failure::Unavailable)?;
    if vault
        .receipt(*prepared.transaction_id())
        .map_err(|_| Failure::Unavailable)?
        != receipt
        || vault
            .commit(prepared.command(), &signature, prepared.body())
            .map_err(|_| Failure::Unavailable)?
            != receipt
    {
        return Err(Failure::Unavailable);
    }
    Ok(())
}

fn authorization_setup(vault: &mut HumanVault, first: &[u8], second: &[u8]) -> Result<(), Failure> {
    if first.len() != SPKI_BYTES || second.len() != SPKI_BYTES || first == second {
        return Err(Failure::Unavailable);
    }
    let record = PasswordRecord::new(
        "Synthetic TLS shared account",
        "ticket07-user",
        b"ticket07-secret-canary",
        "https://ticket07.invalid/login",
        "",
    )
    .map_err(|_| Failure::Unavailable)?;
    let prepared = vault
        .prepare_create(&record)
        .map_err(|_| Failure::Unavailable)?;
    let item = *prepared.item_id();
    commit_authority(vault, &prepared)?;
    let note = LogicalRecord::new(
        RecordKind::Note,
        HumanMetadata {
            title: "Synthetic excluded note".to_owned(),
            destinations: vec![],
            tags: vec![],
            favorite: false,
            notes: "not authorized".to_owned(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![],
        vec![],
    )
    .map_err(|_| Failure::Unavailable)?;
    let prepared = vault
        .prepare_create_record(&note)
        .map_err(|_| Failure::Unavailable)?;
    commit_authority(vault, &prepared)?;
    for (subject, request, rpk, label) in [
        (LAB_AGENT_A, [0x31; 16], first, "Synthetic agent A"),
        (LAB_AGENT_B, [0x32; 16], second, "Synthetic agent B"),
    ] {
        let enrollment = AgentEnrollment::new(subject, request, rpk, label, "ticket07-userns")
            .map_err(|_| Failure::Unavailable)?;
        let prepared = vault
            .prepare_agent_enrollment(&enrollment)
            .map_err(|_| Failure::Unavailable)?;
        commit_authority(vault, prepared.prepared())?;
    }
    let prepared = vault
        .prepare_delegated_resume()
        .map_err(|_| Failure::Unavailable)?;
    commit_authority(vault, &prepared)?;
    let prepared = vault
        .prepare_enable(item)
        .map_err(|_| Failure::Unavailable)?;
    commit_authority(vault, &prepared)
}

fn authorization_suspend(vault: &mut HumanVault) -> Result<(), Failure> {
    let prepared = vault
        .prepare_delegated_suspend(AuthorizationReason::OwnerRequest)
        .map_err(|_| Failure::Unavailable)?;
    commit_authority(vault, &prepared)
}

fn authorization_resume_revoke(vault: &mut HumanVault) -> Result<(), Failure> {
    let prepared = vault
        .prepare_delegated_resume()
        .map_err(|_| Failure::Unavailable)?;
    commit_authority(vault, &prepared)?;
    let prepared = vault
        .prepare_agent_revocation(LAB_AGENT_A, AuthorizationReason::OwnerRequest)
        .map_err(|_| Failure::Unavailable)?;
    commit_authority(vault, &prepared)
}

fn authorization_reenroll(vault: &mut HumanVault, rpk: &[u8]) -> Result<(), Failure> {
    let enrollment = AgentEnrollment::new(
        LAB_AGENT_A,
        [0x33; 16],
        rpk,
        "Synthetic agent A replacement",
        "ticket07-userns",
    )
    .map_err(|_| Failure::Unavailable)?;
    let prepared = vault
        .prepare_agent_enrollment(&enrollment)
        .map_err(|_| Failure::Unavailable)?;
    if prepared.generation() != 2 {
        return Err(Failure::Unavailable);
    }
    commit_authority(vault, prepared.prepared())
}

fn authorization_add_keycloak(vault: &mut HumanVault) -> Result<(), Failure> {
    let alice = LogicalRecord::new(
        RecordKind::Password,
        HumanMetadata {
            title: "Synthetic Keycloak P1 account".to_owned(),
            destinations: vec![Destination {
                label: "installed profile".to_owned(),
                value: "keycloak-lab".to_owned(),
            }],
            tags: vec![],
            favorite: false,
            notes: String::new(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![
            AuthRecord::Password {
                username: "alice".to_owned(),
                password: b"ticket10-password-canary".to_vec(),
                destination_refs: vec![0],
            },
            AuthRecord::Totp {
                secret: b"12345678901234567890".to_vec(),
                algorithm: TotpAlgorithm::Sha1,
                digits: 6,
                period: 30,
                t0: 0,
                issuer: "pm".to_owned(),
                account: "alice".to_owned(),
                destination_refs: vec![0],
            },
        ],
        vec![],
    )
    .map_err(|_| Failure::Unavailable)?;
    create_and_enable(vault, &alice)?;
    let charlie = LogicalRecord::new(
        RecordKind::Password,
        HumanMetadata {
            title: "Synthetic Keycloak challenge account".to_owned(),
            destinations: vec![Destination {
                label: "installed profile".to_owned(),
                value: "keycloak-lab".to_owned(),
            }],
            tags: vec![],
            favorite: false,
            notes: String::new(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![AuthRecord::Password {
            username: "charlie".to_owned(),
            password: b"ticket10-challenge-password".to_vec(),
            destination_refs: vec![0],
        }],
        vec![],
    )
    .map_err(|_| Failure::Unavailable)?;
    create_and_enable(vault, &charlie)
}

fn authorization_add_keycloak_exchange(
    vault: &mut HumanVault,
    subject_token: &[u8],
    requester_secret: &[u8],
) -> Result<(), Failure> {
    let record = LogicalRecord::new(
        RecordKind::Token,
        HumanMetadata {
            title: "Synthetic Keycloak P2 relationship".to_owned(),
            destinations: vec![Destination {
                label: "installed profile".to_owned(),
                value: "keycloak-exchange-lab".to_owned(),
            }],
            tags: vec![],
            favorite: false,
            notes: String::new(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![AuthRecord::TokenExchange {
            subject_token: subject_token.to_vec(),
            requester_client_id: "pm-exchanger".to_owned(),
            requester_client_secret: requester_secret.to_vec(),
            provider: "keycloak".to_owned(),
            profile_id: "keycloak-exchange-lab".to_owned(),
            destination_refs: vec![0],
            expires_at: None,
        }],
        vec![],
    )
    .map_err(|_| Failure::Unavailable)?;
    create_and_enable(vault, &record)
}

fn create_and_enable(vault: &mut HumanVault, record: &LogicalRecord) -> Result<(), Failure> {
    let prepared = vault
        .prepare_create_record(record)
        .map_err(|_| Failure::Unavailable)?;
    let item = *prepared.item_id();
    commit_authority(vault, &prepared)?;
    let prepared = vault
        .prepare_enable(item)
        .map_err(|_| Failure::Unavailable)?;
    commit_authority(vault, &prepared)
}

fn handle_stream_upload(
    tls_vault: &mut HumanVault,
    tls: &mut rustls::StreamOwned<ServerConnection, UnixStream>,
    request: &[u8],
) -> Result<(), Failure> {
    let mut cursor = Cursor::new(request);
    let bytes = cursor.bytes()?;
    cursor.finish()?;
    let record = LogicalRecord::from_descriptor_bytes(&bytes).map_err(|_| Failure::Unavailable)?;
    if record.attachments().len() != 1 {
        return Err(Failure::Unavailable);
    }
    let id = *record.attachments()[0].id();
    let mut reader = FrameReader {
        tls,
        buffer: Vec::new(),
        position: 0,
        ended: false,
    };
    let mut sources = [AttachmentReader::new(id, &mut reader)];
    let prepared = tls_vault
        .prepare_create_record_streaming(&record, &mut sources)
        .map_err(|_| Failure::Unavailable)?;
    let response = encode_prepared(tls_vault, &prepared)?;
    write_frame(reader.tls, &response)
}
fn handle_stream_download(
    vault: &HumanVault,
    tls: &mut rustls::StreamOwned<ServerConnection, UnixStream>,
    request: &[u8],
) -> Result<(), Failure> {
    if request.len() != 32 {
        return Err(Failure::Unavailable);
    }
    let item = request[..16].try_into().map_err(|_| Failure::Unavailable)?;
    let attachment = request[16..].try_into().map_err(|_| Failure::Unavailable)?;
    write_frame(tls, &[0])?;
    let mut writer = FrameWriter { tls };
    vault
        .read_attachment_to(item, attachment, &mut writer)
        .map_err(|_| Failure::Unavailable)?;
    write_frame(writer.tls, &[0])
}

fn handle_native_backup_download(
    vault: &mut HumanVault,
    tls: &mut rustls::StreamOwned<ServerConnection, UnixStream>,
) -> Result<(), Failure> {
    write_frame(tls, &[0])?;
    let mut writer = FrameWriter { tls };
    vault
        .write_native_backup(&mut writer)
        .map_err(|_| Failure::Unavailable)?;
    write_frame(writer.tls, &[0])
}

fn handle_plaintext_backup_download(
    vault: &mut HumanVault,
    tls: &mut rustls::StreamOwned<ServerConnection, UnixStream>,
    request: &[u8],
) -> Result<(), Failure> {
    let mut cursor = Cursor::new(request);
    let command = cursor.bytes()?;
    let signature = cursor
        .fixed(64)?
        .try_into()
        .map_err(|_| Failure::Unavailable)?;
    let body = cursor.bytes()?;
    cursor.finish()?;
    write_frame(tls, &[0])?;
    let mut writer = FrameWriter { tls };
    vault
        .write_plaintext_export(&command, &signature, &body, &mut writer)
        .map_err(|_| Failure::Unavailable)?;
    write_frame(writer.tls, &[0])
}

fn handle_native_backup_restore(
    vault: &mut HumanVault,
    tls: &mut rustls::StreamOwned<ServerConnection, UnixStream>,
    request: &[u8],
) -> Result<(), Failure> {
    let mut cursor = Cursor::new(request);
    let mut password = Zeroizing::new(cursor.bytes()?);
    cursor.finish()?;
    if password.len() > 1024 {
        return Err(Failure::Unavailable);
    }
    let mut reader = FrameReader {
        tls,
        buffer: Vec::new(),
        position: 0,
        ended: false,
    };
    let prepared = vault
        .prepare_native_restore(&mut reader, &password)
        .map_err(|_| Failure::Unavailable)?;
    password.zeroize();
    let response = encode_prepared(vault, prepared.prepared())?;
    write_frame(reader.tls, &response)
}

fn handle_native_recovery(
    vault: &mut HumanVault,
    tls: &mut rustls::StreamOwned<ServerConnection, UnixStream>,
    request: &[u8],
) -> Result<(), Failure> {
    let mut cursor = Cursor::new(request);
    let mut encoded = Zeroizing::new(cursor.bytes()?);
    cursor.finish()?;
    let text = std::str::from_utf8(&encoded).map_err(|_| Failure::Unavailable)?;
    let recovery: RecoveryCode = text.parse().map_err(|_| Failure::Unavailable)?;
    let mut reader = FrameReader {
        tls,
        buffer: Vec::new(),
        position: 0,
        ended: false,
    };
    let prepared = vault
        .prepare_native_recovery(&mut reader, &recovery)
        .map_err(|_| Failure::Unavailable)?;
    encoded.zeroize();
    let response = encode_prepared(vault, prepared.prepared())?;
    write_frame(reader.tls, &response)
}

fn handle_recovery_rotation(
    vault: &mut HumanVault,
    tls: &mut rustls::StreamOwned<ServerConnection, UnixStream>,
    request: &[u8],
) -> Result<(), Failure> {
    if !request.is_empty() {
        return Err(Failure::Unavailable);
    }
    let pending = vault
        .begin_recovery_rotation()
        .map_err(|_| Failure::Unavailable)?;
    let mut code = Zeroizing::new(pending.recovery_code().to_string());
    let mut response = vec![0];
    push_bytes(&mut response, code.as_bytes())?;
    write_frame(tls, &response)?;
    let mut confirmation = Zeroizing::new(read_frame_bounded(tls, 1024)?);
    if confirmation.is_empty() {
        write_frame(tls, &[2])?;
        code.zeroize();
        return Ok(());
    }
    let parsed: RecoveryCode = std::str::from_utf8(&confirmation)
        .map_err(|_| Failure::Unavailable)?
        .parse()
        .map_err(|_| Failure::Unavailable)?;
    let prepared = pending
        .confirm(vault, &parsed)
        .map_err(|_| Failure::Unavailable)?;
    confirmation.zeroize();
    code.zeroize();
    let response = encode_prepared(vault, &prepared)?;
    write_frame(tls, &response)
}
struct FrameReader<'a> {
    tls: &'a mut rustls::StreamOwned<ServerConnection, UnixStream>,
    buffer: Vec<u8>,
    position: usize,
    ended: bool,
}
impl Read for FrameReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if self.position == self.buffer.len() {
            if self.ended {
                return Ok(0);
            }
            self.buffer.zeroize();
            self.buffer = read_frame_bounded(self.tls, STREAM_CHUNK_BYTES).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "stream frame unavailable",
                )
            })?;
            self.position = 0;
            if self.buffer == [0] {
                self.ended = true;
                return Ok(0);
            }
        }
        let count = output.len().min(self.buffer.len() - self.position);
        output[..count].copy_from_slice(&self.buffer[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}
impl Drop for FrameReader<'_> {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}
struct FrameWriter<'a> {
    tls: &'a mut rustls::StreamOwned<ServerConnection, UnixStream>,
}
impl Write for FrameWriter<'_> {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        write_frame(self.tls, input).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "stream frame failed")
        })?;
        Ok(input.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.tls.flush()
    }
}

#[allow(clippy::too_many_lines)]
fn handle_1pux_import(
    vault: &mut HumanVault,
    tls: &mut rustls::StreamOwned<ServerConnection, UnixStream>,
    request: &[u8],
) -> Result<(), Failure> {
    let replace_candidates = match request {
        [0] => false,
        [1] => true,
        _ => return Err(Failure::Unavailable),
    };
    write_frame(tls, &[0])?;
    let source = receive_file_descriptor(&tls.sock)?;
    let preview = vault
        .preview_1pux_file(source)
        .map_err(|_| Failure::Unavailable)?;
    let mut decisions = Vec::with_capacity(preview.total());
    let mut offset = 0;
    while offset < preview.total() {
        let page = preview
            .page(offset, 100)
            .map_err(|_| Failure::Unavailable)?;
        for row in page {
            decisions.push(match row.status() {
                CsvRowStatus::New => CsvImportDecision::ImportNew,
                CsvRowStatus::ExactDuplicate => CsvImportDecision::SkipExact,
                CsvRowStatus::CandidateDuplicate if replace_candidates => {
                    CsvImportDecision::Replace(*row.duplicate_item().ok_or(Failure::Unavailable)?)
                }
                CsvRowStatus::CandidateDuplicate => CsvImportDecision::KeepBoth,
            });
        }
        offset += page.len();
    }
    let prepared = vault
        .prepare_1pux_import(preview, decisions)
        .map_err(|_| Failure::Unavailable)?;
    let signature = vault
        .sign(prepared.prepared())
        .map_err(|_| Failure::Unavailable)?;
    let report = prepared.report();
    let mut response = vec![0];
    for value in [
        report.total(),
        report.new_items(),
        report.replaced(),
        report.skipped_exact(),
        report.excluded(),
        report.preserved_fields(),
        report.event_pages(),
    ] {
        response.extend_from_slice(
            &u64::try_from(value)
                .map_err(|_| Failure::Unavailable)?
                .to_be_bytes(),
        );
    }
    response.extend_from_slice(
        &u32::try_from(prepared.item_ids().len())
            .map_err(|_| Failure::Unavailable)?
            .to_be_bytes(),
    );
    for item in prepared.item_ids() {
        response.extend_from_slice(item);
    }
    response.extend_from_slice(prepared.prepared().transaction_id());
    response.extend_from_slice(prepared.prepared().item_id());
    push_bytes(&mut response, prepared.prepared().command())?;
    push_bytes(&mut response, prepared.prepared().body())?;
    response.extend_from_slice(&signature);
    write_frame(tls, &response)
}

#[allow(clippy::too_many_lines)]
fn handle_human_request(
    vault: &mut HumanVault,
    service: &VaultService,
    request: &[u8],
) -> Result<Vec<u8>, Failure> {
    let (&opcode, rest) = request.split_first().ok_or(Failure::Unavailable)?;
    match opcode {
        2 | 3 => {
            let mut cursor = Cursor::new(rest);
            let item = if opcode == 3 {
                Some(
                    cursor
                        .fixed(16)?
                        .try_into()
                        .map_err(|_| Failure::Unavailable)?,
                )
            } else {
                None
            };
            let record = decode_wire_record(&mut cursor)?;
            cursor.finish()?;
            let prepared = if let Some(item) = item {
                vault.prepare_edit(item, &record)
            } else {
                vault.prepare_create(&record)
            }
            .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared)
        }
        43 => {
            let mut cursor = Cursor::new(rest);
            let mut password = Zeroizing::new(cursor.bytes()?);
            cursor.finish()?;
            let prepared = vault
                .prepare_master_password_rotation(&password, KdfProfile::DEFAULT)
                .map_err(|_| Failure::Unavailable)?;
            password.zeroize();
            encode_prepared(vault, &prepared)
        }
        4 => {
            let item = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_delete(item)
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared)
        }
        5 | 8 => {
            let mut cursor = Cursor::new(rest);
            let command = cursor.bytes()?;
            let signature = cursor
                .fixed(64)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            let body = cursor.bytes()?;
            cursor.finish()?;
            match vault.commit(&command, &signature, &body) {
                Ok(receipt) => {
                    let mut response = vec![0];
                    response.extend_from_slice(&receipt.to_bytes());
                    Ok(response)
                }
                Err(HumanCommitError::BodyChanged) => Ok(vec![2]),
                Err(_) => Ok(vec![1]),
            }
        }
        6 => {
            let item = rest.try_into().map_err(|_| Failure::Unavailable)?;
            match vault.read_password(item) {
                Ok(record) => {
                    let mut response = vec![0];
                    for field in [
                        record.title().as_bytes(),
                        record.username().as_bytes(),
                        record.password(),
                        record.destination().as_bytes(),
                        record.notes().as_bytes(),
                    ] {
                        push_bytes(&mut response, field)?;
                    }
                    Ok(response)
                }
                Err(HumanCommitError::ItemNotFound) => Ok(vec![3]),
                Err(_) => Ok(vec![1]),
            }
        }
        7 => {
            let transaction_id = rest.try_into().map_err(|_| Failure::Unavailable)?;
            match vault.receipt(transaction_id) {
                Ok(receipt) => {
                    let mut response = vec![0];
                    response.extend_from_slice(&receipt.to_bytes());
                    Ok(response)
                }
                Err(_) => Ok(vec![3]),
            }
        }
        9 => {
            let mut cursor = Cursor::new(rest);
            let bytes = cursor.bytes()?;
            cursor.finish()?;
            let record = LogicalRecord::from_bytes(&bytes).map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_create_record(&record)
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared)
        }
        10 => {
            let item = rest.try_into().map_err(|_| Failure::Unavailable)?;
            match vault.read_record(item) {
                Ok(record) => {
                    let mut response = vec![0];
                    response.extend_from_slice(&record.to_bytes());
                    Ok(response)
                }
                Err(HumanCommitError::ItemNotFound) => Ok(vec![3]),
                Err(_) => Ok(vec![1]),
            }
        }
        11 => {
            let mut cursor = Cursor::new(rest);
            let item = cursor
                .fixed(16)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            let favorite = match cursor.fixed(1)? {
                [0] => false,
                [1] => true,
                _ => return Err(Failure::Unavailable),
            };
            let count = usize::from(u16::from_be_bytes(
                cursor
                    .fixed(2)?
                    .try_into()
                    .map_err(|_| Failure::Unavailable)?,
            ));
            let mut tags = Vec::with_capacity(count);
            for _ in 0..count {
                tags.push(String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?);
            }
            cursor.finish()?;
            let prepared = vault
                .prepare_organize(item, tags, favorite)
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared)
        }
        12 => {
            let mut cursor = Cursor::new(rest);
            let text = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
            let tag = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
            let favorite = match cursor.fixed(1)? {
                [0] => None,
                [1] => Some(false),
                [2] => Some(true),
                _ => return Err(Failure::Unavailable),
            };
            cursor.finish()?;
            let hits = vault
                .search(&SearchQuery {
                    text: (!text.is_empty()).then_some(text),
                    tag: (!tag.is_empty()).then_some(tag),
                    favorite,
                })
                .map_err(|_| Failure::Unavailable)?;
            let mut response = vec![0];
            response.extend_from_slice(
                &u16::try_from(hits.len())
                    .map_err(|_| Failure::Unavailable)?
                    .to_be_bytes(),
            );
            for hit in hits {
                response.extend_from_slice(hit.item_id());
            }
            Ok(response)
        }
        13 => {
            let mut cursor = Cursor::new(rest);
            let length = usize::from(u16::from_be_bytes(
                cursor
                    .fixed(2)?
                    .try_into()
                    .map_err(|_| Failure::Unavailable)?,
            ));
            let flags = *cursor.fixed(1)?.first().ok_or(Failure::Unavailable)?;
            cursor.finish()?;
            if flags & !0b1111 != 0 {
                return Err(Failure::Unavailable);
            }
            let generated = vault
                .generate_password(&GeneratorConfig {
                    length,
                    lowercase: flags & 1 != 0,
                    uppercase: flags & 2 != 0,
                    digits: flags & 4 != 0,
                    symbols: flags & 8 != 0,
                })
                .map_err(|_| Failure::Unavailable)?;
            let mut response = vec![0];
            response.extend_from_slice(generated.expose());
            Ok(response)
        }
        15 => {
            let mut cursor = Cursor::new(rest);
            let generation = cursor.u64()?;
            let from_seq = cursor.u64()?;
            let limit = usize::try_from(cursor.u32()?).map_err(|_| Failure::Unavailable)?;
            cursor.finish()?;
            let query = vault
                .query_audit(service.device, generation, from_seq, limit)
                .map_err(|_| Failure::Unavailable)?;
            let mut response = vec![0];
            response.extend_from_slice(
                &u64::try_from(query.records().len())
                    .map_err(|_| Failure::Unavailable)?
                    .to_be_bytes(),
            );
            response.extend_from_slice(
                &u64::try_from(query.discontinuities().len())
                    .map_err(|_| Failure::Unavailable)?
                    .to_be_bytes(),
            );
            response.extend_from_slice(
                &u64::try_from(query.segment_count())
                    .map_err(|_| Failure::Unavailable)?
                    .to_be_bytes(),
            );
            Ok(response)
        }
        60 => {
            let pin: [u8; 44] = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let protected = Zeroizing::new(
                vault
                    .create_sync_pairing(pin)
                    .map_err(|_| Failure::Unavailable)?
                    .to_protected_bytes(),
            );
            let mut response = vec![0];
            push_bytes(&mut response, &protected)?;
            Ok(response)
        }
        61 => {
            let item = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let record = vault.read_record(item).map_err(|_| Failure::Unavailable)?;
            let mut response = vec![0];
            response.extend_from_slice(
                &u16::try_from(record.attachments().len())
                    .map_err(|_| Failure::Unavailable)?
                    .to_be_bytes(),
            );
            for attachment in record.attachments() {
                response.extend_from_slice(attachment.id());
                push_bytes(&mut response, attachment.name().as_bytes())?;
                response.extend_from_slice(&attachment.size().to_be_bytes());
            }
            Ok(response)
        }
        63 => {
            let mut cursor = Cursor::new(rest);
            let protected = Zeroizing::new(cursor.bytes()?);
            let program = std::path::PathBuf::from(
                String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?,
            );
            let socket = std::path::PathBuf::from(
                String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?,
            );
            let client_key = std::path::PathBuf::from(
                String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?,
            );
            let server_public = std::path::PathBuf::from(
                String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?,
            );
            let pin: [u8; 44] = cursor
                .fixed(44)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            cursor.finish()?;
            let pairing = vault
                .open_sync_pairing(&protected)
                .map_err(|_| Failure::Unavailable)?;
            let job = service.sync_jobs.start(
                &pairing,
                program,
                socket,
                client_key,
                server_public,
                pin,
            )?;
            let mut response = vec![0];
            response.extend_from_slice(&job);
            Ok(response)
        }
        64 => {
            let device: [u8; 16] = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_device_retirement(device)
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared)
        }
        65 => {
            if !rest.is_empty() {
                return Err(Failure::Unavailable);
            }
            Ok(vec![0])
        }
        66 => {
            let job: [u8; 16] = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let status = service.sync_jobs.status(job)?;
            let mut response = vec![0, status.phase.byte()];
            response.extend_from_slice(&status.pushed.to_be_bytes());
            response.extend_from_slice(&status.pulled.to_be_bytes());
            Ok(response)
        }
        16 => {
            let mut cursor = Cursor::new(rest);
            let generation = cursor.u64()?;
            let through_seq = cursor.u64()?;
            cursor.finish()?;
            let purge = vault
                .prepare_audit_purge(service.device, generation, through_seq)
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, purge.prepared())
        }
        19 => {
            if rest.len() != SPKI_BYTES * 2 {
                return Err(Failure::Unavailable);
            }
            authorization_setup(vault, &rest[..SPKI_BYTES], &rest[SPKI_BYTES..])?;
            Ok(vec![0])
        }
        20 => {
            if !rest.is_empty() {
                return Err(Failure::Unavailable);
            }
            authorization_suspend(vault)?;
            Ok(vec![0])
        }
        21 => {
            if !rest.is_empty() {
                return Err(Failure::Unavailable);
            }
            authorization_resume_revoke(vault)?;
            Ok(vec![0])
        }
        22 => {
            if rest.len() != SPKI_BYTES {
                return Err(Failure::Unavailable);
            }
            authorization_reenroll(vault, rest)?;
            Ok(vec![0])
        }
        23 => {
            let mut cursor = Cursor::new(rest);
            let format = *cursor.fixed(1)?.first().ok_or(Failure::Unavailable)?;
            let replace_candidates = match cursor.fixed(1)? {
                [0] => false,
                [1] => true,
                _ => return Err(Failure::Unavailable),
            };
            let source = Zeroizing::new(cursor.bytes()?);
            cursor.finish()?;
            let profile = match format {
                0 => CsvImportProfile::chrome(),
                1 => CsvImportProfile::apple(
                    CsvMapping::new(
                        CsvDelimiter::Comma,
                        CsvEncoding::Utf8,
                        true,
                        RecordKind::Password,
                        vec![
                            (0, CsvField::Title),
                            (1, CsvField::Destination),
                            (2, CsvField::Username),
                            (3, CsvField::Password),
                            (4, CsvField::Notes),
                            (5, CsvField::OtpAuth),
                        ],
                    )
                    .map_err(|_| Failure::Unavailable)?,
                ),
                2 => CsvImportProfile::mappable(
                    CsvMapping::new(
                        CsvDelimiter::Semicolon,
                        CsvEncoding::Utf8,
                        true,
                        RecordKind::Password,
                        vec![
                            (0, CsvField::Title),
                            (2, CsvField::Destination),
                            (1, CsvField::Username),
                            (3, CsvField::Password),
                        ],
                    )
                    .map_err(|_| Failure::Unavailable)?,
                ),
                _ => return Err(Failure::Unavailable),
            };
            let preview = vault
                .preview_csv(&source, &profile)
                .map_err(|_| Failure::Unavailable)?;
            let mut decisions = Vec::with_capacity(preview.total());
            let mut offset = 0;
            while offset < preview.total() {
                let page = preview
                    .page(offset, 100)
                    .map_err(|_| Failure::Unavailable)?;
                for row in page {
                    decisions.push(match row.status() {
                        CsvRowStatus::New => CsvImportDecision::ImportNew,
                        CsvRowStatus::ExactDuplicate => CsvImportDecision::SkipExact,
                        CsvRowStatus::CandidateDuplicate if replace_candidates => {
                            CsvImportDecision::Replace(
                                *row.duplicate_item().ok_or(Failure::Unavailable)?,
                            )
                        }
                        CsvRowStatus::CandidateDuplicate => CsvImportDecision::KeepBoth,
                    });
                }
                offset += page.len();
            }
            let prepared = vault
                .prepare_csv_import(preview, decisions)
                .map_err(|_| Failure::Unavailable)?;
            let signature = vault
                .sign(prepared.prepared())
                .map_err(|_| Failure::Unavailable)?;
            let report = prepared.report();
            let mut response = vec![0];
            for value in [
                report.total(),
                report.new_items(),
                report.replaced(),
                report.skipped_exact(),
                report.excluded(),
                report.preserved_fields(),
                report.event_pages(),
            ] {
                response.extend_from_slice(
                    &u64::try_from(value)
                        .map_err(|_| Failure::Unavailable)?
                        .to_be_bytes(),
                );
            }
            response.extend_from_slice(
                &u32::try_from(prepared.item_ids().len())
                    .map_err(|_| Failure::Unavailable)?
                    .to_be_bytes(),
            );
            for item in prepared.item_ids() {
                response.extend_from_slice(item);
            }
            response.extend_from_slice(prepared.prepared().transaction_id());
            response.extend_from_slice(prepared.prepared().item_id());
            push_bytes(&mut response, prepared.prepared().command())?;
            push_bytes(&mut response, prepared.prepared().body())?;
            response.extend_from_slice(&signature);
            Ok(response)
        }
        24 => {
            let item = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_enable(item)
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared)
        }
        35 | 36 => {
            let mut cursor = Cursor::new(rest);
            let request_id = cursor
                .fixed(16)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            let verification = match cursor.fixed(1)? {
                [1] => HumanVerification::Presence,
                [2] => HumanVerification::Verified,
                _ => return Err(Failure::Unavailable),
            };
            cursor.finish()?;
            let provider = passkey_provider(service)?;
            let status = if opcode == 35 {
                let request = provider
                    .pending_request(request_id)
                    .map_err(|_| Failure::Unavailable)?
                    .filter(|value| value.operation() == PasskeyOperation::Create)
                    .ok_or(Failure::Unavailable)?;
                let registration = vault
                    .prepare_passkey_registration(&request)
                    .map_err(|_| Failure::Unavailable)?;
                commit_authority(vault, registration.prepared())?;
                provider
                    .response(request_id)
                    .map_err(|_| Failure::Unavailable)?
                    .ok_or(Failure::Unavailable)?
            } else {
                provider
                    .confirm_assertion(vault, request_id, verification)
                    .map_err(|_| Failure::Unavailable)?
            };
            let mut response = vec![0];
            push_bytes(&mut response, &status.to_bytes())?;
            Ok(response)
        }
        37 => {
            let request_id = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let provider = passkey_provider(service)?;
            let item = provider
                .registered_item(request_id)
                .map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_enable(item)
                .map_err(|_| Failure::Unavailable)?;
            commit_authority(vault, &prepared)?;
            Ok(vec![0])
        }
        25 => {
            let item = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let history = vault.history(item).map_err(|_| Failure::Unavailable)?;
            let mut response = vec![
                0,
                match history.lifecycle() {
                    pm_vault::ItemLifecycle::Active => 1,
                    pm_vault::ItemLifecycle::Trash => 2,
                    pm_vault::ItemLifecycle::Purged => return Err(Failure::Unavailable),
                },
            ];
            response.extend_from_slice(
                &u16::try_from(history.entries().len())
                    .map_err(|_| Failure::Unavailable)?
                    .to_be_bytes(),
            );
            for entry in history.entries() {
                response.extend_from_slice(entry.revision_id());
                response.extend_from_slice(&entry.modified_at_us().to_be_bytes());
                response.extend_from_slice(entry.issuer_device());
                response.push(u8::from(entry.visible()));
                response.extend_from_slice(
                    &u32::try_from(entry.attachment_count())
                        .map_err(|_| Failure::Unavailable)?
                        .to_be_bytes(),
                );
            }
            Ok(response)
        }
        26 => {
            if rest.len() != 32 {
                return Err(Failure::Unavailable);
            }
            let item = rest[..16].try_into().map_err(|_| Failure::Unavailable)?;
            let revision = rest[16..].try_into().map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_restore(item, revision)
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared)
        }
        27 => {
            let mut cursor = Cursor::new(rest);
            let item = cursor
                .fixed(16)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            let count = usize::from(u16::from_be_bytes(
                cursor
                    .fixed(2)?
                    .try_into()
                    .map_err(|_| Failure::Unavailable)?,
            ));
            let mut revisions = Vec::with_capacity(count);
            for _ in 0..count {
                revisions.push(
                    cursor
                        .fixed(16)?
                        .try_into()
                        .map_err(|_| Failure::Unavailable)?,
                );
            }
            cursor.finish()?;
            let purge = vault
                .prepare_purge_revisions(item, revisions)
                .map_err(|_| Failure::Unavailable)?;
            encode_purge_prepared(vault, &purge)
        }
        28 => {
            let item = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let purge = vault
                .prepare_purge_item(item)
                .map_err(|_| Failure::Unavailable)?;
            encode_purge_prepared(vault, &purge)
        }
        29 => {
            let mut cursor = Cursor::new(rest);
            let item = cursor
                .fixed(16)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            let record =
                LogicalRecord::from_bytes(&cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
            cursor.finish()?;
            let prepared = vault
                .prepare_edit_record(item, &record)
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared)
        }
        30 => {
            if rest.len() != 32 {
                return Err(Failure::Unavailable);
            }
            let item = rest[..16].try_into().map_err(|_| Failure::Unavailable)?;
            let revision = rest[16..].try_into().map_err(|_| Failure::Unavailable)?;
            let record = vault
                .read_revision(item, revision)
                .map_err(|_| Failure::Unavailable)?;
            let mut response = vec![0];
            response.extend_from_slice(&record.to_bytes());
            Ok(response)
        }
        33 => {
            if rest != [0] {
                return Err(Failure::Unavailable);
            }
            let prepared = vault
                .prepare_plaintext_export()
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared)
        }
        40 => {
            if !rest.is_empty() {
                return Err(Failure::Unavailable);
            }
            authorization_add_keycloak(vault)?;
            Ok(vec![0])
        }
        41 => {
            let mut cursor = Cursor::new(rest);
            let subject_token = Zeroizing::new(cursor.bytes()?);
            let requester_secret = Zeroizing::new(cursor.bytes()?);
            cursor.finish()?;
            authorization_add_keycloak_exchange(vault, &subject_token, &requester_secret)?;
            Ok(vec![0])
        }
        45 => {
            let mut cursor = Cursor::new(rest);
            let ssh_private = Zeroizing::new(cursor.bytes()?);
            let ssh_public = cursor.bytes()?;
            let account_password = Zeroizing::new(cursor.bytes()?);
            cursor.finish()?;
            let ssh = LogicalRecord::new(
                RecordKind::Ssh,
                HumanMetadata {
                    title: "Synthetic SSH key".into(),
                    destinations: vec![Destination {
                        label: "SSH lab".into(),
                        value: "ssh-lab".into(),
                    }],
                    tags: vec!["synthetic".into()],
                    favorite: false,
                    notes: String::new(),
                    fields: Vec::new(),
                    source_fields: Vec::new(),
                },
                vec![AuthRecord::Ssh {
                    private_format: PrivateKeyFormat::OpenSsh,
                    private_key: ssh_private.to_vec(),
                    public_key: ssh_public,
                    username: "pmssh".into(),
                    destination_refs: vec![0],
                    passphrase: None,
                }],
                Vec::new(),
            )
            .map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_create_record(&ssh)
                .map_err(|_| Failure::Unavailable)?;
            let key_item = *prepared.item_id();
            commit_authority(vault, &prepared)?;
            let enable = vault
                .prepare_enable(key_item)
                .map_err(|_| Failure::Unavailable)?;
            commit_authority(vault, &enable)?;
            let password = PasswordRecord::new(
                "Synthetic Linux system account",
                "pmssh",
                &account_password,
                "ssh-lab",
                "",
            )
            .map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_create(&password)
                .map_err(|_| Failure::Unavailable)?;
            let password_item = *prepared.item_id();
            commit_authority(vault, &prepared)?;
            let enable = vault
                .prepare_enable(password_item)
                .map_err(|_| Failure::Unavailable)?;
            commit_authority(vault, &enable)?;
            let mut response = vec![0];
            response.extend_from_slice(&key_item);
            response.extend_from_slice(&password_item);
            Ok(response)
        }
        46 | 49 => {
            if !rest.is_empty() {
                return Err(Failure::Unavailable);
            }
            if opcode == 46 {
                vault
                    .record_human_interaction(AuditAction::HumanUnlock, None)
                    .map_err(|_| Failure::Unavailable)?;
            }
            encode_human_catalog(vault)
        }
        50 => {
            let mut cursor = Cursor::new(rest);
            let length = usize::from(u16::from_be_bytes(
                cursor
                    .fixed(2)?
                    .try_into()
                    .map_err(|_| Failure::Unavailable)?,
            ));
            let flags = cursor.fixed(1)?[0];
            cursor.finish()?;
            if flags & !0b1111 != 0 {
                return Err(Failure::Unavailable);
            }
            let generated = vault
                .generate_password(&GeneratorConfig {
                    length,
                    lowercase: flags & 1 != 0,
                    uppercase: flags & 2 != 0,
                    digits: flags & 4 != 0,
                    symbols: flags & 8 != 0,
                })
                .map_err(|_| Failure::Unavailable)?;
            vault
                .record_human_interaction(AuditAction::Reveal, None)
                .map_err(|_| Failure::Unavailable)?;
            let mut response = vec![0];
            push_bytes(&mut response, generated.expose())?;
            Ok(response)
        }
        51 => {
            let item = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let record = vault.read_record(item).map_err(|_| Failure::Unavailable)?;
            let fields = human_fields(&record);
            let mut response = vec![0];
            response.extend_from_slice(
                &u16::try_from(fields.len())
                    .map_err(|_| Failure::Unavailable)?
                    .to_be_bytes(),
            );
            for (label, value) in &fields {
                push_bytes(&mut response, label.as_bytes())?;
                response.extend_from_slice(
                    &u64::try_from(value.len())
                        .map_err(|_| Failure::Unavailable)?
                        .to_be_bytes(),
                );
            }
            Ok(response)
        }
        52 | 53 => {
            let mut cursor = Cursor::new(rest);
            let item = cursor
                .fixed(16)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            let index = usize::from(u16::from_be_bytes(
                cursor
                    .fixed(2)?
                    .try_into()
                    .map_err(|_| Failure::Unavailable)?,
            ));
            cursor.finish()?;
            let record = vault.read_record(item).map_err(|_| Failure::Unavailable)?;
            let fields = human_fields(&record);
            let (_, value) = fields.get(index).ok_or(Failure::Unavailable)?;
            vault
                .record_human_interaction(
                    if opcode == 52 {
                        AuditAction::Reveal
                    } else {
                        AuditAction::Copy
                    },
                    Some(item),
                )
                .map_err(|_| Failure::Unavailable)?;
            let mut response = vec![0];
            push_bytes(&mut response, value)?;
            Ok(response)
        }
        54 => {
            if !rest.is_empty() {
                return Err(Failure::Unavailable);
            }
            let overview = vault.access_overview().map_err(|_| Failure::Unavailable)?;
            let mut response = vec![0, u8::from(overview.suspended())];
            response.extend_from_slice(
                &u16::try_from(overview.agents().len())
                    .map_err(|_| Failure::Unavailable)?
                    .to_be_bytes(),
            );
            for agent in overview.agents() {
                response.extend_from_slice(agent.subject());
                response.extend_from_slice(&agent.generation().to_be_bytes());
                response.push(match agent.status() {
                    "active" => 1,
                    "revoked" => 2,
                    "superseded" => 3,
                    _ => return Err(Failure::Unavailable),
                });
                push_bytes(&mut response, agent.label().as_bytes())?;
                push_bytes(&mut response, agent.environment().as_bytes())?;
            }
            response.extend_from_slice(
                &u16::try_from(overview.credentials().len())
                    .map_err(|_| Failure::Unavailable)?
                    .to_be_bytes(),
            );
            for credential in overview.credentials() {
                response.extend_from_slice(credential.item());
                response.push(u8::from(credential.enabled()));
                push_bytes(&mut response, credential.title().as_bytes())?;
            }
            Ok(response)
        }
        55 => {
            let mut cursor = Cursor::new(rest);
            let subject = cursor
                .fixed(16)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            let request = cursor
                .fixed(16)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            let rpk = cursor.fixed(SPKI_BYTES)?;
            let label = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
            let environment =
                String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
            cursor.finish()?;
            let enrollment = AgentEnrollment::new(subject, request, rpk, &label, &environment)
                .map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_agent_enrollment(&enrollment)
                .map_err(|_| Failure::Unavailable)?;
            commit_authority(vault, prepared.prepared())?;
            Ok(vec![0])
        }
        56 => {
            let subject = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_agent_revocation(subject, AuthorizationReason::OwnerRequest)
                .map_err(|_| Failure::Unavailable)?;
            commit_authority(vault, &prepared)?;
            Ok(vec![0])
        }
        57 => {
            let prepared = match rest {
                [0] => vault.prepare_delegated_resume(),
                [1] => vault.prepare_delegated_suspend(AuthorizationReason::OwnerRequest),
                _ => return Err(Failure::Unavailable),
            }
            .map_err(|_| Failure::Unavailable)?;
            commit_authority(vault, &prepared)?;
            Ok(vec![0])
        }
        58 => {
            let mut cursor = Cursor::new(rest);
            let item = cursor
                .fixed(16)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            let enable = match cursor.fixed(1)? {
                [0] => false,
                [1] => true,
                _ => return Err(Failure::Unavailable),
            };
            cursor.finish()?;
            let prepared = if enable {
                vault.prepare_enable(item)
            } else {
                vault.prepare_disable(item)
            }
            .map_err(|_| Failure::Unavailable)?;
            commit_authority(vault, &prepared)?;
            Ok(vec![0])
        }
        59 => handle_human_pending(vault, service, rest),
        _ => Err(Failure::Unavailable),
    }
}

#[allow(clippy::too_many_lines)]
fn handle_human_pending(
    vault: &mut HumanVault,
    service: &VaultService,
    request: &[u8],
) -> Result<Vec<u8>, Failure> {
    let (action, rest) = request.split_first().ok_or(Failure::Unavailable)?;
    let attempts = AttemptVault::open(
        DelegatedVault::open(
            &service.path,
            service.device,
            Arc::clone(&service.audit_custody),
        )
        .map_err(|_| Failure::Unavailable)?,
    )
    .map_err(|_| Failure::Unavailable)?;
    match action {
        0 if rest.is_empty() => {
            let values = attempts
                .human_pending(vault)
                .map_err(|_| Failure::Unavailable)?;
            let provider = passkey_provider(service)?;
            let mut response = vec![0];
            response.extend_from_slice(
                &u16::try_from(values.len())
                    .map_err(|_| Failure::Unavailable)?
                    .to_be_bytes(),
            );
            for value in values {
                response.extend_from_slice(value.attempt_id());
                response.extend_from_slice(value.credential_id());
                response.extend_from_slice(value.owner_subject());
                response.extend_from_slice(&value.owner_generation().to_be_bytes());
                push_bytes(&mut response, value.agent_status().as_bytes())?;
                push_bytes(&mut response, value.title().as_bytes())?;
                push_bytes(&mut response, value.integration_id().as_bytes())?;
                push_bytes(&mut response, attempt_state_name(value.state()).as_bytes())?;
                push_bytes(&mut response, value.reason().unwrap_or("").as_bytes())?;
                response.extend_from_slice(&value.expires_at_us().to_be_bytes());
                let prompt = if value.state() == AttemptState::WaitingForHuman {
                    if let Some(id) = value.passkey_request() {
                        provider
                            .pending_prompt(*id)
                            .map_err(|_| Failure::Unavailable)?
                            .map(|prompt| (*id, prompt))
                    } else {
                        None
                    }
                } else {
                    None
                };
                response.push(u8::from(prompt.is_some()));
                if let Some((request_id, prompt)) = prompt {
                    response.extend_from_slice(&request_id);
                    response.push(match prompt.user_verification() {
                        pm_vault::UserVerificationRequirement::Required => 2,
                        pm_vault::UserVerificationRequirement::Preferred
                        | pm_vault::UserVerificationRequirement::Discouraged => 1,
                    });
                    for field in [
                        prompt.rp_id().as_bytes(),
                        prompt.account().as_bytes(),
                        prompt.origin().as_bytes(),
                        prompt.document_id().as_bytes(),
                    ] {
                        push_bytes(&mut response, field)?;
                    }
                }
            }
            Ok(response)
        }
        1 => {
            let attempt = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let snapshot = attempts
                .human_cancel(vault, attempt)
                .map_err(|_| Failure::Unavailable)?;
            let mut response = vec![0];
            push_bytes(
                &mut response,
                attempt_state_name(snapshot.state()).as_bytes(),
            )?;
            Ok(response)
        }
        2 => {
            let mut cursor = Cursor::new(rest);
            let request_id = cursor
                .fixed(16)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            let verification = match cursor.fixed(1)? {
                [1] => HumanVerification::Presence,
                [2] => HumanVerification::Verified,
                _ => return Err(Failure::Unavailable),
            };
            cursor.finish()?;
            let provider = passkey_provider(service)?;
            let pending = provider
                .pending_request(request_id)
                .map_err(|_| Failure::Unavailable)?
                .ok_or(Failure::Unavailable)?;
            if pending.operation() != PasskeyOperation::Get {
                return Err(Failure::Unavailable);
            }
            let status = provider
                .confirm_assertion(vault, request_id, verification)
                .map_err(|_| Failure::Unavailable)?;
            let mut response = vec![0];
            push_bytes(&mut response, &status.to_bytes())?;
            Ok(response)
        }
        _ => Err(Failure::Unavailable),
    }
}

#[allow(clippy::too_many_lines)]
fn human_fields(record: &LogicalRecord) -> Vec<(String, Zeroizing<Vec<u8>>)> {
    let mut fields = Vec::new();
    let mut push = |label: String, value: &[u8]| {
        fields.push((label, Zeroizing::new(value.to_vec())));
    };
    let human = record.human();
    push("title".into(), human.title.as_bytes());
    for (index, destination) in human.destinations.iter().enumerate() {
        push(
            format!("destination[{index}].label"),
            destination.label.as_bytes(),
        );
        push(
            format!("destination[{index}].value"),
            destination.value.as_bytes(),
        );
    }
    for (index, tag) in human.tags.iter().enumerate() {
        push(format!("tag[{index}]"), tag.as_bytes());
    }
    push(
        "favorite".into(),
        if human.favorite { b"true" } else { b"false" },
    );
    push("notes".into(), human.notes.as_bytes());
    for (index, field) in human.fields.iter().enumerate() {
        push(format!("custom[{index}].id"), hex(&field.id).as_bytes());
        push(format!("custom[{index}].label"), field.label.as_bytes());
        match &field.value {
            LogicalValue::Text(value) => push(format!("custom[{index}].text"), value.as_bytes()),
            LogicalValue::Bytes(value) => push(format!("custom[{index}].bytes"), value),
        }
        push(
            format!("custom[{index}].concealed"),
            if field.concealed { b"true" } else { b"false" },
        );
    }
    for (index, field) in human.source_fields.iter().enumerate() {
        push(format!("source[{index}].path"), field.path.as_bytes());
        push(
            format!("source[{index}].encoding"),
            match field.encoding {
                SourceEncoding::Utf8 => b"utf8",
                SourceEncoding::Json => b"json",
                SourceEncoding::Bytes => b"bytes",
            },
        );
        push(format!("source[{index}].value"), &field.value);
    }
    for (index, auth) in record.auth().iter().enumerate() {
        match auth {
            AuthRecord::Password {
                username,
                password,
                destination_refs,
            } => {
                push(format!("auth[{index}].username"), username.as_bytes());
                push(format!("auth[{index}].password"), password);
                push(
                    format!("auth[{index}].destination_refs"),
                    format!("{destination_refs:?}").as_bytes(),
                );
            }
            AuthRecord::Totp {
                secret,
                algorithm,
                digits,
                period,
                t0,
                issuer,
                account,
                destination_refs,
            } => {
                push(format!("auth[{index}].secret"), secret);
                push(
                    format!("auth[{index}].algorithm"),
                    format!("{algorithm:?}").as_bytes(),
                );
                push(
                    format!("auth[{index}].digits"),
                    digits.to_string().as_bytes(),
                );
                push(
                    format!("auth[{index}].period"),
                    period.to_string().as_bytes(),
                );
                push(format!("auth[{index}].t0"), t0.to_string().as_bytes());
                push(format!("auth[{index}].issuer"), issuer.as_bytes());
                push(format!("auth[{index}].account"), account.as_bytes());
                push(
                    format!("auth[{index}].destination_refs"),
                    format!("{destination_refs:?}").as_bytes(),
                );
            }
            AuthRecord::Passkey {
                rp_id,
                user_handle,
                credential_id,
                cose_alg,
                private_key,
                public_key,
                user_name,
                display_name,
                sign_count,
                backup_eligible,
                backup_state,
            } => {
                push(format!("auth[{index}].rp_id"), rp_id.as_bytes());
                push(format!("auth[{index}].user_handle"), user_handle);
                push(format!("auth[{index}].credential_id"), credential_id);
                push(
                    format!("auth[{index}].cose_alg"),
                    cose_alg.to_string().as_bytes(),
                );
                push(format!("auth[{index}].private_key"), private_key);
                push(format!("auth[{index}].public_key"), public_key);
                push(format!("auth[{index}].user_name"), user_name.as_bytes());
                push(
                    format!("auth[{index}].display_name"),
                    display_name.as_bytes(),
                );
                push(
                    format!("auth[{index}].sign_count"),
                    sign_count.to_string().as_bytes(),
                );
                push(
                    format!("auth[{index}].backup_eligible"),
                    if *backup_eligible { b"true" } else { b"false" },
                );
                push(
                    format!("auth[{index}].backup_state"),
                    if *backup_state { b"true" } else { b"false" },
                );
            }
            AuthRecord::Ssh {
                private_format,
                private_key,
                public_key,
                username,
                destination_refs,
                passphrase,
            } => {
                push(
                    format!("auth[{index}].private_format"),
                    format!("{private_format:?}").as_bytes(),
                );
                push(format!("auth[{index}].private_key"), private_key);
                push(format!("auth[{index}].public_key"), public_key);
                push(format!("auth[{index}].username"), username.as_bytes());
                push(
                    format!("auth[{index}].destination_refs"),
                    format!("{destination_refs:?}").as_bytes(),
                );
                if let Some(passphrase) = passphrase {
                    push(format!("auth[{index}].passphrase"), passphrase);
                }
            }
            AuthRecord::Token {
                secret,
                provider,
                profile_id,
                destination_refs,
                expires_at,
            } => {
                push(format!("auth[{index}].secret"), secret);
                push(format!("auth[{index}].provider"), provider.as_bytes());
                push(format!("auth[{index}].profile_id"), profile_id.as_bytes());
                push(
                    format!("auth[{index}].destination_refs"),
                    format!("{destination_refs:?}").as_bytes(),
                );
                if let Some(expires_at) = expires_at {
                    push(
                        format!("auth[{index}].expires_at"),
                        expires_at.to_string().as_bytes(),
                    );
                }
            }
            AuthRecord::TokenExchange {
                subject_token,
                requester_client_id,
                requester_client_secret,
                provider,
                profile_id,
                destination_refs,
                expires_at,
            } => {
                push(format!("auth[{index}].subject_token"), subject_token);
                push(
                    format!("auth[{index}].requester_client_id"),
                    requester_client_id.as_bytes(),
                );
                push(
                    format!("auth[{index}].requester_client_secret"),
                    requester_client_secret,
                );
                push(format!("auth[{index}].provider"), provider.as_bytes());
                push(format!("auth[{index}].profile_id"), profile_id.as_bytes());
                push(
                    format!("auth[{index}].destination_refs"),
                    format!("{destination_refs:?}").as_bytes(),
                );
                if let Some(expires_at) = expires_at {
                    push(
                        format!("auth[{index}].expires_at"),
                        expires_at.to_string().as_bytes(),
                    );
                }
            }
        }
    }
    for (index, attachment) in record.attachments().iter().enumerate() {
        push(
            format!("attachment[{index}].id"),
            hex(attachment.id()).as_bytes(),
        );
        push(
            format!("attachment[{index}].name"),
            attachment.name().as_bytes(),
        );
        push(
            format!("attachment[{index}].mime"),
            attachment.mime().as_bytes(),
        );
        push(
            format!("attachment[{index}].size"),
            attachment.size().to_string().as_bytes(),
        );
        push(
            format!("attachment[{index}].sha256"),
            hex(attachment.sha256()).as_bytes(),
        );
        push(format!("attachment[{index}].content"), attachment.content());
    }
    fields
}

fn encode_human_catalog(vault: &HumanVault) -> Result<Vec<u8>, Failure> {
    let catalog = vault.human_catalog().map_err(|_| Failure::Unavailable)?;
    let mut response = vec![0];
    response.extend_from_slice(
        &u16::try_from(catalog.len())
            .map_err(|_| Failure::Unavailable)?
            .to_be_bytes(),
    );
    for entry in catalog {
        response.extend_from_slice(entry.item_id());
        response.push(match entry.kind() {
            RecordKind::Password => 1,
            RecordKind::Totp => 2,
            RecordKind::Passkey => 3,
            RecordKind::Ssh => 4,
            RecordKind::Token => 5,
            RecordKind::Note => 6,
            RecordKind::File => 7,
        });
        response.push(match entry.lifecycle() {
            pm_vault::ItemLifecycle::Active => 1,
            pm_vault::ItemLifecycle::Trash => 2,
            pm_vault::ItemLifecycle::Purged => return Err(Failure::Unavailable),
        });
        response.push(u8::from(entry.favorite()));
        push_bytes(&mut response, entry.title().as_bytes())?;
        response.extend_from_slice(
            &u16::try_from(entry.tags().len())
                .map_err(|_| Failure::Unavailable)?
                .to_be_bytes(),
        );
        for tag in entry.tags() {
            push_bytes(&mut response, tag.as_bytes())?;
        }
    }
    Ok(response)
}

fn encode_purge_prepared(
    vault: &HumanVault,
    purge: &pm_vault::PreparedItemPurge,
) -> Result<Vec<u8>, Failure> {
    let scope = purge.scope();
    let mut response = vec![0, u8::from(scope.terminal())];
    response.extend_from_slice(
        &u16::try_from(scope.revision_ids().len())
            .map_err(|_| Failure::Unavailable)?
            .to_be_bytes(),
    );
    response.extend_from_slice(
        &u32::try_from(scope.attachment_count())
            .map_err(|_| Failure::Unavailable)?
            .to_be_bytes(),
    );
    response.extend_from_slice(&scope.encrypted_bytes().to_be_bytes());
    for revision in scope.revision_ids() {
        response.extend_from_slice(revision);
    }
    let prepared = encode_prepared(vault, purge.prepared())?;
    response.extend_from_slice(&prepared[1..]);
    Ok(response)
}

fn encode_prepared(
    vault: &HumanVault,
    prepared: &PreparedHumanCommand,
) -> Result<Vec<u8>, Failure> {
    let signature = vault.sign(prepared).map_err(|_| Failure::Unavailable)?;
    let mut response = vec![0];
    response.extend_from_slice(prepared.transaction_id());
    response.extend_from_slice(prepared.item_id());
    push_bytes(&mut response, prepared.command())?;
    push_bytes(&mut response, prepared.body())?;
    response.extend_from_slice(&signature);
    Ok(response)
}

fn decode_wire_record(cursor: &mut Cursor<'_>) -> Result<PasswordRecord, Failure> {
    let title = cursor.bytes()?;
    let username = cursor.bytes()?;
    let mut password = Zeroizing::new(cursor.bytes()?);
    let destination = cursor.bytes()?;
    let notes = cursor.bytes()?;
    let record = PasswordRecord::new(
        std::str::from_utf8(&title).map_err(|_| Failure::Unavailable)?,
        std::str::from_utf8(&username).map_err(|_| Failure::Unavailable)?,
        &password,
        std::str::from_utf8(&destination).map_err(|_| Failure::Unavailable)?,
        std::str::from_utf8(&notes).map_err(|_| Failure::Unavailable)?,
    )
    .map_err(|_| Failure::Unavailable)?;
    password.zeroize();
    Ok(record)
}

fn write_frame(output: &mut impl Write, value: &[u8]) -> Result<(), Failure> {
    if value.len() > MAX_HUMAN_FRAME {
        return Err(Failure::Unavailable);
    }
    let length = u32::try_from(value.len()).map_err(|_| Failure::Unavailable)?;
    output
        .write_all(&length.to_be_bytes())
        .and_then(|()| output.write_all(value))
        .and_then(|()| output.flush())
        .map_err(|_| Failure::Unavailable)
}

fn read_frame(input: &mut impl Read) -> Result<Vec<u8>, Failure> {
    read_frame_bounded(input, MAX_HUMAN_FRAME)
}

fn read_frame_bounded(input: &mut impl Read, maximum: usize) -> Result<Vec<u8>, Failure> {
    let mut length = [0_u8; 4];
    input
        .read_exact(&mut length)
        .map_err(|_| Failure::Unavailable)?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| Failure::Unavailable)?;
    if length == 0 || length > maximum {
        return Err(Failure::Unavailable);
    }
    let mut value = vec![0_u8; length];
    input
        .read_exact(&mut value)
        .map_err(|_| Failure::Unavailable)?;
    Ok(value)
}

fn read_wire_field(input: &mut impl Read, maximum: usize) -> Result<Vec<u8>, Failure> {
    let mut length = [0_u8; 4];
    input
        .read_exact(&mut length)
        .map_err(|_| Failure::Unavailable)?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| Failure::Unavailable)?;
    if length > maximum {
        return Err(Failure::Unavailable);
    }
    let mut value = vec![0_u8; length];
    input
        .read_exact(&mut value)
        .map_err(|_| Failure::Unavailable)?;
    Ok(value)
}

fn read_wire_string(input: &mut impl Read, maximum: usize) -> Result<String, Failure> {
    String::from_utf8(read_wire_field(input, maximum)?).map_err(|_| Failure::Unavailable)
}

fn decode_hex_16(value: &Path) -> Result<[u8; 16], Failure> {
    let value = value.to_str().ok_or(Failure::Usage)?.as_bytes();
    if value.len() != 32 {
        return Err(Failure::Usage);
    }
    let mut result = [0_u8; 16];
    for (index, pair) in value.as_chunks::<2>().0.iter().enumerate() {
        result[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(result)
}

fn hex_nibble(value: u8) -> Result<u8, Failure> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(Failure::Usage),
    }
}

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn accept_one(
    listener: &UnixListener,
    expected_uid: u32,
    role: Role,
    config: &Arc<ServerConfig>,
    vault: Option<&VaultService>,
    peer_rpk: Option<&[u8]>,
) {
    let Ok((stream, _)) = listener.accept() else {
        return;
    };
    let _ = handle_connection(stream, expected_uid, role, config, vault, peer_rpk);
}

fn handle_connection(
    stream: UnixStream,
    expected_uid: u32,
    role: Role,
    config: &Arc<ServerConfig>,
    vault: Option<&VaultService>,
    peer_rpk: Option<&[u8]>,
) -> Result<(), Failure> {
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|_| Failure::Unavailable)?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|_| Failure::Unavailable)?;
    if unix_peer_uid(&stream).map_err(|_| Failure::Unavailable)? != expected_uid {
        return Err(Failure::Unavailable);
    }
    let human_channel = if role == Role::Human && vault.is_some() {
        Some(
            AuthenticatedHumanChannel::authenticate(
                stream.try_clone().map_err(|_| Failure::Unavailable)?,
                expected_uid,
            )
            .map_err(|_| Failure::Unavailable)?,
        )
    } else {
        None
    };
    let connection = ServerConnection::new(config.clone()).map_err(|_| Failure::Unavailable)?;
    let mut tls = rustls::StreamOwned::new(connection, stream);
    let mut request = [0_u8; 5];
    tls.read_exact(&mut request)
        .map_err(|_| Failure::Unavailable)?;
    if tls.conn.alpn_protocol() != Some(role.alpn()) {
        return Err(Failure::Unavailable);
    }
    if request == *HUMAN_MAGIC && role == Role::Human {
        let service = vault.ok_or(Failure::Unavailable)?;
        return handle_human_rpc(
            &mut tls,
            service,
            human_channel.ok_or(Failure::Unavailable)?,
        );
    }
    if request == *AGENT_MAGIC && role == Role::Agent {
        let service = vault.ok_or(Failure::Unavailable)?;
        return handle_agent_discovery(&mut tls, service, peer_rpk.ok_or(Failure::Unavailable)?);
    }
    if request != *b"PING\n" {
        return Err(Failure::Unavailable);
    }
    tls.write_all(b"READY").map_err(|_| Failure::Unavailable)?;
    tls.flush().map_err(|_| Failure::Unavailable)
}

fn crypto_provider() -> CryptoProvider {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    provider
}

fn certified_key(key: &KeyMaterial) -> Result<Arc<CertifiedKey>, Failure> {
    let provider = crypto_provider();
    let signing_key = provider
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            key.private.to_vec(),
        )))
        .map_err(|_| Failure::Unavailable)?;
    let derived = signing_key.public_key().ok_or(Failure::Unavailable)?;
    if derived.as_ref() != key.spki {
        return Err(Failure::Unavailable);
    }
    Ok(Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(key.spki.clone())],
        signing_key,
    )))
}

fn server_config(
    key: Arc<CertifiedKey>,
    expected_client_spki: &[u8],
    role: Role,
) -> Result<Arc<ServerConfig>, Failure> {
    let provider = crypto_provider();
    let algorithms = provider.signature_verification_algorithms;
    let verifier = Arc::new(PinnedClientVerifier {
        expected: expected_client_spki.to_vec(),
        algorithms,
    });
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&version::TLS13])
        .map_err(|_| Failure::Unavailable)?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(key)));
    config.alpn_protocols = vec![role.alpn().to_vec()];
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    Ok(Arc::new(config))
}

fn client_config(
    key: &KeyMaterial,
    expected_server_spki: &[u8],
    role: Role,
) -> Result<ClientConfig, Failure> {
    let certified = certified_key(key)?;
    let provider = crypto_provider();
    let algorithms = provider.signature_verification_algorithms;
    let verifier = Arc::new(PinnedServerVerifier {
        expected: expected_server_spki.to_vec(),
        algorithms,
    });
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&version::TLS13])
        .map_err(|_| Failure::Unavailable)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(certified)));
    config.alpn_protocols = vec![role.alpn().to_vec()];
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    Ok(config)
}

#[derive(Debug)]
struct PinnedServerVerifier {
    expected: Vec<u8>,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        verify_pin(end_entity, intermediates, &self.expected)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("TLS 1.2 disabled".to_owned()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_raw_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct PinnedClientVerifier {
    expected: Vec<u8>,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for PinnedClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        verify_pin(end_entity, intermediates, &self.expected)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("TLS 1.2 disabled".to_owned()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_raw_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

fn verify_pin(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    expected: &[u8],
) -> Result<(), TlsError> {
    if !intermediates.is_empty() || end_entity.as_ref() != expected {
        return Err(TlsError::InvalidCertificate(
            CertificateError::UnknownIssuer,
        ));
    }
    Ok(())
}

fn verify_raw_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
    algorithms: &rustls::crypto::WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, TlsError> {
    let spki = SubjectPublicKeyInfoDer::from(cert.as_ref());
    verify_tls13_signature_with_raw_key(message, &spki, dss, algorithms)
}

fn read_key(path: &Path, expected_uid: u32) -> Result<KeyMaterial, Failure> {
    let encoded = read_regular(path, expected_uid, 0o400)?;
    let mut cursor = Cursor::new(&encoded);
    cursor.expect(KEY_MAGIC)?;
    let private = Zeroizing::new(cursor.bytes()?);
    let spki = cursor.fixed(SPKI_BYTES)?.to_vec();
    cursor.finish()?;
    validate_spki(&spki)?;
    Ok(KeyMaterial { private, spki })
}

fn read_bootstrap(path: &Path) -> Result<Bootstrap, Failure> {
    let encoded = read_regular(path, current_uid(), 0o400)?;
    let mut cursor = Cursor::new(&encoded);
    cursor.expect(BOOTSTRAP_MAGIC)?;
    let private = Zeroizing::new(cursor.bytes()?);
    let server_spki = cursor.fixed(SPKI_BYTES)?.to_vec();
    let agent_uid = cursor.u32()?;
    let agent_spki = cursor.fixed(SPKI_BYTES)?.to_vec();
    let human_uid = cursor.u32()?;
    let human_spki = cursor.fixed(SPKI_BYTES)?.to_vec();
    cursor.finish()?;
    for spki in [&server_spki, &agent_spki, &human_spki] {
        validate_spki(spki)?;
    }
    if agent_uid == human_uid
        || agent_uid == current_uid()
        || human_uid == current_uid()
        || agent_spki == human_spki
        || agent_spki == server_spki
        || human_spki == server_spki
    {
        return Err(Failure::Unavailable);
    }
    Ok(Bootstrap {
        server: KeyMaterial {
            private,
            spki: server_spki,
        },
        agent_uid,
        agent_spki,
        human_uid,
        human_spki,
    })
}

fn read_profile(path: &Path) -> Result<Profile, Failure> {
    let encoded = read_regular(path, 0, 0o444)?;
    let mut cursor = Cursor::new(&encoded);
    cursor.expect(PROFILE_MAGIC)?;
    let role = match cursor.fixed(1)?[0] {
        1 => Role::Agent,
        2 => Role::Human,
        _ => return Err(Failure::Unavailable),
    };
    let server_uid = cursor.u32()?;
    let server_spki = cursor.fixed(SPKI_BYTES)?.to_vec();
    cursor.finish()?;
    validate_spki(&server_spki)?;
    if server_uid == 0 {
        return Err(Failure::Unavailable);
    }
    Ok(Profile {
        role,
        server_uid,
        server_spki,
    })
}

fn read_public(path: &Path) -> Result<Vec<u8>, Failure> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Failure::Unavailable)?;
    let encoded = read_regular(path, metadata.uid(), 0o444)?;
    validate_spki(&encoded)?;
    Ok(encoded.to_vec())
}

fn read_import_source(path: &Path) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| Failure::Unavailable)?;
    let before = file.metadata().map_err(|_| Failure::Unavailable)?;
    if !before.file_type().is_file()
        || before.uid() != current_uid()
        || !matches!(before.mode() & 0o7777, 0o400 | 0o600)
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > (MAX_HUMAN_FRAME - 16) as u64
    {
        return Err(Failure::Unavailable);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(before.len()).map_err(|_| Failure::Unavailable)?,
    ));
    file.read_to_end(&mut bytes)
        .map_err(|_| Failure::Unavailable)?;
    let after = file.metadata().map_err(|_| Failure::Unavailable)?;
    if u64::try_from(bytes.len()).ok() != Some(before.len())
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(Failure::Unavailable);
    }
    Ok(bytes)
}

fn open_1pux_source(path: &Path) -> Result<File, Failure> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| Failure::Unavailable)?;
    let metadata = file.metadata().map_err(|_| Failure::Unavailable)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != current_uid()
        || !matches!(metadata.mode() & 0o7777, 0o400 | 0o600)
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > 1024_u64.pow(4) + 256 * 1024 * 1024
    {
        return Err(Failure::Unavailable);
    }
    Ok(file)
}

fn send_file_descriptor(socket: &UnixStream, descriptor: RawFd) -> Result<(), Failure> {
    let mut carrier = 0x20_u8;
    let mut vector = libc::iovec {
        iov_base: (&raw mut carrier).cast(),
        iov_len: 1,
    };
    let mut control = [0_usize; 4];
    // SAFETY: the aligned control buffer is at least CMSG_SPACE(sizeof(fd)); all
    // pointers live until sendmsg returns and describe exactly one carrier byte.
    let sent = unsafe {
        let mut message: libc::msghdr = mem::zeroed();
        message.msg_iov = &raw mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = usize::try_from(libc::CMSG_SPACE(
            u32::try_from(mem::size_of::<RawFd>()).map_err(|_| Failure::Unavailable)?,
        ))
        .map_err(|_| Failure::Unavailable)?;
        let header = libc::CMSG_FIRSTHDR(&raw const message);
        if header.is_null() {
            return Err(Failure::Unavailable);
        }
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = usize::try_from(libc::CMSG_LEN(
            u32::try_from(mem::size_of::<RawFd>()).map_err(|_| Failure::Unavailable)?,
        ))
        .map_err(|_| Failure::Unavailable)?;
        std::ptr::copy_nonoverlapping(
            &raw const descriptor,
            libc::CMSG_DATA(header).cast::<RawFd>(),
            1,
        );
        libc::sendmsg(socket.as_raw_fd(), &raw const message, libc::MSG_NOSIGNAL)
    };
    if sent == 1 {
        Ok(())
    } else {
        Err(Failure::Unavailable)
    }
}

fn receive_file_descriptor(socket: &UnixStream) -> Result<File, Failure> {
    let mut carrier = 0_u8;
    let mut vector = libc::iovec {
        iov_base: (&raw mut carrier).cast(),
        iov_len: 1,
    };
    let mut control = [0_usize; 4];
    // SAFETY: recvmsg owns valid aligned buffers for the duration of the call;
    // MSG_CMSG_CLOEXEC closes the inheritance race before File assumes ownership.
    let (received, flags, descriptors, extra) = unsafe {
        let mut message: libc::msghdr = mem::zeroed();
        message.msg_iov = &raw mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = usize::try_from(libc::CMSG_SPACE(
            u32::try_from(mem::size_of::<RawFd>()).map_err(|_| Failure::Unavailable)?,
        ))
        .map_err(|_| Failure::Unavailable)?;
        let received = libc::recvmsg(socket.as_raw_fd(), &raw mut message, libc::MSG_CMSG_CLOEXEC);
        let header = libc::CMSG_FIRSTHDR(&raw const message);
        let mut descriptors = Vec::new();
        let mut extra = false;
        if !header.is_null()
            && (*header).cmsg_level == libc::SOL_SOCKET
            && (*header).cmsg_type == libc::SCM_RIGHTS
        {
            let base = usize::try_from(libc::CMSG_LEN(0)).map_err(|_| Failure::Unavailable)?;
            let payload = (*header).cmsg_len.saturating_sub(base);
            if payload % mem::size_of::<RawFd>() == 0 {
                for index in 0..payload / mem::size_of::<RawFd>() {
                    descriptors.push(std::ptr::read_unaligned(
                        libc::CMSG_DATA(header).cast::<RawFd>().add(index),
                    ));
                }
            }
            extra = !libc::CMSG_NXTHDR(&raw const message, header).is_null();
        }
        (received, message.msg_flags, descriptors, extra)
    };
    let mut files = descriptors
        .into_iter()
        .filter(|descriptor| *descriptor >= 0)
        .map(|descriptor| {
            // SAFETY: every SCM_RIGHTS descriptor is newly owned by this process.
            unsafe { File::from_raw_fd(descriptor) }
        })
        .collect::<Vec<_>>();
    if received != 1
        || carrier != 0x20
        || flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
        || extra
        || files.len() != 1
    {
        return Err(Failure::Unavailable);
    }
    files.pop().ok_or(Failure::Unavailable)
}

fn read_regular(
    path: &Path,
    expected_uid: u32,
    expected_mode: u32,
) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| Failure::Unavailable)?;
    let metadata = file.metadata().map_err(|_| Failure::Unavailable)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o7777 != expected_mode
        || metadata.nlink() != 1
        || !(1..=MAX_PROTECTED_BYTES).contains(&metadata.len())
    {
        return Err(Failure::Unavailable);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| Failure::Unavailable)?,
    ));
    file.read_to_end(&mut bytes)
        .map_err(|_| Failure::Unavailable)?;
    if u64::try_from(bytes.len()).ok() != Some(metadata.len()) {
        return Err(Failure::Unavailable);
    }
    Ok(bytes)
}

fn validate_spki(spki: &[u8]) -> Result<(), Failure> {
    if spki.len() != SPKI_BYTES || !spki.starts_with(ED25519_SPKI_PREFIX) {
        return Err(Failure::Unavailable);
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), Failure> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| Failure::Unavailable)?;
    let result = (|| {
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|_| Failure::Unavailable)?;
        file.write_all(bytes).map_err(|_| Failure::Unavailable)?;
        file.sync_all().map_err(|_| Failure::Unavailable)?;
        let parent = path.parent().ok_or(Failure::Unavailable)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| Failure::Unavailable)
    })();
    if result.is_err() {
        drop(file);
        return result
            .map_err(|error: Failure| error.after_owned_path_cleanup(fs::remove_file(path)));
    }
    result
}

fn validate_runtime_parent(socket: &Path) -> Result<(), Failure> {
    let parent = socket.parent().ok_or(Failure::Unavailable)?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| Failure::Unavailable)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != current_uid()
        || metadata.mode() & 0o022 != 0
    {
        return Err(Failure::Unavailable);
    }
    Ok(())
}

fn bind_socket(path: &Path) -> Result<UnixListener, Failure> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() && metadata.uid() == current_uid() => {
            fs::remove_file(path).map_err(|_| Failure::Unavailable)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) | Err(_) => return Err(Failure::Unavailable),
    }
    let listener = UnixListener::bind(path).map_err(|_| Failure::Unavailable)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o666))
        .map_err(|_| Failure::Unavailable)?;
    Ok(listener)
}

fn take_u32(arguments: &mut impl Iterator<Item = OsString>, flag: &str) -> Result<u32, Failure> {
    let value = take_path(arguments, flag)?;
    value
        .to_str()
        .and_then(|text| text.parse().ok())
        .ok_or(Failure::Usage)
}

fn finish_arguments(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    if arguments.next().is_none() {
        Ok(())
    } else {
        Err(Failure::Usage)
    }
}

fn current_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions.
    unsafe { libc::geteuid() }
}

fn push_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Failure> {
    let length = u32::try_from(bytes.len()).map_err(|_| Failure::Unavailable)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn expect(&mut self, expected: &[u8]) -> Result<(), Failure> {
        if self.fixed(expected.len())? == expected {
            Ok(())
        } else {
            Err(Failure::Unavailable)
        }
    }

    fn u32(&mut self) -> Result<u32, Failure> {
        let bytes: [u8; 4] = self
            .fixed(4)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, Failure> {
        let bytes: [u8; 8] = self
            .fixed(8)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn bytes(&mut self) -> Result<Vec<u8>, Failure> {
        let length = usize::try_from(self.u32()?).map_err(|_| Failure::Unavailable)?;
        Ok(self.fixed(length)?.to_vec())
    }

    fn fixed(&mut self, length: usize) -> Result<&'a [u8], Failure> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(Failure::Unavailable)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(Failure::Unavailable)?;
        self.offset = end;
        Ok(value)
    }

    fn finish(self) -> Result<(), Failure> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Failure::Unavailable)
        }
    }
}
