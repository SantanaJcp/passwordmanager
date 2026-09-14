// SPDX-License-Identifier: AGPL-3.0-only

//! Windows service composition. Named-pipe kernel identity is checked before
//! the pinned TLS 1.3 RPK handshake; request bodies never select a role.

use std::{
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
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
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_RUNNING, SERVICE_STATUS, SERVICE_STOPPED,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
};
use zeroize::{Zeroize, Zeroizing};

use pm_custody::{
    AuthenticatedHumanChannel, WindowsClientPipe, WindowsEndpoint, WindowsServerPipe,
};
use pm_native_channel::{dpapi_protect_machine, dpapi_unprotect};
use pm_vault::{
    AuditAction, AuditActorKind, AuditDeviceCustody, AuditEvent, AuditOutcome,
    AutonomousAuditVault, HumanCommitError, HumanVault, VaultError,
};

use crate::{Failure, take_path};

const KEY_MAGIC: &[u8] = b"PMWK1";
const BOOTSTRAP_MAGIC: &[u8] = b"PMWCB1";
const PROFILE_MAGIC: &[u8] = b"PMWP1";
const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const SPKI_BYTES: usize = 44;
const MAX_PROTECTED_BYTES: usize = 64 * 1024;
const MAX_FRAME: usize = 18 * 1024 * 1024;
const HUMAN_MAGIC: &[u8; 5] = b"PMH1\n";
const AGENT_MAGIC: &[u8; 5] = b"PMA1\n";
static SERVICE_ARGUMENTS: std::sync::OnceLock<Vec<OsString>> = std::sync::OnceLock::new();

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

    const fn alpn(self) -> &'static [u8] {
        match self {
            Self::Agent => b"pm-agent/1",
            Self::Human => b"pm-human/1",
        }
    }

    const fn endpoint(self) -> WindowsEndpoint {
        match self {
            Self::Agent => WindowsEndpoint::Agent,
            Self::Human => WindowsEndpoint::Human,
        }
    }
}

struct KeyMaterial {
    private: Zeroizing<Vec<u8>>,
    spki: Vec<u8>,
}

struct Bootstrap {
    server: KeyMaterial,
    service_sid: String,
    agent_sid: String,
    agent_spki: Vec<u8>,
    human_sid: String,
    human_spki: Vec<u8>,
}

struct Profile {
    role: Role,
    server_spki: Vec<u8>,
}

#[derive(Clone, Copy)]
enum ServiceDiagnosticPhase {
    ArgsOk,
    BootstrapOk,
    AuditOk,
    AgentTlsOk,
    AgentPipeOk,
    HumanTlsOk,
    HumanPipeOk,
    HumanAccepted,
    HumanMagicAlpn,
    HumanUnlockRequest,
    HumanUnlockWrongChannel,
    HumanUnlockStorageIo,
    HumanUnlockVaultCrypto,
    HumanUnlockVaultFormat,
    HumanUnlockOther,
    HumanUnlockOk,
    HumanUnlockAck,
    HumanLockRequest,
    HumanAuditOpen,
    HumanAuditAppend,
    HumanLockAck,
    ServiceFailed,
}

impl ServiceDiagnosticPhase {
    const fn line(self) -> &'static [u8] {
        match self {
            Self::ArgsOk => b"phase=args-ok\n",
            Self::BootstrapOk => b"phase=bootstrap-ok\n",
            Self::AuditOk => b"phase=audit-ok\n",
            Self::AgentTlsOk => b"phase=agent-tls-ok\n",
            Self::AgentPipeOk => b"phase=agent-pipe-ok\n",
            Self::HumanTlsOk => b"phase=human-tls-ok\n",
            Self::HumanPipeOk => b"phase=human-pipe-ok\n",
            Self::HumanAccepted => b"phase=human-accepted\n",
            Self::HumanMagicAlpn => b"phase=human-magic-alpn\n",
            Self::HumanUnlockRequest => b"phase=human-unlock-request\n",
            Self::HumanUnlockWrongChannel => b"phase=human-unlock-wrong-channel\n",
            Self::HumanUnlockStorageIo => b"phase=human-unlock-storage-io\n",
            Self::HumanUnlockVaultCrypto => b"phase=human-unlock-vault-crypto\n",
            Self::HumanUnlockVaultFormat => b"phase=human-unlock-vault-format\n",
            Self::HumanUnlockOther => b"phase=human-unlock-other\n",
            Self::HumanUnlockOk => b"phase=human-unlock-ok\n",
            Self::HumanUnlockAck => b"phase=human-unlock-ack\n",
            Self::HumanLockRequest => b"phase=human-lock-request\n",
            Self::HumanAuditOpen => b"phase=human-audit-open\n",
            Self::HumanAuditAppend => b"phase=human-audit-append\n",
            Self::HumanLockAck => b"phase=human-lock-ack\n",
            Self::ServiceFailed => b"phase=service-failed\n",
        }
    }
}

#[derive(Clone)]
struct ServiceDiagnostics {
    file: Arc<Mutex<File>>,
}

impl ServiceDiagnostics {
    fn open(path: &Path) -> Result<Self, Failure> {
        use std::os::windows::fs::OpenOptionsExt;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(false);
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
        let file = options.open(path).map_err(|_| Failure::Unavailable)?;
        validate_diagnostic_file(&file)?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
        })
    }

    fn record(&self, phase: ServiceDiagnosticPhase) -> Result<(), Failure> {
        let mut file = self.file.lock().map_err(|_| Failure::Unavailable)?;
        file.seek(SeekFrom::End(0))
            .map_err(|_| Failure::Unavailable)?;
        file.write_all(phase.line())
            .map_err(|_| Failure::Unavailable)?;
        file.sync_all().map_err(|_| Failure::Unavailable)
    }
}

fn validate_diagnostic_file(file: &File) -> Result<(), Failure> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        GetFileInformationByHandle,
    };

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `file` owns a valid handle for the duration of this call and
    // `information` is writable storage of the documented type.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut information) };
    let file_index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    if ok == 0
        || information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
            != 0
        || file_index == 0
    {
        return Err(Failure::Unavailable);
    }
    Ok(())
}

#[derive(Clone)]
struct VaultService {
    path: PathBuf,
    device: [u8; 16],
    audit_custody: Arc<AuditDeviceCustody>,
    diagnostics: Option<ServiceDiagnostics>,
}

pub(crate) fn run(arguments: Vec<OsString>) -> Result<(), Failure> {
    let mut arguments = arguments.into_iter();
    let command = arguments.next().ok_or(Failure::Usage)?;
    match command.to_str() {
        Some("keygen") => keygen(&mut arguments),
        Some("provision-bootstrap") => provision_bootstrap(&mut arguments),
        Some("provision-profile") => provision_profile(&mut arguments),
        Some("serve-vault") => serve_vault(&mut arguments),
        Some("service") => service_dispatch(arguments.collect()),
        Some("probe") => probe(&mut arguments),
        Some("human-lock") => human_lock(&mut arguments),
        _ => Err(Failure::Usage),
    }
}

fn service_dispatch(arguments: Vec<OsString>) -> Result<(), Failure> {
    SERVICE_ARGUMENTS
        .set(arguments)
        .map_err(|_| Failure::Unavailable)?;
    let mut name = "PasswordManager"
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(Failure::Unavailable);
    }
    Ok(())
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let mut name = "PasswordManager"
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let status_handle = unsafe {
        RegisterServiceCtrlHandlerExW(name.as_mut_ptr(), Some(service_control), std::ptr::null())
    };
    if status_handle.is_null() {
        return;
    }
    let mut status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: SERVICE_RUNNING,
        dwControlsAccepted: 0,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    if unsafe { SetServiceStatus(status_handle, &raw const status) } == 0 {
        return;
    }
    let result = SERVICE_ARGUMENTS
        .get()
        .cloned()
        .ok_or(Failure::Unavailable)
        .and_then(|arguments| serve_vault(&mut arguments.into_iter()));
    status.dwCurrentState = SERVICE_STOPPED;
    status.dwWin32ExitCode = u32::from(result.is_err());
    unsafe { SetServiceStatus(status_handle, &raw const status) };
}

unsafe extern "system" fn service_control(
    _control: u32,
    _event_type: u32,
    _event_data: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
) -> u32 {
    // This service deliberately advertises no accepted controls. SCM restart
    // tests terminate the service process and verify a fresh identity/handshake.
    120
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
    let mut encoded = Vec::new();
    encoded.extend_from_slice(KEY_MAGIC);
    push_bytes(&mut encoded, document.as_ref())?;
    encoded.extend_from_slice(&spki);
    write_protected(&private_path, &encoded)?;
    encoded.zeroize();
    write_new(&public_path, &spki)
}

fn provision_bootstrap(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let path = take_path(arguments, "--path")?;
    let server_private = take_path(arguments, "--server-private")?;
    let server_public = take_path(arguments, "--server-public")?;
    let service_sid = take_text(arguments, "--service-sid")?;
    let agent_public = take_path(arguments, "--agent-public")?;
    let agent_sid = take_text(arguments, "--agent-sid")?;
    let human_public = take_path(arguments, "--human-public")?;
    let human_sid = take_text(arguments, "--human-sid")?;
    finish_arguments(arguments)?;
    let server = read_key(&server_private)?;
    if server.spki != read_public(&server_public)? {
        return Err(Failure::Unavailable);
    }
    let agent_spki = read_public(&agent_public)?;
    let human_spki = read_public(&human_public)?;
    if agent_sid == human_sid
        || agent_spki == human_spki
        || agent_spki == server.spki
        || human_spki == server.spki
    {
        return Err(Failure::Unavailable);
    }
    // The native-channel constructor performs the canonical SID/DACL validation.
    pm_native_channel::windows_pipe_sddl(&service_sid, &agent_sid)
        .map_err(|_| Failure::Unavailable)?;
    pm_native_channel::windows_pipe_sddl(&service_sid, &human_sid)
        .map_err(|_| Failure::Unavailable)?;
    let mut encoded = Vec::new();
    encoded.extend_from_slice(BOOTSTRAP_MAGIC);
    push_bytes(&mut encoded, &server.private)?;
    encoded.extend_from_slice(&server.spki);
    for field in [service_sid.as_bytes(), agent_sid.as_bytes()] {
        push_bytes(&mut encoded, field)?;
    }
    encoded.extend_from_slice(&agent_spki);
    push_bytes(&mut encoded, human_sid.as_bytes())?;
    encoded.extend_from_slice(&human_spki);
    write_protected(&path, &encoded)?;
    encoded.zeroize();
    Ok(())
}

fn provision_profile(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let path = take_path(arguments, "--path")?;
    let server_public = take_path(arguments, "--server-public")?;
    let flag = arguments.next().ok_or(Failure::Usage)?;
    let value = arguments.next().ok_or(Failure::Usage)?;
    if flag != "--role" {
        return Err(Failure::Usage);
    }
    let role = Role::parse(&value)?;
    finish_arguments(arguments)?;
    let mut encoded = PROFILE_MAGIC.to_vec();
    encoded.push(role.byte());
    encoded.extend_from_slice(&read_public(&server_public)?);
    write_new(&path, &encoded)
}

fn serve_vault(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let bootstrap_path = take_path(arguments, "--bootstrap")?;
    let vault_id = take_text(arguments, "--vault-id")?;
    let vault_path = take_path(arguments, "--vault")?;
    let device = decode_hex_16(&take_path(arguments, "--device")?)?;
    let diagnostics_path = take_optional_path(arguments, "--service-diagnostics")?;
    finish_arguments(arguments)?;
    let diagnostics = diagnostics_path
        .as_deref()
        .map(ServiceDiagnostics::open)
        .transpose()?;
    let result = (|| {
        // Validate before spawning either endpoint so a malformed identifier
        // cannot leave a partially available role.
        WindowsEndpoint::Agent
            .pipe_name(&vault_id)
            .map_err(|_| Failure::Unavailable)?;
        WindowsEndpoint::Human
            .pipe_name(&vault_id)
            .map_err(|_| Failure::Unavailable)?;
        if let Some(diagnostics) = diagnostics.as_ref() {
            diagnostics.record(ServiceDiagnosticPhase::ArgsOk)?;
        }
        let bootstrap = Arc::new(read_bootstrap(&bootstrap_path)?);
        if let Some(diagnostics) = diagnostics.as_ref() {
            diagnostics.record(ServiceDiagnosticPhase::BootstrapOk)?;
        }
        let audit_path = PathBuf::from(format!("{}.audit-custody", vault_path.display()));
        let audit_custody = Arc::new(load_or_create_audit_custody(&audit_path)?);
        if let Some(diagnostics) = diagnostics.as_ref() {
            diagnostics.record(ServiceDiagnosticPhase::AuditOk)?;
        }
        let service = Arc::new(VaultService {
            path: vault_path,
            device,
            audit_custody,
            diagnostics: diagnostics.clone(),
        });
        let agent = {
            let bootstrap = Arc::clone(&bootstrap);
            let service = Arc::clone(&service);
            let vault_id = vault_id.clone();
            std::thread::spawn(move || serve_role(Role::Agent, &vault_id, &bootstrap, &service))
        };
        let human =
            std::thread::spawn(move || serve_role(Role::Human, &vault_id, &bootstrap, &service));
        agent.join().map_err(|_| Failure::Unavailable)??;
        human.join().map_err(|_| Failure::Unavailable)??;
        Err(Failure::Unavailable)
    })();
    if result.is_err() {
        if let Some(diagnostics) = diagnostics.as_ref() {
            diagnostics.record(ServiceDiagnosticPhase::ServiceFailed)?;
        }
    }
    result
}

fn serve_role(
    role: Role,
    vault_id: &str,
    bootstrap: &Bootstrap,
    service: &VaultService,
) -> Result<(), Failure> {
    let (client_sid, client_spki) = match role {
        Role::Agent => (&bootstrap.agent_sid, &bootstrap.agent_spki),
        Role::Human => (&bootstrap.human_sid, &bootstrap.human_spki),
    };
    let config = server_config(certified_key(&bootstrap.server)?, client_spki, role)?;
    if let Some(diagnostics) = service.diagnostics.as_ref() {
        diagnostics.record(match role {
            Role::Agent => ServiceDiagnosticPhase::AgentTlsOk,
            Role::Human => ServiceDiagnosticPhase::HumanTlsOk,
        })?;
    }
    let mut pipe_reported = false;
    loop {
        let pipe = WindowsServerPipe::create(
            role.endpoint(),
            vault_id,
            &bootstrap.service_sid,
            client_sid,
        )
        .map_err(|_| Failure::Unavailable)?;
        if !pipe_reported {
            if let Some(diagnostics) = service.diagnostics.as_ref() {
                diagnostics.record(match role {
                    Role::Agent => ServiceDiagnosticPhase::AgentPipeOk,
                    Role::Human => ServiceDiagnosticPhase::HumanPipeOk,
                })?;
            }
            pipe_reported = true;
        }
        let _ = handle_server_connection(pipe, role, &config, service, client_spki);
    }
}

fn handle_server_connection(
    mut pipe: WindowsServerPipe,
    role: Role,
    config: &Arc<ServerConfig>,
    service: &VaultService,
    peer_rpk: &[u8],
) -> Result<(), Failure> {
    let tls_pipe = pipe.try_clone().map_err(|_| Failure::Unavailable)?;
    let human_channel = if role == Role::Human {
        let channel = AuthenticatedHumanChannel::authenticate_windows(pipe)
            .map_err(|_| Failure::Unavailable)?;
        if let Some(diagnostics) = service.diagnostics.as_ref() {
            diagnostics.record(ServiceDiagnosticPhase::HumanAccepted)?;
        }
        Some(channel)
    } else {
        pipe.accept().map_err(|_| Failure::Unavailable)?;
        None
    };
    let connection = ServerConnection::new(Arc::clone(config)).map_err(|_| Failure::Unavailable)?;
    let mut tls = rustls::StreamOwned::new(connection, tls_pipe);
    let mut magic = [0_u8; 5];
    tls.read_exact(&mut magic)
        .map_err(|_| Failure::Unavailable)?;
    if tls.conn.alpn_protocol() != Some(role.alpn()) {
        return Err(Failure::Unavailable);
    }
    match role {
        Role::Agent if magic == *AGENT_MAGIC => crate::agent_wire::serve_agent(
            &mut tls,
            &crate::agent_wire::AgentService {
                path: &service.path,
                device: service.device,
                audit_custody: &service.audit_custody,
            },
            peer_rpk,
        ),
        Role::Human if magic == *HUMAN_MAGIC => {
            if let Some(diagnostics) = service.diagnostics.as_ref() {
                diagnostics.record(ServiceDiagnosticPhase::HumanMagicAlpn)?;
            }
            serve_human(
                &mut tls,
                service,
                human_channel.ok_or(Failure::Unavailable)?,
            )
        }
        _ => Err(Failure::Unavailable),
    }
}

fn serve_human(
    tls: &mut impl ReadWrite,
    service: &VaultService,
    channel: AuthenticatedHumanChannel,
) -> Result<(), Failure> {
    let request = read_frame(tls)?;
    let mut cursor = Cursor::new(&request);
    cursor.expect(&[1])?;
    let mut password = Zeroizing::new(cursor.bytes()?);
    cursor.finish()?;
    if let Some(diagnostics) = service.diagnostics.as_ref() {
        diagnostics.record(ServiceDiagnosticPhase::HumanUnlockRequest)?;
    }
    let vault_result = HumanVault::unlock_with_audit_custody(
        &service.path,
        &password,
        service.device,
        channel,
        Arc::clone(&service.audit_custody),
    );
    password.zeroize();
    let vault = match vault_result {
        Ok(vault) => vault,
        Err(error) => {
            if let Some(diagnostics) = service.diagnostics.as_ref() {
                diagnostics.record(human_unlock_failure_phase(&error))?;
            }
            return Err(Failure::Unavailable);
        }
    };
    if let Some(diagnostics) = service.diagnostics.as_ref() {
        diagnostics.record(ServiceDiagnosticPhase::HumanUnlockOk)?;
    }
    write_frame(tls, &[0])?;
    if let Some(diagnostics) = service.diagnostics.as_ref() {
        diagnostics.record(ServiceDiagnosticPhase::HumanUnlockAck)?;
    }
    let request = read_frame(tls)?;
    if request != [14] {
        return Err(Failure::Unavailable);
    }
    if let Some(diagnostics) = service.diagnostics.as_ref() {
        diagnostics.record(ServiceDiagnosticPhase::HumanLockRequest)?;
    }
    drop(vault);
    let mut autonomous = AutonomousAuditVault::open(
        &service.path,
        service.device,
        Arc::clone(&service.audit_custody),
    )
    .map_err(|_| Failure::Unavailable)?;
    if let Some(diagnostics) = service.diagnostics.as_ref() {
        diagnostics.record(ServiceDiagnosticPhase::HumanAuditOpen)?;
    }
    autonomous
        .append(&AuditEvent::new(
            AuditActorKind::System,
            None,
            AuditAction::HumanLock,
            AuditOutcome::Succeeded,
        ))
        .map_err(|_| Failure::Unavailable)?;
    if let Some(diagnostics) = service.diagnostics.as_ref() {
        diagnostics.record(ServiceDiagnosticPhase::HumanAuditAppend)?;
    }
    write_frame(tls, &[0])?;
    if let Some(diagnostics) = service.diagnostics.as_ref() {
        diagnostics.record(ServiceDiagnosticPhase::HumanLockAck)?;
    }
    Ok(())
}

fn human_unlock_failure_phase(error: &HumanCommitError) -> ServiceDiagnosticPhase {
    match error {
        HumanCommitError::WrongChannel => ServiceDiagnosticPhase::HumanUnlockWrongChannel,
        HumanCommitError::Storage(_)
        | HumanCommitError::Io(_)
        | HumanCommitError::Vault(VaultError::Storage(_) | VaultError::Io(_)) => {
            ServiceDiagnosticPhase::HumanUnlockStorageIo
        }
        HumanCommitError::Vault(VaultError::Crypto(_)) => {
            ServiceDiagnosticPhase::HumanUnlockVaultCrypto
        }
        HumanCommitError::Vault(VaultError::InvalidFormat | VaultError::AlreadyExists) => {
            ServiceDiagnosticPhase::HumanUnlockVaultFormat
        }
        _ => ServiceDiagnosticPhase::HumanUnlockOther,
    }
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn probe(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let vault_id = take_text(arguments, "--vault-id")?;
    finish_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    let key = read_key(&private_path)?;
    let mut tls = connect(&profile, &key, &vault_id)?;
    let magic = match profile.role {
        Role::Agent => AGENT_MAGIC,
        Role::Human => HUMAN_MAGIC,
    };
    tls.write_all(magic).map_err(|_| Failure::Unavailable)?;
    println!("READY tls=1.3 rpk=pinned named-pipe=bilateral");
    Ok(())
}

fn human_lock(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let vault_id = take_text(arguments, "--vault-id")?;
    finish_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Human {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path)?;
    let mut password = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take(1025)
        .read_to_end(&mut password)
        .map_err(|_| Failure::Unavailable)?;
    while password
        .last()
        .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
    {
        password.pop();
    }
    if password.is_empty() || password.len() > 1024 {
        return Err(Failure::Unavailable);
    }
    let mut tls = connect(&profile, &key, &vault_id)?;
    tls.write_all(HUMAN_MAGIC)
        .map_err(|_| Failure::Unavailable)?;
    let mut unlock = vec![1];
    push_bytes(&mut unlock, &password)?;
    write_frame(&mut tls, &unlock)?;
    unlock.zeroize();
    password.zeroize();
    if read_frame(&mut tls)? != [0] {
        return Err(Failure::Unavailable);
    }
    write_frame(&mut tls, &[14])?;
    if read_frame(&mut tls)? != [0] {
        return Err(Failure::Unavailable);
    }
    println!("PASS windows-human-unlock-lock");
    Ok(())
}

pub fn agent_rpc(
    profile_path: &Path,
    private_path: &Path,
    vault: &Path,
    request: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    let result = (|| {
        let profile = read_profile(profile_path)?;
        if profile.role != Role::Agent {
            return Err(Failure::Unavailable);
        }
        let key = read_key(private_path)?;
        let vault = vault.to_str().ok_or(Failure::Unavailable)?;
        let mut tls = connect(&profile, &key, vault)?;
        tls.write_all(AGENT_MAGIC)
            .map_err(|_| Failure::Unavailable)?;
        let discovery = read_frame(&mut tls)?;
        if let Some(request) = request {
            write_frame(&mut tls, request)?;
            read_frame(&mut tls)
        } else {
            Ok(discovery)
        }
    })();
    result.map_err(|_| "CUSTODY_UNAVAILABLE".to_owned())
}

fn connect(
    profile: &Profile,
    key: &KeyMaterial,
    vault: &str,
) -> Result<rustls::StreamOwned<ClientConnection, WindowsClientPipe>, Failure> {
    let pipe = WindowsClientPipe::connect_installed(profile.role.endpoint(), vault)
        .map_err(|_| Failure::Unavailable)?;
    let config = client_config(key, &profile.server_spki, profile.role)?;
    let server_name =
        ServerName::try_from("passwordmanager.invalid").map_err(|_| Failure::Unavailable)?;
    let connection =
        ClientConnection::new(Arc::new(config), server_name).map_err(|_| Failure::Unavailable)?;
    Ok(rustls::StreamOwned::new(connection, pipe))
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
    if signing_key
        .public_key()
        .ok_or(Failure::Unavailable)?
        .as_ref()
        != key.spki
    {
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
    verify_tls13_signature_with_raw_key(
        message,
        &SubjectPublicKeyInfoDer::from(cert.as_ref()),
        dss,
        algorithms,
    )
}

fn read_key(path: &Path) -> Result<KeyMaterial, Failure> {
    let encoded = read_protected(path)?;
    let mut cursor = Cursor::new(&encoded);
    cursor.expect(KEY_MAGIC)?;
    let private = Zeroizing::new(cursor.bytes()?);
    let spki = cursor.fixed(SPKI_BYTES)?.to_vec();
    cursor.finish()?;
    validate_spki(&spki)?;
    Ok(KeyMaterial { private, spki })
}

fn read_bootstrap(path: &Path) -> Result<Bootstrap, Failure> {
    let encoded = read_protected(path)?;
    let mut cursor = Cursor::new(&encoded);
    cursor.expect(BOOTSTRAP_MAGIC)?;
    let private = Zeroizing::new(cursor.bytes()?);
    let server_spki = cursor.fixed(SPKI_BYTES)?.to_vec();
    let service_sid = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
    let agent_sid = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
    let agent_spki = cursor.fixed(SPKI_BYTES)?.to_vec();
    let human_sid = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
    let human_spki = cursor.fixed(SPKI_BYTES)?.to_vec();
    cursor.finish()?;
    for spki in [&server_spki, &agent_spki, &human_spki] {
        validate_spki(spki)?;
    }
    if agent_sid == human_sid
        || agent_spki == human_spki
        || agent_spki == server_spki
        || human_spki == server_spki
    {
        return Err(Failure::Unavailable);
    }
    pm_native_channel::windows_pipe_sddl(&service_sid, &agent_sid)
        .map_err(|_| Failure::Unavailable)?;
    pm_native_channel::windows_pipe_sddl(&service_sid, &human_sid)
        .map_err(|_| Failure::Unavailable)?;
    Ok(Bootstrap {
        server: KeyMaterial {
            private,
            spki: server_spki,
        },
        service_sid,
        agent_sid,
        agent_spki,
        human_sid,
        human_spki,
    })
}

fn read_profile(path: &Path) -> Result<Profile, Failure> {
    let encoded = read_bounded(path)?;
    let mut cursor = Cursor::new(&encoded);
    cursor.expect(PROFILE_MAGIC)?;
    let role = match cursor.fixed(1)?[0] {
        1 => Role::Agent,
        2 => Role::Human,
        _ => return Err(Failure::Unavailable),
    };
    let server_spki = cursor.fixed(SPKI_BYTES)?.to_vec();
    cursor.finish()?;
    validate_spki(&server_spki)?;
    Ok(Profile { role, server_spki })
}

fn read_public(path: &Path) -> Result<Vec<u8>, Failure> {
    let bytes = read_bounded(path)?;
    validate_spki(&bytes)?;
    Ok(bytes)
}

fn write_protected(path: &Path, bytes: &[u8]) -> Result<(), Failure> {
    let mut protected = dpapi_protect_machine(bytes).map_err(|_| Failure::Unavailable)?;
    let result = write_new(path, &protected);
    protected.zeroize();
    result
}

fn read_protected(path: &Path) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let encoded = read_bounded(path)?;
    dpapi_unprotect(&encoded).map_err(|_| Failure::Unavailable)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Failure> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| Failure::Unavailable)?;
    file.write_all(bytes).map_err(|_| Failure::Unavailable)?;
    file.sync_all().map_err(|_| Failure::Unavailable)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, Failure> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Failure::Unavailable)?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_PROTECTED_BYTES as u64
    {
        return Err(Failure::Unavailable);
    }
    let bytes = fs::read(path).map_err(|_| Failure::Unavailable)?;
    if bytes.len() != metadata.len() as usize {
        return Err(Failure::Unavailable);
    }
    Ok(bytes)
}

fn load_or_create_audit_custody(path: &Path) -> Result<AuditDeviceCustody, Failure> {
    if path.exists() {
        let bytes = read_protected(path)?;
        return AuditDeviceCustody::from_protected_bytes(&bytes).map_err(|_| Failure::Unavailable);
    }
    let custody = AuditDeviceCustody::generate().map_err(|_| Failure::Unavailable)?;
    let mut bytes = Zeroizing::new(custody.to_protected_bytes());
    write_protected(path, &bytes)?;
    bytes.zeroize();
    Ok(custody)
}

fn validate_spki(spki: &[u8]) -> Result<(), Failure> {
    if spki.len() != SPKI_BYTES || !spki.starts_with(ED25519_SPKI_PREFIX) {
        return Err(Failure::Unavailable);
    }
    Ok(())
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
    fn expect(&mut self, expected: &[u8]) -> Result<(), Failure> {
        if self.fixed(expected.len())? == expected {
            Ok(())
        } else {
            Err(Failure::Unavailable)
        }
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

fn finish_arguments(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    if arguments.next().is_none() {
        Ok(())
    } else {
        Err(Failure::Usage)
    }
}

fn take_optional_path(
    arguments: &mut impl Iterator<Item = OsString>,
    flag: &str,
) -> Result<Option<PathBuf>, Failure> {
    match arguments.next() {
        None => Ok(None),
        Some(actual) if actual == flag => {
            Ok(Some(PathBuf::from(arguments.next().ok_or(Failure::Usage)?)))
        }
        Some(_) => Err(Failure::Usage),
    }
}

fn take_text(
    arguments: &mut impl Iterator<Item = OsString>,
    flag: &str,
) -> Result<String, Failure> {
    let actual = arguments.next().ok_or(Failure::Usage)?;
    let value = arguments.next().ok_or(Failure::Usage)?;
    if actual != flag {
        return Err(Failure::Usage);
    }
    value.into_string().map_err(|_| Failure::Usage)
}

fn decode_hex_16(value: &Path) -> Result<[u8; 16], Failure> {
    let bytes = value.as_os_str().to_str().ok_or(Failure::Usage)?.as_bytes();
    if bytes.len() != 32 {
        return Err(Failure::Usage);
    }
    let mut output = [0; 16];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Result<u8, Failure> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(Failure::Usage),
    }
}
