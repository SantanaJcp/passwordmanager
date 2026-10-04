// SPDX-License-Identifier: AGPL-3.0-only

//! Windows service composition. Named-pipe kernel identity is checked before
//! the pinned TLS 1.3 RPK handshake; request bodies never select a role.

use std::{
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
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
use windows_sys::Win32::Foundation::{ERROR_GEN_FAILURE, ERROR_SERVICE_CANNOT_ACCEPT_CTRL};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS,
    SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW,
    SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
};
use zeroize::{Zeroize, Zeroizing};

use pm_custody::{
    AuthenticatedHumanChannel, WindowsClientPipe, WindowsEndpoint, WindowsServerPipe,
};
use pm_native_channel::{WindowsStopEvent, dpapi_protect_machine, dpapi_unprotect};
use pm_vault::{
    AuditAction, AuditActorKind, AuditDeviceCustody, AuditEvent, AuditOutcome,
    AutonomousAuditVault, HumanCommitError, HumanVault, VaultError,
};

pub(super) use crate::human_wire::WirePrepared;
use crate::human_wire::{
    Cursor, HumanResponse, ProtectedFrameWriter, encoded_bytes_len, protected_copy,
    protected_fields_frame, read_frame, write_frame,
};
use crate::{Failure, take_path};
use pm_crypto::{NativeStdin, ProtectedBytes};

const KEY_MAGIC: &[u8] = b"PMWK1";
const BOOTSTRAP_MAGIC: &[u8] = b"PMWCB1";
const PROFILE_MAGIC: &[u8] = b"PMWP1";
const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const SPKI_BYTES: usize = 44;
const MAX_PROTECTED_BYTES: usize = 64 * 1024;
pub(super) const MAX_FRAME: usize = 18 * 1024 * 1024;
pub(super) const STREAM_CHUNK_BYTES: usize = 1024 * 1024;
pub(super) const HUMAN_MAGIC: &[u8; 5] = b"PMH1\n";
const AGENT_MAGIC: &[u8; 5] = b"PMA1\n";
static SERVICE_ARGUMENTS: std::sync::OnceLock<Vec<OsString>> = std::sync::OnceLock::new();
static SERVICE_FAILED: AtomicBool = AtomicBool::new(false);
static SERVICE_MEMORY_QUOTA_FAILED: AtomicBool = AtomicBool::new(false);

struct ServiceControlContext {
    stop: WindowsStopEvent,
    status_handle: SERVICE_STATUS_HANDLE,
    state: AtomicU32,
}

// SCM invokes the handler on a system-owned thread while `service_main` owns
// the stable boxed context. The kernel handles are immutable after registration;
// the atomic state is the only shared mutation.
unsafe impl Send for ServiceControlContext {}
unsafe impl Sync for ServiceControlContext {}

impl ServiceControlContext {
    fn publish(&self, state: u32, controls: u32, exit_code: u32) -> Result<(), Failure> {
        publish_service_status(self.status_handle, state, controls, exit_code)?;
        self.state.store(state, Ordering::Release);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Role {
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

pub(super) struct KeyMaterial {
    private: ProtectedBytes,
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

pub(super) struct Profile {
    pub(super) role: Role,
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
    TransferAck,
    TransferToken,
    TransferDuplicated,
    TransferDuplicateFailed,
    TransferPreviewSent,
    TransferPreviewFailed,
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
            Self::TransferAck => b"phase=transfer-ack31\n",
            Self::TransferToken => b"phase=transfer-token\n",
            Self::TransferDuplicated => b"phase=transfer-duplicated\n",
            Self::TransferDuplicateFailed => b"phase=transfer-duplicate-failed\n",
            Self::TransferPreviewSent => b"phase=transfer-preview-sent\n",
            Self::TransferPreviewFailed => b"phase=transfer-preview-handler-failed\n",
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

    fn record_1pux_result(
        &self,
        stage: crate::human_wire::OnePuxTransferStage,
        error: Option<&pm_vault::HumanCommitError>,
    ) -> Result<(), Failure> {
        use crate::human_wire::OnePuxTransferStage;
        use pm_vault::HumanCommitError;
        let stage = match stage {
            OnePuxTransferStage::Preview => "preview",
            OnePuxTransferStage::Preparation => "preparation",
            OnePuxTransferStage::Signature => "signature",
            OnePuxTransferStage::FrameReady => "frame-ready",
            OnePuxTransferStage::FrameSent => "frame-sent",
            OnePuxTransferStage::FrameFailed => "frame-failed",
        };
        let category = match error {
            None => "ok",
            Some(HumanCommitError::Crypto(pm_crypto::CryptoError::ResourceUnavailable)) => {
                "crypto-resource"
            }
            Some(HumanCommitError::Crypto(_)) => "crypto-other",
            Some(HumanCommitError::InvalidInput) => "invalid-input",
            Some(HumanCommitError::Io(error)) => match error.kind() {
                std::io::ErrorKind::PermissionDenied => "io-permission",
                std::io::ErrorKind::UnexpectedEof => "io-eof",
                std::io::ErrorKind::InvalidInput => "io-input",
                _ => "io-other",
            },
            Some(HumanCommitError::Storage(_)) => "storage",
            Some(HumanCommitError::StateChanged) => "state-changed",
            Some(HumanCommitError::WrongChannel) => "wrong-channel",
            Some(_) => "other",
        };
        let mut file = self.file.lock().map_err(|_| Failure::Unavailable)?;
        file.seek(SeekFrom::End(0))
            .map_err(|_| Failure::Unavailable)?;
        writeln!(file, "phase=onepux-{stage} category={category}")
            .map_err(|_| Failure::Unavailable)?;
        file.sync_all().map_err(|_| Failure::Unavailable)
    }

    fn memory(&self, failure: Option<pm_crypto::WindowsMemoryFailure>) -> Result<(), Failure> {
        let status = match failure {
            Some(failure) => failure.status,
            None => pm_crypto::windows_memory_status().map_err(|_| Failure::Unavailable)?,
        };
        let mut file = self.file.lock().map_err(|_| Failure::Unavailable)?;
        file.seek(SeekFrom::End(0))
            .map_err(|_| Failure::Unavailable)?;
        if let Some(failure) = failure {
            writeln!(file, "phase=protected-memory-failure category={} requested-capacity={} requested-payload-pages={} win32-error={}", failure.category, failure.requested_capacity_bytes, failure.requested_payload_page_bytes, failure.win32_error).map_err(|_| Failure::Unavailable)?;
        }
        writeln!(file, "phase=protected-memory-status live-capacity={} budget={} live-payload-pages={} live-locked-pages={} live-budget-pages={} page-bytes={} live-regions={} working-set-min={} working-set-max={} working-set-flags={}", status.live_capacity_bytes, status.budget_bytes, status.live_payload_page_bytes, status.live_locked_page_bytes, status.live_budget_page_bytes, status.page_bytes, status.live_regions, status.working_set_min_bytes, status.working_set_max_bytes, status.working_set_flags).map_err(|_| Failure::Unavailable)?;
        file.sync_all().map_err(|_| Failure::Unavailable)
    }

    fn memory_quota_failure(
        &self,
        error: pm_crypto::WindowsMemoryQuotaError,
    ) -> Result<(), Failure> {
        let mut file = self.file.lock().map_err(|_| Failure::Unavailable)?;
        writeln!(file, "phase=protected-memory-quota-failure category=PROTECTED_MEMORY_QUOTA_UNAVAILABLE reason={} win32-error={}", error.category, error.win32_error).map_err(|_| Failure::Unavailable)?;
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
    sync_jobs: Arc<crate::sync_job::Manager>,
    admission: Arc<crate::custody_admission::CustodyAdmission>,
}

struct PreparedRole {
    role: Role,
    pipe: WindowsServerPipe,
    config: Arc<ServerConfig>,
    peer_rpk: Vec<u8>,
    service_sid: String,
    client_sid: String,
}

pub(crate) fn run(arguments: Vec<OsString>) -> Result<(), Failure> {
    let mut arguments = arguments.into_iter();
    let command = arguments.next().ok_or(Failure::Usage)?;
    match command.to_str() {
        Some("keygen") => keygen(&mut arguments),
        Some("provision-bootstrap") => provision_bootstrap(&mut arguments),
        Some("provision-profile") => provision_profile(&mut arguments),
        Some("serve-vault") => {
            let stop = WindowsStopEvent::create().map_err(|_| Failure::Unavailable)?;
            let result = serve_vault(&mut arguments, &stop, || Ok(()));
            let cleanup = stop.close().map_err(|_| Failure::Unavailable);
            result.and(cleanup)
        }
        Some("service") => service_dispatch(arguments.collect()),
        Some("probe") => probe(&mut arguments),
        Some("human-lock") => human_lock(&mut arguments),
        Some("tui") => crate::tui::run(&mut arguments),
        _ => Err(Failure::Usage),
    }
}

fn service_dispatch(arguments: Vec<OsString>) -> Result<(), Failure> {
    SERVICE_FAILED.store(false, Ordering::Release);
    SERVICE_MEMORY_QUOTA_FAILED.store(false, Ordering::Release);
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
    if SERVICE_FAILED.load(Ordering::Acquire) {
        Err(Failure::Unavailable)
    } else {
        Ok(())
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let mut name = "PasswordManager"
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let stop = match WindowsStopEvent::create() {
        Ok(stop) => stop,
        Err(_) => {
            SERVICE_FAILED.store(true, Ordering::Release);
            return;
        }
    };
    let mut context = Box::new(ServiceControlContext {
        stop,
        status_handle: std::ptr::null_mut(),
        state: AtomicU32::new(SERVICE_START_PENDING),
    });
    let status_handle = unsafe {
        RegisterServiceCtrlHandlerExW(
            name.as_mut_ptr(),
            Some(service_control),
            (&raw mut *context).cast(),
        )
    };
    if status_handle.is_null() {
        SERVICE_FAILED.store(true, Ordering::Release);
        return;
    }
    context.status_handle = status_handle;
    if context.publish(SERVICE_START_PENDING, 0, 0).is_err() {
        SERVICE_FAILED.store(true, Ordering::Release);
        return;
    }
    let result = SERVICE_ARGUMENTS
        .get()
        .cloned()
        .ok_or(Failure::Unavailable)
        .and_then(|arguments| {
            serve_vault(&mut arguments.into_iter(), &context.stop, || {
                context.publish(SERVICE_RUNNING, SERVICE_ACCEPT_STOP, 0)
            })
        });
    let exit_code = if SERVICE_MEMORY_QUOTA_FAILED.load(Ordering::Acquire) {
        windows_sys::Win32::Foundation::ERROR_NOT_ENOUGH_QUOTA
    } else {
        u32::from(result.is_err() || SERVICE_FAILED.load(Ordering::Acquire))
    };
    let stopped = context.publish(SERVICE_STOPPED, 0, exit_code);
    let ServiceControlContext { stop, .. } = *context;
    let closed = stop.close().map_err(|_| Failure::Unavailable);
    if result.is_err() || stopped.is_err() || closed.is_err() {
        SERVICE_FAILED.store(true, Ordering::Release);
    }
}

unsafe extern "system" fn service_control(
    control: u32,
    _event_type: u32,
    _event_data: *mut core::ffi::c_void,
    context: *mut core::ffi::c_void,
) -> u32 {
    if context.is_null() {
        return 120;
    }
    let context = unsafe { &*context.cast::<ServiceControlContext>() };
    match control {
        SERVICE_CONTROL_STOP => {
            if context.state.load(Ordering::Acquire) != SERVICE_RUNNING {
                return ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
            }
            let pending = context.publish(SERVICE_STOP_PENDING, 0, 0);
            let signalled = context.stop.signal().map_err(|_| Failure::Unavailable);
            if pending.and(signalled).is_err() {
                SERVICE_FAILED.store(true, Ordering::Release);
                ERROR_GEN_FAILURE
            } else {
                0
            }
        }
        SERVICE_CONTROL_INTERROGATE => 0,
        _ => 120,
    }
}

fn publish_service_status(
    handle: SERVICE_STATUS_HANDLE,
    state: u32,
    controls: u32,
    exit_code: u32,
) -> Result<(), Failure> {
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: controls,
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: u32::from(state == SERVICE_STOP_PENDING),
        dwWaitHint: 0,
    };
    if unsafe { SetServiceStatus(handle, &raw const status) } == 0 {
        Err(Failure::Unavailable)
    } else {
        Ok(())
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

fn serve_vault(
    arguments: &mut impl Iterator<Item = OsString>,
    stop: &WindowsStopEvent,
    ready: impl FnOnce() -> Result<(), Failure>,
) -> Result<(), Failure> {
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
        // Establish the quota before DPAPI/bootstrap/audit can place a secret.
        if let Err(error) = pm_crypto::prepare_windows_protected_memory() {
            SERVICE_MEMORY_QUOTA_FAILED.store(true, Ordering::Release);
            eprintln!("PROTECTED_MEMORY_QUOTA_UNAVAILABLE");
            if let Some(diagnostics) = diagnostics.as_ref() {
                diagnostics.memory_quota_failure(error)?;
            }
            return Err(Failure::Unavailable);
        }
        if let Some(diagnostics) = diagnostics.as_ref() {
            diagnostics.memory(None)?;
        }
        let bootstrap = Arc::new(read_bootstrap(&bootstrap_path)?);
        if let Some(diagnostics) = diagnostics.as_ref() {
            diagnostics.record(ServiceDiagnosticPhase::BootstrapOk)?;
        }
        let audit_path = PathBuf::from(format!("{}.audit-custody", vault_path.display()));
        let audit_custody = Arc::new(load_or_create_audit_custody(
            &audit_path,
            &vault_path,
            device,
        )?);
        if let Some(diagnostics) = diagnostics.as_ref() {
            diagnostics.record(ServiceDiagnosticPhase::AuditOk)?;
        }
        let sync_jobs = crate::sync_job::Manager::open(&vault_path)?;
        sync_jobs.resume()?;
        let service = Arc::new(VaultService {
            admission: Arc::new(crate::custody_admission::CustodyAdmission::load(
                &bootstrap_path,
                &audit_path,
                bootstrap_custody_fingerprint,
                audit_custody_fingerprint,
            )?),
            path: vault_path,
            device,
            audit_custody,
            diagnostics: diagnostics.clone(),
            sync_jobs,
        });
        let agent_role = prepare_role(Role::Agent, &vault_id, &bootstrap, &service, stop)?;
        let human_role = prepare_role(Role::Human, &vault_id, &bootstrap, &service, stop)?;
        let agent_stop = stop.clone();
        let agent_service = Arc::clone(&service);
        let agent_vault_id = vault_id.clone();
        let agent = std::thread::Builder::new()
            .name("pm-agent-pipe".to_owned())
            .spawn(move || {
                serve_role_and_signal(agent_role, &agent_vault_id, &agent_service, &agent_stop)
            })
            .map_err(|_| Failure::Unavailable)?;
        let human_stop = stop.clone();
        let human_service = Arc::clone(&service);
        let human_vault_id = vault_id.clone();
        let human = match std::thread::Builder::new()
            .name("pm-human-pipe".to_owned())
            .spawn(move || {
                serve_role_and_signal(human_role, &human_vault_id, &human_service, &human_stop)
            }) {
            Ok(human) => human,
            Err(_) => {
                let signalled = stop.signal().map_err(|_| Failure::Unavailable);
                let joined = agent.join().map_err(|_| Failure::Unavailable);
                signalled?;
                joined??;
                return Err(Failure::Unavailable);
            }
        };
        let readiness = ready();
        let signal_result = if readiness.is_err() {
            stop.signal().map_err(|_| Failure::Unavailable)
        } else {
            Ok(())
        };
        let agent_result = agent.join();
        let human_result = human.join();
        readiness?;
        signal_result?;
        agent_result.map_err(|_| Failure::Unavailable)??;
        human_result.map_err(|_| Failure::Unavailable)??;
        if stop.is_signalled().map_err(|_| Failure::Unavailable)? {
            Ok(())
        } else {
            Err(Failure::Unavailable)
        }
    })();
    if result.is_err() {
        if let Some(diagnostics) = diagnostics.as_ref() {
            if let Some(failure) =
                pm_crypto::windows_memory_failure().map_err(|_| Failure::Unavailable)?
            {
                diagnostics.memory(Some(failure))?;
            }
            diagnostics.record(ServiceDiagnosticPhase::ServiceFailed)?;
        }
    }
    result
}

fn prepare_role(
    role: Role,
    vault_id: &str,
    bootstrap: &Bootstrap,
    service: &VaultService,
    stop: &WindowsStopEvent,
) -> Result<PreparedRole, Failure> {
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
    let pipe = create_role_pipe(
        role,
        vault_id,
        &bootstrap.service_sid,
        client_sid,
        stop,
        true,
    )?;
    if let Some(diagnostics) = service.diagnostics.as_ref() {
        diagnostics.record(match role {
            Role::Agent => ServiceDiagnosticPhase::AgentPipeOk,
            Role::Human => ServiceDiagnosticPhase::HumanPipeOk,
        })?;
    }
    Ok(PreparedRole {
        role,
        pipe,
        config,
        peer_rpk: client_spki.clone(),
        service_sid: bootstrap.service_sid.clone(),
        client_sid: client_sid.to_owned(),
    })
}

fn serve_role_and_signal(
    prepared: PreparedRole,
    vault_id: &str,
    service: &VaultService,
    stop: &WindowsStopEvent,
) -> Result<(), Failure> {
    let result = serve_role(prepared, vault_id, service, stop);
    if result.is_err() {
        let signalled = stop.signal().map_err(|_| Failure::Unavailable);
        return result.and(signalled);
    }
    result
}

fn serve_role(
    prepared: PreparedRole,
    vault_id: &str,
    service: &VaultService,
    stop: &WindowsStopEvent,
) -> Result<(), Failure> {
    let PreparedRole {
        role,
        pipe,
        config,
        peer_rpk,
        service_sid,
        client_sid,
    } = prepared;
    let mut next_pipe = Some(pipe);
    let mut connections = crate::connection_dispatch::AgentConnections::new();
    let result: Result<(), Failure> = (|| {
        loop {
            let mut pipe = next_pipe.take().ok_or(Failure::Unavailable)?;
            if role == Role::Agent {
                connections.reap()?;
                // Accept and verify the kernel SID before handing off TLS.
                let accepted = pipe.accept().is_ok();
                if stop.is_signalled().map_err(|_| Failure::Unavailable)? {
                    drop(pipe);
                    return Ok(());
                }
                // Keep an acceptor alive even after rejected native admission.
                // Two transient acceptor handles coexist while replacing an instance;
                // neither is a TLS/domain worker and both share the fixed DACL.
                next_pipe = Some(create_role_pipe(
                    role,
                    vault_id,
                    &service_sid,
                    &client_sid,
                    stop,
                    false,
                )?);
                if accepted && service.admission.verify().is_ok() {
                    let config = Arc::clone(&config);
                    let service = service.clone();
                    let peer_rpk = peer_rpk.clone();
                    connections.dispatch(move || {
                        // The existing connection-error disposition is preserved.
                        let _ = handle_server_connection(pipe, role, &config, &service, &peer_rpk);
                    })?;
                }
            } else {
                let _ = handle_server_connection(pipe, role, &config, service, &peer_rpk);
            }
            if stop.is_signalled().map_err(|_| Failure::Unavailable)? {
                return Ok(());
            }
            if next_pipe.is_none() {
                next_pipe = Some(create_role_pipe(
                    role,
                    vault_id,
                    &service_sid,
                    &client_sid,
                    stop,
                    true,
                )?);
            }
        }
    })();
    let signalled = if result.is_err() {
        stop.signal().map_err(|_| Failure::Unavailable)
    } else {
        Ok(())
    };
    let joined = connections.finish();
    let mut failure = result.err();
    for error in [signalled.err(), joined.err()].into_iter().flatten() {
        failure = Some(match failure {
            Some(previous) => previous.merge(error),
            None => error,
        });
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn create_role_pipe(
    role: Role,
    vault_id: &str,
    service_sid: &str,
    client_sid: &str,
    stop: &WindowsStopEvent,
    first: bool,
) -> Result<WindowsServerPipe, Failure> {
    match role {
        Role::Agent => WindowsServerPipe::create_agent_instance(
            vault_id,
            service_sid,
            client_sid,
            stop,
            first,
            u32::try_from(crate::connection_dispatch::MAX_AGENT_CONNECTIONS + 2)
                .map_err(|_| Failure::Unavailable)?,
        ),
        Role::Human => {
            WindowsServerPipe::create(role.endpoint(), vault_id, service_sid, client_sid, stop)
        }
    }
    .map_err(|_| Failure::Unavailable)
}

fn handle_server_connection(
    pipe: WindowsServerPipe,
    role: Role,
    config: &Arc<ServerConfig>,
    service: &VaultService,
    peer_rpk: &[u8],
) -> Result<(), Failure> {
    let (tls_pipe, human_channel, human_transfer) = if role == Role::Human {
        let channel = AuthenticatedHumanChannel::authenticate_windows(pipe)
            .map_err(|_| Failure::Unavailable)?;
        let tls_pipe = channel
            .try_clone_windows_pipe()
            .map_err(|_| Failure::Unavailable)?;
        let transfer_pipe = channel
            .try_clone_windows_pipe()
            .map_err(|_| Failure::Unavailable)?;
        if let Some(diagnostics) = service.diagnostics.as_ref() {
            diagnostics.record(ServiceDiagnosticPhase::HumanAccepted)?;
        }
        (tls_pipe, Some(channel), Some(transfer_pipe))
    } else {
        // Agent accept/authentication already happened in the native acceptor.
        pipe.verify().map_err(|_| Failure::Unavailable)?;
        let tls_pipe = pipe.try_clone().map_err(|_| Failure::Unavailable)?;
        (tls_pipe, None, None)
    };
    // Both native roles verify W3 custody before TLS/domain admission; the
    // agent acceptor also checks before reserving a bounded worker.
    service.admission.verify()?;
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
                admission: &service.admission,
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
                human_transfer.ok_or(Failure::Unavailable)?,
            )
        }
        _ => Err(Failure::Unavailable),
    }
}

fn serve_human(
    tls: &mut impl ReadWrite,
    service: &VaultService,
    channel: AuthenticatedHumanChannel,
    transfer_pipe: WindowsServerPipe,
) -> Result<(), Failure> {
    let request = read_frame(tls)?;
    let mut cursor = Cursor::new(&request);
    cursor.expect(&[1])?;
    let password = cursor.bytes()?;
    cursor.finish()?;
    if let Some(diagnostics) = service.diagnostics.as_ref() {
        diagnostics.record(ServiceDiagnosticPhase::HumanUnlockRequest)?;
    }
    let vault_result = HumanVault::unlock(
        &service.path,
        &password,
        service.device,
        channel,
        Arc::clone(&service.audit_custody),
    );
    let mut vault = match vault_result {
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
    loop {
        let request = read_frame(tls)?;
        if request.as_ref() == [14] {
            break;
        }
        let (&opcode, rest) = request.split_first().ok_or(Failure::Unavailable)?;
        match opcode {
            31 => {
                write_frame(tls, &[0])?;
                if let Some(diagnostics) = service.diagnostics.as_ref() {
                    diagnostics.record(ServiceDiagnosticPhase::TransferAck)?;
                }
                let token = read_frame(tls)?;
                let source_value = u64::from_be_bytes(
                    token
                        .as_ref()
                        .try_into()
                        .map_err(|_| Failure::Unavailable)?,
                );
                if let Some(diagnostics) = service.diagnostics.as_ref() {
                    diagnostics.record(ServiceDiagnosticPhase::TransferToken)?;
                }
                let duplicated = transfer_pipe
                    .duplicate_client_file(source_value, 1024_u64.pow(4) + 256 * 1024 * 1024);
                if let Some(diagnostics) = service.diagnostics.as_ref() {
                    diagnostics.record(if duplicated.is_ok() {
                        ServiceDiagnosticPhase::TransferDuplicated
                    } else {
                        ServiceDiagnosticPhase::TransferDuplicateFailed
                    })?;
                }
                let source = duplicated.map_err(|_| Failure::Unavailable)?;
                let preview = crate::human_wire::handle_1pux_file(
                    &mut vault,
                    tls,
                    rest,
                    source,
                    |stage, error| match service.diagnostics.as_ref() {
                        Some(diagnostics) => diagnostics.record_1pux_result(stage, error),
                        None => Ok(()),
                    },
                );
                let diagnostic = if let Some(diagnostics) = service.diagnostics.as_ref() {
                    diagnostics
                        .memory(
                            pm_crypto::windows_memory_failure()
                                .map_err(|_| Failure::Unavailable)?,
                        )
                        .and_then(|()| {
                            diagnostics.record(if preview.is_ok() {
                                ServiceDiagnosticPhase::TransferPreviewSent
                            } else {
                                ServiceDiagnosticPhase::TransferPreviewFailed
                            })
                        })
                } else {
                    Ok(())
                };
                match (preview, diagnostic) {
                    (Ok(()), Ok(())) => {}
                    (Err(error), Ok(())) | (Ok(()), Err(error)) => return Err(error),
                    (Err(error), Err(diagnostic)) => return Err(error.merge(diagnostic)),
                }
                continue;
            }
            17 => {
                crate::human_wire::handle_stream_upload(&mut vault, tls, rest)?;
                continue;
            }
            18 | 62 => {
                crate::human_wire::handle_stream_download(&vault, tls, rest)?;
                continue;
            }
            32 if rest.is_empty() => {
                crate::human_wire::handle_native_backup_download(&mut vault, tls)?;
                continue;
            }
            33 if rest.first() == Some(&1) => {
                crate::human_wire::handle_plaintext_backup_download(&mut vault, tls, &rest[1..])?;
                continue;
            }
            34 => {
                crate::human_wire::handle_native_backup_restore(&mut vault, tls, rest)?;
                continue;
            }
            42 => {
                crate::human_wire::handle_native_recovery(&mut vault, tls, rest)?;
                continue;
            }
            44 => {
                crate::human_wire::handle_recovery_rotation(&mut vault, tls, rest)?;
                continue;
            }
            _ => {}
        }
        let response = crate::human_wire::handle_request_slice(
            &mut vault,
            &service.path,
            service.device,
            &service.audit_custody,
            opcode,
            rest,
        )
        .or_else(|| {
            handle_sync_request(&mut vault, service, opcode, rest)
                .map(|result| result.map(HumanResponse::Public))
        })
        .ok_or(Failure::Unavailable)??;
        write_frame(tls, response.as_ref())?;
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

fn handle_sync_request(
    vault: &mut HumanVault,
    service: &VaultService,
    opcode: u8,
    request: &[u8],
) -> Option<Result<Vec<u8>, Failure>> {
    if !matches!(opcode, 63 | 66) {
        return None;
    }
    Some((|| match opcode {
        63 => {
            let _preparing = pm_sync::timing::Span::new("sync_submit_prepare");
            let mut cursor = Cursor::new(request);
            let protected = protected_copy(cursor.bytes()?)?;
            let program = PathBuf::from(cursor.public_string()?);
            let socket = PathBuf::from(cursor.public_string()?);
            let client_key = PathBuf::from(cursor.public_string()?);
            let server_public = PathBuf::from(cursor.public_string()?);
            let pin = cursor
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
        66 => {
            let job = request.try_into().map_err(|_| Failure::Unavailable)?;
            let status = service.sync_jobs.status(job)?;
            let mut response = vec![0, status.phase.byte()];
            response.extend_from_slice(&status.pushed.to_be_bytes());
            response.extend_from_slice(&status.pulled.to_be_bytes());
            Ok(response)
        }
        _ => unreachable!("closed sync opcode set checked above"),
    })())
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
    let mut input = NativeStdin::open().map_err(|_| Failure::Unavailable)?;
    let mut password = ProtectedBytes::zeroed(1025).map_err(|_| Failure::Unavailable)?;
    let mut used = 0;
    while used < password.len() {
        let count = input
            .read(&mut password[used..])
            .map_err(|_| Failure::Unavailable)?;
        if count == 0 {
            break;
        }
        used += count;
    }
    password.truncate(used);
    while password
        .last()
        .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
    {
        password.truncate(password.len() - 1);
    }
    if password.is_empty() || password.len() > 1024 {
        return Err(Failure::Unavailable);
    }
    let mut tls = connect(&profile, &key, &vault_id)?;
    tls.write_all(HUMAN_MAGIC)
        .map_err(|_| Failure::Unavailable)?;
    let unlock = protected_fields_frame(&[1], &[&password])?;
    write_frame(&mut tls, &unlock)?;
    if read_frame(&mut tls)?.as_ref() != [0] {
        return Err(Failure::Unavailable);
    }
    write_frame(&mut tls, &[14])?;
    if read_frame(&mut tls)?.as_ref() != [0] {
        return Err(Failure::Unavailable);
    }
    println!("PASS windows-human-unlock-lock");
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) struct WireHistoryEntry {
    pub(super) revision_id: [u8; 16],
    pub(super) visible: bool,
    pub(super) attachment_count: u32,
}

pub(super) struct WireHistory {
    pub(super) lifecycle: u8,
    pub(super) entries: Vec<WireHistoryEntry>,
}

pub(super) struct WirePurge {
    pub(super) terminal: bool,
    pub(super) revision_ids: Vec<[u8; 16]>,
    pub(super) attachment_count: u32,
    pub(super) encrypted_bytes: u64,
    pub(super) prepared: WirePrepared,
}

pub(super) fn decode_prepared_response(response: &[u8]) -> Result<WirePrepared, Failure> {
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
    let command = protected_copy(cursor.bytes()?)?;
    let body = protected_copy(cursor.bytes()?)?;
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
) -> Result<ProtectedBytes, Failure> {
    let body_len = encoded_bytes_len(body)?;
    let encoded_len = 1_usize
        .checked_add(encoded_bytes_len(&prepared.command)?)
        .and_then(|value| value.checked_add(64))
        .and_then(|value| value.checked_add(body_len))
        .ok_or(Failure::Unavailable)?;
    let mut request = ProtectedFrameWriter::new(encoded_len)?;
    request.fixed(&[opcode])?;
    request.bytes(&prepared.command)?;
    request.fixed(&prepared.signature)?;
    request.bytes(body)?;
    request.finish_exact()
}

fn expect_success_payload(response: &[u8]) -> Result<ProtectedBytes, Failure> {
    if response.first() != Some(&0) || response.len() < 2 {
        return Err(Failure::Unavailable);
    }
    protected_copy(&response[1..])
}

pub(super) fn rpc_commit(
    tls: &mut rustls::StreamOwned<ClientConnection, WindowsClientPipe>,
    prepared: &WirePrepared,
) -> Result<ProtectedBytes, Failure> {
    write_frame(tls, &encode_commit_request(5, prepared, &prepared.body)?)?;
    let response = read_frame(tls)?;
    expect_success_payload(&response)
}

pub(super) fn rpc_unlock(
    tls: &mut rustls::StreamOwned<ClientConnection, WindowsClientPipe>,
    password: &[u8],
) -> Result<(), Failure> {
    let request = protected_fields_frame(&[1], &[password])?;
    write_frame(tls, &request)?;
    if read_frame(tls)?.as_ref() == [0] {
        Ok(())
    } else {
        Err(Failure::Unavailable)
    }
}

pub(super) fn rpc_prepare_restore(
    tls: &mut rustls::StreamOwned<ClientConnection, WindowsClientPipe>,
    item: [u8; 16],
    revision: [u8; 16],
) -> Result<WirePrepared, Failure> {
    let mut request = vec![26];
    request.extend_from_slice(&item);
    request.extend_from_slice(&revision);
    write_frame(tls, &request)?;
    decode_prepared_response(&read_frame(tls)?)
}

pub(super) fn rpc_history(
    tls: &mut rustls::StreamOwned<ClientConnection, WindowsClientPipe>,
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

pub(super) fn rpc_prepare_purge_revisions(
    tls: &mut rustls::StreamOwned<ClientConnection, WindowsClientPipe>,
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

pub(super) fn rpc_prepare_purge_item(
    tls: &mut rustls::StreamOwned<ClientConnection, WindowsClientPipe>,
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
        command: protected_copy(cursor.bytes()?)?,
        body: protected_copy(cursor.bytes()?)?,
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

fn decode_prepared_from_cursor(cursor: &mut Cursor<'_>) -> Result<WirePrepared, Failure> {
    Ok(WirePrepared {
        transaction_id: cursor
            .fixed(16)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
        item_id: cursor
            .fixed(16)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
        command: protected_copy(cursor.bytes()?)?,
        body: protected_copy(cursor.bytes()?)?,
        signature: cursor
            .fixed(64)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
    })
}

pub(super) fn rpc_download_atomic(
    tls: &mut rustls::StreamOwned<ClientConnection, WindowsClientPipe>,
    request: &[u8],
    destination: &Path,
) -> Result<u64, Failure> {
    let temporary = destination.with_extension("partial");
    let mut output = pm_native_channel::create_private_file(&temporary, false, true)
        .map_err(|_| Failure::Unavailable)?;
    let result = (|| {
        write_frame(tls, request)?;
        if read_frame(tls)?.as_ref() != [0] {
            return Err(Failure::Unavailable);
        }
        let mut written = 0_u64;
        loop {
            let frame = read_frame(tls)?;
            if frame.as_ref() == [0] {
                break;
            }
            if frame.len() > STREAM_CHUNK_BYTES + 64 {
                return Err(Failure::Unavailable);
            }
            written = written
                .checked_add(u64::try_from(frame.len()).map_err(|_| Failure::Unavailable)?)
                .ok_or(Failure::Unavailable)?;
            output.write_all(&frame).map_err(|_| Failure::Unavailable)?;
        }
        output.sync_all().map_err(|_| Failure::Unavailable)?;
        Ok(written)
    })();
    let written = match result {
        Ok(written) => written,
        Err(error) => {
            return Err(error.after_owned_path_cleanup(fs::remove_file(&temporary)));
        }
    };
    drop(output);
    if let Err(error) = pm_vault::publish_new_file(&temporary, destination) {
        let failure = if error.kind() == std::io::ErrorKind::AlreadyExists {
            Failure::DestinationExists
        } else {
            Failure::Unavailable
        };
        return Err(failure.after_owned_path_cleanup(fs::remove_file(&temporary)));
    }
    pm_native_channel::sync_directory(destination.parent().ok_or(Failure::Unavailable)?)
        .map_err(|_| Failure::Unavailable)?;
    Ok(written)
}

pub(super) fn read_import_source(path: &Path) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let mut file = pm_native_channel::open_regular_file(path).map_err(|_| Failure::Unavailable)?;
    let before = file.metadata().map_err(|_| Failure::Unavailable)?;
    if before.len() == 0 || before.len() > (MAX_FRAME - 16) as u64 {
        return Err(Failure::Unavailable);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(before.len()).map_err(|_| Failure::Unavailable)?,
    ));
    file.read_to_end(&mut bytes)
        .map_err(|_| Failure::Unavailable)?;
    let after = file.metadata().map_err(|_| Failure::Unavailable)?;
    let before_modified = before.modified().map_err(|_| Failure::Unavailable)?;
    let after_modified = after.modified().map_err(|_| Failure::Unavailable)?;
    if u64::try_from(bytes.len()).ok() != Some(before.len())
        || before.len() != after.len()
        || before_modified != after_modified
    {
        return Err(Failure::Unavailable);
    }
    Ok(bytes)
}

pub(super) fn open_1pux_source(path: &Path) -> Result<File, Failure> {
    let file = pm_native_channel::open_regular_file(path).map_err(|_| Failure::Unavailable)?;
    pm_native_channel::validate_transfer_file(&file, 1024_u64.pow(4) + 256 * 1024 * 1024)
        .map_err(|_| Failure::Unavailable)?;
    Ok(file)
}

pub(super) fn send_file_handle(
    tls: &mut rustls::StreamOwned<ClientConnection, WindowsClientPipe>,
    source: &File,
) -> Result<(), Failure> {
    use std::os::windows::io::AsRawHandle;

    tls.sock.verify().map_err(|_| Failure::Unavailable)?;
    let value = source.as_raw_handle() as usize as u64;
    if value == 0 || value == usize::MAX as u64 {
        return Err(Failure::Unavailable);
    }
    write_frame(tls, &value.to_be_bytes())?;
    tls.sock.verify().map_err(|_| Failure::Unavailable)
}

pub(super) fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

pub(super) fn connect_tui(
    profile: &Profile,
    key: &KeyMaterial,
    vault: &Path,
) -> Result<rustls::StreamOwned<ClientConnection, WindowsClientPipe>, Failure> {
    connect(profile, key, vault.to_str().ok_or(Failure::Unavailable)?)
}

pub fn agent_rpc(
    profile_path: &Path,
    private_path: &Path,
    vault: &Path,
    request: Option<&[u8]>,
) -> Result<ProtectedBytes, String> {
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

pub(super) fn connect(
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

pub(super) fn read_key(path: &Path) -> Result<KeyMaterial, Failure> {
    let encoded = read_protected(path)?;
    let mut cursor = Cursor::new(&encoded);
    cursor.expect(KEY_MAGIC)?;
    let private = protected_copy(cursor.bytes()?)?;
    let spki = cursor.fixed(SPKI_BYTES)?.to_vec();
    cursor.finish()?;
    validate_spki(&spki)?;
    Ok(KeyMaterial { private, spki })
}

fn read_bootstrap(path: &Path) -> Result<Bootstrap, Failure> {
    let encoded = read_protected(path)?;
    let mut cursor = Cursor::new(&encoded);
    cursor.expect(BOOTSTRAP_MAGIC)?;
    let private = protected_copy(cursor.bytes()?)?;
    let server_spki = cursor.fixed(SPKI_BYTES)?.to_vec();
    let service_sid = cursor.public_string()?;
    let agent_sid = cursor.public_string()?;
    let agent_spki = cursor.fixed(SPKI_BYTES)?.to_vec();
    let human_sid = cursor.public_string()?;
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

pub(super) fn read_profile(path: &Path) -> Result<Profile, Failure> {
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

fn read_protected(path: &Path) -> Result<ProtectedBytes, Failure> {
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

fn bootstrap_custody_fingerprint(path: &Path) -> Result<[u8; 32], Failure> {
    let bootstrap = read_bootstrap(path)?;
    crate::custody_admission::fingerprint_parts(&[
        &bootstrap.server.private,
        &bootstrap.server.spki,
        bootstrap.service_sid.as_bytes(),
        bootstrap.agent_sid.as_bytes(),
        &bootstrap.agent_spki,
        bootstrap.human_sid.as_bytes(),
        &bootstrap.human_spki,
    ])
}

fn audit_custody_fingerprint(path: &Path) -> Result<[u8; 32], Failure> {
    let bytes = read_protected(path)?;
    AuditDeviceCustody::from_protected_bytes(&bytes).map_err(|_| Failure::Unavailable)?;
    Ok(pm_crypto::digest(&bytes))
}

fn load_or_create_audit_custody(
    path: &Path,
    vault_path: &Path,
    device: [u8; 16],
) -> Result<AuditDeviceCustody, Failure> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            let bytes = read_protected(path)?;
            return AuditDeviceCustody::from_protected_bytes(&bytes)
                .map_err(|_| Failure::Unavailable);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(Failure::Unavailable),
    }
    if crate::human_wire::audit_device_initialized(vault_path, device)? {
        return Err(Failure::Unavailable);
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

pub(super) fn push_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), Failure> {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| Failure::Unavailable)?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}

pub(super) fn finish_arguments(
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<(), Failure> {
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
