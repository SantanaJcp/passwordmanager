// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(windows)]
use std::io::Write;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
#[cfg(unix)]
use std::{
    fs::OpenOptions,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};

use pm_crypto::{SyncPairing, random_id};
use pm_sync::{ProcessTlsTransport, SyncError, SyncReplica};
use zeroize::{Zeroize, Zeroizing};

use crate::Failure;

const CONFIG_MAGIC: &[u8; 5] = b"PMSJ1";
const STATUS_MAGIC: &[u8; 5] = b"PMSS1";
const MAX_CONFIG: u64 = 32 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Phase {
    Queued = 1,
    Pushing = 2,
    Pulling = 3,
    Succeeded = 4,
    Unavailable = 5,
    Integrity = 6,
    Backpressure = 7,
    JournalFailure = 8,
    Rejected = 9,
}

impl Phase {
    fn parse(value: u8) -> Result<Self, Failure> {
        match value {
            1 => Ok(Self::Queued),
            2 => Ok(Self::Pushing),
            3 => Ok(Self::Pulling),
            4 => Ok(Self::Succeeded),
            5 => Ok(Self::Unavailable),
            6 => Ok(Self::Integrity),
            7 => Ok(Self::Backpressure),
            8 => Ok(Self::JournalFailure),
            9 => Ok(Self::Rejected),
            _ => Err(Failure::Unavailable),
        }
    }

    pub(super) const fn byte(self) -> u8 {
        self as u8
    }

    const fn terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Unavailable
                | Self::Integrity
                | Self::Backpressure
                | Self::JournalFailure
                | Self::Rejected
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Status {
    pub id: [u8; 16],
    pub phase: Phase,
    pub pushed: u64,
    pub pulled: u64,
}

struct Runtime {
    status: Option<Status>,
    active: bool,
}

pub(super) struct Manager {
    vault: PathBuf,
    config_path: PathBuf,
    status_path: PathBuf,
    runtime: Mutex<Runtime>,
}

struct Config {
    id: [u8; 16],
    protected: Zeroizing<Vec<u8>>,
    program: PathBuf,
    socket: PathBuf,
    client_key: PathBuf,
    server_public: PathBuf,
    pin: [u8; 44],
}

impl Manager {
    pub(super) fn open(vault: &Path) -> Result<Arc<Self>, Failure> {
        let config_path = PathBuf::from(format!("{}.sync-job", vault.display()));
        let status_path = PathBuf::from(format!("{}.sync-status", vault.display()));
        let status = if status_path.exists() {
            Some(decode_status(&read_private(&status_path, 128)?)?)
        } else {
            None
        };
        Ok(Arc::new(Self {
            vault: vault.to_owned(),
            config_path,
            status_path,
            runtime: Mutex::new(Runtime {
                status,
                active: false,
            }),
        }))
    }

    pub(super) fn resume(self: &Arc<Self>) -> Result<(), Failure> {
        if !self.config_path.exists() {
            return Ok(());
        }
        let terminal = self
            .runtime
            .lock()
            .map_err(|_| Failure::Unavailable)?
            .status
            .filter(|status| status.phase.terminal());
        if let Some(status) = terminal {
            if fs::remove_file(&self.config_path).is_err()
                || sync_parent(&self.config_path).is_err()
            {
                self.record_journal_failure(status.id);
            }
            return Ok(());
        }
        let config = decode_config(&read_private(&self.config_path, MAX_CONFIG)?)?;
        self.launch(config, true)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn start(
        self: &Arc<Self>,
        pairing: &SyncPairing,
        program: PathBuf,
        socket: PathBuf,
        client_key: PathBuf,
        server_public: PathBuf,
        pin: [u8; 44],
    ) -> Result<[u8; 16], Failure> {
        {
            let runtime = self.runtime.lock().map_err(|_| Failure::Unavailable)?;
            if runtime.active || self.config_path.exists() {
                return Err(Failure::Unavailable);
            }
        }
        let config = Config {
            id: random_id().map_err(|_| Failure::Unavailable)?,
            protected: Zeroizing::new(pairing.to_protected_bytes()),
            program,
            socket,
            client_key,
            server_public,
            pin,
        };
        let bytes = Zeroizing::new(encode_config(&config)?);
        write_private(&self.config_path, &bytes)?;
        let id = config.id;
        if let Err(error) = self.launch(config, false) {
            fs::remove_file(&self.config_path).map_err(|_| Failure::Unavailable)?;
            return Err(error);
        }
        Ok(id)
    }

    pub(super) fn status(&self, id: [u8; 16]) -> Result<Status, Failure> {
        let runtime = self.runtime.lock().map_err(|_| Failure::Unavailable)?;
        runtime
            .status
            .filter(|status| status.id == id)
            .ok_or(Failure::Unavailable)
    }

    fn launch(self: &Arc<Self>, config: Config, recovering: bool) -> Result<(), Failure> {
        let queued = Status {
            id: config.id,
            phase: Phase::Queued,
            pushed: 0,
            pulled: 0,
        };
        {
            let mut runtime = self.runtime.lock().map_err(|_| Failure::Unavailable)?;
            if runtime.active {
                return Err(Failure::Unavailable);
            }
            if recovering && runtime.status.is_some_and(|status| status.phase.terminal()) {
                return Err(Failure::Unavailable);
            }
            persist_status(&self.status_path, queued)?;
            runtime.status = Some(queued);
            runtime.active = true;
        }
        let manager = Arc::clone(self);
        std::thread::spawn(move || manager.run(config));
        Ok(())
    }

    fn run(self: Arc<Self>, mut config: Config) {
        let result = self.run_inner(&config);
        config.protected.zeroize();
        let status = match result {
            Ok((pushed, pulled)) => Status {
                id: config.id,
                phase: Phase::Succeeded,
                pushed,
                pulled,
            },
            Err(WorkerError::Sync(error)) => Status {
                id: config.id,
                phase: phase_for_error(&error),
                pushed: 0,
                pulled: 0,
            },
            Err(WorkerError::Journal) => Status {
                id: config.id,
                phase: Phase::JournalFailure,
                pushed: 0,
                pulled: 0,
            },
        };
        if persist_status(&self.status_path, status).is_err() {
            self.record_journal_failure(config.id);
            return;
        }
        if fs::remove_file(&self.config_path).is_err() || sync_parent(&self.config_path).is_err() {
            self.record_journal_failure(config.id);
            return;
        }
        if let Ok(mut runtime) = self.runtime.lock() {
            runtime.status = Some(status);
            runtime.active = false;
        }
    }

    fn run_inner(&self, config: &Config) -> Result<(u64, u64), WorkerError> {
        validate_program(&config.program).map_err(WorkerError::Sync)?;
        let trusted = pm_vault::open_vault_identity(&self.vault)
            .map_err(|_| WorkerError::Sync(SyncError::Integrity))?;
        let pairing = SyncPairing::from_protected_bytes(&config.protected, trusted.trusted_root())
            .map_err(|_| WorkerError::Sync(SyncError::Integrity))?;
        if pairing.server_pin() != &config.pin {
            return Err(WorkerError::Sync(SyncError::Unauthorized));
        }
        let transport = ProcessTlsTransport::new(
            &config.program,
            &config.socket,
            &config.client_key,
            &config.server_public,
        );
        let mut replica = SyncReplica::new(&self.vault, pairing, [0; 44], config.pin)
            .map_err(WorkerError::Sync)?;
        self.advance(config.id, Phase::Pushing, 0, 0)
            .map_err(|()| WorkerError::Journal)?;
        let pushed = replica.push(&transport).map_err(WorkerError::Sync)?;
        self.advance(
            config.id,
            Phase::Pulling,
            u64::try_from(pushed).map_err(|_| WorkerError::Sync(SyncError::Integrity))?,
            0,
        )
        .map_err(|()| WorkerError::Journal)?;
        let pulled = replica.pull(&transport).map_err(WorkerError::Sync)?;
        Ok((
            u64::try_from(pushed).map_err(|_| WorkerError::Sync(SyncError::Integrity))?,
            u64::try_from(pulled).map_err(|_| WorkerError::Sync(SyncError::Integrity))?,
        ))
    }

    fn advance(&self, id: [u8; 16], phase: Phase, pushed: u64, pulled: u64) -> Result<(), ()> {
        let status = Status {
            id,
            phase,
            pushed,
            pulled,
        };
        persist_status(&self.status_path, status).map_err(|_| ())?;
        let mut runtime = self.runtime.lock().map_err(|_| ())?;
        runtime.status = Some(status);
        Ok(())
    }

    fn record_journal_failure(&self, id: [u8; 16]) {
        if let Ok(mut runtime) = self.runtime.lock() {
            let status = Status {
                id,
                phase: Phase::JournalFailure,
                pushed: 0,
                pulled: 0,
            };
            let _ = persist_status(&self.status_path, status);
            runtime.status = Some(status);
            runtime.active = false;
        }
    }
}

enum WorkerError {
    Sync(SyncError),
    Journal,
}

const fn phase_for_error(error: &SyncError) -> Phase {
    match error {
        SyncError::Integrity
        | SyncError::Missing
        | SyncError::Reduction(_)
        | SyncError::Crypto(_) => Phase::Integrity,
        SyncError::Backpressure => Phase::Backpressure,
        SyncError::Unauthorized | SyncError::InvalidRequest => Phase::Rejected,
        SyncError::Unavailable | SyncError::Storage(_) => Phase::Unavailable,
    }
}

#[cfg(unix)]
fn validate_program(program: &Path) -> Result<(), SyncError> {
    let metadata = fs::symlink_metadata(program).map_err(|_| SyncError::Unavailable)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != crate::linux::current_uid()
        || metadata.mode() & 0o022 != 0
        || fs::canonicalize(program).map_err(|_| SyncError::Unavailable)? != program
    {
        return Err(SyncError::Unauthorized);
    }
    Ok(())
}

#[cfg(windows)]
fn validate_program(program: &Path) -> Result<(), SyncError> {
    let file = pm_native_channel::open_regular_file(program).map_err(|_| SyncError::Unavailable)?;
    if file.metadata().map_err(|_| SyncError::Unavailable)?.len() == 0 {
        return Err(SyncError::Unauthorized);
    }
    Ok(())
}

fn encode_config(config: &Config) -> Result<Vec<u8>, Failure> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CONFIG_MAGIC);
    bytes.extend_from_slice(&config.id);
    push(&mut bytes, &config.protected)?;
    for path in [
        &config.program,
        &config.socket,
        &config.client_key,
        &config.server_public,
    ] {
        push(
            &mut bytes,
            path.to_str().ok_or(Failure::Unavailable)?.as_bytes(),
        )?;
    }
    bytes.extend_from_slice(&config.pin);
    if bytes.len() as u64 > MAX_CONFIG {
        return Err(Failure::Unavailable);
    }
    Ok(bytes)
}

fn decode_config(bytes: &[u8]) -> Result<Config, Failure> {
    let mut cursor = 0;
    take_exact(bytes, &mut cursor, CONFIG_MAGIC)?;
    let id = take_array(bytes, &mut cursor)?;
    let protected = Zeroizing::new(take(bytes, &mut cursor)?.to_vec());
    let program = path(take(bytes, &mut cursor)?)?;
    let socket = path(take(bytes, &mut cursor)?)?;
    let client_key = path(take(bytes, &mut cursor)?)?;
    let server_public = path(take(bytes, &mut cursor)?)?;
    let pin = take_array(bytes, &mut cursor)?;
    if cursor != bytes.len()
        || encode_config(&Config {
            id,
            protected: protected.clone(),
            program: program.clone(),
            socket: socket.clone(),
            client_key: client_key.clone(),
            server_public: server_public.clone(),
            pin,
        })? != bytes
    {
        return Err(Failure::Unavailable);
    }
    Ok(Config {
        id,
        protected,
        program,
        socket,
        client_key,
        server_public,
        pin,
    })
}

fn encode_status(status: Status) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(46);
    bytes.extend_from_slice(STATUS_MAGIC);
    bytes.extend_from_slice(&status.id);
    bytes.push(status.phase.byte());
    bytes.extend_from_slice(&status.pushed.to_be_bytes());
    bytes.extend_from_slice(&status.pulled.to_be_bytes());
    bytes
}

fn decode_status(bytes: &[u8]) -> Result<Status, Failure> {
    if bytes.len() != 38 || &bytes[..5] != STATUS_MAGIC {
        return Err(Failure::Unavailable);
    }
    let status = Status {
        id: bytes[5..21].try_into().map_err(|_| Failure::Unavailable)?,
        phase: Phase::parse(bytes[21])?,
        pushed: u64::from_be_bytes(bytes[22..30].try_into().map_err(|_| Failure::Unavailable)?),
        pulled: u64::from_be_bytes(bytes[30..38].try_into().map_err(|_| Failure::Unavailable)?),
    };
    (encode_status(status) == bytes)
        .then_some(status)
        .ok_or(Failure::Unavailable)
}

fn persist_status(path: &Path, status: Status) -> Result<(), Failure> {
    let suffix = random_id().map_err(|_| Failure::Unavailable)?;
    let temporary = path.with_extension(format!("sync-status-{}", hex(&suffix)));
    write_private(&temporary, &encode_status(status))?;
    fs::rename(&temporary, path).map_err(|_| Failure::Unavailable)?;
    sync_parent(path)
}

fn sync_parent(path: &Path) -> Result<(), Failure> {
    pm_native_channel::sync_directory(path.parent().ok_or(Failure::Unavailable)?)
        .map_err(|_| Failure::Unavailable)
}

#[cfg(unix)]
fn read_private(path: &Path, maximum: u64) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| Failure::Unavailable)?;
    let metadata = file.metadata().map_err(|_| Failure::Unavailable)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != crate::linux::current_uid()
        || metadata.mode() & 0o7777 != 0o400
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(Failure::Unavailable);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| Failure::Unavailable)?,
    ));
    file.read_to_end(&mut bytes)
        .map_err(|_| Failure::Unavailable)?;
    (bytes.len() as u64 == metadata.len())
        .then_some(bytes)
        .ok_or(Failure::Unavailable)
}

#[cfg(windows)]
fn read_private(path: &Path, maximum: u64) -> Result<Zeroizing<Vec<u8>>, Failure> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, GetFileInformationByHandle,
    };

    let mut file = pm_native_channel::open_regular_file(path).map_err(|_| Failure::Unavailable)?;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut information) } == 0 {
        return Err(Failure::Unavailable);
    }
    let length = (u64::from(information.nFileSizeHigh) << 32) | u64::from(information.nFileSizeLow);
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || information.nNumberOfLinks != 1
        || !(1..=maximum).contains(&length)
    {
        return Err(Failure::Unavailable);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(length).map_err(|_| Failure::Unavailable)?,
    ));
    file.read_to_end(&mut bytes)
        .map_err(|_| Failure::Unavailable)?;
    if u64::try_from(bytes.len()).ok() != Some(length) {
        return Err(Failure::Unavailable);
    }
    Ok(bytes)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Failure> {
    #[cfg(unix)]
    {
        crate::linux::write_new(path, bytes, 0o400)
    }
    #[cfg(windows)]
    {
        let mut file = pm_native_channel::create_private_file(path, true, true)
            .map_err(|_| Failure::Unavailable)?;
        let operation = file
            .write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| Failure::Unavailable)
            .and_then(|()| sync_parent(path));
        if let Err(error) = operation {
            drop(file);
            return Err(error.after_owned_path_cleanup(fs::remove_file(path)));
        }
        Ok(())
    }
}

fn push(output: &mut Vec<u8>, value: &[u8]) -> Result<(), Failure> {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| Failure::Unavailable)?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], Failure> {
    let length = u32::from_be_bytes(take_array(bytes, cursor)?) as usize;
    let end = cursor.checked_add(length).ok_or(Failure::Unavailable)?;
    let value = bytes.get(*cursor..end).ok_or(Failure::Unavailable)?;
    *cursor = end;
    Ok(value)
}

fn take_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], Failure> {
    let end = cursor.checked_add(N).ok_or(Failure::Unavailable)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(Failure::Unavailable)?
        .try_into()
        .map_err(|_| Failure::Unavailable)?;
    *cursor = end;
    Ok(value)
}

fn take_exact(bytes: &[u8], cursor: &mut usize, expected: &[u8]) -> Result<(), Failure> {
    let end = cursor
        .checked_add(expected.len())
        .ok_or(Failure::Unavailable)?;
    if bytes.get(*cursor..end) == Some(expected) {
        *cursor = end;
        Ok(())
    } else {
        Err(Failure::Unavailable)
    }
}

fn path(bytes: &[u8]) -> Result<PathBuf, Failure> {
    Ok(PathBuf::from(
        std::str::from_utf8(bytes).map_err(|_| Failure::Unavailable)?,
    ))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn must<T>(result: Result<T, Failure>) -> T {
        match result {
            Ok(value) => value,
            Err(Failure::Usage) => panic!("unexpected custody usage failure"),
            Err(Failure::Unavailable) => panic!("unexpected custody unavailable failure"),
            Err(Failure::WithCleanup { .. }) => {
                panic!("unexpected custody cleanup failure")
            }
        }
    }

    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "pm-sync-job-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn journal_write_failure_is_visible_in_memory_without_claiming_success() {
        let directory = directory();
        let vault = directory.join("vault.sqlite3");
        let manager = must(Manager::open(&vault));
        let id = [0x25; 16];
        {
            let mut runtime = manager.runtime.lock().unwrap();
            runtime.status = Some(Status {
                id,
                phase: Phase::Pushing,
                pushed: 0,
                pulled: 0,
            });
            runtime.active = true;
        }
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();
        manager.record_journal_failure(id);
        assert_eq!(must(manager.status(id)).phase, Phase::JournalFailure);
        assert!(!manager.runtime.lock().unwrap().active);
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn restart_reconciles_terminal_status_before_accepting_more_work() {
        let directory = directory();
        let vault = directory.join("vault.sqlite3");
        let config = PathBuf::from(format!("{}.sync-job", vault.display()));
        let status = PathBuf::from(format!("{}.sync-status", vault.display()));
        let id = [0x26; 16];
        must(write_private(&config, b"sensitive unfinished container"));
        must(persist_status(
            &status,
            Status {
                id,
                phase: Phase::Succeeded,
                pushed: 1,
                pulled: 2,
            },
        ));
        let manager = must(Manager::open(&vault));
        must(manager.resume());
        assert!(!config.exists());
        assert_eq!(must(manager.status(id)).phase, Phase::Succeeded);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn failed_restart_cleanup_is_journal_failure_not_success_or_daemon_failure() {
        let directory = directory();
        let vault = directory.join("vault.sqlite3");
        let config = PathBuf::from(format!("{}.sync-job", vault.display()));
        let status_path = PathBuf::from(format!("{}.sync-status", vault.display()));
        let id = [0x27; 16];
        must(write_private(&config, b"sensitive terminal container"));
        must(persist_status(
            &status_path,
            Status {
                id,
                phase: Phase::Succeeded,
                pushed: 1,
                pulled: 2,
            },
        ));
        let manager = must(Manager::open(&vault));
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();
        must(manager.resume());
        assert_eq!(must(manager.status(id)).phase, Phase::JournalFailure);
        assert!(config.exists());
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }
}
