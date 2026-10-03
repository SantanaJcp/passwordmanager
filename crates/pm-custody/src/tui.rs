// SPDX-License-Identifier: AGPL-3.0-only

//! Keyboard-only human content interface.  This module deliberately owns no
//! vault state: every mutation and secret exposure crosses the authenticated
//! human TLS-RPK channel implemented by the parent module.

use std::{
    ffi::OsString,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use pm_crypto::{ProtectedBytes, ProtectedText, ProtectedWriter};
#[cfg(target_os = "macos")]
use pm_native_channel::OwnedClipboard;
use pm_vault::PasskeyStatus;
use ratatui::{
    Terminal,
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};
use rustls::{ClientConnection, StreamOwned};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
#[cfg(target_os = "linux")]
use std::process::{Child, Command, Stdio};
use zeroize::{Zeroize, Zeroizing};

use crate::human_wire::{
    Cursor, ProtectedFrameWriter, encoded_bytes_len, protected_copy, read_frame, write_frame,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::linux::{
    HUMAN_MAGIC, KeyMaterial, Profile, Role, STREAM_CHUNK_BYTES, WirePrepared, connect,
    decode_prepared_response, finish_arguments, hex, open_1pux_source, push_bytes,
    read_import_source, read_key, read_profile, rpc_commit, rpc_download_atomic, rpc_history,
    rpc_prepare_purge_item, rpc_prepare_purge_revisions, rpc_prepare_restore, rpc_unlock,
    send_file_descriptor,
};
#[cfg(target_os = "windows")]
use crate::windows::{
    HUMAN_MAGIC, KeyMaterial, Profile, Role, STREAM_CHUNK_BYTES, WirePrepared,
    connect_tui as connect, decode_prepared_response, finish_arguments, hex, open_1pux_source,
    push_bytes, read_import_source, read_profile, rpc_commit, rpc_download_atomic, rpc_history,
    rpc_prepare_purge_item, rpc_prepare_purge_revisions, rpc_prepare_restore, rpc_unlock,
    send_file_handle,
};
use crate::{Failure, take_path};

#[cfg(windows)]
#[path = "windows_console_diagnostic.rs"]
mod console_diagnostic;

const DEFAULT_IDLE: u64 = 300;
const DEFAULT_REVEAL: u64 = 15;
const DEFAULT_COPY: u64 = 30;
#[cfg(target_os = "linux")]
const WL_COPY: &str = "/usr/bin/wl-copy";

#[derive(Clone)]
struct CatalogEntry {
    id: [u8; 16],
    kind: u8,
    trash: bool,
    favorite: bool,
    title: String,
    tags: Vec<String>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Unlock,
    Browse,
    Search,
    Tag,
    Generate,
    SelectField,
    ConfirmPurgeRevisions,
    ConfirmPurgeItem,
    EnrollAgent,
    ConfirmPasskeyApproval,
    ConfirmPasskeyPassword,
    Operations(OperationMenu),
    CsvImport,
    OnePuxImport,
    ConfirmImport,
    NativeBackup,
    PlaintextExport,
    ConfirmPlaintextExport,
    NativeRestore,
    MasterRotate,
    AuditPurge,
    AttachmentPath,
    PairDevice,
    SyncNow,
    SyncStatus,
    RetireDevice,
    RecoveryRotate,
    SelectAttachment,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Screen {
    Content,
    Access,
    Pending,
}

#[derive(Clone)]
enum AccessEntry {
    Agent {
        subject: [u8; 16],
        generation: u64,
        label: String,
        environment: String,
        status: String,
    },
    Credential {
        item: [u8; 16],
        title: String,
        enabled: bool,
    },
}

#[derive(Clone)]
struct PendingEntry {
    attempt: [u8; 16],
    title: String,
    integration: String,
    state: String,
    reason: String,
    expires_at_us: i64,
    owner: [u8; 16],
    generation: u64,
    agent_status: String,
    passkey: Option<PasskeyConfirmation>,
}

#[derive(Clone)]
struct PasskeyConfirmation {
    request: [u8; 16],
    verification: u8,
    rp: String,
    account: String,
    origin: String,
    document: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationMenu {
    Migration,
    Backup,
    Devices,
    Audit,
}

const fn operation_help(menu: OperationMenu) -> &'static str {
    match menu {
        OperationMenu::Migration => {
            "Migration: 1 CSV preview/mapping  2 1PUX preview  Enter confirms only after review  Esc cancels"
        }
        OperationMenu::Backup => {
            "Backup/recovery: 1 native backup  2 plaintext export  3 restore  4 master rotation  5 recovery rotation"
        }
        OperationMenu::Devices => {
            "Devices/sync: 1 pair  2 start sync  3 retire  4 status by job ID; sync remains observable after lock/restart"
        }
        OperationMenu::Audit => {
            "Audit: 1 query metadata  2 purge displayed range; purge preserves an explicit discontinuity"
        }
    }
}

struct App {
    entries: Vec<CatalogEntry>,
    visible: Vec<usize>,
    selected: usize,
    mode: Mode,
    input: ProtectedInput,
    status: String,
    information: Option<String>,
    information_scroll: usize,
    reveal: Option<(ProtectedBytes, Instant)>,
    clipboard: Option<ClipboardLease>,
    idle_at: Instant,
    wire_at: Instant,
    idle: Duration,
    reveal_for: Duration,
    copy_for: Duration,
    fields: Vec<FieldDescriptor>,
    field_selected: usize,
    field_copy: bool,
    screen: Screen,
    access: Vec<AccessEntry>,
    suspended: bool,
    pending: Vec<PendingEntry>,
    passkey_confirmation: Option<PasskeyConfirmation>,
    reauthentication: Option<(PasskeyConfirmation, ProtectedBytes)>,
    password: ProtectedBytes,
    operation: Option<PendingOperation>,
    attachments: Vec<AttachmentDescriptor>,
    sync_job: Option<[u8; 16]>,
    sync_poll_at: Instant,
    #[cfg(windows)]
    initial_diagnostic: Option<console_diagnostic::Diagnostic>,
    #[cfg(windows)]
    csv_diagnostic: Option<console_diagnostic::Diagnostic>,
    #[cfg(windows)]
    transfer_diagnostic: Option<File>,
}

enum PendingOperation {
    Import(WirePrepared),
    PlaintextExport {
        destination: PathBuf,
        prepared: WirePrepared,
    },
    Attachment {
        item: [u8; 16],
        attachment: [u8; 16],
    },
    RecoveryCode(ProtectedBytes),
}

struct AttachmentDescriptor {
    id: [u8; 16],
    label: String,
    size: u64,
}

struct FieldDescriptor {
    label: String,
    size: u64,
}

struct ProtectedInput {
    bytes: ProtectedBytes,
    used: usize,
}

impl ProtectedInput {
    fn new() -> Result<Self, Failure> {
        Ok(Self {
            bytes: ProtectedBytes::zeroed(32 * 1024 + 3).map_err(|_| Failure::Unavailable)?,
            used: 0,
        })
    }

    fn as_str(&self) -> &str {
        // Only `push` appends UTF-8 produced by `char::encode_utf8`.
        unsafe { std::str::from_utf8_unchecked(&self.bytes[..self.used]) }
    }

    const fn len(&self) -> usize {
        self.used
    }

    const fn is_empty(&self) -> bool {
        self.used == 0
    }

    fn push(&mut self, value: char) {
        let mut encoded = [0_u8; 4];
        let value = value.encode_utf8(&mut encoded).as_bytes();
        let end = self.used + value.len();
        self.bytes[self.used..end].copy_from_slice(value);
        self.used = end;
    }

    fn pop(&mut self) {
        let Some(value) = self.as_str().chars().next_back() else {
            return;
        };
        let next = self.used - value.len_utf8();
        self.bytes[next..self.used].fill(0);
        self.used = next;
    }

    fn clear(&mut self) {
        self.bytes[..self.used].fill(0);
        self.used = 0;
    }

    fn copy_value(&self) -> Result<ProtectedBytes, Failure> {
        protected_copy(&self.bytes[..self.used])
    }
}

impl std::ops::Deref for ProtectedInput {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl App {
    fn new(idle: Duration, reveal_for: Duration, copy_for: Duration) -> Result<Self, Failure> {
        Ok(Self {
            entries: Vec::new(),
            visible: Vec::new(),
            selected: 0,
            mode: Mode::Unlock,
            input: ProtectedInput::new()?,
            status: "Password required".into(),
            information: None,
            information_scroll: 0,
            reveal: None,
            clipboard: None,
            idle_at: Instant::now(),
            wire_at: Instant::now(),
            idle,
            reveal_for,
            copy_for,
            fields: Vec::new(),
            field_selected: 0,
            field_copy: false,
            screen: Screen::Content,
            access: Vec::new(),
            suspended: true,
            pending: Vec::new(),
            passkey_confirmation: None,
            reauthentication: None,
            password: ProtectedBytes::zeroed(0).map_err(|_| Failure::Unavailable)?,
            operation: None,
            attachments: Vec::new(),
            sync_job: None,
            sync_poll_at: Instant::now(),
            #[cfg(windows)]
            initial_diagnostic: None,
            #[cfg(windows)]
            csv_diagnostic: None,
            #[cfg(windows)]
            transfer_diagnostic: None,
        })
    }

    fn selected_entry(&self) -> Option<&CatalogEntry> {
        self.visible
            .get(self.selected)
            .and_then(|index| self.entries.get(*index))
    }

    fn clear_exposure(&mut self) {
        self.reveal = None;
    }

    fn navigate(&mut self, down: bool) {
        self.clear_exposure();
        if self.visible.is_empty() {
            self.selected = 0;
            return;
        }
        self.selected = if down {
            (self.selected + 1).min(self.visible.len() - 1)
        } else {
            self.selected.saturating_sub(1)
        };
    }

    fn replace_catalog(&mut self, entries: Vec<CatalogEntry>) {
        let selected_id = self.selected_entry().map(|entry| entry.id);
        self.entries = entries;
        self.visible = (0..self.entries.len()).collect();
        self.selected = selected_id
            .and_then(|id| self.entries.iter().position(|entry| entry.id == id))
            .unwrap_or(0);
    }

    fn expire(&mut self) {
        if self
            .reveal
            .as_ref()
            .is_some_and(|(_, until)| Instant::now() >= *until)
        {
            self.reveal = None;
            self.status = "Reveal expired".into();
        }
        if self
            .clipboard
            .as_ref()
            .is_some_and(|lease| Instant::now() >= lease.until)
            && let Some(mut lease) = self.clipboard.take()
        {
            self.status = if lease.stop_if_owner().is_ok() {
                "Clipboard custody expired".into()
            } else {
                "Clipboard cleanup not confirmed".into()
            };
        }
    }
}

enum ClipboardBackend {
    #[cfg(target_os = "linux")]
    Wayland(Child),
    #[cfg(target_os = "macos")]
    AppKit(Option<OwnedClipboard>),
    #[cfg(target_os = "windows")]
    Windows(Option<pm_native_channel::OwnedClipboard>),
}

struct ClipboardLease {
    backend: ClipboardBackend,
    until: Instant,
    cleanup_attempted: bool,
}

impl ClipboardLease {
    fn stop_if_owner(&mut self) -> Result<(), Failure> {
        if !begin_cleanup(&mut self.cleanup_attempted) {
            return Ok(());
        }
        match &mut self.backend {
            #[cfg(target_os = "windows")]
            ClipboardBackend::Windows(owner) => owner
                .take()
                .ok_or(Failure::Unavailable)?
                .clear_if_owned()
                .map(|_| ())
                .map_err(|_| Failure::Unavailable),
            #[cfg(target_os = "linux")]
            ClipboardBackend::Wayland(child) => stop_clipboard_with(child),
            #[cfg(target_os = "macos")]
            ClipboardBackend::AppKit(owner) => {
                let owner = owner.take().ok_or(Failure::Unavailable)?;
                // `false` means another application owns the pasteboard.  It
                // is a successful ownership-preserving no-op, not a reason
                // to clear the newer selection or retry cleanup.
                owner
                    .clear_if_owned()
                    .map(|_| ())
                    .map_err(|_| Failure::Unavailable)
            }
        }
    }
}

impl Drop for ClipboardLease {
    fn drop(&mut self) {
        if !self.cleanup_attempted && self.stop_if_owner().is_err() {
            report_cleanup_failure("clipboard");
        }
    }
}

struct TerminalGuard {
    writer: File,
    state: TerminalState,
    cleanup_attempted: bool,
    #[cfg(windows)]
    original_output_cp: Option<u32>,
    #[cfg(windows)]
    console_report: Option<File>,
}

#[derive(Clone, Copy)]
struct TerminalState {
    raw: bool,
    alternate: bool,
    cursor_hidden: bool,
}

impl TerminalGuard {
    fn restore(&mut self) -> Result<(), Failure> {
        if !begin_cleanup(&mut self.cleanup_attempted) {
            return Ok(());
        }
        let mut operations = CrosstermRestore {
            writer: &mut self.writer,
        };
        let terminal = restore_terminal_with(self.state, &mut operations);
        #[cfg(windows)]
        {
            combine_failures([terminal, self.restore_output_cp()])
        }
        #[cfg(not(windows))]
        {
            terminal
        }
    }

    #[cfg(windows)]
    fn configure_output_utf8(&mut self) -> Result<(), Failure> {
        use windows_sys::Win32::System::Console::{GetConsoleOutputCP, SetConsoleOutputCP};
        let original = unsafe { GetConsoleOutputCP() };
        if original == 0 {
            return Err(Failure::Unavailable);
        }
        self.original_output_cp = Some(original);
        if unsafe { SetConsoleOutputCP(65001) } == 0 || unsafe { GetConsoleOutputCP() } != 65001 {
            return Err(Failure::Unavailable);
        }
        Ok(())
    }

    #[cfg(windows)]
    fn restore_output_cp(&mut self) -> Result<(), Failure> {
        use windows_sys::Win32::System::Console::{GetConsoleOutputCP, SetConsoleOutputCP};
        let Some(expected) = self.original_output_cp.take() else {
            return Ok(());
        };
        let applied = unsafe { SetConsoleOutputCP(expected) } != 0;
        let observed = unsafe { GetConsoleOutputCP() };
        let restored = applied && observed != 0 && observed == expected;
        let encoding = if restored {
            Ok(())
        } else {
            Err(Failure::Unavailable)
        };
        let report = match self.console_report.as_mut() {
            Some(file) => writeln!(file,
                "TUI_PROBE stage=restore output-cp={observed} expected={expected} restored={restored}"
            ).map_err(|_| Failure::Unavailable),
            None => Ok(()),
        };
        combine_failures([encoding, report])
    }
}

fn begin_cleanup(attempted: &mut bool) -> bool {
    if *attempted {
        false
    } else {
        *attempted = true;
        true
    }
}
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if !self.cleanup_attempted && self.restore().is_err() {
            report_cleanup_failure("terminal");
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
trait ClipboardControl {
    fn try_exited(&mut self) -> Result<bool, ()>;
    fn kill_process(&mut self) -> Result<(), ()>;
    fn wait_process(&mut self) -> Result<(), ()>;
}

#[cfg(target_os = "linux")]
impl ClipboardControl for Child {
    fn try_exited(&mut self) -> Result<bool, ()> {
        self.try_wait()
            .map(|status| status.is_some())
            .map_err(|_| ())
    }

    fn kill_process(&mut self) -> Result<(), ()> {
        self.kill().map_err(|_| ())
    }

    fn wait_process(&mut self) -> Result<(), ()> {
        self.wait().map(|_| ()).map_err(|_| ())
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn stop_clipboard_with(control: &mut impl ClipboardControl) -> Result<(), Failure> {
    let exited = control.try_exited();
    let should_stop = !matches!(exited, Ok(true));
    let kill = if should_stop {
        control.kill_process()
    } else {
        Ok(())
    };
    let wait = if should_stop {
        control.wait_process()
    } else {
        Ok(())
    };
    if exited.is_err() || kill.is_err() || wait.is_err() {
        Err(Failure::Unavailable)
    } else {
        Ok(())
    }
}

trait TerminalRestore {
    fn leave_alternate(&mut self) -> Result<(), ()>;
    fn show_cursor(&mut self) -> Result<(), ()>;
    fn disable_raw(&mut self) -> Result<(), ()>;
}

struct CrosstermRestore<'a> {
    writer: &'a mut File,
}

impl TerminalRestore for CrosstermRestore<'_> {
    fn leave_alternate(&mut self) -> Result<(), ()> {
        execute!(self.writer, LeaveAlternateScreen).map_err(|_| ())
    }

    fn show_cursor(&mut self) -> Result<(), ()> {
        execute!(self.writer, crossterm::cursor::Show).map_err(|_| ())
    }

    fn disable_raw(&mut self) -> Result<(), ()> {
        disable_raw_mode().map_err(|_| ())
    }
}

fn restore_terminal_with(
    state: TerminalState,
    operations: &mut impl TerminalRestore,
) -> Result<(), Failure> {
    let alternate = !state.alternate || operations.leave_alternate().is_ok();
    let cursor = !state.cursor_hidden || operations.show_cursor().is_ok();
    let raw = !state.raw || operations.disable_raw().is_ok();
    if alternate && cursor && raw {
        Ok(())
    } else {
        Err(Failure::Unavailable)
    }
}

fn report_cleanup_failure(component: &str) {
    let _ = writeln!(
        std::io::stderr(),
        "TUI_CLEANUP_FAILED component={component}"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
type HumanTls = StreamOwned<ClientConnection, UnixStream>;
#[cfg(target_os = "windows")]
type HumanTls = StreamOwned<ClientConnection, pm_native_channel::WindowsClientPipe>;

pub(super) fn run(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let parsed = parse_arguments(arguments)?;
    let profile = read_profile(&parsed.profile_path)?;
    if profile.role != Role::Human {
        return Err(Failure::Unavailable);
    }
    let key = read_tui_key(&parsed.private_path)?;
    run_terminal(
        &profile,
        &key,
        &parsed.endpoint,
        parsed.idle,
        parsed.reveal,
        parsed.copy,
        #[cfg(windows)]
        parsed.diagnostic_path.as_deref(),
    )
}

struct TuiArguments {
    profile_path: PathBuf,
    private_path: PathBuf,
    endpoint: PathBuf,
    idle: u64,
    reveal: u64,
    copy: u64,
    #[cfg(windows)]
    diagnostic_path: Option<PathBuf>,
}

fn parse_arguments(
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<TuiArguments, Failure> {
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    #[cfg(unix)]
    let endpoint = take_path(arguments, "--socket")?;
    #[cfg(windows)]
    let endpoint = take_path(arguments, "--vault-id")?;
    let idle = take_seconds(arguments, "--idle-seconds", DEFAULT_IDLE)?;
    let reveal = take_seconds(arguments, "--reveal-seconds", DEFAULT_REVEAL)?;
    let copy = take_seconds(arguments, "--copy-seconds", DEFAULT_COPY)?;
    #[cfg(windows)]
    let diagnostic_path = match arguments.next() {
        None => None,
        Some(flag) if flag == "--console-diagnostics" => {
            Some(PathBuf::from(arguments.next().ok_or(Failure::Usage)?))
        }
        Some(_) => return Err(Failure::Usage),
    };
    finish_arguments(arguments)?;
    if idle > DEFAULT_IDLE || reveal > DEFAULT_REVEAL || copy > DEFAULT_COPY {
        return Err(Failure::Usage);
    }
    Ok(TuiArguments {
        profile_path,
        private_path,
        endpoint,
        idle,
        reveal,
        copy,
        #[cfg(windows)]
        diagnostic_path,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn read_tui_key(path: &Path) -> Result<KeyMaterial, Failure> {
    read_key(path, crate::linux::current_uid())
}

#[cfg(target_os = "windows")]
fn read_tui_key(path: &Path) -> Result<KeyMaterial, Failure> {
    crate::windows::read_key(path)
}

fn take_seconds(
    arguments: &mut impl Iterator<Item = OsString>,
    flag: &str,
    maximum: u64,
) -> Result<u64, Failure> {
    let actual = arguments.next().ok_or(Failure::Usage)?;
    let value = arguments.next().ok_or(Failure::Usage)?;
    if actual != flag {
        return Err(Failure::Usage);
    }
    let parsed = value
        .to_str()
        .ok_or(Failure::Usage)?
        .parse()
        .map_err(|_| Failure::Usage)?;
    if !(1..=maximum).contains(&parsed) {
        return Err(Failure::Usage);
    }
    Ok(parsed)
}

fn run_terminal(
    profile: &Profile,
    key: &KeyMaterial,
    socket: &Path,
    idle: u64,
    reveal: u64,
    copy: u64,
    #[cfg(windows)] diagnostic_path: Option<&Path>,
) -> Result<(), Failure> {
    let writer = open_terminal()?;
    #[cfg(windows)]
    let mut diagnostic = diagnostic_path
        .map(|path| console_diagnostic::Diagnostic::create(path, &writer))
        .transpose()?;
    #[cfg(windows)]
    if let Some(probe) = diagnostic.as_mut() {
        probe.record("before-alt")?;
    }
    if enable_raw_mode().is_err() {
        if disable_raw_mode().is_err() {
            report_cleanup_failure("terminal-initialization");
        }
        return Err(Failure::Unavailable);
    }
    let Ok(guard_writer) = writer.try_clone() else {
        disable_raw_mode().map_err(|_| Failure::Unavailable)?;
        return Err(Failure::Unavailable);
    };
    let mut guard = TerminalGuard {
        writer: guard_writer,
        state: TerminalState {
            raw: true,
            alternate: false,
            cursor_hidden: false,
        },
        cleanup_attempted: false,
        #[cfg(windows)]
        original_output_cp: None,
        #[cfg(windows)]
        console_report: None,
    };
    let operation = (|| {
        #[cfg(windows)]
        {
            if let Some(probe) = diagnostic.as_ref() {
                guard.console_report = Some(probe.report_file()?);
            }
            guard.configure_output_utf8()?;
        }
        guard.state.alternate = true;
        execute!(guard.writer, EnterAlternateScreen).map_err(|_| Failure::Unavailable)?;
        #[cfg(windows)]
        if let Some(probe) = diagnostic.as_mut() {
            probe.record("after-alt")?;
            probe.writer_experiments()?;
        }
        guard.state.cursor_hidden = true;
        execute!(guard.writer, crossterm::cursor::Hide).map_err(|_| Failure::Unavailable)?;
        let backend = CrosstermBackend::new(writer);
        let mut terminal = Terminal::new(backend).map_err(|_| Failure::Unavailable)?;
        terminal
            .backend_mut()
            .clear()
            .map_err(|_| Failure::Unavailable)?;
        let mut app = App::new(
            Duration::from_secs(idle),
            Duration::from_secs(reveal),
            Duration::from_secs(copy),
        )?;
        #[cfg(windows)]
        {
            app.transfer_diagnostic = diagnostic
                .as_ref()
                .map(console_diagnostic::Diagnostic::report_file)
                .transpose()?;
            app.initial_diagnostic = diagnostic;
        }
        run_authenticated_session(profile, key, socket, &mut terminal, &mut app)
    })();
    let restoration = guard.restore();
    combine_failures([operation, restoration])
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_terminal() -> Result<File, Failure> {
    File::options()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| Failure::Unavailable)
}

#[cfg(target_os = "windows")]
fn open_terminal() -> Result<File, Failure> {
    File::options()
        .read(true)
        .write(true)
        .open("CONOUT$")
        .map_err(|_| Failure::Unavailable)
}

fn run_authenticated_session(
    profile: &Profile,
    key: &KeyMaterial,
    socket: &Path,
    terminal: &mut Terminal<CrosstermBackend<File>>,
    app: &mut App,
) -> Result<(), Failure> {
    let session = (|| {
        draw(terminal, app)?;
        let password = read_prompt(terminal, app, true)?;
        let mut tls = Some(connect(profile, key, socket)?);
        let tls_ref = tls.as_mut().ok_or(Failure::Unavailable)?;
        tls_ref
            .write_all(HUMAN_MAGIC)
            .map_err(|_| Failure::Unavailable)?;
        rpc_unlock(tls_ref, &password)?;
        app.password = password;
        app.input.clear();
        write_frame(tls_ref, &[46])?;
        app.replace_catalog(decode_catalog(&read_frame(tls_ref)?)?);
        app.mode = Mode::Browse;
        app.status = "Unlocked: selection never reveals secrets".into();
        app.idle_at = Instant::now();
        let outcome = (|| {
            loop {
                event_loop(terminal, app, tls.as_mut().ok_or(Failure::Unavailable)?)?;
                let Some((confirmation, password)) = app.reauthentication.take() else {
                    break Ok(());
                };
                let mut old_tls = tls.take().ok_or(Failure::Unavailable)?;
                lock_human_channel(&mut old_tls)?;
                drop(old_tls);
                let mut next_tls = connect(profile, key, socket)?;
                next_tls
                    .write_all(HUMAN_MAGIC)
                    .map_err(|_| Failure::Unavailable)?;
                rpc_unlock(&mut next_tls, &password)?;
                let verification = confirmation.verification;
                confirm_passkey(&mut next_tls, &confirmation)?;
                show_pending(app, &mut next_tls)?;
                app.status = if verification == 2 {
                    "Passkey confirmed with fresh UP+UV".into()
                } else {
                    "Passkey confirmed with fresh UP".into()
                };
                tls = Some(next_tls);
            }
        })();
        app.clear_exposure();
        let clipboard = app
            .clipboard
            .take()
            .map_or(Ok(()), |mut lease| lease.stop_if_owner());
        let lock = if outcome.is_ok() {
            if let Some(tls) = tls.as_mut() {
                (|| {
                    lock_human_channel(tls)?;
                    terminal
                        .backend_mut()
                        .clear()
                        .map_err(|_| Failure::Unavailable)
                })()
            } else {
                Err(Failure::Unavailable)
            }
        } else {
            Ok(())
        };
        combine_failures([outcome, clipboard, lock])
    })();
    app.clear_exposure();
    let clipboard = app
        .clipboard
        .take()
        .map_or(Ok(()), |mut lease| lease.stop_if_owner());
    combine_failures([session, clipboard])
}

fn combine_failures<const N: usize>(results: [Result<(), Failure>; N]) -> Result<(), Failure> {
    let mut failure: Option<Failure> = None;
    for result in results {
        if let Err(error) = result {
            failure = Some(match failure {
                Some(previous) => previous.merge(error),
                None => error,
            });
        }
    }
    failure.map_or(Ok(()), Err)
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<File>>,
    app: &mut App,
    tls: &mut HumanTls,
) -> Result<(), Failure> {
    loop {
        app.expire();
        if Instant::now().duration_since(app.idle_at) >= app.idle {
            app.status = "Locked after 5 minutes without human input".into();
            draw(terminal, app)?;
            return Ok(());
        }
        if app.sync_job.is_some()
            && Instant::now().duration_since(app.sync_poll_at) >= Duration::from_millis(250)
        {
            poll_sync(app, tls)?;
        }
        if app.mode != Mode::RecoveryRotate
            && Instant::now().duration_since(app.wire_at) >= Duration::from_secs(5)
        {
            write_frame(tls, &[65])?;
            if *read_frame(tls)? != [0] {
                return Err(Failure::Unavailable);
            }
            app.wire_at = Instant::now();
        }
        draw(terminal, app)?;
        if !event::poll(Duration::from_millis(100)).map_err(|_| Failure::Unavailable)? {
            continue;
        }
        let event = event::read().map_err(|_| Failure::Unavailable)?;
        match event {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                app.idle_at = Instant::now();
                match handle_key(app, tls, key) {
                    Ok(true) => return Ok(()),
                    Ok(false) => {}
                    Err(error) if error.has_native_cleanup_failure() => return Err(error),
                    Err(error) => {
                        app.operation = None;
                        app.information = None;
                        app.reveal = None;
                        app.input.clear();
                        app.mode = Mode::Browse;
                        app.status = "Operation failed explicitly; no success was recorded".into();
                        if error.primary() == crate::failure::PrimaryFailure::DestinationExists {
                            app.status.push_str(" (DESTINATION_EXISTS)");
                        }
                    }
                }
                if app.reauthentication.is_some() {
                    return Ok(());
                }
            }
            _ => {}
        }
    }
}

fn handle_key(app: &mut App, tls: &mut HumanTls, key: KeyEvent) -> Result<bool, Failure> {
    if scroll_information(app, key.code) {
        return Ok(false);
    }
    if app.mode == Mode::Browse {
        app.information = None;
        app.information_scroll = 0;
    }
    if app.mode == Mode::SelectField {
        return handle_field_key(app, tls, key).map(|()| false);
    }
    if app.mode == Mode::SelectAttachment {
        return handle_attachment_key(app, key).map(|()| false);
    }
    if app.mode != Mode::Browse {
        if let Mode::Operations(menu) = app.mode {
            handle_operation_key(app, tls, menu, key)?;
            return Ok(false);
        }
        return handle_prompt_key(app, tls, key).map(|()| false);
    }
    if app.screen == Screen::Access {
        return handle_access_key(app, tls, key).map(|()| false);
    }
    if app.screen == Screen::Pending {
        return handle_pending_key(app, tls, key).map(|()| false);
    }
    match key.code {
        KeyCode::Char('q' | 'l') => return Ok(true),
        KeyCode::Down | KeyCode::Char('j') => app.navigate(true),
        KeyCode::Up | KeyCode::Char('k') => app.navigate(false),
        KeyCode::Char('/') => begin_prompt(app, Mode::Search, "Search (engine-decrypted):"),
        KeyCode::Char('t') => begin_prompt(app, Mode::Tag, "Tag (replaces tags):"),
        KeyCode::Char('g') => begin_prompt(app, Mode::Generate, "Generator length 1-1024:"),
        KeyCode::Char('f') => toggle_favorite(app, tls)?,
        KeyCode::Char('h') => show_history(app, tls)?,
        KeyCode::Char('d') => trash(app, tls)?,
        KeyCode::Char('u') => restore(app, tls)?,
        KeyCode::Char('p') => begin_prompt(
            app,
            Mode::ConfirmPurgeRevisions,
            "Type PURGE to delete non-visible revisions:",
        ),
        KeyCode::Char('P') => begin_prompt(
            app,
            Mode::ConfirmPurgeItem,
            "Type PURGE to permanently delete trashed item:",
        ),
        KeyCode::Char('r') => select_exposure_field(app, tls, false)?,
        KeyCode::Char('c') => select_exposure_field(app, tls, true)?,
        KeyCode::Char('a') => show_access(app, tls)?,
        KeyCode::Char('w') => show_pending(app, tls)?,
        KeyCode::Char('m') => open_operations(app, OperationMenu::Migration),
        KeyCode::Char('b') => open_operations(app, OperationMenu::Backup),
        KeyCode::Char('y') => open_operations(app, OperationMenu::Devices),
        KeyCode::Char('z') => open_operations(app, OperationMenu::Audit),
        KeyCode::Char('D') => select_attachment(app, tls)?,
        _ => {}
    }
    Ok(false)
}

fn handle_operation_key(
    app: &mut App,
    tls: &mut HumanTls,
    menu: OperationMenu,
    key: KeyEvent,
) -> Result<(), Failure> {
    if key.code == KeyCode::Esc {
        app.mode = Mode::Browse;
        app.status = "Cancelled; nothing changed".into();
        return Ok(());
    }
    match (menu, key.code) {
        (OperationMenu::Migration, KeyCode::Char('1')) => begin_prompt(
            app,
            Mode::CsvImport,
            "CSV source|chrome/apple/mappable|keep/replace (plaintext source is never deleted):",
        ),
        (OperationMenu::Migration, KeyCode::Char('2')) => begin_prompt(
            app,
            Mode::OnePuxImport,
            "1PUX source|keep/replace (private source is never deleted):",
        ),
        (OperationMenu::Backup, KeyCode::Char('1')) => begin_prompt(
            app,
            Mode::NativeBackup,
            "New native backup path (encrypted; existing path rejected):",
        ),
        (OperationMenu::Backup, KeyCode::Char('2')) => begin_prompt(
            app,
            Mode::PlaintextExport,
            "New plaintext export path (persistent readable copy; existing path rejected):",
        ),
        (OperationMenu::Backup, KeyCode::Char('3')) => begin_prompt(
            app,
            Mode::NativeRestore,
            "Archive path|RESTORE (adds new IDs/keys; current authority is preserved):",
        ),
        (OperationMenu::Backup, KeyCode::Char('4')) => begin_prompt(
            app,
            Mode::MasterRotate,
            "New master password|ROTATE (old backups and exposed copies retain historical recovery paths):",
        ),
        (OperationMenu::Backup, KeyCode::Char('5')) => rotate_recovery(app, tls)?,
        (OperationMenu::Devices, KeyCode::Char('1')) => begin_prompt(
            app,
            Mode::PairDevice,
            "Observed server RPK pin hex|new protected pairing path|PAIR:",
        ),
        (OperationMenu::Devices, KeyCode::Char('2')) => begin_prompt(
            app,
            Mode::SyncNow,
            "pairing|pm-sync program|socket|client key|server public|server pin hex|SYNC (offline is explicit):",
        ),
        (OperationMenu::Devices, KeyCode::Char('3')) => begin_prompt(
            app,
            Mode::RetireDevice,
            "Exact device ID hex|RETIRE (terminal for observed prefixes; offline events beyond them are rejected):",
        ),
        (OperationMenu::Devices, KeyCode::Char('4')) => begin_prompt(
            app,
            Mode::SyncStatus,
            "Exact sync job ID hex (query only; does not repeat the operation):",
        ),
        (OperationMenu::Audit, KeyCode::Char('1')) => query_audit(app, tls)?,
        (OperationMenu::Audit, KeyCode::Char('2')) => begin_prompt(
            app,
            Mode::AuditPurge,
            "generation:through-sequence:PURGE AUDIT (exact range becomes a gap):",
        ),
        _ => show_information(app, operation_help(menu)),
    }
    Ok(())
}

fn open_operations(app: &mut App, menu: OperationMenu) {
    app.clear_exposure();
    app.mode = Mode::Operations(menu);
    show_information(app, operation_help(menu));
}

fn begin_prompt(app: &mut App, mode: Mode, status: &str) {
    app.clear_exposure();
    app.input.clear();
    app.mode = mode;
    show_information(app, status);
}

fn handle_prompt_key(app: &mut App, tls: &mut HumanTls, key: KeyEvent) -> Result<(), Failure> {
    match key.code {
        KeyCode::Esc => {
            if app.mode == Mode::RecoveryRotate {
                write_frame(tls, &[])?;
                if *read_frame(tls)? != [2] {
                    return Err(Failure::Unavailable);
                }
            }
            app.input.clear();
            app.operation = None;
            app.reveal = None;
            app.mode = Mode::Browse;
            app.information = None;
            app.status = "Cancelled".into();
        }
        KeyCode::Backspace => {
            app.input.pop();
        }
        KeyCode::Enter => submit_prompt(app, tls)?,
        KeyCode::Char(value)
            if !value.is_control() && app.input.len() < prompt_input_limit(app.mode) =>
        {
            app.input.push(value);
        }
        _ => {}
    }
    Ok(())
}

const fn prompt_input_limit(mode: Mode) -> usize {
    match mode {
        Mode::CsvImport
        | Mode::OnePuxImport
        | Mode::NativeBackup
        | Mode::PlaintextExport
        | Mode::NativeRestore
        | Mode::AttachmentPath
        | Mode::PairDevice
        | Mode::SyncNow => 32 * 1024,
        _ => 1024,
    }
}

fn submit_prompt(app: &mut App, tls: &mut HumanTls) -> Result<(), Failure> {
    let mode = app.mode;
    let value = app.input.copy_value()?;
    app.input.clear();
    let value_text = std::str::from_utf8(&value).map_err(|_| Failure::Unavailable)?;
    app.mode = Mode::Browse;
    app.information = None;
    app.information_scroll = 0;
    match mode {
        Mode::Search => search(app, tls, value_text),
        Mode::Tag => organize(app, tls, Some(value_text.to_owned())),
        Mode::Generate => generate(app, tls, value_text),
        Mode::ConfirmPurgeRevisions if value_text == "PURGE" => purge_revisions(app, tls),
        Mode::ConfirmPurgeItem if value_text == "PURGE" => purge_item(app, tls),
        Mode::ConfirmPurgeRevisions | Mode::ConfirmPurgeItem => {
            app.status = "Confirmation mismatch; nothing changed".into();
            Ok(())
        }
        Mode::EnrollAgent => enroll_agent(app, tls, value_text),
        Mode::ConfirmPasskeyApproval => confirm_passkey_approval(app, value_text),
        Mode::ConfirmPasskeyPassword => {
            let confirmation = app
                .passkey_confirmation
                .take()
                .ok_or(Failure::Unavailable)?;
            app.reauthentication = Some((confirmation, value));
            Ok(())
        }
        Mode::CsvImport => preview_csv(app, tls, value_text),
        Mode::OnePuxImport => preview_1pux(app, tls, value_text),
        Mode::ConfirmImport => confirm_import(app, tls, value_text),
        Mode::NativeBackup => native_backup(app, tls, value_text),
        Mode::PlaintextExport => preview_plaintext_export(app, tls, value_text),
        Mode::ConfirmPlaintextExport => confirm_plaintext_export(app, tls, value_text),
        Mode::NativeRestore => native_restore(app, tls, value_text),
        Mode::MasterRotate => master_rotate(app, tls, value_text),
        Mode::AuditPurge => purge_audit(app, tls, value_text),
        Mode::AttachmentPath => download_attachment(app, tls, value_text),
        Mode::PairDevice => pair_device(app, tls, value_text),
        Mode::SyncNow => sync_now(app, tls, value_text),
        Mode::SyncStatus => select_sync_job(app, tls, value_text),
        Mode::RetireDevice => retire_device(app, tls, value_text),
        Mode::RecoveryRotate => confirm_recovery_rotation(app, tls, value_text),
        Mode::Unlock
        | Mode::Browse
        | Mode::SelectField
        | Mode::SelectAttachment
        | Mode::Operations(_) => Ok(()),
    }
}

fn show_access(app: &mut App, tls: &mut HumanTls) -> Result<(), Failure> {
    write_frame(tls, &[54])?;
    let response = read_frame(tls)?;
    let mut cursor = Cursor::new(&response);
    cursor.expect(&[0])?;
    app.suspended = match cursor.fixed(1)? {
        [0] => false,
        [1] => true,
        _ => return Err(Failure::Unavailable),
    };
    let agent_count = usize::from(u16::from_be_bytes(
        cursor
            .fixed(2)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
    ));
    let mut access = Vec::with_capacity(agent_count);
    for _ in 0..agent_count {
        let subject = cursor
            .fixed(16)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?;
        let generation = cursor.u64()?;
        let status = match cursor.fixed(1)? {
            [1] => "active",
            [2] => "revoked",
            [3] => "superseded",
            _ => return Err(Failure::Unavailable),
        }
        .to_owned();
        let label = cursor.public_string()?;
        let environment = cursor.public_string()?;
        access.push(AccessEntry::Agent {
            subject,
            generation,
            label,
            environment,
            status,
        });
    }
    let credential_count = usize::from(u16::from_be_bytes(
        cursor
            .fixed(2)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
    ));
    access.reserve(credential_count);
    for _ in 0..credential_count {
        let item = cursor
            .fixed(16)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?;
        let enabled = match cursor.fixed(1)? {
            [0] => false,
            [1] => true,
            _ => return Err(Failure::Unavailable),
        };
        let title = cursor.public_string()?;
        access.push(AccessEntry::Credential {
            item,
            title,
            enabled,
        });
    }
    cursor.finish()?;
    app.access = access;
    app.selected = 0;
    app.screen = Screen::Access;
    app.status = format!(
        "Delegated access: {}",
        if app.suspended {
            "SUSPENDED"
        } else {
            "RESUMED"
        }
    );
    Ok(())
}

fn split_fields<const N: usize>(
    value: &str,
    mut emit: impl FnMut(usize, char) -> Result<(), Failure>,
) -> Result<(), Failure> {
    let mut index = 0;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            emit(index, character)?;
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '|' {
            index = index.checked_add(1).ok_or(Failure::Unavailable)?;
        } else {
            emit(index, character)?;
        }
        if index >= N {
            return Err(Failure::Unavailable);
        }
    }
    if escaped || index.checked_add(1) != Some(N) {
        return Err(Failure::Unavailable);
    }
    Ok(())
}

fn split_exact<const N: usize>(value: &str) -> Result<[ProtectedText; N], Failure> {
    let mut sizes = [0_usize; N];
    split_fields::<N>(value, |index, character| {
        let size = sizes.get_mut(index).ok_or(Failure::Unavailable)?;
        *size = size
            .checked_add(character.len_utf8())
            .ok_or(Failure::Unavailable)?;
        Ok(())
    })?;
    let mut fields = sizes
        .into_iter()
        .map(|size| ProtectedWriter::new(size).map_err(|_| Failure::Unavailable))
        .collect::<Result<Vec<_>, _>>()?;
    split_fields::<N>(value, |index, character| {
        let mut bytes = [0; 4];
        fields
            .get_mut(index)
            .ok_or(Failure::Unavailable)?
            .put(character.encode_utf8(&mut bytes).as_bytes())
            .map_err(|_| Failure::Unavailable)
    })?;
    fields
        .into_iter()
        .map(|field| {
            ProtectedText::from_bytes(field.finish_exact().map_err(|_| Failure::Unavailable)?)
                .map_err(|_| Failure::Unavailable)
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| Failure::Unavailable)
}

fn decode_import_preview(response: &[u8]) -> Result<(String, WirePrepared), Failure> {
    let mut cursor = Cursor::new(response);
    cursor.expect(&[0])?;
    let values = [
        cursor.u64()?,
        cursor.u64()?,
        cursor.u64()?,
        cursor.u64()?,
        cursor.u64()?,
        cursor.u64()?,
        cursor.u64()?,
    ];
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
        command: protected_copy(cursor.bytes()?)?,
        body: protected_copy(cursor.bytes()?)?,
        signature: cursor
            .fixed(64)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
    };
    cursor.finish()?;
    Ok((
        format!(
            "Preview values hidden: total={} new={} replaced={} exact-duplicates={} excluded={} preserved-fields={} pages={}; type IMPORT to commit",
            values[0], values[1], values[2], values[3], values[4], values[5], values[6]
        ),
        prepared,
    ))
}

fn preview_csv(app: &mut App, tls: &mut HumanTls, value: &str) -> Result<(), Failure> {
    let [path, format, duplicates] = split_exact::<3>(value)?;
    let format = match &*format {
        "chrome" => 0,
        "apple" => 1,
        "mappable" => 2,
        _ => return Err(Failure::Unavailable),
    };
    let (replace, duplicates) = match &*duplicates {
        "keep" => (0, "keep"),
        "replace" => (1, "replace"),
        _ => return Err(Failure::Unavailable),
    };
    let source = read_import_source(Path::new(&*path))?;
    let mut request = vec![23, format, replace];
    push_bytes(&mut request, &source)?;
    write_frame(tls, &request)?;
    let (summary, prepared) = decode_import_preview(&read_frame(tls)?)?;
    let summary = format!(
        "Mapping={} duplicate-action={}; {summary}",
        ["chrome", "apple", "mappable"][usize::from(format)],
        duplicates
    );
    app.operation = Some(PendingOperation::Import(prepared));
    begin_prompt(app, Mode::ConfirmImport, &summary);
    Ok(())
}

fn preview_1pux(app: &mut App, tls: &mut HumanTls, value: &str) -> Result<(), Failure> {
    let [path, duplicates] = split_exact::<2>(value)?;
    let replace = match &*duplicates {
        "keep" => 0,
        "replace" => 1,
        _ => return Err(Failure::Unavailable),
    };
    let source = open_1pux_source(Path::new(&*path))?;
    #[cfg(windows)]
    transfer_phase(app, "source-open")?;
    write_frame(tls, &[31, replace])?;
    #[cfg(windows)]
    transfer_phase(app, "request31-sent")?;
    if *read_frame(tls)? != [0] {
        return Err(Failure::Unavailable);
    }
    #[cfg(windows)]
    transfer_phase(app, "ack31-received")?;
    #[cfg(not(windows))]
    let response = transfer_import_file(tls, &source)?;
    #[cfg(windows)]
    let response = transfer_import_file(app, tls, &source)?;
    let (summary, prepared) = decode_import_preview(&response)?;
    app.operation = Some(PendingOperation::Import(prepared));
    begin_prompt(app, Mode::ConfirmImport, &summary);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn transfer_import_file(tls: &mut HumanTls, source: &File) -> Result<ProtectedBytes, Failure> {
    send_file_descriptor(&tls.sock, source.as_raw_fd()).and_then(|()| read_frame(tls))
}

#[cfg(target_os = "windows")]
fn transfer_phase(app: &mut App, phase: &'static str) -> Result<(), Failure> {
    if let Some(report) = app.transfer_diagnostic.as_mut() {
        writeln!(report, "TUI_PROBE transfer={phase}").map_err(|_| Failure::Unavailable)?;
        report.flush().map_err(|_| Failure::Unavailable)?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn transfer_import_file(
    app: &mut App,
    tls: &mut HumanTls,
    source: &File,
) -> Result<ProtectedBytes, Failure> {
    let lease = match pm_native_channel::ProcessHandleTransferLease::begin() {
        Ok(lease) => lease,
        Err(error) => {
            let failure = Failure::Unavailable.after_native_cleanup(error.cleanup_result());
            return Err(match transfer_phase(app, error.phase()) {
                Ok(()) => failure,
                Err(diagnostic) => failure.merge(diagnostic),
            });
        }
    };
    let operation: Result<ProtectedBytes, Failure> = (|| {
        transfer_phase(app, "child-lease-installed")?;
        send_file_handle(tls, source)?;
        transfer_phase(app, "handle-sent")?;
        let response = read_frame(tls)?;
        transfer_phase(app, "preview-received")?;
        Ok(response)
    })();
    let restored = lease.finish();
    let diagnostic = transfer_phase(
        app,
        if restored.is_ok() {
            "lease-restored"
        } else {
            "lease-restore-failed"
        },
    );
    let result = match operation {
        Ok(response) => match restored {
            Ok(()) => Ok(response),
            Err(cleanup) => Err(Failure::Unavailable.after_native_cleanup(Err(cleanup))),
        },
        Err(error) => Err(error.after_native_cleanup(restored)),
    };
    match (result, diagnostic) {
        (Ok(response), Ok(())) => Ok(response),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(diagnostic)) => Err(error.merge(diagnostic)),
    }
}

fn confirm_import(app: &mut App, tls: &mut HumanTls, value: &str) -> Result<(), Failure> {
    if value != "IMPORT" {
        app.operation = None;
        app.status = "Confirmation mismatch; import cancelled".into();
        return Ok(());
    }
    let Some(PendingOperation::Import(prepared)) = app.operation.take() else {
        return Err(Failure::Unavailable);
    };
    rpc_commit(tls, &prepared)?;
    refresh(app, tls)?;
    app.status = "Import committed transactionally; imported credentials remain disabled".into();
    Ok(())
}

fn native_backup(app: &mut App, tls: &mut HumanTls, value: &str) -> Result<(), Failure> {
    let bytes = rpc_download_atomic(tls, &[32], Path::new(value))?;
    app.status = format!(
        "Native encrypted backup complete: {bytes} bytes; existing exposed copies are unchanged"
    );
    show_information(app, &app.status.clone());
    Ok(())
}

fn handle_access_key(app: &mut App, tls: &mut HumanTls, key: KeyEvent) -> Result<(), Failure> {
    match key.code {
        KeyCode::Esc => {
            app.screen = Screen::Content;
            app.selected = 0;
            app.status = "Content view".into();
        }
        KeyCode::Down | KeyCode::Char('j') if app.selected + 1 < app.access.len() => {
            app.selected += 1;
        }
        KeyCode::Up | KeyCode::Char('k') => app.selected = app.selected.saturating_sub(1),
        KeyCode::Char('n') => begin_prompt(
            app,
            Mode::EnrollAgent,
            "Enroll subject|request|SPKI|label|environment:",
        ),
        KeyCode::Char('s') => {
            write_frame(tls, &[57, u8::from(!app.suspended)])?;
            if *read_frame(tls)? != [0] {
                return Err(Failure::Unavailable);
            }
            show_access(app, tls)?;
        }
        KeyCode::Char('x') => {
            let Some(AccessEntry::Agent {
                subject, status, ..
            }) = app.access.get(app.selected)
            else {
                return Ok(());
            };
            if status != "active" {
                app.status = "Only an active generation can be revoked".into();
                return Ok(());
            }
            let mut request = vec![56];
            request.extend_from_slice(subject);
            write_frame(tls, &request)?;
            if *read_frame(tls)? != [0] {
                return Err(Failure::Unavailable);
            }
            show_access(app, tls)?;
        }
        KeyCode::Char('e') => {
            let Some(AccessEntry::Credential { item, enabled, .. }) = app.access.get(app.selected)
            else {
                return Ok(());
            };
            let mut request = vec![58];
            request.extend_from_slice(item);
            request.push(u8::from(!enabled));
            write_frame(tls, &request)?;
            if *read_frame(tls)? != [0] {
                return Err(Failure::Unavailable);
            }
            show_access(app, tls)?;
        }
        _ => {}
    }
    Ok(())
}

fn preview_plaintext_export(app: &mut App, tls: &mut HumanTls, value: &str) -> Result<(), Failure> {
    write_frame(tls, &[33, 0])?;
    let prepared = decode_prepared_response(&read_frame(tls)?)?;
    app.operation = Some(PendingOperation::PlaintextExport {
        destination: PathBuf::from(value),
        prepared,
    });
    begin_prompt(
        app,
        Mode::ConfirmPlaintextExport,
        "PLAINTEXT WARNING: persistent readable copy outside vault custody; type EXPORT:",
    );
    Ok(())
}

fn confirm_plaintext_export(app: &mut App, tls: &mut HumanTls, value: &str) -> Result<(), Failure> {
    if value != "EXPORT" {
        app.operation = None;
        app.status = "Confirmation mismatch; no plaintext created".into();
        return Ok(());
    }
    let Some(PendingOperation::PlaintextExport {
        destination,
        prepared,
    }) = app.operation.take()
    else {
        return Err(Failure::Unavailable);
    };
    let mut request = vec![33, 1];
    push_bytes(&mut request, &prepared.command)?;
    request.extend_from_slice(&prepared.signature);
    push_bytes(&mut request, &prepared.body)?;
    let bytes = rpc_download_atomic(tls, &request, &destination)?;
    app.status =
        format!("Plaintext export complete: {bytes} bytes; protect or remove it explicitly");
    show_information(app, &app.status.clone());
    Ok(())
}

fn stream_file_to_server(tls: &mut HumanTls, path: &Path) -> Result<(), Failure> {
    let mut source = File::open(path).map_err(|_| Failure::Unavailable)?;
    let mut buffer = vec![0_u8; STREAM_CHUNK_BYTES];
    loop {
        let count =
            std::io::Read::read(&mut source, &mut buffer).map_err(|_| Failure::Unavailable)?;
        if count == 0 {
            break;
        }
        write_frame(tls, &buffer[..count])?;
    }
    buffer.zeroize();
    write_frame(tls, &[0])
}

fn native_restore(app: &mut App, tls: &mut HumanTls, value: &str) -> Result<(), Failure> {
    let [path, confirmation] = split_exact::<2>(value)?;
    if &*confirmation != "RESTORE" {
        app.status = "Confirmation mismatch; vault unchanged".into();
        return Ok(());
    }
    let request = encode_secret_request(34, &app.password)?;
    write_frame(tls, &request)?;
    stream_file_to_server(tls, Path::new(&*path))?;
    let prepared = decode_prepared_response(&read_frame(tls)?)?;
    rpc_commit(tls, &prepared)?;
    refresh(app, tls)?;
    app.status = "Restore committed with new IDs/keys; current authority preserved and imported grants inactive".into();
    show_information(app, &app.status.clone());
    Ok(())
}

fn encode_secret_request(opcode: u8, value: &[u8]) -> Result<ProtectedBytes, Failure> {
    let size = 1_usize
        .checked_add(encoded_bytes_len(value)?)
        .ok_or(Failure::Unavailable)?;
    let mut request = ProtectedFrameWriter::new(size)?;
    request.fixed(&[opcode])?;
    request.bytes(value)?;
    request.finish_exact()
}

#[cfg(target_os = "linux")]
#[cfg(test)]
#[path = "tui_memory_tests.rs"]
mod memory_tests;

fn master_rotate(app: &mut App, tls: &mut HumanTls, value: &str) -> Result<(), Failure> {
    let [replacement, confirmation] = split_exact::<2>(value)?;
    if &*confirmation != "ROTATE" || replacement.is_empty() {
        drop(replacement);
        app.status = "Confirmation mismatch; master password unchanged".into();
        return Ok(());
    }
    let request = encode_secret_request(43, replacement.as_bytes())?;
    write_frame(tls, &request)?;
    drop(request);
    let prepared = decode_prepared_response(&read_frame(tls)?)?;
    rpc_commit(tls, &prepared)?;
    app.password = protected_copy(replacement.as_bytes())?;
    drop(replacement);
    app.status =
        "Master password rotated; old backups and exposed copies retain historical paths".into();
    show_information(app, &app.status.clone());
    Ok(())
}

fn query_audit(app: &mut App, tls: &mut HumanTls) -> Result<(), Failure> {
    let mut request = vec![15];
    request.extend_from_slice(&1_u64.to_be_bytes());
    request.extend_from_slice(&1_u64.to_be_bytes());
    request.extend_from_slice(&64_u32.to_be_bytes());
    write_frame(tls, &request)?;
    let response = read_frame(tls)?;
    let mut c = Cursor::new(&response);
    c.expect(&[0])?;
    let records = c.u64()?;
    let gaps = c.u64()?;
    let segments = c.u64()?;
    c.finish()?;
    app.status = format!(
        "Audit metadata: records={records} discontinuities={gaps} segments={segments}; values hidden"
    );
    show_information(app, &app.status.clone());
    Ok(())
}

fn purge_audit(app: &mut App, tls: &mut HumanTls, value: &str) -> Result<(), Failure> {
    let mut parts = value.splitn(3, ':');
    let generation = parts
        .next()
        .ok_or(Failure::Unavailable)?
        .parse::<u64>()
        .map_err(|_| Failure::Unavailable)?;
    let through = parts
        .next()
        .ok_or(Failure::Unavailable)?
        .parse::<u64>()
        .map_err(|_| Failure::Unavailable)?;
    if parts.next() != Some("PURGE AUDIT") {
        app.status = "Confirmation mismatch; audit unchanged".into();
        return Ok(());
    }
    let mut request = vec![16];
    request.extend_from_slice(&generation.to_be_bytes());
    request.extend_from_slice(&through.to_be_bytes());
    commit_request(tls, &request)?;
    app.status = format!(
        "Audit purged only generation {generation} through sequence {through}; discontinuity retained"
    );
    show_information(app, &app.status.clone());
    Ok(())
}

fn rotate_recovery(app: &mut App, tls: &mut HumanTls) -> Result<(), Failure> {
    write_frame(tls, &[44])?;
    let response = read_frame(tls)?;
    let mut c = Cursor::new(&response);
    c.expect(&[0])?;
    let code = protected_copy(c.bytes()?)?;
    c.finish()?;
    app.operation = Some(PendingOperation::RecoveryCode(code));
    begin_prompt(
        app,
        Mode::RecoveryRotate,
        "Recovery code shown temporarily; store externally, then re-enter it exactly to commit: old backups and exposed copies retain historical recovery paths.",
    );
    if let Some(PendingOperation::RecoveryCode(code)) = app.operation.as_ref() {
        app.reveal = Some((protected_copy(code)?, Instant::now() + app.reveal_for));
    }
    Ok(())
}

fn enroll_agent(app: &mut App, tls: &mut HumanTls, value: &str) -> Result<(), Failure> {
    let mut fields = value.split('|');
    let subject = decode_fixed_hex::<16>(fields.next().ok_or(Failure::Unavailable)?)?;
    let request_id = decode_fixed_hex::<16>(fields.next().ok_or(Failure::Unavailable)?)?;
    let rpk = decode_fixed_hex::<44>(fields.next().ok_or(Failure::Unavailable)?)?;
    let label = fields.next().ok_or(Failure::Unavailable)?;
    let environment = fields.next().ok_or(Failure::Unavailable)?;
    if fields.next().is_some() || label.is_empty() || environment.is_empty() {
        return Err(Failure::Unavailable);
    }
    let mut request = vec![55];
    request.extend_from_slice(&subject);
    request.extend_from_slice(&request_id);
    request.extend_from_slice(&rpk);
    push_bytes(&mut request, label.as_bytes())?;
    push_bytes(&mut request, environment.as_bytes())?;
    write_frame(tls, &request)?;
    if *read_frame(tls)? != [0] {
        return Err(Failure::Unavailable);
    }
    show_access(app, tls)
}

fn show_pending(app: &mut App, tls: &mut HumanTls) -> Result<(), Failure> {
    write_frame(tls, &[59, 0])?;
    let response = read_frame(tls)?;
    let mut cursor = Cursor::new(&response);
    cursor.expect(&[0])?;
    let count = usize::from(u16::from_be_bytes(
        cursor
            .fixed(2)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
    ));
    let mut pending = Vec::with_capacity(count);
    for _ in 0..count {
        let attempt = cursor
            .fixed(16)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?;
        let _credential = cursor.fixed(16)?;
        let owner = cursor
            .fixed(16)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?;
        let generation = cursor.u64()?;
        let agent_status = cursor.public_string()?;
        let title = cursor.public_string()?;
        let integration = cursor.public_string()?;
        let state = cursor.public_string()?;
        let reason = cursor.public_string()?;
        let expires_at_us = i64::from_be_bytes(
            cursor
                .fixed(8)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?,
        );
        let passkey = match cursor.fixed(1)? {
            [0] => None,
            [1] => Some(PasskeyConfirmation {
                request: cursor
                    .fixed(16)?
                    .try_into()
                    .map_err(|_| Failure::Unavailable)?,
                verification: match cursor.fixed(1)? {
                    [1] => 1,
                    [2] => 2,
                    _ => return Err(Failure::Unavailable),
                },
                rp: cursor.public_string()?,
                account: cursor.public_string()?,
                origin: cursor.public_string()?,
                document: cursor.public_string()?,
            }),
            _ => return Err(Failure::Unavailable),
        };
        pending.push(PendingEntry {
            attempt,
            title,
            integration,
            state,
            reason,
            expires_at_us,
            owner,
            generation,
            agent_status,
            passkey,
        });
    }
    cursor.finish()?;
    app.pending = pending;
    app.selected = 0;
    app.screen = Screen::Pending;
    app.status = format!("Pending and recent attempts: {}", app.pending.len());
    Ok(())
}

fn handle_pending_key(app: &mut App, tls: &mut HumanTls, key: KeyEvent) -> Result<(), Failure> {
    match key.code {
        KeyCode::Esc => {
            app.screen = Screen::Content;
            app.selected = 0;
            app.status = "Content view".into();
        }
        KeyCode::Down | KeyCode::Char('j') if app.selected + 1 < app.pending.len() => {
            app.selected += 1;
        }
        KeyCode::Up | KeyCode::Char('k') => app.selected = app.selected.saturating_sub(1),
        KeyCode::Char('x') => {
            let Some(entry) = app.pending.get(app.selected) else {
                return Ok(());
            };
            let mut request = vec![59, 1];
            request.extend_from_slice(&entry.attempt);
            write_frame(tls, &request)?;
            let response = read_frame(tls)?;
            let mut cursor = Cursor::new(&response);
            cursor.expect(&[0])?;
            let state = cursor.public_string()?;
            cursor.finish()?;
            show_pending(app, tls)?;
            app.status = format!("Attempt {state}");
        }
        KeyCode::Char('v') => {
            let Some(confirmation) = app
                .pending
                .get(app.selected)
                .and_then(|entry| entry.passkey.clone())
            else {
                app.status = "Selected attempt has no valid passkey prompt".into();
                return Ok(());
            };
            app.passkey_confirmation = Some(confirmation.clone());
            begin_prompt(
                app,
                Mode::ConfirmPasskeyApproval,
                &format!(
                    "RP {} account {} origin {} document {}; type APPROVE {}:",
                    sanitize_text(&confirmation.rp),
                    sanitize_text(&confirmation.account),
                    sanitize_text(&confirmation.origin),
                    sanitize_text(&confirmation.document),
                    hex(&confirmation.request)
                ),
            );
        }
        _ => {}
    }
    Ok(())
}

fn confirm_recovery_rotation(
    app: &mut App,
    tls: &mut HumanTls,
    value: &str,
) -> Result<(), Failure> {
    let Some(PendingOperation::RecoveryCode(code)) = app.operation.take() else {
        return Err(Failure::Unavailable);
    };
    if value.as_bytes() != code.as_ref() {
        // The server is waiting for the one mandatory confirmation. Send the
        // mismatch so it rejects the pending rotation rather than substituting
        // any other recovery path.
        write_frame(tls, value.as_bytes())?;
        read_frame(tls)?;
        return Err(Failure::Unavailable);
    }
    write_frame(tls, value.as_bytes())?;
    let prepared = decode_prepared_response(&read_frame(tls)?)?;
    rpc_commit(tls, &prepared)?;
    app.reveal = None;
    app.status =
        "Recovery rotated after exact re-entry; historical backups/copies remain usable".into();
    show_information(app, &app.status.clone());
    Ok(())
}

fn decode_hex_44(value: &str) -> Result<[u8; 44], Failure> {
    if value.len() != 88 {
        return Err(Failure::Unavailable);
    }
    let mut out = [0_u8; 44];
    for (index, chunk) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let text = std::str::from_utf8(chunk).map_err(|_| Failure::Unavailable)?;
        out[index] = u8::from_str_radix(text, 16).map_err(|_| Failure::Unavailable)?;
    }
    Ok(out)
}

fn create_private_output(path: &Path) -> Result<File, Failure> {
    pm_native_channel::create_private_file(path, true, true).map_err(|_| Failure::Unavailable)
}

fn pair_device(app: &mut App, tls: &mut HumanTls, value: &str) -> Result<(), Failure> {
    let [pin, path, confirmation] = split_exact::<3>(value)?;
    if &*confirmation != "PAIR" {
        app.status = "Confirmation mismatch; no pairing created".into();
        return Ok(());
    }
    let pin = decode_hex_44(&pin)?;
    let mut request = vec![60];
    request.extend_from_slice(&pin);
    write_frame(tls, &request)?;
    let response = read_frame(tls)?;
    let mut c = Cursor::new(&response);
    c.expect(&[0])?;
    let protected = c.bytes()?;
    c.finish()?;
    let mut output = create_private_output(Path::new(&*path))?;
    if output
        .write_all(protected)
        .and_then(|()| output.sync_all())
        .is_err()
    {
        fs::remove_file(&*path).map_err(|_| Failure::Unavailable)?;
        return Err(Failure::Unavailable);
    }
    app.status =
        "Protected pairing created for the exact observed RPK pin; transfer remains human custody"
            .into();
    show_information(app, &app.status.clone());
    Ok(())
}

fn sync_now(app: &mut App, tls: &mut HumanTls, value: &str) -> Result<(), Failure> {
    let [
        pairing,
        program,
        socket,
        client_key,
        server_public,
        pin,
        confirmation,
    ] = split_exact::<7>(value)?;
    if &*confirmation != "SYNC" {
        app.status = "Confirmation mismatch; sync not started".into();
        return Ok(());
    }
    if !sync_endpoint_available(Path::new(&*socket))? {
        app.status = "Sync endpoint offline; no sync was performed".into();
        return Ok(());
    }
    let protected = Zeroizing::new(fs::read(&*pairing).map_err(|_| Failure::Unavailable)?);
    let pin = decode_hex_44(&pin)?;
    let mut request = Zeroizing::new(vec![63]);
    push_bytes(&mut request, &protected)?;
    for path in [program, socket, client_key, server_public] {
        push_bytes(&mut request, path.as_bytes())?;
    }
    request.extend_from_slice(&pin);
    write_frame(tls, &request)?;
    let response = read_frame(tls)?;
    let mut c = Cursor::new(&response);
    c.expect(&[0])?;
    let job: [u8; 16] = c.fixed(16)?.try_into().map_err(|_| Failure::Unavailable)?;
    c.finish()?;
    app.sync_job = Some(job);
    app.sync_poll_at = Instant::now();
    app.status = format!(
        "Sync job {} authorized and queued; lock/idle does not retain the human root",
        hex(&job)
    );
    show_information(app, &app.status.clone());
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(clippy::unnecessary_wraps)]
fn sync_endpoint_available(path: &Path) -> Result<bool, Failure> {
    Ok(UnixStream::connect(path).is_ok())
}

#[cfg(target_os = "windows")]
fn sync_endpoint_available(path: &Path) -> Result<bool, Failure> {
    pm_native_channel::windows_named_pipe_available(path).map_err(|_| Failure::Unavailable)
}

fn select_sync_job(app: &mut App, tls: &mut HumanTls, value: &str) -> Result<(), Failure> {
    app.sync_job = Some(decode_hex_16_text(value)?);
    poll_sync(app, tls)
}

fn poll_sync(app: &mut App, tls: &mut HumanTls) -> Result<(), Failure> {
    let job = app.sync_job.ok_or(Failure::Unavailable)?;
    let mut request = vec![66];
    request.extend_from_slice(&job);
    write_frame(tls, &request)?;
    let response = read_frame(tls)?;
    let mut cursor = Cursor::new(&response);
    cursor.expect(&[0])?;
    let phase = cursor.fixed(1)?[0];
    let pushed = cursor.u64()?;
    let pulled = cursor.u64()?;
    cursor.finish()?;
    app.sync_poll_at = Instant::now();
    match phase {
        1 => app.status = format!("Sync job {} queued", hex(&job)),
        2 => app.status = format!("Sync job {} pushing ciphertext", hex(&job)),
        3 => {
            app.status = format!("Sync job {} pulling ciphertext; pushed={pushed}", hex(&job));
        }
        4 => {
            app.status = format!(
                "Sync complete through pinned TLS: job={} pushed={pushed} pulled={pulled}",
                hex(&job)
            );
            app.sync_job = None;
        }
        5 => {
            app.status = format!(
                "Sync job {} unavailable after bounded transport backoff; no success recorded",
                hex(&job)
            );
            app.sync_job = None;
        }
        6 => {
            app.status = format!(
                "Sync job {} rejected integrity; no state was accepted as success",
                hex(&job)
            );
            app.sync_job = None;
        }
        7 => {
            app.status = format!(
                "Sync job {} stopped by backpressure; no success was recorded",
                hex(&job)
            );
            app.sync_job = None;
        }
        8 => {
            app.status = format!(
                "Sync job {} journal/cleanup failed; result is not declared successful",
                hex(&job)
            );
            app.sync_job = None;
        }
        9 => {
            app.status = format!(
                "Sync job {} rejected its fixed authority/request context; no success recorded",
                hex(&job)
            );
            app.sync_job = None;
        }
        _ => return Err(Failure::Unavailable),
    }
    if app.mode == Mode::Browse {
        show_information(app, &app.status.clone());
    }
    Ok(())
}

fn decode_hex_16_text(value: &str) -> Result<[u8; 16], Failure> {
    if value.len() != 32 {
        return Err(Failure::Unavailable);
    }
    let mut out = [0_u8; 16];
    for (index, chunk) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        out[index] = u8::from_str_radix(
            std::str::from_utf8(chunk).map_err(|_| Failure::Unavailable)?,
            16,
        )
        .map_err(|_| Failure::Unavailable)?;
    }
    Ok(out)
}

fn retire_device(app: &mut App, tls: &mut HumanTls, value: &str) -> Result<(), Failure> {
    let [device, confirmation] = split_exact::<2>(value)?;
    if &*confirmation != "RETIRE" {
        app.status = "Confirmation mismatch; no device retired".into();
        return Ok(());
    }
    let mut request = vec![64];
    request.extend_from_slice(&decode_hex_16_text(&device)?);
    write_frame(tls, &request)?;
    let prepared = decode_prepared_response(&read_frame(tls)?)?;
    rpc_commit(tls, &prepared)?;
    app.status = format!(
        "Device {} retired at every locally observed prefix; later offline events are outside accepted history",
        &*device
    );
    show_information(app, &app.status.clone());
    Ok(())
}

fn select_attachment(app: &mut App, tls: &mut HumanTls) -> Result<(), Failure> {
    let entry = selected(app)?;
    if entry.trash {
        app.status = "Restore before downloading attachment".into();
        return Ok(());
    }
    let mut request = vec![61];
    request.extend_from_slice(&entry.id);
    write_frame(tls, &request)?;
    let response = read_frame(tls)?;
    let mut c = Cursor::new(&response);
    c.expect(&[0])?;
    let count = usize::from(u16::from_be_bytes(
        c.fixed(2)?.try_into().map_err(|_| Failure::Unavailable)?,
    ));
    app.attachments.clear();
    for _ in 0..count {
        app.attachments.push(AttachmentDescriptor {
            id: c.fixed(16)?.try_into().map_err(|_| Failure::Unavailable)?,
            label: c.public_string()?,
            size: c.u64()?,
        });
    }
    c.finish()?;
    if app.attachments.is_empty() {
        app.status = "Selected item has no attachments".into();
        return Ok(());
    }
    app.field_selected = 0;
    app.mode = Mode::SelectAttachment;
    app.status = "Select exact attachment descriptor; values remain hidden".into();
    Ok(())
}

fn handle_attachment_key(app: &mut App, key: KeyEvent) -> Result<(), Failure> {
    match key.code {
        KeyCode::Esc => {
            app.attachments.clear();
            app.mode = Mode::Browse;
            app.status = "Attachment download cancelled".into();
        }
        KeyCode::Down | KeyCode::Char('j') if app.field_selected + 1 < app.attachments.len() => {
            app.field_selected += 1;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.field_selected = app.field_selected.saturating_sub(1);
        }
        KeyCode::Enter => {
            let entry = selected(app)?;
            let attachment = app
                .attachments
                .get(app.field_selected)
                .ok_or(Failure::Unavailable)?
                .id;
            app.operation = Some(PendingOperation::Attachment {
                item: entry.id,
                attachment,
            });
            app.attachments.clear();
            begin_prompt(
                app,
                Mode::AttachmentPath,
                "New destination path (streamed, 0600, existing path rejected):",
            );
        }
        _ => {}
    }
    Ok(())
}

fn confirm_passkey_approval(app: &mut App, value: &str) -> Result<(), Failure> {
    let confirmation = app
        .passkey_confirmation
        .as_ref()
        .ok_or(Failure::Unavailable)?;
    if value != format!("APPROVE {}", hex(&confirmation.request)) {
        app.passkey_confirmation = None;
        app.mode = Mode::Browse;
        app.status = "Approval mismatch; nothing changed".into();
        return Ok(());
    }
    app.mode = Mode::ConfirmPasskeyPassword;
    app.status = "Master password (fresh reauthentication; input hidden):".into();
    Ok(())
}

fn confirm_passkey(tls: &mut HumanTls, confirmation: &PasskeyConfirmation) -> Result<(), Failure> {
    let mut request = vec![59, 2];
    request.extend_from_slice(&confirmation.request);
    request.push(confirmation.verification);
    write_frame(tls, &request)?;
    let response = read_frame(tls)?;
    let mut cursor = Cursor::new(&response);
    cursor.expect(&[0])?;
    let status = PasskeyStatus::from_bytes(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
    cursor.finish()?;
    if matches!(status, PasskeyStatus::Waiting(_)) {
        return Err(Failure::Unavailable);
    }
    Ok(())
}

fn lock_human_channel(tls: &mut HumanTls) -> Result<(), Failure> {
    write_frame(tls, &[14])?;
    if *read_frame(tls)? == [0] {
        Ok(())
    } else {
        Err(Failure::Unavailable)
    }
}

fn decode_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], Failure> {
    if value.len() != N * 2 {
        return Err(Failure::Unavailable);
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let at = index * 2;
        *byte = u8::from_str_radix(&value[at..at + 2], 16).map_err(|_| Failure::Unavailable)?;
    }
    Ok(output)
}

fn download_attachment(app: &mut App, tls: &mut HumanTls, value: &str) -> Result<(), Failure> {
    let Some(PendingOperation::Attachment { item, attachment }) = app.operation.take() else {
        return Err(Failure::Unavailable);
    };
    let mut request = vec![62];
    request.extend_from_slice(&item);
    request.extend_from_slice(&attachment);
    let bytes = rpc_download_atomic(tls, &request, Path::new(value))?;
    app.status = format!(
        "Attachment streamed atomically: {bytes} bytes; no human frame held the whole value"
    );
    show_information(app, &app.status.clone());
    Ok(())
}

fn read_prompt(
    terminal: &mut Terminal<CrosstermBackend<File>>,
    app: &mut App,
    secret: bool,
) -> Result<ProtectedBytes, Failure> {
    loop {
        draw(terminal, app)?;
        let Event::Key(key) = event::read().map_err(|_| Failure::Unavailable)? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match key.code {
            KeyCode::Enter if !app.input.is_empty() => {
                let value = app.input.copy_value()?;
                app.input.clear();
                return Ok(value);
            }
            KeyCode::Backspace => {
                app.input.pop();
            }
            KeyCode::Char(value) if !value.is_control() && app.input.len() < 1024 => {
                app.input.push(value);
            }
            _ => {}
        }
        if secret {
            app.status = "Password required (input hidden)".into();
        }
    }
}

fn refresh(app: &mut App, tls: &mut HumanTls) -> Result<(), Failure> {
    write_frame(tls, &[49])?;
    app.replace_catalog(decode_catalog(&read_frame(tls)?)?);
    Ok(())
}

fn decode_catalog(response: &[u8]) -> Result<Vec<CatalogEntry>, Failure> {
    let mut cursor = Cursor::new(response);
    cursor.expect(&[0])?;
    let count = usize::from(u16::from_be_bytes(
        cursor
            .fixed(2)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
    ));
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let id = cursor
            .fixed(16)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?;
        let kind = cursor.fixed(1)?[0];
        if !(1..=7).contains(&kind) {
            return Err(Failure::Unavailable);
        }
        let trash = match cursor.fixed(1)? {
            [1] => false,
            [2] => true,
            _ => return Err(Failure::Unavailable),
        };
        let favorite = match cursor.fixed(1)? {
            [0] => false,
            [1] => true,
            _ => return Err(Failure::Unavailable),
        };
        let title = cursor.public_string()?;
        let tag_count = usize::from(u16::from_be_bytes(
            cursor
                .fixed(2)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?,
        ));
        let mut tags = Vec::with_capacity(tag_count);
        for _ in 0..tag_count {
            tags.push(cursor.public_string()?);
        }
        entries.push(CatalogEntry {
            id,
            kind,
            trash,
            favorite,
            title,
            tags,
        });
    }
    cursor.finish()?;
    Ok(entries)
}

fn search(app: &mut App, tls: &mut HumanTls, text: &str) -> Result<(), Failure> {
    let mut request = vec![12];
    push_bytes(&mut request, text.as_bytes())?;
    push_bytes(&mut request, b"")?;
    request.push(0);
    write_frame(tls, &request)?;
    let response = read_frame(tls)?;
    let mut cursor = Cursor::new(&response);
    cursor.expect(&[0])?;
    let count = usize::from(u16::from_be_bytes(
        cursor
            .fixed(2)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
    ));
    let mut ids = Vec::with_capacity(count);
    for _ in 0..count {
        ids.push(cursor.fixed(16)?.to_vec());
    }
    cursor.finish()?;
    app.visible = app
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| ids.iter().any(|id| id == entry.id.as_slice()))
        .map(|(index, _)| index)
        .collect();
    app.selected = 0;
    app.status = format!("Search returned {} active items", app.visible.len());
    Ok(())
}

fn selected(app: &App) -> Result<CatalogEntry, Failure> {
    app.selected_entry().cloned().ok_or(Failure::Unavailable)
}

fn organize(app: &mut App, tls: &mut HumanTls, replacement: Option<String>) -> Result<(), Failure> {
    let entry = selected(app)?;
    if entry.trash {
        app.status = "Restore before organizing".into();
        return Ok(());
    }
    let tags = replacement
        .map(|tag| {
            if tag.is_empty() {
                Vec::new()
            } else {
                vec![tag]
            }
        })
        .unwrap_or(entry.tags);
    let favorite = entry.favorite;
    let mut request = vec![11];
    request.extend_from_slice(&entry.id);
    request.push(u8::from(favorite));
    request.extend_from_slice(
        &u16::try_from(tags.len())
            .map_err(|_| Failure::Unavailable)?
            .to_be_bytes(),
    );
    for tag in &tags {
        push_bytes(&mut request, tag.as_bytes())?;
    }
    commit_request(tls, &request)?;
    refresh(app, tls)?;
    app.status = "Organization committed".into();
    Ok(())
}

fn toggle_favorite(app: &mut App, tls: &mut HumanTls) -> Result<(), Failure> {
    let entry = selected(app)?;
    if entry.trash {
        app.status = "Restore before organizing".into();
        return Ok(());
    }
    let mut request = vec![11];
    request.extend_from_slice(&entry.id);
    request.push(u8::from(!entry.favorite));
    request.extend_from_slice(
        &u16::try_from(entry.tags.len())
            .map_err(|_| Failure::Unavailable)?
            .to_be_bytes(),
    );
    for tag in &entry.tags {
        push_bytes(&mut request, tag.as_bytes())?;
    }
    commit_request(tls, &request)?;
    refresh(app, tls)?;
    app.status = "Favorite committed".into();
    Ok(())
}

fn commit_request(tls: &mut HumanTls, request: &[u8]) -> Result<(), Failure> {
    write_frame(tls, request)?;
    let prepared = decode_prepared_response(&read_frame(tls)?)?;
    rpc_commit(tls, &prepared).map(|_| ())
}

fn show_history(app: &mut App, tls: &mut HumanTls) -> Result<(), Failure> {
    let entry = selected(app)?;
    let history = rpc_history(tls, entry.id)?;
    app.status = format!(
        "History: {} retained revisions; lifecycle {}",
        history.entries.len(),
        if history.lifecycle == 1 {
            "active"
        } else {
            "trash"
        }
    );
    show_information(app, &app.status.clone());
    Ok(())
}

fn trash(app: &mut App, tls: &mut HumanTls) -> Result<(), Failure> {
    let entry = selected(app)?;
    if entry.trash {
        app.status = "Already in trash".into();
        return Ok(());
    }
    let mut request = vec![4];
    request.extend_from_slice(&entry.id);
    commit_request(tls, &request)?;
    refresh(app, tls)?;
    app.status = "Moved to trash".into();
    Ok(())
}

fn restore(app: &mut App, tls: &mut HumanTls) -> Result<(), Failure> {
    let entry = selected(app)?;
    if !entry.trash {
        app.status = "Item is active".into();
        return Ok(());
    }
    let history = rpc_history(tls, entry.id)?;
    let revision = history
        .entries
        .iter()
        .find(|value| value.visible)
        .ok_or(Failure::Unavailable)?
        .revision_id;
    let prepared = rpc_prepare_restore(tls, entry.id, revision)?;
    rpc_commit(tls, &prepared)?;
    refresh(app, tls)?;
    app.status = "Restored with a new revision".into();
    Ok(())
}

fn purge_revisions(app: &mut App, tls: &mut HumanTls) -> Result<(), Failure> {
    let entry = selected(app)?;
    let history = rpc_history(tls, entry.id)?;
    let revisions: Vec<_> = history
        .entries
        .iter()
        .filter(|value| !value.visible)
        .map(|value| value.revision_id)
        .collect();
    if revisions.is_empty() {
        app.status = "No non-visible revisions to purge".into();
        return Ok(());
    }
    let purge = rpc_prepare_purge_revisions(tls, entry.id, &revisions)?;
    if purge.terminal {
        return Err(Failure::Unavailable);
    }
    rpc_commit(tls, &purge.prepared)?;
    app.status = format!("Purged {} old revisions", revisions.len());
    Ok(())
}

fn purge_item(app: &mut App, tls: &mut HumanTls) -> Result<(), Failure> {
    let entry = selected(app)?;
    if !entry.trash {
        app.status = "Permanent purge requires trash".into();
        return Ok(());
    }
    let purge = rpc_prepare_purge_item(tls, entry.id)?;
    if !purge.terminal {
        return Err(Failure::Unavailable);
    }
    rpc_commit(tls, &purge.prepared)?;
    refresh(app, tls)?;
    app.status = "Item permanently purged".into();
    Ok(())
}

fn generate(app: &mut App, tls: &mut HumanTls, value: &str) -> Result<(), Failure> {
    let length: u16 = value.parse().map_err(|_| Failure::Unavailable)?;
    let mut request = vec![50];
    request.extend_from_slice(&length.to_be_bytes());
    request.push(0b1111);
    write_frame(tls, &request)?;
    let secret = expect_secret(&read_frame(tls)?)?;
    app.reveal = Some((secret, Instant::now() + app.reveal_for));
    app.status = "Generated secret revealed temporarily".into();
    Ok(())
}

fn select_exposure_field(app: &mut App, tls: &mut HumanTls, copy: bool) -> Result<(), Failure> {
    let entry = selected(app)?;
    if entry.trash {
        app.status = "Restore before exposing content".into();
        return Ok(());
    }
    let mut request = vec![51];
    request.extend_from_slice(&entry.id);
    write_frame(tls, &request)?;
    app.fields = decode_field_catalog(&read_frame(tls)?)?;
    if app.fields.is_empty() {
        return Err(Failure::Unavailable);
    }
    app.field_selected = 0;
    app.field_copy = copy;
    app.mode = Mode::SelectField;
    app.status = if copy {
        "Select exact field to copy; Enter confirms".into()
    } else {
        "Select exact field to reveal; Enter confirms".into()
    };
    Ok(())
}

fn handle_field_key(app: &mut App, tls: &mut HumanTls, key: KeyEvent) -> Result<(), Failure> {
    match key.code {
        KeyCode::Esc => {
            app.fields.clear();
            app.mode = Mode::Browse;
            app.status = "Exposure cancelled".into();
        }
        KeyCode::Down | KeyCode::Char('j') if app.field_selected + 1 < app.fields.len() => {
            app.field_selected += 1;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.field_selected = app.field_selected.saturating_sub(1);
        }
        KeyCode::Enter => expose_selected_field(app, tls)?,
        _ => {}
    }
    Ok(())
}

fn expose_selected_field(app: &mut App, tls: &mut HumanTls) -> Result<(), Failure> {
    let entry = selected(app)?;
    let copy = app.field_copy;
    let field = u16::try_from(app.field_selected).map_err(|_| Failure::Unavailable)?;
    if copy {
        #[cfg(target_os = "linux")]
        validate_wl_copy()?;
    }
    let mut request = vec![if copy { 53 } else { 52 }];
    request.extend_from_slice(&entry.id);
    request.extend_from_slice(&field.to_be_bytes());
    write_frame(tls, &request)?;
    let secret = expect_secret(&read_frame(tls)?)?;
    app.fields.clear();
    app.mode = Mode::Browse;
    if copy {
        if let Some(mut old) = app.clipboard.take() {
            old.stop_if_owner()?;
        }
        app.clipboard = Some(copy_secret(&secret, app.copy_for)?);
        app.status =
            "Copied explicitly; clipboard managers may retain data beyond our control".into();
    } else {
        app.reveal = Some((secret, Instant::now() + app.reveal_for));
        app.status = "Secret revealed temporarily".into();
    }
    Ok(())
}

fn decode_field_catalog(response: &[u8]) -> Result<Vec<FieldDescriptor>, Failure> {
    let mut cursor = Cursor::new(response);
    cursor.expect(&[0])?;
    let count = usize::from(u16::from_be_bytes(
        cursor
            .fixed(2)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?,
    ));
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        fields.push(FieldDescriptor {
            label: cursor.public_string()?,
            size: cursor.u64()?,
        });
    }
    cursor.finish()?;
    Ok(fields)
}

fn expect_secret(response: &[u8]) -> Result<ProtectedBytes, Failure> {
    let mut cursor = Cursor::new(response);
    cursor.expect(&[0])?;
    let value = protected_copy(cursor.bytes()?)?;
    cursor.finish()?;
    Ok(value)
}

#[cfg(target_os = "linux")]
fn validate_wl_copy() -> Result<(), Failure> {
    let path = PathBuf::from(WL_COPY);
    let metadata = fs::symlink_metadata(&path).map_err(|_| Failure::Unavailable)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || fs::canonicalize(&path).map_err(|_| Failure::Unavailable)? != path
    {
        return Err(Failure::Unavailable);
    }
    let output = Command::new(WL_COPY)
        .arg("--version")
        .env_clear()
        .output()
        .map_err(|_| Failure::Unavailable)?;
    if !output.status.success() || !output.stdout.starts_with(b"wl-clipboard 2.3.0\n") {
        return Err(Failure::Unavailable);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn copy_secret(secret: &[u8], duration: Duration) -> Result<ClipboardLease, Failure> {
    let mut child = Command::new(WL_COPY)
        .args([
            "--foreground",
            "--sensitive",
            "--type",
            "application/octet-stream",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Failure::Unavailable)?;
    let Some(mut stdin) = child.stdin.take() else {
        let _cleanup = stop_clipboard_with(&mut child);
        return Err(Failure::Unavailable);
    };
    if stdin.write_all(secret).is_err() {
        let _cleanup = stop_clipboard_with(&mut child);
        return Err(Failure::Unavailable);
    }
    Ok(ClipboardLease {
        backend: ClipboardBackend::Wayland(child),
        until: Instant::now() + duration,
        cleanup_attempted: false,
    })
}

#[cfg(target_os = "macos")]
fn copy_secret(secret: &[u8], duration: Duration) -> Result<ClipboardLease, Failure> {
    let owner = OwnedClipboard::copy(secret).map_err(|_| Failure::Unavailable)?;
    Ok(ClipboardLease {
        backend: ClipboardBackend::AppKit(Some(owner)),
        until: Instant::now() + duration,
        cleanup_attempted: false,
    })
}

#[cfg(target_os = "windows")]
fn copy_secret(secret: &[u8], duration: Duration) -> Result<ClipboardLease, Failure> {
    let owned =
        pm_native_channel::OwnedClipboard::copy(secret).map_err(|_| Failure::Unavailable)?;
    Ok(ClipboardLease {
        backend: ClipboardBackend::Windows(Some(owned)),
        until: Instant::now() + duration,
        cleanup_attempted: false,
    })
}

fn draw(terminal: &mut Terminal<CrosstermBackend<File>>, app: &mut App) -> Result<(), Failure> {
    let completed = terminal
        .draw(|frame| {
            render_app(frame, app);
        })
        .map_err(|_| Failure::Unavailable)?;
    #[cfg(windows)]
    if let Some(mut probe) = app.initial_diagnostic.take() {
        probe.frame(completed.buffer)?;
        probe.record("after-draw")?;
        app.csv_diagnostic = Some(probe);
    }
    #[cfg(windows)]
    if app.mode == Mode::CsvImport && app.input.ends_with("keep") {
        if let Some(mut probe) = app.csv_diagnostic.take() {
            probe.csv_frame(
                completed.buffer,
                app.input.ends_with("|chrome|keep"),
                Line::raw(app.input.as_str()).width(),
                Line::raw(app.status.as_str()).width(),
            )?;
        }
    }
    #[cfg(not(windows))]
    let _ = completed;
    Ok(())
}

fn render_app(frame: &mut ratatui::Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(6),
        ])
        .split(frame.area());
    let title = Paragraph::new("Password Manager — human TLS-RPK content")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);
    if app.information.is_some() {
        render_information(frame, chunks[1], app);
    } else {
        render_catalog(frame, chunks[1], app);
    }
    render_footer(frame, chunks[2], app);
}

fn catalog_rows(app: &App) -> Vec<ListItem<'static>> {
    app.visible
        .iter()
        .filter_map(|index| app.entries.get(*index))
        .map(|entry| {
            let marker = if entry.trash { "trash" } else { "active" };
            ListItem::new(Line::from(vec![
                Span::raw(if entry.favorite { "★ " } else { "  " }),
                Span::styled(
                    format!("[{}] ", kind_label(entry.kind)),
                    Style::default().fg(Color::Yellow),
                ),
                Span::raw(sanitize_text(&entry.title)),
                Span::raw(format!("  ({marker})")),
            ]))
        })
        .collect()
}

fn render_catalog(frame: &mut ratatui::Frame, area: ratatui::layout::Rect, app: &App) {
    let content_rows = catalog_rows(app);
    let (rows, selected, list_title) = if app.mode == Mode::SelectField {
        let fields = app
            .fields
            .iter()
            .map(|field| {
                ListItem::new(format!(
                    "{} ({} bytes)",
                    sanitize_text(&field.label),
                    field.size
                ))
            })
            .collect();
        (
            fields,
            app.field_selected,
            "Fields (explicit selection; values hidden)",
        )
    } else if app.mode == Mode::SelectAttachment {
        let attachments = app
            .attachments
            .iter()
            .map(|attachment| {
                ListItem::new(format!(
                    "{} ({} bytes)",
                    sanitize_text(&attachment.label),
                    attachment.size
                ))
            })
            .collect();
        (
            attachments,
            app.field_selected,
            "Attachments (exact descriptor; values hidden)",
        )
    } else {
        match app.screen {
            Screen::Content => (
                content_rows,
                app.selected,
                "Items (selection is metadata only)",
            ),
            Screen::Access => {
                let rows = app
                    .access
                    .iter()
                    .map(|entry| match entry {
                        AccessEntry::Agent {
                            subject,
                            generation,
                            label,
                            environment,
                            status,
                        } => ListItem::new(format!(
                            "[agent {status}] {} generation={generation} environment={} subject={}",
                            sanitize_text(label),
                            sanitize_text(environment),
                            hex(subject),
                        )),
                        AccessEntry::Credential {
                            item,
                            title,
                            enabled,
                        } => ListItem::new(format!(
                            "[credential {}] {} item={}",
                            if *enabled { "enabled" } else { "disabled" },
                            sanitize_text(title),
                            hex(item),
                        )),
                    })
                    .collect();
                (rows, app.selected, "Delegated authority (metadata only)")
            }
            Screen::Pending => {
                let rows = app.pending.iter().map(|entry| {
                        let passkey = entry.passkey.as_ref().map_or("", |_| " passkey-confirmation");
                        ListItem::new(format!(
                            "[{}] {} integration={} reason={} expires={} agent={}/{} status={} attempt={}{}",
                            sanitize_text(&entry.state), sanitize_text(&entry.title), sanitize_text(&entry.integration),
                            sanitize_text(&entry.reason), entry.expires_at_us, hex(&entry.owner), entry.generation,
                            sanitize_text(&entry.agent_status), hex(&entry.attempt), passkey,
                        ))
                    }).collect();
                (rows, app.selected, "Attempts (safe context only)")
            }
        }
    };
    let mut state = ListState::default();
    if !rows.is_empty() {
        state.select(Some(selected));
    }
    frame.render_stateful_widget(
        List::new(rows)
            .highlight_symbol("› ")
            .block(Block::default().title(list_title).borders(Borders::ALL)),
        area,
        &mut state,
    );
}

fn show_information(app: &mut App, information: &str) {
    app.information = Some(information.to_owned());
    app.information_scroll = 0;
    app.status = "Review information in panel; PgUp/PgDn scroll".into();
}

fn scroll_information(app: &mut App, key: KeyCode) -> bool {
    if app.information.is_none() {
        return false;
    }
    match key {
        KeyCode::PageDown => app.information_scroll = app.information_scroll.saturating_add(1),
        KeyCode::PageUp => app.information_scroll = app.information_scroll.saturating_sub(1),
        _ => return false,
    }
    true
}

// Wrap whole words where possible, splitting long words only at grapheme
// boundaries. At the 80-column floor every grapheme fits; no Ratatui reflow
// omission or ellipsis is used for this contractual information.
fn information_lines(information: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut occupied = 0;
    for word in information.split_whitespace() {
        let word_width = Line::raw(word).width();
        if occupied > 0 && occupied + 1 + word_width > width {
            lines.push(std::mem::take(&mut line));
            occupied = 0;
        }
        if occupied > 0 {
            line.push(' ');
            occupied += 1;
        }
        let span = Span::raw(word);
        for grapheme in span.styled_graphemes(Style::default()) {
            let cells = Line::raw(grapheme.symbol).width();
            if occupied + cells > width {
                lines.push(std::mem::take(&mut line));
                occupied = 0;
            }
            line.push_str(grapheme.symbol);
            occupied += cells;
        }
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

fn render_information(frame: &mut ratatui::Frame, area: ratatui::layout::Rect, app: &mut App) {
    let block = Block::default().borders(Borders::ALL);
    let inner = block.inner(area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    let mut lines = information_lines(
        &sanitize_text(
            app.information
                .as_deref()
                .expect("information panel selected"),
        ),
        usize::from(inner.width),
    );
    if app.mode == Mode::RecoveryRotate {
        let code = app
            .reveal
            .as_ref()
            .map_or_else(|| "<hidden>".into(), |(code, _)| display_secret(code));
        lines.push("Recovery code:".into());
        lines.extend(information_lines(&code, usize::from(inner.width)));
    }
    let height = usize::from(inner.height);
    app.information_scroll = app
        .information_scroll
        .min(lines.len().saturating_sub(height));
    let start = app.information_scroll;
    let end = (start + height).min(lines.len());
    let title = if lines.len() > height {
        format!(
            "Information {}-{} / {} — PgUp/PgDn",
            start + 1,
            end,
            lines.len()
        )
    } else {
        "Information".into()
    };
    frame.render_widget(block.title(title), area);
    // Render already-wrapped rows individually; do not let reflow truncate or
    // skip a glyph. Resize clamps the viewport while retaining every row.
    for (offset, line) in lines[start..end].iter().enumerate() {
        let row = ratatui::layout::Rect::new(
            inner.x,
            inner.y + u16::try_from(offset).expect("panel row fits"),
            inner.width,
            1,
        );
        frame.render_widget(Paragraph::new(line.as_str()), row);
    }
}

fn render_footer(frame: &mut ratatui::Frame, area: ratatui::layout::Rect, app: &App) {
    let block = Block::default().borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
    ])
    .split(inner);
    let status = ellipsize_status(&sanitize_text(&app.status), usize::from(inner.width));
    frame.render_widget(Paragraph::new(status), rows[0]);

    let prompt = if matches!(
        app.mode,
        Mode::Unlock | Mode::ConfirmPasskeyPassword | Mode::MasterRotate | Mode::RecoveryRotate
    ) {
        "•".repeat(app.input.chars().count())
    } else {
        sanitize_text(&app.input)
    };
    // Reserve one cell after the representation so the insertion cursor never
    // covers its final glyph or the border. Editing currently occurs at the end.
    let prefix = "Input: ";
    let available = usize::from(rows[1].width).saturating_sub(prefix.len() + 1);
    let visible = input_suffix(&prompt, available);
    let cursor_offset = Line::raw(format!("{prefix}{visible}")).width();
    frame.render_widget(Paragraph::new(format!("{prefix}{visible}")), rows[1]);
    if rows[1].height > 0 && cursor_offset < usize::from(rows[1].width) {
        let offset = u16::try_from(cursor_offset).expect("cursor is within the u16 row width");
        frame.set_cursor_position((rows[1].x + offset, rows[1].y));
    }

    let exposure = app
        .reveal
        .as_ref()
        .filter(|_| app.mode != Mode::RecoveryRotate)
        .map_or_else(|| "<hidden>".into(), |(secret, _)| display_secret(secret));
    let controls = match app.screen {
        Screen::Content => {
            "↑↓/jk select  / search  t tag  f favorite  g generate  h history  d trash  u restore  p/P purge  r reveal  c copy  a access  w pending  m migrate  b backup  y sync  z audit  D download  l lock  q quit"
        }
        Screen::Access => {
            "↑↓/jk select  n enroll  s suspend/resume  x revoke agent  e enable/disable credential  Esc content"
        }
        Screen::Pending => "↑↓/jk select  x cancel  v confirm passkey  Esc content",
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(format!("Exposure: {exposure}")),
            Line::from(controls),
        ])
        .wrap(Wrap { trim: true }),
        rows[2],
    );
}

fn input_suffix(prompt: &str, width: usize) -> String {
    if Line::raw(prompt).width() <= width {
        return prompt.to_owned();
    }
    let span = Span::raw(prompt);
    let graphemes = span.styled_graphemes(Style::default()).collect::<Vec<_>>();
    let mut occupied = 1; // The left-hidden marker is one screen cell.
    let mut first = graphemes.len();
    for (index, grapheme) in graphemes.iter().enumerate().rev() {
        let cells = Line::raw(grapheme.symbol).width();
        if occupied + cells > width {
            break;
        }
        occupied += cells;
        first = index;
    }
    let mut visible = String::from("‹");
    for grapheme in &graphemes[first..] {
        visible.push_str(grapheme.symbol);
    }
    visible
}

fn ellipsize_status(status: &str, width: usize) -> String {
    if Line::raw(status).width() <= width {
        return status.to_owned();
    }
    let span = Span::raw(status);
    let mut visible = String::new();
    let mut occupied = 1; // The ellipsis is one screen cell.
    for grapheme in span.styled_graphemes(Style::default()) {
        let cells = Line::raw(grapheme.symbol).width();
        if occupied + cells > width {
            break;
        }
        occupied += cells;
        visible.push_str(grapheme.symbol);
    }
    visible.push('…');
    visible
}

fn display_secret(value: &[u8]) -> String {
    std::str::from_utf8(value).map_or_else(
        |_| format!("<binary secret: {} bytes>", value.len()),
        sanitize_text,
    )
}

fn sanitize_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .collect()
}

const fn kind_label(kind: u8) -> &'static str {
    match kind {
        1 => "password",
        2 => "totp",
        3 => "passkey",
        4 => "ssh",
        5 => "token",
        6 => "note",
        7 => "file",
        _ => "invalid",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ratatui::backend::TestBackend;

    fn render_test_footer(terminal: &mut Terminal<TestBackend>, app: &App) {
        terminal
            .draw(|frame| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3),
                        Constraint::Min(5),
                        Constraint::Length(6),
                    ])
                    .split(frame.area());
                render_footer(frame, chunks[2], app);
            })
            .unwrap();
    }

    fn footer_app(input: &str) -> App {
        let mut app = App::new(
            Duration::from_secs(300),
            Duration::from_secs(15),
            Duration::from_secs(30),
        )
        .expect("protected footer fixture");
        app.mode = Mode::CsvImport;
        for character in input.chars() {
            app.input.push(character);
        }
        app.status =
            "CSV source path|chrome|keep with synthetic mapping and confirmation before importing"
                .into();
        app
    }

    fn footer_row(terminal: &Terminal<TestBackend>, y: u16) -> String {
        let buffer = terminal.backend().buffer();
        (1..79)
            .map(|x| buffer[(x, y)].symbol())
            .collect::<String>()
            .trim_end()
            .to_owned()
    }

    #[test]
    fn footer_long_input_keeps_suffix_and_cursor_at_80x24() {
        let input = format!("{}|chrome|keep", "synthetic-path/".repeat(8));
        let app = footer_app(&input);
        assert!(app.input.ends_with("|chrome|keep"));
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        render_test_footer(&mut terminal, &app);
        let expected = format!("Input: ‹{}", &input[input.len() - 69..]);
        assert_eq!(footer_row(&terminal, 20), expected);
        assert_eq!(terminal.get_cursor_position().unwrap(), (78, 20).into());
        assert!(footer_row(&terminal, 19).ends_with('…'));
        assert_eq!(footer_row(&terminal, 21), "Exposure: <hidden>");
    }

    #[test]
    fn footer_exact_input_width_and_one_more_cell() {
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        for (length, expected) in [
            (70, format!("Input: {}", "a".repeat(70))),
            (71, format!("Input: ‹{}", "a".repeat(69))),
        ] {
            render_test_footer(&mut terminal, &footer_app(&"a".repeat(length)));
            assert_eq!(footer_row(&terminal, 20), expected);
            assert_eq!(terminal.get_cursor_position().unwrap(), (78, 20).into());
        }
    }

    #[test]
    fn footer_wide_glyph_at_the_edge_is_never_split_or_omitted() {
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        for (length, expected) in [
            (68, format!("Input: {}界", "a".repeat(68))),
            (69, format!("Input: ‹{}界", "a".repeat(67))),
        ] {
            render_test_footer(
                &mut terminal,
                &footer_app(&format!("{}界", "a".repeat(length))),
            );
            assert!(footer_row(&terminal, 20).starts_with(&expected));
            assert_eq!(terminal.backend().buffer()[(76, 20)].symbol(), "界");
            assert_eq!(terminal.backend().buffer()[(78, 20)].symbol(), " ");
            assert_eq!(terminal.get_cursor_position().unwrap(), (78, 20).into());
        }
    }

    #[test]
    fn footer_combining_graphemes_scroll_as_screen_cells() {
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        for (length, expected) in [
            (70, format!("Input: {}", "e\u{301}".repeat(70))),
            (71, format!("Input: ‹{}", "e\u{301}".repeat(69))),
        ] {
            render_test_footer(&mut terminal, &footer_app(&"e\u{301}".repeat(length)));
            assert_eq!(footer_row(&terminal, 20), expected);
            assert_eq!(terminal.get_cursor_position().unwrap(), (78, 20).into());
        }
    }

    #[test]
    fn footer_secret_scroll_only_renders_the_existing_mask() {
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        for mode in [
            Mode::Unlock,
            Mode::ConfirmPasskeyPassword,
            Mode::MasterRotate,
            Mode::RecoveryRotate,
        ] {
            let mut app = footer_app(&"synthetic-secret-界e\u{301}".repeat(8));
            app.mode = mode;
            render_test_footer(&mut terminal, &app);
            assert_eq!(
                footer_row(&terminal, 20),
                format!("Input: ‹{}", "•".repeat(69))
            );
            assert!(!format!("{:?}", terminal.backend().buffer()).contains("synthetic-secret"));
            assert_eq!(terminal.get_cursor_position().unwrap(), (78, 20).into());
        }
    }

    #[test]
    fn footer_long_status_cannot_overwrite_input_and_preserves_graphemes() {
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let mut app = footer_app("typed-suffix");
        app.status = format!("{}界e\u{301}tail", "s".repeat(75));
        render_test_footer(&mut terminal, &app);
        assert!(footer_row(&terminal, 19).starts_with(&"s".repeat(75)));
        assert_eq!(terminal.backend().buffer()[(76, 19)].symbol(), "界");
        assert_eq!(terminal.backend().buffer()[(78, 19)].symbol(), "…");
        assert_eq!(footer_row(&terminal, 20), "Input: typed-suffix");
        assert_eq!(terminal.get_cursor_position().unwrap(), (20, 20).into());
    }

    #[test]
    fn footer_resize_recomputes_scroll_at_80x24() {
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        let app = footer_app(&format!("{}|chrome|keep", "synthetic/".repeat(9)));
        render_test_footer(&mut terminal, &app);
        terminal.backend_mut().resize(80, 24);
        terminal.autoresize().unwrap();
        render_test_footer(&mut terminal, &app);
        assert!(footer_row(&terminal, 20).ends_with("|chrome|keep"));
        assert!(footer_row(&terminal, 20).starts_with("Input: ‹"));
        assert_eq!(terminal.get_cursor_position().unwrap(), (78, 20).into());
        assert!(footer_row(&terminal, 19).ends_with('…'));
    }

    fn render_test_app(terminal: &mut Terminal<TestBackend>, app: &mut App) {
        terminal.draw(|frame| render_app(frame, app)).unwrap();
    }

    fn panel_text(terminal: &Terminal<TestBackend>) -> String {
        let buffer = terminal.backend().buffer();
        let area = buffer.area;
        (4..area.height - 7)
            .map(|y| {
                (1..area.width - 1)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn information_import_counters_are_complete_in_panel_at_80x24() {
        let mut app = footer_app("IMPORT");
        let summary = "Mapping=chrome duplicate-action=keep; Preview values hidden: total=1 new=0 replaced=0 exact-duplicates=1 excluded=0 preserved-fields=3 pages=1; type IMPORT to commit";
        begin_prompt(&mut app, Mode::ConfirmImport, summary);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        render_test_app(&mut terminal, &mut app);
        let panel = panel_text(&terminal);
        for token in [
            "Mapping=chrome",
            "duplicate-action=keep;",
            "total=1",
            "new=0",
            "replaced=0",
            "exact-duplicates=1",
            "excluded=0",
            "preserved-fields=3",
            "pages=1;",
            "type IMPORT to commit",
        ] {
            assert!(
                panel
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .contains(token),
                "missing mandatory token: {token}"
            );
        }
        assert_eq!(footer_row(&terminal, 21), "Exposure: <hidden>");
    }

    #[test]
    fn information_long_counters_survive_resize_in_panel() {
        let mut app = footer_app("");
        let summary = "Preview values hidden: total=18446744073709551615 new=18446744073709551615 replaced=18446744073709551615 exact-duplicates=18446744073709551615 excluded=18446744073709551615 preserved-fields=18446744073709551615 pages=18446744073709551615; type IMPORT to commit";
        begin_prompt(&mut app, Mode::ConfirmImport, summary);
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        render_test_app(&mut terminal, &mut app);
        terminal.backend_mut().resize(80, 24);
        terminal.autoresize().unwrap();
        render_test_app(&mut terminal, &mut app);
        let panel = panel_text(&terminal);
        for key in [
            "total",
            "new",
            "replaced",
            "exact-duplicates",
            "excluded",
            "preserved-fields",
            "pages",
        ] {
            assert!(
                panel.contains(&format!("{key}=18446744073709551615")),
                "missing {key}"
            );
        }
    }

    #[test]
    fn information_mandatory_confirmation_warnings_are_in_panel() {
        let mut app = footer_app("");
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        for (mode, warning) in [
            (
                Mode::ConfirmPlaintextExport,
                "PLAINTEXT WARNING: persistent readable copy outside vault custody; type EXPORT:",
            ),
            (
                Mode::MasterRotate,
                "New master password|ROTATE (old backups and exposed copies retain historical recovery paths):",
            ),
            (
                Mode::NativeRestore,
                "Archive path|RESTORE (adds new IDs/keys; current authority is preserved):",
            ),
            (
                Mode::ConfirmPurgeItem,
                "Type PURGE to permanently delete trashed item:",
            ),
            (
                Mode::RecoveryRotate,
                "Recovery code shown temporarily; store externally, then re-enter it exactly to commit: old backups and exposed copies retain historical recovery paths.",
            ),
        ] {
            begin_prompt(&mut app, mode, warning);
            render_test_app(&mut terminal, &mut app);
            assert_eq!(
                panel_text(&terminal).split_whitespace().collect::<Vec<_>>(),
                format!(
                    "{warning}{}",
                    if mode == Mode::RecoveryRotate {
                        " Recovery code: <hidden>"
                    } else {
                        ""
                    }
                )
                .split_whitespace()
                .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn information_scroll_preserves_all_rows_and_input_after_resize() {
        let mut app = footer_app("typed-confirmation");
        let text = (0..80)
            .map(|i| format!("counter-{i}=18446744073709551615"))
            .collect::<Vec<_>>()
            .join(" ");
        begin_prompt(&mut app, Mode::ConfirmImport, &text);
        app.input.push('I');
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let mut observed = String::new();
        for _ in 0..80 {
            render_test_app(&mut terminal, &mut app);
            observed.push_str(&panel_text(&terminal));
            assert_eq!(footer_row(&terminal, 20), "Input: I");
            assert!(scroll_information(&mut app, KeyCode::PageDown));
        }
        for i in 0..80 {
            assert!(observed.contains(&format!("counter-{i}=18446744073709551615")));
        }
        assert!(format!("{:?}", terminal.backend().buffer()).contains("PgUp/PgDn"));
        terminal.backend_mut().resize(100, 60);
        terminal.autoresize().unwrap();
        render_test_app(&mut terminal, &mut app);
        assert_eq!(app.information_scroll, 0);
        assert!(panel_text(&terminal).contains("counter-79=18446744073709551615"));
        assert!(scroll_information(&mut app, KeyCode::PageUp));
        assert_eq!(app.information_scroll, 0);
        assert!(!scroll_information(&mut app, KeyCode::Enter));
        assert!(app.mode == Mode::ConfirmImport);
        assert_eq!(app.input.as_str(), "I");
    }

    #[test]
    fn information_exact_width_wide_and_combining_glyphs_are_not_lost() {
        let mut app = footer_app("");
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        for text in [
            format!("{}界", "a".repeat(76)),
            format!("{}界e\u{301}Z", "a".repeat(77)),
        ] {
            begin_prompt(&mut app, Mode::ConfirmImport, &text);
            render_test_app(&mut terminal, &mut app);
            let buffer = terminal.backend().buffer();
            let actual = (4..17)
                .flat_map(|y| (1..79).map(move |x| buffer[(x, y)].symbol()))
                .filter(|s| *s != " ")
                .collect::<String>();
            assert_eq!(actual, text);
        }
        assert_eq!(terminal.backend().buffer()[(1, 5)].symbol(), "界");
        assert_eq!(terminal.backend().buffer()[(3, 5)].symbol(), "e\u{301}");
    }

    #[test]
    fn information_recovery_is_explicit_temporary_and_does_not_copy_secret_input() {
        let mut app = footer_app("");
        begin_prompt(
            &mut app,
            Mode::RecoveryRotate,
            "Store externally; historical copies remain usable; re-enter exactly",
        );
        for c in "synthetic-secret-input-canary".chars() {
            app.input.push(c);
        }
        app.password = protected_copy(b"synthetic-master-canary").unwrap();
        app.reveal = Some((
            protected_copy(b"PMR1-synthetic-recovery-canary").unwrap(),
            Instant::now() + Duration::from_secs(1),
        ));
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        render_test_app(&mut terminal, &mut app);
        assert!(
            panel_text(&terminal)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .contains("Recovery code: PMR1-synthetic-recovery-canary")
        );
        let all = format!("{:?}", terminal.backend().buffer());
        assert!(!all.contains("synthetic-secret-input-canary"));
        assert!(!all.contains("synthetic-master-canary"));
        assert_eq!(footer_row(&terminal, 21), "Exposure: <hidden>");
        app.reveal.as_mut().unwrap().1 = Instant::now();
        app.expire();
        render_test_app(&mut terminal, &mut app);
        assert!(!panel_text(&terminal).contains("PMR1-synthetic-recovery-canary"));
        assert!(
            panel_text(&terminal)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .contains("Recovery code: <hidden>")
        );
        assert!(panel_text(&terminal).contains("historical copies remain usable"));
    }

    fn arguments<'a>(values: &'a [&'a str]) -> impl Iterator<Item = OsString> + 'a {
        values.iter().map(OsString::from)
    }

    #[cfg(windows)]
    #[test]
    fn windows_tui_arguments_match_the_native_harness() {
        let mut values = arguments(&[
            "--profile",
            r"C:\fixture\human.profile",
            "--private",
            r"C:\fixture\human.key",
            "--vault-id",
            "0123456789abcdef0123456789abcdef",
            "--idle-seconds",
            "300",
            "--reveal-seconds",
            "15",
            "--copy-seconds",
            "30",
        ]);
        let parsed = parse_arguments(&mut values).unwrap();
        assert_eq!(
            parsed.endpoint,
            Path::new("0123456789abcdef0123456789abcdef")
        );

        let mut wrong_endpoint = arguments(&[
            "--profile",
            r"C:\fixture\human.profile",
            "--private",
            r"C:\fixture\human.key",
            "--socket",
            r"\\.\pipe\PasswordManager-test-human",
            "--idle-seconds",
            "300",
            "--reveal-seconds",
            "15",
            "--copy-seconds",
            "30",
        ]);
        assert!(parse_arguments(&mut wrong_endpoint).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn unix_tui_arguments_keep_the_socket_contract() {
        let mut values = arguments(&[
            "--profile",
            "/tmp/human.profile",
            "--private",
            "/tmp/human.key",
            "--socket",
            "/tmp/human.sock",
            "--idle-seconds",
            "300",
            "--reveal-seconds",
            "15",
            "--copy-seconds",
            "30",
        ]);
        let parsed = parse_arguments(&mut values).unwrap();
        assert_eq!(parsed.endpoint, Path::new("/tmp/human.sock"));
    }

    #[test]
    fn terminal_text_never_preserves_control_sequences() {
        let malicious = "safe\u{1b}]52;c;ZXhmaWw=\u{7}界";
        let sanitized = sanitize_text(malicious);
        assert!(!sanitized.contains('\u{1b}'));
        assert!(!sanitized.contains('\u{7}'));
        assert!(sanitized.contains('界'));
        assert!(sanitized.contains("]52;c;ZXhmaWw="));
    }

    #[test]
    fn binary_secrets_are_not_lossily_rendered() {
        assert_eq!(display_secret(&[0xff, 0, 1]), "<binary secret: 3 bytes>");
    }

    #[test]
    fn operation_menu_names_every_keyboard_workflow_without_secrets() {
        let text = operation_help(OperationMenu::Migration);
        assert!(text.contains("CSV"));
        assert!(text.contains("1PUX"));
        assert!(text.contains("preview"));
        assert!(!text.contains("password="));
        for menu in [
            OperationMenu::Backup,
            OperationMenu::Devices,
            OperationMenu::Audit,
        ] {
            assert!(!operation_help(menu).is_empty());
        }
    }

    #[test]
    fn operation_fields_escape_delimiters_without_restricting_paths() {
        let Ok(fields) = split_exact::<3>(r"/tmp/a\|b|chrome|keep") else {
            panic!("valid escaped fields rejected")
        };
        assert!(
            fields
                .iter()
                .zip(["/tmp/a|b", "chrome", "keep"])
                .all(|(actual, expected)| (**actual).eq(expected))
        );
        assert!(split_exact::<2>(r"dangling\").is_err());
    }

    #[test]
    fn clipboard_cleanup_attempts_kill_and_wait_once_after_failures() {
        struct FakeClipboard(Vec<&'static str>);
        impl ClipboardControl for FakeClipboard {
            fn try_exited(&mut self) -> Result<bool, ()> {
                self.0.push("try-wait");
                Ok(false)
            }
            fn kill_process(&mut self) -> Result<(), ()> {
                self.0.push("kill");
                Err(())
            }
            fn wait_process(&mut self) -> Result<(), ()> {
                self.0.push("wait");
                Err(())
            }
        }
        let mut control = FakeClipboard(Vec::new());
        let result = stop_clipboard_with(&mut control);
        assert!(result.is_err());
        assert_eq!(control.0, ["try-wait", "kill", "wait"]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn appkit_clipboard_lease_preserves_newer_owner_and_single_exit_cleanup() {
        let mut first = copy_secret(b"ticket26-tui-first-owner", Duration::from_secs(1))
            .unwrap_or_else(|_| panic!("first AppKit owner"));
        let mut replacement = copy_secret(b"ticket26-tui-new-owner", Duration::from_secs(1))
            .unwrap_or_else(|_| panic!("replacement AppKit owner"));

        // The old lease must not clear a newer pasteboard owner.  The
        // replacement remains independently cleanable on session exit.
        first
            .stop_if_owner()
            .unwrap_or_else(|_| panic!("stale AppKit owner cleanup is not an error"));
        replacement
            .stop_if_owner()
            .unwrap_or_else(|_| panic!("current AppKit owner cleanup"));
        replacement
            .stop_if_owner()
            .unwrap_or_else(|_| panic!("cleanup is not retried after explicit exit cleanup"));
    }

    #[test]
    fn terminal_cleanup_attempts_every_active_restoration() {
        struct FakeTerminal(Vec<&'static str>);
        impl TerminalRestore for FakeTerminal {
            fn leave_alternate(&mut self) -> Result<(), ()> {
                self.0.push("alternate");
                Err(())
            }
            fn show_cursor(&mut self) -> Result<(), ()> {
                self.0.push("cursor");
                Err(())
            }
            fn disable_raw(&mut self) -> Result<(), ()> {
                self.0.push("raw");
                Err(())
            }
        }
        let mut operations = FakeTerminal(Vec::new());
        let result = restore_terminal_with(
            TerminalState {
                raw: true,
                alternate: true,
                cursor_hidden: true,
            },
            &mut operations,
        );
        assert!(result.is_err());
        assert_eq!(operations.0, ["alternate", "cursor", "raw"]);
    }

    #[test]
    fn cleanup_is_not_retried_and_partial_terminal_state_only_restores_active_parts() {
        struct PartialTerminal(Vec<&'static str>);
        impl TerminalRestore for PartialTerminal {
            fn leave_alternate(&mut self) -> Result<(), ()> {
                self.0.push("alternate");
                Ok(())
            }
            fn show_cursor(&mut self) -> Result<(), ()> {
                self.0.push("cursor");
                Ok(())
            }
            fn disable_raw(&mut self) -> Result<(), ()> {
                self.0.push("raw");
                Ok(())
            }
        }
        let mut attempted = false;
        assert!(begin_cleanup(&mut attempted));
        assert!(!begin_cleanup(&mut attempted));

        let mut operations = PartialTerminal(Vec::new());
        assert!(
            restore_terminal_with(
                TerminalState {
                    raw: true,
                    alternate: false,
                    cursor_hidden: false,
                },
                &mut operations,
            )
            .is_ok()
        );
        assert_eq!(operations.0, ["raw"]);
    }
}
