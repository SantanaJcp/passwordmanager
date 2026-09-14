// SPDX-License-Identifier: AGPL-3.0-only

//! Keyboard-only human content interface.  This module deliberately owns no
//! vault state: every mutation and secret exposure crosses the authenticated
//! human TLS-RPK channel implemented by the parent module.

use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use pm_vault::PasskeyStatus;
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};
use rustls::{ClientConnection, StreamOwned};
use std::os::unix::net::UnixStream;
use zeroize::{Zeroize, Zeroizing};

use super::{
    Cursor, HUMAN_MAGIC, KeyMaterial, Profile, Role, STREAM_CHUNK_BYTES, WirePrepared, connect,
    decode_prepared_response, finish_arguments, hex, open_1pux_source, push_bytes, read_frame,
    read_import_source, read_key, read_profile, rpc_commit, rpc_download_atomic, rpc_history,
    rpc_prepare_purge_item, rpc_prepare_purge_revisions, rpc_prepare_restore, rpc_unlock,
    send_file_descriptor, write_frame,
};
use crate::{Failure, take_path};

const DEFAULT_IDLE: u64 = 300;
const DEFAULT_REVEAL: u64 = 15;
const DEFAULT_COPY: u64 = 30;
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
    input: Zeroizing<String>,
    status: String,
    reveal: Option<(Zeroizing<Vec<u8>>, Instant)>,
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
    reauthentication: Option<(PasskeyConfirmation, Zeroizing<Vec<u8>>)>,
    password: Zeroizing<Vec<u8>>,
    operation: Option<PendingOperation>,
    attachments: Vec<AttachmentDescriptor>,
    sync_job: Option<[u8; 16]>,
    sync_poll_at: Instant,
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
    RecoveryCode(Zeroizing<Vec<u8>>),
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

impl App {
    fn new(idle: Duration, reveal_for: Duration, copy_for: Duration) -> Self {
        Self {
            entries: Vec::new(),
            visible: Vec::new(),
            selected: 0,
            mode: Mode::Unlock,
            input: Zeroizing::new(String::new()),
            status: "Password required".into(),
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
            password: Zeroizing::new(Vec::new()),
            operation: None,
            attachments: Vec::new(),
            sync_job: None,
            sync_poll_at: Instant::now(),
        }
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

struct ClipboardLease {
    child: Child,
    until: Instant,
    cleanup_attempted: bool,
}

impl ClipboardLease {
    fn stop_if_owner(&mut self) -> Result<(), Failure> {
        if !begin_cleanup(&mut self.cleanup_attempted) {
            return Ok(());
        }
        stop_clipboard_with(&mut self.child)
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
        restore_terminal_with(self.state, &mut operations)
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

trait ClipboardControl {
    fn try_exited(&mut self) -> Result<bool, ()>;
    fn kill_process(&mut self) -> Result<(), ()>;
    fn wait_process(&mut self) -> Result<(), ()>;
}

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

type HumanTls = StreamOwned<ClientConnection, UnixStream>;

pub(super) fn run(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let socket_path = take_path(arguments, "--socket")?;
    let idle = take_seconds(arguments, "--idle-seconds", DEFAULT_IDLE)?;
    let reveal = take_seconds(arguments, "--reveal-seconds", DEFAULT_REVEAL)?;
    let copy = take_seconds(arguments, "--copy-seconds", DEFAULT_COPY)?;
    finish_arguments(arguments)?;
    if idle > DEFAULT_IDLE || reveal > DEFAULT_REVEAL || copy > DEFAULT_COPY {
        return Err(Failure::Usage);
    }
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Human {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path, super::current_uid())?;
    run_terminal(&profile, &key, &socket_path, idle, reveal, copy)
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
) -> Result<(), Failure> {
    let writer = File::options()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| Failure::Unavailable)?;
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
    };
    let operation = (|| {
        guard.state.alternate = true;
        execute!(guard.writer, EnterAlternateScreen).map_err(|_| Failure::Unavailable)?;
        guard.state.cursor_hidden = true;
        execute!(guard.writer, crossterm::cursor::Hide).map_err(|_| Failure::Unavailable)?;
        let backend = CrosstermBackend::new(writer);
        let mut terminal = Terminal::new(backend).map_err(|_| Failure::Unavailable)?;
        terminal.clear().map_err(|_| Failure::Unavailable)?;
        let mut app = App::new(
            Duration::from_secs(idle),
            Duration::from_secs(reveal),
            Duration::from_secs(copy),
        );
        run_authenticated_session(profile, key, socket, &mut terminal, &mut app)
    })();
    let restoration = guard.restore();
    combine_failures([operation, restoration])
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
        rpc_unlock(tls_ref, password.as_bytes())?;
        app.password.extend_from_slice(password.as_bytes());
        app.input.zeroize();
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
                    terminal.clear().map_err(|_| Failure::Unavailable)
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
    if results.into_iter().all(|result| result.is_ok()) {
        Ok(())
    } else {
        Err(Failure::Unavailable)
    }
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
            if read_frame(tls)? != [0] {
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
                    Err(_) => {
                        app.operation = None;
                        app.input.zeroize();
                        app.mode = Mode::Browse;
                        app.status = "Operation failed explicitly; no success was recorded".into();
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
            "New master password|ROTATE (old backups retain historical recovery paths):",
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
        _ => app.status = operation_help(menu).into(),
    }
    Ok(())
}

fn open_operations(app: &mut App, menu: OperationMenu) {
    app.clear_exposure();
    app.mode = Mode::Operations(menu);
    app.status = operation_help(menu).into();
}

fn begin_prompt(app: &mut App, mode: Mode, status: &str) {
    app.clear_exposure();
    app.input.zeroize();
    app.mode = mode;
    app.status = status.into();
}

fn handle_prompt_key(app: &mut App, tls: &mut HumanTls, key: KeyEvent) -> Result<(), Failure> {
    match key.code {
        KeyCode::Esc => {
            if app.mode == Mode::RecoveryRotate {
                write_frame(tls, &[])?;
                if read_frame(tls)? != [2] {
                    return Err(Failure::Unavailable);
                }
            }
            app.input.zeroize();
            app.operation = None;
            app.reveal = None;
            app.mode = Mode::Browse;
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
    let value = Zeroizing::new(app.input.to_string());
    app.input.zeroize();
    app.mode = Mode::Browse;
    match mode {
        Mode::Search => search(app, tls, &value),
        Mode::Tag => organize(app, tls, Some(value.to_string())),
        Mode::Generate => generate(app, tls, &value),
        Mode::ConfirmPurgeRevisions if value.as_str() == "PURGE" => purge_revisions(app, tls),
        Mode::ConfirmPurgeItem if value.as_str() == "PURGE" => purge_item(app, tls),
        Mode::ConfirmPurgeRevisions | Mode::ConfirmPurgeItem => {
            app.status = "Confirmation mismatch; nothing changed".into();
            Ok(())
        }
        Mode::EnrollAgent => enroll_agent(app, tls, &value),
        Mode::ConfirmPasskeyApproval => confirm_passkey_approval(app, &value),
        Mode::ConfirmPasskeyPassword => {
            let confirmation = app
                .passkey_confirmation
                .take()
                .ok_or(Failure::Unavailable)?;
            app.reauthentication = Some((confirmation, Zeroizing::new(value.as_bytes().to_vec())));
            Ok(())
        }
        Mode::CsvImport => preview_csv(app, tls, &value),
        Mode::OnePuxImport => preview_1pux(app, tls, &value),
        Mode::ConfirmImport => confirm_import(app, tls, &value),
        Mode::NativeBackup => native_backup(app, tls, &value),
        Mode::PlaintextExport => preview_plaintext_export(app, tls, &value),
        Mode::ConfirmPlaintextExport => confirm_plaintext_export(app, tls, &value),
        Mode::NativeRestore => native_restore(app, tls, &value),
        Mode::MasterRotate => master_rotate(app, tls, &value),
        Mode::AuditPurge => purge_audit(app, tls, &value),
        Mode::AttachmentPath => download_attachment(app, tls, &value),
        Mode::PairDevice => pair_device(app, tls, &value),
        Mode::SyncNow => sync_now(app, tls, &value),
        Mode::SyncStatus => select_sync_job(app, tls, &value),
        Mode::RetireDevice => retire_device(app, tls, &value),
        Mode::RecoveryRotate => confirm_recovery_rotation(app, tls, &value),
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
        let label = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
        let environment = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
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
        let title = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
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

fn split_exact<const N: usize>(value: &str) -> Result<[String; N], Failure> {
    let mut fields = vec![String::new()];
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            fields
                .last_mut()
                .ok_or(Failure::Unavailable)?
                .push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '|' {
            fields.push(String::new());
        } else {
            fields
                .last_mut()
                .ok_or(Failure::Unavailable)?
                .push(character);
        }
    }
    if escaped {
        return Err(Failure::Unavailable);
    }
    fields.try_into().map_err(|_| Failure::Unavailable)
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
        command: cursor.bytes()?,
        body: cursor.bytes()?,
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
    let format = match format.as_str() {
        "chrome" => 0,
        "apple" => 1,
        "mappable" => 2,
        _ => return Err(Failure::Unavailable),
    };
    let replace = match duplicates.as_str() {
        "keep" => 0,
        "replace" => 1,
        _ => return Err(Failure::Unavailable),
    };
    let source = read_import_source(Path::new(&path))?;
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
    let replace = match duplicates.as_str() {
        "keep" => 0,
        "replace" => 1,
        _ => return Err(Failure::Unavailable),
    };
    let source = open_1pux_source(Path::new(&path))?;
    write_frame(tls, &[31, replace])?;
    if read_frame(tls)? != [0] {
        return Err(Failure::Unavailable);
    }
    send_file_descriptor(&tls.sock, source.as_raw_fd())?;
    let (summary, prepared) = decode_import_preview(&read_frame(tls)?)?;
    app.operation = Some(PendingOperation::Import(prepared));
    begin_prompt(app, Mode::ConfirmImport, &summary);
    Ok(())
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
            if read_frame(tls)? != [0] {
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
            if read_frame(tls)? != [0] {
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
            if read_frame(tls)? != [0] {
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
    if confirmation != "RESTORE" {
        app.status = "Confirmation mismatch; vault unchanged".into();
        return Ok(());
    }
    let mut request = vec![34];
    push_bytes(&mut request, &app.password)?;
    write_frame(tls, &request)?;
    stream_file_to_server(tls, Path::new(&path))?;
    let prepared = decode_prepared_response(&read_frame(tls)?)?;
    rpc_commit(tls, &prepared)?;
    refresh(app, tls)?;
    app.status = "Restore committed with new IDs/keys; current authority preserved and imported grants inactive".into();
    Ok(())
}

fn master_rotate(app: &mut App, tls: &mut HumanTls, value: &str) -> Result<(), Failure> {
    let [mut replacement, confirmation] = split_exact::<2>(value)?;
    if confirmation != "ROTATE" || replacement.is_empty() {
        replacement.zeroize();
        app.status = "Confirmation mismatch; master password unchanged".into();
        return Ok(());
    }
    let mut request = vec![43];
    push_bytes(&mut request, replacement.as_bytes())?;
    write_frame(tls, &request)?;
    request.zeroize();
    let prepared = decode_prepared_response(&read_frame(tls)?)?;
    rpc_commit(tls, &prepared)?;
    app.password.zeroize();
    app.password.extend_from_slice(replacement.as_bytes());
    replacement.zeroize();
    app.status =
        "Master password rotated; old backups and exposed copies retain historical paths".into();
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
    Ok(())
}

fn rotate_recovery(app: &mut App, tls: &mut HumanTls) -> Result<(), Failure> {
    write_frame(tls, &[44])?;
    let response = read_frame(tls)?;
    let mut c = Cursor::new(&response);
    c.expect(&[0])?;
    let code = Zeroizing::new(c.bytes()?);
    c.finish()?;
    app.operation = Some(PendingOperation::RecoveryCode(code));
    begin_prompt(
        app,
        Mode::RecoveryRotate,
        "Recovery code shown temporarily; store externally, then re-enter it exactly to commit:",
    );
    if let Some(PendingOperation::RecoveryCode(code)) = app.operation.as_ref() {
        app.reveal = Some((
            Zeroizing::new(code.to_vec()),
            Instant::now() + app.reveal_for,
        ));
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
    if read_frame(tls)? != [0] {
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
        let agent_status = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
        let title = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
        let integration = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
        let state = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
        let reason = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
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
                rp: String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?,
                account: String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?,
                origin: String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?,
                document: String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?,
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
            let state = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
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
    if value.as_bytes() != code.as_slice() {
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
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| Failure::Unavailable)
}

fn pair_device(app: &mut App, tls: &mut HumanTls, value: &str) -> Result<(), Failure> {
    let [pin, path, confirmation] = split_exact::<3>(value)?;
    if confirmation != "PAIR" {
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
    let protected = Zeroizing::new(c.bytes()?);
    c.finish()?;
    let mut output = create_private_output(Path::new(&path))?;
    if output
        .write_all(&protected)
        .and_then(|()| output.sync_all())
        .is_err()
    {
        fs::remove_file(path).map_err(|_| Failure::Unavailable)?;
        return Err(Failure::Unavailable);
    }
    app.status =
        "Protected pairing created for the exact observed RPK pin; transfer remains human custody"
            .into();
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
    if confirmation != "SYNC" {
        app.status = "Confirmation mismatch; sync not started".into();
        return Ok(());
    }
    if UnixStream::connect(&socket).is_err() {
        app.status = "Sync endpoint offline; no sync was performed".into();
        return Ok(());
    }
    let protected = Zeroizing::new(fs::read(pairing).map_err(|_| Failure::Unavailable)?);
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
    Ok(())
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
    if confirmation != "RETIRE" {
        app.status = "Confirmation mismatch; no device retired".into();
        return Ok(());
    }
    let mut request = vec![64];
    request.extend_from_slice(&decode_hex_16_text(&device)?);
    write_frame(tls, &request)?;
    let prepared = decode_prepared_response(&read_frame(tls)?)?;
    rpc_commit(tls, &prepared)?;
    app.status = format!(
        "Device {device} retired at every locally observed prefix; later offline events are outside accepted history"
    );
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
            label: String::from_utf8(c.bytes()?).map_err(|_| Failure::Unavailable)?,
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
    let status = PasskeyStatus::from_bytes(&cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
    cursor.finish()?;
    if matches!(status, PasskeyStatus::Waiting(_)) {
        return Err(Failure::Unavailable);
    }
    Ok(())
}

fn lock_human_channel(tls: &mut HumanTls) -> Result<(), Failure> {
    write_frame(tls, &[14])?;
    if read_frame(tls)? == [0] {
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
    Ok(())
}

fn read_prompt(
    terminal: &mut Terminal<CrosstermBackend<File>>,
    app: &mut App,
    secret: bool,
) -> Result<Zeroizing<String>, Failure> {
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
                return Ok(Zeroizing::new(app.input.to_string()));
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
        let title = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
        let tag_count = usize::from(u16::from_be_bytes(
            cursor
                .fixed(2)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?,
        ));
        let mut tags = Vec::with_capacity(tag_count);
        for _ in 0..tag_count {
            tags.push(String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?);
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
            label: String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?,
            size: cursor.u64()?,
        });
    }
    cursor.finish()?;
    Ok(fields)
}

fn expect_secret(response: &[u8]) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let mut cursor = Cursor::new(response);
    cursor.expect(&[0])?;
    let value = Zeroizing::new(cursor.bytes()?);
    cursor.finish()?;
    Ok(value)
}

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
    let result = child
        .stdin
        .take()
        .ok_or(Failure::Unavailable)?
        .write_all(secret);
    if result.is_err() {
        let _cleanup = stop_clipboard_with(&mut child);
        return Err(Failure::Unavailable);
    }
    Ok(ClipboardLease {
        child,
        until: Instant::now() + duration,
        cleanup_attempted: false,
    })
}

fn draw(terminal: &mut Terminal<CrosstermBackend<File>>, app: &mut App) -> Result<(), Failure> {
    terminal.draw(|frame| {
        let chunks = Layout::default().direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(5), Constraint::Length(6)]).split(frame.area());
        let title = Paragraph::new("Password Manager — human TLS-RPK content")
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(title, chunks[0]);
        let content_rows: Vec<ListItem> = app.visible.iter().filter_map(|index| app.entries.get(*index)).map(|entry| {
            let marker = if entry.trash { "trash" } else { "active" };
            ListItem::new(Line::from(vec![
                Span::raw(if entry.favorite { "★ " } else { "  " }),
                Span::styled(format!("[{}] ", kind_label(entry.kind)), Style::default().fg(Color::Yellow)),
                Span::raw(sanitize_text(&entry.title)), Span::raw(format!("  ({marker})")),
            ]))
        }).collect();
        let (rows, selected, list_title) = if app.mode == Mode::SelectField {
            let fields = app.fields.iter().map(|field| ListItem::new(format!("{} ({} bytes)", sanitize_text(&field.label), field.size))).collect();
            (fields, app.field_selected, "Fields (explicit selection; values hidden)")
        } else if app.mode == Mode::SelectAttachment {
            let attachments = app.attachments.iter().map(|attachment| ListItem::new(format!("{} ({} bytes)", sanitize_text(&attachment.label), attachment.size))).collect();
            (attachments, app.field_selected, "Attachments (exact descriptor; values hidden)")
        } else {
            match app.screen {
                Screen::Content => (content_rows, app.selected, "Items (selection is metadata only)"),
                Screen::Access => {
                    let rows = app.access.iter().map(|entry| match entry {
                        AccessEntry::Agent { subject, generation, label, environment, status } => ListItem::new(format!(
                            "[agent {status}] {} generation={generation} environment={} subject={}",
                            sanitize_text(label), sanitize_text(environment), hex(subject),
                        )),
                        AccessEntry::Credential { item, title, enabled } => ListItem::new(format!(
                            "[credential {}] {} item={}", if *enabled { "enabled" } else { "disabled" }, sanitize_text(title), hex(item),
                        )),
                    }).collect();
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
        let mut state = ListState::default(); if !rows.is_empty() { state.select(Some(selected)); }
        frame.render_stateful_widget(List::new(rows).highlight_symbol("› ").block(Block::default().title(list_title).borders(Borders::ALL)), chunks[1], &mut state);
        let prompt = if matches!(
            app.mode,
            Mode::Unlock
                | Mode::ConfirmPasskeyPassword
                | Mode::MasterRotate
                | Mode::RecoveryRotate
        ) {
            "•".repeat(app.input.chars().count())
        } else {
            sanitize_text(&app.input)
        };
        let exposure = app.reveal.as_ref().map_or_else(|| "<hidden>".into(), |(secret, _)| display_secret(secret));
        let controls = match app.screen {
            Screen::Content => "↑↓/jk select  / search  t tag  f favorite  g generate  h history  d trash  u restore  p/P purge  r reveal  c copy  a access  w pending  m migrate  b backup  y sync  z audit  D download  l lock  q quit",
            Screen::Access => "↑↓/jk select  n enroll  s suspend/resume  x revoke agent  e enable/disable credential  Esc content",
            Screen::Pending => "↑↓/jk select  x cancel  v confirm passkey  Esc content",
        };
        let footer = Paragraph::new(vec![
            Line::from(sanitize_text(&app.status)), Line::from(format!("Input: {prompt}")),
            Line::from(format!("Exposure: {exposure}")),
            Line::from(controls),
        ]).wrap(Wrap { trim: true }).block(Block::default().borders(Borders::ALL));
        frame.render_widget(footer, chunks[2]);
    }).map(|_| ()).map_err(|_| Failure::Unavailable)
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
        assert_eq!(fields, ["/tmp/a|b", "chrome", "keep"]);
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
