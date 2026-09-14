// SPDX-License-Identifier: AGPL-3.0-only

//! Keyboard-only human content interface.  This module deliberately owns no
//! vault state: every mutation and secret exposure crosses the authenticated
//! human TLS-RPK channel implemented by the parent module.

use std::{
    ffi::OsString,
    fs::{self, File},
    io::Write,
    os::unix::fs::MetadataExt,
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
    Cursor, HUMAN_MAGIC, KeyMaterial, Profile, Role, connect, decode_prepared_response,
    finish_arguments, hex, push_bytes, read_frame, read_key, read_profile, rpc_commit, rpc_history,
    rpc_prepare_purge_item, rpc_prepare_purge_revisions, rpc_prepare_restore, rpc_unlock,
    write_frame,
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
}

impl ClipboardLease {
    fn stop_if_owner(&mut self) -> Result<(), Failure> {
        if self
            .child
            .try_wait()
            .map_err(|_| Failure::Unavailable)?
            .is_none()
        {
            self.child.kill().map_err(|_| Failure::Unavailable)?;
            self.child.wait().map_err(|_| Failure::Unavailable)?;
        }
        Ok(())
    }
}

impl Drop for ClipboardLease {
    fn drop(&mut self) {
        let _ = self.stop_if_owner();
    }
}

struct TerminalGuard {
    writer: File,
}
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(self.writer, LeaveAlternateScreen, crossterm::cursor::Show);
        let _ = disable_raw_mode();
    }
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
    enable_raw_mode().map_err(|_| Failure::Unavailable)?;
    let mut guard = TerminalGuard {
        writer: writer.try_clone().map_err(|_| Failure::Unavailable)?,
    };
    execute!(guard.writer, EnterAlternateScreen, crossterm::cursor::Hide)
        .map_err(|_| Failure::Unavailable)?;
    let backend = CrosstermBackend::new(writer);
    let mut terminal = Terminal::new(backend).map_err(|_| Failure::Unavailable)?;
    terminal.clear().map_err(|_| Failure::Unavailable)?;
    let mut app = App::new(
        Duration::from_secs(idle),
        Duration::from_secs(reveal),
        Duration::from_secs(copy),
    );
    draw(&mut terminal, &mut app)?;
    let password = read_prompt(&mut terminal, &mut app, true)?;
    let mut tls = connect(profile, key, socket)?;
    tls.write_all(HUMAN_MAGIC)
        .map_err(|_| Failure::Unavailable)?;
    rpc_unlock(&mut tls, password.as_bytes())?;
    app.input.zeroize();
    write_frame(&mut tls, &[46])?;
    app.replace_catalog(decode_catalog(&read_frame(&mut tls)?)?);
    app.mode = Mode::Browse;
    app.status = "Unlocked: selection never reveals secrets".into();
    app.idle_at = Instant::now();
    loop {
        event_loop(&mut terminal, &mut app, &mut tls)?;
        let Some((confirmation, password)) = app.reauthentication.take() else {
            break;
        };
        lock_human_channel(&mut tls)?;
        drop(tls);
        tls = connect(profile, key, socket)?;
        tls.write_all(HUMAN_MAGIC)
            .map_err(|_| Failure::Unavailable)?;
        rpc_unlock(&mut tls, &password)?;
        let verification = confirmation.verification;
        confirm_passkey(&mut tls, &confirmation)?;
        show_pending(&mut app, &mut tls)?;
        app.status = if verification == 2 {
            "Passkey confirmed with fresh UP+UV".into()
        } else {
            "Passkey confirmed with fresh UP".into()
        };
    }
    app.clear_exposure();
    let clipboard = app
        .clipboard
        .take()
        .map_or(Ok(()), |mut lease| lease.stop_if_owner());
    lock_human_channel(&mut tls)?;
    terminal.clear().map_err(|_| Failure::Unavailable)?;
    clipboard?;
    Ok(())
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
        draw(terminal, app)?;
        if !event::poll(Duration::from_millis(100)).map_err(|_| Failure::Unavailable)? {
            continue;
        }
        let event = event::read().map_err(|_| Failure::Unavailable)?;
        match event {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                app.idle_at = Instant::now();
                if handle_key(app, tls, key)? {
                    return Ok(());
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
    if app.mode != Mode::Browse {
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
        _ => {}
    }
    Ok(false)
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
            app.input.zeroize();
            app.mode = Mode::Browse;
            app.status = "Cancelled".into();
        }
        KeyCode::Backspace => {
            app.input.pop();
        }
        KeyCode::Enter => submit_prompt(app, tls)?,
        KeyCode::Char(value) if !value.is_control() && app.input.len() < 1024 => {
            app.input.push(value);
        }
        _ => {}
    }
    Ok(())
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
        Mode::Unlock | Mode::Browse | Mode::SelectField => Ok(()),
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
        let _ = child.kill();
        let _ = child.wait();
        return Err(Failure::Unavailable);
    }
    Ok(ClipboardLease {
        child,
        until: Instant::now() + duration,
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
        let prompt = if matches!(app.mode, Mode::Unlock | Mode::ConfirmPasskeyPassword) {
            "•".repeat(app.input.chars().count())
        } else {
            sanitize_text(&app.input)
        };
        let exposure = app.reveal.as_ref().map_or_else(|| "<hidden>".into(), |(secret, _)| display_secret(secret));
        let controls = match app.screen {
            Screen::Content => "↑↓/jk select  / search  t tag  f favorite  g generate  h history  d trash  u restore  p/P purge  r reveal  c copy  a access  w pending  l lock  q quit",
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
}
