// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("the Windows TUI ConPTY fixture requires Windows");
    std::process::exit(2);
}

#[cfg(target_os = "windows")]
#[path = "windows_tui_fixture/acl.rs"]
mod acl;

#[cfg(target_os = "windows")]
mod windows_fixture {
    use std::{
        ffi::c_void,
        io::{self, Read, Write},
        ptr,
        sync::{
            Arc, Condvar, Mutex,
            atomic::{AtomicU64, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };
    use unicode_width::UnicodeWidthChar;
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, ERROR_BROKEN_PIPE, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_DATA, GetLastError,
            HANDLE, SetLastError, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            SECURITY_ATTRIBUTES,
        },
        System::{
            Console::{COORD, ClosePseudoConsole, CreatePseudoConsole, ResizePseudoConsole},
            DataExchange::{
                CloseClipboard, CountClipboardFormats, GetClipboardData, OpenClipboard,
            },
            Memory::{GlobalLock, GlobalSize, GlobalUnlock},
            Pipes::CreatePipe,
            StationsAndDesktops::{
                CloseDesktop, CloseWindowStation, CreateDesktopW, CreateWindowStationW,
                GetProcessWindowStation, GetUserObjectInformationW, SetProcessWindowStation,
                UOI_NAME,
            },
            Threading::{
                CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
                GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROCESS_INFORMATION, STARTUPINFOEXW,
                UpdateProcThreadAttribute, WaitForSingleObject,
            },
        },
        UI::{
            Input::KeyboardAndMouse::{MAPVK_VK_TO_VSC, MapVirtualKeyW},
            WindowsAndMessaging::{CWF_CREATE_ONLY, WINSTA_ALL_ACCESS},
        },
    };

    const DESKTOP_ALL_ACCESS: u32 = 0x000f_01ff;
    const MAX_CAPTURE_BYTES: usize = 1024 * 1024;
    const SCREEN_COLUMNS: usize = 80;
    const SCREEN_ROWS: usize = 24;
    const SCREEN_WAIT: Duration = Duration::from_secs(15);

    #[derive(Clone, Copy)]
    enum ParseState {
        Ground,
        Escape,
        Csi,
        Osc,
        OscEscape,
    }

    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    enum ScreenCell {
        #[default]
        Empty,
        Glyph(String),
        WideContinuation,
    }

    struct FixedMarkerProbe {
        pattern: &'static [u8],
        matched: usize,
        found: bool,
    }

    impl FixedMarkerProbe {
        const fn new(pattern: &'static [u8]) -> Self {
            Self {
                pattern,
                matched: 0,
                found: false,
            }
        }

        fn feed(&mut self, byte: u8) {
            if self.found {
                return;
            }
            if self.pattern.get(self.matched) == Some(&byte) {
                self.matched += 1;
                if self.matched == self.pattern.len() {
                    self.found = true;
                }
            } else {
                self.matched = usize::from(self.pattern.first() == Some(&byte));
            }
        }
    }

    struct ScreenState {
        columns: usize,
        rows: usize,
        cells: Vec<ScreenCell>,
        row: usize,
        column: usize,
        saved_row: usize,
        saved_column: usize,
        wrap_pending: bool,
        win32_input: bool,
        focus_reporting: bool,
        window_title_updates: u64,
        cursor_positions: u64,
        resize_reports: u64,
        line_feeds: u64,
        delayed_wraps: u64,
        bottom_scrolls: u64,
        escape_sequences: u64,
        csi_sequences: u64,
        osc_sequences: u64,
        raw_markers: [FixedMarkerProbe; 4],
        parse: ParseState,
        csi: Vec<u8>,
        osc_command: Vec<u8>,
        osc_title: Vec<u8>,
        utf8: Vec<u8>,
        error: Option<String>,
        closed: bool,
    }

    impl Drop for ScreenState {
        fn drop(&mut self) {
            for cell in &mut self.cells {
                if let ScreenCell::Glyph(value) = cell {
                    value.clear();
                }
            }
            self.csi.fill(0);
            self.osc_command.fill(0);
            self.osc_title.fill(0);
            self.utf8.fill(0);
        }
    }

    impl ScreenState {
        fn new() -> Self {
            Self {
                columns: SCREEN_COLUMNS,
                rows: SCREEN_ROWS,
                cells: vec![ScreenCell::Empty; SCREEN_COLUMNS * SCREEN_ROWS],
                row: 0,
                column: 0,
                saved_row: 0,
                saved_column: 0,
                wrap_pending: false,
                win32_input: false,
                focus_reporting: false,
                window_title_updates: 0,
                cursor_positions: 0,
                resize_reports: 0,
                line_feeds: 0,
                delayed_wraps: 0,
                bottom_scrolls: 0,
                escape_sequences: 0,
                csi_sequences: 0,
                osc_sequences: 0,
                raw_markers: [
                    FixedMarkerProbe::new(b"Password Manager"),
                    FixedMarkerProbe::new(b"human TLS-RPK"),
                    FixedMarkerProbe::new(b"Password required"),
                    FixedMarkerProbe::new(b"CUSTODY_UNAVAILABLE"),
                ],
                parse: ParseState::Ground,
                csi: Vec::new(),
                osc_command: Vec::new(),
                osc_title: Vec::new(),
                utf8: Vec::new(),
                error: None,
                closed: false,
            }
        }

        fn contains(&self, expected: &str) -> bool {
            self.cells.chunks(self.columns).any(|row| {
                let mut rendered = String::new();
                for cell in row {
                    match cell {
                        ScreenCell::Empty => rendered.push(' '),
                        ScreenCell::Glyph(value) => rendered.push_str(value),
                        ScreenCell::WideContinuation => {}
                    }
                }
                rendered.contains(expected)
            })
        }

        fn information_rows(&self) -> Option<Vec<String>> {
            let row_text = |y: usize| {
                let mut row = String::new();
                for cell in &self.cells[y * self.columns..(y + 1) * self.columns] {
                    match cell {
                        ScreenCell::Empty => row.push(' '),
                        ScreenCell::Glyph(value) => row.push_str(value),
                        ScreenCell::WideContinuation => {}
                    }
                }
                row
            };
            if self.rows <= 7 || !row_text(3).contains("Information") {
                return None;
            }
            (4..self.rows - 7)
                .map(|y| {
                    let row = row_text(y);
                    row.strip_prefix('│')
                        .and_then(|r| r.strip_suffix('│'))
                        .map(|r| r.trim_end().to_owned())
                })
                .collect()
        }

        fn information_contains(&self, expected: &str) -> bool {
            self.information_rows()
                .is_some_and(|rows| rows.join(" ").contains(expected))
        }

        fn contains_flat(&self, expected: &str) -> bool {
            let mut rendered = String::new();
            for cell in &self.cells {
                match cell {
                    ScreenCell::Empty => rendered.push(' '),
                    ScreenCell::Glyph(value) => rendered.push_str(value),
                    ScreenCell::WideContinuation => {}
                }
            }
            rendered.contains(expected)
        }

        fn fail(&mut self, message: impl Into<String>) {
            if self.error.is_none() {
                self.error = Some(message.into());
            }
        }

        fn feed(&mut self, bytes: &[u8]) {
            if self.error.is_some() {
                return;
            }
            for byte in bytes {
                if self.error.is_some() {
                    return;
                }
                for marker in &mut self.raw_markers {
                    marker.feed(*byte);
                }
                match self.parse {
                    ParseState::Ground => self.feed_ground(*byte),
                    ParseState::Escape => match *byte {
                        b'[' => {
                            let Some(next) = self.csi_sequences.checked_add(1) else {
                                self.fail("ConPTY CSI counter overflow");
                                return;
                            };
                            self.csi_sequences = next;
                            self.csi.clear();
                            self.parse = ParseState::Csi;
                        }
                        b']' => {
                            let Some(next) = self.osc_sequences.checked_add(1) else {
                                self.fail("ConPTY OSC counter overflow");
                                return;
                            };
                            self.osc_sequences = next;
                            self.osc_command.clear();
                            self.osc_title.clear();
                            self.parse = ParseState::Osc;
                        }
                        b'7' => {
                            self.saved_row = self.row;
                            self.saved_column = self.column;
                            self.parse = ParseState::Ground;
                        }
                        b'8' => {
                            self.row = self.saved_row;
                            self.column = self.saved_column;
                            self.wrap_pending = false;
                            self.parse = ParseState::Ground;
                        }
                        value => self.fail(format!(
                            "unsupported ConPTY escape after ESC: 0x{value:02x}"
                        )),
                    },
                    ParseState::Csi => {
                        if (0x40..=0x7e).contains(byte) {
                            let parameters = self.csi.clone();
                            self.apply_csi(&parameters, *byte);
                            self.csi.clear();
                            self.parse = ParseState::Ground;
                        } else if (0x20..=0x3f).contains(byte) && self.csi.len() < 64 {
                            self.csi.push(*byte);
                        } else {
                            self.fail("invalid or overlong ConPTY CSI sequence");
                        }
                    }
                    ParseState::Osc => self.feed_osc(*byte),
                    ParseState::OscEscape => {
                        if *byte == b'\\' {
                            self.finish_osc();
                        } else {
                            self.fail("unsupported ConPTY OSC terminator");
                        }
                    }
                }
            }
        }

        fn feed_osc(&mut self, byte: u8) {
            if byte == 0x07 {
                self.finish_osc();
                return;
            }
            if byte == 0x1b {
                self.parse = ParseState::OscEscape;
                return;
            }
            if self.osc_command.last() != Some(&b';') {
                if byte == b';' {
                    if !matches!(self.osc_command.as_slice(), b"0" | b"2") {
                        self.fail("unsupported ConPTY OSC command");
                        return;
                    }
                } else if !byte.is_ascii_digit() || self.osc_command.len() >= 2 {
                    self.fail("invalid ConPTY OSC command");
                    return;
                }
                self.osc_command.push(byte);
                return;
            }
            if byte < 0x20 || self.osc_title.len() >= 1016 {
                self.fail("invalid or overlong ConPTY window title");
                return;
            }
            self.osc_title.push(byte);
        }

        fn finish_osc(&mut self) {
            if !matches!(self.osc_command.as_slice(), b"0;" | b"2;") {
                self.fail("incomplete ConPTY OSC window title");
                return;
            }
            let Ok(title) = std::str::from_utf8(&self.osc_title) else {
                self.fail("invalid UTF-8 in ConPTY window title");
                return;
            };
            if title.chars().count() >= 255 || title.chars().any(char::is_control) {
                self.fail("invalid or overlong ConPTY window title");
                return;
            }
            let Some(updates) = self.window_title_updates.checked_add(1) else {
                self.fail("too many ConPTY window title updates");
                return;
            };
            self.window_title_updates = updates;
            self.osc_command.fill(0);
            self.osc_command.clear();
            self.osc_title.fill(0);
            self.osc_title.clear();
            self.parse = ParseState::Ground;
        }

        fn feed_ground(&mut self, byte: u8) {
            if !self.utf8.is_empty() || byte >= 0x80 {
                self.utf8.push(byte);
                match std::str::from_utf8(&self.utf8) {
                    Ok(value) => {
                        let characters = value.chars().collect::<Vec<_>>();
                        self.utf8.clear();
                        for character in characters {
                            self.put(character);
                        }
                    }
                    Err(error) if error.error_len().is_none() && self.utf8.len() < 4 => {}
                    Err(_) => self.fail("invalid UTF-8 in ConPTY product output"),
                }
                return;
            }
            match byte {
                0x1b => {
                    let Some(next) = self.escape_sequences.checked_add(1) else {
                        self.fail("ConPTY escape counter overflow");
                        return;
                    };
                    self.escape_sequences = next;
                    self.parse = ParseState::Escape;
                }
                b'\r' => {
                    self.column = 0;
                    self.wrap_pending = false;
                }
                b'\n' => {
                    let Some(next) = self.line_feeds.checked_add(1) else {
                        self.fail("ConPTY line-feed counter overflow");
                        return;
                    };
                    self.line_feeds = next;
                    self.advance_row();
                    self.wrap_pending = false;
                }
                0x08 => {
                    self.wrap_pending = false;
                    self.column = self.column.saturating_sub(1);
                }
                0x20..=0x7e => self.put(char::from(byte)),
                value => self.fail(format!("unsupported ConPTY control byte: 0x{value:02x}")),
            }
        }

        fn put(&mut self, character: char) {
            if character.is_control() {
                self.fail("unsupported Unicode control in ConPTY output");
                return;
            }
            let Some(width) = character.width() else {
                self.fail("unclassified Unicode cell width in ConPTY output");
                return;
            };
            if width == 0 {
                self.combine(character);
                return;
            }
            if width > 2 {
                self.fail("unsupported Unicode cell width in ConPTY output");
                return;
            }
            if self.wrap_pending {
                let Some(next) = self.delayed_wraps.checked_add(1) else {
                    self.fail("ConPTY delayed-wrap counter overflow");
                    return;
                };
                self.delayed_wraps = next;
                self.column = 0;
                self.advance_row();
                self.wrap_pending = false;
            }
            if width == 2 && self.column == self.columns - 1 {
                self.column = 0;
                self.advance_row();
            }
            let index = self.row * self.columns + self.column;
            self.erase_cell_footprint(index);
            self.cells[index] = ScreenCell::Glyph(character.to_string());
            if width == 2 {
                self.erase_cell_footprint(index + 1);
                self.cells[index + 1] = ScreenCell::WideContinuation;
            }
            if self.column + width == self.columns {
                self.column = self.columns - 1;
                self.wrap_pending = true;
            } else {
                self.column += width;
            }
        }

        fn combine(&mut self, character: char) {
            let row_start = self.row * self.columns;
            let mut index = row_start + self.column;
            if self.wrap_pending {
                index = row_start + self.column;
            } else if index > row_start {
                index -= 1;
            } else {
                self.fail("combining Unicode has no preceding glyph");
                return;
            }
            if matches!(self.cells[index], ScreenCell::WideContinuation) {
                if index == row_start {
                    self.fail("invalid wide-cell continuation at row start");
                    return;
                }
                index -= 1;
            }
            if let ScreenCell::Glyph(value) = &mut self.cells[index] {
                value.push(character);
            } else {
                self.fail("combining Unicode has no preceding glyph");
            }
        }

        fn erase_cell_footprint(&mut self, index: usize) {
            if matches!(self.cells[index], ScreenCell::WideContinuation) && index > 0 {
                self.cells[index - 1] = ScreenCell::Empty;
            }
            if matches!(self.cells[index], ScreenCell::Glyph(_))
                && index + 1 < self.cells.len()
                && matches!(self.cells[index + 1], ScreenCell::WideContinuation)
            {
                self.cells[index + 1] = ScreenCell::Empty;
            }
            self.cells[index] = ScreenCell::Empty;
        }

        fn advance_row(&mut self) {
            if self.row == self.rows - 1 {
                let Some(next) = self.bottom_scrolls.checked_add(1) else {
                    self.fail("ConPTY bottom-scroll counter overflow");
                    return;
                };
                self.bottom_scrolls = next;
                self.cells.rotate_left(self.columns);
                self.cells[(self.rows - 1) * self.columns..].fill(ScreenCell::Empty);
            } else {
                self.row += 1;
            }
        }

        fn apply_csi(&mut self, bytes: &[u8], command: u8) {
            let (private, bytes) = match bytes.first() {
                Some(b'?') => (true, &bytes[1..]),
                _ => (false, bytes),
            };
            if bytes
                .iter()
                .any(|byte| !byte.is_ascii_digit() && *byte != b';')
            {
                self.fail("unsupported ConPTY CSI intermediate byte");
                return;
            }
            let parameters = if bytes.is_empty() {
                Vec::new()
            } else {
                let mut parsed = Vec::new();
                for field in bytes.split(|byte| *byte == b';') {
                    if field.is_empty() {
                        self.fail("ambiguous empty ConPTY CSI parameter");
                        return;
                    }
                    let Ok(text) = std::str::from_utf8(field) else {
                        self.fail("non-ASCII ConPTY CSI parameter");
                        return;
                    };
                    let Ok(value) = text.parse::<usize>() else {
                        self.fail("overflowing ConPTY CSI parameter");
                        return;
                    };
                    parsed.push(value);
                }
                parsed
            };
            if private {
                if !matches!(command, b'h' | b'l')
                    || parameters.is_empty()
                    || parameters
                        .iter()
                        .any(|value| !matches!(value, 25 | 1004 | 1049 | 2026 | 9001))
                {
                    self.fail(format!(
                        "unsupported private ConPTY CSI modes={parameters:?} count={} final=0x{command:02x}",
                        parameters.len()
                    ));
                } else if command == b'h' && parameters.contains(&1049) {
                    self.cells.fill(ScreenCell::Empty);
                    self.row = 0;
                    self.column = 0;
                    self.wrap_pending = false;
                }
                if parameters.contains(&9001) {
                    self.win32_input = command == b'h';
                }
                if parameters.contains(&1004) {
                    self.focus_reporting = command == b'h';
                }
                return;
            }
            let first = parameters.first().copied().unwrap_or(0);
            let distance = || if first == 0 { 1 } else { first };
            match command {
                b'm' => {}
                b't' if parameters.as_slice() == [8, self.rows, self.columns] => {
                    let Some(next) = self.resize_reports.checked_add(1) else {
                        self.fail("ConPTY resize-report counter overflow");
                        return;
                    };
                    self.resize_reports = next;
                }
                b'H' | b'f' if parameters.len() <= 2 => {
                    let row = parameters.first().copied().unwrap_or(1).max(1) - 1;
                    let column = parameters.get(1).copied().unwrap_or(1).max(1) - 1;
                    if row >= self.rows || column >= self.columns {
                        self.fail("ConPTY absolute cursor position outside screen");
                    } else {
                        let Some(next) = self.cursor_positions.checked_add(1) else {
                            self.fail("ConPTY cursor-position counter overflow");
                            return;
                        };
                        self.cursor_positions = next;
                        self.row = row;
                        self.column = column;
                        self.wrap_pending = false;
                    }
                }
                b'A' if parameters.len() <= 1 => {
                    self.row = self.row.saturating_sub(distance());
                    self.wrap_pending = false;
                }
                b'B' if parameters.len() <= 1 => {
                    self.row = (self.row + distance()).min(self.rows - 1);
                    self.wrap_pending = false;
                }
                b'C' if parameters.len() <= 1 => {
                    self.column = (self.column + distance()).min(self.columns - 1);
                    self.wrap_pending = false;
                }
                b'D' if parameters.len() <= 1 => {
                    self.column = self.column.saturating_sub(distance());
                    self.wrap_pending = false;
                }
                b'G' if parameters.len() <= 1 => {
                    let column = distance() - 1;
                    if column >= self.columns {
                        self.fail("ConPTY horizontal cursor position outside screen");
                    } else {
                        self.column = column;
                        self.wrap_pending = false;
                    }
                }
                b'd' if parameters.len() <= 1 => {
                    let row = distance() - 1;
                    if row >= self.rows {
                        self.fail("ConPTY vertical cursor position outside screen");
                    } else {
                        self.row = row;
                        self.wrap_pending = false;
                    }
                }
                b'J' if parameters.len() <= 1 && matches!(first, 0 | 2 | 3) => {
                    self.wrap_pending = false;
                    if first == 2 || first == 3 {
                        self.cells.fill(ScreenCell::Empty);
                    } else {
                        for cell in &mut self.cells[self.row * self.columns + self.column..] {
                            *cell = ScreenCell::Empty;
                        }
                    }
                }
                b'K' if parameters.len() <= 1 && matches!(first, 0 | 1 | 2) => {
                    self.wrap_pending = false;
                    let start = self.row * self.columns;
                    let (from, through) = match first {
                        0 => (start + self.column, start + self.columns),
                        1 => (start, start + self.column + 1),
                        2 => (start, start + self.columns),
                        _ => unreachable!(),
                    };
                    self.cells[from..through].fill(ScreenCell::Empty);
                }
                b'X' if parameters.len() <= 1 => {
                    self.wrap_pending = false;
                    let from = self.row * self.columns + self.column;
                    let count = distance().min(self.columns - self.column);
                    for index in from..from + count {
                        self.erase_cell_footprint(index);
                    }
                }
                b's' if parameters.is_empty() => {
                    self.saved_row = self.row;
                    self.saved_column = self.column;
                }
                b'u' if parameters.is_empty() => {
                    self.row = self.saved_row;
                    self.column = self.saved_column;
                    self.wrap_pending = false;
                }
                _ => self.fail(format!("unsupported ConPTY CSI command: 0x{command:02x}")),
            }
        }

        fn finish(&mut self) {
            if !matches!(self.parse, ParseState::Ground) || !self.utf8.is_empty() {
                self.fail("truncated ConPTY terminal sequence at EOF");
            }
            self.closed = true;
        }
    }

    struct TerminalObserver {
        state: Mutex<ScreenState>,
        changed: Condvar,
    }

    impl TerminalObserver {
        fn new() -> Self {
            Self {
                state: Mutex::new(ScreenState::new()),
                changed: Condvar::new(),
            }
        }

        fn feed(&self, bytes: &[u8]) -> Result<(), String> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| "ConPTY screen observer lock poisoned".to_owned())?;
            state.feed(bytes);
            let result = state.error.clone().map_or(Ok(()), Err);
            self.changed.notify_all();
            result
        }

        fn finish(&self) -> Result<(), String> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| "ConPTY screen observer lock poisoned".to_owned())?;
            state.finish();
            let result = state.error.clone().map_or(Ok(()), Err);
            self.changed.notify_all();
            result
        }

        fn wait_for(&self, expected: &str) -> Result<(), String> {
            self.wait_for_matching(expected, |state| state.contains(expected))
        }

        fn wait_for_information(&self, expected: &str) -> Result<(), String> {
            self.wait_for_matching(expected, |state| state.information_contains(expected))
        }

        fn wait_for_import_review(
            &self,
            total: u64,
            new: u64,
            preserved: u64,
        ) -> Result<(), String> {
            self.wait_for_matching("complete import counters in main panel", |state| {
                let Some(rows) = state.information_rows() else {
                    return false;
                };
                let text = rows.join(" ");
                let expected = [
                    format!("total={total}"),
                    format!("new={new}"),
                    "replaced=0".into(),
                    "exact-duplicates=0".into(),
                    "excluded=0".into(),
                    format!("preserved-fields={preserved}"),
                    "pages=1;".into(),
                ];
                expected
                    .iter()
                    .all(|token| text.split_whitespace().any(|part| part == token))
                    && text.contains("type IMPORT to commit")
            })
        }

        fn wait_for_recovery_code(&self) -> Result<zeroize::Zeroizing<String>, String> {
            self.wait_for_matching(
                "complete temporary recovery code and historical warning in panel",
                |state| {
                    state.information_contains("Recovery code shown temporarily; store externally, then re-enter it exactly to commit: old backups and exposed copies retain historical recovery paths.")
                        && recovery_code(state).is_some()
                },
            )?;
            let state = self
                .state
                .lock()
                .map_err(|_| "ConPTY observer lock poisoned".to_owned())?;
            recovery_code(&state)
                .ok_or_else(|| "temporary recovery code expired before observation".to_owned())
        }

        fn wait_for_footer_suffix(&self, expected: &str) -> Result<(), String> {
            self.wait_for_matching("footer suffix and insertion cursor", |state| {
                let mut row = String::new();
                for cell in
                    &state.cells[(state.rows - 4) * state.columns..(state.rows - 3) * state.columns]
                {
                    match cell {
                        ScreenCell::Empty => row.push(' '),
                        ScreenCell::Glyph(value) => row.push_str(value),
                        ScreenCell::WideContinuation => {}
                    }
                }
                row.starts_with("│Input: ‹")
                    && row.trim_end_matches('│').trim_end().ends_with(expected)
                    && state.row == state.rows - 4
                    && state.column == state.columns - 2
            })
        }

        fn wait_for_matching(
            &self,
            expected: &str,
            predicate: impl Fn(&ScreenState) -> bool,
        ) -> Result<(), String> {
            self.wait_for_checked_matching(expected, |state| Ok(predicate(state)))
        }

        fn wait_for_checked_matching(
            &self,
            expected: &str,
            predicate: impl Fn(&ScreenState) -> Result<bool, String>,
        ) -> Result<(), String> {
            let deadline = Instant::now() + SCREEN_WAIT;
            let mut state = self
                .state
                .lock()
                .map_err(|_| "ConPTY screen observer lock poisoned".to_owned())?;
            loop {
                if let Some(error) = state.error.as_ref() {
                    return Err(error.clone());
                }
                if predicate(&state)? {
                    return Ok(());
                }
                if state.closed {
                    return Err(format!(
                        "ConPTY output closed before observable text: {expected}"
                    ));
                }
                let now = Instant::now();
                if now >= deadline {
                    return Err(format!(
                        "ConPTY screen did not show expected text within 15 seconds: {expected}"
                    ));
                }
                let remaining = deadline.saturating_duration_since(now);
                let (next, wait) = self
                    .changed
                    .wait_timeout(state, remaining)
                    .map_err(|_| "ConPTY screen observer wait poisoned".to_owned())?;
                state = next;
                if wait.timed_out() && !predicate(&state)? {
                    return Err(format!(
                        "ConPTY screen did not show expected text within 15 seconds: {expected}"
                    ));
                }
            }
        }

        fn win32_input(&self) -> Result<bool, String> {
            self.state
                .lock()
                .map(|state| state.win32_input)
                .map_err(|_| "ConPTY screen observer lock poisoned".to_owned())
        }

        fn diagnostic(&self) -> Result<String, String> {
            let state = self
                .state
                .lock()
                .map_err(|_| "ConPTY screen observer lock poisoned".to_owned())?;
            let parser = match state.parse {
                ParseState::Ground => "ground",
                ParseState::Escape => "escape",
                ParseState::Csi => "csi",
                ParseState::Osc => "osc",
                ParseState::OscEscape => "osc-escape",
            };
            let nonblank = state
                .cells
                .iter()
                .filter(|cell| matches!(cell, ScreenCell::Glyph(_)))
                .count();
            let row_counts = state
                .cells
                .chunks(state.columns)
                .map(|row| {
                    row.iter()
                        .filter(|cell| matches!(cell, ScreenCell::Glyph(_)))
                        .count()
                })
                .collect::<Vec<_>>();
            Ok(format!(
                "observer parser={parser} row={} column={} wrap={} nonblank={nonblank} title-updates={} escapes={} csi={} osc={} cursor-positions={} line-feeds={} delayed-wraps={} bottom-scrolls={} row-nonblank={row_counts:?} markers=manager:{}/flat:{}/raw:{},rpk:{}/flat:{}/raw:{},password:{}/flat:{}/raw:{},unavailable:{}/raw:{}",
                state.row,
                state.column,
                state.wrap_pending,
                state.window_title_updates,
                state.escape_sequences,
                state.csi_sequences,
                state.osc_sequences,
                state.cursor_positions,
                state.line_feeds,
                state.delayed_wraps,
                state.bottom_scrolls,
                state.contains("Password Manager"),
                state.contains_flat("Password Manager"),
                state.raw_markers[0].found,
                state.contains("human TLS-RPK"),
                state.contains_flat("human TLS-RPK"),
                state.raw_markers[1].found,
                state.contains("Password required"),
                state.contains_flat("Password required"),
                state.raw_markers[2].found,
                state.contains("CUSTODY_UNAVAILABLE"),
                state.raw_markers[3].found,
            ))
        }

        fn rejects(&self, forbidden: &[u8]) -> Result<(), String> {
            let forbidden = std::str::from_utf8(forbidden)
                .map_err(|_| "synthetic forbidden value is not UTF-8".to_owned())?;
            let state = self
                .state
                .lock()
                .map_err(|_| "ConPTY screen observer lock poisoned".to_owned())?;
            if state.contains(forbidden) {
                Err("ConPTY screen exposed the synthetic password".to_owned())
            } else {
                Ok(())
            }
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    fn win32(label: &str) -> io::Error {
        let error = io::Error::last_os_error();
        io::Error::new(error.kind(), format!("{label}: {error}"))
    }

    fn failed_hresult(label: &str, status: i32) -> io::Error {
        io::Error::other(format!("{label}: HRESULT=0x{:08x}", status.cast_unsigned()))
    }

    fn close_handle(handle: &mut HANDLE, label: &str, failures: &mut Vec<String>) {
        if handle.is_null() {
            return;
        }
        if unsafe { CloseHandle(*handle) } == 0 {
            failures.push(win32(label).to_string());
        }
        *handle = ptr::null_mut();
    }

    struct OwnedOutput {
        handle: HANDLE,
        drop_error: Arc<AtomicU64>,
        observer: Arc<TerminalObserver>,
    }

    // SAFETY: the read handle has one owner and moves once to the dedicated drainer.
    unsafe impl Send for OwnedOutput {}

    impl Drop for OwnedOutput {
        fn drop(&mut self) {
            if !self.handle.is_null() && unsafe { CloseHandle(self.handle) } == 0 {
                let code = unsafe { GetLastError() };
                self.drop_error
                    .store(u64::from(code) + 1, Ordering::Release);
            }
            self.handle = ptr::null_mut();
        }
    }

    struct DrainReport {
        captured_bytes: usize,
        overflow: bool,
    }

    impl OwnedOutput {
        fn drain(mut self) -> Result<DrainReport, String> {
            let mut captured_bytes = 0_usize;
            let mut overflow = false;
            let mut observer_error = None;
            let operation = loop {
                let mut chunk = [0_u8; 4096];
                let mut read = 0;
                if unsafe {
                    windows_sys::Win32::Storage::FileSystem::ReadFile(
                        self.handle,
                        chunk.as_mut_ptr().cast(),
                        4096,
                        &raw mut read,
                        ptr::null_mut(),
                    )
                } == 0
                {
                    let code = unsafe { GetLastError() };
                    if code == ERROR_BROKEN_PIPE || code == ERROR_NO_DATA {
                        break Ok(());
                    }
                    break Err(format!("ReadFile(ConPTY output): GetLastError={code}"));
                }
                if read == 0 {
                    break Ok(());
                }
                let read = match usize::try_from(read) {
                    Ok(read) => read,
                    Err(_) => break Err("ConPTY read count overflow".to_owned()),
                };
                match captured_bytes.checked_add(read) {
                    Some(total) if total <= MAX_CAPTURE_BYTES => {
                        captured_bytes = total;
                        if observer_error.is_none()
                            && let Err(error) = self.observer.feed(&chunk[..read])
                        {
                            observer_error = Some(error);
                        }
                    }
                    Some(_) | None => overflow = true,
                }
            };
            if observer_error.is_none()
                && let Err(error) = self.observer.finish()
            {
                observer_error = Some(error);
            }
            let mut cleanup = Vec::new();
            close_handle(&mut self.handle, "CloseHandle output reader", &mut cleanup);
            let mut failures = Vec::new();
            if let Err(error) = operation {
                failures.push(error);
            }
            if let Some(error) = observer_error {
                failures.push(format!("screen observer failed: {error}"));
            }
            failures.extend(cleanup);
            if failures.is_empty() {
                Ok(DrainReport {
                    captured_bytes,
                    overflow,
                })
            } else {
                Err(failures.join("; "))
            }
        }
    }

    struct OutputDrain {
        join: thread::JoinHandle<Result<DrainReport, String>>,
    }

    impl OutputDrain {
        fn start(handle: HANDLE, observer: Arc<TerminalObserver>) -> io::Result<Self> {
            let drop_error = Arc::new(AtomicU64::new(0));
            let owner = OwnedOutput {
                handle,
                drop_error: Arc::clone(&drop_error),
                observer,
            };
            let spawn = thread::Builder::new()
                .name("pm27-conpty-drain".to_owned())
                .spawn(move || owner.drain());
            match spawn {
                Ok(join) => Ok(Self { join }),
                Err(primary) => {
                    let cleanup_code = drop_error.load(Ordering::Acquire);
                    if cleanup_code == 0 {
                        Err(primary)
                    } else {
                        let cleanup_code = cleanup_code - 1;
                        Err(io::Error::other(format!(
                            "spawn ConPTY drainer failed: {primary}; CloseHandle output reader failed: GetLastError={cleanup_code}"
                        )))
                    }
                }
            }
        }

        fn finish(self) -> Result<DrainReport, String> {
            self.join
                .join()
                .map_err(|_| "ConPTY output drainer panicked".to_owned())?
        }
    }

    struct Fixture {
        input_read: HANDLE,
        input_write: HANDLE,
        output_read: HANDLE,
        output_write: HANDLE,
        process: HANDLE,
        thread: HANDLE,
        pseudo_console: isize,
        station: HANDLE,
        desktop: HANDLE,
        original_station: HANDLE,
        attribute_words: Vec<usize>,
        attributes_initialized: bool,
        station_selected: bool,
        drain: Option<OutputDrain>,
        observer: Arc<TerminalObserver>,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                input_read: ptr::null_mut(),
                input_write: ptr::null_mut(),
                output_read: ptr::null_mut(),
                output_write: ptr::null_mut(),
                process: ptr::null_mut(),
                thread: ptr::null_mut(),
                pseudo_console: 0,
                station: ptr::null_mut(),
                desktop: ptr::null_mut(),
                original_station: ptr::null_mut(),
                attribute_words: Vec::new(),
                attributes_initialized: false,
                station_selected: false,
                drain: None,
                observer: Arc::new(TerminalObserver::new()),
            }
        }

        fn cleanup(&mut self) -> Result<Option<DrainReport>, String> {
            let mut failures = Vec::new();
            let mut report = None;
            close_handle(&mut self.thread, "CloseHandle thread", &mut failures);
            if self.attributes_initialized {
                unsafe { DeleteProcThreadAttributeList(self.attribute_words.as_mut_ptr().cast()) };
                self.attributes_initialized = false;
            }
            close_handle(
                &mut self.input_write,
                "CloseHandle input writer",
                &mut failures,
            );
            if self.drain.is_none() {
                close_handle(
                    &mut self.output_read,
                    "CloseHandle output reader",
                    &mut failures,
                );
            }
            close_handle(
                &mut self.input_read,
                "CloseHandle ceded ConPTY input",
                &mut failures,
            );
            close_handle(
                &mut self.output_write,
                "CloseHandle ceded ConPTY output",
                &mut failures,
            );
            if self.pseudo_console != 0 {
                unsafe { ClosePseudoConsole(self.pseudo_console) };
                self.pseudo_console = 0;
            }
            if !self.process.is_null() {
                let wait = unsafe { WaitForSingleObject(self.process, INFINITE) };
                if wait != WAIT_OBJECT_0 {
                    failures.push(if wait == WAIT_FAILED {
                        win32("WaitForSingleObject during ConPTY teardown").to_string()
                    } else {
                        format!("unexpected process teardown wait result: {wait}")
                    });
                }
            }
            if let Some(drain) = self.drain.take() {
                match drain.finish() {
                    Ok(result) => report = Some(result),
                    Err(error) => failures.push(error),
                }
            }
            close_handle(&mut self.process, "CloseHandle process", &mut failures);
            if self.station_selected {
                if unsafe { SetProcessWindowStation(self.original_station) } == 0 {
                    failures.push(win32("restore process window station").to_string());
                } else {
                    self.station_selected = false;
                }
            }
            if !self.desktop.is_null() {
                if unsafe { CloseDesktop(self.desktop) } == 0 {
                    failures.push(win32("CloseDesktop").to_string());
                }
                self.desktop = ptr::null_mut();
            }
            if !self.station.is_null() {
                if unsafe { CloseWindowStation(self.station) } == 0 {
                    failures.push(win32("CloseWindowStation").to_string());
                }
                self.station = ptr::null_mut();
            }
            if failures.is_empty() {
                Ok(report)
            } else {
                Err(failures.join("; "))
            }
        }
    }

    fn station_name(station: HANDLE) -> io::Result<String> {
        let mut bytes = 0;
        let first = unsafe {
            GetUserObjectInformationW(station, UOI_NAME, ptr::null_mut(), 0, &raw mut bytes)
        };
        if first != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER || bytes < 2 {
            return Err(win32("query window station name size"));
        }
        let buffer_bytes = usize::try_from(bytes)
            .map_err(|_| io::Error::other("window station name size overflow"))?;
        let mut buffer = vec![0_u16; buffer_bytes.div_ceil(2)];
        if buffer.is_empty()
            || unsafe {
                GetUserObjectInformationW(
                    station,
                    UOI_NAME,
                    buffer.as_mut_ptr().cast(),
                    bytes,
                    &raw mut bytes,
                )
            } == 0
        {
            return Err(win32("query window station name"));
        }
        let length = buffer.iter().position(|word| *word == 0).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "unterminated window station name",
            )
        })?;
        String::from_utf16(&buffer[..length])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid station name"))
    }

    fn create_private_desktop(fixture: &mut Fixture, sddl: &str) -> io::Result<String> {
        let descriptor_text = wide(sddl);
        let mut descriptor = ptr::null_mut();
        let mut descriptor_bytes = 0;
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor_text.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                &raw mut descriptor_bytes,
            )
        } == 0
            || descriptor.is_null()
            || descriptor_bytes == 0
        {
            return Err(win32("parse protected station DACL"));
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
                .map_err(|_| io::Error::other("SECURITY_ATTRIBUTES size overflow"))?,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let operation = (|| {
            fixture.original_station = unsafe { GetProcessWindowStation() };
            if fixture.original_station.is_null() {
                return Err(win32("GetProcessWindowStation"));
            }
            fixture.station = unsafe {
                CreateWindowStationW(
                    ptr::null(),
                    CWF_CREATE_ONLY,
                    WINSTA_ALL_ACCESS.cast_unsigned(),
                    &raw const attributes,
                )
            };
            if fixture.station.is_null() {
                return Err(win32("CreateWindowStationW(CWF_CREATE_ONLY)"));
            }
            let name = station_name(fixture.station)?;
            if name.is_empty() || name.contains('\\') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid private window station name",
                ));
            }
            if unsafe { SetProcessWindowStation(fixture.station) } == 0 {
                return Err(win32("SetProcessWindowStation(private)"));
            }
            fixture.station_selected = true;
            let desktop_name = wide("pm27-tui");
            fixture.desktop = unsafe {
                CreateDesktopW(
                    desktop_name.as_ptr(),
                    ptr::null(),
                    ptr::null(),
                    0,
                    DESKTOP_ALL_ACCESS,
                    &raw const attributes,
                )
            };
            if fixture.desktop.is_null() {
                return Err(win32("CreateDesktopW"));
            }
            Ok(format!("{name}\\pm27-tui"))
        })();
        let remaining = unsafe { windows_sys::Win32::Foundation::LocalFree(descriptor) };
        let release = if remaining.is_null() {
            Ok(())
        } else {
            Err(win32("LocalFree(window station security descriptor)"))
        };
        match (operation, release) {
            (Ok(name), Ok(())) => Ok(name),
            (Err(primary), Ok(())) => Err(primary),
            (Ok(_), Err(cleanup)) => Err(cleanup),
            (Err(primary), Err(cleanup)) => Err(io::Error::other(format!(
                "{primary}; descriptor cleanup failed: {cleanup}"
            ))),
        }
    }

    fn setup_conpty(fixture: &mut Fixture) -> io::Result<()> {
        if unsafe {
            CreatePipe(
                &raw mut fixture.input_read,
                &raw mut fixture.input_write,
                ptr::null(),
                0,
            )
        } == 0
            || unsafe {
                CreatePipe(
                    &raw mut fixture.output_read,
                    &raw mut fixture.output_write,
                    ptr::null(),
                    0,
                )
            } == 0
        {
            return Err(win32("CreatePipe for ConPTY"));
        }
        let status = unsafe {
            CreatePseudoConsole(
                COORD { X: 80, Y: 24 },
                fixture.input_read,
                fixture.output_write,
                0,
                &raw mut fixture.pseudo_console,
            )
        };
        if status < 0 || fixture.pseudo_console == 0 {
            return Err(failed_hresult("CreatePseudoConsole(80x24)", status));
        }
        let output_read = std::mem::replace(&mut fixture.output_read, ptr::null_mut());
        fixture.drain = Some(OutputDrain::start(
            output_read,
            Arc::clone(&fixture.observer),
        )?);
        Ok(())
    }

    fn setup_attributes(fixture: &mut Fixture) -> io::Result<()> {
        let mut bytes = 0;
        let first =
            unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &raw mut bytes) };
        if first != 0 || bytes == 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
            return Err(win32("size process attribute list"));
        }
        fixture.attribute_words = vec![0; bytes.div_ceil(std::mem::size_of::<usize>())];
        let attributes = fixture.attribute_words.as_mut_ptr().cast();
        if unsafe { InitializeProcThreadAttributeList(attributes, 1, 0, &raw mut bytes) } == 0 {
            return Err(win32("initialize process attribute list"));
        }
        fixture.attributes_initialized = true;
        if unsafe {
            UpdateProcThreadAttribute(
                attributes,
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                fixture.pseudo_console as *const c_void,
                std::mem::size_of_val(&fixture.pseudo_console),
                ptr::null_mut(),
                ptr::null(),
            )
        } == 0
        {
            return Err(win32("attach PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE"));
        }
        Ok(())
    }

    fn quote(argument: &str) -> String {
        format!("\"{}\"", argument.replace('"', "\\\""))
    }

    fn spawn_tui(
        fixture: &mut Fixture,
        application: &str,
        desktop: &str,
        child_arguments: &[String],
    ) -> io::Result<()> {
        let app = wide(application);
        let mut command = wide(
            &std::iter::once(quote(application))
                .chain(child_arguments.iter().map(|argument| quote(argument)))
                .collect::<Vec<_>>()
                .join(" "),
        );
        let desktop = wide(desktop);
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = u32::try_from(std::mem::size_of::<STARTUPINFOEXW>())
            .map_err(|_| io::Error::other("STARTUPINFOEXW size overflow"))?;
        startup.StartupInfo.lpDesktop = desktop.as_ptr().cast_mut();
        startup.lpAttributeList = fixture.attribute_words.as_mut_ptr().cast();
        let mut process = PROCESS_INFORMATION::default();
        if unsafe {
            CreateProcessW(
                app.as_ptr(),
                command.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                EXTENDED_STARTUPINFO_PRESENT,
                ptr::null(),
                ptr::null(),
                &raw const startup.StartupInfo,
                &raw mut process,
            )
        } == 0
        {
            return Err(win32("CreateProcessW(pm-custody.exe tui)"));
        }
        fixture.process = process.hProcess;
        fixture.thread = process.hThread;
        Ok(())
    }

    fn start_drain_and_release_conpty_ends(fixture: &mut Fixture) -> io::Result<()> {
        if fixture.drain.is_none() {
            return Err(io::Error::other("ConPTY output drainer is absent"));
        }
        let mut failures = Vec::new();
        close_handle(
            &mut fixture.input_read,
            "CloseHandle ceded ConPTY input",
            &mut failures,
        );
        close_handle(
            &mut fixture.output_write,
            "CloseHandle ceded ConPTY output",
            &mut failures,
        );
        if failures.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(failures.join("; ")))
        }
    }

    fn write_conpty_input(handle: HANDLE, bytes: &[u8]) -> io::Result<()> {
        let mut written = 0;
        if unsafe {
            windows_sys::Win32::Storage::FileSystem::WriteFile(
                handle,
                bytes.as_ptr().cast(),
                u32::try_from(bytes.len())
                    .map_err(|_| io::Error::other("ConPTY input length overflow"))?,
                &raw mut written,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(win32("WriteFile(ConPTY input)"));
        }
        if usize::try_from(written).ok() != Some(bytes.len()) {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short ConPTY input write",
            ));
        }
        Ok(())
    }

    fn encode_win32_key_events(text: &str) -> io::Result<zeroize::Zeroizing<Vec<u8>>> {
        let mut encoded = zeroize::Zeroizing::new(Vec::new());
        for character in text.chars() {
            let (virtual_key, scan_code) = match character {
                'a'..='z' => {
                    let virtual_key = u32::from(character.to_ascii_uppercase());
                    let scan_code = unsafe { MapVirtualKeyW(virtual_key, MAPVK_VK_TO_VSC) };
                    if scan_code == 0 {
                        return Err(io::Error::other("MapVirtualKeyW returned no scan code"));
                    }
                    (virtual_key, scan_code)
                }
                '0'..='9' | ' ' | '\r' | '\x1b' => {
                    let virtual_key = u32::from(character);
                    let scan_code = unsafe { MapVirtualKeyW(virtual_key, MAPVK_VK_TO_VSC) };
                    if scan_code == 0 {
                        return Err(io::Error::other("MapVirtualKeyW returned no scan code"));
                    }
                    (virtual_key, scan_code)
                }
                _ => (0, 0),
            };
            let mut units = [0_u16; 2];
            for unit in character.encode_utf16(&mut units) {
                for down in [1, 0] {
                    write!(encoded, "\x1b[{virtual_key};{scan_code};{unit};{down};0;1_")?;
                }
            }
        }
        Ok(encoded)
    }

    fn write_keyboard_input(fixture: &Fixture, bytes: &[u8]) -> io::Result<()> {
        let input = if fixture.observer.win32_input().map_err(io::Error::other)? {
            encode_win32_key_events(
                std::str::from_utf8(bytes)
                    .map_err(|_| io::Error::other("synthetic keyboard input is not UTF-8"))?,
            )?
        } else {
            zeroize::Zeroizing::new(bytes.to_vec())
        };
        write_conpty_input(fixture.input_write, &input)
    }

    fn read_clipboard_utf16() -> io::Result<zeroize::Zeroizing<Vec<u16>>> {
        if unsafe { OpenClipboard(ptr::null_mut()) } == 0 {
            return Err(win32("OpenClipboard(fixture reader)"));
        }
        let operation = (|| {
            let memory = unsafe {
                GetClipboardData(u32::from(windows_sys::Win32::System::Ole::CF_UNICODETEXT))
            };
            if memory.is_null() {
                return Err(win32("GetClipboardData(CF_UNICODETEXT)"));
            }
            let bytes = unsafe { GlobalSize(memory) };
            if bytes < 2 || bytes % 2 != 0 {
                return Err(io::Error::other(
                    "clipboard UTF-16 allocation has invalid size",
                ));
            }
            let source = unsafe { GlobalLock(memory) };
            if source.is_null() {
                return Err(win32("GlobalLock(clipboard reader)"));
            }
            let words = unsafe { std::slice::from_raw_parts(source.cast::<u16>(), bytes / 2) };
            let end = words
                .iter()
                .position(|word| *word == 0)
                .ok_or_else(|| io::Error::other("clipboard UTF-16 text is unterminated"));
            let value = end.map(|end| zeroize::Zeroizing::new(words[..end].to_vec()));
            unsafe { SetLastError(0) };
            if unsafe { GlobalUnlock(memory) } == 0 && unsafe { GetLastError() } != 0 {
                return Err(win32("GlobalUnlock(clipboard reader)"));
            }
            value
        })();
        let cleanup = if unsafe { CloseClipboard() } == 0 {
            Err(win32("CloseClipboard(fixture reader)"))
        } else {
            Ok(())
        };
        match (operation, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(primary), Ok(())) => Err(primary),
            (Ok(_), Err(cleanup)) => Err(cleanup),
            (Err(primary), Err(cleanup)) => Err(io::Error::other(format!(
                "{primary}; clipboard reader cleanup failed: {cleanup}"
            ))),
        }
    }

    fn press(fixture: &Fixture, key: &str) -> io::Result<()> {
        write_keyboard_input(fixture, key.as_bytes())
    }

    fn type_visible_and_submit(
        fixture: &Fixture,
        value: &str,
        visible_suffix: &str,
    ) -> io::Result<()> {
        press(fixture, value)?;
        fixture
            .observer
            .wait_for(visible_suffix)
            .map_err(io::Error::other)?;
        press(fixture, "\r")
    }

    fn visible_path_name(path: &str) -> io::Result<&str> {
        std::path::Path::new(path)
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| io::Error::other("fixture path has no visible UTF-8 file name"))
    }

    fn encode_operation_field(value: &str) -> String {
        let mut encoded = String::with_capacity(value.len());
        for character in value.chars() {
            if matches!(character, '\\' | '|') {
                encoded.push('\\');
            }
            encoded.push(character);
        }
        encoded
    }

    fn open_menu(fixture: &Fixture, key: &str, expected: &str) -> io::Result<()> {
        press(fixture, key)?;
        fixture
            .observer
            .wait_for_information(expected)
            .map_err(io::Error::other)
    }

    fn search(fixture: &Fixture, query: &str) -> io::Result<()> {
        open_menu(fixture, "/", "Search (engine-decrypted):")?;
        type_visible_and_submit(fixture, query, query)?;
        fixture
            .observer
            .wait_for("Search returned")
            .map_err(io::Error::other)
    }

    struct MatrixPaths<'a> {
        csv: &'a str,
        onepux: &'a str,
        backup: &'a str,
        plaintext: &'a str,
        geometry: &'a std::path::Path,
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Scenario {
        Matrix,
        EncodingExit,
        Resize,
        Clipboard,
        LocalOperations,
        Access,
        Rotations,
    }

    fn read_synthetic_password() -> io::Result<zeroize::Zeroizing<Vec<u8>>> {
        let mut password = zeroize::Zeroizing::new(Vec::new());
        std::io::stdin().take(1025).read_to_end(&mut password)?;
        while password
            .last()
            .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
        {
            password.pop();
        }
        if password.is_empty() || password.len() > 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "synthetic TUI password must contain 1..=1024 bytes",
            ));
        }
        Ok(password)
    }

    fn exercise_keyboard_screen(
        fixture: &Fixture,
        password: &[u8],
        paths: MatrixPaths<'_>,
        scenario: Scenario,
    ) -> io::Result<()> {
        if let Err(primary) = fixture.observer.wait_for("Password required") {
            let observer = fixture.observer.diagnostic().map_err(io::Error::other)?;
            let child = child_diagnostic(fixture.process)?;
            return Err(io::Error::other(format!("{primary}; {child}; {observer}")));
        }
        eprintln!("TUI_STAGE stage=first-prompt result=pass");
        let (first, rest) = password
            .split_first()
            .ok_or_else(|| io::Error::other("synthetic TUI password is empty"))?;
        write_keyboard_input(fixture, std::slice::from_ref(first))?;
        fixture
            .observer
            .wait_for("Password required (input hidden)")
            .map_err(io::Error::other)?;
        eprintln!("TUI_STAGE stage=hidden-input result=pass");
        let mut input = zeroize::Zeroizing::new(rest.to_vec());
        input.push(b'\r');
        write_keyboard_input(fixture, &input)?;
        fixture
            .observer
            .wait_for("Unlocked: selection never reveals secrets")
            .map_err(io::Error::other)?;
        fixture
            .observer
            .wait_for("Items (selection is metadata only)")
            .map_err(io::Error::other)?;
        fixture
            .observer
            .rejects(password)
            .map_err(io::Error::other)?;

        eprintln!("TUI_STAGE stage=unlock result=pass");
        if scenario == Scenario::EncodingExit {
            press(fixture, "q")?;
            require_tui_exit(fixture.process)?;
            eprintln!("TUI_STAGE stage=encoding-natural-exit result=pass");
            return Ok(());
        }
        match scenario {
            Scenario::Resize => {
                exercise_types(fixture)?;
                exercise_resize(fixture, paths.geometry)?;
                press(fixture, "q")?;
                return require_tui_exit(fixture.process);
            }
            Scenario::Clipboard
            | Scenario::LocalOperations
            | Scenario::Access
            | Scenario::Rotations => {
                search(fixture, "Password")?;
                fixture
                    .observer
                    .wait_for("Search returned 1 active items")
                    .map_err(io::Error::other)?;
                if scenario == Scenario::Clipboard {
                    exercise_clipboard(fixture, 14, "ticket05-e2e-password-canary")?;
                    eprintln!("TUI_STAGE stage=clipboard-independent result=pass");
                } else if scenario == Scenario::Access {
                    // A new vault explicitly defaults to suspended. Resume by
                    // real keyboard before the unchanged access regression.
                    press(fixture, "a")?;
                    fixture
                        .observer
                        .wait_for("Delegated access: SUSPENDED")
                        .map_err(io::Error::other)?;
                    press(fixture, "s")?;
                    fixture
                        .observer
                        .wait_for("Delegated access: RESUMED")
                        .map_err(io::Error::other)?;
                    press(fixture, "\x1b")?;
                    fixture
                        .observer
                        .wait_for("Content view")
                        .map_err(io::Error::other)?;
                    exercise_generator_access_audit(fixture)?;
                } else if scenario == Scenario::Rotations {
                    exercise_rotations(fixture, b"synthetic-ticket27-independent-rotated-master")?;
                } else {
                    exercise_organization(fixture)?;
                    exercise_local_operations(
                        fixture,
                        &paths,
                        b"synthetic-ticket27-local-rotated-master",
                    )?;
                }
                press(fixture, "q")?;
                return require_tui_exit(fixture.process);
            }
            Scenario::Matrix => {}
            Scenario::EncodingExit => unreachable!("encoding scenario returned after unlock"),
        }
        exercise_types(fixture)?;
        // Ticket 25 migration is driven through the real keyboard and common
        // human handler. The service result is awaited before the next input;
        // no operation is retried by the fixture.
        open_menu(fixture, "m", "Migration:")?;
        open_menu(fixture, "1", "CSV source")?;
        let csv_request = format!("{}|chrome|keep", encode_operation_field(paths.csv));
        press(fixture, &csv_request)?;
        fixture
            .observer
            .wait_for_footer_suffix("|chrome|keep")
            .map_err(io::Error::other)?;
        eprintln!("TUI_STAGE stage=footer-horizontal result=pass");
        press(fixture, "\r")?;
        fixture
            .observer
            .wait_for_information("Preview values hidden")
            .map_err(io::Error::other)?;
        // Required review data must be visible before the fixture confirms.
        fixture
            .observer
            .wait_for_information("exact-duplicates=0")
            .map_err(io::Error::other)?;
        fixture
            .observer
            .wait_for_import_review(1, 1, 0)
            .map_err(io::Error::other)?;
        type_visible_and_submit(fixture, "IMPORT", "IMPORT")?;
        fixture
            .observer
            .wait_for("Import committed transactionally")
            .map_err(io::Error::other)?;

        eprintln!("TUI_STAGE stage=csv-import result=pass");
        reject_invalid_local_sources(fixture, paths.onepux)?;
        reject_multilink_source(fixture, paths.onepux)?;
        crate::acl::probe_human_token_lease()?;
        eprintln!("TUI_STAGE stage=human-token-lease-discriminant result=pass");
        open_menu(fixture, "m", "Migration:")?;
        open_menu(fixture, "2", "1PUX source")?;
        let onepux_request = format!("{}|keep", encode_operation_field(paths.onepux));
        crate::acl::Sampling::observe(fixture.process, true, || {
            type_visible_and_submit(fixture, &onepux_request, "|keep")?;
            fixture
                .observer
                .wait_for_information("Preview values hidden")
                .map_err(io::Error::other)?;
            fixture
                .observer
                .wait_for_import_review(2, 2, 4)
                .map_err(io::Error::other)
        })
        .map_err(|primary| {
            let child = child_diagnostic(fixture.process);
            let screen = fixture.observer.diagnostic();
            io::Error::other(format!(
                "{primary}; 1PUX child={child:?}; observer={screen:?}"
            ))
        })?;
        eprintln!("TUI_STAGE stage=real-transfer-dacl-before-during-after result=pass");
        type_visible_and_submit(fixture, "IMPORT", "IMPORT")?;
        fixture
            .observer
            .wait_for("Import committed transactionally")
            .map_err(io::Error::other)?;
        eprintln!("TUI_STAGE stage=onepux-import result=pass");
        search(fixture, "Keyboard 1PUX")?;
        fixture
            .observer
            .wait_for("Search returned 2 active items")
            .map_err(io::Error::other)?;

        search(fixture, "Keyboard Windows")?;
        exercise_organization(fixture)?;
        exercise_clipboard(fixture, 7, "synthetic-ticket27-import")?;
        eprintln!("TUI_STAGE stage=organization-history-copy result=pass");
        exercise_generator_access_audit(fixture)?;
        exercise_local_operations(fixture, &paths, b"synthetic-ticket27-rotated-master")?;
        exercise_resize(fixture, paths.geometry)?;
        write_keyboard_input(fixture, b"q")?;
        require_tui_exit(fixture.process)
    }

    fn exercise_organization(fixture: &Fixture) -> io::Result<()> {
        open_menu(fixture, "t", "Tag (replaces tags):")?;
        type_visible_and_submit(fixture, "windows-keyboard", "windows-keyboard")?;
        fixture
            .observer
            .wait_for("Organization committed")
            .map_err(io::Error::other)?;
        press(fixture, "f")?;
        fixture
            .observer
            .wait_for("Favorite committed")
            .map_err(io::Error::other)?;
        press(fixture, "h")?;
        fixture
            .observer
            .wait_for_information("History:")
            .map_err(io::Error::other)?;

        Ok(())
    }

    fn exercise_clipboard(fixture: &Fixture, index: usize, value: &str) -> io::Result<()> {
        // Exact-field reveal/copy always crosses the selection screen; merely
        // selecting an item never exposes its value.
        press(fixture, "r")?;
        fixture
            .observer
            .wait_for("Fields (explicit selection; values hidden)")
            .map_err(io::Error::other)?;
        press(fixture, &"j".repeat(index))?;
        fixture
            .observer
            .wait_for("› auth[0].password")
            .map_err(io::Error::other)?;
        press(fixture, "\r")?;
        fixture
            .observer
            .wait_for("Secret revealed temporarily")
            .map_err(io::Error::other)?;
        fixture.observer.wait_for(value).map_err(io::Error::other)?;
        press(fixture, "c")?;
        fixture
            .observer
            .wait_for("Fields (explicit selection; values hidden)")
            .map_err(io::Error::other)?;
        press(fixture, &"j".repeat(index))?;
        fixture
            .observer
            .wait_for("› auth[0].password")
            .map_err(io::Error::other)?;
        press(fixture, "\r")?;
        fixture
            .observer
            .wait_for("Copied explicitly")
            .map_err(io::Error::other)?;
        let expected_clipboard = zeroize::Zeroizing::new(value.encode_utf16().collect::<Vec<_>>());
        if read_clipboard_utf16()?.as_slice() != expected_clipboard.as_slice() {
            return Err(io::Error::other(
                "TUI clipboard did not contain the exact selected synthetic field",
            ));
        }
        let replacement_started = Instant::now();
        let replacement = pm_native_channel::OwnedClipboard::copy(b"synthetic-ticket27-new-owner")
            .map_err(|_| io::Error::other("fixture interloper could not own private clipboard"))?;
        eprintln!(
            "TUI_CLIPBOARD replacement-crossed-lease={}",
            replacement_started.elapsed() >= Duration::from_secs(1)
        );
        thread::sleep(Duration::from_millis(1_200));
        fixture
            .observer
            .wait_for("Clipboard custody expired")
            .map_err(|primary| {
                let categories = fixture.observer.state.lock().map(|state| format!(
                    "expired={} cleanup-not-confirmed={} reveal-expired={} copied={}",
                    state.contains("Clipboard custody expired"),
                    state.contains("Clipboard cleanup not confirmed"),
                    state.contains("Reveal expired"),
                    state.contains("Copied explicitly"),
                ));
                let observer = fixture.observer.diagnostic();
                let child = child_diagnostic(fixture.process);
                io::Error::other(format!("{primary}; clipboard-status={categories:?}; child={child:?}; observer={observer:?}"))
            })?;
        let expected_replacement = zeroize::Zeroizing::new(
            "synthetic-ticket27-new-owner"
                .encode_utf16()
                .collect::<Vec<_>>(),
        );
        if read_clipboard_utf16()?.as_slice() != expected_replacement.as_slice() {
            return Err(io::Error::other(
                "TUI timeout changed a newer private clipboard selection",
            ));
        }
        if !replacement
            .clear_if_owned()
            .map_err(|_| io::Error::other("fixture interloper clipboard cleanup failed"))?
        {
            return Err(io::Error::other(
                "fixture interloper lost clipboard ownership before cleanup",
            ));
        }

        press(fixture, "c")?;
        fixture
            .observer
            .wait_for("Fields (explicit selection; values hidden)")
            .map_err(io::Error::other)?;
        press(fixture, &"j".repeat(index))?;
        fixture
            .observer
            .wait_for("› auth[0].password")
            .map_err(io::Error::other)?;
        press(fixture, "\r")?;
        fixture
            .observer
            .wait_for("Copied explicitly")
            .map_err(io::Error::other)?;
        if read_clipboard_utf16()?.as_slice() != expected_clipboard.as_slice() {
            return Err(io::Error::other(
                "own-expiry copy did not contain the exact synthetic field",
            ));
        }
        thread::sleep(Duration::from_millis(1_200));
        fixture
            .observer
            .wait_for("Clipboard custody expired")
            .map_err(io::Error::other)?;
        if unsafe { OpenClipboard(ptr::null_mut()) } == 0 {
            return Err(win32("OpenClipboard(own-expiry observer)"));
        }
        unsafe { SetLastError(0) };
        let formats = unsafe { CountClipboardFormats() };
        let counted = formats != 0 || unsafe { GetLastError() } == 0;
        let closed = unsafe { CloseClipboard() } != 0;
        if !counted || !closed || formats != 0 {
            return Err(io::Error::other(
                "own clipboard expiry did not prove an empty private clipboard",
            ));
        }
        eprintln!("TUI_CLIPBOARD newer-owner-preserved=true own-expiry-empty=true");
        Ok(())
    }

    fn exercise_generator_access_audit(fixture: &Fixture) -> io::Result<()> {
        open_menu(fixture, "g", "Generator length")?;
        type_visible_and_submit(fixture, "24", "24")?;
        fixture
            .observer
            .wait_for("Generated secret revealed temporarily")
            .map_err(io::Error::other)?;

        press(fixture, "a")?;
        fixture
            .observer
            .wait_for("Delegated access: RESUMED")
            .map_err(io::Error::other)?;
        press(fixture, "s")?;
        fixture
            .observer
            .wait_for("Delegated access: SUSPENDED")
            .map_err(io::Error::other)?;
        press(fixture, "s")?;
        fixture
            .observer
            .wait_for("Delegated access: RESUMED")
            .map_err(io::Error::other)?;
        press(fixture, "\x1b")?;
        fixture
            .observer
            .wait_for("Content view")
            .map_err(io::Error::other)?;
        press(fixture, "w")?;
        fixture
            .observer
            .wait_for("Pending and recent attempts:")
            .map_err(io::Error::other)?;
        press(fixture, "\x1b")?;
        fixture
            .observer
            .wait_for("Content view")
            .map_err(io::Error::other)?;

        open_menu(fixture, "z", "Audit:")?;
        press(fixture, "1")?;
        fixture
            .observer
            .wait_for_information("Audit metadata:")
            .map_err(io::Error::other)?;
        // Audit queries leave the operation menu open. Return through its
        // ordinary Escape action before testing a browse action or quitting.
        press(fixture, "\x1b")?;
        fixture
            .observer
            .wait_for("Cancelled; nothing changed")
            .map_err(io::Error::other)?;

        eprintln!("TUI_STAGE stage=generator-access-pending-audit result=pass");
        Ok(())
    }

    fn assert_published_files(paths: &MatrixPaths<'_>) -> io::Result<()> {
        for path in [paths.backup, paths.plaintext] {
            let metadata = std::fs::symlink_metadata(path)
                .map_err(|_| io::Error::other("human publication metadata unavailable"))?;
            if !metadata.is_file() || metadata.len() == 0 {
                return Err(io::Error::other(
                    "TUI publication is not a nonempty regular file",
                ));
            }
        }
        eprintln!("TUI_STAGE stage=published-files-regular-nonempty result=pass");
        Ok(())
    }

    fn exercise_local_operations(
        fixture: &Fixture,
        paths: &MatrixPaths<'_>,
        master: &[u8],
    ) -> io::Result<()> {
        // New-file backup/export paths are distinct. Existing destinations are
        // intentionally not removed or truncated by this fixture.
        open_menu(fixture, "b", "Backup/recovery:")?;
        open_menu(fixture, "1", "New native backup path")?;
        type_visible_and_submit(fixture, paths.backup, visible_path_name(paths.backup)?)?;
        fixture
            .observer
            .wait_for_information("Native encrypted backup complete")
            .map_err(io::Error::other)?;
        open_menu(fixture, "b", "Backup/recovery:")?;
        open_menu(fixture, "2", "New plaintext export path")?;
        type_visible_and_submit(
            fixture,
            paths.plaintext,
            visible_path_name(paths.plaintext)?,
        )?;
        fixture
            .observer
            .wait_for_information(
                "PLAINTEXT WARNING: persistent readable copy outside vault custody; type EXPORT:",
            )
            .map_err(io::Error::other)?;
        type_visible_and_submit(fixture, "EXPORT", "EXPORT")?;
        fixture
            .observer
            .wait_for_information("Plaintext export complete")
            .map_err(io::Error::other)?;

        press(fixture, "d")?;
        fixture
            .observer
            .wait_for("Moved to trash")
            .map_err(io::Error::other)?;
        press(fixture, "u")?;
        fixture
            .observer
            .wait_for("Restored with a new revision")
            .map_err(io::Error::other)?;
        open_menu(fixture, "p", "Type PURGE to delete non-visible revisions:")?;
        type_visible_and_submit(fixture, "PURGE", "PURGE")?;
        fixture
            .observer
            .wait_for("Purged ")
            .map_err(io::Error::other)?;
        eprintln!("TUI_STAGE stage=backup-export-trash result=pass");
        exercise_restore_rotations(fixture, paths, master)?;
        assert_published_files(paths)
    }

    fn exercise_types(fixture: &Fixture) -> io::Result<()> {
        for kind in [
            "Password", "TOTP", "Passkey", "SSH", "Token", "Note", "File",
        ] {
            fixture
                .observer
                .wait_for(&format!("[{}]", kind.to_lowercase()))
                .map_err(io::Error::other)?;
        }
        for (title, field, index, value) in [
            (
                "Password",
                "auth[0].password",
                14,
                "ticket05-e2e-password-canary",
            ),
            ("TOTP", "auth[0].secret", 13, "ticket05-e2e-totp-canary"),
            (
                "Passkey",
                "auth[0].private_key",
                17,
                "ssssssssssssssssssssssssssssssss",
            ),
            ("SSH", "auth[0].private_key", 14, "ticket05-e2e-ssh-canary"),
            ("Token", "auth[0].secret", 13, "ticket05-e2e-token-canary"),
            (
                "ticket05-e2e-search-canary",
                "notes",
                5,
                "ticket27-native-note-canary",
            ),
            (
                "File",
                "attachment[0].content",
                18,
                "ticket05-e2e-attachment-canary 🌎",
            ),
        ] {
            search(fixture, title)?;
            fixture
                .observer
                .wait_for("Search returned 1 active items")
                .map_err(io::Error::other)?;
            // Catalogue and explicit field labels expose no selected field value.
            fixture
                .observer
                .rejects(value.as_bytes())
                .map_err(io::Error::other)?;
            press(fixture, "r")?;
            fixture
                .observer
                .wait_for("Fields (explicit selection; values hidden)")
                .map_err(io::Error::other)?;
            press(fixture, &"j".repeat(index))?;
            fixture
                .observer
                .wait_for(&format!("› {field}"))
                .map_err(io::Error::other)?;
            fixture
                .observer
                .rejects(value.as_bytes())
                .map_err(io::Error::other)?;
            press(fixture, "\r")?;
            fixture.observer.wait_for(value).map_err(io::Error::other)?;
            fixture
                .observer
                .wait_for("Reveal expired")
                .map_err(io::Error::other)?;
            fixture
                .observer
                .rejects(value.as_bytes())
                .map_err(io::Error::other)?;
        }
        eprintln!("TUI_STAGE stage=seven-types-explicit-fields result=pass");
        Ok(())
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct GeometryReport {
        sequence: u64,
        buffer: (u16, u16),
        viewport: (u16, u16),
        frame: (u16, u16),
    }

    fn parse_geometry_reports(text: &str) -> io::Result<Option<GeometryReport>> {
        fn dimensions(text: &str, prefix: &str) -> io::Result<(u16, u16)> {
            let value = text
                .strip_prefix(prefix)
                .ok_or_else(|| io::Error::other("invalid child geometry field"))?;
            let (width, height) = value
                .split_once('x')
                .ok_or_else(|| io::Error::other("invalid child geometry dimensions"))?;
            let dimension = |value: &str| -> io::Result<u16> {
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(io::Error::other("invalid child geometry number"));
                }
                value
                    .parse::<u16>()
                    .ok()
                    .filter(|n| *n > 0 && *n <= 32767)
                    .ok_or_else(|| io::Error::other("child geometry out of native bounds"))
            };
            Ok((dimension(width)?, dimension(height)?))
        }
        let mut latest: Option<GeometryReport> = None;
        for line in text.split_inclusive('\n') {
            // A live file can end midway through the next write. Such a record
            // is not yet a witness; only a complete, strictly parsed line counts.
            if !line.ends_with('\n') {
                break;
            }
            let Some(fields) = line
                .trim_end_matches(['\r', '\n'])
                .strip_prefix("TUI_PROBE geometry-seq=")
            else {
                continue;
            };
            let fields = fields.split_whitespace().collect::<Vec<_>>();
            if fields.len() != 4
                || fields[0].is_empty()
                || !fields[0].bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(io::Error::other("invalid child geometry record"));
            }
            let sequence = fields[0]
                .parse::<u64>()
                .map_err(|_| io::Error::other("child geometry sequence overflow"))?;
            if sequence == 0 || latest.is_some_and(|prior| prior.sequence >= sequence) {
                return Err(io::Error::other("child geometry sequence is not fresh"));
            }
            latest = Some(GeometryReport {
                sequence,
                buffer: dimensions(fields[1], "buffer=")?,
                viewport: dimensions(fields[2], "viewport=")?,
                frame: dimensions(fields[3], "frame=")?,
            });
        }
        Ok(latest)
    }

    fn read_geometry_report(path: &std::path::Path) -> io::Result<Option<GeometryReport>> {
        let mut text = String::new();
        std::fs::File::open(path)
            .map_err(|_| io::Error::other("child geometry report unavailable"))?
            .take(8193)
            .read_to_string(&mut text)
            .map_err(|_| io::Error::other("child geometry report read failed"))?;
        if text.len() > 8192 {
            return Err(io::Error::other("child geometry report exceeds its bound"));
        }
        parse_geometry_reports(&text)
    }

    fn exercise_resize(fixture: &Fixture, geometry: &std::path::Path) -> io::Result<()> {
        for (columns, rows, expected) in [
            (100, 30, "Items (selection is metadata only)"),
            (42, 12, "Password Manager"),
            (80, 24, "Items (selection is metadata only)"),
        ] {
            let previous_native = read_geometry_report(geometry)?
                .ok_or_else(|| io::Error::other("initial child native geometry witness absent"))?
                .sequence;
            let (previous_positions, previous_reports) = {
                let mut state = fixture
                    .observer
                    .state
                    .lock()
                    .map_err(|_| io::Error::other("resize observer poisoned"))?;
                let previous_positions = state.cursor_positions;
                let previous_reports = state.resize_reports;
                if unsafe {
                    ResizePseudoConsole(
                        fixture.pseudo_console,
                        COORD {
                            X: columns,
                            Y: rows,
                        },
                    )
                } != 0
                {
                    return Err(io::Error::other("native ConPTY resize rejected"));
                }
                state.columns = columns as usize;
                state.rows = rows as usize;
                // No inferred reflow content: demand new native output at this geometry.
                state.cells = vec![ScreenCell::Empty; state.columns * state.rows];
                state.row = 0;
                state.column = 0;
                state.saved_row = 0;
                state.saved_column = 0;
                state.wrap_pending = false;
                (previous_positions, previous_reports)
            };
            fixture
                .observer
                .wait_for_checked_matching("fresh native resize repaint", |state| {
                    let native = read_geometry_report(geometry).map_err(|_| "child native geometry read failed".to_owned())?;
                    Ok(state.cursor_positions > previous_positions
                        && state.contains(expected)
                        && state.columns == columns as usize && state.rows == rows as usize
                        && native.is_some_and(|native| native.sequence > previous_native
                            && native.buffer == (columns as u16, rows as u16)
                            && native.viewport == (columns as u16, rows as u16)
                            && native.frame == (columns as u16, rows as u16)))
                })
                .map_err(|primary| {
                    let discriminants = fixture.observer.state.lock().map(|state| format!(
                        "report-fresh={} cursor-fresh={} expected-present={} geometry-matches={} child-witness-valid={}",
                        state.resize_reports > previous_reports,
                        state.cursor_positions > previous_positions,
                        state.contains(expected),
                        state.columns == columns as usize && state.rows == rows as usize,
                        read_geometry_report(geometry).is_ok_and(|native| native.is_some_and(|native| native.sequence > previous_native && native.buffer == (columns as u16, rows as u16) && native.viewport == (columns as u16, rows as u16) && native.frame == (columns as u16, rows as u16))),
                    ));
                    io::Error::other(format!(
                        "{primary}; resize={columns}x{rows}; discriminants={discriminants:?}; child={:?}; observer={:?}",
                        child_diagnostic(fixture.process),
                        fixture.observer.diagnostic(),
                    ))
                })?;
        }
        eprintln!("TUI_STAGE stage=resize-native-100x30-42x12-80x24 result=pass");
        Ok(())
    }

    fn reject_invalid_local_sources(fixture: &Fixture, source: &str) -> io::Result<()> {
        let empty = std::path::Path::new(source).with_extension("negative-empty.1pux");
        let directory = std::path::Path::new(source).with_extension("negative-directory.1pux");
        if empty.try_exists()? || directory.try_exists()? {
            return Err(io::Error::other("owned 1PUX negative source collision"));
        }
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&empty)?;
        use std::os::windows::io::IntoRawHandle;
        let mut handle = file.into_raw_handle();
        let mut close_errors = Vec::new();
        close_handle(
            &mut handle,
            "CloseHandle(owned empty source)",
            &mut close_errors,
        );
        if !close_errors.is_empty() {
            return Err(io::Error::other(close_errors.join("; ")));
        }
        if let Err(error) = std::fs::create_dir(&directory) {
            return match std::fs::remove_file(&empty) {
                Ok(()) => Err(error),
                Err(cleanup) => Err(io::Error::other(format!(
                    "{error}; empty-source cleanup: {cleanup}"
                ))),
            };
        }
        let operation = (|| {
            for path in [&empty, &directory] {
                crate::acl::Sampling::observe(fixture.process, false, || {
                    open_menu(fixture, "m", "Migration:")?;
                    open_menu(fixture, "2", "1PUX source")?;
                    let path = path
                        .to_str()
                        .ok_or_else(|| io::Error::other("synthetic source not UTF-8"))?;
                    let request = format!("{}|keep", encode_operation_field(path));
                    type_visible_and_submit(fixture, &request, "|keep")?;
                    fixture
                        .observer
                        .wait_for("Operation failed explicitly; no success was recorded")
                        .map_err(io::Error::other)
                })?;
            }
            eprintln!("TUI_STAGE stage=source-empty-directory-rejected-dacl-unchanged result=pass");
            Ok(())
        })();
        let empty_cleanup = std::fs::remove_file(&empty);
        let directory_cleanup = std::fs::remove_dir(&directory);
        let errors = [operation, empty_cleanup, directory_cleanup]
            .into_iter()
            .filter_map(Result::err)
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(errors.join("; ")))
        }
    }

    fn reject_multilink_source(fixture: &Fixture, source: &str) -> io::Result<()> {
        let alias = std::path::Path::new(source).with_extension("negative-hardlink.1pux");
        if alias.try_exists()? {
            return Err(io::Error::other("owned 1PUX negative alias collision"));
        }
        std::fs::hard_link(source, &alias)?;
        let operation = (|| {
            crate::acl::Sampling::observe(fixture.process, false, || {
                open_menu(fixture, "m", "Migration:")?;
                open_menu(fixture, "2", "1PUX source")?;
                let request = format!("{}|keep", encode_operation_field(source));
                type_visible_and_submit(fixture, &request, "|keep")?;
                fixture
                    .observer
                    .wait_for("Operation failed explicitly; no success was recorded")
                    .map_err(io::Error::other)
            })?;
            eprintln!("TUI_STAGE stage=source-multilink-rejected-dacl-unchanged result=pass");
            Ok(())
        })();
        let cleanup = std::fs::remove_file(&alias);
        match (operation, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(error), Err(cleanup)) => Err(io::Error::other(format!(
                "{error}; negative-source cleanup: {cleanup}"
            ))),
        }
    }

    fn recovery_code(state: &ScreenState) -> Option<zeroize::Zeroizing<String>> {
        let rows = state.information_rows()?;
        let index = rows.iter().position(|row| row == "Recovery code:")?;
        let value = zeroize::Zeroizing::new(rows[index + 1..].join(""));
        let parts = value.split('-').collect::<Vec<_>>();
        if parts.len() != 12
            || parts[0] != "PMR1"
            || parts[1].len() != 32
            || !parts[1].bytes().all(|b| b.is_ascii_hexdigit())
            || parts[2].is_empty()
            || !parts[2].bytes().all(|b| b.is_ascii_digit())
            || !parts[3..]
                .iter()
                .all(|p| p.len() == 8 && p.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return None;
        }
        Some(value)
    }

    fn exercise_restore_rotations(
        fixture: &Fixture,
        paths: &MatrixPaths<'_>,
        master: &[u8],
    ) -> io::Result<()> {
        open_menu(fixture, "b", "Backup/recovery:")?;
        open_menu(
            fixture,
            "3",
            "Archive path|RESTORE (adds new IDs/keys; current authority is preserved):",
        )?;
        let restore = format!("{}|RESTORE", encode_operation_field(paths.backup));
        type_visible_and_submit(fixture, &restore, "|RESTORE")?;
        fixture.observer.wait_for_information("Restore committed with new IDs/keys; current authority preserved and imported grants inactive").map_err(io::Error::other)?;
        eprintln!("TUI_STAGE stage=restore result=pass");
        exercise_rotations(fixture, master)
    }

    fn exercise_rotations(fixture: &Fixture, master: &[u8]) -> io::Result<()> {
        open_menu(fixture, "b", "Backup/recovery:")?;
        open_menu(fixture, "5", "Recovery code shown temporarily")?;
        let code = fixture
            .observer
            .wait_for_recovery_code()
            .map_err(io::Error::other)?;
        // No secret code is printed or sent through a visible-input oracle.
        let request = zeroize::Zeroizing::new(format!("{}\r", code.as_str()));
        write_keyboard_input(fixture, request.as_bytes())?;
        fixture
            .observer
            .wait_for_information(
                "Recovery rotated after exact re-entry; historical backups/copies remain usable",
            )
            .map_err(io::Error::other)?;
        eprintln!("TUI_STAGE stage=recovery-rotation result=pass");
        open_menu(fixture, "b", "Backup/recovery:")?;
        open_menu(
            fixture,
            "4",
            "New master password|ROTATE (old backups and exposed copies retain historical recovery paths):",
        )?;
        let mut request = zeroize::Zeroizing::new(master.to_vec());
        request.extend_from_slice(b"|ROTATE\r");
        write_keyboard_input(fixture, &request)?;
        fixture
            .observer
            .wait_for_information(
                "Master password rotated; old backups and exposed copies retain historical paths",
            )
            .map_err(io::Error::other)?;
        fixture.observer.rejects(master).map_err(io::Error::other)?;
        eprintln!("TUI_STAGE stage=master-rotation result=pass");
        Ok(())
    }

    fn child_diagnostic(process: HANDLE) -> io::Result<String> {
        const STILL_ACTIVE: u32 = 259;
        let mut exit_code = 0;
        if process.is_null() || unsafe { GetExitCodeProcess(process, &raw mut exit_code) } == 0 {
            return Err(win32("GetExitCodeProcess during TUI diagnosis"));
        }
        if exit_code == STILL_ACTIVE {
            Ok("child=running".to_owned())
        } else {
            Ok(format!("child=exited:{exit_code}"))
        }
    }

    fn require_tui_exit(process: HANDLE) -> io::Result<()> {
        let wait = unsafe { WaitForSingleObject(process, 15_000) };
        if wait == WAIT_FAILED {
            return Err(win32(
                "WaitForSingleObject(pm-custody.exe tui natural exit)",
            ));
        }
        if wait == WAIT_TIMEOUT {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "pm-custody.exe tui did not exit within 15 seconds after q",
            ));
        }
        if wait != WAIT_OBJECT_0 {
            return Err(io::Error::other("unexpected TUI natural-exit wait result"));
        }
        let mut exit_code = 0;
        if unsafe { GetExitCodeProcess(process, &raw mut exit_code) } == 0 {
            return Err(win32("GetExitCodeProcess after q"));
        }
        if exit_code == 0 {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "pm-custody.exe tui exited {exit_code} after q"
            )))
        }
    }

    fn exercise(args: &[String]) -> io::Result<()> {
        if args.len() < 11
            || !matches!(
                args.get(3).map(String::as_str),
                Some(
                    "--matrix"
                        | "--matrix-probe"
                        | "--encoding-exit"
                        | "--resize"
                        | "--clipboard"
                        | "--local-operations"
                        | "--access"
                        | "--rotations"
                )
            )
            || args.get(8).map(String::as_str) != Some("--")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "usage: fixture <protected-sddl> <pm-custody.exe> --matrix <csv> <1pux> <backup> <plaintext> -- <tui args...>",
            ));
        }
        let password = read_synthetic_password()?;
        let mut fixture = Fixture::new();
        let scenario = match args[3].as_str() {
            "--matrix" | "--matrix-probe" => Scenario::Matrix,
            "--encoding-exit" => Scenario::EncodingExit,
            "--resize" => Scenario::Resize,
            "--clipboard" => Scenario::Clipboard,
            "--local-operations" => Scenario::LocalOperations,
            "--access" => Scenario::Access,
            "--rotations" => Scenario::Rotations,
            _ => return Err(io::Error::other("unknown native TUI scenario")),
        };
        let diagnostic_path = std::path::Path::new(&args[4]).with_file_name(match scenario {
            Scenario::EncodingExit => "encoding-exit.txt",
            Scenario::Resize => "resize-diagnostic.txt",
            _ => "console-diagnostic.txt",
        });
        let mut child_arguments = args[9..].to_vec();
        let diagnostics_enabled = matches!(
            scenario,
            Scenario::Matrix | Scenario::EncodingExit | Scenario::Resize
        );
        if diagnostics_enabled {
            child_arguments.push("--console-diagnostics".into());
            child_arguments.push(
                diagnostic_path
                    .to_str()
                    .ok_or_else(|| io::Error::other("console diagnostic path is not UTF-8"))?
                    .into(),
            );
        }
        let operation = (|| {
            let desktop = create_private_desktop(&mut fixture, &args[1])?;
            setup_conpty(&mut fixture)?;
            setup_attributes(&mut fixture)?;
            spawn_tui(&mut fixture, &args[2], &desktop, &child_arguments)?;
            start_drain_and_release_conpty_ends(&mut fixture)?;
            exercise_keyboard_screen(
                &fixture,
                &password,
                MatrixPaths {
                    csv: &args[4],
                    onepux: &args[5],
                    backup: &args[6],
                    plaintext: &args[7],
                    geometry: &diagnostic_path,
                },
                scenario,
            )
        })();
        let cleanup = fixture.cleanup();
        let diagnostic = (|| {
            if !diagnostics_enabled {
                return Ok(());
            }
            let file = std::fs::File::open(&diagnostic_path)?;
            let mut metrics = String::new();
            file.take(8193).read_to_string(&mut metrics)?;
            if metrics.len() > 8192
                || metrics.lines().any(|line| {
                    !line.starts_with("TUI_PROBE ")
                        || !line.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || b"= ,:()?._-".contains(&byte)
                        })
                })
            {
                return Err(io::Error::other(
                    "console diagnostic is not bounded public metrics",
                ));
            }
            eprint!("{metrics}");
            if scenario == Scenario::EncodingExit {
                let restoration = metrics
                    .lines()
                    .filter(|line| line.starts_with("TUI_PROBE stage=restore "))
                    .collect::<Vec<_>>();
                if restoration.len() != 1 || !restoration[0].ends_with(" restored=true") {
                    return Err(io::Error::other(
                        "encoding exit did not prove exactly one successful CP restoration",
                    ));
                }
            }
            Ok(())
        })();
        let operation = match (operation, diagnostic) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(primary), Ok(())) => Err(primary),
            (Ok(()), Err(diagnostic)) => Err(diagnostic),
            (Err(primary), Err(diagnostic)) => Err(io::Error::other(format!(
                "{primary}; console diagnostic unavailable: {diagnostic}"
            ))),
        };
        match (operation, cleanup) {
            (Ok(()), Ok(Some(report))) if !report.overflow && report.captured_bytes > 0 => Ok(()),
            (Ok(()), Ok(_)) => Err(io::Error::other(
                "ConPTY product output was absent or exceeded the 1 MiB fixture bound",
            )),
            (Err(primary), Ok(Some(report))) if !report.overflow && report.captured_bytes > 0 => {
                Err(io::Error::other(format!(
                    "{primary}; conpty-product-output=present"
                )))
            }
            (Err(primary), Ok(_)) => Err(io::Error::other(format!(
                "{primary}; ConPTY product output absent or exceeded 1 MiB"
            ))),
            (Ok(()), Err(cleanup)) => Err(io::Error::other(cleanup)),
            (Err(primary), Err(cleanup)) => Err(io::Error::other(format!(
                "{primary}; cleanup failed: {cleanup}"
            ))),
        }
    }

    pub fn main() {
        let args = std::env::args().collect::<Vec<_>>();
        if let Err(error) = exercise(&args) {
            eprintln!("TUI_CONPTY_RED {error}");
            std::process::exit(1);
        }
        println!("TUI_CONPTY_READY");
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn observer_validates_resize_reports_without_inventing_repaint() {
            let observer = TerminalObserver::new();
            observer.feed(b"\x1b[8;24;80t").unwrap();
            let state = observer.state.lock().unwrap();
            assert_eq!(state.resize_reports, 1);
            assert_eq!(state.cursor_positions, 0);
            assert!(
                state
                    .cells
                    .iter()
                    .all(|cell| matches!(cell, ScreenCell::Empty))
            );
        }

        #[test]
        fn observer_rejects_wrong_resize_geometry_or_unrecognized_window_ops() {
            for sequence in [
                b"\x1b[8;30;100t".as_slice(),
                b"\x1b[4;24;80t",
                b"\x1b[8;24t",
                b"\x1b[?8;24;80t",
            ] {
                let observer = TerminalObserver::new();
                assert!(observer.feed(sequence).is_err());
                assert_eq!(observer.state.lock().unwrap().resize_reports, 0);
            }
        }

        #[test]
        fn observer_distinguishes_note_secret_from_its_public_type() {
            let observer = TerminalObserver::new();
            observer.feed(b"[note] synthetic public title").unwrap();
            assert!(observer.rejects(b"note").is_err());
            observer.rejects(b"ticket27-native-note-canary").unwrap();
            observer
                .feed(b"\x1b[22;2HExposure: ticket27-native-note-canary")
                .unwrap();
            assert!(observer.rejects(b"ticket27-native-note-canary").is_err());
            observer
                .feed(b"\x1b[22;2H\x1b[2KExposure: <hidden>")
                .unwrap();
            observer.rejects(b"ticket27-native-note-canary").unwrap();
        }

        #[test]
        fn observer_requires_mandatory_information_in_main_panel() {
            let observer = TerminalObserver::new();
            observer
                .feed(b"\x1b[20;2HPreview values hidden: exact-duplicates=1")
                .unwrap();
            assert!(
                !observer
                    .state
                    .lock()
                    .unwrap()
                    .information_contains("exact-duplicates=1")
            );
            observer.feed("\x1b[4;1H┌Information───────────────────────────────────────────────────────────────────┐".as_bytes()).unwrap();
            for y in 5..18 {
                let text = if y == 5 {
                    "Preview values hidden: exact-duplicates=1"
                } else {
                    ""
                };
                observer
                    .feed(format!("\x1b[{y};1H│{text:<78}│").as_bytes())
                    .unwrap();
            }
            observer.wait_for_information("exact-duplicates=1").unwrap();
        }

        #[test]
        fn observer_matches_footer_suffix_and_cursor_in_one_screen() {
            let observer = TerminalObserver::new();
            observer
                .feed("\x1b[21;1H│Input: ‹synthetic|chrome|keep".as_bytes())
                .unwrap();
            observer.feed(b"\x1b[21;79H").unwrap();
            observer.wait_for_footer_suffix("|chrome|keep").unwrap();
        }

        #[test]
        fn observer_reconstructs_positioned_unicode_screen() {
            let observer = TerminalObserver::new();
            observer
                .feed(b"\x1b[?1049h\x1b[2J\x1b[1;1HPassword Manager \xe2")
                .unwrap();
            observer
                .feed(b"\x80\x94 human TLS-RPK\x1b[4;1HPassword required (input hidden)")
                .unwrap();
            observer
                .wait_for("Password Manager \u{2014} human TLS-RPK")
                .unwrap();
            observer
                .wait_for("Password required (input hidden)")
                .unwrap();
            observer.feed("\x1b[6;1Hcafé ┌─┐│└┘".as_bytes()).unwrap();
            observer.wait_for("café ┌─┐│└┘").unwrap();
        }

        #[test]
        fn observer_models_wide_and_combining_unicode_without_approximating_cells() {
            let observer = TerminalObserver::new();
            observer.feed("A🌎e\u{301}Z".as_bytes()).unwrap();
            observer.wait_for("A🌎e\u{301}Z").unwrap();
            let state = observer.state.lock().unwrap();
            assert_eq!(state.column, 5);
            assert_eq!(state.cells[1], ScreenCell::Glyph("🌎".into()));
            assert_eq!(state.cells[2], ScreenCell::WideContinuation);
            assert_eq!(state.cells[3], ScreenCell::Glyph("e\u{301}".into()));
        }

        #[test]
        fn observer_diagnostic_distinguishes_row_geometry_from_missing_text() {
            let observer = TerminalObserver::new();
            observer.feed(&[b'x'; SCREEN_COLUMNS - 4]).unwrap();
            observer.feed(b"Pass").unwrap();
            observer.feed(b"word").unwrap();
            let state = observer.state.lock().unwrap();
            assert!(!state.contains("Password"));
            assert!(state.contains_flat("Password"));
            assert_eq!(state.delayed_wraps, 1);
        }

        #[test]
        fn observer_diagnostic_tracks_only_fixed_raw_markers_across_chunks() {
            let observer = TerminalObserver::new();
            observer.feed(b"Password req").unwrap();
            observer.feed(b"uired synthetic-unreported-value").unwrap();
            let diagnostic = observer.diagnostic().unwrap();
            assert!(diagnostic.contains("password:true/flat:true/raw:true"));
            assert!(!diagnostic.contains("synthetic-unreported-value"));
        }

        #[test]
        fn operation_field_encoder_preserves_windows_paths_under_existing_grammar() {
            let encoded = encode_operation_field(r"C:\fixture\a|b.1pux");
            assert_eq!(encoded, r"C:\\fixture\\a\|b.1pux");
        }

        #[test]
        fn observer_models_delayed_wrap_margin_controls_and_bottom_scroll() {
            let observer = TerminalObserver::new();
            observer.feed(&[b'x'; SCREEN_COLUMNS]).unwrap();
            {
                let state = observer.state.lock().unwrap();
                assert_eq!((state.row, state.column, state.wrap_pending), (0, 79, true));
            }
            observer.feed(b"y").unwrap();
            {
                let state = observer.state.lock().unwrap();
                assert_eq!((state.row, state.column, state.wrap_pending), (1, 1, false));
                assert_eq!(state.cells[SCREEN_COLUMNS], ScreenCell::Glyph("y".into()));
            }

            observer.feed(b"\x1b[1;80Hz\rR").unwrap();
            {
                let state = observer.state.lock().unwrap();
                assert_eq!(state.cells[0], ScreenCell::Glyph("R".into()));
                assert_eq!(state.row, 0);
            }
            observer.feed(b"\x1b[1;80Hq\x1b[2KE").unwrap();
            {
                let state = observer.state.lock().unwrap();
                assert_eq!(state.cells[79], ScreenCell::Glyph("E".into()));
                assert!(state.wrap_pending);
            }
            observer.feed(b"\x1b[24;80Hb\np").unwrap();
            let state = observer.state.lock().unwrap();
            assert_eq!(state.row, 23);
            assert_eq!(
                state.cells[23 * SCREEN_COLUMNS + 79],
                ScreenCell::Glyph("p".into())
            );
        }

        #[test]
        fn observer_erases_characters_without_shifting_or_moving_the_cursor() {
            let observer = TerminalObserver::new();
            observer.feed(b"abcdef\x1b[1;3H\x1b[2X").unwrap();
            {
                let state = observer.state.lock().unwrap();
                assert!(state.contains("ab  ef"));
                assert_eq!((state.row, state.column), (0, 2));
            }
            observer.feed(b"\x1b[1;5H\x1b[X").unwrap();
            assert!(observer.state.lock().unwrap().contains("ab   f"));
            observer.feed(b"\x1b[1;6H\x1b[0X").unwrap();
            assert!(!observer.state.lock().unwrap().contains("f"));
            observer
                .feed("\x1b[2;1HA🌎Z\x1b[2;3H\x1b[X".as_bytes())
                .unwrap();
            {
                let state = observer.state.lock().unwrap();
                assert!(state.contains("A  Z"));
                assert_eq!((state.row, state.column), (1, 2));
            }
            observer.feed(b"\x1b[1;80Hz\x1b[32767X").unwrap();
            let state = observer.state.lock().unwrap();
            assert_eq!(
                (state.row, state.column, state.wrap_pending),
                (0, 79, false)
            );
            assert_eq!(state.cells[79], ScreenCell::Empty);
            assert_eq!(state.cells[SCREEN_COLUMNS], ScreenCell::Glyph("A".into()));
        }

        #[test]
        fn observer_rejects_unsupported_sequences_instead_of_stripping_them() {
            let observer = TerminalObserver::new();
            let error = observer
                .feed(b"visible\x1b]52;clipboard-payload\x07")
                .unwrap_err();
            assert_eq!(error, "unsupported ConPTY OSC command");
            assert!(!error.contains("clipboard-payload"));
        }

        #[test]
        fn observer_tracks_window_titles_without_rendering_them() {
            let observer = TerminalObserver::new();
            observer.feed(b"visible\x1b]0;synthetic ").unwrap();
            observer.feed(b"\xe2\x80\x94 title\x1b").unwrap();
            observer.feed(b"\\still-visible\x1b]2;second\x07").unwrap();
            observer.wait_for("visiblestill-visible").unwrap();
            let state = observer.state.lock().unwrap();
            assert_eq!(state.window_title_updates, 2);
            assert!(!state.contains("synthetic"));
            assert!(!state.contains("second"));
        }

        #[test]
        fn observer_rejects_invalid_window_titles() {
            let observer = TerminalObserver::new();
            let error = observer.feed(b"\x1b]0;bad\x01title\x07").unwrap_err();
            assert_eq!(error, "invalid or overlong ConPTY window title");

            let observer = TerminalObserver::new();
            let error = observer.feed(b"\x1b]2;bad\xff\x07").unwrap_err();
            assert_eq!(error, "invalid UTF-8 in ConPTY window title");
        }

        #[test]
        fn observer_classifies_private_csi_without_screen_content() {
            let observer = TerminalObserver::new();
            let error = observer
                .feed(b"secret-not-reported\x1b[?7777h")
                .unwrap_err();
            assert_eq!(
                error,
                "unsupported private ConPTY CSI modes=[7777] count=1 final=0x68"
            );
            assert!(!error.contains("secret-not-reported"));
        }

        #[test]
        fn observer_tracks_conpty_win32_input_mode_without_changing_screen() {
            let observer = TerminalObserver::new();
            observer.feed(b"visible\x1b[?9001h").unwrap();
            observer.wait_for("visible").unwrap();
            assert!(observer.state.lock().unwrap().win32_input);
            observer.feed(b"\x1b[?9001l").unwrap();
            let state = observer.state.lock().unwrap();
            assert!(!state.win32_input);
            assert!(state.contains("visible"));
        }

        #[test]
        fn observer_tracks_focus_reporting_without_inventing_focus_events() {
            let observer = TerminalObserver::new();
            observer.feed(b"visible\x1b[?1004h").unwrap();
            assert!(observer.state.lock().unwrap().focus_reporting);
            observer.feed(b"\x1b[?1004l").unwrap();
            let state = observer.state.lock().unwrap();
            assert!(!state.focus_reporting);
            assert!(state.contains("visible"));
        }

        #[test]
        fn win32_input_encoder_preserves_key_fields_and_press_release() {
            let encoded = encode_win32_key_events("a\r\x1bé").unwrap();
            let text = std::str::from_utf8(&encoded).unwrap();
            assert!(text.starts_with("\x1b[65;"));
            assert!(text.contains(";97;1;0;1_\x1b[65;"));
            assert!(text.contains(";97;0;0;1_"));
            assert!(text.contains(";13;1;0;1_"));
            assert!(text.contains(";13;0;0;1_"));
            let scan = unsafe { MapVirtualKeyW(27, MAPVK_VK_TO_VSC) };
            assert_ne!(scan, 0);
            assert!(text.contains(&format!("\x1b[27;{scan};27;1;0;1_\x1b[27;{scan};27;0;0;1_")));
            assert!(text.ends_with("\x1b[0;0;233;0;0;1_"));
        }

        #[test]
        fn child_geometry_requires_complete_monotonic_native_witnesses() {
            let initial = "TUI_PROBE geometry-seq=1 buffer=80x24 viewport=80x24 frame=80x24\n";
            let partial = "TUI_PROBE geometry-seq=2 buffer=42x12 viewport=42x12 frame=42x12";
            assert_eq!(parse_geometry_reports(partial).unwrap(), None);
            assert_eq!(
                parse_geometry_reports(&format!("{initial}{partial}"))
                    .unwrap()
                    .unwrap()
                    .sequence,
                1
            );
            let complete = format!("{initial}{partial}\n");
            let witness = parse_geometry_reports(&complete).unwrap().unwrap();
            assert_eq!(
                (
                    witness.sequence,
                    witness.buffer,
                    witness.viewport,
                    witness.frame
                ),
                (2, (42, 12), (42, 12), (42, 12))
            );
            assert!(parse_geometry_reports(&format!("{initial}{initial}")).is_err());
            assert!(
                parse_geometry_reports(
                    "TUI_PROBE geometry-seq=2 buffer=42x12 viewport=42x12 frame=0x12\n"
                )
                .is_err()
            );
        }

        #[test]
        fn native_witness_query_failure_is_explicit_without_waiting_for_timeout() {
            let observer = TerminalObserver::new();
            let error = observer
                .wait_for_checked_matching("native geometry", |_| {
                    Err("native query failed".to_owned())
                })
                .unwrap_err();
            assert_eq!(error, "native query failed");
        }

        #[test]
        fn observer_rejects_invalid_utf8_instead_of_replacing_it() {
            let observer = TerminalObserver::new();
            let error = observer.feed(&[0xff]).unwrap_err();
            assert_eq!(error, "invalid UTF-8 in ConPTY product output");
        }
    }
}

#[cfg(target_os = "windows")]
fn main() {
    windows_fixture::main();
}
