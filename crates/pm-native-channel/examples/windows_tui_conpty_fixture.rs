// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("the Windows TUI ConPTY fixture requires Windows");
    std::process::exit(2);
}

#[cfg(target_os = "windows")]
mod windows_fixture {
    use std::{
        ffi::c_void,
        io::{self, Read},
        ptr,
        sync::{
            Arc, Condvar, Mutex,
            atomic::{AtomicU64, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, ERROR_BROKEN_PIPE, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_DATA, GetLastError,
            HANDLE, WAIT_FAILED, WAIT_OBJECT_0,
        },
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            SECURITY_ATTRIBUTES,
        },
        System::{
            Console::{COORD, ClosePseudoConsole, CreatePseudoConsole},
            Pipes::CreatePipe,
            StationsAndDesktops::{
                CloseDesktop, CloseWindowStation, CreateDesktopW, CreateWindowStationW,
                GetProcessWindowStation, GetUserObjectInformationW, SetProcessWindowStation,
                UOI_NAME,
            },
            Threading::{
                CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
                INFINITE, InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                PROCESS_INFORMATION, STARTUPINFOEXW, UpdateProcThreadAttribute,
                WaitForSingleObject,
            },
        },
        UI::WindowsAndMessaging::{CWF_CREATE_ONLY, WINSTA_ALL_ACCESS},
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
    }

    struct ScreenState {
        cells: Vec<char>,
        row: usize,
        column: usize,
        saved_row: usize,
        saved_column: usize,
        parse: ParseState,
        csi: Vec<u8>,
        utf8: Vec<u8>,
        error: Option<String>,
        closed: bool,
    }

    impl Drop for ScreenState {
        fn drop(&mut self) {
            self.cells.fill('\0');
            self.csi.fill(0);
            self.utf8.fill(0);
        }
    }

    impl ScreenState {
        fn new() -> Self {
            Self {
                cells: vec![' '; SCREEN_COLUMNS * SCREEN_ROWS],
                row: 0,
                column: 0,
                saved_row: 0,
                saved_column: 0,
                parse: ParseState::Ground,
                csi: Vec::new(),
                utf8: Vec::new(),
                error: None,
                closed: false,
            }
        }

        fn contains(&self, expected: &str) -> bool {
            self.cells
                .chunks(SCREEN_COLUMNS)
                .any(|row| row.iter().collect::<String>().contains(expected))
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
                match self.parse {
                    ParseState::Ground => self.feed_ground(*byte),
                    ParseState::Escape => match *byte {
                        b'[' => {
                            self.csi.clear();
                            self.parse = ParseState::Csi;
                        }
                        b'7' => {
                            self.saved_row = self.row;
                            self.saved_column = self.column;
                            self.parse = ParseState::Ground;
                        }
                        b'8' => {
                            self.row = self.saved_row;
                            self.column = self.saved_column;
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
                }
            }
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
                0x1b => self.parse = ParseState::Escape,
                b'\r' => self.column = 0,
                b'\n' => self.row = (self.row + 1).min(SCREEN_ROWS - 1),
                0x08 => self.column = self.column.saturating_sub(1),
                0x20..=0x7e => self.put(char::from(byte)),
                value => self.fail(format!("unsupported ConPTY control byte: 0x{value:02x}")),
            }
        }

        fn put(&mut self, character: char) {
            if character.is_control() || self.row >= SCREEN_ROWS || self.column >= SCREEN_COLUMNS {
                self.fail("ConPTY character was outside the observable screen");
                return;
            }
            self.cells[self.row * SCREEN_COLUMNS + self.column] = character;
            self.column += 1;
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
                        .any(|value| !matches!(value, 25 | 1049 | 2026))
                {
                    self.fail("unsupported private ConPTY CSI sequence");
                } else if command == b'h' && parameters.contains(&1049) {
                    self.cells.fill(' ');
                    self.row = 0;
                    self.column = 0;
                }
                return;
            }
            let first = parameters.first().copied().unwrap_or(0);
            let distance = || if first == 0 { 1 } else { first };
            match command {
                b'm' => {}
                b'H' | b'f' if parameters.len() <= 2 => {
                    let row = parameters.first().copied().unwrap_or(1).max(1) - 1;
                    let column = parameters.get(1).copied().unwrap_or(1).max(1) - 1;
                    if row >= SCREEN_ROWS || column >= SCREEN_COLUMNS {
                        self.fail("ConPTY absolute cursor position outside screen");
                    } else {
                        self.row = row;
                        self.column = column;
                    }
                }
                b'A' if parameters.len() <= 1 => self.row = self.row.saturating_sub(distance()),
                b'B' if parameters.len() <= 1 => {
                    self.row = (self.row + distance()).min(SCREEN_ROWS - 1);
                }
                b'C' if parameters.len() <= 1 => {
                    self.column = (self.column + distance()).min(SCREEN_COLUMNS - 1);
                }
                b'D' if parameters.len() <= 1 => {
                    self.column = self.column.saturating_sub(distance());
                }
                b'G' if parameters.len() <= 1 => {
                    let column = distance() - 1;
                    if column >= SCREEN_COLUMNS {
                        self.fail("ConPTY horizontal cursor position outside screen");
                    } else {
                        self.column = column;
                    }
                }
                b'd' if parameters.len() <= 1 => {
                    let row = distance() - 1;
                    if row >= SCREEN_ROWS {
                        self.fail("ConPTY vertical cursor position outside screen");
                    } else {
                        self.row = row;
                    }
                }
                b'J' if parameters.len() <= 1 && matches!(first, 0 | 2 | 3) => {
                    if first == 2 || first == 3 {
                        self.cells.fill(' ');
                    } else {
                        for cell in &mut self.cells[self.row * SCREEN_COLUMNS + self.column..] {
                            *cell = ' ';
                        }
                    }
                }
                b'K' if parameters.len() <= 1 && matches!(first, 0 | 1 | 2) => {
                    let start = self.row * SCREEN_COLUMNS;
                    let (from, through) = match first {
                        0 => (start + self.column, start + SCREEN_COLUMNS),
                        1 => (start, start + self.column + 1),
                        2 => (start, start + SCREEN_COLUMNS),
                        _ => unreachable!(),
                    };
                    self.cells[from..through].fill(' ');
                }
                b's' if parameters.is_empty() => {
                    self.saved_row = self.row;
                    self.saved_column = self.column;
                }
                b'u' if parameters.is_empty() => {
                    self.row = self.saved_row;
                    self.column = self.saved_column;
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
            self.changed.notify_all();
            Ok(())
        }

        fn finish(&self) -> Result<(), String> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| "ConPTY screen observer lock poisoned".to_owned())?;
            state.finish();
            self.changed.notify_all();
            Ok(())
        }

        fn wait_for(&self, expected: &str) -> Result<(), String> {
            let deadline = Instant::now() + SCREEN_WAIT;
            let mut state = self
                .state
                .lock()
                .map_err(|_| "ConPTY screen observer lock poisoned".to_owned())?;
            loop {
                if let Some(error) = state.error.as_ref() {
                    return Err(error.clone());
                }
                if state.contains(expected) {
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
                if wait.timed_out() && !state.contains(expected) {
                    return Err(format!(
                        "ConPTY screen did not show expected text within 15 seconds: {expected}"
                    ));
                }
            }
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

    fn exercise_keyboard_screen(fixture: &Fixture, password: &[u8]) -> io::Result<()> {
        fixture
            .observer
            .wait_for("Password required (input hidden)")
            .map_err(io::Error::other)?;
        let mut input = zeroize::Zeroizing::new(password.to_vec());
        input.push(b'\r');
        write_conpty_input(fixture.input_write, &input)?;
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
        write_conpty_input(fixture.input_write, b"q")
    }

    fn exercise(args: &[String]) -> io::Result<()> {
        if args.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "usage: fixture <protected-sddl> <pm-custody.exe> <tui args...>",
            ));
        }
        let password = read_synthetic_password()?;
        let mut fixture = Fixture::new();
        let operation = (|| {
            let desktop = create_private_desktop(&mut fixture, &args[1])?;
            setup_conpty(&mut fixture)?;
            setup_attributes(&mut fixture)?;
            spawn_tui(&mut fixture, &args[2], &desktop, &args[3..])?;
            start_drain_and_release_conpty_ends(&mut fixture)?;
            exercise_keyboard_screen(&fixture, &password)
        })();
        let cleanup = fixture.cleanup();
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
        }

        #[test]
        fn observer_rejects_unsupported_sequences_instead_of_stripping_them() {
            let observer = TerminalObserver::new();
            observer.feed(b"visible\x1b]0;concealed\x07").unwrap();
            let error = observer.wait_for("concealed").unwrap_err();
            assert!(error.contains("unsupported ConPTY escape"));
        }

        #[test]
        fn observer_rejects_invalid_utf8_instead_of_replacing_it() {
            let observer = TerminalObserver::new();
            observer.feed(&[0xff]).unwrap();
            let error = observer.wait_for("replacement").unwrap_err();
            assert_eq!(error, "invalid UTF-8 in ConPTY product output");
        }
    }
}

#[cfg(target_os = "windows")]
fn main() {
    windows_fixture::main();
}
