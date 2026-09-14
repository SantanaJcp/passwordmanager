// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("the Windows TUI ConPTY fixture requires Windows");
    std::process::exit(2);
}

#[cfg(target_os = "windows")]
mod windows_fixture {
    use std::{ffi::c_void, io, ptr, thread};
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, ERROR_BROKEN_PIPE, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_DATA, GetLastError,
            HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
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
                GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROCESS_INFORMATION, STARTUPINFOEXW,
                UpdateProcThreadAttribute, WaitForSingleObject,
            },
        },
        UI::WindowsAndMessaging::{CWF_CREATE_ONLY, WINSTA_ALL_ACCESS},
    };

    const DESKTOP_ALL_ACCESS: u32 = 0x000f_01ff;
    const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

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

    struct OwnedOutput(HANDLE);

    // SAFETY: the read handle has one owner and moves once to the dedicated drainer.
    unsafe impl Send for OwnedOutput {}

    impl Drop for OwnedOutput {
        fn drop(&mut self) {
            if !self.0.is_null() && unsafe { CloseHandle(self.0) } == 0 {
                std::process::abort();
            }
            self.0 = ptr::null_mut();
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
            let operation = loop {
                let mut chunk = [0_u8; 4096];
                let mut read = 0;
                if unsafe {
                    windows_sys::Win32::Storage::FileSystem::ReadFile(
                        self.0,
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
                    Some(total) if total <= MAX_CAPTURE_BYTES => captured_bytes = total,
                    Some(_) | None => overflow = true,
                }
            };
            let mut cleanup = Vec::new();
            close_handle(&mut self.0, "CloseHandle output reader", &mut cleanup);
            match (operation, cleanup.is_empty()) {
                (Ok(()), true) => Ok(DrainReport {
                    captured_bytes,
                    overflow,
                }),
                (Err(primary), true) => Err(primary),
                (Ok(()), false) => Err(cleanup.join("; ")),
                (Err(primary), false) => Err(format!(
                    "{primary}; output-reader cleanup failed: {}",
                    cleanup.join("; ")
                )),
            }
        }
    }

    struct OutputDrain {
        join: thread::JoinHandle<Result<DrainReport, String>>,
    }

    impl OutputDrain {
        fn start(handle: HANDLE) -> io::Result<Self> {
            let owner = OwnedOutput(handle);
            let join = thread::Builder::new()
                .name("pm27-conpty-drain".to_owned())
                .spawn(move || owner.drain())?;
            Ok(Self { join })
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
            close_handle(
                &mut self.input_read,
                "CloseHandle ConPTY input",
                &mut failures,
            );
            close_handle(
                &mut self.output_write,
                "CloseHandle ConPTY output",
                &mut failures,
            );
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
        fixture.drain = Some(OutputDrain::start(output_read)?);
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

    fn require_keyboard_ready_observer(process: HANDLE) -> io::Result<()> {
        let wait = unsafe { WaitForSingleObject(process, 15_000) };
        if wait == WAIT_FAILED {
            return Err(win32("WaitForSingleObject(pm-custody.exe tui)"));
        }
        if wait == WAIT_TIMEOUT {
            return Err(io::Error::other(
                "normal TUI remained alive but has no verified keyboard-ready observer",
            ));
        }
        if wait != WAIT_OBJECT_0 {
            return Err(io::Error::other("unexpected TUI process wait result"));
        }
        let mut exit_code = 0;
        if unsafe { GetExitCodeProcess(process, &raw mut exit_code) } == 0 {
            return Err(win32("GetExitCodeProcess before keyboard-ready observer"));
        }
        Err(io::Error::other(format!(
            "pm-custody.exe tui exited {exit_code} before keyboard-ready observer"
        )))
    }

    fn exercise(args: &[String]) -> io::Result<()> {
        if args.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "usage: fixture <protected-sddl> <pm-custody.exe> <tui args...>",
            ));
        }
        let mut fixture = Fixture::new();
        let operation = (|| {
            let desktop = create_private_desktop(&mut fixture, &args[1])?;
            setup_conpty(&mut fixture)?;
            setup_attributes(&mut fixture)?;
            spawn_tui(&mut fixture, &args[2], &desktop, &args[3..])?;
            start_drain_and_release_conpty_ends(&mut fixture)?;
            require_keyboard_ready_observer(fixture.process)
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
}

#[cfg(target_os = "windows")]
fn main() {
    windows_fixture::main();
}
