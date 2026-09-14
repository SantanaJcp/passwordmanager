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
        io, ptr, thread,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, ERROR_INSUFFICIENT_BUFFER, GetLastError, HANDLE, WAIT_FAILED,
            WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            SECURITY_ATTRIBUTES,
        },
        System::{
            Console::{COORD, ClosePseudoConsole, CreatePseudoConsole, ResizePseudoConsole},
            Pipes::{CreatePipe, PeekNamedPipe},
            StationsAndDesktops::{
                CloseDesktop, CloseWindowStation, CreateDesktopW, CreateWindowStationW,
                GetProcessWindowStation, GetUserObjectInformationW, SetProcessWindowStation,
                UOI_NAME,
            },
            Threading::{
                CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
                GetExitCodeProcess, InitializeProcThreadAttributeList,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROCESS_INFORMATION, STARTUPINFOEXW,
                UpdateProcThreadAttribute, WaitForSingleObject,
            },
        },
        UI::WindowsAndMessaging::{CWF_CREATE_ONLY, WINSTA_ALL_ACCESS},
    };

    const DESKTOP_ALL_ACCESS: u32 = 0x000f_01ff;
    const MARKER: &[u8] = b"Password Manager \xE2\x80\x94 human TLS-RPK content";
    const UI_DEADLINE: Duration = Duration::from_secs(15);

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
            }
        }

        fn cleanup(&mut self) -> Result<(), String> {
            let mut failures = Vec::new();
            close_handle(&mut self.thread, "CloseHandle thread", &mut failures);
            close_handle(&mut self.process, "CloseHandle process", &mut failures);
            if self.attributes_initialized {
                unsafe { DeleteProcThreadAttributeList(self.attribute_words.as_mut_ptr().cast()) };
                self.attributes_initialized = false;
            }
            if self.pseudo_console != 0 {
                unsafe { ClosePseudoConsole(self.pseudo_console) };
                self.pseudo_console = 0;
            }
            close_handle(
                &mut self.input_read,
                "CloseHandle ConPTY input",
                &mut failures,
            );
            close_handle(
                &mut self.input_write,
                "CloseHandle input writer",
                &mut failures,
            );
            close_handle(
                &mut self.output_read,
                "CloseHandle output reader",
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
                Ok(())
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
        Ok(())
    }

    fn setup_attributes(fixture: &mut Fixture) -> io::Result<()> {
        let mut bytes = 0;
        let first = unsafe {
            InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &raw mut bytes);
        };
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
                (&raw const fixture.pseudo_console).cast(),
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

    fn read_until_marker(fixture: &Fixture) -> io::Result<()> {
        let deadline = Instant::now() + UI_DEADLINE;
        let mut capture = Vec::new();
        loop {
            let process_state = unsafe { WaitForSingleObject(fixture.process, 0) };
            if process_state == WAIT_FAILED {
                return Err(win32("WaitForSingleObject(pm-custody.exe tui)"));
            }
            if process_state == WAIT_OBJECT_0 {
                let mut exit_code = 0;
                if unsafe { GetExitCodeProcess(fixture.process, &raw mut exit_code) } == 0 {
                    return Err(win32("GetExitCodeProcess"));
                }
                return Err(io::Error::other(format!(
                    "pm-custody.exe tui exited {exit_code} before locked-screen marker"
                )));
            }
            let mut available = 0;
            if unsafe {
                PeekNamedPipe(
                    fixture.output_read,
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    &raw mut available,
                    ptr::null_mut(),
                )
            } == 0
            {
                return Err(win32("PeekNamedPipe(ConPTY output)"));
            }
            if available > 0 {
                let chunk_length = usize::try_from(available.min(4096))
                    .map_err(|_| io::Error::other("ConPTY available-byte count overflow"))?;
                let mut chunk = vec![0_u8; chunk_length];
                let requested = u32::try_from(chunk.len())
                    .map_err(|_| io::Error::other("ConPTY read length overflow"))?;
                let mut read = 0;
                if unsafe {
                    windows_sys::Win32::Storage::FileSystem::ReadFile(
                        fixture.output_read,
                        chunk.as_mut_ptr().cast(),
                        requested,
                        &raw mut read,
                        ptr::null_mut(),
                    )
                } == 0
                {
                    return Err(win32("ReadFile(ConPTY output)"));
                }
                let read = usize::try_from(read)
                    .map_err(|_| io::Error::other("ConPTY read count overflow"))?;
                capture.extend_from_slice(&chunk[..read]);
                if capture.windows(MARKER.len()).any(|window| window == MARKER) {
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "pm-custody.exe tui did not display locked-screen marker within 15 seconds",
                ));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn write_key(handle: HANDLE, key: u8) -> io::Result<()> {
        let mut written = 0;
        if unsafe {
            windows_sys::Win32::Storage::FileSystem::WriteFile(
                handle,
                (&raw const key).cast::<c_void>(),
                1,
                &raw mut written,
                ptr::null_mut(),
            )
        } == 0
            || written != 1
        {
            Err(win32("WriteFile(ConPTY input)"))
        } else {
            Ok(())
        }
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
            read_until_marker(&fixture)?;
            let small =
                unsafe { ResizePseudoConsole(fixture.pseudo_console, COORD { X: 42, Y: 12 }) };
            if small < 0 {
                return Err(failed_hresult("ResizePseudoConsole(42x12)", small));
            }
            let large =
                unsafe { ResizePseudoConsole(fixture.pseudo_console, COORD { X: 100, Y: 30 }) };
            if large < 0 {
                return Err(failed_hresult("ResizePseudoConsole(100x30)", large));
            }
            write_key(fixture.input_write, b'q')?;
            let exit_wait = unsafe { WaitForSingleObject(fixture.process, 15_000) };
            if exit_wait == WAIT_FAILED {
                return Err(win32("WaitForSingleObject after visible quit input"));
            }
            if exit_wait == WAIT_TIMEOUT {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TUI did not exit after visible quit input",
                ));
            }
            if exit_wait != WAIT_OBJECT_0 {
                return Err(io::Error::other("unexpected TUI process wait result"));
            }
            let mut exit_code = 0;
            if unsafe { GetExitCodeProcess(fixture.process, &raw mut exit_code) } == 0 {
                return Err(win32("GetExitCodeProcess after quit"));
            }
            if exit_code != 0 {
                return Err(io::Error::other(format!(
                    "TUI returned nonzero after visible quit input: {exit_code}"
                )));
            }
            Ok(())
        })();
        let cleanup = fixture.cleanup();
        match (operation, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(primary), Ok(())) => Err(primary),
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
