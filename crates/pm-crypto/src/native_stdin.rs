// SPDX-License-Identifier: AGPL-3.0-only

//! Unbuffered borrowed process stdin preserving native platform semantics.

use std::io::{self, Read};

#[cfg(windows)]
use crate::ProtectedBytes;

#[cfg(unix)]
/// Borrowed, unbuffered process stdin preserving native input semantics.
pub struct NativeStdin {
    descriptor: std::os::fd::RawFd,
}

#[cfg(unix)]
impl NativeStdin {
    /// Validates and borrows stdin without taking ownership.
    ///
    /// # Errors
    ///
    /// Returns the native descriptor error when stdin is invalid.
    pub fn open() -> io::Result<Self> {
        let descriptor = libc::STDIN_FILENO;
        // SAFETY: F_GETFD only inspects the process-owned descriptor number.
        if unsafe { libc::fcntl(descriptor, libc::F_GETFD) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { descriptor })
    }
}

#[cfg(unix)]
impl Read for NativeStdin {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        // SAFETY: `buffer` is writable for its length and this type borrows,
        // but never closes or transfers ownership of, the stdin descriptor.
        let bytes =
            unsafe { libc::read(self.descriptor, buffer.as_mut_ptr().cast(), buffer.len()) };
        if bytes < 0 {
            Err(io::Error::last_os_error())
        } else {
            usize::try_from(bytes).map_err(|_| io::Error::other("invalid native stdin length"))
        }
    }
}

#[cfg(windows)]
/// Borrowed, unbuffered stdin preserving Windows console UTF-8 semantics.
pub struct NativeStdin {
    handle: windows_sys::Win32::Foundation::HANDLE,
    kind: NativeStdinKind,
}

#[cfg(windows)]
enum NativeStdinKind {
    Missing,
    Raw,
    Console {
        wide: ProtectedBytes,
        wide_prefix: usize,
        pending: ProtectedBytes,
        pending_start: usize,
        pending_len: usize,
    },
}

#[cfg(windows)]
impl NativeStdin {
    /// Borrows and classifies the current standard input handle.
    ///
    /// # Errors
    ///
    /// Returns the native handle or protected-buffer allocation error.
    pub fn open() -> io::Result<Self> {
        use windows_sys::Win32::{
            Foundation::INVALID_HANDLE_VALUE,
            System::Console::{GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE},
        };

        // SAFETY: GetStdHandle returns a borrowed process standard handle.
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if handle.is_null() {
            return Ok(Self {
                handle,
                kind: NativeStdinKind::Missing,
            });
        }
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let mut mode = 0_u32;
        // SAFETY: `mode` is writable and a successful call classifies the
        // borrowed standard handle as a Windows console rather than pipe/file.
        let console = unsafe { GetConsoleMode(handle, &raw mut mode) } != 0;
        let kind = if console {
            NativeStdinKind::Console {
                wide: ProtectedBytes::zeroed(4).map_err(io::Error::other)?,
                wide_prefix: 0,
                pending: ProtectedBytes::zeroed(8).map_err(io::Error::other)?,
                pending_start: 0,
                pending_len: 0,
            }
        } else {
            NativeStdinKind::Raw
        };
        Ok(Self { handle, kind })
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::io::Read as _;

    use super::{NativeStdin, NativeStdinKind};

    #[test]
    fn missing_windows_stdin_preserves_eof() {
        let mut input = NativeStdin {
            handle: std::ptr::null_mut(),
            kind: NativeStdinKind::Missing,
        };
        let mut byte = [0_u8; 1];
        assert_eq!(input.read(&mut byte).unwrap(), 0);
    }
}

#[cfg(windows)]
impl Read for NativeStdin {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match &mut self.kind {
            NativeStdinKind::Missing => Ok(0),
            NativeStdinKind::Raw => read_windows_raw(self.handle, buffer),
            NativeStdinKind::Console {
                wide,
                wide_prefix,
                pending,
                pending_start,
                pending_len,
            } => read_windows_console(
                self.handle,
                wide,
                wide_prefix,
                pending,
                pending_start,
                pending_len,
                buffer,
            ),
        }
    }
}

#[cfg(windows)]
fn read_windows_raw(
    handle: windows_sys::Win32::Foundation::HANDLE,
    buffer: &mut [u8],
) -> io::Result<usize> {
    use windows_sys::Win32::{Foundation::ERROR_BROKEN_PIPE, Storage::FileSystem::ReadFile};

    let requested = u32::try_from(buffer.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "native stdin read is too large",
        )
    })?;
    let mut bytes = 0_u32;
    // SAFETY: `handle` is borrowed and valid, `buffer` is writable for the
    // requested length, and the synchronous call does not use OVERLAPPED.
    let result = unsafe {
        ReadFile(
            handle,
            buffer.as_mut_ptr(),
            requested,
            &raw mut bytes,
            std::ptr::null_mut(),
        )
    };
    if result == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == i32::try_from(ERROR_BROKEN_PIPE).ok() {
            // Windows reports a closed pipe as BrokenPipe; `std::io::Stdin`
            // has always exposed this condition as EOF.
            Ok(0)
        } else {
            Err(error)
        }
    } else {
        usize::try_from(bytes).map_err(|_| io::Error::other("invalid native stdin length"))
    }
}

#[cfg(windows)]
fn read_windows_console(
    handle: windows_sys::Win32::Foundation::HANDLE,
    wide: &mut ProtectedBytes,
    wide_prefix: &mut usize,
    pending: &mut ProtectedBytes,
    pending_start: &mut usize,
    pending_len: &mut usize,
    buffer: &mut [u8],
) -> io::Result<usize> {
    use windows_sys::Win32::{
        Foundation::{ERROR_OPERATION_ABORTED, GetLastError, SetLastError},
        Globalization::{CP_UTF8, WC_ERR_INVALID_CHARS, WideCharToMultiByte},
        System::Console::{CONSOLE_READCONSOLE_CONTROL, ReadConsoleW},
    };

    if buffer.is_empty() {
        return Ok(0);
    }
    loop {
        if *pending_start < *pending_len {
            let available = *pending_len - *pending_start;
            let copied = available.min(buffer.len());
            for (destination, source) in buffer[..copied]
                .iter_mut()
                .zip(&mut pending[*pending_start..*pending_start + copied])
            {
                *destination = *source;
                *source = 0;
            }
            *pending_start += copied;
            return Ok(copied);
        }

        *pending_start = 0;
        *pending_len = 0;
        let mut control = CONSOLE_READCONSOLE_CONTROL {
            nLength: u32::try_from(std::mem::size_of::<CONSOLE_READCONSOLE_CONTROL>())
                .map_err(|_| io::Error::other("invalid console control size"))?,
            nInitialChars: 0,
            dwCtrlWakeupMask: 1 << 0x1a,
            dwControlKeyState: 0,
        };
        let mut units = 0_u32;
        // SAFETY: the locked `wide` allocation is aligned and writable at
        // `wide_prefix` for one UTF-16 unit; the borrowed handle and control
        // remain valid for the synchronous call.
        unsafe { SetLastError(0) };
        let result = unsafe {
            ReadConsoleW(
                handle,
                wide.as_mut_ptr().add(*wide_prefix * 2).cast(),
                1,
                &raw mut units,
                &raw mut control,
            )
        };
        if result == 0 {
            wide.fill(0);
            return Err(io::Error::last_os_error());
        }
        if units == 0 {
            if unsafe { GetLastError() } == ERROR_OPERATION_ABORTED {
                continue;
            }
            if *wide_prefix != 0 {
                wide.fill(0);
                *wide_prefix = 0;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Windows console input ended with an unpaired UTF-16 surrogate",
                ));
            }
            return Ok(0);
        }
        let units =
            usize::try_from(units).map_err(|_| io::Error::other("invalid console input length"))?;
        if units != 1 {
            wide.fill(0);
            *wide_prefix = 0;
            return Err(io::Error::other("invalid console input length"));
        }
        // SAFETY: ReadConsoleW initialized the one unit at `wide_prefix`.
        let unit = unsafe { *wide.as_ptr().cast::<u16>().add(*wide_prefix) };
        if *wide_prefix == 0 && unit == 0x1a {
            wide.fill(0);
            return Ok(0);
        }
        if *wide_prefix == 0 && (0xd800..=0xdbff).contains(&unit) {
            *wide_prefix = 1;
            continue;
        }
        let unit_count = *wide_prefix + 1;
        let unit_count_i32 = i32::try_from(unit_count)
            .map_err(|_| io::Error::other("invalid console input length"))?;
        // SAFETY: input names initialized locked UTF-16 units; output names an
        // eight-byte locked buffer, enough for two UTF-16 units as UTF-8.
        let converted = unsafe {
            WideCharToMultiByte(
                CP_UTF8,
                WC_ERR_INVALID_CHARS,
                wide.as_ptr().cast(),
                unit_count_i32,
                pending.as_mut_ptr(),
                8,
                std::ptr::null(),
                std::ptr::null_mut(),
            )
        };
        wide.fill(0);
        *wide_prefix = 0;
        if converted == 0 {
            pending.fill(0);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows console input contains invalid UTF-16",
            ));
        }
        *pending_len = usize::try_from(converted)
            .map_err(|_| io::Error::other("invalid console UTF-8 length"))?;
    }
}
