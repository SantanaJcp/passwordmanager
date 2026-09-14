// SPDX-License-Identifier: AGPL-3.0-only

use std::{io, ptr};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_PIPE_CONNECTED, GENERIC_READ,
        GENERIC_WRITE, GetLastError, GlobalFree, HANDLE, HGLOBAL, INVALID_HANDLE_VALUE, LocalFree,
    },
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SDDL_REVISION_1,
        },
        Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CryptProtectData, CryptUnprotectData,
        },
        GetTokenInformation, RevertToSelf, SECURITY_ATTRIBUTES, SecurityIdentification,
        TOKEN_QUERY, TOKEN_USER, TokenImpersonationLevel, TokenUser,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile,
        SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
    },
    System::{
        Console::{COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, ResizePseudoConsole},
        DataExchange::{
            CloseClipboard, EmptyClipboard, GetClipboardOwner, GetClipboardSequenceNumber,
            OpenClipboard, SetClipboardData,
        },
        Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock},
        Ole::CF_UNICODETEXT,
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
            GetNamedPipeServerProcessId, ImpersonateNamedPipeClient, PIPE_READMODE_BYTE,
            PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT, PeekNamedPipe,
        },
        Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
            SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
            SERVICE_STATUS_PROCESS,
        },
        Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken},
    },
    UI::WindowsAndMessaging::{CreateWindowExW, DestroyWindow, HWND_MESSAGE},
};
use zeroize::Zeroizing;

#[cfg(test)]
use windows_sys::Win32::System::DataExchange::GetClipboardData;
#[cfg(test)]
use windows_sys::Win32::System::Memory::GlobalSize;

use crate::{ChannelAuthenticationError, WindowsEndpoint, windows_pipe_sddl};

const PIPE_BUFFER: u32 = 1024 * 1024;

pub struct WindowsServerPipe {
    handle: HANDLE,
    expected_client_sid: String,
    client_pid: Option<u32>,
}

impl WindowsServerPipe {
    /// Creates the first, local-only instance with an explicit protected DACL.
    ///
    /// # Errors
    /// Returns an opaque error for invalid identities, descriptors or handles.
    pub fn create(
        endpoint: WindowsEndpoint,
        vault: &str,
        service_sid: &str,
        client_sid: &str,
    ) -> Result<Self, ChannelAuthenticationError> {
        let name = wide(&endpoint.pipe_name(vault)?);
        let sddl = wide(&windows_pipe_sddl(service_sid, client_sid)?);
        let mut descriptor = ptr::null_mut();
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                ptr::null_mut(),
            )
        };
        if converted == 0 {
            return Err(ChannelAuthenticationError);
        }
        let security = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
                .map_err(|_| ChannelAuthenticationError)?,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                PIPE_BUFFER,
                PIPE_BUFFER,
                0,
                &raw const security,
            )
        };
        let creation_error = if handle == INVALID_HANDLE_VALUE {
            Some(unsafe { GetLastError() })
        } else {
            None
        };
        unsafe { LocalFree(descriptor) };
        if creation_error.is_some() {
            return Err(ChannelAuthenticationError);
        }
        Ok(Self {
            handle,
            expected_client_sid: client_sid.to_owned(),
            client_pid: None,
        })
    }

    /// Accepts one client and binds its kernel PID and impersonated SID.
    ///
    /// # Errors
    /// Returns an opaque error when either kernel identity check fails.
    pub fn accept(&mut self) -> Result<u32, ChannelAuthenticationError> {
        let connected = unsafe { ConnectNamedPipe(self.handle, ptr::null_mut()) };
        if connected == 0 && unsafe { GetLastError() } != ERROR_PIPE_CONNECTED {
            return Err(ChannelAuthenticationError);
        }
        let mut pid = 0;
        if unsafe { GetNamedPipeClientProcessId(self.handle, &raw mut pid) } == 0 || pid == 0 {
            return Err(ChannelAuthenticationError);
        }
        let sid = impersonated_client_sid(self.handle)?;
        if sid != self.expected_client_sid {
            return Err(ChannelAuthenticationError);
        }
        self.client_pid = Some(pid);
        Ok(pid)
    }

    /// Revalidates that the connected pipe still names the accepted process.
    ///
    /// # Errors
    /// Returns an opaque error after disconnect or peer replacement.
    pub fn verify(&self) -> Result<(), ChannelAuthenticationError> {
        let mut pid = 0;
        if self.client_pid.is_none()
            || unsafe { GetNamedPipeClientProcessId(self.handle, &raw mut pid) } == 0
            || Some(pid) != self.client_pid
            || unsafe {
                PeekNamedPipe(
                    self.handle,
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            } == 0
        {
            return Err(ChannelAuthenticationError);
        }
        Ok(())
    }

    #[must_use]
    pub const fn raw_handle(&self) -> HANDLE {
        self.handle
    }

    /// Duplicates the authenticated kernel handle for a TLS stream while the
    /// original remains attached to the human-channel identity lease.
    ///
    /// # Errors
    /// Returns an opaque error when the kernel refuses the duplication.
    pub fn try_clone(&self) -> Result<Self, ChannelAuthenticationError> {
        let process = unsafe { GetCurrentProcess() };
        let mut handle = ptr::null_mut();
        if unsafe {
            DuplicateHandle(
                process,
                self.handle,
                process,
                &raw mut handle,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(ChannelAuthenticationError);
        }
        Ok(Self {
            handle,
            expected_client_sid: self.expected_client_sid.clone(),
            client_pid: self.client_pid,
        })
    }
}

impl Drop for WindowsServerPipe {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle) };
    }
}

impl io::Read for WindowsServerPipe {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        read_handle(self.handle, buffer)
    }
}

impl io::Write for WindowsServerPipe {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        write_handle(self.handle, buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct WindowsClientPipe {
    handle: HANDLE,
    expected_server_pid: u32,
}

impl WindowsClientPipe {
    /// Connects to the installed service and verifies its PID through SCM.
    ///
    /// # Errors
    /// Returns an opaque error if SCM, connection or peer validation fails.
    pub fn connect_installed(
        endpoint: WindowsEndpoint,
        vault: &str,
    ) -> Result<Self, ChannelAuthenticationError> {
        let expected_server_pid = installed_service_pid()?;
        if expected_server_pid == 0 {
            return Err(ChannelAuthenticationError);
        }
        let name = wide(&endpoint.pipe_name(vault)?);
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(ChannelAuthenticationError);
        }
        let channel = Self {
            handle,
            expected_server_pid,
        };
        channel.verify()?;
        Ok(channel)
    }

    /// Revalidates the server PID and pipe liveness.
    ///
    /// # Errors
    /// Returns an opaque error after disconnect or server replacement.
    pub fn verify(&self) -> Result<(), ChannelAuthenticationError> {
        let mut pid = 0;
        if unsafe { GetNamedPipeServerProcessId(self.handle, &raw mut pid) } == 0
            || pid != self.expected_server_pid
            || unsafe {
                PeekNamedPipe(
                    self.handle,
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            } == 0
        {
            return Err(ChannelAuthenticationError);
        }
        Ok(())
    }

    #[must_use]
    pub const fn raw_handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for WindowsClientPipe {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle) };
    }
}

impl io::Read for WindowsClientPipe {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        read_handle(self.handle, buffer)
    }
}

impl io::Write for WindowsClientPipe {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        write_handle(self.handle, buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Wraps a bounded bootstrap value with machine-scope DPAPI.
///
/// # Errors
/// Returns an opaque error when DPAPI refuses or returns malformed output.
pub fn dpapi_protect_machine(
    value: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ChannelAuthenticationError> {
    crypt(value, true)
}

/// Opens a bounded DPAPI blob after its file DACL has been checked by its owner.
///
/// # Errors
/// Returns an opaque error when DPAPI refuses or returns malformed output.
pub fn dpapi_unprotect(value: &[u8]) -> Result<Zeroizing<Vec<u8>>, ChannelAuthenticationError> {
    crypt(value, false)
}

fn crypt(value: &[u8], protect: bool) -> Result<Zeroizing<Vec<u8>>, ChannelAuthenticationError> {
    if value.is_empty() || value.len() > 16 * 1024 * 1024 {
        return Err(ChannelAuthenticationError);
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(value.len()).map_err(|_| ChannelAuthenticationError)?,
        pbData: value.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    let ok = unsafe {
        if protect {
            CryptProtectData(
                &raw const input,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_LOCAL_MACHINE,
                &raw mut output,
            )
        } else {
            CryptUnprotectData(
                &raw const input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0,
                &raw mut output,
            )
        }
    };
    if ok == 0 || output.pbData.is_null() || output.cbData == 0 {
        return Err(ChannelAuthenticationError);
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe { LocalFree(output.pbData.cast()) };
    Ok(Zeroizing::new(bytes))
}

struct ClipboardWindow(windows_sys::Win32::Foundation::HWND);

impl ClipboardWindow {
    fn create() -> Result<Self, ChannelAuthenticationError> {
        let class = wide("STATIC");
        let title = wide("");
        let handle = unsafe {
            CreateWindowExW(
                0,
                class.as_ptr(),
                title.as_ptr(),
                0,
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
            )
        };
        if handle.is_null() {
            Err(ChannelAuthenticationError)
        } else {
            Ok(Self(handle))
        }
    }

    fn destroy(&mut self) -> Result<(), ChannelAuthenticationError> {
        if self.0.is_null() {
            return Ok(());
        }
        if unsafe { DestroyWindow(self.0) } == 0 {
            return Err(ChannelAuthenticationError);
        }
        self.0 = ptr::null_mut();
        Ok(())
    }
}

impl Drop for ClipboardWindow {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { DestroyWindow(self.0) };
            self.0 = ptr::null_mut();
        }
    }
}

pub struct OwnedClipboard {
    sequence: u32,
    owner: ClipboardWindow,
}

impl OwnedClipboard {
    /// Places UTF-8 input on the human session's `CF_UNICODETEXT` clipboard.
    ///
    /// # Errors
    /// Returns an opaque error for invalid UTF-8 or unavailable clipboard APIs.
    pub fn copy(value: &[u8]) -> Result<Self, ChannelAuthenticationError> {
        Self::copy_then(value, || {})
    }

    fn copy_then(
        value: &[u8],
        after_publish: impl FnOnce(),
    ) -> Result<Self, ChannelAuthenticationError> {
        let value = std::str::from_utf8(value).map_err(|_| ChannelAuthenticationError)?;
        if value.contains('\0') {
            return Err(ChannelAuthenticationError);
        }
        let utf16 = Zeroizing::new(value.encode_utf16().chain(Some(0)).collect::<Vec<u16>>());
        if utf16.len() <= 1 {
            return Err(ChannelAuthenticationError);
        }
        let owner = ClipboardWindow::create()?;
        with_open_clipboard(owner.0, || {
            if unsafe { EmptyClipboard() } == 0 {
                return Err(ChannelAuthenticationError);
            }
            let bytes = utf16
                .len()
                .checked_mul(2)
                .ok_or(ChannelAuthenticationError)?;
            let memory: HGLOBAL = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes) };
            if memory.is_null() {
                return Err(ChannelAuthenticationError);
            }
            let target = unsafe { GlobalLock(memory) };
            if target.is_null() {
                unsafe { GlobalFree(memory) };
                return Err(ChannelAuthenticationError);
            }
            unsafe {
                ptr::copy_nonoverlapping(utf16.as_ptr().cast::<u8>(), target.cast::<u8>(), bytes);
                GlobalUnlock(memory);
            }
            if unsafe { SetClipboardData(u32::from(CF_UNICODETEXT), memory) }.is_null() {
                unsafe { GlobalFree(memory) };
                return Err(ChannelAuthenticationError);
            }
            if unsafe { GetClipboardOwner() } != owner.0 {
                return Err(ChannelAuthenticationError);
            }
            Ok(())
        })?;
        after_publish();
        let sequence = with_open_clipboard(owner.0, || {
            let sequence = unsafe { GetClipboardSequenceNumber() };
            if unsafe { GetClipboardOwner() } != owner.0 || sequence == 0 {
                return Err(ChannelAuthenticationError);
            }
            Ok(sequence)
        })?;
        Ok(Self { sequence, owner })
    }

    /// Clears only if the clipboard owner and sequence still belong to this lease.
    ///
    /// # Errors
    /// Returns an opaque error if ownership cannot be inspected or cleared.
    pub fn clear_if_owned(mut self) -> Result<bool, ChannelAuthenticationError> {
        let cleared = with_open_clipboard(self.owner.0, || {
            if unsafe { GetClipboardOwner() } != self.owner.0
                || unsafe { GetClipboardSequenceNumber() } != self.sequence
            {
                Ok(false)
            } else if unsafe { EmptyClipboard() } != 0 {
                Ok(true)
            } else {
                Err(ChannelAuthenticationError)
            }
        })?;
        self.owner.destroy()?;
        Ok(cleared)
    }

    #[cfg(test)]
    fn read_owned_text(&self) -> Result<String, ChannelAuthenticationError> {
        with_open_clipboard(self.owner.0, || {
            if unsafe { GetClipboardOwner() } != self.owner.0
                || unsafe { GetClipboardSequenceNumber() } != self.sequence
            {
                return Err(ChannelAuthenticationError);
            }
            let memory = unsafe { GetClipboardData(u32::from(CF_UNICODETEXT)) };
            if memory.is_null() {
                return Err(ChannelAuthenticationError);
            }
            let bytes = unsafe { GlobalSize(memory) };
            if bytes < 2 || bytes % 2 != 0 {
                return Err(ChannelAuthenticationError);
            }
            let data = unsafe { GlobalLock(memory) };
            if data.is_null() {
                return Err(ChannelAuthenticationError);
            }
            let units = unsafe { std::slice::from_raw_parts(data.cast::<u16>(), bytes / 2) };
            let text = units
                .iter()
                .position(|unit| *unit == 0)
                .ok_or(ChannelAuthenticationError)
                .and_then(|length| {
                    String::from_utf16(&units[..length]).map_err(|_| ChannelAuthenticationError)
                });
            unsafe { GlobalUnlock(memory) };
            text
        })
    }
}

fn with_open_clipboard<T>(
    owner: windows_sys::Win32::Foundation::HWND,
    operation: impl FnOnce() -> Result<T, ChannelAuthenticationError>,
) -> Result<T, ChannelAuthenticationError> {
    if unsafe { OpenClipboard(owner) } == 0 {
        return Err(ChannelAuthenticationError);
    }
    let result = operation();
    if unsafe { CloseClipboard() } == 0 {
        return Err(ChannelAuthenticationError);
    }
    result
}

pub struct ConPty(HPCON);

impl ConPty {
    /// Creates a `ConPTY` attached to caller-owned live pipe handles.
    ///
    /// # Safety
    /// `input` and `output` must be valid handles for the duration of this call
    /// and remain alive while the pseudoconsole uses them.
    ///
    /// # Errors
    /// Returns an opaque error for invalid dimensions, handles or OS failure.
    pub unsafe fn create(
        width: i16,
        height: i16,
        input: HANDLE,
        output: HANDLE,
    ) -> Result<Self, ChannelAuthenticationError> {
        if width < 1 || height < 1 || input.is_null() || output.is_null() {
            return Err(ChannelAuthenticationError);
        }
        let mut handle: HPCON = 0;
        let result = unsafe {
            CreatePseudoConsole(
                COORD {
                    X: width,
                    Y: height,
                },
                input,
                output,
                0,
                &raw mut handle,
            )
        };
        if result < 0 || handle == 0 {
            return Err(ChannelAuthenticationError);
        }
        Ok(Self(handle))
    }

    /// Resizes the native pseudoconsole, including sizes below the UI floor.
    ///
    /// # Errors
    /// Returns an opaque error for zero/negative dimensions or OS failure.
    pub fn resize(&self, width: i16, height: i16) -> Result<(), ChannelAuthenticationError> {
        if width < 1
            || height < 1
            || unsafe {
                ResizePseudoConsole(
                    self.0,
                    COORD {
                        X: width,
                        Y: height,
                    },
                )
            } < 0
        {
            return Err(ChannelAuthenticationError);
        }
        Ok(())
    }
}

impl Drop for ConPty {
    fn drop(&mut self) {
        unsafe { ClosePseudoConsole(self.0) };
    }
}

fn impersonated_client_sid(pipe: HANDLE) -> Result<String, ChannelAuthenticationError> {
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(ChannelAuthenticationError);
    }
    let result = (|| {
        let mut token = ptr::null_mut();
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token) } == 0 {
            return Err(ChannelAuthenticationError);
        }
        let sid = if token_identification_only(token)? {
            token_sid(token)
        } else {
            Err(ChannelAuthenticationError)
        };
        unsafe { CloseHandle(token) };
        sid
    })();
    if unsafe { RevertToSelf() } == 0 {
        return Err(ChannelAuthenticationError);
    }
    result
}

fn token_identification_only(token: HANDLE) -> Result<bool, ChannelAuthenticationError> {
    let mut level = 0_i32;
    let mut needed = 0;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenImpersonationLevel,
            (&raw mut level).cast(),
            u32::try_from(std::mem::size_of_val(&level)).map_err(|_| ChannelAuthenticationError)?,
            &raw mut needed,
        )
    };
    if ok == 0 {
        return Err(ChannelAuthenticationError);
    }
    Ok(level == SecurityIdentification)
}

fn token_sid(token: HANDLE) -> Result<String, ChannelAuthenticationError> {
    let mut needed = 0;
    unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &raw mut needed) };
    if needed
        < u32::try_from(std::mem::size_of::<TOKEN_USER>())
            .map_err(|_| ChannelAuthenticationError)?
    {
        return Err(ChannelAuthenticationError);
    }
    let words = (needed as usize).div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0_usize; words];
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &raw mut needed,
        )
    } == 0
    {
        return Err(ChannelAuthenticationError);
    }
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut text = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &raw mut text) } == 0 || text.is_null() {
        return Err(ChannelAuthenticationError);
    }
    let length = (0..256)
        .take_while(|index| unsafe { *text.add(*index) } != 0)
        .count();
    if length == 256 {
        unsafe { LocalFree(text.cast()) };
        return Err(ChannelAuthenticationError);
    }
    let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
        .map_err(|_| ChannelAuthenticationError)?;
    unsafe { LocalFree(text.cast()) };
    Ok(sid)
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn installed_service_pid() -> Result<u32, ChannelAuthenticationError> {
    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(ChannelAuthenticationError);
    }
    let name = wide("PasswordManager");
    let service = unsafe { OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_STATUS) };
    unsafe { CloseServiceHandle(manager) };
    if service.is_null() {
        return Err(ChannelAuthenticationError);
    }
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0;
    let ok = unsafe {
        QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            (&raw mut status).cast(),
            u32::try_from(std::mem::size_of::<SERVICE_STATUS_PROCESS>())
                .map_err(|_| ChannelAuthenticationError)?,
            &raw mut needed,
        )
    };
    unsafe { CloseServiceHandle(service) };
    if ok == 0 || status.dwCurrentState != SERVICE_RUNNING || status.dwProcessId == 0 {
        return Err(ChannelAuthenticationError);
    }
    Ok(status.dwProcessId)
}

fn read_handle(handle: HANDLE, buffer: &mut [u8]) -> io::Result<usize> {
    let length = u32::try_from(buffer.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "buffer exceeds Win32 limit"))?;
    let mut read = 0;
    if unsafe {
        ReadFile(
            handle,
            buffer.as_mut_ptr().cast(),
            length,
            &raw mut read,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(read as usize)
}

fn write_handle(handle: HANDLE, buffer: &[u8]) -> io::Result<usize> {
    let length = u32::try_from(buffer.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "buffer exceeds Win32 limit"))?;
    let mut written = 0;
    if unsafe {
        WriteFile(
            handle,
            buffer.as_ptr().cast(),
            length,
            &raw mut written,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(written as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::{
        Foundation::CloseHandle, Security::TOKEN_QUERY, System::Threading::GetCurrentProcess,
    };

    const CANARY: &[u8] = b"ticket27-synthetic-native-canary";
    static CLIPBOARD_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn named_pipe_first_instance_rejects_second_protected_instance() {
        let mut token = ptr::null_mut();
        assert_ne!(
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) },
            0
        );
        let current_client_sid = token_sid(token);
        assert_ne!(unsafe { CloseHandle(token) }, 0);
        let current_client_sid = current_client_sid.unwrap();
        assert!(current_client_sid.starts_with("S-1-5-21-"));

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let vault = format!("{stamp:032x}");
        let service_sid = "S-1-5-80-27027";
        let different_client_sid = "S-1-5-21-999999999-999999999-999999999-9999";
        let first = WindowsServerPipe::create(
            WindowsEndpoint::Agent,
            &vault,
            service_sid,
            &current_client_sid,
        )
        .unwrap();
        assert!(
            WindowsServerPipe::create(
                WindowsEndpoint::Agent,
                &vault,
                service_sid,
                different_client_sid,
            )
            .is_err()
        );
        drop(first);
    }

    #[test]
    fn dpapi_machine_roundtrip_uses_a_distinct_blob() {
        let protected = dpapi_protect_machine(CANARY).unwrap();
        assert_ne!(protected.as_slice(), CANARY);
        assert_eq!(dpapi_unprotect(&protected).unwrap().as_slice(), CANARY);
        assert!(dpapi_unprotect(b"not-a-dpapi-blob").is_err());
    }

    #[test]
    fn clipboard_sequence_never_clears_a_newer_owner() {
        let _exclusive_clipboard = CLIPBOARD_TEST.lock().unwrap();
        let first = OwnedClipboard::copy(CANARY).unwrap();
        let second = OwnedClipboard::copy(b"ticket27-new-owner").unwrap();
        assert!(!first.clear_if_owned().unwrap());
        assert_eq!(second.read_owned_text().unwrap(), "ticket27-new-owner");
        assert!(second.clear_if_owned().unwrap());
    }

    #[test]
    fn clipboard_copy_fails_if_ownership_changes_before_sequence_capture() {
        let _exclusive_clipboard = CLIPBOARD_TEST.lock().unwrap();
        let replacement = std::cell::RefCell::new(None);
        let lost = OwnedClipboard::copy_then(CANARY, || {
            replacement.replace(Some(OwnedClipboard::copy(b"ticket27-new-owner").unwrap()));
        });
        assert!(lost.is_err());
        let replacement = replacement.into_inner().unwrap();
        assert_eq!(replacement.read_owned_text().unwrap(), "ticket27-new-owner");
        assert!(replacement.clear_if_owned().unwrap());
    }

    #[test]
    fn conpty_uses_native_handles_and_accepts_resize_below_layout_floor() {
        let mut input_read = ptr::null_mut();
        let mut input_write = ptr::null_mut();
        let mut output_read = ptr::null_mut();
        let mut output_write = ptr::null_mut();
        unsafe {
            assert_ne!(
                CreatePipe(&raw mut input_read, &raw mut input_write, ptr::null(), 0),
                0
            );
            assert_ne!(
                CreatePipe(&raw mut output_read, &raw mut output_write, ptr::null(), 0),
                0
            );
            let conpty = ConPty::create(80, 24, input_read, output_write).unwrap();
            conpty.resize(40, 10).unwrap();
            drop(conpty);
            CloseHandle(input_read);
            CloseHandle(input_write);
            CloseHandle(output_read);
            CloseHandle(output_write);
        }
    }
}
