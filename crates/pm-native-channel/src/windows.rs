// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    io, ptr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_INSUFFICIENT_BUFFER,
        ERROR_IO_PENDING, ERROR_NOT_FOUND, ERROR_OPERATION_ABORTED, ERROR_PIPE_CONNECTED,
        ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE, GetLastError, GlobalFree, HANDLE, HGLOBAL,
        INVALID_HANDLE_VALUE, LocalFree, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::{
        ACL,
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            EXPLICIT_ACCESS_W, GRANT_ACCESS, GetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT,
            SetEntriesInAclW, SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_USER,
        },
        Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CryptProtectData, CryptUnprotectData,
        },
        DACL_SECURITY_INFORMATION, GetTokenInformation, IsValidSid, LookupAccountNameW,
        NO_INHERITANCE, PSECURITY_DESCRIPTOR, PSID, RevertToSelf, SECURITY_ATTRIBUTES,
        SID_NAME_USE, SecurityIdentification, TOKEN_QUERY, TOKEN_USER, TokenImpersonationLevel,
        TokenUser,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
        GetFileInformationByHandle, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile,
        SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
    },
    System::{
        Console::{COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, ResizePseudoConsole},
        DataExchange::{
            CloseClipboard, EmptyClipboard, GetClipboardOwner, GetClipboardSequenceNumber,
            OpenClipboard, SetClipboardData,
        },
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
        Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock},
        Ole::CF_UNICODETEXT,
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
            GetNamedPipeServerProcessId, ImpersonateNamedPipeClient, PIPE_READMODE_BYTE,
            PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT, PeekNamedPipe, WaitNamedPipeW,
        },
        Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
            SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
            SERVICE_STATUS_PROCESS,
        },
        Threading::{
            CreateEventW, GetCurrentProcess, GetCurrentThread, GetProcessId, INFINITE, OpenProcess,
            OpenProcessToken, OpenThreadToken, PROCESS_DUP_HANDLE,
            PROCESS_QUERY_LIMITED_INFORMATION, SetEvent, WaitForMultipleObjects,
            WaitForSingleObject,
        },
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
const SYNC_PIPE_PREFIX: &str = r"\\.\pipe\pm-sync-";

fn validate_sync_pipe_name(name: &str) -> Result<(), ChannelAuthenticationError> {
    let suffix = name
        .strip_prefix(SYNC_PIPE_PREFIX)
        .ok_or(ChannelAuthenticationError)?;
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ChannelAuthenticationError);
    }
    Ok(())
}

fn sync_pipe_sddl(
    server_sid: &str,
    client_sids: &[String],
) -> Result<String, ChannelAuthenticationError> {
    if !specific_local_sid(server_sid)
        || client_sids.is_empty()
        || client_sids
            .iter()
            .any(|sid| !specific_local_sid(sid) || sid == server_sid)
        || client_sids
            .iter()
            .enumerate()
            .any(|(index, sid)| client_sids[..index].contains(sid))
    {
        return Err(ChannelAuthenticationError);
    }
    let mut value = format!("O:{server_sid}G:{server_sid}D:P(A;;GA;;;SY)(A;;GA;;;{server_sid})");
    for sid in client_sids {
        value.push_str(&format!("(A;;GRGW;;;{sid})"));
    }
    Ok(value)
}

fn specific_local_sid(value: &str) -> bool {
    ["S-1-5-21-", "S-1-5-80-"]
        .iter()
        .any(|prefix| value.starts_with(prefix) && valid_sid_suffix(value, prefix))
}

fn valid_sid_suffix(value: &str, prefix: &str) -> bool {
    value.len() > prefix.len()
        && value
            .split('-')
            .skip(1)
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Manual-reset event shared by the service control handler and server I/O.
struct StopEventHandle {
    handle: HANDLE,
}

unsafe impl Send for StopEventHandle {}
unsafe impl Sync for StopEventHandle {}

impl Drop for StopEventHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() && unsafe { CloseHandle(self.handle) } == 0 {
            std::process::abort();
        }
    }
}

#[derive(Clone)]
pub struct WindowsStopEvent {
    inner: Arc<StopEventHandle>,
}

impl WindowsStopEvent {
    /// Creates an unsignalled manual-reset event.
    ///
    /// # Errors
    /// Returns an opaque error if Windows cannot allocate the event.
    pub fn create() -> Result<Self, ChannelAuthenticationError> {
        let handle = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if handle.is_null() {
            Err(ChannelAuthenticationError)
        } else {
            Ok(Self {
                inner: Arc::new(StopEventHandle { handle }),
            })
        }
    }

    /// Signals every pending server operation to stop.
    ///
    /// # Errors
    /// Returns an opaque error if Windows rejects the signal.
    pub fn signal(&self) -> Result<(), ChannelAuthenticationError> {
        if unsafe { SetEvent(self.inner.handle) } == 0 {
            Err(ChannelAuthenticationError)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn is_signalled(&self) -> Result<bool, ChannelAuthenticationError> {
        event_is_signalled(self.inner.handle).map_err(|_| ChannelAuthenticationError)
    }

    #[must_use]
    pub fn raw_handle(&self) -> HANDLE {
        self.inner.handle
    }

    /// Closes the event after every service worker and pipe has terminated.
    ///
    /// # Errors
    /// Returns an opaque error for outstanding owners or a failed kernel close.
    pub fn close(self) -> Result<(), ChannelAuthenticationError> {
        let mut owned = Arc::try_unwrap(self.inner).map_err(|_| ChannelAuthenticationError)?;
        let handle = owned.handle;
        owned.handle = ptr::null_mut();
        close_handle(handle)
    }
}

fn duplicate_handle(source: HANDLE) -> Result<HANDLE, ChannelAuthenticationError> {
    let process = unsafe { GetCurrentProcess() };
    let mut duplicate = ptr::null_mut();
    if unsafe {
        DuplicateHandle(
            process,
            source,
            process,
            &raw mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        Err(ChannelAuthenticationError)
    } else {
        Ok(duplicate)
    }
}

fn close_handle(handle: HANDLE) -> Result<(), ChannelAuthenticationError> {
    if unsafe { CloseHandle(handle) } == 0 {
        Err(ChannelAuthenticationError)
    } else {
        Ok(())
    }
}

fn event_is_signalled(event: HANDLE) -> io::Result<bool> {
    match unsafe { WaitForSingleObject(event, 0) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        _ => Err(io::Error::last_os_error()),
    }
}

pub struct WindowsServerPipe {
    handle: HANDLE,
    stop: WindowsStopEvent,
    expected_client_sids: Vec<String>,
    client_pid: Option<u32>,
}

// The pipe owns its HANDLE and moves into exactly one service worker before
// any accept or I/O. It is not Sync; duplicated handles remain confined to the
// same worker while rustls and the human identity lease are composed.
unsafe impl Send for WindowsServerPipe {}

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
        stop: &WindowsStopEvent,
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
        let creation = create_pipe_instance(name.as_ptr(), &raw const security);
        unsafe { LocalFree(descriptor) };
        let handle = creation.map_err(|_| ChannelAuthenticationError)?;
        Ok(Self {
            handle,
            stop: stop.clone(),
            expected_client_sids: vec![client_sid.to_owned()],
            client_pid: None,
        })
    }

    /// Creates a dedicated sync pipe after validating the current server SID.
    ///
    /// # Errors
    /// Rejects non-canonical names/SIDs and any token, descriptor or handle failure.
    pub fn create_sync(
        name: &str,
        server_sid: &str,
        client_sids: &[String],
        stop: &WindowsStopEvent,
    ) -> Result<Self, ChannelAuthenticationError> {
        validate_sync_pipe_name(name)?;
        if current_process_sid()? != server_sid {
            return Err(ChannelAuthenticationError);
        }
        let sddl = sync_pipe_sddl(server_sid, client_sids)?;
        Self::create_sync_named(name, &sddl, client_sids.to_vec(), stop)
    }

    fn create_sync_named(
        name: &str,
        sddl: &str,
        client_sids: Vec<String>,
        stop: &WindowsStopEvent,
    ) -> Result<Self, ChannelAuthenticationError> {
        let name = wide(name);
        let sddl = wide(sddl);
        let security_length = u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| ChannelAuthenticationError)?;
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
            nLength: security_length,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let creation = create_pipe_instance(name.as_ptr(), &raw const security);
        let released = free_local(descriptor);
        let handle = match (creation, released) {
            (Ok(handle), Ok(())) => handle,
            (Err(_), Ok(())) | (Err(_), Err(_)) => return Err(ChannelAuthenticationError),
            (Ok(handle), Err(_)) => {
                close_handle(handle)?;
                return Err(ChannelAuthenticationError);
            }
        };
        Ok(Self {
            handle,
            stop: stop.clone(),
            expected_client_sids: client_sids,
            client_pid: None,
        })
    }

    /// Accepts one client and binds its kernel PID and impersonated SID.
    ///
    /// # Errors
    /// Returns an opaque error when either kernel identity check fails.
    pub fn accept(&mut self) -> Result<u32, ChannelAuthenticationError> {
        overlapped_connect(self.handle, self.stop.raw_handle())?;
        let mut pid = 0;
        if unsafe { GetNamedPipeClientProcessId(self.handle, &raw mut pid) } == 0 || pid == 0 {
            return Err(ChannelAuthenticationError);
        }
        let sid = impersonated_client_sid(self.handle)?;
        if !self.expected_client_sids.contains(&sid) {
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

    /// Reports whether SCM has requested shutdown for this server instance.
    #[must_use]
    pub fn stop_requested(&self) -> Result<bool, ChannelAuthenticationError> {
        self.stop.is_signalled()
    }

    /// Duplicates the authenticated kernel handle for a TLS stream while the
    /// original remains attached to the human-channel identity lease.
    ///
    /// # Errors
    /// Returns an opaque error when the kernel refuses a duplication or cleanup.
    pub fn try_clone(&self) -> Result<Self, ChannelAuthenticationError> {
        let handle = duplicate_handle(self.handle)?;
        Ok(Self {
            handle,
            stop: self.stop.clone(),
            expected_client_sids: self.expected_client_sids.clone(),
            client_pid: self.client_pid,
        })
    }

    /// Duplicates one regular source handle from the authenticated client PID.
    /// The client must hold its short-lived process transfer lease.
    ///
    /// # Errors
    /// Returns an opaque error for peer/PID changes, missing exact process
    /// rights, invalid source handles, links/reparse points, or cleanup failure.
    pub fn duplicate_client_file(
        &self,
        source_value: u64,
        maximum: u64,
    ) -> Result<std::fs::File, ChannelAuthenticationError> {
        use std::os::windows::io::FromRawHandle;

        let source =
            usize::try_from(source_value).map_err(|_| ChannelAuthenticationError)? as HANDLE;
        if source.is_null() || source == INVALID_HANDLE_VALUE || maximum == 0 {
            return Err(ChannelAuthenticationError);
        }
        self.verify()?;
        let pid = self.client_pid.ok_or(ChannelAuthenticationError)?;
        let client = unsafe {
            OpenProcess(
                PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                pid,
            )
        };
        if client.is_null() {
            return Err(ChannelAuthenticationError);
        }
        if unsafe { GetProcessId(client) } != pid || self.verify().is_err() {
            close_handle(client)?;
            return Err(ChannelAuthenticationError);
        }
        let mut local = ptr::null_mut();
        let duplicated = unsafe {
            DuplicateHandle(
                client,
                source,
                GetCurrentProcess(),
                &raw mut local,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        let peer_valid = self.verify();
        let client_closed = close_handle(client);
        if duplicated == 0 || peer_valid.is_err() || client_closed.is_err() {
            if !local.is_null() && close_handle(local).is_err() {
                return Err(ChannelAuthenticationError);
            }
            return Err(ChannelAuthenticationError);
        }
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        let queried = unsafe { GetFileInformationByHandle(local, &raw mut information) } != 0;
        let size =
            (u64::from(information.nFileSizeHigh) << 32) | u64::from(information.nFileSizeLow);
        let valid = queried
            && information.dwFileAttributes
                & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
                == 0
            && information.nNumberOfLinks == 1
            && ((u64::from(information.nFileIndexHigh) << 32)
                | u64::from(information.nFileIndexLow))
                != 0
            && size != 0
            && size <= maximum;
        if !valid {
            close_handle(local)?;
            return Err(ChannelAuthenticationError);
        }
        Ok(unsafe { std::fs::File::from_raw_handle(local) })
    }
}

fn create_pipe_instance(
    name: *const u16,
    security: *const SECURITY_ATTRIBUTES,
) -> Result<HANDLE, u32> {
    let handle = unsafe {
        CreateNamedPipeW(
            name,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            PIPE_BUFFER,
            PIPE_BUFFER,
            0,
            security,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(unsafe { GetLastError() });
    }
    Ok(handle)
}

fn overlapped_connect(pipe: HANDLE, stop_event: HANDLE) -> Result<(), ChannelAuthenticationError> {
    if event_is_signalled(stop_event).map_err(|_| ChannelAuthenticationError)? {
        return Err(ChannelAuthenticationError);
    }
    let operation_event = create_operation_event().map_err(|_| ChannelAuthenticationError)?;
    let mut overlapped = OVERLAPPED {
        hEvent: operation_event,
        ..OVERLAPPED::default()
    };
    let connected = unsafe { ConnectNamedPipe(pipe, &raw mut overlapped) };
    let connect_error = if connected == 0 {
        Some(unsafe { GetLastError() })
    } else {
        None
    };
    let result = (|| {
        if connected != 0 || connect_error == Some(ERROR_PIPE_CONNECTED) {
            if event_is_signalled(stop_event)? {
                Err(io::Error::from(io::ErrorKind::Interrupted))
            } else {
                Ok(0)
            }
        } else if connect_error == Some(ERROR_IO_PENDING) {
            await_overlapped(pipe, stop_event, &mut overlapped)
        } else if let Some(code) = connect_error {
            Err(io::Error::from_raw_os_error(code.cast_signed()))
        } else {
            unreachable!("failed ConnectNamedPipe always sets an error code")
        }
    })();
    close_operation_event(operation_event, result)
        .map(|_| ())
        .map_err(|_| ChannelAuthenticationError)
}

fn overlapped_read(pipe: HANDLE, stop_event: HANDLE, buffer: &mut [u8]) -> io::Result<usize> {
    let length =
        u32::try_from(buffer.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    if event_is_signalled(stop_event)? {
        return Err(io::Error::from(io::ErrorKind::Interrupted));
    }
    let operation_event = create_operation_event()?;
    let mut overlapped = OVERLAPPED {
        hEvent: operation_event,
        ..OVERLAPPED::default()
    };
    let started = unsafe {
        ReadFile(
            pipe,
            buffer.as_mut_ptr().cast(),
            length,
            ptr::null_mut(),
            &raw mut overlapped,
        )
    };
    let result = finish_started_operation(pipe, stop_event, &mut overlapped, started);
    close_operation_event(operation_event, result).map(|bytes| bytes as usize)
}

fn overlapped_write(pipe: HANDLE, stop_event: HANDLE, buffer: &[u8]) -> io::Result<usize> {
    let length =
        u32::try_from(buffer.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    if event_is_signalled(stop_event)? {
        return Err(io::Error::from(io::ErrorKind::Interrupted));
    }
    let operation_event = create_operation_event()?;
    let mut overlapped = OVERLAPPED {
        hEvent: operation_event,
        ..OVERLAPPED::default()
    };
    let started = unsafe {
        WriteFile(
            pipe,
            buffer.as_ptr().cast(),
            length,
            ptr::null_mut(),
            &raw mut overlapped,
        )
    };
    let result = finish_started_operation(pipe, stop_event, &mut overlapped, started);
    close_operation_event(operation_event, result).map(|bytes| bytes as usize)
}

fn finish_started_operation(
    pipe: HANDLE,
    stop_event: HANDLE,
    overlapped: &mut OVERLAPPED,
    started: i32,
) -> io::Result<u32> {
    if started != 0 {
        let mut transferred = 0;
        if unsafe { GetOverlappedResult(pipe, overlapped, &raw mut transferred, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        return if event_is_signalled(stop_event)? {
            Err(io::Error::from(io::ErrorKind::Interrupted))
        } else {
            Ok(transferred)
        };
    }
    if unsafe { GetLastError() } != ERROR_IO_PENDING {
        return Err(io::Error::last_os_error());
    }
    await_overlapped(pipe, stop_event, overlapped)
}

fn await_overlapped(
    pipe: HANDLE,
    stop_event: HANDLE,
    overlapped: &mut OVERLAPPED,
) -> io::Result<u32> {
    let handles = [stop_event, overlapped.hEvent];
    let waited = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) };
    if waited == WAIT_OBJECT_0 {
        cancel_and_drain(pipe, overlapped)?;
        return Err(io::Error::from(io::ErrorKind::Interrupted));
    }
    if waited != WAIT_OBJECT_0 + 1 {
        let wait_error = if waited == WAIT_FAILED {
            io::Error::last_os_error()
        } else {
            io::Error::other("unexpected Windows wait result")
        };
        return match cancel_and_drain(pipe, overlapped) {
            Ok(()) => Err(wait_error),
            Err(cleanup_error) => Err(combine_io_errors(wait_error, cleanup_error)),
        };
    }
    let mut transferred = 0;
    if unsafe { GetOverlappedResult(pipe, overlapped, &raw mut transferred, 0) } == 0 {
        Err(io::Error::last_os_error())
    } else if event_is_signalled(stop_event)? {
        Err(io::Error::from(io::ErrorKind::Interrupted))
    } else {
        Ok(transferred)
    }
}

fn cancel_and_drain(pipe: HANDLE, overlapped: &mut OVERLAPPED) -> io::Result<()> {
    let cancelled = unsafe { CancelIoEx(pipe, overlapped) };
    let cancel_error = if cancelled == 0 {
        let code = unsafe { GetLastError() };
        (code != ERROR_NOT_FOUND).then_some(code)
    } else {
        None
    };
    let mut transferred = 0;
    let drained = unsafe { GetOverlappedResult(pipe, overlapped, &raw mut transferred, 1) };
    let drain_error = (drained == 0).then(|| unsafe { GetLastError() });
    let cancel_error = cancel_error.map(|code| io::Error::from_raw_os_error(code.cast_signed()));
    let drain_error = match drain_error {
        None | Some(ERROR_OPERATION_ABORTED) => None,
        Some(code) => Some(io::Error::from_raw_os_error(code.cast_signed())),
    };
    match (cancel_error, drain_error) {
        (None, None) => Ok(()),
        (Some(error), None) | (None, Some(error)) => Err(error),
        (Some(cancel), Some(drain)) => Err(combine_io_errors(cancel, drain)),
    }
}

fn combine_io_errors(primary: io::Error, cleanup: io::Error) -> io::Error {
    io::Error::other(format!(
        "Windows I/O failed: {primary}; cancellation/drain cleanup failed: {cleanup}"
    ))
}

fn create_operation_event() -> io::Result<HANDLE> {
    let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    if event.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(event)
    }
}

fn close_operation_event(event: HANDLE, result: io::Result<u32>) -> io::Result<u32> {
    if unsafe { CloseHandle(event) } == 0 {
        let cleanup = io::Error::last_os_error();
        return match result {
            Ok(_) => Err(cleanup),
            Err(primary) => Err(combine_io_errors(primary, cleanup)),
        };
    }
    result
}

impl Drop for WindowsServerPipe {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle) };
    }
}

impl io::Read for WindowsServerPipe {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        overlapped_read(self.handle, self.stop.raw_handle(), buffer)
    }
}

impl io::Write for WindowsServerPipe {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        overlapped_write(self.handle, self.stop.raw_handle(), buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct WindowsClientPipe {
    handle: HANDLE,
    expected_server_pid: u32,
    io_mode: WindowsClientIoMode,
}

enum WindowsClientIoMode {
    Installed,
    Sync(WindowsStopEvent),
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
            io_mode: WindowsClientIoMode::Installed,
        };
        channel.verify()?;
        Ok(channel)
    }

    /// Connects to a canonical local sync pipe and pins the observed server PID.
    /// TLS-RPK authenticates the server above this kernel transport.
    ///
    /// # Errors
    /// Rejects invalid names and any connect/PID/liveness failure.
    pub fn connect_sync(
        name: &str,
        deadline: &WindowsStopEvent,
    ) -> Result<Self, ChannelAuthenticationError> {
        validate_sync_pipe_name(name)?;
        let name = wide(name);
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(ChannelAuthenticationError);
        }
        let mut expected_server_pid = 0;
        if unsafe { GetNamedPipeServerProcessId(handle, &raw mut expected_server_pid) } == 0
            || expected_server_pid == 0
        {
            close_handle(handle)?;
            return Err(ChannelAuthenticationError);
        }
        if verify_server_pipe(handle, expected_server_pid).is_err() {
            // The sync constructor has not published an owner yet, so this path
            // must close the raw handle explicitly rather than relying on Drop.
            close_handle(handle)?;
            return Err(ChannelAuthenticationError);
        }
        Ok(Self {
            handle,
            expected_server_pid,
            io_mode: WindowsClientIoMode::Sync(deadline.clone()),
        })
    }

    /// Revalidates the server PID and pipe liveness.
    ///
    /// # Errors
    /// Returns an opaque error after disconnect or server replacement.
    pub fn verify(&self) -> Result<(), ChannelAuthenticationError> {
        verify_server_pipe(self.handle, self.expected_server_pid)
    }

    #[must_use]
    pub const fn raw_handle(&self) -> HANDLE {
        self.handle
    }
}

fn verify_server_pipe(
    handle: HANDLE,
    expected_server_pid: u32,
) -> Result<(), ChannelAuthenticationError> {
    let mut pid = 0;
    if unsafe { GetNamedPipeServerProcessId(handle, &raw mut pid) } == 0
        || pid != expected_server_pid
        || unsafe {
            PeekNamedPipe(
                handle,
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

/// Checks whether one exact named-pipe endpoint currently has an available instance.
///
/// # Errors
/// Returns an opaque error for malformed names or any Windows query failure other
/// than the documented busy/not-found states. It never probes a substitute endpoint.
pub fn windows_named_pipe_available(
    path: &std::path::Path,
) -> Result<bool, ChannelAuthenticationError> {
    let value = path.to_str().ok_or(ChannelAuthenticationError)?;
    if !value.starts_with(r"\\.\pipe\") || value.len() <= r"\\.\pipe\".len() {
        return Err(ChannelAuthenticationError);
    }
    let name = wide(value);
    if unsafe { WaitNamedPipeW(name.as_ptr(), 0) } != 0 {
        return Ok(true);
    }
    match unsafe { GetLastError() } {
        windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND
        | windows_sys::Win32::Foundation::ERROR_SEM_TIMEOUT
        | windows_sys::Win32::Foundation::ERROR_PIPE_BUSY => Ok(false),
        _ => Err(ChannelAuthenticationError),
    }
}

/// Temporary access grant allowing only the installed custodian service to
/// duplicate handles out of the current human TUI process.
pub struct ProcessHandleTransferLease {
    original_descriptor: PSECURITY_DESCRIPTOR,
    original_dacl: *mut ACL,
    installed_dacl: *mut ACL,
    installed_bytes: Vec<u8>,
    active: bool,
}

static PROCESS_HANDLE_TRANSFER_ACTIVE: AtomicBool = AtomicBool::new(false);

struct ProcessHandleTransferReservation {
    active: bool,
}

impl ProcessHandleTransferReservation {
    fn acquire() -> Result<Self, ProcessHandleTransferBeginError> {
        PROCESS_HANDLE_TRANSFER_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self { active: true })
            .map_err(|_| ProcessHandleTransferBeginError {
                cleanup_failed: false,
            })
    }

    fn transfer(&mut self) {
        self.active = false;
    }
}

impl Drop for ProcessHandleTransferReservation {
    fn drop(&mut self) {
        if self.active {
            PROCESS_HANDLE_TRANSFER_ACTIVE.store(false, Ordering::Release);
        }
    }
}

/// Failure to start a process-handle transfer lease, including whether
/// restoring a partially-installed process DACL also failed.
#[derive(Debug)]
pub struct ProcessHandleTransferBeginError {
    cleanup_failed: bool,
}

impl ProcessHandleTransferBeginError {
    /// Returns the result of cleanup attempted while starting the lease.
    pub const fn cleanup_result(&self) -> Result<(), ChannelAuthenticationError> {
        if self.cleanup_failed {
            Err(ChannelAuthenticationError)
        } else {
            Ok(())
        }
    }
}

impl ProcessHandleTransferLease {
    /// Adds a non-inheritable process ACE for the installed virtual service.
    ///
    /// # Errors
    /// Returns an opaque error if SID resolution, DACL query/install, or
    /// post-install verification fails.
    pub fn begin() -> Result<Self, ProcessHandleTransferBeginError> {
        Self::begin_unique(ProcessHandleTransferReservation::acquire()?)
    }

    fn begin_unique(
        mut reservation: ProcessHandleTransferReservation,
    ) -> Result<Self, ProcessHandleTransferBeginError> {
        let sid = installed_service_sid().map_err(|_| ProcessHandleTransferBeginError {
            cleanup_failed: false,
        })?;
        let process = unsafe { GetCurrentProcess() };
        let (original_descriptor, original_dacl) =
            query_process_dacl(process).map_err(|_| ProcessHandleTransferBeginError {
                cleanup_failed: false,
            })?;
        let mut entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: NO_INHERITANCE,
            ..EXPLICIT_ACCESS_W::default()
        };
        entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        entry.Trustee.TrusteeType = TRUSTEE_IS_USER;
        entry.Trustee.ptstrName = sid.as_ptr().cast_mut().cast();
        let mut installed_dacl = ptr::null_mut();
        let created = unsafe {
            SetEntriesInAclW(1, &raw const entry, original_dacl, &raw mut installed_dacl)
        };
        if created != ERROR_SUCCESS || installed_dacl.is_null() {
            let installed = free_local(installed_dacl.cast());
            let original = free_local(original_descriptor);
            return Err(ProcessHandleTransferBeginError {
                cleanup_failed: installed.is_err() || original.is_err(),
            });
        }
        let installed_bytes = match acl_bytes(installed_dacl) {
            Ok(value) => value,
            Err(_error) => {
                let installed = free_local(installed_dacl.cast());
                let original = free_local(original_descriptor);
                return Err(ProcessHandleTransferBeginError {
                    cleanup_failed: installed.is_err() || original.is_err(),
                });
            }
        };
        let applied = unsafe {
            SetSecurityInfo(
                process,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                installed_dacl,
                ptr::null(),
            )
        };
        if applied != ERROR_SUCCESS {
            let first = free_local(installed_dacl.cast());
            let second = free_local(original_descriptor);
            return Err(ProcessHandleTransferBeginError {
                cleanup_failed: first.is_err() || second.is_err(),
            });
        }
        reservation.transfer();
        let lease = Self {
            original_descriptor,
            original_dacl,
            installed_dacl,
            installed_bytes,
            active: true,
        };
        if lease.current_matches(&lease.installed_bytes).is_err() {
            let cleanup_failed = lease.finish().is_err();
            return Err(ProcessHandleTransferBeginError { cleanup_failed });
        }
        Ok(lease)
    }

    /// Restores the original DACL only if no external actor changed the
    /// descriptor installed by this lease.
    ///
    /// # Errors
    /// Returns an opaque error for concurrent change, restore, verification,
    /// or descriptor cleanup failure.
    pub fn finish(mut self) -> Result<(), ChannelAuthenticationError> {
        self.finish_inner()
    }

    fn finish_inner(&mut self) -> Result<(), ChannelAuthenticationError> {
        if !self.active {
            return Ok(());
        }
        let result = (|| {
            self.current_matches(&self.installed_bytes)?;
            if unsafe {
                SetSecurityInfo(
                    GetCurrentProcess(),
                    SE_KERNEL_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    self.original_dacl,
                    ptr::null(),
                )
            } != ERROR_SUCCESS
            {
                return Err(ChannelAuthenticationError);
            }
            self.current_matches(&acl_bytes(self.original_dacl)?)
        })();
        let installed = free_local(self.installed_dacl.cast());
        let original = free_local(self.original_descriptor);
        self.active = false;
        PROCESS_HANDLE_TRANSFER_ACTIVE.store(false, Ordering::Release);
        if result.is_err() || installed.is_err() || original.is_err() {
            Err(ChannelAuthenticationError)
        } else {
            Ok(())
        }
    }

    fn current_matches(&self, expected: &[u8]) -> Result<(), ChannelAuthenticationError> {
        let (descriptor, dacl) = query_process_dacl(unsafe { GetCurrentProcess() })?;
        let matches = acl_bytes(dacl).map(|actual| actual == expected);
        let released = free_local(descriptor);
        if matches != Ok(true) || released.is_err() {
            Err(ChannelAuthenticationError)
        } else {
            Ok(())
        }
    }
}

impl Drop for ProcessHandleTransferLease {
    fn drop(&mut self) {
        if self.active && self.finish_inner().is_err() {
            report_process_transfer_cleanup_failure();
        }
    }
}

fn report_process_transfer_cleanup_failure() {
    const MARKER: &[u8] = b"PM_NATIVE_CLEANUP_FAILED component=process-handle-transfer\r\n";
    const MARKER_LENGTH: u32 = 60;
    const _: () = assert!(MARKER.len() == MARKER_LENGTH as usize);
    let mut written = 0;
    if unsafe {
        WriteFile(
            windows_sys::Win32::System::Console::GetStdHandle(
                windows_sys::Win32::System::Console::STD_ERROR_HANDLE,
            ),
            MARKER.as_ptr(),
            MARKER_LENGTH,
            &raw mut written,
            ptr::null_mut(),
        )
    } == 0
    {
        // Drop cannot return a second failure. This one attempted write is the
        // fixed external signal; it is deliberately neither retried nor fatal.
    }
}

fn query_process_dacl(
    process: HANDLE,
) -> Result<(PSECURITY_DESCRIPTOR, *mut ACL), ChannelAuthenticationError> {
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    if unsafe {
        GetSecurityInfo(
            process,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut dacl,
            ptr::null_mut(),
            &raw mut descriptor,
        )
    } != ERROR_SUCCESS
        || descriptor.is_null()
        || dacl.is_null()
    {
        if !descriptor.is_null() {
            free_local(descriptor)?;
        }
        return Err(ChannelAuthenticationError);
    }
    Ok((descriptor, dacl))
}

fn acl_bytes(acl: *const ACL) -> Result<Vec<u8>, ChannelAuthenticationError> {
    if acl.is_null() {
        return Err(ChannelAuthenticationError);
    }
    let length = usize::from(unsafe { (*acl).AclSize });
    if length < std::mem::size_of::<ACL>() || length > u16::MAX.into() {
        return Err(ChannelAuthenticationError);
    }
    Ok(unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), length) }.to_vec())
}

fn installed_service_sid() -> Result<Vec<usize>, ChannelAuthenticationError> {
    let account = wide(r"NT SERVICE\PasswordManager");
    let mut sid_bytes = 0_u32;
    let mut domain_units = 0_u32;
    let mut use_kind: SID_NAME_USE = 0;
    let first = unsafe {
        LookupAccountNameW(
            ptr::null(),
            account.as_ptr(),
            ptr::null_mut(),
            &raw mut sid_bytes,
            ptr::null_mut(),
            &raw mut domain_units,
            &raw mut use_kind,
        )
    };
    if first != 0
        || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
        || sid_bytes == 0
        || domain_units == 0
    {
        return Err(ChannelAuthenticationError);
    }
    let word = std::mem::size_of::<usize>();
    let sid_words = usize::try_from(sid_bytes)
        .map_err(|_| ChannelAuthenticationError)?
        .div_ceil(word);
    let mut sid = vec![0_usize; sid_words];
    let mut domain =
        vec![0_u16; usize::try_from(domain_units).map_err(|_| ChannelAuthenticationError)?];
    if unsafe {
        LookupAccountNameW(
            ptr::null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &raw mut sid_bytes,
            domain.as_mut_ptr(),
            &raw mut domain_units,
            &raw mut use_kind,
        )
    } == 0
        || unsafe { IsValidSid(sid.as_mut_ptr().cast()) } == 0
    {
        return Err(ChannelAuthenticationError);
    }
    let text = sid_string(sid.as_mut_ptr().cast())?;
    if !text.starts_with("S-1-5-80-") {
        return Err(ChannelAuthenticationError);
    }
    Ok(sid)
}

fn sid_string(sid: PSID) -> Result<String, ChannelAuthenticationError> {
    let mut text = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &raw mut text) } == 0 || text.is_null() {
        return Err(ChannelAuthenticationError);
    }
    let length = (0..256)
        .take_while(|index| unsafe { *text.add(*index) } != 0)
        .count();
    if length == 256 {
        free_local(text.cast())?;
        return Err(ChannelAuthenticationError);
    }
    let decoded = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
        .map_err(|_| ChannelAuthenticationError);
    let released = free_local(text.cast());
    match (decoded, released) {
        (Ok(value), Ok(())) => Ok(value),
        _ => Err(ChannelAuthenticationError),
    }
}

fn free_local(value: *mut core::ffi::c_void) -> Result<(), ChannelAuthenticationError> {
    if value.is_null() || unsafe { LocalFree(value) }.is_null() {
        Ok(())
    } else {
        Err(ChannelAuthenticationError)
    }
}

impl Drop for WindowsClientPipe {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle) };
    }
}

impl io::Read for WindowsClientPipe {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match &self.io_mode {
            WindowsClientIoMode::Installed => read_handle(self.handle, buffer),
            WindowsClientIoMode::Sync(deadline) => {
                overlapped_read(self.handle, deadline.raw_handle(), buffer)
            }
        }
    }
}

impl io::Write for WindowsClientPipe {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match &self.io_mode {
            WindowsClientIoMode::Installed => write_handle(self.handle, buffer),
            WindowsClientIoMode::Sync(deadline) => {
                overlapped_write(self.handle, deadline.raw_handle(), buffer)
            }
        }
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

fn current_process_sid() -> Result<String, ChannelAuthenticationError> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(ChannelAuthenticationError);
    }
    let sid = token_sid(token);
    let closed = close_handle(token);
    match (sid, closed) {
        (Ok(sid), Ok(())) => Ok(sid),
        _ => Err(ChannelAuthenticationError),
    }
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
        Foundation::{CloseHandle, ERROR_ACCESS_DENIED},
        Security::TOKEN_QUERY,
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    const CANARY: &[u8] = b"ticket27-synthetic-native-canary";
    static CLIPBOARD_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn owned_server_pipe_can_move_to_one_service_worker() {
        fn require_send<T: Send>() {}
        require_send::<WindowsServerPipe>();
    }

    struct OwnedTestPipe(Option<HANDLE>);

    impl OwnedTestPipe {
        fn close(mut self) -> Result<(), u32> {
            self.close_once()
        }

        fn close_once(&mut self) -> Result<(), u32> {
            let Some(handle) = self.0.take() else {
                return Ok(());
            };
            if unsafe { CloseHandle(handle) } == 0 {
                return Err(unsafe { GetLastError() });
            }
            Ok(())
        }
    }

    impl Drop for OwnedTestPipe {
        fn drop(&mut self) {
            if let Err(error) = self.close_once() {
                if std::thread::panicking() {
                    std::process::abort();
                }
                panic!("owned test pipe cleanup failed with GetLastError={error}");
            }
        }
    }

    fn create_owned_test_pipe(
        vault: &str,
        owner_sid: &str,
        service_sid: &str,
        client_sid: &str,
    ) -> Result<OwnedTestPipe, u32> {
        let name = wide(
            &WindowsEndpoint::Agent
                .pipe_name(vault)
                .expect("the test vault identifier is valid"),
        );
        let canonical = windows_pipe_sddl(service_sid, client_sid)
            .expect("the test service and client SIDs are valid");
        let service_owner = format!("O:{service_sid}G:{service_sid}");
        let creator_owner = format!("O:{owner_sid}G:{owner_sid}");
        let owned_sddl = canonical.replacen(&service_owner, &creator_owner, 1);
        assert!(owned_sddl.starts_with(&creator_owner));
        let sddl = wide(&owned_sddl);
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
            return Err(unsafe { GetLastError() });
        }
        let security = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
                .expect("SECURITY_ATTRIBUTES fits in DWORD"),
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let result = create_pipe_instance(name.as_ptr(), &raw const security);
        unsafe { LocalFree(descriptor) };
        result.map(|handle| OwnedTestPipe(Some(handle)))
    }

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
        let first = create_owned_test_pipe(
            &vault,
            &current_client_sid,
            service_sid,
            &current_client_sid,
        )
        .unwrap_or_else(|error| {
            panic!("first named pipe creation failed with GetLastError={error}")
        });
        assert_eq!(
            create_owned_test_pipe(
                &vault,
                &current_client_sid,
                service_sid,
                different_client_sid,
            )
            .err(),
            Some(ERROR_ACCESS_DENIED),
            "second named pipe creation returned an unexpected GetLastError"
        );
        first.close().unwrap_or_else(|error| {
            panic!("first named pipe cleanup failed with GetLastError={error}")
        });
    }

    #[test]
    fn dpapi_machine_roundtrip_uses_a_distinct_blob() {
        let protected = dpapi_protect_machine(CANARY).unwrap();
        assert_ne!(protected.as_slice(), CANARY);
        assert_eq!(dpapi_unprotect(&protected).unwrap().as_slice(), CANARY);
        assert!(dpapi_unprotect(b"not-a-dpapi-blob").is_err());
    }

    #[test]
    fn sync_pipe_names_and_identity_lists_are_closed() {
        let server = "S-1-5-80-10-20-30-40-50";
        let clients = vec![
            "S-1-5-80-11-21-31-41-51".to_owned(),
            "S-1-5-21-1-2-3-1001".to_owned(),
        ];
        assert!(
            validate_sync_pipe_name(r"\\.\pipe\pm-sync-0123456789abcdef0123456789abcdef").is_ok()
        );
        assert!(validate_sync_pipe_name(r"\\.\pipe\pm-sync-ABC").is_err());
        let descriptor = sync_pipe_sddl(server, &clients).unwrap();
        assert!(descriptor.contains(server));
        assert!(clients.iter().all(|sid| descriptor.contains(sid)));
        assert!(sync_pipe_sddl(server, &["S-1-1-0".to_owned()]).is_err());
        assert!(sync_pipe_sddl(server, &[clients[0].clone(), clients[0].clone()]).is_err());
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
