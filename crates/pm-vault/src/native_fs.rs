// SPDX-License-Identifier: AGPL-3.0-only

//! Platform filesystem primitives used by vault import and ciphertext staging.

use std::{
    fs::{File, Metadata, OpenOptions},
    io,
    path::Path,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) links: u64,
}

/// Opens a path for reading without following a final filesystem link.
pub(crate) fn open_read(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

/// Reads stable identity information from the opened file handle.
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn file_identity(file: &File, metadata: &Metadata) -> io::Result<FileIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = file;
        Ok(FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            links: metadata.nlink(),
        })
    }
    #[cfg(windows)]
    {
        let _ = metadata;
        windows_file_identity(file)
    }
}

/// Returns free bytes available to the current account at `path`.
pub(crate) fn available_capacity(path: &Path) -> io::Result<u64> {
    #[cfg(unix)]
    {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
        // SAFETY: `path` is NUL-terminated and `status` is writable storage.
        let available = unsafe {
            let mut status: libc::statvfs = std::mem::zeroed();
            if libc::statvfs(path.as_ptr(), &raw mut status) != 0 {
                return Err(io::Error::last_os_error());
            }
            status.f_bavail.saturating_mul(status.f_frsize)
        };
        Ok(available)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

        if path.as_os_str().encode_wide().any(|unit| unit == 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains NUL",
            ));
        }
        let directory = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let wide: Vec<u16> = directory
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut available = 0_u64;
        let mut total = 0_u64;
        let mut free = 0_u64;
        // SAFETY: `wide` is a valid NUL-terminated UTF-16 path and all output
        // pointers refer to writable local values for the duration of the call.
        let ok = unsafe {
            GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &raw mut available,
                &raw mut total,
                &raw mut free,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(available)
    }
}

/// Creates an exclusive staging file and applies the platform's private-file
/// protection before returning it to the caller.
pub(crate) fn create_private(path: &Path, read: bool, write: bool) -> io::Result<File> {
    #[cfg(windows)]
    {
        create_private_windows(path, read, write)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = OpenOptions::new();
        options.read(read).write(write).create_new(true);
        options.mode(0o600);
        options.open(path)
    }
}

#[cfg(windows)]
fn windows_file_identity(file: &File) -> io::Result<FileIdentity> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, GetFileInformationByHandle,
    };

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the raw handle remains valid through this call because `file` is
    // borrowed, and `information` is writable storage of the documented type.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut information) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "reparse points are not valid vault files",
        ));
    }
    let inode =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    Ok(FileIdentity {
        device: u64::from(information.dwVolumeSerialNumber),
        inode,
        links: u64::from(information.nNumberOfLinks),
    })
}

#[cfg(windows)]
fn create_private_windows(path: &Path, read: bool, write: bool) -> io::Result<File> {
    use std::{os::windows::ffi::OsStrExt, os::windows::io::FromRawHandle, ptr};
    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree},
        Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        },
        Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES},
        Storage::FileSystem::{
            CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        },
    };

    if !read && !write {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private file needs read or write access",
        ));
    }
    if path.as_os_str().encode_wide().any(|unit| unit == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains NUL",
        ));
    }
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut access = 0_u32;
    if read {
        access |= GENERIC_READ;
    }
    if write {
        access |= GENERIC_WRITE;
    }
    let sddl: Vec<u16> = "D:P(A;;FA;;;SY)(A;;FA;;;OW)"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let security_size = u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
        .map_err(|_| io::Error::other("SECURITY_ATTRIBUTES size does not fit u32"))?;
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated and the output pointer is valid.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(io::Error::last_os_error());
    }
    let security = SECURITY_ATTRIBUTES {
        nLength: security_size,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    // SAFETY: `wide` and `security` stay live through the call. `CreateFileW`
    // copies the descriptor into the new object before exposing its handle.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &raw const security,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    unsafe { LocalFree(descriptor) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `handle` is a successful, uniquely owned CreateFileW handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}
