// SPDX-License-Identifier: AGPL-3.0-only

//! Native file handles with closed creation and final-component link checks.

use std::{fs::File, io, path::Path};

/// Creates one new private regular file without following a final link.
///
/// On Unix the mode is 0600. On Windows the new object receives a protected
/// DACL granting full access only to SYSTEM and its owner.
///
/// # Errors
/// Returns the native creation, security-descriptor cleanup, or identity error.
pub fn create_private_file(path: &Path, read: bool, write: bool) -> io::Result<File> {
    if !read && !write {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private file needs read or write access",
        ));
    }
    #[cfg(unix)]
    {
        use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};
        OpenOptions::new()
            .read(read)
            .write(write)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
    }
    #[cfg(windows)]
    {
        create_private_windows(path, read, write)
    }
}

/// Opens an existing regular file without following a final link.
///
/// # Errors
/// Returns an error for a directory, a reparse point, an invalid path, or any
/// native open/identity failure.
pub fn open_regular_file(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    let file = {
        use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?
    };
    #[cfg(windows)]
    let file = open_existing_windows(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native file handle is not regular",
        ));
    }
    #[cfg(windows)]
    reject_reparse(&file)?;
    Ok(file)
}

/// Flushes directory metadata through a native directory handle.
///
/// # Errors
/// Returns an error when the path is not a directory or native open/flush
/// fails. The operation never substitutes a file or ancestor directory.
pub fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()
    }
    #[cfg(windows)]
    {
        sync_directory_windows(path)
    }
}

#[cfg(windows)]
fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    if path.as_os_str().encode_wide().any(|unit| unit == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains NUL",
        ));
    }
    Ok(path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect())
}

#[cfg(windows)]
fn create_private_windows(path: &Path, read: bool, write: bool) -> io::Result<File> {
    use std::{os::windows::io::FromRawHandle, ptr};
    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree},
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{
            CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        },
    };

    let wide = wide_path(path)?;
    let mut access = 0;
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
        .map_err(|_| io::Error::other("SECURITY_ATTRIBUTES size overflow"))?;
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let security = SECURITY_ATTRIBUTES {
        nLength: security_size,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
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
    let creation = if handle == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        Ok(handle)
    };
    let release = unsafe { LocalFree(descriptor) };
    let release = if release.is_null() {
        Ok(())
    } else {
        Err(io::Error::other(
            "LocalFree failed for private-file security descriptor",
        ))
    };
    let handle = match (creation, release) {
        (Ok(handle), Ok(())) => handle,
        (Err(primary), Ok(())) => return Err(primary),
        (Err(primary), Err(cleanup)) => {
            return Err(io::Error::other(format!(
                "{primary}; descriptor cleanup failed: {cleanup}"
            )));
        }
        (Ok(handle), Err(cleanup)) => {
            if unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) } == 0 {
                return Err(io::Error::other(format!(
                    "{cleanup}; private-file handle cleanup failed: {}",
                    io::Error::last_os_error()
                )));
            }
            return Err(cleanup);
        }
    };
    let file = unsafe { File::from_raw_handle(handle) };
    reject_reparse(&file)?;
    Ok(file)
}

#[cfg(windows)]
fn open_existing_windows(path: &Path) -> io::Result<File> {
    use std::{os::windows::io::FromRawHandle, ptr};
    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, OPEN_EXISTING,
        },
    };
    let wide = wide_path(path)?;
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

#[cfg(windows)]
fn sync_directory_windows(path: &Path) -> io::Result<()> {
    use std::{
        os::windows::io::{AsRawHandle, FromRawHandle},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FlushFileBuffers, OPEN_EXISTING,
        },
    };
    let wide = wide_path(path)?;
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let directory = unsafe { File::from_raw_handle(handle) };
    if !directory.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native directory handle is not a directory",
        ));
    }
    reject_reparse(&directory)?;
    if unsafe { FlushFileBuffers(directory.as_raw_handle()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn reject_reparse(file: &File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, GetFileInformationByHandle,
    };
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "reparse points are not regular files",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn owned_root(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "pm-native-file-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn remove_owned(root: &Path, entries: &[&Path]) {
        let mut failures = Vec::new();
        for entry in entries {
            if let Err(error) = std::fs::remove_file(entry) {
                failures.push(format!("remove {}: {error}", entry.display()));
            }
        }
        if let Err(error) = std::fs::remove_dir(root) {
            failures.push(format!("remove {}: {error}", root.display()));
        }
        assert!(failures.is_empty(), "{}", failures.join("; "));
    }

    #[test]
    fn private_file_creation_is_exclusive_and_regular() {
        let root = owned_root("exclusive");
        std::fs::create_dir(&root).unwrap();
        let path = root.join("object");
        let file = create_private_file(&path, true, true).unwrap();
        assert!(file.metadata().unwrap().is_file());
        let collision = create_private_file(&path, true, true).unwrap_err();
        assert_eq!(collision.kind(), io::ErrorKind::AlreadyExists);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        }
        #[cfg(windows)]
        assert_protected_two_ace_dacl(&file);
        drop(file);
        remove_owned(&root, &[&path]);
    }

    #[cfg(windows)]
    #[test]
    fn regular_open_rejects_a_final_reparse_component() {
        let root = owned_root("reparse");
        std::fs::create_dir(&root).unwrap();
        let target = root.join("target");
        let link = root.join("link");
        drop(create_private_file(&target, true, true).unwrap());
        std::os::windows::fs::symlink_file(&target, &link).unwrap();
        let error = open_regular_file(&link).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        remove_owned(&root, &[&link, &target]);
    }

    #[cfg(windows)]
    fn assert_protected_two_ace_dacl(file: &File) {
        use std::{os::windows::io::AsRawHandle, ptr};
        use windows_sys::Win32::{
            Foundation::{ERROR_SUCCESS, LocalFree},
            Security::{
                ACL_SIZE_INFORMATION, AclSizeInformation,
                Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
                DACL_SECURITY_INFORMATION, GetAclInformation, GetSecurityDescriptorControl,
                PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
            },
        };
        let mut dacl = ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &raw mut dacl,
                ptr::null_mut(),
                &raw mut descriptor,
            )
        };
        assert_eq!(status, ERROR_SUCCESS);
        assert!(!descriptor.is_null());
        assert!(!dacl.is_null());
        let mut control = 0;
        let mut revision = 0;
        assert_ne!(
            unsafe {
                GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision)
            },
            0
        );
        assert_ne!(control & SE_DACL_PROTECTED, 0);
        let mut information = ACL_SIZE_INFORMATION {
            AceCount: 0,
            AclBytesInUse: 0,
            AclBytesFree: 0,
        };
        assert_ne!(
            unsafe {
                GetAclInformation(
                    dacl,
                    (&raw mut information).cast(),
                    u32::try_from(std::mem::size_of::<ACL_SIZE_INFORMATION>()).unwrap(),
                    AclSizeInformation,
                )
            },
            0
        );
        assert_eq!(information.AceCount, 2);
        assert!(unsafe { LocalFree(descriptor) }.is_null());
    }
}
