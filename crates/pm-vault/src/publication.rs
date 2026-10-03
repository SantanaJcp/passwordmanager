// SPDX-License-Identifier: AGPL-3.0-only

use std::{io, path::Path};

/// Atomically moves a completed staging file to a new destination.
///
/// The caller owns staging creation, synchronization and cleanup. Existing
/// destinations (including symlinks) are never replaced. No alternative move
/// is attempted if the native exclusive operation is unavailable.
///
/// # Errors
/// Returns `AlreadyExists` on collision, or the native I/O error on failure.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn publish_new_file(staging: &Path, destination: &Path) -> io::Result<()> {
    publish_native(staging, destination)
}

#[cfg(unix)]
fn native_path(path: &Path) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

#[cfg(target_os = "linux")]
fn publish_native(staging: &Path, destination: &Path) -> io::Result<()> {
    let staging = native_path(staging)?;
    let destination = native_path(destination)?;
    // SAFETY: both C strings stay alive for the call; no handles are retained.
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            staging.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn publish_native(staging: &Path, destination: &Path) -> io::Result<()> {
    let staging = native_path(staging)?;
    let destination = native_path(destination)?;
    // SAFETY: both C strings stay alive for the call; no handles are retained.
    let result =
        unsafe { libc::renamex_np(staging.as_ptr(), destination.as_ptr(), libc::RENAME_EXCL) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "windows")]
fn publish_native(staging: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }
    fn wide(path: &Path) -> io::Result<Vec<u16>> {
        let mut value: Vec<_> = path.as_os_str().encode_wide().collect();
        if value.contains(&0) {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        value.push(0);
        Ok(value)
    }
    let staging = wide(staging)?;
    let destination = wide(destination)?;
    // SAFETY: both terminated UTF-16 buffers stay alive. Flags exclude both
    // REPLACE_EXISTING and COPY_ALLOWED: collision/cross-volume moves fail.
    let result = unsafe { MoveFileExW(staging.as_ptr(), destination.as_ptr(), 0) };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::symlink,
        sync::{Arc, Barrier},
        thread,
    };

    struct Directory(std::path::PathBuf);
    impl Directory {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "pmshared-publication-{}-{name}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("exclusive synthetic fixture");
            Self(path)
        }
        fn path(&self, name: &str) -> std::path::PathBuf {
            self.0.join(name)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove only the owned publication fixture");
            assert!(!self.0.exists());
        }
    }

    #[test]
    fn publication_preserves_existing_file_and_symlink() {
        let dir = Directory::new("existing");
        let original = b"synthetic pmshared existing valid data";
        let file = dir.path("existing");
        fs::write(&file, original).unwrap();
        let dangling = dir.path("dangling");
        symlink(dir.path("absent-target"), &dangling).unwrap();
        let linked = dir.path("linked");
        symlink(&file, &linked).unwrap();
        for (index, destination) in [&file, &linked, &dangling].into_iter().enumerate() {
            let staging = dir.path(&format!("stage-{index}"));
            fs::write(&staging, b"synthetic pmshared replacement").unwrap();
            let error = publish_new_file(&staging, destination).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
            assert!(
                staging.exists(),
                "failed publication leaves owned staging for caller cleanup"
            );
            fs::remove_file(staging).unwrap();
        }
        assert_eq!(fs::read(file).unwrap(), original);
        assert!(
            fs::symlink_metadata(dangling)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(
            fs::symlink_metadata(linked)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn publication_has_one_winner_when_writers_collide() {
        let dir = Directory::new("race");
        let destination = dir.path("new");
        let gate = Arc::new(Barrier::new(2));
        let workers: Vec<_> = (0..2)
            .map(|index| {
                let staging = dir.path(&format!("stage-{index}"));
                fs::write(&staging, format!("synthetic pmshared writer {index}")).unwrap();
                let destination = destination.clone();
                let gate = Arc::clone(&gate);
                thread::spawn(move || {
                    gate.wait();
                    (staging.clone(), publish_new_file(&staging, &destination))
                })
            })
            .collect();
        let mut successes = 0;
        for worker in workers {
            let (staging, result) = worker.join().unwrap();
            match result {
                Ok(()) => {
                    successes += 1;
                    assert!(!staging.exists());
                }
                Err(error) => {
                    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
                    fs::remove_file(staging).unwrap();
                }
            }
        }
        assert_eq!(successes, 1);
        assert!(
            fs::read(destination)
                .unwrap()
                .starts_with(b"synthetic pmshared writer ")
        );
    }
}
