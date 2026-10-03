// SPDX-License-Identifier: AGPL-3.0-only
//! Read-only sampling of the real TUI process during its handle transfer.
use std::{
    io, ptr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError, HANDLE, LocalFree},
    Security::{
        ACCESS_ALLOWED_ACE, ACL,
        Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT},
        DACL_SECURITY_INFORMATION, GetAce, LookupAccountNameW,
    },
    System::Threading::{GetCurrentProcess, PROCESS_DUP_HANDLE, PROCESS_QUERY_LIMITED_INFORMATION},
};

/// Discriminate elevated unit-test results from the real human fixture token.
/// This changes only this disposable fixture's DACL, never the TUI's DACL.
pub(super) fn probe_human_token_lease() -> io::Result<()> {
    let process = unsafe { GetCurrentProcess() };
    let service = service_sid()?;
    let before = snapshot(process, &service)?;
    if before.service_aces != 0 {
        return Err(io::Error::other("human fixture already has a transfer ACE"));
    }
    let lease = pm_native_channel::ProcessHandleTransferLease::begin().map_err(|error| {
        io::Error::other(format!(
            "human-token lease begin rejected; cleanup-failed={}",
            error.cleanup_result().is_err()
        ))
    })?;
    let during = snapshot(process, &service).and_then(|during| {
        if during.service_aces != 1 || during.bytes == before.bytes {
            Err(io::Error::other(
                "human-token lease did not install its exact ACE",
            ))
        } else {
            Ok(())
        }
    });
    let restored = lease
        .finish()
        .map_err(|_| io::Error::other("human-token lease finish failed"));
    let after = snapshot(process, &service).and_then(|after| {
        if after.service_aces != 0 || after.bytes != before.bytes {
            Err(io::Error::other(
                "human-token lease DACL not restored exactly",
            ))
        } else {
            Ok(())
        }
    });
    let errors = [during, restored, after]
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

fn release(value: *mut std::ffi::c_void) -> io::Result<()> {
    if value.is_null() || unsafe { LocalFree(value) }.is_null() {
        Ok(())
    } else {
        Err(io::Error::other("TUI ACL observation LocalFree failed"))
    }
}

fn service_sid() -> io::Result<Vec<usize>> {
    let account = r"NT SERVICE\PasswordManager"
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut bytes = 0;
    let mut units = 0;
    let mut kind = 0;
    if unsafe {
        LookupAccountNameW(
            ptr::null(),
            account.as_ptr(),
            ptr::null_mut(),
            &raw mut bytes,
            ptr::null_mut(),
            &raw mut units,
            &raw mut kind,
        )
    } != 0
        || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
        || bytes == 0
        || units == 0
    {
        return Err(io::Error::other("TUI ACL service SID size query failed"));
    }
    let mut sid = vec![0_usize; (bytes as usize).div_ceil(std::mem::size_of::<usize>())];
    let mut domain = vec![0_u16; units as usize];
    if unsafe {
        LookupAccountNameW(
            ptr::null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &raw mut bytes,
            domain.as_mut_ptr(),
            &raw mut units,
            &raw mut kind,
        )
    } == 0
    {
        return Err(io::Error::other("TUI ACL service SID resolution failed"));
    }
    Ok(sid)
}

struct Snapshot {
    bytes: Vec<u8>,
    service_aces: usize,
}

fn snapshot(process: HANDLE, service: &[usize]) -> io::Result<Snapshot> {
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let queried = unsafe {
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
    };
    let result = (|| {
        if queried != 0 || descriptor.is_null() || dacl.is_null() {
            return Err(io::Error::other("TUI ACL query failed/null DACL"));
        }
        let size = usize::from(unsafe { (*dacl).AclSize });
        if size < std::mem::size_of::<ACL>() {
            return Err(io::Error::other("TUI ACL invalid size"));
        }
        let bytes = unsafe { std::slice::from_raw_parts(dacl.cast::<u8>(), size) }.to_vec();
        let mut service_aces = 0;
        for i in 0..unsafe { (*dacl).AceCount } {
            let mut ace = ptr::null_mut();
            if unsafe { GetAce(dacl, u32::from(i), &raw mut ace) } == 0 || ace.is_null() {
                return Err(io::Error::other("TUI ACL ACE query failed"));
            }
            let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
            if unsafe { (*allowed).Header.AceType } != 0 {
                continue;
            }
            let sid = unsafe { ptr::addr_of!((*allowed).SidStart).cast_mut().cast() };
            if unsafe {
                windows_sys::Win32::Security::EqualSid(sid, service.as_ptr().cast_mut().cast())
            } == 0
            {
                continue;
            }
            if unsafe { (*allowed).Header.AceFlags } != 0
                || unsafe { (*allowed).Mask }
                    != PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION
            {
                return Err(io::Error::other(
                    "TUI ACL service grant has unexpected rights/inheritance",
                ));
            }
            service_aces += 1;
        }
        Ok(Snapshot {
            bytes,
            service_aces,
        })
    })();
    let freed = release(descriptor);
    match (result, freed) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(io::Error::other(format!("{error}; {cleanup}"))),
    }
}

pub(super) struct Sampling {
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<io::Result<usize>>>,
    before: Vec<u8>,
    service: Vec<usize>,
    process: usize,
}

impl Sampling {
    pub(super) fn observe<T>(
        process: HANDLE,
        require_lease: bool,
        operation: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        let sampling = Self::begin(process)?;
        let result = operation();
        let observation = sampling.finish(require_lease);
        match (result, observation) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(cleanup)) => Err(io::Error::other(format!(
                "{error}; TUI ACL observation/cleanup: {cleanup}"
            ))),
        }
    }

    fn begin(process: HANDLE) -> io::Result<Self> {
        let service = service_sid()?;
        let before = snapshot(process, &service)?;
        if before.service_aces != 0 {
            return Err(io::Error::other(
                "TUI transfer grant already present before import",
            ));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread_service = service.clone();
        let process_address = process as usize;
        let join = thread::Builder::new()
            .name("pm27-real-tui-acl".into())
            .spawn(move || {
                let mut observed = 0;
                while !thread_stop.load(Ordering::Acquire) {
                    let current = snapshot(process_address as HANDLE, &thread_service)?;
                    if current.service_aces > 1 {
                        return Err(io::Error::other("TUI duplicate service transfer ACE"));
                    }
                    observed += usize::from(current.service_aces == 1);
                    thread::sleep(Duration::from_millis(1));
                }
                Ok(observed)
            })?;
        Ok(Self {
            stop,
            join: Some(join),
            before: before.bytes,
            service,
            process: process_address,
        })
    }

    fn finish(mut self, require_lease: bool) -> io::Result<()> {
        let observed = self.stop_and_join()?;
        let after = snapshot(self.process as HANDLE, &self.service)?;
        if after.service_aces != 0 || after.bytes != self.before {
            return Err(io::Error::other(
                "TUI DACL not restored exactly after import",
            ));
        }
        if require_lease && observed == 0 {
            return Err(io::Error::other("real TUI transfer lease was not observed"));
        }
        if !require_lease && observed != 0 {
            return Err(io::Error::other(
                "local source rejection unexpectedly granted a process lease",
            ));
        }
        Ok(())
    }

    fn stop_and_join(&mut self) -> io::Result<usize> {
        self.stop.store(true, Ordering::Release);
        self.join
            .take()
            .ok_or_else(|| io::Error::other("TUI ACL sampler already joined"))?
            .join()
            .map_err(|_| io::Error::other("TUI ACL sampler panicked"))?
    }
}

impl Drop for Sampling {
    fn drop(&mut self) {
        if self.join.is_some() && self.stop_and_join().is_err() {
            eprintln!("TUI_ACL_SAMPLER_CLEANUP_FAILED");
        }
    }
}
