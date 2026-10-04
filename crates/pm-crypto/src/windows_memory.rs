// SPDX-License-Identifier: AGPL-3.0-only

//! Windows protected-memory quota and categorical accounting.

use crate::CryptoError;
use std::sync::{
    Mutex, OnceLock,
    atomic::{AtomicUsize, Ordering},
};
use windows_sys::Win32::{
    Foundation::{GetLastError, HANDLE},
    System::{
        Memory::{
            GetProcessWorkingSetSizeEx, QUOTA_LIMITS_HARDWS_MAX_DISABLE,
            QUOTA_LIMITS_HARDWS_MIN_DISABLE, SetProcessWorkingSetSizeEx,
        },
        SystemInformation::{GetSystemInfo, SYSTEM_INFO},
        Threading::GetCurrentProcess,
    },
};

static LIVE_PAYLOAD_PAGES: AtomicUsize = AtomicUsize::new(0);
static LIVE_LOCKED_PAGES: AtomicUsize = AtomicUsize::new(0);
static LIVE_BUDGET_PAGES: AtomicUsize = AtomicUsize::new(0);
static LIVE_REGIONS: AtomicUsize = AtomicUsize::new(0);
static LAST_FAILURE: Mutex<Option<WindowsMemoryFailure>> = Mutex::new(None);
static PROCESS_QUOTA: OnceLock<Result<(), WindowsMemoryQuotaError>> = OnceLock::new();

pub const WINDOWS_PROTECTED_WORKING_SET_MIN: usize = 64 * 1024 * 1024;
// libsodium 1.0.22 utils.c: ceil(size + CANARY_SIZE) plus two no-access
// guard pages. Its metadata page is not locked and is covered by quota margin.
const CANARY_BYTES: usize = 16;
const GUARD_PAGES: usize = 2;
const SOFT_WORKING_SET_FLAGS: u32 =
    QUOTA_LIMITS_HARDWS_MIN_DISABLE | QUOTA_LIMITS_HARDWS_MAX_DISABLE;

/// No content, addresses or handles are exposed by quota failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsMemoryQuotaError {
    pub category: &'static str,
    pub win32_error: u32,
}

/// Applies and verifies the process quota before any protected owner is used.
/// Success and failure are both retained; there is no retry with another quota.
///
/// # Errors
/// Returns an explicit query/set/effective-quota error. The caller must stop
/// startup or deny the operation before accepting plaintext.
pub fn prepare_windows_protected_memory() -> Result<WindowsMemoryStatus, WindowsMemoryQuotaError> {
    // SAFETY: current-process pseudo handle is valid for this process lifetime.
    (*PROCESS_QUOTA.get_or_init(|| configure_working_set(unsafe { GetCurrentProcess() })))?;
    windows_memory_status().map_err(|_| WindowsMemoryQuotaError {
        category: "working-set-query",
        win32_error: last_error(),
    })
}

fn query_working_set(process: HANDLE) -> Result<(usize, usize, u32), WindowsMemoryQuotaError> {
    let mut minimum = 0;
    let mut maximum = 0;
    let mut flags = 0;
    // SAFETY: callers supply a live process handle and writable scalar outputs.
    if unsafe {
        GetProcessWorkingSetSizeEx(process, &raw mut minimum, &raw mut maximum, &raw mut flags)
    } == 0
    {
        return Err(WindowsMemoryQuotaError {
            category: "working-set-query",
            win32_error: last_error(),
        });
    }
    Ok((minimum, maximum, flags))
}

fn configure_working_set(process: HANDLE) -> Result<(), WindowsMemoryQuotaError> {
    let (current_minimum, current_maximum, _) = query_working_set(process)?;
    let minimum = current_minimum.max(WINDOWS_PROTECTED_WORKING_SET_MIN);
    let maximum = current_maximum.max(minimum);
    // SAFETY: the current process is live. Soft limits avoid capping KDF/TLS
    // heaps or pinning the entire working set; VirtualLock is still checked.
    if unsafe { SetProcessWorkingSetSizeEx(process, minimum, maximum, SOFT_WORKING_SET_FLAGS) } == 0
    {
        return Err(WindowsMemoryQuotaError {
            category: "working-set-set",
            win32_error: last_error(),
        });
    }
    let (effective_minimum, effective_maximum, effective_flags) = query_working_set(process)?;
    if effective_minimum < minimum
        || effective_maximum < maximum
        || effective_flags != SOFT_WORKING_SET_FLAGS
    {
        return Err(WindowsMemoryQuotaError {
            category: "working-set-effective",
            win32_error: 0,
        });
    }
    Ok(())
}

/// Counters contain no plaintext, pointers, handles or identities. Payload,
/// canary-inclusive locked pages, and the charge including guards are distinct.
#[derive(Clone, Copy)]
pub struct WindowsMemoryStatus {
    pub live_capacity_bytes: usize,
    pub budget_bytes: usize,
    pub live_payload_page_bytes: usize,
    pub live_locked_page_bytes: usize,
    pub live_budget_page_bytes: usize,
    pub page_bytes: usize,
    pub live_regions: usize,
    pub working_set_min_bytes: usize,
    pub working_set_max_bytes: usize,
    pub working_set_flags: u32,
}

#[derive(Clone, Copy)]
pub struct WindowsMemoryFailure {
    pub category: &'static str,
    pub requested_capacity_bytes: usize,
    pub requested_payload_page_bytes: u128,
    /// Captured immediately after sodium_mlock/VirtualLock, before cleanup or
    /// any other Windows call. Zero for aggregate-budget rejection.
    pub win32_error: u32,
    pub status: WindowsMemoryStatus,
}

/// Reads the current quota and our counters without changing them.
///
/// # Errors
/// Fails explicitly if Windows cannot report the process working set limits.
pub fn windows_memory_status() -> Result<WindowsMemoryStatus, CryptoError> {
    let mut minimum = 0;
    let mut maximum = 0;
    let mut flags = 0;
    // SAFETY: current-process pseudo handle and writable scalar outputs.
    if unsafe {
        GetProcessWorkingSetSizeEx(
            GetCurrentProcess(),
            &raw mut minimum,
            &raw mut maximum,
            &raw mut flags,
        )
    } == 0
    {
        return Err(CryptoError::ResourceUnavailable);
    }
    Ok(WindowsMemoryStatus {
        live_capacity_bytes: crate::root::locked_secret_bytes(),
        budget_bytes: crate::root::LOCKED_SECRET_BUDGET,
        live_payload_page_bytes: LIVE_PAYLOAD_PAGES.load(Ordering::Acquire),
        live_locked_page_bytes: LIVE_LOCKED_PAGES.load(Ordering::Acquire),
        live_budget_page_bytes: LIVE_BUDGET_PAGES.load(Ordering::Acquire),
        page_bytes: page_size(),
        live_regions: LIVE_REGIONS.load(Ordering::Acquire),
        working_set_min_bytes: minimum,
        working_set_max_bytes: maximum,
        working_set_flags: flags,
    })
}

/// Returns the latest allocation failure, without diagnostics of its content.
///
/// # Errors
/// A poisoned diagnostic mutex is reported as unavailable.
pub fn windows_memory_failure() -> Result<Option<WindowsMemoryFailure>, CryptoError> {
    LAST_FAILURE
        .lock()
        .map(|failure| *failure)
        .map_err(|_| CryptoError::ResourceUnavailable)
}

fn page_size() -> usize {
    static PAGE_SIZE: OnceLock<usize> = OnceLock::new();
    *PAGE_SIZE.get_or_init(|| {
        let mut info = SYSTEM_INFO::default();
        // SAFETY: documented infallible system query writes this structure.
        unsafe { GetSystemInfo(&raw mut info) };
        info.dwPageSize as usize
    })
}

fn payload_page_bytes(len: usize) -> usize {
    let page = page_size();
    // libsodium places each payload at the end of a page-aligned region.
    // Successful reservations are bounded to 32 MiB, so this cannot overflow.
    len.div_ceil(page) * page
}

pub(crate) fn allocated(len: usize) {
    LIVE_PAYLOAD_PAGES.fetch_add(payload_page_bytes(len), Ordering::AcqRel);
    LIVE_LOCKED_PAGES.fetch_add(locked_page_bytes(len), Ordering::AcqRel);
    LIVE_BUDGET_PAGES.fetch_add(budget_page_bytes(len), Ordering::AcqRel);
    LIVE_REGIONS.fetch_add(1, Ordering::AcqRel);
}

pub(crate) fn released(len: usize) {
    LIVE_PAYLOAD_PAGES.fetch_sub(payload_page_bytes(len), Ordering::AcqRel);
    LIVE_LOCKED_PAGES.fetch_sub(locked_page_bytes(len), Ordering::AcqRel);
    LIVE_BUDGET_PAGES.fetch_sub(budget_page_bytes(len), Ordering::AcqRel);
    LIVE_REGIONS.fetch_sub(1, Ordering::AcqRel);
}

fn locked_page_bytes(len: usize) -> usize {
    (len + CANARY_BYTES).div_ceil(page_size()) * page_size()
}

fn budget_page_bytes(len: usize) -> usize {
    locked_page_bytes(len) + GUARD_PAGES * page_size()
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_ACCESS_DENIED},
        System::Threading::{GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
    };

    #[test]
    fn native_quota_denial_is_explicit_without_lower_quota_retry() {
        // A real query-only handle allows the pre-read, but Windows denies
        // SetProcessWorkingSetSizeEx because PROCESS_SET_QUOTA is absent.
        // SAFETY: the current PID is live; only query access is requested.
        let process =
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, GetCurrentProcessId()) };
        assert!(!process.is_null());
        let before = query_working_set(process).unwrap();
        let result = configure_working_set(process);
        let after = query_working_set(process).unwrap();
        // SAFETY: this uniquely owned process handle is no longer used.
        assert_ne!(unsafe { CloseHandle(process) }, 0);
        assert_eq!(
            result,
            Err(WindowsMemoryQuotaError {
                category: "working-set-set",
                win32_error: ERROR_ACCESS_DENIED,
            })
        );
        assert_eq!(before, after);
        println!("PASS windows-quota-denied win32=5 effective=unchanged retry=none");
    }
}

pub(crate) fn failed(
    category: &'static str,
    len: usize,
    win32_error: u32,
) -> Result<(), CryptoError> {
    let status = windows_memory_status()?;
    *LAST_FAILURE
        .lock()
        .map_err(|_| CryptoError::ResourceUnavailable)? = Some(WindowsMemoryFailure {
        category,
        requested_capacity_bytes: len,
        // A rejected request can be usize::MAX: its rounded page count can
        // exceed usize even though it never reaches sodium_malloc.
        requested_payload_page_bytes: (len as u128).div_ceil(page_size() as u128)
            * page_size() as u128,
        win32_error,
        status,
    });
    Ok(())
}

pub(crate) fn last_error() -> u32 {
    // SAFETY: reads only this thread's Win32 error slot.
    unsafe { GetLastError() }
}
