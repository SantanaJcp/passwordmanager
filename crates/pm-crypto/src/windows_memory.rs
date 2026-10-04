// SPDX-License-Identifier: AGPL-3.0-only

//! Categorical diagnostics only. This module never changes the process quota.

use crate::CryptoError;
use std::sync::{
    Mutex, OnceLock,
    atomic::{AtomicUsize, Ordering},
};
use windows_sys::Win32::{
    Foundation::GetLastError,
    System::{
        Memory::GetProcessWorkingSetSizeEx,
        SystemInformation::{GetSystemInfo, SYSTEM_INFO},
        Threading::GetCurrentProcess,
    },
};

static LIVE_PAYLOAD_PAGES: AtomicUsize = AtomicUsize::new(0);
static LIVE_REGIONS: AtomicUsize = AtomicUsize::new(0);
static LAST_FAILURE: Mutex<Option<WindowsMemoryFailure>> = Mutex::new(None);

/// Counters contain no plaintext, pointers, handles or identities. Page bytes
/// cover only our explicitly verified payload locks, not libsodium's canary.
#[derive(Clone, Copy)]
pub struct WindowsMemoryStatus {
    pub live_capacity_bytes: usize,
    pub budget_bytes: usize,
    pub live_payload_page_bytes: usize,
    pub live_regions: usize,
    pub working_set_min_bytes: usize,
    pub working_set_max_bytes: usize,
    pub working_set_flags: u32,
}

#[derive(Clone, Copy)]
pub struct WindowsMemoryFailure {
    pub category: &'static str,
    pub requested_capacity_bytes: usize,
    pub requested_payload_page_bytes: usize,
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

fn payload_page_bytes(len: usize) -> usize {
    static PAGE_SIZE: OnceLock<usize> = OnceLock::new();
    let page = *PAGE_SIZE.get_or_init(|| {
        let mut info = SYSTEM_INFO::default();
        // SAFETY: documented infallible system query writes this structure.
        unsafe { GetSystemInfo(&raw mut info) };
        info.dwPageSize as usize
    });
    // libsodium places each payload at the end of a page-aligned region.
    len.div_ceil(page) * page
}

pub(crate) fn allocated(len: usize) {
    LIVE_PAYLOAD_PAGES.fetch_add(payload_page_bytes(len), Ordering::AcqRel);
    LIVE_REGIONS.fetch_add(1, Ordering::AcqRel);
}

pub(crate) fn released(len: usize) {
    LIVE_PAYLOAD_PAGES.fetch_sub(payload_page_bytes(len), Ordering::AcqRel);
    LIVE_REGIONS.fetch_sub(1, Ordering::AcqRel);
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
        requested_payload_page_bytes: payload_page_bytes(len),
        win32_error,
        status,
    });
    Ok(())
}

pub(crate) fn last_error() -> u32 {
    // SAFETY: reads only this thread's Win32 error slot.
    unsafe { GetLastError() }
}
