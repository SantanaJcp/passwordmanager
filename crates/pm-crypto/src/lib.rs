// SPDX-License-Identifier: AGPL-3.0-only

//! The only crate allowed to cross the libsodium FFI boundary.
//!
//! Ticket 01 exposes only the linked-library version. Cryptographic operations
//! and sensitive-buffer handling belong to subsequent approved slices.

use std::ffi::CStr;

/// Returns the version reported by the linked libsodium C artifact.
#[must_use]
pub fn linked_libsodium_version() -> &'static CStr {
    // SAFETY: libsodium documents `sodium_version_string` as returning a
    // non-null pointer to a process-lifetime, NUL-terminated version string.
    unsafe { CStr::from_ptr(libsodium_sys::sodium_version_string()) }
}
