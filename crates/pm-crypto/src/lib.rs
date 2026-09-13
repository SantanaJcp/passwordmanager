// SPDX-License-Identifier: AGPL-3.0-only

//! The only crate allowed to cross the libsodium FFI boundary.
//!
//! Ticket 02 adds the typed G2 foundation and synthetic format vectors. It does
//! not claim later authority reducers, CRUD flows, backups, or native custody.

mod root;

use std::ffi::CStr;

pub use root::{
    AuditCiphertext, CreatedRoot, CryptoError, DeviceKeyPair, FileCiphertext, GrantVectorInput,
    ItemKind, KdfProfile, OpenedRevisionPackage, PendingGrantVector, Pmf1Vector, RecoveryCode,
    RevisionPackage, RevisionPackageInput, RootBundle, SignedGrantVector, TrustedRoot,
    UnlockedRoot, create_human_root, digest, fill_random, open_human_root, random_id,
    recover_human_root, verify_human_command, verify_human_event,
};

/// Returns the version reported by the linked libsodium C artifact.
#[must_use]
pub fn linked_libsodium_version() -> &'static CStr {
    // SAFETY: libsodium documents `sodium_version_string` as returning a
    // non-null pointer to a process-lifetime, NUL-terminated version string.
    unsafe { CStr::from_ptr(libsodium_sys::sodium_version_string()) }
}
