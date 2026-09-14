// SPDX-License-Identifier: AGPL-3.0-only

//! The only crate allowed to cross the libsodium FFI boundary.
//!
//! Ticket 02 adds the typed G2 foundation and synthetic format vectors. It does
//! not claim later authority reducers, CRUD flows, backups, or native custody.

mod native_stdin;
mod root;

use std::ffi::CStr;

pub use native_stdin::NativeStdin;

pub use root::{
    AuditDeviceKeyPair, AuditKey, AuditKeyPackage, BackupOpener, BackupRootEnvelopes, BackupSealer,
    ControlPackageInput, CreatedRoot, CryptoError, DeviceKeyPair, DigestState, FileCiphertext,
    FileOpener, FileSealer, GrantVectorInput, ItemKind, KdfProfile, OpenedRevisionPackage,
    PasskeyKeyPair, PendingGrantVector, PendingRecoveryRotation, Pmf1Vector, ProtectedBytes,
    RecoveryCode, RevisionPackage, RevisionPackageInput, RootBundle, SignedGrantVector,
    SyncPairing, TrustedRoot, UnlockedRoot, create_human_root, digest, fill_random,
    open_human_root, random_id, recover_human_root, verify_audit_key_package,
    verify_audit_signature, verify_device_event, verify_human_command, verify_human_event,
    verify_passkey_signature,
};

/// Applies the Unix process-level controls required before accepting secrets.
///
/// # Errors
///
/// Returns [`CryptoError::ResourceUnavailable`] if core dumps cannot be
/// disabled or, on Linux, the process cannot make itself non-dumpable.
#[cfg(unix)]
pub fn harden_unix_process() -> Result<(), CryptoError> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid immutable rlimit value for this process.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const limit) } != 0 {
        return Err(CryptoError::ResourceUnavailable);
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_SET_DUMPABLE consumes the scalar argument and no pointers.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(CryptoError::ResourceUnavailable);
        }
    }
    Ok(())
}

/// Returns the version reported by the linked libsodium C artifact.
#[must_use]
pub fn linked_libsodium_version() -> &'static CStr {
    // SAFETY: libsodium documents `sodium_version_string` as returning a
    // non-null pointer to a process-lifetime, NUL-terminated version string.
    unsafe { CStr::from_ptr(libsodium_sys::sodium_version_string()) }
}
