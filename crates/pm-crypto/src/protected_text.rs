// SPDX-License-Identifier: AGPL-3.0-only

use crate::{CryptoError, ProtectedBytes};
use std::ops::Deref;

/// UTF-8 plaintext with one locked owner and no diagnostic or cloning traits.
pub struct ProtectedText(ProtectedBytes);

impl ProtectedText {
    /// Locks the exact destination before copying valid UTF-8 plaintext.
    ///
    /// # Errors
    /// Returns `ResourceUnavailable` if allocation, budget or locking fails.
    pub fn copy_from_str(value: &str) -> Result<Self, CryptoError> {
        ProtectedBytes::copy_from_slice(value.as_bytes()).map(Self)
    }

    /// Takes ownership of an exact protected UTF-8 encoding without copying.
    ///
    /// # Errors
    /// Rejects invalid UTF-8 and wipes the rejected owner.
    pub fn from_bytes(value: ProtectedBytes) -> Result<Self, CryptoError> {
        std::str::from_utf8(&value).map_err(|_| CryptoError::InvalidFormat)?;
        Ok(Self(value))
    }
}

impl Deref for ProtectedText {
    type Target = str;

    fn deref(&self) -> &str {
        // SAFETY: construction accepts only UTF-8 and exposes no mutable bytes.
        unsafe { std::str::from_utf8_unchecked(&self.0) }
    }
}

impl PartialEq for ProtectedText {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}
impl Eq for ProtectedText {}
