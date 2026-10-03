// SPDX-License-Identifier: AGPL-3.0-only

use crate::HumanCommitError;
use minicbor::encode::Write;
use pm_crypto::{CryptoError, ProtectedBytes, ProtectedWriter};

struct Size {
    bytes: usize,
}

impl Write for Size {
    type Error = CryptoError;
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .ok_or(CryptoError::InvalidFormat)?;
        Ok(())
    }
}

/// Measures the selected encoding without storing bytes, then writes it once
/// into an exact locked destination. No output is returned on either failure.
pub(crate) fn encode(
    maximum: usize,
    emit: impl Fn(&mut dyn Write<Error = CryptoError>) -> Result<(), HumanCommitError>,
) -> Result<ProtectedBytes, HumanCommitError> {
    let mut size = Size { bytes: 0 };
    emit(&mut size)?;
    if size.bytes > maximum {
        return Err(HumanCommitError::InvalidInput);
    }
    let mut destination = ProtectedWriter::new(size.bytes)?;
    emit(&mut destination)?;
    Ok(destination.finish_exact()?)
}
