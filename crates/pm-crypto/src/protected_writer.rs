// SPDX-License-Identifier: AGPL-3.0-only

use crate::{CryptoError, ProtectedBytes};

/// A fixed-size plaintext destination locked before the first write.
pub struct ProtectedWriter {
    bytes: ProtectedBytes,
    position: usize,
    failed: bool,
}

impl ProtectedWriter {
    /// Reserves the verified exact size before accepting plaintext.
    ///
    /// # Errors
    /// Propagates unavailable allocation, locking or process budget.
    pub fn new(size: usize) -> Result<Self, CryptoError> {
        Ok(Self {
            bytes: ProtectedBytes::zeroed(size)?,
            position: 0,
            failed: false,
        })
    }

    /// Writes a complete slice without truncation or growth.
    ///
    /// # Errors
    /// Rejects overflow or bytes beyond the verified size.
    pub fn put(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        self.put_with(bytes.len(), |destination| {
            destination.copy_from_slice(bytes);
            Ok(())
        })
    }

    /// Lets a checked native operation write directly into the locked owner.
    ///
    /// # Errors
    /// Propagates failure without advancing or publishing a partial owner.
    pub fn put_with(
        &mut self,
        size: usize,
        write: impl FnOnce(&mut [u8]) -> Result<(), CryptoError>,
    ) -> Result<(), CryptoError> {
        if self.failed {
            return Err(CryptoError::InvalidFormat);
        }
        let result = (|| {
            let end = self
                .position
                .checked_add(size)
                .ok_or(CryptoError::InvalidFormat)?;
            let destination = self
                .bytes
                .get_mut(self.position..end)
                .ok_or(CryptoError::InvalidFormat)?;
            write(destination)?;
            self.position = end;
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Publishes the owner only after exactly the verified bytes were written.
    ///
    /// # Errors
    /// Rejects an incomplete encoding, dropping and wiping the whole owner.
    pub fn finish_exact(self) -> Result<ProtectedBytes, CryptoError> {
        if self.failed || self.position != self.bytes.len() {
            return Err(CryptoError::InvalidFormat);
        }
        Ok(self.bytes)
    }
}

impl minicbor::encode::Write for ProtectedWriter {
    type Error = CryptoError;
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.put(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_native_or_overlong_write_cannot_publish_plaintext() {
        let mut complete = ProtectedWriter::new(4).expect("locked owner");
        complete.put(b"PM28").unwrap();
        assert!(complete.put(b"extra").is_err());
        assert!(complete.finish_exact().is_err());
        let mut partial = ProtectedWriter::new(4).expect("locked owner");
        assert!(
            partial
                .put_with(4, |output| {
                    output.copy_from_slice(b"PM28");
                    Err(CryptoError::Authentication)
                })
                .is_err()
        );
        assert!(partial.finish_exact().is_err());
        let mut short = ProtectedWriter::new(4).expect("locked owner");
        short.put(b"PM").unwrap();
        assert!(short.finish_exact().is_err());
        let mut exact = ProtectedWriter::new(4).expect("locked owner");
        exact.put(b"PM28").unwrap();
        assert!(exact.finish_exact().unwrap().as_ref().eq(b"PM28"));
    }
}
