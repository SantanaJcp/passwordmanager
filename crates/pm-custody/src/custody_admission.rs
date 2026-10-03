// SPDX-License-Identifier: AGPL-3.0-only

//! Presence and integrity of native custody at the delegated admission boundary.

use std::path::{Path, PathBuf};

use crate::Failure;

type Fingerprint = fn(&Path) -> Result<[u8; 32], Failure>;

pub(crate) fn fingerprint_parts(parts: &[&[u8]]) -> Result<[u8; 32], Failure> {
    let mut state = pm_crypto::DigestState::new().map_err(|_| Failure::Unavailable)?;
    state.update(b"pm/custody-admission/v1");
    for part in parts {
        let length = u64::try_from(part.len()).map_err(|_| Failure::Unavailable)?;
        state.update(&length.to_be_bytes());
        state.update(part);
    }
    Ok(state.finish())
}

pub(crate) struct CustodyAdmission {
    bootstrap: PathBuf,
    audit: PathBuf,
    bootstrap_hash: [u8; 32],
    audit_hash: [u8; 32],
    read_bootstrap: Fingerprint,
    read_audit: Fingerprint,
}

impl CustodyAdmission {
    pub(crate) fn load(
        bootstrap: &Path,
        audit: &Path,
        read_bootstrap: Fingerprint,
        read_audit: Fingerprint,
    ) -> Result<Self, Failure> {
        Ok(Self {
            bootstrap: bootstrap.to_owned(),
            audit: audit.to_owned(),
            bootstrap_hash: read_bootstrap(bootstrap)?,
            audit_hash: read_audit(audit)?,
            read_bootstrap,
            read_audit,
        })
    }

    pub(crate) fn verify(&self) -> Result<(), Failure> {
        if (self.read_bootstrap)(&self.bootstrap)? != self.bootstrap_hash
            || (self.read_audit)(&self.audit)? != self.audit_hash
        {
            return Err(Failure::Unavailable);
        }
        Ok(())
    }
}
