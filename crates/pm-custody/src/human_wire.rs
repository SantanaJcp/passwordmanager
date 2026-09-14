// SPDX-License-Identifier: AGPL-3.0-only

//! Platform-neutral human wire operations shared by every native custodian.

use pm_vault::{AuditAction, HumanVault, ItemLifecycle, RecordKind};

use crate::Failure;

/// Handles the shared catalog operations, or returns `None` for an opcode
/// owned by another shared human-wire slice.
pub(crate) fn handle_catalog(
    vault: &mut HumanVault,
    opcode: u8,
    request: &[u8],
) -> Option<Result<Vec<u8>, Failure>> {
    if !matches!(opcode, 46 | 49) {
        return None;
    }
    Some((|| {
        if !request.is_empty() {
            return Err(Failure::Unavailable);
        }
        if opcode == 46 {
            vault
                .record_human_interaction(AuditAction::HumanUnlock, None)
                .map_err(|_| Failure::Unavailable)?;
        }
        encode_catalog(vault)
    })())
}

fn encode_catalog(vault: &HumanVault) -> Result<Vec<u8>, Failure> {
    let catalog = vault.human_catalog().map_err(|_| Failure::Unavailable)?;
    let mut response = vec![0];
    response.extend_from_slice(
        &u16::try_from(catalog.len())
            .map_err(|_| Failure::Unavailable)?
            .to_be_bytes(),
    );
    for entry in catalog {
        response.extend_from_slice(entry.item_id());
        response.push(match entry.kind() {
            RecordKind::Password => 1,
            RecordKind::Totp => 2,
            RecordKind::Passkey => 3,
            RecordKind::Ssh => 4,
            RecordKind::Token => 5,
            RecordKind::Note => 6,
            RecordKind::File => 7,
        });
        response.push(match entry.lifecycle() {
            ItemLifecycle::Active => 1,
            ItemLifecycle::Trash => 2,
            ItemLifecycle::Purged => return Err(Failure::Unavailable),
        });
        response.push(u8::from(entry.favorite()));
        push_bytes(&mut response, entry.title().as_bytes())?;
        response.extend_from_slice(
            &u16::try_from(entry.tags().len())
                .map_err(|_| Failure::Unavailable)?
                .to_be_bytes(),
        );
        for tag in entry.tags() {
            push_bytes(&mut response, tag.as_bytes())?;
        }
    }
    Ok(response)
}

fn push_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), Failure> {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| Failure::Unavailable)?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}
