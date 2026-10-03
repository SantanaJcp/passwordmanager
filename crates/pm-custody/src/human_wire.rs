// SPDX-License-Identifier: AGPL-3.0-only

//! Platform-neutral human wire operations shared by every native custodian.

use std::{
    io::{Read, Write},
    sync::Arc,
};

use pm_crypto::{KdfProfile, ProtectedBytes, RecoveryCode};
use pm_vault::{
    AgentEnrollment, AttachmentReader, AttemptState, AttemptVault, AuditAction, AuthRecord,
    AuthorizationReason, CsvDelimiter, CsvEncoding, CsvField, CsvImportDecision, CsvImportProfile,
    CsvMapping, CsvRowStatus, DelegatedVault, Destination, GeneratorConfig, HumanCommitError,
    HumanMetadata, HumanVault, HumanVerification, LogicalRecord, LogicalValue, PasskeyOperation,
    PasskeyProvider, PasswordRecord, PreparedHumanCommand, PrivateKeyFormat, RecordKind,
    SearchQuery, SourceEncoding, TotpAlgorithm,
};
use zeroize::Zeroizing;

use crate::Failure;
#[cfg(unix)]
use crate::linux::Ticket26DiagnosticError;
// Diagnostic phases remain on the native Unix boundary; they do not change
// operation results or introduce another request handler on Windows.
macro_rules! ticket26_diagnostic_error {
    ($phase:ident) => {
        #[cfg(unix)]
        crate::linux::ticket26_diagnostic_error(crate::linux::Ticket26DiagnosticError::$phase);
    };
}

const SPKI_BYTES: usize = 44;
const MAX_HUMAN_FRAME: usize = 18 * 1024 * 1024;
const STREAM_CHUNK_BYTES: usize = 1024 * 1024;
const LAB_AGENT_A: [u8; 16] = [0xa1; 16];
const LAB_AGENT_B: [u8; 16] = [0xb2; 16];

/// Handles the shared catalog and exposure operations, or returns `None` for an opcode
/// owned by another shared human-wire slice.
#[allow(clippy::too_many_lines)]
pub(crate) fn handle_request_slice(
    vault: &mut HumanVault,
    path: &std::path::Path,
    device: [u8; 16],
    audit_custody: &std::sync::Arc<pm_vault::AuditDeviceCustody>,
    opcode: u8,
    request: &[u8],
) -> Option<Result<HumanResponse, Failure>> {
    if !matches!(opcode, 2..=13 | 15..=16 | 19..=30 | 33 | 35..=37 | 40..=41 | 43 | 45..=46 | 49..=61 | 64..=65)
    {
        return None;
    }
    let rest = request;
    Some((|| match opcode {
        2 | 3 => {
            let mut cursor = Cursor::new(rest);
            let item = if opcode == 3 {
                Some(
                    cursor
                        .fixed(16)?
                        .try_into()
                        .map_err(|_| Failure::Unavailable)?,
                )
            } else {
                None
            };
            let record = decode_wire_record(&mut cursor)?;
            cursor.finish()?;
            let prepared = if let Some(item) = item {
                vault.prepare_edit(item, &record)
            } else {
                vault.prepare_create(&record)
            }
            .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared).map(HumanResponse::Protected)
        }
        43 => {
            let mut cursor = Cursor::new(rest);
            let password = cursor.bytes()?;
            cursor.finish()?;
            let prepared = vault
                .prepare_master_password_rotation(password, KdfProfile::DEFAULT)
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared).map(HumanResponse::Protected)
        }
        4 => {
            let item = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_delete(item)
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared).map(HumanResponse::Protected)
        }
        5 | 8 => {
            let mut cursor = Cursor::new(rest);
            let command = cursor.bytes()?;
            let signature = cursor
                .fixed(64)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            let body = cursor.bytes()?;
            cursor.finish()?;
            match vault.commit(command, &signature, body) {
                Ok(receipt) => {
                    let mut response = vec![0];
                    response.extend_from_slice(&receipt.to_bytes());
                    Ok(HumanResponse::Public(response))
                }
                Err(HumanCommitError::BodyChanged) => Ok(HumanResponse::Public(vec![2])),
                Err(_) => Ok(HumanResponse::Public(vec![1])),
            }
        }
        6 => {
            let item = rest.try_into().map_err(|_| Failure::Unavailable)?;
            match vault.read_password(item) {
                Ok(record) => protected_fields_response(&[
                    record.title().as_bytes(),
                    record.username().as_bytes(),
                    record.password(),
                    record.destination().as_bytes(),
                    record.notes().as_bytes(),
                ]),
                Err(HumanCommitError::ItemNotFound) => Ok(HumanResponse::Public(vec![3])),
                Err(_) => Ok(HumanResponse::Public(vec![1])),
            }
        }
        7 => {
            let transaction_id = rest.try_into().map_err(|_| Failure::Unavailable)?;
            match vault.receipt(transaction_id) {
                Ok(receipt) => {
                    let mut response = vec![0];
                    response.extend_from_slice(&receipt.to_bytes());
                    Ok(HumanResponse::Public(response))
                }
                Err(_) => Ok(HumanResponse::Public(vec![3])),
            }
        }
        9 => {
            let mut cursor = Cursor::new(rest);
            let bytes = cursor.bytes()?;
            cursor.finish()?;
            let record = LogicalRecord::from_bytes(bytes).map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_create_record(&record)
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared).map(HumanResponse::Protected)
        }
        10 => {
            let item = rest.try_into().map_err(|_| Failure::Unavailable)?;
            match vault.read_record(item) {
                Ok(record) => {
                    let encoded = record.to_bytes().map_err(|_| Failure::Unavailable)?;
                    protected_payload_response(&encoded)
                }
                Err(HumanCommitError::ItemNotFound) => Ok(HumanResponse::Public(vec![3])),
                Err(_) => Ok(HumanResponse::Public(vec![1])),
            }
        }
        11 => {
            let mut cursor = Cursor::new(rest);
            let item = cursor
                .fixed(16)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            let favorite = match cursor.fixed(1)? {
                [0] => false,
                [1] => true,
                _ => return Err(Failure::Unavailable),
            };
            let count = usize::from(u16::from_be_bytes(
                cursor
                    .fixed(2)?
                    .try_into()
                    .map_err(|_| Failure::Unavailable)?,
            ));
            let mut tags = Vec::with_capacity(count);
            for _ in 0..count {
                tags.push(cursor.public_string()?);
            }
            cursor.finish()?;
            let prepared = vault
                .prepare_organize(item, tags, favorite)
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared).map(HumanResponse::Protected)
        }
        12 => {
            let mut cursor = Cursor::new(rest);
            let text = cursor.public_string()?;
            let tag = cursor.public_string()?;
            let favorite = match cursor.fixed(1)? {
                [0] => None,
                [1] => Some(false),
                [2] => Some(true),
                _ => return Err(Failure::Unavailable),
            };
            cursor.finish()?;
            let hits = vault
                .search(&SearchQuery {
                    text: (!text.is_empty()).then_some(text),
                    tag: (!tag.is_empty()).then_some(tag),
                    favorite,
                })
                .map_err(|_| Failure::Unavailable)?;
            let mut response = vec![0];
            response.extend_from_slice(
                &u16::try_from(hits.len())
                    .map_err(|_| Failure::Unavailable)?
                    .to_be_bytes(),
            );
            for hit in hits {
                response.extend_from_slice(hit.item_id());
            }
            Ok(HumanResponse::Public(response))
        }
        13 => {
            let mut cursor = Cursor::new(rest);
            let length = usize::from(u16::from_be_bytes(
                cursor
                    .fixed(2)?
                    .try_into()
                    .map_err(|_| Failure::Unavailable)?,
            ));
            let flags = *cursor.fixed(1)?.first().ok_or(Failure::Unavailable)?;
            cursor.finish()?;
            if flags & !0b1111 != 0 {
                return Err(Failure::Unavailable);
            }
            let generated = vault
                .generate_password(&GeneratorConfig {
                    length,
                    lowercase: flags & 1 != 0,
                    uppercase: flags & 2 != 0,
                    digits: flags & 4 != 0,
                    symbols: flags & 8 != 0,
                })
                .map_err(|_| Failure::Unavailable)?;
            protected_payload_response(generated.expose())
        }
        15 => {
            let mut cursor = Cursor::new(rest);
            let generation = cursor.u64()?;
            let from_seq = cursor.u64()?;
            let limit = usize::try_from(cursor.u32()?).map_err(|_| Failure::Unavailable)?;
            cursor.finish()?;
            let query = vault
                .query_audit(device, generation, from_seq, limit)
                .map_err(|_| Failure::Unavailable)?;
            let mut response = vec![0];
            response.extend_from_slice(
                &u64::try_from(query.records().len())
                    .map_err(|_| Failure::Unavailable)?
                    .to_be_bytes(),
            );
            response.extend_from_slice(
                &u64::try_from(query.discontinuities().len())
                    .map_err(|_| Failure::Unavailable)?
                    .to_be_bytes(),
            );
            response.extend_from_slice(
                &u64::try_from(query.segment_count())
                    .map_err(|_| Failure::Unavailable)?
                    .to_be_bytes(),
            );
            Ok(HumanResponse::Public(response))
        }
        60 => {
            let pin: [u8; 44] = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let protected = ProtectedBytes::new(
                vault
                    .create_sync_pairing(pin)
                    .map_err(|_| Failure::Unavailable)?
                    .to_protected_bytes(),
            )
            .map_err(|_| Failure::Unavailable)?;
            protected_field_response(&protected)
        }
        61 => {
            let item = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let record = vault.read_record(item).map_err(|_| Failure::Unavailable)?;
            let mut response = vec![0];
            response.extend_from_slice(
                &u16::try_from(record.attachments().len())
                    .map_err(|_| Failure::Unavailable)?
                    .to_be_bytes(),
            );
            for attachment in record.attachments() {
                response.extend_from_slice(attachment.id());
                push_bytes(&mut response, attachment.name().as_bytes())?;
                response.extend_from_slice(&attachment.size().to_be_bytes());
            }
            Ok(HumanResponse::Public(response))
        }
        64 => {
            let device: [u8; 16] = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_device_retirement(device)
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared).map(HumanResponse::Protected)
        }
        65 => {
            if !rest.is_empty() {
                return Err(Failure::Unavailable);
            }
            Ok(HumanResponse::Public(vec![0]))
        }
        16 => {
            let mut cursor = Cursor::new(rest);
            let generation = cursor.u64()?;
            let through_seq = cursor.u64()?;
            cursor.finish()?;
            let purge = vault
                .prepare_audit_purge(device, generation, through_seq)
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, purge.prepared()).map(HumanResponse::Protected)
        }
        19 => {
            if rest.len() != SPKI_BYTES * 2 {
                ticket26_diagnostic_error!(ServerHumanSetupInput);
                return Err(Failure::Unavailable);
            }
            authorization_setup(vault, &rest[..SPKI_BYTES], &rest[SPKI_BYTES..])?;
            Ok(HumanResponse::Public(vec![0]))
        }
        20 => {
            if !rest.is_empty() {
                return Err(Failure::Unavailable);
            }
            authorization_suspend(vault)?;
            Ok(HumanResponse::Public(vec![0]))
        }
        21 => {
            if !rest.is_empty() {
                return Err(Failure::Unavailable);
            }
            authorization_resume_revoke(vault)?;
            Ok(HumanResponse::Public(vec![0]))
        }
        22 => {
            if rest.len() != SPKI_BYTES {
                return Err(Failure::Unavailable);
            }
            authorization_reenroll(vault, rest)?;
            Ok(HumanResponse::Public(vec![0]))
        }
        23 => {
            let mut cursor = Cursor::new(rest);
            let format = *cursor.fixed(1)?.first().ok_or(Failure::Unavailable)?;
            let replace_candidates = match cursor.fixed(1)? {
                [0] => false,
                [1] => true,
                _ => return Err(Failure::Unavailable),
            };
            let source = cursor.bytes()?;
            cursor.finish()?;
            let profile = match format {
                0 => CsvImportProfile::chrome(),
                1 => CsvImportProfile::apple(
                    CsvMapping::new(
                        CsvDelimiter::Comma,
                        CsvEncoding::Utf8,
                        true,
                        RecordKind::Password,
                        vec![
                            (0, CsvField::Title),
                            (1, CsvField::Destination),
                            (2, CsvField::Username),
                            (3, CsvField::Password),
                            (4, CsvField::Notes),
                            (5, CsvField::OtpAuth),
                        ],
                    )
                    .map_err(|_| Failure::Unavailable)?,
                ),
                2 => CsvImportProfile::mappable(
                    CsvMapping::new(
                        CsvDelimiter::Semicolon,
                        CsvEncoding::Utf8,
                        true,
                        RecordKind::Password,
                        vec![
                            (0, CsvField::Title),
                            (2, CsvField::Destination),
                            (1, CsvField::Username),
                            (3, CsvField::Password),
                        ],
                    )
                    .map_err(|_| Failure::Unavailable)?,
                ),
                _ => return Err(Failure::Unavailable),
            };
            let preview = vault
                .preview_csv(source, &profile)
                .map_err(|_| Failure::Unavailable)?;
            let mut decisions = Vec::with_capacity(preview.total());
            let mut offset = 0;
            while offset < preview.total() {
                let page = preview
                    .page(offset, 100)
                    .map_err(|_| Failure::Unavailable)?;
                for row in page {
                    decisions.push(match row.status() {
                        CsvRowStatus::New => CsvImportDecision::ImportNew,
                        CsvRowStatus::ExactDuplicate => CsvImportDecision::SkipExact,
                        CsvRowStatus::CandidateDuplicate if replace_candidates => {
                            CsvImportDecision::Replace(
                                *row.duplicate_item().ok_or(Failure::Unavailable)?,
                            )
                        }
                        CsvRowStatus::CandidateDuplicate => CsvImportDecision::KeepBoth,
                    });
                }
                offset += page.len();
            }
            let prepared = vault
                .prepare_csv_import(preview, decisions)
                .map_err(|_| Failure::Unavailable)?;
            let signature = vault
                .sign(prepared.prepared())
                .map_err(|_| Failure::Unavailable)?;
            let report = prepared.report();
            let item_count =
                u32::try_from(prepared.item_ids().len()).map_err(|_| Failure::Unavailable)?;
            let command_len = encoded_bytes_len(prepared.prepared().command())?;
            let body_len = encoded_bytes_len(prepared.prepared().body())?;
            let encoded_len = 1_usize
                .checked_add(7 * 8 + 4 + 16 + 16 + 64)
                .and_then(|value| value.checked_add(prepared.item_ids().len().checked_mul(16)?))
                .and_then(|value| value.checked_add(command_len))
                .and_then(|value| value.checked_add(body_len))
                .ok_or(Failure::Unavailable)?;
            let mut response = ProtectedFrameWriter::new(encoded_len)?;
            response.fixed(&[0])?;
            for value in [
                report.total(),
                report.new_items(),
                report.replaced(),
                report.skipped_exact(),
                report.excluded(),
                report.preserved_fields(),
                report.event_pages(),
            ] {
                response.fixed(
                    &u64::try_from(value)
                        .map_err(|_| Failure::Unavailable)?
                        .to_be_bytes(),
                )?;
            }
            response.fixed(&item_count.to_be_bytes())?;
            for item in prepared.item_ids() {
                response.fixed(item)?;
            }
            response.fixed(prepared.prepared().transaction_id())?;
            response.fixed(prepared.prepared().item_id())?;
            response.bytes(prepared.prepared().command())?;
            response.bytes(prepared.prepared().body())?;
            response.fixed(&signature)?;
            response.finish_exact().map(HumanResponse::Protected)
        }
        24 => {
            let item = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_enable(item)
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared).map(HumanResponse::Protected)
        }
        35 | 36 => {
            let mut cursor = Cursor::new(rest);
            let request_id = cursor
                .fixed(16)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            let verification = match cursor.fixed(1)? {
                [1] => HumanVerification::Presence,
                [2] => HumanVerification::Verified,
                _ => return Err(Failure::Unavailable),
            };
            cursor.finish()?;
            let provider = passkey_provider(path, device, audit_custody)?;
            let status = if opcode == 35 {
                let request = provider
                    .pending_request(request_id)
                    .map_err(|_| Failure::Unavailable)?
                    .filter(|value| value.operation() == PasskeyOperation::Create)
                    .ok_or(Failure::Unavailable)?;
                let registration = vault
                    .prepare_passkey_registration(&request)
                    .map_err(|_| Failure::Unavailable)?;
                commit_authority(vault, registration.prepared())?;
                provider
                    .response(request_id)
                    .map_err(|_| Failure::Unavailable)?
                    .ok_or(Failure::Unavailable)?
            } else {
                provider
                    .confirm_assertion(vault, request_id, verification)
                    .map_err(|_| Failure::Unavailable)?
            };
            let mut response = vec![0];
            push_bytes(&mut response, &status.to_bytes())?;
            Ok(HumanResponse::Public(response))
        }
        37 => {
            let request_id = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let provider = passkey_provider(path, device, audit_custody)?;
            let item = provider
                .registered_item(request_id)
                .map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_enable(item)
                .map_err(|_| Failure::Unavailable)?;
            commit_authority(vault, &prepared)?;
            Ok(HumanResponse::Public(vec![0]))
        }
        25 => {
            let item = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let history = vault.history(item).map_err(|_| Failure::Unavailable)?;
            let mut response = vec![
                0,
                match history.lifecycle() {
                    pm_vault::ItemLifecycle::Active => 1,
                    pm_vault::ItemLifecycle::Trash => 2,
                    pm_vault::ItemLifecycle::Purged => return Err(Failure::Unavailable),
                },
            ];
            response.extend_from_slice(
                &u16::try_from(history.entries().len())
                    .map_err(|_| Failure::Unavailable)?
                    .to_be_bytes(),
            );
            for entry in history.entries() {
                response.extend_from_slice(entry.revision_id());
                response.extend_from_slice(&entry.modified_at_us().to_be_bytes());
                response.extend_from_slice(entry.issuer_device());
                response.push(u8::from(entry.visible()));
                response.extend_from_slice(
                    &u32::try_from(entry.attachment_count())
                        .map_err(|_| Failure::Unavailable)?
                        .to_be_bytes(),
                );
            }
            Ok(HumanResponse::Public(response))
        }
        26 => {
            if rest.len() != 32 {
                return Err(Failure::Unavailable);
            }
            let item = rest[..16].try_into().map_err(|_| Failure::Unavailable)?;
            let revision = rest[16..].try_into().map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_restore(item, revision)
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared).map(HumanResponse::Protected)
        }
        27 => {
            let mut cursor = Cursor::new(rest);
            let item = cursor
                .fixed(16)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            let count = usize::from(u16::from_be_bytes(
                cursor
                    .fixed(2)?
                    .try_into()
                    .map_err(|_| Failure::Unavailable)?,
            ));
            let mut revisions = Vec::with_capacity(count);
            for _ in 0..count {
                revisions.push(
                    cursor
                        .fixed(16)?
                        .try_into()
                        .map_err(|_| Failure::Unavailable)?,
                );
            }
            cursor.finish()?;
            let purge = vault
                .prepare_purge_revisions(item, revisions)
                .map_err(|_| Failure::Unavailable)?;
            encode_purge_prepared(vault, &purge).map(HumanResponse::Protected)
        }
        28 => {
            let item = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let purge = vault
                .prepare_purge_item(item)
                .map_err(|_| Failure::Unavailable)?;
            encode_purge_prepared(vault, &purge).map(HumanResponse::Protected)
        }
        29 => {
            let mut cursor = Cursor::new(rest);
            let item = cursor
                .fixed(16)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            let record =
                LogicalRecord::from_bytes(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
            cursor.finish()?;
            let prepared = vault
                .prepare_edit_record(item, &record)
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared).map(HumanResponse::Protected)
        }
        30 => {
            if rest.len() != 32 {
                return Err(Failure::Unavailable);
            }
            let item = rest[..16].try_into().map_err(|_| Failure::Unavailable)?;
            let revision = rest[16..].try_into().map_err(|_| Failure::Unavailable)?;
            let record = vault
                .read_revision(item, revision)
                .map_err(|_| Failure::Unavailable)?;
            let encoded = record.to_bytes().map_err(|_| Failure::Unavailable)?;
            protected_payload_response(&encoded)
        }
        33 => {
            if rest != [0] {
                return Err(Failure::Unavailable);
            }
            let prepared = vault
                .prepare_plaintext_export()
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared).map(HumanResponse::Protected)
        }
        40 => {
            if !rest.is_empty() {
                return Err(Failure::Unavailable);
            }
            authorization_add_keycloak(vault)?;
            Ok(HumanResponse::Public(vec![0]))
        }
        41 => {
            let mut cursor = Cursor::new(rest);
            let subject_token = cursor.bytes()?;
            let requester_secret = cursor.bytes()?;
            cursor.finish()?;
            authorization_add_keycloak_exchange(vault, subject_token, requester_secret)?;
            Ok(HumanResponse::Public(vec![0]))
        }
        45 => {
            let mut cursor = Cursor::new(rest);
            let ssh_private = cursor.bytes()?;
            let ssh_public = cursor.bytes()?;
            let account_password = cursor.bytes()?;
            cursor.finish()?;
            let ssh = LogicalRecord::new(
                RecordKind::Ssh,
                HumanMetadata {
                    title: "Synthetic SSH key".into(),
                    destinations: vec![Destination {
                        label: "SSH lab".into(),
                        value: "ssh-lab".into(),
                    }],
                    tags: vec!["synthetic".into()],
                    favorite: false,
                    notes: pm_crypto::ProtectedText::copy_from_str("")
                        .map_err(|_| Failure::Unavailable)?,
                    fields: Vec::new(),
                    source_fields: Vec::new(),
                },
                vec![AuthRecord::Ssh {
                    private_format: PrivateKeyFormat::OpenSsh,
                    private_key: pm_crypto::ProtectedBytes::copy_from_slice(ssh_private)
                        .map_err(|_| Failure::Unavailable)?,
                    public_key: ssh_public.to_vec(),
                    username: "pmssh".into(),
                    destination_refs: vec![0],
                    passphrase: None,
                }],
                Vec::new(),
            )
            .map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_create_record(&ssh)
                .map_err(|_| Failure::Unavailable)?;
            let key_item = *prepared.item_id();
            commit_authority(vault, &prepared)?;
            let enable = vault
                .prepare_enable(key_item)
                .map_err(|_| Failure::Unavailable)?;
            commit_authority(vault, &enable)?;
            let password = PasswordRecord::new(
                "Synthetic Linux system account",
                "pmssh",
                account_password,
                "ssh-lab",
                "",
            )
            .map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_create(&password)
                .map_err(|_| Failure::Unavailable)?;
            let password_item = *prepared.item_id();
            commit_authority(vault, &prepared)?;
            let enable = vault
                .prepare_enable(password_item)
                .map_err(|_| Failure::Unavailable)?;
            commit_authority(vault, &enable)?;
            let mut response = vec![0];
            response.extend_from_slice(&key_item);
            response.extend_from_slice(&password_item);
            Ok(HumanResponse::Public(response))
        }
        46 | 49 => {
            if !rest.is_empty() {
                return Err(Failure::Unavailable);
            }
            if opcode == 46 {
                vault
                    .record_human_interaction(AuditAction::HumanUnlock, None)
                    .map_err(|_| Failure::Unavailable)?;
            }
            encode_catalog(vault).map(HumanResponse::Public)
        }
        50 => {
            let mut cursor = Cursor::new(rest);
            let length = usize::from(u16::from_be_bytes(
                cursor
                    .fixed(2)?
                    .try_into()
                    .map_err(|_| Failure::Unavailable)?,
            ));
            let flags = cursor.fixed(1)?[0];
            cursor.finish()?;
            if flags & !0b1111 != 0 {
                return Err(Failure::Unavailable);
            }
            let generated = vault
                .generate_password(&GeneratorConfig {
                    length,
                    lowercase: flags & 1 != 0,
                    uppercase: flags & 2 != 0,
                    digits: flags & 4 != 0,
                    symbols: flags & 8 != 0,
                })
                .map_err(|_| Failure::Unavailable)?;
            vault
                .record_human_interaction(AuditAction::Reveal, None)
                .map_err(|_| Failure::Unavailable)?;
            protected_field_response(generated.expose())
        }
        51 => {
            let item = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let record = vault.read_record(item).map_err(|_| Failure::Unavailable)?;
            let fields = human_fields(&record)?;
            let mut response = vec![0];
            response.extend_from_slice(
                &u16::try_from(fields.len())
                    .map_err(|_| Failure::Unavailable)?
                    .to_be_bytes(),
            );
            for (label, value) in &fields {
                push_bytes(&mut response, label.as_bytes())?;
                response.extend_from_slice(
                    &u64::try_from(value.len())
                        .map_err(|_| Failure::Unavailable)?
                        .to_be_bytes(),
                );
            }
            Ok(HumanResponse::Public(response))
        }
        52 | 53 => {
            let mut cursor = Cursor::new(rest);
            let item = cursor
                .fixed(16)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            let index = usize::from(u16::from_be_bytes(
                cursor
                    .fixed(2)?
                    .try_into()
                    .map_err(|_| Failure::Unavailable)?,
            ));
            cursor.finish()?;
            let record = vault.read_record(item).map_err(|_| Failure::Unavailable)?;
            let fields = human_fields(&record)?;
            let (_, value) = fields.get(index).ok_or(Failure::Unavailable)?;
            vault
                .record_human_interaction(
                    if opcode == 52 {
                        AuditAction::Reveal
                    } else {
                        AuditAction::Copy
                    },
                    Some(item),
                )
                .map_err(|_| Failure::Unavailable)?;
            protected_field_response(value)
        }
        54 => {
            if !rest.is_empty() {
                return Err(Failure::Unavailable);
            }
            let overview = vault.access_overview().map_err(|_| Failure::Unavailable)?;
            let mut response = vec![0, u8::from(overview.suspended())];
            response.extend_from_slice(
                &u16::try_from(overview.agents().len())
                    .map_err(|_| Failure::Unavailable)?
                    .to_be_bytes(),
            );
            for agent in overview.agents() {
                response.extend_from_slice(agent.subject());
                response.extend_from_slice(&agent.generation().to_be_bytes());
                response.push(match agent.status() {
                    "active" => 1,
                    "revoked" => 2,
                    "superseded" => 3,
                    _ => return Err(Failure::Unavailable),
                });
                push_bytes(&mut response, agent.label().as_bytes())?;
                push_bytes(&mut response, agent.environment().as_bytes())?;
            }
            response.extend_from_slice(
                &u16::try_from(overview.credentials().len())
                    .map_err(|_| Failure::Unavailable)?
                    .to_be_bytes(),
            );
            for credential in overview.credentials() {
                response.extend_from_slice(credential.item());
                response.push(u8::from(credential.enabled()));
                push_bytes(&mut response, credential.title().as_bytes())?;
            }
            Ok(HumanResponse::Public(response))
        }
        55 => {
            let mut cursor = Cursor::new(rest);
            let subject = cursor
                .fixed(16)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            let request = cursor
                .fixed(16)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            let rpk = cursor.fixed(SPKI_BYTES)?;
            let label = cursor.public_string()?;
            let environment = cursor.public_string()?;
            cursor.finish()?;
            let enrollment = AgentEnrollment::new(subject, request, rpk, &label, &environment)
                .map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_agent_enrollment(&enrollment)
                .map_err(|_| Failure::Unavailable)?;
            commit_authority(vault, prepared.prepared())?;
            Ok(HumanResponse::Public(vec![0]))
        }
        56 => {
            let subject = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_agent_revocation(subject, AuthorizationReason::OwnerRequest)
                .map_err(|_| Failure::Unavailable)?;
            commit_authority(vault, &prepared)?;
            Ok(HumanResponse::Public(vec![0]))
        }
        57 => {
            let prepared = match rest {
                [0] => vault.prepare_delegated_resume(),
                [1] => vault.prepare_delegated_suspend(AuthorizationReason::OwnerRequest),
                _ => return Err(Failure::Unavailable),
            }
            .map_err(|_| Failure::Unavailable)?;
            commit_authority(vault, &prepared)?;
            Ok(HumanResponse::Public(vec![0]))
        }
        58 => {
            let mut cursor = Cursor::new(rest);
            let item = cursor
                .fixed(16)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            let enable = match cursor.fixed(1)? {
                [0] => false,
                [1] => true,
                _ => return Err(Failure::Unavailable),
            };
            cursor.finish()?;
            let prepared = if enable {
                vault.prepare_enable(item)
            } else {
                vault.prepare_disable(item)
            }
            .map_err(|_| Failure::Unavailable)?;
            commit_authority(vault, &prepared)?;
            Ok(HumanResponse::Public(vec![0]))
        }
        59 => handle_human_pending(vault, path, device, audit_custody, rest),
        _ => unreachable!("closed opcode set checked above"),
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
            pm_vault::ItemLifecycle::Active => 1,
            pm_vault::ItemLifecycle::Trash => 2,
            pm_vault::ItemLifecycle::Purged => return Err(Failure::Unavailable),
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

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}
#[allow(clippy::too_many_lines)]
fn human_fields(record: &LogicalRecord) -> Result<Vec<(String, ProtectedBytes)>, Failure> {
    let mut fields = Vec::new();
    macro_rules! push {
        ($label:expr, $value:expr $(,)?) => {{
            fields.push(($label, protected_copy($value)?));
        }};
    }
    let human = record.human();
    push!("title".into(), human.title.as_bytes());
    for (index, destination) in human.destinations.iter().enumerate() {
        push!(
            format!("destination[{index}].label"),
            destination.label.as_bytes(),
        );
        push!(
            format!("destination[{index}].value"),
            destination.value.as_bytes(),
        );
    }
    for (index, tag) in human.tags.iter().enumerate() {
        push!(format!("tag[{index}]"), tag.as_bytes());
    }
    push!(
        "favorite".into(),
        if human.favorite { b"true" } else { b"false" },
    );
    push!("notes".into(), human.notes.as_bytes());
    for (index, field) in human.fields.iter().enumerate() {
        push!(format!("custom[{index}].id"), hex(&field.id).as_bytes());
        push!(format!("custom[{index}].label"), field.label.as_bytes());
        match &field.value {
            LogicalValue::Text(value) => push!(format!("custom[{index}].text"), value.as_bytes()),
            LogicalValue::Bytes(value) => push!(format!("custom[{index}].bytes"), value),
        }
        push!(
            format!("custom[{index}].concealed"),
            if field.concealed { b"true" } else { b"false" },
        );
    }
    for (index, field) in human.source_fields.iter().enumerate() {
        push!(format!("source[{index}].path"), field.path.as_bytes());
        push!(
            format!("source[{index}].encoding"),
            match field.encoding {
                SourceEncoding::Utf8 => b"utf8",
                SourceEncoding::Json => b"json",
                SourceEncoding::Bytes => b"bytes",
            },
        );
        push!(format!("source[{index}].value"), &field.value);
    }
    for (index, auth) in record.auth().iter().enumerate() {
        match auth {
            AuthRecord::Password {
                username,
                password,
                destination_refs,
            } => {
                push!(format!("auth[{index}].username"), username.as_bytes());
                push!(format!("auth[{index}].password"), password);
                push!(
                    format!("auth[{index}].destination_refs"),
                    format!("{destination_refs:?}").as_bytes(),
                );
            }
            AuthRecord::Totp {
                secret,
                algorithm,
                digits,
                period,
                t0,
                issuer,
                account,
                destination_refs,
            } => {
                push!(format!("auth[{index}].secret"), secret);
                push!(
                    format!("auth[{index}].algorithm"),
                    format!("{algorithm:?}").as_bytes(),
                );
                push!(
                    format!("auth[{index}].digits"),
                    digits.to_string().as_bytes(),
                );
                push!(
                    format!("auth[{index}].period"),
                    period.to_string().as_bytes(),
                );
                push!(format!("auth[{index}].t0"), t0.to_string().as_bytes());
                push!(format!("auth[{index}].issuer"), issuer.as_bytes());
                push!(format!("auth[{index}].account"), account.as_bytes());
                push!(
                    format!("auth[{index}].destination_refs"),
                    format!("{destination_refs:?}").as_bytes(),
                );
            }
            AuthRecord::Passkey {
                rp_id,
                user_handle,
                credential_id,
                cose_alg,
                private_key,
                public_key,
                user_name,
                display_name,
                sign_count,
                backup_eligible,
                backup_state,
            } => {
                push!(format!("auth[{index}].rp_id"), rp_id.as_bytes());
                push!(format!("auth[{index}].user_handle"), user_handle);
                push!(format!("auth[{index}].credential_id"), credential_id);
                push!(
                    format!("auth[{index}].cose_alg"),
                    cose_alg.to_string().as_bytes(),
                );
                push!(format!("auth[{index}].private_key"), private_key);
                push!(format!("auth[{index}].public_key"), public_key);
                push!(format!("auth[{index}].user_name"), user_name.as_bytes());
                push!(
                    format!("auth[{index}].display_name"),
                    display_name.as_bytes(),
                );
                push!(
                    format!("auth[{index}].sign_count"),
                    sign_count.to_string().as_bytes(),
                );
                push!(
                    format!("auth[{index}].backup_eligible"),
                    if *backup_eligible { b"true" } else { b"false" },
                );
                push!(
                    format!("auth[{index}].backup_state"),
                    if *backup_state { b"true" } else { b"false" },
                );
            }
            AuthRecord::Ssh {
                private_format,
                private_key,
                public_key,
                username,
                destination_refs,
                passphrase,
            } => {
                push!(
                    format!("auth[{index}].private_format"),
                    format!("{private_format:?}").as_bytes(),
                );
                push!(format!("auth[{index}].private_key"), private_key);
                push!(format!("auth[{index}].public_key"), public_key);
                push!(format!("auth[{index}].username"), username.as_bytes());
                push!(
                    format!("auth[{index}].destination_refs"),
                    format!("{destination_refs:?}").as_bytes(),
                );
                if let Some(passphrase) = passphrase {
                    push!(format!("auth[{index}].passphrase"), passphrase);
                }
            }
            AuthRecord::Token {
                secret,
                provider,
                profile_id,
                destination_refs,
                expires_at,
            } => {
                push!(format!("auth[{index}].secret"), secret);
                push!(format!("auth[{index}].provider"), provider.as_bytes());
                push!(format!("auth[{index}].profile_id"), profile_id.as_bytes());
                push!(
                    format!("auth[{index}].destination_refs"),
                    format!("{destination_refs:?}").as_bytes(),
                );
                if let Some(expires_at) = expires_at {
                    push!(
                        format!("auth[{index}].expires_at"),
                        expires_at.to_string().as_bytes(),
                    );
                }
            }
            AuthRecord::TokenExchange {
                subject_token,
                requester_client_id,
                requester_client_secret,
                provider,
                profile_id,
                destination_refs,
                expires_at,
            } => {
                push!(format!("auth[{index}].subject_token"), subject_token);
                push!(
                    format!("auth[{index}].requester_client_id"),
                    requester_client_id.as_bytes(),
                );
                push!(
                    format!("auth[{index}].requester_client_secret"),
                    requester_client_secret,
                );
                push!(format!("auth[{index}].provider"), provider.as_bytes());
                push!(format!("auth[{index}].profile_id"), profile_id.as_bytes());
                push!(
                    format!("auth[{index}].destination_refs"),
                    format!("{destination_refs:?}").as_bytes(),
                );
                if let Some(expires_at) = expires_at {
                    push!(
                        format!("auth[{index}].expires_at"),
                        expires_at.to_string().as_bytes(),
                    );
                }
            }
        }
    }
    for (index, attachment) in record.attachments().iter().enumerate() {
        push!(
            format!("attachment[{index}].id"),
            hex(attachment.id()).as_bytes(),
        );
        push!(
            format!("attachment[{index}].name"),
            attachment.name().as_bytes(),
        );
        push!(
            format!("attachment[{index}].mime"),
            attachment.mime().as_bytes(),
        );
        push!(
            format!("attachment[{index}].size"),
            attachment.size().to_string().as_bytes(),
        );
        push!(
            format!("attachment[{index}].sha256"),
            hex(attachment.sha256()).as_bytes(),
        );
        push!(format!("attachment[{index}].content"), attachment.content());
    }
    Ok(fields)
}

pub(crate) fn encode_prepared(
    vault: &HumanVault,
    prepared: &PreparedHumanCommand,
) -> Result<ProtectedBytes, Failure> {
    let signature = vault.sign(prepared).map_err(|_| Failure::Unavailable)?;
    let command_len = encoded_bytes_len(prepared.command())?;
    let body_len = encoded_bytes_len(prepared.body())?;
    let encoded_len = 1_usize
        .checked_add(16 + 16 + 64)
        .and_then(|value| value.checked_add(command_len))
        .and_then(|value| value.checked_add(body_len))
        .ok_or(Failure::Unavailable)?;
    let mut response = ProtectedFrameWriter::new(encoded_len)?;
    response.fixed(&[0])?;
    response.fixed(prepared.transaction_id())?;
    response.fixed(prepared.item_id())?;
    response.bytes(prepared.command())?;
    response.bytes(prepared.body())?;
    response.fixed(&signature)?;
    response.finish_exact()
}

fn decode_wire_record(cursor: &mut Cursor<'_>) -> Result<PasswordRecord, Failure> {
    let title = cursor.bytes()?;
    let username = cursor.bytes()?;
    let password = cursor.bytes()?;
    let destination = cursor.bytes()?;
    let notes = cursor.bytes()?;
    let record = PasswordRecord::new(
        std::str::from_utf8(title).map_err(|_| Failure::Unavailable)?,
        std::str::from_utf8(username).map_err(|_| Failure::Unavailable)?,
        password,
        std::str::from_utf8(destination).map_err(|_| Failure::Unavailable)?,
        std::str::from_utf8(notes).map_err(|_| Failure::Unavailable)?,
    )
    .map_err(|_| Failure::Unavailable)?;
    Ok(record)
}

fn encode_purge_prepared(
    vault: &HumanVault,
    purge: &pm_vault::PreparedItemPurge,
) -> Result<ProtectedBytes, Failure> {
    let scope = purge.scope();
    let revision_count =
        u16::try_from(scope.revision_ids().len()).map_err(|_| Failure::Unavailable)?;
    let attachment_count =
        u32::try_from(scope.attachment_count()).map_err(|_| Failure::Unavailable)?;
    let prepared = encode_prepared(vault, purge.prepared())?;
    let encoded_len = 2_usize
        .checked_add(2 + 4 + 8)
        .and_then(|value| value.checked_add(scope.revision_ids().len().checked_mul(16)?))
        .and_then(|value| value.checked_add(prepared.len().checked_sub(1)?))
        .ok_or(Failure::Unavailable)?;
    let mut response = ProtectedFrameWriter::new(encoded_len)?;
    response.fixed(&[0, u8::from(scope.terminal())])?;
    response.fixed(&revision_count.to_be_bytes())?;
    response.fixed(&attachment_count.to_be_bytes())?;
    response.fixed(&scope.encrypted_bytes().to_be_bytes())?;
    for revision in scope.revision_ids() {
        response.fixed(revision)?;
    }
    response.fixed(&prepared[1..])?;
    response.finish_exact()
}

pub(crate) fn commit_authority(
    vault: &mut HumanVault,
    prepared: &PreparedHumanCommand,
) -> Result<(), Failure> {
    let signature = vault.sign(prepared).map_err(|_| Failure::Unavailable)?;
    let receipt = vault
        .commit(prepared.command(), &signature, prepared.body())
        .map_err(|_| Failure::Unavailable)?;
    if vault
        .receipt(*prepared.transaction_id())
        .map_err(|_| Failure::Unavailable)?
        != receipt
        || vault
            .commit(prepared.command(), &signature, prepared.body())
            .map_err(|_| Failure::Unavailable)?
            != receipt
    {
        return Err(Failure::Unavailable);
    }
    Ok(())
}

fn authorization_setup(vault: &mut HumanVault, first: &[u8], second: &[u8]) -> Result<(), Failure> {
    if first.len() != SPKI_BYTES || second.len() != SPKI_BYTES || first == second {
        ticket26_diagnostic_error!(ServerHumanSetupInput);
        return Err(Failure::Unavailable);
    }
    let record = PasswordRecord::new(
        "Synthetic TLS shared account",
        "ticket07-user",
        b"ticket07-secret-canary",
        "https://ticket07.invalid/login",
        "",
    )
    .map_err(|_| {
        ticket26_diagnostic_error!(ServerHumanSetupPasswordPrepare);
        Failure::Unavailable
    })?;
    let prepared = vault.prepare_create(&record).map_err(|_| {
        ticket26_diagnostic_error!(ServerHumanSetupPasswordPrepare);
        Failure::Unavailable
    })?;
    let item = *prepared.item_id();
    commit_authority(vault, &prepared).inspect_err(|_| {
        ticket26_diagnostic_error!(ServerHumanSetupPasswordCommit);
    })?;
    let note = LogicalRecord::new(
        RecordKind::Note,
        HumanMetadata {
            title: "Synthetic excluded note".to_owned(),
            destinations: vec![],
            tags: vec![],
            favorite: false,
            notes: pm_crypto::ProtectedText::copy_from_str("not authorized")
                .map_err(|_| Failure::Unavailable)?,
            fields: vec![],
            source_fields: vec![],
        },
        vec![],
        vec![],
    )
    .map_err(|_| {
        ticket26_diagnostic_error!(ServerHumanSetupNotePrepare);
        Failure::Unavailable
    })?;
    let prepared = vault.prepare_create_record(&note).map_err(|_| {
        ticket26_diagnostic_error!(ServerHumanSetupNotePrepare);
        Failure::Unavailable
    })?;
    commit_authority(vault, &prepared).inspect_err(|_| {
        ticket26_diagnostic_error!(ServerHumanSetupNoteCommit);
    })?;
    for (subject, request, rpk, label) in [
        (LAB_AGENT_A, [0x31; 16], first, "Synthetic agent A"),
        (LAB_AGENT_B, [0x32; 16], second, "Synthetic agent B"),
    ] {
        #[cfg(unix)]
        let (prepare_error, commit_error) = if subject == LAB_AGENT_A {
            (
                Ticket26DiagnosticError::ServerHumanSetupAgentAPrepare,
                Ticket26DiagnosticError::ServerHumanSetupAgentACommit,
            )
        } else {
            (
                Ticket26DiagnosticError::ServerHumanSetupAgentBPrepare,
                Ticket26DiagnosticError::ServerHumanSetupAgentBCommit,
            )
        };
        let enrollment = AgentEnrollment::new(subject, request, rpk, label, "ticket07-userns")
            .map_err(|_| {
                #[cfg(unix)]
                crate::linux::ticket26_diagnostic_error(prepare_error);
                Failure::Unavailable
            })?;
        let prepared = vault.prepare_agent_enrollment(&enrollment).map_err(|_| {
            #[cfg(unix)]
            crate::linux::ticket26_diagnostic_error(prepare_error);
            Failure::Unavailable
        })?;
        commit_authority(vault, prepared.prepared()).inspect_err(|_| {
            #[cfg(unix)]
            crate::linux::ticket26_diagnostic_error(commit_error);
        })?;
    }
    let prepared = vault.prepare_delegated_resume().map_err(|_| {
        ticket26_diagnostic_error!(ServerHumanSetupResumePrepare);
        Failure::Unavailable
    })?;
    commit_authority(vault, &prepared).inspect_err(|_| {
        ticket26_diagnostic_error!(ServerHumanSetupResumeCommit);
    })?;
    let prepared = vault.prepare_enable(item).map_err(|_| {
        ticket26_diagnostic_error!(ServerHumanSetupEnablePrepare);
        Failure::Unavailable
    })?;
    commit_authority(vault, &prepared).inspect_err(|_| {
        ticket26_diagnostic_error!(ServerHumanSetupEnableCommit);
    })
}

fn authorization_suspend(vault: &mut HumanVault) -> Result<(), Failure> {
    let prepared = vault
        .prepare_delegated_suspend(AuthorizationReason::OwnerRequest)
        .map_err(|_| Failure::Unavailable)?;
    commit_authority(vault, &prepared)
}

fn authorization_resume_revoke(vault: &mut HumanVault) -> Result<(), Failure> {
    let prepared = vault
        .prepare_delegated_resume()
        .map_err(|_| Failure::Unavailable)?;
    commit_authority(vault, &prepared)?;
    let prepared = vault
        .prepare_agent_revocation(LAB_AGENT_A, AuthorizationReason::OwnerRequest)
        .map_err(|_| Failure::Unavailable)?;
    commit_authority(vault, &prepared)
}

fn authorization_reenroll(vault: &mut HumanVault, rpk: &[u8]) -> Result<(), Failure> {
    let enrollment = AgentEnrollment::new(
        LAB_AGENT_A,
        [0x33; 16],
        rpk,
        "Synthetic agent A replacement",
        "ticket07-userns",
    )
    .map_err(|_| Failure::Unavailable)?;
    let prepared = vault
        .prepare_agent_enrollment(&enrollment)
        .map_err(|_| Failure::Unavailable)?;
    if prepared.generation() != 2 {
        return Err(Failure::Unavailable);
    }
    commit_authority(vault, prepared.prepared())
}

fn authorization_add_keycloak(vault: &mut HumanVault) -> Result<(), Failure> {
    let alice = LogicalRecord::new(
        RecordKind::Password,
        HumanMetadata {
            title: "Synthetic Keycloak P1 account".to_owned(),
            destinations: vec![Destination {
                label: "installed profile".to_owned(),
                value: "keycloak-lab".to_owned(),
            }],
            tags: vec![],
            favorite: false,
            notes: pm_crypto::ProtectedText::copy_from_str("").map_err(|_| Failure::Unavailable)?,
            fields: vec![],
            source_fields: vec![],
        },
        vec![
            AuthRecord::Password {
                username: "alice".to_owned(),
                password: pm_crypto::ProtectedBytes::copy_from_slice(b"ticket10-password-canary")
                    .map_err(|_| Failure::Unavailable)?,
                destination_refs: vec![0],
            },
            AuthRecord::Totp {
                secret: pm_crypto::ProtectedBytes::copy_from_slice(b"12345678901234567890")
                    .map_err(|_| Failure::Unavailable)?,
                algorithm: TotpAlgorithm::Sha1,
                digits: 6,
                period: 30,
                t0: 0,
                issuer: "pm".to_owned(),
                account: "alice".to_owned(),
                destination_refs: vec![0],
            },
        ],
        vec![],
    )
    .map_err(|_| Failure::Unavailable)?;
    create_and_enable(vault, &alice)?;
    let charlie = LogicalRecord::new(
        RecordKind::Password,
        HumanMetadata {
            title: "Synthetic Keycloak challenge account".to_owned(),
            destinations: vec![Destination {
                label: "installed profile".to_owned(),
                value: "keycloak-lab".to_owned(),
            }],
            tags: vec![],
            favorite: false,
            notes: pm_crypto::ProtectedText::copy_from_str("").map_err(|_| Failure::Unavailable)?,
            fields: vec![],
            source_fields: vec![],
        },
        vec![AuthRecord::Password {
            username: "charlie".to_owned(),
            password: pm_crypto::ProtectedBytes::copy_from_slice(b"ticket10-challenge-password")
                .map_err(|_| Failure::Unavailable)?,
            destination_refs: vec![0],
        }],
        vec![],
    )
    .map_err(|_| Failure::Unavailable)?;
    create_and_enable(vault, &charlie)
}

fn authorization_add_keycloak_exchange(
    vault: &mut HumanVault,
    subject_token: &[u8],
    requester_secret: &[u8],
) -> Result<(), Failure> {
    let record = LogicalRecord::new(
        RecordKind::Token,
        HumanMetadata {
            title: "Synthetic Keycloak P2 relationship".to_owned(),
            destinations: vec![Destination {
                label: "installed profile".to_owned(),
                value: "keycloak-exchange-lab".to_owned(),
            }],
            tags: vec![],
            favorite: false,
            notes: pm_crypto::ProtectedText::copy_from_str("").map_err(|_| Failure::Unavailable)?,
            fields: vec![],
            source_fields: vec![],
        },
        vec![AuthRecord::TokenExchange {
            subject_token: pm_crypto::ProtectedBytes::copy_from_slice(subject_token)
                .map_err(|_| Failure::Unavailable)?,
            requester_client_id: "pm-exchanger".to_owned(),
            requester_client_secret: pm_crypto::ProtectedBytes::copy_from_slice(requester_secret)
                .map_err(|_| Failure::Unavailable)?,
            provider: "keycloak".to_owned(),
            profile_id: "keycloak-exchange-lab".to_owned(),
            destination_refs: vec![0],
            expires_at: None,
        }],
        vec![],
    )
    .map_err(|_| Failure::Unavailable)?;
    create_and_enable(vault, &record)
}

fn create_and_enable(vault: &mut HumanVault, record: &LogicalRecord) -> Result<(), Failure> {
    let prepared = vault
        .prepare_create_record(record)
        .map_err(|_| Failure::Unavailable)?;
    let item = *prepared.item_id();
    commit_authority(vault, &prepared)?;
    let prepared = vault
        .prepare_enable(item)
        .map_err(|_| Failure::Unavailable)?;
    commit_authority(vault, &prepared)
}

#[allow(clippy::too_many_lines)]
fn handle_human_pending(
    vault: &mut HumanVault,
    path: &std::path::Path,
    device: [u8; 16],
    audit_custody: &std::sync::Arc<pm_vault::AuditDeviceCustody>,
    request: &[u8],
) -> Result<HumanResponse, Failure> {
    let (action, rest) = request.split_first().ok_or(Failure::Unavailable)?;
    let attempts = AttemptVault::open(
        DelegatedVault::open(path, device, Arc::clone(audit_custody))
            .map_err(|_| Failure::Unavailable)?,
    )
    .map_err(|_| Failure::Unavailable)?;
    match action {
        0 if rest.is_empty() => {
            let values = attempts
                .human_pending(vault)
                .map_err(|_| Failure::Unavailable)?;
            let provider = passkey_provider(path, device, audit_custody)?;
            let mut response = vec![0];
            response.extend_from_slice(
                &u16::try_from(values.len())
                    .map_err(|_| Failure::Unavailable)?
                    .to_be_bytes(),
            );
            for value in values {
                response.extend_from_slice(value.attempt_id());
                response.extend_from_slice(value.credential_id());
                response.extend_from_slice(value.owner_subject());
                response.extend_from_slice(&value.owner_generation().to_be_bytes());
                push_bytes(&mut response, value.agent_status().as_bytes())?;
                push_bytes(&mut response, value.title().as_bytes())?;
                push_bytes(&mut response, value.integration_id().as_bytes())?;
                push_bytes(&mut response, attempt_state_name(value.state()).as_bytes())?;
                push_bytes(&mut response, value.reason().unwrap_or("").as_bytes())?;
                response.extend_from_slice(&value.expires_at_us().to_be_bytes());
                let prompt = if value.state() == AttemptState::WaitingForHuman {
                    if let Some(id) = value.passkey_request() {
                        provider
                            .pending_prompt(*id)
                            .map_err(|_| Failure::Unavailable)?
                            .map(|prompt| (*id, prompt))
                    } else {
                        None
                    }
                } else {
                    None
                };
                response.push(u8::from(prompt.is_some()));
                if let Some((request_id, prompt)) = prompt {
                    response.extend_from_slice(&request_id);
                    response.push(match prompt.user_verification() {
                        pm_vault::UserVerificationRequirement::Required => 2,
                        pm_vault::UserVerificationRequirement::Preferred
                        | pm_vault::UserVerificationRequirement::Discouraged => 1,
                    });
                    for field in [
                        prompt.rp_id().as_bytes(),
                        prompt.account().as_bytes(),
                        prompt.origin().as_bytes(),
                        prompt.document_id().as_bytes(),
                    ] {
                        push_bytes(&mut response, field)?;
                    }
                }
            }
            Ok(HumanResponse::Public(response))
        }
        1 => {
            let attempt = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let snapshot = attempts
                .human_cancel(vault, attempt)
                .map_err(|_| Failure::Unavailable)?;
            let mut response = vec![0];
            push_bytes(
                &mut response,
                attempt_state_name(snapshot.state()).as_bytes(),
            )?;
            Ok(HumanResponse::Public(response))
        }
        2 => {
            let mut cursor = Cursor::new(rest);
            let request_id = cursor
                .fixed(16)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            let verification = match cursor.fixed(1)? {
                [1] => HumanVerification::Presence,
                [2] => HumanVerification::Verified,
                _ => return Err(Failure::Unavailable),
            };
            cursor.finish()?;
            let provider = passkey_provider(path, device, audit_custody)?;
            let pending = provider
                .pending_request(request_id)
                .map_err(|_| Failure::Unavailable)?
                .ok_or(Failure::Unavailable)?;
            if pending.operation() != PasskeyOperation::Get {
                return Err(Failure::Unavailable);
            }
            let status = provider
                .confirm_assertion(vault, request_id, verification)
                .map_err(|_| Failure::Unavailable)?;
            protected_field_response(&status.to_bytes())
        }
        _ => Err(Failure::Unavailable),
    }
}

pub(crate) fn passkey_provider(
    path: &std::path::Path,
    device: [u8; 16],
    audit_custody: &std::sync::Arc<pm_vault::AuditDeviceCustody>,
) -> Result<PasskeyProvider, Failure> {
    let delegated = DelegatedVault::open(path, device, std::sync::Arc::clone(audit_custody))
        .map_err(|_| Failure::Unavailable)?;
    let attempts = AttemptVault::open(delegated).map_err(|_| Failure::Unavailable)?;
    PasskeyProvider::open(attempts).map_err(|_| Failure::Unavailable)
}

fn attempt_state_name(state: pm_vault::AttemptState) -> &'static str {
    match state {
        pm_vault::AttemptState::Created => "CREATED",
        pm_vault::AttemptState::Running => "RUNNING",
        pm_vault::AttemptState::WaitingForHuman => "WAITING_FOR_HUMAN",
        pm_vault::AttemptState::Succeeded => "SUCCEEDED",
        pm_vault::AttemptState::Failed => "FAILED",
        pm_vault::AttemptState::Cancelled => "CANCELLED",
        pm_vault::AttemptState::Expired => "EXPIRED",
        pm_vault::AttemptState::Indeterminate => "INDETERMINATE",
    }
}

pub(crate) fn handle_stream_upload<S: Read + Write>(
    tls_vault: &mut HumanVault,
    tls: &mut S,
    request: &[u8],
) -> Result<(), Failure> {
    let mut cursor = Cursor::new(request);
    let bytes = cursor.bytes()?;
    cursor.finish()?;
    let record = LogicalRecord::from_descriptor_bytes(bytes).map_err(|_| Failure::Unavailable)?;
    if record.attachments().len() != 1 {
        return Err(Failure::Unavailable);
    }
    let id = *record.attachments()[0].id();
    let mut reader = FrameReader {
        tls,
        buffer: ProtectedBytes::zeroed(0).map_err(|_| Failure::Unavailable)?,
        position: 0,
        ended: false,
    };
    let mut sources = [AttachmentReader::new(id, &mut reader)];
    let prepared = tls_vault
        .prepare_create_record_streaming(&record, &mut sources)
        .map_err(|_| Failure::Unavailable)?;
    let response = encode_prepared(tls_vault, &prepared)?;
    write_frame(reader.tls, &response)
}
pub(crate) fn handle_stream_download<S: Read + Write>(
    vault: &HumanVault,
    tls: &mut S,
    request: &[u8],
) -> Result<(), Failure> {
    if request.len() != 32 {
        return Err(Failure::Unavailable);
    }
    let item = request[..16].try_into().map_err(|_| Failure::Unavailable)?;
    let attachment = request[16..].try_into().map_err(|_| Failure::Unavailable)?;
    write_frame(tls, &[0])?;
    let mut writer = FrameWriter { tls };
    vault
        .read_attachment_to(item, attachment, &mut writer)
        .map_err(|_| Failure::Unavailable)?;
    write_frame(writer.tls, &[0])
}

pub(crate) fn handle_native_backup_download<S: Read + Write>(
    vault: &mut HumanVault,
    tls: &mut S,
) -> Result<(), Failure> {
    write_frame(tls, &[0])?;
    let mut writer = FrameWriter { tls };
    vault
        .write_native_backup(&mut writer)
        .map_err(|_| Failure::Unavailable)?;
    write_frame(writer.tls, &[0])
}

pub(crate) fn handle_plaintext_backup_download<S: Read + Write>(
    vault: &mut HumanVault,
    tls: &mut S,
    request: &[u8],
) -> Result<(), Failure> {
    let mut cursor = Cursor::new(request);
    let command = cursor.bytes()?;
    let signature = cursor
        .fixed(64)?
        .try_into()
        .map_err(|_| Failure::Unavailable)?;
    let body = cursor.bytes()?;
    cursor.finish()?;
    write_frame(tls, &[0])?;
    let mut writer = FrameWriter { tls };
    vault
        .write_plaintext_export(command, &signature, body, &mut writer)
        .map_err(|_| Failure::Unavailable)?;
    write_frame(writer.tls, &[0])
}

pub(crate) fn handle_native_backup_restore<S: Read + Write>(
    vault: &mut HumanVault,
    tls: &mut S,
    request: &[u8],
) -> Result<(), Failure> {
    let mut cursor = Cursor::new(request);
    let password = cursor.bytes()?;
    cursor.finish()?;
    if password.len() > 1024 {
        return Err(Failure::Unavailable);
    }
    let mut reader = FrameReader {
        tls,
        buffer: ProtectedBytes::zeroed(0).map_err(|_| Failure::Unavailable)?,
        position: 0,
        ended: false,
    };
    let prepared = vault
        .prepare_native_restore(&mut reader, password)
        .map_err(|_| Failure::Unavailable)?;
    let response = encode_prepared(vault, prepared.prepared())?;
    write_frame(reader.tls, &response)
}

pub(crate) fn handle_native_recovery<S: Read + Write>(
    vault: &mut HumanVault,
    tls: &mut S,
    request: &[u8],
) -> Result<(), Failure> {
    let mut cursor = Cursor::new(request);
    let encoded = cursor.bytes()?;
    cursor.finish()?;
    let text = std::str::from_utf8(encoded).map_err(|_| Failure::Unavailable)?;
    let recovery: RecoveryCode = text.parse().map_err(|_| Failure::Unavailable)?;
    let mut reader = FrameReader {
        tls,
        buffer: ProtectedBytes::zeroed(0).map_err(|_| Failure::Unavailable)?,
        position: 0,
        ended: false,
    };
    let prepared = vault
        .prepare_native_recovery(&mut reader, &recovery)
        .map_err(|_| Failure::Unavailable)?;
    let response = encode_prepared(vault, prepared.prepared())?;
    write_frame(reader.tls, &response)
}

pub(crate) fn handle_recovery_rotation<S: Read + Write>(
    vault: &mut HumanVault,
    tls: &mut S,
    request: &[u8],
) -> Result<(), Failure> {
    if !request.is_empty() {
        return Err(Failure::Unavailable);
    }
    let pending = vault
        .begin_recovery_rotation()
        .map_err(|_| Failure::Unavailable)?;
    let code = Zeroizing::new(pending.recovery_code().to_string());
    let mut response = vec![0];
    push_bytes(&mut response, code.as_bytes())?;
    write_frame(tls, &response)?;
    let confirmation = read_frame_bounded(tls, 1024)?;
    if confirmation.is_empty() {
        write_frame(tls, &[2])?;
        return Ok(());
    }
    let parsed: RecoveryCode = std::str::from_utf8(&confirmation)
        .map_err(|_| Failure::Unavailable)?
        .parse()
        .map_err(|_| Failure::Unavailable)?;
    let prepared = pending
        .confirm(vault, &parsed)
        .map_err(|_| Failure::Unavailable)?;
    let response = encode_prepared(vault, &prepared)?;
    write_frame(tls, &response)
}
struct FrameReader<'a, S> {
    tls: &'a mut S,
    buffer: ProtectedBytes,
    position: usize,
    ended: bool,
}
impl<S: Read + Write> Read for FrameReader<'_, S> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if self.position == self.buffer.len() {
            if self.ended {
                return Ok(0);
            }
            self.buffer = read_frame_bounded(self.tls, STREAM_CHUNK_BYTES).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "stream frame unavailable",
                )
            })?;
            self.position = 0;
            if *self.buffer == [0] {
                self.ended = true;
                return Ok(0);
            }
        }
        let count = output.len().min(self.buffer.len() - self.position);
        output[..count].copy_from_slice(&self.buffer[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}

struct FrameWriter<'a, S> {
    tls: &'a mut S,
}
impl<S: std::io::Read + std::io::Write> std::io::Write for FrameWriter<'_, S> {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        write_frame(self.tls, input).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "stream frame failed")
        })?;
        Ok(input.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.tls.flush()
    }
}

#[cfg(windows)]
#[derive(Clone, Copy)]
pub(crate) enum OnePuxTransferStage {
    Preview,
    Preparation,
    Signature,
    FrameReady,
    FrameSent,
    FrameFailed,
}

#[cfg(windows)]
fn observe_1pux_result<T>(
    result: Result<T, pm_vault::HumanCommitError>,
    stage: OnePuxTransferStage,
    observe: &mut impl FnMut(
        OnePuxTransferStage,
        Option<&pm_vault::HumanCommitError>,
    ) -> Result<(), Failure>,
) -> Result<T, Failure> {
    let diagnostic = observe(stage, result.as_ref().err());
    match (result, diagnostic) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(_), Ok(())) => Err(Failure::Unavailable),
        (Ok(_), Err(error)) => Err(error),
        (Err(_), Err(error)) => Err(Failure::Unavailable.merge(error)),
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn handle_1pux_file<S: std::io::Read + std::io::Write>(
    vault: &mut HumanVault,
    tls: &mut S,
    request: &[u8],
    source: std::fs::File,
    #[cfg(windows)] mut observe: impl FnMut(
        OnePuxTransferStage,
        Option<&pm_vault::HumanCommitError>,
    ) -> Result<(), Failure>,
) -> Result<(), Failure> {
    let replace_candidates = match request {
        [0] => false,
        [1] => true,
        _ => return Err(Failure::Unavailable),
    };
    let preview = vault.preview_1pux_file(source);
    #[cfg(windows)]
    let preview = observe_1pux_result(preview, OnePuxTransferStage::Preview, &mut observe)?;
    #[cfg(not(windows))]
    let preview = preview.map_err(|_| Failure::Unavailable)?;
    let mut decisions = Vec::with_capacity(preview.total());
    let mut offset = 0;
    while offset < preview.total() {
        let page = preview
            .page(offset, 100)
            .map_err(|_| Failure::Unavailable)?;
        for row in page {
            decisions.push(match row.status() {
                CsvRowStatus::New => CsvImportDecision::ImportNew,
                CsvRowStatus::ExactDuplicate => CsvImportDecision::SkipExact,
                CsvRowStatus::CandidateDuplicate if replace_candidates => {
                    CsvImportDecision::Replace(*row.duplicate_item().ok_or(Failure::Unavailable)?)
                }
                CsvRowStatus::CandidateDuplicate => CsvImportDecision::KeepBoth,
            });
        }
        offset += page.len();
    }
    let prepared = vault.prepare_1pux_import(preview, decisions);
    #[cfg(windows)]
    let prepared = observe_1pux_result(prepared, OnePuxTransferStage::Preparation, &mut observe)?;
    #[cfg(not(windows))]
    let prepared = prepared.map_err(|_| Failure::Unavailable)?;
    let signature = vault.sign(prepared.prepared());
    #[cfg(windows)]
    let signature = observe_1pux_result(signature, OnePuxTransferStage::Signature, &mut observe)?;
    #[cfg(not(windows))]
    let signature = signature.map_err(|_| Failure::Unavailable)?;
    let report = prepared.report();
    let mut response = vec![0];
    for value in [
        report.total(),
        report.new_items(),
        report.replaced(),
        report.skipped_exact(),
        report.excluded(),
        report.preserved_fields(),
        report.event_pages(),
    ] {
        response.extend_from_slice(
            &u64::try_from(value)
                .map_err(|_| Failure::Unavailable)?
                .to_be_bytes(),
        );
    }
    response.extend_from_slice(
        &u32::try_from(prepared.item_ids().len())
            .map_err(|_| Failure::Unavailable)?
            .to_be_bytes(),
    );
    for item in prepared.item_ids() {
        response.extend_from_slice(item);
    }
    response.extend_from_slice(prepared.prepared().transaction_id());
    response.extend_from_slice(prepared.prepared().item_id());
    push_bytes(&mut response, prepared.prepared().command())?;
    push_bytes(&mut response, prepared.prepared().body())?;
    response.extend_from_slice(&signature);
    #[cfg(windows)]
    observe(OnePuxTransferStage::FrameReady, None)?;
    let sent = write_frame(tls, &response);
    #[cfg(windows)]
    {
        let diagnostic = observe(
            if sent.is_ok() {
                OnePuxTransferStage::FrameSent
            } else {
                OnePuxTransferStage::FrameFailed
            },
            None,
        );
        return match (sent, diagnostic) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(error), Err(diagnostic)) => Err(error.merge(diagnostic)),
        };
    }
    #[cfg(not(windows))]
    sent
}

pub(crate) enum HumanResponse {
    Public(Vec<u8>),
    Protected(ProtectedBytes),
}

pub(crate) struct ProtectedFrameWriter {
    output: ProtectedBytes,
    offset: usize,
}

pub(crate) struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

pub(crate) struct WirePrepared {
    pub(crate) transaction_id: [u8; 16],
    pub(crate) item_id: [u8; 16],
    pub(crate) command: ProtectedBytes,
    pub(crate) body: ProtectedBytes,
    pub(crate) signature: [u8; 64],
}

impl AsRef<[u8]> for HumanResponse {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Public(value) => value,
            Self::Protected(value) => value,
        }
    }
}

impl ProtectedFrameWriter {
    pub(crate) fn new(encoded_len: usize) -> Result<Self, Failure> {
        Ok(Self {
            output: ProtectedBytes::zeroed(encoded_len).map_err(|_| Failure::Unavailable)?,
            offset: 0,
        })
    }

    pub(crate) fn fixed(&mut self, value: &[u8]) -> Result<(), Failure> {
        let end = self
            .offset
            .checked_add(value.len())
            .ok_or(Failure::Unavailable)?;
        self.output
            .get_mut(self.offset..end)
            .ok_or(Failure::Unavailable)?
            .copy_from_slice(value);
        self.offset = end;
        Ok(())
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) -> Result<(), Failure> {
        self.fixed(
            &u32::try_from(value.len())
                .map_err(|_| Failure::Unavailable)?
                .to_be_bytes(),
        )?;
        self.fixed(value)
    }

    pub(crate) fn finish_exact(self) -> Result<ProtectedBytes, Failure> {
        if self.offset == self.output.len() {
            Ok(self.output)
        } else {
            Err(Failure::Unavailable)
        }
    }
}

impl<'a> Cursor<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(crate) fn expect(&mut self, expected: &[u8]) -> Result<(), Failure> {
        if self.fixed(expected.len())? == expected {
            Ok(())
        } else {
            Err(Failure::Unavailable)
        }
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Failure> {
        let bytes: [u8; 4] = self
            .fixed(4)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?;
        Ok(u32::from_be_bytes(bytes))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, Failure> {
        let bytes: [u8; 8] = self
            .fixed(8)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?;
        Ok(u64::from_be_bytes(bytes))
    }

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], Failure> {
        let length = usize::try_from(self.u32()?).map_err(|_| Failure::Unavailable)?;
        self.fixed(length)
    }

    /// Copies a protocol field that is explicitly classified as public text.
    pub(crate) fn public_string(&mut self) -> Result<String, Failure> {
        std::str::from_utf8(self.bytes()?)
            .map(str::to_owned)
            .map_err(|_| Failure::Unavailable)
    }

    pub(crate) fn fixed(&mut self, length: usize) -> Result<&'a [u8], Failure> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(Failure::Unavailable)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(Failure::Unavailable)?;
        self.offset = end;
        Ok(value)
    }

    pub(crate) fn finish(self) -> Result<(), Failure> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Failure::Unavailable)
        }
    }
}

pub(crate) fn encoded_bytes_len(value: &[u8]) -> Result<usize, Failure> {
    u32::try_from(value.len()).map_err(|_| Failure::Unavailable)?;
    4_usize.checked_add(value.len()).ok_or(Failure::Unavailable)
}

pub(crate) fn protected_copy(value: &[u8]) -> Result<ProtectedBytes, Failure> {
    ProtectedBytes::copy_from_slice(value).map_err(|_| Failure::Unavailable)
}

pub(crate) fn protected_payload_response(value: &[u8]) -> Result<HumanResponse, Failure> {
    let mut response = ProtectedFrameWriter::new(
        1_usize
            .checked_add(value.len())
            .ok_or(Failure::Unavailable)?,
    )?;
    response.fixed(&[0])?;
    response.fixed(value)?;
    response.finish_exact().map(HumanResponse::Protected)
}

pub(crate) fn protected_field_response(value: &[u8]) -> Result<HumanResponse, Failure> {
    let mut response = ProtectedFrameWriter::new(
        1_usize
            .checked_add(encoded_bytes_len(value)?)
            .ok_or(Failure::Unavailable)?,
    )?;
    response.fixed(&[0])?;
    response.bytes(value)?;
    response.finish_exact().map(HumanResponse::Protected)
}

pub(crate) fn protected_fields_response(values: &[&[u8]]) -> Result<HumanResponse, Failure> {
    let mut encoded_len = 1_usize;
    for value in values {
        encoded_len = encoded_len
            .checked_add(encoded_bytes_len(value)?)
            .ok_or(Failure::Unavailable)?;
    }
    let mut response = ProtectedFrameWriter::new(encoded_len)?;
    response.fixed(&[0])?;
    for value in values {
        response.bytes(value)?;
    }
    response.finish_exact().map(HumanResponse::Protected)
}

pub(crate) fn protected_fields_frame(
    prefix: &[u8],
    values: &[&[u8]],
) -> Result<ProtectedBytes, Failure> {
    let mut encoded_len = prefix.len();
    for value in values {
        encoded_len = encoded_len
            .checked_add(encoded_bytes_len(value)?)
            .ok_or(Failure::Unavailable)?;
    }
    let mut frame = ProtectedFrameWriter::new(encoded_len)?;
    frame.fixed(prefix)?;
    for value in values {
        frame.bytes(value)?;
    }
    frame.finish_exact()
}

pub(crate) fn write_frame(output: &mut impl Write, value: &[u8]) -> Result<(), Failure> {
    if value.len() > MAX_HUMAN_FRAME {
        return Err(Failure::Unavailable);
    }
    let length = u32::try_from(value.len()).map_err(|_| Failure::Unavailable)?;
    output
        .write_all(&length.to_be_bytes())
        .and_then(|()| output.write_all(value))
        .and_then(|()| output.flush())
        .map_err(|_| Failure::Unavailable)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameReadFailure {
    Timeout,
    Eof,
    OtherIo,
    MalformedFrame,
}

impl FrameReadFailure {
    fn from_io(error: &std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => Self::Timeout,
            std::io::ErrorKind::UnexpectedEof => Self::Eof,
            _ => Self::OtherIo,
        }
    }

    pub(crate) const fn public_failure(self) -> Failure {
        let _ = self;
        Failure::Unavailable
    }
}

pub(crate) fn read_frame(input: &mut impl Read) -> Result<ProtectedBytes, Failure> {
    read_frame_bounded(input, MAX_HUMAN_FRAME)
}

pub(crate) fn read_frame_bounded(
    input: &mut impl Read,
    maximum: usize,
) -> Result<ProtectedBytes, Failure> {
    read_frame_bounded_classified(input, maximum).map_err(FrameReadFailure::public_failure)
}

pub(crate) fn read_frame_bounded_classified(
    input: &mut impl Read,
    maximum: usize,
) -> Result<ProtectedBytes, FrameReadFailure> {
    let mut length = [0_u8; 4];
    input
        .read_exact(&mut length)
        .map_err(|error| FrameReadFailure::from_io(&error))?;
    let length = usize::try_from(u32::from_be_bytes(length))
        .map_err(|_| FrameReadFailure::MalformedFrame)?;
    if length == 0 || length > maximum {
        return Err(FrameReadFailure::MalformedFrame);
    }
    let mut value = ProtectedBytes::zeroed(length).map_err(|_| FrameReadFailure::OtherIo)?;
    input
        .read_exact(&mut value)
        .map_err(|error| FrameReadFailure::from_io(&error))?;
    Ok(value)
}

pub(crate) fn audit_device_initialized(
    vault_path: &std::path::Path,
    device: [u8; 16],
) -> Result<bool, Failure> {
    let connection = rusqlite::Connection::open_with_flags(
        vault_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|_| Failure::Unavailable)?;
    connection
        .execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;")
        .map_err(|_| Failure::Unavailable)?;
    let initialized: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM audit_keys WHERE device_id=?1)",
            [device.as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| Failure::Unavailable)?;
    Ok(initialized)
}

#[cfg(all(test, unix))]
mod protected_frame_tests {
    use super::*;
    use std::process::Command;

    const CHILD: &str = "PM28_PROTECTED_RESPONSE_CHILD";
    static CANARY: [u8; 512 * 1024] = [0x5a; 512 * 1024];

    #[test]
    fn sensitive_response_requires_locked_owner_before_serialization() {
        if std::env::var_os(CHILD).is_some() {
            let limit = libc::rlimit {
                rlim_cur: 128 * 1024,
                rlim_max: 128 * 1024,
            };
            // SAFETY: the child changes only its own process limit.
            assert_eq!(
                unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const limit) },
                0
            );
            let control = protected_field_response(b"PM28_SYNTHETIC_SMALL")
                .expect("small response under the same memlock pressure");
            assert_eq!(&control.as_ref()[5..], b"PM28_SYNTHETIC_SMALL");
            drop(control);
            println!("PM28_RESPONSE_CONTROL_READY");
            // Synthetic static fixture; no ordinary secret heap owner.
            assert!(
                matches!(protected_field_response(&CANARY), Err(Failure::Unavailable)),
                "unlocked response serialization was accepted"
            );
            println!("PM28_RESPONSE_LOCK_DENIED");
            return;
        }

        let output = Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg("human_wire::protected_frame_tests::sensitive_response_requires_locked_owner_before_serialization")
            .arg("--nocapture")
            .env(CHILD, "1")
            .output()
            .expect("isolated response child");
        assert!(
            output
                .stdout
                .windows(b"PM28_RESPONSE_CONTROL_READY".len())
                .any(|value| value == b"PM28_RESPONSE_CONTROL_READY"),
            "response control marker missing"
        );
        println!("PM28_RESPONSE_CONTROL_READY");
        assert!(
            output.status.success(),
            "unlocked response serialization was accepted after control"
        );
        assert!(
            output
                .stdout
                .windows(b"PM28_RESPONSE_LOCK_DENIED".len())
                .any(|value| value == b"PM28_RESPONSE_LOCK_DENIED"),
            "response denial marker missing"
        );
    }
}
