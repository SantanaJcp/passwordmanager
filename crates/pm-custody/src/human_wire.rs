// SPDX-License-Identifier: AGPL-3.0-only

//! Platform-neutral human wire operations shared by every native custodian.

use pm_crypto::KdfProfile;
use pm_vault::{
    AgentEnrollment, AuditAction, AuthRecord, AuthorizationReason, CsvDelimiter, CsvEncoding,
    CsvField, CsvImportDecision, CsvImportProfile, CsvMapping, CsvRowStatus, Destination,
    GeneratorConfig, HumanCommitError, HumanMetadata, HumanVault, ItemLifecycle, LogicalRecord,
    LogicalValue, PasswordRecord, PreparedHumanCommand, PrivateKeyFormat, RecordKind, SearchQuery,
    SourceEncoding, TotpAlgorithm,
};
use zeroize::{Zeroize, Zeroizing};

use crate::Failure;

const SPKI_BYTES: usize = 44;
const LAB_AGENT_A: [u8; 16] = [0xa1; 16];
const LAB_AGENT_B: [u8; 16] = [0xb2; 16];

/// Handles the shared catalog and exposure operations, or returns `None` for an opcode
/// owned by another shared human-wire slice.
pub(crate) fn handle_request_slice(
    vault: &mut HumanVault,
    device: [u8; 16],
    opcode: u8,
    request: &[u8],
) -> Option<Result<Vec<u8>, Failure>> {
    if !matches!(opcode, 2..=13 | 15..=16 | 19..=30 | 33 | 40..=41 | 43 | 45..=46 | 49..=58) {
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
            encode_prepared(vault, &prepared)
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
            Ok(response)
        }
        16 => {
            let mut cursor = Cursor::new(rest);
            let generation = cursor.u64()?;
            let through_seq = cursor.u64()?;
            cursor.finish()?;
            let purge = vault
                .prepare_audit_purge(device, generation, through_seq)
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, purge.prepared())
        }
        19 => {
            if rest.len() != SPKI_BYTES * 2 {
                return Err(Failure::Unavailable);
            }
            authorization_setup(vault, &rest[..SPKI_BYTES], &rest[SPKI_BYTES..])?;
            Ok(vec![0])
        }
        20 => {
            if !rest.is_empty() {
                return Err(Failure::Unavailable);
            }
            authorization_suspend(vault)?;
            Ok(vec![0])
        }
        21 => {
            if !rest.is_empty() {
                return Err(Failure::Unavailable);
            }
            authorization_resume_revoke(vault)?;
            Ok(vec![0])
        }
        22 => {
            if rest.len() != SPKI_BYTES {
                return Err(Failure::Unavailable);
            }
            authorization_reenroll(vault, rest)?;
            Ok(vec![0])
        }
        23 => {
            let mut cursor = Cursor::new(rest);
            let format = *cursor.fixed(1)?.first().ok_or(Failure::Unavailable)?;
            let replace_candidates = match cursor.fixed(1)? {
                [0] => false,
                [1] => true,
                _ => return Err(Failure::Unavailable),
            };
            let source = Zeroizing::new(cursor.bytes()?);
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
                .preview_csv(&source, &profile)
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
            Ok(response)
        }
        24 => {
            let item = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_enable(item)
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared)
        }
        33 => {
            if rest != [0] {
                return Err(Failure::Unavailable);
            }
            let prepared = vault
                .prepare_plaintext_export()
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared)
        }
        40 => {
            if !rest.is_empty() {
                return Err(Failure::Unavailable);
            }
            authorization_add_keycloak(vault)?;
            Ok(vec![0])
        }
        41 => {
            let mut cursor = Cursor::new(rest);
            let subject_token = Zeroizing::new(cursor.bytes()?);
            let requester_secret = Zeroizing::new(cursor.bytes()?);
            cursor.finish()?;
            authorization_add_keycloak_exchange(vault, &subject_token, &requester_secret)?;
            Ok(vec![0])
        }
        45 => {
            let mut cursor = Cursor::new(rest);
            let ssh_private = Zeroizing::new(cursor.bytes()?);
            let ssh_public = cursor.bytes()?;
            let account_password = Zeroizing::new(cursor.bytes()?);
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
                    notes: String::new(),
                    fields: Vec::new(),
                    source_fields: Vec::new(),
                },
                vec![AuthRecord::Ssh {
                    private_format: PrivateKeyFormat::OpenSsh,
                    private_key: ssh_private.to_vec(),
                    public_key: ssh_public,
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
                &account_password,
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
            Ok(response)
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
            Ok(response)
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
            encode_prepared(vault, &prepared)
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
            encode_purge_prepared(vault, &purge)
        }
        28 => {
            let item = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let purge = vault
                .prepare_purge_item(item)
                .map_err(|_| Failure::Unavailable)?;
            encode_purge_prepared(vault, &purge)
        }
        29 => {
            let mut cursor = Cursor::new(rest);
            let item = cursor
                .fixed(16)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            let record =
                LogicalRecord::from_bytes(&cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
            cursor.finish()?;
            let prepared = vault
                .prepare_edit_record(item, &record)
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared)
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
            let mut response = vec![0];
            response.extend_from_slice(&record.to_bytes());
            Ok(response)
        }
        43 => {
            let mut cursor = Cursor::new(rest);
            let mut password = Zeroizing::new(cursor.bytes()?);
            cursor.finish()?;
            let prepared = vault
                .prepare_master_password_rotation(&password, KdfProfile::DEFAULT)
                .map_err(|_| Failure::Unavailable)?;
            password.zeroize();
            encode_prepared(vault, &prepared)
        }
        4 => {
            let item = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_delete(item)
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared)
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
            match vault.commit(&command, &signature, &body) {
                Ok(receipt) => {
                    let mut response = vec![0];
                    response.extend_from_slice(&receipt.to_bytes());
                    Ok(response)
                }
                Err(HumanCommitError::BodyChanged) => Ok(vec![2]),
                Err(_) => Ok(vec![1]),
            }
        }
        6 => {
            let item = rest.try_into().map_err(|_| Failure::Unavailable)?;
            match vault.read_password(item) {
                Ok(record) => {
                    let mut response = vec![0];
                    for field in [
                        record.title().as_bytes(),
                        record.username().as_bytes(),
                        record.password(),
                        record.destination().as_bytes(),
                        record.notes().as_bytes(),
                    ] {
                        push_bytes(&mut response, field)?;
                    }
                    Ok(response)
                }
                Err(HumanCommitError::ItemNotFound) => Ok(vec![3]),
                Err(_) => Ok(vec![1]),
            }
        }
        7 => {
            let transaction_id = rest.try_into().map_err(|_| Failure::Unavailable)?;
            match vault.receipt(transaction_id) {
                Ok(receipt) => {
                    let mut response = vec![0];
                    response.extend_from_slice(&receipt.to_bytes());
                    Ok(response)
                }
                Err(_) => Ok(vec![3]),
            }
        }
        9 => {
            let mut cursor = Cursor::new(rest);
            let bytes = cursor.bytes()?;
            cursor.finish()?;
            let record = LogicalRecord::from_bytes(&bytes).map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_create_record(&record)
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared)
        }
        10 => {
            let item = rest.try_into().map_err(|_| Failure::Unavailable)?;
            match vault.read_record(item) {
                Ok(record) => {
                    let mut response = vec![0];
                    response.extend_from_slice(&record.to_bytes());
                    Ok(response)
                }
                Err(HumanCommitError::ItemNotFound) => Ok(vec![3]),
                Err(_) => Ok(vec![1]),
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
                tags.push(String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?);
            }
            cursor.finish()?;
            let prepared = vault
                .prepare_organize(item, tags, favorite)
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared)
        }
        12 => {
            let mut cursor = Cursor::new(rest);
            let text = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
            let tag = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
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
            Ok(response)
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
            let mut response = vec![0];
            response.extend_from_slice(generated.expose());
            Ok(response)
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
            Ok(response)
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
            let label = String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
            let environment =
                String::from_utf8(cursor.bytes()?).map_err(|_| Failure::Unavailable)?;
            cursor.finish()?;
            let enrollment = AgentEnrollment::new(subject, request, rpk, &label, &environment)
                .map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_agent_enrollment(&enrollment)
                .map_err(|_| Failure::Unavailable)?;
            commit_authority(vault, prepared.prepared())?;
            Ok(vec![0])
        }
        56 => {
            let subject = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_agent_revocation(subject, AuthorizationReason::OwnerRequest)
                .map_err(|_| Failure::Unavailable)?;
            commit_authority(vault, &prepared)?;
            Ok(vec![0])
        }
        57 => {
            let prepared = match rest {
                [0] => vault.prepare_delegated_resume(),
                [1] => vault.prepare_delegated_suspend(AuthorizationReason::OwnerRequest),
                _ => return Err(Failure::Unavailable),
            }
            .map_err(|_| Failure::Unavailable)?;
            commit_authority(vault, &prepared)?;
            Ok(vec![0])
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
            Ok(vec![0])
        }
        46 | 49 => {
            if !request.is_empty() {
                return Err(Failure::Unavailable);
            }
            if opcode == 46 {
                vault
                    .record_human_interaction(AuditAction::HumanUnlock, None)
                    .map_err(|_| Failure::Unavailable)?;
            }
            encode_catalog(vault)
        }
        50 => generate(vault, request),
        51 => field_catalog(vault, request),
        52 | 53 => expose_field(vault, opcode, request),
        _ => unreachable!("closed opcode set checked above"),
    })())
}

fn generate(vault: &mut HumanVault, request: &[u8]) -> Result<Vec<u8>, Failure> {
    let mut cursor = Cursor::new(request);
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
    let mut response = vec![0];
    push_bytes(&mut response, generated.expose())?;
    Ok(response)
}

fn field_catalog(vault: &HumanVault, request: &[u8]) -> Result<Vec<u8>, Failure> {
    let item = request.try_into().map_err(|_| Failure::Unavailable)?;
    let record = vault.read_record(item).map_err(|_| Failure::Unavailable)?;
    let fields = human_fields(&record);
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
    Ok(response)
}

fn expose_field(vault: &mut HumanVault, opcode: u8, request: &[u8]) -> Result<Vec<u8>, Failure> {
    let mut cursor = Cursor::new(request);
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
    let fields = human_fields(&record);
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
    let mut response = vec![0];
    push_bytes(&mut response, value)?;
    Ok(response)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn fixed(&mut self, length: usize) -> Result<&'a [u8], Failure> {
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
    fn bytes(&mut self) -> Result<Vec<u8>, Failure> {
        let length = usize::try_from(u32::from_be_bytes(
            self.fixed(4)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?,
        ))
        .map_err(|_| Failure::Unavailable)?;
        Ok(self.fixed(length)?.to_vec())
    }
    fn u32(&mut self) -> Result<u32, Failure> {
        Ok(u32::from_be_bytes(
            self.fixed(4)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, Failure> {
        Ok(u64::from_be_bytes(
            self.fixed(8)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?,
        ))
    }
    fn finish(self) -> Result<(), Failure> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Failure::Unavailable)
        }
    }
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
fn human_fields(record: &LogicalRecord) -> Vec<(String, Zeroizing<Vec<u8>>)> {
    let mut fields = Vec::new();
    let mut push = |label: String, value: &[u8]| {
        fields.push((label, Zeroizing::new(value.to_vec())));
    };
    let human = record.human();
    push("title".into(), human.title.as_bytes());
    for (index, destination) in human.destinations.iter().enumerate() {
        push(
            format!("destination[{index}].label"),
            destination.label.as_bytes(),
        );
        push(
            format!("destination[{index}].value"),
            destination.value.as_bytes(),
        );
    }
    for (index, tag) in human.tags.iter().enumerate() {
        push(format!("tag[{index}]"), tag.as_bytes());
    }
    push(
        "favorite".into(),
        if human.favorite { b"true" } else { b"false" },
    );
    push("notes".into(), human.notes.as_bytes());
    for (index, field) in human.fields.iter().enumerate() {
        push(format!("custom[{index}].id"), hex(&field.id).as_bytes());
        push(format!("custom[{index}].label"), field.label.as_bytes());
        match &field.value {
            LogicalValue::Text(value) => push(format!("custom[{index}].text"), value.as_bytes()),
            LogicalValue::Bytes(value) => push(format!("custom[{index}].bytes"), value),
        }
        push(
            format!("custom[{index}].concealed"),
            if field.concealed { b"true" } else { b"false" },
        );
    }
    for (index, field) in human.source_fields.iter().enumerate() {
        push(format!("source[{index}].path"), field.path.as_bytes());
        push(
            format!("source[{index}].encoding"),
            match field.encoding {
                SourceEncoding::Utf8 => b"utf8",
                SourceEncoding::Json => b"json",
                SourceEncoding::Bytes => b"bytes",
            },
        );
        push(format!("source[{index}].value"), &field.value);
    }
    for (index, auth) in record.auth().iter().enumerate() {
        match auth {
            AuthRecord::Password {
                username,
                password,
                destination_refs,
            } => {
                push(format!("auth[{index}].username"), username.as_bytes());
                push(format!("auth[{index}].password"), password);
                push(
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
                push(format!("auth[{index}].secret"), secret);
                push(
                    format!("auth[{index}].algorithm"),
                    format!("{algorithm:?}").as_bytes(),
                );
                push(
                    format!("auth[{index}].digits"),
                    digits.to_string().as_bytes(),
                );
                push(
                    format!("auth[{index}].period"),
                    period.to_string().as_bytes(),
                );
                push(format!("auth[{index}].t0"), t0.to_string().as_bytes());
                push(format!("auth[{index}].issuer"), issuer.as_bytes());
                push(format!("auth[{index}].account"), account.as_bytes());
                push(
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
                push(format!("auth[{index}].rp_id"), rp_id.as_bytes());
                push(format!("auth[{index}].user_handle"), user_handle);
                push(format!("auth[{index}].credential_id"), credential_id);
                push(
                    format!("auth[{index}].cose_alg"),
                    cose_alg.to_string().as_bytes(),
                );
                push(format!("auth[{index}].private_key"), private_key);
                push(format!("auth[{index}].public_key"), public_key);
                push(format!("auth[{index}].user_name"), user_name.as_bytes());
                push(
                    format!("auth[{index}].display_name"),
                    display_name.as_bytes(),
                );
                push(
                    format!("auth[{index}].sign_count"),
                    sign_count.to_string().as_bytes(),
                );
                push(
                    format!("auth[{index}].backup_eligible"),
                    if *backup_eligible { b"true" } else { b"false" },
                );
                push(
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
                push(
                    format!("auth[{index}].private_format"),
                    format!("{private_format:?}").as_bytes(),
                );
                push(format!("auth[{index}].private_key"), private_key);
                push(format!("auth[{index}].public_key"), public_key);
                push(format!("auth[{index}].username"), username.as_bytes());
                push(
                    format!("auth[{index}].destination_refs"),
                    format!("{destination_refs:?}").as_bytes(),
                );
                if let Some(passphrase) = passphrase {
                    push(format!("auth[{index}].passphrase"), passphrase);
                }
            }
            AuthRecord::Token {
                secret,
                provider,
                profile_id,
                destination_refs,
                expires_at,
            } => {
                push(format!("auth[{index}].secret"), secret);
                push(format!("auth[{index}].provider"), provider.as_bytes());
                push(format!("auth[{index}].profile_id"), profile_id.as_bytes());
                push(
                    format!("auth[{index}].destination_refs"),
                    format!("{destination_refs:?}").as_bytes(),
                );
                if let Some(expires_at) = expires_at {
                    push(
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
                push(format!("auth[{index}].subject_token"), subject_token);
                push(
                    format!("auth[{index}].requester_client_id"),
                    requester_client_id.as_bytes(),
                );
                push(
                    format!("auth[{index}].requester_client_secret"),
                    requester_client_secret,
                );
                push(format!("auth[{index}].provider"), provider.as_bytes());
                push(format!("auth[{index}].profile_id"), profile_id.as_bytes());
                push(
                    format!("auth[{index}].destination_refs"),
                    format!("{destination_refs:?}").as_bytes(),
                );
                if let Some(expires_at) = expires_at {
                    push(
                        format!("auth[{index}].expires_at"),
                        expires_at.to_string().as_bytes(),
                    );
                }
            }
        }
    }
    for (index, attachment) in record.attachments().iter().enumerate() {
        push(
            format!("attachment[{index}].id"),
            hex(attachment.id()).as_bytes(),
        );
        push(
            format!("attachment[{index}].name"),
            attachment.name().as_bytes(),
        );
        push(
            format!("attachment[{index}].mime"),
            attachment.mime().as_bytes(),
        );
        push(
            format!("attachment[{index}].size"),
            attachment.size().to_string().as_bytes(),
        );
        push(
            format!("attachment[{index}].sha256"),
            hex(attachment.sha256()).as_bytes(),
        );
        push(format!("attachment[{index}].content"), attachment.content());
    }
    fields
}

pub(crate) fn encode_prepared(
    vault: &HumanVault,
    prepared: &PreparedHumanCommand,
) -> Result<Vec<u8>, Failure> {
    let signature = vault.sign(prepared).map_err(|_| Failure::Unavailable)?;
    let mut response = vec![0];
    response.extend_from_slice(prepared.transaction_id());
    response.extend_from_slice(prepared.item_id());
    push_bytes(&mut response, prepared.command())?;
    push_bytes(&mut response, prepared.body())?;
    response.extend_from_slice(&signature);
    Ok(response)
}

fn decode_wire_record(cursor: &mut Cursor<'_>) -> Result<PasswordRecord, Failure> {
    let title = cursor.bytes()?;
    let username = cursor.bytes()?;
    let mut password = Zeroizing::new(cursor.bytes()?);
    let destination = cursor.bytes()?;
    let notes = cursor.bytes()?;
    let record = PasswordRecord::new(
        std::str::from_utf8(&title).map_err(|_| Failure::Unavailable)?,
        std::str::from_utf8(&username).map_err(|_| Failure::Unavailable)?,
        &password,
        std::str::from_utf8(&destination).map_err(|_| Failure::Unavailable)?,
        std::str::from_utf8(&notes).map_err(|_| Failure::Unavailable)?,
    )
    .map_err(|_| Failure::Unavailable)?;
    password.zeroize();
    Ok(record)
}

fn encode_purge_prepared(
    vault: &HumanVault,
    purge: &pm_vault::PreparedItemPurge,
) -> Result<Vec<u8>, Failure> {
    let scope = purge.scope();
    let mut response = vec![0, u8::from(scope.terminal())];
    response.extend_from_slice(
        &u16::try_from(scope.revision_ids().len())
            .map_err(|_| Failure::Unavailable)?
            .to_be_bytes(),
    );
    response.extend_from_slice(
        &u32::try_from(scope.attachment_count())
            .map_err(|_| Failure::Unavailable)?
            .to_be_bytes(),
    );
    response.extend_from_slice(&scope.encrypted_bytes().to_be_bytes());
    for revision in scope.revision_ids() {
        response.extend_from_slice(revision);
    }
    let prepared = encode_prepared(vault, purge.prepared())?;
    response.extend_from_slice(&prepared[1..]);
    Ok(response)
}

pub(super) fn write_frame(output: &mut impl Write, value: &[u8]) -> Result<(), Failure> {
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

pub(super) fn read_frame(input: &mut impl Read) -> Result<Vec<u8>, Failure> {
    read_frame_bounded(input, MAX_HUMAN_FRAME)
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
        return Err(Failure::Unavailable);
    }
    let record = PasswordRecord::new(
        "Synthetic TLS shared account",
        "ticket07-user",
        b"ticket07-secret-canary",
        "https://ticket07.invalid/login",
        "",
    )
    .map_err(|_| Failure::Unavailable)?;
    let prepared = vault
        .prepare_create(&record)
        .map_err(|_| Failure::Unavailable)?;
    let item = *prepared.item_id();
    commit_authority(vault, &prepared)?;
    let note = LogicalRecord::new(
        RecordKind::Note,
        HumanMetadata {
            title: "Synthetic excluded note".to_owned(),
            destinations: vec![],
            tags: vec![],
            favorite: false,
            notes: "not authorized".to_owned(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![],
        vec![],
    )
    .map_err(|_| Failure::Unavailable)?;
    let prepared = vault
        .prepare_create_record(&note)
        .map_err(|_| Failure::Unavailable)?;
    commit_authority(vault, &prepared)?;
    for (subject, request, rpk, label) in [
        (LAB_AGENT_A, [0x31; 16], first, "Synthetic agent A"),
        (LAB_AGENT_B, [0x32; 16], second, "Synthetic agent B"),
    ] {
        let enrollment = AgentEnrollment::new(subject, request, rpk, label, "ticket07-userns")
            .map_err(|_| Failure::Unavailable)?;
        let prepared = vault
            .prepare_agent_enrollment(&enrollment)
            .map_err(|_| Failure::Unavailable)?;
        commit_authority(vault, prepared.prepared())?;
    }
    let prepared = vault
        .prepare_delegated_resume()
        .map_err(|_| Failure::Unavailable)?;
    commit_authority(vault, &prepared)?;
    let prepared = vault
        .prepare_enable(item)
        .map_err(|_| Failure::Unavailable)?;
    commit_authority(vault, &prepared)
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
            notes: String::new(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![
            AuthRecord::Password {
                username: "alice".to_owned(),
                password: b"ticket10-password-canary".to_vec(),
                destination_refs: vec![0],
            },
            AuthRecord::Totp {
                secret: b"12345678901234567890".to_vec(),
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
            notes: String::new(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![AuthRecord::Password {
            username: "charlie".to_owned(),
            password: b"ticket10-challenge-password".to_vec(),
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
            notes: String::new(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![AuthRecord::TokenExchange {
            subject_token: subject_token.to_vec(),
            requester_client_id: "pm-exchanger".to_owned(),
            requester_client_secret: requester_secret.to_vec(),
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
