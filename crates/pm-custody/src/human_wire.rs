// SPDX-License-Identifier: AGPL-3.0-only

//! Platform-neutral human wire operations shared by every native custodian.

use pm_crypto::KdfProfile;
use pm_vault::{
    AuditAction, AuthRecord, GeneratorConfig, HumanCommitError, HumanVault, ItemLifecycle,
    LogicalRecord, LogicalValue, PasswordRecord, PreparedHumanCommand, PrivateKeyFormat,
    RecordKind, SearchQuery, SourceEncoding,
};
use zeroize::{Zeroize, Zeroizing};

use crate::Failure;

/// Handles the shared catalog and exposure operations, or returns `None` for an opcode
/// owned by another shared human-wire slice.
pub(crate) fn handle_request_slice(
    vault: &mut HumanVault,
    device: [u8; 16],
    opcode: u8,
    request: &[u8],
) -> Option<Result<Vec<u8>, Failure>> {
    if !matches!(opcode, 2..=13 | 15 | 16 | 25..=30 | 43 | 46 | 49..=53) {
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
