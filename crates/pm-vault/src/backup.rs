// SPDX-License-Identifier: AGPL-3.0-only

//! Complete logical PMB1 snapshots over the existing human root and PMF1 stream.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    time::{SystemTime, UNIX_EPOCH},
};

use minicbor::{Decoder, Encoder, data::Type};
use pm_crypto::{
    BackupOpener, BackupRootEnvelopes, BackupSealer, DigestState, FileSealer, RecoveryCode,
    RevisionPackageInput, UnlockedRoot, digest, random_id,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use zeroize::{Zeroize, Zeroizing};

use crate::{HumanCommitError, LogicalRecord, PreparedHumanCommand, load_and_validate_bundle};

const MAX_OUTER_HEADER: usize = 64 * 1024;
const MAX_PMF_HEADER: usize = 4 * 1024 + 8;
const MAX_RECORD: usize = 16 * 1024 * 1024;
const CHUNK: usize = 1024 * 1024;
const MAX_RECORDS: u64 = 1_000_000;
const MAX_ATTACHMENTS: u64 = 100_000;
const MAX_LOGICAL_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const INVENTORY_PAGE: usize = 1024;

type PreparedRestore = (BackupSummary, Vec<[u8; 16]>, [u8; 32]);
type RestoreAttachmentMap = BTreeMap<([u8; 16], [u8; 16]), ([u8; 16], [u8; 16])>;
type ExpectedAttachmentMap = BTreeMap<([u8; 16], [u8; 16]), ([u8; 16], u64, [u8; 32])>;
type AuditRecordRow = (i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
type DecodedAttachment = ([u8; 16], [u8; 16], u64, [u8; 32], u64);
type DecodedAttachmentFull = ([u8; 16], [u8; 16], [u8; 16], u64, [u8; 32], u64);
type DecodedAttachmentChunk<'a> = ([u8; 16], [u8; 16], u64, &'a [u8]);

/// Counts and immutable identifiers authenticated by a complete PMB1 inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupSummary {
    backup_id: [u8; 16],
    source_vault: [u8; 16],
    items: u64,
    revisions: u64,
    attachments: u64,
    attachment_bytes: u64,
    audit_bundles: u64,
    authority_events: u64,
    identity_metadata: u64,
    records: u64,
    logical_bytes: u64,
}

impl BackupSummary {
    #[must_use]
    pub const fn backup_id(&self) -> &[u8; 16] {
        &self.backup_id
    }
    #[must_use]
    pub const fn source_vault(&self) -> &[u8; 16] {
        &self.source_vault
    }
    #[must_use]
    pub const fn items(&self) -> u64 {
        self.items
    }
    #[must_use]
    pub const fn revisions(&self) -> u64 {
        self.revisions
    }
    #[must_use]
    pub const fn attachments(&self) -> u64 {
        self.attachments
    }
    #[must_use]
    pub const fn attachment_bytes(&self) -> u64 {
        self.attachment_bytes
    }
    #[must_use]
    pub const fn audit_bundles(&self) -> u64 {
        self.audit_bundles
    }
    #[must_use]
    pub const fn authority_events(&self) -> u64 {
        self.authority_events
    }
    #[must_use]
    pub const fn identity_metadata(&self) -> u64 {
        self.identity_metadata
    }
    #[must_use]
    pub const fn records(&self) -> u64 {
        self.records
    }
    #[must_use]
    pub const fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }
}

/// Parser entry point for a portable PMB1 whose original vault is unavailable.
pub struct BackupArchive;

/// A fully authenticated backup staged under fresh destination data keys but
/// not visible until its signed human command commits atomically.
pub struct PreparedBackupRestore {
    prepared: PreparedHumanCommand,
    summary: BackupSummary,
    item_ids: Vec<[u8; 16]>,
}

impl PreparedBackupRestore {
    pub(crate) fn new(
        prepared: PreparedHumanCommand,
        summary: BackupSummary,
        item_ids: Vec<[u8; 16]>,
    ) -> Self {
        Self {
            prepared,
            summary,
            item_ids,
        }
    }
    #[must_use]
    pub const fn prepared(&self) -> &PreparedHumanCommand {
        &self.prepared
    }
    #[must_use]
    pub const fn summary(&self) -> &BackupSummary {
        &self.summary
    }
    #[must_use]
    pub fn item_ids(&self) -> &[[u8; 16]] {
        &self.item_ids
    }
}

impl BackupArchive {
    /// Validates a complete backup through its external recovery path without
    /// requiring the source device keyring or historical signing private key.
    ///
    /// # Errors
    /// Rejects wrong recovery material, incompatible bounds, corruption,
    /// truncation, trailing bytes, duplicate/missing inventory or dangling references.
    pub fn verify_with_recovery(
        input: &mut dyn Read,
        recovery: &RecoveryCode,
    ) -> Result<BackupSummary, HumanCommitError> {
        verify(input, OpenPath::Recovery(recovery))
    }

    /// Validates a portable backup through the password path.
    ///
    /// # Errors
    /// Has the same fail-closed behavior as `verify_with_recovery`.
    pub fn verify_with_password(
        input: &mut dyn Read,
        password: &[u8],
    ) -> Result<BackupSummary, HumanCommitError> {
        verify(input, OpenPath::Password(password))
    }
}

pub(crate) fn write_backup(
    path: &std::path::Path,
    root: &UnlockedRoot,
    output: &mut dyn Write,
) -> Result<BackupSummary, HumanCommitError> {
    let mut connection = Connection::open(path)?;
    connection.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;")?;
    let (bundle, trusted) = load_and_validate_bundle(&connection)?;
    if trusted.vault_id() != root.vault_id() {
        return Err(HumanCommitError::InvalidCommand);
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    // Establish the SQLite read snapshot before generating any random output.
    let _: i64 = transaction.query_row("SELECT count(*) FROM vault_items", [], |row| row.get(0))?;
    let backup_id = random_id()?;
    let snapshot_id = random_id()?;
    let roots = bundle.backup_root_envelopes();
    let mut sealer = root.start_backup(backup_id)?;
    let outer = encode_outer(&roots, backup_id, sealer.key_envelope());
    if outer.len() > MAX_OUTER_HEADER {
        return Err(HumanCommitError::InvalidInput);
    }
    let mut outer_bytes = b"PMB1".to_vec();
    outer_bytes.extend_from_slice(&u32::try_from(outer.len()).map_err(invalid)?.to_be_bytes());
    outer_bytes.extend_from_slice(&outer);
    output.write_all(&outer_bytes)?;
    output.write_all(sealer.pmf1_header())?;

    let frontier = current_frontier(&transaction)?;
    let checkpoint = authority_checkpoint(&transaction)?;
    let start = encode_start(
        backup_id,
        snapshot_id,
        now_us()?,
        digest(&outer_bytes),
        *roots.vault_id(),
        frontier,
        checkpoint,
    );
    let mut stream = RecordWriter::new(&mut sealer, output);
    stream.write_control(&start)?;
    let mut state = ExportState::default();
    export_items(&transaction, root, &mut stream, &mut state)?;
    export_revisions(&transaction, root, &mut stream, &mut state)?;
    export_partial_history(&transaction, &mut stream, &mut state)?;
    export_attachments(&transaction, root, &mut stream, &mut state)?;
    export_organizations(&transaction, root, &mut stream, &mut state)?;
    export_settings(&mut stream, &mut state)?;
    export_audit(&transaction, &mut stream, &mut state)?;
    export_authority(&transaction, &mut stream, &mut state)?;
    export_identities(&transaction, &trusted, &mut stream, &mut state)?;
    let pages_hash = stream.write_inventory_pages()?;
    let end = encode_end(
        state.records,
        state.attachments,
        state.logical_bytes,
        pages_hash,
        state.attachment_bytes,
    );
    stream.write_control(&end)?;
    stream.finish()?;
    transaction.commit()?;
    output.flush()?;
    Ok(state.summary(backup_id, *roots.vault_id()))
}

pub(crate) fn verify_with_root(
    root: &UnlockedRoot,
    input: &mut dyn Read,
) -> Result<BackupSummary, HumanCommitError> {
    verify(input, OpenPath::Unlocked(root))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_restore(
    tx: &Transaction<'_>,
    root: &UnlockedRoot,
    device: [u8; 16],
    transaction_id: [u8; 16],
    input: &mut dyn Read,
    password: &[u8],
) -> Result<PreparedRestore, HumanCommitError> {
    prepare_restore_from(
        tx,
        root,
        device,
        transaction_id,
        input,
        OpenPath::Password(password),
    )
}

pub(crate) fn prepare_recovery(
    tx: &Transaction<'_>,
    root: &UnlockedRoot,
    device: [u8; 16],
    transaction_id: [u8; 16],
    input: &mut dyn Read,
    recovery: &RecoveryCode,
) -> Result<PreparedRestore, HumanCommitError> {
    prepare_restore_from(
        tx,
        root,
        device,
        transaction_id,
        input,
        OpenPath::Recovery(recovery),
    )
}

fn prepare_restore_from(
    tx: &Transaction<'_>,
    root: &UnlockedRoot,
    device: [u8; 16],
    transaction_id: [u8; 16],
    input: &mut dyn Read,
    source: OpenPath<'_>,
) -> Result<PreparedRestore, HumanCommitError> {
    let mut collector = RestoreCollector::new(tx, root, device, transaction_id);
    let summary = parse_backup(input, source, Some(&mut collector))?;
    let item_ids = collector.item_ids();
    let object_digest: [u8; 32] = tx
        .query_row(
            "SELECT object_digest FROM backup_restore_batches WHERE transaction_id=?1",
            [transaction_id.as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )?
        .try_into()
        .map_err(invalid)?;
    Ok((summary, item_ids, object_digest))
}

struct RestoreItem {
    target: [u8; 16],
    visible_source: [u8; 16],
}

struct RestoreAttachment {
    source_revision: [u8; 16],
    source_attachment: [u8; 16],
    expected_chunks: u64,
    seen: u64,
    sealer: FileSealer,
}

struct RestoreCollector<'a> {
    tx: &'a Transaction<'a>,
    root: &'a UnlockedRoot,
    device: [u8; 16],
    transaction_id: [u8; 16],
    items: BTreeMap<[u8; 16], RestoreItem>,
    revisions: BTreeMap<[u8; 16], [u8; 16]>,
    attachments: RestoreAttachmentMap,
    active: Option<RestoreAttachment>,
}

impl<'a> RestoreCollector<'a> {
    fn new(
        tx: &'a Transaction<'a>,
        root: &'a UnlockedRoot,
        device: [u8; 16],
        transaction_id: [u8; 16],
    ) -> Self {
        Self {
            tx,
            root,
            device,
            transaction_id,
            items: BTreeMap::new(),
            revisions: BTreeMap::new(),
            attachments: BTreeMap::new(),
            active: None,
        }
    }

    fn item_ids(&self) -> Vec<[u8; 16]> {
        self.items.values().map(|item| item.target).collect()
    }

    fn finish_active(&mut self) -> Result<(), HumanCommitError> {
        if self
            .active
            .as_ref()
            .is_some_and(|value| value.seen != value.expected_chunks)
        {
            return Err(HumanCommitError::Integrity);
        }
        self.active = None;
        Ok(())
    }
}

impl DataCollector for RestoreCollector<'_> {
    #[allow(clippy::too_many_lines)]
    fn data(
        &mut self,
        opener: &BackupOpener,
        kind: &str,
        id: [u8; 16],
        payload: &[u8],
    ) -> Result<(), HumanCommitError> {
        match kind {
            "item" => {
                self.finish_active()?;
                let (visible, item_kind, status) = decode_item_full(payload)?;
                let target = random_id()?;
                if self
                    .items
                    .insert(
                        id,
                        RestoreItem {
                            target,
                            visible_source: visible,
                        },
                    )
                    .is_some()
                {
                    return Err(HumanCommitError::Integrity);
                }
                self.tx.execute(
                    "INSERT INTO backup_restore_items(transaction_id,source_item,target_item,source_visible_revision,target_visible_revision,item_kind,status) VALUES(?1,?2,?3,?4,NULL,?5,?6)",
                    params![self.transaction_id.as_slice(), id.as_slice(), target.as_slice(), visible.as_slice(), item_kind, status],
                )?;
            }
            "revision" => {
                self.finish_active()?;
                let (source_item, _source_issuer, modified_at, mut record) =
                    decode_revision_full(payload)?;
                let item = self
                    .items
                    .get(&source_item)
                    .ok_or(HumanCommitError::Integrity)?;
                let target_revision = random_id()?;
                let mut replacements = BTreeMap::new();
                for attachment in record.attachments() {
                    let target_attachment = random_id()?;
                    replacements.insert(*attachment.id(), target_attachment);
                    self.attachments
                        .insert((id, *attachment.id()), (target_revision, target_attachment));
                }
                record.remap_attachment_ids(&replacements)?;
                let package = self
                    .root
                    .seal_revision_package(RevisionPackageInput {
                        item: item.target,
                        revision: target_revision,
                        issuer_device: self.device,
                        modified_at,
                        kind: record.kind().crypto(),
                        human_plaintext: &record.encode_human(),
                        auth_plaintext: record.encode_auth().as_deref(),
                    })?
                    .to_bytes();
                self.tx.execute(
                    "INSERT INTO backup_restore_revisions(transaction_id,source_revision,target_revision,target_item,modified_at_us,item_kind,package,object_digest) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                    params![self.transaction_id.as_slice(), id.as_slice(), target_revision.as_slice(), item.target.as_slice(), modified_at, record.kind().name(), package, [0_u8;32].as_slice()],
                )?;
                if id == item.visible_source {
                    self.tx.execute(
                        "UPDATE backup_restore_items SET target_visible_revision=?3 WHERE transaction_id=?1 AND source_item=?2",
                        params![self.transaction_id.as_slice(), source_item.as_slice(), target_revision.as_slice()],
                    )?;
                }
                self.revisions.insert(id, target_revision);
            }
            "attachment" => {
                self.finish_active()?;
                let (source_revision, source_attachment, _size, _hash, chunks) =
                    decode_attachment(payload)?;
                let (target_revision, target_attachment) = *self
                    .attachments
                    .get(&(source_revision, source_attachment))
                    .ok_or(HumanCommitError::Integrity)?;
                let sealer = self.root.start_file(target_attachment, target_revision)?;
                self.tx.execute(
                    "INSERT INTO backup_restore_streams(transaction_id,source_revision,source_attachment,target_revision,target_attachment,header,chunk_count) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                    params![self.transaction_id.as_slice(),source_revision.as_slice(),source_attachment.as_slice(),target_revision.as_slice(),target_attachment.as_slice(),sealer.header(),i64::try_from(chunks).map_err(invalid)?],
                )?;
                self.active = Some(RestoreAttachment {
                    source_revision,
                    source_attachment,
                    expected_chunks: chunks,
                    seen: 0,
                    sealer,
                });
            }
            "attachment_chunk" => {
                let (source_revision, source_attachment, index, bytes) =
                    decode_attachment_chunk(payload)?;
                let active = self.active.as_mut().ok_or(HumanCommitError::Integrity)?;
                if active.source_revision != source_revision
                    || active.source_attachment != source_attachment
                    || active.seen != index
                {
                    return Err(HumanCommitError::Integrity);
                }
                let final_chunk = index + 1 == active.expected_chunks;
                let frame = active.sealer.seal_chunk(bytes, final_chunk)?;
                self.tx.execute(
                    "INSERT INTO backup_restore_stream_chunks(transaction_id,source_revision,source_attachment,chunk_index,ciphertext) VALUES(?1,?2,?3,?4,?5)",
                    params![self.transaction_id.as_slice(),source_revision.as_slice(),source_attachment.as_slice(),i64::try_from(index).map_err(invalid)?,frame],
                )?;
                active.seen += 1;
            }
            "organization" | "settings" | "authority_history" | "identity_metadata"
            | "partial_history" => {
                self.finish_active()?;
                let object = derived_id(b"pm/backup-restored-history/v1", &[kind.as_bytes(), &id]);
                let package = self
                    .root
                    .seal_file(object, self.transaction_id, payload)?
                    .to_bytes();
                self.tx.execute(
                    "INSERT INTO backup_restore_history(transaction_id,record_type,record_id,package) VALUES(?1,?2,?3,?4)",
                    params![self.transaction_id.as_slice(),kind,id.as_slice(),package],
                )?;
            }
            "audit_bundle" => {
                self.finish_active()?;
                let (device, generation, source_envelope) = audit_key_fields(payload)?;
                let rewrapped = opener.rewrap_imported_audit_key(
                    self.root,
                    source_envelope,
                    device,
                    generation,
                )?;
                let imported = encode_imported_audit(payload, &rewrapped);
                let object = derived_id(b"pm/backup-restored-history/v1", &[kind.as_bytes(), &id]);
                let package = self
                    .root
                    .seal_file(object, self.transaction_id, &imported)?
                    .to_bytes();
                self.tx.execute(
                    "INSERT INTO backup_restore_history(transaction_id,record_type,record_id,package) VALUES(?1,?2,?3,?4)",
                    params![self.transaction_id.as_slice(),kind,id.as_slice(),package],
                )?;
            }
            _ => return Err(HumanCommitError::InvalidInput),
        }
        Ok(())
    }

    fn finish(&mut self, summary: &BackupSummary) -> Result<(), HumanCommitError> {
        self.finish_active()?;
        if self.items.values().any(|item| {
            !self
                .tx
                .query_row(
                    "SELECT target_visible_revision IS NOT NULL FROM backup_restore_items WHERE transaction_id=?1 AND target_item=?2",
                    params![self.transaction_id.as_slice(), item.target.as_slice()],
                    |row| row.get::<_, bool>(0),
                )
                .unwrap_or(false)
        }) {
            return Err(HumanCommitError::Integrity);
        }
        let mut revisions = self.tx.prepare(
            "SELECT source_revision,package FROM backup_restore_revisions WHERE transaction_id=?1 ORDER BY source_revision",
        )?;
        let rows = revisions
            .query_map([self.transaction_id.as_slice()], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (source, package) in rows {
            let source = fixed::<16>(&source)?;
            let object = restore_graph_digest(self.tx, self.transaction_id, source, &package)?;
            self.tx.execute("UPDATE backup_restore_revisions SET object_digest=?3 WHERE transaction_id=?1 AND source_revision=?2",params![self.transaction_id.as_slice(),source.as_slice(),object.as_slice()])?;
        }
        let object_digest = restore_batch_digest(self.tx, self.transaction_id)?;
        self.tx.execute(
            "INSERT INTO backup_restore_batches(transaction_id,backup_id,source_vault,object_digest,item_count,revision_count,attachment_count,attachment_bytes,audit_bundles,authority_events,identity_metadata) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![self.transaction_id.as_slice(),summary.backup_id.as_slice(),summary.source_vault.as_slice(),object_digest.as_slice(),to_i64(summary.items)?,to_i64(summary.revisions)?,to_i64(summary.attachments)?,to_i64(summary.attachment_bytes)?,to_i64(summary.audit_bundles)?,to_i64(summary.authority_events)?,to_i64(summary.identity_metadata)?],
        )?;
        Ok(())
    }
}

pub(crate) fn write_plaintext(
    tx: &Transaction<'_>,
    root: &UnlockedRoot,
    output: &mut dyn Write,
) -> Result<BackupSummary, HumanCommitError> {
    output.write_all(b"PM-LOGICAL-JSONL/1\n")?;
    let backup_id = random_id()?;
    writeln!(
        output,
        "{{\"type\":\"manifest_start\",\"v\":1,\"backup_id\":\"{}\",\"source_vault\":\"{}\",\"scope\":\"full\"}}",
        hex(&backup_id),
        hex(root.vault_id())
    )?;
    let mut writer = PlaintextWriter { output };
    let mut state = ExportState::default();
    export_items(tx, root, &mut writer, &mut state)?;
    export_revisions(tx, root, &mut writer, &mut state)?;
    export_partial_history(tx, &mut writer, &mut state)?;
    export_attachments(tx, root, &mut writer, &mut state)?;
    export_organizations(tx, root, &mut writer, &mut state)?;
    export_settings(&mut writer, &mut state)?;
    export_audit(tx, &mut writer, &mut state)?;
    export_authority(tx, &mut writer, &mut state)?;
    // The human root is public historical metadata, never an active private key.
    let trusted = root.trusted_root();
    export_identities(tx, &trusted, &mut writer, &mut state)?;
    writer.finish(&state)?;
    Ok(state.summary(backup_id, *root.vault_id()))
}

#[derive(Clone, Copy)]
enum OpenPath<'a> {
    Unlocked(&'a UnlockedRoot),
    Password(&'a [u8]),
    Recovery(&'a RecoveryCode),
}

fn verify(input: &mut dyn Read, path: OpenPath<'_>) -> Result<BackupSummary, HumanCommitError> {
    parse_backup(input, path, None)
}

trait DataCollector {
    fn data(
        &mut self,
        opener: &BackupOpener,
        kind: &str,
        id: [u8; 16],
        payload: &[u8],
    ) -> Result<(), HumanCommitError>;

    fn finish(&mut self, _summary: &BackupSummary) -> Result<(), HumanCommitError> {
        Ok(())
    }
}

fn parse_backup(
    input: &mut dyn Read,
    path: OpenPath<'_>,
    collector: Option<&mut dyn DataCollector>,
) -> Result<BackupSummary, HumanCommitError> {
    let (outer_bytes, outer) = read_outer(input)?;
    let pmf = read_pmf_header(input)?;
    let roots = BackupRootEnvelopes::from_parts(
        outer.vault,
        outer.key_generation,
        &outer.password_envelope,
        &outer.recovery_envelope,
    )?;
    let mut opener = match path {
        OpenPath::Unlocked(root) => BackupOpener::with_unlocked_root(
            root,
            &roots,
            outer.backup_id,
            &outer.backup_key_envelope,
            &pmf,
        )?,
        OpenPath::Password(password) => BackupOpener::with_password(
            &roots,
            outer.backup_id,
            &outer.backup_key_envelope,
            &pmf,
            password,
        )?,
        OpenPath::Recovery(recovery) => BackupOpener::with_recovery(
            &roots,
            outer.backup_id,
            &outer.backup_key_envelope,
            &pmf,
            recovery,
        )?,
    };
    let mut parser = RecordVerifier::new(
        outer.backup_id,
        outer.vault,
        digest(&outer_bytes),
        collector,
    );
    let mut current = read_cipher_frame(input)?.ok_or(HumanCommitError::InvalidInput)?;
    loop {
        let next = read_cipher_frame(input)?;
        let final_chunk = next.is_none();
        let mut plain = Zeroizing::new(opener.open_chunk(&current, final_chunk)?);
        parser.push(&plain, &opener)?;
        plain.zeroize();
        if let Some(frame) = next {
            current = frame;
        } else {
            break;
        }
    }
    parser.finish()
}

#[derive(Default)]
struct ExportState {
    items: u64,
    revisions: u64,
    attachments: u64,
    attachment_bytes: u64,
    audit_bundles: u64,
    authority_events: u64,
    identity_metadata: u64,
    records: u64,
    logical_bytes: u64,
}

impl ExportState {
    fn record(&mut self, kind: &str, logical_size: usize) -> Result<(), HumanCommitError> {
        self.records = self
            .records
            .checked_add(1)
            .ok_or(HumanCommitError::InvalidInput)?;
        self.logical_bytes = self
            .logical_bytes
            .checked_add(u64::try_from(logical_size).map_err(invalid)?)
            .ok_or(HumanCommitError::InvalidInput)?;
        if self.records > MAX_RECORDS || self.logical_bytes > MAX_LOGICAL_BYTES {
            return Err(HumanCommitError::InvalidInput);
        }
        match kind {
            "item" => self.items += 1,
            "revision" => self.revisions += 1,
            "attachment" => {
                self.attachments += 1;
                if self.attachments > MAX_ATTACHMENTS {
                    return Err(HumanCommitError::InvalidInput);
                }
            }
            "audit_bundle" => self.audit_bundles += 1,
            "authority_history" => self.authority_events += 1,
            "identity_metadata" => self.identity_metadata += 1,
            _ => {}
        }
        Ok(())
    }

    fn summary(&self, backup_id: [u8; 16], source_vault: [u8; 16]) -> BackupSummary {
        BackupSummary {
            backup_id,
            source_vault,
            items: self.items,
            revisions: self.revisions,
            attachments: self.attachments,
            attachment_bytes: self.attachment_bytes,
            audit_bundles: self.audit_bundles,
            authority_events: self.authority_events,
            identity_metadata: self.identity_metadata,
            records: self.records,
            logical_bytes: self.logical_bytes,
        }
    }
}

struct InventoryEntry {
    kind: String,
    id: [u8; 16],
    hash: [u8; 32],
    size: u64,
}

trait BackupDataWriter {
    fn write_data(
        &mut self,
        kind: &str,
        id: [u8; 16],
        payload: &[u8],
        state: &mut ExportState,
    ) -> Result<(), HumanCommitError>;
}

struct RecordWriter<'a> {
    sealer: &'a mut BackupSealer,
    output: &'a mut dyn Write,
    buffer: Zeroizing<Vec<u8>>,
    inventory: Vec<InventoryEntry>,
}

impl<'a> RecordWriter<'a> {
    fn new(sealer: &'a mut BackupSealer, output: &'a mut dyn Write) -> Self {
        Self {
            sealer,
            output,
            buffer: Zeroizing::new(Vec::with_capacity(CHUNK)),
            inventory: vec![],
        }
    }

    fn write_control(&mut self, record: &[u8]) -> Result<(), HumanCommitError> {
        self.write_plain(&frame_record(record))
    }

    fn write_encrypted_data(
        &mut self,
        kind: &str,
        id: [u8; 16],
        payload: &[u8],
        state: &mut ExportState,
    ) -> Result<(), HumanCommitError> {
        let record = encode_data(kind, id, payload);
        if record.len() > MAX_RECORD {
            return Err(HumanCommitError::InvalidInput);
        }
        let size = u64::try_from(record.len()).map_err(invalid)?;
        self.inventory.push(InventoryEntry {
            kind: kind.to_owned(),
            id,
            hash: digest(&record),
            size,
        });
        state.record(kind, record.len())?;
        self.write_plain(&frame_record(&record))
    }

    fn write_plain(&mut self, mut bytes: &[u8]) -> Result<(), HumanCommitError> {
        while !bytes.is_empty() {
            let space = CHUNK - self.buffer.len();
            let take = space.min(bytes.len());
            self.buffer.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.buffer.len() == CHUNK {
                let frame = self.sealer.seal_chunk(&self.buffer, false)?;
                self.output.write_all(&frame)?;
                self.buffer.zeroize();
                self.buffer.clear();
            }
        }
        Ok(())
    }

    fn write_inventory_pages(&mut self) -> Result<[u8; 32], HumanCommitError> {
        let inventory = std::mem::take(&mut self.inventory);
        let mut state = DigestState::new()?;
        for (index, page) in inventory.chunks(INVENTORY_PAGE).enumerate() {
            let record = encode_inventory_page(u64::try_from(index).map_err(invalid)?, page);
            let framed = frame_record(&record);
            state.update(&framed);
            self.write_plain(&framed)?;
        }
        Ok(state.finish())
    }

    fn finish(mut self) -> Result<(), HumanCommitError> {
        let frame = self.sealer.seal_chunk(&self.buffer, true)?;
        self.output.write_all(&frame)?;
        self.buffer.zeroize();
        Ok(())
    }
}

impl BackupDataWriter for RecordWriter<'_> {
    fn write_data(
        &mut self,
        kind: &str,
        id: [u8; 16],
        payload: &[u8],
        state: &mut ExportState,
    ) -> Result<(), HumanCommitError> {
        self.write_encrypted_data(kind, id, payload, state)
    }
}

struct PlaintextWriter<'a> {
    output: &'a mut dyn Write,
}

impl PlaintextWriter<'_> {
    fn finish(&mut self, state: &ExportState) -> Result<(), HumanCommitError> {
        writeln!(
            self.output,
            "{{\"type\":\"manifest_end\",\"record_count\":{},\"attachment_count\":{},\"logical_bytes\":{},\"attachment_bytes\":{}}}",
            state.records, state.attachments, state.logical_bytes, state.attachment_bytes
        )?;
        self.output.flush()?;
        Ok(())
    }
}

impl BackupDataWriter for PlaintextWriter<'_> {
    fn write_data(
        &mut self,
        kind: &str,
        id: [u8; 16],
        payload: &[u8],
        state: &mut ExportState,
    ) -> Result<(), HumanCommitError> {
        let record = encode_data(kind, id, payload);
        if record.len() > MAX_RECORD {
            return Err(HumanCommitError::InvalidInput);
        }
        state.record(kind, record.len())?;
        write!(
            self.output,
            "{{\"v\":1,\"type\":\"{}\",\"id\":\"{}\",\"payload\":\"",
            kind,
            hex(&id)
        )?;
        write_base64(self.output, payload)?;
        self.output.write_all(b"\"}\n")?;
        Ok(())
    }
}

fn export_items(
    tx: &Transaction<'_>,
    _root: &UnlockedRoot,
    writer: &mut impl BackupDataWriter,
    state: &mut ExportState,
) -> Result<(), HumanCommitError> {
    let mut statement = tx
        .prepare("SELECT item_id,visible_revision,kind,status FROM vault_items ORDER BY item_id")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let id = fixed::<16>(&row.get::<_, Vec<u8>>(0)?)?;
        let visible = fixed::<16>(&row.get::<_, Vec<u8>>(1)?)?;
        let kind: String = row.get(2)?;
        let status: String = row.get(3)?;
        let payload = encode_item(visible, &kind, &status);
        writer.write_data("item", id, &payload, state)?;
    }
    Ok(())
}

fn export_revisions(
    tx: &Transaction<'_>,
    root: &UnlockedRoot,
    writer: &mut impl BackupDataWriter,
    state: &mut ExportState,
) -> Result<(), HumanCommitError> {
    let mut statement =
        tx.prepare("SELECT revision_id,item_id,package FROM revision_parts ORDER BY revision_id")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let revision = fixed::<16>(&row.get::<_, Vec<u8>>(0)?)?;
        let item = fixed::<16>(&row.get::<_, Vec<u8>>(1)?)?;
        let package: Vec<u8> = row.get(2)?;
        let opened = root.open_revision_package(&package)?;
        let record =
            LogicalRecord::decode_parts(opened.human_plaintext(), opened.auth_plaintext())?;
        if opened.item() != &item
            || opened.revision() != &revision
            || opened.kind() != record.kind().crypto()
        {
            return Err(HumanCommitError::Integrity);
        }
        let item_exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM vault_items WHERE item_id=?1)",
            [item.as_slice()],
            |r| r.get(0),
        )?;
        if !item_exists {
            return Err(HumanCommitError::Integrity);
        }
        let payload = encode_revision(
            item,
            *opened.issuer_device(),
            opened.modified_at(),
            &record.to_descriptor_bytes(),
        );
        writer.write_data("revision", revision, &payload, state)?;
    }
    Ok(())
}

fn export_partial_history(
    tx: &Transaction<'_>,
    writer: &mut impl BackupDataWriter,
    state: &mut ExportState,
) -> Result<(), HumanCommitError> {
    let mut records = Vec::new();
    let mut revisions = tx.prepare(
        "SELECT revision_id,item_id,purge_event_digest FROM purged_revisions ORDER BY revision_id",
    )?;
    let mut rows = revisions.query([])?;
    while let Some(row) = rows.next()? {
        let revision = fixed::<16>(&row.get::<_, Vec<u8>>(0)?)?;
        let item = fixed::<16>(&row.get::<_, Vec<u8>>(1)?)?;
        let event = fixed::<32>(&row.get::<_, Vec<u8>>(2)?)?;
        let id = derived_id(b"pm/backup-partial-revision/v1", &[&item, &revision]);
        records.push((id, encode_partial_revision(item, revision, event)));
    }
    let mut items = tx.prepare(
        "SELECT item_id,purge_event_digest,revision_count,attachment_count,encrypted_bytes
         FROM purged_items ORDER BY item_id",
    )?;
    let mut rows = items.query([])?;
    while let Some(row) = rows.next()? {
        let item = fixed::<16>(&row.get::<_, Vec<u8>>(0)?)?;
        let event = fixed::<32>(&row.get::<_, Vec<u8>>(1)?)?;
        let revision_count = u64::try_from(row.get::<_, i64>(2)?).map_err(invalid)?;
        let attachment_count = u64::try_from(row.get::<_, i64>(3)?).map_err(invalid)?;
        let encrypted_bytes = u64::try_from(row.get::<_, i64>(4)?).map_err(invalid)?;
        let id = derived_id(b"pm/backup-partial-item/v1", &[&item]);
        records.push((
            id,
            encode_partial_item(
                item,
                event,
                revision_count,
                attachment_count,
                encrypted_bytes,
            ),
        ));
    }
    records.sort_unstable_by_key(|(id, _)| *id);
    for (id, payload) in records {
        writer.write_data("partial_history", id, &payload, state)?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn export_attachments(
    tx: &Transaction<'_>,
    root: &UnlockedRoot,
    writer: &mut impl BackupDataWriter,
    state: &mut ExportState,
) -> Result<(), HumanCommitError> {
    let mut revisions =
        tx.prepare("SELECT revision_id,item_id,package FROM revision_parts ORDER BY revision_id")?;
    let mut rows = revisions.query([])?;
    while let Some(row) = rows.next()? {
        let revision = fixed::<16>(&row.get::<_, Vec<u8>>(0)?)?;
        let item = fixed::<16>(&row.get::<_, Vec<u8>>(1)?)?;
        let package: Vec<u8> = row.get(2)?;
        let opened = root.open_revision_package(&package)?;
        let record =
            LogicalRecord::decode_parts(opened.human_plaintext(), opened.auth_plaintext())?;
        for attachment in record.attachments() {
            let attachment_id = *attachment.id();
            let record_id = derived_id(b"pm/backup-attachment/v1", &[&revision, &attachment_id]);
            let inline: Option<Vec<u8>> = tx.query_row(
                "SELECT package FROM attachment_parts WHERE attachment_id=?1 AND revision_id=?2",
                params![attachment_id.as_slice(), revision.as_slice()], |r| r.get(0),
            ).optional()?;
            let stream: Option<(Vec<u8>, i64)> = tx.query_row(
                "SELECT header,chunk_count FROM attachment_streams WHERE attachment_id=?1 AND revision_id=?2",
                params![attachment_id.as_slice(), revision.as_slice()], |r| Ok((r.get(0)?, r.get(1)?)),
            ).optional()?;
            if inline.is_some() == stream.is_some() {
                return Err(HumanCommitError::Integrity);
            }
            let chunk_count = inline.as_ref().map_or_else(
                || stream.as_ref().map_or(0, |v| v.1),
                |value| i64::try_from(value.len().max(1).div_ceil(CHUNK)).unwrap_or(i64::MAX),
            );
            if chunk_count <= 0 {
                return Err(HumanCommitError::Integrity);
            }
            let metadata = encode_attachment(
                item,
                revision,
                attachment_id,
                attachment.name(),
                attachment.mime(),
                attachment.size(),
                *attachment.sha256(),
                u64::try_from(chunk_count).map_err(invalid)?,
            );
            writer.write_data("attachment", record_id, &metadata, state)?;
            let mut digest_state = DigestState::new()?;
            let mut total = 0_u64;
            let mut index = 0_u64;
            if let Some(package) = inline {
                let mut plain =
                    Zeroizing::new(root.open_file(attachment_id, revision, &package)?);
                if plain.is_empty() {
                    write_attachment_chunk(
                        writer,
                        state,
                        revision,
                        attachment_id,
                        0,
                        &[],
                        &mut digest_state,
                        &mut total,
                    )?;
                    index = 1;
                } else {
                    for chunk in plain.chunks(CHUNK) {
                        write_attachment_chunk(
                            writer,
                            state,
                            revision,
                            attachment_id,
                            index,
                            chunk,
                            &mut digest_state,
                            &mut total,
                        )?;
                        index += 1;
                    }
                }
                plain.zeroize();
            } else if let Some((header, count)) = stream {
                let mut file_opener = root.start_file_open(attachment_id, revision, &header)?;
                let mut chunks = tx.prepare(
                    "SELECT chunk_index,ciphertext FROM attachment_stream_chunks WHERE attachment_id=?1 AND revision_id=?2 ORDER BY chunk_index"
                )?;
                let mut source =
                    chunks.query(params![attachment_id.as_slice(), revision.as_slice()])?;
                while let Some(row) = source.next()? {
                    let stored: i64 = row.get(0)?;
                    if stored < 0 || u64::try_from(stored).ok() != Some(index) {
                        return Err(HumanCommitError::Integrity);
                    }
                    let frame: Vec<u8> = row.get(1)?;
                    let mut plain =
                        Zeroizing::new(file_opener.open_chunk(&frame, stored + 1 == count)?);
                    write_attachment_chunk(
                        writer,
                        state,
                        revision,
                        attachment_id,
                        index,
                        &plain,
                        &mut digest_state,
                        &mut total,
                    )?;
                    plain.zeroize();
                    index += 1;
                }
            }
            if index != u64::try_from(chunk_count).map_err(invalid)?
                || total != attachment.size()
                || digest_state.finish() != *attachment.sha256()
            {
                return Err(HumanCommitError::Integrity);
            }
            state.attachment_bytes = state
                .attachment_bytes
                .checked_add(total)
                .ok_or(HumanCommitError::InvalidInput)?;
            if state.attachment_bytes > MAX_LOGICAL_BYTES {
                return Err(HumanCommitError::InvalidInput);
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_attachment_chunk(
    writer: &mut impl BackupDataWriter,
    state: &mut ExportState,
    revision: [u8; 16],
    attachment: [u8; 16],
    index: u64,
    bytes: &[u8],
    digest_state: &mut DigestState,
    total: &mut u64,
) -> Result<(), HumanCommitError> {
    if bytes.len() > CHUNK {
        return Err(HumanCommitError::InvalidInput);
    }
    digest_state.update(bytes);
    *total = total
        .checked_add(u64::try_from(bytes.len()).map_err(invalid)?)
        .ok_or(HumanCommitError::InvalidInput)?;
    let id = derived_id(
        b"pm/backup-attachment-chunk/v1",
        &[&revision, &attachment, &index.to_be_bytes()],
    );
    let payload = encode_attachment_chunk(revision, attachment, index, bytes);
    writer.write_data("attachment_chunk", id, &payload, state)
}

fn export_organizations(
    tx: &Transaction<'_>,
    root: &UnlockedRoot,
    writer: &mut impl BackupDataWriter,
    state: &mut ExportState,
) -> Result<(), HumanCommitError> {
    let mut tags: BTreeMap<String, Vec<[u8; 16]>> = BTreeMap::new();
    let mut statement = tx.prepare(
        "SELECT i.item_id,r.package FROM vault_items i JOIN revision_parts r ON r.revision_id=i.visible_revision ORDER BY i.item_id"
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let item = fixed::<16>(&row.get::<_, Vec<u8>>(0)?)?;
        let package: Vec<u8> = row.get(1)?;
        let opened = root.open_revision_package(&package)?;
        let record =
            LogicalRecord::decode_parts(opened.human_plaintext(), opened.auth_plaintext())?;
        for tag in &record.human().tags {
            tags.entry(tag.clone()).or_default().push(item);
        }
    }
    let mut organizations = Vec::with_capacity(tags.len());
    for (name, mut items) in tags {
        items.sort_unstable();
        items.dedup();
        let id = derived_id(b"pm/backup-organization/v1", &[name.as_bytes()]);
        organizations.push((id, encode_organization(&name, &items)));
    }
    organizations.sort_unstable_by_key(|(id, _)| *id);
    for (id, payload) in organizations {
        writer.write_data("organization", id, &payload, state)?;
    }
    Ok(())
}

fn export_settings(
    writer: &mut impl BackupDataWriter,
    state: &mut ExportState,
) -> Result<(), HumanCommitError> {
    writer.write_data("settings", [0; 16], &encode_settings(), state)
}

fn export_audit(
    tx: &Transaction<'_>,
    writer: &mut impl BackupDataWriter,
    state: &mut ExportState,
) -> Result<(), HumanCommitError> {
    let mut statement = tx.prepare(
        "SELECT segment_id,device_id,generation,first_seq,last_seq,previous_hash,last_hash,record_count,stored_bytes,closed FROM audit_segments ORDER BY segment_id"
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let segment = fixed::<16>(&row.get::<_, Vec<u8>>(0)?)?;
        let device = fixed::<16>(&row.get::<_, Vec<u8>>(1)?)?;
        let generation: i64 = row.get(2)?;
        let key: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = tx.query_row(
            "SELECT human_envelope,encryption_public_key,signing_public_key,human_signature FROM audit_keys WHERE device_id=?1 AND generation=?2",
            params![device.as_slice(), generation], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
        let manifest: Vec<u8> = tx.query_row(
            "SELECT envelope FROM audit_manifests WHERE device_id=?1 AND generation=?2",
            params![device.as_slice(), generation],
            |r| r.get(0),
        )?;
        let mut records = Vec::new();
        let mut record_rows = tx.prepare(
            "SELECT seq,event_id,record,signature,record_hash FROM encrypted_audit_records WHERE segment_id=?1 ORDER BY seq"
        )?;
        let mut source = record_rows.query([segment.as_slice()])?;
        while let Some(record) = source.next()? {
            records.push((
                record.get::<_, i64>(0)?,
                record.get::<_, Vec<u8>>(1)?,
                record.get::<_, Vec<u8>>(2)?,
                record.get::<_, Vec<u8>>(3)?,
                record.get::<_, Vec<u8>>(4)?,
            ));
        }
        let payload = encode_audit_bundle(
            segment,
            device,
            generation,
            row.get(3)?,
            row.get(4)?,
            &row.get::<_, Vec<u8>>(5)?,
            &row.get::<_, Vec<u8>>(6)?,
            row.get(7)?,
            row.get(8)?,
            row.get(9)?,
            &key,
            &manifest,
            &records,
        );
        writer.write_data("audit_bundle", segment, &payload, state)?;
    }
    Ok(())
}

fn export_authority(
    tx: &Transaction<'_>,
    writer: &mut impl BackupDataWriter,
    state: &mut ExportState,
) -> Result<(), HumanCommitError> {
    let mut statement = tx.prepare(
        "SELECT event_digest,event_id,issuer_device,issuer_generation,seq,previous_digest,parents,kind,subject,subject_generation,event,human_signature,device_signature FROM authority_events ORDER BY event_digest"
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let digest_id = fixed::<32>(&row.get::<_, Vec<u8>>(0)?)?;
        let id: [u8; 16] = digest_id[..16].try_into().map_err(invalid)?;
        let payload = encode_sql_row(row, 0, 13)?;
        writer.write_data("authority_history", id, &payload, state)?;
    }
    Ok(())
}

fn export_identities(
    tx: &Transaction<'_>,
    trusted: &pm_crypto::TrustedRoot,
    writer: &mut impl BackupDataWriter,
    state: &mut ExportState,
) -> Result<(), HumanCommitError> {
    let mut identities = Vec::new();
    let human = encode_identity(
        "human",
        "historical human root",
        trusted.public_key(),
        "historical",
        trusted.epoch(),
    );
    identities.push((*trusted.vault_id(), human));
    let mut devices = tx.prepare("SELECT DISTINCT device_id,generation,signing_public_key FROM audit_keys ORDER BY device_id,generation")?;
    let mut rows = devices.query([])?;
    while let Some(row) = rows.next()? {
        let id = fixed::<16>(&row.get::<_, Vec<u8>>(0)?)?;
        let generation = u64::try_from(row.get::<_, i64>(1)?).map_err(invalid)?;
        let public: Vec<u8> = row.get(2)?;
        identities.push((
            id,
            encode_identity(
                "device",
                "historical device",
                &public,
                "historical",
                generation,
            ),
        ));
    }
    let mut agents = tx.prepare("SELECT subject_id,generation,transport_rpk,label,status FROM agent_authorizations ORDER BY subject_id,generation")?;
    let mut rows = agents.query([])?;
    while let Some(row) = rows.next()? {
        let subject = fixed::<16>(&row.get::<_, Vec<u8>>(0)?)?;
        let generation = u64::try_from(row.get::<_, i64>(1)?).map_err(invalid)?;
        let public: Vec<u8> = row.get(2)?;
        let label: String = row.get(3)?;
        let state_name: String = row.get(4)?;
        let id = derived_id(
            b"pm/backup-agent-identity/v1",
            &[&subject, &generation.to_be_bytes()],
        );
        identities.push((
            id,
            encode_identity("agent", &label, &public, &state_name, generation),
        ));
    }
    identities.sort_unstable_by_key(|(id, _)| *id);
    for (id, payload) in identities {
        writer.write_data("identity_metadata", id, &payload, state)?;
    }
    Ok(())
}

struct Outer {
    backup_id: [u8; 16],
    vault: [u8; 16],
    key_generation: u64,
    password_envelope: Vec<u8>,
    recovery_envelope: Vec<u8>,
    backup_key_envelope: Vec<u8>,
}

fn encode_outer(roots: &BackupRootEnvelopes, backup_id: [u8; 16], backup_key: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.map(8).unwrap();
    key(&mut e, "v");
    e.u8(1).unwrap();
    key(&mut e, "suite");
    e.u8(1).unwrap();
    key(&mut e, "backup_id");
    e.bytes(&backup_id).unwrap();
    key(&mut e, "vault");
    e.bytes(roots.vault_id()).unwrap();
    key(&mut e, "key_generation");
    e.u64(roots.key_generation()).unwrap();
    key(&mut e, "password_root_envelope");
    e.bytes(roots.password_envelope()).unwrap();
    key(&mut e, "recovery_root_envelope");
    e.bytes(roots.recovery_envelope()).unwrap();
    key(&mut e, "backup_key_envelope");
    e.bytes(backup_key).unwrap();
    e.into_writer()
}

fn read_outer(input: &mut dyn Read) -> Result<(Vec<u8>, Outer), HumanCommitError> {
    let mut prefix = [0; 8];
    input.read_exact(&mut prefix)?;
    if &prefix[..4] != b"PMB1" {
        return Err(HumanCommitError::InvalidInput);
    }
    let len = usize::try_from(u32::from_be_bytes(prefix[4..].try_into().map_err(invalid)?))
        .map_err(invalid)?;
    if len == 0 || len > MAX_OUTER_HEADER {
        return Err(HumanCommitError::InvalidInput);
    }
    let mut bytes = vec![0; len];
    input.read_exact(&mut bytes)?;
    let mut d = Decoder::new(&bytes);
    expect_map(&mut d, 8)?;
    expect_key(&mut d, "v")?;
    if d.u8().map_err(invalid)? != 1 {
        return Err(HumanCommitError::InvalidInput);
    }
    expect_key(&mut d, "suite")?;
    if d.u8().map_err(invalid)? != 1 {
        return Err(HumanCommitError::InvalidInput);
    }
    expect_key(&mut d, "backup_id")?;
    let backup_id = decode_fixed(&mut d)?;
    expect_key(&mut d, "vault")?;
    let vault = decode_fixed(&mut d)?;
    expect_key(&mut d, "key_generation")?;
    let key_generation = d.u64().map_err(invalid)?;
    expect_key(&mut d, "password_root_envelope")?;
    let password_envelope = d.bytes().map_err(invalid)?.to_vec();
    expect_key(&mut d, "recovery_root_envelope")?;
    let recovery_envelope = d.bytes().map_err(invalid)?.to_vec();
    expect_key(&mut d, "backup_key_envelope")?;
    let backup_key_envelope = d.bytes().map_err(invalid)?.to_vec();
    if d.position() != bytes.len()
        || encode_outer(
            &BackupRootEnvelopes::from_parts(
                vault,
                key_generation,
                &password_envelope,
                &recovery_envelope,
            )?,
            backup_id,
            &backup_key_envelope,
        ) != bytes
    {
        return Err(HumanCommitError::InvalidInput);
    }
    let mut outer_bytes = prefix.to_vec();
    outer_bytes.extend_from_slice(&bytes);
    Ok((
        outer_bytes,
        Outer {
            backup_id,
            vault,
            key_generation,
            password_envelope,
            recovery_envelope,
            backup_key_envelope,
        },
    ))
}

fn read_pmf_header(input: &mut dyn Read) -> Result<Vec<u8>, HumanCommitError> {
    let mut prefix = [0; 8];
    input.read_exact(&mut prefix)?;
    if &prefix[..4] != b"PMF1" {
        return Err(HumanCommitError::InvalidInput);
    }
    let len = usize::try_from(u32::from_be_bytes(prefix[4..].try_into().map_err(invalid)?))
        .map_err(invalid)?;
    if len == 0 || len + 8 > MAX_PMF_HEADER {
        return Err(HumanCommitError::InvalidInput);
    }
    let mut result = prefix.to_vec();
    result.resize(8 + len, 0);
    input.read_exact(&mut result[8..])?;
    Ok(result)
}

fn read_cipher_frame(input: &mut dyn Read) -> Result<Option<Vec<u8>>, HumanCommitError> {
    let mut length = [0; 4];
    let mut seen = 0;
    while seen < 4 {
        let count = input.read(&mut length[seen..])?;
        if count == 0 {
            return if seen == 0 {
                Ok(None)
            } else {
                Err(HumanCommitError::InvalidInput)
            };
        }
        seen += count;
    }
    let len = usize::try_from(u32::from_be_bytes(length)).map_err(invalid)?;
    if !(17..=CHUNK + 17).contains(&len) {
        return Err(HumanCommitError::InvalidInput);
    }
    let mut frame = length.to_vec();
    frame.resize(4 + len, 0);
    input.read_exact(&mut frame[4..])?;
    Ok(Some(frame))
}

struct RecordVerifier<'a> {
    backup_id: [u8; 16],
    vault: [u8; 16],
    outer_hash: [u8; 32],
    input: Zeroizing<Vec<u8>>,
    start_seen: bool,
    end_seen: bool,
    observed: BTreeMap<(String, [u8; 16]), ([u8; 32], u64)>,
    items: BTreeMap<[u8; 16], ([u8; 16], String)>,
    revisions: BTreeMap<[u8; 16], ([u8; 16], String)>,
    expected_attachments: ExpectedAttachmentMap,
    attachments: BTreeMap<([u8; 16], [u8; 16]), AttachmentCheck>,
    active_attachment: Option<([u8; 16], [u8; 16])>,
    authority_digests: BTreeSet<[u8; 32]>,
    authority_references: BTreeSet<[u8; 32]>,
    next_page: u64,
    pages_hash: DigestState,
    state: ExportState,
    collector: Option<&'a mut dyn DataCollector>,
}

struct AttachmentCheck {
    expected_size: u64,
    expected_hash: [u8; 32],
    expected_chunks: u64,
    seen: u64,
    bytes: u64,
    digest: DigestState,
}

impl<'a> RecordVerifier<'a> {
    fn new(
        backup_id: [u8; 16],
        vault: [u8; 16],
        outer_hash: [u8; 32],
        collector: Option<&'a mut dyn DataCollector>,
    ) -> Self {
        Self {
            backup_id,
            vault,
            outer_hash,
            input: Zeroizing::new(vec![]),
            start_seen: false,
            end_seen: false,
            observed: BTreeMap::new(),
            items: BTreeMap::new(),
            revisions: BTreeMap::new(),
            expected_attachments: BTreeMap::new(),
            attachments: BTreeMap::new(),
            active_attachment: None,
            authority_digests: BTreeSet::new(),
            authority_references: BTreeSet::new(),
            next_page: 0,
            pages_hash: DigestState::new().expect("libsodium initialized by opener"),
            state: ExportState::default(),
            collector,
        }
    }
    fn push(&mut self, bytes: &[u8], opener: &BackupOpener) -> Result<(), HumanCommitError> {
        if self.end_seen {
            return Err(HumanCommitError::InvalidInput);
        }
        self.input.extend_from_slice(bytes);
        loop {
            if self.input.len() < 4 {
                break;
            }
            let len = usize::try_from(u32::from_be_bytes(
                self.input[..4].try_into().map_err(invalid)?,
            ))
            .map_err(invalid)?;
            if len == 0 || len > MAX_RECORD {
                return Err(HumanCommitError::InvalidInput);
            }
            if self.input.len() < 4 + len {
                break;
            }
            let mut record = Zeroizing::new(self.input[4..4 + len].to_vec());
            self.consume(&record, opener)?;
            record.zeroize();
            self.input.drain(..4 + len);
        }
        Ok(())
    }
    fn consume(&mut self, record: &[u8], opener: &BackupOpener) -> Result<(), HumanCommitError> {
        let kind = peek_type(record)?;
        match kind.as_str() {
            "manifest_start" => self.consume_start(record),
            "inventory_page" => self.consume_page(record),
            "manifest_end" => self.consume_end(record),
            _ => self.consume_data(record, &kind, opener),
        }
    }
    fn consume_start(&mut self, record: &[u8]) -> Result<(), HumanCommitError> {
        if self.start_seen || !self.observed.is_empty() {
            return Err(HumanCommitError::InvalidInput);
        }
        let mut d = Decoder::new(record);
        expect_map(&mut d, 10)?;
        expect_key(&mut d, "type")?;
        if d.str().map_err(invalid)? != "manifest_start" {
            return Err(HumanCommitError::InvalidInput);
        }
        expect_key(&mut d, "v")?;
        if d.u8().map_err(invalid)? != 1 {
            return Err(HumanCommitError::InvalidInput);
        }
        expect_key(&mut d, "backup_id")?;
        if decode_fixed::<16>(&mut d)? != self.backup_id {
            return Err(HumanCommitError::Integrity);
        }
        expect_key(&mut d, "snapshot_id")?;
        let _: [u8; 16] = decode_fixed(&mut d)?;
        expect_key(&mut d, "created_at")?;
        let _ = d.i64().map_err(invalid)?;
        expect_key(&mut d, "outer_sha256")?;
        if decode_fixed::<32>(&mut d)? != self.outer_hash {
            return Err(HumanCommitError::Integrity);
        }
        expect_key(&mut d, "source_vault")?;
        if decode_fixed::<16>(&mut d)? != self.vault {
            return Err(HumanCommitError::Integrity);
        }
        expect_key(&mut d, "content_frontier")?;
        let _ = d.bytes().map_err(invalid)?;
        expect_key(&mut d, "authority_checkpoint_ref")?;
        let _ = d.bytes().map_err(invalid)?;
        expect_key(&mut d, "scope")?;
        if d.str().map_err(invalid)? != "full" {
            return Err(HumanCommitError::InvalidInput);
        }
        if d.position() != record.len() {
            return Err(HumanCommitError::InvalidInput);
        }
        self.start_seen = true;
        Ok(())
    }
    #[allow(clippy::too_many_lines)]
    fn consume_data(
        &mut self,
        record: &[u8],
        kind: &str,
        opener: &BackupOpener,
    ) -> Result<(), HumanCommitError> {
        if !self.start_seen || self.next_page != 0 || self.end_seen || !is_data_type(kind) {
            return Err(HumanCommitError::InvalidInput);
        }
        if kind != "attachment_chunk" {
            self.finish_active_attachment()?;
        }
        let (id, payload) = decode_data(record, kind)?;
        if self
            .observed
            .insert(
                (kind.to_owned(), id),
                (
                    digest(record),
                    u64::try_from(record.len()).map_err(invalid)?,
                ),
            )
            .is_some()
        {
            return Err(HumanCommitError::Integrity);
        }
        self.state.record(kind, record.len())?;
        match kind {
            "item" => {
                let (visible, kind, _) = decode_item_full(payload)?;
                if self.items.insert(id, (visible, kind)).is_some() {
                    return Err(HumanCommitError::Integrity);
                }
            }
            "revision" => {
                let (item, _, _, record) = decode_revision_full(payload)?;
                if self
                    .revisions
                    .insert(id, (item, record.kind().name().to_owned()))
                    .is_some()
                {
                    return Err(HumanCommitError::Integrity);
                }
                for attachment in record.attachments() {
                    if self
                        .expected_attachments
                        .insert(
                            (id, *attachment.id()),
                            (item, attachment.size(), *attachment.sha256()),
                        )
                        .is_some()
                    {
                        return Err(HumanCommitError::Integrity);
                    }
                }
            }
            "attachment" => {
                let (item, revision, attachment, size, hash, chunks) =
                    decode_attachment_full(payload)?;
                if self.expected_attachments.remove(&(revision, attachment))
                    != Some((item, size, hash))
                {
                    return Err(HumanCommitError::Integrity);
                }
                if self
                    .attachments
                    .insert(
                        (revision, attachment),
                        AttachmentCheck {
                            expected_size: size,
                            expected_hash: hash,
                            expected_chunks: chunks,
                            seen: 0,
                            bytes: 0,
                            digest: DigestState::new()?,
                        },
                    )
                    .is_some()
                {
                    return Err(HumanCommitError::Integrity);
                }
                self.active_attachment = Some((revision, attachment));
                self.state.attachment_bytes = self
                    .state
                    .attachment_bytes
                    .checked_add(size)
                    .ok_or(HumanCommitError::InvalidInput)?;
            }
            "attachment_chunk" => {
                let (revision, attachment, index, bytes) = decode_attachment_chunk(payload)?;
                if self.active_attachment != Some((revision, attachment)) {
                    return Err(HumanCommitError::Integrity);
                }
                let check = self
                    .attachments
                    .get_mut(&(revision, attachment))
                    .ok_or(HumanCommitError::Integrity)?;
                if index != check.seen || bytes.len() > CHUNK {
                    return Err(HumanCommitError::Integrity);
                }
                check.seen += 1;
                check.bytes = check
                    .bytes
                    .checked_add(u64::try_from(bytes.len()).map_err(invalid)?)
                    .ok_or(HumanCommitError::InvalidInput)?;
                check.digest.update(bytes);
            }
            "authority_history" => {
                let (event_digest, references) = decode_authority_history(payload)?;
                let event_id: [u8; 16] = event_digest[..16].try_into().map_err(invalid)?;
                if id != event_id || !self.authority_digests.insert(event_digest) {
                    return Err(HumanCommitError::Integrity);
                }
                self.authority_references.extend(references);
            }
            _ => {}
        }
        if let Some(collector) = &mut self.collector {
            collector.data(opener, kind, id, payload)?;
        }
        Ok(())
    }
    fn consume_page(&mut self, record: &[u8]) -> Result<(), HumanCommitError> {
        self.finish_active_attachment()?;
        if !self.start_seen || self.end_seen {
            return Err(HumanCommitError::InvalidInput);
        }
        let mut d = Decoder::new(record);
        expect_map(&mut d, 3)?;
        expect_key(&mut d, "type")?;
        if d.str().map_err(invalid)? != "inventory_page" {
            return Err(HumanCommitError::InvalidInput);
        }
        expect_key(&mut d, "index")?;
        if d.u64().map_err(invalid)? != self.next_page {
            return Err(HumanCommitError::Integrity);
        }
        expect_key(&mut d, "entries")?;
        let count = array_len(&mut d)?;
        if count == 0 || count > INVENTORY_PAGE {
            return Err(HumanCommitError::InvalidInput);
        }
        for _ in 0..count {
            expect_map(&mut d, 4)?;
            expect_key(&mut d, "type")?;
            let kind = d.str().map_err(invalid)?.to_owned();
            expect_key(&mut d, "id")?;
            let id = decode_fixed(&mut d)?;
            expect_key(&mut d, "record_sha256")?;
            let hash = decode_fixed(&mut d)?;
            expect_key(&mut d, "logical_size")?;
            let size = d.u64().map_err(invalid)?;
            if self.observed.remove(&(kind, id)) != Some((hash, size)) {
                return Err(HumanCommitError::Integrity);
            }
        }
        if d.position() != record.len() {
            return Err(HumanCommitError::InvalidInput);
        }
        self.pages_hash.update(&frame_record(record));
        self.next_page += 1;
        Ok(())
    }
    fn consume_end(&mut self, record: &[u8]) -> Result<(), HumanCommitError> {
        self.finish_active_attachment()?;
        if !self.start_seen || self.end_seen || !self.observed.is_empty() {
            return Err(HumanCommitError::Integrity);
        }
        let mut d = Decoder::new(record);
        expect_map(&mut d, 6)?;
        expect_key(&mut d, "type")?;
        if d.str().map_err(invalid)? != "manifest_end" {
            return Err(HumanCommitError::InvalidInput);
        }
        expect_key(&mut d, "record_count")?;
        if d.u64().map_err(invalid)? != self.state.records {
            return Err(HumanCommitError::Integrity);
        }
        expect_key(&mut d, "attachment_count")?;
        if d.u64().map_err(invalid)? != self.state.attachments {
            return Err(HumanCommitError::Integrity);
        }
        expect_key(&mut d, "logical_bytes")?;
        if d.u64().map_err(invalid)? != self.state.logical_bytes {
            return Err(HumanCommitError::Integrity);
        }
        expect_key(&mut d, "inventory_pages_sha256")?;
        let pages: [u8; 32] = decode_fixed(&mut d)?;
        expect_key(&mut d, "attachment_bytes")?;
        if d.u64().map_err(invalid)? != self.state.attachment_bytes {
            return Err(HumanCommitError::Integrity);
        }
        if d.position() != record.len()
            || pages != std::mem::replace(&mut self.pages_hash, DigestState::new()?).finish()
        {
            return Err(HumanCommitError::Integrity);
        }
        self.end_seen = true;
        Ok(())
    }
    fn finish(mut self) -> Result<BackupSummary, HumanCommitError> {
        self.finish_active_attachment()?;
        if !self.input.is_empty()
            || !self.end_seen
            || !self.observed.is_empty()
            || !self.expected_attachments.is_empty()
            || !self.authority_references.is_subset(&self.authority_digests)
        {
            return Err(HumanCommitError::InvalidInput);
        }
        for (item, (visible, kind)) in &self.items {
            let Some((revision_item, revision_kind)) = self.revisions.get(visible) else {
                return Err(HumanCommitError::Integrity);
            };
            if revision_item != item || revision_kind != kind {
                return Err(HumanCommitError::Integrity);
            }
        }
        for (item, kind) in self.revisions.values() {
            if self.items.get(item).map(|(_, item_kind)| item_kind) != Some(kind) {
                return Err(HumanCommitError::Integrity);
            }
        }
        for ((revision, _), attachment) in self.attachments {
            if !self.revisions.contains_key(&revision)
                || attachment.seen != attachment.expected_chunks
                || attachment.bytes != attachment.expected_size
                || attachment.digest.finish() != attachment.expected_hash
            {
                return Err(HumanCommitError::Integrity);
            }
        }
        let summary = self.state.summary(self.backup_id, self.vault);
        if let Some(collector) = &mut self.collector {
            collector.finish(&summary)?;
        }
        Ok(summary)
    }

    fn finish_active_attachment(&mut self) -> Result<(), HumanCommitError> {
        if let Some(key) = self.active_attachment.take() {
            let attachment = self
                .attachments
                .get(&key)
                .ok_or(HumanCommitError::Integrity)?;
            if attachment.seen != attachment.expected_chunks {
                return Err(HumanCommitError::Integrity);
            }
        }
        Ok(())
    }
}

fn encode_start(
    backup: [u8; 16],
    snapshot: [u8; 16],
    created: i64,
    outer: [u8; 32],
    vault: [u8; 16],
    frontier: [u8; 32],
    checkpoint: [u8; 32],
) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.map(10).unwrap();
    key(&mut e, "type");
    e.str("manifest_start").unwrap();
    key(&mut e, "v");
    e.u8(1).unwrap();
    key(&mut e, "backup_id");
    e.bytes(&backup).unwrap();
    key(&mut e, "snapshot_id");
    e.bytes(&snapshot).unwrap();
    key(&mut e, "created_at");
    e.i64(created).unwrap();
    key(&mut e, "outer_sha256");
    e.bytes(&outer).unwrap();
    key(&mut e, "source_vault");
    e.bytes(&vault).unwrap();
    key(&mut e, "content_frontier");
    e.bytes(&frontier).unwrap();
    key(&mut e, "authority_checkpoint_ref");
    e.bytes(&checkpoint).unwrap();
    key(&mut e, "scope");
    e.str("full").unwrap();
    e.into_writer()
}
fn encode_data(kind: &str, id: [u8; 16], payload: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.map(3).unwrap();
    key(&mut e, "type");
    e.str(kind).unwrap();
    key(&mut e, "id");
    e.bytes(&id).unwrap();
    key(&mut e, "payload");
    e.bytes(payload).unwrap();
    e.into_writer()
}
fn encode_item(visible: [u8; 16], kind: &str, status: &str) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(3).unwrap();
    e.bytes(&visible).unwrap();
    e.str(kind).unwrap();
    e.str(status).unwrap();
    e.into_writer()
}
fn encode_revision(item: [u8; 16], issuer: [u8; 16], modified: i64, descriptor: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(4).unwrap();
    e.bytes(&item).unwrap();
    e.bytes(&issuer).unwrap();
    e.i64(modified).unwrap();
    e.bytes(descriptor).unwrap();
    e.into_writer()
}
#[allow(clippy::too_many_arguments)]
fn encode_attachment(
    item: [u8; 16],
    revision: [u8; 16],
    attachment: [u8; 16],
    name: &str,
    mime: &str,
    size: u64,
    sha: [u8; 32],
    chunks: u64,
) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(8).unwrap();
    e.bytes(&item).unwrap();
    e.bytes(&revision).unwrap();
    e.bytes(&attachment).unwrap();
    e.str(name).unwrap();
    e.str(mime).unwrap();
    e.u64(size).unwrap();
    e.bytes(&sha).unwrap();
    e.u64(chunks).unwrap();
    e.into_writer()
}
fn encode_attachment_chunk(
    revision: [u8; 16],
    attachment: [u8; 16],
    index: u64,
    bytes: &[u8],
) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(4).unwrap();
    e.bytes(&revision).unwrap();
    e.bytes(&attachment).unwrap();
    e.u64(index).unwrap();
    e.bytes(bytes).unwrap();
    e.into_writer()
}
fn encode_organization(name: &str, items: &[[u8; 16]]) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(2).unwrap();
    e.str(name).unwrap();
    e.array(items.len() as u64).unwrap();
    for item in items {
        e.bytes(item).unwrap();
    }
    e.into_writer()
}
fn encode_partial_revision(item: [u8; 16], revision: [u8; 16], purge_event: [u8; 32]) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(4).unwrap();
    e.str("purged_revision").unwrap();
    e.bytes(&item).unwrap();
    e.bytes(&revision).unwrap();
    e.bytes(&purge_event).unwrap();
    e.into_writer()
}
fn encode_partial_item(
    item: [u8; 16],
    purge_event: [u8; 32],
    revision_count: u64,
    attachment_count: u64,
    encrypted_bytes: u64,
) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(6).unwrap();
    e.str("purged_item").unwrap();
    e.bytes(&item).unwrap();
    e.bytes(&purge_event).unwrap();
    e.u64(revision_count).unwrap();
    e.u64(attachment_count).unwrap();
    e.u64(encrypted_bytes).unwrap();
    e.into_writer()
}
fn encode_settings() -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.map(3).unwrap();
    key(&mut e, "retention");
    e.array(3)
        .unwrap()
        .str("manual")
        .unwrap()
        .str("manual")
        .unwrap()
        .str("manual")
        .unwrap();
    key(&mut e, "locale");
    e.str("und").unwrap();
    key(&mut e, "theme");
    e.str("system").unwrap();
    e.into_writer()
}
#[allow(clippy::too_many_arguments)]
fn encode_audit_bundle(
    segment: [u8; 16],
    device: [u8; 16],
    generation: i64,
    first: i64,
    last: i64,
    previous: &[u8],
    last_hash: &[u8],
    count: i64,
    stored: i64,
    closed: bool,
    key_data: &(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>),
    manifest: &[u8],
    records: &[AuditRecordRow],
) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(16).unwrap();
    e.bytes(&segment).unwrap();
    e.bytes(&device).unwrap();
    e.i64(generation).unwrap();
    e.i64(first).unwrap();
    e.i64(last).unwrap();
    e.bytes(previous).unwrap();
    e.bytes(last_hash).unwrap();
    e.i64(count).unwrap();
    e.i64(stored).unwrap();
    e.bool(closed).unwrap();
    e.bytes(&key_data.0).unwrap();
    e.bytes(&key_data.1).unwrap();
    e.bytes(&key_data.2).unwrap();
    e.bytes(&key_data.3).unwrap();
    e.bytes(manifest).unwrap();
    e.array(records.len() as u64).unwrap();
    for r in records {
        e.array(5).unwrap();
        e.i64(r.0).unwrap();
        e.bytes(&r.1).unwrap();
        e.bytes(&r.2).unwrap();
        e.bytes(&r.3).unwrap();
        e.bytes(&r.4).unwrap();
    }
    e.into_writer()
}

fn audit_key_fields(payload: &[u8]) -> Result<([u8; 16], u64, &[u8]), HumanCommitError> {
    let mut d = Decoder::new(payload);
    expect_array(&mut d, 16)?;
    let _: [u8; 16] = decode_fixed(&mut d)?;
    let device = decode_fixed(&mut d)?;
    let generation = u64::try_from(d.i64().map_err(invalid)?).map_err(invalid)?;
    if generation == 0 {
        return Err(HumanCommitError::InvalidInput);
    }
    let _ = d.i64().map_err(invalid)?;
    let _ = d.i64().map_err(invalid)?;
    let _ = d.bytes().map_err(invalid)?;
    let _ = d.bytes().map_err(invalid)?;
    let _ = d.i64().map_err(invalid)?;
    let _ = d.i64().map_err(invalid)?;
    let _ = d.bool().map_err(invalid)?;
    let human_envelope = d.bytes().map_err(invalid)?;
    Ok((device, generation, human_envelope))
}

fn encode_imported_audit(source_bundle: &[u8], rewrapped_human_envelope: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(3).unwrap();
    e.str("pm/imported-audit-bundle/v1").unwrap();
    e.bytes(source_bundle).unwrap();
    e.bytes(rewrapped_human_envelope).unwrap();
    e.into_writer()
}
fn encode_sql_row(
    row: &rusqlite::Row<'_>,
    start: usize,
    end: usize,
) -> Result<Vec<u8>, HumanCommitError> {
    let mut e = Encoder::new(Vec::new());
    e.array((end - start) as u64).unwrap();
    for index in start..end {
        let value = row.get_ref(index)?;
        match value {
            rusqlite::types::ValueRef::Null => {
                e.null().unwrap();
            }
            rusqlite::types::ValueRef::Integer(v) => {
                e.i64(v).unwrap();
            }
            rusqlite::types::ValueRef::Blob(v) => {
                e.bytes(v).unwrap();
            }
            rusqlite::types::ValueRef::Text(v) => {
                e.str(std::str::from_utf8(v).map_err(invalid)?).unwrap();
            }
            rusqlite::types::ValueRef::Real(_) => return Err(HumanCommitError::InvalidInput),
        }
    }
    Ok(e.into_writer())
}
fn encode_identity(
    kind_name: &str,
    label: &str,
    public: &[u8],
    state: &str,
    generation: u64,
) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(5).unwrap();
    e.str(kind_name).unwrap();
    e.str(label).unwrap();
    e.bytes(public).unwrap();
    e.str(state).unwrap();
    e.u64(generation).unwrap();
    e.into_writer()
}
fn encode_inventory_page(index: u64, entries: &[InventoryEntry]) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.map(3).unwrap();
    key(&mut e, "type");
    e.str("inventory_page").unwrap();
    key(&mut e, "index");
    e.u64(index).unwrap();
    key(&mut e, "entries");
    e.array(entries.len() as u64).unwrap();
    for v in entries {
        e.map(4).unwrap();
        key(&mut e, "type");
        e.str(&v.kind).unwrap();
        key(&mut e, "id");
        e.bytes(&v.id).unwrap();
        key(&mut e, "record_sha256");
        e.bytes(&v.hash).unwrap();
        key(&mut e, "logical_size");
        e.u64(v.size).unwrap();
    }
    e.into_writer()
}
fn encode_end(
    records: u64,
    attachments: u64,
    logical: u64,
    pages: [u8; 32],
    attachment_bytes: u64,
) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.map(6).unwrap();
    key(&mut e, "type");
    e.str("manifest_end").unwrap();
    key(&mut e, "record_count");
    e.u64(records).unwrap();
    key(&mut e, "attachment_count");
    e.u64(attachments).unwrap();
    key(&mut e, "logical_bytes");
    e.u64(logical).unwrap();
    key(&mut e, "inventory_pages_sha256");
    e.bytes(&pages).unwrap();
    key(&mut e, "attachment_bytes");
    e.u64(attachment_bytes).unwrap();
    e.into_writer()
}

fn decode_data<'a>(
    record: &'a [u8],
    expected: &str,
) -> Result<([u8; 16], &'a [u8]), HumanCommitError> {
    let mut d = Decoder::new(record);
    expect_map(&mut d, 3)?;
    expect_key(&mut d, "type")?;
    if d.str().map_err(invalid)? != expected {
        return Err(HumanCommitError::InvalidInput);
    }
    expect_key(&mut d, "id")?;
    let id = decode_fixed(&mut d)?;
    expect_key(&mut d, "payload")?;
    let payload = d.bytes().map_err(invalid)?;
    if d.position() != record.len() {
        return Err(HumanCommitError::InvalidInput);
    }
    Ok((id, payload))
}
fn decode_item_full(bytes: &[u8]) -> Result<([u8; 16], String, String), HumanCommitError> {
    let mut d = Decoder::new(bytes);
    expect_array(&mut d, 3)?;
    let visible = decode_fixed(&mut d)?;
    let kind = d.str().map_err(invalid)?.to_owned();
    let status = d.str().map_err(invalid)?.to_owned();
    if !matches!(
        kind.as_str(),
        "password" | "totp" | "passkey" | "ssh" | "token" | "note" | "file"
    ) || !matches!(status.as_str(), "active" | "trash")
        || d.position() != bytes.len()
    {
        return Err(HumanCommitError::InvalidInput);
    }
    Ok((visible, kind, status))
}
fn decode_revision_full(
    bytes: &[u8],
) -> Result<([u8; 16], [u8; 16], i64, LogicalRecord), HumanCommitError> {
    let mut d = Decoder::new(bytes);
    expect_array(&mut d, 4)?;
    let item = decode_fixed(&mut d)?;
    let issuer = decode_fixed(&mut d)?;
    let modified = d.i64().map_err(invalid)?;
    let descriptor = d.bytes().map_err(invalid)?;
    let record = LogicalRecord::from_descriptor_bytes(descriptor)?;
    if d.position() != bytes.len() {
        return Err(HumanCommitError::InvalidInput);
    }
    Ok((item, issuer, modified, record))
}
fn decode_attachment(bytes: &[u8]) -> Result<DecodedAttachment, HumanCommitError> {
    let (_, revision, attachment, size, hash, chunks) = decode_attachment_full(bytes)?;
    Ok((revision, attachment, size, hash, chunks))
}
fn decode_attachment_full(bytes: &[u8]) -> Result<DecodedAttachmentFull, HumanCommitError> {
    let mut d = Decoder::new(bytes);
    expect_array(&mut d, 8)?;
    let item = decode_fixed(&mut d)?;
    let revision = decode_fixed(&mut d)?;
    let attachment = decode_fixed(&mut d)?;
    let _ = d.str().map_err(invalid)?;
    let _ = d.str().map_err(invalid)?;
    let size = d.u64().map_err(invalid)?;
    let hash = decode_fixed(&mut d)?;
    let chunks = d.u64().map_err(invalid)?;
    let expected_chunks = size.max(1).div_ceil(CHUNK as u64);
    if size > MAX_FILE_BYTES
        || chunks != expected_chunks
        || chunks > 16 * 1024
        || d.position() != bytes.len()
    {
        return Err(HumanCommitError::InvalidInput);
    }
    Ok((item, revision, attachment, size, hash, chunks))
}
fn decode_attachment_chunk(bytes: &[u8]) -> Result<DecodedAttachmentChunk<'_>, HumanCommitError> {
    let mut d = Decoder::new(bytes);
    expect_array(&mut d, 4)?;
    let revision = decode_fixed(&mut d)?;
    let attachment = decode_fixed(&mut d)?;
    let index = d.u64().map_err(invalid)?;
    let content = d.bytes().map_err(invalid)?;
    if d.position() != bytes.len() {
        return Err(HumanCommitError::InvalidInput);
    }
    Ok((revision, attachment, index, content))
}
fn decode_authority_history(bytes: &[u8]) -> Result<([u8; 32], Vec<[u8; 32]>), HumanCommitError> {
    let mut d = Decoder::new(bytes);
    expect_array(&mut d, 13)?;
    let event_digest = decode_fixed(&mut d)?;
    let _: [u8; 16] = decode_fixed(&mut d)?;
    let _: [u8; 16] = decode_fixed(&mut d)?;
    if d.i64().map_err(invalid)? <= 0 || d.i64().map_err(invalid)? <= 0 {
        return Err(HumanCommitError::InvalidInput);
    }
    let mut references = Vec::new();
    if d.datatype().map_err(invalid)? == Type::Null {
        d.null().map_err(invalid)?;
    } else {
        references.push(decode_fixed(&mut d)?);
    }
    let parents = d.bytes().map_err(invalid)?;
    let mut parent_decoder = Decoder::new(parents);
    let count = array_len(&mut parent_decoder)?;
    if count > 4096 {
        return Err(HumanCommitError::InvalidInput);
    }
    for _ in 0..count {
        references.push(decode_fixed(&mut parent_decoder)?);
    }
    if parent_decoder.position() != parents.len() {
        return Err(HumanCommitError::InvalidInput);
    }
    let _ = d.str().map_err(invalid)?;
    let _: [u8; 16] = decode_fixed(&mut d)?;
    if d.i64().map_err(invalid)? <= 0 {
        return Err(HumanCommitError::InvalidInput);
    }
    let event = d.bytes().map_err(invalid)?;
    if d.datatype().map_err(invalid)? == Type::Null {
        d.null().map_err(invalid)?;
    } else {
        let _: [u8; 64] = decode_fixed(&mut d)?;
    }
    let _: [u8; 64] = decode_fixed(&mut d)?;
    if d.position() != bytes.len() || digest(event) != event_digest {
        return Err(HumanCommitError::Integrity);
    }
    references.sort_unstable();
    references.dedup();
    Ok((event_digest, references))
}
fn peek_type(bytes: &[u8]) -> Result<String, HumanCommitError> {
    let mut d = Decoder::new(bytes);
    let _ = d
        .map()
        .map_err(invalid)?
        .ok_or(HumanCommitError::InvalidInput)?;
    expect_key(&mut d, "type")?;
    Ok(d.str().map_err(invalid)?.to_owned())
}
fn is_data_type(value: &str) -> bool {
    matches!(
        value,
        "item"
            | "revision"
            | "partial_history"
            | "attachment"
            | "attachment_chunk"
            | "organization"
            | "settings"
            | "audit_bundle"
            | "authority_history"
            | "identity_metadata"
    )
}
fn frame_record(record: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(record.len())
        .expect("records are bounded below u32::MAX")
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(record);
    out
}
fn derived_id(domain: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mut state = DigestState::new().expect("libsodium initialized");
    state.update(domain);
    for part in parts {
        state.update(&(part.len() as u64).to_be_bytes());
        state.update(part);
    }
    state.finish()[..16].try_into().unwrap()
}
fn current_frontier(tx: &Transaction<'_>) -> Result<[u8; 32], HumanCommitError> {
    Ok(tx
        .query_row(
            "SELECT event_digest FROM authority_events ORDER BY rowid DESC LIMIT 1",
            [],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .map_or([0; 32], |v| fixed(&v).unwrap_or([0; 32])))
}
fn authority_checkpoint(tx: &Transaction<'_>) -> Result<[u8; 32], HumanCommitError> {
    let mut state = DigestState::new()?;
    let mut s = tx.prepare("SELECT event_digest FROM authority_events ORDER BY event_digest")?;
    let mut rows = s.query([])?;
    while let Some(row) = rows.next()? {
        let v: Vec<u8> = row.get(0)?;
        if v.len() != 32 {
            return Err(HumanCommitError::Integrity);
        }
        state.update(&v);
    }
    Ok(state.finish())
}
fn now_us() -> Result<i64, HumanCommitError> {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HumanCommitError::InvalidCommand)?;
    i64::try_from(d.as_micros()).map_err(invalid)
}
fn fixed<const N: usize>(value: &[u8]) -> Result<[u8; N], HumanCommitError> {
    value.try_into().map_err(invalid)
}
fn decode_fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N], HumanCommitError> {
    fixed(d.bytes().map_err(invalid)?)
}
fn array_len(d: &mut Decoder<'_>) -> Result<usize, HumanCommitError> {
    usize::try_from(
        d.array()
            .map_err(invalid)?
            .ok_or(HumanCommitError::InvalidInput)?,
    )
    .map_err(invalid)
}
fn expect_map(d: &mut Decoder<'_>, n: u64) -> Result<(), HumanCommitError> {
    if d.map().map_err(invalid)? != Some(n) {
        return Err(HumanCommitError::InvalidInput);
    }
    Ok(())
}
fn expect_array(d: &mut Decoder<'_>, n: u64) -> Result<(), HumanCommitError> {
    if d.array().map_err(invalid)? != Some(n) {
        return Err(HumanCommitError::InvalidInput);
    }
    Ok(())
}
fn expect_key(d: &mut Decoder<'_>, expected: &str) -> Result<(), HumanCommitError> {
    if d.datatype().map_err(invalid)? != Type::String || d.str().map_err(invalid)? != expected {
        return Err(HumanCommitError::InvalidInput);
    }
    Ok(())
}
fn key(e: &mut Encoder<Vec<u8>>, value: &str) {
    e.str(value).unwrap();
}
fn invalid<T>(_: T) -> HumanCommitError {
    HumanCommitError::InvalidInput
}

fn to_i64(value: u64) -> Result<i64, HumanCommitError> {
    i64::try_from(value).map_err(invalid)
}

pub(crate) fn restore_graph_digest(
    tx: &Transaction<'_>,
    transaction_id: [u8; 16],
    source_revision: [u8; 16],
    package: &[u8],
) -> Result<[u8; 32], HumanCommitError> {
    let mut state = DigestState::new()?;
    state.update(b"pm/staged-stream/v1");
    state.update(&u64::try_from(package.len()).map_err(invalid)?.to_be_bytes());
    state.update(package);
    let mut streams = tx.prepare(
        "SELECT source_attachment,target_attachment,header,chunk_count FROM backup_restore_streams WHERE transaction_id=?1 AND source_revision=?2 ORDER BY target_attachment",
    )?;
    let rows = streams
        .query_map(
            params![transaction_id.as_slice(), source_revision.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    for (_, target, header, count) in &rows {
        state.update(target);
        state.update(&u64::try_from(header.len()).map_err(invalid)?.to_be_bytes());
        state.update(header);
        state.update(&count.to_be_bytes());
    }
    for (source, target, _, count) in rows {
        for index in 0..count {
            let frame: Vec<u8> = tx.query_row(
                "SELECT ciphertext FROM backup_restore_stream_chunks WHERE transaction_id=?1 AND source_revision=?2 AND source_attachment=?3 AND chunk_index=?4",
                params![transaction_id.as_slice(),source_revision.as_slice(),source,index],|row|row.get(0),
            )?;
            state.update(&target);
            state.update(&index.to_be_bytes());
            state.update(&u64::try_from(frame.len()).map_err(invalid)?.to_be_bytes());
            state.update(&frame);
        }
    }
    Ok(state.finish())
}

pub(crate) fn restore_batch_digest(
    tx: &Transaction<'_>,
    transaction_id: [u8; 16],
) -> Result<[u8; 32], HumanCommitError> {
    let mut state = DigestState::new()?;
    state.update(b"pm/backup-restore-staging/v1");
    for query in [
        "SELECT target_item,target_visible_revision,item_kind,status FROM backup_restore_items WHERE transaction_id=?1 ORDER BY target_item",
        "SELECT target_revision,target_item,object_digest FROM backup_restore_revisions WHERE transaction_id=?1 ORDER BY target_revision",
        "SELECT record_type,record_id,package FROM backup_restore_history WHERE transaction_id=?1 ORDER BY record_type,record_id",
    ] {
        let mut statement = tx.prepare(query)?;
        let column_count = statement.column_count();
        let mut rows = statement.query([transaction_id.as_slice()])?;
        while let Some(row) = rows.next()? {
            for index in 0..column_count {
                match row.get_ref(index)? {
                    rusqlite::types::ValueRef::Null => state.update(&[0]),
                    rusqlite::types::ValueRef::Integer(value) => {
                        state.update(&[1]);
                        state.update(&value.to_be_bytes());
                    }
                    rusqlite::types::ValueRef::Text(value)
                    | rusqlite::types::ValueRef::Blob(value) => {
                        state.update(&[2]);
                        state.update(&u64::try_from(value.len()).map_err(invalid)?.to_be_bytes());
                        state.update(value);
                    }
                    rusqlite::types::ValueRef::Real(_) => return Err(HumanCommitError::Integrity),
                }
            }
        }
    }
    Ok(state.finish())
}

pub(crate) fn restore_event_count(
    tx: &Transaction<'_>,
    transaction_id: [u8; 16],
) -> Result<u64, HumanCommitError> {
    let revisions: i64 = tx.query_row(
        "SELECT count(*) FROM backup_restore_revisions WHERE transaction_id=?1",
        [transaction_id.as_slice()],
        |row| row.get(0),
    )?;
    let trash: i64 = tx.query_row(
        "SELECT count(*) FROM backup_restore_items WHERE transaction_id=?1 AND status='trash'",
        [transaction_id.as_slice()],
        |row| row.get(0),
    )?;
    let revisions = u64::try_from(revisions).map_err(invalid)?;
    let trash = u64::try_from(trash).map_err(invalid)?;
    revisions
        .checked_add(trash)
        .ok_or(HumanCommitError::InvalidInput)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    result
}

fn write_base64(output: &mut dyn Write, bytes: &[u8]) -> Result<(), HumanCommitError> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = [0_u8; 4096];
    let mut source = 0;
    while source < bytes.len() {
        let available = (bytes.len() - source).min((encoded.len() / 4) * 3);
        let count = available - (available % 3);
        let count = if count == 0 { available } else { count };
        let chunk = &bytes[source..source + count];
        let mut target = 0;
        for group in chunk.chunks(3) {
            let a = group[0];
            let b = group.get(1).copied().unwrap_or(0);
            let c = group.get(2).copied().unwrap_or(0);
            encoded[target] = ALPHABET[usize::from(a >> 2)];
            encoded[target + 1] = ALPHABET[usize::from(((a & 3) << 4) | (b >> 4))];
            encoded[target + 2] = if group.len() > 1 {
                ALPHABET[usize::from(((b & 15) << 2) | (c >> 6))]
            } else {
                b'='
            };
            encoded[target + 3] = if group.len() > 2 {
                ALPHABET[usize::from(c & 63)]
            } else {
                b'='
            };
            target += 4;
        }
        output.write_all(&encoded[..target])?;
        source += count;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{MAX_FILE_BYTES, decode_attachment, encode_attachment};

    #[test]
    fn attachment_metadata_accepts_16_gib_and_rejects_one_byte_more_without_allocating_it() {
        let at_limit = encode_attachment(
            [1; 16],
            [2; 16],
            [3; 16],
            "limit.bin",
            "application/octet-stream",
            MAX_FILE_BYTES,
            [4; 32],
            16 * 1024,
        );
        assert!(decode_attachment(&at_limit).is_ok());
        let above = encode_attachment(
            [1; 16],
            [2; 16],
            [3; 16],
            "above.bin",
            "application/octet-stream",
            MAX_FILE_BYTES + 1,
            [4; 32],
            16 * 1024 + 1,
        );
        assert!(decode_attachment(&above).is_err());
    }
}
