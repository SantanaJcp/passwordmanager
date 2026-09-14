// SPDX-License-Identifier: AGPL-3.0-only

//! Atomic persistence for already-encrypted vault objects.

mod attempts;
mod audit;
mod authorization;
mod backup;
mod content;
mod history;
mod human;
mod migration;
mod onepux;
mod passkey;

mod reducer;

pub use attempts::{
    AttemptError, AttemptLease, AttemptOutcome, AttemptSnapshot, AttemptState, AttemptVault,
    IdempotencyKey, SshLease, StartAttempt, TotpLease,
};
pub use audit::{
    AuditAction, AuditActorKind, AuditDeviceCustody, AuditDiscontinuity, AuditEvent, AuditOutcome,
    AuditPurgeScope, AuditQuery, AuditRecordView, AutonomousAuditVault, PreparedAuditPurge,
};
pub use authorization::{
    AgentEnrollment, AgentIdentity, AgentPeer, AuthorityEventHeader, AuthorizationError,
    AuthorizationReason, DelegatedCredential, DelegatedVault, PreparedAgentEnrollment,
};
pub use backup::{BackupArchive, BackupSummary, PreparedBackupRestore};
pub use content::{
    Attachment, AuthRecord, CustomField, Destination, GeneratedPassword, GeneratorConfig,
    HumanMetadata, LogicalRecord, LogicalValue, PasswordRng, PrivateKeyFormat, RecordKind,
    SearchHit, SearchQuery, SourceEncoding, SourceField, TotpAlgorithm,
};
pub use history::{HistoryEntry, ItemHistory, ItemPurgeScope, PreparedItemPurge};
pub use human::{
    AttachmentReader, HumanCatalogEntry, HumanChannel, HumanCommitError, HumanReceipt, HumanVault,
    PasswordRecord, PendingRecoveryChange, PreparedHumanCommand,
};
pub use migration::{
    CsvDelimiter, CsvEncoding, CsvField, CsvImportDecision, CsvImportPreview, CsvImportProfile,
    CsvImportReport, CsvMapping, CsvRecordPreview, CsvRowPreview, CsvRowStatus, PreparedCsvImport,
};
pub use onepux::{OnePuxImportPreview, OnePuxRecordPreview};
pub use passkey::{
    HumanVerification, PasskeyAssertion, PasskeyError, PasskeyOperation, PasskeyPrompt,
    PasskeyProvider, PasskeyPublicCredential, PasskeyRequest, PasskeyStatus,
    PreparedPasskeyRegistration, UserVerificationRequirement,
};

pub use reducer::{
    AcceptedPrefix, CausalEventBody, CausalEventDraft, CausalEventKind, CausalReducer,
    ItemLifecycle, PurgeScopeKind, ReceivedCiphertextAttachment, ReceivedCiphertextGraph,
    ReceivedCiphertextStream, ReducedItem, ReducedView, ReductionError, SignedCausalEvent,
};

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use pm_crypto::{
    CreatedRoot, CryptoError, KdfProfile, RecoveryCode, RootBundle, TrustedRoot, UnlockedRoot,
    create_human_root, open_human_root,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

const FORMAT_VERSION: i64 = 1;
const SUITE: i64 = 1;
const ROOT_KIND: &str = "human-root-bundle-v1";
const MAX_ROOT_BUNDLE_BYTES: i64 = 16 * 1024 * 1024;
static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub enum VaultError {
    AlreadyExists,
    Crypto(CryptoError),
    InvalidFormat,
    Io(std::io::Error),
    Storage(rusqlite::Error),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists => f.write_str("vault already exists"),
            Self::Crypto(error) => write!(f, "{error}"),
            Self::InvalidFormat => f.write_str("invalid or incompatible vault storage"),
            Self::Io(error) => write!(f, "vault I/O failed: {error}"),
            Self::Storage(error) => write!(f, "vault storage failed: {error}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<CryptoError> for VaultError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<std::io::Error> for VaultError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for VaultError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Storage(value)
    }
}

/// An in-memory enrollment that cannot be persisted until its recovery code
/// has been reintroduced successfully.
pub struct PendingVault {
    created: CreatedRoot,
    trusted_root: TrustedRoot,
}

impl PendingVault {
    /// Prepares independent root material entirely in memory.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid inputs or unavailable cryptographic resources.
    pub fn new(password: &[u8], profile: KdfProfile) -> Result<Self, VaultError> {
        let created = create_human_root(password, profile)?;
        let trusted_root = *created.bundle().trusted_root();
        Ok(Self {
            created,
            trusted_root,
        })
    }

    #[must_use]
    pub const fn recovery_code(&self) -> &RecoveryCode {
        self.created.recovery_code()
    }

    #[must_use]
    pub const fn trusted_root(&self) -> &TrustedRoot {
        &self.trusted_root
    }

    /// Atomically creates a new local vault. An existing target is never replaced.
    ///
    /// # Errors
    ///
    /// Returns an error unless recovery is confirmed, or if atomic durable
    /// persistence cannot complete without replacing the target.
    pub fn persist(self, path: &Path, reintroduced: &RecoveryCode) -> Result<(), VaultError> {
        let bundle = self
            .created
            .into_bundle_after_recovery_confirmation(reintroduced)?;
        persist_new(path, &bundle)
    }
}

/// Non-secret proof that the password path opened the root and matched the
/// separately stored trusted human root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenedVault {
    trusted_root: TrustedRoot,
}

impl OpenedVault {
    #[must_use]
    pub const fn trusted_root(&self) -> &TrustedRoot {
        &self.trusted_root
    }
}

/// Opens the database read-only, rejects its public format before running the
/// KDF, and authenticates all root envelopes without mutating the file.
///
/// # Errors
///
/// Returns an error for incompatible/invalid storage, wrong passwords, altered
/// envelopes, or I/O failures.
pub fn open_vault(path: &Path, password: &[u8]) -> Result<OpenedVault, VaultError> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    connection.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;")?;
    let (bundle, trusted_root) = load_and_validate_bundle(&connection)?;
    let unlocked = open_human_root(&bundle, password)?;
    if unlocked.vault_id() != trusted_root.vault_id()
        || unlocked.human_public_key() != trusted_root.public_key()
    {
        return Err(VaultError::InvalidFormat);
    }
    Ok(OpenedVault { trusted_root })
}

/// Opens and validates only the public vault identity, without opening a human
/// root or running the password KDF.
///
/// # Errors
///
/// Returns an error for incompatible, incomplete or altered public metadata
/// and root envelopes.
pub fn open_vault_identity(path: &Path) -> Result<OpenedVault, VaultError> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    connection.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;")?;
    let (_, trusted_root) = load_and_validate_bundle(&connection)?;
    Ok(OpenedVault { trusted_root })
}

fn load_and_validate_bundle(
    connection: &Connection,
) -> Result<(RootBundle, TrustedRoot), VaultError> {
    let metadata = connection
        .query_row(
            "SELECT format_version, suite, vault_id, authority_epoch, human_public_key \
             FROM vault_metadata WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or(VaultError::InvalidFormat)?;
    if metadata.0 != FORMAT_VERSION
        || metadata.1 != SUITE
        || metadata.2.len() != 16
        || metadata.3 != 1
        || metadata.4.len() != 32
    {
        return Err(VaultError::InvalidFormat);
    }
    let row_count: i64 =
        connection.query_row("SELECT count(*) FROM encrypted_objects", [], |row| {
            row.get(0)
        })?;
    let bundle_size: i64 = connection
        .query_row(
            "SELECT length(value) FROM encrypted_objects WHERE kind = ?1",
            [ROOT_KIND],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(VaultError::InvalidFormat)?;
    if row_count != 1 || !(1..=MAX_ROOT_BUNDLE_BYTES).contains(&bundle_size) {
        return Err(VaultError::InvalidFormat);
    }
    let bytes: Vec<u8> = connection.query_row(
        "SELECT value FROM encrypted_objects WHERE kind = ?1",
        [ROOT_KIND],
        |row| row.get(0),
    )?;
    let bundle = RootBundle::from_bytes(&bytes)?;
    if bundle.trusted_root().vault_id().as_slice() != metadata.2
        || i64::try_from(bundle.trusted_root().epoch()).ok() != Some(metadata.3)
        || bundle.trusted_root().public_key().as_slice() != metadata.4
    {
        return Err(VaultError::InvalidFormat);
    }
    let trusted_root = *bundle.trusted_root();
    Ok((bundle, trusted_root))
}

fn unlock_root(connection: &Connection, password: &[u8]) -> Result<UnlockedRoot, VaultError> {
    let (bundle, trusted_root) = load_and_validate_bundle(connection)?;
    let unlocked = open_human_root(&bundle, password)?;
    if unlocked.vault_id() != trusted_root.vault_id()
        || unlocked.human_public_key() != trusted_root.public_key()
    {
        return Err(VaultError::InvalidFormat);
    }
    Ok(unlocked)
}

#[allow(clippy::too_many_lines)]
fn persist_new(path: &Path, bundle: &RootBundle) -> Result<(), VaultError> {
    if path.exists() {
        return Err(VaultError::AlreadyExists);
    }
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let (temporary_path, temporary_file) = create_temporary(parent, path)?;
    let wal_path = PathBuf::from(format!("{}-wal", temporary_path.display()));
    let shm_path = PathBuf::from(format!("{}-shm", temporary_path.display()));
    let result = (|| {
        drop(temporary_file);
        let mut connection =
            Connection::open_with_flags(&temporary_path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if journal_mode != "wal" {
            return Err(VaultError::InvalidFormat);
        }
        connection.execute_batch(
            "PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
             PRAGMA trusted_schema=OFF;
             CREATE TABLE vault_metadata (
               singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
               format_version INTEGER NOT NULL,
               suite INTEGER NOT NULL,
               vault_id BLOB NOT NULL CHECK (length(vault_id) = 16),
               authority_epoch INTEGER NOT NULL,
               human_public_key BLOB NOT NULL CHECK (length(human_public_key) = 32)
             ) STRICT;
             CREATE TABLE encrypted_objects (
               kind TEXT PRIMARY KEY,
               value BLOB NOT NULL CHECK (length(value) BETWEEN 1 AND 16777216)
             ) STRICT;
             CREATE TABLE vault_items (
               item_id BLOB PRIMARY KEY CHECK (length(item_id) = 16),
               visible_revision BLOB NOT NULL CHECK (length(visible_revision) = 16),
               kind TEXT NOT NULL CHECK (kind IN ('password','totp','passkey','ssh','token','note','file')),
               status TEXT NOT NULL CHECK (status IN ('active', 'trash'))
             ) STRICT;
             CREATE TABLE revision_parts (
               revision_id BLOB PRIMARY KEY CHECK (length(revision_id) = 16),
               item_id BLOB NOT NULL CHECK (length(item_id) = 16),
               package BLOB NOT NULL CHECK (length(package) BETWEEN 1 AND 16777216)
             ) STRICT;
             CREATE TABLE attachment_parts (
               attachment_id BLOB NOT NULL CHECK (length(attachment_id) = 16),
               revision_id BLOB NOT NULL CHECK (length(revision_id) = 16),
               package BLOB NOT NULL CHECK (length(package) BETWEEN 1 AND 17825792),
               PRIMARY KEY (attachment_id, revision_id)
             ) STRICT;
             CREATE TABLE attachment_streams (
               attachment_id BLOB NOT NULL CHECK (length(attachment_id) = 16), revision_id BLOB NOT NULL CHECK (length(revision_id) = 16),
               header BLOB NOT NULL CHECK (length(header) BETWEEN 1 AND 16384), chunk_count INTEGER NOT NULL CHECK (chunk_count > 0),
               PRIMARY KEY (attachment_id, revision_id)
             ) STRICT;
             CREATE TABLE attachment_stream_chunks (
               attachment_id BLOB NOT NULL CHECK (length(attachment_id) = 16), revision_id BLOB NOT NULL CHECK (length(revision_id) = 16),
               chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0), ciphertext BLOB NOT NULL CHECK (length(ciphertext) BETWEEN 21 AND 1048597),
               PRIMARY KEY (attachment_id, revision_id, chunk_index)
             ) STRICT;
             CREATE TABLE purged_items (
               item_id BLOB PRIMARY KEY CHECK (length(item_id) = 16),
               purge_event_digest BLOB NOT NULL CHECK (length(purge_event_digest) = 32),
               revision_count INTEGER NOT NULL CHECK (revision_count >= 0),
               attachment_count INTEGER NOT NULL CHECK (attachment_count >= 0),
               encrypted_bytes INTEGER NOT NULL CHECK (encrypted_bytes >= 0)
             ) STRICT;
             CREATE TABLE purged_revisions (
               revision_id BLOB PRIMARY KEY CHECK (length(revision_id) = 16),
               item_id BLOB NOT NULL CHECK (length(item_id) = 16),
               purge_event_digest BLOB NOT NULL CHECK (length(purge_event_digest) = 32)
             ) STRICT;
             CREATE TRIGGER reject_purged_item_revision BEFORE INSERT ON revision_parts
             WHEN EXISTS(SELECT 1 FROM purged_items WHERE item_id=NEW.item_id)
             BEGIN SELECT RAISE(ABORT,'purged item is terminal'); END;
             CREATE TRIGGER reject_purged_revision BEFORE INSERT ON revision_parts
             WHEN EXISTS(SELECT 1 FROM purged_revisions WHERE revision_id=NEW.revision_id)
             BEGIN SELECT RAISE(ABORT,'purged revision is terminal'); END;
             CREATE TRIGGER reject_purged_item BEFORE INSERT ON vault_items
             WHEN EXISTS(SELECT 1 FROM purged_items WHERE item_id=NEW.item_id)
             BEGIN SELECT RAISE(ABORT,'purged item is terminal'); END;
             CREATE TABLE authority_events (
               event_digest BLOB PRIMARY KEY CHECK (length(event_digest) = 32),
               event_id BLOB NOT NULL UNIQUE CHECK (length(event_id) = 16),
               transaction_id BLOB NOT NULL UNIQUE CHECK (length(transaction_id) = 16),
               issuer_device BLOB NOT NULL CHECK (length(issuer_device) = 16),
               issuer_generation INTEGER NOT NULL CHECK (issuer_generation > 0),
               seq INTEGER NOT NULL CHECK (seq > 0),
               previous_digest BLOB CHECK (previous_digest IS NULL OR length(previous_digest) = 32),
               parents BLOB NOT NULL CHECK (length(parents) BETWEEN 1 AND 262144),
               kind TEXT NOT NULL,
               subject BLOB NOT NULL CHECK (length(subject) = 16),
               subject_generation INTEGER NOT NULL CHECK (subject_generation > 0),
               event BLOB NOT NULL CHECK (length(event) BETWEEN 1 AND 262144),
               human_signature BLOB CHECK (human_signature IS NULL OR length(human_signature) = 64),
               device_signature BLOB NOT NULL CHECK (length(device_signature) = 64)
             ) STRICT;
             CREATE INDEX authority_event_slot ON authority_events(issuer_device,issuer_generation,seq);
             CREATE TABLE outbox (
               event_digest BLOB PRIMARY KEY CHECK (length(event_digest) = 32),
               event BLOB NOT NULL CHECK (length(event) BETWEEN 1 AND 262144)
             ) STRICT;
             CREATE TABLE human_challenges (
               challenge BLOB PRIMARY KEY CHECK (length(challenge) = 32),
               transaction_id BLOB NOT NULL UNIQUE CHECK (length(transaction_id) = 16),
               command BLOB NOT NULL CHECK (length(command) BETWEEN 1 AND 262144),
               body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
               expected_state BLOB NOT NULL CHECK (length(expected_state) = 32),
               expires_at_us INTEGER NOT NULL,
               consumed INTEGER NOT NULL DEFAULT 0 CHECK (consumed IN (0, 1))
             ) STRICT;
             CREATE TABLE human_staging (
               transaction_id BLOB PRIMARY KEY CHECK (length(transaction_id) = 16),
               operation TEXT NOT NULL CHECK (operation IN ('item_write', 'item_lifecycle', 'history_restore', 'item_purge', 'audit_purge', 'availability_change', 'identity_change', 'import_commit', 'backup_restore', 'root_rotation')),
               event_kind TEXT NOT NULL CHECK (event_kind IN ('item-revision', 'trash', 'restore', 'purge-item', 'purge-revisions', 'audit-purge', 'agent-grant', 'agent-revoke', 'enable', 'disable', 'suspend', 'resume', 'device-retire', 'import-batch', 'backup-restore', 'root-password-rotate', 'root-recovery-rotate')),
               item_id BLOB NOT NULL CHECK (length(item_id) = 16),
               revision_id BLOB CHECK (revision_id IS NULL OR length(revision_id) = 16),
               body BLOB NOT NULL CHECK (length(body) BETWEEN 1 AND 262144),
               package BLOB CHECK (package IS NULL OR length(package) BETWEEN 1 AND 16777216),
               item_kind TEXT CHECK (item_kind IS NULL OR item_kind IN ('password','totp','passkey','ssh','token','note','file')),
               attachments BLOB CHECK (attachments IS NULL OR length(attachments) BETWEEN 1 AND 18874368),
               audit_generation INTEGER CHECK (audit_generation IS NULL OR audit_generation > 0),
               audit_through_seq INTEGER CHECK (audit_through_seq IS NULL OR audit_through_seq > 0),
               subject_generation INTEGER CHECK (subject_generation IS NULL OR subject_generation > 0),
               authority_body BLOB CHECK (authority_body IS NULL OR length(authority_body) BETWEEN 1 AND 262144),
               staged_grant BLOB CHECK (staged_grant IS NULL OR length(staged_grant) BETWEEN 1 AND 16777216)
             ) STRICT;
             CREATE TABLE human_staging_streams (
               transaction_id BLOB NOT NULL CHECK (length(transaction_id) = 16), attachment_id BLOB NOT NULL CHECK (length(attachment_id) = 16),
               header BLOB NOT NULL CHECK (length(header) BETWEEN 1 AND 16384), chunk_count INTEGER NOT NULL CHECK (chunk_count > 0),
               PRIMARY KEY (transaction_id, attachment_id)
             ) STRICT;
             CREATE TABLE human_staging_stream_chunks (
               transaction_id BLOB NOT NULL CHECK (length(transaction_id) = 16), attachment_id BLOB NOT NULL CHECK (length(attachment_id) = 16),
               chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0), ciphertext BLOB NOT NULL CHECK (length(ciphertext) BETWEEN 21 AND 1048597),
               PRIMARY KEY (transaction_id, attachment_id, chunk_index)
             ) STRICT;
             CREATE TABLE import_staging_batches (
               transaction_id BLOB PRIMARY KEY CHECK (length(transaction_id) = 16),
               batch_id BLOB NOT NULL UNIQUE CHECK (length(batch_id) = 16),
               source TEXT NOT NULL CHECK (source IN ('chrome','apple','mappable','1pux')),
               object_digest BLOB NOT NULL CHECK (length(object_digest) = 32),
               total INTEGER NOT NULL CHECK (total >= 0),
               new_items INTEGER NOT NULL CHECK (new_items >= 0),
               replaced INTEGER NOT NULL CHECK (replaced >= 0),
               skipped_exact INTEGER NOT NULL CHECK (skipped_exact >= 0),
               excluded INTEGER NOT NULL CHECK (excluded >= 0),
               preserved_fields INTEGER NOT NULL CHECK (preserved_fields >= 0),
               event_pages INTEGER NOT NULL CHECK (event_pages > 0)
             ) STRICT;
             CREATE TABLE import_staging_items (
               transaction_id BLOB NOT NULL CHECK (length(transaction_id) = 16),
               ordinal INTEGER NOT NULL CHECK (ordinal > 0),
               item_id BLOB NOT NULL CHECK (length(item_id) = 16),
               revision_id BLOB NOT NULL CHECK (length(revision_id) = 16),
               item_kind TEXT NOT NULL CHECK (item_kind IN ('password','totp','ssh','token','note','file')),
               package BLOB NOT NULL CHECK (length(package) BETWEEN 1 AND 16777216),
               replacement INTEGER NOT NULL CHECK (replacement IN (0,1)),
               PRIMARY KEY (transaction_id, ordinal),
               UNIQUE (transaction_id, item_id)
             ) STRICT;
             CREATE TABLE import_staging_streams (
               transaction_id BLOB NOT NULL CHECK (length(transaction_id) = 16),
               ordinal INTEGER NOT NULL CHECK (ordinal > 0),
               attachment_id BLOB NOT NULL CHECK (length(attachment_id) = 16),
               header BLOB NOT NULL CHECK (length(header) BETWEEN 1 AND 16384),
               chunk_count INTEGER NOT NULL CHECK (chunk_count > 0),
               PRIMARY KEY (transaction_id,ordinal,attachment_id)
             ) STRICT;
             CREATE TABLE import_staging_stream_chunks (
               transaction_id BLOB NOT NULL CHECK (length(transaction_id) = 16),
               ordinal INTEGER NOT NULL CHECK (ordinal > 0),
               attachment_id BLOB NOT NULL CHECK (length(attachment_id) = 16),
               chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),
               ciphertext BLOB NOT NULL CHECK (length(ciphertext) BETWEEN 21 AND 1048597),
               PRIMARY KEY (transaction_id,ordinal,attachment_id,chunk_index)
             ) STRICT;
             CREATE TABLE import_reports (
               batch_id BLOB PRIMARY KEY CHECK (length(batch_id) = 16),
               transaction_id BLOB NOT NULL UNIQUE CHECK (length(transaction_id) = 16),
               source TEXT NOT NULL CHECK (source IN ('chrome','apple','mappable','1pux')),
               total INTEGER NOT NULL CHECK (total >= 0),
               new_items INTEGER NOT NULL CHECK (new_items >= 0),
               replaced INTEGER NOT NULL CHECK (replaced >= 0),
               skipped_exact INTEGER NOT NULL CHECK (skipped_exact >= 0),
               excluded INTEGER NOT NULL CHECK (excluded >= 0),
               preserved_fields INTEGER NOT NULL CHECK (preserved_fields >= 0),
               event_pages INTEGER NOT NULL CHECK (event_pages > 0),
               committed_at_us INTEGER NOT NULL
             ) STRICT;
             CREATE TABLE backup_restore_batches (
               transaction_id BLOB PRIMARY KEY CHECK(length(transaction_id)=16),
               backup_id BLOB NOT NULL CHECK(length(backup_id)=16),
               source_vault BLOB NOT NULL CHECK(length(source_vault)=16),
               object_digest BLOB NOT NULL CHECK(length(object_digest)=32),
               item_count INTEGER NOT NULL CHECK(item_count>=0),
               revision_count INTEGER NOT NULL CHECK(revision_count>=0),
               attachment_count INTEGER NOT NULL CHECK(attachment_count>=0),
               attachment_bytes INTEGER NOT NULL CHECK(attachment_bytes>=0),
               audit_bundles INTEGER NOT NULL CHECK(audit_bundles>=0),
               authority_events INTEGER NOT NULL CHECK(authority_events>=0),
               identity_metadata INTEGER NOT NULL CHECK(identity_metadata>=0)
             ) STRICT;
             CREATE TABLE backup_restore_items (
               transaction_id BLOB NOT NULL CHECK(length(transaction_id)=16),
               source_item BLOB NOT NULL CHECK(length(source_item)=16),
               target_item BLOB NOT NULL CHECK(length(target_item)=16),
               source_visible_revision BLOB NOT NULL CHECK(length(source_visible_revision)=16),
               target_visible_revision BLOB CHECK(target_visible_revision IS NULL OR length(target_visible_revision)=16),
               item_kind TEXT NOT NULL CHECK(item_kind IN ('password','totp','passkey','ssh','token','note','file')),
               status TEXT NOT NULL CHECK(status IN ('active','trash')),
               PRIMARY KEY(transaction_id,source_item), UNIQUE(transaction_id,target_item)
             ) STRICT;
             CREATE TABLE backup_restore_revisions (
               transaction_id BLOB NOT NULL CHECK(length(transaction_id)=16),
               source_revision BLOB NOT NULL CHECK(length(source_revision)=16),
               target_revision BLOB NOT NULL CHECK(length(target_revision)=16),
               target_item BLOB NOT NULL CHECK(length(target_item)=16),
               modified_at_us INTEGER NOT NULL,
               item_kind TEXT NOT NULL CHECK(item_kind IN ('password','totp','passkey','ssh','token','note','file')),
               package BLOB NOT NULL CHECK(length(package) BETWEEN 1 AND 16777216),
               object_digest BLOB NOT NULL CHECK(length(object_digest)=32),
               PRIMARY KEY(transaction_id,source_revision), UNIQUE(transaction_id,target_revision)
             ) STRICT;
             CREATE TABLE backup_restore_streams (
               transaction_id BLOB NOT NULL CHECK(length(transaction_id)=16),
               source_revision BLOB NOT NULL CHECK(length(source_revision)=16),
               source_attachment BLOB NOT NULL CHECK(length(source_attachment)=16),
               target_revision BLOB NOT NULL CHECK(length(target_revision)=16),
               target_attachment BLOB NOT NULL CHECK(length(target_attachment)=16),
               header BLOB NOT NULL CHECK(length(header) BETWEEN 1 AND 16384),
               chunk_count INTEGER NOT NULL CHECK(chunk_count>0),
               PRIMARY KEY(transaction_id,source_revision,source_attachment)
             ) STRICT;
             CREATE TABLE backup_restore_stream_chunks (
               transaction_id BLOB NOT NULL CHECK(length(transaction_id)=16),
               source_revision BLOB NOT NULL CHECK(length(source_revision)=16),
               source_attachment BLOB NOT NULL CHECK(length(source_attachment)=16),
               chunk_index INTEGER NOT NULL CHECK(chunk_index>=0),
               ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 21 AND 1048597),
               PRIMARY KEY(transaction_id,source_revision,source_attachment,chunk_index)
             ) STRICT;
             CREATE TABLE backup_restore_history (
               transaction_id BLOB NOT NULL CHECK(length(transaction_id)=16),
               record_type TEXT NOT NULL CHECK(record_type IN ('organization','settings','audit_bundle','authority_history','identity_metadata','partial_history')),
               record_id BLOB NOT NULL CHECK(length(record_id)=16),
               package BLOB NOT NULL CHECK(length(package) BETWEEN 1 AND 17825792),
               PRIMARY KEY(transaction_id,record_type,record_id)
             ) STRICT;
             CREATE TABLE imported_backup_history (
               source_vault BLOB NOT NULL CHECK(length(source_vault)=16),
               backup_id BLOB NOT NULL CHECK(length(backup_id)=16),
               record_type TEXT NOT NULL CHECK(record_type IN ('organization','settings','audit_bundle','authority_history','identity_metadata','partial_history')),
               record_id BLOB NOT NULL CHECK(length(record_id)=16),
               package BLOB NOT NULL CHECK(length(package) BETWEEN 1 AND 17825792),
               PRIMARY KEY(source_vault,backup_id,record_type,record_id)
             ) STRICT;
             CREATE TABLE human_receipts (
               transaction_id BLOB PRIMARY KEY CHECK (length(transaction_id) = 16),
               body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
               committed_heads BLOB NOT NULL CHECK (length(committed_heads) BETWEEN 1 AND 262144),
               committed_at_us INTEGER NOT NULL,
               outcome TEXT NOT NULL CHECK (outcome = 'committed')
             ) STRICT;
             CREATE TABLE audit_keys (
               device_id BLOB NOT NULL CHECK (length(device_id) = 16),
               generation INTEGER NOT NULL CHECK (generation > 0),
               human_envelope BLOB NOT NULL CHECK (length(human_envelope) BETWEEN 1 AND 16777216),
               device_envelope BLOB NOT NULL CHECK (length(device_envelope) BETWEEN 49 AND 16777216),
               encryption_public_key BLOB NOT NULL CHECK (length(encryption_public_key) = 32),
               signing_public_key BLOB NOT NULL CHECK (length(signing_public_key) = 32),
               human_signature BLOB NOT NULL CHECK (length(human_signature) = 64),
               PRIMARY KEY (device_id, generation)
             ) STRICT;
             CREATE TABLE audit_state (
               device_id BLOB PRIMARY KEY CHECK (length(device_id) = 16),
               generation INTEGER NOT NULL CHECK (generation > 0),
               seq INTEGER NOT NULL CHECK (seq > 0),
               last_hash BLOB NOT NULL CHECK (length(last_hash) = 32)
             ) STRICT;
             CREATE TABLE encrypted_audit_records (
               device_id BLOB NOT NULL CHECK (length(device_id) = 16),
               generation INTEGER NOT NULL CHECK (generation > 0),
               seq INTEGER NOT NULL CHECK (seq > 0),
               event_id BLOB NOT NULL UNIQUE CHECK (length(event_id) = 16),
               segment_id BLOB NOT NULL CHECK (length(segment_id) = 16),
               record BLOB NOT NULL CHECK (length(record) BETWEEN 1 AND 8192),
               signature BLOB NOT NULL CHECK (length(signature) = 64),
               record_hash BLOB NOT NULL CHECK (length(record_hash) = 32),
               PRIMARY KEY (device_id, generation, seq)
             ) STRICT;
             CREATE TABLE audit_segments (
               segment_id BLOB PRIMARY KEY CHECK (length(segment_id) = 16),
               device_id BLOB NOT NULL CHECK (length(device_id) = 16),
               generation INTEGER NOT NULL CHECK (generation > 0),
               first_seq INTEGER NOT NULL CHECK (first_seq > 0),
               last_seq INTEGER NOT NULL CHECK (last_seq >= first_seq),
               previous_hash BLOB NOT NULL CHECK (length(previous_hash) = 32),
               last_hash BLOB NOT NULL CHECK (length(last_hash) = 32),
               record_count INTEGER NOT NULL CHECK (record_count BETWEEN 0 AND 256),
               stored_bytes INTEGER NOT NULL CHECK (stored_bytes BETWEEN 0 AND 1048576),
               closed INTEGER NOT NULL CHECK (closed IN (0,1))
             ) STRICT;
             CREATE UNIQUE INDEX one_open_audit_segment ON audit_segments(device_id,generation) WHERE closed=0;
             CREATE TABLE audit_manifests (
               device_id BLOB NOT NULL CHECK (length(device_id) = 16),
               generation INTEGER NOT NULL CHECK (generation > 0),
               manifest_id BLOB NOT NULL CHECK (length(manifest_id) = 16),
               envelope BLOB NOT NULL CHECK (length(envelope) BETWEEN 1 AND 16777216),
               PRIMARY KEY (device_id,generation)
             ) STRICT;
             CREATE TABLE audit_purge_ranges (
               device_id BLOB NOT NULL CHECK (length(device_id) = 16),
               generation INTEGER NOT NULL CHECK (generation > 0),
               first_seq INTEGER NOT NULL CHECK (first_seq > 0),
               last_seq INTEGER NOT NULL CHECK (last_seq >= first_seq),
               purge_event_id BLOB NOT NULL CHECK (length(purge_event_id) = 16),
               PRIMARY KEY (device_id,generation,first_seq,last_seq)
             ) STRICT;
             CREATE TABLE agent_authorizations (
               subject_id BLOB NOT NULL CHECK (length(subject_id) = 16),
               generation INTEGER NOT NULL CHECK (generation > 0),
               request_id BLOB NOT NULL UNIQUE CHECK (length(request_id) = 16),
               transport_rpk BLOB NOT NULL UNIQUE CHECK (length(transport_rpk) = 44),
               label TEXT NOT NULL CHECK (length(CAST(label AS BLOB)) <= 256),
               environment_binding TEXT NOT NULL CHECK (length(CAST(environment_binding AS BLOB)) <= 256),
               grant_event_digest BLOB NOT NULL CHECK (length(grant_event_digest) = 32),
               revoke_event_digest BLOB CHECK (revoke_event_digest IS NULL OR length(revoke_event_digest) = 32),
               status TEXT NOT NULL CHECK (status IN ('active','revoked','superseded')),
               PRIMARY KEY (subject_id,generation)
             ) STRICT;
             CREATE TABLE delegated_state (
               singleton INTEGER PRIMARY KEY CHECK (singleton=1),
               status TEXT NOT NULL CHECK (status IN ('resumed','suspended')),
               event_digest BLOB NOT NULL CHECK (length(event_digest) = 32)
             ) STRICT;
             CREATE TABLE credential_authorizations (
               item_id BLOB PRIMARY KEY CHECK (length(item_id) = 16),
               revision_id BLOB NOT NULL CHECK (length(revision_id) = 16),
               status TEXT NOT NULL CHECK (status IN ('enabled','disabled')),
               event_digest BLOB NOT NULL CHECK (length(event_digest) = 32),
               control_package BLOB NOT NULL CHECK (length(control_package) BETWEEN 1 AND 16777216),
               grant BLOB NOT NULL CHECK (length(grant) BETWEEN 1 AND 16777216),
               grant_commitment BLOB NOT NULL CHECK (length(grant_commitment) = 32)
             ) STRICT;
             CREATE TABLE authentication_attempts (
               attempt_id BLOB PRIMARY KEY CHECK(length(attempt_id)=16),
               item_id BLOB NOT NULL CHECK(length(item_id)=16),
               revision_id BLOB NOT NULL CHECK(length(revision_id)=16),
               owner_subject BLOB NOT NULL CHECK(length(owner_subject)=16),
               owner_generation INTEGER NOT NULL CHECK(owner_generation>0),
               state TEXT NOT NULL CHECK(state IN ('created','running','waiting_for_human','succeeded','failed','cancelled','expired','indeterminate')),
               created_at_us INTEGER NOT NULL,
               expires_at_us INTEGER NOT NULL,
               terminal_at_us INTEGER,
               scope_digest BLOB NOT NULL UNIQUE CHECK(length(scope_digest)=32),
               params_digest BLOB NOT NULL CHECK(length(params_digest)=32),
               state_package BLOB CHECK(state_package IS NULL OR length(state_package) BETWEEN 1 AND 16777216),
               lease_token BLOB CHECK(lease_token IS NULL OR length(lease_token)=16),
               claimed_at_us INTEGER,
               provider_sent INTEGER NOT NULL DEFAULT 0 CHECK(provider_sent IN (0,1))
             ) STRICT;
             CREATE TABLE passkey_requests (
               request_id BLOB PRIMARY KEY CHECK (length(request_id)=16),
               request_digest BLOB NOT NULL CHECK (length(request_digest)=32),
               operation TEXT NOT NULL CHECK (operation IN ('create','get')),
               attempt_id BLOB CHECK (attempt_id IS NULL OR length(attempt_id)=16),
               request BLOB NOT NULL CHECK (length(request) BETWEEN 1 AND 262144),
               state TEXT NOT NULL CHECK (state IN ('waiting','complete')),
               item_id BLOB CHECK (item_id IS NULL OR length(item_id)=16),
               response BLOB CHECK (response IS NULL OR length(response) BETWEEN 1 AND 262144),
               created_at_us INTEGER NOT NULL,
               expires_at_us INTEGER NOT NULL CHECK (expires_at_us>created_at_us)
             ) STRICT;
             CREATE TABLE passkey_registration_staging (
               transaction_id BLOB PRIMARY KEY CHECK (length(transaction_id)=16),
               request_id BLOB NOT NULL CHECK (length(request_id)=16),
               item_id BLOB NOT NULL CHECK (length(item_id)=16),
               response BLOB NOT NULL CHECK (length(response) BETWEEN 1 AND 262144)
             ) STRICT;
             CREATE INDEX attempts_owner_state ON authentication_attempts(owner_subject,owner_generation,state);
             CREATE TABLE attempt_clock (
               singleton INTEGER PRIMARY KEY CHECK(singleton=1),
               max_wall_us INTEGER NOT NULL
             ) STRICT;",
        )?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO vault_metadata
             (singleton, format_version, suite, vault_id, authority_epoch, human_public_key)
             VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            params![
                FORMAT_VERSION,
                SUITE,
                bundle.trusted_root().vault_id().as_slice(),
                i64::try_from(bundle.trusted_root().epoch())
                    .map_err(|_| VaultError::InvalidFormat)?,
                bundle.trusted_root().public_key().as_slice(),
            ],
        )?;
        let encrypted = bundle.to_bytes();
        transaction.execute(
            "INSERT INTO encrypted_objects (kind, value) VALUES (?1, ?2)",
            params![ROOT_KIND, encrypted],
        )?;
        transaction.commit()?;
        connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        connection.close().map_err(|(_, error)| error)?;

        File::open(&temporary_path)?.sync_all()?;
        fs::hard_link(&temporary_path, path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                VaultError::AlreadyExists
            } else {
                VaultError::Io(error)
            }
        })?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();

    let _ = fs::remove_file(&temporary_path);
    let _ = fs::remove_file(wal_path);
    let _ = fs::remove_file(shm_path);
    result
}

fn create_temporary(parent: &Path, target: &Path) -> Result<(PathBuf, File), VaultError> {
    let name = target
        .file_name()
        .ok_or(VaultError::InvalidFormat)?
        .to_string_lossy();
    for _ in 0..128 {
        let counter = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".{name}.tmp-{}-{counter}", std::process::id()));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(VaultError::Io(error)),
        }
    }
    Err(VaultError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate vault temporary file",
    )))
}

#[cfg(test)]
mod cleanup_error_tests {
    use super::*;

    #[test]
    fn cleanup_distinguishes_optional_absence_and_attempts_every_artifact() {
        let paths = PersistArtifacts::synthetic("/synthetic/temp");
        let mut attempted = Vec::new();
        let errors = cleanup_persist_artifacts(&paths, |path| {
            attempted.push(path.to_owned());
            if path == paths.temporary {
                Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "synthetic"))
            } else {
                Err(std::io::Error::new(std::io::ErrorKind::NotFound, "synthetic"))
            }
        });
        assert_eq!(attempted.len(), 3);
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn published_cleanup_failure_retains_operation_and_publication_state() {
        let original = VaultError::InvalidFormat;
        let error = combine_persist_result(
            Err(original),
            PersistPublication::Published,
            vec![std::io::Error::new(std::io::ErrorKind::PermissionDenied, "synthetic")],
        )
        .unwrap_err();
        let VaultError::Cleanup(cleanup) = error else {
            panic!("cleanup failure was discarded")
        };
        assert_eq!(cleanup.publication(), PersistPublication::Published);
        assert_eq!(cleanup.failure_count(), 1);
        assert!(matches!(cleanup.operation(), Some(VaultError::InvalidFormat)));
    }
}
