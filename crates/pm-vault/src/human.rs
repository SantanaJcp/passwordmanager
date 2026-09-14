// SPDX-License-Identifier: AGPL-3.0-only

//! Human-only password mutations through a signed, replay-safe transaction.

use std::{
    collections::BTreeMap,
    fmt,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use minicbor::{Decoder, Encoder, data::Type};
use pm_crypto::{
    ControlPackageInput, CryptoError, DigestState, GrantVectorInput, KdfProfile, PasskeyKeyPair,
    PendingRecoveryRotation, RecoveryCode, RevisionPackageInput, RootBundle, TrustedRoot,
    UnlockedRoot, digest, fill_random, open_human_root, random_id, recover_human_root,
    verify_human_command,
};
pub use pm_native_channel::AuthenticatedHumanChannel as HumanChannel;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use zeroize::{Zeroize, Zeroizing};

use crate::audit::{
    self, AuditAction, AuditActorKind, AuditDeviceCustody, AuditEvent, AuditOutcome,
    AuditPurgeScope, AuditQuery, PreparedAuditPurge,
};
use crate::authorization::{G5EventInput, encode_credential, encode_g5_event, new_credential};
use crate::migration::{
    self, CsvImportDecision, CsvImportPreview, CsvImportProfile, CsvImportReport, CsvRowStatus,
    IMPORT_PAGE_ITEMS, PreparedCsvImport,
};
use crate::onepux::OnePuxImportPreview;
use crate::{
    AgentEnrollment, AuthRecord, AuthorizationError, AuthorizationReason, CausalEventDraft,
    Destination, GeneratedPassword, GeneratorConfig, HistoryEntry, HumanMetadata, ItemHistory,
    ItemLifecycle, ItemPurgeScope, LogicalRecord, PasskeyAssertion, PasskeyError, PasskeyOperation,
    PasskeyPublicCredential, PasskeyRequest, PasskeyStatus, PasswordRng, PreparedAgentEnrollment,
    PreparedItemPurge, PreparedPasskeyRegistration, RecordKind, SearchHit, SearchQuery, VaultError,
    content, load_and_validate_bundle, unlock_root,
};

const CHALLENGE_LIFETIME_US: i64 = 60_000_000;
const MAX_TITLE: usize = 1024;
const MAX_URL: usize = 8 * 1024;
const MAX_FIELD: usize = 1024 * 1024;

/// Errors at the stable human transaction boundary.
#[derive(Debug)]
pub enum HumanCommitError {
    BodyChanged,
    ChallengeExpired,
    Crypto(CryptoError),
    InvalidCommand,
    InvalidInput,
    Integrity,
    AuditKeyUnavailable,
    InvalidSignature,
    Io(std::io::Error),
    ItemNotFound,
    RandomUnavailable,
    StateChanged,
    Storage(rusqlite::Error),
    TransactionConflict,
    Vault(VaultError),
    WrongChannel,
}

impl fmt::Display for HumanCommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BodyChanged => "human transaction body changed",
            Self::ChallengeExpired => "human challenge expired or was already consumed",
            Self::Crypto(_) => "human transaction cryptography failed",
            Self::InvalidCommand => "invalid human command",
            Self::InvalidInput => "invalid human input",
            Self::Integrity => "audit integrity verification failed",
            Self::AuditKeyUnavailable => "device audit custody is unavailable",
            Self::InvalidSignature => "invalid human signature",
            Self::Io(_) => "human content stream failed",
            Self::ItemNotFound => "item not found",
            Self::RandomUnavailable => "secure random source unavailable",
            Self::StateChanged => "vault authority state changed",
            Self::Storage(_) => "human transaction storage failed",
            Self::TransactionConflict => "human transaction id conflicts with another body",
            Self::Vault(_) => "vault could not be opened for a human transaction",
            Self::WrongChannel => "peer is not authenticated on the human channel",
        })
    }
}

impl std::error::Error for HumanCommitError {}

impl From<CryptoError> for HumanCommitError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<rusqlite::Error> for HumanCommitError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Storage(value)
    }
}

impl From<std::io::Error> for HumanCommitError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// One bounded plaintext source matched to a declared attachment descriptor.
pub struct AttachmentReader<'a> {
    id: [u8; 16],
    reader: &'a mut dyn Read,
}

impl<'a> AttachmentReader<'a> {
    #[must_use]
    pub fn new(id: [u8; 16], reader: &'a mut dyn Read) -> Self {
        Self { id, reader }
    }
}

impl From<VaultError> for HumanCommitError {
    fn from(value: VaultError) -> Self {
        Self::Vault(value)
    }
}

impl From<pm_native_channel::ChannelAuthenticationError> for HumanCommitError {
    fn from(_: pm_native_channel::ChannelAuthenticationError) -> Self {
        Self::WrongChannel
    }
}

/// The first concrete G6 password record. Secret bytes are wiped on drop.
pub struct PasswordRecord {
    title: String,
    username: String,
    password: Vec<u8>,
    destination: String,
    notes: String,
}

impl PasswordRecord {
    /// Validates the selected G6 limits without trimming or normalizing secrets.
    ///
    /// # Errors
    ///
    /// Returns an error when a field exceeds the v1 bounds.
    pub fn new(
        title: &str,
        username: &str,
        password: &[u8],
        destination: &str,
        notes: &str,
    ) -> Result<Self, HumanCommitError> {
        if title.len() > MAX_TITLE
            || username.len() > MAX_FIELD
            || password.len() > MAX_FIELD
            || destination.len() > MAX_URL
            || notes.len() > MAX_FIELD
        {
            return Err(HumanCommitError::InvalidInput);
        }
        Ok(Self {
            title: title.to_owned(),
            username: username.to_owned(),
            password: password.to_vec(),
            destination: destination.to_owned(),
            notes: notes.to_owned(),
        })
    }

    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    #[must_use]
    pub fn password(&self) -> &[u8] {
        &self.password
    }

    #[must_use]
    pub fn destination(&self) -> &str {
        &self.destination
    }

    #[must_use]
    pub fn notes(&self) -> &str {
        &self.notes
    }
}

impl Drop for PasswordRecord {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

/// Opaque wire artifacts returned by `pm.v1.human.prepare`.
pub struct PreparedHumanCommand {
    transaction_id: [u8; 16],
    item_id: [u8; 16],
    command: Vec<u8>,
    body: Vec<u8>,
}

/// Fresh recovery material that cannot be staged until its external copy is
/// reintroduced. Dropping it leaves the current durable recovery path intact.
pub struct PendingRecoveryChange {
    pending: PendingRecoveryRotation,
    source_bundle_digest: [u8; 32],
}

#[derive(Clone, Copy)]
enum BackupOpen<'a> {
    Password(&'a [u8]),
    Recovery(&'a RecoveryCode),
}

impl PendingRecoveryChange {
    #[must_use]
    pub const fn recovery_code(&self) -> &RecoveryCode {
        self.pending.recovery_code()
    }

    /// Confirms the new external code and stages its encrypted root bundle for
    /// the ordinary signed human commit transaction.
    ///
    /// # Errors
    /// Rejects a wrong/foreign confirmation or a changed vault state.
    pub fn confirm(
        self,
        vault: &mut HumanVault,
        reintroduced: &RecoveryCode,
    ) -> Result<PreparedHumanCommand, HumanCommitError> {
        let (current, _) = load_and_validate_bundle(&open_connection(&vault.path)?)?;
        if digest(&current.to_bytes()) != self.source_bundle_digest {
            return Err(HumanCommitError::StateChanged);
        }
        let bundle = self
            .pending
            .into_bundle_after_recovery_confirmation(reintroduced)?;
        if recover_human_root(&bundle, reintroduced)?.trusted_root() != vault.trusted_root {
            return Err(HumanCommitError::Integrity);
        }
        vault.stage_root_rotation("root-recovery-rotate", &bundle)
    }
}

impl PreparedHumanCommand {
    #[must_use]
    pub const fn transaction_id(&self) -> &[u8; 16] {
        &self.transaction_id
    }

    #[must_use]
    pub const fn item_id(&self) -> &[u8; 16] {
        &self.item_id
    }

    #[must_use]
    pub fn command(&self) -> &[u8] {
        &self.command
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Durable result of one human transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanReceipt {
    transaction_id: [u8; 16],
    body_hash: [u8; 32],
    committed_heads: Vec<[u8; 32]>,
    committed_at_us: i64,
}

impl HumanReceipt {
    #[must_use]
    pub const fn transaction_id(&self) -> &[u8; 16] {
        &self.transaction_id
    }

    #[must_use]
    pub fn committed_heads(&self) -> &[[u8; 32]] {
        &self.committed_heads
    }

    #[must_use]
    pub const fn outcome(&self) -> &'static str {
        "committed"
    }

    /// Returns the canonical minimal receipt schema for the human wire.
    ///
    /// # Panics
    ///
    /// This uses an in-memory `Vec` writer, whose encoder error is
    /// uninhabited; allocation failure follows Rust's process-level behavior.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(Vec::new());
        encoder.map(5).unwrap();
        encoder
            .str("transaction_id")
            .unwrap()
            .bytes(&self.transaction_id)
            .unwrap();
        encoder
            .str("body_hash")
            .unwrap()
            .bytes(&self.body_hash)
            .unwrap();
        encoder.str("committed_heads").unwrap();
        encoder
            .writer_mut()
            .extend_from_slice(&encode_heads(&self.committed_heads));
        encoder
            .str("committed_at")
            .unwrap()
            .i64(self.committed_at_us)
            .unwrap();
        encoder.str("outcome").unwrap().str(self.outcome()).unwrap();
        encoder.into_writer()
    }
}

/// Unlocked executor restricted to a kernel-authenticated human channel.
pub struct HumanVault {
    path: PathBuf,
    device: [u8; 16],
    channel: HumanChannel,
    root: UnlockedRoot,
    trusted_root: TrustedRoot,
    audit_custody: Arc<AuditDeviceCustody>,
}

/// Secret-free metadata used by the interactive human catalog.
#[derive(Debug, Eq, PartialEq)]
pub struct HumanCatalogEntry {
    item_id: [u8; 16],
    kind: RecordKind,
    title: String,
    tags: Vec<String>,
    favorite: bool,
    lifecycle: ItemLifecycle,
}

/// Secret-free materialized authority state for the human access screen.
#[derive(Debug, Eq, PartialEq)]
pub struct HumanAccessOverview {
    suspended: bool,
    agents: Vec<HumanAgentAccess>,
    credentials: Vec<HumanCredentialAccess>,
}

impl HumanAccessOverview {
    #[must_use]
    pub const fn suspended(&self) -> bool {
        self.suspended
    }
    #[must_use]
    pub fn agents(&self) -> &[HumanAgentAccess] {
        &self.agents
    }
    #[must_use]
    pub fn credentials(&self) -> &[HumanCredentialAccess] {
        &self.credentials
    }
}

/// One RPK-bound agent generation, without private or credential material.
#[derive(Debug, Eq, PartialEq)]
pub struct HumanAgentAccess {
    subject: [u8; 16],
    generation: u64,
    label: String,
    environment: String,
    status: String,
}

impl HumanAgentAccess {
    #[must_use]
    pub const fn subject(&self) -> &[u8; 16] {
        &self.subject
    }
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
    #[must_use]
    pub fn environment(&self) -> &str {
        &self.environment
    }
    #[must_use]
    pub fn status(&self) -> &str {
        &self.status
    }
}

/// One content item and whether it belongs to the common delegated set.
#[derive(Debug, Eq, PartialEq)]
pub struct HumanCredentialAccess {
    item: [u8; 16],
    title: String,
    enabled: bool,
}

impl HumanCredentialAccess {
    #[must_use]
    pub const fn item(&self) -> &[u8; 16] {
        &self.item
    }
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }
}

impl HumanCatalogEntry {
    #[must_use]
    pub const fn item_id(&self) -> &[u8; 16] {
        &self.item_id
    }
    #[must_use]
    pub const fn kind(&self) -> RecordKind {
        self.kind
    }
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }
    #[must_use]
    pub fn tags(&self) -> &[String] {
        &self.tags
    }
    #[must_use]
    pub const fn favorite(&self) -> bool {
        self.favorite
    }
    #[must_use]
    pub const fn lifecycle(&self) -> ItemLifecycle {
        self.lifecycle
    }
}

impl HumanVault {
    /// Returns the materialized, secret-free human view of delegated authority.
    ///
    /// # Errors
    /// Fails closed for a malformed status, identifier, or generation.
    pub fn access_overview(&self) -> Result<HumanAccessOverview, HumanCommitError> {
        self.channel.verify()?;
        let connection = open_connection(&self.path)?;
        let global: Option<String> = connection
            .query_row(
                "SELECT status FROM delegated_state WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let suspended = match global.as_deref() {
            None | Some("suspended") => true,
            Some("resumed") => false,
            Some(_) => return Err(HumanCommitError::Integrity),
        };
        let mut statement = connection.prepare(
            "SELECT subject_id,generation,label,environment_binding,status
             FROM agent_authorizations ORDER BY subject_id,generation",
        )?;
        let agents = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?
            .map(|row| {
                let (subject, generation, label, environment, status) = row?;
                if !matches!(status.as_str(), "active" | "revoked" | "superseded") {
                    return Err(HumanCommitError::Integrity);
                }
                Ok(HumanAgentAccess {
                    subject: bytes::<16>(&subject)?,
                    generation: u64::try_from(generation)
                        .map_err(|_| HumanCommitError::Integrity)?,
                    label,
                    environment,
                    status,
                })
            })
            .collect::<Result<Vec<_>, HumanCommitError>>()?;
        drop(statement);
        let mut statement = connection.prepare(
            "SELECT item_id,visible_revision,kind FROM vault_items
             WHERE status='active' ORDER BY item_id",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let mut credentials = Vec::new();
        for (item, revision, kind) in rows {
            let item = bytes::<16>(&item)?;
            let record =
                self.read_revision_from(&connection, item, bytes::<16>(&revision)?, Some(&kind))?;
            if record.auth().is_empty() {
                continue;
            }
            let enabled: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM credential_authorizations
                 WHERE item_id=?1 AND status='enabled')",
                [item.as_slice()],
                |row| row.get(0),
            )?;
            credentials.push(HumanCredentialAccess {
                item,
                title: record.human().title.clone(),
                enabled,
            });
        }
        Ok(HumanAccessOverview {
            suspended,
            agents,
            credentials,
        })
    }

    pub(crate) fn verify_attempt_access(
        &self,
        path: &Path,
        vault: &[u8; 16],
        device: &[u8; 16],
    ) -> Result<(), crate::AttemptError> {
        self.channel
            .verify()
            .map_err(|_| crate::AttemptError::Integrity)?;
        if self.path != path || self.root.vault_id() != vault || &self.device != device {
            return Err(crate::AttemptError::Integrity);
        }
        Ok(())
    }

    pub(crate) fn attempt_title(&self, item: [u8; 16]) -> Result<String, crate::AttemptError> {
        self.read_record(item)
            .map(|record| record.human().title.clone())
            .map_err(|_| crate::AttemptError::Integrity)
    }
    /// Lists authenticated, secret-free human metadata for active and trashed items.
    ///
    /// # Errors
    /// Fails closed if any visible revision or lifecycle row is inconsistent.
    pub fn human_catalog(&self) -> Result<Vec<HumanCatalogEntry>, HumanCommitError> {
        self.channel.verify()?;
        let connection = open_connection(&self.path)?;
        let mut statement = connection.prepare(
            "SELECT item_id,visible_revision,kind,status FROM vault_items ORDER BY item_id",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let mut entries = Vec::with_capacity(rows.len());
        for (item, revision, expected_kind, status) in rows {
            let item_id = bytes::<16>(&item)?;
            let revision_id = bytes::<16>(&revision)?;
            let lifecycle = match status.as_str() {
                "active" => ItemLifecycle::Active,
                "trash" => ItemLifecycle::Trash,
                _ => return Err(HumanCommitError::InvalidCommand),
            };
            let record =
                self.read_revision_from(&connection, item_id, revision_id, Some(&expected_kind))?;
            entries.push(HumanCatalogEntry {
                item_id,
                kind: record.kind(),
                title: record.human().title.clone(),
                tags: record.human().tags.clone(),
                favorite: record.human().favorite,
                lifecycle,
            });
        }
        Ok(entries)
    }

    /// Appends a human-session audit fact without exposing audit storage internals.
    ///
    /// # Errors
    /// Rejects non-interactive audit actions and fails atomically on storage error.
    pub fn record_human_interaction(
        &self,
        action: AuditAction,
        item: Option<[u8; 16]>,
    ) -> Result<(), HumanCommitError> {
        self.channel.verify()?;
        if !matches!(
            action,
            AuditAction::HumanUnlock | AuditAction::Reveal | AuditAction::Copy
        ) {
            return Err(HumanCommitError::InvalidInput);
        }
        let mut connection = open_connection(&self.path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let authority = current_head(&transaction)?.unwrap_or([0; 32]);
        let mut event =
            AuditEvent::new(AuditActorKind::Human, None, action, AuditOutcome::Succeeded);
        if let Some(item) = item {
            event = event.with_item(item, None);
        }
        audit::append_event(
            &transaction,
            &self.trusted_root,
            Some(&self.root),
            self.device,
            &self.audit_custody,
            &event,
            now_us()?,
            authority,
        )?;
        transaction.commit()?;
        Ok(())
    }
    /// Writes a complete logical PMB1 snapshot through bounded PMF1 frames.
    ///
    /// # Errors
    /// Aborts on any missing/corrupt referenced object, size bound, channel,
    /// cryptographic, storage or output error; callers must publish atomically.
    pub fn write_native_backup(
        &self,
        output: &mut dyn Write,
    ) -> Result<crate::BackupSummary, HumanCommitError> {
        self.channel.verify()?;
        let summary = crate::backup::write_backup(&self.path, &self.root, output)?;
        let mut connection = open_connection(&self.path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let authority = current_head(&transaction)?.unwrap_or([0; 32]);
        audit::append_event(
            &transaction,
            &self.trusted_root,
            Some(&self.root),
            self.device,
            &self.audit_custody,
            &AuditEvent::new(
                AuditActorKind::Human,
                None,
                AuditAction::Backup,
                AuditOutcome::Succeeded,
            ),
            now_us()?,
            authority,
        )?;
        transaction.commit()?;
        Ok(summary)
    }

    /// Authenticates and verifies a PMB1 from this already unlocked human root.
    ///
    /// # Errors
    /// Rejects foreign/corrupt/incomplete/trailing backups and invalid inventory.
    pub fn verify_native_backup(
        &self,
        input: &mut dyn Read,
    ) -> Result<crate::BackupSummary, HumanCommitError> {
        self.channel.verify()?;
        crate::backup::verify_with_root(&self.root, input)
    }

    /// Authenticates a PMB1 completely and stages every logical revision and
    /// attachment under fresh destination IDs/keys. Nothing becomes visible
    /// until the returned command is signed and committed.
    ///
    /// # Errors
    /// Rejects invalid passwords, incomplete inventories/references, corrupt
    /// streams, limits and storage failures without changing active content.
    pub fn prepare_native_restore(
        &mut self,
        input: &mut dyn Read,
        backup_password: &[u8],
    ) -> Result<crate::PreparedBackupRestore, HumanCommitError> {
        self.prepare_backup_restore(input, BackupOpen::Password(backup_password))
    }

    /// Authenticates a portable PMB1 with its external recovery key and stages
    /// the content under this vault's fresh/current keys. Source device keyring
    /// and historical signing private keys are neither needed nor activated.
    ///
    /// # Errors
    /// Rejects a wrong recovery code, corruption, incomplete inventory, bounds
    /// or storage failures without changing visible content or current authority.
    pub fn prepare_native_recovery(
        &mut self,
        input: &mut dyn Read,
        source_recovery: &RecoveryCode,
    ) -> Result<crate::PreparedBackupRestore, HumanCommitError> {
        self.prepare_backup_restore(input, BackupOpen::Recovery(source_recovery))
    }

    fn prepare_backup_restore(
        &mut self,
        input: &mut dyn Read,
        source: BackupOpen<'_>,
    ) -> Result<crate::PreparedBackupRestore, HumanCommitError> {
        self.channel.verify()?;
        let transaction_id = random_id()?;
        let challenge = random_challenge()?;
        let mut connection = open_connection(&self.path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let expected_state = state_digest(&transaction, self.root.vault_id(), 1)?;
        let (summary, item_ids, object_digest) = match source {
            BackupOpen::Password(password) => crate::backup::prepare_restore(
                &transaction,
                &self.root,
                self.device,
                transaction_id,
                input,
                password,
            ),
            BackupOpen::Recovery(recovery) => crate::backup::prepare_recovery(
                &transaction,
                &self.root,
                self.device,
                transaction_id,
                input,
                recovery,
            ),
        }?;
        let manifest = encode_event_manifest(
            "backup-restore",
            *summary.backup_id(),
            None,
            Some(object_digest),
            None,
            None,
            None,
        );
        let event_count = crate::backup::restore_event_count(&transaction, transaction_id)?;
        let body = encode_body(&Body {
            transaction_id,
            events_manifest_digest: digest(&manifest),
            event_count,
            object_manifest_digest: Some(object_digest),
        });
        let body_hash = digest(&body);
        let expires_at_us = now_us()?
            .checked_add(CHALLENGE_LIFETIME_US)
            .ok_or(HumanCommitError::InvalidCommand)?;
        let command = encode_command(&CommandFields {
            vault: *self.root.vault_id(),
            challenge,
            expected_state,
            operation: "backup_restore",
            body_hash,
            expires_at_us,
        });
        transaction.execute(
            "INSERT INTO human_challenges(challenge,transaction_id,command,body_hash,expected_state,expires_at_us,consumed) VALUES(?1,?2,?3,?4,?5,?6,0)",
            params![challenge.as_slice(),transaction_id.as_slice(),command,body_hash.as_slice(),expected_state.as_slice(),expires_at_us],
        )?;
        transaction.execute(
            "INSERT INTO human_staging(transaction_id,operation,event_kind,item_id,revision_id,body,package,item_kind,attachments) VALUES(?1,'backup_restore','backup-restore',?2,NULL,?3,NULL,NULL,NULL)",
            params![transaction_id.as_slice(),summary.backup_id().as_slice(),body],
        )?;
        transaction.commit()?;
        Ok(crate::PreparedBackupRestore::new(
            PreparedHumanCommand {
                transaction_id,
                item_id: *summary.backup_id(),
                command,
                body,
            },
            summary,
            item_ids,
        ))
    }

    /// Stages a new password wrapper while preserving the human root,
    /// authority, recovery path and vault lineage.
    ///
    /// # Errors
    /// Rejects invalid inputs, a changed/foreign bundle or unavailable storage.
    pub fn prepare_master_password_rotation(
        &mut self,
        new_password: &[u8],
        profile: KdfProfile,
    ) -> Result<PreparedHumanCommand, HumanCommitError> {
        self.channel.verify()?;
        let (bundle, _) = load_and_validate_bundle(&open_connection(&self.path)?)?;
        let replacement = self.root.rewrap_password(&bundle, new_password, profile)?;
        if open_human_root(&replacement, new_password)?.trusted_root() != self.trusted_root {
            return Err(HumanCommitError::Integrity);
        }
        self.stage_root_rotation("root-password-rotate", &replacement)
    }

    /// Begins replacement of the external recovery key. Nothing durable is
    /// changed until the returned code is reintroduced, staged, signed and committed.
    ///
    /// # Errors
    /// Rejects a foreign/corrupt root bundle or unavailable randomness.
    pub fn begin_recovery_rotation(&self) -> Result<PendingRecoveryChange, HumanCommitError> {
        self.channel.verify()?;
        let (bundle, _) = load_and_validate_bundle(&open_connection(&self.path)?)?;
        Ok(PendingRecoveryChange {
            pending: self.root.rotate_recovery(&bundle)?,
            source_bundle_digest: digest(&bundle.to_bytes()),
        })
    }

    /// Verifies a candidate against the currently durable recovery envelope.
    ///
    /// # Errors
    /// Rejects an old, foreign or malformed recovery code.
    pub fn verify_current_recovery(&self, recovery: &RecoveryCode) -> Result<(), HumanCommitError> {
        self.channel.verify()?;
        let (bundle, trusted) = load_and_validate_bundle(&open_connection(&self.path)?)?;
        let root = recover_human_root(&bundle, recovery)?;
        if root.trusted_root() != trusted {
            return Err(HumanCommitError::Integrity);
        }
        Ok(())
    }

    fn stage_root_rotation(
        &mut self,
        kind: &str,
        bundle: &RootBundle,
    ) -> Result<PreparedHumanCommand, HumanCommitError> {
        self.channel.verify()?;
        if !matches!(kind, "root-password-rotate" | "root-recovery-rotate")
            || bundle.trusted_root() != &self.trusted_root
        {
            return Err(HumanCommitError::InvalidInput);
        }
        let transaction_id = random_id()?;
        let challenge = random_challenge()?;
        let package = bundle.to_bytes();
        let package_digest = digest(&package);
        let body = encode_body(&Body {
            transaction_id,
            events_manifest_digest: digest(kind.as_bytes()),
            event_count: 0,
            object_manifest_digest: Some(package_digest),
        });
        let body_hash = digest(&body);
        let expires_at_us = now_us()?
            .checked_add(CHALLENGE_LIFETIME_US)
            .ok_or(HumanCommitError::InvalidCommand)?;
        let mut connection = open_connection(&self.path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let expected_state = state_digest(&transaction, self.root.vault_id(), 1)?;
        let command = encode_command(&CommandFields {
            vault: *self.root.vault_id(),
            challenge,
            expected_state,
            operation: "root_rotation",
            body_hash,
            expires_at_us,
        });
        transaction.execute(
            "INSERT INTO human_challenges(challenge,transaction_id,command,body_hash,expected_state,expires_at_us,consumed) VALUES(?1,?2,?3,?4,?5,?6,0)",
            params![challenge.as_slice(),transaction_id.as_slice(),command,body_hash.as_slice(),expected_state.as_slice(),expires_at_us],
        )?;
        transaction.execute(
            "INSERT INTO human_staging(transaction_id,operation,event_kind,item_id,body,package) VALUES(?1,'root_rotation',?2,?3,?4,?5)",
            params![transaction_id.as_slice(),kind,self.root.vault_id().as_slice(),body,package],
        )?;
        transaction.commit()?;
        Ok(PreparedHumanCommand {
            transaction_id,
            item_id: *self.root.vault_id(),
            command,
            body,
        })
    }

    /// Prepares a one-use, state-bound confirmation for a full plaintext export.
    /// The export does not share the native backup confirmation and must be
    /// signed separately for every operation.
    ///
    /// # Errors
    /// Returns an error when the human channel, RNG, clock or durable challenge
    /// persistence is unavailable.
    pub fn prepare_plaintext_export(&mut self) -> Result<PreparedHumanCommand, HumanCommitError> {
        self.channel.verify()?;
        let transaction_id = random_id()?;
        let challenge = random_challenge()?;
        let body = encode_body(&Body {
            transaction_id,
            events_manifest_digest: digest(b"pm/plaintext-export/full/v1"),
            event_count: 0,
            object_manifest_digest: None,
        });
        let body_hash = digest(&body);
        let expires_at_us = now_us()?
            .checked_add(CHALLENGE_LIFETIME_US)
            .ok_or(HumanCommitError::InvalidCommand)?;
        let mut connection = open_connection(&self.path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let expected_state = state_digest(&transaction, self.root.vault_id(), 1)?;
        let command = encode_command(&CommandFields {
            vault: *self.root.vault_id(),
            challenge,
            expected_state,
            operation: "plaintext_export",
            body_hash,
            expires_at_us,
        });
        transaction.execute(
            "INSERT INTO human_challenges
             (challenge,transaction_id,command,body_hash,expected_state,expires_at_us,consumed)
             VALUES(?1,?2,?3,?4,?5,?6,0)",
            params![
                challenge.as_slice(),
                transaction_id.as_slice(),
                command,
                body_hash.as_slice(),
                expected_state.as_slice(),
                expires_at_us
            ],
        )?;
        transaction.commit()?;
        Ok(PreparedHumanCommand {
            transaction_id,
            item_id: transaction_id,
            command,
            body,
        })
    }

    /// Writes the complete logical JSONL export only after verifying and
    /// consuming its fresh signed human confirmation.
    ///
    /// # Errors
    /// Rejects replay, altered body, stale state, wrong signature, corrupt
    /// source objects or output failure. The caller publishes its exclusive
    /// private temporary file only after this method returns success.
    pub fn write_plaintext_export(
        &mut self,
        command_bytes: &[u8],
        signature: &[u8; 64],
        body_bytes: &[u8],
        output: &mut dyn Write,
    ) -> Result<crate::BackupSummary, HumanCommitError> {
        self.channel.verify()?;
        let command = decode_command(command_bytes)?;
        let body = decode_body(body_bytes).map_err(|_| HumanCommitError::BodyChanged)?;
        if command.vault != *self.root.vault_id()
            || command.operation != "plaintext_export"
            || command.body_hash != digest(body_bytes)
            || body.events_manifest_digest != digest(b"pm/plaintext-export/full/v1")
            || body.event_count != 0
            || body.object_manifest_digest.is_some()
        {
            return Err(HumanCommitError::BodyChanged);
        }
        verify_human_command(&self.trusted_root, command_bytes, signature)
            .map_err(|_| HumanCommitError::InvalidSignature)?;
        let mut connection = open_connection(&self.path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let challenge = load_challenge(&transaction, body.transaction_id)?;
        if challenge.command != command_bytes || challenge.body_hash != command.body_hash {
            return Err(HumanCommitError::BodyChanged);
        }
        if challenge.consumed || now_us()? > challenge.expires_at_us {
            return Err(HumanCommitError::ChallengeExpired);
        }
        if state_digest(&transaction, self.root.vault_id(), 1)? != command.expected_state {
            return Err(HumanCommitError::StateChanged);
        }
        let summary = crate::backup::write_plaintext(&transaction, &self.root, output)?;
        let authority = current_head(&transaction)?.unwrap_or([0; 32]);
        audit::append_event(
            &transaction,
            &self.trusted_root,
            Some(&self.root),
            self.device,
            &self.audit_custody,
            &AuditEvent::new(
                AuditActorKind::Human,
                None,
                AuditAction::Export,
                AuditOutcome::Succeeded,
            ),
            now_us()?,
            authority,
        )?;
        transaction.execute(
            "UPDATE human_challenges SET consumed=1 WHERE transaction_id=?1 AND consumed=0",
            [body.transaction_id.as_slice()],
        )?;
        transaction.commit()?;
        Ok(summary)
    }

    /// Creates human-authorized E2EE pairing material for a pinned sync server.
    /// The returned secret bundle must remain in native/human custody.
    ///
    /// # Errors
    /// Fails closed unless the human channel remains authenticated.
    pub fn create_sync_pairing(
        &self,
        server_pin: [u8; 44],
    ) -> Result<pm_crypto::SyncPairing, HumanCommitError> {
        self.channel.verify()?;
        Ok(self.root.create_sync_pairing(server_pin)?)
    }
    /// Signs a canonical causal event with device provenance and, for authority
    /// events, the human root. This does not publish the event.
    ///
    /// # Errors
    /// Returns an error if the device key cannot be human-bound or signing fails.
    pub fn sign_causal_event(
        &self,
        draft: &CausalEventDraft,
    ) -> Result<crate::SignedCausalEvent, crate::ReductionError> {
        self.channel
            .verify()
            .map_err(|_| crate::ReductionError::InvalidEvent)?;
        let mut connection = open_connection(&self.path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let package = audit::ensure_package(
            &transaction,
            &self.trusted_root,
            Some(&self.root),
            self.device,
            &self.audit_custody,
        )?;
        if package.generation() != draft.issuer_generation {
            return Err(crate::ReductionError::InvalidEvent);
        }
        transaction.commit()?;
        crate::reducer::sign_draft(
            self.root.vault_id(),
            self.device,
            &self.root,
            &self.audit_custody,
            draft,
        )
    }

    /// Opens an existing vault and retains `K_H`/`SK_H` only in this human session.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong channel, password, root, or storage format.
    pub fn unlock(
        path: &Path,
        password: &[u8],
        device: [u8; 16],
        channel: HumanChannel,
    ) -> Result<Self, HumanCommitError> {
        Self::unlock_with_audit_custody(
            path,
            password,
            device,
            channel,
            Arc::new(AuditDeviceCustody::generate()?),
        )
    }

    /// Opens a human session attached to stable device audit custody. Sharing
    /// this opaque handle with the custodian permits later audit writes after KH
    /// and the human session have been dropped.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong channel, password, root, custody, or storage format.
    pub fn unlock_with_audit_custody(
        path: &Path,
        password: &[u8],
        device: [u8; 16],
        channel: HumanChannel,
        audit_custody: Arc<AuditDeviceCustody>,
    ) -> Result<Self, HumanCommitError> {
        channel.verify()?;
        let connection = open_connection(path)?;
        let root = unlock_root(&connection, password)?;
        let trusted_root = root.trusted_root();
        Ok(Self {
            path: path.to_owned(),
            device,
            channel,
            root,
            trusted_root,
            audit_custody,
        })
    }

    /// Stages an encrypted password revision and emits a 60-second challenge.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption, randomness, channel verification, or
    /// durable staging fails.
    pub fn prepare_create(
        &mut self,
        record: &PasswordRecord,
    ) -> Result<PreparedHumanCommand, HumanCommitError> {
        self.prepare_write(random_id()?, record)
    }

    /// Stages a human-signed G5 registration for one RPK-bound agent generation.
    ///
    /// # Errors
    /// Returns an error for duplicate/active identity material or unavailable storage.
    pub fn prepare_agent_enrollment(
        &mut self,
        enrollment: &AgentEnrollment,
    ) -> Result<PreparedAgentEnrollment, AuthorizationError> {
        self.channel
            .verify()
            .map_err(|_| AuthorizationError::Unauthorized)?;
        let connection = open_connection(&self.path).map_err(AuthorizationError::from)?;
        let prior_status: Option<String> = connection
            .query_row(
                "SELECT status FROM agent_authorizations WHERE subject_id=?1 ORDER BY generation DESC LIMIT 1",
                [enrollment.subject_id.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if prior_status.as_deref() == Some("active") {
            return Err(AuthorizationError::InvalidInput);
        }
        let duplicate_rpk: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM agent_authorizations WHERE transport_rpk=?1)",
            [enrollment.transport_rpk.as_slice()],
            |row| row.get(0),
        )?;
        if duplicate_rpk {
            return Err(AuthorizationError::InvalidInput);
        }
        let maximum: i64 = connection
            .query_row(
                "SELECT coalesce(max(generation),0) FROM agent_authorizations WHERE subject_id=?1",
                [enrollment.subject_id.as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| AuthorizationError::Integrity)?;
        let generation = u64::try_from(maximum)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(AuthorizationError::InvalidInput)?;
        let mut statement = connection
            .prepare("SELECT grant_event_digest FROM agent_authorizations WHERE subject_id=?1")?;
        let mut predecessors = statement
            .query_map([enrollment.subject_id.as_slice()], |row| {
                row.get::<_, Vec<u8>>(0)
            })?
            .map(|value| {
                value
                    .map_err(AuthorizationError::from)
                    .and_then(|bytes| bytes.try_into().map_err(|_| AuthorizationError::Integrity))
            })
            .collect::<Result<Vec<[u8; 32]>, _>>()?;
        predecessors.sort_unstable();
        drop(statement);
        drop(connection);
        let body = encode_agent_grant_body(enrollment, &predecessors);
        let prepared = self
            .prepare_authority(
                "identity_change",
                "agent-grant",
                enrollment.subject_id,
                generation,
                &body,
                None,
                None,
            )
            .map_err(AuthorizationError::from)?;
        Ok(PreparedAgentEnrollment {
            prepared,
            generation,
        })
    }

    /// Stages terminal revocation of the subject's current active generation.
    ///
    /// # Errors
    /// Returns an error when no active generation exists.
    pub fn prepare_agent_revocation(
        &mut self,
        subject: [u8; 16],
        reason: AuthorizationReason,
    ) -> Result<PreparedHumanCommand, AuthorizationError> {
        let connection = open_connection(&self.path).map_err(AuthorizationError::from)?;
        let generation: Option<i64> = connection
            .query_row(
                "SELECT generation FROM agent_authorizations WHERE subject_id=?1 AND status='active' ORDER BY generation DESC LIMIT 1",
                [subject.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        let generation = generation
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(AuthorizationError::Unauthorized)?;
        self.prepare_authority(
            "identity_change",
            "agent-revoke",
            subject,
            generation,
            &encode_reason_body(reason),
            None,
            None,
        )
        .map_err(AuthorizationError::from)
    }

    /// Stages global delegated suspension without changing human lock state.
    ///
    /// # Errors
    /// Returns an error when staging fails.
    pub fn prepare_delegated_suspend(
        &mut self,
        reason: AuthorizationReason,
    ) -> Result<PreparedHumanCommand, AuthorizationError> {
        self.prepare_authority(
            "availability_change",
            "suspend",
            *self.root.vault_id(),
            1,
            &encode_reason_body(reason),
            None,
            None,
        )
        .map_err(AuthorizationError::from)
    }

    /// Stages restoration of global delegated availability.
    ///
    /// # Errors
    /// Returns an error when staging fails.
    pub fn prepare_delegated_resume(&mut self) -> Result<PreparedHumanCommand, AuthorizationError> {
        let withdrawals = authority_digests(
            &open_connection(&self.path).map_err(AuthorizationError::from)?,
            *self.root.vault_id(),
            &["suspend"],
        )
        .map_err(AuthorizationError::from)?;
        self.prepare_authority(
            "availability_change",
            "resume",
            *self.root.vault_id(),
            1,
            &encode_resume_body(&withdrawals),
            None,
            None,
        )
        .map_err(AuthorizationError::from)
    }

    /// Stages an authenticated minimal credential descriptor and its real G2 grant.
    ///
    /// # Errors
    /// Rejects non-auth records and unavailable or corrupt device custody.
    pub fn prepare_enable(
        &mut self,
        item: [u8; 16],
    ) -> Result<PreparedHumanCommand, AuthorizationError> {
        let record = self.read_record(item).map_err(AuthorizationError::from)?;
        let account =
            delegated_account(&record).ok_or(AuthorizationError::CredentialUnavailable)?;
        let connection = open_connection(&self.path).map_err(AuthorizationError::from)?;
        let revision_bytes: Vec<u8> = connection
            .query_row(
                "SELECT visible_revision FROM vault_items WHERE item_id=?1 AND status='active'",
                [item.as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| AuthorizationError::Integrity)?;
        let revision = bytes::<16>(&revision_bytes).map_err(AuthorizationError::from)?;
        let package = audit::load_matching_package(
            &connection,
            &self.trusted_root,
            self.device,
            &self.audit_custody,
        )
        .map_err(|_| AuthorizationError::Integrity)?;
        let descriptor = new_credential(
            item,
            revision,
            record.kind(),
            record.human().title.clone(),
            record
                .human()
                .destinations
                .first()
                .map(|value| value.value.clone()),
            Some(account),
        );
        let auth = Zeroizing::new(
            record
                .encode_auth()
                .ok_or(AuthorizationError::CredentialUnavailable)?,
        );
        let plaintext = Zeroizing::new(encode_credential(&descriptor, &auth));
        let control_package = self
            .root
            .seal_control_package(
                ControlPackageInput {
                    object: item,
                    revision,
                    recipient: self.device,
                    recipient_generation: package.generation(),
                    plaintext: &plaintext,
                },
                self.audit_custody.encryption_public_key(),
            )
            .map_err(|_| AuthorizationError::Integrity)?;
        let pending = self
            .root
            .prepare_grant_vector(
                GrantVectorInput {
                    item,
                    revision,
                    recipient: self.device,
                    authorization_generation: package.generation(),
                    payload_sha256: digest(&control_package),
                },
                self.audit_custody.encryption_public_key(),
            )
            .map_err(|_| AuthorizationError::Integrity)?;
        let staged_grant = pending.to_staged_bytes();
        let positives =
            authority_digests(&connection, item, &["enable"]).map_err(AuthorizationError::from)?;
        let withdrawals = authority_digests(
            &connection,
            item,
            &["disable", "trash", "purge-item", "purge-revisions"],
        )
        .map_err(AuthorizationError::from)?;
        let body = encode_enable_body(revision, pending.commitment(), &positives, &withdrawals);
        self.prepare_authority(
            "availability_change",
            "enable",
            item,
            1,
            &body,
            Some(&control_package),
            Some(&staged_grant),
        )
        .map_err(AuthorizationError::from)
    }

    /// Stages removal of one credential from the common delegated set.
    ///
    /// # Errors
    /// Rejects an item that is not currently enabled or unavailable storage.
    pub fn prepare_disable(
        &mut self,
        item: [u8; 16],
    ) -> Result<PreparedHumanCommand, AuthorizationError> {
        let connection = open_connection(&self.path).map_err(AuthorizationError::from)?;
        let enabled: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM credential_authorizations
             WHERE item_id=?1 AND status='enabled')",
            [item.as_slice()],
            |row| row.get(0),
        )?;
        if !enabled {
            return Err(AuthorizationError::CredentialUnavailable);
        }
        drop(connection);
        self.prepare_authority(
            "availability_change",
            "disable",
            item,
            1,
            &encode_reason_body(AuthorizationReason::OwnerRequest),
            None,
            None,
        )
        .map_err(AuthorizationError::from)
    }

    /// Stages a new encrypted revision of an active password item.
    ///
    /// # Errors
    ///
    /// Returns an error when the item is absent or staging cannot complete.
    pub fn prepare_edit(
        &mut self,
        item: [u8; 16],
        record: &PasswordRecord,
    ) -> Result<PreparedHumanCommand, HumanCommitError> {
        self.require_active(item)?;
        self.prepare_write(item, record)
    }

    /// Stages a signed lifecycle withdrawal; plaintext is never staged.
    ///
    /// # Errors
    ///
    /// Returns an error when the item is absent or staging cannot complete.
    pub fn prepare_delete(
        &mut self,
        item: [u8; 16],
    ) -> Result<PreparedHumanCommand, HumanCommitError> {
        self.require_active(item)?;
        let mut deletions = authority_digests(&open_connection(&self.path)?, item, &["trash"])?;
        deletions.sort_unstable();
        self.prepare_authority(
            "item_lifecycle",
            "trash",
            item,
            1,
            &encode_lifecycle_body(&deletions),
            None,
            None,
        )
    }

    /// Stages a human-confirmed purge of an earlier audit prefix. The returned
    /// scope is the exact visible range/count bound by the signed transaction.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid/non-earlier range or unavailable storage.
    pub fn prepare_audit_purge(
        &mut self,
        device: [u8; 16],
        generation: u64,
        through_seq: u64,
    ) -> Result<PreparedAuditPurge, HumanCommitError> {
        self.channel.verify()?;
        if device != self.device {
            return Err(HumanCommitError::InvalidInput);
        }
        let connection = open_connection(&self.path)?;
        let head: i64 = connection
            .query_row(
                "SELECT last_seq FROM audit_segments WHERE device_id=?1 AND generation=?2
                 ORDER BY last_seq DESC LIMIT 1",
                params![
                    device.as_slice(),
                    i64::try_from(generation).map_err(|_| HumanCommitError::InvalidInput)?
                ],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(HumanCommitError::InvalidInput)?;
        if through_seq == 0
            || through_seq >= u64::try_from(head).map_err(|_| HumanCommitError::InvalidInput)?
        {
            return Err(HumanCommitError::InvalidInput);
        }
        let count: i64 = connection.query_row(
            "SELECT count(*) FROM encrypted_audit_records WHERE device_id=?1 AND generation=?2 AND seq<=?3",
            params![device.as_slice(), i64::try_from(generation).map_err(|_| HumanCommitError::InvalidInput)?, i64::try_from(through_seq).map_err(|_| HumanCommitError::InvalidInput)?], |row| row.get(0),
        )?;
        if count == 0 {
            return Err(HumanCommitError::InvalidInput);
        }
        let prepared = self.prepare(
            "audit_purge",
            "audit-purge",
            device,
            None,
            None,
            None,
            None,
            Some(generation),
            Some(through_seq),
            None,
            None,
            None,
            None,
        )?;
        Ok(PreparedAuditPurge {
            prepared,
            scope: AuditPurgeScope {
                first_seq: 1,
                last_seq: through_seq,
                record_count: u64::try_from(count).map_err(|_| HumanCommitError::InvalidInput)?,
            },
        })
    }

    /// Authenticates, verifies and decrypts a bounded local audit query.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong channel, invalid bound, or any integrity failure.
    pub fn query_audit(
        &self,
        device: [u8; 16],
        generation: u64,
        from_seq: u64,
        limit: usize,
    ) -> Result<AuditQuery, HumanCommitError> {
        self.channel.verify()?;
        audit::query(
            &open_connection(&self.path)?,
            &self.root,
            device,
            generation,
            from_seq,
            limit,
        )
    }

    /// Signs exactly the canonical prepared command under the `SK_H` domain.
    ///
    /// # Errors
    ///
    /// Returns an error if the channel changed or signing fails.
    pub fn sign(&self, prepared: &PreparedHumanCommand) -> Result<[u8; 64], HumanCommitError> {
        self.channel.verify()?;
        Ok(self.root.sign_human_command(prepared.command())?)
    }

    /// Verifies and commits event, encrypted parts, challenge consumption,
    /// outbox, encrypted audit record, audit head and receipt in one SQLite
    /// transaction.
    ///
    /// # Errors
    ///
    /// Returns a precise protocol error without committing a partial effect.
    #[allow(clippy::too_many_lines)]
    pub fn commit(
        &mut self,
        command_bytes: &[u8],
        signature: &[u8; 64],
        body_bytes: &[u8],
    ) -> Result<HumanReceipt, HumanCommitError> {
        self.channel.verify()?;
        let command = decode_command(command_bytes)?;
        let body = decode_body(body_bytes).map_err(|_| HumanCommitError::BodyChanged)?;
        if command.vault != *self.root.vault_id() {
            return Err(HumanCommitError::InvalidCommand);
        }
        let actual_body_hash = digest(body_bytes);
        if actual_body_hash != command.body_hash {
            return Err(HumanCommitError::BodyChanged);
        }
        verify_human_command(&self.trusted_root, command_bytes, signature)
            .map_err(|_| HumanCommitError::InvalidSignature)?;

        let mut connection = open_connection(&self.path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(receipt) = load_receipt(&transaction, body.transaction_id)? {
            if receipt.body_hash != actual_body_hash {
                return Err(HumanCommitError::TransactionConflict);
            }
            transaction.rollback()?;
            return Ok(receipt);
        }
        let challenge = load_challenge(&transaction, body.transaction_id)?;
        if challenge.command != command_bytes || challenge.body_hash != actual_body_hash {
            return Err(HumanCommitError::BodyChanged);
        }
        if challenge.consumed || now_us()? > challenge.expires_at_us {
            return Err(HumanCommitError::ChallengeExpired);
        }
        if state_digest(&transaction, self.root.vault_id(), 1)? != command.expected_state {
            return Err(HumanCommitError::StateChanged);
        }
        let staged = load_staging(&transaction, body.transaction_id)?;
        if staged.body != body_bytes || staged.operation != command.operation {
            return Err(HumanCommitError::BodyChanged);
        }
        validate_staged(&transaction, &staged, &body)?;
        let committed_at_us = now_us()?;
        if matches!(
            staged.event_kind.as_str(),
            "root-password-rotate" | "root-recovery-rotate"
        ) {
            return commit_root_rotation(
                transaction,
                &self.root,
                &self.trusted_root,
                self.device,
                &self.audit_custody,
                &staged,
                &body,
                actual_body_hash,
                committed_at_us,
            );
        }
        if staged.event_kind == "import-batch" {
            return commit_import_batch(
                transaction,
                &self.root,
                &self.trusted_root,
                self.device,
                &self.audit_custody,
                &body,
                actual_body_hash,
                committed_at_us,
            );
        }
        if staged.event_kind == "restore" {
            return commit_restore(
                transaction,
                &self.root,
                &self.trusted_root,
                self.device,
                &self.audit_custody,
                &staged,
                &body,
                actual_body_hash,
                committed_at_us,
            );
        }
        if staged.event_kind == "backup-restore" {
            return commit_backup_restore(
                transaction,
                &self.root,
                &self.trusted_root,
                self.device,
                &self.audit_custody,
                &body,
                actual_body_hash,
                committed_at_us,
            );
        }
        let event_id = random_id()?;
        let previous = current_head(&transaction)?;
        let seq = next_authority_seq(&transaction, self.device, 1)?;
        let mut parents = authority_specific_parents(&transaction, &staged)?;
        if let Some(previous) = previous {
            parents.push(previous);
        }
        parents.sort_unstable();
        parents.dedup();
        if parents.len() > 4096 {
            return Err(HumanCommitError::InvalidCommand);
        }
        let legacy_body;
        let authority_body = if let Some(value) = staged.authority_body.as_deref() {
            value
        } else {
            legacy_body = encode_legacy_event_body(
                staged.revision_id,
                committed_at_us,
                staged.audit_generation,
                staged.audit_through_seq,
                body.object_manifest_digest,
            );
            &legacy_body
        };
        let subject_generation = staged.subject_generation.unwrap_or(1);
        let event = encode_g5_event(&G5EventInput {
            vault: self.root.vault_id(),
            event_id,
            authority_epoch: 1,
            issuer_device: self.device,
            issuer_generation: 1,
            seq,
            previous,
            parents: &parents,
            kind: &staged.event_kind,
            subject: staged.item_id,
            subject_generation,
            body: authority_body,
        });
        let event_signature = self.root.sign_human_event(&event)?;
        let device_signature = self.audit_custody.sign_device_event(&event)?;
        let event_digest = digest(&event);
        let signed_event = encode_signed_event(&event, &device_signature, &event_signature);
        let signed_grant = staged
            .staged_grant
            .as_deref()
            .map(|value| self.root.finish_staged_grant_vector(value, event_digest))
            .transpose()?
            .map(|value| value.to_bytes());

        apply_staged(&transaction, &staged, event_digest, signed_grant.as_deref())?;
        apply_passkey_registration(&transaction, &staged)?;
        transaction.execute(
            "INSERT INTO authority_events
             (event_digest,event_id,transaction_id,issuer_device,issuer_generation,seq,previous_digest,parents,kind,subject,subject_generation,event,human_signature,device_signature)
             VALUES (?1,?2,?3,?4,1,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                event_digest.as_slice(),
                event_id.as_slice(),
                body.transaction_id.as_slice(),
                self.device.as_slice(),
                i64::try_from(seq).map_err(|_| HumanCommitError::InvalidCommand)?,
                previous.as_ref().map(<[u8; 32]>::as_slice),
                encode_heads_allow_empty(&parents),
                staged.event_kind,
                staged.item_id.as_slice(),
                i64::try_from(subject_generation).map_err(|_| HumanCommitError::InvalidCommand)?,
                event,
                event_signature.as_slice(),
                device_signature.as_slice(),
            ],
        )?;
        transaction.execute(
            "INSERT INTO outbox (event_digest,event) VALUES (?1,?2)",
            params![event_digest.as_slice(), signed_event],
        )?;
        if staged.event_kind == "audit-purge" {
            audit::purge(
                &transaction,
                &self.root,
                &self.trusted_root,
                staged.item_id,
                &self.audit_custody,
                staged
                    .audit_generation
                    .ok_or(HumanCommitError::BodyChanged)?,
                staged
                    .audit_through_seq
                    .ok_or(HumanCommitError::BodyChanged)?,
                committed_at_us,
            )?;
        } else {
            audit::append_event(
                &transaction,
                &self.trusted_root,
                Some(&self.root),
                self.device,
                &self.audit_custody,
                &AuditEvent::new(
                    AuditActorKind::Human,
                    None,
                    if staged.authority_body.is_some() {
                        AuditAction::AuthorityChange
                    } else {
                        AuditAction::ItemChange
                    },
                    AuditOutcome::Succeeded,
                )
                .with_item(staged.item_id, staged.revision_id),
                committed_at_us,
                event_digest,
            )?;
        }
        transaction.execute(
            "UPDATE human_challenges SET consumed=1 WHERE transaction_id=?1 AND consumed=0",
            [body.transaction_id.as_slice()],
        )?;
        transaction.execute(
            "DELETE FROM human_staging WHERE transaction_id=?1",
            [body.transaction_id.as_slice()],
        )?;
        transaction.execute(
            "DELETE FROM human_staging_stream_chunks WHERE transaction_id=?1",
            [body.transaction_id.as_slice()],
        )?;
        transaction.execute(
            "DELETE FROM human_staging_streams WHERE transaction_id=?1",
            [body.transaction_id.as_slice()],
        )?;
        transaction.execute(
            "INSERT INTO human_receipts
             (transaction_id,body_hash,committed_heads,committed_at_us,outcome)
             VALUES (?1,?2,?3,?4,'committed')",
            params![
                body.transaction_id.as_slice(),
                actual_body_hash.as_slice(),
                encode_heads(&[event_digest]),
                committed_at_us,
            ],
        )?;
        transaction.commit()?;
        Ok(HumanReceipt {
            transaction_id: body.transaction_id,
            body_hash: actual_body_hash,
            committed_heads: vec![event_digest],
            committed_at_us,
        })
    }

    /// Retrieves a durable receipt without rerunning its effect.
    ///
    /// # Errors
    ///
    /// Returns an error if the channel is invalid, storage fails, or the
    /// transaction is unknown.
    pub fn receipt(&self, transaction_id: [u8; 16]) -> Result<HumanReceipt, HumanCommitError> {
        self.channel.verify()?;
        load_receipt(&open_connection(&self.path)?, transaction_id)?
            .ok_or(HumanCommitError::ItemNotFound)
    }

    /// Reads and authenticates the complete visible password revision.
    ///
    /// # Errors
    ///
    /// Returns an error for an unavailable item or invalid encrypted package.
    pub fn read_password(&self, item: [u8; 16]) -> Result<PasswordRecord, HumanCommitError> {
        let record = self.read_record(item)?;
        password_from_logical(&record)
    }

    /// Stages any selected G6 record and independently encrypted attachments.
    ///
    /// # Errors
    /// Returns an error for invalid logical data, randomness, or durable staging.
    pub fn prepare_create_record(
        &mut self,
        record: &LogicalRecord,
    ) -> Result<PreparedHumanCommand, HumanCommitError> {
        self.prepare_record_write(random_id()?, record)
    }

    /// Generates and stages one independent Ed25519 passkey credential. The
    /// private seed is included only in the encrypted logical revision.
    ///
    /// # Errors
    /// Returns an error unless this is a valid browser registration request or
    /// secure key generation/staging fails.
    pub fn prepare_passkey_registration(
        &mut self,
        request: &PasskeyRequest,
    ) -> Result<PreparedPasskeyRegistration, PasskeyError> {
        if request.operation() != PasskeyOperation::Create {
            return Err(PasskeyError::InvalidRequest);
        }
        let key = PasskeyKeyPair::generate().map_err(HumanCommitError::from)?;
        let mut credential_id = vec![0_u8; 32];
        fill_random(&mut credential_id).map_err(HumanCommitError::from)?;
        let public = PasskeyPublicCredential::new(
            credential_id.clone(),
            request.rp_id().to_owned(),
            request.user_handle().to_vec(),
            *key.public_key(),
            request.user_name().to_owned(),
            request.display_name().to_owned(),
            true,
            false,
            crate::passkey::registration_client_data_json(request),
        );
        let record = LogicalRecord::new(
            RecordKind::Passkey,
            HumanMetadata {
                title: format!("Passkey for {}", request.rp_id()),
                destinations: vec![Destination {
                    label: "RP origin".into(),
                    value: request.origin().to_owned(),
                }],
                tags: Vec::new(),
                favorite: false,
                notes: String::new(),
                fields: Vec::new(),
                source_fields: Vec::new(),
            },
            vec![AuthRecord::Passkey {
                rp_id: request.rp_id().to_owned(),
                user_handle: request.user_handle().to_vec(),
                credential_id,
                cose_alg: -8,
                private_key: key.seed(),
                public_key: *key.public_key(),
                user_name: request.user_name().to_owned(),
                display_name: request.display_name().to_owned(),
                sign_count: 0,
                backup_eligible: true,
                backup_state: false,
            }],
            Vec::new(),
        )?;
        let prepared = self.prepare_create_record(&record)?;
        let connection = open_connection(&self.path)?;
        let generation: i64 = connection.query_row(
            "SELECT generation FROM audit_state WHERE device_id=?1",
            [self.device.as_slice()],
            |row| row.get(0),
        )?;
        let generation = u64::try_from(generation).map_err(|_| HumanCommitError::Integrity)?;
        let response = crate::passkey::encode_status(&PasskeyStatus::Registration(public.clone()));
        let response = self.audit_custody.seal_attempt_state(
            *self.root.vault_id(),
            self.device,
            generation,
            *request.request_id(),
            &response,
        )?;
        connection.execute(
            "INSERT INTO passkey_registration_staging(transaction_id,request_id,item_id,response)
             VALUES(?1,?2,?3,?4)",
            params![
                prepared.transaction_id().as_slice(),
                request.request_id().as_slice(),
                prepared.item_id().as_slice(),
                response
            ],
        )?;
        Ok(PreparedPasskeyRegistration { prepared, public })
    }

    pub(crate) fn sign_passkey_assertion(
        &self,
        item: [u8; 16],
        request: &PasskeyRequest,
        verified: bool,
    ) -> Result<PasskeyAssertion, PasskeyError> {
        self.channel.verify().map_err(HumanCommitError::from)?;
        if request.operation() != PasskeyOperation::Get {
            return Err(PasskeyError::InvalidRequest);
        }
        let record = self.read_record(item)?;
        let [
            AuthRecord::Passkey {
                rp_id,
                user_handle,
                credential_id,
                private_key,
                public_key,
                sign_count,
                ..
            },
        ] = record.auth()
        else {
            return Err(PasskeyError::Integrity);
        };
        if rp_id != request.rp_id()
            || !request
                .credential_ids()
                .iter()
                .any(|id| id == credential_id)
            || *sign_count != 0
        {
            return Err(PasskeyError::InvalidRequest);
        }
        let key = PasskeyKeyPair::from_seed(*private_key).map_err(HumanCommitError::from)?;
        if key.public_key() != public_key {
            return Err(PasskeyError::Integrity);
        }
        let client_data_json = crate::passkey::client_data_json(request);
        let mut authenticator_data = Vec::with_capacity(37);
        authenticator_data.extend_from_slice(&digest(rp_id.as_bytes()));
        authenticator_data.push(1 | if verified { 4 } else { 0 });
        authenticator_data.extend_from_slice(&0_u32.to_be_bytes());
        let mut signed_message = authenticator_data.clone();
        signed_message.extend_from_slice(&digest(&client_data_json));
        let signature = key.sign(&signed_message).map_err(HumanCommitError::from)?;
        Ok(PasskeyAssertion::new(
            credential_id.clone(),
            authenticator_data,
            client_data_json,
            signature,
            user_handle.clone(),
            signed_message,
        ))
    }

    /// Parses a bounded CSV source and classifies every row without writing it.
    ///
    /// # Errors
    /// Rejects malformed, lossy, oversized, or incompletely mapped input.
    pub fn preview_csv(
        &self,
        source_bytes: &[u8],
        profile: &CsvImportProfile,
    ) -> Result<CsvImportPreview, HumanCommitError> {
        self.channel.verify()?;
        let mut preview = migration::parse(source_bytes, profile)?;
        let connection = open_connection(&self.path)?;
        let mut statement = connection
            .prepare("SELECT item_id FROM vault_items WHERE status='active' ORDER BY item_id")?;
        let ids = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        drop(connection);
        let mut existing = Vec::with_capacity(ids.len());
        for id in ids {
            let id = bytes::<16>(&id)?;
            existing.push((id, self.read_record(id)?));
        }
        for (row, record) in preview.rows.iter_mut().zip(&preview.records) {
            if let Some((id, _)) = existing.iter().find(|(_, prior)| prior == record) {
                row.status = CsvRowStatus::ExactDuplicate;
                row.duplicate_item = Some(*id);
            } else if let Some((id, _)) = existing
                .iter()
                .find(|(_, prior)| import_candidate(prior, record))
            {
                row.status = CsvRowStatus::CandidateDuplicate;
                row.duplicate_item = Some(*id);
            }
        }
        Ok(preview)
    }

    /// Parses and classifies a non-extracted 1PUX v3 archive from a stable human source.
    ///
    /// # Errors
    /// Rejects changed, linked, malformed, hostile, oversized, or non-v3 archives.
    pub fn preview_1pux(&self, source: &Path) -> Result<OnePuxImportPreview, HumanCommitError> {
        self.channel.verify()?;
        let mut preview = crate::onepux::preview(source)?;
        self.classify_1pux(&mut preview)?;
        Ok(preview)
    }

    /// Parses 1PUX v3 from an already-open descriptor transferred by the
    /// authenticated human process, without weakening private source modes.
    ///
    /// # Errors
    /// Applies the same stable-source and hostile-archive checks as the path seam.
    pub fn preview_1pux_file(&self, source: File) -> Result<OnePuxImportPreview, HumanCommitError> {
        self.channel.verify()?;
        let mut preview = crate::onepux::preview_file(source)?;
        self.classify_1pux(&mut preview)?;
        Ok(preview)
    }

    fn classify_1pux(&self, preview: &mut OnePuxImportPreview) -> Result<(), HumanCommitError> {
        let connection = open_connection(&self.path)?;
        let mut statement = connection
            .prepare("SELECT item_id FROM vault_items WHERE status='active' ORDER BY item_id")?;
        let ids = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        drop(connection);
        let mut existing = Vec::with_capacity(ids.len());
        for id in ids {
            let id = bytes::<16>(&id)?;
            existing.push((id, self.read_record(id)?));
        }
        for (row, record) in preview.rows.iter_mut().zip(&preview.records) {
            if let Some((id, _)) = existing
                .iter()
                .find(|(_, prior)| crate::onepux::same_import_content(prior, record))
            {
                row.status = CsvRowStatus::ExactDuplicate;
                row.duplicate_item = Some(*id);
            } else if let Some((id, _)) = existing.iter().find(|(_, prior)| {
                crate::onepux::same_external_identity(prior, record)
                    || import_candidate(prior, record)
            }) {
                row.status = CsvRowStatus::CandidateDuplicate;
                row.duplicate_item = Some(*id);
            }
        }
        Ok(())
    }

    /// Encrypts explicitly selected preview rows into one durable signed batch.
    ///
    /// # Errors
    /// Every row needs a decision consistent with its duplicate classification.
    #[allow(clippy::too_many_lines)]
    pub fn prepare_csv_import(
        &mut self,
        preview: CsvImportPreview,
        decisions: Vec<CsvImportDecision>,
    ) -> Result<PreparedCsvImport, HumanCommitError> {
        self.channel.verify()?;
        let CsvImportPreview {
            records,
            rows,
            source,
        } = preview;
        if records.len() != decisions.len() || rows.len() != decisions.len() {
            return Err(HumanCommitError::InvalidInput);
        }
        let transaction_id = random_id()?;
        let batch_id = random_id()?;
        let challenge = random_challenge()?;
        let mut connection = open_connection(&self.path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let expected_state = state_digest(&transaction, self.root.vault_id(), 1)?;
        let mut item_ids = Vec::new();
        let mut new_items = 0_usize;
        let mut replaced = 0_usize;
        let mut skipped_exact = 0_usize;
        let mut excluded = 0_usize;
        let preserved_fields = rows.iter().map(|row| row.unknown_fields).sum();
        for ((record, row), decision) in records.iter().zip(&rows).zip(decisions) {
            let (item, replacement) = match (row.status, decision) {
                (CsvRowStatus::New, CsvImportDecision::ImportNew | CsvImportDecision::KeepBoth)
                | (
                    CsvRowStatus::CandidateDuplicate | CsvRowStatus::ExactDuplicate,
                    CsvImportDecision::KeepBoth,
                ) => {
                    new_items += 1;
                    (random_id()?, false)
                }
                (CsvRowStatus::ExactDuplicate, CsvImportDecision::SkipExact) => {
                    skipped_exact += 1;
                    continue;
                }
                (_, CsvImportDecision::Exclude) => {
                    excluded += 1;
                    continue;
                }
                (
                    CsvRowStatus::CandidateDuplicate | CsvRowStatus::ExactDuplicate,
                    CsvImportDecision::Replace(target),
                ) if row.duplicate_item == Some(target) => {
                    require_active_in(&transaction, target)?;
                    replaced += 1;
                    (target, true)
                }
                _ => return Err(HumanCommitError::InvalidInput),
            };
            let revision = random_id()?;
            let human = record.encode_human();
            let auth = record.encode_auth();
            let package = self
                .root
                .seal_revision_package(RevisionPackageInput {
                    item,
                    revision,
                    issuer_device: self.device,
                    modified_at: now_us()?,
                    kind: record.kind().crypto(),
                    human_plaintext: &human,
                    auth_plaintext: auth.as_deref(),
                })?
                .to_bytes();
            let ordinal = row.ordinal;
            transaction.execute(
                "INSERT INTO import_staging_items
                 (transaction_id,ordinal,item_id,revision_id,item_kind,package,replacement)
                 VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![
                    transaction_id.as_slice(),
                    i64::try_from(ordinal).map_err(|_| HumanCommitError::InvalidInput)?,
                    item.as_slice(),
                    revision.as_slice(),
                    record.kind().name(),
                    package,
                    i64::from(replacement),
                ],
            )?;
            item_ids.push(item);
        }
        let event_pages = item_ids.len().max(1).div_ceil(IMPORT_PAGE_ITEMS);
        let object_digest = import_object_digest(&transaction, transaction_id)?;
        let report = CsvImportReport {
            total: rows.len(),
            new_items,
            replaced,
            skipped_exact,
            excluded,
            preserved_fields,
            event_pages,
        };
        transaction.execute(
            "INSERT INTO import_staging_batches
             (transaction_id,batch_id,source,object_digest,total,new_items,replaced,skipped_exact,excluded,preserved_fields,event_pages)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                transaction_id.as_slice(),
                batch_id.as_slice(),
                source,
                object_digest.as_slice(),
                to_i64(report.total)?,
                to_i64(report.new_items)?,
                to_i64(report.replaced)?,
                to_i64(report.skipped_exact)?,
                to_i64(report.excluded)?,
                to_i64(report.preserved_fields)?,
                to_i64(report.event_pages)?,
            ],
        )?;
        let manifest = encode_import_manifest(batch_id, source, object_digest, &report);
        let body = encode_body(&Body {
            transaction_id,
            events_manifest_digest: digest(&manifest),
            event_count: u64::try_from(item_ids.len() + report.replaced)
                .map_err(|_| HumanCommitError::InvalidInput)?,
            object_manifest_digest: Some(object_digest),
        });
        let body_hash = digest(&body);
        let expires_at_us = now_us()?
            .checked_add(CHALLENGE_LIFETIME_US)
            .ok_or(HumanCommitError::InvalidCommand)?;
        let command = encode_command(&CommandFields {
            vault: *self.root.vault_id(),
            challenge,
            expected_state,
            operation: "import_commit",
            body_hash,
            expires_at_us,
        });
        transaction.execute("INSERT INTO human_challenges (challenge,transaction_id,command,body_hash,expected_state,expires_at_us,consumed) VALUES (?1,?2,?3,?4,?5,?6,0)", params![challenge.as_slice(),transaction_id.as_slice(),command,body_hash.as_slice(),expected_state.as_slice(),expires_at_us])?;
        transaction.execute("INSERT INTO human_staging (transaction_id,operation,event_kind,item_id,body) VALUES (?1,'import_commit','import-batch',?2,?3)",params![transaction_id.as_slice(),batch_id.as_slice(),body])?;
        transaction.commit()?;
        Ok(PreparedCsvImport {
            prepared: PreparedHumanCommand {
                transaction_id,
                item_id: batch_id,
                command,
                body,
            },
            report,
            item_ids,
        })
    }

    /// Revalidates a 1PUX preview and stages selected records plus attachment
    /// streams for the common signed import commit.
    ///
    /// # Errors
    /// Rejects inconsistent decisions, changed archives, invalid streams, or
    /// any staging failure without publishing a partial item.
    #[allow(clippy::too_many_lines)]
    pub fn prepare_1pux_import(
        &mut self,
        preview: OnePuxImportPreview,
        decisions: Vec<CsvImportDecision>,
    ) -> Result<PreparedCsvImport, HumanCommitError> {
        self.channel.verify()?;
        let OnePuxImportPreview {
            records,
            rows,
            attachments,
            source,
            identity,
        } = preview;
        if records.len() != decisions.len()
            || rows.len() != decisions.len()
            || attachments.len() != records.len()
        {
            return Err(HumanCommitError::InvalidInput);
        }
        crate::onepux::verify_source(&source, &identity)?;
        let selected_sources = attachments
            .iter()
            .zip(&decisions)
            .filter(|(_, decision)| {
                !matches!(
                    decision,
                    CsvImportDecision::Exclude | CsvImportDecision::SkipExact
                )
            })
            .flat_map(|(sources, _)| sources);
        let mut logical_bytes = 0_u64;
        let mut file_count = 0_usize;
        for source_entry in selected_sources {
            logical_bytes = logical_bytes
                .checked_add(source_entry.size)
                .ok_or(HumanCommitError::InvalidInput)?;
            file_count = file_count
                .checked_add(1)
                .ok_or(HumanCommitError::InvalidInput)?;
        }
        crate::onepux::ensure_staging_capacity(&self.path, logical_bytes, file_count)?;
        let transaction_id = random_id()?;
        let batch_id = random_id()?;
        let challenge = random_challenge()?;
        let mut connection = open_connection(&self.path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let expected_state = state_digest(&transaction, self.root.vault_id(), 1)?;
        let mut item_ids = Vec::new();
        let mut new_items = 0_usize;
        let mut replaced = 0_usize;
        let mut skipped_exact = 0_usize;
        let mut excluded = 0_usize;
        let preserved_fields = rows.iter().map(|row| row.unknown_fields).sum();
        for (((record, row), sources), decision) in
            records.iter().zip(&rows).zip(&attachments).zip(decisions)
        {
            let (item, replacement) = match (row.status, decision) {
                (CsvRowStatus::New, CsvImportDecision::ImportNew | CsvImportDecision::KeepBoth)
                | (
                    CsvRowStatus::CandidateDuplicate | CsvRowStatus::ExactDuplicate,
                    CsvImportDecision::KeepBoth,
                ) => {
                    new_items += 1;
                    (random_id()?, false)
                }
                (CsvRowStatus::ExactDuplicate, CsvImportDecision::SkipExact) => {
                    skipped_exact += 1;
                    continue;
                }
                (_, CsvImportDecision::Exclude) => {
                    excluded += 1;
                    continue;
                }
                (
                    CsvRowStatus::CandidateDuplicate | CsvRowStatus::ExactDuplicate,
                    CsvImportDecision::Replace(target),
                ) if row.duplicate_item == Some(target) => {
                    require_active_in(&transaction, target)?;
                    replaced += 1;
                    (target, true)
                }
                _ => return Err(HumanCommitError::InvalidInput),
            };
            if record.attachments().len() != sources.len()
                || record
                    .attachments()
                    .iter()
                    .zip(sources)
                    .any(|(descriptor, source)| {
                        descriptor.id() != &source.id
                            || descriptor.size() != source.size
                            || descriptor.sha256() != &source.digest
                            || !descriptor.content().is_empty()
                    })
            {
                return Err(HumanCommitError::InvalidInput);
            }
            let revision = random_id()?;
            let human = record.encode_human();
            let auth = record.encode_auth();
            let package = self
                .root
                .seal_revision_package(RevisionPackageInput {
                    item,
                    revision,
                    issuer_device: self.device,
                    modified_at: now_us()?,
                    kind: record.kind().crypto(),
                    human_plaintext: &human,
                    auth_plaintext: auth.as_deref(),
                })?
                .to_bytes();
            let ordinal = row.ordinal;
            transaction.execute(
                "INSERT INTO import_staging_items
                 (transaction_id,ordinal,item_id,revision_id,item_kind,package,replacement)
                 VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![
                    transaction_id.as_slice(),
                    i64::try_from(ordinal).map_err(|_| HumanCommitError::InvalidInput)?,
                    item.as_slice(),
                    revision.as_slice(),
                    record.kind().name(),
                    package,
                    i64::from(replacement),
                ],
            )?;
            for source_entry in sources {
                let mut sealer = self.root.start_file(source_entry.id, revision)?;
                let mut digest_state = DigestState::new()?;
                let mut remaining = source_entry.size;
                let mut index = 0_i64;
                crate::onepux::stream_entry(&source, &identity, source_entry, |reader| {
                    loop {
                        let count = usize::try_from(remaining.min(1024 * 1024))
                            .map_err(|_| HumanCommitError::InvalidInput)?;
                        let mut plaintext = Zeroizing::new(vec![0_u8; count]);
                        reader.read_exact(&mut plaintext)?;
                        digest_state.update(&plaintext);
                        remaining -=
                            u64::try_from(count).map_err(|_| HumanCommitError::InvalidInput)?;
                        let final_chunk = remaining == 0;
                        let frame = sealer.seal_chunk(&plaintext, final_chunk)?;
                        plaintext.zeroize();
                        transaction.execute("INSERT INTO import_staging_stream_chunks(transaction_id,ordinal,attachment_id,chunk_index,ciphertext)VALUES(?1,?2,?3,?4,?5)",params![transaction_id.as_slice(),i64::try_from(ordinal).map_err(|_| HumanCommitError::InvalidInput)?,source_entry.id.as_slice(),index,frame])?;
                        index = index.checked_add(1).ok_or(HumanCommitError::InvalidInput)?;
                        if final_chunk {
                            break;
                        }
                    }
                    let mut extra = [0_u8; 1];
                    if reader.read(&mut extra)? != 0 || digest_state.finish() != source_entry.digest
                    {
                        return Err(HumanCommitError::InvalidInput);
                    }
                    Ok(())
                })?;
                transaction.execute("INSERT INTO import_staging_streams(transaction_id,ordinal,attachment_id,header,chunk_count)VALUES(?1,?2,?3,?4,?5)",params![transaction_id.as_slice(),i64::try_from(ordinal).map_err(|_| HumanCommitError::InvalidInput)?,source_entry.id.as_slice(),sealer.header(),index])?;
            }
            item_ids.push(item);
        }
        crate::onepux::verify_source(&source, &identity)?;
        let event_pages = item_ids.len().max(1).div_ceil(IMPORT_PAGE_ITEMS);
        let object_digest = import_object_digest(&transaction, transaction_id)?;
        let report = CsvImportReport {
            total: rows.len(),
            new_items,
            replaced,
            skipped_exact,
            excluded,
            preserved_fields,
            event_pages,
        };
        transaction.execute(
            "INSERT INTO import_staging_batches
             (transaction_id,batch_id,source,object_digest,total,new_items,replaced,skipped_exact,excluded,preserved_fields,event_pages)
             VALUES(?1,?2,'1pux',?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                transaction_id.as_slice(), batch_id.as_slice(), object_digest.as_slice(),
                to_i64(report.total)?, to_i64(report.new_items)?, to_i64(report.replaced)?,
                to_i64(report.skipped_exact)?, to_i64(report.excluded)?,
                to_i64(report.preserved_fields)?, to_i64(report.event_pages)?,
            ],
        )?;
        let manifest = encode_import_manifest(batch_id, "1pux", object_digest, &report);
        let body = encode_body(&Body {
            transaction_id,
            events_manifest_digest: digest(&manifest),
            event_count: u64::try_from(item_ids.len() + report.replaced)
                .map_err(|_| HumanCommitError::InvalidInput)?,
            object_manifest_digest: Some(object_digest),
        });
        let body_hash = digest(&body);
        let expires_at_us = now_us()?
            .checked_add(CHALLENGE_LIFETIME_US)
            .ok_or(HumanCommitError::InvalidCommand)?;
        let command = encode_command(&CommandFields {
            vault: *self.root.vault_id(),
            challenge,
            expected_state,
            operation: "import_commit",
            body_hash,
            expires_at_us,
        });
        transaction.execute("INSERT INTO human_challenges(challenge,transaction_id,command,body_hash,expected_state,expires_at_us,consumed)VALUES(?1,?2,?3,?4,?5,?6,0)",params![challenge.as_slice(),transaction_id.as_slice(),command,body_hash.as_slice(),expected_state.as_slice(),expires_at_us])?;
        transaction.execute("INSERT INTO human_staging(transaction_id,operation,event_kind,item_id,body)VALUES(?1,'import_commit','import-batch',?2,?3)",params![transaction_id.as_slice(),batch_id.as_slice(),body])?;
        transaction.commit()?;
        Ok(PreparedCsvImport {
            prepared: PreparedHumanCommand {
                transaction_id,
                item_id: batch_id,
                command,
                body,
            },
            report,
            item_ids,
        })
    }

    /// Encrypts declared files incrementally into SQLite staging and prepares
    /// one atomic signed create without buffering a whole file.
    ///
    /// # Errors
    /// Rejects short/long streams, hash mismatch, size overflow, I/O faults, or
    /// storage failure without publishing any item or partial staging rows.
    #[allow(clippy::too_many_lines)]
    pub fn prepare_create_record_streaming(
        &mut self,
        record: &LogicalRecord,
        sources: &mut [AttachmentReader<'_>],
    ) -> Result<PreparedHumanCommand, HumanCommitError> {
        self.channel.verify()?;
        if record.attachments().len() != sources.len()
            || record
                .attachments()
                .iter()
                .zip(sources.iter())
                .any(|(a, s)| a.id() != &s.id || !a.content().is_empty())
        {
            return Err(HumanCommitError::InvalidInput);
        }
        let item = random_id()?;
        let revision = random_id()?;
        let transaction_id = random_id()?;
        let challenge = random_challenge()?;
        let human = record.encode_human();
        let auth = record.encode_auth();
        let package = self
            .root
            .seal_revision_package(RevisionPackageInput {
                item,
                revision,
                issuer_device: self.device,
                modified_at: now_us()?,
                kind: record.kind().crypto(),
                human_plaintext: &human,
                auth_plaintext: auth.as_deref(),
            })?
            .to_bytes();
        let mut connection = open_connection(&self.path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for (descriptor, source) in record.attachments().iter().zip(sources.iter_mut()) {
            let mut sealer = self.root.start_file(*descriptor.id(), revision)?;
            let mut digest_state = DigestState::new()?;
            let mut remaining = descriptor.size();
            let mut index = 0_i64;
            loop {
                let count = usize::try_from(remaining.min(1024 * 1024))
                    .map_err(|_| HumanCommitError::InvalidInput)?;
                let mut plaintext = Zeroizing::new(vec![0_u8; count]);
                source.reader.read_exact(&mut plaintext)?;
                digest_state.update(&plaintext);
                remaining -= u64::try_from(count).map_err(|_| HumanCommitError::InvalidInput)?;
                let final_chunk = remaining == 0;
                let frame = sealer.seal_chunk(&plaintext, final_chunk)?;
                plaintext.zeroize();
                transaction.execute("INSERT INTO human_staging_stream_chunks (transaction_id,attachment_id,chunk_index,ciphertext) VALUES (?1,?2,?3,?4)",params![transaction_id.as_slice(),descriptor.id().as_slice(),index,frame])?;
                index = index.checked_add(1).ok_or(HumanCommitError::InvalidInput)?;
                if final_chunk {
                    break;
                }
            }
            let mut extra = [0_u8; 1];
            if source.reader.read(&mut extra)? != 0 || digest_state.finish() != *descriptor.sha256()
            {
                return Err(HumanCommitError::InvalidInput);
            }
            transaction.execute("INSERT INTO human_staging_streams (transaction_id,attachment_id,header,chunk_count) VALUES (?1,?2,?3,?4)",params![transaction_id.as_slice(),descriptor.id().as_slice(),sealer.header(),index])?;
        }
        let expected_state = state_digest(&transaction, self.root.vault_id(), 1)?;
        let object_digest = Some(stream_object_digest(
            &transaction,
            transaction_id,
            &package,
        )?);
        let event_manifest = encode_event_manifest(
            "item-revision",
            item,
            Some(revision),
            object_digest,
            None,
            None,
            None,
        );
        let body = encode_body(&Body {
            transaction_id,
            events_manifest_digest: digest(&event_manifest),
            event_count: 1,
            object_manifest_digest: object_digest,
        });
        let body_hash = digest(&body);
        let expires_at_us = now_us()?
            .checked_add(CHALLENGE_LIFETIME_US)
            .ok_or(HumanCommitError::InvalidCommand)?;
        let command = encode_command(&CommandFields {
            vault: *self.root.vault_id(),
            challenge,
            expected_state,
            operation: "item_write",
            body_hash,
            expires_at_us,
        });
        transaction.execute("INSERT INTO human_challenges (challenge,transaction_id,command,body_hash,expected_state,expires_at_us,consumed) VALUES (?1,?2,?3,?4,?5,?6,0)",params![challenge.as_slice(),transaction_id.as_slice(),command,body_hash.as_slice(),expected_state.as_slice(),expires_at_us])?;
        transaction.execute("INSERT INTO human_staging (transaction_id,operation,event_kind,item_id,revision_id,body,package,item_kind,attachments) VALUES (?1,'item_write','item-revision',?2,?3,?4,?5,?6,NULL)",params![transaction_id.as_slice(),item.as_slice(),revision.as_slice(),body,package,record.kind().name()])?;
        transaction.commit()?;
        Ok(PreparedHumanCommand {
            transaction_id,
            item_id: item,
            command,
            body,
        })
    }

    /// Stages a complete replacement revision for any active logical item.
    ///
    /// # Errors
    /// Returns an error when the item is absent or staging cannot complete.
    pub fn prepare_edit_record(
        &mut self,
        item: [u8; 16],
        record: &LogicalRecord,
    ) -> Result<PreparedHumanCommand, HumanCommitError> {
        self.require_active(item)?;
        self.prepare_record_write(item, record)
    }

    /// Reads and authenticates one logical record. Inline attachment bodies are
    /// reconstructed; streaming attachments remain descriptors and are read with
    /// `read_attachment_to` so this metadata operation stays bounded-memory.
    ///
    /// Passkey material returned here is preserved content only; this method is
    /// not a `WebAuthn` authenticator and cannot perform a login.
    ///
    /// # Errors
    /// Returns an error for an absent item, altered revision, or altered file.
    pub fn read_record(&self, item: [u8; 16]) -> Result<LogicalRecord, HumanCommitError> {
        self.channel.verify()?;
        let connection = open_connection(&self.path)?;
        let (revision_bytes, expected_kind): (Vec<u8>, String) = connection
            .query_row(
                "SELECT i.visible_revision,i.kind FROM vault_items i
                 WHERE i.item_id=?1 AND i.status='active'",
                [item.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(HumanCommitError::ItemNotFound)?;
        let revision = bytes::<16>(&revision_bytes)?;
        self.read_revision_from(&connection, item, revision, Some(&expected_kind))
    }

    /// Lists every retained authenticated revision in deterministic LWW order.
    ///
    /// # Errors
    /// Returns an error for an unknown/purged item or altered encrypted history.
    pub fn history(&self, item: [u8; 16]) -> Result<ItemHistory, HumanCommitError> {
        self.channel.verify()?;
        let connection = open_connection(&self.path)?;
        let (visible, status): (Vec<u8>, String) = connection
            .query_row(
                "SELECT visible_revision,status FROM vault_items WHERE item_id=?1",
                [item.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(HumanCommitError::ItemNotFound)?;
        let visible = bytes::<16>(&visible)?;
        let lifecycle = match status.as_str() {
            "active" => ItemLifecycle::Active,
            "trash" => ItemLifecycle::Trash,
            _ => return Err(HumanCommitError::InvalidCommand),
        };
        let mut statement = connection.prepare(
            "SELECT revision_id,package FROM revision_parts WHERE item_id=?1 ORDER BY revision_id",
        )?;
        let rows = statement
            .query_map([item.as_slice()], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let mut entries = Vec::with_capacity(rows.len());
        for (revision, package) in rows {
            let revision = bytes::<16>(&revision)?;
            let opened = self.root.open_revision_package(&package)?;
            if opened.item() != &item || opened.revision() != &revision {
                return Err(HumanCommitError::InvalidCommand);
            }
            let count: i64 = connection.query_row(
                "SELECT (SELECT count(*) FROM attachment_parts WHERE revision_id=?1) +
                        (SELECT count(*) FROM attachment_streams WHERE revision_id=?1)",
                [revision.as_slice()],
                |row| row.get(0),
            )?;
            entries.push(HistoryEntry {
                revision_id: revision,
                modified_at_us: opened.modified_at(),
                issuer_device: *opened.issuer_device(),
                visible: revision == visible,
                attachment_count: usize::try_from(count)
                    .map_err(|_| HumanCommitError::InvalidCommand)?,
            });
        }
        entries.sort_by_key(|entry| (entry.modified_at_us, entry.issuer_device, entry.revision_id));
        if entries.is_empty() || entries.iter().filter(|entry| entry.visible).count() != 1 {
            return Err(HumanCommitError::InvalidCommand);
        }
        Ok(ItemHistory { lifecycle, entries })
    }

    /// Reads one retained historical revision without changing visibility.
    ///
    /// # Errors
    /// Returns an error for a purged/missing revision or failed authentication.
    pub fn read_revision(
        &self,
        item: [u8; 16],
        revision: [u8; 16],
    ) -> Result<LogicalRecord, HumanCommitError> {
        self.channel.verify()?;
        let connection = open_connection(&self.path)?;
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM vault_items WHERE item_id=?1)",
            [item.as_slice()],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(HumanCommitError::ItemNotFound);
        }
        self.read_revision_from(&connection, item, revision, None)
    }

    /// Restores retained content as a freshly encrypted revision plus an
    /// explicit lifecycle event in one human transaction. It never enables use.
    ///
    /// # Errors
    /// Rejects purged/missing or altered revisions. Streaming attachments are
    /// authenticated and re-encrypted incrementally into the same staging
    /// transaction, never buffered as a complete plaintext file.
    pub fn prepare_restore(
        &mut self,
        item: [u8; 16],
        source_revision: [u8; 16],
    ) -> Result<PreparedHumanCommand, HumanCommitError> {
        let history = self.history(item)?;
        if !history
            .entries()
            .iter()
            .any(|entry| entry.revision_id() == &source_revision)
        {
            return Err(HumanCommitError::ItemNotFound);
        }
        let record = self.read_revision(item, source_revision)?;
        let revision = random_id()?;
        let package = self
            .root
            .seal_revision_package(RevisionPackageInput {
                item,
                revision,
                issuer_device: self.device,
                modified_at: now_us()?,
                kind: record.kind().crypto(),
                human_plaintext: &record.encode_human(),
                auth_plaintext: record.encode_auth().as_deref(),
            })?
            .to_bytes();
        let connection = open_connection(&self.path)?;
        let mut attachments = Vec::new();
        for (id, plaintext) in record.attachment_inputs() {
            let inline: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM attachment_parts WHERE attachment_id=?1 AND revision_id=?2)",
                params![id.as_slice(), source_revision.as_slice()],
                |row| row.get(0),
            )?;
            if inline {
                attachments.push((id, self.root.seal_file(id, revision, plaintext)?.to_bytes()));
            }
        }
        attachments.sort_by_key(|(id, _)| *id);
        let attachments = encode_staged_attachments(&attachments);
        let deletions = authority_digests(&connection, item, &["trash"])?;
        let lifecycle = encode_lifecycle_body(&deletions);
        self.prepare_restore_staged(
            item,
            source_revision,
            revision,
            &record,
            &package,
            record.kind().name(),
            &attachments,
            &lifecycle,
        )
    }

    /// Prepares irreversible deletion of selected non-visible revisions.
    ///
    /// # Errors
    /// Rejects empty/duplicate/oversized scope, a visible revision, or prior purge.
    pub fn prepare_purge_revisions(
        &mut self,
        item: [u8; 16],
        revision_ids: Vec<[u8; 16]>,
    ) -> Result<PreparedItemPurge, HumanCommitError> {
        if revision_ids.is_empty() || revision_ids.len() > 4096 {
            return Err(HumanCommitError::InvalidInput);
        }
        let mut sorted = revision_ids;
        sorted.sort_unstable();
        if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(HumanCommitError::InvalidInput);
        }
        let history = self.history(item)?;
        if sorted.iter().any(|revision| {
            history
                .entries()
                .iter()
                .find(|entry| entry.revision_id() == revision)
                .is_none_or(HistoryEntry::visible)
        }) {
            return Err(HumanCommitError::InvalidInput);
        }
        let scope = purge_scope(&open_connection(&self.path)?, item, &sorted, false)?;
        let body = encode_item_purge_body(item, &sorted, false);
        let prepared = self.prepare_item_purge("purge-revisions", item, &body, &scope)?;
        Ok(PreparedItemPurge { prepared, scope })
    }

    /// Prepares terminal purge of an item currently in the trash.
    ///
    /// # Errors
    /// Rejects active, absent, empty, or already purged items.
    pub fn prepare_purge_item(
        &mut self,
        item: [u8; 16],
    ) -> Result<PreparedItemPurge, HumanCommitError> {
        let history = self.history(item)?;
        if history.lifecycle() != ItemLifecycle::Trash || history.entries().is_empty() {
            return Err(HumanCommitError::InvalidInput);
        }
        let mut revisions = history
            .entries()
            .iter()
            .map(|entry| *entry.revision_id())
            .collect::<Vec<_>>();
        revisions.sort_unstable();
        let scope = purge_scope(&open_connection(&self.path)?, item, &revisions, true)?;
        let body = encode_item_purge_body(item, &revisions, true);
        let prepared = self.prepare_item_purge("purge-item", item, &body, &scope)?;
        Ok(PreparedItemPurge { prepared, scope })
    }

    /// Authenticates and writes one active attachment incrementally.
    ///
    /// # Errors
    /// Returns an error for altered/missing chunks, descriptor mismatch or output I/O.
    pub fn read_attachment_to(
        &self,
        item: [u8; 16],
        attachment: [u8; 16],
        output: &mut dyn Write,
    ) -> Result<(), HumanCommitError> {
        self.channel.verify()?;
        let connection = open_connection(&self.path)?;
        let (revision_bytes,package):(Vec<u8>,Vec<u8>)=connection.query_row("SELECT i.visible_revision,r.package FROM vault_items i JOIN revision_parts r ON r.revision_id=i.visible_revision WHERE i.item_id=?1 AND i.status='active'",[item.as_slice()],|row|Ok((row.get(0)?,row.get(1)?))).optional()?.ok_or(HumanCommitError::ItemNotFound)?;
        let revision = bytes::<16>(&revision_bytes)?;
        let opened = self.root.open_revision_package(&package)?;
        let record =
            LogicalRecord::decode_parts(opened.human_plaintext(), opened.auth_plaintext())?;
        let descriptor = record
            .attachments()
            .iter()
            .find(|value| value.id() == &attachment)
            .ok_or(HumanCommitError::ItemNotFound)?;
        let (header,count):(Vec<u8>,i64)=connection.query_row("SELECT header,chunk_count FROM attachment_streams WHERE attachment_id=?1 AND revision_id=?2",params![attachment.as_slice(),revision.as_slice()],|row|Ok((row.get(0)?,row.get(1)?))).optional()?.ok_or(HumanCommitError::ItemNotFound)?;
        let mut decryptor = self.root.start_file_open(attachment, revision, &header)?;
        let mut digest_state = DigestState::new()?;
        let mut total = 0_u64;
        let mut statement=connection.prepare("SELECT chunk_index,ciphertext FROM attachment_stream_chunks WHERE attachment_id=?1 AND revision_id=?2 ORDER BY chunk_index")?;
        let mut rows = statement.query(params![attachment.as_slice(), revision.as_slice()])?;
        let mut seen = 0_i64;
        while let Some(row) = rows.next()? {
            let index: i64 = row.get(0)?;
            let frame: Vec<u8> = row.get(1)?;
            if index != seen {
                return Err(HumanCommitError::InvalidCommand);
            }
            let mut plain = decryptor.open_chunk(&frame, seen + 1 == count)?;
            total = total
                .checked_add(
                    u64::try_from(plain.len()).map_err(|_| HumanCommitError::InvalidInput)?,
                )
                .ok_or(HumanCommitError::InvalidInput)?;
            digest_state.update(&plain);
            output.write_all(&plain)?;
            plain.zeroize();
            seen += 1;
        }
        if seen != count
            || total != descriptor.size()
            || digest_state.finish() != *descriptor.sha256()
        {
            return Err(HumanCommitError::InvalidCommand);
        }
        Ok(())
    }

    /// Updates tags/favorite by publishing a complete encrypted revision.
    ///
    /// # Errors
    /// Returns an error for an absent item or invalid organization limits.
    pub fn prepare_organize(
        &mut self,
        item: [u8; 16],
        tags: Vec<String>,
        favorite: bool,
    ) -> Result<PreparedHumanCommand, HumanCommitError> {
        let mut record = self.read_record(item)?;
        record.set_organization(tags, favorite)?;
        self.prepare_edit_record(item, &record)
    }

    /// Searches decrypted human metadata without a persistent plaintext index.
    ///
    /// # Errors
    /// Returns an error if any visible record fails authentication.
    pub fn search(&self, query: &SearchQuery) -> Result<Vec<SearchHit>, HumanCommitError> {
        self.channel.verify()?;
        let connection = open_connection(&self.path)?;
        let mut statement = connection
            .prepare("SELECT item_id FROM vault_items WHERE status='active' ORDER BY item_id")?;
        let ids = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        drop(connection);
        let mut hits = Vec::new();
        for value in ids {
            let id = bytes::<16>(&value)?;
            let record = self.read_record(id)?;
            if record.matches(query) {
                hits.push(SearchHit::new(id, &record));
            }
        }
        Ok(hits)
    }

    /// Generates a password using the selected native RNG and human configuration.
    ///
    /// # Errors
    /// Returns an error for invalid configuration, wrong channel, or RNG failure.
    pub fn generate_password(
        &self,
        config: &GeneratorConfig,
    ) -> Result<GeneratedPassword, HumanCommitError> {
        struct NativeRng;
        impl PasswordRng for NativeRng {
            fn fill(&mut self, output: &mut [u8]) -> Result<(), HumanCommitError> {
                fill_random(output).map_err(|_| HumanCommitError::RandomUnavailable)
            }
        }
        self.generate_password_with_rng(config, &mut NativeRng)
    }

    /// Runs the same human generator with an explicit RNG boundary for fault evidence.
    ///
    /// # Errors
    /// Returns a fixed failure and no partial output if the RNG cannot fill a block.
    pub fn generate_password_with_rng(
        &self,
        config: &GeneratorConfig,
        rng: &mut impl PasswordRng,
    ) -> Result<GeneratedPassword, HumanCommitError> {
        self.channel.verify()?;
        content::generate_password(config, rng)
    }

    fn read_revision_from(
        &self,
        connection: &Connection,
        item: [u8; 16],
        revision: [u8; 16],
        expected_kind: Option<&str>,
    ) -> Result<LogicalRecord, HumanCommitError> {
        let package: Vec<u8> = connection
            .query_row(
                "SELECT package FROM revision_parts WHERE revision_id=?1 AND item_id=?2",
                params![revision.as_slice(), item.as_slice()],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(HumanCommitError::ItemNotFound)?;
        let opened = self.root.open_revision_package(&package)?;
        let mut record =
            LogicalRecord::decode_parts(opened.human_plaintext(), opened.auth_plaintext())?;
        if opened.item() != &item
            || opened.revision() != &revision
            || record.kind().crypto() != opened.kind()
            || expected_kind.is_some_and(|kind| kind != record.kind().name())
        {
            return Err(HumanCommitError::InvalidCommand);
        }
        let ids = record
            .attachments()
            .iter()
            .map(|value| *value.id())
            .collect::<Vec<_>>();
        let mut has_stream = false;
        for id in ids {
            let file: Option<Vec<u8>> = connection
                .query_row(
                    "SELECT package FROM attachment_parts WHERE attachment_id=?1 AND revision_id=?2",
                    params![id.as_slice(), revision.as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(file) = file {
                record.restore_attachment(id, self.root.open_file(id, revision, &file)?)?;
            } else {
                let exists: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM attachment_streams WHERE attachment_id=?1 AND revision_id=?2)",
                    params![id.as_slice(), revision.as_slice()],
                    |row| row.get(0),
                )?;
                if !exists {
                    return Err(HumanCommitError::InvalidCommand);
                }
                has_stream = true;
            }
        }
        let attachment_count: i64 = connection.query_row(
            "SELECT (SELECT count(*) FROM attachment_parts WHERE revision_id=?1) +
                    (SELECT count(*) FROM attachment_streams WHERE revision_id=?1)",
            [revision.as_slice()],
            |row| row.get(0),
        )?;
        if usize::try_from(attachment_count).ok() != Some(record.attachments().len()) {
            return Err(HumanCommitError::InvalidCommand);
        }
        if has_stream {
            record.validate_descriptors()?;
        } else {
            record.validate_complete()?;
        }
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_restore_staged(
        &mut self,
        item: [u8; 16],
        source_revision: [u8; 16],
        revision: [u8; 16],
        record: &LogicalRecord,
        package: &[u8],
        item_kind: &str,
        attachments: &[u8],
        lifecycle_body: &[u8],
    ) -> Result<PreparedHumanCommand, HumanCommitError> {
        self.channel.verify()?;
        let transaction_id = random_id()?;
        let challenge = random_challenge()?;
        let mut connection = open_connection(&self.path)?;
        let expected_state = state_digest(&connection, self.root.vault_id(), 1)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stream_count = Self::stage_restored_streams(
            &transaction,
            &self.root,
            transaction_id,
            source_revision,
            revision,
            record,
        )?;
        let inline_count = decode_staged_attachments(attachments)?.len();
        if stream_count > 0 && inline_count > 0 {
            return Err(HumanCommitError::InvalidCommand);
        }
        let object_digest = if stream_count > 0 {
            stream_object_digest(&transaction, transaction_id, package)?
        } else {
            staged_object_digest(Some(package), Some(attachments))
                .ok_or(HumanCommitError::InvalidCommand)?
        };
        let manifest = encode_restore_manifest(item, revision, object_digest, lifecycle_body);
        let body = encode_body(&Body {
            transaction_id,
            events_manifest_digest: digest(&manifest),
            event_count: 2,
            object_manifest_digest: Some(object_digest),
        });
        let body_hash = digest(&body);
        let expires_at_us = now_us()?
            .checked_add(CHALLENGE_LIFETIME_US)
            .ok_or(HumanCommitError::InvalidCommand)?;
        let command = encode_command(&CommandFields {
            vault: *self.root.vault_id(),
            challenge,
            expected_state,
            operation: "history_restore",
            body_hash,
            expires_at_us,
        });
        transaction.execute(
            "INSERT INTO human_challenges
             (challenge,transaction_id,command,body_hash,expected_state,expires_at_us,consumed)
             VALUES(?1,?2,?3,?4,?5,?6,0)",
            params![
                challenge.as_slice(),
                transaction_id.as_slice(),
                command,
                body_hash.as_slice(),
                expected_state.as_slice(),
                expires_at_us
            ],
        )?;
        transaction.execute(
            "INSERT INTO human_staging
             (transaction_id,operation,event_kind,item_id,revision_id,body,package,item_kind,attachments,subject_generation,authority_body)
             VALUES(?1,'history_restore','restore',?2,?3,?4,?5,?6,?7,1,?8)",
            params![transaction_id.as_slice(), item.as_slice(), revision.as_slice(), body, package, item_kind, attachments, lifecycle_body],
        )?;
        transaction.commit()?;
        Ok(PreparedHumanCommand {
            transaction_id,
            item_id: item,
            command,
            body,
        })
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn stage_restored_streams(
        transaction: &Transaction<'_>,
        root: &UnlockedRoot,
        transaction_id: [u8; 16],
        source_revision: [u8; 16],
        target_revision: [u8; 16],
        record: &LogicalRecord,
    ) -> Result<usize, HumanCommitError> {
        let mut statement = transaction.prepare(
            "SELECT attachment_id,header,chunk_count FROM attachment_streams
             WHERE revision_id=?1 ORDER BY attachment_id",
        )?;
        let streams = statement
            .query_map([source_revision.as_slice()], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        for (id, header, count) in &streams {
            let id = bytes::<16>(id)?;
            if *count <= 0 {
                return Err(HumanCommitError::InvalidCommand);
            }
            let descriptor = record
                .attachments()
                .iter()
                .find(|attachment| attachment.id() == &id)
                .ok_or(HumanCommitError::InvalidCommand)?;
            let mut opener = root.start_file_open(id, source_revision, header)?;
            let mut sealer = root.start_file(id, target_revision)?;
            let mut digest_state = DigestState::new()?;
            let mut total = 0_u64;
            let mut chunks = transaction.prepare(
                "SELECT chunk_index,ciphertext FROM attachment_stream_chunks
                 WHERE attachment_id=?1 AND revision_id=?2 ORDER BY chunk_index",
            )?;
            let mut rows = chunks.query(params![id.as_slice(), source_revision.as_slice()])?;
            let mut seen = 0_i64;
            while let Some(row) = rows.next()? {
                let index: i64 = row.get(0)?;
                let ciphertext: Vec<u8> = row.get(1)?;
                if index != seen {
                    return Err(HumanCommitError::InvalidCommand);
                }
                let final_chunk = seen + 1 == *count;
                let mut plaintext = Zeroizing::new(opener.open_chunk(&ciphertext, final_chunk)?);
                total = total
                    .checked_add(
                        u64::try_from(plaintext.len())
                            .map_err(|_| HumanCommitError::InvalidInput)?,
                    )
                    .ok_or(HumanCommitError::InvalidInput)?;
                digest_state.update(&plaintext);
                let resealed = sealer.seal_chunk(&plaintext, final_chunk)?;
                plaintext.zeroize();
                transaction.execute(
                    "INSERT INTO human_staging_stream_chunks
                     (transaction_id,attachment_id,chunk_index,ciphertext)
                     VALUES(?1,?2,?3,?4)",
                    params![transaction_id.as_slice(), id.as_slice(), seen, resealed],
                )?;
                seen += 1;
            }
            drop(rows);
            drop(chunks);
            if seen != *count
                || total != descriptor.size()
                || digest_state.finish() != *descriptor.sha256()
            {
                return Err(HumanCommitError::InvalidCommand);
            }
            transaction.execute(
                "INSERT INTO human_staging_streams
                 (transaction_id,attachment_id,header,chunk_count) VALUES(?1,?2,?3,?4)",
                params![
                    transaction_id.as_slice(),
                    id.as_slice(),
                    sealer.header(),
                    count
                ],
            )?;
        }
        Ok(streams.len())
    }

    fn prepare_write(
        &mut self,
        item: [u8; 16],
        record: &PasswordRecord,
    ) -> Result<PreparedHumanCommand, HumanCommitError> {
        let logical = logical_from_password(record)?;
        self.prepare_record_write(item, &logical)
    }

    fn prepare_record_write(
        &mut self,
        item: [u8; 16],
        record: &LogicalRecord,
    ) -> Result<PreparedHumanCommand, HumanCommitError> {
        let revision = random_id()?;
        let human = record.encode_human();
        let auth = record.encode_auth();
        let package = self.root.seal_revision_package(RevisionPackageInput {
            item,
            revision,
            issuer_device: self.device,
            modified_at: now_us()?,
            kind: record.kind().crypto(),
            human_plaintext: &human,
            auth_plaintext: auth.as_deref(),
        })?;
        let package = package.to_bytes();
        let mut attachments = Vec::new();
        for (id, plaintext) in record.attachment_inputs() {
            attachments.push((id, self.root.seal_file(id, revision, plaintext)?.to_bytes()));
        }
        attachments.sort_by_key(|(id, _)| *id);
        let attachments = encode_staged_attachments(&attachments);
        self.prepare(
            "item_write",
            "item-revision",
            item,
            Some(revision),
            Some(&package),
            Some(record.kind().name()),
            Some(&attachments),
            None,
            None,
            None,
            None,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare(
        &mut self,
        operation: &'static str,
        event_kind: &'static str,
        item: [u8; 16],
        revision: Option<[u8; 16]>,
        package: Option<&[u8]>,
        item_kind: Option<&str>,
        attachments: Option<&[u8]>,
        audit_generation: Option<u64>,
        audit_through_seq: Option<u64>,
        subject_generation: Option<u64>,
        authority_body: Option<&[u8]>,
        staged_grant: Option<&[u8]>,
        object_digest_override: Option<[u8; 32]>,
    ) -> Result<PreparedHumanCommand, HumanCommitError> {
        self.channel.verify()?;
        let transaction_id = random_id()?;
        let challenge = random_challenge()?;
        let connection = open_connection(&self.path)?;
        let expected_state = state_digest(&connection, self.root.vault_id(), 1)?;
        let object_digest = object_digest_override.or_else(|| {
            staged_authority_digest(package, attachments, authority_body, staged_grant)
        });
        let event_manifest = encode_event_manifest(
            event_kind,
            item,
            revision,
            object_digest,
            audit_generation,
            audit_through_seq,
            authority_body.map(digest),
        );
        let body = encode_body(&Body {
            transaction_id,
            events_manifest_digest: digest(&event_manifest),
            event_count: 1,
            object_manifest_digest: object_digest,
        });
        let body_hash = digest(&body);
        let expires_at_us = now_us()?
            .checked_add(CHALLENGE_LIFETIME_US)
            .ok_or(HumanCommitError::InvalidCommand)?;
        let command = encode_command(&CommandFields {
            vault: *self.root.vault_id(),
            challenge,
            expected_state,
            operation,
            body_hash,
            expires_at_us,
        });
        let transaction = connection.unchecked_transaction()?;
        transaction.execute(
            "INSERT INTO human_challenges
             (challenge,transaction_id,command,body_hash,expected_state,expires_at_us,consumed)
             VALUES (?1,?2,?3,?4,?5,?6,0)",
            params![
                challenge.as_slice(),
                transaction_id.as_slice(),
                command,
                body_hash.as_slice(),
                expected_state.as_slice(),
                expires_at_us,
            ],
        )?;
        transaction.execute(
            "INSERT INTO human_staging
             (transaction_id,operation,event_kind,item_id,revision_id,body,package,item_kind,attachments,audit_generation,audit_through_seq,subject_generation,authority_body,staged_grant)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                transaction_id.as_slice(),
                operation,
                event_kind,
                item.as_slice(),
                revision.as_ref().map(<[u8; 16]>::as_slice),
                body,
                package,
                item_kind,
                attachments,
                audit_generation.map(i64::try_from).transpose().map_err(|_| HumanCommitError::InvalidInput)?,
                audit_through_seq.map(i64::try_from).transpose().map_err(|_| HumanCommitError::InvalidInput)?,
                subject_generation.map(i64::try_from).transpose().map_err(|_| HumanCommitError::InvalidInput)?,
                authority_body,
                staged_grant,
            ],
        )?;
        transaction.commit()?;
        Ok(PreparedHumanCommand {
            transaction_id,
            item_id: item,
            command,
            body,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_authority(
        &mut self,
        operation: &'static str,
        event_kind: &'static str,
        subject: [u8; 16],
        subject_generation: u64,
        authority_body: &[u8],
        package: Option<&[u8]>,
        staged_grant: Option<&[u8]>,
    ) -> Result<PreparedHumanCommand, HumanCommitError> {
        self.prepare(
            operation,
            event_kind,
            subject,
            None,
            package,
            None,
            None,
            None,
            None,
            Some(subject_generation),
            Some(authority_body),
            staged_grant,
            None,
        )
    }

    fn prepare_item_purge(
        &mut self,
        event_kind: &'static str,
        item: [u8; 16],
        authority_body: &[u8],
        scope: &ItemPurgeScope,
    ) -> Result<PreparedHumanCommand, HumanCommitError> {
        self.prepare(
            "item_purge",
            event_kind,
            item,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(1),
            Some(authority_body),
            None,
            Some(purge_confirmation_digest(scope, authority_body)),
        )
    }

    fn require_active(&self, item: [u8; 16]) -> Result<(), HumanCommitError> {
        let exists = open_connection(&self.path)?
            .query_row(
                "SELECT 1 FROM vault_items WHERE item_id=?1 AND status='active'",
                [item.as_slice()],
                |_| Ok(()),
            )
            .optional()?;
        exists.ok_or(HumanCommitError::ItemNotFound)
    }
}

struct CommandFields<'a> {
    vault: [u8; 16],
    challenge: [u8; 32],
    expected_state: [u8; 32],
    operation: &'a str,
    body_hash: [u8; 32],
    expires_at_us: i64,
}

struct Body {
    transaction_id: [u8; 16],
    events_manifest_digest: [u8; 32],
    event_count: u64,
    object_manifest_digest: Option<[u8; 32]>,
}

struct Challenge {
    command: Vec<u8>,
    body_hash: [u8; 32],
    expires_at_us: i64,
    consumed: bool,
}

#[allow(clippy::struct_field_names)]
struct Staged {
    transaction_id: [u8; 16],
    operation: String,
    event_kind: String,
    item_id: [u8; 16],
    revision_id: Option<[u8; 16]>,
    body: Vec<u8>,
    package: Option<Vec<u8>>,
    item_kind: Option<String>,
    attachments: Option<Vec<u8>>,
    audit_generation: Option<u64>,
    audit_through_seq: Option<u64>,
    subject_generation: Option<u64>,
    authority_body: Option<Vec<u8>>,
    staged_grant: Option<Vec<u8>>,
}

struct ImportBatch {
    batch_id: [u8; 16],
    source: String,
    object_digest: [u8; 32],
    report: CsvImportReport,
}

struct ImportItem {
    ordinal: usize,
    item: [u8; 16],
    revision: [u8; 16],
    kind: String,
    package: Vec<u8>,
    replacement: bool,
}

fn to_i64(value: usize) -> Result<i64, HumanCommitError> {
    i64::try_from(value).map_err(|_| HumanCommitError::InvalidInput)
}

fn require_active_in(connection: &Connection, item: [u8; 16]) -> Result<(), HumanCommitError> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM vault_items WHERE item_id=?1 AND status='active')",
        [item.as_slice()],
        |row| row.get(0),
    )?;
    exists.then_some(()).ok_or(HumanCommitError::ItemNotFound)
}

fn import_account(record: &LogicalRecord) -> &str {
    record.auth().first().map_or("", |auth| match auth {
        AuthRecord::Password { username, .. } | AuthRecord::Ssh { username, .. } => {
            username.as_str()
        }
        AuthRecord::Totp { account, .. } => account.as_str(),
        AuthRecord::Token { profile_id, .. } => profile_id.as_str(),
        AuthRecord::TokenExchange {
            requester_client_id,
            ..
        } => requester_client_id.as_str(),
        AuthRecord::Passkey { user_name, .. } => user_name.as_str(),
    })
}

fn import_candidate(left: &LogicalRecord, right: &LogicalRecord) -> bool {
    left.kind() == right.kind()
        && left.human().title == right.human().title
        && left.human().destinations == right.human().destinations
        && import_account(left) == import_account(right)
}

fn update_import_object_digest(
    state: &mut DigestState,
    ordinal: usize,
    item: [u8; 16],
    revision: [u8; 16],
    kind: &str,
    object_digest: [u8; 32],
    replacement: bool,
) {
    state.update(&u64::try_from(ordinal).unwrap().to_be_bytes());
    state.update(&item);
    state.update(&revision);
    state.update(&u64::try_from(kind.len()).unwrap().to_be_bytes());
    state.update(kind.as_bytes());
    state.update(&object_digest);
    state.update(&[u8::from(replacement)]);
}

fn load_import_items(
    connection: &Connection,
    transaction_id: [u8; 16],
) -> Result<Vec<ImportItem>, HumanCommitError> {
    let mut statement = connection.prepare(
        "SELECT ordinal,item_id,revision_id,item_kind,package,replacement
         FROM import_staging_items WHERE transaction_id=?1 ORDER BY ordinal",
    )?;
    let raw = statement
        .query_map([transaction_id.as_slice()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, bool>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    raw.into_iter()
        .map(|(ordinal, item, revision, kind, package, replacement)| {
            Ok(ImportItem {
                ordinal: usize::try_from(ordinal).map_err(|_| HumanCommitError::BodyChanged)?,
                item: bytes(&item)?,
                revision: bytes(&revision)?,
                kind,
                package,
                replacement,
            })
        })
        .collect()
}

fn import_object_digest(
    connection: &Connection,
    transaction_id: [u8; 16],
) -> Result<[u8; 32], HumanCommitError> {
    let items = load_import_items(connection, transaction_id)?;
    let mut root = DigestState::new()?;
    root.update(b"pm/import-object-root/v1");
    root.update(
        &u64::try_from(items.len().max(1).div_ceil(IMPORT_PAGE_ITEMS))
            .unwrap()
            .to_be_bytes(),
    );
    for page in items.chunks(IMPORT_PAGE_ITEMS) {
        let mut state = DigestState::new()?;
        state.update(b"pm/import-object-page/v1");
        for item in page {
            let object_digest = import_item_object_digest(connection, transaction_id, item)?;
            update_import_object_digest(
                &mut state,
                item.ordinal,
                item.item,
                item.revision,
                &item.kind,
                object_digest,
                item.replacement,
            );
        }
        root.update(&state.finish());
    }
    if items.is_empty() {
        let mut empty = DigestState::new()?;
        empty.update(b"pm/import-object-page/v1");
        root.update(&empty.finish());
    }
    Ok(root.finish())
}

fn import_item_object_digest(
    connection: &Connection,
    transaction_id: [u8; 16],
    item: &ImportItem,
) -> Result<[u8; 32], HumanCommitError> {
    let stream_count: i64 = connection.query_row(
        "SELECT count(*) FROM import_staging_streams WHERE transaction_id=?1 AND ordinal=?2",
        params![transaction_id.as_slice(), to_i64(item.ordinal)?],
        |row| row.get(0),
    )?;
    if stream_count == 0 {
        return Ok(digest(&item.package));
    }
    let mut state = DigestState::new()?;
    state.update(b"pm/staged-stream/v1");
    state.update(
        &u64::try_from(item.package.len())
            .map_err(|_| HumanCommitError::InvalidInput)?
            .to_be_bytes(),
    );
    state.update(&item.package);
    let mut headers = connection.prepare("SELECT attachment_id,header,chunk_count FROM import_staging_streams WHERE transaction_id=?1 AND ordinal=?2 ORDER BY attachment_id")?;
    let mut rows = headers.query(params![transaction_id.as_slice(), to_i64(item.ordinal)?])?;
    while let Some(row) = rows.next()? {
        let id: Vec<u8> = row.get(0)?;
        let header: Vec<u8> = row.get(1)?;
        let count: i64 = row.get(2)?;
        state.update(&id);
        state.update(
            &u64::try_from(header.len())
                .map_err(|_| HumanCommitError::InvalidInput)?
                .to_be_bytes(),
        );
        state.update(&header);
        state.update(&count.to_be_bytes());
    }
    drop(rows);
    drop(headers);
    let mut chunks = connection.prepare("SELECT attachment_id,chunk_index,ciphertext FROM import_staging_stream_chunks WHERE transaction_id=?1 AND ordinal=?2 ORDER BY attachment_id,chunk_index")?;
    let mut rows = chunks.query(params![transaction_id.as_slice(), to_i64(item.ordinal)?])?;
    while let Some(row) = rows.next()? {
        let id: Vec<u8> = row.get(0)?;
        let index: i64 = row.get(1)?;
        let ciphertext: Vec<u8> = row.get(2)?;
        state.update(&id);
        state.update(&index.to_be_bytes());
        state.update(
            &u64::try_from(ciphertext.len())
                .map_err(|_| HumanCommitError::InvalidInput)?
                .to_be_bytes(),
        );
        state.update(&ciphertext);
    }
    Ok(state.finish())
}

fn validate_import_streams(
    connection: &Connection,
    transaction_id: [u8; 16],
    item: &ImportItem,
    record: &LogicalRecord,
) -> Result<(), HumanCommitError> {
    let expected = record
        .attachments()
        .iter()
        .map(|attachment| (*attachment.id(), attachment.content().is_empty()))
        .collect::<BTreeMap<_, _>>();
    let mut statement = connection.prepare(
        "SELECT attachment_id,chunk_count FROM import_staging_streams
         WHERE transaction_id=?1 AND ordinal=?2 ORDER BY attachment_id",
    )?;
    let streams = statement
        .query_map(
            params![transaction_id.as_slice(), to_i64(item.ordinal)?],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    if streams.len() != expected.len() {
        return Err(HumanCommitError::BodyChanged);
    }
    for (raw_id, chunk_count) in streams {
        let attachment_id = bytes::<16>(&raw_id)?;
        if expected.get(&attachment_id) != Some(&true) || chunk_count <= 0 {
            return Err(HumanCommitError::BodyChanged);
        }
        let (count, minimum, maximum): (i64, Option<i64>, Option<i64>) = connection.query_row(
            "SELECT count(*),min(chunk_index),max(chunk_index)
             FROM import_staging_stream_chunks
             WHERE transaction_id=?1 AND ordinal=?2 AND attachment_id=?3",
            params![
                transaction_id.as_slice(),
                to_i64(item.ordinal)?,
                attachment_id.as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if count != chunk_count || minimum != Some(0) || maximum != Some(chunk_count - 1) {
            return Err(HumanCommitError::BodyChanged);
        }
    }
    Ok(())
}

fn load_import_batch(
    connection: &Connection,
    transaction_id: [u8; 16],
) -> Result<ImportBatch, HumanCommitError> {
    let raw = connection
        .query_row(
            "SELECT batch_id,source,object_digest,total,new_items,replaced,skipped_exact,excluded,preserved_fields,event_pages
             FROM import_staging_batches WHERE transaction_id=?1",
            [transaction_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?, row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?, row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?, row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?, row.get::<_, i64>(9)?,
                ))
            },
        )
        .optional()?
        .ok_or(HumanCommitError::BodyChanged)?;
    let convert = |value: i64| usize::try_from(value).map_err(|_| HumanCommitError::BodyChanged);
    Ok(ImportBatch {
        batch_id: bytes(&raw.0)?,
        source: raw.1,
        object_digest: bytes(&raw.2)?,
        report: CsvImportReport {
            total: convert(raw.3)?,
            new_items: convert(raw.4)?,
            replaced: convert(raw.5)?,
            skipped_exact: convert(raw.6)?,
            excluded: convert(raw.7)?,
            preserved_fields: convert(raw.8)?,
            event_pages: convert(raw.9)?,
        },
    })
}

fn open_connection(path: &Path) -> Result<Connection, HumanCommitError> {
    let connection = Connection::open(path)?;
    connection.execute_batch(
        "PRAGMA synchronous=FULL;
         PRAGMA foreign_keys=ON;
         PRAGMA temp_store=MEMORY;
         PRAGMA trusted_schema=OFF;",
    )?;
    Ok(connection)
}

#[allow(clippy::too_many_arguments)]
fn commit_root_rotation(
    transaction: Transaction<'_>,
    root: &UnlockedRoot,
    trusted_root: &TrustedRoot,
    device: [u8; 16],
    audit_custody: &AuditDeviceCustody,
    staged: &Staged,
    body: &Body,
    body_hash: [u8; 32],
    committed_at_us: i64,
) -> Result<HumanReceipt, HumanCommitError> {
    let package = staged
        .package
        .as_deref()
        .ok_or(HumanCommitError::BodyChanged)?;
    let bundle = RootBundle::from_bytes(package)?;
    if bundle.trusted_root() != trusted_root {
        return Err(HumanCommitError::Integrity);
    }
    let changed = transaction.execute(
        "UPDATE encrypted_objects SET value=?1 WHERE kind='human-root-bundle-v1'",
        [package],
    )?;
    if changed != 1 {
        return Err(HumanCommitError::Integrity);
    }
    let head = current_head(&transaction)?;
    audit::append_event(
        &transaction,
        trusted_root,
        Some(root),
        device,
        audit_custody,
        &AuditEvent::new(
            AuditActorKind::Human,
            None,
            AuditAction::Recovery,
            AuditOutcome::Succeeded,
        ),
        committed_at_us,
        head.unwrap_or([0; 32]),
    )?;
    transaction.execute(
        "UPDATE human_challenges SET consumed=1 WHERE transaction_id=?1 AND consumed=0",
        [body.transaction_id.as_slice()],
    )?;
    transaction.execute(
        "DELETE FROM human_staging WHERE transaction_id=?1",
        [body.transaction_id.as_slice()],
    )?;
    let committed_heads = head.into_iter().collect::<Vec<_>>();
    transaction.execute(
        "INSERT INTO human_receipts(transaction_id,body_hash,committed_heads,committed_at_us,outcome) VALUES(?1,?2,?3,?4,'committed')",
        params![body.transaction_id.as_slice(),body_hash.as_slice(),encode_heads(&committed_heads),committed_at_us],
    )?;
    transaction.commit()?;
    Ok(HumanReceipt {
        transaction_id: body.transaction_id,
        body_hash,
        committed_heads,
        committed_at_us,
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn commit_restore(
    transaction: Transaction<'_>,
    root: &UnlockedRoot,
    trusted_root: &TrustedRoot,
    device: [u8; 16],
    audit_custody: &AuditDeviceCustody,
    staged: &Staged,
    body: &Body,
    body_hash: [u8; 32],
    committed_at_us: i64,
) -> Result<HumanReceipt, HumanCommitError> {
    let revision = staged.revision_id.ok_or(HumanCommitError::BodyChanged)?;
    let package = staged
        .package
        .as_deref()
        .ok_or(HumanCommitError::BodyChanged)?;
    let kind = staged
        .item_kind
        .as_deref()
        .ok_or(HumanCommitError::BodyChanged)?;
    let lifecycle_body = staged
        .authority_body
        .as_deref()
        .ok_or(HumanCommitError::BodyChanged)?;
    let previous = current_head(&transaction)?;
    let seq = next_authority_seq(&transaction, device, 1)?;
    let mut revision_parents = authority_digests(&transaction, staged.item_id, &["item-revision"])?;
    if let Some(previous) = previous {
        revision_parents.push(previous);
    }
    revision_parents.sort_unstable();
    revision_parents.dedup();
    let revision_event_id = random_id()?;
    let revision_body = encode_legacy_event_body(
        Some(revision),
        committed_at_us,
        None,
        None,
        Some(
            body.object_manifest_digest
                .ok_or(HumanCommitError::BodyChanged)?,
        ),
    );
    let revision_event = encode_g5_event(&G5EventInput {
        vault: root.vault_id(),
        event_id: revision_event_id,
        authority_epoch: 1,
        issuer_device: device,
        issuer_generation: 1,
        seq,
        previous,
        parents: &revision_parents,
        kind: "item-revision",
        subject: staged.item_id,
        subject_generation: 1,
        body: &revision_body,
    });
    let revision_human_signature = root.sign_human_event(&revision_event)?;
    let revision_device_signature = audit_custody.sign_device_event(&revision_event)?;
    let revision_digest = digest(&revision_event);
    transaction.execute(
        "INSERT INTO revision_parts(revision_id,item_id,package) VALUES(?1,?2,?3)",
        params![revision.as_slice(), staged.item_id.as_slice(), package],
    )?;
    for (attachment, attachment_package) in decode_staged_attachments(
        staged
            .attachments
            .as_deref()
            .ok_or(HumanCommitError::BodyChanged)?,
    )? {
        transaction.execute(
            "INSERT INTO attachment_parts(attachment_id,revision_id,package) VALUES(?1,?2,?3)",
            params![
                attachment.as_slice(),
                revision.as_slice(),
                attachment_package
            ],
        )?;
    }
    transaction.execute("INSERT INTO attachment_streams (attachment_id,revision_id,header,chunk_count) SELECT attachment_id,?2,header,chunk_count FROM human_staging_streams WHERE transaction_id=?1",params![staged.transaction_id.as_slice(),revision.as_slice()])?;
    transaction.execute("INSERT INTO attachment_stream_chunks (attachment_id,revision_id,chunk_index,ciphertext) SELECT attachment_id,?2,chunk_index,ciphertext FROM human_staging_stream_chunks WHERE transaction_id=?1",params![staged.transaction_id.as_slice(),revision.as_slice()])?;
    transaction.execute(
        "UPDATE vault_items SET visible_revision=?2,kind=?3,status='active' WHERE item_id=?1",
        params![staged.item_id.as_slice(), revision.as_slice(), kind],
    )?;
    transaction.execute(
        "INSERT INTO authority_events
         (event_digest,event_id,transaction_id,issuer_device,issuer_generation,seq,previous_digest,parents,kind,subject,subject_generation,event,human_signature,device_signature)
         VALUES(?1,?2,?3,?4,1,?5,?6,?7,'item-revision',?8,1,?9,?10,?11)",
        params![revision_digest.as_slice(), revision_event_id.as_slice(), body.transaction_id.as_slice(), device.as_slice(), i64::try_from(seq).map_err(|_| HumanCommitError::InvalidCommand)?, previous.as_ref().map(<[u8; 32]>::as_slice), encode_heads_allow_empty(&revision_parents), staged.item_id.as_slice(), revision_event, revision_human_signature.as_slice(), revision_device_signature.as_slice()],
    )?;
    transaction.execute(
        "INSERT INTO outbox(event_digest,event) VALUES(?1,?2)",
        params![
            revision_digest.as_slice(),
            encode_signed_event(
                &revision_event,
                &revision_device_signature,
                &revision_human_signature
            )
        ],
    )?;

    let restore_event_id = random_id()?;
    let restore_seq = next_authority_seq(&transaction, device, 1)?;
    let mut restore_parents = authority_digests(
        &transaction,
        staged.item_id,
        &["trash", "restore", "purge-item", "purge-revisions"],
    )?;
    restore_parents.push(revision_digest);
    restore_parents.sort_unstable();
    restore_parents.dedup();
    let restore_event = encode_g5_event(&G5EventInput {
        vault: root.vault_id(),
        event_id: restore_event_id,
        authority_epoch: 1,
        issuer_device: device,
        issuer_generation: 1,
        seq: restore_seq,
        previous: Some(revision_digest),
        parents: &restore_parents,
        kind: "restore",
        subject: staged.item_id,
        subject_generation: 1,
        body: lifecycle_body,
    });
    let restore_human_signature = root.sign_human_event(&restore_event)?;
    let restore_device_signature = audit_custody.sign_device_event(&restore_event)?;
    let restore_digest = digest(&restore_event);
    transaction.execute(
        "INSERT INTO authority_events
         (event_digest,event_id,transaction_id,issuer_device,issuer_generation,seq,previous_digest,parents,kind,subject,subject_generation,event,human_signature,device_signature)
         VALUES(?1,?2,?3,?4,1,?5,?6,?7,'restore',?8,1,?9,?10,?11)",
        params![restore_digest.as_slice(), restore_event_id.as_slice(), random_id()?.as_slice(), device.as_slice(), i64::try_from(restore_seq).map_err(|_| HumanCommitError::InvalidCommand)?, revision_digest.as_slice(), encode_heads_allow_empty(&restore_parents), staged.item_id.as_slice(), restore_event, restore_human_signature.as_slice(), restore_device_signature.as_slice()],
    )?;
    transaction.execute(
        "INSERT INTO outbox(event_digest,event) VALUES(?1,?2)",
        params![
            restore_digest.as_slice(),
            encode_signed_event(
                &restore_event,
                &restore_device_signature,
                &restore_human_signature
            )
        ],
    )?;
    audit::append_event(
        &transaction,
        trusted_root,
        Some(root),
        device,
        audit_custody,
        &AuditEvent::new(
            AuditActorKind::Human,
            None,
            AuditAction::ItemChange,
            AuditOutcome::Succeeded,
        )
        .with_item(staged.item_id, Some(revision)),
        committed_at_us,
        restore_digest,
    )?;
    transaction.execute(
        "UPDATE human_challenges SET consumed=1 WHERE transaction_id=?1 AND consumed=0",
        [body.transaction_id.as_slice()],
    )?;
    transaction.execute(
        "DELETE FROM human_staging WHERE transaction_id=?1",
        [body.transaction_id.as_slice()],
    )?;
    transaction.execute(
        "INSERT INTO human_receipts(transaction_id,body_hash,committed_heads,committed_at_us,outcome)
         VALUES(?1,?2,?3,?4,'committed')",
        params![body.transaction_id.as_slice(), body_hash.as_slice(), encode_heads(&[restore_digest]), committed_at_us],
    )?;
    transaction.commit()?;
    Ok(HumanReceipt {
        transaction_id: body.transaction_id,
        body_hash,
        committed_heads: vec![restore_digest],
        committed_at_us,
    })
}

struct BackupRestoreBatch {
    backup_id: [u8; 16],
    source_vault: [u8; 16],
    object_digest: [u8; 32],
    item_count: usize,
    revision_count: usize,
}

struct BackupRestoreItem {
    target_item: [u8; 16],
    visible_revision: [u8; 16],
    kind: String,
    status: String,
}

struct BackupRestoreRevision {
    source_revision: [u8; 16],
    target_revision: [u8; 16],
    modified_at_us: i64,
    kind: String,
    package: Vec<u8>,
    object_digest: [u8; 32],
}

fn load_backup_restore_batch(
    transaction: &Transaction<'_>,
    transaction_id: [u8; 16],
) -> Result<BackupRestoreBatch, HumanCommitError> {
    let raw = transaction
        .query_row(
            "SELECT backup_id,source_vault,object_digest,item_count,revision_count
             FROM backup_restore_batches WHERE transaction_id=?1",
            [transaction_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or(HumanCommitError::BodyChanged)?;
    Ok(BackupRestoreBatch {
        backup_id: bytes(&raw.0)?,
        source_vault: bytes(&raw.1)?,
        object_digest: bytes(&raw.2)?,
        item_count: usize::try_from(raw.3).map_err(|_| HumanCommitError::BodyChanged)?,
        revision_count: usize::try_from(raw.4).map_err(|_| HumanCommitError::BodyChanged)?,
    })
}

fn load_backup_restore_items(
    transaction: &Transaction<'_>,
    transaction_id: [u8; 16],
) -> Result<Vec<BackupRestoreItem>, HumanCommitError> {
    let mut statement = transaction.prepare(
        "SELECT target_item,target_visible_revision,item_kind,status
         FROM backup_restore_items WHERE transaction_id=?1 ORDER BY target_item",
    )?;
    statement
        .query_map([transaction_id.as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .map(|row| {
            let row = row?;
            Ok(BackupRestoreItem {
                target_item: bytes(&row.0)?,
                visible_revision: bytes(&row.1)?,
                kind: row.2,
                status: row.3,
            })
        })
        .collect()
}

fn load_backup_restore_revisions(
    transaction: &Transaction<'_>,
    transaction_id: [u8; 16],
    item: &BackupRestoreItem,
) -> Result<Vec<BackupRestoreRevision>, HumanCommitError> {
    let mut statement = transaction.prepare(
        "SELECT source_revision,target_revision,modified_at_us,item_kind,package,object_digest
         FROM backup_restore_revisions
         WHERE transaction_id=?1 AND target_item=?2
         ORDER BY (target_revision=?3),modified_at_us,target_revision",
    )?;
    statement
        .query_map(
            params![
                transaction_id.as_slice(),
                item.target_item.as_slice(),
                item.visible_revision.as_slice()
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )?
        .map(|row| {
            let row = row?;
            Ok(BackupRestoreRevision {
                source_revision: bytes(&row.0)?,
                target_revision: bytes(&row.1)?,
                modified_at_us: row.2,
                kind: row.3,
                package: row.4,
                object_digest: bytes(&row.5)?,
            })
        })
        .collect()
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn commit_backup_restore(
    transaction: Transaction<'_>,
    root: &UnlockedRoot,
    trusted_root: &TrustedRoot,
    device: [u8; 16],
    audit_custody: &AuditDeviceCustody,
    body: &Body,
    body_hash: [u8; 32],
    committed_at_us: i64,
) -> Result<HumanReceipt, HumanCommitError> {
    let batch = load_backup_restore_batch(&transaction, body.transaction_id)?;
    let items = load_backup_restore_items(&transaction, body.transaction_id)?;
    if items.len() != batch.item_count
        || crate::backup::restore_batch_digest(&transaction, body.transaction_id)?
            != batch.object_digest
    {
        return Err(HumanCommitError::BodyChanged);
    }

    let mut revision_total = 0_usize;
    for item in &items {
        if transaction
            .query_row(
                "SELECT 1 FROM vault_items WHERE item_id=?1
                 UNION ALL SELECT 1 FROM purged_items WHERE item_id=?1 LIMIT 1",
                [item.target_item.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Err(HumanCommitError::StateChanged);
        }
        let revisions = load_backup_restore_revisions(&transaction, body.transaction_id, item)?;
        if revisions.is_empty()
            || !revisions
                .iter()
                .any(|revision| revision.target_revision == item.visible_revision)
        {
            return Err(HumanCommitError::BodyChanged);
        }
        revision_total = revision_total
            .checked_add(revisions.len())
            .ok_or(HumanCommitError::InvalidCommand)?;
        for revision in revisions {
            let opened = root.open_revision_package(&revision.package)?;
            let record =
                LogicalRecord::decode_parts(opened.human_plaintext(), opened.auth_plaintext())?;
            if opened.item() != &item.target_item
                || opened.revision() != &revision.target_revision
                || opened.modified_at() != revision.modified_at_us
                || record.kind().name() != revision.kind
                || revision.kind != item.kind
                || record.kind().crypto() != opened.kind()
                || crate::backup::restore_graph_digest(
                    &transaction,
                    body.transaction_id,
                    revision.source_revision,
                    &revision.package,
                )? != revision.object_digest
            {
                return Err(HumanCommitError::BodyChanged);
            }
            let stream_count: i64 = transaction.query_row(
                "SELECT count(*) FROM backup_restore_streams
                 WHERE transaction_id=?1 AND source_revision=?2",
                params![
                    body.transaction_id.as_slice(),
                    revision.source_revision.as_slice()
                ],
                |row| row.get(0),
            )?;
            if usize::try_from(stream_count).map_err(|_| HumanCommitError::BodyChanged)?
                != record.attachments().len()
            {
                return Err(HumanCommitError::BodyChanged);
            }
        }
    }
    if revision_total != batch.revision_count {
        return Err(HumanCommitError::BodyChanged);
    }

    let mut previous = current_head(&transaction)?;
    let mut final_digest = previous;
    let mut ordinal = 0_i64;
    let mut first_event = true;
    for item in &items {
        let revisions = load_backup_restore_revisions(&transaction, body.transaction_id, item)?;
        let mut item_revision_digests = Vec::with_capacity(revisions.len());
        for revision in revisions {
            ordinal = ordinal
                .checked_add(1)
                .ok_or(HumanCommitError::InvalidCommand)?;
            let event_id = random_id()?;
            let seq = next_authority_seq(&transaction, device, 1)?;
            let mut parents = item_revision_digests.clone();
            if let Some(head) = previous {
                parents.push(head);
            }
            parents.sort_unstable();
            parents.dedup();
            let modified_at = committed_at_us
                .checked_add(ordinal)
                .ok_or(HumanCommitError::InvalidCommand)?;
            let revision_body = encode_legacy_event_body(
                Some(revision.target_revision),
                modified_at,
                None,
                None,
                Some(revision.object_digest),
            );
            let event = encode_g5_event(&G5EventInput {
                vault: root.vault_id(),
                event_id,
                authority_epoch: 1,
                issuer_device: device,
                issuer_generation: 1,
                seq,
                previous,
                parents: &parents,
                kind: "item-revision",
                subject: item.target_item,
                subject_generation: 1,
                body: &revision_body,
            });
            let human_signature = root.sign_human_event(&event)?;
            let device_signature = audit_custody.sign_device_event(&event)?;
            let event_digest = digest(&event);
            let event_transaction = if first_event {
                first_event = false;
                body.transaction_id
            } else {
                random_id()?
            };
            transaction.execute(
                "INSERT INTO revision_parts(revision_id,item_id,package) VALUES(?1,?2,?3)",
                params![
                    revision.target_revision.as_slice(),
                    item.target_item.as_slice(),
                    revision.package
                ],
            )?;
            transaction.execute(
                "INSERT INTO attachment_streams(attachment_id,revision_id,header,chunk_count)
                 SELECT target_attachment,target_revision,header,chunk_count
                 FROM backup_restore_streams
                 WHERE transaction_id=?1 AND source_revision=?2",
                params![
                    body.transaction_id.as_slice(),
                    revision.source_revision.as_slice()
                ],
            )?;
            transaction.execute(
                "INSERT INTO attachment_stream_chunks(attachment_id,revision_id,chunk_index,ciphertext)
                 SELECT stream.target_attachment,stream.target_revision,chunk.chunk_index,chunk.ciphertext
                 FROM backup_restore_stream_chunks AS chunk
                 JOIN backup_restore_streams AS stream
                   ON stream.transaction_id=chunk.transaction_id
                  AND stream.source_revision=chunk.source_revision
                  AND stream.source_attachment=chunk.source_attachment
                 WHERE chunk.transaction_id=?1 AND chunk.source_revision=?2",
                params![body.transaction_id.as_slice(), revision.source_revision.as_slice()],
            )?;
            transaction.execute(
                "INSERT INTO authority_events
                 (event_digest,event_id,transaction_id,issuer_device,issuer_generation,seq,previous_digest,parents,kind,subject,subject_generation,event,human_signature,device_signature)
                 VALUES(?1,?2,?3,?4,1,?5,?6,?7,'item-revision',?8,1,?9,?10,?11)",
                params![
                    event_digest.as_slice(), event_id.as_slice(), event_transaction.as_slice(),
                    device.as_slice(), i64::try_from(seq).map_err(|_| HumanCommitError::InvalidCommand)?,
                    previous.as_ref().map(<[u8; 32]>::as_slice), encode_heads_allow_empty(&parents),
                    item.target_item.as_slice(), event, human_signature.as_slice(), device_signature.as_slice(),
                ],
            )?;
            transaction.execute(
                "INSERT INTO outbox(event_digest,event) VALUES(?1,?2)",
                params![
                    event_digest.as_slice(),
                    encode_signed_event(&event, &device_signature, &human_signature)
                ],
            )?;
            item_revision_digests.push(event_digest);
            previous = Some(event_digest);
            final_digest = Some(event_digest);
        }
        transaction.execute(
            "INSERT INTO vault_items(item_id,visible_revision,kind,status) VALUES(?1,?2,?3,?4)",
            params![
                item.target_item.as_slice(),
                item.visible_revision.as_slice(),
                item.kind,
                item.status
            ],
        )?;
        if item.status == "trash" {
            ordinal = ordinal
                .checked_add(1)
                .ok_or(HumanCommitError::InvalidCommand)?;
            let event_id = random_id()?;
            let seq = next_authority_seq(&transaction, device, 1)?;
            let mut parents = item_revision_digests;
            if let Some(head) = previous {
                parents.push(head);
            }
            parents.sort_unstable();
            parents.dedup();
            let lifecycle_body = encode_lifecycle_body(&[]);
            let event = encode_g5_event(&G5EventInput {
                vault: root.vault_id(),
                event_id,
                authority_epoch: 1,
                issuer_device: device,
                issuer_generation: 1,
                seq,
                previous,
                parents: &parents,
                kind: "trash",
                subject: item.target_item,
                subject_generation: 1,
                body: &lifecycle_body,
            });
            let human_signature = root.sign_human_event(&event)?;
            let device_signature = audit_custody.sign_device_event(&event)?;
            let event_digest = digest(&event);
            let event_transaction = if first_event {
                first_event = false;
                body.transaction_id
            } else {
                random_id()?
            };
            transaction.execute(
                "INSERT INTO authority_events
                 (event_digest,event_id,transaction_id,issuer_device,issuer_generation,seq,previous_digest,parents,kind,subject,subject_generation,event,human_signature,device_signature)
                 VALUES(?1,?2,?3,?4,1,?5,?6,?7,'trash',?8,1,?9,?10,?11)",
                params![
                    event_digest.as_slice(), event_id.as_slice(), event_transaction.as_slice(),
                    device.as_slice(), i64::try_from(seq).map_err(|_| HumanCommitError::InvalidCommand)?,
                    previous.as_ref().map(<[u8; 32]>::as_slice), encode_heads_allow_empty(&parents),
                    item.target_item.as_slice(), event, human_signature.as_slice(), device_signature.as_slice(),
                ],
            )?;
            transaction.execute(
                "INSERT INTO outbox(event_digest,event) VALUES(?1,?2)",
                params![
                    event_digest.as_slice(),
                    encode_signed_event(&event, &device_signature, &human_signature)
                ],
            )?;
            previous = Some(event_digest);
            final_digest = Some(event_digest);
        }
    }
    let final_digest = final_digest.unwrap_or(batch.object_digest);
    transaction.execute(
        "INSERT INTO imported_backup_history(source_vault,backup_id,record_type,record_id,package)
         SELECT ?2,?3,record_type,record_id,package FROM backup_restore_history
         WHERE transaction_id=?1",
        params![
            body.transaction_id.as_slice(),
            batch.source_vault.as_slice(),
            batch.backup_id.as_slice()
        ],
    )?;
    audit::append_event(
        &transaction,
        trusted_root,
        Some(root),
        device,
        audit_custody,
        &AuditEvent::new(
            AuditActorKind::Human,
            None,
            AuditAction::Restore,
            AuditOutcome::Succeeded,
        )
        .with_item(batch.backup_id, None),
        committed_at_us,
        final_digest,
    )?;
    transaction.execute(
        "UPDATE human_challenges SET consumed=1 WHERE transaction_id=?1 AND consumed=0",
        [body.transaction_id.as_slice()],
    )?;
    transaction.execute(
        "DELETE FROM human_staging WHERE transaction_id=?1",
        [body.transaction_id.as_slice()],
    )?;
    for table in [
        "backup_restore_stream_chunks",
        "backup_restore_streams",
        "backup_restore_revisions",
        "backup_restore_items",
        "backup_restore_history",
        "backup_restore_batches",
    ] {
        transaction.execute(
            &format!("DELETE FROM {table} WHERE transaction_id=?1"),
            [body.transaction_id.as_slice()],
        )?;
    }
    transaction.execute(
        "INSERT INTO human_receipts(transaction_id,body_hash,committed_heads,committed_at_us,outcome)
         VALUES(?1,?2,?3,?4,'committed')",
        params![
            body.transaction_id.as_slice(),
            body_hash.as_slice(),
            encode_heads(&[final_digest]),
            committed_at_us
        ],
    )?;
    transaction.commit()?;
    Ok(HumanReceipt {
        transaction_id: body.transaction_id,
        body_hash,
        committed_heads: vec![final_digest],
        committed_at_us,
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn commit_import_batch(
    transaction: Transaction<'_>,
    root: &UnlockedRoot,
    trusted_root: &TrustedRoot,
    device: [u8; 16],
    audit_custody: &AuditDeviceCustody,
    body: &Body,
    body_hash: [u8; 32],
    committed_at_us: i64,
) -> Result<HumanReceipt, HumanCommitError> {
    let batch = load_import_batch(&transaction, body.transaction_id)?;
    let items = load_import_items(&transaction, body.transaction_id)?;
    if items.len() != batch.report.new_items + batch.report.replaced {
        return Err(HumanCommitError::BodyChanged);
    }
    let mut previous_revisions = Vec::with_capacity(items.len());
    for item in &items {
        let opened = root.open_revision_package(&item.package)?;
        let record =
            LogicalRecord::decode_parts(opened.human_plaintext(), opened.auth_plaintext())?;
        if opened.item() != &item.item
            || opened.revision() != &item.revision
            || record.kind().name() != item.kind
            || record.kind().crypto() != opened.kind()
        {
            return Err(HumanCommitError::BodyChanged);
        }
        validate_import_streams(&transaction, body.transaction_id, item, &record)?;
        if item.replacement {
            require_active_in(&transaction, item.item)?;
        }
        let prior = transaction
            .query_row(
                "SELECT visible_revision FROM vault_items WHERE item_id=?1 AND status='active'",
                [item.item.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|value| bytes(&value))
            .transpose()?;
        previous_revisions.push(prior);
    }

    let mut previous = current_head(&transaction)?;
    let mut final_digest = previous;
    for (index, (item, prior_revision)) in items.iter().zip(previous_revisions).enumerate() {
        let event_id = random_id()?;
        let seq = next_authority_seq(&transaction, device, 1)?;
        let mut parents = authority_digests(&transaction, item.item, &["item-revision"])?;
        if let Some(head) = previous {
            parents.push(head);
        }
        parents.sort_unstable();
        parents.dedup();
        let revisions = prior_revision.into_iter().collect::<Vec<_>>();
        let revision_body = encode_import_revision_body(
            item.revision,
            committed_at_us,
            import_item_object_digest(&transaction, body.transaction_id, item)?,
            &revisions,
        );
        let event = encode_g5_event(&G5EventInput {
            vault: root.vault_id(),
            event_id,
            authority_epoch: 1,
            issuer_device: device,
            issuer_generation: 1,
            seq,
            previous,
            parents: &parents,
            kind: "item-revision",
            subject: item.item,
            subject_generation: 1,
            body: &revision_body,
        });
        let human_signature = root.sign_human_event(&event)?;
        let device_signature = audit_custody.sign_device_event(&event)?;
        let event_digest = digest(&event);
        let signed_event = encode_signed_event(&event, &device_signature, &human_signature);
        let event_transaction = if index == 0 {
            body.transaction_id
        } else {
            random_id()?
        };
        transaction.execute(
            "INSERT INTO revision_parts (revision_id,item_id,package) VALUES(?1,?2,?3)",
            params![item.revision.as_slice(), item.item.as_slice(), item.package],
        )?;
        transaction.execute(
            "INSERT INTO attachment_streams(attachment_id,revision_id,header,chunk_count)
             SELECT attachment_id,?3,header,chunk_count FROM import_staging_streams
             WHERE transaction_id=?1 AND ordinal=?2",
            params![
                body.transaction_id.as_slice(),
                to_i64(item.ordinal)?,
                item.revision.as_slice()
            ],
        )?;
        transaction.execute(
            "INSERT INTO attachment_stream_chunks(attachment_id,revision_id,chunk_index,ciphertext)
             SELECT attachment_id,?3,chunk_index,ciphertext FROM import_staging_stream_chunks
             WHERE transaction_id=?1 AND ordinal=?2",
            params![
                body.transaction_id.as_slice(),
                to_i64(item.ordinal)?,
                item.revision.as_slice()
            ],
        )?;
        transaction.execute(
            "INSERT INTO vault_items (item_id,visible_revision,kind,status)
             VALUES(?1,?2,?3,'active')
             ON CONFLICT(item_id) DO UPDATE SET
               visible_revision=excluded.visible_revision,kind=excluded.kind,status='active'",
            params![item.item.as_slice(), item.revision.as_slice(), item.kind],
        )?;
        transaction.execute(
            "INSERT INTO authority_events
             (event_digest,event_id,transaction_id,issuer_device,issuer_generation,seq,previous_digest,parents,kind,subject,subject_generation,event,human_signature,device_signature)
             VALUES(?1,?2,?3,?4,1,?5,?6,?7,'item-revision',?8,1,?9,?10,?11)",
            params![
                event_digest.as_slice(), event_id.as_slice(), event_transaction.as_slice(),
                device.as_slice(), i64::try_from(seq).map_err(|_| HumanCommitError::InvalidCommand)?,
                previous.as_ref().map(<[u8; 32]>::as_slice), encode_heads_allow_empty(&parents),
                item.item.as_slice(), event, human_signature.as_slice(), device_signature.as_slice(),
            ],
        )?;
        transaction.execute(
            "INSERT INTO outbox(event_digest,event) VALUES(?1,?2)",
            params![event_digest.as_slice(), signed_event],
        )?;
        previous = Some(event_digest);
        final_digest = Some(event_digest);
        if item.replacement {
            let event_id = random_id()?;
            let seq = next_authority_seq(&transaction, device, 1)?;
            let mut parents = authority_digests(&transaction, item.item, &["enable", "disable"])?;
            parents.push(event_digest);
            parents.sort_unstable();
            parents.dedup();
            let reason = encode_reason_body(AuthorizationReason::Replacement);
            let event = encode_g5_event(&G5EventInput {
                vault: root.vault_id(),
                event_id,
                authority_epoch: 1,
                issuer_device: device,
                issuer_generation: 1,
                seq,
                previous: Some(event_digest),
                parents: &parents,
                kind: "disable",
                subject: item.item,
                subject_generation: 1,
                body: &reason,
            });
            let human_signature = root.sign_human_event(&event)?;
            let device_signature = audit_custody.sign_device_event(&event)?;
            let disable_digest = digest(&event);
            let signed_event = encode_signed_event(&event, &device_signature, &human_signature);
            transaction.execute(
                "INSERT INTO authority_events
                 (event_digest,event_id,transaction_id,issuer_device,issuer_generation,seq,previous_digest,parents,kind,subject,subject_generation,event,human_signature,device_signature)
                 VALUES(?1,?2,?3,?4,1,?5,?6,?7,'disable',?8,1,?9,?10,?11)",
                params![
                    disable_digest.as_slice(), event_id.as_slice(), random_id()?.as_slice(),
                    device.as_slice(), i64::try_from(seq).map_err(|_| HumanCommitError::InvalidCommand)?,
                    event_digest.as_slice(), encode_heads_allow_empty(&parents), item.item.as_slice(),
                    event, human_signature.as_slice(), device_signature.as_slice(),
                ],
            )?;
            transaction.execute(
                "INSERT INTO outbox(event_digest,event) VALUES(?1,?2)",
                params![disable_digest.as_slice(), signed_event],
            )?;
            transaction.execute(
                "UPDATE credential_authorizations SET status='disabled',event_digest=?2 WHERE item_id=?1",
                params![item.item.as_slice(), disable_digest.as_slice()],
            )?;
            previous = Some(disable_digest);
            final_digest = Some(disable_digest);
        }
    }
    let final_digest = final_digest.ok_or(HumanCommitError::BodyChanged)?;
    audit::append_event(
        &transaction,
        trusted_root,
        Some(root),
        device,
        audit_custody,
        &AuditEvent::new(
            AuditActorKind::Human,
            None,
            AuditAction::Import,
            AuditOutcome::Succeeded,
        )
        .with_item(batch.batch_id, None),
        committed_at_us,
        final_digest,
    )?;
    transaction.execute(
        "INSERT INTO import_reports
         (batch_id,transaction_id,source,total,new_items,replaced,skipped_exact,excluded,preserved_fields,event_pages,committed_at_us)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![
            batch.batch_id.as_slice(), body.transaction_id.as_slice(), batch.source,
            to_i64(batch.report.total)?, to_i64(batch.report.new_items)?,
            to_i64(batch.report.replaced)?, to_i64(batch.report.skipped_exact)?,
            to_i64(batch.report.excluded)?, to_i64(batch.report.preserved_fields)?,
            to_i64(batch.report.event_pages)?, committed_at_us,
        ],
    )?;
    transaction.execute(
        "UPDATE human_challenges SET consumed=1 WHERE transaction_id=?1 AND consumed=0",
        [body.transaction_id.as_slice()],
    )?;
    transaction.execute(
        "DELETE FROM human_staging WHERE transaction_id=?1",
        [body.transaction_id.as_slice()],
    )?;
    transaction.execute(
        "DELETE FROM import_staging_stream_chunks WHERE transaction_id=?1",
        [body.transaction_id.as_slice()],
    )?;
    transaction.execute(
        "DELETE FROM import_staging_streams WHERE transaction_id=?1",
        [body.transaction_id.as_slice()],
    )?;
    transaction.execute(
        "DELETE FROM import_staging_items WHERE transaction_id=?1",
        [body.transaction_id.as_slice()],
    )?;
    transaction.execute(
        "DELETE FROM import_staging_batches WHERE transaction_id=?1",
        [body.transaction_id.as_slice()],
    )?;
    transaction.execute(
        "INSERT INTO human_receipts
         (transaction_id,body_hash,committed_heads,committed_at_us,outcome)
         VALUES(?1,?2,?3,?4,'committed')",
        params![
            body.transaction_id.as_slice(),
            body_hash.as_slice(),
            encode_heads(&[final_digest]),
            committed_at_us,
        ],
    )?;
    transaction.commit()?;
    Ok(HumanReceipt {
        transaction_id: body.transaction_id,
        body_hash,
        committed_heads: vec![final_digest],
        committed_at_us,
    })
}

#[allow(clippy::too_many_lines)]
fn apply_passkey_registration(
    transaction: &Transaction<'_>,
    staged: &Staged,
) -> Result<(), HumanCommitError> {
    let registration: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = transaction
        .query_row(
            "SELECT request_id,item_id,response FROM passkey_registration_staging
             WHERE transaction_id=?1",
            [staged.transaction_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((request_id, item_id, response)) = registration else {
        return Ok(());
    };
    if staged.event_kind != "item-revision" || item_id.as_slice() != staged.item_id {
        return Err(HumanCommitError::BodyChanged);
    }
    let changed = transaction.execute(
        "UPDATE passkey_requests SET state='complete',item_id=?2,response=?3
         WHERE request_id=?1 AND operation='create' AND state='waiting'",
        params![request_id, item_id, response],
    )?;
    if changed != 1 {
        return Err(HumanCommitError::StateChanged);
    }
    transaction.execute(
        "DELETE FROM passkey_registration_staging WHERE transaction_id=?1",
        [staged.transaction_id.as_slice()],
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn apply_staged(
    transaction: &Transaction<'_>,
    staged: &Staged,
    event_digest: [u8; 32],
    signed_grant: Option<&[u8]>,
) -> Result<(), HumanCommitError> {
    match staged.event_kind.as_str() {
        "item-revision" => {
            let revision = staged.revision_id.expect("validated staging revision");
            let package = staged.package.as_ref().expect("validated staging package");
            let kind = staged.item_kind.as_ref().expect("validated staging kind");
            transaction.execute(
                "INSERT INTO revision_parts (revision_id,item_id,package) VALUES (?1,?2,?3)",
                params![revision.as_slice(), staged.item_id.as_slice(), package],
            )?;
            transaction.execute(
                "INSERT INTO vault_items (item_id,visible_revision,kind,status)
                 VALUES (?1,?2,?3,'active')
                 ON CONFLICT(item_id) DO UPDATE SET
                   visible_revision=excluded.visible_revision,kind=excluded.kind,status='active'",
                params![staged.item_id.as_slice(), revision.as_slice(), kind],
            )?;
            if let Some(encoded) = &staged.attachments {
                for (attachment, attachment_package) in
                    decode_staged_attachments(encoded).map_err(|_| rusqlite::Error::InvalidQuery)?
                {
                    transaction.execute("INSERT INTO attachment_parts (attachment_id,revision_id,package) VALUES (?1,?2,?3)",params![attachment.as_slice(),revision.as_slice(),attachment_package])?;
                }
            }
            transaction.execute("INSERT INTO attachment_streams (attachment_id,revision_id,header,chunk_count) SELECT attachment_id,?2,header,chunk_count FROM human_staging_streams WHERE transaction_id=?1",params![staged.transaction_id.as_slice(),revision.as_slice()])?;
            transaction.execute("INSERT INTO attachment_stream_chunks (attachment_id,revision_id,chunk_index,ciphertext) SELECT attachment_id,?2,chunk_index,ciphertext FROM human_staging_stream_chunks WHERE transaction_id=?1",params![staged.transaction_id.as_slice(),revision.as_slice()])?;
        }
        "trash" => {
            let changed = transaction.execute(
                "UPDATE vault_items SET status='trash' WHERE item_id=?1 AND status='active'",
                [staged.item_id.as_slice()],
            )?;
            if changed != 1 {
                return Err(HumanCommitError::StateChanged);
            }
            transaction.execute(
                "UPDATE credential_authorizations SET status='disabled',event_digest=?2 WHERE item_id=?1",
                params![staged.item_id.as_slice(), event_digest.as_slice()],
            )?;
        }
        "purge-revisions" => {
            apply_revision_purge(transaction, staged, event_digest)?;
        }
        "purge-item" => {
            apply_item_purge(transaction, staged, event_digest)?;
        }
        "audit-purge" => {}
        "agent-grant" => {
            let body = decode_agent_grant_body(
                staged
                    .authority_body
                    .as_deref()
                    .ok_or(HumanCommitError::BodyChanged)?,
            )?;
            let generation = staged
                .subject_generation
                .ok_or(HumanCommitError::BodyChanged)?;
            transaction.execute(
                "INSERT INTO agent_authorizations
                 (subject_id,generation,request_id,transport_rpk,label,environment_binding,grant_event_digest,status)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,'active')",
                params![
                    staged.item_id.as_slice(),
                    i64::try_from(generation).map_err(|_| HumanCommitError::InvalidInput)?,
                    body.request_id.as_slice(),
                    body.transport_rpk.as_slice(),
                    body.label,
                    body.environment_binding,
                    event_digest.as_slice(),
                ],
            )?;
        }
        "agent-revoke" => {
            let generation = staged
                .subject_generation
                .ok_or(HumanCommitError::BodyChanged)?;
            let changed = transaction.execute(
                "UPDATE agent_authorizations SET status='revoked',revoke_event_digest=?3
                 WHERE subject_id=?1 AND generation=?2 AND status='active'",
                params![
                    staged.item_id.as_slice(),
                    i64::try_from(generation).map_err(|_| HumanCommitError::InvalidInput)?,
                    event_digest.as_slice(),
                ],
            )?;
            if changed != 1 {
                return Err(HumanCommitError::StateChanged);
            }
        }
        "suspend" | "resume" => {
            let status = if staged.event_kind == "resume" {
                "resumed"
            } else {
                "suspended"
            };
            transaction.execute(
                "INSERT INTO delegated_state(singleton,status,event_digest) VALUES(1,?1,?2)
                 ON CONFLICT(singleton) DO UPDATE SET status=excluded.status,event_digest=excluded.event_digest",
                params![status, event_digest.as_slice()],
            )?;
        }
        "enable" => {
            let enable = decode_enable_body(
                staged
                    .authority_body
                    .as_deref()
                    .ok_or(HumanCommitError::BodyChanged)?,
            )?;
            transaction.execute(
                "INSERT INTO credential_authorizations
                 (item_id,revision_id,status,event_digest,control_package,grant,grant_commitment)
                 VALUES(?1,?2,'enabled',?3,?4,?5,?6)
                 ON CONFLICT(item_id) DO UPDATE SET revision_id=excluded.revision_id,status='enabled',event_digest=excluded.event_digest,control_package=excluded.control_package,grant=excluded.grant,grant_commitment=excluded.grant_commitment",
                params![
                    staged.item_id.as_slice(),
                    enable.revision.as_slice(),
                    event_digest.as_slice(),
                    staged.package.as_deref().ok_or(HumanCommitError::BodyChanged)?,
                    signed_grant.ok_or(HumanCommitError::BodyChanged)?,
                    enable.commitment.as_slice(),
                ],
            )?;
        }
        "disable" => {
            transaction.execute(
                "UPDATE credential_authorizations SET status='disabled',event_digest=?2 WHERE item_id=?1",
                params![staged.item_id.as_slice(), event_digest.as_slice()],
            )?;
        }
        "restore" => unreachable!("restore uses its two-event commit path"),
        _ => unreachable!("validated staging event kind"),
    }
    Ok(())
}

fn validate_purge_against_current(
    transaction: &Transaction<'_>,
    staged: &Staged,
) -> Result<(), HumanCommitError> {
    let purge = decode_item_purge_body(
        staged
            .authority_body
            .as_deref()
            .ok_or(HumanCommitError::BodyChanged)?,
    )?;
    if purge.item != staged.item_id || purge.terminal != (staged.event_kind == "purge-item") {
        return Err(HumanCommitError::BodyChanged);
    }
    let item: Option<(Vec<u8>, String)> = transaction
        .query_row(
            "SELECT visible_revision,status FROM vault_items WHERE item_id=?1",
            [staged.item_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (visible, status) = item.ok_or(HumanCommitError::StateChanged)?;
    let visible = bytes::<16>(&visible)?;
    let mut statement = transaction
        .prepare("SELECT revision_id FROM revision_parts WHERE item_id=?1 ORDER BY revision_id")?;
    let current = statement
        .query_map([staged.item_id.as_slice()], |row| row.get::<_, Vec<u8>>(0))?
        .map(|value| value?.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
        .collect::<Result<Vec<[u8; 16]>, _>>()?;
    drop(statement);
    if purge.terminal {
        if status != "trash" || current != purge.revisions {
            return Err(HumanCommitError::StateChanged);
        }
    } else if purge
        .revisions
        .iter()
        .any(|revision| revision == &visible || current.binary_search(revision).is_err())
    {
        return Err(HumanCommitError::StateChanged);
    }
    Ok(())
}

fn delete_revision_payloads(
    transaction: &Transaction<'_>,
    revision: [u8; 16],
) -> Result<(), HumanCommitError> {
    transaction.execute(
        "DELETE FROM attachment_stream_chunks WHERE revision_id=?1",
        [revision.as_slice()],
    )?;
    transaction.execute(
        "DELETE FROM attachment_streams WHERE revision_id=?1",
        [revision.as_slice()],
    )?;
    transaction.execute(
        "DELETE FROM attachment_parts WHERE revision_id=?1",
        [revision.as_slice()],
    )?;
    let changed = transaction.execute(
        "DELETE FROM revision_parts WHERE revision_id=?1",
        [revision.as_slice()],
    )?;
    if changed != 1 {
        return Err(HumanCommitError::StateChanged);
    }
    Ok(())
}

fn apply_revision_purge(
    transaction: &Transaction<'_>,
    staged: &Staged,
    event_digest: [u8; 32],
) -> Result<(), HumanCommitError> {
    let purge = decode_item_purge_body(
        staged
            .authority_body
            .as_deref()
            .ok_or(HumanCommitError::BodyChanged)?,
    )?;
    for revision in purge.revisions {
        delete_revision_payloads(transaction, revision)?;
        transaction.execute(
            "INSERT INTO purged_revisions(revision_id,item_id,purge_event_digest) VALUES(?1,?2,?3)",
            params![
                revision.as_slice(),
                staged.item_id.as_slice(),
                event_digest.as_slice()
            ],
        )?;
    }
    Ok(())
}

fn apply_item_purge(
    transaction: &Transaction<'_>,
    staged: &Staged,
    event_digest: [u8; 32],
) -> Result<(), HumanCommitError> {
    let purge = decode_item_purge_body(
        staged
            .authority_body
            .as_deref()
            .ok_or(HumanCommitError::BodyChanged)?,
    )?;
    let scope = purge_scope(transaction, staged.item_id, &purge.revisions, true)?;
    for revision in purge.revisions {
        delete_revision_payloads(transaction, revision)?;
    }
    transaction.execute(
        "DELETE FROM credential_authorizations WHERE item_id=?1",
        [staged.item_id.as_slice()],
    )?;
    let changed = transaction.execute(
        "DELETE FROM vault_items WHERE item_id=?1 AND status='trash'",
        [staged.item_id.as_slice()],
    )?;
    if changed != 1 {
        return Err(HumanCommitError::StateChanged);
    }
    transaction.execute(
        "INSERT INTO purged_items(item_id,purge_event_digest,revision_count,attachment_count,encrypted_bytes)
         VALUES(?1,?2,?3,?4,?5)",
        params![
            staged.item_id.as_slice(),
            event_digest.as_slice(),
            i64::try_from(scope.revision_ids.len()).map_err(|_| HumanCommitError::InvalidInput)?,
            i64::try_from(scope.attachment_count).map_err(|_| HumanCommitError::InvalidInput)?,
            i64::try_from(scope.encrypted_bytes).map_err(|_| HumanCommitError::InvalidInput)?,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_staged(
    transaction: &Transaction<'_>,
    staged: &Staged,
    body: &Body,
) -> Result<(), HumanCommitError> {
    if matches!(
        staged.event_kind.as_str(),
        "root-password-rotate" | "root-recovery-rotate"
    ) {
        let package = staged
            .package
            .as_deref()
            .ok_or(HumanCommitError::BodyChanged)?;
        let replacement = RootBundle::from_bytes(package)?;
        let valid_shape = staged.operation == "root_rotation"
            && staged.item_id == *replacement.trusted_root().vault_id()
            && staged.revision_id.is_none()
            && staged.item_kind.is_none()
            && staged.attachments.is_none()
            && staged.audit_generation.is_none()
            && staged.audit_through_seq.is_none()
            && staged.subject_generation.is_none()
            && staged.authority_body.is_none()
            && staged.staged_grant.is_none();
        if !valid_shape
            || body.event_count != 0
            || body.object_manifest_digest != Some(digest(package))
            || body.events_manifest_digest != digest(staged.event_kind.as_bytes())
        {
            return Err(HumanCommitError::BodyChanged);
        }
        return Ok(());
    }
    if staged.event_kind == "import-batch" {
        let batch = load_import_batch(transaction, staged.transaction_id)?;
        let object_digest = import_object_digest(transaction, staged.transaction_id)?;
        let selected = batch.report.new_items + batch.report.replaced;
        let valid_shape = staged.operation == "import_commit"
            && staged.item_id == batch.batch_id
            && staged.revision_id.is_none()
            && staged.package.is_none()
            && staged.item_kind.is_none()
            && staged.attachments.is_none()
            && staged.audit_generation.is_none()
            && staged.audit_through_seq.is_none()
            && staged.subject_generation.is_none()
            && staged.authority_body.is_none()
            && staged.staged_grant.is_none()
            && batch.report.total == selected + batch.report.skipped_exact + batch.report.excluded
            && batch.report.event_pages == selected.max(1).div_ceil(IMPORT_PAGE_ITEMS);
        let manifest =
            encode_import_manifest(batch.batch_id, &batch.source, object_digest, &batch.report);
        if !valid_shape
            || object_digest != batch.object_digest
            || body.event_count
                != u64::try_from(selected + batch.report.replaced)
                    .map_err(|_| HumanCommitError::BodyChanged)?
            || body.object_manifest_digest != Some(object_digest)
            || body.events_manifest_digest != digest(&manifest)
        {
            return Err(HumanCommitError::BodyChanged);
        }
        return Ok(());
    }
    if staged.event_kind == "backup-restore" {
        let (backup_id, object_digest): (Vec<u8>, Vec<u8>) = transaction
            .query_row(
                "SELECT backup_id,object_digest FROM backup_restore_batches WHERE transaction_id=?1",
                [staged.transaction_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(HumanCommitError::BodyChanged)?;
        let backup_id = bytes::<16>(&backup_id)?;
        let object_digest = bytes::<32>(&object_digest)?;
        let actual_digest =
            crate::backup::restore_batch_digest(transaction, staged.transaction_id)?;
        let event_count = crate::backup::restore_event_count(transaction, staged.transaction_id)?;
        let manifest = encode_event_manifest(
            "backup-restore",
            backup_id,
            None,
            Some(object_digest),
            None,
            None,
            None,
        );
        let valid_shape = staged.operation == "backup_restore"
            && staged.item_id == backup_id
            && staged.revision_id.is_none()
            && staged.package.is_none()
            && staged.item_kind.is_none()
            && staged.attachments.is_none()
            && staged.audit_generation.is_none()
            && staged.audit_through_seq.is_none()
            && staged.subject_generation.is_none()
            && staged.authority_body.is_none()
            && staged.staged_grant.is_none();
        if !valid_shape
            || actual_digest != object_digest
            || body.event_count != event_count
            || body.object_manifest_digest != Some(object_digest)
            || body.events_manifest_digest != digest(&manifest)
        {
            return Err(HumanCommitError::BodyChanged);
        }
        return Ok(());
    }
    let stream_count: i64 = transaction.query_row(
        "SELECT count(*) FROM human_staging_streams WHERE transaction_id=?1",
        [staged.transaction_id.as_slice()],
        |row| row.get(0),
    )?;
    let object_digest = if stream_count > 0 {
        Some(stream_object_digest(
            transaction,
            staged.transaction_id,
            staged
                .package
                .as_deref()
                .ok_or(HumanCommitError::BodyChanged)?,
        )?)
    } else if staged.event_kind == "restore" {
        staged_object_digest(staged.package.as_deref(), staged.attachments.as_deref())
    } else if matches!(staged.event_kind.as_str(), "purge-item" | "purge-revisions") {
        let authority_body = staged
            .authority_body
            .as_deref()
            .ok_or(HumanCommitError::BodyChanged)?;
        let purge = decode_item_purge_body(authority_body)?;
        let scope = purge_scope(
            transaction,
            staged.item_id,
            &purge.revisions,
            purge.terminal,
        )?;
        let digest = purge_confirmation_digest(&scope, authority_body);
        if body.object_manifest_digest != Some(digest) {
            return Err(HumanCommitError::StateChanged);
        }
        Some(digest)
    } else {
        staged_authority_digest(
            staged.package.as_deref(),
            staged.attachments.as_deref(),
            staged.authority_body.as_deref(),
            staged.staged_grant.as_deref(),
        )
    };
    let valid_shape = match staged.event_kind.as_str() {
        "item-revision" => {
            staged.operation == "item_write"
                && staged.revision_id.is_some()
                && staged.package.is_some()
                && staged.item_kind.is_some()
                && (staged
                    .attachments
                    .as_deref()
                    .is_some_and(|value| decode_staged_attachments(value).is_ok())
                    || stream_count > 0)
                && staged.audit_generation.is_none()
                && staged.audit_through_seq.is_none()
                && staged.subject_generation.is_none()
                && staged.authority_body.is_none()
                && staged.staged_grant.is_none()
        }
        "trash" => {
            staged.operation == "item_lifecycle"
                && staged.revision_id.is_none()
                && staged.package.is_none()
                && staged.item_kind.is_none()
                && staged.attachments.is_none()
                && staged.audit_generation.is_none()
                && staged.audit_through_seq.is_none()
                && staged.subject_generation == Some(1)
                && staged
                    .authority_body
                    .as_deref()
                    .is_some_and(|value| decode_lifecycle_body(value).is_ok())
                && staged.staged_grant.is_none()
        }
        "restore" => {
            let inline_count = staged
                .attachments
                .as_deref()
                .and_then(|value| decode_staged_attachments(value).ok())
                .map_or(usize::MAX, |value| value.len());
            staged.operation == "history_restore"
                && staged.revision_id.is_some()
                && staged.package.is_some()
                && staged.item_kind.is_some()
                && inline_count != usize::MAX
                && (stream_count == 0 || inline_count == 0)
                && staged.audit_generation.is_none()
                && staged.audit_through_seq.is_none()
                && staged.subject_generation == Some(1)
                && staged
                    .authority_body
                    .as_deref()
                    .is_some_and(|value| decode_lifecycle_body(value).is_ok())
                && staged.staged_grant.is_none()
        }
        "purge-item" | "purge-revisions" => {
            staged.operation == "item_purge"
                && staged.revision_id.is_none()
                && staged.package.is_none()
                && staged.item_kind.is_none()
                && staged.attachments.is_none()
                && staged.audit_generation.is_none()
                && staged.audit_through_seq.is_none()
                && staged.subject_generation == Some(1)
                && staged
                    .authority_body
                    .as_deref()
                    .and_then(|value| decode_item_purge_body(value).ok())
                    .is_some_and(|value| {
                        value.item == staged.item_id
                            && value.terminal == (staged.event_kind == "purge-item")
                    })
                && staged.staged_grant.is_none()
        }
        "audit-purge" => {
            staged.operation == "audit_purge"
                && staged.revision_id.is_none()
                && staged.package.is_none()
                && staged.item_kind.is_none()
                && staged.attachments.is_none()
                && staged.audit_generation.is_some()
                && staged.audit_through_seq.is_some()
                && staged.subject_generation.is_none()
                && staged.authority_body.is_none()
                && staged.staged_grant.is_none()
        }
        "agent-grant" => {
            staged.operation == "identity_change"
                && staged.subject_generation.is_some()
                && staged
                    .authority_body
                    .as_deref()
                    .is_some_and(|value| decode_agent_grant_body(value).is_ok())
                && staged.package.is_none()
                && staged.staged_grant.is_none()
        }
        "agent-revoke" => {
            staged.operation == "identity_change"
                && staged.subject_generation.is_some()
                && staged
                    .authority_body
                    .as_deref()
                    .is_some_and(|value| decode_reason_body(value).is_ok())
                && staged.package.is_none()
                && staged.staged_grant.is_none()
        }
        "suspend" => {
            staged.operation == "availability_change"
                && staged.subject_generation == Some(1)
                && staged
                    .authority_body
                    .as_deref()
                    .is_some_and(|value| decode_reason_body(value).is_ok())
                && staged.package.is_none()
                && staged.staged_grant.is_none()
        }
        "resume" => {
            staged.operation == "availability_change"
                && staged.subject_generation == Some(1)
                && staged
                    .authority_body
                    .as_deref()
                    .is_some_and(|value| decode_resume_body(value).is_ok())
                && staged.package.is_none()
                && staged.staged_grant.is_none()
        }
        "enable" => {
            staged.operation == "availability_change"
                && staged.subject_generation == Some(1)
                && staged
                    .authority_body
                    .as_deref()
                    .is_some_and(|value| decode_enable_body(value).is_ok())
                && staged.package.is_some()
                && staged.staged_grant.is_some()
        }
        "disable" => {
            staged.operation == "availability_change"
                && staged.subject_generation == Some(1)
                && staged
                    .authority_body
                    .as_deref()
                    .is_some_and(|value| decode_reason_body(value).is_ok())
                && staged.package.is_none()
                && staged.staged_grant.is_none()
        }
        _ => false,
    };
    let event_manifest = encode_event_manifest(
        &staged.event_kind,
        staged.item_id,
        staged.revision_id,
        object_digest,
        staged.audit_generation,
        staged.audit_through_seq,
        staged.authority_body.as_deref().map(digest),
    );
    if valid_shape {
        match staged.event_kind.as_str() {
            "agent-grant" => {
                let decoded = decode_agent_grant_body(
                    staged
                        .authority_body
                        .as_deref()
                        .ok_or(HumanCommitError::BodyChanged)?,
                )?;
                if decoded.predecessors
                    != authority_digests(transaction, staged.item_id, &["agent-grant"])?
                {
                    return Err(HumanCommitError::StateChanged);
                }
            }
            "resume" => {
                let decoded = decode_resume_body(
                    staged
                        .authority_body
                        .as_deref()
                        .ok_or(HumanCommitError::BodyChanged)?,
                )?;
                if decoded != authority_digests(transaction, staged.item_id, &["suspend"])? {
                    return Err(HumanCommitError::StateChanged);
                }
            }
            "enable" => {
                let decoded = decode_enable_body(
                    staged
                        .authority_body
                        .as_deref()
                        .ok_or(HumanCommitError::BodyChanged)?,
                )?;
                if decoded.positives != authority_digests(transaction, staged.item_id, &["enable"])?
                    || decoded.withdrawals
                        != authority_digests(
                            transaction,
                            staged.item_id,
                            &["disable", "trash", "purge-item", "purge-revisions"],
                        )?
                {
                    return Err(HumanCommitError::StateChanged);
                }
            }
            "trash" | "restore" => {
                let decoded = decode_lifecycle_body(
                    staged
                        .authority_body
                        .as_deref()
                        .ok_or(HumanCommitError::BodyChanged)?,
                )?;
                if decoded != authority_digests(transaction, staged.item_id, &["trash"])? {
                    return Err(HumanCommitError::StateChanged);
                }
            }
            "purge-item" | "purge-revisions" => {
                validate_purge_against_current(transaction, staged)?;
            }
            _ => {}
        }
    }
    if staged.event_kind == "restore" {
        let object_digest = object_digest.ok_or(HumanCommitError::BodyChanged)?;
        let manifest = encode_restore_manifest(
            staged.item_id,
            staged.revision_id.ok_or(HumanCommitError::BodyChanged)?,
            object_digest,
            staged
                .authority_body
                .as_deref()
                .ok_or(HumanCommitError::BodyChanged)?,
        );
        if !valid_shape
            || body.event_count != 2
            || body.object_manifest_digest != Some(object_digest)
            || body.events_manifest_digest != digest(&manifest)
        {
            return Err(HumanCommitError::BodyChanged);
        }
        return Ok(());
    }
    if !valid_shape
        || body.event_count != 1
        || body.object_manifest_digest != object_digest
        || body.events_manifest_digest != digest(&event_manifest)
    {
        return Err(HumanCommitError::BodyChanged);
    }
    Ok(())
}

fn logical_from_password(record: &PasswordRecord) -> Result<LogicalRecord, HumanCommitError> {
    LogicalRecord::new(
        RecordKind::Password,
        HumanMetadata {
            title: record.title.clone(),
            destinations: vec![Destination {
                label: String::new(),
                value: record.destination.clone(),
            }],
            tags: Vec::new(),
            favorite: false,
            notes: record.notes.clone(),
            fields: Vec::new(),
            source_fields: Vec::new(),
        },
        vec![AuthRecord::Password {
            username: record.username.clone(),
            password: record.password.clone(),
            destination_refs: vec![0],
        }],
        Vec::new(),
    )
}

fn password_from_logical(record: &LogicalRecord) -> Result<PasswordRecord, HumanCommitError> {
    if record.kind() != RecordKind::Password {
        return Err(HumanCommitError::ItemNotFound);
    }
    let destination = record
        .human()
        .destinations
        .first()
        .ok_or(HumanCommitError::InvalidCommand)?;
    let (username, password) = record
        .auth()
        .iter()
        .find_map(|auth| match auth {
            AuthRecord::Password {
                username, password, ..
            } => Some((username, password)),
            _ => None,
        })
        .ok_or(HumanCommitError::InvalidCommand)?;
    PasswordRecord::new(
        &record.human().title,
        username,
        password,
        &destination.value,
        &record.human().notes,
    )
}

fn delegated_account(record: &LogicalRecord) -> Option<String> {
    record.auth().first().map(|value| match value {
        AuthRecord::Password { username, .. } | AuthRecord::Ssh { username, .. } => {
            username.clone()
        }
        AuthRecord::Totp { account, .. } => account.clone(),
        AuthRecord::Passkey { user_name, .. } => user_name.clone(),
        AuthRecord::Token { profile_id, .. } => profile_id.clone(),
        AuthRecord::TokenExchange {
            requester_client_id,
            ..
        } => requester_client_id.clone(),
    })
}

struct AgentGrantBody {
    request_id: [u8; 16],
    transport_rpk: [u8; 44],
    label: String,
    environment_binding: String,
    predecessors: Vec<[u8; 32]>,
}

fn encode_agent_grant_body(enrollment: &AgentEnrollment, predecessors: &[[u8; 32]]) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(5).unwrap();
    encoder
        .str("request_id")
        .unwrap()
        .bytes(&enrollment.request_id)
        .unwrap();
    encoder.str("public_identity").unwrap().map(2).unwrap();
    encoder
        .str("transport_rpk")
        .unwrap()
        .bytes(&enrollment.transport_rpk)
        .unwrap();
    encoder
        .str("label")
        .unwrap()
        .str(&enrollment.label)
        .unwrap();
    encoder
        .str("predecessor_grants")
        .unwrap()
        .array(u64::try_from(predecessors.len()).unwrap())
        .unwrap();
    for predecessor in predecessors {
        encoder.bytes(predecessor).unwrap();
    }
    encoder.str("expires_at").unwrap().null().unwrap();
    encoder
        .str("environment_binding")
        .unwrap()
        .str(&enrollment.environment_binding)
        .unwrap();
    encoder.into_writer()
}

fn decode_agent_grant_body(value: &[u8]) -> Result<AgentGrantBody, HumanCommitError> {
    let mut decoder = Decoder::new(value);
    expect_map(&mut decoder, 5)?;
    expect_key(&mut decoder, "request_id")?;
    let request_id = decode_fixed(&mut decoder)?;
    expect_key(&mut decoder, "public_identity")?;
    expect_map(&mut decoder, 2)?;
    expect_key(&mut decoder, "transport_rpk")?;
    let transport_rpk = decode_fixed(&mut decoder)?;
    expect_key(&mut decoder, "label")?;
    let label = decoder.str().map_err(invalid)?.to_owned();
    expect_key(&mut decoder, "predecessor_grants")?;
    let count = decoder
        .array()
        .map_err(invalid)?
        .ok_or(HumanCommitError::InvalidCommand)?;
    let mut predecessors =
        Vec::with_capacity(usize::try_from(count).map_err(|_| HumanCommitError::InvalidCommand)?);
    for _ in 0..count {
        let predecessor = decode_fixed(&mut decoder)?;
        if predecessors
            .last()
            .is_some_and(|prior| prior >= &predecessor)
        {
            return Err(HumanCommitError::InvalidCommand);
        }
        predecessors.push(predecessor);
    }
    expect_key(&mut decoder, "expires_at")?;
    decoder.null().map_err(invalid)?;
    expect_key(&mut decoder, "environment_binding")?;
    let environment_binding = decoder.str().map_err(invalid)?.to_owned();
    if decoder.position() != value.len() {
        return Err(HumanCommitError::InvalidCommand);
    }
    let body = AgentGrantBody {
        request_id,
        transport_rpk,
        label,
        environment_binding,
        predecessors,
    };
    let enrollment = AgentEnrollment {
        subject_id: [1; 16],
        request_id: body.request_id,
        transport_rpk: body.transport_rpk,
        label: body.label.clone(),
        environment_binding: body.environment_binding.clone(),
    };
    if encode_agent_grant_body(&enrollment, &body.predecessors) != value {
        return Err(HumanCommitError::InvalidCommand);
    }
    Ok(body)
}

fn encode_lifecycle_body(deletions_seen: &[[u8; 32]]) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(1)
        .unwrap()
        .str("deletions_seen")
        .unwrap()
        .array(u64::try_from(deletions_seen.len()).unwrap())
        .unwrap();
    for deletion in deletions_seen {
        encoder.bytes(deletion).unwrap();
    }
    encoder.into_writer()
}

fn decode_lifecycle_body(value: &[u8]) -> Result<Vec<[u8; 32]>, HumanCommitError> {
    let mut decoder = Decoder::new(value);
    expect_map(&mut decoder, 1)?;
    expect_key(&mut decoder, "deletions_seen")?;
    let count = decoder
        .array()
        .map_err(invalid)?
        .ok_or(HumanCommitError::InvalidCommand)?;
    if count > 4096 {
        return Err(HumanCommitError::InvalidCommand);
    }
    let mut values =
        Vec::with_capacity(usize::try_from(count).map_err(|_| HumanCommitError::InvalidCommand)?);
    for _ in 0..count {
        let value = decode_fixed(&mut decoder)?;
        if values.last().is_some_and(|prior| prior >= &value) {
            return Err(HumanCommitError::InvalidCommand);
        }
        values.push(value);
    }
    if decoder.position() != value.len() || encode_lifecycle_body(&values) != value {
        return Err(HumanCommitError::InvalidCommand);
    }
    Ok(values)
}

struct ItemPurgeBody {
    item: [u8; 16],
    revisions: Vec<[u8; 16]>,
    terminal: bool,
}

fn encode_item_purge_body(item: [u8; 16], revisions: &[[u8; 16]], terminal: bool) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(3)
        .unwrap()
        .str("item_id")
        .unwrap()
        .bytes(&item)
        .unwrap()
        .str("revision_ids")
        .unwrap()
        .array(u64::try_from(revisions.len()).unwrap())
        .unwrap();
    for revision in revisions {
        encoder.bytes(revision).unwrap();
    }
    encoder
        .str("scope")
        .unwrap()
        .str(if terminal { "item" } else { "revisions" })
        .unwrap();
    encoder.into_writer()
}

fn purge_confirmation_digest(scope: &ItemPurgeScope, authority_body: &[u8]) -> [u8; 32] {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(7)
        .unwrap()
        .str("domain")
        .unwrap()
        .str("pm/purge-confirmation/v1")
        .unwrap()
        .str("item_id")
        .unwrap()
        .bytes(&scope.item_id)
        .unwrap()
        .str("revision_ids")
        .unwrap()
        .array(u64::try_from(scope.revision_ids.len()).unwrap())
        .unwrap();
    for revision in &scope.revision_ids {
        encoder.bytes(revision).unwrap();
    }
    encoder
        .str("attachment_count")
        .unwrap()
        .u64(u64::try_from(scope.attachment_count).unwrap())
        .unwrap()
        .str("encrypted_bytes")
        .unwrap()
        .u64(scope.encrypted_bytes)
        .unwrap()
        .str("terminal")
        .unwrap()
        .bool(scope.terminal)
        .unwrap()
        .str("authority_body_digest")
        .unwrap()
        .bytes(&digest(authority_body))
        .unwrap();
    digest(&encoder.into_writer())
}

fn decode_item_purge_body(value: &[u8]) -> Result<ItemPurgeBody, HumanCommitError> {
    let mut decoder = Decoder::new(value);
    expect_map(&mut decoder, 3)?;
    expect_key(&mut decoder, "item_id")?;
    let item = decode_fixed(&mut decoder)?;
    expect_key(&mut decoder, "revision_ids")?;
    let count = decoder
        .array()
        .map_err(invalid)?
        .ok_or(HumanCommitError::InvalidCommand)?;
    if count > 4096 {
        return Err(HumanCommitError::InvalidCommand);
    }
    let mut revisions =
        Vec::with_capacity(usize::try_from(count).map_err(|_| HumanCommitError::InvalidCommand)?);
    for _ in 0..count {
        let revision = decode_fixed(&mut decoder)?;
        if revisions.last().is_some_and(|prior| prior >= &revision) {
            return Err(HumanCommitError::InvalidCommand);
        }
        revisions.push(revision);
    }
    expect_key(&mut decoder, "scope")?;
    let terminal = match decoder.str().map_err(invalid)? {
        "item" => true,
        "revisions" => false,
        _ => return Err(HumanCommitError::InvalidCommand),
    };
    if revisions.is_empty()
        || decoder.position() != value.len()
        || encode_item_purge_body(item, &revisions, terminal) != value
    {
        return Err(HumanCommitError::InvalidCommand);
    }
    Ok(ItemPurgeBody {
        item,
        revisions,
        terminal,
    })
}

fn purge_scope(
    connection: &Connection,
    item: [u8; 16],
    revisions: &[[u8; 16]],
    terminal: bool,
) -> Result<ItemPurgeScope, HumanCommitError> {
    let mut attachment_count = 0_usize;
    let mut encrypted_bytes = 0_u64;
    for revision in revisions {
        let package_bytes: i64 = connection
            .query_row(
                "SELECT length(package) FROM revision_parts WHERE revision_id=?1 AND item_id=?2",
                params![revision.as_slice(), item.as_slice()],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(HumanCommitError::ItemNotFound)?;
        let (inline_count, inline_bytes): (i64, i64) = connection.query_row(
            "SELECT count(*),coalesce(sum(length(package)),0) FROM attachment_parts WHERE revision_id=?1",
            [revision.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let (stream_count, stream_bytes): (i64, i64) = connection.query_row(
            "SELECT count(*),coalesce(sum(length(header)),0) FROM attachment_streams WHERE revision_id=?1",
            [revision.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let chunk_bytes: i64 = connection.query_row(
            "SELECT coalesce(sum(length(ciphertext)),0) FROM attachment_stream_chunks WHERE revision_id=?1",
            [revision.as_slice()],
            |row| row.get(0),
        )?;
        attachment_count = attachment_count
            .checked_add(
                usize::try_from(inline_count + stream_count)
                    .map_err(|_| HumanCommitError::InvalidCommand)?,
            )
            .ok_or(HumanCommitError::InvalidCommand)?;
        for value in [package_bytes, inline_bytes, stream_bytes, chunk_bytes] {
            encrypted_bytes = encrypted_bytes
                .checked_add(u64::try_from(value).map_err(|_| HumanCommitError::InvalidCommand)?)
                .ok_or(HumanCommitError::InvalidCommand)?;
        }
    }
    Ok(ItemPurgeScope {
        item_id: item,
        revision_ids: revisions.to_vec(),
        attachment_count,
        encrypted_bytes,
        terminal,
    })
}

fn encode_reason_body(reason: AuthorizationReason) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(1)
        .unwrap()
        .str("reason_code")
        .unwrap()
        .str(reason.name())
        .unwrap();
    encoder.into_writer()
}

fn decode_reason_body(value: &[u8]) -> Result<(), HumanCommitError> {
    let mut decoder = Decoder::new(value);
    expect_map(&mut decoder, 1)?;
    expect_key(&mut decoder, "reason_code")?;
    let reason = match decoder.str().map_err(invalid)? {
        "owner_request" => AuthorizationReason::OwnerRequest,
        "replacement" => AuthorizationReason::Replacement,
        "suspected_compromise" => AuthorizationReason::SuspectedCompromise,
        _ => return Err(HumanCommitError::InvalidCommand),
    };
    if decoder.position() != value.len() || encode_reason_body(reason) != value {
        return Err(HumanCommitError::InvalidCommand);
    }
    Ok(())
}

fn encode_resume_body(withdrawals: &[[u8; 32]]) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(2).unwrap();
    encoder
        .str("prior_positive_events")
        .unwrap()
        .array(0)
        .unwrap();
    encoder
        .str("withdrawals_seen")
        .unwrap()
        .array(u64::try_from(withdrawals.len()).unwrap())
        .unwrap();
    for withdrawal in withdrawals {
        encoder.bytes(withdrawal).unwrap();
    }
    encoder.into_writer()
}

fn decode_resume_body(value: &[u8]) -> Result<Vec<[u8; 32]>, HumanCommitError> {
    let mut decoder = Decoder::new(value);
    expect_map(&mut decoder, 2)?;
    expect_key(&mut decoder, "prior_positive_events")?;
    if decoder.array().map_err(invalid)? != Some(0) {
        return Err(HumanCommitError::InvalidCommand);
    }
    expect_key(&mut decoder, "withdrawals_seen")?;
    let count = decoder
        .array()
        .map_err(invalid)?
        .ok_or(HumanCommitError::InvalidCommand)?;
    let mut withdrawals =
        Vec::with_capacity(usize::try_from(count).map_err(|_| HumanCommitError::InvalidCommand)?);
    for _ in 0..count {
        let withdrawal = decode_fixed(&mut decoder)?;
        if withdrawals.last().is_some_and(|prior| prior >= &withdrawal) {
            return Err(HumanCommitError::InvalidCommand);
        }
        withdrawals.push(withdrawal);
    }
    if decoder.position() != value.len() || encode_resume_body(&withdrawals) != value {
        return Err(HumanCommitError::InvalidCommand);
    }
    Ok(withdrawals)
}

struct EnableBody {
    revision: [u8; 16],
    commitment: [u8; 32],
    positives: Vec<[u8; 32]>,
    withdrawals: Vec<[u8; 32]>,
}

fn encode_enable_body(
    revision: [u8; 16],
    commitment: [u8; 32],
    positives: &[[u8; 32]],
    withdrawals: &[[u8; 32]],
) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(4).unwrap();
    encoder
        .str("revision_id")
        .unwrap()
        .bytes(&revision)
        .unwrap();
    encoder
        .str("grant_commitments")
        .unwrap()
        .array(1)
        .unwrap()
        .bytes(&commitment)
        .unwrap();
    encoder
        .str("prior_positive_events")
        .unwrap()
        .array(u64::try_from(positives.len()).unwrap())
        .unwrap();
    for positive in positives {
        encoder.bytes(positive).unwrap();
    }
    encoder
        .str("withdrawals_seen")
        .unwrap()
        .array(u64::try_from(withdrawals.len()).unwrap())
        .unwrap();
    for withdrawal in withdrawals {
        encoder.bytes(withdrawal).unwrap();
    }
    encoder.into_writer()
}

fn decode_enable_body(value: &[u8]) -> Result<EnableBody, HumanCommitError> {
    let mut decoder = Decoder::new(value);
    expect_map(&mut decoder, 4)?;
    expect_key(&mut decoder, "revision_id")?;
    let revision = decode_fixed(&mut decoder)?;
    expect_key(&mut decoder, "grant_commitments")?;
    if decoder.array().map_err(invalid)? != Some(1) {
        return Err(HumanCommitError::InvalidCommand);
    }
    let commitment = decode_fixed(&mut decoder)?;
    expect_key(&mut decoder, "prior_positive_events")?;
    let positives = decode_sorted_digests(&mut decoder)?;
    expect_key(&mut decoder, "withdrawals_seen")?;
    let withdrawals = decode_sorted_digests(&mut decoder)?;
    if decoder.position() != value.len()
        || encode_enable_body(revision, commitment, &positives, &withdrawals) != value
    {
        return Err(HumanCommitError::InvalidCommand);
    }
    Ok(EnableBody {
        revision,
        commitment,
        positives,
        withdrawals,
    })
}

fn decode_sorted_digests(decoder: &mut Decoder<'_>) -> Result<Vec<[u8; 32]>, HumanCommitError> {
    let count = decoder
        .array()
        .map_err(invalid)?
        .ok_or(HumanCommitError::InvalidCommand)?;
    if count > 4096 {
        return Err(HumanCommitError::InvalidCommand);
    }
    let mut values =
        Vec::with_capacity(usize::try_from(count).map_err(|_| HumanCommitError::InvalidCommand)?);
    for _ in 0..count {
        let value = decode_fixed(decoder)?;
        if values.last().is_some_and(|prior| prior >= &value) {
            return Err(HumanCommitError::InvalidCommand);
        }
        values.push(value);
    }
    Ok(values)
}

fn encode_staged_attachments(values: &[([u8; 16], Vec<u8>)]) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.array(u64::try_from(values.len()).unwrap()).unwrap();
    for (id, package) in values {
        encoder.map(2).unwrap();
        encoder.str("id").unwrap().bytes(id).unwrap();
        encoder.str("package").unwrap().bytes(package).unwrap();
    }
    encoder.into_writer()
}

type StagedAttachment = ([u8; 16], Vec<u8>);

fn decode_staged_attachments(
    bytes_value: &[u8],
) -> Result<Vec<StagedAttachment>, HumanCommitError> {
    let mut decoder = Decoder::new(bytes_value);
    let count = decoder
        .array()
        .map_err(invalid)?
        .ok_or(HumanCommitError::InvalidCommand)?;
    let count = usize::try_from(count).map_err(|_| HumanCommitError::InvalidCommand)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        expect_map(&mut decoder, 2)?;
        expect_key(&mut decoder, "id")?;
        let id = decode_fixed(&mut decoder)?;
        expect_key(&mut decoder, "package")?;
        let package = decoder.bytes().map_err(invalid)?.to_vec();
        if values.iter().any(|(other, _)| other == &id) {
            return Err(HumanCommitError::InvalidCommand);
        }
        values.push((id, package));
    }
    if decoder.position() != bytes_value.len() {
        return Err(HumanCommitError::InvalidCommand);
    }
    Ok(values)
}

fn staged_object_digest(package: Option<&[u8]>, attachments: Option<&[u8]>) -> Option<[u8; 32]> {
    let package = package?;
    let mut encoder = Encoder::new(Vec::new());
    encoder.array(2).unwrap().bytes(package).unwrap();
    if let Some(attachments) = attachments {
        encoder.bytes(attachments).unwrap();
    } else {
        encoder.null().unwrap();
    }
    Some(digest(&encoder.into_writer()))
}

fn staged_authority_digest(
    package: Option<&[u8]>,
    attachments: Option<&[u8]>,
    authority_body: Option<&[u8]>,
    staged_grant: Option<&[u8]>,
) -> Option<[u8; 32]> {
    if authority_body.is_none() && staged_grant.is_none() {
        return staged_object_digest(package, attachments);
    }
    let mut encoder = Encoder::new(Vec::new());
    encoder.array(4).unwrap();
    encode_optional_bytes(&mut encoder, package);
    encode_optional_bytes(&mut encoder, attachments);
    encode_optional_bytes(&mut encoder, authority_body);
    encode_optional_bytes(&mut encoder, staged_grant);
    Some(digest(&encoder.into_writer()))
}

fn stream_object_digest(
    transaction: &Transaction<'_>,
    transaction_id: [u8; 16],
    package: &[u8],
) -> Result<[u8; 32], HumanCommitError> {
    let mut state = DigestState::new()?;
    state.update(b"pm/staged-stream/v1");
    state.update(
        &u64::try_from(package.len())
            .map_err(|_| HumanCommitError::InvalidInput)?
            .to_be_bytes(),
    );
    state.update(package);
    let mut headers = transaction.prepare("SELECT attachment_id,header,chunk_count FROM human_staging_streams WHERE transaction_id=?1 ORDER BY attachment_id")?;
    let mut rows = headers.query([transaction_id.as_slice()])?;
    while let Some(row) = rows.next()? {
        let id: Vec<u8> = row.get(0)?;
        let header: Vec<u8> = row.get(1)?;
        let count: i64 = row.get(2)?;
        state.update(&id);
        state.update(
            &u64::try_from(header.len())
                .map_err(|_| HumanCommitError::InvalidInput)?
                .to_be_bytes(),
        );
        state.update(&header);
        state.update(&count.to_be_bytes());
    }
    let mut chunks=transaction.prepare("SELECT attachment_id,chunk_index,ciphertext FROM human_staging_stream_chunks WHERE transaction_id=?1 ORDER BY attachment_id,chunk_index")?;
    let mut rows = chunks.query([transaction_id.as_slice()])?;
    while let Some(row) = rows.next()? {
        let id: Vec<u8> = row.get(0)?;
        let index: i64 = row.get(1)?;
        let bytes_value: Vec<u8> = row.get(2)?;
        state.update(&id);
        state.update(&index.to_be_bytes());
        state.update(
            &u64::try_from(bytes_value.len())
                .map_err(|_| HumanCommitError::InvalidInput)?
                .to_be_bytes(),
        );
        state.update(&bytes_value);
    }
    Ok(state.finish())
}

fn encode_command(command: &CommandFields<'_>) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(7).unwrap();
    encoder.str("v").unwrap().u64(1).unwrap();
    encoder.str("vault").unwrap().bytes(&command.vault).unwrap();
    encoder
        .str("challenge")
        .unwrap()
        .bytes(&command.challenge)
        .unwrap();
    encoder
        .str("expected_state")
        .unwrap()
        .bytes(&command.expected_state)
        .unwrap();
    encoder
        .str("operation")
        .unwrap()
        .str(command.operation)
        .unwrap();
    encoder
        .str("body_hash")
        .unwrap()
        .bytes(&command.body_hash)
        .unwrap();
    encoder
        .str("expires_at")
        .unwrap()
        .i64(command.expires_at_us)
        .unwrap();
    encoder.into_writer()
}

fn decode_command(bytes_value: &[u8]) -> Result<CommandFields<'_>, HumanCommitError> {
    let mut decoder = Decoder::new(bytes_value);
    expect_map(&mut decoder, 7)?;
    expect_key(&mut decoder, "v")?;
    if decoder.u64().map_err(invalid)? != 1 {
        return Err(HumanCommitError::InvalidCommand);
    }
    expect_key(&mut decoder, "vault")?;
    let vault = decode_fixed(&mut decoder)?;
    expect_key(&mut decoder, "challenge")?;
    let challenge = decode_fixed(&mut decoder)?;
    expect_key(&mut decoder, "expected_state")?;
    let expected_state = decode_fixed(&mut decoder)?;
    expect_key(&mut decoder, "operation")?;
    let operation = decoder.str().map_err(invalid)?;
    if !matches!(
        operation,
        "item_write"
            | "item_lifecycle"
            | "history_restore"
            | "item_purge"
            | "audit_purge"
            | "identity_change"
            | "availability_change"
            | "import_commit"
            | "plaintext_export"
            | "backup_restore"
            | "root_rotation"
    ) {
        return Err(HumanCommitError::InvalidCommand);
    }
    expect_key(&mut decoder, "body_hash")?;
    let body_hash = decode_fixed(&mut decoder)?;
    expect_key(&mut decoder, "expires_at")?;
    let expires_at_us = decoder.i64().map_err(invalid)?;
    if decoder.position() != bytes_value.len() {
        return Err(HumanCommitError::InvalidCommand);
    }
    let command = CommandFields {
        vault,
        challenge,
        expected_state,
        operation,
        body_hash,
        expires_at_us,
    };
    if encode_command(&command) != bytes_value {
        return Err(HumanCommitError::InvalidCommand);
    }
    Ok(command)
}

fn encode_body(body: &Body) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(5).unwrap();
    encoder
        .str("transaction_id")
        .unwrap()
        .bytes(&body.transaction_id)
        .unwrap();
    encoder
        .str("events_manifest_digest")
        .unwrap()
        .bytes(&body.events_manifest_digest)
        .unwrap();
    encoder
        .str("event_count")
        .unwrap()
        .u64(body.event_count)
        .unwrap();
    encoder.str("object_manifest_digest").unwrap();
    if let Some(value) = body.object_manifest_digest {
        encoder.bytes(&value).unwrap();
    } else {
        encoder.null().unwrap();
    }
    encoder.str("local_effect").unwrap().null().unwrap();
    encoder.into_writer()
}

fn decode_body(bytes_value: &[u8]) -> Result<Body, HumanCommitError> {
    let mut decoder = Decoder::new(bytes_value);
    expect_map(&mut decoder, 5)?;
    expect_key(&mut decoder, "transaction_id")?;
    let transaction_id = decode_fixed(&mut decoder)?;
    expect_key(&mut decoder, "events_manifest_digest")?;
    let events_manifest_digest = decode_fixed(&mut decoder)?;
    expect_key(&mut decoder, "event_count")?;
    let event_count = decoder.u64().map_err(invalid)?;
    if event_count > 1_000_000 {
        return Err(HumanCommitError::InvalidCommand);
    }
    expect_key(&mut decoder, "object_manifest_digest")?;
    let object_manifest_digest = if decoder.datatype().map_err(invalid)? == Type::Null {
        decoder.null().map_err(invalid)?;
        None
    } else {
        Some(decode_fixed(&mut decoder)?)
    };
    expect_key(&mut decoder, "local_effect")?;
    decoder.null().map_err(invalid)?;
    if decoder.position() != bytes_value.len() {
        return Err(HumanCommitError::InvalidCommand);
    }
    let body = Body {
        transaction_id,
        events_manifest_digest,
        event_count,
        object_manifest_digest,
    };
    if encode_body(&body) != bytes_value {
        return Err(HumanCommitError::InvalidCommand);
    }
    Ok(body)
}

fn encode_event_manifest(
    kind: &str,
    item: [u8; 16],
    revision: Option<[u8; 16]>,
    object_digest: Option<[u8; 32]>,
    audit_generation: Option<u64>,
    audit_through_seq: Option<u64>,
    authority_body_digest: Option<[u8; 32]>,
) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.array(1).unwrap().map(7).unwrap();
    encoder.str("kind").unwrap().str(kind).unwrap();
    encoder.str("item").unwrap().bytes(&item).unwrap();
    encoder.str("revision").unwrap();
    encode_optional_bytes(&mut encoder, revision.as_ref().map(<[u8; 16]>::as_slice));
    encoder.str("object_digest").unwrap();
    encode_optional_bytes(
        &mut encoder,
        object_digest.as_ref().map(<[u8; 32]>::as_slice),
    );
    encoder.str("audit_generation").unwrap();
    if let Some(value) = audit_generation {
        encoder.u64(value).unwrap();
    } else {
        encoder.null().unwrap();
    }
    encoder.str("audit_through_seq").unwrap();
    if let Some(value) = audit_through_seq {
        encoder.u64(value).unwrap();
    } else {
        encoder.null().unwrap();
    }
    encoder.str("authority_body_digest").unwrap();
    encode_optional_bytes(
        &mut encoder,
        authority_body_digest.as_ref().map(<[u8; 32]>::as_slice),
    );
    encoder.into_writer()
}

fn encode_restore_manifest(
    item: [u8; 16],
    revision: [u8; 16],
    object_digest: [u8; 32],
    lifecycle_body: &[u8],
) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(2)
        .unwrap()
        .map(4)
        .unwrap()
        .str("kind")
        .unwrap()
        .str("item-revision")
        .unwrap()
        .str("item")
        .unwrap()
        .bytes(&item)
        .unwrap()
        .str("revision")
        .unwrap()
        .bytes(&revision)
        .unwrap()
        .str("object_digest")
        .unwrap()
        .bytes(&object_digest)
        .unwrap()
        .map(3)
        .unwrap()
        .str("kind")
        .unwrap()
        .str("restore")
        .unwrap()
        .str("item")
        .unwrap()
        .bytes(&item)
        .unwrap()
        .str("body_digest")
        .unwrap()
        .bytes(&digest(lifecycle_body))
        .unwrap();
    encoder.into_writer()
}

fn encode_import_manifest(
    batch: [u8; 16],
    source: &str,
    object_digest: [u8; 32],
    report: &CsvImportReport,
) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(11).unwrap();
    encoder
        .str("domain")
        .unwrap()
        .str("pm/import-manifest/v1")
        .unwrap();
    encoder.str("batch").unwrap().bytes(&batch).unwrap();
    encoder.str("source").unwrap().str(source).unwrap();
    encoder
        .str("object_digest")
        .unwrap()
        .bytes(&object_digest)
        .unwrap();
    encoder
        .str("total")
        .unwrap()
        .u64(report.total as u64)
        .unwrap();
    encoder
        .str("new")
        .unwrap()
        .u64(report.new_items as u64)
        .unwrap();
    encoder
        .str("replaced")
        .unwrap()
        .u64(report.replaced as u64)
        .unwrap();
    encoder
        .str("skipped_exact")
        .unwrap()
        .u64(report.skipped_exact as u64)
        .unwrap();
    encoder
        .str("excluded")
        .unwrap()
        .u64(report.excluded as u64)
        .unwrap();
    encoder
        .str("preserved_fields")
        .unwrap()
        .u64(report.preserved_fields as u64)
        .unwrap();
    encoder
        .str("event_pages")
        .unwrap()
        .u64(report.event_pages as u64)
        .unwrap();
    encoder.into_writer()
}

fn encode_import_revision_body(
    revision: [u8; 16],
    modified_at: i64,
    manifest_digest: [u8; 32],
    previous_revisions: &[[u8; 16]],
) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(4).unwrap();
    encoder
        .str("revision_id")
        .unwrap()
        .bytes(&revision)
        .unwrap();
    encoder
        .str("modified_at")
        .unwrap()
        .i64(modified_at)
        .unwrap();
    encoder
        .str("manifest_digest")
        .unwrap()
        .bytes(&manifest_digest)
        .unwrap();
    encoder
        .str("previous_revisions")
        .unwrap()
        .array(previous_revisions.len() as u64)
        .unwrap();
    for prior in previous_revisions {
        encoder.bytes(prior).unwrap();
    }
    encoder.into_writer()
}

fn encode_signed_event(
    event: &[u8],
    device_signature: &[u8; 64],
    human_signature: &[u8; 64],
) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(3).unwrap();
    encoder.str("event").unwrap();
    encoder.writer_mut().extend_from_slice(event);
    encoder
        .str("device_signature")
        .unwrap()
        .bytes(device_signature)
        .unwrap();
    encoder
        .str("human_signature")
        .unwrap()
        .bytes(human_signature)
        .unwrap();
    encoder.into_writer()
}

fn encode_legacy_event_body(
    revision: Option<[u8; 16]>,
    modified_at: i64,
    audit_generation: Option<u64>,
    audit_through_seq: Option<u64>,
    object_manifest_digest: Option<[u8; 32]>,
) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(5).unwrap();
    encoder.str("revision_id").unwrap();
    encode_optional_bytes(&mut encoder, revision.as_ref().map(<[u8; 16]>::as_slice));
    encoder
        .str("modified_at")
        .unwrap()
        .i64(modified_at)
        .unwrap();
    encoder.str("audit_generation").unwrap();
    if let Some(value) = audit_generation {
        encoder.u64(value).unwrap();
    } else {
        encoder.null().unwrap();
    }
    encoder.str("audit_through_seq").unwrap();
    if let Some(value) = audit_through_seq {
        encoder.u64(value).unwrap();
    } else {
        encoder.null().unwrap();
    }
    encoder.str("object_manifest_digest").unwrap();
    encode_optional_bytes(
        &mut encoder,
        object_manifest_digest.as_ref().map(<[u8; 32]>::as_slice),
    );
    encoder.into_writer()
}

fn next_authority_seq(
    connection: &Connection,
    device: [u8; 16],
    generation: u64,
) -> Result<u64, HumanCommitError> {
    let current: i64 = connection.query_row(
        "SELECT coalesce(max(seq),0) FROM authority_events WHERE issuer_device=?1 AND issuer_generation=?2",
        params![device.as_slice(), i64::try_from(generation).map_err(|_| HumanCommitError::InvalidCommand)?],
        |row| row.get(0),
    )?;
    u64::try_from(current)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(HumanCommitError::InvalidCommand)
}

fn authority_digests(
    connection: &Connection,
    subject: [u8; 16],
    kinds: &[&str],
) -> Result<Vec<[u8; 32]>, HumanCommitError> {
    let mut statement = connection.prepare(
        "SELECT event_digest,kind FROM authority_events WHERE subject=?1 ORDER BY event_digest",
    )?;
    let mut rows = statement.query([subject.as_slice()])?;
    let mut digests = Vec::new();
    while let Some(row) = rows.next()? {
        let kind: String = row.get(1)?;
        if kinds.contains(&kind.as_str()) {
            digests.push(bytes(&row.get::<_, Vec<u8>>(0)?)?);
        }
    }
    Ok(digests)
}

fn authority_specific_parents(
    connection: &Connection,
    staged: &Staged,
) -> Result<Vec<[u8; 32]>, HumanCommitError> {
    let kinds: &[&str] = match staged.event_kind.as_str() {
        "agent-grant" => &["agent-grant", "agent-revoke"],
        "resume" => &["suspend"],
        "enable" | "disable" => &[
            "enable",
            "disable",
            "trash",
            "purge-item",
            "purge-revisions",
        ],
        "trash" | "restore" | "purge-item" | "purge-revisions" => &[
            "item-revision",
            "trash",
            "restore",
            "purge-item",
            "purge-revisions",
        ],
        _ => &[],
    };
    authority_digests(connection, staged.item_id, kinds)
}

fn encode_heads_allow_empty(heads: &[[u8; 32]]) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.array(u64::try_from(heads.len()).unwrap()).unwrap();
    for head in heads {
        encoder.bytes(head).unwrap();
    }
    encoder.into_writer()
}

fn state_digest(
    connection: &Connection,
    vault: &[u8; 16],
    epoch: u64,
) -> Result<[u8; 32], HumanCommitError> {
    let head = current_head(connection)?;
    let root_bundle: Vec<u8> = connection.query_row(
        "SELECT value FROM encrypted_objects WHERE kind='human-root-bundle-v1'",
        [],
        |row| row.get(0),
    )?;
    let mut encoder = Encoder::new(Vec::new());
    encoder.array(5).unwrap();
    encoder.str("pm/state-view/v1").unwrap();
    encoder.bytes(vault).unwrap();
    encoder.u64(epoch).unwrap();
    encoder.array(u64::from(head.is_some())).unwrap();
    if let Some(head) = head {
        encoder.bytes(&head).unwrap();
    }
    encoder.bytes(&digest(&root_bundle)).unwrap();
    Ok(digest(&encoder.into_writer()))
}

fn current_head(connection: &Connection) -> Result<Option<[u8; 32]>, HumanCommitError> {
    let value: Option<Vec<u8>> = connection
        .query_row(
            "SELECT event_digest FROM authority_events ORDER BY rowid DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    value.map(|bytes_value| bytes(&bytes_value)).transpose()
}

fn load_challenge(
    connection: &Connection,
    transaction_id: [u8; 16],
) -> Result<Challenge, HumanCommitError> {
    connection
        .query_row(
            "SELECT command,body_hash,expires_at_us,consumed FROM human_challenges
             WHERE transaction_id=?1",
            [transaction_id.as_slice()],
            |row| {
                let hash: Vec<u8> = row.get(1)?;
                Ok(Challenge {
                    command: row.get(0)?,
                    body_hash: hash.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
                    expires_at_us: row.get(2)?,
                    consumed: row.get::<_, i64>(3)? != 0,
                })
            },
        )
        .optional()?
        .ok_or(HumanCommitError::InvalidCommand)
}

fn load_staging(
    connection: &Connection,
    transaction_id: [u8; 16],
) -> Result<Staged, HumanCommitError> {
    connection
        .query_row(
            "SELECT operation,event_kind,item_id,revision_id,body,package,item_kind,attachments,audit_generation,audit_through_seq,subject_generation,authority_body,staged_grant FROM human_staging
             WHERE transaction_id=?1",
            [transaction_id.as_slice()],
            |row| {
                let item: Vec<u8> = row.get(2)?;
                let revision: Option<Vec<u8>> = row.get(3)?;
                Ok(Staged {
                    transaction_id,
                    operation: row.get(0)?,
                    event_kind: row.get(1)?,
                    item_id: item.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
                    revision_id: revision
                        .map(|value| value.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
                        .transpose()?,
                    body: row.get(4)?,
                    package: row.get(5)?,
                    item_kind: row.get(6)?,
                    attachments: row.get(7)?,
                    audit_generation: row
                        .get::<_, Option<i64>>(8)?
                        .map(u64::try_from)
                        .transpose()
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    audit_through_seq: row
                        .get::<_, Option<i64>>(9)?
                        .map(u64::try_from)
                        .transpose()
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    subject_generation: row
                        .get::<_, Option<i64>>(10)?
                        .map(u64::try_from)
                        .transpose()
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    authority_body: row.get(11)?,
                    staged_grant: row.get(12)?,
                })
            },
        )
        .optional()?
        .ok_or(HumanCommitError::InvalidCommand)
}

fn load_receipt(
    connection: &Connection,
    transaction_id: [u8; 16],
) -> Result<Option<HumanReceipt>, HumanCommitError> {
    Ok(connection
        .query_row(
            "SELECT body_hash,committed_heads,committed_at_us FROM human_receipts
             WHERE transaction_id=?1",
            [transaction_id.as_slice()],
            |row| {
                let body_hash: Vec<u8> = row.get(0)?;
                let committed_heads: Vec<u8> = row.get(1)?;
                Ok(HumanReceipt {
                    transaction_id,
                    body_hash: body_hash
                        .try_into()
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    committed_heads: decode_heads(&committed_heads)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    committed_at_us: row.get(2)?,
                })
            },
        )
        .optional()?)
}

fn random_challenge() -> Result<[u8; 32], HumanCommitError> {
    let first = random_id()?;
    let second = random_id()?;
    let mut challenge = [0_u8; 32];
    challenge[..16].copy_from_slice(&first);
    challenge[16..].copy_from_slice(&second);
    Ok(challenge)
}

fn encode_heads(heads: &[[u8; 32]]) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(u64::try_from(heads.len()).expect("bounded committed heads"))
        .unwrap();
    for head in heads {
        encoder.bytes(head).unwrap();
    }
    encoder.into_writer()
}

fn decode_heads(value: &[u8]) -> Result<Vec<[u8; 32]>, HumanCommitError> {
    let mut decoder = Decoder::new(value);
    let count = decoder
        .array()
        .map_err(invalid)?
        .ok_or(HumanCommitError::InvalidCommand)?;
    if count > 4096 {
        return Err(HumanCommitError::InvalidCommand);
    }
    let mut heads =
        Vec::with_capacity(usize::try_from(count).map_err(|_| HumanCommitError::InvalidCommand)?);
    for _ in 0..count {
        heads.push(decode_fixed(&mut decoder)?);
    }
    if decoder.position() != value.len() || encode_heads(&heads) != value {
        return Err(HumanCommitError::InvalidCommand);
    }
    Ok(heads)
}

fn now_us() -> Result<i64, HumanCommitError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HumanCommitError::InvalidCommand)?;
    i64::try_from(duration.as_micros()).map_err(|_| HumanCommitError::InvalidCommand)
}

fn encode_optional_bytes(encoder: &mut Encoder<Vec<u8>>, value: Option<&[u8]>) {
    if let Some(value) = value {
        encoder.bytes(value).unwrap();
    } else {
        encoder.null().unwrap();
    }
}

fn expect_map(decoder: &mut Decoder<'_>, fields: u64) -> Result<(), HumanCommitError> {
    if decoder.map().map_err(invalid)? != Some(fields) {
        return Err(HumanCommitError::InvalidCommand);
    }
    Ok(())
}

fn expect_key(decoder: &mut Decoder<'_>, key: &str) -> Result<(), HumanCommitError> {
    if decoder.str().map_err(invalid)? != key {
        return Err(HumanCommitError::InvalidCommand);
    }
    Ok(())
}

fn decode_fixed<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], HumanCommitError> {
    decoder
        .bytes()
        .map_err(invalid)?
        .try_into()
        .map_err(|_| HumanCommitError::InvalidCommand)
}

fn bytes<const N: usize>(value: &[u8]) -> Result<[u8; N], HumanCommitError> {
    value
        .try_into()
        .map_err(|_| HumanCommitError::InvalidCommand)
}

fn invalid<T>(_: T) -> HumanCommitError {
    HumanCommitError::InvalidCommand
}
