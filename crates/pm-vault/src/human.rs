// SPDX-License-Identifier: AGPL-3.0-only

//! Human-only password mutations through a signed, replay-safe transaction.

use std::{
    fmt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use minicbor::{Decoder, Encoder, data::Type};
use pm_crypto::{
    CryptoError, RevisionPackageInput, TrustedRoot, UnlockedRoot, digest, fill_random, random_id,
    verify_human_command,
};
pub use pm_native_channel::AuthenticatedHumanChannel as HumanChannel;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use zeroize::Zeroize;

use crate::{
    AuthRecord, Destination, GeneratedPassword, GeneratorConfig, HumanMetadata, LogicalRecord,
    PasswordRng, RecordKind, SearchHit, SearchQuery, VaultError, content, unlock_root,
};

const CHALLENGE_LIFETIME_US: i64 = 60_000_000;
const AUDIT_GENERATION: i64 = 1;
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
    InvalidSignature,
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
            Self::InvalidInput => "invalid password record",
            Self::InvalidSignature => "invalid human signature",
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
}

impl HumanVault {
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
        self.prepare("item_lifecycle", "trash", item, None, None, None, None)
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
        validate_staged(&staged, &body)?;
        let committed_at_us = now_us()?;
        let event_id = random_id()?;
        let previous = current_head(&transaction)?;
        let event = encode_event(&EventInput {
            vault: self.root.vault_id(),
            event_id,
            device: self.device,
            kind: &staged.event_kind,
            item: staged.item_id,
            revision: staged.revision_id,
            previous,
            modified_at: committed_at_us,
        });
        let event_signature = self.root.sign_human_event(&event)?;
        let event_digest = digest(&event);
        let signed_event = encode_signed_event(&event, &event_signature);

        apply_staged(&transaction, &staged)?;
        transaction.execute(
            "INSERT INTO authority_events
             (event_digest,event_id,transaction_id,event,human_signature)
             VALUES (?1,?2,?3,?4,?5)",
            params![
                event_digest.as_slice(),
                event_id.as_slice(),
                body.transaction_id.as_slice(),
                event,
                event_signature.as_slice(),
            ],
        )?;
        transaction.execute(
            "INSERT INTO outbox (event_digest,event) VALUES (?1,?2)",
            params![event_digest.as_slice(), signed_event],
        )?;
        persist_audit(
            &transaction,
            &self.root,
            &AuditInput {
                device: self.device,
                event_id,
                item: staged.item_id,
                revision: staged.revision_id,
                frontier: event_digest,
                wall_time_us: committed_at_us,
            },
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

    /// Reads, authenticates and reconstructs one complete logical record.
    ///
    /// Passkey material returned here is preserved content only; this method is
    /// not a `WebAuthn` authenticator and cannot perform a login.
    ///
    /// # Errors
    /// Returns an error for an absent item, altered revision, or altered file.
    pub fn read_record(&self, item: [u8; 16]) -> Result<LogicalRecord, HumanCommitError> {
        self.channel.verify()?;
        let connection = open_connection(&self.path)?;
        let (revision_bytes, expected_kind, package): (Vec<u8>, String, Vec<u8>) = connection
            .query_row(
                "SELECT i.visible_revision,i.kind,r.package FROM vault_items i
                 JOIN revision_parts r ON r.revision_id=i.visible_revision
                 WHERE i.item_id=?1 AND i.status='active'",
                [item.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or(HumanCommitError::ItemNotFound)?;
        let revision = bytes::<16>(&revision_bytes)?;
        let opened = self.root.open_revision_package(&package)?;
        let mut record =
            LogicalRecord::decode_parts(opened.human_plaintext(), opened.auth_plaintext())?;
        if opened.item() != &item
            || opened.revision() != &revision
            || record.kind().name() != expected_kind
            || record.kind().crypto() != opened.kind()
        {
            return Err(HumanCommitError::InvalidCommand);
        }
        let ids: Vec<[u8; 16]> = record
            .attachments()
            .iter()
            .map(|value| *value.id())
            .collect();
        for id in ids {
            let file: Vec<u8> = connection
                .query_row(
                    "SELECT package FROM attachment_parts WHERE attachment_id=?1 AND revision_id=?2",
                    params![id.as_slice(), revision.as_slice()],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or(HumanCommitError::InvalidCommand)?;
            let content = self.root.open_file(id, revision, &file)?;
            record.restore_attachment(id, content)?;
        }
        let attachment_count: i64 = connection.query_row(
            "SELECT count(*) FROM attachment_parts WHERE revision_id=?1",
            [revision.as_slice()],
            |row| row.get(0),
        )?;
        if usize::try_from(attachment_count).ok() != Some(record.attachments().len()) {
            return Err(HumanCommitError::InvalidCommand);
        }
        record.validate_complete()?;
        Ok(record)
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
        let attachments = encode_staged_attachments(&attachments);
        self.prepare(
            "item_write",
            "item-revision",
            item,
            Some(revision),
            Some(&package),
            Some(record.kind().name()),
            Some(&attachments),
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
    ) -> Result<PreparedHumanCommand, HumanCommitError> {
        self.channel.verify()?;
        let transaction_id = random_id()?;
        let challenge = random_challenge()?;
        let connection = open_connection(&self.path)?;
        let expected_state = state_digest(&connection, self.root.vault_id(), 1)?;
        let object_digest = staged_object_digest(package, attachments);
        let event_manifest = encode_event_manifest(event_kind, item, revision, object_digest);
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
             (transaction_id,operation,event_kind,item_id,revision_id,body,package,item_kind,attachments)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
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

struct Staged {
    operation: String,
    event_kind: String,
    item_id: [u8; 16],
    revision_id: Option<[u8; 16]>,
    body: Vec<u8>,
    package: Option<Vec<u8>>,
    item_kind: Option<String>,
    attachments: Option<Vec<u8>>,
}

struct EventInput<'a> {
    vault: &'a [u8; 16],
    event_id: [u8; 16],
    device: [u8; 16],
    kind: &'a str,
    item: [u8; 16],
    revision: Option<[u8; 16]>,
    previous: Option<[u8; 32]>,
    modified_at: i64,
}

struct AuditInput {
    device: [u8; 16],
    event_id: [u8; 16],
    item: [u8; 16],
    revision: Option<[u8; 16]>,
    frontier: [u8; 32],
    wall_time_us: i64,
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

fn apply_staged(transaction: &Transaction<'_>, staged: &Staged) -> rusqlite::Result<()> {
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
            for (attachment, attachment_package) in decode_staged_attachments(
                staged
                    .attachments
                    .as_ref()
                    .expect("validated staged attachments"),
            )
            .map_err(|_| rusqlite::Error::InvalidQuery)?
            {
                transaction.execute(
                    "INSERT INTO attachment_parts (attachment_id,revision_id,package) VALUES (?1,?2,?3)",
                    params![attachment.as_slice(), revision.as_slice(), attachment_package],
                )?;
            }
        }
        "trash" => {
            transaction.execute(
                "UPDATE vault_items SET status='trash' WHERE item_id=?1 AND status='active'",
                [staged.item_id.as_slice()],
            )?;
        }
        _ => unreachable!("validated staging event kind"),
    }
    Ok(())
}

fn validate_staged(staged: &Staged, body: &Body) -> Result<(), HumanCommitError> {
    let object_digest =
        staged_object_digest(staged.package.as_deref(), staged.attachments.as_deref());
    let valid_shape = match staged.event_kind.as_str() {
        "item-revision" => {
            staged.operation == "item_write"
                && staged.revision_id.is_some()
                && staged.package.is_some()
                && staged.item_kind.is_some()
                && staged
                    .attachments
                    .as_deref()
                    .is_some_and(|value| decode_staged_attachments(value).is_ok())
        }
        "trash" => {
            staged.operation == "item_lifecycle"
                && staged.revision_id.is_none()
                && staged.package.is_none()
                && staged.item_kind.is_none()
                && staged.attachments.is_none()
        }
        _ => false,
    };
    let event_manifest = encode_event_manifest(
        &staged.event_kind,
        staged.item_id,
        staged.revision_id,
        object_digest,
    );
    if !valid_shape
        || body.event_count != 1
        || body.object_manifest_digest != object_digest
        || body.events_manifest_digest != digest(&event_manifest)
    {
        return Err(HumanCommitError::BodyChanged);
    }
    Ok(())
}

fn persist_audit(
    transaction: &Transaction<'_>,
    root: &UnlockedRoot,
    input: &AuditInput,
) -> Result<(), HumanCommitError> {
    let state: Option<(i64, i64, Vec<u8>)> = transaction
        .query_row(
            "SELECT generation,seq,last_hash FROM audit_state WHERE device_id=?1",
            [input.device.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let (generation, seq, previous_hash) = match state {
        Some((generation, seq, hash)) => (
            generation,
            seq.checked_add(1).ok_or(HumanCommitError::InvalidCommand)?,
            bytes::<32>(&hash)?,
        ),
        None => (AUDIT_GENERATION, 1, [0_u8; 32]),
    };
    let key_envelope: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT envelope FROM audit_keys WHERE device_id=?1 AND generation=?2",
            params![input.device.as_slice(), generation],
            |row| row.get(0),
        )
        .optional()?;
    let audit_plaintext = encode_audit(
        root.vault_id(),
        input.device,
        u64::try_from(generation).map_err(|_| HumanCommitError::InvalidCommand)?,
        u64::try_from(seq).map_err(|_| HumanCommitError::InvalidCommand)?,
        input.event_id,
        input.wall_time_us,
        input.item,
        input.revision,
        input.frontier,
        previous_hash,
    );
    let sealed = root.seal_audit_record(
        key_envelope.as_deref(),
        input.device,
        u64::try_from(generation).map_err(|_| HumanCommitError::InvalidCommand)?,
        input.event_id,
        random_id()?,
        &audit_plaintext,
    )?;
    if let Some(envelope) = sealed.key_envelope() {
        transaction.execute(
            "INSERT INTO audit_keys (device_id,generation,envelope) VALUES (?1,?2,?3)",
            params![input.device.as_slice(), generation, envelope],
        )?;
    }
    transaction.execute(
        "INSERT INTO encrypted_audit_records (device_id,generation,seq,event_id,record)
         VALUES (?1,?2,?3,?4,?5)",
        params![
            input.device.as_slice(),
            generation,
            seq,
            input.event_id.as_slice(),
            sealed.record()
        ],
    )?;
    let record_hash = digest(sealed.record());
    transaction.execute(
        "INSERT INTO audit_state (device_id,generation,seq,last_hash) VALUES (?1,?2,?3,?4)
         ON CONFLICT(device_id) DO UPDATE SET
           generation=excluded.generation,seq=excluded.seq,last_hash=excluded.last_hash",
        params![
            input.device.as_slice(),
            generation,
            seq,
            record_hash.as_slice()
        ],
    )?;
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
    if !matches!(operation, "item_write" | "item_lifecycle") {
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
    if event_count != 1 {
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
) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.array(1).unwrap().map(4).unwrap();
    encoder.str("kind").unwrap().str(kind).unwrap();
    encoder.str("item").unwrap().bytes(&item).unwrap();
    encoder.str("revision").unwrap();
    encode_optional_bytes(&mut encoder, revision.as_ref().map(<[u8; 16]>::as_slice));
    encoder.str("object_digest").unwrap();
    encode_optional_bytes(
        &mut encoder,
        object_digest.as_ref().map(<[u8; 32]>::as_slice),
    );
    encoder.into_writer()
}

fn encode_event(input: &EventInput<'_>) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(10).unwrap();
    encoder.str("v").unwrap().u64(1).unwrap();
    encoder.str("vault").unwrap().bytes(input.vault).unwrap();
    encoder
        .str("event_id")
        .unwrap()
        .bytes(&input.event_id)
        .unwrap();
    encoder.str("authority_epoch").unwrap().u64(1).unwrap();
    encoder
        .str("issuer_device")
        .unwrap()
        .bytes(&input.device)
        .unwrap();
    encoder.str("kind").unwrap().str(input.kind).unwrap();
    encoder.str("subject").unwrap().bytes(&input.item).unwrap();
    encoder.str("revision_id").unwrap();
    encode_optional_bytes(
        &mut encoder,
        input.revision.as_ref().map(<[u8; 16]>::as_slice),
    );
    encoder
        .str("modified_at")
        .unwrap()
        .i64(input.modified_at)
        .unwrap();
    encoder.str("prev").unwrap();
    encode_optional_bytes(
        &mut encoder,
        input.previous.as_ref().map(<[u8; 32]>::as_slice),
    );
    encoder.into_writer()
}

fn encode_signed_event(event: &[u8], human_signature: &[u8; 64]) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(3).unwrap();
    encoder.str("event").unwrap();
    encoder.writer_mut().extend_from_slice(event);
    encoder.str("device_signature").unwrap().null().unwrap();
    encoder
        .str("human_signature")
        .unwrap()
        .bytes(human_signature)
        .unwrap();
    encoder.into_writer()
}

#[allow(clippy::too_many_arguments)]
fn encode_audit(
    vault: &[u8; 16],
    device: [u8; 16],
    generation: u64,
    seq: u64,
    event_id: [u8; 16],
    wall_time_us: i64,
    item: [u8; 16],
    revision: Option<[u8; 16]>,
    frontier: [u8; 32],
    previous_hash: [u8; 32],
) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(19).unwrap();
    encoder.str("v").unwrap().u64(1).unwrap();
    encoder.str("vault").unwrap().bytes(vault).unwrap();
    encoder.str("device").unwrap().bytes(&device).unwrap();
    encoder
        .str("audit_generation")
        .unwrap()
        .u64(generation)
        .unwrap();
    encoder.str("seq").unwrap().u64(seq).unwrap();
    encoder.str("event_id").unwrap().bytes(&event_id).unwrap();
    encoder
        .str("wall_time_us")
        .unwrap()
        .i64(wall_time_us)
        .unwrap();
    encoder.str("monotonic_us").unwrap().u64(0).unwrap();
    encoder.str("boot_id").unwrap().null().unwrap();
    encoder.str("actor_kind").unwrap().str("human").unwrap();
    encoder.str("actor_id").unwrap().null().unwrap();
    encoder.str("action").unwrap().str("item_change").unwrap();
    encoder.str("outcome").unwrap().str("succeeded").unwrap();
    encoder.str("reason").unwrap().null().unwrap();
    encoder.str("item_id").unwrap().bytes(&item).unwrap();
    encoder.str("revision_id").unwrap();
    encode_optional_bytes(&mut encoder, revision.as_ref().map(<[u8; 16]>::as_slice));
    encoder.str("attempt_id").unwrap().null().unwrap();
    encoder
        .str("authority_frontier_hash")
        .unwrap()
        .bytes(&frontier)
        .unwrap();
    encoder
        .str("previous_record_hash")
        .unwrap()
        .bytes(&previous_hash)
        .unwrap();
    encoder.into_writer()
}

fn state_digest(
    connection: &Connection,
    vault: &[u8; 16],
    epoch: u64,
) -> Result<[u8; 32], HumanCommitError> {
    let head = current_head(connection)?;
    let mut encoder = Encoder::new(Vec::new());
    encoder.array(4).unwrap();
    encoder.str("pm/state-view/v1").unwrap();
    encoder.bytes(vault).unwrap();
    encoder.u64(epoch).unwrap();
    encoder.array(u64::from(head.is_some())).unwrap();
    if let Some(head) = head {
        encoder.bytes(&head).unwrap();
    }
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
            "SELECT operation,event_kind,item_id,revision_id,body,package,item_kind,attachments FROM human_staging
             WHERE transaction_id=?1",
            [transaction_id.as_slice()],
            |row| {
                let item: Vec<u8> = row.get(2)?;
                let revision: Option<Vec<u8>> = row.get(3)?;
                Ok(Staged {
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
    if count == 0 || count > 4096 {
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
