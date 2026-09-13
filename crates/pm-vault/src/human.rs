// SPDX-License-Identifier: AGPL-3.0-only

//! Human-only password mutations through a signed, replay-safe transaction.

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use minicbor::{Decoder, Encoder, data::Type};
use pm_crypto::{
    CryptoError, ItemKind, RevisionPackageInput, TrustedRoot, UnlockedRoot, digest, random_id,
    verify_human_command,
};
pub use pm_native_channel::AuthenticatedHumanChannel as HumanChannel;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use zeroize::Zeroize;

use crate::audit::{
    self, AuditAction, AuditActorKind, AuditDeviceCustody, AuditEvent, AuditOutcome,
    AuditPurgeScope, AuditQuery, PreparedAuditPurge,
};
use crate::{VaultError, unlock_root};

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
    ItemNotFound,
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
            Self::Integrity => "audit integrity verification failed",
            Self::AuditKeyUnavailable => "device audit custody is unavailable",
            Self::InvalidSignature => "invalid human signature",
            Self::ItemNotFound => "password item not found",
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
    audit_custody: Arc<AuditDeviceCustody>,
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
            Some(generation),
            Some(through_seq),
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
                    AuditAction::ItemChange,
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
        self.channel.verify()?;
        let connection = open_connection(&self.path)?;
        let package: Vec<u8> = connection
            .query_row(
                "SELECT r.package FROM vault_items i
                 JOIN revision_parts r ON r.revision_id=i.visible_revision
                 WHERE i.item_id=?1 AND i.status='active'",
                [item.as_slice()],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(HumanCommitError::ItemNotFound)?;
        let opened = self.root.open_revision_package(&package)?;
        if opened.item() != &item {
            return Err(HumanCommitError::InvalidCommand);
        }
        decode_password(opened.human_plaintext(), opened.auth_plaintext())
    }

    fn prepare_write(
        &mut self,
        item: [u8; 16],
        record: &PasswordRecord,
    ) -> Result<PreparedHumanCommand, HumanCommitError> {
        let revision = random_id()?;
        let (human, auth) = encode_password(record);
        let package = self.root.seal_revision_package(RevisionPackageInput {
            item,
            revision,
            issuer_device: self.device,
            modified_at: now_us()?,
            kind: ItemKind::Password,
            human_plaintext: &human,
            auth_plaintext: Some(&auth),
        })?;
        let package = package.to_bytes();
        self.prepare(
            "item_write",
            "item-revision",
            item,
            Some(revision),
            Some(&package),
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
        audit_generation: Option<u64>,
        audit_through_seq: Option<u64>,
    ) -> Result<PreparedHumanCommand, HumanCommitError> {
        self.channel.verify()?;
        let transaction_id = random_id()?;
        let challenge = random_challenge()?;
        let connection = open_connection(&self.path)?;
        let expected_state = state_digest(&connection, self.root.vault_id(), 1)?;
        let object_digest = package.map(digest);
        let event_manifest = encode_event_manifest(
            event_kind,
            item,
            revision,
            object_digest,
            audit_generation,
            audit_through_seq,
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
             (transaction_id,operation,event_kind,item_id,revision_id,body,package,audit_generation,audit_through_seq)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                transaction_id.as_slice(),
                operation,
                event_kind,
                item.as_slice(),
                revision.as_ref().map(<[u8; 16]>::as_slice),
                body,
                package,
                audit_generation.map(i64::try_from).transpose().map_err(|_| HumanCommitError::InvalidInput)?,
                audit_through_seq.map(i64::try_from).transpose().map_err(|_| HumanCommitError::InvalidInput)?,
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
    audit_generation: Option<u64>,
    audit_through_seq: Option<u64>,
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
            transaction.execute(
                "INSERT INTO revision_parts (revision_id,item_id,package) VALUES (?1,?2,?3)",
                params![revision.as_slice(), staged.item_id.as_slice(), package],
            )?;
            transaction.execute(
                "INSERT INTO vault_items (item_id,visible_revision,status)
                 VALUES (?1,?2,'active')
                 ON CONFLICT(item_id) DO UPDATE SET visible_revision=excluded.visible_revision",
                params![staged.item_id.as_slice(), revision.as_slice()],
            )?;
        }
        "trash" => {
            transaction.execute(
                "UPDATE vault_items SET status='trash' WHERE item_id=?1 AND status='active'",
                [staged.item_id.as_slice()],
            )?;
        }
        "audit-purge" => {}
        _ => unreachable!("validated staging event kind"),
    }
    Ok(())
}

fn validate_staged(staged: &Staged, body: &Body) -> Result<(), HumanCommitError> {
    let object_digest = staged.package.as_deref().map(digest);
    let valid_shape = match staged.event_kind.as_str() {
        "item-revision" => {
            staged.operation == "item_write"
                && staged.revision_id.is_some()
                && staged.package.is_some()
        }
        "trash" => {
            staged.operation == "item_lifecycle"
                && staged.revision_id.is_none()
                && staged.package.is_none()
        }
        "audit-purge" => {
            staged.operation == "audit_purge"
                && staged.revision_id.is_none()
                && staged.package.is_none()
                && staged.audit_generation.is_some()
                && staged.audit_through_seq.is_some()
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

fn encode_password(record: &PasswordRecord) -> (Vec<u8>, Vec<u8>) {
    let mut human = Encoder::new(Vec::new());
    human.map(8).unwrap();
    human.str("title").unwrap().str(&record.title).unwrap();
    human.str("destinations").unwrap().array(1).unwrap();
    human.map(2).unwrap();
    human.str("label").unwrap().str("").unwrap();
    human
        .str("value")
        .unwrap()
        .str(&record.destination)
        .unwrap();
    human.str("tags").unwrap().array(0).unwrap();
    human.str("favorite").unwrap().bool(false).unwrap();
    human.str("notes").unwrap().str(&record.notes).unwrap();
    human.str("fields").unwrap().array(0).unwrap();
    human.str("attachment_ids").unwrap().array(0).unwrap();
    human.str("source_fields").unwrap().array(0).unwrap();

    let mut auth = Encoder::new(Vec::new());
    auth.array(1).unwrap().map(4).unwrap();
    auth.str("method").unwrap().str("password").unwrap();
    auth.str("username").unwrap().str(&record.username).unwrap();
    auth.str("password")
        .unwrap()
        .bytes(&record.password)
        .unwrap();
    auth.str("destination_refs")
        .unwrap()
        .array(1)
        .unwrap()
        .u64(0)
        .unwrap();
    (human.into_writer(), auth.into_writer())
}

fn decode_password(
    human_bytes: &[u8],
    auth_bytes: Option<&[u8]>,
) -> Result<PasswordRecord, HumanCommitError> {
    let mut human = Decoder::new(human_bytes);
    expect_map(&mut human, 8)?;
    expect_key(&mut human, "title")?;
    let title = human.str().map_err(invalid)?.to_owned();
    expect_key(&mut human, "destinations")?;
    expect_array(&mut human, 1)?;
    expect_map(&mut human, 2)?;
    expect_key(&mut human, "label")?;
    if !human.str().map_err(invalid)?.is_empty() {
        return Err(HumanCommitError::InvalidCommand);
    }
    expect_key(&mut human, "value")?;
    let destination = human.str().map_err(invalid)?.to_owned();
    expect_key(&mut human, "tags")?;
    expect_array(&mut human, 0)?;
    expect_key(&mut human, "favorite")?;
    if human.bool().map_err(invalid)? {
        return Err(HumanCommitError::InvalidCommand);
    }
    expect_key(&mut human, "notes")?;
    let notes = human.str().map_err(invalid)?.to_owned();
    for key in ["fields", "attachment_ids", "source_fields"] {
        expect_key(&mut human, key)?;
        expect_array(&mut human, 0)?;
    }
    if human.position() != human_bytes.len() {
        return Err(HumanCommitError::InvalidCommand);
    }

    let auth_bytes = auth_bytes.ok_or(HumanCommitError::InvalidCommand)?;
    let mut auth = Decoder::new(auth_bytes);
    expect_array(&mut auth, 1)?;
    expect_map(&mut auth, 4)?;
    expect_key(&mut auth, "method")?;
    if auth.str().map_err(invalid)? != "password" {
        return Err(HumanCommitError::InvalidCommand);
    }
    expect_key(&mut auth, "username")?;
    let username = auth.str().map_err(invalid)?.to_owned();
    expect_key(&mut auth, "password")?;
    let password = auth.bytes().map_err(invalid)?.to_vec();
    expect_key(&mut auth, "destination_refs")?;
    expect_array(&mut auth, 1)?;
    if auth.u64().map_err(invalid)? != 0 || auth.position() != auth_bytes.len() {
        return Err(HumanCommitError::InvalidCommand);
    }
    let decoded = PasswordRecord::new(&title, &username, &password, &destination, &notes);
    let mut password = password;
    password.zeroize();
    decoded
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
    if !matches!(operation, "item_write" | "item_lifecycle" | "audit_purge") {
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
    audit_generation: Option<u64>,
    audit_through_seq: Option<u64>,
) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.array(1).unwrap().map(6).unwrap();
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
            "SELECT operation,event_kind,item_id,revision_id,body,package,audit_generation,audit_through_seq FROM human_staging
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
                    audit_generation: row
                        .get::<_, Option<i64>>(6)?
                        .map(u64::try_from)
                        .transpose()
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    audit_through_seq: row
                        .get::<_, Option<i64>>(7)?
                        .map(u64::try_from)
                        .transpose()
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
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

fn expect_array(decoder: &mut Decoder<'_>, fields: u64) -> Result<(), HumanCommitError> {
    if decoder.array().map_err(invalid)? != Some(fields) {
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
