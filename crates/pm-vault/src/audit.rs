// SPDX-License-Identifier: AGPL-3.0-only

//! Device-custodied, signed and encrypted local audit history.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use minicbor::{Decoder, Encoder, data::Type};
use pm_crypto::{
    AuditDeviceKeyPair, AuditKey, AuditKeyPackage, TrustedRoot, UnlockedRoot, digest, random_id,
    verify_audit_signature,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::PreparedHumanCommand;
use crate::human::HumanCommitError;
use crate::load_and_validate_bundle;

const MAX_SEGMENT_BYTES: i64 = 1024 * 1024;
const MAX_SEGMENT_RECORDS: i64 = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditActorKind {
    Human,
    Agent,
    Custodian,
    System,
}

impl AuditActorKind {
    fn name(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Agent => "agent",
            Self::Custodian => "custodian",
            Self::System => "system",
        }
    }
    fn parse(value: &str) -> Result<Self, HumanCommitError> {
        match value {
            "human" => Ok(Self::Human),
            "agent" => Ok(Self::Agent),
            "custodian" => Ok(Self::Custodian),
            "system" => Ok(Self::System),
            _ => Err(HumanCommitError::InvalidCommand),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditAction {
    HumanUnlock,
    HumanLock,
    Reveal,
    Copy,
    ItemChange,
    AuthorityChange,
    AuthAccepted,
    AuthState,
    AuthUse,
    Import,
    Export,
    Backup,
    Restore,
    AuditPurge,
    ProfileFault,
    Startup,
    Shutdown,
    Recovery,
}

impl AuditAction {
    fn name(self) -> &'static str {
        match self {
            Self::HumanUnlock => "human_unlock",
            Self::HumanLock => "human_lock",
            Self::Reveal => "reveal",
            Self::Copy => "copy",
            Self::ItemChange => "item_change",
            Self::AuthorityChange => "authority_change",
            Self::AuthAccepted => "auth_accepted",
            Self::AuthState => "auth_state",
            Self::AuthUse => "auth_use",
            Self::Import => "import",
            Self::Export => "export",
            Self::Backup => "backup",
            Self::Restore => "restore",
            Self::AuditPurge => "audit_purge",
            Self::ProfileFault => "profile_fault",
            Self::Startup => "startup",
            Self::Shutdown => "shutdown",
            Self::Recovery => "recovery",
        }
    }
    fn parse(value: &str) -> Result<Self, HumanCommitError> {
        match value {
            "human_unlock" => Ok(Self::HumanUnlock),
            "human_lock" => Ok(Self::HumanLock),
            "reveal" => Ok(Self::Reveal),
            "copy" => Ok(Self::Copy),
            "item_change" => Ok(Self::ItemChange),
            "authority_change" => Ok(Self::AuthorityChange),
            "auth_accepted" => Ok(Self::AuthAccepted),
            "auth_state" => Ok(Self::AuthState),
            "auth_use" => Ok(Self::AuthUse),
            "import" => Ok(Self::Import),
            "export" => Ok(Self::Export),
            "backup" => Ok(Self::Backup),
            "restore" => Ok(Self::Restore),
            "audit_purge" => Ok(Self::AuditPurge),
            "profile_fault" => Ok(Self::ProfileFault),
            "startup" => Ok(Self::Startup),
            "shutdown" => Ok(Self::Shutdown),
            "recovery" => Ok(Self::Recovery),
            _ => Err(HumanCommitError::InvalidCommand),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditOutcome {
    Accepted,
    Succeeded,
    Denied,
    Failed,
    Indeterminate,
}

impl AuditOutcome {
    fn name(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Succeeded => "succeeded",
            Self::Denied => "denied",
            Self::Failed => "failed",
            Self::Indeterminate => "indeterminate",
        }
    }
    fn parse(value: &str) -> Result<Self, HumanCommitError> {
        match value {
            "accepted" => Ok(Self::Accepted),
            "succeeded" => Ok(Self::Succeeded),
            "denied" => Ok(Self::Denied),
            "failed" => Ok(Self::Failed),
            "indeterminate" => Ok(Self::Indeterminate),
            _ => Err(HumanCommitError::InvalidCommand),
        }
    }
}

/// Closed audit input: identifiers and enums only, never a free-form payload.
pub struct AuditEvent {
    actor_kind: AuditActorKind,
    actor_id: Option<[u8; 16]>,
    action: AuditAction,
    outcome: AuditOutcome,
    item_id: Option<[u8; 16]>,
    revision_id: Option<[u8; 16]>,
    attempt_id: Option<[u8; 16]>,
}

impl AuditEvent {
    #[must_use]
    pub const fn new(
        actor_kind: AuditActorKind,
        actor_id: Option<[u8; 16]>,
        action: AuditAction,
        outcome: AuditOutcome,
    ) -> Self {
        Self {
            actor_kind,
            actor_id,
            action,
            outcome,
            item_id: None,
            revision_id: None,
            attempt_id: None,
        }
    }
    #[must_use]
    pub const fn with_item(mut self, item_id: [u8; 16], revision_id: Option<[u8; 16]>) -> Self {
        self.item_id = Some(item_id);
        self.revision_id = revision_id;
        self
    }
    #[must_use]
    pub const fn with_attempt(mut self, attempt_id: [u8; 16]) -> Self {
        self.attempt_id = Some(attempt_id);
        self
    }
}

pub struct AuditDeviceCustody {
    keys: AuditDeviceKeyPair,
}

impl AuditDeviceCustody {
    /// Generates independent device envelope and audit signing keys.
    ///
    /// # Errors
    ///
    /// Returns an error when native randomness or key generation is unavailable.
    pub fn generate() -> Result<Self, HumanCommitError> {
        Ok(Self {
            keys: AuditDeviceKeyPair::generate()?,
        })
    }

    /// Returns an opaque private bundle for a caller-enforced custodial file.
    #[must_use]
    pub fn to_protected_bytes(&self) -> Vec<u8> {
        self.keys.to_protected_bytes()
    }

    /// Loads a bundle only after the caller validated native owner/mode/path.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or internally inconsistent private material.
    pub fn from_protected_bytes(bytes: &[u8]) -> Result<Self, HumanCommitError> {
        Ok(Self {
            keys: AuditDeviceKeyPair::from_protected_bytes(bytes)?,
        })
    }

    #[must_use]
    pub(crate) const fn encryption_public_key(&self) -> &[u8; 32] {
        self.keys.encryption_public_key()
    }

    pub(crate) fn sign_device_event(&self, event: &[u8]) -> Result<[u8; 64], HumanCommitError> {
        Ok(self.keys.sign_device_event(event)?)
    }

    pub(crate) fn seal_attempt_state(
        &self,
        vault: [u8; 16],
        device: [u8; 16],
        generation: u64,
        attempt: [u8; 16],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, HumanCommitError> {
        Ok(self
            .keys
            .seal_attempt_state(vault, device, generation, attempt, plaintext)?)
    }

    pub(crate) fn update_attempt_state(
        &self,
        package: &[u8],
        vault: [u8; 16],
        device: [u8; 16],
        generation: u64,
        attempt: [u8; 16],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, HumanCommitError> {
        Ok(self
            .keys
            .update_attempt_state(package, vault, device, generation, attempt, plaintext)?)
    }

    pub(crate) fn open_attempt_state(
        &self,
        package: &[u8],
        vault: [u8; 16],
        device: [u8; 16],
        generation: u64,
        attempt: [u8; 16],
    ) -> Result<Vec<u8>, HumanCommitError> {
        Ok(self
            .keys
            .open_attempt_state(package, vault, device, generation, attempt)?)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open_control_package(
        &self,
        bytes: &[u8],
        vault: [u8; 16],
        device: [u8; 16],
        generation: u64,
        object: [u8; 16],
        revision: [u8; 16],
    ) -> Result<Vec<u8>, HumanCommitError> {
        Ok(self
            .keys
            .open_control_package(bytes, vault, device, generation, object, revision)?)
    }

    pub(crate) fn verify_grant_vector(
        &self,
        bytes: &[u8],
        trusted: &TrustedRoot,
        recipient: [u8; 16],
        authority_event: [u8; 32],
        commitment: [u8; 32],
    ) -> Result<[u8; 32], HumanCommitError> {
        Ok(self
            .keys
            .verify_grant_vector(bytes, trusted, recipient, authority_event, commitment)?)
    }

    pub(crate) fn validate_package(
        &self,
        package: &AuditKeyPackage,
        trusted: &TrustedRoot,
        device: [u8; 16],
    ) -> Result<(), HumanCommitError> {
        self.keys
            .open_audit_key(package, trusted, device, package.generation())?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditRecordView {
    seq: u64,
    actor_kind: AuditActorKind,
    actor_id: Option<[u8; 16]>,
    action: AuditAction,
    outcome: AuditOutcome,
    item_id: Option<[u8; 16]>,
    revision_id: Option<[u8; 16]>,
    attempt_id: Option<[u8; 16]>,
}

impl AuditRecordView {
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }
    #[must_use]
    pub const fn actor_kind(&self) -> AuditActorKind {
        self.actor_kind
    }
    #[must_use]
    pub const fn actor_id(&self) -> Option<&[u8; 16]> {
        self.actor_id.as_ref()
    }
    #[must_use]
    pub const fn action(&self) -> AuditAction {
        self.action
    }
    #[must_use]
    pub const fn outcome(&self) -> AuditOutcome {
        self.outcome
    }
    #[must_use]
    pub const fn item_id(&self) -> Option<&[u8; 16]> {
        self.item_id.as_ref()
    }
    #[must_use]
    pub const fn revision_id(&self) -> Option<&[u8; 16]> {
        self.revision_id.as_ref()
    }
    #[must_use]
    pub const fn attempt_id(&self) -> Option<&[u8; 16]> {
        self.attempt_id.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditDiscontinuity {
    first_seq: u64,
    last_seq: u64,
    purge_event_id: [u8; 16],
}
impl AuditDiscontinuity {
    #[must_use]
    pub const fn first_seq(&self) -> u64 {
        self.first_seq
    }
    #[must_use]
    pub const fn last_seq(&self) -> u64 {
        self.last_seq
    }
    #[must_use]
    pub const fn purge_event_id(&self) -> &[u8; 16] {
        &self.purge_event_id
    }
}

pub struct AuditQuery {
    records: Vec<AuditRecordView>,
    discontinuities: Vec<AuditDiscontinuity>,
    segment_count: usize,
    closed_segment_count: usize,
}
impl AuditQuery {
    #[must_use]
    pub fn records(&self) -> &[AuditRecordView] {
        &self.records
    }
    #[must_use]
    pub fn discontinuities(&self) -> &[AuditDiscontinuity] {
        &self.discontinuities
    }
    #[must_use]
    pub const fn segment_count(&self) -> usize {
        self.segment_count
    }
    #[must_use]
    pub const fn closed_segment_count(&self) -> usize {
        self.closed_segment_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditPurgeScope {
    pub(crate) first_seq: u64,
    pub(crate) last_seq: u64,
    pub(crate) record_count: u64,
}
impl AuditPurgeScope {
    #[must_use]
    pub const fn first_seq(&self) -> u64 {
        self.first_seq
    }
    #[must_use]
    pub const fn last_seq(&self) -> u64 {
        self.last_seq
    }
    #[must_use]
    pub const fn record_count(&self) -> u64 {
        self.record_count
    }
}

pub struct PreparedAuditPurge {
    pub(crate) prepared: PreparedHumanCommand,
    pub(crate) scope: AuditPurgeScope,
}
impl PreparedAuditPurge {
    #[must_use]
    pub const fn prepared(&self) -> &PreparedHumanCommand {
        &self.prepared
    }
    #[must_use]
    pub const fn scope(&self) -> &AuditPurgeScope {
        &self.scope
    }
}

pub struct AutonomousAuditVault {
    path: PathBuf,
    device: [u8; 16],
    custody: Arc<AuditDeviceCustody>,
}

impl AutonomousAuditVault {
    /// Opens device audit custody without opening `K_H`.
    ///
    /// # Errors
    ///
    /// Returns an error for unavailable/mismatched custody or invalid storage.
    pub fn open(
        path: &Path,
        device: [u8; 16],
        custody: Arc<AuditDeviceCustody>,
    ) -> Result<Self, HumanCommitError> {
        let connection = open_connection(path)?;
        let (_, trusted) =
            load_and_validate_bundle(&connection).map_err(HumanCommitError::Vault)?;
        let package = load_matching_package(&connection, &trusted, device, &custody)?;
        custody
            .keys
            .open_audit_key(&package, &trusted, device, package.generation())?;
        Ok(Self {
            path: path.to_owned(),
            device,
            custody,
        })
    }

    /// Atomically advances the encrypted record, segment and manifest heads.
    ///
    /// # Errors
    ///
    /// Returns an error without a partial write if encryption or storage fails.
    pub fn append(&mut self, event: &AuditEvent) -> Result<(), HumanCommitError> {
        let mut connection = open_connection(&self.path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (_, trusted) =
            load_and_validate_bundle(&transaction).map_err(HumanCommitError::Vault)?;
        append_event(
            &transaction,
            &trusted,
            None,
            self.device,
            &self.custody,
            event,
            now_us()?,
            current_frontier(&transaction)?,
        )?;
        transaction.commit()?;
        Ok(())
    }
}

pub(crate) struct AppendedAudit {
    pub event_id: [u8; 16],
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn append_event(
    transaction: &Transaction<'_>,
    trusted: &TrustedRoot,
    root: Option<&UnlockedRoot>,
    device: [u8; 16],
    custody: &AuditDeviceCustody,
    event: &AuditEvent,
    wall_time_us: i64,
    frontier: [u8; 32],
) -> Result<AppendedAudit, HumanCommitError> {
    let package = ensure_package(transaction, trusted, root, device, custody)?;
    let generation = package.generation();
    let key = custody
        .keys
        .open_audit_key(&package, trusted, device, generation)?;
    let state: Option<(i64, i64, Vec<u8>)> = transaction
        .query_row(
            "SELECT generation,seq,last_hash FROM audit_state WHERE device_id=?1",
            [device.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let (seq, previous_hash) = match state {
        Some((stored_generation, seq, hash))
            if stored_generation
                == i64::try_from(generation).map_err(|_| HumanCommitError::InvalidCommand)? =>
        {
            (
                seq.checked_add(1).ok_or(HumanCommitError::InvalidCommand)?,
                fixed::<32>(&hash)?,
            )
        }
        _ => (1, [0_u8; 32]),
    };
    let event_id = random_id()?;
    let plaintext = encode_record(
        trusted.vault_id(),
        device,
        generation,
        u64::try_from(seq).map_err(|_| HumanCommitError::InvalidCommand)?,
        event_id,
        wall_time_us,
        event,
        frontier,
        previous_hash,
    );
    let envelope = key.seal_record(event_id, random_id()?, &plaintext)?;
    let signature = custody.keys.sign_audit_record(&envelope)?;
    let stored = encode_stored_record(&envelope, &signature);
    let record_hash = digest(&stored);
    let segment_id = select_segment(
        transaction,
        device,
        generation,
        i64::try_from(stored.len()).map_err(|_| HumanCommitError::InvalidCommand)?,
    )?;
    transaction.execute(
        "INSERT INTO encrypted_audit_records (device_id,generation,seq,event_id,segment_id,record,signature,record_hash) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![device.as_slice(), sql_i64(generation)?, seq, event_id.as_slice(), segment_id.as_slice(), envelope, signature.as_slice(), record_hash.as_slice()],
    )?;
    transaction.execute(
        "UPDATE audit_segments SET last_seq=?1,last_hash=?2,record_count=record_count+1,stored_bytes=stored_bytes+?3 WHERE segment_id=?4",
        params![seq, record_hash.as_slice(), i64::try_from(stored.len()).map_err(|_| HumanCommitError::InvalidCommand)?, segment_id.as_slice()],
    )?;
    transaction.execute(
        "INSERT INTO audit_state (device_id,generation,seq,last_hash) VALUES (?1,?2,?3,?4) ON CONFLICT(device_id) DO UPDATE SET generation=excluded.generation,seq=excluded.seq,last_hash=excluded.last_hash",
        params![device.as_slice(), sql_i64(generation)?, seq, record_hash.as_slice()],
    )?;
    rebuild_manifest(transaction, device, generation, &key)?;
    Ok(AppendedAudit { event_id })
}

#[allow(clippy::too_many_lines)]
pub(crate) fn query(
    connection: &Connection,
    root: &UnlockedRoot,
    device: [u8; 16],
    generation: u64,
    from_seq: u64,
    limit: usize,
) -> Result<AuditQuery, HumanCommitError> {
    if from_seq == 0 || limit == 0 || limit > 4096 {
        return Err(HumanCommitError::InvalidInput);
    }
    let package = load_package(connection, *root.vault_id(), device, generation)?;
    let key = root.open_audit_key_package(&package)?;
    let discontinuities = load_and_verify_manifest(connection, device, generation, &key)?;
    let newest_generation: i64 = connection.query_row(
        "SELECT max(generation) FROM audit_keys WHERE device_id=?1",
        [device.as_slice()],
        |row| row.get(0),
    )?;
    let active_state: Option<(i64, Vec<u8>)> = connection
        .query_row(
            "SELECT seq,last_hash FROM audit_state WHERE device_id=?1 AND generation=?2",
            params![device.as_slice(), sql_i64(generation)?],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (head, state_hash) = if let Some(state) = active_state {
        state
    } else if sql_i64(generation)? < newest_generation {
        connection
            .query_row(
                "SELECT last_seq,last_hash FROM audit_segments
                 WHERE device_id=?1 AND generation=?2 ORDER BY last_seq DESC LIMIT 1",
                params![device.as_slice(), sql_i64(generation)?],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(HumanCommitError::Integrity)?
    } else {
        return Err(HumanCommitError::Integrity);
    };
    let stored_head: (i64, Vec<u8>) = connection
        .query_row(
            "SELECT seq,record_hash FROM encrypted_audit_records
             WHERE device_id=?1 AND generation=?2 ORDER BY seq DESC LIMIT 1",
            params![device.as_slice(), sql_i64(generation)?],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(HumanCommitError::Integrity)?;
    if stored_head.0 != head || stored_head.1 != state_hash {
        return Err(HumanCommitError::Integrity);
    }
    for seq in 1..=head {
        let exists: bool = connection.query_row("SELECT 1 FROM encrypted_audit_records WHERE device_id=?1 AND generation=?2 AND seq=?3", params![device.as_slice(), sql_i64(generation)?, seq], |_| Ok(true)).optional()?.unwrap_or(false);
        if !exists
            && !discontinuities.iter().any(|gap| {
                i64::try_from(gap.first_seq).is_ok_and(|first| seq >= first)
                    && i64::try_from(gap.last_seq).is_ok_and(|last| seq <= last)
            })
        {
            return Err(HumanCommitError::Integrity);
        }
    }
    let mut statement = connection.prepare(
        "SELECT seq,event_id,record,signature,record_hash FROM encrypted_audit_records WHERE device_id=?1 AND generation=?2 AND seq>=?3 ORDER BY seq LIMIT ?4"
    )?;
    let mut rows = statement.query(params![
        device.as_slice(),
        sql_i64(generation)?,
        sql_i64(from_seq)?,
        i64::try_from(limit).map_err(|_| HumanCommitError::InvalidInput)?
    ])?;
    let mut records = Vec::new();
    let mut prior: Option<(i64, [u8; 32])> = None;
    while let Some(row) = rows.next()? {
        let seq: i64 = row.get(0)?;
        let event_id = fixed::<16>(&row.get::<_, Vec<u8>>(1)?)?;
        let envelope: Vec<u8> = row.get(2)?;
        let signature = fixed::<64>(&row.get::<_, Vec<u8>>(3)?)?;
        let expected_hash = fixed::<32>(&row.get::<_, Vec<u8>>(4)?)?;
        verify_audit_signature(package.signing_public_key(), &envelope, &signature)?;
        if digest(&encode_stored_record(&envelope, &signature)) != expected_hash {
            return Err(HumanCommitError::Integrity);
        }
        let plaintext = key.open_record(event_id, &envelope)?;
        let expected_previous = if seq == 1 {
            Some([0; 32])
        } else if prior.is_some_and(|(prior_seq, _)| prior_seq + 1 == seq) {
            prior.map(|(_, hash)| hash)
        } else {
            connection
                .query_row(
                    "SELECT record_hash FROM encrypted_audit_records
                     WHERE device_id=?1 AND generation=?2 AND seq=?3",
                    params![device.as_slice(), sql_i64(generation)?, seq - 1],
                    |record| record.get::<_, Vec<u8>>(0),
                )
                .optional()?
                .map(|hash| fixed(&hash))
                .transpose()?
        };
        records.push(decode_record(
            &plaintext,
            root.vault_id(),
            device,
            generation,
            u64::try_from(seq).map_err(|_| HumanCommitError::Integrity)?,
            expected_previous,
        )?);
        prior = Some((seq, expected_hash));
    }
    let segment_count: i64 = connection.query_row(
        "SELECT count(*) FROM audit_segments WHERE device_id=?1 AND generation=?2",
        params![device.as_slice(), sql_i64(generation)?],
        |row| row.get(0),
    )?;
    let closed_segment_count: i64 = connection.query_row(
        "SELECT count(*) FROM audit_segments WHERE device_id=?1 AND generation=?2 AND closed=1",
        params![device.as_slice(), sql_i64(generation)?],
        |row| row.get(0),
    )?;
    Ok(AuditQuery {
        records,
        discontinuities,
        segment_count: usize::try_from(segment_count).map_err(|_| HumanCommitError::Integrity)?,
        closed_segment_count: usize::try_from(closed_segment_count)
            .map_err(|_| HumanCommitError::Integrity)?,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn purge(
    transaction: &Transaction<'_>,
    root: &UnlockedRoot,
    trusted: &TrustedRoot,
    device: [u8; 16],
    custody: &AuditDeviceCustody,
    generation: u64,
    through_seq: u64,
    wall_time_us: i64,
) -> Result<(), HumanCommitError> {
    let target_head: i64 = transaction
        .query_row(
            "SELECT last_seq FROM audit_segments WHERE device_id=?1 AND generation=?2
             ORDER BY last_seq DESC LIMIT 1",
            params![device.as_slice(), sql_i64(generation)?],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(HumanCommitError::InvalidInput)?;
    if through_seq == 0
        || through_seq >= u64::try_from(target_head).map_err(|_| HumanCommitError::InvalidInput)?
    {
        return Err(HumanCommitError::InvalidInput);
    }
    let appended = append_event(
        transaction,
        trusted,
        Some(root),
        device,
        custody,
        &AuditEvent::new(
            AuditActorKind::Human,
            None,
            AuditAction::AuditPurge,
            AuditOutcome::Succeeded,
        ),
        wall_time_us,
        current_frontier(transaction)?,
    )?;
    transaction.execute(
        "DELETE FROM encrypted_audit_records WHERE device_id=?1 AND generation=?2 AND seq<=?3",
        params![
            device.as_slice(),
            sql_i64(generation)?,
            sql_i64(through_seq)?
        ],
    )?;
    transaction.execute(
        "DELETE FROM audit_purge_ranges WHERE device_id=?1 AND generation=?2 AND first_seq=1 AND last_seq<=?3",
        params![
            device.as_slice(),
            sql_i64(generation)?,
            sql_i64(through_seq)?
        ],
    )?;
    transaction.execute("INSERT INTO audit_purge_ranges (device_id,generation,first_seq,last_seq,purge_event_id) VALUES (?1,?2,1,?3,?4)", params![device.as_slice(), sql_i64(generation)?, sql_i64(through_seq)?, appended.event_id.as_slice()])?;
    let package = load_package(transaction, *root.vault_id(), device, generation)?;
    let key = root.open_audit_key_package(&package)?;
    rebuild_manifest(transaction, device, generation, &key)
}

pub(crate) fn ensure_package(
    transaction: &Transaction<'_>,
    trusted: &TrustedRoot,
    root: Option<&UnlockedRoot>,
    device: [u8; 16],
    custody: &AuditDeviceCustody,
) -> Result<AuditKeyPackage, HumanCommitError> {
    match load_matching_package(transaction, trusted, device, custody) {
        Ok(package) => return Ok(package),
        Err(HumanCommitError::AuditKeyUnavailable) => {}
        Err(error) => return Err(error),
    }
    let root = root.ok_or(HumanCommitError::AuditKeyUnavailable)?;
    let generation: i64 = transaction.query_row(
        "SELECT coalesce(max(generation),0)+1 FROM audit_keys WHERE device_id=?1",
        [device.as_slice()],
        |row| row.get(0),
    )?;
    let generation = u64::try_from(generation).map_err(|_| HumanCommitError::InvalidCommand)?;
    let package = root.provision_audit_key(
        device,
        generation,
        *custody.keys.encryption_public_key(),
        *custody.keys.signing_public_key(),
    )?;
    transaction.execute(
        "INSERT INTO audit_keys (device_id,generation,human_envelope,device_envelope,encryption_public_key,signing_public_key,human_signature) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![device.as_slice(), sql_i64(generation)?, package.human_envelope(), package.device_envelope(), package.encryption_public_key().as_slice(), package.signing_public_key().as_slice(), package.human_signature().as_slice()],
    )?;
    Ok(package)
}

pub(crate) fn load_matching_package(
    connection: &Connection,
    trusted: &TrustedRoot,
    device: [u8; 16],
    custody: &AuditDeviceCustody,
) -> Result<AuditKeyPackage, HumanCommitError> {
    let (generation, encryption, signing): (i64, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT generation,encryption_public_key,signing_public_key FROM audit_keys
             WHERE device_id=?1 ORDER BY generation DESC LIMIT 1",
            [device.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .ok_or(HumanCommitError::AuditKeyUnavailable)?;
    if encryption != custody.keys.encryption_public_key().as_slice()
        || signing != custody.keys.signing_public_key().as_slice()
    {
        return Err(HumanCommitError::AuditKeyUnavailable);
    }
    load_package(
        connection,
        *trusted.vault_id(),
        device,
        u64::try_from(generation).map_err(|_| HumanCommitError::Integrity)?,
    )
}

pub(crate) fn load_package(
    connection: &Connection,
    vault: [u8; 16],
    device: [u8; 16],
    generation: u64,
) -> Result<AuditKeyPackage, HumanCommitError> {
    connection.query_row(
        "SELECT human_envelope,device_envelope,encryption_public_key,signing_public_key,human_signature FROM audit_keys WHERE device_id=?1 AND generation=?2",
        params![device.as_slice(), sql_i64(generation)?], |row| {
            let human: Vec<u8> = row.get(0)?; let device_envelope: Vec<u8> = row.get(1)?;
            let encryption = fixed_sql::<32>(&row.get::<_, Vec<u8>>(2)?)?; let signing = fixed_sql::<32>(&row.get::<_, Vec<u8>>(3)?)?;
            let signature = fixed_sql::<64>(&row.get::<_, Vec<u8>>(4)?)?;
            AuditKeyPackage::from_parts(vault, device, generation, encryption, signing, human, device_envelope, signature).map_err(|_| rusqlite::Error::InvalidQuery)
        },
    ).map_err(HumanCommitError::Storage)
}

fn select_segment(
    transaction: &Transaction<'_>,
    device: [u8; 16],
    generation: u64,
    record_bytes: i64,
) -> Result<[u8; 16], HumanCommitError> {
    type OpenSegment = (Vec<u8>, i64, i64, Vec<u8>, i64);
    let open: Option<OpenSegment> = transaction.query_row(
        "SELECT segment_id,record_count,stored_bytes,last_hash,last_seq FROM audit_segments WHERE device_id=?1 AND generation=?2 AND closed=0 ORDER BY first_seq DESC LIMIT 1",
        params![device.as_slice(), sql_i64(generation)?], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
    ).optional()?;
    if let Some((id, count, bytes_value, _, _)) = &open
        && *count < MAX_SEGMENT_RECORDS
        && bytes_value
            .checked_add(record_bytes)
            .is_some_and(|sum| sum <= MAX_SEGMENT_BYTES)
    {
        return fixed(id);
    }
    if let Some((id, _, _, _, _)) = open {
        transaction.execute(
            "UPDATE audit_segments SET closed=1 WHERE segment_id=?1",
            [id],
        )?;
    }
    let segment_id = random_id()?;
    let state: Option<(i64, Vec<u8>)> = transaction
        .query_row(
            "SELECT seq,last_hash FROM audit_state WHERE device_id=?1 AND generation=?2",
            params![device.as_slice(), sql_i64(generation)?],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (first_seq, previous_hash) = match state {
        Some((seq, hash)) => (
            seq.checked_add(1).ok_or(HumanCommitError::InvalidCommand)?,
            fixed::<32>(&hash)?,
        ),
        None => (1, [0_u8; 32]),
    };
    transaction.execute("INSERT INTO audit_segments (segment_id,device_id,generation,first_seq,last_seq,previous_hash,last_hash,record_count,stored_bytes,closed) VALUES (?1,?2,?3,?4,?4,?5,?5,0,0,0)", params![segment_id.as_slice(),device.as_slice(),sql_i64(generation)?,first_seq,previous_hash.as_slice()])?;
    Ok(segment_id)
}

fn rebuild_manifest(
    transaction: &Transaction<'_>,
    device: [u8; 16],
    generation: u64,
    key: &AuditKey,
) -> Result<(), HumanCommitError> {
    let plaintext = encode_manifest(transaction, device, generation)?;
    let manifest_id = random_id()?;
    let envelope = key.seal_manifest(manifest_id, &plaintext)?;
    transaction.execute("INSERT INTO audit_manifests (device_id,generation,manifest_id,envelope) VALUES (?1,?2,?3,?4) ON CONFLICT(device_id,generation) DO UPDATE SET manifest_id=excluded.manifest_id,envelope=excluded.envelope", params![device.as_slice(),sql_i64(generation)?,manifest_id.as_slice(),envelope])?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn encode_manifest(
    connection: &Connection,
    device: [u8; 16],
    generation: u64,
) -> Result<Vec<u8>, HumanCommitError> {
    let previous_generation: Option<(i64, Vec<u8>)> = connection
        .query_row(
            "SELECT generation,last_hash FROM audit_segments
             WHERE device_id=?1 AND generation < ?2
             ORDER BY generation DESC,last_seq DESC LIMIT 1",
            params![device.as_slice(), sql_i64(generation)?],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let mut segments_stmt = connection.prepare("SELECT segment_id,first_seq,last_seq,previous_hash,last_hash FROM audit_segments WHERE device_id=?1 AND generation=?2 ORDER BY first_seq")?;
    let segments: Vec<_> = segments_stmt
        .query_map(params![device.as_slice(), sql_i64(generation)?], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })?
        .collect::<Result<_, _>>()?;
    let purges = load_purges(connection, device, generation)?;
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(6).unwrap();
    encoder.str("v").unwrap().u64(1).unwrap();
    encoder.str("device").unwrap().bytes(&device).unwrap();
    encoder.str("generation").unwrap().u64(generation).unwrap();
    encoder.str("previous_generation").unwrap();
    if let Some((previous, last_hash)) = previous_generation {
        encoder.map(2).unwrap();
        encoder
            .str("generation")
            .unwrap()
            .u64(u64::try_from(previous).map_err(|_| HumanCommitError::Integrity)?)
            .unwrap();
        encoder.str("last_hash").unwrap().bytes(&last_hash).unwrap();
    } else {
        encoder.null().unwrap();
    }
    encoder
        .str("segments")
        .unwrap()
        .array(u64::try_from(segments.len()).map_err(|_| HumanCommitError::InvalidCommand)?)
        .unwrap();
    for (id, first, last, previous, final_hash) in segments {
        encoder.map(6).unwrap();
        encoder.str("segment_id").unwrap().bytes(&id).unwrap();
        encoder
            .str("first_seq")
            .unwrap()
            .u64(u64::try_from(first).map_err(|_| HumanCommitError::Integrity)?)
            .unwrap();
        encoder
            .str("last_seq")
            .unwrap()
            .u64(u64::try_from(last).map_err(|_| HumanCommitError::Integrity)?)
            .unwrap();
        encoder
            .str("previous_hash")
            .unwrap()
            .bytes(&previous)
            .unwrap();
        encoder
            .str("last_hash")
            .unwrap()
            .bytes(&final_hash)
            .unwrap();
        encoder.str("record_hashes").unwrap();
        let mut hashes = connection.prepare(
            "SELECT record_hash FROM encrypted_audit_records WHERE segment_id=?1 ORDER BY seq",
        )?;
        let values: Vec<Vec<u8>> = hashes
            .query_map([id], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        encoder
            .array(u64::try_from(values.len()).map_err(|_| HumanCommitError::Integrity)?)
            .unwrap();
        for hash in values {
            encoder.bytes(&hash).unwrap();
        }
    }
    encoder
        .str("purge_ranges")
        .unwrap()
        .array(u64::try_from(purges.len()).map_err(|_| HumanCommitError::Integrity)?)
        .unwrap();
    for gap in purges {
        encoder.map(3).unwrap();
        encoder
            .str("first_seq")
            .unwrap()
            .u64(gap.first_seq)
            .unwrap();
        encoder.str("last_seq").unwrap().u64(gap.last_seq).unwrap();
        encoder
            .str("purge_event_id")
            .unwrap()
            .bytes(&gap.purge_event_id)
            .unwrap();
    }
    Ok(encoder.into_writer())
}

fn load_and_verify_manifest(
    connection: &Connection,
    device: [u8; 16],
    generation: u64,
    key: &AuditKey,
) -> Result<Vec<AuditDiscontinuity>, HumanCommitError> {
    let (id, envelope): (Vec<u8>, Vec<u8>) = connection.query_row(
        "SELECT manifest_id,envelope FROM audit_manifests WHERE device_id=?1 AND generation=?2",
        params![device.as_slice(), sql_i64(generation)?],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let plaintext = key.open_manifest(fixed(&id)?, &envelope)?;
    if plaintext != encode_manifest(connection, device, generation)? {
        return Err(HumanCommitError::Integrity);
    }
    let purges = decode_manifest_purges(&plaintext, device, generation)?;
    if purges != load_purges(connection, device, generation)? {
        return Err(HumanCommitError::Integrity);
    }
    Ok(purges)
}

fn decode_manifest_purges(
    bytes_value: &[u8],
    device: [u8; 16],
    generation: u64,
) -> Result<Vec<AuditDiscontinuity>, HumanCommitError> {
    let mut d = Decoder::new(bytes_value);
    expect_map(&mut d, 6)?;
    expect_key(&mut d, "v")?;
    if d.u64().map_err(invalid)? != 1 {
        return Err(HumanCommitError::Integrity);
    }
    expect_key(&mut d, "device")?;
    if decode_fixed::<16>(&mut d)? != device {
        return Err(HumanCommitError::Integrity);
    }
    expect_key(&mut d, "generation")?;
    if d.u64().map_err(invalid)? != generation {
        return Err(HumanCommitError::Integrity);
    }
    expect_key(&mut d, "previous_generation")?;
    match d.datatype().map_err(invalid)? {
        Type::Null => {
            d.null().map_err(invalid)?;
        }
        Type::Map => {
            expect_map(&mut d, 2)?;
            expect_key(&mut d, "generation")?;
            let previous = d.u64().map_err(invalid)?;
            if previous >= generation {
                return Err(HumanCommitError::Integrity);
            }
            expect_key(&mut d, "last_hash")?;
            let _ = decode_fixed::<32>(&mut d)?;
        }
        _ => return Err(HumanCommitError::Integrity),
    }
    expect_key(&mut d, "segments")?;
    let count = d
        .array()
        .map_err(invalid)?
        .ok_or(HumanCommitError::Integrity)?;
    for _ in 0..count {
        expect_map(&mut d, 6)?;
        expect_key(&mut d, "segment_id")?;
        let _ = decode_fixed::<16>(&mut d)?;
        expect_key(&mut d, "first_seq")?;
        let _ = d.u64().map_err(invalid)?;
        expect_key(&mut d, "last_seq")?;
        let _ = d.u64().map_err(invalid)?;
        expect_key(&mut d, "previous_hash")?;
        let _ = decode_fixed::<32>(&mut d)?;
        expect_key(&mut d, "last_hash")?;
        let _ = decode_fixed::<32>(&mut d)?;
        expect_key(&mut d, "record_hashes")?;
        let hashes = d
            .array()
            .map_err(invalid)?
            .ok_or(HumanCommitError::Integrity)?;
        for _ in 0..hashes {
            let _ = decode_fixed::<32>(&mut d)?;
        }
    }
    expect_key(&mut d, "purge_ranges")?;
    let count = d
        .array()
        .map_err(invalid)?
        .ok_or(HumanCommitError::Integrity)?;
    let mut result = Vec::new();
    for _ in 0..count {
        expect_map(&mut d, 3)?;
        expect_key(&mut d, "first_seq")?;
        let first_seq = d.u64().map_err(invalid)?;
        expect_key(&mut d, "last_seq")?;
        let last_seq = d.u64().map_err(invalid)?;
        expect_key(&mut d, "purge_event_id")?;
        let purge_event_id = decode_fixed(&mut d)?;
        result.push(AuditDiscontinuity {
            first_seq,
            last_seq,
            purge_event_id,
        });
    }
    if d.position() != bytes_value.len() {
        return Err(HumanCommitError::Integrity);
    }
    Ok(result)
}

fn load_purges(
    connection: &Connection,
    device: [u8; 16],
    generation: u64,
) -> Result<Vec<AuditDiscontinuity>, HumanCommitError> {
    let mut statement=connection.prepare("SELECT first_seq,last_seq,purge_event_id FROM audit_purge_ranges WHERE device_id=?1 AND generation=?2 ORDER BY first_seq")?;
    Ok(statement
        .query_map(params![device.as_slice(), sql_i64(generation)?], |row| {
            Ok(AuditDiscontinuity {
                first_seq: u64::try_from(row.get::<_, i64>(0)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                last_seq: u64::try_from(row.get::<_, i64>(1)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                purge_event_id: fixed_sql(&row.get::<_, Vec<u8>>(2)?)?,
            })
        })?
        .collect::<Result<_, _>>()?)
}

#[allow(clippy::too_many_arguments)]
fn encode_record(
    vault: &[u8; 16],
    device: [u8; 16],
    generation: u64,
    seq: u64,
    event_id: [u8; 16],
    wall_time_us: i64,
    event: &AuditEvent,
    frontier: [u8; 32],
    previous_hash: [u8; 32],
) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.map(19).unwrap();
    e.str("v").unwrap().u64(1).unwrap();
    e.str("vault").unwrap().bytes(vault).unwrap();
    e.str("device").unwrap().bytes(&device).unwrap();
    e.str("audit_generation").unwrap().u64(generation).unwrap();
    e.str("seq").unwrap().u64(seq).unwrap();
    e.str("event_id").unwrap().bytes(&event_id).unwrap();
    e.str("wall_time_us").unwrap().i64(wall_time_us).unwrap();
    e.str("monotonic_us").unwrap().u64(0).unwrap();
    e.str("boot_id").unwrap().null().unwrap();
    e.str("actor_kind")
        .unwrap()
        .str(event.actor_kind.name())
        .unwrap();
    e.str("actor_id").unwrap();
    optional(&mut e, event.actor_id.as_ref().map(<[u8; 16]>::as_slice));
    e.str("action").unwrap().str(event.action.name()).unwrap();
    e.str("outcome").unwrap().str(event.outcome.name()).unwrap();
    e.str("reason").unwrap().null().unwrap();
    e.str("item_id").unwrap();
    optional(&mut e, event.item_id.as_ref().map(<[u8; 16]>::as_slice));
    e.str("revision_id").unwrap();
    optional(&mut e, event.revision_id.as_ref().map(<[u8; 16]>::as_slice));
    e.str("attempt_id").unwrap();
    optional(&mut e, event.attempt_id.as_ref().map(<[u8; 16]>::as_slice));
    e.str("authority_frontier_hash")
        .unwrap()
        .bytes(&frontier)
        .unwrap();
    e.str("previous_record_hash")
        .unwrap()
        .bytes(&previous_hash)
        .unwrap();
    e.into_writer()
}

fn decode_record(
    bytes_value: &[u8],
    vault: &[u8; 16],
    device: [u8; 16],
    generation: u64,
    seq: u64,
    expected_previous: Option<[u8; 32]>,
) -> Result<AuditRecordView, HumanCommitError> {
    let mut d = Decoder::new(bytes_value);
    expect_map(&mut d, 19)?;
    expect_key(&mut d, "v")?;
    if d.u64().map_err(invalid)? != 1 {
        return Err(HumanCommitError::Integrity);
    }
    expect_key(&mut d, "vault")?;
    if decode_fixed::<16>(&mut d)? != *vault {
        return Err(HumanCommitError::Integrity);
    }
    expect_key(&mut d, "device")?;
    if decode_fixed::<16>(&mut d)? != device {
        return Err(HumanCommitError::Integrity);
    }
    expect_key(&mut d, "audit_generation")?;
    if d.u64().map_err(invalid)? != generation {
        return Err(HumanCommitError::Integrity);
    }
    expect_key(&mut d, "seq")?;
    if d.u64().map_err(invalid)? != seq {
        return Err(HumanCommitError::Integrity);
    }
    expect_key(&mut d, "event_id")?;
    let _ = decode_fixed::<16>(&mut d)?;
    expect_key(&mut d, "wall_time_us")?;
    let _ = d.i64().map_err(invalid)?;
    expect_key(&mut d, "monotonic_us")?;
    let _ = d.u64().map_err(invalid)?;
    expect_key(&mut d, "boot_id")?;
    skip_null_or_fixed::<16>(&mut d)?;
    expect_key(&mut d, "actor_kind")?;
    let actor_kind = AuditActorKind::parse(d.str().map_err(invalid)?)?;
    expect_key(&mut d, "actor_id")?;
    let actor_id = optional_fixed(&mut d)?;
    expect_key(&mut d, "action")?;
    let action = AuditAction::parse(d.str().map_err(invalid)?)?;
    expect_key(&mut d, "outcome")?;
    let outcome = AuditOutcome::parse(d.str().map_err(invalid)?)?;
    expect_key(&mut d, "reason")?;
    if d.datatype().map_err(invalid)? == Type::Null {
        d.null().map_err(invalid)?;
    } else {
        let _ = d.str().map_err(invalid)?;
    }
    expect_key(&mut d, "item_id")?;
    let item_id = optional_fixed(&mut d)?;
    expect_key(&mut d, "revision_id")?;
    let revision_id = optional_fixed(&mut d)?;
    expect_key(&mut d, "attempt_id")?;
    let attempt_id = optional_fixed(&mut d)?;
    expect_key(&mut d, "authority_frontier_hash")?;
    let _ = decode_fixed::<32>(&mut d)?;
    expect_key(&mut d, "previous_record_hash")?;
    let previous = decode_fixed::<32>(&mut d)?;
    if expected_previous.is_some_and(|expected| expected != previous) {
        return Err(HumanCommitError::Integrity);
    }
    if d.position() != bytes_value.len() {
        return Err(HumanCommitError::Integrity);
    }
    Ok(AuditRecordView {
        seq,
        actor_kind,
        actor_id,
        action,
        outcome,
        item_id,
        revision_id,
        attempt_id,
    })
}

fn encode_stored_record(envelope: &[u8], signature: &[u8; 64]) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.map(2).unwrap();
    e.str("envelope").unwrap().bytes(envelope).unwrap();
    e.str("signature").unwrap().bytes(signature).unwrap();
    e.into_writer()
}
pub(crate) fn current_frontier(connection: &Connection) -> Result<[u8; 32], HumanCommitError> {
    connection
        .query_row(
            "SELECT event_digest FROM authority_events ORDER BY rowid DESC LIMIT 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .map_or(Ok([0; 32]), |v| fixed(&v))
}
fn open_connection(path: &Path) -> Result<Connection, HumanCommitError> {
    let c = Connection::open(path)?;
    crate::configure_platform_durability(&c)?;
    c.execute_batch("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA temp_store=MEMORY; PRAGMA trusted_schema=OFF;")?;
    Ok(c)
}
pub(crate) fn now_us() -> Result<i64, HumanCommitError> {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| HumanCommitError::InvalidCommand)?;
    i64::try_from(d.as_micros()).map_err(|_| HumanCommitError::InvalidCommand)
}
fn fixed<const N: usize>(v: &[u8]) -> Result<[u8; N], HumanCommitError> {
    v.try_into().map_err(|_| HumanCommitError::Integrity)
}
fn fixed_sql<const N: usize>(v: &[u8]) -> rusqlite::Result<[u8; N]> {
    v.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}
fn optional(e: &mut Encoder<Vec<u8>>, v: Option<&[u8]>) {
    if let Some(v) = v {
        e.bytes(v).unwrap();
    } else {
        e.null().unwrap();
    }
}
fn expect_map(d: &mut Decoder<'_>, n: u64) -> Result<(), HumanCommitError> {
    if d.map().map_err(invalid)? == Some(n) {
        Ok(())
    } else {
        Err(HumanCommitError::Integrity)
    }
}
fn expect_key(d: &mut Decoder<'_>, key: &str) -> Result<(), HumanCommitError> {
    if d.str().map_err(invalid)? == key {
        Ok(())
    } else {
        Err(HumanCommitError::Integrity)
    }
}
fn decode_fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N], HumanCommitError> {
    d.bytes()
        .map_err(invalid)?
        .try_into()
        .map_err(|_| HumanCommitError::Integrity)
}
fn optional_fixed<const N: usize>(
    d: &mut Decoder<'_>,
) -> Result<Option<[u8; N]>, HumanCommitError> {
    if d.datatype().map_err(invalid)? == Type::Null {
        d.null().map_err(invalid)?;
        Ok(None)
    } else {
        Ok(Some(decode_fixed(d)?))
    }
}
fn skip_null_or_fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<(), HumanCommitError> {
    let _: Option<[u8; N]> = optional_fixed(d)?;
    Ok(())
}
fn invalid<T>(_: T) -> HumanCommitError {
    HumanCommitError::Integrity
}

fn sql_i64(value: u64) -> Result<i64, HumanCommitError> {
    i64::try_from(value).map_err(|_| HumanCommitError::InvalidInput)
}
