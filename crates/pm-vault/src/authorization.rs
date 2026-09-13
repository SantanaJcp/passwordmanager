// SPDX-License-Identifier: AGPL-3.0-only

//! Persistent local G5 authority and the common delegated discovery set.

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

use minicbor::{Decoder, Encoder, data::Type};
use pm_crypto::{
    TrustedRoot, digest, verify_audit_key_package, verify_device_event, verify_human_event,
};
use rusqlite::{Connection, OptionalExtension};
use zeroize::Zeroizing;

use crate::audit;
use crate::{AuditDeviceCustody, RecordKind, VaultError, load_and_validate_bundle};

const RPK_BYTES: usize = 44;
const MAX_LABEL_BYTES: usize = 256;
type CredentialRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationReason {
    OwnerRequest,
    Replacement,
    SuspectedCompromise,
}

impl AuthorizationReason {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::OwnerRequest => "owner_request",
            Self::Replacement => "replacement",
            Self::SuspectedCompromise => "suspected_compromise",
        }
    }
}

#[derive(Debug)]
pub enum AuthorizationError {
    AccessSuspended,
    AgentRevoked,
    CredentialUnavailable,
    Integrity,
    InvalidInput,
    Storage(rusqlite::Error),
    Unauthorized,
    Vault(VaultError),
}

impl fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AccessSuspended => "delegated access is suspended",
            Self::AgentRevoked => "agent generation is revoked",
            Self::CredentialUnavailable => "credential is unavailable",
            Self::Integrity => "delegated authority integrity failure",
            Self::InvalidInput => "invalid delegated authorization input",
            Self::Storage(_) => "delegated authorization storage failure",
            Self::Unauthorized => "agent is not authorized",
            Self::Vault(_) => "vault is unavailable",
        })
    }
}

impl std::error::Error for AuthorizationError {}

impl From<rusqlite::Error> for AuthorizationError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Storage(value)
    }
}

impl From<VaultError> for AuthorizationError {
    fn from(value: VaultError) -> Self {
        Self::Vault(value)
    }
}

impl From<crate::HumanCommitError> for AuthorizationError {
    fn from(value: crate::HumanCommitError) -> Self {
        match value {
            crate::HumanCommitError::InvalidInput => Self::InvalidInput,
            crate::HumanCommitError::ItemNotFound => Self::CredentialUnavailable,
            crate::HumanCommitError::Storage(error) => Self::Storage(error),
            crate::HumanCommitError::Vault(error) => Self::Vault(error),
            _ => Self::Integrity,
        }
    }
}

pub struct AgentEnrollment {
    pub(crate) subject_id: [u8; 16],
    pub(crate) request_id: [u8; 16],
    pub(crate) transport_rpk: [u8; RPK_BYTES],
    pub(crate) label: String,
    pub(crate) environment_binding: String,
}

impl AgentEnrollment {
    /// Creates the human-reviewed identity material for one stable agent subject.
    ///
    /// # Errors
    /// Returns an error for an all-zero ID, wrong RPK length, or oversized labels.
    pub fn new(
        subject_id: [u8; 16],
        request_id: [u8; 16],
        transport_rpk: &[u8],
        label: &str,
        environment_binding: &str,
    ) -> Result<Self, AuthorizationError> {
        if subject_id == [0; 16]
            || request_id == [0; 16]
            || transport_rpk.len() != RPK_BYTES
            || label.len() > MAX_LABEL_BYTES
            || environment_binding.len() > MAX_LABEL_BYTES
        {
            return Err(AuthorizationError::InvalidInput);
        }
        Ok(Self {
            subject_id,
            request_id,
            transport_rpk: transport_rpk
                .try_into()
                .map_err(|_| AuthorizationError::InvalidInput)?,
            label: label.to_owned(),
            environment_binding: environment_binding.to_owned(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentPeer {
    transport_rpk: [u8; RPK_BYTES],
}

impl AgentPeer {
    /// Captures the RPK observed from the mutually authenticated TLS connection.
    ///
    /// # Errors
    /// Returns an error unless the observed SPKI has the v1 fixed length.
    pub fn from_transport_rpk(value: &[u8]) -> Result<Self, AuthorizationError> {
        Ok(Self {
            transport_rpk: value
                .try_into()
                .map_err(|_| AuthorizationError::InvalidInput)?,
        })
    }
}

pub struct PreparedAgentEnrollment {
    pub(crate) prepared: crate::PreparedHumanCommand,
    pub(crate) generation: u64,
}

impl PreparedAgentEnrollment {
    #[must_use]
    pub const fn prepared(&self) -> &crate::PreparedHumanCommand {
        &self.prepared
    }
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    #[must_use]
    pub fn into_prepared(self) -> crate::PreparedHumanCommand {
        self.prepared
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegatedCredential {
    item_id: [u8; 16],
    revision_id: [u8; 16],
    kind: RecordKind,
    title: String,
    destination: Option<String>,
    account: Option<String>,
}

impl DelegatedCredential {
    #[must_use]
    pub const fn item_id(&self) -> &[u8; 16] {
        &self.item_id
    }
    #[must_use]
    pub const fn revision_id(&self) -> &[u8; 16] {
        &self.revision_id
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
    pub fn destination(&self) -> Option<&str> {
        self.destination.as_deref()
    }
    #[must_use]
    pub fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityEventHeader {
    digest: [u8; 32],
    seq: u64,
    previous: Option<[u8; 32]>,
    parents: Vec<[u8; 32]>,
    kind: String,
    subject: [u8; 16],
    subject_generation: u64,
}

impl AuthorityEventHeader {
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }
    #[must_use]
    pub const fn previous(&self) -> Option<&[u8; 32]> {
        self.previous.as_ref()
    }
    #[must_use]
    pub fn parents(&self) -> &[[u8; 32]] {
        &self.parents
    }
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }
    #[must_use]
    pub const fn subject(&self) -> &[u8; 16] {
        &self.subject
    }
    #[must_use]
    pub const fn subject_generation(&self) -> u64 {
        self.subject_generation
    }
}

pub struct DelegatedVault {
    path: PathBuf,
    device: [u8; 16],
    custody: Arc<AuditDeviceCustody>,
    trusted: TrustedRoot,
    custody_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentIdentity {
    pub(crate) subject: [u8; 16],
    pub(crate) generation: u64,
}

impl AgentIdentity {
    #[must_use]
    pub const fn subject(&self) -> &[u8; 16] {
        &self.subject
    }
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

pub(crate) struct OperationalCredential {
    pub descriptor: DelegatedCredential,
    pub auth: Zeroizing<Vec<u8>>,
}

impl DelegatedVault {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) const fn device(&self) -> [u8; 16] {
        self.device
    }
    pub(crate) fn custody(&self) -> Arc<AuditDeviceCustody> {
        Arc::clone(&self.custody)
    }
    pub(crate) const fn trusted(&self) -> TrustedRoot {
        self.trusted
    }
    pub(crate) const fn custody_generation(&self) -> u64 {
        self.custody_generation
    }
    /// Opens only device custody and verified public authority, never `K_H`.
    ///
    /// # Errors
    /// Returns an error for mismatched device custody or invalid vault state.
    pub fn open(
        path: &Path,
        device: [u8; 16],
        custody: Arc<AuditDeviceCustody>,
    ) -> Result<Self, AuthorizationError> {
        let connection = open_connection(path)?;
        let (_, trusted) = load_and_validate_bundle(&connection)?;
        let package = audit::load_matching_package(&connection, &trusted, device, &custody)
            .map_err(|_| AuthorizationError::Integrity)?;
        custody
            .validate_package(&package, &trusted, device)
            .map_err(|_| AuthorizationError::Integrity)?;
        Ok(Self {
            path: path.to_owned(),
            device,
            custody,
            trusted,
            custody_generation: package.generation(),
        })
    }

    /// Returns the shared enabled metadata set after checking current authority.
    ///
    /// # Errors
    /// Returns a stable denial for unknown/revoked peers, suspension or corruption.
    pub fn discover(
        &self,
        peer: &AgentPeer,
    ) -> Result<Vec<DelegatedCredential>, AuthorizationError> {
        self.verify_device_not_retired()?;
        let connection = open_connection(&self.path)?;
        self.verify_agent_and_global(&connection, peer)?;
        let mut statement = connection.prepare(
            "SELECT item_id,revision_id,control_package,grant,event_digest,grant_commitment
             FROM credential_authorizations WHERE status='enabled' ORDER BY item_id",
        )?;
        let mut rows = statement.query([])?;
        let mut values = Vec::new();
        while let Some(row) = rows.next()? {
            values.push(
                self.open_operational_credential(
                    &connection,
                    fixed_sql(&row.get::<_, Vec<u8>>(0)?)?,
                    fixed_sql(&row.get::<_, Vec<u8>>(1)?)?,
                    &row.get::<_, Vec<u8>>(2)?,
                    &row.get::<_, Vec<u8>>(3)?,
                    fixed_sql(&row.get::<_, Vec<u8>>(4)?)?,
                    fixed_sql(&row.get::<_, Vec<u8>>(5)?)?,
                )?
                .descriptor,
            );
        }
        Ok(values)
    }

    /// Rechecks authority for one sensitive-use reservation boundary.
    ///
    /// # Errors
    /// Returns a denial if authority changed since any earlier discovery.
    pub fn authorize(
        &self,
        peer: &AgentPeer,
        item: [u8; 16],
    ) -> Result<DelegatedCredential, AuthorizationError> {
        self.verify_device_not_retired()?;
        let connection = open_connection(&self.path)?;
        self.verify_agent_and_global(&connection, peer)?;
        let row: Option<CredentialRow> = connection
            .query_row(
                "SELECT revision_id,control_package,grant,event_digest,grant_commitment
             FROM credential_authorizations WHERE item_id=?1 AND status='enabled'",
                [item.as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        let (revision, package, grant, event, commitment) =
            row.ok_or(AuthorizationError::CredentialUnavailable)?;
        Ok(self
            .open_operational_credential(
                &connection,
                item,
                fixed_sql(&revision)?,
                &package,
                &grant,
                fixed_sql(&event)?,
                fixed_sql(&commitment)?,
            )?
            .descriptor)
    }

    /// Resolves the RPK-bound subject and generation without applying the
    /// independent global suspension switch. This is the ownership seam used
    /// by get/cancel; revoked generations still fail closed.
    ///
    /// # Errors
    /// Returns a stable denial for an unknown, revoked, or corrupt RPK binding.
    pub fn agent_identity(&self, peer: &AgentPeer) -> Result<AgentIdentity, AuthorizationError> {
        let connection = open_connection(&self.path)?;
        self.verify_agent(&connection, peer)
    }

    pub(crate) fn operational_credential_for_identity(
        &self,
        identity: AgentIdentity,
        item: [u8; 16],
    ) -> Result<OperationalCredential, AuthorizationError> {
        let connection = open_connection(&self.path)?;
        self.operational_credential_for_identity_in(&connection, identity, item)
    }

    pub(crate) fn operational_credential_for_identity_in(
        &self,
        connection: &Connection,
        identity: AgentIdentity,
        item: [u8; 16],
    ) -> Result<OperationalCredential, AuthorizationError> {
        let rpk: Vec<u8> = connection.query_row(
            "SELECT transport_rpk FROM agent_authorizations WHERE subject_id=?1 AND generation=?2",
            rusqlite::params![identity.subject.as_slice(), i64::try_from(identity.generation).map_err(|_| AuthorizationError::Integrity)?],
            |row| row.get(0),
        ).optional()?.ok_or(AuthorizationError::AgentRevoked)?;
        let peer = AgentPeer::from_transport_rpk(&rpk)?;
        self.verify_agent_and_global(connection, &peer)?;
        let row: Option<CredentialRow> = connection.query_row(
            "SELECT revision_id,control_package,grant,event_digest,grant_commitment FROM credential_authorizations WHERE item_id=?1 AND status='enabled'",
            [item.as_slice()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
        ).optional()?;
        let (revision, package, grant, event, commitment) =
            row.ok_or(AuthorizationError::CredentialUnavailable)?;
        self.open_operational_credential(
            connection,
            item,
            fixed_sql(&revision)?,
            &package,
            &grant,
            fixed_sql(&event)?,
            fixed_sql(&commitment)?,
        )
    }

    /// Exposes verified causal headers for ticket-16 reduction without a second ledger.
    ///
    /// # Errors
    /// Returns an error if any stored event/signature/device chain is invalid.
    pub fn authority_headers(&self) -> Result<Vec<AuthorityEventHeader>, AuthorizationError> {
        let connection = open_connection(&self.path)?;
        let mut statement = connection.prepare(
            "SELECT event_digest,event,human_signature,device_signature,issuer_device,issuer_generation FROM authority_events ORDER BY issuer_generation,seq,event_digest"
        )?;
        let mut rows = statement.query([])?;
        let mut result = Vec::new();
        while let Some(row) = rows.next()? {
            let digest_value = fixed_sql(&row.get::<_, Vec<u8>>(0)?)?;
            let event: Vec<u8> = row.get(1)?;
            let human = row
                .get::<_, Option<Vec<u8>>>(2)?
                .map(|v| fixed_sql(&v))
                .transpose()?;
            let device_signature = fixed_sql(&row.get::<_, Vec<u8>>(3)?)?;
            let issuer = fixed_sql(&row.get::<_, Vec<u8>>(4)?)?;
            let generation =
                u64::try_from(row.get::<_, i64>(5)?).map_err(|_| AuthorizationError::Integrity)?;
            let package =
                audit::load_package(&connection, *self.trusted.vault_id(), issuer, generation)
                    .map_err(|_| AuthorizationError::Integrity)?;
            verify_audit_key_package(&self.trusted, &package, issuer, generation)
                .map_err(|_| AuthorizationError::Integrity)?;
            verify_device_event(package.signing_public_key(), &event, &device_signature)
                .map_err(|_| AuthorizationError::Integrity)?;
            if digest(&event) != digest_value {
                return Err(AuthorizationError::Integrity);
            }
            let header = decode_event_header(digest_value, &event)?;
            if matches!(header.kind.as_str(), "join" | "checkpoint-cache") {
                if human.is_some() {
                    return Err(AuthorizationError::Integrity);
                }
            } else {
                verify_human_event(
                    &self.trusted,
                    &event,
                    human.as_ref().ok_or(AuthorizationError::Integrity)?,
                )
                .map_err(|_| AuthorizationError::Integrity)?;
            }
            result.push(header);
        }
        Ok(result)
    }

    fn verify_agent_and_global(
        &self,
        connection: &Connection,
        peer: &AgentPeer,
    ) -> Result<(), AuthorizationError> {
        self.verify_agent(connection, peer)?;
        let global: Option<(String, Vec<u8>)> = connection
            .query_row(
                "SELECT status,event_digest FROM delegated_state WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (global_status, global_digest) = global.ok_or(AuthorizationError::AccessSuspended)?;
        let global_event = self.verify_authority_event(connection, fixed_sql(&global_digest)?)?;
        let expected_kind = if global_status == "resumed" {
            "resume"
        } else {
            "suspend"
        };
        if global_event.kind != expected_kind || global_event.subject != *self.trusted.vault_id() {
            return Err(AuthorizationError::Integrity);
        }
        if global_status != "resumed" {
            return Err(AuthorizationError::AccessSuspended);
        }
        Ok(())
    }

    fn verify_agent(
        &self,
        connection: &Connection,
        peer: &AgentPeer,
    ) -> Result<AgentIdentity, AuthorizationError> {
        type AgentStatus = (Vec<u8>, i64, String, Vec<u8>, Option<Vec<u8>>);
        let authorization: Option<AgentStatus> = connection
            .query_row(
                "SELECT subject_id,generation,status,grant_event_digest,revoke_event_digest
             FROM agent_authorizations WHERE transport_rpk=?1 ORDER BY generation DESC LIMIT 1",
                [peer.transport_rpk.as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        let (subject, generation, status, grant_digest, revoke_digest) =
            authorization.ok_or(AuthorizationError::Unauthorized)?;
        let subject = fixed_sql(&subject)?;
        let generation = u64::try_from(generation).map_err(|_| AuthorizationError::Integrity)?;
        let grant = self.verify_authority_event(connection, fixed_sql(&grant_digest)?)?;
        if grant.kind != "agent-grant"
            || grant.subject != subject
            || grant.subject_generation != generation
        {
            return Err(AuthorizationError::Integrity);
        }
        match status.as_str() {
            "active" if revoke_digest.is_none() => {}
            "revoked" => {
                let revoked = self.verify_authority_event(
                    connection,
                    fixed_sql(&revoke_digest.ok_or(AuthorizationError::Integrity)?)?,
                )?;
                if revoked.kind != "agent-revoke"
                    || revoked.subject != subject
                    || revoked.subject_generation != generation
                {
                    return Err(AuthorizationError::Integrity);
                }
                return Err(AuthorizationError::AgentRevoked);
            }
            "superseded" => return Err(AuthorizationError::AgentRevoked),
            _ => return Err(AuthorizationError::Integrity),
        }
        Ok(AgentIdentity {
            subject,
            generation,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn open_operational_credential(
        &self,
        connection: &Connection,
        item: [u8; 16],
        revision: [u8; 16],
        package: &[u8],
        grant: &[u8],
        event_digest: [u8; 32],
        commitment: [u8; 32],
    ) -> Result<OperationalCredential, AuthorizationError> {
        let enable = self.verify_authority_event(connection, event_digest)?;
        if enable.kind != "enable" || enable.subject != item {
            return Err(AuthorizationError::Integrity);
        }
        let payload_digest = self
            .custody
            .verify_grant_vector(grant, &self.trusted, self.device, event_digest, commitment)
            .map_err(|_| AuthorizationError::Integrity)?;
        if payload_digest != digest(package) {
            return Err(AuthorizationError::Integrity);
        }
        let plaintext = self
            .custody
            .open_control_package(
                package,
                *self.trusted.vault_id(),
                self.device,
                self.custody_generation,
                item,
                revision,
            )
            .map_err(|_| AuthorizationError::Integrity)?;
        let credential = decode_operational_credential(&plaintext)?;
        if credential.descriptor.item_id != item || credential.descriptor.revision_id != revision {
            return Err(AuthorizationError::Integrity);
        }
        Ok(credential)
    }

    fn verify_authority_event(
        &self,
        connection: &Connection,
        expected: [u8; 32],
    ) -> Result<AuthorityEventHeader, AuthorizationError> {
        let (event,human,device,issuer,generation): (Vec<u8>,Vec<u8>,Vec<u8>,Vec<u8>,i64) = connection.query_row(
            "SELECT event,human_signature,device_signature,issuer_device,issuer_generation FROM authority_events WHERE event_digest=?1",
            [expected.as_slice()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
        ).optional()?.ok_or(AuthorizationError::Integrity)?;
        let issuer = fixed_sql(&issuer)?;
        let generation = u64::try_from(generation).map_err(|_| AuthorizationError::Integrity)?;
        let package = audit::load_package(connection, *self.trusted.vault_id(), issuer, generation)
            .map_err(|_| AuthorizationError::Integrity)?;
        verify_audit_key_package(&self.trusted, &package, issuer, generation)
            .map_err(|_| AuthorizationError::Integrity)?;
        verify_human_event(&self.trusted, &event, &fixed_sql(&human)?)
            .map_err(|_| AuthorizationError::Integrity)?;
        verify_device_event(package.signing_public_key(), &event, &fixed_sql(&device)?)
            .map_err(|_| AuthorizationError::Integrity)?;
        if digest(&event) != expected {
            return Err(AuthorizationError::Integrity);
        }
        decode_event_header(expected, &event)
    }

    fn verify_device_not_retired(&self) -> Result<(), AuthorizationError> {
        let reducer =
            crate::CausalReducer::open(&self.path).map_err(|_| AuthorizationError::Integrity)?;
        let view = reducer.view().map_err(|_| AuthorizationError::Integrity)?;
        if view.device_retired(&self.device) {
            Err(AuthorizationError::AccessSuspended)
        } else {
            Ok(())
        }
    }
}

pub(crate) struct G5EventInput<'a> {
    pub vault: &'a [u8; 16],
    pub event_id: [u8; 16],
    pub authority_epoch: u64,
    pub issuer_device: [u8; 16],
    pub issuer_generation: u64,
    pub seq: u64,
    pub previous: Option<[u8; 32]>,
    pub parents: &'a [[u8; 32]],
    pub kind: &'a str,
    pub subject: [u8; 16],
    pub subject_generation: u64,
    pub body: &'a [u8],
}

pub(crate) fn encode_g5_event(input: &G5EventInput<'_>) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.map(13).unwrap();
    e.str("v").unwrap().u64(1).unwrap();
    e.str("vault").unwrap().bytes(input.vault).unwrap();
    e.str("event_id").unwrap().bytes(&input.event_id).unwrap();
    e.str("authority_epoch")
        .unwrap()
        .u64(input.authority_epoch)
        .unwrap();
    e.str("issuer_device")
        .unwrap()
        .bytes(&input.issuer_device)
        .unwrap();
    e.str("issuer_generation")
        .unwrap()
        .u64(input.issuer_generation)
        .unwrap();
    e.str("seq").unwrap().u64(input.seq).unwrap();
    e.str("prev").unwrap();
    optional_bytes(&mut e, input.previous.as_ref().map(<[u8; 32]>::as_slice));
    e.str("parents")
        .unwrap()
        .array(u64::try_from(input.parents.len()).unwrap())
        .unwrap();
    for parent in input.parents {
        e.bytes(parent).unwrap();
    }
    e.str("kind").unwrap().str(input.kind).unwrap();
    e.str("subject").unwrap().bytes(&input.subject).unwrap();
    e.str("subject_generation")
        .unwrap()
        .u64(input.subject_generation)
        .unwrap();
    e.str("body").unwrap();
    e.writer_mut().extend_from_slice(input.body);
    e.into_writer()
}

pub(crate) fn encode_credential(value: &DelegatedCredential, auth: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.map(7).unwrap();
    e.str("item_id").unwrap().bytes(&value.item_id).unwrap();
    e.str("revision_id")
        .unwrap()
        .bytes(&value.revision_id)
        .unwrap();
    e.str("kind").unwrap().str(value.kind.name()).unwrap();
    e.str("title").unwrap().str(&value.title).unwrap();
    e.str("destination").unwrap();
    optional_string(&mut e, value.destination.as_deref());
    e.str("account").unwrap();
    optional_string(&mut e, value.account.as_deref());
    e.str("auth").unwrap().bytes(auth).unwrap();
    e.into_writer()
}

pub(crate) fn new_credential(
    item_id: [u8; 16],
    revision_id: [u8; 16],
    kind: RecordKind,
    title: String,
    destination: Option<String>,
    account: Option<String>,
) -> DelegatedCredential {
    DelegatedCredential {
        item_id,
        revision_id,
        kind,
        title,
        destination,
        account,
    }
}

fn decode_operational_credential(
    bytes: &[u8],
) -> Result<OperationalCredential, AuthorizationError> {
    let mut d = Decoder::new(bytes);
    expect_map(&mut d, 7)?;
    expect_key(&mut d, "item_id")?;
    let item_id = fixed_decode(&mut d)?;
    expect_key(&mut d, "revision_id")?;
    let revision_id = fixed_decode(&mut d)?;
    expect_key(&mut d, "kind")?;
    let kind = RecordKind::from_name(d.str().map_err(|_| AuthorizationError::Integrity)?)
        .ok_or(AuthorizationError::Integrity)?;
    expect_key(&mut d, "title")?;
    let title = d
        .str()
        .map_err(|_| AuthorizationError::Integrity)?
        .to_owned();
    expect_key(&mut d, "destination")?;
    let destination = optional_string_decode(&mut d)?;
    expect_key(&mut d, "account")?;
    let account = optional_string_decode(&mut d)?;
    expect_key(&mut d, "auth")?;
    let auth = Zeroizing::new(
        d.bytes()
            .map_err(|_| AuthorizationError::Integrity)?
            .to_vec(),
    );
    if d.position() != bytes.len() {
        return Err(AuthorizationError::Integrity);
    }
    let descriptor = DelegatedCredential {
        item_id,
        revision_id,
        kind,
        title,
        destination,
        account,
    };
    if encode_credential(&descriptor, &auth) != bytes {
        return Err(AuthorizationError::Integrity);
    }
    Ok(OperationalCredential { descriptor, auth })
}

fn decode_event_header(
    digest_value: [u8; 32],
    bytes: &[u8],
) -> Result<AuthorityEventHeader, AuthorizationError> {
    let mut d = Decoder::new(bytes);
    expect_map(&mut d, 13)?;
    expect_key(&mut d, "v")?;
    if d.u64().map_err(|_| AuthorizationError::Integrity)? != 1 {
        return Err(AuthorizationError::Integrity);
    }
    expect_key(&mut d, "vault")?;
    let _: [u8; 16] = fixed_decode(&mut d)?;
    expect_key(&mut d, "event_id")?;
    let _: [u8; 16] = fixed_decode(&mut d)?;
    expect_key(&mut d, "authority_epoch")?;
    d.u64().map_err(|_| AuthorizationError::Integrity)?;
    expect_key(&mut d, "issuer_device")?;
    let _: [u8; 16] = fixed_decode(&mut d)?;
    expect_key(&mut d, "issuer_generation")?;
    d.u64().map_err(|_| AuthorizationError::Integrity)?;
    expect_key(&mut d, "seq")?;
    let seq = d.u64().map_err(|_| AuthorizationError::Integrity)?;
    expect_key(&mut d, "prev")?;
    let previous = optional_fixed(&mut d)?;
    expect_key(&mut d, "parents")?;
    let count = d
        .array()
        .map_err(|_| AuthorizationError::Integrity)?
        .ok_or(AuthorizationError::Integrity)?;
    let mut parents =
        Vec::with_capacity(usize::try_from(count).map_err(|_| AuthorizationError::Integrity)?);
    for _ in 0..count {
        let p = fixed_decode(&mut d)?;
        if parents.last().is_some_and(|last| last >= &p) {
            return Err(AuthorizationError::Integrity);
        }
        parents.push(p);
    }
    expect_key(&mut d, "kind")?;
    let kind = d
        .str()
        .map_err(|_| AuthorizationError::Integrity)?
        .to_owned();
    expect_key(&mut d, "subject")?;
    let subject = fixed_decode(&mut d)?;
    expect_key(&mut d, "subject_generation")?;
    let subject_generation = d.u64().map_err(|_| AuthorizationError::Integrity)?;
    expect_key(&mut d, "body")?;
    d.skip().map_err(|_| AuthorizationError::Integrity)?;
    if d.position() != bytes.len() {
        return Err(AuthorizationError::Integrity);
    }
    Ok(AuthorityEventHeader {
        digest: digest_value,
        seq,
        previous,
        parents,
        kind,
        subject,
        subject_generation,
    })
}

fn open_connection(path: &Path) -> Result<Connection, AuthorizationError> {
    let c = Connection::open(path)?;
    c.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;")?;
    Ok(c)
}
fn fixed_sql<const N: usize>(v: &[u8]) -> Result<[u8; N], AuthorizationError> {
    v.try_into().map_err(|_| AuthorizationError::Integrity)
}
fn fixed_decode<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N], AuthorizationError> {
    d.bytes()
        .map_err(|_| AuthorizationError::Integrity)?
        .try_into()
        .map_err(|_| AuthorizationError::Integrity)
}
fn optional_fixed(d: &mut Decoder<'_>) -> Result<Option<[u8; 32]>, AuthorizationError> {
    if d.datatype().map_err(|_| AuthorizationError::Integrity)? == Type::Null {
        d.null().map_err(|_| AuthorizationError::Integrity)?;
        Ok(None)
    } else {
        Ok(Some(fixed_decode(d)?))
    }
}
fn expect_map(d: &mut Decoder<'_>, n: u64) -> Result<(), AuthorizationError> {
    if d.map().map_err(|_| AuthorizationError::Integrity)? == Some(n) {
        Ok(())
    } else {
        Err(AuthorizationError::Integrity)
    }
}
fn expect_key(d: &mut Decoder<'_>, key: &str) -> Result<(), AuthorizationError> {
    if d.str().map_err(|_| AuthorizationError::Integrity)? == key {
        Ok(())
    } else {
        Err(AuthorizationError::Integrity)
    }
}
fn optional_bytes(e: &mut Encoder<Vec<u8>>, v: Option<&[u8]>) {
    if let Some(v) = v {
        e.bytes(v).unwrap();
    } else {
        e.null().unwrap();
    }
}
fn optional_string(e: &mut Encoder<Vec<u8>>, v: Option<&str>) {
    if let Some(v) = v {
        e.str(v).unwrap();
    } else {
        e.null().unwrap();
    }
}
fn optional_string_decode(d: &mut Decoder<'_>) -> Result<Option<String>, AuthorizationError> {
    if d.datatype().map_err(|_| AuthorizationError::Integrity)? == Type::Null {
        d.null().map_err(|_| AuthorizationError::Integrity)?;
        Ok(None)
    } else {
        Ok(Some(
            d.str()
                .map_err(|_| AuthorizationError::Integrity)?
                .to_owned(),
        ))
    }
}
