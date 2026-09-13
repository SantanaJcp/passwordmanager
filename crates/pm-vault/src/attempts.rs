// SPDX-License-Identifier: AGPL-3.0-only

//! Durable G4 authentication attempts. Provider adapters receive a lease only
//! after the intent and RUNNING transition are durably audited.
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::type_complexity
)]

use std::{fmt, sync::Arc};

use minicbor::{Decoder, Encoder};
use pm_crypto::{TrustedRoot, digest, random_id};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use zeroize::Zeroizing;

use crate::{
    AgentIdentity, AgentPeer, AuditAction, AuditActorKind, AuditDeviceCustody, AuditEvent,
    AuditOutcome, AuthorizationError, DelegatedVault, HumanVault, HumanVerification, PasskeyError,
    PasskeyOperation, PasskeyRequest, PasskeyStatus, PrivateKeyFormat, RecordKind, TotpAlgorithm,
    audit,
};

const ATTEMPT_LIFETIME_US: i64 = 24 * 60 * 60 * 1_000_000;
const RESULT_LIFETIME_US: i64 = 24 * 60 * 60 * 1_000_000;
const IDEMPOTENCY_LIFETIME_US: i64 = 7 * 24 * 60 * 60 * 1_000_000;
const KEY_PAST_US: i64 = 600 * 1_000_000;
const KEY_FUTURE_US: i64 = 120 * 1_000_000;
const MAX_CONTEXT: usize = 64 * 1024;
const MAX_PER_AGENT: i64 = 16;
const MAX_PER_CUSTODIAN: i64 = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptState {
    Created,
    Running,
    WaitingForHuman,
    Succeeded,
    Failed,
    Cancelled,
    Expired,
    Indeterminate,
}
impl AttemptState {
    const fn name(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Running => "running",
            Self::WaitingForHuman => "waiting_for_human",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Indeterminate => "indeterminate",
        }
    }
    fn parse(v: &str) -> Result<Self, AttemptError> {
        Ok(match v {
            "created" => Self::Created,
            "running" => Self::Running,
            "waiting_for_human" => Self::WaitingForHuman,
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            "expired" => Self::Expired,
            "indeterminate" => Self::Indeterminate,
            _ => return Err(AttemptError::Integrity),
        })
    }
    const fn terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::Expired
        )
    }
}

#[derive(Debug)]
pub enum AttemptError {
    AccessSuspended,
    AgentRevoked,
    CredentialUnavailable,
    ClockUntrusted,
    IdempotencyConflict,
    IdempotencyExpired,
    ResultExpired,
    Integrity,
    InvalidArgument,
    NotFound,
    RateLimited,
    Storage(rusqlite::Error),
    Vault(crate::VaultError),
}
impl fmt::Display for AttemptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AccessSuspended => "ACCESS_SUSPENDED",
            Self::AgentRevoked => "AGENT_REVOKED",
            Self::CredentialUnavailable => "CREDENTIAL_UNAVAILABLE",
            Self::ClockUntrusted => "CLOCK_UNTRUSTED",
            Self::IdempotencyConflict => "IDEMPOTENCY_CONFLICT",
            Self::IdempotencyExpired => "IDEMPOTENCY_EXPIRED",
            Self::ResultExpired => "RESULT_EXPIRED",
            Self::Integrity => "INTEGRITY_ERROR",
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::NotFound => "NOT_FOUND",
            Self::RateLimited => "RATE_LIMITED",
            Self::Storage(_) => "INTERNAL",
            Self::Vault(_) => "CUSTODY_UNAVAILABLE",
        })
    }
}
impl std::error::Error for AttemptError {}
impl From<rusqlite::Error> for AttemptError {
    fn from(v: rusqlite::Error) -> Self {
        Self::Storage(v)
    }
}
impl From<crate::VaultError> for AttemptError {
    fn from(v: crate::VaultError) -> Self {
        Self::Vault(v)
    }
}
impl From<crate::HumanCommitError> for AttemptError {
    fn from(_: crate::HumanCommitError) -> Self {
        Self::Integrity
    }
}
impl From<AuthorizationError> for AttemptError {
    fn from(v: AuthorizationError) -> Self {
        match v {
            AuthorizationError::AccessSuspended => Self::AccessSuspended,
            AuthorizationError::AgentRevoked => Self::AgentRevoked,
            AuthorizationError::CredentialUnavailable => Self::CredentialUnavailable,
            AuthorizationError::Unauthorized => Self::NotFound,
            AuthorizationError::Storage(e) => Self::Storage(e),
            AuthorizationError::Vault(e) => Self::Vault(e),
            _ => Self::Integrity,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdempotencyKey {
    issued_at_us: i64,
    nonce: [u8; 16],
}
impl IdempotencyKey {
    pub fn new(issued_at_us: i64, nonce: [u8; 16]) -> Result<Self, AttemptError> {
        if nonce == [0; 16] {
            return Err(AttemptError::InvalidArgument);
        }
        Ok(Self {
            issued_at_us,
            nonce,
        })
    }
    pub const fn issued_at_us(&self) -> i64 {
        self.issued_at_us
    }
    pub const fn nonce(&self) -> &[u8; 16] {
        &self.nonce
    }
}

pub struct StartAttempt {
    pub credential_id: [u8; 16],
    pub integration_id: String,
    pub integration_version: u32,
    pub method: String,
    pub destination: String,
    pub context: Vec<u8>,
    pub idempotency: IdempotencyKey,
}
impl StartAttempt {
    pub fn new(
        credential_id: [u8; 16],
        integration_id: &str,
        integration_version: u32,
        method: &str,
        destination: &str,
        context: Vec<u8>,
        idempotency: IdempotencyKey,
    ) -> Result<Self, AttemptError> {
        if credential_id == [0; 16]
            || integration_id.is_empty()
            || integration_id.len() > 128
            || integration_version == 0
            || method.is_empty()
            || method.len() > 64
            || destination.is_empty()
            || destination.len() > 8192
            || context.len() > MAX_CONTEXT
        {
            return Err(AttemptError::InvalidArgument);
        }
        Ok(Self {
            credential_id,
            integration_id: integration_id.into(),
            integration_version,
            method: method.into(),
            destination: destination.into(),
            context,
            idempotency,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptSnapshot {
    attempt_id: [u8; 16],
    credential_id: [u8; 16],
    revision_id: [u8; 16],
    integration_id: String,
    integration_version: u32,
    state: AttemptState,
    created_at_us: i64,
    expires_at_us: i64,
    reason: Option<String>,
    result: Option<Vec<u8>>,
}
impl AttemptSnapshot {
    pub const fn attempt_id(&self) -> &[u8; 16] {
        &self.attempt_id
    }
    pub const fn credential_id(&self) -> &[u8; 16] {
        &self.credential_id
    }
    pub const fn revision_id(&self) -> &[u8; 16] {
        &self.revision_id
    }
    pub fn integration_id(&self) -> &str {
        &self.integration_id
    }
    pub const fn integration_version(&self) -> u32 {
        self.integration_version
    }
    pub const fn state(&self) -> AttemptState {
        self.state
    }
    pub const fn created_at_us(&self) -> i64 {
        self.created_at_us
    }
    pub const fn expires_at_us(&self) -> i64 {
        self.expires_at_us
    }
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }
    pub fn result(&self) -> Option<&[u8]> {
        self.result.as_deref()
    }
}

pub struct AttemptLease {
    attempt_id: [u8; 16],
    lease_token: [u8; 16],
    credential_id: [u8; 16],
    revision_id: [u8; 16],
    destination: String,
    context: Vec<u8>,
    integration_id: String,
    method: String,
    owner: AgentIdentity,
    username: String,
    password: Zeroizing<Vec<u8>>,
    subject_token: Option<Zeroizing<Vec<u8>>>,
    totp: Option<TotpLease>,
    ssh: Option<SshLease>,
    reconciliation: bool,
}

pub struct SshLease {
    private_format: PrivateKeyFormat,
    private_key: Zeroizing<Vec<u8>>,
    public_key: Vec<u8>,
    passphrase: Option<Zeroizing<Vec<u8>>>,
}

impl SshLease {
    pub const fn private_format(&self) -> PrivateKeyFormat {
        self.private_format
    }
    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    pub fn passphrase(&self) -> Option<&[u8]> {
        self.passphrase.as_ref().map(|value| value.as_slice())
    }
}

impl AttemptLease {
    pub const fn attempt_id(&self) -> &[u8; 16] {
        &self.attempt_id
    }
    pub const fn credential_id(&self) -> &[u8; 16] {
        &self.credential_id
    }
    pub const fn revision_id(&self) -> &[u8; 16] {
        &self.revision_id
    }
    pub fn destination(&self) -> &str {
        &self.destination
    }
    pub fn context(&self) -> &[u8] {
        &self.context
    }
    pub fn integration_id(&self) -> &str {
        &self.integration_id
    }
    pub fn method(&self) -> &str {
        &self.method
    }
    pub const fn owner_subject(&self) -> &[u8; 16] {
        self.owner.subject()
    }
    pub const fn owner_generation(&self) -> u64 {
        self.owner.generation()
    }
    pub fn username(&self) -> &str {
        &self.username
    }
    pub fn password(&self) -> &[u8] {
        &self.password
    }
    /// Returns the subject token only for the closed Keycloak exchange
    /// adapter. It remains inside the custodian/provider boundary.
    #[must_use]
    pub fn subject_token(&self) -> Option<&[u8]> {
        self.subject_token.as_ref().map(|value| value.as_slice())
    }
    pub const fn totp(&self) -> Option<&TotpLease> {
        self.totp.as_ref()
    }
    pub const fn ssh(&self) -> Option<&SshLease> {
        self.ssh.as_ref()
    }
    pub const fn reconciliation_only(&self) -> bool {
        self.reconciliation
    }
}

pub struct TotpLease {
    secret: Zeroizing<Vec<u8>>,
    algorithm: TotpAlgorithm,
    digits: u8,
    period: u16,
    t0: u64,
}

impl TotpLease {
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }
    pub const fn algorithm(&self) -> TotpAlgorithm {
        self.algorithm
    }
    pub const fn digits(&self) -> u8 {
        self.digits
    }
    pub const fn period(&self) -> u16 {
        self.period
    }
    pub const fn t0(&self) -> u64 {
        self.t0
    }
}

pub enum AttemptOutcome {
    Succeeded { result: Vec<u8> },
    WaitingForHuman { challenge: Vec<u8> },
    Failed { reason: &'static str },
    Indeterminate,
}

pub struct AttemptVault {
    delegated: DelegatedVault,
    trusted: TrustedRoot,
    device: [u8; 16],
    generation: u64,
    custody: Arc<AuditDeviceCustody>,
}
impl AttemptVault {
    pub fn open(delegated: DelegatedVault) -> Result<Self, AttemptError> {
        let trusted = delegated.trusted();
        let device = delegated.device();
        let generation = delegated.custody_generation();
        let custody = delegated.custody();
        Ok(Self {
            delegated,
            trusted,
            device,
            generation,
            custody,
        })
    }

    pub(crate) fn path(&self) -> &std::path::Path {
        self.delegated.path()
    }

    pub(crate) fn validate_peer(&self, peer: &AgentPeer) -> Result<(), AttemptError> {
        Ok(self.delegated.validate_peer(peer)?)
    }

    pub(crate) fn seal_passkey_blob(
        &self,
        request_id: [u8; 16],
        bytes: &[u8],
    ) -> Result<Vec<u8>, AttemptError> {
        Ok(self.custody.seal_attempt_state(
            *self.trusted.vault_id(),
            self.device,
            self.generation,
            request_id,
            bytes,
        )?)
    }

    pub(crate) fn open_passkey_blob(
        &self,
        request_id: [u8; 16],
        package: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, AttemptError> {
        Ok(Zeroizing::new(self.custody.open_attempt_state(
            package,
            *self.trusted.vault_id(),
            self.device,
            self.generation,
            request_id,
        )?))
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn begin_passkey(
        &self,
        request: &PasskeyRequest,
    ) -> Result<PasskeyStatus, PasskeyError> {
        if request.operation() != PasskeyOperation::Get {
            return Err(PasskeyError::InvalidRequest);
        }
        let attempt = *request.attempt_id().ok_or(PasskeyError::InvalidRequest)?;
        let now = now_us()?;
        let mut connection = open(self.delegated.path())?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_clock(&tx, now)?;
        let (package, subject, generation): (Vec<u8>, Vec<u8>, i64) = tx
            .query_row(
                "SELECT state_package,owner_subject,owner_generation FROM authentication_attempts WHERE attempt_id=?1",
                [attempt.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or(PasskeyError::NotFound)?;
        let identity = AgentIdentity {
            subject: fixed(&subject)?,
            generation: u64::try_from(generation).map_err(|_| PasskeyError::Integrity)?,
        };
        let mut snapshot = decode_snapshot(&self.custody.open_attempt_state(
            &package,
            *self.trusted.vault_id(),
            self.device,
            self.generation,
            attempt,
        )?)?;
        if snapshot.state != AttemptState::Created || now >= snapshot.expires_at_us {
            return Err(if now >= snapshot.expires_at_us {
                PasskeyError::Expired
            } else {
                PasskeyError::InvalidRequest
            });
        }
        let (destination, context, method) = decode_execution(&self.custody.open_attempt_state(
            &package,
            *self.trusted.vault_id(),
            self.device,
            self.generation,
            attempt,
        )?)?;
        if destination != request.origin()
            || context != b"keycloak-webauthn/1"
            || method != "webauthn"
        {
            return Err(PasskeyError::InvalidRequest);
        }
        let operational = self
            .delegated
            .operational_credential_for_identity_in(&tx, identity, snapshot.credential_id)
            .map_err(AttemptError::from)?;
        if operational.descriptor.kind() != RecordKind::Passkey
            || operational.descriptor.revision_id() != &snapshot.revision_id
            || operational.descriptor.destination() != Some(request.origin())
        {
            return Err(PasskeyError::Revoked);
        }
        let material = passkey_material(&operational.auth)?;
        if material.rp_id != request.rp_id()
            || !request
                .credential_ids()
                .iter()
                .any(|id| id == &material.credential_id)
        {
            return Err(PasskeyError::InvalidRequest);
        }
        let request_bytes = request.to_bytes();
        let request_digest = digest(&request_bytes);
        let request_package = self.seal_passkey_blob(*request.request_id(), &request_bytes)?;
        let expires = now
            .saturating_add(5 * 60 * 1_000_000)
            .min(snapshot.expires_at_us);
        let waiting = PasskeyStatus::Waiting(crate::passkey::prompt_for_account(
            request,
            &material.user_name,
        ));
        let waiting_package = self.seal_passkey_blob(
            *request.request_id(),
            &crate::passkey::encode_status(&waiting),
        )?;
        tx.execute(
            "INSERT INTO passkey_requests(request_id,request_digest,operation,attempt_id,request,state,item_id,response,created_at_us,expires_at_us) VALUES(?1,?2,'get',?3,?4,'waiting',?5,?6,?7,?8)",
            params![request.request_id().as_slice(), request_digest.as_slice(), attempt.as_slice(), request_package, snapshot.credential_id.as_slice(), waiting_package, now, expires],
        )?;
        snapshot.state = AttemptState::WaitingForHuman;
        snapshot.reason = Some("PASSKEY_HUMAN_CONFIRMATION".into());
        update_snapshot(
            &tx,
            &self.custody,
            *self.trusted.vault_id(),
            self.device,
            self.generation,
            &snapshot,
            Some((&destination, &context, &method)),
            now,
        )?;
        append_audit(
            &tx,
            &self.trusted,
            self.device,
            &self.custody,
            &snapshot,
            AuditAction::AuthState,
            AuditOutcome::Accepted,
            now,
        )?;
        tx.commit()?;
        Ok(waiting)
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn confirm_passkey(
        &self,
        human: &HumanVault,
        request_id: [u8; 16],
        verification: HumanVerification,
    ) -> Result<PasskeyStatus, PasskeyError> {
        let now = now_us()?;
        let mut connection = open(self.delegated.path())?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_clock(&tx, now)?;
        let (request_bytes, state, expires): (Vec<u8>, String, i64) = tx
            .query_row(
                "SELECT request,state,expires_at_us FROM passkey_requests WHERE request_id=?1 AND operation='get'",
                [request_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or(PasskeyError::NotFound)?;
        let request_plain = self.open_passkey_blob(request_id, &request_bytes)?;
        let request = PasskeyRequest::from_bytes(&request_plain)?;
        if state == "complete" {
            let response: Vec<u8> = tx.query_row(
                "SELECT response FROM passkey_requests WHERE request_id=?1",
                [request_id.as_slice()],
                |row| row.get(0),
            )?;
            let response = self.open_passkey_blob(request_id, &response)?;
            return crate::passkey::decode_status(&response);
        }
        if state != "waiting" || now >= expires {
            return Err(if now >= expires {
                PasskeyError::Expired
            } else {
                PasskeyError::Integrity
            });
        }
        crate::passkey::require_verification(request.user_verification(), verification)?;
        let attempt = *request.attempt_id().ok_or(PasskeyError::Integrity)?;
        let (package, subject, generation): (Vec<u8>, Vec<u8>, i64) = tx.query_row(
            "SELECT state_package,owner_subject,owner_generation FROM authentication_attempts WHERE attempt_id=?1",
            [attempt.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let identity = AgentIdentity {
            subject: fixed(&subject)?,
            generation: u64::try_from(generation).map_err(|_| PasskeyError::Integrity)?,
        };
        let mut snapshot = decode_snapshot(&self.custody.open_attempt_state(
            &package,
            *self.trusted.vault_id(),
            self.device,
            self.generation,
            attempt,
        )?)?;
        if snapshot.state != AttemptState::WaitingForHuman || now >= snapshot.expires_at_us {
            return Err(PasskeyError::Expired);
        }
        let operational = self
            .delegated
            .operational_credential_for_identity_in(&tx, identity, snapshot.credential_id)
            .map_err(AttemptError::from)?;
        if operational.descriptor.kind() != RecordKind::Passkey
            || operational.descriptor.revision_id() != &snapshot.revision_id
            || operational.descriptor.destination() != Some(request.origin())
        {
            return Err(PasskeyError::Revoked);
        }
        let material = passkey_material(&operational.auth)?;
        if material.rp_id != request.rp_id()
            || !request
                .credential_ids()
                .iter()
                .any(|id| id == &material.credential_id)
        {
            return Err(PasskeyError::InvalidRequest);
        }
        let assertion = human.sign_passkey_assertion(
            snapshot.credential_id,
            &request,
            verification == HumanVerification::Verified,
        )?;
        let result = PasskeyStatus::Assertion(assertion);
        let response = crate::passkey::encode_status(&result);
        let response_package = self.seal_passkey_blob(request_id, &response)?;
        let (destination, context, method) = decode_execution(&self.custody.open_attempt_state(
            &package,
            *self.trusted.vault_id(),
            self.device,
            self.generation,
            attempt,
        )?)?;
        snapshot.state = AttemptState::Succeeded;
        snapshot.reason = None;
        snapshot.result = Some(response.clone());
        update_snapshot(
            &tx,
            &self.custody,
            *self.trusted.vault_id(),
            self.device,
            self.generation,
            &snapshot,
            Some((&destination, &context, &method)),
            now,
        )?;
        tx.execute(
            "UPDATE passkey_requests SET state='complete',response=?2 WHERE request_id=?1 AND state='waiting'",
            params![request_id.as_slice(), response_package],
        )?;
        append_audit(
            &tx,
            &self.trusted,
            self.device,
            &self.custody,
            &snapshot,
            AuditAction::AuthState,
            AuditOutcome::Succeeded,
            now,
        )?;
        tx.commit()?;
        Ok(result)
    }

    pub fn start(
        &self,
        peer: &AgentPeer,
        request: &StartAttempt,
    ) -> Result<AttemptSnapshot, AttemptError> {
        let now = now_us()?;
        let identity = self.delegated.agent_identity(peer)?;
        let params_digest = params_digest(request);
        let scope_digest = scope_digest(
            self.trusted.vault_id(),
            self.device,
            identity,
            request.idempotency,
        );
        let mut c = open(self.delegated.path())?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_clock(&tx, now)?;
        if let Some((attempt,stored_params,created))=tx.query_row("SELECT attempt_id,params_digest,created_at_us FROM authentication_attempts WHERE scope_digest=?1",[scope_digest.as_slice()],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,i64>(2)?))).optional()? {
            if now-created>IDEMPOTENCY_LIFETIME_US{return Err(AttemptError::IdempotencyExpired)}
            if stored_params.as_slice()!=params_digest{return Err(AttemptError::IdempotencyConflict)}
            let id=fixed(&attempt)?; drop(tx); return self.get(peer,id);
        }
        if request.idempotency.issued_at_us < now - KEY_PAST_US
            || request.idempotency.issued_at_us > now + KEY_FUTURE_US
        {
            return Err(AttemptError::InvalidArgument);
        }
        let op = self.delegated.operational_credential_for_identity_in(
            &tx,
            identity,
            request.credential_id,
        )?;
        if op.descriptor.destination() != Some(request.destination.as_str())
            || !matches_authentication_profile(op.descriptor.kind(), request)
        {
            return Err(AttemptError::CredentialUnavailable);
        }
        let per_agent:i64=tx.query_row("SELECT count(*) FROM authentication_attempts WHERE owner_subject=?1 AND owner_generation=?2 AND state IN ('created','running','waiting_for_human','indeterminate')",params![identity.subject().as_slice(),i64::try_from(identity.generation()).map_err(|_|AttemptError::Integrity)?],|r|r.get(0))?;
        let total:i64=tx.query_row("SELECT count(*) FROM authentication_attempts WHERE state IN ('created','running','waiting_for_human','indeterminate')",[],|r|r.get(0))?;
        if per_agent >= MAX_PER_AGENT || total >= MAX_PER_CUSTODIAN {
            return Err(AttemptError::RateLimited);
        }
        let attempt = random_id().map_err(|_| AttemptError::Integrity)?;
        let expires = now + ATTEMPT_LIFETIME_US;
        let snap = AttemptSnapshot {
            attempt_id: attempt,
            credential_id: request.credential_id,
            revision_id: *op.descriptor.revision_id(),
            integration_id: request.integration_id.clone(),
            integration_version: request.integration_version,
            state: AttemptState::Created,
            created_at_us: now,
            expires_at_us: expires,
            reason: None,
            result: None,
        };
        let package = self.custody.seal_attempt_state(
            *self.trusted.vault_id(),
            self.device,
            self.generation,
            attempt,
            &encode_snapshot(
                &snap,
                Some((&request.destination, &request.context, &request.method)),
            ),
        )?;
        tx.execute("INSERT INTO authentication_attempts(attempt_id,item_id,revision_id,owner_subject,owner_generation,state,created_at_us,expires_at_us,scope_digest,params_digest,state_package) VALUES(?1,?2,?3,?4,?5,'created',?6,?7,?8,?9,?10)",params![attempt.as_slice(),request.credential_id.as_slice(),op.descriptor.revision_id().as_slice(),identity.subject().as_slice(),i64::try_from(identity.generation()).map_err(|_|AttemptError::Integrity)?,now,expires,scope_digest.as_slice(),params_digest.as_slice(),package])?;
        append_audit(
            &tx,
            &self.trusted,
            self.device,
            &self.custody,
            &snap,
            AuditAction::AuthAccepted,
            AuditOutcome::Accepted,
            now,
        )?;
        tx.commit()?;
        Ok(snap)
    }

    pub fn get(
        &self,
        peer: &AgentPeer,
        attempt: [u8; 16],
    ) -> Result<AttemptSnapshot, AttemptError> {
        let identity = self.delegated.agent_identity(peer)?;
        let now = now_us()?;
        let mut c = open(self.delegated.path())?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_clock(&tx, now)?;
        let mut snap = load_owned(
            &tx,
            &self.custody,
            *self.trusted.vault_id(),
            self.device,
            self.generation,
            identity,
            attempt,
        )?;
        let stored_expires: i64 = tx.query_row(
            "SELECT expires_at_us FROM authentication_attempts WHERE attempt_id=?1",
            [attempt.as_slice()],
            |r| r.get(0),
        )?;
        if stored_expires < snap.expires_at_us {
            snap.expires_at_us = stored_expires;
        }
        if !snap.state.terminal()
            && snap.state != AttemptState::Indeterminate
            && now >= snap.expires_at_us
        {
            snap.state = AttemptState::Expired;
            snap.reason = Some("ATTEMPT_EXPIRED".into());
            update_snapshot(
                &tx,
                &self.custody,
                *self.trusted.vault_id(),
                self.device,
                self.generation,
                &snap,
                None,
                now,
            )?;
            append_audit(
                &tx,
                &self.trusted,
                self.device,
                &self.custody,
                &snap,
                AuditAction::AuthState,
                AuditOutcome::Failed,
                now,
            )?;
        }
        let result_expired = purge_result_if_due(&tx, &mut snap, now)?;
        if result_expired {
            append_audit(
                &tx,
                &self.trusted,
                self.device,
                &self.custody,
                &snap,
                AuditAction::AuthState,
                AuditOutcome::Succeeded,
                now,
            )?;
        }
        tx.commit()?;
        if result_expired {
            return Err(AttemptError::ResultExpired);
        }
        Ok(snap)
    }

    pub fn cancel(
        &self,
        peer: &AgentPeer,
        attempt: [u8; 16],
    ) -> Result<AttemptSnapshot, AttemptError> {
        let identity = self.delegated.agent_identity(peer)?;
        let now = now_us()?;
        let mut c = open(self.delegated.path())?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut snap = load_owned(
            &tx,
            &self.custody,
            *self.trusted.vault_id(),
            self.device,
            self.generation,
            identity,
            attempt,
        )?;
        if matches!(
            snap.state,
            AttemptState::Created | AttemptState::Running | AttemptState::WaitingForHuman
        ) {
            snap.state = AttemptState::Cancelled;
            snap.reason = Some("ATTEMPT_CANCELLED".into());
            update_snapshot(
                &tx,
                &self.custody,
                *self.trusted.vault_id(),
                self.device,
                self.generation,
                &snap,
                None,
                now,
            )?;
            append_audit(
                &tx,
                &self.trusted,
                self.device,
                &self.custody,
                &snap,
                AuditAction::AuthState,
                AuditOutcome::Succeeded,
                now,
            )?;
        }
        tx.commit()?;
        Ok(snap)
    }

    pub fn claim_next(&self) -> Result<Option<AttemptLease>, AttemptError> {
        self.claim(false)
    }
    pub fn claim_waiting_for_reconciliation(&self) -> Result<Option<AttemptLease>, AttemptError> {
        self.claim(true)
    }
    fn claim(&self, reconcile: bool) -> Result<Option<AttemptLease>, AttemptError> {
        let now = now_us()?;
        let mut c = open(self.delegated.path())?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_clock(&tx, now)?;
        let sql = if reconcile {
            "SELECT attempt_id,item_id,owner_subject,owner_generation,state_package FROM authentication_attempts WHERE state IN ('waiting_for_human','indeterminate') AND expires_at_us>?1 AND claimed_at_us<=?1-100000 ORDER BY claimed_at_us LIMIT 1"
        } else {
            "SELECT attempt_id,item_id,owner_subject,owner_generation,state_package FROM authentication_attempts WHERE state='created' AND expires_at_us>?1 ORDER BY created_at_us LIMIT 1"
        };
        let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>, i64, Vec<u8>)> = tx
            .query_row(sql, [now], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })
            .optional()?;
        let Some((aid, item, subject, generation, package)) = row else {
            return Ok(None);
        };
        let attempt = fixed(&aid)?;
        let identity = AgentIdentity {
            subject: fixed(&subject)?,
            generation: u64::try_from(generation).map_err(|_| AttemptError::Integrity)?,
        };
        let op = self
            .delegated
            .operational_credential_for_identity(identity, fixed(&item)?)?;
        let mut snap = decode_snapshot(&self.custody.open_attempt_state(
            &package,
            *self.trusted.vault_id(),
            self.device,
            self.generation,
            attempt,
        )?)?;
        if snap.revision_id != *op.descriptor.revision_id() {
            return Err(AttemptError::CredentialUnavailable);
        }
        let (destination, context, method) = decode_execution(&self.custody.open_attempt_state(
            &package,
            *self.trusted.vault_id(),
            self.device,
            self.generation,
            attempt,
        )?)?;
        let material = credential_material(
            reconcile,
            &snap.integration_id,
            &op.auth,
            &destination,
            &method,
            now,
        )?;
        let token = random_id().map_err(|_| AttemptError::Integrity)?;
        snap.state = AttemptState::Running;
        let replacement = self.custody.update_attempt_state(
            &package,
            *self.trusted.vault_id(),
            self.device,
            self.generation,
            attempt,
            &encode_snapshot(&snap, Some((&destination, &context, &method))),
        )?;
        let update = if reconcile {
            "UPDATE authentication_attempts SET state='running',state_package=?2,lease_token=?3,claimed_at_us=?4,provider_sent=1 WHERE attempt_id=?1 AND state IN ('waiting_for_human','indeterminate')"
        } else {
            "UPDATE authentication_attempts SET state='running',state_package=?2,lease_token=?3,claimed_at_us=?4,provider_sent=1 WHERE attempt_id=?1 AND state='created'"
        };
        let changed = tx.execute(
            update,
            params![attempt.as_slice(), replacement, token.as_slice(), now],
        )?;
        if changed != 1 {
            return Ok(None);
        }
        append_audit(
            &tx,
            &self.trusted,
            self.device,
            &self.custody,
            &snap,
            AuditAction::AuthUse,
            AuditOutcome::Accepted,
            now,
        )?;
        tx.commit()?;
        Ok(Some(AttemptLease {
            attempt_id: attempt,
            lease_token: token,
            credential_id: snap.credential_id,
            revision_id: snap.revision_id,
            destination,
            context,
            integration_id: snap.integration_id,
            method,
            owner: identity,
            username: material.username,
            password: material.password,
            subject_token: material.subject_token,
            totp: material.totp,
            ssh: material.ssh,
            reconciliation: reconcile,
        }))
    }

    /// Executes the single provider-use boundary while holding a SQLite
    /// immediate transaction. A human suspension/revocation that commits first
    /// is observed and the closure is not called; one that commits afterwards
    /// is serialized after the already-issued provider request.
    ///
    /// # Errors
    /// Returns a stable authority or integrity error when the lease is no
    /// longer the running, current-revision attempt.
    pub fn with_authorized_provider_use<T>(
        &self,
        lease: &AttemptLease,
        use_once: impl FnOnce() -> T,
    ) -> Result<T, AttemptError> {
        let mut connection = open(self.delegated.path())?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<(Vec<u8>, Vec<u8>, i64, Vec<u8>)> = transaction
            .query_row(
                "SELECT revision_id,owner_subject,owner_generation,lease_token
                 FROM authentication_attempts
                 WHERE attempt_id=?1 AND item_id=?2 AND state='running'",
                params![lease.attempt_id.as_slice(), lease.credential_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let (revision, subject, generation, token) = row.ok_or(AttemptError::NotFound)?;
        if fixed::<16>(&revision)? != lease.revision_id
            || fixed::<16>(&subject)? != *lease.owner.subject()
            || u64::try_from(generation).map_err(|_| AttemptError::Integrity)?
                != lease.owner.generation()
            || fixed::<16>(&token)? != lease.lease_token
        {
            return Err(AttemptError::Integrity);
        }
        let current = self
            .delegated
            .operational_credential_for_identity(lease.owner, lease.credential_id)?;
        if current.descriptor.revision_id() != &lease.revision_id {
            return Err(AttemptError::CredentialUnavailable);
        }
        let result = use_once();
        transaction.commit()?;
        Ok(result)
    }

    pub fn settle(
        &self,
        lease: &AttemptLease,
        outcome: AttemptOutcome,
    ) -> Result<AttemptSnapshot, AttemptError> {
        let now = now_us()?;
        let mut c = open(self.delegated.path())?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let package:Vec<u8>=tx.query_row("SELECT state_package FROM authentication_attempts WHERE attempt_id=?1 AND state='running' AND lease_token=?2",params![lease.attempt_id.as_slice(),lease.lease_token.as_slice()],|r|r.get(0)).optional()?.ok_or(AttemptError::NotFound)?;
        let mut snap = decode_snapshot(&self.custody.open_attempt_state(
            &package,
            *self.trusted.vault_id(),
            self.device,
            self.generation,
            lease.attempt_id,
        )?)?;
        let (destination, context, method) = decode_execution(&self.custody.open_attempt_state(
            &package,
            *self.trusted.vault_id(),
            self.device,
            self.generation,
            lease.attempt_id,
        )?)?;
        if method != lease.method {
            return Err(AttemptError::Integrity);
        }
        let (audit_outcome, terminal) = match outcome {
            AttemptOutcome::Succeeded { result } => {
                if result.len() > MAX_CONTEXT {
                    return Err(AttemptError::InvalidArgument);
                }
                snap.state = AttemptState::Succeeded;
                snap.result = Some(result);
                (AuditOutcome::Succeeded, true)
            }
            AttemptOutcome::WaitingForHuman { challenge } => {
                if challenge.len() > MAX_CONTEXT {
                    return Err(AttemptError::InvalidArgument);
                }
                snap.state = AttemptState::WaitingForHuman;
                snap.reason =
                    Some(String::from_utf8(challenge).map_err(|_| AttemptError::InvalidArgument)?);
                (AuditOutcome::Accepted, false)
            }
            AttemptOutcome::Failed { reason } => {
                snap.state = AttemptState::Failed;
                snap.reason = Some(reason.into());
                (AuditOutcome::Failed, true)
            }
            AttemptOutcome::Indeterminate => {
                snap.state = AttemptState::Indeterminate;
                snap.reason = Some("INDETERMINATE".into());
                (AuditOutcome::Indeterminate, false)
            }
        };
        let replacement = self.custody.update_attempt_state(
            &package,
            *self.trusted.vault_id(),
            self.device,
            self.generation,
            lease.attempt_id,
            &encode_snapshot(&snap, Some((&destination, &context, &lease.method))),
        )?;
        tx.execute("UPDATE authentication_attempts SET state=?2,state_package=?3,lease_token=NULL,terminal_at_us=?4,claimed_at_us=?5 WHERE attempt_id=?1",params![lease.attempt_id.as_slice(),snap.state.name(),replacement,if terminal{Some(now)}else{None},now])?;
        append_audit(
            &tx,
            &self.trusted,
            self.device,
            &self.custody,
            &snap,
            AuditAction::AuthState,
            audit_outcome,
            now,
        )?;
        tx.commit()?;
        Ok(snap)
    }

    pub fn recover_inflight(&self) -> Result<usize, AttemptError> {
        let ids: Vec<[u8; 16]> = {
            let c = open(self.delegated.path())?;
            let mut s =
                c.prepare("SELECT attempt_id FROM authentication_attempts WHERE state='running'")?;
            let rows = s.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
            rows.map(|r| fixed(&r?)).collect::<Result<_, _>>()?
        };
        let mut n = 0;
        for id in ids {
            let now = now_us()?;
            let mut c = open(self.delegated.path())?;
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let row:Option<(Vec<u8>,Vec<u8>,i64)>=tx.query_row("SELECT state_package,owner_subject,owner_generation FROM authentication_attempts WHERE attempt_id=?1 AND state='running'",[id.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
            if let Some((package, _, _)) = row {
                let mut snap = decode_snapshot(&self.custody.open_attempt_state(
                    &package,
                    *self.trusted.vault_id(),
                    self.device,
                    self.generation,
                    id,
                )?)?;
                let execution = decode_execution(&self.custody.open_attempt_state(
                    &package,
                    *self.trusted.vault_id(),
                    self.device,
                    self.generation,
                    id,
                )?)?;
                snap.state = AttemptState::Indeterminate;
                snap.reason = Some("INDETERMINATE".into());
                let replacement = self.custody.update_attempt_state(
                    &package,
                    *self.trusted.vault_id(),
                    self.device,
                    self.generation,
                    id,
                    &encode_snapshot(&snap, Some((&execution.0, &execution.1, &execution.2))),
                )?;
                tx.execute("UPDATE authentication_attempts SET state='indeterminate',state_package=?2,lease_token=NULL WHERE attempt_id=?1",params![id.as_slice(),replacement])?;
                append_audit(
                    &tx,
                    &self.trusted,
                    self.device,
                    &self.custody,
                    &snap,
                    AuditAction::Recovery,
                    AuditOutcome::Indeterminate,
                    now,
                )?;
                tx.commit()?;
                n += 1;
            }
        }
        Ok(n)
    }
}

fn open(path: &std::path::Path) -> Result<Connection, AttemptError> {
    let c = Connection::open(path)?;
    crate::configure_platform_durability(&c)?;
    c.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;")?;
    Ok(c)
}
fn now_us() -> Result<i64, AttemptError> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AttemptError::ClockUntrusted)?;
    i64::try_from(d.as_micros()).map_err(|_| AttemptError::ClockUntrusted)
}
fn check_clock(tx: &Transaction<'_>, now: i64) -> Result<(), AttemptError> {
    let max: Option<i64> = tx
        .query_row(
            "SELECT max_wall_us FROM attempt_clock WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if max.is_some_and(|v| now + KEY_FUTURE_US < v) {
        return Err(AttemptError::ClockUntrusted);
    }
    tx.execute("INSERT INTO attempt_clock(singleton,max_wall_us) VALUES(1,?1) ON CONFLICT(singleton) DO UPDATE SET max_wall_us=max(max_wall_us,excluded.max_wall_us)",[now])?;
    Ok(())
}
fn fixed<const N: usize>(v: &[u8]) -> Result<[u8; N], AttemptError> {
    v.try_into().map_err(|_| AttemptError::Integrity)
}
fn params_digest(r: &StartAttempt) -> [u8; 32] {
    let mut e = Encoder::new(Vec::new());
    e.array(6)
        .unwrap()
        .bytes(&r.credential_id)
        .unwrap()
        .str(&r.integration_id)
        .unwrap()
        .u32(r.integration_version)
        .unwrap()
        .str(&r.method)
        .unwrap()
        .str(&r.destination)
        .unwrap()
        .bytes(&r.context)
        .unwrap();
    digest(&e.into_writer())
}
fn scope_digest(
    vault: &[u8; 16],
    device: [u8; 16],
    id: AgentIdentity,
    key: IdempotencyKey,
) -> [u8; 32] {
    let mut e = Encoder::new(Vec::new());
    e.array(7)
        .unwrap()
        .str("pm/idempotency/v1")
        .unwrap()
        .bytes(vault)
        .unwrap()
        .bytes(&device)
        .unwrap()
        .bytes(id.subject())
        .unwrap()
        .u64(id.generation())
        .unwrap()
        .i64(key.issued_at_us)
        .unwrap()
        .bytes(&key.nonce)
        .unwrap();
    digest(&e.into_writer())
}
fn encode_snapshot(snapshot: &AttemptSnapshot, execution: Option<(&str, &[u8], &str)>) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(12)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&snapshot.attempt_id)
        .unwrap()
        .bytes(&snapshot.credential_id)
        .unwrap()
        .bytes(&snapshot.revision_id)
        .unwrap()
        .str(&snapshot.integration_id)
        .unwrap()
        .u32(snapshot.integration_version)
        .unwrap()
        .str(snapshot.state.name())
        .unwrap()
        .i64(snapshot.created_at_us)
        .unwrap()
        .i64(snapshot.expires_at_us)
        .unwrap();
    match &snapshot.reason {
        Some(value) => encoder.str(value).unwrap(),
        None => encoder.null().unwrap(),
    };
    match &snapshot.result {
        Some(value) => encoder.bytes(value).unwrap(),
        None => encoder.null().unwrap(),
    };
    match execution {
        Some((destination, context, method)) => encoder
            .array(3)
            .unwrap()
            .str(destination)
            .unwrap()
            .bytes(context)
            .unwrap()
            .str(method)
            .unwrap(),
        None => encoder.null().unwrap(),
    };
    encoder.into_writer()
}
fn decode_snapshot(bytes: &[u8]) -> Result<AttemptSnapshot, AttemptError> {
    let mut d = Decoder::new(bytes);
    if d.array().map_err(|_| AttemptError::Integrity)? != Some(12)
        || d.u8().map_err(|_| AttemptError::Integrity)? != 1
    {
        return Err(AttemptError::Integrity);
    }
    let attempt_id = fixed(d.bytes().map_err(|_| AttemptError::Integrity)?)?;
    let credential_id = fixed(d.bytes().map_err(|_| AttemptError::Integrity)?)?;
    let revision_id = fixed(d.bytes().map_err(|_| AttemptError::Integrity)?)?;
    let integration_id = d.str().map_err(|_| AttemptError::Integrity)?.into();
    let integration_version = d.u32().map_err(|_| AttemptError::Integrity)?;
    let state = AttemptState::parse(d.str().map_err(|_| AttemptError::Integrity)?)?;
    let created_at_us = d.i64().map_err(|_| AttemptError::Integrity)?;
    let expires_at_us = d.i64().map_err(|_| AttemptError::Integrity)?;
    let reason = if d.datatype().map_err(|_| AttemptError::Integrity)? == minicbor::data::Type::Null
    {
        d.null().unwrap();
        None
    } else {
        Some(d.str().map_err(|_| AttemptError::Integrity)?.into())
    };
    let result = if d.datatype().map_err(|_| AttemptError::Integrity)? == minicbor::data::Type::Null
    {
        d.null().unwrap();
        None
    } else {
        Some(d.bytes().map_err(|_| AttemptError::Integrity)?.to_vec())
    };
    d.skip().map_err(|_| AttemptError::Integrity)?;
    if d.position() != bytes.len() {
        return Err(AttemptError::Integrity);
    }
    Ok(AttemptSnapshot {
        attempt_id,
        credential_id,
        revision_id,
        integration_id,
        integration_version,
        state,
        created_at_us,
        expires_at_us,
        reason,
        result,
    })
}
fn decode_execution(bytes: &[u8]) -> Result<(String, Vec<u8>, String), AttemptError> {
    let mut d = Decoder::new(bytes);
    if d.array().map_err(|_| AttemptError::Integrity)? != Some(12) {
        return Err(AttemptError::Integrity);
    }
    for _ in 0..4 {
        d.skip().map_err(|_| AttemptError::Integrity)?;
    }
    let integration = d.str().map_err(|_| AttemptError::Integrity)?;
    for _ in 0..6 {
        d.skip().map_err(|_| AttemptError::Integrity)?;
    }
    let fields = d
        .array()
        .map_err(|_| AttemptError::Integrity)?
        .ok_or(AttemptError::Integrity)?;
    let destination = d.str().map_err(|_| AttemptError::Integrity)?.into();
    let context = d.bytes().map_err(|_| AttemptError::Integrity)?.to_vec();
    let method = match fields {
        3 => d.str().map_err(|_| AttemptError::Integrity)?.into(),
        // Ticket 08 persisted only destination/context. That schema can only
        // represent its single closed method and remains readable after 10.
        2 if integration == "controlled.external" => "password".into(),
        _ => return Err(AttemptError::Integrity),
    };
    if d.position() != bytes.len() {
        return Err(AttemptError::Integrity);
    }
    Ok((destination, context, method))
}

struct CredentialMaterial {
    username: String,
    password: Zeroizing<Vec<u8>>,
    subject_token: Option<Zeroizing<Vec<u8>>>,
    totp: Option<TotpLease>,
    ssh: Option<SshLease>,
}

impl CredentialMaterial {
    fn empty() -> Self {
        Self {
            username: String::new(),
            password: Zeroizing::new(Vec::new()),
            subject_token: None,
            totp: None,
            ssh: None,
        }
    }
}

#[derive(Default)]
enum DecodedPassphrase {
    #[default]
    Absent,
    Present(Option<Zeroizing<Vec<u8>>>),
}

#[derive(Default)]
struct DecodedAuthMethod {
    method: Option<String>,
    username: Option<String>,
    password: Option<Zeroizing<Vec<u8>>>,
    secret: Option<Zeroizing<Vec<u8>>>,
    algorithm: Option<TotpAlgorithm>,
    digits: Option<u8>,
    period: Option<u16>,
    t0: Option<u64>,
    account: Option<String>,
    private_format: Option<PrivateKeyFormat>,
    private_key: Option<Zeroizing<Vec<u8>>>,
    public_key: Option<Vec<u8>>,
    passphrase: DecodedPassphrase,
}

fn decode_auth_method(
    decoder: &mut Decoder<'_>,
    fields: u64,
) -> Result<DecodedAuthMethod, AttemptError> {
    let mut parsed = DecodedAuthMethod::default();
    for _ in 0..fields {
        match decoder.str().map_err(|_| AttemptError::Integrity)? {
            "method" => {
                parsed.method = Some(
                    decoder
                        .str()
                        .map_err(|_| AttemptError::Integrity)?
                        .to_owned(),
                );
            }
            "username" => {
                parsed.username = Some(
                    decoder
                        .str()
                        .map_err(|_| AttemptError::Integrity)?
                        .to_owned(),
                );
            }
            "password" => {
                parsed.password = Some(Zeroizing::new(
                    decoder
                        .bytes()
                        .map_err(|_| AttemptError::Integrity)?
                        .to_vec(),
                ));
            }
            "secret" => {
                parsed.secret = Some(Zeroizing::new(
                    decoder
                        .bytes()
                        .map_err(|_| AttemptError::Integrity)?
                        .to_vec(),
                ));
            }
            "algorithm" => parsed.algorithm = Some(decode_totp_algorithm(decoder)?),
            "digits" => parsed.digits = Some(decoder.u8().map_err(|_| AttemptError::Integrity)?),
            "period" => {
                parsed.period = Some(decoder.u16().map_err(|_| AttemptError::Integrity)?);
            }
            "t0" => parsed.t0 = Some(decoder.u64().map_err(|_| AttemptError::Integrity)?),
            "account" => {
                parsed.account = Some(
                    decoder
                        .str()
                        .map_err(|_| AttemptError::Integrity)?
                        .to_owned(),
                );
            }
            "private_format" => {
                parsed.private_format =
                    Some(match decoder.str().map_err(|_| AttemptError::Integrity)? {
                        "openssh" => PrivateKeyFormat::OpenSsh,
                        "pkcs8" => PrivateKeyFormat::Pkcs8,
                        _ => return Err(AttemptError::Integrity),
                    });
            }
            "private_key" => {
                parsed.private_key = Some(Zeroizing::new(
                    decoder
                        .bytes()
                        .map_err(|_| AttemptError::Integrity)?
                        .to_vec(),
                ));
            }
            "public_key" => {
                parsed.public_key = Some(
                    decoder
                        .bytes()
                        .map_err(|_| AttemptError::Integrity)?
                        .to_vec(),
                );
            }
            "passphrase" => {
                parsed.passphrase = DecodedPassphrase::Present(
                    if decoder.datatype().map_err(|_| AttemptError::Integrity)?
                        == minicbor::data::Type::Null
                    {
                        decoder.null().map_err(|_| AttemptError::Integrity)?;
                        None
                    } else {
                        Some(Zeroizing::new(
                            decoder
                                .bytes()
                                .map_err(|_| AttemptError::Integrity)?
                                .to_vec(),
                        ))
                    },
                );
            }
            _ => decoder.skip().map_err(|_| AttemptError::Integrity)?,
        }
    }
    Ok(parsed)
}

fn decode_totp_algorithm(decoder: &mut Decoder<'_>) -> Result<TotpAlgorithm, AttemptError> {
    match decoder.str().map_err(|_| AttemptError::Integrity)? {
        "SHA1" => Ok(TotpAlgorithm::Sha1),
        "SHA256" => Ok(TotpAlgorithm::Sha256),
        "SHA512" => Ok(TotpAlgorithm::Sha512),
        _ => Err(AttemptError::Integrity),
    }
}

fn credential_material(
    reconcile: bool,
    integration: &str,
    auth: &[u8],
    destination: &str,
    method: &str,
    now: i64,
) -> Result<CredentialMaterial, AttemptError> {
    if reconcile {
        Ok(CredentialMaterial::empty())
    } else if integration == "keycloak-token-exchange" {
        token_exchange_material(auth, destination, now)
    } else if integration == "keycloak-webauthn" || method == "webauthn" {
        Ok(CredentialMaterial {
            username: passkey_material(auth)?.user_name,
            password: Zeroizing::new(Vec::new()),
            subject_token: None,
            totp: None,
            ssh: None,
        })
    } else if integration == "github-rest-bearer" {
        github_token_material(auth, destination, now)
    } else {
        password_material(auth, method)
    }
}

fn matches_authentication_profile(kind: RecordKind, request: &StartAttempt) -> bool {
    let integration_profile = request.integration_version == 1
        && match request.integration_id.as_str() {
            "controlled.external" => kind == RecordKind::Password && request.method == "password",
            "keycloak-browser-oidc" => {
                kind == RecordKind::Password
                    && matches!(request.method.as_str(), "password" | "password_totp")
                    && request.context == request.destination.as_bytes()
            }
            "keycloak-token-exchange" => {
                request.method == "token_exchange"
                    && kind == RecordKind::Token
                    && request.context == request.destination.as_bytes()
            }
            "github-rest-bearer" => {
                request.method == "bearer"
                    && kind == RecordKind::Token
                    && request.destination == "github-assigned-issues/1"
                    && valid_github_context(&request.context)
            }
            _ => false,
        };
    let passkey_profile = kind == RecordKind::Passkey
        && request.method == "webauthn"
        && request.integration_version == 1
        && ((request.integration_id == "vault-webauthn-provider"
            && request.context == b"keycloak-webauthn/1")
            || (request.integration_id == "keycloak-webauthn" && is_profile_id(&request.context)));
    let ssh_profile = request.integration_version == 1
        && request.context == request.destination.as_bytes()
        && match (request.integration_id.as_str(), request.method.as_str()) {
            ("ssh-server" | "linux-system-ssh", "password") => kind == RecordKind::Password,
            ("ssh-server" | "linux-system-ssh", "publickey") => kind == RecordKind::Ssh,
            _ => false,
        };
    integration_profile || passkey_profile || ssh_profile
}

fn password_material(
    auth: &[u8],
    requested_method: &str,
) -> Result<CredentialMaterial, AttemptError> {
    let mut d = Decoder::new(auth);
    let n = d
        .array()
        .map_err(|_| AttemptError::Integrity)?
        .ok_or(AttemptError::Integrity)?;
    let mut username = None;
    let mut password = None;
    let mut totp = None;
    for _ in 0..n {
        let fields = d
            .map()
            .map_err(|_| AttemptError::Integrity)?
            .ok_or(AttemptError::Integrity)?;
        let decoded = decode_auth_method(&mut d, fields)?;
        if decoded.method.as_deref() == Some("password") {
            username = Some(decoded.username.ok_or(AttemptError::Integrity)?);
            password = Some(decoded.password.ok_or(AttemptError::Integrity)?);
        } else if decoded.method.as_deref() == Some("totp") {
            totp = Some((
                decoded.account.ok_or(AttemptError::Integrity)?,
                TotpLease {
                    secret: decoded.secret.ok_or(AttemptError::Integrity)?,
                    algorithm: decoded.algorithm.ok_or(AttemptError::Integrity)?,
                    digits: decoded.digits.ok_or(AttemptError::Integrity)?,
                    period: decoded.period.ok_or(AttemptError::Integrity)?,
                    t0: decoded.t0.ok_or(AttemptError::Integrity)?,
                },
            ));
        } else if decoded.method.as_deref() == Some("ssh") && requested_method == "publickey" {
            return Ok(CredentialMaterial {
                username: decoded.username.ok_or(AttemptError::Integrity)?,
                password: Zeroizing::new(Vec::new()),
                subject_token: None,
                totp: None,
                ssh: Some(SshLease {
                    private_format: decoded.private_format.ok_or(AttemptError::Integrity)?,
                    private_key: decoded.private_key.ok_or(AttemptError::Integrity)?,
                    public_key: decoded.public_key.ok_or(AttemptError::Integrity)?,
                    passphrase: match decoded.passphrase {
                        DecodedPassphrase::Present(value) => value,
                        DecodedPassphrase::Absent => return Err(AttemptError::Integrity),
                    },
                }),
            });
        }
    }
    let username = username.ok_or(AttemptError::CredentialUnavailable)?;
    let password = password.ok_or(AttemptError::CredentialUnavailable)?;
    let totp = if requested_method == "password_totp" {
        let (account, material) = totp.ok_or(AttemptError::CredentialUnavailable)?;
        if account != username {
            return Err(AttemptError::CredentialUnavailable);
        }
        Some(material)
    } else {
        None
    };
    Ok(CredentialMaterial {
        username,
        password,
        subject_token: None,
        totp,
        ssh: None,
    })
}

struct PasskeyMaterial {
    rp_id: String,
    credential_id: Vec<u8>,
    user_name: String,
}

fn is_profile_id(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn passkey_material(auth: &[u8]) -> Result<PasskeyMaterial, AttemptError> {
    let mut decoder = Decoder::new(auth);
    let count = decoder
        .array()
        .map_err(|_| AttemptError::Integrity)?
        .ok_or(AttemptError::Integrity)?;
    for _ in 0..count {
        let fields = decoder
            .map()
            .map_err(|_| AttemptError::Integrity)?
            .ok_or(AttemptError::Integrity)?;
        let mut method = None;
        let mut rp_id = None;
        let mut credential_id = None;
        let mut user_name = None;
        for _ in 0..fields {
            match decoder.str().map_err(|_| AttemptError::Integrity)? {
                "method" => {
                    method = Some(
                        decoder
                            .str()
                            .map_err(|_| AttemptError::Integrity)?
                            .to_owned(),
                    );
                }
                "rp_id" => {
                    rp_id = Some(
                        decoder
                            .str()
                            .map_err(|_| AttemptError::Integrity)?
                            .to_owned(),
                    );
                }
                "credential_id" => {
                    credential_id = Some(
                        decoder
                            .bytes()
                            .map_err(|_| AttemptError::Integrity)?
                            .to_vec(),
                    );
                }
                "user_name" => {
                    user_name = Some(
                        decoder
                            .str()
                            .map_err(|_| AttemptError::Integrity)?
                            .to_owned(),
                    );
                }
                _ => decoder.skip().map_err(|_| AttemptError::Integrity)?,
            }
        }
        if method.as_deref() == Some("passkey") {
            return Ok(PasskeyMaterial {
                rp_id: rp_id.ok_or(AttemptError::Integrity)?,
                credential_id: credential_id.ok_or(AttemptError::Integrity)?,
                user_name: user_name.ok_or(AttemptError::Integrity)?,
            });
        }
    }
    Err(AttemptError::CredentialUnavailable)
}

fn token_exchange_material(
    auth: &[u8],
    destination: &str,
    now: i64,
) -> Result<CredentialMaterial, AttemptError> {
    let mut decoder = Decoder::new(auth);
    if decoder.array().map_err(|_| AttemptError::Integrity)? != Some(1)
        || decoder.map().map_err(|_| AttemptError::Integrity)? != Some(8)
        || decoder.str().map_err(|_| AttemptError::Integrity)? != "method"
        || decoder.str().map_err(|_| AttemptError::Integrity)? != "token_exchange"
        || decoder.str().map_err(|_| AttemptError::Integrity)? != "subject_token"
    {
        return Err(AttemptError::Integrity);
    }
    let subject_token = Zeroizing::new(
        decoder
            .bytes()
            .map_err(|_| AttemptError::Integrity)?
            .to_vec(),
    );
    if decoder.str().map_err(|_| AttemptError::Integrity)? != "requester_client_id" {
        return Err(AttemptError::Integrity);
    }
    let requester_client_id = decoder
        .str()
        .map_err(|_| AttemptError::Integrity)?
        .to_owned();
    if decoder.str().map_err(|_| AttemptError::Integrity)? != "requester_client_secret" {
        return Err(AttemptError::Integrity);
    }
    let requester_client_secret = Zeroizing::new(
        decoder
            .bytes()
            .map_err(|_| AttemptError::Integrity)?
            .to_vec(),
    );
    if decoder.str().map_err(|_| AttemptError::Integrity)? != "provider"
        || decoder.str().map_err(|_| AttemptError::Integrity)? != "keycloak"
        || decoder.str().map_err(|_| AttemptError::Integrity)? != "profile_id"
        || decoder.str().map_err(|_| AttemptError::Integrity)? != destination
        || decoder.str().map_err(|_| AttemptError::Integrity)? != "destination_refs"
    {
        return Err(AttemptError::Integrity);
    }
    let refs = decoder
        .array()
        .map_err(|_| AttemptError::Integrity)?
        .ok_or(AttemptError::Integrity)?;
    for _ in 0..refs {
        decoder.u16().map_err(|_| AttemptError::Integrity)?;
    }
    if decoder.str().map_err(|_| AttemptError::Integrity)? != "expires_at" {
        return Err(AttemptError::Integrity);
    }
    let expires =
        if decoder.datatype().map_err(|_| AttemptError::Integrity)? == minicbor::data::Type::Null {
            decoder.null().map_err(|_| AttemptError::Integrity)?;
            None
        } else {
            Some(decoder.i64().map_err(|_| AttemptError::Integrity)?)
        };
    if decoder.position() != auth.len()
        || subject_token.is_empty()
        || requester_client_secret.is_empty()
        || expires.is_some_and(|value| value <= now)
    {
        return Err(AttemptError::CredentialUnavailable);
    }
    Ok(CredentialMaterial {
        username: requester_client_id,
        password: requester_client_secret,
        subject_token: Some(subject_token),
        totp: None,
        ssh: None,
    })
}

fn github_token_material(
    auth: &[u8],
    destination: &str,
    now: i64,
) -> Result<CredentialMaterial, AttemptError> {
    let mut decoder = Decoder::new(auth);
    if decoder.array().map_err(|_| AttemptError::Integrity)? != Some(1)
        || decoder.map().map_err(|_| AttemptError::Integrity)? != Some(6)
        || decoder.str().map_err(|_| AttemptError::Integrity)? != "method"
        || decoder.str().map_err(|_| AttemptError::Integrity)? != "token"
        || decoder.str().map_err(|_| AttemptError::Integrity)? != "secret"
    {
        return Err(AttemptError::Integrity);
    }
    let token = Zeroizing::new(
        decoder
            .bytes()
            .map_err(|_| AttemptError::Integrity)?
            .to_vec(),
    );
    if decoder.str().map_err(|_| AttemptError::Integrity)? != "provider"
        || decoder.str().map_err(|_| AttemptError::Integrity)? != "github"
        || decoder.str().map_err(|_| AttemptError::Integrity)? != "profile_id"
        || decoder.str().map_err(|_| AttemptError::Integrity)? != destination
        || decoder.str().map_err(|_| AttemptError::Integrity)? != "destination_refs"
    {
        return Err(AttemptError::Integrity);
    }
    let refs = decoder
        .array()
        .map_err(|_| AttemptError::Integrity)?
        .ok_or(AttemptError::Integrity)?;
    for _ in 0..refs {
        decoder.u16().map_err(|_| AttemptError::Integrity)?;
    }
    if decoder.str().map_err(|_| AttemptError::Integrity)? != "expires_at" {
        return Err(AttemptError::Integrity);
    }
    let expires =
        if decoder.datatype().map_err(|_| AttemptError::Integrity)? == minicbor::data::Type::Null {
            decoder.null().map_err(|_| AttemptError::Integrity)?;
            None
        } else {
            Some(decoder.i64().map_err(|_| AttemptError::Integrity)?)
        };
    if decoder.position() != auth.len()
        || token.is_empty()
        || token.len() > 1024
        || expires.is_some_and(|value| value <= now)
    {
        return Err(AttemptError::CredentialUnavailable);
    }
    Ok(CredentialMaterial {
        username: String::new(),
        password: Zeroizing::new(Vec::new()),
        subject_token: Some(token),
        totp: None,
        ssh: None,
    })
}

fn valid_github_context(context: &[u8]) -> bool {
    let Ok(value) = std::str::from_utf8(context) else {
        return false;
    };
    if !value.ends_with('\n') {
        return false;
    }
    let mut lines = value.lines();
    if lines.next() != Some("github-assigned-issues/1") {
        return false;
    }
    let Some(filter) = lines.next().and_then(|line| line.strip_prefix("filter=")) else {
        return false;
    };
    let Some(state) = lines.next().and_then(|line| line.strip_prefix("state=")) else {
        return false;
    };
    let Some(sort) = lines.next().and_then(|line| line.strip_prefix("sort=")) else {
        return false;
    };
    let Some(direction) = lines
        .next()
        .and_then(|line| line.strip_prefix("direction="))
    else {
        return false;
    };
    let Some(page) = lines.next().and_then(|line| line.strip_prefix("page=")) else {
        return false;
    };
    let Some(per_page) = lines.next().and_then(|line| line.strip_prefix("per_page=")) else {
        return false;
    };
    matches!(
        filter,
        "assigned" | "created" | "mentioned" | "subscribed" | "repos" | "all"
    ) && matches!(state, "open" | "closed" | "all")
        && matches!(sort, "created" | "updated" | "comments")
        && matches!(direction, "asc" | "desc")
        && page.parse::<u64>().is_ok_and(|value| value > 0)
        && per_page
            .parse::<u64>()
            .is_ok_and(|value| (1..=100).contains(&value))
        && lines.next().is_none()
}
fn load_owned(
    tx: &Transaction<'_>,
    custody: &AuditDeviceCustody,
    vault: [u8; 16],
    device: [u8; 16],
    generation: u64,
    owner: AgentIdentity,
    attempt: [u8; 16],
) -> Result<AttemptSnapshot, AttemptError> {
    let row:Option<(Option<Vec<u8>>,Vec<u8>,i64)>=tx.query_row("SELECT state_package,owner_subject,owner_generation FROM authentication_attempts WHERE attempt_id=?1",[attempt.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    let (p, s, g) = row.ok_or(AttemptError::NotFound)?;
    if fixed::<16>(&s)? != *owner.subject()
        || u64::try_from(g).map_err(|_| AttemptError::Integrity)? != owner.generation()
    {
        return Err(AttemptError::NotFound);
    }
    let p = p.ok_or(AttemptError::ResultExpired)?;
    decode_snapshot(&custody.open_attempt_state(&p, vault, device, generation, attempt)?)
}
#[allow(clippy::too_many_arguments)]
fn update_snapshot(
    tx: &Transaction<'_>,
    custody: &AuditDeviceCustody,
    vault: [u8; 16],
    device: [u8; 16],
    generation: u64,
    s: &AttemptSnapshot,
    execution: Option<(&str, &[u8], &str)>,
    now: i64,
) -> Result<(), AttemptError> {
    let old: Vec<u8> = tx.query_row(
        "SELECT state_package FROM authentication_attempts WHERE attempt_id=?1",
        [s.attempt_id.as_slice()],
        |r| r.get(0),
    )?;
    let old_plain = custody.open_attempt_state(&old, vault, device, generation, s.attempt_id)?;
    let owned;
    let exec = if let Some(v) = execution {
        Some(v)
    } else {
        owned = decode_execution(&old_plain)?;
        Some((owned.0.as_str(), owned.1.as_slice(), owned.2.as_str()))
    };
    let package = custody.update_attempt_state(
        &old,
        vault,
        device,
        generation,
        s.attempt_id,
        &encode_snapshot(s, exec),
    )?;
    tx.execute("UPDATE authentication_attempts SET state=?2,state_package=?3,terminal_at_us=?4,lease_token=NULL WHERE attempt_id=?1",params![s.attempt_id.as_slice(),s.state.name(),package,if s.state.terminal(){Some(now)}else{None}])?;
    Ok(())
}
fn purge_result_if_due(
    tx: &Transaction<'_>,
    s: &mut AttemptSnapshot,
    now: i64,
) -> Result<bool, AttemptError> {
    let terminal: Option<i64> = tx.query_row(
        "SELECT terminal_at_us FROM authentication_attempts WHERE attempt_id=?1",
        [s.attempt_id.as_slice()],
        |r| r.get(0),
    )?;
    if terminal.is_some_and(|v| now - v >= RESULT_LIFETIME_US) {
        s.result = None;
        tx.execute(
            "UPDATE authentication_attempts SET state_package=NULL WHERE attempt_id=?1",
            [s.attempt_id.as_slice()],
        )?;
        return Ok(true);
    }
    Ok(false)
}
#[allow(clippy::too_many_arguments)]
fn append_audit(
    tx: &Transaction<'_>,
    trusted: &TrustedRoot,
    device: [u8; 16],
    custody: &AuditDeviceCustody,
    s: &AttemptSnapshot,
    action: AuditAction,
    outcome: AuditOutcome,
    now: i64,
) -> Result<(), AttemptError> {
    let actor: Vec<u8> = tx.query_row(
        "SELECT owner_subject FROM authentication_attempts WHERE attempt_id=?1",
        [s.attempt_id.as_slice()],
        |row| row.get(0),
    )?;
    let event = AuditEvent::new(AuditActorKind::Agent, Some(fixed(&actor)?), action, outcome)
        .with_item(s.credential_id, Some(s.revision_id))
        .with_attempt(s.attempt_id);
    audit::append_event(
        tx,
        trusted,
        None,
        device,
        custody,
        &event,
        now,
        audit::current_frontier(tx)?,
    )?;
    Ok(())
}
