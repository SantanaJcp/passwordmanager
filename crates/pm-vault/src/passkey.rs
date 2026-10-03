// SPDX-License-Identifier: AGPL-3.0-only

//! Custodial `WebAuthn` request binding and human confirmation. Browser-facing
//! code transports these closed values; private credential seeds remain inside
//! encrypted logical records and are only used by [`HumanVault`].

use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use minicbor::{Decoder, Encoder};
use pm_crypto::digest;
use rusqlite::{Connection, OptionalExtension, params};

use crate::{AgentPeer, AttemptError, AttemptVault, AuthRecord, HumanCommitError, HumanVault};

const MAX_REQUEST: usize = 256 * 1024;
const REQUEST_LIFETIME_US: i64 = 5 * 60 * 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasskeyOperation {
    Create,
    Get,
}
impl PasskeyOperation {
    const fn name(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Get => "get",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserVerificationRequirement {
    Required,
    Preferred,
    Discouraged,
}
impl UserVerificationRequirement {
    const fn name(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Preferred => "preferred",
            Self::Discouraged => "discouraged",
        }
    }
    fn parse(value: &str) -> Result<Self, PasskeyError> {
        match value {
            "required" => Ok(Self::Required),
            "preferred" => Ok(Self::Preferred),
            "discouraged" => Ok(Self::Discouraged),
            _ => Err(PasskeyError::InvalidRequest),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanVerification {
    Presence,
    Verified,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasskeyRequest {
    request_id: [u8; 16],
    attempt_id: Option<[u8; 16]>,
    operation: PasskeyOperation,
    document_id: String,
    origin: String,
    rp_id: String,
    challenge: Vec<u8>,
    credential_ids: Vec<Vec<u8>>,
    user_handle: Vec<u8>,
    user_name: String,
    display_name: String,
    uv: UserVerificationRequirement,
}

impl PasskeyRequest {
    /// Constructs a closed registration request bound to one browser document.
    ///
    /// # Errors
    /// Rejects malformed identifiers, origins, challenges, or user fields.
    #[allow(clippy::too_many_arguments)]
    pub fn registration(
        request_id: [u8; 16],
        document_id: &str,
        origin: &str,
        rp_id: &str,
        challenge: &[u8],
        user_handle: &[u8],
        user_name: &str,
        display_name: &str,
        uv: UserVerificationRequirement,
    ) -> Result<Self, PasskeyError> {
        let value = Self {
            request_id,
            attempt_id: None,
            operation: PasskeyOperation::Create,
            document_id: document_id.to_owned(),
            origin: origin.to_owned(),
            rp_id: rp_id.to_owned(),
            challenge: challenge.to_vec(),
            credential_ids: Vec::new(),
            user_handle: user_handle.to_vec(),
            user_name: user_name.to_owned(),
            display_name: display_name.to_owned(),
            uv,
        };
        value.validate()?;
        Ok(value)
    }

    /// Constructs an assertion request bound to one admitted attempt.
    ///
    /// # Errors
    /// Rejects malformed identifiers, origins, challenges, or credential lists.
    #[allow(clippy::too_many_arguments)]
    pub fn assertion(
        request_id: [u8; 16],
        attempt_id: [u8; 16],
        document_id: &str,
        origin: &str,
        rp_id: &str,
        challenge: &[u8],
        credential_ids: Vec<Vec<u8>>,
        uv: UserVerificationRequirement,
    ) -> Result<Self, PasskeyError> {
        let value = Self {
            request_id,
            attempt_id: Some(attempt_id),
            operation: PasskeyOperation::Get,
            document_id: document_id.to_owned(),
            origin: origin.to_owned(),
            rp_id: rp_id.to_owned(),
            challenge: challenge.to_vec(),
            credential_ids,
            user_handle: Vec::new(),
            user_name: String::new(),
            display_name: String::new(),
            uv,
        };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub const fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }
    #[must_use]
    pub const fn attempt_id(&self) -> Option<&[u8; 16]> {
        self.attempt_id.as_ref()
    }
    #[must_use]
    pub const fn operation(&self) -> PasskeyOperation {
        self.operation
    }
    #[must_use]
    pub fn document_id(&self) -> &str {
        &self.document_id
    }
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
    #[must_use]
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }
    #[must_use]
    pub fn challenge(&self) -> &[u8] {
        &self.challenge
    }
    #[must_use]
    pub fn credential_ids(&self) -> &[Vec<u8>] {
        &self.credential_ids
    }
    #[must_use]
    pub fn user_handle(&self) -> &[u8] {
        &self.user_handle
    }
    #[must_use]
    pub fn user_name(&self) -> &str {
        &self.user_name
    }
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
    #[must_use]
    pub const fn user_verification(&self) -> UserVerificationRequirement {
        self.uv
    }

    /// Encodes the validated request in its canonical internal wire form.
    ///
    /// # Panics
    /// A vector length cannot exceed the canonical encoder's `u64` bound on
    /// supported targets; writes to an in-memory `Vec` are infallible.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(13)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&self.request_id)
            .unwrap();
        match self.attempt_id {
            Some(value) => e.bytes(&value).unwrap(),
            None => e.null().unwrap(),
        };
        e.str(self.operation.name())
            .unwrap()
            .str(&self.document_id)
            .unwrap()
            .str(&self.origin)
            .unwrap()
            .str(&self.rp_id)
            .unwrap()
            .bytes(&self.challenge)
            .unwrap();
        e.array(u64::try_from(self.credential_ids.len()).unwrap())
            .unwrap();
        for value in &self.credential_ids {
            e.bytes(value).unwrap();
        }
        e.bytes(&self.user_handle)
            .unwrap()
            .str(&self.user_name)
            .unwrap()
            .str(&self.display_name)
            .unwrap()
            .str(self.uv.name())
            .unwrap();
        e.into_writer()
    }

    /// Decodes and revalidates one canonical internal wire request.
    ///
    /// # Errors
    /// Rejects malformed, non-canonical, oversized, or unknown request shapes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PasskeyError> {
        if bytes.len() > MAX_REQUEST {
            return Err(PasskeyError::InvalidRequest);
        }
        let mut d = Decoder::new(bytes);
        if d.array().map_err(invalid)? != Some(13) || d.u8().map_err(invalid)? != 1 {
            return Err(PasskeyError::InvalidRequest);
        }
        let request_id = fixed(d.bytes().map_err(invalid)?)?;
        let attempt_id = if d.datatype().map_err(invalid)? == minicbor::data::Type::Null {
            d.null().map_err(invalid)?;
            None
        } else {
            Some(fixed(d.bytes().map_err(invalid)?)?)
        };
        let operation = match d.str().map_err(invalid)? {
            "create" => PasskeyOperation::Create,
            "get" => PasskeyOperation::Get,
            _ => return Err(PasskeyError::InvalidRequest),
        };
        let document_id = d.str().map_err(invalid)?.to_owned();
        let origin = d.str().map_err(invalid)?.to_owned();
        let rp_id = d.str().map_err(invalid)?.to_owned();
        let challenge = d.bytes().map_err(invalid)?.to_vec();
        let count = d
            .array()
            .map_err(invalid)?
            .ok_or(PasskeyError::InvalidRequest)?;
        if count > 64 {
            return Err(PasskeyError::InvalidRequest);
        }
        let mut credential_ids =
            Vec::with_capacity(usize::try_from(count).map_err(|_| PasskeyError::InvalidRequest)?);
        for _ in 0..count {
            credential_ids.push(d.bytes().map_err(invalid)?.to_vec());
        }
        let value = Self {
            request_id,
            attempt_id,
            operation,
            document_id,
            origin,
            rp_id,
            challenge,
            credential_ids,
            user_handle: d.bytes().map_err(invalid)?.to_vec(),
            user_name: d.str().map_err(invalid)?.to_owned(),
            display_name: d.str().map_err(invalid)?.to_owned(),
            uv: UserVerificationRequirement::parse(d.str().map_err(invalid)?)?,
        };
        if d.position() != bytes.len() || value.to_bytes() != bytes {
            return Err(PasskeyError::InvalidRequest);
        }
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), PasskeyError> {
        let origin_host = self
            .origin
            .strip_prefix("https://")
            .filter(|value| !value.is_empty() && !value.contains(['/', '@', '#', '?']))
            .ok_or(PasskeyError::InvalidRequest)?;
        let host = origin_host
            .split_once(':')
            .map_or(origin_host, |value| value.0);
        let common = self.request_id != [0; 16]
            && (1..=256).contains(&self.document_id.len())
            && self
                .document_id
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'-' | b'_'))
            && (16..=64).contains(&self.challenge.len())
            && (1..=253).contains(&self.rp_id.len())
            && self
                .rp_id
                .bytes()
                .all(|v| v.is_ascii_lowercase() || v.is_ascii_digit() || matches!(v, b'.' | b'-'))
            && host == self.rp_id;
        let shape = match self.operation {
            PasskeyOperation::Create => {
                self.attempt_id.is_none()
                    && self.credential_ids.is_empty()
                    && (1..=64).contains(&self.user_handle.len())
                    && (1..=1024).contains(&self.user_name.len())
                    && (1..=1024).contains(&self.display_name.len())
            }
            PasskeyOperation::Get => {
                self.attempt_id.is_some_and(|v| v != [0; 16])
                    && (1..=64).contains(&self.credential_ids.len())
                    && self
                        .credential_ids
                        .iter()
                        .all(|v| (1..=1024).contains(&v.len()))
                    && self.user_handle.is_empty()
                    && self.user_name.is_empty()
                    && self.display_name.is_empty()
            }
        };
        if !common || !shape || self.to_bytes().len() > MAX_REQUEST {
            return Err(PasskeyError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasskeyPrompt {
    operation: PasskeyOperation,
    request_id: [u8; 16],
    rp_id: String,
    account: String,
    origin: String,
    document_id: String,
    uv: UserVerificationRequirement,
}
impl PasskeyPrompt {
    #[must_use]
    pub const fn operation(&self) -> PasskeyOperation {
        self.operation
    }
    #[must_use]
    pub const fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }
    #[must_use]
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
    #[must_use]
    pub fn document_id(&self) -> &str {
        &self.document_id
    }
    #[must_use]
    pub const fn user_verification(&self) -> UserVerificationRequirement {
        self.uv
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasskeyPublicCredential {
    credential_id: Vec<u8>,
    rp_id: String,
    user_handle: Vec<u8>,
    public_key: [u8; 32],
    user_name: String,
    display_name: String,
    backup_eligible: bool,
    backup_state: bool,
    client_data_json: Vec<u8>,
}
impl PasskeyPublicCredential {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        credential_id: Vec<u8>,
        rp_id: String,
        user_handle: Vec<u8>,
        public_key: [u8; 32],
        user_name: String,
        display_name: String,
        backup_eligible: bool,
        backup_state: bool,
        client_data_json: Vec<u8>,
    ) -> Self {
        Self {
            credential_id,
            rp_id,
            user_handle,
            public_key,
            user_name,
            display_name,
            backup_eligible,
            backup_state,
            client_data_json,
        }
    }
    #[must_use]
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }
    #[must_use]
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }
    #[must_use]
    pub fn user_handle(&self) -> &[u8] {
        &self.user_handle
    }
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
    #[must_use]
    pub fn user_name(&self) -> &str {
        &self.user_name
    }
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
    #[must_use]
    pub const fn cose_algorithm(&self) -> i64 {
        -8
    }
    #[must_use]
    pub const fn sign_count(&self) -> u32 {
        0
    }
    #[must_use]
    pub const fn backup_eligible(&self) -> bool {
        self.backup_eligible
    }
    #[must_use]
    pub const fn backup_state(&self) -> bool {
        self.backup_state
    }

    /// Browser registration client data, bound to the challenge and origin
    /// that caused this credential to be created.
    #[must_use]
    pub fn client_data_json(&self) -> &[u8] {
        &self.client_data_json
    }

    /// Produces the `WebAuthn` `none` attestation for this custodial credential.
    /// The private key is neither needed nor exposed by this public response.
    ///
    /// # Panics
    /// Panics only if an internally constructed credential bypassed the
    /// validated 1,024-byte credential-ID limit.
    #[must_use]
    pub fn attestation_object(&self) -> Vec<u8> {
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&digest(self.rp_id.as_bytes()));
        // UP, UV, BE and AT. BS remains false, matching the stored credential.
        auth_data.push(0x4d);
        auth_data.extend_from_slice(&0_u32.to_be_bytes());
        auth_data.extend_from_slice(&[0; 16]);
        auth_data.extend_from_slice(
            &u16::try_from(self.credential_id.len())
                .expect("validated credential ID fits WebAuthn")
                .to_be_bytes(),
        );
        auth_data.extend_from_slice(&self.credential_id);
        let mut cose = Encoder::new(Vec::new());
        cose.map(4)
            .unwrap()
            .i8(1)
            .unwrap()
            .i8(1)
            .unwrap()
            .i8(3)
            .unwrap()
            .i8(-8)
            .unwrap()
            .i8(-1)
            .unwrap()
            .i8(6)
            .unwrap()
            .i8(-2)
            .unwrap()
            .bytes(&self.public_key)
            .unwrap();
        auth_data.extend_from_slice(&cose.into_writer());
        let mut attestation = Encoder::new(Vec::new());
        attestation
            .map(3)
            .unwrap()
            .str("fmt")
            .unwrap()
            .str("none")
            .unwrap()
            .str("attStmt")
            .unwrap()
            .map(0)
            .unwrap()
            .str("authData")
            .unwrap()
            .bytes(&auth_data)
            .unwrap();
        attestation.into_writer()
    }
}

pub struct PreparedPasskeyRegistration {
    pub(crate) prepared: crate::PreparedHumanCommand,
    pub(crate) public: PasskeyPublicCredential,
}
impl PreparedPasskeyRegistration {
    #[must_use]
    pub const fn prepared(&self) -> &crate::PreparedHumanCommand {
        &self.prepared
    }
    #[must_use]
    pub const fn public(&self) -> &PasskeyPublicCredential {
        &self.public
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasskeyAssertion {
    credential_id: Vec<u8>,
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature: [u8; 64],
    user_handle: Vec<u8>,
    signed_message: Vec<u8>,
}
impl PasskeyAssertion {
    pub(crate) fn new(
        credential_id: Vec<u8>,
        authenticator_data: Vec<u8>,
        client_data_json: Vec<u8>,
        signature: [u8; 64],
        user_handle: Vec<u8>,
        signed_message: Vec<u8>,
    ) -> Self {
        Self {
            credential_id,
            authenticator_data,
            client_data_json,
            signature,
            user_handle,
            signed_message,
        }
    }
    #[must_use]
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }
    #[must_use]
    pub fn authenticator_data(&self) -> &[u8] {
        &self.authenticator_data
    }
    #[must_use]
    pub fn client_data_json(&self) -> &[u8] {
        &self.client_data_json
    }
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
    #[must_use]
    pub fn user_handle(&self) -> &[u8] {
        &self.user_handle
    }
    #[must_use]
    pub fn signed_message(&self) -> &[u8] {
        &self.signed_message
    }
    #[must_use]
    pub fn user_present(&self) -> bool {
        self.authenticator_data.get(32).is_some_and(|v| v & 1 != 0)
    }
    #[must_use]
    pub fn user_verified(&self) -> bool {
        self.authenticator_data.get(32).is_some_and(|v| v & 4 != 0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PasskeyStatus {
    Waiting(PasskeyPrompt),
    Registration(PasskeyPublicCredential),
    Assertion(PasskeyAssertion),
}

impl PasskeyStatus {
    /// Encodes the bounded provider response for the authenticated bridge.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_status(self)
    }

    /// Decodes a canonical bounded provider response.
    ///
    /// # Errors
    /// Rejects malformed, non-canonical, or unknown response shapes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PasskeyError> {
        decode_status(bytes)
    }
}

#[derive(Debug)]
pub enum PasskeyError {
    InvalidRequest,
    IdempotencyConflict,
    HumanRequired,
    UserVerificationRequired,
    Revoked,
    Expired,
    NotFound,
    Integrity,
    Storage(rusqlite::Error),
    Attempt(AttemptError),
    Human(HumanCommitError),
}
impl fmt::Display for PasskeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::IdempotencyConflict => "IDEMPOTENCY_CONFLICT",
            Self::HumanRequired => "HUMAN_ACTION_REQUIRED",
            Self::UserVerificationRequired => "USER_VERIFICATION_REQUIRED",
            Self::Revoked => "REVOKED",
            Self::Expired => "EXPIRED",
            Self::NotFound => "NOT_FOUND",
            Self::Integrity => "INTEGRITY",
            Self::Storage(_) => "STORAGE",
            Self::Attempt(_) => "ATTEMPT",
            Self::Human(_) => "CUSTODY_UNAVAILABLE",
        })
    }
}
impl std::error::Error for PasskeyError {}
impl From<rusqlite::Error> for PasskeyError {
    fn from(v: rusqlite::Error) -> Self {
        Self::Storage(v)
    }
}
impl From<AttemptError> for PasskeyError {
    fn from(v: AttemptError) -> Self {
        match v {
            AttemptError::AgentRevoked
            | AttemptError::AccessSuspended
            | AttemptError::CredentialUnavailable => Self::Revoked,
            AttemptError::NotFound => Self::NotFound,
            AttemptError::ResultExpired => Self::Expired,
            other => Self::Attempt(other),
        }
    }
}
impl From<HumanCommitError> for PasskeyError {
    fn from(v: HumanCommitError) -> Self {
        Self::Human(v)
    }
}

pub struct PasskeyProvider {
    attempts: AttemptVault,
}
impl PasskeyProvider {
    /// Attaches the provider to the existing durable attempt vault.
    ///
    /// # Errors
    /// Reserved for failure-compatible construction as custody evolves.
    pub fn open(attempts: AttemptVault) -> Result<Self, PasskeyError> {
        Ok(Self { attempts })
    }
    #[must_use]
    pub const fn attempts(&self) -> &AttemptVault {
        &self.attempts
    }

    /// Begins or idempotently replays one bounded provider request.
    ///
    /// # Errors
    /// Rejects invalid/conflicting requests and unavailable encrypted state.
    pub fn begin(&self, request: &PasskeyRequest) -> Result<PasskeyStatus, PasskeyError> {
        request.validate()?;
        let bytes = request.to_bytes();
        let request_digest = digest(&bytes);
        let connection = Connection::open(self.attempts.path())?;
        crate::configure_platform_durability(&connection)?;
        if let Some((stored, response)) = connection
            .query_row(
                "SELECT request_digest,response FROM passkey_requests WHERE request_id=?1",
                [request.request_id.as_slice()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
            )
            .optional()?
        {
            if stored.as_slice() != request_digest {
                return Err(PasskeyError::IdempotencyConflict);
            }
            let response = self.attempts.open_passkey_blob(
                request.request_id,
                &response.ok_or(PasskeyError::Integrity)?,
            )?;
            return decode_status(&response);
        }
        if request.operation == PasskeyOperation::Get {
            return self.attempts.begin_passkey(request);
        }
        let now = now_us()?;
        let request_package = self
            .attempts
            .seal_passkey_blob(request.request_id, &bytes)?;
        let waiting = PasskeyStatus::Waiting(prompt(request));
        let waiting_package = self
            .attempts
            .seal_passkey_blob(request.request_id, &encode_status(&waiting))?;
        connection.execute(
            "INSERT INTO passkey_requests(request_id,request_digest,operation,attempt_id,request,state,item_id,response,created_at_us,expires_at_us) VALUES(?1,?2,'create',NULL,?3,'waiting',NULL,?4,?5,?6)",
            params![request.request_id.as_slice(),request_digest.as_slice(),request_package,waiting_package,now,now+REQUEST_LIFETIME_US],
        )?;
        Ok(waiting)
    }

    /// Begins or replays a browser request while binding assertion attempts to
    /// the authenticated agent RPK that created them.
    ///
    /// # Errors
    /// Rejects cross-agent attempt IDs and any normal provider error.
    pub fn begin_for_peer(
        &self,
        peer: &AgentPeer,
        request: &PasskeyRequest,
    ) -> Result<PasskeyStatus, PasskeyError> {
        if let Some(attempt) = request.attempt_id() {
            self.attempts.get(peer, *attempt)?;
        } else {
            self.attempts.validate_peer(peer)?;
        }
        self.begin(request)
    }

    /// Records the public registration response after its signed human commit.
    ///
    /// # Errors
    /// Rejects expired, unverified, mismatched, or unavailable durable state.
    pub fn complete_registration(
        &self,
        human: &HumanVault,
        request_id: [u8; 16],
        item: [u8; 16],
        public: &PasskeyPublicCredential,
        verification: HumanVerification,
    ) -> Result<PasskeyStatus, PasskeyError> {
        let mut connection = Connection::open(self.attempts.path())?;
        crate::configure_platform_durability(&connection)?;
        let tx = connection.transaction()?;
        let (request_bytes, state, expires): (Vec<u8>, String, i64) = tx
            .query_row(
                "SELECT request,state,expires_at_us FROM passkey_requests WHERE request_id=?1",
                [request_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or(PasskeyError::NotFound)?;
        let request_plain = self
            .attempts
            .open_passkey_blob(request_id, &request_bytes)?;
        let request = PasskeyRequest::from_bytes(&request_plain)?;
        if state == "complete" {
            return self.response(request_id)?.ok_or(PasskeyError::Integrity);
        }
        if now_us()? >= expires {
            return Err(PasskeyError::Expired);
        }
        require_verification(request.uv, verification)?;
        if request.operation != PasskeyOperation::Create
            || public.rp_id != request.rp_id
            || public.user_handle != request.user_handle
            || public.user_name != request.user_name
            || public.display_name != request.display_name
        {
            return Err(PasskeyError::InvalidRequest);
        }
        let record = human.read_record(item)?;
        let [
            AuthRecord::Passkey {
                rp_id,
                user_handle,
                credential_id,
                cose_alg,
                public_key,
                user_name,
                display_name,
                sign_count,
                backup_eligible,
                backup_state,
                ..
            },
        ] = record.auth()
        else {
            return Err(PasskeyError::Integrity);
        };
        if rp_id != public.rp_id()
            || user_handle != public.user_handle()
            || credential_id != public.credential_id()
            || *cose_alg != -8
            || public_key != public.public_key()
            || user_name != public.user_name()
            || display_name != public.display_name()
            || *sign_count != 0
            || *backup_eligible != public.backup_eligible
            || *backup_state != public.backup_state
        {
            return Err(PasskeyError::Integrity);
        }
        let result = PasskeyStatus::Registration(public.clone());
        let encoded = encode_status(&result);
        let encoded = self.attempts.seal_passkey_blob(request_id, &encoded)?;
        tx.execute("UPDATE passkey_requests SET state='complete',item_id=?2,response=?3 WHERE request_id=?1 AND state='waiting'",
            params![request_id.as_slice(),item.as_slice(),encoded])?;
        tx.commit()?;
        Ok(result)
    }

    /// Confirms one assertion with fresh human presence or verification.
    ///
    /// # Errors
    /// Rejects insufficient verification, revoked authority, or corrupt state.
    pub fn confirm_assertion(
        &self,
        human: &HumanVault,
        request_id: [u8; 16],
        verification: HumanVerification,
    ) -> Result<PasskeyStatus, PasskeyError> {
        self.attempts
            .confirm_passkey(human, request_id, verification)
    }
    /// Reads a completed public response, or `None` while it is pending.
    ///
    /// # Errors
    /// Rejects corrupt or unavailable encrypted provider state.
    pub fn response(&self, request_id: [u8; 16]) -> Result<Option<PasskeyStatus>, PasskeyError> {
        let connection = Connection::open(self.attempts.path())?;
        crate::configure_platform_durability(&connection)?;
        let row: Option<(String, Option<Vec<u8>>)> = connection
            .query_row(
                "SELECT state,response FROM passkey_requests WHERE request_id=?1",
                [request_id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match row {
            Some((state, response)) if state == "complete" => {
                let response = self
                    .attempts
                    .open_passkey_blob(request_id, &response.ok_or(PasskeyError::Integrity)?)?;
                Ok(Some(decode_status(&response)?))
            }
            None | Some(_) => Ok(None),
        }
    }

    /// Opens one still-pending request for display on the authenticated human
    /// confirmation surface. Request bytes remain encrypted at rest under the
    /// device attempt key.
    ///
    /// # Errors
    /// Returns an error for expired or corrupt persisted state.
    pub fn pending_request(
        &self,
        request_id: [u8; 16],
    ) -> Result<Option<PasskeyRequest>, PasskeyError> {
        let connection = Connection::open(self.attempts.path())?;
        crate::configure_platform_durability(&connection)?;
        let row: Option<(Vec<u8>, String, i64)> = connection
            .query_row(
                "SELECT request,state,expires_at_us FROM passkey_requests WHERE request_id=?1",
                [request_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((package, state, expires)) = row else {
            return Ok(None);
        };
        if state != "waiting" {
            return Ok(None);
        }
        if now_us()? >= expires {
            return Err(PasskeyError::Expired);
        }
        let bytes = self.attempts.open_passkey_blob(request_id, &package)?;
        Ok(Some(PasskeyRequest::from_bytes(&bytes)?))
    }

    /// Retrieves the encrypted-at-rest display prompt for a pending human
    /// confirmation without exposing credential key material.
    ///
    /// # Errors
    /// Returns an error for expired or corrupt persisted state.
    pub fn pending_prompt(
        &self,
        request_id: [u8; 16],
    ) -> Result<Option<PasskeyPrompt>, PasskeyError> {
        let connection = Connection::open(self.attempts.path())?;
        crate::configure_platform_durability(&connection)?;
        let row: Option<(Vec<u8>, String, i64)> = connection
            .query_row(
                "SELECT response,state,expires_at_us FROM passkey_requests WHERE request_id=?1",
                [request_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((package, state, expires)) = row else {
            return Ok(None);
        };
        if state != "waiting" {
            return Ok(None);
        }
        if now_us()? >= expires {
            return Err(PasskeyError::Expired);
        }
        let bytes = self.attempts.open_passkey_blob(request_id, &package)?;
        match decode_status(&bytes)? {
            PasskeyStatus::Waiting(prompt) => Ok(Some(prompt)),
            _ => Err(PasskeyError::Integrity),
        }
    }

    /// Returns the opaque vault item created by a completed registration so a
    /// separate explicit human action can enable delegated use.
    ///
    /// # Errors
    /// Rejects incomplete, non-registration, or corrupt request state.
    pub fn registered_item(&self, request_id: [u8; 16]) -> Result<[u8; 16], PasskeyError> {
        let connection = Connection::open(self.attempts.path())?;
        crate::configure_platform_durability(&connection)?;
        let row: Option<(String, String, Option<Vec<u8>>)> = connection
            .query_row(
                "SELECT operation,state,item_id FROM passkey_requests WHERE request_id=?1",
                [request_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((operation, state, item)) = row else {
            return Err(PasskeyError::NotFound);
        };
        if operation != "create" || state != "complete" {
            return Err(PasskeyError::HumanRequired);
        }
        fixed(&item.ok_or(PasskeyError::Integrity)?)
    }

    /// Retrieves a response only for the RPK-bound owner and rechecks current
    /// revocation/suspension state before releasing an assertion.
    ///
    /// # Errors
    /// Rejects unknown, expired, cross-agent, or currently unauthorized attempts.
    pub fn response_for_peer(
        &self,
        peer: &AgentPeer,
        request_id: [u8; 16],
    ) -> Result<Option<PasskeyStatus>, PasskeyError> {
        let connection = Connection::open(self.attempts.path())?;
        crate::configure_platform_durability(&connection)?;
        let attempt: Option<Option<Vec<u8>>> = connection
            .query_row(
                "SELECT attempt_id FROM passkey_requests WHERE request_id=?1",
                [request_id.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(attempt) = attempt.flatten() {
            self.attempts.get(peer, fixed(&attempt)?)?;
        }
        self.response(request_id)
    }
}

pub(crate) fn require_verification(
    requirement: UserVerificationRequirement,
    verification: HumanVerification,
) -> Result<(), PasskeyError> {
    if requirement == UserVerificationRequirement::Required
        && verification != HumanVerification::Verified
    {
        Err(PasskeyError::UserVerificationRequired)
    } else {
        Ok(())
    }
}
pub(crate) fn prompt(request: &PasskeyRequest) -> PasskeyPrompt {
    PasskeyPrompt {
        operation: request.operation,
        request_id: request.request_id,
        rp_id: request.rp_id.clone(),
        account: request.user_name.clone(),
        origin: request.origin.clone(),
        document_id: request.document_id.clone(),
        uv: request.uv,
    }
}

pub(crate) fn prompt_for_account(request: &PasskeyRequest, account: &str) -> PasskeyPrompt {
    let mut value = prompt(request);
    account.clone_into(&mut value.account);
    value
}

pub(crate) fn client_data_json(request: &PasskeyRequest) -> Vec<u8> {
    format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{}\",\"crossOrigin\":false}}",
        base64url(request.challenge()),
        request.origin()
    )
    .into_bytes()
}

pub(crate) fn registration_client_data_json(request: &PasskeyRequest) -> Vec<u8> {
    format!(
        "{{\"type\":\"webauthn.create\",\"challenge\":\"{}\",\"origin\":\"{}\",\"crossOrigin\":false}}",
        base64url(request.challenge()),
        request.origin()
    )
    .into_bytes()
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let value = u32::from(chunk[0]) << 16
            | u32::from(*chunk.get(1).unwrap_or(&0)) << 8
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(char::from(ALPHABET[((value >> 18) & 63) as usize]));
        output.push(char::from(ALPHABET[((value >> 12) & 63) as usize]));
        if chunk.len() > 1 {
            output.push(char::from(ALPHABET[((value >> 6) & 63) as usize]));
        }
        if chunk.len() > 2 {
            output.push(char::from(ALPHABET[(value & 63) as usize]));
        }
    }
    output
}

pub(crate) fn encode_status(value: &PasskeyStatus) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    match value {
        PasskeyStatus::Registration(v) => {
            e.array(11)
                .unwrap()
                .u8(1)
                .unwrap()
                .str("registration")
                .unwrap()
                .bytes(&v.credential_id)
                .unwrap()
                .str(&v.rp_id)
                .unwrap()
                .bytes(&v.user_handle)
                .unwrap()
                .bytes(&v.public_key)
                .unwrap()
                .str(&v.user_name)
                .unwrap()
                .str(&v.display_name)
                .unwrap()
                .bool(v.backup_eligible)
                .unwrap()
                .bool(v.backup_state)
                .unwrap()
                .bytes(&v.client_data_json)
                .unwrap();
        }
        PasskeyStatus::Assertion(v) => {
            e.array(8)
                .unwrap()
                .u8(1)
                .unwrap()
                .str("assertion")
                .unwrap()
                .bytes(&v.credential_id)
                .unwrap()
                .bytes(&v.authenticator_data)
                .unwrap()
                .bytes(&v.client_data_json)
                .unwrap()
                .bytes(&v.signature)
                .unwrap()
                .bytes(&v.user_handle)
                .unwrap()
                .bytes(&v.signed_message)
                .unwrap();
        }
        PasskeyStatus::Waiting(v) => {
            e.array(9)
                .unwrap()
                .u8(1)
                .unwrap()
                .str("waiting")
                .unwrap()
                .str(v.operation.name())
                .unwrap()
                .bytes(&v.request_id)
                .unwrap()
                .str(&v.rp_id)
                .unwrap()
                .str(&v.account)
                .unwrap()
                .str(&v.origin)
                .unwrap()
                .str(&v.document_id)
                .unwrap()
                .str(v.uv.name())
                .unwrap();
        }
    }
    e.into_writer()
}
pub(crate) fn decode_status(bytes: &[u8]) -> Result<PasskeyStatus, PasskeyError> {
    let mut d = Decoder::new(bytes);
    let len = d.array().map_err(invalid)?.ok_or(PasskeyError::Integrity)?;
    if d.u8().map_err(invalid)? != 1 {
        return Err(PasskeyError::Integrity);
    }
    let kind = d.str().map_err(invalid)?;
    let result = match (len, kind) {
        (9, "waiting") => PasskeyStatus::Waiting(PasskeyPrompt {
            operation: match d.str().map_err(invalid)? {
                "create" => PasskeyOperation::Create,
                "get" => PasskeyOperation::Get,
                _ => return Err(PasskeyError::Integrity),
            },
            request_id: fixed(d.bytes().map_err(invalid)?)?,
            rp_id: d.str().map_err(invalid)?.to_owned(),
            account: d.str().map_err(invalid)?.to_owned(),
            origin: d.str().map_err(invalid)?.to_owned(),
            document_id: d.str().map_err(invalid)?.to_owned(),
            uv: UserVerificationRequirement::parse(d.str().map_err(invalid)?)?,
        }),
        (11, "registration") => PasskeyStatus::Registration(PasskeyPublicCredential {
            credential_id: d.bytes().map_err(invalid)?.to_vec(),
            rp_id: d.str().map_err(invalid)?.to_owned(),
            user_handle: d.bytes().map_err(invalid)?.to_vec(),
            public_key: fixed(d.bytes().map_err(invalid)?)?,
            user_name: d.str().map_err(invalid)?.to_owned(),
            display_name: d.str().map_err(invalid)?.to_owned(),
            backup_eligible: d.bool().map_err(invalid)?,
            backup_state: d.bool().map_err(invalid)?,
            client_data_json: d.bytes().map_err(invalid)?.to_vec(),
        }),
        (8, "assertion") => PasskeyStatus::Assertion(PasskeyAssertion {
            credential_id: d.bytes().map_err(invalid)?.to_vec(),
            authenticator_data: d.bytes().map_err(invalid)?.to_vec(),
            client_data_json: d.bytes().map_err(invalid)?.to_vec(),
            signature: fixed(d.bytes().map_err(invalid)?)?,
            user_handle: d.bytes().map_err(invalid)?.to_vec(),
            signed_message: d.bytes().map_err(invalid)?.to_vec(),
        }),
        _ => return Err(PasskeyError::Integrity),
    };
    if d.position() != bytes.len() || encode_status(&result) != bytes {
        return Err(PasskeyError::Integrity);
    }
    Ok(result)
}

fn now_us() -> Result<i64, PasskeyError> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PasskeyError::Integrity)?
            .as_micros(),
    )
    .map_err(|_| PasskeyError::Integrity)
}
fn fixed<const N: usize>(value: &[u8]) -> Result<[u8; N], PasskeyError> {
    value.try_into().map_err(|_| PasskeyError::InvalidRequest)
}
fn invalid<T>(_: T) -> PasskeyError {
    PasskeyError::InvalidRequest
}
