// SPDX-License-Identifier: AGPL-3.0-only

use std::{fmt, str::FromStr, sync::OnceLock};

use minicbor::{Decoder, Encoder, data::Type};

const KEY_BYTES: usize = 32;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const ID_BYTES: usize = 16;
const FORMAT_VERSION: u64 = 1;
const SUITE: u64 = 1;
const MAX_OBJECT_BYTES: usize = 16 * 1024 * 1024;
const MAX_HEADER_BYTES: usize = 4 * 1024;

/// Errors exposed by the typed cryptographic boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    Authentication,
    InvalidFormat,
    InvalidKdf,
    InvalidPassword,
    RandomUnavailable,
    ResourceUnavailable,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Authentication => "authentication failed",
            Self::InvalidFormat => "invalid or incompatible vault format",
            Self::InvalidKdf => "invalid password derivation parameters",
            Self::InvalidPassword => "password must be 1 to 1024 UTF-8 bytes",
            Self::RandomUnavailable => "cryptographic random source unavailable",
            Self::ResourceUnavailable => "password derivation resource unavailable",
        })
    }
}

impl std::error::Error for CryptoError {}

/// Validated Argon2id v1.3 parameters. Lanes are fixed to one by libsodium.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KdfProfile {
    memory_mib: u64,
    passes: u64,
}

impl KdfProfile {
    pub const DEFAULT: Self = Self {
        memory_mib: 256,
        passes: 3,
    };

    /// Selects a lower accepted profile after the caller has obtained the
    /// required informed human confirmation.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKdf`] outside 64–1024 MiB or 3–10 passes.
    pub fn confirmed(memory_mib: u64, passes: u64) -> Result<Self, CryptoError> {
        let profile = Self { memory_mib, passes };
        profile.validate()?;
        Ok(profile)
    }

    fn validate(self) -> Result<(), CryptoError> {
        if !(64..=1024).contains(&self.memory_mib) || !(3..=10).contains(&self.passes) {
            return Err(CryptoError::InvalidKdf);
        }
        Ok(())
    }
}

#[derive(Eq, PartialEq)]
struct Secret([u8; KEY_BYTES]);

impl Secret {
    fn random() -> Result<Self, CryptoError> {
        sodium()?;
        let mut value = [0_u8; KEY_BYTES];
        // SAFETY: sodium is initialized and `value` is a valid writable buffer.
        unsafe { libsodium_sys::randombytes_buf(value.as_mut_ptr().cast(), value.len()) };
        Ok(Self(value))
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // SAFETY: the array is valid for its exact length and is not used after drop.
        unsafe { libsodium_sys::sodium_memzero(self.0.as_mut_ptr().cast(), self.0.len()) };
    }
}

struct SecretStreamState(libsodium_sys::crypto_secretstream_xchacha20poly1305_state);

impl SecretStreamState {
    fn new() -> Self {
        Self(unsafe {
            // SAFETY: libsodium initialization functions accept a zeroed state.
            std::mem::zeroed()
        })
    }
}

impl Drop for SecretStreamState {
    fn drop(&mut self) {
        // SAFETY: the state is valid storage and is not used after drop.
        unsafe {
            libsodium_sys::sodium_memzero((&raw mut self.0).cast(), std::mem::size_of_val(&self.0));
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Purpose {
    HumanContent,
    AuthPayload,
    Control,
    KeyWrap,
    RootPassword,
    RootRecovery,
    File,
    AuditRecord,
    AuditManifest,
    AttemptState,
}

impl Purpose {
    fn name(self) -> &'static str {
        match self {
            Self::HumanContent => "human-content",
            Self::AuthPayload => "auth-payload",
            Self::Control => "control",
            Self::KeyWrap => "key-wrap",
            Self::RootPassword => "root-password",
            Self::RootRecovery => "root-recovery",
            Self::File => "file",
            Self::AuditRecord => "audit-record",
            Self::AuditManifest => "audit-manifest",
            Self::AttemptState => "attempt-state",
        }
    }

    fn parse(value: &str) -> Result<Self, CryptoError> {
        match value {
            "human-content" => Ok(Self::HumanContent),
            "auth-payload" => Ok(Self::AuthPayload),
            "control" => Ok(Self::Control),
            "key-wrap" => Ok(Self::KeyWrap),
            "root-password" => Ok(Self::RootPassword),
            "root-recovery" => Ok(Self::RootRecovery),
            "file" => Ok(Self::File),
            "audit-record" => Ok(Self::AuditRecord),
            "audit-manifest" => Ok(Self::AuditManifest),
            "attempt-state" => Ok(Self::AttemptState),
            _ => Err(CryptoError::InvalidFormat),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Header {
    vault: [u8; ID_BYTES],
    object: [u8; ID_BYTES],
    revision: [u8; ID_BYTES],
    purpose: Purpose,
    key_generation: u64,
    target_object: [u8; ID_BYTES],
    wrapped_purpose: Purpose,
    kdf: Option<KdfFields>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KdfFields {
    salt: [u8; SALT_BYTES],
    profile: KdfProfile,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Envelope {
    header: Header,
    nonce: [u8; NONCE_BYTES],
    ciphertext: Vec<u8>,
}

/// Public root pinned by the human enrollment flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedRoot {
    vault_id: [u8; ID_BYTES],
    epoch: u64,
    public_key: [u8; KEY_BYTES],
}

impl TrustedRoot {
    #[must_use]
    pub const fn vault_id(&self) -> &[u8; ID_BYTES] {
        &self.vault_id
    }

    #[must_use]
    pub const fn public_key(&self) -> &[u8; KEY_BYTES] {
        &self.public_key
    }

    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// Canonical, self-contained encrypted human-root record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootBundle {
    trusted_root: TrustedRoot,
    password_envelope: Envelope,
    recovery_envelope: Envelope,
    authority_envelope: Envelope,
}

impl RootBundle {
    #[must_use]
    pub const fn trusted_root(&self) -> &TrustedRoot {
        &self.trusted_root
    }

    #[must_use]
    pub fn password_envelope(&self) -> Vec<u8> {
        encode_envelope(&self.password_envelope)
    }

    #[must_use]
    pub fn recovery_envelope(&self) -> Vec<u8> {
        encode_envelope(&self.recovery_envelope)
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_bundle(self)
    }

    /// Parses only deterministic v1 bytes with bounded envelope sizes.
    ///
    /// # Errors
    ///
    /// Returns an error for incompatible, non-canonical, trailing, unknown, or
    /// out-of-bounds data.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() > MAX_OBJECT_BYTES {
            return Err(CryptoError::InvalidFormat);
        }
        let bundle = decode_bundle(bytes)?;
        if encode_bundle(&bundle) != bytes {
            return Err(CryptoError::InvalidFormat);
        }
        validate_bundle(&bundle)?;
        Ok(bundle)
    }
}

/// Root material created in memory until recovery reintroduction succeeds.
pub struct CreatedRoot {
    bundle: RootBundle,
    recovery_code: RecoveryCode,
}

impl CreatedRoot {
    #[must_use]
    pub const fn bundle(&self) -> &RootBundle {
        &self.bundle
    }

    #[must_use]
    pub const fn recovery_code(&self) -> &RecoveryCode {
        &self.recovery_code
    }

    /// # Errors
    ///
    /// Returns an authentication error unless the external code is reintroduced exactly.
    pub fn into_bundle_after_recovery_confirmation(
        self,
        reintroduced: &RecoveryCode,
    ) -> Result<RootBundle, CryptoError> {
        if self.recovery_code != *reintroduced {
            return Err(CryptoError::Authentication);
        }
        Ok(self.bundle)
    }
}

/// Human transport representation of the external recovery key.
pub struct RecoveryCode {
    vault: [u8; ID_BYTES],
    generation: u64,
    key: Secret,
}

impl PartialEq for RecoveryCode {
    fn eq(&self, other: &Self) -> bool {
        self.vault == other.vault
            && self.generation == other.generation
            && constant_time_equal(&self.key.0, &other.key.0)
    }
}

impl Eq for RecoveryCode {}

impl fmt::Display for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PMR1-{}-{}", hex(&self.vault), self.generation)?;
        for group in self.key.0.as_chunks::<4>().0 {
            write!(f, "-{}", hex(group))?;
        }
        write!(f, "-{}", hex(&recovery_checksum(self)))
    }
}

impl FromStr for RecoveryCode {
    type Err = CryptoError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        sodium()?;
        let fields: Vec<_> = value.split('-').collect();
        if fields.len() != 12 || fields[0] != "PMR1" {
            return Err(CryptoError::InvalidFormat);
        }
        let vault = decode_hex_array(fields[1])?;
        let generation = fields[2]
            .parse::<u64>()
            .map_err(|_| CryptoError::InvalidFormat)?;
        let mut key = [0_u8; KEY_BYTES];
        for (index, field) in fields[3..11].iter().enumerate() {
            let group: [u8; 4] = decode_hex_array(field)?;
            key[index * 4..index * 4 + 4].copy_from_slice(&group);
        }
        let parsed = Self {
            vault,
            generation,
            key: Secret(key),
        };
        let supplied: [u8; 4] = decode_hex_array(fields[11])?;
        if supplied != recovery_checksum(&parsed) {
            return Err(CryptoError::InvalidFormat);
        }
        Ok(parsed)
    }
}

/// Unlocked human root. Secret bytes remain confined to this crate and are wiped on drop.
pub struct UnlockedRoot {
    vault: [u8; ID_BYTES],
    human_public_key: [u8; KEY_BYTES],
    human_root: Secret,
    human_signing_seed: Secret,
}

impl UnlockedRoot {
    #[must_use]
    pub const fn vault_id(&self) -> &[u8; ID_BYTES] {
        &self.vault
    }

    #[must_use]
    pub const fn human_public_key(&self) -> &[u8; KEY_BYTES] {
        &self.human_public_key
    }

    /// Encrypts a complete revision-format vector and its independent external
    /// key envelopes. This does not publish or authorize the revision.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized parts, invalid kind/auth composition, or
    /// unavailable cryptographic randomness.
    #[allow(clippy::too_many_lines)]
    pub fn seal_revision_package(
        &self,
        input: RevisionPackageInput<'_>,
    ) -> Result<RevisionPackage, CryptoError> {
        validate_revision_input(&input)?;
        let content_key = Secret::random()?;
        let human_header = target_header(
            self.vault,
            random_array()?,
            input.revision,
            Purpose::HumanContent,
            1,
        );
        let human_ciphertext = seal(&content_key, human_header.clone(), input.human_plaintext)?;
        let human_key_envelope = seal_key(
            &self.human_root,
            &content_key,
            &human_header,
            wrapping_header(
                self.vault,
                random_array()?,
                input.revision,
                Purpose::KeyWrap,
                &human_header,
                None,
            ),
        )?;

        let (auth_ciphertext, auth_key_envelope) = if let Some(plaintext) = input.auth_plaintext {
            let auth_key = Secret::random()?;
            let auth_header = target_header(
                self.vault,
                random_array()?,
                input.revision,
                Purpose::AuthPayload,
                1,
            );
            let ciphertext = seal(&auth_key, auth_header.clone(), plaintext)?;
            let envelope = seal_key(
                &self.human_root,
                &auth_key,
                &auth_header,
                wrapping_header(
                    self.vault,
                    random_array()?,
                    input.revision,
                    Purpose::KeyWrap,
                    &auth_header,
                    None,
                ),
            )?;
            (Some(ciphertext), Some(envelope))
        } else {
            (None, None)
        };

        let manifest_header = target_header(
            self.vault,
            random_array()?,
            input.revision,
            Purpose::HumanContent,
            1,
        );
        let manifest_key_envelope = seal_key(
            &self.human_root,
            &content_key,
            &manifest_header,
            wrapping_header(
                self.vault,
                random_array()?,
                input.revision,
                Purpose::KeyWrap,
                &manifest_header,
                None,
            ),
        )?;
        let human_ciphertext_bytes = encode_envelope(&human_ciphertext);
        let human_key_envelope_bytes = encode_envelope(&human_key_envelope);
        let auth_part = auth_ciphertext
            .as_ref()
            .zip(auth_key_envelope.as_ref())
            .map(|(ciphertext, envelope)| manifest_part(ciphertext, envelope));
        let manifest = RevisionManifest {
            vault: self.vault,
            item: input.item,
            revision: input.revision,
            issuer_device: input.issuer_device,
            modified_at: input.modified_at,
            kind: input.kind,
            human_part: ManifestPart {
                object_id: human_ciphertext.header.object,
                ciphertext_sha256: sha256(&human_ciphertext_bytes),
                ciphertext_length: human_ciphertext_bytes.len() as u64,
                key_envelope_digest: sha256(&human_key_envelope_bytes),
            },
            auth_part,
        };
        let manifest_plaintext = encode_manifest(&manifest);
        let manifest_ciphertext = seal(&content_key, manifest_header, &manifest_plaintext)?;
        Ok(RevisionPackage {
            human_ciphertext,
            auth_ciphertext,
            manifest_ciphertext,
            human_key_envelope,
            auth_key_envelope,
            manifest_key_envelope,
        })
    }

    /// Strictly parses, authenticates, and cross-checks a complete revision
    /// package before returning either plaintext part.
    ///
    /// # Errors
    ///
    /// Returns an error for non-canonical/trailing input, altered AEAD data,
    /// mixed revisions or purposes, missing parts, or digest mismatches.
    pub fn open_revision_package(
        &self,
        bytes: &[u8],
    ) -> Result<OpenedRevisionPackage, CryptoError> {
        let package = RevisionPackage::from_bytes(bytes)?;
        let (content_key, human_target) = open_key(&self.human_root, &package.human_key_envelope)?;
        if human_target != package.human_ciphertext.header {
            return Err(CryptoError::Authentication);
        }
        let (manifest_key, manifest_target) =
            open_key(&self.human_root, &package.manifest_key_envelope)?;
        if manifest_target != package.manifest_ciphertext.header
            || !constant_time_equal(&content_key.0, &manifest_key.0)
        {
            return Err(CryptoError::Authentication);
        }
        let human_plaintext = open(&content_key, &package.human_ciphertext)?;
        let mut manifest_plaintext = open(&content_key, &package.manifest_ciphertext)?;
        let decoded_manifest = decode_manifest(&manifest_plaintext);
        wipe_vec(&mut manifest_plaintext);
        let manifest = decoded_manifest?;

        let auth_plaintext = match (&package.auth_ciphertext, &package.auth_key_envelope) {
            (Some(ciphertext), Some(envelope)) => {
                let (auth_key, auth_target) = open_key(&self.human_root, envelope)?;
                if auth_target != ciphertext.header {
                    return Err(CryptoError::Authentication);
                }
                Some(open(&auth_key, ciphertext)?)
            }
            (None, None) => None,
            _ => return Err(CryptoError::InvalidFormat),
        };
        validate_manifest(self.vault, &manifest, &package)?;
        if manifest.kind.requires_auth() != auth_plaintext.is_some() {
            return Err(CryptoError::InvalidFormat);
        }
        Ok(OpenedRevisionPackage {
            item: manifest.item,
            revision: manifest.revision,
            human_plaintext,
            auth_plaintext,
        })
    }

    /// Prepares the sealed portion and commitment before an authority event exists.
    ///
    /// # Errors
    ///
    /// Returns an error when randomness or sealed-box construction fails.
    pub fn prepare_grant_vector(
        &self,
        input: GrantVectorInput,
        recipient_public_key: &[u8; 32],
    ) -> Result<PendingGrantVector, CryptoError> {
        let target_header = target_header(
            self.vault,
            random_array()?,
            input.revision,
            Purpose::AuthPayload,
            1,
        );
        let key = Secret::random()?;
        let mut sealed_plaintext = encode_sealed_key(
            &key,
            &target_header,
            &input.recipient,
            input.authorization_generation,
        );
        let mut sealed_box = vec![0_u8; sealed_plaintext.len() + 48];
        let result = unsafe {
            // SAFETY: output/input/public-key buffers have their documented sizes.
            libsodium_sys::crypto_box_seal(
                sealed_box.as_mut_ptr(),
                sealed_plaintext.as_ptr(),
                sealed_plaintext.len() as u64,
                recipient_public_key.as_ptr(),
            )
        };
        wipe_vec(&mut sealed_plaintext);
        if result != 0 {
            return Err(CryptoError::Authentication);
        }
        let fields = GrantFields {
            vault: self.vault,
            item: input.item,
            revision: input.revision,
            recipient: input.recipient,
            authorization_generation: input.authorization_generation,
            target_header,
            payload_sha256: input.payload_sha256,
            sealed_box,
            authority_event: None,
        };
        let commitment = sha256(&encode_grant_fields(&fields));
        Ok(PendingGrantVector { fields, commitment })
    }

    /// Completes/signs the grant after its commitment was placed in an event.
    ///
    /// # Errors
    ///
    /// Returns an error if Ed25519 signing cannot be completed.
    pub fn finish_grant_vector(
        &self,
        mut pending: PendingGrantVector,
        authority_event: [u8; 32],
    ) -> Result<SignedGrantVector, CryptoError> {
        pending.fields.authority_event = Some(authority_event);
        let signature = sign_detached(
            &self.human_signing_seed,
            &encode_grant_signature_message(&pending.fields),
        )?;
        Ok(SignedGrantVector {
            fields: pending.fields,
            commitment: pending.commitment,
            signature,
        })
    }
}

/// Logical item type used only to validate revision-format membership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemKind {
    Password,
    Totp,
    Passkey,
    Ssh,
    Token,
    Note,
    File,
}

impl ItemKind {
    fn name(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Totp => "totp",
            Self::Passkey => "passkey",
            Self::Ssh => "ssh",
            Self::Token => "token",
            Self::Note => "note",
            Self::File => "file",
        }
    }

    fn parse(value: &str) -> Result<Self, CryptoError> {
        match value {
            "password" => Ok(Self::Password),
            "totp" => Ok(Self::Totp),
            "passkey" => Ok(Self::Passkey),
            "ssh" => Ok(Self::Ssh),
            "token" => Ok(Self::Token),
            "note" => Ok(Self::Note),
            "file" => Ok(Self::File),
            _ => Err(CryptoError::InvalidFormat),
        }
    }

    const fn requires_auth(self) -> bool {
        !matches!(self, Self::Note | Self::File)
    }
}

/// Already-canonical logical plaintexts to bind as one revision. Schema-level
/// validation of their G6 contents belongs to the owning data-type ticket.
#[derive(Clone, Copy)]
pub struct RevisionPackageInput<'a> {
    pub item: [u8; ID_BYTES],
    pub revision: [u8; ID_BYTES],
    pub issuer_device: [u8; ID_BYTES],
    pub modified_at: i64,
    pub kind: ItemKind,
    pub human_plaintext: &'a [u8],
    pub auth_plaintext: Option<&'a [u8]>,
}

/// Opaque encrypted package. It contains external key envelopes rather than
/// embedding them in the encrypted manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevisionPackage {
    human_ciphertext: Envelope,
    auth_ciphertext: Option<Envelope>,
    manifest_ciphertext: Envelope,
    human_key_envelope: Envelope,
    auth_key_envelope: Option<Envelope>,
    manifest_key_envelope: Envelope,
}

impl RevisionPackage {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_revision_package(self)
    }

    #[must_use]
    pub fn human_key_envelope(&self) -> Vec<u8> {
        encode_envelope(&self.human_key_envelope)
    }

    #[must_use]
    pub fn manifest_key_envelope(&self) -> Vec<u8> {
        encode_envelope(&self.manifest_key_envelope)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() > MAX_OBJECT_BYTES {
            return Err(CryptoError::InvalidFormat);
        }
        let package = decode_revision_package(bytes)?;
        if encode_revision_package(&package) != bytes {
            return Err(CryptoError::InvalidFormat);
        }
        Ok(package)
    }
}

/// Plaintexts released only after the package and manifest validate as a unit.
pub struct OpenedRevisionPackage {
    item: [u8; ID_BYTES],
    revision: [u8; ID_BYTES],
    human_plaintext: Vec<u8>,
    auth_plaintext: Option<Vec<u8>>,
}

impl OpenedRevisionPackage {
    #[must_use]
    pub const fn item(&self) -> &[u8; ID_BYTES] {
        &self.item
    }

    #[must_use]
    pub const fn revision(&self) -> &[u8; ID_BYTES] {
        &self.revision
    }

    #[must_use]
    pub fn human_plaintext(&self) -> &[u8] {
        &self.human_plaintext
    }

    #[must_use]
    pub fn auth_plaintext(&self) -> Option<&[u8]> {
        self.auth_plaintext.as_deref()
    }
}

impl Drop for OpenedRevisionPackage {
    fn drop(&mut self) {
        wipe_vec(&mut self.human_plaintext);
        if let Some(auth) = &mut self.auth_plaintext {
            wipe_vec(auth);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManifestPart {
    object_id: [u8; ID_BYTES],
    ciphertext_sha256: [u8; 32],
    ciphertext_length: u64,
    key_envelope_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RevisionManifest {
    vault: [u8; ID_BYTES],
    item: [u8; ID_BYTES],
    revision: [u8; ID_BYTES],
    issuer_device: [u8; ID_BYTES],
    modified_at: i64,
    kind: ItemKind,
    human_part: ManifestPart,
    auth_part: Option<ManifestPart>,
}

/// Synthetic PMF1 format vector with an opaque, in-memory file key. It proves
/// framing behavior only; backup membership/persistence belongs to later tickets.
pub struct Pmf1Vector {
    key: Secret,
    bytes: Vec<u8>,
}

impl Pmf1Vector {
    /// Seals one synthetic file using 1 MiB secretstream chunks and a mandatory final tag.
    ///
    /// # Errors
    ///
    /// Returns an error for data above the vector limit or unavailable crypto.
    pub fn seal(
        vault: [u8; ID_BYTES],
        object: [u8; ID_BYTES],
        revision: [u8; ID_BYTES],
        plaintext: &[u8],
    ) -> Result<Self, CryptoError> {
        if plaintext.len() > MAX_OBJECT_BYTES {
            return Err(CryptoError::InvalidFormat);
        }
        let key = Secret::random()?;
        let header = target_header(vault, object, revision, Purpose::File, 1);
        let bytes = seal_pmf1(&key, &header, plaintext)?;
        Ok(Self { key, bytes })
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Opens this vector's own bytes.
    ///
    /// # Errors
    ///
    /// Returns an error unless every frame authenticates through the final tag.
    pub fn open(&self) -> Result<Vec<u8>, CryptoError> {
        self.open_bytes(&self.bytes)
    }

    /// Opens alternate bytes with the vector's opaque key for adversarial tests.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, reordered, truncated, trailing, or altered data.
    pub fn open_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
        open_pmf1(&self.key, bytes)
    }
}

/// X25519 vector keypair. The private key never leaves this typed boundary.
pub struct DeviceKeyPair {
    public_key: [u8; 32],
    private_key: Secret,
}

impl DeviceKeyPair {
    /// Generates a device envelope keypair.
    ///
    /// # Errors
    ///
    /// Returns an error when the native random source is unavailable.
    pub fn generate() -> Result<Self, CryptoError> {
        sodium()?;
        let mut public_key = [0_u8; 32];
        let mut private_key = Secret([0_u8; 32]);
        let result = unsafe {
            // SAFETY: buffers are the exact crypto_box key sizes.
            libsodium_sys::crypto_box_keypair(public_key.as_mut_ptr(), private_key.0.as_mut_ptr())
        };
        if result != 0 {
            return Err(CryptoError::RandomUnavailable);
        }
        Ok(Self {
            public_key,
            private_key,
        })
    }

    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Verifies trusted signature/commitment before opening the sealed box.
    ///
    /// # Errors
    ///
    /// Returns an error for any mismatched context, signature, or ciphertext.
    pub fn verify_grant_vector(
        &self,
        bytes: &[u8],
        trusted_root: &TrustedRoot,
        recipient: [u8; 16],
        authority_event: [u8; 32],
        commitment: [u8; 32],
    ) -> Result<(), CryptoError> {
        let signed = decode_signed_grant(bytes)?;
        if signed.fields.vault != trusted_root.vault_id
            || signed.fields.recipient != recipient
            || signed.fields.authority_event != Some(authority_event)
            || sha256(&encode_grant_without_event(&signed.fields)) != commitment
            || signed.fields.target_header.vault != signed.fields.vault
            || signed.fields.target_header.revision != signed.fields.revision
            || signed.fields.target_header.purpose != Purpose::AuthPayload
        {
            return Err(CryptoError::Authentication);
        }
        let message = encode_grant_signature_message(&signed.fields);
        if unsafe {
            // SAFETY: signature/public key sizes and message buffer are valid.
            libsodium_sys::crypto_sign_verify_detached(
                signed.signature.as_ptr(),
                message.as_ptr(),
                message.len() as u64,
                trusted_root.public_key.as_ptr(),
            )
        } != 0
        {
            return Err(CryptoError::Authentication);
        }
        if signed.fields.sealed_box.len() < 48 {
            return Err(CryptoError::InvalidFormat);
        }
        let mut plaintext = vec![0_u8; signed.fields.sealed_box.len() - 48];
        if unsafe {
            // SAFETY: key and message buffers have the exact declared lengths.
            libsodium_sys::crypto_box_seal_open(
                plaintext.as_mut_ptr(),
                signed.fields.sealed_box.as_ptr(),
                signed.fields.sealed_box.len() as u64,
                self.public_key.as_ptr(),
                self.private_key.0.as_ptr(),
            )
        } != 0
        {
            return Err(CryptoError::Authentication);
        }
        let decoded = decode_sealed_key_context(&plaintext);
        wipe_vec(&mut plaintext);
        let (target, inner_recipient, generation) = decoded?;
        if target != signed.fields.target_header
            || inner_recipient != recipient
            || generation != signed.fields.authorization_generation
        {
            return Err(CryptoError::Authentication);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct GrantVectorInput {
    pub item: [u8; 16],
    pub revision: [u8; 16],
    pub recipient: [u8; 16],
    pub authorization_generation: u64,
    pub payload_sha256: [u8; 32],
}

pub struct PendingGrantVector {
    fields: GrantFields,
    commitment: [u8; 32],
}

impl PendingGrantVector {
    #[must_use]
    pub const fn commitment(&self) -> [u8; 32] {
        self.commitment
    }
}

pub struct SignedGrantVector {
    fields: GrantFields,
    commitment: [u8; 32],
    signature: [u8; 64],
}

impl SignedGrantVector {
    #[must_use]
    pub const fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_signed_grant(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GrantFields {
    vault: [u8; 16],
    item: [u8; 16],
    revision: [u8; 16],
    recipient: [u8; 16],
    authorization_generation: u64,
    target_header: Header,
    payload_sha256: [u8; 32],
    sealed_box: Vec<u8>,
    authority_event: Option<[u8; 32]>,
}

/// Generates independent human/recovery roots and encrypted human authority.
///
/// # Errors
///
/// Returns an error for invalid inputs or unavailable native crypto resources.
pub fn create_human_root(password: &[u8], profile: KdfProfile) -> Result<CreatedRoot, CryptoError> {
    validate_password(password)?;
    profile.validate()?;
    sodium()?;

    let vault = random_array()?;
    let root_object = random_array()?;
    let revision = [0_u8; ID_BYTES];
    let human_root = Secret::random()?;
    let recovery_key = Secret::random()?;
    let signing_seed = Secret::random()?;
    let mut public_key = [0_u8; KEY_BYTES];
    let mut expanded_secret = [0_u8; 64];
    // SAFETY: buffers have the exact Ed25519 sizes documented by libsodium.
    let keypair_result = unsafe {
        libsodium_sys::crypto_sign_seed_keypair(
            public_key.as_mut_ptr(),
            expanded_secret.as_mut_ptr(),
            signing_seed.0.as_ptr(),
        )
    };
    // SAFETY: the expanded secret is no longer needed regardless of result.
    unsafe { libsodium_sys::sodium_memzero(expanded_secret.as_mut_ptr().cast(), 64) };
    if keypair_result != 0 {
        return Err(CryptoError::RandomUnavailable);
    }

    let trusted_root = TrustedRoot {
        vault_id: vault,
        epoch: 1,
        public_key,
    };
    let root_target = target_header(vault, root_object, revision, Purpose::KeyWrap, 1);
    let salt = random_array()?;
    let password_key = derive_password(password, &salt, profile)?;
    let password_header = wrapping_header(
        vault,
        random_array()?,
        revision,
        Purpose::RootPassword,
        &root_target,
        Some(KdfFields { salt, profile }),
    );
    let recovery_header = wrapping_header(
        vault,
        random_array()?,
        revision,
        Purpose::RootRecovery,
        &root_target,
        None,
    );
    let authority_target = target_header(vault, random_array()?, revision, Purpose::Control, 1);
    let authority_header = wrapping_header(
        vault,
        random_array()?,
        revision,
        Purpose::KeyWrap,
        &authority_target,
        None,
    );

    let password_envelope = seal_key(&password_key, &human_root, &root_target, password_header)?;
    let recovery_envelope = seal_key(&recovery_key, &human_root, &root_target, recovery_header)?;
    let authority_envelope = seal_key(
        &human_root,
        &signing_seed,
        &authority_target,
        authority_header,
    )?;
    let recovery_code = RecoveryCode {
        vault,
        generation: 1,
        key: recovery_key,
    };

    Ok(CreatedRoot {
        bundle: RootBundle {
            trusted_root,
            password_envelope,
            recovery_envelope,
            authority_envelope,
        },
        recovery_code,
    })
}

/// Authenticates the password path and separately pinned human signing root.
///
/// # Errors
///
/// Returns an error if any format, KDF, envelope context, or root check fails.
pub fn open_human_root(bundle: &RootBundle, password: &[u8]) -> Result<UnlockedRoot, CryptoError> {
    validate_password(password)?;
    validate_bundle(bundle)?;
    let kdf = bundle
        .password_envelope
        .header
        .kdf
        .as_ref()
        .ok_or(CryptoError::InvalidKdf)?;
    kdf.profile.validate()?;
    let password_key = derive_password(password, &kdf.salt, kdf.profile)?;
    unlock_with_key(bundle, &password_key, &bundle.password_envelope)
}

/// Authenticates the independent recovery path and pinned human signing root.
///
/// # Errors
///
/// Returns an error for a foreign/wrong code or any altered root envelope.
pub fn recover_human_root(
    bundle: &RootBundle,
    code: &RecoveryCode,
) -> Result<UnlockedRoot, CryptoError> {
    validate_bundle(bundle)?;
    if code.vault != bundle.trusted_root.vault_id || code.generation != 1 {
        return Err(CryptoError::Authentication);
    }
    unlock_with_key(bundle, &code.key, &bundle.recovery_envelope)
}

fn unlock_with_key(
    bundle: &RootBundle,
    wrapping_key: &Secret,
    root_envelope: &Envelope,
) -> Result<UnlockedRoot, CryptoError> {
    let (human_root, root_target) = open_key(wrapping_key, root_envelope)?;
    if root_target.purpose != Purpose::KeyWrap
        || root_target.vault != bundle.trusted_root.vault_id
        || root_target.object != root_envelope.header.target_object
    {
        return Err(CryptoError::Authentication);
    }
    let (signing_seed, authority_target) = open_key(&human_root, &bundle.authority_envelope)?;
    if authority_target.purpose != Purpose::Control
        || authority_target.vault != bundle.trusted_root.vault_id
    {
        return Err(CryptoError::Authentication);
    }
    let mut derived_public = [0_u8; KEY_BYTES];
    let mut expanded_secret = [0_u8; 64];
    // SAFETY: buffers have the exact sizes required by libsodium.
    let result = unsafe {
        libsodium_sys::crypto_sign_seed_keypair(
            derived_public.as_mut_ptr(),
            expanded_secret.as_mut_ptr(),
            signing_seed.0.as_ptr(),
        )
    };
    // SAFETY: expanded material is no longer needed.
    unsafe { libsodium_sys::sodium_memzero(expanded_secret.as_mut_ptr().cast(), 64) };
    if result != 0 || !constant_time_equal(&derived_public, &bundle.trusted_root.public_key) {
        return Err(CryptoError::Authentication);
    }
    Ok(UnlockedRoot {
        vault: bundle.trusted_root.vault_id,
        human_public_key: derived_public,
        human_root,
        human_signing_seed: signing_seed,
    })
}

fn wrapping_header(
    vault: [u8; ID_BYTES],
    object: [u8; ID_BYTES],
    revision: [u8; ID_BYTES],
    purpose: Purpose,
    target: &Header,
    kdf: Option<KdfFields>,
) -> Header {
    Header {
        vault,
        object,
        revision,
        purpose,
        key_generation: 1,
        target_object: target.object,
        wrapped_purpose: target.purpose,
        kdf,
    }
}

fn target_header(
    vault: [u8; ID_BYTES],
    object: [u8; ID_BYTES],
    revision: [u8; ID_BYTES],
    purpose: Purpose,
    key_generation: u64,
) -> Header {
    Header {
        vault,
        object,
        revision,
        purpose,
        key_generation,
        target_object: object,
        wrapped_purpose: purpose,
        kdf: None,
    }
}

fn seal_key(
    wrapping_key: &Secret,
    wrapped_key: &Secret,
    target: &Header,
    header: Header,
) -> Result<Envelope, CryptoError> {
    let mut plaintext = encode_wrapped_key(wrapped_key, target);
    let result = seal(wrapping_key, header, &plaintext);
    wipe_vec(&mut plaintext);
    result
}

fn open_key(key: &Secret, envelope: &Envelope) -> Result<(Secret, Header), CryptoError> {
    let plaintext = open(key, envelope)?;
    let result = decode_wrapped_key(&plaintext);
    let mut plaintext = plaintext;
    // SAFETY: plaintext is a valid writable allocation and is no longer used.
    unsafe { libsodium_sys::sodium_memzero(plaintext.as_mut_ptr().cast(), plaintext.len()) };
    let (wrapped, target) = result?;
    if target.vault != envelope.header.vault
        || target.object != envelope.header.target_object
        || target.revision != envelope.header.revision
        || target.purpose != envelope.header.wrapped_purpose
        || target.key_generation != envelope.header.key_generation
    {
        return Err(CryptoError::Authentication);
    }
    Ok((wrapped, target))
}

fn seal(key: &Secret, header: Header, plaintext: &[u8]) -> Result<Envelope, CryptoError> {
    sodium()?;
    if plaintext.len() > MAX_OBJECT_BYTES {
        return Err(CryptoError::InvalidFormat);
    }
    let nonce = random_array()?;
    let aad = encode_aad(&header);
    if aad.len() > MAX_HEADER_BYTES {
        return Err(CryptoError::InvalidFormat);
    }
    let mut ciphertext = vec![0_u8; plaintext.len() + TAG_BYTES];
    let mut ciphertext_len = 0_u64;
    // SAFETY: every pointer references a valid buffer for its supplied length.
    let result = unsafe {
        libsodium_sys::crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.as_mut_ptr(),
            &raw mut ciphertext_len,
            plaintext.as_ptr(),
            plaintext.len() as u64,
            aad.as_ptr(),
            aad.len() as u64,
            std::ptr::null(),
            nonce.as_ptr(),
            key.0.as_ptr(),
        )
    };
    if result != 0 || usize::try_from(ciphertext_len).ok() != Some(ciphertext.len()) {
        return Err(CryptoError::Authentication);
    }
    Ok(Envelope {
        header,
        nonce,
        ciphertext,
    })
}

fn open(key: &Secret, envelope: &Envelope) -> Result<Vec<u8>, CryptoError> {
    sodium()?;
    if envelope.ciphertext.len() < TAG_BYTES || envelope.ciphertext.len() > MAX_OBJECT_BYTES {
        return Err(CryptoError::InvalidFormat);
    }
    let aad = encode_aad(&envelope.header);
    if aad.len() > MAX_HEADER_BYTES {
        return Err(CryptoError::InvalidFormat);
    }
    let mut plaintext = vec![0_u8; envelope.ciphertext.len() - TAG_BYTES];
    let mut plaintext_len = 0_u64;
    // SAFETY: every pointer references a valid buffer for its supplied length.
    let result = unsafe {
        libsodium_sys::crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.as_mut_ptr(),
            &raw mut plaintext_len,
            std::ptr::null_mut(),
            envelope.ciphertext.as_ptr(),
            envelope.ciphertext.len() as u64,
            aad.as_ptr(),
            aad.len() as u64,
            envelope.nonce.as_ptr(),
            key.0.as_ptr(),
        )
    };
    if result != 0 || usize::try_from(plaintext_len).ok() != Some(plaintext.len()) {
        wipe_vec(&mut plaintext);
        return Err(CryptoError::Authentication);
    }
    Ok(plaintext)
}

fn derive_password(
    password: &[u8],
    salt: &[u8; SALT_BYTES],
    profile: KdfProfile,
) -> Result<Secret, CryptoError> {
    sodium()?;
    profile.validate()?;
    let memory_bytes = profile
        .memory_mib
        .checked_mul(1024 * 1024)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(CryptoError::InvalidKdf)?;
    let mut key = Secret([0_u8; KEY_BYTES]);
    // SAFETY: output, password, and salt point to valid buffers; limits were validated.
    let result = unsafe {
        libsodium_sys::crypto_pwhash(
            key.0.as_mut_ptr(),
            KEY_BYTES as u64,
            password.as_ptr().cast(),
            password.len() as u64,
            salt.as_ptr(),
            profile.passes,
            memory_bytes,
            libsodium_sys::crypto_pwhash_ALG_ARGON2ID13.cast_signed(),
        )
    };
    if result != 0 {
        return Err(CryptoError::ResourceUnavailable);
    }
    Ok(key)
}

fn validate_password(password: &[u8]) -> Result<(), CryptoError> {
    if !(1..=1024).contains(&password.len()) || std::str::from_utf8(password).is_err() {
        return Err(CryptoError::InvalidPassword);
    }
    Ok(())
}

fn validate_bundle(bundle: &RootBundle) -> Result<(), CryptoError> {
    if bundle.trusted_root.epoch != 1
        || bundle.password_envelope.header.purpose != Purpose::RootPassword
        || bundle.password_envelope.header.kdf.is_none()
        || bundle.recovery_envelope.header.purpose != Purpose::RootRecovery
        || bundle.recovery_envelope.header.kdf.is_some()
        || bundle.authority_envelope.header.purpose != Purpose::KeyWrap
        || bundle.authority_envelope.header.wrapped_purpose != Purpose::Control
    {
        return Err(CryptoError::InvalidFormat);
    }
    for envelope in [
        &bundle.password_envelope,
        &bundle.recovery_envelope,
        &bundle.authority_envelope,
    ] {
        if envelope.header.vault != bundle.trusted_root.vault_id
            || envelope.header.key_generation != 1
            || envelope.ciphertext.len() < TAG_BYTES
            || envelope.ciphertext.len() > MAX_OBJECT_BYTES
        {
            return Err(CryptoError::InvalidFormat);
        }
    }
    bundle
        .password_envelope
        .header
        .kdf
        .as_ref()
        .ok_or(CryptoError::InvalidKdf)?
        .profile
        .validate()
}

fn sodium() -> Result<(), CryptoError> {
    static INIT: OnceLock<bool> = OnceLock::new();
    let initialized = INIT.get_or_init(|| {
        // SAFETY: `sodium_init` is explicitly safe to call concurrently and repeatedly.
        unsafe { libsodium_sys::sodium_init() >= 0 }
    });
    if *initialized {
        Ok(())
    } else {
        Err(CryptoError::RandomUnavailable)
    }
}

fn random_array<const N: usize>() -> Result<[u8; N], CryptoError> {
    sodium()?;
    let mut value = [0_u8; N];
    // SAFETY: sodium is initialized and the destination buffer is valid.
    unsafe { libsodium_sys::randombytes_buf(value.as_mut_ptr().cast(), value.len()) };
    Ok(value)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && unsafe {
            // SAFETY: both slices are valid for the common nonzero length.
            libsodium_sys::sodium_memcmp(left.as_ptr().cast(), right.as_ptr().cast(), left.len())
                == 0
        }
}

fn encode_bundle(bundle: &RootBundle) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(5).expect("Vec writes cannot fail");
    encoder.str("v").expect("Vec writes cannot fail");
    encoder.u64(FORMAT_VERSION).expect("Vec writes cannot fail");
    encoder.str("trusted_root").expect("Vec writes cannot fail");
    encode_trusted_root(&mut encoder, &bundle.trusted_root);
    encoder
        .str("password_envelope")
        .expect("Vec writes cannot fail");
    encoder
        .bytes(&encode_envelope(&bundle.password_envelope))
        .expect("Vec writes cannot fail");
    encoder
        .str("recovery_envelope")
        .expect("Vec writes cannot fail");
    encoder
        .bytes(&encode_envelope(&bundle.recovery_envelope))
        .expect("Vec writes cannot fail");
    encoder
        .str("authority_envelope")
        .expect("Vec writes cannot fail");
    encoder
        .bytes(&encode_envelope(&bundle.authority_envelope))
        .expect("Vec writes cannot fail");
    encoder.into_writer()
}

fn decode_bundle(bytes: &[u8]) -> Result<RootBundle, CryptoError> {
    let mut decoder = Decoder::new(bytes);
    expect_map(&mut decoder, 5)?;
    expect_key(&mut decoder, "v")?;
    if decoder.u64().map_err(invalid)? != FORMAT_VERSION {
        return Err(CryptoError::InvalidFormat);
    }
    expect_key(&mut decoder, "trusted_root")?;
    let trusted_root = decode_trusted_root(&mut decoder)?;
    expect_key(&mut decoder, "password_envelope")?;
    let password_envelope = decode_envelope(decoder.bytes().map_err(invalid)?)?;
    expect_key(&mut decoder, "recovery_envelope")?;
    let recovery_envelope = decode_envelope(decoder.bytes().map_err(invalid)?)?;
    expect_key(&mut decoder, "authority_envelope")?;
    let authority_envelope = decode_envelope(decoder.bytes().map_err(invalid)?)?;
    if decoder.position() != bytes.len() {
        return Err(CryptoError::InvalidFormat);
    }
    Ok(RootBundle {
        trusted_root,
        password_envelope,
        recovery_envelope,
        authority_envelope,
    })
}

fn encode_trusted_root(encoder: &mut Encoder<Vec<u8>>, root: &TrustedRoot) {
    encoder.map(3).expect("Vec writes cannot fail");
    encoder.str("epoch").expect("Vec writes cannot fail");
    encoder.u64(root.epoch).expect("Vec writes cannot fail");
    encoder.str("vault").expect("Vec writes cannot fail");
    encoder
        .bytes(&root.vault_id)
        .expect("Vec writes cannot fail");
    encoder.str("public_key").expect("Vec writes cannot fail");
    encoder
        .bytes(&root.public_key)
        .expect("Vec writes cannot fail");
}

fn decode_trusted_root(decoder: &mut Decoder<'_>) -> Result<TrustedRoot, CryptoError> {
    expect_map(decoder, 3)?;
    expect_key(decoder, "epoch")?;
    let epoch = decoder.u64().map_err(invalid)?;
    expect_key(decoder, "vault")?;
    let vault_id = decode_bytes(decoder)?;
    expect_key(decoder, "public_key")?;
    let public_key = decode_bytes(decoder)?;
    Ok(TrustedRoot {
        vault_id,
        epoch,
        public_key,
    })
}

fn encode_envelope(envelope: &Envelope) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(3).expect("Vec writes cannot fail");
    encoder.str("nonce").expect("Vec writes cannot fail");
    encoder
        .bytes(&envelope.nonce)
        .expect("Vec writes cannot fail");
    encoder.str("header").expect("Vec writes cannot fail");
    encode_header(&mut encoder, &envelope.header);
    encoder.str("ciphertext").expect("Vec writes cannot fail");
    encoder
        .bytes(&envelope.ciphertext)
        .expect("Vec writes cannot fail");
    encoder.into_writer()
}

fn decode_envelope(bytes: &[u8]) -> Result<Envelope, CryptoError> {
    if bytes.len() > MAX_OBJECT_BYTES {
        return Err(CryptoError::InvalidFormat);
    }
    let mut decoder = Decoder::new(bytes);
    expect_map(&mut decoder, 3)?;
    expect_key(&mut decoder, "nonce")?;
    let nonce = decode_bytes(&mut decoder)?;
    expect_key(&mut decoder, "header")?;
    let header = decode_header(&mut decoder)?;
    expect_key(&mut decoder, "ciphertext")?;
    let ciphertext = decoder.bytes().map_err(invalid)?.to_vec();
    if decoder.position() != bytes.len() {
        return Err(CryptoError::InvalidFormat);
    }
    let envelope = Envelope {
        header,
        nonce,
        ciphertext,
    };
    if encode_envelope(&envelope) != bytes {
        return Err(CryptoError::InvalidFormat);
    }
    Ok(envelope)
}

fn encode_aad(header: &Header) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.array(2).expect("Vec writes cannot fail");
    encoder.str("pm/aead/v1").expect("Vec writes cannot fail");
    encode_header(&mut encoder, header);
    encoder.into_writer()
}

fn encode_header(encoder: &mut Encoder<Vec<u8>>, header: &Header) {
    let is_wrapper = matches!(
        header.purpose,
        Purpose::KeyWrap | Purpose::RootPassword | Purpose::RootRecovery
    );
    let fields = 7 + u64::from(is_wrapper) * 2 + u64::from(header.kdf.is_some()) * 5;
    encoder.map(fields).expect("Vec writes cannot fail");
    encoder.str("v").expect("Vec writes cannot fail");
    encoder.u64(FORMAT_VERSION).expect("Vec writes cannot fail");
    if let Some(kdf) = &header.kdf {
        encoder.str("salt").expect("Vec writes cannot fail");
        encoder.bytes(&kdf.salt).expect("Vec writes cannot fail");
        encoder.str("lanes").expect("Vec writes cannot fail");
        encoder.u64(1).expect("Vec writes cannot fail");
    }
    encoder.str("suite").expect("Vec writes cannot fail");
    encoder.u64(SUITE).expect("Vec writes cannot fail");
    encoder.str("vault").expect("Vec writes cannot fail");
    encoder
        .bytes(&header.vault)
        .expect("Vec writes cannot fail");
    if let Some(kdf) = &header.kdf {
        encoder.str("memory").expect("Vec writes cannot fail");
        encoder
            .u64(kdf.profile.memory_mib)
            .expect("Vec writes cannot fail");
    }
    encoder.str("object").expect("Vec writes cannot fail");
    encoder
        .bytes(&header.object)
        .expect("Vec writes cannot fail");
    if let Some(kdf) = &header.kdf {
        encoder.str("passes").expect("Vec writes cannot fail");
        encoder
            .u64(kdf.profile.passes)
            .expect("Vec writes cannot fail");
    }
    encoder.str("purpose").expect("Vec writes cannot fail");
    encoder
        .str(header.purpose.name())
        .expect("Vec writes cannot fail");
    encoder.str("revision").expect("Vec writes cannot fail");
    encoder
        .bytes(&header.revision)
        .expect("Vec writes cannot fail");
    if header.kdf.is_some() {
        encoder.str("algorithm").expect("Vec writes cannot fail");
        encoder
            .str("argon2id-v1.3")
            .expect("Vec writes cannot fail");
    }
    if is_wrapper {
        encoder
            .str("target_object")
            .expect("Vec writes cannot fail");
        encoder
            .bytes(&header.target_object)
            .expect("Vec writes cannot fail");
    }
    encoder
        .str("key_generation")
        .expect("Vec writes cannot fail");
    encoder
        .u64(header.key_generation)
        .expect("Vec writes cannot fail");
    if is_wrapper {
        encoder
            .str("wrapped_purpose")
            .expect("Vec writes cannot fail");
        encoder
            .str(header.wrapped_purpose.name())
            .expect("Vec writes cannot fail");
    }
}

fn decode_header(decoder: &mut Decoder<'_>) -> Result<Header, CryptoError> {
    let fields = decoder
        .map()
        .map_err(invalid)?
        .ok_or(CryptoError::InvalidFormat)?;
    if fields != 7 && fields != 9 && fields != 14 {
        return Err(CryptoError::InvalidFormat);
    }
    let has_kdf = fields == 14;
    let is_wrapper = fields != 7;
    expect_key(decoder, "v")?;
    if decoder.u64().map_err(invalid)? != FORMAT_VERSION {
        return Err(CryptoError::InvalidFormat);
    }
    let mut salt = None;
    let mut profile = None;
    if has_kdf {
        expect_key(decoder, "salt")?;
        salt = Some(decode_bytes(decoder)?);
        expect_key(decoder, "lanes")?;
        if decoder.u64().map_err(invalid)? != 1 {
            return Err(CryptoError::InvalidKdf);
        }
    }
    expect_key(decoder, "suite")?;
    if decoder.u64().map_err(invalid)? != SUITE {
        return Err(CryptoError::InvalidFormat);
    }
    expect_key(decoder, "vault")?;
    let vault = decode_bytes(decoder)?;
    let mut memory = None;
    if has_kdf {
        expect_key(decoder, "memory")?;
        memory = Some(decoder.u64().map_err(invalid)?);
    }
    expect_key(decoder, "object")?;
    let object = decode_bytes(decoder)?;
    let mut passes = None;
    if has_kdf {
        expect_key(decoder, "passes")?;
        passes = Some(decoder.u64().map_err(invalid)?);
    }
    expect_key(decoder, "purpose")?;
    let purpose = Purpose::parse(decoder.str().map_err(invalid)?)?;
    expect_key(decoder, "revision")?;
    let revision = decode_bytes(decoder)?;
    if has_kdf {
        expect_key(decoder, "algorithm")?;
        if decoder.str().map_err(invalid)? != "argon2id-v1.3" {
            return Err(CryptoError::InvalidKdf);
        }
        let kdf_profile = KdfProfile {
            memory_mib: memory.ok_or(CryptoError::InvalidKdf)?,
            passes: passes.ok_or(CryptoError::InvalidKdf)?,
        };
        kdf_profile.validate()?;
        profile = Some(kdf_profile);
    }
    let target_object = if is_wrapper {
        expect_key(decoder, "target_object")?;
        decode_bytes(decoder)?
    } else {
        object
    };
    expect_key(decoder, "key_generation")?;
    let key_generation = decoder.u64().map_err(invalid)?;
    let wrapped_purpose = if is_wrapper {
        expect_key(decoder, "wrapped_purpose")?;
        Purpose::parse(decoder.str().map_err(invalid)?)?
    } else {
        purpose
    };
    Ok(Header {
        vault,
        object,
        revision,
        purpose,
        key_generation,
        target_object,
        wrapped_purpose,
        kdf: match (salt, profile) {
            (Some(salt), Some(profile)) => Some(KdfFields { salt, profile }),
            (None, None) => None,
            _ => return Err(CryptoError::InvalidKdf),
        },
    })
}

fn encode_wrapped_key(key: &Secret, target: &Header) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(2).expect("Vec writes cannot fail");
    encoder.str("key").expect("Vec writes cannot fail");
    encoder.bytes(&key.0).expect("Vec writes cannot fail");
    encoder
        .str("target_header")
        .expect("Vec writes cannot fail");
    encode_header(&mut encoder, target);
    encoder.into_writer()
}

fn decode_wrapped_key(bytes: &[u8]) -> Result<(Secret, Header), CryptoError> {
    let mut decoder = Decoder::new(bytes);
    expect_map(&mut decoder, 2)?;
    expect_key(&mut decoder, "key")?;
    let key = Secret(decode_bytes(&mut decoder)?);
    expect_key(&mut decoder, "target_header")?;
    let target = decode_header(&mut decoder)?;
    if decoder.position() != bytes.len() || encode_wrapped_key(&key, &target) != bytes {
        return Err(CryptoError::InvalidFormat);
    }
    Ok((key, target))
}

fn encode_sealed_key(
    key: &Secret,
    target: &Header,
    recipient: &[u8; 16],
    generation: u64,
) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(4).expect("Vec writes cannot fail");
    encoder.str("key").expect("Vec writes cannot fail");
    encoder.bytes(&key.0).expect("Vec writes cannot fail");
    encoder.str("recipient").expect("Vec writes cannot fail");
    encoder.bytes(recipient).expect("Vec writes cannot fail");
    encoder
        .str("target_header")
        .expect("Vec writes cannot fail");
    encode_header(&mut encoder, target);
    encoder
        .str("authorization_generation")
        .expect("Vec writes cannot fail");
    encoder.u64(generation).expect("Vec writes cannot fail");
    encoder.into_writer()
}

fn decode_sealed_key_context(bytes: &[u8]) -> Result<(Header, [u8; 16], u64), CryptoError> {
    let mut decoder = Decoder::new(bytes);
    expect_map(&mut decoder, 4)?;
    expect_key(&mut decoder, "key")?;
    let _: [u8; 32] = decode_bytes(&mut decoder)?;
    expect_key(&mut decoder, "recipient")?;
    let recipient = decode_bytes(&mut decoder)?;
    expect_key(&mut decoder, "target_header")?;
    let target = decode_header(&mut decoder)?;
    expect_key(&mut decoder, "authorization_generation")?;
    let generation = decoder.u64().map_err(invalid)?;
    if decoder.position() != bytes.len() {
        return Err(CryptoError::InvalidFormat);
    }
    Ok((target, recipient, generation))
}

fn encode_grant_fields(fields: &GrantFields) -> Vec<u8> {
    if fields.authority_event.is_some() {
        encode_grant_with_event(fields)
    } else {
        encode_grant_without_event(fields)
    }
}

fn encode_grant_without_event(fields: &GrantFields) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(9).expect("Vec writes cannot fail");
    encode_grant_prefix(&mut encoder, fields);
    encoder
        .str("authorization_generation")
        .expect("Vec writes cannot fail");
    encoder
        .u64(fields.authorization_generation)
        .expect("Vec writes cannot fail");
    encoder.into_writer()
}

fn encode_grant_with_event(fields: &GrantFields) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(10).expect("Vec writes cannot fail");
    encode_grant_prefix(&mut encoder, fields);
    encoder
        .str("authority_event")
        .expect("Vec writes cannot fail");
    encoder
        .bytes(
            fields
                .authority_event
                .as_ref()
                .expect("full grant has event"),
        )
        .expect("Vec writes cannot fail");
    encoder
        .str("authorization_generation")
        .expect("Vec writes cannot fail");
    encoder
        .u64(fields.authorization_generation)
        .expect("Vec writes cannot fail");
    encoder.into_writer()
}

fn encode_grant_prefix(encoder: &mut Encoder<Vec<u8>>, fields: &GrantFields) {
    encoder.str("v").expect("Vec writes cannot fail");
    encoder.u64(FORMAT_VERSION).expect("Vec writes cannot fail");
    encoder.str("item").expect("Vec writes cannot fail");
    encoder.bytes(&fields.item).expect("Vec writes cannot fail");
    encoder.str("vault").expect("Vec writes cannot fail");
    encoder
        .bytes(&fields.vault)
        .expect("Vec writes cannot fail");
    encoder.str("revision").expect("Vec writes cannot fail");
    encoder
        .bytes(&fields.revision)
        .expect("Vec writes cannot fail");
    encoder.str("recipient").expect("Vec writes cannot fail");
    encoder
        .bytes(&fields.recipient)
        .expect("Vec writes cannot fail");
    encoder.str("sealed_box").expect("Vec writes cannot fail");
    encoder
        .bytes(&fields.sealed_box)
        .expect("Vec writes cannot fail");
    encoder
        .str("target_header")
        .expect("Vec writes cannot fail");
    encode_header(encoder, &fields.target_header);
    encoder
        .str("payload_sha256")
        .expect("Vec writes cannot fail");
    encoder
        .bytes(&fields.payload_sha256)
        .expect("Vec writes cannot fail");
}

fn encode_grant_signature_message(fields: &GrantFields) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.array(2).expect("Vec writes cannot fail");
    encoder.str("pm/grant/v1").expect("Vec writes cannot fail");
    let grant = encode_grant_with_event(fields);
    encoder.writer_mut().extend_from_slice(&grant);
    encoder.into_writer()
}

fn encode_signed_grant(grant: &SignedGrantVector) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(2).expect("Vec writes cannot fail");
    encoder.str("grant").expect("Vec writes cannot fail");
    encoder
        .bytes(&encode_grant_with_event(&grant.fields))
        .expect("Vec writes cannot fail");
    encoder.str("signature").expect("Vec writes cannot fail");
    encoder
        .bytes(&grant.signature)
        .expect("Vec writes cannot fail");
    encoder.into_writer()
}

fn decode_signed_grant(bytes: &[u8]) -> Result<SignedGrantVector, CryptoError> {
    if bytes.len() > MAX_OBJECT_BYTES {
        return Err(CryptoError::InvalidFormat);
    }
    let mut decoder = Decoder::new(bytes);
    expect_map(&mut decoder, 2)?;
    expect_key(&mut decoder, "grant")?;
    let grant_bytes = decoder.bytes().map_err(invalid)?;
    let fields = decode_grant_with_event(grant_bytes)?;
    expect_key(&mut decoder, "signature")?;
    let signature = decode_bytes(&mut decoder)?;
    if decoder.position() != bytes.len() {
        return Err(CryptoError::InvalidFormat);
    }
    let signed = SignedGrantVector {
        commitment: sha256(&encode_grant_without_event(&fields)),
        fields,
        signature,
    };
    if encode_signed_grant(&signed) != bytes {
        return Err(CryptoError::InvalidFormat);
    }
    Ok(signed)
}

fn decode_grant_with_event(bytes: &[u8]) -> Result<GrantFields, CryptoError> {
    let mut decoder = Decoder::new(bytes);
    expect_map(&mut decoder, 10)?;
    expect_key(&mut decoder, "v")?;
    if decoder.u64().map_err(invalid)? != FORMAT_VERSION {
        return Err(CryptoError::InvalidFormat);
    }
    expect_key(&mut decoder, "item")?;
    let item = decode_bytes(&mut decoder)?;
    expect_key(&mut decoder, "vault")?;
    let vault = decode_bytes(&mut decoder)?;
    expect_key(&mut decoder, "revision")?;
    let revision = decode_bytes(&mut decoder)?;
    expect_key(&mut decoder, "recipient")?;
    let recipient = decode_bytes(&mut decoder)?;
    expect_key(&mut decoder, "sealed_box")?;
    let sealed_box = decoder.bytes().map_err(invalid)?.to_vec();
    expect_key(&mut decoder, "target_header")?;
    let target_header = decode_header(&mut decoder)?;
    expect_key(&mut decoder, "payload_sha256")?;
    let payload_sha256 = decode_bytes(&mut decoder)?;
    expect_key(&mut decoder, "authority_event")?;
    let authority_event = Some(decode_bytes(&mut decoder)?);
    expect_key(&mut decoder, "authorization_generation")?;
    let authorization_generation = decoder.u64().map_err(invalid)?;
    if decoder.position() != bytes.len() {
        return Err(CryptoError::InvalidFormat);
    }
    let fields = GrantFields {
        vault,
        item,
        revision,
        recipient,
        authorization_generation,
        target_header,
        payload_sha256,
        sealed_box,
        authority_event,
    };
    if encode_grant_with_event(&fields) != bytes {
        return Err(CryptoError::InvalidFormat);
    }
    Ok(fields)
}

fn sign_detached(seed: &Secret, message: &[u8]) -> Result<[u8; 64], CryptoError> {
    let mut public = [0_u8; 32];
    let mut expanded = [0_u8; 64];
    if unsafe {
        // SAFETY: key buffers have the documented Ed25519 sizes.
        libsodium_sys::crypto_sign_seed_keypair(
            public.as_mut_ptr(),
            expanded.as_mut_ptr(),
            seed.0.as_ptr(),
        )
    } != 0
    {
        return Err(CryptoError::Authentication);
    }
    let mut signature = [0_u8; 64];
    let mut signature_len = 0_u64;
    let result = unsafe {
        // SAFETY: signature/message/secret buffers are valid for supplied sizes.
        libsodium_sys::crypto_sign_detached(
            signature.as_mut_ptr(),
            &raw mut signature_len,
            message.as_ptr(),
            message.len() as u64,
            expanded.as_ptr(),
        )
    };
    // SAFETY: expanded secret is no longer used.
    unsafe { libsodium_sys::sodium_memzero(expanded.as_mut_ptr().cast(), expanded.len()) };
    if result != 0 || signature_len != 64 {
        return Err(CryptoError::Authentication);
    }
    Ok(signature)
}

fn seal_pmf1(key: &Secret, header: &Header, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    sodium()?;
    let mut state = SecretStreamState::new();
    let mut stream_header = [0_u8; 24];
    let initialized = unsafe {
        // SAFETY: state/header/key buffers have exact documented sizes.
        libsodium_sys::crypto_secretstream_xchacha20poly1305_init_push(
            &raw mut state.0,
            stream_header.as_mut_ptr(),
            key.0.as_ptr(),
        )
    };
    if initialized != 0 {
        return Err(CryptoError::RandomUnavailable);
    }
    let header_bytes = encode_pmf1_header(header, &stream_header);
    if header_bytes.len() > MAX_HEADER_BYTES {
        return Err(CryptoError::InvalidFormat);
    }
    let mut output = Vec::with_capacity(8 + header_bytes.len() + plaintext.len() + 64);
    output.extend_from_slice(b"PMF1");
    output.extend_from_slice(
        &u32::try_from(header_bytes.len())
            .expect("header is bounded to 4 KiB")
            .to_be_bytes(),
    );
    output.extend_from_slice(&header_bytes);
    let chunk_count = plaintext.len().max(1).div_ceil(1024 * 1024);
    for index in 0..chunk_count {
        let start = index * 1024 * 1024;
        let end = plaintext.len().min(start + 1024 * 1024);
        let chunk = &plaintext[start.min(plaintext.len())..end];
        let aad = encode_file_aad(header, &stream_header, index as u64);
        let mut ciphertext = vec![0_u8; chunk.len() + 17];
        let mut ciphertext_len = 0_u64;
        let tag = if index + 1 == chunk_count {
            u8::try_from(libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_FINAL)
                .expect("libsodium tag fits u8")
        } else {
            u8::try_from(libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)
                .expect("libsodium tag fits u8")
        };
        let result = unsafe {
            // SAFETY: state and all buffers are valid for the declared lengths.
            libsodium_sys::crypto_secretstream_xchacha20poly1305_push(
                &raw mut state.0,
                ciphertext.as_mut_ptr(),
                &raw mut ciphertext_len,
                chunk.as_ptr(),
                chunk.len() as u64,
                aad.as_ptr(),
                aad.len() as u64,
                tag,
            )
        };
        if result != 0 || usize::try_from(ciphertext_len).ok() != Some(ciphertext.len()) {
            return Err(CryptoError::Authentication);
        }
        output.extend_from_slice(
            &u32::try_from(ciphertext.len())
                .expect("ciphertext chunk is bounded")
                .to_be_bytes(),
        );
        output.extend_from_slice(&ciphertext);
    }
    Ok(output)
}

#[allow(clippy::too_many_lines)]
fn open_pmf1(key: &Secret, bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    sodium()?;
    if bytes.len() < 8
        || bytes.len() > MAX_OBJECT_BYTES + MAX_HEADER_BYTES
        || &bytes[..4] != b"PMF1"
    {
        return Err(CryptoError::InvalidFormat);
    }
    let header_len = usize::try_from(u32::from_be_bytes(bytes[4..8].try_into().map_err(invalid)?))
        .map_err(invalid)?;
    if header_len > MAX_HEADER_BYTES || bytes.len() < 8 + header_len {
        return Err(CryptoError::InvalidFormat);
    }
    let (header, stream_header) = decode_pmf1_header(&bytes[8..8 + header_len])?;
    if header.purpose != Purpose::File || header.kdf.is_some() {
        return Err(CryptoError::InvalidFormat);
    }
    let mut state = SecretStreamState::new();
    if unsafe {
        // SAFETY: state/header/key buffers have exact documented sizes.
        libsodium_sys::crypto_secretstream_xchacha20poly1305_init_pull(
            &raw mut state.0,
            stream_header.as_ptr(),
            key.0.as_ptr(),
        )
    } != 0
    {
        return Err(CryptoError::Authentication);
    }
    let mut position = 8 + header_len;
    let mut index = 0_u64;
    let mut plaintext = Vec::new();
    loop {
        if bytes.len() < position + 4 {
            return Err(CryptoError::InvalidFormat);
        }
        let ciphertext_len = usize::try_from(u32::from_be_bytes(
            bytes[position..position + 4].try_into().map_err(invalid)?,
        ))
        .map_err(invalid)?;
        position += 4;
        if !(17..=1024 * 1024 + 17).contains(&ciphertext_len)
            || bytes.len() < position + ciphertext_len
        {
            return Err(CryptoError::InvalidFormat);
        }
        let ciphertext = &bytes[position..position + ciphertext_len];
        position += ciphertext_len;
        let aad = encode_file_aad(&header, &stream_header, index);
        let mut chunk = vec![0_u8; ciphertext_len - 17];
        let mut chunk_len = 0_u64;
        let mut tag = 0_u8;
        let result = unsafe {
            // SAFETY: state and every buffer are valid for the supplied length.
            libsodium_sys::crypto_secretstream_xchacha20poly1305_pull(
                &raw mut state.0,
                chunk.as_mut_ptr(),
                &raw mut chunk_len,
                &raw mut tag,
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                aad.as_ptr(),
                aad.len() as u64,
            )
        };
        if result != 0 || usize::try_from(chunk_len).ok() != Some(chunk.len()) {
            return Err(CryptoError::Authentication);
        }
        plaintext.extend_from_slice(&chunk);
        if plaintext.len() > MAX_OBJECT_BYTES {
            wipe_vec(&mut plaintext);
            return Err(CryptoError::InvalidFormat);
        }
        if tag
            == u8::try_from(libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_FINAL)
                .expect("libsodium tag fits u8")
        {
            if position != bytes.len() {
                return Err(CryptoError::InvalidFormat);
            }
            break;
        }
        if tag
            != u8::try_from(libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)
                .expect("libsodium tag fits u8")
        {
            return Err(CryptoError::InvalidFormat);
        }
        index = index.checked_add(1).ok_or(CryptoError::InvalidFormat)?;
    }
    Ok(plaintext)
}

fn encode_pmf1_header(header: &Header, stream_header: &[u8; 24]) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(2).expect("Vec writes cannot fail");
    encoder.str("header").expect("Vec writes cannot fail");
    encode_header(&mut encoder, header);
    encoder
        .str("stream_header")
        .expect("Vec writes cannot fail");
    encoder
        .bytes(stream_header)
        .expect("Vec writes cannot fail");
    encoder.into_writer()
}

fn decode_pmf1_header(bytes: &[u8]) -> Result<(Header, [u8; 24]), CryptoError> {
    let mut decoder = Decoder::new(bytes);
    expect_map(&mut decoder, 2)?;
    expect_key(&mut decoder, "header")?;
    let header = decode_header(&mut decoder)?;
    expect_key(&mut decoder, "stream_header")?;
    let stream_header = decode_bytes(&mut decoder)?;
    if decoder.position() != bytes.len() || encode_pmf1_header(&header, &stream_header) != bytes {
        return Err(CryptoError::InvalidFormat);
    }
    Ok((header, stream_header))
}

fn encode_file_aad(header: &Header, stream_header: &[u8; 24], index: u64) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.array(4).expect("Vec writes cannot fail");
    encoder.str("pm/file/v1").expect("Vec writes cannot fail");
    encode_header(&mut encoder, header);
    encoder
        .bytes(stream_header)
        .expect("Vec writes cannot fail");
    encoder.u64(index).expect("Vec writes cannot fail");
    encoder.into_writer()
}

fn validate_revision_input(input: &RevisionPackageInput<'_>) -> Result<(), CryptoError> {
    if input.human_plaintext.len() > MAX_OBJECT_BYTES
        || input
            .auth_plaintext
            .is_some_and(|value| value.len() > MAX_OBJECT_BYTES)
        || input.kind.requires_auth() != input.auth_plaintext.is_some()
    {
        return Err(CryptoError::InvalidFormat);
    }
    Ok(())
}

fn manifest_part(ciphertext: &Envelope, key_envelope: &Envelope) -> ManifestPart {
    let ciphertext_bytes = encode_envelope(ciphertext);
    let key_envelope_bytes = encode_envelope(key_envelope);
    ManifestPart {
        object_id: ciphertext.header.object,
        ciphertext_sha256: sha256(&ciphertext_bytes),
        ciphertext_length: ciphertext_bytes.len() as u64,
        key_envelope_digest: sha256(&key_envelope_bytes),
    }
}

fn validate_manifest(
    vault: [u8; ID_BYTES],
    manifest: &RevisionManifest,
    package: &RevisionPackage,
) -> Result<(), CryptoError> {
    if manifest.vault != vault
        || manifest.revision != package.human_ciphertext.header.revision
        || manifest.revision != package.manifest_ciphertext.header.revision
        || manifest.human_part
            != manifest_part(&package.human_ciphertext, &package.human_key_envelope)
        || manifest.kind.requires_auth() != manifest.auth_part.is_some()
    {
        return Err(CryptoError::Authentication);
    }
    match (
        &manifest.auth_part,
        &package.auth_ciphertext,
        &package.auth_key_envelope,
    ) {
        (Some(expected), Some(ciphertext), Some(envelope))
            if *expected == manifest_part(ciphertext, envelope)
                && ciphertext.header.revision == manifest.revision => {}
        (None, None, None) => {}
        _ => return Err(CryptoError::Authentication),
    }
    Ok(())
}

fn encode_revision_package(package: &RevisionPackage) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(7).expect("Vec writes cannot fail");
    encoder.str("v").expect("Vec writes cannot fail");
    encoder.u64(FORMAT_VERSION).expect("Vec writes cannot fail");
    encoder
        .str("auth_ciphertext")
        .expect("Vec writes cannot fail");
    encode_optional_envelope(&mut encoder, package.auth_ciphertext.as_ref());
    encoder
        .str("human_ciphertext")
        .expect("Vec writes cannot fail");
    encoder
        .bytes(&encode_envelope(&package.human_ciphertext))
        .expect("Vec writes cannot fail");
    encoder
        .str("auth_key_envelope")
        .expect("Vec writes cannot fail");
    encode_optional_envelope(&mut encoder, package.auth_key_envelope.as_ref());
    encoder
        .str("human_key_envelope")
        .expect("Vec writes cannot fail");
    encoder
        .bytes(&encode_envelope(&package.human_key_envelope))
        .expect("Vec writes cannot fail");
    encoder
        .str("manifest_ciphertext")
        .expect("Vec writes cannot fail");
    encoder
        .bytes(&encode_envelope(&package.manifest_ciphertext))
        .expect("Vec writes cannot fail");
    encoder
        .str("manifest_key_envelope")
        .expect("Vec writes cannot fail");
    encoder
        .bytes(&encode_envelope(&package.manifest_key_envelope))
        .expect("Vec writes cannot fail");
    encoder.into_writer()
}

fn decode_revision_package(bytes: &[u8]) -> Result<RevisionPackage, CryptoError> {
    let mut decoder = Decoder::new(bytes);
    expect_map(&mut decoder, 7)?;
    expect_key(&mut decoder, "v")?;
    if decoder.u64().map_err(invalid)? != FORMAT_VERSION {
        return Err(CryptoError::InvalidFormat);
    }
    expect_key(&mut decoder, "auth_ciphertext")?;
    let auth_ciphertext = decode_optional_envelope(&mut decoder)?;
    expect_key(&mut decoder, "human_ciphertext")?;
    let human_ciphertext = decode_envelope(decoder.bytes().map_err(invalid)?)?;
    expect_key(&mut decoder, "auth_key_envelope")?;
    let auth_key_envelope = decode_optional_envelope(&mut decoder)?;
    expect_key(&mut decoder, "human_key_envelope")?;
    let human_key_envelope = decode_envelope(decoder.bytes().map_err(invalid)?)?;
    expect_key(&mut decoder, "manifest_ciphertext")?;
    let manifest_ciphertext = decode_envelope(decoder.bytes().map_err(invalid)?)?;
    expect_key(&mut decoder, "manifest_key_envelope")?;
    let manifest_key_envelope = decode_envelope(decoder.bytes().map_err(invalid)?)?;
    if decoder.position() != bytes.len() {
        return Err(CryptoError::InvalidFormat);
    }
    Ok(RevisionPackage {
        human_ciphertext,
        auth_ciphertext,
        manifest_ciphertext,
        human_key_envelope,
        auth_key_envelope,
        manifest_key_envelope,
    })
}

fn encode_optional_envelope(encoder: &mut Encoder<Vec<u8>>, envelope: Option<&Envelope>) {
    if let Some(envelope) = envelope {
        encoder
            .bytes(&encode_envelope(envelope))
            .expect("Vec writes cannot fail");
    } else {
        encoder.null().expect("Vec writes cannot fail");
    }
}

fn decode_optional_envelope(decoder: &mut Decoder<'_>) -> Result<Option<Envelope>, CryptoError> {
    if decoder.datatype().map_err(invalid)? == Type::Null {
        decoder.null().map_err(invalid)?;
        Ok(None)
    } else {
        Ok(Some(decode_envelope(decoder.bytes().map_err(invalid)?)?))
    }
}

fn encode_manifest(manifest: &RevisionManifest) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(10).expect("Vec writes cannot fail");
    encoder.str("v").expect("Vec writes cannot fail");
    encoder.u64(FORMAT_VERSION).expect("Vec writes cannot fail");
    encoder.str("item").expect("Vec writes cannot fail");
    encoder
        .bytes(&manifest.item)
        .expect("Vec writes cannot fail");
    encoder.str("kind").expect("Vec writes cannot fail");
    encoder
        .str(manifest.kind.name())
        .expect("Vec writes cannot fail");
    encoder.str("vault").expect("Vec writes cannot fail");
    encoder
        .bytes(&manifest.vault)
        .expect("Vec writes cannot fail");
    encoder.str("revision").expect("Vec writes cannot fail");
    encoder
        .bytes(&manifest.revision)
        .expect("Vec writes cannot fail");
    encoder.str("auth_part").expect("Vec writes cannot fail");
    if let Some(part) = &manifest.auth_part {
        encode_manifest_part(&mut encoder, part);
    } else {
        encoder.null().expect("Vec writes cannot fail");
    }
    encoder.str("human_part").expect("Vec writes cannot fail");
    encode_manifest_part(&mut encoder, &manifest.human_part);
    encoder.str("attachments").expect("Vec writes cannot fail");
    encoder.array(0).expect("Vec writes cannot fail");
    encoder.str("modified_at").expect("Vec writes cannot fail");
    encoder
        .i64(manifest.modified_at)
        .expect("Vec writes cannot fail");
    encoder
        .str("issuer_device")
        .expect("Vec writes cannot fail");
    encoder
        .bytes(&manifest.issuer_device)
        .expect("Vec writes cannot fail");
    encoder.into_writer()
}

fn decode_manifest(bytes: &[u8]) -> Result<RevisionManifest, CryptoError> {
    let mut decoder = Decoder::new(bytes);
    expect_map(&mut decoder, 10)?;
    expect_key(&mut decoder, "v")?;
    if decoder.u64().map_err(invalid)? != FORMAT_VERSION {
        return Err(CryptoError::InvalidFormat);
    }
    expect_key(&mut decoder, "item")?;
    let item = decode_bytes(&mut decoder)?;
    expect_key(&mut decoder, "kind")?;
    let kind = ItemKind::parse(decoder.str().map_err(invalid)?)?;
    expect_key(&mut decoder, "vault")?;
    let vault = decode_bytes(&mut decoder)?;
    expect_key(&mut decoder, "revision")?;
    let revision = decode_bytes(&mut decoder)?;
    expect_key(&mut decoder, "auth_part")?;
    let auth_part = if decoder.datatype().map_err(invalid)? == Type::Null {
        decoder.null().map_err(invalid)?;
        None
    } else {
        Some(decode_manifest_part(&mut decoder)?)
    };
    expect_key(&mut decoder, "human_part")?;
    let human_part = decode_manifest_part(&mut decoder)?;
    expect_key(&mut decoder, "attachments")?;
    if decoder.array().map_err(invalid)? != Some(0) {
        return Err(CryptoError::InvalidFormat);
    }
    expect_key(&mut decoder, "modified_at")?;
    let modified_at = decoder.i64().map_err(invalid)?;
    expect_key(&mut decoder, "issuer_device")?;
    let issuer_device = decode_bytes(&mut decoder)?;
    if decoder.position() != bytes.len() {
        return Err(CryptoError::InvalidFormat);
    }
    let manifest = RevisionManifest {
        vault,
        item,
        revision,
        issuer_device,
        modified_at,
        kind,
        human_part,
        auth_part,
    };
    if encode_manifest(&manifest) != bytes {
        return Err(CryptoError::InvalidFormat);
    }
    Ok(manifest)
}

fn encode_manifest_part(encoder: &mut Encoder<Vec<u8>>, part: &ManifestPart) {
    encoder.map(4).expect("Vec writes cannot fail");
    encoder.str("object_id").expect("Vec writes cannot fail");
    encoder
        .bytes(&part.object_id)
        .expect("Vec writes cannot fail");
    encoder
        .str("ciphertext_length")
        .expect("Vec writes cannot fail");
    encoder
        .u64(part.ciphertext_length)
        .expect("Vec writes cannot fail");
    encoder
        .str("ciphertext_sha256")
        .expect("Vec writes cannot fail");
    encoder
        .bytes(&part.ciphertext_sha256)
        .expect("Vec writes cannot fail");
    encoder
        .str("key_envelope_digest")
        .expect("Vec writes cannot fail");
    encoder
        .bytes(&part.key_envelope_digest)
        .expect("Vec writes cannot fail");
}

fn decode_manifest_part(decoder: &mut Decoder<'_>) -> Result<ManifestPart, CryptoError> {
    expect_map(decoder, 4)?;
    expect_key(decoder, "object_id")?;
    let object_id = decode_bytes(decoder)?;
    expect_key(decoder, "ciphertext_length")?;
    let ciphertext_length = decoder.u64().map_err(invalid)?;
    expect_key(decoder, "ciphertext_sha256")?;
    let ciphertext_sha256 = decode_bytes(decoder)?;
    expect_key(decoder, "key_envelope_digest")?;
    let key_envelope_digest = decode_bytes(decoder)?;
    Ok(ManifestPart {
        object_id,
        ciphertext_sha256,
        ciphertext_length,
        key_envelope_digest,
    })
}

fn wipe_vec(value: &mut Vec<u8>) {
    if !value.is_empty() {
        // SAFETY: the allocation is valid for its length and is not read again.
        unsafe { libsodium_sys::sodium_memzero(value.as_mut_ptr().cast(), value.len()) };
    }
}

fn recovery_checksum(code: &RecoveryCode) -> [u8; 4] {
    let mut encoder = Encoder::new(Vec::new());
    encoder.array(4).expect("Vec writes cannot fail");
    encoder
        .str("pm/recovery/v1")
        .expect("Vec writes cannot fail");
    encoder.bytes(&code.vault).expect("Vec writes cannot fail");
    encoder
        .u64(code.generation)
        .expect("Vec writes cannot fail");
    encoder.bytes(&code.key.0).expect("Vec writes cannot fail");
    let digest = sha256(&encoder.into_writer());
    digest[..4].try_into().expect("fixed digest size")
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut digest = [0_u8; 32];
    // SAFETY: input and fixed-size output are valid for their lengths.
    let result = unsafe {
        libsodium_sys::crypto_hash_sha256(digest.as_mut_ptr(), bytes.as_ptr(), bytes.len() as u64)
    };
    debug_assert_eq!(result, 0);
    digest
}

fn expect_map(decoder: &mut Decoder<'_>, fields: u64) -> Result<(), CryptoError> {
    if decoder.map().map_err(invalid)? != Some(fields) {
        return Err(CryptoError::InvalidFormat);
    }
    Ok(())
}

fn expect_key(decoder: &mut Decoder<'_>, expected: &str) -> Result<(), CryptoError> {
    if decoder.datatype().map_err(invalid)? != Type::String
        || decoder.str().map_err(invalid)? != expected
    {
        return Err(CryptoError::InvalidFormat);
    }
    Ok(())
}

fn decode_bytes<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], CryptoError> {
    decoder
        .bytes()
        .map_err(invalid)?
        .try_into()
        .map_err(|_| CryptoError::InvalidFormat)
}

fn invalid<T>(_: T) -> CryptoError {
    CryptoError::InvalidFormat
}

fn hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(ALPHABET[usize::from(byte >> 4)]));
        encoded.push(char::from(ALPHABET[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex_array<const N: usize>(value: &str) -> Result<[u8; N], CryptoError> {
    if value.len() != N * 2 || !value.is_ascii() {
        return Err(CryptoError::InvalidFormat);
    }
    let mut decoded = [0_u8; N];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(decoded)
}

fn hex_nibble(value: u8) -> Result<u8, CryptoError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(CryptoError::InvalidFormat),
    }
}
