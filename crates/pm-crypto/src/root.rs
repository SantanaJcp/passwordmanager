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
const FILE_CHUNK_BYTES: usize = 1024 * 1024;

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

/// Human-authorized E2EE material shared out-of-band by paired custodians.
pub struct SyncPairing {
    vault: [u8; ID_BYTES],
    namespace: [u8; KEY_BYTES],
    server_pin: [u8; 44],
    key: Secret,
    human_signature: [u8; 64],
}

impl SyncPairing {
    #[must_use]
    pub const fn namespace(&self) -> &[u8; KEY_BYTES] {
        &self.namespace
    }
    #[must_use]
    pub const fn server_pin(&self) -> &[u8; 44] {
        &self.server_pin
    }

    /// Serializes pairing material for caller-enforced native/human custody.
    ///
    /// # Panics
    /// Encoding into an in-memory `Vec` is infallible.
    #[must_use]
    pub fn to_protected_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(6)
            .unwrap()
            .str("pm/sync-pairing/v1")
            .unwrap()
            .bytes(&self.vault)
            .unwrap()
            .bytes(&self.namespace)
            .unwrap()
            .bytes(&self.server_pin)
            .unwrap()
            .bytes(&self.key.0)
            .unwrap()
            .bytes(&self.human_signature)
            .unwrap();
        e.into_writer()
    }

    /// Imports pairing material only when its human signature and root match.
    ///
    /// # Errors
    /// Rejects malformed, non-canonical, wrong-vault, or altered material.
    pub fn from_protected_bytes(bytes: &[u8], trusted: &TrustedRoot) -> Result<Self, CryptoError> {
        let mut d = Decoder::new(bytes);
        if d.array().map_err(|_| CryptoError::InvalidFormat)? != Some(6)
            || d.str().map_err(|_| CryptoError::InvalidFormat)? != "pm/sync-pairing/v1"
        {
            return Err(CryptoError::InvalidFormat);
        }
        let vault = decode_bytes(&mut d)?;
        let namespace = decode_bytes(&mut d)?;
        let server_pin = decode_bytes(&mut d)?;
        let key = Secret(decode_bytes(&mut d)?);
        let human_signature = decode_bytes(&mut d)?;
        let value = Self {
            vault,
            namespace,
            server_pin,
            key,
            human_signature,
        };
        if d.position() != bytes.len()
            || value.to_protected_bytes() != bytes
            || vault != trusted.vault_id
        {
            return Err(CryptoError::Authentication);
        }
        verify_human_signature(
            trusted,
            &domain_message(b"pm/sync-pairing/v1", &value.unsigned_bytes()),
            &human_signature,
        )?;
        Ok(value)
    }

    /// Encrypts one opaque synchronization object under the pairing key.
    ///
    /// # Errors
    /// Rejects objects above 512 KiB or unavailable cryptography.
    ///
    /// # Panics
    /// Encoding into an in-memory `Vec` is infallible.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if plaintext.len() > 512 * 1024 - TAG_BYTES - 64 {
            return Err(CryptoError::InvalidFormat);
        }
        sodium()?;
        let nonce: [u8; NONCE_BYTES] = random_array()?;
        let aad = self.unsigned_bytes();
        let mut cipher = vec![0; plaintext.len() + TAG_BYTES];
        let mut n = 0_u64;
        let result = unsafe {
            libsodium_sys::crypto_aead_xchacha20poly1305_ietf_encrypt(
                cipher.as_mut_ptr(),
                &raw mut n,
                plaintext.as_ptr(),
                plaintext.len() as u64,
                aad.as_ptr(),
                aad.len() as u64,
                std::ptr::null(),
                nonce.as_ptr(),
                self.key.0.as_ptr(),
            )
        };
        if result != 0 || usize::try_from(n).ok() != Some(cipher.len()) {
            return Err(CryptoError::Authentication);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(3)
            .unwrap()
            .u64(1)
            .unwrap()
            .bytes(&nonce)
            .unwrap()
            .bytes(&cipher)
            .unwrap();
        Ok(e.into_writer())
    }

    /// Authenticates and decrypts one complete opaque synchronization object.
    ///
    /// # Errors
    /// Rejects malformed, oversized, truncated, or altered ciphertext.
    pub fn open(&self, bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if bytes.len() > 512 * 1024 {
            return Err(CryptoError::InvalidFormat);
        }
        let mut d = Decoder::new(bytes);
        if d.array().map_err(|_| CryptoError::InvalidFormat)? != Some(3)
            || d.u64().map_err(|_| CryptoError::InvalidFormat)? != 1
        {
            return Err(CryptoError::InvalidFormat);
        }
        let nonce: [u8; NONCE_BYTES] = decode_bytes(&mut d)?;
        let cipher = d.bytes().map_err(|_| CryptoError::InvalidFormat)?;
        if d.position() != bytes.len() || cipher.len() < TAG_BYTES {
            return Err(CryptoError::InvalidFormat);
        }
        sodium()?;
        let aad = self.unsigned_bytes();
        let mut plain = vec![0; cipher.len() - TAG_BYTES];
        let mut n = 0_u64;
        let result = unsafe {
            libsodium_sys::crypto_aead_xchacha20poly1305_ietf_decrypt(
                plain.as_mut_ptr(),
                &raw mut n,
                std::ptr::null_mut(),
                cipher.as_ptr(),
                cipher.len() as u64,
                aad.as_ptr(),
                aad.len() as u64,
                nonce.as_ptr(),
                self.key.0.as_ptr(),
            )
        };
        if result != 0 || usize::try_from(n).ok() != Some(plain.len()) {
            wipe_vec(&mut plain);
            return Err(CryptoError::Authentication);
        }
        Ok(plain)
    }

    fn unsigned_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .str("pm/sync-pairing/v1")
            .unwrap()
            .bytes(&self.vault)
            .unwrap()
            .bytes(&self.namespace)
            .unwrap()
            .bytes(&self.server_pin)
            .unwrap()
            .bytes(&sha256(&self.key.0))
            .unwrap();
        e.into_writer()
    }
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
    authority_epoch: u64,
    human_public_key: [u8; KEY_BYTES],
    human_root: Secret,
    human_signing_seed: Secret,
}

impl UnlockedRoot {
    /// Creates a fresh namespace/key and binds the server pin with `SK_H`.
    ///
    /// # Errors
    /// Returns an error when secure randomness or signing is unavailable.
    pub fn create_sync_pairing(&self, server_pin: [u8; 44]) -> Result<SyncPairing, CryptoError> {
        let mut pairing = SyncPairing {
            vault: self.vault,
            namespace: random_array()?,
            server_pin,
            key: Secret::random()?,
            human_signature: [0; 64],
        };
        pairing.human_signature = sign_detached(
            &self.human_signing_seed,
            &domain_message(b"pm/sync-pairing/v1", &pairing.unsigned_bytes()),
        )?;
        Ok(pairing)
    }
    #[must_use]
    pub const fn vault_id(&self) -> &[u8; ID_BYTES] {
        &self.vault
    }

    #[must_use]
    pub const fn human_public_key(&self) -> &[u8; KEY_BYTES] {
        &self.human_public_key
    }

    #[must_use]
    pub const fn trusted_root(&self) -> TrustedRoot {
        TrustedRoot {
            vault_id: self.vault,
            epoch: self.authority_epoch,
            public_key: self.human_public_key,
        }
    }

    /// Signs only the fixed human-command domain; this is not a generic
    /// signing interface.
    ///
    /// # Errors
    ///
    /// Returns an error if native Ed25519 signing fails.
    pub fn sign_human_command(&self, command: &[u8]) -> Result<[u8; 64], CryptoError> {
        sign_detached(
            &self.human_signing_seed,
            &domain_message(b"pm/human-command/v1", command),
        )
    }

    /// Signs only the fixed human authority-event domain.
    ///
    /// # Errors
    ///
    /// Returns an error if native Ed25519 signing fails.
    pub fn sign_human_event(&self, event: &[u8]) -> Result<[u8; 64], CryptoError> {
        sign_detached(
            &self.human_signing_seed,
            &domain_message(b"pm/human-event/v1", event),
        )
    }

    /// Encrypts a bounded operational-control snapshot under a fresh `K_O`
    /// and seals that key to the enrolled device wrapping key.
    ///
    /// # Errors
    ///
    /// Returns an error for generation zero, oversized plaintext, unavailable
    /// randomness, or failed authenticated encryption/sealed-box creation.
    pub fn seal_control_package(
        &self,
        input: ControlPackageInput<'_>,
        recipient_public_key: &[u8; 32],
    ) -> Result<Vec<u8>, CryptoError> {
        if input.recipient_generation == 0 {
            return Err(CryptoError::InvalidFormat);
        }
        let target = target_header(
            self.vault,
            input.object,
            input.revision,
            Purpose::Control,
            input.recipient_generation,
        );
        let key = Secret::random()?;
        let envelope = seal(&key, target.clone(), input.plaintext)?;
        let mut key_plaintext =
            encode_sealed_key(&key, &target, &input.recipient, input.recipient_generation);
        let mut key_box = vec![0_u8; key_plaintext.len() + 48];
        let result = unsafe {
            // SAFETY: output/input/public-key buffers have documented sizes.
            libsodium_sys::crypto_box_seal(
                key_box.as_mut_ptr(),
                key_plaintext.as_ptr(),
                key_plaintext.len() as u64,
                recipient_public_key.as_ptr(),
            )
        };
        wipe_vec(&mut key_plaintext);
        if result != 0 {
            return Err(CryptoError::Authentication);
        }
        Ok(encode_control_package(&ControlPackage {
            recipient: input.recipient,
            recipient_generation: input.recipient_generation,
            envelope,
            key_box,
        }))
    }

    /// Creates one independent audit key with both a human-root envelope and
    /// a sealed device-custody envelope, then binds the complete package with
    /// the human authority signature.
    ///
    /// # Errors
    ///
    /// Returns an error for generation zero or unavailable native cryptography.
    pub fn provision_audit_key(
        &self,
        device: [u8; ID_BYTES],
        generation: u64,
        encryption_public_key: [u8; KEY_BYTES],
        signing_public_key: [u8; KEY_BYTES],
    ) -> Result<AuditKeyPackage, CryptoError> {
        if generation == 0 {
            return Err(CryptoError::InvalidFormat);
        }
        let key = Secret::random()?;
        let target = target_header(self.vault, device, device, Purpose::AuditRecord, generation);
        let mut human_wrapping = wrapping_header(
            self.vault,
            random_array()?,
            device,
            Purpose::KeyWrap,
            &target,
            None,
        );
        human_wrapping.key_generation = generation;
        let human_envelope =
            encode_envelope(&seal_key(&self.human_root, &key, &target, human_wrapping)?);
        let mut plaintext = encode_sealed_key(&key, &target, &device, generation);
        let mut device_envelope = vec![0_u8; plaintext.len() + 48];
        if unsafe {
            // SAFETY: sealed-box buffers and recipient public key have exact lengths.
            libsodium_sys::crypto_box_seal(
                device_envelope.as_mut_ptr(),
                plaintext.as_ptr(),
                plaintext.len() as u64,
                encryption_public_key.as_ptr(),
            )
        } != 0
        {
            wipe_vec(&mut plaintext);
            return Err(CryptoError::RandomUnavailable);
        }
        wipe_vec(&mut plaintext);
        let mut package = AuditKeyPackage {
            vault: self.vault,
            device,
            generation,
            encryption_public_key,
            signing_public_key,
            human_envelope,
            device_envelope,
            human_signature: [0_u8; 64],
        };
        package.human_signature = sign_detached(
            &self.human_signing_seed,
            &domain_message(b"pm/audit-key/v1", &package.unsigned_bytes()),
        )?;
        Ok(package)
    }

    /// Opens only a human audit-key envelope with its exact device/generation context.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, altered, or context-mismatched envelopes.
    pub fn open_audit_key(
        &self,
        human_envelope: &[u8],
        device: [u8; ID_BYTES],
        generation: u64,
    ) -> Result<AuditKey, CryptoError> {
        let envelope = decode_envelope(human_envelope)?;
        if encode_envelope(&envelope) != human_envelope {
            return Err(CryptoError::InvalidFormat);
        }
        let (key, target) = open_key(&self.human_root, &envelope)?;
        validate_audit_target(&target, self.vault, device, generation)?;
        Ok(AuditKey {
            vault: self.vault,
            generation,
            key,
        })
    }

    /// Verifies the complete human-authorized audit package before opening its
    /// human envelope. This binds both device public keys to `KAUD[d,g]`.
    ///
    /// # Errors
    ///
    /// Returns an error for a forged package, mismatched vault, or invalid envelope.
    pub fn open_audit_key_package(
        &self,
        package: &AuditKeyPackage,
    ) -> Result<AuditKey, CryptoError> {
        if package.vault != self.vault {
            return Err(CryptoError::Authentication);
        }
        verify_human_signature(
            &self.trusted_root(),
            &domain_message(b"pm/audit-key/v1", &package.unsigned_bytes()),
            &package.human_signature,
        )?;
        self.open_audit_key(&package.human_envelope, package.device, package.generation)
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
            kind: manifest.kind,
            human_plaintext,
            auth_plaintext,
        })
    }

    /// Encrypts one complete attachment with an independent `K_F`, PMF1
    /// framing and a human-root key envelope bound to its ID and revision.
    ///
    /// # Errors
    /// Returns an error for an oversized file or unavailable randomness.
    pub fn seal_file(
        &self,
        attachment: [u8; ID_BYTES],
        revision: [u8; ID_BYTES],
        plaintext: &[u8],
    ) -> Result<FileCiphertext, CryptoError> {
        if plaintext.len() > MAX_OBJECT_BYTES {
            return Err(CryptoError::InvalidFormat);
        }
        let target = target_header(self.vault, attachment, revision, Purpose::File, 1);
        let key = Secret::random()?;
        let stream = seal_pmf1(&key, &target, plaintext)?;
        let key_envelope = seal_key(
            &self.human_root,
            &key,
            &target,
            wrapping_header(
                self.vault,
                random_array()?,
                revision,
                Purpose::KeyWrap,
                &target,
                None,
            ),
        )?;
        Ok(FileCiphertext {
            key_envelope,
            stream,
        })
    }

    /// Authenticates an attachment package and its expected logical membership.
    ///
    /// # Errors
    /// Returns an error for altered bytes, wrong IDs/revision/purpose, or truncation.
    pub fn open_file(
        &self,
        expected_attachment: [u8; ID_BYTES],
        expected_revision: [u8; ID_BYTES],
        bytes: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let package = FileCiphertext::from_bytes(bytes)?;
        let (key, target) = open_key(&self.human_root, &package.key_envelope)?;
        let stream_header_len = usize::try_from(u32::from_be_bytes(
            package
                .stream
                .get(4..8)
                .ok_or(CryptoError::InvalidFormat)?
                .try_into()
                .map_err(invalid)?,
        ))
        .map_err(invalid)?;
        let header_end = 8_usize
            .checked_add(stream_header_len)
            .ok_or(CryptoError::InvalidFormat)?;
        let (stream_target, _) = decode_pmf1_header(
            package
                .stream
                .get(8..header_end)
                .ok_or(CryptoError::InvalidFormat)?,
        )?;
        if target != stream_target
            || target.vault != self.vault
            || target.object != expected_attachment
            || target.revision != expected_revision
            || target.purpose != Purpose::File
        {
            return Err(CryptoError::Authentication);
        }
        open_pmf1(&key, &package.stream)
    }

    /// Starts bounded-memory PMF1 encryption for one attachment.
    ///
    /// # Errors
    /// Returns an error when keys or secretstream state cannot be generated.
    pub fn start_file(
        &self,
        attachment: [u8; ID_BYTES],
        revision: [u8; ID_BYTES],
    ) -> Result<FileSealer, CryptoError> {
        let target = target_header(self.vault, attachment, revision, Purpose::File, 1);
        let key = Secret::random()?;
        let envelope = seal_key(
            &self.human_root,
            &key,
            &target,
            wrapping_header(
                self.vault,
                random_array()?,
                revision,
                Purpose::KeyWrap,
                &target,
                None,
            ),
        )?;
        FileSealer::new(&key, target, &envelope)
    }

    /// Opens and verifies a streaming file header before accepting chunks.
    ///
    /// # Errors
    /// Returns an error for altered or mismatched membership/key material.
    pub fn start_file_open(
        &self,
        attachment: [u8; ID_BYTES],
        revision: [u8; ID_BYTES],
        header: &[u8],
    ) -> Result<FileOpener, CryptoError> {
        FileOpener::new(&self.human_root, self.vault, attachment, revision, header)
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

    /// Completes a durably staged pending grant after its authority event is known.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed/noncanonical staged bytes or signing failure.
    pub fn finish_staged_grant_vector(
        &self,
        staged: &[u8],
        authority_event: [u8; 32],
    ) -> Result<SignedGrantVector, CryptoError> {
        self.finish_grant_vector(
            PendingGrantVector {
                fields: decode_grant_without_event(staged)?,
                commitment: sha256(staged),
            },
            authority_event,
        )
    }
}

/// Public and encrypted material needed to activate a per-device audit key.
/// Neither envelope is itself a plaintext key.
pub struct AuditKeyPackage {
    vault: [u8; ID_BYTES],
    device: [u8; ID_BYTES],
    generation: u64,
    encryption_public_key: [u8; KEY_BYTES],
    signing_public_key: [u8; KEY_BYTES],
    human_envelope: Vec<u8>,
    device_envelope: Vec<u8>,
    human_signature: [u8; 64],
}

impl AuditKeyPackage {
    /// Reconstructs a package loaded from bounded persistent fields.
    ///
    /// # Errors
    ///
    /// Returns an error for generation zero or invalid envelope lengths.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        vault: [u8; ID_BYTES],
        device: [u8; ID_BYTES],
        generation: u64,
        encryption_public_key: [u8; KEY_BYTES],
        signing_public_key: [u8; KEY_BYTES],
        human_envelope: Vec<u8>,
        device_envelope: Vec<u8>,
        human_signature: [u8; 64],
    ) -> Result<Self, CryptoError> {
        if generation == 0 || human_envelope.is_empty() || device_envelope.len() < 48 {
            return Err(CryptoError::InvalidFormat);
        }
        Ok(Self {
            vault,
            device,
            generation,
            encryption_public_key,
            signing_public_key,
            human_envelope,
            device_envelope,
            human_signature,
        })
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    #[must_use]
    pub fn human_envelope(&self) -> &[u8] {
        &self.human_envelope
    }
    #[must_use]
    pub fn device_envelope(&self) -> &[u8] {
        &self.device_envelope
    }
    #[must_use]
    pub const fn encryption_public_key(&self) -> &[u8; KEY_BYTES] {
        &self.encryption_public_key
    }
    #[must_use]
    pub const fn signing_public_key(&self) -> &[u8; KEY_BYTES] {
        &self.signing_public_key
    }
    #[must_use]
    pub const fn human_signature(&self) -> &[u8; 64] {
        &self.human_signature
    }

    fn unsigned_bytes(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(Vec::new());
        encoder.array(8).expect("Vec writes cannot fail");
        encoder
            .str("pm/audit-key-package/v1")
            .expect("Vec writes cannot fail");
        encoder.bytes(&self.vault).expect("Vec writes cannot fail");
        encoder.bytes(&self.device).expect("Vec writes cannot fail");
        encoder
            .u64(self.generation)
            .expect("Vec writes cannot fail");
        encoder
            .bytes(&self.encryption_public_key)
            .expect("Vec writes cannot fail");
        encoder
            .bytes(&self.signing_public_key)
            .expect("Vec writes cannot fail");
        encoder
            .bytes(&self.human_envelope)
            .expect("Vec writes cannot fail");
        encoder
            .bytes(&self.device_envelope)
            .expect("Vec writes cannot fail");
        encoder.into_writer()
    }
}

/// Device-held X25519 envelope key plus independent Ed25519 audit provenance seed.
pub struct AuditDeviceKeyPair {
    encryption_public_key: [u8; KEY_BYTES],
    encryption_private_key: Secret,
    signing_public_key: [u8; KEY_BYTES],
    signing_seed: Secret,
}

impl AuditDeviceKeyPair {
    /// Generates independent device encryption and signing keys.
    ///
    /// # Errors
    ///
    /// Returns an error when native randomness or key generation is unavailable.
    pub fn generate() -> Result<Self, CryptoError> {
        sodium()?;
        let mut encryption_public_key = [0_u8; KEY_BYTES];
        let mut encryption_private_key = Secret([0_u8; KEY_BYTES]);
        if unsafe {
            // SAFETY: crypto_box key buffers have their documented exact lengths.
            libsodium_sys::crypto_box_keypair(
                encryption_public_key.as_mut_ptr(),
                encryption_private_key.0.as_mut_ptr(),
            )
        } != 0
        {
            return Err(CryptoError::RandomUnavailable);
        }
        let signing_seed = Secret::random()?;
        let mut signing_public_key = [0_u8; KEY_BYTES];
        let mut expanded = [0_u8; 64];
        if unsafe {
            // SAFETY: Ed25519 key buffers have their documented exact lengths.
            libsodium_sys::crypto_sign_seed_keypair(
                signing_public_key.as_mut_ptr(),
                expanded.as_mut_ptr(),
                signing_seed.0.as_ptr(),
            )
        } != 0
        {
            return Err(CryptoError::RandomUnavailable);
        }
        // SAFETY: expanded secret is no longer needed.
        unsafe { libsodium_sys::sodium_memzero(expanded.as_mut_ptr().cast(), expanded.len()) };
        Ok(Self {
            encryption_public_key,
            encryption_private_key,
            signing_public_key,
            signing_seed,
        })
    }

    /// Encodes the device-private custody bundle for a caller-owned protected file.
    #[must_use]
    pub fn to_protected_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(133);
        bytes.extend_from_slice(b"PMAD1");
        bytes.extend_from_slice(&self.encryption_public_key);
        bytes.extend_from_slice(&self.encryption_private_key.0);
        bytes.extend_from_slice(&self.signing_public_key);
        bytes.extend_from_slice(&self.signing_seed.0);
        bytes
    }

    /// Decodes and validates a device-private custody bundle.
    ///
    /// # Errors
    ///
    /// Returns an error for wrong length/magic or mismatched public/private keys.
    pub fn from_protected_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        sodium()?;
        if bytes.len() != 133 || &bytes[..5] != b"PMAD1" {
            return Err(CryptoError::InvalidFormat);
        }
        let encryption_public_key = bytes[5..37]
            .try_into()
            .map_err(|_| CryptoError::InvalidFormat)?;
        let encryption_private_key = Secret(
            bytes[37..69]
                .try_into()
                .map_err(|_| CryptoError::InvalidFormat)?,
        );
        let signing_public_key = bytes[69..101]
            .try_into()
            .map_err(|_| CryptoError::InvalidFormat)?;
        let signing_seed = Secret(
            bytes[101..133]
                .try_into()
                .map_err(|_| CryptoError::InvalidFormat)?,
        );
        let mut derived_encryption = [0_u8; KEY_BYTES];
        if unsafe {
            // SAFETY: X25519 public/private buffers have their documented exact lengths.
            libsodium_sys::crypto_scalarmult_base(
                derived_encryption.as_mut_ptr(),
                encryption_private_key.0.as_ptr(),
            )
        } != 0
            || derived_encryption != encryption_public_key
        {
            return Err(CryptoError::Authentication);
        }
        let mut derived_signing = [0_u8; KEY_BYTES];
        let mut expanded = [0_u8; 64];
        let result = unsafe {
            // SAFETY: Ed25519 key buffers have their documented exact lengths.
            libsodium_sys::crypto_sign_seed_keypair(
                derived_signing.as_mut_ptr(),
                expanded.as_mut_ptr(),
                signing_seed.0.as_ptr(),
            )
        };
        // SAFETY: expanded secret is no longer needed.
        unsafe { libsodium_sys::sodium_memzero(expanded.as_mut_ptr().cast(), expanded.len()) };
        if result != 0 || derived_signing != signing_public_key {
            return Err(CryptoError::Authentication);
        }
        Ok(Self {
            encryption_public_key,
            encryption_private_key,
            signing_public_key,
            signing_seed,
        })
    }

    #[must_use]
    pub const fn encryption_public_key(&self) -> &[u8; KEY_BYTES] {
        &self.encryption_public_key
    }
    #[must_use]
    pub const fn signing_public_key(&self) -> &[u8; KEY_BYTES] {
        &self.signing_public_key
    }

    /// Verifies the human-bound package and opens its sealed device key.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong recipient, signature, context, or sealed box.
    pub fn open_audit_key(
        &self,
        package: &AuditKeyPackage,
        trusted_root: &TrustedRoot,
        device: [u8; ID_BYTES],
        generation: u64,
    ) -> Result<AuditKey, CryptoError> {
        if package.vault != trusted_root.vault_id
            || package.device != device
            || package.generation != generation
            || package.encryption_public_key != self.encryption_public_key
            || package.signing_public_key != self.signing_public_key
        {
            return Err(CryptoError::Authentication);
        }
        verify_human_signature(
            trusted_root,
            &domain_message(b"pm/audit-key/v1", &package.unsigned_bytes()),
            &package.human_signature,
        )?;
        if package.device_envelope.len() < 48 {
            return Err(CryptoError::InvalidFormat);
        }
        let mut plaintext = vec![0_u8; package.device_envelope.len() - 48];
        if unsafe {
            // SAFETY: key and message buffers have exact declared lengths.
            libsodium_sys::crypto_box_seal_open(
                plaintext.as_mut_ptr(),
                package.device_envelope.as_ptr(),
                package.device_envelope.len() as u64,
                self.encryption_public_key.as_ptr(),
                self.encryption_private_key.0.as_ptr(),
            )
        } != 0
        {
            wipe_vec(&mut plaintext);
            return Err(CryptoError::Authentication);
        }
        let decoded = decode_sealed_audit_key(&plaintext);
        wipe_vec(&mut plaintext);
        let (key, target, recipient, decoded_generation) = decoded?;
        if recipient != device || decoded_generation != generation {
            return Err(CryptoError::Authentication);
        }
        validate_audit_target(&target, package.vault, device, generation)?;
        Ok(AuditKey {
            vault: package.vault,
            generation,
            key,
        })
    }

    /// Signs an already-encrypted audit envelope in the `SK_SD` domain.
    ///
    /// # Errors
    ///
    /// Returns an error if native Ed25519 signing fails.
    pub fn sign_audit_record(&self, envelope: &[u8]) -> Result<[u8; 64], CryptoError> {
        sign_detached(
            &self.signing_seed,
            &domain_message(b"pm/audit-record/v1", envelope),
        )
    }

    /// Signs one canonical G5 event as device provenance, not human authority.
    ///
    /// # Errors
    ///
    /// Returns an error if native Ed25519 signing fails.
    pub fn sign_device_event(&self, event: &[u8]) -> Result<[u8; 64], CryptoError> {
        sign_detached(
            &self.signing_seed,
            &domain_message(b"pm/device-event/v1", event),
        )
    }

    /// Creates a device-only `K_ATT` package for one authentication attempt.
    /// The attempt key is never wrapped by, or recoverable through, `K_H`.
    ///
    /// # Errors
    /// Returns an error for invalid context, oversized state, or cryptographic failure.
    pub fn seal_attempt_state(
        &self,
        vault: [u8; ID_BYTES],
        device: [u8; ID_BYTES],
        generation: u64,
        attempt: [u8; ID_BYTES],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if generation == 0 || plaintext.len() > MAX_OBJECT_BYTES {
            return Err(CryptoError::InvalidFormat);
        }
        let target = target_header(vault, attempt, attempt, Purpose::AttemptState, generation);
        let key = Secret::random()?;
        let envelope = seal(&key, target.clone(), plaintext)?;
        let mut key_plaintext = encode_sealed_key(&key, &target, &device, generation);
        let mut key_box = vec![0_u8; key_plaintext.len() + 48];
        let result = unsafe {
            // SAFETY: output/input/public-key buffers have documented sizes.
            libsodium_sys::crypto_box_seal(
                key_box.as_mut_ptr(),
                key_plaintext.as_ptr(),
                key_plaintext.len() as u64,
                self.encryption_public_key.as_ptr(),
            )
        };
        wipe_vec(&mut key_plaintext);
        if result != 0 {
            return Err(CryptoError::Authentication);
        }
        let unsigned = encode_attempt_package_unsigned(device, generation, &envelope, &key_box);
        let signature = sign_detached(
            &self.signing_seed,
            &domain_message(b"pm/attempt-key/v1", &unsigned),
        )?;
        Ok(encode_attempt_package(
            device, generation, &envelope, &key_box, &signature,
        ))
    }

    /// Re-encrypts state with the existing per-attempt `K_ATT` and a fresh nonce.
    ///
    /// # Errors
    /// Returns an error for altered packages, mismatched context, or encryption failure.
    pub fn update_attempt_state(
        &self,
        bytes: &[u8],
        vault: [u8; ID_BYTES],
        device: [u8; ID_BYTES],
        generation: u64,
        attempt: [u8; ID_BYTES],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let (stored_device, stored_generation, envelope, key_box, _) =
            self.verify_attempt_package(bytes, vault, device, generation, attempt)?;
        let key = self.open_attempt_key(&envelope, &key_box, device, generation)?;
        let replacement = seal(&key, envelope.header.clone(), plaintext)?;
        let unsigned = encode_attempt_package_unsigned(
            stored_device,
            stored_generation,
            &replacement,
            &key_box,
        );
        let signature = sign_detached(
            &self.signing_seed,
            &domain_message(b"pm/attempt-key/v1", &unsigned),
        )?;
        Ok(encode_attempt_package(
            stored_device,
            stored_generation,
            &replacement,
            &key_box,
            &signature,
        ))
    }

    /// Opens authenticated attempt state after checking the complete custody context.
    ///
    /// # Errors
    /// Returns an error for altered packages or any vault/device/generation mismatch.
    pub fn open_attempt_state(
        &self,
        bytes: &[u8],
        vault: [u8; ID_BYTES],
        device: [u8; ID_BYTES],
        generation: u64,
        attempt: [u8; ID_BYTES],
    ) -> Result<Vec<u8>, CryptoError> {
        let (_, _, envelope, key_box, _) =
            self.verify_attempt_package(bytes, vault, device, generation, attempt)?;
        let key = self.open_attempt_key(&envelope, &key_box, device, generation)?;
        open(&key, &envelope)
    }

    fn verify_attempt_package(
        &self,
        bytes: &[u8],
        vault: [u8; ID_BYTES],
        device: [u8; ID_BYTES],
        generation: u64,
        attempt: [u8; ID_BYTES],
    ) -> Result<AttemptPackage, CryptoError> {
        let (stored_device, stored_generation, envelope, key_box, signature) =
            decode_attempt_package(bytes)?;
        if stored_device != device
            || stored_generation != generation
            || envelope.header.vault != vault
            || envelope.header.object != attempt
            || envelope.header.revision != attempt
            || envelope.header.purpose != Purpose::AttemptState
            || envelope.header.key_generation != generation
        {
            return Err(CryptoError::Authentication);
        }
        let unsigned =
            encode_attempt_package_unsigned(stored_device, stored_generation, &envelope, &key_box);
        let signed_message = domain_message(b"pm/attempt-key/v1", &unsigned);
        if unsafe {
            // SAFETY: detached signature and public key have fixed documented sizes.
            libsodium_sys::crypto_sign_verify_detached(
                signature.as_ptr(),
                signed_message.as_ptr(),
                signed_message.len() as u64,
                self.signing_public_key.as_ptr(),
            )
        } != 0
        {
            return Err(CryptoError::Authentication);
        }
        Ok((
            stored_device,
            stored_generation,
            envelope,
            key_box,
            signature,
        ))
    }

    fn open_attempt_key(
        &self,
        envelope: &Envelope,
        key_box: &[u8],
        device: [u8; 16],
        generation: u64,
    ) -> Result<Secret, CryptoError> {
        if key_box.len() < 48 {
            return Err(CryptoError::InvalidFormat);
        }
        let mut plaintext = vec![0_u8; key_box.len() - 48];
        if unsafe {
            // SAFETY: sealed-box buffers and device keys have documented sizes.
            libsodium_sys::crypto_box_seal_open(
                plaintext.as_mut_ptr(),
                key_box.as_ptr(),
                key_box.len() as u64,
                self.encryption_public_key.as_ptr(),
                self.encryption_private_key.0.as_ptr(),
            )
        } != 0
        {
            wipe_vec(&mut plaintext);
            return Err(CryptoError::Authentication);
        }
        let decoded = decode_sealed_audit_key(&plaintext);
        wipe_vec(&mut plaintext);
        let (key, target, recipient, stored_generation) = decoded?;
        if recipient != device || stored_generation != generation || target != envelope.header {
            return Err(CryptoError::Authentication);
        }
        Ok(key)
    }

    /// Opens a typed control package sealed to this device. Authority-event
    /// verification and package-digest membership remain the caller's job.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong device/generation/object/revision, altered
    /// ciphertext, or a package not sealed to this device key.
    pub fn open_control_package(
        &self,
        bytes: &[u8],
        expected_vault: [u8; 16],
        expected_recipient: [u8; 16],
        expected_generation: u64,
        expected_object: [u8; 16],
        expected_revision: [u8; 16],
    ) -> Result<Vec<u8>, CryptoError> {
        let package = decode_control_package(bytes)?;
        if expected_generation == 0
            || package.recipient != expected_recipient
            || package.recipient_generation != expected_generation
            || package.envelope.header.vault != expected_vault
            || package.envelope.header.object != expected_object
            || package.envelope.header.revision != expected_revision
            || package.envelope.header.purpose != Purpose::Control
            || package.envelope.header.key_generation != expected_generation
        {
            return Err(CryptoError::Authentication);
        }
        if package.key_box.len() < 48 {
            return Err(CryptoError::InvalidFormat);
        }
        let mut plaintext = vec![0_u8; package.key_box.len() - 48];
        if unsafe {
            // SAFETY: all box buffers and device keys have documented sizes.
            libsodium_sys::crypto_box_seal_open(
                plaintext.as_mut_ptr(),
                package.key_box.as_ptr(),
                package.key_box.len() as u64,
                self.encryption_public_key.as_ptr(),
                self.encryption_private_key.0.as_ptr(),
            )
        } != 0
        {
            wipe_vec(&mut plaintext);
            return Err(CryptoError::Authentication);
        }
        let decoded = decode_sealed_audit_key(&plaintext);
        wipe_vec(&mut plaintext);
        let (key, target, recipient, generation) = decoded?;
        if recipient != expected_recipient
            || generation != expected_generation
            || target != package.envelope.header
        {
            return Err(CryptoError::Authentication);
        }
        open(&key, &package.envelope)
    }

    /// Verifies a human-signed grant bound to one authority event and opens
    /// its device-sealed context. Returns the authenticated payload digest.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong signature, commitment, recipient, event,
    /// generation, or device wrapping key.
    pub fn verify_grant_vector(
        &self,
        bytes: &[u8],
        trusted_root: &TrustedRoot,
        recipient: [u8; 16],
        authority_event: [u8; 32],
        commitment: [u8; 32],
    ) -> Result<[u8; 32], CryptoError> {
        let signed = decode_signed_grant(bytes)?;
        verify_grant_fields(
            &signed,
            trusted_root,
            recipient,
            authority_event,
            commitment,
        )?;
        let mut plaintext = vec![0_u8; signed.fields.sealed_box.len() - 48];
        if unsafe {
            // SAFETY: key and message buffers have the exact declared lengths.
            libsodium_sys::crypto_box_seal_open(
                plaintext.as_mut_ptr(),
                signed.fields.sealed_box.as_ptr(),
                signed.fields.sealed_box.len() as u64,
                self.encryption_public_key.as_ptr(),
                self.encryption_private_key.0.as_ptr(),
            )
        } != 0
        {
            wipe_vec(&mut plaintext);
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
        Ok(signed.fields.payload_sha256)
    }
}

/// Per-device audit encryption key. It exposes only typed audit operations.
pub struct AuditKey {
    vault: [u8; ID_BYTES],
    generation: u64,
    key: Secret,
}

impl AuditKey {
    /// Encrypts a bounded audit record with typed audit-record AAD.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized plaintext or unavailable cryptography.
    pub fn seal_record(
        &self,
        event_id: [u8; ID_BYTES],
        revision: [u8; ID_BYTES],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if plaintext.len() > 4 * 1024 {
            return Err(CryptoError::InvalidFormat);
        }
        let header = target_header(
            self.vault,
            event_id,
            revision,
            Purpose::AuditRecord,
            self.generation,
        );
        Ok(encode_envelope(&seal(&self.key, header, plaintext)?))
    }

    /// Authenticates and decrypts an exact audit-record envelope.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, altered, or context-mismatched bytes.
    pub fn open_record(
        &self,
        event_id: [u8; ID_BYTES],
        bytes: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let envelope = decode_envelope(bytes)?;
        if encode_envelope(&envelope) != bytes
            || envelope.header.vault != self.vault
            || envelope.header.object != event_id
            || envelope.header.purpose != Purpose::AuditRecord
            || envelope.header.key_generation != self.generation
        {
            return Err(CryptoError::Authentication);
        }
        open(&self.key, &envelope)
    }

    /// Encrypts an audit manifest with typed audit-manifest AAD.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized plaintext or unavailable cryptography.
    pub fn seal_manifest(
        &self,
        manifest_id: [u8; ID_BYTES],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let header = target_header(
            self.vault,
            manifest_id,
            manifest_id,
            Purpose::AuditManifest,
            self.generation,
        );
        Ok(encode_envelope(&seal(&self.key, header, plaintext)?))
    }

    /// Authenticates and decrypts an exact audit-manifest envelope.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, altered, or context-mismatched bytes.
    pub fn open_manifest(
        &self,
        manifest_id: [u8; ID_BYTES],
        bytes: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let envelope = decode_envelope(bytes)?;
        if encode_envelope(&envelope) != bytes
            || envelope.header.vault != self.vault
            || envelope.header.object != manifest_id
            || envelope.header.revision != manifest_id
            || envelope.header.purpose != Purpose::AuditManifest
            || envelope.header.key_generation != self.generation
        {
            return Err(CryptoError::Authentication);
        }
        open(&self.key, &envelope)
    }
}

/// Verifies an `SK_SD` signature over the fixed audit-record domain.
///
/// # Errors
///
/// Returns an error for an invalid signature or unavailable cryptography.
pub fn verify_audit_signature(
    public_key: &[u8; KEY_BYTES],
    envelope: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    sodium()?;
    let message = domain_message(b"pm/audit-record/v1", envelope);
    if unsafe {
        // SAFETY: signature/public key sizes and message buffer are valid.
        libsodium_sys::crypto_sign_verify_detached(
            signature.as_ptr(),
            message.as_ptr(),
            message.len() as u64,
            public_key.as_ptr(),
        )
    } != 0
    {
        return Err(CryptoError::Authentication);
    }
    Ok(())
}

/// Verifies that an audit/device signing key was bound to this vault and
/// device generation by `SK_H`.
///
/// # Errors
/// Returns authentication failure for a mismatched or altered package.
pub fn verify_audit_key_package(
    trusted_root: &TrustedRoot,
    package: &AuditKeyPackage,
    device: [u8; ID_BYTES],
    generation: u64,
) -> Result<(), CryptoError> {
    if package.vault != trusted_root.vault_id
        || package.device != device
        || package.generation != generation
    {
        return Err(CryptoError::Authentication);
    }
    verify_human_signature(
        trusted_root,
        &domain_message(b"pm/audit-key/v1", &package.unsigned_bytes()),
        &package.human_signature,
    )
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
    kind: ItemKind,
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
    pub const fn kind(&self) -> ItemKind {
        self.kind
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

/// Portable attachment ciphertext: a PMF1 stream and its independent `K_F` envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileCiphertext {
    key_envelope: Envelope,
    stream: Vec<u8>,
}

impl FileCiphertext {
    /// Returns the closed portable package.
    ///
    /// # Panics
    /// Only if the in-memory `Vec` encoder cannot write, which is uninhabited;
    /// allocation failure follows Rust's process-level behavior.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(Vec::new());
        encoder.map(3).expect("Vec writes cannot fail");
        encoder.str("v").expect("Vec writes cannot fail");
        encoder.u64(FORMAT_VERSION).expect("Vec writes cannot fail");
        encoder.str("key_envelope").expect("Vec writes cannot fail");
        encoder
            .bytes(&encode_envelope(&self.key_envelope))
            .expect("Vec writes cannot fail");
        encoder.str("stream").expect("Vec writes cannot fail");
        encoder.bytes(&self.stream).expect("Vec writes cannot fail");
        encoder.into_writer()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() > MAX_OBJECT_BYTES + MAX_HEADER_BYTES * 2 {
            return Err(CryptoError::InvalidFormat);
        }
        let mut decoder = Decoder::new(bytes);
        expect_map(&mut decoder, 3)?;
        expect_key(&mut decoder, "v")?;
        if decoder.u64().map_err(invalid)? != FORMAT_VERSION {
            return Err(CryptoError::InvalidFormat);
        }
        expect_key(&mut decoder, "key_envelope")?;
        let key_envelope = decode_envelope(decoder.bytes().map_err(invalid)?)?;
        expect_key(&mut decoder, "stream")?;
        let stream = decoder.bytes().map_err(invalid)?.to_vec();
        let package = Self {
            key_envelope,
            stream,
        };
        if decoder.position() != bytes.len() || package.to_bytes() != bytes {
            return Err(CryptoError::InvalidFormat);
        }
        Ok(package)
    }
}

/// Incremental SHA-256 through the repository's native crypto boundary.
pub struct DigestState(libsodium_sys::crypto_hash_sha256_state);

impl DigestState {
    /// Starts a new digest.
    ///
    /// # Errors
    /// Returns an error when libsodium cannot initialize.
    pub fn new() -> Result<Self, CryptoError> {
        sodium()?;
        let mut state = Self(unsafe { std::mem::zeroed() });
        if unsafe { libsodium_sys::crypto_hash_sha256_init(&raw mut state.0) } != 0 {
            return Err(CryptoError::ResourceUnavailable);
        }
        Ok(state)
    }
    /// Incorporates one bounded input chunk.
    pub fn update(&mut self, bytes: &[u8]) {
        unsafe {
            libsodium_sys::crypto_hash_sha256_update(
                &raw mut self.0,
                bytes.as_ptr(),
                bytes.len() as u64,
            );
        }
    }
    /// Finalizes this digest state.
    #[must_use]
    pub fn finish(mut self) -> [u8; 32] {
        let mut out = [0; 32];
        unsafe {
            libsodium_sys::crypto_hash_sha256_final(&raw mut self.0, out.as_mut_ptr());
        }
        out
    }
}

impl Drop for DigestState {
    fn drop(&mut self) {
        // SAFETY: the state is valid storage and is not used after drop.
        unsafe {
            libsodium_sys::sodium_memzero((&raw mut self.0).cast(), std::mem::size_of_val(&self.0));
        }
    }
}

/// One bounded-memory PMF1 encryption session.
pub struct FileSealer {
    state: SecretStreamState,
    target: Header,
    stream_header: [u8; 24],
    header: Vec<u8>,
    index: u64,
    finished: bool,
}
impl FileSealer {
    fn new(key: &Secret, target: Header, envelope: &Envelope) -> Result<Self, CryptoError> {
        let mut state = SecretStreamState::new();
        let mut stream_header = [0; 24];
        if unsafe {
            libsodium_sys::crypto_secretstream_xchacha20poly1305_init_push(
                &raw mut state.0,
                stream_header.as_mut_ptr(),
                key.0.as_ptr(),
            )
        } != 0
        {
            return Err(CryptoError::RandomUnavailable);
        }
        let pmf = encode_pmf1_header(&target, &stream_header);
        let mut e = Encoder::new(Vec::new());
        e.map(3).unwrap();
        e.str("v").unwrap().u64(1).unwrap();
        e.str("key_envelope")
            .unwrap()
            .bytes(&encode_envelope(envelope))
            .unwrap();
        e.str("pmf1_header").unwrap().bytes(&pmf).unwrap();
        let payload = e.into_writer();
        let mut header = b"PMFS1".to_vec();
        header.extend_from_slice(&u32::try_from(payload.len()).map_err(invalid)?.to_be_bytes());
        header.extend_from_slice(&payload);
        Ok(Self {
            state,
            target,
            stream_header,
            header,
            index: 0,
            finished: false,
        })
    }
    #[must_use]
    pub fn header(&self) -> &[u8] {
        &self.header
    }
    /// Encrypts one chunk. `final_chunk` must be true exactly once, on the last chunk.
    ///
    /// # Errors
    /// Returns an error for oversized chunks, calls after the final chunk, or native
    /// authenticated-encryption failure.
    pub fn seal_chunk(
        &mut self,
        plaintext: &[u8],
        final_chunk: bool,
    ) -> Result<Vec<u8>, CryptoError> {
        if self.finished || plaintext.len() > FILE_CHUNK_BYTES {
            return Err(CryptoError::InvalidFormat);
        }
        let aad = encode_file_aad(&self.target, &self.stream_header, self.index);
        let mut ciphertext = vec![0; plaintext.len() + 17];
        let mut length = 0;
        let tag = u8::try_from(if final_chunk {
            libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_FINAL
        } else {
            libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
        })
        .map_err(invalid)?;
        if unsafe {
            libsodium_sys::crypto_secretstream_xchacha20poly1305_push(
                &raw mut self.state.0,
                ciphertext.as_mut_ptr(),
                &raw mut length,
                plaintext.as_ptr(),
                plaintext.len() as u64,
                aad.as_ptr(),
                aad.len() as u64,
                tag,
            )
        } != 0
        {
            ciphertext.fill(0);
            return Err(CryptoError::Authentication);
        }
        self.index += 1;
        self.finished = final_chunk;
        let mut frame = u32::try_from(ciphertext.len())
            .map_err(invalid)?
            .to_be_bytes()
            .to_vec();
        frame.extend_from_slice(&ciphertext);
        Ok(frame)
    }
}
impl Drop for FileSealer {
    fn drop(&mut self) {
        self.header.fill(0);
    }
}

pub struct FileOpener {
    state: SecretStreamState,
    target: Header,
    stream_header: [u8; 24],
    index: u64,
    finished: bool,
}
impl FileOpener {
    fn new(
        root: &Secret,
        vault: [u8; 16],
        attachment: [u8; 16],
        revision: [u8; 16],
        header: &[u8],
    ) -> Result<Self, CryptoError> {
        let (envelope, target, stream_header) = decode_file_stream_header(header)?;
        let (key, wrapped) = open_key(root, &envelope)?;
        if wrapped != target
            || target.vault != vault
            || target.object != attachment
            || target.revision != revision
            || target.purpose != Purpose::File
        {
            return Err(CryptoError::Authentication);
        }
        let mut state = SecretStreamState::new();
        if unsafe {
            libsodium_sys::crypto_secretstream_xchacha20poly1305_init_pull(
                &raw mut state.0,
                stream_header.as_ptr(),
                key.0.as_ptr(),
            )
        } != 0
        {
            return Err(CryptoError::Authentication);
        }
        Ok(Self {
            state,
            target,
            stream_header,
            index: 0,
            finished: false,
        })
    }
    /// Authenticates and decrypts one bounded ciphertext frame.
    ///
    /// # Errors
    /// Returns an error for malformed, reordered, truncated, or unauthenticated frames.
    pub fn open_chunk(&mut self, frame: &[u8], final_chunk: bool) -> Result<Vec<u8>, CryptoError> {
        if self.finished || frame_length(frame)? != frame.len() {
            return Err(CryptoError::InvalidFormat);
        }
        let ciphertext = &frame[4..];
        let aad = encode_file_aad(&self.target, &self.stream_header, self.index);
        let mut plain = vec![0; ciphertext.len() - 17];
        let mut len = 0;
        let mut tag = 0;
        if unsafe {
            libsodium_sys::crypto_secretstream_xchacha20poly1305_pull(
                &raw mut self.state.0,
                plain.as_mut_ptr(),
                &raw mut len,
                &raw mut tag,
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                aad.as_ptr(),
                aad.len() as u64,
            )
        } != 0
        {
            plain.fill(0);
            return Err(CryptoError::Authentication);
        }
        let expected = u8::try_from(if final_chunk {
            libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_FINAL
        } else {
            libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
        })
        .map_err(invalid)?;
        if tag != expected {
            plain.fill(0);
            return Err(CryptoError::InvalidFormat);
        }
        self.index += 1;
        self.finished = final_chunk;
        Ok(plain)
    }
}
fn decode_file_stream_header(header: &[u8]) -> Result<(Envelope, Header, [u8; 24]), CryptoError> {
    if header.len() < 9 || &header[..5] != b"PMFS1" {
        return Err(CryptoError::InvalidFormat);
    }
    let len = usize::try_from(u32::from_be_bytes(
        header[5..9].try_into().map_err(invalid)?,
    ))
    .map_err(invalid)?;
    if header.len() != 9 + len {
        return Err(CryptoError::InvalidFormat);
    }
    let mut d = Decoder::new(&header[9..]);
    expect_map(&mut d, 3)?;
    expect_key(&mut d, "v")?;
    if d.u64().map_err(invalid)? != 1 {
        return Err(CryptoError::InvalidFormat);
    }
    expect_key(&mut d, "key_envelope")?;
    let envelope = decode_envelope(d.bytes().map_err(invalid)?)?;
    expect_key(&mut d, "pmf1_header")?;
    let (target, stream) = decode_pmf1_header(d.bytes().map_err(invalid)?)?;
    if d.position() != len {
        return Err(CryptoError::InvalidFormat);
    }
    Ok((envelope, target, stream))
}
fn frame_length(bytes: &[u8]) -> Result<usize, CryptoError> {
    if bytes.len() < 4 {
        return Err(CryptoError::InvalidFormat);
    }
    let n = usize::try_from(u32::from_be_bytes(bytes[..4].try_into().map_err(invalid)?))
        .map_err(invalid)?;
    if !(17..=FILE_CHUNK_BYTES + 17).contains(&n) {
        return Err(CryptoError::InvalidFormat);
    }
    Ok(4 + n)
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
        verify_grant_fields(
            &signed,
            trusted_root,
            recipient,
            authority_event,
            commitment,
        )?;
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

/// Context for a device-readable operational-control package.
#[derive(Clone, Copy)]
pub struct ControlPackageInput<'a> {
    pub object: [u8; 16],
    pub revision: [u8; 16],
    pub recipient: [u8; 16],
    pub recipient_generation: u64,
    pub plaintext: &'a [u8],
}

struct ControlPackage {
    recipient: [u8; 16],
    recipient_generation: u64,
    envelope: Envelope,
    key_box: Vec<u8>,
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

    /// Returns canonical bytes suitable for durable pre-event staging.
    #[must_use]
    pub fn to_staged_bytes(&self) -> Vec<u8> {
        encode_grant_without_event(&self.fields)
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

/// Generates a cryptographically random 16-byte object identifier.
///
/// # Errors
///
/// Returns an error when the native random source is unavailable.
pub fn random_id() -> Result<[u8; ID_BYTES], CryptoError> {
    sodium()?;
    random_array()
}

/// Fills caller-owned bytes from the selected native random source.
///
/// # Errors
/// Returns an error when the native RNG cannot be initialized securely.
pub fn fill_random(output: &mut [u8]) -> Result<(), CryptoError> {
    sodium()?;
    // SAFETY: sodium is initialized and `output` is writable for its full length.
    unsafe { libsodium_sys::randombytes_buf(output.as_mut_ptr().cast(), output.len()) };
    Ok(())
}

/// Computes SHA-256 through the repository's single native crypto boundary.
#[must_use]
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    sha256(bytes)
}

/// Verifies a signature in the fixed human-command domain.
///
/// # Errors
///
/// Returns authentication failure for a wrong root, signature, or command.
pub fn verify_human_command(
    trusted_root: &TrustedRoot,
    command: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    verify_human_signature(
        trusted_root,
        &domain_message(b"pm/human-command/v1", command),
        signature,
    )
}

/// Verifies a signature in the fixed human-event domain.
///
/// # Errors
///
/// Returns authentication failure for a wrong root, signature, or event.
pub fn verify_human_event(
    trusted_root: &TrustedRoot,
    event: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    verify_human_signature(
        trusted_root,
        &domain_message(b"pm/human-event/v1", event),
        signature,
    )
}

/// Verifies device provenance for one canonical G5 event.
///
/// # Errors
///
/// Returns authentication failure for a wrong device key, signature, or event.
pub fn verify_device_event(
    public_key: &[u8; 32],
    event: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    sodium()?;
    let message = domain_message(b"pm/device-event/v1", event);
    if unsafe {
        // SAFETY: signature/public-key sizes and message buffer are valid.
        libsodium_sys::crypto_sign_verify_detached(
            signature.as_ptr(),
            message.as_ptr(),
            message.len() as u64,
            public_key.as_ptr(),
        )
    } != 0
    {
        return Err(CryptoError::Authentication);
    }
    Ok(())
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
        authority_epoch: bundle.trusted_root.epoch,
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

fn encode_control_package(package: &ControlPackage) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(4).expect("Vec writes cannot fail");
    encoder.str("recipient").expect("Vec writes cannot fail");
    encoder
        .bytes(&package.recipient)
        .expect("Vec writes cannot fail");
    encoder
        .str("recipient_generation")
        .expect("Vec writes cannot fail");
    encoder
        .u64(package.recipient_generation)
        .expect("Vec writes cannot fail");
    encoder.str("envelope").expect("Vec writes cannot fail");
    encoder
        .bytes(&encode_envelope(&package.envelope))
        .expect("Vec writes cannot fail");
    encoder.str("key_box").expect("Vec writes cannot fail");
    encoder
        .bytes(&package.key_box)
        .expect("Vec writes cannot fail");
    encoder.into_writer()
}

fn decode_control_package(bytes: &[u8]) -> Result<ControlPackage, CryptoError> {
    if bytes.len() > MAX_OBJECT_BYTES {
        return Err(CryptoError::InvalidFormat);
    }
    let mut decoder = Decoder::new(bytes);
    expect_map(&mut decoder, 4)?;
    expect_key(&mut decoder, "recipient")?;
    let recipient = decode_bytes(&mut decoder)?;
    expect_key(&mut decoder, "recipient_generation")?;
    let recipient_generation = decoder.u64().map_err(invalid)?;
    expect_key(&mut decoder, "envelope")?;
    let envelope = decode_envelope(decoder.bytes().map_err(invalid)?)?;
    expect_key(&mut decoder, "key_box")?;
    let key_box = decoder.bytes().map_err(invalid)?.to_vec();
    if decoder.position() != bytes.len() {
        return Err(CryptoError::InvalidFormat);
    }
    let package = ControlPackage {
        recipient,
        recipient_generation,
        envelope,
        key_box,
    };
    if recipient_generation == 0 || encode_control_package(&package) != bytes {
        return Err(CryptoError::InvalidFormat);
    }
    Ok(package)
}

fn encode_attempt_package_unsigned(
    device: [u8; 16],
    generation: u64,
    envelope: &Envelope,
    key_box: &[u8],
) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(4).expect("Vec writes cannot fail");
    e.bytes(&device).expect("Vec writes cannot fail");
    e.u64(generation).expect("Vec writes cannot fail");
    e.bytes(&encode_envelope(envelope))
        .expect("Vec writes cannot fail");
    e.bytes(key_box).expect("Vec writes cannot fail");
    e.into_writer()
}

fn encode_attempt_package(
    device: [u8; 16],
    generation: u64,
    envelope: &Envelope,
    key_box: &[u8],
    signature: &[u8; 64],
) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(5).expect("Vec writes cannot fail");
    e.bytes(&device).expect("Vec writes cannot fail");
    e.u64(generation).expect("Vec writes cannot fail");
    e.bytes(&encode_envelope(envelope))
        .expect("Vec writes cannot fail");
    e.bytes(key_box).expect("Vec writes cannot fail");
    e.bytes(signature).expect("Vec writes cannot fail");
    e.into_writer()
}

type AttemptPackage = ([u8; 16], u64, Envelope, Vec<u8>, [u8; 64]);

fn decode_attempt_package(bytes: &[u8]) -> Result<AttemptPackage, CryptoError> {
    if bytes.len() > MAX_OBJECT_BYTES {
        return Err(CryptoError::InvalidFormat);
    }
    let mut d = Decoder::new(bytes);
    if d.array().map_err(invalid)? != Some(5) {
        return Err(CryptoError::InvalidFormat);
    }
    let device = decode_bytes(&mut d)?;
    let generation = d.u64().map_err(invalid)?;
    let envelope = decode_envelope(d.bytes().map_err(invalid)?)?;
    let key_box = d.bytes().map_err(invalid)?.to_vec();
    let signature = decode_bytes(&mut d)?;
    if generation == 0
        || d.position() != bytes.len()
        || encode_attempt_package(device, generation, &envelope, &key_box, &signature) != bytes
    {
        return Err(CryptoError::InvalidFormat);
    }
    Ok((device, generation, envelope, key_box, signature))
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

fn decode_sealed_audit_key(bytes: &[u8]) -> Result<(Secret, Header, [u8; 16], u64), CryptoError> {
    let mut decoder = Decoder::new(bytes);
    expect_map(&mut decoder, 4)?;
    expect_key(&mut decoder, "key")?;
    let key = Secret(decode_bytes(&mut decoder)?);
    expect_key(&mut decoder, "recipient")?;
    let recipient = decode_bytes(&mut decoder)?;
    expect_key(&mut decoder, "target_header")?;
    let target = decode_header(&mut decoder)?;
    expect_key(&mut decoder, "authorization_generation")?;
    let generation = decoder.u64().map_err(invalid)?;
    if decoder.position() != bytes.len()
        || encode_sealed_key(&key, &target, &recipient, generation) != bytes
    {
        return Err(CryptoError::InvalidFormat);
    }
    Ok((key, target, recipient, generation))
}

fn validate_audit_target(
    target: &Header,
    vault: [u8; ID_BYTES],
    device: [u8; ID_BYTES],
    generation: u64,
) -> Result<(), CryptoError> {
    if target.vault != vault
        || target.object != device
        || target.revision != device
        || target.purpose != Purpose::AuditRecord
        || target.key_generation != generation
    {
        return Err(CryptoError::Authentication);
    }
    Ok(())
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

fn verify_grant_fields(
    signed: &SignedGrantVector,
    trusted_root: &TrustedRoot,
    recipient: [u8; 16],
    authority_event: [u8; 32],
    commitment: [u8; 32],
) -> Result<(), CryptoError> {
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
    Ok(())
}

fn decode_grant_without_event(bytes: &[u8]) -> Result<GrantFields, CryptoError> {
    let mut decoder = Decoder::new(bytes);
    expect_map(&mut decoder, 9)?;
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
        authority_event: None,
    };
    if authorization_generation == 0 || encode_grant_without_event(&fields) != bytes {
        return Err(CryptoError::InvalidFormat);
    }
    Ok(fields)
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

fn domain_message(domain: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.array(2).expect("Vec writes cannot fail");
    encoder
        .str(std::str::from_utf8(domain).expect("fixed ASCII domain"))
        .expect("Vec writes cannot fail");
    encoder.writer_mut().extend_from_slice(payload);
    encoder.into_writer()
}

fn verify_human_signature(
    trusted_root: &TrustedRoot,
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    sodium()?;
    if unsafe {
        // SAFETY: signature, message and public-key buffers have declared sizes.
        libsodium_sys::crypto_sign_verify_detached(
            signature.as_ptr(),
            message.as_ptr(),
            message.len() as u64,
            trusted_root.public_key.as_ptr(),
        )
    } != 0
    {
        return Err(CryptoError::Authentication);
    }
    Ok(())
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
