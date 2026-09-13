// SPDX-License-Identifier: AGPL-3.0-only

//! Selected G6 logical records. Native bytes use one closed canonical CBOR schema.

use minicbor::{Decoder, Encoder, data::Type};
use pm_crypto::{ItemKind, digest};
use zeroize::Zeroize;

use crate::human::HumanCommitError;

pub(crate) const MAX_LOGICAL_RECORD: usize = 16 * 1024 * 1024;
const MAX_TITLE: usize = 1024;
const MAX_URL: usize = 8 * 1024;
const MAX_FIELD: usize = 1024 * 1024;
const MAX_FIELDS: usize = 256;
const MAX_DESTINATIONS: usize = 256;
const MAX_TAGS: usize = 1024;
const MAX_FILE: u64 = 16 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    Password,
    Totp,
    Passkey,
    Ssh,
    Token,
    Note,
    File,
}

impl RecordKind {
    pub(crate) const fn crypto(self) -> ItemKind {
        match self {
            Self::Password => ItemKind::Password,
            Self::Totp => ItemKind::Totp,
            Self::Passkey => ItemKind::Passkey,
            Self::Ssh => ItemKind::Ssh,
            Self::Token => ItemKind::Token,
            Self::Note => ItemKind::Note,
            Self::File => ItemKind::File,
        }
    }

    pub(crate) const fn name(self) -> &'static str {
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

    fn parse(value: &str) -> Result<Self, HumanCommitError> {
        match value {
            "password" => Ok(Self::Password),
            "totp" => Ok(Self::Totp),
            "passkey" => Ok(Self::Passkey),
            "ssh" => Ok(Self::Ssh),
            "token" => Ok(Self::Token),
            "note" => Ok(Self::Note),
            "file" => Ok(Self::File),
            _ => Err(HumanCommitError::InvalidInput),
        }
    }

    pub(crate) fn from_name(value: &str) -> Option<Self> {
        Self::parse(value).ok()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Destination {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Eq, PartialEq)]
pub enum LogicalValue {
    Text(String),
    Bytes(Vec<u8>),
}

#[derive(Debug, Eq, PartialEq)]
pub struct CustomField {
    pub id: [u8; 16],
    pub label: String,
    pub value: LogicalValue,
    pub concealed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceEncoding {
    Utf8,
    Json,
    Bytes,
}

impl SourceEncoding {
    const fn name(self) -> &'static str {
        match self {
            Self::Utf8 => "utf8",
            Self::Json => "json",
            Self::Bytes => "bytes",
        }
    }

    fn parse(value: &str) -> Result<Self, HumanCommitError> {
        match value {
            "utf8" => Ok(Self::Utf8),
            "json" => Ok(Self::Json),
            "bytes" => Ok(Self::Bytes),
            _ => Err(HumanCommitError::InvalidInput),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct SourceField {
    pub path: String,
    pub encoding: SourceEncoding,
    pub value: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct HumanMetadata {
    pub title: String,
    pub destinations: Vec<Destination>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub notes: String,
    pub fields: Vec<CustomField>,
    pub source_fields: Vec<SourceField>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgorithm {
    const fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    fn parse(value: &str) -> Result<Self, HumanCommitError> {
        match value {
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            _ => Err(HumanCommitError::InvalidInput),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateKeyFormat {
    OpenSsh,
    Pkcs8,
}

impl PrivateKeyFormat {
    const fn name(self) -> &'static str {
        match self {
            Self::OpenSsh => "openssh",
            Self::Pkcs8 => "pkcs8",
        }
    }

    fn parse(value: &str) -> Result<Self, HumanCommitError> {
        match value {
            "openssh" => Ok(Self::OpenSsh),
            "pkcs8" => Ok(Self::Pkcs8),
            _ => Err(HumanCommitError::InvalidInput),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum AuthRecord {
    Password {
        username: String,
        password: Vec<u8>,
        destination_refs: Vec<u16>,
    },
    Totp {
        secret: Vec<u8>,
        algorithm: TotpAlgorithm,
        digits: u8,
        period: u16,
        t0: u64,
        issuer: String,
        account: String,
        destination_refs: Vec<u16>,
    },
    Passkey {
        rp_id: String,
        user_handle: Vec<u8>,
        credential_id: Vec<u8>,
        cose_alg: i64,
        private_key: [u8; 32],
        public_key: [u8; 32],
        user_name: String,
        display_name: String,
        sign_count: u32,
        backup_eligible: bool,
        backup_state: bool,
    },
    Ssh {
        private_format: PrivateKeyFormat,
        private_key: Vec<u8>,
        public_key: Vec<u8>,
        username: String,
        destination_refs: Vec<u16>,
        passphrase: Option<Vec<u8>>,
    },
    Token {
        secret: Vec<u8>,
        provider: String,
        profile_id: String,
        destination_refs: Vec<u16>,
        expires_at: Option<i64>,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub struct Attachment {
    id: [u8; 16],
    name: String,
    mime: String,
    size: u64,
    sha256: [u8; 32],
    content: Vec<u8>,
}

impl Attachment {
    /// Constructs an attachment without treating its Unicode name as a path.
    ///
    /// # Errors
    /// Returns an explicit error rather than truncating an invalid name or size.
    pub fn new(
        id: [u8; 16],
        name: &str,
        mime: &str,
        content: &[u8],
    ) -> Result<Self, HumanCommitError> {
        let size = u64::try_from(content.len()).map_err(|_| HumanCommitError::InvalidInput)?;
        Self::from_parts(id, name, mime, size, digest(content), content)
    }

    /// Validates external metadata against the complete bytes; mismatches are never truncated.
    ///
    /// # Errors
    /// Returns an error for the v1 size limit or an inconsistent size/hash.
    pub fn from_parts(
        id: [u8; 16],
        name: &str,
        mime: &str,
        size: u64,
        sha256: [u8; 32],
        content: &[u8],
    ) -> Result<Self, HumanCommitError> {
        if name.len() > MAX_TITLE
            || mime.len() > MAX_TITLE
            || size > MAX_FILE
            || usize::try_from(size).ok() != Some(content.len())
            || digest(content) != sha256
        {
            return Err(HumanCommitError::InvalidInput);
        }
        Ok(Self {
            id,
            name: name.to_owned(),
            mime: mime.to_owned(),
            size,
            sha256,
            content: content.to_vec(),
        })
    }

    /// Creates metadata for content supplied through the streaming seam.
    ///
    /// # Errors
    /// Rejects declared sizes above 16 GiB or oversized untrusted names.
    pub fn descriptor(
        id: [u8; 16],
        name: &str,
        mime: &str,
        size: u64,
        sha256: [u8; 32],
    ) -> Result<Self, HumanCommitError> {
        if name.len() > MAX_TITLE || mime.len() > MAX_TITLE || size > MAX_FILE {
            return Err(HumanCommitError::InvalidInput);
        }
        Ok(Self {
            id,
            name: name.to_owned(),
            mime: mime.to_owned(),
            size,
            sha256,
            content: Vec::new(),
        })
    }

    #[must_use]
    pub const fn id(&self) -> &[u8; 16] {
        &self.id
    }
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    #[must_use]
    pub fn mime(&self) -> &str {
        &self.mime
    }
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }
    #[must_use]
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
    #[must_use]
    pub fn content(&self) -> &[u8] {
        &self.content
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct LogicalRecord {
    kind: RecordKind,
    human: HumanMetadata,
    auth: Vec<AuthRecord>,
    attachments: Vec<Attachment>,
}

/// Human-only filters evaluated after decrypting complete records. No plaintext
/// search terms or derived secret hashes are persisted.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct SearchQuery {
    pub text: Option<String>,
    pub tag: Option<String>,
    pub favorite: Option<bool>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct SearchHit {
    item_id: [u8; 16],
    kind: RecordKind,
    title: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct GeneratorConfig {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

/// Injectable public randomness boundary used to prove fail-closed behavior.
pub trait PasswordRng {
    /// Fills the entire buffer or returns a fixed, secret-free error.
    ///
    /// # Errors
    /// Returns an error without partial output when randomness is unavailable.
    fn fill(&mut self, output: &mut [u8]) -> Result<(), HumanCommitError>;
}

/// Generated secret bytes, wiped when the human caller releases them.
pub struct GeneratedPassword(Vec<u8>);

impl GeneratedPassword {
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for GeneratedPassword {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(crate) fn generate_password(
    config: &GeneratorConfig,
    rng: &mut impl PasswordRng,
) -> Result<GeneratedPassword, HumanCommitError> {
    if !(1..=1024).contains(&config.length) {
        return Err(HumanCommitError::InvalidInput);
    }
    let mut alphabet = Vec::new();
    if config.lowercase {
        alphabet.extend_from_slice(b"abcdefghijklmnopqrstuvwxyz");
    }
    if config.uppercase {
        alphabet.extend_from_slice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if config.digits {
        alphabet.extend_from_slice(b"0123456789");
    }
    if config.symbols {
        alphabet.extend_from_slice(b"!#$%&()*+,-./:;<=>?@[]^_{|}~");
    }
    if alphabet.is_empty() {
        return Err(HumanCommitError::InvalidInput);
    }
    let ceiling = u8::MAX
        - (u8::MAX % u8::try_from(alphabet.len()).map_err(|_| HumanCommitError::InvalidInput)?);
    let mut result = Vec::with_capacity(config.length);
    let mut random = [0_u8; 64];
    while result.len() < config.length {
        if let Err(error) = rng.fill(&mut random) {
            result.zeroize();
            random.zeroize();
            return Err(error);
        }
        for value in random {
            if value < ceiling {
                result.push(alphabet[usize::from(value) % alphabet.len()]);
                if result.len() == config.length {
                    break;
                }
            }
        }
    }
    random.zeroize();
    Ok(GeneratedPassword(result))
}

impl SearchHit {
    pub(crate) fn new(item_id: [u8; 16], record: &LogicalRecord) -> Self {
        Self {
            item_id,
            kind: record.kind,
            title: record.human.title.clone(),
        }
    }
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
}

impl LogicalRecord {
    /// Validates one complete native logical record against the selected G6 profile.
    ///
    /// # Errors
    /// Returns an explicit error for a type mismatch or any bound violation.
    pub fn new(
        kind: RecordKind,
        human: HumanMetadata,
        auth: Vec<AuthRecord>,
        attachments: Vec<Attachment>,
    ) -> Result<Self, HumanCommitError> {
        let record = Self {
            kind,
            human,
            auth,
            attachments,
        };
        record.validate()?;
        Ok(record)
    }

    /// Constructs a record whose attachment bytes arrive through bounded readers.
    ///
    /// # Errors
    /// Rejects the same logical/type limits as `new` and any inline file bytes.
    pub fn new_streaming(
        kind: RecordKind,
        human: HumanMetadata,
        auth: Vec<AuthRecord>,
        attachments: Vec<Attachment>,
    ) -> Result<Self, HumanCommitError> {
        let record = Self {
            kind,
            human,
            auth,
            attachments,
        };
        if record
            .attachments
            .iter()
            .any(|value| !value.content.is_empty())
        {
            return Err(HumanCommitError::InvalidInput);
        }
        record.validate_shape(false)?;
        Ok(record)
    }

    #[must_use]
    pub const fn kind(&self) -> RecordKind {
        self.kind
    }
    #[must_use]
    pub const fn human(&self) -> &HumanMetadata {
        &self.human
    }
    #[must_use]
    pub fn auth(&self) -> &[AuthRecord] {
        &self.auth
    }
    #[must_use]
    pub fn attachments(&self) -> &[Attachment] {
        &self.attachments
    }

    /// Encodes the complete human-channel representation, including file bytes.
    ///
    /// # Panics
    /// Only if the in-memory `Vec` encoder cannot write, which is uninhabited;
    /// allocation failure follows Rust's process-level behavior.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let human = self.encode_human();
        let auth = self.encode_auth();
        let mut encoder = Encoder::new(Vec::new());
        encoder.map(4).unwrap();
        key(&mut encoder, "v");
        encoder.u8(1).unwrap();
        key(&mut encoder, "human");
        encoder.bytes(&human).unwrap();
        key(&mut encoder, "auth");
        encode_optional_bytes(&mut encoder, auth.as_deref());
        key(&mut encoder, "attachments");
        encoder
            .array(u64::try_from(self.attachments.len()).unwrap())
            .unwrap();
        for attachment in &self.attachments {
            encoder.map(2).unwrap();
            key(&mut encoder, "id");
            encoder.bytes(&attachment.id).unwrap();
            key(&mut encoder, "content");
            encoder.bytes(&attachment.content).unwrap();
        }
        encoder.into_writer()
    }

    /// Strictly decodes a complete human-channel record.
    ///
    /// # Errors
    /// Rejects unknown/trailing/non-canonical native fields or inconsistent files.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HumanCommitError> {
        if bytes.len() > MAX_LOGICAL_RECORD * 2 {
            return Err(HumanCommitError::InvalidInput);
        }
        let mut decoder = Decoder::new(bytes);
        expect_map(&mut decoder, 4)?;
        expect_key(&mut decoder, "v")?;
        if decoder.u8().map_err(invalid)? != 1 {
            return Err(HumanCommitError::InvalidInput);
        }
        expect_key(&mut decoder, "human")?;
        let human = decoder.bytes().map_err(invalid)?.to_vec();
        expect_key(&mut decoder, "auth")?;
        let auth = decode_optional_bytes(&mut decoder)?;
        expect_key(&mut decoder, "attachments")?;
        let count = array_len(&mut decoder)?;
        let mut contents = Vec::with_capacity(count);
        for _ in 0..count {
            expect_map(&mut decoder, 2)?;
            expect_key(&mut decoder, "id")?;
            let id = fixed(&mut decoder)?;
            expect_key(&mut decoder, "content")?;
            let content = decoder.bytes().map_err(invalid)?.to_vec();
            contents.push((id, content));
        }
        if decoder.position() != bytes.len() {
            return Err(HumanCommitError::InvalidInput);
        }
        let mut record = Self::decode_parts(&human, auth.as_deref())?;
        for (id, content) in contents {
            record.restore_attachment(id, content)?;
        }
        record.validate()?;
        if record.to_bytes() != bytes {
            return Err(HumanCommitError::InvalidInput);
        }
        Ok(record)
    }

    /// Encodes metadata/auth only for the chunked human transport.
    ///
    /// # Panics
    /// The in-memory CBOR writer has an uninhabited encoder error; allocation failure
    /// follows Rust's process-level behavior.
    #[must_use]
    pub fn to_descriptor_bytes(&self) -> Vec<u8> {
        let human = self.encode_human();
        let auth = self.encode_auth();
        let mut encoder = Encoder::new(Vec::new());
        encoder.map(3).unwrap();
        key(&mut encoder, "v");
        encoder.u8(1).unwrap();
        key(&mut encoder, "human");
        encoder.bytes(&human).unwrap();
        key(&mut encoder, "auth");
        encode_optional_bytes(&mut encoder, auth.as_deref());
        encoder.into_writer()
    }

    /// Decodes metadata/auth only for the chunked human transport.
    ///
    /// # Errors
    /// Rejects unknown/trailing/non-canonical native fields.
    pub fn from_descriptor_bytes(bytes: &[u8]) -> Result<Self, HumanCommitError> {
        let mut d = Decoder::new(bytes);
        expect_map(&mut d, 3)?;
        expect_key(&mut d, "v")?;
        if d.u8().map_err(invalid)? != 1 {
            return Err(HumanCommitError::InvalidInput);
        }
        expect_key(&mut d, "human")?;
        let human = d.bytes().map_err(invalid)?.to_vec();
        expect_key(&mut d, "auth")?;
        let auth = decode_optional_bytes(&mut d)?;
        if d.position() != bytes.len() {
            return Err(HumanCommitError::InvalidInput);
        }
        let record = Self::decode_parts(&human, auth.as_deref())?;
        if record
            .attachments
            .iter()
            .any(|value| !value.content.is_empty())
            || record.to_descriptor_bytes() != bytes
        {
            return Err(HumanCommitError::InvalidInput);
        }
        Ok(record)
    }

    pub(crate) fn set_organization(
        &mut self,
        tags: Vec<String>,
        favorite: bool,
    ) -> Result<(), HumanCommitError> {
        self.human.tags = tags;
        self.human.favorite = favorite;
        self.validate()
    }

    pub(crate) fn matches(&self, query: &SearchQuery) -> bool {
        if query
            .favorite
            .is_some_and(|expected| self.human.favorite != expected)
        {
            return false;
        }
        if query
            .tag
            .as_ref()
            .is_some_and(|expected| !self.human.tags.iter().any(|tag| tag == expected))
        {
            return false;
        }
        let Some(expected) = query.text.as_ref() else {
            return true;
        };
        let expected = expected.to_lowercase();
        self.human.title.to_lowercase().contains(&expected)
            || self.human.notes.to_lowercase().contains(&expected)
            || self.human.tags.iter().any(|value| value.to_lowercase().contains(&expected))
            || self.human.destinations.iter().any(|value| value.label.to_lowercase().contains(&expected) || value.value.to_lowercase().contains(&expected))
            || self.human.fields.iter().any(|value| value.label.to_lowercase().contains(&expected) || matches!(&value.value, LogicalValue::Text(text) if text.to_lowercase().contains(&expected)))
    }

    pub(crate) fn attachment_inputs(&self) -> impl Iterator<Item = ([u8; 16], &[u8])> {
        self.attachments
            .iter()
            .map(|value| (value.id, value.content.as_slice()))
    }

    pub(crate) fn restore_attachment(
        &mut self,
        id: [u8; 16],
        content: Vec<u8>,
    ) -> Result<(), HumanCommitError> {
        let attachment = self
            .attachments
            .iter_mut()
            .find(|value| value.id == id)
            .ok_or(HumanCommitError::InvalidCommand)?;
        if usize::try_from(attachment.size).ok() != Some(content.len())
            || digest(&content) != attachment.sha256
            || !attachment.content.is_empty()
        {
            return Err(HumanCommitError::InvalidCommand);
        }
        attachment.content = content;
        Ok(())
    }

    pub(crate) fn validate_complete(&self) -> Result<(), HumanCommitError> {
        self.validate()
    }

    pub(crate) fn validate_descriptors(&self) -> Result<(), HumanCommitError> {
        self.validate_shape(false)
    }

    pub(crate) fn encode_human(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(Vec::new());
        encoder.map(10).unwrap();
        key(&mut encoder, "v");
        encoder.u8(1).unwrap();
        key(&mut encoder, "kind");
        encoder.str(self.kind.name()).unwrap();
        key(&mut encoder, "title");
        encoder.str(&self.human.title).unwrap();
        key(&mut encoder, "destinations");
        encode_destinations(&mut encoder, &self.human.destinations);
        key(&mut encoder, "tags");
        encode_strings(&mut encoder, &self.human.tags);
        key(&mut encoder, "favorite");
        encoder.bool(self.human.favorite).unwrap();
        key(&mut encoder, "notes");
        encoder.str(&self.human.notes).unwrap();
        key(&mut encoder, "fields");
        encode_fields(&mut encoder, &self.human.fields);
        key(&mut encoder, "source_fields");
        encode_source_fields(&mut encoder, &self.human.source_fields);
        key(&mut encoder, "attachments");
        encode_attachment_metadata(&mut encoder, &self.attachments);
        encoder.into_writer()
    }

    pub(crate) fn encode_auth(&self) -> Option<Vec<u8>> {
        if self.auth.is_empty() {
            return None;
        }
        let mut encoder = Encoder::new(Vec::new());
        encoder
            .array(u64::try_from(self.auth.len()).unwrap())
            .unwrap();
        for auth in &self.auth {
            encode_auth(&mut encoder, auth);
        }
        Some(encoder.into_writer())
    }

    pub(crate) fn decode_parts(
        human_bytes: &[u8],
        auth_bytes: Option<&[u8]>,
    ) -> Result<Self, HumanCommitError> {
        let (kind, human, attachments) = decode_human(human_bytes)?;
        let auth = decode_auth_array(auth_bytes)?;
        let record = Self {
            kind,
            human,
            auth,
            attachments,
        };
        record.validate_shape(false)?;
        if record.encode_human().as_slice() != human_bytes
            || record.encode_auth().as_deref() != auth_bytes
        {
            return Err(HumanCommitError::InvalidInput);
        }
        Ok(record)
    }

    fn validate(&self) -> Result<(), HumanCommitError> {
        self.validate_shape(true)
    }

    fn validate_shape(&self, complete_files: bool) -> Result<(), HumanCommitError> {
        let valid_shape = match self.kind {
            RecordKind::Password => {
                self.auth
                    .iter()
                    .filter(|a| matches!(a, AuthRecord::Password { .. }))
                    .count()
                    == 1
                    && self
                        .auth
                        .iter()
                        .all(|a| matches!(a, AuthRecord::Password { .. } | AuthRecord::Totp { .. }))
            }
            RecordKind::Totp => matches!(self.auth.as_slice(), [AuthRecord::Totp { .. }]),
            RecordKind::Passkey => matches!(self.auth.as_slice(), [AuthRecord::Passkey { .. }]),
            RecordKind::Ssh => matches!(self.auth.as_slice(), [AuthRecord::Ssh { .. }]),
            RecordKind::Token => matches!(self.auth.as_slice(), [AuthRecord::Token { .. }]),
            RecordKind::Note => self.auth.is_empty(),
            RecordKind::File => self.auth.is_empty() && !self.attachments.is_empty(),
        };
        if !valid_shape
            || self.human.title.len() > MAX_TITLE
            || self.human.notes.len() > MAX_FIELD
            || self.human.fields.len() > MAX_FIELDS
            || self.human.destinations.len() > MAX_DESTINATIONS
            || self.human.tags.len() > MAX_TAGS
            || self
                .human
                .destinations
                .iter()
                .any(|d| d.label.len() > MAX_TITLE || d.value.len() > MAX_URL)
            || self.human.tags.iter().any(|tag| tag.len() > MAX_TITLE)
            || self.human.fields.iter().any(invalid_field)
            || self.human.source_fields.iter().any(invalid_source_field)
            || self
                .attachments
                .iter()
                .any(|a| a.size > MAX_FILE || a.name.len() > MAX_TITLE || a.mime.len() > MAX_TITLE)
            || complete_files
                && self.attachments.iter().any(|a| {
                    usize::try_from(a.size).ok() != Some(a.content.len())
                        || digest(&a.content) != a.sha256
                })
            || has_duplicate_attachment_ids(&self.attachments)
            || self
                .auth
                .iter()
                .any(|a| !valid_auth(a, self.human.destinations.len()))
        {
            return Err(HumanCommitError::InvalidInput);
        }
        let logical_size = self.encode_human().len() + self.encode_auth().map_or(0, |v| v.len());
        if logical_size > MAX_LOGICAL_RECORD {
            return Err(HumanCommitError::InvalidInput);
        }
        Ok(())
    }
}

impl Drop for LogicalRecord {
    fn drop(&mut self) {
        self.human.notes.zeroize();
        for field in &mut self.human.fields {
            match &mut field.value {
                LogicalValue::Text(v) => v.zeroize(),
                LogicalValue::Bytes(v) => v.zeroize(),
            }
        }
        for field in &mut self.human.source_fields {
            field.value.zeroize();
        }
        for auth in &mut self.auth {
            match auth {
                AuthRecord::Password { password, .. }
                | AuthRecord::Totp {
                    secret: password, ..
                }
                | AuthRecord::Token {
                    secret: password, ..
                } => password.zeroize(),
                AuthRecord::Passkey { private_key, .. } => private_key.zeroize(),
                AuthRecord::Ssh {
                    private_key,
                    passphrase,
                    ..
                } => {
                    private_key.zeroize();
                    if let Some(value) = passphrase {
                        value.zeroize();
                    }
                }
            }
        }
        for attachment in &mut self.attachments {
            attachment.content.zeroize();
        }
    }
}

fn invalid_field(field: &CustomField) -> bool {
    field.label.len() > MAX_TITLE
        || match &field.value {
            LogicalValue::Text(value) => value.len() > MAX_FIELD,
            LogicalValue::Bytes(value) => value.len() > MAX_FIELD,
        }
}

fn invalid_source_field(field: &SourceField) -> bool {
    field.path.len() > MAX_TITLE
        || field.value.len() > MAX_FIELD
        || matches!(field.encoding, SourceEncoding::Utf8 | SourceEncoding::Json)
            && std::str::from_utf8(&field.value).is_err()
}

fn has_duplicate_attachment_ids(values: &[Attachment]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(i, value)| values[..i].iter().any(|other| other.id == value.id))
}

fn valid_refs(refs: &[u16], destinations: usize) -> bool {
    refs.windows(2).all(|pair| pair[0] < pair[1])
        && refs.iter().all(|value| usize::from(*value) < destinations)
}

fn valid_auth(auth: &AuthRecord, destinations: usize) -> bool {
    match auth {
        AuthRecord::Password {
            username,
            password,
            destination_refs,
        } => {
            username.len() <= MAX_FIELD
                && password.len() <= MAX_FIELD
                && valid_refs(destination_refs, destinations)
        }
        AuthRecord::Totp {
            secret,
            digits,
            period,
            t0,
            issuer,
            account,
            destination_refs,
            ..
        } => {
            (10..=128).contains(&secret.len())
                && matches!(digits, 6 | 8)
                && (15..=120).contains(period)
                && *t0 == 0
                && issuer.len() <= MAX_FIELD
                && account.len() <= MAX_FIELD
                && valid_refs(destination_refs, destinations)
        }
        AuthRecord::Passkey {
            rp_id,
            user_handle,
            credential_id,
            cose_alg,
            user_name,
            display_name,
            ..
        } => {
            rp_id.len() <= MAX_URL
                && user_handle.len() <= 64
                && (1..=1024).contains(&credential_id.len())
                && *cose_alg == -8
                && user_name.len() <= MAX_FIELD
                && display_name.len() <= MAX_FIELD
        }
        AuthRecord::Ssh {
            private_key,
            public_key,
            username,
            destination_refs,
            passphrase,
            ..
        } => {
            private_key.len() <= MAX_FIELD
                && public_key.len() <= MAX_FIELD
                && username.len() <= MAX_FIELD
                && passphrase.as_ref().is_none_or(|v| v.len() <= MAX_FIELD)
                && valid_refs(destination_refs, destinations)
        }
        AuthRecord::Token {
            secret,
            provider,
            profile_id,
            destination_refs,
            ..
        } => {
            secret.len() <= MAX_FIELD
                && provider.len() <= MAX_TITLE
                && profile_id.len() <= MAX_TITLE
                && valid_refs(destination_refs, destinations)
        }
    }
}

fn key(encoder: &mut Encoder<Vec<u8>>, value: &str) {
    encoder.str(value).unwrap();
}

fn encode_strings(encoder: &mut Encoder<Vec<u8>>, values: &[String]) {
    encoder.array(u64::try_from(values.len()).unwrap()).unwrap();
    for value in values {
        encoder.str(value).unwrap();
    }
}

fn encode_destinations(encoder: &mut Encoder<Vec<u8>>, values: &[Destination]) {
    encoder.array(u64::try_from(values.len()).unwrap()).unwrap();
    for value in values {
        encoder.map(2).unwrap();
        key(encoder, "label");
        encoder.str(&value.label).unwrap();
        key(encoder, "value");
        encoder.str(&value.value).unwrap();
    }
}

fn encode_fields(encoder: &mut Encoder<Vec<u8>>, values: &[CustomField]) {
    encoder.array(u64::try_from(values.len()).unwrap()).unwrap();
    for value in values {
        encoder.map(5).unwrap();
        key(encoder, "id");
        encoder.bytes(&value.id).unwrap();
        key(encoder, "label");
        encoder.str(&value.label).unwrap();
        key(encoder, "encoding");
        encoder
            .str(match value.value {
                LogicalValue::Text(_) => "utf8",
                LogicalValue::Bytes(_) => "bytes",
            })
            .unwrap();
        key(encoder, "value");
        match &value.value {
            LogicalValue::Text(v) => {
                encoder.str(v).unwrap();
            }
            LogicalValue::Bytes(v) => {
                encoder.bytes(v).unwrap();
            }
        }
        key(encoder, "concealed");
        encoder.bool(value.concealed).unwrap();
    }
}

fn encode_source_fields(encoder: &mut Encoder<Vec<u8>>, values: &[SourceField]) {
    encoder.array(u64::try_from(values.len()).unwrap()).unwrap();
    for value in values {
        encoder.map(3).unwrap();
        key(encoder, "path");
        encoder.str(&value.path).unwrap();
        key(encoder, "encoding");
        encoder.str(value.encoding.name()).unwrap();
        key(encoder, "value");
        encoder.bytes(&value.value).unwrap();
    }
}

fn encode_attachment_metadata(encoder: &mut Encoder<Vec<u8>>, values: &[Attachment]) {
    encoder.array(u64::try_from(values.len()).unwrap()).unwrap();
    for value in values {
        encoder.map(5).unwrap();
        key(encoder, "id");
        encoder.bytes(&value.id).unwrap();
        key(encoder, "name");
        encoder.str(&value.name).unwrap();
        key(encoder, "mime");
        encoder.str(&value.mime).unwrap();
        key(encoder, "size");
        encoder.u64(value.size).unwrap();
        key(encoder, "sha256");
        encoder.bytes(&value.sha256).unwrap();
    }
}

fn encode_refs(encoder: &mut Encoder<Vec<u8>>, refs: &[u16]) {
    encoder.array(u64::try_from(refs.len()).unwrap()).unwrap();
    for value in refs {
        encoder.u16(*value).unwrap();
    }
}

#[allow(clippy::too_many_lines)]
fn encode_auth(encoder: &mut Encoder<Vec<u8>>, auth: &AuthRecord) {
    match auth {
        AuthRecord::Password {
            username,
            password,
            destination_refs,
        } => {
            encoder.map(4).unwrap();
            key(encoder, "method");
            encoder.str("password").unwrap();
            key(encoder, "username");
            encoder.str(username).unwrap();
            key(encoder, "password");
            encoder.bytes(password).unwrap();
            key(encoder, "destination_refs");
            encode_refs(encoder, destination_refs);
        }
        AuthRecord::Totp {
            secret,
            algorithm,
            digits,
            period,
            t0,
            issuer,
            account,
            destination_refs,
        } => {
            encoder.map(9).unwrap();
            key(encoder, "method");
            encoder.str("totp").unwrap();
            key(encoder, "secret");
            encoder.bytes(secret).unwrap();
            key(encoder, "algorithm");
            encoder.str(algorithm.name()).unwrap();
            key(encoder, "digits");
            encoder.u8(*digits).unwrap();
            key(encoder, "period");
            encoder.u16(*period).unwrap();
            key(encoder, "t0");
            encoder.u64(*t0).unwrap();
            key(encoder, "issuer");
            encoder.str(issuer).unwrap();
            key(encoder, "account");
            encoder.str(account).unwrap();
            key(encoder, "destination_refs");
            encode_refs(encoder, destination_refs);
        }
        AuthRecord::Passkey {
            rp_id,
            user_handle,
            credential_id,
            cose_alg,
            private_key,
            public_key,
            user_name,
            display_name,
            sign_count,
            backup_eligible,
            backup_state,
        } => {
            encoder.map(12).unwrap();
            key(encoder, "method");
            encoder.str("passkey").unwrap();
            key(encoder, "rp_id");
            encoder.str(rp_id).unwrap();
            key(encoder, "user_handle");
            encoder.bytes(user_handle).unwrap();
            key(encoder, "credential_id");
            encoder.bytes(credential_id).unwrap();
            key(encoder, "cose_alg");
            encoder.i64(*cose_alg).unwrap();
            key(encoder, "private_key");
            encoder.bytes(private_key).unwrap();
            key(encoder, "public_key");
            encoder.bytes(public_key).unwrap();
            key(encoder, "user_name");
            encoder.str(user_name).unwrap();
            key(encoder, "display_name");
            encoder.str(display_name).unwrap();
            key(encoder, "sign_count");
            encoder.u32(*sign_count).unwrap();
            key(encoder, "backup_eligible");
            encoder.bool(*backup_eligible).unwrap();
            key(encoder, "backup_state");
            encoder.bool(*backup_state).unwrap();
        }
        AuthRecord::Ssh {
            private_format,
            private_key,
            public_key,
            username,
            destination_refs,
            passphrase,
        } => {
            encoder.map(7).unwrap();
            key(encoder, "method");
            encoder.str("ssh").unwrap();
            key(encoder, "private_format");
            encoder.str(private_format.name()).unwrap();
            key(encoder, "private_key");
            encoder.bytes(private_key).unwrap();
            key(encoder, "public_key");
            encoder.bytes(public_key).unwrap();
            key(encoder, "username");
            encoder.str(username).unwrap();
            key(encoder, "destination_refs");
            encode_refs(encoder, destination_refs);
            key(encoder, "passphrase");
            encode_optional_bytes(encoder, passphrase.as_deref());
        }
        AuthRecord::Token {
            secret,
            provider,
            profile_id,
            destination_refs,
            expires_at,
        } => {
            encoder.map(6).unwrap();
            key(encoder, "method");
            encoder.str("token").unwrap();
            key(encoder, "secret");
            encoder.bytes(secret).unwrap();
            key(encoder, "provider");
            encoder.str(provider).unwrap();
            key(encoder, "profile_id");
            encoder.str(profile_id).unwrap();
            key(encoder, "destination_refs");
            encode_refs(encoder, destination_refs);
            key(encoder, "expires_at");
            if let Some(value) = expires_at {
                encoder.i64(*value).unwrap();
            } else {
                encoder.null().unwrap();
            }
        }
    }
}

fn decode_human(
    bytes: &[u8],
) -> Result<(RecordKind, HumanMetadata, Vec<Attachment>), HumanCommitError> {
    let mut d = Decoder::new(bytes);
    expect_map(&mut d, 10)?;
    expect_key(&mut d, "v")?;
    if d.u8().map_err(invalid)? != 1 {
        return Err(HumanCommitError::InvalidInput);
    }
    expect_key(&mut d, "kind")?;
    let kind = RecordKind::parse(d.str().map_err(invalid)?)?;
    expect_key(&mut d, "title")?;
    let title = d.str().map_err(invalid)?.to_owned();
    expect_key(&mut d, "destinations")?;
    let destinations = decode_destinations(&mut d)?;
    expect_key(&mut d, "tags")?;
    let tags = decode_strings(&mut d)?;
    expect_key(&mut d, "favorite")?;
    let favorite = d.bool().map_err(invalid)?;
    expect_key(&mut d, "notes")?;
    let notes = d.str().map_err(invalid)?.to_owned();
    expect_key(&mut d, "fields")?;
    let fields = decode_fields(&mut d)?;
    expect_key(&mut d, "source_fields")?;
    let source_fields = decode_source_fields(&mut d)?;
    expect_key(&mut d, "attachments")?;
    let attachments = decode_attachment_metadata(&mut d)?;
    if d.position() != bytes.len() {
        return Err(HumanCommitError::InvalidInput);
    }
    Ok((
        kind,
        HumanMetadata {
            title,
            destinations,
            tags,
            favorite,
            notes,
            fields,
            source_fields,
        },
        attachments,
    ))
}

fn decode_auth_array(bytes: Option<&[u8]>) -> Result<Vec<AuthRecord>, HumanCommitError> {
    let Some(bytes) = bytes else {
        return Ok(Vec::new());
    };
    let mut d = Decoder::new(bytes);
    let len = array_len(&mut d)?;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        values.push(decode_auth(&mut d)?);
    }
    if d.position() != bytes.len() {
        return Err(HumanCommitError::InvalidInput);
    }
    Ok(values)
}

#[allow(clippy::too_many_lines)]
fn decode_auth(d: &mut Decoder<'_>) -> Result<AuthRecord, HumanCommitError> {
    let fields = d
        .map()
        .map_err(invalid)?
        .ok_or(HumanCommitError::InvalidInput)?;
    if fields == 0 {
        return Err(HumanCommitError::InvalidInput);
    }
    expect_key(d, "method")?;
    let method = d.str().map_err(invalid)?;
    match method {
        "password" if fields == 4 => {
            expect_key(d, "username")?;
            let username = d.str().map_err(invalid)?.to_owned();
            expect_key(d, "password")?;
            let password = d.bytes().map_err(invalid)?.to_vec();
            expect_key(d, "destination_refs")?;
            Ok(AuthRecord::Password {
                username,
                password,
                destination_refs: decode_refs(d)?,
            })
        }
        "totp" if fields == 9 => {
            expect_key(d, "secret")?;
            let secret = d.bytes().map_err(invalid)?.to_vec();
            expect_key(d, "algorithm")?;
            let algorithm = TotpAlgorithm::parse(d.str().map_err(invalid)?)?;
            expect_key(d, "digits")?;
            let digits = d.u8().map_err(invalid)?;
            expect_key(d, "period")?;
            let period = d.u16().map_err(invalid)?;
            expect_key(d, "t0")?;
            let t0 = d.u64().map_err(invalid)?;
            expect_key(d, "issuer")?;
            let issuer = d.str().map_err(invalid)?.to_owned();
            expect_key(d, "account")?;
            let account = d.str().map_err(invalid)?.to_owned();
            expect_key(d, "destination_refs")?;
            Ok(AuthRecord::Totp {
                secret,
                algorithm,
                digits,
                period,
                t0,
                issuer,
                account,
                destination_refs: decode_refs(d)?,
            })
        }
        "passkey" if fields == 12 => {
            expect_key(d, "rp_id")?;
            let rp_id = d.str().map_err(invalid)?.to_owned();
            expect_key(d, "user_handle")?;
            let user_handle = d.bytes().map_err(invalid)?.to_vec();
            expect_key(d, "credential_id")?;
            let credential_id = d.bytes().map_err(invalid)?.to_vec();
            expect_key(d, "cose_alg")?;
            let cose_alg = d.i64().map_err(invalid)?;
            expect_key(d, "private_key")?;
            let private_key = fixed(d)?;
            expect_key(d, "public_key")?;
            let public_key = fixed(d)?;
            expect_key(d, "user_name")?;
            let user_name = d.str().map_err(invalid)?.to_owned();
            expect_key(d, "display_name")?;
            let display_name = d.str().map_err(invalid)?.to_owned();
            expect_key(d, "sign_count")?;
            let sign_count = d.u32().map_err(invalid)?;
            expect_key(d, "backup_eligible")?;
            let backup_eligible = d.bool().map_err(invalid)?;
            expect_key(d, "backup_state")?;
            let backup_state = d.bool().map_err(invalid)?;
            Ok(AuthRecord::Passkey {
                rp_id,
                user_handle,
                credential_id,
                cose_alg,
                private_key,
                public_key,
                user_name,
                display_name,
                sign_count,
                backup_eligible,
                backup_state,
            })
        }
        "ssh" if fields == 7 => {
            expect_key(d, "private_format")?;
            let private_format = PrivateKeyFormat::parse(d.str().map_err(invalid)?)?;
            expect_key(d, "private_key")?;
            let private_key = d.bytes().map_err(invalid)?.to_vec();
            expect_key(d, "public_key")?;
            let public_key = d.bytes().map_err(invalid)?.to_vec();
            expect_key(d, "username")?;
            let username = d.str().map_err(invalid)?.to_owned();
            expect_key(d, "destination_refs")?;
            let destination_refs = decode_refs(d)?;
            expect_key(d, "passphrase")?;
            let passphrase = decode_optional_bytes(d)?;
            Ok(AuthRecord::Ssh {
                private_format,
                private_key,
                public_key,
                username,
                destination_refs,
                passphrase,
            })
        }
        "token" if fields == 6 => {
            expect_key(d, "secret")?;
            let secret = d.bytes().map_err(invalid)?.to_vec();
            expect_key(d, "provider")?;
            let provider = d.str().map_err(invalid)?.to_owned();
            expect_key(d, "profile_id")?;
            let profile_id = d.str().map_err(invalid)?.to_owned();
            expect_key(d, "destination_refs")?;
            let destination_refs = decode_refs(d)?;
            expect_key(d, "expires_at")?;
            let expires_at = if d.datatype().map_err(invalid)? == Type::Null {
                d.null().map_err(invalid)?;
                None
            } else {
                Some(d.i64().map_err(invalid)?)
            };
            Ok(AuthRecord::Token {
                secret,
                provider,
                profile_id,
                destination_refs,
                expires_at,
            })
        }
        _ => Err(HumanCommitError::InvalidInput),
    }
}

fn decode_destinations(d: &mut Decoder<'_>) -> Result<Vec<Destination>, HumanCommitError> {
    let len = array_len(d)?;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        expect_map(d, 2)?;
        expect_key(d, "label")?;
        let label = d.str().map_err(invalid)?.to_owned();
        expect_key(d, "value")?;
        let value = d.str().map_err(invalid)?.to_owned();
        values.push(Destination { label, value });
    }
    Ok(values)
}
fn decode_strings(d: &mut Decoder<'_>) -> Result<Vec<String>, HumanCommitError> {
    let len = array_len(d)?;
    (0..len)
        .map(|_| d.str().map(str::to_owned).map_err(invalid))
        .collect()
}
fn decode_fields(d: &mut Decoder<'_>) -> Result<Vec<CustomField>, HumanCommitError> {
    let len = array_len(d)?;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        expect_map(d, 5)?;
        expect_key(d, "id")?;
        let id = fixed(d)?;
        expect_key(d, "label")?;
        let label = d.str().map_err(invalid)?.to_owned();
        expect_key(d, "encoding")?;
        let encoding = d.str().map_err(invalid)?;
        expect_key(d, "value")?;
        let value = match encoding {
            "utf8" => LogicalValue::Text(d.str().map_err(invalid)?.to_owned()),
            "bytes" => LogicalValue::Bytes(d.bytes().map_err(invalid)?.to_vec()),
            _ => return Err(HumanCommitError::InvalidInput),
        };
        expect_key(d, "concealed")?;
        let concealed = d.bool().map_err(invalid)?;
        values.push(CustomField {
            id,
            label,
            value,
            concealed,
        });
    }
    Ok(values)
}
fn decode_source_fields(d: &mut Decoder<'_>) -> Result<Vec<SourceField>, HumanCommitError> {
    let len = array_len(d)?;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        expect_map(d, 3)?;
        expect_key(d, "path")?;
        let path = d.str().map_err(invalid)?.to_owned();
        expect_key(d, "encoding")?;
        let encoding = SourceEncoding::parse(d.str().map_err(invalid)?)?;
        expect_key(d, "value")?;
        let value = d.bytes().map_err(invalid)?.to_vec();
        values.push(SourceField {
            path,
            encoding,
            value,
        });
    }
    Ok(values)
}
fn decode_attachment_metadata(d: &mut Decoder<'_>) -> Result<Vec<Attachment>, HumanCommitError> {
    let len = array_len(d)?;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        expect_map(d, 5)?;
        expect_key(d, "id")?;
        let id = fixed(d)?;
        expect_key(d, "name")?;
        let name = d.str().map_err(invalid)?.to_owned();
        expect_key(d, "mime")?;
        let mime = d.str().map_err(invalid)?.to_owned();
        expect_key(d, "size")?;
        let size = d.u64().map_err(invalid)?;
        expect_key(d, "sha256")?;
        let sha256 = fixed(d)?;
        values.push(Attachment {
            id,
            name,
            mime,
            size,
            sha256,
            content: Vec::new(),
        });
    }
    Ok(values)
}
fn decode_refs(d: &mut Decoder<'_>) -> Result<Vec<u16>, HumanCommitError> {
    let len = array_len(d)?;
    (0..len).map(|_| d.u16().map_err(invalid)).collect()
}
fn decode_optional_bytes(d: &mut Decoder<'_>) -> Result<Option<Vec<u8>>, HumanCommitError> {
    if d.datatype().map_err(invalid)? == Type::Null {
        d.null().map_err(invalid)?;
        Ok(None)
    } else {
        Ok(Some(d.bytes().map_err(invalid)?.to_vec()))
    }
}
fn encode_optional_bytes(e: &mut Encoder<Vec<u8>>, value: Option<&[u8]>) {
    if let Some(v) = value {
        e.bytes(v).unwrap();
    } else {
        e.null().unwrap();
    }
}
fn array_len(d: &mut Decoder<'_>) -> Result<usize, HumanCommitError> {
    usize::try_from(
        d.array()
            .map_err(invalid)?
            .ok_or(HumanCommitError::InvalidInput)?,
    )
    .map_err(|_| HumanCommitError::InvalidInput)
}
fn expect_map(d: &mut Decoder<'_>, expected: u64) -> Result<(), HumanCommitError> {
    if d.map().map_err(invalid)? == Some(expected) {
        Ok(())
    } else {
        Err(HumanCommitError::InvalidInput)
    }
}
fn expect_key(d: &mut Decoder<'_>, expected: &str) -> Result<(), HumanCommitError> {
    if d.str().map_err(invalid)? == expected {
        Ok(())
    } else {
        Err(HumanCommitError::InvalidInput)
    }
}
fn fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N], HumanCommitError> {
    d.bytes()
        .map_err(invalid)?
        .try_into()
        .map_err(|_| HumanCommitError::InvalidInput)
}
fn invalid<T>(_: T) -> HumanCommitError {
    HumanCommitError::InvalidInput
}
