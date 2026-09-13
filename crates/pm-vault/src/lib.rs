// SPDX-License-Identifier: AGPL-3.0-only

//! Atomic persistence for already-encrypted vault objects.

mod human;

pub use human::{
    HumanChannel, HumanCommitError, HumanReceipt, HumanVault, PasswordRecord, PreparedHumanCommand,
};

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use pm_crypto::{
    CreatedRoot, CryptoError, KdfProfile, RecoveryCode, RootBundle, TrustedRoot, UnlockedRoot,
    create_human_root, open_human_root,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

const FORMAT_VERSION: i64 = 1;
const SUITE: i64 = 1;
const ROOT_KIND: &str = "human-root-bundle-v1";
const MAX_ROOT_BUNDLE_BYTES: i64 = 16 * 1024 * 1024;
static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub enum VaultError {
    AlreadyExists,
    Crypto(CryptoError),
    InvalidFormat,
    Io(std::io::Error),
    Storage(rusqlite::Error),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists => f.write_str("vault already exists"),
            Self::Crypto(error) => write!(f, "{error}"),
            Self::InvalidFormat => f.write_str("invalid or incompatible vault storage"),
            Self::Io(error) => write!(f, "vault I/O failed: {error}"),
            Self::Storage(error) => write!(f, "vault storage failed: {error}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<CryptoError> for VaultError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<std::io::Error> for VaultError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for VaultError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Storage(value)
    }
}

/// An in-memory enrollment that cannot be persisted until its recovery code
/// has been reintroduced successfully.
pub struct PendingVault {
    created: CreatedRoot,
    trusted_root: TrustedRoot,
}

impl PendingVault {
    /// Prepares independent root material entirely in memory.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid inputs or unavailable cryptographic resources.
    pub fn new(password: &[u8], profile: KdfProfile) -> Result<Self, VaultError> {
        let created = create_human_root(password, profile)?;
        let trusted_root = *created.bundle().trusted_root();
        Ok(Self {
            created,
            trusted_root,
        })
    }

    #[must_use]
    pub const fn recovery_code(&self) -> &RecoveryCode {
        self.created.recovery_code()
    }

    #[must_use]
    pub const fn trusted_root(&self) -> &TrustedRoot {
        &self.trusted_root
    }

    /// Atomically creates a new local vault. An existing target is never replaced.
    ///
    /// # Errors
    ///
    /// Returns an error unless recovery is confirmed, or if atomic durable
    /// persistence cannot complete without replacing the target.
    pub fn persist(self, path: &Path, reintroduced: &RecoveryCode) -> Result<(), VaultError> {
        let bundle = self
            .created
            .into_bundle_after_recovery_confirmation(reintroduced)?;
        persist_new(path, &bundle)
    }
}

/// Non-secret proof that the password path opened the root and matched the
/// separately stored trusted human root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenedVault {
    trusted_root: TrustedRoot,
}

impl OpenedVault {
    #[must_use]
    pub const fn trusted_root(&self) -> &TrustedRoot {
        &self.trusted_root
    }
}

/// Opens the database read-only, rejects its public format before running the
/// KDF, and authenticates all root envelopes without mutating the file.
///
/// # Errors
///
/// Returns an error for incompatible/invalid storage, wrong passwords, altered
/// envelopes, or I/O failures.
pub fn open_vault(path: &Path, password: &[u8]) -> Result<OpenedVault, VaultError> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    connection.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;")?;
    let (bundle, trusted_root) = load_and_validate_bundle(&connection)?;
    let unlocked = open_human_root(&bundle, password)?;
    if unlocked.vault_id() != trusted_root.vault_id()
        || unlocked.human_public_key() != trusted_root.public_key()
    {
        return Err(VaultError::InvalidFormat);
    }
    Ok(OpenedVault { trusted_root })
}

fn load_and_validate_bundle(
    connection: &Connection,
) -> Result<(RootBundle, TrustedRoot), VaultError> {
    let metadata = connection
        .query_row(
            "SELECT format_version, suite, vault_id, authority_epoch, human_public_key \
             FROM vault_metadata WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or(VaultError::InvalidFormat)?;
    if metadata.0 != FORMAT_VERSION
        || metadata.1 != SUITE
        || metadata.2.len() != 16
        || metadata.3 != 1
        || metadata.4.len() != 32
    {
        return Err(VaultError::InvalidFormat);
    }
    let row_count: i64 =
        connection.query_row("SELECT count(*) FROM encrypted_objects", [], |row| {
            row.get(0)
        })?;
    let bundle_size: i64 = connection
        .query_row(
            "SELECT length(value) FROM encrypted_objects WHERE kind = ?1",
            [ROOT_KIND],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(VaultError::InvalidFormat)?;
    if row_count != 1 || !(1..=MAX_ROOT_BUNDLE_BYTES).contains(&bundle_size) {
        return Err(VaultError::InvalidFormat);
    }
    let bytes: Vec<u8> = connection.query_row(
        "SELECT value FROM encrypted_objects WHERE kind = ?1",
        [ROOT_KIND],
        |row| row.get(0),
    )?;
    let bundle = RootBundle::from_bytes(&bytes)?;
    if bundle.trusted_root().vault_id().as_slice() != metadata.2
        || i64::try_from(bundle.trusted_root().epoch()).ok() != Some(metadata.3)
        || bundle.trusted_root().public_key().as_slice() != metadata.4
    {
        return Err(VaultError::InvalidFormat);
    }
    let trusted_root = *bundle.trusted_root();
    Ok((bundle, trusted_root))
}

fn unlock_root(connection: &Connection, password: &[u8]) -> Result<UnlockedRoot, VaultError> {
    let (bundle, trusted_root) = load_and_validate_bundle(connection)?;
    let unlocked = open_human_root(&bundle, password)?;
    if unlocked.vault_id() != trusted_root.vault_id()
        || unlocked.human_public_key() != trusted_root.public_key()
    {
        return Err(VaultError::InvalidFormat);
    }
    Ok(unlocked)
}

#[allow(clippy::too_many_lines)]
fn persist_new(path: &Path, bundle: &RootBundle) -> Result<(), VaultError> {
    if path.exists() {
        return Err(VaultError::AlreadyExists);
    }
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let (temporary_path, temporary_file) = create_temporary(parent, path)?;
    let wal_path = PathBuf::from(format!("{}-wal", temporary_path.display()));
    let shm_path = PathBuf::from(format!("{}-shm", temporary_path.display()));
    let result = (|| {
        drop(temporary_file);
        let mut connection =
            Connection::open_with_flags(&temporary_path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if journal_mode != "wal" {
            return Err(VaultError::InvalidFormat);
        }
        connection.execute_batch(
            "PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
             PRAGMA trusted_schema=OFF;
             CREATE TABLE vault_metadata (
               singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
               format_version INTEGER NOT NULL,
               suite INTEGER NOT NULL,
               vault_id BLOB NOT NULL CHECK (length(vault_id) = 16),
               authority_epoch INTEGER NOT NULL,
               human_public_key BLOB NOT NULL CHECK (length(human_public_key) = 32)
             ) STRICT;
             CREATE TABLE encrypted_objects (
               kind TEXT PRIMARY KEY,
               value BLOB NOT NULL CHECK (length(value) BETWEEN 1 AND 16777216)
             ) STRICT;
             CREATE TABLE vault_items (
               item_id BLOB PRIMARY KEY CHECK (length(item_id) = 16),
               visible_revision BLOB NOT NULL CHECK (length(visible_revision) = 16),
               status TEXT NOT NULL CHECK (status IN ('active', 'trash'))
             ) STRICT;
             CREATE TABLE revision_parts (
               revision_id BLOB PRIMARY KEY CHECK (length(revision_id) = 16),
               item_id BLOB NOT NULL CHECK (length(item_id) = 16),
               package BLOB NOT NULL CHECK (length(package) BETWEEN 1 AND 16777216)
             ) STRICT;
             CREATE TABLE authority_events (
               event_digest BLOB PRIMARY KEY CHECK (length(event_digest) = 32),
               event_id BLOB NOT NULL UNIQUE CHECK (length(event_id) = 16),
               transaction_id BLOB NOT NULL UNIQUE CHECK (length(transaction_id) = 16),
               event BLOB NOT NULL CHECK (length(event) BETWEEN 1 AND 262144),
               human_signature BLOB NOT NULL CHECK (length(human_signature) = 64)
             ) STRICT;
             CREATE TABLE outbox (
               event_digest BLOB PRIMARY KEY CHECK (length(event_digest) = 32),
               event BLOB NOT NULL CHECK (length(event) BETWEEN 1 AND 262144)
             ) STRICT;
             CREATE TABLE human_challenges (
               challenge BLOB PRIMARY KEY CHECK (length(challenge) = 32),
               transaction_id BLOB NOT NULL UNIQUE CHECK (length(transaction_id) = 16),
               command BLOB NOT NULL CHECK (length(command) BETWEEN 1 AND 262144),
               body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
               expected_state BLOB NOT NULL CHECK (length(expected_state) = 32),
               expires_at_us INTEGER NOT NULL,
               consumed INTEGER NOT NULL DEFAULT 0 CHECK (consumed IN (0, 1))
             ) STRICT;
             CREATE TABLE human_staging (
               transaction_id BLOB PRIMARY KEY CHECK (length(transaction_id) = 16),
               operation TEXT NOT NULL CHECK (operation IN ('item_write', 'item_lifecycle')),
               event_kind TEXT NOT NULL CHECK (event_kind IN ('item-revision', 'trash')),
               item_id BLOB NOT NULL CHECK (length(item_id) = 16),
               revision_id BLOB CHECK (revision_id IS NULL OR length(revision_id) = 16),
               body BLOB NOT NULL CHECK (length(body) BETWEEN 1 AND 262144),
               package BLOB CHECK (package IS NULL OR length(package) BETWEEN 1 AND 16777216)
             ) STRICT;
             CREATE TABLE human_receipts (
               transaction_id BLOB PRIMARY KEY CHECK (length(transaction_id) = 16),
               body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
               committed_heads BLOB NOT NULL CHECK (length(committed_heads) BETWEEN 2 AND 262144),
               committed_at_us INTEGER NOT NULL,
               outcome TEXT NOT NULL CHECK (outcome = 'committed')
             ) STRICT;
             CREATE TABLE audit_keys (
               device_id BLOB NOT NULL CHECK (length(device_id) = 16),
               generation INTEGER NOT NULL CHECK (generation > 0),
               envelope BLOB NOT NULL CHECK (length(envelope) BETWEEN 1 AND 16777216),
               PRIMARY KEY (device_id, generation)
             ) STRICT;
             CREATE TABLE audit_state (
               device_id BLOB PRIMARY KEY CHECK (length(device_id) = 16),
               generation INTEGER NOT NULL CHECK (generation > 0),
               seq INTEGER NOT NULL CHECK (seq > 0),
               last_hash BLOB NOT NULL CHECK (length(last_hash) = 32)
             ) STRICT;
             CREATE TABLE encrypted_audit_records (
               device_id BLOB NOT NULL CHECK (length(device_id) = 16),
               generation INTEGER NOT NULL CHECK (generation > 0),
               seq INTEGER NOT NULL CHECK (seq > 0),
               event_id BLOB NOT NULL UNIQUE CHECK (length(event_id) = 16),
               record BLOB NOT NULL CHECK (length(record) BETWEEN 1 AND 8192),
               PRIMARY KEY (device_id, generation, seq)
             ) STRICT;",
        )?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO vault_metadata
             (singleton, format_version, suite, vault_id, authority_epoch, human_public_key)
             VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            params![
                FORMAT_VERSION,
                SUITE,
                bundle.trusted_root().vault_id().as_slice(),
                i64::try_from(bundle.trusted_root().epoch())
                    .map_err(|_| VaultError::InvalidFormat)?,
                bundle.trusted_root().public_key().as_slice(),
            ],
        )?;
        let encrypted = bundle.to_bytes();
        transaction.execute(
            "INSERT INTO encrypted_objects (kind, value) VALUES (?1, ?2)",
            params![ROOT_KIND, encrypted],
        )?;
        transaction.commit()?;
        connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        connection.close().map_err(|(_, error)| error)?;

        File::open(&temporary_path)?.sync_all()?;
        fs::hard_link(&temporary_path, path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                VaultError::AlreadyExists
            } else {
                VaultError::Io(error)
            }
        })?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();

    let _ = fs::remove_file(&temporary_path);
    let _ = fs::remove_file(wal_path);
    let _ = fs::remove_file(shm_path);
    result
}

fn create_temporary(parent: &Path, target: &Path) -> Result<(PathBuf, File), VaultError> {
    let name = target
        .file_name()
        .ok_or(VaultError::InvalidFormat)?
        .to_string_lossy();
    for _ in 0..128 {
        let counter = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".{name}.tmp-{}-{counter}", std::process::id()));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(VaultError::Io(error)),
        }
    }
    Err(VaultError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate vault temporary file",
    )))
}
