// SPDX-License-Identifier: AGPL-3.0-only

//! Opaque self-hosted synchronization storage and E2EE vault replication.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use minicbor::{Decoder, Encoder};
use pm_crypto::{SyncPairing, digest};
use pm_vault::{CausalReducer, ReductionError, SignedCausalEvent};
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    fmt,
    fs::OpenOptions,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::Duration,
};

pub const MAX_BLOCK_BYTES: usize = 512 * 1024;
pub const MAX_LIST_LIMIT: usize = 256;

#[derive(Debug)]
pub enum SyncError {
    Unauthorized,
    InvalidRequest,
    Integrity,
    Missing,
    Backpressure,
    Unavailable,
    Storage(rusqlite::Error),
    Reduction(ReductionError),
    Crypto(pm_crypto::CryptoError),
}

#[allow(clippy::missing_errors_doc)]
pub trait SyncTransport {
    fn put(&self, namespace: [u8; 32], hash: [u8; 32], bytes: &[u8]) -> Result<(), SyncError>;
    fn get(&self, namespace: [u8; 32], hash: [u8; 32]) -> Result<Vec<u8>, SyncError>;
    fn publish(&self, namespace: [u8; 32], root: [u8; 32]) -> Result<(), SyncError>;
    fn list(
        &self,
        namespace: [u8; 32],
        cursor: Option<u64>,
        limit: usize,
    ) -> Result<Vec<(u64, [u8; 32])>, SyncError>;
}

impl SyncTransport for (&OpaqueSyncStore, &[u8]) {
    fn put(&self, n: [u8; 32], h: [u8; 32], b: &[u8]) -> Result<(), SyncError> {
        self.0.put(n, self.1, h, b)
    }
    fn get(&self, n: [u8; 32], h: [u8; 32]) -> Result<Vec<u8>, SyncError> {
        self.0.get(n, self.1, h)
    }
    fn publish(&self, n: [u8; 32], h: [u8; 32]) -> Result<(), SyncError> {
        self.0.publish(n, self.1, h)
    }
    fn list(
        &self,
        n: [u8; 32],
        c: Option<u64>,
        l: usize,
    ) -> Result<Vec<(u64, [u8; 32])>, SyncError> {
        self.0.list(n, self.1, c, l)
    }
}

/// Production transport adapter that invokes the bounded `pm-sync` TLS/RPK
/// client without exposing key bytes to the replica process.
pub struct ProcessTlsTransport {
    program: PathBuf,
    socket: PathBuf,
    client_key: PathBuf,
    server_public: PathBuf,
}
impl ProcessTlsTransport {
    #[must_use]
    pub fn new(program: &Path, socket: &Path, client_key: &Path, server_public: &Path) -> Self {
        Self {
            program: program.to_owned(),
            socket: socket.to_owned(),
            client_key: client_key.to_owned(),
            server_public: server_public.to_owned(),
        }
    }
    fn call(
        &self,
        method: &str,
        namespace: [u8; 32],
        extra: &[(&str, String)],
    ) -> Result<String, SyncError> {
        let mut command = Command::new(&self.program);
        command
            .arg(method)
            .arg("--socket")
            .arg(&self.socket)
            .arg("--client-key")
            .arg(&self.client_key)
            .arg("--server-pub")
            .arg(&self.server_public)
            .arg("--namespace")
            .arg(hex(&namespace));
        for (flag, value) in extra {
            command.arg(flag).arg(value);
        }
        let output = command.output().map_err(|_| SyncError::Unavailable)?;
        if !output.status.success() {
            return Err(SyncError::Unavailable);
        }
        String::from_utf8(output.stdout).map_err(|_| SyncError::Integrity)
    }
}
impl SyncTransport for ProcessTlsTransport {
    fn put(&self, n: [u8; 32], h: [u8; 32], b: &[u8]) -> Result<(), SyncError> {
        let parent = self.client_key.parent().ok_or(SyncError::Unavailable)?;
        let temporary = parent.join(format!(".pm-sync-put-{}-{}", std::process::id(), hex(&h)));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| SyncError::Unavailable)?;
        file.write_all(b)
            .and_then(|()| file.sync_all())
            .map_err(|_| SyncError::Unavailable)?;
        drop(file);
        let result = self.call(
            "put",
            n,
            &[
                ("--hash", hex(&h)),
                ("--input", temporary.display().to_string()),
            ],
        );
        let _ = std::fs::remove_file(temporary);
        result.map(drop)
    }
    fn get(&self, n: [u8; 32], h: [u8; 32]) -> Result<Vec<u8>, SyncError> {
        let response = self.call("get", n, &[("--hash", hex(&h))])?;
        let encoded = json_string(&response, "bytes").ok_or(SyncError::Integrity)?;
        let bytes = STANDARD.decode(encoded).map_err(|_| SyncError::Integrity)?;
        (digest(&bytes) == h)
            .then_some(bytes)
            .ok_or(SyncError::Integrity)
    }
    fn publish(&self, n: [u8; 32], h: [u8; 32]) -> Result<(), SyncError> {
        self.call("publish", n, &[("--hash", hex(&h))]).map(drop)
    }
    fn list(
        &self,
        n: [u8; 32],
        c: Option<u64>,
        l: usize,
    ) -> Result<Vec<(u64, [u8; 32])>, SyncError> {
        let mut extra = vec![("--limit", l.to_string())];
        if let Some(cursor) = c {
            extra.push(("--cursor", cursor.to_string()));
        }
        let response = self.call("list", n, &extra)?;
        parse_roots(&response)
    }
}

fn json_string<'a>(json: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("\"{name}\":\"");
    let rest = &json[json.find(&needle)? + needle.len()..];
    Some(&rest[..rest.find('"')?])
}
fn parse_roots(json: &str) -> Result<Vec<(u64, [u8; 32])>, SyncError> {
    let mut rest = json;
    let mut out = Vec::new();
    while let Some(index) = rest.find("\"cursor\":\"") {
        rest = &rest[index..];
        let cursor = json_string(rest, "cursor")
            .ok_or(SyncError::Integrity)?
            .parse()
            .map_err(|_| SyncError::Integrity)?;
        let hash = json_string(rest, "root_hash").ok_or(SyncError::Integrity)?;
        out.push((cursor, decode_hex32(hash)?));
        rest = &rest[rest.find("root_hash").ok_or(SyncError::Integrity)? + 9..];
    }
    Ok(out)
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    out
}
fn decode_hex32(value: &str) -> Result<[u8; 32], SyncError> {
    if value.len() != 64 {
        return Err(SyncError::Integrity);
    }
    let mut out = [0; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| SyncError::Integrity)?;
    }
    Ok(out)
}
impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("synchronization failed")
    }
}
impl std::error::Error for SyncError {}
impl From<rusqlite::Error> for SyncError {
    fn from(v: rusqlite::Error) -> Self {
        Self::Storage(v)
    }
}
impl From<ReductionError> for SyncError {
    fn from(v: ReductionError) -> Self {
        Self::Reduction(v)
    }
}
impl From<pm_crypto::CryptoError> for SyncError {
    fn from(v: pm_crypto::CryptoError) -> Self {
        Self::Crypto(v)
    }
}

/// Storage-only server. ACL identities protect availability, never vault authority.
pub struct OpaqueSyncStore {
    path: PathBuf,
}
#[allow(clippy::missing_errors_doc)]
impl OpaqueSyncStore {
    pub fn create(path: &Path) -> Result<Self, SyncError> {
        let c = Connection::open(path)?;
        c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA trusted_schema=OFF; CREATE TABLE IF NOT EXISTS namespaces(namespace BLOB NOT NULL,client_rpk BLOB NOT NULL,PRIMARY KEY(namespace,client_rpk)) STRICT; CREATE TABLE IF NOT EXISTS blocks(namespace BLOB NOT NULL,hash BLOB NOT NULL,bytes BLOB NOT NULL CHECK(length(bytes) BETWEEN 1 AND 524288),PRIMARY KEY(namespace,hash)) STRICT; CREATE TABLE IF NOT EXISTS roots(seq INTEGER PRIMARY KEY AUTOINCREMENT,namespace BLOB NOT NULL,hash BLOB NOT NULL,UNIQUE(namespace,hash)) STRICT;")?;
        Ok(Self {
            path: path.to_owned(),
        })
    }
    pub fn authorize(&self, namespace: [u8; 32], client_rpk: &[u8]) -> Result<(), SyncError> {
        if client_rpk.len() != 44 {
            return Err(SyncError::InvalidRequest);
        }
        let c = Connection::open(&self.path)?;
        c.execute(
            "INSERT OR IGNORE INTO namespaces(namespace,client_rpk) VALUES(?1,?2)",
            params![namespace.as_slice(), client_rpk],
        )?;
        Ok(())
    }
    fn check(c: &Connection, namespace: &[u8; 32], rpk: &[u8]) -> Result<(), SyncError> {
        let ok: Option<i64> = c
            .query_row(
                "SELECT 1 FROM namespaces WHERE namespace=?1 AND client_rpk=?2",
                params![namespace.as_slice(), rpk],
                |r| r.get(0),
            )
            .optional()?;
        ok.ok_or(SyncError::Unauthorized).map(drop)
    }
    pub fn put(
        &self,
        namespace: [u8; 32],
        rpk: &[u8],
        hash: [u8; 32],
        bytes: &[u8],
    ) -> Result<(), SyncError> {
        if bytes.is_empty() || bytes.len() > MAX_BLOCK_BYTES || digest(bytes) != hash {
            return Err(SyncError::Integrity);
        }
        let c = Connection::open(&self.path)?;
        Self::check(&c, &namespace, rpk)?;
        let existing: Option<Vec<u8>> = c
            .query_row(
                "SELECT bytes FROM blocks WHERE namespace=?1 AND hash=?2",
                params![namespace.as_slice(), hash.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(v) = existing {
            return if v == bytes {
                Ok(())
            } else {
                Err(SyncError::Integrity)
            };
        }
        c.execute(
            "INSERT INTO blocks(namespace,hash,bytes)VALUES(?1,?2,?3)",
            params![namespace.as_slice(), hash.as_slice(), bytes],
        )?;
        Ok(())
    }
    pub fn get(
        &self,
        namespace: [u8; 32],
        rpk: &[u8],
        hash: [u8; 32],
    ) -> Result<Vec<u8>, SyncError> {
        let c = Connection::open(&self.path)?;
        Self::check(&c, &namespace, rpk)?;
        let bytes: Vec<u8> = c
            .query_row(
                "SELECT bytes FROM blocks WHERE namespace=?1 AND hash=?2",
                params![namespace.as_slice(), hash.as_slice()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(SyncError::Missing)?;
        if digest(&bytes) != hash {
            return Err(SyncError::Integrity);
        }
        Ok(bytes)
    }
    pub fn publish(
        &self,
        namespace: [u8; 32],
        rpk: &[u8],
        root: [u8; 32],
    ) -> Result<(), SyncError> {
        let c = Connection::open(&self.path)?;
        Self::check(&c, &namespace, rpk)?;
        let exists: Option<i64> = c
            .query_row(
                "SELECT 1 FROM blocks WHERE namespace=?1 AND hash=?2",
                params![namespace.as_slice(), root.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        exists.ok_or(SyncError::Missing)?;
        c.execute(
            "INSERT OR IGNORE INTO roots(namespace,hash)VALUES(?1,?2)",
            params![namespace.as_slice(), root.as_slice()],
        )?;
        Ok(())
    }
    pub fn list(
        &self,
        namespace: [u8; 32],
        rpk: &[u8],
        cursor: Option<u64>,
        limit: usize,
    ) -> Result<Vec<(u64, [u8; 32])>, SyncError> {
        if limit == 0 || limit > MAX_LIST_LIMIT {
            return Err(SyncError::InvalidRequest);
        }
        let c = Connection::open(&self.path)?;
        Self::check(&c, &namespace, rpk)?;
        let mut s = c.prepare(
            "SELECT seq,hash FROM roots WHERE namespace=?1 AND seq>?2 ORDER BY seq LIMIT ?3",
        )?;
        let rows = s.query_map(
            params![
                namespace.as_slice(),
                i64::try_from(cursor.unwrap_or(0)).map_err(|_| SyncError::InvalidRequest)?,
                i64::try_from(limit).map_err(|_| SyncError::InvalidRequest)?
            ],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
        )?;
        let mut out = Vec::new();
        for row in rows {
            let (seq, h) = row?;
            out.push((
                u64::try_from(seq).map_err(|_| SyncError::Integrity)?,
                h.try_into().map_err(|_| SyncError::Integrity)?,
            ));
        }
        Ok(out)
    }
    pub fn delete(
        &self,
        namespace: [u8; 32],
        rpk: &[u8],
        hashes: &[[u8; 32]],
    ) -> Result<(), SyncError> {
        if hashes.len() > 256 {
            return Err(SyncError::InvalidRequest);
        }
        let mut c = Connection::open(&self.path)?;
        Self::check(&c, &namespace, rpk)?;
        let tx = c.transaction()?;
        for hash in hashes {
            tx.execute("DELETE FROM blocks WHERE namespace=?1 AND hash=?2 AND NOT EXISTS(SELECT 1 FROM roots WHERE namespace=?1 AND hash=?2)",params![namespace.as_slice(),hash.as_slice()])?;
        }
        tx.commit()?;
        Ok(())
    }
}

/// Local E2EE replication client backed by the vault's durable outbox/reducer.
pub struct SyncReplica {
    vault: PathBuf,
    pairing: SyncPairing,
}
#[allow(clippy::missing_errors_doc)]
impl SyncReplica {
    pub fn new(
        vault: &Path,
        pairing: SyncPairing,
        _client_rpk: [u8; 44],
        observed_server_pin: [u8; 44],
    ) -> Result<Self, SyncError> {
        if pairing.server_pin() != &observed_server_pin {
            return Err(SyncError::Unauthorized);
        }
        Ok(Self {
            vault: vault.to_owned(),
            pairing,
        })
    }
    pub fn push(&mut self, server: &impl SyncTransport) -> Result<usize, SyncError> {
        let reducer = CausalReducer::open(&self.vault)?;
        // Never acknowledge a locally corrupted ledger merely because an
        // availability-only server accepted opaque bytes.
        reducer.view()?;
        let events = reducer.pending_outbox()?;
        if events.is_empty() {
            return Ok(0);
        }
        let namespace = *self.pairing.namespace();
        let mut hashes = Vec::with_capacity(events.len());
        let mut event_ids = Vec::with_capacity(events.len());
        for event in &events {
            let sealed = self.pairing.seal(&event.to_bytes())?;
            let hash = digest(&sealed);
            retry(|| server.put(namespace, hash, &sealed))?;
            hashes.push(hash);
            event_ids.push(event.digest());
        }
        hashes.sort_unstable();
        hashes.dedup();
        let descriptor = encode_descriptor(&hashes);
        let sealed = self.pairing.seal(&descriptor)?;
        let root = digest(&sealed);
        retry(|| server.put(namespace, root, &sealed))?;
        retry(|| server.publish(namespace, root))?;
        reducer.acknowledge_outbox(&event_ids)?;
        Ok(events.len())
    }
    pub fn pull(&mut self, server: &impl SyncTransport) -> Result<usize, SyncError> {
        ensure_replica_schema(&self.vault)?;
        let namespace = *self.pairing.namespace();
        let mut cursor = 0_u64;
        let mut applied = 0_usize;
        loop {
            let roots = retry(|| server.list(namespace, Some(cursor), 128))?;
            if roots.is_empty() {
                break;
            }
            for (seq, root) in &roots {
                cursor = *seq;
                if root_seen(&self.vault, *root)? {
                    continue;
                }
                let sealed_root = retry(|| server.get(namespace, *root))?;
                let descriptor = self.pairing.open(&sealed_root)?;
                let hashes = decode_descriptor(&descriptor)?;
                let mut events = Vec::with_capacity(hashes.len());
                for hash in hashes {
                    let sealed = retry(|| server.get(namespace, hash))?;
                    let bytes = self.pairing.open(&sealed)?;
                    events.push(SignedCausalEvent::from_bytes(&bytes)?);
                }
                let mut reducer = CausalReducer::open(&self.vault)?;
                reducer.apply_received(&events)?;
                mark_root_seen(&self.vault, *root)?;
                applied = applied
                    .checked_add(events.len())
                    .ok_or(SyncError::Backpressure)?;
            }
            if roots.len() < 128 {
                break;
            }
        }
        Ok(applied)
    }
    pub fn reducer(&self) -> Result<CausalReducer, SyncError> {
        Ok(CausalReducer::open(&self.vault)?)
    }
}

const RETRY_SECONDS: [u64; 6] = [1, 2, 4, 8, 16, 30];
fn retry<T>(mut operation: impl FnMut() -> Result<T, SyncError>) -> Result<T, SyncError> {
    for delay in RETRY_SECONDS {
        match operation() {
            Err(SyncError::Unavailable) => thread::sleep(Duration::from_secs(delay)),
            result => return result,
        }
    }
    operation()
}

fn encode_descriptor(hashes: &[[u8; 32]]) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(2)
        .unwrap()
        .u64(1)
        .unwrap()
        .array(u64::try_from(hashes.len()).unwrap())
        .unwrap();
    for hash in hashes {
        e.bytes(hash).unwrap();
    }
    e.into_writer()
}
fn decode_descriptor(bytes: &[u8]) -> Result<Vec<[u8; 32]>, SyncError> {
    let mut d = Decoder::new(bytes);
    if d.array().map_err(|_| SyncError::Integrity)? != Some(2)
        || d.u64().map_err(|_| SyncError::Integrity)? != 1
    {
        return Err(SyncError::Integrity);
    }
    let n = d
        .array()
        .map_err(|_| SyncError::Integrity)?
        .ok_or(SyncError::Integrity)?;
    if n > 256 {
        return Err(SyncError::Backpressure);
    }
    let mut out = Vec::with_capacity(usize::try_from(n).map_err(|_| SyncError::Backpressure)?);
    for _ in 0..n {
        out.push(
            d.bytes()
                .map_err(|_| SyncError::Integrity)?
                .try_into()
                .map_err(|_| SyncError::Integrity)?,
        );
    }
    if d.position() != bytes.len()
        || !out.windows(2).all(|w| w[0] < w[1])
        || encode_descriptor(&out) != bytes
    {
        return Err(SyncError::Integrity);
    }
    Ok(out)
}
fn ensure_replica_schema(path: &Path) -> Result<(), SyncError> {
    Connection::open(path)?.execute_batch("CREATE TABLE IF NOT EXISTS sync_received_roots(root_hash BLOB PRIMARY KEY CHECK(length(root_hash)=32)) STRICT;")?;
    Ok(())
}
fn root_seen(path: &Path, root: [u8; 32]) -> Result<bool, SyncError> {
    Ok(Connection::open(path)?
        .query_row(
            "SELECT 1 FROM sync_received_roots WHERE root_hash=?1",
            [root.as_slice()],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
        .is_some())
}
fn mark_root_seen(path: &Path, root: [u8; 32]) -> Result<(), SyncError> {
    Connection::open(path)?.execute(
        "INSERT OR IGNORE INTO sync_received_roots(root_hash)VALUES(?1)",
        [root.as_slice()],
    )?;
    Ok(())
}
