// SPDX-License-Identifier: AGPL-3.0-only

//! Opaque self-hosted synchronization storage and E2EE vault replication.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use minicbor::{Decoder, Encoder};
use pm_crypto::{SyncPairing, digest};
use pm_vault::{
    CausalReducer, ReceivedCiphertextAttachment, ReceivedCiphertextGraph, ReceivedCiphertextStream,
    ReductionError, SignedCausalEvent,
};
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    fmt,
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::Duration,
};

pub const MAX_BLOCK_BYTES: usize = 512 * 1024;
pub const MAX_LIST_LIMIT: usize = 256;
pub const MAX_OBJECT_BYTES: u64 = 16 * 1024 * 1024 * 1024;

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
            return Err(match output.status.code() {
                Some(5) => SyncError::Missing,
                Some(6) => SyncError::Backpressure,
                Some(7) => SyncError::Integrity,
                _ => SyncError::Unavailable,
            });
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
        let mut graph_hashes = Vec::new();
        let mut event_ids = Vec::with_capacity(events.len());
        for event in &events {
            let sealed = self.pairing.seal(&event.to_bytes())?;
            let hash = digest(&sealed);
            retry(|| server.put(namespace, hash, &sealed))?;
            hashes.push(hash);
            event_ids.push(event.digest());
            let stage = sync_stage(&self.vault, event.digest())?;
            if let Some(graph) = reducer.export_ciphertext_graph(event, &stage)? {
                graph_hashes.push(self.upload_graph(server, &graph)?);
            }
            let _ = std::fs::remove_dir_all(stage);
        }
        hashes.sort_unstable();
        hashes.dedup();
        let descriptor = encode_descriptor(&hashes, &graph_hashes);
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
                let (hashes, graph_hashes) = decode_descriptor(&descriptor)?;
                let mut events = Vec::with_capacity(hashes.len());
                for hash in hashes {
                    let sealed = retry(|| server.get(namespace, hash))?;
                    let bytes = self.pairing.open(&sealed)?;
                    events.push(SignedCausalEvent::from_bytes(&bytes)?);
                }
                let mut graphs = Vec::new();
                let mut stages = Vec::new();
                for hash in graph_hashes {
                    let stage = sync_stage(&self.vault, hash)?;
                    graphs.push(self.download_graph(server, hash, &stage)?);
                    stages.push(stage);
                }
                let mut reducer = CausalReducer::open(&self.vault)?;
                reducer.apply_received_package(&events, &graphs)?;
                for stage in stages {
                    let _ = std::fs::remove_dir_all(stage);
                }
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

    fn upload_graph(
        &self,
        t: &impl SyncTransport,
        g: &ReceivedCiphertextGraph,
    ) -> Result<[u8; 32], SyncError> {
        let package = self.upload_paged_file(t, &g.package)?;
        let mut attachments = Vec::new();
        for a in &g.attachments {
            attachments.push((a.id, self.upload_paged_file(t, &a.package)?));
        }
        let mut streams = Vec::new();
        for s in &g.streams {
            let joined = g
                .package
                .parent()
                .ok_or(SyncError::Integrity)?
                .join(format!("joined-{}", hex(&s.id)));
            let mut out = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&joined)
                .map_err(|_| SyncError::Unavailable)?;
            let mut lengths = Vec::new();
            for path in &s.chunks {
                let mut input = std::fs::File::open(path).map_err(|_| SyncError::Unavailable)?;
                let n = std::io::copy(&mut input, &mut out).map_err(|_| SyncError::Unavailable)?;
                lengths.push(n);
            }
            out.sync_all().map_err(|_| SyncError::Unavailable)?;
            drop(out);
            let root = self.upload_paged_file(t, &joined)?;
            streams.push((s.id, s.header.clone(), root, lengths));
            let _ = std::fs::remove_file(joined);
        }
        let bytes = encode_graph(g.item, g.revision, &g.kind, package, &attachments, &streams);
        let sealed = self.pairing.seal(&bytes)?;
        let hash = digest(&sealed);
        retry(|| t.put(*self.pairing.namespace(), hash, &sealed))?;
        Ok(hash)
    }
    fn download_graph(
        &self,
        t: &impl SyncTransport,
        root: [u8; 32],
        stage: &Path,
    ) -> Result<ReceivedCiphertextGraph, SyncError> {
        std::fs::create_dir_all(stage).map_err(|_| SyncError::Unavailable)?;
        let sealed = retry(|| t.get(*self.pairing.namespace(), root))?;
        let wire = decode_graph(&self.pairing.open(&sealed)?)?;
        let package = stage.join("revision");
        self.download_paged_file(t, wire.package, &package)?;
        let mut attachments = Vec::new();
        for (id, hash) in wire.attachments {
            let path = stage.join(format!("attachment-{}", hex(&id)));
            self.download_paged_file(t, hash, &path)?;
            attachments.push(ReceivedCiphertextAttachment { id, package: path });
        }
        let mut streams = Vec::new();
        for (id, header, hash, lengths) in wire.streams {
            let joined = stage.join(format!("joined-{}", hex(&id)));
            self.download_paged_file(t, hash, &joined)?;
            let mut input = std::fs::File::open(&joined).map_err(|_| SyncError::Unavailable)?;
            let mut chunks = Vec::new();
            for (index, length) in lengths.into_iter().enumerate() {
                if length == 0 || length > 1_048_597 {
                    return Err(SyncError::Backpressure);
                }
                let path = stage.join(format!("stream-{}-{index}", hex(&id)));
                let mut out = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .map_err(|_| SyncError::Unavailable)?;
                let copied = std::io::copy(
                    &mut std::io::Read::by_ref(&mut input).take(length),
                    &mut out,
                )
                .map_err(|_| SyncError::Unavailable)?;
                if copied != length {
                    return Err(SyncError::Integrity);
                }
                chunks.push(path);
            }
            let mut extra = [0];
            if input.read(&mut extra).map_err(|_| SyncError::Unavailable)? != 0 {
                return Err(SyncError::Integrity);
            }
            let _ = std::fs::remove_file(joined);
            streams.push(ReceivedCiphertextStream { id, header, chunks });
        }
        Ok(ReceivedCiphertextGraph {
            item: wire.item,
            revision: wire.revision,
            kind: wire.kind,
            package,
            attachments,
            streams,
        })
    }
}

const RETRY_SECONDS: [u64; 6] = [1, 2, 4, 8, 16, 30];
const PLAIN_BLOCK: usize = MAX_BLOCK_BYTES - 128;
const PAGE_ENTRIES: usize = 3;
fn retry<T>(mut operation: impl FnMut() -> Result<T, SyncError>) -> Result<T, SyncError> {
    for delay in RETRY_SECONDS {
        match operation() {
            Err(SyncError::Unavailable) => thread::sleep(Duration::from_secs(delay)),
            result => return result,
        }
    }
    operation()
}

#[derive(Clone)]
struct BlockRef {
    index: u64,
    hash: [u8; 32],
    cipher_len: u64,
    plain_len: u64,
}

impl SyncReplica {
    /// Uploads one already-encrypted logical object as ordered bounded blocks.
    ///
    /// # Errors
    /// Rejects empty, oversized, unavailable, or cryptographically failed input.
    pub fn upload_paged_file(
        &self,
        transport: &impl SyncTransport,
        path: &Path,
    ) -> Result<[u8; 32], SyncError> {
        let mut input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| {
                if error.raw_os_error() == Some(libc::ELOOP) {
                    SyncError::InvalidRequest
                } else {
                    SyncError::Unavailable
                }
            })?;
        let metadata = input.metadata().map_err(|_| SyncError::Unavailable)?;
        if !metadata.file_type().is_file() {
            return Err(SyncError::InvalidRequest);
        }
        let length = metadata.len();
        if length == 0 || length > MAX_OBJECT_BYTES {
            return Err(SyncError::Backpressure);
        }
        let namespace = *self.pairing.namespace();
        let mut buffer = vec![0; PLAIN_BLOCK];
        let mut index = 0u64;
        let mut total = 0u64;
        let mut full = pm_crypto::DigestState::new()?;
        let mut page = Vec::new();
        let mut pages = Vec::new();
        loop {
            let mut used = 0;
            while used < buffer.len() {
                let n = input
                    .read(&mut buffer[used..])
                    .map_err(|_| SyncError::Unavailable)?;
                if n == 0 {
                    break;
                }
                used += n;
            }
            if used == 0 {
                break;
            }
            let next_total = total
                .checked_add(used as u64)
                .ok_or(SyncError::Backpressure)?;
            if next_total > length || next_total > MAX_OBJECT_BYTES {
                return Err(SyncError::Integrity);
            }
            let sealed = self.pairing.seal(&buffer[..used])?;
            let hash = digest(&sealed);
            retry(|| transport.put(namespace, hash, &sealed))?;
            full.update(&sealed);
            total = next_total;
            page.push(BlockRef {
                index,
                hash,
                cipher_len: sealed.len() as u64,
                plain_len: used as u64,
            });
            index += 1;
            if page.len() == PAGE_ENTRIES {
                pages.push(self.upload_page(transport, &page)?);
                page.clear();
            }
        }
        if !page.is_empty() {
            pages.push(self.upload_page(transport, &page)?);
        }
        if total != length || total > MAX_OBJECT_BYTES {
            return Err(SyncError::Integrity);
        }
        if pages.is_empty() {
            return Err(SyncError::InvalidRequest);
        }
        let root = encode_object_root(total, full.finish(), &pages);
        let sealed = self.pairing.seal(&root)?;
        let hash = digest(&sealed);
        retry(|| transport.put(namespace, hash, &sealed))?;
        Ok(hash)
    }
    fn upload_page(
        &self,
        transport: &impl SyncTransport,
        entries: &[BlockRef],
    ) -> Result<[u8; 32], SyncError> {
        let bytes = encode_object_page(entries);
        let sealed = self.pairing.seal(&bytes)?;
        let hash = digest(&sealed);
        retry(|| transport.put(*self.pairing.namespace(), hash, &sealed))?;
        Ok(hash)
    }
    /// Downloads and validates every page/block before atomically renaming output.
    ///
    /// # Errors
    /// Rejects missing, reordered, altered, truncated, or oversized objects.
    pub fn download_paged_file(
        &self,
        transport: &impl SyncTransport,
        root: [u8; 32],
        output: &Path,
    ) -> Result<(), SyncError> {
        let namespace = *self.pairing.namespace();
        let sealed = retry(|| transport.get(namespace, root))?;
        let (total, expected, pages) = decode_object_root(&self.pairing.open(&sealed)?)?;
        if total == 0 || total > MAX_OBJECT_BYTES {
            return Err(SyncError::Backpressure);
        }
        let temporary = output.with_extension(format!("sync-part-{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| SyncError::Unavailable)?;
        let result = (|| {
            let mut next = 0u64;
            let mut size = 0u64;
            let mut full = pm_crypto::DigestState::new()?;
            for page_hash in pages {
                let cipher = retry(|| transport.get(namespace, page_hash))?;
                for entry in decode_object_page(&self.pairing.open(&cipher)?)? {
                    if entry.index != next {
                        return Err(SyncError::Integrity);
                    }
                    let block = retry(|| transport.get(namespace, entry.hash))?;
                    if block.len() as u64 != entry.cipher_len {
                        return Err(SyncError::Integrity);
                    }
                    full.update(&block);
                    let plain = self.pairing.open(&block)?;
                    if plain.len() as u64 != entry.plain_len {
                        return Err(SyncError::Integrity);
                    }
                    file.write_all(&plain).map_err(|_| SyncError::Unavailable)?;
                    size += entry.plain_len;
                    next += 1;
                }
            }
            if size != total || full.finish() != expected {
                return Err(SyncError::Integrity);
            }
            file.sync_all().map_err(|_| SyncError::Unavailable)?;
            drop(file);
            std::fs::rename(&temporary, output).map_err(|_| SyncError::Unavailable)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }
}
fn encode_object_page(entries: &[BlockRef]) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(2)
        .unwrap()
        .u64(1)
        .unwrap()
        .array(entries.len() as u64)
        .unwrap();
    for v in entries {
        e.array(4)
            .unwrap()
            .u64(v.index)
            .unwrap()
            .bytes(&v.hash)
            .unwrap()
            .u64(v.cipher_len)
            .unwrap()
            .u64(v.plain_len)
            .unwrap();
    }
    e.into_writer()
}
fn decode_object_page(bytes: &[u8]) -> Result<Vec<BlockRef>, SyncError> {
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
    if n == 0 || n > PAGE_ENTRIES as u64 {
        return Err(SyncError::Backpressure);
    }
    let mut out = Vec::new();
    for _ in 0..n {
        if d.array().map_err(|_| SyncError::Integrity)? != Some(4) {
            return Err(SyncError::Integrity);
        }
        out.push(BlockRef {
            index: d.u64().map_err(|_| SyncError::Integrity)?,
            hash: d
                .bytes()
                .map_err(|_| SyncError::Integrity)?
                .try_into()
                .map_err(|_| SyncError::Integrity)?,
            cipher_len: d.u64().map_err(|_| SyncError::Integrity)?,
            plain_len: d.u64().map_err(|_| SyncError::Integrity)?,
        });
    }
    if d.position() != bytes.len() {
        return Err(SyncError::Integrity);
    }
    Ok(out)
}
fn encode_object_root(total: u64, full: [u8; 32], pages: &[[u8; 32]]) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(4)
        .unwrap()
        .u64(1)
        .unwrap()
        .u64(total)
        .unwrap()
        .bytes(&full)
        .unwrap()
        .array(pages.len() as u64)
        .unwrap();
    for p in pages {
        e.bytes(p).unwrap();
    }
    e.into_writer()
}
#[allow(clippy::type_complexity)]
fn decode_object_root(bytes: &[u8]) -> Result<(u64, [u8; 32], Vec<[u8; 32]>), SyncError> {
    let mut d = Decoder::new(bytes);
    if d.array().map_err(|_| SyncError::Integrity)? != Some(4)
        || d.u64().map_err(|_| SyncError::Integrity)? != 1
    {
        return Err(SyncError::Integrity);
    }
    let total = d.u64().map_err(|_| SyncError::Integrity)?;
    let full = d
        .bytes()
        .map_err(|_| SyncError::Integrity)?
        .try_into()
        .map_err(|_| SyncError::Integrity)?;
    let n = d
        .array()
        .map_err(|_| SyncError::Integrity)?
        .ok_or(SyncError::Integrity)?;
    if n == 0 || n > 12000 {
        return Err(SyncError::Backpressure);
    }
    let mut pages = Vec::new();
    for _ in 0..n {
        pages.push(
            d.bytes()
                .map_err(|_| SyncError::Integrity)?
                .try_into()
                .map_err(|_| SyncError::Integrity)?,
        );
    }
    if d.position() != bytes.len() {
        return Err(SyncError::Integrity);
    }
    Ok((total, full, pages))
}

fn encode_descriptor(hashes: &[[u8; 32]], graphs: &[[u8; 32]]) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(3)
        .unwrap()
        .u64(2)
        .unwrap()
        .array(u64::try_from(hashes.len()).unwrap())
        .unwrap();
    for hash in hashes {
        e.bytes(hash).unwrap();
    }
    e.array(graphs.len() as u64).unwrap();
    for hash in graphs {
        e.bytes(hash).unwrap();
    }
    e.into_writer()
}
#[allow(clippy::type_complexity)]
fn decode_descriptor(bytes: &[u8]) -> Result<(Vec<[u8; 32]>, Vec<[u8; 32]>), SyncError> {
    let mut d = Decoder::new(bytes);
    if d.array().map_err(|_| SyncError::Integrity)? != Some(3)
        || d.u64().map_err(|_| SyncError::Integrity)? != 2
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
    let gn = d
        .array()
        .map_err(|_| SyncError::Integrity)?
        .ok_or(SyncError::Integrity)?;
    if gn > 256 {
        return Err(SyncError::Backpressure);
    }
    let mut graphs = Vec::new();
    for _ in 0..gn {
        graphs.push(
            d.bytes()
                .map_err(|_| SyncError::Integrity)?
                .try_into()
                .map_err(|_| SyncError::Integrity)?,
        );
    }
    if d.position() != bytes.len()
        || !out.windows(2).all(|w| w[0] < w[1])
        || encode_descriptor(&out, &graphs) != bytes
    {
        return Err(SyncError::Integrity);
    }
    Ok((out, graphs))
}
type WireStream = ([u8; 16], Vec<u8>, [u8; 32], Vec<u64>);
struct WireGraph {
    item: [u8; 16],
    revision: [u8; 16],
    kind: String,
    package: [u8; 32],
    attachments: Vec<([u8; 16], [u8; 32])>,
    streams: Vec<WireStream>,
}
fn encode_graph(
    item: [u8; 16],
    revision: [u8; 16],
    kind: &str,
    package: [u8; 32],
    attachments: &[([u8; 16], [u8; 32])],
    streams: &[WireStream],
) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(7)
        .unwrap()
        .u64(1)
        .unwrap()
        .bytes(&item)
        .unwrap()
        .bytes(&revision)
        .unwrap()
        .str(kind)
        .unwrap()
        .bytes(&package)
        .unwrap()
        .array(attachments.len() as u64)
        .unwrap();
    for (id, root) in attachments {
        e.array(2).unwrap().bytes(id).unwrap().bytes(root).unwrap();
    }
    e.array(streams.len() as u64).unwrap();
    for (id, header, root, lengths) in streams {
        e.array(4)
            .unwrap()
            .bytes(id)
            .unwrap()
            .bytes(header)
            .unwrap()
            .bytes(root)
            .unwrap()
            .array(lengths.len() as u64)
            .unwrap();
        for n in lengths {
            e.u64(*n).unwrap();
        }
    }
    e.into_writer()
}
fn decode_graph(bytes: &[u8]) -> Result<WireGraph, SyncError> {
    let mut d = Decoder::new(bytes);
    if d.array().map_err(|_| SyncError::Integrity)? != Some(7)
        || d.u64().map_err(|_| SyncError::Integrity)? != 1
    {
        return Err(SyncError::Integrity);
    }
    let item = d
        .bytes()
        .map_err(|_| SyncError::Integrity)?
        .try_into()
        .map_err(|_| SyncError::Integrity)?;
    let revision = d
        .bytes()
        .map_err(|_| SyncError::Integrity)?
        .try_into()
        .map_err(|_| SyncError::Integrity)?;
    let kind = d.str().map_err(|_| SyncError::Integrity)?.to_owned();
    if !matches!(
        kind.as_str(),
        "password" | "totp" | "passkey" | "ssh" | "token" | "note" | "file"
    ) {
        return Err(SyncError::Integrity);
    }
    let package = d
        .bytes()
        .map_err(|_| SyncError::Integrity)?
        .try_into()
        .map_err(|_| SyncError::Integrity)?;
    let an = d
        .array()
        .map_err(|_| SyncError::Integrity)?
        .ok_or(SyncError::Integrity)?;
    if an > 256 {
        return Err(SyncError::Backpressure);
    }
    let mut attachments = Vec::new();
    for _ in 0..an {
        if d.array().map_err(|_| SyncError::Integrity)? != Some(2) {
            return Err(SyncError::Integrity);
        }
        attachments.push((
            d.bytes()
                .map_err(|_| SyncError::Integrity)?
                .try_into()
                .map_err(|_| SyncError::Integrity)?,
            d.bytes()
                .map_err(|_| SyncError::Integrity)?
                .try_into()
                .map_err(|_| SyncError::Integrity)?,
        ));
    }
    let sn = d
        .array()
        .map_err(|_| SyncError::Integrity)?
        .ok_or(SyncError::Integrity)?;
    if sn > 256 {
        return Err(SyncError::Backpressure);
    }
    let mut streams = Vec::new();
    for _ in 0..sn {
        if d.array().map_err(|_| SyncError::Integrity)? != Some(4) {
            return Err(SyncError::Integrity);
        }
        let id = d
            .bytes()
            .map_err(|_| SyncError::Integrity)?
            .try_into()
            .map_err(|_| SyncError::Integrity)?;
        let header = d.bytes().map_err(|_| SyncError::Integrity)?.to_vec();
        let root = d
            .bytes()
            .map_err(|_| SyncError::Integrity)?
            .try_into()
            .map_err(|_| SyncError::Integrity)?;
        let n = d
            .array()
            .map_err(|_| SyncError::Integrity)?
            .ok_or(SyncError::Integrity)?;
        if n == 0 || n > 16385 {
            return Err(SyncError::Backpressure);
        }
        let mut lengths = Vec::new();
        for _ in 0..n {
            lengths.push(d.u64().map_err(|_| SyncError::Integrity)?);
        }
        streams.push((id, header, root, lengths));
    }
    if d.position() != bytes.len() {
        return Err(SyncError::Integrity);
    }
    Ok(WireGraph {
        item,
        revision,
        kind,
        package,
        attachments,
        streams,
    })
}
fn sync_stage(vault: &Path, id: [u8; 32]) -> Result<PathBuf, SyncError> {
    let parent = vault.parent().ok_or(SyncError::Unavailable)?;
    let path = parent.join(format!(
        ".pm-sync-stage-{}-{}",
        std::process::id(),
        hex(&id)
    ));
    match std::fs::create_dir(&path) {
        Ok(()) => Ok(path),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_dir_all(&path).map_err(|_| SyncError::Unavailable)?;
            std::fs::create_dir(&path).map_err(|_| SyncError::Unavailable)?;
            Ok(path)
        }
        Err(_) => Err(SyncError::Unavailable),
    }
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
