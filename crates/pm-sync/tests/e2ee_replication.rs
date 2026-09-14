// SPDX-License-Identifier: AGPL-3.0-only
#![cfg(target_os = "linux")]

use pm_crypto::{KdfProfile, SyncPairing};
use pm_sync::{
    MAX_BLOCK_BYTES, MAX_OBJECT_BYTES, OpaqueSyncStore, ProcessTlsTransport, SyncError,
    SyncReplica, SyncTransport,
};
use pm_vault::{
    Attachment, AttachmentReader, AuditDeviceCustody, CausalEventBody, CausalEventDraft,
    CausalEventKind, CausalReducer, HumanChannel, HumanMetadata, HumanVault, LogicalRecord,
    PendingVault, ReceivedCiphertextAttachment, RecordKind, open_vault,
};

#[test]
#[allow(clippy::too_many_lines)]
fn human_streaming_attachment_graph_is_complete_before_atomic_activation() {
    let dir = TestDir::new();
    let seed = dir.path("graph-seed.sqlite3");
    persist(&seed);
    let sender = dir.path("graph-a.sqlite3");
    let receiver = dir.path("graph-b.sqlite3");
    fs::copy(&seed, &sender).unwrap();
    let (mut human, _peer) = human(&sender, [0xf1; 16]);
    let pairing = human.create_sync_pairing([0x51; 44]).unwrap();
    let protected = pairing.to_protected_bytes();
    let _device_package = human
        .sign_causal_event(&revision([0xfe; 16], [0xfd; 16], 1))
        .unwrap();
    let trusted = *open_vault(&sender, MASTER).unwrap().trusted_root();
    rusqlite::Connection::open(&sender)
        .unwrap()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    fs::copy(&sender, &receiver).unwrap();
    let payload = vec![0x6d; 2 * 1024 * 1024 + 37];
    let attachment = Attachment::descriptor(
        [0x88; 16],
        "large.bin",
        "application/octet-stream",
        payload.len() as u64,
        pm_crypto::digest(&payload),
    )
    .unwrap();
    let record = LogicalRecord::new_streaming(
        RecordKind::File,
        HumanMetadata {
            title: "Graph".into(),
            destinations: vec![],
            tags: vec![],
            favorite: false,
            notes: String::new(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![],
        vec![attachment],
    )
    .unwrap();
    let mut cursor = std::io::Cursor::new(payload.clone());
    let mut sources = [AttachmentReader::new([0x88; 16], &mut cursor)];
    let prepared = human
        .prepare_create_record_streaming(&record, &mut sources)
        .unwrap();
    human
        .commit(
            prepared.command(),
            &human.sign(&prepared).unwrap(),
            prepared.body(),
        )
        .unwrap();
    let malicious_receiver = dir.path("graph-malicious.sqlite3");
    fs::copy(&receiver, &malicious_receiver).unwrap();
    let reducer = CausalReducer::open(&sender).unwrap();
    let event = reducer.pending_outbox().unwrap().remove(0);
    let graph_stage = dir.path("mixed-graph-stage");
    let mut mixed = reducer
        .export_ciphertext_graph(&event, &graph_stage)
        .unwrap()
        .unwrap();
    mixed.attachments.push(ReceivedCiphertextAttachment {
        id: [0x99; 16],
        package: mixed.package.clone(),
    });
    assert!(matches!(
        CausalReducer::open(&malicious_receiver)
            .unwrap()
            .apply_received_package(&[event], &[mixed]),
        Err(pm_vault::ReductionError::Integrity)
    ));
    assert_eq!(
        rusqlite::Connection::open(&malicious_receiver)
            .unwrap()
            .query_row("SELECT count(*) FROM revision_parts", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    let server_path = dir.path("graph-server.sqlite3");
    let server = OpaqueSyncStore::create(&server_path).unwrap();
    let rpk = [0x81; 44];
    let namespace = *pairing.namespace();
    server.authorize(namespace, &rpk).unwrap();
    let mut tx = SyncReplica::new(&sender, pairing, rpk, [0x51; 44]).unwrap();
    let mut rx = SyncReplica::new(
        &receiver,
        SyncPairing::from_protected_bytes(&protected, &trusted).unwrap(),
        rpk,
        [0x51; 44],
    )
    .unwrap();
    assert_eq!(tx.push(&(&server, &rpk[..])).unwrap(), 1);
    let db = rusqlite::Connection::open(&server_path).unwrap();
    let(hash,bytes):(Vec<u8>,Vec<u8>)=db.query_row("SELECT hash,bytes FROM blocks WHERE hash NOT IN(SELECT hash FROM roots) ORDER BY length(bytes) DESC LIMIT 1",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
    db.execute("DELETE FROM blocks WHERE hash=?1", [&hash])
        .unwrap();
    assert!(rx.pull(&(&server, &rpk[..])).is_err());
    assert_eq!(
        rusqlite::Connection::open(&receiver)
            .unwrap()
            .query_row("SELECT count(*) FROM vault_items", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    db.execute(
        "INSERT INTO blocks(namespace,hash,bytes)VALUES(?1,?2,?3)",
        rusqlite::params![namespace.as_slice(), hash, bytes],
    )
    .unwrap();
    drop(db);
    let fault = rusqlite::Connection::open(&receiver).unwrap();
    fault.execute_batch("CREATE TRIGGER fail_sync_graph BEFORE INSERT ON attachment_stream_chunks BEGIN SELECT RAISE(ABORT,'synthetic crash'); END;").unwrap();
    assert!(rx.pull(&(&server, &rpk[..])).is_err());
    assert_eq!(
        fault
            .query_row("SELECT count(*) FROM revision_parts", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        fault
            .query_row("SELECT count(*) FROM authority_events", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    fault.execute_batch("DROP TRIGGER fail_sync_graph").unwrap();
    drop(fault);
    assert_eq!(rx.pull(&(&server, &rpk[..])).unwrap(), 1);
    let (channel, peer) = UnixStream::pair().unwrap();
    let reader = HumanVault::unlock(
        &receiver,
        MASTER,
        [0xf1; 16],
        HumanChannel::authenticate(channel, unsafe { libc::geteuid() }).unwrap(),
    )
    .unwrap();
    let mut output = Vec::new();
    reader
        .read_attachment_to(*prepared.item_id(), [0x88; 16], &mut output)
        .unwrap();
    assert_eq!(output, payload);
    let mut raw = Vec::new();
    for suffix in ["", "-wal"] {
        let path = PathBuf::from(format!("{}{}", server_path.display(), suffix));
        if path.exists() {
            raw.extend_from_slice(&fs::read(path).unwrap());
        }
    }
    assert!(!contains(&raw, &payload[..64]));
    drop(peer);
}
use std::{
    fs,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{self, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

#[test]
#[allow(clippy::too_many_lines)]
fn replica_push_and_pull_cross_the_real_tls_rpc_process() {
    use std::{
        os::unix::fs::PermissionsExt,
        thread,
        time::{Duration, Instant},
    };
    let dir = TestDir::new();
    let seed = dir.path("seed-tls.sqlite3");
    persist(&seed);
    let (server_key, server_public) = tls_key(&dir, "server");
    let (client_key, client_public) = tls_key(&dir, "client");
    let pin: [u8; 44] = fs::read(&server_public).unwrap().try_into().unwrap();
    let sender = dir.path("tls-a.sqlite3");
    let receiver = dir.path("tls-b.sqlite3");
    fs::copy(&seed, &sender).unwrap();
    let (mut human, _peer) = human(&sender, [0xe1; 16]);
    let pairing = human.create_sync_pairing(pin).unwrap();
    let protected = pairing.to_protected_bytes();
    let namespace = *pairing.namespace();
    let _device_package = human
        .sign_causal_event(&revision([9; 16], [8; 16], 8))
        .unwrap();
    let trusted = *open_vault(&sender, MASTER).unwrap().trusted_root();
    rusqlite::Connection::open(&sender)
        .unwrap()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    fs::copy(&sender, &receiver).unwrap();
    let tls_attachment = vec![0x4b; 2 * 1024 * 1024 + 17];
    let record = LogicalRecord::new(
        RecordKind::File,
        HumanMetadata {
            title: "TLS graph".into(),
            destinations: vec![],
            tags: vec![],
            favorite: false,
            notes: String::new(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![],
        vec![
            Attachment::new(
                [0x89; 16],
                "tls.bin",
                "application/octet-stream",
                &tls_attachment,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let prepared = human.prepare_create_record(&record).unwrap();
    human
        .commit(
            prepared.command(),
            &human.sign(&prepared).unwrap(),
            prepared.body(),
        )
        .unwrap();
    let socket = dir.path("sync.sock");
    let database = dir.path("opaque.sqlite3");
    let mut child = Command::new(env!("CARGO_BIN_EXE_pm-sync"))
        .args(["serve", "--db"])
        .arg(&database)
        .arg("--socket")
        .arg(&socket)
        .arg("--server-key")
        .arg(&server_key)
        .arg("--namespace")
        .arg(hex_test(&namespace))
        .arg("--client-pub")
        .arg(&client_public)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    fs::set_permissions(
        client_key.parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let transport = ProcessTlsTransport::new(
        Path::new(env!("CARGO_BIN_EXE_pm-sync")),
        &socket,
        &client_key,
        &server_public,
    );
    let client_rpk: [u8; 44] = fs::read(&client_public).unwrap().try_into().unwrap();
    let mut tx = SyncReplica::new(&sender, pairing, client_rpk, pin).unwrap();
    let mut rx = SyncReplica::new(
        &receiver,
        SyncPairing::from_protected_bytes(&protected, &trusted).unwrap(),
        client_rpk,
        pin,
    )
    .unwrap();
    let flaky = LostFirstPut {
        inner: &transport,
        calls: AtomicU64::new(0),
    };
    let retry_started = Instant::now();
    assert_eq!(tx.push(&flaky).unwrap(), 1);
    assert!(retry_started.elapsed() >= Duration::from_secs(1));
    assert_eq!(rx.pull(&transport).unwrap(), 1);
    let inspect = rusqlite::Connection::open(&receiver).unwrap();
    assert_eq!(
        inspect
            .query_row("SELECT count(*) FROM vault_items", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        inspect
            .query_row("SELECT count(*) FROM attachment_parts", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    drop(inspect);
    let (channel, peer) = UnixStream::pair().unwrap();
    let reader = HumanVault::unlock(
        &receiver,
        MASTER,
        [0xe1; 16],
        HumanChannel::authenticate(channel, unsafe { libc::geteuid() }).unwrap(),
    )
    .unwrap();
    let opened_record = reader.read_record(*prepared.item_id()).unwrap();
    assert_eq!(opened_record.attachments()[0].content(), tls_attachment);
    drop(peer);
    let large = dir.path("large-ciphertext.bin");
    let mut bytes = Vec::with_capacity(2 * 1024 * 1024 + 17);
    while bytes.len() < 2 * 1024 * 1024 + 17 {
        bytes.extend_from_slice(b"synthetic-ticket17-large-graph-canary|");
    }
    bytes.truncate(2 * 1024 * 1024 + 17);
    fs::write(&large, &bytes).unwrap();
    let object_root = tx.upload_paged_file(&transport, &large).unwrap();
    let restored = dir.path("restored-ciphertext.bin");
    rx.download_paged_file(&transport, object_root, &restored)
        .unwrap();
    assert_eq!(fs::read(&restored).unwrap(), bytes);
    let oversized = dir.path("oversized-sparse");
    let sparse = fs::File::create(&oversized).unwrap();
    sparse.set_len(MAX_OBJECT_BYTES + 1).unwrap();
    assert!(matches!(
        tx.upload_paged_file(&transport, &oversized),
        Err(SyncError::Backpressure)
    ));
    let symlink = dir.path("ciphertext-symlink");
    std::os::unix::fs::symlink(&large, &symlink).unwrap();
    assert!(matches!(
        tx.upload_paged_file(&transport, &symlink),
        Err(SyncError::InvalidRequest)
    ));
    child.kill().unwrap();
    child.wait().unwrap();
    let mut raw = Vec::new();
    for suffix in ["", "-wal", "-shm"] {
        let path = PathBuf::from(format!("{}{suffix}", database.display()));
        if path.exists() {
            raw.extend_from_slice(&fs::read(path).unwrap());
        }
    }
    assert!(!contains(&raw, &tls_attachment[..64]));
    assert!(!contains(&raw, b"synthetic-ticket17-large-graph-canary"));
}

struct LostFirstPut<'a> {
    inner: &'a ProcessTlsTransport,
    calls: AtomicU64,
}
impl SyncTransport for LostFirstPut<'_> {
    fn put(&self, n: [u8; 32], h: [u8; 32], b: &[u8]) -> Result<(), SyncError> {
        self.inner.put(n, h, b)?;
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            Err(SyncError::Unavailable)
        } else {
            Ok(())
        }
    }
    fn get(&self, n: [u8; 32], h: [u8; 32]) -> Result<Vec<u8>, SyncError> {
        self.inner.get(n, h)
    }
    fn publish(&self, n: [u8; 32], h: [u8; 32]) -> Result<(), SyncError> {
        self.inner.publish(n, h)
    }
    fn list(
        &self,
        n: [u8; 32],
        c: Option<u64>,
        l: usize,
    ) -> Result<Vec<(u64, [u8; 32])>, SyncError> {
        self.inner.list(n, c, l)
    }
}

fn tls_key(dir: &TestDir, name: &str) -> (PathBuf, PathBuf) {
    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use std::os::unix::fs::PermissionsExt;
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
    let mut public = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    public.extend_from_slice(pair.public_key().as_ref());
    let private = dir.path(&format!("{name}.key"));
    let public_path = dir.path(&format!("{name}.pub"));
    let mut bytes = b"PMK1".to_vec();
    bytes.extend_from_slice(
        &u32::try_from(document.as_ref().len())
            .unwrap()
            .to_be_bytes(),
    );
    bytes.extend_from_slice(document.as_ref());
    bytes.extend_from_slice(&public);
    fs::write(&private, bytes).unwrap();
    fs::set_permissions(&private, fs::Permissions::from_mode(0o400)).unwrap();
    fs::write(&public_path, public).unwrap();
    (private, public_path)
}
fn hex_test(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut o = String::new();
    for b in bytes {
        o.push(char::from(D[usize::from(b >> 4)]));
        o.push(char::from(D[usize::from(b & 15)]));
    }
    o
}

const MASTER: &[u8] = b"synthetic ticket 17 master";
const ITEM: [u8; 16] = [0x17; 16];
static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
fn human_retirement_commits_every_observed_prefix_for_the_exact_device() {
    let dir = TestDir::new();
    let vault = dir.path("retire.sqlite3");
    persist(&vault);
    let (mut owner, _owner_peer) = human(&vault, [0xa1; 16]);
    let (remote, _remote_peer) = human(&vault, [0xb2; 16]);
    let event = remote
        .sign_causal_event(&revision([0x31; 16], [0x32; 16], 1))
        .unwrap();
    CausalReducer::open(&vault)
        .unwrap()
        .apply(&[event])
        .unwrap();
    let prepared = owner.prepare_device_retirement([0xb2; 16]).unwrap();
    let signature = owner.sign(&prepared).unwrap();
    owner
        .commit(prepared.command(), &signature, prepared.body())
        .unwrap();
    assert!(
        CausalReducer::open(&vault)
            .unwrap()
            .view()
            .unwrap()
            .device_retired(&[0xb2; 16])
    );
    assert!(owner.prepare_device_retirement([0xa1; 16]).is_err());
}

#[test]
#[allow(clippy::too_many_lines)]
fn three_paired_replicas_converge_through_opaque_ciphertext_without_copying_sqlite() {
    let dir = TestDir::new();
    let seed = dir.path("seed.sqlite3");
    persist(&seed);
    let (a, _pa) = human(&seed, [0xa1; 16]);
    let (b, _pb) = human(&seed, [0xb2; 16]);
    let (c, _pc) = human(&seed, [0xc3; 16]);
    let pairing = a.create_sync_pairing([0x51; 44]).unwrap();
    let protected = pairing.to_protected_bytes();
    let namespace = *pairing.namespace();
    let ea = a
        .sign_causal_event(&revision([1; 16], [0xa1; 16], 10))
        .unwrap();
    let eb = b
        .sign_causal_event(&revision([2; 16], [0xb2; 16], 99))
        .unwrap();
    let ec = c
        .sign_causal_event(&revision([3; 16], [0xc3; 16], 40))
        .unwrap();
    rusqlite::Connection::open(&seed)
        .unwrap()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let paths = [
        dir.path("a.sqlite3"),
        dir.path("b.sqlite3"),
        dir.path("c.sqlite3"),
    ];
    for p in &paths {
        fs::copy(&seed, p).unwrap();
    }
    for (p, event) in paths.iter().zip([ea.clone(), eb.clone(), ec.clone()]) {
        CausalReducer::open(p).unwrap().apply(&[event]).unwrap();
    }
    let store_path = dir.path("server.sqlite3");
    let server = OpaqueSyncStore::create(&store_path).unwrap();
    let rpks = [[0x61; 44], [0x62; 44], [0x63; 44]];
    for rpk in &rpks {
        server.authorize(namespace, rpk).unwrap();
    }
    let trusted = *open_vault(&seed, MASTER).unwrap().trusted_root();
    let mut altered_pairing = protected.clone();
    *altered_pairing.last_mut().unwrap() ^= 1;
    assert!(SyncPairing::from_protected_bytes(&altered_pairing, &trusted).is_err());
    let mut replicas: Vec<_> = paths
        .iter()
        .zip(rpks)
        .map(|(p, rpk)| {
            SyncReplica::new(
                p,
                SyncPairing::from_protected_bytes(&protected, &trusted).unwrap(),
                rpk,
                [0x51; 44],
            )
            .unwrap()
        })
        .collect();
    for (index, replica) in replicas.iter_mut().enumerate() {
        assert_eq!(replica.push(&(&server, &rpks[index][..])).unwrap(), 1);
    }
    let before_server = fs::read(&store_path).unwrap();
    assert!(!contains(&before_server, MASTER));
    assert!(!contains(&before_server, b"synthetic ticket 17"));
    let mut digests = Vec::new();
    for (index, replica) in replicas.iter_mut().enumerate() {
        assert_eq!(replica.pull(&(&server, &rpks[index][..])).unwrap(), 3);
        let view = replica.reducer().unwrap().view().unwrap();
        assert_eq!(
            view.item(&ITEM).unwrap().visible_revision(),
            Some(&[0xb2; 16])
        );
        digests.push(*view.digest());
    }
    assert!(digests.windows(2).all(|v| v[0] == v[1]));
    let mut retire_parents = vec![ea.digest(), eb.digest()];
    retire_parents.sort_unstable();
    let retire = a
        .sign_causal_event(
            &CausalEventDraft::new(
                [4; 16],
                1,
                2,
                Some(ea.digest()),
                retire_parents,
                CausalEventKind::DeviceRetire,
                [0xb2; 16],
                1,
                CausalEventBody::Retire {
                    accepted_prefixes: vec![pm_vault::AcceptedPrefix {
                        generation: 1,
                        seq: 1,
                        tip_digest: eb.digest(),
                    }],
                },
            )
            .unwrap(),
        )
        .unwrap();
    replicas[0].reducer().unwrap().apply(&[retire]).unwrap();
    assert_eq!(replicas[0].push(&(&server, &rpks[0][..])).unwrap(), 1);
    assert!(
        !replicas[1]
            .reducer()
            .unwrap()
            .view()
            .unwrap()
            .device_retired(&[0xb2; 16])
    );
    assert_eq!(replicas[1].pull(&(&server, &rpks[1][..])).unwrap(), 1);
    assert!(
        replicas[1]
            .reducer()
            .unwrap()
            .view()
            .unwrap()
            .device_retired(&[0xb2; 16])
    );
    for (index, replica) in replicas.iter_mut().enumerate() {
        assert_eq!(replica.push(&(&server, &rpks[index][..])).unwrap(), 0);
        let _ = replica.pull(&(&server, &rpks[index][..])).unwrap();
        assert_eq!(replica.pull(&(&server, &rpks[index][..])).unwrap(), 0);
    }
    assert!(!paths.iter().any(|p| p == &store_path));
}

#[test]
#[allow(clippy::too_many_lines)]
fn omitted_block_never_activates_half_of_one_published_root_and_retry_is_atomic() {
    let dir = TestDir::new();
    let seed = dir.path("seed-partial.sqlite3");
    persist(&seed);
    let (human, _peer) = human(&seed, [0xd1; 16]);
    let pairing = human.create_sync_pairing([0x51; 44]).unwrap();
    let protected = pairing.to_protected_bytes();
    let namespace = *pairing.namespace();
    let first = human
        .sign_causal_event(&revision([0x11; 16], [0x21; 16], 1))
        .unwrap();
    let second = human
        .sign_causal_event(
            &CausalEventDraft::new(
                [0x12; 16],
                1,
                2,
                Some(first.digest()),
                vec![first.digest()],
                CausalEventKind::ItemRevision,
                ITEM,
                1,
                CausalEventBody::Revision {
                    revision_id: [0x22; 16],
                    modified_at: 2,
                    manifest_digest: [0x77; 32],
                    previous_revisions: vec![[0x21; 16]],
                },
            )
            .unwrap(),
        )
        .unwrap();
    rusqlite::Connection::open(&seed)
        .unwrap()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let sender = dir.path("sender.sqlite3");
    let receiver = dir.path("receiver.sqlite3");
    fs::copy(&seed, &sender).unwrap();
    fs::copy(&seed, &receiver).unwrap();
    CausalReducer::open(&sender)
        .unwrap()
        .apply(&[first, second])
        .unwrap();
    let server_path = dir.path("opaque-partial.sqlite3");
    let server = OpaqueSyncStore::create(&server_path).unwrap();
    let rpk = [0x71; 44];
    server.authorize(namespace, &rpk).unwrap();
    let trusted = *open_vault(&seed, MASTER).unwrap().trusted_root();
    assert!(
        SyncReplica::new(
            &sender,
            SyncPairing::from_protected_bytes(&protected, &trusted).unwrap(),
            rpk,
            [0x52; 44]
        )
        .is_err()
    );
    let mut tx = SyncReplica::new(&sender, pairing, rpk, [0x51; 44]).unwrap();
    let mut rx = SyncReplica::new(
        &receiver,
        SyncPairing::from_protected_bytes(&protected, &trusted).unwrap(),
        rpk,
        [0x51; 44],
    )
    .unwrap();
    assert_eq!(tx.push(&(&server, &rpk[..])).unwrap(), 2);
    let db = rusqlite::Connection::open(&server_path).unwrap();
    let root: Vec<u8> = db
        .query_row("SELECT hash FROM roots LIMIT 1", [], |r| r.get(0))
        .unwrap();
    let (hash, bytes): (Vec<u8>, Vec<u8>) = db
        .query_row(
            "SELECT hash,bytes FROM blocks WHERE hash<>?1 LIMIT 1",
            [root],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    db.execute("DELETE FROM blocks WHERE hash=?1", [&hash])
        .unwrap();
    assert!(rx.pull(&(&server, &rpk[..])).is_err());
    assert_eq!(
        rx.reducer()
            .unwrap()
            .view()
            .unwrap()
            .retained_header_count(),
        0
    );
    db.execute(
        "INSERT INTO blocks(namespace,hash,bytes)VALUES(?1,?2,?3)",
        rusqlite::params![namespace.as_slice(), hash, bytes],
    )
    .unwrap();
    drop(db);
    assert_eq!(rx.pull(&(&server, &rpk[..])).unwrap(), 2);
    let view = rx.reducer().unwrap().view().unwrap();
    assert_eq!(view.retained_header_count(), 2);
    assert_eq!(
        view.item(&ITEM).unwrap().visible_revision(),
        Some(&[0x22; 16])
    );
}

#[test]
fn opaque_store_enforces_hash_acl_and_all_published_boundaries_without_truncation() {
    let dir = TestDir::new();
    let store = OpaqueSyncStore::create(&dir.path("bounds.sqlite3")).unwrap();
    let namespace = [0x17; 32];
    let allowed = [0x41; 44];
    store.authorize(namespace, &allowed).unwrap();
    let exact = vec![0x5a; MAX_BLOCK_BYTES];
    let exact_hash = pm_crypto::digest(&exact);
    store.put(namespace, &allowed, exact_hash, &exact).unwrap();
    assert_eq!(store.get(namespace, &allowed, exact_hash).unwrap(), exact);
    assert!(matches!(
        store.put(namespace, &allowed, [0; 32], &[1]),
        Err(SyncError::Integrity)
    ));
    assert!(matches!(
        store.put(
            namespace,
            &allowed,
            pm_crypto::digest(&vec![1; MAX_BLOCK_BYTES + 1]),
            &vec![1; MAX_BLOCK_BYTES + 1]
        ),
        Err(SyncError::Integrity)
    ));
    assert!(matches!(
        store.get(namespace, &[0x42; 44], exact_hash),
        Err(SyncError::Unauthorized)
    ));
    assert!(matches!(
        store.list(namespace, &allowed, None, 0),
        Err(SyncError::InvalidRequest)
    ));
    assert!(matches!(
        store.list(namespace, &allowed, None, 257),
        Err(SyncError::InvalidRequest)
    ));
    assert!(matches!(
        store.publish(namespace, &allowed, [0x99; 32]),
        Err(SyncError::Missing)
    ));
    store.publish(namespace, &allowed, exact_hash).unwrap();
    store.publish(namespace, &allowed, exact_hash).unwrap();
    assert_eq!(store.list(namespace, &allowed, None, 128).unwrap().len(), 1);
    store.delete(namespace, &allowed, &[exact_hash]).unwrap();
    assert_eq!(
        pm_crypto::digest(&store.get(namespace, &allowed, exact_hash).unwrap()),
        exact_hash
    );
}

fn revision(event: [u8; 16], revision: [u8; 16], time: i64) -> CausalEventDraft {
    CausalEventDraft::new(
        event,
        1,
        1,
        None,
        vec![],
        CausalEventKind::ItemRevision,
        ITEM,
        1,
        CausalEventBody::Revision {
            revision_id: revision,
            modified_at: time,
            manifest_digest: [0x77; 32],
            previous_revisions: vec![],
        },
    )
    .unwrap()
}
fn human(path: &Path, device: [u8; 16]) -> (HumanVault, UnixStream) {
    let (server, peer) = UnixStream::pair().unwrap();
    let ch = HumanChannel::authenticate(server, unsafe { libc::geteuid() }).unwrap();
    (
        HumanVault::unlock_with_audit_custody(
            path,
            MASTER,
            device,
            ch,
            Arc::new(AuditDeviceCustody::generate().unwrap()),
        )
        .unwrap(),
        peer,
    )
}
fn persist(path: &Path) {
    let p = PendingVault::new(MASTER, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    let r = p.recovery_code().to_string().parse().unwrap();
    p.persist(path, &r).unwrap();
}
fn contains(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}
struct TestDir(PathBuf);
impl TestDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "pm-ticket17-{}-{}",
            process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn path(&self, n: &str) -> PathBuf {
        self.0.join(n)
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
