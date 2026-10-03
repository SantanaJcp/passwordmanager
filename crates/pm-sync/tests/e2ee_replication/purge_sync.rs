// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use pm_vault::{ItemLifecycle, PreparedHumanCommand, PurgeScopeKind, SignedCausalEvent};
use std::{
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct PurgeFixture {
    dir: TestDir,
    sender: PathBuf,
    receiver: PathBuf,
    owner: HumanVault,
    remote: HumanVault,
    receiver_custody: Arc<AuditDeviceCustody>,
    _peers: [UnixStream; 2],
    protected: Vec<u8>,
    trusted: pm_crypto::TrustedRoot,
    namespace: [u8; 32],
    client_rpk: [u8; 44],
    server_pin: [u8; 44],
    item: [u8; 16],
}
impl PurgeFixture {
    fn new() -> Self {
        let dir = TestDir::new();
        let seed = dir.path("purge-seed.sqlite3");
        persist(&seed);
        let ca = test_audit_custody();
        let cb = test_audit_custody();
        let (a, pa) = human(&seed, [0xa1; 16], &ca);
        let (b, pb) = human(&seed, [0xb2; 16], &cb);
        a.sign_causal_event(&revision([0xf1; 16], [0xf2; 16], 1))
            .unwrap();
        b.sign_causal_event(&revision([0xf3; 16], [0xf4; 16], 1))
            .unwrap();
        let pairing = a.create_sync_pairing([0x51; 44]).unwrap();
        let protected = pairing.to_protected_bytes();
        let namespace = *pairing.namespace();
        let trusted = *open_vault(&seed, MASTER).unwrap().trusted_root();
        drop((a, b, pa, pb));
        rusqlite::Connection::open(&seed)
            .unwrap()
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        let sender = dir.path("purge-a.sqlite3");
        let receiver = dir.path("purge-b.sqlite3");
        fs::copy(&seed, &sender).unwrap();
        fs::copy(&seed, &receiver).unwrap();
        let (mut owner, pa) = human(&sender, [0xa1; 16], &ca);
        let (remote, pb) = human(&receiver, [0xb2; 16], &cb);
        let create = owner
            .prepare_create_record(&note("synthetic W2 create"))
            .unwrap();
        let item = *create.item_id();
        commit(&mut owner, &create);
        Self {
            dir,
            sender,
            receiver,
            owner,
            remote,
            receiver_custody: cb,
            _peers: [pa, pb],
            protected,
            trusted,
            namespace,
            client_rpk: [0x61; 44],
            server_pin: [0x51; 44],
            item,
        }
    }
    fn replica(&self, path: &Path) -> SyncReplica {
        SyncReplica::new(
            path,
            SyncPairing::from_protected_bytes(&self.protected, &self.trusted).unwrap(),
            self.client_rpk,
            self.server_pin,
        )
        .unwrap()
    }
    fn purge(&mut self) {
        let edit = self
            .owner
            .prepare_edit_record(self.item, &note("synthetic W2 offline edit"))
            .unwrap();
        commit(&mut self.owner, &edit);
        let trash = self.owner.prepare_delete(self.item).unwrap();
        commit(&mut self.owner, &trash);
        let purge = self.owner.prepare_purge_item(self.item).unwrap();
        commit(&mut self.owner, purge.prepared());
    }
    fn store(&self) -> OpaqueSyncStore {
        let store = OpaqueSyncStore::create(&self.dir.path("purge-store.sqlite3")).unwrap();
        store.authorize(self.namespace, &[0x61; 44]).unwrap();
        store
    }
}
fn commit(h: &mut HumanVault, p: &PreparedHumanCommand) {
    h.commit(p.command(), &h.sign(p).unwrap(), p.body())
        .unwrap();
}
fn note(title: &str) -> LogicalRecord {
    LogicalRecord::new(
        RecordKind::Note,
        HumanMetadata {
            title: title.into(),
            destinations: vec![],
            tags: vec![],
            favorite: false,
            notes: pm_crypto::ProtectedText::copy_from_str("synthetic W2 payload").unwrap(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![],
        vec![],
    )
    .unwrap()
}
// Compare authority, all valid ciphertext, outbox, purge and reception markers.
fn snapshot(path: &Path) -> Vec<(String, Vec<String>)> {
    let db = rusqlite::Connection::open(path).unwrap();
    let mut result = Vec::new();
    for table in [
        "vault_meta",
        "authority_events",
        "audit_key_packages",
        "vault_items",
        "revision_parts",
        "attachment_parts",
        "attachment_streams",
        "attachment_stream_chunks",
        "credential_authorizations",
        "outbox",
        "purged_items",
        "purged_revisions",
        "sync_received_roots",
    ] {
        let exists: i64 = db
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |r| r.get(0),
            )
            .unwrap();
        let mut values = Vec::new();
        if exists != 0 {
            let mut s = db.prepare(&format!("SELECT * FROM {table}")).unwrap();
            let columns = s.column_count();
            let rows = s
                .query_map([], |r| {
                    Ok((0..columns)
                        .map(|i| format!("{:?}", r.get_ref(i).unwrap()))
                        .collect::<Vec<_>>()
                        .join("|"))
                })
                .unwrap();
            values = rows.map(Result::unwrap).collect();
            values.sort();
        }
        result.push((table.into(), values));
    }
    result
}
fn reject(
    f: &PurgeFixture,
    events: &[SignedCausalEvent],
    graphs: &[pm_vault::ReceivedCiphertextGraph],
    label: &str,
) {
    ensure_valid_content(f);
    let before = snapshot(&f.receiver);
    assert!(
        CausalReducer::open(&f.receiver)
            .unwrap()
            .apply_received_package(events, graphs)
            .is_err(),
        "{label}"
    );
    assert_eq!(snapshot(&f.receiver), before, "{label}: atomic rejection");
    println!("PASS rejection={label} authority/content/outbox/markers unchanged");
}

fn ensure_valid_content(f: &PurgeFixture) {
    if count_rows(&f.receiver, "vault_items") == 0 {
        let (mut owner, _peer) = human(&f.receiver, [0xb2; 16], &f.receiver_custody);
        let record = owner
            .prepare_create_record(&note("synthetic unaffected content"))
            .unwrap();
        commit(&mut owner, &record);
        assert_eq!(
            owner.read_record(*record.item_id()).unwrap().human().title,
            "synthetic unaffected content"
        );
    }
}

fn tampered_wire(value: &SignedCausalEvent, mode: &str) -> Vec<u8> {
    let wire = value.to_bytes();
    let mut d = minicbor::Decoder::new(&wire);
    assert_eq!(d.array().unwrap(), Some(3));
    let mut event = d.bytes().unwrap().to_vec();
    let mut device = d.bytes().unwrap().to_vec();
    let mut human = if d.datatype().unwrap() == minicbor::data::Type::Null {
        d.null().unwrap();
        None
    } else {
        Some(d.bytes().unwrap().to_vec())
    };
    match mode {
        "missing human signature" => human = None,
        "foreign human signature" => human = Some(vec![0x55; 64]),
        "foreign device signature" => device = vec![0x56; 64],
        "missing device signature" => device.clear(),
        "kind absent" => {
            let at = event.windows(5).position(|w| w == b"\x64kind").unwrap();
            event.drain(at..at + 5);
        }
        _ => panic!("unknown tamper"),
    }
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(3)
        .unwrap()
        .bytes(&event)
        .unwrap()
        .bytes(&device)
        .unwrap();
    if let Some(h) = human {
        e.bytes(&h).unwrap();
    } else {
        e.null().unwrap();
    }
    e.into_writer()
}
fn tamper(value: &SignedCausalEvent, mode: &str) -> SignedCausalEvent {
    SignedCausalEvent::from_bytes(&tampered_wire(value, mode)).unwrap()
}

#[test]
fn signed_purge_rejects_missing_foreign_signatures_and_incomplete_proof_atomically() {
    let mut f = PurgeFixture::new();
    f.purge();
    let events = CausalReducer::open(&f.sender)
        .unwrap()
        .pending_outbox()
        .unwrap();
    for mode in [
        "missing human signature",
        "foreign human signature",
        "foreign device signature",
    ] {
        let altered: Vec<_> = events.iter().map(|e| tamper(e, mode)).collect();
        reject(&f, &altered, &[], mode);
    }
    let headers: Vec<_> = events
        .iter()
        .filter(|e| {
            let db = rusqlite::Connection::open(&f.sender).unwrap();
            db.query_row(
                "SELECT kind FROM authority_events WHERE event_digest=?1",
                [e.digest().as_slice()],
                |r| r.get::<_, String>(0),
            )
            .unwrap()
                != "purge-item"
        })
        .cloned()
        .collect();
    reject(&f, &headers, &[], "purge proof absent");
    let missing_kind: Vec<_> = events.iter().map(|e| tamper(e, "kind absent")).collect();
    reject(&f, &missing_kind, &[], "event kind absent");
}

fn reject_purge_membership(label: &str) {
    let mut f = PurgeFixture::new();
    let revision_id = *f.owner.history(f.item).unwrap().entries()[0].revision_id();
    let foreign = if label == "revision of another item" {
        let other = f
            .owner
            .prepare_create_record(&note("synthetic foreign item"))
            .unwrap();
        commit(&mut f.owner, &other);
        *f.owner.history(*other.item_id()).unwrap().entries()[0].revision_id()
    } else {
        [0x98; 16]
    };
    let base = CausalReducer::open(&f.sender)
        .unwrap()
        .pending_outbox()
        .unwrap();
    let db = rusqlite::Connection::open(&f.sender).unwrap();
    let (seq, previous): (i64, Vec<u8>) = db
        .query_row(
            "SELECT seq,event_digest FROM authority_events ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let (subject, revisions, kind) = match label {
        "unknown item" => ([0x99; 16], vec![revision_id], CausalEventKind::PurgeItem),
        "revision of another item" => (f.item, vec![foreign], CausalEventKind::PurgeItem),
        "purge causal winner" => (f.item, vec![revision_id], CausalEventKind::PurgeRevisions),
        _ => unreachable!(),
    };
    let e = f
        .owner
        .sign_causal_event(
            &CausalEventDraft::new(
                [0x90; 16],
                1,
                u64::try_from(seq + 1).unwrap(),
                Some(previous.try_into().unwrap()),
                base.iter().map(SignedCausalEvent::digest).collect(),
                kind,
                subject,
                1,
                CausalEventBody::PurgeScoped {
                    item_id: subject,
                    revision_ids: revisions,
                    scope: if kind == CausalEventKind::PurgeItem {
                        PurgeScopeKind::Item
                    } else {
                        PurgeScopeKind::Revisions
                    },
                },
            )
            .unwrap(),
        )
        .unwrap();
    let mut events = base.clone();
    events.push(e);
    // Every authentic revision has its real graph, including the other item.
    let graphs: Vec<_> = base
        .iter()
        .enumerate()
        .map(|(i, event)| {
            CausalReducer::open(&f.sender)
                .unwrap()
                .export_ciphertext_graph(event, &f.dir.path(&format!("{label}-{i}")))
                .unwrap()
                .unwrap()
        })
        .collect();
    reject(&f, &events, &graphs, label);
}
#[test]
fn purge_unknown_item_rejected() {
    reject_purge_membership("unknown item");
}
#[test]
fn purge_revision_of_another_item_rejected() {
    reject_purge_membership("revision of another item");
}
#[test]
fn purge_causal_winner_rejected() {
    reject_purge_membership("purge causal winner");
}

#[test]
fn offline_purge_publishes_headers_and_converges_after_restart() {
    let mut f = PurgeFixture::new();
    f.purge();
    let store = f.store();
    let t = (&store, &[0x61; 44][..]);
    let mut tx = f.replica(&f.sender);
    let mut rx = f.replica(&f.receiver);
    assert_eq!(tx.push(&t).unwrap(), 4);
    assert!(tx.reducer().unwrap().pending_outbox().unwrap().is_empty());
    assert_eq!(rx.pull(&t).unwrap(), 4);
    assert_eq!(
        rx.reducer().unwrap().view().unwrap().digest(),
        tx.reducer().unwrap().view().unwrap().digest()
    );
    assert_eq!(
        rx.reducer()
            .unwrap()
            .view()
            .unwrap()
            .item(&f.item)
            .unwrap()
            .lifecycle(),
        ItemLifecycle::Purged
    );
    assert_eq!(f.replica(&f.receiver).pull(&t).unwrap(), 0);
    assert!(f.remote.read_record(f.item).is_err());
    assert_eq!(
        rusqlite::Connection::open(&f.receiver)
            .unwrap()
            .query_row("SELECT count(*) FROM purged_items", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

struct Interrupt<'a> {
    inner: (&'a OpaqueSyncStore, &'a [u8]),
    puts: AtomicU64,
    max_puts: u64,
}
impl SyncTransport for Interrupt<'_> {
    fn put(&self, n: [u8; 32], h: [u8; 32], b: &[u8]) -> Result<(), SyncError> {
        if self.puts.fetch_add(1, Ordering::SeqCst) >= self.max_puts {
            return Err(SyncError::Backpressure);
        }
        self.inner.put(n, h, b)
    }
    fn get(&self, n: [u8; 32], h: [u8; 32]) -> Result<Vec<u8>, SyncError> {
        self.inner.get(n, h)
    }
    fn publish(&self, _: [u8; 32], _: [u8; 32]) -> Result<(), SyncError> {
        Err(SyncError::Backpressure)
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
#[test]
fn interrupted_publication_preserves_outbox_then_resumes_all_antecedents() {
    let mut f = PurgeFixture::new();
    f.purge();
    let store = f.store();
    let t = (&store, &[0x61; 44][..]);
    let before = snapshot(&f.sender);
    for max_puts in [0, 2, u64::MAX] {
        assert!(
            f.replica(&f.sender)
                .push(&Interrupt {
                    inner: t,
                    puts: AtomicU64::new(0),
                    max_puts
                })
                .is_err()
        );
        assert_eq!(snapshot(&f.sender), before);
        assert!(t.list(f.namespace, None, 128).unwrap().is_empty());
    }
    assert_eq!(f.replica(&f.sender).push(&t).unwrap(), 4);
    assert_eq!(f.replica(&f.receiver).pull(&t).unwrap(), 4);
}

#[test]
fn duplicate_package_rejects_with_valid_payload_unchanged() {
    let f = PurgeFixture::new();
    let events = CausalReducer::open(&f.sender)
        .unwrap()
        .pending_outbox()
        .unwrap();
    let graph = CausalReducer::open(&f.sender)
        .unwrap()
        .export_ciphertext_graph(&events[0], &f.dir.path("valid-graph"))
        .unwrap()
        .unwrap();
    let duplicates = vec![events[0].clone(), events[0].clone()];
    reject(
        &f,
        &duplicates,
        std::slice::from_ref(&graph),
        "duplicate package event",
    );
}
#[test]
fn missing_graph_kind_rejects_with_valid_payload_unchanged() {
    let f = PurgeFixture::new();
    let events = CausalReducer::open(&f.sender)
        .unwrap()
        .pending_outbox()
        .unwrap();
    let mut graph = CausalReducer::open(&f.sender)
        .unwrap()
        .export_ciphertext_graph(&events[0], &f.dir.path("valid-graph"))
        .unwrap()
        .unwrap();
    graph.kind.clear();
    reject(&f, &events, &[graph], "graph kind absent");
}

#[test]
fn pending_purge_carries_previously_acknowledged_graphless_antecedents() {
    let mut f = PurgeFixture::new();
    let edit = f
        .owner
        .prepare_edit_record(f.item, &note("synthetic acknowledged edit"))
        .unwrap();
    commit(&mut f.owner, &edit);
    let trash = f.owner.prepare_delete(f.item).unwrap();
    commit(&mut f.owner, &trash);
    let old_store = f.store();
    assert_eq!(
        f.replica(&f.sender)
            .push(&(&old_store, &[0x61; 44][..]))
            .unwrap(),
        3
    );
    let purge = f.owner.prepare_purge_item(f.item).unwrap();
    commit(&mut f.owner, purge.prepared());
    // A fresh server has no old roots. The one pending purge must carry proof.
    let store = OpaqueSyncStore::create(&f.dir.path("fresh-store.sqlite3")).unwrap();
    store.authorize(f.namespace, &[0x61; 44]).unwrap();
    let t = (&store, &[0x61; 44][..]);
    assert_eq!(f.replica(&f.sender).push(&t).unwrap(), 1);
    assert_eq!(f.replica(&f.receiver).pull(&t).unwrap(), 4);
    assert_eq!(count_rows(&f.receiver, "authority_events"), 4);
    assert_eq!(count_rows(&f.receiver, "revision_parts"), 0);
}
fn count_rows(path: &Path, table: &str) -> i64 {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}
fn pairing(f: &PurgeFixture) -> SyncPairing {
    SyncPairing::from_protected_bytes(&f.protected, &f.trusted).unwrap()
}
fn root_wire(count: u64, pages: &[(u64, [u8; 32])]) -> Vec<u8> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(3)
        .unwrap()
        .u64(3)
        .unwrap()
        .u64(count)
        .unwrap()
        .array(pages.len() as u64)
        .unwrap();
    for (i, h) in pages {
        e.array(2).unwrap().u64(*i).unwrap().bytes(h).unwrap();
    }
    e.into_writer()
}
fn page_wire(events: &[[u8; 32]], graphs: &[[u8; 32]]) -> Vec<u8> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(3)
        .unwrap()
        .u64(2)
        .unwrap()
        .array(events.len() as u64)
        .unwrap();
    for h in events {
        e.bytes(h).unwrap();
    }
    e.array(graphs.len() as u64).unwrap();
    for h in graphs {
        e.bytes(h).unwrap();
    }
    e.into_writer()
}
fn put_wire(f: &PurgeFixture, t: &impl SyncTransport, wire: &[u8]) -> [u8; 32] {
    let bytes = pairing(f).seal(wire).unwrap();
    let hash = pm_crypto::digest(&bytes);
    t.put(f.namespace, hash, &bytes).unwrap();
    hash
}
fn rejection_root(f: &PurgeFixture, wire: &[u8], label: &str) {
    ensure_valid_content(f);
    let store = OpaqueSyncStore::create(&f.dir.path(label)).unwrap();
    store.authorize(f.namespace, &[0x61; 44]).unwrap();
    let t = (&store, &[0x61; 44][..]);
    let hash = put_wire(f, &t, wire);
    t.publish(f.namespace, hash).unwrap();
    let mut rx = f.replica(&f.receiver);
    let before = snapshot(&f.receiver);
    assert!(rx.pull(&t).is_err(), "{label}");
    assert_eq!(snapshot(&f.receiver), before, "{label}");
    println!("PASS rejection={label} authority/content/outbox/markers unchanged");
}

#[test]
fn transfer_root_rejects_unknown_version_duplicate_reordered_and_missing_pages() {
    let f = PurgeFixture::new();
    rejection_root(&f, &[0x83, 0x04, 0x01, 0x80], "unsupported version");
    rejection_root(
        &f,
        &root_wire(2, &[(0, [7; 32]), (1, [7; 32])]),
        "duplicate page hash",
    );
    rejection_root(
        &f,
        &root_wire(2, &[(1, [7; 32]), (0, [8; 32])]),
        "reordered page index",
    );
    rejection_root(&f, &root_wire(1, &[(0, [7; 32])]), "missing page");
    rejection_root(
        &f,
        &root_wire(257, &[(0, [7; 32])]),
        "incomplete page count",
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn paginated_purge_verifies_all_pages_and_causal_order_before_activation() {
    let mut f = PurgeFixture::new();
    // Actual signed revisions fill both pages; purge is in the second page.
    for _ in 0..256 {
        let edit = f
            .owner
            .prepare_edit_record(f.item, &note("synthetic paginated edit"))
            .unwrap();
        commit(&mut f.owner, &edit);
    }
    let trash = f.owner.prepare_delete(f.item).unwrap();
    commit(&mut f.owner, &trash);
    let purge = f.owner.prepare_purge_item(f.item).unwrap();
    commit(&mut f.owner, purge.prepared());
    let store = f.store();
    let t = (&store, &[0x61; 44][..]);
    assert_eq!(f.replica(&f.sender).push(&t).unwrap(), 259);
    let roots = t.list(f.namespace, None, 128).unwrap();
    assert_eq!(roots.len(), 1);
    let root = pairing(&f)
        .open(&t.get(f.namespace, roots[0].1).unwrap())
        .unwrap();
    let mut d = minicbor::Decoder::new(&root);
    assert_eq!(d.array().unwrap(), Some(3));
    assert_eq!(d.u64().unwrap(), 3);
    assert_eq!(d.u64().unwrap(), 259);
    assert_eq!(d.array().unwrap(), Some(2));
    let mut pages = Vec::new();
    for index in 0..2 {
        assert_eq!(d.array().unwrap(), Some(2));
        assert_eq!(d.u64().unwrap(), index);
        pages.push(<[u8; 32]>::try_from(d.bytes().unwrap()).unwrap());
    }
    let original = t.get(f.namespace, pages[1]).unwrap();
    let db = rusqlite::Connection::open(f.dir.path("purge-store.sqlite3")).unwrap();
    db.execute("DELETE FROM blocks WHERE hash=?1", [pages[1].as_slice()])
        .unwrap();
    let mut rx = f.replica(&f.receiver);
    let before = snapshot(&f.receiver);
    assert!(rx.pull(&t).is_err());
    assert_eq!(snapshot(&f.receiver), before);
    println!(
        "PASS rejection=incomplete published group authority/content/outbox/markers unchanged"
    );
    db.execute(
        "INSERT INTO blocks(namespace,hash,bytes)VALUES(?1,?2,?3)",
        rusqlite::params![f.namespace.as_slice(), pages[1].as_slice(), original],
    )
    .unwrap();
    // Re-indexed swapped pages still violate causal order, independently of wire indices.
    let swapped = put_wire(&f, &t, &root_wire(259, &[(0, pages[1]), (1, pages[0])]));
    db.execute(
        "UPDATE roots SET hash=?1 WHERE hash=?2",
        rusqlite::params![swapped.as_slice(), roots[0].1.as_slice()],
    )
    .unwrap();
    assert!(rx.pull(&t).is_err());
    assert_eq!(snapshot(&f.receiver), before);
    println!("PASS rejection=swapped causal pages authority/content/outbox/markers unchanged");
    db.execute(
        "UPDATE roots SET hash=?1 WHERE hash=?2",
        rusqlite::params![roots[0].1.as_slice(), swapped.as_slice()],
    )
    .unwrap();
    assert_eq!(rx.pull(&t).unwrap(), 259);
    assert_eq!(count_rows(&f.receiver, "authority_events"), 259);
    assert_eq!(count_rows(&f.receiver, "revision_parts"), 0);
    assert_eq!(count_rows(&f.receiver, "purged_items"), 1);
    assert_eq!(
        rx.reducer().unwrap().view().unwrap().digest(),
        f.replica(&f.sender)
            .reducer()
            .unwrap()
            .view()
            .unwrap()
            .digest()
    );
    println!("PASS paginated-purge events=259 pages=2 payloads=0 headers=259");
}

#[test]
fn selective_purge_and_replay_preserve_newer_content_and_authority() {
    let mut f = PurgeFixture::new();
    let old_events = CausalReducer::open(&f.sender)
        .unwrap()
        .pending_outbox()
        .unwrap();
    let old_graph = CausalReducer::open(&f.sender)
        .unwrap()
        .export_ciphertext_graph(&old_events[0], &f.dir.path("old-graph"))
        .unwrap()
        .unwrap();
    let old_revision = *f.owner.history(f.item).unwrap().entries()[0].revision_id();
    let edit = f
        .owner
        .prepare_edit_record(f.item, &note("synthetic newer winner"))
        .unwrap();
    commit(&mut f.owner, &edit);
    let purge = f
        .owner
        .prepare_purge_revisions(f.item, vec![old_revision])
        .unwrap();
    commit(&mut f.owner, purge.prepared());
    let store = f.store();
    let t = (&store, &[0x61; 44][..]);
    assert_eq!(f.replica(&f.sender).push(&t).unwrap(), 3);
    let mut rx = f.replica(&f.receiver);
    assert_eq!(rx.pull(&t).unwrap(), 3);
    assert_eq!(count_rows(&f.receiver, "revision_parts"), 1);
    assert_eq!(count_rows(&f.receiver, "purged_revisions"), 1);
    let before = snapshot(&f.receiver);
    // Previously purged payload is explicitly rejected, even with valid signatures.
    assert!(
        rx.reducer()
            .unwrap()
            .apply_received_package(&old_events, &[old_graph])
            .is_err()
    );
    assert_eq!(snapshot(&f.receiver), before);
    // Replaying retained headers alone is idempotent under the local purge proof.
    rx.reducer()
        .unwrap()
        .apply_received_package(&old_events, &[])
        .unwrap();
    assert_eq!(snapshot(&f.receiver), before);
    assert_eq!(
        f.remote.read_record(f.item).unwrap().human().title,
        "synthetic newer winner"
    );
    assert_eq!(f.replica(&f.receiver).pull(&t).unwrap(), 0);
    println!(
        "PASS rejection=purged payload replay/rollback authority/content/outbox/markers unchanged; header replay idempotent"
    );
}

#[test]
fn duplicated_and_reordered_event_lists_reject_atomically() {
    let mut f = PurgeFixture::new();
    f.purge();
    for mode in [
        "duplicate event hash",
        "reordered event hashes",
        "duplicate signed event",
    ] {
        let store = OpaqueSyncStore::create(&f.dir.path(mode)).unwrap();
        store.authorize(f.namespace, &[0x61; 44]).unwrap();
        let t = (&store, &[0x61; 44][..]);
        let events = CausalReducer::open(&f.sender)
            .unwrap()
            .pending_outbox()
            .unwrap();
        let mut hashes = vec![
            put_wire(&f, &t, &events[0].to_bytes()),
            put_wire(&f, &t, &events[1].to_bytes()),
        ];
        hashes.sort_unstable();
        match mode {
            "duplicate event hash" => hashes[1] = hashes[0],
            "reordered event hashes" => hashes.reverse(),
            "duplicate signed event" => {
                hashes[1] = put_wire(&f, &t, &events[0].to_bytes());
                hashes.sort_unstable();
            }
            _ => unreachable!(),
        }
        let page = put_wire(&f, &t, &page_wire(&hashes, &[]));
        let root = put_wire(&f, &t, &root_wire(2, &[(0, page)]));
        t.publish(f.namespace, root).unwrap();
        let mut rx = f.replica(&f.receiver);
        let before = snapshot(&f.receiver);
        assert!(rx.pull(&t).is_err(), "{mode}");
        assert_eq!(snapshot(&f.receiver), before, "{mode}");
        println!("PASS rejection={mode} authority/content/outbox/markers unchanged");
    }
}

struct TlsServer {
    child: std::process::Child,
    transport: ProcessTlsTransport,
}
impl TlsServer {
    fn start(f: &mut PurgeFixture) -> Self {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&f.dir.0, fs::Permissions::from_mode(0o700)).unwrap();
        let (server_key, server_public) = tls_key(&f.dir, "w2-server");
        let (client_key, client_public) = tls_key(&f.dir, "w2-client");
        let pin = fs::read(&server_public).unwrap().try_into().unwrap();
        f.server_pin = pin;
        f.client_rpk = fs::read(&client_public).unwrap().try_into().unwrap();
        // Reprovision before the test's first transfer, keeping the same vault authority.
        f.protected = f
            .owner
            .create_sync_pairing(pin)
            .unwrap()
            .to_protected_bytes();
        f.namespace = *pairing(f).namespace();
        let socket = f.dir.path("w2-sync.sock");
        let mut child = Command::new(env!("CARGO_BIN_EXE_pm-sync"))
            .arg("serve")
            .arg("--db")
            .arg(f.dir.path("tls-store.sqlite3"))
            .arg("--socket")
            .arg(&socket)
            .arg("--server-key")
            .arg(server_key)
            .arg("--namespace")
            .arg(hex_test(&f.namespace))
            .arg("--client-pub")
            .arg(client_public)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !socket.exists() {
            assert!(Instant::now() < deadline);
            assert!(child.try_wait().unwrap().is_none());
            thread::sleep(Duration::from_millis(10));
        }
        Self {
            child,
            transport: ProcessTlsTransport::authenticated_session(
                Path::new(env!("CARGO_BIN_EXE_pm-sync")),
                &socket,
                &client_key,
                &server_public,
            ),
        }
    }
}
impl Drop for TlsServer {
    fn drop(&mut self) {
        self.transport
            .finish()
            .expect("close owned W2 client session");
        if self
            .child
            .try_wait()
            .expect("query owned W2 server")
            .is_none()
        {
            self.child.kill().expect("stop owned W2 server");
        }
        self.child.wait().expect("reap owned W2 server");
    }
}

#[test]
fn two_real_replicas_offline_edit_purge_converge_over_tls_rpk() {
    let mut f = PurgeFixture::new();
    let server = TlsServer::start(&mut f);
    f.purge();
    let mut tx = f.replica(&f.sender);
    let mut rx = f.replica(&f.receiver);
    assert_eq!(count_rows(&f.sender, "outbox"), 4);
    assert_eq!(count_rows(&f.sender, "revision_parts"), 0);
    assert_eq!(tx.push(&server.transport).unwrap(), 4);
    assert_eq!(rx.pull(&server.transport).unwrap(), 4);
    assert_eq!(
        tx.reducer().unwrap().view().unwrap().digest(),
        rx.reducer().unwrap().view().unwrap().digest()
    );
    assert_eq!(count_rows(&f.sender, "outbox"), 0);
    assert_eq!(count_rows(&f.receiver, "revision_parts"), 0);
    assert_eq!(count_rows(&f.receiver, "authority_events"), 4);
    assert_eq!(
        *open_vault(&f.receiver, MASTER).unwrap().trusted_root(),
        f.trusted
    );
    assert!(f.remote.read_record(f.item).is_err());
    let before = snapshot(&f.receiver);
    assert_eq!(f.replica(&f.receiver).pull(&server.transport).unwrap(), 0);
    assert_eq!(snapshot(&f.receiver), before);
    println!("PASS TLS/RPK offline create/edit/trash/purge push/pull/restart headers=4 payloads=0");
}

#[test]
fn trash_and_terminal_purge_win_concurrent_edit_over_tls_rpk() {
    let mut f = PurgeFixture::new();
    let server = TlsServer::start(&mut f);
    assert_eq!(f.replica(&f.sender).push(&server.transport).unwrap(), 1);
    assert_eq!(f.replica(&f.receiver).pull(&server.transport).unwrap(), 1);
    let edit = f
        .remote
        .prepare_edit_record(f.item, &note("synthetic concurrent winner"))
        .unwrap();
    commit(&mut f.remote, &edit);
    let trash = f.owner.prepare_delete(f.item).unwrap();
    commit(&mut f.owner, &trash);
    assert_eq!(f.replica(&f.sender).push(&server.transport).unwrap(), 1);
    assert_eq!(f.replica(&f.receiver).pull(&server.transport).unwrap(), 1);
    let view = f.replica(&f.receiver).reducer().unwrap().view().unwrap();
    assert_eq!(
        view.item(&f.item).unwrap().lifecycle(),
        ItemLifecycle::Trash
    );
    assert_eq!(
        f.remote
            .read_revision(
                f.item,
                *view.item(&f.item).unwrap().visible_revision().unwrap()
            )
            .unwrap()
            .human()
            .title,
        "synthetic concurrent winner"
    );
    let purge = f.owner.prepare_purge_item(f.item).unwrap();
    commit(&mut f.owner, purge.prepared());
    // Publish the concurrent edit after the purge has removed the sender's payload.
    assert_eq!(f.replica(&f.sender).push(&server.transport).unwrap(), 1);
    assert_eq!(f.replica(&f.receiver).push(&server.transport).unwrap(), 1);
    f.replica(&f.receiver).pull(&server.transport).unwrap();
    f.replica(&f.sender).pull(&server.transport).unwrap();
    for path in [&f.sender, &f.receiver] {
        assert_eq!(count_rows(path, "revision_parts"), 0);
        assert_eq!(count_rows(path, "vault_items"), 0);
        assert_eq!(count_rows(path, "purged_items"), 1);
        assert_eq!(
            f.replica(path)
                .reducer()
                .unwrap()
                .view()
                .unwrap()
                .item(&f.item)
                .unwrap()
                .lifecycle(),
            ItemLifecycle::Purged
        );
    }
    assert_eq!(
        f.replica(&f.sender)
            .reducer()
            .unwrap()
            .view()
            .unwrap()
            .digest(),
        f.replica(&f.receiver)
            .reducer()
            .unwrap()
            .view()
            .unwrap()
            .digest()
    );
    println!("PASS TLS/RPK ADR0002 trash retains concurrent LWW; purge terminal on both replicas");
}

#[test]
fn missing_parent_and_count_mismatch_reject_complete_wire_atomically() {
    let mut f = PurgeFixture::new();
    f.purge();
    ensure_valid_content(&f);
    let events = CausalReducer::open(&f.sender)
        .unwrap()
        .pending_outbox()
        .unwrap();
    for (label, skip, count) in [
        ("missing causal parent", true, 3),
        ("event count mismatch", false, 5),
    ] {
        let store = OpaqueSyncStore::create(&f.dir.path(label)).unwrap();
        store.authorize(f.namespace, &[0x61; 44]).unwrap();
        let t = (&store, &[0x61; 44][..]);
        let mut hashes: Vec<_> = events
            .iter()
            .skip(usize::from(skip))
            .map(|e| put_wire(&f, &t, &e.to_bytes()))
            .collect();
        hashes.sort_unstable();
        let page = put_wire(&f, &t, &page_wire(&hashes, &[]));
        let root = put_wire(&f, &t, &root_wire(count, &[(0, page)]));
        t.publish(f.namespace, root).unwrap();
        let mut rx = f.replica(&f.receiver);
        let before = snapshot(&f.receiver);
        assert!(rx.pull(&t).is_err(), "{label}");
        assert_eq!(snapshot(&f.receiver), before, "{label}");
        println!("PASS rejection={label} authority/content/outbox/markers unchanged");
    }
}

#[test]
fn reception_marker_failure_rolls_back_authority_payload_and_purge_then_resumes() {
    let mut f = PurgeFixture::new();
    f.purge();
    ensure_valid_content(&f);
    let store = f.store();
    let t = (&store, &[0x61; 44][..]);
    let mut rx = f.replica(&f.receiver);
    assert_eq!(rx.pull(&t).unwrap(), 0);
    assert_eq!(f.replica(&f.sender).push(&t).unwrap(), 4);
    let db = rusqlite::Connection::open(&f.receiver).unwrap();
    db.execute_batch("CREATE TRIGGER fail_root BEFORE INSERT ON sync_received_roots BEGIN SELECT RAISE(ABORT,'synthetic marker interruption'); END;").unwrap();
    let before = snapshot(&f.receiver);
    assert!(rx.pull(&t).is_err());
    assert_eq!(snapshot(&f.receiver), before);
    println!(
        "PASS rejection=receive marker commit failure authority/content/outbox/markers unchanged"
    );
    db.execute_batch("DROP TRIGGER fail_root").unwrap();
    assert_eq!(f.replica(&f.receiver).pull(&t).unwrap(), 4);
    assert_eq!(count_rows(&f.receiver, "purged_items"), 1);
    assert_eq!(count_rows(&f.receiver, "sync_received_roots"), 1);
    assert_eq!(count_rows(&f.receiver, "revision_parts"), 1); // unrelated valid local content
}

#[test]
fn missing_device_signature_rejects_at_wire_boundary_without_mutation() {
    let mut f = PurgeFixture::new();
    f.purge();
    ensure_valid_content(&f);
    let store = f.store();
    let t = (&store, &[0x61; 44][..]);
    let events = CausalReducer::open(&f.sender)
        .unwrap()
        .pending_outbox()
        .unwrap();
    let mut hashes: Vec<_> = events
        .iter()
        .enumerate()
        .map(|(i, e)| {
            put_wire(
                &f,
                &t,
                &if i == 0 {
                    tampered_wire(e, "missing device signature")
                } else {
                    e.to_bytes()
                },
            )
        })
        .collect();
    hashes.sort_unstable();
    let page = put_wire(&f, &t, &page_wire(&hashes, &[]));
    let root = put_wire(&f, &t, &root_wire(4, &[(0, page)]));
    t.publish(f.namespace, root).unwrap();
    let mut rx = f.replica(&f.receiver);
    let before = snapshot(&f.receiver);
    assert!(rx.pull(&t).is_err());
    assert_eq!(snapshot(&f.receiver), before);
    println!("PASS rejection=missing device signature authority/content/outbox/markers unchanged");
}

#[test]
fn losing_graph_never_substitutes_kind_of_exact_local_winner() {
    let mut f = PurgeFixture::new();
    let store = f.store();
    let t = (&store, &[0x61; 44][..]);
    let events = CausalReducer::open(&f.sender)
        .unwrap()
        .pending_outbox()
        .unwrap();
    let graph = CausalReducer::open(&f.sender)
        .unwrap()
        .export_ciphertext_graph(&events[0], &f.dir.path("losing-note"))
        .unwrap()
        .unwrap();
    assert_eq!(f.replica(&f.sender).push(&t).unwrap(), 1);
    assert_eq!(f.replica(&f.receiver).pull(&t).unwrap(), 1);
    let record = LogicalRecord::new(
        RecordKind::File,
        HumanMetadata {
            title: "synthetic newer file".into(),
            destinations: vec![],
            tags: vec![],
            favorite: false,
            notes: pm_crypto::ProtectedText::copy_from_str("").unwrap(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![],
        vec![
            Attachment::new(
                [0x81; 16],
                "synthetic.txt",
                "text/plain",
                b"synthetic W2 attachment",
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let edit = f.remote.prepare_edit_record(f.item, &record).unwrap();
    commit(&mut f.remote, &edit);
    let before = snapshot(&f.receiver);
    // Only the old, losing note graph is supplied. The local winner is a file.
    CausalReducer::open(&f.receiver)
        .unwrap()
        .apply_received_package(&events, &[graph])
        .unwrap();
    assert_eq!(snapshot(&f.receiver), before);
    let kind: String = rusqlite::Connection::open(&f.receiver)
        .unwrap()
        .query_row(
            "SELECT kind FROM vault_items WHERE item_id=?1",
            [f.item.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(kind, "file");
    assert_eq!(
        f.remote.read_record(f.item).unwrap().kind(),
        RecordKind::File
    );
    println!("PASS exact local winner kind=file; losing note graph never substitutes kind");
}

#[test]
fn historical_v2_graph_reference_order_remains_compatible() {
    let mut f = PurgeFixture::new();
    let other = f
        .owner
        .prepare_create_record(&note("synthetic other legacy item"))
        .unwrap();
    commit(&mut f.owner, &other);
    let store = f.store();
    let t = (&store, &[0x61; 44][..]);
    assert_eq!(f.replica(&f.sender).push(&t).unwrap(), 2);
    let root = t.list(f.namespace, None, 128).unwrap()[0].1;
    let root_bytes = pairing(&f)
        .open(&t.get(f.namespace, root).unwrap())
        .unwrap();
    let mut d = minicbor::Decoder::new(&root_bytes);
    assert_eq!(d.array().unwrap(), Some(3));
    assert_eq!(d.u64().unwrap(), 3);
    assert_eq!(d.u64().unwrap(), 2);
    assert_eq!(d.array().unwrap(), Some(1));
    assert_eq!(d.array().unwrap(), Some(2));
    assert_eq!(d.u64().unwrap(), 0);
    let page_hash = d.bytes().unwrap().try_into().unwrap();
    let page = pairing(&f)
        .open(&t.get(f.namespace, page_hash).unwrap())
        .unwrap();
    let mut d = minicbor::Decoder::new(&page);
    assert_eq!(d.array().unwrap(), Some(3));
    assert_eq!(d.u64().unwrap(), 2);
    let n = d.array().unwrap().unwrap();
    let events: Vec<[u8; 32]> = (0..n)
        .map(|_| d.bytes().unwrap().try_into().unwrap())
        .collect();
    let n = d.array().unwrap().unwrap();
    let mut graphs: Vec<[u8; 32]> = (0..n)
        .map(|_| d.bytes().unwrap().try_into().unwrap())
        .collect();
    assert_eq!(graphs.len(), 2);
    graphs.sort_unstable_by(|a, b| b.cmp(a));
    let legacy = put_wire(&f, &t, &page_wire(&events, &graphs));
    rusqlite::Connection::open(f.dir.path("purge-store.sqlite3"))
        .unwrap()
        .execute("DELETE FROM roots", [])
        .unwrap();
    t.publish(f.namespace, legacy).unwrap();
    assert_eq!(f.replica(&f.receiver).pull(&t).unwrap(), 2);
    assert_eq!(
        f.remote.read_record(f.item).unwrap().human().title,
        "synthetic W2 create"
    );
    assert_eq!(
        f.remote
            .read_record(*other.item_id())
            .unwrap()
            .human()
            .title,
        "synthetic other legacy item"
    );
    println!("PASS historical v2 accepts graph reference order while v3 remains mandatory on push");
}

#[test]
fn backup_restored_streams_remain_bound_and_publish_with_offline_purge() {
    let mut f = PurgeFixture::new();
    let bytes = vec![0x67; 2 * 1024 * 1024 + 37];
    let record = LogicalRecord::new_streaming(
        RecordKind::File,
        HumanMetadata {
            title: "synthetic W2 backup stream".into(),
            destinations: vec![],
            tags: vec![],
            favorite: false,
            notes: pm_crypto::ProtectedText::copy_from_str("").unwrap(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![],
        vec![
            Attachment::descriptor(
                [0x88; 16],
                "synthetic.bin",
                "application/octet-stream",
                bytes.len() as u64,
                pm_crypto::digest(&bytes),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let mut cursor = std::io::Cursor::new(&bytes);
    let mut readers = [AttachmentReader::new([0x88; 16], &mut cursor)];
    let create = f
        .owner
        .prepare_create_record_streaming(&record, &mut readers)
        .unwrap();
    commit(&mut f.owner, &create);
    let mut archive = Vec::new();
    f.owner.write_native_backup(&mut archive).unwrap();
    let restore = f
        .owner
        .prepare_native_restore(&mut std::io::Cursor::new(&archive), MASTER)
        .unwrap();
    commit(&mut f.owner, restore.prepared());
    f.purge();
    let reducer = CausalReducer::open(&f.sender).unwrap();
    for (index, event) in reducer.pending_outbox().unwrap().iter().enumerate() {
        let db = rusqlite::Connection::open(&f.sender).unwrap();
        let kind: String = db
            .query_row(
                "SELECT kind FROM authority_events WHERE event_digest=?1",
                [event.digest().as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        let graph =
            reducer.export_ciphertext_graph(event, &f.dir.path(&format!("restore-export-{index}")));
        if let Err(error) = graph {
            panic!("restore/export {index} kind={kind} failed: {error:?}");
        }
    }
    let store = f.store();
    let t = (&store, &[0x61; 44][..]);
    assert_eq!(f.replica(&f.sender).push(&t).unwrap(), 7);
    assert_eq!(f.replica(&f.receiver).pull(&t).unwrap(), 7);
    assert_eq!(count_rows(&f.receiver, "vault_items"), 3);
    assert_eq!(count_rows(&f.receiver, "purged_items"), 1);
    println!(
        "PASS backup restore stream graphs publish alongside offline purge without integrity loss"
    );
}

struct WorkloadTransport<'a> {
    inner: &'a ProcessTlsTransport,
    started: Instant,
    puts: std::cell::Cell<usize>,
    gets: std::cell::Cell<usize>,
    publishes: std::cell::Cell<usize>,
}

fn workload_trace(message: std::fmt::Arguments<'_>) {
    use std::io::Write as _;
    // The native workflow does not use --nocapture. Write directly so only
    // these fixed categorical counters remain observable on a passing test.
    writeln!(std::io::stdout().lock(), "{message}").expect("write workload diagnostic");
}

impl SyncTransport for WorkloadTransport<'_> {
    fn put(&self, n: [u8; 32], h: [u8; 32], b: &[u8]) -> Result<(), SyncError> {
        self.inner.put(n, h, b)?;
        let puts = self.puts.get() + 1;
        self.puts.set(puts);
        if puts.is_multiple_of(64) {
            workload_trace(format_args!(
                "PMW2_WORKLOAD phase=put puts={puts} elapsed_ms={}",
                self.started.elapsed().as_millis()
            ));
        }
        Ok(())
    }

    fn get(&self, n: [u8; 32], h: [u8; 32]) -> Result<Vec<u8>, SyncError> {
        let bytes = self.inner.get(n, h)?;
        self.gets.set(self.gets.get() + 1);
        Ok(bytes)
    }

    fn publish(&self, n: [u8; 32], h: [u8; 32]) -> Result<(), SyncError> {
        workload_trace(format_args!(
            "PMW2_WORKLOAD phase=publish-start puts={} elapsed_ms={}",
            self.puts.get(),
            self.started.elapsed().as_millis()
        ));
        self.inner.publish(n, h)?;
        self.publishes.set(self.publishes.get() + 1);
        workload_trace(format_args!(
            "PMW2_WORKLOAD phase=publish-complete roots={} elapsed_ms={}",
            self.publishes.get(),
            self.started.elapsed().as_millis()
        ));
        Ok(())
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

fn count_client_executions(f: &PurgeFixture, server: &mut TlsServer) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let calls = f.dir.path("workload-client-executions");
    let wrapper = f.dir.path("workload-client-wrapper");
    let quote = |path: &Path| format!("'{}'", path.to_str().unwrap().replace('\'', "'\"'\"'"));
    fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nprintf x >> {}\nexec {} \"$@\"\n",
            quote(&calls),
            quote(Path::new(env!("CARGO_BIN_EXE_pm-sync")))
        ),
    )
    .unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    server.transport = ProcessTlsTransport::authenticated_session(
        &wrapper,
        &f.dir.path("w2-sync.sock"),
        &f.dir.path("w2-client.key"),
        &f.dir.path("w2-server.pub"),
    );
    calls
}

#[test]
fn restored_large_workload_measures_real_tls_root_publication() {
    let mut f = PurgeFixture::new();
    let mut server = TlsServer::start(&mut f);
    let calls = count_client_executions(&f, &mut server);
    for _ in 0..16 {
        let create = f
            .owner
            .prepare_create_record(&note("PMW2_SYNTHETIC_WORKLOAD_NOTE"))
            .unwrap();
        commit(&mut f.owner, &create);
    }
    let bytes = vec![0x67; 16 * 1024 * 1024 + 4096];
    let record = LogicalRecord::new_streaming(
        RecordKind::File,
        HumanMetadata {
            title: "PMW2_SYNTHETIC_WORKLOAD_FILE".into(),
            destinations: vec![],
            tags: vec![],
            favorite: false,
            notes: pm_crypto::ProtectedText::copy_from_str("").unwrap(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![],
        vec![
            Attachment::descriptor(
                [0x89; 16],
                "synthetic.bin",
                "application/octet-stream",
                bytes.len() as u64,
                pm_crypto::digest(&bytes),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let mut cursor = std::io::Cursor::new(&bytes);
    let mut readers = [AttachmentReader::new([0x89; 16], &mut cursor)];
    let create = f
        .owner
        .prepare_create_record_streaming(&record, &mut readers)
        .unwrap();
    commit(&mut f.owner, &create);
    let mut archive = Vec::new();
    f.owner.write_native_backup(&mut archive).unwrap();
    let restore = f
        .owner
        .prepare_native_restore(&mut std::io::Cursor::new(&archive), MASTER)
        .unwrap();
    commit(&mut f.owner, restore.prepared());
    f.purge();
    let measured = WorkloadTransport {
        inner: &server.transport,
        started: Instant::now(),
        puts: std::cell::Cell::new(0),
        gets: std::cell::Cell::new(0),
        publishes: std::cell::Cell::new(0),
    };
    assert_eq!(f.replica(&f.sender).push(&measured).unwrap(), 39);
    assert_eq!(count_rows(&f.sender, "outbox"), 0);
    let roots = measured.list(f.namespace, None, 128).unwrap();
    assert_eq!(roots.len(), 1);
    let root = pairing(&f)
        .open(&measured.get(f.namespace, roots[0].1).unwrap())
        .unwrap();
    let mut decoder = minicbor::Decoder::new(&root);
    assert_eq!(decoder.array().unwrap(), Some(3));
    assert_eq!(decoder.u64().unwrap(), 3);
    assert_eq!(decoder.u64().unwrap(), 39);
    assert_eq!(decoder.array().unwrap(), Some(1));
    assert_eq!(f.replica(&f.receiver).pull(&measured).unwrap(), 39);
    assert_eq!(count_rows(&f.receiver, "vault_items"), 35);
    assert_eq!(count_rows(&f.receiver, "purged_items"), 1);
    workload_trace(format_args!(
        "PMW2_WORKLOAD phase=converged events=39 pages=1 roots=1 puts={} gets={} elapsed_ms={}",
        measured.puts.get(),
        measured.gets.get(),
        measured.started.elapsed().as_millis()
    ));
    server.transport.finish().unwrap();
    assert_eq!(
        fs::read(&calls).unwrap().len(),
        1,
        "one authenticated session must serve the complete restored workload"
    );
}

#[test]
fn authenticated_session_checks_acl_on_every_rpc_and_keeps_integrity_limits() {
    let mut f = PurgeFixture::new();
    let server = TlsServer::start(&mut f);
    assert!(
        server
            .transport
            .list(f.namespace, None, 128)
            .unwrap()
            .is_empty()
    );
    let bytes = b"PMW2_SYNTHETIC_OPAQUE_BLOCK";
    let hash = pm_crypto::digest(bytes);
    assert!(matches!(
        server.transport.put(f.namespace, [0; 32], bytes),
        Err(SyncError::Integrity)
    ));
    assert!(matches!(
        server
            .transport
            .put(f.namespace, hash, &vec![0; MAX_BLOCK_BYTES + 1]),
        Err(SyncError::Integrity)
    ));
    let db = rusqlite::Connection::open(f.dir.path("tls-store.sqlite3")).unwrap();
    db.execute(
        "DELETE FROM namespaces WHERE namespace=?1",
        [f.namespace.as_slice()],
    )
    .unwrap();
    assert!(
        server.transport.put(f.namespace, hash, bytes).is_err(),
        "TLS identity must not cache namespace permission"
    );
    assert_eq!(count_rows(&f.dir.path("tls-store.sqlite3"), "blocks"), 0);
    OpaqueSyncStore::create(&f.dir.path("tls-store.sqlite3"))
        .unwrap()
        .authorize(f.namespace, &f.client_rpk)
        .unwrap();
    server.transport.put(f.namespace, hash, bytes).unwrap();
    assert_eq!(server.transport.get(f.namespace, hash).unwrap(), bytes);
    assert!(matches!(
        server.transport.get(f.namespace, [0; 32]),
        Err(SyncError::Missing)
    ));
    server.transport.publish(f.namespace, hash).unwrap();
    assert_eq!(
        server.transport.list(f.namespace, None, 128).unwrap().len(),
        1
    );
}

#[test]
fn authenticated_session_connection_loss_is_explicit_without_internal_replay() {
    let mut f = PurgeFixture::new();
    let mut server = TlsServer::start(&mut f);
    let bytes = b"PMW2_SYNTHETIC_CONNECTION_LOSS";
    let hash = pm_crypto::digest(bytes);
    server.transport.put(f.namespace, hash, bytes).unwrap();
    server.child.kill().unwrap();
    server.child.wait().unwrap();
    let started = Instant::now();
    assert!(matches!(
        server.transport.get(f.namespace, hash),
        Err(SyncError::Unavailable)
    ));
    assert!(started.elapsed() < Duration::from_secs(30));
    assert_eq!(count_rows(&f.dir.path("tls-store.sqlite3"), "roots"), 0);
    assert!(
        !f.replica(&f.sender)
            .reducer()
            .unwrap()
            .pending_outbox()
            .unwrap()
            .is_empty()
    );
    server.transport.finish().unwrap();
}

#[test]
fn authenticated_session_preserves_wal_and_durable_commits_between_blocks() {
    let mut f = PurgeFixture::new();
    let mut server = TlsServer::start(&mut f);
    let bytes = b"PMW2_SYNTHETIC_DURABLE_WAL_BLOCK";
    let hash = pm_crypto::digest(bytes);
    server.transport.put(f.namespace, hash, bytes).unwrap();
    let db_path = f.dir.path("tls-store.sqlite3");
    let wal_path = f.dir.path("tls-store.sqlite3-wal");
    assert!(
        wal_path.exists(),
        "a block must not close the last WAL connection and force a checkpoint"
    );
    assert!(fs::metadata(wal_path).unwrap().len() > 0);
    let db = rusqlite::Connection::open(&db_path).unwrap();
    assert_eq!(
        db.query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        2,
        "FULL durability remains enabled"
    );
    drop(db);
    server.transport.publish(f.namespace, hash).unwrap();
    assert_eq!(server.transport.get(f.namespace, hash).unwrap(), bytes);
    server.transport.finish().unwrap();
    server.child.kill().unwrap();
    server.child.wait().unwrap();
    let reopened = OpaqueSyncStore::create(&db_path).unwrap();
    assert_eq!(
        reopened.get(f.namespace, &f.client_rpk, hash).unwrap(),
        bytes
    );
    assert_eq!(
        reopened
            .list(f.namespace, &f.client_rpk, None, 128)
            .unwrap()
            .len(),
        1
    );
}
