// SPDX-License-Identifier: AGPL-3.0-only
#![cfg(target_os = "linux")]

use pm_crypto::{KdfProfile, SyncPairing};
use pm_sync::{MAX_BLOCK_BYTES, OpaqueSyncStore, SyncError, SyncReplica};
use pm_vault::{
    AuditDeviceCustody, CausalEventBody, CausalEventDraft, CausalEventKind, CausalReducer,
    HumanChannel, HumanVault, PendingVault, open_vault,
};
use std::{
    fs,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

const MASTER: &[u8] = b"synthetic ticket 17 master";
const ITEM: [u8; 16] = [0x17; 16];
static NEXT: AtomicU64 = AtomicU64::new(0);

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
    for replica in &mut replicas {
        assert_eq!(replica.push(&server).unwrap(), 1);
    }
    let before_server = fs::read(&store_path).unwrap();
    assert!(!contains(&before_server, MASTER));
    assert!(!contains(&before_server, b"synthetic ticket 17"));
    let mut digests = Vec::new();
    for replica in &mut replicas {
        assert_eq!(replica.pull(&server).unwrap(), 3);
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
    assert_eq!(replicas[0].push(&server).unwrap(), 1);
    assert!(
        !replicas[1]
            .reducer()
            .unwrap()
            .view()
            .unwrap()
            .device_retired(&[0xb2; 16])
    );
    assert_eq!(replicas[1].pull(&server).unwrap(), 1);
    assert!(
        replicas[1]
            .reducer()
            .unwrap()
            .view()
            .unwrap()
            .device_retired(&[0xb2; 16])
    );
    for replica in &mut replicas {
        assert_eq!(replica.push(&server).unwrap(), 0);
        let _ = replica.pull(&server).unwrap();
        assert_eq!(replica.pull(&server).unwrap(), 0);
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
    assert_eq!(tx.push(&server).unwrap(), 2);
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
    assert!(rx.pull(&server).is_err());
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
    assert_eq!(rx.pull(&server).unwrap(), 2);
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
