// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(target_os = "linux")]

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

use pm_crypto::KdfProfile;
use pm_vault::{
    AuditDeviceCustody, CausalEventBody, CausalEventDraft, CausalEventKind, CausalReducer,
    HumanChannel, HumanVault, ItemLifecycle, PasswordRecord, PendingVault, SignedCausalEvent,
};

const MASTER: &[u8] = b"synthetic ticket 16 master";
const ITEM: [u8; 16] = [0x16; 16];
static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
fn concurrent_revisions_converge_by_exact_tuple_in_every_delivery_order() {
    let directory = TestDir::new();
    let seed = directory.path("seed.sqlite3");
    persist_test_vault(&seed);

    let mut signed = Vec::new();
    for (index, modified_at) in [3_i64, 99, 40].into_iter().enumerate() {
        let device = [u8::try_from(index + 1).unwrap(); 16];
        let custody = Arc::new(AuditDeviceCustody::generate().unwrap());
        let (human, _peer) = open_human(&seed, device, custody);
        signed.push(
            human
                .sign_causal_event(&revision_draft(
                    [0x30 + u8::try_from(index).unwrap(); 16],
                    [0x40 + u8::try_from(index).unwrap(); 16],
                    modified_at,
                ))
                .unwrap(),
        );
    }
    rusqlite::Connection::open(&seed)
        .unwrap()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();

    let orders = [[0, 1, 2], [2, 0, 1], [1, 2, 0], [2, 1, 0]];
    let mut expected_digest = None;
    for (case, order) in orders.into_iter().enumerate() {
        let path = directory.path(&format!("case-{case}.sqlite3"));
        fs::copy(&seed, &path).unwrap();
        let mut reducer = CausalReducer::open(&path).unwrap();
        for index in order {
            reducer.apply(std::slice::from_ref(&signed[index])).unwrap();
        }
        let view = reducer.view().unwrap();
        assert_eq!(
            view.item(&ITEM).unwrap().visible_revision(),
            Some(&[0x41; 16])
        );
        assert_eq!(view.item(&ITEM).unwrap().history().len(), 3);
        match expected_digest {
            None => expected_digest = Some(*view.digest()),
            Some(expected) => assert_eq!(*view.digest(), expected),
        }
    }
}

#[test]
fn reducer_consumes_the_existing_human_commit_ledger_instead_of_a_parallel_store() {
    let directory = TestDir::new();
    let path = directory.path("existing.sqlite3");
    persist_test_vault(&path);
    let (mut human, _peer) = open_human(
        &path,
        [0x60; 16],
        Arc::new(AuditDeviceCustody::generate().unwrap()),
    );
    let record = PasswordRecord::new(
        "Synthetic existing record",
        "synthetic-user",
        b"synthetic-ticket16-secret",
        "https://synthetic.invalid",
        "synthetic",
    )
    .unwrap();
    let prepared = human.prepare_create(&record).unwrap();
    let item = *prepared.item_id();
    let signature = human.sign(&prepared).unwrap();
    human
        .commit(prepared.command(), &signature, prepared.body())
        .unwrap();
    let view = CausalReducer::open(&path).unwrap().view().unwrap();
    assert_eq!(view.retained_header_count(), 1);
    assert_eq!(view.item(&item).unwrap().lifecycle(), ItemLifecycle::Active);
}

#[test]
fn pending_delivery_replay_and_fork_need_all_signed_branches_before_successor_activates() {
    let directory = TestDir::new();
    let path = directory.path("dag.sqlite3");
    persist_test_vault(&path);
    let (device_a, _peer_a) = open_human(
        &path,
        [0xa1; 16],
        Arc::new(AuditDeviceCustody::generate().unwrap()),
    );
    let (device_b, _peer_b) = open_human(
        &path,
        [0xb2; 16],
        Arc::new(AuditDeviceCustody::generate().unwrap()),
    );

    let parent = device_a
        .sign_causal_event(&revision_draft([0x51; 16], [0x61; 16], 1))
        .unwrap();
    let child = device_a
        .sign_causal_event(
            &CausalEventDraft::new(
                [0x52; 16],
                1,
                2,
                Some(parent.digest()),
                vec![parent.digest()],
                CausalEventKind::ItemRevision,
                ITEM,
                1,
                revision_body([0x62; 16], 2),
            )
            .unwrap(),
        )
        .unwrap();
    let mut reducer = CausalReducer::open(&path).unwrap();
    let pending = reducer.apply(&[child.clone(), child.clone()]).unwrap();
    assert_eq!(pending.pending_count(), 1);
    assert_eq!(pending.retained_header_count(), 1);
    assert!(pending.item(&ITEM).is_none());
    let complete = reducer.apply(std::slice::from_ref(&parent)).unwrap();
    assert_eq!(complete.pending_count(), 0);
    assert_eq!(
        complete.item(&ITEM).unwrap().visible_revision(),
        Some(&[0x62; 16])
    );

    let fork_a = device_b
        .sign_causal_event(&revision_draft([0x71; 16], [0x81; 16], 8))
        .unwrap();
    let fork_b = device_b
        .sign_causal_event(&revision_draft([0x72; 16], [0x82; 16], 9))
        .unwrap();
    let forked = reducer.apply(&[fork_a.clone(), fork_b.clone()]).unwrap();
    assert_eq!(forked.unresolved_fork_count(), 1);
    assert!(!forked.event_active(&fork_a.digest()));
    assert!(!forked.event_active(&fork_b.digest()));
    let mut both = vec![fork_a.digest(), fork_b.digest()];
    both.sort_unstable();
    let join = device_b
        .sign_causal_event(
            &CausalEventDraft::new(
                [0x73; 16],
                1,
                2,
                Some(fork_a.digest()),
                both,
                CausalEventKind::Join,
                [0x99; 16],
                1,
                CausalEventBody::Join,
            )
            .unwrap(),
        )
        .unwrap();
    let joined = reducer.apply(std::slice::from_ref(&join)).unwrap();
    assert_eq!(joined.unresolved_fork_count(), 0);
    assert!(joined.event_active(&join.digest()));
}

#[test]
#[allow(clippy::too_many_lines)]
fn delete_beats_future_clock_edit_until_restore_sees_every_delete_and_purge_is_terminal() {
    let directory = TestDir::new();
    let path = directory.path("lifecycle.sqlite3");
    persist_test_vault(&path);
    let (a, _pa) = open_human(
        &path,
        [0x11; 16],
        Arc::new(AuditDeviceCustody::generate().unwrap()),
    );
    let (b, _pb) = open_human(
        &path,
        [0x22; 16],
        Arc::new(AuditDeviceCustody::generate().unwrap()),
    );
    let (c, _pc) = open_human(
        &path,
        [0x33; 16],
        Arc::new(AuditDeviceCustody::generate().unwrap()),
    );
    let rev_a = a
        .sign_causal_event(&revision_draft([1; 16], [0xa1; 16], 1))
        .unwrap();
    let edit_b = b
        .sign_causal_event(&revision_draft([2; 16], [0xb2; 16], 9_000_000_000_000_000))
        .unwrap();
    let trash_1 = c
        .sign_causal_event(
            &CausalEventDraft::new(
                [3; 16],
                1,
                1,
                None,
                vec![],
                CausalEventKind::Trash,
                ITEM,
                1,
                CausalEventBody::Lifecycle {
                    deletions_seen: vec![],
                },
            )
            .unwrap(),
        )
        .unwrap();
    let mut reducer = CausalReducer::open(&path).unwrap();
    let trashed = reducer
        .apply(&[rev_a.clone(), edit_b.clone(), trash_1.clone()])
        .unwrap();
    assert_eq!(
        trashed.item(&ITEM).unwrap().lifecycle(),
        ItemLifecycle::Trash
    );
    assert_eq!(
        trashed.item(&ITEM).unwrap().visible_revision(),
        Some(&[0xb2; 16])
    );

    let mut restore_parents = vec![rev_a.digest(), edit_b.digest(), trash_1.digest()];
    restore_parents.sort_unstable();
    let restore_1 = a
        .sign_causal_event(
            &CausalEventDraft::new(
                [4; 16],
                1,
                2,
                Some(rev_a.digest()),
                restore_parents,
                CausalEventKind::Restore,
                ITEM,
                1,
                CausalEventBody::Lifecycle {
                    deletions_seen: vec![trash_1.digest()],
                },
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        reducer
            .apply(std::slice::from_ref(&restore_1))
            .unwrap()
            .item(&ITEM)
            .unwrap()
            .lifecycle(),
        ItemLifecycle::Active
    );
    let mut trash2_parents = vec![trash_1.digest(), restore_1.digest()];
    trash2_parents.sort_unstable();
    let trash_2 = c
        .sign_causal_event(
            &CausalEventDraft::new(
                [5; 16],
                1,
                2,
                Some(trash_1.digest()),
                trash2_parents,
                CausalEventKind::Trash,
                ITEM,
                1,
                CausalEventBody::Lifecycle {
                    deletions_seen: vec![],
                },
            )
            .unwrap(),
        )
        .unwrap();
    let incomplete = a
        .sign_causal_event(
            &CausalEventDraft::new(
                [6; 16],
                1,
                3,
                Some(restore_1.digest()),
                vec![restore_1.digest()],
                CausalEventKind::Restore,
                ITEM,
                1,
                CausalEventBody::Lifecycle {
                    deletions_seen: vec![trash_1.digest()],
                },
            )
            .unwrap(),
        )
        .unwrap();
    let again = reducer
        .apply(&[trash_2.clone(), incomplete.clone()])
        .unwrap();
    assert_eq!(again.item(&ITEM).unwrap().lifecycle(), ItemLifecycle::Trash);
    let mut full_parents = vec![incomplete.digest(), trash_2.digest()];
    full_parents.sort_unstable();
    let mut deletions = vec![trash_1.digest(), trash_2.digest()];
    deletions.sort_unstable();
    let full = a
        .sign_causal_event(
            &CausalEventDraft::new(
                [7; 16],
                1,
                4,
                Some(incomplete.digest()),
                full_parents,
                CausalEventKind::Restore,
                ITEM,
                1,
                CausalEventBody::Lifecycle {
                    deletions_seen: deletions,
                },
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        reducer
            .apply(std::slice::from_ref(&full))
            .unwrap()
            .item(&ITEM)
            .unwrap()
            .lifecycle(),
        ItemLifecycle::Active
    );
    let purge_old = a
        .sign_causal_event(
            &CausalEventDraft::new(
                [0x09; 16],
                1,
                5,
                Some(full.digest()),
                vec![full.digest()],
                CausalEventKind::PurgeRevisions,
                ITEM,
                1,
                CausalEventBody::Purge {
                    revision_ids: vec![[0xa1; 16]],
                },
            )
            .unwrap(),
        )
        .unwrap();
    let compacted = reducer.apply(std::slice::from_ref(&purge_old)).unwrap();
    assert_eq!(compacted.item(&ITEM).unwrap().history(), &[[0xb2; 16]]);
    let purge_winner = a
        .sign_causal_event(
            &CausalEventDraft::new(
                [0x0a; 16],
                1,
                6,
                Some(purge_old.digest()),
                vec![purge_old.digest()],
                CausalEventKind::PurgeRevisions,
                ITEM,
                1,
                CausalEventBody::Purge {
                    revision_ids: vec![[0xb2; 16]],
                },
            )
            .unwrap(),
        )
        .unwrap();
    let protected = reducer.apply(std::slice::from_ref(&purge_winner)).unwrap();
    assert!(!protected.event_active(&purge_winner.digest()));
    assert_eq!(
        protected.item(&ITEM).unwrap().visible_revision(),
        Some(&[0xb2; 16])
    );
    let purge = c
        .sign_causal_event(
            &CausalEventDraft::new(
                [8; 16],
                1,
                3,
                Some(trash_2.digest()),
                vec![trash_2.digest()],
                CausalEventKind::PurgeItem,
                ITEM,
                1,
                CausalEventBody::Purge {
                    revision_ids: vec![],
                },
            )
            .unwrap(),
        )
        .unwrap();
    let purged = reducer.apply(&[purge.clone(), restore_1.clone()]).unwrap();
    assert_eq!(
        purged.item(&ITEM).unwrap().lifecycle(),
        ItemLifecycle::Purged
    );
    assert_eq!(purged.retained_header_count(), 10);
}

#[test]
fn altered_batch_is_rejected_atomically_and_checkpoint_is_only_a_verified_cache() {
    let directory = TestDir::new();
    let path = directory.path("atomic.sqlite3");
    persist_test_vault(&path);
    let (human, _peer) = open_human(
        &path,
        [0x44; 16],
        Arc::new(AuditDeviceCustody::generate().unwrap()),
    );
    let revision = human
        .sign_causal_event(&revision_draft([0x10; 16], [0x20; 16], 10))
        .unwrap();
    let mut wire = revision.to_bytes();
    *wire.last_mut().unwrap() ^= 1;
    let altered = SignedCausalEvent::from_bytes(&wire).unwrap();
    let mut reducer = CausalReducer::open(&path).unwrap();
    assert!(matches!(
        reducer.apply(&vec![revision.clone(); 257]),
        Err(pm_vault::ReductionError::ResourceLimit)
    ));
    assert_eq!(reducer.view().unwrap().retained_header_count(), 0);
    assert!(reducer.apply(&[revision.clone(), altered]).is_err());
    assert_eq!(reducer.view().unwrap().retained_header_count(), 0);
    let before = reducer.apply(std::slice::from_ref(&revision)).unwrap();
    let checkpoint = human
        .sign_causal_event(
            &CausalEventDraft::new(
                [0x11; 16],
                1,
                2,
                Some(revision.digest()),
                vec![revision.digest()],
                CausalEventKind::CheckpointCache,
                [0x55; 16],
                1,
                CausalEventBody::Checkpoint {
                    covered_heads: vec![revision.digest()],
                    state_digest: *before.digest(),
                    index_parts: vec![],
                },
            )
            .unwrap(),
        )
        .unwrap();
    let after = reducer.apply(std::slice::from_ref(&checkpoint)).unwrap();
    assert_eq!(before.digest(), after.digest());
    assert!(after.event_active(&checkpoint.digest()));
    assert_eq!(after.retained_header_count(), 2);
    let omitted = human
        .sign_causal_event(
            &CausalEventDraft::new(
                [0x12; 16],
                1,
                3,
                Some(checkpoint.digest()),
                vec![checkpoint.digest()],
                CausalEventKind::CheckpointCache,
                [0x55; 16],
                1,
                CausalEventBody::Checkpoint {
                    covered_heads: vec![revision.digest()],
                    state_digest: [0xff; 32],
                    index_parts: vec![],
                },
            )
            .unwrap(),
        )
        .unwrap();
    let rejected_cache = reducer.apply(std::slice::from_ref(&omitted)).unwrap();
    assert!(!rejected_cache.event_active(&omitted.digest()));
    assert_eq!(rejected_cache.digest(), before.digest());
    drop(reducer);
    let restarted = CausalReducer::open(&path).unwrap().view().unwrap();
    assert_eq!(restarted.digest(), before.digest());
    assert_eq!(restarted.retained_header_count(), 3);
}

#[test]
#[allow(clippy::many_single_char_names, clippy::too_many_lines)]
fn crossed_retirements_are_monotonic_cuts_and_revocation_needs_causal_resume_not_time() {
    let directory = TestDir::new();
    let path = directory.path("authority.sqlite3");
    persist_test_vault(&path);
    let (a, _peer_a) = open_human(
        &path,
        [0xa0; 16],
        Arc::new(AuditDeviceCustody::generate().unwrap()),
    );
    let (b, _peer_b) = open_human(
        &path,
        [0xb0; 16],
        Arc::new(AuditDeviceCustody::generate().unwrap()),
    );
    let (c, _peer_c) = open_human(
        &path,
        [0xc0; 16],
        Arc::new(AuditDeviceCustody::generate().unwrap()),
    );
    let (d, _peer_d) = open_human(
        &path,
        [0xd0; 16],
        Arc::new(AuditDeviceCustody::generate().unwrap()),
    );
    let (e, _peer_e) = open_human(
        &path,
        [0xe0; 16],
        Arc::new(AuditDeviceCustody::generate().unwrap()),
    );
    let retire_a = b
        .sign_causal_event(
            &CausalEventDraft::new(
                [0x31; 16],
                1,
                1,
                None,
                vec![],
                CausalEventKind::DeviceRetire,
                [0xa0; 16],
                1,
                CausalEventBody::Retire {
                    accepted_prefixes: vec![],
                },
            )
            .unwrap(),
        )
        .unwrap();
    let retire_b = a
        .sign_causal_event(
            &CausalEventDraft::new(
                [0x32; 16],
                1,
                1,
                None,
                vec![],
                CausalEventKind::DeviceRetire,
                [0xb0; 16],
                1,
                CausalEventBody::Retire {
                    accepted_prefixes: vec![],
                },
            )
            .unwrap(),
        )
        .unwrap();
    let suspend = c
        .sign_causal_event(
            &CausalEventDraft::new(
                [0x33; 16],
                1,
                1,
                None,
                vec![],
                CausalEventKind::Suspend,
                [0xf0; 16],
                1,
                CausalEventBody::Reason,
            )
            .unwrap(),
        )
        .unwrap();
    let resume = c
        .sign_causal_event(
            &CausalEventDraft::new(
                [0x34; 16],
                1,
                2,
                Some(suspend.digest()),
                vec![suspend.digest()],
                CausalEventKind::Resume,
                [0xf0; 16],
                1,
                CausalEventBody::Positive {
                    prior_positive_events: vec![],
                    withdrawals_seen: vec![suspend.digest()],
                },
            )
            .unwrap(),
        )
        .unwrap();
    let revision = c
        .sign_causal_event(
            &CausalEventDraft::new(
                [0x35; 16],
                1,
                3,
                Some(resume.digest()),
                vec![resume.digest()],
                CausalEventKind::ItemRevision,
                ITEM,
                1,
                revision_body([0x35; 16], 35),
            )
            .unwrap(),
        )
        .unwrap();
    let mut cut_parents = vec![retire_b.digest(), revision.digest()];
    cut_parents.sort_unstable();
    let cut = a
        .sign_causal_event(
            &CausalEventDraft::new(
                [0x36; 16],
                1,
                2,
                Some(retire_b.digest()),
                cut_parents,
                CausalEventKind::DeviceRetire,
                [0xc0; 16],
                1,
                CausalEventBody::Retire {
                    accepted_prefixes: vec![pm_vault::AcceptedPrefix {
                        generation: 1,
                        seq: 3,
                        tip_digest: revision.digest(),
                    }],
                },
            )
            .unwrap(),
        )
        .unwrap();
    let future = c
        .sign_causal_event(
            &CausalEventDraft::new(
                [0x37; 16],
                1,
                4,
                Some(revision.digest()),
                vec![revision.digest()],
                CausalEventKind::ItemRevision,
                ITEM,
                1,
                revision_body([0x37; 16], i64::MAX),
            )
            .unwrap(),
        )
        .unwrap();
    let agent = [0x9a; 16];
    let grant_before = d
        .sign_causal_event(
            &CausalEventDraft::new(
                [0x41; 16],
                1,
                1,
                None,
                vec![],
                CausalEventKind::AgentGrant,
                agent,
                1,
                CausalEventBody::Positive {
                    prior_positive_events: vec![],
                    withdrawals_seen: vec![],
                },
            )
            .unwrap(),
        )
        .unwrap();
    let revoke = e
        .sign_causal_event(
            &CausalEventDraft::new(
                [0x42; 16],
                1,
                1,
                None,
                vec![],
                CausalEventKind::AgentRevoke,
                agent,
                1,
                CausalEventBody::Reason,
            )
            .unwrap(),
        )
        .unwrap();
    let mut grant_parents = vec![grant_before.digest(), revoke.digest(), suspend.digest()];
    grant_parents.sort_unstable();
    let grant_after = d
        .sign_causal_event(
            &CausalEventDraft::new(
                [0x43; 16],
                1,
                2,
                Some(grant_before.digest()),
                grant_parents,
                CausalEventKind::AgentGrant,
                agent,
                2,
                CausalEventBody::Positive {
                    prior_positive_events: vec![grant_before.digest()],
                    withdrawals_seen: {
                        let mut seen = vec![revoke.digest(), suspend.digest()];
                        seen.sort_unstable();
                        seen
                    },
                },
            )
            .unwrap(),
        )
        .unwrap();

    let mut reducer = CausalReducer::open(&path).unwrap();
    let view = reducer
        .apply(&[
            future.clone(),
            retire_a.clone(),
            grant_after.clone(),
            revision.clone(),
            retire_b.clone(),
            resume.clone(),
            grant_before.clone(),
            revoke.clone(),
            cut.clone(),
            suspend.clone(),
        ])
        .unwrap();
    assert!(view.event_active(&retire_a.digest()) && view.event_active(&retire_b.digest()));
    assert!(
        view.device_retired(&[0xa0; 16])
            && view.device_retired(&[0xb0; 16])
            && view.device_retired(&[0xc0; 16])
    );
    assert!(view.event_active(&revision.digest()));
    assert!(!view.event_active(&future.digest()));
    assert!(!view.event_active(&grant_before.digest()));
    assert!(view.event_active(&revoke.digest()));
    assert!(view.event_active(&grant_after.digest()));
    assert!(view.event_active(&resume.digest()));
    assert!(!view.agent_authorized(&agent, 1));
    assert!(view.agent_authorized(&agent, 2));
    assert!(view.delegated_resumed());
}

fn revision_draft(event_id: [u8; 16], revision_id: [u8; 16], modified_at: i64) -> CausalEventDraft {
    CausalEventDraft::new(
        event_id,
        1,
        1,
        None,
        Vec::new(),
        CausalEventKind::ItemRevision,
        ITEM,
        1,
        revision_body(revision_id, modified_at),
    )
    .unwrap()
}

fn revision_body(revision_id: [u8; 16], modified_at: i64) -> CausalEventBody {
    CausalEventBody::Revision {
        revision_id,
        modified_at,
        manifest_digest: [0x55; 32],
        previous_revisions: Vec::new(),
    }
}

fn open_human(
    path: &Path,
    device: [u8; 16],
    custody: Arc<AuditDeviceCustody>,
) -> (HumanVault, UnixStream) {
    let (server, peer) = UnixStream::pair().unwrap();
    let channel = HumanChannel::authenticate(server, unsafe { libc::geteuid() }).unwrap();
    (
        HumanVault::unlock_with_audit_custody(path, MASTER, device, channel, custody).unwrap(),
        peer,
    )
}

fn persist_test_vault(path: &Path) {
    let pending = PendingVault::new(MASTER, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    let recovery = pending.recovery_code().to_string().parse().unwrap();
    pending.persist(path, &recovery).unwrap();
}

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "pm-ticket-16-{}-{}",
            process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self, file: &str) -> PathBuf {
        self.0.join(file)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
