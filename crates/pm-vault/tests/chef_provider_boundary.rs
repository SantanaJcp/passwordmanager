// SPDX-License-Identifier: AGPL-3.0-only
#![cfg(target_os = "linux")]

use pm_crypto::{KdfProfile, ProtectedBytes};
use pm_vault::{
    AgentEnrollment, AgentPeer, AttemptError, AttemptOutcome, AttemptState, AttemptVault,
    AuditDeviceCustody, AuthorizationReason, DelegatedVault, HumanChannel, HumanVault,
    HumanVerification, IdempotencyKey, LogicalRecord, PasskeyProvider, PasskeyRequest,
    PasskeyStatus, PendingVault, RecordKind, StartAttempt, UserVerificationRequirement,
};
use std::{
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

const MASTER: &[u8] = b"synthetic chef provider boundary master";
const DEVICE: [u8; 16] = [0x73; 16];
const AGENT: [u8; 16] = [0xa1; 16];
const RPK: [u8; 44] = [0x41; 44];
const ORIGIN: &str = "https://passkey.test";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    path: PathBuf,
    custody: Arc<AuditDeviceCustody>,
    human: HumanVault,
    _channel: UnixStream,
    attempts: AttemptVault,
    peer: AgentPeer,
    item: [u8; 16],
}
impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "chef-provider-{}-{}-{}",
            std::process::id(),
            now(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("vault.sqlite3");
        let pending = PendingVault::new(MASTER, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
        let recovery = pending.recovery_code().to_string().parse().unwrap();
        pending.persist(&path, &recovery).unwrap();
        let custody = Arc::new(AuditDeviceCustody::generate().unwrap());
        let (mut human, channel) = open_human(&path, Arc::clone(&custody));
        let enrollment = AgentEnrollment::new(
            AGENT,
            [0x31; 16],
            &RPK,
            "Synthetic chef agent",
            "synthetic-boundary",
        )
        .unwrap();
        let p = human.prepare_agent_enrollment(&enrollment).unwrap();
        commit(&mut human, p.prepared());
        let p = human.prepare_delegated_resume().unwrap();
        commit(&mut human, &p);
        let p = human.prepare_create_record(&exchange_record()).unwrap();
        let item = *p.item_id();
        commit(&mut human, &p);
        let p = human.prepare_enable(item).unwrap();
        commit(&mut human, &p);
        let attempts =
            AttemptVault::open(DelegatedVault::open(&path, DEVICE, Arc::clone(&custody)).unwrap())
                .unwrap();
        Self {
            path,
            custody,
            human,
            _channel: channel,
            attempts,
            peer: AgentPeer::from_transport_rpk(&RPK).unwrap(),
            item,
        }
    }
    fn start(&self, nonce: u8) -> pm_vault::AttemptSnapshot {
        self.attempts
            .start(
                &self.peer,
                &StartAttempt::new(
                    self.item,
                    "keycloak-token-exchange",
                    1,
                    "token_exchange",
                    "keycloak-exchange-lab",
                    b"keycloak-exchange-lab".to_vec(),
                    IdempotencyKey::new(now(), [nonce; 16]).unwrap(),
                )
                .unwrap(),
            )
            .unwrap()
    }
}
// Retain the small synthetic databases on panic and success for diagnosis.
fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}
fn open_human(path: &Path, custody: Arc<AuditDeviceCustody>) -> (HumanVault, UnixStream) {
    let (server, peer) = UnixStream::pair().unwrap();
    let channel = HumanChannel::authenticate(server, unsafe { libc::geteuid() }).unwrap();
    (
        HumanVault::unlock(path, MASTER, DEVICE, channel, custody).unwrap(),
        peer,
    )
}
fn commit(human: &mut HumanVault, p: &pm_vault::PreparedHumanCommand) {
    let s = human.sign(p).unwrap();
    human.commit(p.command(), &s, p.body()).unwrap();
}

fn exchange_record() -> LogicalRecord {
    use pm_vault::{AuthRecord, Destination, HumanMetadata};
    LogicalRecord::new(
        RecordKind::Token,
        HumanMetadata {
            title: "Synthetic Keycloak exchange relationship".to_owned(),
            destinations: vec![Destination {
                label: "installed profile".to_owned(),
                value: "keycloak-exchange-lab".to_owned(),
            }],
            tags: Vec::new(),
            favorite: false,
            notes: pm_crypto::ProtectedText::copy_from_str("").expect("synthetic protected notes"),
            fields: Vec::new(),
            source_fields: Vec::new(),
        },
        vec![AuthRecord::TokenExchange {
            subject_token: pm_crypto::ProtectedBytes::copy_from_slice(
                b"synthetic-subject-token-A-canary",
            )
            .expect("synthetic protected field"),
            requester_client_id: "pm-exchanger".to_owned(),
            requester_client_secret: pm_crypto::ProtectedBytes::copy_from_slice(
                b"synthetic-requester-secret-canary",
            )
            .expect("synthetic protected field"),
            provider: "keycloak".to_owned(),
            profile_id: "keycloak-exchange-lab".to_owned(),
            destination_refs: vec![0],
            expires_at: None,
        }],
        Vec::new(),
    )
    .unwrap()
}

#[test]
#[allow(clippy::too_many_lines)]
fn ordinary_claimant_leaves_intrinsic_created_and_waiting_for_the_human_provider() {
    let mut f = Fixture::new();
    let provider = PasskeyProvider::open(
        AttemptVault::open(DelegatedVault::open(&f.path, DEVICE, Arc::clone(&f.custody)).unwrap())
            .unwrap(),
    )
    .unwrap();
    let create = PasskeyRequest::registration(
        [0x51; 16],
        "synthetic-register",
        ORIGIN,
        "passkey.test",
        &[0x52; 32],
        b"synthetic-user",
        "alice",
        "Alice",
        UserVerificationRequirement::Required,
    )
    .unwrap();
    provider.begin(&create).unwrap();
    let p = f.human.prepare_passkey_registration(&create).unwrap();
    let public = p.public().clone();
    let item = *p.prepared().item_id();
    commit(&mut f.human, p.prepared());
    provider
        .complete_registration(
            &f.human,
            *create.request_id(),
            item,
            &public,
            HumanVerification::Verified,
        )
        .unwrap();
    let p = f.human.prepare_enable(item).unwrap();
    commit(&mut f.human, &p);
    let intrinsic = f
        .attempts
        .start(
            &f.peer,
            &StartAttempt::new(
                item,
                "vault-webauthn-provider",
                1,
                "webauthn",
                ORIGIN,
                b"keycloak-webauthn/1".to_vec(),
                IdempotencyKey::new(now(), [0x53; 16]).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    let ordinary = f.start(0x54);
    let lease = f.attempts.claim_next().unwrap().unwrap();
    assert_eq!(
        lease.attempt_id(),
        ordinary.attempt_id(),
        "intrinsic attempt must never be leased to an adapter"
    );
    assert_eq!(
        f.attempts
            .get(&f.peer, *intrinsic.attempt_id())
            .unwrap()
            .state(),
        AttemptState::Created
    );
    f.attempts
        .settle(
            &lease,
            AttemptOutcome::WaitingForHuman {
                challenge: ProtectedBytes::copy_from_slice(b"synthetic-challenge").unwrap(),
            },
        )
        .unwrap();
    let get = PasskeyRequest::assertion(
        [0x55; 16],
        *intrinsic.attempt_id(),
        "synthetic-get",
        ORIGIN,
        "passkey.test",
        &[0x56; 32],
        vec![public.credential_id().to_vec()],
        UserVerificationRequirement::Required,
    )
    .unwrap();
    assert!(matches!(
        provider.begin(&get).unwrap(),
        PasskeyStatus::Waiting(_)
    ));
    std::thread::sleep(std::time::Duration::from_millis(110));
    let reconciliation = f
        .attempts
        .claim_waiting_for_reconciliation()
        .unwrap()
        .unwrap();
    assert_eq!(reconciliation.attempt_id(), ordinary.attempt_id());
    assert!(reconciliation.reconciliation_only());
    assert!(
        f.attempts
            .claim_waiting_for_reconciliation()
            .unwrap()
            .is_none()
    );
    assert_eq!(
        f.attempts
            .get(&f.peer, *intrinsic.attempt_id())
            .unwrap()
            .state(),
        AttemptState::WaitingForHuman
    );
    provider
        .confirm_assertion(&f.human, *get.request_id(), HumanVerification::Verified)
        .unwrap();
    assert_eq!(
        f.attempts
            .get(&f.peer, *intrinsic.attempt_id())
            .unwrap()
            .state(),
        AttemptState::Succeeded
    );
}

#[test]
fn expired_running_lease_cannot_emit_even_without_a_status_poll() {
    let f = Fixture::new();
    let created = f.start(0x61);
    let lease = f.attempts.claim_next().unwrap().unwrap();
    rusqlite::Connection::open(&f.path)
        .unwrap()
        .execute(
            "UPDATE authentication_attempts SET expires_at_us=0 WHERE attempt_id=?1",
            [created.attempt_id().as_slice()],
        )
        .unwrap();
    let calls = std::cell::Cell::new(0);
    let denied = f
        .attempts
        .with_authorized_provider_use(&lease, || calls.set(calls.get() + 1));
    assert!(
        denied.is_err(),
        "expired lease emitted without polling status"
    );
    assert_eq!(calls.get(), 0);
}

#[test]
fn authority_withdrawals_before_emission_make_zero_calls() {
    for withdrawal in ["suspend", "revoke", "disable"] {
        let mut f = Fixture::new();
        f.start(0x62);
        let lease = f.attempts.claim_next().unwrap().unwrap();
        let p = match withdrawal {
            "suspend" => f
                .human
                .prepare_delegated_suspend(AuthorizationReason::OwnerRequest)
                .unwrap(),
            "revoke" => f
                .human
                .prepare_agent_revocation(AGENT, AuthorizationReason::OwnerRequest)
                .unwrap(),
            "disable" => f.human.prepare_disable(f.item).unwrap(),
            _ => unreachable!(),
        };
        commit(&mut f.human, &p);
        let calls = std::cell::Cell::new(0);
        assert!(
            f.attempts
                .with_authorized_provider_use(&lease, || calls.set(calls.get() + 1))
                .is_err(),
            "{withdrawal}"
        );
        assert_eq!(calls.get(), 0);
    }
}

#[test]
fn emitted_request_can_cancel_and_late_success_cannot_overwrite_it() {
    let f = Fixture::new();
    let created = f.start(0x63);
    let lease = f.attempts.claim_next().unwrap().unwrap();
    let calls = std::cell::Cell::new(0);
    f.attempts
        .with_authorized_provider_use(&lease, || calls.set(calls.get() + 1))
        .unwrap();
    assert_eq!(
        f.attempts
            .cancel(&f.peer, *created.attempt_id())
            .unwrap()
            .state(),
        AttemptState::Cancelled
    );
    assert!(matches!(
        f.attempts.settle(
            &lease,
            AttemptOutcome::Succeeded {
                result: ProtectedBytes::copy_from_slice(b"late synthetic success").unwrap()
            }
        ),
        Err(AttemptError::NotFound)
    ));
    assert_eq!(
        f.attempts
            .get(&f.peer, *created.attempt_id())
            .unwrap()
            .state(),
        AttemptState::Cancelled
    );
    assert_eq!(f.attempts.recover_inflight().unwrap(), 0);
    assert_eq!(calls.get(), 1);
}

#[test]
fn recovered_unknown_request_is_reconciliation_only_and_stale_token_cannot_emit() {
    let f = Fixture::new();
    let created = f.start(0x64);
    let stale = f.attempts.claim_next().unwrap().unwrap();
    let calls = std::cell::Cell::new(0);
    f.attempts
        .with_authorized_provider_use(&stale, || calls.set(calls.get() + 1))
        .unwrap();
    let reopened =
        AttemptVault::open(DelegatedVault::open(&f.path, DEVICE, Arc::clone(&f.custody)).unwrap())
            .unwrap();
    assert_eq!(reopened.recover_inflight().unwrap(), 1);
    assert!(reopened.claim_next().unwrap().is_none());
    std::thread::sleep(std::time::Duration::from_millis(110));
    let lease = reopened
        .claim_waiting_for_reconciliation()
        .unwrap()
        .unwrap();
    assert!(lease.reconciliation_only());
    assert_eq!(lease.attempt_id(), created.attempt_id());
    assert!(
        reopened
            .with_authorized_provider_use(&stale, || calls.set(calls.get() + 1))
            .is_err()
    );
    reopened
        .settle(&lease, AttemptOutcome::Indeterminate)
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(
        reopened
            .get(&f.peer, *created.attempt_id())
            .unwrap()
            .state(),
        AttemptState::Indeterminate
    );
}

#[test]
fn emission_guard_serializes_a_competing_withdrawal_but_releases_before_result_wait() {
    let f = Fixture::new();
    f.start(0x65);
    let lease = f.attempts.claim_next().unwrap().unwrap();
    let competitor = rusqlite::Connection::open(&f.path).unwrap();
    competitor.busy_timeout(std::time::Duration::ZERO).unwrap();
    let calls = std::cell::Cell::new(0);
    f.attempts
        .with_authorized_provider_use(&lease, || {
            // This would succeed if authorization were committed before the send.
            let error = competitor.execute_batch("BEGIN IMMEDIATE").unwrap_err();
            assert_eq!(
                error.sqlite_error_code(),
                Some(rusqlite::ErrorCode::DatabaseBusy)
            );
            calls.set(calls.get() + 1);
        })
        .unwrap();
    competitor
        .execute_batch("BEGIN IMMEDIATE; ROLLBACK")
        .unwrap();
    assert_eq!(calls.get(), 1);
}

#[test]
fn claim_audit_failure_rolls_back_before_any_provider_can_receive_a_lease() {
    let f = Fixture::new();
    let created = f.start(0x66);
    let c = rusqlite::Connection::open(&f.path).unwrap();
    c.execute_batch("CREATE TRIGGER synthetic_fail_claim_audit BEFORE INSERT ON encrypted_audit_records BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END;").unwrap();
    assert!(f.attempts.claim_next().is_err());
    let state: String = c
        .query_row(
            "SELECT state FROM authentication_attempts WHERE attempt_id=?1",
            [created.attempt_id().as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(state, "created");
    c.execute_batch("DROP TRIGGER synthetic_fail_claim_audit")
        .unwrap();
    assert_eq!(
        f.attempts.claim_next().unwrap().unwrap().attempt_id(),
        created.attempt_id()
    );
}

#[test]
fn claim_commit_failure_rolls_back_before_a_provider_receives_a_lease() {
    let f = Fixture::new();
    let created = f.start(0x67);
    let c = rusqlite::Connection::open(&f.path).unwrap();
    c.execute_batch("CREATE TABLE synthetic_parent(id INTEGER PRIMARY KEY);
        CREATE TABLE synthetic_child(id INTEGER REFERENCES synthetic_parent(id) DEFERRABLE INITIALLY DEFERRED);
        CREATE TRIGGER synthetic_fail_claim_commit AFTER INSERT ON encrypted_audit_records BEGIN INSERT INTO synthetic_child VALUES(1); END;").unwrap();
    let Err(AttemptError::Storage(error)) = f.attempts.claim_next() else {
        panic!("claim must fail its durable commit before returning a lease");
    };
    assert_eq!(
        error.sqlite_error_code(),
        Some(rusqlite::ErrorCode::ConstraintViolation)
    );
    let state: String = c
        .query_row(
            "SELECT state FROM authentication_attempts WHERE attempt_id=?1",
            [created.attempt_id().as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(state, "created");
    let children: i64 = c
        .query_row("SELECT count(*) FROM synthetic_child", [], |r| r.get(0))
        .unwrap();
    assert_eq!(children, 0);
    c.execute_batch("DROP TRIGGER synthetic_fail_claim_commit")
        .unwrap();
    assert_eq!(
        f.attempts.claim_next().unwrap().unwrap().attempt_id(),
        created.attempt_id()
    );
}

#[test]
fn ordinary_attempts_preserve_the_128_custodian_admission_bound() {
    let mut f = Fixture::new();
    let mut peers = vec![AgentPeer::from_transport_rpk(&RPK).unwrap()];
    for n in 0x80..=0x87 {
        let rpk = [n; 44];
        let enrollment = AgentEnrollment::new(
            [n; 16],
            [n; 16],
            &rpk,
            "Synthetic bound agent",
            "synthetic-boundary",
        )
        .unwrap();
        let p = f.human.prepare_agent_enrollment(&enrollment).unwrap();
        commit(&mut f.human, p.prepared());
        peers.push(AgentPeer::from_transport_rpk(&rpk).unwrap());
    }
    let request = |nonce| {
        StartAttempt::new(
            f.item,
            "keycloak-token-exchange",
            1,
            "token_exchange",
            "keycloak-exchange-lab",
            b"keycloak-exchange-lab".to_vec(),
            IdempotencyKey::new(now(), [nonce; 16]).unwrap(),
        )
        .unwrap()
    };
    for peer in peers.iter().take(8) {
        for nonce in 1..=16 {
            assert_eq!(
                f.attempts.start(peer, &request(nonce)).unwrap().state(),
                AttemptState::Created
            );
        }
        assert!(matches!(
            f.attempts.start(peer, &request(17)),
            Err(AttemptError::RateLimited)
        ));
    }
    assert!(matches!(
        f.attempts.start(&peers[8], &request(1)),
        Err(AttemptError::RateLimited)
    ));
    let count: i64 = rusqlite::Connection::open(&f.path)
        .unwrap()
        .query_row("SELECT count(*) FROM authentication_attempts", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 128);
    assert!(f.attempts.claim_next().unwrap().is_some());
}

#[test]
fn r2_enabled_organization_edit_preserves_new_ordinary_uses() {
    let mut f = Fixture::new();
    let before = f.start(0x71);
    f.attempts.cancel(&f.peer, *before.attempt_id()).unwrap();
    let p = f
        .human
        .prepare_organize(f.item, vec!["synthetic-r2".into()], true)
        .unwrap();
    let receipt = f
        .human
        .commit(p.command(), &f.human.sign(&p).unwrap(), p.body())
        .unwrap();
    assert_eq!(f.human.receipt(*p.transaction_id()).unwrap(), receipt);
    let started = f.start(0x72);
    let lease = f.attempts.claim_next().unwrap().unwrap();
    let calls = std::cell::Cell::new(0);
    let emitted = f
        .attempts
        .with_authorized_provider_use(&lease, || calls.set(calls.get() + 1));
    assert!(
        emitted.is_ok(),
        "F1: ordinary edit denied new emission: {emitted:?}"
    );
    assert_ne!(
        started.revision_id(),
        before.revision_id(),
        "new starts must pin the new enabled revision"
    );
    assert_eq!(calls.get(), 1);
    let c = rusqlite::Connection::open(&f.path).unwrap();
    let revisions:(Vec<u8>,Vec<u8>)=c.query_row("SELECT visible_revision,revision_id FROM vault_items JOIN credential_authorizations USING(item_id) WHERE item_id=?1",[f.item.as_slice()],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
    assert_eq!(revisions.0, revisions.1);
}

#[test]
fn r2_edited_unknown_uses_pinned_query_without_new_auth_material() {
    let mut f = Fixture::new();
    let original = f.start(0x73);
    let lease = f.attempts.claim_next().unwrap().unwrap();
    f.attempts
        .with_authorized_provider_use(&lease, || ())
        .unwrap();
    f.attempts
        .settle(&lease, AttemptOutcome::Indeterminate)
        .unwrap();
    let p = f.human.prepare_organize(f.item, vec![], true).unwrap();
    commit(&mut f.human, &p);
    std::thread::sleep(std::time::Duration::from_millis(110));
    let query = f
        .attempts
        .claim_waiting_for_reconciliation()
        .unwrap()
        .unwrap();
    assert!(query.reconciliation_only());
    assert_eq!(query.revision_id(), original.revision_id());
    assert!(query.password().is_empty());
    assert!(query.subject_token().is_none());
    let calls = std::cell::Cell::new(0);
    let issued = f
        .attempts
        .with_authorized_provider_use(&query, || calls.set(calls.get() + 1));
    assert!(
        issued.is_ok(),
        "F2: legitimate query denied after normal edit: {issued:?}"
    );
    assert_eq!(calls.get(), 1);
}

#[test]
fn r2_new_start_after_material_rotation_uses_new_material() {
    use pm_vault::{AuthRecord, Destination, HumanMetadata};
    let mut f = Fixture::new();
    let pinned = f.start(0x70);
    let previous_lease = f.attempts.claim_next().unwrap().unwrap();
    // Construct the new complete record through the public content API.
    let updated = LogicalRecord::new(
        RecordKind::Token,
        HumanMetadata {
            title: "Synthetic rotated exchange".into(),
            destinations: vec![Destination {
                label: "installed profile".into(),
                value: "keycloak-exchange-lab".into(),
            }],
            tags: vec![],
            favorite: false,
            notes: pm_crypto::ProtectedText::copy_from_str("").unwrap(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![AuthRecord::TokenExchange {
            subject_token: ProtectedBytes::copy_from_slice(b"synthetic-r2-new-subject").unwrap(),
            requester_client_id: "pm-exchanger".into(),
            requester_client_secret: ProtectedBytes::copy_from_slice(b"synthetic-r2-new-requester")
                .unwrap(),
            provider: "keycloak".into(),
            profile_id: "keycloak-exchange-lab".into(),
            destination_refs: vec![0],
            expires_at: None,
        }],
        vec![],
    )
    .unwrap();
    let p = f.human.prepare_edit_record(f.item, &updated).unwrap();
    commit(&mut f.human, &p);
    f.start(0x74);
    let lease = f.attempts.claim_next().unwrap().unwrap();
    assert_eq!(lease.password(), b"synthetic-r2-new-requester");
    assert_eq!(
        lease.subject_token(),
        Some(b"synthetic-r2-new-subject".as_slice())
    );
    f.attempts
        .with_authorized_provider_use(&lease, || ())
        .unwrap();
    let delegated = DelegatedVault::open(&f.path, DEVICE, Arc::clone(&f.custody)).unwrap();
    let found = delegated.discover(&f.peer).unwrap();
    assert_eq!(found[0].title(), "Synthetic rotated exchange");
    assert_eq!(found[0].revision_id(), lease.revision_id());
    let overview = f.human.access_overview().unwrap();
    let visible = overview
        .credentials()
        .iter()
        .find(|entry| entry.item() == &f.item)
        .unwrap();
    assert!(visible.enabled());
    assert_eq!(visible.title(), "Synthetic rotated exchange");
    assert_eq!(previous_lease.revision_id(), pinned.revision_id());
    assert_eq!(
        previous_lease.password(),
        b"synthetic-requester-secret-canary"
    );
    f.attempts
        .with_authorized_provider_use(&previous_lease, || ())
        .unwrap();
}

#[test]
fn r2_materialized_pinned_lease_survives_organization_but_not_a_causal_withdrawal() {
    let mut f = Fixture::new();
    let started = f.start(0x75);
    let lease = f.attempts.claim_next().unwrap().unwrap();
    let p = f.human.prepare_organize(f.item, vec![], true).unwrap();
    commit(&mut f.human, &p);
    let calls = std::cell::Cell::new(0);
    f.attempts
        .with_authorized_provider_use(&lease, || calls.set(calls.get() + 1))
        .expect("a materialized valid attempt retains its pinned revision");
    assert_eq!(lease.revision_id(), started.revision_id());
    assert_eq!(calls.get(), 1);
    let p = f.human.prepare_disable(f.item).unwrap();
    commit(&mut f.human, &p);
    let p = f.human.prepare_enable(f.item).unwrap();
    commit(&mut f.human, &p);
    assert!(
        f.attempts
            .with_authorized_provider_use(&lease, || calls.set(calls.get() + 1))
            .is_err(),
        "enable must not resurrect a lease invalidated by disable"
    );
    assert_eq!(calls.get(), 1);
}

#[test]
fn r2_staged_enabled_edit_cannot_undo_a_later_withdrawal() {
    for withdrawal in ["disable", "suspend", "revoke", "trash"] {
        let mut f = Fixture::new();
        let edit = f.human.prepare_organize(f.item, vec![], true).unwrap();
        let signature = f.human.sign(&edit).unwrap();
        let p = match withdrawal {
            "disable" => f.human.prepare_disable(f.item).unwrap(),
            "suspend" => f
                .human
                .prepare_delegated_suspend(AuthorizationReason::OwnerRequest)
                .unwrap(),
            "revoke" => f
                .human
                .prepare_agent_revocation(AGENT, AuthorizationReason::OwnerRequest)
                .unwrap(),
            "trash" => f.human.prepare_delete(f.item).unwrap(),
            _ => unreachable!(),
        };
        commit(&mut f.human, &p);
        assert!(
            matches!(
                f.human.commit(edit.command(), &signature, edit.body()),
                Err(pm_vault::HumanCommitError::StateChanged)
            ),
            "{withdrawal}"
        );
        assert!(
            f.attempts
                .start(
                    &f.peer,
                    &StartAttempt::new(
                        f.item,
                        "keycloak-token-exchange",
                        1,
                        "token_exchange",
                        "keycloak-exchange-lab",
                        b"keycloak-exchange-lab".to_vec(),
                        IdempotencyKey::new(now(), [0x76; 16]).unwrap()
                    )
                    .unwrap()
                )
                .is_err(),
            "{withdrawal}"
        );
    }
}

#[test]
fn r2_failed_grant_publication_rolls_back_revision_receipt_and_authority() {
    let mut f = Fixture::new();
    let p = f.human.prepare_organize(f.item, vec![], true).unwrap();
    let signature = f.human.sign(&p).unwrap();
    let c = rusqlite::Connection::open(&f.path).unwrap();
    let state = || -> (Vec<u8>, Vec<u8>, i64, i64) {
        c.query_row("SELECT visible_revision,revision_id,(SELECT count(*) FROM authority_events),(SELECT count(*) FROM human_receipts) FROM vault_items JOIN credential_authorizations USING(item_id) WHERE item_id=?1",[f.item.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap()
    };
    let before = state();
    c.execute_batch("CREATE TRIGGER synthetic_r2_fail_publication BEFORE UPDATE ON credential_authorizations BEGIN SELECT RAISE(ABORT,'synthetic publication failure'); END;").unwrap();
    assert!(
        f.human.commit(p.command(), &signature, p.body()).is_err(),
        "edit must include provision in the same transaction"
    );
    assert_eq!(state(), before);
    assert!(f.human.receipt(*p.transaction_id()).is_err());
    c.execute_batch("DROP TRIGGER synthetic_r2_fail_publication")
        .unwrap();
    let receipt = f.human.commit(p.command(), &signature, p.body()).unwrap();
    assert_eq!(
        f.human.commit(p.command(), &signature, p.body()).unwrap(),
        receipt
    );
    let after = state();
    assert_eq!(after.0, after.1);
    assert_ne!(after.0, before.0);
    assert_eq!(after.2, before.2 + 2);
    assert_eq!(after.3, before.3 + 1);
}

#[test]
fn r2_tampered_content_staging_never_publishes_a_grant() {
    let mut f = Fixture::new();
    let p = f.human.prepare_organize(f.item, vec![], true).unwrap();
    let signature = f.human.sign(&p).unwrap();
    let c = rusqlite::Connection::open(&f.path).unwrap();
    let before: Vec<u8> = c
        .query_row(
            "SELECT grant FROM credential_authorizations WHERE item_id=?1",
            [f.item.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    c.execute(
        "UPDATE human_staging SET package=zeroblob(length(package)) WHERE transaction_id=?1",
        [p.transaction_id().as_slice()],
    )
    .unwrap();
    assert!(f.human.commit(p.command(), &signature, p.body()).is_err());
    let after: Vec<u8> = c
        .query_row(
            "SELECT grant FROM credential_authorizations WHERE item_id=?1",
            [f.item.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(before, after);
}

#[test]
fn r2_edit_of_disabled_item_does_not_publish_an_enable() {
    let mut f = Fixture::new();
    let p = f.human.prepare_disable(f.item).unwrap();
    commit(&mut f.human, &p);
    let c = rusqlite::Connection::open(&f.path).unwrap();
    let enables = || {
        c.query_row(
            "SELECT count(*) FROM authority_events WHERE kind='enable'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
    };
    let before = enables();
    let p = f.human.prepare_organize(f.item, vec![], true).unwrap();
    commit(&mut f.human, &p);
    assert_eq!(enables(), before);
    assert!(
        DelegatedVault::open(&f.path, DEVICE, Arc::clone(&f.custody))
            .unwrap()
            .discover(&f.peer)
            .unwrap()
            .is_empty()
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn r2_127_intrinsic_plus_one_ordinary_preserves_selection_and_16_128_bounds() {
    let mut f = Fixture::new();
    let provider = PasskeyProvider::open(
        AttemptVault::open(DelegatedVault::open(&f.path, DEVICE, Arc::clone(&f.custody)).unwrap())
            .unwrap(),
    )
    .unwrap();
    let create = PasskeyRequest::registration(
        [0x51; 16],
        "synthetic-register",
        ORIGIN,
        "passkey.test",
        &[0x52; 32],
        b"synthetic-user",
        "alice",
        "Alice",
        UserVerificationRequirement::Required,
    )
    .unwrap();
    provider.begin(&create).unwrap();
    let p = f.human.prepare_passkey_registration(&create).unwrap();
    let public = p.public().clone();
    let item = *p.prepared().item_id();
    commit(&mut f.human, p.prepared());
    provider
        .complete_registration(
            &f.human,
            *create.request_id(),
            item,
            &public,
            HumanVerification::Verified,
        )
        .unwrap();
    let p = f.human.prepare_enable(item).unwrap();
    commit(&mut f.human, &p);

    let mut peers = vec![AgentPeer::from_transport_rpk(&RPK).unwrap()];
    for n in 0x80..0x87 {
        let rpk = [n; 44];
        let enrollment = AgentEnrollment::new(
            [n; 16],
            [n; 16],
            &rpk,
            "Synthetic intrinsic-bound agent",
            "synthetic-boundary",
        )
        .unwrap();
        let p = f.human.prepare_agent_enrollment(&enrollment).unwrap();
        commit(&mut f.human, p.prepared());
        peers.push(AgentPeer::from_transport_rpk(&rpk).unwrap());
    }
    for (index, peer) in peers.iter().enumerate() {
        for nonce in 1..=if index == 7 { 15 } else { 16 } {
            f.attempts
                .start(
                    peer,
                    &StartAttempt::new(
                        item,
                        "vault-webauthn-provider",
                        1,
                        "webauthn",
                        ORIGIN,
                        b"keycloak-webauthn/1".to_vec(),
                        IdempotencyKey::new(now(), [nonce; 16]).unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap();
        }
    }
    let request = StartAttempt::new(
        f.item,
        "keycloak-token-exchange",
        1,
        "token_exchange",
        "keycloak-exchange-lab",
        b"keycloak-exchange-lab".to_vec(),
        IdempotencyKey::new(now(), [0x79; 16]).unwrap(),
    )
    .unwrap();
    let ordinary = f.attempts.start(&peers[7], &request).unwrap();
    let c = rusqlite::Connection::open(&f.path).unwrap();
    let count: i64 = c
        .query_row("SELECT count(*) FROM authentication_attempts", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 128);
    let lease = f.attempts.claim_next().unwrap().unwrap();
    assert_eq!(lease.attempt_id(), ordinary.attempt_id());
    let pending: i64 = c
        .query_row(
            "SELECT count(*) FROM authentication_attempts WHERE state='created'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(pending, 127);
    assert!(f.attempts.claim_next().unwrap().is_none());
}

#[test]
fn r2_withdrawn_oldest_unknown_does_not_starve_another_registered_agent() {
    let mut f = Fixture::new();
    f.start(0x7a);
    let a = f.attempts.claim_next().unwrap().unwrap();
    f.attempts
        .settle(&a, AttemptOutcome::Indeterminate)
        .unwrap();
    let rpk = [0x81; 44];
    let enrollment = AgentEnrollment::new(
        [0x81; 16],
        [0x81; 16],
        &rpk,
        "Synthetic second agent",
        "synthetic-boundary",
    )
    .unwrap();
    let p = f.human.prepare_agent_enrollment(&enrollment).unwrap();
    commit(&mut f.human, p.prepared());
    let peer = AgentPeer::from_transport_rpk(&rpk).unwrap();
    let b = f
        .attempts
        .start(
            &peer,
            &StartAttempt::new(
                f.item,
                "keycloak-token-exchange",
                1,
                "token_exchange",
                "keycloak-exchange-lab",
                b"keycloak-exchange-lab".to_vec(),
                IdempotencyKey::new(now(), [0x7b; 16]).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    let lease = f.attempts.claim_next().unwrap().unwrap();
    f.attempts
        .settle(&lease, AttemptOutcome::Indeterminate)
        .unwrap();
    let p = f
        .human
        .prepare_agent_revocation(AGENT, AuthorizationReason::OwnerRequest)
        .unwrap();
    commit(&mut f.human, &p);
    std::thread::sleep(std::time::Duration::from_millis(110));
    let query = f
        .attempts
        .claim_waiting_for_reconciliation()
        .unwrap()
        .unwrap();
    assert_eq!(query.attempt_id(), b.attempt_id());
    assert!(query.reconciliation_only());
    assert!(query.password().is_empty());
    f.attempts
        .with_authorized_provider_use(&query, || ())
        .unwrap();
}

#[test]
fn r2_edit_after_suspension_or_revocation_does_not_restore_authority() {
    for withdrawal in ["suspend", "revoke"] {
        let mut f = Fixture::new();
        let p = if withdrawal == "suspend" {
            f.human
                .prepare_delegated_suspend(AuthorizationReason::OwnerRequest)
                .unwrap()
        } else {
            f.human
                .prepare_agent_revocation(AGENT, AuthorizationReason::OwnerRequest)
                .unwrap()
        };
        commit(&mut f.human, &p);
        let p = f.human.prepare_organize(f.item, vec![], true).unwrap();
        commit(&mut f.human, &p);
        assert!(
            f.attempts
                .start(
                    &f.peer,
                    &StartAttempt::new(
                        f.item,
                        "keycloak-token-exchange",
                        1,
                        "token_exchange",
                        "keycloak-exchange-lab",
                        b"keycloak-exchange-lab".to_vec(),
                        IdempotencyKey::new(now(), [0x7c; 16]).unwrap()
                    )
                    .unwrap()
                )
                .is_err(),
            "{withdrawal}"
        );
    }
}

#[test]
fn r2_claim_to_guard_expiry_is_observed_without_status_poll() {
    let f = Fixture::new();
    let started = f.start(0x7d);
    let lease = f.attempts.claim_next().unwrap().unwrap();
    let c = rusqlite::Connection::open(&f.path).unwrap();
    c.execute(
        "UPDATE authentication_attempts SET expires_at_us=0 WHERE attempt_id=?1",
        [started.attempt_id().as_slice()],
    )
    .unwrap();
    let calls = std::cell::Cell::new(0);
    assert!(
        f.attempts
            .with_authorized_provider_use(&lease, || calls.set(calls.get() + 1))
            .is_err()
    );
    assert_eq!(calls.get(), 0);
    // Finite observation of the inherited slot/recovery gap, not acceptance:
    // absent a status poll the existing implementation still records running.
    let state: String = c
        .query_row(
            "SELECT state FROM authentication_attempts WHERE attempt_id=?1",
            [started.attempt_id().as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    println!(
        "CORPUS expiry pre-restart-state={state} recovered={}",
        f.attempts.recover_inflight().unwrap()
    );
}

#[test]
fn r2_never_leased_old_revision_does_not_block_new_current_work() {
    let mut f = Fixture::new();
    let old = f.start(0x7e);
    let p = f.human.prepare_organize(f.item, vec![], true).unwrap();
    commit(&mut f.human, &p);
    let current = f.start(0x7f);
    let lease = f.attempts.claim_next().unwrap().unwrap();
    assert_eq!(lease.attempt_id(), current.attempt_id());
    let old = f.attempts.get(&f.peer, *old.attempt_id()).unwrap();
    assert_eq!(old.state(), AttemptState::Failed);
    assert_eq!(old.reason(), Some("CREDENTIAL_UNAVAILABLE"));
    f.attempts
        .with_authorized_provider_use(&lease, || ())
        .unwrap();
}

#[test]
fn r2_query_only_recovery_rejects_sql_revision_metadata_without_signed_provision() {
    let mut f = Fixture::new();
    let original = f.start(0x6a);
    let lease = f.attempts.claim_next().unwrap().unwrap();
    f.attempts
        .settle(&lease, AttemptOutcome::Indeterminate)
        .unwrap();
    let p = f
        .human
        .prepare_organize(f.item, vec!["synthetic-edited".into()], false)
        .unwrap();
    commit(&mut f.human, &p);
    let c = rusqlite::Connection::open(&f.path).unwrap();
    // Tamper metadata only: the new signed provision still authenticates its
    // real new revision. Query authorization must not trust these SQL columns.
    c.execute(
        "UPDATE credential_authorizations SET revision_id=?1 WHERE item_id=?2",
        rusqlite::params![original.revision_id().as_slice(), f.item.as_slice()],
    )
    .unwrap();
    c.execute(
        "UPDATE vault_items SET visible_revision=?1 WHERE item_id=?2",
        rusqlite::params![original.revision_id().as_slice(), f.item.as_slice()],
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(110));
    assert!(matches!(
        f.attempts.claim_waiting_for_reconciliation(),
        Err(AttemptError::Integrity)
    ));
    assert_eq!(
        f.attempts
            .get(&f.peer, *original.attempt_id())
            .unwrap()
            .state(),
        AttemptState::Indeterminate
    );
}

#[test]
fn indeterminate_reconciliation_backs_off_with_attempt_age() {
    use std::time::{Duration, Instant};
    let f = Fixture::new();
    f.start(0x61);
    // Measured after creation, so the recorded age is at least this long.
    let started = Instant::now();
    let lease = f.attempts.claim_next().unwrap().unwrap();
    // The outcome becomes unknown only after the attempt has aged.
    std::thread::sleep(Duration::from_millis(400));
    f.attempts
        .settle(&lease, AttemptOutcome::Indeterminate)
        .unwrap();
    let settled = Instant::now();
    let age = settled.duration_since(started);
    // A fixed 100 ms cadence re-queried the provider and appended audit
    // records every cycle until expiry; the next query waits for its age.
    std::thread::sleep(Duration::from_millis(150));
    assert!(
        f.attempts
            .claim_waiting_for_reconciliation()
            .unwrap()
            .is_none()
    );
    let again = loop {
        if let Some(lease) = f.attempts.claim_waiting_for_reconciliation().unwrap() {
            break lease;
        }
        assert!(
            settled.elapsed() < age * 3 + Duration::from_secs(1),
            "unknown outcome was never re-queried"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(settled.elapsed() >= age);
    assert!(again.reconciliation_only());
}
