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
    time::{SystemTime, UNIX_EPOCH},
};

use pm_crypto::{KdfProfile, verify_passkey_signature};
use pm_vault::{
    AgentEnrollment, AgentPeer, AttemptState, AttemptVault, AuditDeviceCustody,
    AuthorizationReason, DelegatedVault, HumanChannel, HumanVault, HumanVerification,
    IdempotencyKey, PasskeyError, PasskeyOperation, PasskeyProvider, PasskeyRequest, PasskeyStatus,
    PendingVault, StartAttempt, UserVerificationRequirement,
};

const MASTER: &[u8] = b"synthetic ticket13 master";
const DEVICE: [u8; 16] = [0x13; 16];
const AGENT: [u8; 16] = [0xa3; 16];
const RPK: [u8; 44] = [0x43; 44];
const ORIGIN: &str = "https://passkey.test";
const RP: &str = "passkey.test";
static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
fn human_registration_generates_one_independent_g6_key_and_replays_public_response() {
    let directory = TestDir::new();
    let path = directory.vault();
    persist(&path);
    let custody = Arc::new(AuditDeviceCustody::generate().unwrap());
    let (mut human, _peer) = open_human(&path, Arc::clone(&custody));
    initialize_device(&mut human);
    let provider = PasskeyProvider::open(
        AttemptVault::open(DelegatedVault::open(&path, DEVICE, custody).unwrap()).unwrap(),
    )
    .unwrap();
    let request = PasskeyRequest::registration(
        [0x11; 16],
        "document-ticket13-create",
        ORIGIN,
        RP,
        &[0x21; 32],
        b"synthetic-user-handle",
        "synthetic-user",
        "Synthetic User",
        UserVerificationRequirement::Required,
    )
    .unwrap();
    let PasskeyStatus::Waiting(prompt) = provider.begin(&request).unwrap() else {
        panic!("registration must wait for a human")
    };
    assert_eq!(prompt.operation(), PasskeyOperation::Create);
    assert_eq!(prompt.rp_id(), RP);
    assert_eq!(prompt.account(), "synthetic-user");

    let prepared = human.prepare_passkey_registration(&request).unwrap();
    let public = prepared.public().clone();
    assert_eq!(public.cose_algorithm(), -8);
    assert_eq!(public.rp_id(), RP);
    assert_eq!(public.user_handle(), b"synthetic-user-handle");
    assert_eq!(public.sign_count(), 0);
    assert!(public.backup_eligible());
    assert!(!public.backup_state());
    let item = *prepared.prepared().item_id();
    commit(&mut human, prepared.prepared());
    let completed = provider
        .complete_registration(
            &human,
            *request.request_id(),
            item,
            &public,
            HumanVerification::Verified,
        )
        .unwrap();
    assert!(matches!(completed, PasskeyStatus::Registration(_)));
    assert_eq!(provider.begin(&request).unwrap(), completed);

    let altered = PasskeyRequest::registration(
        [0x11; 16],
        "different-document",
        ORIGIN,
        RP,
        &[0x21; 32],
        b"synthetic-user-handle",
        "synthetic-user",
        "Synthetic User",
        UserVerificationRequirement::Required,
    )
    .unwrap();
    assert!(matches!(
        provider.begin(&altered),
        Err(PasskeyError::IdempotencyConflict)
    ));

    let record = human.read_record(item).unwrap();
    let [
        pm_vault::AuthRecord::Passkey {
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
        },
    ] = record.auth()
    else {
        panic!("exactly one passkey auth record")
    };
    assert_eq!(rp_id, RP);
    assert_eq!(user_handle, b"synthetic-user-handle");
    assert_eq!(credential_id, public.credential_id());
    assert_eq!(*cose_alg, -8);
    assert_ne!(private_key, &[0; 32]);
    assert_eq!(public_key, public.public_key());
    assert_eq!(user_name, "synthetic-user");
    assert_eq!(display_name, "Synthetic User");
    assert_eq!(*sign_count, 0);
    assert!(*backup_eligible);
    assert!(!*backup_state);
}

#[test]
#[allow(clippy::too_many_lines)]
fn assertion_needs_bound_up_uv_and_live_attempt_authority_before_signing() {
    let directory = TestDir::new();
    let path = directory.vault();
    persist(&path);
    let custody = Arc::new(AuditDeviceCustody::generate().unwrap());
    let (mut human, _peer) = open_human(&path, Arc::clone(&custody));
    initialize_device(&mut human);
    let attempts =
        AttemptVault::open(DelegatedVault::open(&path, DEVICE, Arc::clone(&custody)).unwrap())
            .unwrap();
    let provider = PasskeyProvider::open(attempts).unwrap();
    let create = PasskeyRequest::registration(
        [0x31; 16],
        "document-ticket13-register",
        ORIGIN,
        RP,
        &[0x32; 32],
        b"ticket13-user-handle",
        "alice",
        "Alice Synthetic",
        UserVerificationRequirement::Required,
    )
    .unwrap();
    provider.begin(&create).unwrap();
    let registration = human.prepare_passkey_registration(&create).unwrap();
    let public = registration.public().clone();
    let item = *registration.prepared().item_id();
    commit(&mut human, registration.prepared());
    provider
        .complete_registration(
            &human,
            *create.request_id(),
            item,
            &public,
            HumanVerification::Verified,
        )
        .unwrap();
    enroll_and_enable(&mut human, item);

    let peer = AgentPeer::from_transport_rpk(&RPK).unwrap();
    let now = now_us();
    let first = provider
        .attempts()
        .start(
            &peer,
            &StartAttempt::new(
                item,
                "vault-webauthn-provider",
                1,
                "webauthn",
                ORIGIN,
                b"keycloak-webauthn/1".to_vec(),
                IdempotencyKey::new(now, [0x41; 16]).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    let assertion_request = PasskeyRequest::assertion(
        [0x42; 16],
        *first.attempt_id(),
        "document-ticket13-get",
        ORIGIN,
        RP,
        &[0x43; 32],
        vec![public.credential_id().to_vec()],
        UserVerificationRequirement::Required,
    )
    .unwrap();
    assert!(matches!(
        provider.begin(&assertion_request).unwrap(),
        PasskeyStatus::Waiting(_)
    ));
    assert_eq!(
        provider
            .attempts()
            .get(&peer, *first.attempt_id())
            .unwrap()
            .state(),
        AttemptState::WaitingForHuman
    );
    assert!(matches!(
        provider.confirm_assertion(
            &human,
            *assertion_request.request_id(),
            HumanVerification::Presence
        ),
        Err(PasskeyError::UserVerificationRequired)
    ));
    let completed = provider
        .confirm_assertion(
            &human,
            *assertion_request.request_id(),
            HumanVerification::Verified,
        )
        .unwrap();
    let PasskeyStatus::Assertion(assertion) = &completed else {
        panic!("assertion expected")
    };
    assert!(assertion.user_present());
    assert!(assertion.user_verified());
    assert_eq!(assertion.credential_id(), public.credential_id());
    verify_passkey_signature(
        public.public_key(),
        assertion.signed_message(),
        assertion.signature(),
    )
    .unwrap();
    assert_eq!(provider.begin(&assertion_request).unwrap(), completed);
    assert_eq!(
        provider
            .attempts()
            .get(&peer, *first.attempt_id())
            .unwrap()
            .state(),
        AttemptState::Succeeded
    );

    let pending_attempt = provider
        .attempts()
        .start(
            &peer,
            &StartAttempt::new(
                item,
                "vault-webauthn-provider",
                1,
                "webauthn",
                ORIGIN,
                b"keycloak-webauthn/1".to_vec(),
                IdempotencyKey::new(now, [0x51; 16]).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    let pending = PasskeyRequest::assertion(
        [0x52; 16],
        *pending_attempt.attempt_id(),
        "document-before-revoke",
        ORIGIN,
        RP,
        &[0x53; 32],
        vec![public.credential_id().to_vec()],
        UserVerificationRequirement::Preferred,
    )
    .unwrap();
    provider.begin(&pending).unwrap();
    let revoke = human
        .prepare_agent_revocation(AGENT, AuthorizationReason::SuspectedCompromise)
        .unwrap();
    commit(&mut human, &revoke);
    assert!(matches!(
        provider.confirm_assertion(&human, *pending.request_id(), HumanVerification::Verified),
        Err(PasskeyError::Revoked)
    ));
    assert!(provider.response(*pending.request_id()).unwrap().is_none());
}

fn enroll_and_enable(human: &mut HumanVault, item: [u8; 16]) {
    let enrollment = AgentEnrollment::new(
        AGENT,
        [0x61; 16],
        &RPK,
        "Synthetic passkey agent",
        "ticket13-userns",
    )
    .unwrap();
    let prepared = human.prepare_agent_enrollment(&enrollment).unwrap();
    commit(human, prepared.prepared());
    let resume = human.prepare_delegated_resume().unwrap();
    commit(human, &resume);
    let enable = human.prepare_enable(item).unwrap();
    commit(human, &enable);
}

fn initialize_device(human: &mut HumanVault) {
    let prepared = human.prepare_delegated_resume().unwrap();
    commit(human, &prepared);
}

fn commit(human: &mut HumanVault, prepared: &pm_vault::PreparedHumanCommand) {
    let signature = human.sign(prepared).unwrap();
    human
        .commit(prepared.command(), &signature, prepared.body())
        .unwrap();
}

fn open_human(path: &Path, custody: Arc<AuditDeviceCustody>) -> (HumanVault, UnixStream) {
    let (server, peer) = UnixStream::pair().unwrap();
    let channel = HumanChannel::authenticate(server, unsafe { libc::geteuid() }).unwrap();
    (
        HumanVault::unlock_with_audit_custody(path, MASTER, DEVICE, channel, custody).unwrap(),
        peer,
    )
}

fn persist(path: &Path) {
    let pending = PendingVault::new(MASTER, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    let recovery = pending.recovery_code().to_string().parse().unwrap();
    pending.persist(path, &recovery).unwrap();
}

fn now_us() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}

struct TestDir(PathBuf);
impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "pm-ticket13-{}-{}",
            process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn vault(&self) -> PathBuf {
        self.0.join("vault.sqlite3")
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
