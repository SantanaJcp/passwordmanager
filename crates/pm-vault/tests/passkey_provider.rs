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
    AgentEnrollment, AgentPeer, AttemptOutcome, AttemptState, AttemptVault, AuditDeviceCustody,
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

fn connection_count(path: &Path, table: &str) -> i64 {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

#[test]
#[allow(clippy::too_many_lines)]
fn human_registration_generates_one_independent_g6_key_and_replays_public_response() {
    let directory = TestDir::new();
    let path = directory.vault();
    persist(&path);
    let custody = Arc::new(AuditDeviceCustody::generate().unwrap());
    let (mut human, _channel_peer) = open_human(&path, Arc::clone(&custody));
    initialize_device(&mut human);
    let peer = AgentPeer::from_transport_rpk(&RPK).unwrap();
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
    assert_eq!(provider.response_for_peer(&peer, [0x11; 16]).unwrap(), None);

    let prepared = human.prepare_passkey_registration(&request).unwrap();
    let public = prepared.public().clone();
    assert_eq!(public.cose_algorithm(), -8);
    assert_eq!(public.rp_id(), RP);
    assert_eq!(public.user_handle(), b"synthetic-user-handle");
    assert_eq!(public.sign_count(), 0);
    assert!(public.backup_eligible());
    assert!(!public.backup_state());
    let client_data = public.client_data_json();
    assert_eq!(
        client_data,
        br#"{"type":"webauthn.create","challenge":"ISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISE","origin":"https://passkey.test","crossOrigin":false}"#
    );
    let attestation = public.attestation_object();
    let mut decoder = minicbor::Decoder::new(&attestation);
    assert_eq!(decoder.map().unwrap(), Some(3));
    assert_eq!(decoder.str().unwrap(), "fmt");
    assert_eq!(decoder.str().unwrap(), "none");
    assert_eq!(decoder.str().unwrap(), "attStmt");
    assert_eq!(decoder.map().unwrap(), Some(0));
    assert_eq!(decoder.str().unwrap(), "authData");
    let auth_data = decoder.bytes().unwrap();
    assert_eq!(&auth_data[..32], pm_crypto::digest(RP.as_bytes()));
    assert_eq!(
        auth_data[32], 0x4d,
        "UP+UV+BE+AT are real registration flags"
    );
    assert_eq!(&auth_data[33..37], &[0; 4]);
    assert_eq!(&auth_data[37..53], &[0; 16]);
    assert_eq!(
        usize::from(u16::from_be_bytes(auth_data[53..55].try_into().unwrap())),
        public.credential_id().len()
    );
    assert!(auth_data.ends_with(public.public_key()));
    assert_eq!(decoder.position(), attestation.len());
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
    assert_eq!(
        provider
            .response_for_peer(&peer, [0x11; 16])
            .unwrap()
            .unwrap(),
        completed
    );
    assert_eq!(
        connection_count(&path, "passkey_registration_staging"),
        0,
        "registration response is published by the same durable human transaction"
    );
    assert_eq!(provider.begin(&request).unwrap(), completed);

    let connection = rusqlite::Connection::open(&path).unwrap();
    let stored: (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT request,response FROM passkey_requests WHERE request_id=?1",
            [request.request_id().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    for package in [&stored.0, &stored.1] {
        assert!(
            !package
                .windows(RP.len())
                .any(|window| window == RP.as_bytes())
        );
        assert!(
            !package
                .windows(b"synthetic-user".len())
                .any(|window| window == b"synthetic-user")
        );
        assert!(!package.windows(32).any(|window| window == [0x21; 32]));
    }

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

    let login = provider
        .attempts()
        .start(
            &peer,
            &StartAttempt::new(
                item,
                "keycloak-webauthn",
                1,
                "webauthn",
                ORIGIN,
                b"keycloak-lab".to_vec(),
                IdempotencyKey::new(now, [0x45; 16]).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(login.state(), AttemptState::Created);
    let lease = provider.attempts().claim_next().unwrap().unwrap();
    assert_eq!(lease.integration_id(), "keycloak-webauthn");
    assert_eq!(lease.username(), "alice");
    assert!(
        lease.password().is_empty(),
        "a passkey seed is never leased"
    );
    assert_eq!(lease.credential_id(), &item);
    let finished = provider
        .attempts()
        .settle(
            &lease,
            AttemptOutcome::Succeeded {
                result: b"validated-oidc-result".to_vec(),
            },
        )
        .unwrap();
    assert_eq!(finished.state(), AttemptState::Succeeded);
    assert_eq!(finished.result(), Some(b"validated-oidc-result".as_slice()));

    let rollback_attempt = provider
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
                IdempotencyKey::new(now, [0x47; 16]).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    let rollback_request = PasskeyRequest::assertion(
        [0x48; 16],
        *rollback_attempt.attempt_id(),
        "document-audit-rollback",
        ORIGIN,
        RP,
        &[0x49; 32],
        vec![public.credential_id().to_vec()],
        UserVerificationRequirement::Preferred,
    )
    .unwrap();
    provider.begin_for_peer(&peer, &rollback_request).unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_ticket13_audit BEFORE INSERT ON encrypted_audit_records
             BEGIN SELECT raise(ABORT, 'synthetic ticket13 audit failure'); END;",
        )
        .unwrap();
    assert!(
        provider
            .confirm_assertion(
                &human,
                *rollback_request.request_id(),
                HumanVerification::Verified,
            )
            .is_err()
    );
    assert!(
        provider
            .response(*rollback_request.request_id())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        provider
            .attempts()
            .get(&peer, *rollback_attempt.attempt_id())
            .unwrap()
            .state(),
        AttemptState::WaitingForHuman
    );
    connection
        .execute_batch("DROP TRIGGER fail_ticket13_audit")
        .unwrap();
    assert!(matches!(
        provider
            .confirm_assertion(
                &human,
                *rollback_request.request_id(),
                HumanVerification::Verified,
            )
            .unwrap(),
        PasskeyStatus::Assertion(_)
    ));

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
    assert!(matches!(
        provider.response_for_peer(&peer, *assertion_request.request_id()),
        Err(PasskeyError::Revoked)
    ));
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
        HumanVault::unlock(path, MASTER, DEVICE, channel, custody).unwrap(),
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
