// SPDX-License-Identifier: AGPL-3.0-only

use pm_crypto::{DeviceKeyPair, GrantVectorInput, KdfProfile, create_human_root, open_human_root};

#[test]
fn grant_vector_uses_commitment_then_event_then_final_signature_without_a_hash_cycle() {
    let created = create_human_root(
        b"synthetic grant password",
        KdfProfile::confirmed(64, 3).unwrap(),
    )
    .unwrap();
    let unlocked = open_human_root(created.bundle(), b"synthetic grant password").unwrap();
    let device = DeviceKeyPair::generate().unwrap();
    let recipient = [0x71; 16];
    let pending = unlocked
        .prepare_grant_vector(
            GrantVectorInput {
                item: [0x72; 16],
                revision: [0x73; 16],
                recipient,
                authorization_generation: 9,
                payload_sha256: [0x74; 32],
            },
            device.public_key(),
        )
        .unwrap();
    let commitment = pending.commitment();
    let authority_event = [0x75; 32];
    let signed = unlocked
        .finish_grant_vector(pending, authority_event)
        .unwrap();
    assert_eq!(signed.commitment(), &commitment);

    device
        .verify_grant_vector(
            &signed.to_bytes(),
            created.bundle().trusted_root(),
            recipient,
            authority_event,
            commitment,
        )
        .expect("trusted signed and sealed vector");

    let mut altered = signed.to_bytes();
    *altered.last_mut().unwrap() ^= 1;
    assert!(
        device
            .verify_grant_vector(
                &altered,
                created.bundle().trusted_root(),
                recipient,
                authority_event,
                commitment,
            )
            .is_err()
    );
}
