// SPDX-License-Identifier: AGPL-3.0-only

use pm_crypto::{KdfProfile, RecoveryCode, RootBundle, create_human_root, open_human_root};

const PASSWORD: &[u8] = b"synthetic ticket 02 password";

#[test]
fn creates_two_independent_root_paths_and_reopens_the_human_authority() {
    let created = create_human_root(PASSWORD, KdfProfile::confirmed(64, 3).unwrap())
        .expect("create root bundle");
    let recovery = created.recovery_code().to_string();
    let bundle_bytes = created.bundle().to_bytes();

    let parsed = RootBundle::from_bytes(&bundle_bytes).expect("parse canonical bundle");
    let unlocked = open_human_root(&parsed, PASSWORD).expect("open password path");
    assert_eq!(
        unlocked.vault_id(),
        created.bundle().trusted_root().vault_id()
    );
    assert_eq!(
        unlocked.human_public_key(),
        created.bundle().trusted_root().public_key()
    );

    let code: RecoveryCode = recovery.parse().expect("parse recovery code");
    let recovered = pm_crypto::recover_human_root(&parsed, &code).expect("open recovery path");
    assert_eq!(recovered.human_public_key(), unlocked.human_public_key());
    assert_ne!(
        created.bundle().password_envelope(),
        created.bundle().recovery_envelope()
    );
}

#[test]
fn wrong_password_tampering_and_noncanonical_or_incompatible_bytes_are_rejected() {
    let created = create_human_root(PASSWORD, KdfProfile::confirmed(64, 3).unwrap())
        .expect("create root bundle");
    let bytes = created.bundle().to_bytes();

    assert!(open_human_root(created.bundle(), b"synthetic wrong password").is_err());

    let mut tampered = bytes.clone();
    let last = tampered.last_mut().expect("bundle is not empty");
    *last ^= 1;
    let tampered = RootBundle::from_bytes(&tampered).expect("tampering remains valid CBOR");
    assert!(open_human_root(&tampered, PASSWORD).is_err());

    let mut trailing = bytes;
    trailing.push(0);
    assert!(RootBundle::from_bytes(&trailing).is_err());
}

#[test]
fn version_kdf_purpose_and_complete_aad_context_are_fail_closed() {
    let created = create_human_root(PASSWORD, KdfProfile::confirmed(64, 3).unwrap())
        .expect("create root bundle");
    let bytes = created.bundle().to_bytes();

    let mut incompatible = bytes.clone();
    assert_eq!(&incompatible[..4], &[0xa5, 0x61, b'v', 0x01]);
    incompatible[3] = 2;
    assert!(RootBundle::from_bytes(&incompatible).is_err());
    assert!(KdfProfile::confirmed(63, 3).is_err());
    assert!(KdfProfile::confirmed(1025, 3).is_err());
    assert!(KdfProfile::confirmed(64, 2).is_err());

    let mut wrong_purpose = bytes.clone();
    replace_once(&mut wrong_purpose, b"root-password", b"wrong-purpose");
    assert!(RootBundle::from_bytes(&wrong_purpose).is_err());

    let mut altered_aad = bytes;
    let marker = find(&altered_aad, b"target_object").expect("header target marker");
    let target = marker + b"target_object".len();
    assert_eq!(altered_aad[target], 0x50);
    altered_aad[target + 1] ^= 1;
    let altered = RootBundle::from_bytes(&altered_aad).expect("still canonical CBOR");
    assert!(open_human_root(&altered, PASSWORD).is_err());
}

fn replace_once(bytes: &mut [u8], from: &[u8], to: &[u8]) {
    assert_eq!(from.len(), to.len());
    let offset = find(bytes, from).expect("fixture marker");
    bytes[offset..offset + from.len()].copy_from_slice(to);
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
