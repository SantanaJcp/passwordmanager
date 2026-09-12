// SPDX-License-Identifier: AGPL-3.0-only

use pm_crypto::{ItemKind, KdfProfile, RevisionPackageInput, create_human_root, open_human_root};

const PASSWORD: &[u8] = b"synthetic manifest password";
const HUMAN: &[u8] = &[0xa1, 0x61, b'x', 0x01];
const AUTH: &[u8] = &[
    0x81, 0xa1, 0x66, b'm', b'e', b't', b'h', b'o', b'd', 0x68, b'p', b'a', b's', b's', b'w', b'o',
    b'r', b'd',
];

#[test]
fn manifest_binds_encrypted_parts_to_external_distinct_key_envelopes_without_a_cycle() {
    let created = create_human_root(PASSWORD, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    let unlocked = open_human_root(created.bundle(), PASSWORD).unwrap();
    let input = RevisionPackageInput {
        item: [0x11; 16],
        revision: [0x22; 16],
        issuer_device: [0x33; 16],
        modified_at: 1_725_000_000_000_000,
        kind: ItemKind::Password,
        human_plaintext: HUMAN,
        auth_plaintext: Some(AUTH),
    };

    let package = unlocked.seal_revision_package(input).expect("seal package");
    let bytes = package.to_bytes();

    let mut cross_purpose = bytes.clone();
    replace_once(&mut cross_purpose, b"auth-payload", b"audit-record");
    assert!(unlocked.open_revision_package(&cross_purpose).is_err());
    let mut attempt_substitution = bytes.clone();
    replace_once(
        &mut attempt_substitution,
        b"human-content",
        b"attempt-state",
    );
    assert!(
        unlocked
            .open_revision_package(&attempt_substitution)
            .is_err()
    );
    assert!(!contains(&bytes, HUMAN));
    assert!(!contains(&bytes, AUTH));
    assert_ne!(
        package.human_key_envelope(),
        package.manifest_key_envelope()
    );

    let opened = unlocked
        .open_revision_package(&bytes)
        .expect("verify complete package");
    assert_eq!(opened.item(), &[0x11; 16]);
    assert_eq!(opened.revision(), &[0x22; 16]);
    assert_eq!(opened.human_plaintext(), HUMAN);
    assert_eq!(opened.auth_plaintext(), Some(AUTH));
}

#[test]
fn altered_reordered_or_trailing_package_bytes_never_activate_a_partial_revision() {
    let created = create_human_root(PASSWORD, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    let unlocked = open_human_root(created.bundle(), PASSWORD).unwrap();
    let package = unlocked
        .seal_revision_package(RevisionPackageInput {
            item: [0x44; 16],
            revision: [0x55; 16],
            issuer_device: [0x66; 16],
            modified_at: -1,
            kind: ItemKind::Token,
            human_plaintext: HUMAN,
            auth_plaintext: Some(AUTH),
        })
        .unwrap();
    let bytes = package.to_bytes();

    for offset in [bytes.len() / 3, bytes.len() / 2, bytes.len() - 1] {
        let mut altered = bytes.clone();
        altered[offset] ^= 1;
        assert!(unlocked.open_revision_package(&altered).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(unlocked.open_revision_package(&trailing).is_err());
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn replace_once(bytes: &mut [u8], from: &[u8], to: &[u8]) {
    assert_eq!(from.len(), to.len());
    let offset = bytes
        .windows(from.len())
        .position(|window| window == from)
        .expect("fixture purpose");
    bytes[offset..offset + from.len()].copy_from_slice(to);
}
