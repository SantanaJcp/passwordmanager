// SPDX-License-Identifier: AGPL-3.0-only
use pm_crypto::{CryptoError, KdfProfile, create_human_root, open_human_root};

#[test]
fn existing_stream_ciphertext_authenticates_only_its_original_revision() {
    let master = b"synthetic W7 stream membership master";
    let created = create_human_root(master, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    let root = open_human_root(created.bundle(), master).unwrap();
    let attachment = [0x77; 16];
    let original = [0x71; 16];
    let next = [0x72; 16];
    let mut sealer = root.start_file(attachment, original).unwrap();
    let ciphertext = sealer.seal_chunk(b"synthetic W7 attachment", true).unwrap();
    let mut opener = root
        .start_file_open(attachment, original, sealer.header())
        .unwrap();
    assert_eq!(
        opener.open_chunk(&ciphertext, true).unwrap().as_ref(),
        b"synthetic W7 attachment"
    );
    assert!(matches!(
        root.start_file_open(attachment, next, sealer.header()),
        Err(CryptoError::Authentication)
    ));
}
