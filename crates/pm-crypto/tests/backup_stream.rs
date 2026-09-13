// SPDX-License-Identifier: AGPL-3.0-only

use pm_crypto::{BackupOpener, KdfProfile, RootBundle, create_human_root, open_human_root};

#[test]
fn pmb1_payload_uses_independent_pmf1_and_both_human_root_paths() {
    let password = b"synthetic ticket21 backup password";
    let created = create_human_root(password, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    let recovery = created.recovery_code().to_string();
    let bundle = RootBundle::from_bytes(&created.bundle().to_bytes()).unwrap();
    let unlocked = open_human_root(&bundle, password).unwrap();
    let backup_id = [0x21; 16];
    let mut sealer = unlocked.start_backup(backup_id).unwrap();
    let root_envelopes = bundle.backup_root_envelopes();

    let first = sealer.seal_chunk(b"manifest-start", false).unwrap();
    let last = sealer.seal_chunk(b"manifest-end", true).unwrap();
    assert!(sealer.pmf1_header().starts_with(b"PMF1"));
    assert!(!sealer.key_envelope().is_empty());

    for mut opener in [
        BackupOpener::with_password(
            &root_envelopes,
            backup_id,
            sealer.key_envelope(),
            sealer.pmf1_header(),
            password,
        )
        .unwrap(),
        BackupOpener::with_recovery(
            &root_envelopes,
            backup_id,
            sealer.key_envelope(),
            sealer.pmf1_header(),
            &recovery.parse().unwrap(),
        )
        .unwrap(),
    ] {
        assert_eq!(opener.open_chunk(&first, false).unwrap(), b"manifest-start");
        assert_eq!(opener.open_chunk(&last, true).unwrap(), b"manifest-end");
        assert!(opener.open_chunk(&last, true).is_err());
    }

    let mut altered = last.clone();
    *altered.last_mut().unwrap() ^= 1;
    let mut opener = BackupOpener::with_password(
        &root_envelopes,
        backup_id,
        sealer.key_envelope(),
        sealer.pmf1_header(),
        password,
    )
    .unwrap();
    opener.open_chunk(&first, false).unwrap();
    assert!(opener.open_chunk(&altered, true).is_err());

    let device = [0xa7; 16];
    let audit_package = unlocked
        .provision_audit_key(device, 1, [0x31; 32], [0x32; 32])
        .unwrap();
    let source_audit = unlocked.open_audit_key_package(&audit_package).unwrap();
    let event = [0xe1; 16];
    let ciphertext = source_audit
        .seal_record(event, [0xe2; 16], b"historical audit payload")
        .unwrap();
    let destination_created = create_human_root(
        b"synthetic ticket21 destination password",
        KdfProfile::confirmed(64, 3).unwrap(),
    )
    .unwrap();
    let destination = open_human_root(
        destination_created.bundle(),
        b"synthetic ticket21 destination password",
    )
    .unwrap();
    let opener = BackupOpener::with_password(
        &root_envelopes,
        backup_id,
        sealer.key_envelope(),
        sealer.pmf1_header(),
        password,
    )
    .unwrap();
    let rewrapped = opener
        .rewrap_imported_audit_key(&destination, audit_package.human_envelope(), device, 1)
        .unwrap();
    assert_ne!(rewrapped, audit_package.human_envelope());
    assert!(
        unlocked
            .open_imported_audit_key(&rewrapped, *unlocked.vault_id(), device, 1)
            .is_err()
    );
    let imported = destination
        .open_imported_audit_key(&rewrapped, *unlocked.vault_id(), device, 1)
        .unwrap();
    assert_eq!(
        imported.open_record(event, &ciphertext).unwrap(),
        b"historical audit payload"
    );
}
