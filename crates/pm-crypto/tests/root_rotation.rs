// SPDX-License-Identifier: AGPL-3.0-only

use pm_crypto::{KdfProfile, create_human_root, open_human_root, recover_human_root};

const OLD: &[u8] = b"synthetic ticket22 old master";
const NEW: &[u8] = b"synthetic ticket22 new master";

#[test]
fn rotates_password_and_recovery_paths_without_changing_human_authority() {
    let created = create_human_root(OLD, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    let original_recovery = created.recovery_code().to_string();
    let unlocked = open_human_root(created.bundle(), OLD).unwrap();
    let authority = unlocked.trusted_root();

    let password_rotated = unlocked
        .rewrap_password(created.bundle(), NEW, KdfProfile::confirmed(64, 3).unwrap())
        .unwrap();
    assert!(open_human_root(&password_rotated, OLD).is_err());
    assert_eq!(
        open_human_root(&password_rotated, NEW)
            .unwrap()
            .trusted_root(),
        authority
    );
    assert!(recover_human_root(&password_rotated, &original_recovery.parse().unwrap()).is_ok());

    let pending = unlocked.rotate_recovery(&password_rotated).unwrap();
    let new_recovery = pending.recovery_code().to_string();
    let confirmed = pending
        .into_bundle_after_recovery_confirmation(&new_recovery.parse().unwrap())
        .unwrap();
    assert!(recover_human_root(&confirmed, &original_recovery.parse().unwrap()).is_err());
    assert_eq!(
        recover_human_root(&confirmed, &new_recovery.parse().unwrap())
            .unwrap()
            .trusted_root(),
        authority
    );
    assert!(open_human_root(&confirmed, NEW).is_ok());
}

#[test]
fn recovery_rotation_requires_reintroduction_and_never_accepts_a_foreign_code() {
    let created = create_human_root(OLD, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    let unlocked = open_human_root(created.bundle(), OLD).unwrap();
    let pending = unlocked.rotate_recovery(created.bundle()).unwrap();
    let foreign = create_human_root(OLD, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    assert!(
        pending
            .into_bundle_after_recovery_confirmation(foreign.recovery_code())
            .is_err()
    );
}
