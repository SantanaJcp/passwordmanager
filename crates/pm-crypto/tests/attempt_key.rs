// SPDX-License-Identifier: AGPL-3.0-only

use pm_crypto::AuditDeviceKeyPair;

#[test]
fn device_only_attempt_key_is_context_bound_signed_and_reused_for_state_updates() {
    let keys = AuditDeviceKeyPair::generate().unwrap();
    let vault = [1; 16];
    let device = [2; 16];
    let attempt = [3; 16];
    let canary = b"synthetic-ticket08-attempt-state-canary";
    let package = keys
        .seal_attempt_state(vault, device, 7, attempt, canary)
        .unwrap();
    assert!(!package.windows(canary.len()).any(|v| v == canary));
    assert_eq!(
        keys.open_attempt_state(&package, vault, device, 7, attempt)
            .unwrap(),
        canary
    );
    assert!(
        keys.open_attempt_state(&package, vault, device, 8, attempt)
            .is_err()
    );
    assert!(
        keys.open_attempt_state(&package, vault, device, 7, [4; 16])
            .is_err()
    );
    let replacement = keys
        .update_attempt_state(&package, vault, device, 7, attempt, b"terminal")
        .unwrap();
    assert_ne!(package, replacement);
    assert_eq!(
        keys.open_attempt_state(&replacement, vault, device, 7, attempt)
            .unwrap(),
        b"terminal"
    );
    let mut altered = replacement;
    *altered.last_mut().unwrap() ^= 1;
    assert!(
        keys.open_attempt_state(&altered, vault, device, 7, attempt)
            .is_err()
    );
}
