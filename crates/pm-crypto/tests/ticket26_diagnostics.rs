// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(feature = "macos-ticket26-diagnostics")]

use pm_crypto::{
    KdfDiagnosticBoundary, KdfProfile, create_human_root, open_human_root,
    open_human_root_diagnostic,
};

#[test]
fn diagnostic_opener_observes_existing_derivation_without_changing_public_result() {
    let password = b"synthetic ticket 26 diagnostic password";
    let created = create_human_root(password, KdfProfile::confirmed(64, 3).unwrap()).unwrap();

    let ordinary = open_human_root(created.bundle(), password).unwrap();
    let mut boundaries = Vec::new();
    let observed = open_human_root_diagnostic(created.bundle(), password, |boundary| {
        boundaries.push(boundary);
    })
    .unwrap();

    assert_eq!(
        boundaries,
        [KdfDiagnosticBoundary::Start, KdfDiagnosticBoundary::End]
    );
    assert_eq!(ordinary.vault_id(), observed.vault_id());
    assert_eq!(ordinary.human_public_key(), observed.human_public_key());
    assert_eq!(ordinary.trusted_root(), observed.trusted_root());
}
