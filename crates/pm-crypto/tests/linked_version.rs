// SPDX-License-Identifier: AGPL-3.0-only

#[test]
fn links_the_selected_libsodium_c_version() {
    assert_eq!(
        pm_crypto::linked_libsodium_version()
            .to_str()
            .expect("the upstream version is ASCII"),
        "1.0.22"
    );
}
