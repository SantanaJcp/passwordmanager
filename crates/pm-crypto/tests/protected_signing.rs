// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(target_os = "linux")]

use pm_crypto::{CryptoError, PasskeyKeyPair};
use std::process::Command;

#[test]
fn signing_requires_locked_expanded_key() {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "signing_memlock_helper",
            "--nocapture",
        ])
        .env_clear()
        .output()
        .expect("isolated signing process");
    assert!(
        output
            .stdout
            .windows(b"RFC8032_CONTROL_OK".len())
            .any(|v| v == b"RFC8032_CONTROL_OK"),
        "RFC8032 control missing"
    );
    assert!(
        output.status.success(),
        "expanded signing key accepted without available locks: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "executed in isolated subprocess by signing_requires_locked_expanded_key"]
fn signing_memlock_helper() {
    // RFC 8032 section 7.1 TEST 1: public synthetic seed, empty message.
    let seed = hex::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let key = PasskeyKeyPair::from_seed(seed).unwrap();
    assert_eq!(
        *key.public_key(),
        hex::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    );
    assert_eq!(
        key.sign(b"").unwrap(),
        hex::<64>(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
    );
    println!("RFC8032_CONTROL_OK");
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: only this isolated helper's future locks are denied.
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const limit) },
        0
    );
    assert_eq!(
        key.sign(b""),
        Err(CryptoError::ResourceUnavailable),
        "unlocked expanded signing key accepted"
    );
}

fn hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    std::array::from_fn(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap())
}
