// SPDX-License-Identifier: AGPL-3.0-only
#![cfg(windows)]

use pm_crypto::{
    CryptoError, ProtectedBytes, ProtectedWriter, windows_memory_failure, windows_memory_status,
};

#[test]
fn native_oversized_request_is_resource_unavailable_without_secret_write_or_counter_overflow() {
    let mut placed_secret = false;
    let rejected = ProtectedWriter::new(usize::MAX).and_then(|mut writer| {
        writer.put_with(1, |destination| {
            placed_secret = true;
            destination[0] = b'S';
            Ok(())
        })
    });
    assert_eq!(rejected, Err(CryptoError::ResourceUnavailable));
    assert!(!placed_secret);
    let failure = windows_memory_failure()
        .unwrap()
        .expect("explicit oversized rejection");
    assert_eq!(failure.category, "budget");
    assert_eq!(failure.win32_error, 0);
    assert_eq!(failure.requested_capacity_bytes, usize::MAX);
    assert!(failure.requested_payload_page_bytes > usize::MAX as u128);
    assert_eq!(windows_memory_status().unwrap().live_capacity_bytes, 0);
}

/// Runs in its own integration-test process, with no concurrent secret owners.
/// The production quota must be prepared before this acceptance case can pass.
#[test]
fn native_aggregate_budget_near_and_above_32_mib_denies_before_secret_write() {
    let initial = windows_memory_status().expect("native quota query");
    assert_eq!(initial.budget_bytes, 32 * 1024 * 1024);
    assert_eq!(initial.live_capacity_bytes, 0);
    let mut owners = Vec::new();
    for _ in 0..31 {
        owners.push(ProtectedBytes::zeroed(1024 * 1024).expect("real locked MiB"));
    }
    assert_eq!(
        windows_memory_status().unwrap().live_capacity_bytes,
        31 * 1024 * 1024
    );
    owners.push(ProtectedBytes::zeroed(1024 * 1024).expect("exact budget owner"));
    let at_limit = windows_memory_status().unwrap();
    assert_eq!(at_limit.live_capacity_bytes, at_limit.budget_bytes);
    assert_eq!(at_limit.live_payload_page_bytes, at_limit.budget_bytes);
    assert_eq!(at_limit.live_regions, 32);
    // The write closure never receives a destination for the synthetic secret.
    let mut placed_secret = false;
    let rejected = ProtectedWriter::new(1).and_then(|mut writer| {
        writer.put_with(1, |destination| {
            placed_secret = true;
            destination[0] = b'S';
            Ok(())
        })
    });
    assert_eq!(rejected, Err(CryptoError::ResourceUnavailable));
    assert!(!placed_secret);
    let failure = windows_memory_failure()
        .unwrap()
        .expect("explicit budget failure");
    assert_eq!(failure.category, "budget");
    assert_eq!(failure.win32_error, 0);
    assert_eq!(failure.requested_capacity_bytes, 1);
    assert_eq!(
        windows_memory_status().unwrap().live_capacity_bytes,
        at_limit.budget_bytes
    );
    owners[0].truncate(1);
    assert!(matches!(
        ProtectedBytes::zeroed(1),
        Err(CryptoError::ResourceUnavailable)
    ));
    drop(owners.pop());
    let replacement = ProtectedBytes::zeroed(1024 * 1024).expect("released capacity reusable");
    drop(replacement);
    drop(owners);
    let released = windows_memory_status().unwrap();
    assert_eq!(released.live_capacity_bytes, 0);
    assert_eq!(released.live_payload_page_bytes, 0);
    assert_eq!(released.live_regions, 0);
}
