// SPDX-License-Identifier: AGPL-3.0-only
#![cfg(windows)]

use pm_crypto::{
    CryptoError, ProtectedBytes, ProtectedWriter, WINDOWS_PROTECTED_WORKING_SET_MIN,
    prepare_windows_protected_memory, windows_memory_failure, windows_memory_status,
};

#[test]
fn native_quota_is_applied_and_effectively_re_read_before_protected_owners() {
    let status = prepare_windows_protected_memory().expect("explicit native working-set setup");
    assert!(status.working_set_min_bytes >= WINDOWS_PROTECTED_WORKING_SET_MIN);
    assert!(status.working_set_max_bytes >= status.working_set_min_bytes);
    assert_eq!(status.working_set_flags, 10);
    assert_eq!(status.live_capacity_bytes, 0);
    println!(
        "PASS windows-quota-applied min={} max={} flags={}",
        status.working_set_min_bytes, status.working_set_max_bytes, status.working_set_flags
    );
}

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
/// The 32 MiB Windows budget includes rounded canary/payload and two guards.
#[test]
fn native_aggregate_budget_near_and_above_32_mib_denies_before_secret_write() {
    let initial = prepare_windows_protected_memory().expect("native quota setup");
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
    let near = windows_memory_status().unwrap();
    assert!(near.live_budget_page_bytes > 31 * 1024 * 1024);
    assert!(near.live_budget_page_bytes < near.budget_bytes);
    let final_capacity = near.budget_bytes - near.live_budget_page_bytes - 2 * near.page_bytes - 16;
    owners.push(ProtectedBytes::zeroed(final_capacity).expect("exact page-budget owner"));
    let at_limit = windows_memory_status().unwrap();
    assert_eq!(at_limit.live_budget_page_bytes, at_limit.budget_bytes);
    assert!(at_limit.live_capacity_bytes >= 31 * 1024 * 1024);
    assert!(at_limit.live_capacity_bytes < at_limit.budget_bytes);
    assert_eq!(
        at_limit.live_locked_page_bytes + 32 * 2 * at_limit.page_bytes,
        at_limit.budget_bytes
    );
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
    assert_eq!(failure.category, "page-budget");
    assert_eq!(failure.win32_error, 0);
    assert_eq!(failure.requested_capacity_bytes, 1);
    assert_eq!(
        windows_memory_status().unwrap().live_capacity_bytes,
        at_limit.live_capacity_bytes
    );
    owners[0].truncate(1);
    assert!(matches!(
        ProtectedBytes::zeroed(1),
        Err(CryptoError::ResourceUnavailable)
    ));
    drop(owners.pop());
    let replacement =
        ProtectedBytes::zeroed(final_capacity).expect("released page capacity reusable");
    assert_eq!(
        windows_memory_status().unwrap().live_budget_page_bytes,
        at_limit.budget_bytes
    );
    drop(replacement);
    drop(owners);
    let released = windows_memory_status().unwrap();
    assert_eq!(released.live_capacity_bytes, 0);
    assert_eq!(released.live_payload_page_bytes, 0);
    assert_eq!(released.live_locked_page_bytes, 0);
    assert_eq!(released.live_budget_page_bytes, 0);
    assert_eq!(released.live_regions, 0);
    println!(
        "PASS windows-page-budget near=31MiB exact={} capacity={} locked={} guards={} rejected=before-secret win32=0 released=0",
        at_limit.live_budget_page_bytes,
        at_limit.live_capacity_bytes,
        at_limit.live_locked_page_bytes,
        32 * 2 * at_limit.page_bytes
    );
}

#[test]
fn native_small_regions_exhaust_page_budget_while_logical_capacity_is_small() {
    let initial = prepare_windows_protected_memory().unwrap();
    assert_eq!(initial.live_capacity_bytes, 0);
    let charge = 3 * initial.page_bytes;
    let count = initial.budget_bytes / charge;
    let owners = (0..count)
        .map(|_| ProtectedBytes::zeroed(1).expect("real small locked region"))
        .collect::<Vec<_>>();
    let at_limit = windows_memory_status().unwrap();
    assert_eq!(at_limit.live_capacity_bytes, count);
    assert_eq!(at_limit.live_budget_page_bytes, count * charge);
    assert!(at_limit.live_budget_page_bytes + charge > at_limit.budget_bytes);
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
        .expect("explicit page-budget failure");
    assert_eq!(failure.category, "page-budget");
    assert_eq!(failure.win32_error, 0);
    assert_eq!(
        windows_memory_status().unwrap().live_budget_page_bytes,
        at_limit.live_budget_page_bytes
    );
    drop(owners);
    assert_eq!(windows_memory_status().unwrap().live_budget_page_bytes, 0);
    println!(
        "PASS windows-small-regions regions={count} capacity={count} charged={} rejected=before-secret win32=0 released=0",
        at_limit.live_budget_page_bytes
    );
}

#[test]
fn native_concurrent_owners_share_one_page_budget_and_release_pending_reservations() {
    use std::sync::{Arc, Barrier};
    let initial = prepare_windows_protected_memory().unwrap();
    assert_eq!(initial.live_capacity_bytes, 0);
    let capacity = 16 * initial.page_bytes - 16;
    let charge = 18 * initial.page_bytes;
    let start = Arc::new(Barrier::new(8));
    let threads = (0..8)
        .map(|_| {
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                let mut owners = Vec::new();
                for _ in 0..256 {
                    match ProtectedBytes::zeroed(capacity) {
                        Ok(owner) => owners.push(owner),
                        Err(CryptoError::ResourceUnavailable) => break,
                        Err(other) => panic!("unexpected allocation error: {other}"),
                    }
                }
                // The output remains alive in the join handle until it is moved
                // into the main thread's collection, so no early budget release.
                owners
            })
        })
        .collect::<Vec<_>>();
    let owners = threads
        .into_iter()
        .flat_map(|thread| thread.join().expect("native worker"))
        .collect::<Vec<_>>();
    let at_limit = windows_memory_status().unwrap();
    assert_eq!(owners.len(), initial.budget_bytes / charge);
    assert_eq!(at_limit.live_budget_page_bytes, owners.len() * charge);
    assert!(at_limit.live_budget_page_bytes + charge > initial.budget_bytes);
    assert!(matches!(
        ProtectedBytes::zeroed(capacity),
        Err(CryptoError::ResourceUnavailable)
    ));
    let failure = windows_memory_failure()
        .unwrap()
        .expect("explicit shared budget rejection");
    assert_eq!(failure.category, "page-budget");
    assert_eq!(failure.win32_error, 0);
    drop(owners);
    let released = windows_memory_status().unwrap();
    assert_eq!(released.live_capacity_bytes, 0);
    assert_eq!(released.live_budget_page_bytes, 0);
    assert_eq!(released.live_locked_page_bytes, 0);
    assert_eq!(released.live_regions, 0);
    println!(
        "PASS windows-concurrent-page-budget workers=8 charged={} rejected=page-budget win32=0 released=0",
        at_limit.live_budget_page_bytes
    );
}
