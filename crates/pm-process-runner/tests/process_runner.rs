// SPDX-License-Identifier: AGPL-3.0-only

use pm_process_runner::{BuildIdentity, Canary, CanaryLocation, ProcessRequest, run};
use std::time::{Duration, Instant};
#[cfg(unix)]
use std::{
    fs,
    os::unix::{ffi::OsStringExt, fs::PermissionsExt},
    process::Command,
};

const STDOUT_CANARY: &str = "SYNTHETIC_TICKET01_STDOUT_CANARY";
const STDERR_CANARY: &str = "SYNTHETIC_TICKET01_STDERR_CANARY";
const FILE_CANARY: &str = "SYNTHETIC_TICKET01_FILE_CANARY";

#[cfg(unix)]
#[test]
#[ignore = "helper process for the public Drop diagnostic regression"]
fn cleanup_failure_child() {
    let report = std::env::var_os("PM_RUNNER_CLEANUP_REPORT").expect("report path is required");
    let request = ProcessRequest::new(
        "/bin/sh",
        BuildIdentity::new("synthetic-cleanup-probe", "ticket-28-red"),
    )
    .args(["-c", "mkdir blocked; printf synthetic > blocked/artifact; chmod 0500 blocked"]);
    let evidence = run(&request).expect("the fixture child should run");
    fs::write(report, evidence.working_directory().as_os_str().as_encoded_bytes())
        .expect("the owned path should be reported to the parent fixture");
    drop(evidence);
}

#[cfg(unix)]
#[test]
fn drop_reports_an_owned_temporary_directory_cleanup_failure() {
    let report = std::env::temp_dir().join(format!(
        "pm-runner-cleanup-report-{}",
        std::process::id()
    ));
    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .args(["--exact", "cleanup_failure_child", "--ignored", "--nocapture"])
        .env("PM_RUNNER_CLEANUP_REPORT", &report)
        .output()
        .expect("cleanup helper process should start");
    let owned = std::path::PathBuf::from(std::ffi::OsString::from_vec(
        fs::read(&report).expect("cleanup helper should report its owned path"),
    ));

    let result = std::panic::catch_unwind(|| {
        assert!(output.status.success(), "cleanup helper failed before Drop");
        assert!(owned.is_dir(), "the failed cleanup must leave observable evidence");
        assert!(
            output.stderr.windows(b"CLEANUP_FAILED".len()).any(|window| window == b"CLEANUP_FAILED"),
            "Drop discarded the owned directory cleanup failure"
        );
    });

    fs::set_permissions(owned.join("blocked"), fs::Permissions::from_mode(0o700))
        .expect("fixture should restore the exact owned directory");
    fs::remove_dir_all(&owned).expect("fixture should remove the exact owned directory");
    fs::remove_file(&report).expect("fixture should remove its exact report");
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

#[cfg(unix)]
#[test]
fn runs_a_real_process_in_an_owned_temporary_directory_and_records_evidence() {
    let script = format!(
        "printf '%s' '{STDOUT_CANARY}'; printf '%s' '{STDERR_CANARY}' >&2; \
         printf '%s' '{FILE_CANARY}' > artifact.bin; exit 23"
    );
    let request = ProcessRequest::new(
        "/bin/sh",
        BuildIdentity::new("synthetic-process-probe", "ticket-01-red-green"),
    )
    .args(["-c", script.as_str()])
    .canaries([
        Canary::new("stdout-canary", STDOUT_CANARY.as_bytes()),
        Canary::new("stderr-canary", STDERR_CANARY.as_bytes()),
        Canary::new("file-canary", FILE_CANARY.as_bytes()),
    ]);

    let evidence = run(&request).expect("the real child process should start");

    assert_eq!(evidence.termination().code(), Some(23));
    assert!(!evidence.termination().success());
    assert_eq!(evidence.stdout(), STDOUT_CANARY.as_bytes());
    assert_eq!(evidence.stderr(), STDERR_CANARY.as_bytes());
    assert_eq!(evidence.build().component(), "synthetic-process-probe");
    assert_eq!(evidence.build().build_id(), "ticket-01-red-green");
    assert!(evidence.working_directory().is_dir());
    assert_eq!(
        std::fs::read(evidence.working_directory().join("artifact.bin"))
            .expect("the child's artifact should remain observable"),
        FILE_CANARY.as_bytes()
    );
    assert_eq!(
        evidence.canary("stdout-canary").unwrap().locations(),
        &[CanaryLocation::Argument(1), CanaryLocation::Stdout]
    );
    assert_eq!(
        evidence.canary("stderr-canary").unwrap().locations(),
        &[CanaryLocation::Argument(1), CanaryLocation::Stderr]
    );
    assert_eq!(
        evidence.canary("file-canary").unwrap().locations(),
        &[
            CanaryLocation::Argument(1),
            CanaryLocation::TemporaryFile("artifact.bin".into()),
        ]
    );
}

#[cfg(unix)]
#[test]
fn uses_a_fresh_temporary_directory_for_each_process() {
    let request = ProcessRequest::new(
        "/bin/sh",
        BuildIdentity::new("synthetic-process-probe", "ticket-01-red-green"),
    )
    .args(["-c", "pwd"]);

    let first = run(&request).unwrap();
    let second = run(&request).unwrap();

    assert_ne!(first.working_directory(), second.working_directory());
    assert_eq!(
        String::from_utf8_lossy(first.stdout()).trim(),
        first.working_directory().to_string_lossy()
    );
    assert_eq!(
        String::from_utf8_lossy(second.stdout()).trim(),
        second.working_directory().to_string_lossy()
    );
}

#[cfg(unix)]
#[test]
fn records_only_the_effective_environment_value() {
    let request = ProcessRequest::new(
        "/bin/sh",
        BuildIdentity::new("synthetic-process-probe", "ticket-01-red-green"),
    )
    .args(["-c", "printf '%s' \"$PM_CANARY\""])
    .env("PM_CANARY", STDOUT_CANARY)
    .env("PM_CANARY", "replacement")
    .canaries([Canary::new("replaced-canary", STDOUT_CANARY.as_bytes())]);

    let evidence = run(&request).unwrap();

    assert_eq!(evidence.stdout(), b"replacement");
    assert!(
        evidence
            .canary("replaced-canary")
            .unwrap()
            .locations()
            .is_empty()
    );
}

#[cfg(unix)]
#[test]
fn refuses_ambient_environment_inheritance_when_tracking_canaries() {
    let request = ProcessRequest::new(
        "/bin/sh",
        BuildIdentity::new("synthetic-process-probe", "ticket-01-red-green"),
    )
    .args(["-c", "exit 0"])
    .inherit_environment(true)
    .canaries([Canary::new("environment-canary", STDOUT_CANARY.as_bytes())]);

    let error = run(&request).unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[cfg(unix)]
#[test]
fn times_out_and_terminates_a_process_tree() {
    let request = ProcessRequest::new(
        "/bin/sh",
        BuildIdentity::new("synthetic-process-probe", "ticket-01-red-green"),
    )
    .args(["-c", "sleep 30 & wait"])
    .timeout(Duration::from_millis(50));
    let started = Instant::now();

    let evidence = run(&request).unwrap();

    assert!(evidence.termination().timed_out());
    assert!(!evidence.termination().success());
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[cfg(unix)]
#[test]
fn timeout_still_applies_after_the_process_group_leader_exits() {
    let request = ProcessRequest::new(
        "/bin/sh",
        BuildIdentity::new("synthetic-process-probe", "ticket-01-red-green"),
    )
    .args(["-c", "sleep 1 & exit 0"])
    .timeout(Duration::from_millis(50));
    let started = Instant::now();

    let evidence = run(&request).unwrap();

    assert!(evidence.termination().timed_out());
    assert!(started.elapsed() < Duration::from_millis(500));
}

#[cfg(unix)]
#[test]
fn bounds_captured_output_and_marks_the_canary_scan_incomplete() {
    let request = ProcessRequest::new(
        "/bin/sh",
        BuildIdentity::new("synthetic-process-probe", "ticket-01-red-green"),
    )
    .args(["-c", "head -c 128 /dev/zero"])
    .output_limit(16);

    let evidence = run(&request).unwrap();

    assert_eq!(evidence.stdout().len(), 16);
    assert!(evidence.stdout_truncated());
    assert!(!evidence.canary_scan_complete());
}
