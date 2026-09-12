// SPDX-License-Identifier: AGPL-3.0-only

use pm_process_runner::{BuildIdentity, ProcessRequest, run};

#[test]
fn version_starts_the_real_cli_and_reports_the_linked_c_build() {
    let request = ProcessRequest::new(
        env!("CARGO_BIN_EXE_pm"),
        BuildIdentity::new("pm", env!("CARGO_PKG_VERSION")),
    )
    .args(["--version"]);

    let evidence = run(&request).expect("the CLI should start as a real process");

    assert!(evidence.termination().success());
    assert_eq!(evidence.termination().code(), Some(0));
    assert_eq!(
        evidence.stdout(),
        b"passwordmanager 0.1.0 (libsodium 1.0.22)\n"
    );
    assert!(evidence.stderr().is_empty());
    assert_eq!(evidence.build().component(), "pm");
    assert_eq!(evidence.build().build_id(), "0.1.0");
}
