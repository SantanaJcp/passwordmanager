// SPDX-License-Identifier: AGPL-3.0-only

use pm_native_channel::{WindowsEndpoint, windows_pipe_sddl};

#[test]
fn windows_pipe_contract_is_local_scoped_and_names_two_distinct_endpoints() {
    assert_eq!(
        WindowsEndpoint::Agent
            .pipe_name("0123456789abcdef0123456789abcdef")
            .unwrap(),
        r"\\.\pipe\PasswordManager-0123456789abcdef0123456789abcdef-agent"
    );
    assert_eq!(
        WindowsEndpoint::Human
            .pipe_name("0123456789abcdef0123456789abcdef")
            .unwrap(),
        r"\\.\pipe\PasswordManager-0123456789abcdef0123456789abcdef-human"
    );
    assert!(WindowsEndpoint::Agent.pipe_name("../agent").is_err());
    assert!(WindowsEndpoint::Human.pipe_name("").is_err());

    assert_eq!(
        windows_pipe_sddl("S-1-5-80-123", "S-1-5-21-456").unwrap(),
        "O:S-1-5-80-123G:S-1-5-80-123D:P(A;;GA;;;SY)(A;;GA;;;S-1-5-80-123)(A;;GRGW;;;S-1-5-21-456)"
    );
    assert!(windows_pipe_sddl("S-1-1-0", "S-1-5-21-456").is_err());
    assert!(windows_pipe_sddl("S-1-5-80-123", "WD").is_err());
}
