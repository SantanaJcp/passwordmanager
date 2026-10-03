// SPDX-License-Identifier: AGPL-3.0-only

use super::{build_request, parse_context};
use crate::{
    GithubProfile,
    memory_test_support::{isolated, limit},
};

#[test]
fn bearer_request_requires_locked_destination() {
    isolated(
        "github::memory_tests::bearer_request_requires_locked_destination",
        || {
            let profile = GithubProfile::parse(b"version=1\nprofile_id=github-assigned-issues/1\nintegration_id=github-rest-bearer\norigin=https://api.github.com\nconnect_port=18443\nca_der=/lab/ca.der\n").unwrap();
            let query = parse_context(b"github-assigned-issues/1\nfilter=assigned\nstate=open\nsort=updated\ndirection=desc\npage=2\nper_page=50\n").unwrap();
            let request = build_request(&profile, b"PM28P4_SYNTHETIC_PAT", &query).unwrap();
            assert!(
                request
                    .windows(b"Authorization: Bearer PM28P4_SYNTHETIC_PAT".len())
                    .any(|v| v == b"Authorization: Bearer PM28P4_SYNTHETIC_PAT")
            );
            drop(request);
            println!("PM28P4_CONTROL_READY");
            limit(0);
            assert!(
                build_request(&profile, b"PM28P4_SYNTHETIC_PAT", &query).is_err(),
                "unlocked bearer request accepted"
            );
        },
    );
}
