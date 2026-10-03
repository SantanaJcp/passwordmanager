// SPDX-License-Identifier: AGPL-3.0-only

use super::{js_string, read_cdp_message};
use crate::memory_test_support::{filled, isolated, limit};

#[test]
fn javascript_secret_requires_locked_destination() {
    isolated(
        "browser::memory_tests::javascript_secret_requires_locked_destination",
        || {
            static LARGE: [u8; 65536] = filled(b"PM28P4_SYNTHETIC_JS_", b"");

            limit(32 * 1024);
            let small = js_string("PM28\"\\\n").unwrap();
            assert!(small.as_bytes().eq(b"\"PM28\\\"\\\\\\n\""));
            drop(small);
            println!("PM28P4_CONTROL_READY");
            let result = js_string(std::str::from_utf8(&LARGE).unwrap());
            assert!(result.is_err(), "unlocked JavaScript secret accepted");
        },
    );
}

#[test]
fn cdp_source_is_locked_before_read() {
    isolated(
        "browser::memory_tests::cdp_source_is_locked_before_read",
        || {
            let mut input = std::io::Cursor::new(b"{\"id\":1,\"result\":\"PM28\"}\0");
            let small = read_cdp_message(&mut input).unwrap();
            assert_eq!(
                small.field("result").and_then(super::Json::string),
                Some("PM28")
            );
            drop(small);
            println!("PM28P4_CONTROL_READY");
            limit(0);
            let mut input = std::io::Cursor::new(b"{\"id\":1,\"result\":\"PM28\"}\0");
            let result = read_cdp_message(&mut input);
            assert_eq!(input.position(), 0, "CDP source consumed before locking");
            assert!(result.is_err(), "unlocked CDP source accepted");
        },
    );
}
