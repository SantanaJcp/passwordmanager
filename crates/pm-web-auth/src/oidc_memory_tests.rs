// SPDX-License-Identifier: AGPL-3.0-only

use super::{form_component, parse_http_response, parse_json};
use crate::memory_test_support::{filled, isolated, limit};

#[test]
fn http_fixed_body_requires_locked_destination() {
    isolated(
        "oidc::memory_tests::http_fixed_body_requires_locked_destination",
        || {
            const HEADER: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n\r\n";
            static LARGE: [u8; HEADER.len() + 65536] = filled(HEADER, b"");

            limit(32 * 1024);
            let small =
                parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nPM28").unwrap();
            assert!((&small[..]).eq(b"PM28"));
            drop(small);
            println!("PM28P4_CONTROL_READY");
            assert!(
                parse_http_response(&LARGE).is_err(),
                "unlocked fixed HTTP body accepted"
            );
        },
    );
}

#[test]
fn http_chunked_body_requires_locked_destination() {
    isolated(
        "oidc::memory_tests::http_chunked_body_requires_locked_destination",
        || {
            const HEADER: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10000\r\n";
            static LARGE: [u8; HEADER.len() + 65536 + 7] = filled(HEADER, b"\r\n0\r\n\r\n");

            limit(32 * 1024);
            let small = parse_http_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nPM28\r\n0\r\n\r\n",
            )
            .unwrap();
            assert!((&small[..]).eq(b"PM28"));
            drop(small);
            println!("PM28P4_CONTROL_READY");
            assert!(
                parse_http_response(&LARGE).is_err(),
                "unlocked chunked HTTP body accepted"
            );
        },
    );
}

#[test]
fn form_secret_requires_locked_destination() {
    isolated(
        "oidc::memory_tests::form_secret_requires_locked_destination",
        || {
            static LARGE: [u8; 65536] = filled(b"PM28P4_SYNTHETIC_FORM_", b"");

            limit(32 * 1024);
            let small = form_component("PM28 +").unwrap();
            assert!(small.as_bytes().eq(b"PM28%20%2B"));
            drop(small);
            println!("PM28P4_CONTROL_READY");
            let result = form_component(std::str::from_utf8(&LARGE).unwrap());
            assert!(result.is_err(), "unlocked form secret accepted");
        },
    );
}

#[test]
fn json_source_requires_locked_destination() {
    isolated(
        "oidc::memory_tests::json_source_requires_locked_destination",
        || {
            const PREFIX: &[u8] = b"{\"access_token\":\"PM28P4_SYNTHETIC_JSON_";
            static LARGE: [u8; 65536 + PREFIX.len() + 2] = filled(PREFIX, b"\"}");

            limit(32 * 1024);
            let small = parse_json(br#"{"token":"PM28","n":42}"#).unwrap();
            assert_eq!(
                small.field("token").and_then(super::Json::string),
                Some("PM28")
            );
            drop(small);
            println!("PM28P4_CONTROL_READY");
            assert!(parse_json(&LARGE).is_err(), "unlocked JSON source accepted");
        },
    );
}
