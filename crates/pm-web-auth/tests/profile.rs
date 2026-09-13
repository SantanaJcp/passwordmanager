// SPDX-License-Identifier: AGPL-3.0-only

use pm_web_auth::{Profile, ProfileError};

const VALID: &str = concat!(
    "version=1\n",
    "profile_id=keycloak-lab\n",
    "issuer=https://auth.test:18443/realms/pm\n",
    "authorization_endpoint=https://auth.test:18443/realms/pm/protocol/openid-connect/auth\n",
    "token_endpoint=https://auth.test:18443/realms/pm/protocol/openid-connect/token\n",
    "jwks_uri=https://auth.test:18443/realms/pm/protocol/openid-connect/certs\n",
    "client_id=pm-browser\n",
    "redirect_uri=https://callback.test:19443/callback\n",
    "expected_subject=11111111-1111-1111-1111-111111111111\n",
    "expected_username=alice\n",
    "audience=pm-browser\n",
    "scopes=openid\n",
    "browser_version=153.0.8010.36\n",
    "browser_sha256=167a098c4fdec156b58a9f678c90a84f9072d789f9c6e7b35496a6987b8b7ef8\n",
    "browser_path=/opt/pm-lab/chrome\n",
    "browser_home=/opt/pm-lab/browser-home\n",
    "ca_der=/opt/pm-lab/ca.der\n",
    "callback_cert=/opt/pm-lab/callback.der\n",
    "callback_key=/opt/pm-lab/callback.key.der\n",
);

#[test]
fn accepts_closed_https_keycloak_profile() {
    let profile = Profile::parse(VALID.as_bytes()).unwrap();
    assert_eq!(profile.profile_id(), "keycloak-lab");
    assert_eq!(profile.browser_version(), "153.0.8010.36");
}

#[test]
fn rejects_redirect_issuer_or_unknown_profile_fields() {
    let http = VALID.replace("issuer=https://", "issuer=http://");
    assert_eq!(Profile::parse(http.as_bytes()), Err(ProfileError::Invalid));
    let wrong_callback = VALID.replace("callback.test", "auth.test");
    assert_eq!(
        Profile::parse(wrong_callback.as_bytes()),
        Err(ProfileError::Invalid)
    );
    let extra = format!("{VALID}helper=/tmp/agent-controlled\n");
    assert_eq!(Profile::parse(extra.as_bytes()), Err(ProfileError::Invalid));
    let hostile_endpoint = VALID.replace(
        "authorization_endpoint=https://auth.test:18443",
        "authorization_endpoint=https://evil.test:18443",
    );
    assert_eq!(
        Profile::parse(hostile_endpoint.as_bytes()),
        Err(ProfileError::Invalid)
    );
}

#[test]
fn rejects_unpinned_or_wrong_browser_artifact() {
    let latest = VALID.replace("browser_version=153.0.8010.36", "browser_version=latest");
    assert_eq!(
        Profile::parse(latest.as_bytes()),
        Err(ProfileError::Invalid)
    );
    let relative = VALID.replace("browser_path=/opt/pm-lab/chrome", "browser_path=chrome");
    assert_eq!(
        Profile::parse(relative.as_bytes()),
        Err(ProfileError::Invalid)
    );
}
