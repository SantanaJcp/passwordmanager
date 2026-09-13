// SPDX-License-Identifier: AGPL-3.0-only

//! Trusted web authentication adapters. Configuration is installed and closed;
//! delegated callers select only opaque request profiles.

use std::{collections::BTreeMap, path::Path};

mod browser;
mod exchange;
mod github;
mod oidc;
mod provider;

pub use oidc::{OidcError, OidcResult};
pub use provider::serve;

const PROFILE_KEYS: [&str; 19] = [
    "version",
    "profile_id",
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
    "client_id",
    "redirect_uri",
    "expected_subject",
    "expected_username",
    "audience",
    "scopes",
    "browser_version",
    "browser_sha256",
    "browser_path",
    "browser_home",
    "ca_der",
    "callback_cert",
    "callback_key",
];

const EXCHANGE_PROFILE_KEYS: [&str; 11] = [
    "version",
    "profile_id",
    "integration_id",
    "issuer",
    "token_endpoint",
    "jwks_uri",
    "requester_client_id",
    "expected_subject",
    "audience",
    "scopes",
    "ca_der",
];

const GITHUB_PROFILE_KEYS: [&str; 6] = [
    "version",
    "profile_id",
    "integration_id",
    "origin",
    "connect_port",
    "ca_der",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileError {
    Invalid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Profile {
    values: BTreeMap<String, String>,
}

/// Installed, human-owned configuration for one Keycloak Standard Token
/// Exchange v2 relationship. Requests can select only `profile_id`; endpoints,
/// requester, subject, audience and scopes are fixed here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExchangeProfile {
    values: BTreeMap<String, String>,
}

/// Installed profile for the single typed GitHub issues request. The network
/// origin, method, path and headers are not caller-controlled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubProfile {
    values: BTreeMap<String, String>,
    connect_port: u16,
}

impl GithubProfile {
    /// Parses the closed `github-rest-bearer/1` profile.
    ///
    /// # Errors
    /// Rejects unknown/duplicate fields or any origin/request profile other
    /// than the selected GitHub API contract.
    pub fn parse(bytes: &[u8]) -> Result<Self, ProfileError> {
        let text = std::str::from_utf8(bytes).map_err(|_| ProfileError::Invalid)?;
        if text.len() > 16 * 1024 || !text.ends_with('\n') {
            return Err(ProfileError::Invalid);
        }
        let mut values = BTreeMap::new();
        for line in text.lines() {
            let (key, value) = line.split_once('=').ok_or(ProfileError::Invalid)?;
            if !GITHUB_PROFILE_KEYS.contains(&key)
                || value.is_empty()
                || values.insert(key.to_owned(), value.to_owned()).is_some()
            {
                return Err(ProfileError::Invalid);
            }
        }
        let port = get(&values, "connect_port")?
            .parse::<u16>()
            .map_err(|_| ProfileError::Invalid)?;
        if values.len() != GITHUB_PROFILE_KEYS.len()
            || get(&values, "version")? != "1"
            || get(&values, "profile_id")? != "github-assigned-issues/1"
            || get(&values, "integration_id")? != "github-rest-bearer"
            || get(&values, "origin")? != "https://api.github.com"
            || port == 0
            || !Path::new(get(&values, "ca_der")?).is_absolute()
        {
            return Err(ProfileError::Invalid);
        }
        Ok(Self {
            values,
            connect_port: port,
        })
    }

    #[must_use]
    pub fn profile_id(&self) -> &str {
        self.value("profile_id")
    }

    #[must_use]
    pub fn origin(&self) -> &str {
        self.value("origin")
    }

    #[must_use]
    pub const fn connect_port(&self) -> u16 {
        self.connect_port
    }

    #[must_use]
    pub const fn path(&self) -> &'static str {
        "/issues"
    }

    #[must_use]
    pub const fn api_version(&self) -> &'static str {
        "2026-03-10"
    }

    pub(crate) fn value(&self, key: &str) -> &str {
        self.values.get(key).expect("validated GitHub profile")
    }
}

impl ExchangeProfile {
    /// Parses the closed `keycloak-token-exchange/1` installed profile.
    ///
    /// # Errors
    /// Returns [`ProfileError::Invalid`] for unknown/duplicate fields, a
    /// non-HTTPS or cross-origin endpoint, or an unbounded profile value.
    pub fn parse(bytes: &[u8]) -> Result<Self, ProfileError> {
        let text = std::str::from_utf8(bytes).map_err(|_| ProfileError::Invalid)?;
        if text.len() > 16 * 1024 || !text.ends_with('\n') {
            return Err(ProfileError::Invalid);
        }
        let mut values = BTreeMap::new();
        for line in text.lines() {
            let (key, value) = line.split_once('=').ok_or(ProfileError::Invalid)?;
            if !EXCHANGE_PROFILE_KEYS.contains(&key)
                || value.is_empty()
                || values.insert(key.to_owned(), value.to_owned()).is_some()
            {
                return Err(ProfileError::Invalid);
            }
        }
        if values.len() != EXCHANGE_PROFILE_KEYS.len()
            || get(&values, "version")? != "1"
            || get(&values, "integration_id")? != "keycloak-token-exchange"
            || !is_identifier(get(&values, "profile_id")?, 128)
            || !is_identifier(get(&values, "requester_client_id")?, 128)
            || !is_identifier(get(&values, "audience")?, 128)
            || !is_subject(get(&values, "expected_subject")?)
            || !valid_exchange_scopes(get(&values, "scopes")?)
            || !Path::new(get(&values, "ca_der")?).is_absolute()
        {
            return Err(ProfileError::Invalid);
        }
        let issuer = HttpsUrl::parse(get(&values, "issuer")?)?;
        if issuer.query.is_some() || issuer.path == "/" {
            return Err(ProfileError::Invalid);
        }
        for key in ["token_endpoint", "jwks_uri"] {
            let endpoint = HttpsUrl::parse(get(&values, key)?)?;
            if endpoint.origin() != issuer.origin() || endpoint.query.is_some() {
                return Err(ProfileError::Invalid);
            }
        }
        Ok(Self { values })
    }

    #[must_use]
    pub fn profile_id(&self) -> &str {
        self.value("profile_id")
    }

    #[must_use]
    pub fn requester_client_id(&self) -> &str {
        self.value("requester_client_id")
    }

    #[must_use]
    pub fn audience(&self) -> &str {
        self.value("audience")
    }

    #[must_use]
    pub fn scopes(&self) -> &str {
        self.value("scopes")
    }

    #[must_use]
    pub fn value(&self, key: &str) -> &str {
        self.values.get(key).map_or("", String::as_str)
    }

    pub(crate) fn url(&self, key: &str) -> Result<HttpsUrl<'_>, ProfileError> {
        HttpsUrl::parse(self.value(key))
    }
}

impl Profile {
    /// Parses the closed `keycloak-browser-oidc/1` installed profile.
    ///
    /// # Errors
    /// Returns [`ProfileError::Invalid`] for unknown/duplicate fields, non-HTTPS
    /// endpoints, an unfixed browser, or paths that are not absolute.
    pub fn parse(bytes: &[u8]) -> Result<Self, ProfileError> {
        let text = std::str::from_utf8(bytes).map_err(|_| ProfileError::Invalid)?;
        if text.len() > 16 * 1024 || !text.ends_with('\n') {
            return Err(ProfileError::Invalid);
        }
        let mut values = BTreeMap::new();
        for line in text.lines() {
            let (key, value) = line.split_once('=').ok_or(ProfileError::Invalid)?;
            if !PROFILE_KEYS.contains(&key)
                || value.is_empty()
                || values.insert(key.to_owned(), value.to_owned()).is_some()
            {
                return Err(ProfileError::Invalid);
            }
        }
        if values.len() != PROFILE_KEYS.len()
            || get(&values, "version")? != "1"
            || get(&values, "browser_version")? != "153.0.8010.36"
            || !is_identifier(get(&values, "profile_id")?, 128)
            || !is_identifier(get(&values, "client_id")?, 128)
            || !is_identifier(get(&values, "audience")?, 128)
            || !is_subject(get(&values, "expected_subject")?)
            || !is_subject(get(&values, "expected_username")?)
            || !valid_scopes(get(&values, "scopes")?)
            || !is_sha256(get(&values, "browser_sha256")?)
        {
            return Err(ProfileError::Invalid);
        }
        for key in [
            "browser_path",
            "browser_home",
            "ca_der",
            "callback_cert",
            "callback_key",
        ] {
            if !Path::new(get(&values, key)?).is_absolute() {
                return Err(ProfileError::Invalid);
            }
        }
        let issuer = HttpsUrl::parse(get(&values, "issuer")?)?;
        if issuer.query.is_some() || issuer.path == "/" {
            return Err(ProfileError::Invalid);
        }
        for key in ["authorization_endpoint", "token_endpoint", "jwks_uri"] {
            let endpoint = HttpsUrl::parse(get(&values, key)?)?;
            if endpoint.origin() != issuer.origin() || endpoint.query.is_some() {
                return Err(ProfileError::Invalid);
            }
        }
        let callback = HttpsUrl::parse(get(&values, "redirect_uri")?)?;
        if callback.host == issuer.host
            || callback.origin() == issuer.origin()
            || callback.path != "/callback"
            || callback.query.is_some()
        {
            return Err(ProfileError::Invalid);
        }
        Ok(Self { values })
    }

    #[must_use]
    pub fn profile_id(&self) -> &str {
        self.value("profile_id")
    }

    #[must_use]
    pub fn browser_version(&self) -> &str {
        self.value("browser_version")
    }

    #[must_use]
    pub fn value(&self, key: &str) -> &str {
        self.values.get(key).map_or("", String::as_str)
    }

    pub(crate) fn url(&self, key: &str) -> Result<HttpsUrl<'_>, ProfileError> {
        HttpsUrl::parse(self.value(key))
    }
}

fn get<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, ProfileError> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or(ProfileError::Invalid)
}

fn is_identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_subject(value: &str) -> bool {
    value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn valid_scopes(value: &str) -> bool {
    value.split(' ').any(|scope| scope == "openid")
        && value.len() <= 512
        && value.split(' ').all(|scope| is_identifier(scope, 64))
}

fn valid_exchange_scopes(value: &str) -> bool {
    value.len() <= 512
        && !value.is_empty()
        && value.split(' ').all(|scope| is_identifier(scope, 64))
        && {
            let mut scopes: Vec<_> = value.split(' ').collect();
            scopes.sort_unstable();
            scopes.windows(2).all(|pair| pair[0] != pair[1])
        }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpsUrl<'a> {
    host: &'a str,
    port: u16,
    path: &'a str,
    query: Option<&'a str>,
}

impl<'a> HttpsUrl<'a> {
    /// Parses the narrow HTTPS URL form permitted by an installed profile.
    ///
    /// # Errors
    /// Rejects userinfo, fragments, IP literals, implicit ports, and malformed paths.
    pub fn parse(value: &'a str) -> Result<Self, ProfileError> {
        let rest = value
            .strip_prefix("https://")
            .ok_or(ProfileError::Invalid)?;
        if rest.contains(['@', '#']) {
            return Err(ProfileError::Invalid);
        }
        let slash = rest.find('/').ok_or(ProfileError::Invalid)?;
        let authority = &rest[..slash];
        let (host, port) = authority.rsplit_once(':').ok_or(ProfileError::Invalid)?;
        if !valid_host(host) {
            return Err(ProfileError::Invalid);
        }
        let port = port.parse::<u16>().map_err(|_| ProfileError::Invalid)?;
        if port == 0 {
            return Err(ProfileError::Invalid);
        }
        let path_query = &rest[slash..];
        let (path, query) = path_query
            .split_once('?')
            .map_or((path_query, None), |(path, query)| (path, Some(query)));
        if !path.starts_with('/') || path.contains("//") || path.contains("..") {
            return Err(ProfileError::Invalid);
        }
        Ok(Self {
            host,
            port,
            path,
            query,
        })
    }

    #[must_use]
    pub fn origin(&self) -> (&str, u16) {
        (self.host, self.port)
    }

    #[must_use]
    pub const fn host(&self) -> &str {
        self.host
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub const fn path(&self) -> &str {
        self.path
    }
}

fn valid_host(host: &str) -> bool {
    host.contains('.')
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}
