// SPDX-License-Identifier: AGPL-3.0-only

//! Trusted Keycloak browser adapter. Configuration is an installed, closed
//! profile; the delegated caller can select only its opaque identifier.

use std::{collections::BTreeMap, path::Path};

mod browser;
mod oidc;
mod provider;

pub use oidc::{OidcError, OidcResult};
pub use provider::serve;

const PROFILE_KEYS: [&str; 22] = [
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
    "method",
    "extension_path",
    "extension_sha256",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileError {
    Invalid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Profile {
    values: BTreeMap<String, String>,
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
        let passkey = values.contains_key("method");
        if values.len()
            != if passkey {
                PROFILE_KEYS.len()
            } else {
                PROFILE_KEYS.len() - 3
            }
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
        if passkey
            && (get(&values, "method")? != "webauthn"
                || !Path::new(get(&values, "extension_path")?).is_absolute()
                || !is_sha256(get(&values, "extension_sha256")?))
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
    pub fn is_passkey(&self) -> bool {
        self.value("method") == "webauthn"
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

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
