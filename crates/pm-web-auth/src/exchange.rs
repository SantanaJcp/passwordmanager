// SPDX-License-Identifier: AGPL-3.0-only

use pm_interface::{Json, encode_json, parse_json};
use zeroize::Zeroizing;

use crate::ExchangeProfile;
use crate::oidc::{form_component, https_request, verified_jwt_claims};

const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExchangeError {
    Network,
    InvalidResponse,
    InvalidToken,
    SecretReflection,
}

pub(crate) struct ExchangeCredential<'a> {
    pub subject_token: &'a [u8],
    pub requester_client_id: &'a str,
    pub requester_client_secret: &'a [u8],
}

pub(crate) struct ExchangeResult {
    issuer: String,
    audience: String,
    access_token: String,
    expires_at: i64,
    scope: String,
}

impl ExchangeResult {
    pub(crate) fn encode(&self) -> Vec<u8> {
        encode_json(&Json::Object(vec![
            ("kind".into(), Json::String("exchanged_access_token".into())),
            ("issuer".into(), Json::String(self.issuer.clone())),
            ("audience".into(), Json::String(self.audience.clone())),
            ("token_type".into(), Json::String("Bearer".into())),
            (
                "access_token".into(),
                Json::String(self.access_token.clone()),
            ),
            (
                "issued_token_type".into(),
                Json::String(ACCESS_TOKEN_TYPE.into()),
            ),
            (
                "expires_at".into(),
                Json::String(self.expires_at.to_string()),
            ),
            ("scope".into(), Json::String(self.scope.clone())),
        ]))
    }
}

pub(crate) fn perform(
    profile: &ExchangeProfile,
    credential: &ExchangeCredential<'_>,
    now: i64,
) -> Result<ExchangeResult, ExchangeError> {
    if credential.requester_client_id != profile.requester_client_id()
        || credential.subject_token.len() < 32
        || credential.requester_client_secret.len() < 16
    {
        return Err(ExchangeError::InvalidToken);
    }
    let subject =
        std::str::from_utf8(credential.subject_token).map_err(|_| ExchangeError::InvalidToken)?;
    let client_secret = std::str::from_utf8(credential.requester_client_secret)
        .map_err(|_| ExchangeError::InvalidToken)?;
    let form = Zeroizing::new(format!(
        "grant_type={}&subject_token={}&subject_token_type={}&requested_token_type={}&audience={}&scope={}&client_id={}&client_secret={}",
        form_component(EXCHANGE_GRANT),
        form_component(subject),
        form_component(ACCESS_TOKEN_TYPE),
        form_component(ACCESS_TOKEN_TYPE),
        form_component(profile.audience()),
        form_component(profile.scopes()),
        form_component(credential.requester_client_id),
        form_component(client_secret),
    ));
    let response = Zeroizing::new(
        https_request(
            profile
                .url("token_endpoint")
                .map_err(|_| ExchangeError::Network)?,
            profile.value("ca_der"),
            "POST",
            "application/x-www-form-urlencoded",
            form.as_bytes(),
        )
        .map_err(map_oidc)?,
    );
    if contains(&response, credential.subject_token)
        || contains(&response, credential.requester_client_secret)
    {
        return Err(ExchangeError::SecretReflection);
    }
    let json = parse_json(&response).map_err(|_| ExchangeError::InvalidResponse)?;
    if json.field("refresh_token").is_some()
        || json.field("id_token").is_some()
        || response_string(&json, "token_type")? != "Bearer"
        || response_string(&json, "issued_token_type")? != ACCESS_TOKEN_TYPE
    {
        return Err(ExchangeError::InvalidResponse);
    }
    let access_token = response_string(&json, "access_token")?.to_owned();
    if access_token == subject || access_token == client_secret || access_token.len() > 64 * 1024 {
        return Err(ExchangeError::SecretReflection);
    }
    let expires_in = response_integer(&json, "expires_in")?;
    if !(1..=86_400).contains(&expires_in) {
        return Err(ExchangeError::InvalidResponse);
    }
    let scope = response_string(&json, "scope")?.to_owned();
    if !same_scope_set(&scope, profile.scopes()) {
        return Err(ExchangeError::InvalidResponse);
    }
    let jwks = https_request(
        profile
            .url("jwks_uri")
            .map_err(|_| ExchangeError::Network)?,
        profile.value("ca_der"),
        "GET",
        "",
        &[],
    )
    .map_err(map_oidc)?;
    let jwks = parse_json(&jwks).map_err(|_| ExchangeError::InvalidResponse)?;
    let claims = verified_jwt_claims(&access_token, &jwks).map_err(map_oidc)?;
    validate_exchange_claims(
        profile,
        &claims,
        credential.subject_token,
        credential.requester_client_secret,
        now,
    )?;
    let token_expiry = integer_field(&claims, "exp")?;
    let declared_expiry = now
        .checked_add(expires_in)
        .ok_or(ExchangeError::InvalidResponse)?;
    if token_expiry < declared_expiry - 30 || token_expiry > declared_expiry + 30 {
        return Err(ExchangeError::InvalidToken);
    }
    Ok(ExchangeResult {
        issuer: profile.value("issuer").to_owned(),
        audience: profile.audience().to_owned(),
        access_token,
        expires_at: token_expiry,
        scope,
    })
}

fn map_oidc(error: crate::OidcError) -> ExchangeError {
    match error {
        crate::OidcError::Network => ExchangeError::Network,
        crate::OidcError::InvalidResponse => ExchangeError::InvalidResponse,
        crate::OidcError::InvalidToken => ExchangeError::InvalidToken,
    }
}

fn response_string<'a>(value: &'a Json, name: &str) -> Result<&'a str, ExchangeError> {
    value
        .field(name)
        .and_then(Json::string)
        .ok_or(ExchangeError::InvalidResponse)
}

fn response_integer(value: &Json, name: &str) -> Result<i64, ExchangeError> {
    value
        .field(name)
        .and_then(Json::number)
        .ok_or(ExchangeError::InvalidResponse)?
        .parse()
        .map_err(|_| ExchangeError::InvalidResponse)
}

fn validate_exchange_claims(
    profile: &ExchangeProfile,
    claims: &Json,
    subject_token: &[u8],
    requester_secret: &[u8],
    now: i64,
) -> Result<(), ExchangeError> {
    if json_contains_secret(claims, subject_token) || json_contains_secret(claims, requester_secret)
    {
        return Err(ExchangeError::SecretReflection);
    }
    if string_field(claims, "iss")? != profile.value("issuer")
        || string_field(claims, "sub")? != profile.value("expected_subject")
        || string_field(claims, "aud")? != profile.audience()
        || string_field(claims, "azp")? != profile.requester_client_id()
        || integer_field(claims, "exp")? <= now
        || !same_scope_set(string_field(claims, "scope")?, profile.scopes())
    {
        return Err(ExchangeError::InvalidToken);
    }
    Ok(())
}

fn string_field<'a>(value: &'a Json, name: &str) -> Result<&'a str, ExchangeError> {
    value
        .field(name)
        .and_then(Json::string)
        .ok_or(ExchangeError::InvalidToken)
}

fn integer_field(value: &Json, name: &str) -> Result<i64, ExchangeError> {
    value
        .field(name)
        .and_then(Json::number)
        .ok_or(ExchangeError::InvalidToken)?
        .parse()
        .map_err(|_| ExchangeError::InvalidToken)
}

fn same_scope_set(left: &str, right: &str) -> bool {
    let mut left: Vec<&str> = left.split(' ').collect();
    let mut right: Vec<&str> = right.split(' ').collect();
    left.sort_unstable();
    right.sort_unstable();
    left == right && left.windows(2).all(|pair| pair[0] != pair[1])
}

fn json_contains_secret(value: &Json, secret: &[u8]) -> bool {
    if secret.len() < 16 {
        return true;
    }
    match value {
        Json::String(value) => contains(value.as_bytes(), secret),
        Json::Array(values) => values
            .iter()
            .any(|value| json_contains_secret(value, secret)),
        Json::Object(fields) => fields
            .iter()
            .any(|(_, value)| json_contains_secret(value, secret)),
        Json::Null | Json::Bool(_) | Json::Number(_) => false,
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|candidate| candidate == needle)
}

#[cfg(test)]
mod tests {
    use pm_interface::Json;

    use super::{ExchangeError, validate_exchange_claims};
    use crate::ExchangeProfile;

    fn profile() -> ExchangeProfile {
        ExchangeProfile::parse(
            b"version=1\nprofile_id=keycloak-exchange-lab\nintegration_id=keycloak-token-exchange\nissuer=https://auth.test:8443/realms/pm\ntoken_endpoint=https://auth.test:8443/realms/pm/protocol/openid-connect/token\njwks_uri=https://auth.test:8443/realms/pm/protocol/openid-connect/certs\nrequester_client_id=pm-exchanger\nexpected_subject=subject-1\naudience=pm-target\nscopes=target.read\nca_der=/lab/ca.der\n",
        )
        .unwrap()
    }

    fn claims() -> Json {
        Json::Object(vec![
            (
                "iss".into(),
                Json::String("https://auth.test:8443/realms/pm".into()),
            ),
            ("sub".into(), Json::String("subject-1".into())),
            ("aud".into(), Json::String("pm-target".into())),
            ("azp".into(), Json::String("pm-exchanger".into())),
            ("exp".into(), Json::Number("200".into())),
            ("scope".into(), Json::String("target.read".into())),
        ])
    }

    #[test]
    fn binds_subject_actor_audience_scope_and_rejects_secret_reflection() {
        let profile = profile();
        assert_eq!(
            validate_exchange_claims(
                &profile,
                &claims(),
                b"header.subject-token.signature",
                b"requester-secret-canary",
                100,
            ),
            Ok(())
        );
        for (field, hostile) in [
            ("sub", "other-subject"),
            ("aud", "other-target"),
            ("azp", "other-actor"),
            ("scope", "excess.scope"),
        ] {
            let mut value = claims();
            let Json::Object(fields) = &mut value else {
                unreachable!()
            };
            fields.iter_mut().find(|(key, _)| key == field).unwrap().1 =
                Json::String(hostile.into());
            assert_eq!(
                validate_exchange_claims(
                    &profile,
                    &value,
                    b"header.subject-token.signature",
                    b"requester-secret-canary",
                    100,
                ),
                Err(ExchangeError::InvalidToken)
            );
        }
        let mut reflected = claims();
        let Json::Object(fields) = &mut reflected else {
            unreachable!()
        };
        fields.push((
            "echo".into(),
            Json::String("prefix-requester-secret-canary-suffix".into()),
        ));
        assert_eq!(
            validate_exchange_claims(
                &profile,
                &reflected,
                b"header.subject-token.signature",
                b"requester-secret-canary",
                100,
            ),
            Err(ExchangeError::SecretReflection)
        );
    }
}
