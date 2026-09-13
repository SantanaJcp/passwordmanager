// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
    sync::Arc,
    time::Duration,
};

use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use pm_interface::{Json, encode_json, parse_json};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned, version};

use crate::Profile;

const MAX_HTTP_BODY: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcError {
    Network,
    InvalidResponse,
    InvalidToken,
}

#[derive(Debug, Eq, PartialEq)]
pub struct OidcResult {
    pub issuer: String,
    pub subject: String,
    pub client_id: String,
    pub audience: String,
    pub access_token: String,
    pub id_token: String,
    pub expires_at: i64,
    pub scope: String,
}

impl OidcResult {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        encode_json(&Json::Object(vec![
            ("kind".into(), Json::String("oidc_tokens".into())),
            ("issuer".into(), Json::String(self.issuer.clone())),
            ("subject".into(), Json::String(self.subject.clone())),
            ("client_id".into(), Json::String(self.client_id.clone())),
            ("audience".into(), Json::String(self.audience.clone())),
            ("token_type".into(), Json::String("Bearer".into())),
            (
                "access_token".into(),
                Json::String(self.access_token.clone()),
            ),
            ("id_token".into(), Json::String(self.id_token.clone())),
            (
                "expires_at".into(),
                Json::String(self.expires_at.to_string()),
            ),
            ("scope".into(), Json::String(self.scope.clone())),
        ]))
    }
}

pub(crate) fn exchange_code(
    profile: &Profile,
    code: &str,
    verifier: &str,
    nonce: &str,
    now: i64,
) -> Result<OidcResult, OidcError> {
    let form = format!(
        "grant_type=authorization_code&client_id={}&redirect_uri={}&code={}&code_verifier={}",
        form_component(profile.value("client_id")),
        form_component(profile.value("redirect_uri")),
        form_component(code),
        form_component(verifier),
    );
    let response = https_request(
        profile,
        "token_endpoint",
        "POST",
        "application/x-www-form-urlencoded",
        form.as_bytes(),
    )?;
    let json = parse_json(&response).map_err(|_| OidcError::InvalidResponse)?;
    let access_token = string_field(&json, "access_token")?.to_owned();
    let id_token = string_field(&json, "id_token")?.to_owned();
    if string_field(&json, "token_type")? != "Bearer" || access_token == id_token {
        return Err(OidcError::InvalidResponse);
    }
    let expires_in = uint_field(&json, "expires_in")?;
    if !(1..=86_400).contains(&expires_in) {
        return Err(OidcError::InvalidResponse);
    }
    let scope = string_field(&json, "scope")?.to_owned();
    if !scope.split(' ').any(|value| value == "openid") {
        return Err(OidcError::InvalidResponse);
    }
    let jwks = https_request(profile, "jwks_uri", "GET", "", &[])?;
    let jwks = parse_json(&jwks).map_err(|_| OidcError::InvalidResponse)?;
    let id_subject = validate_jwt(&id_token, &jwks, profile, Some(nonce), now)?;
    let access_subject = validate_jwt(&access_token, &jwks, profile, None, now)?;
    validate_subject_binding(profile, &id_subject, &access_subject)?;
    Ok(OidcResult {
        issuer: profile.value("issuer").to_owned(),
        subject: id_subject,
        client_id: profile.value("client_id").to_owned(),
        audience: profile.value("audience").to_owned(),
        access_token,
        id_token,
        expires_at: now
            .checked_add(expires_in)
            .ok_or(OidcError::InvalidResponse)?,
        scope,
    })
}

fn validate_subject_binding(
    profile: &Profile,
    id_subject: &str,
    access_subject: &str,
) -> Result<(), OidcError> {
    if id_subject != access_subject || id_subject != profile.value("expected_subject") {
        return Err(OidcError::InvalidToken);
    }
    Ok(())
}

fn validate_jwt(
    token: &str,
    jwks: &Json,
    profile: &Profile,
    nonce: Option<&str>,
    now: i64,
) -> Result<String, OidcError> {
    let mut parts = token.split('.');
    let header64 = parts.next().ok_or(OidcError::InvalidToken)?;
    let claims64 = parts.next().ok_or(OidcError::InvalidToken)?;
    let signature64 = parts.next().ok_or(OidcError::InvalidToken)?;
    if parts.next().is_some() {
        return Err(OidcError::InvalidToken);
    }
    let header = parse_segment(header64)?;
    if string_field(&header, "alg")? != "RS256"
        || header.field("crit").is_some()
        || header.field("jku").is_some()
        || header.field("jwk").is_some()
    {
        return Err(OidcError::InvalidToken);
    }
    let kid = string_field(&header, "kid")?;
    let key = jwk(jwks, kid)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature64)
        .map_err(|_| OidcError::InvalidToken)?;
    let signed = format!("{header64}.{claims64}");
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key)
        .verify(signed.as_bytes(), &signature)
        .map_err(|_| OidcError::InvalidToken)?;
    let claims = parse_segment(claims64)?;
    if string_field(&claims, "iss")? != profile.value("issuer")
        || !audience_contains(&claims, profile.value("audience"))
        || int_field(&claims, "exp")? <= now
        || claims.field("nbf").is_some()
            && int_field(&claims, "nbf").map_or(true, |value| value > now + 30)
    {
        return Err(OidcError::InvalidToken);
    }
    if let Some(expected) = nonce
        && string_field(&claims, "nonce")? != expected
    {
        return Err(OidcError::InvalidToken);
    }
    if matches!(claims.field("aud"), Some(Json::Array(values)) if values.len() > 1)
        && string_field(&claims, "azp")? != profile.value("client_id")
    {
        return Err(OidcError::InvalidToken);
    }
    Ok(string_field(&claims, "sub")?.to_owned())
}

fn parse_segment(value: &str) -> Result<Json, OidcError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| OidcError::InvalidToken)?;
    parse_json(&decoded).map_err(|_| OidcError::InvalidToken)
}

fn jwk(jwks: &Json, kid: &str) -> Result<Vec<u8>, OidcError> {
    let Some(Json::Array(keys)) = jwks.field("keys") else {
        return Err(OidcError::InvalidToken);
    };
    let mut matches = keys.iter().filter(|key| {
        key.field("kid").and_then(Json::string) == Some(kid)
            && key.field("kty").and_then(Json::string) == Some("RSA")
            && key.field("alg").and_then(Json::string) == Some("RS256")
            && key
                .field("use")
                .and_then(Json::string)
                .is_none_or(|value| value == "sig")
    });
    let key = matches.next().ok_or(OidcError::InvalidToken)?;
    if matches.next().is_some() {
        return Err(OidcError::InvalidToken);
    }
    let n = URL_SAFE_NO_PAD
        .decode(string_field(key, "n")?)
        .map_err(|_| OidcError::InvalidToken)?;
    let e = URL_SAFE_NO_PAD
        .decode(string_field(key, "e")?)
        .map_err(|_| OidcError::InvalidToken)?;
    if !(256..=1024).contains(&n.len()) || e.is_empty() || e.len() > 5 {
        return Err(OidcError::InvalidToken);
    }
    Ok(der_sequence(&[der_integer(&n), der_integer(&e)]))
}

fn der_integer(value: &[u8]) -> Vec<u8> {
    let first_nonzero = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len().saturating_sub(1));
    let value = &value[first_nonzero..];
    let mut body = Vec::with_capacity(value.len() + 1);
    if value.first().is_some_and(|byte| byte & 0x80 != 0) {
        body.push(0);
    }
    body.extend_from_slice(value);
    der(0x02, &body)
}

fn der_sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = parts.iter().flatten().copied().collect();
    der(0x30, &body)
}

fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    if body.len() < 128 {
        output.push(u8::try_from(body.len()).unwrap());
    } else {
        let bytes = body.len().to_be_bytes();
        let start = bytes.iter().position(|byte| *byte != 0).unwrap();
        output.push(0x80 | u8::try_from(bytes.len() - start).unwrap());
        output.extend_from_slice(&bytes[start..]);
    }
    output.extend_from_slice(body);
    output
}

fn audience_contains(claims: &Json, expected: &str) -> bool {
    match claims.field("aud") {
        Some(Json::String(value)) => value == expected,
        Some(Json::Array(values)) => values.iter().any(|value| value.string() == Some(expected)),
        _ => false,
    }
}

fn string_field<'a>(value: &'a Json, key: &str) -> Result<&'a str, OidcError> {
    value
        .field(key)
        .and_then(Json::string)
        .ok_or(OidcError::InvalidResponse)
}

fn int_field(value: &Json, key: &str) -> Result<i64, OidcError> {
    value
        .field(key)
        .and_then(Json::number)
        .ok_or(OidcError::InvalidToken)?
        .parse()
        .map_err(|_| OidcError::InvalidToken)
}

fn uint_field(value: &Json, key: &str) -> Result<i64, OidcError> {
    let number = value
        .field(key)
        .and_then(Json::number)
        .ok_or(OidcError::InvalidResponse)?;
    number.parse().map_err(|_| OidcError::InvalidResponse)
}

pub(crate) fn form_component(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(output, "%{byte:02X}").unwrap();
        }
    }
    output
}

pub(crate) fn https_request(
    profile: &Profile,
    endpoint: &str,
    method: &str,
    content_type: &str,
    body: &[u8],
) -> Result<Vec<u8>, OidcError> {
    let url = profile.url(endpoint).map_err(|_| OidcError::Network)?;
    let ca = fs::read(profile.value("ca_der")).map_err(|_| OidcError::Network)?;
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca))
        .map_err(|_| OidcError::Network)?;
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&version::TLS13])
        .map_err(|_| OidcError::Network)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let socket = TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, url.port()))
        .map_err(|_| OidcError::Network)?;
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| OidcError::Network)?;
    socket
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| OidcError::Network)?;
    let name = ServerName::try_from(url.host().to_owned()).map_err(|_| OidcError::Network)?;
    let connection =
        ClientConnection::new(Arc::new(config), name).map_err(|_| OidcError::Network)?;
    let mut tls = StreamOwned::new(connection, socket);
    let mut request = format!(
        "{method} {} HTTP/1.1\r\nHost: {}:{}\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: {}\r\n",
        url.path(),
        url.host(),
        url.port(),
        body.len()
    );
    if !content_type.is_empty() {
        request.push_str("Content-Type: ");
        request.push_str(content_type);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    tls.write_all(request.as_bytes())
        .and_then(|()| tls.write_all(body))
        .and_then(|()| tls.flush())
        .map_err(|_| OidcError::Network)?;
    let mut response = Vec::new();
    tls.take(u64::try_from(MAX_HTTP_BODY + 64 * 1024).unwrap())
        .read_to_end(&mut response)
        .map_err(|_| OidcError::Network)?;
    parse_http_response(&response)
}

fn parse_http_response(response: &[u8]) -> Result<Vec<u8>, OidcError> {
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(OidcError::InvalidResponse)?;
    let headers =
        std::str::from_utf8(&response[..split]).map_err(|_| OidcError::InvalidResponse)?;
    let mut lines = headers.split("\r\n");
    if lines.next() != Some("HTTP/1.1 200 OK") {
        return Err(OidcError::InvalidResponse);
    }
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(OidcError::InvalidResponse)?;
        if name.eq_ignore_ascii_case("content-length") {
            let length = value
                .trim()
                .parse::<usize>()
                .map_err(|_| OidcError::InvalidResponse)?;
            if content_length.replace(length).is_some() {
                return Err(OidcError::InvalidResponse);
            }
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.trim().eq_ignore_ascii_case("chunked") {
                return Err(OidcError::InvalidResponse);
            }
            chunked = true;
        }
    }
    if chunked && content_length.is_some() {
        return Err(OidcError::InvalidResponse);
    }
    let body = &response[split + 4..];
    let decoded = if chunked {
        decode_chunked(body)?
    } else {
        body.to_vec()
    };
    if content_length.is_some_and(|length| length != decoded.len()) || decoded.len() > MAX_HTTP_BODY
    {
        return Err(OidcError::InvalidResponse);
    }
    Ok(decoded)
}

fn decode_chunked(mut body: &[u8]) -> Result<Vec<u8>, OidcError> {
    let mut output = Vec::new();
    loop {
        let line = body
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or(OidcError::InvalidResponse)?;
        let size = usize::from_str_radix(
            std::str::from_utf8(&body[..line])
                .map_err(|_| OidcError::InvalidResponse)?
                .split(';')
                .next()
                .ok_or(OidcError::InvalidResponse)?,
            16,
        )
        .map_err(|_| OidcError::InvalidResponse)?;
        body = &body[line + 2..];
        if size == 0 {
            return (body == b"\r\n")
                .then_some(output)
                .ok_or(OidcError::InvalidResponse);
        }
        if size > MAX_HTTP_BODY || body.len() < size + 2 || &body[size..size + 2] != b"\r\n" {
            return Err(OidcError::InvalidResponse);
        }
        output.extend_from_slice(&body[..size]);
        if output.len() > MAX_HTTP_BODY {
            return Err(OidcError::InvalidResponse);
        }
        body = &body[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::{
        rand::SystemRandom,
        rsa::{KeyPair as RsaKeyPair, KeySize},
        signature::{self, KeyPair as _},
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use pm_interface::{Json, encode_json};

    use super::{OidcError, validate_jwt, validate_subject_binding};
    use crate::Profile;

    fn profile() -> Profile {
        Profile::parse(
            b"version=1\nprofile_id=keycloak-lab\nissuer=https://auth.test:8443/realms/pm\nauthorization_endpoint=https://auth.test:8443/realms/pm/protocol/openid-connect/auth\ntoken_endpoint=https://auth.test:8443/realms/pm/protocol/openid-connect/token\njwks_uri=https://auth.test:8443/realms/pm/protocol/openid-connect/certs\nclient_id=pm-browser\nredirect_uri=https://callback.test:9443/callback\nexpected_subject=synthetic-subject\nexpected_username=alice\naudience=pm-browser\nscopes=openid\nbrowser_version=153.0.8010.36\nbrowser_sha256=0000000000000000000000000000000000000000000000000000000000000000\nbrowser_path=/lab/chrome\nbrowser_home=/lab/home\nca_der=/lab/ca.der\ncallback_cert=/lab/cert.der\ncallback_key=/lab/key.der\n",
        )
        .unwrap()
    }

    fn key_and_jwks() -> (RsaKeyPair, Json) {
        let pair = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        let public = pair.public_key().as_ref();
        let mut at = 0;
        assert_eq!(public[at], 0x30);
        at += 1;
        let _ = der_len(public, &mut at);
        let n = der_integer(public, &mut at);
        let e = der_integer(public, &mut at);
        let jwks = Json::Object(vec![(
            "keys".into(),
            Json::Array(vec![Json::Object(vec![
                ("kid".into(), Json::String("lab-key".into())),
                ("kty".into(), Json::String("RSA".into())),
                ("alg".into(), Json::String("RS256".into())),
                ("use".into(), Json::String("sig".into())),
                ("n".into(), Json::String(URL_SAFE_NO_PAD.encode(n))),
                ("e".into(), Json::String(URL_SAFE_NO_PAD.encode(e))),
            ])]),
        )]);
        (pair, jwks)
    }

    fn der_len(bytes: &[u8], at: &mut usize) -> usize {
        let first = bytes[*at];
        *at += 1;
        if first & 0x80 == 0 {
            return usize::from(first);
        }
        let count = usize::from(first & 0x7f);
        let mut len = 0;
        for _ in 0..count {
            len = len * 256 + usize::from(bytes[*at]);
            *at += 1;
        }
        len
    }

    fn der_integer<'a>(bytes: &'a [u8], at: &mut usize) -> &'a [u8] {
        assert_eq!(bytes[*at], 0x02);
        *at += 1;
        let len = der_len(bytes, at);
        let value = &bytes[*at..*at + len];
        *at += len;
        value.strip_prefix(&[0]).unwrap_or(value)
    }

    fn claims(audience: &str, nonce: &str, expires: i64, subject: &str) -> Json {
        Json::Object(vec![
            (
                "iss".into(),
                Json::String("https://auth.test:8443/realms/pm".into()),
            ),
            ("aud".into(), Json::String(audience.into())),
            ("exp".into(), Json::Number(expires.to_string())),
            ("nonce".into(), Json::String(nonce.into())),
            ("sub".into(), Json::String(subject.into())),
        ])
    }

    fn multi_audience_claims(azp: &str) -> Json {
        Json::Object(vec![
            (
                "iss".into(),
                Json::String("https://auth.test:8443/realms/pm".into()),
            ),
            (
                "aud".into(),
                Json::Array(vec![
                    Json::String("pm-browser".into()),
                    Json::String("other".into()),
                ]),
            ),
            ("azp".into(), Json::String(azp.into())),
            ("exp".into(), Json::Number("200".into())),
            ("nonce".into(), Json::String("expected-nonce".into())),
            ("sub".into(), Json::String("synthetic-subject".into())),
        ])
    }

    fn signed(pair: &RsaKeyPair, claims: &Json, algorithm: &str) -> String {
        let header = Json::Object(vec![
            ("alg".into(), Json::String(algorithm.into())),
            ("kid".into(), Json::String("lab-key".into())),
        ]);
        let header = URL_SAFE_NO_PAD.encode(encode_json(&header));
        let claims = URL_SAFE_NO_PAD.encode(encode_json(claims));
        let input = format!("{header}.{claims}");
        let mut output = vec![0; pair.public_modulus_len()];
        pair.sign(
            &signature::RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            input.as_bytes(),
            &mut output,
        )
        .unwrap();
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(output))
    }

    #[test]
    fn token_claims_reject_nonce_audience_expiry_and_account_mismatch() {
        let profile = profile();
        let (pair, jwks) = key_and_jwks();
        let valid = signed(
            &pair,
            &claims("pm-browser", "expected-nonce", 200, "synthetic-subject"),
            "RS256",
        );
        assert_eq!(
            validate_jwt(&valid, &jwks, &profile, Some("expected-nonce"), 100),
            Ok("synthetic-subject".into())
        );
        assert_eq!(
            validate_jwt(&valid, &jwks, &profile, Some("wrong-nonce"), 100),
            Err(OidcError::InvalidToken)
        );
        let mut wrong_signature = valid.clone().into_bytes();
        let signature_at = wrong_signature
            .iter()
            .enumerate()
            .filter(|(_, byte)| **byte == b'.')
            .nth(1)
            .map(|(index, _)| index + 1)
            .unwrap();
        wrong_signature[signature_at] = if wrong_signature[signature_at] == b'A' {
            b'B'
        } else {
            b'A'
        };
        let wrong_signature = String::from_utf8(wrong_signature).unwrap();
        assert_eq!(
            validate_jwt(
                &wrong_signature,
                &jwks,
                &profile,
                Some("expected-nonce"),
                100
            ),
            Err(OidcError::InvalidToken)
        );
        let wrong_audience = signed(
            &pair,
            &claims("other-client", "expected-nonce", 200, "synthetic-subject"),
            "RS256",
        );
        assert_eq!(
            validate_jwt(
                &wrong_audience,
                &jwks,
                &profile,
                Some("expected-nonce"),
                100
            ),
            Err(OidcError::InvalidToken)
        );
        let mut wrong_issuer_claims =
            claims("pm-browser", "expected-nonce", 200, "synthetic-subject");
        if let Json::Object(fields) = &mut wrong_issuer_claims {
            fields[0].1 = Json::String("https://evil.test:8443/realms/pm".into());
        }
        let wrong_issuer = signed(&pair, &wrong_issuer_claims, "RS256");
        assert_eq!(
            validate_jwt(&wrong_issuer, &jwks, &profile, Some("expected-nonce"), 100),
            Err(OidcError::InvalidToken)
        );
        assert_eq!(
            validate_jwt(&valid, &jwks, &profile, Some("expected-nonce"), 200),
            Err(OidcError::InvalidToken)
        );
        let wrong_azp = signed(&pair, &multi_audience_claims("other"), "RS256");
        assert_eq!(
            validate_jwt(&wrong_azp, &jwks, &profile, Some("expected-nonce"), 100),
            Err(OidcError::InvalidToken)
        );
        let wrong_algorithm = signed(
            &pair,
            &claims("pm-browser", "expected-nonce", 200, "synthetic-subject"),
            "HS256",
        );
        assert_eq!(
            validate_jwt(
                &wrong_algorithm,
                &jwks,
                &profile,
                Some("expected-nonce"),
                100
            ),
            Err(OidcError::InvalidToken)
        );
        assert_eq!(
            validate_subject_binding(&profile, "other", "other"),
            Err(OidcError::InvalidToken)
        );
        assert_eq!(
            validate_subject_binding(&profile, "synthetic-subject", "other"),
            Err(OidcError::InvalidToken)
        );
    }
}
