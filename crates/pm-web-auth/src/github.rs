// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    fs,
    io::Write,
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
    sync::Arc,
    time::Duration,
};

use crate::plaintext::{self, Error, Json, Value};
use pm_crypto::ProtectedBytes;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
    pki_types::{CertificateDer, ServerName},
    version,
};

use crate::GithubProfile;

const MAX_HTTP_RESPONSE: usize = 1024 * 1024;
const MAX_PUBLIC_RESULT: usize = 64 * 1024;

#[derive(Eq, PartialEq)]
pub(crate) enum GithubOutcome {
    Succeeded(ProtectedBytes),
    WaitingForSso,
    Rejected,
    RateLimited,
    IntegrityFailure,
    Indeterminate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GithubQuery {
    filter: &'static str,
    state: &'static str,
    sort: &'static str,
    direction: &'static str,
    page: u64,
    per_page: u64,
}

pub(crate) fn perform(
    profile: &GithubProfile,
    token: &[u8],
    context: &[u8],
) -> Result<GithubOutcome, Error> {
    let query = parse_context(context)?;
    let request = build_request(profile, token, &query)?;
    let ca = fs::read(profile.value("ca_der")).map_err(|_| ())?;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca)).map_err(|_| ())?;
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&version::TLS13])
        .map_err(|_| ())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let socket = TcpStream::connect(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        profile.connect_port(),
    ))
    .map_err(|_| ())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| ())?;
    socket
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| ())?;
    let name = ServerName::try_from("api.github.com").map_err(|_| ())?;
    let connection = ClientConnection::new(Arc::new(config), name).map_err(|_| ())?;
    let mut tls = StreamOwned::new(connection, socket);
    tls.write_all(&request)
        .and_then(|()| tls.flush())
        .map_err(|_| ())?;
    let response = match plaintext::read_all(&mut tls, MAX_HTTP_RESPONSE) {
        Ok(response) => response,
        Err(Error::InvalidJson) => return Ok(GithubOutcome::IntegrityFailure),
        Err(error) => return Err(error),
    };
    parse_response(&response, token, &query)
}

pub(crate) fn parse_context(value: &[u8]) -> Result<GithubQuery, ()> {
    let text = std::str::from_utf8(value).map_err(|_| ())?;
    if !text.ends_with('\n') {
        return Err(());
    }
    let mut lines = text.lines();
    if lines.next() != Some("github-assigned-issues/1") {
        return Err(());
    }
    let filter = field(&mut lines, "filter")?;
    let state = field(&mut lines, "state")?;
    let sort = field(&mut lines, "sort")?;
    let direction = field(&mut lines, "direction")?;
    let page = field(&mut lines, "page")?.parse::<u64>().map_err(|_| ())?;
    let per_page = field(&mut lines, "per_page")?
        .parse::<u64>()
        .map_err(|_| ())?;
    if lines.next().is_some() {
        return Err(());
    }
    query_from_fields(filter, state, sort, direction, page, per_page)
}

fn query_from_fields(
    filter: &str,
    state: &str,
    sort: &str,
    direction: &str,
    page: u64,
    per_page: u64,
) -> Result<GithubQuery, ()> {
    fn selected(value: &str, choices: &[&'static str]) -> Result<&'static str, ()> {
        choices
            .iter()
            .copied()
            .find(|choice| *choice == value)
            .ok_or(())
    }
    if page == 0 || !(1..=100).contains(&per_page) {
        return Err(());
    }
    Ok(GithubQuery {
        filter: selected(
            filter,
            &[
                "assigned",
                "created",
                "mentioned",
                "subscribed",
                "repos",
                "all",
            ],
        )?,
        state: selected(state, &["open", "closed", "all"])?,
        sort: selected(sort, &["created", "updated", "comments"])?,
        direction: selected(direction, &["asc", "desc"])?,
        page,
        per_page,
    })
}

fn field<'a>(lines: &mut impl Iterator<Item = &'a str>, key: &str) -> Result<&'a str, ()> {
    lines
        .next()
        .and_then(|line| line.strip_prefix(key))
        .and_then(|value| value.strip_prefix('='))
        .filter(|value| !value.is_empty())
        .ok_or(())
}

pub(crate) fn build_request(
    profile: &GithubProfile,
    token: &[u8],
    query: &GithubQuery,
) -> Result<ProtectedBytes, Error> {
    if !(16..=1024).contains(&token.len()) || !token.iter().all(u8::is_ascii_graphic) {
        return Err(Error::InvalidJson);
    }
    let token = std::str::from_utf8(token).map_err(|_| ())?;
    let request = plaintext::format(format_args!(
        "GET {}?filter={}&state={}&sort={}&direction={}&page={}&per_page={} HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nAuthorization: Bearer {}\r\nX-GitHub-Api-Version: {}\r\nUser-Agent: passwordmanager/1\r\nConnection: close\r\n\r\n",
        profile.path(),
        query.filter,
        query.state,
        query.sort,
        query.direction,
        query.page,
        query.per_page,
        token,
        profile.api_version(),
    ))?;
    plaintext::encode(|output| output.put(request.as_bytes()))
}

pub(crate) fn parse_response(
    response: &[u8],
    token: &[u8],
    query: &GithubQuery,
) -> Result<GithubOutcome, Error> {
    if token.is_empty() || contains(response, token) {
        return Ok(GithubOutcome::IntegrityFailure);
    }
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(())?;
    let headers = std::str::from_utf8(&response[..split]).map_err(|_| ())?;
    let mut lines = headers.split("\r\n");
    let status = lines.next().ok_or(())?;
    let mut content_length = None;
    let mut chunked = false;
    let mut sso = None;
    let mut retry_after = None;
    let mut link = None;
    let mut location = None;
    for line in lines {
        let (name, raw) = line.split_once(':').ok_or(())?;
        let value = raw.trim();
        if value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(Error::InvalidJson);
        }
        if name.eq_ignore_ascii_case("content-length") {
            let length = value.parse::<usize>().map_err(|_| ())?;
            if content_length.replace(length).is_some() {
                return Err(Error::InvalidJson);
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case("chunked") {
                return Err(Error::InvalidJson);
            }
            chunked = true;
        } else if name.eq_ignore_ascii_case("x-github-sso") {
            if sso.replace(value).is_some() {
                return Err(Error::InvalidJson);
            }
        } else if name.eq_ignore_ascii_case("retry-after") {
            if retry_after.replace(value).is_some() {
                return Err(Error::InvalidJson);
            }
        } else if name.eq_ignore_ascii_case("link") {
            if link.replace(value).is_some() {
                return Err(Error::InvalidJson);
            }
        } else if name.eq_ignore_ascii_case("location") && location.replace(value).is_some() {
            return Err(Error::InvalidJson);
        }
    }
    if chunked && content_length.is_some() {
        return Err(Error::InvalidJson);
    }
    let body = &response[split + 4..];
    let body = if chunked {
        decode_chunked(body)?
    } else {
        if content_length.is_some_and(|length| length != body.len()) {
            return Err(Error::InvalidJson);
        }
        if body.len() > MAX_HTTP_RESPONSE {
            return Ok(GithubOutcome::IntegrityFailure);
        }
        ProtectedBytes::copy_from_slice(body).map_err(Error::from)?
    };
    if body.len() > MAX_HTTP_RESPONSE {
        return Ok(GithubOutcome::IntegrityFailure);
    }
    match status {
        "HTTP/1.1 200 OK" => success(&body, query, link),
        "HTTP/1.1 401 Unauthorized" => Ok(GithubOutcome::Rejected),
        "HTTP/1.1 403 Forbidden" | "HTTP/1.1 404 Not Found" => {
            if sso.is_some_and(valid_sso) {
                Ok(GithubOutcome::WaitingForSso)
            } else if let Some(value) = retry_after {
                if value
                    .parse::<u64>()
                    .is_ok_and(|seconds| (1..=86_400).contains(&seconds))
                {
                    Ok(GithubOutcome::RateLimited)
                } else {
                    Ok(GithubOutcome::IntegrityFailure)
                }
            } else {
                Ok(GithubOutcome::Rejected)
            }
        }
        value if value.starts_with("HTTP/1.1 3") => {
            let _ = location;
            Ok(GithubOutcome::IntegrityFailure)
        }
        value if value.starts_with("HTTP/1.1 5") => Ok(GithubOutcome::Indeterminate),
        _ => Ok(GithubOutcome::IntegrityFailure),
    }
}

fn success(body: &[u8], query: &GithubQuery, link: Option<&str>) -> Result<GithubOutcome, Error> {
    let Json::Array(items) = plaintext::parse_json(body)? else {
        return Ok(GithubOutcome::IntegrityFailure);
    };
    if items.len() > usize::try_from(query.per_page).map_err(|_| ())? {
        return Ok(GithubOutcome::IntegrityFailure);
    }
    let mut numbers = Vec::with_capacity(items.len());
    for issue in &items {
        numbers.push((
            json_u64(issue, "id")?.to_string(),
            json_u64(issue, "number")?.to_string(),
        ));
    }
    let mut public = Vec::with_capacity(items.len());
    for (issue, (id, number_text)) in items.iter().zip(&numbers) {
        let number = json_u64(issue, "number")?;
        let title = issue.field("title").and_then(Json::string).ok_or(())?;
        let state = issue.field("state").and_then(Json::string).ok_or(())?;
        let html_url = issue.field("html_url").and_then(Json::string).ok_or(())?;
        if number == 0
            || title.len() > 1024
            || !matches!(state, "open" | "closed")
            || !html_url.starts_with("https://github.com/")
            || html_url.len() > 8 * 1024
            || html_url.bytes().any(|byte| byte.is_ascii_control())
        {
            return Ok(GithubOutcome::IntegrityFailure);
        }
        public.push(Value::Object(vec![
            ("id", Value::String(id)),
            ("number", Value::Number(number_text)),
            ("title", Value::String(title)),
            ("state", Value::String(state)),
            ("html_url", Value::String(html_url)),
        ]));
    }
    let next_page = match link {
        None => None,
        Some(value) => Some(parse_next_link(value, query)?.to_string()),
    };
    let page = query.page.to_string();
    let encoded = Value::Object(vec![
        ("kind", Value::String("authenticated_http_response")),
        ("provider", Value::String("github")),
        (
            "request_profile_id",
            Value::String("github-assigned-issues/1"),
        ),
        ("status", Value::Number("200")),
        ("items", Value::Array(public)),
        ("page", Value::Number(&page)),
        (
            "next_page",
            match &next_page {
                Some(value) => Value::Number(value),
                None => Value::Null,
            },
        ),
    ])
    .encode()?;
    if encoded.len() > MAX_PUBLIC_RESULT {
        return Ok(GithubOutcome::IntegrityFailure);
    }
    Ok(GithubOutcome::Succeeded(encoded))
}

fn json_u64(value: &Json, key: &str) -> Result<u64, ()> {
    value
        .field(key)
        .and_then(Json::number)
        .ok_or(())?
        .parse()
        .map_err(|_| ())
}

fn parse_next_link(value: &str, query: &GithubQuery) -> Result<u64, ()> {
    let mut next = None;
    for part in value.split(',') {
        let part = part.trim();
        if !part.ends_with("; rel=\"next\"") {
            continue;
        }
        let url = part
            .strip_suffix("; rel=\"next\"")
            .and_then(|item| item.strip_prefix('<'))
            .and_then(|item| item.strip_suffix('>'))
            .ok_or(())?;
        let query_string = url
            .strip_prefix("https://api.github.com/issues?")
            .ok_or(())?;
        let parsed = parse_link_query(query_string)?;
        if parsed.filter != query.filter
            || parsed.state != query.state
            || parsed.sort != query.sort
            || parsed.direction != query.direction
            || parsed.per_page != query.per_page
            || parsed.page != query.page.checked_add(1).ok_or(())?
            || next.replace(parsed.page).is_some()
        {
            return Err(());
        }
    }
    next.ok_or(())
}

fn parse_link_query(value: &str) -> Result<GithubQuery, ()> {
    let mut filter = None;
    let mut state = None;
    let mut sort = None;
    let mut direction = None;
    let mut page = None;
    let mut per_page = None;
    for part in value.split('&') {
        let (key, value) = part.split_once('=').ok_or(())?;
        let target = match key {
            "filter" => &mut filter,
            "state" => &mut state,
            "sort" => &mut sort,
            "direction" => &mut direction,
            "page" => &mut page,
            "per_page" => &mut per_page,
            _ => return Err(()),
        };
        if target.replace(value).is_some() {
            return Err(());
        }
    }
    query_from_fields(
        filter.ok_or(())?,
        state.ok_or(())?,
        sort.ok_or(())?,
        direction.ok_or(())?,
        page.ok_or(())?.parse().map_err(|_| ())?,
        per_page.ok_or(())?.parse().map_err(|_| ())?,
    )
}

fn valid_sso(value: &str) -> bool {
    value.starts_with("required; ") && value.contains("url=https://github.com/")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn decode_chunked(body: &[u8]) -> Result<ProtectedBytes, Error> {
    plaintext::encode(|output| {
        let mut body = body;
        let mut total = 0_usize;
        loop {
            let line = body
                .windows(2)
                .position(|window| window == b"\r\n")
                .ok_or(())?;
            let size = usize::from_str_radix(
                std::str::from_utf8(&body[..line])
                    .map_err(|_| ())?
                    .split(';')
                    .next()
                    .ok_or(())?,
                16,
            )
            .map_err(|_| ())?;
            body = &body[line + 2..];
            if size == 0 {
                return (body == b"\r\n").then_some(()).ok_or(Error::InvalidJson);
            }
            let end = size.checked_add(2).ok_or(())?;
            total = total
                .checked_add(size)
                .filter(|n| *n <= MAX_HTTP_RESPONSE)
                .ok_or(())?;
            if body.len() < end || &body[size..end] != b"\r\n" {
                return Err(Error::InvalidJson);
            }
            output.put(&body[..size])?;
            body = &body[end..];
        }
    })
}

#[cfg(test)]
mod tests {
    use pm_interface::{Json, parse_json};

    use super::{GithubOutcome, build_request, parse_context, parse_response};
    use crate::GithubProfile;

    const TOKEN: &[u8] = b"synthetic-github-pat-canary";
    const CONTEXT: &[u8] = b"github-assigned-issues/1\nfilter=assigned\nstate=open\nsort=updated\ndirection=desc\npage=2\nper_page=50\n";

    fn profile() -> GithubProfile {
        GithubProfile::parse(
            b"version=1\nprofile_id=github-assigned-issues/1\nintegration_id=github-rest-bearer\norigin=https://api.github.com\nconnect_port=18443\nca_der=/lab/ca.der\n",
        )
        .unwrap()
    }

    #[test]
    fn request_is_fixed_and_success_is_reduced_to_the_allowed_issue_fields() {
        let query = parse_context(CONTEXT).unwrap();
        let request = build_request(&profile(), TOKEN, &query).unwrap();
        let text = std::str::from_utf8(&request).unwrap();
        assert!(text.starts_with("GET /issues?filter=assigned&state=open&sort=updated&direction=desc&page=2&per_page=50 HTTP/1.1\r\n"));
        assert!(text.contains("Host: api.github.com\r\n"));
        assert!(text.contains("Authorization: Bearer synthetic-github-pat-canary\r\n"));
        assert!(text.contains("X-GitHub-Api-Version: 2026-03-10\r\n"));
        assert!(!text.contains("reflect.invalid"));

        let body = br#"[{"id":9007199254740993,"number":7,"title":"Synthetic issue","state":"open","html_url":"https://github.com/acme/repo/issues/7","body":"forbidden","user":{"login":"private"}}]"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            std::str::from_utf8(body).unwrap()
        );
        let GithubOutcome::Succeeded(encoded) =
            parse_response(response.as_bytes(), TOKEN, &query).unwrap()
        else {
            panic!("expected success")
        };
        let result = parse_json(&encoded).unwrap();
        assert_eq!(
            result
                .field("items")
                .and_then(|value| match value {
                    Json::Array(items) => items.first(),
                    _ => None,
                })
                .and_then(|item| item.field("id"))
                .and_then(Json::string),
            Some("9007199254740993")
        );
        assert!(encoded.windows(4).all(|window| window != b"body"));
        assert!(!encoded.windows(TOKEN.len()).any(|window| window == TOKEN));
    }

    #[test]
    fn github_next_link_is_bound_to_the_exact_next_query() {
        let query = parse_context(b"github-assigned-issues/1\nfilter=assigned\nstate=open\nsort=created\ndirection=desc\npage=1\nper_page=30\n").unwrap();
        let response = b"HTTP/1.1 200 OK\r\nLink: <https://api.github.com/issues?filter=assigned&state=open&sort=created&direction=desc&page=2&per_page=30>; rel=\"next\"\r\nContent-Length: 2\r\n\r\n[]";
        assert!(matches!(
            parse_response(response, b"synthetic-token-123", &query),
            Ok(GithubOutcome::Succeeded(_))
        ));
    }

    #[test]
    fn redirects_reflection_sso_quota_and_errors_are_closed_outcomes() {
        let query = parse_context(CONTEXT).unwrap();
        let response = |status: &str, headers: &str, body: &[u8]| {
            let mut value = format!(
                "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            value.extend_from_slice(body);
            value
        };
        assert!(matches!(
            parse_response(
                &response("302 Found", "Location: https://evil.invalid/\r\n", b""),
                TOKEN,
                &query
            ),
            Ok(GithubOutcome::IntegrityFailure)
        ));
        assert!(matches!(
            parse_response(&response("200 OK", "", TOKEN), TOKEN, &query),
            Ok(GithubOutcome::IntegrityFailure)
        ));
        assert!(matches!(
            parse_response(
                &response(
                    "403 Forbidden",
                    "X-GitHub-SSO: required; url=https://github.com/orgs/acme/sso\r\n",
                    b""
                ),
                TOKEN,
                &query
            ),
            Ok(GithubOutcome::WaitingForSso)
        ));
        assert!(matches!(
            parse_response(
                &response("403 Forbidden", "Retry-After: 60\r\n", b"quota"),
                TOKEN,
                &query
            ),
            Ok(GithubOutcome::RateLimited)
        ));
        assert!(matches!(
            parse_response(
                &response("401 Unauthorized", "", b"bad token"),
                TOKEN,
                &query
            ),
            Ok(GithubOutcome::Rejected)
        ));
        assert!(matches!(
            parse_response(
                &response("500 Internal Server Error", "", b"secret error"),
                TOKEN,
                &query
            ),
            Ok(GithubOutcome::Indeterminate)
        ));
    }
}

#[cfg(test)]
#[path = "github_memory_tests.rs"]
mod memory_tests;
