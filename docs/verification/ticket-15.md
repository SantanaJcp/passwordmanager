# Ticket 15 verification evidence

Date: 2026-09-13. Requirements: R03, R08, R09, R14. Observed host: Linux
x86_64. Every credential, certificate, issue and identity used by the laboratory
is synthetic; the laboratory deletes its private state after each run.

## Implemented slice

`github-rest-bearer/1` exposes only `github-assigned-issues/1`. The caller can
select the closed `filter`, `state`, `sort`, `direction`, `page` and `per_page`
parameters. The installed profile fixes `https://api.github.com`, `GET /issues`,
the media type, API version and user agent. It accepts no URL, path, method,
header, token, `Link` or response-shape input.

The existing delegated attempt authority owns admission and idempotency. A
current-authority transaction linearizes provider use against suspension and
revocation. The token remains in the encrypted Token record/lease and crosses
only the custodian-to-adapter socket and adapter TLS request. Successful output
contains only issue ID, number, title, state and GitHub HTML URL plus bounded
pagination metadata; upstream headers and bodies are never returned.

The adapter pins its installed CA, requires TLS 1.3 and GitHub SNI, never
follows redirects, rejects token reflection, and classifies 401, ordinary
403/404, valid SSO, bounded `Retry-After`, malformed quota, redirects and 5xx
without exposing upstream diagnostics. This is not a generic bearer proxy or
business-policy engine. A real authorized GitHub account remains reserved for
ticket 33.

## TDD observations

The following failures were observed before each implementation seam:

```text
./scripts/cargo-local.sh test -p pm-interface --locked --offline
# RED: missing github_request_context
# GREEN: 5 passed

./scripts/cargo-local.sh test -p pm-cli --lib --locked --offline
# RED: typed GitHub flags rejected as INVALID_ARGUMENT
# GREEN: 1 passed

./scripts/cargo-local.sh test -p pm-vault --test delegated_authorization --locked --offline
# RED: valid GitHub attempt returned CREDENTIAL_UNAVAILABLE
# GREEN: 10 passed

./scripts/cargo-local.sh test -p pm-web-auth --test profile --locked --offline
# RED: missing GithubProfile
# GREEN: 5 passed

./scripts/cargo-local.sh test -p pm-web-auth --lib --locked --offline
# RED: missing closed GitHub request/response adapter
# GREEN: 7 passed
```

The first full process run failed closed with `INTEGRITY_FAILURE` because the
synthetic TLS server closed without TLS `close_notify`; completing the real TLS
shutdown made the successful response observable. No client-side downgrade or
alternate transport was added.

## Process evidence and limits

```text
./scripts/test-linux-github-bearer-lab.sh
PASS github-bearer profile=github-assigned-issues/1 origin+path+method+headers+query=fixed tls=1.3 uids=separate
PASS github-bearer-adversarial redirect+reflection+401+403+sso+quota+invalid-retry+5xx=closed public=reduced
PASS github-bearer-custody token=opaque idempotency=stable authority=real cancel=terminal real-github=ticket33
```

The lab uses distinct user-namespace UIDs for human, two agents, custodian,
adapter and destination. It traverses real TLS-RPK enrollment, encrypted record
creation/explicit enable, discovery, typed CLI start/status/cancel, provider
socket peer-UID enforcement and destination TLS 1.3. It asserts the exact
request line and fixed headers, stable idempotency, closed attack outcomes, and
absence of the token/upstream private fields in public output, provider logs
and custodial files.

The destination is an adversarial GitHub-protocol double, not GitHub. Thus this
ticket claims the typed security boundary and Linux process behavior only; it
does not claim live GitHub compatibility, packaging, or another platform.

## Final gates

```text
./scripts/check.sh
# exit 0; format, locked workspace check/tests and Clippy passed

./scripts/clean-offline-build.sh
# exit 0

for lab in scripts/test-linux-*-lab.sh; do "$lab"; done
# exit 0; all 16 Linux labs, including GitHub bearer, passed

git diff --check
# exit 0
```

