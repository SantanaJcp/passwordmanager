# Ticket 10 verification evidence

Date: 2026-09-13. Requirements: R03, R08, R09, R13, R14. Observed host:
Linux x86_64. All identities, credentials, certificates and Keycloak accounts
are synthetic; the laboratory is deleted after each run.

## Implemented slice

`pm-web-auth` is a trusted, custodian-only `keycloak-browser-oidc/1` adapter.
It accepts only an installed closed profile, checks the browser executable
version and SHA-256, creates a mode-0700 profile per attempt, and drives Chrome
for Testing through inherited CDP descriptors 3/4. It opens no DevTools TCP
port, does not use the user's Chrome/Chromium profile, clears the child
environment, disables extensions/downloads/background services, and does not
pass `--no-sandbox`. The provider Unix socket authenticates the existing
custodian UID with `SO_PEERCRED` before reading a request.

The browser recognizes the exact Keycloak 26.7.3 standard login and OTP form
IDs. Before inserting password material it requires the top frame, installed
issuer origin, text/password input types, and a form action on the issuer
origin. The OTP seed and generated code remain inside the trusted adapter.
Required-action forms return `WAITING_FOR_HUMAN`; reconciliation carries no
password and cancel remains terminal through the ticket-08 attempt engine.

The adapter performs Authorization Code + PKCE S256 with fresh state, nonce and
verifier. Its TLS-1.3 callback requires the installed host, exact `/callback`
path and state. The token endpoint is HTTPS, does not follow redirects, and the
adapter validates RS256/JWKS, issuer, audience, `azp` for multiple audiences,
expiry, nonce, and the same expected subject in ID/access tokens. Only the
closed ten-field `oidc_tokens` result crosses CLI/MCP; unknown or extended
provider results remain rejected/redacted. No refresh or browser session is
handed off.

Primary contracts used: [OIDC Core code flow and token
validation](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth),
[PKCE](https://www.rfc-editor.org/rfc/rfc7636.html#section-4),
[RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.html),
[Keycloak OIDC code flow](https://www.keycloak.org/securing-apps/oidc-layers#_authorization_code),
and Chromium's [pipe descriptor
implementation](https://chromium.googlesource.com/chromium/src/+/dbfe56b09b3e95b3587ff93fdf0e12a77d3ca36a).

## Fixed laboratory artifacts

`scripts/fetch-ticket10-lab-artifacts.sh` has no floating lookup. It fetches
only these repository-local disposable instruments and verifies byte lengths
and hashes before extraction:

| Artifact | Observed bytes | SHA-256 |
|---|---:|---|
| Keycloak `keycloak-26.7.3.tar.gz` | 176,448,763 | `77657f30b7e90d70f727712ce1c967f430fd6a5e9f458d32d8c6df0635345f47` |
| CFT `chrome-linux64-153.0.8010.36.zip` | 195,711,476 | `167a098c4fdec156b58a9f678c90a84f9072d789f9c6e7b35496a6987b8b7ef8` |
| extracted CFT `chrome` | 293,100,864 | `79a4ebf6da53e4ceab11844257aabc5166f17b595dc694d6382cbee8ff50565f` |

Keycloak's hash and size are published on the [official 26.7.3
release](https://github.com/keycloak/keycloak/releases/tag/26.7.3). CFT version
153.0.8010.36/revision r1681091 is in the [official availability
manifest](https://googlechromelabs.github.io/chrome-for-testing/); because that
manifest publishes URLs rather than SHA-256, the archive/executable hashes
above are the exact bytes observed and subsequently pinned by this lab.
Extraction occupied approximately 935 MiB; the host had 738 GiB free before
download. Nothing is tracked from `.scratch/lab-artifacts`.

## TDD and executable evidence

Red observations included: the new profile tests did not compile before the
crate existed; a callback on the issuer hostname was initially accepted; the
first real OTP flow reached Keycloak but exposed an unrecognized real
`kc-update-profile-form`; and the required-action lab initially had no matching
vault credential. Each was followed by the narrow implementation/profile or
fixture correction. The RFC 6238 SHA-1 vector at time 59 is independently
checked (`94287082` for eight digits).

Focused tests:

```text
./scripts/cargo-local.sh test -p pm-web-auth -p pm-interface --locked --offline
# pm-web-auth: 6 passed; pm-interface: 3 passed

./scripts/cargo-local.sh test -p pm-vault --test delegated_authorization --locked --offline
# 6 passed

./scripts/cargo-local.sh test -p pm-cli --test delegated --locked --offline
# 2 passed
```

Real provider/browser lab:

```text
./scripts/test-linux-web-auth-lab.sh
PASS web-auth-p1 keycloak=26.7.3 browser=CFT-153.0.8010.36 oidc=code+PKCE-S256 password+totp=real callback=TLS1.3
PASS web-auth-isolation provider-uid=5 agent-uid=3 cdp=pipe profile=private original-secrets=absent tokens=new
PASS web-auth-adversarial dom=form-action+iframe presecret=denied proc-mem+cdp-fds=denied
PASS web-auth-challenge keycloak-required-action=UPDATE_PASSWORD state=WAITING_FOR_HUMAN cancel=CANCELLED no-resume
LIMIT product-browser=Chromium-own-NOT_RUN six-native-targets=ticket33 cross-platform=NOT_RUN
```

The lab starts the official Keycloak distribution with HTTPS only and a
real imported realm/public OIDC client. Separate user-namespace UIDs represent
custodian, human, two agents, adapter and destination. It runs the existing
TLS-1.3/RPK custody service plus public CLI discovery/start/status/cancel.
The live hostile form-action and top-document-with-login-in-iframe fixtures
receive no POST or secret canary. A mismatched installed account is rejected
before the browser makes even a GET. The agent cannot traverse the provider
profile/browser home or read provider/browser `/proc/*/mem` or the browser's
CDP descriptors 3/4. The observed browser command line contains the pipe flag
and no remote-debugging port. Agent output, persisted regular files and adapter
logs contain neither synthetic password nor TOTP seed; per-attempt browser
profiles are absent after terminal outcomes.

Final checks at candidate time:

```text
./scripts/cargo-local.sh check --workspace --all-targets --locked --offline
./scripts/cargo-local.sh test --workspace --locked --offline
./scripts/cargo-local.sh clippy --workspace --all-targets --locked --offline -- -D warnings
git diff --check
./scripts/clean-offline-build.sh
# removed 10,790 files / 2.0 GiB; clean locked/offline build finished in 32.90 s
```

## Exact limits

- The executed browser is **Google Chrome for Testing 153.0.8010.36**, a
  disposable Linux x86_64 conformance instrument. It is not the
  Chromium-from-source, product-packaged artifact required by tickets 29/33.
  No Chrome account or normal host profile was used.
- Only Linux x86_64 was run. Linux AArch64, both macOS targets, Windows x64 and
  Windows ARM64 remain ticket 33; no native compatibility claim is closed here.
- The user-namespace run exercises live hostile DOM/iframe and Unix process/
  descriptor denial, but it is evidence for this disposable Linux profile, not
  a declaration that R09 or every G7 host control is globally closed.
- Adversarial installed issuer/origin/redirect/account configuration fails
  before credential insertion; callback host/path/state tests and signed JWT
  tests reject signature algorithm, audience/`azp`, nonce, expiry and subject
  after those response values exist but before success/token delivery. This is
  the protocol ordering required by G3 and OIDC Core §3.1.3.7.

Consequently this is a complete implementation candidate for Ticket 10's
observable Linux/CFT laboratory slice, not evidence that production P1
delivery, own-Chromium packaging, R09 as a whole, or six-target compatibility
is closed. Formal Astra review remains the final DAG gate and merger
verification is still separate.
