# Ticket 11 verification evidence

Date: 2026-09-13. Requirements: R03, R08, R09, R14. Observed host: Linux
x86_64. Keycloak realm, tokens, requester secret, certificates and all user
identities were synthetic and the laboratory deleted them after every run.

## Implemented slice

`keycloak-token-exchange/1` is a closed trusted-adapter profile for Keycloak
26.7.3 Standard Token Exchange v2. A single human-created Token record binds
the stored subject token and confidential requester credential to one installed
profile. Agent discovery/start can choose only that profile ID and the fixed
`token_exchange` method; issuer, same-origin TLS endpoint/JWKS, expected
subject, requester, audience and exact scopes are profile-owned.

The custodian rechecks current item revision and delegated subject/generation
inside a SQLite immediate transaction that linearizes the one provider POST
against human suspension/revocation. If authority committed first, the POST
closure is not called. A POST already linearized may issue token B; the product
does not claim to revoke B afterward. Crashed provider work is terminally
indeterminate. Existing reconciliation may query adapter state, but never sends
the stored inputs or replays the exchange POST.

The adapter uses TLS 1.3, does not follow redirects, and sends only the fixed
RFC 8693 access-token exchange form. It rejects refresh/ID tokens, non-Bearer or
wrong issued types, malformed/oversized responses, and a result equal to or
containing either stored input. It verifies the RS256 signature from the fixed
JWKS endpoint, issuer, expected subject, singleton audience, requester `azp`,
expiry and exact scopes. Only the closed eight-string
`exchanged_access_token` result can cross the public CLI boundary.

Primary-source constraints and implementation rationale are recorded in
[the runtime research note](../research/keycloak-token-exchange-v2-runtime.md).

## TDD red/green observations

The following red failures were observed before their corresponding minimal
implementation:

```text
./scripts/cargo-local.sh test -p pm-web-auth --test profile --locked --offline
# RED: unresolved import `pm_web_auth::ExchangeProfile`
# GREEN: 4 passed

./scripts/cargo-local.sh test -p pm-vault --test delegated_authorization \
  keycloak_exchange_lease_is_context_bound_and_rechecked_before_provider_use \
  --locked --offline
# RED: missing AuthRecord::TokenExchange / subject_token / authority-use gate
# GREEN: 1 passed

./scripts/cargo-local.sh test -p pm-interface \
  only_the_closed_oidc_result_crosses_the_delegated_boundary --locked --offline
# RED: exchanged result decoded as Null
# GREEN: 1 passed

./scripts/cargo-local.sh test -p pm-web-auth \
  exchange::tests::binds_subject_actor_audience_scope_and_rejects_secret_reflection \
  --locked --offline
# RED: exchange validator/types absent
# GREEN: 1 passed

```

The first real lab POST reached Keycloak and failed closed with `AUTH_REJECTED`:
requesting `openid` caused Keycloak to return an auxiliary `id_token`. The
profile was narrowed to the independently required `target.read` scope, after
which Keycloak returned only the permitted exchanged access token. The first
hostile TLS fixture exposed a server close-notify deadlock as `INDETERMINATE`;
its server was corrected to complete TLS shutdown, after which both credential
reflection cases became `INTEGRITY_FAILURE` and redirect became
`AUTH_REJECTED`.

## Focused and process evidence

```text
./scripts/cargo-local.sh test -p pm-web-auth -p pm-interface --locked --offline
# pm-web-auth: 8 passed; pm-interface: 3 passed

./scripts/cargo-local.sh test -p pm-vault --test delegated_authorization --locked --offline
# 8 passed

./scripts/cargo-local.sh test -p pm-cli --test delegated --locked --offline
# 2 passed

PM_KEYCLOAK_DIST=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/keycloak/keycloak-26.7.3 \
  ./scripts/test-linux-token-exchange-lab.sh
PASS token-exchange-p2 keycloak=26.7.3 exchange=standard-v2 A!=B subject+actor+audience+scope=bound tls=1.3
PASS token-exchange-adversarial reflect=subject+auxiliary redirect=closed audience=real-denial public=redacted
PASS token-exchange-controls credential=combined+custodied idempotency=stable context=closed cancel=terminal suspend=pre-post-denied result=token-B-only
```

The process lab runs the official fixed Keycloak 26.7.3 artifact over HTTPS and
uses separate user-namespace UIDs for custodian, human, two agents, trusted
adapter and destination. It traverses the real TLS-1.3/RPK human enrollment and
agent discovery/start/status/cancel APIs. A real Standard-v2 exchange proves
A != B and signed subject/actor/audience/scope bindings. Live TLS destinations
reflect A, reflect the auxiliary client secret, and redirect; all remain failed
with no result or secret in public output/logs. A real unauthorized Keycloak
audience also fails. Stable idempotency, an invalid agent context, terminal
cancel, and human suspension before an observed POST are exercised publicly;
the vault integration test covers individual agent revocation after lease and
before the provider-use closure.

## Authorized asynchronous diagnostic method

The unauthorized-audience assertion keeps its final contract unchanged:
`auth start` is still required to publish an attempt that settles to `FAILED`
with a null result. If it fails before publication, the existing precondition
remains red; the lab does not accept that path as a green result. It now reports
only a bounded diagnostic containing the return code, `stdout` and `stderr`.
The diagnostic replaces the synthetic subject token, requester secret and
master password with `<REDACTED>` before any assertion context is shown. It
performs no retry and does not alter the subsequent terminal-state assertion
when an attempt was published.

The baseline diagnostic had observed a non-zero return code with empty
`stdout`/`stderr`; nine additional runs did not reproduce it. This remains
evidence to preserve, not a reason to weaken the final failure assertion.

## Exact limits

- This is the single installed Keycloak 26.7.3 Standard-v2 profile. It is not a
  generic exchange facility, arbitrary endpoint client, legacy impersonation
  flow, or fallback for opaque API keys.
- Token B is deliberately returned to the authorized caller. Tokens A and the
  requester secret never cross that result boundary. No refresh or ID token is
  accepted.
- Local revocation/suspension blocks only a provider POST that has not already
  linearized. No claim is made that it revokes a token B already issued by
  Keycloak.
- The process evidence is Linux x86_64. It does not add a new platform claim or
  close later packaging/compatibility tickets.

## Final checks and regression labs

```text
./scripts/check.sh
# pinned inputs, format, workspace all-target check/tests and clippy: exit 0

git diff --check
# exit 0

./scripts/clean-offline-build.sh
# Removed 14,672 files / 3.0 GiB; locked/offline build finished in 30.34 s: exit 0
```

All eleven existing Linux process labs were run. Custody, human transaction,
content, authorization, attempts, CSV import, three-custodian sync, history,
1PUX import, the ticket-10 real browser flow, and this real token-exchange flow
all returned exit 0. The attempts regression initially exposed an overbroad
change that excluded every indeterminate operation from non-secret provider
reconciliation; that change was removed and the attempts lab then returned its
expected `ambiguous=INDETERMINATE restart=no-blind-retry` evidence. Ticket 11's
adapter still cannot replay the POST during reconciliation because opcode 2
carries no credential material and the exchange adapter supports only opcode 4.


## Unified integration verification

Candidate `6bc1e7a5a8ea6e6ad385f30d8f783592b802f4fd` was merged
non-destructively as `d0c628845f516e2495139bdb8c09f3ea73acc26a` onto
`3c4844199144f1d07f595b2dcfa388a9c4d3eae6`. Integration was resumed by
Astra after the interrupted, distinct Sol merger; this is integration
verification, not the formal end-of-DAG review.

The union preserves passkey, SSH, backup and exchange paths. Human opcodes
remain 31 (1PUX), 32–34 (backup), 35–37 (passkey), 40 (web), 41 (exchange)
and 45 (SSH). Opaque `controlled.external` results remain opaque; only the
closed provider-specific result schemas are parsed. The SSH lease explicitly
initializes the new optional subject token to absent.

The first integrated `check.sh` passed all tests but failed Clippy because the
combined attempt-start profile checks made the function 107 lines. Extracting
those unchanged checks into `matches_authentication_profile` restored the gate;
no global lint suppression or behavioral fallback was added.

Final verification on the combined code:

```sh
./scripts/check.sh
# exit 0; 96 tests passed across all targets, format/check/clippy passed
./scripts/clean-offline-build.sh
# exit 0; removed 15,860 files / 4.2 GiB; build completed in 33.44 s
for lab in scripts/test-linux-*-lab.sh; do "$lab"; done
# exit 0; all 14 labs passed on the final code after the clean build
```

The final sorted run included 1PUX, attempts, authorization, backup, content,
CSV, custody, history, human transactions, passkey, SSH, sync, real Keycloak
Token Exchange V2 and real Keycloak/CFT password/TOTP OIDC. This preserves the
Linux-lab-only and later native/distribution/review limitations above.
