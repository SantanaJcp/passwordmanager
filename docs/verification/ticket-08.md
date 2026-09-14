# Ticket 08 verification evidence

Date: 2026-09-12. Requirements: R08, R09, R13. Observed host: Linux
x86_64; Rust 1.98.1; libsodium 1.0.22; repository-pinned bundled SQLite.
Every credential, key, RPK, provider response and path is synthetic and lives
in a disposable user-namespace laboratory.

## TDD red/green and stable seams

The focused vault command is:

```text
./scripts/cargo-local.sh test -p pm-vault --test delegated_authorization --locked --offline
```

It passes five tests. The two ticket-08 tests cover pinned revisions, RPK-bound
subject/generation ownership, absent/foreign indistinguishability, normalized
idempotency replay/conflict and admission window, persisted clock rollback,
per-attempt expiry, single leases, crash recovery to `INDETERMINATE`, challenge
isolation, cancellation, and trusted result settlement. The independent crypto
test proves `K_ATT` is generated under device custody, signed in
`pm/attempt-key/v1`, purpose/context bound, encrypted at rest, reused with fresh
nonces for transitions, and rejects tampering.

The first composed lab run was red because a suspended vault made the PMA1
handler abort at discovery before an owned `get` could reach the attempt API:

```text
AssertionError: agent-attempt ... --action get ... returncode=4 ... CUSTODY_UNAVAILABLE
```

The fix separates discovery authorization from the persistent PMA1 request
loop. Suspension still blocks `start`, while an active generation may get or
cancel its owned attempt. The same lab then went green.

Stable seams for tickets 09/16/19 are `AttemptVault::{start,get,cancel,
claim_next,claim_waiting_for_reconciliation,settle,recover_inflight}`,
`StartAttempt`, `IdempotencyKey`, `AttemptSnapshot`, `AttemptLease` and
`AttemptOutcome`. Provider code receives a single durable lease only after the
intent and RUNNING audit are committed. Reconciliation leases carry no password
and never resend login. Ticket 08 continues to recheck ticket-07
`DelegatedVault::authorize` authority; `agent_identity` only supplies the
subject/generation ownership key and deliberately does not create a causal
reducer or provisional ledger.

## Composed TLS/RPK/provider laboratory

```text
./scripts/test-linux-attempts-lab.sh
```

Observed output:

```text
PASS attempts-e2e tls=rpk+alpn/pm-agent/1 provider=separate-uid idempotency=stable ownership=hidden challenge=trusted cancel=terminal
PASS attempts-crash provider-calls=1 ambiguous=INDETERMINATE restart=no-blind-retry K_ATT=device-only audit=atomic
```

The public `agent-attempt` processes traverse kernel UID checks, mutual TLS 1.3
RPK authentication, `pm-agent/1` ALPN, the real custody handler and SQLite
attempt/audit transaction. A separate UID-5 Unix service is authenticated by
`SO_PEERCRED`, consumes the synthetic password, and durably journals call
counts without retaining it. It supplies success, rejection, challenge,
verified challenge resolution, response-loss reconciliation and unresolvable
evidence. Both response-loss cases make exactly one login call: resolvable loss
finishes through status evidence; unresolved loss remains `INDETERMINATE`
across custodian restart and only status queries repeat.

The lab also proves same-key replay, different-parameters conflict, foreign
ownership as `NOT_FOUND`, cancel terminality, suspension semantics and terminal
revocation. An injected audit trigger makes public start fail while attempt and
audit publication roll back together. Raw state scans reject the credential
secret canary.

## Authorized asynchronous observation method

The state assertions use only the existing public `get` operation for the same
attempt. A worker may legitimately expose `RUNNING` with no reason while a new
request settles, or `RUNNING` + `reason=provider-challenge-ref` while a trusted
challenge settles. After `recover_inflight`, reconciliation may expose
`RUNNING` + `reason=INDETERMINATE`; the observer polls within the laboratory's
existing command bound until the operation-specific terminal snapshot is
visible. Any other state or reason fails. It never calls `start`, resends
provider credentials, or changes the one-call journal assertion. Fixed sleeps
are not used as readiness evidence; the final state and `result` remain the
contract being asserted.

The historical diagnostic found this race in the worker-extraction baseline
(one `RUNNING/INDETERMINATE` read in eight attempts runs). The modified lab must
retain that red evidence and then show the same single-lease/no-blind-retry
contract green, without changing the attempts engine.

## Regression evidence and limits

The exact final commands were:

```text
./scripts/check.sh
for lab in scripts/test-linux-custody-lab.sh scripts/test-linux-human-transaction-lab.sh scripts/test-linux-content-lab.sh scripts/test-linux-authorization-lab.sh scripts/test-linux-attempts-lab.sh; do "$lab"; done
./scripts/clean-offline-build.sh
git diff --check
```

All 43 Rust tests, formatting, workspace/all-target checks and clippy pass. All
five Linux laboratories pass. The earlier laboratories retain their explicit
`reboot_host=NOT_RUN production_systemd_fde=NOT_RUN` limits.

This ticket intentionally provides only the controlled external provider
protocol used by the laboratory. It does not claim ticket-09 production
adapters, ticket-16 causal reduction, ticket-19 MCP/CLI product surface,
business-session management, a physical host reboot, production service/FDE,
or cross-platform support. Formal Astra review remains the final DAG gate, not
a per-ticket action. At candidate stage, unified merger verification was still
pending.

## Unified merger verification

Candidate `28ad9bff6b871022210ab7ec85bd28a0a85f6e95` had the expected base
`261ebe2c1a3408671aabdd8379ad583105f0aab2`. It was merged without textual
conflicts or history rewriting onto unified HEAD
`996ac5d47e3a58e805f9a2ac39c9ca7ce96a13d8`, which already contained
SOLO16, as `080c4fa23dd4deafb6b1dc37a6148f1b72a2df77`.

Semantic inspection confirmed that the combined schema retains the sole
`authority_events` ledger, its non-unique `authority_event_slot` fork index,
nullable technical-event human signatures and SOLO16 verification. Attempts
obtain ownership only through SOLO07 `AgentIdentity`; start rechecks the real
`DelegatedVault::authorize` boundary. No competing authorization model or
causal reducer was introduced.

The merger observed:

```text
./scripts/cargo-local.sh test -p pm-crypto --test attempt_key --locked --offline
# 1 passed; exit 0

./scripts/cargo-local.sh test -p pm-vault --test delegated_authorization --locked --offline
# 5 passed; exit 0

./scripts/cargo-local.sh test -p pm-vault --test causal_reducer --locked --offline
# 6 passed; exit 0

./scripts/check.sh
# pinned inputs, fmt, workspace/all-target check, 49 integration tests and
# clippy passed; exit 0

./scripts/clean-offline-build.sh
# pinned inputs passed; removed 11121 files/1.6 GiB and compiled the clean
# locked/offline workspace in 20.86 s; exit 0

git diff --check
# exit 0
```

All current Linux laboratories returned exit 0:

```text
./scripts/test-linux-custody-lab.sh
# bootstrap_sha256=dabfc487e16b7e396bfcda1ccdc83d13ed761947e0fb2bde54685dc609b41ea6

./scripts/test-linux-human-transaction-lab.sh
# bootstrap_sha256=c11f6ff5d3c3f82f681bf580202e65c5efed538e70ee78f971de9c3ba22d161d

./scripts/test-linux-content-lab.sh
# bootstrap_sha256=87c8fa2c005eb9280f3254b6dbb84d76103e19490c513b595cf300786bf6757f

./scripts/test-linux-authorization-lab.sh
# PASS authorization-e2e rpk-agents=2 same-set=1 human-lock-independent=1
# suspend=denied revoke=terminal generation=2 restart=durable
# PASS authorization-path ... prepare-commit-receipt=replayed audit=atomic

./scripts/test-linux-attempts-lab.sh
# PASS attempts-e2e tls=rpk+alpn/pm-agent/1 provider=separate-uid
# idempotency=stable ownership=hidden challenge=trusted cancel=terminal
# PASS attempts-crash provider-calls=1 ambiguous=INDETERMINATE
# restart=no-blind-retry K_ATT=device-only audit=atomic
```

The provider runs as a separate authenticated user-namespace UID and both
response-loss paths make exactly one synthetic login call. Trusted challenge
settlement, cancellation, terminal revocation, ownership hiding, durable
lease/restart behavior and atomic audit rollback were therefore observed
through the real TLS/RPK/custodian path, not a second in-memory model.

The earlier labs retained
`reboot_host=NOT_RUN production_systemd_fde=NOT_RUN`. No formal Astra review,
physical reboot, production service/FDE, cross-platform run, external real
provider or ticket-09+ public adapter surface was run or claimed.
