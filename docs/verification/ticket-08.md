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
a per-ticket action; unified merger verification is still pending.
