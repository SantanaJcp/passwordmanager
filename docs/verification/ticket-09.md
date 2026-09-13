# Ticket 09 verification evidence

Date: 2026-09-12. Requirements: R01, R08, R09, R13. Observed host: Linux
x86_64; all fixtures and paths are synthetic and disposable.

## Shared contract and framing

`pm-interface` owns the private `u32` big-endian framing (maximum 1 MiB),
strict UTF-8 JSON parsing, duplicate-key rejection, depth 16, closed request
envelopes, and the common dispatcher. `VaultEngine` calls the existing
`DelegatedVault`/`AttemptVault` seams; it does not contain a second
authorization policy. The CLI and MCP adapters both call that dispatcher.
Provider result bytes are not reflected into the delegated result: a typed G3
schema is required before a result can cross the boundary.

## TDD evidence

Focused commands:

```text
./scripts/cargo-local.sh test -p pm-interface --locked --offline
./scripts/cargo-local.sh test -p pm-cli --test delegated --locked --offline
```

Observed: framing/hostile-JSON tests pass; a real `pm mcp` child process emits
MCP 2025-11-25 `initialize`, exactly five delegated tools, and no human,
reveal, export, or generic-sign tool. A real `pm --json capabilities` process
keeps diagnostics on stderr and exits with transport code 4 when no RPK profile
is configured. The existing real vault CLI tests remain green.

The authenticated Linux client seam is `pm_custody::agent_rpc`: it consumes
the PMA1 discovery frame and uses the existing TLS 1.3/RPK/`pm-agent/1`
connection before sending the bounded delegated request. `AgentEngine` uses
this seam for discover/start/get/cancel when `PM_PROFILE`, `PM_PRIVATE`, and
`PM_SOCKET` (or equivalent CLI references) are configured.

The composed Linux laboratory also drives both front doors against the same
real custody/provider process. It launches separate UID processes, performs
the TLS/RPK `pm-agent/1` handshake, and compares discover, start (idempotent
replay), get, and cancel structured results plus a not-found error:

```text
./scripts/test-linux-attempts-lab.sh
```

Observed (including the existing crash/reconciliation assertions):

```text
PASS attempts-e2e tls=rpk+alpn/pm-agent/1 provider=separate-uid idempotency=stable ownership=hidden challenge=trusted cancel=terminal
PASS attempts-crash provider-calls=1 ambiguous=INDETERMINATE restart=no-blind-retry K_ATT=device-only audit=atomic
```

The comparison uses the synthetic provider process and real SQLite attempt
records; no mock engine is substituted. Both adapters produce the same public
snapshot schema (including redacted `result`) and public error category. The
lab also checks the provider secret canary remains out of agent output and
persisted state.

## Checks and limits

```text
./scripts/cargo-local.sh check --workspace --all-targets --locked --offline
./scripts/cargo-local.sh test --workspace --all-targets --locked --offline
./scripts/cargo-local.sh clippy --workspace --all-targets --locked --offline
git diff --check
```

These checks pass on this host. No production integration, external session
management, or cross-platform support is claimed. Formal Astra review and
unified merger verification remain the DAG gates.
