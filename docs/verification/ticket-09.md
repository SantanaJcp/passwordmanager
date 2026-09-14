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
the TLS/RPK `pm-agent/1` handshake, and compares capabilities, discover, start
(idempotent replay), get, and cancel structured results plus a not-found error:

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
unified merger verification remained the DAG gates at candidate handoff.

## Unified merger verification

Candidate `7399b039d8308f19186f5f2153fe13ea9d2bfb10` was a direct descendant
of unified base `0868cb96a0b02cc5a2dff17b50c40918a7ab7ac9` and included the
later real CLI/MCP laboratory commits, not only the first unit-only slice. Its
history was integrated without conflicts as
`88f469f90fea3af1b5f89f053c134fa11e54640c`.

The first integration gate found that both new crate roots used global
`allow(clippy::all, clippy::pedantic)` attributes. Removing those attributes
exposed 22 denied lints in `pm-interface`, so that intermediate merge was not
accepted as resolved. Luna's descendant corrector
`8429cdb86e36f210494bc30cc4b02cf97a5472b1` removed both global suppressions,
fixed the diagnostics, and was integrated without rewriting the first merge as
`9577040850919cdee10c4fe57023b3315ae95e9f`.

The merger then observed:

```text
./scripts/cargo-local.sh clippy -p pm-interface -p pm-cli --all-targets --locked --offline
# no warnings or errors; exit 0

./scripts/cargo-local.sh test -p pm-interface --locked --offline
# private framing/hostile JSON: 2 passed; exit 0

./scripts/cargo-local.sh test -p pm-cli --test delegated --locked --offline
# exact five MCP tools and diagnostic separation: 2 passed; exit 0

./scripts/cargo-local.sh test -p pm-vault --test causal_reducer --locked --offline
# 6 passed; exit 0

./scripts/check.sh
# pinned inputs, fmt, workspace/all-target check, 53 integration tests and
# clippy passed with no global clippy allow; exit 0

./scripts/clean-offline-build.sh
# pinned inputs passed; removed 10004 files/1.6 GiB and compiled the clean
# locked/offline workspace in 27.02 s; exit 0

git diff --check
# exit 0
```

All current Linux laboratories returned exit 0 after the corrector:

```text
./scripts/test-linux-custody-lab.sh
# bootstrap_sha256=d423fff83279e6911824c6a048d07633d9acaa73ed26dbd275b061751e66fd28

./scripts/test-linux-human-transaction-lab.sh
# bootstrap_sha256=67616b73580161e53d50b8d4d7e85801be682d793a50a4a15add7fdb3b082b8a

./scripts/test-linux-content-lab.sh
# bootstrap_sha256=2bd9a436a201e65608d7c6839b7fa187b512665d1a8a3388fb206f95ef5265d0

./scripts/test-linux-authorization-lab.sh
# PASS authorization-e2e ... same-set=1 human-lock-independent=1
# suspend=denied revoke=terminal generation=2 restart=durable

./scripts/test-linux-attempts-lab.sh
# PASS attempts-e2e tls=rpk+alpn/pm-agent/1 provider=separate-uid ...
# PASS attempts-crash provider-calls=1 ambiguous=INDETERMINATE ... audit=atomic
```

The last laboratory executes both real front doors as the agent UID against
the same custodian/provider/vault: `get_capabilities`, discovery, start with
idempotent replay, get and cancel are compared structurally between CLI JSON
and MCP, including `NOT_FOUND`. It asserts stderr separation and scans the
agent output and persisted state for the synthetic provider canary. MCP lists
exactly those five delegated tools and exposes no human command, reveal,
export or generic-sign operation.

The earlier labs retained
`reboot_host=NOT_RUN production_systemd_fde=NOT_RUN`. No formal Astra review,
physical reboot, production service/FDE, cross-platform run, real external
provider or ticket-10+ integration was run or claimed.
