# Ticket 07 verification evidence

Date: 2026-09-12. Requirements: R06, R07, R08, R09, R11, R12.
Observed host: Linux x86_64; Rust 1.98.1; libsodium 1.0.22; SQLite is
the repository-pinned bundled build. All credentials, keys, IDs and paths are
synthetic and confined to disposable test directories.

## TDD red/green and stable seams

The first focused command was:

```text
./scripts/cargo-local.sh test -p pm-vault --test delegated_authorization --locked --offline
```

It exited 101 because the public `AgentEnrollment`, `AgentPeer`,
`DelegatedVault`, `AuthorizationError`, `AuthorizationReason` and authority
prepare methods did not exist. After implementation, the same command passes
three tests covering two RPK identities and an identical common set, human
lock versus delegated suspension, terminal revocation and a second generation,
restart, unknown peers, authenticated package corruption, and atomic rollback
when the mandatory audit insert fails.

The stable ticket-08/16/19 seams are:

- `HumanVault::{prepare_agent_enrollment,prepare_agent_revocation,
  prepare_delegated_suspend,prepare_delegated_resume,prepare_enable}`. They
  return the existing signed `PreparedHumanCommand`, use the only
  `HumanVault::commit`, and therefore retain receipt/replay/audit atomicity.
- `DelegatedVault::{open,discover,authorize,authority_headers}` and
  `AgentPeer::from_transport_rpk`. Discovery and each authorization boundary
  reload and authenticate current agent, global and item authority.
- the persisted canonical G5 header fields (`authority_epoch`, emitter
  generation/sequence, `prev`, sorted `parents`, kind, subject and subject
  generation) plus human and device signatures. Ticket 16 can reduce these
  events rather than migrate a ticket-local ledger.

The materialized agent/global/item tables are read models. Positive decisions
are checked back against the signed G5 event and G2 grant commitment. No wall
clock or arrival timestamp participates in authority reduction.

## Composed public TLS/RPK laboratory

Command:

```text
./scripts/test-linux-authorization-lab.sh
```

Observed output:

```text
PASS authorization-e2e rpk-agents=2 same-set=1 human-lock-independent=1 suspend=denied revoke=terminal generation=2 restart=durable
PASS authorization-path agent=tls1.3+rpk+alpn/pm-agent/1 human=tls1.3+rpk+alpn/pm-human/1 prepare-commit-receipt=replayed audit=atomic
```

The harness provisions two distinct real Ed25519 RPKs under different user-
namespace UIDs. Each public `agent-discover` process traverses kernel peer UID,
mutual TLS 1.3 RPK authentication, `pm-agent/1` ALPN, the custodian handler and
the shared persisted vault. The human setup/suspend/revoke/re-enrol operations
traverse the corresponding `pm-human/1` channel. It compares exact process
output for both agents, closes the human session before discovery, restarts the
custodian, rejects suspended/revoked/unknown RPKs, and admits only generation 2
after replacement.

An injected SQLite audit trigger is reached through the public human TLS
command. The authority event, outbox, receipt and encrypted audit counts remain
unchanged and its challenge remains unconsumed. Removing the trigger permits
the same real path. Raw state-file scans reject the synthetic title and secret
canaries; the delegated response contains only item/revision, type, title,
destination and account.

## Regression evidence and limits

The existing ticket-03 through ticket-06 laboratories pass unchanged:

```text
./scripts/test-linux-custody-lab.sh
./scripts/test-linux-human-transaction-lab.sh
./scripts/test-linux-content-lab.sh
```

They continue to report mutual TLS RPK/role ALPN, human CRUD
prepare/commit/receipt and audit atomicity, all selected content types and
streaming rollback, encrypted device audit, and their explicit
`reboot_host=NOT_RUN production_systemd_fde=NOT_RUN` limitation.

Final candidate checks:

```text
./scripts/cargo-local.sh test -p pm-vault --test delegated_authorization --locked --offline
./scripts/test-linux-authorization-lab.sh
./scripts/test-linux-custody-lab.sh
./scripts/test-linux-human-transaction-lab.sh
./scripts/test-linux-content-lab.sh
./scripts/check.sh
./scripts/clean-offline-build.sh
git diff --check
```

This ticket does not perform external provider actions, delegated use, full
multi-device synchronization/reduction, or host reboot/production service/FDE
validation; those remain tickets 08+, 16 and 19 as assigned. Formal Astra
review remains a separate final gate; unified merger evidence follows.

## Unified merger verification

Candidate `29089a383b9bab212184a963609a55046c9d2949` was a direct child of
unified base `104e19eca882d80a53ea503aca7060b21d37864e` and was integrated
without conflicts or history rewriting as merge
`07b9b025a285b124a08a4e81014e3dfc3f806b62`. The merger observed:

```text
./scripts/cargo-local.sh test -p pm-vault --test delegated_authorization --locked --offline
# 3 passed; exit 0

./scripts/test-linux-authorization-lab.sh
# PASS authorization-e2e rpk-agents=2 same-set=1 human-lock-independent=1 suspend=denied revoke=terminal generation=2 restart=durable
# PASS authorization-path agent=tls1.3+rpk+alpn/pm-agent/1 human=tls1.3+rpk+alpn/pm-human/1 prepare-commit-receipt=replayed audit=atomic
# exit 0

./scripts/check.sh
# pinned inputs, fmt, workspace/all-target check, 40 tests and clippy passed; exit 0

./scripts/clean-offline-build.sh
# pinned inputs passed; removed 9109 files/1.3 GiB and compiled the clean offline workspace in 19.53 s; exit 0
```

All three prior Linux labs also passed. Their synthetic bootstrap hashes were
`d6a12b9661003ad8062ba2289eeb116b230b48e4c27b79fb731ee5ad22f648f9`
(custody),
`0932cc447fe041750ed64bcd78fe50efe5da603b7d9ac26dd01dcf0662736814`
(human/audit), and
`1d7e0a701b0e2ff15095c70fb1edc4a419e4a7de9f482b7ff8d036586b2ad4bf`
(content/streaming/audit). Each returned exit 0 and retained the explicit
`reboot_host=NOT_RUN production_systemd_fde=NOT_RUN` limitation. Formal Astra
review was not run per ticket and remains reserved for the final DAG review.
