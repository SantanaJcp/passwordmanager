# Ticket 06 verification evidence

Date: 2026-09-12. Requirements: R05, R09. Observed host: Linux x86_64;
Rust 1.98.1; libsodium 1.0.22; SQLite is the repository-pinned bundled
build. Every password, key, ID and path used below is synthetic and confined
to disposable test directories.

## TDD red/green and public seam

The public seam is `pm_vault::{AuditDeviceCustody, AutonomousAuditVault,
AuditEvent, AuditQuery, HumanVault::query_audit,
HumanVault::prepare_audit_purge}`. Audit inputs expose closed actor/action/
outcome enums and typed IDs, not a free-form payload.

The first red command was:

```text
./scripts/cargo-local.sh test -p pm-vault --test audit_lifecycle --locked --offline
```

It exited 101 because the public audit types and human query/purge methods did
not exist. After the initial implementation, a rollback regression deleted the
last encrypted record and rolled back the local head; the focused command

```text
./scripts/cargo-local.sh test -p pm-vault --test audit_lifecycle \
  query_rejects_a_locally_rolled_back_record_and_head --locked --offline
```

also exited 101 because the query accepted the inconsistent local snapshot.
The manifest/state comparison made the same command pass. A segment-boundary
test next failed to compile because the public observation did not expose a
closed-segment count; after adding that bounded observation, 257 records
produced exactly one closed segment and one open segment.

The final test file has six passing cases. They verify an autonomous encrypted
and device-signed append after the human root is dropped; rollback on injected
record-storage failure; signed human purge with a visible range while authority
and outbox rows remain; rollover before record 257; rejection of a rolled-back
record/head; human-bound device signing keys; a linked second generation; and
rejection of superseded custody for autonomous writes.

## Real human transport and device custody

The composed Linux laboratory uses the existing public custodian process and
the real ticket-03 transport: human UID/`SO_PEERCRED` -> mutual TLS 1.3 RPK ->
`pm-human/1` ALPN -> human unlock/commit/query/purge handlers. The custodian
creates an audit custody file with its own UID and mode `0400`. The test asks
the server to drop `HumanVault` (and therefore `K_H`), performs an autonomous
append through `AutonomousAuditVault`, reconnects as the human, queries it and
commits an explicitly prepared purge. It then restarts the process, verifies
that the custody file hash did not change, and repeats the lifecycle.

Command:

```text
./scripts/test-linux-human-transaction-lab.sh
```

Observed output:

```text
PASS uid_map='0       1000          1\n         1     100000      65535'
PASS custody_uid=1 human_uid=2 agent_uid=3
PASS bootstrap_sha256=73578acf9251f5bd5d0049c3e19424c8086e71224ba5f8e10606a446445f306e restart=process tls=1.3 rpk=mutual alpn=role-specific
PASS human_crud=prepare-commit-receipt tls=1.3 rpk=mutual alpn=pm-human/1
PASS human_negatives=wrong-role,body-change,audit-failure atomicity=no-partial replay=receipt response-loss=recovered
PASS audit=encrypted,signed,segmented,query,purge autonomous_without_kh=device-custody human_path=mutual-tls-rpk
LIMIT reboot_host=NOT_RUN production_systemd_fde=NOT_RUN
```

The existing injected SQLite trigger is reached by a mutation over that TLS
path. Item/revision, authority event, outbox, receipt, audit key/state/record
and challenge consumption remain unchanged when the audit insert fails. This
is an atomic rollback of the real commit engine, not a callback or fault stub
in production code.

## Cryptographic and integrity boundaries

`KAUD[d,g]` is random and independent. Its activation package contains a human
envelope, an X25519 sealed device envelope, distinct device encryption and
Ed25519 `SK_SD` public keys, and a human signature binding the complete
package. Human queries verify that binding before opening the human envelope.
The persisted records use typed `audit-record` AAD, a fresh revision/nonce, an
`SK_SD` signature over the exact encrypted envelope, and a stored-record hash
chain. Encrypted manifests authenticate ordered segment membership, purge
ranges, and the preceding generation head. Segments close before exceeding
256 records or 1 MiB.

These signatures authenticate bytes produced under the enrolled device key;
they do **not** provide non-repudiation or prove that a compromised custodian
is honest. Local inconsistencies and undeclared gaps are rejected, but a
whole-database rollback is detectable only when a newer independent anchor is
available. Independent anchoring, multi-device sync/restore and backup bundle
transport remain later tickets.

## Final candidate commands

```text
./scripts/cargo-local.sh test -p pm-vault --test audit_lifecycle --locked --offline
./scripts/test-linux-human-transaction-lab.sh
./scripts/check.sh
./scripts/clean-offline-build.sh
git diff --check
```

All commands above passed on the candidate; exact final counts/output are
recorded in the ticket handoff. The laboratory explicitly reports that host
reboot, production systemd/FDE, macOS and Windows were not run. Formal Astra
review remains deferred until all tickets, as required by the execution
contract; merger integration is a separate pending gate.
