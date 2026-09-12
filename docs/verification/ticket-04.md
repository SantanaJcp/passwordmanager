# Ticket 04 verification evidence

Date: 2026-09-12. Requirements: R03, R04, R06, R09. Observed host:
Linux x86_64, kernel 7.2.3; Rust 1.98.1; libsodium 1.0.22; SQLite is the
repository-pinned bundled build. Every password, key, ID and filesystem path
used by these tests is synthetic and confined to disposable test directories.

## TDD red/green

The public seam is `pm_vault::{HumanChannel, HumanVault,
PreparedHumanCommand, HumanReceipt, PasswordRecord}`. It composes the ticket-02
root/revision-package cryptography and the ticket-03 native identity premise;
it does not duplicate their crypto or accept a request-provided role.

Red command, run before production implementation:

```text
./scripts/cargo-local.sh test -p pm-vault --test human_transactions --locked --offline
```

It exited 101 because `HumanChannel`, `HumanVault`, `HumanCommitError` and
`PasswordRecord` did not exist. This was a behavioral seam failure, not an
unresolved dependency failure. After implementing the smallest vertical CRUD
and transaction path, the same locked/offline command passed. Subsequent
cycles added stale-state/invalid-signature and audit rollback assertions and
remained green.

## Observable transaction and Linux laboratory

`scripts/test-linux-human-transaction-lab.sh` exercises public Rust APIs over a
real Unix socket pair, obtains the peer UID through Linux `SO_PEERCRED`, uses
the real libsodium and bundled SQLite builds, and restarts the human vault
session against the durable file. It covers:

- create/read/edit/delete of a G6 password record whose human and auth parts
  are protected by the existing revision-package seam;
- 32-byte challenge, signed canonical command/body/state hashes, 60-second
  expiry, `SK_H` domain signatures, wrong peer, altered signature/body, stale
  state and replay;
- retry after an injected audit insertion failure leaves item, revision,
  authority event, outbox, receipt, audit key/head/record and challenge
  consumption all unchanged;
- retry after that no-op succeeds, while a new session retrieves the durable
  receipt without applying the effect again;
- one encrypted audit record and its per-device audit-key envelope are written
  in the same transaction as every mutation. A scan of the SQLite/WAL files
  does not find either synthetic password.

Observed output:

```text
PASS channel=SO_PEERCRED role=request-field-absent crypto=libsodium storage=sqlite-wal-full
PASS prepare=challenge60s commit=atomic receipt=idempotent audit=encrypted-atomic
LIMIT tls-rpk-alpn=ticket-03-lab host-reboot=NOT_RUN non-linux=NOT_RUN
```

The channel object intentionally has no role field supplied by a request.
Ticket 03 separately observed mutual TLS 1.3 RPK, human/agent ALPN separation,
and rejection of an agent UID on the human endpoint. This ticket does not
claim a new TLS implementation, host reboot, macOS/Windows behavior, sync
reduction, delegated authorization, external authentication, or the audit
segment/query/purge work owned by tickets 06 and later.

## Stable extension seams and limits

- Human transaction commit is centralized in one SQLite `IMMEDIATE`
  transaction; ticket 05 can add logical record encoders/stagers without a
  second commit engine.
- Audit persistence already uses a typed `audit-record` envelope, a human
  envelope for the per-device audit key, sequence/head rows and encrypted
  record rows inside that same transaction. Ticket 06 extends this mechanism
  with autonomous device custody, signatures, segments, query and explicit
  purge; it must not replace atomic commit with a callback or later write.
- The current authority history is a single local linear head. Multi-device
  DAG reduction, `SK_SD` device signatures and sync are deliberately not
  claimed by ticket 04 and remain owned by later G5 tickets.

## Final quality commands

To be recorded on the candidate commit:

```text
./scripts/cargo-local.sh test -p pm-vault --all-targets --locked --offline
./scripts/test-linux-human-transaction-lab.sh
./scripts/check.sh
./scripts/clean-offline-build.sh
```

Formal Astra review remains deferred until all tickets, as required by the
execution contract. The merger must still integrate and independently verify
this candidate before resolving ticket 04.
