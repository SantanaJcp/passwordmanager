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

The first candidate still exercised that engine only through a direct native
socket seam. The composed transport regression was preserved against commit
`c6159fa` by building that commit in a detached disposable worktree and running
the current public process harness against it:

```text
unshare ... python3 crates/pm-custody/tests/linux_lab.py \
  /tmp/passwordmanager-pm04-red.../target/debug/pm-custody \
  /tmp/passwordmanager-pm04-red.../target/debug/pm
```

It exited 1 because the old custodian process rejected `serve-vault` with
exactly `INVALID_ARGUMENT`; consequently no password operation could traverse
the ticket-03 transport. The green command is the ticket-04 laboratory below.
It now drives the real custodian handler across the authenticated connection,
not a direct invocation of `HumanVault`.

## Observable transaction and Linux laboratory

`scripts/test-linux-human-transaction-lab.sh` builds the public `pm-custody`
and `pm` processes, creates three real identities in a disposable user
namespace and executes the password flow through the existing ticket-03
listener. The product path is human UID/`SO_PEERCRED` -> mutual TLS 1.3 RPK ->
`pm-human/1` ALPN -> custodian human handler -> `HumanVault` -> bundled SQLite.
It uses the real libsodium and SQLite builds and reconnects the human client
against the durable file. It covers:

- create/read/edit/delete of a G6 password record whose human and auth parts
  are protected by the existing revision-package seam;
- 32-byte challenge, signed canonical command/body/state hashes, 60-second
  expiry, `SK_H` domain signatures, wrong peer, altered signature/body, stale
  state and replay;
- an injected SQLite audit trigger reached by a commit over that TLS channel:
  the client receives the permitted no-op outcome after reconnect, while
  item, revision, authority event, outbox, receipt, audit key/head/record and
  challenge consumption all remain unchanged; no production fault hook exists;
- after removal of the laboratory trigger, create/edit/delete each publish an
  encrypted audit record in their single transaction; deliberate response
  loss after create is recovered through `receipt`, and exact replay returns
  that receipt without applying the effect again;
- one encrypted audit record and its per-device audit-key envelope are written
  in the same transaction as every mutation. A scan of the SQLite/WAL files
  does not find either synthetic password.

Observed output:

```text
PASS uid_map='0       1000          1\n         1     100000      65535'
PASS custody_uid=1 human_uid=2 agent_uid=3
PASS bootstrap_sha256=26cacb07bac68b0b98d48008c86fc2377cadeb6b2010ee559c42fb4beb999177 restart=process tls=1.3 rpk=mutual alpn=role-specific
PASS human_crud=prepare-commit-receipt tls=1.3 rpk=mutual alpn=pm-human/1
PASS human_negatives=wrong-role,body-change,audit-failure atomicity=no-partial replay=receipt response-loss=recovered
LIMIT reboot_host=NOT_RUN production_systemd_fde=NOT_RUN
```

The channel object and request payload intentionally have no role field. The
same composed laboratory rejects an agent UID at the human endpoint before TLS
and the TLS profile pins the human RPK and ALPN; ticket-03 evidence is reused as
code, not substituted as disconnected evidence. This ticket does not claim a
new TLS implementation, host reboot, macOS/Windows behavior, sync reduction,
delegated authorization, external authentication, or the audit
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

## Final integration quality commands

Observed by the merger on unified branch merge
`4a190ecaa2d08f7469a60d2fb3484588d9897fcb`; its 16 ticket paths matched
candidate `04d434c424c2441385ccf4d32e62af7710c08f5a` exactly before this evidence
update:

```text
./scripts/clean-offline-build.sh
# pinned inputs passed; clean locked/offline workspace build passed; exit 0

./scripts/check.sh
# pinned inputs, fmt, workspace/all-target check, 26 tests and clippy passed; exit 0

./scripts/test-linux-custody-lab.sh
# existing multi-UID/RPK/ACL/process-restart laboratory passed; exit 0

./scripts/test-linux-human-transaction-lab.sh
# composed multi-UID TLS human CRUD/atomic audit/replay/recovery laboratory passed; exit 0
```

The first laboratory observed bootstrap SHA-256
`65eff10a7d4787e7bac4daff19d2333b38a43c84f2bf5a15568bf2d05cd1511e`.
The composed human laboratory independently generated bootstrap SHA-256
`3b384610ab6cb649143bbf32af7ad29198c3aad73302a520b6318b232767a408`
and printed the two `PASS human_*` lines shown above. Both printed
`LIMIT reboot_host=NOT_RUN production_systemd_fde=NOT_RUN`; no custodian
process remained after either harness.

Formal Astra review remains deferred until all tickets, as required by the
execution contract. This evidence is integration verification, not that final
review.
