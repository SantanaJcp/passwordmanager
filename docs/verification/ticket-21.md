# Ticket 21 verification evidence

Date: 2026-09-13. Requirements: R04, R05, R18, R19. Observed host:
Linux x86_64; Rust 1.98.1; libsodium 1.0.22; repository-pinned bundled
SQLite. Every vault, password, recovery code, key, record and canary was
synthetic and disposable.

## TDD red/green

The first crypto test was added before the PMB1 seam existed:

```text
./scripts/cargo-local.sh test -p pm-crypto --test backup_stream --locked --offline
```

The RED build exited 101 with unresolved `BackupOpener`, missing
`UnlockedRoot::start_backup` and missing `RootBundle::backup_root_envelopes`.
After the independent backup `K_F`, PMF1 header and password/recovery openers
were implemented, the same test reached a second RED assertion because the
header omitted literal `PMF1`; after fixing the framing it passed. The final
test also proves that restored historical KAUD material is rewrapped to a new
K_H, cannot be opened by the source K_H, and still opens the unchanged source
audit ciphertext in its source-vault AAD context.

The native lifecycle test was then added before the vault API:

```text
./scripts/cargo-local.sh test -p pm-vault --test backup_lifecycle --locked --offline
```

Its RED build exited 101 with unresolved `BackupArchive` and missing
`HumanVault::{write_native_backup,verify_native_backup}`. The plaintext case
subsequently failed to compile for missing confirmation/export methods, then
failed at runtime because the closed command decoder rejected the new
operation. The restore case first failed to compile for missing
`prepare_native_restore` and its bounded hashing sink. Each slice was made
green before the next was added; no production reference model or stub
substituted for the real writer, parser, staging or commit path.

Final focused runs:

```text
./scripts/cargo-local.sh test -p pm-crypto --test backup_stream --locked --offline
# 1 passed; 0 failed

./scripts/cargo-local.sh test -p pm-vault --test backup_lifecycle --locked --offline
# 5 passed; 0 failed
```

The vault suite covers all seven logical types and every private/source field,
active and trash state, multiple retained revisions, partial-history purge
markers, inline/empty/streamed attachments, audit bundles, authority history,
identity metadata, organizations/settings, wrong password, altered/reordered/
omitted/truncated/trailing archives, exact multi-page inventory above 1,024
entries, final-tag replay, one-use plaintext confirmation, state binding,
injected audit failure and atomic retry. The 16 GiB file ceiling and 16 GiB + 1
rejection are exercised with descriptor metadata only; no 16 GiB allocation or
sparse-file shortcut is used.

## PMB1/PMF1 and restore transaction

`HumanVault::write_native_backup` holds one SQLite read snapshot and exports
logical records rather than SQLite/WAL bytes. PMB1 contains the bounded,
canonical outer header and both existing K_H root envelopes, but neither the
password nor K_R. Its fresh backup K_F is used only by one literal PMF1 stream.
The first encrypted manifest binds the complete outer SHA-256 and declares
`scope=full`; data membership is paged in groups of at most 1,024, and the final
manifest binds counts, logical sizes, attachment bytes and the framed page
hash. Records are at most 16 MiB, plaintext/ciphertext chunks are at most 1 MiB
plus the documented tag/framing, files are at most 16 GiB, and aggregate
records/attachments/logical bytes are capped at 1,000,000/100,000/1 TiB.

The streaming verifier rejects unknown schemas, noncanonical outer data,
invalid KDF bounds, duplicate or missing inventory, dangling item/revision/
attachment or authority-parent references, mismatched attachment descriptor
hash/size, noncontiguous/reordered/missing chunks, wrong FINAL and trailing
bytes. It keeps bounded chunks and capped membership maps; it never reads an
attachment or archive into one allocation.

Restore authenticates the complete archive before producing a signed command.
During parsing it generates fresh item, revision, attachment and file keys and
stores only destination-encrypted staging. Audit ciphertext/signatures/source
bundle are retained exactly while KAUD is opened through the backup K_H and
rewrapped to the destination K_H. The existing `HumanVault::commit` validates
the staged graph digest again, then publishes revision packages, attachment
streams, new signed item/trash events, outbox, imported historical metadata,
minimal encrypted audit and receipt in one SQLite transaction. Imported
authority events, agent identity state, grants and attempts never become live;
no credential is automatically delegated/enabled. A failed audit insertion
rolls back every active row and leaves authenticated staging available for a
safe retry.

Plaintext export has a separate 60-second, one-use, state-bound signed human
confirmation for the exact full scope. The public client writes both native
and plaintext artifacts through an exclusive mode-0600 temporary file,
`sync_all`, atomic rename and directory sync. Broken streams delete the
temporary and never replace an existing destination.

## Real human TLS/RPK laboratory

```text
./scripts/test-linux-backup-lab.sh
```

Observed result:

```text
PASS backup-e2e tls=rpk+alpn/pm-human/1 native=PMB1/PMF1 plaintext=confirmed streaming=>2MiB inventory=exact history+trash=roundtrip authority=historical-only private-keys+grants+attempts=excluded corrupt+truncated=atomic source=immutable permissions=0600 role=human-only raw-canaries=absent
```

The disposable multi-UID lab creates all seven types and a 2 MiB + 211 byte
descriptor attachment through the real human TLS 1.3 service with pinned RPK
and ALPN `pm-human/1`. Human opcodes 32--34 stream PMB1 download, separately
confirmed plaintext download and PMB1 upload/prepare; commit and receipt replay
remain the existing signed protocol. It observes 16 items and 18 revisions
after exact existing-vault import, two trash states, imported history, zero
credential/agent authorizations and zero attempts. PMB1 and plaintext files are
owned by the human UID with mode 0600. Corrupt and truncated uploads leave all
durable counts unchanged, the source archive hash stays unchanged, an agent
profile is denied, and scans find no raw canary in custodian state.

## Repository gates and regression laboratories

```text
./scripts/check.sh
# pinned inputs, fmt, workspace/all-target check and tests, clippy: exit 0

./scripts/clean-offline-build.sh
# Removed 15865 files, 3.0GiB total
# Finished `dev` profile in 31.65s, with no network access: exit 0

set -euo pipefail
for lab in scripts/test-linux-*-lab.sh; do
  "$lab"
done
# all nine laboratories: exit 0

git diff --check
# exit 0
```

The same sorted laboratory run passed attempts, authorization, backup, content,
CSV, custody, history, human-transaction and sync. Relevant retained evidence
includes attempts' no-blind-retry crash path, two-agent authorization,
all-type content streaming, CSV atomic replacement, history purge anti-replay,
human transaction rollback and three-custodian opaque sync.

## Limits

This ticket implements full archive production/verification and explicit
content import into an already-authoritative unlocked vault. Ticket 22 still
owns the operational lost-device workflow that creates and atomically replaces
a wholly new vault after separately verifying its new recovery path. No host
reboot, production systemd/FDE, public Internet, real provider, real passkey
ceremony, TUI, database-copy backup or production secret was exercised.

## Unified merger verification

Candidate `2a3415fad0096ffbc2a28bccd6d8c314cd854d8f`, based on
`699ac1162243f874ddd3be090f672abca7d65578`, was merged without rewriting
history as `3d76d029e5a0b39e7d8d50455978a8b7dc18affc` on top of unified HEAD
`60d6016d2ab09277257a6a38a13b34bf36fa50ad`. The sole content conflict was
additive in `pm-custody`: the merger retained ticket 20's 1PUX command and
ticket 10's human opcode 40 together with the backup commands and plaintext
confirmation opcode 33. Existing attempt opcodes 30--32 and all web, sync,
history and import paths remained present.

Focused and repository-wide verification on the integrated tree reported:

```text
./scripts/cargo-local.sh test -p pm-crypto --test backup_stream --locked --offline
# 1 passed; 0 failed

./scripts/cargo-local.sh test -p pm-vault --test backup_lifecycle --locked --offline
# 5 passed; 0 failed

./scripts/clean-offline-build.sh
# Removed 8,826 files / 2.1 GiB; locked/offline build in 33.16 s: exit 0

./scripts/check.sh
# pinned inputs, fmt, workspace/all-target tests and clippy: exit 0

git diff --check
# exit 0
```

All eleven current `scripts/test-linux-*-lab.sh` laboratories passed on the
integrated tree: 1PUX, attempts, authorization, backup, content, CSV, custody,
history, human transaction, sync and web authentication. Ticket 21's exact
observation remained:

```text
PASS backup-e2e tls=rpk+alpn/pm-human/1 native=PMB1/PMF1 plaintext=confirmed streaming=>2MiB inventory=exact history+trash=roundtrip authority=historical-only private-keys+grants+attempts=excluded corrupt+truncated=atomic source=immutable permissions=0600 role=human-only raw-canaries=absent
```

The web regression used the pinned repository-local Keycloak 26.7.3 and CFT
153.0.8010.36 laboratory artifacts; it passed code+PKCE-S256, password+TOTP,
pre-secret hostile DOM/iframe rejection, private CDP pipe/profile,
post-response validation and challenge cancellation. It continues to report
Chromium-own, six native targets and cross-platform coverage as not run/ticket
33, rather than extending Ticket 21's claims. No Ticket 12 code was integrated,
no worktree was removed, and no push or formal Astra review was performed.
