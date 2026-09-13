# Ticket 18 verification evidence

Date: 2026-09-13. Requirements: R04, R05, R17. Observed host: Linux
x86_64; Rust 1.98.1; libsodium 1.0.22; SQLite is the repository-pinned
bundled build. Every vault, identity, attachment and plaintext canary used here
is synthetic and disposable.

## TDD red/green

The first streaming-restore behavioral test created a 2 MiB + 37 byte
descriptor-backed attachment, replaced it with a note, moved the item to trash
and requested restoration of the historical file revision. Before the streaming
restore implementation, the focused command

```text
./scripts/cargo-local.sh test -p pm-vault --test history_lifecycle streaming_history_restores_incrementally_with_fresh_ciphertext_and_exact_content -- --nocapture
```

failed because `prepare_restore` returned `InvalidInput`. After implementing
incremental authenticate/re-encrypt staging, the same test passed and verified
the exact byte count/digest, a fresh secretstream header and a ticket-17
exportable ciphertext graph bound by the restored revision's signed map-5
`object_manifest_digest`.

The purge-scope test then changed one encrypted attachment after the human had
prepared a selective purge. Before the confirmation manifest was bound, commit
succeeded and the `StateChanged` assertion failed. After binding the exact
revision IDs, attachment count, encrypted byte count and terminal bit into the
signed human body, the altered commit returns `StateChanged`. The unchanged
prepared transaction subsequently commits, while an injected audit failure
rolls back payload deletion, purge marker, authority event, outbox, receipt and
audit record together.

Final focused commands:

```text
./scripts/cargo-local.sh test -p pm-vault --test history_lifecycle --locked --offline
# 3 passed; 0 failed

./scripts/cargo-local.sh test -p pm-vault --test causal_reducer --locked --offline
# 7 passed; 0 failed
```

The reducer suite includes all 120 delivery permutations of revision, trash,
causally later revision, restore and selective purge, followed by duplicate old
delivery. Every replica converges to active state, the same winning revision,
the same retained single-revision history, no pending event and five retained
signed headers. A separate terminal-purge test replays the old signed event plus
its complete ciphertext graph through `CausalReducer::apply_received_package`;
the transaction is rejected, payload/marker/header counts remain unchanged and
the item remains terminally purged.

## Stable transaction and lifecycle seams

`pm-vault` exposes `HumanVault::{history,read_revision,prepare_restore,
prepare_purge_revisions,prepare_purge_item}` with closed `ItemHistory`,
`HistoryEntry`, `ItemPurgeScope` and `PreparedItemPurge` results. Restore copies
the selected historical logical record into a fresh revision and never creates
or enables a credential authorization. Inline attachments receive new file
packages; descriptor-backed attachments are authenticated and re-encrypted one
bounded chunk at a time into durable human staging. Publication of the new
revision, restored stream, item-revision event, restore event, signed outbox
envelopes, minimal encrypted audit and receipt occurs in the existing single
`HumanVault::commit` SQLite transaction.

Selective and terminal purge share that same commit engine. Preparation exposes
the exact bounded scope, and commit recomputes it inside the write transaction
before deleting. Payload rows and attachment streams/chunks are deleted, while
`purged_revisions`/`purged_items`, signed authority headers, parents and event
digests remain as anti-resurrection evidence. No timestamp or automatic trash
expiry is used. The existing `CausalReducer` remains the sole authority
projection; no lifecycle ledger, reducer, crypto or custody callback was added.

The human service uses existing opcodes 25--30 for history, restore, selective
purge, terminal purge, edit and historical read. Ticket 20 was coordinated to
use opcode 31, so its 1PUX seam does not collide.

## Real public process/TLS laboratory

```text
./scripts/test-linux-history-lab.sh
```

Observed result:

```text
PASS history-e2e tls=rpk+alpn/pm-human/1 types=7 inline+stream=exact restore=new-revision response-loss=recovered restart=trash-durable scope=signed audit-failure=atomic purge=terminal markers=retained replay=blocked raw-canaries=absent
```

The disposable multi-UID laboratory invokes only public `pm-custody` commands
for product operations. `human-history-exercise` traverses the real human TLS
1.3 connection with pinned RPK and ALPN `pm-human/1`; for all seven logical
record types it creates, edits, trashes, lists, reads, restores as a fresh
revision and selectively purges a losing revision. It restores every inline
attachment exactly and separately restores/downloads the 2 MiB + 37 byte
secretstream attachment exactly. A deliberately lost restore response is
recovered by receipt and identical commit replay.

The lab leaves a synthetic item in trash, restarts the custodian and observes
trash state with the public history command, proving there is no process-time
expiry. It injects an audit insertion failure before public terminal purge and
verifies all durable product-table counts and target payload/header counts are
unchanged. The successful retry deliberately loses its response, reconnects,
recovers the receipt and replays it. After another restart, public history
rejects the purged item; SQLite inspection confirms only the terminal marker and
all signed authority rows remain. Direct state/sidecar scans find no plaintext
canaries.

## Repository gates and regression laboratories

```text
./scripts/check.sh
# verify-build-inputs, fmt, workspace/all-target check and tests, clippy: exit 0

./scripts/clean-offline-build.sh
# verified LATEST.tar.gz + minisig, removed 12509 files / 2.6 GiB,
# compiled locked/offline workspace in 29.83 s: exit 0

set -euo pipefail
for lab in $(find scripts -maxdepth 1 -name 'test-linux-*-lab.sh' | sort); do
  "$lab"
done
# all eight laboratories: exit 0

git diff --check
# exit 0
```

The final single regression run passed attempts, authorization, content, CSV,
custody, history, human-transaction and sync laboratories. Their relevant
observable results include attempts' no-blind-retry crash path, the two-agent
shared authorization set, CSV replacement/disable, human transaction atomicity,
the new history line above, and three-custodian opaque sync with omitted/hostile
graphs rejected.

## Limits

No host reboot, production systemd/FDE, public Internet sync, real provider,
browser database or keychain was exercised. The laboratories use process
restart and response-loss injection in a disposable user namespace. Ticket 18
does not implement backup/export, 1PUX, WebAuthn sessions or TUI flows; those
remain owned by their later tickets and must consume these transaction seams
rather than bypassing them.
