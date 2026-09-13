# Ticket 17 verification evidence

Date: 2026-09-13. Requirements: R06, R15, R16, R17. Observed host: Linux
x86_64; Rust 1.98.1; libsodium 1.0.22; SQLite is the repository-pinned bundled
build. Every key, namespace, identifier and payload is synthetic and confined
to disposable test directories.

## TDD red/green

The first complete three-replica behavioral test ran with received events
incorrectly entering the receiver's durable outbox:

```text
./scripts/cargo-local.sh test -p pm-sync --test e2ee_replication --offline

running 1 test
test three_paired_replicas_converge_through_opaque_ciphertext_without_copying_sqlite ... FAILED

assertion `left == right` failed
  left: 3
 right: 2

test result: FAILED. 0 passed; 1 failed
```

That was a protocol behavior failure, not a missing symbol: a remote apply was
being echoed as a new local commit. The reducer gained a received-event entry
point that shares validation and transaction logic but never enqueues remote
input. A later real `HumanVault`/replica/TLS test exposed the missing content
graph after the signed event arrived:

```text
test replica_push_and_pull_cross_the_real_tls_rpc_process ... FAILED
called `Result::unwrap()` on an `Err` value: ItemNotFound
```

The implementation now stages the complete signed ciphertext graph and
activates graph plus authority headers in one SQLite transaction. Two further
hardening tests were observed red before their fixes:

```text
test human_streaming_attachment_graph_is_complete_before_atomic_activation ... FAILED
assertion failed: matches!(...apply_received_package(&[event], &[mixed]),
    Err(pm_vault::ReductionError::Integrity))

test replica_push_and_pull_cross_the_real_tls_rpc_process ... FAILED
assertion failed: matches!(tx.upload_paged_file(&transport, &symlink),
    Err(SyncError::InvalidRequest))
```

The first showed that an unsigned extra legacy part could accompany an
otherwise signed streaming graph; the reducer now rejects mixed or duplicate
attachment representations before insertion. The second showed input preflight
following symlinks; upload now accepts only regular files, enforces the declared
16 GiB boundary while reading, and rejects concurrent length changes without
truncating or publishing a root. The focused suite is green:

```text
running 5 tests
test opaque_store_enforces_hash_acl_and_all_published_boundaries_without_truncation ... ok
test omitted_block_never_activates_half_of_one_published_root_and_retry_is_atomic ... ok
test human_streaming_attachment_graph_is_complete_before_atomic_activation ... ok
test three_paired_replicas_converge_through_opaque_ciphertext_without_copying_sqlite ... ok
test replica_push_and_pull_cross_the_real_tls_rpc_process ... ok

test result: ok. 5 passed; 0 failed
```

## Composed E2EE, content graph and authority path

The three-replica test starts one persisted vault, enrolls three distinct
synthetic device signing-custodies through `HumanVault`, and copies the closed
seed into three independent SQLite stores. Human-authorized pairing creates a
fresh random namespace and E2EE key, binds their digest and the observed server
RPK pin with `SK_H`, and rejects a changed bundle or wrong observed pin. Each
replica commits a different `SK_SD`-signed causal event into the existing
reducer/outbox, publishes only authenticated ciphertext blocks to the opaque
store, and pulls complete published roots through `SyncReplica`.

Human item revisions carry the digest of their exact persisted ciphertext graph
in the signed event body. `SyncReplica` exports that graph through the existing
reducer, encrypts its revision package, legacy attachments or G2 stream chunks
again under the pairing key, and transports each logical object through
authenticated descriptor pages. On receive it fetches and verifies every page,
contiguous index, length, ciphertext hash and graph digest before publishing
revision parts, attachment parts and signed authority events in one transaction.
A synthetic trigger aborting an attachment-chunk insert leaves both
`revision_parts` and `authority_events` at zero. Retry after removing the
trigger activates the record and `HumanVault::read_attachment_to` returns every
one of the original 2 MiB + 37 bytes.

All three reducers converge on the same digest and exact LWW winner. Duplicate
root/event replay is idempotent, received events are not echoed, and local
outbox acknowledgement occurs only after root storage and publication. A root
with an omitted event or graph block fails before any header activates;
restoring the exact block activates the complete package. A signed device
retirement remains unknown while offline, activates on pull, and composed
`DelegatedVault::authorize` then returns `AccessSuspended` on the next use by
that retired custodian. No SQLite or WAL file is copied.

The server persists only `(namespace, transport-RPK ACL)`, immutable
`(SHA-256,ciphertext)` blocks and published root hashes. Its ACL protects
transport availability, not vault authority. Put and publish replay are
idempotent; get recomputes the requested hash; published roots cannot be
physically deleted by housekeeping. Block size is exactly bounded at 512 KiB,
list is 1–256/default 128, and reducer/outbox batches are at most 256. Tests
exercise the accepted 512 KiB edge, 512 KiB + 1 rejection, hash mismatch,
unauthorized RPK, missing publish, list limit 0/257, replay and non-deletion of a
published root without truncation.

Logical objects are bounded at exactly 16 GiB. A sparse 16 GiB + 1 fixture is
rejected before allocation/read/network; regular-file and stable-length checks
prevent symlink/TOCTOU boundary bypass. Only one ≤512 KiB block, one ≤256 KiB
descriptor page, the bounded ≤1 MiB RPC frame and bounded reducer chunks are
handled at a time; the complete logical file is staged on disk, not in memory.

## Real-process Linux transport laboratory

```text
./scripts/test-linux-sync-lab.sh

PASS sync-e2e custodians=3 server=opaque put=idempotent list=roots get=hash-bound partial=rejected hostile-tamper=rejected
PASS sync-path process=real multi-uid=1 tls=1.3 rpk=mutual alpn=pm-sync/1 json=base64 sqlite-copy=none
LIMIT public-internet=NOT_RUN production-service=NOT_RUN network-partition=simulated
```

The disposable user-namespace lab runs the Rust/SQLite server as UID 1 and
three authorized clients as UIDs 2–4. A fifth RPK/UID is rejected during mutual
TLS. The channel is TLS 1.3 only, uses raw Ed25519 public keys pinned on both
sides, X25519 key exchange, role-separated `pm-sync/1` ALPN, no resumption or
early data, 30 second I/O timeouts, private big-endian framing capped at 1 MiB,
and the closed `sync.put/get/publish/list/delete` JSON/base64 protocol. Private
key inputs must be process-owned regular non-symlink files at mode 0400; a
pre-existing socket is removed only if it is a socket owned by the server UID.

The lab replays the same put, publishes/lists/fetches across three identities,
rejects publication of a missing block, stops the server, alters its opaque
SQLite as a hostile operator, restarts, and observes hash-bound get rejection.
No account, SaaS endpoint, database/WAL copy, host service or persistent host
configuration is used.

The Rust process integration additionally runs an actual `HumanVault` commit
and `SyncReplica::push/pull` through that TLS subprocess with a 2 MiB + 17 byte
encrypted attachment. Its object spans multiple descriptor pages and reopens
byte-exactly on the other vault. A separate 2 MiB + 17 byte paged-file
round-trip crosses the same RPC. The server database is scanned for both
canaries and contains neither. A wrapper loses the first successful `put`
response; retry waits the first one-second interval and repeats the identical
hash idempotently. Production retry intervals are the closed sequence
1,2,4,8,16,30 seconds and only `Unavailable` is retried; missing, integrity and
backpressure preserve distinct TLS client statuses and return immediately.

## Final candidate checks and limits

```text
./scripts/cargo-local.sh test -p pm-sync --test e2ee_replication --offline
# 5 passed; exit 0

./scripts/cargo-local.sh test -p pm-vault --test delegated_authorization --offline
# 4 passed; exit 0

./scripts/test-linux-custody-lab.sh
./scripts/test-linux-human-transaction-lab.sh
./scripts/test-linux-content-lab.sh
./scripts/test-linux-authorization-lab.sh
./scripts/test-linux-sync-lab.sh
# all five labs completed successfully; exit 0

./scripts/check.sh
# pinned inputs, fmt, workspace/all-target check, 52 tests and clippy; exit 0

./scripts/clean-offline-build.sh
# removed 13620 files/2.4 GiB and rebuilt the locked/offline workspace; exit 0

git diff --check
# exit 0
```

The sync suite simulates an offline interval and omitted/replayed/reordered
delivery using independent SQLite stores; it does not claim a public-Internet
partition test. Public Internet deployment, production service installation,
host reboot and production systemd/FDE remain explicitly not run. Ticket 17
does not add backup/import/history or provider actions. Formal Astra review and
unified merger verification remain separate final gates, so this candidate
evidence does not resolve the ticket.
