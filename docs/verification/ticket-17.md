# Ticket 17 verification evidence

Date: 2026-09-13. Requirements: R06, R15, R16, R17. Observed host: Linux
x86_64; Rust 1.98.1; libsodium 1.0.22; SQLite is the repository-pinned
bundled build. Every key, namespace, identifier and payload is synthetic and
confined to disposable test directories.

## TDD red/green

The first complete three-replica behavioral test ran with received events
incorrectly entering the receiver's durable outbox:

```text
./scripts/cargo-local.sh test -p pm-sync --test e2ee_replication --offline
```

Observed red result:

```text
running 1 test
test three_paired_replicas_converge_through_opaque_ciphertext_without_copying_sqlite ... FAILED

thread 'three_paired_replicas_converge_through_opaque_ciphertext_without_copying_sqlite' panicked at crates/pm-sync/tests/e2ee_replication.rs:95:9:
assertion `left == right` failed
  left: 3
 right: 2

test result: FAILED. 0 passed; 1 failed
error: test failed, to rerun pass `-p pm-sync --test e2ee_replication`
```

That red was a protocol behavior failure, not a missing symbol: a remote apply
was being echoed as though it were a new local commit. The reducer gained the
separate `apply_received` entry point, sharing the same validation/transaction
but never enqueueing remote input. After adding omission rollback and exact
resource-boundary cases, the focused command reports:

```text
running 3 tests
test opaque_store_enforces_hash_acl_and_all_published_boundaries_without_truncation ... ok
test omitted_block_never_activates_half_of_one_published_root_and_retry_is_atomic ... ok
test three_paired_replicas_converge_through_opaque_ciphertext_without_copying_sqlite ... ok

test result: ok. 3 passed; 0 failed
```

## Composed E2EE and authority path

The three-replica test starts one real persisted vault, enrolls three distinct
synthetic device signing-custodies through `HumanVault`, and copies the closed
seed into three independent SQLite stores. Human-authorized pairing creates a
fresh random namespace and E2EE key, binds their digest and the observed server
RPK pin with `SK_H`, and rejects a changed bundle or wrong observed pin. Each
replica commits a different `SK_SD`-signed causal event into the existing
reducer/outbox, publishes only authenticated ciphertext blocks to the opaque
store, and pulls complete published roots through `SyncReplica`.

All three reducers converge on the same digest and exact LWW winner. Duplicate
root/event replay is idempotent, received events are not echoed, and local
outbox acknowledgement occurs only after both root storage and publication.
The server file is scanned for the synthetic master/canary and is not a copy of
any custodian SQLite/WAL. A root with one omitted event block fails before any
header activates; restoring the exact block atomically activates both parent
and child. A signed device retirement remains unknown while offline, activates
on pull, and the composed `DelegatedVault::authorize` regression then returns
`AccessSuspended` on the next use by that retired custodian.

The server persists only `(namespace,transport RPK ACL)`, immutable
`(SHA-256,ciphertext)` blocks and published root hashes. Its ACL is explicitly
transport availability, not vault authority. Put and publish replay are
idempotent; get recomputes the requested hash; published roots cannot be
physically deleted by the housekeeping call. Block size is exactly bounded at
512 KiB, list is 1–256/default 128, and the reducer/outbox batch is 256. Tests
exercise the accepted 512 KiB edge, 512 KiB + 1 rejection, hash mismatch,
unauthorized RPK, missing publish, limit 0/257, replay and non-deletion of a
published root without truncation.

## Real-process Linux transport laboratory

Command and observed output:

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
key inputs must be owned by the process, regular non-symlink files at mode
0400; a pre-existing socket is removed only when it is a socket owned by the
server UID.

The lab replays the same put, publishes/lists/fetches across three identities,
rejects publication of a missing block, stops the server, alters its opaque
SQLite as a hostile operator, restarts, and observes hash-bound get rejection.
No account, SaaS endpoint, database/WAL copy, host service or persistent host
configuration is used.

## Final candidate checks and limits

```text
./scripts/cargo-local.sh test -p pm-sync --test e2ee_replication --locked --offline
# 3 passed; exit 0

./scripts/cargo-local.sh test -p pm-vault --test delegated_authorization --locked --offline
# 4 passed; exit 0

./scripts/test-linux-custody-lab.sh
./scripts/test-linux-human-transaction-lab.sh
./scripts/test-linux-content-lab.sh
./scripts/test-linux-authorization-lab.sh
./scripts/test-linux-sync-lab.sh
# all completed successfully; exit 0

./scripts/check.sh
# pinned inputs, fmt, workspace/all-target check, 50 tests and clippy; exit 0

./scripts/clean-offline-build.sh
# removed 11371 files/1.7 GiB and rebuilt the locked/offline workspace; exit 0

git diff --check
# exit 0
```

The sync test simulates an offline interval and omitted/replayed/reordered
delivery using independent real SQLite stores; it does not claim a public-
Internet partition test. Public Internet deployment, production service
installation, host reboot and production systemd/FDE remain explicitly not
run. The transport implements bounded immutable operational event packages;
ticket 17 does not add backup/import/history or provider actions. Formal Astra
review and unified merger verification remain separate final gates, so this
candidate evidence does not resolve the ticket.
