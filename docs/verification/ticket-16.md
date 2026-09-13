# Ticket 16 verification evidence

Date: 2026-09-12. Requirements: R05, R06, R16, R17. Observed host: Linux
x86_64; Rust 1.98.1; libsodium 1.0.22; SQLite is the repository-pinned
bundled build. Keys, identifiers, records and paths are synthetic and confined
to disposable test directories.

## TDD red/green

After the public signing and reducer seams compiled, the first behavioral test
ran with the reducer deliberately returning an empty view:

```text
./scripts/cargo-local.sh test -p pm-vault --test causal_reducer --locked --offline
```

Observed red result:

```text
running 1 test
test concurrent_revisions_converge_by_exact_tuple_in_every_delivery_order ... FAILED

thread 'concurrent_revisions_converge_by_exact_tuple_in_every_delivery_order' panicked at crates/pm-vault/tests/causal_reducer.rs:63:30:
called `Option::unwrap()` on a `None` value

test result: FAILED. 0 passed; 1 failed
error: test failed, to rerun pass `-p pm-vault --test causal_reducer`
```

This was a behavioral red, not a missing API or dependency failure: three
human/device-signed concurrent revisions had been accepted, while the empty
reducer did not produce the expected item winner.

After incremental implementation, the same focused command reports:

```text
running 6 tests
test altered_batch_is_rejected_atomically_and_checkpoint_is_only_a_verified_cache ... ok
test reducer_consumes_the_existing_human_commit_ledger_instead_of_a_parallel_store ... ok
test pending_delivery_replay_and_fork_need_all_signed_branches_before_successor_activates ... ok
test delete_beats_future_clock_edit_until_restore_sees_every_delete_and_purge_is_terminal ... ok
test concurrent_revisions_converge_by_exact_tuple_in_every_delivery_order ... ok
test crossed_retirements_are_monotonic_cuts_and_revocation_needs_causal_resume_not_time ... ok

test result: ok. 6 passed; 0 failed
```

## Signed reducer and composed paths

The tests use only the public `HumanVault::sign_causal_event`,
`SignedCausalEvent` transport envelope and `CausalReducer::{open,apply,view}`
boundaries. They provision real synthetic `SK_H` and independent per-device
`SK_SD` custody, persist into the existing `authority_events` ledger, close
and reopen the SQLite vault, and inspect the public reduced content/authority
view. No production reference model substitutes for reduction.

Coverage includes:

- three devices and four delivery permutations with exact
  `(modified_at,issuer_device,revision_id)` LWW, including a far-future clock;
- child-before-parent pending activation, duplicate replay, a retained same-slot
  fork, and a technical join whose parents recognize both branches;
- crossed device retirements, an accepted-prefix cut that admits its tip but
  rejects a later positive event, global suspend/resume, agent revoke, and a
  causally acknowledged next generation without timestamp ordering;
- concurrent delete/edit retaining the LWW winner in trash, incomplete and
  complete restores, terminal item purge, and refusal to purge the winner in
  the purge event's causal view;
- valid and omitted/bogus checkpoint state digests, cache-only restart, durable
  signed headers, altered signature rollback, and an over-limit batch.

The reducer verifies canonical versioned CBOR, the trusted human signature,
the issuing generation's human-bound device-key package, and the device event
signature before an atomic batch publication. Missing parents remain pending;
invalid signed envelopes fail the entire batch. The pre-existing unique
emitter-slot constraint was replaced by a non-unique index so both fork
branches are retained. Existing ticket 04–07 human event bodies remain
reducible, rather than creating or migrating to a ticket-local ledger.

## Resource and scope limits

The exercised batch boundary is 256 events; 257 is rejected before storage.
Each event body is capped at 256 KiB, parent/reference lists at 4096, and the
pending set at 4096 events or 256 MiB. The transport decoder rejects envelopes
above its fixed bound and trailing/non-canonical data. Checkpoints are caches:
they neither grant permission nor truncate signed headers.

Ticket 16 adds no synchronization server, network synchronization opcode,
provider action, attempt table, backup/import path, passkey authentication, or
host configuration. The existing Linux labs exercise the unchanged public
mutual-TLS/RPK custody and human/agent paths; reducer transport between devices
belongs to ticket 17. Host reboot and production systemd/FDE validation remain
explicitly not run.

## Final candidate checks

Candidate implementation commit:
`56b41ee3b9871bd8163ccc6594498728d2d52ea6`.

```text
./scripts/cargo-local.sh test -p pm-vault --test causal_reducer --locked --offline
# 6 passed; exit 0

./scripts/cargo-local.sh clippy --workspace --all-targets --locked --offline -- -D warnings
# exit 0

./scripts/check.sh
# pinned inputs, fmt, workspace/all-target check, 46 tests and clippy passed; exit 0

./scripts/test-linux-custody-lab.sh
./scripts/test-linux-human-transaction-lab.sh
./scripts/test-linux-authorization-lab.sh
./scripts/test-linux-content-lab.sh
# all exited 0; mutual TLS 1.3 RPK/role ALPN, CRUD/audit atomicity,
# authorization rechecks and streaming limits remained green

git diff --check
# exit 0
```

The labs reported their existing explicit limitation:

```text
LIMIT reboot_host=NOT_RUN production_systemd_fde=NOT_RUN
```

Formal Astra review and unified merger verification remain separate final
gates. This evidence does not resolve the ticket.
