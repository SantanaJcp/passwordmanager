# Cleanup-error propagation verification

## Scope and preserved behavior

This method covers only two previously reported cleanup suppressions authorized
under `Engram authorization/cleanup-and-canary`: Linux keyboard TUI clipboard
and terminal restoration, and `pm-vault::persist_new` temporary SQLite artifact
removal. It does not change clipboard ownership, secret exposure, vault
publication, KDF/crypto, TUI operations, or any unrelated cleanup.

## TUI method

First add focused regressions around injectable cleanup operations. The red must
show that `ClipboardLease::drop` discards a failed child stop/wait and that
`TerminalGuard::drop` discards alternate-screen, cursor and raw-mode failures.
The correction must:

1. track whether clipboard and terminal cleanup was already attempted so Drop
   never retries a failed explicit cleanup;
2. on every normal return, take an active clipboard lease, attempt its
   ownership-preserving child termination/wait, then independently attempt
   alternate-screen exit, cursor restoration and raw-mode disable;
3. return `Failure::Unavailable` if the operation or any cleanup fails, while
   still attempting every restoration and retaining the existing redacted
   public output;
4. on unwind, perform the same not-yet-attempted cleanup and emit only a fixed
   non-secret cleanup-failure diagnostic rather than silently suppressing it or
   panicking during unwinding.

Success requires focused early-return, simultaneous restoration-failure,
clipboard ownership and no-double-attempt tests. The real PTY/TUI laboratory
must remain green in the final authorized verification window.

## Vault publication method and authorized public semantics

Focused filesystem regressions force removal failures for the unique temporary
database, its `-wal`, and its `-shm` sidecars. `NotFound` is success only for the
optional WAL/SHM targets. Absence of the required owned temporary database is a
cleanup failure. Every artifact is attempted exactly once.

The narrow authorized extension is `VaultError::Cleanup`. Its payload retains
the original `VaultError` when one existed, the number of failed cleanup
artifacts and `PersistPublication::{NotPublished, Published}`. Publication is
recorded immediately after the hard link succeeds, before the parent-directory
fsync, because that fsync can fail after the target already exists. Publication
metadata is available only on the cleanup variant; there is no general Boolean
query that could falsely describe other I/O errors as unpublished. The fixed
display distinguishes creation plus cleanup failure from published-vault
cleanup failure. The implementation never removes the published target,
retries publication or substitutes another path.

Tests must cover: absent WAL/SHM accepted; all hard removal failures aggregated;
the original pre-publication error retained; and a post-hardlink cleanup error
reported with `published=true` while the authenticated target remains present
and openable. Full crypto/vault/TUI regression gates and the documented PTY lab
run only after an exclusive verification grant.

## Execution evidence

The initial test-first checkpoint `cd320084951b3a8e1328c7367c8882a43eafe456`
did not contain the cleanup implementation. The first focused build after the
implementation exposed a lifetime mismatch in the injected remover; the
corrected focused package run passed. The first complete `scripts/check.sh`
then reached Clippy and failed because the existing schema-heavy persistence
body's `too_many_lines` exemption remained on its new thin wrapper. Moving that
existing local exemption with the unchanged body fixed the lint without a
global suppression or behavior change. The later partial-initialization
regression first failed to compile because `Failure` intentionally has no
`Debug`, then Clippy rejected a test-local type declared after statements; both
were test-harness defects corrected without changing product behavior.

Final authorized Linux verification from this worktree:

```text
./scripts/check.sh
PASS (workspace build, tests and Clippy)

./scripts/clean-offline-build.sh
PASS (clean locked/offline workspace build)

./scripts/test-linux-custody-lab.sh
PASS bootstrap_sha256=ed97b913505fb69941d0fe1559478223a2fed076236dd99e7b1f279f71c4921f restart=process tls=1.3 rpk=mutual alpn=role-specific

./scripts/test-linux-tui-content-lab.sh
PASS tui-content types=7 fields=explicit-complete ... clipboard-race=preserved ...

./scripts/test-linux-tui-operations-lab.sh
PASS tui-operations keyboard=1 pty=1 tls-rpk=1 ... source-unchanged=1 no-secrets-preview=1
```

The focused tests cover simultaneous clipboard kill/wait failures, all active
terminal restorations, partial terminal initialization, no second explicit
cleanup attempt, optional sidecar absence, retained original operation error,
and a published target that remains authenticated and openable after cleanup
failure. The PTY labs cover the real ownership-preserving clipboard and normal
terminal early-return paths.

This base intentionally predates Ticket 24's access lab and additions. The
distinct merger must run the unified 20-lab suite after composing those changes;
this checkpoint does not claim that composed result.
