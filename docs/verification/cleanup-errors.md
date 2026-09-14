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

## Vault publication method and proposed public semantics

Focused filesystem regressions must force removal failures for the unique
temporary database, its `-wal`, and its `-shm` sidecars. `NotFound` is success
only for each optional cleanup target; every other error is retained while all
three removals are attempted exactly once.

The existing `VaultError` cannot truthfully represent both an operation result
and cleanup failure, especially after `hard_link(temporary, target)` has already
published the vault. The proposed narrow extension is a cleanup error variant
that carries the original `VaultError` when one existed, the count of failed
cleanup artifacts, and an explicit `published: bool`. Its display is fixed and
distinguishes “creation failed and cleanup also failed” from “vault was
published but cleanup failed”. It exposes a non-secret `was_published()` query
so callers cannot interpret the latter as “not created”. It does not delete the
published target, retry publication, or substitute another path.

Tests must cover: absent WAL/SHM accepted; all hard removal failures aggregated;
the original pre-publication error retained; and a post-hardlink cleanup error
reported with `published=true` while the authenticated target remains present
and openable. Full crypto/vault/TUI regression gates and the documented PTY lab
run only after an exclusive verification grant.

## Current test boundary

Until the public cleanup-error representation above is confirmed, no product
code or behavior test will be changed. Cheap syntax, link and diff checks do
not establish cleanup behavior.
