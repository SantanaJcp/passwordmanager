# Cleanup-error propagation verification

## Scope and preserved behavior

This method covers only two previously reported cleanup suppressions authorized
under `Engram authorization/cleanup-and-canary`: Linux keyboard TUI clipboard
and terminal restoration, and `pm-vault::persist_new` temporary SQLite artifact
removal. It does not change clipboard ownership, secret exposure, vault
publication, KDF/crypto, TUI operations, or any unrelated cleanup.

## TUI method

First add focused regressions around injectable cleanup operations. Any
behavioral red would need to show that `ClipboardLease::drop` discards a failed
child stop/wait or that `TerminalGuard::drop` discards alternate-screen, cursor
and raw-mode failures; the implementation checkpoint below did not produce
such a behavioral red. The correction must:

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

## Candidate execution evidence

The initial test-first checkpoint `cd320084951b3a8e1328c7367c8882a43eafe456`
did not contain the cleanup implementation and did not compile because helper
definitions were still missing; it is not a behavioral red. The first focused
build after the implementation exposed a lifetime mismatch in the injected
remover; the corrected focused package run passed. The first complete
`scripts/check.sh` then reached Clippy and failed because the existing
schema-heavy persistence body's `too_many_lines` exemption remained on its new
thin wrapper. Moving that existing local exemption with the unchanged body
fixed the lint without a global suppression or behavior change. Later compile
and Clippy failures (including `Failure` intentionally having no `Debug` and a
test-local type declared after statements) were test-harness defects, not
behavioral reproductions, and were corrected without changing product
behavior. The final injected-failure checks are green regression evidence; this
record makes no red-to-green behavioral claim.

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
candidate's checks and focused labs therefore do not claim the composed result.

## Distinct merger evidence

The merger composed candidate `4400ffb6af241dcb03e806abb594359a71e49762`
onto root `9db150c671703364069d0ed784cfa0034f5155aa`. There was one textual
conflict in `crates/pm-custody/src/linux/tui.rs`; its resolution retained the
Ticket 24 access/pending and reauthentication flow while applying the
candidate's cleanup guards. No other worktree or native target was changed.

The merger first ran the two focused package filters, then the repository
check and clean build, and finally one sequential pass over the sorted set of
20 Linux laboratory scripts. The exact lab invocation was:

```bash
export PM_KEYCLOAK_DIST=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/keycloak/keycloak-26.7.3
export PM_CFT_DIR=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/cft/chrome-linux64
for lab in $(find scripts -maxdepth 1 -type f -name 'test-linux-*-lab.sh' | sort); do
  "$lab"
done
```

Evidence from the exclusive Linux window:

```text
pm-vault cleanup tests: 3 passed
pm-custody cleanup tests: 4 passed (including the existing sync-job tests)
./scripts/check.sh: exit 0
./scripts/clean-offline-build.sh: exit 0
sequential lab sweep: SUMMARY count=20 failures=0
```

The historical clean log is `/tmp/pm-cleanup-clean-final.log`, and the one
historical lab sweep wrote `/tmp/pm-cleanup-final-test-linux-*-lab.log`. The
historical check path `/tmp/pm-cleanup-check-final.log` was later overwritten
by a subsequent merger invocation; it is not treated as recoverable historical
evidence. The lab output included the real TUI access/pending, content and
operations paths and the token-exchange, web-auth, passkey and recovery suites;
their `LIMIT` lines remain explicit non-acceptance boundaries for product-
browser, native and cross-platform coverage.

The published-target regression was tightened after an observed test-owned
residue: it now inventories the exact temporary database and sidecars plus
the target database and sidecars, bounds the read-only assertion before
cleanup, and removes/verifies each owned path without globbing or ignoring
non-`NotFound` errors. The final focused run and the final check left no new
artifact. The eight regular `0600`, UID-1000 sidecars for PIDs `3809446`,
`3811566`, `3827457` and `3832552` were verified as the merger's earlier
test/check artifacts and removed by their exact paths. Six older sidecar pairs
for PIDs `3682543`, `3692174`, `3697766`, `3729529`, `3743420` and `3748215`
predate the merger window; available logs do not prove their provenance, so
they were enumerated and left untouched rather than claimed as zero residuals
or deleted by a glob.

This evidence is Linux x86_64 only. It does not close native gates, dispatch
or publish anything, and it is not the formal Astra review.

## Merger cleanup-errors — custody and process ownership

This separate merger integrated the frozen candidate range
`a4b7704..f3fe05dbb39321deecc402007373a9511d1017d4` onto the clean root
`168573d`. Only the 13 code, test and script paths in that range were admitted;
the candidate issue-28 file and `docs/verification/ticket-28.md` were
deliberately excluded. No other worktree, native target, default branch,
workflow dispatch or publication was changed.

The merger applied the authorized cleanup-error contract and records that
method here: preserve the primary custody failure, append every typed failure
from an exact owned cleanup in order, report a fixed `CLEANUP_FAILED` marker,
and never retry, delete an authenticated target, substitute a path or hide an
error. The process-runner `close()` boundary performs one checked removal;
`Drop` reports a fixed marker only when no explicit close was attempted. The
fault labs inject one exact Linux syscall failure and use only synthetic data;
the RPC lab cuts a real peer after partial output and verifies the owned
partial file remains visible. These are cleanup propagation checks, not a new
behavioral RED claim; the candidate's earlier compile/harness-only checkpoint
remains classified above as non-behavioral.

Verification order in the exclusive Linux window was: formatting, path and
conflict scans; focused `pm-process-runner`, `pm-cli`, and `pm-custody` tests;
the two cleanup-fault laboratories; `scripts/check.sh`; one clean locked/
offline build; and one sorted, sequential sweep of all 22 Linux lab scripts.
The sweep used these fixed synthetic artifact directories and no retries:

```text
PM_KEYCLOAK_DIST=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/keycloak/keycloak-26.7.3
PM_CFT_DIR=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/cft/chrome-linux64
```

Observed evidence:

```text
focused process-runner: 9 passed, 2 ignored; CLI: 1 passed;
pm-custody cleanup filter: 10 passed across lib/bin targets;
cleanup fault lab: PASS keygen/write-new/nested typed cleanup;
RPC cleanup fault lab: PASS real peer-cut cleanup;
scripts/check.sh: exit 0;
scripts/clean-offline-build.sh: exit 0;
sequential lab sweep: SUMMARY count=22 failures=0.
```

The current-run logs are `/tmp/pm-four-cleanups-root-check.log`,
`/tmp/pm-four-cleanups-root-clean.log`,
`/tmp/pm-cleanup-focused-process-runner.log`,
`/tmp/pm-cleanup-focused-cli.log`, `/tmp/pm-cleanup-focused-custody.log`,
`/tmp/pm-cleanup-focused-nested-lab.log`,
`/tmp/pm-cleanup-focused-rpc-lab.log`, and
`/tmp/pm-four-cleanups-root-test-linux-summary.log` with one per-lab log
under the same prefix. The current cleanup fault outputs contain only fixed
synthetic markers; no secret or dynamic OS error is asserted or printed.

This is Linux x86_64 evidence only. It does not close native, Windows or
macOS gates, does not claim the full product acceptance matrix, and is not the
formal Astra review.
