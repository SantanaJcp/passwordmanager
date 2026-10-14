**Verdict: ISSUES at the source level, with no P0 or P1.** I found one P2 and three P3s. This is a source review only. It does not certify native behaviour, security or any ticket.

**Route and scope.** All four candidates were written by Codex Sol. I'm a different model (Claude Opus 5.5), so I reviewed directly with the minimalist lens and launched no panel (`cross-review`). All four heads resolve and each diff is non-empty:
- Windows: 7 files, +736/−37
- macOS: 3 files, +135/−1
- TLS: 3 files, +240
- G7: 3 files, +409

Every measured number below comes from the authors' reports. My own claims come from reading source. I wrote no files.

## What each request needed, and what the source shows

- **Windows retirement observer.** All six requirements hold in the source:
  - It opens SQLite read-only (`observer.rs:160`).
  - The subject is `[0x28;16]` (`:95`) and it requires exactly one event, `count != 1` → error (`:195`).
  - The connection is closed explicitly before PASS can come out (`:204-205`, `finish` `:148`).
  - Diagnostics are a phase plus fixed categories and numeric codes only, with no `Display`/`Debug`, SQL, paths or row values (`:99-129`).
  - A query failure and a close failure are both reported, query error first (`:151-154`).
  - The Windows caller still ends in `Failure::Unavailable` and exit 1 (`windows_human_tui_seed.rs:659-663`).
- **W1 cleanup script.** It is byte-identical to W1: the PowerShell file's blob id is `0019a07d…` at both `ea4c3584` and the head. Staging removal is gated on:
  - the service and every recorded service PID being stopped (`ps1:537-541`);
  - a closed name grammar matching product `sync_stage` (`pm-sync/src/lib.rs:1658-1663`);
  - rejection of reparse points, foreign owners and unexpected children, with the whole directory validated before anything is added to the removal list (`:546-558`).

  Leftover staging after an accepted sync stays a failure in the final result (`:628-634`). Nothing is deleted outside the owned ledger.
- **macOS.** Only the failure-diagnostic text changes (`macos_lab.py:935-944`). `wait_text`, its 8 s default and all acceptance checks are unchanged. Only marker bits are logged; the test's "synthetic" canary must not appear in the output (`:1300`).
- **TLS.** `main.rs` gains only a `#[cfg(all(test, unix))]` module; no product code changes. The reported 32→16 writes and 1088→736 bytes fit TLS 1.3's 22-byte per-record overhead: (4+22)+(20+22)=68 bytes ×16 = 1088, and (24+22)×16 = 736.
- **G7.** No product, schema or verifier changes. The witness patches `lab.counts` only at runtime, and the original lab's assertions still decide the exit code. The Rust test pins the confirmed G4 rule: a failed final commit leaves every durable row unchanged, and the same signed prepared commit can be retried and gets its receipt.

No new fallbacks in any candidate. The inherited ones (`InnerConnection::drop` ignoring close, cleanup in `pm-sync`, `run_provider_once`) are reported as unchanged in the authors' notes.

## Findings

**P2 · Standards · `prove`, `small-owned` — `crates/pm-sync/src/frame_cost_tests.rs:113-120`**
- **What's wrong:** the test asserts the inefficiency exists (`costs[0].0 > costs[1].0`, "split framing should exhibit its extra transport work"). Through `main.rs:45-46` it runs in `check.sh`'s `cargo test --workspace --all-targets`.
- **Repro:** change `write_frame` (`main.rs:1027-1029`) to write `len||body` with one `write_all`, then run the same probe command. It fails at `:113`.
- **Why it matters:** the report's own "extra-record candidate" fix would turn the gate red, so a finite diagnostic has become a permanent check on a defect.
- **Smallest fix:** add `#[ignore]` and run it with `--ignored` (the documented command), or keep only the wire-equality checks in the default suite.

**P3 · Standards — `crates/pm-vault/examples/g7_loss_witness.py:37`**
- **What's wrong:** `assert calls == [1]` runs inside the counts hook, before the original `assert after == before` (`custody_loss_lab.py:134-136`).
- **Effect:** if the provider were called again and the counts also changed, the first failure shown would be "witness observed repeated login" instead of the lab's own message. The exit code doesn't change, and in the reported runs calls stayed at 1, so nothing measured is affected. The docstring's "without changing its outcome" holds only for the exit code.
- **Fix:** record the calls in the summary instead of asserting them.

**P3 · Standards — `crates/pm-custody/examples/windows_human_tui_seed/observer_tests.rs:239-242`**
- **What's wrong:** `Drop` calls `remove_file(...).unwrap()`.
- **Effect:** if a test assertion has already panicked and the removal also fails, the second panic aborts the test binary and the other tests' results are lost. Cleanup only, no effect on the oracle.

**P3 · Request/report — `crates/pm-native-channel/tests/chef_retire_observer_probe.py:489`**
- **What's wrong:** `test_duplicate_events_remain_rejected` only checks that the SQL count is 2. The rejection itself is tested in the Rust test (`observer_tests.rs:274`).
- **Context:** the probe also parses Rust source with regexes; it already broke once on rustfmt and isn't wired into `check.sh`. It's acceptable as a one-shot probe if it's named as one.
- **Same commit range:** the earlier report's pointer `windows_human_tui_seed.rs:648–687` is now stale at this head (now `:652-666`).

## Independence of the checks

- **Windows:** expected SQLite codes 1, 14 and 5 are SQLite constants, and the five count controls are written by hand. The Rust tests use a simplified two-column table; the Python probe uses the real schema. Together they cover both sides.
- **macOS:** the expected marker bits are hand-written over synthetic terminal bytes, and the RED was reported failing at the missing assertion.
- **G7:** full-row snapshots are compared before and after, with no recomputation in product code. The TLS P2 is a different problem: its comparison is independent, but what it pins is the defect.

No tautological test found.

## Not run (gaps, not bugs)

- **Windows:** no native run of the new observer diagnostics or the current PowerShell (no `pwsh` locally, per the report). The cause of the RETIRE failure is still unknown. Push 334 / root 1 doesn't show pull, convergence or retirement.
- **macOS:** no ARM rerun and no raw terminal capture. The cause of the 30 s streaming timeout still needs a phase-level capture. Pattern `101` (prompt plus Items, no unlocked marker) does not mean the vault unlocked.
- **TLS:** no native causal or speed evidence; the full 70/68-event acceptance is unmeasured.
- **G7:** the matrix RED, the vault RED and the intermittent bootstrap case remain. The audit 10→12 sample can't prove security from counts. Picking option 1 or 2 is still owner decision 4.
- **Inherited suite:** the 52-case sweep, 49 passing plus three G7 REDs, stays non-green.

**Risk if merged.** All four are two-way doors confined to tests, examples, probes and reports, so a revert undoes any of them. What makes them safe: no product file changes except one test-only module declaration. That is shown by the file lists and the `cfg` attribute, not by running anything.

No new owner question is needed. The only one-way decision is G7 option 1 or 2, which is already open as owner decision 4.
