**Source verdict: PASS. No P0 or P1 findings.** Nothing here certifies native behavior, security or a ticket. I am Claude Opus 5.5 and the author is Codex Sol, so I reviewed directly with no panel (`cross-review`).

**Pinned (inferred, `git diff --stat ea57a717...<head>`):** all four heads resolve and every diff is non-empty. Windows touches 7 files (+736/−37), macOS 3 (+135/−1), TLS 3 (+240) and G7 3 (+409). The touched paths match the brief's allowlist.

**Evidence gap.** Every measurement below is as the authors reported it; I ran no tests, as briefed. Partway through, Claude Code's temp directory hit its disk quota (EDQUOT), so every later command failed. As a result I did not read the macOS report, the full Windows reports, spec §15/G1/G7 or CONTEXT. My findings rest on the four code diffs, the TLS and G7 reports in full, and grep excerpts of the Windows report. This is a gap in my review, not a pass.

## Windows retirement diagnostics (6a2a81fa)

**Oracle preserved (inferred).** I compared `observer.rs` against the removed inline code:
- Same read-only open.
- Same SQL text.
- The subject `[0x28;16]` is still bound as a BLOB (`&[u8]` now, `Vec<u8>` before).
- `count != 1` still fails, and both sync counts must still be greater than 0.

**A failure cannot become zero or PASS.** `finish` (`observer.rs:69-82`) suppresses the PASS line whenever close fails, and keeps both the primary error and the close error, primary first.
- The diagnostics print only fixed phase names and numeric SQLite codes, never `Display`/`Debug`, so no query text or values leak.
- The expected codes in the tests come from SQLite itself (1 SQLITE_ERROR, 14 CANTOPEN, 5 BUSY), not recomputed by the code.
- The BUSY close is a real one: an unfinalized statement makes rusqlite's `sqlite3_close` fail.
- The tests would fail on the old code, which printed no diagnostics at all.
- `check.sh` runs `cargo test --workspace --all-targets`, which includes these example tests.

**Python probe (`crates/pm-native-channel/tests/chef_retire_observer_probe.py`).** The rows it inserts use an independent 0x28 subject literal. It exercises Python's `sqlite3`, not rusqlite's binding, and no gate runs it, so it is evidence only. The Rust tests do cover the binding.

**Cleanup reconciliation.** The script's blob hash `0019a07d` matches the "byte-identical W1" claim. Each staging directory is fully validated before it becomes removable. A completed sync that leaves staging behind still records an error and fails the run, even though cleanup continues.

- **P3 (inferred), `scripts/test-windows-custody-lab.ps1:379`.** Service PIDs are only recorded by `Get-StoppableServicePid`.
  - Case: the service is started by `sc.exe start` (lines 1013 and 1325) and dies on its own before anything records its PID, after creating `.pm-sync-stage-<pid>`.
  - Result: cleanup throws "staging owner PID is outside the owned SCM ledger" and leaves the service directory in place.
  - This is fail-closed and visible, not a mask. Windows PID reuse can trigger the same false failure.
- **P3 (inferred, new in this diff), `ps1:1358`.** Final cleanup now goes through `Get-StoppableServicePid`, which requires the state to be `Running` (`ps1:46`).
  - Case: the service is in StartPending, StopPending or Paused.
  - Result: it throws before `sc delete`, and the service stays installed. The old `Stop-Service` path would have tried to stop it.
  - The error still reaches `cleanupErrors`, so it is not hidden.

The native RETIRE cause is still unknown. The new diagnostic has not run on Windows, so RETIRE remains NOT_RUN.

## macOS observation diagnostics (837f5564)

`unlock-markers` is diagnostic output only. The `wait_text` oracle is unchanged: it still checks `expected in` the current screen, and the regression's final check proves the history does not replace it. The markers are fixed strings, the canary is excluded, and the parser-pending state stays distinguishable. Both `assert_screen_observer_regression` and the CI config verifier call the test.

The VT input is synthetic, not bytes captured on ARM. The 8s unlock and 30s stream deadlines are unchanged and the root cause is still open. Nothing is wrong in the source.

## TLS framing probe (5e26f3b4)

The probe is test-only (`#[cfg(all(test, unix))]`) and uses the product's `server_config` and `client_config` (raw public keys, ALPN). The receiver checks the request and reply bytes with the existing `read_frame`/`write_frame`.

**Independent check (inferred, arithmetic).** A TLS 1.3 AEAD record adds 22 bytes. With the length header and body sent separately: (4+22)+(20+22) = 68 bytes per frame, and 68×16 = 1088. Sent together: 46 bytes per frame, and 46×16 = 736. Both match the reported numbers exactly, as does 32 writes against 16.

- **P3, `frame_cost_tests.rs:113-120`.** The test only asserts `>`, so the exact 32/16 and 1088/736 figures are not guarded. That is acceptable for a differential.

The report claims no speed gain and no native cause, and says the Windows transport may not go through this rustls path.

## G7 staging and custody-loss probes (0eff9d93)

**Witness `g7_loss_witness.py`.** It replaces `lab.counts` and reads every table inside one read-only transaction. `REPO`, the journal path and the lab's `__file__` lookups all resolve correctly. The original assertions, cleanup and exit code still decide the result.

- **P3, `g7_loss_witness.py:38`.** The new `assert calls == [1]` runs inside `counts()`, before the original `assert after == before` (`custody_loss_lab.py:134`).
  - Case: both the counts differ and the provider was called again.
  - Result: the reported error changes from "authority or receipts changed across loss" to "witness observed repeated login". Pass/fail stays the same, but the docstring's "without changing its outcome" is not quite true.
  - It did not apply in the reported samples, which all showed calls=1.

**Rust test `g7_prepared_stream.rs:38`.** I checked the table indices against `TABLES`. A real audit trigger makes the final commit fail, and the test requires every row to be rolled back. After reopening, the only change is one HumanUnlock audit row. Retrying with the same signature produces the exact content, one receipt, and replay causes no new effect.

- **P2, Request axis.** This test runs in `check.sh` and requires staging to be kept after a failed final commit. That is the same leftover state the matrix lab reports as RED (staging 1 / streams 1 / chunks 17).
  - That fits the current rule that deleting retained payloads is not authorized.
  - But if owner decision 4 picks option 2 (abort and delete), this test must be replaced in that same change, so two contradicting oracles never coexist (`no-fallbacks`).
  - The report already says the test is not a fix.

The probes measure cleanup and counts but do not claim security from them. The historical 49/52 sweep and the three inherited REDs stay non-PASS.

## Merge danger

These are two-way doors: test code, scripts and reports only. Product, frame, crypto, wire, grants, revocation, KDF and the fixed deadlines (Windows 15s, macOS 20s, unlock 8s, stream 30s) are unchanged in the diffs. The observable diagnostics are safe because close failures and wrong counts always produce an error and never PASS (`observer.rs:69-82`, plus unit tests that would fail on the old code); I traced that by reading, not by running it.

Still unproven:
- Native Windows RETIRE and the new diagnostic on Windows.
- The macOS root cause and a raw VT capture.
- Native sync cost.
- Owner decision 4 for G7.

I found no new fallback. The generic worker/handler/settle code and the CLI Unavailable/env/JSON masking are inherited and out of scope. No file was written.
