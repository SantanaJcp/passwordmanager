**Source verdict: PASS. No P0 or P1 findings.** This is a source review only. It does not certify native behaviour, security, or any ticket.

**Route:** the authors are Codex (Sol, per the brief; the commits carry no co-author trailer). I reviewed directly as Claude Opus 5.5 on the Standards, Request and Design axes, using `git show` / `git diff` on the exact SHAs and nothing else. I ran no builds, tests, labs or temp files. Every count, RED→GREEN, `rc0` and native number below is **author-reported**. Everything I say about the code is **inferred** from the `file:line` I cite.

**What I checked against the request (inferred):**
- **Windows observer** (`observer.rs:20-22, 84-133`)
  - The retirement check is preserved: READ_ONLY open, the same exact SELECT, subject `0x28×16` bound as a BLOB (`as_slice()`, same as the old `Vec<u8>`), and `count != 1` is rejected.
  - Close always runs. A close failure suppresses PASS, and when both fail, the query error and the close error are printed together in order (`finish`, :70-81).
  - Diagnostics carry only fixed phase names and numeric SQLite codes. There is no Display/Debug of the error, no SQL text, no paths and no row values. When codes are missing it prints `not-available`, not an invented `0`.
  - The caller still maps every failure to `Failure::Unavailable` and exit 1. The `WINDOWS_HUMAN_FIXTURE_FAILED` stderr path already existed (`windows_human_tui_seed.rs:15`), so the new stderr lines add no new PowerShell `$ErrorActionPreference='Stop'` risk.
- **Windows cleanup:** the staging inventory deletes nothing by pattern. Unknown nodes, reparse points, unrecorded owner PIDs and unexpected child names all throw. A successful sync that leaves staging behind is kept as an aggregate failure (:462-467). The staging grammar matches the product's names (`pm-sync/src/lib.rs:1153,1661,974-992`). The staging owner is the in-process custody service PID, and that PID is recorded in the ledger.
- **macOS:** the change only adds three on-screen marker flags. `wait_text` acceptance, the 8s unlock and 30s stream deadlines, and the screen-dump rule (no secrets printed) are unchanged. The test confirms that history does not substitute for the current screen.
- **Sync:** product code is unchanged; the probe is test-only (`#[cfg(all(test, unix))]`). The reported 1088/736 bytes match the per-record cost of TLS 1.3 (16 × (26+42) versus 16 × 46). That is my arithmetic check, not a measurement.
- **G7:** no product, schema or shared-oracle change. The witness leaves the lab's own assertions and exit code in charge, and compares full rows of 11 authority tables, so it does not infer authority from an audit-count delta. The report says "refutada en estas muestras" ("refuted in these samples") and stops there.

### Act on (P2, non-blocking)

**S1 — Standards (`root-cause`, `truthful-state`): a reused PID can falsely block Windows cleanup.**
- **Where:** `scripts/test-windows-custody-lab.ps1:370-372` @6a2a81fa.
- **Code path:** `Repair-OwnedCleanupAcl` (finally block) → `Register-StoppedSyncStages`. This re-queries `Win32_Process` for every service PID recorded since start, and fails if any of them is alive.
- **Why that's wrong:** `Stop-OwnedService:60-61` already proved each PID dead when it stopped. Windows reuses PIDs aggressively. Between those stops and cleanup the run executes `cargo build`, TUI child processes, the sync server, and CIM calls that start `WmiPrvSE`.
- **Failure:** a recorded PID reused by an unrelated process makes cleanup throw "owned custodial PID is alive". The fixture root is left behind and the run is RED with no product cause.
- **How to show it:** record a PID, stop it, start any long-lived process until it gets that same PID, then call `Register-StoppedSyncStages`. This is fail-closed, so it is not a security issue.
- **Fix direction:** check that the service record is stopped or deleted, and rely on the stop-time proof of PID death. Alternatively, record each PID's creation time and compare it.

**S2 — Standards (`prove`: "Test Behavior, Not Implementation"): the sync probe will block its own fix.**
- **Where:** `crates/pm-sync/src/frame_cost_tests.rs:113-120` @5e26f3b4.
- **Problem:** it asserts that current framing does more writes and bytes than the combined candidate, and it runs in the default `check`.
- **Failure:** once someone combines `write_frame` into one write, this test goes RED with "split framing should exhibit…". It locks in the inefficiency the report proposes to test. Have it print the measurement only, or make it opt-in with `#[ignore]`.

### Consider

**R1 — Design/Request (`doors`, `prove`): the G7 test pins today's storage layout as well as behaviour.**
- **Where:** `crates/pm-vault/tests/g7_prepared_stream.rs:118-125` @0eff9d93.
- **Problem:** it requires the `human_staging*` rows (indexes 8-10) to be unchanged across reopen. Both of the report's owner options (decision 4) change that representation, so this test would have to be edited whichever option is chosen.
- **What is worth keeping:** the durable behaviour is in :129-163 — retry with the same signature, exact content, a single receipt, and replay with no new effect.
- **Suggestion:** keep the assertions on rows 0-7, 11 and 14. Move rows 8-10 into a separately named characterization test so the owner's decision does not quietly become this oracle.

### Noted

- **G7 witness is not a pure observer.** `g7_loss_witness.py:27,55` replaces the lab's read-write `counts()` with a `mode=ro` snapshot. The original connection, closing after the daemon stops, can checkpoint and delete the WAL; the read-only one cannot. So the witness's bootstrap `rc1`, versus the original's `rc0`, cannot be attributed purely to intermittency.
- **Test cleanup can abort.** `observer_tests.rs:25` calls `remove_file(...).unwrap()` inside `Drop`. If removal fails while a failing test is already unwinding, the process aborts and the original failure message is lost.
- **Python probe is not wired into anything.** `chef_retire_observer_probe.py` runs from no script or workflow, and overlaps `retirement_controls…` (although it does use the real STRICT schema). The same applies to `g7_loss_witness.py`.
- **Synthetic Windows staging fixture is not representative.** It provisions an explicit installer ACL (:413-415). Real product staging inherits the sealed parent's ACL, so the inventory's ability to read real staging children is only historically evidenced (run 37188616185 found 0 directories). It is not exercised here.

### Dismissed

- **Unchanged cleanup on non-Running services.** The cleanup-time call to `Get-StoppableServicePid` throws if the service is in a pending state. That fails loud, with the same coverage as the old `Stop-Service`.
- **macOS regression runs twice.** The diagnostic regression is called from both the verifier and `assert_screen_observer_regression`. That is harmless.

### Evidence gaps (not bugs)

- Windows PowerShell and the cfg(windows) caller were NOT RUN (author: `pwsh` is not available). RETIRE's native cause is still unknown.
- macOS: no ARM run and no raw VT capture. The streaming phase cause is undiagnosed.
- Sync: no native profiling, and no speed claim.
- G7: the 3 inherited REDs and the 49/52 baseline stay non-green.
- The integrator's run on the exact heads has not been reviewed here.

### Merge danger

- **Door:** all four are two-way doors (tests, probes and reports), with no change to product, wire, KDF, schema or grants.
- **Blast radius:** lab false-REDs (S1) and future blocked fixes (S2, R1).
- **Why it is safe:** every change in these heads only adds checks or is test-only. Proven to "pointed at the line" level, not "ran it".
