# Windows sync cost — 2026-10-14

**BLOCKED: full 70/68-event Windows acceptance remains unmeasured here.**
This lane delivers a local differential probe, not a performance fix or ticket
resolution. Principles: `prove`, `truthful-state`, `root-cause`, `small-owned`.

## Provenance and scope

Measured: pwd, Git root and T3 binding all identify
`/home/santana/.t3/worktrees/passwordmanager/t3-fe348d1a`, branch
`t3/windows-sync-performance`, parent/base
`ea57a7173424a7c607376ff5e0b49d2a19bc334f`. Code baseline supplied by the
coordinator: `d4b1be662a1b8766eff54c2b8269ef4c94770c54`.
Only `src/main.rs`'s test-module declaration, new `src/frame_cost_tests.rs`
and this report change. No production behavior changes; W7 is preserved.
Read-only diff against stale W1 `ea4c3584f77e846e782cddead6562e0eb73f196b`
found only an older endpoint-failure fixture in this lane; nothing imported.

## Native evidence refreshed read-only

Measured retrieval: `gh run list --repo SantanaJcp/passwordmanager --limit 15
--json databaseId,headSha,conclusion,workflowName`, then `gh run view
37191368827 --repo SantanaJcp/passwordmanager --log`, retaining only categorical
timing lines in `/tmp/chef-sync-windows-native-categories.log`.
[Windows run](https://github.com/SantanaJcp/passwordmanager/actions/runs/37191368827)
is failure at `2272a1f446fb80cf35566b2b4406338a61e4f1dd`.
This is a recovered historical native measurement, not native execution here.

- 70 events, 52 graphs, one export (0.697226 s), one process, one handshake,
  one server SQLite open. Push completed in 8.738605 s; 334 puts took
  7.628736 s. Partial pull: 46 gets / 1.001502 s. No complete pull/job total.
- Client TLS response reads: 382 / 8.236810 s. Server snapshot: 485 dispatches /
  2.576655 s, request reads / 0.216023 s, response writes / 0.027955 s;
  watchdog spawn/join / 0.024929/0.041584 s. These are different cutoffs;
  subtraction is not a measured causal cost.
- Local operations passed; device-sync explicitly failed; RETIRE is
  explicitly NOT_RUN (`sync-failed`).
  `NATIVE_SYNC blocks=334 roots=1 close=checked` proves durable push, not
  successful pull, visible TUI convergence or cleanup acceptance.
- [pmint8](integration-26-28.md#windows-nativo-pmint8--fail-por-plazo-conocido)
  remains distinct: 68 events/49 graphs, 238 puts complete at 15.007 s during
  push. Older 36-event successes are not comparable full-workflow acceptance.
  The supplied latest cleanup failure remains open; no remote cleanup executed.

## Source discrimination and local probe

Inferred: `lib.rs:SyncReplica::push` already exports once per page;
`windows_session.rs:serve` already owns one SQLite connection with ACL/commit
per RPC; `Session` already owns one client process. Repeating those fixes adds
no demonstrated benefit. Native phase 8 rejected watchdog amortization as the
dominant cost; no watchdog change is proposed.

Inferred source seam: `main.rs:write_frame` writes the four-byte header and
body separately through rustls. The pinned rustls `stream.rs:Write` sends TLS
I/O on each write. Measured local probe runs 32 sequential exchanges over one
real TLS1.3/RPK Unix socket pair, checks literal application bytes and ALPN,
and compares the current helper against a **test-only** combined frame:

```text
requests_per_mode=16 current_writes=32 candidate_writes=16
current_tls_bytes=1088 candidate_tls_bytes=736
1 passed; 0 failed (Linux x86_64)
```

This demonstrates extra transport work, not slow Windows I/O, a native
bottleneck, or seconds saved. No behavioral RED→GREEN or 15-second GREEN is
claimed. No production optimization ships without that causal evidence.

All Cargo/build commands use blocking `flock /tmp/pm-cargo-window.lock`,
`scripts/cargo-local.sh`, `--locked --offline`, `RUSTUP_AUTO_INSTALL=0`,
`RUSTUP_HOME=/home/santana/Documents/ChatGPT/passwordmanager/.toolchain/rustup`,
`CARGO_HOME=/home/santana/Documents/ChatGPT/passwordmanager/.toolchain/cargo`,
PATH prepended with `$CARGO_HOME/bin`, and this worktree's
`CARGO_TARGET_DIR=.../target-chef-sync-windows`.

Probe command:
`cargo-local.sh test -p pm-sync --bin pm-sync --locked --offline
frame_cost_tests -- --nocapture`; rc0, log
`/tmp/chef-sync-windows-frame-probe.log`. Socket pair only, synthetic ephemeral
keys, no on-disk fixture or external service.

Measured verification (same environment/lock above):

- `./scripts/cargo-local.sh fmt -p pm-sync`: rc0; no unrelated tracked change.
- `./scripts/cargo-local.sh test -p pm-sync --test e2ee_replication --locked
  --offline authenticated_session -- --nocapture`: rc0, 4 passed. Real
  process/TLS session preserves ACL per RPC, loss without internal replay,
  durable commits/WAL and 34 RPCs with one SQLite open. Log
  `/tmp/chef-sync-windows-session.log`.
- One `./scripts/check.sh`: rc0 (config/fmt/check/tests/Clippy); log
  `/tmp/chef-sync-windows-check.log`. Includes the new probe. It is not the
  52-case lab sweep and does not turn the three inherited G7 REDs green.
- `git diff --check`: rc0; local report links PASS. Own target artifacts remain
  untracked and excluded from the commit. No residual probe fixtures.

## Inherited omissions and next step

Inferred, unchanged: `lib.rs` push/pull/stream staging removal and failed
download cleanup ignore removal errors, hiding residual encrypted staging;
legacy put ignores temporary removal failure. `timing.rs:emit` ignores PMW2
stderr write failure (diagnostic loss); PMW1 sink failure explicitly reports
`PMW1_TIMING_FAILED`. `main.rs:dispatch_response` maps dispatcher failure to
`ok=false` without its detailed reason; `Session::Drop` can only print cleanup
failure. None is altered or used to infer success (`no-fallbacks`). Explicit
legacy transport selection is not automatic failover after session failure.

Recommendation to coordinator: obtain explicit authorization for one native
profiling round on the current composed W7 head, preserving full70/68 workload,
15-second TUI cutoff, request30 and strict cleanup. Align client/server RPC
scopes and separately measure PMW1 sink emission, stdio IPC and native pipe I/O;
current TLS spans do not measure all three. The extra-record candidate can
then be tested without batching RPCs or changing wire. Native-channel source
or ConPTY instrumentation belongs to the coordinator's other lanes; no such
cross-file edit was made. No one-way-door change is necessary or proposed.

NOT_RUN: Windows/macOS product execution, complete70/68 acceptance, RETIRE,
native cleanup, clean build/full lab sweep and formal Astra review35.
