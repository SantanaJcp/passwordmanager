# macOS stability — focused local handoff, 2026-10-14

Status: **BLOCKED native; diagnostic candidate only.** No product fix or ticket
resolution claimed (`truthful-state`, `root-cause`).

Measured binding: T3 attached, branch `t3/macos-custody-stability`, worktree
`/home/santana/.t3/worktrees/passwordmanager/t3-8528f022`; initial HEAD and
parent base `ea57a7173424a7c607376ff5e0b49d2a19bc334f`. Code baseline supplied
by the owner: `d4b1be662a1b8766eff54c2b8269ef4c94770c54`. Only the harness,
its CI-config verifier and this report change. No product, launcher, deadline,
authentication, wire, KDF, schema, replay or cleanup-policy change.

Measured historical evidence, retrieved read-only through GH API:
[run37191369928](https://github.com/SantanaJcp/passwordmanager/actions/runs/37191369928)
is completed/failure at `2272a1f446fb80cf35566b2b4406338a61e4f1dd`;
Intel job111404083763 success, ARM job111404083884 failure. ARM log saved as
`/tmp/chef-macos-stability-20261014-arm.log`, SHA256
`41bc7a7f25be043fab07b5d136bf930f3bd8b49ff34bf371c4a2418076f587c1`.
It records unlock wait8106ms, password-prompt/ground, then post-cutoff samples
with TUI catalog/SQLite/socket-read and custodian unlock/SQLite/socket-read.
Full25 independently times out in `human-streaming-file` after30s. The saved
log has zero cursor-positioning VT sequences and zero W6 phase records; no
recorded TUI-byte replay is available. Earlier dual-CPU PASS is not substituted.

Inferred source map: `start_macos_tui` sends the password through the PTY and
waits for the unlocked status; `_screen_diagnostic` selected the first matching
category, concealing overlapping markers. Product `run_authenticated_session`
retrieves/decodes the catalog before setting unlocked status; `draw` also shows
the Items title while prompting. Thus catalog sample activity is compatible
with work continuing after the cutoff, but neither it nor the Items title
proves unlock completed on time. `run_tui_ticket25_matrix` calls the streaming
command through `run`/`subprocess.run`, independently of the VT parser.

The candidate adds independent **current-screen** password/unlocked/Items bits
to failure diagnostics, preserving parser/mode/event/child fields and every
acceptance predicate. `101` means prompt+Items, not successful unlock; `111`
exposes overlapping status markers. Neither proves product completion or a
parser defect. `child=alive` remains the inherited EOF-derived label, not an
OS liveness measurement. No input, screen contents or raw bytes are printed.

Local regression uses explicitly synthetic cursor-addressed VT bytes, including
split control input, overlapping markers, erased cells and a private-cell
canary. It checks marker distinctions, no cell disclosure and rejection after
current evidence disappears despite retained screen history. This proves the
diagnostic gap only, not the native failure's cause (`prove`, `small-owned`).

Measured local verification:

- RED rc1 before diagnostic change: `flock /tmp/pm-cargo-window.lock python3
  -B -c 'import sys; sys.path.insert(0,"crates/pm-custody/tests"); import
  macos_lab; macos_lab.assert_unlock_cutoff_diagnostic_regression()'` failed
  specifically at the missing `unlock-markers=100` assertion.
- Same command GREEN rc0 after change; added erasure/history and private-cell
  controls also pass in the final full observer run.
- `scripts/verify-macos-custody-ci-config.sh` and `python3 -B -c 'import sys;
  sys.path.insert(0,"crates/pm-custody/tests"); import macos_lab;
  macos_lab.assert_screen_observer_regression()'` both rc0 under one blocking
  flock. Log `/tmp/chef-macos-stability-focused.log`; Linux fixtures only.
- Python AST, shell syntax and `git diff --check` rc0.
- Single `scripts/check.sh` rc0 (config, fmt, workspace check/test/Clippy),
  Linux x86_64; log `/tmp/chef-macos-stability-check.log`. This is not the
  standalone52-case lab sweep or native acceptance. Its private build artifacts
  remain untracked in `target-chef-macos-stability/` and are not committed.

All lab/build commands use blocking `flock /tmp/pm-cargo-window.lock`.
Cargo uses the immutable root
toolchain and this worktree's `target-chef-macos-stability`, with no installs.

Inherited alternatives, unchanged (`no-fallbacks`):
`VtScreen.application_text` retains the last application snapshot after leaving
the alternate screen, obscuring the restored primary screen for application
observers. `classify_shared_control_exit`/`run_shared_pasteboard_control` accept
an owned SIGTERM exit for the supporting control; this does not prove natural
completion. `AGENT_PASTEBOARD_LAUNCHER.command_output` maps failed metadata
commands to None, losing exact failure detail, then reports unavailable or
indeterminate. None is changed or used as replacement native acceptance.

Next action: coordinator reviews/composes this diagnostic candidate. Any new
native execution needs explicit authorization; none was dispatched here. A
future ARM cutoff can distinguish parser-pending/overlapping/unchanged-prompt
observations without logging secrets, while all failures remain failures.
Streaming needs a separate phase-level capture from its real execution before
any fix; the present log cannot discriminate its internal cause. Keep8s unlock,
30s streaming,20s sync. Native keyboard acceptance, fresh Intel/ARM execution,
reboot/FDE/signing and formal final review35 remain unexecuted. No one-way-door
change is proposed and no owner decision is required for this local diagnostic.
Clean build,52-case sweep and sibling integration are reserved for the integrator
and were not run. The inherited52/49rc0/3RED state remains non-green.
