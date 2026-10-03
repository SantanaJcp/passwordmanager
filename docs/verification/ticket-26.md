# Ticket 26 verification method and checkpoint

Created: 2026-09-13. Updated: 2026-10-03 (America/Santo_Domingo).
Requirements: R01, R02, R09, R10, R11. This is the written verification method
and native CI chronology for the macOS custody port. The current state is an
**implementation checkpoint with partial native evidence, not complete Ticket
26 acceptance**. Native claims refer only to the exact GitHub runs/SHAs and
CPU observed below; local Linux checks cannot execute Darwin kernel, launchd,
AppKit or macOS ACL behavior. Ticket 26 remains claimed, pending integration
and the recorded gates; reboot/human/platform support are not certified here.
See the [October 3 clipboard and final-phase checkpoint](#october-3-clipboard-and-final-phase-checkpoint)
for this bounded continuation and the [October 2 consolidated checkpoint](#october-2-consolidated-checkpoint)
for the earlier full-matrix baseline. Earlier observations remain historical
evidence; a bounded fixture PASS does not establish full Ticket26 acceptance.

## October 3 clipboard and final-phase checkpoint

Bounded implementation worktree: `.worktrees/26-clipboard`, branch
`codex/pm-26-clipboard`, based on `36eecc8c365328ca4c8ca074ae013564767d79b7`.
This work does not integrate the main branch, merge PR #1 or change ticket status.

The task authorizes categorical diagnosis, native CI and an independent fixture
mode for the final gates. Concrete method before execution:

1. Run the ordinary matrix with `pasteboard_diagnostic=false`, preserving its
   cold isolated AppleScript path (no shared-bootstrap supporting session).
   Keep all existing timeouts, copy/idle limits, G1 UID/system-domain assertions
   and the post-control. Add always-on **fixture-only** fixed categories:
   AppleScript error class, timeout vs completed, elapsed before/at the existing
   copy bound, TUI idle-lock observed, and native human pasteboard type/text/
   exact-canary categories before and after. Never print clipboard data,
   hashes, raw errors or identity material. Build the standalone test observer
   with the runner's native `cc`/AppKit and verify its Mach-O CPU alongside
   the product. No extra dependency or product diagnostic feature is used.
2. Discriminate: a post `coercion-1700` with native `empty`/`nil`, absent canary
   and idle-lock after the probe timeout demonstrates a fixture observation
   after expiry; string/value with the canary still present instead implicates
   AppleScript coercion itself. An unavailable/unstable native snapshot is a
   failed requirement, never denial or PASS. A cold timeout vs a completed
   warm/shared-bootstrap run is environment/observer evidence, not a CPU cause.
3. Correct only the demonstrated cause and repeat natively on Intel/ARM.
   A native AppKit probe may replace AppleScript as the isolated **observer**
   if the evidence supports it; it must keep the same real agent UID, system
   bootstrap and exact-canary negative with positive human pre/post controls.
   No warmup, retry, longer lease or substitute value is permitted.
4. Add explicit `final_phase_only` fixture mode: run setup, core clipboard/TUI
   matrix and the same final suspension/restart/native probes without Full25.
   Emit `full25=NOT_RUN acceptance=NOT_CLAIMED`; preserve all core failures and
   strict cleanup. The default remains the full matrix, including happy sync.
   Strengthen final evidence with a changed real custody PID, unchanged native
   identity/keys/bootstrap/ACLs, suspension denied before/after restart, resume
   under the same enrolled identity and a second restart with delegation still
   usable and the same exact enabled metadata. No provider is substituted.
5. Local fixture verification uses the documented macOS CI guard, Python AST,
   existing PTY/helper/observer regressions and shell/YAML/diff/link checks.
   Any local laboratory invocation acquires `flock /tmp/pm-cargo-window.lock`
   in this worktree. No local Darwin run or product check is claimed; if
   product changes become necessary, `check.sh` and native RED/GREEN are required.
   At most approximately five hypothesis-driven exact-SHA native dispatches,
   with both jobs awaited to completion and URL/SHA/result retained here.

The inherited `MacPtySession.close` ignores `EBADF` from closing its PTY;
it remains unchanged. The purge/outbox, provider/second-agent, import summary,
listener/dispatcher and inherited fallbacks remain outside this workstream.
Apple documents `errAECoercionFail` as a descriptor coercion failure
([reference](https://developer.apple.com/documentation/coreservices/erraecoercionfail));
it is not an isolation denial. Native state is observed using
[`NSPasteboard`](https://developer.apple.com/documentation/appkit/nspasteboard),
without changing product clipboard operations.

First diagnostic run
[37106382228](https://github.com/SantanaJcp/passwordmanager/actions/runs/37106382228),
SHA `5652ef7c8cdca8be0a9b166d96497c484c45bae7`, completed **FAIL globally,
both CPUs**. Native build/test/Mach-O and all reached core assertions passed;
Full25 retained `durable=integrity screen=integrity process=same`, with zero
roots (23 opaque blocks Intel, 15 ARM). No final gates were reached.
With no shared-bootstrap control, the isolated AppleScript read completed
nonzero without the canary in about 21.5 s Intel / 24 s ARM, before the existing
copy bound. Human native snapshots were string/value, exact canary present,
stable before/after; `tui-idle-lock=no`. No `-1700` was reproduced. This does
not establish a CPU-specific cause or close the historical failures.

Stage 2 method (written before run 37107134590), still fixture-only: use the standalone AppKit
observer as the **only** read in the same agent UID/system-domain job, with
the same 30-second probe bound and human AppleScript pre/post controls.
Require a completed, stable native read, strict fixed schema, no stderr,
no exact canary, and the existing domain/UID assertions. Invalid/unavailable/
unstable/timeout results remain explicit failures; no AppleScript retry or
alternate read is selected after failure. The positive/negative oracle is
unchanged, now observing the same native API as the product rather than
AppleScript's descriptor conversion/runtime. The new independent mode still
runs every core assertion and then the final gates; sync is explicitly NOT_RUN.

Add a separate causal control before final gates: a real TUI copies with the
existing 5-second lease; observe the exact human canary, wait for the original
`Clipboard custody expired` status without replacement or added delay, and
require native empty/nil/absent/stable plus `coercion-1700` from the exact
human `the clipboard as text` expression. Lock normally and check no canary
in PTY output. This tests the empty-pasteboard hypothesis directly on both CPUs;
it is not a manufactured isolation denial and cannot replace a failed agent
probe. The old timeout and shared-bootstrap exposure remain historical FAILs.

Second run
[37107134590](https://github.com/SantanaJcp/passwordmanager/actions/runs/37107134590),
SHA `87baf92505b0aa67b346c993a30a598866d6cbb5`, completed **FAIL, both CPUs**,
explicit `final_phase_only=true`, ordinary binaries. Both reached core
Ticket23/partial24 and kept the human canary string/value/stable before/after.
The direct AppKit agent process completed nonzero in under the copy bound
(approximately 0.3 s Intel / 1.1 s ARM), but the first classifier reported
`probe-native=invalid`; no clipboard denial or scoped PASS was accepted.
Both independently observed real owned expiry as empty/nil/absent/stable and
the exact human AppleScript expression returning `coercion-1700`. This proves
that error's empty-pasteboard cause on both architectures. Both then observed
`PM26_FINAL suspension=durable restart=real identity=unchanged peer=verified`.
The later resume fixture failed its original 8-second exit wait: it sent `l`
while still on the Access screen, where `handle_access_key` ignores it.
The established path is `Esc` → `Content view` → `l`; fix that fixture path,
without modifying product keys, event handling or the wait.

The new observer must preserve the old **substring** canary oracle, not only
whole-string equality. Scan hash-matched windows natively without exporting
data/digests, and add an embedded synthetic-canary positive control to the
independent causal session after its expiry assertion (then replace it with
the existing harmless external marker). This control does not touch the timed
isolated lease or introduce a warmup before it.

Final native-rejection discriminant: emit `PM26_PB denied=pasteboard-null`
with the unique exit 69 **only** when `NSPasteboard.generalPasteboard` returns
nil. Accept this completed explicit API rejection as the negative result only
with that exact sentinel/exit, absent canary in both captured streams, verified
agent UID/system manager/different domain and unchanged positive human controls
using the same native binary. This is an expected failure of the attempted
secret read, not a fallback or an unavailable result treated as success.
Timeout, bad arguments/signal/other exit, malformed schema, unavailable types,
unstable data or any exact canary remain FAIL. A human nil board still fails
the positive control. Cocoa stderr is captured/scanned and never dumped;
arbitrary nonzero statuses are never accepted as a denial. The next run must
confirm this sentinel before attributing the preceding generic nonzero result.

Historical CPU claim checked against GitHub: run
[37087946638](https://github.com/SantanaJcp/passwordmanager/actions/runs/37087946638),
SHA `7038e667e67b1521df04d10efdc68569c92c31ae`, contains post-control `-1700`
on **both Intel and ARM**. The latest 26 candidate failed only on Intel at
that boundary; the defect is not inherently Intel-only. No root cause for
the operating system's variable AppleScript startup latency is claimed.

Local classifier extension before verification: execute the actual launcher
with fixed synthetic command results in the existing CI guard. Require that
only the complete read or exact nil/exit-69 pair can report `no`; canary in
native output or stderr reports `yes`; signal, missing sentinel, arbitrary
stdout/stderr, unavailable types, instability and timeout remain indeterminate
failures. Fake command data verifies this fixture classifier only. Actual
pasteboard, sentinel, substring recognition and identities require the native
runs. Reuse the existing flock, AST/shell/CI guard and relative-link checks.

### Final executed candidate and cause

Executed fixture/code SHA: `e3f02d4f34ea45c50754b150f5eec96e9c1a77b6`.
The later report/guard-only commit does not alter this executed harness,
workflow or native observer. No product source, listener/dispatcher, admission,
provider, footer, import summary, purge/outbox or inherited fallback changed.

| Run / exact SHA | Intel | ARM | Scope and observed result |
| --- | --- | --- | --- |
| [37106382228](https://github.com/SantanaJcp/passwordmanager/actions/runs/37106382228) / `5652ef7c8cdca8be0a9b166d96497c484c45bae7` | FAIL global; core observed | FAIL global; core observed | Original cold AppleScript diagnostic: 21.5/24 s, human canary intact; later happy sync integrity, zero roots. |
| [37107134590](https://github.com/SantanaJcp/passwordmanager/actions/runs/37107134590) / `87baf92505b0aa67b346c993a30a598866d6cbb5` | FAIL bounded fixture | FAIL bounded fixture | Empty expiry → human `-1700` confirmed; generic native nonzero not accepted. Suspension/first restart/identity observed; Access-screen `l` prevented final completion. |
| [37107761539](https://github.com/SantanaJcp/passwordmanager/actions/runs/37107761539) / `e3f02d4f34ea45c50754b150f5eec96e9c1a77b6` | **PASS bounded mode** ([job](https://github.com/SantanaJcp/passwordmanager/actions/runs/37107761539/job/111159537648)) | **PASS bounded mode** ([job](https://github.com/SantanaJcp/passwordmanager/actions/runs/37107761539/job/111159537406)) | Every core assertion, explicit native nil rejection, real expiry/coercion and embedded-canary control, both final restarts, identity/authority, final native probes and strict cleanup passed. Full25 NOT_RUN; full acceptance NOT_CLAIMED. |
| [37107763341](https://github.com/SantanaJcp/passwordmanager/actions/runs/37107763341) / `e3f02d4f34ea45c50754b150f5eec96e9c1a77b6` | **FAIL full matrix** ([job](https://github.com/SantanaJcp/passwordmanager/actions/runs/37107763341/job/111159543703)) | **FAIL full matrix** ([job](https://github.com/SantanaJcp/passwordmanager/actions/runs/37107763341/job/111159543802)) | Both core/clipboard passed. Intel reached mandatory happy sync and failed original 20 s wait with integrity, same custody PID, 25 opaque blocks and zero roots. ARM failed the original wait for the complete master-rotation historical-copy warning (`macos_tui_migration_lab.py:510`), before full25-local/collision/sync. No final gate or full acceptance PASS in this mode. |

Both final runs use `pasteboard_diagnostic=false` and ordinary production
binaries/plist. The independent run uses `final_phase_only=true`; the full
run uses false. In **all four final jobs**, the isolated native API completes
in approximately 0.3 s with `probe-native=denied probe-error=pasteboard-null`,
correct real agent UID, system manager and different domain, no exact canary
in either stream. The same native binary observes the human canary as
string/value/present/stable before and after. No TUI idle-lock occurs during
the isolated read. This is completed explicit rejection, never timeout PASS.

**Demonstrated cause and attribution boundary:** the human post-control
expression is `the clipboard as text`, not the product AppKit writer and not
an agent transport operation. After a real owned lease expires, native state
is empty/nil and that expression emits `errAECoercionFail (-1700)` on both
CPUs, independently of sync. The old isolated indeterminate branch follows
only `TimeoutExpired` when both canary streams are absent; its 30 s read bound
and preceding metadata/launch observation cannot ensure the positive human
post-control remains inside the separate 30 s copy/idle lifetime. This is the
fixture's mismatched observation lifetimes. Direct native observation removes
the AppleScript runtime/coercion dependency from the isolated reader, while
preserving the negative oracle and positive human controls and all deadlines.
The explicit native nil in the job, paired with positive same-binary human
controls, demonstrates the G1 fixture's domain separation for this probe.

The old failing runs did not record native pasteboard types or latency phases;
their precise historical empty state is therefore inferred from the timeout
branch, expiry contract and now-native causal control, not a recovered
measurement. The OS-internal cause of variable cold AppleScript latency is
unclassified and is not claimed repaired. Historical exposure in the shared
human bootstrap remains a confirmed unsafe profile, not an accepted agent
deployment. No arbitrary error, empty substitute value, warmup, retry, longer
lease/deadline, KDF relaxation or fallback is introduced.

### Current criterion 3 and handoff

This table supersedes the **current** clipboard/final-phase cells of the
October 2 checkpoint; it does not rewrite its historical failures.

| Criterion 3 component | Current evidence at `e3f02d4` | Remaining boundary |
| --- | --- | --- |
| Native clipboard isolation, ownership race, TUI keyboard/resize/lock/expiry | **PASS component Intel + ARM**, bounded and full runs above; same-domain exposure remains explicitly unsupported. | Does not certify all desktop capture APIs, human terminal apps, reboot/FDE or platform support. |
| Suspension and real launchd restart | **PASS component Intel + ARM**, bounded run: discovery denied before and after real restart; changed custody PID, same installed process/UID and peer verified. | Full25 normal path remains blocked before these final gates. |
| Persistent native identity and authority | **PASS component Intel + ARM**, bounded run: native account UIDs, private/public keys, bootstrap, profiles, published RPKs, binary/plist content and owner/modes unchanged across both restarts. Resume through real human TUI, lock, same exact enabled metadata discovered; second changed-PID restart preserves usable authorization without another setup/enrollment. | Single admitted bootstrap agent only; no second functioning agent/provider or full credential authentication is claimed. |
| Final native probes and teardown | **PASS component Intel + ARM**, bounded run: real `script` PTY `/dev/tty`, core limit zero, AppKit changeCount probe; strict absence checks and cleanup before the scoped PASS. Native build/tests/Mach-O checks passed in both final runs. | Reboot/FileVault/real human terminal applications remain Ticket31; signing/notarization Ticket34. `MacPtySession.close`'s inherited EBADF handling stays untouched. |
| Full Ticket26 / complete Full25 | **FAIL / incomplete**; normal run preserves mandatory gates and no full PASS. | Intel sync/purge-outbox integrity remains open; ARM rotation-warning observation failed, cause not newly classified here. No repeated identical run or owning-workstream change. |

Local verification passed in this worktree: existing screen/PTY-helper
regressions with flock, macOS CI configuration guard (including 11 synthetic
classifier cases), harness and embedded-launcher AST, shell syntax, YAML,
relative file/section links and `git diff --check`. No local Darwin execution,
product `check.sh`, full Linux laboratory rerun or product RED/GREEN is claimed:
product code is byte-for-byte unchanged against `36eecc8`. The failed new
fixture classification/exit path in run 2 and corrected bounded PASS in run 3
are fixture evidence, not a manufactured product RED/GREEN.

Four hypothesis-driven runs, all completed; no own run remains active. No
cache/artifact/secret/certificate, dependency installation on this host,
larger runner, root checkout edit, other-worktree edit, issue-status change,
force push, rule change, main-branch integration or PR merge occurred.
The existing credential-helper path failed; only the task-authorized per-push
`gh auth git-credential` override was used. GitHub reported the already
authorized permissions bypass on normal branch creation/update.

Handoff: orchestrator reviews/integrates this focused fixture branch, retaining
the normal full matrix. Owning workstream/user must resolve purge/outbox and
classify the Full25 rotation-warning failure before full acceptance can be
retested. The unrelated admission/provider/footer/summary/fallback gates and
human/reboot/FDE/signing evidence remain open; no ticket is advanced here.

## Native contract under test

The port keeps the existing vault engine, binary request framing, TLS 1.3 RPK
pinning and role-specific ALPN. macOS selects platform implementations only at
the existing boundaries:

- `getpeereid(2)` supplies the effective UID of the connected peer on both
  ends of the Unix stream. No request field supplies identity and an
  unimplemented target returns an explicit channel error.
- The custody process sets `RLIMIT_CORE` to zero before loading keys, uses a
  `077` umask and sets `SO_NOSIGPIPE` on connected/accepted Darwin sockets.
  Received descriptors get `FD_CLOEXEC` immediately because Darwin has no
  Linux `MSG_CMSG_CLOEXEC` path.
- Every writable vault connection enables and reads back SQLite `fullfsync`
  and `checkpoint_fullfsync`; a value other than one is an error. Linux keeps
  its existing durability configuration unchanged.
- The clipboard seam uses AppKit `NSPasteboard`, records its `changeCount`, and
  clears only if the same lease still owns the pasteboard. `/dev/tty` and
  `isatty` are tested as real native terminal primitives. No shell clipboard,
  OSC52, generic Unix peer stub or second vault engine is used.
- The shipped LaunchDaemon has a fixed `_passwordmanager` user/group, fixed
  root-owned program path, state/runtime paths, core limits and umask. It does
  not daemonize itself or accept identity through its request body.

Primary platform references used for these narrow primitives are Apple's
archived [`getpeereid(2)` manual](https://github.com/apple-oss-distributions/Libc/blob/main/gen/FreeBSD/getpeereid.3),
[`setrlimit(2)` manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/setrlimit.2.html),
[`launchd` job guidance](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html),
and current [`NSPasteboard`](https://developer.apple.com/documentation/appkit/nspasteboard)
documentation.

## Authorized ephemeral native method

The manual
[macOS custody acceptance workflow](../../.github/workflows/macos-custody-acceptance.yml)
orchestrates exactly the two standard runners `macos-15-intel` and `macos-15`.
It was published as workflow-only bootstrap `c4e8779` and its first product
run is recorded below. Its only product entry point is:

```text
PM_MACOS_EPHEMERAL_CI=1 ./scripts/test-macos-custody-lab.sh
```

That command is the normal acceptance mode. It builds the ordinary binaries
without `macos-ticket26-diagnostics`, launches the unmodified production plist,
sets no diagnostic environment variable and creates or reads no diagnostic
log. It must exercise the same identity, TLS/RPK, ACL, durability, restart,
terminal, clipboard and strict owned-cleanup gates described below. The pinned
libsodium build metadata remains a build-input gate and must classify the exact
build as optimized; it is not a product diagnostic channel.

The previous product-phase diagnostic path remains available only through the
exact explicit opt-in:

```text
PM_MACOS_EPHEMERAL_CI=1 ./scripts/test-macos-custody-lab.sh --diagnostic
```

That mode alone enables the compile-time diagnostic feature, injects the fixed
diagnostic environment into the synthetic client and launchd fixture, and
validates the protected diagnostic log. Unknown, duplicate or conflicting arguments fail;
normal-mode failure never selects diagnostic mode. Native acceptance requires
the default normal command, while diagnostic runs remain supporting evidence.

The task's separate, explicit bounded mode is
`PM_MACOS_EPHEMERAL_CI=1 ./scripts/test-macos-custody-lab.sh --final-phase-only`
(workflow input `final_phase_only=true`, default false). It runs the ordinary
core and final gates with ordinary binaries and the original master password,
without Full25's rotation/sync. Only its scoped result may be green;
`full25=NOT_RUN acceptance=NOT_CLAIMED` is mandatory, and it never prints the
normal acceptance PASS group. It can be combined with one diagnostic flag;
it is never selected after a failed full run. Every core failure remains fatal
after the independent final observations and strict teardown.

The pasteboard-only observation path is a separate explicit opt-in. It builds
and installs the ordinary binary and ordinary LaunchDaemon plist; it does not
enable `macos-ticket26-diagnostics`, set `PM_MACOS_TICKET26_DIAGNOSTIC` or
create the service diagnostic log:

```text
PM_MACOS_EPHEMERAL_CI=1 ./scripts/test-macos-custody-lab.sh --pasteboard-diagnostic
```

The manual workflow exposes this as the boolean `pasteboard_diagnostic` input.
When true it passes only `--pasteboard-diagnostic` to the harness. The mode is
limited to the categorical human/agent pasteboard observation below; it is
supporting evidence and cannot turn a normal product failure into a pass.

Prerequisites are a fresh macOS 13-or-newer Intel or Apple-silicon CI runner,
the repository-pinned Rust 1.98.1 toolchain, Xcode command-line tools,
Python 3, a logged-in non-root console user, and passwordless `sudo`. The
runner must not already contain the three synthetic accounts or any of the
canonical product paths. The only fixture root is the fixed
`/private/var/tmp/passwordmanager-ticket26`; its parent must be root-owned mode
`01777`. A missing/mismatched parent or fixture collision is a hard failure,
never permission to select another path or replace existing host state.

The workflow fixes `RUSTUP_AUTO_INSTALL=0` before every Rustup invocation and
installs only the exact fully qualified 1.98.1 host toolchain into
`<repo>/.toolchain`. It runs the environment preflight, fetches the locked
dependency graph in a separate network-enabled step, then invokes the product
laboratory whose build and tests are locked/offline. There is no dependency
cache or artifact upload and a preflight PASS cannot bypass a product failure.

The shell gate performs the locked/offline native build, native unit tests and
`plutil` validation. It requires each `pm`/`pm-custody` artifact to be a
single-architecture Mach-O exactly matching `uname -m`, including `pm-sync`.
Its Python harness then:

1. creates the collision-guarded, runner-owned `0711` fixture root, then
   `_passwordmanager`, `_pmagent26` and
   `_pmother26` with unused real Darwin UIDs/groups; its private per-identity
   directories remain `0700`, bilateral denial is probed, and only synthetic
   public RPKs are copied into a root-owned `0444` publication directory;
2. installs a root-owned binary and plist, creates custody-owned state/runtime,
   generates only synthetic RPKs, and bootstraps a fresh synthetic vault;
3. bootstraps the LaunchDaemon in the system domain and proves its live PID is
   `_passwordmanager` running the installed, architecture-checked binary;
4. exercises successful agent and human TLS/RPK channels, then gives the wrong
   UID a correct copied synthetic agent key and requires kernel-peer rejection;
5. proves an agent UID cannot use the human endpoint, establishes authorization,
   suspends it, kills/restarts the real launchd job, and requires delegated
   discovery to remain denied;
6. runs the native clipboard ownership race, the exact pasteboard negative
   probe from a separate ephemeral system-domain launchd job running as the
   no-login agent account, real `/dev/tty`/`isatty`, and zero-core-limit probe
   from the logged-in user session;
7. boots the job out and removes only the collision-checked paths/accounts it
   created, even on failure.

Full acceptance in normal mode requires every assertion and command to exit zero
and all four final `PASS` lines to be present. The explicitly scoped mode above
has its own result and never establishes full acceptance. A skip, cross-build, Linux execution, missing pasteboard
session, missing sudo privilege, pre-existing path/account, or cleanup failure
is not acceptance. The harness intentionally does not claim reboot, FileVault,
Intel+Apple-silicon coverage, signing, notarization or a human's daily machine;
those gates remain Tickets 31 and 34.

## TDD and current evidence

The intended red is the native test/laboratory run against the pre-port public
seams: Darwin `unix_peer_uid` returned the explicit unsupported error, the
custody binary returned `CUSTODY_UNAVAILABLE`, and `OwnedClipboard` did not
exist. It must be recorded on the native runner rather than inferred here.
The green is the exact same native test/laboratory command after this patch.
Until those two observed native records exist, the ticket must remain claimed.

The first native product run
[`34763192705`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34763192705)
on checkpoint `3409f5b` is an observed **RED** on both `macos-15-intel` and
`macos-15`. Environment validation, the locked dependency fetch and the
native libsodium build advanced successfully, but `pm-vault` failed to compile
before any product assertion ran. Darwin exposes `statvfs.f_bavail` as `u32`
while `f_frsize` is `u64`, and exposes `S_IFMT`, `S_IFREG` and `S_IFDIR` as
`u16` while ZIP modes are `u32`. The six compiler errors were the same width
mismatches on both architectures. This is real native compile evidence, not
custody behavioral evidence and not acceptance. The focused repair converts
both platform values into their protocol-sized unsigned type with checked
conversions, rejects multiplication overflow explicitly, and keeps rejecting
non-regular/non-directory ZIP entry kinds. Both native targets must rerun the
unchanged product entry point before any GREEN claim.

The second native product run
[`34763755579`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34763755579)
on checkpoint `7f63429` is a further observed **RED** on both targets. The
portable 1PUX repair compiled, exposing the next Darwin boundary in the shared
human import transport: Darwin represents `msghdr.msg_controllen` and
`cmsghdr.cmsg_len` as `u32`, whereas Linux represents them as `usize`. Both
jobs stopped at the same checked ancillary-message code in `pm-custody` before
the native custody assertions ran. The repair now converts the send and
receive control lengths to each platform field type through checked generic
boundaries, validates returned header and payload lengths before indexing,
rejects truncated, malformed, additional or multiple-descriptor messages, and
owns every received descriptor before later validation so every failure path
closes it. This remains native compile evidence only; another two-target run
of the unchanged entry point is required.

The third native product run
[`34764564812`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34764564812)
on checkpoint `45af206` compiled the product and native tests successfully on
both targets, including the AppKit/getpeereid and fullfsync tests, and verified
single-architecture `arm64` and `x86_64` Mach-O artifacts. Both jobs then
failed before service bootstrap when `_pmagent26` key generation returned the
explicit unavailable status. Inspection of the exact fixture construction
identified the cause: the runner-owned `pm-ticket26` parent was created mode
`0700`, so the real agent UID could not traverse to its own `0700` child.
Captured stdout/stderr were hidden by `check=True`, and the later bootstrap
and authorization steps would also have crossed private `0700` directories to
read public RPKs. Checkpoint `8b54d20` made synthetic keygen failures report
bounded return-code/stdout/stderr metadata, required `RUNNER_TEMP` without a
substitute path, used a `0711` collision-guarded fixture root, proved private
subdirectory denials, published only public RPKs through a root-owned `0444`
area, and obtained privileged metadata through the administrative test
observer. It did not broaden a private directory or change the runner parent.
That remained a runtime fixture RED, not native acceptance.

The fourth native product run
[`34765246514`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34765246514)
on checkpoint `8b54d20` is **RED** on both targets for two distinct reasons.
Both CPUs again compiled the native binaries and ran exactly nine applicable
native tests: one `pm-native-channel` test, five `pm-vault` unit tests and the
three macOS-applicable `local_vault` tests. The other workspace integration
executables reported zero tests because their cases remain Linux-gated, so
this is not a full native workspace suite. Both jobs also verified the
matching single-architecture Mach-O artifacts.

On Apple silicon, the new prerequisite probe established that
`/Users/runner/work/_temp` itself is not traversable by `_passwordmanager`.
The laboratory stopped there before product setup, exactly as required; it
did not modify the runner-owned parent. The user subsequently authorized the
single fixed `/private/var/tmp/passwordmanager-ticket26` replacement described
by the method above, with no alternate path or parent permission change.

On Intel, the parent traversal probes passed and the fixture advanced through
synthetic key generation, public-RPK publication, bootstrap/vault creation,
launchd bootstrap, live process user/command checks and the protected-file
metadata checks. The first real agent probe then received the explicit
`CUSTODY_UNAVAILABLE` result. Read-only inspection bounds the failure to the
probe's profile/key validation, Unix connection/configuration, cross-UID
`getpeereid` comparison, or TLS-RPK/ALPN exchange. The profile is created by
the root provisioner as mode `0444`; the agent key is created by the real
agent UID under its own `0700` directory; the server profile and bootstrap
derive from the same server RPK; and the published agent RPK is byte-compared
with its private key's public companion before bootstrap provisioning. Those
facts make an obvious path or trust-input divergence less likely, but the
opaque failure does not prove which remaining boundary failed. The successful
same-UID socket-pair `getpeereid` unit test does not establish the cross-UID
launchd case. No product dispatch, native primitive, or verification method
was changed on the basis of this uncertainty.

Before repeating the first agent probe, the harness now verifies only safe
fixture metadata and kernel identity observations: exact owner/mode for the
root-owned profile and public RPK, agent-owned private-key path and
custodian-owned socket; the numeric UID actually selected by `sudo`; bilateral
cross-UID `getpeereid` on a synthetic Unix pair; and the agent-side peer UID on
the real launchd socket. Diagnostics contain only synthetic account names,
numeric UIDs, modes, return codes and bounded stdout/stderr. They never read or
print private-key bytes, and the public `probe` failure remains exactly
`CUSTODY_UNAVAILABLE`.

The next diagnostic checkpoint keeps that public failure contract unchanged.
Before the first probe, the harness must additionally verify the complete safe
metadata tuple (type, owner, permission bits, link count and byte count), path
traversal and effective readability of the agent profile and private-key file
under the real agent UID. If those gates pass, the native binary is built with
the explicit `macos-ticket26-diagnostics` laboratory-only feature. That feature
is inert unless the fixture supplies the exact
`PM_MACOS_TICKET26_DIAGNOSTIC=1` opt-in. It may emit only fixed phase codes for
process hardening, profile/key parsing, Unix connect/configuration, bilateral
peer UID, TLS 1.3 handshake, pinned RPK and ALPN/READY, plus fixed `0|1`
accepted-stream `O_NONBLOCK` observations; it must not emit key or profile
bytes, dynamic paths, credentials or expanded public errors. The fixture
captures the service diagnostics in its owned protected state, validates
the fixed grammar and reports only a bounded suffix if the probe remains red.
The checker must require both compile-time and fixture opt-ins and reject
activation in the workflow or ordinary builds. This is diagnosis, not native
acceptance and not permission to weaken any guard.

### Accepted-stream blocking checkpoint

The seventh native custody run
[`34797022111`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34797022111)
on checkpoint `678319b` is an observed **RED** on both macOS targets after the
safe fixture and identity gates passed. The client and service each reached
their fixed `*-tls-configured` diagnostic phase, but neither reached its next
handshake phase; the public probe result remained exactly
`CUSTODY_UNAVAILABLE`. This bounds the failure to the I/O boundary immediately
after TLS configuration, but does not by itself prove the cause.

The next checkable hypothesis is that the accepted Darwin Unix stream retains
the listener's nonblocking state. `serve_loop` deliberately makes both
listeners nonblocking so that its polling loop can handle `WouldBlock`.
Darwin's [`accept(2)` contract](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/accept.2.html)
says the new socket has the listening socket's properties, while Linux's
[`accept(2)` documentation](https://www.man7.org/linux/man-pages/man2/accept.2.html)
explicitly warns that Linux does not inherit `O_NONBLOCK`. This makes inherited
`O_NONBLOCK` a Darwin-specific hypothesis, not a cross-platform assumption.
The rustls [`StreamOwned` wrapper](https://docs.rs/rustls/latest/rustls/struct.StreamOwned.html)
delegates handshake I/O to `ConnectionCommon::complete_io` through the
underlying stream, so a nonblocking accepted descriptor can explain a
handshake that stops before the first request/flush; that sentence is an
inference until the next native run observes the flags.

The authorized correction is deliberately narrow: immediately after
`accept(2)`, normalize the accepted stream to blocking mode before constructing
the rustls stream, read back `F_GETFL`, and return the existing visible
`CUSTODY_UNAVAILABLE` failure if the setter or readback fails. It does not add a
retry, alternate transport, relaxed TLS check, or longer deadline, and it does
not alter `IO_TIMEOUT`. The regression test accepts a real Unix-listener
connection and independently asserts that `F_GETFL` has no `O_NONBLOCK` bit
after preparation. With only the laboratory `macos-ticket26-diagnostics`
feature **and** the exact `PM_MACOS_TICKET26_DIAGNOSTIC=1` opt-in, the native
harness may additionally observe fixed, data-free
`PM26_DIAGNOSTIC accepted-stream-nonblocking-before=0|1` and
`PM26_DIAGNOSTIC accepted-stream-nonblocking-after=0|1` lines; ordinary builds
emit no such diagnostic. The feature remains absent from Cargo defaults.

Verification must proceed in this order: record the regression test RED against
this checkpoint, implement the normalization, rerun that test GREEN, then run
the existing Linux custody lab with the normal feature set. A subsequent
ephemeral Mac run must observe `before=1` and `after=0` on each target before
the hypothesis is considered confirmed. Full Ticket 26 acceptance still must
execute the normal binary/laboratory entry point without the diagnostic feature;
the diagnostic run is evidence for this boundary only and is not an acceptance
gate.

For this candidate, the focused local TDD record is:

```text
./scripts/cargo-local.sh test -p pm-custody --lib \
  accepted_stream_is_blocking_after_preparation --locked --offline
# RED before the implementation: cannot find function `normalize_accepted_stream`
# GREEN after the implementation: 1 test passed
```

### Eighth-run fixture-only RED

Run
[`34798902550`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34798902550)
on `87dc908` confirmed the product correction on both architectures: the
diagnostics observed `accepted-stream-nonblocking-before=1` and `after=0`, and
the agent probe reached client/server READY, including TLS, RPK pinning and
ALPN. The run then stopped in the negative `fake_server_rejected_before_tls`
fixture: its `OTHER`-owned impostor socket was bound successfully, but the
default socket mode did not grant `_pmagent26` write permission to connect.
The path-exists check therefore passed while the fake server's `accept()`
remained blocked until the existing five-second `communicate` bound. This is a
fixture permission mismatch, not a product or TLS failure.

The fixture correction is limited to `os.chmod(sys.argv[1], 0o666)` after the
synthetic impostor bind and before `listen(1)`. It preserves the real
wrong-UID-before-secret contract: `_pmagent26` must connect to the real fake
server, the custody probe must reject on kernel peer UID before sending a TLS
request, and the fake server must receive EOF (`0` bytes). The timeout is not
changed, no failure is converted to success, and no product path is altered.
The rerun must retain this `0`-byte assertion on both native architectures.

The acceptance-workflow checker was written before the workflow existed:

```text
./scripts/verify-macos-custody-ci-config.sh
# RED exit 1: required macOS custody CI workflow was absent
```

After adding the workflow and architecture checks, the same checker must pass.
It verifies only the two standard macOS labels, manual trigger, read-only
permissions, fixed Node-24 checkout SHA, repository toolchain homes, exact
Rust install, ordered preflight/fetch/offline-lab phases, and absence of
secrets, cache, artifacts, paid runners, emulation and success substitution.

```text
./scripts/verify-macos-custody-ci-config.sh
./scripts/verify-native-ci-config.sh
# GREEN: exit 0

# PyYAML 6.0.3: jobs=1, targets=2, steps=5
./scripts/check.sh
# PASS after merging the CI remediation and adding the acceptance workflow
```

Observed on the Linux x86_64 development host:

```text
./scripts/cargo-local.sh check -p pm-native-channel -p pm-vault \
  -p pm-custody -p pm-web-auth -p pm-ssh-client --locked --offline
# PASS

./scripts/check.sh
# PASS: pinned inputs, fmt, workspace check/tests and clippy

./scripts/clean-offline-build.sh
# PASS: removed 17608 files / 5.1 GiB; locked offline rebuild 1m48s

python3 -m py_compile crates/pm-custody/tests/macos_lab.py
bash -n scripts/test-macos-custody-lab.sh
git diff --check
# PASS
```

The final sorted Linux regression run also passed all 17 current laboratories:

```text
export PM_KEYCLOAK_DIST=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/keycloak/keycloak-26.7.3
export PM_CFT_DIR=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/cft/chrome-linux64
for lab in $(find scripts -maxdepth 1 -name 'test-linux-*-lab.sh' | sort); do
  "$lab"
done
# LAB_COUNT=17 ALL_LABS_EXIT=0
```

This includes the real multi-UID Linux custody, all content/import/history,
authorization/attempt, backup/recovery, SSH, synchronization, GitHub bearer,
Keycloak exchange, passkey and CFT/Keycloak web laboratories. It establishes
that the Darwin cfg additions did not regress those existing Linux flows; it
does not establish macOS behavior.

An attempted `--target aarch64-apple-darwin` check failed before compiling the
project because that Rust standard-library target is not installed in the
pinned local toolchain. It is not counted as a behavioral red, a native build,
or macOS evidence. Linux repository gates and all current Linux laboratories
must also pass on the eventual integrated candidate; those preserve the
existing provider, backup, passkey, recovery, SSH and web flows but cannot
replace the native method above.

### Ninth-run human-authorization setup diagnostic method

Run `34799626677` on `249cbd8` is a new RED after the accepted-stream fix:
Intel completed the laboratory, while Apple silicon reached client/server
`READY` for the real agent probe and then `human-authorization --action setup`
returned exit 4. The captured traceback exposes only the command and the
public `CUSTODY_UNAVAILABLE` boundary; it does not identify whether setup
failed while reading the human inputs, connecting/unlocking, or applying one
of its signed vault mutations. The existing `finally` cleanup remains
unchanged and is not part of this diagnostic.

Before editing, the single-variable method is fixed as follows:

1. Keep the exact public setup invocation, wire fields, password handling,
   TLS/RPK/ALPN checks, `IO_TIMEOUT`, and all assertions. Add no retry, sleep,
   deadline, alternate transport, TLS relaxation, or product behavior change.
2. Under only the existing laboratory feature
   `macos-ticket26-diagnostics` **and** the exact opt-in
   `PM_MACOS_TICKET26_DIAGNOSTIC=1`, emit fixed phase names around the human
   authorization client and server boundaries: profile/key input, socket and
   peer setup, TLS configuration, unlock request/response, setup request,
   and setup response. On the server, add fixed setup boundary phases and fixed
   error categories for input validation, unlock, each prepare/commit stage,
   and response writing. No phase includes a path, account, key, password,
   vault byte, request body, dynamic error text, or timing.
3. The fixture invokes only this setup subprocess with the opt-in, captures
   its bounded stderr and the custodian-owned diagnostic file, validates the
   existing fixed grammar, strips only the unchanged terminal
   `CUSTODY_UNAVAILABLE` line, and reports a bounded phase/category suffix.
   The original success assertion remains for a future green run; a failure
   must still be exactly exit 4, empty stdout, and
   `CUSTODY_UNAVAILABLE\n`. Diagnostics are evidence only and cannot turn a
   failure into a pass.
4. First run the available local syntax/checker tests and preserve the native
   RED record. If the phase/category identifies a deterministic fixture or
   product cause that is safely correctable within Ticket 26, write a
   public-seam regression before the minimal fix and rerun the same lab. If
   the native run is required to distinguish the categories, freeze this
   diagnostic-only checkpoint without changing product logic.

This method remains feature- and opt-in-gated, preserves the negative and
human-authorization contracts, and is not a Ticket 26 acceptance claim.

Checkpoint evidence from this worktree:

- TDD RED: before the implementation, the macOS checker exited `1` because
  `ticket26_diagnostic_error` was absent from `linux.rs`.
- GREEN: the final `./scripts/check.sh` passed (workspace checks, tests, and
  clippy); `pm-custody` tests also passed with
  `--features macos-ticket26-diagnostics`. Python compilation, shell syntax,
  the focused macOS CI checker, and `git diff --check` passed.
- Native status: no local macOS runner is available. The ARM failure from run
  `34799626677` remains the preserved RED; this checkpoint adds evidence only
  and needs the same native lab rerun to identify a phase/category before any
  product or fixture correction.

### Tenth-run unlock-result diagnostic method

The 2026-09-14 Apple-silicon rerun reached
`server-human-unlock-frame` while the client ended at
`error=client-human-unlock`. The current frame helper maps a socket timeout,
EOF, other I/O failure, malformed response and non-success status to the same
public failure. The fixture also reads the server log immediately after the
client returns, so the absence of a server terminal phase does not distinguish
an unlock still executing from a terminated or restarted custodian. Buffered
fixture output means the workflow timestamps are not operation durations.

Before editing, the next single-variable diagnostic method is fixed as follows:

1. Preserve the exact setup command, public stdout/stderr/exit contract,
   `IO_TIMEOUT`, Argon2id profile, wire format and server behavior. Add no retry,
   sleep, new deadline, alternate path, or relaxed assertion.
2. Refactor the existing frame reader once, without duplicating its framing
   protocol, so its internal result retains only these fixed categories until
   the human-unlock observer: `timeout` (`TimedOut` or `WouldBlock`), `eof`,
   `other-io`, `malformed-frame`, and `status-nonzero`. Its ordinary wrapper
   must continue mapping every category to the same `Failure::Unavailable`.
   A focused regression checks that public-equivalent mapping.
3. Under only `macos-ticket26-diagnostics` plus the exact opt-in
   `PM_MACOS_TICKET26_DIAGNOSTIC=1`, report the fixed client unlock category and
   a monotonic, bounded elapsed-millisecond value. Around the server vault
   unlock, report only `ok` or `vault-error` with the same bounded elapsed
   grammar. Do not include an error string, status byte, secret, key, path,
   request, vault data, account, or wall-clock value.
4. On setup exit 4, before reading the server log or raising the unchanged
   failure, query the exact launchd label once and compare its parsed PID with
   the already verified service PID. Emit only one fixed classification:
   `same-pid`, `different-pid`, `unavailable`, or `unparseable`. Do not dump
   launchctl output and do not wait for the server.
5. Keep diagnostics evidence-only. `timeout` plus `same-pid` and no server
   terminal result isolates a live server still inside unlock at the client
   deadline; EOF plus a missing/replaced process distinguishes termination;
   a server `vault-error` distinguishes an explicit unlock rejection. None is
   acceptance, and the native RED remains until the unchanged observable lab
   succeeds on both architectures.

The inherited best-effort cleanup remains unchanged and outside this bounded
checkpoint; it still requires separate authorization before Ticket 26 can be
accepted.

Checkpoint evidence from the Linux development host:

- TDD RED: the focused `pm-custody` regression failed to compile because
  `FrameReadFailure` and `read_frame_bounded_classified` did not yet exist.
- Focused GREEN: the same regression passed both with and without
  `macos-ticket26-diagnostics`; every classified frame failure retained the
  ordinary `Failure::Unavailable` result.
- The Python diagnostic grammar/classifier checks, Python and shell syntax,
  the focused macOS CI checker, and `git diff --check` passed. The final
  `./scripts/check.sh` passed in 97 seconds.
- `./scripts/clean-offline-build.sh` removed 11,183 files / 3.8 GiB and the
  locked offline rebuild passed in 39 seconds.
- No native macOS rerun was performed for this checkpoint. The tenth-run ARM
  failure remains RED, and the new categories are not native evidence until
  the same unchanged laboratory runs there.

### Eleventh-run unlock-latency discriminant method

Run `34807572032` on checkpoint `98d41d` is GREEN on Intel and RED on Apple
silicon. The ARM client classified the human unlock response as `timeout` at
15,002 ms; launchd still reported the same service PID; and the service had
accepted and decoded the complete human unlock frame but emitted neither an
unlock result nor its terminal phase. This verifies the deadline and bounds
the wait to `HumanVault::unlock_with_audit_custody`; it does not yet identify
which operation inside unlock consumed the time.

Read-only call-graph inspection fixes the next single-run discriminant:

1. Preserve the exact password, Argon2id profile (256 MiB, three passes,
   `p=1`), `IO_TIMEOUT`, process priority, build profile, TLS/RPK exchange and
   public `CUSTODY_UNAVAILABLE` mapping. Do not add an authentication/KDF
   operation, retry, sleep, alternate path or larger deadline.
2. Extend the existing default-off `macos-ticket26-diagnostics` feature
   through `pm-vault` and `pm-crypto`. It remains inert unless the service has
   the exact `PM_MACOS_TICKET26_DIAGNOSTIC=1` opt-in. During only the existing
   unlock, emit fixed phases for `channel-verified`, `sqlite-opened`,
   `durability-configured`, `bundle-loaded`, `kdf-start`, `kdf-end` and
   `root-authenticated`. Each line contains only the fixed name and a bounded
   millisecond duration measured with a monotonic clock; it contains no path,
   UID, password, key, bundle, SQL value or dynamic error text.
3. Measure the already required creation derivation without executing another
   derivation: start immediately after flushing the confirmed password and
   stop when the CLI prints its recovery-code prompt. `PendingVault::new`
   executes the same default KDF in that interval and persistence has not yet
   started. Report only `vault-root-create-ms=<0..999999>`.
4. Read the one native libsodium `config.log` produced by this clean build,
   require a parseable `CFLAGS` assignment, and classify it only as `opt0` or
   `optimized` from mutually exclusive exact optimization tokens. Missing,
   multiple, contradictory or unclassified metadata is a laboratory failure,
   never a default category. Report only `sodium-cflags=opt0|optimized`; never
   dump the flags or select an ambient library.
5. A focused regression must prove that the diagnostic root opener returns the
   same authenticated root as the ordinary public opener and observes exactly
   one `kdf-start`/`kdf-end` pair. The checker must require all feature/opt-in
   gates and the closed fixture grammar. Local syntax/check gates may run once
   the shared Linux test window is free; only a native Intel+ARM rerun supplies
   the discriminant.

Interpretation is closed. `kdf-start` without `kdf-end` at the unchanged client
deadline identifies the password derivation. Stopping before `sqlite-opened`,
`durability-configured` or `bundle-loaded` identifies channel, SQLite setup or
bundle I/O respectively. A fast creation derivation but slow service KDF makes
the launchd execution context a candidate; both slow makes the native crypto
build/profile the leading candidate. Audit custody is not a candidate for this
deadline: unlock only clones its already-open opaque handle after root
authentication and performs no audit append, transaction or I/O.

Current source inspection makes the KDF/build path the leading hypothesis, not
a confirmed cause. The lab uses Cargo's dev profile; the workspace fixes
`libsodium-sys-stable` 1.24.0 with default features disabled; and that crate's
build script obtains C flags from `cc::Build` while adding `--enable-opt` only
for its inactive `optimized` feature. A Linux build of the same graph recorded
`-O0`, but that is not evidence of the ARM build, hence the required native
classification above. Do not enable `optimized` speculatively: its build script
also adds `-march=native`/`-mtune=native`, which may change distribution
portability. Any optimization correction requires the native result and a
separate approved method; increasing the timeout or reducing the KDF is not a
correction.

The bounded diagnostic checkpoint was verified locally without making a native
latency claim. The focused feature-enabled `pm-crypto` regression passed 1/1
and the static macOS CI checker passed. The first full `./scripts/check.sh`
reached Clippy and failed because the feature-disabled no-op observer left its
`self` argument unused; after making that no-op consume both fixed inputs, the
same complete check passed. `./scripts/clean-offline-build.sh` then completed a
clean locked/offline rebuild successfully. No macOS runner was dispatched, so
the ARM location and its native `sodium-cflags` category remain unverified.

Native run `34810076591` on `ad9e6ad` failed on both architectures before the
fixture mutated the host: the closed metadata guard found other than exactly
one globbed libsodium `config.log`. The preceding feature-enabled build and
tests create more than one eligible Cargo build directory, so a target-wide
glob cannot identify the build linked into the custody artifact. The twelfth
run therefore provides no CFLAGS or unlock-latency result.

The corrected discriminant binds metadata to the exact custody build rather
than weakening the guard. That single `cargo build` emits machine-readable
`build-script-executed` records; a checked parser requires exactly one record
for the locked `libsodium-sys-stable@1.24.0` package and writes only its
`out_dir`. Missing, duplicate, malformed, foreign-package or non-directory
records fail explicitly. The harness receives that exact output directory and
requires its fixed `source/libsodium-stable/config.log`; it never globs, picks
the first result or derives a category from another feature build. The existing
closed CFLAGS parser and `opt0|optimized` output remain unchanged.

Native run `34810631226` on `902018b` completed the discriminant on both
architectures. Both exact builds reported `sodium-cflags=opt0`. Intel measured
the existing root creation at 6,318 ms and its service unlock KDF at 4,156 ms
(4,161 ms for the whole unlock), then passed. Apple silicon measured creation
at 9,108 ms; service unlock reached `channel-verified` (0 ms), `sqlite-opened`
(3 ms), `durability-configured` (5 ms), `bundle-loaded` (1 ms) and `kdf-start`,
then the unchanged client deadline expired at 15,003 ms with the same launchd
PID and no `kdf-end`. This verifies the ARM hotspot is the password KDF, not
channel authentication, SQLite, durability, bundle I/O or audit.

The bounded correction keeps the dev/test product and every workspace crate at
their existing profiles except the exact locked native package
`libsodium-sys-stable:1.24.0`, whose package override sets `opt-level=2`.
The [Cargo profile override contract](https://doc.rust-lang.org/cargo/reference/profiles.html#overrides)
documents that a named package override has precedence for that package;
the pinned `cc` 1.4.5 source obtains its C compiler optimization from Cargo's
`OPT_LEVEL`, and the pinned libsodium build obtains its `CFLAGS` from that
`cc::Build`. This selects ordinary portable `-O2`; it does not enable the
dependency's `optimized` feature (which adds `--enable-opt` and native tuning),
change Argon2id parameters, deadlines, QoS, Rust workspace optimization or any
public format/operation. Local verification must cover the existing crypto byte
vectors, root open/create behavior, vault regressions, full check and clean
offline rebuild. The next native run must still obtain its exact current build
metadata and assert `sodium-cflags=optimized`; unavailable or unclassified
metadata remains a hard failure, never permission to use an alternate build.

Local verification of this correction passed the full feature-enabled
`pm-crypto` suite (including fixed format/root vectors and the diagnostic
equivalence test), the three `pm-vault` local persistence/root regressions, the
complete `./scripts/check.sh`, the macOS static checker, and
`./scripts/clean-offline-build.sh`. The exact clean Linux build metadata
classified as portable `-O2`; that confirms the Cargo/cc seam locally but does
not predict either native macOS result.

Native run [`34811375717`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34811375717)
on `634ac8a` completed GREEN on both authorized architectures. The exact current
libsodium build classified as `optimized` on both. Apple silicon measured the
existing root creation at 599 ms, the service KDF at 605 ms and the whole
unlock at 609 ms. Intel measured creation at 1,803 ms, the service KDF at
1,362 ms and the whole unlock at 1,371 ms. Both jobs retained the unchanged
Argon2id parameters and deadline and passed the live LaunchDaemon identity,
bilateral `getpeereid`, TLS 1.3/RPK, ACL/wrong-UID rejection, durable suspension
across a real launchd restart, `/dev/tty`, AppKit clipboard ownership and
queried fullfsync assertions. Each job printed all four product PASS lines and
the workflow concluded successfully.

This result verifies that the bounded portable package optimization removed the
observed KDF deadline failure on both native runners without changing the KDF
contract. It is not complete Ticket 26 acceptance. Authorization remains
pending for the inherited cleanup behavior identified separately; the normal
non-diagnostic binary/TUI composition, reboot plus FileVault coverage, and
signing/notarization gates also remain outstanding. The diagnostic build and CI
runner do not substitute for those requirements.

### Owned native-fixture cleanup method

The prior harness printed its four product PASS lines before entering cleanup,
then invoked every cleanup command with `check=False` without inspecting its
result. A failed `launchctl bootout`, path removal, user deletion or group
deletion could therefore leave owned host state while the job still appeared
successful. The user authorized propagating all of those inherited cleanup
errors after run 14; that successful diagnostic record remains unchanged.

The correction is fixture-only and uses a closed ownership ledger. Collision
checks remain before mutation. A path, launchd job, user or group is added to
the ledger immediately after its own creation command succeeds, including
partially configured accounts. Cleanup attempts every and only ledger entry in
dependency-safe reverse order, records every nonzero result or exception using
fixed non-sensitive action names, then queries absence for every owned path,
launchd label and directory-service record. It raises one aggregate error after
all attempts, or attaches that aggregate as the cause while re-raising the same
pre-existing failure; no cleanup failure can be ignored or converted to
success. The four PASS lines move after successful cleanup and verified
absence. No glob,
alternate root, broad account match, home-directory deletion or unrelated
system mutation is permitted.

Callable fake-command regressions cover a successful cleanup and simultaneous
bootout/path/user/group failures, proving all later operations and absence
checks still run and the aggregate is visible. These regressions validate only
error propagation; they are not native acceptance. Native validation remains
the same collision-guarded ephemeral CI laboratory on both architectures.

The focused callable regressions passed for both the all-success result and a
seven-error bootout/path/user/group plus absence-check result; they also proved
all seven commands were attempted. Python AST parsing, the macOS static checker
and `git diff --check` passed. No Rust gate, build or native laboratory was run
for this scripts-and-documentation-only checkpoint. Only the unchanged native
CI laboratory can verify real launchd, filesystem and Directory Services
cleanup on both architectures.

Before native dispatch, static review found two regressions in that first
cleanup checkpoint. It treated every nonzero per-record query as proof of
absence, which could conceal a permission or Directory Services/launchd
transport failure, and `except Exception` no longer guaranteed cleanup for
`KeyboardInterrupt` or `SystemExit` as the prior `finally` did. The corrected
method requires successful, closed-format `launchctl list` and `dscl -list`
inventory queries and proves the exact owned label/user/group names are absent;
any query error or malformed listing is itself aggregated. It captures
`BaseException`, completes cleanup, and re-raises the same interruption object
when cleanup succeeds. Focused regressions must cover listing-query failure and
identity-preserving interruption cleanup before native dispatch.

The corrected focused checks passed: successful closed inventories were
accepted; nonzero launchd and both Directory Services inventory queries were
all retained in the seven-error aggregate; and both successful and failing
cleanup re-raised the identical `KeyboardInterrupt` object after attempting the
owned removal. Python AST parsing, the static macOS checker and
`git diff --check` passed. No Cargo, Rust build or native laboratory was run.

Native cleanup run `34836722393` on `81ffa4c` failed on both architectures
before custody startup: the new exact `mkdir` of
`/usr/local/libexec/passwordmanager` exited nonzero, whereas the prior
`mkdir -p` had also provisioned its missing parent when necessary. The captured
record does not include the command's stderr, so parent absence is a bounded
explanation to test, not a claimed observed cause.

The fixture correction explicitly handles only the fixed
`/usr/local/libexec` parent. If it exists, the harness requires a real
root-owned directory without group/world write and records but does not alter
its mode or ownership. If absent, it creates that exact parent as root-owned
`0755`, verifies it, and records separate ownership immediately. Cleanup first
removes the owned child install root, then uses only `rmdir` on a parent created
by this run; nonempty or failed parent removal is aggregated and never replaced
by recursive deletion. Final absence is required only for the created parent.
Fake-command checks must cover existing-parent preservation, created-parent
ordering, nonempty `rmdir` failure and continued cleanup attempts. This remains
fixture-only and needs the same native two-architecture run.

Native cleanup run
[`34837550960`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34837550960)
on `c7f6fb6` passed on both `macos-15-intel` and `macos-15`. Both jobs completed
the custody, identity, TLS/RPK, ACL, persistence, terminal and AppKit gates and
then removed the exact owned launchd job, paths, accounts and conditionally
created install parent with verified absence. This closes the reported fixture
cleanup defect, but the jobs still used the explicit diagnostic build and do
not establish the normal-binary or complete TUI requirements.

### Normal-mode checkpoint

The laboratory now defaults to the normal mode defined above. The shell passes
no feature or harness-mode argument in that path; the harness installs the
unchanged production plist, rejects ambient diagnostic activation, runs agent
and human operations without the diagnostic environment, and requires the
protected diagnostic log to remain absent. `--diagnostic` is the explicit
alternative that enables product-phase diagnostics; `--pasteboard-diagnostic`
is the separate harness-only categorical observation mode. All modes still
bind and reject ambiguous libsodium build metadata, and require the exact build
to be optimized.

The static checker covers all three closed argument forms, rejects unknown and
incomplete modes, distinguishes normal, product-diagnostic and
pasteboard-diagnostic output, rejects unoptimized metadata, and pins normal
plist/log behavior. Shell syntax, Python
AST parsing, the static macOS checker and `git diff --check` passed. No Cargo,
build, native laboratory or product behavior was executed for this checkpoint;
the default command must run on both native architectures before it is evidence.

Native normal-mode run
[`34840405573`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34840405573)
on `8dcc980` is **RED** on both architectures before the build. The macOS runner's
system Bash 3.2, with `set -u`, rejected expansion of the intentionally empty
normal-mode `diagnostic_features` array as an unbound variable at line 50. The
following missing libsodium metadata error was secondary because the build
command never ran. Linux syntax and static checks did not establish that native
shell behavior.

The correction must keep `set -u` and the system Bash. Normal and diagnostic
modes each construct complete, nonempty build, test and harness command arrays;
only the explicit diagnostic branch appends its feature and mode arguments.
The static regression must source the exact command constructor under `bash -u`
and actually expand every normal and diagnostic command, checking that normal
contains no diagnostic argument and diagnostic contains each opt-in exactly
once. String inspection alone is insufficient. This remains script-only until
the unchanged normal entry point succeeds natively on both architectures.

The corrected command-plan regression passed under `bash -u`: every nonempty
normal and diagnostic build, test and harness array expanded successfully;
normal contained no diagnostic argument, while diagnostic contained each
explicit opt-in exactly once. Shell syntax, Python AST parsing, the complete
static macOS checker and `git diff --check` also passed. No Cargo command or
native product behavior was executed for this checkpoint.

Native normal-mode run
[`34841029441`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34841029441)
on `1be9f4c` passed on both `macos-15-intel` and `macos-15`. Both jobs built the
ordinary single-architecture binaries without
`macos-ticket26-diagnostics`, installed the production plist without a
diagnostic environment or log, classified the exact libsodium build as
optimized, and passed the live LaunchDaemon, bilateral `getpeereid`, TLS/RPK,
ACL/wrong-UID, persistent suspension/restart, `/dev/tty`, AppKit clipboard,
SQLite full-fsync and strict owned-cleanup gates. This closes the normal-mode
checkpoint. The applicable native Rust selection still contained nine tests
and several Linux-gated executables reported zero tests, so this run does not
claim the integrated keyboard TUI or complete native workspace coverage.

### Integrated native keyboard-TUI method

This method is fixed before composing the already integrated Ticket 23--25
interfaces into the macOS branch. The acceptance entry point remains the
normal, non-diagnostic laboratory. It must build and architecture-check
`pm-custody`, `pm` and `pm-sync`, install the ordinary custody binary, and run
the TUI through the same live system LaunchDaemon, vault engine, human Unix
socket, TLS 1.3/RPK profile and native peer-UID checks used above. A separate
CLI-only invocation, a second engine, a simulated terminal or a diagnostic
feature is not TUI evidence.

The harness will use Python's native `forkpty`/PTY primitives, not a Linux user
or mount namespace and not an optional terminal package. The child is the
logged-in non-root human and runs the public `pm-custody tui` command with the
owned human profile/key and live human socket. The parent sends only keyboard
bytes, reads the rendered PTY stream, and changes the terminal dimensions with
`TIOCSWINSZ`. It must observe 80x24, 42x12 and 100x30 rendering. Before sending
Enter for visible input, it waits for that exact input to be rendered; this is
only synchronization with Crossterm consumption, not an operation retry or a
deadline extension. Password and recovery re-entry remain hidden and are
never searched for in the captured stream.

The native run must replay the complete observable keyboard contracts of
Tickets 23, 24 and 25, rather than accepting a screen that merely starts:

1. seed and browse all seven record kinds and every field descriptor, including
   notes, custom/source, every auth member and attachment descriptors; prove
   selection alone exposes no value, then use exact-field reveal and copy;
   cover search, tags, favorite, generator, history, trash, restore and both
   purge ceremonies, Unicode/control sanitization, reveal expiry and idle lock;
2. operate the access and pending views by keyboard: closed enrollment,
   enable/disable, suspend/resume, revoke, safe pending context and cancel;
   check the resulting state from a real agent process, and prove human lock
   does not transfer ownership of the channel or suspend the agent;
3. execute CSV and 1PUX preview/mapping/duplicate/cancel/confirm, encrypted
   backup, warned plaintext export, restore, both rotations, real pinned sync
   pairing/status/offline/failure/restart, causal retirement, audit query and
   purge, and streaming download of an attachment larger than the human frame.
   Every negative remains an explicit failure and no source is mutated.

The platform composition itself has two closed requirements. First, the TUI
module and `tui` command must compile and execute on both Linux and macOS from
the one custody implementation; a macOS cfg that omits the command or reports
zero applicable TUI tests is a failure. Second, explicit copy on macOS must use
`pm_native_channel::OwnedClipboard`, which publishes through AppKit and clears
only while its recorded `NSPasteboard.changeCount` still owns the selection.
It must not invoke Linux `wl-copy`, `pbcopy`, OSC52 or an alternate clipboard
backend. The test observer may read the pasteboard to compare the synthetic
value and publish a synthetic replacement; after the copy lease expires that
replacement must remain. The agent account must be unable to obtain the copied
value. This observer use is not a product execution path.

The existing wrong-UID cases remain mandatory with the integrated binary: a
copied correct RPK under the wrong native UID is rejected, the agent cannot use
the human endpoint, and the human cannot use the agent endpoint. After keyboard
lock and after idle lock, the PTY must terminate, an agent operation must still
work when authorization is otherwise enabled, and a fresh human connection
must require the master password again. A wrong password must leave the vault
unchanged and must not produce an unlock-success audit record. Terminal bytes
must contain neither fixture secrets outside explicit timed exposure nor an
executed OSC52 sequence.

All fixture resources join the existing collision-checked ownership ledger.
The TUI child, sync/provider processes and clipboard observer are stopped and
waited; then the strict launchd/path/account cleanup and exact absence checks
run before any PASS line. Cleanup failures are aggregated and prevent success.
The native TUI PASS must name keyboard, PTY, TLS/RPK, seven kinds/all fields,
access/pending, operations, AppKit ownership race, wrong UID, explicit lock and
idle lock. It must appear on both authorized architectures in the same run.

### Clipboard backend composition checkpoint

The shared `ClipboardLease` keeps the Linux `wl-copy` child path and its
validated root-owned helper unchanged. On macOS, the same lease uses only the
existing `pm_native_channel::OwnedClipboard`: `copy` records the AppKit
`NSPasteboard.changeCount`, and explicit expiry/session-exit cleanup calls
`clear_if_owned` once. A stale lease that no longer owns the pasteboard is a
successful ownership-preserving no-op; an AppKit copy or clear error remains a
`CUSTODY_UNAVAILABLE` failure. A failed copy creates no lease, and a Linux
helper partial-initialization failure still attempts the existing child
stop/wait cleanup. No `pbcopy`, OSC52, shell fallback or alternate backend is
allowed.

The focused macOS regression is cfg-gated to the real AppKit backend and
exercises a replacement-owner race plus explicit cleanup's no-second-attempt
behavior when executed. The native acceptance method above must additionally
execute the normal non-diagnostic `pm-custody tui` through a real PTY, verify
copy/lock/idle exit and the observer's replacement remains after the stale lease
expires, then perform strict owned cleanup before PASS. This checkpoint was
prepared without Cargo, a local build, or a native runner; it makes no
RED/green or macOS TUI acceptance claim.

### Native PTY fixture implementation checkpoint

The normal macOS laboratory now includes a bounded core TUI fixture in the
same collision-checked harness. Before launching the TUI it seeds the seven
record kinds and the token-exchange relationship through the existing
`human-content-flow` command over the live human TLS/RPK endpoint; this is
fixture setup, not a second vault engine. The child is started with Python's
`forkpty`, receives the installed `pm-custody tui` binary and the real human
profile/key/socket, and opens the product's `/dev/tty` itself. The parent sends
keyboard bytes only, waits for each visible prompt to render before sending
Enter, and applies `TIOCSWINSZ` at 80x24, 42x12 and 100x30. It does not use
tmux, a fake terminal, `wl-copy`, `pbcopy`, OSC52 or a clipboard fallback.

The core assertions are deliberately observable and narrow: the unlocked
catalog contains the seeded metadata without secret values; engine-backed
search selects the Password record; exact field selection reaches
`auth[0].password` and copies its synthetic UTF-8 value through the existing
macOS `OwnedClipboard`/AppKit lease; a separate logged-in-user observer reads
the pasteboard, publishes a synthetic replacement, and proves the lease expiry
does not clear that newer owner. The `_pmagent26` observer cannot read the
copied value. A keyboard `l` exits the first session and a subsequent session
must show the master-password prompt again. A fresh session with no further
keys exits through the existing idle deadline; the lab then checks delegated
agent discovery while authorization remains enabled. Child exit status, PTY
bytes, hidden-input secrecy, the real launchd service/socket and the strict
owned cleanup are all required. The observer uses `osascript` only as a test
observer; it is not a product execution path.

The fixture does not add field validation or byte conversion: the existing
human-field catalog remains length-delimited and the existing renderer keeps
its binary-value branch for non-UTF-8 bytes and its control-character
sanitization. The synthetic seed exercises the established seven-kind
content path; empty or binary field behavior is not changed or accepted by a
new fixture-specific rule.

There is an existing macOS capability boundary that this checkpoint does not
hide: `pm_native_channel::OwnedClipboard::copy` rejects an empty value or
bytes that are not valid UTF-8 before calling the AppKit bridge, and the
Objective-C bridge also requires a nonempty `NSUTF8StringEncoding` string.
Those fields remain representable and revealable through the human-field
protocol, but an explicit macOS copy fails closed rather than converting or
substituting their bytes; Linux's byte-oriented `wl-copy` path is broader.
The complete TUI acceptance must report this compatibility boundary instead
of treating the UTF-8 copy fixture as coverage for empty/binary fields.

This checkpoint is intentionally named `tui-core`: it proves the native PTY,
service/channel, AppKit ownership race, explicit lock and idle lock seams
without claiming the complete Ticket 23--25 keyboard operation matrix. The
full acceptance method above still requires every record field, access/pending,
import/backup/sync/audit flow and both purge ceremonies. The normal command
must print the core evidence only after the PTY child has exited successfully;
failure or cleanup errors remain failures. The script also includes package
`pm-custody` in its native test command so the cfg-gated AppKit clipboard lease
regression is actually compiled and executed instead of being omitted by the
previous package list.

Static verification for this implementation is closed before native execution:
the Python AST parses; the shell command plan still has normal and explicit
diagnostic modes with no implicit feature; the PTY implementation contains
`forkpty`/`TIOCSWINSZ`, prompt-render synchronization, strict incremental
UTF-8 decoding across split reads, bounded child wait and one teardown policy
(with checked wait/close for the owned helper group; a timeout is a failure,
not an escalation or retry); the macOS fixture contains neither a shell clipboard command
nor an alternate/fallback branch; and the existing nine native tests and
wrong-UID/negative assertions remain in the same harness. No Linux run or
local macOS result is substituted for the required normal Intel+Apple-silicon
run. Until that run succeeds, this is an implementation checkpoint only.

Native run 20
[`34847582724`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34847582724)
on `a6c3` failed on both authorized macOS architectures during compilation,
before the laboratory or any TUI behavior ran. Five cfg-gated AppKit test
assertions used `Result::expect`, which attempted to format the deliberately
opaque product `Failure` and produced `E0277` in both the library and binary
test targets. This is a test-compilation failure, not a behavioral RED or
acceptance result. Checkpoint `a247340` replaces those assertions with static
panic closures, preserving the non-`Debug` product error and the test's
failure behavior; native redispatch remains pending.

Native run 21
[`34848148030`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34848148030)
on `a247340` compiled the ordinary binaries and applicable native tests on both
authorized architectures, then reached the normal TUI core laboratory. The
first real PTY child exited with the public `CUSTODY_UNAVAILABLE` result before
rendering `Password required`; the Intel and Apple-silicon jobs reported the
same outcome. This is a behavioral RED, not native acceptance. The traceback
shows the failure at `start_macos_tui` after content seeding and normal human
authorization setup, but the public custody error does not identify its
internal stage.

Static source inspection provides a bounded, source-supported diagnosis while
native confirmation remains pending. `run_terminal` calls Ratatui's
`Terminal::clear` before the first application draw and again on the final
successful lock/exit path. Ratatui 0.30's fullscreen `Terminal::clear`
unconditionally asks its backend for the current cursor position before
clearing. The pinned Crossterm 0.29 Unix implementation answers that request by
writing the terminal status query `ESC[6n` and waiting for a cursor-position
reply. The laboratory's `forkpty` child has a kernel PTY, not a terminal
emulator, and `MacPtySession` only resizes, reads and writes it; it never
answers that query. Therefore the initial draw cannot run and the resulting
`Failure::Unavailable` is rendered only as `CUSTODY_UNAVAILABLE`. The buffered
Python stdout explains why the short adjacent log timestamps do not measure
the internal wait.

The bounded repair changes only those two sites to the backend's direct
fullscreen clear operation, which writes and flushes the clear command while
propagating its I/O error; it does not emulate a terminal, add a retry, extend
a deadline, relax a guard or select a fallback. At startup Ratatui's buffers
are empty, and after final lock/idle exit no later frame relies on the buffer,
so the direct operation does not require a cursor-preserving query at either
site. The real normal PTY harness now records raw bytes and rejects `ESC[6n`
during startup and exit, proving that the fixture does not conceal a future
cursor-query dependency. This static regression method and the repair require
the unchanged normal two-architecture native run; neither this diagnosis nor
the local source checks is a GREEN or acceptance claim.

Before native dispatch, static verification must establish that the new
harness parses, its command/fixture inventory is closed, its PTY driver waits
for visible input before Enter, and the workflow still invokes only the normal
entry point. Native success then requires every prior custody assertion plus
the integrated TUI assertion on both architectures. The separate merger must
also repeat `scripts/check.sh`, the clean locked/offline build and the complete
ordered Linux laboratory set after composition. None of those local gates,
the prior nine native tests, or run 18 substitutes for this native PTY run.

### Native run 22 observer RED and bounded correction

The Apple-silicon job for checkpoint `6c6bec` reached the normal TUI and
rendered its first screen, but the laboratory timed out while looking for
`Password required`. Its captured diagnostic representation contained
`Passwordrequired` and `Items(selectionismetadataonly)`. This is not evidence
that the product omitted spaces: the existing `MacPtySession` removed every
cursor-positioning CSI and concatenated the text bytes, so spaces represented
by untouched screen cells were lost. The result is a harness-observer RED,
not a product behavioral RED or acceptance result; the Intel outcome must be
reported separately.

The bounded test-only correction is a small VT screen observer in
`crates/pm-custody/tests/macos_lab.py`. It consumes the real `forkpty` bytes
incrementally and maintains the requested cursor, grid, wrap state and
application alternate-screen snapshot. Its accepted grammar is intentionally
closed around the pinned Crossterm output: cursor addressing/movement,
erase, SGR, the two private screen/cursor modes, basic C0 cursor controls,
strict UTF-8, and Unicode combining/wide-cell accounting. Any other escape
or control sequence fails with a fixed category; in particular `CSI 6n` is a
terminal-query failure and is never answered or ignored. Rows retain their
spaces and Unicode; no whitespace normalization, terminal-response
emulation, retry, deadline change, product change or optional terminal
dependency is introduced.

The parser regression feeds a cursor-positioned no-secret capture pattern one
byte at a time, including split UTF-8 and combining bytes, and verifies the
separated `Password required`/`Items (selection is metadata only)` rows,
resize, alternate-screen exit snapshot, and rejection of incomplete UTF-8 and
`CSI 6n`. The native TUI waits use the same observer over the actual captured
PTY stream; raw bytes remain available only for the existing secret, OSC52 and
DSR checks. Error messages do not include screen rows or raw bytes. The
parser-only GREEN is recorded in checkpoint `44160b1`; the next normal
two-architecture native result remains pending. This observer is not complete
Ticket 23--25 acceptance, which still requires the separately documented full
matrix.

The test-first chronology is recorded explicitly. Before the observer was
implemented, the new parser regression was run against the old
`MacPtySession` with this non-exclusive local command:

```text
python3 - <<'PY'
import importlib.util
path = 'crates/pm-custody/tests/macos_lab.py'
spec = importlib.util.spec_from_file_location('macos_lab', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.assert_screen_observer_regression()
PY
```

It exited with code 1 and the fixed assertion
`cursor-positioned screen regression: item title lost its separating cell`.
This intentional parser RED occurred while the Windows 27 exclusive window
was held; it was not a granted Cargo/Linux/native/system-lab gate and carries
no acceptance evidence. The import created only the test module's own
`crates/pm-custody/tests/__pycache__/`, which was removed by exact-path file
deletion and directory removal. No retry or fabricated pass followed. After
that RED, checkpoint `1820b8b` added `VtScreen`; checkpoint `44160b1` then
made wide-cell, `CSI 1J`, and zero-parameter movement cases explicit and the
parser-only regression passed. The parser result is not native evidence.

### Native run 23 event-boundary RED and bounded fixture correction

Run [`34853427359`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34853427359)
on `44160b1` compiled the ordinary binaries and applicable native tests on
Intel and Apple silicon, and both jobs passed native preflight, the exact
toolchain, dependency fetch, unit-test and architecture checks. Both then
failed inside the test-only TUI fixture before any `PASS macos-tui-core` line.

The Apple-silicon job timed out in `tui_search` while waiting for the
`Search (engine-decrypted):` screen. The captured log contains no screen dump,
secret, or internal product phase, so this is an unclassified fixture
observation RED rather than evidence of a product search failure. The Intel
job reached field selection and reported `selected password field was not
rendered` after the fixture sent fourteen `j` bytes. The old helper could stop
on any historical frame containing the field label before the current frame's
highlight marker had rendered; this is also an observer synchronization RED,
not product acceptance evidence.

The bounded test-only correction keeps the same `forkpty`, product binary,
live service and fixed deadlines. `MacPtySession.mark()` drains bytes already
queued by the PTY and records an event-count boundary instead of using a raw
byte offset. `wait_text()` and the new `wait_selected()` inspect only the
current screen after that boundary; the latter requires the exact highlighted
row. A local resize changes decoder geometry but no longer creates a
synthetic screen event. Search explicitly marks the post-prompt transition
before submitting the query. Timeout diagnostics expose only fixed categories:
`mode` (primary/alternate), `render` (known screen class/other), `event`
(`post-mark`/`none`), parser state and child state; they never print rows, raw
bytes, paths or secrets. The regression preserves event history for terminal
exit while proving stale history cannot satisfy a current-screen wait.

This correction has only static AST and diff checks so far; no local Cargo,
system lab, native rerun or complete Ticket 23--25 acceptance is claimed. The
next native run must still prove the normal two-architecture TUI core and the
separately documented full keyboard matrix.

### Native run 24 pasteboard negative-observation correction

Run [`34855277724`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34855277724)
on `f1a1a51` reached the real TUI copy assertion on both authorized macOS
targets after the ordinary build, unit tests and architecture checks passed.
The human-side read is the exact `TUI_PASSWORD_RECORD` control in the harness;
the traceback therefore shows that this positive control completed before the
agent-side probe. This is not native acceptance: Intel's `_pmagent26`
`osascript` probe timed out after the existing 30-second bound, while Apple
silicon returned exit code `0` from the same command.

The old assertion required `returncode != 0` and checked that the exact canary
was absent from captured stdout and stderr. The Apple-silicon traceback prints
only the return code, not either captured stream. Consequently the run proves
neither that the agent extracted the canary nor that it was isolated from the
human pasteboard; it records only `rc=0`. The Intel timeout similarly has no
completed read result. The later PTY-close `incomplete-control` error is a
separate cleanup observation and cannot classify the pasteboard result.

Static inspection also found a fixture boundary that must be distinguished
before changing the negative test: the agent command is launched as a direct
`sudo -u _pmagent26 osascript` child of the logged-in human harness. It does
not explicitly enter a distinct launchd bootstrap or login session. The
production service is separately installed as a system LaunchDaemon under
`_passwordmanager`; that service's domain is not evidence about the agent
probe's GUI session. Apple's session model makes login/bootstrap sessions a
relevant boundary, and Apple's launchd guidance distinguishes system daemons
from per-user agents ([Root and Login Sessions](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPMultipleUsers/Concepts/SystemContexts.html),
[Creating Launch Daemons and Agents](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)).
The possibility that the UID-switched child retains the caller's bootstrap is
a source-supported fixture hypothesis, not a native finding; no product or
fixture session change is authorized by this record.

The bounded pasteboard-only correction records the missing distinction under
the separate `--pasteboard-diagnostic` harness/workflow opt-in. It uses the
ordinary binary and ordinary LaunchDaemon plist, without the
`macos-ticket26-diagnostics` feature or `PM_MACOS_TICKET26_DIAGNOSTIC=1`.
It emits only fixed categories, never the canary, captured bytes, numeric UIDs,
paths or OS error text:

- `pasteboard-human-canary-read=yes|no` records the exact human positive
  control before the negative probe;
- `pasteboard-agent-result=zero|nonzero|timeout`,
  `pasteboard-agent-canary-stdout=present|absent` and
  `pasteboard-agent-canary-stderr=present|absent` distinguish command outcome
  from exact-canary exposure;
- `pasteboard-agent-success-read=yes|no|indeterminate` is `yes` only when the
  exact human canary is observed in either captured stream, `no` for a completed
  result without that canary (including `rc=0` with empty/different output),
  and `indeterminate` for the existing timeout;
- `pasteboard-human-identity` and `pasteboard-agent-identity` classify the
  expected synthetic identity without printing its UID; and
- `pasteboard-human-domain`, `pasteboard-agent-domain` and
  `pasteboard-domain-relation` classify `launchctl manageruid` as
  `system|human|other|unavailable|unparseable`. The two raw manager UIDs are
  parsed and compared internally before their categories are emitted, so two
  `other` categories are not treated as equal merely because their labels
  match. The relation is only `same|different|indeterminate`. The command's
  bootstrap-namespace meaning follows the documented
  [`launchctl manageruid`](https://github.com/apple-oss-distributions/launchd/blob/main/man/launchctl.1)
  interface; neither numeric output is printed.

The negative assertion now rejects exact-canary exposure or an indeterminate
timeout, but does not reject a completed zero exit solely because it is zero:
the human exact-canary control and the categorical identity/domain evidence
must be considered together. This is an evidence correction, not a claim that
the run proved isolation or a relaxation of the native G1 requirement. A
future native pasteboard-diagnostic run must capture these fixed categories
before any decision to redesign the agent fixture; normal mode remains
uses the ordinary binary/plist and emits no diagnostic output.

The isolation scenario now uses the product's maximum/default 30-second copy
lease, and reads the exact human canary immediately before and immediately
after the agent probe. The added identity/domain commands and the existing
agent `osascript` call must complete within that unchanged lease; a failed
post-probe human control is not reinterpreted as agent denial. The separate
expiry scenario remains explicit: a fresh TUI uses the existing 5-second copy
lease, replaces the canary from another application, and requires the normal
expiry/ownership result. This preserves both the long-lease isolation
observation and the short-lease expiry race without changing product limits.

The checkpoint has only had a Python AST parse and static diff inspection on
the Linux host; no local Cargo, macOS runtime, system lab or native acceptance
is claimed. The Mac24 result remains a RED with canary exposure status
`indeterminate` (ARM `rc=0`, Intel timeout), not evidence of extraction.

### Native run 25: shared-bootstrap control negative and isolated-job correction

Run [`34858597883`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34858597883)
on `73e9175` was dispatched with the separate pasteboard observation option.
Both `macos-15-intel` and `macos-15` passed environment validation, the locked
build/tests and architecture checks, then failed in the pasteboard laboratory.
The fixed observations on each target were:

```text
human-canary-before=yes
agent-result=zero canary-stdout=present canary-stderr=absent success-read=yes
human-identity=expected agent-identity=expected
human-domain=human agent-domain=human domain-relation=same
human-canary-after=yes
```

The exact synthetic human canary was therefore present in the agent probe's
captured stdout. The matching `human` launchd-domain categories were obtained
from the raw manager UID comparison, not from the account names. This is a
reproducible **control negative** for the unsafe fixture shape: a direct
`sudo -u _pmagent26 osascript` child inherits the logged-in harness bootstrap
and cannot be counted as an isolated agent. It is not a product failure or an
isolation PASS, and the control must remain labelled unsupported even if a
future runner happens not to expose the canary. The later
`incomplete-control`/PTY-cleanup error is separate cleanup evidence and does
not weaken the canary observation.

The bounded fixture correction is based on the selected isolation profile,
not on changing the product or lowering the negative assertion. Apple's
[daemon/agent guidance](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
requires `UserName`/`GroupName` to be supplied by launchd for a root-managed
job and distinguishes the system daemon bootstrap from per-user agents. Apple's
[root/login-session model](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPMultipleUsers/Concepts/SystemContexts.html)
also treats bootstrap/session boundaries as a real IPC security boundary.
The fixture therefore does the following, in order:

1. Retains the shared-bootstrap control only as explicitly labelled supporting
   evidence. It never contributes to the isolation assertion or a PASS line.
2. Before any copy operation, creates a fresh root-owned, `0644` temporary
   plist and root-owned, non-writable helper under the collision-guarded
   fixture root. It bootstraps the helper in the **system** launchd domain with
   `UserName` and `GroupName` set to `_pmagent26`,
   `LimitLoadToSessionType=System`, `RunAtLoad=false` and explicit
   `KeepAlive=false`; an explicit `launchctl kickstart` starts the on-demand
   job only after a fresh TUI copy lease. `LaunchOnlyOnce` is intentionally not
   set: launchd must retain this non-respawning job long enough for the harness
   to observe its result and last exit status before the owned bootout. The
   synthetic account keeps
   `UserShell=/usr/bin/false` and `NFSHomeDirectory=/var/empty`; it has no
   login session. Its result, stdout and stderr files are pre-created inside
   its own `0700` directory and are tracked as owned resources. The plist
   carries only the marker length and a SHA-256 digest for exact-stream
   matching; the canary plaintext is never put in launchd arguments or the
   `0644` plist.
3. The helper records only fixed categories for its effective UID,
   `launchctl manageruid`, `launchctl managername`, and the parsed relation to
   the human harness manager. The manager UID category must be `system` and
   the combined manager-domain relation must be `different`; a merely
   different account label is insufficient. It then executes the **same** public
   `/usr/bin/osascript -e 'the clipboard as text'` probe as the agent. The
   harness requires the launched process UID and manager domain to be
   different from the human context before interpreting the probe. Missing or
   malformed manager metadata is indeterminate, never a fallback.
4. The shared-bootstrap control is run only as a separately labelled
   supporting negative. The isolated scenario then starts a fresh TUI and
   fresh 30-second copy lease, reads the exact human canary immediately before
   and immediately after the isolated-job probe, and kicks the already-loaded
   system job only after the copy. A completed result without the canary is a
   denial; exact-canary stdout/stderr exposure fails; timeout, missing result,
   unknown exit state or failed post-control remains a failure/indeterminate
   result. The helper allows the fixed `2*10s` manager metadata bounds plus the
   fixed `30s` public probe bound and a bounded launch margin; this is only a
   fixture lifecycle bound and never extends the product copy lease. No extra
   retry, lease extension, clipboard implementation or product diagnostic
   feature is used. The existing 5-second expiry case remains a separate
   scenario.
5. Cleanup first boots out the owned system-domain job, verifies no owned PID
   or label remains, then removes only the helper/plist/result files and
   directories recorded by the fixture. It propagates every bootout, close and
   removal error. PTY EOF finalization remains strict: an incomplete VT
   control is recorded as a cleanup error, but cleanup continues and the
   original behavioral error is preserved as the primary failure; the parser
   is not made permissive.

This is a test-only fixture correction and a method checkpoint. A future native
run must show the isolated job's UID/domain relation as `different`, both human
pre/post controls as `yes`, and no exact canary in either captured stream on
both architectures before any isolation evidence is considered. The shared
bootstrap control remains a documented negative, not acceptance evidence.

### Run 26 TUI fixture diagnosis and bounded correction

Native run 34862828726 on `d514233` reached the TUI fixture on both
architectures but did not reach the isolated pasteboard probe. The Apple
silicon job timed out while waiting for the selected
`auth[0].password` row in a fresh `80x24` session. Its fixed observer state was
`mode=alternate render=field-list event=post-mark parser=ground child=alive`.
The Intel job reached the same shared-bootstrap control, whose agent probe
used its existing 30-second bound and returned `timeout`; it then failed the
first session's `wait_exit(timeout=8)` assertion after sending `l`. The run
therefore proves neither isolated pasteboard behavior nor a product exit
failure. No raw PTY screen or agent output was captured, and no local runtime
reproduction is claimed.

Static inspection found the concrete ARM fixture defect: every fresh TUI
session resets `App.selected` to catalog index zero, while only the first
session searched for `Password` before calling `select_tui_password_for_copy`.
The isolated and expiry sessions sent fourteen field-navigation keys from an
unspecified catalog item, so the selected row was not necessarily
`auth[0].password`. The bounded correction searches for the synthetic
`Password` catalog title in each fresh session before opening the explicit
field list. The field index remains the existing contract-driven fourteen;
there is no implicit field substitution or catalog-order assumption.

The Intel failure is not independently localized by this run. Static
inspection identifies a bounded fixture-lifecycle ambiguity: the unsupported
shared-bootstrap negative was run inside the same TUI session that had the
existing 30-second idle bound. If its direct agent probe consumed that bound,
the subsequent `l` assertion could race the already-defined TUI idle behavior.
The correction runs that same real TUI copy plus shared bootstrap probe in a
disposable, separately labelled control session, then runs the ordinary
keyboard session without the control's external wait. It does not alter the
product idle bound, the copy lease, the probe bound, the agent assertion, or
cleanup policy; the shared control remains unsupported evidence and never
contributes to acceptance. Its cleanup records a fixed exit category and
return code: `natural-zero`, `natural-nonzero`, `owned-termination`, or
`unknown`. A naturally observed nonzero child status remains a failure; a
signal-derived code is not accepted merely because it is `143`: only the exact
`128 + SIGTERM` code is `owned-termination`, and only when this fixture sent
that cleanup signal. Any other nonzero code remains `natural-nonzero`, even if
a signal was sent; `unknown` is not accepted. If the control session exits or
cleanup fails, the categorized control result or cleanup failure remains
visible. The next native run must confirm whether this removes the Intel
ambiguity; it is not claimed as a verified product or fixture cause here.

The next native run must first show the fresh-session title searches and
complete the existing first/isolated/expiry TUI flows before interpreting the
isolated system-launchd result. It must retain the shared-bootstrap control as
`unsupported`, require the existing human pre/post canary controls, and keep
the normal generic failure path. A native pass of the revised fixture is not
by itself Ticket 26 acceptance: the full TUI 23--25 matrix, reboot/FileVault,
signing/notarization and final integration gates remain separate.

That earlier checkpoint was prepared statically on Linux only with Python AST,
shell syntax and `git diff --check`; its statement that the macOS custody
checker passed does not apply after the later helper-drain addition. The
checker then failed because its broad `SIGKILL` grep rejected the helper's
single owned-group teardown. The current candidate narrows that check
semantically; its updated static result is recorded below. No Cargo, build,
parser runtime, system lab or native run was executed for that correction;
native behavior remains pending.

### Native run 27 shared-control PTY-close RED and bounded correction

The subsequent native run on `a3db150` failed on both authorized macOS
architectures in the supporting shared-bootstrap control before the isolated
agent job. The run's fixed logs are
`/tmp/pm-macos-run27-arm-full.log` and
`/tmp/pm-macos-run27-intel-full.log`. The control's direct pasteboard probe
remained supporting, non-acceptance evidence. Its still-running TUI was then
closed by `MacPtySession.close()`, which sent the fixture's cleanup `SIGTERM`;
strict PTY finalization consequently observed an incomplete VT control and
reported `incomplete-control`. This is a fixture teardown RED, not evidence of
pasteboard isolation or a product TUI failure, and the raw PTY stream remains
unmodified.

The bounded correction keeps strict parsing, checked cleanup and the exact
exit classifier. After the shared probe, the harness first observes whether
the child has already exited. If it is still alive, it sends the existing
human `l` key and requires `wait_exit(timeout=8) == 0`, allowing the normal
TUI path to finish its VT stream before cleanup closes the PTY. An already
exited child is not signalled and is classified from its natural status.
Thus the successful path must report `natural-zero returncode=0`; every
nonzero or unknown status remains a failure. The strict SIGTERM cleanup path
is retained only for an exceptional failure before normal close and is not a
successful-control fallback. No product code, deadline, pasteboard assertion,
or isolation boundary changed.

This candidate has only static Python AST, shell syntax, macOS-checker and
diff checks on Linux; no local Cargo, parser runtime, system lab or native
rerun was executed. The next native run must show the categorized
`natural-zero returncode=0` result on both architectures before the shared
control can be considered clean; it still cannot count as Ticket 26
acceptance.

### Native run 28 ARM one-shot launchd lifecycle RED and bounded correction

Run [`34872038731`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34872038731)
on `3aac714` reached the isolated pasteboard stage on Apple silicon after the
ordinary build, native tests and supporting shared-control flow. The shared
control now reported `pasteboard-shared-control-exit=natural-zero returncode=0`,
so the normal keyboard teardown correction was exercised successfully. The
isolated helper then failed with the fixed assertion `isolated pasteboard
launch job disappeared`; its cleanup also reported the owned launchd bootout
return code `3`. The fixed ARM log is
`/tmp/pm-macos-run28-arm-full.log`. This is a fixture lifecycle RED, not a
pasteboard isolation result; no isolated result schema or canary status was
available to interpret. The Intel log is
`/tmp/pm-macos-run28-intel-full.log`; its supporting control classified its
natural exit as `natural-nonzero returncode=4` and therefore failed before the
isolated stage. That is not an owned SIGTERM result, and it is not accepted as
cleanup or isolation evidence.

Static inspection confirms the lifecycle cause. Apple's
[launchd.plist.5](https://raw.githubusercontent.com/apple-oss-distributions/launchd/main/man/launchd.plist.5)
defines `LaunchOnlyOnce` as a job that can run only once, and the corresponding
[launchd source](https://raw.githubusercontent.com/apple-oss-distributions/launchd/main/src/core.c)
marks a job with `only_once` and a nonzero start time as useless and removes it
after exit. The harness was asking `launchctl print system/<label>` to remain
available while using that exact one-shot setting, so a completed helper could
write its result and be removed before the next observation. The bootout return
code `3` is consistent with the same already-removed owned label, but does not
by itself establish the exact race timing.

The bounded fixture correction removes `LaunchOnlyOnce` and sets
`KeepAlive=false` explicitly while retaining `RunAtLoad=false`. The helper is
still launched exactly once by the existing explicit `kickstart`, does not
respawn, and remains loaded with no PID after exit so `wait_for_agent_launch`
can require both the fixed result file and the persisted job record. A missing
label remains an explicit failure; cleanup must still boot out the owned label
and report errors. No result, timeout, canary, UID/domain, isolation, product,
or deadline assertion is weakened, and no fallback treats disappearance as a
pass.

The Intel result also exposed a separate fixture-drain risk. The supporting
control invokes a synchronous external pasteboard probe while its real TUI
continues drawing, but the old harness drained that PTY only from wait loops.
A full PTY can therefore stop the TUI's draw/heartbeat path while the probe is
blocked, yielding a generic natural nonzero result; the run does not expose
enough data to call that inference proven. The bounded fixture correction uses
one selector loop to drain the active TUI PTY while each owned external helper
(`osascript`, `launchctl`, `cat`, and metadata commands) runs. It captures
stdout/stderr exactly for the existing categorical canary classifier, keeps
the existing 10/30-second helper bounds, gives each helper an owned process
group, and performs one bounded group teardown on timeout or parser failure.
It does not alter the product, lease/idle deadlines, parser strictness,
pasteboard assertion, or isolation profile.

On helper timeout or strict parser failure, the fixture performs one direct
`os.killpg(process.pid, signal.SIGKILL)` against the process group created by
`start_new_session`; it then waits, closes both captured streams and preserves
every cleanup error. This is a fatal teardown of an owned test helper, not a
SIGTERM-to-SIGKILL escalation or an alternate product path, and it is never
retried. The checker uses Python's standard-library AST to allow exactly that
call inside `terminate_owned_group` and rejects any other `SIGKILL` reference,
including one in `MacPtySession.close`.

Before executing the local regression, the following method was written and
approved for the short Linux-only verification window. It does not start a
Password Manager binary, Cargo, a system lab, or a native runner:

1. Allocate a real PTY with `pty.fork()` and run a synthetic child that emits
   complete ASCII heartbeat bytes while a helper command writes fixed,
   non-secret stdout/stderr. Assert that the helper returns zero with both
   streams intact and that the PTY bytes were consumed; keeping this writer
   ASCII-only prevents owned teardown from cutting a VT/UTF-8 sequence and
   creating an unrelated cleanup error.
2. Run a helper that emits a synthetic canary and exits zero. Pass its captured
   streams through the existing `classify_pasteboard_output` contract without
   printing them; assert exact canary detection remains categorical.
3. Run a helper whose leader exits while a forked descendant holds the helper
   pipes open. With the existing bounded timeout, require `TimeoutExpired`,
   capture only fixed empty streams, and verify the owned descendant cannot
   create its marker after group teardown.
4. Emit a real unsupported terminal-query sequence from the PTY while a
   helper is alive. Require the strict `UnsupportedVtSequence` category and
   verify the owned helper cannot create its marker; the same parser bytes are
   not fed again during cleanup.

The launchd observation has a separate fixed-input regression in
`assert_pasteboard_diagnostic_regression`: an exact `launchctl print` record
with `last exit code = 0` is accepted, while a nonzero, absent, malformed or
duplicate field is rejected. `wait_for_agent_launch` applies that parser only
after the owned result file exists and the job has no PID, so a result left by a
child that later exits nonzero cannot be treated as success. The parser emits
no status text or dynamic error data. The field and `print` status contract are
documented by Apple's [`launchctl.1`](https://raw.githubusercontent.com/apple-oss-distributions/launchd/main/man/launchctl.1).

Each case closes its own PTY and removes only its own synthetic marker. The
method treats a timeout, parser error, nonzero status, unknown status, helper
leak, or cleanup error as failure; it never turns one into a pass. The next
native run must still reach and parse the isolated fixed-schema result on both
architectures, retain supporting `natural-zero returncode=0`, and prove the
separate UID/domain and pasteboard-negative requirements before any isolation
evidence is considered.

The granted Linux-only focused run executed that method exactly once, with
`PYTHONDONTWRITEBYTECODE=1`, and passed in 4.3 seconds:

```text
PYTHONDONTWRITEBYTECODE=1 python3 - <<'PY'
import importlib.util
from pathlib import Path
path = Path('crates/pm-custody/tests/macos_lab.py').resolve()
spec = importlib.util.spec_from_file_location('pm26_macos_lab', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.assert_pty_helper_drain_regression()
print('synthetic PTY helper/drain/canary/timeout/parser cleanup: PASS')
PY
# synthetic PTY helper/drain/canary/timeout/parser cleanup: PASS
# focused-helper-rc=0
```

The run's sole log is `/tmp/pm26-helper-focused-20260914.log`. Its cleanup
check found no `pm26-helper-descendant-*` or `pm26-helper-parser-*` marker and
no owned helper process. This verifies only the Python fixture helper and its
synthetic PTY cases on Linux; it is not a macOS product, Cargo, system-lab or
Ticket 26 acceptance result. The later launchd last-exit parser cases were
added after this focused runtime and were not rerun locally; only AST, shell
syntax, the updated scoped checker and `git diff --check` cover this latest
checkpoint. The follow-up static commands all exited zero: `ast.parse` for
`macos_lab.py`, `bash -n scripts/verify-macos-custody-ci-config.sh`, the
updated checker, and `git diff --check`. The native corrected fixture remains
pending.

### Native run 31 expiry observation RED and bounded screen correction

The Ticket 23 candidate `af1f1d8` reached the catalog and reveal cases on
both macOS architectures. The fixed logs are
`/tmp/pm-macos-run31-arm-full.log` and
`/tmp/pm-macos-run31-intel-full.log`. The ARM run reported the synthetic
Password value still visible when the expiry assertion ran; the Intel run
reported the same observation for the synthetic TOTP value. This is a real
observer failure record, but it does not yet prove an expiry bug in the
product: the status and footer can be repainted before the prior exposure
line is overwritten, so a PTY read can capture an intermediate screen.

The bounded test-only correction keeps the existing `wait_text` deadline and
does not change reveal duration, product code or assertions. A
`wait_stable_reveal_expiry` observation now reads only the current
`VtScreen.application_text` and accepts expiry only when the same frame has
`Reveal expired`, `Exposure: <hidden>`, and no expected synthetic value. It
does not search historical screen events, add sleeps, retry a failed
operation, or normalize whitespace. `assert_screen_observer_regression` now
feeds a deterministic three-frame split repaint (old exposure, expired status
with old exposure, then hidden exposure) and requires the helper to consume the
third frame. This separates the known intermediate-render race from a genuine
product expiry failure; native rerun is required before either is accepted.

### Static native TUI coverage matrix (not yet executed on macOS)

The current macOS `run_tui_core_lab` exercises real PTY startup, three sizes,
searches for the eight seeded titles, exact `auth[0].password` selection,
copy/expiry, explicit lock, idle lock, AppKit ownership and delegated-agent
discovery. It does not yet drive the following concrete keyboard contracts
already implemented by Tickets 23--25; these are the bounded matrix to add to
the same normal binary/service fixture, not substitutes or mocks:

| Contract | Real keys and observable checks still required |
| --- | --- |
| Ticket 23 content | From the catalog, select each of the seven kinds and each field descriptor (notes, custom/source, every auth member and attachment descriptor), assert selection/reveal boundaries, then exercise `t` tag replacement, `f` favorite, `g` generator, `h` history, `d` trash, `u` restore, `p` revision purge and `P` item purge. Retain search, Unicode/control sanitization, replacement-owner clipboard race, reveal expiry and idle lock. |
| Ticket 24 access | `a` → `n` with the closed subject/request/SPKI/label/environment input, verify the real agent view; use `e` for enable/disable, `s` for suspend/resume and `x` for revoke, then verify the next agent operation. Exercise `w` pending, `x` terminal cancellation and `v` passkey context plus the fresh human approval/password path; `Esc` must leave state unchanged. |
| Ticket 25 migration | `m` → `1` CSV preview for each mapping/duplicate choice and `2` 1PUX preview; verify hidden-value summaries, cancel/incorrect confirmation, then exact `IMPORT` commit and source immutability. |
| Ticket 25 backup/recovery | `b` → `1` native backup, `2` warning then `EXPORT` plaintext, `3` `|RESTORE`, `4` `|ROTATE`, and `5` recovery-code re-entry; verify destination collision rejection, durable results, historical-copy warning and both rotation outcomes. |
| Ticket 25 devices/sync | `y` → `1` pinned `|PAIR`, `2` real `|SYNC`, `4` status for the same job ID, and `3` exact `|RETIRE`; observe offline/failure, restart recovery and causal second-device retirement without retry or alternate endpoint. |
| Ticket 25 audit/attachment | `z` → `1` audit query and `2` exact `generation:through:PURGE AUDIT`, then `D` with a selected attachment and a new 0600 destination; verify the >16 MiB stream's digest/length, no full-frame secret and source preservation. |

The native matrix must run through the same human TLS/RPK channel and service
as the core flow, with real keyboard/PTY observations and engine/file checks
after each commit point. This table records missing native coverage only; the
existing Linux 23--25 evidence remains separate, no macOS acceptance is
claimed, and no product code or deadline is changed by this preparation.

### Static matrix carry-forward map (fixture and adapter preflight)

The table above is a coverage inventory, not an implementation plan. Before
adding any matrix code, bind each Linux assertion to the existing macOS PTY,
AppKit and native-stream seams as follows. This mapping is written before a
future GREEN run; it does not claim that any of these native scenarios has
executed.

| Existing Linux source/assertion | macOS adapter and required fixture |
| --- | --- |
| `tui_content_lab.py`: `screen`, `wait_text`, `send`, `query`, `choose_field` | `VtScreen.application_text`, `MacPtySession.wait_text`, `send_key`/`send_text`, `tui_search` and `select_tui_password_for_copy`; resize only with `MacPtySession.resize` plus a current-screen wait. Keep split UTF-8, wide-cell and row-position assertions; do not flatten rows or normalize whitespace. |
| `tui_content_lab.py`: `setup` and `catalog_cases` | Extend the existing `seed_tui_content` fixture with the same seven-kind/field seed and synthetic token-exchange, notes, source/custom and attachment descriptors. Assert the seed command's `types=7` result before starting the TUI; do not create a second vault engine or silently substitute a field. |
| `tui_content_lab.py`: wrong password, reveal expiry, clipboard race, trash/restore/purge | Fresh real `start_macos_tui` sessions over the human TLS/RPK socket; use `read_appkit_pasteboard`/`write_appkit_pasteboard` and `OwnedClipboard` only. Preserve the exact canary, replacement-owner check, no-secret PTY scan, `l` exit and durable revision/audit counts. |
| `tui_access_lab.py`: `authorization`, `discover`, `wait_state`, `choose` | The first Mac slice reuses the already-provisioned A/B metadata, generates one additional synthetic RPK through the real agent account for keyboard enrollment, and drives `a`/`n`, `e`, `s`, `x`, `w`, `x` with `MacPtySession`; it checks the next real bootstrap-agent discovery and safe pending context, not only screen labels. The standard Mac `serve_vault` fixture has no provider worker and its agent TLS profile pins only the bootstrap agent, so this slice deliberately stops at a real `CREATED`/cancelled attempt and does not fabricate a second transport, provider, or passkey `v` response. A separate provider/browser fixture and multi-agent transport profile remain required for the full native Ticket 24 matrix. |
| `tui_operations_lab.py`: `onepux`, `seed_remote_device`, `send_long` and durable assertions | Create deterministic CSV/1PUX/native/JSONL/recovery fixtures and a >16 MiB attachment before the TUI. Replace `tmux send_long` with visible-suffix waits plus `send_text`; run the existing `human-streaming-file`/native stream path and real `pm-sync` process with distinct device keys. Assert source bytes, digest/length, 0600 destination, pinned namespace and durable job/restart state. |
| `tui_operations_lab.py`: `ClosingEndpoint` and negative confirmations | Use an owned native Unix endpoint that closes connections for the offline branch; all invalid source, existing destination, wrong pin, confirmation mismatch and cancelled flows must remain explicit failures with no retry or alternate endpoint. |

The Mac fixture inventory must therefore be created and ownership-registered
before the operation driver is changed: one deterministic content seed, three
or more agent identities plus provider, CSV and 1PUX inputs, remote sync
identity/pairing, backup/plaintext/restore destinations, recovery material,
large-attachment source/destination, and every owned child socket/process.
Each path is collision-checked, synthetic and removed only through the existing
strict ledger. `seed_tui_content`, the real service and all stream helpers run
before the first matrix `PASS`; no fixture setup failure is converted into a
screen-only success.

The first implementation slice is now test-only `run_tui_ticket23_matrix` in
`crates/pm-custody/tests/macos_lab.py`, invoked after the existing core/expiry
flow. It adds a wrong-master-password PTY case, walks the exact `human_fields`
descriptor order for all seven kinds plus the exchange relationship, reveals
one real synthetic field per descriptor family with expiry checks, verifies
the AppKit copy/replacement-owner lease, and drives the existing `t`, `f`,
`g`, `h`, `d`, `u`, `p` and `P` keyboard contracts. `TUI23_FIELD_CATALOG`
mirrors the Rust descriptor ordering rather than relying on insertion order or
an initial selection. This code has only static validation so far; its native
execution and every durable result remain pending.

The next bounded implementation slice is test-only
`run_tui_ticket24_matrix`, invoked after the content flow. It uses the existing
real macOS PTY and human TLS/RPK channel to inspect the two setup-authorized
agent rows, enrolls and revokes a newly generated synthetic RPK through the
closed `n` payload (the public RPK is read by the fixture's privileged
observer), toggles the shared credential with `e`, and checks an actual
bootstrap-agent discovery before and after disable, suspend and resume.
It then starts one real `agent-attempt` against the ordinary LaunchDaemon,
observes its safe `CREATED` context with `w`, cancels it with `x`, verifies the
terminal `CANCELLED` state from the agent process, and finally exits with the
human `l` key before proving discovery still works. No pending context, attempt
reason, master password or field canary is printed by the observer. This is
static/test-fixture preparation only: because the normal macOS service has no
provider worker and pins one agent transport identity, provider-backed
`WAITING_FOR_HUMAN`/passkey approval and a second live agent remain explicit
native coverage gaps rather than being simulated.

The implementation order is fixed: (1) add only fixture construction and
adapter assertions, (2) run a focused real-PTY content/access/operations
scenario with the existing deadlines, (3) add the complete matrix runner, and
(4) run the normal two-architecture native job. The runner must retain the
current core cases and negative pasteboard control, use AppKit for copy, and
report each 23/24/25 contract in its final PASS. Until that sequence runs,
the static map and Linux labs are planning evidence only.

## Remaining acceptance work

- Compose and verify the complete keyboard TUI through the normal
  non-diagnostic binary; run 18 verifies that binary's custody flow but not the
  TUI command or Ticket 23--25 keyboard operations.
- Complete the separately scoped reboot/FileVault and signing/notarization
  gates.
- Execute or recover the intended pre-port behavioral red if the acceptance
  record requires it; the observed compile RED does not substitute for that
  behavioral evidence.
- Record exact runner versions, command output and cleanup result here.
- Repeat the repository and Linux gates on the integrated candidate after the
  separate merger incorporates the native CI configuration.
- Have the separate merger integrate and verify before resolving Ticket 26.

No existing fallback was changed. The previously unsupported non-Linux path
failed explicitly; this patch replaces that explicit failure only for macOS
with native primitives. Other unimplemented targets continue to fail
explicitly.

### Bounded interruption close — 2026-09-16

Mac32 (`34880042223`, `9e3f46e`) failed in both CPUs at the Passkey reveal
assertion. The seed is `[0x73; 32]`, valid UTF-8 (`s` repeated 32 times), not
invalid binary: the expected fixture string was wrong. The fixture now matches
the unchanged product seed. Reveal acceptance observes status and expected
exposure together on the current screen within the original eight seconds.
Expiry observes the real bordered footer, tolerates only its space padding,
and requires hidden exposure plus full-screen absence for unique canaries.
Only the generic note value uses exposure-local absence because `[note]` is
legitimate catalog metadata. Split-frame regression retains both cases and
strict VT parsing. Linux focused observer/helper regression passed; it does not
prove macOS product acceptance. The first local correction run failed because
the synthetic bordered row retained trailing screen spaces; that fixture/parser
alignment was corrected without relaxing the status/canary predicates.

The interrupted macOS sync seam from Sol's `c010af7` is composed without the
Windows port: exact Linux/macOS cfg and checked `SO_NOSIGPIPE` on both accepted
and connected Unix streams. Native build/test now includes `pm-sync`; this is
not the pending complete TUI25 sync/pair/retire acceptance fixture.

Verification correction: /tmp/pm-handoff-mac-check.log ran Cargo from the root cwd;
it is ROOT Linux evidence, not WT26 evidence. Correct WT26 command runs from
its worktree, log /tmp/pm-handoff-mac-worktree-check.log. No native claim.

Final bounded local verification: focused observer/helper regression PASS;
`cd .worktrees/26-macos && ./scripts/check.sh` PASS in
`/tmp/pm-handoff-mac-worktree-check.log` (Linux, no native acceptance).


### Concurrent discovery isolation method — 2026-10-02

User-authorized continuation starts at `8951e6bab642edf5fe99ac51b48a963882b62c1c`.
Recovered [run 35300789424](https://github.com/SantanaJcp/passwordmanager/actions/runs/35300789424)
executed that exact SHA and failed on Intel and Apple silicon after the catalog,
reveal/expiry, favorites and isolated clipboard assertions. Both jobs observed
`before=ok discovery=failed after=ok cleanup=ok process=same result=nonzero
stderr=custody-unavailable elapsed=io-bound-or-later`. No crash or restart was
observed. Previous run logs remain available in GitHub, not in the removed
September `/tmp` handoff directory.

Source isolation: `serve_loop` synchronously calls `accept_one` for the agent,
then the human; `accept_one` synchronously calls `handle_connection`, whose
human branch stays in `handle_human_rpc` until the human locks/disconnects.
A live TUI can therefore prevent the next agent accept. This is a hypothesis
supported by the call graph, not yet a native root-cause finding.

Discriminant, before changing product behavior: start a fresh ordinary TUI,
unlock over the existing native channel, and start **one** real agent discovery
while continuously draining the PTY. At two seconds, only if that same helper
is still pending, send the human `l` key once. Keep the original helper bound
(30 seconds), product I/O bound (15 seconds), KDF and all original assertions.
Require the same helper to complete, the TUI to exit zero and launchd to retain
its PID. Emit only `completed-with-human-open` or
`completed-after-human-lock`, plus fixed process/result categories. This is
supporting evidence: the original Ticket 24 concurrent discovery still runs
and must pass with the human connection open; releasing a blocking human
connection cannot substitute for that requirement. No operation is retried.

The fixture pump gains one explicit progress callback solely to send that key
while its existing selector keeps draining. Check Python AST, the existing
observer/helper regressions, shell/CI guards and diff before native dispatch.
Native confirmation requires the same causal classification on both CPUs.
Only after that result may a bounded macOS accept-lane correction be made.
Linux's existing serialized accept behavior is outside this port's correction.

Inherited behavior reported and retained: `accept_one` ignores listener accept,
stream-configuration and individual connection-handler errors; the client
fails visibly while the service continues. It is not changed by this diagnosis.


### Full25 native keyboard fixture method — 2026-10-02

The Linux source present in this checkout is `tui_operations_lab.py`, not
`tui_migration_lab.py`. Extract its unchanged deterministic 1PUX3 builder and
pairing-CBOR namespace reader into a shared test-only module, keeping Linux's
owner mapping explicit. macOS uses the logged-in human's UID, private sources,
the existing `MacPtySession` and native descriptor/streaming channel. No tmux,
Linux namespace, provider double or direct operation command counts as TUI
acceptance. CLI CRUD/stream commands below are clearly named fixture setup.

Before the TUI, create the same synthetic remote-device signed history through
a separate real custody process (owner stopped, distinct device/audit custody,
then owner restarted), and seed the existing >16 MiB streaming attachment.
Install architecture-checked `pm-sync` in a custody-owned private fixture path,
create synthetic server/client RPKs, and start a real system-domain sync job
against a private opaque store. Every job/path joins the strict ownership
ledger; any setup or cleanup error fails, no PASS precedes verified cleanup.

Replay by keyboard: Chrome, Apple and mappable CSV preview and commit; missing
source, malformed/hostile 1PUX, duplicate keep/replace preview, Esc and wrong
confirmation without item-count changes; 1PUX3 import with source-digest
preservation; protected pairing, real pinned sync and same-job status,
wrong-pin rejection, offline endpoint and bounded transport failure across
custody restart and human lock/idle; causal retirement of the seeded device;
encrypted backup and warned plaintext export, collision/confirmation failures;
selected large-attachment download with exact bytes/length and mode 0600;
audit query/purge preserving content; restore preserving current authority;
recovery exact re-entry and historical-copy warning; master rotation, rejection
of the old password and successful fresh unlock using the new password.

Synchronize menus/prompts, current status and visible input suffix before Enter.
Keep existing waits (8 seconds for ordinary UI, 20 seconds for happy sync,
75 seconds for the already documented bounded-backoff terminal observation),
product deadlines, KDF, frame limits and lease/idle settings. Queries observe
the original job ID, never resubmit sync. Read-only durable counts and file
checks supplement keyboard results; they do not replace operations. Stream
verification compares bounded chunks against the existing synthetic pattern.
No secret/canary, recovery code or screen dump is printed. Individual native
PASS labels are emitted only after the entire fixture and strict cleanup.

Full24 remains blocked beyond the existing slice: ordinary `serve_vault` sets
`provider: None`, and `serve_loop` pins `bootstrap.agent_uid/agent_spki` in the
only agent listener. The second enrolled RPK cannot use that endpoint. Running
`serve-attempt-lab` or a second bootstrap listener would not demonstrate the
ordinary service's provider worker or multi-agent transport. No substitute is
introduced; WAITING, passkey UP/UV and a second working agent remain open.

Happy-sync timeout isolation, before any further correction: preserve the
same keyboard request and original 20-second wait, then on its failure record
only fixed current-screen and durable `PMSS1` phase categories, whether the
sync PID is the original readiness PID, and read-only opaque block/root
counts. Do not print paths, job IDs, RPKs, ciphertext, stdout, or screen
contents. Retain and re-raise the original failure; diagnostics never perform
sync, extend the wait, or retry authentication/operations. This distinguishes
an observer failure, worker rejection, unavailable transport, or incomplete
progress without guessing a product correction.


Discriminant run [37087372922](https://github.com/SantanaJcp/passwordmanager/actions/runs/37087372922),
exact `c5735f66d923eee2ce92931a0ac171e6e7e3786d`, completed FAILED on both CPUs.
Apple silicon emitted `PM26_ACCEPT_LANE control=completed-after-human-lock
process=same result=zero`, then the untouched concurrent gate failed with the
original 15-second-or-later category. This confirms the serialized human lane
blocks agent acceptance on ARM, with no operation retry. Intel failed earlier
in the independent isolated pasteboard probe: its result was indeterminate,
and the required post-probe human read returned AppleScript conversion error
`-1700`. No Intel causal classification is claimed. The discriminant is moved
immediately after authorization setup, before clipboard/content matrices,
so that unrelated later failures cannot prevent observation. All original
clipboard assertions and the concurrent acceptance gate remain intact.


[Run 37087946638](https://github.com/SantanaJcp/passwordmanager/actions/runs/37087946638),
exact `7038e667e67b1521df04d10efdc68569c92c31ae`, completed FAILED. **Both Intel
and Apple silicon** emitted `completed-after-human-lock process=same result=zero`
before later isolated-clipboard indeterminacy and post-control AppleScript
`-1700`. This confirms the shared synchronous accept loop is the concurrent
discovery root cause, not a catalog expectation or VT repaint race. The
clipboard failure is independent and remains an explicit failed prerequisite.

Minimal product correction now authorized by the task's native defect scope:
on macOS only, allocate exactly one human accept thread at service startup
and retain the agent accept lane on the main thread. The human lane owns its
listener, the same verified TLS config and a cloned service handle (Arc audit
custody and sync manager, no new engine or plaintext roots). Thread creation
failure or unexpected lane termination is `CUSTODY_UNAVAILABLE`; no unbounded
per-connection threads are introduced. Existing bilateral UID/RPK/ALPN,
blocking accepted-stream normalization, socket bounds and provider settings
remain unchanged. Linux's existing accept loop remains intact. Validate with
repository check under the shared flock, then the ordinary native concurrency
assertions on both CPUs. The causal control should now complete while the
human TUI is open. Do not count the clipboard prerequisite as a denial if it
is indeterminate; the next run enables its existing categorical observation.


Independent-matrix ordering refinement: retain the initial seeded catalog,
three terminal sizes and core keyboard lock; run the unchanged full Ticket23
and partial Ticket24 matrices before the independent isolated clipboard gate.
Then run Full25 even if the clipboard assertion failed, provided the verified
custody PID is unchanged. Aggregate every failure and finish strict cleanup;
any error prevents all overall PASS lines. `PM26_MATRIX ...=observed` labels
name completed assertion groups, never whole-ticket acceptance. A changed or
missing custody process stops further matrices, rather than inventing a
recovered service. This ordering gives useful native evidence despite a
separate clipboard prerequisite failure and does not substitute any gate.
Full25 keeps idle=30; during the 75-second bounded transport observation,
keyboard status queries every 20 seconds select the same job ID. They do not
restart sync or repeat authentication. Invalid server-side CSV/1PUX requests
currently terminate their human channel; dedicated negative sessions require
the visible failure, subsequent exit 4 and unchanged item count. No product
error handling is changed to keep those sessions alive.


Local correction evidence (Linux x86_64, exact worktree cwd):
`flock /tmp/pm-cargo-window.lock ./scripts/check.sh` first completed all tests
but failed Clippy on four needless by-value arguments in the new lane helper.
The agent listener/config/RPK and service are now borrowed; only the human
listener/config and cloned service move into its fixed thread. The same full
check subsequently passed (`/tmp/pm26-20261002-check-final.log`). This is local
build/regression evidence, not native concurrency evidence. Python ASTs,
existing VT/helper/pasteboard-parser regressions, shared 1PUX construction,
CI guards and diff checks passed; no local macOS or provider result is claimed.


### Recovered September 17 chronology

The following URLs/SHAs were re-read from GitHub's run catalog and failure
logs on October 2 (local date). Every listed workflow is completed FAILED;
partial progression does not imply native acceptance.

| Run | Exact SHA | Recovered failure/progression |
| --- | --- | --- |
| [35227363111](https://github.com/SantanaJcp/passwordmanager/actions/runs/35227363111) | `fa6038c3a44b79bed503ca1ac7cdcf4ce01b68b0` | Both CPUs timed out observing the favorite selected row. |
| [35228456377](https://github.com/SantanaJcp/passwordmanager/actions/runs/35228456377) | `c92634a6e2878b5bfe5f65ad9119224f4b39c8e4` | FAILED; favorite status-render correction. No new root-cause attribution here. |
| [35229959654](https://github.com/SantanaJcp/passwordmanager/actions/runs/35229959654) | `925112ec64eb38bf35bb16d5c6ce9fc16f894dbc` | Intel failed selecting the enrolled `ticket24-agent-c` row. |
| [35231927929](https://github.com/SantanaJcp/passwordmanager/actions/runs/35231927929) | `665893da8e96bb3fda98ca9b0f49abe63c753a0b` | Intel fixture helper descendant readiness failed. |
| [35233363436](https://github.com/SantanaJcp/passwordmanager/actions/runs/35233363436) | `5c1f257ea583e8d70d30fecdc12b7c939ef08db2` | Both CPUs timed out on a current-screen observation. |
| [35235287689](https://github.com/SantanaJcp/passwordmanager/actions/runs/35235287689) | `ccaf17e996bea5626096bbc5325bf8ac70028eb9` | Intel discovery returned unavailable; ARM safe-metadata observation failed; PTY cleanup errors also retained. |
| [35300789424](https://github.com/SantanaJcp/passwordmanager/actions/runs/35300789424) | `8951e6bab642edf5fe99ac51b48a963882b62c1c` | Both CPUs passed catalog/reveals/favorites, then failed concurrent discovery with unchanged custody PID and I/O-bound-or-later timing. |

The new [Full25 driver](../../crates/pm-custody/tests/macos_tui_migration_lab.py)
reuses the [shared migration fixtures](../../crates/pm-custody/tests/tui_migration_fixtures.py)
and Linux [operations lab](../../crates/pm-custody/tests/tui_operations_lab.py).
It is first dispatched on `4a2faec7ef613fba7f79bc2d6291de6c4e730617`,
[run 37088951129](https://github.com/SantanaJcp/passwordmanager/actions/runs/37088951129).
This ordinary-binary run enables only the existing harness pasteboard categories;
no product diagnostic feature or environment is selected. The accidental test
file execute-mode change in `7038e66` is restored in `4a2faec`; Python execution
in that diagnostic run was unaffected.


First Full25 ARM run advanced through remote signed-history setup, large
attachment setup, invalid CSV/1PUX rejection, Chrome/Apple/mappable commits,
duplicates/cancel, 1PUX3 commit and protected pairing. It then failed because
`ps` no longer found the sync LaunchDaemon PID immediately after the readiness
socket connected. No exit status/signal was captured, so neither a crash nor
an ordinary failure is attributed. Before changing `pm-sync`, add owned
fixture stderr capture and fixed launchd exit/signal categories at that exact
boundary. Preserve the original raw readiness connection, all timeouts,
program arguments and assertions. The capture must classify stderr only as
empty, exact `SYNC_UNAVAILABLE`, other or unavailable; never dump it. A
confirmed product crash requiring a design decision stops this continuation.


Run [37088951129](https://github.com/SantanaJcp/passwordmanager/actions/runs/37088951129)
completed FAILED on both CPUs, exact `4a2faec7ef613fba7f79bc2d6291de6c4e730617`.
Both observed the corrected product control `completed-with-human-open` and
the unchanged concurrent discovery gate `discovery=ok process=same result=zero
elapsed=immediate`. Both completed the Ticket23 and partial Ticket24 assertions,
and recorded the real second enrolled native identity as blocked by the single
bootstrap transport. Both isolated clipboard jobs completed nonzero without
the exact canary, with different system manager domain and human pre/post
controls still positive. The September/earlier October indeterminate clipboard
runs remain failure evidence; their cause is not inferred from this success.
Full25 reached the same sync-readiness PID disappearance on both CPUs. No
product or deadline correction to sync is made without its exit discriminant.


Run [37089591305](https://github.com/SantanaJcp/passwordmanager/actions/runs/37089591305),
exact `8a852cb7293c9f71633a49bded7f31722a3b83cb`, completed FAILED on
Intel and Apple Silicon. Both retained `completed-with-human-open` and both
recorded the pending-row observation failure and sync-readiness failure.
The sync lifecycle discriminant on both CPUs observed ordinary exit `4` and exact
`SYNC_UNAVAILABLE` stderr, not evidence of a signal or panic. After successful
bind/connect in `pm-sync::serve`, the only fallible operation which can return
this error from the listener loop is
`pm_native_channel::configure_unix_stream(&stream)`. The closed readiness peer
thus exposes a **product per-connection guard error terminating the listener**.
The TUI's own online check also connects and closes before launching sync, so
removing a fixture probe would conceal the real defect.

Minimal correction method: keep the same checked native socket guard, but run
it first inside `serve_one`, before timeouts/TLS/request processing. A guard
failure rejects that connection through the existing handler error path and
transfers no bytes; the opaque listener continues exactly as it already does
for other rejected connections. No guard, retry, transport, deadline or key
validation is removed. Preserve the original readiness close, then require
real pinned sync plus negative pin/closing/offline cases in Full25 on both CPUs.
Product scope is the macOS `pm-sync` port; Linux's configure call is a no-op.

Both CPUs also retained a separate partial Ticket24 observer failure: the
pending header was found before the `[CREATED]` row/context painted. The
ordinary daemon has no provider and the same started attempt must be CREATED.
Wait for the header, exact state/title, integration and attempt ID **together
on the current screen** within the existing eight seconds, then perform the
unchanged secrecy/cancel/terminal assertions. This is a fixture repaint
correction, not a state transition, authentication retry or product change.

Local verification of the listener correction:
`flock /tmp/pm-cargo-window.lock ./scripts/check.sh` completed successfully
(workspace format/check/tests/Clippy and repository guards), logged in the
owned `/tmp/pm26-20261002-sync-check.log`. This Linux host verifies compilation
and regressions; the native closed-peer case still requires the next exact
Mac candidate on both architectures.

Additional inherited behavior encountered and preserved: `pm-sync::serve_one`
uses `dispatch(...).unwrap_or_else(...)` to send `{"ok":false}` when dispatch
returns an error, omitting the underlying cause in the wire response. It is
not introduced or changed by the socket-guard correction. The existing
provider recovery conditional in `serve_loop` runs recovery only if opening
the delegated vault succeeds; an open error skips that block. Ordinary
`serve_vault` has no provider, so this is not activated by the native matrix.

Run [37090294105](https://github.com/SantanaJcp/passwordmanager/actions/runs/37090294105),
exact `244be8743b8864847642e561036c7eecf2b60cb6`, completed FAILED on both
CPUs. Both passed the ordinary native build/test/architecture gates, retained
`completed-with-human-open`, passed the unchanged concurrent discovery gate,
and completed Ticket23/partial Ticket24 after the current-screen pending
correction. Full25 passed the original readiness probe and reached its happy
pinned-sync wait; both timed out at its original 20 seconds with the TUI alive.
No cause is attributed before the durable/UI/server discriminant. ARM had no
independent core error; Intel also retained isolated clipboard indeterminacy
and its post-control AppleScript `-1700`. Strict cleanup ran and no cleanup
error was reported. Neither job emitted overall acceptance PASS.

Run [37090972867](https://github.com/SantanaJcp/passwordmanager/actions/runs/37090972867),
exact `1d74a8b63e4d5d2059237553801da5842abafbb7`, completed FAILED on both
CPUs. Intel completed Ticket23/partial Ticket24 and the concurrent gate, then
the happy-sync discriminant found `durable=integrity screen=integrity
process=same`, `blocks=23 roots=0`. Thus real pinned transport accepted opaque
blocks and the server stayed alive; this is not incomplete progress or an
observer-only timeout. Intel also retained clipboard indeterminacy/`-1700`.
ARM failed earlier at the first causal-control TUI unlock: the child remained
alive in a password-prompt screen at the existing eight-second bound. The
sync diagnostic was not reached; no input/KDF/dispatcher cause is attributed.
Both strict cleanups completed without additional errors.

Source-supported next discriminant: the preceding Ticket23 permanently purges
an item/revisions, `apply_item_purge` deletes their payloads while signed
revision events remain in outbox, and `SyncReplica::push` calls
`export_ciphertext_graph` for every pending bound revision. That export joins
the now-required item/revision payload and maps a reducer error to the observed
integrity phase. Count pending `item-revision` events whose subject is in
`purged_items` and has no `vault_items` row, using read-only SQL, before Full25.
No IDs, event bodies or payloads are logged, and no outbox row is acknowledged,
deleted or skipped. If confirmed this is a shared engine/sync blocker, outside
the macOS port; do not change `pm-vault` or shared sync replication here.

Predetermined fixture ordering refinement: run import, causal retirement,
backup/export/collisions, streamed download, audit, restore and rotations before
pairing/sync. These independent cases keep their original assertions and
bounds; they never substitute for rejected sync. Sync, its negatives and
strict cleanup remain mandatory for Full25 PASS. Reopen post-rotation sessions
with the explicit rotated synthetic password. Report completed groups as
`observed`, not overall acceptance.

Restore observer correction supported by `backup::restore_event_count` and
`human::commit_backup_restore`: a restore creates new content events. Require
new item/event counts and an unchanged digest of the pre-existing authority
events (exclude only content lifecycle and audit-purge kinds), rather than
requiring the entire `authority_events` count to remain identical. This checks
preserved authority and does not suppress legitimate restored revisions.

Inherited compatibility path also encountered and retained:
`reducer::decode_event` tries `decode_legacy_body` when the primary body decode
fails/canonicality differs; it can accept a supported legacy representation.
This is not modified or used as a diagnostic substitute.

The next fixture candidate puts output-collision negatives after the other
independent local cases. Before them, create protected pairing, prove the
ordinary offline message against the not-yet-started real sync endpoint,
launch the same owned native sync daemon with the original closed-peer
readiness probe, and exercise the existing wrong-pin request-context negative.
None substitutes for happy sync. On collision failure, keep the original
eight-second wait and emit only `kind`, fixed UI result category, and whether
the original destination digest changed, then re-raise. Do not overwrite a
destination deliberately through a setup command or alter product rename
behavior. Require original source digests before reporting the local group
observed; all collision and sync assertions still gate overall Full25 PASS.

Run [37091908012](https://github.com/SantanaJcp/passwordmanager/actions/runs/37091908012),
exact `282531282b045a17eabaa607a3738b78b9438d31`, completed FAILED on both
CPUs. Both completed Ticket23/partial Ticket24, immediate concurrent discovery,
and Full25 imports. Both recorded `items=1 pending-revisions=5 missing-items=5`:
purged item payloads are absent but five signed revision events remain pending.
This confirms the shared purge/outbox prerequisite defect traced above. The
exact error returned by the export was not instrumented, so attribution of the
earlier integrity phase to that export remains a source-traced inference.
Both then passed causal retirement and the first native backup, but timed out
waiting for the second backup to reject the existing destination. Source
inspection shows `rpc_download_atomic` checks only its temporary's novelty
and then uses `fs::rename` onto the destination; the next fixed UI/digest
discriminant must distinguish actual overwrite from an observer failure.
Neither shared path is changed. Intel retained its independent clipboard
indeterminacy/`-1700`; ARM had no core error. Both strict cleanups completed.

Recovery observer method: the first `Exposure:` substring can still be the
previous hidden row while the recovery prompt repaints. Require the recovery
prompt and a complete canonical `PMR1` code together on the current bordered
exposure row within the original eight seconds. Its grammar is derived from
`pm_crypto::RecoveryCode::fmt`: 16-byte vault ID, decimal generation, eight
four-byte key groups and one four-byte checksum. Return that same observed
code only for hidden exact re-entry; never log it, regenerate it, use a direct
command, extend reveal=10, or accept `<hidden>`/a partial code. Server mandatory
exact confirmation and subsequent rotation assertions remain intact.

Tighten the restore authority fingerprint to exclude only the two new event
kinds actually produced by `commit_backup_restore`: `item-revision` and
`trash`. Existing purge/restore/audit and all grant/root/device events must
remain unchanged. This strengthens the existing authority-preservation check.

Run [37092669202](https://github.com/SantanaJcp/passwordmanager/actions/runs/37092669202),
exact `0a8e339be9066806f2b70fba0bf8aa86e887f41e`, completed FAILED on both
CPUs. Both completed Ticket23/partial Ticket24, concurrent discovery, Full25
imports, causal retirement, protected pairing, original sync readiness,
explicit offline and fixed wrong-pin rejection. Both retained the five pending
purged revisions. Both passed first backup/export (including warning and wrong
confirmation), exact >16 MiB streamed download, audit query/purge and wrong
restore confirmation. ARM additionally completed real native restore, new
item/event counts and the authority fingerprint, then hit the partial/hidden
recovery exposure assertion. Intel timed out at the original eight-second
restore wait with a live TUI and pending VT control; no completed restore is
claimed there. Intel retained clipboard indeterminacy/`-1700`. Neither reached
the collision discriminant. Both strict cleanups completed without new errors.

Intel restore-timeout discriminant: retain that request and eight-second wait.
On failure only, record fixed current UI status before/after one read-only
durable snapshot, item-count delta and unchanged/changed authority fingerprint,
then re-raise the original timeout. No screen, ID, digest or archive content is
printed. Do not retry restore or extend its observation into a success. This
distinguishes committed state/late repaint from an incomplete or explicitly
failed operation; any original timeout still fails the matrix.

Composite-status repaint correction: the wrong-pin observer can read the
fixed rejection prefix before its required `no success recorded` suffix.
Wait for the entire literal rejection phrase, retaining the suffix and durable
count assertions. Apply the same complete-literal rule to the recovery and
master-rotation historical-copy warnings, whose required suffixes follow their
status prefixes in `tui.rs`. Every wait remains eight seconds. No status,
warning, pin, password, confirmation or operation is changed; incomplete
repaints can no longer satisfy a prerequisite observation.

Run [37093502065](https://github.com/SantanaJcp/passwordmanager/actions/runs/37093502065),
exact `af5a99c568ef8326f730ca81c3ab68253135e338`, completed FAILED on both
CPUs. Both completed Ticket23/partial Ticket24, immediate concurrent discovery,
Full25 imports, retirement, protected pairing/readiness/offline and retained
the five missing pending purge graphs. ARM hit the wrong-pin prefix/suffix
repaint assertion, plus independent clipboard indeterminacy/`-1700`; it did
not reach recovery. Intel completed the wrong-pin negative, backup/export,
exact attachment stream, audit and native restore within the original bounds;
the stricter authority fingerprint passed. It observed a complete recovery
code, performed exact hidden re-entry and received the rotation status prefix,
then failed before observing the historical-copy warning suffix. This is
direct evidence for the composite-status observer correction above. Intel
had no independent core failure. Both strict cleanups completed without
additional errors. No timeout was converted into success and neither job
reached output-collision classification or overall acceptance.

Run [37094118542](https://github.com/SantanaJcp/passwordmanager/actions/runs/37094118542),
exact `53f8aa54881d190ced7ac17e0de7658d65eb4288`, completed FAILED on both
CPUs, with `pasteboard_diagnostic=false` and ordinary production binaries.
The workflow finished at 2026-10-03 03:50:39 UTC (October 2 local date).
Both passed native build/test/Mach-O gates, the causal control with the human
connection still open, unchanged immediate concurrent discovery, Ticket23 and
the existing partial Ticket24 slice. Both recorded the same five pending
purged revision graphs and completed Full25 import/offline/wrong-pin/local
assertion groups. Both emitted `PM26_OUTPUT_COLLISION kind=backup
result=unexpected-complete destination=changed`: a second keyboard backup
reported completion and changed the pre-existing destination digest instead
of rejecting it. The original eight-second rejection wait failed and remained
a failure. This proves a shared Unix product overwrite defect, not a repaint
expectation: `rpc_download_atomic` uses `create_new` for its `.partial` file
only, then `fs::rename` replaces the destination. Its body is not changed here.
ARM had no independent core error; Intel additionally retained isolated
pasteboard indeterminacy and the post-control AppleScript `-1700`. Both ran
strict cleanup without an additional reported cleanup failure. Neither emitted
overall acceptance PASS. No identical rerun is justified while these shared
blockers remain unchanged.

### October 2 consolidated checkpoint

Latest executed source candidate:
`53f8aa54881d190ced7ac17e0de7658d65eb4288`,
[Intel job](https://github.com/SantanaJcp/passwordmanager/actions/runs/37094118542/job/111120416664)
and [Apple-silicon job](https://github.com/SantanaJcp/passwordmanager/actions/runs/37094118542/job/111120416554).
Both jobs are completed FAILED. A following documentation-only commit records
this result; it is not a newly executed native candidate. All launched native
runs have finished. The branch remains `codex/pm-26`; Ticket26 stays claimed,
with no main-branch integration or PR merge.

Here **PASS (component)** means that the identified assertions completed on
the exact candidate above, not that the failed job or entire criterion passed.
The issue's checkboxes are intentionally unchanged.

| Ticket26 acceptance / requested coverage | Current evidence and boundary |
| --- | --- |
| Native account / LaunchDaemon / bilateral peer / keys and ACL (criterion 1) | **PASS (component), Intel + arm64.** Real `_passwordmanager` process, installed binary/plist ownership, native peer UID, TLS/RPK roles, wrong-UID/role/fake-server rejection, inaccessible protected state and bad-bootstrap rejection completed before the matrices. No overall gate PASS was emitted. |
| CLI-first authority and fail-closed TUI (criterion 2) | **PASS (component), Intel + arm64** for full Ticket23, existing partial Ticket24, original concurrent agent discovery, invalid import negatives, wrong old password and fixed wrong-pin request context. **Incomplete** for the entire criterion: second working agent / provider states below and post-Full25 gates are not demonstrated. The wrong-pin case rejects the fixed request context; it does not certify every bad-certificate network case. |
| Native clipboard / terminal / suspension and identity persistence (criterion 3) | **PARTIAL / FAIL.** ARM's reached core assertions passed on the latest candidate; Intel's isolated pasteboard probe remained indeterminate and its human post-control failed `-1700`. Terminal keyboard/resize assertions were reached on both. The separate final suspension/restart and native-probe gates occur after Full25 and were not reached. Older passes are retained in the chronology and are not current acceptance. Reboot/FileVault/human-terminal evidence stays in Ticket31; signing/notarization in Ticket34. |
| TDD red/green and exact checks (criterion 4) | **PASS (bounded evidence)** for concurrent-discovery red/green on both native CPUs and the local full `flock /tmp/pm-cargo-window.lock ./scripts/check.sh` after product changes. Native build/test/architecture checks passed on both at the latest SHA. Full native acceptance remains FAILED; Linux-gated tests reporting zero cases on Darwin do not establish native integration coverage. |
| Contract/standards review and merger integration (criterion 5) | **NOT DEMONSTRATED / pending merger.** This branch preserves the recorded limits/KDF, ordinary daemon, peer/role validation and design agreements; it does not certify an independent review or integration with 27/28. No issue status or confirmed design decision is changed. |
| Full24 second real agent / provider WAITING / passkey UP and UV | **BLOCKED, Intel + arm64.** Real second identity is enrolled, but the ordinary endpoint pins one bootstrap UID/SPKI; its transport is rejected. `serve_vault` sets `provider: None`. No normal provider worker, working second transport, WAITING or passkey ceremony is demonstrated; no lab provider/second listener substitutes for them. |
| Full25 independent local positive and negative groups | **PASS (component), Intel + arm64.** Keyboard CSV/1PUX import/preview/cancel/duplicate/malformed cases, source hashes, signed causal retirement, protected pairing, real endpoint readiness, offline and wrong-pin context; native backup, warned/confirmed plaintext export, exact 16 MiB + 4096 streaming download (bytes/length/mode), audit query/purge, wrong restore confirmation, native restore with new content and unchanged current-authority fingerprint, exact recovery re-entry/warning, master rotation/warning, old-password rejection and fresh new-password unlock completed. `full25-local=observed` precedes mandatory collision/sync gates; it is not full Full25 acceptance. |
| Full25 existing-destination negative | **FAIL, Intel + arm64.** Latest native keyboard backup overwrote the pre-existing file, with completion status and changed digest. Plaintext collision is later in the fixture and **not demonstrated**. The shared `rpc_download_atomic` body is untouched; authorize its owning workstream before changing it. |
| Native `pm-sync` build / tests / architecture / listener readiness | **PASS (component), Intel + arm64.** Locked/offline build/tests and single native Mach-O architecture passed, followed by real custody-owned system job and unchanged closed-peer readiness probe. This is not an end-to-end sync PASS. |
| Full25 happy pinned sync / status / persistent job / idle / bounded backoff | **FAIL / BLOCKED / not demonstrated.** Runs `37090294105` (both CPUs) and `37090972867` (Intel) retain the happy-sync timeout / durable integrity failure. Real server received 23 opaque blocks but zero roots in the Intel discriminant. Both latest jobs confirm one purged item with five pending signed revisions lacking required item payload. Attribution of the earlier integrity phase to graph export remains a source-traced inference; the missing prerequisite is verified. Latest fixture stops at backup overwrite, so happy sync, same-job status, closing-endpoint/restart/idle/backoff and final post-stop offline assertions were not reached. |

Concurrent-discovery root cause is confirmed by the native before/after
discriminant: at `7038e667e67b1521df04d10efdc68569c92c31ae` both CPUs complete
the same pending discovery only after the human lock; after the macOS-only
two-lane correction both complete it while that human connection stays open,
and the original concurrent acceptance assertion is immediate. The correction
adds one fixed human thread, not a new vault engine or per-client custody
thread pool. The fixture repaint changes separately require complete current
frames/status literals without changing any existing bound or assertion.

The second product correction confines a checked native socket-guard failure
to the existing `pm-sync::serve_one` connection handler before TLS processing.
The original listener probe had terminated `serve` with ordinary exit 4 and
`SYNC_UNAVAILABLE`; after moving the guard the same probe leaves the real
daemon alive on both CPUs. No error is converted into a successful connection,
and no native guard is removed.

Product files changed since `8951e6b` are only
[`pm-custody/src/linux.rs`](../../crates/pm-custody/src/linux.rs)
and [`pm-sync/src/main.rs`](../../crates/pm-sync/src/main.rs), both potential
merge-conflict sites for Ticket28. No `tui.rs`, `lib.rs` or `pm-vault` product
change is included. Test changes add the native Full25 driver, share the
unchanged Linux 1PUX/pairing builders, and update Mac observers/diagnostics.
The full Linux TUI laboratory was not rerun; integration regression coverage
belongs to the merger. The unrelated dirty `.gitignore` is preserved and
excluded from all commits.

Additional inherited cleanup concealment encountered and preserved:
`rpc_download_atomic` ignores failure of `remove_file(.partial)` after a
stream error, so cleanup failure is not separately surfaced. The existing
`accept_one` ignored handler errors, sync dispatch error substitution,
conditional provider recovery and legacy event decoder described above are
also unchanged. None is introduced as a way to pass this fixture.

Next authorized boundary: hand the branch/evidence to the orchestrator, who
can assign the shared purge/outbox and atomic destination-publication defects
to their owning implementation workstreams, provide the ordinary multi-agent
and provider paths, and reconcile the two product conflict sites with 28.
After those changes and merger regression checks, dispatch a new exact native
candidate on both CPUs and execute the still-mandatory gates. Do not resolve
26, delete pending revision events, bypass purge, substitute a provider,
reinterpret clipboard indeterminacy as denial or extend deadlines here.

### W1 fase 2 — discriminante ARM de colisión (2026-10-03)

Baseline W1 `7d8ba007729bd637add676a6a34429b176ef7d11`,
[37126535485](https://github.com/SantanaJcp/passwordmanager/actions/runs/37126535485):
ambas CPU completan Full25 local con avisos completos; Intel observa ambas
colisiones y llega al bloqueo purge/outbox W2. ARM conserva destino intacto,
pero no observa rechazo en8s. Hipótesis del rechazo trasladado al panel
**descartada por código**: sigue en status y el oráculo busca el mismo literal;
los resultados exitosos de backup sí van al panel.

Método acotado de diagnóstico antes de ejecutarlo: mantener la negativa y su
wait8s sin modificación. Si falla, registrar sólo estado booleano de rechazo,
validez de panel, destino same/changed y temporal propio absent/empty/nonempty.
Después del gate ya fallido, usar `sample` nativo durante1s en el hijo TUI y
custodio launchd propios, sin suspenderlos ni cambiar el plazo/aserción. Reducir
cada sample a presencia booleana de símbolos download/read-frame/backup-write/
native-backup/socket-read/fsync/sqlite. No imprimir direcciones, PIDs, paths,
contenido del sample ni secretos. Outputs propios collision-checked dentro de
la raíz sintética, eliminados con errores propagados. El diagnóstico nunca
convierte el FAIL8s en PASS; falta sample también es error. No tocar el flujo
compartido de backup/persistencia de W2. Registrar asimismo cada colisión que
sí pase con `result=rejected destination=same`, conservando digest y literal.

Corrida W1 fase2 propia3:
[37129005704](https://github.com/SantanaJcp/passwordmanager/actions/runs/37129005704),
SHA `c4038653314a8adeef1e75f16d3828106894d5aa`, terminó FAIL en ambos CPU.
Intel y ARM pasan Full25 local y **ambas colisiones** con literal de rechazo
antes de8s y digest de destino intacto: Intel14:23:30/14:23:34 UTC,
ARM14:19:02/14:19:06 UTC. Ambos avanzan al bloqueo conocido de W2:
`durable=integrity screen=integrity process=same`, missingpurgeditems5.
Log `/tmp/pmw1b-macos1.log`. No se ejecutó el sample posterior al fallo porque
el gate pasó. No atribuir causa raíz al timeout histórico ARM ni afirmar que
la instrumentación lo corrigió: **no reproducido**, causa pendiente. No repetir
el mismo SHA sin hipótesis nueva. Deadline8s, backup y aserciones intactos.

Handoff W1 fase2: se consumieron las6 corridas autorizadas (5 Windows+1Mac),
todas terminadas; ningún run Mac adicional. La causa del timeout histórico
ARM queda pendiente, con hipótesis status/panel descartada y negativas nativas
Intel/ARM PASS8s sobrec403865. Antes de nueva corrida, el coordinador debe
proveer hipótesis/cambio pertinente y una nueva ventana CI. Entorno propio:
macOS15.7.9/kernel24.6.0; Intel20260824.0482.1, ARM20260907.0337.1,
Rust1.98.1. No se cambió backup, deadline, publicación ni estado de26.
