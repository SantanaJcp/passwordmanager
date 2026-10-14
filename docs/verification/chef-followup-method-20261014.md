# Followup method — 2026-10-14

**CLEAN_METHOD_ONLY; GUI BLOCKED.** Measured: 18 deterministic Python/structural
checks passed, exit0. No Rust, Cargo, product build/check/clean, product lab,
full52, affected flow, kitchen integrate, compositor or clipboard ran. The
method's future runtime behavior is source implementation, not executed product
coverage. No product candidate SHA exists in this handoff.

Workspace: `/home/santana/.t3/worktrees/passwordmanager/t3-0eed2d3d`.
Branch: `t3/chef-integration-tests`. Starting exact HEAD:
`d056ec72d75773c750fddc9cd71f945e8315f384`. Binding unchanged. Only this NEW report
and `scripts/chef-integration-followup-20261014/**` were authored. Principles:
`isolate`, `evidence`, `truthful-state`, `small-owned`, `handoff`.
Chef-mode and Omarchy skills were read in full; installed Hyprland/Aquamarine
manual/API were inspected before deciding against a compositor launch.

## Exact inputs and future dispatch

Base remains `8cd45529b062506a2cbe0c567538d3999ac8a2b6`; its nine original sibling
SHAs remain in core.py as mandatory transitive provenance, not remerged originals.
Canonical prepared refs remain unchanged, read-only:

| Role | SHA |
| --- | --- |
| caller | `3b4dd416a4dcd6f7cc301fc4c9f2c1d30ce540d9` |
| guide | `55abf2592cc67a7da9a0fcaa89055540f41fe61c` |
| sync_gate | `15013de74d7bf55464c2d6aef7e99ee2f9ee25fc` |
| original_method | `0a11733ffc784e80cb75c8df01d2cdcf34862d7e` |

The future caller supplies a JSON object with exactly these keys:
`sourceRepo`, `ownedRoot`, `base`, `heads`, `rootMode`, `guiMode`.
`heads` is an ordered array of `{role, sha}` records. Required roles are the four
above plus `followup_method` (this NEW commit's actual SHA) and `product_fix`
(the actual reviewed candidate, still unreturned/unreviewed). Recommended order:
caller, guide, sync_gate, original_method, followup_method, product_fix.
There is deliberately no dummy manifest, product placeholder SHA or runnable
composition supplied here. The vector is incomplete until the parent supplies
and locally imports the real reviewed product candidate and new method commit.

Future sourceRepo must resolve under its explicit ownedRoot in this worktree's
.scratch, with Git common objects inside that root and current-user ownership;
no linked worktree that borrows common objects elsewhere. Use a NEW disposable
source repository for later imports; the existing normalized repo is immutable
for this task. Missing roles, duplicates, nonliteral/non40hex refs, unresolved
objects, excluded ancestry, source symlinks/outside-owned paths and mixed root
or GUI modes fail before kitchen/artifact execution. Exclusion proof objects
2801c489/e18cf389/e448 must be available locally, but cannot be ancestors of any
selected input. No network import, review bypass or automatic semantic conflict
resolution is implemented. Parent retains responsibility for the exact reviewed
product range and allowed footprint.

The future entrypoint is [dispatch.py](../../scripts/chef-integration-followup-20261014/dispatch.py).
It invokes the verified installed kitchen executable with explicit --repo,
--base, ordered SHAs and --check; never --recorded. The manifest, actual vector
length, method HEAD/content hashes, historical input hash, full original nine,
kitchen implementation hashes and command/check digests bind a NEW request.
Evidence must be a NEW directory below `.scratch/chef-followup-runs/`; create
that parent locally before invoking the future dispatcher. No such product
run/evidence directory was created now.

[stage.py](../../scripts/chef-integration-followup-20261014/stage.py) verifies
previous/base/all ordered ancestors after each kitchen merge, including a
legitimate already-transitive no-op. Only the final stage schedules check.sh,
exactly once; extra stages, changed helpers and existing check receipts fail.
Kitchen's unconditional finally/rmtree is handled by moving its newly owned
clone into evidence/clone and leaving a temporary symlink. Kitchen removes its
temporary tree/symlink; preserved clone/logs/targets remain outside that cleanup.
This lifecycle is inferred from the installed kitchen implementation and old
method evidence; this NEW dispatcher was not executed.

All future Cargo/lab commands use blocking flock on
`/tmp/pm-cargo-window.lock`. Read-only inspection found no inner flock in the
historical shell wrappers/check/clean helpers. The clone gets its own explicit
.toolchain symlink to the verified fixed root, a fresh private target aligned
with wrapper target/debug execution, RUSTUP_AUTO_INSTALL=0 and offline mode;
check/build scripts retain --locked/--offline. Full-clean preserves target as
target-check and allocates a new EMPTY owned target before clean. No borrowed
product binary, shared target, dependency installation or target download.

## Exact52 and single-root routing

[sweep.py](../../scripts/chef-integration-followup-20261014/sweep.py) imports the
historical file read-only from exact0a and checks workspace/combined bytes.
SHA256: `0644a20f2f18a21c3f5f3298bf8d8f2b37495c7b59af26c613c2584ad764751c`.
All52 IDs, order, commands, expectations and existing assertions/deadlines remain
unchanged. Each original wrapper is dispatched directly; self-initializing3b
callers never acquire an outer owned_root/Popen hook. No resume/cache mode.
The same run's final-check receipt supplies its final-check row; changed vector
or HEAD cannot reuse it. Every row retains command/binding/status/log data.
Any nonzero product rc remains RED, including expected historical rc1 cases
`g7-matrix`, `g7-extra-bootstrap`, `g7-extra-vault`; aggregate exit remains nonzero.
GUI BLOCKED rows remain counted, rc=null, never exit0 or omitted.

[cli_adapter.py](../../scripts/chef-integration-followup-20261014/cli_adapter.py)
is a separate focused future command, to be called inside the existing owned
UID namespace under one outer flock with arguments CLONE CUSTODY PM NEW_EVIDENCE
and mode `direct-self-initializing`. It verifies pinned3b fixture/API bytes and
module/binary origins, requires actual namespace UID/eUID0, rejects preexisting
initialization or a Popen hook, then calls
linux_lab.initialize_installed_fixture(fresh custody) BEFORE fixture allocation.
Only the API's prepare() chroots installed UID1 commands; human/client PTYs
remain outside. No fallback to the old hook on failure.

Measured source transformation: all23 original CLI Assert ASTs identical; removing
the one migration insertion restores exact source bytes. The insertion is
byte-identical to original0a's setup→stop→migrate→restart insertion. Original
fixture SHA256 `f70418c7284f4a7ef4153ce4a100169bc5ec4b1b42c0675358149d418d0c7d07`;
transformed `cee71f4c91bbdb86ffbefcff5ed858ca26ed460d3d2dec72fe697743a8c434e8`.
This proves bounded source adaptation, not actual UI success. No3b file changed.

## Private GUI gate and precise prerequisite

Measured installed packages: Hyprland0.56.2-2 and Aquamarine0.15.0-2. Installed
Hyprland.1 documents config/socket/handover options, not a mandatory headless
backend selection. Backend.hpp/Headless.hpp expose library HEADLESS and
MANDATORY APIs, but do not establish Hyprland's environment/config mapping or a
safe renderer with no DRM/input/DBus fallback. No AQ_BACKEND value was guessed.
**No environment preflight was launched.** Prerequisite: local authoritative
Hyprland launch semantics that force only headless, plus an owned namespace
plan masking real input/DRM, with no owner config/data/device/desktop/DBus paths.
Then one bounded owned compositor/real synthetic clipboard preflight can be
prepared under the required lock, with endpoint/PID/UID/start-time binding and
resource-specific shutdown evidence. Availability alone is insufficient.

Current accepted guiMode is explicitly `blocked-private-prerequisite`;
[gui.py](../../scripts/chef-integration-followup-20261014/gui.py) cannot emit a
successful compositor/clipboard receipt. Future GUI rows blocked by this gate:
lab-tui-access, lab-tui-content, lab-tui-operations, publication-backup,
publication-plaintext, publication-attachment. Six of52 remain counted. Access
is conservatively grouped with TUI GUI prerequisites. No fixture assertions were
edited, clipboard helpers faked, or product failures suppressed.

The new runtime environment is an allowlist; owner WAYLAND_DISPLAY, DISPLAY,
XDG_RUNTIME_DIR, HYPRLAND_INSTANCE_SIGNATURE, DBUS_SESSION_BUS_ADDRESS and
XAUTHORITY are never inherited. Read-only endpoint identity checks require
private0700 directory, socket UID/device/inode, exact process UID/command/start
and kernel socket-inode binding to its fd. Crossed/foreign paths are rejected
without connecting. The unit server was CLEARLY SYNTHETIC AF_UNIX, not Wayland,
and provides no GUI proof. Actual wl-copy/wl-paste were not run. Old52 source
implies unknown GUI isolation coverage; it proves neither current private GUI
isolation nor owner-data exposure.

Other compatibility limits: the fresh clone does not inherit old host lab
artifact environment overrides. Existing browser/Keycloak wrappers retain their
own checks/default paths; their exact private, approved public artifacts must
be prepared before a later full run. No installation, alternate package or
borrowed product binary fallback was added. The focused CLI adapter is not an
additional historical case; it is a separate future affected-flow command.

## Measured method verification and retained evidence

Final verification command (exit0, 18 tests):

```sh
flock /tmp/pm-cargo-window.lock env PYTHONDONTWRITEBYTECODE=1 PM_METHOD_UNIT_EVIDENCE=structural-evidence-final2 python3 scripts/chef-integration-followup-20261014/test_method.py
```

Command SHA256: `6447d46c940215f947cfe64ecbf9f78b317594b84810d81ead23819f7d566e2d`.
[Final log](../../scripts/chef-integration-followup-20261014/structural-check-final2.log),
[verification/source hashes](../../scripts/chef-integration-followup-20261014/verification.json).
Coverage includes missing candidate, duplicate SHA/role, symbolic/unresolved
SHA, outside owned source, mixed initialization/GUI mode, seven-stage final-only
policy, lost ancestry and transitive no-op, exact52/expectedRED preservation,
all CLI assertions/removal equality, AST validity/no chroot hook, environment
allowlist and crossed/foreign command/endpoint rejection without contact.
No unit test is a passed kitchen merge, complete check or product52 run.

The first run's single unit error was AF_UNIX path too long before bind. Its log
is retained; only the new unit fixture changed to a fresh short0700 own /tmp
root, whose UID/path receipt is retained with the synthetic Git repositories.
Subsequent/final logs are preserved. No old or foreign resource was deleted.
All original0a eleven method/report files are measured byte-identical; d056's
prepare utility/report, original run1 targets/roots/logs and normalized refs were
not changed. Private artifacts are ignored by the NEW method-local .gitignore;
logs, hashes and the own kitchen journal are committed in new paths.
A kitchen log checkpoint ran exit0 with private HOME/KITCHEN_STATE and status
'done', avoiding owner notification or global state/config changes.

Parent must supply the actual reviewed provider fix before final composition.
No inference adds five caller GREENs to old42/52; no47/52 claim. The original8cd
42/52 and three G7RED remain immutable exact-run evidence. Native decision3 and
G7 durable-intent decision4 remain pending. No native acceptance, ticket close,
product/master acceptance, release or external action occurred. Work stops at
this new method source/structural result.
