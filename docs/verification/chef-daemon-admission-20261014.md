# Ordinary daemon: D1/D2 corrective candidate

Result: **ISSUES** for the product bundle; **measured GREEN** for the two local
P1 reproductions below. Independent R2 and parent composition remain pending.
No native support certification, external-provider acceptance or ticket closure.
Principles: `design`, `prove`, `root-cause`, `truthful-state`, `small-owned`,
`no-fallbacks`, `isolate`, `handoff`.

Starting HEAD: `7b7026e0099ec87114dbb8e962e8e398bee18a71`, branch
`t3/daemon-readiness-registry-adapter`, worktree
`/home/santana/.t3/worktrees/passwordmanager/t3-9959e6f2`.
Original authorized base: `ecc2e9d390b780223dfdf1322288762f87af891c`.
This report supplements the unchanged historical
[1A/2A implementation report](chef-daemon-implementation-20261014.md).
The root/current-owner correction in 7b remains; the standalone 672 candidate
remains withdrawn. No dynamically learned root owner, UID alias or trust exception
was introduced. No new schema, grant, wire, receipt or replay behavior.

## D1: bounded admission by authenticated identity

Measured RED at exact 7b: four real authenticated A channels prevented a normal
B discovery (`CUSTODY_UNAVAILABLE`), both with separate UIDs and two RPKs sharing
one UID. The fifth A was already denied: this was cross-agent starvation, not
absence of a connection bound.

The immutable validated registry supplies N distinct RPK entries. Before spawning
a worker, the observed OS UID consumes a native budget of `4 * N_uid`. Total
workers are bounded by `4 * N`. Immediately after the authenticated TLS handshake,
before **any application magic read**, the observed RPK and native UID must match
the installed registry and consume one of that RPK's four permits. No client
label, unrecognized UID or TLS key adds a map entry or budget. Existing deadlines
remain. Registry admission remains separate from current human grants and
operation-time revocation.

The existing Unix encoding is exactly `5 + 16 + 16 + 44 + 2 + N*(44+4)` bytes:
83-byte header and 48-byte entries. Its actual 16,384-byte read limit therefore
permits at most floor((16384-83)/48) = 339 entries. The worker bound is derived
from the actual validated N; no arbitrary 64-agent or 128-connection cap was added.
Shared-UID rotation/cohort entries remain valid. Before authentication those
entries share native capacity; this does not establish separate OS isolation or
guarantee fairness against incomplete handshakes from the same principal.

RAII permits release on rejection, normal close and unwind. A current
AGENT_REVOKED response closes that channel after delivering the response.
Measured GREEN: separate/shared UID A4+B4 simultaneously, fifth of each denied,
A4 TLS-without-magic with B admitted, fifth A with **no magic** closed before
application read, disconnect permits reused, hot revoke across existing A
channels, B independent, service stop with open channels followed by fresh
four-slot B budget. Unit tests measure panic releasing both budgets while
preserving fatal orchestration error, unknown-native pre-admission and drain.
Existing registry regression also measures crossed UID/RPK, unknown RPK/native,
bilateral roles, actual human TUI concurrent with agents and trust-file failures.

## D2: local failure cannot invent an external outcome

Measured RED at exact 7b: an actual ordinary attempt reached WAITING_FOR_HUMAN
through real pm-web-auth and a controlled synthetic TLS destination. Removing
the socket, removing config, replacing config with equal bytes, removing the
registry, making bootstrap writable, or making audit custody writable then
produced terminal FAILED after one second, despite exactly one provider login.
An initially INDETERMINATE attempt and a native SSH-protocol double reproduced
the same terminalization (eight D2 cases total, six original cases retained).

Only local custody/preflight failures now inspect the existing lease's
`reconciliation_only` flag: reconciliation returns existing Indeterminate;
a new operation may still return explicit Failed with its fixed local reason.
Existing transport uncertainty, explicit authority revocation, cancellation and
expiry behavior remain. No new authentication retry, provider substitute or
authorization path. SSH's reconciliation-only path no longer becomes terminal
before reaching its no-login reconciliation behavior when its endpoint is absent.

New observability is limited to fixed local categories and reconciliation phase:
`PM_PROVIDER_LOCAL_FAILURE category=ADAPTER_UNAVAILABLE reconciliation=true`
(or CUSTODY_UNAVAILABLE). One thread-local slot deduplicates repeated failures;
no per-attempt map, upstream text, secrets or queries. Successful preflight resets
the slot. Generic worker, recovery and settlement error policies are unchanged.

Measured same-case GREEN for all eight: unknown outcome stays nonterminal,
provider login count remains one through trust restoration and daemon restart,
adapter recovery is reconciliation only, another registered/currently granted
agent gets NOT_FOUND, and cancel preserves existing CANCELLED/INDETERMINATE
semantics. Six original cases plus initial INDETERMINATE assert one deduplicated
diagnostic without the synthetic token. SSH uses real native peer credentials,
human authority and the ordinary attempt engine with a controlled native double;
it is **not** evidence of an external SSH login.

## Reproduction and measured checks

All builds and labs used blocking `flock /tmp/pm-cargo-window.lock`, fixed root
`.toolchain` homes, `RUSTUP_AUTO_INSTALL=0`, `scripts/cargo-local.sh`, locked/offline
Cargo and this worktree's private `target-chef-daemon-implementation`.
No wrapper with hardcoded target/debug paths was used. Python received exact
private binary paths. No dependency installation, host identity provisioning,
mount, native dispatch, network write, push or publication.

The exact-7b baseline binaries are preserved privately under
`target-chef-daemon-implementation/baseline-7b/` (including examples/):

| Binary | SHA-256 |
| --- | --- |
| pm-custody | 238d94768722acbd749bea5ab576626c719f1ac1c72544f114306e41ed511466 |
| pm | 5dcb90cefba529a323f9c7df2b476b9d33182c5b5a88c60347e803e34387b1ef |
| pm-web-auth | 9d657c8d36e181fdda74d305d69868f846768d5bf0043f3e64b1f1a59c214fb1 |

Within the documented subordinate-UID user/mount namespace, run:

```sh
python3 crates/pm-custody/tests/chef_runtime_chroot.py admission \
  "$BIN/pm-custody" "$BIN/pm" "$BIN/pm-web-auth"
CHEF_RECONCILIATION_CASE=socket python3 \
  crates/pm-custody/tests/chef_runtime_chroot.py reconciliation \
  "$BIN/pm-custody" "$BIN/pm" "$BIN/pm-web-auth"
```

`BIN` is the absolute baseline or current private debug directory. Other D2
case names are config-remove, config-replace, registry-remove, bootstrap-mode,
audit-mode, indeterminate-socket and ssh-socket. The owned UID0 chroot copies only
owned binaries and required public runtime libraries. Custody runs inside it;
real native clients and human TUI remain outside. No host mounts. Fixture-owned
processes/files are strictly cleaned; errors propagate, including on RED.

| Evidence log in /tmp | Measured result |
| --- | --- |
| chef-admission-D1-red.log / D1-red-shared.log | rc1, B denied under A4 |
| chef-admission-D2-red-summary.log | six original rc1 behavioral REDs |
| chef-admission-extra-red-summary.log | initial INDETERMINATE and SSH rc1 |
| chef-admission-final-focused.log | admission, registry, adapter and eight D2 cases rc0; package all-target tests/clippy rc0 |
| chef-admission-final-D2-CASE.log | individual state/count/ownership/diagnostic/cleanup evidence |
| chef-admission-check.log | scripts/check.sh once, rc0 |
| chef-admission-strengthened.log | final no-magic fifth-A and stop/restart proof, rc0; final example build/clippy rc0 |

The global check included the panic-release unit; subsequent changes only
strengthened the owned example/admission fixture, which were rebuilt and rerun.
Source/data-flow review, Python AST parsing and `git diff --check` also pass.
Local completed checkpoints recorded with `kitchen log`.

## Owned file ledger and remaining evidence

Product: connection_dispatch.rs (finite two-stage budgets), linux.rs (admission
placement and truthful local reconciliation failure), agent_wire.rs (close after
current revoke). No lib.rs edit. New fixtures: chef_runtime_admission.py and
chef_runtime_reconciliation.py. Existing owned helper changes: open_channel
example adds TLS-only quota witnesses; chroot runner routes new modes; adapter
fixture exposes a reconciliation hook and B ownership setup; registry fixture
replaces its historical global-four limitation assertion with B admission.
No existing non-chef custody tests or other writer's probes changed.

Executed platform: Linux ordinary daemon and actual native UID/TLS channels.
macOS/Windows execution, Windows secure-file primitive integration, hosted native
tests, six-target/external-provider acceptance and real SSH login remain NOT_RUN.
This correction does not claim Windows admission integration; legacy Windows
dispatcher behavior is unchanged. Parent must compose exact sibling SHAs and run
R2 only against prior D1/D2 repros; no outside-lane API change is required for the
executed Linux correction.

Inherited reported limitations remain: ignored generic handler/worker/recovery/
settlement errors can hide orchestration failures; parse_routes permits the
custody UID as adapter; create-only registry has no later update command;
duplicate file checks/dead peer-pin parameter/single fingerprint vector are P2
review corpus. They were not broadened into this correction. Product trust-file
safety, migration policy and G7 recovery remain unchanged.
