# Provider worker boundaries — 2026-10-14

## Data shape

Execution ownership is intrinsic (`vault-webauthn-provider` → `PasskeyProvider`)
or ordinary (adapter worker). Ownership derives from the authenticated encrypted
attempt snapshot before leasing, opening operational credentials or emitting a
request. Ordinary selection scans the existing bounded pending set, preserving
its ordering and the existing 16/128 attempt limits. Intrinsic creation and human
confirmation retain their existing durable representation and sole executor.

An ordinary sensitive provider use has a protected authorized-emission phase
(current lease/token, credential revision, grants, deadline and local/native
configuration checked under the SQLite immediate guard) followed by an
unprotected response-wait phase. The immutable lease and already-connected
transport carry the result to existing settlement. Cancellation commits locally
while the response is pending; the exact running lease token remains the
settlement condition. No schema, receipt, retention, wire or durable-prepared
representation change is proposed or authorized here.

## Authority and provenance

LOCAL implementation authorized by the task and decisions1A/2A. Decisions3/4
remain unanswered. No nested delegation; the parent owns the independent final
Claude review. No push, PR, base-branch merge, publication, installation, CI,
native dispatch, dependencies or real credentials.

Measured: starting HEAD `ecced0d8af056826c780b2cfd2373f700ea9e7f3` was clean.
Exact caller candidate `3b4dd416a4dcd6f7cc301fc4c9f2c1d30ce540d9` merged
automatically as `d97006b3` with no conflict resolution. Before product edits,
`git diff 3b4dd416 HEAD -- crates scripts Cargo.toml Cargo.lock` was empty;
against `8cd45529b062506a2cbe0c567538d3999ac8a2b6` only the eight migrated
caller fixtures differed. Parent `.scratch` ledgers were unchanged. Proof:
[preedit-proof.json](../../.scratch/chef-provider-boundaries-20261014/preedit-proof.json)
and [Git blob manifest](../../.scratch/chef-provider-boundaries-20261014/preedit-tree.txt).
The foreign caller report/evidence were read only; no foreign binary/target or
executable path was used.

## Own RED before fix

Measured: fresh own target; fixed Rust1.98.1 toolchain homes/PATH,
`RUSTUP_AUTO_INSTALL=0`, locked/offline build rc0. Each build/lab is serialized
by one outer `flock /tmp/pm-cargo-window.lock`. Own subordinate user/mount/PID
namespace, private proc mount, unchanged strict UID0 root/chroot, real human
PTY/browser outside custody, explicit1A/2A fixture. Cross-UID roots remain short
under `/var/tmp/pc-*`; TMPDIR is explicit; owner/home permissions untouched.
Existing Keycloak26.7.3, Java17 and pinned CFT prerequisites were reused, never
installed. Binary hashes and exact commands:
[red-results.json](../../.scratch/chef-provider-boundaries-20261014/red-results.json).

- Full unchanged passkey lab rc1: real create/registration/human enable completed;
  get request4141… returned NativeMessaging `NOT_ALLOWED`. Own root
  `/var/tmp/pc-jojvc648/passkey-get-failure.json` records public attempt
  `e7c7d3e32f502742e952acb46a724631`, `FAILED/ADAPTER_UNAVAILABLE`.
  Its daemon stderr records the adapter failure. Cleanup also reports that
  diagnostic; it is not suppressed. [Log](../../.scratch/chef-provider-boundaries-20261014/red-passkey.log).
- Full unchanged token exchange lab rc1: ordinary start rc0, actual own
  pm-web-auth POST observed by controlled TLS destination. With only response
  held, SQLite timeout0 `BEGIN IMMEDIATE` reports `database is locked`, then
  public cancel returns `INTERNAL_ERROR/CUSTODY_UNAVAILABLE`.
  `/var/tmp/pc-xdzinsae/cancel-boundary.json` binds observation to attempt
  `dbb839df34a4f9aebb41274abdc545c4`. [Log](../../.scratch/chef-provider-boundaries-20261014/red-token-exchange.log).

## Ranked falsifiable hypotheses before edits

1. Generic claimant steals intrinsic created/waiting attempts. Discriminate by
   starting intrinsic before ordinary, checking selected attempt and unchanged
   intrinsic state, then completing the original intrinsic human ceremony.
2. SQL guard spans response wait. Discriminate with an installed adapter that
   acknowledges receipt but holds its response; an independent SQLite writer,
   public get/discover/cancel must proceed before release.
3. Browser/method rejection precedes worker. Falsified if the nearest claimant
   reproduces ownership theft without a browser, and the unchanged browser lab
   passes after only the claimant fix.
4. Another connection or settlement races cancel. Falsified if only moving the
   existing transport wait outside the guard admits the independent writer and
   late success leaves the durably cancelled attempt unchanged.

No parent artifact is counted as this writer's RED. Fixture-construction errors
(INVALID_ARGUMENT argument ordering and missing test imports) are retained but
are not product RED measurements.

## Root cause, change and acceptance boundary

Measured nearest RED:
[seam-red2.log](../../.scratch/chef-provider-boundaries-20261014/seam-red2.log)
reports `claim_next` returning the intrinsic attempt rather than the ordinary
one created afterwards. This reproduces ownership theft without browser/method
handling. It also reports emission allowed for an expired running lease and a
lease whose human-visible revision changed. The other two original seam tests
(cancellation versus late success, stale token after recovery) already passed.
The minimized installed transport
[seam-red3-boundary.log](../../.scratch/chef-provider-boundaries-20261014/seam-red3-boundary.log)
fails exactly at `response wait holds SQLite writer: database is locked`.
These are own measurements, not the foreign caller's reproductions.

Inferred from the final diff:

- `attempts.rs::claim` classifies `ExecutionOwner` from the AEAD-opened attempt
  snapshot before operational credential opening, state change, lease token or
  AuthUse audit. Only `vault-webauthn-provider` belongs to the intrinsic executor.
  Both created and reconciliation scans skip that owner, scan at most128 rows
  under the existing admission bound, and preserve their original ordering.
  Public claim method signatures remain; existing manual ordinary callers and
  `keycloak-webauthn` adapter processing remain supported. No passkey.rs edit.
- `linux.rs::run_provider_once` preserves the existing guarded integration set:
  `keycloak-token-exchange` and `github-rest-bearer`. Connection and protected
  request encoding precede the SQL guard. `ConnectedProviderRequest` contains
  either the explicit local outcome or the connected socket/protected frame;
  it is never persisted. After connecting, `with_authorized_provider_use`
  verifies exact running lease token/owner/item/revision, unexpired deadline,
  current grants/suspension/revocation and current visible revision in the
  immediate transaction. `emit_provider_request` revalidates pinned custody,
  registry/config selection and actual peer UID before writing that frame.
- The acceptance point is transmission of the authentication request/secret to
  the selected trusted adapter while that guard is held. Authority commits
  ordered before it prevent transmission. Once transmitted, cancellation is
  local; no external logout or rollback is claimed. This implements the
  existing [G4 acceptance contract](../design/agent-identity.md#6-revocación-carreras-y-errores).
- `PendingProviderResponse::Sent` owns only the already-issued socket.
  Response decoding and existing exact-token settlement run after the guard
  commits. A cancellation committed before settlement removes its running
  eligibility, so late success cannot replace CANCELLED. Partial write/read
  failure remains Indeterminate; a guard-release failure after a possible write
  also remains Indeterminate. Authority withdrawal during reconciliation now
  preserves an unknown external result rather than inventing terminal failure.
  No second authentication, provider fallback, retry or background queue added.

The visible-revision check fails closed on a stale grant after a human edit.
It does not implement or certify publication of replacement delegated grants by
`human.rs::prepare_edit_record`/`apply_staged`; that ownership is outside this
worker fix. No human/source-framework file was edited to make the test pass.
The direct old-revision emission is denied by the owned guard.

## GREEN and affected flows

Measured: the same first five Rust seam tests pass after the fix; the final
file adds four independent checks for emission serialization, pre-emission
AuthUse audit failure, pre-emission deferred-constraint commit failure and the
128-custodian admission bound. Fault injection is confined to each test's own
synthetic database, never product schema. The serialization test proves a
competing SQLite writer is blocked **inside** emission and available **after**
it, preventing a commit-before-callback regression. Nine seam tests pass,
including zero callbacks for suspension, revocation, disable, changed revision,
expired lease and stale token, intrinsic created/waiting/human completion,
CANCELLED versus late success, and unknown recovery without another initial use.

Measured: final unchanged labs and exact binary/source hashes are in
[verified-results.json](../../.scratch/chef-provider-boundaries-20261014/verified-results.json).
Each log below is a complete execution, with its own retained root:

- [Passkey](../../.scratch/chef-provider-boundaries-20261014/verified-passkey.log):
  real MV3/Native Messaging/RPK browser create, registration, human enable,
  UP/UV assertion, restart, replay, origin/document/extension/host rejection,
  revoke-before-sign and secret-canary assertions; rc0.
- [Token exchange](../../.scratch/chef-provider-boundaries-20261014/verified-token-exchange.log):
  real Keycloak26.7.3 exchange, own pm-web-auth TLS POST, actual held response,
  public cancellation, terminal CANCELLED after release, suspension before
  admission, reflection/redirect/audience and result-token controls; rc0.
  Its `cancel-boundary.json` records `write_transaction=available`.
- [Nearest installed transport](../../.scratch/chef-provider-boundaries-20261014/verified-boundary.log):
  independent SQLite writer admitted while response held, public start/status/
  discover live, cancel durably CANCELLED, late success consumed before the
  following request, cancelled state retained across restart, initial call
  count exactly1 per attempt and unknown result reconciled with opcode2 only;
  suspension produces zero additional calls; rc0.
- [Authorization](../../.scratch/chef-provider-boundaries-20261014/verified-authorization.log):
  installed ordinary A/B, shared enabled set, cross-RPK denial, hot human
  revocation, re-enrolment, suspension, restart and failed-commit controls; rc0.
- [Concurrency](../../.scratch/chef-provider-boundaries-20261014/verified-concurrency.log):
  ordinary daemon, TUI open, same process serving discovery, incomplete
  handshakes and limit4, strict created-resource cleanup; rc0.
- [Passkey login](../../.scratch/chef-provider-boundaries-20261014/verified-passkey-login.log):
  ordinary `keycloak-webauthn` adapter still performs real Keycloak login with
  the same vault key, human confirmation, challenge expiry and revocation;
  rc0. [Attempts](../../.scratch/chef-provider-boundaries-20261014/verified-attempts.log)
  preserves CLI/MCP, idempotency, pause/cancel/recovery and controlled response
  loss behavior; rc0. Controlled-adapter evidence is not external-provider
  acceptance.

Measured source package tests: custody lib/bin units each48 passed/1 ignored
in [short-temp run](../../.scratch/chef-provider-boundaries-20261014/affected-source-short-tmp.log).
The first run stopped later at a new fixture directory-name collision; it is
not reported as a successful command. The fixture now includes an atomic
counter. In [vault/web run](../../.scratch/chef-provider-boundaries-20261014/affected-source-final.log),
the Cargo test subcommand passed133 tests/1 ignored across21 result groups,
including `delegated_authorization`13 passed/1 subprocess-only ignored helper,
`passkey_provider`2 passed, the new9, and web-auth profile6 passed. The following
Clippy subcommand initially failed on line-count/doc formatting; those were
corrected. Final targeted Clippy and own product build both rc0:
[build2](../../.scratch/chef-provider-boundaries-20261014/targeted-final-build2.log).
These counts distinguish unit/subprocess exclusions from unrun native labs.

## Environment corrections and integrity

Measured: long TMPDIR caused an existing Unix-socket length assertion; no
product oracle changed. Rust tests now use own `/var/tmp/pb-affa6bd1`, with
large target data still in this worktree. The new test's parallel directory
collision was fixed with a unique atomic counter; no acceptance assertion was
removed. Initial minimized adapter mode0755 prevented its UID1 client from
connecting; the fixture's own socket now explicitly permits that client while
its parent remains protected. That construction failure is not a product RED.

Measured: first concurrency execution under Python directly as namespace PID1
passed discovery but failed strict tmux cleanup waiting for an exited PID.
A private namespace init now calls `waitpid(-1)` while the fixture runs, without
changing any caller. The unchanged concurrency fixture then passes; its
[reap ledger](../../.scratch/chef-provider-boundaries-20261014/verified-concurrency-reaped.jsonl)
records the adopted processes reaped before fixture exit. No deadline was
extended and no cleanup failure was ignored. Initial failing logs remain.

Measured: [caller-integrity.json](../../.scratch/chef-provider-boundaries-20261014/caller-integrity.json)
compares all eight migrated callers byte-for-byte against3b4dd416, including
original assertions and8/15/20/30s deadlines. Manifests, lockfile, native,
registry, CLI/frameworks, crypto, workflows, spec, tickets and foreign ledgers
are unchanged by the fix. Only the two owned production files, two new tests
and this new report are in the implementation commit.
[Candidate source digests](../../.scratch/chef-provider-boundaries-20261014/candidate-source-digests.json)
bind the exact source files to final check evidence.

## Inherited outcomes, coverage limits and handoff

Inferred, preserved: `serve_loop` skips recovery when its initial delegated
vault open fails; the5ms provider loop ignores `run_provider_once` errors;
connection handlers and the authority-error settlement path discard errors;
the bounded agent pool closes when full. Those conditions can hide the worker/
settlement cause from the loop, though durable attempt state remains the
observable authority. A late success after cancellation follows the existing
NotFound settlement error path, with CANCELLED retained. CLI UnavailableEngine,
environment and JSON behavior are inherited and untouched. Local routing
failure categories retain their existing bounded diagnostic slot. No new
provider selection fallback was introduced.

Inferred rather than fault-injected: a read-only emission-guard COMMIT failure
after actual transmission is mapped to Indeterminate. Pre-emission durable
claim COMMIT/audit failures were injected and measured; the post-transmission
COMMIT-failure branch was not forced through a custom VFS. Hot grant withdrawal
and real installed-caller revocation were measured; all native filesystem
replacement races at individual instructions were not exhaustively scheduled.
Other existing provider kinds retain their previous execution boundaries.

Status: scoped local fixes have measured RED→GREEN. Overall **ISSUES / partial
acceptance**: parent independent Claude review is still required; previous D1/D2
reviews are not reopened or credited to this diff. G7's staging-deletion RED
and decisions3/4 remain separate and open; the passing Rust prepared-stream
retry discriminator does not close the G7 lab conflict. NOT_RUN: native
Windows/macOS/other CPUs, native dispatch, reboot/FDE/human acceptance, real
credentials/providers, full52, clean rebuild/integrator run, installations,
release, CI, push/PR/publication. No ticket or product-ready claim.

All own logs, synthetic diagnostics, namespace roots, short temp databases and
target are retained. No foreign checkout/target/artifact was mutated or cleaned.
Principles: `design`, `small-owned`, `root-cause`, `prove`, `isolate`,
`no-fallbacks`, `truthful-state`, `evidence`, `owner-attention`, `handoff`.

## Final repository check

Measured: one execution only of `flock /tmp/pm-cargo-window.lock
./scripts/check.sh`, fixed toolchain homes/PATH, `RUSTUP_AUTO_INSTALL=0`, own
target and short explicit TMPDIR: **rc0**,98.05s including lock acquisition.
Config/build-input checks, workspace fmt/check/test/clippy all completed with
locked/offline Cargo. [Log](../../.scratch/chef-provider-boundaries-20261014/check.log)
SHA256 `0246b717461fcaccf1ee3e2109b6689eef71c83bb162e569f4a789dfb7f5bd41`;
[command/result and source digests](../../.scratch/chef-provider-boundaries-20261014/check-result.json).
Source and all caller digests were checked again after completion, unchanged.
This repository check is not the full52 native/process lab matrix and does not
close G7 or count the parent's independent review as performed.

Integration range: `ecced0d8af056826c780b2cfd2373f700ea9e7f3..HEAD` includes
the exact caller merge. Implementation-only range: `d97006b33a0bca58ca6d54dab9c9d73abb8a11a5..HEAD`;
the implementation commit has that merge as its sole parent. The final response
provides the immutable committed HEAD. The retained
[artifact manifest](../../.scratch/chef-provider-boundaries-20261014/artifact-manifest.json)
records final commands, roots, binary/source/log hashes and coverage state.
