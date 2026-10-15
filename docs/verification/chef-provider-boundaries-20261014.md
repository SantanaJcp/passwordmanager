# Provider worker boundaries — 2026-10-14

## r2 data shape — enabled human edits and retained attempts

This is a bounded implementation follow-up to parent
`899890f72be093b1d1be94fd65cce55aee9edb47`, in branch
`t3/fix-provider-worker-boundaries`, worktree
`/home/santana/.t3/worktrees/passwordmanager/t3-affa6bd1`.
The historical 899 report below is retained verbatim. This section supersedes
its treatment of an ordinary edit as a withdrawal and its replacement-grant
limitation. It does not supersede historical measurements with new acceptance.

Inferred from the corrective source: an edit of an already-enabled item is one
complete content revision plus one authenticated replacement provision for the
same enabled common set, within one SQLite human transaction and one replayable
receipt. Both effects use existing signed authority-event and event-manifest
encodings. The prepared body binds both effects and the complete content object
digest. No new persisted fields, schema, wire version, key format, recipients,
generation, auth scope, or durable-prepared representation is introduced.

Execution still has intrinsic versus ordinary owners. For ordinary workers,
connection precedes the protected authorized-emission phase; result waiting and
exact-token settlement follow guard release. Those transport functions are
byte-identical to 899 in this follow-up. A private in-memory lease fingerprint
records relevant authenticated causal withdrawals. Current native/config/RPK,
identity, grants, current coherent provision, exact token and deadline checks
still apply at emission. No unconditional removal of the revision guard.

A materialized lease holds its original authenticated revision and material.
A content edit alone permits that lease to finish while valid; disable,
disable/re-enable, suspend/resume, revoke or retirement cannot revive it through
this fingerprint. Query recovery keeps the sealed attempt ID, owner, revision,
destination and context and opens **no** new credential plaintext. An initial
Created row whose old provision was replaced before any lease/material was
issued cannot be rebound to the new revision: it becomes explicit
FAILED/CREDENTIAL_UNAVAILABLE with an AuthState audit and no AuthUse/emission.
This narrowly handles known-unsent superseded work without blocking fresh work;
it does not terminalize an unknown external result or provide history access.

## r2 authorization, trace and discriminating hypotheses

Local implementation authorization expressly extends the human/authorization
seam for these two accepted P1s. No owner decisions3/4 were inferred. Skills
chef-mode/PRINCIPLES, feature-xray and find-the-cause, project context/decisions,
spec §15, key-hierarchy §4, synchronization §9.2, agent-identity G3/G4 and
existing delegated authorization tests informed the trace. No agent was
spawned, no review authored and no remaining review budget spent.

Ranked falsifiable causes traced before product correction:

1. Human edit changes only visible content while the enabled provision remains
   old. Discriminator: enable → genuine organize commit → NEW start/claim/use;
   compare visible revision, grant, discovery and emitted revision.
2. Unknown reconciliation reuses the old grant and hits the new guard instead
   of querying. Discriminator: one initial authentication → unknown → genuine
   edit → finite opcode/audit/connection observation and legitimate query result.
3. Edits are causal withdrawals that should invalidate all old leases.
   Discriminator: compare normal organization/rotation against signed disable
   and disable/re-enable on a previously materialized lease. Contract and tests
   reject this hypothesis for a plain edit.
4. Query recovery requires a fresh credential opening. Discriminator: require
   empty authentication fields and original pinned request metadata, then
   resolve through opcode2 with exactly one original opcode4 authentication.

The source trace confirmed hypotheses1/2 and rejected3/4. Existing
`commit_restore` demonstrated multi-event human receipts; restore was not
changed. Fresh enable and enabled-edit publication share the original
control-package/grant primitives. `publish_edited_provision` validates the old
signed provision before mutation, opens the complete new revision within the
transaction, generates fresh envelopes, updates only the existing enabled row,
and publishes existing item-revision + enable authority/outbox events. Failed
grant publication rolls all effects and the receipt back. Current expected
state, challenge, body and signature checks precede those effects.

## r2 own 899 RED and same corrective GREEN

Measured baseline and original byte snapshots:
[baseline.json](../../.scratch/chef-provider-boundaries-r2-20261014/baseline.json),
[original sources/tests/report](../../.scratch/chef-provider-boundaries-r2-20261014/original/).
No foreign target, executable or modified caller was used. All builds/labs use
one blocking `/tmp/pm-cargo-window.lock`, fixed repository toolchain homes/PATH,
`RUSTUP_AUTO_INSTALL=0`, locked/offline Cargo, fresh owned `target-provider-r2`,
and explicit short TMPDIR. Namespace labs use unchanged strict root UID0,
separate actual subordinate native identities, original installed registry and
real human/browser channels outside custody. Existing Keycloak/Java/CFT were
reused; nothing was installed/downloaded. Namespace PID1 reaps adopted children;
original strict cleanup assertions and deadlines remain unchanged.

Measured RED on 899 production, before correction:

- The two new F1/F2 Rust tests failed with `CredentialUnavailable`:
  [red-rust.log](../../.scratch/chef-provider-boundaries-r2-20261014/red-rust.log).
- Genuine installed human organize/commit → NEW start failed to produce the
  expected adapter opcode4 within the unchanged20s predicate bound:
  [red-worker-edit-new.log](../../.scratch/chef-provider-boundaries-r2-20261014/red-worker-edit-new.log),
  root `/var/tmp/pc-917khctd`.
- Genuine installed unknown → human rotation → finite1.2s recovery observation:
  **audit26→48 (+22),17 connections,1 original authentication,0 post-edit
  queries,INDETERMINATE**. The legitimate-result assertion failed:
  [red-cause-edit-unknown.log](../../.scratch/chef-provider-boundaries-r2-20261014/red-cause-edit-unknown.log),
  root `/var/tmp/pc-g4tkd54y`. The reviewer estimate of1.7M/day is not a measured
  result and is not extrapolated here.

Measured corrective GREEN, same F1/F2 public paths and assertions:

- [final-edit-new.log](../../.scratch/chef-provider-boundaries-r2-20261014/final-edit-new.log):
  organize, title and actual secret rotation each permit a NEW ordinary
  opcode4 request. Captured SHA256 fields equal the independently specified
  new synthetic subject/requester values after rotation. Real human wire
  prepare/commit/receipt replay used; helper never mutates SQL or manufactures
  trust. Root `/var/tmp/pc-2hohy0sw` retains per-edit receipt digests and requests.
- [final-edit-unknown.log](../../.scratch/chef-provider-boundaries-r2-20261014/final-edit-unknown.log):
  **audit22→26 (+4),6 connections,1 original authentication,2 post-edit opcode2
  queries,FAILED via actual provider AUTH_REJECTED**. Query revision remains
  the original revision. The adapter returns unknown on the first post-marker
  query and a legitimate result only on the second, excluding a single
  pre-edit in-flight query as a false GREEN. Root `/var/tmp/pc-ry_csf0k`.
- [affected-final2.log](../../.scratch/chef-provider-boundaries-r2-20261014/affected-final2.log):
  all23 boundary tests pass, including the same original F1/F2 tests. Entire
  affected pm-vault/pm-custody/pm-web-auth all-targets command rc0:
  **251 passed,0 failed,3 ignored across29 result groups**. Existing
  delegated_authorization, human transactions/content/history, passkey provider,
  token material and web profile checks are included.

The unchanged core commands are `bash .scratch/chef-provider-boundaries-r2-20261014/cargo.sh
test -p pm-vault --test chef_provider_boundary` (the first RED filters `r2_`),
and `python3 .scratch/chef-provider-boundaries-r2-20261014/run_labs.py PHASE
edit-new edit-unknown`. Phase only names evidence output. The worker tests use
the same substantive oracles; subsequent corpus adds genuine pinned-but-unenrolled
migration denial and human receipt capture. Exact command arrays, binary hashes
and source hashes are in each phase's results JSON and the final manifest.

## r2 transaction and boundary controls

Measured in the23 boundary cases:

- Injected existing-grant UPDATE failure rolls back new visible content,
  provision, both authority events and receipt; the same signed transaction
  retries successfully with two events/one receipt, then replays identically.
- Tampered staging is rejected. Edit staged before disable/suspend/revoke/trash
  cannot commit over the withdrawal; editing an already-disabled item does not
  enable it. Newly prepared edits after suspension/revocation retain their
  denial. No recipients or generations are added.
- An old materialized lease retains old material across organization and secret
  rotation while new starts use new material. Subsequent disable/re-enable
  rejects that old lease. Real withdrawals before emission yield zero callback
  calls; expired and stale-token guards remain denied.
- Query-only authorization verifies signed current provision and revision
  metadata without opening authentication plaintext. SQL metadata altered to
  disagree with the signed provision produces Integrity; the unknown result
  remains unknown.
- A genuinely withdrawn oldest unknown for one enrolled RPK is skipped without
  claim/audit, allowing another enrolled RPK's query. Unexpected errors still
  propagate. This is a vault claimant test, not worker race injection.
- **127 genuine intrinsic passkey rows +1 ordinary** with eight explicitly
  enrolled peers respect16/agent and128/custodian. Only the ordinary row is
  leased; all127 intrinsic rows stay Created. The old128 test had no intrinsic
  rows and is now honestly named for its ordinary-only coverage.

The original899 revision-as-withdrawal case is retained in the immutable
original test snapshot. Its oracle was wrong under the confirmed edit contract:
this corrective file separates positive normal edits from genuine withdrawals.
No historical caller or original52 assertion was relaxed. Initial fixture/helper
construction errors and an error-category regression caught by the unchanged
delegated authorization test are retained in failed logs; the latter was fixed
by restoring `prepare_enable`'s original CredentialUnavailable rejection for a
non-delegable note. None is counted as product RED or a successful test run.

The Python independent-writer proof now waits for a successful timeout0
BEGIN IMMEDIATE predicate within the existing20s bound. An adapter event alone
can precede guard release and is not claimed as proof. It does not add a busy
retry to production. The added corpus also rejects a genuinely native-bound,
pinned-but-unenrolled RPK at installed registry migration; bootstrap bytes are
unchanged and no registry is created. This supplements immutable migrated
caller negatives without editing their source.

## r2 full flow checks, footprint and limitations

Measured: all nine final namespace lab executions rc0, each with own binaries
from `target-provider-r2/debug` and unchanged source during execution:
[final-results.json](../../.scratch/chef-provider-boundaries-r2-20261014/final-results.json).
The full immutable [passkey](../../.scratch/chef-provider-boundaries-r2-20261014/final-passkey.log)
and [token-exchange](../../.scratch/chef-provider-boundaries-r2-20261014/final-token-exchange.log)
labs retain their original assertions and deadlines. Actual browser create,
registration, human enable/UP/UV, intrinsic assertion/restart/revocation and
actual Keycloak exchange/own pm-web-auth TLS POST/cancel controls pass.
[Boundary](../../.scratch/chef-provider-boundaries-r2-20261014/final-boundary.log)
proves real writer availability, status/discovery, durable cancellation before
release, late success still CANCELLED, restart and opcode2-only unknown recovery.
[Authorization](../../.scratch/chef-provider-boundaries-r2-20261014/final-authorization.log),
[concurrency](../../.scratch/chef-provider-boundaries-r2-20261014/final-concurrency.log),
[passkey-login](../../.scratch/chef-provider-boundaries-r2-20261014/final-passkey-login.log)
and [attempts](../../.scratch/chef-provider-boundaries-r2-20261014/final-attempts.log)
also pass. This includes hot-revoked identities, limit4, human open, strict
cleanup, public cancel/status and one-call crash/restart ambiguity. These are
controlled installed/laboratory paths, not native/formal acceptance.

The23 boundary tests and251 affected package tests are measured separately from
those nine process labs; they are not an original52 matrix run. Per-edit human
transaction IDs/receipt digests and artifact hashes are retained in
[edit-new receipt manifest](../../.scratch/chef-provider-boundaries-r2-20261014/final-edit-new-receipts.json)
and [edit-unknown receipt manifest](../../.scratch/chef-provider-boundaries-r2-20261014/final-edit-unknown-receipts.json).

Inferred footprint: human.rs supplies atomic complete enabled edits;
authorization.rs reuses signed provision verification and supplies metadata-only
attempt authorization; attempts.rs separates fresh material from query-only
leases and checks causal withdrawals. Existing two boundary test files extend
the corpus; the new `pm-custody/examples/chef_human_enabled_edit.rs` is a narrow
synthetic client for existing authenticated human operations. This report is
the seventh authored path. linux.rs, passkey.rs, all eight3b callers, manifests,
lockfile, crypto, native, registry wire, CLI/frameworks, restore semantics, sync,
workflows, spec/tickets and foreign ledgers remain unchanged in this follow-up.

Measured byte comparison and all final source/log/binary digests:
[final-source-evidence.json](../../.scratch/chef-provider-boundaries-r2-20261014/final-source-evidence.json).
Commands/roots/log hashes and human receipt artifacts are retained under own
[private evidence](../../.scratch/chef-provider-boundaries-r2-20261014/).
No original target, untracked evidence or foreign artifact was removed.

Status: **F1/F2 scoped local implementation GREEN; overall ISSUES / partial
verification**, with no reviewer acceptance claimed. Accepted are the two
source-inferred P1s, now independently reproduced and corrected. Rejected are
unconditional visible-guard removal, disable/re-enable as user recovery,
configured-but-unusable success, suppressing audit/errors, and invented terminal
unknown outcomes. Parent's one bounded R2 on these repros remains unused.

Measured finite corpus still OPEN: expiry between claim and guard rejects
emission, leaves Running until a status poll, and recovery can call it unknown.
No status poll was used to hide this case. The new finite test records it;
no unrelated state cleanup is claimed. Inferred coverage limits: worker
post-write guard-release COMMIT fault and withdrawal precisely between a real
worker reconciliation claim and emission were not injected. Vault-level
withdrawal/fairness controls are narrower evidence. Causal withdrawal digest
verification scans retained relevant signed event history; no performance or
retention certification is claimed. Unknown withdrawn work remains unknown
without new login or fabricated acknowledgement.

Inherited fallbacks remain unchanged: startup vault-open failure skips recovery;
provider/handler/settlement errors can be discarded by their existing outer
loops; pool-full closes connections; CLI environment/JSON/UnavailableEngine
behavior is inherited. Activation and hidden outcome are described in the899
report below. No new fallback or external session management was added.

NOT_RUN: native dispatch/Windows/macOS/other CPUs, native CI, reboot/FDE/human
formal acceptance, G7 staging deletion/representation acceptance, full52/full
clean/integrator composition, installation/release/publication and real
credentials. Decisions3/4 remain unanswered and do not block this reversible
local correction. No ticket closure or product-ready claim.

FINAL_CHECK_RESULTS

---

## Historical 899 report — preserved verbatim below

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
