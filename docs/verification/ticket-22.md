# Ticket 22 verification evidence

Date: 2026-09-13. Requirements: R06, R18, R19. Observed host: Linux
x86_64; Rust 1.98.1; libsodium 1.0.22; repository-pinned SQLite. Every
password, recovery key, item, RPK and canary was synthetic and disposable.

## TDD red/green

The root-path test was written before either rotation seam existed:

```text
./scripts/cargo-local.sh test -p pm-crypto --test root_rotation --locked --offline
# RED: E0599, UnlockedRoot had no rewrap_password or rotate_recovery
```

After adding typed rewrapping inside the existing crypto boundary, the same
test passed two cases. It independently opens the replacement bundle through
the new path, rejects the old current path, preserves the pinned human
authority and requires exact reintroduction of a newly generated recovery
code.

The public vault test was then written before recovery or signed rotation APIs
existed:

```text
./scripts/cargo-local.sh test -p pm-vault --test recovery_lifecycle --locked --offline
# RED: E0599 for prepare_native_recovery, prepare_master_password_rotation,
# begin_recovery_rotation and verify_current_recovery
```

The final focused runs were:

```text
./scripts/cargo-local.sh test -p pm-crypto --test root_rotation --locked --offline
# 2 passed; 0 failed

./scripts/cargo-local.sh test -p pm-vault --test recovery_lifecycle --locked --offline
# 3 passed; 0 failed
```

The vault tests cover clean recovery after deleting the entire source vault,
fresh destination vault/human roots, new item/revision/attachment IDs, an
existing destination with a live agent generation and a terminal revocation,
wrong recovery material, altered ciphertext, audit-write rollback and retry,
stale concurrent recovery rotation, durable receipt/state binding, old/new
password and recovery access, and old versus newly produced backups.

A replay assertion added at the public `HumanVault::commit`/`receipt` seam
initially failed for a root rotation with `Storage(InvalidQuery)`: the receipt
decoder still rejected the valid empty authority-head array used when a new
vault has no G5 head yet. Allowing zero current authority heads (while retaining
canonical CBOR and the 4096-head bound) made the first commit, repeated commit
and receipt lookup return byte-identical receipts.

## Recovery and rotation transaction

`HumanVault::prepare_native_recovery` reuses Ticket 21's one bounded PMB1/PMF1
parser and encrypted restore staging, selecting `BackupOpener::with_recovery`
rather than constructing a second archive engine. The source signing/device
private keys are absent. Destination `K_H`, `SK_H`, vault identity and device
custody already belong to the new healthy environment; every content key and
logical ID is generated anew. Historical identity/authority/audit records stay
imported history, while current `agent_authorizations`, revocations, authority
ledger and checkpoint remain the destination's state. The existing signed
`backup_restore` commit publishes staged graphs, current-device events, outbox,
encrypted audit and receipt atomically.

Fresh recovery does not overwrite a named previous vault. The destination is
first created through the existing no-clobber atomic creation path, which
verifies its new password and externally reintroduced recovery code; PMB1 is
then fully validated into encrypted staging and becomes visible only at the
signed SQLite commit. Existing-vault recovery is also an import-only commit.
Both modes therefore preserve any prior valid destination rather than exposing
incomplete staging after a crash or using a destructive replacement.

Password rotation derives a fresh Argon2id password key/salt and nonce and
rewraps the existing `K_H`; recovery rotation generates a fresh independent
`K_R`, requires the exact external representation to be reintroduced, then
authenticates the new envelope before staging. Both use the existing
prepare/sign/commit/receipt machinery. The root bundle hash is part of the
state view, so concurrent prepared mutations and a recovery rotation begun
against an older bundle cannot restore an obsolete path. Root bundle update,
encrypted `recovery` audit record, challenge consumption and receipt are one
SQLite transaction; the injected audit failure leaves the old root bundle and
challenge usable for a safe retry.

Current backups use the new current wrapper. Historical backups remain bound
to the password/recovery paths embedded when they were created: changing a
current wrapper neither erases nor remotely invalidates old copies. The public
human commands print that limit and also state that recovering data cannot
revoke provider credentials, offline devices or exposed copies.

Human opcodes are additive and coordinated with Tickets 11/13: 42 recovery
restore, 43 master-password rotation, 44 recovery-key rotation. They do not
collide with 31 (1PUX), 32--34 (backup), 35--37 (passkey), 40 (web) or 41
(Keycloak exchange). The agent opcode namespace remains separate.

## Real clean-environment human laboratory

```text
./scripts/test-linux-recovery-lab.sh
```

Observed result:

```text
PASS recovery-e2e tls=rpk+alpn/pm-human/1 clean-env=1 source-keyring=absent fresh-vault+human+device=1 all-types+history+attachments=restored authority+revocations=current wrong-key+corrupt=atomic master+recovery-rotation=verified signed+audit+receipt=1 restart=durable old-backups=remain-historical external-credentials+exposed-copies=not-revoked raw-canaries=absent
```

The multi-UID lab creates a source PMB1 containing all seven logical types,
history, trash and a >2 MiB streaming attachment. It copies only PMB1 and the
external `K_R`, stops the old daemon and deletes the complete old state,
profile and native key directory. A separately provisioned server RPK, human
RPK, fresh vault/human root and distinct device perform recovery through real
TLS 1.3 RPK/ALPN `pm-human/1`. The destination has two newly registered agents
and a known revocation before restore; those rows remain byte-for-byte equal.
Wrong/foreign recovery and a corrupted archive leave all durable counts
unchanged and the input backup hash unchanged.

Master and recovery rotations then travel through the same human TLS/UID
channel. The old password is rejected, the new password succeeds, the daemon
is restarted, current identity is unchanged, and the new path remains durable.
Both rotation commands repeat commit and fetch the durable receipt over that
same channel; all three receipt encodings are identical.
The lab scans custodian files for every password/recovery/canary and finds none
raw. No host configuration or persistent identity is changed.

## Repository gates and regression laboratories

```text
./scripts/check.sh
# pinned inputs, fmt, workspace/all-target check and tests, clippy: exit 0

./scripts/clean-offline-build.sh
# Removed 17832 files, 4.5GiB; locked/offline rebuild completed in 51.52s

set -euo pipefail
export PM_KEYCLOAK_DIST=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/keycloak/keycloak-26.7.3
export PM_CFT_DIR=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/cft/chrome-linux64
for lab in scripts/test-linux-*-lab.sh; do
  "$lab"
done
# all fifteen laboratories on the integrated branch: exit 0

git diff --check
# exit 0
```

The sorted laboratory run covers 1PUX, attempts, authorization, backup,
content, CSV, custody, history, human transaction, passkey, recovery, SSH,
sync, Keycloak token exchange and real Keycloak/CFT web authentication.
Pre-final aggregate runs exposed bounded-I/O
timing rather than a fallback: under accumulated memory-hard KDF load, content
unlock and Ticket 22 master rotation could exceed the original five-second
socket deadline and return `CUSTODY_UNAVAILABLE`. The product keeps a bounded
deadline but now allows 15 seconds for intentionally memory-hard human
operations. A Ticket 20 retry and one Ticket 08 reconciliation poll also failed
transiently in those diagnostic runs; focused reruns passed, and no Ticket
20/08 code was changed. During merger verification, the first aggregate run
also hit one transient Ticket 11 cancellation-start assertion after repeated
daemon restarts. The focused token-exchange lab and the subsequent complete
sorted run both passed without a code change. The final complete sorted run
above passed every lab, including the real restart/crash seams; earlier reds
are not treated as Ticket 22 success or silently omitted.

## Authorized fail-closed correction during integration

Pre-read found an existing fallback in `backup::current_frontier`: a present
authority-event digest with invalid length was silently replaced by the
all-zero sentinel reserved for a vault with no authority events. The owner
explicitly authorized correcting it during Ticket 22 integration. The function
now preserves the zero sentinel only for the valid empty-ledger case and
returns `HumanCommitError::Integrity` for malformed stored bytes.

The public backup seam has a regression in `recovery_lifecycle` which creates a
real authority event, injects a length-invalid digest through SQLite's explicit
test-only check-constraint override, and verifies that native backup returns
the integrity error rather than producing a zero-frontier archive. The focused
four-test recovery lifecycle run and the repository gate passed.

## Limits

Recovery cannot prove a backup is newest, erase historical/offline copies,
revoke credentials at external providers, or distinguish every machine that
may retain compromised authority. If all usable passwords/recovery keys and
backups are lost, there is no bypass. A suspected `SK_H`/`K_H` compromise
requires the demonstrated fresh lineage in a healthy environment, human
review of membership, explicit reprovisioning and external credential
rotation; this ticket does not claim omniscient revocation. Only Linux x86_64
was exercised here; the six-target native release gate remains later scope.

The separate merger integrated and verified the candidate. No push or formal
Astra review was performed; that review remains reserved for the final DAG
gate.
