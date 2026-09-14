# Ticket 05 verification evidence

Date: 2026-09-12. Requirements: R03, R04, R05, R09. Observed host:
Linux x86_64, kernel 7.2.3; Rust 1.98.1; libsodium 1.0.22; bundled
SQLite. All values are visibly synthetic; no real credential was used.

## Public seam and TDD evidence

The public seam is `pm_vault::{LogicalRecord, AuthRecord, Attachment,
HumanVault, SearchQuery, GeneratorConfig, PasswordRng}` plus the existing
signed `prepare`/`commit`/receipt engine. Attachments use a new
`pm_crypto::FileCiphertext`: independent random `K_F`, PMF1 secretstream and a
`K_H` envelope bound to vault/file/revision. Files also expose a bounded
`FileSealer`/`FileOpener`: 1 MiB plaintext frames are encrypted directly into
SQLite staging and transported through human RPC opcodes 17/18 as 1 MiB
frames (leaving ticket-06 audit opcodes 14–16 intact), so neither endpoint nor
the transaction layer buffers the whole file. The logical codec is closed,
canonical CBOR. External unknown data has only the explicit encrypted
`source_fields` container.

Incremental red observations, before each production slice:

```text
./scripts/cargo-local.sh test -p pm-vault --test content_records --locked --offline
# exit 101: the logical types and HumanVault record seam did not exist.

./scripts/cargo-local.sh test -p pm-vault --test content_records \
  human_search_tag_and_favorite_use_complete_encrypted_records --locked --offline
# exit 101: SearchQuery, prepare_organize and search did not exist.

./scripts/cargo-local.sh test -p pm-vault --test content_records \
  configured_generator_uses_native_rng_and_fails_closed_when_rng_fails --locked --offline
# exit 101: GeneratorConfig and PasswordRng did not exist.

./scripts/test-linux-content-lab.sh
# exit 1: the real human process returned exit 2/INVALID_ARGUMENT because
# human-content-flow did not yet exist.

# Current process harness against the pre-streaming candidate 1f630869:
unshare ... python3 <current>/crates/pm-custody/tests/linux_lab.py \
  <detached-1f630869>/target/debug/pm-custody \
  <detached-1f630869>/target/debug/pm content
# exit 1: human-streaming-file returned exit 2 because the actual chunked
# process/RPC path did not exist. This was a detached, disposable worktree.
```

The corresponding green unit command passes five tests: exact seven-type
roundtrip, organization/search, configured generator plus injected RNG
failure, staging/size-limit canaries, and a 16 MiB + 4096 byte streamed
attachment. The streaming test uses generated readers/writers rather than a
whole-file `Vec`, verifies 16,781,312 exact bytes and digest after readback,
and observes 17 durable ciphertext rows whose maximum size is 1 MiB + 21
framing/authentication bytes. Short and overlong sources roll back all staging
rather than truncating to their declaration. The
attachment and source-field assertions compare independent synthetic bytes,
not values recomputed by the implementation. Oversized title and declared
file size are rejected; no unit is truncated or committed.

## Composed human-path observation

`scripts/test-linux-content-lab.sh` drives a real human process through the
ticket-03/ticket-04 path:

```text
human UID / SO_PEERCRED -> TLS 1.3 mutual RPK -> pm-human/1 ALPN ->
custodian RPC handler -> HumanVault signed transaction -> bundled SQLite
```

The client creates and reads password, TOTP, preserved passkey, SSH, token,
note and file records; compares Unicode attachment bytes and external unknown
fields exactly; then publishes a tag/favorite revision, searches it, and asks
the custodian generator for 96 uppercase-or-digit bytes. It never invokes a
passkey authentication operation: the passkey case is explicitly
`storage-only`. A second human RPC uploads and downloads 16 MiB + 4096 bytes in
17 frames through the same UID/TLS/RPK/ALPN route. It accepts the declared
16 GiB limit and rejects 16 GiB + 1 without allocating either size. It then
disconnects a short upload and, separately, kills the custodian while a 2 MiB
upload transaction has one 1 MiB frame staged; restart observes no staging or
partial publication and preserves the prior committed 17 chunks. The harness
scans SQLite, WAL and SHM while the service is running for all credential and
large-stream canaries. It does not rely on direct `HumanVault` calls as a
substitute for this composed path.

The harness requires the streaming child to emit exactly:

```text
PASS streaming-file bytes=16781312 chunks=17 max_plain_chunk=1048576 short-input=rolled-back limit-16gib=accepted oversize-16gib=rejected
```

Observed green output:

```text
PASS uid_map='0       1000          1\n         1     100000      65535'
PASS custody_uid=1 human_uid=2 agent_uid=3
PASS bootstrap_sha256=9bf2607c20b65e66fdc81d6dd213cbddcdffc7cdedb2307838e7cb0afb4d84e7 restart=process tls=1.3 rpk=mutual alpn=role-specific
PASS human_crud=prepare-commit-receipt tls=1.3 rpk=mutual alpn=pm-human/1
PASS human_negatives=wrong-role,body-change,audit-failure atomicity=no-partial replay=receipt response-loss=recovered
PASS content=all-types+organization+generator+streaming-file stream-crash=rolled-back tls=1.3 rpk=mutual alpn=pm-human/1
PASS audit=encrypted,signed,segmented,query,purge autonomous_without_kh=device-custody human_path=mutual-tls-rpk
LIMIT reboot_host=NOT_RUN production_systemd_fde=NOT_RUN
```

Search deliberately decrypts human metadata in the authenticated human
session instead of persisting a plaintext or secret-derived index. Staging
contains only revision/file ciphertext packages. Generator failures return a
fixed error and no partial password, database write, log, stdout or stderr.

## Verification commands

```text
./scripts/cargo-local.sh test -p pm-vault --test content_records --locked --offline
# 5 passed; exit 0

./scripts/cargo-local.sh clippy --workspace --all-targets --locked --offline -- -D warnings
# exit 0

./scripts/clean-offline-build.sh
# pinned inputs and clean locked/offline workspace build passed; exit 0

./scripts/check.sh
# pinned inputs, fmt, workspace/all-target check, 37 tests and clippy passed; exit 0

./scripts/test-linux-custody-lab.sh
# ticket-03 native multi-UID/RPK laboratory passed; exit 0

./scripts/test-linux-human-transaction-lab.sh
# ticket-04 composed transaction laboratory remained green; exit 0

./scripts/test-linux-content-lab.sh
# all PASS lines above; 16 MiB + 4096 exact transfer, short/error rollback,
# real mid-transaction SIGKILL/restart rollback, and declared 16 GiB boundary;
# exit 0
```

The corrector `9ea748aef95ca0e0c1fa1f0e5223c8e0f1468789` was integrated as
`d7f0389`. The normal ticket-04 command remains unchanged and does not opt
into the new content flow; it passed independently, as did the ticket-03
custody lab and all six ticket-06 audit lifecycle tests. The merge preserves
audit opcodes 14–16 and uses 17–18 only for streaming. Formal Astra review
remains deferred until all tickets. This evidence does not claim
passkey/WebAuthn use, SSH/provider login, import, history, sync, host reboot,
systemd/FDE or non-Linux behavior.
