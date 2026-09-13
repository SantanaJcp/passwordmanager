# Ticket 05 verification evidence

Date: 2026-09-13. Requirements: R03, R04, R05, R09. Observed host:
Linux x86_64, kernel 7.2.3; Rust 1.98.1; libsodium 1.0.22; bundled
SQLite. All values are visibly synthetic; no real credential was used.

## Public seam and TDD evidence

The public seam is `pm_vault::{LogicalRecord, AuthRecord, Attachment,
HumanVault, SearchQuery, GeneratorConfig, PasswordRng}` plus the existing
signed `prepare`/`commit`/receipt engine. Attachments use a new
`pm_crypto::FileCiphertext`: independent random `K_F`, PMF1 secretstream and a
`K_H` envelope bound to vault/file/revision. The logical codec is closed,
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
```

The corresponding green unit command passes four tests: exact seven-type
roundtrip, organization/search, configured generator plus injected RNG
failure, and staging/size-limit canaries. The attachment and source-field
assertions compare independent synthetic bytes, not values recomputed by the
implementation. Oversized title and declared file size are rejected; no unit
is truncated or committed.

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
`storage-only`. The harness scans SQLite, WAL and SHM while the service is
running for password/TOTP/SSH/token/attachment/source/search canaries. It does
not rely on direct `HumanVault` calls as a substitute for this composed path.

Observed green output:

```text
PASS uid_map='0       1000          1\n         1     100000      65535'
PASS custody_uid=1 human_uid=2 agent_uid=3
PASS bootstrap_sha256=b0e3e5ad105e39ba33ec45fda4a8d8e7b7c609641a71c1460d149e04108cfda6 restart=process tls=1.3 rpk=mutual alpn=role-specific
PASS human_crud=prepare-commit-receipt tls=1.3 rpk=mutual alpn=pm-human/1
PASS human_negatives=wrong-role,body-change,audit-failure atomicity=no-partial replay=receipt response-loss=recovered
PASS content=all-types+organization+generator tls=1.3 rpk=mutual alpn=pm-human/1
LIMIT reboot_host=NOT_RUN production_systemd_fde=NOT_RUN
```

Search deliberately decrypts human metadata in the authenticated human
session instead of persisting a plaintext or secret-derived index. Staging
contains only revision/file ciphertext packages. Generator failures return a
fixed error and no partial password, database write, log, stdout or stderr.

## Verification commands

```text
./scripts/cargo-local.sh test -p pm-vault --test content_records --locked --offline
# 4 passed; exit 0

./scripts/cargo-local.sh clippy --workspace --all-targets --locked --offline -- -D warnings
# exit 0

./scripts/clean-offline-build.sh
# pinned inputs and clean locked/offline workspace build passed; exit 0

./scripts/check.sh
# pinned inputs, fmt, workspace/all-target check, 30 tests and clippy passed; exit 0

./scripts/test-linux-custody-lab.sh
# ticket-03 native multi-UID/RPK laboratory passed; exit 0

./scripts/test-linux-human-transaction-lab.sh
# ticket-04 composed transaction laboratory remained green; exit 0

./scripts/test-linux-content-lab.sh
# all PASS lines above; exit 0
```

The normal ticket-04 command remains unchanged and does not opt into the new
content flow. Formal Astra review remains deferred until all tickets. This
evidence does not claim passkey/WebAuthn use, SSH/provider login, import,
history, sync, host reboot, systemd/FDE, non-Linux behavior, or ticket-06
audit query/purge.
