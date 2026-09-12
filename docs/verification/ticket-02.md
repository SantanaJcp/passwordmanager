# Ticket 02 verification evidence

Date: 2026-09-12. Requirements: R01, R04, R09, R15, R18. Every password,
plaintext, ID pattern and payload in tests is explicitly synthetic. Observed
host: Linux x86_64; Rust 1.98.1, libsodium 1.0.22, minicbor 2.3.0, rusqlite
0.40.2 with bundled SQLite.

This evidence covers the ticket-02 G2 foundation and format vectors only. It
does not claim operational CRUD/authority/reducer/backup flows, native custody,
other target support, or independent cryptographic review.

## TDD red/green

Commands ran in the isolated ticket worktree with the repository toolchain.
The recorded reds below were missing behavior at the tested public seam, not
dependency or environment setup failures.

1. Human-root seam red:
   `./scripts/cargo-local.sh test -p pm-crypto --test root_bundle --locked --offline`
   exited 101 because `KdfProfile`, `RootBundle`, recovery and create/open APIs
   did not exist. Green: the same command passed; the final file has three tests
   for both root paths, pinned PK_H, exact KDF limits, canonical bytes, typed
   purposes/full AAD, wrong password, incompatible version and alteration.
2. Atomic persistence seam red:
   `./scripts/cargo-local.sh test -p pm-vault --test local_vault --locked --offline`
   exited 101 solely because `PendingVault` and `open_vault` did not exist.
   Green: the same command passed; the final file has three tests for WAL/FULL,
   encrypted-root-only object storage, read-only reopening, recovery
   confirmation, no replacement, and byte conservation on every rejected open.
3. Real CLI seam red:
   `./scripts/cargo-local.sh test -p pm-cli --test vault_cli --locked --offline`
   launched the real binary and exited 101 at the assertion because stdout was
   empty instead of the password prompt. Green: the same command passed with
   interactive recovery reintroduction followed by a distinct open process.
4. Revision package seam red:
   `./scripts/cargo-local.sh test -p pm-crypto --test revision_package --locked --offline`
   exited 101 because the package types and seal/open methods did not exist.
   Green: two tests passed for independently keyed human/auth parts, encrypted
   manifest, distinct external K_C envelopes, exact hashes/lengths, no
   self-reference, cross-purpose substitution, partial/tampered/trailing bytes.
5. PMF1 vector seam red:
   `./scripts/cargo-local.sh test -p pm-crypto --test pmf1 --locked --offline`
   exited 101 because `Pmf1Vector` did not exist. Green: two tests passed for
   empty FINAL, multi-chunk framing and rejection of tamper, truncation,
   trailing bytes and frame reordering.
6. Grant construction seam red:
   `./scripts/cargo-local.sh test -p pm-crypto --test grant_vector --locked --offline`
   exited 101 because device/grant vector types and prepare/finish methods did
   not exist. Green: one test passed for sealed K_A context, commitment over G
   without `authority_event`, event insertion, final domain-separated Ed25519
   signature under pinned PK_H, and alteration rejection.

## Observable storage and process checks

- `pm vault create PATH` reads password/confirmation only from stdin, generates
  K_H/K_R/SK_H independently, prints the human recovery representation, and
  publishes no file until the exact checksum-protected code is reintroduced.
- Publication writes a 0600 same-directory temporary SQLite file, uses
  `journal_mode=WAL` and `synchronous=FULL`, checkpoints/fsyncs it, then uses an
  atomic non-overwriting hard link. Existing targets are conserved.
- `pm vault open PATH` uses read-only/query-only SQLite and rejects public
  version/suite and bounded lengths before Argon2id. Tests compare exact file
  bytes before/after wrong password, incompatible version, altered ciphertext,
  and a second create.
- SQLite receives public trusted-root metadata plus one canonical root bundle;
  all K_H, K_R and SK_H bytes are inside XChaCha20-Poly1305 envelopes before the
  persistence API sees them. Tests inspect table cardinality/types and confirm
  synthetic password/recovery text does not occur in the stored object.

## Final quality gate

```text
./scripts/check.sh
# pinned libsodium archive/signature: pass
# cargo fmt --all --check: pass
# cargo check --workspace --all-targets --locked --offline: pass
# cargo test --workspace --all-targets --locked --offline: pass
# cargo clippy --workspace --all-targets --locked --offline: pass
```

The selected creation KDF is Argon2id v1.3, 256 MiB, three passes and implicit
libsodium lane count one. Lower accepted profiles exist only through an API
named `confirmed`; tests use 64 MiB to bound runtime. No test/profile result is
a latency claim for the other five native targets.
