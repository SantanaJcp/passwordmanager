# Ticket 01 verification evidence

Date: 2026-09-12. Requirements: R01, R02, R20. Fixture data is explicitly
synthetic. Observed host: Linux 7.2.3-arch1-3 x86_64. Toolchain:
`rustc 1.98.1 (48a229cea 2026-09-01)` and
`cargo 1.98.1 (797e8a9bc 2026-08-05)`.

This evidence covers the ticket-01 bootstrap only. It does not certify the five
other native targets, product security, release readiness, or a final license
audit.

## TDD red/green

All commands ran in the ticket worktree using the repository-local toolchain.

1. Process runner red:
   `cargo test -p pm-process-runner --test process_runner --offline` failed with
   exit 101 because the tested public seam (`BuildIdentity`, `Canary`,
   `ProcessRequest`, and `run`) did not exist. Green: the same test passed after
   the minimal implementation.
2. Native version red:
   `cargo test -p pm-crypto --test linked_version --locked --offline` failed
   with exit 101 because `linked_libsodium_version` did not exist. Green: the
   same command passed and observed `1.0.22` from the linked C function.
3. CLI red:
   `cargo test -p pm-cli --test cli --locked --offline` launched the empty real
   binary but failed with exit 101 because stdout was empty. Green: the same
   command passed with `passwordmanager 0.1.0 (libsodium 1.0.22)` and exit 0.

The runner test launches `/bin/sh` as a real child in a unique 0700 temporary
directory. It retains exit code 23, failure status, build identity, stdout,
stderr, and the directory until evidence is dropped. Synthetic canaries are
observed independently in argv/stdout, argv/stderr, and argv/a temporary file.
Review regressions then went red before implementation for effective environment
replacement, forbidden ambient inheritance during canary tracking, bounded
output, timeout/process-tree termination, and a descendant retaining pipes after
its group leader exits; all seven runner tests are green.

## Reproducible-input and quality gates

The dependency fetch was explicit and separate from builds:

```text
./scripts/fetch-dependencies.sh
```

The clean build gate was then run with Cargo offline:

```text
./scripts/clean-offline-build.sh
LATEST.tar.gz: OK
LATEST.tar.gz.minisig: OK
Removed 3762 files, 312.2MiB total
Compiling libsodium-sys-stable v1.24.0
Finished dev profile ... in 12.47s
exit 0
```

The archive SHA-256 is
`b20a92e7ec25b285eafa349d721a5bb27e3a8ba94c0816630a127883f1d1b3ab`;
its internal `configure.ac` declares libsodium 1.0.22. The binding verifies the
committed minisign signature while compiling. `cargo tree -e features` showed
`libsodium-sys-stable v1.24.0` with no binding feature enabled, so
`fetch-latest` is absent. `nm -g target/debug/pm` contained the linked
`sodium_version_string` symbol; `ldd target/debug/pm` had no dynamic libsodium.

Final combined command:

```text
./scripts/check.sh
# SHA-256 checks: pass
# cargo fmt --all --check: pass
# cargo check --workspace --all-targets --locked --offline: pass
# cargo test --workspace --all-targets --locked --offline: 9 passed, 0 failed
# cargo clippy --workspace --all-targets --locked --offline: pass
exit 0
```
