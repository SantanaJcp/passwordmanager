# Reproducible build inputs

The workspace selects Rust 1.98.1 through `rust-toolchain.toml`, pins the Rust
package graph in `Cargo.lock`, and pins direct dependency versions in the root
manifest. `libsodium-sys-stable` 1.24.0 has default features disabled; in
particular, `fetch-latest` is forbidden.

The C archive named `LATEST.tar.gz` is committed because that filename is the
binding's interface. It is not floating: `SHA256SUMS` fixes its bytes and the
verification script checks that its internal `configure.ac` declares libsodium
1.0.22. `.cargo/config.toml` forces the binding to use that directory. Its build
script verifies the committed upstream minisign signature before compiling C.
It cannot silently fall back to an implicit C download while this setting is
present.

The repository-local toolchain lives in the main checkout, including when these
commands run from a worktree:

```sh
# The only networked dependency step; it never runs as part of build/check.
./scripts/fetch-dependencies.sh

# Verify hashes, lockfile, features, formatting, typecheck, tests, and lint offline.
./scripts/check.sh

# Demonstrate a clean build of every target in the workspace with network disabled.
./scripts/clean-offline-build.sh
```

This has only been observed on Linux x86_64. It does not certify the other five
native targets or constitute the final G8 artifact/license audit.
