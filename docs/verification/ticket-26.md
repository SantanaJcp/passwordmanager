# Ticket 26 verification method and checkpoint

Date: 2026-09-13. Requirements: R01, R02, R09, R10, R11. This document is
the written verification method for the macOS custody port. The current state
is an **implementation checkpoint, not native acceptance evidence**: this
Linux host cannot execute Darwin kernel, launchd, AppKit or ACL behavior.

## Native contract under test

The port keeps the existing vault engine, binary request framing, TLS 1.3 RPK
pinning and role-specific ALPN. macOS selects platform implementations only at
the existing boundaries:

- `getpeereid(2)` supplies the effective UID of the connected peer on both
  ends of the Unix stream. No request field supplies identity and an
  unimplemented target returns an explicit channel error.
- The custody process sets `RLIMIT_CORE` to zero before loading keys, uses a
  `077` umask and sets `SO_NOSIGPIPE` on connected/accepted Darwin sockets.
  Received descriptors get `FD_CLOEXEC` immediately because Darwin has no
  Linux `MSG_CMSG_CLOEXEC` path.
- Every writable vault connection enables and reads back SQLite `fullfsync`
  and `checkpoint_fullfsync`; a value other than one is an error. Linux keeps
  its existing durability configuration unchanged.
- The clipboard seam uses AppKit `NSPasteboard`, records its `changeCount`, and
  clears only if the same lease still owns the pasteboard. `/dev/tty` and
  `isatty` are tested as real native terminal primitives. No shell clipboard,
  OSC52, generic Unix peer stub or second vault engine is used.
- The shipped LaunchDaemon has a fixed `_passwordmanager` user/group, fixed
  root-owned program path, state/runtime paths, core limits and umask. It does
  not daemonize itself or accept identity through its request body.

Primary platform references used for these narrow primitives are Apple's
archived [`getpeereid(2)` manual](https://github.com/apple-oss-distributions/Libc/blob/main/gen/FreeBSD/getpeereid.3),
[`setrlimit(2)` manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/setrlimit.2.html),
[`launchd` job guidance](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html),
and current [`NSPasteboard`](https://developer.apple.com/documentation/appkit/nspasteboard)
documentation.

## Authorized ephemeral native method

The manual
[macOS custody acceptance workflow](../../.github/workflows/macos-custody-acceptance.yml)
orchestrates exactly the two standard runners `macos-15-intel` and `macos-15`.
It is prepared but has not been published or executed. Its only product entry
point is:

```text
PM_MACOS_EPHEMERAL_CI=1 ./scripts/test-macos-custody-lab.sh
```

Prerequisites are a fresh macOS 13-or-newer Intel or Apple-silicon CI runner,
the repository-pinned Rust 1.98.1 toolchain, Xcode command-line tools,
Python 3, a logged-in non-root console user, and passwordless `sudo`. The
runner must not already contain the three synthetic accounts or any of the
canonical product paths. A collision is a hard failure, never permission to
replace existing host state.

The workflow fixes `RUSTUP_AUTO_INSTALL=0` before every Rustup invocation and
installs only the exact fully qualified 1.98.1 host toolchain into
`<repo>/.toolchain`. It runs the environment preflight, fetches the locked
dependency graph in a separate network-enabled step, then invokes the product
laboratory whose build and tests are locked/offline. There is no dependency
cache or artifact upload and a preflight PASS cannot bypass a product failure.

The shell gate performs the locked/offline native build, native unit tests and
`plutil` validation. It requires each `pm`/`pm-custody` artifact to be a
single-architecture Mach-O exactly matching `uname -m`. Its Python harness then:

1. creates `_passwordmanager`, `_pmagent26` and `_pmother26` with unused real
   Darwin UIDs/groups;
2. installs a root-owned binary and plist, creates custody-owned state/runtime,
   generates only synthetic RPKs, and bootstraps a fresh synthetic vault;
3. bootstraps the LaunchDaemon in the system domain and proves its live PID is
   `_passwordmanager` running the installed, architecture-checked binary;
4. exercises successful agent and human TLS/RPK channels, then gives the wrong
   UID a correct copied synthetic agent key and requires kernel-peer rejection;
5. proves an agent UID cannot use the human endpoint, establishes authorization,
   suspends it, kills/restarts the real launchd job, and requires delegated
   discovery to remain denied;
6. runs the native clipboard ownership race, real `/dev/tty`/`isatty`, and
   zero-core-limit probe from the logged-in user session;
7. boots the job out and removes only the collision-checked paths/accounts it
   created, even on failure.

Success requires every assertion and command to exit zero and all four final `PASS`
lines to be present. A skip, cross-build, Linux execution, missing pasteboard
session, missing sudo privilege, pre-existing path/account, or cleanup failure
is not acceptance. The harness intentionally does not claim reboot, FileVault,
Intel+Apple-silicon coverage, signing, notarization or a human's daily machine;
those gates remain Tickets 31 and 34.

## TDD and current evidence

The intended red is the native test/laboratory run against the pre-port public
seams: Darwin `unix_peer_uid` returned the explicit unsupported error, the
custody binary returned `CUSTODY_UNAVAILABLE`, and `OwnedClipboard` did not
exist. It must be recorded on the native runner rather than inferred here.
The green is the exact same native test/laboratory command after this patch.
Until those two observed native records exist, the ticket must remain claimed.

The acceptance-workflow checker was written before the workflow existed:

```text
./scripts/verify-macos-custody-ci-config.sh
# RED exit 1: required macOS custody CI workflow was absent
```

After adding the workflow and architecture checks, the same checker must pass.
It verifies only the two standard macOS labels, manual trigger, read-only
permissions, fixed Node-24 checkout SHA, repository toolchain homes, exact
Rust install, ordered preflight/fetch/offline-lab phases, and absence of
secrets, cache, artifacts, paid runners, emulation and success substitution.

```text
./scripts/verify-macos-custody-ci-config.sh
./scripts/verify-native-ci-config.sh
# GREEN: exit 0

# PyYAML 6.0.3: jobs=1, targets=2, steps=5
./scripts/check.sh
# PASS after merging the CI remediation and adding the acceptance workflow
```

Observed on the Linux x86_64 development host:

```text
./scripts/cargo-local.sh check -p pm-native-channel -p pm-vault \
  -p pm-custody -p pm-web-auth -p pm-ssh-client --locked --offline
# PASS

./scripts/check.sh
# PASS: pinned inputs, fmt, workspace check/tests and clippy

./scripts/clean-offline-build.sh
# PASS: removed 17608 files / 5.1 GiB; locked offline rebuild 1m48s

python3 -m py_compile crates/pm-custody/tests/macos_lab.py
bash -n scripts/test-macos-custody-lab.sh
git diff --check
# PASS
```

The final sorted Linux regression run also passed all 17 current laboratories:

```text
export PM_KEYCLOAK_DIST=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/keycloak/keycloak-26.7.3
export PM_CFT_DIR=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/cft/chrome-linux64
for lab in $(find scripts -maxdepth 1 -name 'test-linux-*-lab.sh' | sort); do
  "$lab"
done
# LAB_COUNT=17 ALL_LABS_EXIT=0
```

This includes the real multi-UID Linux custody, all content/import/history,
authorization/attempt, backup/recovery, SSH, synchronization, GitHub bearer,
Keycloak exchange, passkey and CFT/Keycloak web laboratories. It establishes
that the Darwin cfg additions did not regress those existing Linux flows; it
does not establish macOS behavior.

An attempted `--target aarch64-apple-darwin` check failed before compiling the
project because that Rust standard-library target is not installed in the
pinned local toolchain. It is not counted as a behavioral red, a native build,
or macOS evidence. Linux repository gates and all current Linux laboratories
must also pass on the eventual integrated candidate; those preserve the
existing provider, backup, passkey, recovery, SSH and web flows but cannot
replace the native method above.

## Remaining acceptance work

- Execute the red record on the pre-port revision and the green record on both
  authorized ephemeral macOS architectures after the CI bootstrap is
  published.
- Record exact runner versions, command output and cleanup result here.
- Repeat the repository and Linux gates on the integrated candidate after the
  separate merger incorporates the native CI configuration.
- Have the separate merger integrate and verify before resolving Ticket 26.

No existing fallback was changed. The previously unsupported non-Linux path
failed explicitly; this patch replaces that explicit failure only for macOS
with native primitives. Other unimplemented targets continue to fail
explicitly.
