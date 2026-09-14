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
It was published as workflow-only bootstrap `c4e8779` and its first product
run is recorded below. Its only product entry point is:

```text
PM_MACOS_EPHEMERAL_CI=1 ./scripts/test-macos-custody-lab.sh
```

Prerequisites are a fresh macOS 13-or-newer Intel or Apple-silicon CI runner,
the repository-pinned Rust 1.98.1 toolchain, Xcode command-line tools,
Python 3, a logged-in non-root console user, and passwordless `sudo`. The
runner must not already contain the three synthetic accounts or any of the
canonical product paths. The only fixture root is the fixed
`/private/var/tmp/passwordmanager-ticket26`; its parent must be root-owned mode
`01777`. A missing/mismatched parent or fixture collision is a hard failure,
never permission to select another path or replace existing host state.

The workflow fixes `RUSTUP_AUTO_INSTALL=0` before every Rustup invocation and
installs only the exact fully qualified 1.98.1 host toolchain into
`<repo>/.toolchain`. It runs the environment preflight, fetches the locked
dependency graph in a separate network-enabled step, then invokes the product
laboratory whose build and tests are locked/offline. There is no dependency
cache or artifact upload and a preflight PASS cannot bypass a product failure.

The shell gate performs the locked/offline native build, native unit tests and
`plutil` validation. It requires each `pm`/`pm-custody` artifact to be a
single-architecture Mach-O exactly matching `uname -m`. Its Python harness then:

1. creates the collision-guarded, runner-owned `0711` fixture root, then
   `_passwordmanager`, `_pmagent26` and
   `_pmother26` with unused real Darwin UIDs/groups; its private per-identity
   directories remain `0700`, bilateral denial is probed, and only synthetic
   public RPKs are copied into a root-owned `0444` publication directory;
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

The first native product run
[`34763192705`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34763192705)
on checkpoint `3409f5b` is an observed **RED** on both `macos-15-intel` and
`macos-15`. Environment validation, the locked dependency fetch and the
native libsodium build advanced successfully, but `pm-vault` failed to compile
before any product assertion ran. Darwin exposes `statvfs.f_bavail` as `u32`
while `f_frsize` is `u64`, and exposes `S_IFMT`, `S_IFREG` and `S_IFDIR` as
`u16` while ZIP modes are `u32`. The six compiler errors were the same width
mismatches on both architectures. This is real native compile evidence, not
custody behavioral evidence and not acceptance. The focused repair converts
both platform values into their protocol-sized unsigned type with checked
conversions, rejects multiplication overflow explicitly, and keeps rejecting
non-regular/non-directory ZIP entry kinds. Both native targets must rerun the
unchanged product entry point before any GREEN claim.

The second native product run
[`34763755579`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34763755579)
on checkpoint `7f63429` is a further observed **RED** on both targets. The
portable 1PUX repair compiled, exposing the next Darwin boundary in the shared
human import transport: Darwin represents `msghdr.msg_controllen` and
`cmsghdr.cmsg_len` as `u32`, whereas Linux represents them as `usize`. Both
jobs stopped at the same checked ancillary-message code in `pm-custody` before
the native custody assertions ran. The repair now converts the send and
receive control lengths to each platform field type through checked generic
boundaries, validates returned header and payload lengths before indexing,
rejects truncated, malformed, additional or multiple-descriptor messages, and
owns every received descriptor before later validation so every failure path
closes it. This remains native compile evidence only; another two-target run
of the unchanged entry point is required.

The third native product run
[`34764564812`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34764564812)
on checkpoint `45af206` compiled the product and native tests successfully on
both targets, including the AppKit/getpeereid and fullfsync tests, and verified
single-architecture `arm64` and `x86_64` Mach-O artifacts. Both jobs then
failed before service bootstrap when `_pmagent26` key generation returned the
explicit unavailable status. Inspection of the exact fixture construction
identified the cause: the runner-owned `pm-ticket26` parent was created mode
`0700`, so the real agent UID could not traverse to its own `0700` child.
Captured stdout/stderr were hidden by `check=True`, and the later bootstrap
and authorization steps would also have crossed private `0700` directories to
read public RPKs. Checkpoint `8b54d20` made synthetic keygen failures report
bounded return-code/stdout/stderr metadata, required `RUNNER_TEMP` without a
substitute path, used a `0711` collision-guarded fixture root, proved private
subdirectory denials, published only public RPKs through a root-owned `0444`
area, and obtained privileged metadata through the administrative test
observer. It did not broaden a private directory or change the runner parent.
That remained a runtime fixture RED, not native acceptance.

The fourth native product run
[`34765246514`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34765246514)
on checkpoint `8b54d20` is **RED** on both targets for two distinct reasons.
Both CPUs again compiled the native binaries and ran exactly nine applicable
native tests: one `pm-native-channel` test, five `pm-vault` unit tests and the
three macOS-applicable `local_vault` tests. The other workspace integration
executables reported zero tests because their cases remain Linux-gated, so
this is not a full native workspace suite. Both jobs also verified the
matching single-architecture Mach-O artifacts.

On Apple silicon, the new prerequisite probe established that
`/Users/runner/work/_temp` itself is not traversable by `_passwordmanager`.
The laboratory stopped there before product setup, exactly as required; it
did not modify the runner-owned parent. The user subsequently authorized the
single fixed `/private/var/tmp/passwordmanager-ticket26` replacement described
by the method above, with no alternate path or parent permission change.

On Intel, the parent traversal probes passed and the fixture advanced through
synthetic key generation, public-RPK publication, bootstrap/vault creation,
launchd bootstrap, live process user/command checks and the protected-file
metadata checks. The first real agent probe then received the explicit
`CUSTODY_UNAVAILABLE` result. Read-only inspection bounds the failure to the
probe's profile/key validation, Unix connection/configuration, cross-UID
`getpeereid` comparison, or TLS-RPK/ALPN exchange. The profile is created by
the root provisioner as mode `0444`; the agent key is created by the real
agent UID under its own `0700` directory; the server profile and bootstrap
derive from the same server RPK; and the published agent RPK is byte-compared
with its private key's public companion before bootstrap provisioning. Those
facts make an obvious path or trust-input divergence less likely, but the
opaque failure does not prove which remaining boundary failed. The successful
same-UID socket-pair `getpeereid` unit test does not establish the cross-UID
launchd case. No product dispatch, native primitive, or verification method
was changed on the basis of this uncertainty.

Before repeating the first agent probe, the harness now verifies only safe
fixture metadata and kernel identity observations: exact owner/mode for the
root-owned profile and public RPK, agent-owned private-key path and
custodian-owned socket; the numeric UID actually selected by `sudo`; bilateral
cross-UID `getpeereid` on a synthetic Unix pair; and the agent-side peer UID on
the real launchd socket. Diagnostics contain only synthetic account names,
numeric UIDs, modes, return codes and bounded stdout/stderr. They never read or
print private-key bytes, and the public `probe` failure remains exactly
`CUSTODY_UNAVAILABLE`.

The next diagnostic checkpoint keeps that public failure contract unchanged.
Before the first probe, the harness must additionally verify the complete safe
metadata tuple (type, owner, permission bits, link count and byte count), path
traversal and effective readability of the agent profile and private-key file
under the real agent UID. If those gates pass, the native binary is built with
the explicit `macos-ticket26-diagnostics` laboratory-only feature. That feature
is inert unless the fixture supplies the exact
`PM_MACOS_TICKET26_DIAGNOSTIC=1` opt-in. It may emit only fixed phase codes for
process hardening, profile/key parsing, Unix connect/configuration, bilateral
peer UID, TLS 1.3 handshake, pinned RPK, ALPN and READY; it must not emit key or
profile bytes, dynamic paths, credentials or expanded public errors. The
fixture captures the service phases in its owned protected state, validates
the fixed grammar and reports only a bounded suffix if the probe remains red.
The checker must require both compile-time and fixture opt-ins and reject
activation in the workflow or ordinary builds. This is diagnosis, not native
acceptance and not permission to weaken any guard.

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

- Rerun the repaired checkpoint on both authorized ephemeral macOS
  architectures; the first run stopped at the native compile RED and did not
  reach the product assertions.
- Execute or recover the intended pre-port behavioral red if the acceptance
  record requires it; the observed compile RED does not substitute for that
  behavioral evidence.
- Record exact runner versions, command output and cleanup result here.
- Repeat the repository and Linux gates on the integrated candidate after the
  separate merger incorporates the native CI configuration.
- Have the separate merger integrate and verify before resolving Ticket 26.

No existing fallback was changed. The previously unsupported non-Linux path
failed explicitly; this patch replaces that explicit failure only for macOS
with native primitives. Other unimplemented targets continue to fail
explicitly.
