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
peer UID, TLS 1.3 handshake, pinned RPK and ALPN/READY, plus fixed `0|1`
accepted-stream `O_NONBLOCK` observations; it must not emit key or profile
bytes, dynamic paths, credentials or expanded public errors. The fixture
captures the service diagnostics in its owned protected state, validates
the fixed grammar and reports only a bounded suffix if the probe remains red.
The checker must require both compile-time and fixture opt-ins and reject
activation in the workflow or ordinary builds. This is diagnosis, not native
acceptance and not permission to weaken any guard.

### Accepted-stream blocking checkpoint

The seventh native custody run
[`34797022111`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34797022111)
on checkpoint `678319b` is an observed **RED** on both macOS targets after the
safe fixture and identity gates passed. The client and service each reached
their fixed `*-tls-configured` diagnostic phase, but neither reached its next
handshake phase; the public probe result remained exactly
`CUSTODY_UNAVAILABLE`. This bounds the failure to the I/O boundary immediately
after TLS configuration, but does not by itself prove the cause.

The next checkable hypothesis is that the accepted Darwin Unix stream retains
the listener's nonblocking state. `serve_loop` deliberately makes both
listeners nonblocking so that its polling loop can handle `WouldBlock`.
Darwin's [`accept(2)` contract](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/accept.2.html)
says the new socket has the listening socket's properties, while Linux's
[`accept(2)` documentation](https://www.man7.org/linux/man-pages/man2/accept.2.html)
explicitly warns that Linux does not inherit `O_NONBLOCK`. This makes inherited
`O_NONBLOCK` a Darwin-specific hypothesis, not a cross-platform assumption.
The rustls [`StreamOwned` wrapper](https://docs.rs/rustls/latest/rustls/struct.StreamOwned.html)
delegates handshake I/O to `ConnectionCommon::complete_io` through the
underlying stream, so a nonblocking accepted descriptor can explain a
handshake that stops before the first request/flush; that sentence is an
inference until the next native run observes the flags.

The authorized correction is deliberately narrow: immediately after
`accept(2)`, normalize the accepted stream to blocking mode before constructing
the rustls stream, read back `F_GETFL`, and return the existing visible
`CUSTODY_UNAVAILABLE` failure if the setter or readback fails. It does not add a
retry, alternate transport, relaxed TLS check, or longer deadline, and it does
not alter `IO_TIMEOUT`. The regression test accepts a real Unix-listener
connection and independently asserts that `F_GETFL` has no `O_NONBLOCK` bit
after preparation. With only the laboratory `macos-ticket26-diagnostics`
feature **and** the exact `PM_MACOS_TICKET26_DIAGNOSTIC=1` opt-in, the native
harness may additionally observe fixed, data-free
`PM26_DIAGNOSTIC accepted-stream-nonblocking-before=0|1` and
`PM26_DIAGNOSTIC accepted-stream-nonblocking-after=0|1` lines; ordinary builds
emit no such diagnostic. The feature remains absent from Cargo defaults.

Verification must proceed in this order: record the regression test RED against
this checkpoint, implement the normalization, rerun that test GREEN, then run
the existing Linux custody lab with the normal feature set. A subsequent
ephemeral Mac run must observe `before=1` and `after=0` on each target before
the hypothesis is considered confirmed. Full Ticket 26 acceptance still must
execute the normal binary/laboratory entry point without the diagnostic feature;
the diagnostic run is evidence for this boundary only and is not an acceptance
gate.

For this candidate, the focused local TDD record is:

```text
./scripts/cargo-local.sh test -p pm-custody --lib \
  accepted_stream_is_blocking_after_preparation --locked --offline
# RED before the implementation: cannot find function `normalize_accepted_stream`
# GREEN after the implementation: 1 test passed
```

### Eighth-run fixture-only RED

Run
[`34798902550`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34798902550)
on `87dc908` confirmed the product correction on both architectures: the
diagnostics observed `accepted-stream-nonblocking-before=1` and `after=0`, and
the agent probe reached client/server READY, including TLS, RPK pinning and
ALPN. The run then stopped in the negative `fake_server_rejected_before_tls`
fixture: its `OTHER`-owned impostor socket was bound successfully, but the
default socket mode did not grant `_pmagent26` write permission to connect.
The path-exists check therefore passed while the fake server's `accept()`
remained blocked until the existing five-second `communicate` bound. This is a
fixture permission mismatch, not a product or TLS failure.

The fixture correction is limited to `os.chmod(sys.argv[1], 0o666)` after the
synthetic impostor bind and before `listen(1)`. It preserves the real
wrong-UID-before-secret contract: `_pmagent26` must connect to the real fake
server, the custody probe must reject on kernel peer UID before sending a TLS
request, and the fake server must receive EOF (`0` bytes). The timeout is not
changed, no failure is converted to success, and no product path is altered.
The rerun must retain this `0`-byte assertion on both native architectures.

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

### Ninth-run human-authorization setup diagnostic method

Run `34799626677` on `249cbd8` is a new RED after the accepted-stream fix:
Intel completed the laboratory, while Apple silicon reached client/server
`READY` for the real agent probe and then `human-authorization --action setup`
returned exit 4. The captured traceback exposes only the command and the
public `CUSTODY_UNAVAILABLE` boundary; it does not identify whether setup
failed while reading the human inputs, connecting/unlocking, or applying one
of its signed vault mutations. The existing `finally` cleanup remains
unchanged and is not part of this diagnostic.

Before editing, the single-variable method is fixed as follows:

1. Keep the exact public setup invocation, wire fields, password handling,
   TLS/RPK/ALPN checks, `IO_TIMEOUT`, and all assertions. Add no retry, sleep,
   deadline, alternate transport, TLS relaxation, or product behavior change.
2. Under only the existing laboratory feature
   `macos-ticket26-diagnostics` **and** the exact opt-in
   `PM_MACOS_TICKET26_DIAGNOSTIC=1`, emit fixed phase names around the human
   authorization client and server boundaries: profile/key input, socket and
   peer setup, TLS configuration, unlock request/response, setup request,
   and setup response. On the server, add fixed setup boundary phases and fixed
   error categories for input validation, unlock, each prepare/commit stage,
   and response writing. No phase includes a path, account, key, password,
   vault byte, request body, dynamic error text, or timing.
3. The fixture invokes only this setup subprocess with the opt-in, captures
   its bounded stderr and the custodian-owned diagnostic file, validates the
   existing fixed grammar, strips only the unchanged terminal
   `CUSTODY_UNAVAILABLE` line, and reports a bounded phase/category suffix.
   The original success assertion remains for a future green run; a failure
   must still be exactly exit 4, empty stdout, and
   `CUSTODY_UNAVAILABLE\n`. Diagnostics are evidence only and cannot turn a
   failure into a pass.
4. First run the available local syntax/checker tests and preserve the native
   RED record. If the phase/category identifies a deterministic fixture or
   product cause that is safely correctable within Ticket 26, write a
   public-seam regression before the minimal fix and rerun the same lab. If
   the native run is required to distinguish the categories, freeze this
   diagnostic-only checkpoint without changing product logic.

This method remains feature- and opt-in-gated, preserves the negative and
human-authorization contracts, and is not a Ticket 26 acceptance claim.

Checkpoint evidence from this worktree:

- TDD RED: before the implementation, the macOS checker exited `1` because
  `ticket26_diagnostic_error` was absent from `linux.rs`.
- GREEN: the final `./scripts/check.sh` passed (workspace checks, tests, and
  clippy); `pm-custody` tests also passed with
  `--features macos-ticket26-diagnostics`. Python compilation, shell syntax,
  the focused macOS CI checker, and `git diff --check` passed.
- Native status: no local macOS runner is available. The ARM failure from run
  `34799626677` remains the preserved RED; this checkpoint adds evidence only
  and needs the same native lab rerun to identify a phase/category before any
  product or fixture correction.

### Tenth-run unlock-result diagnostic method

The 2026-09-14 Apple-silicon rerun reached
`server-human-unlock-frame` while the client ended at
`error=client-human-unlock`. The current frame helper maps a socket timeout,
EOF, other I/O failure, malformed response and non-success status to the same
public failure. The fixture also reads the server log immediately after the
client returns, so the absence of a server terminal phase does not distinguish
an unlock still executing from a terminated or restarted custodian. Buffered
fixture output means the workflow timestamps are not operation durations.

Before editing, the next single-variable diagnostic method is fixed as follows:

1. Preserve the exact setup command, public stdout/stderr/exit contract,
   `IO_TIMEOUT`, Argon2id profile, wire format and server behavior. Add no retry,
   sleep, new deadline, alternate path, or relaxed assertion.
2. Refactor the existing frame reader once, without duplicating its framing
   protocol, so its internal result retains only these fixed categories until
   the human-unlock observer: `timeout` (`TimedOut` or `WouldBlock`), `eof`,
   `other-io`, `malformed-frame`, and `status-nonzero`. Its ordinary wrapper
   must continue mapping every category to the same `Failure::Unavailable`.
   A focused regression checks that public-equivalent mapping.
3. Under only `macos-ticket26-diagnostics` plus the exact opt-in
   `PM_MACOS_TICKET26_DIAGNOSTIC=1`, report the fixed client unlock category and
   a monotonic, bounded elapsed-millisecond value. Around the server vault
   unlock, report only `ok` or `vault-error` with the same bounded elapsed
   grammar. Do not include an error string, status byte, secret, key, path,
   request, vault data, account, or wall-clock value.
4. On setup exit 4, before reading the server log or raising the unchanged
   failure, query the exact launchd label once and compare its parsed PID with
   the already verified service PID. Emit only one fixed classification:
   `same-pid`, `different-pid`, `unavailable`, or `unparseable`. Do not dump
   launchctl output and do not wait for the server.
5. Keep diagnostics evidence-only. `timeout` plus `same-pid` and no server
   terminal result isolates a live server still inside unlock at the client
   deadline; EOF plus a missing/replaced process distinguishes termination;
   a server `vault-error` distinguishes an explicit unlock rejection. None is
   acceptance, and the native RED remains until the unchanged observable lab
   succeeds on both architectures.

The inherited best-effort cleanup remains unchanged and outside this bounded
checkpoint; it still requires separate authorization before Ticket 26 can be
accepted.

Checkpoint evidence from the Linux development host:

- TDD RED: the focused `pm-custody` regression failed to compile because
  `FrameReadFailure` and `read_frame_bounded_classified` did not yet exist.
- Focused GREEN: the same regression passed both with and without
  `macos-ticket26-diagnostics`; every classified frame failure retained the
  ordinary `Failure::Unavailable` result.
- The Python diagnostic grammar/classifier checks, Python and shell syntax,
  the focused macOS CI checker, and `git diff --check` passed. The final
  `./scripts/check.sh` passed in 97 seconds.
- `./scripts/clean-offline-build.sh` removed 11,183 files / 3.8 GiB and the
  locked offline rebuild passed in 39 seconds.
- No native macOS rerun was performed for this checkpoint. The tenth-run ARM
  failure remains RED, and the new categories are not native evidence until
  the same unchanged laboratory runs there.

### Eleventh-run unlock-latency discriminant method

Run `34807572032` on checkpoint `98d41d` is GREEN on Intel and RED on Apple
silicon. The ARM client classified the human unlock response as `timeout` at
15,002 ms; launchd still reported the same service PID; and the service had
accepted and decoded the complete human unlock frame but emitted neither an
unlock result nor its terminal phase. This verifies the deadline and bounds
the wait to `HumanVault::unlock_with_audit_custody`; it does not yet identify
which operation inside unlock consumed the time.

Read-only call-graph inspection fixes the next single-run discriminant:

1. Preserve the exact password, Argon2id profile (256 MiB, three passes,
   `p=1`), `IO_TIMEOUT`, process priority, build profile, TLS/RPK exchange and
   public `CUSTODY_UNAVAILABLE` mapping. Do not add an authentication/KDF
   operation, retry, sleep, alternate path or larger deadline.
2. Extend the existing default-off `macos-ticket26-diagnostics` feature
   through `pm-vault` and `pm-crypto`. It remains inert unless the service has
   the exact `PM_MACOS_TICKET26_DIAGNOSTIC=1` opt-in. During only the existing
   unlock, emit fixed phases for `channel-verified`, `sqlite-opened`,
   `durability-configured`, `bundle-loaded`, `kdf-start`, `kdf-end` and
   `root-authenticated`. Each line contains only the fixed name and a bounded
   millisecond duration measured with a monotonic clock; it contains no path,
   UID, password, key, bundle, SQL value or dynamic error text.
3. Measure the already required creation derivation without executing another
   derivation: start immediately after flushing the confirmed password and
   stop when the CLI prints its recovery-code prompt. `PendingVault::new`
   executes the same default KDF in that interval and persistence has not yet
   started. Report only `vault-root-create-ms=<0..999999>`.
4. Read the one native libsodium `config.log` produced by this clean build,
   require a parseable `CFLAGS` assignment, and classify it only as `opt0` or
   `optimized` from mutually exclusive exact optimization tokens. Missing,
   multiple, contradictory or unclassified metadata is a laboratory failure,
   never a default category. Report only `sodium-cflags=opt0|optimized`; never
   dump the flags or select an ambient library.
5. A focused regression must prove that the diagnostic root opener returns the
   same authenticated root as the ordinary public opener and observes exactly
   one `kdf-start`/`kdf-end` pair. The checker must require all feature/opt-in
   gates and the closed fixture grammar. Local syntax/check gates may run once
   the shared Linux test window is free; only a native Intel+ARM rerun supplies
   the discriminant.

Interpretation is closed. `kdf-start` without `kdf-end` at the unchanged client
deadline identifies the password derivation. Stopping before `sqlite-opened`,
`durability-configured` or `bundle-loaded` identifies channel, SQLite setup or
bundle I/O respectively. A fast creation derivation but slow service KDF makes
the launchd execution context a candidate; both slow makes the native crypto
build/profile the leading candidate. Audit custody is not a candidate for this
deadline: unlock only clones its already-open opaque handle after root
authentication and performs no audit append, transaction or I/O.

Current source inspection makes the KDF/build path the leading hypothesis, not
a confirmed cause. The lab uses Cargo's dev profile; the workspace fixes
`libsodium-sys-stable` 1.24.0 with default features disabled; and that crate's
build script obtains C flags from `cc::Build` while adding `--enable-opt` only
for its inactive `optimized` feature. A Linux build of the same graph recorded
`-O0`, but that is not evidence of the ARM build, hence the required native
classification above. Do not enable `optimized` speculatively: its build script
also adds `-march=native`/`-mtune=native`, which may change distribution
portability. Any optimization correction requires the native result and a
separate approved method; increasing the timeout or reducing the KDF is not a
correction.

The bounded diagnostic checkpoint was verified locally without making a native
latency claim. The focused feature-enabled `pm-crypto` regression passed 1/1
and the static macOS CI checker passed. The first full `./scripts/check.sh`
reached Clippy and failed because the feature-disabled no-op observer left its
`self` argument unused; after making that no-op consume both fixed inputs, the
same complete check passed. `./scripts/clean-offline-build.sh` then completed a
clean locked/offline rebuild successfully. No macOS runner was dispatched, so
the ARM location and its native `sodium-cflags` category remain unverified.

Native run `34810076591` on `ad9e6ad` failed on both architectures before the
fixture mutated the host: the closed metadata guard found other than exactly
one globbed libsodium `config.log`. The preceding feature-enabled build and
tests create more than one eligible Cargo build directory, so a target-wide
glob cannot identify the build linked into the custody artifact. The twelfth
run therefore provides no CFLAGS or unlock-latency result.

The corrected discriminant binds metadata to the exact custody build rather
than weakening the guard. That single `cargo build` emits machine-readable
`build-script-executed` records; a checked parser requires exactly one record
for the locked `libsodium-sys-stable@1.24.0` package and writes only its
`out_dir`. Missing, duplicate, malformed, foreign-package or non-directory
records fail explicitly. The harness receives that exact output directory and
requires its fixed `source/libsodium-stable/config.log`; it never globs, picks
the first result or derives a category from another feature build. The existing
closed CFLAGS parser and `opt0|optimized` output remain unchanged.

Native run `34810631226` on `902018b` completed the discriminant on both
architectures. Both exact builds reported `sodium-cflags=opt0`. Intel measured
the existing root creation at 6,318 ms and its service unlock KDF at 4,156 ms
(4,161 ms for the whole unlock), then passed. Apple silicon measured creation
at 9,108 ms; service unlock reached `channel-verified` (0 ms), `sqlite-opened`
(3 ms), `durability-configured` (5 ms), `bundle-loaded` (1 ms) and `kdf-start`,
then the unchanged client deadline expired at 15,003 ms with the same launchd
PID and no `kdf-end`. This verifies the ARM hotspot is the password KDF, not
channel authentication, SQLite, durability, bundle I/O or audit.

The bounded correction keeps the dev/test product and every workspace crate at
their existing profiles except the exact locked native package
`libsodium-sys-stable:1.24.0`, whose package override sets `opt-level=2`.
The [Cargo profile override contract](https://doc.rust-lang.org/cargo/reference/profiles.html#overrides)
documents that a named package override has precedence for that package;
the pinned `cc` 1.4.5 source obtains its C compiler optimization from Cargo's
`OPT_LEVEL`, and the pinned libsodium build obtains its `CFLAGS` from that
`cc::Build`. This selects ordinary portable `-O2`; it does not enable the
dependency's `optimized` feature (which adds `--enable-opt` and native tuning),
change Argon2id parameters, deadlines, QoS, Rust workspace optimization or any
public format/operation. Local verification must cover the existing crypto byte
vectors, root open/create behavior, vault regressions, full check and clean
offline rebuild. The next native run must still obtain its exact current build
metadata and assert `sodium-cflags=optimized`; unavailable or unclassified
metadata remains a hard failure, never permission to use an alternate build.

Local verification of this correction passed the full feature-enabled
`pm-crypto` suite (including fixed format/root vectors and the diagnostic
equivalence test), the three `pm-vault` local persistence/root regressions, the
complete `./scripts/check.sh`, the macOS static checker, and
`./scripts/clean-offline-build.sh`. The exact clean Linux build metadata
classified as portable `-O2`; that confirms the Cargo/cc seam locally but does
not predict either native macOS result.

Native run [`34811375717`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34811375717)
on `634ac8a` completed GREEN on both authorized architectures. The exact current
libsodium build classified as `optimized` on both. Apple silicon measured the
existing root creation at 599 ms, the service KDF at 605 ms and the whole
unlock at 609 ms. Intel measured creation at 1,803 ms, the service KDF at
1,362 ms and the whole unlock at 1,371 ms. Both jobs retained the unchanged
Argon2id parameters and deadline and passed the live LaunchDaemon identity,
bilateral `getpeereid`, TLS 1.3/RPK, ACL/wrong-UID rejection, durable suspension
across a real launchd restart, `/dev/tty`, AppKit clipboard ownership and
queried fullfsync assertions. Each job printed all four product PASS lines and
the workflow concluded successfully.

This result verifies that the bounded portable package optimization removed the
observed KDF deadline failure on both native runners without changing the KDF
contract. It is not complete Ticket 26 acceptance. Authorization remains
pending for the inherited cleanup behavior identified separately; the normal
non-diagnostic binary/TUI composition, reboot plus FileVault coverage, and
signing/notarization gates also remain outstanding. The diagnostic build and CI
runner do not substitute for those requirements.

## Remaining acceptance work

- Resolve and verify the inherited cleanup behavior only after its separate
  authorization decision; do not treat the two successful jobs as approval to
  change that path.
- Verify the normal non-diagnostic binary and complete keyboard TUI composition
  rather than treating the diagnostic custody flow as the daily human UI.
- Complete the separately scoped reboot/FileVault and signing/notarization
  gates.
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
