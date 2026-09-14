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

That command is the normal acceptance mode. It builds the ordinary binaries
without `macos-ticket26-diagnostics`, launches the unmodified production plist,
sets no diagnostic environment variable and creates or reads no diagnostic
log. It must exercise the same identity, TLS/RPK, ACL, durability, restart,
terminal, clipboard and strict owned-cleanup gates described below. The pinned
libsodium build metadata remains a build-input gate and must classify the exact
build as optimized; it is not a product diagnostic channel.

The previous product-phase diagnostic path remains available only through the
exact explicit opt-in:

```text
PM_MACOS_EPHEMERAL_CI=1 ./scripts/test-macos-custody-lab.sh --diagnostic
```

That mode alone enables the compile-time diagnostic feature, injects the fixed
diagnostic environment into the synthetic client and launchd fixture, and
validates the protected diagnostic log. Unknown or additional arguments fail;
normal-mode failure never selects diagnostic mode. Native acceptance requires
the default normal command, while diagnostic runs remain supporting evidence.

The pasteboard-only observation path is a separate explicit opt-in. It builds
and installs the ordinary binary and ordinary LaunchDaemon plist; it does not
enable `macos-ticket26-diagnostics`, set `PM_MACOS_TICKET26_DIAGNOSTIC` or
create the service diagnostic log:

```text
PM_MACOS_EPHEMERAL_CI=1 ./scripts/test-macos-custody-lab.sh --pasteboard-diagnostic
```

The manual workflow exposes this as the boolean `pasteboard_diagnostic` input.
When true it passes only `--pasteboard-diagnostic` to the harness. The mode is
limited to the categorical human/agent pasteboard observation below; it is
supporting evidence and cannot turn a normal product failure into a pass.

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
6. runs the native clipboard ownership race, the exact pasteboard negative
   probe from a separate ephemeral system-domain launchd job running as the
   no-login agent account, real `/dev/tty`/`isatty`, and zero-core-limit probe
   from the logged-in user session;
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

### Owned native-fixture cleanup method

The prior harness printed its four product PASS lines before entering cleanup,
then invoked every cleanup command with `check=False` without inspecting its
result. A failed `launchctl bootout`, path removal, user deletion or group
deletion could therefore leave owned host state while the job still appeared
successful. The user authorized propagating all of those inherited cleanup
errors after run 14; that successful diagnostic record remains unchanged.

The correction is fixture-only and uses a closed ownership ledger. Collision
checks remain before mutation. A path, launchd job, user or group is added to
the ledger immediately after its own creation command succeeds, including
partially configured accounts. Cleanup attempts every and only ledger entry in
dependency-safe reverse order, records every nonzero result or exception using
fixed non-sensitive action names, then queries absence for every owned path,
launchd label and directory-service record. It raises one aggregate error after
all attempts, or attaches that aggregate as the cause while re-raising the same
pre-existing failure; no cleanup failure can be ignored or converted to
success. The four PASS lines move after successful cleanup and verified
absence. No glob,
alternate root, broad account match, home-directory deletion or unrelated
system mutation is permitted.

Callable fake-command regressions cover a successful cleanup and simultaneous
bootout/path/user/group failures, proving all later operations and absence
checks still run and the aggregate is visible. These regressions validate only
error propagation; they are not native acceptance. Native validation remains
the same collision-guarded ephemeral CI laboratory on both architectures.

The focused callable regressions passed for both the all-success result and a
seven-error bootout/path/user/group plus absence-check result; they also proved
all seven commands were attempted. Python AST parsing, the macOS static checker
and `git diff --check` passed. No Rust gate, build or native laboratory was run
for this scripts-and-documentation-only checkpoint. Only the unchanged native
CI laboratory can verify real launchd, filesystem and Directory Services
cleanup on both architectures.

Before native dispatch, static review found two regressions in that first
cleanup checkpoint. It treated every nonzero per-record query as proof of
absence, which could conceal a permission or Directory Services/launchd
transport failure, and `except Exception` no longer guaranteed cleanup for
`KeyboardInterrupt` or `SystemExit` as the prior `finally` did. The corrected
method requires successful, closed-format `launchctl list` and `dscl -list`
inventory queries and proves the exact owned label/user/group names are absent;
any query error or malformed listing is itself aggregated. It captures
`BaseException`, completes cleanup, and re-raises the same interruption object
when cleanup succeeds. Focused regressions must cover listing-query failure and
identity-preserving interruption cleanup before native dispatch.

The corrected focused checks passed: successful closed inventories were
accepted; nonzero launchd and both Directory Services inventory queries were
all retained in the seven-error aggregate; and both successful and failing
cleanup re-raised the identical `KeyboardInterrupt` object after attempting the
owned removal. Python AST parsing, the static macOS checker and
`git diff --check` passed. No Cargo, Rust build or native laboratory was run.

Native cleanup run `34836722393` on `81ffa4c` failed on both architectures
before custody startup: the new exact `mkdir` of
`/usr/local/libexec/passwordmanager` exited nonzero, whereas the prior
`mkdir -p` had also provisioned its missing parent when necessary. The captured
record does not include the command's stderr, so parent absence is a bounded
explanation to test, not a claimed observed cause.

The fixture correction explicitly handles only the fixed
`/usr/local/libexec` parent. If it exists, the harness requires a real
root-owned directory without group/world write and records but does not alter
its mode or ownership. If absent, it creates that exact parent as root-owned
`0755`, verifies it, and records separate ownership immediately. Cleanup first
removes the owned child install root, then uses only `rmdir` on a parent created
by this run; nonempty or failed parent removal is aggregated and never replaced
by recursive deletion. Final absence is required only for the created parent.
Fake-command checks must cover existing-parent preservation, created-parent
ordering, nonempty `rmdir` failure and continued cleanup attempts. This remains
fixture-only and needs the same native two-architecture run.

Native cleanup run
[`34837550960`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34837550960)
on `c7f6fb6` passed on both `macos-15-intel` and `macos-15`. Both jobs completed
the custody, identity, TLS/RPK, ACL, persistence, terminal and AppKit gates and
then removed the exact owned launchd job, paths, accounts and conditionally
created install parent with verified absence. This closes the reported fixture
cleanup defect, but the jobs still used the explicit diagnostic build and do
not establish the normal-binary or complete TUI requirements.

### Normal-mode checkpoint

The laboratory now defaults to the normal mode defined above. The shell passes
no feature or harness-mode argument in that path; the harness installs the
unchanged production plist, rejects ambient diagnostic activation, runs agent
and human operations without the diagnostic environment, and requires the
protected diagnostic log to remain absent. `--diagnostic` is the explicit
alternative that enables product-phase diagnostics; `--pasteboard-diagnostic`
is the separate harness-only categorical observation mode. All modes still
bind and reject ambiguous libsodium build metadata, and require the exact build
to be optimized.

The static checker covers all three closed argument forms, rejects unknown and
incomplete modes, distinguishes normal, product-diagnostic and
pasteboard-diagnostic output, rejects unoptimized metadata, and pins normal
plist/log behavior. Shell syntax, Python
AST parsing, the static macOS checker and `git diff --check` passed. No Cargo,
build, native laboratory or product behavior was executed for this checkpoint;
the default command must run on both native architectures before it is evidence.

Native normal-mode run
[`34840405573`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34840405573)
on `8dcc980` is **RED** on both architectures before the build. The macOS runner's
system Bash 3.2, with `set -u`, rejected expansion of the intentionally empty
normal-mode `diagnostic_features` array as an unbound variable at line 50. The
following missing libsodium metadata error was secondary because the build
command never ran. Linux syntax and static checks did not establish that native
shell behavior.

The correction must keep `set -u` and the system Bash. Normal and diagnostic
modes each construct complete, nonempty build, test and harness command arrays;
only the explicit diagnostic branch appends its feature and mode arguments.
The static regression must source the exact command constructor under `bash -u`
and actually expand every normal and diagnostic command, checking that normal
contains no diagnostic argument and diagnostic contains each opt-in exactly
once. String inspection alone is insufficient. This remains script-only until
the unchanged normal entry point succeeds natively on both architectures.

The corrected command-plan regression passed under `bash -u`: every nonempty
normal and diagnostic build, test and harness array expanded successfully;
normal contained no diagnostic argument, while diagnostic contained each
explicit opt-in exactly once. Shell syntax, Python AST parsing, the complete
static macOS checker and `git diff --check` also passed. No Cargo command or
native product behavior was executed for this checkpoint.

Native normal-mode run
[`34841029441`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34841029441)
on `1be9f4c` passed on both `macos-15-intel` and `macos-15`. Both jobs built the
ordinary single-architecture binaries without
`macos-ticket26-diagnostics`, installed the production plist without a
diagnostic environment or log, classified the exact libsodium build as
optimized, and passed the live LaunchDaemon, bilateral `getpeereid`, TLS/RPK,
ACL/wrong-UID, persistent suspension/restart, `/dev/tty`, AppKit clipboard,
SQLite full-fsync and strict owned-cleanup gates. This closes the normal-mode
checkpoint. The applicable native Rust selection still contained nine tests
and several Linux-gated executables reported zero tests, so this run does not
claim the integrated keyboard TUI or complete native workspace coverage.

### Integrated native keyboard-TUI method

This method is fixed before composing the already integrated Ticket 23--25
interfaces into the macOS branch. The acceptance entry point remains the
normal, non-diagnostic laboratory. It must build and architecture-check
`pm-custody`, `pm` and `pm-sync`, install the ordinary custody binary, and run
the TUI through the same live system LaunchDaemon, vault engine, human Unix
socket, TLS 1.3/RPK profile and native peer-UID checks used above. A separate
CLI-only invocation, a second engine, a simulated terminal or a diagnostic
feature is not TUI evidence.

The harness will use Python's native `forkpty`/PTY primitives, not a Linux user
or mount namespace and not an optional terminal package. The child is the
logged-in non-root human and runs the public `pm-custody tui` command with the
owned human profile/key and live human socket. The parent sends only keyboard
bytes, reads the rendered PTY stream, and changes the terminal dimensions with
`TIOCSWINSZ`. It must observe 80x24, 42x12 and 100x30 rendering. Before sending
Enter for visible input, it waits for that exact input to be rendered; this is
only synchronization with Crossterm consumption, not an operation retry or a
deadline extension. Password and recovery re-entry remain hidden and are
never searched for in the captured stream.

The native run must replay the complete observable keyboard contracts of
Tickets 23, 24 and 25, rather than accepting a screen that merely starts:

1. seed and browse all seven record kinds and every field descriptor, including
   notes, custom/source, every auth member and attachment descriptors; prove
   selection alone exposes no value, then use exact-field reveal and copy;
   cover search, tags, favorite, generator, history, trash, restore and both
   purge ceremonies, Unicode/control sanitization, reveal expiry and idle lock;
2. operate the access and pending views by keyboard: closed enrollment,
   enable/disable, suspend/resume, revoke, safe pending context and cancel;
   check the resulting state from a real agent process, and prove human lock
   does not transfer ownership of the channel or suspend the agent;
3. execute CSV and 1PUX preview/mapping/duplicate/cancel/confirm, encrypted
   backup, warned plaintext export, restore, both rotations, real pinned sync
   pairing/status/offline/failure/restart, causal retirement, audit query and
   purge, and streaming download of an attachment larger than the human frame.
   Every negative remains an explicit failure and no source is mutated.

The platform composition itself has two closed requirements. First, the TUI
module and `tui` command must compile and execute on both Linux and macOS from
the one custody implementation; a macOS cfg that omits the command or reports
zero applicable TUI tests is a failure. Second, explicit copy on macOS must use
`pm_native_channel::OwnedClipboard`, which publishes through AppKit and clears
only while its recorded `NSPasteboard.changeCount` still owns the selection.
It must not invoke Linux `wl-copy`, `pbcopy`, OSC52 or an alternate clipboard
backend. The test observer may read the pasteboard to compare the synthetic
value and publish a synthetic replacement; after the copy lease expires that
replacement must remain. The agent account must be unable to obtain the copied
value. This observer use is not a product execution path.

The existing wrong-UID cases remain mandatory with the integrated binary: a
copied correct RPK under the wrong native UID is rejected, the agent cannot use
the human endpoint, and the human cannot use the agent endpoint. After keyboard
lock and after idle lock, the PTY must terminate, an agent operation must still
work when authorization is otherwise enabled, and a fresh human connection
must require the master password again. A wrong password must leave the vault
unchanged and must not produce an unlock-success audit record. Terminal bytes
must contain neither fixture secrets outside explicit timed exposure nor an
executed OSC52 sequence.

All fixture resources join the existing collision-checked ownership ledger.
The TUI child, sync/provider processes and clipboard observer are stopped and
waited; then the strict launchd/path/account cleanup and exact absence checks
run before any PASS line. Cleanup failures are aggregated and prevent success.
The native TUI PASS must name keyboard, PTY, TLS/RPK, seven kinds/all fields,
access/pending, operations, AppKit ownership race, wrong UID, explicit lock and
idle lock. It must appear on both authorized architectures in the same run.

### Clipboard backend composition checkpoint

The shared `ClipboardLease` keeps the Linux `wl-copy` child path and its
validated root-owned helper unchanged. On macOS, the same lease uses only the
existing `pm_native_channel::OwnedClipboard`: `copy` records the AppKit
`NSPasteboard.changeCount`, and explicit expiry/session-exit cleanup calls
`clear_if_owned` once. A stale lease that no longer owns the pasteboard is a
successful ownership-preserving no-op; an AppKit copy or clear error remains a
`CUSTODY_UNAVAILABLE` failure. A failed copy creates no lease, and a Linux
helper partial-initialization failure still attempts the existing child
stop/wait cleanup. No `pbcopy`, OSC52, shell fallback or alternate backend is
allowed.

The focused macOS regression is cfg-gated to the real AppKit backend and
exercises a replacement-owner race plus explicit cleanup's no-second-attempt
behavior when executed. The native acceptance method above must additionally
execute the normal non-diagnostic `pm-custody tui` through a real PTY, verify
copy/lock/idle exit and the observer's replacement remains after the stale lease
expires, then perform strict owned cleanup before PASS. This checkpoint was
prepared without Cargo, a local build, or a native runner; it makes no
RED/green or macOS TUI acceptance claim.

### Native PTY fixture implementation checkpoint

The normal macOS laboratory now includes a bounded core TUI fixture in the
same collision-checked harness. Before launching the TUI it seeds the seven
record kinds and the token-exchange relationship through the existing
`human-content-flow` command over the live human TLS/RPK endpoint; this is
fixture setup, not a second vault engine. The child is started with Python's
`forkpty`, receives the installed `pm-custody tui` binary and the real human
profile/key/socket, and opens the product's `/dev/tty` itself. The parent sends
keyboard bytes only, waits for each visible prompt to render before sending
Enter, and applies `TIOCSWINSZ` at 80x24, 42x12 and 100x30. It does not use
tmux, a fake terminal, `wl-copy`, `pbcopy`, OSC52 or a clipboard fallback.

The core assertions are deliberately observable and narrow: the unlocked
catalog contains the seeded metadata without secret values; engine-backed
search selects the Password record; exact field selection reaches
`auth[0].password` and copies its synthetic UTF-8 value through the existing
macOS `OwnedClipboard`/AppKit lease; a separate logged-in-user observer reads
the pasteboard, publishes a synthetic replacement, and proves the lease expiry
does not clear that newer owner. The `_pmagent26` observer cannot read the
copied value. A keyboard `l` exits the first session and a subsequent session
must show the master-password prompt again. A fresh session with no further
keys exits through the existing idle deadline; the lab then checks delegated
agent discovery while authorization remains enabled. Child exit status, PTY
bytes, hidden-input secrecy, the real launchd service/socket and the strict
owned cleanup are all required. The observer uses `osascript` only as a test
observer; it is not a product execution path.

The fixture does not add field validation or byte conversion: the existing
human-field catalog remains length-delimited and the existing renderer keeps
its binary-value branch for non-UTF-8 bytes and its control-character
sanitization. The synthetic seed exercises the established seven-kind
content path; empty or binary field behavior is not changed or accepted by a
new fixture-specific rule.

There is an existing macOS capability boundary that this checkpoint does not
hide: `pm_native_channel::OwnedClipboard::copy` rejects an empty value or
bytes that are not valid UTF-8 before calling the AppKit bridge, and the
Objective-C bridge also requires a nonempty `NSUTF8StringEncoding` string.
Those fields remain representable and revealable through the human-field
protocol, but an explicit macOS copy fails closed rather than converting or
substituting their bytes; Linux's byte-oriented `wl-copy` path is broader.
The complete TUI acceptance must report this compatibility boundary instead
of treating the UTF-8 copy fixture as coverage for empty/binary fields.

This checkpoint is intentionally named `tui-core`: it proves the native PTY,
service/channel, AppKit ownership race, explicit lock and idle lock seams
without claiming the complete Ticket 23--25 keyboard operation matrix. The
full acceptance method above still requires every record field, access/pending,
import/backup/sync/audit flow and both purge ceremonies. The normal command
must print the core evidence only after the PTY child has exited successfully;
failure or cleanup errors remain failures. The script also includes package
`pm-custody` in its native test command so the cfg-gated AppKit clipboard lease
regression is actually compiled and executed instead of being omitted by the
previous package list.

Static verification for this implementation is closed before native execution:
the Python AST parses; the shell command plan still has normal and explicit
diagnostic modes with no implicit feature; the PTY implementation contains
`forkpty`/`TIOCSWINSZ`, prompt-render synchronization, strict incremental
UTF-8 decoding across split reads, bounded child wait and one teardown policy
(SIGTERM plus checked wait/close; a timeout is a failure, not a forced-signal
fallback); the macOS fixture contains neither a shell clipboard command
nor an alternate/fallback branch; and the existing nine native tests and
wrong-UID/negative assertions remain in the same harness. No Linux run or
local macOS result is substituted for the required normal Intel+Apple-silicon
run. Until that run succeeds, this is an implementation checkpoint only.

Native run 20
[`34847582724`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34847582724)
on `a6c3` failed on both authorized macOS architectures during compilation,
before the laboratory or any TUI behavior ran. Five cfg-gated AppKit test
assertions used `Result::expect`, which attempted to format the deliberately
opaque product `Failure` and produced `E0277` in both the library and binary
test targets. This is a test-compilation failure, not a behavioral RED or
acceptance result. Checkpoint `a247340` replaces those assertions with static
panic closures, preserving the non-`Debug` product error and the test's
failure behavior; native redispatch remains pending.

Native run 21
[`34848148030`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34848148030)
on `a247340` compiled the ordinary binaries and applicable native tests on both
authorized architectures, then reached the normal TUI core laboratory. The
first real PTY child exited with the public `CUSTODY_UNAVAILABLE` result before
rendering `Password required`; the Intel and Apple-silicon jobs reported the
same outcome. This is a behavioral RED, not native acceptance. The traceback
shows the failure at `start_macos_tui` after content seeding and normal human
authorization setup, but the public custody error does not identify its
internal stage.

Static source inspection provides a bounded, source-supported diagnosis while
native confirmation remains pending. `run_terminal` calls Ratatui's
`Terminal::clear` before the first application draw and again on the final
successful lock/exit path. Ratatui 0.30's fullscreen `Terminal::clear`
unconditionally asks its backend for the current cursor position before
clearing. The pinned Crossterm 0.29 Unix implementation answers that request by
writing the terminal status query `ESC[6n` and waiting for a cursor-position
reply. The laboratory's `forkpty` child has a kernel PTY, not a terminal
emulator, and `MacPtySession` only resizes, reads and writes it; it never
answers that query. Therefore the initial draw cannot run and the resulting
`Failure::Unavailable` is rendered only as `CUSTODY_UNAVAILABLE`. The buffered
Python stdout explains why the short adjacent log timestamps do not measure
the internal wait.

The bounded repair changes only those two sites to the backend's direct
fullscreen clear operation, which writes and flushes the clear command while
propagating its I/O error; it does not emulate a terminal, add a retry, extend
a deadline, relax a guard or select a fallback. At startup Ratatui's buffers
are empty, and after final lock/idle exit no later frame relies on the buffer,
so the direct operation does not require a cursor-preserving query at either
site. The real normal PTY harness now records raw bytes and rejects `ESC[6n`
during startup and exit, proving that the fixture does not conceal a future
cursor-query dependency. This static regression method and the repair require
the unchanged normal two-architecture native run; neither this diagnosis nor
the local source checks is a GREEN or acceptance claim.

Before native dispatch, static verification must establish that the new
harness parses, its command/fixture inventory is closed, its PTY driver waits
for visible input before Enter, and the workflow still invokes only the normal
entry point. Native success then requires every prior custody assertion plus
the integrated TUI assertion on both architectures. The separate merger must
also repeat `scripts/check.sh`, the clean locked/offline build and the complete
ordered Linux laboratory set after composition. None of those local gates,
the prior nine native tests, or run 18 substitutes for this native PTY run.

### Native run 22 observer RED and bounded correction

The Apple-silicon job for checkpoint `6c6bec` reached the normal TUI and
rendered its first screen, but the laboratory timed out while looking for
`Password required`. Its captured diagnostic representation contained
`Passwordrequired` and `Items(selectionismetadataonly)`. This is not evidence
that the product omitted spaces: the existing `MacPtySession` removed every
cursor-positioning CSI and concatenated the text bytes, so spaces represented
by untouched screen cells were lost. The result is a harness-observer RED,
not a product behavioral RED or acceptance result; the Intel outcome must be
reported separately.

The bounded test-only correction is a small VT screen observer in
`crates/pm-custody/tests/macos_lab.py`. It consumes the real `forkpty` bytes
incrementally and maintains the requested cursor, grid, wrap state and
application alternate-screen snapshot. Its accepted grammar is intentionally
closed around the pinned Crossterm output: cursor addressing/movement,
erase, SGR, the two private screen/cursor modes, basic C0 cursor controls,
strict UTF-8, and Unicode combining/wide-cell accounting. Any other escape
or control sequence fails with a fixed category; in particular `CSI 6n` is a
terminal-query failure and is never answered or ignored. Rows retain their
spaces and Unicode; no whitespace normalization, terminal-response
emulation, retry, deadline change, product change or optional terminal
dependency is introduced.

The parser regression feeds a cursor-positioned no-secret capture pattern one
byte at a time, including split UTF-8 and combining bytes, and verifies the
separated `Password required`/`Items (selection is metadata only)` rows,
resize, alternate-screen exit snapshot, and rejection of incomplete UTF-8 and
`CSI 6n`. The native TUI waits use the same observer over the actual captured
PTY stream; raw bytes remain available only for the existing secret, OSC52 and
DSR checks. Error messages do not include screen rows or raw bytes. The
parser-only GREEN is recorded in checkpoint `44160b1`; the next normal
two-architecture native result remains pending. This observer is not complete
Ticket 23--25 acceptance, which still requires the separately documented full
matrix.

The test-first chronology is recorded explicitly. Before the observer was
implemented, the new parser regression was run against the old
`MacPtySession` with this non-exclusive local command:

```text
python3 - <<'PY'
import importlib.util
path = 'crates/pm-custody/tests/macos_lab.py'
spec = importlib.util.spec_from_file_location('macos_lab', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.assert_screen_observer_regression()
PY
```

It exited with code 1 and the fixed assertion
`cursor-positioned screen regression: item title lost its separating cell`.
This intentional parser RED occurred while the Windows 27 exclusive window
was held; it was not a granted Cargo/Linux/native/system-lab gate and carries
no acceptance evidence. The import created only the test module's own
`crates/pm-custody/tests/__pycache__/`, which was removed by exact-path file
deletion and directory removal. No retry or fabricated pass followed. After
that RED, checkpoint `1820b8b` added `VtScreen`; checkpoint `44160b1` then
made wide-cell, `CSI 1J`, and zero-parameter movement cases explicit and the
parser-only regression passed. The parser result is not native evidence.

### Native run 23 event-boundary RED and bounded fixture correction

Run [`34853427359`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34853427359)
on `44160b1` compiled the ordinary binaries and applicable native tests on
Intel and Apple silicon, and both jobs passed native preflight, the exact
toolchain, dependency fetch, unit-test and architecture checks. Both then
failed inside the test-only TUI fixture before any `PASS macos-tui-core` line.

The Apple-silicon job timed out in `tui_search` while waiting for the
`Search (engine-decrypted):` screen. The captured log contains no screen dump,
secret, or internal product phase, so this is an unclassified fixture
observation RED rather than evidence of a product search failure. The Intel
job reached field selection and reported `selected password field was not
rendered` after the fixture sent fourteen `j` bytes. The old helper could stop
on any historical frame containing the field label before the current frame's
highlight marker had rendered; this is also an observer synchronization RED,
not product acceptance evidence.

The bounded test-only correction keeps the same `forkpty`, product binary,
live service and fixed deadlines. `MacPtySession.mark()` drains bytes already
queued by the PTY and records an event-count boundary instead of using a raw
byte offset. `wait_text()` and the new `wait_selected()` inspect only the
current screen after that boundary; the latter requires the exact highlighted
row. A local resize changes decoder geometry but no longer creates a
synthetic screen event. Search explicitly marks the post-prompt transition
before submitting the query. Timeout diagnostics expose only fixed categories:
`mode` (primary/alternate), `render` (known screen class/other), `event`
(`post-mark`/`none`), parser state and child state; they never print rows, raw
bytes, paths or secrets. The regression preserves event history for terminal
exit while proving stale history cannot satisfy a current-screen wait.

This correction has only static AST and diff checks so far; no local Cargo,
system lab, native rerun or complete Ticket 23--25 acceptance is claimed. The
next native run must still prove the normal two-architecture TUI core and the
separately documented full keyboard matrix.

### Native run 24 pasteboard negative-observation correction

Run [`34855277724`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34855277724)
on `f1a1a51` reached the real TUI copy assertion on both authorized macOS
targets after the ordinary build, unit tests and architecture checks passed.
The human-side read is the exact `TUI_PASSWORD_RECORD` control in the harness;
the traceback therefore shows that this positive control completed before the
agent-side probe. This is not native acceptance: Intel's `_pmagent26`
`osascript` probe timed out after the existing 30-second bound, while Apple
silicon returned exit code `0` from the same command.

The old assertion required `returncode != 0` and checked that the exact canary
was absent from captured stdout and stderr. The Apple-silicon traceback prints
only the return code, not either captured stream. Consequently the run proves
neither that the agent extracted the canary nor that it was isolated from the
human pasteboard; it records only `rc=0`. The Intel timeout similarly has no
completed read result. The later PTY-close `incomplete-control` error is a
separate cleanup observation and cannot classify the pasteboard result.

Static inspection also found a fixture boundary that must be distinguished
before changing the negative test: the agent command is launched as a direct
`sudo -u _pmagent26 osascript` child of the logged-in human harness. It does
not explicitly enter a distinct launchd bootstrap or login session. The
production service is separately installed as a system LaunchDaemon under
`_passwordmanager`; that service's domain is not evidence about the agent
probe's GUI session. Apple's session model makes login/bootstrap sessions a
relevant boundary, and Apple's launchd guidance distinguishes system daemons
from per-user agents ([Root and Login Sessions](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPMultipleUsers/Concepts/SystemContexts.html),
[Creating Launch Daemons and Agents](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)).
The possibility that the UID-switched child retains the caller's bootstrap is
a source-supported fixture hypothesis, not a native finding; no product or
fixture session change is authorized by this record.

The bounded pasteboard-only correction records the missing distinction under
the separate `--pasteboard-diagnostic` harness/workflow opt-in. It uses the
ordinary binary and ordinary LaunchDaemon plist, without the
`macos-ticket26-diagnostics` feature or `PM_MACOS_TICKET26_DIAGNOSTIC=1`.
It emits only fixed categories, never the canary, captured bytes, numeric UIDs,
paths or OS error text:

- `pasteboard-human-canary-read=yes|no` records the exact human positive
  control before the negative probe;
- `pasteboard-agent-result=zero|nonzero|timeout`,
  `pasteboard-agent-canary-stdout=present|absent` and
  `pasteboard-agent-canary-stderr=present|absent` distinguish command outcome
  from exact-canary exposure;
- `pasteboard-agent-success-read=yes|no|indeterminate` is `yes` only when the
  exact human canary is observed in either captured stream, `no` for a completed
  result without that canary (including `rc=0` with empty/different output),
  and `indeterminate` for the existing timeout;
- `pasteboard-human-identity` and `pasteboard-agent-identity` classify the
  expected synthetic identity without printing its UID; and
- `pasteboard-human-domain`, `pasteboard-agent-domain` and
  `pasteboard-domain-relation` classify `launchctl manageruid` as
  `system|human|other|unavailable|unparseable`. The two raw manager UIDs are
  parsed and compared internally before their categories are emitted, so two
  `other` categories are not treated as equal merely because their labels
  match. The relation is only `same|different|indeterminate`. The command's
  bootstrap-namespace meaning follows the documented
  [`launchctl manageruid`](https://github.com/apple-oss-distributions/launchd/blob/main/man/launchctl.1)
  interface; neither numeric output is printed.

The negative assertion now rejects exact-canary exposure or an indeterminate
timeout, but does not reject a completed zero exit solely because it is zero:
the human exact-canary control and the categorical identity/domain evidence
must be considered together. This is an evidence correction, not a claim that
the run proved isolation or a relaxation of the native G1 requirement. A
future native pasteboard-diagnostic run must capture these fixed categories
before any decision to redesign the agent fixture; normal mode remains
uses the ordinary binary/plist and emits no diagnostic output.

The isolation scenario now uses the product's maximum/default 30-second copy
lease, and reads the exact human canary immediately before and immediately
after the agent probe. The added identity/domain commands and the existing
agent `osascript` call must complete within that unchanged lease; a failed
post-probe human control is not reinterpreted as agent denial. The separate
expiry scenario remains explicit: a fresh TUI uses the existing 5-second copy
lease, replaces the canary from another application, and requires the normal
expiry/ownership result. This preserves both the long-lease isolation
observation and the short-lease expiry race without changing product limits.

The checkpoint has only had a Python AST parse and static diff inspection on
the Linux host; no local Cargo, macOS runtime, system lab or native acceptance
is claimed. The Mac24 result remains a RED with canary exposure status
`indeterminate` (ARM `rc=0`, Intel timeout), not evidence of extraction.

### Native run 25: shared-bootstrap control negative and isolated-job correction

Run [`34858597883`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34858597883)
on `73e9175` was dispatched with the separate pasteboard observation option.
Both `macos-15-intel` and `macos-15` passed environment validation, the locked
build/tests and architecture checks, then failed in the pasteboard laboratory.
The fixed observations on each target were:

```text
human-canary-before=yes
agent-result=zero canary-stdout=present canary-stderr=absent success-read=yes
human-identity=expected agent-identity=expected
human-domain=human agent-domain=human domain-relation=same
human-canary-after=yes
```

The exact synthetic human canary was therefore present in the agent probe's
captured stdout. The matching `human` launchd-domain categories were obtained
from the raw manager UID comparison, not from the account names. This is a
reproducible **control negative** for the unsafe fixture shape: a direct
`sudo -u _pmagent26 osascript` child inherits the logged-in harness bootstrap
and cannot be counted as an isolated agent. It is not a product failure or an
isolation PASS, and the control must remain labelled unsupported even if a
future runner happens not to expose the canary. The later
`incomplete-control`/PTY-cleanup error is separate cleanup evidence and does
not weaken the canary observation.

The bounded fixture correction is based on the selected isolation profile,
not on changing the product or lowering the negative assertion. Apple's
[daemon/agent guidance](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
requires `UserName`/`GroupName` to be supplied by launchd for a root-managed
job and distinguishes the system daemon bootstrap from per-user agents. Apple's
[root/login-session model](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPMultipleUsers/Concepts/SystemContexts.html)
also treats bootstrap/session boundaries as a real IPC security boundary.
The fixture therefore does the following, in order:

1. Retains the shared-bootstrap control only as explicitly labelled supporting
   evidence. It never contributes to the isolation assertion or a PASS line.
2. Before any copy operation, creates a fresh root-owned, `0644` temporary
   plist and root-owned, non-writable helper under the collision-guarded
   fixture root. It bootstraps the helper in the **system** launchd domain with
   `UserName` and `GroupName` set to `_pmagent26`,
   `LimitLoadToSessionType=System`, `RunAtLoad=false` and
   `LaunchOnlyOnce=true`; an explicit `launchctl kickstart` starts the one-shot
   only after a fresh TUI copy lease. The synthetic account keeps
   `UserShell=/usr/bin/false` and `NFSHomeDirectory=/var/empty`; it has no
   login session. Its result, stdout and stderr files are pre-created inside
   its own `0700` directory and are tracked as owned resources. The plist
   carries only the marker length and a SHA-256 digest for exact-stream
   matching; the canary plaintext is never put in launchd arguments or the
   `0644` plist.
3. The helper records only fixed categories for its effective UID,
   `launchctl manageruid`, `launchctl managername`, and the parsed relation to
   the human harness manager. The manager UID category must be `system` and
   the combined manager-domain relation must be `different`; a merely
   different account label is insufficient. It then executes the **same** public
   `/usr/bin/osascript -e 'the clipboard as text'` probe as the agent. The
   harness requires the launched process UID and manager domain to be
   different from the human context before interpreting the probe. Missing or
   malformed manager metadata is indeterminate, never a fallback.
4. The shared-bootstrap control is run only as a separately labelled
   supporting negative. The isolated scenario then starts a fresh TUI and
   fresh 30-second copy lease, reads the exact human canary immediately before
   and immediately after the isolated-job probe, and kicks the already-loaded
   system job only after the copy. A completed result without the canary is a
   denial; exact-canary stdout/stderr exposure fails; timeout, missing result,
   unknown exit state or failed post-control remains a failure/indeterminate
   result. The helper allows the fixed `2*10s` manager metadata bounds plus the
   fixed `30s` public probe bound and a bounded launch margin; this is only a
   fixture lifecycle bound and never extends the product copy lease. No extra
   retry, lease extension, clipboard implementation or product diagnostic
   feature is used. The existing 5-second expiry case remains a separate
   scenario.
5. Cleanup first boots out the owned system-domain job, verifies no owned PID
   or label remains, then removes only the helper/plist/result files and
   directories recorded by the fixture. It propagates every bootout, close and
   removal error. PTY EOF finalization remains strict: an incomplete VT
   control is recorded as a cleanup error, but cleanup continues and the
   original behavioral error is preserved as the primary failure; the parser
   is not made permissive.

This is a test-only fixture correction and a method checkpoint. A future native
run must show the isolated job's UID/domain relation as `different`, both human
pre/post controls as `yes`, and no exact canary in either captured stream on
both architectures before any isolation evidence is considered. The shared
bootstrap control remains a documented negative, not acceptance evidence.

### Run 26 TUI fixture diagnosis and bounded correction

Native run 34862828726 on `d514233` reached the TUI fixture on both
architectures but did not reach the isolated pasteboard probe. The Apple
silicon job timed out while waiting for the selected
`auth[0].password` row in a fresh `80x24` session. Its fixed observer state was
`mode=alternate render=field-list event=post-mark parser=ground child=alive`.
The Intel job reached the same shared-bootstrap control, whose agent probe
used its existing 30-second bound and returned `timeout`; it then failed the
first session's `wait_exit(timeout=8)` assertion after sending `l`. The run
therefore proves neither isolated pasteboard behavior nor a product exit
failure. No raw PTY screen or agent output was captured, and no local runtime
reproduction is claimed.

Static inspection found the concrete ARM fixture defect: every fresh TUI
session resets `App.selected` to catalog index zero, while only the first
session searched for `Password` before calling `select_tui_password_for_copy`.
The isolated and expiry sessions sent fourteen field-navigation keys from an
unspecified catalog item, so the selected row was not necessarily
`auth[0].password`. The bounded correction searches for the synthetic
`Password` catalog title in each fresh session before opening the explicit
field list. The field index remains the existing contract-driven fourteen;
there is no implicit field substitution or catalog-order assumption.

The Intel failure is not independently localized by this run. Static
inspection identifies a bounded fixture-lifecycle ambiguity: the unsupported
shared-bootstrap negative was run inside the same TUI session that had the
existing 30-second idle bound. If its direct agent probe consumed that bound,
the subsequent `l` assertion could race the already-defined TUI idle behavior.
The correction runs that same real TUI copy plus shared bootstrap probe in a
disposable, separately labelled control session, then runs the ordinary
keyboard session without the control's external wait. It does not alter the
product idle bound, the copy lease, the probe bound, the agent assertion, or
cleanup policy; the shared control remains unsupported evidence and never
contributes to acceptance. Its cleanup records a fixed exit category and
return code: `natural-zero`, `natural-nonzero`, `owned-termination`, or
`unknown`. A naturally observed nonzero child status remains a failure; a
signal-derived code is not accepted merely because it is `143`: only the exact
`128 + SIGTERM` code is `owned-termination`, and only when this fixture sent
that cleanup signal. Any other nonzero code remains `natural-nonzero`, even if
a signal was sent; `unknown` is not accepted. If the control session exits or
cleanup fails, the categorized control result or cleanup failure remains
visible. The next native run must confirm whether this removes the Intel
ambiguity; it is not claimed as a verified product or fixture cause here.

The next native run must first show the fresh-session title searches and
complete the existing first/isolated/expiry TUI flows before interpreting the
isolated system-launchd result. It must retain the shared-bootstrap control as
`unsupported`, require the existing human pre/post canary controls, and keep
the normal generic failure path. A native pass of the revised fixture is not
by itself Ticket 26 acceptance: the full TUI 23--25 matrix, reboot/FileVault,
signing/notarization and final integration gates remain separate.

The checkpoint was prepared statically on Linux only: Python AST parsing,
shell syntax checks, the macOS custody checker, and `git diff --check` pass for
this correction. No Cargo, build, parser runtime, system lab or native run was
executed for this correction; native behavior remains pending.

### Native run 27 shared-control PTY-close RED and bounded correction

The subsequent native run on `a3db150` failed on both authorized macOS
architectures in the supporting shared-bootstrap control before the isolated
agent job. The run's fixed logs are
`/tmp/pm-macos-run27-arm-full.log` and
`/tmp/pm-macos-run27-intel-full.log`. The control's direct pasteboard probe
remained supporting, non-acceptance evidence. Its still-running TUI was then
closed by `MacPtySession.close()`, which sent the fixture's cleanup `SIGTERM`;
strict PTY finalization consequently observed an incomplete VT control and
reported `incomplete-control`. This is a fixture teardown RED, not evidence of
pasteboard isolation or a product TUI failure, and the raw PTY stream remains
unmodified.

The bounded correction keeps strict parsing, checked cleanup and the exact
exit classifier. After the shared probe, the harness first observes whether
the child has already exited. If it is still alive, it sends the existing
human `l` key and requires `wait_exit(timeout=8) == 0`, allowing the normal
TUI path to finish its VT stream before cleanup closes the PTY. An already
exited child is not signalled and is classified from its natural status.
Thus the successful path must report `natural-zero returncode=0`; every
nonzero or unknown status remains a failure. The strict SIGTERM cleanup path
is retained only for an exceptional failure before normal close and is not a
successful-control fallback. No product code, deadline, pasteboard assertion,
or isolation boundary changed.

This candidate has only static Python AST, shell syntax, macOS-checker and
diff checks on Linux; no local Cargo, parser runtime, system lab or native
rerun was executed. The next native run must show the categorized
`natural-zero returncode=0` result on both architectures before the shared
control can be considered clean; it still cannot count as Ticket 26
acceptance.

## Remaining acceptance work

- Compose and verify the complete keyboard TUI through the normal
  non-diagnostic binary; run 18 verifies that binary's custody flow but not the
  TUI command or Ticket 23--25 keyboard operations.
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
