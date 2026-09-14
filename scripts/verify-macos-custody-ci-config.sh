#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
workflow="$root/.github/workflows/macos-custody-acceptance.yml"
method="$root/docs/verification/ticket-26.md"
lab="$root/scripts/test-macos-custody-lab.sh"
harness="$root/crates/pm-custody/tests/macos_lab.py"
fetch="$root/scripts/fetch-dependencies.sh"
custody_manifest="$root/crates/pm-custody/Cargo.toml"
custody_source="$root/crates/pm-custody/src/linux.rs"
vault_manifest="$root/crates/pm-vault/Cargo.toml"
vault_source="$root/crates/pm-vault/src/human.rs"
crypto_manifest="$root/crates/pm-crypto/Cargo.toml"
crypto_source="$root/crates/pm-crypto/src/root.rs"
crypto_diagnostic_test="$root/crates/pm-crypto/tests/ticket26_diagnostics.rs"
metadata_parser="$root/scripts/extract-libsodium-build-metadata.py"
workspace_manifest="$root/Cargo.toml"

for file in "$workflow" "$method" "$lab" "$harness" "$fetch" "$custody_manifest" "$custody_source" "$vault_manifest" "$vault_source" "$crypto_manifest" "$crypto_source" "$crypto_diagnostic_test" "$metadata_parser" "$workspace_manifest"; do
    test -f "$file" || {
        echo "required macOS custody CI file is absent: $file" >&2
        exit 1
    }
done
test -x "$lab" || {
    echo 'macOS custody laboratory is not executable' >&2
    exit 1
}

require_literal() {
    grep -Fq -- "$1" "$2" || {
        echo "required macOS custody CI contract is absent from $2: $1" >&2
        exit 1
    }
}
require_count() {
    actual=$(awk -v needle="$1" 'index($0, needle) { count++ } END { print count + 0 }' "$3")
    test "$actual" -eq "$2" || {
        echo "macOS custody CI contract count mismatch: expected $2 for '$1', got $actual" >&2
        exit 1
    }
}
require_exact_count() {
    actual=$(awk -v needle="$1" '$0 == needle { count++ } END { print count + 0 }' "$3")
    test "$actual" -eq "$2" || {
        echo "macOS custody CI exact-line count mismatch: expected $2 for '$1', got $actual" >&2
        exit 1
    }
}

require_literal '  workflow_dispatch:' "$workflow"
require_literal '  contents: read' "$workflow"
require_literal "  RUSTUP_AUTO_INSTALL: '0'" "$workflow"
require_literal '    RUSTUP_HOME: ${{ github.workspace }}/.toolchain/rustup' "$workflow"
require_literal '    CARGO_HOME: ${{ github.workspace }}/.toolchain/cargo' "$workflow"
require_literal '    RUSTUP_TOOLCHAIN: 1.98.1-${{ matrix.rust_host }}' "$workflow"
require_literal "rustup toolchain install \"\$RUSTUP_TOOLCHAIN\" --profile minimal --no-self-update" "$workflow"
require_count 'rustup toolchain install' 1 "$workflow"
require_literal './scripts/ci/native-preflight-unix.sh' "$workflow"
require_literal './scripts/fetch-dependencies.sh' "$workflow"
require_literal 'PM_MACOS_EPHEMERAL_CI=1 ./scripts/test-macos-custody-lab.sh' "$workflow"
require_count '          persist-credentials: false' 1 "$workflow"
require_exact_count '            runner: macos-15-intel' 1 "$workflow"
require_exact_count '            runner: macos-15' 1 "$workflow"
require_count '          - target:' 2 "$workflow"

checkout='actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1 (Node 24)'
require_count "      - uses: $checkout" 1 "$workflow"
uses_count=$(grep -Ec '^[[:space:]]+- uses:' "$workflow")
test "$uses_count" -eq 1 || {
    echo "macOS custody CI must contain exactly one pinned action, got $uses_count" >&2
    exit 1
}

preflight_line=$(grep -nF './scripts/ci/native-preflight-unix.sh' "$workflow" | cut -d: -f1)
fetch_line=$(grep -nF './scripts/fetch-dependencies.sh' "$workflow" | cut -d: -f1)
lab_line=$(grep -nF 'PM_MACOS_EPHEMERAL_CI=1 ./scripts/test-macos-custody-lab.sh' "$workflow" | cut -d: -f1)
test "$preflight_line" -lt "$fetch_line" && test "$fetch_line" -lt "$lab_line" || {
    echo 'macOS custody CI phases are not ordered preflight -> fetch -> offline laboratory' >&2
    exit 1
}

if grep -Eiq '(^|[^[:alnum:]_-])(push|pull_request|schedule):|continue-on-error|secrets\.|upload-artifact|actions/cache|ubuntu|windows|-(xlarge|large)([^[:alnum:]_-]|$)|qemu|rosetta|cross[ -]?compil|rustup[[:space:]]+(default|override|update)|curl|wget|brew[[:space:]]+install|\|\|[[:space:]]+true' "$workflow"; then
    echo 'macOS custody CI contains a forbidden trigger, target, secret, cache, artifact, emulation or fallback' >&2
    exit 1
fi

require_literal '[macOS custody acceptance workflow](../../.github/workflows/macos-custody-acceptance.yml)' "$method"
require_literal 'fetch --locked' "$fetch"
require_literal '--locked --offline' "$lab"
require_literal 'lipo -archs' "$lab"
require_literal 'configure_ticket26_build_commands()' "$lab"
require_literal 'configure_ticket26_harness_command()' "$lab"
require_literal 'build_command=(' "$lab"
require_literal 'test_command=(' "$lab"
require_literal '-p pm-native-channel -p pm-vault -p pm-crypto -p pm-custody --locked --offline' "$lab"
require_literal 'harness_command=(python3' "$lab"
require_literal 'scratch = pathlib.Path("/private/var/tmp/passwordmanager-ticket26")' "$harness"
require_literal 'require_owner_mode(scratch.parent, (0, 0o1777))' "$harness"
require_literal 'stat.S_IMODE(full_mode)' "$harness"
require_literal 'scratch.mkdir(mode=0o711)' "$harness"
require_literal 'synthetic keygen failed' "$harness"
require_literal 'cross_uid_peer_diagnostic(agent_uid, scratch)' "$harness"
require_literal 'assert launchd_peer_uid(AGENT, RUNTIME / "agent.sock") == custodian_uid' "$harness"
require_literal 'pid, master = pty.fork()' "$harness"
require_literal 'termios.TIOCSWINSZ' "$harness"
require_literal 'self.wait_text(f"Input: {value}", since=start)' "$harness"
require_literal 'wait_exit(timeout=8)' "$harness"
require_literal 'human-content-flow' "$harness"
require_literal 'assert_agent_cannot_read_pasteboard' "$harness"
require_literal 'osascript' "$harness"
require_literal 'run_tui_core_lab(' "$harness"
require_literal 'tui_core_verified = True' "$harness"
require_literal 'macos-ticket26-diagnostics = ["pm-vault/macos-ticket26-diagnostics"]' "$custody_manifest"
require_literal 'macos-ticket26-diagnostics = ["pm-crypto/macos-ticket26-diagnostics"]' "$vault_manifest"
require_literal 'macos-ticket26-diagnostics = []' "$crypto_manifest"
require_literal '--features macos-ticket26-diagnostics' "$lab"
require_literal '--message-format=json-render-diagnostics' "$lab"
require_literal 'scripts/extract-libsodium-build-metadata.py' "$lab"
require_literal 'source/libsodium-stable/config.log' "$lab"
require_literal 'PACKAGE_SUFFIX = "#libsodium-sys-stable@1.24.0"' "$metadata_parser"
require_literal 'message.get("reason") != "build-script-executed"' "$metadata_parser"
require_literal '[profile.dev.package."libsodium-sys-stable:1.24.0"]' "$workspace_manifest"
require_literal 'opt-level = 2' "$workspace_manifest"
if grep -Eq 'libsodium-sys-stable.*features.*optimized|march=native|mtune=native' "$workspace_manifest"; then
    echo 'portable libsodium optimization was replaced by target-native tuning' >&2
    exit 1
fi
require_literal 'PM_MACOS_TICKET26_DIAGNOSTIC' "$harness"
require_literal 'feature = "macos-ticket26-diagnostics"' "$custody_source"
require_literal 'feature = "macos-ticket26-diagnostics"' "$vault_source"
require_literal 'open_human_root_diagnostic' "$crypto_source"
require_literal 'KdfDiagnosticBoundary::Start, KdfDiagnosticBoundary::End' "$crypto_diagnostic_test"
require_literal 'PM26_DIAGNOSTIC unlock-phase={}' "$vault_source"
require_literal 'PM26_DIAGNOSTIC vault-root-create-ms=' "$harness"
require_literal 'PM26_DIAGNOSTIC sodium-cflags=' "$harness"
require_literal 'native libsodium build metadata is unavailable or ambiguous' "$harness"
require_literal 'ticket26_diagnostic_error' "$custody_source"
require_literal 'PM26_DIAGNOSTIC error=' "$custody_source"
require_literal 'client-human-unlock-result=' "$custody_source"
require_literal 'server-human-unlock-result=' "$custody_source"
require_literal 'PM26_DIAGNOSTIC launchd-service=' "$harness"
require_literal 'classify_launchd_service(launchd, service_pid)' "$harness"
require_literal 'libc::F_GETFL' "$custody_source"
require_literal 'set_nonblocking(false)' "$custody_source"
require_literal 'accepted-stream-nonblocking-before=' "$custody_source"
require_literal 'accepted-stream-nonblocking-after=' "$custody_source"
require_literal 'require_readable_regular(AGENT, agent_profile' "$harness"
require_literal 'require_readable_regular(AGENT, agent_key' "$harness"
require_literal 'os.chmod(sys.argv[1], 0o666)' "$harness"
require_literal 'human_authorization_setup' "$harness"
require_literal 'path_exists=os.path.lexists' "$harness"
require_literal 'require_safe_existing_parent(install_parent)' "$harness"
require_literal 'owned_empty_directories.append(("install-parent", install_parent))' "$harness"
require_literal 'attempt(f"rmdir-{name}", ["rmdir", path])' "$harness"
require_literal '"env", f"{DIAGNOSTIC_ENV}=1"' "$harness"
require_literal 'plist_to_install = source_plist' "$harness"
require_literal 'diagnostic=diagnostic' "$harness"
require_literal 'classify_native_sodium(sodium_config, diagnostic)' "$harness"
require_literal 'assert DIAGNOSTIC_ENV not in os.environ' "$harness"
require_literal '"normal mode created a diagnostic log"' "$harness"
if grep -Fq 'RUNNER_TEMP' "$harness"; then
    echo 'macOS custody laboratory still depends on the private runner temp root' >&2
    exit 1
fi
if grep -Eq 'wl-copy|pbcopy|OSC52|tmux' "$harness"; then
    echo 'macOS TUI laboratory contains a non-AppKit clipboard or simulated-terminal path' >&2
    exit 1
fi
if grep -Fq 'macos-ticket26-diagnostics' "$workflow" ||
   grep -Fq 'PM_MACOS_TICKET26_DIAGNOSTIC' "$workflow" ||
   grep -Fq 'PM_MACOS_TICKET26_DIAGNOSTIC' "$root/packaging/macos/com.santanajcp.passwordmanager.plist"; then
    echo 'macOS ticket-26 diagnostics escaped the explicit laboratory fixture' >&2
    exit 1
fi

bash -u -s -- "$lab" <<'SH'
source "$1"

count_argument() {
    local expected="$1"
    shift
    local count=0 argument
    for argument in "$@"; do
        if [[ "$argument" == "$expected" ]]; then
            count=$((count + 1))
        fi
    done
    [[ "$count" == 1 ]]
}

configure_ticket26_build_commands normal /synthetic-ticket26
[[ "${build_command[*]}" != *macos-ticket26-diagnostics* ]]
[[ "${test_command[*]}" != *macos-ticket26-diagnostics* ]]
printf '%s\n' "${build_command[@]}" "${test_command[@]}" >/dev/null
configure_ticket26_harness_command normal /synthetic-ticket26 /synthetic-config.log
[[ "${harness_command[*]}" != *--diagnostic* ]]
printf '%s\n' "${harness_command[@]}" >/dev/null

configure_ticket26_build_commands diagnostic /synthetic-ticket26
count_argument macos-ticket26-diagnostics "${build_command[@]}"
count_argument macos-ticket26-diagnostics "${test_command[@]}"
printf '%s\n' "${build_command[@]}" "${test_command[@]}" >/dev/null
configure_ticket26_harness_command diagnostic /synthetic-ticket26 /synthetic-config.log
count_argument --diagnostic "${harness_command[@]}"
printf '%s\n' "${harness_command[@]}" >/dev/null
SH

PYTHONDONTWRITEBYTECODE=1 python3 - "$harness" <<'PY'
import contextlib
import importlib.util
import io
import pathlib
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("pm_macos_lab", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

normal, paths = module.parse_lab_arguments(["custody", "cli", "plist", "config"])
assert normal is False and len(paths) == 4
diagnostic, paths = module.parse_lab_arguments(
    ["--diagnostic", "custody", "cli", "plist", "config"]
)
assert diagnostic is True and len(paths) == 4
for rejected in (
    ["--unknown", "cli", "plist", "config"],
    ["--diagnostic", "--unknown", "cli", "plist", "config"],
    ["custody", "cli", "plist"],
):
    try:
        module.parse_lab_arguments(rejected)
    except AssertionError:
        pass
    else:
        raise AssertionError("unknown or incomplete laboratory mode was accepted")

with tempfile.TemporaryDirectory() as temporary:
    config = pathlib.Path(temporary) / "config.log"
    config.write_bytes(b"CFLAGS='-O2 -g'\n")
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        module.classify_native_sodium(config, False)
    assert output.getvalue() == "PASS macos-libsodium cflags=optimized\n"
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        module.classify_native_sodium(config, True)
    assert output.getvalue() == "PM26_DIAGNOSTIC sodium-cflags=optimized\n"
    config.write_bytes(b"CFLAGS='-O0 -g'\n")
    try:
        module.classify_native_sodium(config, False)
    except AssertionError as error:
        assert "not optimized" in str(error)
    else:
        raise AssertionError("unoptimized native libsodium metadata was accepted")

assert module.parse_owner_mode("0 041777") == (0, 0o1777)
assert module.parse_owner_mode("501 0100400") == (501, 0o400)
assert module.parse_regular_metadata("502 0100400 1 128") == (502, 0o400, 1, 128)
try:
    module.parse_owner_mode("0 0120777")
except AssertionError as error:
    assert "symbolic link" in str(error)
else:
    raise AssertionError("symbolic-link metadata was accepted")

try:
    module.parse_regular_metadata("502 0120777 1 128")
except AssertionError as error:
    assert "not a regular file" in str(error)
else:
    raise AssertionError("non-regular readable fixture was accepted")

assert module.diagnostic_lines(b"PM26_DIAGNOSTIC phase=client-profile\n") == [
    b"PM26_DIAGNOSTIC phase=client-profile"
]
assert module.diagnostic_lines(
    b"PM26_DIAGNOSTIC accepted-stream-nonblocking-before=1\n"
) == [b"PM26_DIAGNOSTIC accepted-stream-nonblocking-before=1"]
assert module.diagnostic_lines(
    b"PM26_DIAGNOSTIC error=server-human-setup-password-commit\n"
) == [b"PM26_DIAGNOSTIC error=server-human-setup-password-commit"]
assert module.diagnostic_lines(
    b"PM26_DIAGNOSTIC client-human-unlock-result=timeout elapsed-ms=15001\n"
) == [b"PM26_DIAGNOSTIC client-human-unlock-result=timeout elapsed-ms=15001"]
assert module.diagnostic_lines(
    b"PM26_DIAGNOSTIC server-human-unlock-result=ok elapsed-ms=14999\n"
) == [b"PM26_DIAGNOSTIC server-human-unlock-result=ok elapsed-ms=14999"]
assert module.diagnostic_lines(
    b"PM26_DIAGNOSTIC launchd-service=same-pid\n"
) == [b"PM26_DIAGNOSTIC launchd-service=same-pid"]
assert module.diagnostic_lines(
    b"PM26_DIAGNOSTIC unlock-phase=kdf-end elapsed-ms=15001\n"
) == [b"PM26_DIAGNOSTIC unlock-phase=kdf-end elapsed-ms=15001"]
assert module.diagnostic_lines(
    b"PM26_DIAGNOSTIC vault-root-create-ms=24001\n"
) == [b"PM26_DIAGNOSTIC vault-root-create-ms=24001"]
assert module.diagnostic_lines(
    b"PM26_DIAGNOSTIC sodium-cflags=opt0\n"
) == [b"PM26_DIAGNOSTIC sodium-cflags=opt0"]
assert module.parse_sodium_cflags(b"CFLAGS='-O0 -g'\n") == b"opt0"
assert module.parse_sodium_cflags(b"CFLAGS='-O2 -g'\n") == b"optimized"
for rejected in (b"", b"CFLAGS='-Og'\n", b"CFLAGS='-O0 -O2'\n"):
    try:
        module.parse_sodium_cflags(rejected)
    except AssertionError:
        pass
    else:
        raise AssertionError("ambiguous native libsodium metadata was accepted")

owned_paths = [("state", pathlib.Path("/synthetic-ticket26-owned-state"))]
owned_empty_directories = [("install-parent", pathlib.Path("/synthetic-ticket26-parent"))]
owned_records = ["/Groups/_synthetic26", "/Users/_synthetic26"]
success_calls = []
def successful_cleanup(command, *, check):
    assert check is False
    success_calls.append(tuple(map(str, command)))
    if command[:2] == ["launchctl", "list"]:
        stdout = b"PID\tStatus\tLabel\n1\t0\tcom.apple.synthetic\n"
    elif command[:3] == ["dscl", ".", "-list"]:
        stdout = b"root\nnobody\n"
    else:
        stdout = b""
    return type("Result", (), {"returncode": 0, "stdout": stdout})()
assert module.cleanup_owned_resources(
    True, owned_paths, owned_empty_directories, owned_records,
    successful_cleanup, lambda _path: False
) == []
assert len(success_calls) == 8
assert success_calls.index(("rm", "-rf", "/synthetic-ticket26-owned-state")) < \
       success_calls.index(("rmdir", "/synthetic-ticket26-parent"))

failure_calls = []
def failing_cleanup(command, *, check):
    assert check is False
    failure_calls.append(tuple(map(str, command)))
    return type("Result", (), {"returncode": 9, "stdout": b""})()
cleanup_errors = module.cleanup_owned_resources(
    True, owned_paths, owned_empty_directories, owned_records,
    failing_cleanup, lambda _path: False
)
assert len(failure_calls) == 8 and len(cleanup_errors) == 8
aggregate = module.OwnedCleanupError(cleanup_errors)
assert len(aggregate.errors) == 8
assert "launchd-bootout" in str(aggregate) and "delete-user" in str(aggregate)
assert "rmdir-install-parent" in str(aggregate)

interrupt = KeyboardInterrupt()
interrupt_calls = []
def interruption_cleanup(command, *, check):
    interrupt_calls.append(tuple(map(str, command)))
    return type("Result", (), {"returncode": 0, "stdout": b""})()
try:
    module.finish_owned_resources(
        interrupt, False, owned_paths, [], [], interruption_cleanup
    )
except KeyboardInterrupt as caught:
    assert caught is interrupt
else:
    raise AssertionError("interruption was not re-raised after owned cleanup")
assert len(interrupt_calls) == 1
try:
    module.finish_owned_resources(
        interrupt, False, owned_paths, [], [], failing_cleanup
    )
except KeyboardInterrupt as caught:
    assert caught is interrupt
    assert isinstance(caught.__cause__, module.OwnedCleanupError)
else:
    raise AssertionError("cleanup failure replaced the original interruption")
result = type("Result", (), {
    "returncode": 0, "stdout": b"state = running\n\tpid = 321\n", "stderr": b""
})()
assert module.classify_launchd_service(result, 321) == b"same-pid"
assert module.classify_launchd_service(result, 654) == b"different-pid"
result.returncode = 1
assert module.classify_launchd_service(result, 321) == b"unavailable"
result.returncode = 0
result.stdout = b"state = running\n"
assert module.classify_launchd_service(result, 321) == b"unparseable"
try:
    module.diagnostic_lines(b"PM26_DIAGNOSTIC phase=client-profile path=/secret\n")
except AssertionError:
    pass
else:
    raise AssertionError("dynamic diagnostic content was accepted")

module.owner_mode = lambda _path: (501, 0o755)
try:
    module.require_owner_mode("/synthetic-parent", (0, 0o1777))
except AssertionError as error:
    diagnostic = str(error)
    assert "expected=(0, 1023)" in diagnostic
    assert "actual=(501, 493)" in diagnostic
else:
    raise AssertionError("owner/mode mismatch omitted its observed metadata")
PY
