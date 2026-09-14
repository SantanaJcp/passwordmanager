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

for file in "$workflow" "$method" "$lab" "$harness" "$fetch" "$custody_manifest" "$custody_source"; do
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
require_literal 'scratch = pathlib.Path("/private/var/tmp/passwordmanager-ticket26")' "$harness"
require_literal 'require_owner_mode(scratch.parent, (0, 0o1777))' "$harness"
require_literal 'stat.S_IMODE(full_mode)' "$harness"
require_literal 'scratch.mkdir(mode=0o711)' "$harness"
require_literal 'synthetic keygen failed' "$harness"
require_literal 'cross_uid_peer_diagnostic(agent_uid, scratch)' "$harness"
require_literal 'assert launchd_peer_uid(AGENT, RUNTIME / "agent.sock") == custodian_uid' "$harness"
require_literal 'macos-ticket26-diagnostics = []' "$custody_manifest"
require_literal '--features macos-ticket26-diagnostics' "$lab"
require_literal 'PM_MACOS_TICKET26_DIAGNOSTIC' "$harness"
require_literal 'feature = "macos-ticket26-diagnostics"' "$custody_source"
require_literal 'ticket26_diagnostic_error' "$custody_source"
require_literal 'PM26_DIAGNOSTIC error=' "$custody_source"
require_literal 'libc::F_GETFL' "$custody_source"
require_literal 'set_nonblocking(false)' "$custody_source"
require_literal 'accepted-stream-nonblocking-before=' "$custody_source"
require_literal 'accepted-stream-nonblocking-after=' "$custody_source"
require_literal 'require_readable_regular(AGENT, agent_profile' "$harness"
require_literal 'require_readable_regular(AGENT, agent_key' "$harness"
require_literal 'os.chmod(sys.argv[1], 0o666)' "$harness"
require_literal 'human_authorization_setup' "$harness"
require_literal '"env", f"{DIAGNOSTIC_ENV}=1"' "$harness"
if grep -Fq 'RUNNER_TEMP' "$harness"; then
    echo 'macOS custody laboratory still depends on the private runner temp root' >&2
    exit 1
fi
if grep -Fq 'macos-ticket26-diagnostics' "$workflow" ||
   grep -Fq 'PM_MACOS_TICKET26_DIAGNOSTIC' "$workflow" ||
   grep -Fq 'PM_MACOS_TICKET26_DIAGNOSTIC' "$root/packaging/macos/com.santanajcp.passwordmanager.plist"; then
    echo 'macOS ticket-26 diagnostics escaped the explicit laboratory fixture' >&2
    exit 1
fi

python3 - "$harness" <<'PY'
import importlib.util
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("pm_macos_lab", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

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
