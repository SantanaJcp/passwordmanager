#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

workspace_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
workflow="$workspace_root/.github/workflows/native-environment-preflight.yml"
method="$workspace_root/docs/verification/native-ci.md"
unix_preflight="$workspace_root/scripts/ci/native-preflight-unix.sh"
windows_preflight="$workspace_root/scripts/ci/native-preflight-windows.ps1"

require_file() {
    if ! test -f "$1"; then
        echo "required native CI file is absent: $1" >&2
        exit 1
    fi
}

require_literal() {
    if ! grep -Fq -- "$1" "$2"; then
        echo "required native CI contract is absent from $2: $1" >&2
        exit 1
    fi
}

require_count() {
    actual=$(awk -v needle="$1" 'index($0, needle) { count++ } END { print count + 0 }' "$3")
    if test "$actual" -ne "$2"; then
        echo "native CI contract count mismatch in $3: expected $2 for '$1', got $actual" >&2
        exit 1
    fi
}

require_file "$workflow"
require_file "$method"
require_file "$unix_preflight"
require_file "$windows_preflight"
test -x "$unix_preflight" || {
    echo 'Unix native preflight is not executable' >&2
    exit 1
}

require_literal '  workflow_dispatch:' "$workflow"
require_literal '  contents: read' "$workflow"
require_count '          persist-credentials: false' 2 "$workflow"

for label in ubuntu-24.04 ubuntu-24.04-arm macos-15-intel macos-15 windows-11-vs2026-arm; do
    if ! grep -Eq "(runner|runs-on): $label$" "$workflow"; then
        echo "required standard runner label is absent: $label" >&2
        exit 1
    fi
done

checkout='actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1 (Node 24)'
if ! uses_lines=$(grep -E '^[[:space:]]+- uses:' "$workflow"); then
    echo 'native preflight has no pinned action' >&2
    exit 1
fi
uses_count=$(printf '%s\n' "$uses_lines" | awk 'END { print NR }')
if test "$uses_count" -ne 2; then
    echo "native preflight must use checkout exactly twice, got $uses_count action references" >&2
    exit 1
fi
if printf '%s\n' "$uses_lines" | grep -Fv -- "- uses: $checkout"; then
    echo 'native preflight has an unexpected action reference' >&2
    exit 1
fi

require_count "  RUSTUP_AUTO_INSTALL: '0'" 1 "$workflow"
require_count "rustup toolchain install '1.98.1-\${{ matrix.rust_host }}' --profile minimal --no-self-update" 1 "$workflow"
require_count "rustup toolchain install '1.98.1-aarch64-pc-windows-msvc' --profile minimal --no-self-update" 1 "$workflow"
require_literal '$matchingToolchains = @(' "$windows_preflight"
if grep -Fq '}).Count' "$windows_preflight"; then
    echo 'Windows native preflight reads Count from a possibly scalar pipeline result' >&2
    exit 1
fi

if grep -Eiq '(^|[^[:alnum:]_-])(push|pull_request|schedule):|continue-on-error|secrets\.|upload-artifact|actions/cache|ubuntu-slim|-(xlarge|large)([^[:alnum:]_-]|$)|qemu|rosetta|wsl|cross[ -]?compil|\|\|[[:space:]]+true' "$workflow"; then
    echo 'native preflight contains a forbidden trigger, runner, secret, substitution or emulation path' >&2
    exit 1
fi

if grep -Eiq 'curl|wget|invoke-webrequest|apt(-get)?[[:space:]]+install|brew[[:space:]]+install|rustup[[:space:]]+(install|update)|rustup[[:space:]]+toolchain[[:space:]]+install|choco[[:space:]]+install|winget[[:space:]]+install|\|\|[[:space:]]+true' "$unix_preflight" "$windows_preflight"; then
    echo 'native preflight contains a download, installation or success-substitution path' >&2
    exit 1
fi

require_literal '[Método CI nativo efímero](docs/verification/native-ci.md)' "$workspace_root/AGENTS.md"
require_literal '[método CI nativo efímero](../../docs/verification/native-ci.md)' "$workspace_root/.scratch/passwordmanager/execution.md"
