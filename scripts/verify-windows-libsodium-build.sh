#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
workflow="$root/.github/workflows/ticket-27-windows.yml"
prepare="$root/scripts/prepare-windows-libsodium.ps1"
lab="$root/scripts/test-windows-custody-lab.ps1"
verifier="$root/crates/pm-build-input-verifier/src/main.rs"
attributes="$root/.gitattributes"

for file in "$workflow" "$prepare" "$lab" "$verifier" "$attributes"; do
    test -f "$file" || {
        echo "required Windows source-build file is absent: $file" >&2
        exit 1
    }
done

require_literal() {
    grep -Fq -- "$1" "$2" || {
        echo "required Windows source-build contract is absent from $2: $1" >&2
        exit 1
    }
}

require_literal './scripts/prepare-windows-libsodium.ps1 -EphemeralCI' "$workflow"
require_literal 'b20a92e7ec25b285eafa349d721a5bb27e3a8ba94c0816630a127883f1d1b3ab' "$prepare"
require_literal '2162883303fb903068519916871476b192d5cf31d5e412378db8ae05a0c05895' "$prepare"
require_literal 'ReleaseLIB' "$prepare"
require_literal 'v145' "$prepare"
require_literal 'Hostarm64\arm64' "$prepare"
require_literal "rustup which --toolchain \$env:RUSTUP_TOOLCHAIN cargo" "$prepare"
require_literal "Join-Path \$env:RUSTUP_HOME \"toolchains\\\$env:RUSTUP_TOOLCHAIN\\bin\\cargo.exe\"" "$prepare"
require_literal "Join-Path \$env:SystemRoot 'System32\\tar.exe'" "$prepare"
require_literal '$armObjects = @($headers | Select-String' "$prepare"
require_literal '$foreignObjects = @($headers | Select-String' "$prepare"
require_literal 'SODIUM_LIB_DIR=' "$prepare"
require_literal 'SODIUM_LIB_DIR' "$lab"
require_literal 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3' "$verifier"
require_literal 'third_party/libsodium/LATEST.tar.gz -text' "$attributes"
require_literal 'third_party/libsodium/LATEST.tar.gz.minisig -text' "$attributes"

for input in third_party/libsodium/LATEST.tar.gz third_party/libsodium/LATEST.tar.gz.minisig; do
    attribute=$(git -C "$root" check-attr text -- "$input")
    case "$attribute" in
        *': text: unset') ;;
        *)
            echo "authenticated build input is not checkout-byte-stable: $attribute" >&2
            exit 1
            ;;
    esac
done

fetch_line=$(grep -nF 'cargo fetch --locked' "$workflow" | cut -d: -f1)
prepare_line=$(grep -nF './scripts/prepare-windows-libsodium.ps1 -EphemeralCI' "$workflow" | cut -d: -f1)
lab_line=$(grep -nF './scripts/test-windows-custody-lab.ps1 -EphemeralCI' "$workflow" | cut -d: -f1)
test "$fetch_line" -lt "$prepare_line" && test "$prepare_line" -lt "$lab_line" || {
    echo 'Windows phases are not ordered fetch -> authenticated source build -> offline lab' >&2
    exit 1
}

if grep -Eiq 'libsodium-1\.0\.22-stable-msvc\.zip|SODIUM_DIST_DIR[[:space:]]*=|Get-Command[[:space:]]+(msbuild|cl|dumpbin)|continue-on-error|\|\|[[:space:]]+true' "$prepare" "$workflow"; then
    echo 'Windows source preparation contains a binary ZIP, ambient tool lookup, or fallback' >&2
    exit 1
fi

if grep -Fq 'Join-Path $env:CARGO_HOME' "$prepare" ||
   grep -Eq '\(\$headers[[:space:]]*\|[[:space:]]*Select-String[^)]*\)\.Count' "$prepare"; then
    echo 'Windows source preparation uses an uninstalled Cargo proxy or StrictMode-unsafe scalar Count' >&2
    exit 1
fi
