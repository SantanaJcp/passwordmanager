#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
workflow="$root/.github/workflows/ticket-27-windows.yml"
prepare="$root/scripts/prepare-windows-libsodium.ps1"
lab="$root/scripts/test-windows-custody-lab.ps1"
verifier="$root/crates/pm-build-input-verifier/src/main.rs"
attributes="$root/.gitattributes"
cargo_config="$root/.cargo/config.toml"

for file in "$workflow" "$prepare" "$lab" "$verifier" "$attributes" "$cargo_config"; do
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
require_literal "Microsoft.VCToolsVersion.default.txt'" "$prepare"
require_literal "'/p:VCToolsVersion=' + \$toolVersion" "$prepare"
require_literal '$versionFiles = @(' "$prepare"
require_literal "rustup which --toolchain \$env:RUSTUP_TOOLCHAIN cargo" "$prepare"
require_literal "Join-Path \$env:RUSTUP_HOME \"toolchains\\\$env:RUSTUP_TOOLCHAIN\\bin\\cargo.exe\"" "$prepare"
require_literal "Join-Path \$env:SystemRoot 'System32\\tar.exe'" "$prepare"
require_literal '$armObjects = @($headers | Select-String' "$prepare"
require_literal '$foreignObjects = @($headers | Select-String' "$prepare"
require_literal 'SODIUM_LIB_DIR=' "$prepare"
require_literal 'SODIUM_LIB_DIR' "$lab"
require_literal 'PM_NATIVE_DUMPBIN=' "$prepare"
require_literal 'PM_NATIVE_DUMPBIN' "$lab"
require_literal 'Assert-NativeStaticMsvcBinary' "$lab"
require_literal "'/headers'" "$lab"
require_literal "'/dependents'" "$lab"
require_literal 'AA64 machine (ARM64)' "$lab"
require_literal 'api-ms-win-crt-' "$lab"
require_literal 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3' "$verifier"
require_literal 'third_party/libsodium/LATEST.tar.gz -text' "$attributes"
require_literal 'third_party/libsodium/LATEST.tar.gz.minisig -text' "$attributes"

require_windows_static_crt() {
    target=$1
    block=$(awk -v target="$target" '
        $0 == "[target." target "]" { found = 1; next }
        found && /^\[/ { exit }
        found { print }
    ' "$cargo_config")
    printf '%s\n' "$block" | grep -Fqx 'rustflags = ["-C", "target-feature=+crt-static"]' || {
        echo "Windows target $target must enable the static MSVC CRT explicitly" >&2
        exit 1
    }
}

require_windows_static_crt 'aarch64-pc-windows-msvc'
require_windows_static_crt 'x86_64-pc-windows-msvc'
if grep -Eq 'NODEFAULTLIB|target-feature=-crt-static' "$cargo_config" ||
   ! awk '
       /^\[/ { target = ($0 ~ /^\[target\./); next }
       /^rustflags[[:space:]]*=/ && !target { exit 1 }
   ' "$cargo_config"; then
    echo 'Windows CRT alignment contains a suppression, dynamic override, or global rustflags' >&2
    exit 1
fi

service_create_line=$(grep -F "Invoke-Checked 'sc.exe' @('create', \$serviceName" "$lab" || true)
test -n "$service_create_line" || {
    echo 'Windows custody lab service creation contract is absent' >&2
    exit 1
}
case "$service_create_line" in
    *"'password='"*)
        echo 'virtual Windows service must omit password= so SCM receives a NULL password' >&2
        exit 1
        ;;
esac
require_literal 'NT SERVICE\$serviceName' "$lab"

build_line=$(grep -nF "Invoke-Checked 'cargo' @('build', '-p', 'pm-custody'" "$lab" | cut -d: -f1)
dumpbin_line=$(grep -nF 'Assert-NativeStaticMsvcBinary $dumpbin' "$lab" | cut -d: -f1)
test "$(printf '%s\n' "$dumpbin_line" | wc -l)" -eq 2 || {
    echo 'Windows custody lab must inspect both native product executables' >&2
    exit 1
}
first_dumpbin_line=$(printf '%s\n' "$dumpbin_line" | sed -n '1p')
last_dumpbin_line=$(printf '%s\n' "$dumpbin_line" | sed -n '2p')
service_line=$(grep -nF "Invoke-Checked 'sc.exe' @('create', \$serviceName" "$lab" | cut -d: -f1)
test "$build_line" -lt "$first_dumpbin_line" &&
    test "$last_dumpbin_line" -lt "$service_line" || {
    echo 'Native PE dependency inspection must run after build and before SCM fixtures' >&2
    exit 1
}

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
   grep -Fq 'Microsoft.VCToolsVersion.VC.14.50.default.txt' "$prepare" ||
   grep -Eq '\(\$headers[[:space:]]*\|[[:space:]]*Select-String[^)]*\)\.Count' "$prepare"; then
    echo 'Windows source preparation uses an uninstalled Cargo proxy or StrictMode-unsafe scalar Count' >&2
    exit 1
fi
