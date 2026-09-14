#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
workflow="$root/.github/workflows/ticket-27-windows.yml"
prepare="$root/scripts/prepare-windows-libsodium.ps1"
lab="$root/scripts/test-windows-custody-lab.ps1"
storage_diagnostics="$root/scripts/test-windows-storage-diagnostics.ps1"
verifier="$root/crates/pm-build-input-verifier/src/main.rs"
attributes="$root/.gitattributes"
cargo_config="$root/.cargo/config.toml"
native_fs="$root/crates/pm-vault/src/native_fs.rs"
vault_lib="$root/crates/pm-vault/src/lib.rs"
vault_tests="$root/crates/pm-vault/src/onepux.rs"

for file in "$workflow" "$prepare" "$lab" "$storage_diagnostics" "$verifier" "$attributes" "$cargo_config" "$native_fs" "$vault_lib" "$vault_tests"; do
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
require_literal 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1 (Node 24)' "$workflow"
require_literal 'persist-credentials: false' "$workflow"
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
require_literal 'function Invoke-NativeStorageDiagnostics' "$storage_diagnostics"
require_literal 'CreateFileW' "$storage_diagnostics"
require_literal 'FlushFileBuffers' "$storage_diagnostics"
require_literal 'FileFlagBackupSemantics' "$storage_diagnostics"
require_literal 'file-flush-readonly=' "$storage_diagnostics"
require_literal 'directory-open-no-backup=' "$storage_diagnostics"
require_literal 'directory-flush-no-backup=' "$storage_diagnostics"
require_literal 'directory-flush-readonly=' "$storage_diagnostics"
require_literal 'directory-flush-write=' "$storage_diagnostics"
require_literal 'file-flush-write=success' "$storage_diagnostics"
require_literal 'function Assert-ExactProbeFileAcl' "$storage_diagnostics"
require_literal 'storage diagnostics writable file open failed' "$storage_diagnostics"
require_literal 'storage diagnostics require explicit EphemeralCI' "$storage_diagnostics"
require_literal 'storage diagnostics cleanup failed' "$storage_diagnostics"
require_literal 'Assert-NotReparse' "$storage_diagnostics"
require_literal '[IO.FileAttributes]::ReparsePoint' "$storage_diagnostics"
require_literal 'pub(crate) fn sync_file' "$native_fs"
require_literal 'pub(crate) fn sync_directory' "$native_fs"
require_literal 'FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT' "$native_fs"
require_literal 'GENERIC_READ | GENERIC_WRITE' "$native_fs"
require_literal 'libc::O_CLOEXEC | libc::O_NOFOLLOW' "$native_fs"
require_literal 'windows_file_identity(&file)?' "$native_fs"
require_literal 'native_fs::sync_file(&temporary_path)?;' "$vault_lib"
require_literal 'native_fs::sync_directory(parent)?;' "$vault_lib"
require_literal 'native_flush_seams_sync_synthetic_file_and_parent' "$vault_tests"
if grep -Fq 'File::open(&temporary_path)?.sync_all()' "$vault_lib" ||
   grep -Fq 'File::open(parent)?.sync_all()' "$vault_lib"; then
    echo 'Windows vault persistence must not flush through read-only path opens' >&2
    exit 1
fi
require_literal 'diagnostic_only:' "$workflow"
require_literal 'default: false' "$workflow"
require_literal 'type: boolean' "$workflow"
require_literal 'if: ${{ inputs.diagnostic_only != true }}' "$workflow"
require_literal 'if: ${{ inputs.diagnostic_only == true }}' "$workflow"
require_literal './scripts/test-windows-storage-diagnostics.ps1 -EphemeralCI' "$workflow"
storage_job_block=$(awk '
    /^  windows-arm64-storage-diagnostics:/ { inside = 1 }
    inside && /^  [[:alnum:]_-]+:/ && $0 !~ /^  windows-arm64-storage-diagnostics:/ { exit }
    inside { print }
' "$workflow")
printf '%s\n' "$storage_job_block" | grep -Fq './scripts/test-windows-storage-diagnostics.ps1 -EphemeralCI' || {
    echo 'Diagnostic workflow job must invoke the fixed native storage probe' >&2
    exit 1
}
if printf '%s\n' "$storage_job_block" | grep -Eiq 'cargo|prepare-windows|test-windows-custody|native-preflight|msbuild|rustup'; then
    echo 'Diagnostic workflow job must not install/build/test the product' >&2
    exit 1
fi
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

# The Windows custody fixture must stage all data while the elevated installer
# is the only non-SYSTEM trustee, then seal each runtime tree before SCM starts.
# Keep this regression textual and order-sensitive: Linux has no PowerShell or
# Windows ACL provider, so the native job is the executable verification.
require_literal '$installerName = [Security.Principal.WindowsIdentity]::GetCurrent().Name' "$lab"
require_literal 'Set-ExactTreeAcl $root @(' "$lab"
require_literal '$harnessDir = Join-Path $root' "$lab"
require_literal 'Set-ExactTreeAcl $harnessDir @(' "$lab"
require_literal '/reset' "$lab"
require_literal 'function Add-OwnedPath' "$lab"
require_literal 'Add-OwnedPath $ownedPaths $auditPath' "$lab"
require_literal 'function Assert-ExactNodeAcl' "$lab"
require_literal 'AreAccessRulesProtected' "$lab"
require_literal 'IsInherited' "$lab"
require_literal 'function Repair-OwnedCleanupAcl' "$lab"
require_literal 'function Remove-OwnedTree' "$lab"
require_literal 'refusing unplanned cleanup path' "$lab"
require_literal 'takeown.exe' "$lab"
require_literal '[IO.FileAttributes]::ReparsePoint' "$lab"
require_literal 'Remove-Item -LiteralPath $Path -Force -ErrorAction Stop' "$lab"
require_literal 'if ($cleanupErrors.Count -gt 0)' "$lab"

if grep -Eq 'Remove-Item[^\n]*-Recurse|takeown\.exe[^\n]*(/R|/r)|Get-ChildItem[^\n]*-Recurse' "$lab"; then
    echo 'Windows fixture cleanup must not recurse opaquely or follow reparse trees' >&2
    exit 1
fi

staging_line=$(grep -nF 'Set-ExactTreeAcl $root @(' "$lab" | cut -d: -f1 | head -n1)
mkdirs_line=$(grep -nF 'New-Item -ItemType Directory -Path $serviceDir, $agentDir, $humanDir' "$lab" | cut -d: -f1)
directory_staging_line=$(grep -nF 'Set-ExactTreeAcl $serviceDir @(' "$lab" | grep -F 'installerName' | cut -d: -f1 | head -n1)
agent_directory_staging_line=$(grep -nF 'Set-ExactTreeAcl $agentDir @(' "$lab" | grep -F 'installerName' | cut -d: -f1 | head -n1)
human_directory_staging_line=$(grep -nF 'Set-ExactTreeAcl $humanDir @(' "$lab" | grep -F 'installerName' | cut -d: -f1 | head -n1)
harness_staging_line=$(grep -nF 'Set-ExactTreeAcl $harnessDir @(' "$lab" | grep -F 'installerName' | cut -d: -f1 | head -n1)
keygen_line=$(grep -nF "Invoke-Checked \$custody @('keygen'" "$lab" | cut -d: -f1 | head -n1)
vault_line=$(grep -nF '$vault = Join-Path $serviceDir' "$lab" | cut -d: -f1 | head -n1)
service_final_line=$(grep -nF 'Set-ExactTreeAcl $serviceDir @(' "$lab" | grep -vF 'installerName' | cut -d: -f1 | tail -n1)
agent_final_line=$(grep -nF 'Set-ExactTreeAcl $agentDir @(' "$lab" | grep -vF 'installerName' | cut -d: -f1 | tail -n1)
human_final_line=$(grep -nF 'Set-ExactTreeAcl $humanDir @(' "$lab" | grep -vF 'installerName' | cut -d: -f1 | tail -n1)
harness_file_line=$(grep -nF '[IO.File]::WriteAllBytes($emptyInput' "$lab" | cut -d: -f1)
scm_config_line=$(grep -nF "Invoke-Checked 'sc.exe' @('config', \$serviceName" "$lab" | cut -d: -f1)
test "$(grep -nF 'Set-ExactTreeAcl $serviceDir @(' "$lab" | grep -vF 'installerName' | wc -l)" -eq 1 &&
    test "$(grep -nF 'Set-ExactTreeAcl $agentDir @(' "$lab" | grep -vF 'installerName' | wc -l)" -eq 1 &&
    test "$(grep -nF 'Set-ExactTreeAcl $humanDir @(' "$lab" | grep -vF 'installerName' | wc -l)" -eq 1 || {
    echo 'Windows fixture must have one role-only seal for each custody tree' >&2
    exit 1
}
test -n "$staging_line" && test -n "$mkdirs_line" && test -n "$keygen_line" &&
    test -n "$directory_staging_line" && test -n "$agent_directory_staging_line" &&
    test -n "$human_directory_staging_line" && test -n "$harness_staging_line" &&
    test -n "$vault_line" &&
    test -n "$harness_file_line" && test -n "$service_final_line" &&
    test -n "$agent_final_line" && test -n "$human_final_line" &&
    test -n "$scm_config_line" || {
    echo 'Windows fixture ACL phase markers are incomplete' >&2
    exit 1
}
test "$staging_line" -lt "$mkdirs_line" && test "$mkdirs_line" -lt "$directory_staging_line" &&
    test "$directory_staging_line" -lt "$agent_directory_staging_line" &&
    test "$agent_directory_staging_line" -lt "$human_directory_staging_line" &&
    test "$human_directory_staging_line" -lt "$harness_staging_line" &&
    test "$harness_staging_line" -lt "$keygen_line" &&
    test "$vault_line" -lt "$harness_file_line" && test "$harness_file_line" -lt "$service_final_line" &&
    test "$service_final_line" -lt "$agent_final_line" && test "$agent_final_line" -lt "$human_final_line" &&
    test "$human_final_line" -lt "$scm_config_line" || {
    echo 'Windows fixture ACL order must be stage -> provision/vault -> seal -> SCM' >&2
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
