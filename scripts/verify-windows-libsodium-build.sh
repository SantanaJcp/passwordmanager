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
windows_service="$root/crates/pm-custody/src/windows.rs"
native_channel="$root/crates/pm-native-channel/src/windows.rs"
native_fs="$root/crates/pm-vault/src/native_fs.rs"
vault_lib="$root/crates/pm-vault/src/lib.rs"
vault_tests="$root/crates/pm-vault/src/onepux.rs"

for file in "$workflow" "$prepare" "$lab" "$storage_diagnostics" "$verifier" "$attributes" "$cargo_config" "$windows_service" "$native_channel" "$native_fs" "$vault_lib" "$vault_tests"; do
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
require_literal '[switch]$ServiceDiagnostics' "$lab"
require_literal 'function Write-ServiceDiagnostic' "$lab"
require_literal "Write-ServiceDiagnostic 'before-start'" "$lab"
require_literal "Write-ServiceDiagnostic 'after-start'" "$lab"
require_literal "Write-ServiceDiagnostic 'after-settle'" "$lab"
require_literal 'Start-Sleep -Seconds 2' "$lab"
require_literal 'stopped-exit-zero' "$lab"
require_literal 'stopped-exit-nonzero' "$lab"
require_literal 'ServiceSpecificExitCode' "$lab"
require_literal 'service_diagnostics:' "$workflow"
require_literal "inputs.service_diagnostics" "$workflow"
require_literal '-ServiceDiagnostics' "$workflow"
service_diagnostics_input_block=$(awk '
    /^      service_diagnostics:/ { inside = 1 }
    inside && /^      [[:alnum:]_-]+:/ && $0 !~ /^      service_diagnostics:/ { exit }
    inside { print }
' "$workflow")
printf '%s\n' "$service_diagnostics_input_block" | grep -Fq 'default: false' || {
    echo 'service diagnostics workflow input must default to false' >&2
    exit 1
}
printf '%s\n' "$service_diagnostics_input_block" | grep -Fq 'type: boolean' || {
    echo 'service diagnostics workflow input must be an explicit boolean' >&2
    exit 1
}

# Service subphase diagnostics are opt-in and write only fixed literals to a
# pre-created, owned fixture file. Keep this contract textual because Linux
# cannot compile the Windows module or exercise its ACL provider.
require_literal 'enum ServiceDiagnosticPhase' "$windows_service"
require_literal 'struct ServiceDiagnostics' "$windows_service"
require_literal 'Arc<Mutex<File>>' "$windows_service"
require_literal 'fn take_optional_path' "$windows_service"
require_literal '--service-diagnostics' "$windows_service"
require_literal 'ServiceDiagnostics::open' "$windows_service"
require_literal '.create(false)' "$windows_service"
require_literal 'options.read(true).write(true).create(false)' "$windows_service"
require_literal 'FILE_FLAG_OPEN_REPARSE_POINT' "$windows_service"
require_literal 'GetFileInformationByHandle' "$windows_service"
require_literal 'SeekFrom::End(0)' "$windows_service"
require_literal 'ServiceDiagnosticPhase::ServiceFailed' "$windows_service"
for phase in args-ok bootstrap-ok audit-ok agent-tls-ok agent-pipe-ok human-tls-ok human-pipe-ok service-failed; do
    require_literal "b\"phase=$phase\\n\"" "$windows_service"
done
require_literal 'ServiceDiagnosticPhase::ArgsOk' "$windows_service"
require_literal 'ServiceDiagnosticPhase::BootstrapOk' "$windows_service"
require_literal 'ServiceDiagnosticPhase::AuditOk' "$windows_service"
require_literal 'ServiceDiagnosticPhase::AgentTlsOk' "$windows_service"
require_literal 'ServiceDiagnosticPhase::AgentPipeOk' "$windows_service"
require_literal 'ServiceDiagnosticPhase::HumanTlsOk' "$windows_service"
require_literal 'ServiceDiagnosticPhase::HumanPipeOk' "$windows_service"
require_literal 'diagnostics.as_ref()' "$windows_service"
require_literal 'record(ServiceDiagnosticPhase::ServiceFailed)' "$windows_service"
require_literal 'fn human_unlock_failure_phase' "$windows_service"
human_phases='human-accepted human-magic-alpn human-unlock-request human-unlock-wrong-channel human-unlock-storage-io human-unlock-vault-crypto human-unlock-vault-format human-unlock-other human-unlock-ok human-unlock-ack human-lock-request human-audit-open human-audit-append human-lock-ack'
for phase in $human_phases; do
    require_literal "b\"phase=$phase\\n\"" "$windows_service"
done
unlock_calls=$(grep -Fc 'HumanVault::unlock_with_audit_custody(' "$windows_service")
test "$unlock_calls" -eq 1 || {
    echo "Windows human diagnostic must preserve one unlock operation, got $unlock_calls" >&2
    exit 1
}

# CreateNamedPipeW accepts only server open-mode flags; SQOS belongs on the
# client CreateFileW call. The Windows unit regression exercises the real API
# with an owned unique pipe, the current token SID and a different client SID.
require_literal 'fn named_pipe_first_instance_rejects_second_protected_instance' "$native_channel"
require_literal 'OpenProcessToken' "$native_channel"
require_literal 'token_sid(token)' "$native_channel"
require_literal 'SystemTime::now()' "$native_channel"
require_literal 'format!("{stamp:032x}")' "$native_channel"
require_literal 'different_client_sid' "$native_channel"
require_literal 'create_owned_test_pipe' "$native_channel"
require_literal 'create_pipe_instance' "$native_channel"
require_literal 'struct OwnedTestPipe' "$native_channel"
require_literal 'impl OwnedTestPipe' "$native_channel"
require_literal 'impl Drop for OwnedTestPipe' "$native_channel"
require_literal 'fn close_once' "$native_channel"
require_literal 'self.0.take()' "$native_channel"
require_literal 'if unsafe { CloseHandle(handle) } == 0' "$native_channel"
require_literal 'if let Err(error) = self.close_once()' "$native_channel"
require_literal 'std::thread::panicking()' "$native_channel"
require_literal 'std::process::abort()' "$native_channel"
require_literal 'let creator_owner' "$native_channel"
require_literal '&current_client_sid,' "$native_channel"
require_literal 'ERROR_ACCESS_DENIED' "$native_channel"
require_literal 'Some(ERROR_ACCESS_DENIED)' "$native_channel"
require_literal 'replacen(&service_owner, &creator_owner, 1)' "$native_channel"
require_literal 'panic!("first named pipe creation failed with GetLastError={error}")' "$native_channel"
require_literal 'first.close()' "$native_channel"
require_literal 'panic!("first named pipe cleanup failed with GetLastError={error}")' "$native_channel"
require_literal 'CreateNamedPipeW' "$native_channel"
require_literal 'CreateFileW' "$native_channel"
require_literal 'SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION' "$native_channel"

if ! awk '
    /CreateNamedPipeW\(/ { inside = 1 }
    inside && /SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION/ { bad = 1 }
    inside && /^[[:space:]]*\)/ { done = 1; inside = 0 }
    END { exit (bad || !done) }
' "$native_channel"; then
    echo 'CreateNamedPipeW server mode must not contain client SQOS flags' >&2
    exit 1
fi
server_pipe_block=$(awk '
    /CreateNamedPipeW\(/ { inside = 1 }
    inside { print }
    inside && /^[[:space:]]*\)/ { exit }
' "$native_channel")
printf '%s\n' "$server_pipe_block" | grep -Fq 'PIPE_ACCESS_DUPLEX' || {
    echo 'CreateNamedPipeW must retain duplex access' >&2
    exit 1
}
printf '%s\n' "$server_pipe_block" | grep -Fq 'FILE_FLAG_FIRST_PIPE_INSTANCE' || {
    echo 'CreateNamedPipeW must retain first-instance protection' >&2
    exit 1
}
client_pipe_block=$(awk '
    /CreateFileW\(/ { inside = 1 }
    inside { print }
    inside && /^[[:space:]]*\)/ { exit }
' "$native_channel")
printf '%s\n' "$client_pipe_block" | grep -Fq 'SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION' || {
    echo 'CreateFileW client must retain identification SQOS flags' >&2
    exit 1
}
pipe_helper_block=$(awk '
    /^fn create_pipe_instance\(/ { inside = 1 }
    inside { print }
    inside && /^}/ { exit }
' "$native_channel")
printf '%s\n' "$pipe_helper_block" | grep -Fq 'if handle == INVALID_HANDLE_VALUE' &&
    printf '%s\n' "$pipe_helper_block" | grep -Fq 'return Err(unsafe { GetLastError() });' || {
    echo 'CreateNamedPipeW helper must capture GetLastError on invalid handle' >&2
    exit 1
}
creation_call_line=$(grep -nF 'let creation = create_pipe_instance' "$native_channel" | head -n1 | cut -d: -f1)
descriptor_free_line=$(grep -nF 'LocalFree(descriptor)' "$native_channel" | head -n1 | cut -d: -f1)
test -n "$creation_call_line" && test -n "$descriptor_free_line" &&
    test "$creation_call_line" -lt "$descriptor_free_line" || {
    echo 'CreateNamedPipeW result must be captured before LocalFree' >&2
    exit 1
}

require_literal '$diagnosticDir = Join-Path $root' "$lab"
require_literal '$diagnosticPath = Join-Path $diagnosticDir' "$lab"
require_literal 'Add-OwnedPath $ownedPaths $diagnosticDir' "$lab"
require_literal 'Add-OwnedPath $ownedPaths $diagnosticPath' "$lab"
require_literal 'function Write-ServiceSubphaseDiagnostics' "$lab"
require_literal 'SERVICE_PHASE' "$lab"
require_literal 'Assert-ExactNodeAcl $diagnosticDir' "$lab"
require_literal 'Assert-ExactNodeAcl $diagnosticPath' "$lab"
require_literal 'Set-ExactTreeAcl $diagnosticDir @(' "$lab"
require_literal 'if ($ServiceDiagnostics)' "$lab"
require_literal '--service-diagnostics' "$lab"
require_literal '$binPath += " --service-diagnostics' "$lab"
require_literal 'Write-ServiceSubphaseDiagnostics $diagnosticPath' "$lab"
for phase in args-ok bootstrap-ok audit-ok agent-tls-ok agent-pipe-ok human-tls-ok human-pipe-ok service-failed; do
    require_literal "'phase=$phase'" "$lab"
done
require_literal 'function Assert-HumanDiagnosticTrace' "$lab"
require_literal 'Assert-HumanDiagnosticTrace $lines' "$lab"
for phase in $human_phases; do
    require_literal "'phase=$phase'" "$lab"
done
human_run_line=$(grep -nF "@('human-lock', '--profile'" "$lab" | cut -d: -f1)
human_diagnostic_line=$(grep -nF 'Write-ServiceSubphaseDiagnostics $diagnosticPath' "$lab" | tail -n1 | cut -d: -f1)
human_assert_line=$(grep -nF "'human native channel failed: '" "$lab" | cut -d: -f1)
test -n "$human_run_line" && test -n "$human_diagnostic_line" &&
    test -n "$human_assert_line" && test "$human_run_line" -lt "$human_diagnostic_line" &&
    test "$human_diagnostic_line" -lt "$human_assert_line" || {
    echo 'Windows human diagnostic must be read after the operation and before its public assertion' >&2
    exit 1
}

diagnostic_dir_line=$(grep -nF 'New-Item -ItemType Directory -Path $diagnosticDir' "$lab" | cut -d: -f1)
diagnostic_dir_owned_line=$(grep -nF 'Add-OwnedPath $ownedPaths $diagnosticDir' "$lab" | cut -d: -f1)
diagnostic_file_owned_line=$(grep -nF 'Add-OwnedPath $ownedPaths $diagnosticPath' "$lab" | cut -d: -f1)
diagnostic_file_write_line=$(grep -nF '[IO.File]::WriteAllText($diagnosticPath' "$lab" | cut -d: -f1)
diagnostic_final_acl_line=$(grep -nF 'Set-ExactTreeAcl $diagnosticDir @(' "$lab" | tail -n1 | cut -d: -f1)
diagnostic_read_line=$(grep -nF 'Write-ServiceSubphaseDiagnostics $diagnosticPath' "$lab" | head -n1 | cut -d: -f1)
service_assert_line=$(grep -nF "Assert-True ((Get-Service \$serviceName).Status -eq 'Running')" "$lab" | head -n1 | cut -d: -f1)
test -n "$diagnostic_dir_line" && test -n "$diagnostic_dir_owned_line" &&
    test -n "$diagnostic_file_owned_line" && test -n "$diagnostic_file_write_line" &&
    test -n "$diagnostic_final_acl_line" && test -n "$diagnostic_read_line" &&
    test -n "$service_assert_line" || {
    echo 'Windows service diagnostics fixture markers are incomplete' >&2
    exit 1
}
test "$diagnostic_dir_line" -lt "$diagnostic_dir_owned_line" &&
    test "$diagnostic_dir_owned_line" -lt "$diagnostic_file_owned_line" &&
    test "$diagnostic_file_owned_line" -lt "$diagnostic_file_write_line" &&
    test "$diagnostic_file_write_line" -lt "$diagnostic_final_acl_line" &&
    test "$diagnostic_final_acl_line" -lt "$diagnostic_read_line" &&
    test "$diagnostic_read_line" -lt "$service_assert_line" || {
    echo 'Windows service diagnostics fixture order must be create -> own -> seal -> read' >&2
    exit 1
}

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
lab_line=$(grep -nF './scripts/test-windows-custody-lab.ps1 -EphemeralCI' "$workflow" | head -n1 | cut -d: -f1)
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
