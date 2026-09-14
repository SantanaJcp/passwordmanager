# SPDX-License-Identifier: AGPL-3.0-only
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) {
        throw $Message
    }
}

Assert-True ($env:CI -eq 'true') 'CI=true is required'
Assert-True ($env:RUSTUP_AUTO_INSTALL -eq '0') 'RUSTUP_AUTO_INSTALL=0 is required before invoking rustup'
Assert-True ($env:RUNNER_OS -eq 'Windows') "Runner OS mismatch: expected Windows, got $($env:RUNNER_OS)"
Assert-True ($env:RUNNER_ARCH -eq 'ARM64') "Runner architecture mismatch: expected ARM64, got $($env:RUNNER_ARCH)"
Assert-True (-not [string]::IsNullOrWhiteSpace($env:ImageOS)) 'ImageOS is absent'
Assert-True (-not [string]::IsNullOrWhiteSpace($env:ImageVersion)) 'ImageVersion is absent'

$os = Get-CimInstance Win32_OperatingSystem
Assert-True ($os.Caption -match 'Windows 11') "OS mismatch: expected Windows 11, got $($os.Caption)"
Assert-True ([Environment]::OSVersion.Version.Build -ge 22000) "Windows build is below 22000: $([Environment]::OSVersion.Version)"
Assert-True ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq [System.Runtime.InteropServices.Architecture]::Arm64) 'OS architecture is not ARM64'
Assert-True ([System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq [System.Runtime.InteropServices.Architecture]::Arm64) 'PowerShell process is emulated rather than ARM64'

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
Assert-True ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'Workflow process is not an administrator'

foreach ($commandName in @('cargo', 'rustc', 'rustup', 'sc.exe', 'icacls.exe', 'whoami.exe', 'msiexec.exe', 'Get-Acl', 'Set-Acl', 'Get-Service')) {
    if ($null -eq (Get-Command $commandName -ErrorAction SilentlyContinue)) {
        throw "Required native CI command is absent: $commandName"
    }
}

$toolchain = '1.98.1-aarch64-pc-windows-msvc'
$installedToolchains = @(& rustup toolchain list)
Assert-True ($LASTEXITCODE -eq 0) "Listing installed Rust toolchains failed with exit code $LASTEXITCODE"
$matchingToolchains = @(
    $installedToolchains | Where-Object { $_ -match '^1\.98\.1-aarch64-pc-windows-msvc(?:\s|$)' }
)
Assert-True ($matchingToolchains.Count -gt 0) "Required explicitly installed native Rust toolchain is absent: $toolchain"
$env:RUSTUP_TOOLCHAIN = $toolchain
$rustVersion = & rustc --version
$cargoVersion = & cargo --version
Assert-True ($rustVersion -match '^rustc 1\.98\.1 ') "Rust version mismatch: $rustVersion"
Assert-True ($cargoVersion -match '^cargo 1\.98\.1 ') "Cargo version mismatch: $cargoVersion"
$rustHostLine = (& rustc -vV | Select-String '^host: ').Line
$rustHost = $rustHostLine.Substring(6)
Assert-True ($rustHost -eq 'aarch64-pc-windows-msvc') "Native Rust host mismatch: $rustHost"

$probeDirectory = Join-Path $env:RUNNER_TEMP 'passwordmanager-native-preflight'
if (Test-Path $probeDirectory) {
    throw "Preflight directory already exists: $probeDirectory"
}
New-Item -ItemType Directory -Path $probeDirectory | Out-Null
try {
    $source = Join-Path $probeDirectory 'probe.rs'
    $binary = Join-Path $probeDirectory 'probe.exe'
    [IO.File]::WriteAllText($source, 'fn main() { println!("PM_NATIVE_CI_PROBE"); }')
    & rustc $source -o $binary
    Assert-True ($LASTEXITCODE -eq 0) "Native Rust probe compilation failed with exit code $LASTEXITCODE"

    $stream = [IO.File]::OpenRead($binary)
    try {
        $reader = [IO.BinaryReader]::new($stream)
        $stream.Position = 0x3c
        $peOffset = $reader.ReadInt32()
        $stream.Position = $peOffset + 4
        $machine = $reader.ReadUInt16()
    }
    finally {
        $stream.Dispose()
    }
    Assert-True ($machine -eq 0xaa64) ('PE machine mismatch: expected ARM64 0xAA64, got 0x{0:X4}' -f $machine)
    $probeOutput = & $binary
    Assert-True ($LASTEXITCODE -eq 0) "Native Rust probe execution failed with exit code $LASTEXITCODE"
    Assert-True ($probeOutput -eq 'PM_NATIVE_CI_PROBE') "Unexpected native Rust probe output: $probeOutput"
}
finally {
    Remove-Item -Recurse -Force $probeDirectory
}

$uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Write-Output "os=$($os.Caption) version=$($os.Version) build=$($os.BuildNumber)"
Write-Output "runner_os=$($env:RUNNER_OS) runner_arch=$($env:RUNNER_ARCH) image_os=$($env:ImageOS) image_version=$($env:ImageVersion) user=$([Security.Principal.WindowsIdentity]::GetCurrent().Name) rust_host=$rustHost uac_enable_lua=$($uac.EnableLUA)"
Write-Output 'PASS native-environment-preflight target=windows/arm64 scope=environment-only product-validation=NOT_RUN'
