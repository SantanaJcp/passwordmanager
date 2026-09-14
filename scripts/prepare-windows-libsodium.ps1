# SPDX-License-Identifier: AGPL-3.0-only
[CmdletBinding()]
param(
    [switch]$EphemeralCI
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Invoke-Checked([string]$File, [string[]]$Arguments) {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$File failed with exit code $LASTEXITCODE" }
}

function Assert-FileHash([string]$Path, [string]$Expected) {
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-True ($actual -eq $Expected) "SHA-256 mismatch for $Path"
}

function Get-PeMachine([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    try {
        $reader = [IO.BinaryReader]::new($stream)
        $stream.Position = 0x3c
        $peOffset = $reader.ReadInt32()
        $stream.Position = $peOffset + 4
        return $reader.ReadUInt16()
    }
    finally {
        $stream.Dispose()
    }
}

Assert-True $EphemeralCI 'Explicit -EphemeralCI is required'
Assert-True ($env:GITHUB_ACTIONS -eq 'true' -and $env:CI -eq 'true') 'Authorized ephemeral CI is required'
Assert-True ($env:RUNNER_OS -eq 'Windows' -and $env:RUNNER_ARCH -eq 'ARM64') 'Native Windows ARM64 runner is required'
Assert-True ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq [Runtime.InteropServices.Architecture]::Arm64) 'Windows OS is not ARM64'
Assert-True ([Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq [Runtime.InteropServices.Architecture]::Arm64) 'PowerShell host is not ARM64'
Assert-True (-not [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) 'RUNNER_TEMP is required'
Assert-True (-not [string]::IsNullOrWhiteSpace($env:GITHUB_ENV)) 'GITHUB_ENV is required'
Assert-True (-not [string]::IsNullOrWhiteSpace($env:CARGO_HOME)) 'CARGO_HOME is required'
foreach ($name in @('SODIUM_LIB_DIR', 'SODIUM_SHARED', 'SODIUM_USE_PKG_CONFIG', 'SODIUM_DIST_DIR')) {
    Assert-True (-not (Test-Path "Env:$name")) "Ambient $name is forbidden"
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$archive = Join-Path $repo 'third_party\libsodium\LATEST.tar.gz'
$signature = Join-Path $repo 'third_party\libsodium\LATEST.tar.gz.minisig'
$cargo = Join-Path $env:CARGO_HOME 'bin\cargo.exe'
$tar = Join-Path $env:SystemRoot 'System32\tar.exe'
Assert-True (Test-Path -LiteralPath $archive -PathType Leaf) 'Pinned libsodium source archive is absent'
Assert-True (Test-Path -LiteralPath $signature -PathType Leaf) 'Pinned libsodium signature is absent'
Assert-True (Test-Path -LiteralPath $cargo -PathType Leaf) 'Repository-home Cargo is absent'
Assert-True (Test-Path -LiteralPath $tar -PathType Leaf) 'System tar is absent'
Assert-True ((Get-PeMachine $cargo) -eq 0xaa64) 'Cargo host PE is not ARM64'
Assert-True ((Get-PeMachine $tar) -eq 0xaa64) 'System tar host PE is not ARM64'
Assert-FileHash $archive 'b20a92e7ec25b285eafa349d721a5bb27e3a8ba94c0816630a127883f1d1b3ab'
Assert-FileHash $signature '2162883303fb903068519916871476b192d5cf31d5e412378db8ae05a0c05895'

Push-Location $repo
try {
    Invoke-Checked $cargo @(
        'run', '-p', 'pm-build-input-verifier', '--locked', '--offline', '--',
        $archive, $signature
    )
}
finally {
    Pop-Location
}

$buildRoot = Join-Path $env:RUNNER_TEMP 'passwordmanager-libsodium-source'
Assert-True (-not (Test-Path -LiteralPath $buildRoot)) "Source-build root already exists: $buildRoot"
New-Item -ItemType Directory -Path $buildRoot | Out-Null
Invoke-Checked $tar @('-xzf', $archive, '-C', $buildRoot)
$roots = @(Get-ChildItem -LiteralPath $buildRoot -Directory -Force)
Assert-True ($roots.Count -eq 1 -and $roots[0].Name -eq 'libsodium-stable') 'Archive has an unexpected top-level layout'
$source = $roots[0].FullName
$project = Join-Path $source 'builds\msvc\vs2026\libsodium\libsodium.vcxproj'
$releaseProperties = Join-Path $source 'builds\msvc\properties\ReleaseLIB.props'
$versionHeader = Join-Path $source 'builds\msvc\version.h'
foreach ($path in @($project, $releaseProperties, $versionHeader)) {
    Assert-True (Test-Path -LiteralPath $path -PathType Leaf) "Required source-build input is absent: $path"
}
Assert-True ((Get-Content -LiteralPath $project -Raw).Contains('<PlatformToolset>v145</PlatformToolset>')) 'Project toolset is not v145'
Assert-True ((Get-Content -LiteralPath $project -Raw).Contains('ReleaseLIB|ARM64')) 'Project lacks ReleaseLIB|ARM64'
Assert-True ((Get-Content -LiteralPath $releaseProperties -Raw).Contains('<RuntimeLibrary>MultiThreaded</RuntimeLibrary>')) 'ReleaseLIB is not /MT'
Assert-True ((Get-Content -LiteralPath $versionHeader -Raw).Contains('#define SODIUM_VERSION_STRING "1.0.22"')) 'Source version is not libsodium 1.0.22'

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
Assert-True (Test-Path -LiteralPath $vswhere -PathType Leaf) 'Pinned Visual Studio installer locator is absent'
$installations = @(& $vswhere -products '*' -version '[18.0,19.0)' -requires Microsoft.Component.MSBuild Microsoft.VisualStudio.Component.VC.Tools.ARM64 -property installationPath)
Assert-True ($LASTEXITCODE -eq 0) "vswhere failed with exit code $LASTEXITCODE"
$installations = @($installations | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
Assert-True ($installations.Count -eq 1) "Expected exactly one Visual Studio 2026 installation, got $($installations.Count)"
$installation = $installations[0].Trim()
$msbuild = Join-Path $installation 'MSBuild\Current\Bin\arm64\MSBuild.exe'
$toolVersionFile = Join-Path $installation 'VC\Auxiliary\Build\Microsoft.VCToolsVersion.VC.14.50.default.txt'
Assert-True (Test-Path -LiteralPath $msbuild -PathType Leaf) 'ARM64-host MSBuild is absent'
Assert-True (Test-Path -LiteralPath $toolVersionFile -PathType Leaf) 'Pinned v145 tool-version file is absent'
$toolVersion = (Get-Content -LiteralPath $toolVersionFile -Raw).Trim()
Assert-True ($toolVersion -match '^14\.5[0-9]\.[0-9]+$') "Unexpected v145 tool version: $toolVersion"
$nativeToolBin = Join-Path $installation "VC\Tools\MSVC\$toolVersion\bin\Hostarm64\arm64"
$dumpbin = Join-Path $nativeToolBin 'dumpbin.exe'
Assert-True (Test-Path -LiteralPath $dumpbin -PathType Leaf) 'ARM64-host/ARM64-target Dumpbin is absent'
Assert-True ((Get-PeMachine $msbuild) -eq 0xaa64) 'MSBuild host PE is not ARM64'
Assert-True ((Get-PeMachine $dumpbin) -eq 0xaa64) 'Dumpbin host PE is not ARM64'

Invoke-Checked $msbuild @(
    $project, '/m:1', '/t:Rebuild', '/p:Configuration=ReleaseLIB',
    '/p:Platform=ARM64', '/p:PlatformToolset=v145'
)
$libDir = Join-Path $source 'bin\ARM64\Release\v145\static'
$library = Join-Path $libDir 'libsodium.lib'
Assert-True (Test-Path -LiteralPath $library -PathType Leaf) 'Expected source-built libsodium.lib is absent'
$libraries = @(Get-ChildItem -LiteralPath $source -Filter 'libsodium.lib' -File -Recurse)
Assert-True ($libraries.Count -eq 1 -and $libraries[0].FullName -eq $library) 'Source build emitted an ambiguous libsodium library set'
$headers = @(& $dumpbin '/headers' $library)
Assert-True ($LASTEXITCODE -eq 0) "Dumpbin failed with exit code $LASTEXITCODE"
Assert-True (($headers | Select-String -SimpleMatch 'AA64 machine (ARM64)').Count -gt 0) 'Source-built library contains no ARM64 objects'
Assert-True (($headers | Select-String -Pattern 'machine \((x64|x86)\)').Count -eq 0) 'Source-built library contains a non-ARM64 object'

$env:SODIUM_LIB_DIR = $libDir
Push-Location $repo
try {
    Invoke-Checked $cargo @(
        'test', '-p', 'pm-crypto', '--test', 'linked_version', '--locked', '--offline'
    )
}
finally {
    Pop-Location
}
Add-Content -LiteralPath $env:GITHUB_ENV -Value "SODIUM_LIB_DIR=$libDir" -Encoding utf8
Write-Output "PASS libsodium-source version=1.0.22 cpu=ARM64 toolset=v145 runtime=MT signature=minisign"
