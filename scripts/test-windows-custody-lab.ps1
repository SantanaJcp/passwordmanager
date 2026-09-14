# SPDX-License-Identifier: AGPL-3.0-only
# Native, destructive-only-to-ephemeral-fixtures Windows 11 ticket-27 lab.
[CmdletBinding()]
param(
    [switch]$EphemeralCI,
    [switch]$ServiceDiagnostics
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $EphemeralCI) {
    throw 'This destructive lab requires the explicit -EphemeralCI flag.'
}
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:CI -ne 'true') {
    throw 'This destructive lab runs only in the authorized ephemeral CI environment.'
}

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Invoke-Checked([string]$File, [string[]]$Arguments) {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$File failed ($LASTEXITCODE)" }
}

function Write-ServiceDiagnostic([string]$Phase, [string]$Name) {
    if (-not $ServiceDiagnostics) { return }
    $stateCategory = 'query-error'
    $pidCategory = 'unknown'
    try {
        $service = Get-CimInstance Win32_Service -Filter "Name='$Name'"
        if ($null -eq $service) {
            $stateCategory = 'missing'
            $pidCategory = 'absent'
        }
        else {
            $pidCategory = if ([int]$service.ProcessId -gt 0) { 'present' } else { 'absent' }
            switch ([string]$service.State) {
                'Running' { $stateCategory = 'running' }
                'Start Pending' { $stateCategory = 'start-pending' }
                'Stop Pending' { $stateCategory = 'stop-pending' }
                'Stopped' {
                    if ([int]$service.ExitCode -ne 0 -or [int]$service.ServiceSpecificExitCode -ne 0) {
                        $stateCategory = 'stopped-exit-nonzero'
                    }
                    else {
                        $stateCategory = 'stopped-exit-zero'
                    }
                }
                default { $stateCategory = 'other' }
            }
        }
    }
    catch {
        $stateCategory = 'query-error'
        $pidCategory = 'unknown'
    }
    Write-Host "SCM_DIAG phase=$Phase state=$stateCategory pid=$pidCategory"
}

function Write-ServiceSubphaseDiagnostics([string]$Path) {
    if (-not $ServiceDiagnostics) { return }
    Assert-True (Test-Path -LiteralPath $Path -PathType Leaf) 'service diagnostic file is absent'
    $lines = @(Get-Content -LiteralPath $Path -ErrorAction Stop)
    Assert-True ($lines.Count -gt 0) 'service diagnostic file is empty'
    $allowed = @(
        'phase=args-ok'
        'phase=bootstrap-ok'
        'phase=audit-ok'
        'phase=agent-tls-ok'
        'phase=agent-pipe-ok'
        'phase=human-tls-ok'
        'phase=human-pipe-ok'
        'phase=human-accepted'
        'phase=human-magic-alpn'
        'phase=human-unlock-request'
        'phase=human-unlock-wrong-channel'
        'phase=human-unlock-storage-io'
        'phase=human-unlock-vault-crypto'
        'phase=human-unlock-vault-format'
        'phase=human-unlock-other'
        'phase=human-unlock-ok'
        'phase=human-unlock-ack'
        'phase=human-lock-request'
        'phase=human-audit-open'
        'phase=human-audit-append'
        'phase=human-lock-ack'
        'phase=service-failed'
    )
    foreach ($line in $lines) {
        Assert-True ($allowed -contains [string]$line) 'unexpected service diagnostic phase'
        Write-Host "SERVICE_PHASE $line"
    }
    Assert-HumanDiagnosticTrace $lines
}

function Assert-HumanDiagnosticTrace([object[]]$Lines) {
    $observed = @($Lines | Where-Object { [string]$_ -like 'phase=human-*' -and $_ -notin @('phase=human-tls-ok', 'phase=human-pipe-ok') })
    $prefix = @(
        'phase=human-accepted'
        'phase=human-magic-alpn'
        'phase=human-unlock-request'
    )
    $success = @($prefix) + @(
        'phase=human-unlock-ok'
        'phase=human-unlock-ack'
        'phase=human-lock-request'
        'phase=human-audit-open'
        'phase=human-audit-append'
        'phase=human-lock-ack'
    )
    $failurePhases = @(
        'phase=human-unlock-wrong-channel'
        'phase=human-unlock-storage-io'
        'phase=human-unlock-vault-crypto'
        'phase=human-unlock-vault-format'
        'phase=human-unlock-other'
    )
    $candidates = @()
    $candidates += ,$success
    foreach ($failure in $failurePhases) {
        $candidates += ,(@($prefix) + @($failure))
    }
    $validPrefix = $false
    foreach ($candidate in $candidates) {
        if ($observed.Count -gt $candidate.Count) { continue }
        $matches = $true
        for ($index = 0; $index -lt $observed.Count; $index++) {
            if ([string]$observed[$index] -ne [string]$candidate[$index]) {
                $matches = $false
                break
            }
        }
        if ($matches) {
            $validPrefix = $true
            break
        }
    }
    Assert-True $validPrefix 'human service diagnostic phases are out of order or repeated'
}

function Get-Sid([string]$Name) {
    return ([Security.Principal.NTAccount]$Name).Translate([Security.Principal.SecurityIdentifier]).Value
}

function Assert-ExactNodeAcl([string]$Path, [string[]]$Trustees) {
    $security = Get-Acl -LiteralPath $Path -ErrorAction Stop
    Assert-True $security.AreAccessRulesProtected "ACL inheritance remains enabled: $Path"
    $expectedSids = @($Trustees | ForEach-Object { Get-Sid $_ })
    $rules = @($security.Access)
    Assert-True ($rules.Count -eq $expectedSids.Count) "unexpected ACL entry count for $Path"
    $actualSids = @()
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        $actualSids += $sid
        Assert-True ($expectedSids -contains $sid) "unexpected ACL trustee on ${Path}: $sid"
        Assert-True ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) "deny ACL entry on ${Path}: $sid"
        Assert-True (-not $rule.IsInherited) "inherited ACL entry on ${Path}: $sid"
        Assert-True (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl) "non-full ACL entry on ${Path}: $sid"
    }
    foreach ($sid in $expectedSids) {
        $matching = @($actualSids | Where-Object { $_ -eq $sid })
        Assert-True ($matching.Count -eq 1) "missing ACL trustee on ${Path}: $sid"
    }
}

function Set-ExactTreeAcl([string]$Path, [string[]]$Trustees) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-True (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "refusing reparse ACL path: $Path"
    if ($item.PSIsContainer) {
        # Walk children first so the installer still reaches each child through
        # the parent while that child is being sealed. Never follow reparse
        # points or ask icacls to recurse opaquely.
        $children = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop)
        foreach ($child in $children) {
            Set-ExactTreeAcl $child.FullName $Trustees
        }
    }
    $permission = if ($item.PSIsContainer) { '(OI)(CI)F' } else { 'F' }
    # /reset removes prior explicit entries and restores only the parent's
    # staging ACL. That keeps the installer able to reach this node while the
    # next operation protects it and installs only the requested trustees.
    Invoke-Checked 'icacls.exe' @($Path, '/reset')
    # /inheritance:r then protects this node, while /grant:r installs only the
    # requested trustees. Omitting /c makes any per-node icacls failure fail the
    # fixture.
    $arguments = @($Path, '/inheritance:r', '/grant:r')
    foreach ($trustee in $Trustees) { $arguments += "${trustee}:$permission" }
    Invoke-Checked 'icacls.exe' $arguments
    Assert-ExactNodeAcl $Path $Trustees
}

function Add-OwnedPath([hashtable]$Owned, [string]$Path) {
    $Owned[[IO.Path]::GetFullPath($Path)] = $true
}

function Repair-OwnedCleanupAcl([string]$Path, [string]$Installer, [hashtable]$Owned) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-True ($Owned.ContainsKey([IO.Path]::GetFullPath($Path))) "refusing unplanned cleanup path: $Path"
    Assert-True (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "refusing reparse cleanup path: $Path"
    Invoke-Checked 'takeown.exe' @('/F', $Path, '/A')
    Invoke-Checked 'icacls.exe' @($Path, '/reset')
    $permission = if ($item.PSIsContainer) { '(OI)(CI)F' } else { 'F' }
    Invoke-Checked 'icacls.exe' @($Path, '/inheritance:r', '/grant:r', "${Installer}:$permission", "SYSTEM:$permission")
    Assert-ExactNodeAcl $Path @($Installer, 'SYSTEM')
    if ($item.PSIsContainer) {
        $children = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop)
        foreach ($child in $children) {
            Repair-OwnedCleanupAcl $child.FullName $Installer $Owned
        }
    }
}

function Remove-OwnedTree([string]$Path, [hashtable]$Owned) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-True ($Owned.ContainsKey([IO.Path]::GetFullPath($Path))) "refusing unplanned cleanup path: $Path"
    Assert-True (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "refusing reparse cleanup path: $Path"
    if ($item.PSIsContainer) {
        $children = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop)
        foreach ($child in $children) {
            Remove-OwnedTree $child.FullName $Owned
        }
    }
    Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
}

function Start-AsUser(
    [PSCredential]$Credential,
    [string]$File,
    [string[]]$Arguments,
    [string]$InputPath,
    [string]$OutputPath,
    [string]$ErrorPath
) {
    $parameters = @{
        FilePath = $File
        ArgumentList = $Arguments
        Credential = $Credential
        LoadUserProfile = $true
        Wait = $true
        PassThru = $true
        RedirectStandardOutput = $OutputPath
        RedirectStandardError = $ErrorPath
    }
    if ($InputPath) { $parameters.RedirectStandardInput = $InputPath }
    return Start-Process @parameters
}

function Assert-Arm64Pe([string]$Dumpbin, [string]$Path, [string]$Label) {
    Assert-True (Test-Path -LiteralPath $Path -PathType Leaf) "$Label is absent"
    $headers = @(& $Dumpbin '/headers' $Path)
    Assert-True ($LASTEXITCODE -eq 0) "$Label dumpbin /headers failed with exit code $LASTEXITCODE"
    $nativeHeaders = @($headers | Select-String -SimpleMatch 'AA64 machine (ARM64)')
    $foreignHeaders = @($headers | Select-String -Pattern 'machine \((x64|x86)\)')
    Assert-True ($nativeHeaders.Count -gt 0) "$Label is not an ARM64 PE"
    Assert-True ($foreignHeaders.Count -eq 0) "$Label contains a non-ARM64 PE section"
}

function Assert-NativeStaticMsvcBinary([string]$Dumpbin, [string]$Path, [string]$Label) {
    Assert-Arm64Pe $Dumpbin $Path $Label
    $dependents = @(& $Dumpbin '/dependents' $Path)
    Assert-True ($LASTEXITCODE -eq 0) "$Label dumpbin /dependents failed with exit code $LASTEXITCODE"
    $dynamicCrt = @(
        $dependents | Select-String -Pattern '(?i)(api-ms-win-crt-[^\s]+|ucrtbase\.dll|vcruntime[0-9_]*\.dll|msvcp[0-9_]*\.dll|msvcr[0-9_]*\.dll|msvcrt\.dll|concrt[0-9_]*\.dll|vcomp[0-9_]*\.dll)'
    )
    Assert-True ($dynamicCrt.Count -eq 0) "$Label links a dynamic MSVC runtime: $($dynamicCrt -join ', ')"
}

$product = (Get-CimInstance Win32_OperatingSystem).Caption
Assert-True ($product -match 'Windows 11') "Windows 11 required; observed $product"
$osArch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
$processArch = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
Assert-True ($osArch -eq $processArch) "native process required: OS=$osArch process=$processArch"
Assert-True ($osArch -in @('Arm64', 'X64')) "unsupported native CPU $osArch"
Assert-True (-not [string]::IsNullOrWhiteSpace($env:SODIUM_LIB_DIR)) 'Prepared SODIUM_LIB_DIR is required'
Assert-True (Test-Path -LiteralPath (Join-Path $env:SODIUM_LIB_DIR 'libsodium.lib') -PathType Leaf) 'Prepared libsodium.lib is absent'
foreach ($name in @('SODIUM_SHARED', 'SODIUM_USE_PKG_CONFIG', 'SODIUM_DIST_DIR')) {
    Assert-True (-not (Test-Path "Env:$name")) "Forbidden libsodium selection variable is present: $name"
}
Assert-True (-not [string]::IsNullOrWhiteSpace($env:PM_NATIVE_DUMPBIN)) 'Prepared ARM64 Dumpbin path is required'
$dumpbin = $env:PM_NATIVE_DUMPBIN
Assert-Arm64Pe $dumpbin $dumpbin 'Prepared ARM64 Dumpbin'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$gitCommon = (& git -C $repo rev-parse --path-format=absolute --git-common-dir).Trim()
Assert-True ($LASTEXITCODE -eq 0) 'git common directory unavailable'
$repositoryRoot = Split-Path $gitCommon -Parent
$env:RUSTUP_HOME = Join-Path $repositoryRoot '.toolchain\rustup'
$env:CARGO_HOME = Join-Path $repositoryRoot '.toolchain\cargo'
$env:PATH = (Join-Path $env:CARGO_HOME 'bin') + ';' + $env:PATH
$root = Join-Path $env:ProgramData ("PasswordManager-ticket27-" + [Guid]::NewGuid().ToString('N'))
$serviceDir = Join-Path $root 'service'
$agentDir = Join-Path $root 'agent'
$humanDir = Join-Path $root 'human'
$harnessDir = Join-Path $root 'harness'
$diagnosticDir = Join-Path $root 'service-diagnostics'
$diagnosticPath = Join-Path $diagnosticDir 'startup.phases'
$agentName = 'pm27agent'
$humanName = 'pm27human'
$serviceName = 'PasswordManager'
$syntheticPassword = ConvertTo-SecureString 'T27!Synthetic-Only-8472a' -AsPlainText -Force
$agentCredential = [PSCredential]::new("$env:COMPUTERNAME\$agentName", $syntheticPassword)
$humanCredential = [PSCredential]::new("$env:COMPUTERNAME\$humanName", $syntheticPassword)
$installerName = $null
$rootOwned = $false
$agentOwned = $false
$humanOwned = $false
$serviceOwned = $false
$locationPushed = $false
$bodyError = $null
$cleanupErrors = [System.Collections.Generic.List[string]]::new()
$ownedPaths = @{}
$passMessage = $null

try {
    $runnerPrincipal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    Assert-True ($runnerPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'lab requires an elevated ephemeral runner'
    $installerName = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    Assert-True (-not [string]::IsNullOrWhiteSpace($installerName)) 'elevated installer identity unavailable'

    # Refuse every collision before creating or changing a fixture. The fixed
    # names are deliberate so the test also exercises the installed names.
    Assert-True (-not (Test-Path -LiteralPath $root)) "fixture root already exists: $root"
    Assert-True ($null -eq (Get-CimInstance Win32_UserAccount -Filter "LocalAccount=TRUE AND Name='$agentName'")) "local user already exists: $agentName"
    Assert-True ($null -eq (Get-CimInstance Win32_UserAccount -Filter "LocalAccount=TRUE AND Name='$humanName'")) "local user already exists: $humanName"
    Assert-True ($null -eq (Get-CimInstance Win32_Service -Filter "Name='$serviceName'")) "service already exists: $serviceName"

    Push-Location $repo
    $locationPushed = $true

    New-Item -ItemType Directory -Path $root | Out-Null
    $rootOwned = $true
    Add-OwnedPath $ownedPaths $root
    Set-ExactTreeAcl $root @('SYSTEM', $installerName)
    New-LocalUser -Name $agentName -Password $syntheticPassword -PasswordNeverExpires | Out-Null
    $agentOwned = $true
    New-LocalUser -Name $humanName -Password $syntheticPassword -PasswordNeverExpires | Out-Null
    $humanOwned = $true
    Assert-True (-not ((Get-LocalGroupMember Administrators).Name -contains "$env:COMPUTERNAME\$agentName")) 'agent must not be administrator'
    New-Item -ItemType Directory -Path $serviceDir, $agentDir, $humanDir, $harnessDir | Out-Null
    foreach ($path in @($serviceDir, $agentDir, $humanDir, $harnessDir)) {
        Add-OwnedPath $ownedPaths $path
    }
    Set-ExactTreeAcl $serviceDir @('SYSTEM', $installerName)
    Set-ExactTreeAcl $agentDir @('SYSTEM', $installerName)
    Set-ExactTreeAcl $humanDir @('SYSTEM', $installerName)
    Set-ExactTreeAcl $harnessDir @('SYSTEM', $installerName)
    if ($ServiceDiagnostics) {
        New-Item -ItemType Directory -Path $diagnosticDir | Out-Null
        Add-OwnedPath $ownedPaths $diagnosticDir
        Set-ExactTreeAcl $diagnosticDir @('SYSTEM', $installerName)
    }

    Invoke-Checked 'cargo' @('test', '-p', 'pm-native-channel', '--all-targets', '--locked', '--offline')
    Invoke-Checked 'cargo' @('build', '-p', 'pm-custody', '-p', 'pm-cli', '--locked', '--offline')
    $custody = Join-Path $repo 'target\debug\pm-custody.exe'
    $cli = Join-Path $repo 'target\debug\pm.exe'
    Assert-True ((Get-Item $custody).VersionInfo.FileName.EndsWith('.exe')) 'native PE custody binary missing'
    Assert-True ((Get-Item $cli).VersionInfo.FileName.EndsWith('.exe')) 'native PE CLI binary missing'
    Assert-NativeStaticMsvcBinary $dumpbin $custody 'pm-custody.exe'
    Assert-NativeStaticMsvcBinary $dumpbin $cli 'pm.exe'

    $agentSid = Get-Sid "$env:COMPUTERNAME\$agentName"
    $humanSid = Get-Sid "$env:COMPUTERNAME\$humanName"
    # Omit password= for a virtual account: SCM maps the absent argument to
    # the required NULL lpPassword value, rather than an empty string.
    Invoke-Checked 'sc.exe' @('create', $serviceName, 'type=', 'own', 'start=', 'demand', 'obj=', "NT SERVICE\$serviceName", 'binPath=', 'cmd /c exit 0')
    $serviceOwned = $true
    Invoke-Checked 'sc.exe' @('sidtype', $serviceName, 'unrestricted')
    $serviceSid = Get-Sid "NT SERVICE\$serviceName"
    if ($ServiceDiagnostics) {
        Add-OwnedPath $ownedPaths $diagnosticPath
        [IO.File]::WriteAllText($diagnosticPath, [string]::Empty)
        Set-ExactTreeAcl $diagnosticDir @('SYSTEM', $installerName, "NT SERVICE\$serviceName")
        Assert-ExactNodeAcl $diagnosticDir @('SYSTEM', $installerName, "NT SERVICE\$serviceName")
        Assert-ExactNodeAcl $diagnosticPath @('SYSTEM', $installerName, "NT SERVICE\$serviceName")
    }

    $serverPrivate = Join-Path $serviceDir 'server.key'
    $serverPublic = Join-Path $serviceDir 'server.rpk'
    $agentPrivate = Join-Path $agentDir 'agent.key'
    $agentPublic = Join-Path $agentDir 'agent.rpk'
    $humanPrivate = Join-Path $humanDir 'human.key'
    $humanPublic = Join-Path $humanDir 'human.rpk'
    foreach ($path in @($serverPrivate, $serverPublic, $agentPrivate, $agentPublic, $humanPrivate, $humanPublic)) {
        Add-OwnedPath $ownedPaths $path
    }
    Invoke-Checked $custody @('keygen', '--private', $serverPrivate, '--public', $serverPublic)
    Invoke-Checked $custody @('keygen', '--private', $agentPrivate, '--public', $agentPublic)
    Invoke-Checked $custody @('keygen', '--private', $humanPrivate, '--public', $humanPublic)
    $bootstrap = Join-Path $serviceDir 'bootstrap.dpapi'
    Add-OwnedPath $ownedPaths $bootstrap
    Invoke-Checked $custody @('provision-bootstrap', '--path', $bootstrap, '--server-private', $serverPrivate, '--server-public', $serverPublic, '--service-sid', $serviceSid, '--agent-public', $agentPublic, '--agent-sid', $agentSid, '--human-public', $humanPublic, '--human-sid', $humanSid)
    $agentProfile = Join-Path $agentDir 'profile'
    $humanProfile = Join-Path $humanDir 'profile'
    Add-OwnedPath $ownedPaths $agentProfile
    Add-OwnedPath $ownedPaths $humanProfile
    Invoke-Checked $custody @('provision-profile', '--path', $agentProfile, '--server-public', $serverPublic, '--role', 'agent')
    Invoke-Checked $custody @('provision-profile', '--path', $humanProfile, '--server-public', $serverPublic, '--role', 'human')
    # Create a synthetic vault without ever printing its recovery code.
    $vault = Join-Path $serviceDir 'vault.sqlite3'
    $auditPath = "${vault}.audit-custody"
    Add-OwnedPath $ownedPaths $vault
    Add-OwnedPath $ownedPaths $auditPath
    $master = 'synthetic ticket 27 master only'
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = [Diagnostics.ProcessStartInfo]::new($cli, "vault create `"$vault`"")
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.RedirectStandardInput = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    Assert-True $process.Start() 'pm-cli did not start'
    $process.StandardInput.WriteLine($master)
    $process.StandardInput.WriteLine($master)
    $null = $process.StandardOutput.ReadLine()
    $null = $process.StandardOutput.ReadLine()
    $recoveryLine = $process.StandardOutput.ReadLine()
    Assert-True ($recoveryLine -match '^Recovery code .*: (PMR1-.+)$') 'synthetic recovery not emitted'
    $process.StandardInput.WriteLine($Matches[1])
    $process.StandardInput.Close()
    $process.WaitForExit()
    Assert-True ($process.ExitCode -eq 0) ('vault create failed: ' + $process.StandardError.ReadToEnd())

    # Start-Process owns the redirection handles in the elevated installer.
    # Keep all input/output in a non-custodial synthetic harness that retains
    # only SYSTEM and installer access; role directories are sealed below.
    $emptyInput = Join-Path $harnessDir 'empty.in'
    $agentOut = Join-Path $harnessDir 'probe.out'; $agentErr = Join-Path $harnessDir 'probe.err'
    $humanInput = Join-Path $harnessDir 'master.in'
    $humanOut = Join-Path $harnessDir 'human.out'; $humanErr = Join-Path $harnessDir 'human.err'
    $badOut = Join-Path $harnessDir 'bad.out'; $badErr = Join-Path $harnessDir 'bad.err'
    foreach ($path in @($emptyInput, $agentOut, $agentErr, $humanInput, $humanOut, $humanErr, $badOut, $badErr)) {
        Add-OwnedPath $ownedPaths $path
    }
    [IO.File]::WriteAllBytes($emptyInput, [byte[]]@())
    [IO.File]::WriteAllText($humanInput, $master + [Environment]::NewLine)
    foreach ($path in @($agentOut, $agentErr, $humanOut, $humanErr, $badOut, $badErr)) {
        [IO.File]::WriteAllText($path, [string]::Empty)
    }

    # The installer is intentionally removed before any runtime process starts.
    Set-ExactTreeAcl $serviceDir @('SYSTEM', "NT SERVICE\$serviceName")
    Set-ExactTreeAcl $agentDir @('SYSTEM', "$env:COMPUTERNAME\$agentName")
    Set-ExactTreeAcl $humanDir @('SYSTEM', "$env:COMPUTERNAME\$humanName")

    $vaultId = '27aa27aa27aa27aa27aa27aa27aa27aa'
    $device = '27272727272727272727272727272727'
    $binPath = "`"$custody`" service --bootstrap `"$bootstrap`" --vault-id $vaultId --vault `"$vault`" --device $device"
    if ($ServiceDiagnostics) {
        $binPath += " --service-diagnostics `"$diagnosticPath`""
    }
    Invoke-Checked 'sc.exe' @('config', $serviceName, 'binPath=', $binPath)
    Write-ServiceDiagnostic 'before-start' $serviceName
    Invoke-Checked 'sc.exe' @('start', $serviceName)
    Write-ServiceDiagnostic 'after-start' $serviceName
    Start-Sleep -Seconds 2
    Write-ServiceDiagnostic 'after-settle' $serviceName
    Write-ServiceSubphaseDiagnostics $diagnosticPath
    Assert-True ((Get-Service $serviceName).Status -eq 'Running') 'custody service did not reach RUNNING'

    $p = Start-AsUser $agentCredential $custody @('probe', '--profile', $agentProfile, '--private', $agentPrivate, '--vault-id', $vaultId) $emptyInput $agentOut $agentErr
    Assert-True ($p.ExitCode -eq 0) ('agent native probe failed: ' + (Get-Content $agentErr -Raw))
    Assert-True ((Get-Content $agentOut -Raw) -match 'tls=1.3 rpk=pinned named-pipe=bilateral') 'agent did not prove pinned transport'

    $p = Start-AsUser $humanCredential $custody @('human-lock', '--profile', $humanProfile, '--private', $humanPrivate, '--vault-id', $vaultId) $humanInput $humanOut $humanErr
    Write-ServiceSubphaseDiagnostics $diagnosticPath
    Assert-True ($p.ExitCode -eq 0) ('human native channel failed: ' + (Get-Content $humanErr -Raw))

    # Cross-role RPK/SID substitution must fail before vault operation.
    $p = Start-AsUser $agentCredential $custody @('probe', '--profile', $humanProfile, '--private', $agentPrivate, '--vault-id', $vaultId) $emptyInput $badOut $badErr
    Assert-True ($p.ExitCode -ne 0) 'cross-role identity substitution unexpectedly succeeded'

    $servicePid = (Get-CimInstance Win32_Service -Filter "Name='$serviceName'").ProcessId
    Assert-True ($servicePid -gt 0) 'SCM did not expose service PID'
    Stop-Process -Id $servicePid -Force
    Start-Sleep -Seconds 1
    Invoke-Checked 'sc.exe' @('start', $serviceName)
    Start-Sleep -Seconds 2
    Assert-True ((Get-Service $serviceName).Status -eq 'Running') 'service restart failed'
    $p = Start-AsUser $agentCredential $custody @('probe', '--profile', $agentProfile, '--private', $agentPrivate, '--vault-id', $vaultId) $emptyInput $agentOut $agentErr
    Assert-True ($p.ExitCode -eq 0) 'persistent vault failed after service restart'

    $passMessage = "PASS ticket27 windows=$product cpu=$osArch service-virtual-account=1 dacl=protected dpapi=machine pipe=bilateral tls=1.3-rpk human=unlock-lock restart=1 agent-admin=0"
}
catch {
    $bodyError = $_
}
finally {
    if ($serviceOwned) {
        try {
            $installed = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
            if ($null -ne $installed -and $installed.State -ne 'Stopped') {
                Stop-Service -Name $serviceName -Force -ErrorAction Stop
            }
            Invoke-Checked 'sc.exe' @('delete', $serviceName)
        }
        catch { $cleanupErrors.Add("service cleanup failed: $($_.Exception.Message)") }
    }
    if ($agentOwned) {
        try { Remove-LocalUser -Name $agentName -ErrorAction Stop }
        catch { $cleanupErrors.Add("agent user cleanup failed: $($_.Exception.Message)") }
    }
    if ($humanOwned) {
        try { Remove-LocalUser -Name $humanName -ErrorAction Stop }
        catch { $cleanupErrors.Add("human user cleanup failed: $($_.Exception.Message)") }
    }
    if ($rootOwned) {
        try {
            # Runtime DACLs deliberately exclude the installer after sealing;
            # recover access only for this collision-checked owned tree, one
            # non-reparse node at a time, then remove it without -Recurse.
            Repair-OwnedCleanupAcl $root $installerName $ownedPaths
            Remove-OwnedTree $root $ownedPaths
        }
        catch { $cleanupErrors.Add("fixture cleanup failed: $($_.Exception.Message)") }
    }
    if ($locationPushed) {
        try { Pop-Location -ErrorAction Stop }
        catch { $cleanupErrors.Add("location cleanup failed: $($_.Exception.Message)") }
    }
}

if ($cleanupErrors.Count -gt 0) {
    $prefix = if ($null -ne $bodyError) { "$($bodyError.Exception.Message); " } else { '' }
    throw ($prefix + ($cleanupErrors -join '; '))
}
if ($null -ne $bodyError) { throw $bodyError }
Write-Output $passMessage
