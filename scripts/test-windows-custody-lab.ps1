# SPDX-License-Identifier: AGPL-3.0-only
# Native, destructive-only-to-ephemeral-fixtures Windows 11 ticket-27 lab.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Invoke-Checked([string]$File, [string[]]$Arguments) {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$File failed ($LASTEXITCODE)" }
}

function Get-Sid([string]$Name) {
    return ([Security.Principal.NTAccount]$Name).Translate([Security.Principal.SecurityIdentifier]).Value
}

function Set-ExactTreeAcl([string]$Path, [string[]]$Trustees) {
    Invoke-Checked 'icacls.exe' @($Path, '/inheritance:r')
    $grants = @('/grant:r')
    foreach ($trustee in $Trustees) { $grants += "${trustee}:(OI)(CI)F" }
    Invoke-Checked 'icacls.exe' (@($Path) + $grants + @('/t', '/c'))
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

$product = (Get-CimInstance Win32_OperatingSystem).Caption
Assert-True ($product -match 'Windows 11') "Windows 11 required; observed $product"
$osArch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
$processArch = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
Assert-True ($osArch -eq $processArch) "native process required: OS=$osArch process=$processArch"
Assert-True ($osArch -in @('Arm64', 'X64')) "unsupported native CPU $osArch"

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $repo
$gitCommon = (& git -C $repo rev-parse --path-format=absolute --git-common-dir).Trim()
Assert-True ($LASTEXITCODE -eq 0) 'git common directory unavailable'
$repositoryRoot = Split-Path $gitCommon -Parent
$env:RUSTUP_HOME = Join-Path $repositoryRoot '.toolchain\rustup'
$env:CARGO_HOME = Join-Path $repositoryRoot '.toolchain\cargo'
$env:PATH = (Join-Path $env:CARGO_HOME 'bin') + ';' + $env:PATH
Invoke-Checked 'cargo' @('fetch', '--locked')
$root = Join-Path $env:ProgramData ("PasswordManager-ticket27-" + [Guid]::NewGuid().ToString('N'))
$serviceDir = Join-Path $root 'service'
$agentDir = Join-Path $root 'agent'
$humanDir = Join-Path $root 'human'
$agentName = 'pm27agent'
$humanName = 'pm27human'
$serviceName = 'PasswordManager'
$syntheticPassword = ConvertTo-SecureString 'T27!Synthetic-Only-8472a' -AsPlainText -Force
$agentCredential = [PSCredential]::new("$env:COMPUTERNAME\$agentName", $syntheticPassword)
$humanCredential = [PSCredential]::new("$env:COMPUTERNAME\$humanName", $syntheticPassword)

try {
    Assert-True ((whoami /groups) -match 'S-1-5-32-544') 'lab requires an elevated ephemeral runner'
    New-LocalUser -Name $agentName -Password $syntheticPassword -PasswordNeverExpires | Out-Null
    New-LocalUser -Name $humanName -Password $syntheticPassword -PasswordNeverExpires | Out-Null
    Assert-True (-not ((Get-LocalGroupMember Administrators).Name -contains "$env:COMPUTERNAME\$agentName")) 'agent must not be administrator'
    New-Item -ItemType Directory -Path $serviceDir, $agentDir, $humanDir | Out-Null

    Invoke-Checked 'cargo' @('test', '-p', 'pm-native-channel', '--all-targets', '--locked', '--offline')
    Invoke-Checked 'cargo' @('build', '-p', 'pm-custody', '-p', 'pm-cli', '--locked', '--offline')
    $custody = Join-Path $repo 'target\debug\pm-custody.exe'
    $cli = Join-Path $repo 'target\debug\pm-cli.exe'
    Assert-True ((Get-Item $custody).VersionInfo.FileName.EndsWith('.exe')) 'native PE custody binary missing'

    $agentSid = Get-Sid "$env:COMPUTERNAME\$agentName"
    $humanSid = Get-Sid "$env:COMPUTERNAME\$humanName"
    Invoke-Checked 'sc.exe' @('create', $serviceName, 'type=', 'own', 'start=', 'demand', 'obj=', "NT SERVICE\$serviceName", 'password=', '', 'binPath=', 'cmd /c exit 0')
    Invoke-Checked 'sc.exe' @('sidtype', $serviceName, 'unrestricted')
    $serviceSid = Get-Sid "NT SERVICE\$serviceName"

    Set-ExactTreeAcl $serviceDir @('SYSTEM', "NT SERVICE\$serviceName")
    Set-ExactTreeAcl $agentDir @('SYSTEM', "$env:COMPUTERNAME\$agentName")
    Set-ExactTreeAcl $humanDir @('SYSTEM', "$env:COMPUTERNAME\$humanName")

    $serverPrivate = Join-Path $serviceDir 'server.key'
    $serverPublic = Join-Path $serviceDir 'server.rpk'
    $agentPrivate = Join-Path $agentDir 'agent.key'
    $agentPublic = Join-Path $agentDir 'agent.rpk'
    $humanPrivate = Join-Path $humanDir 'human.key'
    $humanPublic = Join-Path $humanDir 'human.rpk'
    Invoke-Checked $custody @('keygen', '--private', $serverPrivate, '--public', $serverPublic)
    Invoke-Checked $custody @('keygen', '--private', $agentPrivate, '--public', $agentPublic)
    Invoke-Checked $custody @('keygen', '--private', $humanPrivate, '--public', $humanPublic)
    $bootstrap = Join-Path $serviceDir 'bootstrap.dpapi'
    Invoke-Checked $custody @('provision-bootstrap', '--path', $bootstrap, '--server-private', $serverPrivate, '--server-public', $serverPublic, '--service-sid', $serviceSid, '--agent-public', $agentPublic, '--agent-sid', $agentSid, '--human-public', $humanPublic, '--human-sid', $humanSid)
    $agentProfile = Join-Path $agentDir 'profile'
    $humanProfile = Join-Path $humanDir 'profile'
    Invoke-Checked $custody @('provision-profile', '--path', $agentProfile, '--server-public', $serverPublic, '--role', 'agent')
    Invoke-Checked $custody @('provision-profile', '--path', $humanProfile, '--server-public', $serverPublic, '--role', 'human')
    Set-ExactTreeAcl $serviceDir @('SYSTEM', "NT SERVICE\$serviceName")
    Set-ExactTreeAcl $agentDir @('SYSTEM', "$env:COMPUTERNAME\$agentName")
    Set-ExactTreeAcl $humanDir @('SYSTEM', "$env:COMPUTERNAME\$humanName")

    # Create a synthetic vault without ever printing its recovery code.
    $vault = Join-Path $serviceDir 'vault.sqlite3'
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = [Diagnostics.ProcessStartInfo]::new($cli, "vault create `"$vault`"")
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.RedirectStandardInput = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    Assert-True $process.Start() 'pm-cli did not start'
    $master = 'synthetic ticket 27 master only'
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
    Set-ExactTreeAcl $serviceDir @('SYSTEM', "NT SERVICE\$serviceName")

    $vaultId = '27aa27aa27aa27aa27aa27aa27aa27aa'
    $device = '27272727272727272727272727272727'
    $binPath = "`"$custody`" service --bootstrap `"$bootstrap`" --vault-id $vaultId --vault `"$vault`" --device $device"
    Invoke-Checked 'sc.exe' @('config', $serviceName, 'binPath=', $binPath)
    Invoke-Checked 'sc.exe' @('start', $serviceName)
    Start-Sleep -Seconds 2
    Assert-True ((Get-Service $serviceName).Status -eq 'Running') 'custody service did not reach RUNNING'

    $emptyInput = Join-Path $agentDir 'empty.in'; [IO.File]::WriteAllBytes($emptyInput, @())
    $agentOut = Join-Path $agentDir 'probe.out'; $agentErr = Join-Path $agentDir 'probe.err'
    $p = Start-AsUser $agentCredential $custody @('probe', '--profile', $agentProfile, '--private', $agentPrivate, '--vault-id', $vaultId) $emptyInput $agentOut $agentErr
    Assert-True ($p.ExitCode -eq 0) ('agent native probe failed: ' + (Get-Content $agentErr -Raw))
    Assert-True ((Get-Content $agentOut -Raw) -match 'tls=1.3 rpk=pinned named-pipe=bilateral') 'agent did not prove pinned transport'

    $humanInput = Join-Path $humanDir 'master.in'; [IO.File]::WriteAllText($humanInput, $master + "`n")
    $humanOut = Join-Path $humanDir 'human.out'; $humanErr = Join-Path $humanDir 'human.err'
    $p = Start-AsUser $humanCredential $custody @('human-lock', '--profile', $humanProfile, '--private', $humanPrivate, '--vault-id', $vaultId) $humanInput $humanOut $humanErr
    Assert-True ($p.ExitCode -eq 0) ('human native channel failed: ' + (Get-Content $humanErr -Raw))

    # Cross-role RPK/SID substitution must fail before vault operation.
    $badOut = Join-Path $agentDir 'bad.out'; $badErr = Join-Path $agentDir 'bad.err'
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

    Write-Output "PASS ticket27 windows=$product cpu=$osArch service-virtual-account=1 dacl=protected dpapi=machine pipe=bilateral tls=1.3-rpk human=unlock-lock restart=1 agent-admin=0"
}
finally {
    $installed = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
    if ($null -ne $installed -and $installed.ProcessId -gt 0) {
        Stop-Process -Id $installed.ProcessId -Force -ErrorAction SilentlyContinue
    }
    sc.exe delete $serviceName 2>$null | Out-Null
    Remove-LocalUser -Name $agentName -ErrorAction SilentlyContinue
    Remove-LocalUser -Name $humanName -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    Pop-Location
}
