# SPDX-License-Identifier: AGPL-3.0-only
# Native, destructive-only-to-ephemeral-fixtures Windows 11 ticket-27 lab.
[CmdletBinding()]
param(
    [switch]$EphemeralCI,
    [switch]$ServiceDiagnostics,
    [switch]$TuiConPtyRed,
    [switch]$OnePuxMemoryDiagnostics
)

if ($OnePuxMemoryDiagnostics -and (-not $ServiceDiagnostics -or $TuiConPtyRed)) {
    throw 'Focused memory diagnostics require ServiceDiagnostics and exclude TuiConPtyRed.'
}
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

function Assert-TuiFixtureOutput([string]$Path, [string]$Scenario) {
    $actual = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    Assert-True ($null -ne $actual) "$Scenario fixture emitted empty public output"
    $exact = $actual -ceq "TUI_CONPTY_READY`n"
    $lf = $actual.EndsWith("`n")
    $crlf = $actual.EndsWith("`r`n")
    Write-Host "TUI_PUBLIC_OUTPUT scenario=$Scenario chars=$($actual.Length) lf=$lf crlf=$crlf exact=$exact"
    Assert-True $exact "$Scenario fixture emitted unexpected public output"
}

function Invoke-Checked([string]$File, [string[]]$Arguments) {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$File failed ($LASTEXITCODE)" }
}

function Get-StoppableServicePid([string]$Name) {
    $record = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
    Assert-True ($null -ne $record) 'owned service record is absent'
    Assert-True ([string]$record.State -eq 'Running') 'owned service is not RUNNING'
    Assert-True ([int]$record.ProcessId -gt 0) 'SCM did not expose service PID'
    $controller = Get-Service -Name $Name -ErrorAction Stop
    Assert-True $controller.CanStop 'RUNNING service did not advertise SERVICE_ACCEPT_STOP'
    return [int]$record.ProcessId
}

function Stop-OwnedService([string]$Name, [int]$ServiceProcessId) {
    Stop-Service -Name $Name -ErrorAction Stop
    $service = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
    Assert-True ($null -ne $service) 'owned service record vanished during STOP'
    Assert-True ([string]$service.State -eq 'Stopped') 'service did not reach STOPPED'
    Assert-True ([int]$service.ProcessId -eq 0) 'SCM retained a PID after STOPPED'
    $process = @(Get-CimInstance Win32_Process -Filter "ProcessId=$ServiceProcessId" -ErrorAction Stop)
    Assert-True ($process.Count -eq 0) 'stopped service PID remains alive'
}

function Start-OwnedServiceWithNewPid([string]$Name, [int]$PreviousProcessId) {
    Start-Service -Name $Name -ErrorAction Stop
    $current = Get-StoppableServicePid $Name
    Assert-True ($current -ne $PreviousProcessId) 'service restart reused the terminated PID'
    return $current
}

function Assert-OwnedResourcesAbsent(
    [bool]$ServiceWasOwned,
    [string]$ServiceName,
    [bool]$AgentWasOwned,
    [string]$AgentName,
    [bool]$HumanWasOwned,
    [string]$HumanName,
    [bool]$RootWasOwned,
    [string]$RootPath
) {
    if ($ServiceWasOwned) {
        $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
        Assert-True ($null -eq $service) 'owned service remains after cleanup'
    }
    if ($AgentWasOwned -or $HumanWasOwned) {
        $users = @(Get-LocalUser -ErrorAction Stop)
        if ($AgentWasOwned) {
            $agentMatches = @($users | Where-Object { [string]$_.Name -ceq $AgentName })
            Assert-True ($agentMatches.Count -eq 0) 'owned agent user remains after cleanup'
        }
        if ($HumanWasOwned) {
            $humanMatches = @($users | Where-Object { [string]$_.Name -ceq $HumanName })
            Assert-True ($humanMatches.Count -eq 0) 'owned human user remains after cleanup'
        }
    }
    if ($RootWasOwned) {
        Assert-True (-not (Test-Path -LiteralPath $RootPath -ErrorAction Stop)) 'owned fixture root remains after cleanup'
    }
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
        'phase=transfer-ack31'
        'phase=transfer-token'
        'phase=transfer-duplicated'
        'phase=transfer-duplicate-failed'
        'phase=transfer-preview-sent'
        'phase=transfer-preview-handler-failed'
        'phase=service-failed'
    )
    foreach ($stage in @('preview', 'preparation', 'signature', 'frame-ready', 'frame-sent', 'frame-failed')) {
        foreach ($category in @('ok', 'crypto-resource', 'crypto-other', 'invalid-input', 'io-permission', 'io-eof', 'io-input', 'io-other', 'storage', 'state-changed', 'wrong-channel', 'other')) {
            $allowed += "phase=onepux-$stage category=$category"
        }
    }
    foreach ($line in $lines) {
        $memoryStatus = [string]$line -match '^phase=protected-memory-status live-capacity=[0-9]+ budget=33554432 live-payload-pages=[0-9]+ live-locked-pages=[0-9]+ live-budget-pages=[0-9]+ page-bytes=[0-9]+ live-regions=[0-9]+ working-set-min=[0-9]+ working-set-max=[0-9]+ working-set-flags=[0-9]+$'
        $memoryFailure = [string]$line -match '^phase=protected-memory-failure category=(budget|page-budget|alloc|virtual-lock|working-set-query|working-set-set|working-set-effective) requested-capacity=[0-9]+ requested-payload-pages=[0-9]+ win32-error=[0-9]+$'
        Assert-True (($allowed -contains [string]$line) -or $memoryStatus -or $memoryFailure) 'unexpected service diagnostic phase'
        if ($memoryStatus) {
            Assert-True ([string]$line -match 'working-set-min=([0-9]+) working-set-max=([0-9]+) working-set-flags=10$') 'working-set policy is not soft min/max'
            Assert-True ([long]$Matches[1] -ge 67108864 -and [long]$Matches[2] -ge [long]$Matches[1]) 'effective service quota is insufficient'
        }
        Write-Host "SERVICE_PHASE $line"
    }
    Assert-ServiceDiagnosticGenerations $lines
    Assert-HumanDiagnosticTrace $lines
}

function Write-ServiceDumpPolicyObservation {
    # Read only fixed product keys. Never crash a process or create a dump.
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
        try {
            $wer = 'SOFTWARE\Microsoft\Windows\Windows Error Reporting'
            $global = $base.OpenSubKey("$wer\LocalDumps", $false)
            $service = $base.OpenSubKey("$wer\LocalDumps\pm-custody.exe", $false)
            $exclusions = $base.OpenSubKey("$wer\ExcludedApplications", $false)
            try {
                $globalPresent = $null -ne $global
                $servicePresent = $null -ne $service
                $excluded = $null -ne $exclusions -and $null -ne $exclusions.GetValue('pm-custody.exe', $null)
                Write-Host "WER_POLICY view=$view global-localdumps-key=$globalPresent service-localdumps-key=$servicePresent all-user-exclusion-value=$excluded scope=registry-only crash=not-run acceptance=not-demonstrated"
            }
            finally {
                if ($null -ne $global) { $global.Dispose() }
                if ($null -ne $service) { $service.Dispose() }
                if ($null -ne $exclusions) { $exclusions.Dispose() }
            }
        }
        finally { $base.Dispose() }
    }
}

function Assert-ServiceDiagnosticGenerations([object[]]$Lines) {
    $starts = @()
    for ($index = 0; $index -lt $Lines.Count; $index++) {
        if ([string]$Lines[$index] -eq 'phase=args-ok') { $starts += $index }
    }
    Assert-True ($starts.Count -gt 0 -and $starts[0] -eq 0) 'diagnostic history lacks its first service generation'
    for ($generation = 0; $generation -lt $starts.Count; $generation++) {
        $end = if ($generation + 1 -lt $starts.Count) { $starts[$generation + 1] } else { $Lines.Count }
        $segment = @($Lines[$starts[$generation]..($end - 1)])
        foreach ($phase in @('phase=args-ok', 'phase=bootstrap-ok', 'phase=audit-ok', 'phase=agent-tls-ok', 'phase=agent-pipe-ok', 'phase=human-tls-ok', 'phase=human-pipe-ok')) {
            $matching = @($segment | Where-Object { [string]$_ -eq $phase })
            Assert-True ($matching.Count -eq 1) "service generation has missing/repeated phase: $phase"
        }
        Assert-True ([Array]::IndexOf($segment, 'phase=agent-tls-ok') -lt [Array]::IndexOf($segment, 'phase=agent-pipe-ok')) 'agent pipe preceded its TLS configuration'
        Assert-True ([Array]::IndexOf($segment, 'phase=human-tls-ok') -lt [Array]::IndexOf($segment, 'phase=human-pipe-ok')) 'human pipe preceded its TLS configuration'
        $firstConnection = [Array]::IndexOf($segment, 'phase=human-accepted')
        if ($firstConnection -ge 0) {
            Assert-True ([Array]::IndexOf($segment, 'phase=agent-pipe-ok') -lt $firstConnection) 'agent listener was not ready before a human connection'
            Assert-True ([Array]::IndexOf($segment, 'phase=human-pipe-ok') -lt $firstConnection) 'human listener was not ready before a human connection'
        }
        $failed = @($segment | Where-Object { [string]$_ -eq 'phase=service-failed' })
        Assert-True ($failed.Count -le 1) 'service generation repeated its terminal failure'
        if ($failed.Count -eq 1) {
            Assert-True ([string]$segment[-1] -eq 'phase=service-failed') 'service failure was not terminal in its generation'
        }
    }
}

function Assert-OneHumanDiagnosticTrace([object[]]$Observed) {
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
        if ($Observed.Count -gt $candidate.Count) { continue }
        $matches = $true
        for ($index = 0; $index -lt $Observed.Count; $index++) {
            if ([string]$Observed[$index] -ne [string]$candidate[$index]) {
                $matches = $false
                break
            }
        }
        if ($matches) {
            $validPrefix = $true
            break
        }
    }
    Assert-True $validPrefix 'one human connection has phases out of order or repeated'
}

function Assert-HumanDiagnosticTrace([object[]]$Lines) {
    $observed = @($Lines | Where-Object { [string]$_ -like 'phase=human-*' -and $_ -notin @('phase=human-tls-ok', 'phase=human-pipe-ok') })
    $trace = [Collections.Generic.List[object]]::new()
    foreach ($phase in $observed) {
        if ([string]$phase -eq 'phase=human-accepted' -and $trace.Count -gt 0) {
            Assert-OneHumanDiagnosticTrace ($trace.ToArray())
            $trace.Clear()
        }
        Assert-True ($trace.Count -gt 0 -or [string]$phase -eq 'phase=human-accepted') 'human phase lacks its connection boundary'
        $trace.Add($phase)
    }
    if ($trace.Count -gt 0) { Assert-OneHumanDiagnosticTrace ($trace.ToArray()) }
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

function Open-StoppedInstallerNode([string]$Path) {
    $record = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop
    Assert-True ($null -ne $record -and $record.State -eq 'Stopped' -and [int]$record.ProcessId -eq 0) 'device audit move requires stopped SCM'
    Assert-True ($ownedPaths.ContainsKey([IO.Path]::GetFullPath($Path))) 'device node not in owned ledger'
    Invoke-Checked 'takeown.exe' @('/F', $Path, '/A')
    Invoke-Checked 'icacls.exe' @($Path, '/grant:r', "${installerName}:F")
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-True (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'device move refuses reparse'
    # Runtime atomic replacement may inherit the sealed parent's role ACL.
    # Provision an explicit protected ACL while SCM is stopped, after proving
    # the inherited/effective trustees are exactly the same three principals.
    $before = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $expected = @(@('SYSTEM', $installerName, "NT SERVICE\$serviceName") | ForEach-Object { Get-Sid $_ })
    $seen = @{}
    foreach ($rule in @($before.Access)) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        Assert-True ($expected -contains $sid) 'stopped installer node has unexpected trustee'
        Assert-True ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) 'stopped installer node has deny ACE'
        Assert-True (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl) 'stopped installer node lacks full role rights'
        $seen[$sid] = $true
    }
    Assert-True ($seen.Count -eq $expected.Count) 'stopped installer node lacks an expected trustee'
    $inherited = @($before.Access | Where-Object { $_.IsInherited }).Count
    Write-Host "STOPPED_NODE_ACL protected=$($before.AreAccessRulesProtected) entries=$(@($before.Access).Count) inherited=$inherited trustees=exact rights=full"
    $rolePermission = if ($item.PSIsContainer) { '(OI)(CI)F' } else { 'F' }
    Invoke-Checked 'icacls.exe' @($Path, '/inheritance:r', '/grant:r', "SYSTEM:$rolePermission", "NT SERVICE\${serviceName}:$rolePermission", "${installerName}:F")
    Assert-ExactNodeAcl $Path @('SYSTEM', $installerName, "NT SERVICE\$serviceName")
}

function Close-StoppedInstallerDirectory([string]$Path) {
    Invoke-Checked 'icacls.exe' @($Path, '/remove:g', $installerName)
    Assert-ExactNodeAcl $Path @('SYSTEM', "NT SERVICE\$serviceName")
}

function Write-SyncTimingSummary([string]$Path, [string]$Source = 'server') {
    $totals = @{}
    foreach ($line in @(Get-Content -LiteralPath $Path -ErrorAction Stop)) {
        if ([string]::IsNullOrEmpty($line)) { continue }
        Assert-True ($line -cmatch '^PMW2_TIMING category=([a-z_]+) count=([0-9]+) us=([0-9]+)$') 'sync server emitted unexpected diagnostics'
        if ($Source -eq 'job') { Write-Host "WINDOWS_SYNC_SAMPLE $line" }
        $category = $Matches[1]; $count = [long]$Matches[2]; $us = [long]$Matches[3]
        if (-not $totals.ContainsKey($category)) { $totals[$category] = @{ Count = 0L; Us = 0L; Max = 0L } }
        $totals[$category].Count += $count; $totals[$category].Us += $us
        $totals[$category].Max = [Math]::Max($totals[$category].Max, $us)
    }
    foreach ($category in @($totals.Keys | Sort-Object)) {
        $row = $totals[$category]
        Write-Host "WINDOWS_SYNC_TIMING source=$Source category=$category count=$($row.Count) us=$($row.Us) max_us=$($row.Max)"
    }
    if ($Source -eq 'job') {
        foreach ($required in @('job_prepare', 'events', 'process_started', 'spawn_to_main', 'client_prepare', 'client_pipe_open', 'tls_handshake_first_write', 'rpc_put')) {
            Assert-True ($totals.ContainsKey($required)) 'sync job lacks a required measurement category'
        }
        Write-Host 'WINDOWS_SYNC_CUTOFF source=job scope=partial-observation wait-seconds=15'
    }
}

function Add-SyntheticZipEntry(
    [IO.Compression.ZipArchive]$Archive,
    [string]$Name,
    [byte[]]$Bytes
) {
    $stream = $null
    $primary = $null
    $cleanup = $null
    try {
        $entry = $Archive.CreateEntry($Name, [IO.Compression.CompressionLevel]::Optimal)
        $stream = $entry.Open()
        $stream.Write($Bytes, 0, $Bytes.Length)
    }
    catch { $primary = $_.Exception }
    finally {
        if ($null -ne $stream) {
            try { $stream.Dispose() }
            catch { $cleanup = $_.Exception }
        }
    }
    if ($null -ne $primary -and $null -ne $cleanup) {
        throw [AggregateException]::new('1PUX entry write and cleanup failed', @($primary, $cleanup))
    }
    if ($null -ne $primary) { throw $primary }
    if ($null -ne $cleanup) { throw $cleanup }
}

function New-SyntheticOnePux([string]$Path) {
    Assert-True (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) 'synthetic 1PUX path collided'
    $archive = $null
    $primary = $null
    $cleanup = $null
    try {
        $archive = [IO.Compression.ZipFile]::Open($Path, [IO.Compression.ZipArchiveMode]::Create)
        $utf8 = [Text.UTF8Encoding]::new($false)
        Add-SyntheticZipEntry $archive 'export.attributes' ($utf8.GetBytes('{"version":3,"description":"synthetic ticket27"}'))
        $data = '{"accounts":[{"attrs":{"uuid":"ticket27-account"},"vaults":[{"attrs":{"uuid":"ticket27-vault"},"items":[{"uuid":"ticket27-login","categoryUuid":"001","details":{"loginFields":[{"designation":"username","value":"synthetic-user"},{"designation":"password","value":"synthetic-ticket27-1pux"}]},"overview":{"title":"Keyboard 1PUX"}},{"uuid":"ticket27-file","categoryUuid":"004","details":{"documentAttributes":{"fileName":"ticket27-large.bin","documentId":"ticket27-document","decryptedSize":2097159}},"overview":{"title":"Keyboard 1PUX File"}}]}]}]}'
        Add-SyntheticZipEntry $archive 'export.data' ($utf8.GetBytes($data))
        $content = [byte[]]::new(2097159)
        [Random]::new(2527).NextBytes($content)
        Add-SyntheticZipEntry $archive 'files/ticket27-document___ignored.bin' $content
        [Array]::Clear($content, 0, $content.Length)
    }
    catch { $primary = $_.Exception }
    finally {
        if ($null -ne $archive) {
            try { $archive.Dispose() }
            catch { $cleanup = $_.Exception }
        }
    }
    if ($null -ne $primary -and $null -ne $cleanup) {
        throw [AggregateException]::new('1PUX creation and cleanup failed', @($primary, $cleanup))
    }
    if ($null -ne $primary) { throw $primary }
    if ($null -ne $cleanup) { throw $cleanup }
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
$aliasDir = Join-Path $root 'reparse-fixture'
$syncDir = Join-Path $root 'sync-fixture'
$aliasOwned = $false
$syncProcess = $null
$diagnosticDir = Join-Path $root 'service-diagnostics'
$diagnosticPath = Join-Path $diagnosticDir 'startup.phases'
$syncTimingPath = Join-Path $diagnosticDir 'sync.timings'
$measureSync = $ServiceDiagnostics -and $TuiConPtyRed
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
    Assert-True (-not ((Get-LocalGroupMember Administrators).Name -contains "$env:COMPUTERNAME\$humanName")) 'human must not be administrator'
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

    Invoke-Checked 'cargo' @('build', '-p', 'pm-custody', '-p', 'pm-cli', '--locked', '--offline')
    if ($OnePuxMemoryDiagnostics) {
        Invoke-Checked 'cargo' @('build', '-p', 'pm-custody', '--example', 'windows_onepux_memory_probe', '--locked', '--offline')
    }
    if ($TuiConPtyRed) {
        Invoke-Checked 'cargo' @('build', '-p', 'pm-native-channel', '--example', 'windows_tui_conpty_fixture', '--locked', '--offline')
        Invoke-Checked 'cargo' @('build', '-p', 'pm-custody', '--example', 'windows_human_tui_seed', '--locked', '--offline')
    }
    $custody = Join-Path $repo 'target\debug\pm-custody.exe'
    $cli = Join-Path $repo 'target\debug\pm.exe'
    Assert-True ((Get-Item $custody).VersionInfo.FileName.EndsWith('.exe')) 'native PE custody binary missing'
    Assert-True ((Get-Item $cli).VersionInfo.FileName.EndsWith('.exe')) 'native PE CLI binary missing'
    Assert-NativeStaticMsvcBinary $dumpbin $custody 'pm-custody.exe'
    Assert-NativeStaticMsvcBinary $dumpbin $cli 'pm.exe'

    # The native process-transfer regression resolves the real virtual service
    # SID and verifies its short-lived process DACL lease. Provision the
    # collision-checked owned SCM record only after inspecting both product
    # binaries; its inert command is replaced before the service is started.
    # Omit password=: SCM maps absence to the required NULL lpPassword for a
    # virtual account rather than to an empty password.
    Invoke-Checked 'sc.exe' @('create', $serviceName, 'type=', 'own', 'start=', 'demand', 'obj=', "NT SERVICE\$serviceName", 'binPath=', 'cmd /c exit 0')
    $serviceOwned = $true
    Invoke-Checked 'sc.exe' @('sidtype', $serviceName, 'unrestricted')
    $serviceSid = Get-Sid "NT SERVICE\$serviceName"
    Invoke-Checked 'cargo' @('test', '-p', 'pm-native-channel', '--all-targets', '--locked', '--offline')
    Invoke-Checked 'cargo' @('test', '-p', 'pm-sync', '--lib', '--locked', '--offline')
    $tuiFixture = $null
    $tuiCustody = $null
    $tuiSeed = $null
    $identityFixture = $null
    if ($TuiConPtyRed) {
        $builtFixture = Join-Path $repo 'target\debug\examples\windows_tui_conpty_fixture.exe'
        Assert-NativeStaticMsvcBinary $dumpbin $builtFixture 'windows_tui_conpty_fixture.exe'
        $builtSeed = Join-Path $repo 'target\debug\examples\windows_human_tui_seed.exe'
        Assert-NativeStaticMsvcBinary $dumpbin $builtSeed 'windows_human_tui_seed.exe'
        $tuiSeed = Join-Path $humanDir 'windows_human_tui_seed.exe'
        Copy-Item -LiteralPath $builtSeed -Destination $tuiSeed -ErrorAction Stop
        Add-OwnedPath $ownedPaths $tuiSeed
        $identityFixture = Join-Path $agentDir 'windows_human_tui_seed.exe'
        Copy-Item -LiteralPath $builtSeed -Destination $identityFixture -ErrorAction Stop
        Add-OwnedPath $ownedPaths $identityFixture
        $tuiFixture = Join-Path $humanDir 'windows_tui_conpty_fixture.exe'
        $tuiCustody = Join-Path $humanDir 'pm-custody.exe'
        Copy-Item -LiteralPath $builtFixture -Destination $tuiFixture -ErrorAction Stop
        Copy-Item -LiteralPath $custody -Destination $tuiCustody -ErrorAction Stop
        Add-OwnedPath $ownedPaths $tuiFixture
        Add-OwnedPath $ownedPaths $tuiCustody
    }

    $memoryProbe = $null
    $memorySource = $null
    if ($OnePuxMemoryDiagnostics) {
        $builtProbe = Join-Path $repo 'target\debug\examples\windows_onepux_memory_probe.exe'
        Assert-NativeStaticMsvcBinary $dumpbin $builtProbe 'windows_onepux_memory_probe.exe'
        $memoryProbe = Join-Path $humanDir 'windows_onepux_memory_probe.exe'
        $memorySource = Join-Path $humanDir 'memory.1pux'
        Copy-Item -LiteralPath $builtProbe -Destination $memoryProbe -ErrorAction Stop
        Add-OwnedPath $ownedPaths $memoryProbe
        Add-OwnedPath $ownedPaths $memorySource
        New-SyntheticOnePux $memorySource
    }

    $agentSid = Get-Sid "$env:COMPUTERNAME\$agentName"
    $humanSid = Get-Sid "$env:COMPUTERNAME\$humanName"
    if ($ServiceDiagnostics) {
        Add-OwnedPath $ownedPaths $diagnosticPath
        [IO.File]::WriteAllText($diagnosticPath, [string]::Empty)
        if ($measureSync) {
            Add-OwnedPath $ownedPaths $syncTimingPath
            [IO.File]::WriteAllText($syncTimingPath, [string]::Empty)
        }
        if ($OnePuxMemoryDiagnostics) {
            $quotaDeniedDiagnosticPath = Join-Path $diagnosticDir 'quota-denied.txt'
            Add-OwnedPath $ownedPaths $quotaDeniedDiagnosticPath
            [IO.File]::WriteAllText($quotaDeniedDiagnosticPath, [string]::Empty)
        }
        Set-ExactTreeAcl $diagnosticDir @('SYSTEM', $installerName, "NT SERVICE\$serviceName")
        Assert-ExactNodeAcl $diagnosticDir @('SYSTEM', $installerName, "NT SERVICE\$serviceName")
        Assert-ExactNodeAcl $diagnosticPath @('SYSTEM', $installerName, "NT SERVICE\$serviceName")
        if ($measureSync) { Assert-ExactNodeAcl $syncTimingPath @('SYSTEM', $installerName, "NT SERVICE\$serviceName") }
    }

    $serverPrivate = Join-Path $serviceDir 'server.key'
    $serverPublic = Join-Path $serviceDir 'server.rpk'
    $agentPrivate = Join-Path $agentDir 'agent.key'
    $agentPublic = Join-Path $agentDir 'agent.rpk'
    $humanPrivate = Join-Path $humanDir 'human.key'
    $humanPublic = Join-Path $humanDir 'human.rpk'
    $impostorPrivate = Join-Path $humanDir 'impostor.key'
    $impostorPublic = Join-Path $humanDir 'impostor.rpk'
    Add-OwnedPath $ownedPaths $impostorPrivate
    Add-OwnedPath $ownedPaths $impostorPublic
    foreach ($path in @($serverPrivate, $serverPublic, $agentPrivate, $agentPublic, $humanPrivate, $humanPublic)) {
        Add-OwnedPath $ownedPaths $path
    }
    Invoke-Checked $custody @('keygen', '--private', $serverPrivate, '--public', $serverPublic)
    Invoke-Checked $custody @('keygen', '--private', $agentPrivate, '--public', $agentPublic)
    Invoke-Checked $custody @('keygen', '--private', $humanPrivate, '--public', $humanPublic)
    Invoke-Checked $custody @('keygen', '--private', $impostorPrivate, '--public', $impostorPublic)
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
    $ownerAudit = Join-Path $serviceDir 'device-owner.audit-custody'
    $remoteAudit = Join-Path $serviceDir 'device-remote.audit-custody'
    Add-OwnedPath $ownedPaths $ownerAudit
    Add-OwnedPath $ownedPaths $remoteAudit
    Add-OwnedPath $ownedPaths $vault
    Add-OwnedPath $ownedPaths $auditPath
    $master = 'synthetic ticket 27 master only'
    $tuiCsv = Join-Path $humanDir 'keyboard.csv'
    $tuiOnePux = Join-Path $humanDir 'keyboard.1pux'
    $tuiBackup = Join-Path $humanDir 'keyboard.pmb1'
    $tuiPlaintext = Join-Path $humanDir 'keyboard.jsonl'
    $localBackup = Join-Path $humanDir 'local-operations.pmb1'
    $localPlaintext = Join-Path $humanDir 'local-operations.jsonl'
    Add-OwnedPath $ownedPaths $tuiCsv
    Add-OwnedPath $ownedPaths $tuiOnePux
    foreach ($negative in @('file-empty', 'directory-handle', 'file-multilink')) {
        Add-OwnedPath $ownedPaths ([IO.Path]::ChangeExtension($tuiOnePux, "wire-$negative"))
    }
    Add-OwnedPath $ownedPaths $tuiBackup
    Add-OwnedPath $ownedPaths $tuiPlaintext
    Add-OwnedPath $ownedPaths $localBackup
    Add-OwnedPath $ownedPaths $localPlaintext
    [IO.File]::WriteAllText(
        $tuiCsv,
        "name,url,username,password,note$([Environment]::NewLine)Keyboard Windows,https://keyboard-windows.invalid,synthetic-user,synthetic-ticket27-import,synthetic-note$([Environment]::NewLine)",
        [Text.UTF8Encoding]::new($false)
    )
    New-SyntheticOnePux $tuiOnePux
    $installerSeed = Join-Path $repo 'target\debug\examples\windows_human_tui_seed.exe'
    $aliasPath = Join-Path $aliasDir 'installer-alias.1pux'
    $deviceConfig = Join-Path $humanDir 'device-config.txt'
    $pairing = Join-Path $humanDir 'device-pairing.cbor'
    $syncBinary = Join-Path $serviceDir 'pm-sync.exe'
    $syncServerKey = Join-Path $syncDir 'server.key'
    $syncServerPublic = Join-Path $serviceDir 'sync-server.rpk'
    $syncClientKey = Join-Path $serviceDir 'sync-client.key'
    $syncClientPublic = Join-Path $syncDir 'client.rpk'
    $syncDb = Join-Path $syncDir 'opaque.sqlite3'
    $syncOut = Join-Path $harnessDir 'sync.out'
    $syncErr = Join-Path $harnessDir 'sync.err'
    $syncPipe = '\\.\pipe\pm-sync-' + [Guid]::NewGuid().ToString('N')
    Assert-True ($syncPipe -cmatch '^\\\\\.\\pipe\\pm-sync-[a-f0-9]{32}$') 'sync endpoint violates the ordinary named-pipe contract'
    $remoteDevice = '28282828282828282828282828282828'
    foreach ($path in @($aliasDir, $aliasPath, $syncDir, $deviceConfig, $pairing, $syncBinary, $syncServerKey, $syncServerPublic, $syncClientKey, $syncClientPublic, $syncDb, "${syncDb}-wal", "${syncDb}-shm", $syncOut, $syncErr, "${vault}.sync-status", "${vault}.sync-job", "${vault}.sync-stage")) { Add-OwnedPath $ownedPaths $path }
    if ($TuiConPtyRed) {
        New-Item -ItemType Directory -Path $aliasDir, $syncDir | Out-Null
        Set-ExactTreeAcl $aliasDir @('SYSTEM', $installerName, "$env:COMPUTERNAME\$humanName")
        Set-ExactTreeAcl $syncDir @('SYSTEM', $installerName)
        $builtSync = Join-Path $repo 'target\debug\pm-sync.exe'
        Invoke-Checked $installerSeed @('--sync-keygen', $syncServerKey, $syncServerPublic)
        Invoke-Checked $installerSeed @('--sync-keygen', $syncClientKey, $syncClientPublic)
        $pin = ([IO.File]::ReadAllBytes($syncServerPublic) | ForEach-Object { $_.ToString('x2') }) -join ''
        Assert-True ($pin.Length -eq 88) 'sync RPK is not exactly 44 bytes'
        [IO.File]::WriteAllLines($deviceConfig, @($pin, $pairing, $syncBinary, $syncPipe, $syncClientKey, $syncServerPublic, $remoteDevice), [Text.UTF8Encoding]::new($false))
    }
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
    $previousMasterInput = Join-Path $harnessDir 'previous-master.in'
    $humanOut = Join-Path $harnessDir 'human.out'; $humanErr = Join-Path $harnessDir 'human.err'
    $tuiOut = Join-Path $harnessDir 'tui.out'; $tuiErr = Join-Path $harnessDir 'tui.err'
    $badOut = Join-Path $harnessDir 'bad.out'; $badErr = Join-Path $harnessDir 'bad.err'
    foreach ($path in @($emptyInput, $agentOut, $agentErr, $humanInput, $previousMasterInput, $humanOut, $humanErr, $tuiOut, $tuiErr, $badOut, $badErr)) {
        Add-OwnedPath $ownedPaths $path
    }
    [IO.File]::WriteAllBytes($emptyInput, [byte[]]@())
    [IO.File]::WriteAllText($humanInput, $master + [Environment]::NewLine)
    [IO.File]::WriteAllBytes($previousMasterInput, [byte[]]@())
    $currentMaster = $master
    $tuiCaseFailures = [Collections.Generic.List[string]]::new()
    foreach ($path in @($agentOut, $agentErr, $humanOut, $humanErr, $tuiOut, $tuiErr, $badOut, $badErr)) {
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
    if ($OnePuxMemoryDiagnostics) {
        $deniedBinPath = $binPath.Replace($diagnosticPath, $quotaDeniedDiagnosticPath)
        Invoke-Checked 'sc.exe' @('config', $serviceName, 'binPath=', $deniedBinPath)
        $quotaNegativeFailure = $null
        try {
            & (Join-Path $repo 'scripts\test-windows-memory-quota-denial.ps1') -ServiceName $serviceName -DiagnosticPath $quotaDeniedDiagnosticPath
        }
        catch { $quotaNegativeFailure = $_ }
        try {
            # ChangeServiceConfig2 treats the original NULL privilege list as
            # "unchanged", so remove the temporary negative record. Re-create
            # the normal owned record with its original unset privileges.
            $quotaRecord = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop
            Assert-True ($null -ne $quotaRecord) 'quota fixture record disappeared'
            if ([string]$quotaRecord.State -eq 'Running') {
                $quotaPid = Get-StoppableServicePid $serviceName
                Stop-OwnedService $serviceName $quotaPid
            }
            $quotaRecord = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop
            Assert-True ($null -ne $quotaRecord -and [string]$quotaRecord.State -eq 'Stopped') 'quota fixture did not stop before removal'
            Invoke-Checked 'sc.exe' @('delete', $serviceName)
            Assert-True ($null -eq (Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop)) 'quota fixture SCM record survived deletion'
            $serviceOwned = $false
            Invoke-Checked 'sc.exe' @('create', $serviceName, 'type=', 'own', 'start=', 'demand', 'obj=', "NT SERVICE\$serviceName", 'binPath=', $binPath)
            $serviceOwned = $true
            Invoke-Checked 'sc.exe' @('sidtype', $serviceName, 'unrestricted')
            Assert-True ((Get-Sid "NT SERVICE\$serviceName") -eq $serviceSid) 'normal service SID changed after quota fixture'
            [W5QuotaDeniedService]::Run($serviceName, $false)
            Write-Host 'PASS windows-quota-fixture-restored privileges=original-exact sid=same command=normal'
        }
        catch {
            if ($null -ne $quotaNegativeFailure) {
                throw [AggregateException]::new('Quota negative and fixture restoration failed', @($quotaNegativeFailure.Exception, $_.Exception))
            }
            throw
        }
        if ($null -ne $quotaNegativeFailure) { throw $quotaNegativeFailure }
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

    # STOP is exercised before first human unlock so the independent empty-vault
    # audit failure cannot explain its result. No process termination substitutes
    # for the SCM transition.
    $preUnlockPid = Get-StoppableServicePid $serviceName
    Stop-OwnedService $serviceName $preUnlockPid
    $postStopPid = Start-OwnedServiceWithNewPid $serviceName $preUnlockPid
    $p = Start-AsUser $agentCredential $custody @('probe', '--profile', $agentProfile, '--private', $agentPrivate, '--vault-id', $vaultId) $emptyInput $agentOut $agentErr
    Assert-True ($p.ExitCode -eq 0) 'agent RPK channel failed after SCM restart'
    $p = Start-AsUser $humanCredential $custody @('probe', '--profile', $humanProfile, '--private', $humanPrivate, '--vault-id', $vaultId) $emptyInput $humanOut $humanErr
    Assert-True ($p.ExitCode -eq 0) 'human RPK channel failed after SCM restart'

    if ($OnePuxMemoryDiagnostics) {
        Write-ServiceDumpPolicyObservation
        $p = Start-AsUser $humanCredential $memoryProbe @($humanProfile, $humanPrivate, $vaultId, $memorySource) $humanInput $humanOut $humanErr
        Write-Host (Get-Content $humanErr -Raw)
        Write-Host (Get-Content $humanOut -Raw)
        Write-ServiceSubphaseDiagnostics $diagnosticPath
        $previewExit = $p.ExitCode
        # Independent native budget evidence, even when the seed8 preview is RED.
        & cargo test -p pm-crypto --lib windows_memory::tests:: --locked --offline -- --nocapture --test-threads=1
        $quotaExit = $LASTEXITCODE
        & cargo test -p pm-crypto --test windows_memory_budget --locked --offline -- --nocapture --test-threads=1
        $budgetExit = $LASTEXITCODE
        Assert-True ($previewExit -eq 0) 'focused seed8 1PUX preview failed'
        Assert-True ((Get-Content $humanOut -Raw).Trim() -eq 'PASS w5-onepux-memory seed8=exact preview=2 prepared=validated lease=restored commit=not-sent') 'focused preview did not prove exact result'
        Assert-True ($budgetExit -eq 0) 'native aggregate protected-memory budget failed'
        Assert-True ($quotaExit -eq 0) 'native working-set quota denial failed'
    }
    if ($TuiConPtyRed) {
        $p = Start-AsUser $agentCredential $identityFixture @('--peer-negative', $vaultId) $emptyInput $badOut $badErr
        Assert-True ($p.ExitCode -eq 0) ('native agent-to-human peer negative failed: ' + (Get-Content $badErr -Raw))
        Assert-True ((Get-Content $badOut -Raw).Trim() -eq 'PASS windows-peer-negative agent-human-pipe=access-denied installed-connect=rejected') 'agent-to-human peer did not prove native access denial'
        Write-Host (Get-Content $badOut -Raw)
        $pidStationSddl = "D:P(A;;GA;;;SY)(A;;GA;;;$humanSid)"
        $pidService = Get-StoppableServicePid $serviceName
        $p = Start-AsUser $humanCredential $tuiSeed @('--pid-negative', '27bb27bb27bb27bb27bb27bb27bb27bb', $pidStationSddl, [string]$pidService) $emptyInput $humanOut $humanErr
        Write-Host (Get-Content $humanErr -Raw)
        if ($p.ExitCode -eq 0 -and (Get-Content $humanOut -Raw).Trim() -eq 'PASS windows-pid-negative native-server=impostor installed-connect=rejected client-observed=1 endpoint-absent=1') {
            Write-Host (Get-Content $humanOut -Raw)
        }
        else {
            $tuiCaseFailures.Add('peer-pid')
            Write-Host 'NATIVE_PID case=impostor result=fail'
        }
        $rpkStart = if ($ServiceDiagnostics) { @(Get-Content -LiteralPath $diagnosticPath -ErrorAction Stop).Count } else { 0 }
        $p = Start-AsUser $humanCredential $tuiSeed @('--rpk-negative', $humanProfile, $impostorPrivate, $vaultId) $emptyInput $humanOut $humanErr
        Write-Host (Get-Content $humanErr -Raw)
        if ($p.ExitCode -eq 0 -and (Get-Content $humanOut -Raw).Trim() -eq 'PASS windows-rpk-negative same-sid=accepted wrong-rpk=unknown-ca app-request=0 close=checked') {
            if ($ServiceDiagnostics) {
                $rpkPhases = @(Get-Content -LiteralPath $diagnosticPath -ErrorAction Stop | Select-Object -Skip $rpkStart)
                Assert-True ($rpkPhases.Count -eq 1 -and $rpkPhases[0] -eq 'phase=human-accepted') 'wrong RPK reached application authorization'
            }
            Write-Host (Get-Content $humanOut -Raw)
        } else { $tuiCaseFailures.Add('peer-rpk'); Write-Host 'NATIVE_RPK result=fail' }
        $p = Start-AsUser $humanCredential $tuiSeed @($humanProfile, $humanPrivate, $vaultId) $humanInput $humanOut $humanErr
        Assert-True ($p.ExitCode -eq 0) ('ordinary human type seeding failed: ' + (Get-Content $humanErr -Raw))
        Assert-True ((Get-Content $humanOut -Raw).Trim() -eq 'PASS windows-tui-seed types=7 ordinary-human-wire=1 readback=exact') 'seven-type readback was not exact'
        Write-Host (Get-Content $humanOut -Raw)
        # Invalid source frames are independent of restore and key rotations.
        # Preserve every failure, then continue the other native cases once.
        foreach ($negative in @('null', 'invalid-handle', 'thread-pseudohandle', 'malformed-token', 'file-empty', 'directory-handle', 'file-multilink')) {
            $diagnosticStart = if ($ServiceDiagnostics) { @(Get-Content -LiteralPath $diagnosticPath -ErrorAction Stop).Count } else { 0 }
            $negativeArgs = @($humanProfile, $humanPrivate, $vaultId, '--transfer-negative', $negative)
            if ($negative -in @('file-empty', 'directory-handle', 'file-multilink')) {
                $negativeArgs += $tuiOnePux
            }
            $p = Start-AsUser $humanCredential $tuiSeed $negativeArgs $humanInput $humanOut $humanErr
            Write-Host (Get-Content $humanErr -Raw)
            Write-ServiceSubphaseDiagnostics $diagnosticPath
            try {
                Assert-True ($p.ExitCode -eq 0) ('ordinary human transfer negative failed: ' + $negative + '; ' + (Get-Content $humanErr -Raw))
                Assert-True ((Get-Content $humanOut -Raw).Trim() -eq "PASS windows-transfer-negative case=$negative ack31=accepted peer-eof=1 dacl-before-during-after=exact") 'negative transfer did not prove exact DACL and peer closure'
                Write-Host (Get-Content $humanOut -Raw)
                if ($negative -in @('file-empty', 'directory-handle', 'file-multilink')) {
                    $sourceWitness = @(Get-Content $humanErr -ErrorAction Stop)
                    Assert-True (@($sourceWitness | Where-Object { $_ -eq "NATIVE_SOURCE case=$negative witness=exact handle=open" }).Count -eq 1) 'negative source lacks exact native handle witness'
                    Assert-True (@($sourceWitness | Where-Object { $_ -eq "NATIVE_SOURCE case=$negative handle-closed=true source-cleaned=true" }).Count -eq 1) 'negative source lacks checked close and cleanup'
                }
                if ($ServiceDiagnostics) {
                    $newPhases = @(Get-Content -LiteralPath $diagnosticPath -ErrorAction Stop | Select-Object -Skip $diagnosticStart)
                    Assert-True (@($newPhases | Where-Object { $_ -eq 'phase=transfer-ack31' }).Count -eq 1) 'negative transfer lacks one native ack31'
                    Assert-True ($newPhases -notcontains 'phase=transfer-duplicated') 'negative source was duplicated successfully'
                    Assert-True (@($newPhases | Where-Object { $_ -like 'phase=onepux-*' }).Count -eq 0) 'negative source reached the 1PUX parser'
                    if ($negative -eq 'malformed-token') {
                        Assert-True ($newPhases -notcontains 'phase=transfer-token') 'malformed frame was accepted as a token'
                    }
                    else {
                        Assert-True (@($newPhases | Where-Object { $_ -eq 'phase=transfer-token' }).Count -eq 1) 'negative transfer lacks one decoded token'
                        Assert-True (@($newPhases | Where-Object { $_ -eq 'phase=transfer-duplicate-failed' }).Count -eq 1) 'negative token lacks a native duplication rejection'
                    }
                }
                Write-Host "WIRE_CASE case=$negative result=pass"
            }
            catch {
                $tuiCaseFailures.Add("wire-$negative")
                Write-Host "WIRE_CASE case=$negative result=fail"
            }
        }
        $stationSddl = "D:P(A;;GA;;;SY)(A;;GA;;;$humanSid)"
        $consoleDiagnostic = Join-Path $humanDir 'console-diagnostic.txt'
        Add-OwnedPath $ownedPaths $consoleDiagnostic
        $encodingDiagnostic = Join-Path $humanDir 'encoding-exit.txt'
        Add-OwnedPath $ownedPaths $encodingDiagnostic
        Add-OwnedPath $ownedPaths (Join-Path $humanDir 'resize-diagnostic.txt')
        if ($ServiceDiagnostics) {
            $p = Start-AsUser $humanCredential $tuiFixture @($stationSddl, $tuiCustody, '--encoding-exit', $tuiCsv, $tuiOnePux, $tuiBackup, $tuiPlaintext, '--', 'tui', '--profile', $humanProfile, '--private', $humanPrivate, '--vault-id', $vaultId, '--idle-seconds', '300', '--reveal-seconds', '1', '--copy-seconds', '1') $humanInput $tuiOut $tuiErr
            Write-Host (Get-Content $tuiErr -Raw)
            Assert-True ($p.ExitCode -eq 0) ('TUI encoding natural-exit scenario failed: ' + (Get-Content $tuiErr -Raw))
            Assert-TuiFixtureOutput $tuiOut 'encoding-exit'
        }
        Invoke-Checked $installerSeed @('--installer-alias', $aliasPath, $tuiOnePux)
        $aliasOwned = $true
        $p = Start-AsUser $humanCredential $tuiFixture @($stationSddl, $tuiCustody, '--sources', $tuiCsv, $tuiOnePux, $aliasPath, $tuiPlaintext, '--', 'tui', '--profile', $humanProfile, '--private', $humanPrivate, '--vault-id', $vaultId, '--idle-seconds', '300', '--reveal-seconds', '1', '--copy-seconds', '1') $humanInput $tuiOut $tuiErr
        Write-Host (Get-Content $tuiErr -Raw)
        if ($p.ExitCode -eq 0) { Assert-TuiFixtureOutput $tuiOut 'sources'; Write-Host 'TUI_CASE case=sources result=pass' }
        else { $tuiCaseFailures.Add('sources'); Write-Host 'TUI_CASE case=sources result=fail' }
        Invoke-Checked $installerSeed @('--remove-alias', $aliasPath, $tuiOnePux)
        $aliasOwned = $false
        $matrixMode = if ($ServiceDiagnostics) { '--matrix-probe' } else { '--matrix' }
        # Each case starts a separate ordinary TUI/ConPTY session. Failure is
        # retained in the aggregate while independent cases remain observable;
        # no case retries an operation or substitutes for the integral matrix.
        $cases = @(
            @{ Name = 'resize'; Mode = '--resize'; Backup = $tuiBackup; Plaintext = $tuiPlaintext; RotatedMaster = $null },
            @{ Name = 'clipboard'; Mode = '--clipboard'; Backup = $tuiBackup; Plaintext = $tuiPlaintext; RotatedMaster = $null },
            @{ Name = 'access'; Mode = '--access'; Backup = $tuiBackup; Plaintext = $tuiPlaintext; RotatedMaster = $null },
            @{ Name = 'rotations'; Mode = '--rotations'; Backup = $localBackup; Plaintext = $localPlaintext; RotatedMaster = 'synthetic-ticket27-independent-rotated-master' },
            @{ Name = 'matrix'; Mode = $matrixMode; Backup = $tuiBackup; Plaintext = $tuiPlaintext; RotatedMaster = 'synthetic-ticket27-rotated-master' },
            @{ Name = 'local-operations'; Mode = '--local-operations'; Backup = $localBackup; Plaintext = $localPlaintext; RotatedMaster = 'synthetic-ticket27-local-rotated-master' }
        )
        foreach ($case in $cases) {
            if ($case.Name -eq 'matrix') {
                $p = Start-AsUser $humanCredential $tuiFixture @($stationSddl, $tuiCustody, $matrixMode, $tuiCsv, $tuiOnePux, $tuiBackup, $tuiPlaintext, '--', 'tui', '--profile', $humanProfile, '--private', $humanPrivate, '--vault-id', $vaultId, '--idle-seconds', '300', '--reveal-seconds', '1', '--copy-seconds', '1') $humanInput $tuiOut $tuiErr
            }
            else {
            $p = Start-AsUser $humanCredential $tuiFixture @($stationSddl, $tuiCustody, $case.Mode, $tuiCsv, $tuiOnePux, $case.Backup, $case.Plaintext, '--', 'tui', '--profile', $humanProfile, '--private', $humanPrivate, '--vault-id', $vaultId, '--idle-seconds', '300', '--reveal-seconds', '1', '--copy-seconds', '1') $humanInput $tuiOut $tuiErr
            }
            $caseLog = Get-Content $tuiErr -Raw
            Write-Host $caseLog
            Write-ServiceSubphaseDiagnostics $diagnosticPath
            if ($p.ExitCode -eq 0) {
                Assert-TuiFixtureOutput $tuiOut $case.Name
                Write-Host "TUI_CASE case=$($case.Name) result=pass"
            }
            else {
                $tuiCaseFailures.Add($case.Name)
                Write-Host "TUI_CASE case=$($case.Name) result=fail"
            }
            # A rotation can commit before a later fixture assertion fails.
            # Track only the explicit native observation of that commit.
            if ($caseLog -match '(?m)^TUI_STAGE stage=master-rotation result=pass\r?$') {
                Assert-True ($null -ne $case.RotatedMaster) 'unexpected rotation in an independent case'
                [IO.File]::WriteAllText($previousMasterInput, $currentMaster + [Environment]::NewLine)
                $currentMaster = $case.RotatedMaster
                [IO.File]::WriteAllText($humanInput, $currentMaster + [Environment]::NewLine)
                $rotationLockArguments = @('human-lock') + @('--profile', $humanProfile, '--private', $humanPrivate, '--vault-id', $vaultId)
                $old = Start-AsUser $humanCredential $custody $rotationLockArguments $previousMasterInput $humanOut $humanErr
                Assert-True ($old.ExitCode -ne 0) 'previous master unexpectedly unlocked after native rotation'
                $new = Start-AsUser $humanCredential $custody $rotationLockArguments $humanInput $humanOut $humanErr
                Assert-True ($new.ExitCode -eq 0) 'exact new master failed ordinary human unlock after rotation'
                Write-Host "TUI_CASE case=$($case.Name) previous-master=denied new-master=accepted"
            }
            if ($p.ExitCode -eq 0 -and $case.Name -in @('matrix', 'local-operations')) {
                Assert-True ($caseLog -match '(?m)^TUI_STAGE stage=published-files-regular-nonempty result=pass\r?$') 'human publication did not prove regular, nonempty backup and export files'
            }
        }
    }

    if ($TuiConPtyRed) {
        $devicePid = Get-StoppableServicePid $serviceName
        Stop-OwnedService $serviceName $devicePid
        Open-StoppedInstallerNode $serviceDir
        Open-StoppedInstallerNode $auditPath
        Assert-True (-not (Test-Path -LiteralPath $ownerAudit)) 'owner audit collision'
        Assert-True (-not (Test-Path -LiteralPath $remoteAudit)) 'remote audit collision'
        $ownerAuditHash = (Get-FileHash -LiteralPath $auditPath -Algorithm SHA256 -ErrorAction Stop).Hash
        Move-Item -LiteralPath $auditPath -Destination $ownerAudit -ErrorAction Stop
        Set-ExactTreeAcl $ownerAudit @('SYSTEM', "NT SERVICE\$serviceName")
        Close-StoppedInstallerDirectory $serviceDir
        $remoteBinPath = $binPath.Replace("--device $device", "--device $remoteDevice")
        Assert-True ($remoteBinPath -cne $binPath) 'second device did not change service ID'
        Invoke-Checked 'sc.exe' @('config', $serviceName, 'binPath=', $remoteBinPath)
        $remotePid = Start-OwnedServiceWithNewPid $serviceName $devicePid
        $remotePrimary = $null
        try {
            $p = Start-AsUser $humanCredential $tuiSeed @($humanProfile, $humanPrivate, $vaultId, '--remote-seed') $humanInput $humanOut $humanErr
            Assert-True ($p.ExitCode -eq 0) 'second-device wire seed failed'
            Assert-True ((Get-Content $humanOut -Raw).Trim() -eq 'PASS windows-device-seed records=1 ordinary-human-wire=1 readback=exact') 'second-device readback missing'
            Write-Host (Get-Content $humanOut -Raw)
        } catch { $remotePrimary = $_ }
        finally {
            Stop-OwnedService $serviceName $remotePid
            Open-StoppedInstallerNode $serviceDir
            Open-StoppedInstallerNode $auditPath
            $remoteAuditHash = (Get-FileHash -LiteralPath $auditPath -Algorithm SHA256 -ErrorAction Stop).Hash
            Move-Item -LiteralPath $auditPath -Destination $remoteAudit -ErrorAction Stop
            Assert-True ((Get-FileHash -LiteralPath $remoteAudit -Algorithm SHA256 -ErrorAction Stop).Hash -ceq $remoteAuditHash) 'remote audit bytes changed during preservation'
            Set-ExactTreeAcl $remoteAudit @('SYSTEM', "NT SERVICE\$serviceName")
            Open-StoppedInstallerNode $ownerAudit
            Move-Item -LiteralPath $ownerAudit -Destination $auditPath -ErrorAction Stop
            Assert-True ((Get-FileHash -LiteralPath $auditPath -Algorithm SHA256 -ErrorAction Stop).Hash -ceq $ownerAuditHash) 'owner audit bytes changed during restoration'
            Set-ExactTreeAcl $auditPath @('SYSTEM', "NT SERVICE\$serviceName")
            Close-StoppedInstallerDirectory $serviceDir
            Invoke-Checked 'sc.exe' @('config', $serviceName, 'binPath=', $binPath)
            $postStopPid = Start-OwnedServiceWithNewPid $serviceName $remotePid
        }
        if ($null -ne $remotePrimary) { throw $remotePrimary }
        Write-Host 'SECOND_DEVICE method=scm-alternated audit-owner=restored audit-remote=preserved bytes=exact second-agent=not-tested'
        foreach ($deviceMode in @('pair', 'sync', 'retire')) {
            if ($deviceMode -eq 'sync') {
                # Pairing does not require a running sync endpoint. Build the
                # ordinary binary here as a mandatory gate, after observing the
                # independent SCM/audit/pairing contract.
                Invoke-Checked 'cargo' @('build', '-p', 'pm-sync', '--locked', '--offline')
                Assert-NativeStaticMsvcBinary $dumpbin $builtSync 'pm-sync.exe'
                $installPid = Get-StoppableServicePid $serviceName
                Stop-OwnedService $serviceName $installPid
                Open-StoppedInstallerNode $serviceDir
                Copy-Item -LiteralPath $builtSync -Destination $syncBinary -ErrorAction Stop
                Set-ExactTreeAcl $syncBinary @('SYSTEM', "NT SERVICE\$serviceName")
                Close-StoppedInstallerDirectory $serviceDir
                if ($measureSync) {
                    # Only the owned SCM service and its clients receive timing.
                    $serviceRegistry = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
                    Assert-True (-not (Get-Item -LiteralPath $serviceRegistry).GetValueNames().Contains('Environment')) 'owned service already has a private environment'
                    New-ItemProperty -LiteralPath $serviceRegistry -Name Environment -PropertyType MultiString -Value @('PMW1_TIMING=1', "PMW1_TIMING_FILE=$syncTimingPath") | Out-Null
                }
                $postStopPid = Start-OwnedServiceWithNewPid $serviceName $installPid
                $syncArguments = @('serve', '--db', $syncDb, '--socket', $syncPipe, '--server-key', $syncServerKey, '--namespace', $namespace, '--server-sid', (Get-Sid $installerName), '--client-pub', $syncClientPublic, '--client-sid', $serviceSid)
                $env:PMW2_TIMING = '1'
                try { $syncProcess = Start-Process -FilePath $builtSync -ArgumentList $syncArguments -RedirectStandardOutput $syncOut -RedirectStandardError $syncErr -PassThru }
                finally { Remove-Item Env:PMW2_TIMING -ErrorAction Stop }
                # Ordinary endpoint readiness is proved by the TUI result; this
                # pause precedes submit and never replaces a screen assertion.
                Start-Sleep -Seconds 1
                Assert-True (-not $syncProcess.HasExited) 'ordinary sync server exited before TUI submit'
            }
            $p = Start-AsUser $humanCredential $tuiFixture @($stationSddl, $tuiCustody, "--$deviceMode", $deviceConfig, $tuiOnePux, $tuiBackup, $tuiPlaintext, '--', 'tui', '--profile', $humanProfile, '--private', $humanPrivate, '--vault-id', $vaultId, '--idle-seconds', '300', '--reveal-seconds', '1', '--copy-seconds', '1') $humanInput $tuiOut $tuiErr
            Write-Host (Get-Content $tuiErr -Raw)
            if ($deviceMode -eq 'sync' -and $measureSync) { Write-SyncTimingSummary $syncTimingPath 'job' }
            if ($p.ExitCode -eq 0) { Assert-TuiFixtureOutput $tuiOut $deviceMode; Write-Host "TUI_CASE case=device-$deviceMode result=pass" }
            else { $tuiCaseFailures.Add("device-$deviceMode"); Write-Host "TUI_CASE case=device-$deviceMode result=fail" }
            if ($deviceMode -eq 'sync' -and $p.ExitCode -ne 0) {
                Write-Host 'TUI_CASE case=device-retire result=not-run reason=sync-failed'
                break
            }
            if ($deviceMode -eq 'pair') {
                if ($p.ExitCode -ne 0) { break }
                $p = Start-AsUser $humanCredential $tuiSeed @('--pair-namespace', $pairing) $emptyInput $humanOut $humanErr
                Assert-True ($p.ExitCode -eq 0) 'protected pairing namespace unavailable'
                $namespace = (Get-Content $humanOut -Raw).Trim()
                Assert-True ($namespace -cmatch '^[a-f0-9]{64}$') 'pairing namespace not exact'
                Write-Host 'PAIR_NAMESPACE format=exact protected-file=1 close=checked'
            }
        }
        if ($null -ne $syncProcess) {
            Write-SyncTimingSummary $syncErr
            & $installerSeed '--sync-observe' $syncDb
            if ($LASTEXITCODE -ne 0) { $tuiCaseFailures.Add('device-sync-durable') }
        }
        $devicePid = Get-StoppableServicePid $serviceName
        Stop-OwnedService $serviceName $devicePid
        Open-StoppedInstallerNode $serviceDir
        Open-StoppedInstallerNode $vault
        & $installerSeed '--retire-observe' $vault
        if ($LASTEXITCODE -ne 0) { $tuiCaseFailures.Add('device-retire-durable') }
        Set-ExactTreeAcl $vault @('SYSTEM', "NT SERVICE\$serviceName")
        Close-StoppedInstallerDirectory $serviceDir
        $postStopPid = Start-OwnedServiceWithNewPid $serviceName $devicePid
    }

    $p = Start-AsUser $humanCredential $custody @('human-lock', '--profile', $humanProfile, '--private', $humanPrivate, '--vault-id', $vaultId) $humanInput $humanOut $humanErr
    Write-ServiceSubphaseDiagnostics $diagnosticPath
    Assert-True ($p.ExitCode -eq 0) ('human native channel failed: ' + (Get-Content $humanErr -Raw))

    # Cross-role RPK/SID substitution must fail before vault operation.
    $p = Start-AsUser $agentCredential $custody @('probe', '--profile', $humanProfile, '--private', $agentPrivate, '--vault-id', $vaultId) $emptyInput $badOut $badErr
    Assert-True ($p.ExitCode -ne 0) 'cross-role identity substitution unexpectedly succeeded'

    $servicePid = Get-StoppableServicePid $serviceName
    Assert-True ($servicePid -eq $postStopPid) 'service PID changed without an SCM stop'
    Stop-OwnedService $serviceName $servicePid
    $null = Start-OwnedServiceWithNewPid $serviceName $servicePid
    $p = Start-AsUser $agentCredential $custody @('probe', '--profile', $agentProfile, '--private', $agentPrivate, '--vault-id', $vaultId) $emptyInput $agentOut $agentErr
    Assert-True ($p.ExitCode -eq 0) 'persistent vault failed after service restart'
    $p = Start-AsUser $humanCredential $custody @('probe', '--profile', $humanProfile, '--private', $humanPrivate, '--vault-id', $vaultId) $emptyInput $humanOut $humanErr
    Assert-True ($p.ExitCode -eq 0) 'human channel failed after post-operation restart'

    # Preserve the independent abrupt-crash/recovery scenario. This is not a
    # substitute path after STOP failure: both graceful STOP assertions above
    # must already have succeeded before this intentional process kill.
    $crashPid = Get-StoppableServicePid $serviceName
    Stop-Process -Id $crashPid -Force -ErrorAction Stop
    Start-Sleep -Seconds 1
    $crashed = @(Get-CimInstance Win32_Process -Filter "ProcessId=$crashPid" -ErrorAction Stop)
    Assert-True ($crashed.Count -eq 0) 'intentionally crashed service PID remains alive'
    Invoke-Checked 'sc.exe' @('start', $serviceName)
    Start-Sleep -Seconds 2
    $postCrashPid = Get-StoppableServicePid $serviceName
    Assert-True ($postCrashPid -ne $crashPid) 'crash recovery reused the terminated PID'
    $p = Start-AsUser $agentCredential $custody @('probe', '--profile', $agentProfile, '--private', $agentPrivate, '--vault-id', $vaultId) $emptyInput $agentOut $agentErr
    Assert-True ($p.ExitCode -eq 0) 'agent channel failed after intentional crash recovery'
    $p = Start-AsUser $humanCredential $custody @('probe', '--profile', $humanProfile, '--private', $humanPrivate, '--vault-id', $vaultId) $emptyInput $humanOut $humanErr
    Assert-True ($p.ExitCode -eq 0) 'human channel failed after intentional crash recovery'
    Write-ServiceSubphaseDiagnostics $diagnosticPath

    Assert-True ($tuiCaseFailures.Count -eq 0) ('native TUI cases failed: ' + ($tuiCaseFailures -join ','))
    $passMessage = "PASS ticket27 windows=$product cpu=$osArch service-virtual-account=1 dacl=protected dpapi=machine pipe=bilateral tls=1.3-rpk human=unlock-lock restart=scm-stop+crash agent-admin=0"
}
catch {
    $bodyError = $_
}
finally {
    if ($aliasOwned) {
        try { Invoke-Checked $installerSeed @('--remove-alias', $aliasPath, $tuiOnePux); $aliasOwned = $false }
        catch { $cleanupErrors.Add("alias cleanup failed: $($_.Exception.Message)") }
    }
    if ($null -ne $syncProcess) {
        try {
            Assert-True (-not $syncProcess.HasExited) 'owned sync server exited unexpectedly'
            Stop-Process -Id $syncProcess.Id -ErrorAction Stop
            $syncProcess.WaitForExit()
            Assert-True ($syncProcess.HasExited) 'owned sync server remains after stop'
        } catch { $cleanupErrors.Add("sync cleanup failed: $($_.Exception.Message)") }
    }
    if ($serviceOwned) {
        try {
            $installed = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
            if ($null -ne $installed -and $installed.State -ne 'Stopped') {
                Stop-Service -Name $serviceName -ErrorAction Stop
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
    try {
        Assert-OwnedResourcesAbsent $serviceOwned $serviceName $agentOwned $agentName $humanOwned $humanName $rootOwned $root
    }
    catch { $cleanupErrors.Add("cleanup absence verification failed: $($_.Exception.Message)") }
}

if ($cleanupErrors.Count -gt 0) {
    $prefix = if ($null -ne $bodyError) { "$($bodyError.Exception.Message); " } else { '' }
    throw ($prefix + ($cleanupErrors -join '; '))
}
if ($null -ne $bodyError) { throw $bodyError }
Write-Output $passMessage
