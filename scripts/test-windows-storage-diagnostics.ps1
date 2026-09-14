# SPDX-License-Identifier: AGPL-3.0-only
# Opt-in, destructive-only-to-ephemeral-fixtures Windows storage diagnostics.
[CmdletBinding()]
param(
    [switch]$EphemeralCI
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-NotReparse([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-True (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'storage diagnostics refuse reparse fixtures'
}

function Get-Sid([string]$Name) {
    return ([Security.Principal.NTAccount]$Name).Translate([Security.Principal.SecurityIdentifier]).Value
}

function Assert-ExactProbeFileAcl([string]$Path, [string]$Installer) {
    $security = Get-Acl -LiteralPath $Path -ErrorAction Stop
    Assert-True $security.AreAccessRulesProtected 'storage diagnostics probe ACL is inherited'
    $expectedSids = @(
        (Get-Sid $Installer)
        (Get-Sid 'SYSTEM')
    )
    $rules = @($security.Access)
    Assert-True ($rules.Count -eq $expectedSids.Count) 'storage diagnostics probe ACL entry count is unexpected'
    $actualSids = @()
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        $actualSids += $sid
        Assert-True ($expectedSids -contains $sid) 'storage diagnostics probe ACL trustee is unexpected'
        Assert-True ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) 'storage diagnostics probe ACL contains a deny'
        Assert-True (-not $rule.IsInherited) 'storage diagnostics probe ACL entry is inherited'
        Assert-True (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl) 'storage diagnostics probe ACL is not full control'
    }
    foreach ($sid in $expectedSids) {
        Assert-True (@($actualSids | Where-Object { $_ -eq $sid }).Count -eq 1) 'storage diagnostics probe ACL trustee is missing'
    }
}

function Invoke-SilentChecked([string]$File, [string[]]$Arguments, [string]$Failure) {
    & $File @Arguments *> $null
    if ($LASTEXITCODE -ne 0) { throw $Failure }
}

if (-not $EphemeralCI) {
    throw 'storage diagnostics require explicit EphemeralCI'
}
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:CI -ne 'true') {
    throw 'storage diagnostics require the authorized ephemeral CI environment'
}

$product = (Get-CimInstance Win32_OperatingSystem).Caption
Assert-True ($product -match 'Windows 11') 'storage diagnostics require Windows 11'
$osArch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
$processArch = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
Assert-True ($osArch -eq $processArch) 'storage diagnostics require a native process'
Assert-True ($osArch -in @('Arm64', 'X64')) 'storage diagnostics require a supported native CPU'

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace PasswordManager {
    public static class WindowsStorageDiagnosticsNative {
        public const UInt32 GenericRead = 0x80000000;
        public const UInt32 GenericWrite = 0x40000000;
        public const UInt32 ShareRead = 0x00000001;
        public const UInt32 ShareWrite = 0x00000002;
        public const UInt32 ShareDelete = 0x00000004;
        public const UInt32 OpenExisting = 3;
        public const UInt32 FileAttributeNormal = 0x00000080;
        public const UInt32 FileFlagBackupSemantics = 0x02000000;
        public const Int32 ErrorInvalidFunction = 1;
        public const Int32 ErrorAccessDenied = 5;
        public const Int32 ErrorInvalidHandle = 6;
        public const Int32 ErrorNotSupported = 50;
        public const Int32 ErrorInvalidParameter = 87;
        public static readonly IntPtr InvalidHandleValue = new IntPtr(-1);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
        public static extern IntPtr CreateFileW(
            string path,
            UInt32 desiredAccess,
            UInt32 shareMode,
            IntPtr securityAttributes,
            UInt32 creationDisposition,
            UInt32 flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FlushFileBuffers(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);
    }
}
'@

function Get-StorageCategory([int]$ErrorCode) {
    switch ($ErrorCode) {
        ([PasswordManager.WindowsStorageDiagnosticsNative]::ErrorInvalidFunction) { return 'invalid-function' }
        ([PasswordManager.WindowsStorageDiagnosticsNative]::ErrorAccessDenied) { return 'access-denied' }
        ([PasswordManager.WindowsStorageDiagnosticsNative]::ErrorInvalidHandle) { return 'invalid-handle' }
        ([PasswordManager.WindowsStorageDiagnosticsNative]::ErrorNotSupported) { return 'not-supported' }
        ([PasswordManager.WindowsStorageDiagnosticsNative]::ErrorInvalidParameter) { return 'invalid-parameter' }
        default { return 'other-error' }
    }
}

function Open-StorageProbeHandle([string]$Path, [uint32]$Access, [uint32]$Flags) {
    $share = [PasswordManager.WindowsStorageDiagnosticsNative]::ShareRead -bor
        [PasswordManager.WindowsStorageDiagnosticsNative]::ShareWrite -bor
        [PasswordManager.WindowsStorageDiagnosticsNative]::ShareDelete
    $handle = [PasswordManager.WindowsStorageDiagnosticsNative]::CreateFileW(
        $Path,
        $Access,
        $share,
        [IntPtr]::Zero,
        [PasswordManager.WindowsStorageDiagnosticsNative]::OpenExisting,
        $Flags,
        [IntPtr]::Zero)
    $errorCode = 0
    if ($handle -eq [PasswordManager.WindowsStorageDiagnosticsNative]::InvalidHandleValue) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    }
    return [pscustomobject]@{
        Handle = $handle
        ErrorCode = $errorCode
    }
}

function Close-StorageProbeHandle([IntPtr]$Handle) {
    if ($Handle -ne [PasswordManager.WindowsStorageDiagnosticsNative]::InvalidHandleValue -and
        -not [PasswordManager.WindowsStorageDiagnosticsNative]::CloseHandle($Handle)) {
        throw 'storage diagnostics could not close a native handle'
    }
}

function Flush-StorageProbeHandle([IntPtr]$Handle) {
    if ([PasswordManager.WindowsStorageDiagnosticsNative]::FlushFileBuffers($Handle)) {
        return 'success'
    }
    return Get-StorageCategory ([Runtime.InteropServices.Marshal]::GetLastWin32Error())
}

function Invoke-NativeStorageDiagnostics([string]$FilePath, [string]$DirectoryPath) {
    $results = [System.Collections.Generic.List[string]]::new()
    $readAccess = [PasswordManager.WindowsStorageDiagnosticsNative]::GenericRead
    $writeAccess = [PasswordManager.WindowsStorageDiagnosticsNative]::GenericRead -bor
        [PasswordManager.WindowsStorageDiagnosticsNative]::GenericWrite
    $backupFlag = [PasswordManager.WindowsStorageDiagnosticsNative]::FileFlagBackupSemantics
    $normalFlag = [PasswordManager.WindowsStorageDiagnosticsNative]::FileAttributeNormal

    $fileWritable = Open-StorageProbeHandle $FilePath $writeAccess $normalFlag
    if ($fileWritable.Handle -eq [PasswordManager.WindowsStorageDiagnosticsNative]::InvalidHandleValue) {
        throw 'storage diagnostics writable file open failed'
    }
    try {
        $writeFlush = Flush-StorageProbeHandle $fileWritable.Handle
        if ($writeFlush -ne 'success') {
            throw 'storage diagnostics writable file flush failed'
        }
    }
    finally {
        Close-StorageProbeHandle $fileWritable.Handle
    }
    $null = $results.Add('file-open-write=success')
    $null = $results.Add('file-flush-write=success')

    $fileProbe = Open-StorageProbeHandle $FilePath $readAccess $normalFlag
    if ($fileProbe.Handle -eq [PasswordManager.WindowsStorageDiagnosticsNative]::InvalidHandleValue) {
        $null = $results.Add(('file-open-readonly=' + (Get-StorageCategory $fileProbe.ErrorCode)))
        $null = $results.Add('file-flush-readonly=not-run')
    }
    else {
        $null = $results.Add('file-open-readonly=success')
        try {
            $null = $results.Add(('file-flush-readonly=' + (Flush-StorageProbeHandle $fileProbe.Handle)))
        }
        finally {
            Close-StorageProbeHandle $fileProbe.Handle
        }
    }

    $directoryNoBackup = Open-StorageProbeHandle $DirectoryPath $readAccess $normalFlag
    if ($directoryNoBackup.Handle -eq [PasswordManager.WindowsStorageDiagnosticsNative]::InvalidHandleValue) {
        $null = $results.Add(('directory-open-no-backup=' + (Get-StorageCategory $directoryNoBackup.ErrorCode)))
        $null = $results.Add('directory-flush-no-backup=not-run')
    }
    else {
        $null = $results.Add('directory-open-no-backup=success')
        try {
            $null = $results.Add(('directory-flush-no-backup=' + (Flush-StorageProbeHandle $directoryNoBackup.Handle)))
        }
        finally {
            Close-StorageProbeHandle $directoryNoBackup.Handle
        }
    }

    $directoryReadOnly = Open-StorageProbeHandle $DirectoryPath $readAccess $backupFlag
    if ($directoryReadOnly.Handle -eq [PasswordManager.WindowsStorageDiagnosticsNative]::InvalidHandleValue) {
        $null = $results.Add(('directory-open-backup-readonly=' + (Get-StorageCategory $directoryReadOnly.ErrorCode)))
        $null = $results.Add('directory-flush-readonly=not-run')
    }
    else {
        $null = $results.Add('directory-open-backup-readonly=success')
        try {
            $null = $results.Add(('directory-flush-readonly=' + (Flush-StorageProbeHandle $directoryReadOnly.Handle)))
        }
        finally {
            Close-StorageProbeHandle $directoryReadOnly.Handle
        }
    }

    $directoryWritable = Open-StorageProbeHandle $DirectoryPath $writeAccess $backupFlag
    if ($directoryWritable.Handle -eq [PasswordManager.WindowsStorageDiagnosticsNative]::InvalidHandleValue) {
        $null = $results.Add(('directory-open-backup-write=' + (Get-StorageCategory $directoryWritable.ErrorCode)))
        $null = $results.Add('directory-flush-write=not-run')
    }
    else {
        $null = $results.Add('directory-open-backup-write=success')
        try {
            $null = $results.Add(('directory-flush-write=' + (Flush-StorageProbeHandle $directoryWritable.Handle)))
        }
        finally {
            Close-StorageProbeHandle $directoryWritable.Handle
        }
    }
    return ('storage-diagnostic ' + ($results -join ' '))
}

$root = Join-Path $env:ProgramData ("PasswordManager-ticket27-storage-" + [Guid]::NewGuid().ToString('N'))
$probeFile = Join-Path $root 'storage-diagnostic.bin'
$rootOwned = $false
$bodyFailed = $false
$cleanupFailed = $false
$diagnostic = $null

try {
    $installer = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    Assert-True (-not [string]::IsNullOrWhiteSpace($installer)) 'storage diagnostics installer identity unavailable'
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    Assert-True ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'storage diagnostics require an elevated installer'
    Assert-True (-not (Test-Path -LiteralPath $root)) 'storage diagnostics fixture collision'
    New-Item -ItemType Directory -Path $root | Out-Null
    $rootOwned = $true
    Assert-NotReparse $root
    Invoke-SilentChecked 'icacls.exe' @($root, '/inheritance:r', '/grant:r', "${installer}:(OI)(CI)F", 'SYSTEM:(OI)(CI)F') 'storage diagnostics ACL setup failed'
    [IO.File]::WriteAllBytes($probeFile, [byte[]](0x27, 0x27, 0x00, 0x27))
    Invoke-SilentChecked 'icacls.exe' @($probeFile, '/inheritance:r', '/grant:r', "${installer}:F", 'SYSTEM:F') 'storage diagnostics probe ACL setup failed'
    Assert-ExactProbeFileAcl $probeFile $installer
    $diagnostic = Invoke-NativeStorageDiagnostics $probeFile $root
}
catch {
    $bodyFailed = $true
}
finally {
    if ($rootOwned) {
        try {
            if (Test-Path -LiteralPath $probeFile -PathType Leaf) {
                Assert-NotReparse $probeFile
                Remove-Item -LiteralPath $probeFile -Force -ErrorAction Stop
            }
            if (Test-Path -LiteralPath $root -PathType Container) {
                Assert-NotReparse $root
                Remove-Item -LiteralPath $root -Force -ErrorAction Stop
            }
        }
        catch {
            $cleanupFailed = $true
        }
    }
}

if ($cleanupFailed) { throw 'storage diagnostics cleanup failed' }
if ($bodyFailed) { throw 'storage diagnostics execution failed' }
Write-Output $diagnostic
