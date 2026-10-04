# SPDX-License-Identifier: AGPL-3.0-only
param(
    [Parameter(Mandatory=$true)][string]$ServiceName,
    [Parameter(Mandatory=$true)][string]$DiagnosticPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Called only for the collision-checked synthetic SCM record owned by the
# custody harness. Snapshot and restore its exact privileges through SCM APIs.
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

public static class W5QuotaDeniedService {
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr OpenSCManagerW(string machine, string database, uint access);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr OpenServiceW(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool CloseServiceHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool QueryServiceConfig2W(IntPtr service, uint level, IntPtr buffer, uint size, out uint needed);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool ChangeServiceConfig2W(IntPtr service, uint level, IntPtr info);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool StartServiceW(IntPtr service, uint count, IntPtr arguments);
    [StructLayout(LayoutKind.Sequential)]
    struct Status {
        public uint Type, State, Controls, Win32Exit, SpecificExit, Checkpoint, Hint, Pid, Flags;
    }
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool QueryServiceStatusEx(IntPtr service, uint level, out Status status, uint size, out uint needed);

    static void Check(bool result, string operation) {
        if (!result) throw new Win32Exception(Marshal.GetLastWin32Error(), operation);
    }
    static IntPtr Snapshot(IntPtr service, out uint bytes) {
        bool first = QueryServiceConfig2W(service, 6, IntPtr.Zero, 0, out bytes);
        int error = Marshal.GetLastWin32Error();
        if (first || error != 122 || bytes < IntPtr.Size || bytes > 65536)
            throw new InvalidOperationException("unexpected required-privilege query result");
        IntPtr buffer = Marshal.AllocHGlobal((int)bytes);
        try {
            uint needed;
            Check(QueryServiceConfig2W(service, 6, buffer, bytes, out needed), "query service privileges");
            return buffer;
        }
        catch { Marshal.FreeHGlobal(buffer); throw; }
    }
    static string Privileges(IntPtr buffer, uint bytes) {
        IntPtr text = Marshal.ReadIntPtr(buffer);
        if (text == IntPtr.Zero) return null;
        long offset = text.ToInt64() - buffer.ToInt64();
        if (offset < IntPtr.Size || offset >= bytes) throw new InvalidOperationException("privilege pointer out of snapshot");
        var chars = new List<char>();
        for (long i = offset; i + 2 <= bytes; i += 2) {
            char value = (char)Marshal.ReadInt16(buffer, (int)i);
            chars.Add(value);
            if (value == '\0' && (chars.Count == 1 || chars[chars.Count - 2] == '\0'))
                return new string(chars.ToArray());
        }
        throw new InvalidOperationException("unterminated privilege list");
    }
    static Status ReadStatus(IntPtr service) {
        Status status; uint needed;
        Check(QueryServiceStatusEx(service, 0, out status, (uint)Marshal.SizeOf<Status>(), out needed), "query service status");
        return status;
    }
    public static void Run(string name) {
        IntPtr manager = IntPtr.Zero, service = IntPtr.Zero, snapshot = IntPtr.Zero;
        IntPtr text = IntPtr.Zero, info = IntPtr.Zero;
        uint bytes = 0; bool changed = false;
        var errors = new List<Exception>();
        try {
            manager = OpenSCManagerW(null, null, 1); Check(manager != IntPtr.Zero, "open SCM");
            service = OpenServiceW(manager, name, 1 | 2 | 4 | 16); Check(service != IntPtr.Zero, "open owned service");
            if (ReadStatus(service).State != 1) throw new InvalidOperationException("quota negative requires stopped service");
            snapshot = Snapshot(service, out bytes);
            // Validate the snapshot before modifying the owned SCM record.
            Privileges(snapshot, bytes);
            text = Marshal.StringToHGlobalUni("SeChangeNotifyPrivilege\0");
            info = Marshal.AllocHGlobal(IntPtr.Size); Marshal.WriteIntPtr(info, text);
            Check(ChangeServiceConfig2W(service, 6, info), "remove owned service working-set privilege");
            changed = true;
            bool started = StartServiceW(service, 0, IntPtr.Zero);
            int startError = Marshal.GetLastWin32Error();
            if (!started && startError != 1067 && startError != 1053 && startError != 1816)
                throw new Win32Exception(startError, "start quota negative service");
            var timer = Stopwatch.StartNew();
            for (;;) {
                Status status = ReadStatus(service);
                if (status.State == 4) throw new InvalidOperationException("quota denied service reached RUNNING");
                if (status.State == 1) {
                    if (status.Win32Exit != 1816 || status.Pid != 0)
                        throw new InvalidOperationException("service did not report stable quota failure");
                    break;
                }
                if (status.State != 2 || timer.ElapsedMilliseconds >= 15000)
                    throw new InvalidOperationException("quota negative service did not stop");
                Thread.Sleep(100);
            }
        }
        catch (Exception error) { errors.Add(error); }
        finally {
            if (changed) {
                try {
                    Check(ChangeServiceConfig2W(service, 6, snapshot), "restore exact service privileges");
                    uint restoredBytes; IntPtr restored = Snapshot(service, out restoredBytes);
                    try {
                        if (Privileges(snapshot, bytes) != Privileges(restored, restoredBytes))
                            throw new InvalidOperationException("service privilege restoration differs");
                    }
                    finally { Marshal.FreeHGlobal(restored); }
                }
                catch (Exception error) { errors.Add(error); }
            }
            if (service != IntPtr.Zero && !CloseServiceHandle(service))
                errors.Add(new Win32Exception(Marshal.GetLastWin32Error(), "close owned service handle"));
            if (manager != IntPtr.Zero && !CloseServiceHandle(manager))
                errors.Add(new Win32Exception(Marshal.GetLastWin32Error(), "close SCM handle"));
            if (info != IntPtr.Zero) Marshal.FreeHGlobal(info);
            if (text != IntPtr.Zero) Marshal.FreeHGlobal(text);
            if (snapshot != IntPtr.Zero) Marshal.FreeHGlobal(snapshot);
        }
        if (errors.Count != 0) throw new AggregateException(errors);
    }
}
'@

[W5QuotaDeniedService]::Run($ServiceName)
$lines = @(Get-Content -LiteralPath $DiagnosticPath -ErrorAction Stop)
if ($lines.Count -ne 3 -or $lines[0] -ne 'phase=args-ok' -or $lines[2] -ne 'phase=service-failed' -or
    $lines[1] -notmatch '^phase=protected-memory-quota-failure category=PROTECTED_MEMORY_QUOTA_UNAVAILABLE reason=working-set-set win32-error=1314$') {
    throw 'SCM quota negative did not stop before bootstrap with the explicit category'
}
Write-Host 'PASS windows-scm-quota-denied public=PROTECTED_MEMORY_QUOTA_UNAVAILABLE scm-exit=1816 win32=1314 bootstrap=not-opened endpoints=not-created privileges=restored'
