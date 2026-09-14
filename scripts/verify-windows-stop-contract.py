#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Static preflight for the native STOP implementation; not native evidence."""

from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SERVICE = (ROOT / "crates/pm-custody/src/windows.rs").read_text(encoding="utf-8")
CHANNEL = (ROOT / "crates/pm-native-channel/src/windows.rs").read_text(encoding="utf-8")
HARNESS = (ROOT / "scripts/test-windows-custody-lab.ps1").read_text(encoding="utf-8")


def require(source: str, values: tuple[str, ...], scope: str) -> None:
    missing = [value for value in values if value not in source]
    assert not missing, f"{scope} lacks required STOP contract: {missing}"


require(
    SERVICE,
    (
        "SERVICE_ACCEPT_STOP",
        "SERVICE_CONTROL_STOP",
        "SERVICE_STOP_PENDING",
        "SERVICE_STOPPED",
        "SetServiceStatus",
    ),
    "service",
)
require(
    CHANNEL,
    (
        "FILE_FLAG_OVERLAPPED",
        "CancelIoEx",
        "GetOverlappedResult",
        "WaitForMultipleObjects",
        "OVERLAPPED",
    ),
    "native channel",
)
assert "CancelSynchronousIo" not in SERVICE + CHANNEL
assert HARNESS.count("Stop-Process -Id $crashPid -Force -ErrorAction Stop") == 1
assert "Stop-Service -Name $serviceName -Force" not in HARNESS
assert HARNESS.count("Stop-OwnedService $serviceName") == 2
assert HARNESS.index("Stop-OwnedService $serviceName $preUnlockPid") < HARNESS.index(
    "@('human-lock'"
)
assert HARNESS.count("agent RPK channel failed after SCM restart") == 1
assert HARNESS.count("human RPK channel failed after SCM restart") == 1
assert "Get-CimInstance Win32_Process -Filter \"ProcessId=$ServiceProcessId\"" in HARNESS
assert HARNESS.index("Stop-OwnedService $serviceName $servicePid") < HARNESS.index(
    "Stop-Process -Id $crashPid -Force"
)
assert "Assert-ServiceDiagnosticGenerations $lines" in HARNESS
assert "Assert-OneHumanDiagnosticTrace" in HARNESS
assert "restart=scm-stop+crash" in HARNESS
print("PASS windows-stop-contract static=1 native=NOT_RUN")
