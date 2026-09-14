#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Linux process-security tracer for ticket 28; all subjects are owned children."""

import ctypes
import errno
import os
import pathlib
import resource
import select
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time


PASSWORD = b"synthetic-ticket28-master-canary"
PREFIX = "pm-fault-safety-linux-lab-"
PTRACE_ATTACH = 16
PTRACE_DETACH = 17


def wait_line(process, expected, timeout=20, prefix=False):
    deadline = time.monotonic() + timeout
    received = b""
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise AssertionError((process.returncode, received + stdout, stderr))
        remaining = max(0.0, deadline - time.monotonic())
        readable, _, _ = select.select([process.stdout], [], [], min(0.05, remaining))
        if not readable:
            continue
        line = process.stdout.readline()
        received += line
        if line == expected or (prefix and line.startswith(expected)):
            return line
        if line:
            raise AssertionError((expected, received))
    raise AssertionError(("timed out waiting for child output", expected, received))


def attach_result(pid):
    libc = ctypes.CDLL(None, use_errno=True)
    ctypes.set_errno(0)
    result = libc.ptrace(PTRACE_ATTACH, pid, None, None)
    error = ctypes.get_errno()
    if result == 0:
        waited, status = os.waitpid(pid, os.WUNTRACED)
        assert waited == pid and os.WIFSTOPPED(status), (waited, status)
        ctypes.set_errno(0)
        detached = libc.ptrace(PTRACE_DETACH, pid, None, None)
        assert detached == 0, ctypes.get_errno()
        os.kill(pid, signal.SIGCONT)
    return result, error


def core_limits(pid):
    for line in pathlib.Path(f"/proc/{pid}/limits").read_text().splitlines():
        if line.startswith("Max core file size"):
            fields = line.split()
            return fields[-3], fields[-2]
    raise AssertionError("Max core file size missing from proc limits")


def locked_kib(pid):
    for line in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmLck:"):
            return int(line.split()[1])
    raise AssertionError("VmLck missing from proc status")


def assert_no_canary_in_process_metadata(pid, *, guarded):
    cmdline = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes()
    assert PASSWORD not in cmdline
    try:
        environment = pathlib.Path(f"/proc/{pid}/environ").read_bytes()
    except PermissionError as error:
        assert guarded and error.errno in (errno.EACCES, errno.EPERM), error
    else:
        assert not guarded, "guarded process environment remained readable"
        assert PASSWORD not in environment


def stop_owned(process):
    if process.poll() is None:
        process.send_signal(signal.SIGCONT)
        process.send_signal(signal.SIGTERM)
    stdout, stderr = process.communicate(timeout=8)
    assert process.returncode == -signal.SIGTERM, (process.returncode, stdout, stderr)
    return stdout, stderr


def start_create(cli, vault, *, memlock=None):
    def limits():
        if memlock is not None:
            resource.setrlimit(resource.RLIMIT_MEMLOCK, (memlock, memlock))

    return subprocess.Popen(
        [cli, "vault", "create", vault],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={},
        preexec_fn=limits,
    )


def main():
    source_cli = pathlib.Path(sys.argv[1]).resolve(strict=True)
    assert os.geteuid() == 0, "fixture requires only namespace root before dropping privilege"
    root = pathlib.Path(tempfile.mkdtemp(prefix=PREFIX))
    root.chmod(0o700)
    cli = root / "pm"
    shutil.copyfile(source_cli, cli)
    cli.chmod(0o755)
    os.chown(root, 1, 1)
    os.chown(cli, 1, 1)
    os.setgroups([])
    os.setgid(1)
    os.setuid(1)
    processes = []
    try:
        root_stat = root.lstat()
        assert stat.S_ISDIR(root_stat.st_mode) and root_stat.st_uid == os.geteuid()

        control = subprocess.Popen(["/bin/sleep", "30"], env={})
        processes.append(control)
        assert_no_canary_in_process_metadata(control.pid, guarded=False)
        assert attach_result(control.pid) == (0, 0), "ptrace control did not prove observability"
        stop_owned(control)
        processes.remove(control)

        subject = start_create(cli, root / "guarded.sqlite3")
        processes.append(subject)
        wait_line(subject, b"Master password (read from stdin):\n")
        assert_no_canary_in_process_metadata(subject.pid, guarded=True)
        assert core_limits(subject.pid) == ("0", "0")
        result, error = attach_result(subject.pid)
        assert result == -1 and error == errno.EPERM, (result, error)
        subject.stdin.write(PASSWORD + b"\n" + PASSWORD + b"\n")
        subject.stdin.flush()
        wait_line(subject, b"Confirm master password:\n")
        recovery = wait_line(
            subject,
            b"Recovery code (store externally): PMR1-",
            timeout=60,
            prefix=True,
        )
        assert PASSWORD not in recovery
        assert locked_kib(subject.pid) > 0
        stdout, stderr = stop_owned(subject)
        processes.remove(subject)
        assert PASSWORD not in stdout + stderr

        denied = start_create(cli, root / "denied.sqlite3", memlock=0)
        processes.append(denied)
        wait_line(denied, b"Master password (read from stdin):\n")
        try:
            denied.wait(timeout=3)
        except subprocess.TimeoutExpired as error:
            raise AssertionError(
                "client read stdin before reserving its protected input destination"
            ) from error
        stdout, stderr = denied.communicate(timeout=3)
        processes.remove(denied)
        assert denied.returncode == 5, (denied.returncode, stdout, stderr)
        assert b"resource unavailable" in stderr.lower(), stderr
        assert b"Confirm master password" not in stdout
        assert b"Recovery code" not in stdout
        assert PASSWORD not in stdout + stderr
        assert not (root / "denied.sqlite3").exists()

    finally:
        for process in reversed(processes):
            stop_owned(process)
        cli.unlink()
        root.rmdir()

    print(
        "PASS fault-safety-process core=0 dumpable=0 "
        "locked-secrets=1 memlock-denial=closed argv+env+stdout+stderr=clean cleanup=verified"
    )


if __name__ == "__main__":
    main()
