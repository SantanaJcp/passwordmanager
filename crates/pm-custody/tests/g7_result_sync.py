# SPDX-License-Identifier: AGPL-3.0-only
"""A real settlement fsync failure after exactly one external provider call."""
import contextlib
import pathlib
import errno
import fcntl
import os
import re
import signal
import sqlite3
import time

from g7_fault_matrix import rows, stopped, witness
from linux_lab import AGENT, CUSTODIAN, wait_for_sockets
from storage_fault_lab import pause_owned


def wal_guard(descriptor, daemon, deadline):
    """Fence SQLite's Unix WAL writer/checkpoint/recovery until all tasks stop.

    SQLite 3.53.2's Unix VFS uses bytes 120..122 of the existing SHM file.
    No file contents or database transactions are changed. The source SQLite
    connection pins the live WAL index throughout this observation.
    """
    while True:
        assert time.monotonic() < deadline, "settlement WAL quiescence deadline"
        assert daemon.poll() is None, "custodian exited before WAL quiescence"
        try:
            fcntl.lockf(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB, 3, 120)
            break
        except OSError as error:
            if error.errno not in (errno.EACCES, errno.EAGAIN):
                raise
            assert time.monotonic() < deadline, "settlement WAL locks not released"
            time.sleep(0.002)
    pause_owned(daemon, timeout=deadline - time.monotonic())
    while True:
        states = [task.joinpath("status").read_text() for task in pathlib.Path(f"/proc/{daemon.pid}/task").iterdir()]
        if states and all(any(line.startswith("State:\tT") for line in status.splitlines()) for status in states):
            return
        assert daemon.poll() is None and time.monotonic() < deadline, "settlement tasks not quiescent"
        time.sleep(0.002)


def writer_busy(descriptor):
    try:
        fcntl.lockf(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB, 1, 120)
    except OSError as error:
        if error.errno in (errno.EACCES, errno.EAGAIN):
            return True
        raise
    fcntl.lockf(descriptor, fcntl.LOCK_UN, 1, 120)
    return False


def result_sync(f, channels, daemon, provider, gate, journal, attempt, before, arm, fault, failure):
    from g7_inflight import AUTHORITY, calls
    preceding = len(rows(f["events"], daemon.pid))
    # This must be confirmed by the successful control's copied pending row:
    # first call is the WAL header, second is the settlement commit sync.
    arm.chmod(0o644)
    assert failure in ("EIO", "ENOSPC")
    arm.write_text(f"{preceding + 2} {failure} {int(fault)}")
    arm.chmod(0o444)
    pathlib.Path(str(gate) + ".release").write_bytes(b"release")
    provider.send_signal(signal.SIGCONT)
    daemon.send_signal(signal.SIGCONT)
    deadline = time.monotonic() + 8
    while not stopped(daemon):
        assert time.monotonic() < deadline, "settlement syscall control not reached"
        time.sleep(0.002)
    events = rows(f["events"], daemon.pid)
    assert len(events) == preceding + 2 and int(events[-1][4]) == int(fault), "wrong settlement syscall/injection count"
    pending = witness(f, channels)
    assert pending["encrypted_audit_records"][0] == before["encrypted_audit_records"][0] + 1, "positive settlement audit witness"
    assert pending["authentication_attempts"][0] == 1 and pending["authentication_attempts"][1] != before["authentication_attempts"][1], "positive settlement state witness"
    assert all(pending[table] == before[table] for table in AUTHORITY), "settlement changed authority"
    pause_owned(provider)
    assert calls(journal, attempt) == 1
    channels.scan("settlement-active-syscall", (daemon, provider))
    print(f"PM28_RESULT_SYNC_CONTROL errno={failure} fault={int(fault)} offset=2 syscall={events[-1][2]} pending-state=changed pending-audit=1 provider-calls=1 injected={events[-1][4]}", flush=True)
    # Pin the original WAL index while its custodian is still at the syscall.
    # A new raw-copy connection would rebuild the index from commit markers,
    # including frames from a failed sync. Keep this read-only connection open
    # through rollback and use it for the committed snapshot.
    with contextlib.closing(sqlite3.connect(f["vault"].resolve().as_uri() + "?mode=ro", uri=True, timeout=5)) as source:
        assert source.execute("SELECT state,provider_sent FROM authentication_attempts").fetchall() == [("running", 1)]
        descriptor = os.open(str(f["vault"]) + "-shm", os.O_RDWR | os.O_CLOEXEC)
        try:
            assert writer_busy(descriptor), "settlement writer-lock positive control missing"
            daemon.send_signal(signal.SIGCONT)
            deadline = time.monotonic() + 8
            expected = "running" if fault else "indeterminate"
            while True:
                visible = source.execute("SELECT state,provider_sent FROM authentication_attempts").fetchall()
                if visible == [(expected, 1)] and not stopped(daemon):
                    break
                assert visible == [("running", 1)] and time.monotonic() < deadline, "settlement did not preserve expected durable intent"
                time.sleep(0.002)
            wal_guard(descriptor, daemon, deadline)
            assert source.execute("SELECT state,provider_sent FROM authentication_attempts").fetchall() == [(expected, 1)], "settlement changed the committed durable intent"
            after = witness(f, channels, committed_source=source)
            print(f"PMRS_QUIESCENT writer-control=busy tasks-stopped=all snapshot=committed state-exact={int(after['authentication_attempts'] == before['authentication_attempts'])} audit-exact={int(after['encrypted_audit_records'] == before['encrypted_audit_records'])} provider-calls={calls(journal, attempt)}", flush=True)
        finally:
            os.close(descriptor)
    assert all(after[table] == before[table] for table in AUTHORITY)
    if fault:
        assert after["authentication_attempts"] == before["authentication_attempts"], "partial state settlement after fsync failure"
        assert after["encrypted_audit_records"] == before["encrypted_audit_records"], "partial audit settlement after fsync failure"
    channels.scan("settlement-historical-error" if fault else "settlement-historical-control", (daemon, provider))
    daemon.send_signal(signal.SIGCONT)
    daemon.send_signal(signal.SIGTERM)
    assert daemon.wait(timeout=8) == -signal.SIGTERM
    for path in (f["agent_socket"], f["human_socket"]):
        assert path.is_socket()
        path.unlink()
    serve = list(f["serve"])
    serve[1] = "serve-attempt-lab"
    serve += ["--provider-socket", f["root"] / "provider/provider.sock", "--provider-uid", "5"]
    provider.send_signal(signal.SIGCONT)
    restarted = channels.spawn(CUSTODIAN, serve, "settlement-restart")
    wait_for_sockets(restarted, (f["agent_socket"], f["human_socket"]))
    deadline = time.monotonic() + 15
    with contextlib.closing(sqlite3.connect(f["vault"].resolve().as_uri() + "?mode=ro", uri=True, timeout=5)) as source:
        # Pin sidecars before recovery/reconciliation can close its last DB
        # connection. Scanning a task frozen during unlink/close is incomplete.
        source.execute("SELECT state,provider_sent FROM authentication_attempts").fetchall()
        number = 0
        while True:
            get = channels.spawn(AGENT, [f["binary"], "agent-attempt", "--profile", f["profiles"] / "agent.profile", "--private", f["agent_key"], "--socket", f["agent_socket"], "--action", "get", "--attempt", attempt], "settlement-get-" + str(number))
            result = channels.result(get)
            assert result.returncode == 0 and result.stderr == b""
            state = re.search(rb"state=([A-Z_]+) reason=([^ ]*) result=(.*)", result.stdout)
            assert state and state[3] == b"", "intention without durable result published success"
            if state[1] == b"INDETERMINATE":
                break
            assert (state[1], state[2]) == (b"RUNNING", b"INDETERMINATE") and time.monotonic() < deadline
            number += 1
        pause_owned(provider)
        descriptor = os.open(str(f["vault"]) + "-shm", os.O_RDWR | os.O_CLOEXEC)
        try:
            # Preserve the prior five-second stop budget for the final scan too.
            wal_guard(descriptor, restarted, time.monotonic() + 5)
            final = witness(f, channels, committed_source=source)
        finally:
            os.close(descriptor)
        assert all(final[table] == before[table] for table in AUTHORITY)
        assert calls(journal, attempt) == 1, "blind login repeated after failed result persistence"
        channels.scan("settlement-historical-restarted", (restarted, provider))
    print(f"PASS result-sync errno={failure} fault={int(fault)} injected={int(fault)} state=INDETERMINATE authority-exact=1 provider-calls=1", flush=True)
    return 2
