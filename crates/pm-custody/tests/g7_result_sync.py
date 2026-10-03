# SPDX-License-Identifier: AGPL-3.0-only
"""A real settlement fsync failure after exactly one external provider call."""
import pathlib
import re
import signal
import time

from g7_fault_matrix import rows, stopped, witness
from linux_lab import AGENT, CUSTODIAN, wait_for_sockets
from storage_fault_lab import pause_owned


def result_sync(f, channels, daemon, provider, gate, journal, attempt, before, arm, fault, failure):
    from g7_inflight import AUTHORITY, calls, query
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
    daemon.send_signal(signal.SIGCONT)
    # Observe the durable SQLite state, not a sleep claiming completion. No
    # provider is released to reconcile during this observation.
    deadline = time.monotonic() + 8
    expected = "running" if fault else "indeterminate"
    while True:
        visible = query(f["vault"], "SELECT state,provider_sent FROM authentication_attempts")
        if visible == [(expected, 1)] and not stopped(daemon):
            break
        assert visible == [("running", 1)] and time.monotonic() < deadline, "settlement did not preserve expected durable intent"
        time.sleep(0.002)
    pause_owned(daemon)
    after = witness(f, channels)
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
    pause_owned(restarted)
    pause_owned(provider)
    final = witness(f, channels)
    assert all(final[table] == before[table] for table in AUTHORITY)
    assert calls(journal, attempt) == 1, "blind login repeated after failed result persistence"
    channels.scan("settlement-historical-restarted", (restarted, provider))
    print(f"PASS result-sync errno={failure} fault={int(fault)} injected={int(fault)} state=INDETERMINATE authority-exact=1 provider-calls=1", flush=True)
    return 2
