# SPDX-License-Identifier: AGPL-3.0-only
"""Real syscalls, quiescent SQLite witnesses and the existing ticket-28 lab."""
import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import sqlite3
import time

from g7_canary_channels import Channels, scan_bytes, scan_file, scanner_controls
from linux_lab import CUSTODIAN, HUMAN, wire_fields
from sqlite_sync_fault_lab import CANARY, run_case
from storage_fault_lab import ATOMIC_TABLES, STAGING_TABLES, pause_owned

STREAM_CANARY = b"ticket05-large-stream-canary"
ATOMIC_CONTENT = ATOMIC_TABLES + (
    "vault_metadata", "encrypted_objects", "audit_keys", "encrypted_audit_records",
    "audit_state", "audit_segments", "audit_manifests", "agent_authorizations",
    "delegated_state", "credential_authorizations",
)
TABLES = ATOMIC_CONTENT + ("authentication_attempts", "human_staging") + STAGING_TABLES
EVENT = re.compile(r"pid=(\d+) op=(fsync|fdatasync|pwrite64|pwrite) count=(\d+) injected=([01])")


class ProductRed(AssertionError):
    """Only post-control behavioral failures; fixture errors never use this."""


def rows(path, pid):
    parsed = [EVENT.fullmatch(line) for line in path.read_text().splitlines()]
    assert all(parsed), "incomplete or malformed syscall event"
    assert all(int(row[1]) == pid for row in parsed), "interposer targeted a foreign PID"
    assert [int(row[3]) for row in parsed] == list(range(1, len(parsed) + 1)), "missing syscall ordinal"
    return parsed


def stopped(process):
    assert process.poll() is None, "custodian exited during syscall observation"
    return any(line.startswith("State:\tT") for line in pathlib.Path(f"/proc/{process.pid}/status").read_text().splitlines())


def witness(f, channels):
    """Open only a copied WAL view; never checkpoint or mutate the real vault."""
    folder = channels.logdir / "sqlite-witness"
    folder.mkdir(mode=0o700)
    channels.directories.add(folder)
    copy = folder / "vault.sqlite3"
    for suffix, category in (("", "database"), ("-wal", "wal"), ("-shm", "shm"), ("-journal", "journal")):
        source = pathlib.Path(str(f["vault"]) + suffix)
        destination = pathlib.Path(str(copy) + suffix)
        channels.register(destination, category)
        if source.exists():
            shutil.copyfile(source, destination)
            scan_file(destination, channels.canaries, category)
    assert copy.is_file(), "missing main SQLite witness"
    database = sqlite3.connect(copy.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        result = {}
        for table in TABLES:
            values = database.execute("SELECT * FROM " + table + " ORDER BY rowid").fetchall()
            digest = hashlib.sha256()
            total = 0
            for row in values:
                for value in row:
                    encoded = value if isinstance(value, bytes) else repr(value).encode("utf-8")
                    scan_bytes(encoded, channels.canaries, "staging/audit-sql")
                    total += len(encoded)
                    digest.update(len(encoded).to_bytes(8, "big"))
                    digest.update(encoded)
            result[table] = (len(values), digest.hexdigest())
            if table in STAGING_TABLES + ("human_staging", "encrypted_audit_records", "audit_state", "audit_segments", "audit_manifests"):
                category = "staging-sql" if table.startswith("human_staging") else "audit-sql"
                print(f"PM28_CANARY channel={category} table={table} rows={len(values)} bytes={total} complete=1", flush=True)
        assert database.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        database.close()
    for path in folder.iterdir():
        assert path in channels.files and path.is_file(), "unclassified SQLite witness artifact"
        scan_file(path, channels.canaries, channels.files[path])
    shutil.rmtree(folder)
    channels.directories.remove(folder)
    return result


def summary(snapshot):
    return {name: count for name, (count, _) in snapshot.items()}


def boundary(snapshot, before):
    count = summary(snapshot)
    previous = summary(before)
    if count["human_receipts"] > previous["human_receipts"]:
        assert all(count[name] > previous[name] for name in ("vault_items", "revision_parts", "authority_events", "outbox", "encrypted_audit_records")), "positive commit witness is partial"
        return "commit-outbox-audit"
    if count["human_staging"] > previous["human_staging"] and count["human_staging_stream_chunks"] > 0:
        return "staging"
    if count["encrypted_audit_records"] > previous["encrypted_audit_records"]:
        return "audit"
    return "wal"


def exercise(f, *, selected=None, error="EIO", trace=False, control=None):
    channels = Channels(f, (CANARY, STREAM_CANARY, f["password"]))
    process = client = None
    try:
        environment = dict(f["environment"], PM28_SYNC_OPERATION="sync", PM28_SYNC_PAUSE="all",
                           PM28_SYNC_INDEX=str(selected or 1), PM28_SYNC_FAIL=str(int(selected is not None)), PM28_SYNC_ERRNO=error)
        process = channels.spawn(CUSTODIAN, f["serve"], "custodian", environment=environment)
        f["pid_path"].write_text(str(process.pid))
        f["pid_path"].chmod(0o444)
        from linux_lab import wait_for_sockets
        wait_for_sockets(process, (f["agent_socket"], f["human_socket"]))
        pause_owned(process)
        baseline = witness(f, channels)
        channels.scan("active-before-request", (process,))
        process.send_signal(signal.SIGCONT)
        command = [f["binary"], "human-streaming-file", "--profile", f["human_profile"], "--private", f["human_key"], "--socket", f["human_socket"]]
        client = channels.spawn(HUMAN, command, "human", input=wire_fields([f["password"]]))
        previous = baseline
        observed = []
        last = 0
        selected_before = selected_pending = None
        deadline = time.monotonic() + 15
        while client.poll() is None:
            assert time.monotonic() < deadline, "syscall fixture deadline (not a product RED)"
            if stopped(process):
                events = rows(f["events"], process.pid)
                assert len(events) == last + 1, "non-serial syscall checkpoint"
                current = witness(f, channels)
                phase = boundary(current, previous)
                last += 1
                observed.append((last, phase, summary(current)))
                if trace:
                    print("PM28_SYSCALL_WITNESS " + json.dumps(dict(index=last, phase=phase, counts=summary(current))), flush=True)
                if last == selected:
                    selected_before, selected_pending = previous, current
                    assert summary(current) == control[2], "fault ordinal did not reach the positive logical boundary"
                    channels.scan("active-fault-" + phase, (process, client))
                previous = current
                process.send_signal(signal.SIGCONT)
            else:
                time.sleep(0.002)
        result = channels.result(client)
        # Stop rotation before enumerating the actual DB/WAL/SHM and logs.
        pause_owned(process)
        channels.scan("after-error" if selected else "after-success", (process,))
        after = witness(f, channels)
        events = rows(f["events"], process.pid)
        assert sum(int(event[4]) for event in events) == int(selected is not None), "fault was not injected exactly once"
        defects = []
        if selected:
            assert selected_before is not None and selected_pending is not None, "unreached boundary"
            exact = all(after[table] == selected_before[table] for table in ATOMIC_CONTENT)
            print(f"PM28_BOUNDARY index={selected} errno={error} phase={control[1]} syscall={events[selected - 1][2]} injected=1 rc={result.returncode} authority-atomic={int(exact)} counts={summary(after)}", flush=True)
            if not (result.returncode == 4 and result.stdout == b"" and result.stderr == b"CUSTODY_UNAVAILABLE\n"):
                defects.append("failed syscall published a successful mutation")
            if not exact:
                defects.append("failed syscall changed authoritative transaction or audit")
            if not all(after[table][0] == 0 for table in STAGING_TABLES):
                defects.append("stream staging survived failed operation")
        else:
            assert result.returncode == 0 and result.stderr == b"", "positive stream control failed"
            assert after["human_receipts"][0] == 1 and after["outbox"][0] == 1
            assert after["attachment_stream_chunks"][0] == 17
        process.send_signal(signal.SIGCONT)
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=8) == -signal.SIGTERM
        channels.scan("historical-before-restart")
        for path in (f["agent_socket"], f["human_socket"]):
            assert path.is_socket()
            path.unlink()
        restarted = channels.spawn(CUSTODIAN, f["serve"], "restart", environment={})
        wait_for_sockets(restarted, (f["agent_socket"], f["human_socket"]))
        pause_owned(restarted)
        channels.scan("historical-after-restart", (restarted,))
        final = witness(f, channels)
        assert all(final[table] == after[table] for table in ATOMIC_CONTENT), "restart changed authority or transaction"
        if not all(final[table][0] == 0 for table in STAGING_TABLES):
            defects.append("restart retained stream staging")
        print("PM28_RESTART_STAGING counts=" + str(tuple(final[table][0] for table in STAGING_TABLES)), flush=True)
        print(f"PM28_BOUNDARY_DONE selected={selected or 0} syscall-calls={len(events)} restart=same-vault", flush=True)
        if defects:
            raise ProductRed("; ".join(defects))
        return observed
    finally:
        channels.close()


def matrix(binary, cli, interposer, arguments):
    if arguments == ["canaries"]:
        run_case(binary, cli, interposer, False, scanner_controls)
        run_case(binary, cli, interposer, False, historical_crud)
        return
    if arguments[0] in ("inflight", "inflight-live"):
        from g7_inflight import inflight
        if arguments[1] == "result-sync":
            control = []
            run_case(binary, cli, interposer, False, lambda f: control.append(inflight(f, "result-control")))
            assert len(control) == 1 and control[0] == 2, "unconfirmed settlement syscall control"
            for error in ("EIO", "ENOSPC"):
                run_case(binary, cli, interposer, False, lambda f, failure=error: inflight(f, "result-sync", failure=failure))
            return
        run_case(binary, cli, interposer, False, lambda f: inflight(f, arguments[1], live=arguments[0] == "inflight-live"))
        return
    assert arguments in (["matrix"], ["matrix", "trace"])
    run_case(binary, cli, interposer, False, scanner_controls)
    controls = []
    run_case(binary, cli, interposer, False, lambda f: controls.extend(exercise(f, trace=True)))
    assert controls, "no syscall control"
    if len(arguments) == 2:
        return
    # Each logical boundary uses a new vault. Commit/outbox/audit share one
    # physical commit and are checked together, plus a separate audit unlock.
    red = []
    run_case(binary, cli, interposer, False, lambda f: spill(f, False, "EIO"))
    for error in ("EIO", "ENOSPC"):
        run_case(binary, cli, interposer, True, lambda f, failure=error: spill(f, True, failure))
    for logical in ("wal", "staging", "commit-outbox-audit", "audit"):
        control = next(row for row in controls if row[1] == logical)
        for error in ("EIO", "ENOSPC"):
            try:
                run_case(binary, cli, interposer, True,
                         lambda f, row=control, failure=error: exercise(f, selected=row[0], control=row, error=failure))
            except ProductRed as defect:
                red.append((logical, error, str(defect)))
                print(f"RED boundary={logical} errno={error} defect={defect}", flush=True)
            else:
                print(f"PASS boundary={logical} errno={error} positive-control=1", flush=True)
    if red:
        raise ProductRed(json.dumps(red))
    print("PASS matrix logical=wal,staging,commit,outbox,audit syscall=real faults=EIO+ENOSPC fresh-vault=each no-operation-retry=1", flush=True)


def spill(f, fault, error):
    """The uncommitted stream spill uses pwrite, before staging's fsync."""
    channels = Channels(f, (STREAM_CANARY, f["password"]))
    try:
        environment = dict(f["environment"], PM28_SYNC_OPERATION="write", PM28_SYNC_PAUSE="selected",
                           PM28_SYNC_INDEX="600", PM28_SYNC_FAIL=str(int(fault)), PM28_SYNC_ERRNO=error)
        daemon = channels.spawn(CUSTODIAN, f["serve"], "custodian", environment=environment)
        f["pid_path"].write_text(str(daemon.pid))
        f["pid_path"].chmod(0o444)
        from linux_lab import wait_for_sockets
        wait_for_sockets(daemon, (f["agent_socket"], f["human_socket"]))
        client = channels.spawn(HUMAN, [f["binary"], "human-streaming-file", "--profile", f["human_profile"], "--private", f["human_key"], "--socket", f["human_socket"]], "stream", input=wire_fields([f["password"]]))
        deadline = time.monotonic() + 15
        while not stopped(daemon):
            assert client.poll() is None and time.monotonic() < deadline, "spill syscall control not reached"
            time.sleep(0.002)
        events = rows(f["events"], daemon.pid)
        assert len(events) == 600 and int(events[-1][4]) == int(fault) and events[-1][2] in ("pwrite64", "pwrite")
        wal_size = pathlib.Path(str(f["vault"]) + "-wal").stat().st_size
        assert wal_size > 1024 * 1024, "positive real uncommitted spill WAL witness"
        before = witness(f, channels)
        assert before["vault_items"][0] == before["outbox"][0] == before["human_receipts"][0] == 0
        channels.scan("active-uncommitted-spill", (daemon, client))
        daemon.send_signal(signal.SIGCONT)
        result = channels.result(client)
        pause_owned(daemon)
        channels.scan("historical-uncommitted-spill", (daemon,))
        after = witness(f, channels)
        events = rows(f["events"], daemon.pid)
        assert sum(int(event[4]) for event in events) == int(fault)
        if fault:
            assert result.returncode == 4 and result.stdout == b"" and result.stderr == b"CUSTODY_UNAVAILABLE\n"
            assert all(after[table] == before[table] for table in ATOMIC_CONTENT), "spill error changed authority"
            assert all(after[table][0] == 0 for table in STAGING_TABLES), "spill error retained staged chunks"
        else:
            assert result.returncode == 0 and after["human_receipts"][0] == after["outbox"][0] == 1
        daemon.send_signal(signal.SIGCONT)
        daemon.send_signal(signal.SIGTERM)
        assert daemon.wait(timeout=8) == -signal.SIGTERM
        for path in (f["agent_socket"], f["human_socket"]):
            assert path.is_socket()
            path.unlink()
        restarted = channels.spawn(CUSTODIAN, f["serve"], "restart")
        wait_for_sockets(restarted, (f["agent_socket"], f["human_socket"]))
        pause_owned(restarted)
        channels.scan("historical-spill-restart", (restarted,))
        final = witness(f, channels)
        assert all(final[table] == after[table] for table in ATOMIC_CONTENT)
        print(f"PASS spill syscall={events[599][2]} index=600 wal-bytes={wal_size} errno={error} injected={int(fault)} positive-control=1 restart=same-vault", flush=True)
    finally:
        channels.close()


def historical_crud(f):
    channels = Channels(f, (CANARY, CANARY + b"_EDITED", f["password"]))
    try:
        daemon = channels.spawn(CUSTODIAN, f["serve"], "custodian", environment=dict(f["environment"], PM28_SYNC_FAIL="0", PM28_SYNC_PAUSE="all"))
        f["pid_path"].write_text(str(daemon.pid))
        f["pid_path"].chmod(0o444)
        from linux_lab import wait_for_sockets
        wait_for_sockets(daemon, (f["agent_socket"], f["human_socket"]))
        client = channels.spawn(HUMAN, [f["binary"], "human-password-crud", "--profile", f["human_profile"], "--private", f["human_key"], "--socket", f["human_socket"]], "crud",
                                input=wire_fields([f["password"], b"PM28 synthetic title", b"PM28 synthetic account", CANARY, b"https://pm28.invalid", b"PM28 synthetic note", b"PM28 edited title", CANARY + b"_EDITED"]))
        last, revisions = 0, 0
        deadline = time.monotonic() + 15
        while client.poll() is None:
            assert time.monotonic() < deadline, "historical CRUD fixture deadline"
            if stopped(daemon):
                events = rows(f["events"], daemon.pid)
                assert len(events) == last + 1 and events[-1][4] == "0"
                last += 1
                current = witness(f, channels)
                if current["revision_parts"][0] > revisions:
                    revisions = current["revision_parts"][0]
                    channels.scan("active-revision-" + str(revisions), (daemon, client))
                daemon.send_signal(signal.SIGCONT)
            else:
                time.sleep(0.002)
        result = channels.result(client)
        assert result.returncode == 0 and result.stderr == b"" and result.stdout == b"PASS human-crud-e2e receipts=3 replay=1 body-change=rejected\n", "historical CRUD public control"
        pause_owned(daemon)
        snapshot = witness(f, channels)
        assert snapshot["revision_parts"][0] == 2 and snapshot["human_receipts"][0] == snapshot["outbox"][0] == 3
        channels.scan("historical-revisions-after-trash", (daemon,))
        daemon.send_signal(signal.SIGCONT)
        daemon.send_signal(signal.SIGTERM)
        assert daemon.wait(timeout=8) == -signal.SIGTERM
        for path in (f["agent_socket"], f["human_socket"]):
            assert path.is_socket()
            path.unlink()
        restarted = channels.spawn(CUSTODIAN, f["serve"], "restart")
        wait_for_sockets(restarted, (f["agent_socket"], f["human_socket"]))
        pause_owned(restarted)
        final = witness(f, channels)
        assert all(final[table] == snapshot[table] for table in ATOMIC_CONTENT)
        channels.scan("historical-revisions-after-restart", (restarted,))
        print("PASS canaries active-revisions=2 historical-revisions=2 receipts=3 explicit-CRUD-replay=1 sources=original+edited scan=complete", flush=True)
    finally:
        channels.close()
