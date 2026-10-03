#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Ticket 28: bootstrap/vault loss, exact restoration, one provider call."""
import json
import os
import pathlib
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from linux_lab import as_uid, create_vault, start_as, wait_for_sockets
from storage_fault_lab import stop_owned
from attempts_lab import agent, human, observe_state, parse, provision

CUSTODIAN, HUMAN, AGENT, AGENT_B, PROVIDER = 1, 2, 3, 4, 5
DEVICE = "88888888888888888888888888888888"
CANARY = b"ticket07-secret-canary"
TABLES = ("authentication_attempts", "encrypted_audit_records", "authority_events", "outbox", "human_receipts")

def counts(vault):
    database = sqlite3.connect(vault)
    try:
        return tuple(database.execute("SELECT count(*) FROM " + table).fetchone()[0] for table in TABLES)
    finally:
        database.close()

def provider_calls(journal, attempt):
    rows = json.loads(journal.read_bytes())
    assert set(rows) == {attempt}, "unexpected provider attempt"
    return rows[attempt]["calls"]

def case(source_binary, source_cli, target, completed):
    root = pathlib.Path(tempfile.mkdtemp(prefix="pm28-custody-loss-" + target + "-"))
    daemon = provider = None
    retained = []
    originals = {}
    replacement = False
    admission_closed = False
    restored_calls = None
    try:
        root.chmod(0o711)
        binary, cli = root / "pm-custody", root / "pm"
        for source, destination in ((source_binary, binary), (source_cli, cli)):
            shutil.copyfile(source, destination)
            destination.chmod(0o755)
        state, runtime, hhome, ahome, bhome, phome, profiles = [root / name for name in ("state", "run", "human", "agent", "agent-b", "provider", "profiles")]
        for path, uid, mode in ((state, CUSTODIAN, 0o700), (runtime, CUSTODIAN, 0o755), (hhome, HUMAN, 0o755), (ahome, AGENT, 0o755), (bhome, AGENT_B, 0o755), (phome, PROVIDER, 0o755), (profiles, 0, 0o755)):
            path.mkdir(mode=mode)
            os.chown(path, uid, uid)
        sk, sp, hk, hp, ak, ap, bk, bp = state / "server.key", state / "server.pub", hhome / "human.key", hhome / "human.pub", ahome / "agent.key", ahome / "agent.pub", bhome / "agent.key", bhome / "agent.pub"
        for uid, private, public in ((CUSTODIAN, sk, sp), (HUMAN, hk, hp), (AGENT, ak, ap), (AGENT_B, bk, bp)):
            as_uid(uid, [binary, "keygen", "--private", private, "--public", public])
        bootstrap = state / "bootstrap"
        provision(binary, bootstrap, sk, sp, ap, AGENT, hp)
        aprof, hprof = profiles / "agent.profile", profiles / "human.profile"
        for role, profile in (("agent", aprof), ("human", hprof)):
            result = subprocess.run([binary, "provision-profile", "--path", profile, "--server-public", sp, "--server-uid", str(CUSTODIAN), "--role", role], capture_output=True, timeout=15)
            assert result.returncode == 0, "profile precondition"
        vault = state / "vault.sqlite3"
        password = create_vault(cli, vault)
        psock, journal = phome / "provider.sock", phome / "journal.json"
        provider_script = phome / "provider.py"
        for source, destination in ((pathlib.Path(__file__).with_name("attempts_lab.py"), provider_script), (pathlib.Path(__file__).with_name("linux_lab.py"), phome / "linux_lab.py")):
            shutil.copyfile(source, destination)
            os.chown(destination, PROVIDER, PROVIDER)
            destination.chmod(0o500)
        provider = start_as(PROVIDER, [sys.executable, provider_script, "provider", psock, journal, str(phome / "resolve-")])
        wait_for_sockets(provider, [psock])
        agent_socket, human_socket = runtime / "agent.sock", runtime / "human.sock"
        serve = [binary, "serve-attempt-lab", "--bootstrap", bootstrap, "--agent-socket", agent_socket, "--human-socket", human_socket, "--vault", vault, "--device", DEVICE, "--provider-socket", psock, "--provider-uid", str(PROVIDER)]
        daemon = start_as(CUSTODIAN, serve)
        wait_for_sockets(daemon, [agent_socket, human_socket])
        human(binary, hk, hprof, human_socket, password, "setup", ap.read_bytes(), bp.read_bytes())
        discovery = as_uid(AGENT, [binary, "agent-discover", "--profile", aprof, "--private", ak, "--socket", agent_socket])
        match = re.search(rb"set=([0-9a-f]{32}):", discovery.stdout)
        assert match, "enabled credential precondition"
        item = match.group(1).decode("ascii")
        issued = int(time.time() * 1_000_000)
        initial = agent(binary, AGENT, ak, aprof, agent_socket, "start", item=item, issued_at=issued, nonce="28" * 16, context="success" if completed else "ambiguous")
        attempt = parse(initial, "CREATED")
        observe_state(binary, AGENT, ak, aprof, agent_socket, attempt, "SUCCEEDED" if completed else "INDETERMINATE", {("RUNNING", "")})
        assert provider_calls(journal, attempt) == 1, "provider control count"
        stop_owned(daemon)
        daemon = None
        before = counts(vault)
        originals = {path: path.read_bytes() for path in (bootstrap, sk, pathlib.Path(str(vault) + ".audit-custody"))}
        print("PM28_CUSTODY_LOSS_CONTROL target=" + target + " provider-calls=1 state=" + ("SUCCEEDED" if completed else "INDETERMINATE"), flush=True)
        paths = [bootstrap] if target == "bootstrap" else [vault, pathlib.Path(str(vault) + "-wal"), pathlib.Path(str(vault) + "-shm")]
        for path in paths:
            if path.exists():
                saved = path.with_name("owned-retained-" + path.name)
                path.rename(saved)
                retained.append((path, saved))
        # Remove only known stale sockets before this one startup, not as a retry.
        for path in (agent_socket, human_socket):
            if path.exists():
                path.unlink()
        daemon = start_as(CUSTODIAN, serve)
        deadline = time.monotonic() + 8
        while daemon.poll() is None and not (agent_socket.exists() and human_socket.exists()):
            assert time.monotonic() < deadline, "lost custody startup observation deadline"
            time.sleep(0.005)
        if daemon.poll() is not None:
            stdout, stderr = daemon.communicate(timeout=1)
            admission_closed = daemon.returncode == 4 and stdout == b"" and stderr == b"CUSTODY_UNAVAILABLE\n"
            print("PM28_CUSTODY_LOSS_PUBLIC target=" + target + " rc=" + str(daemon.returncode) + " empty-stdout=" + str(int(stdout == b"")) + " custody-error=" + str(int(stderr == b"CUSTODY_UNAVAILABLE\n")), flush=True)
            daemon = None
        else:
            denied = agent(binary, AGENT, ak, aprof, agent_socket, "start", item=item, issued_at=issued, nonce="29" * 16, context="success")
            admission_closed = denied.returncode == 4 and denied.stdout in (b"", b"DENIED code=1\n") and denied.stderr == b"CUSTODY_UNAVAILABLE\n"
            print("PM28_CUSTODY_LOSS_PUBLIC target=" + target + " rc=" + str(denied.returncode) + " empty-stdout=" + str(int(denied.stdout == b"")) + " denied-one=" + str(int(denied.stdout == b"DENIED code=1\n")) + " custody-error=" + str(int(denied.stderr == b"CUSTODY_UNAVAILABLE\n")), flush=True)
            assert CANARY not in denied.stdout and CANARY not in denied.stderr, "canary in public error"
        assert provider_calls(journal, attempt) == 1, "provider repeated after loss"
        if daemon is not None:
            stop_owned(daemon)
            daemon = None
        replacement = any(path.exists() for path, _ in retained)
        print("PM28_CUSTODY_LOSS_REPLACEMENT target=" + target + " main-vault=" + str(int(target == "vault" and vault.exists())), flush=True)
        for path, saved in retained:
            if path.exists():
                path.unlink()
            saved.rename(path)
        retained.clear()
        assert all(path.read_bytes() == value for path, value in originals.items()), "custody keys changed"
        for path in (agent_socket, human_socket):
            if path.exists():
                path.unlink()
        daemon = start_as(CUSTODIAN, serve)
        wait_for_sockets(daemon, [agent_socket, human_socket])
        observe_state(binary, AGENT, ak, aprof, agent_socket, attempt, "SUCCEEDED" if completed else "INDETERMINATE", {("RUNNING", "INDETERMINATE")})
        after = counts(vault)
        print("PM28_CUSTODY_LOSS_INVARIANTS target=" + target + " unchanged=" + str(tuple(int(a == b) for a, b in zip(before, after))) + " replacement=" + str(int(replacement)) + " closed=" + str(int(admission_closed)), flush=True)
        assert after == before, "authority or receipts changed across loss"
        restored_calls = provider_calls(journal, attempt)
        assert restored_calls == 1, "provider repeated after restoration"
        print("PM28_CUSTODY_LOSS_OBSERVED target=" + target + " replacement=" + str(int(replacement)) + " closed=" + str(int(admission_closed)) + " provider-calls=" + str(restored_calls) + " exact-restoration=1", flush=True)
    finally:
        primary = sys.exception()
        errors = []
        for process in (daemon, provider):
            if process is not None:
                try:
                    stop_owned(process)
                except BaseException as error:
                    errors.append(error)
        try:
            shutil.rmtree(root)
            assert not root.exists()
        except BaseException as error:
            errors.append(error)
        print("PM28_CUSTODY_LOSS_CLEANUP target=" + target + " errors=" + str(len(errors)), flush=True)
        if errors:
            if primary is not None:
                errors.insert(0, primary)
            raise ExceptionGroup("owned custody loss cleanup failures", errors)
    assert admission_closed, "custody loss did not close admission"
    assert not replacement, "lost custody was replaced automatically"
    print("PASS custody-loss target=" + target + " provider-calls=1", flush=True)

def main():
    assert os.geteuid() == 0 and len(sys.argv) in (4, 5)
    binary, cli = (pathlib.Path(value).resolve(strict=True) for value in sys.argv[1:3])
    target = sys.argv[3]
    assert target in ("bootstrap", "vault")
    completed = len(sys.argv) == 5
    if completed:
        assert sys.argv[4] == "completed"
    case(binary, cli, target, completed)

if __name__ == "__main__":
    main()
