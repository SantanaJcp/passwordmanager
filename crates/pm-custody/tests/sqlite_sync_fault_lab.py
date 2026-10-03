#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Real SQLite FULL WAL sync failure at the first human audit admission."""
import os
import pathlib
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
from linux_lab import AGENT, CUSTODIAN, HUMAN, as_uid, create_vault, start_as, wait_for_sockets, wire_fields
from storage_fault_lab import ATOMIC_TABLES, STAGING_TABLES, counts, pause_owned, stop_owned
DEVICE = "28282828282828282828282828282828"
CANARY = b"PM28_SYNTHETIC_SQLITE_SYNC_CANARY"


def run_case(source_binary, source_cli, interposer_source, fault):
    root = pathlib.Path(tempfile.mkdtemp(prefix="pm28-sqlite-sync-linux-lab-"))
    state = root / "state"
    daemon = None
    try:
        root.chmod(0o711)
        state.mkdir(mode=0o700)
        os.chown(state, CUSTODIAN, CUSTODIAN)
        binary, cli = root / "pm-custody", root / "pm"
        shutil.copyfile(source_binary, binary)
        shutil.copyfile(source_cli, cli)
        binary.chmod(0o755)
        cli.chmod(0o755)
        runtime, human_home, agent_home, profiles = [
            root / name for name in ("run", "human", "agent", "profiles")
        ]
        for path, uid, mode in (
            (runtime, CUSTODIAN, 0o755),
            (human_home, HUMAN, 0o755),
            (agent_home, AGENT, 0o755),
            (profiles, 0, 0o755),
        ):
            path.mkdir(mode=mode)
            os.chown(path, uid, uid)
        server_key, server_pub = state / "server.key", state / "server.pub"
        human_key, human_pub = human_home / "human.key", human_home / "human.pub"
        agent_key, agent_pub = agent_home / "agent.key", agent_home / "agent.pub"
        for uid, private, public in (
            (CUSTODIAN, server_key, server_pub),
            (HUMAN, human_key, human_pub),
            (AGENT, agent_key, agent_pub),
        ):
            as_uid(uid, [binary, "keygen", "--private", private, "--public", public])
        bootstrap = state / "bootstrap"
        as_uid(CUSTODIAN, [
            binary, "provision-bootstrap", "--path", bootstrap,
            "--server-private", server_key, "--server-public", server_pub,
            "--agent-public", agent_pub, "--agent-uid", str(AGENT),
            "--human-public", human_pub, "--human-uid", str(HUMAN),
        ])
        human_profile = profiles / "human.profile"
        subprocess.run([
            binary, "provision-profile", "--path", human_profile,
            "--server-public", server_pub, "--server-uid", str(CUSTODIAN),
            "--role", "human",
        ], check=True, capture_output=True)
        vault = state / "vault.sqlite3"
        password = create_vault(cli, vault)
        agent_socket, human_socket = runtime / "agent.sock", runtime / "human.sock"
        serve = [
            binary, "serve-vault", "--bootstrap", bootstrap,
            "--agent-socket", agent_socket, "--human-socket", human_socket,
            "--vault", vault, "--device", DEVICE,
        ]
        interposer = root / "sync-interposer.so"
        subprocess.run(["cc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror", "-o", interposer, interposer_source, "-ldl"], check=True, capture_output=True)
        interposer.chmod(0o755)
        events, pid_path = state / "owned-sync.events", state / "owned-sync.pid"
        events.write_bytes(b"")
        os.chown(events, CUSTODIAN, CUSTODIAN)
        environment = {"LD_PRELOAD": str(interposer), "PM28_SYNC_TARGET": str(vault) + "-wal", "PM28_SYNC_PID": str(pid_path), "PM28_SYNC_LOG": str(events), "PM28_SYNC_FAIL": str(int(fault))}
        def identity():
            os.setgroups([])
            os.setgid(CUSTODIAN)
            os.setuid(CUSTODIAN)
        daemon = subprocess.Popen(serve, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=identity)
        pid_path.write_text(str(daemon.pid))
        pid_path.chmod(0o444)
        wait_for_sockets(daemon, [agent_socket, human_socket])
        baseline = counts(vault, ATOMIC_TABLES + ("audit_keys", "encrypted_audit_records"))
        before_database = vault.read_bytes()
        crud = [binary, "human-password-crud", "--profile", human_profile, "--private", human_key, "--socket", human_socket]
        payload = wire_fields([password, b"PM28 synthetic title", b"PM28 synthetic account", CANARY, b"https://pm28.invalid", b"PM28 synthetic note", b"PM28 synthetic edited", CANARY + b"_EDITED"])
        result = as_uid(HUMAN, crud, input=payload, check=False)
        assert CANARY not in result.stdout and CANARY not in result.stderr
        pause_owned(daemon)
        required = {server_key, server_pub, bootstrap, vault, pathlib.Path(str(vault) + ".audit-custody"), events, pid_path}
        sidecars = {pathlib.Path(str(vault) + suffix) for suffix in ("-wal", "-shm", "-journal")}
        inventory = sorted(state.rglob("*"))
        assert required <= set(inventory) <= required | sidecars, "unclassified/missing owned storage channel"
        assert all(stat.S_ISREG(path.lstat().st_mode) for path in inventory), "non-regular owned storage channel"
        # Quiescent full-file scan with overlap; no truncation, skips or sidecar race.
        scanned = 0
        for path in inventory:
            expected_size = path.stat().st_size
            total, previous = 0, b""
            with path.open("rb") as stream:
                while block := stream.read(1024 * 1024):
                    assert CANARY not in previous + block, "canary in owned storage"
                    total += len(block)
                    previous = block[-(len(CANARY) - 1):]
            assert total == expected_size == path.stat().st_size, "incomplete storage scan"
            scanned += 1
        rows = events.read_text().splitlines()
        assert rows, "SQLite never reached the real WAL sync syscall"
        parsed = [re.fullmatch(r"pid=(\d+) op=(fsync|fdatasync) count=(\d+) injected=([01])", row) for row in rows]
        assert all(parsed), "invalid syscall observation"
        assert all(int(row[1]) == daemon.pid for row in parsed)
        assert [int(row[3]) for row in parsed] == list(range(1, len(rows) + 1))
        injected = sum(int(row[4]) for row in parsed)
        assert injected == int(fault), "fault count was not exact"
        stop_owned(daemon)
        daemon = None
        if fault:
            assert result.returncode == 4 and result.stdout == b"" and result.stderr == b"CUSTODY_UNAVAILABLE\n", "failed SQLite sync admitted the request"
            assert counts(vault, ATOMIC_TABLES + ("audit_keys", "encrypted_audit_records")) == baseline, "partial commit after SQLite sync failure"
            assert counts(vault, STAGING_TABLES) == (0, 0)
            assert vault.read_bytes() == before_database, "authority/database changed after rejected admission"
        else:
            assert result.returncode == 0, "positive public CRUD control failed"
            assert counts(vault, ("human_receipts",))[0] > 0
        database = sqlite3.connect(vault)
        try:
            assert database.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        finally:
            database.close()
        daemon = start_as(CUSTODIAN, serve)
        wait_for_sockets(daemon, [agent_socket, human_socket])
        stop_owned(daemon)
        daemon = None
        print("PM28_SQLITE_SYNC_OBSERVED fault=" + str(int(fault)) + " injected=" + str(injected) + " first-op=" + parsed[0][2] + " calls=" + str(len(rows)) + " client-rc=" + str(result.returncode) + " scanned=" + str(scanned) + " restart=1", flush=True)
    finally:
        primary = sys.exception()
        errors = []
        if daemon is not None:
            try:
                stop_owned(daemon)
            except BaseException as error:
                errors.append(error)
        try:
            shutil.rmtree(root)
            assert not root.exists()
        except BaseException as error:
            errors.append(error)
        print("PM28_SQLITE_SYNC_CLEANUP errors=" + str(len(errors)), flush=True)
        if errors:
            if primary is not None:
                errors.insert(0, primary)
            raise ExceptionGroup("sqlite sync fixture failures", errors)


def main():
    assert os.geteuid() == 0 and len(sys.argv) == 4
    binary, cli, interposer = (pathlib.Path(value).resolve(strict=True) for value in sys.argv[1:])
    run_case(binary, cli, interposer, False)
    print("PM28_SQLITE_SYNC_CONTROL_READY", flush=True)
    run_case(binary, cli, interposer, True)
    print("PASS sqlite-sync first-wal-sync=EIO admission=closed atomic=rollback storage-canary=absent restart=same-vault", flush=True)

if __name__ == "__main__":
    main()
