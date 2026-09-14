#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Ticket-28 real ENOSPC fault at the public streaming transaction seam."""

import errno
import os
import pathlib
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time

from linux_lab import AGENT, CUSTODIAN, HUMAN, as_uid, create_vault, start_as, wait_for_sockets, wire_fields


DEVICE = "28282828282828282828282828282828"
CANARY = b"ticket05-large-stream-canary"
ATOMIC_TABLES = (
    "vault_items",
    "revision_parts",
    "attachment_streams",
    "attachment_stream_chunks",
    "authority_events",
    "outbox",
    "human_receipts",
)
STAGING_TABLES = ("human_staging_streams", "human_staging_stream_chunks")


def counts(vault, tables):
    database = sqlite3.connect(vault)
    try:
        return tuple(database.execute(f"SELECT count(*) FROM {table}").fetchone()[0] for table in tables)
    finally:
        database.close()


def pause_owned(process, timeout=5):
    assert process.poll() is None, "owned custodian exited before the fault checkpoint"
    process.send_signal(signal.SIGSTOP)
    deadline = time.monotonic() + timeout
    status = pathlib.Path(f"/proc/{process.pid}/status")
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError("owned custodian exited instead of acknowledging SIGSTOP")
        if any(line.startswith("State:\tT") for line in status.read_text().splitlines()):
            return
        time.sleep(0.01)
    raise AssertionError("owned custodian did not acknowledge SIGSTOP before fixture deadline")


def resume_owned(process):
    process.send_signal(signal.SIGCONT)


def fill_until_enospc(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    observed = False
    try:
        block = b"\0" * (1024 * 1024)
        maximum = os.statvfs(path.parent).f_bavail * os.statvfs(path.parent).f_frsize + len(block)
        written = 0
        while written < maximum:
            try:
                count = os.write(descriptor, block[: min(len(block), maximum - written)])
            except OSError as error:
                if error.errno != errno.ENOSPC:
                    raise
                observed = True
                break
            assert count > 0
            written += count
        try:
            os.fsync(descriptor)
        except OSError as error:
            if error.errno != errno.ENOSPC:
                raise
            observed = True
    finally:
        os.close(descriptor)
    available = os.statvfs(path.parent).f_bavail
    assert observed, "fixture did not observe real ENOSPC"
    assert available == 0, ("tmpfs retained writable blocks", available)


def scan_canary(root, excluded):
    for candidate in root.rglob("*"):
        if candidate.is_file() and candidate != excluded:
            with candidate.open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    assert CANARY not in chunk, candidate.name


def stop_owned(process):
    if process.poll() is None:
        process.send_signal(signal.SIGCONT)
        process.send_signal(signal.SIGTERM)
    stdout, stderr = process.communicate(timeout=8)
    assert process.returncode == -signal.SIGTERM, (process.returncode, stdout, stderr)


def main():
    assert os.geteuid() == 0 and len(sys.argv) == 3
    source_binary, source_cli = (pathlib.Path(value).resolve(strict=True) for value in sys.argv[1:])
    root = pathlib.Path(tempfile.mkdtemp(prefix="pm-storage-fault-linux-lab-"))
    state = root / "state"
    mounted = False
    daemon = client = None
    filler = state / "owned-enospc-filler"
    try:
        root.chmod(0o711)
        state.mkdir()
        subprocess.run(
            ["mount", "-t", "tmpfs", "-o", "size=64m,mode=0700,uid=1,gid=1", "tmpfs", state],
            check=True,
            capture_output=True,
        )
        mounted = True
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
        daemon = start_as(CUSTODIAN, serve)
        wait_for_sockets(daemon, [agent_socket, human_socket])
        before = counts(vault, ATOMIC_TABLES)
        audit_before = counts(vault, ("encrypted_audit_records",))[0]
        wal = pathlib.Path(f"{vault}-wal")
        wal_before = wal.stat().st_size if wal.exists() else 0
        client = start_as(HUMAN, [
            binary, "human-streaming-file", "--profile", human_profile,
            "--private", human_key, "--socket", human_socket,
        ], stdin=subprocess.PIPE)
        client.stdin.write(wire_fields([password]))
        client.stdin.close()
        client.stdin = None
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if client.poll() is not None:
                raise AssertionError(("stream client exited before WAL checkpoint", client.returncode))
            if wal.exists() and wal.stat().st_size >= wal_before + 1024 * 1024:
                break
            time.sleep(0.01)
        else:
            raise AssertionError("WAL did not grow by 1 MiB before fixture deadline")
        pause_owned(daemon)
        fill_until_enospc(filler)
        resume_owned(daemon)
        stdout, stderr = client.communicate(timeout=30)
        client = None
        assert stdout == b"" and CANARY not in stderr
        assert stderr == b"CUSTODY_UNAVAILABLE\n", stderr

        pause_owned(daemon)
        scan_canary(state, filler)
        filler.unlink()
        resume_owned(daemon)
        stop_owned(daemon)
        daemon = None

        database = sqlite3.connect(vault)
        try:
            assert database.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        finally:
            database.close()
        assert counts(vault, ATOMIC_TABLES) == before
        assert counts(vault, STAGING_TABLES) == (0, 0)
        assert counts(vault, ("encrypted_audit_records",))[0] == audit_before + 1
        daemon = start_as(CUSTODIAN, serve)
        wait_for_sockets(daemon, [agent_socket, human_socket])
        stop_owned(daemon)
        daemon = None
    finally:
        primary = sys.exception()
        cleanup_errors = []
        if client is not None:
            try:
                if client.poll() is None:
                    client.kill()
                client.communicate(timeout=8)
            except BaseException as error:
                cleanup_errors.append(error)
        if daemon is not None:
            try:
                stop_owned(daemon)
            except BaseException as error:
                cleanup_errors.append(error)
        if filler.exists():
            try:
                filler.unlink()
            except BaseException as error:
                cleanup_errors.append(error)
        if mounted:
            try:
                subprocess.run(["umount", state], check=True, capture_output=True)
            except BaseException as error:
                cleanup_errors.append(error)
        try:
            shutil.rmtree(root)
        except BaseException as error:
            cleanup_errors.append(error)
        if cleanup_errors:
            if primary is not None:
                cleanup_errors.insert(0, primary)
            raise ExceptionGroup("storage fault lab failures", cleanup_errors)
    print(
        "PASS storage-fault enospc=real wal-checkpoint=>1MiB atomic=rollback "
        "audit=human-unlock-only canary=absent restart=same-vault cleanup=verified"
    )


if __name__ == "__main__":
    main()
