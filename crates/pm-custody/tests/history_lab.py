#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Ticket-18 history/trash/purge through the real human TLS/RPK service."""

import os
import pathlib
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile

from linux_lab import (
    as_uid,
    create_vault,
    expect_unavailable,
    start_as,
    stop,
    wait_for_sockets,
    wire_fields,
)

CUSTODIAN, HUMAN, AGENT = 1, 2, 3
DEVICE = "18181818181818181818181818181818"


def start(binary, bootstrap, runtime, vault):
    for socket in (runtime / "agent.sock", runtime / "human.sock"):
        socket.unlink(missing_ok=True)
    daemon = start_as(
        CUSTODIAN,
        [
            binary,
            "serve-vault",
            "--bootstrap",
            bootstrap,
            "--agent-socket",
            runtime / "agent.sock",
            "--human-socket",
            runtime / "human.sock",
            "--vault",
            vault,
            "--device",
            DEVICE,
        ],
    )
    wait_for_sockets(daemon, [runtime / "agent.sock", runtime / "human.sock"])
    return daemon


def human(binary, command, key, profile, socket, password, item=None, ok=True):
    argv = [
        binary,
        command,
        "--profile",
        profile,
        "--private",
        key,
        "--socket",
        socket,
    ]
    if item is not None:
        argv += ["--item", item]
    result = as_uid(HUMAN, argv, input=wire_fields([password]), check=False)
    if not ok:
        expect_unavailable(result)
        return b""
    assert result.returncode == 0 and result.stderr == b"", result
    assert b"tls-rpk=1 alpn=pm-human/1" in result.stdout, result.stdout
    return result.stdout


def durable_counts(database):
    tables = (
        "vault_items",
        "revision_parts",
        "attachment_parts",
        "attachment_streams",
        "attachment_stream_chunks",
        "authority_events",
        "outbox",
        "human_receipts",
        "encrypted_audit_records",
        "purged_items",
        "purged_revisions",
    )
    return tuple(database.execute(f"select count(*) from {table}").fetchone()[0] for table in tables)


def main():
    assert os.geteuid() == 0
    assert len(sys.argv) == 3
    source_binary, source_cli = (pathlib.Path(value).resolve() for value in sys.argv[1:])
    root = pathlib.Path(tempfile.mkdtemp(prefix="pm-history-linux-lab-"))
    daemon = None
    try:
        root.chmod(0o711)
        binary, cli = root / "pm-custody", root / "pm"
        shutil.copyfile(source_binary, binary)
        shutil.copyfile(source_cli, cli)
        binary.chmod(0o755)
        cli.chmod(0o755)
        state, runtime, human_home, agent_home, profiles = [
            root / name for name in ("state", "run", "human", "agent", "profiles")
        ]
        for path, uid, mode in (
            (state, CUSTODIAN, 0o700),
            (runtime, CUSTODIAN, 0o755),
            (human_home, HUMAN, 0o755),
            (agent_home, AGENT, 0o755),
            (profiles, 0, 0o755),
        ):
            path.mkdir()
            os.chown(path, uid, uid)
            path.chmod(mode)

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
        as_uid(
            CUSTODIAN,
            [
                binary,
                "provision-bootstrap",
                "--path",
                bootstrap,
                "--server-private",
                server_key,
                "--server-public",
                server_pub,
                "--agent-public",
                agent_pub,
                "--agent-uid",
                str(AGENT),
                "--human-public",
                human_pub,
                "--human-uid",
                str(HUMAN),
            ],
        )
        profile = profiles / "human.profile"
        subprocess.run(
            [
                binary,
                "provision-profile",
                "--path",
                profile,
                "--server-public",
                server_pub,
                "--server-uid",
                str(CUSTODIAN),
                "--role",
                "human",
            ],
            check=True,
            capture_output=True,
        )
        vault = state / "vault.sqlite3"
        password = create_vault(cli, vault)
        daemon = start(binary, bootstrap, runtime, vault)

        exercise = human(
            binary,
            "human-history-exercise",
            human_key,
            profile,
            runtime / "human.sock",
            password,
        )
        assert exercise.startswith(b"PASS history-exercise types=7 "), exercise
        assert b"inline-restored=7" in exercise and b"stream-exact=1" in exercise
        assert b"selective-scopes=7 response-loss=recovered receipts=replayed" in exercise
        match = re.search(rb"purge-target=([0-9a-f]{32})", exercise)
        assert match, exercise
        item_hex = match.group(1).decode()
        item = bytes.fromhex(item_hex)

        stop(daemon)
        daemon = start(binary, bootstrap, runtime, vault)
        listed = human(
            binary,
            "human-history-list",
            human_key,
            profile,
            runtime / "human.sock",
            password,
            item_hex,
        )
        assert b"lifecycle=trash revisions=1" in listed, listed

        database = sqlite3.connect(vault)
        before = durable_counts(database)
        target_before = (
            database.execute("select count(*) from revision_parts where item_id=?", (item,)).fetchone()[0],
            database.execute("select count(*) from authority_events where subject=?", (item,)).fetchone()[0],
        )
        database.execute(
            "create trigger ticket18_fail_public_audit before insert on encrypted_audit_records "
            "begin select raise(abort,'ticket18 audit'); end"
        )
        database.commit()
        database.close()
        human(
            binary,
            "human-history-purge-item",
            human_key,
            profile,
            runtime / "human.sock",
            password,
            item_hex,
            ok=False,
        )
        database = sqlite3.connect(vault)
        assert durable_counts(database) == before
        assert database.execute("select count(*) from revision_parts where item_id=?", (item,)).fetchone() == (target_before[0],)
        assert database.execute("select count(*) from authority_events where subject=?", (item,)).fetchone() == (target_before[1],)
        database.execute("drop trigger ticket18_fail_public_audit")
        database.commit()
        database.close()

        purged = human(
            binary,
            "human-history-purge-item",
            human_key,
            profile,
            runtime / "human.sock",
            password,
            item_hex,
        )
        assert purged.startswith(b"PASS history-purge-item revisions=1 "), purged
        assert b"terminal=1 response-loss=recovered receipt-replay=1" in purged
        stop(daemon)
        daemon = start(binary, bootstrap, runtime, vault)
        human(
            binary,
            "human-history-list",
            human_key,
            profile,
            runtime / "human.sock",
            password,
            item_hex,
            ok=False,
        )
        stop(daemon)
        daemon = None

        database = sqlite3.connect(vault)
        assert database.execute("select count(*) from purged_items where item_id=?", (item,)).fetchone() == (1,)
        assert database.execute("select count(*) from vault_items where item_id=?", (item,)).fetchone() == (0,)
        assert database.execute("select count(*) from revision_parts where item_id=?", (item,)).fetchone() == (0,)
        assert database.execute("select count(*) from authority_events where subject=?", (item,)).fetchone()[0] == target_before[1] + 1
        assert database.execute("select count(*) from encrypted_audit_records").fetchone()[0] > before[8]
        database.close()
        for path in state.iterdir():
            if path.is_file():
                data = path.read_bytes()
                for canary in (
                    b"ticket18-trash-canary",
                    b"ticket05-e2e-password-canary",
                    b"ticket05-e2e-attachment-canary",
                    b"ticket05-large-stream-canary",
                ):
                    assert canary not in data
        print(
            "PASS history-e2e tls=rpk+alpn/pm-human/1 types=7 inline+stream=exact "
            "restore=new-revision response-loss=recovered restart=trash-durable "
            "scope=signed audit-failure=atomic purge=terminal markers=retained replay=blocked "
            "raw-canaries=absent"
        )
    finally:
        if daemon is not None and daemon.poll() is None:
            stop(daemon)
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
