#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

"""Ticket-07 two-RPK authorization lab over the real TLS/ALPN service."""

import pathlib
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile

from linux_lab import as_uid, create_vault, expect_unavailable, start_as, stop, wait_for_sockets, wire_fields

CUSTODIAN, HUMAN, AGENT_A, AGENT_B = 1, 2, 3, 4
DEVICE = "77777777777777777777777777777777"


def provision_bootstrap(binary, path, server_private, server_public, agent_public, agent_uid, human_public):
    as_uid(CUSTODIAN, [binary, "provision-bootstrap", "--path", path,
        "--server-private", server_private, "--server-public", server_public,
        "--agent-public", agent_public, "--agent-uid", str(agent_uid),
        "--human-public", human_public, "--human-uid", str(HUMAN)])
    metadata = path.stat()
    assert metadata.st_uid == CUSTODIAN and stat.S_IMODE(metadata.st_mode) == 0o400


def start(binary, bootstrap, runtime, vault):
    for socket in (runtime / "agent.sock", runtime / "human.sock"):
        socket.unlink(missing_ok=True)
    daemon = start_as(CUSTODIAN, [binary, "serve-vault", "--bootstrap", bootstrap,
        "--agent-socket", runtime / "agent.sock", "--human-socket", runtime / "human.sock",
        "--vault", vault, "--device", DEVICE])
    wait_for_sockets(daemon, [runtime / "agent.sock", runtime / "human.sock"])
    return daemon


def human_action(binary, private, profile, socket, password, action, *rpks):
    result = as_uid(HUMAN, [binary, "human-authorization", "--profile", profile,
        "--private", private, "--socket", socket, "--action", action],
        input=wire_fields([password, *rpks]))
    assert result.stdout == f"PASS human-authorization action={action}\n".encode(), result
    assert result.stderr == b""


def discover(binary, uid, private, profile, socket, *, allowed=True):
    result = as_uid(uid, [binary, "agent-discover", "--profile", profile,
        "--private", private, "--socket", socket], check=False)
    if not allowed:
        expect_unavailable(result)
        return None
    assert result.returncode == 0 and result.stderr == b"", result
    assert result.stdout.startswith(b"PASS delegated-discovery count=1 set="), result.stdout
    assert b"Synthetic TLS shared account" in result.stdout
    assert b"ticket07-user" in result.stdout
    assert b"https://ticket07.invalid/login" in result.stdout
    assert b"ticket07-secret-canary" not in result.stdout
    return result.stdout


def main():
    assert pathlib.Path("/proc/self/uid_map").exists() and len(sys.argv) == 3
    source_binary, source_cli = map(lambda value: pathlib.Path(value).resolve(), sys.argv[1:])
    root = pathlib.Path(tempfile.mkdtemp(prefix="pm-authorization-linux-lab-"))
    try:
        root.chmod(0o711)
        binary, cli = root / "pm-custody", root / "pm"
        shutil.copyfile(source_binary, binary); binary.chmod(0o755)
        shutil.copyfile(source_cli, cli); cli.chmod(0o755)
        state, runtime, human_home = root / "state", root / "run", root / "human"
        agent_a_home, agent_b_home, profiles = root / "agent-a", root / "agent-b", root / "profiles"
        for path, uid, mode in [(state,CUSTODIAN,0o700),(runtime,CUSTODIAN,0o755),
            (human_home,HUMAN,0o755),(agent_a_home,AGENT_A,0o755),(agent_b_home,AGENT_B,0o755),
            (profiles,0,0o755)]:
            path.mkdir(); os.chown(path, uid, uid); path.chmod(mode)

        server_key, server_pub = state / "server.key", state / "server.pub"
        human_key, human_pub = human_home / "human.key", human_home / "human.pub"
        a_key, a_pub = agent_a_home / "a.key", agent_a_home / "a.pub"
        a2_key, a2_pub = agent_a_home / "a2.key", agent_a_home / "a2.pub"
        rogue_key, rogue_pub = agent_a_home / "rogue.key", agent_a_home / "rogue.pub"
        b_key, b_pub = agent_b_home / "b.key", agent_b_home / "b.pub"
        for uid, private, public in [(CUSTODIAN,server_key,server_pub),(HUMAN,human_key,human_pub),
            (AGENT_A,a_key,a_pub),(AGENT_A,a2_key,a2_pub),(AGENT_A,rogue_key,rogue_pub),(AGENT_B,b_key,b_pub)]:
            as_uid(uid, [binary, "keygen", "--private", private, "--public", public])

        boot_a, boot_a2, boot_b, boot_rogue = [state / name for name in
            ("bootstrap-a", "bootstrap-a2", "bootstrap-b", "bootstrap-rogue")]
        for path, public, uid in [(boot_a,a_pub,AGENT_A),(boot_a2,a2_pub,AGENT_A),
            (boot_b,b_pub,AGENT_B),(boot_rogue,rogue_pub,AGENT_A)]:
            provision_bootstrap(binary, path, server_key, server_pub, public, uid, human_pub)
        agent_profile, human_profile = profiles / "agent.profile", profiles / "human.profile"
        for role, profile in [("agent",agent_profile),("human",human_profile)]:
            subprocess.run([binary, "provision-profile", "--path", profile, "--server-public", server_pub,
                "--server-uid", str(CUSTODIAN), "--role", role], check=True, capture_output=True)

        vault = state / "vault.sqlite3"
        password = create_vault(cli, vault)
        daemon = start(binary, boot_a, runtime, vault)
        human_action(binary, human_key, human_profile, runtime / "human.sock", password,
            "setup", a_pub.read_bytes(), b_pub.read_bytes())
        first = discover(binary, AGENT_A, a_key, agent_profile, runtime / "agent.sock")
        stop(daemon)

        daemon = start(binary, boot_b, runtime, vault)
        second = discover(binary, AGENT_B, b_key, agent_profile, runtime / "agent.sock")
        assert first == second
        stop(daemon)
        daemon = start(binary, boot_b, runtime, vault)  # durable restart
        assert discover(binary, AGENT_B, b_key, agent_profile, runtime / "agent.sock") == second
        database = sqlite3.connect(vault)
        before_atomic = tuple(database.execute(f"select count(*) from {table}").fetchone()[0]
            for table in ("authority_events", "outbox", "human_receipts", "encrypted_audit_records"))
        database.execute("create trigger fail_ticket07_public_audit before insert on encrypted_audit_records begin select raise(abort, 'synthetic ticket07 audit failure'); end")
        database.commit(); database.close()
        failed = as_uid(HUMAN, [binary, "human-authorization", "--profile", human_profile,
            "--private", human_key, "--socket", runtime / "human.sock", "--action", "suspend"],
            check=False, input=wire_fields([password]))
        expect_unavailable(failed)
        database = sqlite3.connect(vault)
        after_atomic = tuple(database.execute(f"select count(*) from {table}").fetchone()[0]
            for table in ("authority_events", "outbox", "human_receipts", "encrypted_audit_records"))
        assert after_atomic == before_atomic
        assert database.execute("select count(*) from human_challenges where consumed=1").fetchone() == (6,)
        database.execute("drop trigger fail_ticket07_public_audit"); database.commit(); database.close()
        human_action(binary, human_key, human_profile, runtime / "human.sock", password, "suspend")
        discover(binary, AGENT_B, b_key, agent_profile, runtime / "agent.sock", allowed=False)
        stop(daemon)

        daemon = start(binary, boot_a, runtime, vault)
        discover(binary, AGENT_A, a_key, agent_profile, runtime / "agent.sock", allowed=False)
        human_action(binary, human_key, human_profile, runtime / "human.sock", password, "resume-revoke-a")
        discover(binary, AGENT_A, a_key, agent_profile, runtime / "agent.sock", allowed=False)
        stop(daemon)
        daemon = start(binary, boot_b, runtime, vault)
        assert discover(binary, AGENT_B, b_key, agent_profile, runtime / "agent.sock") == second
        human_action(binary, human_key, human_profile, runtime / "human.sock", password,
            "reenroll-a", a2_pub.read_bytes())
        stop(daemon)

        daemon = start(binary, boot_a, runtime, vault)
        discover(binary, AGENT_A, a_key, agent_profile, runtime / "agent.sock", allowed=False)
        stop(daemon)
        daemon = start(binary, boot_a2, runtime, vault)
        assert discover(binary, AGENT_A, a2_key, agent_profile, runtime / "agent.sock") == second
        stop(daemon)
        daemon = start(binary, boot_rogue, runtime, vault)
        discover(binary, AGENT_A, rogue_key, agent_profile, runtime / "agent.sock", allowed=False)
        stop(daemon)

        database = sqlite3.connect(vault)
        assert database.execute("select count(*) from authority_events").fetchone() == (10,)
        assert database.execute("select count(*) from human_receipts").fetchone() == (10,)
        assert database.execute("select count(*) from outbox").fetchone() == (10,)
        assert database.execute("select group_concat(generation, ',') from (select generation from agent_authorizations where subject_id=? order by generation)", (bytes([0xa1])*16,)).fetchone() == ("1,2",)
        assert database.execute("select status from agent_authorizations where subject_id=? and generation=1", (bytes([0xa1])*16,)).fetchone() == ("revoked",)
        database.close()
        for path in state.iterdir():
            if path.is_file():
                contents = path.read_bytes()
                assert b"Synthetic TLS shared account" not in contents
                assert b"ticket07-secret-canary" not in contents
        print("PASS authorization-e2e rpk-agents=2 same-set=1 human-lock-independent=1 suspend=denied revoke=terminal generation=2 restart=durable")
        print("PASS authorization-path agent=tls1.3+rpk+alpn/pm-agent/1 human=tls1.3+rpk+alpn/pm-human/1 prepare-commit-receipt=replayed audit=atomic")
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
