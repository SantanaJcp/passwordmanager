#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Ticket-21 backup, plaintext export and restore over human TLS/RPK."""

import base64
import hashlib
import json
import os
import pathlib
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile

from linux_lab import as_uid, create_vault, expect_unavailable, start_as, stop, wait_for_sockets, wire_fields

CUSTODIAN, HUMAN, AGENT = 1, 2, 3
DEVICE = "21212121212121212121212121212121"


def start(binary, bootstrap, runtime, vault):
    for socket in (runtime / "agent.sock", runtime / "human.sock"):
        socket.unlink(missing_ok=True)
    daemon = start_as(CUSTODIAN, [binary, "serve-vault", "--bootstrap", bootstrap,
        "--agent-socket", runtime / "agent.sock", "--human-socket", runtime / "human.sock",
        "--vault", vault, "--device", DEVICE])
    wait_for_sockets(daemon, [runtime / "agent.sock", runtime / "human.sock"])
    return daemon


def human(binary, command, key, profile, socket, password, extra=(), ok=True):
    result = as_uid(HUMAN, [binary, command, "--profile", profile, "--private", key,
        "--socket", socket, *extra], input=wire_fields([password]), check=False)
    if not ok:
        expect_unavailable(result)
        return b""
    assert result.returncode == 0 and result.stderr == b"", result
    assert b"tls-rpk=1 alpn=pm-human/1" in result.stdout, result.stdout
    return result.stdout


def counts(path):
    db = sqlite3.connect(path)
    result = tuple(db.execute(f"select count(*) from {table}").fetchone()[0] for table in (
        "vault_items", "revision_parts", "attachment_streams", "attachment_stream_chunks",
        "authority_events", "outbox", "human_receipts", "encrypted_audit_records",
        "credential_authorizations", "agent_authorizations", "authentication_attempts",
        "imported_backup_history", "backup_restore_batches"))
    db.close()
    return result


def assert_only_human_unlock_changed(before, after, unlocks):
    assert after[:7] == before[:7], (before, after)
    assert after[7] == before[7] + unlocks, (before, after)
    assert after[8:] == before[8:], (before, after)


def digest(path):
    state = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(65536):
            state.update(chunk)
    return state.digest()


def main():
    assert os.geteuid() == 0 and len(sys.argv) == 3
    source_binary, source_cli = (pathlib.Path(value).resolve() for value in sys.argv[1:])
    root = pathlib.Path(tempfile.mkdtemp(prefix="pm-backup-linux-lab-"))
    daemon = None
    try:
        root.chmod(0o711)
        binary, cli = root / "pm-custody", root / "pm"
        shutil.copyfile(source_binary, binary); shutil.copyfile(source_cli, cli)
        binary.chmod(0o755); cli.chmod(0o755)
        state, runtime, human_home, agent_home, profiles = [root / name for name in
            ("state", "run", "human", "agent", "profiles")]
        for path, uid, mode in ((state,CUSTODIAN,0o700),(runtime,CUSTODIAN,0o755),
            (human_home,HUMAN,0o755),(agent_home,AGENT,0o755),(profiles,0,0o755)):
            path.mkdir(); os.chown(path, uid, uid); path.chmod(mode)
        server_key, server_pub = state/"server.key", state/"server.pub"
        human_key, human_pub = human_home/"human.key", human_home/"human.pub"
        agent_key, agent_pub = agent_home/"agent.key", agent_home/"agent.pub"
        for uid, private, public in ((CUSTODIAN,server_key,server_pub),(HUMAN,human_key,human_pub),
            (AGENT,agent_key,agent_pub)):
            as_uid(uid, [binary,"keygen","--private",private,"--public",public])
        bootstrap = state/"bootstrap"
        as_uid(CUSTODIAN, [binary,"provision-bootstrap","--path",bootstrap,
            "--server-private",server_key,"--server-public",server_pub,
            "--agent-public",agent_pub,"--agent-uid",str(AGENT),
            "--human-public",human_pub,"--human-uid",str(HUMAN)])
        human_profile, agent_profile = profiles/"human.profile", profiles/"agent.profile"
        for profile, role in ((human_profile,"human"),(agent_profile,"agent")):
            subprocess.run([binary,"provision-profile","--path",profile,"--server-public",server_pub,
                "--server-uid",str(CUSTODIAN),"--role",role], check=True, capture_output=True)
        vault = state/"vault.sqlite3"; password = create_vault(cli, vault)
        output = human_home/"exports"; output.mkdir(); os.chown(output,HUMAN,HUMAN); output.chmod(0o700)
        daemon = start(binary, bootstrap, runtime, vault)
        observed = human(binary, "human-backup-exercise", human_key, human_profile,
            runtime/"human.sock", password, ("--output-dir", output))
        assert observed.startswith(b"PASS backup-exercise types=7 records=8 "), observed
        assert b"inventory=exact" in observed and b"confirmation=strong+one-use" in observed
        native, plaintext = output/"ticket21-backup.pmb1", output/"ticket21-export.jsonl"
        assert native.read_bytes()[:4] == b"PMB1"
        assert plaintext.read_bytes().startswith(b"PM-LOGICAL-JSONL/1\n")
        for artifact in (native, plaintext):
            metadata = artifact.stat()
            assert metadata.st_uid == HUMAN
            assert stat.S_IMODE(metadata.st_mode) == 0o600
        assert native.stat().st_size > 2 * 1024 * 1024
        decoded = b"".join(base64.b64decode(json.loads(line)["payload"])
            for line in plaintext.read_text().splitlines()[2:-1])
        assert b"ticket21-stream-note-canary" in decoded
        assert b"ticket21-stream-note-canary" not in plaintext.read_bytes()
        durable = counts(vault)
        assert durable[0] == 18 and durable[1] == 20, durable
        assert durable[8:11] == (0, 0, 0)
        assert durable[11] > 0 and durable[12] == 0

        original_hash = digest(native)
        corrupt = output/"corrupt.pmb1"; data = bytearray(native.read_bytes()); data[len(data)//2] ^= 1
        corrupt.write_bytes(data); os.chown(corrupt,HUMAN,HUMAN); corrupt.chmod(0o600)
        truncated = output/"truncated.pmb1"; truncated.write_bytes(data[:len(data)//3])
        os.chown(truncated,HUMAN,HUMAN); truncated.chmod(0o600)
        before = counts(vault)
        for unlocks, invalid in enumerate((corrupt, truncated), start=1):
            human(binary, "human-backup-restore", human_key, human_profile,
                runtime/"human.sock", password, ("--archive",invalid), ok=False)
            assert_only_human_unlock_changed(before, counts(vault), unlocks)
        assert digest(native) == original_hash
        agent_denied = as_uid(AGENT, [binary,"human-backup-restore","--profile",agent_profile,
            "--private",agent_key,"--socket",runtime/"agent.sock","--archive",native],
            input=wire_fields([password]), check=False)
        expect_unavailable(agent_denied)
        stop(daemon); daemon = None
        for path in state.iterdir():
            if path.is_file():
                raw = path.read_bytes()
                assert b"ticket21-stream-note-canary" not in raw
        print("PASS backup-e2e tls=rpk+alpn/pm-human/1 native=PMB1/PMF1 plaintext=confirmed "
            "streaming=>2MiB inventory=exact history+trash=roundtrip authority=historical-only "
            "private-keys+grants+attempts=excluded corrupt+truncated=atomic source=immutable "
            "permissions=0600 role=human-only raw-canaries=absent")
    finally:
        if daemon is not None and daemon.poll() is None: stop(daemon)
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
