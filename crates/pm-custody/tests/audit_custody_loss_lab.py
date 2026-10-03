#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""G7 regression: an initialized device must not regenerate lost audit custody."""
import os
import pathlib
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from linux_lab import AGENT, CUSTODIAN, HUMAN, as_uid, create_vault, start_as, wait_for_sockets, wire_fields
from storage_fault_lab import stop_owned
DEVICE = "28282828282828282828282828282828"
CANARY = b"PM28_SYNTHETIC_AUDIT_LOSS_SECRET"

def main():
    assert os.geteuid() == 0 and len(sys.argv) == 3
    source_binary, source_cli = (pathlib.Path(value).resolve(strict=True) for value in sys.argv[1:])
    root = pathlib.Path(tempfile.mkdtemp(prefix="pm28-audit-loss-linux-lab-"))
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
        daemon = start_as(CUSTODIAN, serve)
        wait_for_sockets(daemon, [agent_socket, human_socket])
        crud = [binary, "human-password-crud", "--profile", human_profile,
                "--private", human_key, "--socket", human_socket]
        payload = wire_fields([password, b"PM28 synthetic title", b"PM28 synthetic account",
                               CANARY, b"https://pm28.invalid", b"PM28 synthetic note",
                               b"PM28 synthetic edited", CANARY + b"_EDITED"])
        control = as_uid(HUMAN, crud, input=payload)
        assert control.returncode == 0 and CANARY not in control.stdout and CANARY not in control.stderr
        database = sqlite3.connect(vault)
        try:
            assert database.execute("SELECT count(*) FROM audit_keys").fetchone()[0] > 0
        finally:
            database.close()
        print("PM28_AUDIT_LOSS_INITIALIZED_CONTROL_READY", flush=True)
        stop_owned(daemon)
        daemon = None
        custody = pathlib.Path(str(vault) + ".audit-custody")
        retained = state / "owned-original-audit-custody"
        custody.rename(retained)
        daemon = start_as(CUSTODIAN, serve)
        wait_for_sockets(daemon, [agent_socket, human_socket])
        replacement_created = custody.exists()
        denied = as_uid(HUMAN, crud, input=payload, check=False)
        admission_closed = denied.returncode == 4 and denied.stdout == b"" and denied.stderr == b"CUSTODY_UNAVAILABLE\n"
        assert CANARY not in denied.stdout and CANARY not in denied.stderr
        print("PM28_AUDIT_LOSS_ADMISSION rc=" + str(denied.returncode) + " closed=" + str(int(admission_closed)), flush=True)
        stop_owned(daemon)
        daemon = None
        if replacement_created:
            custody.unlink()
        retained.rename(custody)
        daemon = start_as(CUSTODIAN, serve)
        wait_for_sockets(daemon, [agent_socket, human_socket])
        stop_owned(daemon)
        daemon = None
        print("PM28_AUDIT_LOSS_OBSERVED replacement-created=" + str(int(replacement_created)) + " original-restored=1", flush=True)
        assert not replacement_created, "initialized device regenerated lost audit custody"
        assert admission_closed, "initialized device admitted a request after custody loss"
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
        print("PM28_AUDIT_LOSS_CLEANUP errors=" + str(len(errors)), flush=True)
        if errors:
            if primary is not None:
                errors.insert(0, primary)
            raise ExceptionGroup("audit custody loss fixture failures", errors)
    print("PASS audit-custody-loss", flush=True)

if __name__ == "__main__":
    main()
