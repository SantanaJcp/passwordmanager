#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Public RED for a failed atomic-download cleanup after a real peer cut."""

import os
import pathlib
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from backup_lab import DEVICE, start
from linux_lab import as_uid, create_vault, wire_fields

CUSTODIAN, HUMAN, AGENT = 1, 2, 3


def run_human(command, password, environment):
    def identity():
        os.setgroups([])
        os.setgid(HUMAN)
        os.setuid(HUMAN)

    return subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        preexec_fn=identity,
    ), wire_fields([password])


def main():
    assert os.geteuid() == 0 and len(sys.argv) == 4
    source_binary, source_cli, interposer_source = (
        pathlib.Path(value).resolve(strict=True) for value in sys.argv[1:]
    )
    root = pathlib.Path(tempfile.mkdtemp(prefix="pm-rpc-cleanup-fault-linux-lab-"))
    daemon = client = None
    try:
        root.chmod(0o711)
        binary, cli, interposer = root / "pm-custody", root / "pm", root / "interposer.so"
        shutil.copyfile(source_binary, binary)
        shutil.copyfile(source_cli, cli)
        binary.chmod(0o755)
        cli.chmod(0o755)
        subprocess.run(
            ["cc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror",
             "-o", interposer, interposer_source, "-ldl"],
            check=True,
        )
        interposer.chmod(0o755)
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
        as_uid(CUSTODIAN, [
            binary, "provision-bootstrap", "--path", bootstrap,
            "--server-private", server_key, "--server-public", server_pub,
            "--agent-public", agent_pub, "--agent-uid", str(AGENT),
            "--human-public", human_pub, "--human-uid", str(HUMAN),
        ])
        profile = profiles / "human.profile"
        subprocess.run([
            binary, "provision-profile", "--path", profile,
            "--server-public", server_pub, "--server-uid", str(CUSTODIAN),
            "--role", "human",
        ], check=True, capture_output=True)
        vault = state / "vault.sqlite3"
        password = create_vault(cli, vault)
        output = human_home / "exports"
        output.mkdir(mode=0o700)
        os.chown(output, HUMAN, HUMAN)
        partial = output / "ticket21-backup.partial"
        final = output / "ticket21-backup.pmb1"
        events = human_home / "rpc.events"
        events.write_bytes(b"")
        os.chown(events, HUMAN, HUMAN)
        daemon = start(binary, bootstrap, runtime, vault)
        environment = {
            "LD_PRELOAD": str(interposer),
            "PM_FAIL_UNLINK_PATH": str(partial),
            "PM_INTERPOSE_LOG": str(events),
        }
        command = [
            binary, "human-backup-exercise", "--profile", profile,
            "--private", human_key, "--socket", runtime / "human.sock",
            "--output-dir", output,
        ]
        client, input_bytes = run_human(command, password, environment)
        client.stdin.write(input_bytes)
        client.stdin.close()
        client.stdin = None
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if client.poll() is not None:
                raise AssertionError(("client finished before peer cut", client.returncode))
            if partial.exists() and partial.stat().st_size > 0:
                break
            time.sleep(0.001)
        else:
            raise AssertionError("download did not publish partial bytes before fixture deadline")
        daemon.send_signal(signal.SIGKILL)
        daemon.communicate(timeout=5)
        daemon = None
        stdout = client.stdout.read()
        stderr = client.stderr.read()
        client.wait(timeout=15)
        client = None
        observed_events = events.read_text().splitlines()
        assert observed_events == ["unlink"], observed_events
        assert partial.is_file() and partial.stat().st_size > 0
        assert not final.exists()
        assert stdout == b"", stdout
        assert stderr == b"CUSTODY_UNAVAILABLE\nCLEANUP_FAILED\n", (
            "rpc_download_atomic cleanup failure was discarded",
            stderr,
        )
        partial.unlink()
        events.unlink()
    finally:
        if client is not None and client.poll() is None:
            client.kill()
            client.communicate(timeout=5)
        if daemon is not None and daemon.poll() is None:
            daemon.kill()
            daemon.communicate(timeout=5)
        shutil.rmtree(root)
    print("PASS cleanup-errors rpc-download=propagated peer-cut=real cleanup=verified")


if __name__ == "__main__":
    main()
