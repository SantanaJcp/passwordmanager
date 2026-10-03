#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""W4 ordinary-daemon concurrency through real UID/RPK/TUI connections."""

import os
import pathlib
import select
import shutil
import subprocess
import sys
import tempfile

os.environ["PM_TMUX_SERVER"] = f"pmw4-concurrency-{os.getpid()}"

from linux_lab import as_uid, create_vault, expect_unavailable, start_as, wait_for_sockets
from tui_content_lab import screen, send, start_tui, wait_text
from tui_access_lab import (
    AGENT_A, AGENT_B, AGENT_C, CUSTODIAN, HUMAN, LAB_PARENT, LAB_PREFIX,
    PROVIDER, authorization, close_tui, discover, finish_owned_resources, provision,
)

DEVICE = "44444444444444444444444444444444"


def hold_connections(socket_path, count):
    # Kernel UID is switched by start_as before opening sockets. No claimed
    # identity is sent to the service; these connections intentionally stop
    # before TLS and exercise admission during an incomplete handshake.
    code = """
import socket, sys
connections = []
for _ in range(int(sys.argv[2])):
    stream = socket.socket(socket.AF_UNIX)
    stream.connect(sys.argv[1])
    connections.append(stream)
print('READY', flush=True)
sys.stdin.buffer.read(1)
for stream in connections:
    stream.close()
"""
    process = start_as(AGENT_A, [sys.executable, "-c", code, socket_path, str(count)],
                       stdin=subprocess.PIPE)
    readable, _, _ = select.select([process.stdout], [], [], 10)
    assert readable and process.stdout.readline() == b"READY\n"
    return process


def release(process):
    output, error = process.communicate(b"x", timeout=5)
    assert process.returncode == 0 and output == b"" and error == b"", (output, error)


def main():
    assert os.geteuid() == 0 and len(sys.argv) in (3, 4)
    mode = sys.argv[3] if len(sys.argv) == 4 else "concurrency"
    assert mode in ("concurrency", "multiagent")
    source_binary, source_cli = (pathlib.Path(value).resolve() for value in sys.argv[1:3])
    root = pathlib.Path(tempfile.mkdtemp(prefix=LAB_PREFIX, dir=LAB_PARENT))
    daemon = held = None
    try:
        root.chmod(0o711)
        binary, cli = root / "pm-custody", root / "pm"
        shutil.copyfile(source_binary, binary); binary.chmod(0o755)
        shutil.copyfile(source_cli, cli); cli.chmod(0o755)
        directories = [("state", CUSTODIAN, 0o700), ("run", CUSTODIAN, 0o755),
                       ("human", HUMAN, 0o755), ("profiles", HUMAN, 0o755),
                       ("provider", PROVIDER, 0o755),
                       *[(f"agent-{uid}", uid, 0o755) for uid in (AGENT_A, AGENT_B, AGENT_C)]]
        for name, uid, mode_bits in directories:
            path = root / name
            path.mkdir(); os.chown(path, uid, uid); path.chmod(mode_bits)
        state, runtime = root / "state", root / "run"
        server_key, server_public = state / "server.key", state / "server.pub"
        human_key, human_public = root / "human/human.key", root / "human/human.pub"
        a_key, a_public = root / "agent-3/agent.key", root / "agent-3/agent.pub"
        b_key, b_public = root / "agent-4/agent.key", root / "agent-4/agent.pub"
        for uid, private, public in [(CUSTODIAN, server_key, server_public),
                (HUMAN, human_key, human_public), (AGENT_A, a_key, a_public),
                (AGENT_B, b_key, b_public)]:
            as_uid(uid, [binary, "keygen", "--private", private, "--public", public])
        bootstrap = state / "bootstrap"
        provision(binary, bootstrap, server_key, server_public, a_public, AGENT_A, human_public)
        agent_profile, human_profile = root / "profiles/agent.profile", root / "profiles/human.profile"
        for role, profile in (("agent", agent_profile), ("human", human_profile)):
            as_uid(HUMAN, [binary, "provision-profile", "--path", profile,
                          "--server-public", server_public, "--server-uid", str(CUSTODIAN),
                          "--role", role])
        vault = state / "vault.sqlite3"
        password = create_vault(cli, vault)
        daemon = start_as(CUSTODIAN, [binary, "serve-vault", "--bootstrap", bootstrap,
            "--agent-socket", runtime / "agent.sock", "--human-socket", runtime / "human.sock",
            "--vault", vault, "--device", DEVICE])
        wait_for_sockets(daemon, [runtime / "agent.sock", runtime / "human.sock"])
        authorization(binary, human_key, human_profile, runtime / "human.sock", password,
                      "setup", a_public.read_bytes(), b_public.read_bytes())
        baseline = discover(binary, AGENT_A, a_key, agent_profile, runtime / "agent.sock")
        start_tui(root, binary, human_profile, human_key, runtime, password)
        if mode == "multiagent":
            second = discover(binary, AGENT_B, b_key, agent_profile, runtime / "agent.sock")
            assert second == baseline and daemon.poll() is None
        else:
            assert discover(binary, AGENT_A, a_key, agent_profile, runtime / "agent.sock") == baseline
            assert "Unlocked:" in screen(root) and daemon.poll() is None
            print("OBSERVED ordinary-daemon tui=open discovery=served same-pid=1", flush=True)
            held = hold_connections(runtime / "agent.sock", 3)
            assert discover(binary, AGENT_A, a_key, agent_profile, runtime / "agent.sock") == baseline
            release(held); held = None
            # Completion is observed by another real request, not a sleep.
            assert discover(binary, AGENT_A, a_key, agent_profile, runtime / "agent.sock") == baseline
            held = hold_connections(runtime / "agent.sock", 4)
            denied = as_uid(AGENT_A, [binary, "agent-discover", "--profile", agent_profile,
                            "--private", a_key, "--socket", runtime / "agent.sock"], check=False)
            expect_unavailable(denied)
            assert held.poll() is None and daemon.poll() is None
            release(held); held = None
            assert discover(binary, AGENT_A, a_key, agent_profile, runtime / "agent.sock") == baseline
            assert "Unlocked:" in screen(root)
            # close_tui's documented precondition is the delegated-access view.
            send(root, "a"); wait_text(root, "Delegated authority")
            close_tui(root)
    finally:
        try:
            if held is not None:
                release(held)
        finally:
            finish_owned_resources(root, daemon, None)
    if mode == "multiagent":
        print("PASS w4-multiagent daemon=ordinary agents=A+B same-pid=1 cleanup=verified")
    else:
        print("PASS w4-concurrency daemon=ordinary tui=open same-role-agent=concurrent limit=4 cleanup=verified")


if __name__ == "__main__":
    main()
