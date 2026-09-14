#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Ticket-24 real keyboard/PTY delegated-access and pending-attempt lab."""

import json
import os
import pathlib
import re
import shutil
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import time

from linux_lab import as_uid, create_vault, expect_unavailable, start_as, stop, wait_for_sockets, wire_fields

if len(sys.argv) <= 1 or sys.argv[1] != "provider":
    from tui_content_lab import screen, send, start_tui, tmux, wait_text

CUSTODIAN, HUMAN, AGENT_A, AGENT_B, AGENT_C, PROVIDER = 1, 0, 3, 4, 6, 5
DEVICE = "24242424242424242424242424242424"
LAB_PREFIX = "pm-tui-access-linux-lab-"
LAB_PARENT = pathlib.Path("/tmp")


def frame(value):
    return struct.pack(">I", len(value)) + value


def recv_exact(connection, size):
    value = b""
    while len(value) < size:
        part = connection.recv(size - len(value))
        if not part:
            raise EOFError
        value += part
    return value


def recv_frame(connection):
    return recv_exact(connection, struct.unpack(">I", recv_exact(connection, 4))[0])


def field(value):
    return struct.pack(">I", len(value)) + value


def fields(value):
    output, position = [], 0
    while position < len(value):
        size = struct.unpack(">I", value[position:position + 4])[0]
        position += 4
        output.append(value[position:position + size])
        position += size
    return output


def provider(sock):
    pathlib.Path(sock).unlink(missing_ok=True)
    server = socket.socket(socket.AF_UNIX)
    server.bind(sock)
    os.chmod(sock, 0o666)
    server.listen()
    while True:
        connection, _ = server.accept()
        try:
            request = recv_frame(connection)
            assert request[0] in (1, 2)
            if request[0] == 1:
                destination, context, username, password = fields(request[33:])
                assert destination == b"https://ticket07.invalid/login"
                assert username == b"ticket07-user"
                assert password == b"ticket07-secret-canary"
                assert context == b"ticket24-pending-canary"
            connection.sendall(frame(b"\x01" + field(b"ticket24-human-action-required")))
        except (EOFError, BrokenPipeError):
            pass
        finally:
            connection.close()


def provision(binary, path, server_key, server_public, agent_public, agent_uid, human_public):
    as_uid(CUSTODIAN, [binary, "provision-bootstrap", "--path", path,
        "--server-private", server_key, "--server-public", server_public,
        "--agent-public", agent_public, "--agent-uid", str(agent_uid),
        "--human-public", human_public, "--human-uid", str(HUMAN)])


def start(binary, bootstrap, runtime, vault, provider_socket):
    for path in (runtime / "agent.sock", runtime / "human.sock"):
        path.unlink(missing_ok=True)
    daemon = start_as(CUSTODIAN, [binary, "serve-attempt-lab", "--bootstrap", bootstrap,
        "--agent-socket", runtime / "agent.sock", "--human-socket", runtime / "human.sock",
        "--vault", vault, "--device", DEVICE, "--provider-socket", provider_socket,
        "--provider-uid", str(PROVIDER)])
    wait_for_sockets(daemon, [runtime / "agent.sock", runtime / "human.sock"])
    return daemon


def authorization(binary, key, profile, socket_path, password, action, *rpks):
    result = as_uid(HUMAN, [binary, "human-authorization", "--profile", profile,
        "--private", key, "--socket", socket_path, "--action", action],
        input=wire_fields([password, *rpks]), check=False)
    assert result.returncode == 0 and result.stderr == b"", result


def discover(binary, uid, key, profile, socket_path, allowed=True):
    result = as_uid(uid, [binary, "agent-discover", "--profile", profile,
        "--private", key, "--socket", socket_path], check=False)
    if not allowed:
        expect_unavailable(result)
        return None
    assert result.returncode == 0 and result.stderr == b"", result
    text = result.stdout.decode()
    assert "PASS delegated-discovery count=1" in text and "Synthetic TLS shared account" in text, text
    assert "ticket07-secret-canary" not in text
    return text


def discover_empty(binary, uid, key, profile, socket_path):
    result = as_uid(uid, [binary, "agent-discover", "--profile", profile,
        "--private", key, "--socket", socket_path], check=False)
    assert result.returncode == 0 and result.stdout == b"PASS delegated-discovery count=0 set=\n"
    assert result.stderr == b""


def choose(root, marker):
    wait_text(root, "Delegated authority (metadata only)")
    for _ in range(32):
        page = screen(root)
        if any("›" in line and marker in line for line in page.splitlines()):
            return page
        send(root, "j")
        time.sleep(0.08)
    raise AssertionError((marker, screen(root)))


def close_tui(root):
    tmux(root, "send-keys", "Escape")
    wait_text(root, "Content view")
    send(root, "l")
    deadline = time.monotonic() + 5
    while tmux(root, "has-session", check=False).returncode == 0:
        assert time.monotonic() < deadline
        time.sleep(0.05)
    # tmux exits its server asynchronously after the last client; observe the
    # session boundary above, then allow that owned server to finish teardown.
    time.sleep(0.1)


def stop_owned_tmux(root):
    result = tmux(root, "has-session", check=False)
    if result.returncode == 0:
        tmux(root, "kill-server")
        return
    expected = b"no server running on"
    assert result.returncode == 1 and expected in result.stderr, result


def remove_as_owner(path, uid):
    pid = os.fork()
    if pid == 0:
        try:
            os.setgroups([])
            os.setgid(uid)
            os.setuid(uid)
            for entry in path.iterdir():
                if entry.is_symlink() or not entry.is_dir():
                    entry.unlink()
                else:
                    shutil.rmtree(entry)
        except BaseException as error:
            message = f"cleanup failed for {path.name} as uid {uid}: {type(error).__name__}\n"
            os.write(2, message.encode())
            os._exit(1)
        os._exit(0)
    waited, status = os.waitpid(pid, 0)
    assert waited == pid and os.waitstatus_to_exitcode(status) == 0, (path, uid, status)


def cleanup_owned_root(root):
    expected = {
        "state": ("directory", CUSTODIAN),
        "run": ("directory", CUSTODIAN),
        "human": ("directory", HUMAN),
        "profiles": ("directory", HUMAN),
        "provider": ("directory", PROVIDER),
        "agent-3": ("directory", AGENT_A),
        "agent-4": ("directory", AGENT_B),
        "agent-6": ("directory", AGENT_C),
        "pm": ("file", HUMAN),
        "pm-custody": ("file", HUMAN),
        "terminal.raw": ("file", HUMAN),
    }
    parent = LAB_PARENT.resolve(strict=True)
    assert root.parent.resolve(strict=True) == parent and root.name.startswith(LAB_PREFIX), root
    root_stat = root.lstat()
    assert stat.S_ISDIR(root_stat.st_mode) and root_stat.st_uid == HUMAN, root_stat
    children = list(root.iterdir())
    assert all(child.name in expected for child in children), children
    for child in children:
        kind, uid = expected[child.name]
        child_stat = child.lstat()
        if kind == "directory":
            assert stat.S_ISDIR(child_stat.st_mode) and child_stat.st_uid == uid, (child, child_stat)
            remove_as_owner(child, uid)
            child.rmdir()
        else:
            assert stat.S_ISREG(child_stat.st_mode) and child_stat.st_uid == uid, (child, child_stat)
            child.unlink()
    root.rmdir()
    assert not root.exists(), root


def finish_owned_resources(root, daemon, provider_process):
    errors = []
    actions = [("tmux", lambda: stop_owned_tmux(root))]
    if daemon is not None:
        actions.append(("custody", lambda: stop(daemon)))
    if provider_process is not None:
        actions.append(("provider", lambda: stop(provider_process)))
    actions.append(("root", lambda: cleanup_owned_root(root)))
    for name, action in actions:
        try:
            action()
        except BaseException as error:
            error.add_note(f"ticket24 cleanup resource: {name}")
            errors.append(error)
    if errors:
        raise ExceptionGroup("ticket24 cleanup failed", errors)


def agent_start(binary, uid, key, profile, socket_path, item):
    result = as_uid(uid, [binary, "agent-attempt", "--profile", profile, "--private", key,
        "--socket", socket_path, "--action", "start", "--item", item,
        "--issued-at", str(int(time.time() * 1_000_000)), "--nonce", "24" * 16,
        "--context", "ticket24-pending-canary"], check=False)
    assert result.returncode == 0 and result.stderr == b"", result
    match = re.search(r"id=([0-9a-f]{32}).*state=CREATED", result.stdout.decode())
    assert match, result.stdout
    return match.group(1)


def agent_get(binary, uid, key, profile, socket_path, attempt):
    return as_uid(uid, [binary, "agent-attempt", "--profile", profile, "--private", key,
        "--socket", socket_path, "--action", "get", "--attempt", attempt], check=False)


def wait_state(binary, uid, key, profile, socket_path, attempt, wanted):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        result = agent_get(binary, uid, key, profile, socket_path, attempt)
        assert result.returncode == 0 and result.stderr == b"", result
        if f"state={wanted}" in result.stdout.decode():
            return
        time.sleep(0.05)
    raise AssertionError((wanted, result.stdout))


def main():
    assert os.geteuid() == 0 and len(sys.argv) == 3
    source_binary, source_cli = (pathlib.Path(value).resolve() for value in sys.argv[1:])
    root = pathlib.Path(tempfile.mkdtemp(prefix=LAB_PREFIX, dir=LAB_PARENT))
    daemon = provider_process = None
    try:
        root.chmod(0o711)
        binary, cli = root / "pm-custody", root / "pm"
        shutil.copyfile(source_binary, binary); binary.chmod(0o755)
        shutil.copyfile(source_cli, cli); cli.chmod(0o755)
        state, runtime, human_home, profiles, provider_home = [root / value for value in
            ("state", "run", "human", "profiles", "provider")]
        agent_homes = {uid: root / f"agent-{uid}" for uid in (AGENT_A, AGENT_B, AGENT_C)}
        for path, uid, mode in [(state, CUSTODIAN, 0o700), (runtime, CUSTODIAN, 0o755),
                (human_home, HUMAN, 0o755), (profiles, HUMAN, 0o755),
                (provider_home, PROVIDER, 0o755),
                *[(path, uid, 0o755) for uid, path in agent_homes.items()]]:
            path.mkdir(); os.chown(path, uid, uid); path.chmod(mode)
        server_key, server_public = state / "server.key", state / "server.pub"
        human_key, human_public = human_home / "human.key", human_home / "human.pub"
        keys = {}
        for uid, private, public in [(CUSTODIAN, server_key, server_public),
                (HUMAN, human_key, human_public), *[(uid, agent_homes[uid] / "agent.key",
                agent_homes[uid] / "agent.pub") for uid in agent_homes]]:
            as_uid(uid, [binary, "keygen", "--private", private, "--public", public])
            if uid in agent_homes:
                keys[uid] = (private, public)
        bootstraps = {}
        for uid, (_, public) in keys.items():
            bootstraps[uid] = state / f"bootstrap-{uid}"
            provision(binary, bootstraps[uid], server_key, server_public, public, uid, human_public)
        agent_profile, human_profile = profiles / "agent.profile", profiles / "human.profile"
        for role, profile in (("agent", agent_profile), ("human", human_profile)):
            as_uid(HUMAN, [binary, "provision-profile", "--path", profile,
                "--server-public", server_public, "--server-uid", str(CUSTODIAN), "--role", role])
        vault = state / "vault.sqlite3"
        password = create_vault(cli, vault)
        provider_socket = provider_home / "provider.sock"
        provider_script = provider_home / "provider.py"
        shutil.copyfile(__file__, provider_script); os.chown(provider_script, PROVIDER, PROVIDER); provider_script.chmod(0o500)
        helper = provider_home / "linux_lab.py"
        shutil.copyfile(pathlib.Path(__file__).with_name("linux_lab.py"), helper); os.chown(helper, PROVIDER, PROVIDER); helper.chmod(0o400)
        provider_process = start_as(PROVIDER, [sys.executable, provider_script, "provider", provider_socket])
        wait_for_sockets(provider_process, [provider_socket])
        daemon = start(binary, bootstraps[AGENT_A], runtime, vault, provider_socket)
        authorization(binary, human_key, human_profile, runtime / "human.sock", password,
            "setup", keys[AGENT_A][1].read_bytes(), keys[AGENT_B][1].read_bytes())

        # TUI enrollment is a closed request, not a free-form policy editor.
        start_tui(root, binary, human_profile, human_key, runtime, password)
        send(root, "a"); wait_text(root, "Delegated access: RESUMED")
        tmux(root, "resize-window", "-x", "240", "-y", "30")
        send(root, "n"); wait_text(root, "Enroll subject|request|SPKI|label|environment:")
        enrollment = "c3" * 16 + "|" + "24" * 16 + "|" + keys[AGENT_C][1].read_bytes().hex() + "|ticket24-agent-c|linux-lab"
        send(root, enrollment, enter=True)
        wait_text(root, "ticket24-agent-c")
        close_tui(root)
        baseline = discover(binary, AGENT_A, keys[AGENT_A][0], agent_profile, runtime / "agent.sock")

        # Human lock is independent; TUI suspend/resume and common-set changes are immediate.
        start_tui(root, binary, human_profile, human_key, runtime, password)
        send(root, "a"); choose(root, "[credential enabled] Synthetic TLS shared account")
        send(root, "e"); wait_text(root, "[credential disabled] Synthetic TLS shared account")
        close_tui(root)
        discover_empty(binary, AGENT_A, keys[AGENT_A][0], agent_profile, runtime / "agent.sock")
        start_tui(root, binary, human_profile, human_key, runtime, password)
        send(root, "a"); choose(root, "[credential disabled] Synthetic TLS shared account")
        send(root, "e"); wait_text(root, "[credential enabled] Synthetic TLS shared account")
        close_tui(root)
        assert discover(binary, AGENT_A, keys[AGENT_A][0], agent_profile, runtime / "agent.sock") == baseline
        start_tui(root, binary, human_profile, human_key, runtime, password)
        send(root, "a")
        send(root, "s"); wait_text(root, "Delegated access: SUSPENDED")
        close_tui(root)
        discover(binary, AGENT_A, keys[AGENT_A][0], agent_profile, runtime / "agent.sock", allowed=False)
        start_tui(root, binary, human_profile, human_key, runtime, password)
        send(root, "a")
        send(root, "s"); wait_text(root, "Delegated access: RESUMED")
        close_tui(root)
        assert discover(binary, AGENT_A, keys[AGENT_A][0], agent_profile, runtime / "agent.sock") == baseline

        # A real provider challenge appears with safe context and is cancelled from the TUI.
        item = re.search(r"set=([0-9a-f]{32}):", baseline).group(1)
        attempt = agent_start(binary, AGENT_A, keys[AGENT_A][0], agent_profile, runtime / "agent.sock", item)
        wait_state(binary, AGENT_A, keys[AGENT_A][0], agent_profile, runtime / "agent.sock", attempt, "WAITING_FOR_HUMAN")
        start_tui(root, binary, human_profile, human_key, runtime, password)
        tmux(root, "resize-window", "-x", "240", "-y", "30")
        send(root, "w"); page = wait_text(root, attempt[:24])
        assert "ticket24-human-action-required" in page
        assert "ticket24-pending-canary" not in page and "ticket07-secret-canary" not in page
        send(root, "x"); wait_text(root, "Attempt CANCELLED")
        close_tui(root)
        wait_state(binary, AGENT_A, keys[AGENT_A][0], agent_profile, runtime / "agent.sock", attempt, "CANCELLED")
        start_tui(root, binary, human_profile, human_key, runtime, password)
        send(root, "a"); choose(root, "Synthetic agent A")
        send(root, "x"); wait_text(root, "[agent revoked] Synthetic agent A")
        close_tui(root)
        discover(binary, AGENT_A, keys[AGENT_A][0], agent_profile, runtime / "agent.sock", allowed=False)
        stop(daemon); daemon = start(binary, bootstraps[AGENT_B], runtime, vault, provider_socket)
        discover(binary, AGENT_B, keys[AGENT_B][0], agent_profile, runtime / "agent.sock")

        db = sqlite3.connect(vault)
        assert db.execute("select status from agent_authorizations where subject_id=? and generation=1",
            (bytes.fromhex("a1" * 16),)).fetchone() == ("revoked",)
        assert db.execute("select state from authentication_attempts where attempt_id=?",
            (bytes.fromhex(attempt),)).fetchone() == ("cancelled",)
        db.close()
    finally:
        finish_owned_resources(root, daemon, provider_process)
    print("PASS tui-access keyboard=enroll+enable+disable+suspend+resume+revoke agents=2 common-set=same human-lock=independent cleanup=verified")
    print("PASS tui-pending safe-context=1 provider=separate-uid cancel=terminal secrets=absent cleanup=verified")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "provider":
        provider(*sys.argv[2:])
    else:
        main()
