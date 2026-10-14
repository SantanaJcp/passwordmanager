#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Private multi-UID, real PTY proof; explicit binaries, no desktop/clipboard."""

import fcntl
import hashlib
import json
import os
import pathlib
import pty
import re
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import termios
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "pm-custody/tests"))
from linux_lab import as_uid, create_vault, start_as, stop, wait_for_sockets, wire_fields


class Terminal:
    def __init__(self, command, uid):
        self.master, self.slave = pty.openpty()
        os.fchown(self.slave, uid, uid)
        os.fchmod(self.slave, 0o600)
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        self.before = termios.tcgetattr(self.slave)
        self.raw = bytearray()
        self.observed = []

        def identity():
            os.setsid()
            fcntl.ioctl(self.slave, termios.TIOCSCTTY, 0)
            os.setgroups([])
            os.setgid(uid)
            os.setuid(uid)

        self.process = subprocess.Popen(command, stdin=self.slave, stdout=self.slave,
            stderr=self.slave, preexec_fn=identity, env={**os.environ, "TERM": "xterm"})

    def drain(self):
        while select.select([self.master], [], [], 0.05)[0]:
            self.raw.extend(os.read(self.master, 8192))
            assert len(self.raw) <= 262144, "bounded PTY capture exceeded"

    def wait(self, text):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            self.drain()
            page = self.screen()
            if text in page:
                self.observed.append(page)
                return
            if self.process.poll() is not None:
                break
        raise AssertionError((text, self.process.poll(), self.screen()))

    def screen(self):
        # Decode actual cursor positioning, including Ratatui's differential
        # repaint. Stripping escapes would invent missing spaces/stale text.
        rows = [[" "] * 80 for _ in range(24)]
        row = column = position = 0
        value = self.raw.decode("utf-8", "replace")
        while position < len(value):
            character = value[position]
            if character == "\x1b":
                sequence = re.match(r"\x1b\[([0-9;?]*)([A-Za-z~])", value[position:])
                if sequence is None:
                    position += 1
                    continue
                params, operation = sequence.groups()
                numbers = [int(part or "0") for part in params.lstrip("?").split(";")]
                if operation in ["H", "f"]:
                    row = (numbers[0] or 1) - 1
                    column = (numbers[1] or 1) - 1 if len(numbers) > 1 else 0
                elif operation == "J" and numbers[0] == 2:
                    rows = [[" "] * 80 for _ in range(24)]
                elif operation == "K" and 0 <= row < 24:
                    for at in range(max(column, 0), 80):
                        rows[row][at] = " "
                position += len(sequence.group())
                continue
            if character == "\r":
                column = 0
            elif character == "\n":
                row += 1
            elif character >= " ":
                if 0 <= row < 24 and 0 <= column < 80:
                    rows[row][column] = character
                column += 1
            position += 1
        return "\n".join("".join(line).rstrip() for line in rows)

    def send(self, value):
        os.write(self.master, value)

    def finish(self, expected):
        self.process.wait(timeout=10)
        self.drain()
        assert self.process.returncode == expected, (expected, bytes(self.raw[-2048:]))
        assert termios.tcgetattr(self.slave) == self.before, "terminal attributes not restored"
        if b"\x1b[?1049h" in self.raw:
            assert b"\x1b[?1049l" in self.raw and b"\x1b[?25h" in self.raw

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=5)
        os.close(self.master)
        os.close(self.slave)


def main():
    assert os.geteuid() == 0 and len(sys.argv) == 4, "run inside disposable multi-UID namespace"
    mapping = pathlib.Path("/proc/self/uid_map").read_text().splitlines()
    assert any(int(parts[0]) == 0 and int(parts[1]) != 0 and int(parts[2]) == 1
        for parts in [line.split() for line in mapping]), mapping
    subprocess.run(["/usr/bin/mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["/usr/bin/mount", "-t", "devpts", "-o",
        "newinstance,ptmxmode=0666,mode=0600", "devpts", "/dev/pts"], check=True)
    source_custody, source_cli, evidence = map(lambda p: pathlib.Path(p).resolve(), sys.argv[1:])
    evidence.mkdir(parents=True, exist_ok=False)
    root = pathlib.Path(tempfile.mkdtemp(prefix="pm-chef-human-"))
    ledger = {"root": str(root), "synthetic_only": True, "desktop": False,
              "clipboard": False, "daemon_stopped": False, "ptys_closed": False}
    ledger["binary_sha256"] = {str(binary): hashlib.sha256(binary.read_bytes()).hexdigest()
        for binary in [source_custody, source_cli]}
    daemon = None
    terminals = []
    try:
        root.chmod(0o711)
        custody, cli = root / "pm-custody", root / "pm"
        for source, destination in [(source_custody, custody), (source_cli, cli)]:
            shutil.copyfile(source, destination)
            destination.chmod(0o755)
        for name, uid, mode in [("state", 1, 0o700), ("run", 1, 0o755),
                ("human", 0, 0o755), ("agent", 3, 0o755), ("profiles", 0, 0o755)]:
            path = root / name
            path.mkdir()
            os.chown(path, uid, uid)
            path.chmod(mode)
        keys = {}
        for name, uid in [("state", 1), ("human", 0), ("agent", 3)]:
            private, public = root / name / "key", root / name / "public"
            as_uid(uid, [custody, "keygen", "--private", private, "--public", public])
            keys[name] = (private, public)
        bootstrap = root / "state/bootstrap"
        as_uid(1, [custody, "provision-bootstrap", "--path", bootstrap,
            "--server-private", keys["state"][0], "--server-public", keys["state"][1],
            "--agent-public", keys["agent"][1], "--agent-uid", "3",
            "--human-public", keys["human"][1], "--human-uid", "0"])
        profiles = {}
        for role in ["human", "agent"]:
            path = root / "profiles" / role
            as_uid(0, [custody, "provision-profile", "--path", path,
                "--server-public", keys["state"][1], "--server-uid", "1", "--role", role])
            profiles[role] = path
        vault = root / "state/vault"
        password = create_vault(cli, vault)
        human_socket, agent_socket = root / "run/human.sock", root / "run/agent.sock"
        daemon = start_as(1, [custody, "serve-vault", "--bootstrap", bootstrap,
            "--agent-socket", agent_socket, "--human-socket", human_socket,
            "--vault", vault, "--device", "14" * 16])
        wait_for_sockets(daemon, [agent_socket, human_socket])
        second_private, second_public = root / "agent/second-key", root / "agent/second-public"
        as_uid(3, [custody, "keygen", "--private", second_private, "--public", second_public])
        authorization = as_uid(0, [custody, "human-authorization", "--profile", profiles["human"],
            "--private", keys["human"][0], "--socket", human_socket, "--action", "setup"],
            input=wire_fields([password, keys["agent"][1].read_bytes(), second_public.read_bytes()]))
        assert authorization.stdout.startswith(b"PASS") and not authorization.stderr
        seeded = as_uid(0, [custody, "human-content-flow", "--profile", profiles["human"],
            "--private", keys["human"][0], "--socket", human_socket], input=wire_fields([password]))
        assert seeded.stdout.startswith(b"PASS content-e2e types=7") and not seeded.stderr

        def command(profile, key, socket=human_socket):
            return [cli, "tui", "--profile", profile, "--private", key, "--socket", socket,
                "--idle-seconds", "30", "--reveal-seconds", "1", "--copy-seconds", "2"]

        def delegated():
            outputs = []
            for arguments, expected in [(["capabilities"], 0), (["credentials", "list"], 0),
                    (["auth", "status", "--attempt-id", "ff" * 16], 4),
                    (["auth", "cancel", "--attempt-id", "ff" * 16], 4)]:
                result = as_uid(3, [cli, *arguments, "--json", "--profile", profiles["agent"],
                    "--private", keys["agent"][0], "--socket", agent_socket], check=False)
                assert result.returncode == expected, (arguments, result.stdout, result.stderr)
                document = json.loads(result.stdout)
                if expected == 0:
                    assert "result" in document and not result.stderr
                else:
                    assert "error" in document and b"NOT_FOUND" in result.stdout
                    assert result.stderr == b"error: CUSTODY_UNAVAILABLE\n"
                assert b"ticket07-secret-canary" not in result.stdout
                outputs.append(result.stdout)
            return outputs

        delegated_before = delegated()
        machine = as_uid(0, [*command(profiles["human"], keys["human"][0]), "--json"], check=False)
        assert machine.returncode == 3 and machine.stdout == b""
        assert machine.stderr == b"error: UNAUTHORIZED\n"

        human = Terminal(command(profiles["human"], keys["human"][0]), 0)
        terminals.append(human)
        human.wait("Password required")  # Exact pre-fix RED: exit 3 UNAUTHORIZED.
        human.send(password + b"\r")
        human.wait("Unlocked: selection never reveals secrets")
        human.send(b"/")
        human.wait("Search (engine-decrypted):")
        human.send(b"Password")
        human.wait("Input: Password")
        human.send(b"\r")
        human.wait("Search returned 1 active items")
        human.send(b"t")
        human.wait("Tag (replaces tags):")
        human.send(b"chef-human-entry")
        human.wait("Input: chef-human-entry")
        human.send(b"\r")
        human.wait("Organization committed")
        human.send(b"l")
        human.finish(0)
        assert password not in human.raw and b"ticket05-e2e-password-canary" not in human.raw
        (evidence / "human.vt").write_bytes(human.raw)
        (evidence / "human-screens.txt").write_text("\n\n".join(human.observed) + "\n")
        assert delegated() == delegated_before, "human TUI altered delegated wire behavior"

        # A genuine agent has a TTY and its own profile/key. No human authority.
        agent = Terminal(command(profiles["agent"], keys["agent"][0]), 3)
        terminals.append(agent)
        agent.finish(4)
        assert b"Password required" not in agent.raw and b"CUSTODY_UNAVAILABLE" in agent.raw
        # Even a public human profile cannot elevate the agent's native UID/key.
        crossed = Terminal(command(profiles["human"], keys["agent"][0]), 3)
        terminals.append(crossed)
        crossed.wait("Password required")
        crossed.send(password + b"\r")
        crossed.finish(4)
        assert b"Unlocked: selection" not in crossed.raw
        # Human UID with an agent key also fails RPK authentication.
        wrong_key = root / "human/wrong-key"
        shutil.copyfile(keys["agent"][0], wrong_key)
        wrong_key.chmod(0o400)
        rpk = Terminal(command(profiles["human"], wrong_key), 0)
        terminals.append(rpk)
        rpk.wait("Password required")
        rpk.send(password + b"\r")
        rpk.finish(4)
        assert b"Unlocked: selection" not in rpk.raw
        # Wrong native server UID and wrong server RPK independently fail closed.
        for name, server_uid, server_public in [
                ("wrong-peer", "4", keys["state"][1]),
                ("wrong-pin", "1", keys["human"][1])]:
            path = root / "profiles" / name
            as_uid(0, [custody, "provision-profile", "--path", path,
                "--server-public", server_public, "--server-uid", server_uid, "--role", "human"])
            terminal = Terminal(command(path, keys["human"][0]), 0)
            terminals.append(terminal)
            terminal.wait("Password required")
            terminal.send(password + b"\r")
            terminal.finish(4)
            assert b"Unlocked: selection" not in terminal.raw
        # Missing input fails before UI; endpoint failure restores the UI.
        for profile, key in [(root / "missing", keys["human"][0]),
                (profiles["human"], root / "missing")]:
            result = as_uid(0, command(profile, key), check=False)
            assert result.returncode == 4 and result.stdout == b""
        absent = Terminal(command(profiles["human"], keys["human"][0], root / "missing.sock"), 0)
        terminals.append(absent)
        absent.wait("Password required")
        absent.send(password + b"\r")
        absent.finish(4)
        assert b"Unlocked: selection" not in absent.raw
        ledger["behavior_complete"] = True
    finally:
        for index, terminal in enumerate(terminals):
            (evidence / f"terminal-{index}.vt").write_bytes(terminal.raw)
            terminal.close()
        ledger["ptys_closed"] = True
        if daemon is not None:
            stop(daemon)
            ledger["daemon_stopped"] = True
        # Retain only our explicitly created synthetic tree, never delete shared files.
        ledger["retained_at"] = str(root)
        (evidence / "resources.json").write_text(json.dumps(ledger, indent=2) + "\n")
    print("PASS public pm tui: password + native unlock + search + organization commit + lock/exit + terminal restoration")
    print("PASS negatives: real agent TTY/profile/key + crossed native UID + wrong client RPK + wrong server UID/RPK + missing profile/key/endpoint; no unlocked human session")
    print("PASS resources: private devpts/PTYs closed + custodian stopped; synthetic files retained in ledger")
    print("PASS delegated native CLI before/after: capabilities + discovery + absent attempt status/cancel; exact JSON/exit unchanged")


if __name__ == "__main__":
    for variable in ["WAYLAND_DISPLAY", "DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"]:
        os.environ.pop(variable, None)
    main()
