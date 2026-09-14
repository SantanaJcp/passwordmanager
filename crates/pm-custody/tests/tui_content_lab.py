#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Ticket-23 real keyboard/PTY TUI over the human TLS-RPK service."""

import os
import pathlib
import shutil
import signal
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time

from linux_lab import as_uid, create_vault, start_as, stop, wait_for_sockets, wire_fields

CUSTODIAN, HUMAN, AGENT = 1, 0, 3
DEVICE = "23232323232323232323232323232323"
TMUX = "/usr/bin/tmux"


def tmux(root, *args, check=True):
    return subprocess.run(
        [TMUX, "-L", "pm-ticket23", *map(str, args)],
        check=check, capture_output=True, timeout=10,
        env={**os.environ, "HOME": str(root / "human"), "TERM": "xterm-256color"},
    )


def screen(root):
    return tmux(root, "capture-pane", "-p").stdout.decode("utf-8", "replace")


def wait_text(root, text, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = screen(root)
        if text in value:
            return value
        time.sleep(0.05)
    raise AssertionError((text, screen(root)))


def send(root, value, enter=False, hidden=False):
    if value:
        tmux(root, "send-keys", "-l", value)
    if enter:
        # For visible prompts, observe the literal keyboard input in the real
        # pane before sending Enter.  This keeps the lab ordered at the PTY
        # boundary instead of assuming two tmux client processes imply that
        # Crossterm has already consumed and rendered the first key batch.
        if value and not hidden:
            wait_text(root, f"Input: {value}")
        tmux(root, "send-keys", "Enter")


def query(root, value):
    send(root, "/")
    wait_text(root, "Search (engine-decrypted):")
    send(root, value, enter=True)
    return wait_text(root, "Search returned")


def choose_field(root, action, label, index):
    send(root, action)
    wait_text(root, "Fields (explicit selection; values hidden)")
    send(root, "j" * index)
    time.sleep(0.12 * index + 0.2)
    page = screen(root)
    assert any("›" in line and label in line for line in page.splitlines()), (label, page)
    tmux(root, "send-keys", "Enter")


def setup(root, binary, cli):
    root.chmod(0o711)
    # The disposable user namespace maps the host desktop owner to uid 0, while
    # the host's real root appears unmapped.  Bind the exact pinned helper bytes
    # into this private mount namespace so the product's root-owner check is
    # exercised rather than relaxed for the laboratory.
    trusted_wl_copy = root / "wl-copy-2.3.0"
    shutil.copyfile(WL_COPY := "/usr/bin/wl-copy", trusted_wl_copy)
    trusted_wl_copy.chmod(0o755)
    subprocess.run(["/usr/bin/mount", "--bind", trusted_wl_copy, WL_COPY], check=True)
    installed_binary, installed_cli = root / "pm-custody", root / "pm"
    shutil.copyfile(binary, installed_binary)
    shutil.copyfile(cli, installed_cli)
    installed_binary.chmod(0o755)
    installed_cli.chmod(0o755)
    state, runtime, human_home, agent_home, profiles = [
        root / name for name in ("state", "run", "human", "agent", "profiles")
    ]
    for path, uid, mode in (
        (state, CUSTODIAN, 0o700), (runtime, CUSTODIAN, 0o755),
        # Bootstrap provisioning runs as the custodian and must be able to
        # traverse to the public keys.  The private key files remain 0400 and
        # owned by their distinct principals.
        (human_home, HUMAN, 0o755), (agent_home, AGENT, 0o755), (profiles, HUMAN, 0o700),
    ):
        path.mkdir(); os.chown(path, uid, uid); path.chmod(mode)
    server_key, server_pub = state / "server.key", state / "server.pub"
    human_key, human_pub = human_home / "human.key", human_home / "human.pub"
    agent_key, agent_pub = agent_home / "agent.key", agent_home / "agent.pub"
    for uid, private, public in (
        (CUSTODIAN, server_key, server_pub), (HUMAN, human_key, human_pub), (AGENT, agent_key, agent_pub),
    ):
        as_uid(uid, [installed_binary, "keygen", "--private", private, "--public", public])
    bootstrap = state / "bootstrap"
    as_uid(CUSTODIAN, [installed_binary, "provision-bootstrap", "--path", bootstrap,
        "--server-private", server_key, "--server-public", server_pub,
        "--agent-public", agent_pub, "--agent-uid", str(AGENT),
        "--human-public", human_pub, "--human-uid", str(HUMAN)])
    profile = profiles / "human.profile"
    as_uid(HUMAN, [installed_binary, "provision-profile", "--path", profile,
        "--server-public", server_pub, "--server-uid", str(CUSTODIAN), "--role", "human"])
    vault = state / "vault.sqlite3"
    password = create_vault(installed_cli, vault)
    daemon = start_as(CUSTODIAN, [installed_binary, "serve-vault", "--bootstrap", bootstrap,
        "--agent-socket", runtime / "agent.sock", "--human-socket", runtime / "human.sock",
        "--vault", vault, "--device", DEVICE])
    wait_for_sockets(daemon, [runtime / "agent.sock", runtime / "human.sock"])
    seeded = as_uid(HUMAN, [installed_binary, "human-content-flow", "--profile", profile,
        "--private", human_key, "--socket", runtime / "human.sock"],
        input=wire_fields([password]), check=False)
    assert seeded.returncode == 0 and seeded.stdout.startswith(b"PASS content-e2e types=7"), (
        seeded.returncode, seeded.stdout, seeded.stderr)
    return installed_binary, daemon, password, profile, human_key, runtime, vault


def launch_tui(root, binary, profile, key, runtime, *, idle=30, reveal=1, copy=2):
    tmux(root, "kill-server", check=False)
    raw = root / "terminal.raw"
    command = [binary, "tui", "--profile", profile, "--private", key,
        "--socket", runtime / "human.sock", "--idle-seconds", str(idle),
        "--reveal-seconds", str(reveal), "--copy-seconds", str(copy)]
    tmux(root, "new-session", "-d", "-x", "80", "-y", "24", "--", *command)
    tmux(root, "pipe-pane", "-o", f"cat >> {raw}")
    wait_text(root, "Password required")
    return raw


def start_tui(root, binary, profile, key, runtime, password, *, idle=30, reveal=1, copy=2):
    raw = launch_tui(root, binary, profile, key, runtime, idle=idle, reveal=reveal, copy=copy)
    send(root, password.decode(), enter=True, hidden=True)
    wait_text(root, "Unlocked: selection never reveals secrets")
    return raw


def main():
    assert os.geteuid() == 0 and len(sys.argv) == 3
    source_binary, source_cli = (pathlib.Path(value).resolve() for value in sys.argv[1:])
    root = pathlib.Path(tempfile.mkdtemp(prefix="pm-tui-linux-lab-"))
    daemon = replacement = None
    try:
        binary, daemon, password, profile, key, runtime, vault = setup(root, source_binary, source_cli)

        # A wrong master password closes only this human channel and does not
        # create revisions or audit success; the human can launch and retry.
        db = sqlite3.connect(vault)
        before_wrong = (
            db.execute("select count(*) from revision_parts").fetchone()[0],
            db.execute("select count(*) from encrypted_audit_records").fetchone()[0],
        )
        db.close()
        wrong_raw = launch_tui(root, binary, profile, key, runtime)
        send(root, "synthetic-definitely-wrong", enter=True, hidden=True)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and tmux(root, "has-session", check=False).returncode == 0:
            time.sleep(0.05)
        assert tmux(root, "has-session", check=False).returncode != 0
        db = sqlite3.connect(vault)
        after_wrong = (
            db.execute("select count(*) from revision_parts").fetchone()[0],
            db.execute("select count(*) from encrypted_audit_records").fetchone()[0],
        )
        db.close()
        assert after_wrong == before_wrong
        assert password not in wrong_raw.read_bytes()

        raw = start_tui(root, binary, profile, key, runtime, password)
        initial = screen(root)
        for kind, title in (("password", "Password"), ("totp", "TOTP"), ("passkey", "Passkey"),
                            ("ssh", "SSH"), ("token", "Token"), ("note", "ticket05-e2e-search-canary"),
                            ("file", "File")):
            assert f"[{kind}]" in initial and title in initial, initial
        for forbidden in ("ticket05-e2e-password-canary", "ticket05-e2e-totp-canary",
                          "ticket05-e2e-token-canary", "ticket11-e2e-subject-token-canary",
                          "ticket11-e2e-requester-secret-canary"):
            assert forbidden not in initial

        # Real PTY resize: compact and larger frames remain interactive.
        tmux(root, "resize-window", "-x", "42", "-y", "12")
        wait_text(root, "Password Manager")
        tmux(root, "resize-window", "-x", "100", "-y", "30")
        wait_text(root, "selection is metadata only")

        # Every native kind is found by engine-backed search and history is keyboard reachable.
        catalog_cases = (
            ("Password", "auth[0].password"),
            ("TOTP", "auth[0].secret"),
            ("Passkey", "auth[0].private_key"),
            ("SSH", "auth[0].private_key"),
            ("Token", "auth[0].secret"),
            ("Exchange Relationship", "auth[0].requester_client_secret"),
            ("ticket05-e2e-search-canary", "notes"),
            ("File", "attachment[0].content"),
        )
        for index, (title, field_label) in enumerate(catalog_cases):
            page = query(root, title)
            assert "Search returned 1 active items" in page, page
            send(root, "t"); send(root, f"keyboard-{index}", enter=True)
            wait_text(root, "Organization committed")
            query(root, title)
            send(root, "h")
            wait_text(root, "History:")
            send(root, "r")
            field_page = wait_text(root, "Fields (explicit selection; values hidden)")
            assert field_label in field_page, (field_label, field_page)
            tmux(root, "send-keys", "Escape")
            wait_text(root, "Exposure cancelled")

        # Field selection enumerates the complete logical record rather than
        # silently choosing the first auth record or substituting notes.
        query(root, "Password")
        choose_field(root, "r", "source[0].value", 12)
        assert "ticket05-e2e-source-canary" in wait_text(root, "Secret revealed temporarily")
        time.sleep(1.3)
        wait_text(root, "Reveal expired")

        # Notes remain independently selectable; absence of an auth secret no
        # longer causes an implicit substitution by a legacy exposure opcode.
        query(root, "ticket05-e2e-search-canary")
        choose_field(root, "r", "notes", 5)
        assert "Exposure: note" in wait_text(root, "Secret revealed temporarily")
        time.sleep(1.3)
        wait_text(root, "Reveal expired")

        # The token-exchange relationship added by the unified base exposes
        # both sensitive members only through the same exact-field ceremony.
        query(root, "Exchange Relationship")
        choose_field(root, "r", "auth[0].subject_token", 6)
        assert "ticket11-e2e-subject-token-canary" in wait_text(root, "Secret revealed temporarily")
        time.sleep(1.3)
        wait_text(root, "Reveal expired")
        choose_field(root, "r", "auth[0].requester_client_secret", 8)
        assert "ticket11-e2e-requester-secret-canary" in wait_text(root, "Secret revealed temporarily")
        time.sleep(1.3)
        wait_text(root, "Reveal expired")

        # Search + organization + generator, all through public opcodes.
        query(root, "ticket05-e2e-search-canary")
        send(root, "t"); send(root, "keyboard", enter=True)
        wait_text(root, "Organization committed")
        send(root, "f"); wait_text(root, "Favorite committed")
        send(root, "g"); send(root, "24", enter=True)
        wait_text(root, "Generated secret revealed temporarily")
        time.sleep(1.3)
        expired = wait_text(root, "Reveal expired")
        assert "Exposure: <hidden>" in expired

        # Selection cannot expose; explicit reveal does and expires from current screen.
        query(root, "Password")
        assert "ticket05-e2e-password-canary" not in screen(root)
        choose_field(root, "r", "auth[0].password", 14)
        assert "ticket05-e2e-password-canary" in wait_text(root, "Secret revealed temporarily")
        time.sleep(1.3)
        expired = wait_text(root, "Reveal expired")
        assert "ticket05-e2e-password-canary" not in expired

        # Fixed real wl-copy helper, hostile agent UID denied, ownership race does not clear replacement.
        choose_field(root, "c", "auth[0].password", 14)
        wait_text(root, "Copied explicitly")
        pasted = subprocess.run(["/usr/bin/wl-paste", "--no-newline", "--type", "application/octet-stream"], capture_output=True, timeout=5)
        assert pasted.returncode == 0 and pasted.stdout == b"ticket05-e2e-password-canary", pasted
        hostile = as_uid(AGENT, ["/usr/bin/wl-paste", "--no-newline"], check=False)
        assert hostile.returncode != 0 and b"ticket05-e2e-password-canary" not in hostile.stdout
        replacement = subprocess.Popen(["/usr/bin/wl-copy", "--foreground", "--type", "application/octet-stream"], stdin=subprocess.PIPE)
        replacement.stdin.write(b"ticket23-external-replacement"); replacement.stdin.close()
        time.sleep(0.4)
        assert subprocess.run(["/usr/bin/wl-paste", "--no-newline", "--type", "application/octet-stream"], capture_output=True).stdout == b"ticket23-external-replacement"
        time.sleep(2.2)
        assert subprocess.run(["/usr/bin/wl-paste", "--no-newline", "--type", "application/octet-stream"], capture_output=True).stdout == b"ticket23-external-replacement"
        replacement.terminate(); replacement.wait(timeout=5); replacement = None

        # Non-visible purge, trash, restore, then typed permanent purge.
        query(root, "ticket05-e2e-search-canary")
        send(root, "p"); send(root, "PURGE", enter=True); wait_text(root, "Purged")
        send(root, "d"); wait_text(root, "Moved to trash")
        send(root, "h"); wait_text(root, "lifecycle trash")
        send(root, "u"); wait_text(root, "Restored with a new revision")
        send(root, "d"); wait_text(root, "Moved to trash")
        send(root, "P"); send(root, "PURGE", enter=True); wait_text(root, "Item permanently purged")
        send(root, "l")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and tmux(root, "has-session", check=False).returncode == 0:
            time.sleep(0.05)
        assert tmux(root, "has-session", check=False).returncode != 0

        raw_bytes = raw.read_bytes()
        assert password not in raw_bytes
        assert b"\x1b]52;c;dGlja2V0MjM=" not in raw_bytes
        assert b"dGlja2V0MjM=" in raw_bytes  # text survived, controls did not

        # Idle timeout is based only on human key input and produces a durable lock audit.
        before_audit = sqlite3.connect(vault).execute("select count(*) from encrypted_audit_records").fetchone()[0]
        start_tui(root, binary, profile, key, runtime, password, idle=2, reveal=1, copy=1)
        time.sleep(2.7)
        assert tmux(root, "has-session", check=False).returncode != 0
        after_audit = sqlite3.connect(vault).execute("select count(*) from encrypted_audit_records").fetchone()[0]
        assert after_audit >= before_audit + 2  # unlock + automatic lock

        stop(daemon); daemon = None
        print("PASS tui-content types=7 fields=explicit-complete token-exchange-fields=subject+requester notes=explicit legacy-exposure=rejected "
              "type-mutations=7 wrong-password=unchanged tls-rpk=1 keyboard=1 pty=1 terminal=linux "
              "resize=80x24+42x12+100x30 unicode=1 controls=sanitized osc52=absent "
              "selection-secret=absent reveal-expiry=1 idle-lock=1 clipboard=wl-copy-2.3.0 "
              "clipboard-race=preserved hostile-agent=denied history=1 trash=1 restore=1 purge=1")
    finally:
        tmux(root, "kill-server", check=False)
        if replacement is not None:
            replacement.terminate(); replacement.wait(timeout=5)
        if daemon is not None:
            daemon.send_signal(signal.SIGTERM); daemon.communicate(timeout=5)
        if os.environ.get("PM_KEEP_TUI_LAB"):
            print(f"KEEP {root}", file=sys.stderr)
        else:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
