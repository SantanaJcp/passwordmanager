#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Ticket-25 keyboard operations against the real human service and PTY."""

import os
import json
import pathlib
import re
import shutil
import signal
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import zipfile

from linux_lab import as_uid, start_as, stop, wait_for_sockets, wire_fields
from tui_content_lab import HUMAN, query, screen, send, setup, start_tui, tmux, wait_text

REMOTE_DEVICE = "25252525252525252525252525252525"


def send_long(root, value, visible_suffix):
    tmux(root, "send-keys", "-l", value)
    wait_text(root, visible_suffix)
    tmux(root, "send-keys", "Enter")


def onepux(path):
    document = "ticket25-document"
    data = {"accounts": [{"attrs": {"uuid": "ticket25-account"}, "vaults": [{"attrs": {"uuid": "ticket25-vault"}, "items": [
        {"uuid": "ticket25-login", "state": "archived", "favIndex": 1, "categoryUuid": "001", "details": {"loginFields": [{"designation": "username", "value": "u"}, {"designation": "password", "value": "synthetic-ticket25-1pux"}], "notesPlain": "synthetic note", "passwordHistory": [{"value": "synthetic-prior", "time": 1}]}, "overview": {"title": "Keyboard 1PUX", "url": "https://ticket25.invalid", "tags": ["imported"]}},
        {"uuid": "ticket25-file", "categoryUuid": "004", "details": {"documentAttributes": {"fileName": "ticket25.bin", "documentId": document, "decryptedSize": 2 * 1024 * 1024 + 7}}, "overview": {"title": "Keyboard 1PUX file"}}
    ]}]}]}
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as out:
        out.writestr("export.attributes", json.dumps({"version": 3, "description": "synthetic"}))
        out.writestr("export.data", json.dumps(data, separators=(",", ":")))
        state = 0x251A1BC3D4E5F607
        content = bytearray(2 * 1024 * 1024 + 7)
        for index in range(len(content)):
            state ^= (state << 13) & 0xffffffffffffffff; state ^= state >> 7; state ^= (state << 17) & 0xffffffffffffffff
            content[index] = state & 0xff
        out.writestr(f"files/{document}___ignored.bin", content)
    os.chown(path, HUMAN, HUMAN); path.chmod(0o400)


def cbor_length(data, offset, major):
    lead = data[offset]; assert lead >> 5 == major; value = lead & 31; offset += 1
    if value < 24: return value, offset
    width = 1 << (value - 24) if value <= 27 else 0
    assert width in (1, 2, 4, 8)
    return int.from_bytes(data[offset:offset + width], "big"), offset + width


def pairing_namespace(data):
    count, offset = cbor_length(data, 0, 4); assert count == 6
    length, offset = cbor_length(data, offset, 3); offset += length
    length, offset = cbor_length(data, offset, 2); assert length == 16; offset += length
    length, offset = cbor_length(data, offset, 2); assert length == 32
    return data[offset:offset + length].hex()


def seed_remote_device(root, binary, profile, key, runtime, vault, password):
    """Publish real signed history from a second device custody process."""
    audit = pathlib.Path(f"{vault}.audit-custody")
    owner_audit = root / "state" / "owner.audit-custody"
    remote_audit = root / "state" / "remote.audit-custody"
    audit.rename(owner_audit)
    command = [binary, "serve-vault", "--bootstrap", root / "state" / "bootstrap",
        "--agent-socket", runtime / "agent.sock", "--human-socket", runtime / "human.sock",
        "--vault", vault, "--device", REMOTE_DEVICE]
    daemon = start_as(1, command)
    try:
        wait_for_sockets(daemon, [runtime / "agent.sock", runtime / "human.sock"])
        seeded = as_uid(HUMAN, [binary, "human-password-crud", "--profile", profile,
            "--private", key, "--socket", runtime / "human.sock"],
            input=wire_fields([password, b"Remote device item", b"remote-user",
                b"synthetic-ticket25-remote-secret", b"https://remote-device.invalid",
                b"synthetic remote note", b"Remote device item edited",
                b"synthetic-ticket25-remote-secret-2"]), check=False)
        assert seeded.returncode == 0 and seeded.stdout.startswith(b"PASS human-crud-e2e"), seeded
    finally:
        stop(daemon)
    audit.rename(remote_audit)
    owner_audit.rename(audit)


def restart_owner(root, binary, runtime, vault):
    daemon = start_as(1, [binary, "serve-vault", "--bootstrap", root / "state" / "bootstrap",
        "--agent-socket", runtime / "agent.sock", "--human-socket", runtime / "human.sock",
        "--vault", vault, "--device", "23232323232323232323232323232323"])
    wait_for_sockets(daemon, [runtime / "agent.sock", runtime / "human.sock"])
    return daemon


def stop_tmux_owned(root):
    listed = tmux(root, "list-sessions", check=False)
    if listed.returncode == 0:
        killed = tmux(root, "kill-server", check=False)
        assert killed.returncode == 0, killed
    else:
        assert listed.returncode == 1 and (
            b"no server running" in listed.stderr or b"failed to connect" in listed.stderr
            or b"server exited unexpectedly" in listed.stderr
        ), listed


def finish_owned_resources(root, daemon, sync_daemon, closing_endpoint):
    """Attempt every owned cleanup and report every failure before PASS."""
    def assert_absent():
        assert not root.exists(), root

    failures = []
    for cleanup in (
        lambda: stop_tmux_owned(root),
        lambda: stop(daemon) if daemon is not None else None,
        lambda: stop(sync_daemon) if sync_daemon is not None else None,
        lambda: closing_endpoint.close() if closing_endpoint is not None else None,
        lambda: shutil.rmtree(root),
        assert_absent,
    ):
        try:
            cleanup()
        except Exception as error:
            failures.append(error)
    if failures:
        raise ExceptionGroup("ticket25 owned cleanup failed", failures)


class ClosingEndpoint:
    """Reachable Unix endpoint that closes every real TLS attempt."""
    def __init__(self, path):
        self.path = path
        self.closed = threading.Event()
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(path))
        self.listener.listen(16)
        self.listener.settimeout(0.1)
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.closed.is_set():
            try:
                connection, _ = self.listener.accept()
                connection.close()
            except TimeoutError:
                pass

    def close(self):
        self.closed.set()
        self.thread.join(timeout=2)
        assert not self.thread.is_alive()
        self.listener.close()
        self.path.unlink()


def main():
    assert os.geteuid() == 0 and len(sys.argv) == 4
    source_binary, source_cli, source_sync = (pathlib.Path(value).resolve() for value in sys.argv[1:])
    root = pathlib.Path(tempfile.mkdtemp(prefix="pm-tui-operations-"))
    daemon = sync_daemon = closing_endpoint = None
    passed = None
    try:
        binary, daemon, password, profile, key, runtime, vault = setup(root, source_binary, source_cli)
        stop(daemon); daemon = None
        seed_remote_device(root, binary, profile, key, runtime, vault, password)
        daemon = restart_owner(root, binary, runtime, vault)
        streamed = as_uid(HUMAN, [binary, "human-streaming-file", "--profile", profile,
            "--private", key, "--socket", runtime / "human.sock"],
            input=wire_fields([password]), check=False)
        assert streamed.returncode == 0 and streamed.stdout.startswith(b"PASS streaming-file"), streamed

        source = root / "human" / "import.csv"
        source.write_text("name,url,username,password,note\nKeyboard import,https://keyboard.invalid,u,synthetic-ticket25-import,n\n", encoding="utf-8")
        os.chown(source, HUMAN, HUMAN); source.chmod(0o400)
        before_source = source.read_bytes()
        archive = root / "human" / "import.1pux"; onepux(archive); before_archive = archive.read_bytes()
        native = root / "human" / "keyboard.pmb1"
        plaintext = root / "human" / "keyboard.jsonl"
        attachment = root / "human" / "large.bin"
        sync_binary = root / "pm-sync"; shutil.copyfile(source_sync, sync_binary); sync_binary.chmod(0o755); os.chown(sync_binary, 1, 1)
        sync_key, sync_pub = root / "state" / "sync-server.key", root / "state" / "sync-server.pub"
        client_key, client_pub = root / "state" / "sync-client.key", root / "state" / "sync-client.pub"
        as_uid(1, [binary, "keygen", "--private", sync_key, "--public", sync_pub])
        as_uid(1, [binary, "keygen", "--private", client_key, "--public", client_pub])
        pin = sync_pub.read_bytes().hex(); pairing = root / "human" / "pairing.cbor"

        start_tui(root, binary, profile, key, runtime, password, idle=90, reveal=10, copy=2)
        send(root, "m"); send(root, "1"); send(root, f"{root / 'human' / 'missing.csv'}|chrome|keep", enter=True)
        wait_text(root, "Operation failed explicitly; no success was recorded")
        assert tmux(root, "has-session", check=False).returncode == 0
        send(root, "m"); wait_text(root, "Migration:")
        send(root, "1"); wait_text(root, "CSV source")
        send(root, f"{source}|chrome|keep", enter=True)
        preview = wait_text(root, "Preview values hidden")
        assert "new=1" in preview and "synthetic-ticket25-import" not in preview
        send(root, "IMPORT", enter=True); wait_text(root, "Import committed transactionally")
        assert source.read_bytes() == before_source
        query(root, "Keyboard import")
        before_cancel = sqlite3.connect(vault).execute("select count(*) from vault_items").fetchone()[0]
        send(root, "m"); send(root, "1"); send(root, f"{source}|chrome|keep", enter=True)
        wait_text(root, "exact-duplicates=1"); send(root, "NOT IMPORT", enter=True)
        wait_text(root, "Confirmation mismatch; import cancelled")
        assert sqlite3.connect(vault).execute("select count(*) from vault_items").fetchone()[0] == before_cancel
        send(root, "m"); send(root, "2"); send(root, f"{archive}|keep", enter=True)
        preview = wait_text(root, "Preview values hidden")
        assert "new=2" in preview and "synthetic-ticket25-1pux" not in preview
        send(root, "IMPORT", enter=True); wait_text(root, "Import committed transactionally")
        assert archive.read_bytes() == before_archive
        query(root, "Keyboard 1PUX")

        send(root, "y"); send(root, "1"); send_long(root, f"{pin}|{pairing}|PAIR", "|PAIR")
        wait_text(root, "Protected pairing created")
        assert pairing.stat().st_mode & 0o777 == 0o600
        namespace = pairing_namespace(pairing.read_bytes())
        sync_socket, sync_db = root / "run" / "sync.sock", root / "state" / "sync.sqlite3"
        sync_daemon = start_as(1, [sync_binary, "serve", "--db", sync_db, "--socket", sync_socket,
            "--server-key", sync_key, "--namespace", namespace, "--client-pub", client_pub])
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not sync_socket.exists(): time.sleep(0.05)
        assert sync_socket.exists()
        send(root, "y"); send(root, "2")
        send_long(root, f"{pairing}|{sync_binary}|{sync_socket}|{client_key}|{sync_pub}|{pin}|SYNC", "|SYNC")
        sync_page = wait_text(root, "Sync complete through pinned TLS", timeout=20)
        assert "pushed=" in sync_page and sync_db.stat().st_size > 0
        send(root, "y"); send(root, "3")
        send_long(root, f"{REMOTE_DEVICE}|RETIRE", "|RETIRE")
        wait_text(root, "retired at every locally observed")
        retirement = sqlite3.connect(vault).execute(
            "select count(*) from authority_events where kind='device-retire' and subject=?",
            [bytes.fromhex(REMOTE_DEVICE)]).fetchone()[0]
        assert retirement == 1

        hostile_socket = root / "run" / "sync-closing.sock"
        closing_endpoint = ClosingEndpoint(hostile_socket)
        send(root, "y"); send(root, "2")
        send_long(root, f"{pairing}|{sync_binary}|{hostile_socket}|{client_key}|{sync_pub}|{pin}|SYNC", "|SYNC")
        queued = wait_text(root, "authorized and queued")
        job_match = re.search(r"Sync job ([0-9a-f]{32})", queued)
        assert job_match
        failed_job = job_match.group(1)
        send(root, "l")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and tmux(root, "has-session", check=False).returncode == 0:
            time.sleep(0.05)
        assert tmux(root, "has-session", check=False).returncode == 1
        stop(daemon); daemon = None
        assert pathlib.Path(f"{vault}.sync-job").exists()
        daemon = restart_owner(root, binary, runtime, vault)
        start_tui(root, binary, profile, key, runtime, password, idle=1, reveal=1, copy=1)
        send(root, "y"); send(root, "4"); send(root, failed_job, enter=True)
        progress = wait_text(root, "Sync job")
        assert "complete through" not in progress
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and tmux(root, "has-session", check=False).returncode == 0:
            time.sleep(0.05)
        assert tmux(root, "has-session", check=False).returncode == 1
        start_tui(root, binary, profile, key, runtime, password, idle=90, reveal=10, copy=2)
        send(root, "y"); send(root, "4"); send(root, failed_job, enter=True)
        wait_text(root, "unavailable after bounded transport", timeout=75)
        assert not pathlib.Path(f"{vault}.sync-job").exists()
        closing_endpoint.close(); closing_endpoint = None

        send(root, "b"); wait_text(root, "Backup/recovery:")
        send(root, "1"); send(root, str(native), enter=True); wait_text(root, "Native encrypted backup complete")
        assert native.stat().st_mode & 0o777 == 0o600 and native.stat().st_size > 0
        send(root, "b"); send(root, "2"); send(root, str(plaintext), enter=True)
        wait_text(root, "PLAINTEXT WARNING")
        send(root, "EXPORT", enter=True); wait_text(root, "Plaintext export complete")
        assert plaintext.stat().st_mode & 0o777 == 0o600 and plaintext.read_bytes().startswith(b"PM-LOGICAL-JSONL/1\n")

        results = query(root, "Large stream")
        assert "Large stream" in results, results
        send(root, "D"); page = wait_text(root, "large-雪.bin")
        assert "Attachments (exact descriptor; values hidden)" in page, page
        assert "synthetic-ticket25" not in page, page
        tmux(root, "send-keys", "Enter"); wait_text(root, "New destination path")
        send(root, str(attachment), enter=True); wait_text(root, "Attachment streamed atomically")
        assert attachment.stat().st_size == 16 * 1024 * 1024 + 4096

        send(root, "z"); send(root, "1"); audit = wait_text(root, "Audit metadata:")
        match = re.search(r"records=(\d+)", audit); assert match and int(match.group(1)) > 0
        before_parts = sqlite3.connect(vault).execute("select count(*) from revision_parts").fetchone()[0]
        send(root, "z"); send(root, "2"); send(root, "1:2:PURGE AUDIT", enter=True)
        wait_text(root, "discontinuity retained")
        after_parts = sqlite3.connect(vault).execute("select count(*) from revision_parts").fetchone()[0]
        assert after_parts == before_parts

        send(root, "b"); wait_text(root, "Backup/recovery:")
        send(root, "3"); wait_text(root, "Archive path|RESTORE")
        send(root, f"{native}|RESTORE", enter=True)
        wait_text(root, "Restore committed with new IDs/keys")
        tmux(root, "resize-window", "-x", "240", "-y", "30")
        send(root, "b"); send(root, "5")
        recovery = wait_text(root, "Recovery code shown temporarily")
        match = re.search(r"Exposure: ([^\s]+)", recovery)
        assert match and match.group(1) != "<hidden>", recovery
        send(root, match.group(1), enter=True, hidden=True)
        wait_text(root, "Recovery rotated after exact re-entry")
        send(root, "l")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and tmux(root, "has-session", check=False).returncode == 0:
            time.sleep(0.05)
        assert tmux(root, "has-session", check=False).returncode == 1
        start_tui(root, binary, profile, key, runtime, password, idle=90, reveal=10, copy=2)
        send(root, "b"); send(root, "4"); send(root, "synthetic-ticket25-new-master|ROTATE", enter=True, hidden=True)
        wait_text(root, "Master password rotated")
        send(root, "l")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and tmux(root, "has-session", check=False).returncode == 0:
            time.sleep(0.05)
        assert tmux(root, "has-session", check=False).returncode == 1

        stop(sync_daemon); sync_daemon = None
        offline_raw = start_tui(root, binary, profile, key, runtime,
            b"synthetic-ticket25-new-master", idle=90, reveal=10, copy=2)
        send(root, "y"); send(root, "2")
        send_long(root, f"{pairing}|{sync_binary}|{sync_socket}|{client_key}|{sync_pub}|{pin}|SYNC", "|SYNC")
        wait_text(root, "Sync endpoint offline; no sync was performed")
        assert tmux(root, "has-session", check=False).returncode == 0
        assert b"Sync complete through pinned TLS" not in offline_raw.read_bytes()
        send(root, "l")

        stop(daemon); daemon = None
        passed = "PASS tui-operations keyboard=1 pty=1 tls-rpk=1 import=csv+1pux+preview+mapping+duplicates+confirm backup=native plaintext=warn+confirm restore=1 rotation=master+recovery sync=pair+pinned-real+job-id+restart+idle-lock+bounded-unavailable+retire-second-device+offline-explicit audit=query+purge attachment=streamed-large source-unchanged=1 no-secrets-preview=1"
    finally:
        if os.environ.get("PM_KEEP_TUI_OPERATIONS_LAB"):
            print(f"KEEP {root}", file=sys.stderr)
        else:
            finish_owned_resources(root, daemon, sync_daemon, closing_endpoint)
    if passed is not None:
        print(passed)


if __name__ == "__main__":
    main()
