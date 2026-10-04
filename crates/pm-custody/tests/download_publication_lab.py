#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared download collision: real vault, human TLS/RPK, keyboard and PTY."""

import hashlib
import os
import pathlib
import signal
import time
import sys
import tempfile

from linux_lab import as_uid, wire_fields
from tui_content_lab import HUMAN, query, screen, send, setup, start_tui, tmux, wait_text
from tui_operations_lab import finish_owned_resources


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(65536):
            value.update(chunk)
    return value.digest()


def request(root, kind, destination, *, confirm=True):
    if kind in ("backup", "plaintext"):
        send(root, "b"); wait_text(root, "Backup/recovery:")
        send(root, "1" if kind == "backup" else "2")
        wait_text(root, "New native backup path" if kind == "backup" else "New plaintext export path")
        send(root, str(destination), enter=True)
        if kind == "plaintext" and confirm:
            wait_text(root, "PLAINTEXT WARNING")
            send(root, "EXPORT", enter=True)
    else:
        query(root, "Large stream")
        send(root, "D"); wait_text(root, "large-雪.bin")
        tmux(root, "send-keys", "Enter"); wait_text(root, "New destination path")
        send(root, str(destination), enter=True)


def main():
    assert os.geteuid() == 0 and len(sys.argv) == 4
    root = pathlib.Path(tempfile.mkdtemp(prefix="pmshared-download-"))
    daemon = None
    kind = sys.argv[3]
    success = {"backup": "Native encrypted backup complete", "plaintext": "Plaintext export complete",
               "attachment": "Attachment streamed atomically"}[kind]
    try:
        binary, daemon, password, profile, key, runtime, vault = setup(
            root, pathlib.Path(sys.argv[1]).resolve(), pathlib.Path(sys.argv[2]).resolve())
        if kind == "attachment":
            streamed = as_uid(HUMAN, [binary, "human-streaming-file", "--profile", profile,
                "--private", key, "--socket", runtime / "human.sock"],
                input=wire_fields([password]), check=False)
            assert streamed.returncode == 0 and streamed.stdout.startswith(b"PASS streaming-file")
        destination = root / "human" / f"shared-{kind}.output"
        start_tui(root, binary, profile, key, runtime, password, idle=90, reveal=10, copy=2)
        tmux(root, "resize-window", "-x", "160", "-y", "30")
        request(root, kind, destination)
        wait_text(root, success)
        original = (digest(destination), destination.stat().st_size, destination.stat().st_mode,
                    destination.stat().st_ino)
        assert destination.stat().st_mode & 0o777 == 0o600
        if kind in ("backup", "plaintext"):
            os.kill(daemon.pid, signal.SIGSTOP)
        try:
            request(root, kind, destination, confirm=False)
            failed = wait_text(root, "Operation failed explicitly; no success was recorded (DESTINATION_EXISTS)")
        except AssertionError:
            print(f"RED shared-download kind={kind} unexpected-success={success in screen(root)} "
                  f"destination-changed={digest(destination) != original[0]}", flush=True)
            raise AssertionError(f"{kind}: existing destination was not rejected") from None
        finally:
            if kind in ("backup", "plaintext"):
                os.kill(daemon.pid, signal.SIGCONT)
        assert success not in failed
        assert (digest(destination), destination.stat().st_size, destination.stat().st_mode,
                destination.stat().st_ino) == original
        assert not destination.with_suffix(".partial").exists()
        if kind == "plaintext":
            confirmation_collision = destination.with_name("confirmation-plaintext.output")
            request(root, kind, confirmation_collision, confirm=False)
            wait_text(root, "PLAINTEXT WARNING")
            os.kill(daemon.pid, signal.SIGSTOP)
            try:
                as_uid(HUMAN, [sys.executable, "-c",
                    "import os,sys;fd=os.open(sys.argv[1],os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.write(fd,b'synthetic-confirmation-destination');os.close(fd)", confirmation_collision])
                before_confirmation = (digest(confirmation_collision), confirmation_collision.stat())
                send(root, "EXPORT", enter=True)
                wait_text(root, "Operation failed explicitly; no success was recorded (DESTINATION_EXISTS)")
                assert (digest(confirmation_collision), confirmation_collision.stat()) == before_confirmation
                assert not confirmation_collision.with_suffix(".partial").exists()
            finally:
                os.kill(daemon.pid, signal.SIGCONT)
            print("PASS plaintext-confirmation collision=DestinationExists server=paused partial=absent", flush=True)
        if kind in ("backup", "plaintext"):
            print(f"PASS {kind}-early collision=DestinationExists server=paused partial=absent", flush=True)
            raced = destination.with_name(f"raced-{kind}.output")
            assert not raced.exists() and not raced.with_suffix(".partial").exists()
            if kind == "plaintext":
                request(root, kind, raced, confirm=False)
                wait_text(root, "PLAINTEXT WARNING")
            os.kill(daemon.pid, signal.SIGSTOP)
            try:
                if kind == "plaintext":
                    send(root, "EXPORT", enter=True)
                else:
                    request(root, kind, raced)
                deadline = time.monotonic() + 8
                while not raced.with_suffix(".partial").exists():
                    assert time.monotonic() < deadline, f"{kind} request did not create its own temporary"
                    time.sleep(.05)
                as_uid(HUMAN, [sys.executable, "-c",
                    "import os,sys;fd=os.open(sys.argv[1],os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.write(fd,b'synthetic-race-destination');os.close(fd)", raced])
                original_race = (digest(raced), raced.stat())
            finally:
                os.kill(daemon.pid, signal.SIGCONT)
            wait_text(root, "Operation failed explicitly; no success was recorded (DESTINATION_EXISTS)")
            assert (digest(raced), raced.stat()) == original_race
            assert not raced.with_suffix(".partial").exists()
            print(f"PASS {kind}-race collision=DestinationExists destination=unchanged partial=absent", flush=True)
    finally:
        finish_owned_resources(root, daemon, None, None)
    print(f"PASS shared-download kind={kind} collision=error digest=unchanged mode=0600 "
          "partial=absent keyboard=real tls=rpk cleanup=verified")


if __name__ == "__main__":
    main()
