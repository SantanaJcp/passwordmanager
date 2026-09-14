#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Public RED: custody locks a framed secret destination before payload read."""

import os
import pathlib
import resource
import shutil
import signal
import subprocess
import sys
import tempfile

from linux_lab import as_uid

CUSTODIAN = 1
HUMAN = 2


def child_identity():
    resource.setrlimit(resource.RLIMIT_MEMLOCK, (0, 0))
    os.setgroups([])
    os.setgid(HUMAN)
    os.setuid(HUMAN)


def main():
    assert os.geteuid() == 0 and len(sys.argv) == 2
    source = pathlib.Path(sys.argv[1]).resolve(strict=True)
    root = pathlib.Path(tempfile.mkdtemp(prefix="pm-custody-protected-input-linux-lab-"))
    child = None
    try:
        root.chmod(0o711)
        binary = root / "pm-custody"
        shutil.copyfile(source, binary)
        binary.chmod(0o755)
        server_home = root / "server"
        human_home = root / "human"
        profiles = root / "profiles"
        for path, uid in ((server_home, CUSTODIAN), (human_home, HUMAN), (profiles, 0)):
            path.mkdir(mode=0o755)
            os.chown(path, uid, uid)
        server_key, server_pub = server_home / "server.key", server_home / "server.pub"
        human_key, human_pub = human_home / "human.key", human_home / "human.pub"
        as_uid(CUSTODIAN, [binary, "keygen", "--private", server_key, "--public", server_pub])
        as_uid(HUMAN, [binary, "keygen", "--private", human_key, "--public", human_pub])
        profile = profiles / "human.profile"
        subprocess.run(
            [binary, "provision-profile", "--path", profile,
             "--server-public", server_pub, "--server-uid", str(CUSTODIAN),
             "--role", "human"],
            check=True, capture_output=True,
        )
        socket_path = root / "absent.sock"
        child = subprocess.Popen(
            [binary, "human-password-crud", "--profile", profile,
             "--private", human_key, "--socket", socket_path],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={}, preexec_fn=child_identity,
        )
        child.stdin.write((32).to_bytes(4, "big"))
        child.stdin.flush()
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired as error:
            raise AssertionError(
                "custody read secret payload before locking its owned destination"
            ) from error
        stdout, stderr = child.communicate(timeout=3)
        child = None
        assert stdout == b"", stdout
        assert stderr == b"CUSTODY_UNAVAILABLE\n", stderr
        assert not socket_path.exists()
    finally:
        if child is not None and child.poll() is None:
            child.send_signal(signal.SIGTERM)
            child.communicate(timeout=5)
        shutil.rmtree(root)
    print("PASS fault-safety custody-framed-secret=locked-before-read cleanup=verified")


if __name__ == "__main__":
    main()
