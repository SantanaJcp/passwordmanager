#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Public REDs: trusted adapters reserve locked frames before payload read."""

import os
import pathlib
import resource
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


def deny_memlock():
    resource.setrlimit(resource.RLIMIT_MEMLOCK, (0, 0))


def wait_socket(process, path):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError((process.returncode, process.stdout.read(), process.stderr.read()))
        if path.exists():
            return
        time.sleep(0.01)
    raise AssertionError(("missing adapter socket", path))


def stop(process):
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    stdout, stderr = process.communicate(timeout=5)
    assert process.returncode == -signal.SIGTERM, (process.returncode, stdout, stderr)
    assert b"ticket28-adapter-secret" not in stdout + stderr


def main():
    assert len(sys.argv) == 3 and os.geteuid() != 0
    web_source, ssh_source = (pathlib.Path(value).resolve(strict=True) for value in sys.argv[1:])
    root = pathlib.Path(tempfile.mkdtemp(prefix="pm-adapter-protected-frame-linux-lab-"))
    processes = []
    unlocked_readers = []
    try:
        root.chmod(0o700)
        web, ssh = root / "pm-web-auth", root / "pm-ssh-client"
        shutil.copyfile(web_source, web); web.chmod(0o755)
        shutil.copyfile(ssh_source, ssh); ssh.chmod(0o755)
        ca = root / "synthetic-ca.der"; ca.write_bytes(b"synthetic-not-used")
        github = root / "github.profile"
        github.write_text(
            "version=1\nprofile_id=github-assigned-issues/1\n"
            "integration_id=github-rest-bearer\norigin=https://api.github.com\n"
            "connect_port=443\nca_der=" + str(ca) + "\n"
        )
        github.chmod(0o400)
        web_socket = root / "web.sock"
        web_process = subprocess.Popen(
            [web, "serve", "--profile", github, "--socket", web_socket,
             "--custodian-uid", str(os.geteuid())],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={}, preexec_fn=deny_memlock,
        )
        processes.append(web_process); wait_socket(web_process, web_socket)
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(3); client.connect(str(web_socket)); client.sendall((64).to_bytes(4, "big"))
            try:
                assert client.recv(1) == b"", "web adapter returned data instead of closing"
            except TimeoutError:
                unlocked_readers.append("web")

        ssh_profile = root / "ssh.profile"
        ssh_profile.write_text(
            "version=1\nprofile_id=ssh-lab\nintegrations=ssh-server,linux-system-ssh\n"
            "methods=publickey,password\nhost=127.0.0.1\nport=22\nusername=alice\n"
            "host_key_sha256=" + "0" * 64 + "\nconsumer_uid=" + str(os.geteuid()) +
            "\nserver_version=OpenSSH_10.5p1\n"
        )
        ssh_profile.chmod(0o400)
        provider_socket, consumer_socket = root / "ssh-provider.sock", root / "ssh-consumer.sock"
        ssh_process = subprocess.Popen(
            [ssh, "serve", "--profile", ssh_profile, "--profile-owner", str(os.geteuid()),
             "--provider-socket", provider_socket, "--provider-uid", str(os.geteuid()),
             "--consumer-socket", consumer_socket],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={}, preexec_fn=deny_memlock,
        )
        processes.append(ssh_process); wait_socket(ssh_process, provider_socket)
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(3); client.connect(str(provider_socket)); client.sendall((64).to_bytes(4, "big"))
            try:
                header = client.recv(4)
                assert len(header) == 4
                response = client.recv(int.from_bytes(header, "big"))
                assert response == b"\x03\x00\x00\x00\x00", response
            except TimeoutError:
                unlocked_readers.append("ssh")
        assert not unlocked_readers, (
            "adapters read payload before locked frame allocation", tuple(unlocked_readers)
        )
    finally:
        for process in reversed(processes):
            stop(process)
        shutil.rmtree(root)
    print("PASS fault-safety adapter-frames=locked-before-payload web+ssh=closed cleanup=verified")


if __name__ == "__main__":
    main()
