#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

"""Disposable multi-UID acceptance harness for ticket 03.

This harness only orchestrates public pm-custody commands. The peer identities
are kernel credentials from the caller-provided user namespace, never fields
invented by this script or by a client.
"""

import hashlib
import os
import pathlib
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

CUSTODIAN = 1
HUMAN = 2
AGENT = 3


def as_uid(uid, command, *, check=True):
    def change_identity():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)

    return subprocess.run(
        command,
        check=check,
        capture_output=True,
        preexec_fn=change_identity,
        timeout=15,
    )


def start_as(uid, command):
    def change_identity():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)

    return subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=change_identity,
    )


def expect_unavailable(result):
    assert result.returncode == 4, result
    assert result.stdout == b"", result.stdout
    assert result.stderr == b"CUSTODY_UNAVAILABLE\n", result.stderr


def wait_for_sockets(process, paths):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise AssertionError((process.returncode, stdout, stderr))
        if all(path.exists() for path in paths):
            return
        time.sleep(0.02)
    raise AssertionError("custodian did not publish both sockets")


def stop(process):
    process.send_signal(signal.SIGTERM)
    stdout, stderr = process.communicate(timeout=5)
    assert process.returncode == -signal.SIGTERM, (process.returncode, stdout, stderr)
    assert stdout == b"", stdout
    assert stderr == b"", stderr


def main():
    assert os.geteuid() == 0, "harness must be root only inside the disposable user namespace"
    source_binary = pathlib.Path(sys.argv[1]).resolve()
    root = pathlib.Path(tempfile.mkdtemp(prefix="pm-custody-linux-lab-"))
    try:
        os.chmod(root, 0o711)
        binary = root / "pm-custody"
        shutil.copyfile(source_binary, binary)
        os.chmod(binary, 0o755)
        state = root / "state"
        runtime = root / "run"
        agent_home = root / "agent"
        human_home = root / "human"
        profiles = root / "profiles"
        for path, uid, mode in [
            (state, CUSTODIAN, 0o700),
            (runtime, CUSTODIAN, 0o755),
            (agent_home, AGENT, 0o755),
            (human_home, HUMAN, 0o755),
            (profiles, 0, 0o755),
        ]:
            path.mkdir()
            os.chown(path, uid, uid)
            os.chmod(path, mode)

        server_private, server_public = state / "server.key", state / "server.pub"
        agent_private, agent_public = agent_home / "agent.key", agent_home / "agent.pub"
        human_private, human_public = human_home / "human.key", human_home / "human.pub"
        rogue_private, rogue_public = agent_home / "rogue.key", agent_home / "rogue.pub"
        for uid, private, public in [
            (CUSTODIAN, server_private, server_public),
            (AGENT, agent_private, agent_public),
            (HUMAN, human_private, human_public),
            (AGENT, rogue_private, rogue_public),
        ]:
            as_uid(uid, [binary, "keygen", "--private", private, "--public", public])

        bootstrap = state / "bootstrap.bin"
        as_uid(
            CUSTODIAN,
            [
                binary,
                "provision-bootstrap",
                "--path",
                bootstrap,
                "--server-private",
                server_private,
                "--server-public",
                server_public,
                "--agent-public",
                agent_public,
                "--agent-uid",
                str(AGENT),
                "--human-public",
                human_public,
                "--human-uid",
                str(HUMAN),
            ],
        )
        agent_profile = profiles / "agent.profile"
        human_profile = profiles / "human.profile"
        for role, profile in [("agent", agent_profile), ("human", human_profile)]:
            subprocess.run(
                [
                    binary,
                    "provision-profile",
                    "--path",
                    profile,
                    "--server-public",
                    server_public,
                    "--server-uid",
                    str(CUSTODIAN),
                    "--role",
                    role,
                ],
                check=True,
                capture_output=True,
            )

        bootstrap_stat = bootstrap.stat()
        assert bootstrap_stat.st_uid == CUSTODIAN
        assert stat.S_IMODE(bootstrap_stat.st_mode) == 0o400
        before = hashlib.sha256(bootstrap.read_bytes()).hexdigest()

        denied_read = as_uid(AGENT, ["cat", bootstrap], check=False)
        assert denied_read.returncode != 0 and denied_read.stdout == b""
        denied_write = as_uid(
            AGENT,
            [sys.executable, "-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(b'x')", bootstrap],
            check=False,
        )
        assert denied_write.returncode != 0
        denied_binary_replace = as_uid(
            AGENT,
            [sys.executable, "-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(b'x')", binary],
            check=False,
        )
        assert denied_binary_replace.returncode != 0
        denied_profile_replace = as_uid(
            AGENT,
            [sys.executable, "-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(b'x')", agent_profile],
            check=False,
        )
        assert denied_profile_replace.returncode != 0

        agent_socket = runtime / "agent.sock"
        human_socket = runtime / "human.sock"
        serve = [
            binary,
            "serve",
            "--bootstrap",
            bootstrap,
            "--agent-socket",
            agent_socket,
            "--human-socket",
            human_socket,
        ]
        daemon = start_as(CUSTODIAN, serve)
        wait_for_sockets(daemon, [agent_socket, human_socket])

        denied_unlink = as_uid(AGENT, ["rm", agent_socket], check=False)
        assert denied_unlink.returncode != 0 and agent_socket.exists()

        agent_ok = as_uid(
            AGENT,
            [binary, "probe", "--profile", agent_profile, "--private", agent_private, "--socket", agent_socket],
        )
        assert agent_ok.stdout == b"READY role=agent peer_uid=1 tls=1.3 rpk=pinned alpn=pm-agent/1\n"
        assert agent_ok.stderr == b""
        human_ok = as_uid(
            HUMAN,
            [binary, "probe", "--profile", human_profile, "--private", human_private, "--socket", human_socket],
        )
        assert human_ok.stdout == b"READY role=human peer_uid=1 tls=1.3 rpk=pinned alpn=pm-human/1\n"
        assert human_ok.stderr == b""

        os.chmod(agent_private, 0o600)
        key_acl_fault = as_uid(
            AGENT,
            [binary, "probe", "--profile", agent_profile, "--private", agent_private, "--socket", agent_socket],
            check=False,
        )
        expect_unavailable(key_acl_fault)
        os.chmod(agent_private, 0o400)

        wrong_native_peer = as_uid(
            AGENT,
            [binary, "probe", "--profile", human_profile, "--private", agent_private, "--socket", human_socket],
            check=False,
        )
        expect_unavailable(wrong_native_peer)
        wrong_rpk = as_uid(
            AGENT,
            [binary, "probe", "--profile", agent_profile, "--private", rogue_private, "--socket", agent_socket],
            check=False,
        )
        expect_unavailable(wrong_rpk)

        stop(daemon)
        daemon = start_as(CUSTODIAN, serve)
        wait_for_sockets(daemon, [agent_socket, human_socket])
        after = hashlib.sha256(bootstrap.read_bytes()).hexdigest()
        assert after == before
        restarted = as_uid(
            AGENT,
            [binary, "probe", "--profile", agent_profile, "--private", agent_private, "--socket", agent_socket],
        )
        assert restarted.stdout == agent_ok.stdout
        stop(daemon)

        print(f"PASS uid_map={pathlib.Path('/proc/self/uid_map').read_text().strip()!r}")
        print(f"PASS custody_uid={CUSTODIAN} human_uid={HUMAN} agent_uid={AGENT}")
        print(f"PASS bootstrap_sha256={before} restart=process tls=1.3 rpk=mutual alpn=role-specific")
        print("LIMIT reboot_host=NOT_RUN production_systemd_fde=NOT_RUN")
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
