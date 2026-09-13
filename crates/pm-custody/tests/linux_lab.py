#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

"""Disposable multi-UID acceptance harness for tickets 03 and 04.

This harness only orchestrates public pm-custody commands. The peer identities
are kernel credentials from the caller-provided user namespace, never fields
invented by this script or by a client.
"""

import hashlib
import os
import pathlib
import select
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

CUSTODIAN = 1
HUMAN = 2
AGENT = 3


def as_uid(uid, command, *, check=True, input=None):
    def change_identity():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)

    return subprocess.run(
        command,
        check=check,
        capture_output=True,
        input=input,
        preexec_fn=change_identity,
        timeout=15,
    )


def start_as(uid, command, *, stdin=None):
    def change_identity():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)

    return subprocess.Popen(
        command,
        stdin=stdin,
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
            probes = []
            try:
                for path in paths:
                    probe = socket.socket(socket.AF_UNIX)
                    probes.append(probe)
                    probe.settimeout(0.1)
                    probe.connect(str(path))
                return
            except OSError:
                pass
            finally:
                for probe in probes:
                    probe.close()
        time.sleep(0.02)
    raise AssertionError("custodian did not publish both sockets")


def stop(process):
    process.send_signal(signal.SIGTERM)
    stdout, stderr = process.communicate(timeout=5)
    assert process.returncode == -signal.SIGTERM, (process.returncode, stdout, stderr)
    assert stdout == b"", stdout
    assert stderr == b"", stderr


def create_vault(cli, path):
    password = b"synthetic ticket 04 e2e master"

    def change_identity():
        os.setgroups([])
        os.setgid(CUSTODIAN)
        os.setuid(CUSTODIAN)

    process = subprocess.Popen(
        [cli, "vault", "create", path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=change_identity,
    )
    assert process.stdout.readline() == b"Master password (read from stdin):\n"
    process.stdin.write(password + b"\n")
    process.stdin.flush()
    assert process.stdout.readline() == b"Confirm master password:\n"
    process.stdin.write(password + b"\n")
    process.stdin.flush()
    recovery = process.stdout.readline()
    assert recovery.startswith(b"Recovery code (store externally): PMR1-")
    assert process.stdout.readline() == b"Reintroduce recovery code to confirm the external copy:\n"
    process.stdin.write(recovery.split(b": ", 1)[1])
    process.stdin.close()
    stdout = process.stdout.read()
    stderr = process.stderr.read()
    assert process.wait(timeout=15) == 0, (stdout, stderr)
    assert stdout.startswith(b"Vault created: ") and stderr == b""
    return password


def wire_fields(values):
    encoded = bytearray()
    for value in values:
        encoded.extend(len(value).to_bytes(4, "big"))
        encoded.extend(value)
    return bytes(encoded)


def main():
    assert os.geteuid() == 0, "harness must be root only inside the disposable user namespace"
    source_binary = pathlib.Path(sys.argv[1]).resolve()
    source_cli = pathlib.Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else None
    run_content = len(sys.argv) > 3 and sys.argv[3] == "content"
    root = pathlib.Path(tempfile.mkdtemp(prefix="pm-custody-linux-lab-"))
    try:
        os.chmod(root, 0o711)
        binary = root / "pm-custody"
        shutil.copyfile(source_binary, binary)
        os.chmod(binary, 0o755)
        cli = root / "pm"
        if source_cli is not None:
            shutil.copyfile(source_cli, cli)
            os.chmod(cli, 0o755)
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
            "serve-vault" if source_cli is not None else "serve",
            "--bootstrap",
            bootstrap,
            "--agent-socket",
            agent_socket,
            "--human-socket",
            human_socket,
        ]
        vault = state / "vault.sqlite3"
        if source_cli is not None:
            master = create_vault(cli, vault)
            serve.extend(["--vault", vault, "--device", "44444444444444444444444444444444"])
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

        if source_cli is not None:
            title = b"Synthetic E2E account"
            username = b"synthetic-e2e-user"
            secret_one = b"synthetic e2e secret one"
            destination = b"https://e2e.invalid/login"
            notes = b"synthetic e2e note"
            edited_title = b"Synthetic E2E account edited"
            secret_two = b"synthetic e2e secret two"
            crud_command = [
                binary,
                "human-password-crud",
                "--profile",
                human_profile,
                "--private",
                human_private,
                "--socket",
                human_socket,
            ]
            crud_input = wire_fields(
                [master, title, username, secret_one, destination, notes, edited_title, secret_two]
            )

            # Force the encrypted audit insert to fail inside the real commit
            # reached over TLS. The failed client reconnects for a receipt and
            # observes the permitted no-op outcome; no production test hook is
            # involved.
            database = sqlite3.connect(vault)
            database.execute(
                "CREATE TRIGGER lab_reject_audit BEFORE INSERT ON encrypted_audit_records "
                "BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END"
            )
            database.commit()
            database.close()
            atomic_failure = as_uid(
                HUMAN, crud_command, check=False, input=crud_input
            )
            expect_unavailable(atomic_failure)
            database = sqlite3.connect(vault)
            for table in [
                "vault_items",
                "revision_parts",
                "authority_events",
                "outbox",
                "human_receipts",
                "audit_keys",
                "audit_state",
                "encrypted_audit_records",
            ]:
                assert database.execute(f"select count(*) from {table}").fetchone() == (0,)
            assert database.execute(
                "select count(*) from human_challenges where consumed=1"
            ).fetchone() == (0,)
            assert database.execute(
                "select count(*) from human_challenges where consumed=0"
            ).fetchone() == (1,)
            assert database.execute("select count(*) from human_staging").fetchone() == (1,)
            database.execute("DROP TRIGGER lab_reject_audit")
            database.commit()
            database.close()

            crud = as_uid(HUMAN, crud_command, input=crud_input)
            assert crud.stdout == b"PASS human-crud-e2e receipts=3 replay=1 body-change=rejected\n"
            assert crud.stderr == b""
            persisted = vault.read_bytes()
            assert secret_one not in persisted and secret_two not in persisted
            database = sqlite3.connect(vault)
            assert database.execute("select count(*) from human_receipts").fetchone() == (3,)
            assert database.execute("select count(*) from authority_events").fetchone() == (3,)
            assert database.execute("select count(*) from outbox").fetchone() == (3,)
            assert database.execute("select count(*) from encrypted_audit_records").fetchone() == (3,)
            assert database.execute("select count(*) from human_challenges where consumed=1").fetchone() == (3,)
            assert database.execute("select count(*) from human_challenges where consumed=0").fetchone() == (1,)
            assert database.execute("select count(*) from human_staging").fetchone() == (1,)
            assert database.execute("select status from vault_items").fetchone() == ("trash",)
            database.close()

            audit_command = [
                binary,
                "human-audit-lifecycle",
                "--profile",
                human_profile,
                "--private",
                human_private,
                "--socket",
                human_socket,
            ]
            audit = as_uid(HUMAN, audit_command, input=wire_fields([master]))
            assert audit.stdout == (
                b"PASS audit-e2e autonomous-without-kh=1 signed-device=1 "
                b"purge-gap=1 authority-retained=1\n"
            )
            assert audit.stderr == b""
            database = sqlite3.connect(vault)
            assert database.execute("select count(*) from audit_purge_ranges").fetchone() == (1,)
            assert database.execute("select count(*) from authority_events").fetchone() == (4,)
            assert database.execute("select count(*) from outbox").fetchone() == (4,)
            database.close()
            audit_custody = pathlib.Path(str(vault) + ".audit-custody")
            custody_stat = audit_custody.stat()
            assert custody_stat.st_uid == CUSTODIAN
            assert stat.S_IMODE(custody_stat.st_mode) == 0o400
            custody_hash = hashlib.sha256(audit_custody.read_bytes()).hexdigest()
            if run_content:
                content = as_uid(
                    HUMAN,
                    [
                        binary,
                        "human-content-flow",
                        "--profile",
                        human_profile,
                        "--private",
                        human_private,
                        "--socket",
                        human_socket,
                    ],
                    input=wire_fields([master]),
                )
                assert content.stdout == (
                    b"PASS content-e2e types=7 unicode-attachment=exact source-fields=preserved "
                    b"search=1 organize=tag+favorite generator=configured passkey=storage-only\n"
                )
                assert content.stderr == b""
                streamed = as_uid(
                    HUMAN,
                    [binary, "human-streaming-file", "--profile", human_profile,
                     "--private", human_private, "--socket", human_socket],
                    input=wire_fields([master]),
                )
                assert streamed.stdout == (
                    b"PASS streaming-file bytes=16781312 chunks=17 max_plain_chunk=1048576 "
                    b"short-input=rolled-back limit-16gib=accepted oversize-16gib=rejected\n"
                )
                assert streamed.stderr == b""
                canaries = [
                    b"ticket05-e2e-password-canary",
                    b"ticket05-e2e-totp-canary",
                    b"ticket05-e2e-ssh-canary",
                    b"ticket05-e2e-token-canary",
                    b"ticket05-e2e-attachment-canary",
                    b"ticket05-e2e-source-canary",
                    b"ticket05-e2e-search-canary",
                    b"ticket05-large-stream-canary",
                ]
                for candidate in vault.parent.glob(vault.name + "*"):
                    persisted = candidate.read_bytes()
                    assert all(canary not in persisted for canary in canaries)
                database = sqlite3.connect(vault)
                assert database.execute("select count(*) from attachment_stream_chunks").fetchone() == (17,)
                assert database.execute("select max(length(ciphertext)) from attachment_stream_chunks").fetchone()[0] <= 1024 * 1024 + 21
                assert database.execute("select count(*) from human_staging_streams").fetchone() == (0,)
                published_before_crash = database.execute(
                    "select (select count(*) from vault_items), "
                    "(select count(*) from authority_events), "
                    "(select count(*) from attachment_stream_chunks)"
                ).fetchone()
                database.close()

                interrupted = start_as(
                    HUMAN,
                    [binary, "human-streaming-stall", "--profile", human_profile,
                     "--private", human_private, "--socket", human_socket],
                    stdin=subprocess.PIPE,
                )
                interrupted.stdin.write(wire_fields([master]))
                interrupted.stdin.close()
                interrupted.stdin = None
                ready, _, _ = select.select([interrupted.stdout], [], [], 10)
                assert ready, "streaming crash client did not reach its open transaction"
                assert interrupted.stdout.readline() == b"READY streaming-upload-transaction=open\n"
                daemon.kill()
                daemon_stdout, daemon_stderr = daemon.communicate(timeout=5)
                assert daemon.returncode == -signal.SIGKILL
                assert daemon_stdout == b"" and daemon_stderr == b""
                client_stdout, client_stderr = interrupted.communicate(timeout=5)
                assert interrupted.returncode == 4
                assert client_stdout == b""
                assert client_stderr == b"CUSTODY_UNAVAILABLE\n"
                daemon = start_as(CUSTODIAN, serve)
                wait_for_sockets(daemon, [agent_socket, human_socket])
                database = sqlite3.connect(vault)
                assert database.execute("select count(*) from human_staging_streams").fetchone() == (0,)
                assert database.execute("select count(*) from human_staging_stream_chunks").fetchone() == (0,)
                assert database.execute(
                    "select (select count(*) from vault_items), "
                    "(select count(*) from authority_events), "
                    "(select count(*) from attachment_stream_chunks)"
                ).fetchone() == published_before_crash
                database.close()

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
        if source_cli is not None:
            restarted_audit = as_uid(HUMAN, audit_command, input=wire_fields([master]))
            assert restarted_audit.stdout == audit.stdout
            assert restarted_audit.stderr == b""
            assert hashlib.sha256(audit_custody.read_bytes()).hexdigest() == custody_hash
        stop(daemon)

        print(f"PASS uid_map={pathlib.Path('/proc/self/uid_map').read_text().strip()!r}")
        print(f"PASS custody_uid={CUSTODIAN} human_uid={HUMAN} agent_uid={AGENT}")
        print(f"PASS bootstrap_sha256={before} restart=process tls=1.3 rpk=mutual alpn=role-specific")
        if source_cli is not None:
            print("PASS human_crud=prepare-commit-receipt tls=1.3 rpk=mutual alpn=pm-human/1")
            print(
                "PASS human_negatives=wrong-role,body-change,audit-failure "
                "atomicity=no-partial replay=receipt response-loss=recovered"
            )
            if run_content:
                print(
                    "PASS content=all-types+organization+generator+streaming-file "
                    "stream-crash=rolled-back tls=1.3 rpk=mutual alpn=pm-human/1"
                )
            print(
                "PASS audit=encrypted,signed,segmented,query,purge "
                "autonomous_without_kh=device-custody human_path=mutual-tls-rpk"
            )
        print("LIMIT reboot_host=NOT_RUN production_systemd_fde=NOT_RUN")
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
