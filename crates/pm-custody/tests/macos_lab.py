#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

"""Destructive-only-inside-ephemeral-CI native macOS custody laboratory."""

import os
import pathlib
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import time

LABEL = "com.santanajcp.passwordmanager"
CUSTODIAN = "_passwordmanager"
AGENT = "_pmagent26"
OTHER = "_pmother26"
INSTALL = pathlib.Path("/usr/local/libexec/passwordmanager")
STATE = pathlib.Path("/Library/Application Support/PasswordManager")
RUNTIME = pathlib.Path("/var/run/passwordmanager")
PLIST = pathlib.Path(f"/Library/LaunchDaemons/{LABEL}.plist")
PASSWORD = b"synthetic ticket 26 master password"


def run(command, *, check=True, input=None, timeout=30):
    return subprocess.run(
        [str(value) for value in command], check=check, capture_output=True,
        input=input, timeout=timeout,
    )


def sudo(command, *, user=None, check=True, input=None):
    prefix = ["sudo", "-n"]
    if user is not None:
        prefix += ["-u", user]
    return run(prefix + list(command), check=check, input=input)


def wire_fields(values):
    result = bytearray()
    for value in values:
        result += len(value).to_bytes(4, "big") + value
    return bytes(result)


def create_account(name, uid):
    group = f"/Groups/{name}"
    user = f"/Users/{name}"
    sudo(["dscl", ".", "-create", group])
    sudo(["dscl", ".", "-create", group, "PrimaryGroupID", str(uid)])
    sudo(["dscl", ".", "-create", user])
    for attribute, value in [
        ("RealName", f"Password Manager ticket 26 {name}"),
        ("UniqueID", str(uid)), ("PrimaryGroupID", str(uid)),
        ("NFSHomeDirectory", "/var/empty"), ("UserShell", "/usr/bin/false"),
        ("IsHidden", "1"), ("Password", "*"),
    ]:
        sudo(["dscl", ".", "-create", user, attribute, value])


def unused_ids(count):
    listings = [
        run(["dscl", ".", "-list", "/Users", "UniqueID"]).stdout.decode(),
        run(["dscl", ".", "-list", "/Groups", "PrimaryGroupID"]).stdout.decode(),
    ]
    used = {
        int(line.rsplit(None, 1)[1])
        for output in listings
        for line in output.splitlines()
        if line.split()
    }
    values = [candidate for candidate in range(450, 500) if candidate not in used]
    assert len(values) >= count, "no unused synthetic system-account UIDs"
    return values[:count]


def keygen(binary, user, private, public):
    sudo([binary, "keygen", "--private", private, "--public", public], user=user)


def create_vault(cli, path):
    process = subprocess.Popen(
        ["sudo", "-n", "-u", CUSTODIAN, str(cli), "vault", "create", str(path)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert process.stdout.readline() == b"Master password (read from stdin):\n"
    process.stdin.write(PASSWORD + b"\n"); process.stdin.flush()
    assert process.stdout.readline() == b"Confirm master password:\n"
    process.stdin.write(PASSWORD + b"\n"); process.stdin.flush()
    recovery = process.stdout.readline()
    assert recovery.startswith(b"Recovery code (store externally): PMR1-")
    assert process.stdout.readline() == b"Reintroduce recovery code to confirm the external copy:\n"
    process.stdin.write(recovery.split(b": ", 1)[1]); process.stdin.close()
    stdout, stderr = process.stdout.read(), process.stderr.read()
    assert process.wait(timeout=30) == 0, (stdout, stderr)
    assert stdout.startswith(b"Vault created: ") and stderr == b""


def wait_for_service():
    deadline = time.monotonic() + 20
    sockets = [RUNTIME / "agent.sock", RUNTIME / "human.sock"]
    while time.monotonic() < deadline:
        if all(path.exists() for path in sockets):
            try:
                for path in sockets:
                    probe = socket.socket(socket.AF_UNIX)
                    probe.settimeout(0.2); probe.connect(str(path)); probe.close()
                return
            except OSError:
                pass
        time.sleep(0.1)
    details = sudo(["launchctl", "print", f"system/{LABEL}"], check=False)
    raise AssertionError((details.returncode, details.stdout, details.stderr))


def probe(binary, user, profile, private, endpoint, *, allowed=True):
    result = sudo([binary, "probe", "--profile", profile, "--private", private,
                   "--socket", endpoint], user=user, check=False)
    if allowed:
        assert result.returncode == 0 and result.stderr == b"", result
        assert result.stdout.startswith(b"READY role="), result.stdout
    else:
        assert result.returncode == 4 and result.stdout == b""
        assert result.stderr == b"CUSTODY_UNAVAILABLE\n", result.stderr


def expect_unavailable(result):
    assert result.returncode == 4 and result.stdout == b"", result
    assert result.stderr == b"CUSTODY_UNAVAILABLE\n", result.stderr


def fake_server_rejected_before_tls(binary, profile, private, impostor_home):
    endpoint = impostor_home / "impostor.sock"
    code = (
        "import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); "
        "s.listen(1); c,_=s.accept(); c.settimeout(2); "
        "\ntry: data=c.recv(1)\nexcept TimeoutError: data=b''\n"
        "print(len(data), flush=True)"
    )
    server = subprocess.Popen(
        ["sudo", "-n", "-u", OTHER, sys.executable, "-c", code, str(endpoint)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not endpoint.exists() and server.poll() is None:
        time.sleep(0.02)
    assert endpoint.exists(), server.communicate(timeout=1)
    probe(binary, AGENT, profile, private, endpoint, allowed=False)
    stdout, stderr = server.communicate(timeout=5)
    assert server.returncode == 0 and stdout == b"0\n" and stderr == b"", (stdout, stderr)


def main():
    assert sys.platform == "darwin" and os.geteuid() != 0
    assert os.environ.get("PM_MACOS_EPHEMERAL_CI") == "1"
    binary, cli, source_plist = map(lambda value: pathlib.Path(value).resolve(), sys.argv[1:])
    guarded = [INSTALL, STATE, RUNTIME, PLIST]
    collisions = [str(path) for path in guarded if path.exists()]
    assert not collisions, f"refusing to replace pre-existing host paths: {collisions}"
    assert sudo(["launchctl", "print", f"system/{LABEL}"], check=False).returncode != 0, \
        f"refusing to replace pre-existing launchd job: {LABEL}"
    for name in (CUSTODIAN, AGENT, OTHER):
        for record in (f"/Users/{name}", f"/Groups/{name}"):
            assert run(["dscl", ".", "-read", record], check=False).returncode != 0

    created = []
    bootstrapped = False
    scratch = pathlib.Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "pm-ticket26"
    assert not scratch.exists(), f"refusing to replace pre-existing scratch path: {scratch}"
    try:
        scratch.mkdir(mode=0o700)
        custodian_uid, agent_uid, other_uid = unused_ids(3)
        for name, uid in [(CUSTODIAN, custodian_uid), (AGENT, agent_uid), (OTHER, other_uid)]:
            created.append(name); create_account(name, uid)

        sudo(["mkdir", "-p", INSTALL, STATE, RUNTIME])
        sudo(["install", "-o", "root", "-g", "wheel", "-m", "0755", binary, INSTALL / "pm-custody"])
        sudo(["install", "-o", "root", "-g", "wheel", "-m", "0755", cli, INSTALL / "pm"])
        sudo(["chown", f"{CUSTODIAN}:{CUSTODIAN}", STATE, RUNTIME])
        sudo(["chmod", "0700", STATE]); sudo(["chmod", "0755", RUNTIME])

        human = scratch / "human"; profiles = scratch / "profiles"
        sudo(["mkdir", "-p", human, profiles])
        sudo(["chown", f"{os.getuid()}:{os.getgid()}", human]); sudo(["chmod", "0700", human])
        agent = scratch / "agent"; other = scratch / "other"
        impostor = scratch / "impostor"
        sudo(["mkdir", "-p", agent, other, impostor])
        sudo(["chown", f"{AGENT}:{AGENT}", agent]); sudo(["chmod", "0700", agent])
        sudo(["chown", f"{OTHER}:{OTHER}", other]); sudo(["chmod", "0700", other])
        sudo(["chown", f"{OTHER}:{OTHER}", impostor]); sudo(["chmod", "0755", impostor])

        server_key, server_pub = STATE / "server.key", STATE / "server.pub"
        human_key, human_pub = human / "human.key", human / "human.pub"
        agent_key, agent_pub = agent / "agent.key", agent / "agent.pub"
        other_key, other_pub = other / "other.key", other / "other.pub"
        keygen(INSTALL / "pm-custody", CUSTODIAN, server_key, server_pub)
        run([INSTALL / "pm-custody", "keygen", "--private", human_key, "--public", human_pub])
        keygen(INSTALL / "pm-custody", AGENT, agent_key, agent_pub)
        keygen(INSTALL / "pm-custody", OTHER, other_key, other_pub)

        bootstrap = STATE / "bootstrap"
        sudo([INSTALL / "pm-custody", "provision-bootstrap", "--path", bootstrap,
              "--server-private", server_key, "--server-public", server_pub,
              "--agent-public", agent_pub, "--agent-uid", str(agent_uid),
              "--human-public", human_pub, "--human-uid", str(os.getuid())], user=CUSTODIAN)
        agent_profile, human_profile = profiles / "agent.profile", profiles / "human.profile"
        for role, profile in [("agent", agent_profile), ("human", human_profile)]:
            sudo([INSTALL / "pm-custody", "provision-profile", "--path", profile,
                  "--server-public", server_pub, "--server-uid", str(custodian_uid),
                  "--role", role])
        sudo(["chmod", "0444", agent_profile, human_profile])
        create_vault(INSTALL / "pm", STATE / "vault.sqlite3")

        sudo(["install", "-o", "root", "-g", "wheel", "-m", "0644", source_plist, PLIST])
        sudo(["plutil", "-lint", PLIST])
        sudo(["launchctl", "bootstrap", "system", PLIST]); bootstrapped = True
        wait_for_service()
        service = sudo(["launchctl", "print", f"system/{LABEL}"]).stdout.decode()
        pid = int(re.search(r"\bpid = (\d+)", service).group(1))
        process_user = run(["ps", "-o", "user=", "-p", str(pid)]).stdout.decode().strip()
        assert process_user == CUSTODIAN, (pid, process_user)
        process_command = run(["ps", "-o", "command=", "-p", str(pid)]).stdout.decode().strip()
        assert process_command.split()[0] == str(INSTALL / "pm-custody"), process_command

        for path, uid, mode in [(INSTALL / "pm-custody", 0, 0o755),
                                (PLIST, 0, 0o644), (bootstrap, custodian_uid, 0o400)]:
            metadata = path.stat()
            assert metadata.st_uid == uid and stat.S_IMODE(metadata.st_mode) == mode
        probe(INSTALL / "pm-custody", AGENT, agent_profile, agent_key, RUNTIME / "agent.sock")
        probe(INSTALL / "pm-custody", pwd.getpwuid(os.getuid()).pw_name,
              human_profile, human_key, RUNTIME / "human.sock")

        # Give the wrong native UID the correct synthetic TLS key. Kernel peer
        # authentication must still reject it before request processing.
        copied_key = other / "agent-copy.key"
        sudo(["cp", agent_key, copied_key]); sudo(["chown", f"{OTHER}:{OTHER}", copied_key])
        sudo(["chmod", "0400", copied_key])
        probe(INSTALL / "pm-custody", OTHER, agent_profile, copied_key,
              RUNTIME / "agent.sock", allowed=False)
        probe(INSTALL / "pm-custody", AGENT, human_profile, agent_key,
              RUNTIME / "human.sock", allowed=False)
        probe(INSTALL / "pm-custody", pwd.getpwuid(os.getuid()).pw_name,
              agent_profile, human_key, RUNTIME / "agent.sock", allowed=False)
        fake_server_rejected_before_tls(INSTALL / "pm-custody", agent_profile,
                                        agent_key, impostor)

        for protected in [bootstrap, STATE / "vault.sqlite3"]:
            denied = sudo(["cat", protected], user=AGENT, check=False)
            assert denied.returncode != 0 and denied.stdout == b""
        for protected in [INSTALL / "pm-custody", PLIST, bootstrap]:
            denied = sudo(["chmod", "0777", protected], user=AGENT, check=False)
            assert denied.returncode != 0
        denied_service_control = sudo(
            ["launchctl", "bootout", f"system/{LABEL}"], user=AGENT, check=False,
        )
        assert denied_service_control.returncode != 0
        sudo(["chmod", "0600", agent_key], user=AGENT)
        probe(INSTALL / "pm-custody", AGENT, agent_profile, agent_key,
              RUNTIME / "agent.sock", allowed=False)
        sudo(["chmod", "0400", agent_key], user=AGENT)

        # Missing, malformed, or permission-broadened bootstrap must terminate
        # explicitly rather than generating or selecting substitute identity.
        for bad_bootstrap in [scratch / "missing-bootstrap", other / "corrupt-bootstrap",
                              other / "wide-bootstrap"]:
            if bad_bootstrap.name == "corrupt-bootstrap":
                sudo([sys.executable, "-c",
                      "import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(b'synthetic-corruption')",
                      bad_bootstrap], user=OTHER)
                sudo(["chmod", "0400", bad_bootstrap], user=OTHER)
            elif bad_bootstrap.name == "wide-bootstrap":
                sudo(["cp", bootstrap, bad_bootstrap])
                sudo(["chown", f"{OTHER}:{OTHER}", bad_bootstrap]); sudo(["chmod", "0440", bad_bootstrap])
            failure = sudo(
                [INSTALL / "pm-custody", "serve", "--bootstrap", bad_bootstrap,
                 "--agent-socket", other / f"{bad_bootstrap.name}-agent.sock",
                 "--human-socket", other / f"{bad_bootstrap.name}-human.sock"],
                user=OTHER, check=False,
            )
            expect_unavailable(failure)

        setup = run([INSTALL / "pm-custody", "human-authorization", "--profile", human_profile,
                     "--private", human_key, "--socket", RUNTIME / "human.sock", "--action", "setup"],
                    input=wire_fields([PASSWORD, agent_pub.read_bytes(), other_pub.read_bytes()]))
        assert setup.stdout == b"PASS human-authorization action=setup\n" and setup.stderr == b""
        suspend = run([INSTALL / "pm-custody", "human-authorization", "--profile", human_profile,
                       "--private", human_key, "--socket", RUNTIME / "human.sock", "--action", "suspend"],
                      input=wire_fields([PASSWORD]))
        assert suspend.stdout == b"PASS human-authorization action=suspend\n" and suspend.stderr == b""
        sudo(["launchctl", "kickstart", "-k", f"system/{LABEL}"])
        time.sleep(1); wait_for_service()
        discover = sudo([INSTALL / "pm-custody", "agent-discover", "--profile", agent_profile,
                         "--private", agent_key, "--socket", RUNTIME / "agent.sock"],
                        user=AGENT, check=False)
        assert discover.returncode == 4 and discover.stdout == b""
        assert discover.stderr == b"CUSTODY_UNAVAILABLE\n"

        tty_clipboard = run(["script", "-q", "/dev/null", INSTALL / "pm-custody", "macos-native-probe"])
        assert b"PASS macos-native tty=real rlimit-core=0 clipboard=AppKit-changeCount" in tty_clipboard.stdout
        print("PASS macos-launchdaemon account=_passwordmanager peer=getpeereid bilateral=tls-rpk")
        print("PASS macos-acl bootstrap=0400 binary+plist=root-owned wrong-uid=rejected")
        print("PASS macos-persistence suspension=durable launchd-restart=real")
        print("PASS macos-native tty=/dev/tty clipboard=AppKit-changeCount fullfsync=queried-tests")
        print("LIMIT reboot=NOT_RUN intel+arm64=handled-by-ticket31 signing+notarization=NOT_RUN")
    finally:
        if bootstrapped:
            sudo(["launchctl", "bootout", f"system/{LABEL}"], check=False)
        for path in [PLIST, INSTALL, STATE, RUNTIME, scratch]:
            sudo(["rm", "-rf", path], check=False)
        for name in reversed(created):
            sudo(["dscl", ".", "-delete", f"/Users/{name}"], check=False)
            sudo(["dscl", ".", "-delete", f"/Groups/{name}"], check=False)


if __name__ == "__main__":
    main()
