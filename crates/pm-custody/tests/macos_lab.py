#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

"""Destructive-only-inside-ephemeral-CI native macOS custody laboratory."""

import ctypes
import os
import pathlib
import plistlib
import pwd
import re
import shlex
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
DIAGNOSTIC_ENV = "PM_MACOS_TICKET26_DIAGNOSTIC"
DIAGNOSTIC_LOG = STATE / "ticket26-diagnostic.log"
DIAGNOSTIC_LINE = re.compile(
    rb"(?:PM26_DIAGNOSTIC phase=[a-z-]+|"
    rb"PM26_DIAGNOSTIC accepted-stream-nonblocking-(?:before|after)=[01]|"
    rb"PM26_DIAGNOSTIC error=[a-z-]+|"
    rb"PM26_DIAGNOSTIC client-human-unlock-result="
    rb"(?:timeout|eof|other-io|malformed-frame|status-nonzero) elapsed-ms=[0-9]{1,6}|"
    rb"PM26_DIAGNOSTIC server-human-unlock-result="
    rb"(?:ok|vault-error) elapsed-ms=[0-9]{1,6}|"
    rb"PM26_DIAGNOSTIC launchd-service="
    rb"(?:same-pid|different-pid|unavailable|unparseable)|"
    rb"PM26_DIAGNOSTIC unlock-phase="
    rb"(?:channel-verified|sqlite-opened|durability-configured|bundle-loaded|"
    rb"kdf-start|kdf-end|root-authenticated) elapsed-ms=[0-9]{1,6}|"
    rb"PM26_DIAGNOSTIC vault-root-create-ms=[0-9]{1,6}|"
    rb"PM26_DIAGNOSTIC sodium-cflags=(?:opt0|optimized))$"
)
PEER_UID_SCRIPT = """
import ctypes, socket, sys
stream = socket.socket(socket.AF_UNIX)
stream.connect(sys.argv[1])
uid = ctypes.c_uint(0)
gid = ctypes.c_uint(0)
libc = ctypes.CDLL(None, use_errno=True)
libc.getpeereid.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint)]
libc.getpeereid.restype = ctypes.c_int
assert libc.getpeereid(stream.fileno(), ctypes.byref(uid), ctypes.byref(gid)) == 0
print(uid.value, flush=True)
if len(sys.argv) == 3:
    assert stream.recv(1) == b'x'
"""


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


def create_account(name, uid, owned_records):
    group = f"/Groups/{name}"
    user = f"/Users/{name}"
    sudo(["dscl", ".", "-create", group])
    owned_records.append(group)
    sudo(["dscl", ".", "-create", group, "PrimaryGroupID", str(uid)])
    sudo(["dscl", ".", "-create", user])
    owned_records.append(user)
    for attribute, value in [
        ("RealName", f"Password Manager ticket 26 {name}"),
        ("UniqueID", str(uid)), ("PrimaryGroupID", str(uid)),
        ("NFSHomeDirectory", "/var/empty"), ("UserShell", "/usr/bin/false"),
        ("IsHidden", "1"), ("Password", "*"),
    ]:
        sudo(["dscl", ".", "-create", user, attribute, value])


class OwnedCleanupError(AssertionError):
    def __init__(self, errors):
        self.errors = tuple(errors)
        super().__init__("; ".join(str(error) for error in self.errors))


def parse_launchctl_labels(output):
    try:
        lines = output.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise AssertionError("launchd cleanup inventory is malformed") from error
    assert lines and lines[0] == "PID\tStatus\tLabel", \
        "launchd cleanup inventory is malformed"
    labels = set()
    for line in lines[1:]:
        fields = line.split("\t")
        assert len(fields) == 3, "launchd cleanup inventory is malformed"
        pid, status, label = fields
        assert (pid == "-" or pid.isascii() and pid.isdecimal()), \
            "launchd cleanup inventory is malformed"
        assert re.fullmatch(r"-?[0-9]+", status), \
            "launchd cleanup inventory is malformed"
        assert label and not any(ord(character) < 0x20 for character in label), \
            "launchd cleanup inventory is malformed"
        labels.add(label)
    return labels


def parse_directory_records(output):
    try:
        records = output.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise AssertionError("directory cleanup inventory is malformed") from error
    assert records, "directory cleanup inventory is malformed"
    assert all(record and not any(ord(character) < 0x20 for character in record)
               for record in records), "directory cleanup inventory is malformed"
    return set(records)


def require_safe_existing_parent(path):
    result = sudo(["stat", "-f", "%u %p", path])
    try:
        owner, encoded_mode = result.stdout.decode().strip().split()
        full_mode = int(encoded_mode, 8)
        assert int(owner) == 0 and stat.S_ISDIR(full_mode)
        assert stat.S_IMODE(full_mode) & 0o022 == 0
    except (AssertionError, UnicodeDecodeError, ValueError) as error:
        raise AssertionError("fixed install parent is not a safe root directory") from error


def cleanup_owned_resources(
    bootstrapped, owned_paths, owned_empty_directories, owned_records, invoke=sudo,
    path_exists=os.path.lexists,
):
    errors = []

    def attempt(action, command):
        try:
            result = invoke(command, check=False)
            if result.returncode != 0:
                errors.append(AssertionError(
                    f"owned cleanup failed: action={action} returncode={result.returncode}"
                ))
        except BaseException as error:
            errors.append(AssertionError(f"owned cleanup raised: action={action}"))
            errors[-1].__cause__ = error

    if bootstrapped:
        attempt("launchd-bootout", ["launchctl", "bootout", f"system/{LABEL}"])
    for name, path in reversed(owned_paths):
        attempt(f"remove-{name}", ["rm", "-rf", path])
    for name, path in reversed(owned_empty_directories):
        attempt(f"rmdir-{name}", ["rmdir", path])
    for record in reversed(owned_records):
        kind = "user" if record.startswith("/Users/") else "group"
        attempt(f"delete-{kind}", ["dscl", ".", "-delete", record])

    if bootstrapped:
        try:
            result = invoke(["launchctl", "list"], check=False)
            if result.returncode != 0:
                raise AssertionError("launchd cleanup inventory query failed")
            if LABEL in parse_launchctl_labels(result.stdout):
                errors.append(AssertionError("owned cleanup left launchd job"))
        except BaseException as error:
            wrapped = AssertionError("owned cleanup absence check raised: launchd")
            wrapped.__cause__ = error
            errors.append(wrapped)
    for name, path in owned_paths:
        try:
            if path_exists(path):
                errors.append(AssertionError(f"owned cleanup left path: name={name}"))
        except BaseException as error:
            wrapped = AssertionError("owned cleanup absence check raised: path")
            wrapped.__cause__ = error
            errors.append(wrapped)
    for name, path in owned_empty_directories:
        try:
            if path_exists(path):
                errors.append(AssertionError(f"owned cleanup left directory: name={name}"))
        except BaseException as error:
            wrapped = AssertionError("owned cleanup absence check raised: directory")
            wrapped.__cause__ = error
            errors.append(wrapped)
    for kind, root in (("user", "/Users"), ("group", "/Groups")):
        prefix = f"/{root.strip('/')}/"
        expected = {
            record.rsplit("/", 1)[1]
            for record in owned_records
            if record.startswith(prefix)
        }
        if not expected:
            continue
        try:
            result = invoke(["dscl", ".", "-list", root], check=False)
            if result.returncode != 0:
                raise AssertionError("directory cleanup inventory query failed")
            inventory = parse_directory_records(result.stdout)
            if expected & inventory:
                errors.append(AssertionError(f"owned cleanup left record: kind={kind}"))
        except BaseException as error:
            wrapped = AssertionError("owned cleanup absence check raised: directory-record")
            wrapped.__cause__ = error
            errors.append(wrapped)
    return errors


def finish_owned_resources(
    lab_error, bootstrapped, owned_paths, owned_empty_directories,
    owned_records, invoke=sudo,
):
    cleanup_errors = cleanup_owned_resources(
        bootstrapped, owned_paths, owned_empty_directories, owned_records, invoke
    )
    if lab_error is not None:
        if cleanup_errors:
            raise lab_error from OwnedCleanupError(cleanup_errors)
        raise lab_error
    if cleanup_errors:
        raise OwnedCleanupError(cleanup_errors)


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
    command = [binary, "keygen", "--private", private, "--public", public]
    result = run(command, check=False) if user is None else sudo(
        command, user=user, check=False,
    )
    identity = "runner" if user is None else user
    if result.returncode != 0:
        raise AssertionError(
            f"synthetic keygen failed for {identity}: returncode={result.returncode}, "
            f"stdout={result.stdout[:1024]!r}, stderr={result.stderr[:1024]!r}"
        )


def parse_owner_mode(output):
    owner, mode = output.strip().split()
    full_mode = int(mode, 8)
    assert not stat.S_ISLNK(full_mode), (
        f"refusing symbolic link metadata: owner={owner}, mode={mode}"
    )
    return int(owner), stat.S_IMODE(full_mode)


def owner_mode(path):
    result = sudo(["stat", "-f", "%u %p", path])
    try:
        return parse_owner_mode(result.stdout.decode())
    except (AssertionError, UnicodeDecodeError, ValueError) as error:
        raise AssertionError(
            f"invalid owner/mode metadata: path={path}, raw={result.stdout[:128]!r}"
        ) from error


def require_owner_mode(path, expected):
    actual = owner_mode(path)
    assert actual == expected, (
        f"owner/mode mismatch: path={path}, expected={expected}, actual={actual}"
    )


def parse_regular_metadata(output):
    owner, mode, links, size = output.strip().split()
    full_mode = int(mode, 8)
    assert stat.S_ISREG(full_mode), (
        f"fixture is not a regular file: owner={owner}, mode={mode}, "
        f"links={links}, size={size}"
    )
    return int(owner), stat.S_IMODE(full_mode), int(links), int(size)


def require_readable_regular(user, path, expected_uid, expected_mode):
    metadata = sudo(["stat", "-f", "%u %p %l %z", path])
    actual = parse_regular_metadata(metadata.stdout.decode())
    expected = (expected_uid, expected_mode)
    assert actual[:2] == expected and actual[2] == 1 and 1 <= actual[3] <= 16 * 1024, (
        f"unsafe readable-file metadata: path={path}, expected={expected}, actual={actual}"
    )
    readable = sudo(["test", "-r", path], user=user, check=False)
    assert readable.returncode == 0 and readable.stdout == b"" and readable.stderr == b"", (
        f"effective fixture read failed: user={user}, path={path}, "
        f"returncode={readable.returncode}, stderr={readable.stderr[:1024]!r}"
    )


def require_traversal(user, path):
    result = sudo(["test", "-x", path], user=user, check=False)
    assert result.returncode == 0, (
        f"fixture traversal prerequisite failed: user={user}, path={path}, "
        f"returncode={result.returncode}, stdout={result.stdout[:1024]!r}, "
        f"stderr={result.stderr[:1024]!r}"
    )


def peer_uid(stream):
    uid = ctypes.c_uint(0)
    gid = ctypes.c_uint(0)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.getpeereid.argtypes = [
        ctypes.c_int, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint),
    ]
    libc.getpeereid.restype = ctypes.c_int
    result = libc.getpeereid(stream.fileno(), ctypes.byref(uid), ctypes.byref(gid))
    assert result == 0, f"synthetic getpeereid failed: errno={ctypes.get_errno()}"
    return uid.value


def cross_uid_peer_diagnostic(agent_uid, scratch):
    endpoint = scratch / "cross-uid-diagnostic.sock"
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(endpoint)); endpoint.chmod(0o666)
    require_owner_mode(endpoint, (os.getuid(), 0o666))
    listener.listen(1); listener.settimeout(5)
    client = subprocess.Popen(
        ["sudo", "-n", "-u", AGENT, sys.executable, "-c", PEER_UID_SCRIPT,
         str(endpoint), "wait"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        connection, _ = listener.accept()
        with connection:
            assert peer_uid(connection) == agent_uid
            connection.sendall(b"x")
        stdout, stderr = client.communicate(timeout=5)
        assert client.returncode == 0 and stderr == b"", (
            client.returncode, stdout[:1024], stderr[:1024],
        )
        assert stdout == f"{os.getuid()}\n".encode(), stdout[:1024]
    finally:
        listener.close()
        if client.poll() is None:
            client.kill(); client.wait(timeout=5)
        if endpoint.exists():
            endpoint.unlink()


def launchd_peer_uid(user, endpoint):
    result = sudo(
        [sys.executable, "-c", PEER_UID_SCRIPT, endpoint],
        user=user, check=False,
    )
    assert result.returncode == 0 and result.stderr == b"", (
        result.returncode, result.stdout[:1024], result.stderr[:1024],
    )
    return int(result.stdout.decode().strip())


def publish_rpk(source, destination):
    sudo(["install", "-o", "root", "-g", "wheel", "-m", "0444", source, destination])
    require_owner_mode(destination, (0, 0o444))
    assert sudo(["cmp", "-s", source, destination], check=False).returncode == 0


def create_vault(cli, path):
    process = subprocess.Popen(
        ["sudo", "-n", "-u", CUSTODIAN, str(cli), "vault", "create", str(path)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert process.stdout.readline() == b"Master password (read from stdin):\n"
    process.stdin.write(PASSWORD + b"\n"); process.stdin.flush()
    assert process.stdout.readline() == b"Confirm master password:\n"
    process.stdin.write(PASSWORD + b"\n"); process.stdin.flush()
    derivation_started = time.monotonic_ns()
    recovery = process.stdout.readline()
    derivation_ms = min((time.monotonic_ns() - derivation_started) // 1_000_000, 999_999)
    creation_status = f"PM26_DIAGNOSTIC vault-root-create-ms={derivation_ms}".encode()
    diagnostic_lines(creation_status)
    print(creation_status.decode())
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


def diagnostic_lines(value):
    lines = value.splitlines()
    assert lines and len(lines) <= 32 and all(DIAGNOSTIC_LINE.fullmatch(line) for line in lines), (
        "unsafe or missing ticket-26 diagnostic output", len(lines),
    )
    return lines


def parse_sodium_cflags(config_log):
    values = re.findall(rb"(?m)^CFLAGS='([^']*)'$", config_log)
    assert len(values) == 1, "native libsodium build metadata is unavailable or ambiguous"
    try:
        flags = shlex.split(values[0].decode("ascii"))
    except (UnicodeDecodeError, ValueError) as error:
        raise AssertionError(
            "native libsodium build metadata is unavailable or ambiguous"
        ) from error
    opt0 = "-O0" in flags
    optimized = any(flag in {"-O1", "-O2", "-O3", "-Os", "-Oz", "-Ofast"} for flag in flags)
    assert opt0 != optimized, "native libsodium build metadata is unavailable or ambiguous"
    return b"opt0" if opt0 else b"optimized"


def classify_native_sodium(config_log):
    assert config_log.is_file(), "native libsodium build metadata is unavailable"
    classification = parse_sodium_cflags(config_log.read_bytes())
    status = b"PM26_DIAGNOSTIC sodium-cflags=" + classification
    diagnostic_lines(status)
    print(status.decode())


def classify_launchd_service(result, expected_pid):
    if result.returncode != 0:
        return b"unavailable"
    if result.stderr:
        return b"unparseable"
    match = re.search(rb"\bpid = ([0-9]+)\b", result.stdout)
    if match is None:
        return b"unparseable"
    return b"same-pid" if int(match.group(1)) == expected_pid else b"different-pid"


def human_authorization_setup(binary, profile, private, endpoint, first, second, service_pid):
    command = [
        "env", f"{DIAGNOSTIC_ENV}=1", binary, "human-authorization",
        "--profile", profile, "--private", private, "--socket", endpoint,
        "--action", "setup",
    ]
    result = run(command, check=False, input=wire_fields([PASSWORD, first, second]))
    diagnostic_stderr = result.stderr
    if result.returncode == 4:
        assert diagnostic_stderr.endswith(b"CUSTODY_UNAVAILABLE\n")
        diagnostic_stderr = diagnostic_stderr.removesuffix(b"CUSTODY_UNAVAILABLE\n")
    assert result.returncode in (0, 4), (
        "human authorization setup exited outside its public contract",
        result.returncode,
    )
    client = diagnostic_lines(diagnostic_stderr)
    if result.returncode == 4:
        launchd = sudo(["launchctl", "print", f"system/{LABEL}"], check=False)
        classification = classify_launchd_service(launchd, service_pid)
        status = b"PM26_DIAGNOSTIC launchd-service=" + classification
        diagnostic_lines(status + b"\n")
        print(status.decode())
    service = sudo(["tail", "-n", "32", DIAGNOSTIC_LOG], check=False)
    assert service.returncode == 0 and service.stderr == b"", (
        "custodian diagnostic log unavailable", service.returncode,
    )
    server = diagnostic_lines(service.stdout)
    print("PM26_DIAGNOSTIC client=" + ",".join(line.decode() for line in client))
    print("PM26_DIAGNOSTIC server=" + ",".join(line.decode() for line in server))
    if result.returncode == 0:
        assert result.stdout == b"PASS human-authorization action=setup\n"
        return result
    assert result.stdout == b""
    raise AssertionError(
        "human authorization setup remained unavailable; see fixed PM26_DIAGNOSTIC lines"
    )


def probe(binary, user, profile, private, endpoint, *, allowed=True, diagnostic=False):
    command = [binary, "probe", "--profile", profile, "--private", private,
               "--socket", endpoint]
    if diagnostic:
        command = ["env", f"{DIAGNOSTIC_ENV}=1"] + command
    result = sudo(command, user=user, check=False)
    diagnostic_stderr = result.stderr
    if diagnostic and result.returncode == 4:
        assert diagnostic_stderr.endswith(b"CUSTODY_UNAVAILABLE\n")
        diagnostic_stderr = diagnostic_stderr.removesuffix(b"CUSTODY_UNAVAILABLE\n")
    if diagnostic:
        client = diagnostic_lines(diagnostic_stderr)
        service = sudo(["cat", DIAGNOSTIC_LOG]).stdout
        server = diagnostic_lines(service)[-32:]
        assert b"PM26_DIAGNOSTIC accepted-stream-nonblocking-before=1" in server
        assert b"PM26_DIAGNOSTIC accepted-stream-nonblocking-after=0" in server
        print("PM26_DIAGNOSTIC client=" + ",".join(line.decode() for line in client))
        print("PM26_DIAGNOSTIC server=" + ",".join(line.decode() for line in server))
    if allowed:
        assert result.returncode == 0 and (diagnostic or result.stderr == b""), result
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
        "import os,socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); "
        "os.chmod(sys.argv[1], 0o666); "
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
    binary, cli, source_plist, sodium_config = map(
        lambda value: pathlib.Path(value).resolve(), sys.argv[1:]
    )
    classify_native_sodium(sodium_config)
    guarded = [INSTALL, STATE, RUNTIME, PLIST]
    collisions = [str(path) for path in guarded if path.exists()]
    assert not collisions, f"refusing to replace pre-existing host paths: {collisions}"
    assert sudo(["launchctl", "print", f"system/{LABEL}"], check=False).returncode != 0, \
        f"refusing to replace pre-existing launchd job: {LABEL}"
    for name in (CUSTODIAN, AGENT, OTHER):
        for record in (f"/Users/{name}", f"/Groups/{name}"):
            assert run(["dscl", ".", "-read", record], check=False).returncode != 0

    owned_records = []
    owned_paths = []
    owned_empty_directories = []
    bootstrapped = False
    lab_error = None
    scratch = pathlib.Path("/private/var/tmp/passwordmanager-ticket26")
    require_owner_mode(scratch.parent, (0, 0o1777))
    assert not scratch.exists(), f"refusing to replace pre-existing scratch path: {scratch}"
    try:
        scratch.mkdir(mode=0o711)
        owned_paths.append(("scratch", scratch))
        scratch.chmod(0o711)
        require_owner_mode(scratch, (os.getuid(), 0o711))
        custodian_uid, agent_uid, other_uid = unused_ids(3)
        for name, uid in [(CUSTODIAN, custodian_uid), (AGENT, agent_uid), (OTHER, other_uid)]:
            create_account(name, uid, owned_records)
        for name in (CUSTODIAN, AGENT, OTHER):
            require_traversal(name, scratch.parent)
            require_traversal(name, scratch)
        observed_agent_uid = sudo(["id", "-u"], user=AGENT).stdout.decode().strip()
        assert observed_agent_uid == str(agent_uid), observed_agent_uid
        cross_uid_peer_diagnostic(agent_uid, scratch)

        install_parent = INSTALL.parent
        if os.path.lexists(install_parent):
            require_safe_existing_parent(install_parent)
        else:
            sudo(["install", "-d", "-o", "root", "-g", "wheel", "-m", "0755", install_parent])
            owned_empty_directories.append(("install-parent", install_parent))
            require_owner_mode(install_parent, (0, 0o755))

        for name, path in [("install", INSTALL), ("state", STATE), ("runtime", RUNTIME)]:
            sudo(["mkdir", path])
            owned_paths.append((name, path))
        sudo(["install", "-o", "root", "-g", "wheel", "-m", "0755", binary, INSTALL / "pm-custody"])
        sudo(["install", "-o", "root", "-g", "wheel", "-m", "0755", cli, INSTALL / "pm"])
        sudo(["chown", f"{CUSTODIAN}:{CUSTODIAN}", STATE, RUNTIME])
        sudo(["chmod", "0700", STATE]); sudo(["chmod", "0755", RUNTIME])

        human = scratch / "human"; profiles = scratch / "profiles"
        publics = scratch / "public-rpks"
        sudo(["mkdir", "-p", human, profiles, publics])
        sudo(["chown", f"{os.getuid()}:{os.getgid()}", human]); sudo(["chmod", "0700", human])
        sudo(["chown", "root:wheel", profiles, publics])
        sudo(["chmod", "0755", profiles, publics])
        agent = scratch / "agent"; other = scratch / "other"
        impostor = scratch / "impostor"
        sudo(["mkdir", "-p", agent, other, impostor])
        sudo(["chown", f"{AGENT}:{AGENT}", agent]); sudo(["chmod", "0700", agent])
        sudo(["chown", f"{OTHER}:{OTHER}", other]); sudo(["chmod", "0700", other])
        sudo(["chown", f"{OTHER}:{OTHER}", impostor]); sudo(["chmod", "0755", impostor])
        for user, private in [(AGENT, human), (OTHER, human),
                              (CUSTODIAN, agent), (OTHER, agent),
                              (CUSTODIAN, other), (AGENT, other)]:
            denied = sudo(["test", "-r", private], user=user, check=False)
            assert denied.returncode != 0 and denied.stdout == b"", (user, private)

        server_key, server_pub = STATE / "server.key", STATE / "server.pub"
        human_key, human_pub = human / "human.key", human / "human.pub"
        agent_key, agent_pub = agent / "agent.key", agent / "agent.pub"
        other_key, other_pub = other / "other.key", other / "other.pub"
        keygen(INSTALL / "pm-custody", CUSTODIAN, server_key, server_pub)
        keygen(INSTALL / "pm-custody", None, human_key, human_pub)
        keygen(INSTALL / "pm-custody", AGENT, agent_key, agent_pub)
        keygen(INSTALL / "pm-custody", OTHER, other_key, other_pub)
        published_human_pub = publics / "human.pub"
        published_agent_pub = publics / "agent.pub"
        published_other_pub = publics / "other.pub"
        for source, destination in [(human_pub, published_human_pub),
                                    (agent_pub, published_agent_pub),
                                    (other_pub, published_other_pub)]:
            publish_rpk(source, destination)

        bootstrap = STATE / "bootstrap"
        sudo([INSTALL / "pm-custody", "provision-bootstrap", "--path", bootstrap,
              "--server-private", server_key, "--server-public", server_pub,
              "--agent-public", published_agent_pub, "--agent-uid", str(agent_uid),
              "--human-public", published_human_pub, "--human-uid", str(os.getuid())],
             user=CUSTODIAN)
        agent_profile, human_profile = profiles / "agent.profile", profiles / "human.profile"
        for role, profile in [("agent", agent_profile), ("human", human_profile)]:
            sudo([INSTALL / "pm-custody", "provision-profile", "--path", profile,
                  "--server-public", server_pub, "--server-uid", str(custodian_uid),
                  "--role", role])
        sudo(["chmod", "0444", agent_profile, human_profile])
        create_vault(INSTALL / "pm", STATE / "vault.sqlite3")

        diagnostic_plist = scratch / "ticket26-launchd.plist"
        with open(source_plist, "rb") as source:
            launchd_config = plistlib.load(source)
        assert "EnvironmentVariables" not in launchd_config
        assert "StandardErrorPath" not in launchd_config
        launchd_config["EnvironmentVariables"] = {DIAGNOSTIC_ENV: "1"}
        launchd_config["StandardErrorPath"] = str(DIAGNOSTIC_LOG)
        with open(diagnostic_plist, "wb") as destination:
            plistlib.dump(launchd_config, destination)
        sudo(["install", "-o", "root", "-g", "wheel", "-m", "0644", diagnostic_plist, PLIST])
        owned_paths.append(("plist", PLIST))
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
                                (PLIST, 0, 0o644), (bootstrap, custodian_uid, 0o400),
                                (agent_profile, 0, 0o444),
                                (published_agent_pub, 0, 0o444),
                                (agent_key, agent_uid, 0o400),
                                (RUNTIME / "agent.sock", custodian_uid, 0o666)]:
            require_owner_mode(path, (uid, mode))
        require_owner_mode(profiles, (0, 0o755))
        require_traversal(AGENT, profiles)
        require_traversal(AGENT, agent)
        require_readable_regular(AGENT, agent_profile, 0, 0o444)
        require_readable_regular(AGENT, agent_key, agent_uid, 0o400)
        assert launchd_peer_uid(AGENT, RUNTIME / "agent.sock") == custodian_uid
        probe(INSTALL / "pm-custody", AGENT, agent_profile, agent_key,
              RUNTIME / "agent.sock", diagnostic=True)
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

        human_authorization_setup(
            INSTALL / "pm-custody", human_profile, human_key, RUNTIME / "human.sock",
            published_agent_pub.read_bytes(), published_other_pub.read_bytes(), pid,
        )
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
    except BaseException as error:
        lab_error = error

    finish_owned_resources(
        lab_error,
        bootstrapped, owned_paths, owned_empty_directories, owned_records
    )
    print("PASS macos-launchdaemon account=_passwordmanager peer=getpeereid bilateral=tls-rpk")
    print("PASS macos-acl bootstrap=0400 binary+plist=root-owned wrong-uid=rejected")
    print("PASS macos-persistence suspension=durable launchd-restart=real")
    print("PASS macos-native tty=/dev/tty clipboard=AppKit-changeCount fullfsync=queried-tests")
    print("LIMIT reboot=NOT_RUN intel+arm64=handled-by-ticket31 signing+notarization=NOT_RUN")


if __name__ == "__main__":
    main()
