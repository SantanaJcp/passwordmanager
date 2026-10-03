# SPDX-License-Identifier: AGPL-3.0-only
"""Closed inventory and complete reads for the ticket-28 owned Linux labs."""
import errno
import hashlib
import json
import os
import pathlib
import signal
import stat
import subprocess
import sys

from linux_lab import AGENT


def scan_bytes(data, canaries, channel):
    assert all(value not in data for value in canaries), "plaintext canary in " + channel


def scan_file(path, canaries, channel):
    before = path.stat()
    total, tail = 0, b""
    overlap = max(map(len, canaries)) - 1
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            scan_bytes(tail + block, canaries, channel)
            total += len(block)
            tail = (tail + block)[-overlap:]
    after = path.stat()
    assert (before.st_ino, before.st_size, before.st_mtime_ns) == (after.st_ino, after.st_size, after.st_mtime_ns), "rotated channel " + channel
    assert total == before.st_size, "truncated channel " + channel
    return total


# This observer is run as the actual agent UID. Its positive child belongs to
# that UID and has a known live address, so Yama/invalid-address denial cannot
# produce a false positive for either memory syscall.
AGENT_OBSERVER = r'''
import ctypes, errno, json, os, pathlib, signal, sys
request = json.loads(sys.stdin.buffer.read())
libc = ctypes.CDLL(None, use_errno=True)
class Iovec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]
def vm(pid, address):
    buffer = ctypes.create_string_buffer(32)
    local = Iovec(ctypes.addressof(buffer), 32)
    remote = Iovec(address, 32)
    ctypes.set_errno(0)
    size = libc.process_vm_readv(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
    return size, ctypes.get_errno(), buffer.raw
def ptrace(pid):
    ctypes.set_errno(0)
    result = libc.ptrace(16, pid, None, None)
    error = ctypes.get_errno()
    if result == 0:
        waited, status = os.waitpid(pid, os.WUNTRACED)
        assert waited == pid and os.WIFSTOPPED(status)
        assert libc.ptrace(17, pid, None, None) == 0
        os.kill(pid, signal.SIGCONT)
    return result, error
control_bytes = ctypes.create_string_buffer(b"PM28_AGENT_MEMORY_POSITIVE".ljust(32, b"!"))
reader, writer = os.pipe()
control = os.fork()
if control == 0:
    os.close(reader)
    os.write(writer, b"ready")
    os.close(writer)
    signal.pause()
    os._exit(0)
os.close(writer)
try:
    assert os.read(reader, 5) == b"ready"
    size, error, content = vm(control, ctypes.addressof(control_bytes))
    assert size == 32 and content == control_bytes.raw[:32], "process_vm_readv positive control"
    assert ptrace(control) == (0, 0), "ptrace positive control"
    denied = 0
    for path in request["private"]:
        try:
            pathlib.Path(path).read_bytes()
        except PermissionError as error:
            assert error.errno in (errno.EACCES, errno.EPERM)
            denied += 1
        else:
            raise AssertionError("agent read a private channel")
    canaries = [bytes.fromhex(value) for value in request["canaries"]]
    for path in request["resources"]:
        with open(path, "rb") as stream:
            value = stream.read()
        assert all(canary not in value for canary in canaries), "agent resource canary"
        assert len(value) == os.stat(path).st_size, "agent resource truncated"
    for pid in request["pids"]:
        size, error, _ = vm(pid, ctypes.addressof(control_bytes))
        assert size == -1 and error == errno.EPERM, "agent memory target must deny by authority"
        assert ptrace(pid) == (-1, errno.EPERM), "agent ptrace target must deny"
        for resource in ("fd", "maps", "mem"):
            try:
                if resource == "fd":
                    list(pathlib.Path(f"/proc/{pid}/fd").iterdir())
                else:
                    descriptor = os.open(f"/proc/{pid}/{resource}", os.O_RDONLY)
                    os.close(descriptor)
            except PermissionError as error:
                assert error.errno in (errno.EACCES, errno.EPERM)
            else:
                raise AssertionError("agent opened protected process resource")
        for channel in ("cmdline", "environ"):
            try:
                value = pathlib.Path(f"/proc/{pid}/{channel}").read_bytes()
            except PermissionError as error:
                assert error.errno in (errno.EACCES, errno.EPERM)
            else:
                assert all(canary not in value for canary in canaries)
    print("PM28_AGENT_CHANNELS control=vm+ptrace files-denied=" + str(denied) + " targets=" + str(len(request["pids"])) + " resources=" + str(len(request["resources"])) + " complete=1")
finally:
    os.close(reader)
    os.kill(control, signal.SIGTERM)
    assert os.waitpid(control, 0)[0] == control
'''


class Channels:
    def __init__(self, fixture, canaries):
        self.root = fixture["root"]
        self.canaries = tuple(canaries)
        self.files = {}
        self.directories = {self.root}
        self.sockets = set()
        self.assets = {}
        self.required = set()
        self.processes = []
        self.streams = []
        self.logdir = self.root / "observations"
        self.logdir.mkdir(mode=0o700)
        self.directories.add(self.logdir)
        for name in ("state", "run", "human", "agent", "profiles"):
            self.directories.add(self.root / name)
        for name in ("binary", "cli", "interposer"):
            path = fixture[name]
            self.assets[path] = hashlib.sha256(path.read_bytes()).digest()
            self.required.add(path)
        for name in ("server_key", "server_pub", "bootstrap", "human_key", "human_pub", "agent_key", "agent_pub", "human_profile", "events", "pid_path", "vault"):
            self.register(fixture[name], "database" if name == "vault" else "logs" if name == "events" else "agent-resources" if name.startswith("agent_") else "owned-temporaries")
        self.required.update(fixture[name] for name in ("server_key", "server_pub", "bootstrap", "human_key", "human_pub", "agent_key", "agent_pub", "human_profile", "events", "pid_path", "vault"))
        vault = fixture["vault"]
        self.register(pathlib.Path(str(vault) + ".audit-custody"), "audit")
        for suffix, channel in (("-wal", "wal"), ("-shm", "shm"), ("-journal", "journal")):
            self.register(pathlib.Path(str(vault) + suffix), channel)
        self.sockets.update((fixture["agent_socket"], fixture["human_socket"]))
        self.observer = self.root / "agent-observer.py"
        self.observer.write_text(AGENT_OBSERVER)
        self.observer.chmod(0o555)
        self.assets[self.observer] = hashlib.sha256(self.observer.read_bytes()).digest()
        self.required.add(self.observer)

    def register(self, path, channel):
        self.files[path] = channel
        if path.exists():
            self.required.add(path)

    def spawn(self, uid, command, label, *, environment=None, input=None):
        paths = [self.logdir / (label + suffix) for suffix in (".stdout", ".stderr")]
        streams = []
        for path, channel in zip(paths, ("stdout", "stderr")):
            self.register(path, channel)
            stream = path.open("xb", buffering=0)
            self.required.add(path)
            streams.append(stream)
            self.streams.append(stream)
        def identity():
            os.setgroups([])
            os.setgid(uid)
            os.setuid(uid)
        temp = self.root / {0: "observations", 1: "state", 2: "human", 3: "agent", 4: "agent-b", 5: "provider"}[uid] / "owned-tmp"
        if temp not in self.directories:
            temp.mkdir(mode=0o700)
            os.chown(temp, uid, uid)
            self.directories.add(temp)
        child_environment = {} if environment is None else dict(environment)
        child_environment["TMPDIR"] = str(temp)
        process = subprocess.Popen(command, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                                   stdout=streams[0], stderr=streams[1], env=child_environment,
                                   cwd=self.root, preexec_fn=identity)
        self.processes.append((process, paths, label))
        if input is not None:
            process.stdin.write(input)
            process.stdin.close()
            process.stdin = None
        return process

    def result(self, process, timeout=15):
        process.wait(timeout=timeout)
        paths = next(paths for subject, paths, _ in self.processes if subject is process)
        return subprocess.CompletedProcess(process.args, process.returncode, *[path.read_bytes() for path in paths])

    def scan(self, phase, live=()):
        inventory = set(self.root.rglob("*"))
        allowed = set(self.files) | self.directories | self.sockets | set(self.assets)
        assert inventory <= allowed, "unclassified owned canary channel"
        assert self.required <= inventory, "incomplete owned canary inventory"
        assert self.directories <= inventory | {self.root}, "missing owned directory"
        groups = {name: [0, 0] for name in ("stdout", "stderr", "logs", "public-errors", "owned-temporaries", "database", "wal", "shm", "journal", "staging", "audit", "core-crash", "agent-resources")}
        for path in sorted(inventory):
            mode = path.lstat().st_mode
            if path in self.directories:
                assert stat.S_ISDIR(mode)
            elif path in self.sockets:
                assert stat.S_ISSOCK(mode)
            elif path in self.assets:
                assert stat.S_ISREG(mode) and hashlib.sha256(path.read_bytes()).digest() == self.assets[path], "fixture executable/source changed"
            else:
                assert stat.S_ISREG(mode), "special/symlink canary channel"
                channel = self.files[path]
                size = scan_file(path, self.canaries, channel)
                groups[channel][0] += 1
                groups[channel][1] += size
                if channel == "stderr":
                    groups["public-errors"][0] += 1
                    groups["public-errors"][1] += size
        # Every product-created file has a category; absent logs/core are
        # explicitly empty, rather than omitted or read with a size limit.
        for channel, (files, size) in groups.items():
            print(f"PM28_CANARY phase={phase} channel={channel} files={files} bytes={size} complete=1", flush=True)
        for process in live:
            assert process.poll() is None, "process metadata inventory lost a live PID"
            for channel in ("cmdline", "environ"):
                path = pathlib.Path(f"/proc/{process.pid}/{channel}")
                try:
                    value = path.read_bytes()
                except PermissionError as error:
                    assert error.errno in (errno.EACCES, errno.EPERM)
                    print(f"PM28_CANARY phase={phase} channel=proc-{channel} pid={process.pid} access=denied", flush=True)
                else:
                    scan_bytes(value, self.canaries, "proc-" + channel)
                    print(f"PM28_CANARY phase={phase} channel=proc-{channel} pid={process.pid} bytes={len(value)} complete=1", flush=True)
            descriptors = list(pathlib.Path(f"/proc/{process.pid}/fd").iterdir())
            for descriptor in descriptors:
                target = os.readlink(descriptor)
                scan_bytes(os.fsencode(target), self.canaries, "proc-fd")
                if target.startswith(("socket:[", "pipe:[", "anon_inode:")) or target == "/dev/null":
                    continue
                assert pathlib.Path(target) in self.files or pathlib.Path(target) in self.assets, "unclassified process file/temporary resource"
            print(f"PM28_CANARY phase={phase} channel=proc-fd pid={process.pid} descriptors={len(descriptors)} complete=1", flush=True)
        if live:
            request = dict(private=[str(path) for path in inventory if path in self.files and (path.parent == self.root / "state" or path.parent == self.logdir or path == self.root / "human/human.key")],
                           resources=[str(self.root / "agent" / name) for name in ("agent.key", "agent.pub")],
                           canaries=[value.hex() for value in self.canaries], pids=[p.pid for p in live])
            def identity():
                os.setgroups([])
                os.setgid(AGENT)
                os.setuid(AGENT)
            result = subprocess.run([sys.executable, self.observer], input=json.dumps(request).encode(),
                                    capture_output=True, timeout=8, preexec_fn=identity)
            scan_bytes(result.stdout + result.stderr, self.canaries, "agent-resources")
            assert result.returncode == 0 and result.stderr == b"", "agent channel control/denial failed"
            print(result.stdout.decode("ascii").strip(), flush=True)

    def close(self):
        errors = []
        for process, _, _ in reversed(self.processes):
            try:
                if process.poll() is None:
                    process.send_signal(signal.SIGCONT)
                    process.send_signal(signal.SIGTERM)
                    assert process.wait(timeout=8) == -signal.SIGTERM
            except BaseException as error:
                errors.append(error)
        for stream in self.streams:
            try:
                stream.close()
            except BaseException as error:
                errors.append(error)
        if errors:
            raise ExceptionGroup("owned channel process/descriptor cleanup", errors)


def scanner_controls(fixture):
    """Prove detection, including a canary crossing the read chunk boundary."""
    canary = b"PM28_SCANNER_POSITIVE_SYNTHETIC"
    fixture["pid_path"].write_text("0")
    channels = Channels(fixture, (canary,))
    probe = channels.logdir / "scanner-positive"
    try:
        probe.write_bytes(b"!" * (1024 * 1024 - 7) + canary + b"!")
        channels.register(probe, "owned-temporaries")
        try:
            scan_file(probe, (canary,), "scanner-positive")
        except AssertionError as error:
            assert str(error) == "plaintext canary in scanner-positive"
        else:
            raise AssertionError("scanner missed cross-chunk positive canary")
        probe.write_bytes(b"!" * 4096)
        # A fixture reader that returns premature EOF must fail against the
        # actual file size. It changes no product reader or engine callback.
        class ShortStream:
            def __enter__(self):
                self.stream = probe.open("rb")
                self.remaining = 4095
                return self
            def read(self, size):
                count = min(size, self.remaining)
                self.remaining -= count
                return self.stream.read(count)
            def __exit__(self, *_):
                self.stream.close()
        class ShortPath:
            def stat(self):
                return probe.stat()
            def open(self, *_):
                return ShortStream()
        try:
            scan_file(ShortPath(), (canary,), "scanner-truncation")
        except AssertionError as error:
            assert str(error) == "truncated channel scanner-truncation"
        else:
            raise AssertionError("scanner accepted a truncated read")
        unknown = channels.logdir / "unclassified"
        unknown.write_bytes(b"synthetic unknown channel")
        try:
            channels.scan("scanner-unknown-positive")
        except AssertionError as error:
            assert str(error) == "unclassified owned canary channel"
        else:
            raise AssertionError("scanner accepted incomplete classification")
        unknown.unlink()
        probe.unlink()
        try:
            channels.scan("scanner-missing-positive")
        except AssertionError as error:
            assert str(error) == "incomplete owned canary inventory"
        else:
            raise AssertionError("scanner accepted a missing required channel")
        print("PASS scanner-control cross-chunk-canary=detected premature-eof=rejected unclassified=rejected missing=rejected", flush=True)
    finally:
        channels.close()
