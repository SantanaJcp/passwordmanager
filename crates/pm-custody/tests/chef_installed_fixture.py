#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit installed-policy fixture. Custody is chrooted; clients keep real PTYs.

Call initialize with this checkout's fresh binary before allocating fixture data.
Only the three public installed custody commands enter the private filesystem.
No Popen hooks, source rewriting, host mounts, learned owners or alternate modes.
"""
import atexit
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tempfile

ROOT = None
INSTALLED = {'serve-vault', 'migrate-agent-registry', 'provision-adapters'}
PATH_FLAGS = {'--bootstrap', '--vault', '--agent-socket', '--human-socket',
              '--agent-public', '--endpoint'}


def initialize(custody):
    global ROOT
    assert ROOT is None
    assert os.getuid() == os.geteuid() == 0
    mapping = Path('/proc/self/uid_map').read_text().split()
    assert mapping[0] == '0' and mapping[1] != '0' and mapping[2] == '1', mapping
    source = Path(custody).resolve(strict=True)
    assert source.name == 'pm-custody' and source.is_file()
    # A short, disk-backed name keeps real outside Unix socket paths below108.
    ROOT = Path(tempfile.mkdtemp(prefix='pc-', dir='/var/tmp'))
    ROOT.chmod(0o755)
    assert ROOT.stat().st_uid == 0
    (ROOT / 'tmp').mkdir(); (ROOT / 'tmp').chmod(0o1777)
    copied = {}
    def copy(public_source, destination):
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(public_source.resolve(strict=True), destination)
        assert destination.stat().st_uid == 0
        copied[str(destination.relative_to(ROOT))] = hashlib.sha256(destination.read_bytes()).hexdigest()
    copy(source, ROOT / 'bin/pm-custody')
    for library in re.findall(r'(/[^\s()]+)', subprocess.check_output(['ldd', str(source)], text=True)):
        library = Path(library)
        if library.is_file():
            copy(library, ROOT / str(library).lstrip('/'))
    (ROOT / 'fixture.json').write_text(json.dumps({'source': str(source), 'copied': copied,
        'uid_map': Path('/proc/self/uid_map').read_text(), 'host_mounts': False}, indent=2)+'\n')
    tempfile.tempdir = str(ROOT)
    atexit.register(lambda: print('OWNED_ROOT retained='+str(ROOT), flush=True))
    return ROOT


def prepare(uid, command, change_identity):
    """Return exact command/preexec; non-installed callers retain their identity API."""
    command = list(command)
    installed = (len(command) > 1 and Path(command[0]).name == 'pm-custody'
                 and command[1] in INSTALLED)
    if not installed:
        return command, change_identity
    assert ROOT is not None, "installed fixture was not initialized"
    assert uid == 1, 'installed custody commands must run as actual custodian'
    command[0] = '/bin/pm-custody'
    for index in range(2, len(command)):
        if str(command[index - 1]) in PATH_FLAGS:
            path = Path(command[index])
            assert path.is_absolute() and '..' not in path.parts and not path.is_symlink()
            command[index] = '/' + str(path.relative_to(ROOT))
    def enter():
        os.chroot(ROOT); os.chdir('/')
        change_identity()
    return command, enter


def run(uid, command, *, check=True):
    def change():
        os.setgroups([]); os.setgid(uid); os.setuid(uid)
    command, preexec = prepare(uid, command, change)
    return subprocess.run(command, preexec_fn=preexec, check=check,
                          capture_output=True, timeout=15)


def stop_and_unlink(process, paths, *, timeout=5):
    """Stop this live child, verify exit/output, unlink only its owned sockets."""
    assert process.poll() is None
    process.send_signal(signal.SIGTERM)
    out, err = process.communicate(timeout=timeout)
    assert process.returncode == -signal.SIGTERM and out == err == b'', (process.returncode, out, err)
    for path in paths:
        path = Path(path)
        assert ROOT is not None and path.is_relative_to(ROOT)
        metadata = path.lstat()
        assert stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == 1
        assert path.parent.stat().st_uid == 1
        path.unlink()


def migrate(custody, bootstrap, vault, device, *pairs):
    """Public CLI validates the legacy binding and every supplied current grant."""
    before = Path(bootstrap).read_bytes()
    destination = Path(str(vault) + '.agent-registry')
    assert not destination.exists()
    command = [custody, 'migrate-agent-registry', '--bootstrap', bootstrap,
               '--vault', vault, '--device', device]
    for public, uid in pairs:
        command += ['--agent-public', public, '--agent-uid', str(uid)]
    result = run(1, command)
    assert result.returncode == 0 and result.stderr == b'', result
    assert Path(bootstrap).read_bytes() == before
    metadata = destination.lstat()
    assert metadata.st_uid == 1 and stat.S_IMODE(metadata.st_mode) == 0o400
    return destination


def assert_agent_root_rejected(custody, bootstrap, vault, device, paths):
    """Adversarial filesystem root is really UID3, not a virtual trust flag."""
    assert ROOT.stat().st_uid == 0
    os.chown(ROOT, 3, 3)
    try:
        assert ROOT.stat().st_uid == 3
        result = run(1, [custody, 'serve-vault', '--bootstrap', bootstrap,
            '--agent-socket', paths[0], '--human-socket', paths[1],
            '--vault', vault, '--device', device], check=False)
        assert result.returncode == 4 and result.stdout == b'' and result.stderr == b'CUSTODY_UNAVAILABLE\n', result
        assert not any(Path(path).exists() for path in paths)
    finally:
        os.chown(ROOT, 0, 0)
    assert ROOT.stat().st_uid == 0
    print('OBSERVED agent-owned filesystem root=rejected', flush=True)
