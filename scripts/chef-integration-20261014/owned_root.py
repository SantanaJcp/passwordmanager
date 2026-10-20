#!/usr/bin/env python3
"""Run unchanged fixture assertions with custody inside an owned UID0 chroot.

Clients and their PTYs stay outside. Only fresh owned binaries and public
libraries are copied; no host mounts or learned root owner. Evidence retained.
"""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import json

assert os.getuid() == 0
assert Path('/proc/self/uid_map').read_text().split()[1] != '0'
fixture = Path(sys.argv[1]).resolve(strict=True)
args = sys.argv[2:]
assert fixture.name != 'sqlite_sync_fault_lab.py', 'syscall/proc fixtures use matrix_counts.py outside the no-mount chroot'
root = Path(tempfile.mkdtemp(prefix='pm-chef-owned-'))
root.chmod(0o755)
(root / 'tmp').mkdir(mode=0o1777)
(root / 'tmp').chmod(0o1777)
for source in [Path(args[0]), Path(args[1])]:
    source = source.resolve(strict=True)
    dest = root / 'bin' / source.name
    dest.parent.mkdir(exist_ok=True)
    shutil.copy2(source, dest)
    for library in re.findall(r'(/[^\s()]+)', subprocess.check_output(['ldd', str(source)], text=True)):
        library = Path(library)
        if library.is_file():
            dest = root / str(library).lstrip('/')
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(library.resolve(strict=True), dest)
tempfile.tempdir = str(root / 'tmp')
original_popen = subprocess.Popen

def popen(command, *pargs, **kwargs):
    command = list(command) if isinstance(command, (list, tuple)) else command
    installed = (isinstance(command, list) and len(command)>1 and
        Path(command[0]).name == 'pm-custody' and command[1] in
        ('serve-vault', 'migrate-agent-registry', 'provision-adapters'))
    if installed:
        def translate(value):
            value = str(value)
            return value.replace(str(root)+'/', '/')
        original_preexec = kwargs.get('preexec_fn')
        def enter():
            os.chroot(root)
            os.chdir('/')
            if original_preexec:
                original_preexec()
        kwargs['preexec_fn'] = enter
        command = [translate(value) for value in command]
        if not str(command[0]).startswith('/tmp/'):
            command[0] = '/bin/pm-custody'
        if 'env' in kwargs:
            kwargs['env'] = {key: translate(value) for key,value in kwargs['env'].items()}
    return original_popen(command, *pargs, **kwargs)

subprocess.Popen = popen
sys.path.insert(0, str(fixture.parent))
sys.path.insert(0, str(fixture.parents[2] / 'pm-custody/tests'))
source = fixture.read_text()
if fixture.name == 'chef_human_entry_lab.py':
    # Explicit 1A caller migration, after human authorization and before discovery.
    anchor = '        seeded = as_uid(0, [custody, "human-content-flow",'
    assert source.count(anchor)==1
    migration = '''        stop(daemon)
        daemon = None
        as_uid(1, [custody, "migrate-agent-registry", "--bootstrap", bootstrap,
            "--vault", vault, "--device", "14" * 16,
            "--agent-public", second_public, "--agent-uid", "3"])
        for owned_socket in [agent_socket, human_socket]:
            owned_socket.unlink()
        daemon = start_as(1, [custody, "serve-vault", "--bootstrap", bootstrap,
            "--agent-socket", agent_socket, "--human-socket", human_socket,
            "--vault", vault, "--device", "14" * 16])
        wait_for_sockets(daemon, [agent_socket, human_socket])
'''
    source = source.replace(anchor, migration+anchor)
    (root/'cli-migration.txt').write_text(migration)
ledger = {'root':str(root), 'fixture':str(fixture), 'original_sha256':hashlib.sha256(fixture.read_bytes()).hexdigest(),
    'executed_sha256':hashlib.sha256(source.encode()).hexdigest(), 'host_mounts':False,
    'binary_sha256':{str(Path(a).resolve()):hashlib.sha256(Path(a).read_bytes()).hexdigest() for a in args[:2]},
    'status':'running'}
(root/'ledger.json').write_text(json.dumps(ledger,indent=2)+'\n')
sys.argv = [str(fixture), *args]
try:
    exec(compile(source,str(fixture),'exec'), {'__file__':str(fixture),'__name__':'__main__'})
    ledger['status']='completed'
finally:
    ledger['status']='completed' if ledger['status']=='completed' else 'failed'
    (root/'ledger.json').write_text(json.dumps(ledger,indent=2)+'\n')
    print('OWNED_ROOT retained='+str(root)+' status='+ledger['status'],flush=True)
