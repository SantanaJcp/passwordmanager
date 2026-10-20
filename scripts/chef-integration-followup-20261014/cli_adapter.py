#!/usr/bin/env python3
"""Focused CLI adapter: initialize the pinned API once; never a Popen/chroot hook."""
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from core import require, digest, write

ANCHOR = '        seeded = as_uid(0, [custody, "human-content-flow",'
# Byte-identical migration insertion to original 0a owned_root.py; no assertion change.
MIGRATION = '''        stop(daemon)
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

def assertions(source):
    return [ast.dump(node, include_attributes=False) for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Assert)]

def adapt(source):
    require(source.count(ANCHOR) == 1 and MIGRATION not in source, 'CLI anchor/mixed migration mode')
    require('initialize_installed_fixture(' not in source and 'owned_root' not in source,
            'self-initializing/outer-hook mixed CLI mode')
    adapted = source.replace(ANCHOR, MIGRATION + ANCHOR)
    require(adapted.replace(MIGRATION, '', 1) == source, 'unexpected semantic delta')
    require(assertions(source) == assertions(adapted), 'CLI assertions changed')
    return adapted

def main():
    require(len(sys.argv) == 6, 'usage: cli_adapter.py CLONE CUSTODY PM NEW_EVIDENCE direct-self-initializing')
    clone, custody, pm, evidence = map(Path, sys.argv[1:5])
    require(sys.argv[5] == 'direct-self-initializing', 'mixed/outer hook mode')
    require(os.getuid() == 0 and os.geteuid() == 0, 'initialize before UID drop')
    mapping = Path('/proc/self/uid_map').read_text().split()
    require(mapping[0] == '0' and mapping[1] != '0' and mapping[2] == '1', 'own mapped namespace required')
    clone = clone.resolve(strict=True)
    for binary in (custody, pm):
        require(binary.is_absolute() and binary.resolve(strict=True) == clone / 'target/debug' / binary.name,
                'borrowed/non-private binary')
    require(custody.name == 'pm-custody' and pm.name == 'pm', 'binary roles')
    fixture = clone / 'crates/pm-cli/tests/chef_human_entry_lab.py'
    for relative in ('crates/pm-cli/tests/chef_human_entry_lab.py',
                     'crates/pm-custody/tests/linux_lab.py',
                     'crates/pm-custody/tests/chef_installed_fixture.py'):
        pinned = subprocess.check_output(['git', '-C', str(clone), 'show',
                 '3b4dd416a4dcd6f7cc301fc4c9f2c1d30ce540d9:' + relative])
        require((clone / relative).read_bytes() == pinned, 'selected CLI/API source drift: ' + relative)
    source = fixture.read_text()
    adapted = adapt(source)
    tests = clone / 'crates/pm-custody/tests'
    sys.path.insert(0, str(tests))
    import linux_lab
    import chef_installed_fixture
    require(Path(linux_lab.__file__).resolve() == tests / 'linux_lab.py' and
            Path(chef_installed_fixture.__file__).resolve() == tests / 'chef_installed_fixture.py', 'borrowed fixture module')
    require(linux_lab.INSTALLED_FIXTURE is None and chef_installed_fixture.ROOT is None, 'already initialized root')
    require(subprocess.Popen is subprocess.__dict__['Popen'] and subprocess.Popen.__module__ == 'subprocess',
            'outer Popen hook forbidden')
    # initialize BEFORE exec allocates any data; API prepare alone owns installed UID1 chroot.
    root = linux_lab.initialize_installed_fixture(str(custody))
    evidence.mkdir(mode=0o700, exist_ok=False)
    receipt = dict(fixture=str(fixture), source_digest=digest(source.encode()), executed_digest=digest(adapted.encode()),
                   migration_digest=digest(MIGRATION.encode()), assertion_count=len(assertions(source)),
                   exact_removal_restores_source=True, root=str(root), mode='direct-self-initializing',
                   binaries={str(b): digest(b.read_bytes()) for b in (custody, pm)}, status='RUNNING')
    write(evidence / 'adapter.json', receipt)
    sys.argv = [str(fixture), str(custody), str(pm), str(evidence / 'human-ui')]
    try:
        exec(compile(adapted, str(fixture), 'exec'), {'__file__': str(fixture), '__name__': '__main__'})
        receipt['status'] = 'COMPLETED'
    finally:
        if receipt['status'] != 'COMPLETED':
            receipt['status'] = 'FAILED'
        write(evidence / 'adapter.json', receipt)

if __name__ == '__main__':
    main()
