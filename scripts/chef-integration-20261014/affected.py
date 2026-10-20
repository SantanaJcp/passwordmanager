#!/usr/bin/env python3
"""Focused combined-tree flows, fixed limits and honest REDs retained."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import time
from integrate import TOOLCHAIN

evidence = Path(sys.argv[1]).resolve(strict=True)
clone = evidence / 'clone'
method = Path(__file__).resolve().parent
binary = clone / 'target/debug'
head = subprocess.check_output(['git', '-C', str(clone), 'rev-parse', 'HEAD'], text=True).strip()
env = dict(os.environ, CARGO_TARGET_DIR=str(clone / 'target'), RUSTUP_AUTO_INSTALL='0',
    CARGO_NET_OFFLINE='true', RUSTUP_HOME=str(TOOLCHAIN / 'rustup'),
    CARGO_HOME=str(TOOLCHAIN / 'cargo'), PATH=str(TOOLCHAIN / 'cargo/bin')+os.pathsep+os.environ['PATH'],
    PYTHONDONTWRITEBYTECODE='1')
user = pwd.getpwuid(os.getuid()).pw_name
def subordinate(path):
    values = [line.split(':')[1] for line in Path(path).read_text().splitlines() if line.split(':')[0]==user]
    assert len(values)==1
    return values[0]
ns = ['unshare', '--user', '--mount', '--pid', '--fork', '--mount-proc',
    '--map-users', f'0:{os.getuid()}:1', '--map-users', '1:'+subordinate('/etc/subuid')+':65535',
    '--map-groups', f'0:{os.getgid()}:1', '--map-groups', '1:'+subordinate('/etc/subgid')+':65535']
cargo = ['./scripts/cargo-local.sh']
tests = clone / 'crates/pm-custody/tests'
cases = [
    ('focused-memory', cargo+['test','-p','pm-crypto','--test','protected_signing','--test',
        'protected_grant_context','--locked','--offline','--','--nocapture'], {}),
    ('focused-ssh-wire', cargo+['test','-p','pm-ssh-client','--lib','wire_memory_tests',
        '--locked','--offline','--','--nocapture'], {}),
    ('focused-g7-w7', cargo+['test','-p','pm-vault','--test','g7_prepared_stream','--test',
        'human_transactions','--test','content_records','--test','backup_lifecycle','--test',
        'history_lifecycle','--locked','--offline'], {}),
    ('focused-cli-mcp', cargo+['test','-p','pm-cli','--locked','--offline'], {}),
    ('daemon-example-build', cargo+['build','-p','pm-custody','--example',
        'chef_runtime_open_channel','--locked','--offline'], {}),
]
for mode in ['registry','adapter','admission']:
    cases.append(('daemon-'+mode, ns+['python3',str(tests/'chef_runtime_chroot.py'),mode,
        str(binary/'pm-custody'),str(binary/'pm'),str(binary/'pm-web-auth')], {}))
for case in ['socket','config-remove','config-replace','registry-remove','bootstrap-mode',
             'audit-mode','indeterminate-socket','ssh-socket']:
    cases.append(('daemon-reconcile-'+case, ns+['python3',str(tests/'chef_runtime_chroot.py'),
        'reconciliation',str(binary/'pm-custody'),str(binary/'pm'),str(binary/'pm-web-auth')],
        {'CHEF_RECONCILIATION_CASE':case}))
cases.append(('public-human-tui-migrated', ns+['python3',str(method/'owned_root.py'),
    str(clone/'crates/pm-cli/tests/chef_human_entry_lab.py'),str(binary/'pm-custody'),
    str(binary/'pm'),str(evidence/'human-ui')], {}))
for target in ['bootstrap','vault']:
    cases.append(('g7-witness-'+target, ns+['python3',str(method/'owned_root.py'),
        str(clone/'crates/pm-vault/examples/g7_loss_witness.py'),str(binary/'pm-custody'),
        str(binary/'pm'),target], {}))
cases.append(('g7-matrix-counts-diagnostic', ns+['python3',str(method/'matrix_counts.py'),
    str(tests/'sqlite_sync_fault_lab.py'),str(binary/'pm-custody'),str(binary/'pm'),
    str(tests/'sqlite_sync_interposer.c'),'matrix'], {}))
rows=[]
for name,command,extra in cases:
    actual=['flock','/tmp/pm-cargo-window.lock',*command]
    log=evidence/(name+'.log')
    started=time.monotonic()
    with log.open('w') as output:
        rc=subprocess.run(actual,cwd=clone,env=env|extra,stdout=output,stderr=subprocess.STDOUT).returncode
    row=dict(name=name, command=actual, env_overrides=extra, rc=rc, log=str(log),
        command_sha256=hashlib.sha256(json.dumps(actual).encode()).hexdigest(),seconds=round(time.monotonic()-started,3))
    rows.append(row)
    (evidence/'affected-results.json').write_text(json.dumps(dict(head=head,rows=rows),indent=2)+'\n')
    print(name,'rc='+str(rc),flush=True)
origins={str(p):dict(realpath=str(p.resolve()),sha256=hashlib.sha256(p.read_bytes()).hexdigest())
    for p in [binary/'pm-custody',binary/'pm',binary/'pm-web-auth',binary/'pm-ssh-client',
              binary/'pm-sync',binary/'examples/chef_runtime_open_channel'] if p.is_file()}
(evidence/'binary-origins.json').write_text(json.dumps(dict(head=head,binaries=origins),indent=2)+'\n')
raise SystemExit(1 if any(row['rc']!=0 for row in rows) else 0)
