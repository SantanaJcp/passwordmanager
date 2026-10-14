#!/usr/bin/env python3
"""Same independent memory tests on exact pre-fix code; never merge this tree."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from integrate import TOOLCHAIN

evidence=Path(sys.argv[1]).resolve(strict=True)
clone=evidence/'clone'
baseline=evidence/'memory-baseline'
base='d4b1be662a1b8766eff54c2b8269ef4c94770c54'
assert not baseline.exists()
subprocess.run(['git','-C',str(clone),'worktree','add','--detach',str(baseline),base],check=True)
tests=['protected_signing.rs','protected_grant_context.rs']
for name in tests:
    assert not (baseline/'crates/pm-crypto/tests'/name).exists()
    shutil.copyfile(clone/'crates/pm-crypto/tests'/name,baseline/'crates/pm-crypto/tests'/name)
env=dict(os.environ,CARGO_TARGET_DIR=str(baseline/'target'),RUSTUP_AUTO_INSTALL='0',
    RUSTUP_HOME=str(TOOLCHAIN/'rustup'),CARGO_HOME=str(TOOLCHAIN/'cargo'),
    PATH=str(TOOLCHAIN/'cargo/bin')+os.pathsep+os.environ['PATH'],CARGO_NET_OFFLINE='true')
command=['flock','/tmp/pm-cargo-window.lock','./scripts/cargo-local.sh','test','-p','pm-crypto',
    '--test','protected_signing','--test','protected_grant_context','--no-fail-fast','--locked','--offline','--','--nocapture']
with (evidence/'memory-baseline-red.log').open('w') as out:
    rc=subprocess.run(command,cwd=baseline,env=env,stdout=out,stderr=subprocess.STDOUT).returncode
record=dict(base=base,command=command,rc=rc,baseline=str(baseline),
    command_sha256=hashlib.sha256(json.dumps(command).encode()).hexdigest(),
    tests={n:hashlib.sha256((baseline/'crates/pm-crypto/tests'/n).read_bytes()).hexdigest() for n in tests})
(evidence/'memory-baseline-red.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record),flush=True)
raise SystemExit(rc)
