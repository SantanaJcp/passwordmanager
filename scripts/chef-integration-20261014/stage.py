#!/usr/bin/env python3
"""Preserve kitchen-owned clone before its unconditional finally/rmtree."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from integrate import REFS, TOOLCHAIN

evidence = Path(sys.argv[1]).resolve(strict=True)
cwd = Path.cwd()
clone = evidence / 'clone'
if not clone.exists():
    assert cwd.name == 'clone' and cwd.parent.name.startswith('kitchen-integrate-')
    assert not (cwd / 'target').exists()
    cwd.rename(clone)
    cwd.symlink_to(clone, target_is_directory=True)
    (clone / '.toolchain').symlink_to(TOOLCHAIN, target_is_directory=True)
os.chdir(clone)
assert (clone / '.toolchain').resolve(strict=True) == TOOLCHAIN
subprocess.run(['git', 'diff', '--check'], check=True)
steps_path = evidence / 'stages.json'
steps = json.loads(steps_path.read_text()) if steps_path.exists() else []
index = len(steps)
assert index < len(REFS)
subprocess.run(['git', 'merge-base', '--is-ancestor', REFS[index], 'HEAD'], check=True)
head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
steps.append(dict(ref=REFS[index], head=head, check='git diff --check', rc=0))
steps_path.write_text(json.dumps(steps, indent=2)+'\n')
if index == len(REFS)-1:
    env = dict(os.environ, CARGO_TARGET_DIR=str(clone / 'target'), RUSTUP_AUTO_INSTALL='0',
        RUSTUP_HOME=str(TOOLCHAIN / 'rustup'), CARGO_HOME=str(TOOLCHAIN / 'cargo'),
        PATH=str(TOOLCHAIN / 'cargo/bin')+os.pathsep+os.environ['PATH'])
    command = ['flock', '/tmp/pm-cargo-window.lock', './scripts/check.sh']
    with (evidence / 'combined-check.log').open('w') as log:
        result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
    (evidence / 'combined-check.json').write_text(json.dumps(dict(head=head, command=command,
        rc=result.returncode, target=str(clone / 'target'),
        script_sha256=hashlib.sha256((clone / 'scripts/check.sh').read_bytes()).hexdigest()), indent=2)+'\n')
    print('combined check', head, result.returncode, flush=True)
    raise SystemExit(result.returncode)
print('source stage', index+1, head, flush=True)
