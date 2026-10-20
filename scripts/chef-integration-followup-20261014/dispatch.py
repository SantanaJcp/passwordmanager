#!/usr/bin/env python3
"""Future explicit manifest -> kitchen integration; never called by unit checks."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
from core import METHOD, WORKSPACE, KITCHEN, KITCHEN_REAL, HISTORY_HASH, ORIGINAL_HEADS, digest, git, helpers, require, validate_runtime, write

def main():
    require(len(sys.argv) == 3, 'usage: dispatch.py COMPLETE_MANIFEST NEW_EVIDENCE')
    data = json.loads(Path(sys.argv[1]).read_text())
    repo = validate_runtime(data)  # all metadata gates BEFORE artifact creation/execution
    require(KITCHEN.resolve(strict=True) == KITCHEN_REAL and os.access(KITCHEN_REAL, os.X_OK), 'installed kitchen origin changed')
    evidence = Path(sys.argv[2])
    require(evidence.is_absolute() and evidence.parent.resolve(strict=True) == evidence.parent,
            'absolute non-symlink evidence parent required')
    require(evidence.is_relative_to(WORKSPACE / '.scratch/chef-followup-runs'), 'new evidence boundary')
    evidence.mkdir(mode=0o700, exist_ok=False)
    (evidence / 'home').mkdir(mode=0o700)
    check = shlex.join(['python3', str(METHOD / 'stage.py'), str(evidence)])
    command = [str(KITCHEN), 'integrate', *(h['sha'] for h in data['heads']), '--repo', str(repo),
               '--base', data['base'], '--project', 'pm-chef-followup-20261014', '--check', check]
    req = dict(manifest=data, vector_length=len(data['heads']), method_head=git(WORKSPACE, 'rev-parse', 'HEAD'),
               helpers=helpers(), kitchen_digest=digest(KITCHEN_REAL.read_bytes()),
               kitchen_integrate_digest=digest((KITCHEN_REAL.parent.parent / 'lib/kitchen/integrate.py').read_bytes()), historical_input_digest=HISTORY_HASH, original_transitive_heads=ORIGINAL_HEADS, check=check, check_digest=digest(check.encode()), command=command,
               command_digest=digest(command))
    req['binding'] = digest(req)
    write(evidence / 'request.json', req)
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(evidence / 'home'),
           'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1', 'RUSTUP_AUTO_INSTALL': '0'}
    with (evidence / 'kitchen.log').open('w') as out:
        result = subprocess.run(command, env=env, stdout=out, stderr=subprocess.STDOUT)
    write(evidence / 'kitchen-exit.json', dict(binding=req['binding'], rc=result.returncode,
          status='SOURCE_CHECK_ONLY' if result.returncode == 0 else 'ISSUES'))
    raise SystemExit(result.returncode)

if __name__ == '__main__':
    main()
