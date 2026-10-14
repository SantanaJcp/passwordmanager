#!/usr/bin/env python3
"""Preserve kitchen's owned clone; one full check only at the final merge."""
import os
from pathlib import Path
import subprocess
import sys
import json
from core import TOOLCHAIN, LOCK, digest, environment, read_request, require, stage_ancestry, write

def main():
    evidence, req = read_request(sys.argv[1])
    clone = evidence / 'clone'
    cwd = Path.cwd()
    if not clone.exists():
        require(cwd.name == 'clone' and cwd.parent.name.startswith('kitchen-integrate-'), 'unexpected kitchen clone')
        require(cwd.stat().st_uid == os.getuid() and not (cwd / 'target').exists(), 'foreign/borrowed clone target')
        require(not (cwd / '.toolchain').exists() and not (cwd / '.toolchain').is_symlink(), 'unexpected toolchain path')
        require(TOOLCHAIN.resolve(strict=True) == TOOLCHAIN, 'fixed toolchain unavailable')
        # kitchen finally rmtree deletes its temporary symlink, not this retained clone.
        cwd.rename(clone)
        cwd.symlink_to(clone, target_is_directory=True)
        (clone / '.toolchain').symlink_to(TOOLCHAIN, target_is_directory=True)
        (clone / 'target').mkdir(mode=0o700)
    require(cwd.resolve(strict=True) == clone and not clone.is_symlink(), 'stage clone mismatch')
    steps_path = evidence / 'stages.json'
    steps = json.loads(steps_path.read_text()) if steps_path.exists() else []
    previous = steps[-1]['head'] if steps else req['manifest']['base']
    head, final = stage_ancestry(clone, req['manifest'], previous, len(steps))
    subprocess.run(['git', '-C', str(clone), 'diff', '--check'], check=True)
    steps.append(dict(index=len(steps), sha=req['manifest']['heads'][len(steps)]['sha'], head=head,
                      binding=req['binding'], rc=0, final=final))
    write(steps_path, steps)
    if final:
        receipt = evidence / 'combined-check.json'
        require(not receipt.exists() and not (evidence / 'combined-check.log').exists(), 'no repeated/cached final check')
        command = ['flock', LOCK, './scripts/check.sh']
        with (evidence / 'combined-check.log').open('w') as out:
            rc = subprocess.run(command, cwd=clone, env=environment(clone, evidence),
                                stdout=out, stderr=subprocess.STDOUT).returncode
        write(receipt, dict(binding=req['binding'], head=head, vector_length=len(steps), rc=rc,
              command=command, command_digest=digest(command), script_digest=digest((clone / 'scripts/check.sh').read_bytes()),
              target=str(clone / 'target'), status='CHECK_ONLY'))
        raise SystemExit(rc)

if __name__ == '__main__':
    main()
