#!/usr/bin/env python3
"""Future exact52 dispatcher; direct callers, real REDs, counted GUI BLOCKED rows."""
import json
from pathlib import Path
import subprocess
import sys
import time
from core import LOCK, digest, environment, git, history, read_request, require, write
from gui import blocked_case, PREREQUISITE

def summary(rows):
    return dict(cases=len(rows), rc0=sum(r['rc'] == 0 for r in rows),
                failed=[r['name'] for r in rows if r['rc'] not in (0, None)],
                blocked=[r['name'] for r in rows if r['rc'] is None],
                status='ISSUES' if any(r['rc'] not in (0, None) for r in rows) else
                       'BLOCKED' if any(r['rc'] is None for r in rows) else 'PASS')

def sources(clone):
    tracked = subprocess.check_output(['git', '-C', str(clone), 'ls-files', '-z'])
    return {p.decode(): digest((clone / p.decode()).read_bytes()) for p in tracked.split(b'\0') if p}

def main():
    evidence, req = read_request(sys.argv[1])
    require(len(sys.argv) == 2, 'no resume/retry/cache mode')
    clone = evidence / 'clone'
    head = git(clone, 'rev-parse', 'HEAD')
    check = json.loads((evidence / 'combined-check.json').read_text())
    require(check['binding'] == req['binding'] and check['head'] == head and
            check['vector_length'] == len(req['manifest']['heads']), 'final check/vector mismatch')
    require(check['rc'] == 0, 'full check failed; retain receipt, no sweep')
    require(not (evidence / '52-results.json').exists(), 'no reuse of sweep')
    cases = history(req['manifest']['sourceRepo'])
    require((clone / 'scripts/chef-integration-20261014/historical-cases.json').read_bytes() ==
            (Path(__file__).parents[1] / 'chef-integration-20261014/historical-cases.json').read_bytes(),
            'combined historical source changed')
    env = environment(clone, evidence)
    initial = sources(clone)
    write(evidence / 'source-manifest.json', initial)
    rows = []
    for case in cases:
        require(sources(clone) == initial, 'tracked source changed during sweep')
        name, command = case['name'], case['command']
        actual = ['flock', LOCK, *command]  # wrappers remain direct: no owned_root/Popen hook
        started = time.monotonic()
        log = evidence / (name + '.log')
        reason = None
        if name == 'final-check':
            rc, actual, log = check['rc'], check['command'], evidence / 'combined-check.log'
        elif blocked_case(name):
            rc, reason = None, PREREQUISITE
            log.write_text(reason + '\n')
        else:
            if name == 'final-clean':
                require((clone / 'target').is_dir() and not (clone / 'target').is_symlink() and
                        not (clone / 'target-check').exists(), 'borrowed/reused clean target')
                (clone / 'target').rename(clone / 'target-check')
                (clone / 'target').mkdir(mode=0o700)  # new EMPTY owned target, preserves original
            with log.open('w') as out:
                rc = subprocess.run(actual, cwd=clone, env=env, stdout=out, stderr=subprocess.STDOUT).returncode
        rows.append(dict(case, rc=rc, status='BLOCKED' if rc is None else 'GREEN' if rc == 0 else 'RED',
                         actual_command=actual, command_digest=digest(actual), binding=req['binding'],
                         log=str(log), reason=reason, matches_historical=rc == case['historical_expected'],
                         seconds=round(time.monotonic() - started, 3)))
        write(evidence / '52-results.json', dict(head=head, binding=req['binding'], rows=rows))
    require(sources(clone) == initial and len(rows) == 52, 'exact52/source retention')
    result = dict(summary(rows), head=head, binding=req['binding'], historical_input_digest=req['historical_input_digest']
                  if 'historical_input_digest' in req else digest((clone / 'scripts/chef-integration-20261014/historical-cases.json').read_bytes()))
    write(evidence / '52-summary.json', result)
    binaries = {str(p): dict(realpath=str(p.resolve(strict=True)), digest=digest(p.read_bytes()))
                for p in sorted((clone / 'target/debug').glob('pm*')) if p.is_file() and not p.is_symlink()}
    write(evidence / 'binary-origins.json', dict(binding=req['binding'], head=head, binaries=binaries))
    raise SystemExit(0 if result['status'] == 'PASS' else 1)

if __name__ == '__main__':
    main()
