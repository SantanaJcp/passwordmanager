#!/usr/bin/env python3
"""Run all historical cases; expected RED never becomes product PASS."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from integrate import TOOLCHAIN

evidence = Path(sys.argv[1]).resolve(strict=True)
clone = evidence / 'clone'
method = Path(__file__).resolve().parent
cases = json.loads((method / 'historical-cases.json').read_text())['cases']
assert len(cases) == 52
head = subprocess.check_output(['git', '-C', str(clone), 'rev-parse', 'HEAD'], text=True).strip()
check = json.loads((evidence / 'combined-check.json').read_text())
assert check['head'] == head
env = dict(os.environ, RUSTUP_AUTO_INSTALL='0', CARGO_NET_OFFLINE='true',
    CARGO_TARGET_DIR=str(clone / 'target'), RUSTUP_HOME=str(TOOLCHAIN / 'rustup'),
    CARGO_HOME=str(TOOLCHAIN / 'cargo'), PATH=str(TOOLCHAIN / 'cargo/bin')+os.pathsep+os.environ['PATH'],
    PYTHONDONTWRITEBYTECODE='1', WAYLAND_DISPLAY='wayland-1',
    PM_KEYCLOAK_DIST='/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/keycloak/keycloak-26.7.3',
    PM_CFT_DIR='/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/cft/chrome-linux64')

def manifest():
    files = subprocess.check_output(['git', '-C', str(clone), 'ls-files', '-z', 'crates',
        'scripts', '.github', 'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml']).split(b'\0')
    return {os.fsdecode(p): hashlib.sha256((clone / os.fsdecode(p)).read_bytes()).hexdigest() for p in files if p}

initial = manifest()
(evidence / 'source-manifest.json').write_text(json.dumps(initial, indent=2)+'\n')
rows = []
resume = '--resume-after-quota' in sys.argv[2:]
results_path = evidence / ('52-resumed-results.json' if resume else '52-results.json')
for case in cases:
    assert manifest() == initial
    name, command = case['name'], case['command']
    started = time.monotonic()
    if name == 'final-check':
        # The exact same combined head's sole complete check, just executed by kitchen.
        rc, log = check['rc'], str(evidence / 'combined-check.log')
        actual = check['command']
        reused_same_run = True
    elif resume and name == 'final-clean':
        receipt = json.loads((evidence/'quota-interruption.json').read_text())['final-clean']
        rc, log = receipt['rc'], receipt['log']
        actual, reused_same_run = ['flock','/tmp/pm-cargo-window.lock',*command], True
    else:
        if name == 'final-clean':
            # Preserve the first target. cargo clean now touches only a NEW EMPTY owned target.
            assert (clone / 'target').is_dir() and not (clone / 'target-check').exists()
            (clone / 'target').rename(clone / 'target-check')
            (clone / 'target').mkdir()
        actual = ['flock', '/tmp/pm-cargo-window.lock', *command]
        log = str(evidence / (name+('-resumed' if resume else '')+'.log'))
        with open(log, 'w') as out:
            rc = subprocess.run(actual, cwd=clone, env=env, stdout=out, stderr=subprocess.STDOUT).returncode
        reused_same_run = False
    row = dict(case, actual_command=actual, rc=rc, log=log, reused_same_run=reused_same_run,
        command_sha256=hashlib.sha256(json.dumps(actual).encode()).hexdigest(),
        matches_historical=rc == case['historical_expected'], seconds=round(time.monotonic()-started,3))
    rows.append(row)
    results_path.write_text(json.dumps(dict(head=head, rows=rows), indent=2)+'\n')
    print(name, 'rc='+str(rc), flush=True)
assert manifest() == initial
summary = dict(head=head, cases=len(rows), rc0=sum(r['rc']==0 for r in rows),
    failed=[r['name'] for r in rows if r['rc']!=0],
    historical_mismatches=[r['name'] for r in rows if not r['matches_historical']], source_unchanged=True,
    status='ISSUES' if any(r['rc']!=0 for r in rows) else 'PASS')
(evidence / '52-summary.json').write_text(json.dumps(summary, indent=2)+'\n')
print(json.dumps(summary), flush=True)
raise SystemExit(1 if summary['status']=='ISSUES' else 0)
