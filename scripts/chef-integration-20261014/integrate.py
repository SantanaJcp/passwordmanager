#!/usr/bin/env python3
"""Owned evidence and exact kitchen vector; principles isolate/evidence/prove."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

SOURCE = Path('/home/santana/Documents/ChatGPT/passwordmanager/.worktrees/chef-finish-20261014')
BASE = '31b48ace181512d273738ff3b344201be8e8f08b'
REFS = [
    '894aa3600610e23a1834d831668bf66dc2bb7112',
    'a900a69f0a57e4ff09baa458dae69f278d29b250',
    '15bfaa248cf4950f5c8a3bf99dccc869791f3227',
    '4c3a90c8e3c5ceac229060e66f551012e88c46dd',
    '6a2a81fa76023c28e6b7e4a6d8282820c4e09fdc',
    '837f5564b14f5b6f8a058b21304dfbd5d7ef1fb7',
    '5e26f3b4d4813c4e606339353e67e82ede4dcdf5',
    '0eff9d93b97abefd8048d16236cf674601af0a41',
    '9de9aa99347cc2b3300190601ba00c568f22aa86',
]
TOOLCHAIN = Path('/home/santana/Documents/ChatGPT/passwordmanager/.toolchain')

def main():
    evidence = Path(sys.argv[1]).resolve()
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    method = Path(__file__).resolve().parent
    for ref in [BASE, *REFS]:
        assert subprocess.check_output(['git', '-C', str(SOURCE), 'rev-parse', ref], text=True).strip() == ref
    subprocess.run(['git', '-C', str(SOURCE), 'merge-base', '--is-ancestor',
                    'd4b1be662a1b8766eff54c2b8269ef4c94770c54', BASE], check=True)
    assert not subprocess.check_output(['git', '-C', str(SOURCE), 'diff', '--name-only',
        'd4b1be662a1b8766eff54c2b8269ef4c94770c54', BASE, '--', 'crates', 'scripts',
        'Cargo.toml', 'Cargo.lock', '.github', 'rust-toolchain.toml'])
    assert TOOLCHAIN.is_dir()
    check = 'python3 ' + str(method / 'stage.py') + ' ' + str(evidence)
    command = ['kitchen', 'integrate', *REFS, '--repo', str(SOURCE), '--base', BASE,
               '--project', 'pm-chef-integration-20261014', '--check', check]
    (evidence / 'request.json').write_text(json.dumps(dict(base=BASE, refs=REFS, command=command,
        check=check, check_sha256=hashlib.sha256(check.encode()).hexdigest(),
        helpers={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in method.glob('*.py')}), indent=2)+'\n')
    env = dict(os.environ, PM_CHEF_EVIDENCE=str(evidence), RUSTUP_AUTO_INSTALL='0',
               CARGO_NET_OFFLINE='true', PYTHONDONTWRITEBYTECODE='1')
    with (evidence / 'kitchen-output.log').open('w') as log:
        result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
    print((evidence / 'kitchen-output.log').read_text())
    (evidence / 'kitchen-exit.json').write_text(json.dumps({'rc': result.returncode})+'\n')
    raise SystemExit(result.returncode)

if __name__ == '__main__':
    main()
