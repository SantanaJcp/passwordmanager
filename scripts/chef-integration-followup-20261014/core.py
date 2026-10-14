"""Fail-closed, local-only method inputs. No product commands at import time."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

WORKSPACE = Path('/home/santana/.t3/worktrees/passwordmanager/t3-0eed2d3d')
METHOD = Path(__file__).resolve().parent
ORIGINAL_METHOD = '0a11733ffc784e80cb75c8df01d2cdcf34862d7e'
COMPOSITE = '8cd45529b062506a2cbe0c567538d3999ac8a2b6'
HISTORY = 'scripts/chef-integration-20261014/historical-cases.json'
HISTORY_HASH = '0644a20f2f18a21c3f5f3298bf8d8f2b37495c7b59af26c613c2584ad764751c'
TOOLCHAIN = Path('/home/santana/Documents/ChatGPT/passwordmanager/.toolchain')
LOCK = '/tmp/pm-cargo-window.lock'
KITCHEN = Path('/home/santana/.local/bin/kitchen')
KITCHEN_REAL = Path('/home/santana/Development/kitchen-skills/bin/kitchen')
PINNED = {
    'caller': '3b4dd416a4dcd6f7cc301fc4c9f2c1d30ce540d9',
    'guide': '55abf2592cc67a7da9a0fcaa89055540f41fe61c',
    'sync_gate': '15013de74d7bf55464c2d6aef7e99ee2f9ee25fc',
    'original_method': ORIGINAL_METHOD,
}
ORIGINAL_HEADS = [
    '894aa3600610e23a1834d831668bf66dc2bb7112', 'a900a69f0a57e4ff09baa458dae69f278d29b250',
    '15bfaa248cf4950f5c8a3bf99dccc869791f3227', '4c3a90c8e3c5ceac229060e66f551012e88c46dd',
    '6a2a81fa76023c28e6b7e4a6d8282820c4e09fdc', '837f5564b14f5b6f8a058b21304dfbd5d7ef1fb7',
    '5e26f3b4d4813c4e606339353e67e82ede4dcdf5', '0eff9d93b97abefd8048d16236cf674601af0a41',
    '9de9aa99347cc2b3300190601ba00c568f22aa86',
]
EXCLUDED = ['2801c4893b1a1e1870479eb692b120929518c8a4',
            'e18cf389c91623072d7e8584860e9ca85a6f5356',
            'e44854e451b4dea705fdf57972ea3bb3ba78ae1d']

class GateError(RuntimeError):
    pass

def require(condition, message):
    if not condition:
        raise GateError(message)

def digest(value):
    if not isinstance(value, bytes):
        value = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(value).hexdigest()

def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.PIPE).decode().strip()

def ancestor(repo, older, newer):
    rc = subprocess.run(['git', '-C', str(repo), 'merge-base', '--is-ancestor', older, newer],
                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE).returncode
    require(rc in (0, 1), 'ancestry operation failed')
    return rc == 0

def resolve(repo, sha):
    require(isinstance(sha, str) and re.fullmatch('[0-9a-f]{40}', sha), 'actual 40hex SHA required')
    require(git(repo, 'rev-parse', '--verify', sha + '^{commit}') == sha, 'commit identity mismatch')

def owned_source(root, repo):
    root, repo = Path(root), Path(repo)
    require(root.is_absolute() and repo.is_absolute(), 'absolute owned paths required')
    require(root.resolve(strict=True) == root and repo.resolve(strict=True) == repo, 'symlink source/root')
    require(repo.is_relative_to(root) and repo != root, 'source outside owned root')
    require(root.stat().st_uid == os.getuid() and repo.stat().st_uid == os.getuid(), 'foreign source owner')
    common = Path(git(repo, 'rev-parse', '--path-format=absolute', '--git-common-dir')).resolve(strict=True)
    require(common.is_relative_to(root), 'Git objects borrowed from outside owned root')
    require(common.stat().st_uid == os.getuid(), 'foreign Git object owner')
    return repo

def validate_vector(data):
    """Generic metadata validation; synthetic tests call this, not runtime policy."""
    require(set(data) == {'sourceRepo', 'ownedRoot', 'base', 'heads', 'rootMode', 'guiMode'}, 'manifest keys/mixed mode')
    require(data['rootMode'] == 'direct-self-initializing', 'outer hook/mixed root modes forbidden')
    require(data['guiMode'] == 'blocked-private-prerequisite', 'private compositor capability not yet established')
    repo = owned_source(data['ownedRoot'], data['sourceRepo'])
    heads = data['heads']
    require(isinstance(heads, list) and heads, 'complete ordered heads required')
    require(all(isinstance(h, dict) and set(h) == {'role', 'sha'} for h in heads), 'head schema')
    roles = [h['role'] for h in heads]
    shas = [data['base'], *(h['sha'] for h in heads)]
    require(all(isinstance(r, str) and r for r in roles), 'role required')
    require(len(set(roles)) == len(roles) and len(set(shas)) == len(shas), 'duplicate role/SHA')
    # Resolve every commit before any kitchen, target, clone or lab operation.
    for sha in shas:
        resolve(repo, sha)
    return repo

def history(repo):
    raw = subprocess.check_output(['git', '-C', str(repo), 'show', ORIGINAL_METHOD + ':' + HISTORY])
    require(digest(raw) == HISTORY_HASH, 'original historical input changed')
    current = (WORKSPACE / HISTORY).read_bytes()
    require(current == raw, 'workspace historical input changed')
    cases = json.loads(raw)['cases']
    require(len(cases) == 52 and len({c['name'] for c in cases}) == 52, 'exact52 identity')
    return cases

def validate_roles(heads):
    roles = {h['role']: h['sha'] for h in heads}
    require(set(roles) == {*PINNED, 'product_fix', 'followup_method'}, 'missing candidate/method or unexpected role')
    require(all(roles[r] == s for r, s in PINNED.items()), 'pinned sibling differs')
    return roles

def validate_runtime(data):
    roles = validate_roles(data['heads'])
    repo = validate_vector(data)
    require(Path(data['ownedRoot']).is_relative_to(WORKSPACE / '.scratch'), 'outside integration-owned workspace')
    require(data['base'] == COMPOSITE, 'no alternate integration base')
    require(roles['followup_method'] == git(WORKSPACE, 'rev-parse', 'HEAD'), 'method commit differs from checked out method')
    require(ancestor(repo, ORIGINAL_METHOD, roles['followup_method']), 'method provenance missing')
    for name, expected in helpers().items():
        blob = subprocess.check_output(['git', '-C', str(repo), 'show', roles['followup_method'] +
                                      ':scripts/chef-integration-followup-20261014/' + name])
        require(digest(blob) == expected, 'uncommitted/different method content')
    require(ancestor(repo, COMPOSITE, roles['product_fix']), 'product candidate lacks original composite')
    for sha in ORIGINAL_HEADS:
        require(ancestor(repo, sha, data['base']), 'original nine provenance missing: ' + sha)
    for sha in [data['base'], *roles.values()]:
        for excluded in EXCLUDED:
            # Missing exclusion objects fail loud too: future source must import proof objects locally.
            resolve(repo, excluded)
            require(not ancestor(repo, excluded, sha), 'excluded input inherited: ' + excluded)
    history(repo)
    return repo

def helpers():
    return {p.name: digest(p.read_bytes()) for p in sorted(METHOD.glob('*.py'))}

def write(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')

def read_request(evidence):
    evidence = Path(evidence).resolve(strict=True)
    require(evidence.is_relative_to(WORKSPACE / '.scratch/chef-followup-runs'), 'outside new owned evidence')
    require(evidence.stat().st_uid == os.getuid() and evidence.stat().st_mode & 0o777 == 0o700, 'evidence ownership/mode')
    req = json.loads((evidence / 'request.json').read_text())
    require(req['helpers'] == helpers(), 'method content changed during run')
    require(req['binding'] == digest({k: v for k, v in req.items() if k != 'binding'}), 'request digest mismatch')
    validate_runtime(req['manifest'])
    return evidence, req

def environment(clone, evidence):
    require((clone / '.toolchain').is_symlink() and (clone / '.toolchain').resolve(strict=True) == TOOLCHAIN,
            'explicit fixed toolchain link required')
    require(TOOLCHAIN.resolve(strict=True) == TOOLCHAIN, 'fixed root toolchain changed')
    # Never inherit desktop, clipboard, dbus, cargo, rustup or credential environment.
    return {'PATH': str(TOOLCHAIN / 'cargo/bin') + ':/usr/bin:/bin', 'HOME': str(evidence / 'home'),
            'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1', 'RUSTUP_AUTO_INSTALL': '0',
            'RUSTUP_HOME': str(TOOLCHAIN / 'rustup'), 'CARGO_HOME': str(TOOLCHAIN / 'cargo'),
            'CARGO_TARGET_DIR': str(clone / 'target'), 'CARGO_NET_OFFLINE': 'true'}

def stage_ancestry(repo, data, previous, index):
    require(index < len(data['heads']), 'extra kitchen stage')
    head = git(repo, 'rev-parse', 'HEAD')
    require(ancestor(repo, previous, head), 'previous merge not retained')
    require(ancestor(repo, data['base'], head), 'base lost')
    for item in data['heads'][:index + 1]:
        require(ancestor(repo, item['sha'], head), 'ordered ancestor missing')
    return head, index == len(data['heads']) - 1
