#!/usr/bin/env python3
"""LOCAL metadata only: normalize authored deltas; never run product checks.

Principles: isolate, evidence, truthful-state. A fresh destination is mandatory.
The returned known refs are incomplete until the reviewed product fix exists.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

BASE = '8cd45529b062506a2cbe0c567538d3999ac8a2b6'
METHOD = '0a11733ffc784e80cb75c8df01d2cdcf34862d7e'
CALLER = '3b4dd416a4dcd6f7cc301fc4c9f2c1d30ce540d9'
DOC_DELTAS = ['e1307808be9b88a77cc3a9725356b7281f4bb49f',
              '2d86a31537d9418b7f7f7a66e567ca84fe82f505']
TLS_DELTA = 'fffceb33622af151a55216677b20946b05f4e844'
ROOT = Path(__file__).resolve().parents[2]
SOURCES = {'local': ROOT, 'docs': Path('/home/santana/.t3/worktrees/passwordmanager/t3-9eb5de46'),
           'tls': Path('/home/santana/.t3/worktrees/passwordmanager/t3-e1e1ea68')}

def main():
    destination = Path(sys.argv[1]).resolve()
    destination.mkdir(parents=True, mode=0o700, exist_ok=False)
    repo = destination / 'repo'
    env = {k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
    commit_env = env | {'GIT_COMMITTER_NAME':'chef metadata normalization',
        'GIT_COMMITTER_EMAIL':'normalization@kitchen.invalid',
        'GIT_COMMITTER_DATE':'2000-01-01T00:00:00+00:00'}
    operations = []
    def git(*args, cwd=repo, input=None, commit=False):
        command = ['git','-C',str(cwd),*args]
        result = subprocess.run(command, input=input, capture_output=True,
            env=commit_env if commit else env)
        operations.append(dict(command=command,rc=result.returncode,
            stdout=result.stdout.decode(errors='replace'),stderr=result.stderr.decode(errors='replace')))
        (destination/'git-operations.json').write_text(json.dumps(operations,indent=2)+'\n')
        if result.returncode:
            raise RuntimeError(json.dumps(operations[-1]))
        return result.stdout
    def sha(ref):
        return git('rev-parse',ref).decode().strip()
    def paths(parent, head):
        return git('diff','--name-only',parent,head).decode().splitlines()
    def patch_id(ref):
        patch=git('show','--format=','--binary',ref)
        stable=git('patch-id','--stable',input=patch).decode().split()[0]
        return dict(stable_patch_id=stable,raw_diff_sha256=hashlib.sha256(patch).hexdigest())
    def content(ref, names):
        return {name:dict(blob=sha(ref+':'+name),sha256=hashlib.sha256(git('show',ref+':'+name)).hexdigest())
                for name in names}
    git('init','-q',str(repo),cwd=destination)
    imports=[('local',BASE,'original-composite'),('local',METHOD,'original-method'),
             ('local',CALLER,'selected-caller'),('docs',DOC_DELTAS[-1],'docs-source'),
             ('tls',TLS_DELTA,'tls-source')]
    for lane,ref,label in imports:
        assert SOURCES[lane].is_dir()
        git('fetch','--no-tags','--no-write-fetch-head',str(SOURCES[lane]),
            ref+':refs/inputs/'+label)
        assert sha('refs/inputs/'+label)==ref
    mappings=[]
    def normalize(branch, deltas, allowed):
        git('checkout','-q','-b',branch,BASE)
        for source in deltas:
            old_parent=sha(source+'^')
            old_paths=paths(old_parent,source)
            assert set(old_paths)<=allowed
            parent=sha('HEAD')
            git('cherry-pick','-x',source,commit=True)
            normalized=sha('HEAD')
            assert sha(normalized+'^')==parent
            assert paths(parent,normalized)==old_paths
            original_patch,normalized_patch=patch_id(source),patch_id(normalized)
            assert original_patch['stable_patch_id']==normalized_patch['stable_patch_id']
            original_content=content(source,old_paths)
            assert content(normalized,old_paths)==original_content
            mappings.append(dict(source=source,source_parent=old_parent,normalized=normalized,
                normalized_parent=parent,paths=old_paths,content=original_content,
                source_patch=original_patch,normalized_patch=normalized_patch))
        head=sha('HEAD')
        assert set(paths(BASE,head))<=allowed
        return head
    guide=normalize('chef/normalized-guide-20261014',DOC_DELTAS,
        {'README.md','docs/user/evaluacion-linux.md','docs/verification/chef-guide-alignment-20261014.md'})
    tls=normalize('chef/normalized-tls-gate-20261014',[TLS_DELTA],
        {'crates/pm-sync/src/frame_cost_tests.rs','docs/verification/chef-sync-probe-gate-20261014.md'})
    excluded={}
    for ref in ['2801c4893b1a1e1870479eb692b120929518c8a4','e18cf389c91623072d7e8584860e9ca85a6f5356',
                'e44854e451b4dea705fdf57972ea3bb3ba78ae1d']:
        # Object absence is not ancestry evidence: fetch exact local object first.
        git('fetch','--no-tags','--no-write-fetch-head',str(SOURCES['local']),ref)
        excluded[ref]={}
        for head in [BASE,CALLER,guide,tls,METHOD]:
            result=subprocess.run(['git','-C',str(repo),'merge-base','--is-ancestor',ref,head],env=env)
            assert result.returncode==1
            excluded[ref][head]=result.returncode
    caller_paths=paths(BASE,CALLER)
    production_paths=[name for name in caller_paths if '/src/' in name or name.startswith('scripts/')
        or name in {'Cargo.toml','Cargo.lock','rust-toolchain.toml'} or name.startswith('.github/')]
    assert not production_paths
    record=dict(status='CLEAN_METADATA_ONLY',repo=str(repo),base=BASE,method=METHOD,
        selected_caller=CALLER,normalized_guide=guide,normalized_tls_gate=tls,
        mappings=mappings,normalized_diffs={guide:paths(BASE,guide),tls:paths(BASE,tls)},
        caller_inherited_paths=paths(BASE,sha(CALLER+'^')),caller_changed_paths=caller_paths,
        excluded_ancestry=excluded,known_refs=[CALLER,guide,tls,METHOD],
        product_fix=dict(status='NOT_RETURNED',required_before_execution=True),
        kitchen_integrate='NOT_RUN',cargo_build_check_labs_full52='NOT_RUN',
        prepared_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    (destination/'provenance.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))

if __name__=='__main__':
    main()
