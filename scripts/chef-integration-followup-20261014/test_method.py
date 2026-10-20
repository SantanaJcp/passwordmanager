#!/usr/bin/env python3
"""Structural tests only: CLEAR SYNTHETIC local Git history, no Rust/product/GUI."""
import ast
import copy
import json
import os
from pathlib import Path
import socket
import tempfile
import subprocess
import unittest
from unittest.mock import patch
from core import (METHOD, WORKSPACE, ORIGINAL_METHOD, HISTORY, HISTORY_HASH, GateError,
                  digest, git, history, stage_ancestry, validate_roles, validate_vector)
from cli_adapter import MIGRATION, adapt, assertions
from gui import FORBIDDEN, GUI_CASES, endpoint_identity, require_private_gui
from sweep import summary

ARTIFACTS = METHOD / os.environ.get('PM_METHOD_UNIT_EVIDENCE', 'structural-evidence')
if ARTIFACTS.parent != METHOD:
    raise RuntimeError('unit evidence must be a NEW direct child of the owned method directory')

class MethodTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ARTIFACTS.mkdir(mode=0o700, exist_ok=False)
        cls.root = ARTIFACTS / 'CLEAR-SYNTHETIC-LOCAL-GIT'
        cls.root.mkdir(mode=0o700)
        cls.repo = cls.root / 'repo'
        cls.repo.mkdir(mode=0o700)
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(cls.root),
               'GIT_AUTHOR_NAME': 'Synthetic method test', 'GIT_AUTHOR_EMAIL': 'synthetic@invalid',
               'GIT_COMMITTER_NAME': 'Synthetic method test', 'GIT_COMMITTER_EMAIL': 'synthetic@invalid',
               'GIT_AUTHOR_DATE': '2000-01-01T00:00:00+00:00', 'GIT_COMMITTER_DATE': '2000-01-01T00:00:00+00:00',
               'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
        cls.env = env
        def run(*args):
            subprocess.run(['git', '-C', str(cls.repo), *args], check=True, env=env, capture_output=True)
        run('init', '-q')
        cls.shas = []
        for i in range(8):
            (cls.repo / 'synthetic.txt').write_text('SYNTHETIC METADATA ONLY ' + str(i))
            run('add', 'synthetic.txt'); run('commit', '-qm', 'synthetic metadata ' + str(i))
            cls.shas.append(git(cls.repo, 'rev-parse', 'HEAD'))
        cls.data = dict(sourceRepo=str(cls.repo), ownedRoot=str(cls.root), base=cls.shas[0],
                        heads=[dict(role='synthetic-stage-' + str(i), sha=sha) for i, sha in enumerate(cls.shas[1:])],
                        rootMode='direct-self-initializing', guiMode='blocked-private-prerequisite')

    def rejected(self, data, fragment):
        with self.assertRaisesRegex((GateError, subprocess.CalledProcessError), fragment):
            validate_vector(data)

    def test_complete_synthetic_resolution(self):
        self.assertEqual(validate_vector(self.data), self.repo)

    def test_duplicate_sha(self):
        d = copy.deepcopy(self.data); d['heads'][1]['sha'] = d['heads'][0]['sha']
        self.rejected(d, 'duplicate')

    def test_duplicate_role(self):
        d = copy.deepcopy(self.data); d['heads'][1]['role'] = d['heads'][0]['role']
        self.rejected(d, 'duplicate')

    def test_unresolvable_actual_sha(self):
        d = copy.deepcopy(self.data); d['heads'][-1]['sha'] = 'f' * 40
        with self.assertRaises(subprocess.CalledProcessError):
            validate_vector(d)

    def test_symbolic_sha_forbidden(self):
        d = copy.deepcopy(self.data); d['heads'][0]['sha'] = 'HEAD'
        self.rejected(d, 'actual 40hex')

    def test_missing_candidate(self):
        with self.assertRaisesRegex(GateError, 'missing candidate'):
            validate_roles([])

    def test_outside_owned_source(self):
        d = copy.deepcopy(self.data); d['ownedRoot'] = str(self.repo)
        self.rejected(d, 'outside owned root')

    def test_no_mixed_root_mode(self):
        d = copy.deepcopy(self.data); d['rootMode'] = 'owned_root+direct'
        self.rejected(d, 'mixed root')

    def test_no_desktop_or_unproved_gui_mode(self):
        d = copy.deepcopy(self.data); d['guiMode'] = 'owner-desktop'
        self.rejected(d, 'not yet established')
        with self.assertRaisesRegex(GateError, 'BLOCKED'):
            require_private_gui()

    def test_arbitrary_seven_stage_vector_final_only(self):
        # Generic synthetic history proves stage-length logic, not kitchen/product integration.
        previous = self.data['base']; finals = []
        for index, entry in enumerate(self.data['heads']):
            subprocess.run(['git', '-C', str(self.repo), 'checkout', '-q', '--detach', entry['sha']],
                           check=True, env=self.env)
            previous, final = stage_ancestry(self.repo, self.data, previous, index)
            finals.append(final)
        self.assertEqual(finals, [False] * 6 + [True])
        with self.assertRaisesRegex(GateError, 'extra kitchen stage'):
            stage_ancestry(self.repo, self.data, previous, 7)

    def test_lost_previous_ancestry_fails(self):
        subprocess.run(['git', '-C', str(self.repo), 'checkout', '-q', '--detach', self.shas[0]],
                       check=True, env=self.env)
        with self.assertRaisesRegex(GateError, 'previous merge'):
            stage_ancestry(self.repo, self.data, self.shas[-1], 0)

    def test_transitive_noop_merge_is_still_an_ancestry_stage(self):
        subprocess.run(['git', '-C', str(self.repo), 'checkout', '-q', '--detach', self.shas[-1]],
                       check=True, env=self.env)
        head, final = stage_ancestry(self.repo, self.data, self.shas[-1], 6)
        self.assertEqual(head, self.shas[-1])
        self.assertTrue(final)

    def test_historical_bytes_order_expectations(self):
        cases = history(WORKSPACE)
        self.assertEqual(digest((WORKSPACE / HISTORY).read_bytes()), HISTORY_HASH)
        self.assertEqual(len(cases), 52)
        self.assertEqual([c['name'] for c in cases[:2]], ['final-check', 'final-clean'])
        self.assertEqual([c['name'] for c in cases if c['historical_expected'] == 1],
                         ['g7-matrix', 'g7-extra-bootstrap', 'g7-extra-vault'])

    def test_red_remains_red_even_expected(self):
        self.assertEqual(summary([dict(name='known-red', rc=1)])['status'], 'ISSUES')
        self.assertEqual(summary([dict(name='gui', rc=None)])['status'], 'BLOCKED')
        cases = history(WORKSPACE)
        rows = [dict(name=c['name'], rc=None if c['name'] in GUI_CASES else c['historical_expected']) for c in cases]
        self.assertEqual(summary(rows)['cases'], 52)
        self.assertEqual(len(summary(rows)['blocked']), 6)
        self.assertEqual(summary(rows)['status'], 'ISSUES')

    def test_cli_all_assertions_and_removal_equality(self):
        source = subprocess.check_output(['git', '-C', str(WORKSPACE), 'show',
                '3b4dd416a4dcd6f7cc301fc4c9f2c1d30ce540d9:crates/pm-cli/tests/chef_human_entry_lab.py']).decode()
        transformed = adapt(source)
        self.assertEqual(assertions(source), assertions(transformed))
        self.assertEqual(transformed.replace(MIGRATION, '', 1), source)
        old = subprocess.check_output(['git', '-C', str(WORKSPACE), 'show',
                                      ORIGINAL_METHOD + ':scripts/chef-integration-20261014/owned_root.py']).decode()
        old_ast = ast.parse(old)
        old_insertions = [node.value.value for node in ast.walk(old_ast) if isinstance(node, ast.Assign)
                          and any(isinstance(t, ast.Name) and t.id == 'migration' for t in node.targets)]
        self.assertEqual(old_insertions, [MIGRATION])
        with self.assertRaisesRegex(GateError, 'mixed migration'):
            adapt(transformed)
        (ARTIFACTS / 'cli-source-proof.json').write_text(json.dumps(dict(source=digest(source.encode()),
            transformed=digest(transformed.encode()), migration=digest(MIGRATION.encode()),
            assertions=len(assertions(source)), removal_equality=True), indent=2) + '\n')

    def test_source_ast_no_chroot_hook_in_new_adapter(self):
        source = (METHOD / 'cli_adapter.py').read_text()
        self.assertNotIn('os.chroot(', source)
        self.assertNotIn('subprocess.Popen =', source)
        self.assertLess(source.index('linux_lab.initialize_installed_fixture(str(custody))'), source.index('exec(compile'))
        for p in METHOD.glob('*.py'):
            ast.parse(p.read_text(), filename=str(p))
        # No suite may inherit owner environment; explicit environment() excludes desktop keys.
        from core import TOOLCHAIN, environment
        with patch('pathlib.Path.is_symlink', return_value=True), patch('pathlib.Path.resolve', return_value=TOOLCHAIN):
            env = environment(Path('/synthetic-clone'), Path('/synthetic-evidence'))
        self.assertFalse(FORBIDDEN & env.keys())

    def test_crossed_endpoint_rejected_without_contact(self):
        runtime = ARTIFACTS / 'private-runtime'; runtime.mkdir(mode=0o700)
        with patch('socket.socket.connect', side_effect=AssertionError('must never contact foreign server')):
            with self.assertRaisesRegex(GateError, 'crossed/foreign'):
                endpoint_identity(runtime, ARTIFACTS / 'wayland-foreign', os.getpid(), 'unused')

    def test_synthetic_socket_process_identity_is_not_gui_proof(self):
        # The observed first run hit Linux sockaddr_un's path-length bound, before any bind.
        # Allocate a fresh short owned unit root; preserve it and its exact ownership receipt.
        runtime = Path(tempfile.mkdtemp(prefix='pm-method-unit-'))
        runtime.chmod(0o700)
        (ARTIFACTS / 'synthetic-runtime.json').write_text(json.dumps(dict(
            path=str(runtime), uid=runtime.stat().st_uid, mode=oct(runtime.stat().st_mode & 0o777),
            purpose='SYNTHETIC UNIT SOCKET ONLY; NOT A GUI'), indent=2) + '\n')
        endpoint = runtime / 'wayland-synthetic'
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(str(endpoint)); server.listen(1)
            cmd = Path('/proc/self/cmdline').read_bytes()
            proof = endpoint_identity(runtime, endpoint, os.getpid(), digest(cmd))
            self.assertEqual(proof['pid'], os.getpid())
            with self.assertRaisesRegex(GateError, 'command differs'):
                endpoint_identity(runtime, endpoint, os.getpid(), digest(b'foreign-command'))
            with self.assertRaisesRegex(GateError, 'BLOCKED'):
                require_private_gui()
        # Preserve synthetic socket path; no foreign or old resource cleanup.

if __name__ == '__main__':
    unittest.main(verbosity=2)
