"""Frozen-source boundary checks, including an opt-in real Aviary exporter."""
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import spec_identity

verify = runpy.run_path(str(ROOT / 'scripts/verify-source-catalog'))['verify']


def digest(value):
    body = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    return 'sha256:' + hashlib.sha256(body).hexdigest()


class SourceCatalogTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.checkout = Path(self.directory.name)
        (self.checkout / 'waterfowl').mkdir()
        (self.checkout / 'waterfowl/pubspec.lock').write_bytes(b'frozen lockfile')
        self.config = json.loads((ROOT / 'tests/fixtures/build-spec-apk.json').read_text())['config']
        native = json.loads((ROOT / 'tests/fixtures/build_spec_v2_identity.json').read_text())['input']
        for key in ('releaseId', 'releaseRevision', 'releaseChannel', 'bundledReleaseCanonicalJson', 'swanConfig'):
            self.config.pop(key, None)
        self.config.update(schemaVersion=2, platform='android', assembly=copy.deepcopy(native['assembly']))
        self.config['assembly']['catalog']['lockfileDigest'] = 'sha256:' + hashlib.sha256(b'frozen lockfile').hexdigest()
        self.config['assembly']['catalog']['sourceCommit'] = self.config['commitSha']
        self.config['dartDefines']['SWAN_INTERNAL_BUILD'] = 'false'
        self.exported = copy.deepcopy(self.config['assembly']['catalog'])
        self.spec = self.checkout / 'spec.json'
        self.write_spec()

    def write_spec(self):
        self.config['assembly']['catalogDigest'] = digest(self.config['assembly']['catalog'])
        self.spec.write_text(json.dumps({'config': self.config, 'specHash': spec_identity.digest(self.config)}))

    def export(self, checkout, commit):
        self.assertEqual(checkout, self.checkout)
        self.assertEqual(commit, self.config['commitSha'])
        return self.exported

    def check(self):
        with patch('subprocess.check_output', return_value=self.config['commitSha'] + '\n'), \
                patch('runpy.run_path', return_value={'export_catalog': self.export}) as loader:
            verify(self.spec, self.checkout)
            loader.assert_called_once_with(str(self.checkout / 'waterfowl/tools/app_assembler/generate_catalog.py'))

    def test_frozen_catalog_is_reexported_before_assembly(self):
        self.check()

    def test_rehashed_catalog_tampering_still_fails_source_comparison(self):
        self.config['assembly']['catalog']['presentations'][0]['messages'] = {'home-title': 'Changed'}
        self.write_spec()
        with self.assertRaisesRegex(ValueError, 'Catalog differs'):
            self.check()

    def test_wrong_checkout_fails_before_source_execution(self):
        with patch('subprocess.check_output', return_value='b' * 40), patch('runpy.run_path') as exporter:
            with self.assertRaisesRegex(ValueError, 'not the frozen source commit'):
                verify(self.spec, self.checkout)
            exporter.assert_not_called()

    def test_modified_working_lockfile_is_rejected(self):
        (self.checkout / 'waterfowl/pubspec.lock').write_bytes(b'changed dependencies')
        with self.assertRaisesRegex(ValueError, 'Working dependency lockfile'):
            self.check()

    def test_modified_spec_fails_before_source_execution(self):
        value = json.loads(self.spec.read_text())
        value['specHash'] = 'sha256:' + '0' * 64
        self.spec.write_text(json.dumps(value))
        with patch('runpy.run_path') as exporter:
            with self.assertRaisesRegex(ValueError, 'Prepared Spec digest'):
                verify(self.spec, self.checkout)
            exporter.assert_not_called()

    @unittest.skipUnless(os.environ.get('BUILDBOX_AVIARY_CHECKOUT'), 'Set BUILDBOX_AVIARY_CHECKOUT for exact-source integration')
    def test_real_aviary_export_and_changed_catalog(self):
        source = Path(os.environ['BUILDBOX_AVIARY_CHECKOUT']).resolve()
        commit = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
        prepare = self.checkout / 'prepare'
        prepare.mkdir()
        original = prepare / 'aviary-source'
        # actions/checkout creates a self-contained repository, not a linked
        # worktree gitfile. Reproduce its shallow exact-commit checkout locally.
        subprocess.run(['git', 'init', '-q', str(original)], check=True)
        subprocess.run(['git', '-C', str(original), 'fetch', '-q', '--depth=1',
                        source.as_uri(), commit], check=True)
        subprocess.run(['git', '-C', str(original), 'checkout', '-q', '--detach', 'FETCH_HEAD'], check=True)
        archive = self.checkout / 'source.tar'
        subprocess.run(['tar', '-cf', str(archive), '-C', str(prepare), 'aviary-source'], check=True)
        compile_root = self.checkout / 'compile'
        compile_root.mkdir()
        subprocess.run(['tar', '-xf', str(archive), '-C', str(compile_root)], check=True)
        checkout = compile_root / 'aviary-source'
        # Hide the prepare repository to prove the tar carries its own objects.
        original.rename(prepare / 'unavailable-source')
        self.assertTrue((checkout / '.git/objects').is_dir())
        output = self.checkout / 'real-catalog.json'
        subprocess.run([sys.executable, str(checkout / 'waterfowl/tools/app_assembler/generate_catalog.py'),
            '--source-commit', commit, '--output', str(output)], check=True)
        catalog = json.loads(output.read_text())
        self.config['commitSha'] = commit
        self.config['frozenInputs']['commitSha'] = commit
        self.config['frozenInputs']['flutterVersion'] = catalog['flutterVersion']
        self.config['assembly']['catalog'] = catalog
        self.write_spec()
        verify(self.spec, checkout)
        self.config['assembly']['catalog']['presentations'][0]['messages']['home-title'] = 'Tampered'
        self.write_spec()
        with self.assertRaisesRegex(ValueError, 'Catalog differs'):
            verify(self.spec, checkout)

        (checkout / '.git').rename(checkout / 'unavailable-git')
        with self.assertRaises(subprocess.CalledProcessError):
            verify(self.spec, checkout)
