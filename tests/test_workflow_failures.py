"""Execute finalize failure scripts on a fresh runner, using the workflow's conditions.

GitHub delivery itself is deferred. This harness models implicit success() and
artifact restore failures, while running actual exchange/callback scripts.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def steps():
    source = (ROOT / '.github/workflows/finalize.yml').read_text()
    result = []
    for match in re.finditer(r'^      - name: ([^\n]+)\n(.*?)(?=^      - name:|\Z)', source, re.M | re.S):
        name, body = match.groups()
        condition = re.search(r'^        if: (.+)$', body, re.M)
        run = re.search(r'^        run: (.+)\n?', body, re.M)
        script = None
        if run:
            script = run.group(1)
            if script == '|':
                script = '\n'.join(line[10:] for line in body[run.end():].splitlines() if line.startswith('          '))
        result.append((name, condition.group(1) if condition else None, script))
    return result


def enabled(expression, inputs, failed):
    if not expression:
        return not failed
    expression = expression.removeprefix('${{').removesuffix('}}').strip()
    # GitHub applies success() unless a status function is present:
    # https://docs.github.com/en/actions/reference/workflows-and-actions/expressions#status-check-functions
    if not re.search(r'\b(success|failure|always|cancelled)\(\)', expression):
        expression = 'success() && (' + expression + ')'
    expression = expression.replace('&&', ' and ').replace('||', ' or ')
    expression = expression.replace('failure()', str(failed)).replace('success()', str(not failed)).replace('always()', 'True').replace('cancelled()', 'False')
    expression = re.sub(r'inputs\.(\w+)', lambda m: repr(inputs[m[1]]), expression)
    return bool(eval(expression, {'__builtins__': {}}, {}))


class FinalizeFailureTests(unittest.TestCase):
    def execute(self, prepare, compile, sign, missing=None, upload_failure=False):
        inputs = dict(prepare_result=prepare, compile_result=compile, sign_result=sign, failure_reason='fixture prepare failure')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'event.json').write_text(json.dumps({'inputs': {'dispatch_proof': 'a' * 64}}))
            env = dict(os.environ, PATH=str(ROOT / 'tests/bin') + os.pathsep + os.environ['PATH'],
                BUILDBOX_STATE_DIR=str(root / 'state'), RUNNER_TEMP=str(root), GITHUB_ENV=str(root / 'env'),
                GITHUB_EVENT_PATH=str(root / 'event.json'), BUILDBOX_RUN_ID='401', BUILDBOX_GITHUB_RUN_ID='987654321',
                HAWK_BASE_URL='https://hawk.example', HAWK_OIDC_AUDIENCE='https://hawk.example/audience',
                ACTIONS_ID_TOKEN_REQUEST_TOKEN='fixture-request', ACTIONS_ID_TOKEN_REQUEST_URL='https://oidc.example/token?request=1',
                CURL_LOG=str(root / 'curl.log'), FIXTURE_DIR=str(ROOT / 'tests/fixtures'),
                HAWK_CALLBACK_STAGE='finalize', FAILURE_REASON=inputs['failure_reason'],
                MOCK_UPLOAD_FAIL='1' if upload_failure else '0', MOCK_CALLBACK_LOG=str(root / 'callbacks.jsonl'))
            env.pop('HAWK_STAGE_TOKEN', None)
            failed = False
            executed = []
            for index, (name, condition, script) in enumerate(steps()):
                if not enabled(condition, inputs, failed):
                    continue
                executed.append(name)
                if name.startswith('Restore '):
                    if missing == name:
                        failed = True
                        continue
                    state = root / 'state'
                    state.mkdir(exist_ok=True)
                    if name == 'Restore sign inputs':
                        (state / 'targets.json').write_text('["apk"]')
                        (state / 'spec.env').write_text(
                            'BUILDBOX_TARGETS_JSON=' + shlex.quote(str(state / 'targets.json')) + '\n'
                            'BUILDBOX_ARTIFACT_PREFIX=builds/spec-apk-1/build-apk-1/\n')
                    else:
                        (state / 'artifacts').mkdir()
                        content = b'signed fixture transport'
                        (state / 'artifacts/swan-release.apk').write_bytes(content)
                        (state / 'artifacts.json').write_text(json.dumps([dict(
                            target='apk', fileName='swan-release.apk', byteSize=len(content),
                            sha256='sha256:' + hashlib.sha256(content).hexdigest(), signMode='signed')]))
                        (state / 'sign-proof.json').write_text('{"signer":"fixture-signer"}')
                    continue
                if not script or name == 'Initialize isolated state directory':
                    continue
                # Actions gives every step a fresh command file; exported values
                # persist in the environment, not in the next step's file.
                command_file = root / f'env-{index}'
                command_file.touch()
                env['GITHUB_ENV'] = str(command_file)
                script = re.sub(r'\$\{\{ inputs\.(\w+) \}\}', lambda m: inputs[m[1]], script)
                result = subprocess.run(['bash', '-e', '-c', script], cwd=ROOT, env=env, capture_output=True, text=True)
                if result.returncode:
                    self.assertEqual(name, 'Upload signed artifacts', name + ': ' + result.stderr)
                    self.assertTrue(upload_failure, result.stderr)
                    failed = True
                if command_file.exists():
                    for line in command_file.read_text().splitlines():
                        key, value = line.split('=', 1)
                        env[key] = value
            callbacks = [json.loads(line) for line in (root / 'callbacks.jsonl').read_text().splitlines()]
            reported = [callback['status'] for callback in callbacks]
            self.assertEqual(len([status for status in reported if status != 'running']), 1)
            if missing or upload_failure:
                self.assertNotIn('Report success', executed)
                self.assertNotIn('succeeded', reported)
            if upload_failure:
                self.assertIn('Upload signed artifacts', executed)
                self.assertIn('PUT', (root / 'curl.log').read_text())
            return reported

    def test_prepare_failure_without_artifacts_gets_one_terminal_receipt(self):
        self.assertEqual(self.execute('failure', 'skipped', 'skipped'), ['failed'])

    def test_each_job_cancellation_gets_a_terminal_receipt(self):
        for results in [('cancelled', 'skipped', 'skipped'), ('success', 'cancelled', 'skipped'), ('success', 'success', 'cancelled')]:
            self.assertEqual(self.execute(*results), ['failed'])

    def test_compile_failure_and_missing_transport_never_report_success(self):
        self.assertEqual(self.execute('success', 'failure', 'skipped'), ['running', 'failed'])
        for missing in ['Restore sign inputs', 'Restore signed outputs']:
            with self.subTest(missing=missing):
                self.assertEqual(self.execute('success', 'success', 'success', missing=missing), ['failed'])

    def test_upload_failure_with_restored_metadata_only_posts_failure(self):
        self.assertEqual(self.execute('success', 'success', 'success', upload_failure=True), ['running', 'failed'])

    def test_successful_upload_posts_success(self):
        self.assertEqual(self.execute('success', 'success', 'success'), ['running', 'succeeded'])

    def test_sign_failure_posts_failure(self):
        self.assertEqual(self.execute('success', 'success', 'failure'), ['running', 'failed'])

    def test_status_function_selection_matches_actions(self):
        inputs = {'sign_result': 'success'}
        self.assertFalse(enabled("${{ inputs.sign_result == 'success' }}", inputs, True))
        self.assertFalse(enabled("${{ success() && inputs.sign_result == 'success' }}", inputs, True))
        self.assertTrue(enabled("${{ failure() && inputs.sign_result == 'success' }}", inputs, True))
        self.assertTrue(enabled('${{ always() }}', inputs, True))



if __name__ == '__main__':
    unittest.main()
