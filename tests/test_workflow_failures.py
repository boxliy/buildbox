"""Execute finalize failure scripts on a fresh runner, using the workflow's conditions.

GitHub delivery itself is deferred. This harness models implicit success() and
artifact restore failures, while running actual exchange/callback scripts.
"""
import json
import os
from pathlib import Path
import re
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
    if 'failure()' not in expression and 'always()' not in expression and failed:
        return False
    expression = expression.replace('&&', ' and ').replace('||', ' or ')
    expression = expression.replace('failure()', str(failed)).replace('always()', 'True')
    expression = re.sub(r'inputs\.(\w+)', lambda m: repr(inputs[m[1]]), expression)
    return bool(eval(expression, {'__builtins__': {}}, {}))


class FinalizeFailureTests(unittest.TestCase):
    def execute(self, prepare, compile, sign, missing=False):
        inputs = dict(prepare_result=prepare, compile_result=compile, sign_result=sign, failure_reason='fixture prepare failure')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = dict(os.environ, PATH=str(ROOT / 'tests/bin') + os.pathsep + os.environ['PATH'],
                BUILDBOX_STATE_DIR=str(root / 'state'), RUNNER_TEMP=str(root), GITHUB_ENV=str(root / 'env'),
                BUILDBOX_RUN_ID='401', BUILDBOX_GITHUB_RUN_ID='987654321',
                HAWK_BASE_URL='https://hawk.example', HAWK_OIDC_AUDIENCE='https://hawk.example/audience',
                ACTIONS_ID_TOKEN_REQUEST_TOKEN='fixture-request', ACTIONS_ID_TOKEN_REQUEST_URL='https://oidc.example/token?request=1',
                CURL_LOG=str(root / 'curl.log'), FIXTURE_DIR=str(ROOT / 'tests/fixtures'),
                HAWK_CALLBACK_STAGE='finalize', FAILURE_REASON=inputs['failure_reason'])
            env.pop('HAWK_STAGE_TOKEN', None)
            failed = False
            reported = []
            for name, condition, script in steps():
                if not enabled(condition, inputs, failed):
                    continue
                if name.startswith('Restore '):
                    if missing:
                        failed = True
                    continue
                if not script or not ('scripts/exchange-stage' in script or 'scripts/report-result' in script):
                    continue
                script = re.sub(r'\$\{\{ inputs\.(\w+) \}\}', lambda m: inputs[m[1]], script)
                result = subprocess.run(['bash', '-e', '-c', script], cwd=ROOT, env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, name + ': ' + result.stderr)
                if (root / 'env').exists():
                    for line in (root / 'env').read_text().splitlines():
                        key, value = line.split('=', 1)
                        env[key] = value
                reported.extend(re.findall(r'Reported (\w+) for run', result.stdout))
            return reported

    def test_prepare_failure_without_artifacts_gets_one_terminal_receipt(self):
        self.assertEqual(self.execute('failure', 'skipped', 'skipped'), ['failed'])

    def test_each_job_cancellation_gets_a_terminal_receipt(self):
        for results in [('cancelled', 'skipped', 'skipped'), ('success', 'cancelled', 'skipped'), ('success', 'success', 'cancelled')]:
            self.assertEqual(self.execute(*results), ['failed'])

    def test_compile_failure_and_missing_transport_never_report_success(self):
        self.assertEqual(self.execute('success', 'failure', 'skipped'), ['running', 'failed'])
        self.assertEqual(self.execute('success', 'success', 'success', missing=True), ['failed'])


if __name__ == '__main__':
    unittest.main()
