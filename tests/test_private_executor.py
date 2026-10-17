"""Public code hosting must never become public product transport."""
import re
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PrivateExecutorTests(unittest.TestCase):
    def test_all_privileged_jobs_refuse_public_callers(self):
        for stage in ('prepare', 'sign', 'finalize'):
            workflow = (ROOT / f'.github/workflows/{stage}.yml').read_text()
            self.assertRegex(workflow, rf'jobs:\n  {stage}:\n    if: github.event.repository.private == true\n')
        caller = (ROOT / '.github/workflows/build.yml').read_text()
        self.assertIn("if: github.event_name == 'workflow_dispatch' && github.event.repository.private == true", caller)
        self.assertIn('needs: prepare', caller)
        compile_job = caller.split('\n  compile:', 1)[1].split('\n  sign:', 1)[0]
        for forbidden in ('id-token:', 'HAWK_STAGE_TOKEN', 'secrets.', 'dispatch_proof', 'signing-material', 'AVIARY_SOURCE_APP_PRIVATE_KEY'):
            self.assertNotIn(forbidden, compile_job)
        self.assertIn('persist-credentials: false', compile_job)

    def test_artifacts_have_fixed_run_scopes_and_short_retention(self):
        for path in (ROOT / '.github/workflows').glob('*.yml'):
            workflow = path.read_text()
            for step in re.split(r'\n      - name:', workflow)[1:]:
                if 'actions/upload-artifact@' in step:
                    self.assertIn('retention-days: 1', step)
                    self.assertRegex(step, r'name: [a-z-]+-\$\{\{ github.run_id \}\}')
                    for forbidden in ('GITHUB_ENV', 'event.json', 'spec-response.json', 'uploads.json', 'sign-material-', 'signing.keychain'):
                        self.assertNotIn(forbidden, step)
                if 'actions/download-artifact@' in step:
                    self.assertRegex(step, r'name: [a-z-]+-\$\{\{ github.run_id \}\}')
                    self.assertNotIn('github-token:', step)
                    self.assertNotIn('run-id:', step)
                    self.assertNotIn('repository:', step)

    def test_proof_is_read_from_event_not_interpolated_into_logs(self):
        for path in (ROOT / '.github/workflows').glob('*.yml'):
            self.assertNotIn('${{ inputs.dispatch_proof }}', path.read_text())
        script = (ROOT / 'scripts/exchange-stage').read_text()
        self.assertIn('set +x', script)
        self.assertIn('GITHUB_EVENT_PATH', script)
        self.assertNotIn('dispatch_proof', (ROOT / '.github/workflows/build.yml').read_text().split('run-name:',1)[1].split('\n',1)[0])
