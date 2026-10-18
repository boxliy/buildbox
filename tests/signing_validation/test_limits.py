import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.signing_validation.contract import CONTRACT_VERSION, FORBIDDEN_RESULT_KEYS
from scripts.signing_validation.outcome import ValidationFailure
from scripts.signing_validation.validate import validate_document


class LimitTests(unittest.TestCase):
    def test_scope_rejects_sign_stage_and_kind_mismatch(self):
        document = {
            "contract": CONTRACT_VERSION, "evaluatedAt": "2026-06-01T00:00:00Z",
            "platform": "android", "purpose": "direct_distribution", "storeType": "PKCS12",
            "scope": {
                "validationId": "val", "tenantId": "t", "assetId": "a", "versionId": "v",
                "kind": "android_keystore", "stage": "sign",
            },
            "material": {"path": "unused", "storePassword": "x", "keyPassword": "x"},
        }
        with self.assertRaises(ValidationFailure) as error:
            validate_document(document)
        self.assertEqual(error.exception.code, "scope_mismatch")

    def test_traversal_zip_and_size_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "bad.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("../outside", b"x")
            document = {
                "contract": CONTRACT_VERSION, "evaluatedAt": "2026-06-01T00:00:00Z",
                "platform": "ios", "kind": "certificate",
                "scope": {
                    "validationId": "val", "tenantId": "t", "assetId": "a", "versionId": "v",
                    "kind": "apple_certificate", "stage": "validate",
                },
                "material": {"path": str(archive), "password": "x"},
            }
            with self.assertRaises(ValidationFailure) as error:
                validate_document(document)
            self.assertIn(error.exception.code, ("path_rejected", "wrong_password", "malformed_material"))

    def test_cli_failure_omits_secrets(self):
        request = {
            "contract": "other",
            "password": "super-secret-value",
            "material": {"privateKey": "BEGIN PRIVATE KEY"},
        }
        result = subprocess.run(
            [sys.executable, "-m", "scripts.signing_validation"],
            input=json.dumps(request).encode(), cwd=Path(__file__).resolve().parents[2],
            capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 2)
        body = json.loads(result.stdout)
        self.assertEqual(body["reasonCodes"], ["unsupported_input"])
        rendered = result.stdout.decode() + result.stderr.decode()
        self.assertNotIn("super-secret-value", rendered)
        self.assertNotIn("BEGIN PRIVATE", rendered)
        self.assertTrue(FORBIDDEN_RESULT_KEYS.isdisjoint(body))

    def test_oversized_stdin(self):
        result = subprocess.run(
            [sys.executable, "-m", "scripts.signing_validation"],
            input=b'{"a":"' + b"x" * (1024 * 1024) + b'"}',
            cwd=Path(__file__).resolve().parents[2], capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["reasonCodes"], ["size_limit"])
        self.assertEqual(result.stderr, b"")


if __name__ == "__main__":
    unittest.main()
