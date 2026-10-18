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

def envelope(platform, kind, scope_kind, **extra):
    document = {
        "contract": CONTRACT_VERSION,
        "evaluatedAt": "2026-06-01T00:00:00Z",
        "platform": platform,
        "kind": kind,
        "scope": {
            "validationId": "val", "tenantId": "t", "assetId": "a", "versionId": "v",
            "kind": scope_kind, "stage": "validate",
        },
        "material": {},
    }
    document.update(extra)
    return document


class LimitTests(unittest.TestCase):
    def test_scope_rejects_sign_stage_and_kind_mismatch(self):
        document = envelope(
            "android", None, "android_keystore",
            material={"path": "unused", "storePassword": "x", "keyPassword": "x"},
        )
        document["scope"]["stage"] = "sign"
        with self.assertRaises(ValidationFailure) as error:
            validate_document(document)
        self.assertEqual(error.exception.code, "scope_mismatch")

    def test_zip_slip_is_path_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "bad.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("../outside", b"x")
            document = envelope(
                "ios", "certificate", "apple_certificate",
                material={"path": str(archive), "password": "x"},
            )
            with self.assertRaises(ValidationFailure) as error:
                validate_document(document)
            self.assertEqual(error.exception.code, "path_rejected")

    def test_cli_failure_omits_secrets_and_keeps_identity(self):
        request = {
            "contract": "other",
            "password": "super-secret-value",
            "scope": {
                "validationId": "val-fail", "tenantId": "tenant", "assetId": "asset",
                "versionId": "version", "kind": "android_keystore", "stage": "validate",
            },
            "material": {"privateKey": "BEGIN PRIVATE KEY", "password": "super-secret-value"},
        }
        result = subprocess.run(
            [sys.executable, "-m", "scripts.signing_validation"],
            input=json.dumps(request).encode(), cwd=Path(__file__).resolve().parents[2],
            capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 2)
        body = json.loads(result.stdout)
        self.assertEqual(body["reasonCodes"], ["unsupported_input"])
        self.assertEqual(body["scope"]["validationId"], "val-fail")
        self.assertEqual(body["status"], "invalid")
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
