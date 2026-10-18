import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.signing_validation import fixtures
from scripts.signing_validation.contract import CONTRACT_VERSION, TRUST_CHECKS
from scripts.signing_validation.tools import not_executed
from scripts.signing_validation.validate import validate_document


WHEN = "2026-06-01T00:00:00Z"


class ToolsPresentTrustTests(unittest.TestCase):
    def test_present_macos_tools_remain_not_executed(self):
        with mock.patch("scripts.signing_validation.tools.probe", return_value={
            "openssl": "OpenSSL 3.6.5",
            "keytool": "openjdk 17",
            "security": "present",
            "codesign": "present",
            "macosKeychain": True,
        }):
            self.assertEqual(not_executed(), list(TRUST_CHECKS))

    def test_apple_stays_invalid_when_tools_exist_but_trust_did_not_run(self):
        present = {
            "openssl": "OpenSSL 3.6.5",
            "keytool": "openjdk 17",
            "security": "present",
            "codesign": "present",
            "macosKeychain": True,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = fixtures.rsa_key()
            cert = fixtures.certificate(key, "Leaf", team="TEAM123456")
            certificate_path = root / "identity.p12"
            certificate_path.write_bytes(fixtures.p12_bytes(key, cert))
            signer = fixtures.rsa_key()
            signer_cert = fixtures.certificate(signer, "Fixture CMS")
            profile_path = root / "development.mobileprovision"
            fixtures.cms_sign(
                fixtures.profile_plist("development", certificate=cert, devices=["device-1"]),
                signer, signer_cert, profile_path)
            certificate = {
                "contract": CONTRACT_VERSION, "evaluatedAt": WHEN, "platform": "ios",
                "kind": "certificate",
                "scope": {
                    "validationId": "val-ios", "tenantId": "tenant-1", "assetId": "asset-1",
                    "versionId": "version-1", "kind": "apple_certificate", "stage": "validate",
                },
                "material": {"path": str(certificate_path), "password": fixtures.PASSWORD},
            }
            profile = {
                "contract": CONTRACT_VERSION, "evaluatedAt": WHEN, "platform": "ios",
                "kind": "provisioning_profile",
                "scope": {
                    "validationId": "val-ios", "tenantId": "tenant-1", "assetId": "asset-1",
                    "versionId": "version-1", "kind": "apple_profile", "stage": "validate",
                },
                "material": {"path": str(profile_path)},
            }
            with mock.patch("scripts.signing_validation.tools.probe", return_value=present):
                certificate_result = validate_document(certificate)
                profile_result = validate_document(profile)
        for result in (certificate_result, profile_result):
            self.assertEqual(result["status"], "invalid")
            self.assertNotIn("ok", result["reasonCodes"])
            self.assertEqual(result["evidence"]["notExecuted"], list(TRUST_CHECKS))
            self.assertFalse(result["evidence"]["chainTrusted"])
            self.assertFalse(result["evidence"]["cmsSignatureVerified"])

    def test_android_can_be_valid_only_when_no_check_remains(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "keys.p12"
            key = fixtures.rsa_key()
            fixtures.keystore(store, "release", key, fixtures.certificate(key, "RSA"), "PKCS12")
            request = {
                "contract": CONTRACT_VERSION, "evaluatedAt": WHEN, "platform": "android",
                "scope": {
                    "validationId": "val-1", "tenantId": "tenant-1", "assetId": "asset-1",
                    "versionId": "version-1", "kind": "android_keystore", "stage": "validate",
                },
                "material": {
                    "path": str(store), "storePassword": fixtures.PASSWORD,
                    "keyPassword": fixtures.PASSWORD, "alias": "release",
                },
            }
            blocked = validate_document(request)
            self.assertEqual(blocked["status"], "invalid")
            self.assertTrue(blocked["evidence"]["privateKeyProven"])
            self.assertTrue(blocked["evidence"]["notExecuted"])
            with mock.patch("scripts.signing_validation.validate.not_executed", return_value=[]):
                proven = validate_document(request)
        self.assertEqual(proven["status"], "valid")
        self.assertEqual(proven["reasonCodes"], ["ok"])
        self.assertFalse(proven["evidence"]["chainTrusted"])
        self.assertEqual(proven["evidence"]["notExecuted"], [])

    def test_empty_not_executed_does_not_make_untrusted_apple_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.p12"
            key = fixtures.rsa_key()
            path.write_bytes(fixtures.p12_bytes(
                key, fixtures.certificate(key, "Leaf", team="TEAM123456")))
            request = {
                "contract": CONTRACT_VERSION, "evaluatedAt": WHEN, "platform": "ios",
                "kind": "certificate",
                "scope": {
                    "validationId": "val-ios", "tenantId": "tenant-1", "assetId": "asset-1",
                    "versionId": "version-1", "kind": "apple_certificate", "stage": "validate",
                },
                "material": {"path": str(path), "password": fixtures.PASSWORD},
            }
            with mock.patch("scripts.signing_validation.validate.not_executed", return_value=[]):
                result = validate_document(request)
        self.assertEqual(result["status"], "invalid")
        self.assertNotEqual(result["reasonCodes"], ["ok"])
        self.assertFalse(result["evidence"]["chainTrusted"])


class WorkflowContractTests(unittest.TestCase):
    def test_reusable_job_matches_dispatch_caller(self):
        root = Path(__file__).resolve().parents[2]
        reusable = (root / ".github/workflows/validate-signing-material.yml").read_text()
        caller = (root / ".github/workflows/validate-material.yml").read_text()
        self.assertNotIn("github.event_name == 'workflow_call'", reusable)
        self.assertNotIn('== "workflow_call"', reusable)
        self.assertIn("github.event_name != 'pull_request'", reusable)
        self.assertIn("github.event.repository.private == true", reusable)
        self.assertIn("actions/setup-java@cf277c60eb25467037889841efdb72551f06f6c3", reusable)
        self.assertIn("distribution: temurin", reusable)
        self.assertIn("java-version: '17'", reusable)
        self.assertIn("HAWK_OIDC_AUDIENCE: ${{ secrets.HAWK_OIDC_AUDIENCE }}", caller)
        self.assertIn("secrets:\n      HAWK_OIDC_AUDIENCE:", reusable)
        pinned = "549b8a8c5005ae16c092c98c32452d4cf559f0d9"
        self.assertEqual(caller.count(pinned), 2)


if __name__ == "__main__":
    unittest.main()
