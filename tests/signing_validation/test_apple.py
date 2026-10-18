import datetime
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes

from tests.signing_validation import fixtures
from scripts.signing_validation.contract import CONTRACT_VERSION
from scripts.signing_validation.outcome import ValidationFailure
from scripts.signing_validation.validate import validate_document


WHEN = "2026-06-01T16:00:00Z"
UTC = datetime.timezone.utc


def scope(kind):
    return {
        "validationId": "val-ios", "tenantId": "tenant-1", "assetId": "asset-1",
        "versionId": "version-1", "kind": kind, "stage": "validate",
    }


class AppleMaterialTests(unittest.TestCase):
    def certificate_request(self, path, password=fixtures.PASSWORD):
        return {
            "contract": CONTRACT_VERSION, "evaluatedAt": WHEN, "platform": "ios",
            "kind": "certificate", "scope": scope("apple_certificate"),
            "material": {"path": str(path), "password": password},
        }

    def profile_request(self, path, expectations=None):
        document = {
            "contract": CONTRACT_VERSION, "evaluatedAt": WHEN, "platform": "ios",
            "kind": "provisioning_profile", "scope": scope("apple_profile"),
            "material": {"path": str(path)},
        }
        if expectations:
            document["expectations"] = expectations
        return document

    def signed_profile(self, directory, distribution, **kwargs):
        key, signer = fixtures.rsa_key(), fixtures.rsa_key()
        leaf = kwargs.pop("certificate", None) or fixtures.certificate(key, "Leaf", team="TEAM123456")
        signer_cert = fixtures.certificate(signer, "Fixture CMS")
        payload = fixtures.profile_plist(distribution, certificate=leaf, **kwargs)
        path = Path(directory) / (distribution + ".mobileprovision")
        fixtures.cms_sign(payload, signer, signer_cert, path)
        return path, leaf

    def test_rsa_and_ec_certificates_match_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, key in (("rsa.p12", fixtures.rsa_key()), ("ec.p12", fixtures.ec_key())):
                cert = fixtures.certificate(key, name, team="TEAM123456")
                path = root / name
                path.write_bytes(fixtures.p12_bytes(key, cert))
                result = validate_document(self.certificate_request(path))
                self.assertEqual(result["status"], "invalid", name)
                self.assertIn("macos_capability_unavailable", result["reasonCodes"])
                self.assertNotIn("ok", result["reasonCodes"])
                self.assertEqual(result["certificate"]["algorithm"], "RSA" if name.startswith("rsa") else "EC")
                self.assertEqual(result["certificate"]["teamId"], "TEAM123456")
                self.assertTrue(result["certificate"]["signingCapable"])
                self.assertTrue(result["evidence"]["privateKeyProven"])
                self.assertFalse(result["evidence"]["chainTrusted"])
                self.assertFalse(result["evidence"]["trustedByPlatform"])
                self.assertFalse(result["evidence"]["installable"])
                self.assertIn("security_cms_anchor_verify", result["evidence"]["notExecuted"])
            with self.assertRaises(ValidationFailure) as wrong:
                validate_document(self.certificate_request(root / "rsa.p12", password="nope"))
            self.assertEqual(wrong.exception.code, "wrong_password")

    def test_private_key_mismatch(self):
        import os
        from scripts.signing_validation.apple import match_private_key
        from scripts.signing_validation.tools import run
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.p12"
            key = fixtures.rsa_key()
            owned = fixtures.certificate(key, "Owned", team="TEAM123456")
            other = fixtures.certificate(fixtures.rsa_key(), "Other", team="TEAM123456")
            path.write_bytes(fixtures.p12_bytes(key, owned))
            env = dict(os.environ, VALIDATION_P12_PASSWORD=fixtures.PASSWORD)
            code, key_pem = run([
                "openssl", "pkcs12", "-in", str(path), "-nocerts", "-nodes",
                "-passin", "env:VALIDATION_P12_PASSWORD",
            ], env)
            self.assertEqual(code, 0)
            match_private_key(key_pem, owned)
            with self.assertRaises(ValidationFailure) as mismatch:
                match_private_key(key_pem, other)
            self.assertEqual(mismatch.exception.code, "private_key_mismatch")

    def test_four_distributions_and_timezone_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            cases = {
                "development": {"devices": ["device-1"]},
                "ad_hoc": {"devices": ["device-1"]},
                "enterprise": {"all_devices": True},
                "app_store": {},
            }
            for distribution, options in cases.items():
                path, leaf = self.signed_profile(directory, distribution, **options)
                result = validate_document(self.profile_request(path, {
                    "teamId": "TEAM123456", "bundleId": "com.example.app", "distribution": distribution,
                    "certificateSha256": leaf.fingerprint(hashes.SHA256()).hex(),
                    "entitlements": {
                        "application-identifier": "TEAM123456.com.example.app",
                        "com.apple.developer.team-identifier": "TEAM123456",
                        "get-task-allow": distribution == "development",
                    },
                }))
                self.assertEqual(result["status"], "invalid", distribution)
                self.assertEqual(result["reasonCodes"], ["macos_capability_unavailable"])
                self.assertEqual(result["profile"]["distribution"], distribution)
                self.assertEqual(result["profile"]["uuid"], "11111111-2222-3333-4444-555555555555")
                self.assertIn("get-task-allow", result["profile"]["entitlements"])
                self.assertFalse(result["evidence"]["cmsSignatureVerified"])
                self.assertTrue(result["evidence"]["cmsParsed"])
            # 2026-06-01T16:00:00Z is 2026-06-02 in Asia/Taipei.
            boundary, _leaf = self.signed_profile(
                directory, "development", devices=["device-1"],
                created=datetime.datetime(2026, 6, 1, 16, 0, tzinfo=UTC),
                expires=datetime.datetime(2026, 6, 2, 16, 0, tzinfo=UTC))
            result = validate_document({**self.profile_request(boundary), "evaluatedAt": "2026-06-01T15:59:59Z"})
            self.assertIn("profile_not_yet_valid", result["reasonCodes"])
            result = validate_document({**self.profile_request(boundary), "evaluatedAt": "2026-06-02T16:00:00Z"})
            self.assertIn("profile_expired", result["reasonCodes"])
            self.assertEqual(result["profile"]["expiresAt"], "2026-06-02T16:00:00Z")

    def test_rejects_tamper_team_bundle_and_claimed_type(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _leaf = self.signed_profile(directory, "ad_hoc", devices=["device-1"])
            data = path.read_bytes()
            path.write_bytes(data[:-8] + b"tampered")
            with self.assertRaises(ValidationFailure) as broken:
                validate_document(self.profile_request(path))
            self.assertEqual(broken.exception.code, "cms_invalid")
            path.write_bytes(data)
            mismatched = validate_document(self.profile_request(path, {
                "teamId": "OTHERTEAM1", "bundleId": "com.other.app", "distribution": "app_store",
                "certificateSha256": "ab" * 32,
                "entitlements": {"aps-environment": "production", "get-task-allow": True},
            }))
            self.assertEqual(mismatched["status"], "invalid")
            self.assertIn("team_mismatch", mismatched["reasonCodes"])
            self.assertIn("bundle_mismatch", mismatched["reasonCodes"])
            self.assertIn("distribution_mismatch", mismatched["reasonCodes"])
            self.assertIn("certificate_mismatch", mismatched["reasonCodes"])
            self.assertIn("entitlements_mismatch", mismatched["reasonCodes"])
            self.assertEqual(mismatched["profile"]["distribution"], "ad_hoc")
            self.assertEqual(mismatched["profile"]["entitlements"]["get-task-allow"], False)


if __name__ == "__main__":
    unittest.main()
