import base64
import datetime
import json
import tempfile
import unittest
from pathlib import Path

from tests.signing_validation import fixtures
from scripts.signing_validation.hawk_adapter import AdapterError, hawk_result, offline_request
from scripts.signing_validation.validate import validate_document


WHEN = "2026-06-01T00:00:00Z"
IDENTITY = {
    "validationId": "101",
    "tenantId": "102",
    "assetId": "103",
    "versionId": "104",
    "toolchainSha": "dddddddddddddddddddddddddddddddddddddddd",
}


def envelope(kind, container, password="fixture-only", key_password=None, expected=None):
    material = {"containerBase64": base64.b64encode(container).decode(), "password": password}
    if key_password is not None:
        material["keyPassword"] = key_password
    return {
        "schemaVersion": 1,
        **IDENTITY,
        "kind": kind,
        "material": material,
        "expected": {} if expected is None else expected,
    }


class HawkAdapterTests(unittest.TestCase):
    def test_empty_expected_becomes_offline_android_request(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "keys.p12"
            key = fixtures.rsa_key()
            fixtures.keystore(store, "release", key, fixtures.certificate(key, "RSA"), "PKCS12")
            document = envelope("android_keystore", store.read_bytes(), fixtures.PASSWORD, fixtures.PASSWORD)
            offline = offline_request(document, WHEN)
        self.assertEqual(offline["contract"], "signing-material-validation/v1")
        self.assertEqual(offline["evaluatedAt"], WHEN)
        self.assertNotIn("purpose", offline)
        self.assertNotIn("storeType", offline)
        self.assertEqual(offline["material"]["storePassword"], fixtures.PASSWORD)
        self.assertEqual(offline["scope"]["kind"], "android_keystore")

    def test_published_android_result_matches_allowlist(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "keys.p12"
            key = fixtures.rsa_key()
            certificate = fixtures.certificate(
                key, "RSA",
                not_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
                not_after=datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc))
            fixtures.keystore(store, "release", key, certificate, "PKCS12")
            document = envelope("android_keystore", store.read_bytes(), fixtures.PASSWORD, fixtures.PASSWORD)
            offline = validate_document(offline_request(document, WHEN))
        result = hawk_result(document, offline, WHEN)
        self.assertEqual(result["schemaVersion"], 1)
        self.assertEqual(result["validatedAt"], WHEN)
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(result["reasonCodes"], ["macos_capability_unavailable"])
        self.assertNotIn("ok", result["reasonCodes"])
        self.assertNotIn("selectedAlias", result["metadata"])
        self.assertEqual(result["metadata"]["expiresAt"], result["metadata"]["aliases"][0]["expiresAt"])
        self.assertEqual(result["metadata"]["aliases"][0]["purpose"], "signing")
        self.assertTrue(result["evidence"]["privateKeyProven"])
        self.assertFalse(result["evidence"]["chainTrusted"])
        self.assertIn("security_cms_anchor_verify", result["evidence"]["notExecuted"])
        rendered = json.dumps(result)
        self.assertNotIn(fixtures.PASSWORD, rendered)
        self.assertNotIn("containerBase64", rendered)

    def test_profile_distribution_and_entitlement_code(self):
        offline = {
            "contract": "signing-material-validation/v1",
            "status": "invalid",
            "reasonCodes": ["entitlements_mismatch", "macos_capability_unavailable"],
            "scope": {**{key: IDENTITY[key] for key in ("validationId", "tenantId", "assetId", "versionId")}, "kind": "apple_profile"},
            "profile": {
                "uuid": "11111111-2222-3333-4444-555555555555",
                "teamId": "TEAM123456",
                "applicationIdentifier": "TEAM123456.com.example.app",
                "distribution": "app_store",
                "developerCertificateSha256": ["aa" * 32],
                "entitlements": {"get-task-allow": False},
                "expiresAt": "2026-12-31T00:00:00Z",
            },
            "evidence": {"notExecuted": ["security_cms_anchor_verify"]},
            "tools": {"openssl": "OpenSSL 3.6.5", "macosKeychain": False},
        }
        document = envelope("apple_profile", b"not-posted")
        result = hawk_result(document, offline, WHEN)
        self.assertEqual(result["metadata"]["distributionMethod"], "app-store")
        self.assertEqual(result["metadata"]["entitlements"], {"get-task-allow": False})
        self.assertEqual(result["reasonCodes"], ["entitlement_mismatch", "macos_capability_unavailable"])
        self.assertEqual(result["evidence"]["tools"], [{"name": "openssl", "version": "OpenSSL 3.6.5"}])

    def test_valid_reasons_are_empty_and_unknown_codes_fail(self):
        offline = {
            "contract": "signing-material-validation/v1",
            "status": "valid",
            "reasonCodes": ["ok"],
            "scope": {**{key: IDENTITY[key] for key in ("validationId", "tenantId", "assetId", "versionId")}, "kind": "android_keystore"},
            "expiresAt": "2099-01-01T00:00:00Z",
            "aliases": [],
            "evidence": {"privateKeyProven": True, "notExecuted": []},
            "tools": {},
        }
        document = envelope("android_keystore", b"unused")
        result = hawk_result(document, offline, WHEN)
        self.assertEqual(result["reasonCodes"], [])
        offline["reasonCodes"] = ["invented_code"]
        offline["status"] = "invalid"
        with self.assertRaises(AdapterError):
            hawk_result(document, offline, WHEN)

    def test_missing_instant_is_not_material_damage(self):
        document = envelope("apple_certificate", b"\x30\x00", "secret")
        with self.assertRaises(AdapterError) as error:
            offline_request(document, None)
        self.assertNotIn("material", error.exception.message)


if __name__ == "__main__":
    unittest.main()
