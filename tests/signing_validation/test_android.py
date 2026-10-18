import datetime
import json
import tempfile
import unittest
from pathlib import Path

from tests.signing_validation import fixtures
from scripts.signing_validation.contract import CONTRACT_VERSION
from scripts.signing_validation.validate import validate_document
from scripts.signing_validation.outcome import ValidationFailure


WHEN = "2026-06-01T00:00:00Z"
def scope(kind="android_keystore"):
    return {
        "validationId": "val-1", "tenantId": "tenant-1", "assetId": "asset-1",
        "versionId": "version-1", "kind": kind, "stage": "validate",
    }


class AndroidMaterialTests(unittest.TestCase):
    def request(self, path, alias="release", password=fixtures.PASSWORD, key_password=None):
        return {
            "contract": CONTRACT_VERSION,
            "evaluatedAt": WHEN,
            "platform": "android",
            "scope": scope(),
            "material": {
                "path": str(path),
                "storePassword": password,
                "keyPassword": key_password or password,
                "alias": alias,
            },
        }

    def test_pkcs12_rsa_and_ec_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = root / "keys.p12"
            rsa_cert = fixtures.certificate(fixtures.rsa_key(), "RSA", team=None)
            rsa = fixtures.rsa_key()
            ec = fixtures.ec_key()
            fixtures.keystore(store, "release", rsa, fixtures.certificate(rsa, "RSA Release"), "PKCS12")
            fixtures.add_alias(store, "upload", ec, fixtures.certificate(ec, "EC Upload"))
            del rsa_cert
            selected = validate_document(self.request(store, alias="release"))
            self.assertEqual(selected["status"], "invalid")
            self.assertIn("macos_capability_unavailable", selected["reasonCodes"])
            self.assertEqual(selected["scope"]["validationId"], "val-1")
            self.assertEqual(selected["contract"], CONTRACT_VERSION)
            release = next(item for item in selected["aliases"] if item["alias"] == "release")
            self.assertEqual(release["algorithm"], "RSA")
            self.assertTrue(release["signingCapable"])
            self.assertEqual(release["purpose"], "signing")
            self.assertIn("certificateSha256", release)
            self.assertEqual(selected["storeType"], "PKCS12")
            self.assertEqual(selected["expiresAt"], release["expiresAt"])
            self.assertFalse(selected["evidence"]["trustedByPlatform"])
            self.assertFalse(selected["evidence"]["chainTrusted"])
            self.assertTrue(selected["evidence"]["privateKeyProven"])
            self.assertFalse(selected["evidence"]["playAppSigningIdentity"])
            upload = validate_document(self.request(store, alias="upload"))
            upload_alias = next(item for item in upload["aliases"] if item["alias"] == "upload")
            self.assertEqual(upload_alias["algorithm"], "EC")
            self.assertEqual(upload_alias["purpose"], "signing")

    def test_jks_wrong_password_expired_and_not_yet_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = fixtures.rsa_key()
            store = root / "app.jks"
            fixtures.keystore(store, "release", key, fixtures.certificate(key, "JKS"), "JKS")
            parsed = validate_document(self.request(store))
            self.assertEqual(parsed["storeType"], "JKS")
            self.assertIn("macos_capability_unavailable", parsed["reasonCodes"])
            self.assertTrue(parsed["aliases"][0]["signingCapable"])
            with self.assertRaises(ValidationFailure) as wrong:
                validate_document(self.request(store, password="incorrect-password"))
            self.assertEqual(wrong.exception.code, "wrong_password")
            early = root / "early.p12"
            late = root / "late.p12"
            utc = datetime.timezone.utc
            fixtures.keystore(early, "release", key, fixtures.certificate(
                key, "Early", not_before=datetime.datetime(2026, 8, 1, tzinfo=utc)), "PKCS12")
            fixtures.keystore(late, "release", key, fixtures.certificate(
                key, "Late",
                not_before=datetime.datetime(2025, 1, 1, tzinfo=utc),
                not_after=datetime.datetime(2026, 2, 1, tzinfo=utc)), "PKCS12")
            self.assertIn("certificate_not_yet_valid", validate_document(self.request(early))["reasonCodes"])
            self.assertIn("certificate_expired", validate_document(self.request(late))["reasonCodes"])

    def test_ambiguous_alias_and_jks_key_password(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = root / "multi.p12"
            one, two = fixtures.rsa_key(), fixtures.rsa_key()
            fixtures.keystore(store, "one", one, fixtures.certificate(one, "One"), "PKCS12")
            fixtures.add_alias(store, "two", two, fixtures.certificate(two, "Two"))
            missing = dict(self.request(store))
            missing["material"] = dict(missing["material"])
            missing["material"].pop("alias")
            with self.assertRaises(ValidationFailure) as ambiguous:
                validate_document(missing)
            self.assertEqual(ambiguous.exception.code, "ambiguous_alias")
            jks = root / "separate.jks"
            key = fixtures.rsa_key()
            fixtures.keystore(
                jks, "release", key, fixtures.certificate(key, "Separate"), "JKS",
                store_password=fixtures.PASSWORD, key_password="different-key-password")
            parsed = validate_document(self.request(jks, key_password="different-key-password"))
            self.assertEqual(parsed["storeType"], "JKS")
            self.assertTrue(parsed["aliases"][0]["signingCapable"])
            with self.assertRaises(ValidationFailure) as wrong_key:
                validate_document(self.request(jks, key_password="not-the-key-password"))
            self.assertEqual(wrong_key.exception.code, "wrong_key_password")

    def test_unknown_format_is_not_a_password_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unknown.bin"
            path.write_bytes(b"not-a-keystore")
            with self.assertRaises(ValidationFailure) as unknown:
                validate_document(self.request(path))
            self.assertEqual(unknown.exception.code, "unknown_format")
            encoded = json.dumps(self.request(path))
            self.assertNotIn("BEGIN PRIVATE", encoded)

    def test_pkcs12_chain_length_is_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            issuer_key = fixtures.rsa_key()
            leaf_key = fixtures.rsa_key()
            issuer = fixtures.certificate(issuer_key, "Fixture CA")
            leaf = fixtures.certificate(
                leaf_key, "Leaf", issuer_key=issuer_key, issuer_name=issuer.subject)
            store = root / "chain.p12"
            fixtures.keystore(store, "release", leaf_key, leaf, "PKCS12", chain=[issuer])
            result = validate_document(self.request(store))
            selected = next(item for item in result["aliases"] if item["alias"] == "release")
            self.assertEqual(selected["chainLength"], 2)
            self.assertEqual(len(selected["chainSha256"]), 2)
            self.assertEqual(len(set(selected["chainSha256"])), 2)


if __name__ == "__main__":
    unittest.main()
