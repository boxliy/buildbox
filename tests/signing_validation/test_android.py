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
    def request(self, path, purpose="direct_distribution", store_type="PKCS12", alias="release", password=fixtures.PASSWORD, key_password=None):
        return {
            "contract": CONTRACT_VERSION,
            "evaluatedAt": WHEN,
            "platform": "android",
            "purpose": purpose,
            "storeType": store_type,
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
            self.assertEqual(selected["status"], "valid")
            self.assertEqual(selected["selectedAlias"], "release")
            self.assertEqual(selected["certificate"]["publicKeyAlgorithm"], "RSA")
            self.assertEqual(selected["aliasCount"], 2)
            self.assertTrue(selected["evidence"]["directDistributionReady"])
            self.assertFalse(selected["evidence"]["playAppSigningIdentity"])
            upload = validate_document(self.request(store, purpose="play_upload", alias="upload"))
            self.assertEqual(upload["certificate"]["publicKeyAlgorithm"], "EC")
            self.assertFalse(upload["evidence"]["directDistributionReady"])
            self.assertFalse(upload["evidence"]["playAppSigningIdentity"])

    def test_jks_wrong_password_expired_and_not_yet_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = fixtures.rsa_key()
            store = root / "app.jks"
            fixtures.keystore(store, "release", key, fixtures.certificate(key, "JKS"), "JKS")
            valid = validate_document(self.request(store, store_type="JKS"))
            self.assertEqual(valid["status"], "valid")
            with self.assertRaises(ValidationFailure) as wrong:
                validate_document(self.request(store, store_type="JKS", password="incorrect-password"))
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
            self.assertEqual(validate_document(self.request(early))["reasonCodes"], ["certificate_not_yet_valid"])
            self.assertEqual(validate_document(self.request(late))["reasonCodes"], ["certificate_expired"])

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
            valid = validate_document(self.request(
                jks, store_type="JKS", key_password="different-key-password"))
            self.assertEqual(valid["status"], "valid")
            with self.assertRaises(ValidationFailure) as wrong_key:
                validate_document(self.request(jks, store_type="JKS", key_password="not-the-key-password"))
            self.assertEqual(wrong_key.exception.code, "wrong_key_password")

    def test_unknown_format_and_secret_log(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unknown.bin"
            path.write_bytes(b"not-a-keystore")
            with self.assertRaises(ValidationFailure) as unknown:
                validate_document(self.request(path, store_type="BCFKS"))
            self.assertEqual(unknown.exception.code, "unsupported_input")
            encoded = json.dumps(self.request(path))
            self.assertNotIn("BEGIN PRIVATE", encoded)


if __name__ == "__main__":
    unittest.main()
