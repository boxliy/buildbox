import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

MODULE = Path(__file__).resolve().parents[1] / "scripts/sign_android.py"
spec = importlib.util.spec_from_file_location("sign_android", MODULE)
signer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signer)


class SigningTests(unittest.TestCase):
    def test_archive_rejects_traversal_duplicate_symlink_and_apk_signing_block(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "app.apk"
            for name in ("../outside", "/absolute", "a\\b", "META-INF/KEY.RSA"):
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr(name, b"x")
                with self.assertRaises(ValueError):
                    signer.checked_zip(path)
            with zipfile.ZipFile(path, "w") as archive:
                info = zipfile.ZipInfo("symlink")
                info.external_attr = 0o120777 << 16
                archive.writestr(info, "outside")
            with self.assertRaises(ValueError):
                signer.checked_zip(path)
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"APK Sig Block 42")
            with self.assertRaises(ValueError):
                signer.checked_zip(path)

    def test_real_jar_sign_verify_certificate_mismatch_and_tampering(self):
        for algorithm, size in (("RSA", "2048"), ("EC", "256")):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                key = root / "fixture.p12"
                env = dict(os.environ, FIXTURE_PASSWORD="isolated-test-only")
                subprocess.run(["keytool", "-genkeypair", "-alias", "fixture", "-keyalg", algorithm,
                                "-keysize", size, "-dname", "CN=Isolated Test", "-validity", "2",
                                "-storetype", "PKCS12", "-keystore", str(key),
                                "-storepass:env", "FIXTURE_PASSWORD"], env=env, check=True, capture_output=True)
                certificate = subprocess.run(["keytool", "-J-Duser.language=en", "-list", "-v", "-keystore", str(key),
                                "-storepass:env", "FIXTURE_PASSWORD"], env=env, check=True, capture_output=True, text=True).stdout
                fingerprint = re.search(r"SHA256:\s*([0-9A-F:]+)", certificate).group(1).replace(":", "").lower()
                unsigned, signed = root / "unsigned.aab", root / "signed.aab"
                with zipfile.ZipFile(unsigned, "w") as archive:
                    archive.writestr("base/manifest/AndroidManifest.xml", b"isolated-signature-test")
                material = {"containerBase64": base64.b64encode(key.read_bytes()).decode(),
                            "password": env["FIXTURE_PASSWORD"], "alias": "fixture"}
                metadata = {"certificateSha256": fingerprint}
                # This test exercises real JAR crypto. Bundle protobuf identity has separate tests.
                with patch.object(signer, "verify_identity"):
                    signer.sign_one(unsigned, signed, "aab", metadata, material, root)
                    with self.assertRaises(ValueError):
                        signer.sign_one(unsigned, root / "wrong.aab", "aab",
                                        {"certificateSha256": "0" * 64}, material, root)
                with zipfile.ZipFile(signed, "a") as archive:
                    archive.writestr("base/manifest/AndroidManifest.xml", b"tampered")
                with self.assertRaises(ValueError):
                    signer.run(["jarsigner", "-verify", str(signed)])

    def test_apk_identity_must_match_all_frozen_fields(self):
        metadata = {"applicationIdentifier": "com.example.app", "buildNumber": 12, "versionName": "1.2.3"}
        with patch.object(signer, "run", return_value="package: name='com.example.app' versionCode='12' versionName='1.2.3'"):
            signer.verify_identity(Path("fixture.apk"), "apk", metadata)
        for value in ("package: name='com.other.app' versionCode='12' versionName='1.2.3'",
                      "package: name='com.example.app' versionCode='11' versionName='1.2.3'"):
            with patch.object(signer, "run", return_value=value), self.assertRaises(ValueError):
                signer.verify_identity(Path("fixture.apk"), "apk", metadata)


if __name__ == "__main__":
    unittest.main()

class KeyAlgorithmPolicyTests(unittest.TestCase):
    def test_unsupported_key_algorithm_is_rejected_before_signing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'unsigned.aab'
            with zipfile.ZipFile(source, 'w') as archive:
                archive.writestr('base/manifest/AndroidManifest.xml', b'fixture')
            material = {'containerBase64': base64.b64encode(b'fixture').decode(), 'password': 'fixture', 'alias': 'fixture'}
            def command(args, env=None):
                if '-text' in args:
                    return 'Public Key Algorithm: dsaEncryption'
                return ''
            with patch.object(signer, 'verify_identity'), patch.object(signer, 'run', side_effect=command) as commands:
                with self.assertRaisesRegex(ValueError, 'unsupported signing key algorithm'):
                    signer.sign_one(source, root / 'signed.aab', 'aab', {'certificateSha256': 'a' * 64}, material, root)
                self.assertFalse(any(call.args[0][0] == 'jarsigner' for call in commands.call_args_list))

    def test_aab_identity_checks_package_and_both_versions(self):
        with tempfile.TemporaryDirectory() as directory:
            jar = Path(directory) / 'bundletool.jar'
            jar.write_bytes(b'isolated-tool')
            import hashlib
            metadata = {'applicationIdentifier': 'com.example.app', 'buildNumber': 12, 'versionName': '1.2.3'}
            with patch.dict(os.environ, BUILDBOX_BUNDLETOOL_JAR=str(jar), BUILDBOX_BUNDLETOOL_SHA256=hashlib.sha256(jar.read_bytes()).hexdigest()):
                for package, number, name in [('com.example.app','12','1.2.3'), ('com.other.app','12','1.2.3'), ('com.example.app','11','1.2.3'), ('com.example.app','12','1.2.2')]:
                    xml = f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{package}" android:versionCode="{number}" android:versionName="{name}"/>'
                    with patch.object(signer, 'run', return_value=xml):
                        if (package,number,name) == ('com.example.app','12','1.2.3'):
                            signer.verify_identity(Path('fixture.aab'), 'aab', metadata)
                        else:
                            with self.assertRaisesRegex(ValueError, 'AAB identity or version mismatch'):
                                signer.verify_identity(Path('fixture.aab'), 'aab', metadata)
