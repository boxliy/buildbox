import datetime
import importlib.util
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import sign_ios


class IosSigningPolicyTests(unittest.TestCase):
    @patch("sign_ios.datetime")
    def test_profile_binds_team_identity_certificate_expiry_and_distribution(self, clock):
        now = datetime.datetime(2030, 1, 2, 12, tzinfo=datetime.timezone.utc)
        clock.datetime.now.return_value = now
        clock.datetime.min = datetime.datetime.min
        clock.timezone = datetime.timezone
        metadata = {'teamId': 'TEAM123456', 'applicationIdentifier': 'com.example.app', 'distributionMethod': 'ad-hoc'}
        profile = {'TeamIdentifier': ['TEAM123456'], 'DeveloperCertificates': [b'fixture'],
                   'ExpirationDate': now.replace(tzinfo=None) + datetime.timedelta(days=1),
                   'ProvisionedDevices': ['fixture-device'], 'Entitlements': {
                       'application-identifier': 'TEAM123456.com.example.app',
                       'com.apple.developer.team-identifier': 'TEAM123456', 'get-task-allow': False}}
        self.assertEqual(sign_ios.validate_profile(profile, metadata, b'fixture'), profile['Entitlements'])
        for changes in ({'TeamIdentifier': ['OTHER']}, {'DeveloperCertificates': [b'other']},
                        {'ExpirationDate': now.replace(tzinfo=None) - datetime.timedelta(seconds=1)},
                        {'ProvisionedDevices': []}, {'ProvisionedDevices': ['']}, {'ProvisionsAllDevices': True}, {'Entitlements': dict(profile['Entitlements'], **{'get-task-allow': True})}):
            with self.assertRaises(ValueError):
                sign_ios.validate_profile(dict(profile, **changes), metadata, b'fixture')
        for method in ('app-store', 'enterprise', 'unknown'):
            with self.assertRaises(ValueError):
                sign_ios.validate_profile(profile, dict(metadata, distributionMethod=method), b'fixture')
        development = dict(profile, Entitlements=dict(profile['Entitlements'], **{'get-task-allow': True}))
        sign_ios.validate_profile(development, dict(metadata, distributionMethod='development'), b'fixture')
        broad = dict(profile, Entitlements=dict(profile['Entitlements'], **{'aps-environment': 'production'}))
        self.assertNotIn('aps-environment', sign_ios.validate_profile(broad, metadata, b'fixture'))
        push = dict(metadata, deviceCapabilities=[{'key': 'notifications.push'}])
        self.assertEqual(sign_ios.validate_profile(broad, push, b'fixture')['aps-environment'], 'production')
        with self.assertRaises(ValueError):
            sign_ios.validate_profile(profile, push, b'fixture')


    def test_unsigned_app_requires_device_identity_and_no_extensions(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory)
            metadata = {'applicationIdentifier': 'com.example.app', 'versionName': '1.2.3', 'buildNumber': 7}
            info = {'CFBundleIdentifier': 'com.example.app', 'CFBundleShortVersionString': '1.2.3',
                    'CFBundleVersion': '7', 'CFBundleExecutable': 'Runner', 'CFBundleSupportedPlatforms': ['iPhoneOS']}
            (app / 'Runner').write_bytes(b'fixture')
            (app / 'Info.plist').write_bytes(plistlib.dumps(info))
            sign_ios.validate_app(app, metadata)
            for changes in ({'CFBundleVersion': '6'}, {'CFBundleSupportedPlatforms': ['iPhoneSimulator']},
                            {'CFBundleExecutable': '../Runner'}, {'CFBundleIdentifier': 'com.other.app'}):
                (app / 'Info.plist').write_bytes(plistlib.dumps(dict(info, **changes)))
                with self.assertRaises(ValueError):
                    sign_ios.validate_app(app, metadata)
            (app / 'Info.plist').write_bytes(plistlib.dumps(info))
            (app / 'PlugIns').mkdir()
            with self.assertRaises(ValueError):
                sign_ios.validate_app(app, metadata)


if __name__ == '__main__':
    unittest.main()

class IosCapabilityContractTests(unittest.TestCase):
    def test_plist_and_signer_consume_hawk_serialized_capabilities(self):
        import json
        import os
        import subprocess
        # The cross-repository Rust test supplies the real serialized enum values.
        keys = json.loads(os.environ.get('HAWK_CAPABILITY_KEYS', '["photos.read", "photos.write"]'))
        source = (Path(__file__).resolve().parents[1] / 'scripts/build-ios').read_text()
        script = source.split("<<'PYNAME'\n", 1)[1].split('\nPYNAME', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            info = root / 'build/ios/iphoneos/Runner.app/Info.plist'
            info.parent.mkdir(parents=True)
            spec = root / 'spec.json'
            for capabilities, accepted in [(keys, True), ([], True), (['storage.photos.read'], False), (['unknown'], False)]:
                info.write_bytes(plistlib.dumps({}))
                spec.write_text(json.dumps({'config': {'appProfile': {'deviceCapabilities': [{'key': key} for key in capabilities]}}}))
                result = subprocess.run([sys.executable, '-c', script, 'Fixture App', str(spec)], cwd=root, capture_output=True)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                profile = {'TeamIdentifier': ['TEAM123456'], 'DeveloperCertificates': [b'fixture'],
                    'ExpirationDate': datetime.datetime(2099, 1, 1), 'ProvisionedDevices': ['fixture-device'],
                    'Entitlements': {'application-identifier': 'TEAM123456.com.example.app',
                        'com.apple.developer.team-identifier': 'TEAM123456', 'get-task-allow': False}}
                metadata = {'teamId': 'TEAM123456', 'applicationIdentifier': 'com.example.app',
                    'distributionMethod': 'ad-hoc', 'deviceCapabilities': [{'key': key} for key in capabilities]}
                if accepted:
                    sign_ios.validate_profile(profile, metadata, b'fixture')
                    plist = plistlib.loads(info.read_bytes())
                    self.assertEqual('NSPhotoLibraryUsageDescription' in plist, 'photos.read' in capabilities)
                    self.assertEqual('NSPhotoLibraryAddUsageDescription' in plist, 'photos.write' in capabilities)
                else:
                    with self.assertRaises(ValueError):
                        sign_ios.validate_profile(profile, metadata, b'fixture')
