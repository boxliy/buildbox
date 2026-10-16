import datetime
import importlib.util
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import sign_ios


class IosSigningPolicyTests(unittest.TestCase):
    def test_profile_binds_team_identity_certificate_expiry_and_distribution(self):
        metadata = {'teamId': 'TEAM123456', 'applicationIdentifier': 'com.example.app', 'distributionMethod': 'ad-hoc'}
        profile = {'TeamIdentifier': ['TEAM123456'], 'DeveloperCertificates': [b'fixture'],
                   'ExpirationDate': datetime.datetime.now() + datetime.timedelta(days=1),
                   'ProvisionedDevices': ['fixture-device'], 'Entitlements': {
                       'application-identifier': 'TEAM123456.com.example.app',
                       'com.apple.developer.team-identifier': 'TEAM123456', 'get-task-allow': False}}
        self.assertEqual(sign_ios.validate_profile(profile, metadata, b'fixture'), profile['Entitlements'])
        for changes in ({'TeamIdentifier': ['OTHER']}, {'DeveloperCertificates': [b'other']},
                        {'ExpirationDate': datetime.datetime.now() - datetime.timedelta(seconds=1)},
                        {'ProvisionedDevices': []}, {'Entitlements': dict(profile['Entitlements'], **{'get-task-allow': True})}):
            with self.assertRaises(ValueError):
                sign_ios.validate_profile(dict(profile, **changes), metadata, b'fixture')
        with self.assertRaises(ValueError):
            sign_ios.validate_profile(profile, dict(metadata, distributionMethod='app-store'), b'fixture')

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
