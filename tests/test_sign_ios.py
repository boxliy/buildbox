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
            child = app / 'PlugIns' / 'Share.appex'
            child.mkdir(parents=True)
            (child / 'Runner').write_bytes(b'fixture')
            (child / 'Info.plist').write_bytes(plistlib.dumps(dict(info, CFBundleIdentifier='com.example.app.share')))
            with self.assertRaises(ValueError):
                sign_ios.component_apps(app, metadata)
            configured = dict(metadata, components=[{'applicationIdentifier': 'com.example.app.share', 'profileVersionId': '12'}])
            self.assertEqual([p for p, _ in sign_ios.component_apps(app, configured)], [child, app])
            (child / 'Info.plist').write_bytes(plistlib.dumps(dict(info, CFBundleIdentifier='com.other.app')))
            with self.assertRaises(ValueError):
                sign_ios.component_apps(app, configured)


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

class DistributionMatrixTests(unittest.TestCase):
    def test_all_four_distributions_derive_from_profile(self):
        base = {'TeamIdentifier': ['TEAM123456'], 'DeveloperCertificates': [b'fixture'],
                'ExpirationDate': datetime.datetime(2099, 1, 1), 'Entitlements': {
                    'application-identifier': 'TEAM123456.com.example.app',
                    'com.apple.developer.team-identifier': 'TEAM123456', 'get-task-allow': False,
                    'unused-profile-privilege': True}}
        for method in ('development', 'ad-hoc', 'enterprise', 'app-store'):
            profile = dict(base, Entitlements=dict(base['Entitlements'], **{'get-task-allow': method == 'development'}))
            if method in ('development', 'ad-hoc'):
                profile['ProvisionedDevices'] = ['device']
            if method == 'enterprise':
                profile['ProvisionsAllDevices'] = True
            metadata = {'teamId': 'TEAM123456', 'applicationIdentifier': 'com.example.app', 'distributionMethod': method}
            self.assertEqual(sign_ios.distribution_method(profile), method)
            self.assertNotIn('unused-profile-privilege', sign_ios.validate_profile(profile, metadata, b'fixture'))
            for wrong in {'development', 'ad-hoc', 'enterprise', 'app-store'} - {method}:
                with self.assertRaises(ValueError):
                    sign_ios.validate_profile(profile, dict(metadata, distributionMethod=wrong), b'fixture')

class SignedComponentInspectionTests(unittest.TestCase):
    def test_actual_certificate_profile_entitlements_and_identity_must_match(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / 'Runner.app'
            app.mkdir()
            metadata = {'applicationIdentifier': 'com.example.app', 'versionName': '1.2.3', 'buildNumber': 7}
            info = {'CFBundleIdentifier': 'com.example.app', 'CFBundleShortVersionString': '1.2.3', 'CFBundleVersion': '7'}
            (app / 'Info.plist').write_bytes(plistlib.dumps(info))
            (app / 'embedded.mobileprovision').write_bytes(b'profile')
            certificate = b'fixture certificate'
            entitlements = {'application-identifier': 'TEAM123456.com.example.app'}
            actual = dict(entitlements)

            def tools(args):
                if '--extract-certificates' in args:
                    Path(str(root / 'verified-cert-') + '0').write_bytes(certificate)
                if '--entitlements' in args:
                    return plistlib.dumps(actual).decode()
                return ''

            with patch('sign_ios.run', side_effect=tools):
                sign_ios.verify_signed(app, metadata, certificate, entitlements, b'profile', root)
                actual['ungranted-profile-privilege'] = True
                with self.assertRaises(ValueError):
                    sign_ios.verify_signed(app, metadata, certificate, entitlements, b'profile', root)
                actual.clear()
                actual.update(entitlements)
                with self.assertRaises(ValueError):
                    sign_ios.verify_signed(app, metadata, b'other certificate', entitlements, b'profile', root)
                with self.assertRaises(ValueError):
                    sign_ios.verify_signed(app, metadata, certificate, entitlements, b'other profile', root)
                (app / 'Info.plist').write_bytes(plistlib.dumps(dict(info, CFBundleVersion='8')))
                with self.assertRaises(ValueError):
                    sign_ios.verify_signed(app, metadata, certificate, entitlements, b'profile', root)

class NestedSigningOrderTests(unittest.TestCase):
    def test_signs_and_verifies_frameworks_children_and_host_without_source_scripts(self):
        import base64
        import json
        import os
        import zipfile
        calls, signed_entitlements, proofs = [], {}, []
        certificate = b'fixture certificate bytes'
        metadata = {'platform': 'ios', 'targets': ['ipa'], 'runId': '123', 'specHash': 'sha256:fixture',
                    'versionId': '12', 'certificateSha256': __import__('hashlib').sha256(certificate).hexdigest(),
                    'applicationIdentifier': 'com.example.app', 'versionName': '1.2.3', 'buildNumber': 7,
                    'appDisplayName': 'Fixture App',
                    'teamId': 'TEAM123456', 'distributionMethod': 'enterprise', 'profileUuid': 'HOST',
                    'components': [{'applicationIdentifier': 'com.example.app.share', 'profileVersionId': '14', 'profileUuid': 'CHILD'}]}
        def profile(bundle, uuid):
            return plistlib.dumps({'UUID': uuid, 'TeamIdentifier': ['TEAM123456'],
                'DeveloperCertificates': [certificate], 'ExpirationDate': datetime.datetime(2099, 1, 1),
                'ProvisionsAllDevices': True, 'Entitlements': {'application-identifier': 'TEAM123456.' + bundle,
                'com.apple.developer.team-identifier': 'TEAM123456', 'get-task-allow': False}})
        material = {'containerBase64': base64.b64encode(b'fixture p12').decode(), 'password': 'fixture',
                    'provisioningProfileBase64': base64.b64encode(profile('com.example.app', 'HOST')).decode(),
                    'components': [{'applicationIdentifier': 'com.example.app.share',
                        'provisioningProfileBase64': base64.b64encode(profile('com.example.app.share', 'CHILD')).decode()}]}
        def tools(args, env=None):
            calls.append(args)
            if args[:3] == ['security', 'cms', '-D']:
                return Path(args[-1]).read_text()
            if args[:2] == ['openssl', 'pkcs12']:
                return '-----BEGIN CERTIFICATE-----\n' + base64.b64encode(certificate).decode() + '\n-----END CERTIFICATE-----'
            if args[0] == 'codesign':
                if '--entitlements' in args:
                    if '--display' in args:
                        return plistlib.dumps(signed_entitlements[args[-1]]).decode()
                    signed_entitlements[args[-1]] = plistlib.loads(Path(args[args.index('--entitlements') + 1]).read_bytes())
                if '--extract-certificates' in args:
                    Path(args[args.index('--extract-certificates') + 1] + '0').write_bytes(certificate)
            return ''
        def platform(path, body=None):
            if body is None:
                return {'metadata': metadata, 'material': material}
            proofs.append(body)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'unsigned').mkdir()
            with zipfile.ZipFile(root / 'unsigned/swan-release.ipa', 'w') as archive:
                for path, bundle in [('Runner.app', 'com.example.app'), ('Runner.app/PlugIns/Share.appex', 'com.example.app.share')]:
                    info = {'CFBundleIdentifier': bundle, 'CFBundleDisplayName': 'Fixture App',
                            'CFBundleShortVersionString': '1.2.3', 'CFBundleVersion': '7',
                            'CFBundleExecutable': 'Runner', 'CFBundleSupportedPlatforms': ['iPhoneOS']}
                    archive.writestr('Payload/' + path + '/Info.plist', plistlib.dumps(info))
                    archive.writestr('Payload/' + path + '/Runner', b'fixture executable')
                archive.writestr('Payload/Runner.app/PlugIns/Share.appex/Frameworks/Nested.framework/Nested', b'fixture framework')
                archive.writestr('Payload/Runner.app/Frameworks/libfixture.dylib', b'fixture dylib')
            with patch.dict(os.environ, BUILDBOX_STATE_DIR=str(root), BUILDBOX_RUN_ID='123'), \
                    patch('sign_ios.os.uname') as uname, patch('sign_ios.run', side_effect=tools), \
                    patch('sign_ios.request', side_effect=platform):
                uname.return_value.sysname = 'Darwin'
                sign_ios.main()
            signatures = [c[-1] for c in calls if c[0] == 'codesign' and '--sign' in c]
            self.assertTrue(signatures[0].endswith('Nested.framework'))
            self.assertTrue(signatures[-2].endswith('Share.appex'))
            self.assertTrue(signatures[-1].endswith('Runner.app'))
            self.assertEqual(len([c for c in calls if c[:3] == ['codesign', '--verify', '--strict']]), 4)
            self.assertEqual(len(proofs[0]['components']), 2)
            self.assertTrue(any(c[:2] == ['security', 'delete-keychain'] for c in calls))
            self.assertFalse(any(c[0] in ('xcodebuild', 'flutter', 'sh', 'bash') for c in calls))
            self.assertTrue((root / 'artifacts/swan-release.ipa').is_file())
            with zipfile.ZipFile(root / 'artifacts/swan-release.ipa') as archive:
                self.assertIn('Payload/Runner.app/Info.plist', archive.namelist())
                self.assertIn('Payload/Runner.app/PlugIns/Share.appex/Info.plist', archive.namelist())
