"""Source privacy defaults must never cross the frozen product boundary."""
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from ios_privacy import MANAGED_USAGE_KEYS, privacy_usage, project_privacy, validate_privacy


class FrozenPrivacyTests(unittest.TestCase):
    def test_source_defaults_and_unconfigured_locales_are_stripped(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory)
            source = {key: 'unconfirmed source purpose' for key in MANAGED_USAGE_KEYS}
            (app / 'Info.plist').write_bytes(plistlib.dumps(source))
            stale = app / 'fr.lproj/InfoPlist.strings'
            stale.parent.mkdir()
            stale.write_bytes(plistlib.dumps(dict(source, Other='preserved')))
            metadata = {'source': 'tenant', 'appDisplayName': 'Frozen', 'defaultLocale': 'en',
                        'localizations': [{'locale': 'zh-CN', 'displayName': '冻结'}],
                        'deviceCapabilities': [{'key': 'camera.capture', 'purposes': [
                            {'locale': 'en', 'description': 'Capture print images.'}]}]}
            project_privacy(app, metadata)
            info = plistlib.loads((app / 'Info.plist').read_bytes())
            self.assertEqual({key: info[key] for key in MANAGED_USAGE_KEYS if key in info},
                             {'NSCameraUsageDescription': 'Capture print images.'})
            self.assertEqual(plistlib.loads(stale.read_bytes()), {'Other': 'preserved'})
            localized = app / 'zh-CN.lproj/InfoPlist.strings'
            self.assertEqual(plistlib.loads(localized.read_bytes())['NSCameraUsageDescription'],
                             'Capture print images.')
            validate_privacy(app, metadata, info)
            for key in MANAGED_USAGE_KEYS - {'NSCameraUsageDescription'}:
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'undeclared'):
                    validate_privacy(app, metadata, dict(info, **{key: 'residue'}))
            original = localized.read_bytes()
            for strings in ({}, {'NSCameraUsageDescription': 'tampered'},
                            {'NSCameraUsageDescription': 'Capture print images.', 'NSPhotoLibraryUsageDescription': 'residue'}):
                localized.write_bytes(plistlib.dumps(strings))
                with self.assertRaises(ValueError):
                    validate_privacy(app, metadata, info)
            localized.write_bytes(original)
            stale.write_bytes(plistlib.dumps({'NSPhotoLibraryUsageDescription': 'residue'}))
            with self.assertRaisesRegex(ValueError, 'undeclared'):
                validate_privacy(app, metadata, info)
            stale.write_bytes(plistlib.dumps({}))
            # A stale locale cannot hide the absence of a required locale.
            localized.rename(app / 'removed.strings')
            with self.assertRaisesRegex(ValueError, 'missing localized'):
                validate_privacy(app, metadata, info)

    def test_camera_requires_frozen_purpose_and_gallery_only_needs_no_usage(self):
        with self.assertRaisesRegex(ValueError, 'missing frozen'):
            privacy_usage({'source': 'tenant', 'deviceCapabilities': [{'key': 'camera.capture'}]}, 'en')
        self.assertEqual(privacy_usage({'source': 'tenant', 'deviceCapabilities': []}, 'en'), {})

    def test_localized_purposes_and_background_location_fallback(self):
        metadata = {'source': 'tenant', 'defaultLocale': 'en', 'deviceCapabilities': [
            {'key': 'location.background', 'purposes': [{'locale': 'en', 'description': 'Track jobs.'}]},
            {'key': 'camera.capture', 'purposes': [{'locale': 'en', 'description': 'Capture.'},
                                                  {'locale': 'zh-CN', 'description': '拍照。'}]}]}
        self.assertEqual(privacy_usage(metadata, 'zh-CN'), {
            'NSCameraUsageDescription': '拍照。', 'NSLocationWhenInUseUsageDescription': 'Track jobs.',
            'NSLocationAlwaysAndWhenInUseUsageDescription': 'Track jobs.'})

    def test_signer_rejects_background_modes_for_host_and_empty_nested_component(self):
        import sign_ios
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / 'Runner.app'
            child = app / 'PlugIns/Share.appex'
            child.mkdir(parents=True)
            metadata = {'applicationIdentifier': 'com.example.app', 'versionName': '1.0',
                        'buildNumber': 1, 'deviceCapabilities': [{'key': 'background.execution'}],
                        'components': [{'applicationIdentifier': 'com.example.app.share', 'deviceCapabilities': []}]}
            for product, identifier in ((app, 'com.example.app'), (child, 'com.example.app.share')):
                body = {'CFBundleIdentifier': identifier, 'CFBundleShortVersionString': '1.0',
                        'CFBundleVersion': '1', 'CFBundleExecutable': 'Runner',
                        'CFBundleSupportedPlatforms': ['iPhoneOS']}
                if product == app:
                    body['UIBackgroundModes'] = ['fetch']
                (product / 'Info.plist').write_bytes(plistlib.dumps(body))
                (product / 'Runner').write_bytes(b'fixture')
            sign_ios.component_apps(app, metadata)
            for product, modes in ((app, ['location']), (app, ['fetch', 'location']),
                                   (child, ['fetch']), (child, [])):
                info = product / 'Info.plist'
                original = info.read_bytes()
                body = plistlib.loads(original)
                body['UIBackgroundModes'] = modes
                info.write_bytes(plistlib.dumps(body))
                with self.assertRaisesRegex(ValueError, 'background modes'):
                    sign_ios.component_apps(app, metadata)
                info.write_bytes(original)
