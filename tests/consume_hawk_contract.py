#!/usr/bin/env python3
"""Cross-repo fixture consumer. OS signatures are exercised in scoped signer tests."""
import datetime
import json
from pathlib import Path
import plistlib
import sys
import tempfile
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import sign_android
import sign_ios
import spec_identity


def consume(value):
    spec, metadata = value['spec'], value['metadata']
    spec_identity.validate(spec['config'])
    if spec_identity.digest(spec['config']) != spec['specHash']:
        raise ValueError('cross-repository canonical hash mismatch')
    if metadata['platform'] == 'android':
        output = "package: name='%s' versionCode='%s' versionName='%s'" % (
            metadata['applicationIdentifier'], metadata['buildNumber'], metadata['versionName'])
        with patch('sign_android.run', return_value=output):
            sign_android.verify_identity(Path('fixture.apk'), 'apk', metadata)
            try:
                sign_android.verify_identity(Path('fixture.apk'), 'apk', dict(metadata, buildNumber=0))
            except ValueError:
                pass
            else:
                raise ValueError('version override accepted')
        return
    with tempfile.TemporaryDirectory() as directory:
        app = Path(directory) / 'Runner.app'
        entries = [(app, metadata)] + [(app / 'PlugIns' / (str(i) + '.appex'), dict(metadata, **c))
            for i, c in enumerate(metadata.get('components', []))]
        for product, component in entries:
            product.mkdir(parents=True)
            (product / 'Runner').write_bytes(b'fixture executable, not a real device build')
            (product / 'Info.plist').write_bytes(plistlib.dumps({
                'CFBundleIdentifier': component['applicationIdentifier'],
                'CFBundleDisplayName': component['appDisplayName'],
                'CFBundleVersion': str(component['buildNumber']),
                'CFBundleShortVersionString': component['versionName'],
                'CFBundleExecutable': 'Runner', 'CFBundleSupportedPlatforms': ['iPhoneOS']}))
            method = metadata['distributionMethod']
            profile = {'UUID': component['profileUuid'], 'TeamIdentifier': [metadata['teamId']],
                'DeveloperCertificates': [b'fixture'], 'ExpirationDate': datetime.datetime(2099, 1, 1),
                'Entitlements': {'application-identifier': metadata['teamId'] + '.' + component['applicationIdentifier'],
                    'com.apple.developer.team-identifier': metadata['teamId'], 'get-task-allow': method == 'development'}}
            if method in ('development', 'ad-hoc'):
                profile['ProvisionedDevices'] = ['fixture device']
            if method == 'enterprise':
                profile['ProvisionsAllDevices'] = True
            sign_ios.validate_profile(profile, component, b'fixture')
        if len(sign_ios.component_apps(app, metadata)) != len(entries):
            raise ValueError('component coverage mismatch')


if __name__ == '__main__':
    consume(json.load(sys.stdin))
    print('Hawk Spec/hash and native signing consumer contract passed (fixture)')
