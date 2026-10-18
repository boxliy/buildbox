"""Exercise credential-free compilation and nested branding with fake native tools."""
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import sign_ios

ROOT = Path(__file__).resolve().parents[1]


class IosCompileTests(unittest.TestCase):
    def test_unsigned_device_build_and_nested_names_for_every_distribution(self):
        for method in ('development', 'ad-hoc', 'enterprise', 'app-store'):
            with self.subTest(method=method), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, state, tools = root / 'source', root / 'state', root / 'bin'
                swan = source / 'waterfowl/apps/swan'
                project = swan / 'ios/Runner.xcodeproj'
                project.mkdir(parents=True)
                (project / 'project.pbxproj').write_text('{}')
                adapter = source / 'waterfowl/tools/build_spec_adapter.py'
                adapter.parent.mkdir()
                adapter.write_text('')
                (source / 'waterfowl/pubspec.lock').write_text('fixture')
                state.mkdir()
                tools.mkdir()
                spec = {'config': {'platform': 'ios', 'targets': ['ipa'],
                    'applicationIdentifier': 'com.example.app', 'appDisplayName': 'Frozen App',
                    'dartDefines': {}, 'appProfile': {'deviceCapabilities': []},
                    'frozenInputs': {'flutterVersion': '3.47.4', 'xcodeBuild': 'FIXTURE',
                        'versionName': '1.2.3', 'buildNumber': 7,
                        'iosComponentTargets': {'share': 'Share', 'watch': 'Watch'}},
                    'signing': {'teamId': 'TEAM123456', 'distributionMethod': method,
                        'components': [{'applicationIdentifier': 'com.example.app.share'},
                                       {'applicationIdentifier': 'com.example.app.watch'}]}}}
                (state / 'spec.json').write_text(json.dumps(spec))
                # Real build-ios/configure_ios run; only external tools are substituted.
                native = tools / 'native'
                native.write_text('''#!/usr/bin/env python3
import json, os, plistlib, sys
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
if name == 'uname':
    print('Darwin')
elif name == 'xcodebuild':
    assert args == ['-version'], args
    print('Build version FIXTURE')
elif name == 'plutil':
    objects = {}
    for target, kind in [('Runner', 'application'), ('Share', 'app-extension'), ('Watch', 'application')]:
        objects[target] = dict(isa='PBXNativeTarget', name=target,
            productType='com.apple.product-type.' + kind, buildConfigurationList=target + '-list')
        objects[target + '-list'] = dict(buildConfigurations=[target + '-release'])
        objects[target + '-release'] = dict(buildSettings={})
    print(json.dumps(dict(objects=objects)))
elif name == 'flutter':
    if args == ['--version', '--machine']:
        print(json.dumps(dict(frameworkVersion='3.47.4')))
    elif args == ['pub', 'get', '--enforce-lockfile']:
        pass
    else:
        assert args[:2] == ['build', 'ios'], args
        assert '--no-codesign' in args and '--release' in args, args
        assert '--build-name=1.2.3' in args and '--build-number=7' in args, args
        assert not any('export' in arg for arg in args), args
        assert 'HAWK_STAGE_TOKEN' not in os.environ
        assert 'ACTIONS_ID_TOKEN_REQUEST_TOKEN' not in os.environ
        Path(os.environ['COMPILE_CALL']).write_text(json.dumps(args))
        for path, bundle in [('Runner.app', 'com.example.app'),
            ('Runner.app/PlugIns/Share.appex', 'com.example.app.share'),
            ('Runner.app/Watch/Watch.app', 'com.example.app.watch')]:
            app = Path('build/ios/iphoneos') / path
            app.mkdir(parents=True)
            (app / 'Runner').write_bytes(b'fixture executable')
            (app / 'Info.plist').write_bytes(plistlib.dumps(dict(CFBundleIdentifier=bundle,
                CFBundleDisplayName='Source Name', CFBundleShortVersionString='1.2.3',
                CFBundleVersion='7', CFBundleExecutable='Runner', CFBundleSupportedPlatforms=['iPhoneOS'])))
elif name != 'dart':
    raise AssertionError(name)
''')
                native.chmod(0o755)
                for name in ('uname', 'xcodebuild', 'plutil', 'flutter', 'dart'):
                    (tools / name).symlink_to(native)
                env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH'],
                    BUILDBOX_STATE_DIR=str(state), BUILDBOX_SOURCE_ROOT=str(source),
                    COMPILE_CALL=str(root / 'compile.json'))
                env.pop('HAWK_STAGE_TOKEN', None)
                env.pop('ACTIONS_ID_TOKEN_REQUEST_TOKEN', None)
                result = subprocess.run(['bash', str(ROOT / 'scripts/build-ios')], env=env,
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue((root / 'compile.json').is_file())
                with zipfile.ZipFile(state / 'unsigned/swan-release.ipa') as archive:
                    archive.extractall(root / 'inspect')
                metadata = dict(spec['config'], versionName='1.2.3', buildNumber=7,
                    components=spec['config']['signing']['components'])
                apps = sign_ios.component_apps(root / 'inspect/Payload/Runner.app', metadata)
                self.assertEqual(len(apps), 3)
                for app, component in apps:
                    sign_ios.validate_app(app, component)
                    info = app / 'Info.plist'
                    body = plistlib.loads(info.read_bytes())
                    self.assertEqual(body['CFBundleDisplayName'], 'Frozen App')
                    info.write_bytes(plistlib.dumps(dict(body, CFBundleDisplayName='Source Name')))
                    with self.assertRaises(ValueError):
                        sign_ios.validate_app(app, component)
                    info.write_bytes(plistlib.dumps(body))
