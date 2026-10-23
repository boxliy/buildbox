import hashlib
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import spec_identity


class SpecIdentityTests(unittest.TestCase):
    def test_hawk_fixed_v1_vector_and_prefix_exclusion(self):
        fixture = json.loads((Path(__file__).parent / 'fixtures/build_spec_v1_identity.json').read_text())
        self.assertEqual(spec_identity.digest(fixture['input']), fixture['sha256'])
        fixture['input']['artifactPrefix'] = 'different-attempt/'
        self.assertEqual(spec_identity.digest(fixture['input']), fixture['sha256'])
        fixture['input']['appId'] = '43'
        self.assertNotEqual(spec_identity.digest(fixture['input']), fixture['sha256'])

    def test_unknown_schema_and_ambiguous_json_fail(self):
        for source in ['{"x":1,"x":2}', '{"x":9007199254740992}', '{"x":1.0}', '{"x":NaN}']:
            with self.assertRaises(ValueError):
                spec_identity.load(source)
        for version in [None, 0, 3, True, '1']:
            with self.assertRaises(ValueError):
                spec_identity.digest({'schemaVersion': version})


if __name__ == '__main__':
    unittest.main()

class SpecSemanticTests(unittest.TestCase):
    def test_frozen_v1_channel_matches_revision_and_application_define(self):
        import copy
        value = json.loads((Path(__file__).parent / 'fixtures/build-spec-apk.json').read_text())['config']
        for channel in ('dev', 'canary', 'stable'):
            current = copy.deepcopy(value)
            current['releaseChannel'] = channel
            current.setdefault('releaseRevision', {})['channel'] = channel
            current.setdefault('dartDefines', {})['SWAN_RELEASE_CHANNEL'] = channel
            spec_identity.validate(current)
            self.assertNotEqual(spec_identity.digest(current), spec_identity.digest(value))
            for target in ('releaseRevision', 'dartDefines'):
                invalid = copy.deepcopy(current)
                invalid[target]['channel' if target == 'releaseRevision' else 'SWAN_RELEASE_CHANNEL'] = 'other'
                with self.assertRaisesRegex(ValueError, 'channel mismatch'):
                    spec_identity.validate(invalid)
                missing = copy.deepcopy(current)
                del missing[target]['channel' if target == 'releaseRevision' else 'SWAN_RELEASE_CHANNEL']
                with self.assertRaisesRegex(ValueError, 'channel mismatch'):
                    spec_identity.validate(missing)
                for malformed in (None, [], 'stable'):
                    missing = dict(current, **{target: malformed})
                    with self.assertRaisesRegex(ValueError, 'missing frozen release channel inputs'):
                        spec_identity.validate(missing)
                missing = copy.deepcopy(current)
                del missing[target]
                with self.assertRaisesRegex(ValueError, 'missing frozen release channel inputs'):
                    spec_identity.validate(missing)
        for channel in ('latest', '', None, 1, True):
            invalid = dict(value, releaseChannel=channel)
            with self.assertRaisesRegex(ValueError, 'invalid frozen release channel'):
                spec_identity.validate(invalid)

    def test_current_v1_rejects_unknown_fields_scope_versions_and_targets(self):
        import copy
        value = json.loads((Path(__file__).parent / 'fixtures/build-spec-apk.json').read_text())['config']
        spec_identity.validate(value)
        for key, changed in [('unexpected', True), ('targets', ['apk', 'ipa']), ('tenantId', 1)]:
            invalid = copy.deepcopy(value)
            invalid[key] = changed
            with self.assertRaises((ValueError, TypeError)):
                spec_identity.validate(invalid)
        for key, changed in [('unexpected', True), ('buildNumber', 0), ('buildNumber', 2100000001), ('commitSha', 'main')]:
            invalid = copy.deepcopy(value)
            invalid['frozenInputs'][key] = changed
            with self.assertRaises(ValueError):
                spec_identity.validate(invalid)

class NativeSpecTests(unittest.TestCase):
    def test_fixed_native_hash_vector_is_shared_with_hawk(self):
        value = json.loads((Path(__file__).parent / 'fixtures/build_spec_v2_identity.json').read_text())
        self.assertEqual(spec_identity.digest(value['input']), value['sha256'])
        value['input']['artifactPrefix'] = 'different-attempt/'
        self.assertEqual(spec_identity.digest(value['input']), value['sha256'])
        value['input']['assembly']['revision'] += 1
        self.assertNotEqual(spec_identity.digest(value['input']), value['sha256'])

    def test_native_selection_source_platform_and_catalog_tampering_fail(self):
        import copy
        value = json.loads((Path(__file__).parent / 'fixtures/build-spec-apk.json').read_text())['config']
        native = json.loads((Path(__file__).parent / 'fixtures/build_spec_v2_identity.json').read_text())['input']
        value.pop('releaseId')
        value['schemaVersion'] = 2
        value['platform'] = 'android'
        value['commitSha'] = native['commitSha']
        value['frozenInputs']['commitSha'] = native['commitSha']
        value['frozenInputs']['builtinResources'] = []
        value['frozenInputs']['languages'] = []
        value['assembly'] = native['assembly']
        value['dartDefines']['SWAN_INTERNAL_BUILD'] = 'false'
        spec_identity.validate(value)
        for change in (lambda s: s.update(releaseId='1'),
                       lambda s: s['assembly'].update(catalogDigest='sha256:' + '0' * 64),
                       lambda s: s['assembly']['catalog'].update(sourceCommit='b' * 40),
                       lambda s: s['assembly']['selections'][0].update(presentation='UNKNOWN'),
                       lambda s: s['dartDefines'].update(SWAN_INTERNAL_BUILD='true')):
            invalid = copy.deepcopy(value)
            change(invalid)
            with self.assertRaises(ValueError):
                spec_identity.validate(invalid)

    def test_resolved_app_configuration_does_not_require_home(self):
        import copy
        import hashlib
        value = json.loads((Path(__file__).parent / 'fixtures/build-spec-apk.json').read_text())['config']
        native = json.loads((Path(__file__).parent / 'fixtures/build_spec_v2_identity.json').read_text())['input']
        value.pop('releaseId')
        value['schemaVersion'] = 2
        value['platform'] = 'android'
        value['commitSha'] = native['commitSha']
        value['frozenInputs']['commitSha'] = native['commitSha']
        value['frozenInputs']['builtinResources'] = []
        value['frozenInputs']['languages'] = []
        value['assembly'] = copy.deepcopy(native['assembly'])
        value['dartDefines']['SWAN_INTERNAL_BUILD'] = 'false'
        presentation = value['assembly']['catalog']['presentations'][0]
        presentation['feature'] = 'FEEDBACK'
        value['assembly']['selections'] = [{'feature': 'FEEDBACK', 'presentation': 'PLUME'}]
        catalog = value['assembly']['catalog']
        body = json.dumps(catalog, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
        value['assembly']['catalogDigest'] = 'sha256:' + hashlib.sha256(body).hexdigest()
        historical = copy.deepcopy(value)
        with self.assertRaisesRegex(ValueError, 'native HOME implementation required'):
            spec_identity.validate(historical)
        digest = 'sha256:' + 'ab' * 32
        theme = {
            'kind': 'builtinDefault', 'featureKey': 'FEEDBACK', 'presentationKey': 'PLUME',
            'assets': [], 'digest': digest,
        }
        value['appConfiguration'] = {
            'configurationRevision': 2,
            'commonSnapshotDigest': digest,
            'explicitEnabledFeatures': ['FEEDBACK'],
            'dependencyFeatures': [],
            'resolvedFeatures': ['FEEDBACK'],
            'bindings': [{'featureKey': 'FEEDBACK', 'presentationKey': 'PLUME', 'themeDigest': digest, 'theme': theme}],
            'themes': [theme],
            'shell': {
                'appBar': [{'featureKey': 'FEEDBACK', 'label': 'Help', 'order': 0, 'visible': True}],
                'personalCenter': [],
                'startupFeature': 'FEEDBACK',
            },
            'digests': {key: digest for key in ('capability', 'catalog', 'resource', 'source')},
            'identity': {
                'tenantId': value['tenantId'], 'appId': value['appId'], 'platform': 'android',
                'applicationIdentifier': value.get('applicationIdentifier', 'com.example.app'),
            },
            'permissions': [],
            'signing': {
                'reference': 'signing:1', 'versionId': '1', 'certificateSha256': 'ab',
                'purpose': 'direct', 'distributionMethod': 'direct',
            },
            'targetFacts': {'buildNumber': 1, 'versionName': '1.0.0', 'packagingRevision': 1},
            'targets': value['targets'],
        }
        spec_identity.validate(value)

    def test_app_configuration_contract_rejects_secrets_and_disabled_personal_center(self):
        import copy
        legacy = json.loads((Path(__file__).parent / 'fixtures/build-spec-apk.json').read_text())['config']
        native = json.loads((Path(__file__).parent / 'fixtures/build_spec_v2_identity.json').read_text())['input']
        value = copy.deepcopy(legacy)
        value.pop('releaseId')
        value['schemaVersion'] = 2
        value['platform'] = 'android'
        value['commitSha'] = native['commitSha']
        value['frozenInputs']['commitSha'] = native['commitSha']
        value['frozenInputs']['builtinResources'] = []
        value['frozenInputs']['languages'] = []
        value['assembly'] = native['assembly']
        value['dartDefines']['SWAN_INTERNAL_BUILD'] = 'false'
        digest = 'sha256:' + 'ab' * 32
        theme = {
            'kind': 'builtinDefault', 'featureKey': 'HOME', 'presentationKey': 'PLUME',
            'assets': [], 'digest': digest,
        }
        value['appConfiguration'] = {
            'configurationRevision': 2,
            'commonSnapshotDigest': digest,
            'explicitEnabledFeatures': ['HOME'],
            'dependencyFeatures': [],
            'resolvedFeatures': ['HOME'],
            'bindings': [{'featureKey': 'HOME', 'presentationKey': 'PLUME', 'themeDigest': digest, 'theme': theme}],
            'themes': [theme],
            'shell': {
                'appBar': [{'featureKey': 'HOME', 'label': 'Home', 'order': 0, 'visible': True}],
                'personalCenter': [],
                'startupFeature': 'HOME',
            },
            'digests': {key: digest for key in ('capability', 'catalog', 'resource', 'source')},
            'identity': {
                'tenantId': value['tenantId'], 'appId': value['appId'], 'platform': 'android',
                'applicationIdentifier': 'com.example.app',
            },
            'permissions': [],
            'signing': {
                'reference': 'signing:1', 'versionId': '1', 'certificateSha256': 'ab',
                'purpose': 'direct', 'distributionMethod': 'direct',
            },
            'targetFacts': {'buildNumber': 1, 'versionName': '1.0.0', 'packagingRevision': 1},
            'targets': value['targets'],
        }
        spec_identity.validate(value)
        for presentation in ('A', 'HOME_2', 'A' * 80):
            with self.subTest(presentation=presentation):
                valid = copy.deepcopy(value)
                valid['appConfiguration']['bindings'][0]['presentationKey'] = presentation
                valid['appConfiguration']['themes'][0]['presentationKey'] = presentation
                spec_identity.validate(valid)
        missing = copy.deepcopy(value)
        del missing['appConfiguration']['bindings'][0]['presentationKey']
        del missing['appConfiguration']['themes'][0]['presentationKey']
        with self.assertRaisesRegex(ValueError, 'invalid presentation key'):
            spec_identity.validate(missing)
        for presentation in ('', ' ', 'plume', '1PLUME', 'PLUME-HOME', 'PLÜME', 'PLUME\n',
                             'A' * 81, None, 1, True, [], {}):
            with self.subTest(presentation=presentation):
                invalid = copy.deepcopy(value)
                invalid['appConfiguration']['bindings'][0]['presentationKey'] = presentation
                invalid['appConfiguration']['themes'][0]['presentationKey'] = presentation
                with self.assertRaisesRegex(ValueError, 'invalid presentation key'):
                    spec_identity.validate(invalid)
        different = copy.deepcopy(value)
        different['appConfiguration']['bindings'][0]['presentationKey'] = 'OTHER'
        with self.assertRaisesRegex(ValueError, 'theme digest does not match its binding'):
            spec_identity.validate(different)
        leaked = copy.deepcopy(value)
        leaked['appConfiguration']['themes'][0]['password'] = 'nope'
        with self.assertRaisesRegex(ValueError, 'secret entered the build spec'):
            spec_identity.validate(leaked)
        omitted = copy.deepcopy(value)
        del omitted['appConfiguration']
        spec_identity.validate(omitted)
        personal = copy.deepcopy(value)
        personal['appConfiguration']['shell']['personalCenter'] = [
            {'featureKey': 'HOME', 'label': 'Unused', 'order': 0, 'visible': True}
        ]
        with self.assertRaisesRegex(ValueError, 'personal center was frozen while disabled'):
            spec_identity.validate(personal)
        empty = copy.deepcopy(value)
        empty['appConfiguration']['bindings'] = [{}]
        empty['appConfiguration']['themes'] = [{}]
        with self.assertRaisesRegex(ValueError, 'invalid binding'):
            spec_identity.validate(empty)
        unresolved = copy.deepcopy(value)
        unresolved['appConfiguration']['shell']['appBar'] = [{'featureKey': 'NOT_COMPILED', 'visible': True}]
        unresolved['appConfiguration']['shell']['startupFeature'] = 'NOT_COMPILED'
        with self.assertRaisesRegex(ValueError, 'unknown shell item field'):
            spec_identity.validate(unresolved)
        outside = copy.deepcopy(value)
        outside['appConfiguration']['shell']['appBar'] = [
            {'featureKey': 'NOT_COMPILED', 'label': 'Missing', 'order': 0, 'visible': True}
        ]
        outside['appConfiguration']['shell']['startupFeature'] = 'NOT_COMPILED'
        with self.assertRaisesRegex(ValueError, 'shell feature is invalid'):
            spec_identity.validate(outside)
        mismatch = copy.deepcopy(value)
        mismatch['appConfiguration']['bindings'][0]['themeDigest'] = 'sha256:' + 'cd' * 32
        with self.assertRaisesRegex(ValueError, 'theme digest does not match its binding'):
            spec_identity.validate(mismatch)

        current = copy.deepcopy(value)
        block = current['appConfiguration']
        del block['bindings']
        del block['themes']
        theme = {
            'kind': 'builtinDefault',
            'key': 'PLUME:builtinDefault',
            'name': 'Built-in default',
            'version': 1,
            'presentationKey': 'PLUME',
            'assets': [],
            'sourceCommit': current['commitSha'],
        }
        body = json.dumps(theme, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
        theme['digest'] = 'sha256:' + hashlib.sha256(body).hexdigest()
        block['appearance'] = {
            'contractVersion': 1,
            'defaultPresentationKey': 'PLUME',
            'presentations': [{
                'presentationKey': 'PLUME',
                'styleKey': 'PLUME',
                'name': 'Plume',
                'order': 10,
                'directoryRevision': 1,
                'featureKeys': ['HOME'],
                'defaultThemeKey': 'PLUME:builtinDefault',
                'themes': [theme],
            }],
        }
        spec_identity.validate(current)
        invalid = copy.deepcopy(current)
        invalid['appConfiguration']['appearance']['presentations'][0]['themes'][0]['name'] = 'Changed'
        with self.assertRaisesRegex(ValueError, 'appearance theme digest mismatch'):
            spec_identity.validate(invalid)
