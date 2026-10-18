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
        for version in [None, 0, 2, True, '1']:
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
