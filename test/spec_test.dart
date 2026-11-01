import 'dart:convert';
import 'dart:io';
import 'package:test/test.dart';
import 'package:buildbox_tools/src/core.dart';
import 'package:buildbox_tools/src/spec.dart';
import 'fixtures.dart';

void main() {
  test(
    'revision manifest preserves emitted zero appearance revision and rejects malformed shape',
    () {
      final spec = nativeSpec();
      spec['revisionManifest'] = <String, dynamic>{
        'featureRevision': 1,
        'shellRevision': 1,
        'appearanceRevision': 0,
        'resourceRevision': 1,
      };
      validateSpec(spec);
      final originalHash = specDigest(spec);
      spec['revisionManifest']['appearanceRevision'] = 1;
      expect(specDigest(spec), isNot(originalHash));
      for (final mutation in <void Function(Json)>[
        (m) => m['featureRevision'] = 0,
        (m) => m['shellRevision'] = -1,
        (m) => m['appearanceRevision'] = -1,
        (m) => m['resourceRevision'] = 1.0,
        (m) => m['unknown'] = 1,
        (m) => m.remove('featureRevision'),
      ]) {
        final changed = clone(spec);
        mutation(changed['revisionManifest'] as Json);
        expect(() => validateSpec(changed), throwsA(anything));
      }
    },
  );
  test('canonical bytes and SHA match Hawk fixed vectors', () {
    final vectors =
        jsonDecode(
              File(
                'test/fixtures/dart_canonical_vectors.json',
              ).readAsStringSync(),
            )
            as List;
    for (final vector in vectors) {
      final value = strictJson(vector['json'] as String);
      expect(
        canonical(value),
        vector['canonical'],
        reason: vector['name'] as String,
      );
      expect(hashJson(value), vector['sha256']);
    }
  });
  test('strict JSON rejects duplicate keys, nonfinite, and trailing data', () {
    for (final input in [
      '{"a":1,"a":2}',
      '{"nested":{"a":1,"a":2}}',
      'NaN',
      '1e999',
      '{}[]',
      '{"schemaVersion":2.0,"schemaVersion":2}',
    ]) {
      expect(() => strictJson(input), throwsA(anything), reason: input);
    }
  });
  test(
    'native identity matches Hawk fixed digest and excludes attempt prefix',
    () {
      final fixture = readJson('tests/fixtures/build_spec_v2_identity.json');
      expect(specDigest(fixture['input'] as Json), fixture['sha256']);
      final changed = clone(fixture['input'] as Json)
        ..['artifactPrefix'] = 'new/attempt/';
      expect(specDigest(changed), fixture['sha256']);
      changed['assembly']['revision']++;
      expect(specDigest(changed), isNot(fixture['sha256']));
    },
  );
  test('current native spec validates without any legacy adapter', () {
    validateSpec(nativeSpec());
    final old = nativeSpec()..['schemaVersion'] = 1;
    expect(() => validateSpec(old), throwsFormatException);
  });
  test(
    'scope versions IDs resources unknown fields and target mutations reject',
    () {
      final mutations = <void Function(Json)>[
        (s) => s['unexpected'] = true,
        (s) => s['tenantId'] = 1,
        (s) => s['targets'] = ['apk', 'ipa'],
        (s) => s['targets'] = ['apk', 'aab'],
        (s) => s['frozenInputs']['buildNumber'] = 0,
        (s) => s['frozenInputs']['buildNumber'] = 2100000001,
        (s) => s['frozenInputs']['commitSha'] = 'main',
        (s) => s['frozenInputs']['sourceRepo'] = 'other/repo',
        (s) => s['frozenInputs']['fvmrc']['path'] = '../fvmrc',
        (s) => s['frozenInputs']['brandAssets'][0]['path'] =
            'waterfowl/../private',
        (s) => s['frozenInputs']['unknown'] = true,
      ];
      for (final mutation in mutations) {
        final spec = nativeSpec();
        mutation(spec);
        expect(() => validateSpec(spec), throwsA(anything));
      }
    },
  );
  test(
    'native catalog source selection platform and digest tampering reject',
    () {
      for (final mutation in <void Function(Json)>[
        (s) => s['releaseId'] = '1',
        (s) => s['assembly']['catalogDigest'] = 'sha256:${'0' * 64}',
        (s) => s['assembly']['catalog']['sourceCommit'] = 'b' * 40,
        (s) => s['assembly']['selections'][0]['presentation'] = 'UNKNOWN',
        (s) => s['dartDefines']['SWAN_INTERNAL_BUILD'] = 'true',
      ]) {
        final spec = nativeSpec();
        mutation(spec);
        expect(() => validateSpec(spec), throwsA(anything));
      }
    },
  );
}
