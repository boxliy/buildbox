import 'dart:convert';
import 'package:test/test.dart';
import 'package:buildbox_tools/src/core.dart';
import 'package:buildbox_tools/src/material_common.dart';
import 'package:buildbox_tools/src/material_validation.dart';
import 'fixtures.dart';

void main() {
  test('published empty expected object becomes scoped Android request', () {
    final envelope = validationEnvelope(),
        offline = offlineRequest(envelope, '2026-11-01T00:00:00Z');
    expect(offline['platform'], 'android');
    expect(offline['scope']['stage'], 'validate');
    expect(offline['scope']['versionId'], '3');
    expect(offline['material']['storePassword'], 'changeit');
    expect(offline['material']['keyPassword'], 'changeit');
    expect(offline['material'].containsKey('alias'), false);
  });
  test('malformed expected, time, identity, schema and kind reject', () {
    for (final mutate in <void Function(Json)>[
      (e) => e['schemaVersion'] = 2,
      (e) => e['toolchainSha'] = 'main',
      (e) => e['material'] = {},
      (e) => e['expected'] = null,
      (e) => e['kind'] = 'other',
    ]) {
      final envelope = validationEnvelope();
      mutate(envelope);
      expect(
        () => offlineRequest(envelope, '2026-11-01T00:00:00Z'),
        throwsA(isA<ValidationFailure>()),
      );
    }
    expect(
      () => offlineRequest(validationEnvelope(), 'missing'),
      throwsA(isA<ValidationFailure>()),
    );
  });
  test(
    'Android public result uses exact Hawk allowlisted fields, no material',
    () {
      final envelope = validationEnvelope(),
          scope = offlineRequest(envelope, '2026-11-01T00:00:00Z')['scope'];
      final offline = <String, dynamic>{
        'contract': contract,
        'scope': scope,
        'status': 'valid',
        'reasonCodes': ['ok'],
        'expiresAt': '2030-01-01T00:00:00Z',
        'aliases': [
          {
            'alias': 'release',
            'certificateSha256': 'a' * 64,
            'signingCapable': true,
            'purpose': 'signing',
            'chainLength': 1,
            'chainSha256': ['a' * 64],
          },
        ],
        'evidence': {'privateKeyProven': true, 'notExecuted': []},
        'tools': {'openssl': 'OpenSSL fixture'},
      };
      final result = hawkResult(envelope, offline, '2026-11-01T00:00:00Z');
      expect(result['reasonCodes'], isEmpty);
      expect(result['metadata']['aliases'][0].keys.toSet(), {
        'alias',
        'certificateSha256',
        'notBefore',
        'expiresAt',
        'algorithm',
        'signingCapable',
        'purpose',
      });
      expect(result['evidence']['privateKeyProven'], true);
      expect(jsonEncode(result), isNot(contains('changeit')));
      assertPublic(result);
      offline['scope'] = {...scope as Json, 'versionId': 'other'};
      expect(
        () => hawkResult(envelope, offline, '2026-11-01T00:00:00Z'),
        throwsA(isA<ValidationFailure>()),
      );
    },
  );
  test('profile distribution and reason mapping are Hawk compatible', () {
    final e = validationEnvelope()..['kind'] = 'apple_profile';
    final r = offlineRequest(e, '2026-11-01T00:00:00Z');
    final offline = <String, dynamic>{
      'contract': contract,
      'scope': r['scope'],
      'status': 'invalid',
      'reasonCodes': ['entitlements_mismatch', 'profile_expired'],
      'profile': {
        'distribution': 'ad_hoc',
        'entitlements': {'get-task-allow': false},
      },
      'evidence': {'notExecuted': trustChecks},
    };
    final result = hawkResult(e, offline, '2026-11-01T00:00:00Z');
    expect(result['metadata']['distributionMethod'], 'ad-hoc');
    expect(result['reasonCodes'], ['entitlement_mismatch', 'expired']);
    expect(result['evidence']['notExecuted'], trustChecks);
  });
  test(
    'valid status cannot claim unfinished trust checks; unknown failures fail closed',
    () {
      final e = validationEnvelope(),
          scope = offlineRequest(e, '2026-11-01T00:00:00Z')['scope'];
      final offline = <String, dynamic>{
        'contract': contract,
        'scope': scope,
        'status': 'valid',
        'reasonCodes': ['ok'],
        'evidence': {'notExecuted': trustChecks},
      };
      expect(
        () => hawkResult(e, offline, '2026-11-01T00:00:00Z'),
        throwsA(isA<ValidationFailure>()),
      );
      offline['status'] = 'invalid';
      offline['reasonCodes'] = ['unpublished_reason'];
      expect(
        () => hawkResult(e, offline, '2026-11-01T00:00:00Z'),
        throwsA(isA<ValidationFailure>()),
      );
      final apple = validationEnvelope()..['kind'] = 'apple_certificate';
      final appleScope = offlineRequest(apple, '2026-11-01T00:00:00Z')['scope'];
      final appleResult = <String, dynamic>{
        'contract': contract,
        'scope': appleScope,
        'status': 'valid',
        'reasonCodes': ['ok'],
        'certificate': {
          'teamId': 'ABCDEFGHIJ',
          'certificateSha256': 'a' * 64,
          'notBefore': '2026-01-01T00:00:00Z',
          'expiresAt': '2030-01-01T00:00:00Z',
        },
        'evidence': {
          'privateKeyProven': true,
          'chainTrusted': true,
          'cmsSignatureVerified': false,
          'notExecuted': <String>[],
        },
      };
      final published = hawkResult(apple, appleResult, '2026-11-01T00:00:00Z');
      expect(published['status'], 'valid');
      expect(published['evidence']['chainTrusted'], true);
      expect(published['evidence']['notExecuted'], isEmpty);
      appleResult['evidence']['notExecuted'] = trustChecks;
      expect(
        () => hawkResult(apple, appleResult, '2026-11-01T00:00:00Z'),
        throwsA(isA<ValidationFailure>()),
      );
    },
  );
  test('secret-shaped result fields and PEM strings never escape', () {
    for (final secret in [
      {'token': 'secret'},
      {
        'metadata': {'privateKey': 'secret'},
      },
      {'reason': '-----BEGIN PRIVATE KEY-----'},
    ]) {
      expect(() => assertPublic(secret), throwsA(isA<ValidationFailure>()));
    }
  });
}
