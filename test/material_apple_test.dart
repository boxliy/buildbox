import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:buildbox_tools/src/core.dart';
import 'package:buildbox_tools/src/material_common.dart';
import 'package:buildbox_tools/src/material_apple.dart';
import 'package:buildbox_tools/src/material_validation.dart';
import 'fixtures.dart';

void main() {
  for (final algorithm in ['RSA', 'EC']) {
    test(
      'Apple $algorithm certificate private-key proof is valid after key, team, and validity checks',
      () async {
        await temporary('test-apple-', (dir) async {
          final key = '${dir.path}/key.pem',
              crt = '${dir.path}/cert.pem',
              p12 = '${dir.path}/identity.p12';
          await tool([
            'openssl',
            'req',
            '-x509',
            '-newkey',
            algorithm == 'RSA' ? 'rsa:2048' : 'ec',
            '-nodes',
            if (algorithm == 'EC') ...['-pkeyopt', 'ec_paramgen_curve:P-256'],
            '-keyout',
            key,
            '-out',
            crt,
            '-days',
            '365',
            '-subj',
            '/CN=Apple/OU=ABCDEFGHIJ',
          ]);
          await tool(
            [
              'openssl',
              'pkcs12',
              '-export',
              '-inkey',
              key,
              '-in',
              crt,
              '-out',
              p12,
              '-passout',
              'env:TEST_P12_PASSWORD',
            ],
            environment: {
              ...Platform.environment,
              'TEST_P12_PASSWORD': 'changeit',
            },
          );
          final request = appleRequest(p12, 'certificate')
            ..['evaluatedAt'] = instant(
              DateTime.now().toUtc().add(const Duration(minutes: 1)),
            );
          final result = await validateDocument(request);
          expect(result['status'], 'valid');
          expect(result['certificate']['algorithm'], algorithm);
          expect(result['certificate']['teamId'], 'ABCDEFGHIJ');
          expect(result['evidence']['privateKeyProven'], true);
          expect(result['evidence']['chainTrusted'], true);
          expect(result['evidence']['notExecuted'], isEmpty);
          expect(result['reasonCodes'], ['ok']);
          final expired = Map<String, dynamic>.from(request);
          expired['evaluatedAt'] = instant(
            DateTime.now().toUtc().add(const Duration(days: 400)),
          );
          final expiredResult = await validateDocument(expired);
          expect(expiredResult['status'], 'invalid');
          expect(expiredResult['reasonCodes'], contains('certificate_expired'));
          request['material']['password'] = 'wrong';
          expect((await validateSafely(request))['reasonCodes'], [
            'wrong_password',
          ]);
        });
      },
    );
  }
  for (final method in ['development', 'ad_hoc', 'enterprise', 'app_store']) {
    test('profile derives $method and fixed UTC validity boundary', () async {
      await temporary('test-profile-', (dir) async {
        final profile = <String, dynamic>{
          'UUID': 'UUID',
          'TeamIdentifier': ['ABCDEFGHIJ'],
          'CreationDate': DateTime.utc(2026, 1, 1),
          'ExpirationDate': DateTime.utc(2027, 1, 1),
          'DeveloperCertificates': <Uint8List>[],
          'Entitlements': {
            'application-identifier': 'ABCDEFGHIJ.com.example.app',
            'com.apple.developer.team-identifier': 'ABCDEFGHIJ',
            'get-task-allow': method == 'development',
          },
          if (['development', 'ad_hoc'].contains(method))
            'ProvisionedDevices': ['device'],
          if (method == 'enterprise') 'ProvisionsAllDevices': true,
        };
        final derived = await deriveProfile(
          profile,
          DateTime.utc(2026, 11, 1),
          dir,
        );
        expect(derived['profile']['distribution'], method);
        expect(derived['profile']['bundleId'], 'com.example.app');
        final late = await deriveProfile(
          profile,
          DateTime.utc(2027, 1, 1),
          dir,
        );
        expect(late['reasonCodes'], contains('profile_expired'));
        final early = await deriveProfile(
          profile,
          DateTime.utc(2025, 12, 31, 23, 59, 59),
          dir,
        );
        expect(early['reasonCodes'], contains('profile_not_yet_valid'));
        expect(
          instant(evaluatedTime('2026-11-01T00:00:00Z')),
          '2026-11-01T00:00:00Z',
        );
        expect(
          () => evaluatedTime('2026-11-01T08:00:00+08:00'),
          throwsA(isA<ValidationFailure>()),
        );
      });
    });
  }
  test(
    'CMS-signed provisioning profiles are valid until identity expectations or the CMS bytes are tampered',
    () async {
      await temporary('test-cms-', (dir) async {
        final key = '${dir.path}/key.pem', cert = '${dir.path}/cert.pem';
        await issueCertificate(
          key,
          cert,
          start: '20260101000000Z',
          end: '20280101000000Z',
        );
        final der = await tool([
          'openssl',
          'x509',
          '-in',
          cert,
          '-outform',
          'PEM',
        ]);
        final encoded = RegExp(
          r'-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----',
        ).firstMatch(der)![1]!.replaceAll(RegExp(r'\s'), '');
        final profile = <String, dynamic>{
          'UUID': 'fixture',
          'TeamIdentifier': ['ABCDEFGHIJ'],
          'CreationDate': DateTime.utc(2026, 1, 1),
          'ExpirationDate': DateTime.utc(2099, 1, 1),
          'DeveloperCertificates': [base64.decode(encoded)],
          'Entitlements': {
            'application-identifier': 'ABCDEFGHIJ.com.example.app',
            'com.apple.developer.team-identifier': 'ABCDEFGHIJ',
            'get-task-allow': false,
          },
          'ProvisionedDevices': ['device'],
        };
        final plist = File('${dir.path}/profile.plist')
              ..writeAsStringSync(encodePlist(profile)),
            cms = '${dir.path}/profile.mobileprovision';
        await tool([
          'openssl',
          'cms',
          '-sign',
          '-binary',
          '-nodetach',
          '-in',
          plist.path,
          '-signer',
          cert,
          '-inkey',
          key,
          '-outform',
          'DER',
          '-out',
          cms,
        ]);
        final request = appleRequest(cms, 'provisioning_profile');
        final result = await validateDocument(request);
        expect(result['evidence']['cmsParsed'], true);
        expect(result['evidence']['cmsSignatureVerified'], true);
        expect(result['evidence']['chainTrusted'], true);
        expect(result['evidence']['notExecuted'], isEmpty);
        expect(result['status'], 'valid');
        request['expectations'] = {
          'teamId': 'ZZZZZZZZZZ',
          'bundleId': 'com.wrong.app',
          'distribution': 'enterprise',
          'entitlements': {'aps-environment': 'production'},
          'certificateSha256': '0' * 64,
        };
        final mismatch = await validateDocument(request);
        expect(
          mismatch['reasonCodes'],
          containsAll([
            'team_mismatch',
            'bundle_mismatch',
            'distribution_mismatch',
            'entitlements_mismatch',
            'certificate_mismatch',
          ]),
        );
        final bytes = File(cms).readAsBytesSync();
        bytes[bytes.length - 1] ^= 1;
        File(cms).writeAsBytesSync(bytes);
        final tampered = await validateSafely(request);
        expect(tampered['status'], 'invalid');
      });
    },
  );
  test(
    'active profiles reject expired or not-yet-valid developer certificates',
    () async {
      await temporary('test-profile-validity-', (dir) async {
        final signerKey = '${dir.path}/signer.key',
            signerCert = '${dir.path}/signer.crt';
        await issueCertificate(
          signerKey,
          signerCert,
          start: '20260101000000Z',
          end: '20280101000000Z',
        );
        final expiredKey = '${dir.path}/expired.key',
            expiredCert = '${dir.path}/expired.crt';
        await issueCertificate(
          expiredKey,
          expiredCert,
          start: '20200101000000Z',
          end: '20210101000000Z',
        );
        final futureKey = '${dir.path}/future.key',
            futureCert = '${dir.path}/future.crt';
        await issueCertificate(
          futureKey,
          futureCert,
          start: '20990101000000Z',
          end: '21000101000000Z',
        );
        final validDer = await certificateDerFile(signerCert),
            expiredDer = await certificateDerFile(expiredCert),
            futureDer = await certificateDerFile(futureCert);
        final expiredOnly = await cmsProfile(
          dir,
          [expiredDer],
          signerCert: signerCert,
          signerKey: signerKey,
          name: 'expired',
        );
        final expiredResult = await validateDocument(
          appleRequest(expiredOnly, 'provisioning_profile'),
        );
        expect(expiredResult['status'], 'invalid');
        expect(expiredResult['reasonCodes'], contains('certificate_expired'));
        expect(expiredResult['evidence']['chainTrusted'], false);
        final futureOnly = await cmsProfile(
          dir,
          [futureDer],
          signerCert: signerCert,
          signerKey: signerKey,
          name: 'future',
        );
        final futureResult = await validateDocument(
          appleRequest(futureOnly, 'provisioning_profile'),
        );
        expect(futureResult['status'], 'invalid');
        expect(
          futureResult['reasonCodes'],
          contains('certificate_not_yet_valid'),
        );
        expect(futureResult['evidence']['chainTrusted'], false);
        final mixed = await cmsProfile(
          dir,
          [expiredDer, validDer],
          signerCert: signerCert,
          signerKey: signerKey,
          name: 'mixed',
        );
        final mixedRequest = appleRequest(mixed, 'provisioning_profile');
        final usable = await validateDocument(mixedRequest);
        expect(usable['status'], 'valid');
        expect(usable['evidence']['chainTrusted'], true);
        expect(usable['reasonCodes'], ['ok']);
        mixedRequest['expectations'] = {
          'certificateSha256': hashBytes(expiredDer),
        };
        final selectedExpired = await validateDocument(mixedRequest);
        expect(selectedExpired['status'], 'invalid');
        expect(selectedExpired['reasonCodes'], contains('certificate_expired'));
        expect(selectedExpired['evidence']['chainTrusted'], false);
        expect(
          selectedExpired['reasonCodes'],
          isNot(contains('certificate_mismatch')),
        );
        mixedRequest['expectations'] = {
          'certificateSha256': hashBytes(validDer),
        };
        final selectedValid = await validateDocument(mixedRequest);
        expect(selectedValid['status'], 'valid');
        expect(selectedValid['evidence']['chainTrusted'], true);
        expect(selectedValid['reasonCodes'], ['ok']);
      });
    },
  );
}

Future<void> issueCertificate(
  String key,
  String cert, {
  required String start,
  required String end,
}) => tool([
  'openssl',
  'req',
  '-x509',
  '-newkey',
  'rsa:2048',
  '-nodes',
  '-keyout',
  key,
  '-out',
  cert,
  '-subj',
  '/CN=Fixture/OU=ABCDEFGHIJ',
  '-not_before',
  start,
  '-not_after',
  end,
]);

Future<Uint8List> certificateDerFile(String cert) async {
  final der = '$cert.der';
  await tool(['openssl', 'x509', '-in', cert, '-outform', 'DER', '-out', der]);
  return File(der).readAsBytesSync();
}

Future<String> cmsProfile(
  Directory dir,
  List<Uint8List> certificates, {
  required String signerCert,
  required String signerKey,
  String name = 'profile',
}) async {
  final profile = <String, dynamic>{
    'UUID': 'fixture',
    'TeamIdentifier': ['ABCDEFGHIJ'],
    'CreationDate': DateTime.utc(2026, 1, 1),
    'ExpirationDate': DateTime.utc(2099, 1, 1),
    'DeveloperCertificates': certificates,
    'Entitlements': {
      'application-identifier': 'ABCDEFGHIJ.com.example.app',
      'com.apple.developer.team-identifier': 'ABCDEFGHIJ',
      'get-task-allow': false,
    },
    'ProvisionedDevices': ['device'],
  };
  final plist = File('${dir.path}/$name.plist')
    ..writeAsStringSync(encodePlist(profile));
  final cms = '${dir.path}/$name.mobileprovision';
  await tool([
    'openssl',
    'cms',
    '-sign',
    '-binary',
    '-nodetach',
    '-in',
    plist.path,
    '-signer',
    signerCert,
    '-inkey',
    signerKey,
    '-outform',
    'DER',
    '-out',
    cms,
  ]);
  return cms;
}
