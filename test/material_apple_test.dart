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
      'Apple $algorithm certificate private-key proof stays invalid without real Apple trust execution',
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
          expect(result['status'], 'invalid');
          expect(result['certificate']['algorithm'], algorithm);
          expect(result['certificate']['teamId'], 'ABCDEFGHIJ');
          expect(result['evidence']['privateKeyProven'], true);
          expect(result['evidence']['chainTrusted'], false);
          expect(result['evidence']['notExecuted'], trustChecks);
          expect(
            result['reasonCodes'],
            contains('macos_capability_unavailable'),
          );
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
    'CMS parsing success never becomes trusted or installable; expected identity tamper rejects',
    () async {
      await temporary('test-cms-', (dir) async {
        final key = '${dir.path}/key.pem', cert = '${dir.path}/cert.pem';
        await tool([
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
          '-days',
          '365',
          '-subj',
          '/CN=Fixture/OU=ABCDEFGHIJ',
        ]);
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
        expect(result['evidence']['cmsSignatureVerified'], false);
        expect(result['evidence']['chainTrusted'], false);
        expect(result['status'], 'invalid');
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
}
