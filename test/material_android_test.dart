import 'dart:io';
import 'package:test/test.dart';
import 'package:buildbox_tools/src/core.dart' hide matches;
import 'package:buildbox_tools/src/material_common.dart';
import 'package:buildbox_tools/src/material_validation.dart';
import 'fixtures.dart';

void main() {
  for (final algorithm in ['RSA', 'EC']) {
    test(
      'PKCS12 $algorithm private-key challenge, alias facts, no Apple trust claims',
      () async {
        await temporary('test-material-', (dir) async {
          await keytoolStore(dir, algorithm: algorithm);
          final result = await validateDocument(
            androidRequest('${dir.path}/store'),
          );
          expect(result['status'], 'valid');
          expect(result['reasonCodes'], ['ok']);
          expect(result['storeType'], 'PKCS12');
          final leaf = (result['aliases'] as List).single;
          expect(leaf['algorithm'], algorithm);
          expect(leaf['signingCapable'], true);
          expect(leaf['purpose'], 'signing');
          expect(leaf['chainLength'], 1);
          expect(result['evidence']['privateKeyProven'], true);
          expect(result['evidence']['chainTrusted'], false);
          expect(result['evidence']['installable'], false);
          expect(result['evidence']['notExecuted'], isEmpty);
          expect(leaf['certificateSha256'], matches(RegExp(r'^[0-9a-f]{64}$')));
          assertPublic(result);
        });
      },
      timeout: const Timeout(Duration(minutes: 2)),
    );
  }
  test(
    'JKS wrong store/key passwords, validity boundaries, valid selected key',
    () async {
      await temporary('test-jks-', (dir) async {
        await keytoolStore(dir, type: 'JKS', keyPassword: 'keysecret');
        final base = androidRequest('${dir.path}/store');
        expect(
          (await validateSafely({
            ...base,
            'material': {
              'path': '${dir.path}/store',
              'storePassword': 'wrongpass',
            },
          }))['reasonCodes'],
          ['wrong_password'],
        );
        expect((await validateSafely(base))['reasonCodes'], [
          'wrong_key_password',
        ]);
        base['material']['keyPassword'] = 'keysecret';
        final valid = await validateSafely(base);
        expect(valid['status'], 'valid');
        final certificate = (valid['aliases'] as List).single;
        base['evaluatedAt'] = instant(
          DateTime.parse(
            certificate['notBefore'] as String,
          ).subtract(const Duration(seconds: 1)),
        );
        expect((await validateSafely(base))['reasonCodes'], [
          'certificate_not_yet_valid',
        ]);
        base['evaluatedAt'] = certificate['expiresAt'];
        expect((await validateSafely(base))['reasonCodes'], [
          'certificate_expired',
        ]);
      });
    },
    timeout: const Timeout(Duration(minutes: 2)),
  );
  test(
    'multi-alias requires explicit choice and reports uninspected aliases honestly',
    () async {
      await temporary('test-alias-', (dir) async {
        await keytoolStore(dir, type: 'JKS');
        await keytoolStore(dir, type: 'JKS', alias: 'second');
        final request = androidRequest('${dir.path}/store');
        expect((await validateSafely(request))['reasonCodes'], [
          'ambiguous_alias',
        ]);
        request['material']['alias'] = 'missing';
        expect((await validateSafely(request))['reasonCodes'], [
          'alias_not_found',
        ]);
        request['material']['alias'] = 'second';
        final result = await validateSafely(request);
        expect(result['status'], 'valid');
        expect(result['aliasCount'], 2);
        expect(
          (result['aliases'] as List).singleWhere(
            (a) => a['alias'] == 'release',
          )['signingCapable'],
          false,
        );
        expect(
          (result['aliases'] as List).singleWhere(
            (a) => a['alias'] == 'second',
          )['signingCapable'],
          true,
        );
      });
    },
    timeout: const Timeout(Duration(minutes: 2)),
  );
  test(
    'stored PKCS12 chain exports every certificate, not just leaf',
    () async {
      await temporary('test-chain-', (dir) async {
        await keytoolStore(dir, type: 'PKCS12');
        final ca = '${dir.path}/ca.p12',
            csr = '${dir.path}/leaf.csr',
            caCert = '${dir.path}/ca.pem',
            reply = '${dir.path}/reply.pem',
            store = '${dir.path}/store';
        final env = {...Platform.environment, 'TEST_STORE_PASS': 'changeit'};
        await tool([
          'keytool',
          '-genkeypair',
          '-noprompt',
          '-keystore',
          ca,
          '-storetype',
          'PKCS12',
          '-storepass:env',
          'TEST_STORE_PASS',
          '-alias',
          'ca',
          '-keyalg',
          'RSA',
          '-keysize',
          '2048',
          '-dname',
          'CN=Root',
          '-ext',
          'BC=ca:true',
          '-validity',
          '3650',
        ], environment: env);
        await tool([
          'keytool',
          '-certreq',
          '-keystore',
          store,
          '-storepass:env',
          'TEST_STORE_PASS',
          '-alias',
          'release',
          '-file',
          csr,
        ], environment: env);
        await tool([
          'keytool',
          '-gencert',
          '-keystore',
          ca,
          '-storepass:env',
          'TEST_STORE_PASS',
          '-alias',
          'ca',
          '-infile',
          csr,
          '-outfile',
          reply,
          '-rfc',
          '-validity',
          '3650',
        ], environment: env);
        await tool([
          'keytool',
          '-exportcert',
          '-keystore',
          ca,
          '-storepass:env',
          'TEST_STORE_PASS',
          '-alias',
          'ca',
          '-rfc',
          '-file',
          caCert,
        ], environment: env);
        await tool([
          'keytool',
          '-importcert',
          '-noprompt',
          '-keystore',
          store,
          '-storepass:env',
          'TEST_STORE_PASS',
          '-alias',
          'root',
          '-file',
          caCert,
        ], environment: env);
        await tool([
          'keytool',
          '-importcert',
          '-keystore',
          store,
          '-storepass:env',
          'TEST_STORE_PASS',
          '-alias',
          'release',
          '-file',
          reply,
        ], environment: env);
        final request = androidRequest(store)
          ..['evaluatedAt'] = instant(
            DateTime.now().toUtc().add(const Duration(minutes: 1)),
          );
        final result = await validateSafely(request);
        expect(result['status'], 'valid');
        final leaf = (result['aliases'] as List).single;
        expect(leaf['chainLength'], 2);
        expect((leaf['chainSha256'] as List).toSet().length, 2);
      });
    },
    timeout: const Timeout(Duration(minutes: 3)),
  );
  test('unknown format is distinct from password failure', () async {
    await temporary('test-format-', (dir) async {
      final file = File('${dir.path}/bytes')
        ..writeAsStringSync('not a keystore');
      expect((await validateSafely(androidRequest(file.path)))['reasonCodes'], [
        'unknown_format',
      ]);
    });
  });
  test(
    'native private-key challenge rejects a different certificate',
    () async {
      await temporary('test-challenge-', (dir) async {
        await tool([
          'openssl',
          'req',
          '-x509',
          '-newkey',
          'rsa:2048',
          '-nodes',
          '-keyout',
          '${dir.path}/one.key',
          '-out',
          '${dir.path}/one.crt',
          '-days',
          '1',
          '-subj',
          '/CN=One',
        ]);
        await tool([
          'openssl',
          'req',
          '-x509',
          '-newkey',
          'rsa:2048',
          '-nodes',
          '-keyout',
          '${dir.path}/two.key',
          '-out',
          '${dir.path}/two.crt',
          '-days',
          '1',
          '-subj',
          '/CN=Two',
        ]);
        await expectLater(
          provePrivateKey(
            File('${dir.path}/one.key').readAsStringSync(),
            File('${dir.path}/two.crt').readAsStringSync(),
            dir,
          ),
          throwsA(
            isA<ValidationFailure>().having(
              (e) => e.code,
              'code',
              'private_key_mismatch',
            ),
          ),
        );
      });
    },
  );
}
