import 'dart:convert';
import 'dart:io';
import 'package:archive/archive.dart';
import 'package:test/test.dart';
import 'package:buildbox_tools/src/core.dart';
import 'package:buildbox_tools/src/sign_android.dart';
import 'package:buildbox_tools/src/sign_ios.dart' show certificateDer;
import 'fixtures.dart';

void main() {
  test('APK identity checks package, versionCode and versionName', () async {
    const output =
        "package: name='com.example.app' versionCode='7' versionName='1.2.3'";
    final m = <String, dynamic>{
      'applicationIdentifier': 'com.example.app',
      'buildNumber': 7,
      'versionName': '1.2.3',
    };
    await verifyAndroidIdentity(
      'fixture.apk',
      'apk',
      m,
      execute: (_) async => output,
    );
    for (final changed in [
      {...m, 'applicationIdentifier': 'com.wrong'},
      {...m, 'buildNumber': 8},
      {...m, 'versionName': '2.0.0'},
    ]) {
      await expectLater(
        verifyAndroidIdentity(
          'fixture.apk',
          'apk',
          changed,
          execute: (_) async => output,
        ),
        throwsFormatException,
      );
    }
  });
  test(
    'real JAR signing verifies certificate and rejects fingerprint mismatch and tamper',
    () async {
      await temporary('test-sign-', (dir) async {
        await keytoolStore(dir);
        final archive = Archive()
          ..addFile(ArchiveFile.string('classes.dex', 'fixture code'));
        final source = '${dir.path}/unsigned.aab';
        File(source).writeAsBytesSync(ZipEncoder().encode(archive));
        final env = {...Platform.environment, 'TEST_STORE_PASS': 'changeit'};
        final pem = await tool([
          'keytool',
          '-exportcert',
          '-rfc',
          '-keystore',
          '${dir.path}/store',
          '-storepass:env',
          'TEST_STORE_PASS',
          '-alias',
          'release',
        ], environment: env);
        final m = <String, dynamic>{
              'certificateSha256': hashBytes(certificateDer(pem)),
            },
            material = <String, dynamic>{
              'containerBase64': base64.encode(
                File('${dir.path}/store').readAsBytesSync(),
              ),
              'password': 'changeit',
              'alias': 'release',
            };
        final signed = '${dir.path}/signed.aab';
        var identityChecks = 0;
        Future<void> identity(String path, String target, Json meta) async {
          identityChecks++;
          expect(target, 'aab');
        }

        await signAndroidOne(
          source,
          signed,
          'aab',
          m,
          material,
          dir,
          verifyIdentity: identity,
        );
        expect(identityChecks, 2);
        expect(File(signed).existsSync(), true);
        await expectLater(
          signAndroidOne(
            source,
            '${dir.path}/mismatch.aab',
            'aab',
            {'certificateSha256': '0' * 64},
            material,
            dir,
            verifyIdentity: identity,
          ),
          throwsFormatException,
        );
        final append = Archive()
          ..addFile(ArchiveFile.string('classes.dex', 'tampered code'));
        final extra = '${dir.path}/classes.dex';
        File(extra).writeAsStringSync('tampered code');
        final result = await Process.run('jar', [
          'uf',
          signed,
          '-C',
          dir.path,
          'classes.dex',
        ]);
        expect(result.exitCode, 0);
        final verify = await toolResult([
          'jarsigner',
          '-verify',
          '-strict',
          '-keystore',
          '${dir.path}/store',
          '-storepass:env',
          'TEST_STORE_PASS',
          signed,
        ], environment: env);
        expect(verify.exitCode, isNot(0));
        expect(append.length, 1);
      });
    },
    timeout: const Timeout(Duration(minutes: 2)),
  );
  test(
    'unsupported DSA signing key fails before application signing',
    () async {
      await temporary('test-dsa-', (dir) async {
        await tool(
          [
            'keytool',
            '-genkeypair',
            '-noprompt',
            '-keystore',
            '${dir.path}/store',
            '-storetype',
            'PKCS12',
            '-storepass:env',
            'TEST_STORE_PASS',
            '-alias',
            'release',
            '-keyalg',
            'DSA',
            '-keysize',
            '2048',
            '-dname',
            'CN=DSA',
            '-validity',
            '3650',
          ],
          environment: {...Platform.environment, 'TEST_STORE_PASS': 'changeit'},
        );
        final source = '${dir.path}/input.aab';
        File(source).writeAsBytesSync(
          ZipEncoder().encode(
            Archive()..addFile(ArchiveFile.string('payload', 'fixture')),
          ),
        );
        await expectLater(
          signAndroidOne(
            source,
            '${dir.path}/out.aab',
            'aab',
            {'certificateSha256': '0' * 64},
            {
              'containerBase64': base64.encode(
                File('${dir.path}/store').readAsBytesSync(),
              ),
              'password': 'changeit',
              'alias': 'release',
            },
            dir,
            verifyIdentity: (_, __, ___) async {},
          ),
          throwsFormatException,
        );
        expect(File('${dir.path}/out.aab').existsSync(), false);
      });
    },
    timeout: const Timeout(Duration(minutes: 2)),
  );
}
