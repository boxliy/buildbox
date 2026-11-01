import 'dart:convert';
import 'dart:io';
import 'package:archive/archive.dart';
import 'package:test/test.dart';
import 'package:buildbox_tools/src/core.dart';
import 'package:buildbox_tools/src/archive.dart';
import 'package:buildbox_tools/src/material_common.dart';
import 'package:buildbox_tools/src/material_validation.dart';
import 'fixtures.dart';

void main() {
  test('scope rejects other stage platform and material kind', () {
    for (final mutation in <void Function(Json)>[
      (r) => r['scope']['stage'] = 'sign',
      (r) => r['scope']['kind'] = 'apple_certificate',
      (r) => r['scope']['platform'] = 'ios',
      (r) => r['scope']['validationId'] = '../task',
    ]) {
      final request = androidRequest('/unused');
      mutation(request);
      expect(
        () => authorizeValidation(request),
        throwsA(isA<ValidationFailure>()),
      );
    }
  });
  test('passwords and aliases are bounded and path-safe', () {
    for (final password in ['', null, 'a' * 257, 'secret\x00']) {
      expect(
        () => boundedPassword(password),
        throwsA(isA<ValidationFailure>()),
      );
    }
    for (final name in ['../a', 'a/b', r'a\b', '.', '..', 'a\x00']) {
      expect(() => safeName(name), throwsA(isA<ValidationFailure>()));
    }
  });
  test(
    'material path refuses symlinks, directories, empty, oversized files',
    () async {
      await temporary('test-limits-', (dir) async {
        final file = File('${dir.path}/material')..writeAsStringSync('x');
        final link = Link('${dir.path}/link')..createSync(file.path);
        expect(
          () => materialBytes({'path': link.path}),
          throwsA(isA<ValidationFailure>()),
        );
        expect(
          () => materialBytes({'path': dir.path}),
          throwsA(isA<ValidationFailure>()),
        );
        file.writeAsStringSync('');
        expect(
          () => materialBytes({'path': file.path}),
          throwsA(isA<ValidationFailure>()),
        );
        file.writeAsBytesSync(List.filled(2 * 1024 * 1024 + 1, 0));
        expect(
          () => materialBytes({'path': file.path}),
          throwsA(isA<ValidationFailure>()),
        );
      });
    },
  );
  test(
    'zip slip duplicate symlink signature blocks and excessive expansion reject',
    () async {
      await temporary('test-zips-', (dir) async {
        for (final name in [
          '../escape',
          '/absolute',
          'a/../b',
          'a\\b',
          'a//b',
          './a',
        ]) {
          final path = '${dir.path}/input.zip',
              archive = Archive()..addFile(ArchiveFile(name, 1, [0]));
          final encoded = ZipEncoder().encode(archive);
          if (name == 'a\\b') {
            // ZipEncoder normalizes separators; corrupt both stored names to
            // exercise an actual hostile archive rather than its safe output.
            for (var i = 0; i < encoded.length - 2; i++) {
              if (encoded[i] == 97 &&
                  encoded[i + 1] == 47 &&
                  encoded[i + 2] == 98) {
                encoded[i + 1] = 92;
              }
            }
          }
          File(path).writeAsBytesSync(encoded);
          expect(() => checkedZip(path), throwsA(anything), reason: name);
        }
        final symlink = ArchiveFile('link', 1, [0])..mode = 0xa1ff;
        File(
          '${dir.path}/link.zip',
        ).writeAsBytesSync(ZipEncoder().encode(Archive()..addFile(symlink)));
        expect(() => checkedZip('${dir.path}/link.zip'), throwsA(anything));
        final zip = Archive()..addFile(ArchiveFile('payload', 1, [0]));
        File(
          '${dir.path}/limit.zip',
        ).writeAsBytesSync(ZipEncoder().encode(zip));
        expect(
          () => checkedZip('${dir.path}/limit.zip', maxExpanded: 0),
          throwsFormatException,
        );
        final signed = Archive()
          ..addFile(ArchiveFile.string('META-INF/CERT.SF', 'signature'));
        File(
          '${dir.path}/signed.zip',
        ).writeAsBytesSync(ZipEncoder().encode(signed));
        expect(
          () => checkedZip('${dir.path}/signed.zip'),
          throwsFormatException,
        );
        expect(signingState('${dir.path}/signed.zip'), 'signed');
        final block = Archive()
          ..addFile(ArchiveFile.string('payload', 'APK Sig Block 42'));
        File(
          '${dir.path}/block.zip',
        ).writeAsBytesSync(ZipEncoder().encode(block, level: 0));
        expect(
          () => checkedZip('${dir.path}/block.zip'),
          throwsFormatException,
        );
      });
    },
  );
  test(
    'validator stdin failure omits secrets and preserves identity',
    () async {
      final request = androidRequest('/does/not/exist');
      request['material']['storePassword'] = 'MUST_NOT_LEAK';
      final result = await validateSafely(request);
      expect(result['status'], 'invalid');
      expect(result['scope']['validationId'], 'validation-1');
      expect(jsonEncode(result), isNot(contains('MUST_NOT_LEAK')));
      assertPublic(result);
    },
  );
  test('oversized stdin is rejected before JSON decoding', () async {
    final process = await Process.start(Platform.resolvedExecutable, [
      'run',
      'bin/buildbox.dart',
      'validate-material',
    ]);
    process.stdin.add(utf8.encode(' ' * (1024 * 1024 + 1)));
    await process.stdin.close();
    final out = await process.stdout.transform(utf8.decoder).join();
    await process.stderr.drain<void>();
    expect(await process.exitCode, 2);
    expect(jsonDecode(out)['reasonCodes'], ['size_limit']);
  });
}
