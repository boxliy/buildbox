import 'dart:convert';
import 'dart:io';
import 'package:test/test.dart';
import 'package:buildbox_tools/src/core.dart';
import 'package:buildbox_tools/src/spec.dart';
import 'package:buildbox_tools/src/source_catalog.dart';
import 'fixtures.dart';

Future<void> sourceFixture(
  Future<void> Function(Directory, String, Json) check,
) async {
  await temporary('catalog-contract-', (root) async {
    final checkout = Directory('${root.path}/source')..createSync();
    final lock = File('${checkout.path}/waterfowl/pubspec.lock')
      ..parent.createSync(recursive: true);
    lock.writeAsStringSync('frozen dependency lockfile\n');
    final c = nativeSpec(), catalog = c['assembly']['catalog'] as Json;
    catalog['lockfileDigest'] = 'sha256:${hashBytes(lock.readAsBytesSync())}';
    final bin = Directory('${checkout.path}/waterfowl/tools/swan_build/bin')
      ..createSync(recursive: true);
    File('${bin.path}/export_catalog.dart').writeAsStringSync(
      "import 'dart:convert';void main(List<String> args){final catalog=jsonDecode(r'''${jsonEncode(catalog)}''') as Map<String,dynamic>;catalog['sourceCommit']=args[args.indexOf('--revision')+1];print(jsonEncode({'catalog':catalog}));}",
    );
    await tool(['git', '-C', checkout.path, 'init', '--quiet']);
    await tool(['git', '-C', checkout.path, 'add', '.']);
    await tool([
      'git',
      '-C',
      checkout.path,
      '-c',
      'user.name=Buildbox Fixture',
      '-c',
      'user.email=fixture@example.invalid',
      '-c',
      'commit.gpgsign=false',
      'commit',
      '--quiet',
      '-m',
      'fixture',
    ]);
    final commit = (await tool([
      'git',
      '-C',
      checkout.path,
      'rev-parse',
      'HEAD',
    ])).trim();
    c['commitSha'] = commit;
    c['frozenInputs']['commitSha'] = commit;
    catalog['sourceCommit'] = commit;
    c['assembly']['catalogDigest'] = hashJson(catalog);
    final spec = <String, dynamic>{'config': c, 'specHash': specDigest(c)},
        path = '${root.path}/spec.json';
    writeJson(path, spec);
    await check(checkout, path, spec);
  });
}

void main() {
  final aviaryCheckout = Platform.environment['BUILDBOX_AVIARY_CHECKOUT'];
  test(
    'real committed Aviary exporter survives private tar handoff and rejects catalog tampering',
    () async {
      await temporary('real-source-contract-', (root) async {
        final source = Directory('${root.path}/source')..createSync();
        final commit = (await tool([
          'git',
          '-C',
          aviaryCheckout!,
          'rev-parse',
          'HEAD',
        ])).trim();
        await tool(['git', '-C', source.path, 'init', '--quiet']);
        await tool([
          'git',
          '-C',
          source.path,
          'fetch',
          '--depth=1',
          aviaryCheckout,
          commit,
        ]);
        await tool([
          'git',
          '-C',
          source.path,
          'checkout',
          '--detach',
          'FETCH_HEAD',
        ]);
        final package = '${source.path}/waterfowl/tools/swan_build';
        final resolve = await Process.run(Platform.resolvedExecutable, [
          'pub',
          'get',
          '--enforce-lockfile',
        ], workingDirectory: package);
        expect(resolve.exitCode, 0, reason: '${resolve.stderr}');
        final exported =
            strictJson(
                  await tool([
                    Platform.resolvedExecutable,
                    'run',
                    '$package/bin/export_catalog.dart',
                    '--repo',
                    source.path,
                    '--revision',
                    commit,
                  ]),
                )
                as Json;
        final config = nativeSpec();
        config['commitSha'] = commit;
        config['frozenInputs']['commitSha'] = commit;
        config['frozenInputs']['flutterVersion'] =
            exported['catalog']['flutterVersion'];
        config['assembly']['catalog'] = exported['catalog'];
        config['assembly']['catalogDigest'] = exported['digest'];
        final spec = <String, dynamic>{
              'config': config,
              'specHash': specDigest(config),
            },
            specPath = '${root.path}/spec.json';
        writeJson(specPath, spec);
        final archive = '${root.path}/source.tar';
        await tool(['tar', '-cf', archive, '-C', root.path, 'source']);
        source.renameSync('${root.path}/prepare-unavailable');
        final restore = Directory('${root.path}/compile')..createSync();
        await tool(['tar', '-xf', archive, '-C', restore.path]);
        await verifySourceCatalog(specPath, '${restore.path}/source');
        config['assembly']['catalog']['lockfileDigest'] = 'sha256:${'0' * 64}';
        config['assembly']['catalogDigest'] = hashJson(
          config['assembly']['catalog'],
        );
        spec['specHash'] = specDigest(config);
        writeJson(specPath, spec);
        await expectLater(
          verifySourceCatalog(specPath, '${restore.path}/source'),
          throwsA(anything),
        );
      });
    },
    skip: aviaryCheckout == null
        ? 'Set BUILDBOX_AVIARY_CHECKOUT to a committed Dart-migrated Aviary checkout'
        : false,
    timeout: const Timeout(Duration(minutes: 3)),
  );
  test(
    'workflow tar transport preserves self-contained committed source at a new path',
    () async {
      await sourceFixture((checkout, path, _) async {
        final root = checkout.parent;
        final archive = '${root.path}/source.tar';
        await tool(['tar', '-cf', archive, '-C', root.path, 'source']);
        checkout.renameSync('${root.path}/old-source');
        final restored = Directory('${root.path}/restored')..createSync();
        await tool(['tar', '-xf', archive, '-C', restored.path]);
        await verifySourceCatalog(path, '${restored.path}/source');
        Directory(
          '${restored.path}/source/.git',
        ).renameSync('${restored.path}/source/git-unavailable');
        await expectLater(
          verifySourceCatalog(path, '${restored.path}/source'),
          throwsA(anything),
        );
      });
    },
  );
  test(
    'frozen catalog re-export and lockfile pass on credential-free source runner',
    () async {
      await sourceFixture((checkout, path, _) async {
        await verifySourceCatalog(path, checkout.path);
      });
    },
  );
  test(
    'rehashing tampered catalog does not bypass exact source exporter comparison',
    () async {
      await sourceFixture((checkout, path, spec) async {
        spec['config']['assembly']['catalog']['presentations'][0]['presentation'] =
            'FORGED';
        spec['config']['assembly']['catalogDigest'] = hashJson(
          spec['config']['assembly']['catalog'],
        );
        spec['specHash'] = specDigest(spec['config'] as Json);
        writeJson(path, spec);
        await expectLater(
          verifySourceCatalog(path, checkout.path),
          throwsA(anything),
        );
      });
    },
  );
  test('wrong checkout commit fails before source exporter executes', () async {
    await sourceFixture((checkout, path, spec) async {
      spec['config']['commitSha'] = 'b' * 40;
      spec['config']['frozenInputs']['commitSha'] = 'b' * 40;
      spec['config']['assembly']['catalog']['sourceCommit'] = 'b' * 40;
      spec['config']['assembly']['catalogDigest'] = hashJson(
        spec['config']['assembly']['catalog'],
      );
      spec['specHash'] = specDigest(spec['config'] as Json);
      writeJson(path, spec);
      File(
        '${checkout.path}/waterfowl/tools/swan_build/bin/export_catalog.dart',
      ).writeAsStringSync(
        "import 'dart:io';void main(){File('${checkout.path}/MUST_NOT_RUN').writeAsStringSync('ran');}",
      );
      await expectLater(
        verifySourceCatalog(path, checkout.path),
        throwsFormatException,
      );
      expect(File('${checkout.path}/MUST_NOT_RUN').existsSync(), false);
    });
  });
  test('working dependency lockfile drift fails frozen digest', () async {
    await sourceFixture((checkout, path, _) async {
      File(
        '${checkout.path}/waterfowl/pubspec.lock',
      ).writeAsStringSync('modified');
      await expectLater(
        verifySourceCatalog(path, checkout.path),
        throwsFormatException,
      );
    });
  });
  test('modified prepared spec hash fails before exporter execution', () async {
    await sourceFixture((checkout, path, spec) async {
      spec['config']['appDisplayName'] = 'tamper';
      writeJson(path, spec);
      await expectLater(
        verifySourceCatalog(path, checkout.path),
        throwsFormatException,
      );
    });
  });
}
