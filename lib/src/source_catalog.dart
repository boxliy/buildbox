import 'dart:io';
import 'core.dart';
import 'spec.dart';

Future<void> verifySourceCatalog(String specPath, String checkout) async {
  final spec = readJson(specPath),
      config = validateSpec(spec['config'] as Json);
  require(
    specDigest(config) == spec['specHash'],
    'prepared Spec digest mismatch',
  );
  final commit = (await tool([
    'git',
    '-C',
    checkout,
    'rev-parse',
    'HEAD',
  ])).trim();
  require(
    commit == config['commitSha'],
    'build checkout is not frozen source commit',
  );
  // Application-source code executes only in the credential-free compile job.
  // The source-owned tool resolves from its own lockfile, never this package.
  final output = await tool([
    Platform.resolvedExecutable,
    'run',
    '$checkout/waterfowl/tools/swan_build/bin/export_catalog.dart',
    '--repo',
    checkout,
    '--revision',
    commit,
  ]);
  final catalog = (strictJson(output) as Json)['catalog'];
  final assembly = config['assembly'] as Json;
  require(
    same(catalog, assembly['catalog']) &&
        hashJson(catalog) == assembly['catalogDigest'],
    'catalog differs from exact source commit',
  );
  require(
    'sha256:${hashBytes(File('$checkout/waterfowl/pubspec.lock').readAsBytesSync())}' ==
        catalog['lockfileDigest'],
    'dependency lockfile differs from frozen source',
  );
}
