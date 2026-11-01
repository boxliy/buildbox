import 'dart:io';
import 'package:archive/archive.dart';
import 'package:buildbox_tools/src/core.dart';
import 'package:buildbox_tools/src/spec.dart';

void main(List<String> args) {
  switch (args.first) {
    case 'rehash':
      final spec = readJson(args[1]);
      spec['specHash'] = specDigest(spec['config'] as Json);
      writeJson(args[1], spec);
    case 'zip':
      final path = args[1], payload = args[2], kind = args[3];
      final archive = Archive()
        ..addFile(ArchiveFile.string('AndroidManifest.xml', payload));
      if (kind == 'debug') {
        archive.addFile(ArchiveFile.string('META-INF/ANDROIDD.SF', 'debug'));
        archive.addFile(ArchiveFile.string('META-INF/ANDROIDD.RSA', 'debug'));
      } else if (kind == 'signed') {
        archive.addFile(ArchiveFile.string('META-INF/CERT.SF', 'signed'));
        archive.addFile(ArchiveFile.string('META-INF/CERT.RSA', 'signed'));
      }
      File(path).writeAsBytesSync(ZipEncoder().encode(archive));
    case 'fixtures':
      for (final name in ['apk', 'aab']) {
        final path = 'tests/fixtures/build-spec-$name.json',
            spec = readJson(path),
            c = spec['config'] as Json,
            native =
                readJson('tests/fixtures/build_spec_v2_identity.json')['input']
                    as Json;
        c.remove('releaseId');
        c['schemaVersion'] = 2;
        c['platform'] = 'android';
        c['frozenInputs']['builtinResources'] = [];
        c['frozenInputs']['languages'] = [];
        c['assembly'] = native['assembly'];
        c['assembly']['catalog']['sourceCommit'] = c['commitSha'];
        c['assembly']['catalog']['lockfileDigest'] =
            'sha256:${hashBytes('fixture\n'.codeUnits)}';
        c['assembly']['catalogDigest'] = hashJson(c['assembly']['catalog']);
        c['dartDefines']['SWAN_INTERNAL_BUILD'] = 'false';
        spec['specHash'] = specDigest(c);
        writeJson(path, spec);
      }
    case 'stub-source':
      final root = args[1],
          bin = Directory('$root/waterfowl/tools/swan_build/bin')
            ..createSync(recursive: true);
      final config =
          readJson('tests/fixtures/build-spec-apk.json')['config'] as Json;
      final catalog = config['assembly']['catalog'];
      File('${bin.path}/export_catalog.dart').writeAsStringSync(
        "import 'dart:convert';\nvoid main(List<String> args){final catalog=jsonDecode(r'''${canonical(catalog)}''') as Map<String,dynamic>;catalog['sourceCommit']=args[args.indexOf('--revision')+1];print(jsonEncode({'catalog':catalog}));}\n",
      );
      File(
        '${bin.path}/assemble.dart',
      ).writeAsStringSync('void main(List<String> args) {}\n');
    default:
      throw ArgumentError('unknown support command');
  }
}
