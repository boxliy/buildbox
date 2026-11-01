import 'dart:io';
import 'dart:convert';
import 'package:archive/archive.dart';
import 'core.dart';

const maxArtifactBytes = 512 * 1024 * 1024;
Archive checkedZip(
  String path, {
  bool unsigned = true,
  int maxBytes = maxArtifactBytes,
  int maxEntries = 100000,
  int? maxExpanded,
}) {
  require(
    FileSystemEntity.typeSync(path, followLinks: false) ==
        FileSystemEntityType.file,
    'invalid artifact file',
  );
  final file = File(path);
  require(
    file.lengthSync() > 0 && file.lengthSync() <= maxBytes,
    'artifact size limit',
  );
  // Read directory metadata first, before decompressing any entry.
  final input = InputFileStream(path);
  try {
    final directory = ZipDirectory()..read(input);
    final names = <String>{};
    var expanded = 0;
    for (final entry in directory.fileHeaders) {
      final name = entry.filename;
      final normalized = name.endsWith('/')
          ? name.substring(0, name.length - 1)
          : name;
      final mode = (entry.externalFileAttributes >> 16) & 0xf000;
      require(
        name.isNotEmpty &&
            !name.startsWith('/') &&
            !name.contains('\\') &&
            !normalized
                .split('/')
                .any((p) => p.isEmpty || p == '.' || p == '..') &&
            names.add(normalized) &&
            [0, 0x8000, 0x4000].contains(mode) &&
            (entry.generalPurposeBitFlag & 1) == 0,
        'unsafe archive entry',
      );
      expanded += entry.uncompressedSize;
      require(
        expanded <= (maxExpanded ?? 2 * maxBytes) && names.length <= maxEntries,
        'archive expansion limit',
      );
      final upper = name.toUpperCase();
      require(
        !unsigned ||
            !upper.startsWith('META-INF/') ||
            !RegExp(r'\.(SF|RSA|DSA|EC)$').hasMatch(upper),
        'refusing already-signed artifact',
      );
    }
  } finally {
    input.closeSync();
  }
  if (unsigned) {
    final stream = file.openSync();
    try {
      var previous = <int>[];
      while (true) {
        final bytes = stream.readSync(1024 * 1024);
        if (bytes.isEmpty) break;
        final joined = [...previous, ...bytes];
        require(
          !latin1.decode(joined).contains('APK Sig Block 42'),
          'refusing signed APK',
        );
        previous = bytes
            .skip(bytes.length > 16 ? bytes.length - 16 : 0)
            .toList();
      }
    } finally {
      stream.closeSync();
    }
  }
  // Keep the bounded compressed bytes alive for the decoder's lazy entries;
  // closing a file-backed stream here would invalidate extraction later.
  return ZipDecoder().decodeBytes(file.readAsBytesSync(), verify: true);
}

String signingState(String path) {
  final zip = checkedZip(path, unsigned: false);
  final names = zip.map((e) => e.name.toUpperCase()).toList();
  if (names.any((n) => '/$n'.contains('/ANDROIDD.'))) return 'debug';
  if (names.any(
    (n) =>
        n.startsWith('META-INF/') && RegExp(r'\.(SF|RSA|DSA|EC)$').hasMatch(n),
  ))
    return 'signed';
  return 'unsigned';
}

void extractProduct(Archive archive, Directory destination) {
  destination.createSync();
  for (final entry in archive) {
    final parts = entry.name.split('/');
    require(
      parts.length >= 2 && parts[0] == 'Payload' && parts[1].endsWith('.app'),
      'unexpected archive layout',
    );
    final path = '${destination.path}/${entry.name}';
    if (entry.isFile) {
      final file = File(path);
      file.parent.createSync(recursive: true);
      file.writeAsBytesSync(entry.content);
      if (entry.mode & 0x49 != 0) Process.runSync('chmod', ['700', path]);
    } else {
      Directory(path).createSync(recursive: true);
    }
  }
}

void zipTree(Directory root, String output, {String prefix = ''}) {
  require(
    !File(output).existsSync() && !Link(output).existsSync(),
    'output exists',
  );
  final archive = Archive();
  final entries = root.listSync(recursive: true, followLinks: false).toList()
    ..sort((a, b) => a.path.compareTo(b.path));
  for (final entry in entries) {
    require(entry is! Link, 'symlink in unsigned transport');
    if (entry is File) {
      final relative = entry.path.substring(root.path.length + 1);
      final bytes = entry.readAsBytesSync();
      archive.addFile(
        ArchiveFile('$prefix$relative', bytes.length, bytes)
          ..mode = entry.statSync().mode,
      );
    }
  }
  final stream = OutputFileStream(output);
  try {
    ZipEncoder().encodeStream(archive, stream);
  } finally {
    stream.closeSync();
  }
}
