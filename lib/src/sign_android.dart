import 'dart:io';
import 'package:xml/xml.dart';
import 'core.dart';
import 'archive.dart';

Future<void> verifyAndroidIdentity(
  String path,
  String target,
  Json metadata, {
  Future<String> Function(List<String>)? execute,
}) async {
  final run = execute ?? tool;
  final expected = [
    metadata['applicationIdentifier'],
    '${metadata['buildNumber']}',
    metadata['versionName'],
  ];
  if (target == 'apk') {
    final output = await run(['aapt2', 'dump', 'badging', path]);
    final match = RegExp(
      r"package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'",
    ).firstMatch(output);
    require(
      match != null && same([match[1], match[2], match[3]], expected),
      'APK identity or version mismatch',
    );
  } else {
    final jar = Platform.environment['BUILDBOX_BUNDLETOOL_JAR'] ?? '',
        digest = Platform.environment['BUILDBOX_BUNDLETOOL_SHA256'];
    require(
      matches(digest, r'[0-9a-f]{64}') &&
          hashBytes(File(jar).readAsBytesSync()) == digest,
      'bundletool checksum mismatch',
    );
    final xml = XmlDocument.parse(
      await run([
        'java',
        '-jar',
        jar,
        'dump',
        'manifest',
        '--bundle=$path',
        '--module=base',
      ]),
    ).rootElement;
    const ns = 'http://schemas.android.com/apk/res/android';
    require(
      same([
        xml.getAttribute('package'),
        xml.getAttribute('versionCode', namespace: ns),
        xml.getAttribute('versionName', namespace: ns),
      ], expected),
      'AAB identity or version mismatch',
    );
  }
}

Future<void> signAndroidOne(
  String source,
  String destination,
  String target,
  Json metadata,
  Json material,
  Directory private, {
  Future<void> Function(String, String, Json)? verifyIdentity,
}) async {
  checkedZip(source);
  final verify = verifyIdentity ?? verifyAndroidIdentity;
  await verify(source, target, metadata);
  final keystore = await privateFile(
    '${private.path}/keystore',
    decodeMaterial(material['containerBase64']),
  );
  final env = {
    ...Platform.environment,
    'SIGN_STORE_PASSWORD': material['password'] as String,
    'SIGN_KEY_PASSWORD':
        (material['keyPassword'] ?? material['password']) as String,
  };
  final expected = (metadata['certificateSha256'] as String).toLowerCase();
  require(matches(expected, r'[0-9a-f]{64}'), 'invalid expected certificate');
  final cert = File('${private.path}/certificate.pem')
    ..writeAsStringSync(
      await tool([
        'keytool',
        '-exportcert',
        '-rfc',
        '-keystore',
        keystore.path,
        '-storepass:env',
        'SIGN_STORE_PASSWORD',
        '-alias',
        material['alias'] as String,
      ], environment: env),
    );
  await tool(['openssl', 'x509', '-in', cert.path, '-checkend', '0', '-noout']);
  final text = await tool([
    'openssl',
    'x509',
    '-in',
    cert.path,
    '-text',
    '-noout',
  ]);
  final algorithm = RegExp(
    r'Public Key Algorithm:\s*(\S+)',
  ).firstMatch(text)?[1];
  final signature = {
    'rsaEncryption': 'SHA256withRSA',
    'id-ecPublicKey': 'SHA256withECDSA',
  }[algorithm];
  require(signature != null, 'unsupported signing key algorithm');
  if (target == 'apk') {
    final aligned = '${private.path}/aligned.apk';
    await tool(['zipalign', '-p', '-f', '4', source, aligned]);
    await tool([
      'apksigner',
      'sign',
      '--ks',
      keystore.path,
      '--ks-key-alias',
      material['alias'] as String,
      '--ks-pass',
      'env:SIGN_STORE_PASSWORD',
      '--key-pass',
      'env:SIGN_KEY_PASSWORD',
      '--out',
      destination,
      aligned,
    ], environment: env);
    await tool(['zipalign', '-c', '-p', '4', destination]);
    final output = await tool([
      'apksigner',
      'verify',
      '--verbose',
      '--print-certs',
      destination,
    ]);
    final fingerprints = RegExp(
      r'Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]+)',
    ).allMatches(output).map((m) => m[1]!.toLowerCase()).toList();
    require(same(fingerprints, [expected]), 'APK certificate mismatch');
  } else {
    await tool([
      'jarsigner',
      '-keystore',
      keystore.path,
      '-storepass:env',
      'SIGN_STORE_PASSWORD',
      '-keypass:env',
      'SIGN_KEY_PASSWORD',
      '-sigalg',
      signature!,
      '-digestalg',
      'SHA-256',
      '-signedjar',
      destination,
      source,
      material['alias'] as String,
    ], environment: env);
    await tool([
      'jarsigner',
      '-verify',
      '-strict',
      '-keystore',
      keystore.path,
      '-storepass:env',
      'SIGN_STORE_PASSWORD',
      destination,
    ], environment: env);
    final output = await tool([
      'keytool',
      '-J-Duser.language=en',
      '-printcert',
      '-jarfile',
      destination,
    ]);
    final fingerprints = RegExp(
      r'SHA256:\s*([0-9A-Fa-f:]+)',
    ).allMatches(output).map((m) => m[1]!.replaceAll(':', '').toLowerCase());
    require(
      fingerprints.isNotEmpty && fingerprints.every((f) => f == expected),
      'AAB certificate mismatch',
    );
  }
  await verify(destination, target, metadata);
}

Future<void> signAndroid() async {
  final state = Platform.environment['BUILDBOX_STATE_DIR'] ?? '/tmp/buildbox',
      id = Platform.environment['BUILDBOX_RUN_ID'];
  require(matches(id, r'[1-9][0-9]*'), 'invalid platform run');
  for (final name in ['uploads.json', 'spec-response.json']) {
    require(
      !File('$state/$name').existsSync(),
      'sign runner contains upload authorization',
    );
  }
  final response =
          await request('/api/v1/buildbox/runs/$id/signing-material') as Json,
      m = response['metadata'] as Json,
      material = response['material'] as Json;
  require(
    m['platform'] == 'android' && m['runId'] == id,
    'Android signing scope mismatch',
  );
  final targets = (m['targets'] as List).cast<String>();
  final sorted = targets.toSet().toList()..sort();
  require(
    targets.isNotEmpty &&
        same(targets, sorted) &&
        targets.every(['apk', 'aab'].contains),
    'invalid signing targets',
  );
  final artifacts = <Json>[];
  await temporary('android-sign-', (private) async {
    final output = Directory('$state/artifacts')..createSync();
    for (final target in targets) {
      final destination = '${output.path}/swan-release.$target';
      require(
        FileSystemEntity.typeSync(destination, followLinks: false) ==
            FileSystemEntityType.notFound,
        'sign output exists',
      );
      await signAndroidOne(
        '$state/unsigned/swan-release.$target',
        destination,
        target,
        m,
        material,
        private,
      );
      final file = File(destination),
          digest = hashBytes(File(destination).readAsBytesSync()),
          size = File(destination).lengthSync();
      await request('/api/v1/buildbox/runs/$id/signing-proofs', {
        'target': target,
        'signingVersionId': m['versionId'],
        'certificateSha256': m['certificateSha256'],
        'sha256': digest,
        'byteSize': size,
      });
      artifacts.add({
        'target': target,
        'fileName': file.uri.pathSegments.last,
        'sha256': 'sha256:$digest',
        'byteSize': size,
        'signMode': 'signed',
      });
    }
  });
  writeJson('$state/artifacts.json', artifacts);
  writeJson('$state/sign-proof.json', {
    'signer': 'android-tools',
    'runId': id,
    'specHash': m['specHash'],
    'signingVersionId': m['versionId'],
    'artifacts': artifacts,
  });
}
