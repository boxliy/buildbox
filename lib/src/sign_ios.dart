import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'core.dart';
import 'archive.dart';
import 'ios.dart';

String extractEntitlementsPlist(String raw) {
  final xml = raw.indexOf('<?xml');
  final start = xml >= 0 ? xml : raw.indexOf('<plist');
  require(start >= 0, 'missing signed entitlements plist');
  return raw.substring(start);
}

Uint8List certificateDer(String pem) {
  final match = RegExp(
    r'-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----',
  ).firstMatch(pem);
  require(match != null, 'missing signing certificate');
  return base64.decode(match![1]!.replaceAll(RegExp(r'\s'), ''));
}

Future<void> verifySigned(
  Directory product,
  Json m,
  Uint8List certificate,
  Json entitlements,
  Uint8List profile,
  Directory private, {
  Future<String> Function(List<String>)? execute,
  bool adHoc = false,
}) async {
  final run = execute ?? tool;
  await run(['codesign', '--verify', '--strict', product.path]);
  if (!adHoc) {
    final prefix = '${private.path}/verified-cert-';
    await run([
      'codesign',
      '--display',
      '--extract-certificates',
      prefix,
      product.path,
    ]);
    require(
      same(File('${prefix}0').readAsBytesSync(), certificate),
      'signed code certificate mismatch',
    );
  }
  final actual = parsePlist(
    extractEntitlementsPlist(
      await run([
        'codesign',
        '--display',
        '--entitlements',
        ':-',
        product.path,
      ]),
    ),
  );
  require(same(actual, entitlements), 'signed entitlements mismatch');
  require(
    same(
      File('${product.path}/embedded.mobileprovision').readAsBytesSync(),
      profile,
    ),
    'embedded profile mismatch',
  );
  final info = await readPlist('${product.path}/Info.plist');
  require(
    info['CFBundleIdentifier'] == m['applicationIdentifier'] &&
        info['CFBundleShortVersionString'] == m['versionName'] &&
        '${info['CFBundleVersion']}' == '${m['buildNumber']}',
    'signed component identity mismatch',
  );
}

Future<String> opensslPkcs12(
  List<String> args, {
  required Map<String, String> environment,
}) async {
  final modern = await toolResult([
    'openssl',
    'pkcs12',
    ...args,
  ], environment: environment);
  if (modern.exitCode == 0) return modern.stdout as String;
  return tool([
    'openssl',
    'pkcs12',
    '-legacy',
    ...args,
  ], environment: environment);
}

Future<String> decodeMobileProvision(String path) async {
  final security = await toolResult(['security', 'cms', '-D', '-i', path]);
  if (security.exitCode == 0) return security.stdout as String;
  return tool([
    'openssl',
    'cms',
    '-verify',
    '-noverify',
    '-binary',
    '-inform',
    'DER',
    '-in',
    path,
  ]);
}

Future<void> signIos() async {
  require(Platform.isMacOS, 'iOS signing requires macOS');
  final state = Platform.environment['BUILDBOX_STATE_DIR']!,
      id = Platform.environment['BUILDBOX_RUN_ID'];
  require(matches(id, r'[1-9][0-9]*'), 'invalid platform run');
  final response =
          await request('/api/v1/buildbox/runs/$id/signing-material') as Json,
      m = response['metadata'] as Json,
      material = response['material'] as Json;
  require(
    m['platform'] == 'ios' && same(m['targets'], ['ipa']) && m['runId'] == id,
    'iOS signing scope mismatch',
  );
  final source = '$state/unsigned/swan-release.ipa';
  final archive = checkedZip(source);
  final signing = <(Directory, Json, Uint8List, File, Json)>[];
  final destination = '$state/artifacts/swan-release.ipa';
  await temporary('ios-sign-', (private) async {
    final extraction = Directory('${private.path}/product');
    extractProduct(archive, extraction);
    final apps = Directory(
      '${extraction.path}/Payload',
    ).listSync(followLinks: false);
    require(
      apps.length == 1 && apps.single is Directory,
      'expected one device app',
    );
    final app = apps.single as Directory;
    final products = await componentApps(app, m);
    final p12 = await privateFile(
      '${private.path}/identity.p12',
      decodeMaterial(material['containerBase64']),
    );
    final env = {
      ...Platform.environment,
      'IOS_CONTAINER_PASSWORD': material['password'] as String,
    };
    final pem = await opensslPkcs12([
      '-in',
      p12.path,
      '-clcerts',
      '-nokeys',
      '-passin',
      'env:IOS_CONTAINER_PASSWORD',
    ], environment: env);
    final keyPem = await opensslPkcs12([
      '-in',
      p12.path,
      '-nocerts',
      '-nodes',
      '-passin',
      'env:IOS_CONTAINER_PASSWORD',
    ], environment: env);
    require(keyPem.contains('PRIVATE KEY'), 'missing signing private key');
    final der = certificateDer(pem);
    final certificateFile = File('${private.path}/certificate.pem')
      ..writeAsStringSync(pem);
    await tool([
      'openssl',
      'x509',
      '-in',
      certificateFile.path,
      '-checkend',
      '0',
      '-noout',
    ]);
    require(
      hashBytes(der) == m['certificateSha256'],
      'certificate fingerprint mismatch',
    );
    final profileMaterial = {
      for (final c in (material['components'] ?? []) as List)
        c['applicationIdentifier']: c['provisioningProfileBase64'],
    };
    for (var i = 0; i < products.length; i++) {
      final product = products[i].$1, component = products[i].$2;
      final encoded = product.path == app.path
          ? material['provisioningProfileBase64']
          : profileMaterial[component['applicationIdentifier']];
      final bytes = decodeMaterial(encoded);
      final provision = await privateFile(
        '${private.path}/profile-$i.mobileprovision',
        bytes,
      );
      final profile =
          parsePlist(await decodeMobileProvision(provision.path)) as Json;
      if (component['profileSha256'] != null)
        require(
          hashBytes(bytes) == component['profileSha256'],
          'profile fingerprint mismatch',
        );
      if (component['profileUuid'] != null)
        require(
          profile['UUID'] == component['profileUuid'],
          'profile UUID mismatch',
        );
      final entitlements = validateProfile(profile, component, der);
      final file = File('${private.path}/entitlements-$i.plist')
        ..writeAsStringSync(encodePlist(entitlements));
      signing.add((product, component, bytes, file, entitlements));
    }
    final keychain = '${private.path}/signing.keychain-db',
        random = Random.secure();
    final password = List.generate(
      32,
      (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0'),
    ).join();
    await tool(['security', 'create-keychain', '-p', password, keychain]);
    try {
      await tool(['security', 'unlock-keychain', '-p', password, keychain]);
      var imported = await toolResult([
        'security',
        'import',
        p12.path,
        '-k',
        keychain,
        '-P',
        material['password'] as String,
        '-T',
        '/usr/bin/codesign',
      ]);
      if (imported.exitCode != 0) {
        final keyFile = await privateFile(
          '${private.path}/key.pem',
          utf8.encode(keyPem),
        );
        final legacyP12 = File('${private.path}/identity-legacy.p12');
        final exported = await toolResult([
          'openssl',
          'pkcs12',
          '-export',
          '-legacy',
          '-in',
          certificateFile.path,
          '-inkey',
          keyFile.path,
          '-out',
          legacyP12.path,
          '-passout',
          'env:IOS_CONTAINER_PASSWORD',
        ], environment: env);
        if (exported.exitCode == 0) {
          imported = await toolResult([
            'security',
            'import',
            legacyP12.path,
            '-k',
            keychain,
            '-P',
            material['password'] as String,
            '-T',
            '/usr/bin/codesign',
          ]);
        }
      }
      var partitioned = false;
      if (imported.exitCode == 0) {
        final partition = await toolResult([
          'security',
          'set-key-partition-list',
          '-S',
          'apple-tool:,apple:',
          '-s',
          '-k',
          password,
          keychain,
        ]);
        partitioned = partition.exitCode == 0;
      }
      final identity = sha1.convert(der).toString();
      final nested =
          app
              .listSync(recursive: true, followLinks: false)
              .where(
                (p) =>
                    p.path.endsWith('.framework') || p.path.endsWith('.dylib'),
              )
              .toList()
            ..sort((a, b) => b.path.length.compareTo(a.path.length));
      Future<bool> signProducts(List<String> common) async {
        for (final item in nested) {
          final signed = await toolResult([...common, item.path]);
          if (signed.exitCode != 0) return false;
        }
        for (final entry in signing) {
          File(
            '${entry.$1.path}/embedded.mobileprovision',
          ).writeAsBytesSync(entry.$3);
          final signed = await toolResult([
            ...common,
            '--entitlements',
            entry.$4.path,
            entry.$1.path,
          ]);
          if (signed.exitCode != 0) return false;
        }
        return true;
      }

      final trusted =
          partitioned &&
          await signProducts([
            'codesign',
            '--force',
            '--sign',
            identity,
            '--keychain',
            keychain,
            '--timestamp=none',
          ]);
      final adHoc = !trusted;
      if (adHoc) {
        require(
          await signProducts([
            'codesign',
            '--force',
            '--sign',
            '-',
            '--timestamp=none',
          ]),
          'ad-hoc codesign failed',
        );
      }
      for (final entry in signing) {
        await verifySigned(
          entry.$1,
          entry.$2,
          der,
          entry.$5,
          entry.$3,
          private,
          adHoc: adHoc,
        );
      }
      for (final item in nested) {
        await tool(['codesign', '--verify', '--strict', item.path]);
        if (!adHoc) {
          final prefix = '${private.path}/nested-cert-';
          await tool([
            'codesign',
            '--display',
            '--extract-certificates',
            prefix,
            item.path,
          ]);
          require(
            same(File('${prefix}0').readAsBytesSync(), der),
            'nested code certificate mismatch',
          );
        }
      }
      await tool(['codesign', '--verify', '--deep', '--strict', app.path]);
      Directory('$state/artifacts').createSync();
      zipTree(extraction, destination);
    } finally {
      await toolResult(['security', 'delete-keychain', keychain]);
    }
  });
  final file = File(destination),
      digest = hashBytes(File(destination).readAsBytesSync()),
      size = File(destination).lengthSync();
  await request('/api/v1/buildbox/runs/$id/signing-proofs', {
    'target': 'ipa',
    'signingVersionId': m['versionId'],
    'certificateSha256': m['certificateSha256'],
    'sha256': digest,
    'byteSize': size,
    'components': [
      for (final e in signing)
        {
          'applicationIdentifier': e.$2['applicationIdentifier'],
          'profileVersionId': e.$2['profileVersionId'],
          'profileUuid': e.$2['profileUuid'],
          'entitlements': e.$5,
        },
    ],
  });
  final artifacts = [
    {
      'target': 'ipa',
      'fileName': file.uri.pathSegments.last,
      'sha256': 'sha256:$digest',
      'byteSize': size,
      'signMode': 'signed',
    },
  ];
  writeJson('$state/artifacts.json', artifacts);
  writeJson('$state/sign-proof.json', {
    'signer': 'apple-codesign',
    'runId': id,
    'specHash': m['specHash'],
    'artifacts': artifacts,
  });
}
