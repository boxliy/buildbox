import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:buildbox_tools/src/core.dart';
import 'package:buildbox_tools/src/spec.dart';
import 'package:buildbox_tools/src/sign_android.dart';
import 'package:buildbox_tools/src/ios.dart';

Future<void> consume(Json value) async {
  final spec = value['spec'] as Json, metadata = value['metadata'] as Json;
  validateSpec(spec['config'] as Json);
  require(
    specDigest(spec['config'] as Json) == spec['specHash'],
    'cross-repository canonical hash mismatch',
  );
  if (metadata['platform'] == 'android') {
    final output =
        "package: name='${metadata['applicationIdentifier']}' versionCode='${metadata['buildNumber']}' versionName='${metadata['versionName']}'";
    await verifyAndroidIdentity(
      'fixture.apk',
      'apk',
      metadata,
      execute: (_) async => output,
    );
    var rejected = false;
    try {
      await verifyAndroidIdentity('fixture.apk', 'apk', {
        ...metadata,
        'buildNumber': 0,
      }, execute: (_) async => output);
    } on FormatException {
      rejected = true;
    }
    require(rejected, 'version override accepted');
    return;
  }
  await temporary('hawk-contract-', (dir) async {
    final app = Directory('${dir.path}/Runner.app');
    final entries = <(Directory, Json)>[
      (app, metadata),
      for (var i = 0; i < ((metadata['components'] ?? []) as List).length; i++)
        (
          Directory('${app.path}/PlugIns/$i.appex'),
          {
            ...metadata,
            ...metadata['components'][i] as Json,
            'deviceCapabilities':
                metadata['components'][i]['deviceCapabilities'] ?? [],
          },
        ),
    ];
    for (final (product, component) in entries) {
      product.createSync(recursive: true);
      File(
        '${product.path}/Runner',
      ).writeAsStringSync('fixture executable, not a real device build');
      File('${product.path}/Info.plist').writeAsStringSync(
        encodePlist({
          'CFBundleIdentifier': component['applicationIdentifier'],
          'CFBundleDisplayName': component['appDisplayName'],
          'CFBundleVersion': '${component['buildNumber']}',
          'CFBundleShortVersionString': component['versionName'],
          'CFBundleExecutable': 'Runner',
          'CFBundleSupportedPlatforms': ['iPhoneOS'],
        }),
      );
      await projectPrivacy(product, component);
      final method = metadata['distributionMethod'];
      final profile = <String, dynamic>{
        'UUID': component['profileUuid'],
        'TeamIdentifier': [metadata['teamId']],
        'DeveloperCertificates': [Uint8List.fromList('fixture'.codeUnits)],
        'ExpirationDate': DateTime.utc(2099, 1, 1),
        'Entitlements': {
          'application-identifier':
              '${metadata['teamId']}.${component['applicationIdentifier']}',
          'com.apple.developer.team-identifier': metadata['teamId'],
          'get-task-allow': method == 'development',
          if (((component['deviceCapabilities'] ?? []) as List).any(
            (v) => v['key'] == 'notifications.push',
          ))
            'aps-environment': method == 'development'
                ? 'development'
                : 'production',
        },
        if (['development', 'ad-hoc'].contains(method))
          'ProvisionedDevices': ['fixture device'],
        if (method == 'enterprise') 'ProvisionsAllDevices': true,
      };
      validateProfile(
        profile,
        component,
        Uint8List.fromList('fixture'.codeUnits),
      );
    }
    require(
      (await componentApps(app, metadata)).length == entries.length,
      'component coverage mismatch',
    );
  });
}

Future<void> main() async {
  try {
    await consume(
      strictJson(await stdin.transform(utf8.decoder).join()) as Json,
    );
    stdout.writeln(
      'Hawk Spec/hash and native signing consumer contract passed (fixture)',
    );
  } catch (e) {
    stderr.writeln(e);
    exitCode = 1;
  }
}
