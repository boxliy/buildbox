import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:buildbox_tools/src/core.dart';
import 'package:buildbox_tools/src/ios.dart';

Json metadata() => {
  'applicationIdentifier': 'com.example.swan',
  'versionName': '1.2.3',
  'buildNumber': 7,
  'appDisplayName': 'Tenant App',
  'teamId': 'ABCDEFGHIJ',
  'distributionMethod': 'ad-hoc',
  'source': 'tenant',
  'defaultLocale': 'zh-TW',
  'deviceCapabilities': <dynamic>[],
  'localizations': <dynamic>[],
};
Json profile(Json m) => {
  'TeamIdentifier': [m['teamId']],
  'DeveloperCertificates': [
    Uint8List.fromList([1, 2, 3]),
  ],
  'ExpirationDate': DateTime.utc(2099, 1, 1),
  'ProvisionedDevices': ['device'],
  'Entitlements': {
    'application-identifier': '${m['teamId']}.${m['applicationIdentifier']}',
    'com.apple.developer.team-identifier': m['teamId'],
    'get-task-allow': false,
  },
};
Future<void> createApp(Directory app, Json m) async {
  app.createSync(recursive: true);
  File('${app.path}/Runner').writeAsStringSync('fixture');
  File('${app.path}/Info.plist').writeAsStringSync(
    encodePlist({
      'CFBundleIdentifier': m['applicationIdentifier'],
      'CFBundleDisplayName': m['appDisplayName'],
      'CFBundleShortVersionString': m['versionName'],
      'CFBundleVersion': '${m['buildNumber']}',
      'CFBundleExecutable': 'Runner',
      'CFBundleSupportedPlatforms': ['iPhoneOS'],
      'NSCameraUsageDescription': 'stale source camera',
      'NSBluetoothPeripheralUsageDescription': 'stale Bluetooth',
      'UIBackgroundModes': ['audio'],
    }),
  );
  await projectPrivacy(app, m);
}

void main() {
  test(
    'profile binds team native identity certificate expiry and distribution',
    () {
      final m = metadata();
      final p = profile(m);
      validateProfile(p, m, Uint8List.fromList([1, 2, 3]));
      for (final mutate in <void Function(Json)>[
        (p) => p['TeamIdentifier'] = ['WRONGTEAMX'],
        (p) => p['Entitlements']['application-identifier'] =
            'ABCDEFGHIJ.com.wrong',
        (p) => p['DeveloperCertificates'] = [
          Uint8List.fromList([4]),
        ],
        (p) => p['ExpirationDate'] = DateTime.utc(2000),
        (p) => p.remove('ProvisionedDevices'),
      ]) {
        final changed = profile(m);
        mutate(changed);
        expect(
          () => validateProfile(changed, m, Uint8List.fromList([1, 2, 3])),
          throwsFormatException,
        );
      }
    },
  );
  test('all four distributions derive only from profile facts', () {
    for (final method in ['development', 'ad-hoc', 'enterprise', 'app-store']) {
      final p = profile(metadata());
      if (method == 'development') p['Entitlements']['get-task-allow'] = true;
      if (['enterprise', 'app-store'].contains(method))
        p.remove('ProvisionedDevices');
      if (method == 'enterprise') p['ProvisionsAllDevices'] = true;
      expect(distributionMethod(p), method);
    }
    for (final p in [
      {'ProvisionedDevices': []},
      {
        'ProvisionsAllDevices': true,
        'ProvisionedDevices': ['device'],
        'Entitlements': {},
      },
      {
        'Entitlements': {'get-task-allow': 'true'},
      },
    ]) {
      expect(() => distributionMethod(p), throwsFormatException);
    }
  });
  test(
    'device product rejects simulator identity tampering and existing signatures',
    () async {
      await temporary('test-device-', (dir) async {
        final app = Directory('${dir.path}/Runner.app'), m = metadata();
        await createApp(app, m);
        await validateApp(app, m);
        final path = '${app.path}/Info.plist', info = await readPlist(path);
        for (final mutation in <void Function(Json)>[
          (i) => i['CFBundleVersion'] = '8',
          (i) => i['CFBundleIdentifier'] = 'com.other',
          (i) => i['CFBundleSupportedPlatforms'] = ['iPhoneSimulator'],
          (i) => i['CFBundleExecutable'] = '../escape',
        ]) {
          final changed = {...info};
          mutation(changed);
          File(path).writeAsStringSync(encodePlist(changed));
          await expectLater(validateApp(app, m), throwsFormatException);
        }
        File(path).writeAsStringSync(encodePlist(info));
        Directory('${app.path}/_CodeSignature').createSync();
        await expectLater(validateApp(app, m), throwsFormatException);
      });
    },
  );
  test(
    'nested products require exact frozen component coverage and no inherited permissions',
    () async {
      await temporary('test-components-', (dir) async {
        final app = Directory('${dir.path}/Runner.app'),
            host = metadata(),
            child = {
              ...metadata(),
              'applicationIdentifier': 'com.example.swan.widget',
              'deviceCapabilities': [],
            };
        host['components'] = [child];
        await createApp(app, host);
        final nested = Directory('${app.path}/PlugIns/Widget.appex');
        await createApp(nested, child);
        final products = await componentApps(app, host);
        expect(products.length, 2);
        expect(products.first.$1.path, nested.path);
        await expectLater(
          componentApps(app, {...host, 'components': []}),
          throwsFormatException,
        );
        await expectLater(
          componentApps(app, {
            ...host,
            'components': [child, child],
          }),
          throwsFormatException,
        );
      });
    },
  );
  test(
    'Bluetooth shared usage orders deduplicates localizes and requires purposes',
    () {
      final m = metadata();
      m['deviceCapabilities'] = [
        {
          'key': 'bluetooth.scan',
          'purposes': [
            {'locale': 'zh-TW', 'description': '搜尋裝置'},
          ],
        },
        {
          'key': 'bluetooth.connect',
          'purposes': [
            {'locale': 'zh-TW', 'description': '連接裝置'},
          ],
        },
      ];
      expect(privacyUsage(m, 'zh-TW')[bluetoothUsageKey], '搜尋裝置 連接裝置');
      expect(privacyUsage(m, 'en')[bluetoothUsageKey], '搜尋裝置 連接裝置');
      m['deviceCapabilities'][1]['purposes'][0]['description'] = '搜尋裝置';
      expect(privacyUsage(m, 'zh-TW')[bluetoothUsageKey], '搜尋裝置');
      m['deviceCapabilities'][0]['purposes'] = [];
      expect(() => privacyUsage(m, 'zh-TW'), throwsFormatException);
    },
  );
  test(
    'projection strips stale source privacy and unconfigured locale declarations',
    () async {
      await temporary('test-privacy-', (dir) async {
        final app = Directory('${dir.path}/Runner.app'), m = metadata();
        app.createSync();
        File('${app.path}/Info.plist').writeAsStringSync(
          encodePlist({
            'NSCameraUsageDescription': 'stale',
            'NSBluetoothPeripheralUsageDescription': 'stale',
            'UIBackgroundModes': ['audio'],
          }),
        );
        Directory('${app.path}/fr.lproj').createSync();
        File(
          '${app.path}/fr.lproj/InfoPlist.strings',
        ).writeAsStringSync(encodePlist({'NSCameraUsageDescription': 'stale'}));
        m['deviceCapabilities'] = [
          {
            'key': 'camera.capture',
            'purposes': [
              {'locale': 'zh-TW', 'description': '拍照'},
            ],
          },
        ];
        m['localizations'] = [
          {'locale': 'zh-TW', 'displayName': '租戶'},
        ];
        await projectPrivacy(app, m);
        final info = await readPlist('${app.path}/Info.plist');
        expect(info['NSCameraUsageDescription'], '拍照');
        expect(
          info.containsKey('NSBluetoothPeripheralUsageDescription'),
          false,
        );
        expect(info.containsKey('UIBackgroundModes'), false);
        await validatePrivacy(app, m, info);
        expect(
          (await readPlist(
            '${app.path}/fr.lproj/InfoPlist.strings',
          )).containsKey('NSCameraUsageDescription'),
          false,
        );
        info['UIBackgroundModes'] = ['audio'];
        await expectLater(validatePrivacy(app, m, info), throwsFormatException);
      });
    },
  );
  test(
    'background location needs frozen purpose and projects foreground fallback',
    () {
      final m = metadata();
      m['deviceCapabilities'] = [
        {
          'key': 'location.background',
          'purposes': [
            {'locale': 'zh-TW', 'description': '背景定位'},
          ],
        },
      ];
      expect(
        privacyUsage(m, 'zh-TW')['NSLocationWhenInUseUsageDescription'],
        '背景定位',
      );
      expect(backgroundModes(m), ['location']);
    },
  );
  test(
    'serialized Hawk native capability keys are consumed without renaming',
    () {
      final raw = Platform.environment['HAWK_CAPABILITY_KEYS'];
      if (raw == null) return;
      final keys = (jsonDecode(raw) as List).cast<String>();
      final m = metadata();
      m['deviceCapabilities'] = [
        for (final key in keys)
          {
            'key': key,
            'purposes': [
              {'locale': 'zh-TW', 'description': key},
            ],
          },
      ];
      final usage = privacyUsage(m, 'zh-TW');
      for (final key in keys.where(bluetoothKeys.contains)) {
        expect(usage[bluetoothUsageKey], contains(key));
      }
      final p = profile(m);
      if (keys.contains('notifications.push'))
        p['Entitlements']['aps-environment'] = 'production';
      validateProfile(p, m, Uint8List.fromList([1, 2, 3]));
    },
  );
}
