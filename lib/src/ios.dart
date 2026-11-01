import 'dart:io';
import 'dart:typed_data';
import 'core.dart';
import 'archive.dart';

const usageKeys = {
  'camera.capture': 'NSCameraUsageDescription',
  'microphone.record': 'NSMicrophoneUsageDescription',
  'location.foreground': 'NSLocationWhenInUseUsageDescription',
  'location.background': 'NSLocationAlwaysAndWhenInUseUsageDescription',
  'photos.read': 'NSPhotoLibraryUsageDescription',
  'photos.write': 'NSPhotoLibraryAddUsageDescription',
  'biometrics.authenticate': 'NSFaceIDUsageDescription',
};
const bluetoothKeys = ['bluetooth.scan', 'bluetooth.connect'];
const bluetoothUsageKey = 'NSBluetoothAlwaysUsageDescription';
final managedUsageKeys = {
  ...usageKeys.values,
  bluetoothUsageKey,
  'NSBluetoothPeripheralUsageDescription',
  'NSLocationAlwaysUsageDescription',
};
final supportedCapabilities = {
  ...usageKeys.keys,
  ...bluetoothKeys,
  'notifications.push',
  'background.execution',
};
Json privacyUsage(Json m, String? locale) {
  final capabilities = (m['deviceCapabilities'] ?? []) as List;
  require(
    capabilities.every((c) => supportedCapabilities.contains(c['key'])),
    'unsupported iOS native capability',
  );
  final purposes = <String, Json>{
    for (final c in capabilities)
      c['key'] as String: {
        for (final p in (c['purposes'] ?? []) as List)
          p['locale'] as String: p['description'],
      },
  };
  final fallback = m['source'] == 'tenant'
      ? null
      : (m['appDisplayName'] ?? 'App') as String;
  final result = <String, dynamic>{};
  String description(String key, bool bluetooth) {
    final values = purposes[key]!;
    final value = values[locale] ?? values[m['defaultLocale']];
    if (value is String && value.isNotEmpty) return value;
    require(fallback != null, 'missing frozen usage description');
    return bluetooth
        ? '$fallback uses Bluetooth for enabled app features.'
        : '$fallback uses $key for enabled app features.';
  }

  for (final entry in usageKeys.entries) {
    if (purposes.containsKey(entry.key))
      result[entry.value] = description(entry.key, false);
  }
  if (purposes.containsKey('location.background'))
    result.putIfAbsent(
      usageKeys['location.foreground']!,
      () => result[usageKeys['location.background']!],
    );
  final descriptions = <String>[];
  for (final key in bluetoothKeys) {
    if (purposes.containsKey(key)) {
      final value = description(key, true);
      if (!descriptions.contains(value)) descriptions.add(value);
    }
  }
  if (descriptions.isNotEmpty)
    result[bluetoothUsageKey] = descriptions.join(' ');
  return result;
}

List<String> backgroundModes(Json m) {
  final capabilities = ((m['deviceCapabilities'] ?? []) as List)
      .map((e) => e['key'])
      .toSet();
  return [
    for (final entry in {
      'location.background': 'location',
      'notifications.push': 'remote-notification',
      'background.execution': 'fetch',
    }.entries)
      if (capabilities.contains(entry.key)) entry.value,
  ];
}

Future<List<(String, String, Json)>> localizedStrings(Directory app) async {
  final result = <(String, String, Json)>[];
  for (final dir
      in app
          .listSync(followLinks: false)
          .whereType<Directory>()
          .where((d) => d.path.endsWith('.lproj'))) {
    final path = '${dir.path}/InfoPlist.strings';
    if (File(path).existsSync())
      result.add((
        dir.path.split('/').last.replaceFirst(RegExp(r'\.lproj$'), ''),
        path,
        await readPlist(path),
      ));
  }
  return result;
}

Future<void> projectPrivacy(Directory app, Json m) async {
  final path = '${app.path}/Info.plist';
  final body = await readPlist(path);
  for (final key in managedUsageKeys) {
    body.remove(key);
  }
  body.addAll(privacyUsage(m, m['defaultLocale'] as String?));
  body['CFBundleDisplayName'] = m['appDisplayName'];
  body.remove('UIBackgroundModes');
  final modes = backgroundModes(m);
  if (modes.isNotEmpty) body['UIBackgroundModes'] = modes;
  File(path).writeAsStringSync(encodePlist(body));
  for (final item in await localizedStrings(app)) {
    for (final key in managedUsageKeys) {
      item.$3.remove(key);
    }
    File(item.$2).writeAsStringSync(encodePlist(item.$3));
  }
  for (final localization in (m['localizations'] ?? []) as List) {
    final locale = localization['locale'];
    require(matches(locale, r'[A-Za-z0-9-]+'), 'invalid native localization');
    final dir = Directory('${app.path}/$locale.lproj')..createSync();
    File('${dir.path}/InfoPlist.strings').writeAsStringSync(
      encodePlist({
        'CFBundleDisplayName': localization['displayName'],
        ...privacyUsage(m, locale as String),
      }),
    );
  }
}

Future<void> validatePrivacy(Directory app, Json m, Json info) async {
  final modes = backgroundModes(m);
  require(
    modes.isNotEmpty
        ? same(info['UIBackgroundModes'], modes)
        : !info.containsKey('UIBackgroundModes'),
    'iOS background modes mismatch',
  );
  Json managed(Json body) => {
    for (final key in managedUsageKeys)
      if (body.containsKey(key)) key: body[key],
  };
  final expected = privacyUsage(m, m['defaultLocale'] as String?);
  require(same(managed(info), expected), 'iOS privacy usage mismatch');
  final configured = ((m['localizations'] ?? []) as List)
      .map((i) => i['locale'] as String)
      .toSet();
  require(
    configured.every((v) => matches(v, r'[A-Za-z0-9-]+')),
    'invalid native localization',
  );
  final found = <String>{};
  for (final item in await localizedStrings(app)) {
    found.add(item.$1);
    require(
      same(
        managed(item.$3),
        configured.contains(item.$1) ? privacyUsage(m, item.$1) : {},
      ),
      'localized privacy mismatch',
    );
  }
  require(
    expected.isEmpty || found.containsAll(configured),
    'missing localized privacy',
  );
}

String distributionMethod(Json profile) {
  final devices = profile['ProvisionedDevices'];
  require(
    devices == null ||
        (devices is List &&
            devices.isNotEmpty &&
            devices.every((d) => d is String && d.isNotEmpty)),
    'invalid provisioning devices',
  );
  final rawEntitlements = profile['Entitlements'];
  require(
    rawEntitlements == null || rawEntitlements is Map,
    'invalid provisioning entitlements',
  );
  final all = profile['ProvisionsAllDevices'] ?? false,
      task = (rawEntitlements as Map?)?['get-task-allow'] ?? false;
  require(
    all is bool && task is bool,
    'invalid provisioning distribution flags',
  );
  if (all == true && devices == null && task == false) return 'enterprise';
  if (all == false && devices == null && task == false) return 'app-store';
  if (devices != null && all == false)
    return task == true ? 'development' : 'ad-hoc';
  return fail('inconsistent provisioning distribution');
}

Json validateProfile(
  Json profile,
  Json m,
  Uint8List certificate, {
  DateTime? now,
}) {
  final entitlement = profile['Entitlements'] as Json;
  final expected = '${m['teamId']}.${m['applicationIdentifier']}';
  final expiry = profile['ExpirationDate'];
  require(
    same(profile['TeamIdentifier'], [m['teamId']]) &&
        entitlement['application-identifier'] == expected &&
        entitlement['com.apple.developer.team-identifier'] == m['teamId'] &&
        (profile['DeveloperCertificates'] as List).any(
          (c) => c is List<int> && same(c, certificate),
        ) &&
        expiry is DateTime &&
        expiry.isAfter(now ?? DateTime.now().toUtc()),
    'profile identity certificate or expiry mismatch',
  );
  final method = m['distributionMethod'];
  require(
    distributionMethod(profile) == method,
    'profile distribution mismatch',
  );
  final capabilities = ((m['deviceCapabilities'] ?? []) as List)
      .map((i) => i['key'])
      .toSet();
  require(
    capabilities.difference(supportedCapabilities).isEmpty,
    'unsupported iOS native capability',
  );
  final requested = <String, dynamic>{
    'application-identifier': expected,
    'com.apple.developer.team-identifier': m['teamId'],
    'get-task-allow': method == 'development',
    if (capabilities.contains('notifications.push'))
      'aps-environment': method == 'development' ? 'development' : 'production',
  };
  require(
    requested.entries.every((e) => entitlement[e.key] == e.value),
    'profile does not permit frozen entitlements',
  );
  return requested;
}

Future<void> validateApp(Directory app, Json m) async {
  final info = await readPlist('${app.path}/Info.plist');
  require(
    info['CFBundleIdentifier'] == m['applicationIdentifier'] &&
        info['CFBundleShortVersionString'] == m['versionName'] &&
        '${info['CFBundleVersion']}' == '${m['buildNumber']}',
    'iOS identity or version mismatch',
  );
  if (m['appDisplayName'] != null)
    require(
      info['CFBundleDisplayName'] == m['appDisplayName'],
      'iOS display name mismatch',
    );
  await validatePrivacy(app, m, info);
  require(
    matches(info['CFBundleExecutable'], r'[A-Za-z0-9_.-]+') &&
        File('${app.path}/${info['CFBundleExecutable']}').existsSync() &&
        same(info['CFBundleSupportedPlatforms'], ['iPhoneOS']),
    'invalid device executable',
  );
  require(
    !app
        .listSync(recursive: true, followLinks: false)
        .any(
          (e) => [
            '_CodeSignature',
            'embedded.mobileprovision',
          ].contains(e.path.split('/').last),
        ),
    'compile product must be unsigned',
  );
}

Future<List<(Directory, Json)>> componentApps(Directory app, Json m) async {
  final actual = [
    app,
    ...app
        .listSync(recursive: true, followLinks: false)
        .whereType<Directory>()
        .where((p) => p.path.endsWith('.app') || p.path.endsWith('.appex')),
  ];
  final components = (m['components'] ?? []) as List;
  final byId = {
    for (final c in components) c['applicationIdentifier'] as String: c,
  };
  require(
    byId.length == components.length &&
        !byId.containsKey(m['applicationIdentifier']),
    'duplicate component identity',
  );
  final found = <String>{}, result = <(Directory, Json)>[];
  for (final product in actual) {
    final info = await readPlist('${product.path}/Info.plist');
    final id = info['CFBundleIdentifier'];
    Json component = m;
    if (product.path != app.path) {
      require(
        id is String &&
            byId.containsKey(id) &&
            id.startsWith('${m['applicationIdentifier']}.') &&
            found.add(id),
        'unconfigured nested component',
      );
      component = {
        ...m,
        ...byId[id] as Json,
        'deviceCapabilities': byId[id]['deviceCapabilities'] ?? [],
      };
    }
    await validateApp(product, component);
    result.add((product, component));
  }
  require(
    found.containsAll(byId.keys) && found.length == byId.length,
    'missing configured component',
  );
  result.sort((a, b) => b.$1.path.length.compareTo(a.$1.path.length));
  return result;
}

Json configureProject(Json project, Json spec) {
  final identity = spec['applicationIdentifier'] as String,
      inputs = spec['frozenInputs'] as Json,
      signing = spec['signing'] as Json;
  final targets = <String, String>{'Runner': identity};
  for (final component in (signing['components'] ?? []) as List) {
    final bundle = component['applicationIdentifier'] as String;
    if (bundle == identity) continue;
    require(bundle.startsWith('$identity.'), 'component identity mismatch');
    final target =
        inputs['iosComponentTargets'][bundle.substring(identity.length + 1)]
            as String;
    require(!targets.containsKey(target), 'duplicate native target');
    targets[target] = bundle;
  }
  final objects = project['objects'] as Json;
  for (final e in targets.entries) {
    final matches = objects.values.where(
      (t) => t['isa'] == 'PBXNativeTarget' && t['name'] == e.key,
    );
    require(
      matches.length == 1 &&
          [
            'com.apple.product-type.application',
            'com.apple.product-type.app-extension',
          ].contains(matches.single['productType']),
      'invalid native target',
    );
    final list = objects[matches.single['buildConfigurationList']];
    for (final reference in list['buildConfigurations']) {
      final settings = Map<String, dynamic>.from(
        objects[reference]['buildSettings'] as Map,
      );
      objects[reference]['buildSettings'] = settings;
      settings.addAll({
        'PRODUCT_BUNDLE_IDENTIFIER': e.value,
        'MARKETING_VERSION': inputs['versionName'],
        'CURRENT_PROJECT_VERSION': '${inputs['buildNumber']}',
        'INFOPLIST_KEY_CFBundleDisplayName': spec['appDisplayName'],
        'DEVELOPMENT_TEAM': signing['teamId'],
        'CODE_SIGNING_ALLOWED': 'NO',
        'CODE_SIGNING_REQUIRED': 'NO',
      });
    }
  }
  return project;
}

Future<void> packageIos(String buildDirectory, String output, Json spec) async {
  final apps = Directory(buildDirectory)
      .listSync(followLinks: false)
      .whereType<Directory>()
      .where((d) => d.path.endsWith('.app'))
      .toList();
  require(apps.length == 1, 'expected one unsigned device app');
  final config = spec['config'] as Json;
  final metadata = {
    ...config['appProfile'] as Json,
    'appDisplayName': config['appDisplayName'],
    'source': config['signing']?['source'],
  };
  final components = {
    for (final c in (config['signing']?['components'] ?? []) as List)
      c['applicationIdentifier']: c,
  };
  final app = apps.single;
  for (final product in [
    app,
    ...app
        .listSync(recursive: true, followLinks: false)
        .whereType<Directory>()
        .where((d) => d.path.endsWith('.app') || d.path.endsWith('.appex')),
  ]) {
    Json selected = metadata;
    if (product.path != app.path) {
      final id = (await readPlist(
        '${product.path}/Info.plist',
      ))['CFBundleIdentifier'];
      require(components.containsKey(id), 'unconfigured nested component');
      selected = {
        ...metadata,
        ...components[id] as Json,
        'deviceCapabilities': components[id]['deviceCapabilities'] ?? [],
      };
    }
    await projectPrivacy(product, selected);
  }
  zipTree(app, output, prefix: 'Payload/${app.path.split('/').last}/');
}
