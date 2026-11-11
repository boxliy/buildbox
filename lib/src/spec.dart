import 'dart:convert';
import 'core.dart';

void keys(Json value, Set<String> allowed, {bool exact = false}) => require(
  value.keys.every(allowed.contains) &&
      (!exact || value.length == allowed.length),
  'unknown or missing field',
);
const shaPattern = r'sha256:[0-9a-f]{64}';
bool validSourceRef(String value) {
  if (value.isEmpty || value.length > 128 || value.startsWith('-'))
    return false;
  if (value == 'latest' || value == 'main' || value == 'local') return true;
  if (value.contains('..') ||
      value.startsWith('/') ||
      value.endsWith('/') ||
      RegExp(r'\s').hasMatch(value)) {
    return false;
  }
  return value.codeUnits.every((unit) => unit >= 32 && unit < 127) &&
      RegExp(r'^[A-Za-z0-9._/-]+$').hasMatch(value);
}

String? readSourceRef(Json config, Json frozen) {
  final top = config['sourceRef'];
  final nested = frozen['sourceRef'];
  String? ref;
  if (top is String && top.isNotEmpty) ref = top;
  if (nested is String && nested.isNotEmpty) {
    require(ref == null || ref == nested, 'frozen scope mismatch');
    ref ??= nested;
  }
  if (top != null || nested != null)
    require(ref != null && validSourceRef(ref), 'invalid sourceRef');
  return ref;
}

List<String> features(dynamic value) {
  require(value is List, 'invalid features');
  final list = (value as List).cast<String>();
  require(
    list.every((v) => matches(v, r'[A-Z][A-Z0-9_]{0,63}')) &&
        list.toSet().length == list.length,
    'invalid features',
  );
  return list;
}

String specDigest(Json config) =>
    hashJson({...config}..remove('artifactPrefix'));
Json validateSpec(Json c) {
  require(
    c['schemaVersion'] == 2 && c['schemaVersion'] is int,
    'unsupported Build Spec version',
  );
  keys(c, {
    'schemaVersion',
    'tenantId',
    'appId',
    'platform',
    'targets',
    'commitSha',
    'sourceRef',
    'sourceRepo',
    'appProfile',
    'artifactPrefix',
    'frozenInputs',
    'appDisplayName',
    'appName',
    'appSlug',
    'tenantSlug',
    'applicationIdentifier',
    'androidApplicationId',
    'iosBundleId',
    'dartDefines',
    'storageProfileId',
    'storageProfileRevision',
    'signing',
    'packagingRevision',
    'brandResources',
    'assembly',
    'appConfiguration',
    'revisionManifest',
  });
  if (c.containsKey('revisionManifest')) {
    final manifest = c['revisionManifest'] as Json;
    keys(manifest, {
      'featureRevision',
      'shellRevision',
      'appearanceRevision',
      'resourceRevision',
    }, exact: true);
    require(
      manifest.entries.every(
        (entry) =>
            entry.value is int &&
            entry.value >= (entry.key == 'appearanceRevision' ? 0 : 1),
      ),
      'invalid revision manifest',
    );
  }
  final targets = (c['targets'] as List).cast<String>(),
      platform = c['platform'];
  final sorted = targets.toSet().toList()..sort();
  require(
    targets.isNotEmpty &&
        same(targets, sorted) &&
        targets.every(
          (t) =>
              (platform == 'android'
                      ? ['apk', 'aab']
                      : platform == 'ios'
                      ? ['ipa']
                      : [])
                  .contains(t),
        ),
    'invalid platform targets',
  );
  for (final key in ['tenantId', 'appId', 'storageProfileId']) {
    if (c.containsKey(key))
      require(
        matches(c[key], r'[1-9][0-9]*') &&
            BigInt.parse(c[key] as String) <=
                BigInt.parse('9223372036854775807'),
        'IDs must be canonical decimal strings',
      );
  }
  final f = c['frozenInputs'] as Json;
  keys(f, {
    'tenantId',
    'appId',
    'platform',
    'sourceRepo',
    'commitSha',
    'sourceRef',
    'flutterVersion',
    'fvmrc',
    'versionName',
    'buildNumber',
    'brandAssets',
    'builtinResources',
    'languages',
    'signingReference',
    'xcodeBuild',
    'iosComponentTargets',
  });
  for (final key in [
    'tenantId',
    'appId',
    'sourceRepo',
    'commitSha',
    'platform',
  ]) {
    if (c.containsKey(key)) require(c[key] == f[key], 'frozen scope mismatch');
  }
  final sourceRef = readSourceRef(c, f);
  final commitSha = f['commitSha'];
  require(
    f['buildNumber'] is int &&
        f['buildNumber'] >= 1 &&
        f['buildNumber'] <= 2100000000 &&
        (sourceRef == null
            ? matches(commitSha, r'[0-9a-f]{40}')
            : commitSha == null ||
                  commitSha == '' ||
                  commitSha == sourceRef ||
                  matches(commitSha, r'[0-9a-fA-F]{40}')),
    'invalid frozen version or source',
  );
  for (final key in ['flutterVersion', 'versionName']) {
    require(
      matches(f[key], r'[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}'),
      'invalid frozen version',
    );
  }
  if (platform == 'ios') {
    final xcode = f['xcodeBuild'];
    require(
      sourceRef != null && (xcode == null || xcode == '') ||
          matches(xcode, r'[A-Za-z0-9]{1,32}'),
      'missing fixed Xcode build',
    );
  } else {
    require(
      f['xcodeBuild'] == null &&
          (f['iosComponentTargets'] == null ||
              (f['iosComponentTargets'] as Map).isEmpty),
      'iOS inputs on Android',
    );
  }
  if (f['fvmrc'] == null) {
    require(sourceRef != null, 'invalid fixed Flutter configuration');
  } else {
    final resource = f['fvmrc'] as Json;
    keys(resource, {'path', 'sha256'}, exact: true);
    require(
      resource['path'] == 'waterfowl/.fvmrc' &&
          matches(resource['sha256'], r'[0-9a-f]{64}'),
      'invalid fixed Flutter configuration',
    );
  }
  require(
    matches(f['signingReference'], r'signing:[A-Za-z0-9:._-]{1,120}'),
    'invalid signing reference',
  );
  final components = (f['iosComponentTargets'] ?? <String, dynamic>{}) as Json;
  require(
    components.length <= 32 &&
        components.values.toSet().length == components.length &&
        components.entries.every(
          (e) =>
              matches(e.key, r'[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*') &&
              e.key.length <= 128 &&
              matches(e.value, r'[A-Za-z0-9_-]{1,128}') &&
              e.value != 'Runner',
        ),
    'invalid native component targets',
  );
  for (final group in ['brandAssets', 'builtinResources', 'languages']) {
    if (f[group] == null) {
      require(
        sourceRef != null && group != 'brandAssets',
        'invalid resource group',
      );
      continue;
    }
    final values = f[group] as List;
    final paths = values.map((v) => v['path'] as String).toList();
    final sorted = paths.toSet().toList()..sort();
    require(
      values.length >= (group == 'brandAssets' ? 1 : 0) &&
          values.length <= 256 &&
          same(paths, sorted),
      'invalid resource group',
    );
    for (final v in values) {
      keys(v as Json, {'path', 'sha256'}, exact: true);
      require(
        matches(v['path'], r'waterfowl/[A-Za-z0-9/._@-]+') &&
            (v['path'] as String).length <= 512 &&
            !(v['path'] as String)
                .split('/')
                .any((p) => ['', '.', '..'].contains(p)) &&
            matches(v['sha256'], r'[0-9a-f]{64}'),
        'invalid resource reference',
      );
    }
  }
  final brand = c['brandResources'] as List? ?? [];
  require(
    brand.isEmpty ||
        same(brand.map((i) => i['path']).toList(), [
          'waterfowl/.aviary-brand/icon.png',
          'waterfowl/.aviary-brand/launch.png',
        ]),
    'invalid frozen brand paths',
  );
  for (final item in brand) {
    keys(item as Json, {
      'resourceId',
      'revision',
      'path',
      'sha256',
      'contentBase64',
    }, exact: true);
    final bytes = base64.decode(item['contentBase64'] as String);
    require(
      bytes.isNotEmpty &&
          bytes.length <= 8388608 &&
          hashBytes(bytes) == item['sha256'],
      'frozen brand digest mismatch',
    );
  }
  final signing = c['signing'] as Json? ?? {};
  if (signing['source'] == 'tenant') {
    keys(signing, {
      'source',
      'versionId',
      'assetId',
      'version',
      'certificateSha256',
      'alias',
      'purpose',
      'distributionMethod',
      'teamId',
      'materials',
      'components',
    });
    require(
      matches(signing['certificateSha256'], r'[0-9a-f]{64}'),
      'invalid signing certificate',
    );
    if (platform == 'android') {
      require(
        (signing['purpose'] == 'direct' &&
                signing['distributionMethod'] == 'direct') ||
            (signing['purpose'] == 'play_upload' &&
                signing['distributionMethod'] == 'play'),
        'Android signing purpose mismatch',
      );
    } else {
      require(
        signing['purpose'] == 'apple_distribution' &&
            [
              'development',
              'ad-hoc',
              'enterprise',
              'app-store',
            ].contains(signing['distributionMethod']),
        'invalid Apple distribution',
      );
    }
  }
  validateNative(c);
  return c;
}

bool forbidden(dynamic value) {
  const banned = {
    'authorization',
    'ciphertext',
    'credential',
    'keystore',
    'password',
    'payloadciphertext',
    'privatekey',
    'secret',
    'token',
    'wrappeddek',
  };
  if (value is List) return value.any(forbidden);
  if (value is Map)
    return value.entries.any(
      (e) =>
          banned.contains(
            (e.key as String).toLowerCase().replaceAll(RegExp('[^a-z0-9]'), ''),
          ) ||
          forbidden(e.value),
    );
  return false;
}

void validateNative(Json c) {
  final a = c['assembly'] as Json;
  keys(a, {'revision', 'catalogDigest', 'catalog', 'selections'}, exact: true);
  require(
    a['revision'] is int && a['revision'] >= 1,
    'invalid assembly revision',
  );
  final catalog = a['catalog'] as Json;
  keys(catalog, {
    'schemaVersion',
    'sourceCommit',
    'flutterVersion',
    'lockfileDigest',
    'presentations',
  }, exact: true);
  require(
    catalog['schemaVersion'] == 1 &&
        (readSourceRef(c, c['frozenInputs'] as Json) != null ||
            catalog['sourceCommit'] == c['commitSha']) &&
        catalog['flutterVersion'] == c['frozenInputs']['flutterVersion'] &&
        matches(catalog['lockfileDigest'], shaPattern),
    'native catalog source mismatch',
  );
  require(
    hashJson(catalog) == a['catalogDigest'],
    'native catalog digest mismatch',
  );
  final selections = a['selections'] as List;
  require(
    selections.isNotEmpty && selections.length <= 256,
    'invalid native selections',
  );
  final selected = <String>{};
  for (final item in selections) {
    keys(item as Json, {'feature', 'presentation'}, exact: true);
    require(
      item.values.every((v) => matches(v, r'[A-Z][A-Z0-9_]{0,63}')) &&
          selected.add(item['feature'] as String),
      'invalid native selection',
    );
    final implementations = (catalog['presentations'] as List).where(
      (p) =>
          p['feature'] == item['feature'] &&
          p['presentation'] == item['presentation'],
    );
    require(
      implementations.length == 1 &&
          (implementations.single['platforms'] as List).contains(c['platform']),
      'unsupported native implementation',
    );
  }
  if (c['appConfiguration'] == null)
    require(selected.contains('HOME'), 'native HOME implementation required');
  require(
    c['dartDefines']['SWAN_INTERNAL_BUILD'] == 'false',
    'product build cannot enable internal capabilities',
  );
  if (c['appConfiguration'] != null) validateAppConfiguration(c);
}

void validateAppConfiguration(Json c) {
  final b = c['appConfiguration'] as Json;
  const common = {
    'commonSnapshotDigest',
    'configurationRevision',
    'dependencyFeatures',
    'digests',
    'explicitEnabledFeatures',
    'identity',
    'permissions',
    'resolvedFeatures',
    'shell',
    'signing',
    'targetFacts',
    'targets',
  };
  final appearance = b.containsKey('appearance');
  keys(b, {
    ...common,
    ...(appearance ? {'appearance'} : {'bindings', 'themes'}),
  }, exact: true);
  require(!forbidden(b), 'secret entered build spec');
  require(
    b['configurationRevision'] is int &&
        b['configurationRevision'] >= 1 &&
        matches(b['commonSnapshotDigest'], shaPattern),
    'invalid configuration revision or digest',
  );
  final explicit = features(b['explicitEnabledFeatures']).toSet(),
      dependency = features(b['dependencyFeatures']).toSet(),
      resolved = features(b['resolvedFeatures']);
  require(
    explicit.intersection(dependency).isEmpty &&
        explicit.union(dependency).containsAll(resolved) &&
        resolved.toSet().containsAll(explicit.union(dependency)),
    'invalid feature closure',
  );
  if (appearance) {
    validateAppearance(b['appearance'] as Json, resolved);
  } else {
    Map<String, Json> records(dynamic values) {
      final result = <String, Json>{};
      for (final v in values as List) {
        require(
          v is Map<String, dynamic> &&
              v['featureKey'] is String &&
              !result.containsKey(v['featureKey']),
          'invalid feature record',
        );
        result[v['featureKey'] as String] = v as Json;
      }
      require(
        result.keys.toSet().containsAll(resolved) &&
            resolved.toSet().containsAll(result.keys),
        'missing feature record',
      );
      return result;
    }

    final bindings = records(b['bindings']), themes = records(b['themes']);
    for (final key in resolved) {
      final binding = bindings[key]!, theme = themes[key]!;
      require(
        matches(binding['presentationKey'], r'[A-Z][A-Z0-9_]{0,79}') &&
            binding['presentationKey'] == theme['presentationKey'] &&
            binding['themeDigest'] == theme['digest'] &&
            same(binding['theme'], theme) &&
            matches(theme['digest'], shaPattern),
        'theme binding mismatch',
      );
      require(
        (theme['kind'] == 'builtinDefault' || theme['tokens'] is Map) &&
            theme['assets'] is List,
        'invalid managed theme',
      );
    }
  }
  final shell = b['shell'] as Json;
  keys(shell, {'appBar', 'personalCenter', 'startupFeature'}, exact: true);
  List<Json> items(dynamic list) {
    final seen = <String>{}, orders = <int>{};
    return (list as List).map((value) {
      final item = value as Json;
      keys(item, {'featureKey', 'label', 'order', 'visible'}, exact: true);
      require(
        resolved.contains(item['featureKey']) &&
            seen.add(item['featureKey'] as String) &&
            item['order'] is int &&
            item['order'] >= 0 &&
            orders.add(item['order'] as int) &&
            item['label'] is String &&
            (item['label'] as String).trim().isNotEmpty &&
            item['visible'] is bool,
        'invalid shell item',
      );
      return item;
    }).toList();
  }

  final bar = items(shell['appBar'])
    ..sort((a, b) => (a['order'] as int).compareTo(b['order'] as int));
  final personal = items(shell['personalCenter']);
  require(
    resolved.contains('PERSONAL_CENTER') || personal.isEmpty,
    'disabled personal center',
  );
  final visible = bar.where((i) => i['visible'] == true);
  require(
    visible.isNotEmpty &&
        resolved.contains(shell['startupFeature']) &&
        visible.first['featureKey'] == shell['startupFeature'],
    'invalid startup feature',
  );
  final digests = b['digests'] as Json;
  keys(digests, {'capability', 'catalog', 'resource', 'source'}, exact: true);
  require(
    digests.values.every((v) => matches(v, shaPattern)) &&
        b['identity']['platform'] == c['platform'] &&
        same(b['targets'], c['targets']),
    'invalid configuration digest or target',
  );
}

void validateAppearance(Json a, List<String> resolved) {
  keys(a, {
    'contractVersion',
    'defaultPresentationKey',
    'presentations',
  }, exact: true);
  require(
    a['contractVersion'] == 1 &&
        matches(a['defaultPresentationKey'], r'[A-Z][A-Z0-9_]{0,79}'),
    'invalid appearance',
  );
  final presentations = a['presentations'] as List;
  require(presentations.isNotEmpty, 'empty appearance');
  final seen = <String>{}, namespaces = <String>{};
  int? previousOrder;
  String? previousKey;
  for (final raw in presentations) {
    final p = raw as Json;
    keys(p, {
      'presentationKey',
      'styleKey',
      'name',
      'order',
      'directoryRevision',
      'featureKeys',
      'defaultThemeKey',
      'themes',
    }, exact: true);
    final key = p['presentationKey'] as String;
    require(
      matches(key, r'[A-Z][A-Z0-9_]{0,79}') &&
          seen.add(key) &&
          p['styleKey'] is String &&
          (p['styleKey'] as String).isNotEmpty &&
          p['name'] is String &&
          (p['name'] as String).trim().isNotEmpty &&
          p['directoryRevision'] is int &&
          p['directoryRevision'] >= 1 &&
          p['order'] is int,
      'invalid appearance presentation',
    );
    final order = p['order'] as int;
    require(
      previousOrder == null ||
          order > previousOrder ||
          (order == previousOrder && unicodeCompare(key, previousKey!) > 0),
      'unstable presentation order',
    );
    previousOrder = order;
    previousKey = key;
    require(
      same(features(p['featureKeys']), resolved),
      'appearance feature closure mismatch',
    );
    final themeKeys = <String>{};
    final themes = p['themes'] as List;
    require(themes.isNotEmpty, 'empty themes');
    for (final raw in themes) {
      final theme = raw as Json;
      final themeKey = theme['key'];
      require(
        !theme.containsKey('featureKey') &&
            theme['presentationKey'] == key &&
            theme['assets'] is List &&
            themeKey is String &&
            themeKey.isNotEmpty &&
            themeKeys.add(themeKey),
        'invalid appearance theme',
      );
      final kind = theme['kind'];
      require(
        ['builtinDefault', 'managed'].contains(kind) &&
            (kind != 'managed' ||
                (theme['styleKey'] == p['styleKey'] && theme['tokens'] is Map)),
        'invalid managed theme',
      );
      final namespace = theme['assetNamespace'];
      final expected = kind == 'builtinDefault'
          ? key.toLowerCase()
          : 'managed/${key.toLowerCase()}/$themeKey';
      require(
        (namespace == expected ||
                (kind == 'managed' && namespace == themeKey)) &&
            namespace is String &&
            namespaces.add(namespace),
        'invalid theme namespace',
      );
      require(
        (theme['assets'] as List).every(
          (asset) =>
              asset is Map &&
              asset['path'] is String &&
              (asset['path'] as String).contains('/assets/themes/$namespace/'),
        ),
        'invalid theme asset path',
      );
      final content = {...theme}..remove('digest');
      require(
        matches(theme['digest'], shaPattern) &&
            hashJson(content) == theme['digest'],
        'theme digest mismatch',
      );
    }
    require(
      themeKeys.contains(p['defaultThemeKey']),
      'unavailable default theme',
    );
  }
  require(
    seen.contains(a['defaultPresentationKey']),
    'unavailable default presentation',
  );
}
