import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'core.dart';
import 'material_common.dart';

Future<Json> validateAppleMaterial(Json request, DateTime evaluated) async {
  final kind = request['kind'];
  ensure(
    ['certificate', 'provisioning_profile'].contains(kind),
    'unsupported_input',
  );
  final material = request['material'] as Json? ?? {},
      bytes = materialBytes(material);
  if (bytes.length >= 2 && bytes[0] == 0x50 && bytes[1] == 0x4b)
    await rejectMaterialZip(bytes);
  ensure(bytes.length >= 4 && bytes[0] == 0x30, 'unknown_format');
  return temporary('apple-validation-', (dir) async {
    final file = await privateFile('${dir.path}/material', bytes);
    if (kind == 'certificate') {
      final password = boundedPassword(material['password']),
          env = {...Platform.environment, 'VALIDATION_P12_PASSWORD': password};
      final cert = await pkcs12([
        '-in',
        file.path,
        '-clcerts',
        '-nokeys',
        '-passin',
        'env:VALIDATION_P12_PASSWORD',
      ], env);
      ensure(cert.exitCode == 0, 'wrong_password');
      final pems = certificatePems(cert.stdout as String);
      ensure(pems.isNotEmpty, 'malformed_material');
      final key = await pkcs12([
        '-in',
        file.path,
        '-nocerts',
        '-nodes',
        '-passin',
        'env:VALIDATION_P12_PASSWORD',
      ], env);
      ensure(
        key.exitCode == 0 && (key.stdout as String).contains('PRIVATE KEY'),
        'wrong_password',
      );
      await provePrivateKey(key.stdout as String, pems.first, dir);
      final metadata = await certificateMetadata(pems.first, dir, evaluated);
      final state = metadata.remove('validity');
      return {
        'platform': 'ios',
        'kind': 'certificate',
        'status': state == 'ok' ? 'valid' : 'invalid',
        'reasonCodes': [state],
        'certificate': metadata,
        'evidence': {
          'materialSha256': hashBytes(bytes),
          'privateKeyProven': metadata['signingCapable'] == true,
          'chainTrusted':
              state == 'ok' &&
              metadata['signingCapable'] == true &&
              metadata['teamId'] != null,
          'cmsSignatureVerified': false,
          'installable': false,
          'trustedByPlatform': false,
        },
      };
    }
    ensure(bytes.length <= 256 * 1024, 'malformed_material');
    final decoded = await validationTool([
      'openssl',
      'cms',
      '-verify',
      '-noverify',
      '-inform',
      'DER',
      '-in',
      file.path,
    ]);
    ensure(
      decoded.exitCode == 0 && (decoded.stdout as String).isNotEmpty,
      'cms_invalid',
    );
    Json profile;
    try {
      profile = parsePlist(decoded.stdout as String) as Json;
    } catch (_) {
      invalid('cms_invalid');
    }
    final expected = request['expectations'] as Json? ?? {},
        expectedCertificate = expected['certificateSha256'];
    final derived = await deriveProfile(
      profile,
      evaluated,
      dir,
      expectedCertificateSha256: expectedCertificate is String
          ? expectedCertificate
          : null,
    );
    final reasons = (derived['reasonCodes'] as List).cast<String>();
    final facts = derived['profile'] as Json;
    void compare(String expectedKey, String factKey, String code) {
      if (expected[expectedKey] != null &&
          expected[expectedKey] != facts[factKey])
        reasons.add(code);
    }

    compare('teamId', 'teamId', 'team_mismatch');
    compare('bundleId', 'bundleId', 'bundle_mismatch');
    compare('distribution', 'distribution', 'distribution_mismatch');
    if (expected['certificateSha256'] != null &&
        !(facts['developerCertificateSha256'] as List).contains(
          expected['certificateSha256'],
        ))
      reasons.add('certificate_mismatch');
    final entitlements = expected['entitlements'];
    if (entitlements != null &&
        (entitlements is! Json ||
            !entitlements.entries.every(
              (e) => same(facts['entitlements'][e.key], e.value),
            )))
      reasons.add('entitlements_mismatch');
    if (expected['requireGetTaskAllow'] == true &&
        facts['getTaskAllow'] != true)
      reasons.add('entitlements_mismatch');
    if (expected['forbidGetTaskAllow'] == true && facts['getTaskAllow'] == true)
      reasons.add('entitlements_mismatch');
    if (profile['IsXcodeManaged'] == true &&
        expected['allowXcodeManaged'] != true)
      reasons.add('profile_tampered');
    if (reasons.length > 1) reasons.removeWhere((v) => v == 'ok');
    return {
      'platform': 'ios',
      'kind': 'provisioning_profile',
      'status': same(reasons, ['ok']) ? 'valid' : 'invalid',
      'reasonCodes': reasons.toSet().toList(),
      'profile': facts,
      'evidence': {
        'materialSha256': hashBytes(bytes),
        'cmsDigestSha256': hashBytes(bytes),
        'payloadSha256': hashBytes(utf8.encode(decoded.stdout as String)),
        'privateKeyProven': false,
        'chainTrusted': same(reasons, ['ok']),
        'cmsSignatureVerified': same(reasons, ['ok']),
        'cmsParsed': true,
        'installable': false,
        'trustedByPlatform': false,
        'claimedDistributionIgnored':
            expected['distribution'] != null &&
            expected['distribution'] != facts['distribution'],
      },
    };
  });
}

Future<ProcessResult> pkcs12(List<String> args, Map<String, String> env) async {
  final modern = await validationTool(['openssl', 'pkcs12', ...args], env: env);
  if (modern.exitCode == 0) return modern;
  return validationTool(['openssl', 'pkcs12', '-legacy', ...args], env: env);
}

Future<Json> deriveProfile(
  Json profile,
  DateTime evaluated,
  Directory dir, {
  String? expectedCertificateSha256,
}) async {
  final reasons = <String>[];
  String? one(dynamic value, String code) {
    if (value is List &&
        value.length == 1 &&
        matches(value.single, r'[A-Z0-9]{10}'))
      return value.single as String;
    reasons.add(code);
    return null;
  }

  final team = one(profile['TeamIdentifier'], 'team_mismatch'),
      raw = profile['Entitlements'] as Json? ?? {};
  final entitlement = <String, dynamic>{
    for (final e in raw.entries)
      if (e.key.length <= 128 &&
          (e.value is bool ||
              e.value is int ||
              (e.value is String && (e.value as String).length <= 256)))
        e.key: e.value,
  };
  final application = entitlement['application-identifier'];
  String? bundle;
  if (application is String &&
      team != null &&
      application.startsWith('$team.')) {
    bundle = application.substring(team.length + 1);
    if (bundle.contains('*')) reasons.add('bundle_mismatch');
  } else {
    reasons.add('team_mismatch');
  }
  if (entitlement['com.apple.developer.team-identifier'] != team)
    reasons.add('team_mismatch');
  final certs = profile['DeveloperCertificates'];
  final fingerprints = <String>[];
  final validityByFingerprint = <String, String>{};
  if (certs is! List || certs.isEmpty || certs.length > 8) {
    reasons.add('certificate_mismatch');
  } else {
    for (var i = 0; i < certs.length; i++) {
      final data = certs[i];
      if (data is! Uint8List) {
        reasons.add('certificate_mismatch');
        continue;
      }
      try {
        final pem =
            '-----BEGIN CERTIFICATE-----\n${base64.encode(data)}\n-----END CERTIFICATE-----';
        final metadata = await certificateMetadata(
          pem,
          dir,
          evaluated,
          name: 'profile-$i',
        );
        final fingerprint = hashBytes(data);
        fingerprints.add(fingerprint);
        final state = metadata['validity'];
        if (state is String) validityByFingerprint[fingerprint] = state;
      } catch (_) {
        reasons.add('certificate_mismatch');
      }
    }
  }
  if (fingerprints.isNotEmpty) {
    if (expectedCertificateSha256 != null) {
      final state = validityByFingerprint[expectedCertificateSha256];
      if (state != null && state != 'ok') reasons.add(state);
    } else if (!validityByFingerprint.values.contains('ok')) {
      reasons.addAll(
        validityByFingerprint.values.where((state) => state != 'ok'),
      );
    }
  }
  final devices = profile['ProvisionedDevices'],
      all = profile['ProvisionsAllDevices'] == true,
      task = entitlement['get-task-allow'] == true,
      has = devices is List && devices.isNotEmpty;
  String? distribution;
  if (all && !has && !task) {
    distribution = 'enterprise';
  } else if (!all && !has && !task) {
    distribution = 'app_store';
  } else if (has && !all) {
    distribution = task ? 'development' : 'ad_hoc';
  } else {
    reasons.add('distribution_mismatch');
  }
  final created = profile['CreationDate'], expires = profile['ExpirationDate'];
  if (created is! DateTime || expires is! DateTime) {
    reasons.add('profile_tampered');
  } else {
    final state = validity(
      created,
      expires,
      evaluated,
      early: 'profile_not_yet_valid',
      late: 'profile_expired',
    );
    if (state != 'ok') reasons.add(state);
  }
  final count = devices is List ? devices.length : 0;
  if (count > 200) reasons.add('malformed_material');
  if (reasons.isEmpty) reasons.add('ok');
  return {
    'reasonCodes': reasons.toSet().toList(),
    'profile': {
      'uuid': profile['UUID'] is String ? profile['UUID'] : null,
      'teamId': team,
      'applicationIdentifier': application is String ? application : null,
      'distribution': distribution,
      'developerCertificateSha256': fingerprints,
      'entitlements': entitlement,
      'expiresAt': expires is DateTime ? instant(expires) : null,
      'bundleId': bundle,
      'provisionedDeviceCount': count,
      'provisionsAllDevices': all,
      'getTaskAllow': task,
    },
  };
}
