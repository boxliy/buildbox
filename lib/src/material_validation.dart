import 'dart:convert';
import 'dart:io';
import 'core.dart';
import 'material_common.dart';
import 'material_android.dart';
import 'material_apple.dart';

const contract = 'signing-material-validation/v1', validatorVersion = '1.2.0';
const trustChecks = [
  'security_cms_anchor_verify',
  'keychain_import',
  'codesign_identity_check',
];
Future<Json> validateDocument(Json document) async {
  ensure(document['contract'] == contract, 'unsupported_input');
  final scope = authorizeValidation(document),
      evaluated = evaluatedTime(document['evaluatedAt']);
  final platform = document['platform'];
  final body = platform == 'android'
      ? await validateAndroidMaterial(document, evaluated)
      : await validateAppleMaterial(document, evaluated);
  final reasons = (body['reasonCodes'] as List).cast<String>();
  final evidence = Map<String, dynamic>.from(body['evidence'] as Map);
  final pending =
      platform == 'ios' &&
          same(reasons, ['ok']) &&
          evidence['chainTrusted'] == true
      ? <String>[]
      : platform == 'ios'
      ? trustChecks
      : <String>[];
  if (pending.isNotEmpty && !reasons.contains('macos_capability_unavailable'))
    reasons.add('macos_capability_unavailable');
  body['evidence'] = evidence;
  final proven = platform == 'android'
      ? evidence['privateKeyProven'] == true
      : evidence['chainTrusted'] == true &&
            (body['kind'] == 'certificate'
                ? evidence['privateKeyProven'] == true
                : evidence['cmsSignatureVerified'] == true);
  final valid = same(reasons, ['ok']) && pending.isEmpty && proven;
  body['status'] = valid ? 'valid' : 'invalid';
  if (!valid) {
    reasons.removeWhere((v) => v == 'ok');
    if (reasons.isEmpty) reasons.add('tool_failed');
  }
  body['reasonCodes'] = reasons;
  evidence.addAll({
    'notExecuted': pending,
    'installable': false,
    'trustedByPlatform': false,
  });
  final result = <String, dynamic>{
    'contract': contract,
    'validatorVersion': validatorVersion,
    'scope': scope,
    'evaluatedAt': instant(evaluated),
    'tools': await probeTools(),
    'idempotent': true,
    'retried': false,
    ...body,
  };
  assertPublic(result);
  return result;
}

Future<Json> probeTools() async {
  final result = <String, dynamic>{};
  for (final name in ['openssl', 'keytool', 'security', 'codesign']) {
    final found = await Process.run('which', [name]);
    if (found.exitCode != 0) {
      result[name] = null;
      continue;
    }
    if (name == 'openssl') {
      final version = await toolResult(['openssl', 'version']);
      result[name] = (version.stdout as String).split('\n').first;
    } else if (name == 'keytool') {
      result[name] = 'present';
    } else {
      result[name] = 'present';
    }
  }
  result['macosKeychain'] =
      Platform.isMacOS &&
      result['security'] != null &&
      result['codesign'] != null;
  return result;
}

Future<Json> validateSafely(dynamic document) async {
  try {
    ensure(document is Json, 'malformed_material');
    return await validateDocument(document as Json);
  } on ValidationFailure catch (e) {
    final scope = document is Json ? document['scope'] : null;
    return publicFailure(e.code, scope);
  } catch (_) {
    return publicFailure(
      'tool_failed',
      document is Json ? document['scope'] : null,
    );
  }
}

Json publicFailure(String code, dynamic scope) {
  final result = <String, dynamic>{
    'contract': contract,
    'validatorVersion': validatorVersion,
    'status': 'invalid',
    'reasonCodes': [code],
    'message': 'validation failed closed',
    'idempotent': true,
    'retried': false,
  };
  if (scope is Json) {
    final filtered = <String, dynamic>{};
    for (final k in [
      'validationId',
      'tenantId',
      'assetId',
      'versionId',
      'kind',
      'stage',
    ]) {
      final value = scope[k];
      if (value is String &&
          value.isNotEmpty &&
          value.length <= 128 &&
          !value.contains('\n'))
        filtered[k] = value;
    }
    if (filtered.isNotEmpty) result['scope'] = filtered;
  }
  assertPublic(result);
  return result;
}

Json offlineRequest(Json e, String evaluated) {
  ensure(e['schemaVersion'] == 1, 'unsupported_input');
  final material = e['material'], expected = e['expected'];
  ensure(
    material is Map && material['containerBase64'] is String && expected is Map,
    'malformed_material',
  );
  final identity = validationIdentity(e), kind = e['kind'];
  final m = <String, dynamic>{'bytesBase64': material['containerBase64']},
      result = <String, dynamic>{
        'contract': contract,
        'evaluatedAt': instant(evaluatedTime(evaluated)),
        'scope': {...identity, 'stage': 'validate'},
        'material': m,
      };
  switch (kind) {
    case 'android_keystore':
      result['platform'] = 'android';
      ensure(material['password'] is String, 'malformed_material');
      m['storePassword'] = material['password'];
      m['keyPassword'] = material['keyPassword'] ?? material['password'];
      if (expected['alias'] != null) m['alias'] = expected['alias'];
    case 'apple_certificate':
      result.addAll({'platform': 'ios', 'kind': 'certificate'});
      ensure(material['password'] is String, 'malformed_material');
      m['password'] = material['password'];
    case 'apple_profile':
      result.addAll({
        'platform': 'ios',
        'kind': 'provisioning_profile',
        'expectations': expected,
      });
    default:
      invalid('unsupported_input');
  }
  return result;
}

Json validationIdentity(Json e) {
  final result = <String, dynamic>{};
  for (final key in [
    'validationId',
    'tenantId',
    'assetId',
    'versionId',
    'kind',
  ]) {
    ensure(e[key] is String && (e[key] as String).isNotEmpty, 'scope_mismatch');
    result[key] = e[key];
  }
  ensure(matches(e['toolchainSha'], r'[0-9a-f]{40}'), 'scope_mismatch');
  return result;
}

const hawkReasons = {
  'wrong_password',
  'invalid_material',
  'unsupported_format',
  'unsupported_algorithm',
  'expired',
  'not_yet_valid',
  'private_key_mismatch',
  'signature_invalid',
  'untrusted_chain',
  'scope_mismatch',
  'tool_unavailable',
  'resource_limit',
  'validation_failed',
  'macos_capability_unavailable',
  'path_rejected',
  'entitlement_mismatch',
};
const reasonMap = {
  'malformed_material': 'invalid_material',
  'unknown_format': 'unsupported_format',
  'size_limit': 'resource_limit',
  'wrong_key_password': 'wrong_password',
  'alias_not_found': 'invalid_material',
  'ambiguous_alias': 'invalid_material',
  'certificate_not_yet_valid': 'not_yet_valid',
  'certificate_expired': 'expired',
  'chain_invalid': 'untrusted_chain',
  'cms_invalid': 'signature_invalid',
  'profile_tampered': 'signature_invalid',
  'team_mismatch': 'scope_mismatch',
  'bundle_mismatch': 'scope_mismatch',
  'certificate_mismatch': 'scope_mismatch',
  'entitlements_mismatch': 'entitlement_mismatch',
  'distribution_mismatch': 'scope_mismatch',
  'profile_not_yet_valid': 'not_yet_valid',
  'profile_expired': 'expired',
  'tool_failed': 'validation_failed',
  'unsupported_input': 'invalid_material',
  'idempotent_terminal_failure': 'validation_failed',
  'result_rejected': 'validation_failed',
};
Json hawkResult(Json envelope, Json offline, String evaluated) {
  ensure(offline['contract'] == contract, 'unsupported_input');
  final identity = validationIdentity(envelope), scope = offline['scope'];
  ensure(
    scope is Json && identity.entries.every((e) => scope[e.key] == e.value),
    'scope_mismatch',
  );
  final status = offline['status'];
  ensure(['valid', 'invalid'].contains(status), 'malformed_material');
  final reasons = <String>[];
  for (final code in offline['reasonCodes'] as List) {
    if (code == 'ok') continue;
    final mapped = hawkReasons.contains(code) ? code : reasonMap[code];
    ensure(hawkReasons.contains(mapped), 'malformed_material');
    if (!reasons.contains(mapped)) reasons.add(mapped!);
  }
  final evidence = offline['evidence'] as Json? ?? {}, kind = identity['kind'];
  Json metadata;
  if (kind == 'android_keystore') {
    const aliasKeys = [
      'alias',
      'certificateSha256',
      'notBefore',
      'expiresAt',
      'algorithm',
      'signingCapable',
      'purpose',
    ];
    metadata = {
      'expiresAt': offline['expiresAt'],
      'aliases': [
        for (final item in (offline['aliases'] ?? []) as List)
          {for (final key in aliasKeys) key: item[key]},
      ],
    };
  } else if (kind == 'apple_certificate') {
    final cert = offline['certificate'] as Json? ?? {};
    metadata = {
      for (final key in [
        'teamId',
        'certificateSha256',
        'notBefore',
        'expiresAt',
      ])
        key: cert[key],
    };
  } else {
    final p = offline['profile'] as Json? ?? {};
    metadata = {
      'uuid': p['uuid'],
      'teamId': p['teamId'],
      'applicationIdentifier': p['applicationIdentifier'],
      'distributionMethod': {
        'development': 'development',
        'ad_hoc': 'ad-hoc',
        'enterprise': 'enterprise',
        'app_store': 'app-store',
      }[p['distribution']],
      'certificateSha256s': p['developerCertificateSha256'] ?? [],
      'entitlements': p['entitlements'] ?? {},
      'expiresAt': p['expiresAt'],
    };
  }
  final tools = offline['tools'] as Json? ?? {},
      pending = (evidence['notExecuted'] ?? []) as List;
  ensure(status != 'valid' || pending.isEmpty, 'malformed_material');
  final result = <String, dynamic>{
    'schemaVersion': 1,
    ...identity,
    'toolchainSha': envelope['toolchainSha'],
    'status': status,
    'reasonCodes': status == 'valid'
        ? []
        : reasons.isEmpty
        ? ['validation_failed']
        : reasons,
    'validatedAt': instant(evaluatedTime(evaluated)),
    'metadata': metadata,
    'evidence': {
      'privateKeyProven': evidence['privateKeyProven'] == true,
      'chainTrusted': evidence['chainTrusted'] == true,
      'cmsSignatureVerified': evidence['cmsSignatureVerified'] == true,
      'tools': [
        for (final key in ['openssl', 'keytool', 'security', 'codesign'])
          if (tools[key] is String && (tools[key] as String).isNotEmpty)
            {
              'name': key,
              'version': (tools[key] as String).substring(
                0,
                (tools[key] as String).length > 160
                    ? 160
                    : (tools[key] as String).length,
              ),
            },
      ],
      'notExecuted': pending.whereType<String>().toList(),
    },
  };
  assertPublic(result);
  return result;
}

Future<void> validateStdin() async {
  final bytes = <int>[];
  await for (final chunk in stdin) {
    bytes.addAll(chunk);
    if (bytes.length > 1024 * 1024) {
      stdout.write(canonical(publicFailure('size_limit', null)));
      exitCode = 2;
      return;
    }
  }
  dynamic document;
  try {
    document = strictJson(utf8.decode(bytes));
  } catch (_) {
    stdout.write(canonical(publicFailure('malformed_material', null)));
    exitCode = 2;
    return;
  }
  final result = await validateSafely(document);
  stdout.write(canonical(result));
  if (result['message'] != null) exitCode = 2;
}
