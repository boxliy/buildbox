import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'core.dart';
import 'sign_ios.dart' show certificateDer;
import 'archive.dart';

class ValidationFailure implements Exception {
  final String code;
  const ValidationFailure(this.code);
}

Never invalid(String code) => throw ValidationFailure(code);
void ensure(bool condition, String code) {
  if (!condition) invalid(code);
}

String boundedPassword(dynamic value) {
  ensure(value is String && value.isNotEmpty, 'malformed_material');
  ensure(
    utf8.encode(value as String).length <= 256 && !value.contains('\x00'),
    'size_limit',
  );
  return value;
}

String safeName(dynamic value) {
  ensure(
    value is String && value.isNotEmpty && value.length <= 128,
    'malformed_material',
  );
  ensure(
    !['.', '..'].contains(value) &&
        !(value as String).contains(RegExp(r'[/\\\x00]')),
    'path_rejected',
  );
  return value;
}

Uint8List materialBytes(Json material) {
  if (material.containsKey('path')) {
    final path = material['path'];
    ensure(
      path is String &&
          FileSystemEntity.typeSync(path, followLinks: false) ==
              FileSystemEntityType.file,
      'path_rejected',
    );
    final file = File(path as String);
    ensure(
      file.lengthSync() > 0 && file.lengthSync() <= 2 * 1024 * 1024,
      'size_limit',
    );
    return file.readAsBytesSync();
  }
  try {
    return decodeMaterial(material['bytesBase64']);
  } on FormatException {
    invalid('malformed_material');
  }
}

Future<void> rejectMaterialZip(Uint8List bytes) async {
  await temporary('material-archive-', (dir) async {
    final file = await privateFile('${dir.path}/material.zip', bytes);
    try {
      checkedZip(
        file.path,
        unsigned: false,
        maxBytes: 2 * 1024 * 1024,
        maxEntries: 64,
        maxExpanded: 4 * 1024 * 1024,
      );
    } on FormatException catch (e) {
      invalid(
        e.message.contains('limit')
            ? 'size_limit'
            : e.message.contains('unsafe')
            ? 'path_rejected'
            : 'malformed_material',
      );
    }
  });
  invalid('unknown_format');
}

DateTime evaluatedTime(dynamic value) {
  ensure(value is String && value.endsWith('Z'), 'malformed_material');
  try {
    final time = DateTime.parse(value as String).toUtc();
    ensure(time.year >= 2000 && time.year <= 2100, 'malformed_material');
    return time;
  } on FormatException {
    invalid('malformed_material');
  }
}

String instant(DateTime value) =>
    value.toUtc().toIso8601String().replaceFirst(RegExp(r'\.\d+Z$'), 'Z');
String validity(
  DateTime start,
  DateTime end,
  DateTime now, {
  String early = 'certificate_not_yet_valid',
  String late = 'certificate_expired',
}) => now.isBefore(start)
    ? early
    : !now.isBefore(end)
    ? late
    : 'ok';
DateTime opensslDate(String value) {
  final match = RegExp(
    r'([A-Z][a-z]{2})\s+(\d+)\s+(\d+):(\d+):(\d+)\s+(\d{4})\s+GMT',
  ).firstMatch(value);
  ensure(match != null, 'malformed_material');
  const months = [
    'Jan',
    'Feb',
    'Mar',
    'Apr',
    'May',
    'Jun',
    'Jul',
    'Aug',
    'Sep',
    'Oct',
    'Nov',
    'Dec',
  ];
  final m = match!;
  final month = months.indexOf(m[1]!) + 1;
  ensure(month > 0, 'malformed_material');
  return DateTime.utc(
    int.parse(m[6]!),
    month,
    int.parse(m[2]!),
    int.parse(m[3]!),
    int.parse(m[4]!),
    int.parse(m[5]!),
  );
}

Future<Json> certificateMetadata(
  String pem,
  Directory dir,
  DateTime now, {
  String name = 'cert',
}) async {
  final file = await privateFile('${dir.path}/$name.pem', utf8.encode(pem));
  final text = await tool([
    'openssl',
    'x509',
    '-in',
    file.path,
    '-text',
    '-noout',
  ]);
  final algorithm = RegExp(
    r'Public Key Algorithm:\s*(\S+)',
  ).firstMatch(text)?[1];
  final key = {'rsaEncryption': 'RSA', 'id-ecPublicKey': 'EC'}[algorithm];
  ensure(key != null, 'unsupported_algorithm');
  final dates = await tool([
    'openssl',
    'x509',
    '-in',
    file.path,
    '-dates',
    '-noout',
  ]);
  final start = opensslDate(
        RegExp(r'notBefore=(.+)').firstMatch(dates)?.group(1) ?? '',
      ),
      end = opensslDate(
        RegExp(r'notAfter=(.+)').firstMatch(dates)?.group(1) ?? '',
      );
  final subject = await tool([
    'openssl',
    'x509',
    '-in',
    file.path,
    '-subject',
    '-noout',
    '-nameopt',
    'RFC2253',
  ]);
  final team = RegExp(
    r'(?:^|[,=])OU=([A-Z0-9]{10})(?:,|$)',
  ).firstMatch(subject)?[1];
  final state = validity(start, end, now);
  return {
    'teamId': team,
    'certificateSha256': hashBytes(certificateDer(pem)),
    'notBefore': instant(start),
    'expiresAt': instant(end),
    'algorithm': key,
    'signingCapable': state == 'ok',
    'validity': state,
  };
}

Future<void> provePrivateKey(
  String privatePem,
  String certificatePem,
  Directory dir,
) async {
  final key = await privateFile(
    '${dir.path}/challenge.key',
    utf8.encode(privatePem),
  );
  final cert = await privateFile(
    '${dir.path}/challenge.cert',
    utf8.encode(certificatePem),
  );
  final pub = File('${dir.path}/challenge.pub')
    ..writeAsStringSync(
      await tool(['openssl', 'x509', '-in', cert.path, '-pubkey', '-noout']),
    );
  final data = File('${dir.path}/challenge.txt')
    ..writeAsStringSync('aviary-signing-material-challenge-v1');
  final signature = '${dir.path}/challenge.sig';
  final sign = await toolResult([
    'openssl',
    'dgst',
    '-sha256',
    '-sign',
    key.path,
    '-out',
    signature,
    data.path,
  ]);
  ensure(sign.exitCode == 0, 'private_key_mismatch');
  final verify = await toolResult([
    'openssl',
    'dgst',
    '-sha256',
    '-verify',
    pub.path,
    '-signature',
    signature,
    data.path,
  ]);
  ensure(verify.exitCode == 0, 'private_key_mismatch');
}

List<String> certificatePems(String pem) => RegExp(
  r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----',
).allMatches(pem).map((m) => m[0]!).toList();
Future<ProcessResult> validationTool(
  List<String> args, {
  Map<String, String>? env,
}) => toolResult(args, environment: env, timeout: const Duration(seconds: 20));
Json authorizeValidation(Json document) {
  final raw = document['scope'];
  ensure(raw is Json, 'scope_mismatch');
  final scope = raw as Json;
  final result = <String, dynamic>{};
  for (final key in [
    'validationId',
    'tenantId',
    'assetId',
    'versionId',
    'kind',
    'stage',
  ]) {
    ensure(
      matches(scope[key], r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}'),
      'scope_mismatch',
    );
    result[key] = scope[key];
  }
  final platform = document['platform'];
  ensure(
    result['stage'] == 'validate' &&
        ['android', 'ios'].contains(platform) &&
        (scope['platform'] == null || scope['platform'] == platform),
    'scope_mismatch',
  );
  ensure(
    platform == 'android'
        ? result['kind'] == 'android_keystore'
        : {
                'certificate': 'apple_certificate',
                'provisioning_profile': 'apple_profile',
              }[document['kind']] ==
              result['kind'],
    'scope_mismatch',
  );
  return result;
}

void assertPublic(dynamic value) {
  const banned = {
    'password',
    'storePassword',
    'keyPassword',
    'privateKey',
    'privateKeyPem',
    'keystore',
    'container',
    'containerBase64',
    'material',
    'pkcs12',
    'provisioningProfile',
    'profileBytes',
    'signedUrl',
    'presignedUrl',
    'authorization',
    'token',
    'secret',
  };
  void walk(dynamic v) {
    if (v is Map) {
      for (final e in v.entries) {
        ensure(!banned.contains(e.key), 'result_rejected');
        walk(e.value);
      }
    } else if (v is List) {
      for (final e in v) {
        walk(e);
      }
    } else if (v is String) {
      ensure(
        !v.contains('BEGIN PRIVATE') && !v.contains('BEGIN CERTIFICATE'),
        'result_rejected',
      );
    }
  }

  walk(value);
  ensure(utf8.encode(canonical(value)).length <= 64 * 1024, 'result_rejected');
}
