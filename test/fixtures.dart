import 'dart:convert';
import 'dart:io';
import 'package:buildbox_tools/src/core.dart';

Json clone(Json value) => jsonDecode(jsonEncode(value)) as Json;
Json nativeSpec() {
  final config = clone(
        readJson('tests/fixtures/build-spec-apk.json')['config'] as Json,
      ),
      native =
          readJson('tests/fixtures/build_spec_v2_identity.json')['input']
              as Json;
  config.remove('releaseId');
  config['schemaVersion'] = 2;
  config['platform'] = 'android';
  config['commitSha'] = native['commitSha'];
  config['frozenInputs']['commitSha'] = native['commitSha'];
  config['frozenInputs']['builtinResources'] = [];
  config['frozenInputs']['languages'] = [];
  config['assembly'] = clone(native['assembly'] as Json);
  config['dartDefines']['SWAN_INTERNAL_BUILD'] = 'false';
  return config;
}

Json androidRequest(
  String path, {
  String password = 'changeit',
  String? alias,
}) => {
  'contract': 'signing-material-validation/v1',
  'platform': 'android',
  'evaluatedAt': '2026-11-01T00:00:00Z',
  'scope': {
    'validationId': 'validation-1',
    'tenantId': '1',
    'assetId': '2',
    'versionId': '3',
    'kind': 'android_keystore',
    'stage': 'validate',
  },
  'material': {
    'path': path,
    'storePassword': password,
    if (alias != null) 'alias': alias,
  },
};
Json appleRequest(String path, String kind) => {
  'contract': 'signing-material-validation/v1',
  'platform': 'ios',
  'kind': kind,
  'evaluatedAt': '2026-11-01T00:00:00Z',
  'scope': {
    'validationId': 'validation-1',
    'tenantId': '1',
    'assetId': '2',
    'versionId': '3',
    'kind': kind == 'certificate' ? 'apple_certificate' : 'apple_profile',
    'stage': 'validate',
  },
  'material': {'path': path, if (kind == 'certificate') 'password': 'changeit'},
};
Json validationEnvelope() => {
  'schemaVersion': 1,
  'validationId': 'validation-1',
  'tenantId': '1',
  'assetId': '2',
  'versionId': '3',
  'kind': 'android_keystore',
  'toolchainSha': 'a' * 40,
  'material': {'containerBase64': 'Ynl0ZXM=', 'password': 'changeit'},
  'expected': {},
};
Future<void> keytoolStore(
  Directory dir, {
  String type = 'PKCS12',
  String alias = 'release',
  String algorithm = 'RSA',
  String keyPassword = 'changeit',
  String start = '2026/01/01 00:00:00',
  int validity = 3650,
  bool append = false,
}) async {
  final command = [
    'keytool',
    '-J-Duser.language=en',
    '-genkeypair',
    '-noprompt',
    '-keystore',
    '${dir.path}/store',
    '-storetype',
    type,
    '-storepass:env',
    'TEST_STORE_PASS',
    '-keypass:env',
    'TEST_KEY_PASS',
    '-alias',
    alias,
    '-keyalg',
    algorithm,
    if (algorithm == 'EC') ...[
      '-groupname',
      'secp256r1',
    ] else ...[
      '-keysize',
      '2048',
    ],
    '-dname',
    'CN=Test,OU=ABCDEFGHIJ,O=Aviary,C=TW',
    '-startdate',
    start,
    '-validity',
    '$validity',
  ];
  await tool(
    command,
    environment: {
      ...Platform.environment,
      'TEST_STORE_PASS': 'changeit',
      'TEST_KEY_PASS': keyPassword,
    },
  );
}
