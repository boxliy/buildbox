import 'dart:io';
import 'core.dart';
import 'material_common.dart';

Future<Json> validateAndroidMaterial(Json request, DateTime evaluated) async {
  final material = request['material'] as Json? ?? {},
      password = boundedPassword(material['storePassword']),
      keyPassword = boundedPassword(
        material['keyPassword'] ?? material['storePassword'],
      ),
      bytes = materialBytes(material);
  final store =
      bytes.length >= 4 &&
          bytes[0] == 0xfe &&
          bytes[1] == 0xed &&
          bytes[2] == 0xfe &&
          bytes[3] == 0xed
      ? 'JKS'
      : bytes.length >= 4 && bytes[0] == 0x30
      ? 'PKCS12'
      : null;
  ensure(store != null, 'unknown_format');
  final requested = material['alias'] == null
      ? null
      : safeName(material['alias']);
  return temporary('android-validation-', (dir) async {
    final keystore = await privateFile('${dir.path}/material.keystore', bytes);
    final env = {
      ...Platform.environment,
      'VALIDATION_STORE_PASSWORD': password,
      'VALIDATION_KEY_PASSWORD': keyPassword,
      'LC_ALL': 'C',
      'LANG': 'C',
    };
    final listing = await validationTool([
      'keytool',
      '-J-Duser.language=en',
      '-list',
      '-keystore',
      keystore.path,
      '-storetype',
      store!,
      '-storepass:env',
      'VALIDATION_STORE_PASSWORD',
    ], env: env);
    ensure(listing.exitCode == 0, 'wrong_password');
    final aliases = (listing.stdout as String)
        .split('\n')
        .where((line) => line.contains('PrivateKeyEntry'))
        .map((line) => line.split(',').first.trim())
        .where((v) => v.isNotEmpty)
        .toList();
    ensure(aliases.isNotEmpty && aliases.length <= 32, 'malformed_material');
    ensure(aliases.toSet().length == aliases.length, 'ambiguous_alias');
    ensure(requested != null || aliases.length == 1, 'ambiguous_alias');
    final selected = requested ?? aliases.single;
    ensure(aliases.contains(selected), 'alias_not_found');
    final verbose = await validationTool([
      'keytool',
      '-J-Duser.language=en',
      '-list',
      '-v',
      '-keystore',
      keystore.path,
      '-storetype',
      store,
      '-alias',
      selected,
      '-storepass:env',
      'VALIDATION_STORE_PASSWORD',
    ], env: env);
    ensure(verbose.exitCode == 0, 'malformed_material');
    final chainMatch = RegExp(
      r'Certificate chain length:\s*(\d+)',
    ).firstMatch(verbose.stdout as String);
    ensure(chainMatch != null, 'chain_invalid');
    final expected = int.parse(chainMatch![1]!);
    ensure(expected >= 1 && expected <= 8, 'chain_invalid');
    final destination = '${dir.path}/leaf.p12';
    final copy = await validationTool([
      'keytool',
      '-importkeystore',
      '-srckeystore',
      keystore.path,
      '-srcstoretype',
      store,
      '-destkeystore',
      destination,
      '-deststoretype',
      'PKCS12',
      '-srcalias',
      selected,
      '-destalias',
      selected,
      '-srcstorepass:env',
      'VALIDATION_STORE_PASSWORD',
      '-deststorepass:env',
      'VALIDATION_STORE_PASSWORD',
      if (store == 'JKS') ...['-srckeypass:env', 'VALIDATION_KEY_PASSWORD'],
    ], env: env);
    ensure(
      copy.exitCode == 0 && File(destination).existsSync(),
      store == 'JKS' ? 'wrong_key_password' : 'chain_invalid',
    );
    var certs = await validationTool([
      'openssl',
      'pkcs12',
      '-in',
      destination,
      '-nokeys',
      '-passin',
      'env:VALIDATION_STORE_PASSWORD',
    ], env: env);
    if (certs.exitCode != 0) {
      certs = await validationTool([
        'openssl',
        'pkcs12',
        '-in',
        destination,
        '-nokeys',
        '-legacy',
        '-passin',
        'env:VALIDATION_STORE_PASSWORD',
      ], env: env);
    }
    ensure(certs.exitCode == 0, 'chain_invalid');
    final pems = certificatePems(certs.stdout as String);
    ensure(pems.length == expected, 'chain_invalid');
    final metadata = <Json>[];
    for (var i = 0; i < pems.length; i++) {
      metadata.add(
        await certificateMetadata(pems[i], dir, evaluated, name: 'cert-$i'),
      );
    }
    final key = await validationTool([
      'openssl',
      'pkcs12',
      '-in',
      destination,
      '-nocerts',
      '-nodes',
      '-passin',
      'env:VALIDATION_STORE_PASSWORD',
    ], env: env);
    ensure(
      key.exitCode == 0 && (key.stdout as String).contains('PRIVATE KEY'),
      'wrong_key_password',
    );
    await provePrivateKey(key.stdout as String, pems.first, dir);
    final leaf = metadata.first, state = leaf['validity'];
    final entries = [
      for (final name in aliases)
        {
          'alias': name,
          'certificateSha256': name == selected
              ? leaf['certificateSha256']
              : null,
          'notBefore': name == selected ? leaf['notBefore'] : null,
          'expiresAt': name == selected ? leaf['expiresAt'] : null,
          'algorithm': name == selected ? leaf['algorithm'] : null,
          'signingCapable': name == selected && leaf['signingCapable'] == true,
          'purpose': 'signing',
          'chainLength': name == selected ? metadata.length : null,
          'chainSha256': name == selected
              ? metadata.map((v) => v['certificateSha256']).toList()
              : [],
        },
    ];
    return {
      'platform': 'android',
      'storeType': store,
      'status': state == 'ok' ? 'valid' : 'invalid',
      'reasonCodes': [state],
      'selectedAlias': selected,
      'expiresAt': leaf['expiresAt'],
      'aliasCount': aliases.length,
      'aliases': entries,
      'evidence': {
        'materialSha256': hashBytes(bytes),
        'challenge': 'detached-rsa-or-ecdsa-v1',
        'privateKeyProven': leaf['signingCapable'] == true,
        'chainTrusted': false,
        'playAppSigningIdentity': false,
        'installable': false,
        'trustedByPlatform': false,
      },
    };
  });
}
