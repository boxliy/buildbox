import 'dart:io';
import 'core.dart';
import 'spec.dart';
import 'archive.dart';
import 'ios.dart';
import 'sign_android.dart';
import 'sign_ios.dart';
import 'material_validation.dart';
import 'source_catalog.dart';

Future<void> commands(List<String> args) async {
  require(args.isNotEmpty, 'missing command');
  final inputs = args.skip(1).toList();
  switch (args.first) {
    case 'spec-identity':
      final spec = readJson(inputs.single);
      stdout.writeln(specDigest(validateSpec(spec['config'] as Json)));
    case 'verify-source-catalog':
      await verifySourceCatalog(inputs[0], inputs[1]);
    case 'artifact-state':
      stdout.writeln(signingState(inputs.single));
    case 'ios-identity':
      require(
        matches(
              inputs[1],
              r'[A-Za-z][A-Za-z0-9-]*(\.[A-Za-z][A-Za-z0-9-]*)+',
            ) &&
            !inputs[2].contains(RegExp('[\r\n\x00]')),
        'invalid native identity',
      );
      File(inputs[0]).writeAsStringSync('SWAN_IOS_BUNDLE_ID = ${inputs[1]}\n');
    case 'ios-configure':
      final spec = readJson(inputs[0])['config'] as Json,
          path = '${inputs[1]}/project.pbxproj';
      require(
        FileSystemEntity.typeSync(path, followLinks: false) ==
            FileSystemEntityType.file,
        'unsafe Xcode project',
      );
      final project =
          strictJson(
                await tool(['plutil', '-convert', 'json', '-o', '-', path]),
              )
              as Json;
      File(
        path,
      ).writeAsStringSync(encodePlist(configureProject(project, spec)));
    case 'ios-package':
      await packageIos(inputs[0], inputs[1], readJson(inputs[2]));
    case 'sign-android':
      await signAndroid();
    case 'sign-ios':
      await signIos();
    case 'validate-material':
      await validateStdin();
    case 'validation-request':
      final envelope = readJson(inputs[0]);
      require(
        envelope['validationId'] == Platform.environment['VALIDATION_ID'] &&
            envelope['toolchainSha'] == inputs[2],
        'validation envelope identity mismatch',
      );
      writeJson(
        inputs[1],
        offlineRequest(envelope, Platform.environment['EVALUATED_AT']!),
      );
    case 'validation-result':
      writeJson(
        inputs[2],
        hawkResult(
          readJson(inputs[0]),
          readJson(inputs[1]),
          Platform.environment['EVALUATED_AT']!,
        ),
      );
    case 'validation-summary':
      final result = readJson(inputs.single);
      stdout.writeln(
        'validation status=${result['status']} reasons=${(result['reasonCodes'] as List).join(',')}',
      );
    default:
      fail('unknown command');
  }
}
