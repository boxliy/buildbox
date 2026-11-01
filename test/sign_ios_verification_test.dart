import 'dart:io';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:buildbox_tools/src/core.dart';
import 'package:buildbox_tools/src/sign_ios.dart';
import 'sign_ios_test.dart' show metadata, createApp;

void main() {
  test(
    'actual signature certificate entitlements embedded profile and version all match',
    () async {
      await temporary('test-signed-ios-', (dir) async {
        final app = Directory('${dir.path}/Runner.app'),
            m = metadata(),
            certificate = Uint8List.fromList([1, 2, 3]),
            profile = Uint8List.fromList([4, 5, 6]),
            entitlements = <String, dynamic>{
              'application-identifier': 'ABCDEFGHIJ.com.example.swan',
            };
        await createApp(app, m);
        File('${app.path}/embedded.mobileprovision').writeAsBytesSync(profile);
        var wrongCert = false,
            wrongEntitlements = false,
            rejectSignature = false;
        final commands = <List<String>>[];
        Future<String> execute(List<String> args) async {
          commands.add(args);
          if (args.contains('--verify')) {
            if (rejectSignature)
              throw const FormatException('signature invalid');
            return '';
          }
          if (args.contains('--extract-certificates')) {
            final prefix = args[args.indexOf('--extract-certificates') + 1];
            File('${prefix}0').writeAsBytesSync(wrongCert ? [7] : certificate);
            return '';
          }
          if (args.contains('--entitlements'))
            return encodePlist(
              wrongEntitlements ? {'extra': true} : entitlements,
            );
          throw StateError('unexpected native command');
        }

        Future<void> verify() => verifySigned(
          app,
          m,
          certificate,
          entitlements,
          profile,
          dir,
          execute: execute,
        );
        await verify();
        expect(commands.first, ['codesign', '--verify', '--strict', app.path]);
        rejectSignature = true;
        await expectLater(verify(), throwsFormatException);
        rejectSignature = false;
        wrongCert = true;
        await expectLater(verify(), throwsFormatException);
        wrongCert = false;
        wrongEntitlements = true;
        await expectLater(verify(), throwsFormatException);
        wrongEntitlements = false;
        File('${app.path}/embedded.mobileprovision').writeAsBytesSync([0]);
        await expectLater(verify(), throwsFormatException);
        File('${app.path}/embedded.mobileprovision').writeAsBytesSync(profile);
        final info = await readPlist('${app.path}/Info.plist');
        info['CFBundleVersion'] = '8';
        File('${app.path}/Info.plist').writeAsStringSync(encodePlist(info));
        await expectLater(verify(), throwsFormatException);
      });
    },
  );
}
