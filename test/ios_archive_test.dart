import 'dart:io';
import 'package:test/test.dart';
import 'package:buildbox_tools/src/core.dart';
import 'package:buildbox_tools/src/archive.dart';
import 'package:buildbox_tools/src/ios.dart';
import 'sign_ios_test.dart' show metadata, createApp;

void main() {
  test(
    'unsigned device transport keeps executable modes and exact child identity privacy',
    () async {
      await temporary('test-ios-transport-', (dir) async {
        final host = metadata(),
            child = {
              ...metadata(),
              'applicationIdentifier': 'com.example.swan.widget',
              'deviceCapabilities': <dynamic>[],
            };
        final build = Directory('${dir.path}/iphoneos')..createSync(),
            app = Directory('${build.path}/Runner.app'),
            nested = Directory('${app.path}/PlugIns/Widget.appex');
        await createApp(app, host);
        await createApp(nested, child);
        await tool(['chmod', '755', '${app.path}/Runner']);
        await tool(['chmod', '755', '${nested.path}/Runner']);
        final output = '${dir.path}/unsigned.ipa';
        await packageIos(build.path, output, {
          'config': {
            'appDisplayName': host['appDisplayName'],
            'appProfile': host,
            'signing': {
              'source': 'tenant',
              'components': [child],
            },
          },
        });
        final zip = checkedZip(output),
            restored = Directory('${dir.path}/restored');
        extractProduct(zip, restored);
        final restoredApp = Directory('${restored.path}/Payload/Runner.app');
        expect(
          (await componentApps(restoredApp, {
            ...host,
            'components': [child],
          })).length,
          2,
        );
        expect(
          File('${restoredApp.path}/Runner').statSync().mode & 0x49,
          isNot(0),
        );
        expect(
          zip.map((e) => e.name),
          contains('Payload/Runner.app/PlugIns/Widget.appex/Info.plist'),
        );
        expect(
          zip.map((e) => e.name).any((name) => name.contains('_CodeSignature')),
          false,
        );
      });
    },
  );
  test('unsigned archive refuses symlinks and multiple host apps', () async {
    await temporary('test-ios-unsafe-', (dir) async {
      final root = Directory('${dir.path}/root')..createSync();
      final file = File('${root.path}/normal')..writeAsStringSync('x');
      Link('${root.path}/link').createSync(file.path);
      expect(
        () => zipTree(root, '${dir.path}/unsafe.ipa'),
        throwsFormatException,
      );
      final build = Directory('${dir.path}/iphoneos')..createSync();
      Directory('${build.path}/One.app').createSync();
      Directory('${build.path}/Two.app').createSync();
      await expectLater(
        packageIos(build.path, '${dir.path}/multiple.ipa', {}),
        throwsFormatException,
      );
    });
  });

  test('packageIos strips pre-signed framework signatures', () async {
    await temporary('test-ios-strip-', (dir) async {
      final host = metadata();
      final build = Directory('${dir.path}/iphoneos')..createSync(),
          app = Directory('${build.path}/Runner.app'),
          signature = Directory(
            '${app.path}/Frameworks/Flutter.framework/_CodeSignature',
          );
      await createApp(app, host);
      signature.createSync(recursive: true);
      File('${signature.path}/CodeResources').writeAsStringSync('signed');
      File(
        '${app.path}/Frameworks/Flutter.framework/embedded.mobileprovision',
      ).writeAsBytesSync([1, 2, 3]);
      final output = '${dir.path}/unsigned.ipa';
      await packageIos(build.path, output, {
        'config': {
          'appDisplayName': host['appDisplayName'],
          'appProfile': host,
          'signing': {'source': 'tenant', 'components': <dynamic>[]},
        },
      });
      final names = checkedZip(output).map((entry) => entry.name);
      expect(names.any((name) => name.contains('_CodeSignature')), false);
      expect(
        names.any((name) => name.endsWith('embedded.mobileprovision')),
        false,
      );
    });
  });
}
