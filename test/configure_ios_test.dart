import 'dart:convert';
import 'package:test/test.dart';
import 'package:buildbox_tools/src/core.dart';
import 'package:buildbox_tools/src/ios.dart';

void main() {
  Json projectRaw() => {
    'objects': {
      'runner': {
        'isa': 'PBXNativeTarget',
        'name': 'Runner',
        'productType': 'com.apple.product-type.application',
        'buildConfigurationList': 'runner-list',
      },
      'widget': {
        'isa': 'PBXNativeTarget',
        'name': 'Widget',
        'productType': 'com.apple.product-type.app-extension',
        'buildConfigurationList': 'widget-list',
      },
      'runner-list': {
        'buildConfigurations': ['runner-debug', 'runner-release'],
      },
      'widget-list': {
        'buildConfigurations': ['widget-release'],
      },
      'runner-debug': {'buildSettings': {}},
      'runner-release': {'buildSettings': {}},
      'widget-release': {'buildSettings': {}},
    },
  };
  Json specRaw() => {
    'applicationIdentifier': 'com.example.app',
    'appDisplayName': 'Tenant App',
    'frozenInputs': {
      'versionName': '1.2.3',
      'buildNumber': 7,
      'iosComponentTargets': {'widget': 'Widget'},
    },
    'signing': {
      'teamId': 'ABCDEFGHIJ',
      'components': [
        {'applicationIdentifier': 'com.example.app.widget'},
      ],
    },
  };
  Json project() => strictJson(jsonEncode(projectRaw())) as Json;
  Json spec() => strictJson(jsonEncode(specRaw())) as Json;
  test(
    'exact target identities version team and unsigned archive settings',
    () {
      final p = configureProject(project(), spec());
      for (final key in ['runner-debug', 'runner-release', 'widget-release']) {
        final settings = p['objects'][key]['buildSettings'];
        expect(
          settings['PRODUCT_BUNDLE_IDENTIFIER'],
          key.startsWith('widget')
              ? 'com.example.app.widget'
              : 'com.example.app',
        );
        expect(settings['MARKETING_VERSION'], '1.2.3');
        expect(settings['CURRENT_PROJECT_VERSION'], '7');
        expect(settings['INFOPLIST_KEY_CFBundleDisplayName'], 'Tenant App');
        expect(settings['DEVELOPMENT_TEAM'], 'ABCDEFGHIJ');
        expect(settings['CODE_SIGNING_ALLOWED'], 'NO');
        expect(settings['CODE_SIGNING_REQUIRED'], 'NO');
      }
    },
  );
  test(
    'missing ambiguous unsupported and mismatched native targets reject',
    () {
      final missing = project();
      missing['objects'].remove('widget');
      expect(() => configureProject(missing, spec()), throwsFormatException);
      final ambiguous = project();
      ambiguous['objects']['other'] = {
        ...ambiguous['objects']['runner'] as Json,
      };
      expect(() => configureProject(ambiguous, spec()), throwsFormatException);
      final unsupported = project();
      unsupported['objects']['widget']['productType'] =
          'com.apple.product-type.library.static';
      expect(
        () => configureProject(unsupported, spec()),
        throwsFormatException,
      );
      final mismatch = spec();
      mismatch['signing']['components'][0]['applicationIdentifier'] =
          'com.other.widget';
      expect(
        () => configureProject(project(), mismatch),
        throwsFormatException,
      );
    },
  );
}
