import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from configure_ios import configure


class NativeTargetTests(unittest.TestCase):
    def test_exact_target_identity_version_and_unsigned_archive_settings(self):
        project = {'objects': {}}
        for name, product in [('Runner', 'application'), ('Share', 'app-extension')]:
            project['objects'].update({name: {'isa': 'PBXNativeTarget', 'name': name,
                'productType': 'com.apple.product-type.' + product, 'buildConfigurationList': name + '-list'},
                name + '-list': {'buildConfigurations': [name + '-release']},
                name + '-release': {'buildSettings': {}}})
        spec = {'applicationIdentifier': 'com.example.app', 'appDisplayName': 'Fixture App',
                'frozenInputs': {'versionName': '1.2.3', 'buildNumber': 42, 'iosComponentTargets': {'share': 'Share'}},
                'signing': {'teamId': 'TEAM123456', 'components': [{'applicationIdentifier': 'com.example.app.share'}]}}
        configured = configure(copy.deepcopy(project), spec)
        for name, identifier in [('Runner', 'com.example.app'), ('Share', 'com.example.app.share')]:
            settings = configured['objects'][name + '-release']['buildSettings']
            self.assertEqual(settings['PRODUCT_BUNDLE_IDENTIFIER'], identifier)
            self.assertEqual(settings['CURRENT_PROJECT_VERSION'], '42')
            self.assertEqual(settings['MARKETING_VERSION'], '1.2.3')
            self.assertEqual(settings['DEVELOPMENT_TEAM'], 'TEAM123456')
            self.assertEqual(settings['CODE_SIGNING_ALLOWED'], 'NO')
        for target in ('Missing', 'Runner'):
            invalid = copy.deepcopy(spec)
            invalid['frozenInputs']['iosComponentTargets']['share'] = target
            with self.assertRaises(ValueError):
                configure(copy.deepcopy(project), invalid)
