#!/usr/bin/env python3
"""Freeze Xcode target settings before archive, on the credential-free runner."""
import json
from pathlib import Path
import plistlib
import subprocess
import sys


def configure(project, spec):
    identity = spec['applicationIdentifier']
    inputs, signing = spec['frozenInputs'], spec['signing']
    targets = {'Runner': identity}
    for component in signing.get('components', []):
        bundle = component['applicationIdentifier']
        if bundle == identity:
            continue
        if not bundle.startswith(identity + '.'):
            raise ValueError('component identity mismatch')
        target = inputs['iosComponentTargets'][bundle[len(identity) + 1:]]
        if target in targets:
            raise ValueError('duplicate native target')
        targets[target] = bundle
    objects = project['objects']
    for name, bundle in targets.items():
        matches = [t for t in objects.values() if t.get('isa') == 'PBXNativeTarget' and t.get('name') == name]
        if len(matches) != 1 or matches[0].get('productType') not in (
                'com.apple.product-type.application', 'com.apple.product-type.app-extension'):
            raise ValueError('native target missing, ambiguous or unsupported')
        configuration_list = objects[matches[0]['buildConfigurationList']]
        for reference in configuration_list['buildConfigurations']:
            settings = objects[reference]['buildSettings']
            settings.update(PRODUCT_BUNDLE_IDENTIFIER=bundle,
                            MARKETING_VERSION=inputs['versionName'],
                            CURRENT_PROJECT_VERSION=str(inputs['buildNumber']),
                            INFOPLIST_KEY_CFBundleDisplayName=spec['appDisplayName'],
                            DEVELOPMENT_TEAM=signing['teamId'],
                            CODE_SIGNING_ALLOWED='NO', CODE_SIGNING_REQUIRED='NO')
    return project


def main():
    spec = json.loads(Path(sys.argv[1]).read_text())['config']
    project = Path(sys.argv[2]) / 'project.pbxproj'
    if project.is_symlink():
        raise ValueError('unsafe Xcode project')
    # macOS plutil reads Xcode's OpenStep property list. Xcode also reads XML
    # property lists; no third-party parser or application-supplied script runs.
    body = subprocess.check_output(['plutil', '-convert', 'json', '-o', '-', str(project)])
    project.write_bytes(plistlib.dumps(configure(json.loads(body), spec)))


if __name__ == '__main__':
    main()
