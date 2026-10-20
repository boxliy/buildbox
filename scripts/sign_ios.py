#!/usr/bin/env python3
"""Sign an unsigned device app on an isolated macOS runner, without build scripts."""
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import tempfile
import zipfile

from sign_android import checked_zip, request, run
from bluetooth_usage import BLUETOOTH_KEYS, bluetooth_usage


def distribution_method(profile):
    devices = profile.get('ProvisionedDevices')
    if devices is not None and (not isinstance(devices, list) or not devices
                               or any(not isinstance(d, str) or not d for d in devices)):
        raise ValueError('invalid provisioning devices')
    all_devices = profile.get('ProvisionsAllDevices', False)
    task_allow = profile.get('Entitlements', {}).get('get-task-allow', False)
    if type(all_devices) is not bool or type(task_allow) is not bool:
        raise ValueError('invalid provisioning distribution flags')
    if all_devices and not devices and not task_allow:
        return 'enterprise'
    if not all_devices and not devices and not task_allow:
        return 'app-store'
    if devices and not all_devices:
        return 'development' if task_allow else 'ad-hoc'
    raise ValueError('inconsistent provisioning distribution')


def validate_profile(profile, metadata, certificate):
    expected = metadata['teamId'] + '.' + metadata['applicationIdentifier']
    entitlements = profile.get('Entitlements', {})
    if (profile.get('TeamIdentifier') != [metadata['teamId']]
            or entitlements.get('application-identifier') != expected
            or entitlements.get('com.apple.developer.team-identifier') != metadata['teamId']
            or certificate not in profile.get('DeveloperCertificates', [])
            or profile.get('ExpirationDate', datetime.datetime.min) <= datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)):
        raise ValueError('profile identity, certificate or expiry mismatch')
    method = metadata['distributionMethod']
    if distribution_method(profile) != method:
        raise ValueError('profile distribution mismatch')
    # Grant only the fixed App capability set, never every privilege in a profile.
    requested = {
        'application-identifier': expected,
        'com.apple.developer.team-identifier': metadata['teamId'],
        'get-task-allow': method == 'development',
    }
    capabilities = {item['key'] for item in metadata.get('deviceCapabilities', [])}
    supported = {'camera.capture', 'microphone.record', 'location.foreground',
                 'location.background', 'notifications.push', 'photos.read',
                 'photos.write', 'biometrics.authenticate', 'background.execution'}
    if not capabilities <= supported | set(BLUETOOTH_KEYS):
        raise ValueError('unsupported iOS native capability')
    if 'notifications.push' in capabilities:
        requested['aps-environment'] = 'development' if method == 'development' else 'production'
    if any(entitlements.get(key) != value for key, value in requested.items()):
        raise ValueError('profile does not permit frozen entitlements')
    return requested


def validate_app(app, metadata):
    with (app / 'Info.plist').open('rb') as stream:
        info = plistlib.load(stream)
    if (info.get('CFBundleIdentifier'), info.get('CFBundleShortVersionString'), str(info.get('CFBundleVersion'))) != (
            metadata['applicationIdentifier'], metadata['versionName'], str(metadata['buildNumber'])):
        raise ValueError('iOS identity or version mismatch')
    if metadata.get('appDisplayName') and info.get('CFBundleDisplayName') != metadata['appDisplayName']:
        raise ValueError('iOS display name mismatch')
    usage = {'camera.capture': 'NSCameraUsageDescription', 'microphone.record': 'NSMicrophoneUsageDescription',
             'location.foreground': 'NSLocationWhenInUseUsageDescription', 'location.background': 'NSLocationAlwaysAndWhenInUseUsageDescription',
             'photos.read': 'NSPhotoLibraryUsageDescription', 'photos.write': 'NSPhotoLibraryAddUsageDescription',
             'biometrics.authenticate': 'NSFaceIDUsageDescription'}
    for capability in metadata.get('deviceCapabilities', []):
        if metadata.get('source') == 'tenant' and capability['key'] in usage:
            description = next((p['description'] for p in capability.get('purposes', []) if p['locale'] == metadata.get('defaultLocale')), None)
            if not description or info.get(usage[capability['key']]) != description:
                raise ValueError('iOS usage description mismatch')
    if metadata.get('source') == 'tenant':
        for key, description in bluetooth_usage(metadata.get('deviceCapabilities', []), metadata.get('defaultLocale')).items():
            if info.get(key) != description:
                raise ValueError('iOS Bluetooth usage description mismatch')
        for localization in metadata.get('localizations', []):
            locale = localization['locale']
            if not re.fullmatch(r'[A-Za-z0-9-]+', locale):
                raise ValueError('invalid native localization')
            expected = bluetooth_usage(metadata.get('deviceCapabilities', []), locale,
                fallback_locale=metadata.get('defaultLocale'))
            if expected:
                try:
                    localized = plistlib.loads((app / (locale + '.lproj') / 'InfoPlist.strings').read_bytes())
                except (OSError, plistlib.InvalidFileException) as error:
                    raise ValueError('missing or invalid localized Bluetooth usage description') from error
                if any(localized.get(key) != description for key, description in expected.items()):
                    raise ValueError('localized Bluetooth usage description mismatch')
    executable = info.get('CFBundleExecutable', '')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', executable) or not (app / executable).is_file():
        raise ValueError('invalid iOS executable')
    if info.get('CFBundleSupportedPlatforms') != ['iPhoneOS']:
        raise ValueError('simulator products cannot be signed as device apps')
    if any(p.name in ('_CodeSignature', 'embedded.mobileprovision') for p in app.rglob('*')):
        raise ValueError('compile product must be unsigned')


def component_apps(app, metadata):
    """Match every nested app/extension to an exact frozen identity and profile."""
    actual = [app] + sorted((p for p in app.rglob('*') if p.suffix in ('.app', '.appex')),
                            key=lambda p: len(p.parts), reverse=True)
    components = metadata.get('components', [])
    by_id = {c['applicationIdentifier']: c for c in components}
    if len(by_id) != len(components) or metadata['applicationIdentifier'] in by_id:
        raise ValueError('duplicate component identity')
    found, result = set(), []
    for product in actual:
        info = plistlib.loads((product / 'Info.plist').read_bytes())
        identifier = info.get('CFBundleIdentifier')
        if product == app:
            component = metadata
        else:
            if identifier not in by_id or not identifier.startswith(metadata['applicationIdentifier'] + '.'):
                raise ValueError('unconfigured nested component')
            component = dict(metadata, **by_id[identifier])
            # Component privileges must be explicit; never inherit the host set.
            component['deviceCapabilities'] = by_id[identifier].get('deviceCapabilities', [])
            if identifier in found:
                raise ValueError('duplicate nested identity')
            found.add(identifier)
        validate_app(product, component)
        result.append((product, component))
    if found != set(by_id):
        raise ValueError('configured component missing from product')
    return sorted(result, key=lambda pair: len(pair[0].parts), reverse=True)


def verify_signed(product, metadata, certificate, entitlements, profile_bytes, private):
    """Inspect the actual signature and embedded provisioning of each component."""
    run(['codesign', '--verify', '--strict', str(product)])
    prefix = private / 'verified-cert-'
    run(['codesign', '--display', '--extract-certificates', str(prefix), str(product)])
    if Path(str(prefix) + '0').read_bytes() != certificate:
        raise ValueError('signed code certificate mismatch')
    actual = plistlib.loads(run(['codesign', '--display', '--entitlements', ':-', str(product)]).encode())
    if actual != entitlements:
        raise ValueError('signed entitlements mismatch')
    if (product / 'embedded.mobileprovision').read_bytes() != profile_bytes:
        raise ValueError('embedded profile mismatch')
    validate_signed_info = plistlib.loads((product / 'Info.plist').read_bytes())
    if (validate_signed_info.get('CFBundleIdentifier'), validate_signed_info.get('CFBundleShortVersionString'),
            str(validate_signed_info.get('CFBundleVersion'))) != (
            metadata['applicationIdentifier'], metadata['versionName'], str(metadata['buildNumber'])):
        raise ValueError('signed component identity mismatch')


def main():
    os.umask(0o077)
    if os.uname().sysname != 'Darwin':
        raise ValueError('iOS signing requires macOS')
    state = Path(os.environ['BUILDBOX_STATE_DIR'])
    run_id = os.environ['BUILDBOX_RUN_ID']
    if not re.fullmatch(r'[1-9][0-9]*', run_id):
        raise ValueError('invalid platform run')
    response = request(f'/api/v1/buildbox/runs/{run_id}/signing-material')
    metadata, material = response['metadata'], response['material']
    if metadata['platform'] != 'ios' or metadata['targets'] != ['ipa'] or metadata['runId'] != run_id:
        raise ValueError('iOS signing scope mismatch')
    source = state / 'unsigned' / 'swan-release.ipa'
    checked_zip(source)
    with tempfile.TemporaryDirectory(prefix='ios-sign-') as temporary:
        private = Path(temporary)
        extraction_root = private / 'product'
        with zipfile.ZipFile(source) as archive:
            for entry in archive.infolist():
                parts = Path(entry.filename).parts
                if len(parts) < 2 or parts[0] != 'Payload' or not parts[1].endswith('.app'):
                    raise ValueError('unexpected archive layout')
            archive.extractall(extraction_root)
            # zipfile intentionally ignores Unix modes; device executables need
            # their validated executable bits restored before codesign.
            for entry in archive.infolist():
                extracted = extraction_root / entry.filename
                if extracted.is_file():
                    extracted.chmod(0o755 if (entry.external_attr >> 16) & 0o111 else 0o644)
        apps = list((extraction_root / 'Payload').iterdir())
        if len(apps) != 1 or not apps[0].is_dir():
            raise ValueError('exactly one device app required')
        app = apps[0]
        products = component_apps(app, metadata)
        p12 = private / 'identity.p12'
        p12.write_bytes(base64.b64decode(material['containerBase64'], validate=True))
        env = dict(os.environ, IOS_CONTAINER_PASSWORD=material['password'])
        pem = run(['openssl', 'pkcs12', '-in', str(p12), '-clcerts', '-nokeys', '-passin', 'env:IOS_CONTAINER_PASSWORD'], env)
        import ssl
        match = re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', pem, re.S)
        if not match:
            raise ValueError('missing signing certificate')
        certificate_file = private / 'certificate.pem'
        certificate_file.write_text(match.group())
        run(['openssl', 'x509', '-in', str(certificate_file), '-checkend', '0', '-noout'])
        certificate = ssl.PEM_cert_to_DER_cert(match.group())
        if hashlib.sha256(certificate).hexdigest() != metadata['certificateSha256']:
            raise ValueError('certificate fingerprint mismatch')
        signing = []
        profile_material = {c['applicationIdentifier']: c['provisioningProfileBase64']
                            for c in material.get('components', [])}
        for index, (product, component) in enumerate(products):
            encoded = (material['provisioningProfileBase64'] if product == app
                       else profile_material[component['applicationIdentifier']])
            profile_bytes = base64.b64decode(encoded, validate=True)
            provision = private / f'profile-{index}.mobileprovision'
            provision.write_bytes(profile_bytes)
            profile = plistlib.loads(run(['security', 'cms', '-D', '-i', str(provision)]).encode())
            if component.get('profileSha256') and hashlib.sha256(profile_bytes).hexdigest() != component['profileSha256']:
                raise ValueError('profile fingerprint mismatch')
            if component.get('profileUuid') and profile.get('UUID') != component['profileUuid']:
                raise ValueError('profile UUID mismatch')
            entitlements = validate_profile(profile, component, certificate)
            entitlement_file = private / f'entitlements-{index}.plist'
            entitlement_file.write_bytes(plistlib.dumps(entitlements))
            signing.append((product, component, profile_bytes, entitlement_file, entitlements))
        keychain = private / 'signing.keychain-db'
        password = secrets.token_hex(32)
        run(['security', 'create-keychain', '-p', password, str(keychain)])
        try:
            run(['security', 'unlock-keychain', '-p', password, str(keychain)])
            run(['security', 'import', str(p12), '-k', str(keychain), '-P', material['password'], '-T', '/usr/bin/codesign'])
            run(['security', 'set-key-partition-list', '-S', 'apple-tool:,apple:', '-s', '-k', password, str(keychain)])
            identity = hashlib.sha1(certificate).hexdigest()
            common = ['codesign', '--force', '--sign', identity, '--keychain', str(keychain), '--timestamp=none']
            # Sign nested native code from the inside out; never invoke xcodebuild here.
            nested = sorted([p for p in app.rglob('*') if p.suffix in ('.framework', '.dylib')], key=lambda p: len(p.parts), reverse=True)
            for item in nested:
                run(common + [str(item)])
            for product, component, profile_bytes, entitlement_file, entitlements in signing:
                (product / 'embedded.mobileprovision').write_bytes(profile_bytes)
                run(common + ['--entitlements', str(entitlement_file), str(product)])
                verify_signed(product, component, certificate, entitlements, profile_bytes, private)
            for item in nested:
                run(['codesign', '--verify', '--strict', str(item)])
                prefix = private / 'nested-cert-'
                run(['codesign', '--display', '--extract-certificates', str(prefix), str(item)])
                if Path(str(prefix) + '0').read_bytes() != certificate:
                    raise ValueError('nested code certificate mismatch')
            run(['codesign', '--verify', '--deep', '--strict', str(app)])
            destination = state / 'artifacts' / 'swan-release.ipa'
            destination.parent.mkdir(exist_ok=True)
            if destination.exists() or destination.is_symlink():
                raise ValueError('output exists')
            with zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED) as archive:
                for item in sorted(extraction_root.rglob('*')):
                    if item.is_file():
                        archive.write(item, item.relative_to(extraction_root))
        finally:
            run(['security', 'delete-keychain', str(keychain)])
    with destination.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    size = destination.stat().st_size
    request(f'/api/v1/buildbox/runs/{run_id}/signing-proofs', {
        'target': 'ipa', 'signingVersionId': metadata['versionId'], 'certificateSha256': metadata['certificateSha256'],
        'sha256': digest, 'byteSize': size,
        'components': [{'applicationIdentifier': c['applicationIdentifier'],
                        'profileVersionId': c.get('profileVersionId'),
                        'profileUuid': c.get('profileUuid'),
                        'entitlements': e} for _, c, _, _, e in signing]})
    artifacts = [{'target': 'ipa', 'fileName': destination.name, 'sha256': 'sha256:' + digest, 'byteSize': size, 'signMode': 'signed'}]
    (state / 'artifacts.json').write_text(json.dumps(artifacts))
    (state / 'sign-proof.json').write_text(json.dumps({'signer': 'apple-codesign', 'runId': run_id, 'specHash': metadata['specHash'], 'artifacts': artifacts}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('sign-ios: signing failed; no signed delivery was authorized')
