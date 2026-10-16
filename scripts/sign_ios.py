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
import shutil
import tempfile
import zipfile

from sign_android import checked_zip, request, run


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
    # Store transport and enterprise distribution require separate authorization.
    if method not in ('development', 'ad-hoc') or not profile.get('ProvisionedDevices'):
        raise ValueError('only device-scoped development or ad-hoc profiles are supported')
    if bool(entitlements.get('get-task-allow')) != (method == 'development'):
        raise ValueError('profile distribution mismatch')
    if any('*' in str(value) for value in entitlements.values()):
        raise ValueError('wildcard entitlements must be resolved before signing')
    return entitlements


def validate_app(app, metadata):
    with (app / 'Info.plist').open('rb') as stream:
        info = plistlib.load(stream)
    if (info.get('CFBundleIdentifier'), info.get('CFBundleShortVersionString'), str(info.get('CFBundleVersion'))) != (
            metadata['applicationIdentifier'], metadata['versionName'], str(metadata['buildNumber'])):
        raise ValueError('iOS identity or version mismatch')
    executable = info.get('CFBundleExecutable', '')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', executable) or not (app / executable).is_file():
        raise ValueError('invalid iOS executable')
    if info.get('CFBundleSupportedPlatforms') != ['iPhoneOS']:
        raise ValueError('simulator products cannot be signed as device apps')
    if (app / 'PlugIns').exists() or (app / 'Watch').exists():
        raise ValueError('extensions require their own frozen signing profiles')
    if any(p.name in ('_CodeSignature', 'embedded.mobileprovision') for p in app.rglob('*')):
        raise ValueError('compile product must be unsigned')


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
        product = private / 'product'
        with zipfile.ZipFile(source) as archive:
            for entry in archive.infolist():
                parts = Path(entry.filename).parts
                if len(parts) < 2 or parts[0] != 'Payload' or not parts[1].endswith('.app'):
                    raise ValueError('unexpected archive layout')
            archive.extractall(product)
        apps = list((product / 'Payload').iterdir())
        if len(apps) != 1 or not apps[0].is_dir():
            raise ValueError('exactly one device app required')
        app = apps[0]
        validate_app(app, metadata)
        p12, provision = private / 'identity.p12', private / 'profile.mobileprovision'
        p12.write_bytes(base64.b64decode(material['containerBase64'], validate=True))
        provision.write_bytes(base64.b64decode(material['provisioningProfileBase64'], validate=True))
        profile = plistlib.loads(run(['security', 'cms', '-D', '-i', str(provision)]).encode())
        env = dict(os.environ, IOS_CONTAINER_PASSWORD=material['password'])
        pem = run(['openssl', 'pkcs12', '-in', str(p12), '-clcerts', '-nokeys', '-passin', 'env:IOS_CONTAINER_PASSWORD'], env)
        import ssl
        match = re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', pem, re.S)
        if not match:
            raise ValueError('missing signing certificate')
        certificate = ssl.PEM_cert_to_DER_cert(match.group())
        if hashlib.sha256(certificate).hexdigest() != metadata['certificateSha256']:
            raise ValueError('certificate fingerprint mismatch')
        entitlements = validate_profile(profile, metadata, certificate)
        entitlement_file = private / 'entitlements.plist'
        entitlement_file.write_bytes(plistlib.dumps(entitlements))
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
            shutil.copyfile(provision, app / 'embedded.mobileprovision')
            run(common + ['--entitlements', str(entitlement_file), str(app)])
            run(['codesign', '--verify', '--deep', '--strict', str(app)])
            prefix = private / 'verified-cert-'
            run(['codesign', '--display', '--extract-certificates', str(prefix), str(app)])
            if hashlib.sha256(Path(str(prefix) + '0').read_bytes()).hexdigest() != metadata['certificateSha256']:
                raise ValueError('signed app certificate mismatch')
            destination = state / 'artifacts' / 'swan-release.ipa'
            destination.parent.mkdir(exist_ok=True)
            if destination.exists() or destination.is_symlink():
                raise ValueError('output exists')
            with zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED) as archive:
                for item in sorted(product.rglob('*')):
                    if item.is_file():
                        archive.write(item, item.relative_to(product))
        finally:
            run(['security', 'delete-keychain', str(keychain)])
    with destination.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    size = destination.stat().st_size
    request(f'/api/v1/buildbox/runs/{run_id}/signing-proofs', {
        'target': 'ipa', 'signingVersionId': metadata['versionId'], 'certificateSha256': metadata['certificateSha256'],
        'sha256': digest, 'byteSize': size})
    artifacts = [{'target': 'ipa', 'fileName': destination.name, 'sha256': 'sha256:' + digest, 'byteSize': size, 'signMode': 'signed'}]
    (state / 'artifacts.json').write_text(json.dumps(artifacts))
    (state / 'sign-proof.json').write_text(json.dumps({'signer': 'apple-codesign', 'runId': run_id, 'specHash': metadata['specHash'], 'artifacts': artifacts}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('sign-ios: signing failed; no signed delivery was authorized')
