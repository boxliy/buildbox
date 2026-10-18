#!/usr/bin/env python3
"""Canonical Build Spec v1 identity shared with Hawk's fixed test vector."""
import base64
import hashlib
import json
import re
import sys


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def integer(value):
    number = int(value)
    if abs(number) > 9007199254740991:
        raise ValueError('non-interoperable JSON integer')
    return number


def reject(value):
    raise ValueError('non-integer JSON number')


def load(text):
    return json.loads(text, object_pairs_hook=pairs, parse_int=integer, parse_float=reject, parse_constant=reject)


def digest(config):
    if type(config.get('schemaVersion')) is not int or config['schemaVersion'] != 1:
        raise ValueError('unsupported Build Spec version')
    identity = {key: value for key, value in config.items() if key != 'artifactPrefix'}
    body = json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
    return 'sha256:' + hashlib.sha256(body).hexdigest()


def validate(config):
    """Reject unknown current-v1 inputs before preparing any application source."""
    allowed = {'schemaVersion', 'tenantId', 'appId', 'releaseId', 'releaseRevision', 'platform', 'targets',
               'commitSha', 'sourceRepo', 'appProfile', 'artifactPrefix', 'frozenInputs', 'appDisplayName',
               'appName', 'appSlug', 'tenantSlug', 'applicationIdentifier', 'androidApplicationId', 'iosBundleId',
               'dartDefines', 'storageProfileId', 'storageProfileRevision', 'signing', 'bundledReleaseCanonicalJson',
               'packagingRevision', 'brandResources', 'swanConfig'}
    if set(config) - allowed:
        raise ValueError('unknown Build Spec field')
    targets = config.get('targets')
    platform = config.get('platform', 'ios' if targets == ['ipa'] else 'android')
    if (not isinstance(targets, list) or not targets or targets != sorted(set(targets))
            or not set(targets) <= {'android': {'aab', 'apk'}, 'ios': {'ipa'}}.get(platform, set())):
        raise ValueError('invalid platform targets')
    for key in ('tenantId', 'appId', 'releaseId', 'storageProfileId'):
        if key in config and (not isinstance(config[key], str) or not re.fullmatch(r'[1-9][0-9]*', config[key]) or int(config[key]) > 9223372036854775807):
            raise ValueError('IDs must be canonical decimal strings')
    frozen = config['frozenInputs']
    fields = {'tenantId', 'appId', 'platform', 'sourceRepo', 'commitSha', 'flutterVersion', 'fvmrc',
              'versionName', 'buildNumber', 'brandAssets', 'builtinResources', 'languages', 'signingReference',
              'xcodeBuild', 'iosComponentTargets'}
    if set(frozen) - fields:
        raise ValueError('unknown frozen input')
    for key in ('tenantId', 'appId', 'sourceRepo', 'commitSha', 'platform'):
        if key in config and frozen[key] != config[key]:
            raise ValueError('frozen scope mismatch')
    if (not re.fullmatch(r'[0-9a-f]{40}', frozen['commitSha'])
            or type(frozen['buildNumber']) is not int or not 1 <= frozen['buildNumber'] <= 2100000000):
        raise ValueError('invalid frozen version or source')
    for key in ('flutterVersion', 'versionName'):
        if not re.fullmatch(r'[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}', frozen[key]):
            raise ValueError('invalid frozen version')
    if platform == 'ios':
        if not re.fullmatch(r'[A-Za-z0-9]{1,32}', frozen.get('xcodeBuild', '')):
            raise ValueError('missing fixed Xcode build')
    elif frozen.get('xcodeBuild') is not None or frozen.get('iosComponentTargets'):
        raise ValueError('iOS inputs on Android')
    resource = frozen['fvmrc']
    if (set(resource) != {'path', 'sha256'} or resource['path'] != 'waterfowl/.fvmrc'
            or not re.fullmatch(r'[0-9a-f]{64}', resource['sha256'])):
        raise ValueError('invalid fixed Flutter configuration')
    if not re.fullmatch(r'signing:[A-Za-z0-9:._-]{1,120}', frozen['signingReference']):
        raise ValueError('invalid signing reference')
    components = frozen.get('iosComponentTargets', {})
    if (not isinstance(components, dict) or len(components) > 32
            or len(set(components.values())) != len(components)
            or any(not re.fullmatch(r'[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*', suffix)
                   or len(suffix) > 128 or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', target)
                   or target == 'Runner' for suffix, target in components.items())):
        raise ValueError('invalid native component targets')
    for group in ('brandAssets', 'builtinResources', 'languages'):
        values = frozen[group]
        paths = [v['path'] for v in values]
        if not 1 <= len(values) <= 256 or paths != sorted(set(paths)):
            raise ValueError('invalid resource group')
        for value in values:
            if (set(value) != {'path', 'sha256'} or not re.fullmatch(r'waterfowl/[A-Za-z0-9/._@-]+', value['path'])
                    or len(value['path']) > 512 or any(p in ('', '.', '..') for p in value['path'].split('/'))
                    or not re.fullmatch(r'[0-9a-f]{64}', value['sha256'])):
                raise ValueError('invalid resource reference')
    brand = config.get('brandResources', [])
    paths = [item['path'] for item in brand]
    if paths and paths != ['waterfowl/.aviary-brand/icon.png', 'waterfowl/.aviary-brand/launch.png']:
        raise ValueError('invalid frozen brand paths')
    for item in brand:
        if set(item) != {'resourceId', 'revision', 'path', 'sha256', 'contentBase64'}:
            raise ValueError('unknown frozen brand input')
        body = base64.b64decode(item['contentBase64'], validate=True)
        if not 0 < len(body) <= 8388608 or hashlib.sha256(body).hexdigest() != item['sha256']:
            raise ValueError('frozen brand digest mismatch')
    signing = config.get('signing', {})
    if signing.get('source') == 'tenant':
        if set(signing) - {'source', 'versionId', 'assetId', 'version', 'certificateSha256', 'alias',
                           'purpose', 'distributionMethod', 'teamId', 'materials', 'components'}:
            raise ValueError('unknown signing input')
        if not re.fullmatch(r'[0-9a-f]{64}', signing['certificateSha256']):
            raise ValueError('invalid signing certificate')
        if platform == 'android':
            if (signing['purpose'], signing['distributionMethod']) not in (('direct', 'direct'), ('play_upload', 'play')):
                raise ValueError('Android signing purpose mismatch')
        elif (signing['purpose'] != 'apple_distribution' or signing['distributionMethod'] not in
              ('development', 'ad-hoc', 'enterprise', 'app-store')):
            raise ValueError('invalid Apple distribution')
    return config


if __name__ == '__main__':
    try:
        with open(sys.argv[1]) as stream:
            print(digest(validate(load(stream.read())['config'])))
    except (ValueError, KeyError, OSError, IndexError, TypeError, AttributeError):
        raise SystemExit('invalid Build Spec v1 identity')
