#!/usr/bin/env python3
"""Canonical versioned Build Spec identity shared with Hawk's fixed test vector."""
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
    if type(config.get('schemaVersion')) is not int or config['schemaVersion'] not in (1, 2):
        raise ValueError('unsupported Build Spec version')
    identity = {key: value for key, value in config.items() if key != 'artifactPrefix'}
    body = json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
    return 'sha256:' + hashlib.sha256(body).hexdigest()


def validate(config):
    """Validate versioned frozen inputs before preparing application source."""
    allowed = {'schemaVersion', 'tenantId', 'appId', 'releaseId', 'releaseRevision', 'releaseChannel', 'platform', 'targets',
               'commitSha', 'sourceRepo', 'appProfile', 'artifactPrefix', 'frozenInputs', 'appDisplayName',
               'appName', 'appSlug', 'tenantSlug', 'applicationIdentifier', 'androidApplicationId', 'iosBundleId',
               'dartDefines', 'storageProfileId', 'storageProfileRevision', 'signing', 'bundledReleaseCanonicalJson',
               'packagingRevision', 'brandResources', 'swanConfig'}
    if config.get('schemaVersion') == 2:
        allowed -= {'releaseId', 'releaseRevision', 'releaseChannel', 'bundledReleaseCanonicalJson', 'swanConfig'}
        allowed.add('assembly')
        allowed.add('appConfiguration')
        validate_native(config)
    elif config.get('schemaVersion') != 1 or type(config.get('schemaVersion')) is not int:
        raise ValueError('unsupported Build Spec version')
    if set(config) - allowed:
        raise ValueError('unknown Build Spec field')
    if 'releaseChannel' in config:
        channel = config['releaseChannel']
        if channel not in ('dev', 'canary', 'stable'):
            raise ValueError('invalid frozen release channel')
        revision = config.get('releaseRevision')
        defines = config.get('dartDefines')
        if not isinstance(revision, dict) or not isinstance(defines, dict):
            raise ValueError('missing frozen release channel inputs')
        revision_channel = revision.get('channel')
        define_channel = defines.get('SWAN_RELEASE_CHANNEL')
        if revision_channel != channel or define_channel != channel:
            raise ValueError('frozen release channel mismatch')
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
        if not (0 if config['schemaVersion'] == 2 and group != 'brandAssets' else 1) <= len(values) <= 256 or paths != sorted(set(paths)):
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


def validate_app_configuration(config):
    """Frozen appConfiguration is optional for older Specs and strict when present."""
    block = config.get('appConfiguration')
    if block is None:
        return
    common = {
        'commonSnapshotDigest', 'configurationRevision', 'dependencyFeatures', 'digests',
        'explicitEnabledFeatures', 'identity', 'permissions', 'resolvedFeatures', 'shell', 'signing',
        'targetFacts', 'targets',
    }
    legacy = common | {'bindings', 'themes'}
    current = common | {'appearance'}
    if not isinstance(block, dict) or set(block) not in (legacy, current):
        raise ValueError('unknown app configuration field')
    if _forbidden(block):
        raise ValueError('secret entered the build spec')
    if type(block['configurationRevision']) is not int or block['configurationRevision'] < 1:
        raise ValueError('invalid configuration revision')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', block['commonSnapshotDigest']):
        raise ValueError('invalid common snapshot digest')
    explicit, dependency, resolved = (_features(block[name]) for name in (
        'explicitEnabledFeatures', 'dependencyFeatures', 'resolvedFeatures'))
    if set(explicit) & set(dependency) or set(explicit) | set(dependency) != set(resolved):
        raise ValueError('resolved features must equal the explicit and dependency closure')
    if 'appearance' in block:
        _validate_appearance(block['appearance'], resolved)
    else:
        bindings = _feature_records(block['bindings'], resolved, 'binding')
        themes = _feature_records(block['themes'], resolved, 'theme')
        for key in resolved:
            binding, theme = bindings[key], themes[key]
            presentation = binding.get('presentationKey')
            if not isinstance(presentation, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,79}', presentation):
                raise ValueError('invalid presentation key')
            if (binding.get('presentationKey') != theme.get('presentationKey')
                    or binding.get('themeDigest') != theme.get('digest')
                    or binding.get('theme') != theme
                    or not re.fullmatch(r'sha256:[0-9a-f]{64}', str(theme.get('digest') or ''))):
                raise ValueError('theme digest does not match its binding')
            if theme.get('kind') != 'builtinDefault' and not isinstance(theme.get('tokens'), dict):
                raise ValueError('managed theme is missing tokens')
            if not isinstance(theme.get('assets'), list):
                raise ValueError('theme assets must be a list')
    shell = block['shell']
    if not isinstance(shell, dict) or set(shell) != {'appBar', 'personalCenter', 'startupFeature'}:
        raise ValueError('unknown shell field')
    app_bar = _shell_items(shell['appBar'], resolved)
    personal = _shell_items(shell['personalCenter'], resolved)
    if 'PERSONAL_CENTER' not in resolved and personal:
        raise ValueError('personal center was frozen while disabled')
    visible = [item for item in sorted(app_bar, key=lambda item: item['order']) if item['visible']]
    if not visible or shell.get('startupFeature') not in resolved or visible[0]['featureKey'] != shell['startupFeature']:
        raise ValueError('startup feature must be the first visible app bar entry')
    digests = block['digests']
    if set(digests) != {'capability', 'catalog', 'resource', 'source'} or any(
            not re.fullmatch(r'sha256:[0-9a-f]{64}', digests[key]) for key in digests):
        raise ValueError('invalid configuration digest')
    identity = block['identity']
    if identity.get('platform') != config.get('platform'):
        raise ValueError('app configuration platform mismatch')
    if block.get('targets') != config.get('targets'):
        raise ValueError('app configuration target mismatch')


def _validate_appearance(appearance, resolved):
    if (not isinstance(appearance, dict)
            or set(appearance) != {'contractVersion', 'defaultPresentationKey', 'presentations'}
            or type(appearance.get('contractVersion')) is not int
            or appearance['contractVersion'] != 1):
        raise ValueError('unknown appearance field')
    default = appearance.get('defaultPresentationKey')
    if not isinstance(default, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,79}', default):
        raise ValueError('appearance default presentation is invalid')
    presentations = appearance.get('presentations')
    if not isinstance(presentations, list) or not presentations:
        raise ValueError('appearance presentations must be a non-empty list')
    keys = set()
    previous = None
    for item in presentations:
        if not isinstance(item, dict) or set(item) != {
                'presentationKey', 'styleKey', 'name', 'order', 'directoryRevision',
                'featureKeys', 'defaultThemeKey', 'themes'}:
            raise ValueError('unknown appearance presentation field')
        key = item.get('presentationKey')
        if (not isinstance(key, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,79}', key)
                or key in keys or not isinstance(item.get('styleKey'), str) or not item['styleKey']):
            raise ValueError('appearance presentation identity is invalid')
        keys.add(key)
        if (not isinstance(item.get('name'), str) or not item['name'].strip()
                or type(item.get('directoryRevision')) is not int or item['directoryRevision'] < 1):
            raise ValueError('appearance presentation metadata is invalid')
        order = item.get('order')
        if type(order) is not int:
            raise ValueError('appearance presentation order is invalid')
        current = (order, key)
        if previous is not None and previous >= current:
            raise ValueError('appearance presentations are not stably ordered')
        previous = current
        if _features(item.get('featureKeys')) != resolved:
            raise ValueError('appearance feature keys must equal resolved features')
        default_theme = item.get('defaultThemeKey')
        if not isinstance(default_theme, str) or not default_theme:
            raise ValueError('appearance default theme is invalid')
        themes = item.get('themes')
        if not isinstance(themes, list) or not themes:
            raise ValueError('appearance themes must be a non-empty list')
        theme_keys = set()
        for theme in themes:
            if (not isinstance(theme, dict) or 'featureKey' in theme
                    or theme.get('presentationKey') != key or not isinstance(theme.get('assets'), list)):
                raise ValueError('appearance theme scope is invalid')
            theme_key = theme.get('key')
            if not isinstance(theme_key, str) or not theme_key:
                raise ValueError('appearance theme key is invalid')
            if theme_key in theme_keys:
                raise ValueError('appearance theme is duplicated')
            theme_keys.add(theme_key)
            expected_namespace = (key.lower() if theme.get('kind') == 'builtinDefault'
                                  else f'managed/{key.lower()}/{theme_key}')
            if theme.get('assetNamespace') != expected_namespace:
                raise ValueError('appearance theme asset namespace is invalid')
            theme_digest = theme.get('digest')
            if not isinstance(theme_digest, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', theme_digest):
                raise ValueError('appearance theme digest is invalid')
            content = {name: value for name, value in theme.items() if name != 'digest'}
            body = json.dumps(content, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
            if theme_digest != 'sha256:' + hashlib.sha256(body).hexdigest():
                raise ValueError('appearance theme digest mismatch')
            kind = theme.get('kind')
            if kind not in ('builtinDefault', 'managed'):
                raise ValueError('appearance theme kind is invalid')
            if kind == 'managed' and not isinstance(theme.get('tokens'), dict):
                raise ValueError('managed theme is missing tokens')
        if default_theme not in theme_keys:
            raise ValueError('appearance default theme is unavailable')
    if default not in keys:
        raise ValueError('appearance default presentation is unavailable')


def _feature_records(items, resolved, label):
    if not isinstance(items, list):
        raise ValueError(f'invalid {label}')
    records = {}
    for item in items:
        if not isinstance(item, dict):
            raise ValueError(f'invalid {label}')
        key = item.get('featureKey')
        if not isinstance(key, str) or key in records:
            raise ValueError(f'invalid {label}')
        records[key] = item
    if set(records) != set(resolved):
        raise ValueError(f'each resolved feature needs one {label}')
    return records


def _shell_items(items, resolved):
    if not isinstance(items, list):
        raise ValueError('shell item must be an object')
    seen = set()
    orders = set()
    parsed = []
    for item in items:
        if not isinstance(item, dict) or set(item) != {'featureKey', 'label', 'order', 'visible'}:
            raise ValueError('unknown shell item field')
        feature = item['featureKey']
        if not isinstance(feature, str) or feature not in resolved or feature in seen:
            raise ValueError('shell feature is invalid')
        seen.add(feature)
        order = item['order']
        if type(order) is not int or order < 0 or order in orders:
            raise ValueError('shell order is invalid')
        orders.add(order)
        if not isinstance(item['label'], str) or not item['label'].strip():
            raise ValueError('shell label is required')
        if type(item['visible']) is not bool:
            raise ValueError('shell visibility is invalid')
        parsed.append(item)
    return parsed


def _features(values):
    if not isinstance(values, list) or any(not re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', item) for item in values):
        raise ValueError('invalid feature')
    if len(values) != len(set(values)):
        raise ValueError('invalid feature')
    return values


def _forbidden(value):
    banned = {'authorization', 'ciphertext', 'credential', 'keystore', 'password', 'payloadciphertext',
              'privatekey', 'secret', 'token', 'wrappeddek'}
    if isinstance(value, list):
        return any(_forbidden(item) for item in value)
    if isinstance(value, dict):
        return any(''.join(char for char in key.lower() if char.isalnum()) in banned or _forbidden(child)
                   for key, child in value.items())
    return False


def validate_native(config):
    validate_app_configuration(config)
    assembly = config['assembly']
    if set(assembly) != {'revision', 'catalogDigest', 'catalog', 'selections'}:
        raise ValueError('unknown native assembly field')
    if type(assembly['revision']) is not int or assembly['revision'] < 1:
        raise ValueError('invalid assembly revision')
    catalog = assembly['catalog']
    if (set(catalog) != {'schemaVersion', 'sourceCommit', 'flutterVersion', 'lockfileDigest', 'presentations'}
            or type(catalog['schemaVersion']) is not int or catalog['schemaVersion'] != 1
            or catalog['sourceCommit'] != config['commitSha']
            or catalog['flutterVersion'] != config['frozenInputs']['flutterVersion']
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', catalog['lockfileDigest'])):
        raise ValueError('native catalog source mismatch')
    body = json.dumps(catalog, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
    if assembly['catalogDigest'] != 'sha256:' + hashlib.sha256(body).hexdigest():
        raise ValueError('native catalog digest mismatch')
    selections = assembly['selections']
    if not isinstance(selections, list) or not 1 <= len(selections) <= 256:
        raise ValueError('invalid native selections')
    features = set()
    for item in selections:
        if (set(item) != {'feature', 'presentation'} or item['feature'] in features
                or any(not re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', value) for value in item.values())):
            raise ValueError('invalid native selection')
        features.add(item['feature'])
        implementation = next((p for p in catalog['presentations']
            if p['feature'] == item['feature'] and p['presentation'] == item['presentation']), None)
        if implementation is None or config['platform'] not in implementation['platforms']:
            raise ValueError('unsupported native implementation')
    # Historical Specs still compile the HOME shell. A frozen appConfiguration
    # names startup from its first visible app bar item and does not require HOME.
    if config.get('appConfiguration') is None and 'HOME' not in features:
        raise ValueError('native HOME implementation required')
    if config['dartDefines'].get('SWAN_INTERNAL_BUILD') != 'false':
        raise ValueError('product build cannot enable internal capabilities')


if __name__ == '__main__':
    try:
        with open(sys.argv[1]) as stream:
            print(digest(validate(load(stream.read())['config'])))
    except (ValueError, KeyError, OSError, IndexError, TypeError, AttributeError):
        raise SystemExit('invalid Build Spec identity')
