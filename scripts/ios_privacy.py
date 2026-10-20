"""Project frozen native capabilities to exact iOS privacy declarations."""
import plistlib
import re

from bluetooth_usage import BLUETOOTH_KEYS, BLUETOOTH_USAGE_KEY, bluetooth_usage

USAGE_KEYS = {
    'camera.capture': 'NSCameraUsageDescription',
    'microphone.record': 'NSMicrophoneUsageDescription',
    'location.foreground': 'NSLocationWhenInUseUsageDescription',
    'location.background': 'NSLocationAlwaysAndWhenInUseUsageDescription',
    'photos.read': 'NSPhotoLibraryUsageDescription',
    'photos.write': 'NSPhotoLibraryAddUsageDescription',
    'biometrics.authenticate': 'NSFaceIDUsageDescription',
}
MANAGED_USAGE_KEYS = set(USAGE_KEYS.values()) | {
    BLUETOOTH_USAGE_KEY, 'NSBluetoothPeripheralUsageDescription', 'NSLocationAlwaysUsageDescription',
}
SUPPORTED = set(USAGE_KEYS) | set(BLUETOOTH_KEYS) | {'notifications.push', 'background.execution'}


def privacy_usage(metadata, locale):
    capabilities = metadata.get('deviceCapabilities', [])
    if not {item['key'] for item in capabilities} <= SUPPORTED:
        raise ValueError('unsupported iOS native capability')
    purposes = {item['key']: {p['locale']: p['description'] for p in item.get('purposes', [])}
                for item in capabilities}
    fallback_name = None if metadata.get('source') == 'tenant' else metadata.get('appDisplayName', 'App')
    result = {}
    for capability, key in USAGE_KEYS.items():
        if capability not in purposes:
            continue
        description = purposes[capability].get(locale) or purposes[capability].get(metadata.get('defaultLocale'))
        if not description:
            if fallback_name is None:
                raise ValueError('missing frozen usage description')
            description = fallback_name + ' uses ' + capability + ' for enabled app features.'
        result[key] = description
    if 'location.background' in purposes:
        result.setdefault(USAGE_KEYS['location.foreground'], result[USAGE_KEYS['location.background']])
    result.update(bluetooth_usage(capabilities, locale, fallback_locale=metadata.get('defaultLocale'),
                                  fallback_name=fallback_name))
    return result


def localized_strings(app):
    # Only this component's resources; nested apps have independent frozen capabilities.
    for directory in app.glob('*.lproj'):
        path = directory / 'InfoPlist.strings'
        if path.is_file():
            try:
                body = plistlib.loads(path.read_bytes())
                if not isinstance(body, dict):
                    raise ValueError('localized privacy strings must be a dictionary')
            except (plistlib.InvalidFileException, ValueError) as error:
                raise ValueError('invalid localized privacy strings') from error
            yield directory.stem, path, body


def background_modes(metadata):
    capabilities = {item['key'] for item in metadata.get('deviceCapabilities', [])}
    return [mode for capability, mode in (
        ('location.background', 'location'), ('notifications.push', 'remote-notification'),
        ('background.execution', 'fetch')) if capability in capabilities]


def project_privacy(app, metadata):
    info = app / 'Info.plist'
    body = plistlib.loads(info.read_bytes())
    for key in MANAGED_USAGE_KEYS:
        body.pop(key, None)
    body.update(privacy_usage(metadata, metadata.get('defaultLocale')))
    body['CFBundleDisplayName'] = metadata['appDisplayName']
    body.pop('UIBackgroundModes', None)
    modes = background_modes(metadata)
    if modes:
        body['UIBackgroundModes'] = modes
    info.write_bytes(plistlib.dumps(body))
    # Erase stale source purposes, including locales absent from the frozen profile.
    for _, path, strings in localized_strings(app):
        for key in MANAGED_USAGE_KEYS:
            strings.pop(key, None)
        path.write_bytes(plistlib.dumps(strings))
    for localization in metadata.get('localizations', []):
        locale = localization['locale']
        if not re.fullmatch(r'[A-Za-z0-9-]+', locale):
            raise ValueError('invalid native localization')
        directory = app / (locale + '.lproj')
        directory.mkdir(exist_ok=True)
        strings = {'CFBundleDisplayName': localization['displayName']}
        strings.update(privacy_usage(metadata, locale))
        (directory / 'InfoPlist.strings').write_bytes(plistlib.dumps(strings))


def validate_privacy(app, metadata, info):
    modes = background_modes(metadata)
    if (modes and info.get('UIBackgroundModes') != modes) or (not modes and 'UIBackgroundModes' in info):
        raise ValueError('iOS background modes mismatch or undeclared mode')
    expected = privacy_usage(metadata, metadata.get('defaultLocale'))
    actual = {key: info[key] for key in MANAGED_USAGE_KEYS if key in info}
    if actual != expected:
        raise ValueError('iOS privacy/Bluetooth usage description mismatch or undeclared key')
    requires_localization = bool(expected)
    configured = {item['locale'] for item in metadata.get('localizations', [])}
    if any(not re.fullmatch(r'[A-Za-z0-9-]+', locale) for locale in configured):
        raise ValueError('invalid native localization')
    found = set()
    for locale, _, strings in localized_strings(app):
        found.add(locale)
        expected = privacy_usage(metadata, locale) if locale in configured else {}
        actual = {key: strings[key] for key in MANAGED_USAGE_KEYS if key in strings}
        if actual != expected:
            raise ValueError('localized Bluetooth/privacy usage description mismatch or undeclared key')
    if requires_localization and configured - found:
        raise ValueError('missing localized Bluetooth/privacy usage description')
