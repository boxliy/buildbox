"""Map independent Bluetooth purposes to Apple's shared privacy description."""

BLUETOOTH_KEYS = ('bluetooth.scan', 'bluetooth.connect')
BLUETOOTH_USAGE_KEY = 'NSBluetoothAlwaysUsageDescription'


def bluetooth_usage(capabilities, locale, *, fallback_name=None, fallback_locale=None):
    by_key = {item['key']: item for item in capabilities}
    descriptions = []
    for key in BLUETOOTH_KEYS:
        if key not in by_key:
            continue
        description = next((p['description'] for p in by_key[key].get('purposes', [])
                            if p['locale'] == locale), None)
        if not description and fallback_locale is not None:
            description = next((p['description'] for p in by_key[key].get('purposes', [])
                                if p['locale'] == fallback_locale), None)
        if not description:
            if fallback_name is None:
                raise ValueError('missing frozen Bluetooth usage description')
            description = fallback_name + ' uses Bluetooth for enabled app features.'
        if description not in descriptions:
            descriptions.append(description)
    return {BLUETOOTH_USAGE_KEY: ' '.join(descriptions)} if descriptions else {}
