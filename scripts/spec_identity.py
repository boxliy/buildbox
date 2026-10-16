#!/usr/bin/env python3
"""Canonical Build Spec v1 identity shared with Hawk's fixed test vector."""
import hashlib
import json
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


if __name__ == '__main__':
    try:
        with open(sys.argv[1]) as stream:
            print(digest(load(stream.read())['config']))
    except (ValueError, KeyError, OSError, IndexError):
        raise SystemExit('invalid Build Spec v1 identity')
