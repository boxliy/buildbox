"""Terminal validation results. Failures are idempotent and never retried."""

import json

from .contract import FORBIDDEN_RESULT_KEYS


class ValidationFailure(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def assert_public(document):
    def walk(value, key=None):
        if key in FORBIDDEN_RESULT_KEYS:
            raise ValidationFailure("result_rejected", "result contains a forbidden field")
        if isinstance(value, dict):
            for child_key, child in value.items():
                walk(child, child_key)
        elif isinstance(value, list):
            for child in value:
                walk(child, key)
        elif isinstance(value, str) and ("BEGIN PRIVATE" in value or "BEGIN CERTIFICATE" in value):
            raise ValidationFailure("result_rejected", "result contains key material")
    walk(document)
    encoded = json.dumps(document, sort_keys=True).encode()
    if len(encoded) > 64 * 1024:
        raise ValidationFailure("result_rejected", "result exceeds the public size limit")
    return document
