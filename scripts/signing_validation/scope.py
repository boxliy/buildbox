"""Authorize one validation task. A compile or sign token is not accepted."""

import re

from .contract import PLATFORMS, REASON_SCOPE_MISMATCH, STAGE
from .outcome import ValidationFailure

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def authorize(document):
    scope = document.get("scope")
    if not isinstance(scope, dict):
        raise ValidationFailure(REASON_SCOPE_MISMATCH, "validation scope is required")
    required = ("validationId", "tenantId", "assetId", "versionId", "kind", "stage")
    values = {}
    for key in required:
        value = scope.get(key)
        if not isinstance(value, str) or not _ID.fullmatch(value):
            raise ValidationFailure(REASON_SCOPE_MISMATCH, "validation scope field is invalid")
        values[key] = value
    if values["stage"] != STAGE:
        raise ValidationFailure(REASON_SCOPE_MISMATCH, "only the validate stage may read material")
    platform = document.get("platform")
    if platform not in PLATFORMS or scope.get("platform") not in (None, platform):
        raise ValidationFailure(REASON_SCOPE_MISMATCH, "validation platform does not match the scope")
    if platform == "android" and values["kind"] != "android_keystore":
        raise ValidationFailure(REASON_SCOPE_MISMATCH, "android validation requires an android_keystore kind")
    expected = {"certificate": "apple_certificate", "provisioning_profile": "apple_profile"}.get(document.get("kind"))
    if platform == "ios" and (expected is None or expected != values["kind"]):
        raise ValidationFailure(REASON_SCOPE_MISMATCH, "ios material kind does not match the scope")
    return values
