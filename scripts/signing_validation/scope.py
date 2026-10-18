"""Authorize one validation task. A compile or sign token is not accepted."""

import re

from .contract import KINDS, REASON_SCOPE_MISMATCH, STAGE
from .outcome import ValidationFailure

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")


def authorize(document):
    values = {}
    for key in ("validationId", "tenantId", "assetId", "versionId", "kind"):
        value = document.get(key)
        if not isinstance(value, str) or not _ID.fullmatch(value):
            raise ValidationFailure(REASON_SCOPE_MISMATCH, "validation identity field is invalid")
        values[key] = value
    toolchain = document.get("toolchainSha")
    if not isinstance(toolchain, str) or not _SHA.fullmatch(toolchain):
        raise ValidationFailure(REASON_SCOPE_MISMATCH, "toolchain SHA is invalid")
    values["toolchainSha"] = toolchain
    if values["kind"] not in KINDS:
        raise ValidationFailure(REASON_SCOPE_MISMATCH, "validation kind is not supported")
    stage = document.get("stage", STAGE)
    if stage != STAGE:
        raise ValidationFailure(REASON_SCOPE_MISMATCH, "only the validate stage may read material")
    return values
