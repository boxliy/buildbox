#!/usr/bin/env python3
"""Offline signing-material validator.

Read one Hawk JSON request on stdin. Write one public JSON result on stdout.
Passwords stay inside the request process and are never placed on argv.
"""

import json
import sys

from . import android, apple
from .contract import REASON_MACOS_REQUIRED, SCHEMA_VERSION, VALIDATOR_VERSION
from .outcome import ValidationFailure, assert_public
from .scope import authorize
from .time_basis import instant, parse_instant
from .tools import not_executed, probe


def validate_document(document):
    if not isinstance(document, dict):
        raise ValidationFailure("malformed_material", "request must be an object")
    if document.get("schemaVersion") != SCHEMA_VERSION:
        raise ValidationFailure("unsupported_input", "schema version is not supported")
    identity = authorize(document)
    evaluated_at = parse_instant(document.get("evaluatedAt"))
    kind = identity["kind"]
    if kind == "android_keystore":
        metadata, reasons = android.validate(document, evaluated_at)
    elif kind == "apple_certificate":
        metadata, reasons = apple.validate_certificate(document, evaluated_at)
    else:
        metadata, reasons = apple.validate_profile(document, evaluated_at)
    pending = not_executed()
    if pending and REASON_MACOS_REQUIRED not in reasons:
        reasons = [*reasons, REASON_MACOS_REQUIRED]
    status = "valid" if reasons == ["ok"] and not pending else "invalid"
    if status == "invalid":
        reasons = [code for code in reasons if code != "ok"] or ["tool_failed"]
    result = {
        "schemaVersion": SCHEMA_VERSION,
        "validationId": identity["validationId"],
        "tenantId": identity["tenantId"],
        "assetId": identity["assetId"],
        "versionId": identity["versionId"],
        "kind": kind,
        "toolchainSha": identity["toolchainSha"],
        "validatorVersion": VALIDATOR_VERSION,
        "status": status,
        "reasonCodes": reasons,
        "validatedAt": instant(evaluated_at),
        "metadata": metadata,
        "evidence": {
            "tools": probe(),
            "notExecuted": pending,
            "installable": False,
            "trustedByPlatform": False,
            "idempotent": True,
            "retried": False,
        },
    }
    return assert_public(result)


def main():
    raw = sys.stdin.buffer.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        _fail("size_limit", "request exceeds the input limit", None)
    identity = None
    try:
        document = json.loads(raw)
        if isinstance(document, dict):
            identity = _partial_identity(document)
        result = validate_document(document)
    except ValidationFailure as error:
        _fail(error.code, error.message, identity)
    except json.JSONDecodeError:
        _fail("malformed_material", "request is not JSON", None)
    except Exception:
        _fail("tool_failed", "validation failed closed", identity)
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


def _partial_identity(document):
    keys = ("validationId", "tenantId", "assetId", "versionId", "kind", "toolchainSha")
    found = {}
    for key in keys:
        value = document.get(key)
        if isinstance(value, str) and value and len(value) <= 128 and "\n" not in value:
            found[key] = value
    return found or None


def _fail(code, message, identity):
    payload = {
        "schemaVersion": SCHEMA_VERSION,
        "validatorVersion": VALIDATOR_VERSION,
        "status": "invalid",
        "reasonCodes": [code],
        "message": message,
        "evidence": {"idempotent": True, "retried": False, "installable": False, "trustedByPlatform": False},
    }
    if identity:
        payload.update(identity)
    public = assert_public(payload)
    sys.stdout.write(json.dumps(public, sort_keys=True, separators=(",", ":")))
    raise SystemExit(2)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        raise SystemExit(2)
