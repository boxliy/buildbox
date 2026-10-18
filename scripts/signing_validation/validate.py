#!/usr/bin/env python3
"""Offline signing-material validator.

Read one signing-material-validation/v1 JSON request on stdin. Write one
public JSON result on stdout. The controlled job translates Hawk's HTTP
envelope; this process does not fetch it. Passwords stay inside the request
and are never placed on argv.
"""

import json
import sys

from . import android, apple
from .contract import CONTRACT_VERSION, REASON_MACOS_REQUIRED, VALIDATOR_VERSION
from .outcome import ValidationFailure, assert_public
from .scope import authorize
from .time_basis import instant, parse_instant
from .tools import not_executed, probe


def validate_document(document):
    if not isinstance(document, dict):
        raise ValidationFailure("malformed_material", "request must be an object")
    if document.get("contract") != CONTRACT_VERSION:
        raise ValidationFailure("unsupported_input", "contract version is not supported")
    scope = authorize(document)
    evaluated_at = parse_instant(document.get("evaluatedAt"))
    platform = document["platform"]
    if platform == "android":
        body = android.validate(document, evaluated_at)
    else:
        body = apple.validate(document, evaluated_at)
    pending = not_executed()
    reasons = list(body["reasonCodes"])
    if pending and REASON_MACOS_REQUIRED not in reasons:
        reasons.append(REASON_MACOS_REQUIRED)
    status = "valid" if reasons == ["ok"] and not pending else "invalid"
    if status == "invalid":
        reasons = [code for code in reasons if code != "ok"] or ["tool_failed"]
    body["status"] = status
    body["reasonCodes"] = reasons
    evidence = body.setdefault("evidence", {})
    evidence["notExecuted"] = pending
    evidence["installable"] = False
    evidence["trustedByPlatform"] = False
    result = {
        "contract": CONTRACT_VERSION,
        "validatorVersion": VALIDATOR_VERSION,
        "scope": scope,
        "evaluatedAt": instant(evaluated_at),
        "tools": probe(),
        "idempotent": True,
        "retried": False,
        **body,
    }
    return assert_public(result)


def main():
    raw = sys.stdin.buffer.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        _fail("size_limit", "request exceeds the input limit", None)
    scope = None
    try:
        document = json.loads(raw)
        if isinstance(document, dict) and isinstance(document.get("scope"), dict):
            scope = _partial_scope(document["scope"])
        result = validate_document(document)
    except ValidationFailure as error:
        _fail(error.code, error.message, scope)
    except json.JSONDecodeError:
        _fail("malformed_material", "request is not JSON", None)
    except Exception:
        _fail("tool_failed", "validation failed closed", scope)
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


def _partial_scope(scope):
    found = {}
    for key in ("validationId", "tenantId", "assetId", "versionId", "kind", "stage"):
        value = scope.get(key)
        if isinstance(value, str) and value and len(value) <= 128 and "\n" not in value:
            found[key] = value
    return found or None


def _fail(code, message, scope):
    payload = {
        "contract": CONTRACT_VERSION,
        "validatorVersion": VALIDATOR_VERSION,
        "status": "invalid",
        "reasonCodes": [code],
        "message": message,
        "idempotent": True,
        "retried": False,
    }
    if scope:
        payload["scope"] = scope
    public = assert_public(payload)
    sys.stdout.write(json.dumps(public, sort_keys=True, separators=(",", ":")))
    raise SystemExit(2)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        raise SystemExit(2)
