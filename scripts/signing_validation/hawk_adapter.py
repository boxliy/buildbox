"""Translate Hawk HTTP envelopes to the offline validator and back.

The published material envelope uses schemaVersion 1, expected {}, and no
evaluatedAt, purpose, or storeType. The offline contract stays
signing-material-validation/v1. Passwords remain inside the offline request
and never appear in the Hawk result.
"""

import json

from .contract import HAWK_DISTRIBUTIONS, HAWK_REASON_CODES, HAWK_REASON_MAP
from .outcome import ValidationFailure
from .time_basis import instant, parse_instant

HAWK_TOOL_NAMES = ("openssl", "keytool", "security", "codesign")
HAWK_METADATA_KEYS = {
    "android_keystore": ("expiresAt", "aliases"),
    "apple_certificate": ("teamId", "certificateSha256", "notBefore", "expiresAt"),
    "apple_profile": (
        "uuid", "teamId", "applicationIdentifier", "distributionMethod",
        "certificateSha256s", "entitlements", "expiresAt",
    ),
}
ALIAS_KEYS = (
    "alias", "certificateSha256", "notBefore", "expiresAt", "algorithm",
    "signingCapable", "purpose",
)


class AdapterError(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message


def offline_request(envelope, evaluated_at):
    """Build one offline request from a published Hawk material envelope."""
    if not isinstance(envelope, dict) or envelope.get("schemaVersion") != 1:
        raise AdapterError("material schema is not version 1")
    kind = envelope.get("kind")
    material = envelope.get("material") if isinstance(envelope.get("material"), dict) else None
    expected = envelope.get("expected") if isinstance(envelope.get("expected"), dict) else None
    if material is None or not isinstance(material.get("containerBase64"), str):
        raise AdapterError("material container is missing")
    if expected is None:
        raise AdapterError("expected object is missing")
    identity = _identity(envelope)
    evaluated = _evaluated(evaluated_at)
    scope = {**identity, "stage": "validate"}
    offline_material = {"bytesBase64": material["containerBase64"]}
    offline = {
        "contract": "signing-material-validation/v1",
        "evaluatedAt": evaluated,
        "scope": scope,
        "material": offline_material,
    }
    if kind == "android_keystore":
        offline["platform"] = "android"
        password = material.get("password")
        if not isinstance(password, str):
            raise AdapterError("keystore password is missing")
        offline_material["storePassword"] = password
        key_password = material.get("keyPassword")
        offline_material["keyPassword"] = password if key_password is None else key_password
        alias = expected.get("alias")
        if alias is not None:
            offline_material["alias"] = alias
    elif kind == "apple_certificate":
        offline["platform"] = "ios"
        offline["kind"] = "certificate"
        password = material.get("password")
        if not isinstance(password, str):
            raise AdapterError("certificate password is missing")
        offline_material["password"] = password
    elif kind == "apple_profile":
        offline["platform"] = "ios"
        offline["kind"] = "provisioning_profile"
        if expected:
            offline["expectations"] = expected
    else:
        raise AdapterError("material kind is not supported")
    return offline


def hawk_result(envelope, offline, evaluated_at):
    """Build the published Hawk result. Missing facts stay null or empty."""
    if not isinstance(offline, dict) or offline.get("contract") != "signing-material-validation/v1":
        raise AdapterError("offline result contract is not accepted")
    identity = _identity(envelope)
    scope = offline.get("scope") if isinstance(offline.get("scope"), dict) else {}
    for key, value in identity.items():
        if scope.get(key) != value:
            raise AdapterError("offline result identity does not match the envelope")
    status = offline.get("status")
    if status not in ("valid", "invalid"):
        raise AdapterError("offline status is not accepted")
    reasons = _reasons(offline.get("reasonCodes"), status)
    evidence = offline.get("evidence") if isinstance(offline.get("evidence"), dict) else {}
    body = {
        "schemaVersion": 1,
        **identity,
        "toolchainSha": envelope["toolchainSha"],
        "status": status,
        "reasonCodes": [] if status == "valid" else reasons,
        "validatedAt": _evaluated(evaluated_at),
        "metadata": _metadata(identity["kind"], offline),
        "evidence": {
            "privateKeyProven": evidence.get("privateKeyProven") is True,
            "chainTrusted": evidence.get("chainTrusted") is True,
            "cmsSignatureVerified": evidence.get("cmsSignatureVerified") is True,
            "tools": _tools(offline.get("tools")),
            "notExecuted": _not_executed(evidence.get("notExecuted")),
        },
    }
    if status == "valid" and body["evidence"]["notExecuted"]:
        raise AdapterError("valid result still has checks that were not executed")
    raw = json.dumps(body, sort_keys=True).encode()
    if b"BEGIN PRIVATE" in raw or b"BEGIN CERTIFICATE" in raw or b"containerBase64" in raw:
        raise AdapterError("hawk result contains material")
    return body


def _evaluated(value):
    try:
        return instant(parse_instant(value))
    except ValidationFailure as error:
        raise AdapterError("evaluation instant is missing") from error


def _identity(envelope):
    found = {}
    for key in ("validationId", "tenantId", "assetId", "versionId", "kind"):
        value = envelope.get(key)
        if not isinstance(value, str) or not value:
            raise AdapterError("material identity is missing")
        found[key] = value
    toolchain = envelope.get("toolchainSha")
    if not isinstance(toolchain, str) or len(toolchain) != 40:
        raise AdapterError("material toolchain SHA is missing")
    return found


def _reasons(codes, status):
    if not isinstance(codes, list) or any(not isinstance(code, str) for code in codes):
        raise AdapterError("offline reason codes are not a list")
    if status == "valid":
        return []
    translated = []
    for code in codes:
        if code == "ok":
            continue
        mapped = code if code in HAWK_REASON_CODES else HAWK_REASON_MAP.get(code)
        if mapped not in HAWK_REASON_CODES:
            raise AdapterError("offline reason is outside the Hawk allowlist")
        if mapped not in translated:
            translated.append(mapped)
    return translated or ["validation_failed"]


def _metadata(kind, offline):
    if kind == "android_keystore":
        aliases = []
        for item in offline.get("aliases") or []:
            if not isinstance(item, dict):
                continue
            aliases.append({key: item.get(key) for key in ALIAS_KEYS})
        return {"expiresAt": offline.get("expiresAt"), "aliases": aliases}
    if kind == "apple_certificate":
        certificate = offline.get("certificate") if isinstance(offline.get("certificate"), dict) else {}
        return {key: certificate.get(key) for key in HAWK_METADATA_KEYS[kind]}
    profile = offline.get("profile") if isinstance(offline.get("profile"), dict) else {}
    entitlements = profile.get("entitlements") if isinstance(profile.get("entitlements"), dict) else {}
    distribution = profile.get("distribution")
    return {
        "uuid": profile.get("uuid"),
        "teamId": profile.get("teamId"),
        "applicationIdentifier": profile.get("applicationIdentifier"),
        "distributionMethod": HAWK_DISTRIBUTIONS.get(distribution),
        "certificateSha256s": profile.get("developerCertificateSha256") or [],
        "entitlements": entitlements,
        "expiresAt": profile.get("expiresAt"),
    }


def _tools(tools):
    found = []
    if not isinstance(tools, dict):
        return found
    for name in HAWK_TOOL_NAMES:
        version = tools.get(name)
        if isinstance(version, str) and version:
            found.append({"name": name, "version": version[:160]})
    return found


def _not_executed(values):
    if not isinstance(values, list):
        return []
    return [item for item in values if isinstance(item, str)]
