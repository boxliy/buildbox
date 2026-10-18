"""Validate an Apple identity and a provisioning profile separately.

CMS structural checks use OpenSSL. A successful parse is not trust, not
installability, and not a substitute for the macOS security/codesign job.
"""

import datetime
import os
import plistlib
import re
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

from .contract import (
    APPLE_DISTRIBUTIONS,
    APPLE_KINDS,
    MAX_DEVICES,
    MAX_PLIST_BYTES,
    PUBLIC_KEY_ALGORITHMS,
    REASON_BUNDLE_MISMATCH,
    REASON_CERTIFICATE_EXPIRED,
    REASON_CERTIFICATE_MISMATCH,
    REASON_CERTIFICATE_NOT_YET_VALID,
    REASON_CMS_INVALID,
    REASON_DISTRIBUTION_MISMATCH,
    REASON_ENTITLEMENTS_MISMATCH,
    REASON_MACOS_REQUIRED,
    REASON_MALFORMED_MATERIAL,
    REASON_OK,
    REASON_PRIVATE_KEY_MISMATCH,
    REASON_PROFILE_EXPIRED,
    REASON_PROFILE_NOT_YET_VALID,
    REASON_PROFILE_TAMPERED,
    REASON_TEAM_MISMATCH,
    REASON_UNSUPPORTED_ALGORITHM,
    REASON_UNSUPPORTED_INPUT,
    REASON_WRONG_PASSWORD,
)
from .limits import bounded_file, bounded_password, reject_zip
from .outcome import ValidationFailure
from .time_basis import as_utc, instant, taipei_date, validity
from .tools import digest_bytes, probe, run, which


def validate(request, evaluated_at):
    kind = request.get("kind")
    if kind not in APPLE_KINDS:
        raise ValidationFailure(REASON_UNSUPPORTED_INPUT, "apple material kind is not supported")
    if kind == "certificate":
        return _certificate(request, evaluated_at)
    return _profile(request, evaluated_at)


def _certificate(request, evaluated_at):
    if not which("openssl"):
        raise ValidationFailure(REASON_UNSUPPORTED_INPUT, "apple certificate validation requires openssl")
    material = request.get("material") or {}
    password = bounded_password(material.get("password"), "password")
    data = bounded_file(material["path"]) if "path" in material else _inline(material)
    reject_zip(data) if data[:2] == b"PK" else None
    with tempfile.TemporaryDirectory(prefix="apple-cert-") as temporary:
        container = Path(temporary) / "identity.p12"
        container.write_bytes(data)
        container.chmod(0o600)
        env = dict(os.environ, VALIDATION_P12_PASSWORD=password)
        code, pem = run([
            "openssl", "pkcs12", "-in", str(container), "-clcerts", "-nokeys",
            "-passin", "env:VALIDATION_P12_PASSWORD",
        ], env)
        if code or "BEGIN CERTIFICATE" not in pem:
            raise ValidationFailure(REASON_WRONG_PASSWORD, "certificate password was rejected")
        code, key_pem = run([
            "openssl", "pkcs12", "-in", str(container), "-nocerts", "-nodes",
            "-passin", "env:VALIDATION_P12_PASSWORD",
        ], env)
        if code or "PRIVATE KEY" not in key_pem:
            raise ValidationFailure(REASON_WRONG_PASSWORD, "private key password was rejected")
    certificate = _leaf(pem)
    _match_key(key_pem, certificate)
    metadata = _certificate_metadata(certificate, evaluated_at)
    reasons = [metadata["validity"]] if metadata["validity"] != REASON_OK else [REASON_OK]
    return {
        "platform": "ios",
        "kind": "certificate",
        "status": "valid" if reasons == [REASON_OK] else "invalid",
        "reasonCodes": reasons,
        "certificate": metadata,
        "evidence": _capability_evidence(digest_bytes(data)),
    }


def _profile(request, evaluated_at):
    if not which("openssl"):
        raise ValidationFailure(REASON_UNSUPPORTED_INPUT, "profile validation requires openssl")
    material = request.get("material") or {}
    data = bounded_file(material["path"]) if "path" in material else _inline(material)
    if len(data) > MAX_PLIST_BYTES:
        raise ValidationFailure(REASON_MALFORMED_MATERIAL, "profile exceeds the plist limit")
    plist_bytes, cms = _decode_cms(data)
    try:
        profile = plistlib.loads(plist_bytes)
    except (plistlib.InvalidFileException, ValueError) as error:
        raise ValidationFailure(REASON_CMS_INVALID, "profile payload is not a plist") from error
    if not isinstance(profile, dict):
        raise ValidationFailure(REASON_CMS_INVALID, "profile payload is not an object")
    derived = _derive(profile, evaluated_at)
    expectations = request.get("expectations") or {}
    mismatches = _compare(profile, derived, expectations)
    reasons = list(derived["reasonCodes"])
    reasons.extend(mismatches)
    status = "valid" if reasons == [REASON_OK] else "invalid"
    if REASON_OK in reasons and len(reasons) > 1:
        reasons = [code for code in reasons if code != REASON_OK]
    return {
        "platform": "ios",
        "kind": "provisioning_profile",
        "status": status,
        "reasonCodes": reasons,
        "profile": derived["profile"],
        "evidence": {
            **_capability_evidence(digest_bytes(data)),
            "cmsDigestSha256": digest_bytes(cms),
            "payloadSha256": digest_bytes(plist_bytes),
            "claimedDistributionIgnored": expectations.get("distribution") not in (None, derived["profile"]["distribution"]),
        },
    }


def _decode_cms(data):
    with tempfile.TemporaryDirectory(prefix="apple-profile-") as temporary:
        source = Path(temporary) / "profile.mobileprovision"
        source.write_bytes(data)
        source.chmod(0o600)
        code, output = run(["openssl", "cms", "-verify", "-noverify", "-inform", "DER", "-in", str(source)], os.environ)
        if code or not output:
            raise ValidationFailure(REASON_CMS_INVALID, "profile CMS could not be decoded")
        # -noverify decodes the signed plist. It does not establish Apple trust.
        encoded = output.encode()
        if not encoded.startswith(b"<?xml") and not encoded.startswith(b"bplist"):
            raise ValidationFailure(REASON_CMS_INVALID, "CMS payload is not a profile plist")
        return encoded, data


def _leaf(pem):
    match = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S)
    if not match:
        raise ValidationFailure(REASON_MALFORMED_MATERIAL, "certificate is missing")
    try:
        return x509.load_pem_x509_certificate(match.group().encode())
    except ValueError as error:
        raise ValidationFailure(REASON_MALFORMED_MATERIAL, "certificate is not readable") from error


def match_private_key(private_pem, certificate):
    _match_key(private_pem, certificate)


def _match_key(private_pem, certificate):
    try:
        key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    except (ValueError, TypeError) as error:
        raise ValidationFailure(REASON_PRIVATE_KEY_MISMATCH, "private key is not readable") from error
    public = certificate.public_key()
    challenge = b"aviary-apple-material-challenge-v1"
    try:
        if isinstance(key, rsa.RSAPrivateKey) and isinstance(public, rsa.RSAPublicKey):
            signature = key.sign(challenge, padding.PKCS1v15(), hashes.SHA256())
            public.verify(signature, challenge, padding.PKCS1v15(), hashes.SHA256())
            return
        if isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(public, ec.EllipticCurvePublicKey):
            signature = key.sign(challenge, ec.ECDSA(hashes.SHA256()))
            public.verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
            return
    except Exception as error:
        raise ValidationFailure(REASON_PRIVATE_KEY_MISMATCH, "private key does not match the certificate") from error
    raise ValidationFailure(REASON_UNSUPPORTED_ALGORITHM, "private key algorithm is not supported")


def _certificate_metadata(certificate, evaluated_at):
    public = certificate.public_key()
    if isinstance(public, rsa.RSAPublicKey):
        algorithm, detail = "RSA", public.key_size
    elif isinstance(public, ec.EllipticCurvePublicKey):
        algorithm, detail = "EC", public.curve.name
    else:
        raise ValidationFailure(REASON_UNSUPPORTED_ALGORITHM, "certificate algorithm is not supported")
    if algorithm not in PUBLIC_KEY_ALGORITHMS:
        raise ValidationFailure(REASON_UNSUPPORTED_ALGORITHM, "certificate algorithm is not supported")
    state = validity(
        certificate.not_valid_before_utc, certificate.not_valid_after_utc, evaluated_at,
        REASON_CERTIFICATE_NOT_YET_VALID, REASON_CERTIFICATE_EXPIRED)
    return {
        "sha256": certificate.fingerprint(hashes.SHA256()).hex(),
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "notBefore": instant(certificate.not_valid_before_utc),
        "notAfter": instant(certificate.not_valid_after_utc),
        "publicKeyAlgorithm": algorithm,
        "publicKeyDetail": detail,
        "teamId": _team(certificate),
        "validity": state or REASON_OK,
    }


def _team(certificate):
    for attribute in certificate.subject:
        if attribute.oid == NameOID.ORGANIZATIONAL_UNIT_NAME and re.fullmatch(r"[A-Z0-9]{10}", attribute.value):
            return attribute.value
    return None


def _derive(profile, evaluated_at):
    reasons = []
    team = _one(profile.get("TeamIdentifier"), REASON_TEAM_MISMATCH, reasons)
    entitlements = profile.get("Entitlements") if isinstance(profile.get("Entitlements"), dict) else {}
    application = entitlements.get("application-identifier")
    bundle = None
    if isinstance(application, str) and team and application.startswith(team + "."):
        bundle = application[len(team) + 1:]
    else:
        reasons.append(REASON_BUNDLE_MISMATCH)
    if entitlements.get("com.apple.developer.team-identifier") != team:
        reasons.append(REASON_TEAM_MISMATCH)
    certificates = profile.get("DeveloperCertificates")
    fingerprints = []
    if not isinstance(certificates, list) or not certificates:
        reasons.append(REASON_CERTIFICATE_MISMATCH)
    else:
        for item in certificates:
            if not isinstance(item, bytes):
                reasons.append(REASON_CERTIFICATE_MISMATCH)
                continue
            try:
                parsed = x509.load_der_x509_certificate(item)
            except ValueError:
                reasons.append(REASON_CERTIFICATE_MISMATCH)
                continue
            fingerprints.append(parsed.fingerprint(hashes.SHA256()).hex())
    distribution = _distribution(profile, entitlements, reasons)
    created = _time(profile.get("CreationDate"))
    expires = _time(profile.get("ExpirationDate"))
    if created is None or expires is None:
        reasons.append(REASON_PROFILE_TAMPERED)
    else:
        state = validity(created, expires, evaluated_at, REASON_PROFILE_NOT_YET_VALID, REASON_PROFILE_EXPIRED)
        if state:
            reasons.append(state)
    devices = profile.get("ProvisionedDevices")
    device_count = len(devices) if isinstance(devices, list) else 0
    if device_count > MAX_DEVICES:
        reasons.append(REASON_MALFORMED_MATERIAL)
    if not reasons:
        reasons.append(REASON_OK)
    return {
        "reasonCodes": list(dict.fromkeys(reasons)),
        "profile": {
            "uuid": profile.get("UUID") if isinstance(profile.get("UUID"), str) else None,
            "name": profile.get("Name") if isinstance(profile.get("Name"), str) else None,
            "teamId": team,
            "teamName": profile.get("TeamName") if isinstance(profile.get("TeamName"), str) else None,
            "bundleId": bundle,
            "applicationIdentifier": application if isinstance(application, str) else None,
            "distribution": distribution,
            "developerCertificateSha256": fingerprints,
            "provisionedDeviceCount": device_count,
            "provisionsAllDevices": bool(profile.get("ProvisionsAllDevices")),
            "getTaskAllow": bool(entitlements.get("get-task-allow")),
            "creationDate": instant(created) if created else None,
            "expirationDate": instant(expires) if expires else None,
            "expirationDateTaipei": taipei_date(expires) if expires else None,
            "entitlementKeys": sorted(str(key) for key in entitlements),
        },
    }


def _distribution(profile, entitlements, reasons):
    devices = profile.get("ProvisionedDevices")
    all_devices = bool(profile.get("ProvisionsAllDevices"))
    task_allow = bool(entitlements.get("get-task-allow"))
    has_devices = isinstance(devices, list) and len(devices) > 0
    if all_devices and not has_devices and not task_allow:
        return "enterprise"
    if not all_devices and not has_devices and not task_allow:
        return "app_store"
    if has_devices and not all_devices and task_allow:
        return "development"
    if has_devices and not all_devices and not task_allow:
        return "ad_hoc"
    reasons.append(REASON_DISTRIBUTION_MISMATCH)
    return None


def _compare(profile, derived, expectations):
    found = []
    expected_team = expectations.get("teamId")
    if expected_team is not None and expected_team != derived["profile"]["teamId"]:
        found.append(REASON_TEAM_MISMATCH)
    expected_bundle = expectations.get("bundleId")
    if expected_bundle is not None and expected_bundle != derived["profile"]["bundleId"]:
        found.append(REASON_BUNDLE_MISMATCH)
    expected_distribution = expectations.get("distribution")
    if expected_distribution is not None:
        if expected_distribution not in APPLE_DISTRIBUTIONS or expected_distribution != derived["profile"]["distribution"]:
            found.append(REASON_DISTRIBUTION_MISMATCH)
    expected_cert = expectations.get("certificateSha256")
    if expected_cert is not None and expected_cert not in derived["profile"]["developerCertificateSha256"]:
        found.append(REASON_CERTIFICATE_MISMATCH)
    if expectations.get("requireGetTaskAllow") is True and not derived["profile"]["getTaskAllow"]:
        found.append(REASON_ENTITLEMENTS_MISMATCH)
    if expectations.get("forbidGetTaskAllow") is True and derived["profile"]["getTaskAllow"]:
        found.append(REASON_ENTITLEMENTS_MISMATCH)
    if profile.get("IsXcodeManaged") is True and expectations.get("allowXcodeManaged") is not True:
        found.append(REASON_PROFILE_TAMPERED)
    return found


def _one(value, code, reasons):
    if isinstance(value, list) and len(value) == 1 and isinstance(value[0], str) and re.fullmatch(r"[A-Z0-9]{10}", value[0]):
        return value[0]
    reasons.append(code)
    return None


def _time(value):
    if isinstance(value, datetime.datetime):
        return as_utc(value)
    return None


def _capability_evidence(material_sha256):
    capabilities = probe()
    return {
        "materialSha256": material_sha256,
        "cmsVerifiedWithAppleAnchor": False,
        "installable": False,
        "trustedByPlatform": False,
        "macosKeychain": capabilities["macosKeychain"],
        "notExecuted": [] if capabilities["macosKeychain"] else [
            "security_cms_anchor_verify",
            "keychain_import",
            "codesign_identity_check",
        ],
        "requiredForTrust": REASON_MACOS_REQUIRED,
    }


def _inline(material):
    import base64
    encoded = material.get("bytesBase64")
    if not isinstance(encoded, str):
        raise ValidationFailure(REASON_MALFORMED_MATERIAL, "apple material is missing")
    try:
        return base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise ValidationFailure(REASON_MALFORMED_MATERIAL, "apple material encoding is invalid") from error
