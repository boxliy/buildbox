"""Validate an Android keystore without signing an application."""

import os
import re
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from .contract import (
    ANDROID_FORMATS,
    ANDROID_PURPOSES,
    MAX_ALIASES,
    MAX_CHAIN,
    PUBLIC_KEY_ALGORITHMS,
    REASON_ALIAS_NOT_FOUND,
    REASON_AMBIGUOUS_ALIAS,
    REASON_CERTIFICATE_EXPIRED,
    REASON_CERTIFICATE_NOT_YET_VALID,
    REASON_CHAIN_INVALID,
    REASON_MALFORMED_MATERIAL,
    REASON_OK,
    REASON_PRIVATE_KEY_MISMATCH,
    REASON_UNSUPPORTED_ALGORITHM,
    REASON_UNSUPPORTED_INPUT,
    REASON_WRONG_KEY_PASSWORD,
    REASON_WRONG_PASSWORD,
)
from .limits import bounded_file, bounded_password, safe_name
from .outcome import ValidationFailure
from .time_basis import instant, validity
from .tools import digest_bytes, run, which

_STORE_TYPES = {"JKS": "JKS", "PKCS12": "PKCS12"}
_CHALLENGE = b"aviary-signing-material-challenge-v1"


def validate(request, evaluated_at):
    if not which("keytool") or not which("openssl"):
        raise ValidationFailure(REASON_UNSUPPORTED_INPUT, "android validation requires keytool and openssl")
    purpose = request.get("purpose")
    if purpose not in ANDROID_PURPOSES:
        raise ValidationFailure(REASON_UNSUPPORTED_INPUT, "android purpose is not supported")
    store_type = request.get("storeType")
    if store_type not in ANDROID_FORMATS:
        raise ValidationFailure(REASON_UNSUPPORTED_INPUT, "android store type is not supported")
    material = request.get("material") or {}
    password = bounded_password(material.get("storePassword"), "storePassword")
    key_password = bounded_password(material.get("keyPassword") or material.get("storePassword"), "keyPassword")
    data = bounded_file(material["path"]) if "path" in material else _inline(material)
    alias = material.get("alias")
    if alias is not None:
        alias = safe_name(alias, "alias")
    with tempfile.TemporaryDirectory(prefix="android-material-") as temporary:
        keystore = Path(temporary) / "material.keystore"
        keystore.write_bytes(data)
        keystore.chmod(0o600)
        env = dict(os.environ, VALIDATION_STORE_PASSWORD=password, VALIDATION_KEY_PASSWORD=key_password)
        aliases = _aliases(keystore, store_type, env)
        selected = _select(aliases, alias)
        chain = _chain(keystore, store_type, selected, env)
        _confirm_private_key(keystore, store_type, selected, env, chain[0])
    metadata = _certificate_metadata(chain, evaluated_at)
    status, reasons = _status(metadata)
    return {
        "platform": "android",
        "purpose": purpose,
        "storeType": store_type,
        "status": status,
        "reasonCodes": reasons,
        "selectedAlias": selected,
        "aliasCount": len(aliases),
        "aliases": aliases,
        "certificate": metadata,
        "evidence": {
            "materialSha256": digest_bytes(data),
            "challenge": "detached-rsa-or-ecdsa-v1",
            "playAppSigningIdentity": False,
            "directDistributionReady": purpose == "direct_distribution" and status == "valid",
            "installable": False,
            "trustedByPlatform": False,
        },
    }


def _inline(material):
    import base64
    encoded = material.get("bytesBase64")
    if not isinstance(encoded, str):
        raise ValidationFailure(REASON_MALFORMED_MATERIAL, "android material is missing")
    try:
        return base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise ValidationFailure(REASON_MALFORMED_MATERIAL, "android material encoding is invalid") from error


def _aliases(keystore, store_type, env):
    code, output = run([
        "keytool", "-list", "-keystore", str(keystore), "-storetype", _STORE_TYPES[store_type],
        "-storepass:env", "VALIDATION_STORE_PASSWORD",
    ], env)
    if code:
        raise ValidationFailure(REASON_WRONG_PASSWORD, "keystore password was rejected")
    found = []
    for line in output.splitlines():
        if "PrivateKeyEntry" not in line:
            continue
        alias = line.split(",", 1)[0].strip()
        if alias:
            found.append(alias)
    if not found or len(found) > MAX_ALIASES:
        raise ValidationFailure(REASON_MALFORMED_MATERIAL, "keystore alias set is outside the supported range")
    if len(set(found)) != len(found):
        raise ValidationFailure(REASON_AMBIGUOUS_ALIAS, "keystore contains a duplicate alias")
    return found


def _select(aliases, requested):
    if requested is None:
        if len(aliases) != 1:
            raise ValidationFailure(REASON_AMBIGUOUS_ALIAS, "alias is required when several keys exist")
        return aliases[0]
    if requested not in aliases:
        raise ValidationFailure(REASON_ALIAS_NOT_FOUND, "requested alias is not in the keystore")
    return requested


def _chain(keystore, store_type, alias, env):
    code, output = run([
        "keytool", "-exportcert", "-rfc", "-keystore", str(keystore), "-storetype", _STORE_TYPES[store_type],
        "-alias", alias, "-storepass:env", "VALIDATION_STORE_PASSWORD",
    ], env)
    if code or "BEGIN CERTIFICATE" not in output:
        raise ValidationFailure(REASON_MALFORMED_MATERIAL, "certificate export failed")
    pems = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", output, re.S)
    if not pems or len(pems) > MAX_CHAIN:
        raise ValidationFailure(REASON_CHAIN_INVALID, "certificate chain length is not supported")
    try:
        return [x509.load_pem_x509_certificate(item.encode()) for item in pems]
    except ValueError as error:
        raise ValidationFailure(REASON_CHAIN_INVALID, "certificate chain is not readable") from error


def _confirm_private_key(keystore, store_type, alias, env, certificate):
    with tempfile.TemporaryDirectory(prefix="android-key-") as temporary:
        destination = Path(temporary) / "leaf.p12"
        if store_type == "JKS":
            # PKCS12 ignores a distinct key password. JKS must unlock the key.
            algorithm = "SHA256withECDSA" if isinstance(certificate.public_key(), ec.EllipticCurvePublicKey) else "SHA256withRSA"
            code, _output = run([
                "keytool", "-certreq", "-keystore", str(keystore), "-storetype", "JKS",
                "-alias", alias, "-sigalg", algorithm,
                "-storepass:env", "VALIDATION_STORE_PASSWORD",
                "-keypass:env", "VALIDATION_KEY_PASSWORD",
            ], env)
            if code:
                raise ValidationFailure(REASON_WRONG_KEY_PASSWORD, "key password was rejected")
        command = [
            "keytool", "-importkeystore",
            "-srckeystore", str(keystore), "-srcstoretype", _STORE_TYPES[store_type],
            "-destkeystore", str(destination), "-deststoretype", "PKCS12",
            "-srcalias", alias, "-destalias", alias,
            "-srcstorepass:env", "VALIDATION_STORE_PASSWORD",
            "-deststorepass:env", "VALIDATION_STORE_PASSWORD",
        ]
        if store_type == "JKS":
            command.extend(["-srckeypass:env", "VALIDATION_KEY_PASSWORD"])
        code, _output = run(command, env)
        if code or not destination.is_file():
            raise ValidationFailure(REASON_WRONG_KEY_PASSWORD, "key password was rejected")
        code, pem = run([
            "openssl", "pkcs12", "-in", str(destination), "-nocerts", "-nodes",
            "-passin", "env:VALIDATION_STORE_PASSWORD",
        ], env)
        if code or "PRIVATE KEY" not in pem:
            raise ValidationFailure(REASON_WRONG_KEY_PASSWORD, "private key could not be unlocked")
        _challenge(pem, certificate)


def _challenge(private_pem, certificate):
    try:
        key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    except (ValueError, TypeError) as error:
        raise ValidationFailure(REASON_PRIVATE_KEY_MISMATCH, "private key is not readable") from error
    public = certificate.public_key()
    try:
        if isinstance(key, rsa.RSAPrivateKey) and isinstance(public, rsa.RSAPublicKey):
            signature = key.sign(_CHALLENGE, padding.PKCS1v15(), hashes.SHA256())
            public.verify(signature, _CHALLENGE, padding.PKCS1v15(), hashes.SHA256())
            return
        if isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(public, ec.EllipticCurvePublicKey):
            signature = key.sign(_CHALLENGE, ec.ECDSA(hashes.SHA256()))
            public.verify(signature, _CHALLENGE, ec.ECDSA(hashes.SHA256()))
            return
    except Exception as error:
        raise ValidationFailure(REASON_PRIVATE_KEY_MISMATCH, "private key does not match the certificate") from error
    raise ValidationFailure(REASON_UNSUPPORTED_ALGORITHM, "private key algorithm is not supported")


def _certificate_metadata(chain, evaluated_at):
    leaf = chain[0]
    public = leaf.public_key()
    if isinstance(public, rsa.RSAPublicKey):
        algorithm, detail = "RSA", public.key_size
    elif isinstance(public, ec.EllipticCurvePublicKey):
        algorithm, detail = "EC", public.curve.name
    else:
        raise ValidationFailure(REASON_UNSUPPORTED_ALGORITHM, "certificate algorithm is not supported")
    if algorithm not in PUBLIC_KEY_ALGORITHMS:
        raise ValidationFailure(REASON_UNSUPPORTED_ALGORITHM, "certificate algorithm is not supported")
    early = validity(
        leaf.not_valid_before_utc, leaf.not_valid_after_utc, evaluated_at,
        REASON_CERTIFICATE_NOT_YET_VALID, REASON_CERTIFICATE_EXPIRED)
    fingerprint = leaf.fingerprint(hashes.SHA256()).hex()
    return {
        "sha256": fingerprint,
        "subject": leaf.subject.rfc4514_string(),
        "issuer": leaf.issuer.rfc4514_string(),
        "serial": format(leaf.serial_number, "x"),
        "notBefore": instant(leaf.not_valid_before_utc),
        "notAfter": instant(leaf.not_valid_after_utc),
        "publicKeyAlgorithm": algorithm,
        "publicKeyDetail": detail,
        "chainLength": len(chain),
        "chainSha256": [item.fingerprint(hashes.SHA256()).hex() for item in chain],
        "validity": early or REASON_OK,
        "selfSigned": leaf.subject == leaf.issuer,
    }


def _status(metadata):
    if metadata["validity"] != REASON_OK:
        return "invalid", [metadata["validity"]]
    return "valid", [REASON_OK]
