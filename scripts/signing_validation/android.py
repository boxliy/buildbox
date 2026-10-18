"""Validate an Android keystore without signing an application.

A synthetic private-key challenge can set signingCapable. The store type is
detected from the container. Alias purpose is the material capability
`signing`; direct versus Play upload is chosen later by packaging.
"""

import os
import re
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from .contract import (
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
    REASON_UNKNOWN_FORMAT,
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
_CHAIN_LENGTH = re.compile(r"Certificate chain length:\s*(\d+)")
_ALIAS_HEADER = re.compile(r"(?m)^Alias name:\s*(.+)$")


def validate(request, evaluated_at):
    if not which("keytool") or not which("openssl"):
        raise ValidationFailure(REASON_UNSUPPORTED_INPUT, "android validation requires keytool and openssl")
    material = request.get("material") or {}
    password = bounded_password(material.get("storePassword"), "storePassword")
    key_password = bounded_password(material.get("keyPassword") or material.get("storePassword"), "keyPassword")
    data = _material_bytes(material)
    store_type = _detect_store_type(data)
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
    entries = [_alias_entry(name, chain if name == selected else None, evaluated_at) for name in aliases]
    selected_entry = next(item for item in entries if item["alias"] == selected)
    reasons = [selected_entry.get("_validity") or REASON_OK]
    private_key_proven = selected_entry.get("signingCapable") is True
    for item in entries:
        item.pop("_validity", None)
    selected_expiry = selected_entry.get("expiresAt")
    return {
        "platform": "android",
        "storeType": store_type,
        "status": "valid" if reasons == [REASON_OK] else "invalid",
        "reasonCodes": reasons,
        "selectedAlias": selected,
        "expiresAt": selected_expiry,
        "aliasCount": len(aliases),
        "aliases": entries,
        "evidence": {
            "materialSha256": digest_bytes(data),
            "challenge": "detached-rsa-or-ecdsa-v1",
            "privateKeyProven": private_key_proven,
            "chainTrusted": False,
            "playAppSigningIdentity": False,
            "installable": False,
            "trustedByPlatform": False,
        },
    }


def _material_bytes(material):
    import base64
    if "path" in material:
        return bounded_file(material["path"])
    encoded = material.get("bytesBase64")
    if not isinstance(encoded, str):
        raise ValidationFailure(REASON_MALFORMED_MATERIAL, "android material is missing")
    try:
        return base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise ValidationFailure(REASON_MALFORMED_MATERIAL, "android material encoding is invalid") from error


def _detect_store_type(data):
    """Identify JKS or PKCS#12. A declared store type is not required."""
    if data[:4] == b"\xfe\xed\xfe\xed":
        return "JKS"
    if data[:2] == b"PK":
        raise ValidationFailure(REASON_UNKNOWN_FORMAT, "container is a zip archive, not a keystore")
    if len(data) >= 4 and data[0] == 0x30:
        return "PKCS12"
    raise ValidationFailure(REASON_UNKNOWN_FORMAT, "container is not JKS or PKCS12")


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
    code, listing = run([
        "keytool", "-list", "-v", "-keystore", str(keystore), "-storetype", _STORE_TYPES[store_type],
        "-alias", alias, "-storepass:env", "VALIDATION_STORE_PASSWORD",
    ], env)
    if code:
        raise ValidationFailure(REASON_MALFORMED_MATERIAL, "certificate listing failed")
    expected = _listed_chain_length(listing, alias)
    # keytool -exportcert emits only the leaf. Read the stored chain from a
    # one-alias PKCS12 copy so length greater than one is preserved.
    with tempfile.TemporaryDirectory(prefix="android-chain-") as temporary:
        destination = Path(temporary) / "chain.p12"
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
            if store_type == "JKS":
                raise ValidationFailure(REASON_WRONG_KEY_PASSWORD, "key password was rejected")
            raise ValidationFailure(REASON_CHAIN_INVALID, "certificate chain could not be exported")
        code, output = run([
            "openssl", "pkcs12", "-in", str(destination), "-nokeys", "-legacy",
            "-passin", "env:VALIDATION_STORE_PASSWORD",
        ], env)
        if code or "BEGIN CERTIFICATE" not in output:
            code, output = run([
                "openssl", "pkcs12", "-in", str(destination), "-nokeys",
                "-passin", "env:VALIDATION_STORE_PASSWORD",
            ], env)
    if code or "BEGIN CERTIFICATE" not in output:
        raise ValidationFailure(REASON_CHAIN_INVALID, "certificate chain could not be read")
    pems = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", output, re.S)
    chain = _load_pems(pems)
    if len(chain) != expected or not chain or len(chain) > MAX_CHAIN:
        raise ValidationFailure(REASON_CHAIN_INVALID, "certificate chain length is not supported")
    return chain


def _listed_chain_length(listing, alias):
    section = _alias_section(listing, alias)
    match = _CHAIN_LENGTH.search(section)
    if not match:
        raise ValidationFailure(REASON_CHAIN_INVALID, "certificate chain length is missing")
    length = int(match.group(1))
    if length < 1 or length > MAX_CHAIN:
        raise ValidationFailure(REASON_CHAIN_INVALID, "certificate chain length is not supported")
    return length


def _alias_section(listing, alias):
    parts = re.split(r"(?m)(?=^Alias name:)", listing)
    for part in parts:
        match = _ALIAS_HEADER.search(part)
        if match and match.group(1).strip() == alias:
            return part
    raise ValidationFailure(REASON_ALIAS_NOT_FOUND, "requested alias is not in the keystore listing")


def _load_pems(pems):
    try:
        return [x509.load_pem_x509_certificate(item.encode()) for item in pems]
    except ValueError as error:
        raise ValidationFailure(REASON_CHAIN_INVALID, "certificate chain is not readable") from error


def _confirm_private_key(keystore, store_type, alias, env, certificate):
    with tempfile.TemporaryDirectory(prefix="android-key-") as temporary:
        destination = Path(temporary) / "leaf.p12"
        if store_type == "JKS":
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


def _alias_entry(alias, chain, evaluated_at):
    if chain is None:
        return {
            "alias": alias,
            "certificateSha256": None,
            "notBefore": None,
            "expiresAt": None,
            "algorithm": None,
            "signingCapable": False,
            "purpose": "signing",
            "chainLength": None,
            "chainSha256": [],
            "_validity": REASON_OK,
        }
    leaf = chain[0]
    public = leaf.public_key()
    if isinstance(public, rsa.RSAPublicKey):
        algorithm = "RSA"
    elif isinstance(public, ec.EllipticCurvePublicKey):
        algorithm = "EC"
    else:
        raise ValidationFailure(REASON_UNSUPPORTED_ALGORITHM, "certificate algorithm is not supported")
    if algorithm not in PUBLIC_KEY_ALGORITHMS:
        raise ValidationFailure(REASON_UNSUPPORTED_ALGORITHM, "certificate algorithm is not supported")
    state = validity(
        leaf.not_valid_before_utc, leaf.not_valid_after_utc, evaluated_at,
        REASON_CERTIFICATE_NOT_YET_VALID, REASON_CERTIFICATE_EXPIRED)
    return {
        "alias": alias,
        "certificateSha256": leaf.fingerprint(hashes.SHA256()).hex(),
        "notBefore": instant(leaf.not_valid_before_utc),
        "expiresAt": instant(leaf.not_valid_after_utc),
        "algorithm": algorithm,
        "signingCapable": state is None,
        "purpose": "signing",
        "chainLength": len(chain),
        "chainSha256": [item.fingerprint(hashes.SHA256()).hex() for item in chain],
        "_validity": state or REASON_OK,
    }
