"""Generate ephemeral signing material. These identities are tests only."""

import datetime
import plistlib
import subprocess
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

PASSWORD = "isolated-validation-only"
KEY_PASSWORD = "isolated-key-only"
NOT_A_SECRET = PASSWORD


def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def certificate(key, common_name, team=None, not_before=None, not_after=None, issuer_key=None, issuer_name=None):
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    subject = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if team:
        subject.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, team))
    name = x509.Name(subject)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name or name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now)
        .not_valid_after(not_after or now + datetime.timedelta(days=365))
    )
    return builder.sign(issuer_key or key, hashes.SHA256())


def p12_bytes(key, cert, password=PASSWORD):
    return pkcs12.serialize_key_and_certificates(
        b"fixture", key, cert, None,
        serialization.BestAvailableEncryption(password.encode()),
    )


def keystore(path, alias, key, cert, store_type, store_password=PASSWORD, key_password=None):
    container = path.with_name(path.name + ".src.p12")
    container.write_bytes(p12_bytes(key, cert, key_password or store_password))
    env = dict(__import__("os").environ)
    env.update(SRC_PASS=key_password or store_password, DEST_PASS=store_password, KEY_PASS=key_password or store_password)
    subprocess.run([
        "keytool", "-importkeystore",
        "-srckeystore", str(container), "-srcstoretype", "PKCS12",
        "-destkeystore", str(path), "-deststoretype", store_type,
        "-srcalias", "fixture", "-destalias", alias,
        "-srcstorepass:env", "SRC_PASS", "-deststorepass:env", "DEST_PASS",
        "-srckeypass:env", "KEY_PASS", "-destkeypass:env", "KEY_PASS",
    ], check=True, env=env, capture_output=True)
    container.unlink()


def add_alias(path, alias, key, cert, store_password=PASSWORD, key_password=None):
    extra = path.with_name(path.name + "." + alias + ".src.p12")
    extra.write_bytes(p12_bytes(key, cert, key_password or store_password))
    env = dict(__import__("os").environ)
    env.update(SRC_PASS=key_password or store_password, DEST_PASS=store_password, KEY_PASS=key_password or store_password)
    subprocess.run([
        "keytool", "-importkeystore",
        "-srckeystore", str(extra), "-srcstoretype", "PKCS12",
        "-destkeystore", str(path), "-deststoretype", "PKCS12",
        "-srcalias", "fixture", "-destalias", alias,
        "-srcstorepass:env", "SRC_PASS", "-deststorepass:env", "DEST_PASS",
        "-srckeypass:env", "KEY_PASS", "-destkeypass:env", "KEY_PASS",
    ], check=True, env=env, capture_output=True)


def profile_plist(distribution, team="TEAM123456", bundle="com.example.app", certificate=None,
                  created=None, expires=None, entitlements=None, devices=None, all_devices=False):
    created = created or datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    expires = expires or datetime.datetime(2026, 12, 31, tzinfo=datetime.timezone.utc)
    if entitlements is None:
        entitlements = {
            "application-identifier": team + "." + bundle,
            "com.apple.developer.team-identifier": team,
            "get-task-allow": distribution == "development",
        }
    payload = {
        "AppIDName": "fixture",
        "CreationDate": created,
        "ExpirationDate": expires,
        "Name": "fixture-" + distribution,
        "TeamIdentifier": [team],
        "TeamName": "Fixture Team",
        "UUID": "11111111-2222-3333-4444-555555555555",
        "Version": 1,
        "DeveloperCertificates": [certificate.public_bytes(serialization.Encoding.DER)] if certificate else [],
        "Entitlements": entitlements,
        "ProvisionsAllDevices": all_devices,
    }
    if devices is not None:
        payload["ProvisionedDevices"] = devices
    return plistlib.dumps(payload, fmt=plistlib.FMT_XML)


def cms_sign(plist_bytes, key, cert, destination: Path):
    work = destination.parent
    key_path, cert_path, content = work / "key.pem", work / "cert.pem", work / "payload.plist"
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    content.write_bytes(plist_bytes)
    subprocess.run([
        "openssl", "cms", "-sign", "-nodetach", "-binary", "-outform", "DER",
        "-in", str(content), "-out", str(destination),
        "-inkey", str(key_path), "-signer", str(cert_path),
    ], check=True, capture_output=True)
    key_path.unlink()
    cert_path.unlink()
    content.unlink()


