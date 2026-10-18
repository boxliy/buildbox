#!/usr/bin/env python3
"""Isolated Android signing. Never run source-provided scripts or extract ZIPs."""
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
import urllib.request
import zipfile

MAX_BYTES = 512 * 1024 * 1024


def checked_zip(path):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_BYTES:
        raise ValueError("invalid artifact file")
    with zipfile.ZipFile(path) as archive:
        seen, expanded = set(), 0
        for item in archive.infolist():
            name = PurePosixPath(item.filename)
            if (name.is_absolute() or ".." in name.parts or "\\" in item.filename
                    or str(name) in seen or str(name) != item.filename.rstrip("/")
                    or (stat.S_IFMT(item.external_attr >> 16) not in (0, stat.S_IFREG, stat.S_IFDIR))
                    or item.flag_bits & 1):
                raise ValueError("unsafe archive entry")
            seen.add(str(name))
            expanded += item.file_size
            if expanded > 2 * MAX_BYTES or len(seen) > 100000:
                raise ValueError("archive size limit exceeded")
            upper = item.filename.upper()
            if upper.startswith("META-INF/") and upper.endswith((".SF", ".RSA", ".DSA", ".EC")):
                raise ValueError("refusing already-signed artifact")
    # APK Signature Scheme v2/v3 blocks do not have META-INF entries.
    with path.open("rb") as source:
        previous = b""
        while chunk := source.read(1024 * 1024):
            if b"APK Sig Block 42" in previous + chunk:
                raise ValueError("refusing already-signed APK")
            previous = chunk[-16:]


def run(args, env=None):
    result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=120)
    if result.returncode:
        # Tool diagnostics may contain aliases or credential details.
        raise ValueError("signing tool rejected artifact or signing material")
    return result.stdout


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("platform redirects are forbidden")


def request(path, body=None):
    base = os.environ["HAWK_BASE_URL"].rstrip("/")
    if not base.startswith("https://"):
        raise ValueError("Hawk requires HTTPS")
    token = os.environ["HAWK_STAGE_TOKEN"]
    payload = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=payload, headers={
        "Authorization": "Bearer " + token, "Content-Type": "application/json"})
    with urllib.request.build_opener(NoRedirect).open(req, timeout=30) as response:
        data = response.read(32 * 1024 * 1024 + 1)
        if len(data) > 32 * 1024 * 1024:
            raise ValueError("platform response too large")
        return json.loads(data) if data else None


def verify_identity(path, target, metadata):
    if target == "apk":
        output = run(["aapt2", "dump", "badging", str(path)])
        match = re.search(r"package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'", output)
        if not match or match.groups() != (metadata["applicationIdentifier"], str(metadata["buildNumber"]), metadata["versionName"]):
            raise ValueError("APK identity or version mismatch")
    else:
        # Bundletool is an operator-provided, SHA-pinned trusted tool, not an artifact input.
        jar = Path(os.environ["BUILDBOX_BUNDLETOOL_JAR"])
        digest = os.environ["BUILDBOX_BUNDLETOOL_SHA256"]
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or hashlib.sha256(jar.read_bytes()).hexdigest() != digest:
            raise ValueError("bundletool checksum mismatch")
        import xml.etree.ElementTree as ET
        xml = run(["java", "-jar", str(jar), "dump", "manifest", "--bundle=" + str(path), "--module=base"])
        root = ET.fromstring(xml)
        android = "{http://schemas.android.com/apk/res/android}"
        if (root.get("package"), root.get(android + "versionCode"), root.get(android + "versionName")) != (
                metadata["applicationIdentifier"], str(metadata["buildNumber"]), metadata["versionName"]):
            raise ValueError("AAB identity or version mismatch")


def sign_one(source, destination, target, metadata, material, private):
    checked_zip(source)
    verify_identity(source, target, metadata)
    keystore = private / "keystore"
    keystore.write_bytes(base64.b64decode(material["containerBase64"], validate=True))
    keystore.chmod(0o600)
    env = dict(os.environ, SIGN_STORE_PASSWORD=material["password"],
               SIGN_KEY_PASSWORD=material.get("keyPassword") or material["password"])
    expected = metadata["certificateSha256"].lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("invalid expected certificate")
    certificate = private / "certificate.pem"
    certificate.write_text(run(["keytool", "-exportcert", "-rfc", "-keystore", str(keystore),
        "-storepass:env", "SIGN_STORE_PASSWORD", "-alias", material["alias"]], env))
    run(["openssl", "x509", "-in", str(certificate), "-checkend", "0", "-noout"])
    # Read the actual frozen certificate, not caller-supplied algorithm metadata.
    certificate_text = run(["openssl", "x509", "-in", str(certificate), "-text", "-noout"])
    algorithm = re.search(r"Public Key Algorithm:\s*(\S+)", certificate_text)
    signature_algorithm = {"rsaEncryption": "SHA256withRSA", "id-ecPublicKey": "SHA256withECDSA"}.get(
        algorithm.group(1) if algorithm else "")
    if not signature_algorithm:
        raise ValueError("unsupported signing key algorithm")
    if target == "apk":
        aligned = private / "aligned.apk"
        run(["zipalign", "-p", "-f", "4", str(source), str(aligned)])
        run(["apksigner", "sign", "--ks", str(keystore), "--ks-key-alias", material["alias"],
             "--ks-pass", "env:SIGN_STORE_PASSWORD", "--key-pass", "env:SIGN_KEY_PASSWORD",
             "--out", str(destination), str(aligned)], env)
        run(["zipalign", "-c", "-p", "4", str(destination)])
        output = run(["apksigner", "verify", "--verbose", "--print-certs", str(destination)])
        fingerprints = re.findall(r"Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]+)", output)
        if [f.lower() for f in fingerprints] != [expected]:
            raise ValueError("APK certificate mismatch")
    else:
        run(["jarsigner", "-keystore", str(keystore), "-storepass:env", "SIGN_STORE_PASSWORD",
             "-keypass:env", "SIGN_KEY_PASSWORD", "-sigalg", signature_algorithm, "-digestalg", "SHA-256",
             "-signedjar", str(destination), str(source), material["alias"]], env)
        run(["jarsigner", "-verify", "-strict", "-keystore", str(keystore),
             "-storepass:env", "SIGN_STORE_PASSWORD", str(destination)], env)
        output = run(["keytool", "-J-Duser.language=en", "-printcert", "-jarfile", str(destination)])
        fingerprints = re.findall(r"SHA256:\s*([0-9A-Fa-f:]+)", output)
        if not fingerprints or any(f.replace(":", "").lower() != expected for f in fingerprints):
            raise ValueError("AAB certificate mismatch")
    verify_identity(destination, target, metadata)


def main():
    os.umask(0o077)
    state = Path(os.environ.get("BUILDBOX_STATE_DIR", "/tmp/buildbox"))
    run_id = os.environ["BUILDBOX_RUN_ID"]
    if not re.fullmatch(r"[1-9][0-9]*", run_id):
        raise ValueError("invalid platform run id")
    if any((state / name).exists() for name in ("uploads.json", "spec-response.json")):
        raise ValueError("sign runner contains forbidden upload authorization")
    response = request(f"/api/v1/buildbox/runs/{run_id}/signing-material")
    metadata, material = response["metadata"], response["material"]
    if metadata["platform"] != "android" or metadata["runId"] != run_id:
        raise ValueError("signing scope mismatch")
    targets = metadata["targets"]
    if not targets or targets != sorted(set(targets)) or any(t not in ("apk", "aab") for t in targets):
        raise ValueError("invalid Android targets")
    artifacts = []
    (state / "artifacts").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sign-material-") as temporary:
        for target in targets:
            filename = f"swan-release.{target}"
            source, destination = state / "unsigned" / filename, state / "artifacts" / filename
            if destination.exists() or destination.is_symlink():
                raise ValueError("signed output already exists")
            sign_one(source, destination, target, metadata, material, Path(temporary))
            with destination.open("rb") as signed:
                digest = hashlib.file_digest(signed, "sha256").hexdigest()
            size = destination.stat().st_size
            request(f"/api/v1/buildbox/runs/{run_id}/signing-proofs", {
                "target": target, "signingVersionId": metadata["versionId"],
                "certificateSha256": metadata["certificateSha256"], "sha256": digest, "byteSize": size})
            artifacts.append({"target": target, "fileName": filename, "sha256": "sha256:" + digest,
                              "byteSize": size, "signMode": "signed"})
    (state / "artifacts.json").write_text(json.dumps(artifacts))
    (state / "sign-proof.json").write_text(json.dumps({"signer": "android-tools", "runId": run_id,
        "specHash": metadata["specHash"], "signingVersionId": metadata["versionId"], "artifacts": artifacts}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("sign-android: signing failed; no signed delivery was authorized")
