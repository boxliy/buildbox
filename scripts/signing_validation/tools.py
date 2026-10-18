"""Pinned local tool probes. Passwords are passed by environment, never argv."""

import hashlib
import os
import shutil
import subprocess

from .contract import TOOL_TIMEOUT_SECONDS, TRUST_CHECKS


def which(name):
    return shutil.which(name)


def probe():
    openssl = which("openssl")
    keytool = which("keytool")
    security = which("security")
    codesign = which("codesign")
    return {
        "openssl": _version(openssl, ["version"]) if openssl else None,
        "keytool": _java_version() if keytool else None,
        "security": "present" if security else None,
        "codesign": "present" if codesign else None,
        "macosKeychain": bool(security and codesign and os.uname().sysname == "Darwin"),
    }


def not_executed(platform):
    """Apple trust checks this process did not run.

    Those three checks belong only to an Apple certificate or profile. They
    are not Android results. Finding security and codesign is not the same as
    running them. This validator never invokes those tools, so the checks stay
    not executed on every host, including macOS, until the commands actually run.
    """
    if platform == "ios":
        return list(TRUST_CHECKS)
    return []


def _version(binary, args):
    result = subprocess.run([binary, *args], capture_output=True, text=True, timeout=5, check=False)
    line = (result.stdout or result.stderr).strip().splitlines()
    return line[0][:160] if line else None


def _java_version():
    result = subprocess.run(["java", "-version"], capture_output=True, text=True, timeout=5, check=False)
    line = (result.stderr or result.stdout).strip().splitlines()
    return line[0][:160] if line else None


def run(args, env, timeout=TOOL_TIMEOUT_SECONDS):
    """Run a tool. The caller must not put secrets in args. Stderr is discarded."""
    for item in args:
        if not isinstance(item, str) or "\x00" in item or "\n" in item:
            raise ValueError("tool argument rejected")
    result = subprocess.run(
        args, env=env, capture_output=True, text=True, timeout=timeout, check=False,
    )
    return result.returncode, result.stdout


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()
