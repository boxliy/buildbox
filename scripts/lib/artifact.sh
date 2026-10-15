#!/usr/bin/env bash
# Classify an APK/AAB zip without extracting it.

artifact_signing_state() {
  local path=$1
  python3 - "$path" <<'PY'
import sys
import zipfile

path = sys.argv[1]
try:
    with zipfile.ZipFile(path) as archive:
        names = [name.upper() for name in archive.namelist()]
except Exception:
    sys.exit(2)

if any("/ANDROIDD." in f"/{name}" or name.startswith("META-INF/ANDROIDD.") for name in names):
    print("debug")
elif any(
    name.startswith("META-INF/") and name.endswith((".SF", ".RSA", ".DSA", ".EC"))
    for name in names
):
    print("signed")
else:
    print("unsigned")
PY
}
