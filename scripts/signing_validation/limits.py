"""Resource limits for untrusted signing material."""

import os
import stat
import zipfile
from pathlib import Path, PurePosixPath

from .contract import (
    MAX_EXPANDED_BYTES,
    MAX_MATERIAL_BYTES,
    MAX_PASSWORD_BYTES,
    MAX_ZIP_ENTRIES,
    REASON_MALFORMED_MATERIAL,
    REASON_PATH_REJECTED,
    REASON_SIZE_LIMIT,
)
from .outcome import ValidationFailure


def bounded_file(path, limit=MAX_MATERIAL_BYTES):
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        raise ValidationFailure(REASON_PATH_REJECTED, "material path is not a regular file")
    size = candidate.stat().st_size
    if size <= 0 or size > limit:
        raise ValidationFailure(REASON_SIZE_LIMIT, "material size is outside the allowed range")
    return candidate.read_bytes()


def bounded_password(value, name):
    if not isinstance(value, str) or value == "":
        raise ValidationFailure(REASON_MALFORMED_MATERIAL, name + " is required")
    encoded = value.encode()
    if len(encoded) > MAX_PASSWORD_BYTES or "\x00" in value:
        raise ValidationFailure(REASON_SIZE_LIMIT, name + " exceeds the password limit")
    return value


def safe_name(value, label):
    if not isinstance(value, str) or len(value) > 128:
        raise ValidationFailure(REASON_MALFORMED_MATERIAL, label + " is invalid")
    if value in (".", "..") or "/" in value or "\\" in value or "\x00" in value:
        raise ValidationFailure(REASON_PATH_REJECTED, label + " contains a forbidden path")
    return value


def reject_zip(data):
    """Reject archives before any extraction. Callers never unpack them."""
    try:
        import io
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as error:
        raise ValidationFailure(REASON_MALFORMED_MATERIAL, "zip container is not readable") from error
    seen, expanded = set(), 0
    entries = archive.infolist()
    if len(entries) > MAX_ZIP_ENTRIES:
        raise ValidationFailure(REASON_SIZE_LIMIT, "zip entry count exceeds the limit")
    for item in entries:
        name = PurePosixPath(item.filename)
        if (name.is_absolute() or ".." in name.parts or "\\" in item.filename
                or item.filename in seen or str(name) != item.filename.rstrip("/")):
            raise ValidationFailure(REASON_PATH_REJECTED, "zip entry path is rejected")
        mode = stat.S_IFMT(item.external_attr >> 16)
        if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise ValidationFailure(REASON_PATH_REJECTED, "zip entry type is rejected")
        seen.add(item.filename)
        expanded += item.file_size
        if expanded > MAX_EXPANDED_BYTES:
            raise ValidationFailure(REASON_SIZE_LIMIT, "zip expanded size exceeds the limit")
    archive.close()


def private_temp(directory):
    path = Path(directory)
    path.mkdir(mode=0o700, exist_ok=False)
    os.chmod(path, 0o700)
    return path
