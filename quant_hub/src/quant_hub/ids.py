from __future__ import annotations

import hashlib
import re
import uuid


_PUBLIC_ID_RE = re.compile(r"^[a-z][a-z0-9_]*_[0-9a-f]{32}$")
_OBJECT_ID_RE = re.compile(r"^obj_sha256_[0-9a-f]{64}$")


def new_public_id(prefix: str) -> str:
    if not re.fullmatch(r"[a-z][a-z0-9_]*", prefix):
        raise ValueError(f"invalid public ID prefix: {prefix!r}")
    return f"{prefix}_{uuid.uuid4().hex}"


def validate_public_id(value: str) -> str:
    if not _PUBLIC_ID_RE.fullmatch(value):
        raise ValueError(f"invalid public ID: {value!r}")
    return value


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def object_id_for_sha256(digest: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("content digest must be lowercase SHA-256 hex")
    return f"obj_sha256_{digest}"


def validate_object_id(value: str) -> str:
    if not _OBJECT_ID_RE.fullmatch(value):
        raise ValueError(f"invalid object ID: {value!r}")
    return value


def stable_sha256(*parts: str) -> str:
    payload = b"\0".join(part.encode("utf-8") for part in parts)
    return hashlib.sha256(payload).hexdigest()

