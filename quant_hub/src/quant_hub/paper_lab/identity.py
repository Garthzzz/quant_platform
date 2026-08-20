from __future__ import annotations

from pathlib import PurePosixPath
import re

from quant_hub.ids import stable_sha256


def stable_public_id(prefix: str, *parts: str) -> str:
    if not re.fullmatch(r"[a-z][a-z0-9_]*", prefix):
        raise ValueError(f"invalid public ID prefix: {prefix!r}")
    return f"{prefix}_{stable_sha256(*parts)[:32]}"


def normalized_relative_path(value: str) -> str:
    candidate = value.replace("\\", "/")
    path = PurePosixPath(candidate)
    if path.is_absolute() or not path.parts or ".." in path.parts or "." in path.parts:
        raise ValueError(f"unsafe relative path: {value!r}")
    return path.as_posix()
