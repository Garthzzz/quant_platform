from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat

from quant_hub.config import (
    ConfigurationError,
    ensure_no_reparse_components,
    stat_is_reparse_point,
)


@dataclass(frozen=True, slots=True)
class ManagedAssetError(RuntimeError):
    code: str
    detail: str

    def __str__(self) -> str:
        return self.detail


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_nlink),
    )


def _require_regular_single_link(info: os.stat_result, *, label: str) -> None:
    if stat_is_reparse_point(info):
        raise ManagedAssetError("reparse_point", f"{label} is a reparse point")
    if not stat.S_ISREG(info.st_mode):
        raise ManagedAssetError("not_regular", f"{label} is not a regular file")
    if int(info.st_nlink) != 1:
        raise ManagedAssetError(
            "hard_linked",
            f"{label} must have exactly one hard link; observed {info.st_nlink}",
        )


def _managed_path(root: Path, relative: str, *, label: str) -> tuple[Path, Path]:
    if not isinstance(relative, str) or not relative or relative != relative.strip():
        raise ManagedAssetError("unsafe_relative_path", f"{label} path is not canonical")
    posix = PurePosixPath(relative)
    native = Path(relative)
    if (
        "\\" in relative
        or posix.is_absolute()
        or native.is_absolute()
        or bool(native.drive)
        or any(part in {"", ".", ".."} for part in posix.parts)
    ):
        raise ManagedAssetError("unsafe_relative_path", f"{label} path leaves its managed root")
    try:
        ensure_no_reparse_components(root)
        resolved_root = root.resolve(strict=True)
    except (ConfigurationError, FileNotFoundError, OSError) as error:
        raise ManagedAssetError("managed_root_unavailable", f"{label} root is unavailable: {error}") from error
    if not resolved_root.is_dir():
        raise ManagedAssetError("managed_root_unavailable", f"{label} root is not a directory")
    candidate = root / Path(*posix.parts)
    try:
        ensure_no_reparse_components(candidate)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except FileNotFoundError as error:
        raise ManagedAssetError("missing", f"{label} is missing") from error
    except (ConfigurationError, ValueError, OSError) as error:
        raise ManagedAssetError("outside_managed_root", f"{label} is outside its managed root: {error}") from error
    return candidate, resolved


def read_frozen_asset(
    root: Path,
    relative: str,
    *,
    expected_sha256: str,
    expected_bytes: int,
    label: str,
    capture: bool = True,
) -> bytes | None:
    """Read one DB-frozen file without ever returning unverified bytes.

    The open descriptor, the pathname before/after the read, link count, byte
    count and digest must all agree.  Capturing is used by HTTP routes so the
    verified descriptor cannot be swapped before Flask sends the response.
    """

    if (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
        or isinstance(expected_bytes, bool)
        or not isinstance(expected_bytes, int)
        or expected_bytes <= 0
    ):
        raise ManagedAssetError("invalid_frozen_metadata", f"{label} DB metadata is invalid")
    candidate, resolved = _managed_path(root, relative, label=label)
    try:
        before = candidate.lstat()
    except FileNotFoundError as error:
        raise ManagedAssetError("missing", f"{label} is missing") from error
    _require_regular_single_link(before, label=label)
    try:
        resolved_before = resolved.stat()
    except OSError as error:
        raise ManagedAssetError("unreadable", f"{label} cannot be inspected: {error}") from error
    _require_regular_single_link(resolved_before, label=label)
    if _identity(before) != _identity(resolved_before):
        raise ManagedAssetError("path_identity_mismatch", f"{label} path identity changed")

    digest = hashlib.sha256()
    size = 0
    chunks: list[bytes] | None = [] if capture else None
    try:
        with candidate.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            _require_regular_single_link(opened, label=label)
            if _identity(opened) != _identity(before):
                raise ManagedAssetError("path_identity_mismatch", f"{label} changed before open")
            while chunk := handle.read(1024 * 1024):
                size += len(chunk)
                if size > expected_bytes:
                    raise ManagedAssetError(
                        "content_mismatch",
                        f"{label} exceeds its frozen byte count",
                    )
                digest.update(chunk)
                if chunks is not None:
                    chunks.append(chunk)
            opened_after = os.fstat(handle.fileno())
            _require_regular_single_link(opened_after, label=label)
            if _identity(opened_after) != _identity(opened):
                raise ManagedAssetError("changed_during_read", f"{label} changed during read")
    except ManagedAssetError:
        raise
    except FileNotFoundError as error:
        raise ManagedAssetError("missing", f"{label} disappeared before open") from error
    except OSError as error:
        raise ManagedAssetError("unreadable", f"{label} cannot be read: {error}") from error

    try:
        after = candidate.lstat()
        ensure_no_reparse_components(candidate)
    except FileNotFoundError as error:
        raise ManagedAssetError("changed_during_read", f"{label} disappeared after read") from error
    except ConfigurationError as error:
        raise ManagedAssetError("changed_during_read", f"{label} became a reparse path") from error
    _require_regular_single_link(after, label=label)
    if _identity(after) != _identity(before):
        raise ManagedAssetError("changed_during_read", f"{label} changed during read")
    if size != expected_bytes or digest.hexdigest() != expected_sha256:
        raise ManagedAssetError(
            "content_mismatch",
            f"{label} bytes or SHA-256 differ from the frozen DB version",
        )
    return b"".join(chunks) if chunks is not None else None


def verify_frozen_asset(
    root: Path,
    relative: str,
    *,
    expected_sha256: str,
    expected_bytes: int,
    label: str,
) -> None:
    read_frozen_asset(
        root,
        relative,
        expected_sha256=expected_sha256,
        expected_bytes=expected_bytes,
        label=label,
        capture=False,
    )


__all__ = ["ManagedAssetError", "read_frozen_asset", "verify_frozen_asset"]
