from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import os
from pathlib import Path, PurePath, PurePosixPath
import stat
import unicodedata
from urllib.parse import quote

from quant_hub.config import ConfigurationError, ensure_no_reparse_components, is_reparse_point
from quant_hub.ids import sha256_hex
from quant_hub.platform.db import utc_now


class SourceBoundaryError(RuntimeError):
    pass


class UnstableSourceError(SourceBoundaryError):
    pass


def validate_archive_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise SourceBoundaryError("archive identity must use a non-empty POSIX relative path")
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or not pure.parts
        or str(pure) != value
        or any(
            part in ("", ".", "..")
            or ":" in part
            or part.endswith((" ", "."))
            or any(unicodedata.category(character) == "Cc" for character in part)
            for part in pure.parts
        )
    ):
        raise SourceBoundaryError("archive identity path is not canonical")
    if pure.suffix.lower() not in {".md", ".markdown"}:
        raise SourceBoundaryError("archive snapshot input must be Markdown")
    return value


def archive_origin_uri(relative_path: str) -> str:
    return f"archive:///{quote(validate_archive_relative_path(relative_path), safe='/')}"


def validate_utc_z(value: str) -> str:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except (TypeError, ValueError) as error:
        raise SourceBoundaryError("source observation time must be canonical UTC-Z") from error
    canonical = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if canonical != value:
        raise SourceBoundaryError("source observation time must be canonical UTC-Z")
    return value


def _identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


@dataclass(frozen=True, slots=True)
class SourceSnapshot:
    namespace: str
    relative_path: str
    origin_uri: str
    content: bytes
    sha256: str
    bytes: int
    observed_at: str


@dataclass(frozen=True, slots=True)
class ArchiveAssetSnapshot:
    relative_path: str
    content: bytes
    sha256: str
    bytes: int


class ReadOnlyArchiveAssetSource:
    """按展示 manifest 的冻结身份读取少量非 Markdown Archive 资源。

    该读取器不接受任意用户路径。调用方必须同时提供经 manifest 审核的长度与
    SHA-256；路径、文件类型、reparse point、读取期间身份变化或内容漂移任一
    不满足即拒绝返回。
    """

    # Raster figures are allowed only through a presentation-manifest entry
    # that also freezes their byte length and SHA-256.  Active content such as
    # SVG/HTML remains outside this reader's trust boundary.
    _ALLOWED_SUFFIXES = frozenset(
        {".pdf", ".txt", ".tex", ".bib", ".png", ".jpg", ".jpeg", ".webp"}
    )

    def __init__(self, root: Path):
        configured = root.absolute()
        try:
            ensure_no_reparse_components(configured)
        except ConfigurationError as error:
            raise SourceBoundaryError("archive root contains a reparse component") from error
        self.root = configured.resolve(strict=True)
        if is_reparse_point(self.root) or not self.root.is_dir():
            raise SourceBoundaryError("archive root must be a real directory")

    def _target(self, relative_path: str) -> tuple[Path, str]:
        pure = PurePosixPath(relative_path)
        if (
            pure.is_absolute()
            or not pure.parts
            or str(pure) != relative_path
            or pure.suffix.lower() not in self._ALLOWED_SUFFIXES
            or any(
                part in ("", ".", "..")
                or ":" in part
                or part.endswith((" ", "."))
                or any(unicodedata.category(character) == "Cc" for character in part)
                for part in pure.parts
            )
        ):
            raise SourceBoundaryError("archive asset path is not canonical or allowed")
        current = self.root
        for part in pure.parts:
            current = current / part
            try:
                if is_reparse_point(current):
                    raise SourceBoundaryError("archive asset path contains a reparse component")
            except (FileNotFoundError, NotADirectoryError) as error:
                raise SourceBoundaryError("archive asset does not exist") from error
        try:
            resolved = current.resolve(strict=True)
            canonical = resolved.relative_to(self.root).as_posix()
        except (FileNotFoundError, NotADirectoryError, RuntimeError, ValueError) as error:
            raise SourceBoundaryError("archive asset escapes root or cannot be resolved") from error
        if canonical != relative_path:
            raise SourceBoundaryError("archive asset path does not match canonical identity")
        return resolved, canonical

    def read_verified(
        self, relative_path: str, *, expected_sha256: str, expected_bytes: int
    ) -> ArchiveAssetSnapshot:
        target, normalized = self._target(relative_path)
        path_before = target.lstat()
        if is_reparse_point(target) or not stat.S_ISREG(path_before.st_mode):
            raise SourceBoundaryError("archive asset must be a regular non-reparse file")
        with target.open("rb") as handle:
            handle_before = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(handle_before.st_mode)
                or _identity(handle_before) != _identity(path_before)
            ):
                raise UnstableSourceError(
                    "opened archive asset identity differs from path identity"
                )
            content = handle.read()
            handle_after = os.fstat(handle.fileno())
        path_after = target.lstat()
        if (
            is_reparse_point(target)
            or not stat.S_ISREG(path_after.st_mode)
            or _identity(path_before) != _identity(handle_before)
            or _identity(handle_before) != _identity(handle_after)
            or _identity(handle_after) != _identity(path_after)
        ):
            raise UnstableSourceError("archive asset changed while being read")
        digest = sha256_hex(content)
        if len(content) != expected_bytes or digest != expected_sha256:
            raise SourceBoundaryError("archive asset bytes do not match frozen manifest identity")
        return ArchiveAssetSnapshot(
            relative_path=normalized,
            content=content,
            sha256=digest,
            bytes=len(content),
        )


class ReadOnlyArchiveSource:
    def __init__(self, root: Path):
        configured = root.absolute()
        try:
            ensure_no_reparse_components(configured)
        except ConfigurationError as error:
            raise SourceBoundaryError("archive root contains a reparse component") from error
        self.root = configured.resolve(strict=True)
        if is_reparse_point(self.root) or not self.root.is_dir():
            raise SourceBoundaryError("archive root must be a real directory")

    def _target(self, relative_path: str | Path) -> tuple[Path, str]:
        pure = PurePath(relative_path)
        if (
            pure.is_absolute()
            or pure.drive
            or not pure.parts
            or any(
                part in ("", ".", "..")
                or ":" in part
                or part.endswith((" ", "."))
                or any(unicodedata.category(character) == "Cc" for character in part)
                for part in pure.parts
            )
        ):
            raise SourceBoundaryError("archive path must be a normalized relative path")
        current = self.root
        for part in pure.parts:
            current = current / part
            try:
                if is_reparse_point(current):
                    raise SourceBoundaryError("archive path contains a reparse component")
            except (FileNotFoundError, NotADirectoryError) as error:
                raise SourceBoundaryError("archive source does not exist") from error
        try:
            resolved = current.resolve(strict=True)
        except (FileNotFoundError, NotADirectoryError, RuntimeError) as error:
            raise SourceBoundaryError("archive source does not exist or cannot be resolved") from error
        try:
            resolved.relative_to(self.root)
        except ValueError as error:
            raise SourceBoundaryError("archive path escapes configured root") from error
        canonical_relative = resolved.relative_to(self.root).as_posix()
        validate_archive_relative_path(canonical_relative)
        return resolved, canonical_relative

    def _after_read(self, path: Path) -> None:
        """Test seam executed after bytes are read and before stability recheck."""

    def snapshot(self, relative_path: str | Path) -> SourceSnapshot:
        target, normalized = self._target(relative_path)
        path_before = target.lstat()
        if is_reparse_point(target) or not stat.S_ISREG(path_before.st_mode):
            raise SourceBoundaryError("archive source must be a regular non-reparse file")
        with target.open("rb") as handle:
            handle_before = os.fstat(handle.fileno())
            if not stat.S_ISREG(handle_before.st_mode) or _identity(handle_before) != _identity(path_before):
                raise UnstableSourceError("opened source identity differs from path identity")
            content = handle.read()
            handle_after = os.fstat(handle.fileno())
        self._after_read(target)
        path_after = target.lstat()
        if is_reparse_point(target) or not stat.S_ISREG(path_after.st_mode):
            raise UnstableSourceError("source path changed type during read")
        if (
            _identity(path_before) != _identity(handle_before)
            or _identity(handle_before) != _identity(handle_after)
            or _identity(handle_after) != _identity(path_after)
            or len(content) != handle_after.st_size
        ):
            raise UnstableSourceError("archive source changed while being snapshotted")
        try:
            content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise SourceBoundaryError("archive Markdown source must be valid UTF-8") from error
        digest = sha256_hex(content)
        observed_at = validate_utc_z(utc_now())
        return SourceSnapshot(
            namespace="archive",
            relative_path=normalized,
            origin_uri=archive_origin_uri(normalized),
            content=content,
            sha256=digest,
            bytes=len(content),
            observed_at=observed_at,
        )
