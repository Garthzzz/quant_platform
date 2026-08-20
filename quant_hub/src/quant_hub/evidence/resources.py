from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
import tempfile

from quant_hub.config import (
    ConfigurationError,
    Settings,
    ensure_no_reparse_components,
    stat_is_reparse_point,
)

from .database import evidence_connection


class EvidenceResourceError(RuntimeError):
    pass


class EvidenceResourceNotFound(EvidenceResourceError):
    pass


class EvidenceResourceCorruption(EvidenceResourceError):
    pass


@dataclass(frozen=True, slots=True)
class StagedPdf:
    content_sha256: str
    bytes: int
    relative_path: str
    created: bool


@dataclass(frozen=True, slots=True)
class ResourceResponse:
    resource_id: str
    payload: bytes
    media_type: str
    download_name: str


def _is_regular_single_link(path: Path) -> bool:
    info = path.lstat()
    return (
        stat.S_ISREG(info.st_mode)
        and not stat_is_reparse_point(info)
        and info.st_nlink == 1
    )


def _validate_relative_path(value: str) -> PurePosixPath:
    if not value or "\\" in value or ":" in value:
        raise EvidenceResourceCorruption("resource relative path is not canonical POSIX form")
    relative = PurePosixPath(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise EvidenceResourceCorruption("resource path escapes the managed root")
    return relative


class EvidenceResourceStore:
    """内容寻址 PDF 资源区；公开读取只接受数据库 `resource_id`。"""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.root = settings.research_papers_root.absolute()

    def _ensure_root(self) -> None:
        try:
            ensure_no_reparse_components(self.root)
            self.root.mkdir(parents=True, exist_ok=True)
            ensure_no_reparse_components(self.root)
            info = self.root.lstat()
        except (ConfigurationError, OSError) as error:
            raise EvidenceResourceError("research_papers root is unsafe") from error
        if not stat.S_ISDIR(info.st_mode) or stat_is_reparse_point(info):
            raise EvidenceResourceError("research_papers root must be a real directory")

    def _ensure_directory(self, path: Path) -> None:
        try:
            ensure_no_reparse_components(path)
            path.mkdir(exist_ok=True)
            ensure_no_reparse_components(path)
            info = path.lstat()
        except (ConfigurationError, OSError) as error:
            raise EvidenceResourceError("resource shard directory is unsafe") from error
        if not stat.S_ISDIR(info.st_mode) or stat_is_reparse_point(info):
            raise EvidenceResourceError("resource shard is not a real directory")

    @staticmethod
    def relative_pdf_path(digest: str) -> PurePosixPath:
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError("PDF digest must be lowercase SHA-256 hex")
        return PurePosixPath("objects", digest[:2], digest[2:4], f"{digest}.pdf")

    @staticmethod
    def _verify_pdf(payload: bytes) -> None:
        if len(payload) < 5 or not payload.startswith(b"%PDF-"):
            raise EvidenceResourceCorruption("resource does not have PDF magic bytes")

    def _verify_file(self, path: Path, digest: str, expected_bytes: int) -> bytes:
        try:
            if not _is_regular_single_link(path):
                raise EvidenceResourceCorruption(
                    "resource must be a regular, non-reparse, single-link file"
                )
            payload = path.read_bytes()
            if not _is_regular_single_link(path):
                raise EvidenceResourceCorruption("resource path changed during verification")
        except FileNotFoundError as error:
            raise EvidenceResourceNotFound("resource bytes are missing") from error
        if len(payload) != expected_bytes or hashlib.sha256(payload).hexdigest() != digest:
            raise EvidenceResourceCorruption("resource bytes do not match database identity")
        self._verify_pdf(payload)
        return payload

    def put_pdf(self, payload: bytes) -> StagedPdf:
        self._verify_pdf(payload)
        self._ensure_root()
        digest = hashlib.sha256(payload).hexdigest()
        relative = self.relative_pdf_path(digest)
        current = self.root
        for part in relative.parts[:-1]:
            current = current / part
            self._ensure_directory(current)
        target = self.root.joinpath(*relative.parts)
        if os.path.lexists(target):
            self._verify_file(target, digest, len(payload))
            return StagedPdf(digest, len(payload), relative.as_posix(), False)

        descriptor, temporary_name = tempfile.mkstemp(prefix=".qrh-evidence-", dir=target.parent)
        temporary = Path(temporary_name)
        created = False
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            if hashlib.sha256(temporary.read_bytes()).hexdigest() != digest:
                raise EvidenceResourceCorruption("temporary PDF verification failed")
            try:
                os.link(temporary, target)
                created = True
            except FileExistsError:
                self._verify_file(target, digest, len(payload))
            except OSError as error:
                if os.path.lexists(target):
                    self._verify_file(target, digest, len(payload))
                else:
                    raise EvidenceResourceError("atomic PDF finalize failed") from error
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        self._verify_file(target, digest, len(payload))
        return StagedPdf(digest, len(payload), relative.as_posix(), created)

    def put_pdf_from_path(self, source: Path) -> StagedPdf:
        try:
            if not _is_regular_single_link(source):
                raise EvidenceResourceError("PDF source is not a regular single-link file")
            payload = source.read_bytes()
        except FileNotFoundError as error:
            raise EvidenceResourceNotFound("PDF source does not exist") from error
        return self.put_pdf(payload)

    def resource_response(self, resource_id: str) -> ResourceResponse:
        """安全 route service contract；调用方不得传路径。"""

        if not resource_id or "/" in resource_id or "\\" in resource_id or ".." in resource_id:
            raise EvidenceResourceNotFound("resource ID is not canonical")
        with evidence_connection(self.settings) as connection:
            row = connection.execute(
                """
                SELECT resource_id,media_type,content_sha256,bytes,relative_path,
                       verification_status
                FROM paper_resource WHERE resource_id=?
                """,
                (resource_id,),
            ).fetchone()
        if row is None or row["verification_status"] != "verified":
            raise EvidenceResourceNotFound("verified evidence resource not found")
        if row["media_type"] != "application/pdf":
            raise EvidenceResourceCorruption("registered PDF has an unexpected MIME type")
        relative = _validate_relative_path(str(row["relative_path"]))
        self._ensure_root()
        current = self.root
        for part in relative.parts[:-1]:
            current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError as error:
                raise EvidenceResourceNotFound("resource directory is missing") from error
            if not stat.S_ISDIR(info.st_mode) or stat_is_reparse_point(info):
                raise EvidenceResourceCorruption("resource path contains an unsafe component")
        target = self.root.joinpath(*relative.parts)
        payload = self._verify_file(
            target, str(row["content_sha256"]), int(row["bytes"])
        )
        return ResourceResponse(
            resource_id=str(row["resource_id"]),
            payload=payload,
            media_type="application/pdf",
            download_name=f"{resource_id}.pdf",
        )
