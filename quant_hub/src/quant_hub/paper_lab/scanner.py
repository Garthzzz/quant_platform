from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path
import re

from quant_hub.config import Settings, ensure_no_reparse_components, is_reparse_point
from .identity import stable_public_id


_STANDARD = re.compile(r"^(?P<id>[0-9]{1,5})[_\-\s](?P<title>.+)\.pdf$", re.IGNORECASE)
_DATE = re.compile(r"^(?P<date>[0-9]{8})[_\-](?P<rest>.+)\.pdf$", re.IGNORECASE)
_INSTITUTION_SUFFIXES = ("证券", "基金", "资产", "投资", "期货", "研究")


@dataclass(frozen=True, slots=True)
class ScanCandidate:
    candidate_id: str
    original_filename: str
    legacy_id_hint: str | None
    title_hint: str
    institution_hint: str | None
    naming_kind: str
    content_sha256: str
    bytes: int
    pdf_header_valid: bool
    status: str
    reason: str | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ScanReport:
    status: str
    drop_root: str
    candidates: tuple[ScanCandidate, ...]
    source_file_count: int
    source_manifest_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "drop_root": self.drop_root,
            "source_file_count": self.source_file_count,
            "source_manifest_sha256": self.source_manifest_sha256,
            "candidates": [item.to_dict() for item in self.candidates],
        }


def _sha256(path: Path) -> tuple[str, int, bytes]:
    digest = hashlib.sha256()
    size = 0
    prefix = b""
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            if not prefix:
                prefix = chunk[:8]
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size, prefix


def _name_hints(name: str) -> tuple[str | None, str, str | None, str]:
    standard = _STANDARD.fullmatch(name)
    if standard:
        return (
            str(int(standard.group("id"))),
            standard.group("title"),
            None,
            "standard",
        )
    dated = _DATE.fullmatch(name)
    if dated:
        rest = dated.group("rest")
        parts = re.split(r"[_\-]", rest, maxsplit=1)
        if len(parts) == 2 and any(mark in parts[0] for mark in _INSTITUTION_SUFFIXES):
            return None, parts[1], parts[0], "dated"
        return None, rest, None, "dated"
    return None, Path(name).stem, None, "unrecognized"


class PaperDropScanner:
    """纯读发现器；不 rename、不创建来源 sidecar、不分配顺序 ID。"""

    def __init__(self, settings: Settings):
        self.settings = settings

    def scan(self) -> ScanReport:
        self.settings.validate()
        root = self.settings.paper_lab_drop_root
        ensure_no_reparse_components(root)
        root.mkdir(parents=True, exist_ok=True)
        ensure_no_reparse_components(root)

        candidates: list[ScanCandidate] = []
        manifest_lines: list[str] = []
        for path in sorted(root.iterdir(), key=lambda item: item.name.casefold()):
            if path.suffix.casefold() != ".pdf":
                continue
            if is_reparse_point(path) or not path.is_file():
                candidates.append(
                    ScanCandidate(
                        candidate_id=stable_public_id("labcand", path.name, "unsafe"),
                        original_filename=path.name,
                        legacy_id_hint=None,
                        title_hint=path.stem,
                        institution_hint=None,
                        naming_kind="unrecognized",
                        content_sha256="0" * 64,
                        bytes=0,
                        pdf_header_valid=False,
                        status="rejected",
                        reason="non_regular_or_reparse_input",
                    )
                )
                continue
            digest, size, prefix = _sha256(path)
            legacy_id, title, institution, naming = _name_hints(path.name)
            header_ok = prefix.startswith(b"%PDF-")
            status = "discovered" if header_ok else "quarantined"
            reason = None if header_ok else "invalid_pdf_header"
            candidate = ScanCandidate(
                candidate_id=stable_public_id("labcand", digest, path.name),
                original_filename=path.name,
                legacy_id_hint=legacy_id,
                title_hint=title,
                institution_hint=institution,
                naming_kind=naming,
                content_sha256=digest,
                bytes=size,
                pdf_header_valid=header_ok,
                status=status,
                reason=reason,
            )
            candidates.append(candidate)
            manifest_lines.append(f"{path.name}\t{size}\t{digest}")

        manifest = hashlib.sha256("\n".join(manifest_lines).encode("utf-8")).hexdigest()
        failed = any(item.status in {"quarantined", "rejected"} for item in candidates)
        return ScanReport(
            status="PARTIAL" if failed else "PASS",
            drop_root=str(root),
            candidates=tuple(candidates),
            source_file_count=len(candidates),
            source_manifest_sha256=manifest,
        )
