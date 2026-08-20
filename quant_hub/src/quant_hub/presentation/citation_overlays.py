from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

from quant_hub.config import Settings
from quant_hub.evidence.ids import citation_id_for_marker


_SCHEMA_VERSION = "qrh-reviewed-citation-projection/v1"
_MANIFEST = Path(__file__).with_name("citation_projection_overrides.json")


class CitationOverlayError(ValueError):
    """The reviewed presentation mapping no longer matches its immutable source."""


@dataclass(frozen=True, slots=True)
class CitationOverlay:
    citation_id: str
    document_sha256: str
    source_path: str
    line_number: int
    byte_start: int
    byte_end: int
    marker: str
    context_text: str
    source_candidate_id: str
    relation_summary_zh: str
    paper: dict[str, Any]


def _line_material(payload: bytes) -> tuple[list[bytes], list[int]]:
    lines = payload.splitlines(keepends=True)
    offsets: list[int] = []
    current = 0
    for line in lines:
        offsets.append(current)
        current += len(line)
    return lines, offsets


def _line_body(value: bytes) -> bytes:
    if value.endswith(b"\r\n"):
        return value[:-2]
    if value.endswith((b"\n", b"\r")):
        return value[:-1]
    return value


def _exact_positions(haystack: bytes, needle: bytes) -> list[int]:
    positions: list[int] = []
    cursor = 0
    while needle:
        position = haystack.find(needle, cursor)
        if position < 0:
            break
        positions.append(position)
        cursor = position + len(needle)
    return positions


class CitationOverlayRegistry:
    """Verified, display-only repairs for malformed historical citation spans.

    The evidence ledger remains append-only and queryable.  This registry only
    supplies the smallest exact source span that should receive an interactive
    citation marker.  Every mapping is sealed to the source SHA-256 and a unique
    UTF-8 marker on a reviewed line, so a changed Archive document fails closed.
    """

    def __init__(self, settings: Settings, *, manifest_path: Path | None = None):
        self.settings = settings
        self.manifest_path = manifest_path or _MANIFEST
        self._loaded = False
        self._by_document: dict[str, tuple[CitationOverlay, ...]] = {}
        self._by_id: dict[str, CitationOverlay] = {}
        self._declared_documents: set[str] = set()

    def for_document(self, document_sha256: str) -> tuple[CitationOverlay, ...]:
        self._load()
        if document_sha256 in self._declared_documents and document_sha256 not in self._by_document:
            raise CitationOverlayError("reviewed citation projection source is unavailable")
        return self._by_document.get(document_sha256, ())

    def detail(self, citation_id: str) -> CitationOverlay | None:
        self._load()
        return self._by_id.get(citation_id)

    def _load(self) -> None:
        if self._loaded:
            return
        raw = self.manifest_path.read_bytes()
        try:
            manifest = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CitationOverlayError("citation projection manifest is not valid UTF-8 JSON") from error
        if manifest.get("schema_version") != _SCHEMA_VERSION:
            raise CitationOverlayError("unsupported citation projection manifest")
        documents = manifest.get("documents")
        if not isinstance(documents, list):
            raise CitationOverlayError("citation projection documents must be a list")

        by_document: dict[str, list[CitationOverlay]] = {}
        by_id: dict[str, CitationOverlay] = {}
        declared_documents: set[str] = set()
        for document in documents:
            if not isinstance(document, dict):
                raise CitationOverlayError("citation projection document must be an object")
            declared_documents.add(str(document.get("document_sha256") or ""))
            overlay_rows = self._load_document(document)
            for overlay in overlay_rows:
                if overlay.citation_id in by_id:
                    raise CitationOverlayError("citation projection generated a duplicate citation ID")
                by_id[overlay.citation_id] = overlay
                by_document.setdefault(overlay.document_sha256, []).append(overlay)

        self._by_document = {
            key: tuple(sorted(value, key=lambda item: (item.byte_start, item.byte_end)))
            for key, value in by_document.items()
        }
        self._by_id = by_id
        self._declared_documents = declared_documents
        self._loaded = True

    def _load_document(self, document: dict[str, Any]) -> tuple[CitationOverlay, ...]:
        document_sha256 = str(document.get("document_sha256") or "")
        if len(document_sha256) != 64 or any(value not in "0123456789abcdef" for value in document_sha256):
            raise CitationOverlayError("citation projection document SHA-256 is invalid")
        source_path = str(document.get("source_path") or "")
        relative = PurePosixPath(source_path)
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise CitationOverlayError("citation projection source path is unsafe")
        path = self.settings.archive_root.joinpath(*relative.parts)
        if not path.is_file():
            # Isolated Evidence unit tests and partial deployments may not carry
            # this Archive document.  Requests for its declared SHA still fail
            # closed in ``for_document``; unrelated citation queries stay usable.
            return ()
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != document_sha256:
            raise CitationOverlayError(
                f"citation projection source hash changed: {source_path}"
            )
        try:
            payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise CitationOverlayError("citation projection source is not UTF-8") from error
        lines, offsets = _line_material(payload)
        rows = document.get("entries")
        if not isinstance(rows, list) or not rows:
            raise CitationOverlayError("citation projection document has no entries")

        result: list[CitationOverlay] = []
        keys: set[str] = set()
        spans: set[tuple[int, int]] = set()
        for row in rows:
            if not isinstance(row, dict):
                raise CitationOverlayError("citation projection entry must be an object")
            key = str(row.get("key") or "")
            if not key or key in keys:
                raise CitationOverlayError("citation projection keys must be non-empty and unique")
            keys.add(key)
            line_number = int(row.get("line_number") or 0)
            if line_number < 1 or line_number > len(lines):
                raise CitationOverlayError(f"citation projection line is outside source: {key}")
            marker = str(row.get("marker") or "")
            marker_bytes = marker.encode("utf-8")
            body = _line_body(lines[line_number - 1])
            positions = _exact_positions(body, marker_bytes)
            if len(positions) != 1:
                raise CitationOverlayError(
                    f"citation projection marker must be unique on reviewed line: {key}"
                )
            byte_start = offsets[line_number - 1] + positions[0]
            byte_end = byte_start + len(marker_bytes)
            span = (byte_start, byte_end)
            if span in spans:
                raise CitationOverlayError(f"citation projection repeats a source span: {key}")
            spans.add(span)
            paper = row.get("paper")
            if not isinstance(paper, dict) or not str(paper.get("title") or ""):
                raise CitationOverlayError(f"citation projection paper metadata is incomplete: {key}")
            external_links = paper.get("external_links", [])
            if not isinstance(external_links, list) or any(
                not isinstance(item, dict)
                or not str(item.get("url") or "").startswith("https://")
                for item in external_links
            ):
                raise CitationOverlayError(f"citation projection external links are invalid: {key}")
            relation_summary = str(row.get("relation_summary_zh") or "").strip()
            if not relation_summary:
                raise CitationOverlayError(f"citation projection relation summary is empty: {key}")
            citation_id = citation_id_for_marker(
                document_sha256, byte_start, byte_end, marker_bytes
            )
            result.append(
                CitationOverlay(
                    citation_id=citation_id,
                    document_sha256=document_sha256,
                    source_path=source_path,
                    line_number=line_number,
                    byte_start=byte_start,
                    byte_end=byte_end,
                    marker=marker,
                    context_text=body.decode("utf-8"),
                    source_candidate_id=str(row.get("source_candidate_id") or ""),
                    relation_summary_zh=relation_summary,
                    paper=dict(paper),
                )
            )
        return tuple(result)
