from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence, TypeVar
from urllib.parse import urlsplit

from quant_hub.archive.source_reader import (
    ReadOnlyArchiveSource,
    SourceBoundaryError,
    validate_archive_relative_path,
)
from quant_hub.config import Settings
from quant_hub.evidence.ids import citation_id_for_marker


_SCHEMA_VERSION = "qrh-reviewed-citation-projection/v1"
_MANIFEST = Path(__file__).with_name("citation_projection_overrides.json")
T = TypeVar("T")


class CitationOverlayError(ValueError):
    """The reviewed presentation mapping no longer matches its immutable source."""


def citation_overlay_manifest_path() -> Path:
    """Return the runtime-bound reviewed-overlay authority used by Web."""

    return _MANIFEST


def select_non_overlapping_citations(specs: Sequence[T]) -> list[T]:
    """Select one deterministic valid/shortest citation set for every view."""

    state_priority = {"valid": 0, "conflicted": 1, "source-only": 2, "unresolved": 3}
    candidates = sorted(
        (
            item
            for item in specs
            if getattr(item, "byte_start", None) is not None
            and getattr(item, "byte_end", None) is not None
            and int(getattr(item, "byte_start")) < int(getattr(item, "byte_end"))
        ),
        key=lambda item: (
            state_priority.get(str(getattr(item, "resolution_state", "")), 9),
            int(getattr(item, "byte_end")) - int(getattr(item, "byte_start")),
            int(getattr(item, "byte_start")),
            str(getattr(item, "citation_id")),
        ),
    )
    selected: list[T] = []
    for item in candidates:
        start = int(getattr(item, "byte_start"))
        end = int(getattr(item, "byte_end"))
        if any(
            start < int(getattr(existing, "byte_end"))
            and int(getattr(existing, "byte_start")) < end
            for existing in selected
        ):
            continue
        selected.append(item)
    return sorted(
        selected,
        key=lambda item: (
            int(getattr(item, "byte_start")),
            int(getattr(item, "byte_end")),
        ),
    )


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

    def __init__(
        self,
        settings: Settings | None,
        *,
        manifest_path: Path | None = None,
        source_objects: Mapping[str, bytes] | None = None,
        source_paths: Mapping[str, str] | None = None,
    ):
        self.settings = settings
        self.manifest_path = manifest_path or _MANIFEST
        self.source_objects = source_objects
        self.source_paths = source_paths or {}
        if source_objects is None and settings is None:
            raise CitationOverlayError(
                "citation projection requires settings or immutable source objects"
            )
        try:
            self.archive_source = (
                ReadOnlyArchiveSource(settings.archive_root)
                if source_objects is None and settings is not None
                else None
            )
        except SourceBoundaryError as error:
            raise CitationOverlayError(
                "citation projection archive authority is invalid"
            ) from error
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
        if type(manifest) is not dict or set(manifest) != {
            "schema_version",
            "review_scope",
            "reviewed_at",
            "documents",
        } or manifest.get("schema_version") != _SCHEMA_VERSION or any(
            type(manifest.get(field)) is not str
            or not manifest[field].strip()
            for field in ("review_scope", "reviewed_at")
        ):
            raise CitationOverlayError("unsupported citation projection manifest")
        documents = manifest.get("documents")
        if type(documents) is not list:
            raise CitationOverlayError("citation projection documents must be a list")

        by_document: dict[str, list[CitationOverlay]] = {}
        by_id: dict[str, CitationOverlay] = {}
        declared_documents: set[str] = set()
        declared_paths: set[str] = set()
        for document in documents:
            if type(document) is not dict or set(document) != {
                "source_path",
                "document_sha256",
                "entries",
            }:
                raise CitationOverlayError("citation projection document must be an object")
            document_sha256 = document.get("document_sha256")
            source_path = document.get("source_path")
            source_path_identity = (
                source_path.casefold() if type(source_path) is str else None
            )
            if (
                type(document_sha256) is not str
                or type(source_path) is not str
                or document_sha256 in declared_documents
                or source_path_identity in declared_paths
            ):
                raise CitationOverlayError(
                    "citation projection document identity is invalid or duplicated"
                )
            declared_documents.add(document_sha256)
            assert source_path_identity is not None
            declared_paths.add(source_path_identity)
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
        document_sha256 = document["document_sha256"]
        if type(document_sha256) is not str:
            raise CitationOverlayError("citation projection document SHA-256 is invalid")
        if len(document_sha256) != 64 or any(value not in "0123456789abcdef" for value in document_sha256):
            raise CitationOverlayError("citation projection document SHA-256 is invalid")
        source_path = document["source_path"]
        if type(source_path) is not str:
            raise CitationOverlayError("citation projection source path is unsafe")
        try:
            validate_archive_relative_path(source_path)
        except SourceBoundaryError as error:
            raise CitationOverlayError(
                "citation projection source path is unsafe"
            ) from error
        rows = document.get("entries")
        if type(rows) is not list or not rows:
            raise CitationOverlayError("citation projection document has no entries")
        if self.source_objects is not None:
            payload = self.source_objects.get(document_sha256)
            configured_source_path = self.source_paths.get(document_sha256)
            if payload is not None and (
                type(configured_source_path) is not str
                or configured_source_path != source_path
            ):
                raise CitationOverlayError("citation projection source path changed")
        else:
            assert self.archive_source is not None
            try:
                snapshot = self.archive_source.snapshot(source_path)
            except SourceBoundaryError:
                payload = None
            else:
                if snapshot.relative_path != source_path:
                    raise CitationOverlayError(
                        "citation projection source path changed"
                    )
                payload = snapshot.content
        if payload is None:
            # Isolated Evidence unit tests and partial deployments may not carry
            # this Archive document.  Requests for its declared SHA still fail
            # closed in ``for_document``; unrelated citation queries stay usable.
            return ()
        if type(payload) is not bytes:
            raise CitationOverlayError("citation projection source is not immutable bytes")
        if hashlib.sha256(payload).hexdigest() != document_sha256:
            raise CitationOverlayError(
                f"citation projection source hash changed: {source_path}"
            )
        try:
            payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise CitationOverlayError("citation projection source is not UTF-8") from error
        lines, offsets = _line_material(payload)
        result: list[CitationOverlay] = []
        keys: set[str] = set()
        spans: set[tuple[int, int]] = set()
        for row in rows:
            if type(row) is not dict or set(row) != {
                "key",
                "line_number",
                "marker",
                "source_candidate_id",
                "relation_summary_zh",
                "paper",
            }:
                raise CitationOverlayError("citation projection entry must be an object")
            key = row.get("key")
            if type(key) is not str:
                raise CitationOverlayError(
                    "citation projection keys must be non-empty and unique"
                )
            if not key or key in keys:
                raise CitationOverlayError("citation projection keys must be non-empty and unique")
            keys.add(key)
            line_number = row.get("line_number")
            if type(line_number) is not int:
                raise CitationOverlayError(
                    f"citation projection line is outside source: {key}"
                )
            if line_number < 1 or line_number > len(lines):
                raise CitationOverlayError(f"citation projection line is outside source: {key}")
            marker = row.get("marker")
            if type(marker) is not str or not marker:
                raise CitationOverlayError(
                    f"citation projection marker must be unique on reviewed line: {key}"
                )
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
            paper_fields = set(paper) if type(paper) is dict else set()
            if (
                type(paper) is not dict
                or frozenset(paper_fields)
                not in {
                    frozenset({"paper_id", "title", "external_links"}),
                    frozenset({
                        "canonical_urn",
                        "title",
                        "publication_date",
                        "authors",
                        "categories",
                        "external_links",
                    }),
                }
                or type(paper.get("title")) is not str
                or not paper["title"].strip()
                or (
                    "paper_id" in paper
                    and (
                        type(paper["paper_id"]) is not str
                        or not re.fullmatch(r"paper_[0-9a-f]{32}", paper["paper_id"])
                    )
                )
                or (
                    "canonical_urn" in paper
                    and (
                        type(paper["canonical_urn"]) is not str
                        or not paper["canonical_urn"].strip()
                    )
                )
            ):
                raise CitationOverlayError(f"citation projection paper metadata is incomplete: {key}")
            if "authors" in paper and (
                type(paper["authors"]) is not list
                or not paper["authors"]
                or any(type(item) is not str or not item.strip() for item in paper["authors"])
                or type(paper["categories"]) is not list
                or not paper["categories"]
                or any(type(item) is not str or not item.strip() for item in paper["categories"])
                or type(paper["publication_date"]) is not str
                or not paper["publication_date"].strip()
            ):
                raise CitationOverlayError(f"citation projection paper metadata is incomplete: {key}")
            external_links = paper.get("external_links", [])
            if type(external_links) is not list or any(
                type(item) is not dict
                or set(item) != {"kind", "url"}
                or type(item["kind"]) is not str
                or not item["kind"].strip()
                or type(item["url"]) is not str
                or urlsplit(item["url"]).scheme != "https"
                or not urlsplit(item["url"]).netloc
                for item in external_links
            ):
                raise CitationOverlayError(f"citation projection external links are invalid: {key}")
            relation_summary_raw = row.get("relation_summary_zh")
            source_candidate_id = row.get("source_candidate_id")
            if (
                type(relation_summary_raw) is not str
                or not relation_summary_raw.strip()
                or type(source_candidate_id) is not str
                or not source_candidate_id.strip()
            ):
                raise CitationOverlayError(f"citation projection relation summary is empty: {key}")
            relation_summary = relation_summary_raw.strip()
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
                    source_candidate_id=source_candidate_id,
                    relation_summary_zh=relation_summary,
                    paper=dict(paper),
                )
            )
        return tuple(result)
