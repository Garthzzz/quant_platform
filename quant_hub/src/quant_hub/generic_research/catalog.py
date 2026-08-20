"""Immutable view model over one effective deterministic knowledge snapshot.

This catalog is deliberately separate from the Archive catalog.  Existing V39
documents keep their established routes and renderer; only documents explicitly
installed in this catalog can enter the generic namespace.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
from types import MappingProxyType
from typing import Literal, Mapping, Sequence
from urllib.parse import urlsplit

from quant_hub.knowledge.compiler import validate_snapshot
from quant_hub.knowledge.contracts import BaseSnapshot, DocumentVersion, SourceSpan
from quant_hub.knowledge.ir import build_document_ir


class GenericCatalogError(ValueError):
    """The installed view cannot be proven to represent its bound snapshot."""


KnowledgeKind = Literal["method", "condition", "limitation", "failure", "summary"]


@dataclass(frozen=True, slots=True)
class GenericKnowledgeCard:
    """Accepted knowledge only; candidates must not instantiate this contract."""

    knowledge_id: str
    kind: KnowledgeKind
    title: str
    statement: str
    evidence_span_ids: tuple[str, ...]
    acceptance: Literal["mechanically_verified", "human_accepted"]


@dataclass(frozen=True, slots=True)
class GenericLocator:
    span_id: str
    kind: str
    label: str
    line_start: int
    line_end: int
    byte_start: int
    byte_end: int
    href: str | None = None
    heading_anchor: str | None = None
    heading_level: int | None = None


@dataclass(frozen=True, slots=True)
class GenericVersionLink:
    version_id: str
    source_sha256: str
    logical_path: str
    is_current: bool
    supersedes: str | None


@dataclass(frozen=True, slots=True)
class GenericDocumentPage:
    snapshot_id: str
    document_id: str
    research_id: str
    version_id: str
    source_sha256: str
    source_bytes: int
    logical_path: str
    title: str
    rendered_html: str
    is_current: bool
    knowledge_status: str
    toc: tuple[GenericLocator, ...]
    references: tuple[GenericLocator, ...]
    knowledge_cards: tuple[GenericKnowledgeCard, ...]
    knowledge_evidence: Mapping[str, tuple[GenericLocator, ...]]
    versions: tuple[GenericVersionLink, ...]


def _safe_external_href(value: object) -> str | None:
    href = str(value or "").strip()
    if not href:
        return None
    parsed = urlsplit(href)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return None
    return href


def _locator(span: SourceSpan, *, label: str, href: str | None = None) -> GenericLocator:
    return GenericLocator(
        span_id=span.span_id,
        kind=span.kind,
        label=label,
        line_start=span.line_start,
        line_end=span.line_end,
        byte_start=span.byte_start,
        byte_end=span.byte_end,
        href=href,
    )


class GenericResearchCatalog:
    """Validate and serve a single immutable snapshot and its content objects.

    ``source_objects`` is keyed by source SHA-256, not by a release-relative
    path.  Each request rechecks bytes and rebuilds the deterministic projection;
    a missing or mismatched object fails closed instead of showing stale content.
    """

    def __init__(
        self,
        snapshot: BaseSnapshot,
        source_objects: Mapping[str, bytes],
        *,
        accepted_knowledge: Mapping[str, Sequence[GenericKnowledgeCard]] | None = None,
    ) -> None:
        validate_snapshot(snapshot)
        copied: dict[str, bytes] = {}
        for digest, value in source_objects.items():
            if type(value) is not bytes:
                raise TypeError("generic source objects must be immutable bytes")
            if hashlib.sha256(value).hexdigest() != digest:
                raise GenericCatalogError("source object key does not match its bytes")
            copied[digest] = value
        self._snapshot = copy.deepcopy(snapshot)
        self._sources: Mapping[str, bytes] = MappingProxyType(copied)
        self._knowledge: Mapping[str, tuple[GenericKnowledgeCard, ...]] = MappingProxyType(
            {
                version_id: tuple(cards)
                for version_id, cards in (accepted_knowledge or {}).items()
            }
        )
        unknown = set(self._knowledge).difference(self._snapshot.versions)
        if unknown:
            raise GenericCatalogError("knowledge references an unknown document version")
        for version_id, cards in self._knowledge.items():
            if (
                cards
                and self._snapshot.knowledge_status_membership.get(version_id) != "ready"
            ):
                raise GenericCatalogError(
                    "accepted knowledge requires a ready snapshot membership"
                )
            self._validate_cards(version_id, cards)

    def _validate_cards(
        self, version_id: str, cards: Sequence[GenericKnowledgeCard]
    ) -> None:
        ir = self._snapshot.ir_documents[version_id]
        spans = {
            span.span_id: span
            for block in ir.blocks
            for span in (block.source_span, *block.spans)
        }
        seen: set[str] = set()
        for card in cards:
            if not card.knowledge_id or card.knowledge_id in seen:
                raise GenericCatalogError("knowledge IDs must be non-empty and unique")
            seen.add(card.knowledge_id)
            if not card.title.strip() or not card.statement.strip():
                raise GenericCatalogError("accepted knowledge cannot be empty")
            if not card.evidence_span_ids:
                raise GenericCatalogError("accepted knowledge requires source evidence")
            if any(span_id not in spans for span_id in card.evidence_span_ids):
                raise GenericCatalogError("knowledge evidence escapes its document version")

    def _resolve_version(
        self, document_id: str, version_id: str | None
    ) -> tuple[DocumentVersion, bool]:
        record = self._snapshot.documents.get(document_id)
        if record is None:
            raise KeyError(document_id)
        selected = version_id or self._snapshot.active_membership.get(document_id)
        if selected is None or selected not in record.version_ids:
            raise KeyError(version_id or document_id)
        version = self._snapshot.versions[selected]
        return version, selected == self._snapshot.active_membership.get(document_id)

    def source_bytes(self, document_id: str, version_id: str | None = None) -> bytes:
        version, _ = self._resolve_version(document_id, version_id)
        source = self._sources.get(version.source_sha256)
        if source is None:
            raise GenericCatalogError("snapshot source object is unavailable")
        if len(source) != version.source_bytes:
            raise GenericCatalogError("snapshot source object length mismatch")
        if hashlib.sha256(source).hexdigest() != version.source_sha256:
            raise GenericCatalogError("snapshot source object digest mismatch")
        return source

    def page(
        self, document_id: str, version_id: str | None = None
    ) -> GenericDocumentPage:
        version, is_current = self._resolve_version(document_id, version_id)
        source = self.source_bytes(document_id, version.document_version_id)
        expected_ir = self._snapshot.ir_documents[version.document_version_id]
        actual_ir, rendered_html = build_document_ir(
            source,
            document_id=document_id,
            document_version_id=version.document_version_id,
            logical_path=version.logical_path,
        )
        if actual_ir.ir_hash != expected_ir.ir_hash:
            raise GenericCatalogError("deterministic IR no longer matches the snapshot")
        rendered_sha256 = hashlib.sha256(rendered_html.encode("utf-8")).hexdigest()
        if rendered_sha256 != version.rendered_html_sha256:
            raise GenericCatalogError("rendered page no longer matches the snapshot")

        all_spans = {
            span.span_id: span
            for block in expected_ir.blocks
            for span in (block.source_span, *block.spans)
        }
        toc: list[GenericLocator] = []
        references: list[GenericLocator] = []
        for block in expected_ir.blocks:
            if block.kind == "heading":
                toc.append(
                    GenericLocator(
                        span_id=block.source_span.span_id,
                        kind="heading",
                        label=block.text,
                        line_start=block.source_span.line_start,
                        line_end=block.source_span.line_end,
                        byte_start=block.source_span.byte_start,
                        byte_end=block.source_span.byte_end,
                        heading_anchor=str(block.attributes.get("anchor_id") or ""),
                        heading_level=int(block.attributes.get("level") or 1),
                    )
                )
            for span in block.spans:
                if span.kind == "citation":
                    references.append(
                        _locator(
                            span,
                            label=str(span.attributes.get("citation_id") or span.text),
                        )
                    )
                elif span.kind == "link":
                    href = _safe_external_href(span.attributes.get("target"))
                    references.append(_locator(span, label=href or span.text, href=href))
                elif span.kind == "figure_ref":
                    references.append(
                        _locator(
                            span,
                            label=str(span.attributes.get("caption") or span.text),
                        )
                    )

        cards = self._knowledge.get(version.document_version_id, ())
        evidence = MappingProxyType(
            {
                card.knowledge_id: tuple(
                    _locator(
                        all_spans[span_id],
                        label=(
                            next(
                                (
                                    block.text
                                    for block in expected_ir.blocks
                                    if block.source_span.span_id == span_id
                                ),
                                all_spans[span_id].text.strip()[:120],
                            )
                        ),
                    )
                    for span_id in card.evidence_span_ids
                )
                for card in cards
            }
        )
        record = self._snapshot.documents[document_id]
        versions = tuple(
            GenericVersionLink(
                version_id=item.document_version_id,
                source_sha256=item.source_sha256,
                logical_path=item.logical_path,
                is_current=item.document_version_id
                == self._snapshot.active_membership.get(document_id),
                supersedes=item.supersedes,
            )
            for item in (
                self._snapshot.versions[item_id]
                for item_id in reversed(record.version_ids)
            )
        )
        return GenericDocumentPage(
            snapshot_id=self._snapshot.snapshot_id,
            document_id=document_id,
            research_id=version.research_id,
            version_id=version.document_version_id,
            source_sha256=version.source_sha256,
            source_bytes=version.source_bytes,
            logical_path=version.logical_path,
            title=expected_ir.title,
            rendered_html=rendered_html,
            is_current=is_current,
            knowledge_status=self._snapshot.knowledge_status_membership.get(
                version.document_version_id, version.knowledge_status
            ),
            toc=tuple(toc),
            references=tuple(references),
            knowledge_cards=tuple(cards),
            knowledge_evidence=evidence,
            versions=versions,
        )


__all__ = [
    "GenericCatalogError",
    "GenericDocumentPage",
    "GenericKnowledgeCard",
    "GenericResearchCatalog",
]
