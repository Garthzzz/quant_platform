"""Immutable view model over one effective deterministic knowledge snapshot.

This catalog is deliberately separate from the Archive catalog.  Existing V39
documents keep their established routes and renderer; only documents explicitly
installed in this catalog can enter the generic namespace.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import json
import posixpath
import re
from types import MappingProxyType
from typing import Literal, Mapping, Sequence
from urllib.parse import urlsplit

from quant_hub.knowledge.compiler import validate_snapshot
from quant_hub.collaboration.comment_anchors import (
    CommentAnchorSnapshot,
    CommentTargetInput,
    SnapshotBlock,
    SnapshotDocument,
)
from quant_hub.knowledge.contracts import (
    BaseSnapshot,
    DocumentIR,
    DocumentVersion,
    IRBlock,
    SourceSpan,
    content_hash,
)
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
    acceptance: Literal["source_explicit", "mechanically_verified", "human_accepted"]


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
class GenericCommentAnchorOption:
    span_id: str
    block_type: str
    label: str
    line_start: int
    line_end: int


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
    comment_anchor_options: tuple[GenericCommentAnchorOption, ...]


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
        effective_snapshot_id: str | None = None,
        knowledge_status_membership: Mapping[str, str] | None = None,
        release_manifest_sha256: str | None = None,
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
        self._effective_snapshot_id = effective_snapshot_id or snapshot.snapshot_id
        self._release_manifest_sha256 = release_manifest_sha256 or content_hash(
            "qrh-generic-catalog-manifest-surrogate/v1",
            {
                "base_snapshot_id": snapshot.snapshot_id,
                "effective_snapshot_id": self._effective_snapshot_id,
            },
        )
        if not re.fullmatch(r"[0-9a-f]{64}", self._release_manifest_sha256):
            raise GenericCatalogError("release manifest SHA-256 is invalid")
        self._knowledge_status = MappingProxyType(
            dict(knowledge_status_membership or snapshot.knowledge_status_membership)
        )
        if set(self._knowledge_status) != set(snapshot.knowledge_status_membership):
            raise GenericCatalogError("knowledge status membership differs from base snapshot")
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
            if cards and self._knowledge_status.get(version_id) != "ready" and any(
                card.acceptance != "source_explicit" for card in cards
            ):
                raise GenericCatalogError(
                    "accepted knowledge requires a ready snapshot membership"
                )
            self._validate_cards(version_id, cards)
        self._page_cache: dict[tuple[str, str], GenericDocumentPage] = {}

    @property
    def base_snapshot(self) -> BaseSnapshot:
        """Return an isolated copy of the release-verified deterministic base."""

        return copy.deepcopy(self._snapshot)

    @staticmethod
    def _block_context(ir: DocumentIR, position: int) -> dict[str, object]:
        block = ir.blocks[position]
        ordinal = 1 + sum(
            prior.kind == block.kind and prior.heading_path == block.heading_path
            for prior in ir.blocks[:position]
        )
        return {
            "heading_path": list(block.heading_path),
            "ordinal": ordinal,
        }

    @staticmethod
    def _comment_block_positions(ir: DocumentIR) -> tuple[int, ...]:
        """Select deterministic leaf-like, non-overlapping anchor blocks.

        IR may contain a container (for example a list) and its child blocks.
        Comment projection deliberately chooses the smallest exact source
        occurrence so one byte range cannot resolve through two structures.
        """

        selected: list[int] = []
        for position in sorted(
            range(len(ir.blocks)),
            key=lambda index: (
                ir.blocks[index].source_span.byte_end
                - ir.blocks[index].source_span.byte_start,
                ir.blocks[index].source_span.byte_start,
                ir.blocks[index].source_span.byte_end,
                index,
            ),
        ):
            candidate = ir.blocks[position].source_span
            if candidate.byte_end <= candidate.byte_start:
                continue
            if any(
                candidate.byte_start < ir.blocks[other].source_span.byte_end
                and ir.blocks[other].source_span.byte_start < candidate.byte_end
                for other in selected
            ):
                continue
            selected.append(position)
        return tuple(
            sorted(selected, key=lambda index: ir.blocks[index].source_span.byte_start)
        )

    def comment_research_exists(self, research_id: str) -> bool:
        return any(
            version.research_id == research_id
            for version in self._snapshot.versions.values()
        )

    def _comment_document_version(
        self, research_id: str, document_id: str, version_id: str
    ) -> tuple[DocumentVersion, DocumentIR, bytes] | None:
        version = self._snapshot.versions.get(version_id)
        if (
            version is None
            or version.document_id != document_id
            or version.research_id != research_id
        ):
            return None
        return (
            version,
            self._snapshot.ir_documents[version_id],
            self.source_bytes(document_id, version_id),
        )

    def validate_comment_target(
        self,
        research_id: str,
        _target: CommentTargetInput,
        material: dict[str, object],
    ) -> str | None:
        """Prove a submitted target against immutable IR/source bytes."""

        if material["target_kind"] == "research":
            return None if self.comment_research_exists(research_id) else "研究不存在。"
        document_id = str(material["document_id"])
        record = self._snapshot.documents.get(document_id)
        if record is None or record.research_id != research_id:
            return "document_id 不属于当前 stable research identity。"
        if material["target_kind"] == "document":
            return None
        located = self._comment_document_version(
            research_id,
            document_id,
            str(material["origin_document_version_id"]),
        )
        if located is None:
            return "origin document version 不属于当前 stable document identity。"
        version, ir, source = located
        if version.source_sha256 != material["origin_source_sha256"]:
            return "origin source hash 与 document version 不一致。"
        start = int(material["origin_start_byte"])
        end = int(material["origin_end_byte"])
        exact = material["origin_exact_bytes"]
        if type(exact) is not bytes or end > len(source) or source[start:end] != exact:
            return "exact byte span 无法在 origin source 中确定性定位。"
        matching: list[IRBlock] = []
        for position in self._comment_block_positions(ir):
            block = ir.blocks[position]
            if (
                block.kind == material["origin_block_type"]
                and block.source_span.byte_start <= start
                and block.source_span.byte_end >= end
                and self._block_context(ir, position)
                == json.loads(str(material["origin_structural_context_json"]))
            ):
                matching.append(block)
        if len(matching) != 1:
            return "origin anchor 不能由唯一 IR block 确定性证明。"
        locator = json.loads(str(material["origin_locator_json"]))
        span_id = locator.get("span_id")
        valid_spans = (matching[0].source_span, *matching[0].spans)
        if not any(
            span.span_id == span_id
            and span.byte_start == start
            and span.byte_end == end
            for span in valid_spans
        ):
            return "origin locator 与确定性 IR span 不一致。"
        return None

    def comment_target(
        self,
        document_id: str,
        version_id: str,
        *,
        target_kind: Literal["document", "block", "span"],
        span_id: str | None = None,
    ) -> CommentTargetInput:
        version, _ = self._resolve_version(document_id, version_id)
        if target_kind == "document":
            return CommentTargetInput.document(document_id)
        ir = self._snapshot.ir_documents[version.document_version_id]
        source = self.source_bytes(document_id, version.document_version_id)
        candidates: list[tuple[int, IRBlock, SourceSpan]] = []
        for position in self._comment_block_positions(ir):
            block = ir.blocks[position]
            spans = (block.source_span,) if target_kind == "block" else block.spans
            for span in spans:
                if span.span_id == span_id:
                    candidates.append((position, block, span))
        if len(candidates) != 1:
            raise KeyError(span_id or "")
        position, block, span = candidates[0]
        return CommentTargetInput.anchored(
            target_kind=target_kind,
            document_id=document_id,
            origin_document_version_id=version.document_version_id,
            origin_source_sha256=version.source_sha256,
            origin_block_type=block.kind,
            origin_start_byte=span.byte_start,
            origin_end_byte=span.byte_end,
            origin_exact_bytes=source[span.byte_start : span.byte_end],
            structural_context=self._block_context(ir, position),
            locator={
                "kind": "generic-ir-span",
                "span_id": span.span_id,
                "line_start": span.line_start,
                "line_end": span.line_end,
            },
        )

    def comment_snapshot(
        self, document_id: str, version_id: str | None = None
    ) -> CommentAnchorSnapshot:
        version, is_current = self._resolve_version(document_id, version_id)
        ir = self._snapshot.ir_documents[version.document_version_id]
        source = self.source_bytes(document_id, version.document_version_id)
        return CommentAnchorSnapshot(
            snapshot_id=self._effective_snapshot_id,
            manifest_sha256=self._release_manifest_sha256,
            view="current" if is_current else "history",
            documents=(
                SnapshotDocument(
                    research_id=version.research_id,
                    document_id=document_id,
                    document_version_id=version.document_version_id,
                    source_sha256=version.source_sha256,
                    source_bytes=source,
                    blocks=tuple(
                        SnapshotBlock(
                            block_type=block.kind,
                            start_byte=block.source_span.byte_start,
                            end_byte=block.source_span.byte_end,
                            structural_context=self._block_context(ir, position),
                        )
                        for position in self._comment_block_positions(ir)
                        for block in (ir.blocks[position],)
                    ),
                ),
            ),
        )

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

    def resolve_logical_link(
        self,
        target: str,
        *,
        source_document_id: str | None = None,
        source_version_id: str | None = None,
    ) -> str | None:
        """Resolve a source Markdown link to a current generic document page."""

        parsed = urlsplit(str(target).strip())
        if parsed.scheme or parsed.netloc:
            return None

        def normalized(value: str) -> str | None:
            candidate = posixpath.normpath(value.replace("\\", "/")).lstrip("/")
            if candidate in {"", ".", ".."} or candidate.startswith("../"):
                return None
            return candidate

        direct = normalized(parsed.path)
        candidates = [direct] if direct is not None else []
        if source_document_id is not None:
            version, _ = self._resolve_version(
                source_document_id, source_version_id
            )
            relative = normalized(
                posixpath.join(posixpath.dirname(version.logical_path), parsed.path)
            )
            if relative is not None and relative not in candidates:
                candidates.append(relative)
        aliases = {
            alias.replace("\\", "/"): document_id
            for document_id, record in self._snapshot.documents.items()
            for alias in (record.canonical_path, *record.aliases)
        }
        for candidate in candidates:
            document_id = aliases.get(candidate)
            if document_id is not None:
                return document_id
        return None

    def logical_path(
        self, document_id: str, version_id: str | None = None
    ) -> str:
        version, _ = self._resolve_version(document_id, version_id)
        return version.logical_path

    def prewarm_pages(self) -> None:
        """Build immutable page projections before the service accepts traffic."""

        for document_id, record in sorted(self._snapshot.documents.items()):
            for version_id in record.version_ids:
                self.page(document_id, version_id)

    def page(
        self, document_id: str, version_id: str | None = None
    ) -> GenericDocumentPage:
        version, is_current = self._resolve_version(document_id, version_id)
        cache_key = (document_id, version.document_version_id)
        cached = self._page_cache.get(cache_key)
        if cached is not None:
            return cached
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
        comment_anchor_options = tuple(
            GenericCommentAnchorOption(
                span_id=block.source_span.span_id,
                block_type=block.kind,
                label=(block.text.strip() or block.kind)[:120],
                line_start=block.source_span.line_start,
                line_end=block.source_span.line_end,
            )
            for block in expected_ir.blocks
            if block.kind != "heading" and block.source_span.byte_end > block.source_span.byte_start
        )
        page = GenericDocumentPage(
            snapshot_id=self._effective_snapshot_id,
            document_id=document_id,
            research_id=version.research_id,
            version_id=version.document_version_id,
            source_sha256=version.source_sha256,
            source_bytes=version.source_bytes,
            logical_path=version.logical_path,
            title=expected_ir.title,
            rendered_html=rendered_html,
            is_current=is_current,
            knowledge_status=self._knowledge_status.get(
                version.document_version_id, version.knowledge_status
            ),
            toc=tuple(toc),
            references=tuple(references),
            knowledge_cards=tuple(cards),
            knowledge_evidence=evidence,
            versions=versions,
            comment_anchor_options=comment_anchor_options,
        )
        self._page_cache[cache_key] = page
        return page


__all__ = [
    "GenericCatalogError",
    "GenericCommentAnchorOption",
    "GenericDocumentPage",
    "GenericKnowledgeCard",
    "GenericResearchCatalog",
]
