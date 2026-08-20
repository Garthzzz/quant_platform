"""Versioned reference compiler contracts.

The contracts in this module deliberately contain only immutable, rebuildable
content.  Mutable comments and deployment pointers are outside this package.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
from typing import Any, Literal


KnowledgeStatus = Literal[
    "pending", "ready", "failed_retryable", "blocked_policy"
]
DocumentStatus = Literal["active", "tombstoned", "deprecated"]


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def content_hash(protocol: str, value: object) -> str:
    payload = protocol.encode("ascii") + b"\0" + canonical_json(value).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class SourceSpan:
    span_id: str
    kind: str
    line_start: int
    line_end: int
    byte_start: int
    byte_end: int
    source_sha256: str
    text_sha256: str
    text: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class IRBlock:
    block_id: str
    kind: str
    source_span: SourceSpan
    heading_path: tuple[str, ...]
    parent_block_id: str | None
    text: str
    attributes: dict[str, Any] = field(default_factory=dict)
    spans: tuple[SourceSpan, ...] = ()


@dataclass(frozen=True, slots=True)
class DocumentIR:
    schema_version: str
    parser_version: str
    source_sha256: str
    source_bytes: int
    document_id: str
    document_version_id: str
    logical_path: str
    title: str
    metadata: dict[str, Any]
    blocks: tuple[IRBlock, ...]
    ir_hash: str


@dataclass(frozen=True, slots=True)
class Chunk:
    chunk_id: str
    document_id: str
    document_version_id: str
    chunker_version: str
    role: Literal["leaf", "parent", "child"]
    heading_path: tuple[str, ...]
    ordered_span_ids: tuple[str, ...]
    byte_start: int
    byte_end: int
    line_start: int
    line_end: int
    text: str
    content_sha256: str
    parent_chunk_id: str | None = None
    previous_chunk_id: str | None = None
    next_chunk_id: str | None = None
    retrievable: bool = True
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class DocumentVersion:
    document_version_id: str
    document_id: str
    research_id: str
    source_sha256: str
    source_bytes: int
    source_object_id: str
    logical_path: str
    aliases: tuple[str, ...]
    supersedes: str | None
    external_ai_allowed: bool
    external_ai_policy_reason: str
    knowledge_status: KnowledgeStatus
    ir_hash: str
    rendered_html_sha256: str
    chunk_membership_hash: str
    lexical_membership_hash: str


@dataclass(frozen=True, slots=True)
class DocumentRecord:
    document_id: str
    research_id: str
    canonical_path: str
    aliases: tuple[str, ...]
    active_version_id: str | None
    version_ids: tuple[str, ...]
    status: DocumentStatus = "active"
    tombstone_reason: str | None = None
    replacement_document_id: str | None = None


@dataclass(frozen=True, slots=True)
class BaseSnapshot:
    schema_version: str
    compiler_version: str
    policy_version: str
    snapshot_id: str
    documents: dict[str, DocumentRecord]
    versions: dict[str, DocumentVersion]
    ir_documents: dict[str, DocumentIR]
    chunks: dict[str, Chunk]
    active_membership: dict[str, str]
    external_ai_membership: dict[str, dict[str, Any]]
    knowledge_status_membership: dict[str, KnowledgeStatus]
    page_membership: dict[str, str]
    lexical_membership: tuple[tuple[str, str], ...]
    page_membership_hash: str
    chunk_membership_hash: str
    lexical_membership_hash: str
    knowledge_membership_hash: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return canonical_json(self.to_dict())


@dataclass(frozen=True, slots=True)
class QuarantineItem:
    logical_path: str
    code: str
    detail: str


@dataclass(frozen=True, slots=True)
class CompileReport:
    status: Literal["PASS", "PARTIAL", "ERROR"]
    candidate_snapshot: BaseSnapshot | None
    effective_snapshot: BaseSnapshot | None
    activation_allowed: bool
    compiled_paths: tuple[str, ...]
    reused_paths: tuple[str, ...]
    retained_prior_paths: tuple[str, ...]
    supporting_paths: tuple[str, ...]
    quarantined: tuple[QuarantineItem, ...]
    notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class TombstoneDirective:
    document_id: str
    reason: str
    replacement_document_id: str | None = None
    deprecated: bool = False


__all__ = [
    "BaseSnapshot",
    "Chunk",
    "CompileReport",
    "DocumentIR",
    "DocumentRecord",
    "DocumentStatus",
    "DocumentVersion",
    "IRBlock",
    "KnowledgeStatus",
    "QuarantineItem",
    "SourceSpan",
    "TombstoneDirective",
    "canonical_json",
    "content_hash",
]
