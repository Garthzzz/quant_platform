"""Atomic deterministic compiler for a growing reference Markdown root."""

from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Callable, Iterable

from quant_hub.archive.source_reader import (
    ReadOnlyArchiveSource,
    SourceBoundaryError,
    SourceSnapshot,
)
from quant_hub.config import stat_is_reparse_point
from quant_hub.ids import stable_sha256

from .chunks import build_chunks
from .contracts import (
    BaseSnapshot,
    Chunk,
    CompileReport,
    DocumentIR,
    DocumentRecord,
    DocumentVersion,
    QuarantineItem,
    TombstoneDirective,
    content_hash,
)
from .ir import DocumentIRValidationError, build_document_ir
from .policy import PolicyDecision, SourcePolicy


COMPILER_VERSION = "qrh-reference-compiler/v1"
SNAPSHOT_SCHEMA_VERSION = "qrh-deterministic-base-snapshot/v1"


def _stable_public_id(prefix: str, protocol: str, seed: str) -> str:
    return f"{prefix}_{stable_sha256(protocol, seed)[:32]}"


def _enumerate_markdown(root: Path) -> tuple[tuple[str, ...], tuple[QuarantineItem, ...]]:
    paths: list[str] = []
    issues: list[QuarantineItem] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            info = directory.lstat()
            if stat_is_reparse_point(info) or not stat.S_ISDIR(info.st_mode):
                raise SourceBoundaryError("source directory is reparse or not a directory")
            with os.scandir(directory) as entries:
                children = sorted(entries, key=lambda row: (row.name.casefold(), row.name))
        except (OSError, SourceBoundaryError) as error:
            try:
                logical = directory.relative_to(root).as_posix() or "."
            except ValueError:
                logical = "<outside-root>"
            issues.append(
                QuarantineItem(logical, "directory_boundary_rejected", type(error).__name__)
            )
            continue
        child_directories: list[Path] = []
        for entry in children:
            path = Path(entry.path)
            logical = path.relative_to(root).as_posix()
            try:
                entry_info = entry.stat(follow_symlinks=False)
            except OSError as error:
                issues.append(QuarantineItem(logical, "source_stat_failed", type(error).__name__))
                continue
            if stat_is_reparse_point(entry_info):
                if stat.S_ISDIR(entry_info.st_mode) or path.suffix.casefold() in {".md", ".markdown"}:
                    issues.append(QuarantineItem(logical, "reparse_rejected", "source boundary"))
                continue
            if stat.S_ISDIR(entry_info.st_mode):
                child_directories.append(path)
            elif path.suffix.casefold() in {".md", ".markdown"}:
                if stat.S_ISREG(entry_info.st_mode):
                    paths.append(logical)
                else:
                    issues.append(
                        QuarantineItem(logical, "non_regular_markdown", "source boundary")
                    )
        pending.extend(reversed(child_directories))
    return (
        tuple(sorted(set(paths), key=lambda value: (value.casefold(), value))),
        tuple(sorted(issues, key=lambda row: (row.logical_path.casefold(), row.code))),
    )


def _lexical_terms(text: str) -> tuple[str, ...]:
    terms: set[str] = set()
    for match in re.finditer(r"[A-Za-z][A-Za-z0-9_.+-]*|[0-9]+(?:\.[0-9]+)?|[\u3400-\u9fff]+", text):
        value = match.group(0).casefold()
        terms.add(value)
        if value and "\u3400" <= value[0] <= "\u9fff":
            terms.update(value[index : index + 2] for index in range(max(0, len(value) - 1)))
    return tuple(sorted(terms))


def _membership_hash(protocol: str, value: object) -> str:
    return content_hash(protocol, value)


def _empty_snapshot(policy: SourcePolicy) -> BaseSnapshot:
    return _assemble_snapshot(
        policy=policy,
        documents={},
        versions={},
        ir_documents={},
        chunks={},
        active_external={},
        active_knowledge={},
    )


def _assemble_snapshot(
    *,
    policy: SourcePolicy,
    documents: dict[str, DocumentRecord],
    versions: dict[str, DocumentVersion],
    ir_documents: dict[str, DocumentIR],
    chunks: dict[str, Chunk],
    active_external: dict[str, dict[str, object]],
    active_knowledge: dict[str, str],
) -> BaseSnapshot:
    active_membership = {
        document_id: record.active_version_id
        for document_id, record in sorted(documents.items())
        if record.status == "active" and record.active_version_id is not None
    }
    page_membership = {
        document_id: versions[version_id].rendered_html_sha256
        for document_id, version_id in active_membership.items()
    }
    active_versions = set(active_membership.values())
    active_chunk_rows = sorted(
        (
            chunk.chunk_id,
            chunk.document_version_id,
            chunk.content_sha256,
            chunk.byte_start,
            chunk.byte_end,
            chunk.retrievable,
        )
        for chunk in chunks.values()
        if chunk.document_version_id in active_versions
    )
    lexical_rows = tuple(
        sorted(
            (term, chunk.chunk_id)
            for chunk in chunks.values()
            if chunk.document_version_id in active_versions and chunk.retrievable
            for term in _lexical_terms(chunk.text)
        )
    )
    page_hash = _membership_hash("qrh-page-membership/v1", page_membership)
    chunk_hash = _membership_hash("qrh-chunk-membership/v1", active_chunk_rows)
    lexical_hash = _membership_hash("qrh-lexical-membership/v1", lexical_rows)
    external_membership = {
        version_id: dict(active_external[version_id])
        for version_id in sorted(active_versions)
    }
    knowledge_membership = {
        version_id: active_knowledge[version_id] for version_id in sorted(active_versions)
    }
    knowledge_hash = _membership_hash(
        "qrh-knowledge-status-membership/v1", knowledge_membership
    )
    provisional = BaseSnapshot(
        schema_version=SNAPSHOT_SCHEMA_VERSION,
        compiler_version=COMPILER_VERSION,
        policy_version=policy.config.policy_version,
        snapshot_id="",
        documents=dict(sorted(documents.items())),
        versions=dict(sorted(versions.items())),
        ir_documents=dict(sorted(ir_documents.items())),
        chunks=dict(sorted(chunks.items())),
        active_membership=active_membership,
        external_ai_membership=external_membership,
        knowledge_status_membership=knowledge_membership,  # type: ignore[arg-type]
        page_membership=page_membership,
        lexical_membership=lexical_rows,
        page_membership_hash=page_hash,
        chunk_membership_hash=chunk_hash,
        lexical_membership_hash=lexical_hash,
        knowledge_membership_hash=knowledge_hash,
    )
    payload = asdict(provisional)
    payload.pop("snapshot_id")
    snapshot_id = "snap_" + content_hash("qrh-base-snapshot-id/v1", payload)
    return replace(provisional, snapshot_id=snapshot_id)


def validate_snapshot(snapshot: BaseSnapshot) -> None:
    spans_by_version: dict[str, set[str]] = {}
    for version_id, ir in snapshot.ir_documents.items():
        spans_by_version[version_id] = {
            span_id
            for block in ir.blocks
            for span_id in (
                block.source_span.span_id,
                *(span.span_id for span in block.spans),
            )
        }
    for chunk_id, chunk in snapshot.chunks.items():
        version = snapshot.versions.get(chunk.document_version_id)
        ir = snapshot.ir_documents.get(chunk.document_version_id)
        if version is None or ir is None or version.document_id != chunk.document_id:
            raise ValueError("chunk is not bound to one known document version")
        if any(span_id not in spans_by_version[chunk.document_version_id] for span_id in chunk.ordered_span_ids):
            raise ValueError("chunk references a span outside its document version")
        if chunk.parent_chunk_id is not None:
            parent = snapshot.chunks.get(chunk.parent_chunk_id)
            if (
                parent is None
                or parent.role != "parent"
                or parent.document_version_id != chunk.document_version_id
            ):
                raise ValueError("child chunk parent identity is invalid")
        for adjacent_id in (chunk.previous_chunk_id, chunk.next_chunk_id):
            if adjacent_id is None:
                continue
            adjacent = snapshot.chunks.get(adjacent_id)
            if adjacent is None or adjacent.document_version_id != chunk.document_version_id:
                raise ValueError("chunk adjacency escapes its document version")
    for document_id, version_id in snapshot.active_membership.items():
        document = snapshot.documents.get(document_id)
        version = snapshot.versions.get(version_id)
        ir = snapshot.ir_documents.get(version_id)
        if document is None or document.status != "active" or document.active_version_id != version_id:
            raise ValueError("active membership disagrees with document authority")
        if version is None or version.document_id != document_id:
            raise ValueError("active membership refers to wrong document version")
        if ir is None or ir.ir_hash != version.ir_hash or ir.source_sha256 != version.source_sha256:
            raise ValueError("active IR identity disagrees with source version")
        if document_id not in snapshot.page_membership:
            raise ValueError("active document is missing page membership")
        if version_id not in snapshot.external_ai_membership:
            raise ValueError("active document is missing external-AI policy membership")
        if version_id not in snapshot.knowledge_status_membership:
            raise ValueError("active document is missing knowledge status")
        if snapshot.page_membership[document_id] != version.rendered_html_sha256:
            raise ValueError("page membership does not bind the active rendered object")
        for block in ir.blocks:
            if block.source_span.source_sha256 != version.source_sha256:
                raise ValueError("IR block span belongs to another source version")
            if any(span.source_sha256 != version.source_sha256 for span in block.spans):
                raise ValueError("IR occurrence span belongs to another source version")
    active_versions = set(snapshot.active_membership.values())
    for _, chunk_id in snapshot.lexical_membership:
        chunk = snapshot.chunks.get(chunk_id)
        if chunk is None or not chunk.retrievable or chunk.document_version_id not in active_versions:
            raise ValueError("lexical membership contains stale or non-retrievable chunk")
    rebuilt = _assemble_snapshot(
        policy=SourcePolicy(),
        documents=snapshot.documents,
        versions=snapshot.versions,
        ir_documents=snapshot.ir_documents,
        chunks=snapshot.chunks,
        active_external=snapshot.external_ai_membership,
        active_knowledge=snapshot.knowledge_status_membership,
    )
    # Policy version can be customized; all artifact membership hashes must
    # nevertheless reproduce independently.
    if (
        rebuilt.active_membership != snapshot.active_membership
        or rebuilt.page_membership != snapshot.page_membership
        or rebuilt.lexical_membership != snapshot.lexical_membership
        or rebuilt.external_ai_membership != snapshot.external_ai_membership
        or rebuilt.knowledge_status_membership != snapshot.knowledge_status_membership
    ):
        raise ValueError("snapshot carries a parallel or stale artifact membership")
    if (
        rebuilt.page_membership_hash,
        rebuilt.chunk_membership_hash,
        rebuilt.lexical_membership_hash,
        rebuilt.knowledge_membership_hash,
    ) != (
        snapshot.page_membership_hash,
        snapshot.chunk_membership_hash,
        snapshot.lexical_membership_hash,
        snapshot.knowledge_membership_hash,
    ):
        raise ValueError("snapshot artifact membership does not reproduce")
    identity_payload = asdict(snapshot)
    actual_snapshot_id = identity_payload.pop("snapshot_id")
    expected_snapshot_id = "snap_" + content_hash(
        "qrh-base-snapshot-id/v1", identity_payload
    )
    if actual_snapshot_id != expected_snapshot_id:
        raise ValueError("snapshot identity does not bind its immutable content")


class ReferenceCompiler:
    def __init__(
        self,
        policy: SourcePolicy | None = None,
        *,
        ir_builder: Callable[..., tuple[DocumentIR, str]] = build_document_ir,
        max_chunk_bytes: int = 2400,
    ):
        self.policy = policy or SourcePolicy()
        self.ir_builder = ir_builder
        self.max_chunk_bytes = max_chunk_bytes

    def compile(
        self,
        source_root: Path,
        *,
        previous: BaseSnapshot | None = None,
        tombstones: Iterable[TombstoneDirective] = (),
        identity_claims: dict[str, str] | None = None,
        approved_move_revisions: frozenset[str] = frozenset(),
    ) -> CompileReport:
        previous = previous or _empty_snapshot(self.policy)
        identity_claims = identity_claims or {}
        try:
            reader = ReadOnlyArchiveSource(source_root)
            paths, boundary_issues = _enumerate_markdown(reader.root)
        except Exception as error:
            issue = QuarantineItem(".", "source_root_rejected", type(error).__name__)
            return CompileReport(
                "ERROR", None, previous, False, (), (), (), (), (issue,), (str(error),)
            )

        documents = dict(previous.documents)
        versions = dict(previous.versions)
        ir_documents = dict(previous.ir_documents)
        chunks = dict(previous.chunks)
        active_external = dict(previous.external_ai_membership)
        active_knowledge = dict(previous.knowledge_status_membership)
        quarantined = list(boundary_issues)
        supporting: list[str] = []
        compiled: list[str] = []
        reused: list[str] = []
        retained: list[str] = []
        notes: list[str] = []

        snapshots: dict[str, SourceSnapshot] = {}
        preliminary: dict[str, PolicyDecision] = {}
        for path in paths:
            try:
                snapshot = reader.snapshot(path)
            except Exception as error:
                quarantined.append(
                    QuarantineItem(path, "source_boundary_rejected", type(error).__name__)
                )
                continue
            decision = self.policy.evaluate(path, snapshot.content)
            if decision.source_class == "quarantine":
                quarantined.append(QuarantineItem(path, decision.reason_code, "policy quarantine"))
            elif decision.source_class == "supporting":
                supporting.append(path)
            else:
                snapshots[path] = snapshot
                preliminary[path] = decision

        path_index: dict[str, str] = {}
        for document_id, record in documents.items():
            for alias in record.aliases:
                existing = path_index.get(alias)
                if existing is not None and existing != document_id:
                    return CompileReport(
                        "ERROR",
                        None,
                        previous,
                        False,
                        (),
                        (),
                        (),
                        tuple(supporting),
                        tuple(quarantined),
                        ("prior snapshot contains duplicate stable path identity",),
                    )
                path_index[alias] = document_id
        current_paths = set(snapshots)
        missing_aliases_by_document = {
            document_id: tuple(alias for alias in record.aliases if alias not in current_paths)
            for document_id, record in documents.items()
        }
        assigned_documents: set[str] = set()

        for path in sorted(snapshots, key=lambda value: (value.casefold(), value)):
            source = snapshots[path]
            decision = preliminary[path]
            claimed = identity_claims.get(path)
            document_id = path_index.get(path)
            moved = False
            if claimed is not None:
                claimed_record = documents.get(claimed)
                if claimed_record is None:
                    quarantined.append(QuarantineItem(path, "identity_claim_unknown", "unknown document"))
                    continue
                active_id = claimed_record.active_version_id
                active_hash = versions[active_id].source_sha256 if active_id else None
                known_path = path in claimed_record.aliases
                if not known_path and active_hash != source.sha256 and path not in approved_move_revisions:
                    quarantined.append(
                        QuarantineItem(path, "move_with_revision_unapproved", "identity ambiguity")
                    )
                    continue
                document_id = claimed
                moved = not known_path
            elif document_id is None:
                move_candidates = []
                for candidate_id, record in documents.items():
                    if record.status != "active" or record.active_version_id is None:
                        continue
                    if not missing_aliases_by_document.get(candidate_id):
                        continue
                    if versions[record.active_version_id].source_sha256 == source.sha256:
                        move_candidates.append(candidate_id)
                if len(move_candidates) > 1:
                    quarantined.append(
                        QuarantineItem(path, "pure_move_identity_ambiguous", "multiple hash matches")
                    )
                    continue
                if len(move_candidates) == 1:
                    document_id = move_candidates[0]
                    moved = True
                else:
                    document_id = _stable_public_id("doc", "qrh-document-id/v1", path)
                    research_id = _stable_public_id("res", "qrh-research-id/v1", path)
                    documents[document_id] = DocumentRecord(
                        document_id=document_id,
                        research_id=research_id,
                        canonical_path=path,
                        aliases=(path,),
                        active_version_id=None,
                        version_ids=(),
                    )
            record = documents[document_id]
            if document_id in assigned_documents:
                quarantined.append(
                    QuarantineItem(path, "duplicate_document_identity", "two current paths map to one document")
                )
                continue
            assigned_documents.add(document_id)
            if moved:
                aliases = tuple(dict.fromkeys((*record.aliases, path)))
                record = replace(record, canonical_path=path, aliases=aliases)
                documents[document_id] = record

            active_version = versions.get(record.active_version_id or "")
            if active_version is not None and active_version.source_sha256 == source.sha256:
                reused.append(path)
                active_external[active_version.document_version_id] = {
                    "allowed": decision.external_ai_allowed,
                    "reason": decision.external_ai_reason,
                    "policy_version": self.policy.config.policy_version,
                    "logical_path": path,
                }
                active_knowledge[active_version.document_version_id] = (
                    "pending" if decision.external_ai_allowed else "blocked_policy"
                )
                continue

            version_id = _stable_public_id(
                "ver", "qrh-document-version-id/v1", f"{document_id}\0{source.sha256}"
            )
            try:
                ir, rendered_html = self.ir_builder(
                    source.content,
                    document_id=document_id,
                    document_version_id=version_id,
                    logical_path=path,
                )
                built_chunks = build_chunks(ir, max_chunk_bytes=self.max_chunk_bytes)
            except Exception as error:
                quarantined.append(
                    QuarantineItem(
                        path,
                        "invalid_structure"
                        if isinstance(error, DocumentIRValidationError)
                        else "deterministic_compile_failed",
                        type(error).__name__,
                    )
                )
                if active_version is not None:
                    retained.append(path)
                    notes.append(f"retained prior active version for {path}")
                continue
            knowledge_status = (
                "pending" if decision.external_ai_allowed else "blocked_policy"
            )
            chunk_rows = sorted(
                (chunk.chunk_id, chunk.content_sha256, chunk.byte_start, chunk.byte_end)
                for chunk in built_chunks
            )
            lexical_rows = sorted(
                (term, chunk.chunk_id)
                for chunk in built_chunks
                if chunk.retrievable
                for term in _lexical_terms(chunk.text)
            )
            version = DocumentVersion(
                document_version_id=version_id,
                document_id=document_id,
                research_id=record.research_id,
                source_sha256=source.sha256,
                source_bytes=source.bytes,
                source_object_id=f"obj_sha256_{source.sha256}",
                logical_path=path,
                aliases=record.aliases,
                supersedes=active_version.document_version_id if active_version else None,
                external_ai_allowed=decision.external_ai_allowed,
                external_ai_policy_reason=decision.external_ai_reason,
                knowledge_status=knowledge_status,
                ir_hash=ir.ir_hash,
                rendered_html_sha256=hashlib.sha256(rendered_html.encode("utf-8")).hexdigest(),
                chunk_membership_hash=_membership_hash("qrh-document-chunks/v1", chunk_rows),
                lexical_membership_hash=_membership_hash("qrh-document-lexical/v1", lexical_rows),
            )
            versions[version_id] = version
            ir_documents[version_id] = ir
            chunks.update({chunk.chunk_id: chunk for chunk in built_chunks})
            active_external[version_id] = {
                "allowed": version.external_ai_allowed,
                "reason": version.external_ai_policy_reason,
                "policy_version": self.policy.config.policy_version,
                "logical_path": path,
            }
            active_knowledge[version_id] = knowledge_status
            documents[document_id] = replace(
                record,
                active_version_id=version_id,
                version_ids=tuple(dict.fromkeys((*record.version_ids, version_id))),
                status="active",
                tombstone_reason=None,
                replacement_document_id=None,
            )
            compiled.append(path)

        directive_ids: set[str] = set()
        for directive in tombstones:
            if directive.document_id in directive_ids:
                return CompileReport(
                    "ERROR", None, previous, False, tuple(compiled), tuple(reused),
                    tuple(retained), tuple(supporting), tuple(quarantined),
                    ("duplicate tombstone directive",),
                )
            directive_ids.add(directive.document_id)
            record = documents.get(directive.document_id)
            if record is None or not directive.reason.strip():
                return CompileReport(
                    "ERROR", None, previous, False, tuple(compiled), tuple(reused),
                    tuple(retained), tuple(supporting), tuple(quarantined),
                    ("invalid tombstone directive",),
                )
            if directive.replacement_document_id is not None:
                replacement = documents.get(directive.replacement_document_id)
                if replacement is None or replacement.document_id == directive.document_id:
                    return CompileReport(
                        "ERROR", None, previous, False, tuple(compiled), tuple(reused),
                        tuple(retained), tuple(supporting), tuple(quarantined),
                        ("invalid tombstone replacement",),
                    )
            documents[directive.document_id] = replace(
                record,
                status="deprecated" if directive.deprecated else "tombstoned",
                tombstone_reason=directive.reason.strip(),
                replacement_document_id=directive.replacement_document_id,
            )

        for document_id, record in documents.items():
            if record.status == "active" and not any(alias in current_paths for alias in record.aliases):
                notes.append(
                    f"source absent without tombstone; retained active document {document_id}"
                )

        try:
            candidate = _assemble_snapshot(
                policy=self.policy,
                documents=documents,
                versions=versions,
                ir_documents=ir_documents,
                chunks=chunks,
                active_external=active_external,
                active_knowledge=active_knowledge,
            )
            validate_snapshot(candidate)
        except Exception as error:
            quarantined.append(
                QuarantineItem(".", "snapshot_consistency_failed", type(error).__name__)
            )
            return CompileReport(
                "ERROR", None, previous, False, tuple(compiled), tuple(reused),
                tuple(retained), tuple(supporting), tuple(quarantined), (str(error),),
            )
        status = "PARTIAL" if quarantined else "PASS"
        return CompileReport(
            status,
            candidate,
            candidate,
            bool(candidate.active_membership),
            tuple(compiled),
            tuple(reused),
            tuple(retained),
            tuple(sorted(supporting)),
            tuple(sorted(quarantined, key=lambda row: (row.logical_path.casefold(), row.code))),
            tuple(dict.fromkeys(notes)),
        )


__all__ = [
    "COMPILER_VERSION",
    "ReferenceCompiler",
    "SNAPSHOT_SCHEMA_VERSION",
    "validate_snapshot",
]
