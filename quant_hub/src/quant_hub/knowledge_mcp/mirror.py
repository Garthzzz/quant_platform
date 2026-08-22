"""Immutable user mirror and read-only production authority resolver."""

from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
from pathlib import PureWindowsPath
import re
import shutil
import stat
import subprocess
import threading
import time
from typing import Any, Mapping, Protocol, Sequence

from quant_hub.config import (
    ConfigurationError,
    ensure_no_reparse_components,
    stat_is_reparse_point,
)
from quant_hub.knowledge.contracts import BaseSnapshot, canonical_json, content_hash
from quant_hub.knowledge.citations import (
    CITATION_PROJECTION_SCHEMA,
    CitationAttribution,
    CitationProjection,
    citation_attributions_for_binding as projected_citation_attributions_for_binding,
    citation_ids_for_chunk as projected_citation_ids_for_chunk,
    is_valid_citation_gap,
)
from quant_hub.knowledge.retrieval import (
    ArtifactKnowledgeIndex,
    KnowledgeIndex,
    citation_attributions_for_evidence_binding,
)
from quant_hub.knowledge.semantic import EnrichedSnapshot, KnowledgeGeneration
from quant_hub.evidence.ids import citation_id_for_marker, validate_citation_id
from quant_hub.ops.release_identity import (
    manifest_sha256,
    validate_active_release,
    validate_release_manifest,
)


SEARCH_ARTIFACT_SCHEMA = "qrh-mcp-search-artifact/v2"
CITATION_SEARCH_ARTIFACT_SCHEMA = "qrh-mcp-search-artifact/v3"
LEGACY_SEARCH_ARTIFACT_SCHEMA = "qrh-mcp-search-artifact/v1"
MIRROR_METADATA_SCHEMA = "qrh-user-knowledge-mirror/v1"
MIRROR_POINTER_SCHEMA = "qrh-user-mirror-pointer/v1"
MIRROR_ACKNOWLEDGED_SCHEMA = "qrh-user-mirror-acknowledged/v1"
MIRROR_PENDING_TRANSITION_SCHEMA = "qrh-user-mirror-pending-transition/v1"
SEARCH_ARTIFACT_RELATIVE_PATH = "content/mcp_search.json"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_REMOTE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
VM_AUTHORITY_ROOT = PureWindowsPath(r"D:\quant\quant_platform")
_LOCK_REGISTRY_GUARD = threading.Lock()
_LOCK_REGISTRY: dict[str, threading.RLock] = {}

if os.name == "nt":
    import msvcrt
else:  # pragma: no cover - exercised by non-Windows CI only.
    import fcntl


class MirrorError(RuntimeError):
    pass


class AuthorityUnavailable(MirrorError):
    pass


def _retryable_sharing_error(error: OSError) -> bool:
    return (
        isinstance(error, PermissionError)
        or getattr(error, "winerror", None) in {5, 32, 33}
        or getattr(error, "errno", None) in {13, 16}
    )


def _replace_with_retry(source: Path, destination: Path) -> None:
    deadline = time.monotonic() + 5.0
    while True:
        try:
            os.replace(source, destination)
            return
        except OSError as error:
            if not _retryable_sharing_error(error) or time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


def _unlink_with_retry(path: Path) -> None:
    deadline = time.monotonic() + 5.0
    while True:
        try:
            path.unlink()
            return
        except FileNotFoundError:
            return
        except OSError as error:
            if not _retryable_sharing_error(error) or time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


def _local_lock_for(path: Path) -> threading.RLock:
    key = str(path.resolve(strict=False))
    if os.name == "nt":
        key = key.casefold()
    with _LOCK_REGISTRY_GUARD:
        return _LOCK_REGISTRY.setdefault(key, threading.RLock())


def _acquire_os_lock(handle: Any, *, timeout_seconds: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:  # pragma: no cover - exercised by non-Windows CI only.
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except OSError as error:
            if time.monotonic() >= deadline:
                raise MirrorError("mirror cross-process lock timed out") from error
            time.sleep(0.01)


def _release_os_lock(handle: Any) -> None:
    handle.seek(0)
    if os.name == "nt":
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:  # pragma: no cover - exercised by non-Windows CI only.
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@dataclass(frozen=True, slots=True)
class AuthorityIdentity:
    release_id: str
    manifest_sha256: str
    snapshot_id: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AuthorityObservation:
    identity: AuthorityIdentity
    verified_at: str


@dataclass(frozen=True, slots=True)
class MirrorSnapshot:
    root: Path
    identity: AuthorityIdentity
    synced_at: str
    artifact: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class MirrorTransition:
    from_identity: AuthorityIdentity
    to_identity: AuthorityIdentity


class AuthorityProbe(Protocol):
    def probe(self) -> AuthorityObservation: ...


class ArtifactSource(Protocol):
    """Materialize an exact, read-only release closure into local staging."""

    def stage(self, identity: AuthorityIdentity, destination: Path) -> None: ...


class CommandRunner(Protocol):
    def run(self, argv: Sequence[str], *, timeout_seconds: float) -> bytes: ...


class SubprocessCommandRunner:
    """Small shell-free process boundary with bounded, redacted failures."""

    def __init__(self, *, max_stdout_bytes: int = 64 * 1024 * 1024) -> None:
        if max_stdout_bytes < 1:
            raise ValueError("max_stdout_bytes must be positive")
        self.max_stdout_bytes = max_stdout_bytes

    def run(self, argv: Sequence[str], *, timeout_seconds: float) -> bytes:
        if not argv or timeout_seconds <= 0:
            raise AuthorityUnavailable("read-only process invocation is invalid")
        try:
            completed = subprocess.run(
                tuple(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                timeout=timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise AuthorityUnavailable("read-only OpenSSH process failed") from error
        if completed.returncode != 0:
            # Deliberately do not expose stderr: ssh configuration and remote
            # diagnostics can contain usernames, paths, or credential hints.
            raise AuthorityUnavailable("read-only OpenSSH process returned failure")
        if len(completed.stdout) > self.max_stdout_bytes:
            raise AuthorityUnavailable("read-only OpenSSH response exceeds limit")
        return completed.stdout


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise MirrorError(f"cannot read verified JSON: {path.name}") from error


def _decode_json_bytes(value: bytes, *, label: str) -> object:
    try:
        return json.loads(value.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise MirrorError(f"{label} is not valid UTF-8 JSON") from error


def _regular_file(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise MirrorError(f"required file is unavailable: {path.name}") from error
    if (
        stat_is_reparse_point(info)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
    ):
        raise MirrorError(
            f"path is not a regular non-reparse non-hard-linked file: {path.name}"
        )


def _validate_open_regular_file(path: Path, descriptor: int) -> None:
    """Bind an already-open handle to the exact safe directory entry."""

    try:
        handle_info = os.fstat(descriptor)
        path_info = path.lstat()
    except OSError as error:
        raise MirrorError("mirror lock identity is unavailable") from error
    if (
        stat_is_reparse_point(path_info)
        or not stat.S_ISREG(path_info.st_mode)
        or not stat.S_ISREG(handle_info.st_mode)
        or path_info.st_nlink != 1
        or handle_info.st_nlink != 1
        or (path_info.st_dev, path_info.st_ino)
        != (handle_info.st_dev, handle_info.st_ino)
    ):
        raise MirrorError("mirror lock must be an exact regular single-link file")


def _safe_directory(path: Path, *, must_exist: bool) -> Path:
    try:
        ensure_no_reparse_components(path)
        resolved = path.resolve(strict=must_exist)
    except (ConfigurationError, OSError) as error:
        raise MirrorError("path contains an unsafe or unavailable component") from error
    if must_exist:
        info = path.lstat()
        if stat_is_reparse_point(info) or not stat.S_ISDIR(info.st_mode):
            raise MirrorError("mirror path is not a regular directory")
    return resolved


def _identity_from_release(release: Mapping[str, object]) -> AuthorityIdentity:
    content = release.get("content")
    if not isinstance(content, Mapping):
        raise MirrorError("release content identity is unavailable")
    return AuthorityIdentity(
        release_id=str(release["release_id"]),
        manifest_sha256=manifest_sha256(release),
        snapshot_id=str(content["snapshot_id"]),
    )


def _heading_labels(ir: object, heading_path: Sequence[str]) -> list[str]:
    by_anchor = {
        str(block.attributes.get("anchor_id")): (
            int(block.attributes.get("level", 0)),
            block.text,
        )
        for block in ir.blocks  # type: ignore[attr-defined]
        if block.kind == "heading" and block.attributes.get("anchor_id")
    }
    return [
        by_anchor[anchor][1]
        for anchor in heading_path
        if anchor in by_anchor and by_anchor[anchor][0] > 1
    ]


def _native_citation_references(snapshot: BaseSnapshot) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for version_id, ir in sorted(snapshot.ir_documents.items()):
        for block in ir.blocks:
            for span in block.spans:
                if span.kind != "citation" or "citation_id" not in span.attributes:
                    continue
                citation_id = str(span.attributes["citation_id"])
                try:
                    validate_citation_id(citation_id)
                except ValueError as error:
                    raise MirrorError("native citation reference ID is not canonical") from error
                marker_bytes = span.text.encode("utf-8")
                expected_marker = f"^src:{{{citation_id}}}"
                if (
                    span.text != expected_marker
                    or span.attributes.get("locator_precision") != "exact"
                    or hashlib.sha256(marker_bytes).hexdigest() != span.text_sha256
                    or span.source_sha256 != snapshot.versions[version_id].source_sha256
                ):
                    raise MirrorError("native citation reference locator is invalid")
                rows.append(
                    {
                        "citation_id": citation_id,
                        "document_version_id": version_id,
                        "source_sha256": span.source_sha256,
                        "containing_span_id": block.source_span.span_id,
                        "line_start": span.line_start,
                        "line_end": span.line_end,
                        "byte_start": span.byte_start,
                        "byte_end": span.byte_end,
                        "raw_marker_text": span.text,
                        "raw_marker_sha256": span.text_sha256,
                    }
                )
    return sorted(
        rows,
        key=lambda row: (
            str(row["source_sha256"]),
            str(row["document_version_id"]),
            int(row["byte_start"]),
            int(row["byte_end"]),
            str(row["citation_id"]),
        ),
    )


def _merge_attributions(
    *groups: Sequence[CitationAttribution],
) -> list[dict[str, object]]:
    selected: dict[str, CitationAttribution] = {}
    candidates = sorted(
        (row for group in groups for row in group),
        key=lambda row: (
            row.citation_id,
            0 if row.relation == "contained" else 1,
            len(row.gap_text.encode("utf-8")),
            row.anchor_byte_end,
            row.gap_text,
        ),
    )
    for row in candidates:
        selected.setdefault(row.citation_id, row)
    return [selected[citation_id].to_dict() for citation_id in sorted(selected)]


def build_search_artifact(
    snapshot: BaseSnapshot,
    *,
    enriched: EnrichedSnapshot | None = None,
    generations: Sequence[KnowledgeGeneration] = (),
    citation_projection: CitationProjection | None = None,
) -> bytes:
    """Serialize rebuildable current/history evidence without release identity.

    Excluding release identity is intentional: the release can hash this
    artifact without creating a release↔artifact identity cycle.  The local
    mirror metadata binds it to a finalized release afterwards.
    """

    if enriched is not None and enriched.base_snapshot_id != snapshot.snapshot_id:
        raise MirrorError("enriched knowledge belongs to another deterministic snapshot")
    if (
        citation_projection is not None
        and citation_projection.base_snapshot_id != snapshot.snapshot_id
    ):
        raise MirrorError("citation projection belongs to another deterministic snapshot")
    artifact_snapshot_id = enriched.snapshot_id if enriched is not None else snapshot.snapshot_id
    knowledge_status = (
        enriched.knowledge_status_membership
        if enriched is not None
        else snapshot.knowledge_status_membership
    )
    versions = []
    for version_id, version in sorted(snapshot.versions.items()):
        ir = snapshot.ir_documents[version_id]
        versions.append(
            {
                "version_id": version_id,
                "document_id": version.document_id,
                "research_id": version.research_id,
                "title": ir.title,
                "logical_path": version.logical_path,
                "source_sha256": version.source_sha256,
                "source_bytes": version.source_bytes,
                "supersedes": version.supersedes,
                "knowledge_enrichment": knowledge_status.get(
                    version_id, "historical"
                ),
                "is_current": snapshot.active_membership.get(version.document_id)
                == version_id,
            }
        )
    documents = [
        {
            "document_id": document_id,
            "research_id": record.research_id,
            "canonical_path": record.canonical_path,
            "aliases": list(record.aliases),
            "active_version_id": record.active_version_id,
            "version_ids": list(record.version_ids),
            "status": record.status,
            "replacement_document_id": record.replacement_document_id,
            "tombstone_reason": record.tombstone_reason,
        }
        for document_id, record in sorted(snapshot.documents.items())
    ]
    chunks = []
    for chunk_id, chunk in sorted(snapshot.chunks.items()):
        ir = snapshot.ir_documents[chunk.document_version_id]
        native_citation_ids = {
            str(span.attributes["citation_id"])
            for block in ir.blocks
            if block.source_span.span_id in chunk.ordered_span_ids
            for span in block.spans
            if span.kind == "citation"
            and "citation_id" in span.attributes
            and chunk.byte_start <= span.byte_start
            and span.byte_end <= chunk.byte_end
        }
        citation_ids = sorted(
            native_citation_ids
            | (
                set(
                    projected_citation_ids_for_chunk(
                        citation_projection, chunk.document_version_id, chunk
                    )
                )
                if citation_projection is not None
                else set()
            )
        )
        chunks.append(
            {
                "chunk_id": chunk_id,
                "document_id": chunk.document_id,
                "document_version_id": chunk.document_version_id,
                "role": chunk.role,
                "heading_path": list(chunk.heading_path),
                "heading_labels": _heading_labels(ir, chunk.heading_path),
                "ordered_span_ids": list(chunk.ordered_span_ids),
                "citation_ids": citation_ids,
                "byte_start": chunk.byte_start,
                "byte_end": chunk.byte_end,
                "line_start": chunk.line_start,
                "line_end": chunk.line_end,
                "text": chunk.text,
                "content_sha256": chunk.content_sha256,
                "parent_chunk_id": chunk.parent_chunk_id,
                "retrievable": chunk.retrievable,
                "attributes": chunk.attributes,
            }
        )
    span_by_version = {
        version_id: {
            span.span_id: span
            for block in snapshot.ir_documents[version_id].blocks
            for span in (block.source_span, *block.spans)
        }
        for version_id in snapshot.versions
    }
    generation_by_id = {row.generation_id: row for row in generations}
    knowledge_rows: list[dict[str, object]] = []
    if enriched is not None:
        for item in sorted(
            enriched.knowledge_items.values(), key=lambda value: value.knowledge_item_id
        ):
            version_id = item.document_version_id
            if version_id not in span_by_version:
                raise MirrorError("accepted knowledge references an unknown version")
            version = snapshot.versions[version_id]
            if (
                version.document_id != item.document_id
                or snapshot.active_membership.get(item.document_id) != version_id
            ):
                raise MirrorError("accepted knowledge is not bound to the active document version")
            if item.fact_status not in {
                "source_explicit",
                "machine_verified",
                "human_reviewed",
            }:
                raise MirrorError("unaccepted knowledge cannot enter the MCP artifact")
            if item.generation_id is None:
                if item.fact_status != "source_explicit":
                    raise MirrorError(
                        "non-source knowledge must bind a verified generation"
                    )
            elif knowledge_status.get(version_id) != "ready":
                raise MirrorError("model knowledge is not in a ready active generation")
            if not item.evidence:
                raise MirrorError("accepted knowledge has no source span")
            locators: list[dict[str, object]] = []
            for binding in item.evidence:
                span = span_by_version[version_id].get(binding.span_id)
                if span is None:
                    raise MirrorError("accepted knowledge source span escapes its version")
                if hashlib.sha256(binding.quote.encode("utf-8")).hexdigest() != binding.quote_sha256:
                    raise MirrorError("accepted knowledge quote hash is invalid")
                occurrences = [
                    match.start()
                    for match in re.finditer(re.escape(binding.quote), span.text)
                ]
                if len(occurrences) != 1:
                    raise MirrorError("accepted knowledge quote is absent or ambiguous")
                prefix = span.text[: occurrences[0]]
                expected_byte_start = span.byte_start + len(prefix.encode("utf-8"))
                expected_byte_end = expected_byte_start + len(
                    binding.quote.encode("utf-8")
                )
                if (
                    binding.byte_start != expected_byte_start
                    or binding.byte_end != expected_byte_end
                ):
                    raise MirrorError("accepted knowledge quote locator is invalid")
                quote_line_start = span.line_start + prefix.count("\n")
                locators.append(
                    {
                        "span_id": span.span_id,
                        "source_sha256": span.source_sha256,
                        "line_start": quote_line_start,
                        "line_end": quote_line_start + binding.quote.count("\n"),
                        "byte_start": binding.byte_start,
                        "byte_end": binding.byte_end,
                        "quote_sha256": binding.quote_sha256,
                    }
                )
            generation: dict[str, object] | None = None
            if item.generation_id is not None:
                source_generation = generation_by_id.get(item.generation_id)
                if source_generation is None or source_generation.status != "succeeded":
                    raise MirrorError("model-derived knowledge lacks a successful generation")
                if (
                    enriched.generation_membership.get(version_id) != item.generation_id
                    or not source_generation.provider_revision
                    or not source_generation.returned_model
                    or not source_generation.system_fingerprint
                    or not source_generation.model_identity_contract_hash
                    or not source_generation.prompt_version
                    or not source_generation.output_schema_version
                    or
                    source_generation.document_version_id != version_id
                    or source_generation.source_sha256
                    != snapshot.versions[version_id].source_sha256
                ):
                    raise MirrorError("knowledge generation source identity mismatch")
                generation = {
                    "generation_id": source_generation.generation_id,
                    "requested_model_alias": source_generation.requested_model_alias,
                    "provider_revision": source_generation.provider_revision,
                    "returned_model": source_generation.returned_model,
                    "system_fingerprint": source_generation.system_fingerprint,
                    "model_identity_contract_hash": source_generation.model_identity_contract_hash,
                    "model_identity_evidence_url": source_generation.model_identity_evidence_url,
                    "model_identity_evidence_hash": source_generation.model_identity_evidence_hash,
                    "model_identity_evidence_observed_at": source_generation.model_identity_evidence_observed_at,
                    "response_id": source_generation.response_id,
                    "response_created_at": source_generation.response_created_at,
                    "response_hash": source_generation.response_hash,
                    "prompt_version": source_generation.prompt_version,
                    "output_schema_version": source_generation.output_schema_version,
                    "source_sha256": source_generation.source_sha256,
                    "ir_hash": source_generation.ir_hash,
                    "created_at": source_generation.created_at,
                }
            ir = snapshot.ir_documents[version_id]
            heading_path = next(
                (
                    list(block.heading_path)
                    for block in ir.blocks
                    if block.source_span.span_id == item.evidence[0].span_id
                ),
                [],
            )
            source_citations = []
            for binding, locator in zip(item.evidence, locators, strict=True):
                native_attributions = citation_attributions_for_evidence_binding(
                    ir, binding
                )
                projected_attributions = (
                    projected_citation_attributions_for_binding(
                        citation_projection, version_id, binding
                    )
                    if citation_projection is not None
                    else ()
                )
                attributions = _merge_attributions(
                    native_attributions, projected_attributions
                )
                member = {
                    "source_locator": locator,
                    "citation_ids": [
                        row["citation_id"] for row in attributions
                    ],
                }
                if citation_projection is not None:
                    member["citation_attributions"] = attributions
                source_citations.append(member)
            citation_ids = sorted(
                {
                    citation_id
                    for member in source_citations
                    for citation_id in member["citation_ids"]
                }
            )
            knowledge_rows.append(
                {
                    "knowledge_item_id": item.knowledge_item_id,
                    "cluster_id": item.cluster_id,
                    "document_id": item.document_id,
                    "document_version_id": version_id,
                    "kind": item.kind,
                    "text": item.text,
                    "heading_path": heading_path,
                    "heading_labels": _heading_labels(ir, heading_path),
                    "citation_ids": citation_ids,
                    "source_span_ids": [binding.span_id for binding in item.evidence],
                    "source_locator": locators[0],
                    "source_locators": locators,
                    "source_citations": source_citations,
                    "applicability": item.applicability,
                    "relation": item.relation,
                    "fact_status": item.fact_status,
                    "extractor": item.extractor,
                    "extractor_version": item.extractor_version,
                    "generation": generation,
                    "accepted_at": item.accepted_at,
                    "accepted_by": item.accepted_by,
                }
            )
    with KnowledgeIndex(
        snapshot, enriched, citation_projection=citation_projection
    ) as retrieval_index:
        retrieval = retrieval_index.export_artifact_records()
    citations = (
        [row.to_dict() for row in citation_projection.occurrences]
        if citation_projection is not None
        else []
    )
    citation_identity = (
        citation_projection.identity_dict()
        if citation_projection is not None
        else None
    )
    native_citation_references = (
        _native_citation_references(snapshot)
        if citation_projection is not None
        else []
    )
    citation_source_material: list[dict[str, object]] = []
    if citation_projection is not None:
        relevant_spans: dict[str, set[str]] = {}
        for row in native_citation_references:
            relevant_spans.setdefault(
                str(row["document_version_id"]), set()
            ).add(str(row["containing_span_id"]))
        for version_id, version in sorted(snapshot.versions.items()):
            for row in citation_projection.for_version(version_id):
                if row.source_sha256 == version.source_sha256:
                    relevant_spans.setdefault(version_id, set()).update(
                        row.containing_span_ids
                    )
        for version_id, span_ids in sorted(relevant_spans.items()):
            for block in snapshot.ir_documents[version_id].blocks:
                span = block.source_span
                if span.span_id not in span_ids:
                    continue
                citation_source_material.append(
                    {
                        "document_version_id": version_id,
                        "source_sha256": span.source_sha256,
                        "span_id": span.span_id,
                        "kind": span.kind,
                        "byte_start": span.byte_start,
                        "byte_end": span.byte_end,
                        "source_text": span.text,
                        "source_text_sha256": span.text_sha256,
                        "attributes": json.loads(canonical_json(span.attributes)),
                    }
                )
        citation_source_material.sort(
            key=lambda row: (
                str(row["source_sha256"]),
                str(row["document_version_id"]),
                int(row["byte_start"]),
                int(row["byte_end"]),
                str(row["span_id"]),
            )
        )
    canonical_members: dict[str, object] = {
        "documents": documents,
        "versions": versions,
        "chunks": chunks,
        "knowledge": sorted(
            knowledge_rows,
            key=lambda row: str(row.get("knowledge_item_id") or ""),
        ),
    }
    if citation_projection is not None:
        canonical_members["citation_projection"] = citation_identity
        canonical_members["citations"] = citations
        canonical_members["native_citation_references"] = native_citation_references
        canonical_members["citation_source_material"] = citation_source_material
    retrieval["canonical_membership_sha256"] = hashlib.sha256(
        canonical_json(canonical_members).encode("utf-8")
    ).hexdigest()
    payload = {
        "schema_version": (
            CITATION_SEARCH_ARTIFACT_SCHEMA
            if citation_projection is not None
            else SEARCH_ARTIFACT_SCHEMA
        ),
        "snapshot_id": artifact_snapshot_id,
        "knowledge_identity": (
            {
                "base_snapshot_id": enriched.base_snapshot_id,
                "snapshot_id": enriched.snapshot_id,
                "knowledge_status_membership": enriched.knowledge_status_membership,
                "generation_membership": enriched.generation_membership,
                "accepted_knowledge_hash": enriched.accepted_knowledge_hash,
                "coverage_hash": enriched.coverage_hash,
            }
            if enriched is not None
            else None
        ),
        "retrieval": retrieval,
        "documents": documents,
        "versions": versions,
        "chunks": chunks,
        "knowledge": sorted(
            knowledge_rows, key=lambda row: str(row.get("knowledge_item_id") or "")
        ),
    }
    if citation_projection is not None:
        payload["citation_projection"] = citation_identity
        payload["citations"] = citations
        payload["native_citation_references"] = native_citation_references
        payload["citation_source_material"] = citation_source_material
    return canonical_json(payload).encode("utf-8")


def validate_search_artifact(value: object, *, expected_snapshot_id: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise MirrorError("search artifact must be an object")
    schema_version = value.get("schema_version")
    current_fields = {
        "schema_version",
        "snapshot_id",
        "citation_projection",
        "citations",
        "native_citation_references",
        "citation_source_material",
        "knowledge_identity",
        "retrieval",
        "documents",
        "versions",
        "chunks",
        "knowledge",
    }
    legacy_fields = current_fields - {
        "citation_projection",
        "citations",
        "native_citation_references",
        "citation_source_material",
    }
    if (
        schema_version == CITATION_SEARCH_ARTIFACT_SCHEMA
        and set(value) != current_fields
    ) or (
        schema_version in {
            LEGACY_SEARCH_ARTIFACT_SCHEMA,
            SEARCH_ARTIFACT_SCHEMA,
        }
        and set(value) != legacy_fields
    ):
        raise MirrorError("search artifact fields are not closed")
    if schema_version not in {
        LEGACY_SEARCH_ARTIFACT_SCHEMA,
        SEARCH_ARTIFACT_SCHEMA,
        CITATION_SEARCH_ARTIFACT_SCHEMA,
    }:
        raise MirrorError("unsupported search artifact schema")
    legacy_v1 = schema_version == LEGACY_SEARCH_ARTIFACT_SCHEMA
    has_projection_contract = schema_version == CITATION_SEARCH_ARTIFACT_SCHEMA
    if value["snapshot_id"] != expected_snapshot_id:
        raise MirrorError("search artifact snapshot identity mismatch")
    identity = value["knowledge_identity"]
    if identity is not None:
        if not isinstance(identity, dict) or set(identity) != {
            "base_snapshot_id",
            "snapshot_id",
            "knowledge_status_membership",
            "generation_membership",
            "accepted_knowledge_hash",
            "coverage_hash",
        }:
            raise MirrorError("search artifact knowledge identity is invalid")
        if identity["snapshot_id"] != expected_snapshot_id:
            raise MirrorError("knowledge and search snapshot identities disagree")
        if not isinstance(identity["base_snapshot_id"], str) or not identity[
            "base_snapshot_id"
        ]:
            raise MirrorError("knowledge base snapshot identity is unavailable")
        if not isinstance(identity["knowledge_status_membership"], dict) or not isinstance(
            identity["generation_membership"], dict
        ):
            raise MirrorError("knowledge membership identity is invalid")
        if any(
            not _SHA256.fullmatch(str(identity[field]))
            for field in ("accepted_knowledge_hash", "coverage_hash")
        ):
            raise MirrorError("knowledge membership hash is invalid")
    for key in ("documents", "versions", "chunks", "knowledge"):
        if not isinstance(value[key], list):
            raise MirrorError(f"search artifact {key} must be a list")
    raw_citations = value["citations"] if has_projection_contract else []
    raw_native_citations = (
        value["native_citation_references"] if has_projection_contract else []
    )
    raw_citation_source_material = (
        value["citation_source_material"] if has_projection_contract else []
    )
    citation_projection = value["citation_projection"] if has_projection_contract else None
    if not isinstance(raw_citations, list):
        raise MirrorError("search artifact citations must be a list")
    if not isinstance(raw_native_citations, list):
        raise MirrorError("search artifact native citations must be a list")
    if not isinstance(raw_citation_source_material, list):
        raise MirrorError("search artifact citation source material must be a list")
    document_fields = {
        "document_id",
        "research_id",
        "canonical_path",
        "aliases",
        "active_version_id",
        "version_ids",
        "status",
        "replacement_document_id",
        "tombstone_reason",
    }
    version_fields = {
        "version_id",
        "document_id",
        "research_id",
        "title",
        "logical_path",
        "source_sha256",
        "source_bytes",
        "supersedes",
        "knowledge_enrichment",
        "is_current",
    }
    chunk_fields = {
        "chunk_id",
        "document_id",
        "document_version_id",
        "role",
        "heading_path",
        "heading_labels",
        "ordered_span_ids",
        "citation_ids",
        "byte_start",
        "byte_end",
        "line_start",
        "line_end",
        "text",
        "content_sha256",
        "parent_chunk_id",
        "retrievable",
        "attributes",
    }
    knowledge_fields = {
        "knowledge_item_id",
        "cluster_id",
        "document_id",
        "document_version_id",
        "kind",
        "text",
        "heading_path",
        "heading_labels",
        "citation_ids",
        "source_span_ids",
        "source_locator",
        "source_locators",
        "source_citations",
        "applicability",
        "relation",
        "fact_status",
        "extractor",
        "extractor_version",
        "generation",
        "accepted_at",
        "accepted_by",
    }
    if legacy_v1:
        knowledge_fields.remove("source_citations")

    def indexed(rows: list[object], key: str, fields: set[str]) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        previous_identifier: str | None = None
        for row in rows:
            if not isinstance(row, dict) or set(row) != fields:
                raise MirrorError(f"search artifact {key} row fields are not closed")
            identifier = row.get(key)
            if not isinstance(identifier, str) or not identifier or identifier in result:
                raise MirrorError(f"search artifact {key} identity is invalid")
            if previous_identifier is not None and identifier <= previous_identifier:
                raise MirrorError(f"search artifact {key} order is not canonical")
            result[identifier] = row
            previous_identifier = identifier
        return result

    documents = indexed(value["documents"], "document_id", document_fields)
    versions = indexed(value["versions"], "version_id", version_fields)
    chunks = indexed(value["chunks"], "chunk_id", chunk_fields)
    knowledge = indexed(value["knowledge"], "knowledge_item_id", knowledge_fields)
    for version_id, version in versions.items():
        document = documents.get(str(version["document_id"]))
        if document is None or version_id not in document["version_ids"]:
            raise MirrorError("search artifact version/document membership is invalid")
        if version.get("is_current") is True and document.get("active_version_id") != version_id:
            raise MirrorError("search artifact current version membership is invalid")
    citation_fields = {
        "citation_id",
        "source_sha256",
        "containing_span_ids",
        "line_start",
        "line_end",
        "byte_start",
        "byte_end",
        "raw_marker_text",
        "raw_marker_sha256",
        "occurrence_kind",
        "resolution_state",
        "authority_kind",
    }
    citations: dict[str, dict[str, Any]] = {}
    for raw in raw_citations:
        if not isinstance(raw, dict) or set(raw) != citation_fields:
            raise MirrorError("search artifact citation row fields are not closed")
        citation_id = raw.get("citation_id")
        source_sha256 = raw.get("source_sha256")
        marker = raw.get("raw_marker_text")
        byte_start = raw.get("byte_start")
        byte_end = raw.get("byte_end")
        if (
            not isinstance(citation_id, str)
            or citation_id in citations
            or not isinstance(source_sha256, str)
            or not _SHA256.fullmatch(source_sha256)
            or not isinstance(marker, str)
            or type(byte_start) is not int
            or type(byte_end) is not int
            or not 0 <= byte_start < byte_end
            or type(raw.get("line_start")) is not int
            or type(raw.get("line_end")) is not int
            or not 1 <= raw["line_start"] <= raw["line_end"]
            or not isinstance(raw.get("containing_span_ids"), list)
            or not raw["containing_span_ids"]
            or any(
                not isinstance(span_id, str) or not span_id
                for span_id in raw["containing_span_ids"]
            )
            or raw["containing_span_ids"]
            != sorted(set(raw["containing_span_ids"]))
            or not isinstance(raw.get("occurrence_kind"), str)
            or not raw["occurrence_kind"]
            or raw.get("resolution_state") != "valid"
            or raw.get("authority_kind")
            not in {"evidence_binding", "reviewed_overlay"}
        ):
            raise MirrorError("search artifact citation identity is invalid")
        marker_bytes = marker.encode("utf-8")
        try:
            validate_citation_id(citation_id)
        except ValueError as error:
            raise MirrorError("search artifact citation ID is not canonical") from error
        if (
            raw.get("raw_marker_sha256")
            != hashlib.sha256(marker_bytes).hexdigest()
            or citation_id
            != citation_id_for_marker(
                source_sha256, byte_start, byte_end, marker_bytes
            )
        ):
            raise MirrorError("search artifact citation marker identity is invalid")
        if not any(
            version["source_sha256"] == source_sha256
            and byte_end <= version["source_bytes"]
            for version in versions.values()
        ):
            raise MirrorError("search artifact citation escapes source identity")
        citations[citation_id] = raw
    native_fields = {
        "citation_id",
        "document_version_id",
        "source_sha256",
        "containing_span_id",
        "line_start",
        "line_end",
        "byte_start",
        "byte_end",
        "raw_marker_text",
        "raw_marker_sha256",
    }
    native_citations: list[dict[str, Any]] = []
    native_keys: set[tuple[str, str, int, int]] = set()
    for raw in raw_native_citations:
        if not isinstance(raw, dict) or set(raw) != native_fields:
            raise MirrorError("native citation reference fields are not closed")
        citation_id = raw.get("citation_id")
        version_id = raw.get("document_version_id")
        version = versions.get(str(version_id))
        marker = raw.get("raw_marker_text")
        byte_start = raw.get("byte_start")
        byte_end = raw.get("byte_end")
        key = (str(citation_id), str(version_id), int(byte_start or -1), int(byte_end or -1))
        expected_marker = (
            f"^src:{{{citation_id}}}" if isinstance(citation_id, str) else None
        )
        if (
            not isinstance(citation_id, str)
            or not isinstance(version_id, str)
            or version is None
            or not isinstance(marker, str)
            or marker != expected_marker
            or type(byte_start) is not int
            or type(byte_end) is not int
            or not 0 <= byte_start < byte_end <= version["source_bytes"]
            or raw.get("source_sha256") != version["source_sha256"]
            or not isinstance(raw.get("containing_span_id"), str)
            or not raw["containing_span_id"]
            or type(raw.get("line_start")) is not int
            or type(raw.get("line_end")) is not int
            or not 1 <= raw["line_start"] <= raw["line_end"]
            or raw.get("raw_marker_sha256")
            != hashlib.sha256(marker.encode("utf-8")).hexdigest()
            or key in native_keys
        ):
            raise MirrorError("native citation reference identity is invalid")
        try:
            validate_citation_id(citation_id)
        except ValueError as error:
            raise MirrorError("native citation reference ID is not canonical") from error
        native_keys.add(key)
        native_citations.append(raw)
    expected_native_order = sorted(
        native_citations,
        key=lambda row: (
            row["source_sha256"],
            row["document_version_id"],
            row["byte_start"],
            row["byte_end"],
            row["citation_id"],
        ),
    )
    if raw_native_citations != expected_native_order:
        raise MirrorError("native citation reference order is not canonical")
    source_material_fields = {
        "document_version_id",
        "source_sha256",
        "span_id",
        "kind",
        "byte_start",
        "byte_end",
        "source_text",
        "source_text_sha256",
        "attributes",
    }

    def is_closed_json(value: object) -> bool:
        if value is None or type(value) in {bool, int, float, str}:
            try:
                canonical_json(value)
            except (TypeError, ValueError):
                return False
            return True
        if type(value) is list:
            return all(is_closed_json(member) for member in value)
        if type(value) is dict:
            return all(
                type(key) is str and is_closed_json(member)
                for key, member in value.items()
            )
        return False

    source_material_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in raw_citation_source_material:
        if not isinstance(raw, dict) or set(raw) != source_material_fields:
            raise MirrorError("citation source material fields are not closed")
        version_id = raw.get("document_version_id")
        span_id = raw.get("span_id")
        version = versions.get(str(version_id))
        source_text = raw.get("source_text")
        source_text_sha256 = raw.get("source_text_sha256")
        kind = raw.get("kind")
        attributes = raw.get("attributes")
        byte_start = raw.get("byte_start")
        byte_end = raw.get("byte_end")
        key = (str(version_id), str(span_id))
        expected_span_id = (
            "spn_"
            + content_hash(
                "qrh-source-span/v1",
                {
                    "document_version_id": version_id,
                    "kind": kind,
                    "byte_start": byte_start,
                    "byte_end": byte_end,
                    "text_sha256": source_text_sha256,
                    "attributes": attributes,
                },
            )[:32]
            if isinstance(version_id, str)
            and isinstance(kind, str)
            and kind
            and type(byte_start) is int
            and type(byte_end) is int
            and isinstance(source_text_sha256, str)
            and _SHA256.fullmatch(source_text_sha256)
            and type(attributes) is dict
            and is_closed_json(attributes)
            else None
        )
        if (
            not isinstance(version_id, str)
            or version is None
            or not isinstance(span_id, str)
            or not span_id
            or span_id != expected_span_id
            or raw.get("source_sha256") != version["source_sha256"]
            or type(byte_start) is not int
            or type(byte_end) is not int
            or not 0 <= byte_start < byte_end <= version["source_bytes"]
            or not isinstance(source_text, str)
            or len(source_text.encode("utf-8")) != byte_end - byte_start
            or source_text_sha256
            != hashlib.sha256(source_text.encode("utf-8")).hexdigest()
            or key in source_material_by_key
        ):
            raise MirrorError("citation source material identity is invalid")
        source_material_by_key[key] = raw
    expected_source_material_order = sorted(
        raw_citation_source_material,
        key=lambda row: (
            row["source_sha256"],
            row["document_version_id"],
            row["byte_start"],
            row["byte_end"],
            row["span_id"],
        ),
    )
    if raw_citation_source_material != expected_source_material_order:
        raise MirrorError("citation source material order is not canonical")
    required_source_material: set[tuple[str, str]] = {
        (str(row["document_version_id"]), str(row["containing_span_id"]))
        for row in native_citations
    }
    for citation in citations.values():
        for version_id, version in versions.items():
            if (
                version.get("is_current") is True
                and version["source_sha256"] == citation["source_sha256"]
            ):
                required_source_material.update(
                    (version_id, str(span_id))
                    for span_id in citation["containing_span_ids"]
                )
    if set(source_material_by_key) != required_source_material:
        raise MirrorError("citation source material membership is invalid")
    structurally_referenced_material: set[tuple[str, str]] = {
        (str(row["document_version_id"]), str(span_id))
        for row in chunks.values()
        if isinstance(row.get("document_version_id"), str)
        and isinstance(row.get("ordered_span_ids"), list)
        for span_id in row["ordered_span_ids"]
        if isinstance(span_id, str)
    }
    structurally_referenced_material.update(
        (str(row["document_version_id"]), str(row["containing_span_id"]))
        for row in native_citations
    )
    # A resolved sidecar occurrence is itself a source-bound artifact member.
    # Container spans such as list/list_item/quote can be required to replay
    # the exact marker bytes without also becoming a retrievable chunk or a
    # formal-knowledge locator. Keep those spans in the closed reference set;
    # ``required_source_material`` above still rejects every unrelated extra.
    for citation in citations.values():
        for version_id, version in versions.items():
            if (
                version.get("is_current") is True
                and version["source_sha256"] == citation["source_sha256"]
            ):
                structurally_referenced_material.update(
                    (version_id, str(span_id))
                    for span_id in citation["containing_span_ids"]
                )
    for row in knowledge.values():
        version_id = row.get("document_version_id")
        locators = row.get("source_locators")
        if not isinstance(version_id, str) or not isinstance(locators, list):
            continue
        for locator in locators:
            if not isinstance(locator, dict):
                continue
            locator_span_ids = locator.get("span_ids")
            if isinstance(locator_span_ids, list):
                structurally_referenced_material.update(
                    (version_id, span_id)
                    for span_id in locator_span_ids
                    if isinstance(span_id, str)
                )
            locator_span_id = locator.get("span_id")
            if isinstance(locator_span_id, str):
                structurally_referenced_material.add((version_id, locator_span_id))
    if not set(source_material_by_key).issubset(structurally_referenced_material):
        raise MirrorError("citation source material is structurally orphaned")

    def marker_matches_source_material(
        *,
        version_id: str,
        span_id: str,
        byte_start: int,
        byte_end: int,
        marker: str,
    ) -> bool:
        material = source_material_by_key.get((version_id, span_id))
        if (
            material is None
            or not material["byte_start"]
            <= byte_start
            < byte_end
            <= material["byte_end"]
        ):
            return False
        raw = material["source_text"].encode("utf-8")
        relative_start = byte_start - material["byte_start"]
        relative_end = byte_end - material["byte_start"]
        return raw[relative_start:relative_end] == marker.encode("utf-8")

    for row in native_citations:
        if not marker_matches_source_material(
            version_id=str(row["document_version_id"]),
            span_id=str(row["containing_span_id"]),
            byte_start=int(row["byte_start"]),
            byte_end=int(row["byte_end"]),
            marker=str(row["raw_marker_text"]),
        ):
            raise MirrorError("native citation differs from canonical source material")
    for citation in citations.values():
        if not any(
            marker_matches_source_material(
                version_id=version_id,
                span_id=str(span_id),
                byte_start=int(citation["byte_start"]),
                byte_end=int(citation["byte_end"]),
                marker=str(citation["raw_marker_text"]),
            )
            for version_id, version in versions.items()
            if version.get("is_current") is True
            and version["source_sha256"] == citation["source_sha256"]
            for span_id in citation["containing_span_ids"]
        ):
            raise MirrorError("projected citation differs from canonical source material")
    ordered_citations = sorted(
        citations.values(),
        key=lambda row: (
            row["source_sha256"],
            row["byte_start"],
            row["byte_end"],
            row["citation_id"],
        ),
    )
    if raw_citations != ordered_citations:
        raise MirrorError("search artifact citation order is not canonical")
    previous_by_source: dict[str, tuple[int, int]] = {}
    for row in ordered_citations:
        previous = previous_by_source.get(str(row["source_sha256"]))
        if previous is not None and int(row["byte_start"]) < previous[1]:
            raise MirrorError("search artifact citation projection overlaps")
        previous_by_source[str(row["source_sha256"])] = (
            int(row["byte_start"]),
            int(row["byte_end"]),
        )
    if has_projection_contract:
        if citation_projection is None:
            raise MirrorError("search artifact citations lack projection identity")
        else:
            projection_fields = {
                "schema_version",
                "base_snapshot_id",
                "evidence_database_sha256",
                "evidence_migration_authority_sha256",
                "reviewed_overlay_manifest_sha256",
                "active_source_membership",
                "occurrence_count",
                "rejected_overlap_count",
                "membership_sha256",
            }
            if (
                not isinstance(citation_projection, dict)
                or set(citation_projection) != projection_fields
                or citation_projection.get("schema_version")
                != CITATION_PROJECTION_SCHEMA
                or not _SHA256.fullmatch(
                    str(citation_projection.get("evidence_database_sha256") or "")
                )
                or not _SHA256.fullmatch(
                    str(
                        citation_projection.get(
                            "evidence_migration_authority_sha256"
                        )
                        or ""
                    )
                )
                or not _SHA256.fullmatch(
                    str(
                        citation_projection.get("reviewed_overlay_manifest_sha256")
                        or ""
                    )
                )
                or not _SHA256.fullmatch(
                    str(citation_projection.get("membership_sha256") or "")
                )
                or type(citation_projection.get("occurrence_count")) is not int
                or citation_projection["occurrence_count"] != len(citations)
                or type(citation_projection.get("rejected_overlap_count")) is not int
                or citation_projection["rejected_overlap_count"] < 0
                or not isinstance(
                    citation_projection.get("active_source_membership"), dict
                )
            ):
                raise MirrorError("search artifact citation projection identity is invalid")
            expected_base = (
                identity["base_snapshot_id"] if identity is not None else expected_snapshot_id
            )
            active_membership = {
                version_id: str(version["source_sha256"])
                for version_id, version in sorted(versions.items())
                if version.get("is_current") is True
            }
            if (
                citation_projection["base_snapshot_id"] != expected_base
                or citation_projection["active_source_membership"] != active_membership
            ):
                raise MirrorError("search artifact citation active membership is invalid")
            expected_projection_hash = content_hash(
                CITATION_PROJECTION_SCHEMA,
                {
                    "schema_version": CITATION_PROJECTION_SCHEMA,
                    "base_snapshot_id": expected_base,
                    "evidence_database_sha256": citation_projection[
                        "evidence_database_sha256"
                    ],
                    "evidence_migration_authority_sha256": citation_projection[
                        "evidence_migration_authority_sha256"
                    ],
                    "reviewed_overlay_manifest_sha256": citation_projection[
                        "reviewed_overlay_manifest_sha256"
                    ],
                    "active_source_membership": active_membership,
                    "occurrences": ordered_citations,
                    "rejected_overlap_count": citation_projection[
                        "rejected_overlap_count"
                    ],
                },
            )
            if citation_projection["membership_sha256"] != expected_projection_hash:
                raise MirrorError("search artifact citation membership hash is invalid")
    for chunk in chunks.values():
        version = versions.get(str(chunk["document_version_id"]))
        if version is None or version["document_id"] != chunk["document_id"]:
            raise MirrorError("search artifact chunk membership is invalid")
        chunk_text = chunk.get("text")
        chunk_text_bytes = (
            chunk_text.encode("utf-8") if isinstance(chunk_text, str) else None
        )
        if (
            not isinstance(chunk["byte_start"], int)
            or not isinstance(chunk["byte_end"], int)
            or not 0 <= chunk["byte_start"] <= chunk["byte_end"] <= version["source_bytes"]
            or chunk_text_bytes is None
            or len(chunk_text_bytes) > chunk["byte_end"] - chunk["byte_start"]
            or chunk.get("content_sha256")
            != hashlib.sha256(chunk_text_bytes).hexdigest()
            or not isinstance(chunk.get("ordered_span_ids"), list)
            or not chunk["ordered_span_ids"]
            or any(
                not isinstance(span_id, str) or not span_id
                for span_id in chunk["ordered_span_ids"]
            )
            or chunk["ordered_span_ids"]
            != list(dict.fromkeys(chunk["ordered_span_ids"]))
            or any(
                not isinstance(chunk[field], list)
                or any(not isinstance(value, str) or not value for value in chunk[field])
                for field in ("heading_path", "heading_labels")
            )
        ):
            raise MirrorError("search artifact chunk byte range is invalid")
        if has_projection_contract and citation_projection is not None:
            expected_chunk_citations = sorted(
                {
                    citation_id
                    for citation_id, citation in citations.items()
                    if citation["source_sha256"] == version["source_sha256"]
                    and chunk["byte_start"] <= citation["byte_start"]
                    and citation["byte_end"] <= chunk["byte_end"]
                }
                | {
                    str(citation["citation_id"])
                    for citation in native_citations
                    if citation["document_version_id"]
                    == chunk["document_version_id"]
                    and citation["containing_span_id"] in chunk["ordered_span_ids"]
                    and chunk["byte_start"] <= citation["byte_start"]
                    and citation["byte_end"] <= chunk["byte_end"]
                }
            )
            if chunk["citation_ids"] != expected_chunk_citations:
                raise MirrorError("search artifact chunk citation membership is invalid")

    def canonical_chunk_source_slice(
        *,
        version_id: str,
        span_id: str,
        byte_start: int,
        byte_end: int,
    ) -> bytes:
        matching_chunks = [
            chunk
            for chunk in chunks.values()
            if chunk["document_version_id"] == version_id
            and chunk.get("retrievable") is True
            and span_id in chunk["ordered_span_ids"]
            and chunk["byte_start"] <= byte_start <= byte_end <= chunk["byte_end"]
        ]
        if matching_chunks:
            narrowest = min(
                chunk["byte_end"] - chunk["byte_start"]
                for chunk in matching_chunks
            )
            matching_chunks = [
                chunk
                for chunk in matching_chunks
                if chunk["byte_end"] - chunk["byte_start"] == narrowest
            ]
        material = source_material_by_key.get((version_id, span_id))
        if (
            len(matching_chunks) > 1
            or material is None
            or not material["byte_start"]
            <= byte_start
            <= byte_end
            <= material["byte_end"]
        ):
            raise MirrorError(
                "formal knowledge citation lacks unique canonical source material"
            )
        raw = material["source_text"].encode("utf-8")
        relative_start = byte_start - material["byte_start"]
        relative_end = byte_end - material["byte_start"]
        return raw[relative_start:relative_end]

    if identity is None and knowledge:
        raise MirrorError("deterministic-only artifact cannot contain formal knowledge")
    status_membership = identity["knowledge_status_membership"] if identity else {}
    generation_membership = identity["generation_membership"] if identity else {}
    for row in knowledge.values():
        version_id = str(row["document_version_id"])
        version = versions.get(version_id)
        if version is None or version["document_id"] != row["document_id"]:
            raise MirrorError("formal knowledge version membership is invalid")
        if not version["is_current"] or documents[str(row["document_id"])]["status"] != "active":
            raise MirrorError("formal knowledge must bind an active source version")
        if row["fact_status"] not in {
            "source_explicit",
            "machine_verified",
            "human_reviewed",
        }:
            raise MirrorError("formal knowledge fact status is invalid")
        if any(
            not isinstance(row[field], list)
            or any(not isinstance(value, str) or not value for value in row[field])
            for field in ("heading_path", "heading_labels")
        ):
            raise MirrorError("formal knowledge heading projection is invalid")
        locators = row["source_locators"]
        if not isinstance(locators, list) or not locators or row["source_locator"] != locators[0]:
            raise MirrorError("formal knowledge source locator is invalid")
        for locator in locators:
            if (
                not isinstance(locator, dict)
                or locator.get("source_sha256") != version["source_sha256"]
                or not isinstance(locator.get("byte_start"), int)
                or not isinstance(locator.get("byte_end"), int)
                or not 0
                <= locator["byte_start"]
                < locator["byte_end"]
                <= version["source_bytes"]
                or not _SHA256.fullmatch(str(locator.get("quote_sha256") or ""))
            ):
                raise MirrorError("formal knowledge locator escapes source bytes")
        if (
            not isinstance(row["citation_ids"], list)
            or any(
                not isinstance(citation_id, str) or not citation_id
                for citation_id in row["citation_ids"]
            )
            or row["citation_ids"] != sorted(set(row["citation_ids"]))
        ):
            raise MirrorError("formal knowledge citation union is invalid")
        if not legacy_v1:
            source_citations = row["source_citations"]
            if (
                not isinstance(source_citations, list)
                or len(source_citations) != len(locators)
            ):
                raise MirrorError("formal knowledge source citation membership is invalid")
            citation_union: set[str] = set()
            for locator, member in zip(locators, source_citations, strict=True):
                expected_member_fields = {"source_locator", "citation_ids"}
                if has_projection_contract:
                    expected_member_fields.add("citation_attributions")
                if (
                    not isinstance(member, dict)
                    or set(member) != expected_member_fields
                    or member["source_locator"] != locator
                    or not isinstance(member["citation_ids"], list)
                    or any(
                        not isinstance(citation_id, str) or not citation_id
                        for citation_id in member["citation_ids"]
                    )
                    or member["citation_ids"]
                    != sorted(set(member["citation_ids"]))
                ):
                    raise MirrorError("formal knowledge source citation is invalid")
                if has_projection_contract and citation_projection is not None:
                    raw_attributions = member["citation_attributions"]
                    if (
                        not isinstance(raw_attributions, list)
                        or len(raw_attributions) != len(member["citation_ids"])
                    ):
                        raise MirrorError(
                            "formal knowledge citation attribution proof is invalid"
                        )
                    attribution_ids: list[str] = []
                    for attribution in raw_attributions:
                        if (
                            not isinstance(attribution, dict)
                            or set(attribution)
                            != {
                                "citation_id",
                                "relation",
                                "anchor_byte_end",
                                "gap_text",
                                "gap_sha256",
                            }
                            or not isinstance(attribution.get("citation_id"), str)
                            or attribution.get("relation")
                            not in {"contained", "adjacent"}
                            or type(attribution.get("anchor_byte_end")) is not int
                            or not isinstance(attribution.get("gap_text"), str)
                            or not _SHA256.fullmatch(
                                str(attribution.get("gap_sha256") or "")
                            )
                        ):
                            raise MirrorError(
                                "formal knowledge citation attribution proof is invalid"
                            )
                        citation_id = attribution["citation_id"]
                        anchor_byte_end = attribution["anchor_byte_end"]
                        gap_bytes = attribution["gap_text"].encode("utf-8")
                        if (
                            hashlib.sha256(gap_bytes).hexdigest()
                            != attribution["gap_sha256"]
                            or attribution["relation"] == "contained"
                            and gap_bytes != b""
                            or attribution["relation"] == "adjacent"
                            and not is_valid_citation_gap(gap_bytes)
                        ):
                            raise MirrorError(
                                "formal knowledge citation attribution gap is invalid"
                            )
                        citation = citations.get(citation_id)
                        candidates = (
                            [citation] if citation is not None else []
                        ) + [
                            native
                            for native in native_citations
                            if native["citation_id"] == citation_id
                            and native["document_version_id"] == version_id
                        ]
                        member_candidates = [
                            candidate
                            for member_citation_id in member["citation_ids"]
                            for candidate in (
                                ([citations[member_citation_id]]
                                 if member_citation_id in citations else [])
                                + [
                                    native
                                    for native in native_citations
                                    if native["citation_id"] == member_citation_id
                                    and native["document_version_id"] == version_id
                                ]
                            )
                            if candidate["source_sha256"] == locator["source_sha256"]
                            and locator["span_id"] in candidate.get(
                                "containing_span_ids",
                                [candidate.get("containing_span_id")],
                            )
                        ]
                        allowed_anchors = {locator["byte_end"]} | {
                            candidate["byte_end"] for candidate in member_candidates
                        }

                        def matches_canonical_source(candidate: Mapping[str, Any]) -> bool:
                            marker_bytes = str(candidate["raw_marker_text"]).encode(
                                "utf-8"
                            )
                            material_start = (
                                int(candidate["byte_start"])
                                if attribution["relation"] == "contained"
                                else anchor_byte_end
                            )
                            actual = canonical_chunk_source_slice(
                                version_id=version_id,
                                span_id=str(locator["span_id"]),
                                byte_start=material_start,
                                byte_end=int(candidate["byte_end"]),
                            )
                            expected = (
                                marker_bytes
                                if attribution["relation"] == "contained"
                                else gap_bytes + marker_bytes
                            )
                            return actual == expected

                        if not any(
                            candidate["source_sha256"] == locator["source_sha256"]
                            and locator["span_id"] in candidate.get(
                                "containing_span_ids",
                                [candidate.get("containing_span_id")],
                            )
                            and (
                                attribution["relation"] == "contained"
                                and anchor_byte_end == locator["byte_end"]
                                and gap_bytes == b""
                                and locator["byte_start"] <= candidate["byte_start"]
                                and candidate["byte_end"] <= locator["byte_end"]
                                or attribution["relation"] == "adjacent"
                                and anchor_byte_end in allowed_anchors
                                and anchor_byte_end <= candidate["byte_start"]
                                and candidate["byte_start"] - anchor_byte_end
                                == len(gap_bytes)
                            )
                            and matches_canonical_source(candidate)
                            for candidate in candidates
                        ):
                            raise MirrorError(
                                "formal knowledge citation does not cover its locator"
                            )
                        attribution_ids.append(citation_id)
                    if attribution_ids != member["citation_ids"]:
                        raise MirrorError(
                            "formal knowledge citation attribution membership is invalid"
                        )
                citation_union.update(member["citation_ids"])
            if row["citation_ids"] != sorted(citation_union):
                raise MirrorError("formal knowledge citation union is invalid")
        generation = row["generation"]
        generation_fields = {
            "generation_id",
            "requested_model_alias",
            "provider_revision",
            "returned_model",
            "system_fingerprint",
            "model_identity_contract_hash",
            "model_identity_evidence_url",
            "model_identity_evidence_hash",
            "model_identity_evidence_observed_at",
            "response_id",
            "response_created_at",
            "response_hash",
            "prompt_version",
            "output_schema_version",
            "source_sha256",
            "ir_hash",
            "created_at",
        }
        if generation is None:
            if row["fact_status"] != "source_explicit":
                raise MirrorError("formal model knowledge lacks generation identity")
        elif (
            not isinstance(generation, dict)
            or set(generation) != generation_fields
            or generation_membership.get(version_id) != generation.get("generation_id")
            or status_membership.get(version_id) != "ready"
            or any(
                not isinstance(generation.get(field), str) or not generation[field]
                for field in (
                    "generation_id",
                    "requested_model_alias",
                    "provider_revision",
                    "returned_model",
                    "system_fingerprint",
                    "model_identity_contract_hash",
                    "model_identity_evidence_url",
                    "model_identity_evidence_hash",
                    "model_identity_evidence_observed_at",
                    "response_id",
                    "response_created_at",
                    "response_hash",
                    "prompt_version",
                    "output_schema_version",
                    "source_sha256",
                    "ir_hash",
                    "created_at",
                )
            )
        ):
            raise MirrorError("formal knowledge generation identity is invalid")
    retrieval = value["retrieval"]
    if not isinstance(retrieval, dict) or not isinstance(retrieval.get("records"), list):
        raise MirrorError("search artifact retrieval projection is invalid")
    retrieval_by_id = {
        str(row.get("record_id")): row
        for row in retrieval["records"]
        if isinstance(row, dict)
    }
    expected_record_ids = {
        str(chunk_id)
        for chunk_id, chunk in chunks.items()
        if chunk.get("retrievable") is True
    } | set(knowledge)
    if set(retrieval_by_id) != expected_record_ids:
        raise MirrorError("search artifact retrieval membership differs from canonical rows")
    for record_id in sorted(expected_record_ids):
        canonical = chunks.get(record_id) or knowledge.get(record_id)
        record = retrieval_by_id[record_id]
        if canonical is None or record.get("citation_ids") != canonical.get("citation_ids"):
            raise MirrorError("search artifact retrieval citation membership differs")
    membership_material = {
        "documents": value["documents"],
        "versions": value["versions"],
        "chunks": value["chunks"],
        "knowledge": value["knowledge"],
    }
    if has_projection_contract:
        membership_material["citation_projection"] = citation_projection
        membership_material["citations"] = raw_citations
        membership_material["native_citation_references"] = raw_native_citations
        membership_material["citation_source_material"] = (
            raw_citation_source_material
        )
    expected_membership = hashlib.sha256(
        canonical_json(membership_material).encode("utf-8")
    ).hexdigest()
    if retrieval.get("canonical_membership_sha256") != expected_membership:
        raise MirrorError("search artifact canonical membership hash is invalid")
    try:
        ArtifactKnowledgeIndex(value, _build_runtime=False).close()
    except (KeyError, TypeError, ValueError) as error:
        raise MirrorError("search artifact retrieval projection is invalid") from error
    return value


class FileAuthorityProbe:
    """Read active identity through a configured read-only file-share view."""

    def __init__(self, active_release_path: Path, release_root: Path) -> None:
        self.active_release_path = Path(active_release_path)
        self.release_root = Path(release_root)

    def probe(self) -> AuthorityObservation:
        try:
            _safe_directory(self.active_release_path.parent, must_exist=True)
            _safe_directory(self.release_root, must_exist=True)
            _regular_file(self.active_release_path)
            active = validate_active_release(_read_json(self.active_release_path))
            release_id = str(active["release_id"])
            manifest_path = self.release_root / release_id / "release_manifest.json"
            _regular_file(manifest_path)
            release = validate_release_manifest(_read_json(manifest_path))
            observed_hash = manifest_sha256(release)
            if observed_hash != active["manifest_sha256"]:
                raise MirrorError("active pointer manifest hash mismatch")
            if release["release_id"] != release_id:
                raise MirrorError("active pointer release ID mismatch")
            return AuthorityObservation(
                identity=_identity_from_release(release),
                verified_at=_utc_now(),
            )
        except (MirrorError, TypeError, ValueError, OSError) as error:
            raise AuthorityUnavailable("production authority cannot be verified") from error


class FileArtifactSource:
    """Copy exact artifacts from an already-mounted read-only release view."""

    def __init__(self, release_root: Path) -> None:
        self.release_root = Path(release_root)

    def stage(self, identity: AuthorityIdentity, destination: Path) -> None:
        source_root = self.release_root / identity.release_id
        source_artifact = source_root / SEARCH_ARTIFACT_RELATIVE_PATH
        _safe_directory(self.release_root, must_exist=True)
        _safe_directory(source_root, must_exist=True)
        _safe_directory(source_artifact.parent, must_exist=True)
        source_manifest = source_root / "release_manifest.json"
        _regular_file(source_manifest)
        _regular_file(source_artifact)
        shutil.copyfile(source_manifest, destination / "release_manifest.json")
        shutil.copyfile(source_artifact, destination / SEARCH_ARTIFACT_RELATIVE_PATH)


class OpenSSHAuthoritySource:
    """Read VM authority and artifacts over OpenSSH without a remote write.

    Authentication is delegated to the user's OpenSSH agent/config alias.  No
    key path or secret is accepted by this contract, persisted, or included in
    errors.  Every remote operation is one fixed shell-free ssh invocation
    whose PowerShell payload can only read an identity-derived file below the
    fixed production VM root.
    """

    def __init__(
        self,
        ssh_alias: str,
        *,
        runner: CommandRunner | None = None,
        ssh_executable: str = "ssh",
        timeout_seconds: float = 20.0,
        vm_root: PureWindowsPath = VM_AUTHORITY_ROOT,
    ) -> None:
        if not _SAFE_REMOTE_NAME.fullmatch(ssh_alias):
            raise ValueError("ssh alias must be a simple OpenSSH config name")
        if vm_root != VM_AUTHORITY_ROOT:
            raise ValueError("OpenSSH authority root must be D:\\quant\\quant_platform")
        if not ssh_executable or timeout_seconds <= 0:
            raise ValueError("OpenSSH process configuration is invalid")
        self.ssh_alias = ssh_alias
        self.runner = runner or SubprocessCommandRunner()
        self.ssh_executable = ssh_executable
        self.timeout_seconds = timeout_seconds
        self.vm_root = vm_root

    def _read_remote(self, path: PureWindowsPath) -> bytes:
        if not path.is_relative_to(self.vm_root):
            raise MirrorError("remote read escaped the fixed VM root")
        # All path components are either fixed or checked release identities.
        # EncodedCommand prevents the remote login shell from interpreting the
        # path or any local input as command syntax.
        text_path = str(path)
        if "'" in text_path or any(ord(character) < 32 for character in text_path):
            raise MirrorError("remote read path is unsafe")
        script = (
            "$ErrorActionPreference='Stop';"
            f"$b=[IO.File]::ReadAllBytes('{text_path}');"
            "[Console]::Out.Write([Convert]::ToBase64String($b))"
        )
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        argv = (
            self.ssh_executable,
            "-T",
            "-o",
            "BatchMode=yes",
            "--",
            self.ssh_alias,
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            encoded,
        )
        output = self.runner.run(argv, timeout_seconds=self.timeout_seconds)
        try:
            return base64.b64decode(output.strip(), validate=True)
        except (ValueError, UnicodeError) as error:
            raise AuthorityUnavailable("read-only OpenSSH response is invalid") from error

    def _verified_identity(self) -> AuthorityIdentity:
        active_path = self.vm_root / "control" / "active_release.json"
        active_before = self._read_remote(active_path)
        active = validate_active_release(
            _decode_json_bytes(active_before, label="remote active authority")
        )
        release_id = str(active["release_id"])
        if not _SAFE_REMOTE_NAME.fullmatch(release_id):
            raise MirrorError("active release ID cannot form an exact remote path")
        exact_release_root = self.vm_root / "releases" / release_id
        if PureWindowsPath(str(active["release_path"])) != exact_release_root:
            raise MirrorError("active release path is not the exact VM release path")
        manifest_bytes = self._read_remote(exact_release_root / "release_manifest.json")
        release = validate_release_manifest(
            _decode_json_bytes(manifest_bytes, label="remote release manifest")
        )
        identity = _identity_from_release(release)
        if (
            identity.release_id != release_id
            or identity.manifest_sha256 != active["manifest_sha256"]
        ):
            raise MirrorError("remote active and release identities disagree")
        # Close the active-pointer race: a transition during the reads is not a
        # verified observation and must be retried on the next tool call.
        if self._read_remote(active_path) != active_before:
            raise MirrorError("remote authority changed during verification")
        return identity

    def probe(self) -> AuthorityObservation:
        try:
            return AuthorityObservation(
                identity=self._verified_identity(), verified_at=_utc_now()
            )
        except (MirrorError, TypeError, ValueError, OSError, KeyError) as error:
            raise AuthorityUnavailable("OpenSSH production authority cannot be verified") from error

    def stage(self, identity: AuthorityIdentity, destination: Path) -> None:
        try:
            before = self._verified_identity()
            if before != identity:
                raise MirrorError("remote authority changed before artifact download")
            if not _SAFE_REMOTE_NAME.fullmatch(identity.release_id):
                raise MirrorError("release ID cannot form an exact remote path")
            release_root = self.vm_root / "releases" / identity.release_id
            manifest_bytes = self._read_remote(release_root / "release_manifest.json")
            artifact_bytes = self._read_remote(
                release_root / PureWindowsPath(SEARCH_ARTIFACT_RELATIVE_PATH)
            )
            if self._verified_identity() != identity:
                raise MirrorError("remote authority changed during artifact download")
            # The destination is the MirrorStore-owned dot-prefixed staging
            # directory.  It cannot become current until full closure checks.
            (destination / "release_manifest.json").write_bytes(manifest_bytes)
            (destination / SEARCH_ARTIFACT_RELATIVE_PATH).write_bytes(artifact_bytes)
        except (MirrorError, TypeError, ValueError, OSError, KeyError) as error:
            raise AuthorityUnavailable("OpenSSH artifact download cannot be verified") from error


class MirrorStore:
    """User-level immutable artifacts with a mutable cache pointer only."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.releases_root = self.root / "releases"
        self.current_path = self.root / "current.json"
        self.acknowledged_path = self.root / "acknowledged.json"
        self.pending_transition_path = self.root / "pending_transition.json"
        self.lock_path = self.root / ".mirror.lock"

    @contextmanager
    def _locked(self):
        self.root.mkdir(parents=True, exist_ok=True)
        _safe_directory(self.root, must_exist=True)
        local_lock = _local_lock_for(self.lock_path)
        with local_lock:
            base_flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
            base_flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(
                    self.lock_path,
                    base_flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError:
                try:
                    descriptor = os.open(self.lock_path, base_flags)
                except OSError as error:
                    raise MirrorError("mirror lock cannot be opened safely") from error
            except OSError as error:
                raise MirrorError("mirror lock cannot be opened safely") from error
            with os.fdopen(descriptor, "r+b") as handle:
                _validate_open_regular_file(self.lock_path, handle.fileno())
                lock_size = os.fstat(handle.fileno()).st_size
                # New locks are deliberately zero-byte. Windows byte-range
                # locking works beyond EOF, and an empty file removes the
                # former create->sentinel crash window and all data writes that
                # a precisely raced hardlink could observe. The historical
                # one-byte marker remains read-only compatible for upgrades.
                if lock_size not in {0, 1}:
                    raise MirrorError("mirror lock identity is invalid")
                _validate_open_regular_file(self.lock_path, handle.fileno())
                _acquire_os_lock(handle)
                try:
                    _validate_open_regular_file(self.lock_path, handle.fileno())
                    if os.fstat(handle.fileno()).st_size != lock_size:
                        raise MirrorError("mirror lock changed while held")
                    if lock_size == 1:
                        handle.seek(0)
                        if handle.read(2) != b"\0":
                            raise MirrorError("mirror lock identity is invalid")
                    yield
                    if os.fstat(handle.fileno()).st_size != lock_size:
                        raise MirrorError("mirror lock changed while held")
                    if lock_size == 1:
                        handle.seek(0)
                        if handle.read(2) != b"\0":
                            raise MirrorError("mirror lock changed while held")
                finally:
                    _release_os_lock(handle)

    def initialize(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        with self._locked():
            self.releases_root.mkdir(exist_ok=True)
            _safe_directory(self.releases_root, must_exist=True)

    def _release_path(self, identity: AuthorityIdentity) -> Path:
        if not _SHA256.fullmatch(identity.manifest_sha256):
            raise MirrorError("mirror manifest SHA-256 is invalid")
        return self.releases_root / identity.manifest_sha256

    def _atomic_json(self, path: Path, value: Mapping[str, object]) -> None:
        temporary = self.root / f".{path.name}.partial"
        if temporary.exists():
            _regular_file(temporary)
            _unlink_with_retry(temporary)
        try:
            with temporary.open("x", encoding="utf-8", newline="") as handle:
                handle.write(canonical_json(value))
                handle.flush()
                os.fsync(handle.fileno())
            _regular_file(temporary)
            _replace_with_retry(temporary, path)
        finally:
            if temporary.exists():
                _regular_file(temporary)
                _unlink_with_retry(temporary)

    @staticmethod
    def _closed_identity(value: object, *, label: str) -> AuthorityIdentity:
        if not isinstance(value, dict) or set(value) != {
            "release_id",
            "manifest_sha256",
            "snapshot_id",
        }:
            raise MirrorError(f"{label} identity is invalid")
        if (
            not isinstance(value["release_id"], str)
            or not value["release_id"]
            or not isinstance(value["snapshot_id"], str)
            or not value["snapshot_id"]
            or not isinstance(value["manifest_sha256"], str)
            or not _SHA256.fullmatch(value["manifest_sha256"])
        ):
            raise MirrorError(f"{label} identity values are invalid")
        try:
            return AuthorityIdentity(**value)
        except TypeError as error:
            raise MirrorError(f"{label} identity is invalid") from error

    def _acknowledged_identity(self) -> AuthorityIdentity | None:
        if not self.acknowledged_path.exists():
            return None
        _regular_file(self.acknowledged_path)
        value = _read_json(self.acknowledged_path)
        if not isinstance(value, dict) or set(value) != {
            "schema_version",
            "identity",
        }:
            raise MirrorError("mirror acknowledged pointer fields are not closed")
        if value["schema_version"] != MIRROR_ACKNOWLEDGED_SCHEMA:
            raise MirrorError("mirror acknowledged pointer schema is invalid")
        identity = self._closed_identity(
            value["identity"], label="mirror acknowledged pointer"
        )
        return identity

    def _pending_transition_record(self) -> MirrorTransition | None:
        if not self.pending_transition_path.exists():
            return None
        _regular_file(self.pending_transition_path)
        value = _read_json(self.pending_transition_path)
        if not isinstance(value, dict) or set(value) != {
            "schema_version",
            "from_identity",
            "to_identity",
        }:
            raise MirrorError("mirror pending transition fields are not closed")
        if value["schema_version"] != MIRROR_PENDING_TRANSITION_SCHEMA:
            raise MirrorError("mirror pending transition schema is invalid")
        transition = MirrorTransition(
            from_identity=self._closed_identity(
                value["from_identity"], label="mirror pending from"
            ),
            to_identity=self._closed_identity(
                value["to_identity"], label="mirror pending to"
            ),
        )
        if transition.from_identity == transition.to_identity:
            raise MirrorError("mirror pending transition cannot be a no-op")
        return transition

    def _transition_state(
        self,
    ) -> tuple[MirrorSnapshot | None, AuthorityIdentity | None, MirrorTransition | None]:
        current = self._current_unlocked()
        acknowledged = self._acknowledged_identity()
        pending = self._pending_transition_record()
        if current is None:
            if acknowledged is not None or pending is not None:
                raise MirrorError("mirror transition state exists without current pointer")
            return None, None, None
        if acknowledged is None:
            if pending is not None:
                raise MirrorError("mirror pending transition has no acknowledged baseline")
            # Legacy/current-only mirrors are treated as already acknowledged;
            # the explicit pointer is backfilled before the next transition.
            return current, current.identity, None
        if pending is None:
            if current.identity != acknowledged:
                raise MirrorError("mirror current identity escaped acknowledged baseline")
            return current, acknowledged, None
        if (
            pending.to_identity == acknowledged
            and current.identity == acknowledged
        ):
            # Crash after the acknowledged pointer commit but before removing
            # the now-stale pending record. It is already acknowledged.
            return current, acknowledged, None
        if pending.from_identity != acknowledged or current.identity not in {
            pending.from_identity,
            pending.to_identity,
        }:
            raise MirrorError("mirror pending transition is inconsistent")
        return current, acknowledged, pending

    def pending_transition(self) -> MirrorTransition | None:
        """Return a validated, durable unacknowledged transition."""

        if not self.root.exists():
            return None
        with self._locked():
            _current, _acknowledged, pending = self._transition_state()
            return pending

    def current_and_pending(
        self,
    ) -> tuple[MirrorSnapshot | None, MirrorTransition | None]:
        """Read the composite mutable state under one cross-process lock."""

        if not self.root.exists():
            return None, None
        with self._locked():
            current, _acknowledged, pending = self._transition_state()
            return current, pending

    def _record_observed_identity(self, identity: AuthorityIdentity) -> None:
        current, acknowledged, pending = self._transition_state()
        if current is None:
            self._write_pointer(identity)
            self._write_acknowledged(identity)
            return
        assert acknowledged is not None
        if not self.acknowledged_path.exists():
            self._write_acknowledged(acknowledged)
        # Remove only a stale record left after a completed acknowledgement.
        raw_pending = self._pending_transition_record()
        if (
            raw_pending is not None
            and raw_pending.to_identity == acknowledged
            and current.identity == acknowledged
        ):
            _unlink_with_retry(self.pending_transition_path)
            pending = None
        if identity == acknowledged:
            self._write_pointer(identity)
            if pending is not None and self.pending_transition_path.exists():
                _unlink_with_retry(self.pending_transition_path)
            return
        transition = MirrorTransition(acknowledged, identity)
        self._write_pending_transition(transition)
        # Pending is committed first. A crash here leaves current at either
        # endpoint and is safely resumed without losing the old identity.
        self._write_pointer(identity)

    def _write_acknowledged(self, identity: AuthorityIdentity) -> None:
        self._atomic_json(
            self.acknowledged_path,
            {
                "schema_version": MIRROR_ACKNOWLEDGED_SCHEMA,
                "identity": identity.to_dict(),
            },
        )

    def _write_pending_transition(self, transition: MirrorTransition) -> None:
        self._atomic_json(
            self.pending_transition_path,
            {
                "schema_version": MIRROR_PENDING_TRANSITION_SCHEMA,
                "from_identity": transition.from_identity.to_dict(),
                "to_identity": transition.to_identity.to_dict(),
            },
        )

    def acknowledge_transition(
        self, from_identity: AuthorityIdentity, to_identity: AuthorityIdentity
    ) -> None:
        if not self.root.exists():
            raise MirrorError("mirror transition acknowledgement has no current state")
        with self._locked():
            self._acknowledge_transition_locked(from_identity, to_identity)

    def _acknowledge_transition_locked(
        self, from_identity: AuthorityIdentity, to_identity: AuthorityIdentity
    ) -> None:
        current, acknowledged, pending = self._transition_state()
        if current is None or acknowledged is None:
            raise MirrorError("mirror transition acknowledgement has no current state")
        if pending is None:
            if acknowledged == to_identity and current.identity == to_identity:
                return
            raise MirrorError("mirror has no matching pending transition")
        if (
            pending != MirrorTransition(from_identity, to_identity)
            or acknowledged != from_identity
            or current.identity != to_identity
        ):
            raise MirrorError("mirror transition acknowledgement identity mismatch")
        # Acknowledged pointer commits first. If deletion is interrupted, the
        # stale pending record is recognized as already acknowledged.
        self._write_acknowledged(to_identity)
        if self.pending_transition_path.exists():
            _unlink_with_retry(self.pending_transition_path)

    def sync_from(
        self, identity: AuthorityIdentity, artifact_source: Path | ArtifactSource
    ) -> MirrorSnapshot:
        """Copy one exact release artifact via partial→immutable final."""

        self.initialize()
        with self._locked():
            return self._sync_from_locked(identity, artifact_source)

    def _sync_from_locked(
        self, identity: AuthorityIdentity, artifact_source: Path | ArtifactSource
    ) -> MirrorSnapshot:
        # Any corrupt pointer/ack/pending state fails closed before adopting a
        # newly observed authority identity.
        self._transition_state()
        final = self._release_path(identity)
        if final.exists():
            snapshot = self.load(identity)
            self._record_observed_identity(identity)
            return snapshot
        partial = self.releases_root / f".{identity.manifest_sha256}.partial"
        existing_partials = self._owned_release_partials()
        if existing_partials:
            if existing_partials != (partial,):
                raise MirrorError(
                    "another interrupted mirror release must be resolved first"
                )
            try:
                self._load_release_root(identity, partial)
            except (MirrorError, OSError, TypeError, ValueError, KeyError):
                self._remove_owned_release_partial(partial)
            else:
                # A complete verified stage survives a sharing violation or
                # response loss and is adopted directly on the same-identity
                # retry. No source bytes are downloaded twice.
                _replace_with_retry(partial, final)
                snapshot = self.load(identity)
                self._record_observed_identity(identity)
                return snapshot
        partial.mkdir()
        staged_complete = False
        try:
            (partial / "content").mkdir()
            source = (
                FileArtifactSource(Path(artifact_source))
                if isinstance(artifact_source, (str, os.PathLike))
                else artifact_source
            )
            source.stage(identity, partial)
            staged_manifest = partial / "release_manifest.json"
            staged_artifact = partial / SEARCH_ARTIFACT_RELATIVE_PATH
            _regular_file(staged_manifest)
            _regular_file(staged_artifact)
            release = validate_release_manifest(_read_json(staged_manifest))
            actual_identity = _identity_from_release(release)
            if actual_identity != identity:
                raise MirrorError("artifact source release identity mismatch")
            artifact_bytes = staged_artifact.read_bytes()
            expected_search_hash = str(release["content"]["search_sha256"])
            if hashlib.sha256(artifact_bytes).hexdigest() != expected_search_hash:
                raise MirrorError("artifact source search hash mismatch")
            try:
                artifact = json.loads(artifact_bytes)
            except (UnicodeError, json.JSONDecodeError) as error:
                raise MirrorError("search artifact is not canonical UTF-8 JSON") from error
            validate_search_artifact(artifact, expected_snapshot_id=identity.snapshot_id)
            if canonical_json(artifact).encode("utf-8") != artifact_bytes:
                raise MirrorError("search artifact is not canonical")
            metadata = {
                "schema_version": MIRROR_METADATA_SCHEMA,
                "identity": identity.to_dict(),
                "synced_at": _utc_now(),
                "artifact": {
                    "path": SEARCH_ARTIFACT_RELATIVE_PATH,
                    "bytes": len(artifact_bytes),
                    "sha256": expected_search_hash,
                },
                "closure_sha256": content_hash(
                    "qrh-user-mirror-closure/v1",
                    {
                        "release_manifest_sha256": identity.manifest_sha256,
                        "artifact_sha256": expected_search_hash,
                        "artifact_bytes": len(artifact_bytes),
                    },
                ),
            }
            (partial / "mirror.json").write_text(
                canonical_json(metadata), encoding="utf-8", newline=""
            )
            self._load_release_root(identity, partial)
            staged_complete = True
            _replace_with_retry(partial, final)
        except BaseException as error:
            # A complete validated stage is the durable retry point. An
            # incomplete stage is removed only through the exact owned closure;
            # unknown entries/reparse points remain fail-closed for inspection.
            if not staged_complete:
                try:
                    self._remove_owned_release_partial(partial)
                except BaseException as cleanup_error:
                    if hasattr(error, "add_note"):
                        error.add_note(
                            "incomplete mirror partial cleanup also failed: "
                            + type(cleanup_error).__name__
                        )
            raise
        snapshot = self.load(identity)
        self._record_observed_identity(identity)
        return snapshot

    def _owned_release_partials(self) -> tuple[Path, ...]:
        pattern = re.compile(r"^\.[0-9a-f]{64}\.partial$")
        partials: list[Path] = []
        for path in self.releases_root.iterdir():
            if not path.name.startswith("."):
                continue
            if pattern.fullmatch(path.name) is None:
                raise MirrorError("mirror releases contain an unknown staging entry")
            _safe_directory(path, must_exist=True)
            partials.append(path)
        if len(partials) > 1:
            raise MirrorError("mirror contains multiple interrupted release stages")
        return tuple(partials)

    def _remove_owned_release_partial(self, partial: Path) -> None:
        if partial.parent != self.releases_root:
            raise MirrorError("mirror partial escaped the release root")
        _safe_directory(partial, must_exist=True)
        top = {path.name: path for path in partial.iterdir()}
        if not set(top).issubset({"content", "release_manifest.json", "mirror.json"}):
            raise MirrorError("mirror partial contains an unknown entry")
        content = top.get("content")
        if content is not None:
            _safe_directory(content, must_exist=True)
            content_rows = {path.name: path for path in content.iterdir()}
            if not set(content_rows).issubset({"mcp_search.json"}):
                raise MirrorError("mirror partial content is not closed")
            artifact = content_rows.get("mcp_search.json")
            if artifact is not None:
                _regular_file(artifact)
                artifact.unlink()
            content.rmdir()
        for name in ("release_manifest.json", "mirror.json"):
            path = top.get(name)
            if path is not None:
                _regular_file(path)
                path.unlink()
        partial.rmdir()

    def _write_pointer(self, identity: AuthorityIdentity) -> None:
        pointer = {
            "schema_version": MIRROR_POINTER_SCHEMA,
            "identity": identity.to_dict(),
            "relative_path": f"releases/{identity.manifest_sha256}",
        }
        self._atomic_json(self.current_path, pointer)

    def current(self) -> MirrorSnapshot | None:
        if not self.root.exists():
            return None
        with self._locked():
            return self._current_unlocked()

    def _current_unlocked(self) -> MirrorSnapshot | None:
        if not self.current_path.exists():
            return None
        _regular_file(self.current_path)
        pointer = _read_json(self.current_path)
        if not isinstance(pointer, dict) or set(pointer) != {
            "schema_version",
            "identity",
            "relative_path",
        }:
            raise MirrorError("mirror pointer fields are not closed")
        if pointer["schema_version"] != MIRROR_POINTER_SCHEMA:
            raise MirrorError("unsupported mirror pointer schema")
        raw_identity = pointer["identity"]
        if not isinstance(raw_identity, dict) or set(raw_identity) != {
            "release_id",
            "manifest_sha256",
            "snapshot_id",
        }:
            raise MirrorError("mirror pointer identity is invalid")
        identity = AuthorityIdentity(**raw_identity)
        if pointer["relative_path"] != f"releases/{identity.manifest_sha256}":
            raise MirrorError("mirror pointer path is not identity-derived")
        return self.load(identity)

    def load(self, identity: AuthorityIdentity) -> MirrorSnapshot:
        return self._load_release_root(identity, self._release_path(identity))

    def _load_release_root(
        self, identity: AuthorityIdentity, root: Path
    ) -> MirrorSnapshot:
        _safe_directory(root, must_exist=True)
        if {path.name for path in root.iterdir()} != {
            "content",
            "mirror.json",
            "release_manifest.json",
        }:
            raise MirrorError("mirror release top-level closure is invalid")
        metadata_path = root / "mirror.json"
        release_path = root / "release_manifest.json"
        artifact_path = root / SEARCH_ARTIFACT_RELATIVE_PATH
        _safe_directory(artifact_path.parent, must_exist=True)
        if {path.name for path in artifact_path.parent.iterdir()} != {
            "mcp_search.json"
        }:
            raise MirrorError("mirror release content closure is invalid")
        for path in (metadata_path, release_path, artifact_path):
            _regular_file(path)
        metadata = _read_json(metadata_path)
        if not isinstance(metadata, dict) or set(metadata) != {
            "schema_version",
            "identity",
            "synced_at",
            "artifact",
            "closure_sha256",
        }:
            raise MirrorError("mirror metadata fields are not closed")
        if metadata.get("schema_version") != MIRROR_METADATA_SCHEMA:
            raise MirrorError("mirror metadata schema is invalid")
        if metadata.get("identity") != identity.to_dict():
            raise MirrorError("mirror metadata identity mismatch")
        release = validate_release_manifest(_read_json(release_path))
        if _identity_from_release(release) != identity:
            raise MirrorError("mirrored release identity mismatch")
        artifact_bytes = artifact_path.read_bytes()
        artifact_meta = metadata.get("artifact")
        if not isinstance(artifact_meta, dict):
            raise MirrorError("mirror artifact metadata is invalid")
        if (
            artifact_meta.get("path") != SEARCH_ARTIFACT_RELATIVE_PATH
            or artifact_meta.get("bytes") != len(artifact_bytes)
            or artifact_meta.get("sha256")
            != hashlib.sha256(artifact_bytes).hexdigest()
            or artifact_meta.get("sha256") != release["content"]["search_sha256"]
        ):
            raise MirrorError("mirror artifact closure mismatch")
        expected_closure = content_hash(
            "qrh-user-mirror-closure/v1",
            {
                "release_manifest_sha256": identity.manifest_sha256,
                "artifact_sha256": artifact_meta["sha256"],
                "artifact_bytes": artifact_meta["bytes"],
            },
        )
        if metadata.get("closure_sha256") != expected_closure:
            raise MirrorError("mirror closure identity mismatch")
        if not isinstance(metadata.get("synced_at"), str) or not metadata["synced_at"]:
            raise MirrorError("mirror sync time is unavailable")
        try:
            decoded = json.loads(artifact_bytes)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise MirrorError("mirrored search artifact is invalid JSON") from error
        artifact = validate_search_artifact(
            decoded, expected_snapshot_id=identity.snapshot_id
        )
        if canonical_json(artifact).encode("utf-8") != artifact_bytes:
            raise MirrorError("mirrored search artifact is not canonical")
        return MirrorSnapshot(
            root=root,
            identity=identity,
            synced_at=str(metadata.get("synced_at") or ""),
            artifact=artifact,
        )

    def find_snapshot(self, snapshot_id: str) -> MirrorSnapshot | None:
        if not self.root.exists():
            return None
        with self._locked():
            return self._find_snapshot_unlocked(snapshot_id)

    def _find_snapshot_unlocked(self, snapshot_id: str) -> MirrorSnapshot | None:
        if not self.releases_root.is_dir():
            return None
        for candidate in sorted(self.releases_root.iterdir()):
            if not candidate.is_dir() or candidate.name.startswith("."):
                continue
            try:
                _safe_directory(candidate, must_exist=True)
                metadata = _read_json(candidate / "mirror.json")
                raw = metadata["identity"] if isinstance(metadata, dict) else None
                if isinstance(raw, dict) and raw.get("snapshot_id") == snapshot_id:
                    return self.load(AuthorityIdentity(**raw))
            except (MirrorError, KeyError, TypeError, ValueError):
                continue
        return None


__all__ = [
    "ArtifactSource",
    "AuthorityIdentity",
    "AuthorityObservation",
    "AuthorityProbe",
    "AuthorityUnavailable",
    "CommandRunner",
    "FileArtifactSource",
    "FileAuthorityProbe",
    "MirrorError",
    "MirrorSnapshot",
    "MirrorStore",
    "OpenSSHAuthoritySource",
    "SEARCH_ARTIFACT_RELATIVE_PATH",
    "SubprocessCommandRunner",
    "VM_AUTHORITY_ROOT",
    "build_search_artifact",
    "validate_search_artifact",
]
