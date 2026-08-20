"""Stable comment targets and deterministic per-snapshot anchor projections.

The comment/current and event tables remain the mutable authority.  This module
only describes an immutable origin target and derives a read-only projection for
one content snapshot.  In particular, projection never rewrites a comment,
never uses fuzzy/embedding similarity, and never treats a release path as an
identity.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Any, Literal, Mapping


COMMENT_TARGET_SCHEMA_VERSION = 3
COMMENT_LOCATOR_SCHEMA_VERSION = "comment-locator/v1"
COMMENT_ANCHOR_PROJECTION_SCHEMA_VERSION = "comment-anchor-projection/v1"

TargetKind = Literal["research", "document", "block", "span"]
ProjectionStatus = Literal[
    "resolved_current", "resolved_history", "unresolved", "ambiguous"
]

_SHA256 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_BLOCK_TYPE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$", re.ASCII)
_FORBIDDEN_LOCATOR_KEYS = {
    "path",
    "route",
    "release_path",
    "source_path",
    "snapshot_row_id",
}


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _json_hash(value: Any) -> str:
    return _sha256(_canonical_json(value).encode("utf-8"))


def _validate_json_object(value: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    normalized = json.loads(_canonical_json(dict(value)))
    if not isinstance(normalized, dict):
        raise ValueError(f"{label} must be a JSON object")

    def keys(item: Any) -> set[str]:
        if isinstance(item, dict):
            return set(item).union(*(keys(child) for child in item.values()))
        if isinstance(item, list):
            return set().union(*(keys(child) for child in item))
        return set()

    if _FORBIDDEN_LOCATOR_KEYS.intersection(keys(normalized)):
        raise ValueError(f"{label} must not bind a release path or route")
    return normalized


@dataclass(frozen=True, slots=True)
class CommentTargetInput:
    """Server-side target input whose anchor is checked against source bytes."""

    target_kind: TargetKind
    document_id: str | None = None
    origin_document_version_id: str | None = None
    origin_source_sha256: str | None = None
    origin_block_type: str | None = None
    origin_start_byte: int | None = None
    origin_end_byte: int | None = None
    origin_exact_bytes: bytes | None = None
    structural_context: Mapping[str, Any] | None = None
    locator: Mapping[str, Any] | None = None
    locator_schema_version: str = COMMENT_LOCATOR_SCHEMA_VERSION

    @classmethod
    def research(cls) -> "CommentTargetInput":
        return cls(target_kind="research")

    @classmethod
    def document(cls, document_id: str) -> "CommentTargetInput":
        return cls(target_kind="document", document_id=document_id)

    @classmethod
    def anchored(
        cls,
        *,
        target_kind: Literal["block", "span"],
        document_id: str,
        origin_document_version_id: str,
        origin_source_sha256: str,
        origin_block_type: str,
        origin_start_byte: int,
        origin_end_byte: int,
        origin_exact_bytes: bytes,
        structural_context: Mapping[str, Any],
        locator: Mapping[str, Any],
    ) -> "CommentTargetInput":
        return cls(
            target_kind=target_kind,
            document_id=document_id,
            origin_document_version_id=origin_document_version_id,
            origin_source_sha256=origin_source_sha256,
            origin_block_type=origin_block_type,
            origin_start_byte=origin_start_byte,
            origin_end_byte=origin_end_byte,
            origin_exact_bytes=origin_exact_bytes,
            structural_context=structural_context,
            locator=locator,
        )

    def normalized(self) -> dict[str, Any]:
        if self.target_kind == "research":
            if any(
                value is not None
                for value in (
                    self.document_id,
                    self.origin_document_version_id,
                    self.origin_source_sha256,
                    self.origin_block_type,
                    self.origin_start_byte,
                    self.origin_end_byte,
                    self.origin_exact_bytes,
                    self.structural_context,
                    self.locator,
                )
            ):
                raise ValueError("research target must not contain a document anchor")
            return {"target_kind": "research", "document_id": None}
        if not self.document_id or not self.document_id.strip():
            raise ValueError("document target requires a stable document_id")
        document_id = self.document_id.strip()
        if self.target_kind == "document":
            if any(
                value is not None
                for value in (
                    self.origin_document_version_id,
                    self.origin_source_sha256,
                    self.origin_block_type,
                    self.origin_start_byte,
                    self.origin_end_byte,
                    self.origin_exact_bytes,
                    self.structural_context,
                    self.locator,
                )
            ):
                raise ValueError("document target must not contain a versioned anchor")
            return {"target_kind": "document", "document_id": document_id}
        if self.target_kind not in {"block", "span"}:
            raise ValueError("unsupported comment target kind")
        if not self.origin_document_version_id or not self.origin_document_version_id.strip():
            raise ValueError("anchored target requires origin_document_version_id")
        if not self.origin_source_sha256 or not _SHA256.fullmatch(
            self.origin_source_sha256
        ):
            raise ValueError("anchored target requires a lowercase source SHA-256")
        if not self.origin_block_type or not _BLOCK_TYPE.fullmatch(
            self.origin_block_type
        ):
            raise ValueError("anchored target requires a canonical block type")
        if (
            self.origin_start_byte is None
            or self.origin_end_byte is None
            or self.origin_start_byte < 0
            or self.origin_end_byte <= self.origin_start_byte
        ):
            raise ValueError("anchored target requires a non-empty byte span")
        if not isinstance(self.origin_exact_bytes, bytes) or not self.origin_exact_bytes:
            raise ValueError("anchored target requires the exact source bytes")
        if self.origin_end_byte - self.origin_start_byte != len(self.origin_exact_bytes):
            raise ValueError("byte span length must equal the exact source byte length")
        if self.locator_schema_version != COMMENT_LOCATOR_SCHEMA_VERSION:
            raise ValueError("unsupported comment locator schema")
        if self.structural_context is None or self.locator is None:
            raise ValueError("anchored target requires structural context and locator")
        context = _validate_json_object(
            self.structural_context, label="structural_context"
        )
        locator = _validate_json_object(self.locator, label="locator")
        return {
            "target_kind": self.target_kind,
            "document_id": document_id,
            "origin_document_version_id": self.origin_document_version_id.strip(),
            "origin_source_sha256": self.origin_source_sha256,
            "origin_block_type": self.origin_block_type,
            "origin_start_byte": self.origin_start_byte,
            "origin_end_byte": self.origin_end_byte,
            "origin_exact_bytes": self.origin_exact_bytes,
            "origin_exact_bytes_sha256": _sha256(self.origin_exact_bytes),
            "origin_structural_context_json": _canonical_json(context),
            "origin_structural_context_sha256": _json_hash(context),
            "origin_locator_json": _canonical_json(locator),
            "locator_schema_version": self.locator_schema_version,
        }


@dataclass(frozen=True, slots=True)
class SnapshotBlock:
    block_type: str
    start_byte: int
    end_byte: int
    structural_context: Mapping[str, Any]

    def normalized(self, source_bytes: bytes) -> dict[str, Any]:
        if not _BLOCK_TYPE.fullmatch(self.block_type):
            raise ValueError("snapshot block type is not canonical")
        if self.start_byte < 0 or self.end_byte <= self.start_byte:
            raise ValueError("snapshot block span must be non-empty")
        if self.end_byte > len(source_bytes):
            raise ValueError("snapshot block lies outside source bytes")
        context = _validate_json_object(
            self.structural_context, label="structural_context"
        )
        return {
            "block_type": self.block_type,
            "start_byte": self.start_byte,
            "end_byte": self.end_byte,
            "structural_context": context,
            "structural_context_sha256": _json_hash(context),
        }


@dataclass(frozen=True, slots=True)
class SnapshotDocument:
    research_id: str
    document_id: str
    document_version_id: str
    source_sha256: str
    source_bytes: bytes
    blocks: tuple[SnapshotBlock, ...]

    def normalized(self) -> dict[str, Any]:
        if not self.research_id.strip() or not self.document_id.strip():
            raise ValueError("snapshot document requires stable identities")
        if not self.document_version_id.strip():
            raise ValueError("snapshot document requires a version identity")
        if not _SHA256.fullmatch(self.source_sha256):
            raise ValueError("snapshot source SHA-256 is invalid")
        if _sha256(self.source_bytes) != self.source_sha256:
            raise ValueError("snapshot source bytes do not match source_sha256")
        blocks = tuple(block.normalized(self.source_bytes) for block in self.blocks)
        prior_end = -1
        for block in sorted(blocks, key=lambda item: (item["start_byte"], item["end_byte"])):
            if block["start_byte"] < prior_end:
                raise ValueError("snapshot blocks must not overlap")
            prior_end = int(block["end_byte"])
        return {
            "research_id": self.research_id,
            "document_id": self.document_id,
            "document_version_id": self.document_version_id,
            "source_sha256": self.source_sha256,
            "source_bytes": self.source_bytes,
            "blocks": blocks,
        }


@dataclass(frozen=True, slots=True)
class UnchangedBlockMapping:
    """Compiler proof for one unchanged block across two versions."""

    document_id: str
    origin_document_version_id: str
    target_document_version_id: str
    origin_start_byte: int
    origin_end_byte: int
    target_start_byte: int
    target_end_byte: int
    exact_bytes_sha256: str
    block_type: str
    origin_structural_context_sha256: str
    target_structural_context_sha256: str


@dataclass(frozen=True, slots=True)
class CommentAnchorSnapshot:
    snapshot_id: str
    manifest_sha256: str
    view: Literal["current", "history"]
    documents: tuple[SnapshotDocument, ...]
    unchanged_block_mappings: tuple[UnchangedBlockMapping, ...] = ()

    def normalized(self) -> dict[str, Any]:
        if not self.snapshot_id.strip() or not _SHA256.fullmatch(self.manifest_sha256):
            raise ValueError("snapshot identity is invalid")
        documents = tuple(document.normalized() for document in self.documents)
        keys = [(item["research_id"], item["document_id"]) for item in documents]
        if len(keys) != len(set(keys)):
            raise ValueError("snapshot has duplicate stable document identities")
        return {
            "snapshot_id": self.snapshot_id,
            "manifest_sha256": self.manifest_sha256,
            "view": self.view,
            "documents": documents,
            "unchanged_block_mappings": self.unchanged_block_mappings,
        }


def insert_comment_target(
    connection: sqlite3.Connection,
    *,
    comment_id: str,
    research_id: str,
    target: CommentTargetInput,
    created_at: str,
) -> None:
    material = target.normalized()
    target_id = "ctgt_" + _sha256(comment_id.encode("utf-8"))[:32]
    connection.execute(
        """
        INSERT INTO comment_target(
            comment_target_id,comment_id,target_kind,research_id,document_id,
            origin_document_version_id,origin_source_sha256,origin_block_type,
            origin_start_byte,origin_end_byte,origin_exact_bytes,
            origin_exact_bytes_sha256,origin_structural_context_json,
            origin_structural_context_sha256,origin_locator_json,
            locator_schema_version,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            target_id,
            comment_id,
            material["target_kind"],
            research_id,
            material.get("document_id"),
            material.get("origin_document_version_id"),
            material.get("origin_source_sha256"),
            material.get("origin_block_type"),
            material.get("origin_start_byte"),
            material.get("origin_end_byte"),
            material.get("origin_exact_bytes"),
            material.get("origin_exact_bytes_sha256"),
            material.get("origin_structural_context_json"),
            material.get("origin_structural_context_sha256"),
            material.get("origin_locator_json"),
            material.get("locator_schema_version"),
            created_at,
        ),
    )


def _readonly_database(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        f"file:{path.resolve().as_posix()}?mode=ro", uri=True, timeout=10
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def _find_occurrences(payload: bytes, needle: bytes) -> list[tuple[int, int]]:
    found: list[tuple[int, int]] = []
    position = 0
    while True:
        start = payload.find(needle, position)
        if start < 0:
            return found
        found.append((start, start + len(needle)))
        position = start + 1


def _matching_blocks(
    document: dict[str, Any],
    *,
    start: int,
    end: int,
    block_type: str,
    context_sha256: str,
) -> list[dict[str, Any]]:
    return [
        block
        for block in document["blocks"]
        if block["block_type"] == block_type
        and block["structural_context_sha256"] == context_sha256
        and block["start_byte"] <= start
        and block["end_byte"] >= end
    ]


def _mapping_candidates(
    target: sqlite3.Row,
    document: dict[str, Any],
    mappings: tuple[UnchangedBlockMapping, ...],
) -> list[tuple[int, int]]:
    selected = [
        item
        for item in mappings
        if item.document_id == target["document_id"]
        and item.origin_document_version_id == target["origin_document_version_id"]
        and item.target_document_version_id == document["document_version_id"]
        and item.origin_start_byte == target["origin_start_byte"]
        and item.origin_end_byte == target["origin_end_byte"]
        and item.exact_bytes_sha256 == target["origin_exact_bytes_sha256"]
        and item.block_type == target["origin_block_type"]
        and item.origin_structural_context_sha256
        == target["origin_structural_context_sha256"]
    ]
    results: list[tuple[int, int]] = []
    for item in selected:
        if item.target_end_byte <= item.target_start_byte:
            continue
        exact = bytes(target["origin_exact_bytes"])
        if document["source_bytes"][item.target_start_byte : item.target_end_byte] != exact:
            continue
        blocks = _matching_blocks(
            document,
            start=item.target_start_byte,
            end=item.target_end_byte,
            block_type=item.block_type,
            context_sha256=item.target_structural_context_sha256,
        )
        if len(blocks) == 1:
            results.append((item.target_start_byte, item.target_end_byte))
    # A mapping is a proof only while it is one-to-one.
    return results if len(results) == len(set(results)) else []


def _resolution(
    target: sqlite3.Row,
    *,
    documents: dict[tuple[str, str], dict[str, Any]],
    view: Literal["current", "history"],
    mappings: tuple[UnchangedBlockMapping, ...],
) -> dict[str, Any]:
    resolved_status: ProjectionStatus = (
        "resolved_current" if view == "current" else "resolved_history"
    )
    key = (str(target["research_id"]), str(target["document_id"] or ""))
    if target["target_kind"] == "research":
        research_exists = any(item[0] == target["research_id"] for item in documents)
        return {
            "status": resolved_status if research_exists else "unresolved",
            "reason": "stable_research_identity" if research_exists else "research_absent",
        }
    document = documents.get(key)
    if document is None:
        return {"status": "unresolved", "reason": "document_absent"}
    if target["target_kind"] == "document":
        return {
            "status": resolved_status,
            "reason": "stable_document_identity",
            "document_version_id": document["document_version_id"],
        }

    exact = bytes(target["origin_exact_bytes"])
    if _sha256(exact) != target["origin_exact_bytes_sha256"]:
        return {"status": "unresolved", "reason": "origin_anchor_corrupt"}
    candidates: list[tuple[int, int]] = []
    for start, end in _find_occurrences(document["source_bytes"], exact):
        blocks = _matching_blocks(
            document,
            start=start,
            end=end,
            block_type=str(target["origin_block_type"]),
            context_sha256=str(target["origin_structural_context_sha256"]),
        )
        if len(blocks) == 1:
            candidates.append((start, end))
    reason = "exact_unique_source_bytes_and_context"
    if not candidates:
        candidates = _mapping_candidates(target, document, mappings)
        reason = "verified_one_to_one_unchanged_block_mapping"
    unique = sorted(set(candidates))
    if len(unique) == 1:
        start, end = unique[0]
        return {
            "status": resolved_status,
            "reason": reason,
            "document_version_id": document["document_version_id"],
            "start_byte": start,
            "end_byte": end,
            "block_type": target["origin_block_type"],
        }
    if len(unique) > 1:
        return {
            "status": "ambiguous",
            "reason": "multiple_exact_context_candidates",
            "candidate_count": len(unique),
        }
    return {"status": "unresolved", "reason": "no_exact_verified_candidate"}


def build_comment_anchor_projection(
    database_path: Path,
    snapshot: CommentAnchorSnapshot,
) -> dict[str, Any]:
    """Derive an API/artifact model without mutating comment state."""

    normalized = snapshot.normalized()
    documents = {
        (str(item["research_id"]), str(item["document_id"])): item
        for item in normalized["documents"]
    }
    connection = _readonly_database(database_path)
    try:
        rows = connection.execute(
            """
            SELECT c.comment_id,c.research_id,c.deleted_at,
                   COALESCE(t.target_kind,'research') AS target_kind,
                   COALESCE(t.research_id,c.research_id) AS target_research_id,
                   t.document_id,t.origin_document_version_id,t.origin_source_sha256,
                   t.origin_block_type,t.origin_start_byte,t.origin_end_byte,
                   t.origin_exact_bytes,t.origin_exact_bytes_sha256,
                   t.origin_structural_context_sha256,t.origin_locator_json,
                   t.locator_schema_version
            FROM comment AS c
            LEFT JOIN comment_target AS t ON t.comment_id=c.comment_id
            WHERE c.deleted_at IS NULL
            ORDER BY c.created_at,c.comment_id
            """
        ).fetchall()
    finally:
        connection.close()

    entries: list[dict[str, Any]] = []
    target_hash_material: list[dict[str, Any]] = []
    for source in rows:
        # Alias column names back to the target contract while retaining v2
        # fallback for comments written by an old release after expansion.
        target = dict(source)
        target["research_id"] = target.pop("target_research_id")
        origin = {
            "document_version_id": target.get("origin_document_version_id"),
            "source_sha256": target.get("origin_source_sha256"),
            "block_type": target.get("origin_block_type"),
            "start_byte": target.get("origin_start_byte"),
            "end_byte": target.get("origin_end_byte"),
            "exact_bytes_sha256": target.get("origin_exact_bytes_sha256"),
            "structural_context_sha256": target.get(
                "origin_structural_context_sha256"
            ),
            "locator": (
                json.loads(str(target["origin_locator_json"]))
                if target.get("origin_locator_json")
                else None
            ),
            "locator_schema_version": target.get("locator_schema_version"),
        }
        material = {
            "comment_id": str(target["comment_id"]),
            "target_kind": str(target["target_kind"]),
            "research_id": str(target["research_id"]),
            "document_id": target.get("document_id"),
            "origin": origin,
        }
        target_hash_material.append(material)
        # sqlite.Row behavior is enough for _resolution; a dict is intentional
        # here so the v2 fallback can be represented without state writes.
        entries.append(
            {
                **material,
                "resolution": _resolution(
                    target,  # type: ignore[arg-type]
                    documents=documents,
                    view=normalized["view"],
                    mappings=normalized["unchanged_block_mappings"],
                ),
                "history": {
                    "origin_document_version_id": origin["document_version_id"],
                    "origin_locator": origin["locator"],
                    "preserved": True,
                },
            }
        )
    return {
        "schema_version": COMMENT_ANCHOR_PROJECTION_SCHEMA_VERSION,
        "snapshot_id": normalized["snapshot_id"],
        "manifest_sha256": normalized["manifest_sha256"],
        "view": normalized["view"],
        "comment_target_set_sha256": _json_hash(target_hash_material),
        "entries": entries,
    }


def write_comment_anchor_projection(
    database_path: Path,
    snapshot: CommentAnchorSnapshot,
    destination: Path,
) -> tuple[Path, str]:
    """Write-once projection artifact; a different overwrite is rejected."""

    artifact = build_comment_anchor_projection(database_path, snapshot)
    payload = (_canonical_json(artifact) + "\n").encode("utf-8")
    digest = _sha256(payload)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if destination.read_bytes() != payload:
            raise FileExistsError("comment anchor projection is immutable")
        return destination, digest
    temporary = destination.with_name(destination.name + f".{os.getpid()}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return destination, digest


def load_comment_anchor_projection(
    path: Path,
    *,
    expected_snapshot_id: str | None = None,
    expected_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    artifact = json.loads(path.read_text(encoding="utf-8"))
    if artifact.get("schema_version") != COMMENT_ANCHOR_PROJECTION_SCHEMA_VERSION:
        raise ValueError("unsupported comment anchor projection schema")
    if expected_snapshot_id is not None and artifact.get("snapshot_id") != expected_snapshot_id:
        raise ValueError("comment anchor projection snapshot mismatch")
    if (
        expected_manifest_sha256 is not None
        and artifact.get("manifest_sha256") != expected_manifest_sha256
    ):
        raise ValueError("comment anchor projection manifest mismatch")
    if not isinstance(artifact.get("entries"), list):
        raise ValueError("comment anchor projection entries are invalid")
    return artifact


__all__ = [
    "COMMENT_ANCHOR_PROJECTION_SCHEMA_VERSION",
    "COMMENT_LOCATOR_SCHEMA_VERSION",
    "COMMENT_TARGET_SCHEMA_VERSION",
    "CommentAnchorSnapshot",
    "CommentTargetInput",
    "SnapshotBlock",
    "SnapshotDocument",
    "UnchangedBlockMapping",
    "build_comment_anchor_projection",
    "insert_comment_target",
    "load_comment_anchor_projection",
    "write_comment_anchor_projection",
]
