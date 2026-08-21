"""Canonical release artifacts and fail-closed generic catalog loading."""

from __future__ import annotations

from dataclasses import asdict, fields
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from quant_hub.knowledge.compiler import validate_snapshot
from quant_hub.knowledge.contracts import (
    BaseSnapshot,
    Chunk,
    DocumentIR,
    DocumentRecord,
    DocumentVersion,
    IRBlock,
    SourceSpan,
    canonical_json,
    content_hash,
)
from quant_hub.knowledge.semantic import EnrichedSnapshot
from quant_hub.ops.release_identity import (
    manifest_sha256,
    validate_release_manifest,
)
from quant_hub.runtime_seal import RuntimeSealError, safe_tree_file_state
from quant_hub.config import ensure_no_reparse_components
from quant_hub.knowledge_mcp.mirror import (
    SEARCH_ARTIFACT_RELATIVE_PATH,
    MirrorError,
    validate_search_artifact,
)

from .catalog import GenericKnowledgeCard, GenericResearchCatalog


SNAPSHOT_ARTIFACT_PATH = "content/deterministic_snapshot.json"
SOURCE_MANIFEST_PATH = "content/source_objects.json"
SOURCE_OBJECT_PREFIX = "content/source_objects/sha256"
KNOWLEDGE_ARTIFACT_PATH = "content/generic_knowledge.json"
SNAPSHOT_ARTIFACT_SCHEMA = "qrh-deterministic-snapshot-artifact/v1"
SOURCE_MANIFEST_SCHEMA = "qrh-source-object-closure/v1"
KNOWLEDGE_ARTIFACT_SCHEMA = "qrh-generic-knowledge-artifact/v1"


class GenericReleaseError(ValueError):
    pass


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _closed(value: object, cls: type[Any], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GenericReleaseError(f"{label} must be an object")
    expected = {field.name for field in fields(cls)}
    if set(value) != expected:
        raise GenericReleaseError(f"{label} fields are not closed")
    return value


def _span(value: object) -> SourceSpan:
    row = _closed(value, SourceSpan, "source span")
    return SourceSpan(**row)


def serialize_snapshot(snapshot: BaseSnapshot) -> bytes:
    validate_snapshot(snapshot)
    return canonical_json(
        {
            "schema_version": SNAPSHOT_ARTIFACT_SCHEMA,
            "snapshot": snapshot.to_dict(),
        }
    ).encode("utf-8")


def deserialize_snapshot(payload: bytes) -> BaseSnapshot:
    try:
        wrapper = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise GenericReleaseError("deterministic snapshot is not valid JSON") from error
    if not isinstance(wrapper, dict) or set(wrapper) != {"schema_version", "snapshot"}:
        raise GenericReleaseError("deterministic snapshot wrapper is not closed")
    if wrapper["schema_version"] != SNAPSHOT_ARTIFACT_SCHEMA:
        raise GenericReleaseError("unsupported deterministic snapshot schema")
    raw = _closed(wrapper["snapshot"], BaseSnapshot, "base snapshot")
    ir_documents: dict[str, DocumentIR] = {}
    if not isinstance(raw["ir_documents"], dict):
        raise GenericReleaseError("IR membership must be an object")
    for version_id, value in raw["ir_documents"].items():
        row = _closed(value, DocumentIR, "document IR")
        blocks: list[IRBlock] = []
        if not isinstance(row["blocks"], list):
            raise GenericReleaseError("IR blocks must be an array")
        for value_block in row["blocks"]:
            block = _closed(value_block, IRBlock, "IR block")
            if not isinstance(block["spans"], list):
                raise GenericReleaseError("inline spans must be an array")
            blocks.append(
                IRBlock(
                    **{
                        **block,
                        "source_span": _span(block["source_span"]),
                        "heading_path": tuple(block["heading_path"]),
                        "spans": tuple(_span(item) for item in block["spans"]),
                    }
                )
            )
        ir_documents[str(version_id)] = DocumentIR(
            **{**row, "blocks": tuple(blocks)}
        )
    documents = {
        str(key): DocumentRecord(
            **{
                **_closed(value, DocumentRecord, "document record"),
                "aliases": tuple(value["aliases"]),
                "version_ids": tuple(value["version_ids"]),
            }
        )
        for key, value in raw["documents"].items()
    }
    versions = {
        str(key): DocumentVersion(
            **{
                **_closed(value, DocumentVersion, "document version"),
                "aliases": tuple(value["aliases"]),
            }
        )
        for key, value in raw["versions"].items()
    }
    chunks = {
        str(key): Chunk(
            **{
                **_closed(value, Chunk, "chunk"),
                "heading_path": tuple(value["heading_path"]),
                "ordered_span_ids": tuple(value["ordered_span_ids"]),
            }
        )
        for key, value in raw["chunks"].items()
    }
    snapshot = BaseSnapshot(
        **{
            **raw,
            "documents": documents,
            "versions": versions,
            "ir_documents": ir_documents,
            "chunks": chunks,
            "lexical_membership": tuple(
                tuple(item) for item in raw["lexical_membership"]
            ),
        }
    )
    validate_snapshot(snapshot)
    if serialize_snapshot(snapshot) != payload:
        raise GenericReleaseError("deterministic snapshot is not canonical")
    return snapshot


def source_closure(
    snapshot: BaseSnapshot, source_objects: Mapping[str, bytes]
) -> tuple[bytes, dict[str, bytes]]:
    required = {version.source_sha256: version.source_bytes for version in snapshot.versions.values()}
    if set(source_objects) != set(required):
        raise GenericReleaseError("source object closure is incomplete or contains extras")
    copied: dict[str, bytes] = {}
    records: list[dict[str, object]] = []
    for digest, expected_bytes in sorted(required.items()):
        value = source_objects[digest]
        if type(value) is not bytes or _sha256(value) != digest or len(value) != expected_bytes:
            raise GenericReleaseError("source object bytes do not match snapshot identity")
        copied[digest] = value
        records.append(
            {
                "sha256": digest,
                "bytes": len(value),
                "path": f"{SOURCE_OBJECT_PREFIX}/{digest}",
            }
        )
    manifest = canonical_json(
        {
            "schema_version": SOURCE_MANIFEST_SCHEMA,
            "base_snapshot_id": snapshot.snapshot_id,
            "objects": records,
        }
    ).encode("utf-8")
    return manifest, copied


_KIND_TITLE = {
    "summary": "结构化摘要",
    "method": "方法",
    "condition": "适用条件",
    "limitation": "限制",
    "failure": "失败经验",
}


def serialize_generic_knowledge(
    snapshot: BaseSnapshot, enriched: EnrichedSnapshot | None
) -> bytes:
    if enriched is not None and enriched.base_snapshot_id != snapshot.snapshot_id:
        raise GenericReleaseError("knowledge snapshot belongs to another base snapshot")
    if enriched is not None:
        active_versions = set(snapshot.active_membership.values())
        if set(enriched.knowledge_status_membership) != active_versions:
            raise GenericReleaseError("knowledge status membership is not the active base closure")
        if not set(enriched.generation_membership).issubset(active_versions):
            raise GenericReleaseError("knowledge generation membership escapes active versions")
        if any(
            item.document_version_id not in active_versions
            for item in enriched.knowledge_items.values()
        ):
            raise GenericReleaseError("accepted knowledge escapes active versions")
        accepted_hash = content_hash(
            "qrh-accepted-knowledge-membership/v1",
            {
                key: asdict(value)
                for key, value in sorted(enriched.knowledge_items.items())
            },
        )
        coverage_hash = content_hash(
            "qrh-coverage-membership/v1",
            {
                key: asdict(value)
                for key, value in sorted(enriched.coverage_reports.items())
            },
        )
        identity_payload = {
            "base_snapshot_id": enriched.base_snapshot_id,
            "knowledge_status_membership": enriched.knowledge_status_membership,
            "generation_membership": enriched.generation_membership,
            "accepted_knowledge_hash": accepted_hash,
            "coverage_hash": coverage_hash,
        }
        if (
            enriched.accepted_knowledge_hash != accepted_hash
            or enriched.coverage_hash != coverage_hash
            or enriched.snapshot_id
            != "ksnap_" + content_hash("qrh-enriched-snapshot-id/v1", identity_payload)
        ):
            raise GenericReleaseError("enriched knowledge snapshot identity is invalid")
    effective_id = enriched.snapshot_id if enriched is not None else snapshot.snapshot_id
    statuses = (
        enriched.knowledge_status_membership
        if enriched is not None
        else snapshot.knowledge_status_membership
    )
    cards: dict[str, list[dict[str, object]]] = {}
    if enriched is not None:
        for item in sorted(
            enriched.knowledge_items.values(), key=lambda row: row.knowledge_item_id
        ):
            if item.kind not in _KIND_TITLE or (
                statuses.get(item.document_version_id) != "ready"
                and item.fact_status != "source_explicit"
            ):
                continue
            cards.setdefault(item.document_version_id, []).append(
                {
                    "knowledge_id": item.knowledge_item_id,
                    "kind": item.kind,
                    "title": _KIND_TITLE[item.kind],
                    "statement": item.text,
                    "evidence_span_ids": [binding.span_id for binding in item.evidence],
                    "acceptance": (
                        "source_explicit"
                        if item.fact_status == "source_explicit"
                        else (
                            "human_accepted"
                            if item.fact_status == "human_reviewed"
                            else "mechanically_verified"
                        )
                    ),
                }
            )
    return canonical_json(
        {
            "schema_version": KNOWLEDGE_ARTIFACT_SCHEMA,
            "base_snapshot_id": snapshot.snapshot_id,
            "snapshot_id": effective_id,
            "knowledge_status_membership": statuses,
            "cards_by_version": cards,
        }
    ).encode("utf-8")


def _load_knowledge(payload: bytes) -> tuple[str, str, dict[str, str], dict[str, tuple[GenericKnowledgeCard, ...]]]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise GenericReleaseError("generic knowledge artifact is not valid JSON") from error
    expected = {
        "schema_version", "base_snapshot_id", "snapshot_id",
        "knowledge_status_membership", "cards_by_version",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise GenericReleaseError("generic knowledge artifact is not closed")
    if value["schema_version"] != KNOWLEDGE_ARTIFACT_SCHEMA:
        raise GenericReleaseError("unsupported generic knowledge schema")
    statuses = value["knowledge_status_membership"]
    raw_cards = value["cards_by_version"]
    if not isinstance(statuses, dict) or not isinstance(raw_cards, dict):
        raise GenericReleaseError("generic knowledge memberships are invalid")
    cards: dict[str, tuple[GenericKnowledgeCard, ...]] = {}
    for version_id, rows in raw_cards.items():
        if not isinstance(rows, list):
            raise GenericReleaseError("generic knowledge cards must be arrays")
        parsed = []
        for row in rows:
            closed = _closed(row, GenericKnowledgeCard, "generic knowledge card")
            parsed.append(
                GenericKnowledgeCard(
                    **{**closed, "evidence_span_ids": tuple(closed["evidence_span_ids"])}
                )
            )
        cards[str(version_id)] = tuple(parsed)
    if canonical_json(value).encode("utf-8") != payload:
        raise GenericReleaseError("generic knowledge artifact is not canonical")
    return (
        str(value["base_snapshot_id"]),
        str(value["snapshot_id"]),
        {str(key): str(status) for key, status in statuses.items()},
        cards,
    )


def _verified_release_inventory(root: Path) -> Mapping[str, Mapping[str, object]]:
    try:
        manifest = validate_release_manifest(
            json.loads((root / "release_manifest.json").read_text(encoding="utf-8"))
        )
        actual = safe_tree_file_state(root)
    except (OSError, UnicodeError, json.JSONDecodeError, RuntimeSealError, ValueError) as error:
        raise GenericReleaseError("finalized release cannot be verified") from error
    if manifest["release_id"] != root.name:
        raise GenericReleaseError("release directory and release identity disagree")
    inventory = manifest["inventory"]
    if (
        not isinstance(inventory, dict)
        or set(inventory) != {"schema_version", "files"}
        or inventory["schema_version"] != "qrh-release-file-inventory/v1"
        or not isinstance(inventory["files"], list)
    ):
        raise GenericReleaseError("release inventory schema is invalid")
    if manifest["resources"]["inventory_sha256"] != manifest_sha256(inventory):
        raise GenericReleaseError("release inventory hash is not bound")
    expected: dict[str, Mapping[str, object]] = {}
    for row in inventory["files"]:
        if (
            not isinstance(row, dict)
            or set(row) != {"path", "bytes", "sha256"}
            or not isinstance(row["path"], str)
            or PurePosixPath(row["path"]).is_absolute()
            or ".." in PurePosixPath(row["path"]).parts
            or not isinstance(row["bytes"], int)
            or isinstance(row["bytes"], bool)
            or row["bytes"] < 0
            or not isinstance(row["sha256"], str)
            or len(row["sha256"]) != 64
        ):
            raise GenericReleaseError("release inventory record is invalid")
        if row["path"] in expected:
            raise GenericReleaseError("release inventory path is duplicated")
        expected[row["path"]] = {"bytes": row["bytes"], "sha256": row["sha256"]}
    actual.pop("release_manifest.json", None)
    if actual != expected:
        raise GenericReleaseError("finalized release inventory differs from disk")
    return {**expected, "__manifest__": manifest}


def load_generic_catalog_from_release(release_root: Path) -> GenericResearchCatalog:
    try:
        ensure_no_reparse_components(Path(release_root))
        root = Path(release_root).resolve(strict=True)
    except (OSError, ValueError) as error:
        raise GenericReleaseError("release root is unavailable or unsafe") from error
    inventory = _verified_release_inventory(root)
    manifest = inventory["__manifest__"]
    content = manifest["content"]

    def read_bound(relative: str, field: str) -> bytes:
        try:
            payload = (root / PurePosixPath(relative)).read_bytes()
        except OSError as error:
            raise GenericReleaseError(f"release artifact is unavailable: {relative}") from error
        if _sha256(payload) != content[field]:
            raise GenericReleaseError(f"release {field} does not bind {relative}")
        return payload

    snapshot = deserialize_snapshot(read_bound(SNAPSHOT_ARTIFACT_PATH, "ir_sha256"))
    source_manifest_bytes = read_bound(SOURCE_MANIFEST_PATH, "source_inventory_sha256")
    try:
        source_manifest = json.loads(source_manifest_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise GenericReleaseError("source object manifest is invalid") from error
    if (
        not isinstance(source_manifest, dict)
        or set(source_manifest) != {"schema_version", "base_snapshot_id", "objects"}
        or source_manifest["schema_version"] != SOURCE_MANIFEST_SCHEMA
        or source_manifest["base_snapshot_id"] != snapshot.snapshot_id
        or canonical_json(source_manifest).encode("utf-8") != source_manifest_bytes
    ):
        raise GenericReleaseError("source object manifest identity is invalid")
    sources: dict[str, bytes] = {}
    for row in source_manifest["objects"]:
        if not isinstance(row, dict) or set(row) != {"sha256", "bytes", "path"}:
            raise GenericReleaseError("source object record is not closed")
        digest = str(row["sha256"])
        expected_path = f"{SOURCE_OBJECT_PREFIX}/{digest}"
        if row["path"] != expected_path:
            raise GenericReleaseError("source object path is not content-addressed")
        try:
            payload = (root / PurePosixPath(expected_path)).read_bytes()
        except OSError as error:
            raise GenericReleaseError("source object is unavailable") from error
        if _sha256(payload) != digest or len(payload) != row["bytes"]:
            raise GenericReleaseError("source object differs from its manifest")
        sources[digest] = payload
    source_closure(snapshot, sources)
    knowledge_bytes = read_bound(KNOWLEDGE_ARTIFACT_PATH, "knowledge_sha256")
    base_id, effective_id, statuses, cards = _load_knowledge(knowledge_bytes)
    if (
        base_id != snapshot.snapshot_id
        or effective_id != content["snapshot_id"]
        or set(statuses) != set(snapshot.knowledge_status_membership)
    ):
        raise GenericReleaseError("generic knowledge and release snapshot identities disagree")
    try:
        search_bytes = read_bound(SEARCH_ARTIFACT_RELATIVE_PATH, "search_sha256")
        validate_search_artifact(
            json.loads(search_bytes.decode("utf-8")),
            expected_snapshot_id=effective_id,
        )
    except (UnicodeError, json.JSONDecodeError, MirrorError) as error:
        raise GenericReleaseError("release search artifact is invalid") from error
    return GenericResearchCatalog(
        snapshot,
        sources,
        accepted_knowledge=cards,
        effective_snapshot_id=effective_id,
        knowledge_status_membership=statuses,
        release_manifest_sha256=manifest_sha256(manifest),
    )


__all__ = [
    "GenericReleaseError",
    "KNOWLEDGE_ARTIFACT_PATH",
    "SNAPSHOT_ARTIFACT_PATH",
    "SOURCE_MANIFEST_PATH",
    "SOURCE_OBJECT_PREFIX",
    "deserialize_snapshot",
    "load_generic_catalog_from_release",
    "serialize_generic_knowledge",
    "serialize_snapshot",
    "source_closure",
]
