"""Seal a complete candidate tree with one immutable release manifest."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import stat
from typing import Mapping, Sequence
from uuid import uuid4

from quant_hub.runtime_seal import RuntimeSealError, safe_tree_file_state
from quant_hub.knowledge.contracts import BaseSnapshot
from quant_hub.knowledge.citations import (
    CitationProjectionError,
    build_citation_projection,
)
from quant_hub.knowledge.semantic import EnrichedSnapshot, KnowledgeGeneration
from quant_hub.knowledge_mcp.mirror import (
    MirrorError,
    SEARCH_ARTIFACT_RELATIVE_PATH,
    build_search_artifact,
    validate_search_artifact,
)
from quant_hub.config import ensure_no_reparse_components, stat_is_reparse_point
from quant_hub.generic_research.release import (
    KNOWLEDGE_ARTIFACT_PATH,
    SNAPSHOT_ARTIFACT_PATH,
    SOURCE_MANIFEST_PATH,
    SOURCE_OBJECT_PREFIX,
    GenericReleaseError,
    serialize_generic_knowledge,
    serialize_snapshot,
    source_closure,
)

from .release_identity import (
    canonical_manifest_bytes,
    manifest_sha256,
    validate_release_manifest,
)
from . import local_release_identity as local_identity


INVENTORY_SCHEMA = "qrh-release-file-inventory/v1"


class ReleaseBuildError(RuntimeError):
    pass


@dataclass(frozen=True)
class SealedRelease:
    root: Path
    release_id: str
    manifest_sha256: str
    file_count: int
    total_bytes: int


@dataclass(frozen=True)
class PreparedKnowledgeSearch:
    root: Path
    artifact_path: Path
    artifact_sha256: str
    snapshot_id: str
    manifest_without_inventory: dict[str, object]


def _manifest_copy(value: Mapping[str, object]) -> dict[str, object]:
    try:
        parsed = json.loads(canonical_manifest_bytes(value))
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise ReleaseBuildError("manifest input is not canonical JSON material") from error
    if not isinstance(parsed, dict):
        raise ReleaseBuildError("manifest input must be an object")
    return parsed


def _atomic_create_or_verify(path: Path, payload: bytes) -> None:
    if path.exists():
        try:
            current = path.read_bytes()
        except OSError as error:
            raise ReleaseBuildError("existing search artifact cannot be read") from error
        if current != payload:
            raise ReleaseBuildError("existing search artifact differs from requested snapshot")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.partial-{uuid4().hex}")
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        if temporary.exists():
            temporary.unlink()
        raise


def _source_objects_from_root(snapshot: BaseSnapshot, source_root: Path) -> dict[str, bytes]:
    root = Path(source_root)
    ensure_no_reparse_components(root)
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ReleaseBuildError("source root is not a directory")
    objects: dict[str, bytes] = {}
    for version in snapshot.versions.values():
        relative = PurePosixPath(version.logical_path)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise ReleaseBuildError("snapshot logical path escapes source root")
        path = root.joinpath(*relative.parts)
        ensure_no_reparse_components(path)
        try:
            info = path.lstat()
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise ReleaseBuildError("snapshot source file is unavailable") from error
        if (
            stat_is_reparse_point(info)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or root not in resolved.parents
        ):
            raise ReleaseBuildError("snapshot source file is unsafe")
        value = path.read_bytes()
        digest = hashlib.sha256(value).hexdigest()
        if digest != version.source_sha256:
            raise ReleaseBuildError(
                "source root cannot provide an immutable historical version; use explicit source_objects"
            )
        objects[digest] = value
    return objects


def prepare_knowledge_search(
    *,
    candidate_root: Path,
    manifest_without_inventory: Mapping[str, object],
    snapshot: BaseSnapshot,
    enriched: EnrichedSnapshot | None = None,
    generations: Sequence[KnowledgeGeneration] = (),
    source_root: Path | None = None,
    source_objects: Mapping[str, bytes] | None = None,
    evidence_database_path: Path | None = None,
    citation_overlay_manifest_path: Path | None = None,
    evidence_migration_root: Path | None = None,
) -> PreparedKnowledgeSearch:
    """Materialize the immutable MCP artifact before release sealing.

    The artifact intentionally has no release identity.  The one-way binding
    is artifact bytes -> `content.search_sha256` -> immutable release manifest.
    A failed rebuild never overwrites an existing candidate artifact.
    """

    root = Path(candidate_root).resolve(strict=True)
    if (root / "release_manifest.json").exists():
        raise ReleaseBuildError("candidate already contains a release manifest")
    # This runs before creating `content/` so an existing junction, symlink or
    # hard-linked artifact cannot redirect the build outside the candidate.
    build_file_inventory(root)
    manifest = _manifest_copy(manifest_without_inventory)
    content = manifest.get("content")
    if not isinstance(content, dict):
        raise ReleaseBuildError("manifest content must be an object")
    expected_snapshot_id = enriched.snapshot_id if enriched is not None else snapshot.snapshot_id
    if content.get("snapshot_id") != expected_snapshot_id:
        raise ReleaseBuildError("manifest snapshot differs from knowledge artifact snapshot")
    if (source_root is None) == (source_objects is None):
        raise ReleaseBuildError("provide exactly one of source_root or source_objects")
    citation_authorities = (
        evidence_database_path,
        citation_overlay_manifest_path,
        evidence_migration_root,
    )
    if any(value is not None for value in citation_authorities) and not all(
        value is not None for value in citation_authorities
    ):
        raise ReleaseBuildError(
            "Evidence database, migration schema, and citation overlay must be configured together"
        )
    try:
        selected_sources = (
            _source_objects_from_root(snapshot, source_root)
            if source_root is not None
            else dict(source_objects or {})
        )
        citation_projection = (
            build_citation_projection(
                snapshot,
                evidence_database_path,
                selected_sources,
                overlay_manifest_path=citation_overlay_manifest_path,
                evidence_migration_root=evidence_migration_root,
            )
            if evidence_database_path is not None
            else None
        )
        snapshot_payload = serialize_snapshot(snapshot)
        source_manifest_payload, source_payloads = source_closure(snapshot, selected_sources)
        knowledge_payload = serialize_generic_knowledge(snapshot, enriched)
        payload = build_search_artifact(
            snapshot,
            enriched=enriched,
            generations=generations,
            citation_projection=citation_projection,
        )
        validate_search_artifact(
            json.loads(payload.decode("utf-8")),
            expected_snapshot_id=expected_snapshot_id,
        )
    except (
        CitationProjectionError,
        MirrorError,
        GenericReleaseError,
        UnicodeError,
        json.JSONDecodeError,
    ) as error:
        raise ReleaseBuildError("knowledge release closure is invalid") from error
    component_payloads = {
        "ir_sha256": snapshot_payload,
        "source_inventory_sha256": source_manifest_payload,
        "knowledge_sha256": knowledge_payload,
        "search_sha256": payload,
    }
    component_hashes = {
        key: hashlib.sha256(value).hexdigest()
        for key, value in component_payloads.items()
    }
    for key, digest in component_hashes.items():
        claimed = content.get(key)
        if claimed not in (None, digest):
            raise ReleaseBuildError(f"manifest {key} differs from generated artifact")
        content[key] = digest
    artifact_hash = hashlib.sha256(payload).hexdigest()
    artifact_path = root / SEARCH_ARTIFACT_RELATIVE_PATH
    materialized = {
        root / SNAPSHOT_ARTIFACT_PATH: snapshot_payload,
        root / SOURCE_MANIFEST_PATH: source_manifest_payload,
        root / KNOWLEDGE_ARTIFACT_PATH: knowledge_payload,
        artifact_path: payload,
        **{
            root / SOURCE_OBJECT_PREFIX / digest: value
            for digest, value in source_payloads.items()
        },
    }
    # Preflight the full closure before writing any new member.  This preserves
    # an existing coherent candidate if a mixed snapshot is attempted.
    for path, value in materialized.items():
        if path.exists() and path.read_bytes() != value:
            raise ReleaseBuildError("existing release closure differs from requested snapshot")
    for path, value in materialized.items():
        _atomic_create_or_verify(path, value)
    return PreparedKnowledgeSearch(
        root=root,
        artifact_path=artifact_path,
        artifact_sha256=artifact_hash,
        snapshot_id=expected_snapshot_id,
        manifest_without_inventory=manifest,
    )


def seal_knowledge_release(
    *,
    candidate_root: Path,
    manifest_without_inventory: Mapping[str, object],
    snapshot: BaseSnapshot,
    enriched: EnrichedSnapshot | None = None,
    generations: Sequence[KnowledgeGeneration] = (),
    source_root: Path | None = None,
    source_objects: Mapping[str, bytes] | None = None,
    evidence_database_path: Path | None = None,
    citation_overlay_manifest_path: Path | None = None,
    evidence_migration_root: Path | None = None,
) -> SealedRelease:
    prepared = prepare_knowledge_search(
        candidate_root=candidate_root,
        manifest_without_inventory=manifest_without_inventory,
        snapshot=snapshot,
        enriched=enriched,
        generations=generations,
        source_root=source_root,
        source_objects=source_objects,
        evidence_database_path=evidence_database_path,
        citation_overlay_manifest_path=citation_overlay_manifest_path,
        evidence_migration_root=evidence_migration_root,
    )
    if (
        prepared.manifest_without_inventory.get("schema_version")
        == local_identity.RELEASE_MANIFEST_SCHEMA
    ):
        return seal_exact_release(
            candidate_root=prepared.root,
            manifest_without_inventory=prepared.manifest_without_inventory,
        )
    return seal_release(
        candidate_root=prepared.root,
        manifest_without_inventory=prepared.manifest_without_inventory,
    )


def build_file_inventory(candidate_root: Path) -> dict[str, object]:
    root = Path(candidate_root).resolve(strict=True)
    try:
        state = safe_tree_file_state(root)
    except (OSError, RuntimeSealError) as error:
        raise ReleaseBuildError("candidate tree cannot be safely inventoried") from error
    if "release_manifest.json" in state:
        raise ReleaseBuildError("candidate already contains a release manifest")
    return {
        "schema_version": INVENTORY_SCHEMA,
        "files": [
            {"path": path, "bytes": facts["bytes"], "sha256": facts["sha256"]}
            for path, facts in sorted(state.items())
        ],
    }


def build_exact_file_inventory(candidate_root: Path) -> dict[str, object]:
    """Build the Windows-safe v2 inventory used by local active/prior."""

    inventory = build_file_inventory(candidate_root)
    inventory["schema_version"] = "qrh-release-file-inventory/v2"
    return inventory


def seal_exact_release(
    *, candidate_root: Path, manifest_without_inventory: Mapping[str, object]
) -> SealedRelease:
    """Seal an immutable v2 release consumable by the exact VM controller."""

    root = Path(candidate_root).resolve(strict=True)
    manifest_path = root / "release_manifest.json"
    if manifest_path.exists():
        raise ReleaseBuildError("immutable release manifest already exists")
    manifest = _manifest_copy(manifest_without_inventory)
    if (
        manifest.get("schema_version") != local_identity.RELEASE_MANIFEST_SCHEMA
        or "inventory" in manifest
    ):
        raise ReleaseBuildError("exact manifest input must be inventory-free v2")
    inventory = build_exact_file_inventory(root)
    resources = manifest.get("resources")
    content = manifest.get("content")
    if not isinstance(resources, dict) or not isinstance(content, dict):
        raise ReleaseBuildError("exact manifest resources/content must be objects")
    inventory_hash = local_identity.identity_sha256(inventory)
    if resources.get("inventory_sha256") not in {None, inventory_hash}:
        raise ReleaseBuildError(
            "caller resource hash differs from exact candidate inventory"
        )
    resources["inventory_sha256"] = inventory_hash
    content_hash_fields = {
        "source_inventory_sha256",
        "ir_sha256",
        "knowledge_sha256",
        "search_sha256",
    }
    if any(type(content.get(field)) is not str for field in content_hash_fields):
        raise ReleaseBuildError("exact knowledge component hashes are incomplete")
    page_projection = local_identity.identity_sha256(
        {
            "schema_version": "qrh-page-projection-input/v1",
            "snapshot_id": content.get("snapshot_id"),
            "source_inventory_sha256": content["source_inventory_sha256"],
            "ir_sha256": content["ir_sha256"],
            "knowledge_sha256": content["knowledge_sha256"],
            "presentation": content.get("presentation"),
        }
    )
    if content.get("page_projection_sha256") not in {None, page_projection}:
        raise ReleaseBuildError("page projection input identity differs")
    content["page_projection_sha256"] = page_projection
    if content.get("mcp_sha256") not in {None, content["search_sha256"]}:
        raise ReleaseBuildError("MCP identity differs from the sealed search artifact")
    content["mcp_sha256"] = content["search_sha256"]
    manifest["inventory"] = inventory
    try:
        validated = local_identity.validate_release_manifest(manifest)
    except (TypeError, ValueError) as error:
        raise ReleaseBuildError(
            "exact release manifest violates the v2 identity contract"
        ) from error
    payload = local_identity.canonical_bytes(validated)
    temporary = root / f".release_manifest.partial-{uuid4().hex}"
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, manifest_path)
    except BaseException:
        if temporary.exists():
            temporary.unlink()
        raise
    written = json.loads(manifest_path.read_text(encoding="utf-8"))
    confirmed = local_identity.validate_release_manifest(written)
    if local_identity.canonical_bytes(confirmed) != payload:
        raise ReleaseBuildError("exact release manifest changed while sealing")
    files = inventory["files"]
    assert isinstance(files, list)
    return SealedRelease(
        root=root,
        release_id=str(confirmed["release_id"]),
        manifest_sha256=local_identity.identity_sha256(confirmed),
        file_count=len(files),
        total_bytes=sum(int(item["bytes"]) for item in files),
    )


def seal_release(
    *, candidate_root: Path, manifest_without_inventory: Mapping[str, object]
) -> SealedRelease:
    """Add the only manifest after hashing every other candidate file.

    The caller supplies semantic component identities.  This function owns the
    whole-tree inventory and its resources binding, preventing a manifest from
    claiming a closure different from the candidate bytes.
    """

    root = Path(candidate_root).resolve(strict=True)
    manifest_path = root / "release_manifest.json"
    if manifest_path.exists():
        raise ReleaseBuildError("immutable release manifest already exists")
    manifest = _manifest_copy(manifest_without_inventory)
    if not isinstance(manifest, dict) or "inventory" in manifest:
        raise ReleaseBuildError("manifest input must not predefine inventory")
    inventory = build_file_inventory(root)
    inventory_hash = manifest_sha256(inventory)
    resources = manifest.get("resources")
    if not isinstance(resources, dict):
        raise ReleaseBuildError("manifest resources must be an object")
    claimed = resources.get("inventory_sha256")
    if claimed not in (None, inventory_hash):
        raise ReleaseBuildError("caller resource hash differs from real candidate inventory")
    resources["inventory_sha256"] = inventory_hash
    manifest["inventory"] = inventory
    application = manifest.get("application")
    content = manifest.get("content")
    if not isinstance(application, dict) or not isinstance(content, dict):
        raise ReleaseBuildError("manifest application/content must be objects")
    if application.get("source_kind", "git") == "git":
        artifact_path = root / SEARCH_ARTIFACT_RELATIVE_PATH
        try:
            artifact_bytes = artifact_path.read_bytes()
            artifact_value = json.loads(artifact_bytes.decode("utf-8"))
            validate_search_artifact(
                artifact_value,
                expected_snapshot_id=str(content.get("snapshot_id", "")),
            )
        except (OSError, UnicodeError, json.JSONDecodeError, MirrorError) as error:
            raise ReleaseBuildError("Git release lacks a valid MCP search artifact") from error
        actual_search_hash = hashlib.sha256(artifact_bytes).hexdigest()
        if content.get("search_sha256") != actual_search_hash:
            raise ReleaseBuildError("manifest search hash differs from candidate artifact")
    try:
        validate_release_manifest(manifest)
    except (TypeError, ValueError) as error:
        raise ReleaseBuildError("release manifest violates the identity contract") from error
    payload = canonical_manifest_bytes(manifest)
    temporary = root / f".release_manifest.partial-{uuid4().hex}"
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, manifest_path)
    except BaseException:
        if temporary.exists():
            temporary.unlink()
        raise
    # Re-read both manifest and complete tree through the deployment contract's
    # exact representation before returning the release identity.
    written = json.loads(manifest_path.read_text(encoding="utf-8"))
    validate_release_manifest(written)
    if canonical_manifest_bytes(written) != payload:
        raise ReleaseBuildError("release manifest changed while being sealed")
    files = inventory["files"]
    assert isinstance(files, list)
    return SealedRelease(
        root=root,
        release_id=str(written["release_id"]),
        manifest_sha256=manifest_sha256(written),
        file_count=len(files),
        total_bytes=sum(int(item["bytes"]) for item in files),
    )


__all__ = [
    "INVENTORY_SCHEMA",
    "ReleaseBuildError",
    "PreparedKnowledgeSearch",
    "SealedRelease",
    "build_file_inventory",
    "build_exact_file_inventory",
    "prepare_knowledge_search",
    "seal_knowledge_release",
    "seal_exact_release",
    "seal_release",
]
