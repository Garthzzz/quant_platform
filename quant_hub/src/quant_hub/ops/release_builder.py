"""Seal a complete candidate tree with one immutable release manifest."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Mapping
from uuid import uuid4

from quant_hub.runtime_seal import RuntimeSealError, safe_tree_file_state

from .release_identity import (
    canonical_manifest_bytes,
    manifest_sha256,
    validate_release_manifest,
)


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
    try:
        manifest = json.loads(canonical_manifest_bytes(manifest_without_inventory))
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise ReleaseBuildError("manifest input is not canonical JSON material") from error
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
    "SealedRelease",
    "build_file_inventory",
    "seal_release",
]
