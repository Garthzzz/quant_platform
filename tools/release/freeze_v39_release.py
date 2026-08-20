"""Seal the pre-Git V39 broadcast as an explicit legacy release identity."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from quant_hub.ops.release_builder import seal_release
from quant_hub.ops.release_identity import canonical_manifest_bytes


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _semantic_hash(value: object) -> str:
    return hashlib.sha256(canonical_manifest_bytes(value)).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--source-zip", type=Path, required=True)
    parser.add_argument(
        "--release-id", default="v39-baseline-20260731-hotfix1"
    )
    args = parser.parse_args()

    candidate = args.candidate_root.resolve(strict=True)
    source_zip = args.source_zip.resolve(strict=True)
    package_path = candidate / "deployment_manifest.json"
    package_bytes = package_path.read_bytes()
    package = json.loads(package_bytes.decode("utf-8"))
    if package.get("schema_version") != "qrh-company-broadcast-package/v1":
        raise RuntimeError("candidate is not a V39 broadcast package")
    deployment_id = package.get("deployment_id")
    if deployment_id != "quant-hub-v39-company-broadcast-20260731-hotfix1":
        raise RuntimeError("candidate deployment identity is not the frozen V39 baseline")
    trees = package["trees"]
    databases = package["databases"]
    code_tree = trees["runtime_contract/code/src"]
    source_binding = {
        "archive_tree": trees["reference/archive"],
        "archive_database": databases["archive.sqlite3"],
    }
    deterministic_render_binding = {
        "code_tree": code_tree,
        "archive_source": source_binding,
        "mode": "legacy_v39_presentation",
    }
    knowledge_binding = {
        "mode": "legacy_v39_no_semantic_enrichment",
        "archive_database_logical_sha256": databases["archive.sqlite3"][
            "logical_sha256"
        ],
    }
    search_binding = {
        "mode": "legacy_v39_sqlite_search",
        "archive_database": databases["archive.sqlite3"],
        "platform_database": databases["platform.sqlite3"],
    }
    manifest = {
        "schema_version": "qrh-release-manifest/v1",
        "release_id": args.release_id,
        "built_at": package["built_at"],
        "application": {
            "source_kind": "legacy_broadcast",
            "commit_sha": "0" * 40,
            "tracked_tree_sha256": code_tree["tree_sha256"],
            "build_tool_version": "qrh-freeze-v39/v1",
            "source_archive_sha256": _hash_file(source_zip),
            "source_package_manifest_sha256": hashlib.sha256(
                package_bytes
            ).hexdigest(),
            "legacy_deployment_id": deployment_id,
        },
        "content": {
            "snapshot_id": "v39-content-20260731-hotfix1",
            "source_inventory_sha256": _semantic_hash(source_binding),
            "ir_sha256": _semantic_hash(deterministic_render_binding),
            "knowledge_sha256": _semantic_hash(knowledge_binding),
            "search_sha256": _semantic_hash(search_binding),
            "knowledge_enrichment": {
                "status": "not_applicable",
                "reason": "legacy_v39_baseline",
            },
            "component_bindings": {
                "source": source_binding,
                "deterministic_render": deterministic_render_binding,
                "knowledge": knowledge_binding,
                "search": search_binding,
            },
        },
        "resources": {},
        "state": {
            "compatibility": {
                "comments": {"read": [1, 2], "write": [1, 2]},
                "research_workspace": {"read": [1, 2, 3], "write": [1, 2, 3]},
                "rollback_policy": "expand_only_no_down_migration",
            }
        },
        "recovery": {
            "compatibility": {
                "checkpoint_manifest_schemas": ["qrh-checkpoint-manifest/v1"],
                "restore_protocol_versions": ["qrh-restore/v1"],
            }
        },
    }
    sealed = seal_release(
        candidate_root=candidate, manifest_without_inventory=manifest
    )
    print(
        json.dumps(
            {
                "release_id": sealed.release_id,
                "manifest_sha256": sealed.manifest_sha256,
                "file_count": sealed.file_count,
                "total_bytes": sealed.total_bytes,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
