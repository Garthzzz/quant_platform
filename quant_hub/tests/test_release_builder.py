from __future__ import annotations

from copy import deepcopy
import json
import hashlib
from pathlib import Path
import tempfile
import unittest

from quant_hub.ops.deployment import DeploymentController
from quant_hub.ops.release_builder import ReleaseBuildError, seal_release
from quant_hub.ops.release_identity import validate_release_manifest
from quant_hub.knowledge import ReferenceCompiler
from quant_hub.knowledge_mcp.mirror import build_search_artifact


def base_manifest(
    release_id: str = "release-test",
    *,
    search_sha256: str = "5" * 64,
    snapshot_id: str = "snapshot-test",
) -> dict[str, object]:
    return {
        "schema_version": "qrh-release-manifest/v1",
        "release_id": release_id,
        "built_at": "2026-08-21T10:00:00+08:00",
        "application": {
            "commit_sha": "a" * 40,
            "tracked_tree_sha256": "1" * 64,
            "build_tool_version": "release-builder-tests/v1",
        },
        "content": {
            "snapshot_id": snapshot_id,
            "source_inventory_sha256": "2" * 64,
            "ir_sha256": "3" * 64,
            "knowledge_sha256": "4" * 64,
            "search_sha256": search_sha256,
            "knowledge_enrichment": {"status": "pending"},
        },
        "resources": {},
        "state": {"compatibility": {"comments": {"read": [2], "write": [2]}}},
        "recovery": {
            "compatibility": {
                "checkpoint_manifest_schemas": ["qrh-checkpoint-manifest/v1"],
                "restore_protocol_versions": ["qrh-restore/v1"],
            }
        },
    }


class ReleaseBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate"
        self.candidate.mkdir()
        (self.candidate / "app.py").write_text("print('ok')\n", encoding="utf-8")
        empty_sources = self.root / "empty-sources"
        empty_sources.mkdir()
        report = ReferenceCompiler().compile(empty_sources)
        assert report.candidate_snapshot is not None
        self.snapshot_id = report.candidate_snapshot.snapshot_id
        artifact = build_search_artifact(report.candidate_snapshot)
        artifact_path = self.candidate / "content" / "mcp_search.json"
        artifact_path.parent.mkdir()
        artifact_path.write_bytes(artifact)
        self.search_sha256 = hashlib.sha256(artifact).hexdigest()

    def test_sealed_manifest_binds_real_tree_and_deployment_accepts_it(self) -> None:
        sealed = seal_release(
            candidate_root=self.candidate,
            manifest_without_inventory=base_manifest(
                search_sha256=self.search_sha256, snapshot_id=self.snapshot_id
            ),
        )
        self.assertEqual(2, sealed.file_count)
        manifest = json.loads(
            (self.candidate / "release_manifest.json").read_text(encoding="utf-8")
        )
        validate_release_manifest(manifest)
        controller = DeploymentController(self.root / "D-root")
        partial = controller.partial_path("release-test")
        self.candidate.rename(partial)
        final, digest = controller.finalize_candidate(
            "release-test", state_compatibility_probe=lambda _: True
        )
        self.assertEqual(sealed.manifest_sha256, digest)
        self.assertTrue(final.is_dir())

    def test_existing_manifest_or_false_resource_hash_fails_closed(self) -> None:
        invalid = deepcopy(
            base_manifest(search_sha256=self.search_sha256, snapshot_id=self.snapshot_id)
        )
        invalid["resources"]["inventory_sha256"] = "9" * 64
        with self.assertRaisesRegex(ReleaseBuildError, "resource hash"):
            seal_release(candidate_root=self.candidate, manifest_without_inventory=invalid)
        self.assertFalse((self.candidate / "release_manifest.json").exists())
        seal_release(
            candidate_root=self.candidate,
            manifest_without_inventory=base_manifest(
                search_sha256=self.search_sha256, snapshot_id=self.snapshot_id
            ),
        )
        with self.assertRaisesRegex(ReleaseBuildError, "already exists"):
            seal_release(
                candidate_root=self.candidate,
                manifest_without_inventory=base_manifest(
                    search_sha256=self.search_sha256, snapshot_id=self.snapshot_id
                ),
            )

    def test_git_release_rejects_missing_or_tampered_search_artifact(self) -> None:
        artifact = self.candidate / "content" / "mcp_search.json"
        artifact.unlink()
        with self.assertRaisesRegex(ReleaseBuildError, "valid MCP search artifact"):
            seal_release(
                candidate_root=self.candidate,
                manifest_without_inventory=base_manifest(
                    search_sha256=self.search_sha256, snapshot_id=self.snapshot_id
                ),
            )
        artifact.write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(ReleaseBuildError, "valid MCP search artifact"):
            seal_release(
                candidate_root=self.candidate,
                manifest_without_inventory=base_manifest(
                    search_sha256=self.search_sha256, snapshot_id=self.snapshot_id
                ),
            )


if __name__ == "__main__":
    unittest.main()
