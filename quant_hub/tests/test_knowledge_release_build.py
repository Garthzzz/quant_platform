from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from quant_hub.app import create_app
from quant_hub.knowledge import ReferenceCompiler
from quant_hub.knowledge.semantic import (
    SemanticJobStore,
    build_enriched_snapshot,
    extract_source_explicit,
)
from quant_hub.knowledge_mcp.mirror import (
    SEARCH_ARTIFACT_RELATIVE_PATH,
    validate_search_artifact,
)
from quant_hub.ops.release_builder import (
    ReleaseBuildError,
    prepare_knowledge_search,
    seal_knowledge_release,
)
from quant_hub.generic_research import (
    GenericReleaseError,
    load_generic_catalog_from_release,
)
from tests.helpers import SettingsTestCase


def _manifest(snapshot_id: str) -> dict[str, object]:
    return {
        "schema_version": "qrh-release-manifest/v1",
        "release_id": "knowledge-release-test",
        "built_at": "2026-08-21T12:00:00Z",
        "application": {
            "commit_sha": "a" * 40,
            "tracked_tree_sha256": "1" * 64,
            "build_tool_version": "knowledge-release-tests/v1",
            "source_kind": "git",
        },
        "content": {
            "snapshot_id": snapshot_id,
            "source_inventory_sha256": None,
            "ir_sha256": None,
            "knowledge_sha256": None,
            "search_sha256": None,
            "knowledge_enrichment": {"status": "pending"},
        },
        "resources": {},
        "state": {"compatibility": {"comments": {"read": [2], "write": [2]}}},
    }


def _manifest_v2(snapshot_id: str) -> dict[str, object]:
    return {
        "schema_version": "qrh-release-manifest/v2",
        "release_id": "knowledge-release-test",
        "built_at": "2026-08-21T12:00:00Z",
        "application": {
            "source_kind": "git",
            "commit_sha": "a" * 40,
            "tracked_tree_sha256": "1" * 64,
            "build_tool_version": "knowledge-release-tests/v2",
            "provenance": {
                "builder": "knowledge-release-tests",
                "labels": ["exact-local-active-prior", "public-source"],
            },
        },
        "content": {
            "snapshot_id": snapshot_id,
            "source_inventory_sha256": None,
            "ir_sha256": None,
            "knowledge_sha256": None,
            "search_sha256": None,
            "page_projection_sha256": None,
            "mcp_sha256": None,
            "active_membership_sha256": "2" * 64,
            "knowledge_enrichment": {"status": "not_applicable"},
            "presentation": {"language": "zh-CN"},
        },
        "resources": {"inventory_sha256": None},
        "state": {
            "compatibility": {
                "comments": {"read": [2], "write": [2]},
                "research_workspace": {"read": [3], "write": [3]},
                "rollback_policy": "expand_only_no_down_migration",
            }
        },
    }


class KnowledgeReleaseBuildTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sources = self.root / "sources"
        self.sources.mkdir()
        (self.sources / "factor.md").write_text(
            "# 因子研究\n\n方法：使用 Rank IC 评估横截面因子\n\n限制：低 SNR 时排序不稳定\n",
            encoding="utf-8",
        )
        self.source_bytes = (self.sources / "factor.md").read_bytes()
        report = ReferenceCompiler().compile(self.sources)
        self.assertEqual("PASS", report.status)
        assert report.candidate_snapshot is not None
        self.base = report.candidate_snapshot
        self.store = SemanticJobStore(self.root / "state" / "semantic.sqlite3")
        extract_source_explicit(self.base, self.store)
        self.enriched = build_enriched_snapshot(self.base, self.store)

    def _source_objects(self, *extra: bytes) -> dict[str, bytes]:
        values = (self.source_bytes, *extra)
        return {hashlib.sha256(value).hexdigest(): value for value in values}

    def _candidate(self, name: str) -> Path:
        candidate = self.root / name
        candidate.mkdir()
        (candidate / "app.py").write_text("print('candidate')\n", encoding="utf-8")
        return candidate

    def test_production_builder_binds_exact_artifact_bytes_into_release(self) -> None:
        candidate = self._candidate("candidate")
        sealed = seal_knowledge_release(
            candidate_root=candidate,
            manifest_without_inventory=_manifest(self.enriched.snapshot_id),
            snapshot=self.base,
            enriched=self.enriched,
            source_objects=self._source_objects(),
        )
        artifact_path = candidate / SEARCH_ARTIFACT_RELATIVE_PATH
        artifact_bytes = artifact_path.read_bytes()
        artifact_hash = hashlib.sha256(artifact_bytes).hexdigest()
        artifact = json.loads(artifact_bytes)
        validate_search_artifact(
            artifact, expected_snapshot_id=self.enriched.snapshot_id
        )
        manifest = json.loads((candidate / "release_manifest.json").read_text("utf-8"))
        self.assertEqual(artifact_hash, manifest["content"]["search_sha256"])
        self.assertEqual(self.enriched.snapshot_id, manifest["content"]["snapshot_id"])
        self.assertEqual(
            hashlib.sha256(
                (candidate / "content" / "generic_knowledge.json").read_bytes()
            ).hexdigest(),
            manifest["content"]["knowledge_sha256"],
        )
        inventory = {row["path"]: row for row in manifest["inventory"]["files"]}
        self.assertEqual(artifact_hash, inventory[SEARCH_ARTIFACT_RELATIVE_PATH]["sha256"])
        self.assertEqual(64, len(sealed.manifest_sha256))

        # The same immutable inputs produce byte-identical artifacts even in a
        # second candidate tree; no release identity is embedded in the file.
        second = self._candidate("candidate-second")
        prepared = prepare_knowledge_search(
            candidate_root=second,
            manifest_without_inventory=_manifest(self.enriched.snapshot_id),
            snapshot=self.base,
            enriched=self.enriched,
            source_objects=self._source_objects(),
        )
        self.assertEqual(artifact_bytes, prepared.artifact_path.read_bytes())
        self.assertEqual(artifact_hash, prepared.artifact_sha256)

    def test_identity_mismatch_and_changed_snapshot_preserve_existing_artifact(self) -> None:
        candidate = self._candidate("candidate")
        manifest = _manifest(self.enriched.snapshot_id)
        prepared = prepare_knowledge_search(
            candidate_root=candidate,
            manifest_without_inventory=manifest,
            snapshot=self.base,
            enriched=self.enriched,
            source_objects=self._source_objects(),
        )
        original = prepared.artifact_path.read_bytes()

        wrong_claim = _manifest(self.enriched.snapshot_id)
        wrong_claim["content"]["search_sha256"] = "f" * 64
        with self.assertRaisesRegex(ReleaseBuildError, "search_sha256"):
            prepare_knowledge_search(
                candidate_root=candidate,
                manifest_without_inventory=wrong_claim,
                snapshot=self.base,
                enriched=self.enriched,
                source_objects=self._source_objects(),
            )
        self.assertEqual(original, prepared.artifact_path.read_bytes())

        (self.sources / "factor.md").write_text(
            "# 因子研究 v2\n\n方法：使用分组稳定性替代 Rank IC\n",
            encoding="utf-8",
        )
        revised_bytes = (self.sources / "factor.md").read_bytes()
        revised_report = ReferenceCompiler().compile(self.sources, previous=self.base)
        assert revised_report.candidate_snapshot is not None
        revised = revised_report.candidate_snapshot
        revised_enriched = build_enriched_snapshot(revised, self.store)
        historical_candidate = self._candidate("historical-source-root")
        with self.assertRaisesRegex(ReleaseBuildError, "immutable historical version"):
            prepare_knowledge_search(
                candidate_root=historical_candidate,
                manifest_without_inventory=_manifest(revised_enriched.snapshot_id),
                snapshot=revised,
                enriched=revised_enriched,
                source_root=self.sources,
            )
        self.assertFalse(
            (historical_candidate / "content" / "deterministic_snapshot.json").exists()
        )
        with self.assertRaisesRegex(ReleaseBuildError, "existing release closure differs"):
            prepare_knowledge_search(
                candidate_root=candidate,
                manifest_without_inventory=_manifest(revised_enriched.snapshot_id),
                snapshot=revised,
                enriched=revised_enriched,
                source_objects=self._source_objects(revised_bytes),
            )
        self.assertEqual(original, prepared.artifact_path.read_bytes())

    def test_snapshot_or_knowledge_authority_mismatch_writes_nothing(self) -> None:
        candidate = self._candidate("candidate")
        with self.assertRaisesRegex(ReleaseBuildError, "snapshot differs"):
            prepare_knowledge_search(
                candidate_root=candidate,
                manifest_without_inventory=_manifest("ksnap-not-current"),
                snapshot=self.base,
                enriched=self.enriched,
                source_objects=self._source_objects(),
            )
        self.assertFalse((candidate / SEARCH_ARTIFACT_RELATIVE_PATH).exists())
        with self.assertRaisesRegex(ReleaseBuildError, "knowledge_sha256"):
            prepare_knowledge_search(
                candidate_root=candidate,
                manifest_without_inventory={
                    **_manifest(self.enriched.snapshot_id),
                    "content": {
                        **_manifest(self.enriched.snapshot_id)["content"],
                        "knowledge_sha256": "e" * 64,
                    },
                },
                snapshot=self.base,
                enriched=self.enriched,
                source_objects=self._source_objects(),
            )
        self.assertFalse((candidate / SEARCH_ARTIFACT_RELATIVE_PATH).exists())


class GenericReleaseApplicationTests(SettingsTestCase):
    def _sealed_release(
        self, *, exact_v2: bool = False, incoming_partial: bool = False
    ) -> tuple[Path, bytes, str, str]:
        sources = self.root / "new-research"
        sources.mkdir()
        source = (
            "# 新增量化研究\n\n"
            "## 方法\n\n方法：使用 $RankIC$ 验证横截面稳定性。\n\n"
            "| 条件 | 值 |\n|---|---:|\n| 频率 | 日频 |\n\n"
            "```python\nscore = rank_ic(exposure, returns)\n```\n\n"
            "来源：https://example.org/research/rank-ic\n"
        ).encode("utf-8")
        (sources / "new-factor.md").write_bytes(source)
        report = ReferenceCompiler().compile(sources)
        assert report.candidate_snapshot is not None
        base = report.candidate_snapshot
        store = SemanticJobStore(self.root / "semantic-state" / "knowledge.sqlite3")
        extract_source_explicit(base, store)
        enriched = build_enriched_snapshot(base, store)
        release_name = (
            "knowledge-release-test.partial"
            if incoming_partial
            else "knowledge-release-test"
        )
        release = self.root / release_name
        release.mkdir()
        (release / "app.py").write_text("print('release')\n", encoding="utf-8")
        seal_knowledge_release(
            candidate_root=release,
            manifest_without_inventory=(
                _manifest_v2(enriched.snapshot_id)
                if exact_v2
                else _manifest(enriched.snapshot_id)
            ),
            snapshot=base,
            enriched=enriched,
            source_root=sources,
        )
        document_id, version_id = next(iter(base.active_membership.items()))
        return release, source, document_id, version_id

    def test_exact_v2_incoming_candidate_loads_after_full_inventory_verification(self) -> None:
        release, source, document_id, version_id = self._sealed_release(
            exact_v2=True,
            incoming_partial=True,
        )

        catalog = load_generic_catalog_from_release(release)

        self.assertEqual(source, catalog.source_bytes(document_id, version_id))

    def test_app_factory_loads_new_document_from_finalized_release_without_route_code(self) -> None:
        release, source, document_id, version_id = self._sealed_release()
        catalog = load_generic_catalog_from_release(release)
        self.assertEqual(source, catalog.source_bytes(document_id, version_id))
        with (
            patch(
                "quant_hub.archive.catalog.ArchivePresentation.default",
                return_value=Mock(research={}),
            ),
            patch(
                "quant_hub.archive.catalog.ArchiveChapterManifests.default",
                return_value=Mock(),
            ),
            patch(
                "quant_hub.archive.catalog.ArchiveCatalog.archive_link_index",
                return_value={},
            ),
        ):
            app = create_app(
                self.settings,
                {
                    "TESTING": True,
                    "SECRET_KEY": "release-loader-test",
                    "GENERIC_RESEARCH_RELEASE_ROOT": release,
                },
            )
        response = app.test_client().get(f"/knowledge/research/{document_id}/")
        self.assertEqual(200, response.status_code)
        html = response.get_data(as_text=True)
        self.assertIn("新增量化研究", html)
        self.assertIn("table-scroll", html)
        self.assertIn("<pre", html)
        self.assertIn("https://example.org/research/rank-ic", html)
        self.assertIn("已验证知识", html)
        self.assertIn("使用 $RankIC$ 验证横截面稳定性", html)
        downloaded = app.test_client().get(
            f"/knowledge/research/{document_id}/versions/{version_id}/source"
        )
        self.assertEqual(source, downloaded.data)

    def test_corrupt_release_fails_closed_and_default_app_remains_legacy_only(self) -> None:
        release, _source, document_id, _version_id = self._sealed_release()
        object_path = next((release / "content" / "source_objects" / "sha256").iterdir())
        object_path.write_bytes(object_path.read_bytes() + b"tampered")
        with self.assertRaisesRegex(GenericReleaseError, "inventory differs"):
            load_generic_catalog_from_release(release)
        with (
            patch(
                "quant_hub.archive.catalog.ArchivePresentation.default",
                return_value=Mock(research={}),
            ),
            patch(
                "quant_hub.archive.catalog.ArchiveChapterManifests.default",
                return_value=Mock(),
            ),
            patch(
                "quant_hub.archive.catalog.ArchiveCatalog.archive_link_index",
                return_value={},
            ),
        ):
            app = create_app(self.settings, {"TESTING": True})
        self.assertNotIn("generic_research_catalog", app.extensions)
        self.assertEqual(
            404,
            app.test_client().get(f"/knowledge/research/{document_id}/").status_code,
        )


if __name__ == "__main__":
    unittest.main()
