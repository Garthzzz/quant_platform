from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

from typer.testing import CliRunner

from quant_hub.archive.catalog import ArchiveCatalog, ArchiveMappingConflict, ArchiveNotFound
from quant_hub.archive.contracts import ArchiveDocumentInput, ArchiveReleaseInput
from quant_hub.archive.discovery import ArchiveDiscoveryScanner
from quant_hub.archive.database import archive_connection
from quant_hub.cli import app
from quant_hub.platform.db import connect_database
from tests.helpers import SettingsTestCase


class ArchiveDiscoveryTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.first = self.archive / "研究一.md"
        self.second = self.archive / "专题" / "研究二.markdown"
        self.second.parent.mkdir()
        self.first.write_text("# 研究一\n\n第一版。\n", encoding="utf-8")
        self.second.write_text("# 研究二\n\n独立内容。\n", encoding="utf-8")
        (self.archive / "忽略.txt").write_text("不是 Markdown", encoding="utf-8")

    @staticmethod
    def _by_path(report):
        return {item.relative_path: item for item in report.items}

    def _platform_counts(self) -> tuple[int, int, int, int]:
        connection = connect_database(self.settings.database_path)
        try:
            return tuple(
                connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                for table in ("object_blob", "source_location", "pipeline_run", "outbox_event")
            )
        finally:
            connection.close()

    def test_first_repeat_and_changed_scans_reuse_snapshot_registry_idempotently(self) -> None:
        before = {path: path.read_bytes() for path in (self.first, self.second)}
        scanner = ArchiveDiscoveryScanner(self.settings)

        first = scanner.scan()
        self.assertEqual("PASS", first.status)
        self.assertEqual(2, first.counts.markdown_candidates)
        self.assertEqual((2, 0, 0), (first.counts.discovered, first.counts.changed, first.counts.unchanged))
        self.assertEqual(2, first.counts.pending_mapping)
        self.assertTrue(all(item.mapping_state == "unmapped" for item in first.items))
        first_ids = {
            item.relative_path: (item.object_id, item.source_location_id, item.run_id)
            for item in first.items
        }
        first_counts = self._platform_counts()

        repeated = scanner.scan()
        self.assertEqual((0, 0, 2), (repeated.counts.discovered, repeated.counts.changed, repeated.counts.unchanged))
        self.assertEqual(
            first_ids,
            {
                item.relative_path: (item.object_id, item.source_location_id, item.run_id)
                for item in repeated.items
            },
        )
        self.assertEqual(first_counts, self._platform_counts())

        self.first.write_text("# 研究一\n\n第二版，字节身份已变化。\n", encoding="utf-8")
        changed = scanner.scan()
        changed_by_path = self._by_path(changed)
        self.assertEqual("changed", changed_by_path["研究一.md"].observation_state)
        self.assertEqual("pending_mapping", changed_by_path["研究一.md"].workflow_state)
        self.assertEqual("unchanged", changed_by_path["专题/研究二.markdown"].observation_state)
        self.assertNotEqual(first_ids["研究一.md"][0], changed_by_path["研究一.md"].object_id)
        changed_counts = self._platform_counts()
        self.assertEqual(tuple(value + 1 for value in first_counts), changed_counts)

        repeated_changed = scanner.scan()
        self.assertEqual(2, repeated_changed.counts.unchanged)
        self.assertEqual(changed_counts, self._platform_counts())
        self.assertEqual(before[self.second], self.second.read_bytes())

    def test_only_exact_verified_manifest_mapping_is_mapped(self) -> None:
        release = ArchiveReleaseInput(
            research_slug="research-one",
            display_title="研究一",
            release_key="first-release",
            documents=(
                ArchiveDocumentInput(
                    document_slug="main",
                    document_role="primary",
                    source_path="研究一.md",
                    **self.approved_source_fields("研究一.md"),
                    navigation_role="primary",
                    sort_key=0,
                    mapping_authority_urn="urn:test:approved-archive-mapping",
                    mapping_note="测试中显式审核通过的 source→document 映射。",
                ),
            ),
            activate=False,
        )
        catalog = ArchiveCatalog(self.settings)
        staged = catalog.publish_release(release)
        self.assertEqual([], catalog.list_research())
        with self.assertRaises(ArchiveNotFound):
            catalog.research_page(staged.research_id)

        report = ArchiveDiscoveryScanner(self.settings).scan()
        by_path = self._by_path(report)
        mapped = by_path["研究一.md"]
        self.assertEqual(("mapped", "mapped"), (mapped.mapping_state, mapped.workflow_state))
        self.assertEqual(1, len(mapped.mappings))
        self.assertEqual("verified", mapped.mappings[0].mapping_status)
        self.assertEqual("research-one", mapped.mappings[0].research_slug)
        self.assertEqual("main", mapped.mappings[0].document_slug)
        self.assertEqual("pending_mapping", by_path["专题/研究二.markdown"].workflow_state)

        # 相同路径的新字节是新的 source_location；旧版本的显式映射不得被路径继承。
        self.first.write_text("# 研究一\n\n未经审核的新版本。\n", encoding="utf-8")
        changed = self._by_path(ArchiveDiscoveryScanner(self.settings).scan())["研究一.md"]
        self.assertEqual("changed", changed.observation_state)
        self.assertEqual(("unmapped", "pending_mapping"), (changed.mapping_state, changed.workflow_state))
        self.assertEqual((), changed.mappings)

    def test_scan_approved_identity_cannot_be_rebound_to_changed_path_bytes(self) -> None:
        first_report = ArchiveDiscoveryScanner(self.settings).scan()
        approved = self._by_path(first_report)["研究一.md"]
        release = ArchiveReleaseInput(
            research_slug="frozen-research-one",
            display_title="冻结身份研究一",
            release_key="frozen-v1",
            documents=(
                ArchiveDocumentInput(
                    document_slug="main",
                    document_role="primary",
                    source_path=approved.relative_path,
                    approved_origin_uri=approved.origin_uri,
                    approved_object_urn=f"qrh:object:{approved.object_id}",
                    approved_content_sha256=approved.sha256,
                    approved_bytes=approved.bytes,
                    navigation_role="primary",
                    sort_key=0,
                    mapping_authority_urn="qrh:review:frozen-mapping-v1",
                    mapping_note="审核只批准 scanner 观察到的 v1 字节身份。",
                ),
            ),
            activate=False,
        )
        self.first.write_text("# 研究一\n\n审核后发生变化的 v2。\n", encoding="utf-8")
        with self.assertRaisesRegex(ArchiveMappingConflict, "approved discovery identity"):
            ArchiveCatalog(self.settings).publish_release(release)
        with archive_connection(self.settings) as connection:
            self.assertEqual(0, connection.execute("SELECT count(*) FROM research").fetchone()[0])
        changed = self._by_path(ArchiveDiscoveryScanner(self.settings).scan())["研究一.md"]
        # fail-closed apply 已将当前 v2 字节登记到 A1；再次扫描在 registry 层不变，
        # 但它没有继承 v1 映射，也没有创建 research。
        self.assertEqual("unchanged", changed.observation_state)
        self.assertEqual("pending_mapping", changed.workflow_state)

    def test_invalid_utf8_is_reported_and_never_registered_or_rewritten(self) -> None:
        invalid = self.archive / "非法编码.md"
        invalid_bytes = b"# invalid\n\xff\xfe"
        invalid.write_bytes(invalid_bytes)

        report = ArchiveDiscoveryScanner(self.settings).scan()
        self.assertEqual("PARTIAL", report.status)
        self.assertEqual(3, report.counts.markdown_candidates)
        self.assertEqual(2, report.counts.processed)
        self.assertEqual(1, report.counts.errors)
        issue = next(issue for issue in report.issues if issue.relative_path == "非法编码.md")
        self.assertEqual("source_boundary_rejected", issue.issue_code)
        self.assertEqual("SourceBoundaryError", issue.error_type)
        self.assertIn("UTF-8", issue.detail)
        self.assertEqual(invalid_bytes, invalid.read_bytes())
        connection = connect_database(self.settings.database_path)
        try:
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT count(*) FROM source_location WHERE observed_path=?",
                    ("非法编码.md",),
                ).fetchone()[0],
            )
        finally:
            connection.close()

    def test_reparse_directory_is_reported_and_outside_markdown_is_not_read(self) -> None:
        outside = self.project / "outside-archive"
        outside.mkdir()
        outside_source = outside / "outside.md"
        outside_bytes = b"# outside\n"
        outside_source.write_bytes(outside_bytes)
        reparse = self.archive / "越界入口"
        if os.name == "nt":
            completed = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(reparse), str(outside)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr or completed.stdout)
        else:
            os.symlink(outside, reparse, target_is_directory=True)
        try:
            report = ArchiveDiscoveryScanner(self.settings).scan()
            self.assertEqual("PARTIAL", report.status)
            issue = next(issue for issue in report.issues if issue.relative_path == "越界入口")
            self.assertEqual("reparse_rejected", issue.issue_code)
            self.assertNotIn("越界入口/outside.md", {item.relative_path for item in report.items})
            self.assertEqual(outside_bytes, outside_source.read_bytes())
        finally:
            if os.path.lexists(reparse):
                if os.name == "nt":
                    os.rmdir(reparse)
                else:
                    reparse.unlink()

    def test_report_is_plain_json_serializable_and_documents_no_inference_policy(self) -> None:
        report = ArchiveDiscoveryScanner(self.settings).scan()
        payload = report.to_dict()
        self.assertEqual("archive-discovery-report/v1", payload["schema_version"])
        self.assertEqual("explicit_verified_manifest_required", payload["mapping_policy"])
        self.assertEqual(2, payload["counts"]["pending_mapping"])
        self.assertEqual("pending_mapping", payload["items"][0]["workflow_state"])

    def test_archive_scan_cli_emits_versioned_auditable_json(self) -> None:
        common = [
            "--project-root",
            str(self.project),
            "--archive-root",
            str(self.archive),
            "--var-root",
            str(self.var),
        ]
        runner = CliRunner()
        first = runner.invoke(app, ["archive", "scan", *common])
        self.assertEqual(0, first.exit_code, first.output)
        first_payload = json.loads(first.stdout)
        self.assertEqual("qrh-cli-envelope/v1", first_payload["schema_version"])
        self.assertEqual("PASS", first_payload["status"])
        self.assertEqual("archive-discovery-report/v1", first_payload["report"]["schema_version"])
        self.assertEqual(2, first_payload["report"]["counts"]["discovered"])
        self.assertEqual(2, first_payload["report"]["counts"]["pending_mapping"])

        repeated = runner.invoke(app, ["archive", "scan", *common])
        self.assertEqual(0, repeated.exit_code, repeated.output)
        self.assertEqual(2, json.loads(repeated.stdout)["report"]["counts"]["unchanged"])

        (self.archive / "bad.md").write_bytes(b"# bad\n\xff")
        partial = runner.invoke(app, ["archive", "scan", *common])
        self.assertEqual(3, partial.exit_code, partial.output)
        partial_payload = json.loads(partial.stdout)
        self.assertEqual("PARTIAL", partial_payload["status"])
        self.assertEqual(1, partial_payload["report"]["counts"]["errors"])
        self.assertNotIn("Traceback", partial.output)
