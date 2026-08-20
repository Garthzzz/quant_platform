from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "quant_hub" / "tools" / "export_frontend_research_markdown.py"
SPEC = importlib.util.spec_from_file_location("export_frontend_research_markdown", TOOL_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import contract guard
    raise RuntimeError("cannot load research revision exporter")
EXPORTER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = EXPORTER
SPEC.loader.exec_module(EXPORTER)

REPORT_TOOL_PATH = ROOT / "quant_hub" / "tools" / "report_research_revision_changes.py"
REPORT_SPEC = importlib.util.spec_from_file_location(
    "report_research_revision_changes", REPORT_TOOL_PATH
)
if REPORT_SPEC is None or REPORT_SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("cannot load research revision change reporter")
REPORTER = importlib.util.module_from_spec(REPORT_SPEC)
sys.modules[REPORT_SPEC.name] = REPORTER
REPORT_SPEC.loader.exec_module(REPORTER)


class ResearchRevisionExporterTests(unittest.TestCase):
    def test_safe_component_is_readable_and_windows_safe(self) -> None:
        self.assertEqual("_CON", EXPORTER.safe_component("CON", max_chars=20))
        self.assertEqual(
            "目标：风险／收益？",
            EXPORTER.safe_component("目标:风险/收益?", max_chars=20),
        )
        shortened = EXPORTER.safe_component("很长的研究标题" * 20, max_chars=24)
        self.assertLessEqual(len(shortened), 24)
        self.assertRegex(shortened, r"…-[0-9a-f]{8}$")

    def test_heading_projection_matches_display_and_skips_fences(self) -> None:
        presentation = {
            "heading_overrides_by_path": {
                "Q5/example.md": {"第二章：旧标题": "第二章：专业标题"}
            },
            "heading_overrides": {},
            "visible_text_overrides": {},
            "heading_token_overrides": {"Q5": "序列表征研究"},
        }
        source = (
            "# 第二章：旧标题\r\n\r\n"
            "## Q5 方法\r\n\r\n"
            "```markdown\r\n# 第二章：旧标题\r\n```\r\n"
        )
        projected = EXPORTER.project_heading_labels(
            source, "Q5/example.md", presentation
        )
        self.assertIn("# 第二章：专业标题\n", projected)
        self.assertIn("## 序列表征研究 方法\n", projected)
        self.assertIn("```markdown\n# 第二章：旧标题\n```", projected)
        self.assertNotIn("\r", projected)

    def test_output_policy_rejects_protected_and_existing_roots(self) -> None:
        project = ROOT
        archive = project / "reference" / "archive"
        delivery = project / "quant_hub" / "var"
        with self.assertRaises(EXPORTER.RevisionWorkspaceError):
            EXPORTER.validate_roots(
                project_root=project,
                archive_root=archive,
                delivery_var=delivery,
                output_root=project / "reference" / "bad-output",
            )
        with tempfile.TemporaryDirectory(dir=project / "project_state") as directory:
            with self.assertRaises(EXPORTER.RevisionWorkspaceError):
                EXPORTER.validate_roots(
                    project_root=project,
                    archive_root=archive,
                    delivery_var=delivery,
                    output_root=Path(directory),
                )

    def test_page_header_declares_manual_only_sync(self) -> None:
        header = EXPORTER._page_header(
            {
                "page_id": "rpage_test",
                "page_title": "历史表示质量评价体系",
                "frontend_url": "/research/example",
                "sync_policy": "manual_review_only",
            }
        )
        self.assertTrue(header.startswith("<!-- QRH_RESEARCH_REVISION_COPY_V1\n"))
        self.assertIn("修改不会自动影响", header)
        self.assertIn('"sync_policy":"manual_review_only"', header)

    def test_change_reporter_detects_an_edit_without_writing(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "project_state") as directory:
            workspace = Path(directory)
            body = "# 初始研究稿\n"
            page = workspace / "01_专题" / "01_章节.md"
            page.parent.mkdir()
            page.write_text(
                EXPORTER._page_header(
                    {
                        "page_id": "rpage_test",
                        "page_title": "章节",
                        "frontend_url": "/research/test",
                        "sync_policy": "manual_review_only",
                    }
                )
                + body,
                encoding="utf-8",
                newline="\n",
            )
            manifest = {
                "research": [],
                "pages": [
                    {
                        "page_id": "rpage_test",
                        "page_title": "章节",
                        "frontend_url": "/research/test",
                        "workspace_relative_path": "01_专题/01_章节.md",
                        "exported_markdown_sha256": REPORTER.digest(body),
                    }
                ],
            }
            (workspace / "_导出清单.json").write_text(
                EXPORTER.canonical_json(manifest), encoding="utf-8", newline="\n"
            )
            self.assertEqual("CLEAN", REPORTER.report(workspace)["status"])
            page.write_text(
                page.read_text(encoding="utf-8") + "\n新增研究判断。\n",
                encoding="utf-8",
                newline="\n",
            )
            changed = REPORTER.report(workspace)
            self.assertEqual("CHANGED", changed["status"])
            self.assertEqual(1, changed["changed_page_count"])
            self.assertEqual("rpage_test", changed["changed_pages"][0]["page_id"])


if __name__ == "__main__":
    unittest.main()
