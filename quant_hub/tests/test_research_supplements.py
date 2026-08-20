from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from quant_hub.presentation.supplements import (
    ResearchSupplementError,
    SupplementalResearchDocuments,
)


class SupplementalResearchDocumentsTests(unittest.TestCase):
    def test_default_q2_experiment_pages_are_hash_bound_and_renderable(self) -> None:
        supplements = SupplementalResearchDocuments.default()
        rows = supplements.documents_for(
            "q2-low-snr-neural-selection-factory", "res_test"
        )
        self.assertEqual(
            [
                "yao-experiment-overview",
                "training-temperature-early-stopping",
                "depth-parameter-budget",
                "ranking-objective-comparison",
            ],
            [row["supplement_id"] for row in rows],
        )
        page = supplements.document_for(
            "q2-low-snr-neural-selection-factory",
            "res_test",
            "ranking-objective-comparison",
        )
        self.assertIsNotNone(page)
        assert page is not None
        self.assertIn("50 / 50", page["rendered_html"])
        self.assertIn("/api/v1/archive/assets/q2-yao-loss-rankic", page["rendered_html"])
        self.assertTrue(page["toc"])
        self.assertTrue(page["is_supplement"])
        workspace_bindings = supplements.workspace_page_bindings(
            {"q2-low-snr-neural-selection-factory": "res_test"}
        )
        overview_path = (
            "02_低信噪比选股模型训练体系/05_实证结果与研究回验/"
            "01_截面选股训练动力学实证/01_研究设计、证据边界与总体结论.md"
        ).casefold()
        self.assertEqual(
            (
                "res_test",
                None,
                "/research/res_test/supplements/yao-experiment-overview",
            ),
            workspace_bindings[overview_path],
        )
        self.assertEqual(4, len(workspace_bindings))
        linked = supplements.link_workspace_updates(
            [
                {
                    "title": "Pearson IC 与可微排序目标对照",
                    "source_relative_path": (
                        "02_低信噪比选股模型训练体系/05_实证结果与研究回验/"
                        "01_截面选股训练动力学实证/04_Pearson_IC与可微排序目标对照.md"
                    ),
                    "page_url": "/?node=fallback",
                },
                {
                    "title": "未发布研究",
                    "source_relative_path": "08_未来研究/01_草稿.md",
                    "page_url": "/?node=draft",
                },
                {
                    "title": "实证结果与研究回验",
                    "source_relative_path": (
                        "02_低信噪比选股模型训练体系/05_实证结果与研究回验"
                    ),
                    "page_url": "/?node=experiment-directory",
                },
            ],
            {"q2-low-snr-neural-selection-factory": "res_test"},
        )
        self.assertEqual(
            (
                "/research/res_test/supplements/"
                "ranking-objective-comparison"
            ),
            linked[0]["page_url"],
        )
        self.assertEqual("/?node=draft", linked[1]["page_url"])
        self.assertFalse(linked[1]["has_published_page"])
        self.assertEqual(
            "/research/res_test/supplements/yao-experiment-overview",
            linked[2]["page_url"],
        )
        self.assertTrue(linked[2]["has_published_page"])

    def test_resource_drift_is_rejected_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            resource = root / "page.md"
            resource.write_text("# reviewed\n", encoding="utf-8", newline="\n")
            source = resource.read_bytes()
            manifest = {
                "schema_version": "qrh-research-supplements/v1",
                "documents": [
                    {
                        "research_slug": "q2-low-snr-neural-selection-factory",
                        "supplement_id": "reviewed-page",
                        "document_key": "reviewed-page",
                        "display_title": "Reviewed page",
                        "group_title": "Evidence",
                        "workspace_relative_path": "01_研究/01_页面.md",
                        "resource": "page.md",
                        "sort_key": 10,
                        "bytes": len(source),
                        "sha256": hashlib.sha256(source).hexdigest(),
                    }
                ],
            }
            manifest_path = root / "manifest.json"
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False), encoding="utf-8"
            )
            SupplementalResearchDocuments(manifest_path)
            resource.write_text("# drifted\n", encoding="utf-8", newline="\n")
            with self.assertRaisesRegex(
                ResearchSupplementError, "resource identity changed"
            ):
                SupplementalResearchDocuments(manifest_path)


if __name__ == "__main__":
    unittest.main()
