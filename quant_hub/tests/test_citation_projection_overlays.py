from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from quant_hub.presentation.citation_overlays import (
    CitationOverlayError,
    CitationOverlayRegistry,
)
from quant_hub.web.routes import (
    _select_non_overlapping_citations,
    _toc_with_numbering_semantics,
)


ROOT = Path(__file__).resolve().parents[2]
DOCUMENT_SHA256 = "e68a63a1883c24cf48de6d4b3f0a9030689feced99e02ea4ed9f33144ed4dc7a"


class CitationProjectionOverlayTests(unittest.TestCase):
    def test_q2_reviewed_markers_are_exact_and_complete(self) -> None:
        settings = SimpleNamespace(archive_root=ROOT / "reference" / "archive")
        registry = CitationOverlayRegistry(settings)
        overlays = registry.for_document(DOCUMENT_SHA256)

        self.assertEqual(31, len(overlays))
        markers = {(item.line_number, item.marker) for item in overlays}
        self.assertTrue(
            {
                (91, "Hochreiter 1997"),
                (91, "Keskar 2017"),
                (91, "Jastrzębski 2017"),
                (97, "Goodfellow-Vinyals-Saxe (2015)"),
                (97, "Garipov 2018"),
                (97, "Draxler 2018"),
                (97, "Sagun et al. (2017)"),
            }.issubset(markers)
        )
        source = (
            ROOT
            / "reference"
            / "archive"
            / "Q2_如何造一个好的工厂"
            / "低信噪比金融工程下神经网络选股训练工厂全维度优化研究.md"
        ).read_bytes()
        for item in overlays:
            self.assertEqual(
                item.marker.encode("utf-8"), source[item.byte_start : item.byte_end]
            )
            self.assertTrue(item.relation_summary_zh)

    def test_valid_exact_projection_beats_earlier_greedy_source_span(self) -> None:
        broad = SimpleNamespace(
            byte_start=10,
            byte_end=200,
            resolution_state="source-only",
            citation_id="broad",
        )
        exact_one = SimpleNamespace(
            byte_start=40,
            byte_end=60,
            resolution_state="valid",
            citation_id="exact-one",
        )
        exact_two = SimpleNamespace(
            byte_start=90,
            byte_end=110,
            resolution_state="valid",
            citation_id="exact-two",
        )

        selected = _select_non_overlapping_citations([broad, exact_two, exact_one])

        self.assertEqual([exact_one, exact_two], selected)

    def test_reviewed_overlay_external_link_schema_is_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = b"# Research\n\nPaper A\n"
            source_sha256 = hashlib.sha256(source).hexdigest()
            manifest = root / "overlay.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": "qrh-reviewed-citation-projection/v1",
                        "review_scope": "public-test-fixture",
                        "reviewed_at": "2026-08-22",
                        "documents": [
                            {
                                "source_path": "research.md",
                                "document_sha256": source_sha256,
                                "entries": [
                                    {
                                        "key": "paper-a",
                                        "line_number": 3,
                                        "marker": "Paper A",
                                        "source_candidate_id": "candidate-a",
                                        "relation_summary_zh": "公开测试关系。",
                                        "paper": {
                                            "paper_id": "paper_" + "1" * 32,
                                            "title": "Paper A",
                                            "external_links": [
                                                {
                                                    "kind": "repository",
                                                    "url": "https://example.invalid/paper-a",
                                                    "unexpected": True,
                                                }
                                            ],
                                        },
                                    }
                                ],
                            }
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            registry = CitationOverlayRegistry(
                None,
                manifest_path=manifest,
                source_objects={source_sha256: source},
                source_paths={source_sha256: "research.md"},
            )
            with self.assertRaisesRegex(CitationOverlayError, "external links"):
                registry.for_document(source_sha256)

    def test_current_chapter_toc_uses_hierarchical_counters_and_wraps(self) -> None:
        css = (ROOT / "quant_hub" / "src" / "quant_hub" / "web" / "static" / "styles.css").read_text(encoding="utf-8")
        self.assertIn('content: counters(chapter-item, ".") "."', css)
        self.assertIn("grid-template-columns: fit-content(4.5rem) minmax(0, 1fr)", css)
        self.assertIn("overflow-wrap: anywhere", css)
        self.assertIn("overflow-x: clip", css)
        self.assertIn("li.toc-entry--source::before { content: none; }", css)
        self.assertIn("list-style: none", css)

    def test_source_numbered_headings_do_not_receive_duplicate_numbers(self) -> None:
        toc = _toc_with_numbering_semantics(
            [
                {
                    "title_text": "低信噪比因子序列表征",
                    "children": [
                        {"title_text": "第 1 部分：问题定义", "children": []},
                        {"title_text": "1.1 序列表征", "children": []},
                        {"title_text": "机制一：噪声传播", "children": []},
                        {"title_text": "稳健性边界", "children": []},
                    ],
                }
            ]
        )

        self.assertEqual("automatic", toc[0]["numbering_mode"])
        self.assertEqual(
            ["source", "source", "source", "automatic"],
            [item["numbering_mode"] for item in toc[0]["children"]],
        )


if __name__ == "__main__":
    unittest.main()
