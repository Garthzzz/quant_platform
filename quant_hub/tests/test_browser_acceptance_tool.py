from __future__ import annotations

from contextlib import closing
from copy import deepcopy
from pathlib import Path
import sqlite3
import tempfile
import unittest

from tools.browser_acceptance import (
    _backup_database,
    _database_evidence_content_counts,
    _displayable_archive_relation_paper_count,
    _file_identity,
    _forbidden_elements_absent,
    _forbidden_phrases_absent,
    _researcher_evidence_content_counts,
    _semantic_items_gate,
    _validate_database_release_row_counts,
    _validate_evidence_aggregate_counts,
    _validate_evidence_detail_snapshot,
    _validate_output_paths,
    _validate_research_landing_snapshot,
    _verified_response_sha256,
)


class BrowserAcceptanceToolTests(unittest.TestCase):
    @staticmethod
    def _valid_evidence_snapshot() -> dict[str, list[dict[str, object]]]:
        return {
            "external-original": [
                {
                    "visible": True,
                    "text": "arXiv 官方原文",
                    "href": "https://arxiv.org/abs/1706.03762",
                }
            ],
            "local-original": [
                {
                    "visible": True,
                    "text": "PDF · 12345 bytes",
                    "href": "/api/v1/evidence/resources/resource_fixture",
                }
            ],
            "abstract-evidence": [
                {
                    "visible": True,
                    "text": "Verified official abstract evidence. " * 5,
                    "href": "",
                }
            ],
            "abstract-translation-zh": [
                {
                    "visible": True,
                    "text": "这是与当前英文摘要哈希精确绑定的中文参考译文。" * 4,
                    "href": "",
                }
            ],
            "synthesis-zh": [
                {
                    "visible": True,
                    "text": "这是区分来源事实与生成辅助的中文综述总结。" * 2,
                    "href": "",
                }
            ],
            "core-conclusions": [
                {
                    "visible": True,
                    "text": "来源支持的核心结论具有可回指定位和明确事实边界。",
                    "href": "",
                }
            ],
            "archive-relations": [
                {
                    "visible": True,
                    "text": "研究专题、子文档、正文观点、引用位置和中文关系说明均完整显示。" * 3,
                    "href": "/research/research_fixture/documents/document_fixture#document-document_fixture",
                    "research_title": "研究专题",
                    "document_title": "子研究文档",
                    "relation_label": "正文观点引用",
                    "usage_description": "该论文为这项量化研究的方法和论证提供直接来源支持。",
                    "source_excerpt": "研究正文在此处明确使用论文观点形成判断。",
                    "source_location": "第 12 行 · 方法来源",
                }
            ],
        }

    @staticmethod
    def _valid_research_landing_snapshot() -> dict[str, object]:
        return {
            "expected_featured_kinds": ["overview", "review"],
            "expected_child_count": 1,
            "direct_content": [
                {
                    "kind": "overview",
                    "document_id": "document_overview",
                    "visible": True,
                    "text": "专题概述直接呈现研究问题、范围和阅读路径。" * 20,
                    "href": "",
                    "order": 0,
                },
                {
                    "kind": "review",
                    "document_id": "document_review",
                    "visible": True,
                    "text": "综合综述直接呈现主要证据、差异、限制和当前结论。" * 20,
                    "href": "",
                    "order": 1,
                },
            ],
            "catalog": {
                "visible": True,
                "order": 2,
                "children": [
                    {
                        "visible": True,
                        "text": "独立子研究文档",
                        "href": "/research/research_fixture/documents/document_child",
                        "document_id": "document_child",
                    }
                ],
            },
            "markup": "<main><article>专题概述与综合综述</article></main>",
            "research_document_count": 0,
        }

    def test_semantic_item_gate_rejects_empty_placeholder_hidden_and_invalid_link(self) -> None:
        valid = [
            {
                "visible": True,
                "text": "可核验的原文链接",
                "href": "https://example.test/paper",
            }
        ]
        passed, evidence = _semantic_items_gate(
            valid,
            min_text_chars=4,
            href_pattern=r"https?://\S+",
        )
        self.assertTrue(passed, evidence)

        invalid_cases = {
            "empty": [{**valid[0], "text": "   "}],
            "placeholder": [{**valid[0], "text": "暂无可用原文"}],
            "hidden": [{**valid[0], "visible": False}],
            "invalid-link": [{**valid[0], "href": "#"}],
        }
        for label, items in invalid_cases.items():
            with self.subTest(label=label):
                passed, evidence = _semantic_items_gate(
                    items,
                    min_text_chars=4,
                    href_pattern=r"https?://\S+",
                )
                self.assertFalse(passed, evidence)
                self.assertEqual(0, evidence["valid"])

    def test_evidence_snapshot_requires_real_content_in_every_semantic_section(self) -> None:
        snapshot = self._valid_evidence_snapshot()
        passed, evidence = _validate_evidence_detail_snapshot(snapshot)
        self.assertTrue(passed, evidence)

        library_route = deepcopy(snapshot)
        library_route["local-original"][0]["href"] = (
            "/evidence/library/paper_reviewed_pdf"
        )
        passed, evidence = _validate_evidence_detail_snapshot(library_route)
        self.assertTrue(passed, evidence)

        conditional = deepcopy(snapshot)
        conditional["local-original"] = []
        expectations = {name: True for name in conditional}
        expectations["local-original"] = False
        passed, evidence = _validate_evidence_detail_snapshot(
            conditional, expectations
        )
        self.assertTrue(passed, evidence)
        conditional["local-original"] = [
            {
                "visible": False,
                "text": "隐藏的本地原文",
                "href": "/api/v1/evidence/resources/hidden",
            }
        ]
        passed, evidence = _validate_evidence_detail_snapshot(
            conditional, expectations
        )
        self.assertFalse(passed, evidence)
        self.assertIn(
            "unexpected-content-when-missing",
            evidence["checks"]["local-original"]["invalid"][0]["reasons"],
        )

        cases = {
            "empty-abstract": ("abstract-evidence", "text", ""),
            "placeholder-conclusion": (
                "core-conclusions",
                "text",
                "尚无可用结论",
            ),
            "hidden-local-original": ("local-original", "visible", False),
            "invalid-external-url": ("external-original", "href", "javascript:void(0)"),
            "missing-relation-usage": ("archive-relations", "usage_description", ""),
            "unowned-relation-anchor": (
                "archive-relations",
                "href",
                "/research/research_fixture/documents/document_fixture#citation-citation_fixture",
            ),
        }
        for label, (section, field, value) in cases.items():
            with self.subTest(label=label):
                candidate = deepcopy(snapshot)
                candidate[section][0][field] = value
                passed, evidence = _validate_evidence_detail_snapshot(candidate)
                self.assertFalse(passed, evidence)
                self.assertFalse(evidence["checks"][section]["passed"])

    def test_evidence_aggregate_counts_must_match_browser_api_database_and_release(self) -> None:
        exact = {
            "external-original": 78,
            "local-original": 48,
            "abstract-evidence": 53,
            "abstract-translation-zh": 53,
            "synthesis-zh": 53,
            "core-conclusions": 53,
            "archive-relations": 63,
        }
        passed, evidence = _validate_evidence_aggregate_counts(
            browser_expected=exact,
            browser_valid=exact,
            api=exact,
            database=exact,
            release=exact,
        )
        self.assertTrue(passed, evidence)

        stale_browser = {**exact, "archive-relations": 1}
        passed, evidence = _validate_evidence_aggregate_counts(
            browser_expected=stale_browser,
            browser_valid=stale_browser,
            api=exact,
            database=exact,
            release=exact,
        )
        self.assertFalse(passed, evidence)
        self.assertFalse(
            evidence["comparisons"]["archive-relations"]["passed"]
        )

    def test_effective_researcher_counts_include_reviewed_enrichment_projection(self) -> None:
        complete = {
            "external_links": [{"url": "https://example.test/paper"}],
            "local_resources": [{"url": "/evidence/library/paper_complete"}],
            "abstract_excerpts": [
                {
                    "text": "abstract",
                    "chinese_presentation": {
                        "abstract_translation_zh": "中文参考翻译"
                    },
                }
            ],
            "chinese_presentation": {"synthesis_zh": "研究解读"},
            "core_conclusions": [{"text": "conclusion"}],
            "archive_relations": [{"source_url": "/research/internal-candidate"}],
            "archive_core_relations": [{"source_url": "/research/topic"}],
            "archive_reference_relations": [],
        }
        without_local = deepcopy(complete)
        without_local["local_resources"] = []
        counts = _researcher_evidence_content_counts(
            [complete, without_local]
        )
        self.assertEqual(
            {
                "external-original": 2,
                "local-original": 1,
                "abstract-evidence": 2,
                "abstract-translation-zh": 2,
                "synthesis-zh": 2,
                "core-conclusions": 2,
                "archive-relations": 2,
            },
            counts,
        )

        broad_only = deepcopy(complete)
        broad_only["archive_core_relations"] = []
        broad_only["archive_reference_relations"] = []
        broad_counts = _researcher_evidence_content_counts([broad_only])
        self.assertEqual(0, broad_counts["archive-relations"])

    def test_database_storage_rows_are_independently_bound_to_release(self) -> None:
        database = {
            "official-abstract-excerpts": 53,
            "core-conclusion-rows": 53,
            "abstract-translation-zh": 53,
            "synthesis-zh": 53,
            "archive-relations": 63,
        }
        release = {
            "official_abstract_excerpts": 53,
            "core_conclusions": 53,
            "displayable_archive_relation_papers": 63,
        }
        passed, evidence = _validate_database_release_row_counts(
            database=database,
            release=release,
        )
        self.assertTrue(passed, evidence)

        stale_release = {**release, "core_conclusions": 52}
        passed, evidence = _validate_database_release_row_counts(
            database=database,
            release=stale_release,
        )
        self.assertFalse(passed, evidence)
        self.assertFalse(evidence["checks"]["core-conclusion-rows"]["passed"])

        duplicate_excerpt = {**database, "official-abstract-excerpts": 54}
        passed, evidence = _validate_database_release_row_counts(
            database=duplicate_excerpt,
            release=release,
        )
        self.assertFalse(passed, evidence)
        self.assertFalse(
            evidence["checks"]["official-abstract-excerpt-rows"]["passed"]
        )

    def test_database_overlay_count_uses_candidate_excerpt_intersection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "research_papers.sqlite3"
            with closing(sqlite3.connect(database)) as connection:
                connection.executescript(
                    """
                    CREATE TABLE paper(paper_id TEXT PRIMARY KEY);
                    CREATE TABLE paper_catalog_projection(
                        paper_id TEXT PRIMARY KEY,
                        external_links_json TEXT NOT NULL,
                        core_conclusions_json TEXT NOT NULL
                    );
                    CREATE TABLE paper_resource(
                        resource_id TEXT PRIMARY KEY,
                        paper_id TEXT,
                        verification_status TEXT NOT NULL
                    );
                    CREATE TABLE evidence_canonical_resource_attachment(
                        resource_id TEXT NOT NULL,
                        paper_id TEXT NOT NULL
                    );
                    CREATE TABLE evidence_excerpt(
                        excerpt_id TEXT PRIMARY KEY,
                        paper_id TEXT NOT NULL,
                        excerpt_sha256 TEXT NOT NULL
                    );
                    CREATE TABLE paper_core_conclusion(
                        conclusion_id TEXT PRIMARY KEY,
                        paper_id TEXT NOT NULL
                    );
                    CREATE TABLE citation_binding(
                        binding_id TEXT PRIMARY KEY,
                        paper_id TEXT,
                        binding_status TEXT NOT NULL
                    );
                    CREATE TABLE citation_binding_projection(binding_id TEXT NOT NULL);
                    CREATE TABLE evidence_associated_method_relation(paper_id TEXT NOT NULL);

                    INSERT INTO paper VALUES ('paper_active');
                    INSERT INTO paper_catalog_projection VALUES(
                        'paper_active', '["https://example.test/paper"]', '["claim"]'
                    );
                    INSERT INTO evidence_excerpt VALUES(
                        'excerpt_active', 'paper_active', 'active_hash'
                    );
                    INSERT INTO paper_core_conclusion VALUES(
                        'conclusion_active', 'paper_active'
                    );
                    """
                )
                connection.commit()

            counts = _database_evidence_content_counts(
                database,
                chinese_overlay_excerpt_hashes={"active_hash", "stale_other_release_hash"},
                displayable_archive_relation_papers=0,
            )
            self.assertEqual(1, counts["abstract-translation-zh"])
            self.assertEqual(1, counts["synthesis-zh"])
            self.assertEqual(1, counts["official-abstract-excerpts"])
            self.assertEqual(1, counts["core-conclusion-rows"])

    def test_archive_relation_count_uses_linkable_core_or_formal_fallback(self) -> None:
        def relation(
            relation_id: str,
            *,
            path: str,
            occurrence_type: str,
            relation_kind: str = "formal_reference",
        ) -> dict[str, object]:
            return {
                "relation_id": relation_id,
                "research_urn": f"urn:research:{relation_id}",
                "document_version_urn": f"urn:document:{relation_id}",
                "citation_id": f"citation_{relation_id}",
                "ledger_entry_id": f"ledger_{relation_id}",
                "relation_kind": relation_kind,
                "relation_semantics": "formal_or_direct",
                "source_path": path,
                "canonical_path": path,
                "locator_claim": "fixture",
                "occurrence_type": occurrence_type,
                "line_start": 12,
                "line_end": 12,
                "context_text": "研究正文中的真实来源语境。",
                "raw_marker_text": "fixture",
            }

        index = {
            "mapped.md": {
                "research_id": "research_fixture",
                "research_title": "研究专题",
                "document_id": "document_fixture",
                "title": "研究文档",
                "sections": [],
            }
        }
        rows_by_paper = {
            "paper_core": [
                relation(
                    "core",
                    path="mapped.md",
                    occurrence_type="formal_citation_command",
                )
            ],
            "paper_formal_fallback": [
                relation(
                    "formal",
                    path="mapped.md",
                    occurrence_type="formal_reference_list_occurrence",
                )
            ],
            "paper_unmapped_core": [
                relation(
                    "unmapped",
                    path="historical.md",
                    occurrence_type="formal_citation_command",
                )
            ],
            "paper_identity_only": [
                relation(
                    "identity",
                    path="mapped.md",
                    occurrence_type="strong_identifier_arxiv",
                )
            ],
        }
        self.assertEqual(
            2,
            _displayable_archive_relation_paper_count(rows_by_paper, index),
        )

    def test_research_landing_requires_direct_overview_review_then_child_links(self) -> None:
        snapshot = self._valid_research_landing_snapshot()
        passed, evidence = _validate_research_landing_snapshot(snapshot)
        self.assertTrue(passed, evidence)

        overview_only = deepcopy(snapshot)
        overview_only["expected_featured_kinds"] = ["overview"]
        overview_only["expected_child_count"] = 0
        overview_only["direct_content"] = [overview_only["direct_content"][0]]
        overview_only["catalog"]["order"] = 1
        overview_only["catalog"]["children"] = []
        passed, evidence = _validate_research_landing_snapshot(overview_only)
        self.assertTrue(passed, evidence)

        negative_cases: dict[str, dict[str, object]] = {}
        hidden_review = deepcopy(snapshot)
        hidden_review["direct_content"][1]["visible"] = False
        negative_cases["hidden-review"] = hidden_review
        placeholder_overview = deepcopy(snapshot)
        placeholder_overview["direct_content"][0]["text"] = "暂无专题概述"
        negative_cases["placeholder-overview"] = placeholder_overview
        wrong_order = deepcopy(snapshot)
        wrong_order["catalog"]["order"] = 1
        negative_cases["catalog-before-review"] = wrong_order
        duplicated_direct_document = deepcopy(snapshot)
        duplicated_direct_document["catalog"]["children"][0]["document_id"] = (
            "document_overview"
        )
        negative_cases["overview-repeated-as-child"] = duplicated_direct_document
        forbidden_copy = deepcopy(snapshot)
        forbidden_copy["markup"] = "<p hidden>最终支持的决策</p>"
        negative_cases["hidden-final-decision-copy"] = forbidden_copy
        missing_children = deepcopy(snapshot)
        missing_children["catalog"]["children"] = []
        negative_cases["empty-child-catalog"] = missing_children

        for label, candidate in negative_cases.items():
            with self.subTest(label=label):
                passed, evidence = _validate_research_landing_snapshot(candidate)
                self.assertFalse(passed, evidence)

    def test_hidden_parent_topic_control_and_hidden_decision_copy_fail_closed(self) -> None:
        passed, evidence = _forbidden_elements_absent([])
        self.assertTrue(passed, evidence)
        passed, evidence = _forbidden_elements_absent(
            [{"name": "parent_topic_id", "visible": False, "type": "hidden"}]
        )
        self.assertFalse(passed, evidence)
        self.assertEqual(1, evidence["hidden"])

        passed, evidence = _forbidden_phrases_absent(
            "<span hidden>最终支持的决策</span>", ("最终支持的决策",)
        )
        self.assertFalse(passed, evidence)

    def test_response_digest_accepts_body_bound_sha_header_or_strong_etag(self) -> None:
        payload = b"%PDF-1.7\nverified bytes"
        import hashlib

        digest = hashlib.sha256(payload).hexdigest()
        self.assertEqual(
            (digest, "x-content-sha256"),
            _verified_response_sha256({"x-content-sha256": digest}, payload),
        )
        self.assertEqual(
            (digest, "etag"),
            _verified_response_sha256({"etag": f'"{digest}"'}, payload),
        )
        self.assertEqual(
            ("", "etag"),
            _verified_response_sha256({"etag": f'"{digest}"'}, payload + b"tampered"),
        )

    def test_backup_reads_wal_database_without_source_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.sqlite3"
            destination = root / "copy" / "destination.sqlite3"
            with closing(sqlite3.connect(source)) as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("CREATE TABLE sample(value TEXT NOT NULL)")
                connection.execute("INSERT INTO sample(value) VALUES ('原文不变')")
                connection.commit()

            self.assertFalse(Path(f"{source}-wal").exists())
            self.assertFalse(Path(f"{source}-shm").exists())

            source_identity = _backup_database(source, destination)

            with closing(
                sqlite3.connect(
                    f"file:{destination.as_posix()}?mode=ro&immutable=1", uri=True
                )
            ) as connection:
                self.assertEqual(
                    [("原文不变",)],
                    connection.execute("SELECT value FROM sample").fetchall(),
                )
            self.assertFalse(Path(f"{source}-wal").exists())
            self.assertFalse(Path(f"{source}-shm").exists())
            self.assertEqual(source_identity, _file_identity(source))

    def test_output_must_be_new_gate_child_and_disjoint_from_delivery_and_reference(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            delivery_root = project / "quant_hub" / "var"
            delivery = delivery_root / "candidate"
            gates = project / "project_state" / "gates"
            reference = project / "reference" / "archive"
            for path in (delivery, gates, reference):
                path.mkdir(parents=True, exist_ok=True)

            valid = gates / "browser-new"
            self.assertEqual(
                (delivery_root.resolve(), gates.resolve()),
                _validate_output_paths(
                    project.resolve(), delivery.resolve(), valid.resolve(strict=False)
                ),
            )
            with self.assertRaisesRegex(RuntimeError, "project_state/gates"):
                _validate_output_paths(
                    project.resolve(),
                    delivery.resolve(),
                    (reference / "forbidden").resolve(strict=False),
                )
            with self.assertRaisesRegex(RuntimeError, "project_state/gates"):
                _validate_output_paths(
                    project.resolve(),
                    delivery.resolve(),
                    (delivery / "forbidden").resolve(strict=False),
                )


if __name__ == "__main__":
    unittest.main()
