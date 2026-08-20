from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock

from flask import Blueprint, Flask

from quant_hub.config import Settings
from quant_hub.evidence.database import evidence_connection
from quant_hub.evidence.fixture import import_vertical_fixture
from quant_hub.evidence.presentation import EvidencePresentationError
from quant_hub.evidence.service import EvidenceQueryService
from quant_hub.evidence.web import create_evidence_blueprint


class EvidenceWebTests(unittest.TestCase):
    def setUp(self) -> None:
        self.formal_root = Path(__file__).resolve().parents[1]
        self.workspace_root = self.formal_root.parent
        self.temporary = tempfile.TemporaryDirectory(
            dir=self.formal_root, prefix=".evidence-web-test-"
        )
        self.addCleanup(self.temporary.cleanup)
        self.settings = Settings.default(
            project_root=self.workspace_root,
            var_root=Path(self.temporary.name) / "var",
        )
        import_vertical_fixture(
            self.settings,
            self.formal_root / "fixtures" / "evidence" / "vertical_slice.json",
        )
        with evidence_connection(self.settings) as connection:
            self.paper_id = str(
                connection.execute(
                    "SELECT paper_id FROM paper ORDER BY paper_id LIMIT 1"
                ).fetchone()[0]
            )
            resource = connection.execute(
                "SELECT resource_id,relative_path FROM paper_resource ORDER BY resource_id LIMIT 1"
            ).fetchone()
            self.resource_id = str(resource["resource_id"])
            self.resource_relative_path = str(resource["relative_path"])
            citation = connection.execute(
                """
                SELECT citation_id,document_sha256 FROM citation_occurrence
                ORDER BY citation_id LIMIT 1
                """
            ).fetchone()
            self.citation_id = str(citation["citation_id"])
            self.document_sha256 = str(citation["document_sha256"])

        app = Flask(
            __name__,
            template_folder=str(self.formal_root / "src" / "quant_hub" / "web" / "templates"),
            static_folder=str(self.formal_root / "src" / "quant_hub" / "web" / "static"),
        )
        app.config.update(TESTING=True)
        shell = Blueprint("web", __name__)

        @shell.get("/")
        def home_page() -> str:
            return "home"

        api = Blueprint("api_v1", __name__)

        @api.get("/api/v1/dashboard")
        def dashboard() -> dict[str, str]:
            return {"status": "ok"}

        app.register_blueprint(shell)
        app.register_blueprint(api)
        app.register_blueprint(create_evidence_blueprint(self.settings))
        self.client = app.test_client()

    def test_success_envelope_request_id_and_conditional_get(self) -> None:
        response = self.client.get(
            "/api/v1/evidence/papers?limit=2",
            headers={"X-Request-ID": "evidence.web-test:1"},
        )
        self.assertEqual(200, response.status_code)
        self.assertEqual("application/json", response.mimetype)
        payload = response.get_json()
        self.assertEqual({"api_version", "data", "meta"}, set(payload))
        self.assertNotIn("error", payload)
        self.assertEqual("v1", payload["api_version"])
        self.assertEqual("evidence.web-test:1", payload["meta"]["request_id"])
        self.assertEqual("evidence.web-test:1", response.headers["X-Request-ID"])
        self.assertEqual("nosniff", response.headers["X-Content-Type-Options"])
        self.assertTrue(response.headers["ETag"])
        self.assertIn(
            payload["data"]["papers"][0]["institution_resolution_status"],
            {"verified", "unresolved"},
        )
        dossier = payload["data"]["papers"][0]["dossier_coverage"]
        self.assertEqual(
            {
                "external_original",
                "local_original",
                "abstract_evidence",
                "core_conclusions",
                "archive_relations",
                "complete",
                "missing",
            },
            set(dossier),
        )
        self.assertIsInstance(dossier["complete"], bool)

        conditional = self.client.get(
            "/api/v1/evidence/papers?limit=2",
            headers={"If-None-Match": response.headers["ETag"]},
        )
        self.assertEqual(304, conditional.status_code)

    def test_error_envelope_has_no_success_data_and_valid_request_id(self) -> None:
        invalid_query = self.client.get(
            "/api/v1/evidence/papers?limit=invalid",
            headers={"X-Request-ID": "contains whitespace"},
        )
        self.assertEqual(422, invalid_query.status_code)
        payload = invalid_query.get_json()
        self.assertEqual({"api_version", "error", "meta"}, set(payload))
        self.assertNotIn("data", payload)
        self.assertEqual("invalid_query", payload["error"]["code"])
        self.assertRegex(
            payload["meta"]["request_id"],
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        )
        self.assertEqual(
            payload["meta"]["request_id"], invalid_query.headers["X-Request-ID"]
        )

        invalid_document = self.client.get(
            "/api/v1/evidence/documents/not-a-sha/citations"
        )
        self.assertEqual(422, invalid_document.status_code)
        self.assertEqual(
            "invalid_document_sha256", invalid_document.get_json()["error"]["code"]
        )
        missing = self.client.get(
            "/api/v1/evidence/citations/cit_" + "a" * 52
        )
        self.assertEqual(404, missing.status_code)
        self.assertEqual("citation_not_found", missing.get_json()["error"]["code"])

    def test_citation_contract_exposes_stable_render_and_detail_urls(self) -> None:
        response = self.client.get(
            f"/api/v1/evidence/documents/{self.document_sha256}/citations"
        )
        self.assertEqual(200, response.status_code)
        items = response.get_json()["data"]["items"]
        self.assertGreaterEqual(len(items), 1)
        selected = next(item for item in items if item["citation_id"] == self.citation_id)
        self.assertEqual(self.document_sha256, selected["document_sha256"])
        self.assertIn(selected["resolution_state"], {"valid", "source-only", "unresolved", "conflicted"})
        self.assertEqual(
            f"/api/v1/evidence/citations/{self.citation_id}", selected["detail_url"]
        )

        detail = self.client.get(selected["detail_url"])
        self.assertEqual(200, detail.status_code)
        citation = detail.get_json()["data"]
        self.assertEqual(self.citation_id, citation["citation_id"])
        self.assertTrue(citation["raw_marker_text"])
        self.assertTrue(citation["context_text"])
        self.assertTrue(citation["entries"])
        for entry in citation["entries"]:
            if entry["paper"] is not None:
                summary = entry["paper"]["paper_summary"]
                self.assertIn("external_links", summary)
                self.assertIn("local_resources", summary)
                self.assertIn("evidence_excerpts", summary)

    def test_resource_endpoint_is_id_only_verified_and_conditional(self) -> None:
        response = self.client.get(
            f"/api/v1/evidence/resources/{self.resource_id}",
            headers={"X-Request-ID": "resource-1"},
        )
        self.assertEqual(200, response.status_code)
        self.assertEqual("application/pdf", response.mimetype)
        self.assertTrue(response.data.startswith(b"%PDF-"))
        self.assertIn("inline;", response.headers["Content-Disposition"])
        self.assertEqual("nosniff", response.headers["X-Content-Type-Options"])
        self.assertEqual("resource-1", response.headers["X-Request-ID"])
        self.assertNotIn(self.resource_relative_path.encode("utf-8"), response.data)

        conditional = self.client.get(
            f"/api/v1/evidence/resources/{self.resource_id}",
            headers={"If-None-Match": response.headers["ETag"]},
        )
        self.assertEqual(304, conditional.status_code)
        traversal = self.client.get("/api/v1/evidence/resources/%2e%2e")
        self.assertEqual(404, traversal.status_code)
        self.assertEqual("resource_not_found", traversal.get_json()["error"]["code"])

    def test_human_pages_extend_platform_shell_and_show_explicit_empty_state(self) -> None:
        home = self.client.get("/evidence/")
        self.assertEqual(200, home.status_code)
        body = home.get_data(as_text=True)
        self.assertNotIn("Coverage ledger", body)
        for marker in (
            'class="skip-link"',
            'class="site-header"',
            'class="site-footer"',
            'class="page-shell evidence-shell"',
            "/evidence/static/evidence.css",
            "论文证据库",
            "可直接阅读 PDF",
            "研究资料概览",
        ):
            self.assertIn(marker, body)
        for audit_label in ("核验状态", "身份冲突", "证据档案覆盖", "类别来源与映射"):
            self.assertNotIn(audit_label, body)

        css = self.client.get("/evidence/static/evidence.css").get_data(
            as_text=True
        )
        self.assertIn("max-width: 110rem", css)
        self.assertIn(
            '.evidence-shell[data-evidence-page="detail"] { width: calc(100% - clamp(2.5rem, 5vw, 5rem)); max-width: 104rem;',
            css,
        )

        complete = self.client.get("/evidence/?dossier=complete")
        self.assertEqual(200, complete.status_code)
        self.assertIn("显示 0 篇论文", complete.get_data(as_text=True))
        incomplete = self.client.get("/evidence/?dossier=needs_evidence")
        self.assertEqual(200, incomplete.status_code)
        self.assertIn(
            'data-dossier-complete="false"', incomplete.get_data(as_text=True)
        )

        filtered = self.client.get("/evidence/?q=definitely-no-such-paper")
        self.assertEqual(200, filtered.status_code)
        self.assertIn('class="empty-state"', filtered.get_data(as_text=True))

        detail = self.client.get(f"/evidence/papers/{self.paper_id}")
        self.assertEqual(200, detail.status_code)
        detail_body = detail.get_data(as_text=True)
        self.assertIn('class="page-shell evidence-shell"', detail_body)
        self.assertIn("原文来源", detail_body)
        self.assertIn("在 Archive 量化研究中的应用", detail_body)
        self.assertIn("研究解读", detail_body)
        for internal_audit_label in (
            "机构核验状态",
            "证据来源与校验",
            "支持文本哈希",
            "事实边界",
            "标识与类别",
            "source_verified",
        ):
            self.assertNotIn(internal_audit_label, detail_body)
        for content_key in (
            "external-original",
            "local-original",
            "abstract-evidence",
            "core-conclusions",
            "archive-relations",
        ):
            self.assertIn(
                f'data-acceptance-content="{content_key}"', detail_body
            )
        self.assertNotIn("<h2>读取任务</h2>", detail_body)
        self.assertNotIn(">Ledger<", detail_body)
        self.assertNotIn(">查看引用</a>", detail_body)
        self.assertNotIn("<pre>", detail_body)
        missing = self.client.get("/evidence/papers/not-present")
        self.assertEqual(404, missing.status_code)
        self.assertIn("evidence-not-found", missing.get_data(as_text=True))

    def test_research_relations_are_deduplicated_and_link_to_archive_source(self) -> None:
        citation_id = "cit_" + "a" * 52
        common = {
            "research_urn": "qrh:archive:research:Q2_FACTORY_DESIGN",
            "document_version_urn": "qrh:archive:document-version:fixture",
            "ledger_entry_id": "ledger-fixture",
            "citation_id": citation_id,
            "source_path": "Q2/embedding.md",
            "canonical_path": "Q2/embedding.md",
            "locator_claim": "line:42",
            "line_start": 42,
            "line_end": 42,
            "context_text": "研究在此采用可微排序目标来优化横截面排序质量。",
            "raw_marker_text": "fixture",
            "relation_semantics": "formal_or_direct",
        }
        rows = [
            {
                **common,
                "relation_id": "relation-identifier",
                "relation_kind": "mentions",
                "occurrence_type": "strong_identifier_arxiv",
            },
            {
                **common,
                "relation_id": "relation-usage",
                "relation_kind": "mentions",
                "occurrence_type": "textual_author_year_mention",
            },
        ]
        index = {
            "Q2/embedding.md": {
                "research_id": "res_fixture",
                "research_title": "量化模型工厂设计",
                "document_id": "doc_fixture",
                "title": "数值特征表征与排序目标",
                "sections": [
                    {
                        "anchor_id": "anc_sha256_" + "1" * 64,
                        "line_start": 1,
                        "title_text": "数值特征表征与排序目标",
                    },
                    {
                        "anchor_id": "anc_sha256_" + "2" * 64,
                        "line_start": 40,
                        "title_text": "可微排序目标",
                    },
                ],
            }
        }
        relations = EvidenceQueryService._present_archive_relations(rows, index)
        self.assertEqual(1, len(relations))
        self.assertEqual("正文观点引用", relations[0]["relation_label"])
        self.assertEqual(
            "/research/res_fixture/documents/doc_fixture#anc_sha256_" + "2" * 64,
            relations[0]["source_url"],
        )
        self.assertEqual("定位到原文所在章节", relations[0]["source_link_label"])
        self.assertEqual("可微排序目标", relations[0]["source_section_title"])
        self.assertNotIn("/api/", str(relations[0]["source_url"]))
        self.assertEqual(
            [],
            EvidenceQueryService._present_archive_relations(
                [rows[0]], index, core_only=True
            ),
        )
        self.assertEqual(
            "正文观点引用",
            EvidenceQueryService._present_archive_relations(
                rows, index, core_only=True
            )[0]["relation_label"],
        )
        historical = EvidenceQueryService._present_archive_relations(
            rows, {}, core_only=True
        )
        self.assertEqual([], historical)

    def test_linkable_formal_reference_is_visible_without_core_upgrade(self) -> None:
        citation_id = "cit_" + "f" * 52
        row = {
            "relation_id": "relation-formal-reference",
            "research_urn": "qrh:archive:research:fixture",
            "document_version_urn": "qrh:archive:document-version:fixture",
            "ledger_entry_id": "ledger-formal-reference",
            "citation_id": citation_id,
            "source_path": "Q2/references.md",
            "canonical_path": "Q2/references.md",
            "locator_claim": "line:20",
            "line_start": 20,
            "line_end": 20,
            "context_text": "Author 2020，论文标题（方法选择的参考文献）。",
            "raw_marker_text": "fixture",
            "relation_kind": "formal_reference",
            "relation_semantics": "formal_or_direct",
            "occurrence_type": "formal_reference_list_occurrence",
        }
        index = {
            "Q2/references.md": {
                "research_id": "res_fixture",
                "research_title": "量化研究",
                "document_id": "doc_fixture",
                "title": "研究综述",
                "sections": [
                    {
                        "anchor_id": "anc_sha256_" + "6" * 64,
                        "line_start": 1,
                        "title_text": "参考文献",
                    }
                ],
            }
        }
        relations = EvidenceQueryService._present_archive_relations([row], index)
        self.assertEqual([], EvidenceQueryService._present_archive_relations(
            [row], index, core_only=True
        ))
        fallback = EvidenceQueryService._select_archive_reference_relations(relations)
        self.assertEqual(1, len(fallback))
        self.assertEqual("formal_reference_only", fallback[0]["display_scope"])
        self.assertTrue(str(fallback[0]["source_url"]).startswith("/research/"))

    def test_aliased_identifier_is_not_promoted_to_historical_reference(self) -> None:
        row = {
            "relation_id": "relation-aliased-identifier",
            "research_urn": "qrh:archive:research:fixture",
            "document_version_urn": "qrh:archive:document-version:fixture",
            "ledger_entry_id": "ledger-aliased-identifier",
            "citation_id": "cit_" + "e" * 52,
            "source_path": "Q2/retired.md",
            "canonical_path": "Q2/retired.md",
            "locator_claim": "line:20",
            "line_start": 20,
            "line_end": 20,
            "context_text": "arXiv:2203.05556",
            "raw_marker_text": "arXiv:2203.05556",
            "relation_kind": "mentions",
            "relation_semantics": "formal_or_direct",
            "occurrence_type": "strong_identifier_arxiv",
        }
        index = {
            "Q2/retired.md": {
                "source_path": "Q2/current.md",
                "research_id": "res_fixture",
                "research_title": "量化研究",
                "document_id": "doc_fixture",
                "title": "当前研究综述",
                "sections": [],
            }
        }
        relations = EvidenceQueryService._present_archive_relations([row], index)
        self.assertEqual(1, len(relations))
        self.assertEqual("论文身份定位", relations[0]["relation_label"])
        self.assertEqual(
            [],
            EvidenceQueryService._select_archive_reference_relations(relations),
        )

    def test_archive_relation_source_anchor_is_always_owned_by_target_page(self) -> None:
        citation_id = "cit_" + "b" * 52
        row = {
            "relation_id": "relation-before-first-heading",
            "research_urn": "qrh:archive:research:fixture",
            "document_version_urn": "qrh:archive:document-version:fixture",
            "ledger_entry_id": "ledger-before-first-heading",
            "citation_id": citation_id,
            "source_path": "Q2/front-matter.md",
            "canonical_path": "Q2/front-matter.md",
            "locator_claim": "line:1",
            "line_start": 1,
            "line_end": 1,
            "context_text": "标题前的来源线索不能伪造 citation fragment。",
            "raw_marker_text": "fixture",
            "relation_kind": "mentions",
            "relation_semantics": "formal_or_direct",
            "occurrence_type": "textual_author_year_mention",
        }
        heading_anchor = "anc_sha256_" + "3" * 64
        target = {
            "research_id": "res_fixture",
            "research_title": "量化研究",
            "document_id": "doc_fixture",
            "title": "前置说明",
            "sections": [
                {
                    "anchor_id": heading_anchor,
                    "line_start": 3,
                    "title_text": "第一节",
                }
            ],
        }
        relation = EvidenceQueryService._present_archive_relations(
            [row], {"Q2/front-matter.md": target}
        )[0]
        self.assertEqual(
            "/research/res_fixture/documents/doc_fixture#document-doc_fixture",
            relation["source_url"],
        )
        self.assertEqual("定位到研究文档", relation["source_link_label"])
        self.assertIsNone(relation["source_section_title"])
        target_ids = {"document-doc_fixture", heading_anchor}
        self.assertIn(str(relation["source_url"]).partition("#")[2], target_ids)

    def test_chinese_overlay_is_bound_to_excerpt_identifier_title_and_source_path(self) -> None:
        excerpt_text = "Verified official abstract fixture."
        excerpt_hash = hashlib.sha256(excerpt_text.encode("utf-8")).hexdigest()
        source_path = "project_state/workers/fixture/official-atom.xml"
        with evidence_connection(self.settings) as connection:
            connection.execute(
                """
                INSERT INTO evidence_excerpt(
                    excerpt_id,paper_id,resource_id,excerpt_text,locator_json,
                    excerpt_sha256,provenance_urn,created_at
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    "excerpt_overlay_binding_fixture",
                    self.paper_id,
                    None,
                    excerpt_text,
                    json.dumps({"source_path": source_path}, sort_keys=True),
                    excerpt_hash,
                    "qrh:test:official-abstract-overlay",
                    "2026-07-16T00:00:00+00:00",
                ),
            )
            connection.commit()
        base = EvidenceQueryService(self.settings).paper_detail(self.paper_id)
        rendered_source = self.client.get(f"/evidence/papers/{self.paper_id}")
        self.assertEqual(200, rendered_source.status_code)
        rendered_body = rendered_source.get_data(as_text=True)
        self.assertIn("摘要原文", rendered_body)
        self.assertNotIn("证据来源与校验", rendered_body)
        self.assertNotIn("摘要内容哈希", rendered_body)
        identifier = base["identifiers"][0]
        overlay = {
            "identifier_scheme": identifier["scheme"],
            "normalized_identifier": identifier["value"],
            "title": base["title"],
            "source_excerpt_sha256": excerpt_hash,
            "source_excerpt_bytes": len(excerpt_text.encode("utf-8")),
            "source_path": source_path,
            "abstract_translation_zh": "已核验官方摘要的中文参考译文。",
            "synthesis_zh": "仅用于研究阅读辅助的中文综述。",
            "translation_status": "generated_reference_translation",
            "summary_status": "generated_research_aid_not_source_fact",
            "fact_boundary": "生成译文与综述，不属于来源事实",
        }
        with mock.patch(
            "quant_hub.evidence.service.chinese_overlays_by_excerpt",
            return_value={excerpt_hash: overlay},
        ):
            detail = EvidenceQueryService(self.settings).paper_detail(self.paper_id)
        self.assertEqual(
            "已核验官方摘要的中文参考译文。",
            detail["abstract_excerpts"][0]["chinese_presentation"][
                "abstract_translation_zh"
            ],
        )
        for field, bad_value, message in (
            ("title", "Wrong title", "论文标题不一致"),
            ("source_path", "wrong/source.xml", "来源路径不一致"),
            ("normalized_identifier", "wrong-id", "强标识符不一致"),
        ):
            with self.subTest(field=field):
                tampered = {**overlay, field: bad_value}
                with mock.patch(
                    "quant_hub.evidence.service.chinese_overlays_by_excerpt",
                    return_value={excerpt_hash: tampered},
                ):
                    with self.assertRaisesRegex(EvidencePresentationError, message):
                        EvidenceQueryService(self.settings).paper_detail(self.paper_id)

        same_byte_count_tamper = "Tampered official abstract fixture."
        self.assertEqual(
            len(excerpt_text.encode("utf-8")),
            len(same_byte_count_tamper.encode("utf-8")),
        )
        with evidence_connection(self.settings) as connection:
            connection.execute(
                """
                INSERT INTO evidence_excerpt(
                    excerpt_id,paper_id,resource_id,excerpt_text,locator_json,
                    excerpt_sha256,provenance_urn,created_at
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    "excerpt_overlay_same_bytes_tamper",
                    self.paper_id,
                    None,
                    same_byte_count_tamper,
                    json.dumps({"source_path": source_path}, sort_keys=True),
                    excerpt_hash,
                    "qrh:test:tampered-official-abstract",
                    "2026-07-16T00:01:00+00:00",
                ),
            )
            connection.commit()
        with self.assertRaisesRegex(
            EvidencePresentationError, "官方摘要文本与登记哈希不一致"
        ):
            EvidenceQueryService(self.settings).paper_detail(self.paper_id)


if __name__ == "__main__":
    unittest.main()
