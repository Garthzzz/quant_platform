from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from quant_hub.app import create_app
from quant_hub.archive.catalog import ArchiveCatalog
from quant_hub.archive.contracts import (
    ActorInput,
    ArchiveDocumentInput,
    ArchiveReleaseInput,
    TopicInput,
)
from quant_hub.archive.database import archive_connection
from quant_hub.collaboration.service import ArchiveCollaboration
from quant_hub.evidence.contracts import CitationOccurrenceInput
from quant_hub.evidence.repository import EvidenceRepository
from quant_hub.evidence.service import EvidenceQueryService
from quant_hub.ids import sha256_hex
from quant_hub.presentation import ArchivePresentation
from tests.helpers import SettingsTestCase


class ArchiveWebTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.source = (
            "# Web 集成研究\n\n"
            "独特检索词 omega-signal 与中文证据边界。\n\n"
            "## 宽表与公式\n\n"
            "| 模型 | 很长的样本窗口 | IC | IR |\n"
            "|---|---|---:|---:|\n"
            "| baseline | 2018–2025 | 0.031 | 1.18 |\n\n"
            "$$R=\\sum_t r_t$$\n\n"
            "<script>正文中的 raw HTML 不可执行</script>\n"
        ).encode("utf-8")
        (self.archive / "web-research.md").write_bytes(self.source)
        self.source_before = (self.archive / "web-research.md").read_bytes()
        self.companion_source = (
            "# 表征稳定性补充研究\n\n"
            "该独立文档用于验证专题内其他文档在左栏只显示标题。\n\n"
            "## 跨种子一致性\n\n"
            "补充研究正文不得混入当前子专题页面。\n"
        ).encode("utf-8")
        (self.archive / "web-companion.md").write_bytes(self.companion_source)
        self.child_source = (
            "# 成本扰动子研究\n\n"
            "该文档用于验证概述与综述之后只列具体子研究链接。\n\n"
            "## 扰动边界\n\n"
            "子研究正文只在独立阅读页展开。\n"
        ).encode("utf-8")
        (self.archive / "web-child.md").write_bytes(self.child_source)

        self.catalog = ArchiveCatalog(self.settings)
        release_draft = ArchiveReleaseInput(
                research_slug="web-research",
                display_title="Web 集成研究",
                release_key="v1",
                documents=(
                    ArchiveDocumentInput(
                        document_slug="main",
                        document_role="primary",
                        source_path="web-research.md",
                        **self.approved_source_fields("web-research.md"),
                        navigation_role="primary",
                        sort_key=10,
                        mapping_authority_urn="qrh:review:web-test-mapping",
                        mapping_note="Web 端到端测试的显式研究映射",
                    ),
                    ArchiveDocumentInput(
                        document_slug="representation-stability",
                        document_role="supporting",
                        source_path="web-companion.md",
                        **self.approved_source_fields("web-companion.md"),
                        navigation_role="supporting",
                        sort_key=20,
                        mapping_authority_urn="qrh:review:web-test-companion-mapping",
                        mapping_note="验证多文档专题左栏契约的显式补充文档映射",
                    ),
                    ArchiveDocumentInput(
                        document_slug="cost-perturbation",
                        document_role="supporting",
                        source_path="web-child.md",
                        **self.approved_source_fields("web-child.md"),
                        navigation_role="supporting",
                        sort_key=30,
                        mapping_authority_urn="qrh:review:web-test-child-mapping",
                        mapping_note="验证专题概述与综述之后的子研究链接契约",
                    ),
                ),
                summary="用于验证真实 SQLite Web 垂直切片。",
                summary_provenance_urn=(
                    f"qrh:object:obj_sha256_{sha256_hex(self.source)}"
                ),
                activate=False,
            )
        published = self.publish_with_test_certificate(
            self.catalog,
            release_draft,
            label="archive-web-v1",
        )
        self.research_id = published.research_id
        self.release_id = published.research_release_id
        page_documents = self.catalog.research_page(self.research_id)["documents"]
        self.document_id = page_documents[0]["document_id"]
        self.companion_document_id = page_documents[1]["document_id"]
        self.companion_document_title = page_documents[1]["display_title"]
        self.child_document_id = page_documents[2]["document_id"]
        self.child_document_title = page_documents[2]["display_title"]

        collaboration = ArchiveCollaboration(self.settings)
        actor = ActorInput(actor_kind="zhang_zhengze")
        topic = collaboration.create_topic(
            TopicInput(topic_key="web-topic", title="Web 集成 Topic", manual_order=10),
            actor,
            idempotency_key="web-topic-create-0001",
        )
        self.assertTrue(topic.ok)
        self.topic_id = str(topic.data["topic_id"])
        linked = collaboration.link_topic_research(
            self.topic_id,
            self.research_id,
            actor,
            link_kind="primary",
            dashboard_primary=True,
            display_rank=10,
            provenance_urn="qrh:review:web-topic-link",
            idempotency_key="web-topic-link-0001",
        )
        self.assertTrue(linked.ok)
        completed = collaboration.complete_research(
            self.research_id,
            self.release_id,
            reason="Web 端到端夹具已由测试操作者明确确认。",
            actor=actor,
            idempotency_key="web-research-complete-0001",
        )
        self.assertTrue(completed.ok)
        self.completion_decision_id = str(completed.data["decision_id"])
        conflict_topic = collaboration.create_topic(
            TopicInput(
                topic_key="web-conflict-topic",
                title="需核验的冲突 Topic",
                manual_order=20,
            ),
            actor,
            idempotency_key="web-conflict-topic-create-0001",
        )
        self.assertTrue(conflict_topic.ok)
        conflict_link = collaboration.link_topic_research(
            str(conflict_topic.data["topic_id"]),
            self.research_id,
            actor,
            link_kind="primary",
            dashboard_primary=False,
            display_rank=10,
            provenance_urn="qrh:review:web-conflict-link",
            idempotency_key="web-conflict-topic-link-0001",
        )
        self.assertTrue(conflict_link.ok)

        self.app = create_app(
            self.settings,
            {
                "TESTING": True,
                "SECRET_KEY": "archive-web-test-only",
                "TRUSTED_ORIGINS": ("http://localhost",),
            },
        )
        self.client = self.app.test_client()
        session_response = self.client.get("/api/v1/session")
        self.csrf = session_response.get_json()["data"]["csrf_token"]
        self.write_headers = {
            "Origin": "http://localhost",
            "X-CSRF-Token": self.csrf,
        }

    def assert_envelope(self, response, *, status: int, error: str | None = None):
        self.assertEqual(status, response.status_code)
        self.assertEqual("application/json", response.mimetype)
        payload = response.get_json()
        self.assertEqual("v1", payload["api_version"])
        self.assertIn("request_id", payload["meta"])
        if error is None:
            self.assertIn("data", payload)
            self.assertNotIn("error", payload)
        else:
            self.assertEqual(error, payload["error"]["code"])
            self.assertNotIn("data", payload)
        return payload

    def enable_direct_overview_presentation(self) -> None:
        default = ArchivePresentation.default()
        assert default.source is not None
        payload = json.loads(default.source.read_text(encoding="utf-8"))
        payload["research"]["web-research"] = {
            "title": "Web 集成研究",
            "summary": "直接阅读专题概述与综合综述，再进入独立子研究。",
            "landing_document_path": "web-research.md",
            "review_document_path": "web-companion.md",
            "orientation": {
                "question": "如何验证专题阅读层的内容顺序与来源边界？",
                "decision": (
                    "依据稳定性、表征一致性、复杂模型增量价值及过拟合校正结果，"
                    "接受、修正或否决训练方案。"
                ),
                "stages": [
                    {"title": "概述", "description": "先建立问题边界。"},
                    {"title": "综述", "description": "再汇总相关研究。"},
                ],
            },
            "document_titles": {
                "web-research.md": "专题概述",
                "web-companion.md": "综合综述",
                "web-child.md": "成本扰动边界",
            },
            "document_groups": [
                {
                    "key": "research-documents",
                    "title": "专题研究",
                    "paths": [
                        "web-research.md",
                        "web-companion.md",
                        "web-child.md",
                    ],
                }
            ],
        }
        presentation = ArchivePresentation(payload)
        self.catalog.presentation = presentation
        self.app.extensions["archive_catalog"].presentation = presentation

    def test_topic_landing_renders_overview_and_review_before_child_links(self) -> None:
        self.enable_direct_overview_presentation()

        response = self.client.get(f"/research/{self.research_id}")
        self.assertEqual(200, response.status_code)
        html = response.get_data(as_text=True)
        self.assertIn('data-expected-featured-kinds="overview,review"', html)
        self.assertIn('data-expected-child-count="1"', html)
        overview = html.index('data-research-direct-content="overview"')
        review = html.index('data-research-direct-content="review"')
        child_links = html.index("data-research-document-links")
        self.assertLess(overview, review)
        self.assertLess(review, child_links)
        self.assertIn("独特检索词 omega-signal", html[overview:review])
        self.assertIn("该独立文档用于验证专题内其他文档", html[review:child_links])
        self.assertIn(f'data-document-id="{self.document_id}"', html[overview:review])
        self.assertIn(
            f'data-document-id="{self.companion_document_id}"',
            html[review:child_links],
        )

        linked_html = html[child_links:]
        self.assertIn(f'data-document-id="{self.child_document_id}"', linked_html)
        self.assertIn("成本扰动边界", linked_html)
        self.assertNotIn(f'data-document-id="{self.document_id}"', linked_html)
        self.assertNotIn(
            f'data-document-id="{self.companion_document_id}"', linked_html
        )
        self.assertNotIn("最终支持的决策", html)
        self.assertNotIn("接受、修正或否决训练方案", html)
        self.assertIn('id="citation-dialog"', html)

    def test_archive_page_keeps_exact_citation_with_path_only_neighbor(self) -> None:
        marker = "omega-signal"
        byte_start = self.source.index(marker.encode("utf-8"))
        byte_end = byte_start + len(marker.encode("utf-8"))
        document = self.catalog.research_page(self.research_id)["documents"][0]
        digest = sha256_hex(self.source)
        occurrence = CitationOccurrenceInput(
            legacy_occurrence_id="WEB-CITATION-0001",
            research_urn=f"qrh:archive:research:{self.research_id}",
            archive_release_urn=f"qrh:archive:release:{self.release_id}",
            document_version_urn=f"qrh:archive:document-version:{document['document_version_id']}",
            source_object_urn=f"qrh:archive:source-object:sha256:{digest}",
            document_sha256=digest,
            source_path="web-research.md",
            canonical_path="web-research.md",
            locator_claim="line:3",
            locator_kind="utf8_bytes",
            locator={"byte_start": byte_start, "byte_end": byte_end},
            line_start=3,
            line_end=3,
            byte_start=byte_start,
            byte_end=byte_end,
            raw_marker_text=marker,
            context_text="独特检索词 omega-signal 与中文证据边界。",
            occurrence_kind="textual_mention",
            resolution_status="unresolved",
            status_reason="Web 集成夹具保留待核验状态。",
            raw_occurrence_type="paper_mention",
            candidate_link_method="test_fixture",
            evidence_strength="textual_mention",
        )
        repository = EvidenceRepository(self.settings)
        citation_id, created = repository.add_citation(occurrence, self.source)
        self.assertTrue(created)
        repository.bind_citation(
            occurrence.legacy_occurrence_id,
            paper_id=None,
            binding_status="unresolved",
            rationale="没有足够证据绑定具体论文。",
            provenance_urn="qrh:test:archive-evidence-web",
        )
        path_only = CitationOccurrenceInput(
            legacy_occurrence_id="WEB-CITATION-PATH-ONLY-0001",
            research_urn=f"qrh:archive:research:{self.research_id}",
            archive_release_urn=f"qrh:archive:release:{self.release_id}",
            document_version_urn=(
                f"qrh:archive:document-version:{document['document_version_id']}"
            ),
            source_object_urn=f"qrh:archive:source-object:sha256:{digest}",
            document_sha256=digest,
            source_path="web-research.md",
            canonical_path="web-research.md",
            locator_claim="line:3",
            locator_kind="source_locator_claim",
            locator={"match_status": "not_exact_on_claimed_line"},
            line_start=3,
            line_end=3,
            byte_start=None,
            byte_end=None,
            raw_marker_text="unlocated-paper-reference",
            context_text="独特检索词 omega-signal 与中文证据边界。",
            occurrence_kind="textual_mention",
            resolution_status="source_only",
            status_reason="只有来源行声明，没有可验证 UTF-8 byte span。",
            raw_occurrence_type="paper_mention",
            candidate_link_method="test_fixture_path_only",
            evidence_strength="source_locator_only",
        )
        path_only_citation_id, path_only_created = repository.add_citation(
            path_only, self.source
        )
        self.assertTrue(path_only_created)

        landing = self.client.get(f"/research/{self.research_id}")
        landing_html = landing.get_data(as_text=True)
        child_url = f"/research/{self.research_id}/documents/{self.document_id}"
        self.assertEqual(200, landing.status_code)
        self.assertEqual(0, landing_html.count('class="research-document"'))
        self.assertIn(child_url, landing_html)
        self.assertNotIn(f'data-citation-id="{citation_id}"', landing_html)
        self.assertNotIn('id="citation-dialog"', landing_html)

        child = self.client.get(child_url)
        child_html = child.get_data(as_text=True)
        companion_url = (
            f"/research/{self.research_id}/documents/{self.companion_document_id}"
        )
        self.assertEqual(200, child.status_code)
        self.assertEqual(1, child_html.count('class="research-document"'))
        self.assertIn(f'data-citation-id="{citation_id}"', child_html)
        self.assertNotIn(
            f'data-citation-id="{path_only_citation_id}"', child_html
        )
        self.assertIn('data-citation-state="unresolved"', child_html)
        self.assertIn('id="citation-dialog"', child_html)
        self.assertEqual(1, child_html.count("data-document-toc"))
        self.assertEqual(1, child_html.count("current-document-toc"))
        self.assertRegex(
            child_html,
            re.compile(
                rf'<li class="topic-document-item">\s*'
                rf'<a href="{re.escape(companion_url)}">'
                rf'{re.escape(self.companion_document_title)}</a>\s*</li>',
                re.DOTALL,
            ),
        )
        self.assertIn(
            f'href="{child_url}" aria-current="page"', child_html
        )
        self.assertLess(
            child_html.index('class="current-document-toc"'),
            child_html.index(">专题文档<"),
        )
        self.assertEqual(self.source_before, (self.archive / "web-research.md").read_bytes())

        detail = self.client.get(f"/api/v1/evidence/citations/{citation_id}")
        self.assertEqual(200, detail.status_code)
        payload = detail.get_json()
        self.assertEqual(citation_id, payload["data"]["citation_id"])
        self.assertEqual("unresolved", payload["data"]["resolution_state"])
        self.assertEqual("WEB-CITATION-0001", payload["data"]["entries"][0]["ledger_entry_id"])

    def test_all_presented_evidence_relation_urls_target_archive_owned_ids(self) -> None:
        """A ledger citation need not be an HTML citation; every shown URL must land."""

        def relation(
            *, relation_id: str, path: str, line_start: int, suffix: str
        ) -> dict[str, object]:
            return {
                "relation_id": relation_id,
                "research_urn": f"qrh:archive:research:{self.research_id}",
                "document_version_urn": "qrh:archive:document-version:fixture",
                "ledger_entry_id": f"ledger-{suffix}",
                # Deliberately not projected into either page: this reproduces
                # the historical broken-fragment condition without weakening
                # the Archive renderer's overlap/AST safety policy.
                "citation_id": "cit_" + suffix * 52,
                "source_path": path,
                "canonical_path": path,
                "locator_claim": f"line:{line_start}",
                "line_start": line_start,
                "line_end": line_start,
                "context_text": "量化研究正文中的论文用途说明。",
                "raw_marker_text": "fixture",
                "relation_kind": "mentions",
                "relation_semantics": "formal_or_direct",
                "occurrence_type": "textual_author_year_mention",
            }

        rows = [
            relation(
                relation_id="relation-main-front",
                path="web-research.md",
                line_start=1,
                suffix="a",
            ),
            relation(
                relation_id="relation-main-section",
                path="web-research.md",
                line_start=7,
                suffix="b",
            ),
            relation(
                relation_id="relation-companion-section",
                path="web-companion.md",
                line_start=5,
                suffix="c",
            ),
        ]
        presented = EvidenceQueryService._present_archive_relations(
            rows, self.catalog.archive_link_index(), core_only=True
        )
        self.assertEqual(3, len(presented))
        for item in presented:
            parsed = urlsplit(str(item["source_url"]))
            self.assertTrue(parsed.fragment)
            self.assertFalse(parsed.fragment.startswith("citation-"))
            response = self.client.get(parsed.path)
            self.assertEqual(200, response.status_code)
            self.assertIn(
                f'id="{parsed.fragment}"', response.get_data(as_text=True)
            )

    def test_write_without_established_session_cannot_bypass_csrf(self) -> None:
        fresh_client = self.app.test_client()
        with archive_connection(self.settings) as connection:
            before = int(connection.execute("SELECT count(*) FROM comment").fetchone()[0])
        rejected = fresh_client.post(
            f"/api/v1/research/{self.research_id}/comments",
            json={
                "actor": {"actor_kind": "zhang_zhengze"},
                "content": "没有 session 的请求不得写入",
            },
            headers={
                "Origin": "http://localhost",
                "Idempotency-Key": "web-no-session-csrf-0001",
            },
        )
        self.assert_envelope(rejected, status=403, error="csrf_rejected")
        with archive_connection(self.settings) as connection:
            after = int(connection.execute("SELECT count(*) FROM comment").fetchone()[0])
        self.assertEqual(before, after)

    def test_real_dashboard_search_longform_and_exact_source(self) -> None:
        home = self.client.get("/")
        self.assertEqual(200, home.status_code)
        html = home.get_data(as_text=True)
        self.assertIn("量化研究工作台", html)
        self.assertIn("最近研究更新", html)
        self.assertIn("研究目录", html)
        self.assertIn("搜索研究树", html)
        self.assertNotIn("Web 集成研究", html)
        self.assertNotIn("需核验的冲突 Topic", html)
        self.assertIn("frame-ancestors 'none'", home.headers["Content-Security-Policy"])
        self.assertEqual("nosniff", home.headers["X-Content-Type-Options"])

        dashboard = self.client.get("/api/v1/dashboard")
        dashboard_payload = self.assert_envelope(dashboard, status=200)
        self.assertEqual("completed", dashboard_payload["data"]["topics"][0]["state"])
        self.assertEqual("conflicted", dashboard_payload["data"]["topics"][1]["state"])
        self.assertEqual(
            f"/research/{self.research_id}",
            dashboard_payload["data"]["topics"][0]["page_url"],
        )
        conditional = self.client.get(
            "/api/v1/dashboard",
            headers={"If-None-Match": dashboard.headers["ETag"]},
        )
        self.assertEqual(304, conditional.status_code)

        search = self.client.get("/api/v1/search", query_string={"q": "omega-signal"})
        search_payload = self.assert_envelope(search, status=200)
        self.assertEqual(1, len(search_payload["data"]["results"]))
        self.assertEqual(self.research_id, search_payload["data"]["results"][0]["research_id"])

        detail = self.client.get(f"/api/v1/research/{self.research_id}")
        detail_payload = self.assert_envelope(detail, status=200)
        document = detail_payload["data"]["research"]["documents"][0]
        self.assertIn('class="table-scroll"', document["rendered_html"])
        self.assertIn('class="math math-display"', document["rendered_html"])
        self.assertNotIn("<script>", document["rendered_html"])
        self.assertIn("ETag", detail.headers)

        landing = self.client.get(f"/research/{self.research_id}")
        landing_html = landing.get_data(as_text=True)
        child_url = f"/research/{self.research_id}/documents/{self.document_id}"
        self.assertEqual(200, landing.status_code)
        self.assertNotIn("研究三轴状态", landing_html)
        self.assertNotIn("工作状态", landing_html)
        self.assertEqual(0, landing_html.count('class="research-document"'))
        self.assertIn("子研究文档", landing_html)
        self.assertIn(child_url, landing_html)
        self.assertNotIn('class="table-scroll"', landing_html)
        self.assertNotIn('id="citation-dialog"', landing_html)

        child = self.client.get(child_url)
        child_html = child.get_data(as_text=True)
        self.assertEqual(200, child.status_code)
        self.assertEqual(1, child_html.count('class="research-document"'))
        self.assertIn("原文、哈希与证据定位保持不变", child_html)
        self.assertIn('class="table-scroll"', child_html)
        self.assertIn('class="math math-display"', child_html)
        self.assertIn("下载原始 Markdown", child_html)
        self.assertIn('id="citation-dialog"', child_html)
        self.assertNotIn("<script>正文中的", child_html)
        self.assertEqual(1, child_html.count("data-document-toc"))
        self.assertIn("当前章节目录", child_html)

        source = self.client.get(
            f"/api/v1/research/{self.research_id}/documents/{self.document_id}/source"
        )
        self.assertEqual(200, source.status_code)
        self.assertEqual(self.source, source.data)
        self.assertEqual("text/markdown", source.mimetype)
        self.assertIn("X-Content-SHA256", source.headers)
        self.assertEqual(
            self.source_before,
            (self.archive / "web-research.md").read_bytes(),
        )

    def test_human_shell_uses_sticky_navigation_clean_cards_and_diagram_enhancement(self) -> None:
        home = self.client.get("/")
        html = home.get_data(as_text=True)
        self.assertEqual(200, home.status_code)
        self.assertNotIn(">API</a>", html)
        self.assertNotIn('class="axis-list axis-list--compact"', html)

        with self.client.get("/static/styles.css") as response:
            styles = response.get_data(as_text=True)
        self.assertIn(".site-header {", styles)
        self.assertIn("position: sticky", styles)
        self.assertIn('"Noto Sans SC"', styles)
        self.assertIn(".research-body .ascii-diagram", styles)
        self.assertIn("overscroll-behavior: contain", styles)
        self.assertIn("contain: layout paint", styles)
        self.assertIn("scroll-margin-top: calc(var(--site-header-offset) + 1rem)", styles)

        with self.client.get("/static/app.js") as response:
            script = response.get_data(as_text=True)
        self.assertIn("looksLikeDiagram", script)
        self.assertIn("createElementNS(svgNamespace, \"svg\")", script)
        self.assertIn("查看原始 ASCII", script)
        self.assertIn("dataset.sourceLength", script)

    def test_comment_commands_are_secure_escaped_idempotent_and_persistent(self) -> None:
        rejected = self.client.post(
            f"/api/v1/research/{self.research_id}/comments",
            json={
                "actor": {"actor_kind": "zhang_zhengze"},
                "content": "不得写入",
            },
            headers={"Idempotency-Key": "web-comment-rejected-0001"},
        )
        self.assert_envelope(rejected, status=403, error="origin_rejected")

        create_key = "web-comment-create-0001"
        body = "评论 <script>alert('xss')</script> 必须保持纯文本"
        display_name = "研究员甲 <img src=x onerror=alert(1)>"
        create_headers = {**self.write_headers, "Idempotency-Key": create_key}
        created = self.client.post(
            f"/api/v1/research/{self.research_id}/comments",
            json={
                "actor": {"actor_kind": "other", "display_name": display_name},
                "content": body,
            },
            headers=create_headers,
        )
        created_payload = self.assert_envelope(created, status=201)
        self.assertEqual("false", created.headers["Idempotency-Replayed"])
        self.assertEqual(body, created_payload["data"]["content"])
        self.assertEqual(1, created_payload["meta"]["revision"])
        etag_v1 = created.headers["ETag"]
        comment_id = created_payload["data"]["comment_id"]

        replay = self.client.post(
            f"/api/v1/research/{self.research_id}/comments",
            json={
                "actor": {"actor_kind": "other", "display_name": display_name},
                "content": body,
            },
            headers=create_headers,
        )
        self.assert_envelope(replay, status=201)
        self.assertEqual("true", replay.headers["Idempotency-Replayed"])
        self.assertEqual(created_payload["data"], replay.get_json()["data"])
        self.assertEqual(etag_v1, replay.headers["ETag"])

        collision = self.client.post(
            f"/api/v1/research/{self.research_id}/comments",
            json={
                "actor": {"actor_kind": "other", "display_name": display_name},
                "content": "不同载荷",
            },
            headers=create_headers,
        )
        self.assert_envelope(collision, status=409, error="idempotency_conflict")

        comments = self.client.get(f"/api/v1/research/{self.research_id}/comments")
        comments_payload = self.assert_envelope(comments, status=200)
        self.assertEqual(body, comments_payload["data"]["comments"][0]["content"])
        self.assertEqual(etag_v1, comments_payload["data"]["comments"][0]["etag"])

        page = self.client.get(f"/research/{self.research_id}").get_data(as_text=True)
        self.assertNotIn("<script>alert('xss')</script>", page)
        self.assertNotIn("<img src=x onerror=alert(1)>", page)
        self.assertIn("&lt;script&gt;alert", page)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", page)

        missing_precondition = self.client.patch(
            f"/api/v1/comments/{comment_id}",
            json={
                "actor": {"actor_kind": "zhang_zhengze"},
                "content": "修订",
            },
            headers={**self.write_headers, "Idempotency-Key": "web-comment-no-etag-0001"},
        )
        self.assert_envelope(missing_precondition, status=428, error="precondition_required")

        update_headers = {
            **self.write_headers,
            "Idempotency-Key": "web-comment-update-0001",
            "If-Match": etag_v1,
        }
        updated = self.client.patch(
            f"/api/v1/comments/{comment_id}",
            json={
                "actor": {"actor_kind": "song_dingkun"},
                "content": "修订后的纯文本",
            },
            headers=update_headers,
        )
        updated_payload = self.assert_envelope(updated, status=200)
        self.assertEqual(2, updated_payload["data"]["revision"])
        etag_v2 = updated.headers["ETag"]

        update_replay = self.client.patch(
            f"/api/v1/comments/{comment_id}",
            json={
                "actor": {"actor_kind": "song_dingkun"},
                "content": "修订后的纯文本",
            },
            headers=update_headers,
        )
        self.assert_envelope(update_replay, status=200)
        self.assertEqual("true", update_replay.headers["Idempotency-Replayed"])
        self.assertEqual(etag_v2, update_replay.headers["ETag"])

        stale_headers = {
            **self.write_headers,
            "Idempotency-Key": "web-comment-stale-0001",
            "If-Match": etag_v1,
        }
        stale = self.client.patch(
            f"/api/v1/comments/{comment_id}",
            json={
                "actor": {"actor_kind": "zhang_zhengze"},
                "content": "过时覆盖",
            },
            headers=stale_headers,
        )
        self.assert_envelope(stale, status=409, error="revision_conflict")
        stale_replay = self.client.patch(
            f"/api/v1/comments/{comment_id}",
            json={
                "actor": {"actor_kind": "zhang_zhengze"},
                "content": "过时覆盖",
            },
            headers=stale_headers,
        )
        self.assert_envelope(stale_replay, status=409, error="revision_conflict")
        self.assertEqual("true", stale_replay.headers["Idempotency-Replayed"])

        delete_headers = {
            **self.write_headers,
            "Idempotency-Key": "web-comment-delete-0001",
            "If-Match": etag_v2,
        }
        deleted = self.client.delete(
            f"/api/v1/comments/{comment_id}",
            json={"actor": {"actor_kind": "zhang_zhengze"}},
            headers=delete_headers,
        )
        deleted_payload = self.assert_envelope(deleted, status=200)
        self.assertTrue(deleted_payload["data"]["deleted"])
        self.assertEqual(3, deleted_payload["data"]["revision"])
        delete_replay = self.client.delete(
            f"/api/v1/comments/{comment_id}",
            json={"actor": {"actor_kind": "zhang_zhengze"}},
            headers=delete_headers,
        )
        self.assert_envelope(delete_replay, status=200)
        self.assertEqual("true", delete_replay.headers["Idempotency-Replayed"])

        second_app = create_app(
            self.settings,
            {
                "TESTING": True,
                "SECRET_KEY": "archive-web-reopen-test",
                "TRUSTED_ORIGINS": ("http://localhost",),
            },
        )
        persisted = second_app.test_client().get(
            f"/api/v1/research/{self.research_id}/comments"
        )
        persisted_payload = self.assert_envelope(persisted, status=200)
        self.assertEqual([], persisted_payload["data"]["comments"])
        self.assertEqual(
            self.source_before,
            (self.archive / "web-research.md").read_bytes(),
        )

    def test_validation_unknown_routes_and_precondition_target(self) -> None:
        invalid = self.client.post(
            f"/api/v1/research/{self.research_id}/comments",
            json={
                "actor": {"actor_kind": "other"},
                "content": "无姓名",
                "extra": "forbidden",
            },
            headers={
                **self.write_headers,
                "Idempotency-Key": "web-invalid-comment-0001",
            },
        )
        self.assert_envelope(invalid, status=422, error="validation_error")

        unknown = self.client.get("/api/v1/does-not-exist")
        self.assert_envelope(unknown, status=404, error="route_not_found")
        wrong_method = self.client.post("/api/v1/dashboard")
        self.assert_envelope(wrong_method, status=405, error="method_not_allowed")
        ambiguous_query = self.client.get("/api/v1/search?q=a&query=b")
        self.assert_envelope(ambiguous_query, status=422, error="validation_error")

        created = self.client.post(
            f"/api/v1/research/{self.research_id}/comments",
            json={
                "actor": {"actor_kind": "zhang_zhengze"},
                "content": "ETag target test",
            },
            headers={
                **self.write_headers,
                "Idempotency-Key": "web-etag-target-create-0001",
            },
        )
        payload = self.assert_envelope(created, status=201)
        comment_id = payload["data"]["comment_id"]
        wrong = self.client.patch(
            f"/api/v1/comments/{comment_id}",
            json={
                "actor": {"actor_kind": "zhang_zhengze"},
                "content": "不应执行",
            },
            headers={
                **self.write_headers,
                "Idempotency-Key": "web-etag-target-patch-0001",
                "If-Match": '"comment:cmt_00000000000000000000000000000000:r1"',
            },
        )
        self.assert_envelope(wrong, status=400, error="precondition_target_mismatch")

    def test_controlled_topic_link_and_work_state_http_commands(self) -> None:
        actor = {"actor_kind": "song_dingkun"}
        create_body = {
            "actor": actor,
            "topic_key": "http-controlled-topic",
            "title": "HTTP 受控状态 Topic",
            "manual_order": 30,
        }
        rejected = self.client.post(
            "/api/v1/topics",
            json=create_body,
            headers={"Idempotency-Key": "http-topic-origin-rejected-0001"},
        )
        self.assert_envelope(rejected, status=403, error="origin_rejected")

        create_headers = {
            **self.write_headers,
            "Idempotency-Key": "http-topic-create-0001",
        }
        created = self.client.post(
            "/api/v1/topics",
            json=create_body,
            headers=create_headers,
        )
        created_payload = self.assert_envelope(created, status=201)
        topic_id = created_payload["data"]["topic_id"]
        self.assertEqual("false", created.headers["Idempotency-Replayed"])

        replay = self.client.post(
            "/api/v1/topics",
            json=create_body,
            headers=create_headers,
        )
        replay_payload = self.assert_envelope(replay, status=201)
        self.assertEqual("true", replay.headers["Idempotency-Replayed"])
        self.assertEqual(created_payload["data"], replay_payload["data"])

        collision = self.client.post(
            "/api/v1/topics",
            json={**create_body, "title": "不同载荷"},
            headers=create_headers,
        )
        self.assert_envelope(collision, status=409, error="idempotency_conflict")

        topics = self.client.get("/api/v1/topics")
        topics_payload = self.assert_envelope(topics, status=200)
        self.assertIn(
            topic_id,
            {item["topic_id"] for item in topics_payload["data"]["topics"]},
        )
        self.assertIn("ETag", topics.headers)

        link_body = {
            "actor": actor,
            "research_id": self.research_id,
            "link_kind": "primary",
            "dashboard_primary": True,
            "display_rank": 5,
            "provenance_urn": "qrh:review:http-controlled-link",
        }
        linked = self.client.post(
            f"/api/v1/topics/{topic_id}/research-links",
            json=link_body,
            headers={
                **self.write_headers,
                "Idempotency-Key": "http-topic-link-0001",
            },
        )
        linked_payload = self.assert_envelope(linked, status=200)
        self.assertEqual(self.research_id, linked_payload["data"]["research_id"])

        state_body = {
            "actor": actor,
            "state": "paused",
            "note": "等待新的样本窗口。",
        }
        state_headers = {
            **self.write_headers,
            "Idempotency-Key": "http-topic-state-0001",
        }
        paused = self.client.post(
            f"/api/v1/topics/{topic_id}/state-events",
            json=state_body,
            headers=state_headers,
        )
        paused_payload = self.assert_envelope(paused, status=201)
        self.assertEqual("paused", paused_payload["data"]["state"])
        paused_replay = self.client.post(
            f"/api/v1/topics/{topic_id}/state-events",
            json=state_body,
            headers=state_headers,
        )
        self.assert_envelope(paused_replay, status=201)
        self.assertEqual("true", paused_replay.headers["Idempotency-Replayed"])

        work_body = {
            "actor": actor,
            "state": "in_progress",
            "note": "研究工作继续，完成轴仍由显式 decision 控制。",
        }
        work_headers = {
            **self.write_headers,
            "Idempotency-Key": "http-work-state-0001",
        }
        work = self.client.post(
            f"/api/v1/research/{self.research_id}/work-state-events",
            json=work_body,
            headers=work_headers,
        )
        self.assert_envelope(work, status=201)
        work_replay = self.client.post(
            f"/api/v1/research/{self.research_id}/work-state-events",
            json=work_body,
            headers=work_headers,
        )
        self.assert_envelope(work_replay, status=201)
        self.assertEqual("true", work_replay.headers["Idempotency-Replayed"])

        invalid_state = self.client.post(
            f"/api/v1/topics/{topic_id}/state-events",
            json={"actor": actor, "state": "completed", "extra": "forbidden"},
            headers={
                **self.write_headers,
                "Idempotency-Key": "http-topic-invalid-state-0001",
            },
        )
        self.assert_envelope(invalid_state, status=422, error="validation_error")
        invalid_link = self.client.post(
            f"/api/v1/topics/{topic_id}/research-links",
            json={
                **link_body,
                "link_kind": "supporting",
                "dashboard_primary": True,
            },
            headers={
                **self.write_headers,
                "Idempotency-Key": "http-topic-invalid-link-0001",
            },
        )
        self.assert_envelope(invalid_link, status=422, error="validation_error")
        unexpected_precondition = self.client.post(
            "/api/v1/topics",
            json={**create_body, "topic_key": "unexpected-precondition"},
            headers={
                **self.write_headers,
                "Idempotency-Key": "http-topic-if-match-0001",
                "If-Match": '"invented:r1"',
            },
        )
        self.assert_envelope(
            unexpected_precondition,
            status=400,
            error="unexpected_precondition",
        )

        with archive_connection(self.settings) as connection:
            self.assertEqual(
                1,
                connection.execute(
                    "SELECT count(*) FROM topic_state_event WHERE topic_id=?",
                    (topic_id,),
                ).fetchone()[0],
            )
            self.assertEqual(
                1,
                connection.execute(
                    "SELECT count(*) FROM research_work_state_event "
                    "WHERE research_id=? AND state='in_progress'",
                    (self.research_id,),
                ).fetchone()[0],
            )

    def test_completion_conflict_reviewed_import_and_revocation_projection(self) -> None:
        human_actor = {"actor_kind": "zhang_zhengze"}
        conflict_body = {
            "decision": "completed",
            "research_release_id": "rel_" + "0" * 32,
            "reason": "错误 release 不得完成。",
            "actor": human_actor,
        }
        conflict_headers = {
            **self.write_headers,
            "Idempotency-Key": "http-completion-release-conflict-0001",
        }
        conflict = self.client.post(
            f"/api/v1/research/{self.research_id}/completion-decisions",
            json=conflict_body,
            headers=conflict_headers,
        )
        self.assert_envelope(conflict, status=409, error="release_not_active")
        conflict_replay = self.client.post(
            f"/api/v1/research/{self.research_id}/completion-decisions",
            json=conflict_body,
            headers=conflict_headers,
        )
        conflict_replay_payload = self.assert_envelope(
            conflict_replay,
            status=409,
            error="release_not_active",
        )
        self.assertEqual("true", conflict_replay.headers["Idempotency-Replayed"])
        self.assertEqual(
            conflict.get_json()["error"],
            conflict_replay_payload["error"],
        )

        revoke_body = {
            "decision": "revoked",
            "target_decision_id": self.completion_decision_id,
            "reason": "通过 HTTP 显式撤销旧完成决定。",
            "actor": human_actor,
        }
        revoke_headers = {
            **self.write_headers,
            "Idempotency-Key": "http-completion-revoke-0001",
        }
        revoked = self.client.post(
            f"/api/v1/research/{self.research_id}/completion-decisions",
            json=revoke_body,
            headers=revoke_headers,
        )
        revoked_payload = self.assert_envelope(revoked, status=201)
        self.assertEqual("revoked", revoked_payload["data"]["decision"])
        revoke_replay = self.client.post(
            f"/api/v1/research/{self.research_id}/completion-decisions",
            json=revoke_body,
            headers=revoke_headers,
        )
        self.assert_envelope(revoke_replay, status=201)
        self.assertEqual("true", revoke_replay.headers["Idempotency-Replayed"])

        after_revoke = self.client.get("/api/v1/dashboard").get_json()["data"]["topics"]
        projection = next(item for item in after_revoke if item["topic_id"] == self.topic_id)
        self.assertEqual("planned", projection["state"])
        self.assertIsNone(projection["page_url"])

        reviewed_body = {
            "decision": "completed",
            "research_release_id": self.release_id,
            "reason": "冻结候选经独立 reviewer 复核后重新完成。",
            "review_urn": "qrh:review:http-independent-review-0001",
        }
        reviewed_headers = {
            **self.write_headers,
            "Idempotency-Key": "http-completion-reviewed-0001",
        }
        reviewed = self.client.post(
            f"/api/v1/research/{self.research_id}/completion-decisions",
            json=reviewed_body,
            headers=reviewed_headers,
        )
        self.assert_envelope(reviewed, status=409, error="review_certificate_invalid")
        reviewed_replay = self.client.post(
            f"/api/v1/research/{self.research_id}/completion-decisions",
            json=reviewed_body,
            headers=reviewed_headers,
        )
        self.assert_envelope(
            reviewed_replay, status=409, error="review_certificate_invalid"
        )
        self.assertEqual("true", reviewed_replay.headers["Idempotency-Replayed"])

        after_review = self.client.get("/api/v1/dashboard").get_json()["data"]["topics"]
        projection = next(item for item in after_review if item["topic_id"] == self.topic_id)
        self.assertEqual("planned", projection["state"])

        recompleted = self.client.post(
            f"/api/v1/research/{self.research_id}/completion-decisions",
            json={
                "decision": "completed",
                "research_release_id": self.release_id,
                "reason": "由明确的人类操作者重新确认当前 release。",
                "actor": human_actor,
            },
            headers={
                **self.write_headers,
                "Idempotency-Key": "http-completion-human-recomplete-0001",
            },
        )
        self.assert_envelope(recompleted, status=201)
        after_human = self.client.get("/api/v1/dashboard").get_json()["data"]["topics"]
        projection = next(item for item in after_human if item["topic_id"] == self.topic_id)
        self.assertEqual("completed", projection["state"])

        authority_conflict = self.client.post(
            f"/api/v1/research/{self.research_id}/completion-decisions",
            json={**reviewed_body, "actor": human_actor},
            headers={
                **self.write_headers,
                "Idempotency-Key": "http-completion-invalid-authority-0001",
            },
        )
        self.assert_envelope(authority_conflict, status=422, error="validation_error")

        collision = self.client.post(
            f"/api/v1/research/{self.research_id}/completion-decisions",
            json={**reviewed_body, "reason": "不同载荷"},
            headers=reviewed_headers,
        )
        self.assert_envelope(collision, status=409, error="idempotency_conflict")

        with archive_connection(self.settings) as connection:
            reviewed_count = connection.execute(
                "SELECT count(*) FROM research_completion_decision "
                "WHERE decision_kind='reviewed_import'"
            ).fetchone()[0]
            self.assertEqual(0, reviewed_count)


if __name__ == "__main__":
    import unittest

    unittest.main()
