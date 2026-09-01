from __future__ import annotations

from contextlib import closing, contextmanager
from dataclasses import replace
import hashlib
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

from quant_hub.app import create_app
from quant_hub.config import ConfigurationError
from quant_hub.generic_research import (
    GenericCatalogError,
    GenericKnowledgeCard,
    GenericResearchCatalog,
)
from quant_hub.knowledge import ReferenceCompiler, SourcePolicy
from quant_hub.knowledge.compiler import _assemble_snapshot
from tests.helpers import SettingsTestCase


PROJECT_ROOT = Path(__file__).resolve().parents[2]
Q5_SHA256 = "4994d1df74414fdadfefb7ba812c3851ef26fd82c36bc7f174c7db577e756679"
LEGACY_FILES = (
    "quant_hub/src/quant_hub/web/routes.py",
    "quant_hub/src/quant_hub/web/templates/base.html",
    "quant_hub/src/quant_hub/web/templates/home.html",
    "quant_hub/src/quant_hub/web/templates/research.html",
    "quant_hub/src/quant_hub/web/templates/research_document.html",
    "quant_hub/src/quant_hub/web/static/styles.css",
    "quant_hub/src/quant_hub/web/static/app.js",
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _legacy_hashes() -> dict[str, str]:
    return {
        path: _sha256_bytes((PROJECT_ROOT / path).read_bytes()) for path in LEGACY_FILES
    }


@contextmanager
def _generic_only_legacy_shell():
    """Keep generic-route CI independent of the private legacy projection.

    ``archive_presentation.json`` and chapter manifests are release-bound
    business content and are deliberately absent from a Public Git checkout.
    These tests never visit a legacy route, so they inject the smallest empty
    legacy read shell rather than weakening production's fail-closed manifest
    requirement or checking private content into Git.
    """

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
        yield


def _ready_snapshot(snapshot):
    versions = {
        version_id: replace(version, knowledge_status="ready")
        for version_id, version in snapshot.versions.items()
    }
    return _assemble_snapshot(
        policy=SourcePolicy(),
        documents=dict(snapshot.documents),
        versions=versions,
        ir_documents=dict(snapshot.ir_documents),
        chunks=dict(snapshot.chunks),
        active_external={
            version_id: dict(value)
            for version_id, value in snapshot.external_ai_membership.items()
        },
        active_knowledge={
            version_id: "ready" for version_id in snapshot.knowledge_status_membership
        },
    )


class GenericCatalogContractTests(unittest.TestCase):
    def test_catalog_rejects_source_or_unaccepted_knowledge_identity_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = b"# Method\n\nUse only after a verified liquidity condition.\n"
            (root / "method.md").write_bytes(source)
            report = ReferenceCompiler().compile(root)
        assert report.candidate_snapshot is not None
        snapshot = report.candidate_snapshot
        version_id = next(iter(snapshot.active_membership.values()))
        document_id = next(iter(snapshot.active_membership))
        digest = _sha256_bytes(source)
        with self.assertRaisesRegex(GenericCatalogError, "key does not match"):
            GenericResearchCatalog(snapshot, {digest: source + b"tampered"})

        paragraph = next(
            block
            for block in snapshot.ir_documents[version_id].blocks
            if block.kind == "paragraph"
        )
        card = GenericKnowledgeCard(
            knowledge_id="kn_test_condition",
            kind="condition",
            title="Liquidity gate",
            statement="Apply only after the source-bound liquidity condition passes.",
            evidence_span_ids=(paragraph.source_span.span_id,),
            acceptance="mechanically_verified",
        )
        with self.assertRaisesRegex(GenericCatalogError, "ready snapshot"):
            GenericResearchCatalog(
                snapshot,
                {digest: source},
                accepted_knowledge={version_id: (card,)},
            )

        ready = _ready_snapshot(snapshot)
        catalog = GenericResearchCatalog(
            ready,
            {digest: source},
            accepted_knowledge={version_id: (card,)},
        )
        page = catalog.page(document_id)
        self.assertEqual("ready", page.knowledge_status)
        self.assertEqual(
            paragraph.source_span.span_id,
            page.knowledge_cards[0].evidence_span_ids[0],
        )

    def test_heading_span_can_anchor_accepted_knowledge(self) -> None:
        source = b"# Evidence heading\n\nBody evidence.\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "heading.md").write_bytes(source)
            report = ReferenceCompiler().compile(root)
        assert report.candidate_snapshot is not None
        snapshot = _ready_snapshot(report.candidate_snapshot)
        document_id, version_id = next(iter(snapshot.active_membership.items()))
        heading = next(
            block
            for block in snapshot.ir_documents[version_id].blocks
            if block.kind == "heading"
        )
        card = GenericKnowledgeCard(
            knowledge_id="kn_heading_evidence",
            kind="summary",
            title="Heading evidence",
            statement="The accepted statement is anchored to the heading span.",
            evidence_span_ids=(heading.source_span.span_id,),
            acceptance="mechanically_verified",
        )
        catalog = GenericResearchCatalog(
            snapshot,
            {_sha256_bytes(source): source},
            accepted_knowledge={version_id: (card,)},
        )

        page = catalog.page(document_id)

        self.assertEqual(
            heading.source_span.span_id,
            page.knowledge_evidence[card.knowledge_id][0].span_id,
        )

    def test_current_and_history_are_selected_from_one_snapshot_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "factor.md"
            first_bytes = b"# Factor\n\nVersion one.\n"
            path.write_bytes(first_bytes)
            first = ReferenceCompiler().compile(root)
            assert first.candidate_snapshot is not None
            first_snapshot = first.candidate_snapshot
            document_id, first_version = next(
                iter(first_snapshot.active_membership.items())
            )
            second_bytes = b"# Factor\n\nVersion two with a changed condition.\n"
            path.write_bytes(second_bytes)
            second = ReferenceCompiler().compile(root, previous=first_snapshot)
        assert second.candidate_snapshot is not None
        snapshot = second.candidate_snapshot
        second_version = snapshot.active_membership[document_id]
        catalog = GenericResearchCatalog(
            snapshot,
            {
                _sha256_bytes(first_bytes): first_bytes,
                _sha256_bytes(second_bytes): second_bytes,
            },
        )

        current = catalog.page(document_id)
        history = catalog.page(document_id, first_version)
        self.assertEqual(second_version, current.version_id)
        self.assertTrue(current.is_current)
        self.assertFalse(history.is_current)
        self.assertIn("Version one", history.rendered_html)
        self.assertEqual(
            [second_version, first_version],
            [version.version_id for version in current.versions],
        )


class GenericInternalLinkTests(SettingsTestCase):
    def test_relative_markdown_link_redirects_to_generic_document_page(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / "folder"
            folder.mkdir()
            first_source = b"# First\n\n[Second](second.md)\n"
            second_source = b"# Second\n\nResolved target.\n"
            (folder / "first.md").write_bytes(first_source)
            (folder / "second.md").write_bytes(second_source)
            report = ReferenceCompiler().compile(root)
        assert report.candidate_snapshot is not None
        snapshot = report.candidate_snapshot
        by_path = {
            record.canonical_path: document_id
            for document_id, record in snapshot.documents.items()
        }
        first_id = by_path["folder/first.md"]
        second_id = by_path["folder/second.md"]
        first_version_id = snapshot.active_membership[first_id]
        catalog = GenericResearchCatalog(
            snapshot,
            {
                _sha256_bytes(first_source): first_source,
                _sha256_bytes(second_source): second_source,
            },
        )
        with _generic_only_legacy_shell():
            app = create_app(
                self.settings,
                {"TESTING": True, "GENERIC_RESEARCH_CATALOG": catalog},
            )
        app.extensions["archive_catalog"] = None

        client = app.test_client()
        page = client.get(f"/knowledge/research/{first_id}/")
        self.assertEqual(200, page.status_code)
        self.assertIn(
            f"/knowledge/link/{first_id}/{first_version_id}",
            page.get_data(as_text=True),
        )
        redirect_response = client.get(
            f"/knowledge/research/{first_id}/second.md"
        )
        self.assertEqual(302, redirect_response.status_code)
        self.assertTrue(
            redirect_response.headers["Location"].endswith(
                f"/knowledge/research/{second_id}/"
            )
        )
        resolved = client.get(
            f"/knowledge/research/{first_id}/second.md", follow_redirects=True
        )
        self.assertEqual(200, resolved.status_code)
        self.assertIn("Resolved target", resolved.get_data(as_text=True))

        proxied = client.get(
            f"/knowledge/link/{first_id}/{first_version_id}",
            query_string={"kind": "href", "target": "second.md"},
            follow_redirects=True,
        )
        self.assertEqual(200, proxied.status_code)
        self.assertIn("Resolved target", proxied.get_data(as_text=True))

        unavailable_asset = client.get(
            f"/knowledge/link/{first_id}/{first_version_id}",
            query_string={"kind": "src", "target": "missing.png"},
        )
        self.assertEqual(200, unavailable_asset.status_code)
        self.assertEqual("image/svg+xml", unavailable_asset.mimetype)


class RealQ5GenericRendererAcceptanceTests(SettingsTestCase):
    def test_q5_byte_exact_copy_is_automatic_structured_page_and_legacy_is_unchanged(self) -> None:
        q5 = (
            PROJECT_ROOT
            / "reference"
            / "archive"
            / "Q5"
            / "低SNR横截面选股_因子历史表示与压缩研究_结构重构扩展版.md"
        )
        if not q5.is_file():
            self.skipTest("public source checkout intentionally excludes reference content")
        legacy_before = _legacy_hashes()
        original_before = q5.read_bytes()
        self.assertEqual(Q5_SHA256, _sha256_bytes(original_before))

        with tempfile.TemporaryDirectory() as directory:
            intake = Path(directory) / "isolated-acceptance-source"
            intake.mkdir()
            copied = intake / "generic-renderer-acceptance.md"
            shutil.copyfile(q5, copied)
            self.assertEqual(original_before, copied.read_bytes())
            report = ReferenceCompiler(max_chunk_bytes=2400).compile(intake)
            self.assertEqual("PASS", report.status, report.quarantined)
            assert report.candidate_snapshot is not None
            snapshot = _ready_snapshot(report.candidate_snapshot)
            document_id, version_id = next(iter(snapshot.active_membership.items()))
            ir = snapshot.ir_documents[version_id]
            evidence_block = next(
                block
                for block in ir.blocks
                if block.kind == "paragraph"
                and "方法" in block.text
                and 20 <= len(block.text) <= 1_000
            )
            card = GenericKnowledgeCard(
                knowledge_id="kn_q5_acceptance_method",
                kind="method",
                title="原文绑定的方法证据",
                statement=evidence_block.text,
                evidence_span_ids=(evidence_block.source_span.span_id,),
                acceptance="mechanically_verified",
            )
            catalog = GenericResearchCatalog(
                snapshot,
                {Q5_SHA256: copied.read_bytes()},
                accepted_knowledge={version_id: (card,)},
            )
            app = create_app(
                self.settings,
                {
                    "TESTING": True,
                    "SECRET_KEY": "generic-renderer-test-only",
                    "TRUSTED_ORIGINS": ("http://localhost",),
                    "GENERIC_RESEARCH_CATALOG": catalog,
                    "COMMENT_DATABASE_PATH": str(
                        Path(directory) / "external-state" / "comments.sqlite3"
                    ),
                },
            )
            client = app.test_client()
            response = client.get(f"/knowledge/research/{document_id}/")
            self.assertEqual(200, response.status_code)
            html = response.get_data(as_text=True)

            # One generic route handles the fixed, test-only identity.  The
            # source name appears as data, never as a route/template branch.
            self.assertIn(f'data-snapshot-id="{snapshot.snapshot_id}"', html)
            self.assertIn(f'data-document-version-id="{version_id}"', html)
            self.assertGreaterEqual(html.count("qrh-generic__toc-level-"), 300)
            self.assertIn('data-math-rendered="mathml"', html)
            self.assertNotIn('data-math-rendered="fallback"', html)
            self.assertNotIn('class="math math-display math-invalid"', html)
            self.assertIn('class="table-scroll"', html)
            self.assertIn("<pre", html)
            with client.get("/knowledge/assets/generic.css") as css_response:
                self.assertEqual(200, css_response.status_code)
                self.assertIn("overflow-x: auto", css_response.get_data(as_text=True))
            self.assertIn("已验证知识", html)
            self.assertIn("bytes ", html)
            self.assertIn("版本历史", html)
            self.assertIn("当前有效版本", html)
            self.assertIn("https://arxiv.org/abs/physics/0004057", html)
            self.assertRegex(html, r'href="https://arxiv\.org/abs/physics/0004057"')
            self.assertGreaterEqual(html.count("qrh-generic__references"), 1)

            # Pre-registered usability checks: raw Markdown has no generated
            # deep-link TOC, immutable identity, source locator or clickable
            # naked bibliography URL; the generic page provides all four.
            raw = copied.read_text(encoding="utf-8")
            self.assertNotIn('data-snapshot-id="', raw)
            self.assertNotIn('href="#', raw)
            self.assertNotIn('href="https://arxiv.org/abs/physics/0004057"', raw)
            self.assertNotIn("<math", raw)
            self.assertNotIn("<table", raw)
            self.assertNotIn("<pre", raw)
            self.assertIn('href="#', html)
            self.assertIn("<math", html)
            self.assertIn("<table", html)
            self.assertIn("行 ", html)
            fragment_targets = {
                match for match in re.findall(r'\sid="([^"]+)"', html)
            }
            fragment_links = {
                match for match in re.findall(r'href="#([^"]+)"', html)
            }
            self.assertFalse(fragment_links.difference(fragment_targets))

            source_response = client.get(
                f"/knowledge/research/{document_id}/versions/{version_id}/source"
            )
            self.assertEqual(200, source_response.status_code)
            self.assertEqual(original_before, source_response.data)
            history = client.get(
                f"/knowledge/research/{document_id}/versions/{version_id}/"
            )
            self.assertEqual(200, history.status_code)

        css_path = (
            PROJECT_ROOT
            / "quant_hub/src/quant_hub/generic_research/static/generic.css"
        )
        css = css_path.read_text(encoding="utf-8")
        self.assertIn("@media (max-width: 860px)", css)
        self.assertIn("grid-template-columns: minmax(0, 1fr)", css)
        self.assertNotRegex(css, r"(?m)^\.(?:research|site|brand|document)-")
        self.assertEqual(legacy_before, _legacy_hashes())
        self.assertEqual(original_before, q5.read_bytes())


class GenericCitationInteractionTests(SettingsTestCase):
    def test_generic_citation_reuses_trace_dialog_without_changing_legacy_assets(self) -> None:
        citation_id = "cit_" + ("a" * 52)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = f"# Evidence\n\nSource-bound claim ^src:{{{citation_id}}}.\n".encode()
            (root / "evidence.md").write_bytes(source)
            report = ReferenceCompiler().compile(root)
        assert report.candidate_snapshot is not None
        snapshot = report.candidate_snapshot
        document_id, _version_id = next(iter(snapshot.active_membership.items()))
        catalog = GenericResearchCatalog(
            snapshot,
            {_sha256_bytes(source): source},
        )
        with _generic_only_legacy_shell():
            app = create_app(
                self.settings,
                {
                    "TESTING": True,
                    "SECRET_KEY": "generic-citation-test-only",
                    "TRUSTED_ORIGINS": ("http://localhost",),
                    "GENERIC_RESEARCH_CATALOG": catalog,
                },
            )
        response = app.test_client().get(f"/knowledge/research/{document_id}/")
        self.assertEqual(200, response.status_code)
        html = response.get_data(as_text=True)
        self.assertIn(f'data-citation-id="{citation_id}"', html)
        self.assertIn("data-citation-dialog", html)
        self.assertIn("data-endpoint-prefix=\"/api/v1/evidence/citations/\"", html)


class GenericCommentPersistenceAcceptanceTests(SettingsTestCase):
    @staticmethod
    def _database_facts(path: Path) -> dict[str, list[tuple[object, ...]]]:
        with closing(sqlite3.connect(path)) as connection:
            return {
                "comments": connection.execute(
                    "SELECT comment_id,research_id,actor_id,body,created_at,updated_at,revision,deleted_at FROM comment ORDER BY comment_id"
                ).fetchall(),
                "events": connection.execute(
                    "SELECT comment_event_id,comment_id,event_type,old_body_hash,new_body_hash,actor_id,revision,occurred_at FROM comment_event ORDER BY comment_event_id"
                ).fetchall(),
                "targets": connection.execute(
                    "SELECT comment_target_id,comment_id,target_kind,research_id,document_id,origin_document_version_id,origin_source_sha256,origin_start_byte,origin_end_byte,origin_exact_bytes_sha256,origin_structural_context_sha256,origin_locator_json,created_at FROM comment_target ORDER BY comment_id"
                ).fetchall(),
                "actors": connection.execute(
                    "SELECT actor_id,actor_kind,display_name,created_at FROM actor ORDER BY actor_id"
                ).fetchall(),
            }

    def _app(self, catalog: GenericResearchCatalog, database: Path):
        with _generic_only_legacy_shell():
            return create_app(
                self.settings,
                {
                    "TESTING": True,
                    "SECRET_KEY": "generic-comment-test-only",
                    "TRUSTED_ORIGINS": ("http://localhost",),
                    "COMMENT_DATABASE_PATH": str(database),
                    "GENERIC_RESEARCH_CATALOG": catalog,
                },
            )

    @staticmethod
    def _post_comment(client, document_id: str, payload: dict[str, object], key: str):
        page = client.get(f"/knowledge/research/{document_id}/")
        token = re.search(
            r'<meta name="csrf-token" content="([A-Za-z0-9_-]{43})">',
            page.get_data(as_text=True),
        )
        assert token is not None
        return client.post(
            f"/knowledge/research/{document_id}/comments",
            json=payload,
            headers={
                "Origin": "http://localhost",
                "X-CSRF-Token": token.group(1),
                "Idempotency-Key": key,
            },
        )

    def test_nonempty_ui_comments_survive_code_revision_move_and_release_rollback(self) -> None:
        legacy_before = _legacy_hashes()
        database = self.project / "external-state" / "comments.sqlite3"
        with tempfile.TemporaryDirectory() as directory:
            intake = Path(directory) / "intake"
            intake.mkdir()
            source = intake / "factor.md"
            v1 = (
                "# 因子稳定性\n\n"
                "## 方法\n\n收益率必须滞后一日。\n\n"
                "## 限制\n\n旧限制只适用于高流动性样本。\n"
            ).encode("utf-8")
            source.write_bytes(v1)
            first = ReferenceCompiler().compile(intake)
            assert first.candidate_snapshot is not None
            snapshot_v1 = first.candidate_snapshot
            document_id, version_v1 = next(iter(snapshot_v1.active_membership.items()))
            catalog_v1 = GenericResearchCatalog(snapshot_v1, {_sha256_bytes(v1): v1})

            app_v1 = self._app(catalog_v1, database)
            client_v1 = app_v1.test_client()
            html_v1 = client_v1.get(
                f"/knowledge/research/{document_id}/"
            ).get_data(as_text=True)
            self.assertIn("张正泽", html_v1)
            self.assertIn("宋定坤", html_v1)
            self.assertIn("其他", html_v1)
            paragraph_anchor = next(
                option
                for option in catalog_v1.page(document_id).comment_anchor_options
                if "旧限制" in option.label
            )
            document_response = self._post_comment(
                client_v1,
                document_id,
                {
                    "actor_kind": "zhang_zhengze",
                    "display_name": None,
                    "content": "整篇研究的稳定评论。",
                    "version_id": version_v1,
                    "target_kind": "document",
                    "anchor_span_id": None,
                },
                "generic-document-comment-0001",
            )
            self.assertEqual(201, document_response.status_code, document_response.json)
            block_response = self._post_comment(
                client_v1,
                document_id,
                {
                    "actor_kind": "song_dingkun",
                    "display_name": None,
                    "content": "这条限制需要继续核验。",
                    "version_id": version_v1,
                    "target_kind": "block",
                    "anchor_span_id": paragraph_anchor.span_id,
                },
                "generic-block-comment-0001",
            )
            self.assertEqual(201, block_response.status_code, block_response.json)
            before = self._database_facts(database)
            self.assertEqual(2, len(before["comments"]))
            self.assertEqual(2, len(before["events"]))

            # A new code process reopens the same release-external authority.
            reopened = self._app(catalog_v1, database).test_client()
            reopened_html = reopened.get(
                f"/knowledge/research/{document_id}/"
            ).get_data(as_text=True)
            self.assertIn("整篇研究的稳定评论。", reopened_html)
            self.assertIn("这条限制需要继续核验。", reopened_html)
            self.assertEqual(2, reopened_html.count('data-resolution-status="resolved_current"'))

            # Revise the source, then move the unchanged revision.  Compiler
            # history preserves document identity; the old block must not be
            # fuzzy-attached to the semantically similar new text.
            v2 = v1.replace(
                "旧限制只适用于高流动性样本。".encode("utf-8"),
                "新限制只适用于高流动性且低冲击成本样本。".encode("utf-8"),
            )
            source.write_bytes(v2)
            revised = ReferenceCompiler().compile(intake, previous=snapshot_v1)
            assert revised.candidate_snapshot is not None
            snapshot_v2 = revised.candidate_snapshot
            version_v2 = snapshot_v2.active_membership[document_id]
            moved_source = intake / "renamed-factor.md"
            source.rename(moved_source)
            moved = ReferenceCompiler().compile(intake, previous=snapshot_v2)
            assert moved.candidate_snapshot is not None
            snapshot_moved = moved.candidate_snapshot
            self.assertEqual(version_v2, snapshot_moved.active_membership[document_id])
            self.assertIn("renamed-factor.md", snapshot_moved.documents[document_id].aliases)
            catalog_moved = GenericResearchCatalog(
                snapshot_moved,
                {_sha256_bytes(v1): v1, _sha256_bytes(v2): v2},
            )
            moved_client = self._app(catalog_moved, database).test_client()
            current_html = moved_client.get(
                f"/knowledge/research/{document_id}/"
            ).get_data(as_text=True)
            self.assertIn(
                f'data-comment-snapshot-id="{snapshot_moved.snapshot_id}"',
                current_html,
            )
            self.assertRegex(
                current_html, r'data-comment-manifest-sha256="[0-9a-f]{64}"'
            )
            self.assertIn('data-comment-group="unresolved"', current_html)
            self.assertIn('data-resolution-status="unresolved"', current_html)
            self.assertIn("这条限制需要继续核验。", current_html)
            self.assertIn("未解析／历史定位", current_html)
            self.assertIn('data-resolution-status="resolved_current"', current_html)

            history_html = moved_client.get(
                f"/knowledge/research/{document_id}/versions/{version_v1}/"
            ).get_data(as_text=True)
            self.assertIn('data-resolution-status="resolved_history"', history_html)
            self.assertIn("这条限制需要继续核验。", history_html)

            # D-prior code/content rollback selects v1 while retaining current
            # state. Both exact anchors resolve again and no fact/event changes.
            rollback_client = self._app(catalog_v1, database).test_client()
            rollback_html = rollback_client.get(
                f"/knowledge/research/{document_id}/"
            ).get_data(as_text=True)
            self.assertEqual(2, rollback_html.count('data-resolution-status="resolved_current"'))
            self.assertEqual(before, self._database_facts(database))

        self.assertEqual(legacy_before, _legacy_hashes())

    def test_production_generic_catalog_requires_explicit_external_comment_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = b"# Comment config\n\nProduction state is external.\n"
            (root / "config.md").write_bytes(source)
            report = ReferenceCompiler().compile(root)
        assert report.candidate_snapshot is not None
        catalog = GenericResearchCatalog(
            report.candidate_snapshot,
            {_sha256_bytes(source): source},
        )
        with _generic_only_legacy_shell():
            with self.assertRaisesRegex(ConfigurationError, "COMMENT_DATABASE_PATH"):
                create_app(
                    self.settings,
                    {
                        "TESTING": False,
                        "GENERIC_RESEARCH_CATALOG": catalog,
                    },
                )


if __name__ == "__main__":
    unittest.main()
