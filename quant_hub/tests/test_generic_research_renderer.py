from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from unittest.mock import Mock, patch

from quant_hub.app import create_app
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
        # The public checkout deliberately excludes the private, generated
        # legacy presentation bundle.  This test only exercises the isolated
        # generic namespace, so inject empty legacy projections instead of
        # accidentally making CI depend on ignored business content.
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


if __name__ == "__main__":
    unittest.main()
