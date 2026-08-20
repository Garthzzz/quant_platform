from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import tempfile
import unittest

from quant_hub.knowledge import (
    ReferenceCompiler,
    SourcePolicy,
    TombstoneDirective,
    build_document_ir,
    validate_snapshot,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SourcePolicyTests(unittest.TestCase):
    def test_default_publishable_is_independent_from_external_ai(self) -> None:
        policy = SourcePolicy()
        normal = policy.evaluate("Q7/new-research.md", b"# Research\n")
        blocked = policy.evaluate("no_external_ai/new-research.md", b"# Research\n")
        supporting = policy.evaluate("README.md", b"# Guide\n")

        self.assertTrue(normal.publishable)
        self.assertTrue(normal.external_ai_allowed)
        self.assertTrue(blocked.publishable)
        self.assertFalse(blocked.external_ai_allowed)
        self.assertEqual("supporting", supporting.source_class)

    def test_reserved_private_secret_and_identity_are_quarantined(self) -> None:
        policy = SourcePolicy()
        self.assertEqual(
            "quarantine", policy.evaluate("_draft/x.md", b"# X\n").source_class
        )
        self.assertEqual(
            "quarantine", policy.evaluate("Q/private-note.md", b"# X\n").source_class
        )
        synthetic_secret = b"api_key = \"" + (b"s" * 24) + b"\"\n"
        secret = policy.evaluate("Q/x.md", b"# X\n" + synthetic_secret)
        ambiguous = policy.evaluate("Q/x.md", b"# X\n", identity_ambiguous=True)
        self.assertEqual("quarantine", secret.source_class)
        self.assertEqual("quarantine", ambiguous.source_class)


class DeterministicIRTests(unittest.TestCase):
    def test_ir_binds_structural_blocks_and_occurrences_to_source_bytes(self) -> None:
        citation_id = "cit_" + ("a" * 52)
        source = (
            "# 方法标题\n\n"
            "说明 $x_t = r_t$，见 [论文](https://example.test/paper)。\n\n"
            "$$\n\\sum_i w_i r_i\n$$\n\n"
            "| 因子 | 值 |\n|:--|--:|\n| A | 1 |\n\n"
            "```python\nprint('factor')\n```\n\n"
            "![收益图](assets/pnl.png)\n\n"
            f"证据 ^src:{{{citation_id}}}\n"
        ).encode("utf-8")
        digest = hashlib.sha256(source).hexdigest()
        ir, rendered = build_document_ir(
            source,
            document_id="doc_" + ("1" * 32),
            document_version_id="ver_" + ("2" * 32),
            logical_path="Q/new.md",
        )

        self.assertEqual(digest, ir.source_sha256)
        self.assertEqual("方法标题", ir.title)
        self.assertIn('class="table-scroll"', rendered)
        kinds = {block.kind for block in ir.blocks}
        self.assertTrue({"heading", "paragraph", "math", "table", "code"} <= kinds)
        span_kinds = {span.kind for block in ir.blocks for span in block.spans}
        self.assertTrue({"math", "link", "figure_ref", "citation"} <= span_kinds)
        for block in ir.blocks:
            raw = source[block.source_span.byte_start : block.source_span.byte_end]
            self.assertEqual(block.source_span.text_sha256, hashlib.sha256(raw).hexdigest())
            self.assertEqual(digest, block.source_span.source_sha256)

    def test_bare_urls_have_exact_nonduplicated_link_spans_without_legacy_linkify(self) -> None:
        source = (
            "# Sources\n\n"
            "裸源 https://example.test/paper?id=1。\n"
            "[显式](https://example.test/linked) 与 "
            "[https://example.test/label](https://example.test/destination)。\n"
            "![图](https://example.test/figure.png)\n"
            "`https://example.test/code`\n"
            "<https://example.test/auto>\n"
            "括号 https://example.test/a_(b).\n"
        ).encode("utf-8")
        ir, legacy_rendered = build_document_ir(
            source,
            document_id="doc_" + ("3" * 32),
            document_version_id="ver_" + ("4" * 32),
            logical_path="Q/sources.md",
        )
        links = [span for block in ir.blocks for span in block.spans if span.kind == "link"]
        targets = [span.attributes["target"] for span in links]
        self.assertCountEqual(
            [
                "https://example.test/paper?id=1",
                "https://example.test/linked",
                "https://example.test/destination",
                "https://example.test/auto",
                "https://example.test/a_(b)",
            ],
            targets,
        )
        self.assertEqual(len(targets), len(set(targets)))
        self.assertNotIn("https://example.test/code", targets)
        self.assertNotIn("https://example.test/figure.png", targets)
        for span in links:
            self.assertEqual("exact", span.attributes["locator_precision"])
            self.assertEqual(span.attributes["target"], source[span.byte_start : span.byte_end].decode("utf-8"))
            self.assertTrue(span.attributes["external"])
        # The IR addition does not turn on linkify or change the established
        # renderer's contract for bare source text.
        self.assertNotIn('href="https://example.test/paper?id=1"', legacy_rendered)

    def test_oversized_atomic_blocks_use_parent_children_without_cutting_citation(self) -> None:
        citation_id = "cit_" + ("b" * 52)
        source = (
            "# Chunk\n\n"
            + "很长段落" * 80
            + f" ^src:{{{citation_id}}} "
            + "继续论证" * 80
            + "\n\n```text\n"
            + ("0123456789" * 80)
            + "\n```\n"
        ).encode("utf-8")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "long.md").write_bytes(source)
            report = ReferenceCompiler(max_chunk_bytes=160).compile(root)
        self.assertEqual("PASS", report.status, report)
        assert report.candidate_snapshot is not None
        chunks = tuple(report.candidate_snapshot.chunks.values())
        self.assertTrue(any(chunk.role == "parent" for chunk in chunks))
        self.assertTrue(any(chunk.role == "child" for chunk in chunks))
        citation_chunks = [chunk for chunk in chunks if citation_id in chunk.text]
        self.assertEqual(1, len(citation_chunks))
        self.assertEqual("child", citation_chunks[0].role)
        parent_ids = {chunk.chunk_id for chunk in chunks if chunk.role == "parent"}
        self.assertTrue(
            all(chunk.parent_chunk_id in parent_ids for chunk in chunks if chunk.role == "child")
        )


class ReferenceCompilerLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_revision_move_absence_and_explicit_tombstone_history(self) -> None:
        source = self.root / "factor.md"
        source.write_text("# 因子\n\n第一版。\n", encoding="utf-8")
        first = ReferenceCompiler().compile(self.root)
        self.assertEqual("PASS", first.status)
        assert first.candidate_snapshot is not None
        first_snapshot = first.candidate_snapshot
        document_id = next(iter(first_snapshot.active_membership))
        first_version = first_snapshot.active_membership[document_id]

        unchanged = ReferenceCompiler().compile(self.root, previous=first_snapshot)
        self.assertEqual(("factor.md",), unchanged.reused_paths)
        assert unchanged.candidate_snapshot is not None
        self.assertEqual(first_snapshot.snapshot_id, unchanged.candidate_snapshot.snapshot_id)

        source.write_text("# 因子\n\n第二版。\n", encoding="utf-8")
        revised = ReferenceCompiler().compile(self.root, previous=first_snapshot)
        self.assertEqual(("factor.md",), revised.compiled_paths)
        assert revised.candidate_snapshot is not None
        second_snapshot = revised.candidate_snapshot
        second_version = second_snapshot.active_membership[document_id]
        self.assertNotEqual(first_version, second_version)
        self.assertEqual(first_version, second_snapshot.versions[second_version].supersedes)

        moved_path = self.root / "renamed.md"
        source.rename(moved_path)
        moved = ReferenceCompiler().compile(self.root, previous=second_snapshot)
        assert moved.candidate_snapshot is not None
        self.assertEqual(("renamed.md",), moved.reused_paths)
        self.assertEqual(second_version, moved.candidate_snapshot.active_membership[document_id])
        self.assertEqual(
            ("factor.md", "renamed.md"), moved.candidate_snapshot.documents[document_id].aliases
        )

        moved_path.unlink()
        absent = ReferenceCompiler().compile(self.root, previous=moved.candidate_snapshot)
        assert absent.candidate_snapshot is not None
        self.assertEqual(second_version, absent.candidate_snapshot.active_membership[document_id])
        self.assertTrue(any("without tombstone" in note for note in absent.notes))

        tombstoned = ReferenceCompiler().compile(
            self.root,
            previous=absent.candidate_snapshot,
            tombstones=(TombstoneDirective(document_id, "研究已由新版方法替代"),),
        )
        assert tombstoned.candidate_snapshot is not None
        self.assertNotIn(document_id, tombstoned.candidate_snapshot.active_membership)
        self.assertEqual("tombstoned", tombstoned.candidate_snapshot.documents[document_id].status)
        self.assertIn(first_version, tombstoned.candidate_snapshot.versions)
        self.assertIn(second_version, tombstoned.candidate_snapshot.versions)

    def test_changed_document_only_and_compile_failure_retains_prior_active(self) -> None:
        (self.root / "a.md").write_text("# A\n\none\n", encoding="utf-8")
        (self.root / "b.md").write_text("# B\n\ntwo\n", encoding="utf-8")
        initial = ReferenceCompiler().compile(self.root)
        assert initial.candidate_snapshot is not None
        prior = initial.candidate_snapshot
        a_id = next(
            document_id
            for document_id, record in prior.documents.items()
            if record.canonical_path == "a.md"
        )
        old_a = prior.active_membership[a_id]
        (self.root / "a.md").write_text("# A\n\nchanged\n", encoding="utf-8")

        def fail_changed(source_bytes: bytes, **kwargs):
            if b"changed" in source_bytes:
                raise ValueError("synthetic deterministic parser failure")
            return build_document_ir(source_bytes, **kwargs)

        failed = ReferenceCompiler(ir_builder=fail_changed).compile(self.root, previous=prior)
        self.assertEqual("PARTIAL", failed.status)
        self.assertEqual(("b.md",), failed.reused_paths)
        self.assertEqual(("a.md",), failed.retained_prior_paths)
        assert failed.candidate_snapshot is not None
        self.assertEqual(old_a, failed.candidate_snapshot.active_membership[a_id])
        self.assertEqual(prior.page_membership[a_id], failed.candidate_snapshot.page_membership[a_id])
        validate_snapshot(failed.candidate_snapshot)

        repaired = ReferenceCompiler().compile(self.root, previous=failed.candidate_snapshot)
        self.assertEqual(("a.md",), repaired.compiled_paths)
        self.assertEqual(("b.md",), repaired.reused_paths)
        assert repaired.candidate_snapshot is not None
        self.assertNotEqual(old_a, repaired.candidate_snapshot.active_membership[a_id])

    def test_real_structure_failure_keeps_previous_page_chunk_and_index_identity(self) -> None:
        source = self.root / "method.md"
        source.write_text("# Valid method\n\nusable evidence\n", encoding="utf-8")
        first = ReferenceCompiler().compile(self.root)
        assert first.candidate_snapshot is not None
        prior = first.candidate_snapshot
        source.write_text("paragraph without any heading\n", encoding="utf-8")

        failed = ReferenceCompiler().compile(self.root, previous=prior)
        self.assertEqual("PARTIAL", failed.status)
        self.assertTrue(any(item.code == "invalid_structure" for item in failed.quarantined))
        assert failed.candidate_snapshot is not None
        self.assertEqual(prior.snapshot_id, failed.candidate_snapshot.snapshot_id)
        self.assertEqual(prior.page_membership_hash, failed.candidate_snapshot.page_membership_hash)
        self.assertEqual(prior.chunk_membership_hash, failed.candidate_snapshot.chunk_membership_hash)
        self.assertEqual(prior.lexical_membership_hash, failed.candidate_snapshot.lexical_membership_hash)

    def test_ambiguous_pure_move_and_move_with_revision_are_quarantined(self) -> None:
        duplicate = "# Same\n\nidentical\n"
        (self.root / "a.md").write_text(duplicate, encoding="utf-8")
        (self.root / "b.md").write_text(duplicate, encoding="utf-8")
        initial = ReferenceCompiler().compile(self.root)
        assert initial.candidate_snapshot is not None
        prior = initial.candidate_snapshot
        (self.root / "a.md").unlink()
        (self.root / "b.md").unlink()
        (self.root / "c.md").write_text(duplicate, encoding="utf-8")
        ambiguous = ReferenceCompiler().compile(self.root, previous=prior)
        self.assertTrue(any(item.code == "pure_move_identity_ambiguous" for item in ambiguous.quarantined))

        document_id = next(iter(prior.documents))
        (self.root / "c.md").write_text("# Same\n\nrevised while moving\n", encoding="utf-8")
        claimed = ReferenceCompiler().compile(
            self.root, previous=prior, identity_claims={"c.md": document_id}
        )
        self.assertTrue(any(item.code == "move_with_revision_unapproved" for item in claimed.quarantined))

    def test_no_external_ai_document_enters_base_snapshot_as_blocked(self) -> None:
        folder = self.root / "no_external_ai"
        folder.mkdir()
        (folder / "safe.md").write_text("# Internal-safe deterministic page\n", encoding="utf-8")
        report = ReferenceCompiler().compile(self.root)
        self.assertEqual("PASS", report.status)
        assert report.candidate_snapshot is not None
        version_id = next(iter(report.candidate_snapshot.active_membership.values()))
        self.assertFalse(report.candidate_snapshot.external_ai_membership[version_id]["allowed"])
        self.assertEqual(
            "blocked_policy", report.candidate_snapshot.knowledge_status_membership[version_id]
        )


class RealQ5ReadOnlyAcceptanceTests(unittest.TestCase):
    EXPECTED_SHA256 = "4994d1df74414fdadfefb7ba812c3851ef26fd82c36bc7f174c7db577e756679"

    def test_q5_bytes_are_copied_outside_reference_before_compilation(self) -> None:
        project_root = Path(__file__).resolve().parents[2]
        original = project_root / "reference" / "archive" / "Q5" / "低SNR横截面选股_因子历史表示与压缩研究_结构重构扩展版.md"
        if not original.is_file():
            self.skipTest("public source checkout intentionally excludes reference content")
        before = _sha256(original)
        self.assertEqual(self.EXPECTED_SHA256, before)
        try:
            with tempfile.TemporaryDirectory() as directory:
                isolated = Path(directory)
                copied = isolated / "generic-renderer-acceptance.md"
                shutil.copyfile(original, copied)
                self.assertEqual(before, _sha256(copied))
                report = ReferenceCompiler(max_chunk_bytes=2400).compile(isolated)
                self.assertEqual("PASS", report.status, report.quarantined)
                assert report.candidate_snapshot is not None
                ir = next(iter(report.candidate_snapshot.ir_documents.values()))
                self.assertGreaterEqual(len([block for block in ir.blocks if block.kind == "heading"]), 300)
                self.assertTrue(any(block.kind == "table" for block in ir.blocks))
                self.assertTrue(any(block.kind == "code" for block in ir.blocks))
                self.assertTrue(any(block.kind == "math" for block in ir.blocks))
                bare_links = [
                    span
                    for block in ir.blocks
                    for span in block.spans
                    if span.kind == "link" and span.attributes.get("bare") is True
                ]
                self.assertGreater(len(bare_links), 0)
                for span in bare_links:
                    self.assertTrue(span.text.startswith(("http://", "https://")))
                    self.assertEqual(span.text, span.attributes["target"])
                    self.assertEqual("exact", span.attributes["locator_precision"])
        finally:
            self.assertEqual(before, _sha256(original))


if __name__ == "__main__":
    unittest.main()
