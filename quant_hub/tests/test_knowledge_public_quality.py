from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from quant_hub.knowledge import ReferenceCompiler
from quant_hub.knowledge.evaluation import bind_qrel_templates, evaluate
from quant_hub.knowledge.retrieval import ArtifactKnowledgeIndex, KnowledgeIndex
from quant_hub.knowledge.semantic import (
    EvidenceBinding,
    KnowledgeItem,
    SemanticJobStore,
    build_enriched_snapshot,
)
from quant_hub.knowledge_mcp.mirror import build_search_artifact


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "public_knowledge_quality"


class PublicKnowledgeQualityTests(unittest.TestCase):
    """Inspectable development evidence; never a sealed release holdout."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        runtime = Path(self.temporary.name)
        source_root = runtime / "sources"
        source_root.mkdir()
        for source in FIXTURE_ROOT.glob("*.md"):
            shutil.copyfile(source, source_root / source.name)
        current_history = (source_root / "history.md").read_bytes()
        (source_root / "history.md").write_bytes(
            (FIXTURE_ROOT / "history_previous.txt").read_bytes()
        )
        previous = ReferenceCompiler().compile(source_root)
        self.assertEqual("PASS", previous.status)
        assert previous.candidate_snapshot is not None
        self.previous_base = previous.candidate_snapshot
        (source_root / "history.md").write_bytes(current_history)
        compiled = ReferenceCompiler().compile(
            source_root, previous=self.previous_base
        )
        self.assertEqual("PASS", compiled.status)
        assert compiled.candidate_snapshot is not None
        self.base = compiled.candidate_snapshot
        store = SemanticJobStore(runtime / "knowledge.sqlite3")
        payload = json.loads(
            (FIXTURE_ROOT / "semantic.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            "qrh-public-development-knowledge/v1", payload["schema_version"]
        )
        documents = {
            row.canonical_path: row for row in self.base.documents.values()
        }
        for ordinal, raw in enumerate(payload["items"], 1):
            document = documents[raw["logical_path"]]
            assert document.active_version_id is not None
            ir = self.base.ir_documents[document.active_version_id]
            matches = [
                block.source_span
                for block in ir.blocks
                if raw["quote"] in block.source_span.text
            ]
            self.assertEqual(1, len(matches), raw)
            span = matches[0]
            character_start = span.text.index(raw["quote"])
            byte_start = span.byte_start + len(
                span.text[:character_start].encode("utf-8")
            )
            quote_bytes = raw["quote"].encode("utf-8")
            store.add_item(
                KnowledgeItem(
                    knowledge_item_id=f"kitm-public-quality-{ordinal:02d}",
                    cluster_id=f"kcl-public-quality-{ordinal:02d}",
                    document_id=document.document_id,
                    document_version_id=document.active_version_id,
                    kind=raw["kind"],
                    text=raw["text"],
                    evidence=(
                        EvidenceBinding(
                            span.span_id,
                            raw["quote"],
                            hashlib.sha256(quote_bytes).hexdigest(),
                            byte_start,
                            byte_start + len(quote_bytes),
                        ),
                    ),
                    applicability={
                        key: tuple(values)
                        for key, values in raw["applicability"].items()
                    },
                    relation=None,
                    fact_status="source_explicit",
                    extractor="public-development-fixture",
                    extractor_version="public-development-fixture/v1",
                    generation_id=None,
                    accepted_at="2026-08-22T00:00:00.000000Z",
                    accepted_by="public-development-fixture",
                )
            )
        self.enriched = build_enriched_snapshot(self.base, store)
        self.index = KnowledgeIndex(self.base, self.enriched)
        self.addCleanup(self.index.close)
        self.artifact_index = ArtifactKnowledgeIndex(
            json.loads(build_search_artifact(self.base, enriched=self.enriched)),
            base=self.base,
        )
        self.addCleanup(self.artifact_index.close)
        self.suite = bind_qrel_templates(FIXTURE_ROOT / "qrels.json", self.base)

    def test_public_development_exact_kind_and_hard_gates(self) -> None:
        direct = evaluate(self.index, self.suite, split="development")
        product = evaluate(self.artifact_index, self.suite, split="development")
        self.assertEqual(13, direct.count)
        self.assertEqual(1.0, direct.recall_at_k, direct)
        self.assertEqual(1.0, direct.no_answer_accuracy, direct)
        self.assertEqual(1.0, direct.citation_accuracy, direct)
        self.assertEqual(0, direct.deprecated_errors, direct)
        self.assertEqual(0, direct.conflict_errors, direct)
        self.assertEqual(0, direct.forbidden_errors, direct)
        self.assertEqual(0, direct.knowledge_kind_errors, direct)
        self.assertEqual(0, direct.citation_errors, direct)
        self.assertGreaterEqual(
            sum(bool(qrel.forbidden_document_ids) for qrel in self.suite.qrels),
            2,
        )
        source_bound_routes = 0
        for qrel in self.suite.development():
            response = self.index.search(qrel.query, context=qrel.context)
            self.assertEqual(
                response,
                self.artifact_index.search(qrel.query, context=qrel.context),
                qrel.qrel_id,
            )
            source_bound_routes += sum(
                any(
                    reason.startswith("route:exact-source-evidence-kind:")
                    for reason in card.hit_reasons
                )
                for card in response.cards
            )
        self.assertGreaterEqual(source_bound_routes, 4)
        for field in (
            "recall_at_k",
            "ndcg_at_k",
            "reciprocal_rank",
            "no_answer_accuracy",
            "citation_accuracy",
            "deprecated_errors",
            "conflict_errors",
            "forbidden_errors",
            "knowledge_kind_errors",
            "citation_errors",
        ):
            self.assertEqual(getattr(direct, field), getattr(product, field), field)

    def test_public_superseded_version_is_hidden_by_default_and_explicit_in_history(self) -> None:
        document = next(
            row
            for row in self.base.documents.values()
            if row.canonical_path == "history.md"
        )
        self.assertEqual(2, len(document.version_ids))
        old_version_id = next(
            value
            for value in document.version_ids
            if value != document.active_version_id
        )
        default = self.index.search("expanding-window harmonic blend")
        self.assertFalse(
            any(card.document_version_id == old_version_id for card in default.cards)
        )
        historical = self.index.search(
            "expanding-window harmonic blend", include_history=True
        )
        old_cards = [
            card
            for card in historical.cards
            if card.document_version_id == old_version_id
        ]
        self.assertTrue(old_cards)
        self.assertTrue(
            all(card.active_status == "superseded" for card in old_cards)
        )
        self.assertEqual(
            default,
            self.artifact_index.search("expanding-window harmonic blend"),
        )
        self.assertEqual(
            historical,
            self.artifact_index.search(
                "expanding-window harmonic blend", include_history=True
            ),
        )

    def test_public_adversarial_named_requests_remain_fail_closed(self) -> None:
        for query in (
            "Analyze Heston CVA calibration",
            "Estimate convenience yield for this strategy",
            "APPLY Avellaneda-Stoikov market making",
        ):
            response = self.index.search(query)
            self.assertFalse(response.answerable, query)
            self.assertEqual((), response.cards, query)
            self.assertIn("named_anchor:", response.no_answer_reason or "", query)

    def test_exact_source_kind_bridge_is_bound_to_its_own_evidence_span(self) -> None:
        source_root = Path(self.temporary.name) / "span-bridge-sources"
        source_root.mkdir()
        source = (
            FIXTURE_ROOT / "adversarial" / "span_bridge.md"
        )
        shutil.copyfile(source, source_root / source.name)
        compiled = ReferenceCompiler(max_chunk_bytes=256).compile(source_root)
        self.assertEqual("PASS", compiled.status)
        assert compiled.candidate_snapshot is not None
        base = compiled.candidate_snapshot
        document = next(iter(base.documents.values()))
        assert document.active_version_id is not None
        ir = base.ir_documents[document.active_version_id]
        evidence_block, inline_span = next(
            (block, span)
            for block in ir.blocks
            for span in block.spans
            if span.kind == "inline_code"
        )
        quote = inline_span.text
        store = SemanticJobStore(Path(self.temporary.name) / "span-bridge.sqlite3")
        store.add_item(
            KnowledgeItem(
                knowledge_item_id="kitm-public-span-bridge",
                cluster_id="kcl-public-span-bridge",
                document_id=document.document_id,
                document_version_id=document.active_version_id,
                kind="limitation",
                text="受控异常值策略存在明确边界。",
                evidence=(
                    EvidenceBinding(
                        evidence_block.source_span.span_id,
                        quote,
                        hashlib.sha256(quote.encode("utf-8")).hexdigest(),
                        inline_span.byte_start,
                        inline_span.byte_end,
                    ),
                ),
                applicability={},
                relation=None,
                fact_status="source_explicit",
                extractor="public-span-bridge-fixture",
                extractor_version="public-span-bridge-fixture/v1",
                generation_id=None,
                accepted_at="2026-08-22T00:00:00.000000Z",
                accepted_by="public-span-bridge-fixture",
            )
        )
        enriched = build_enriched_snapshot(base, store)
        direct = KnowledgeIndex(base, enriched)
        artifact_payload = json.loads(
            build_search_artifact(base, enriched=enriched)
        )
        artifact = ArtifactKnowledgeIndex(
            artifact_payload,
            base=base,
        )
        self.addCleanup(direct.close)
        self.addCleanup(artifact.close)
        containing = [
            chunk
            for chunk in base.chunks.values()
            if inline_span.span_id in chunk.ordered_span_ids
            and chunk.retrievable
        ]
        self.assertEqual(1, len(containing))
        self.assertGreaterEqual(len(containing[0].ordered_span_ids), 2)
        self.assertIn("quasar lattice cadence", containing[0].text)
        query = "quasar lattice cadence 有什么风险？"
        for index in (direct, artifact):
            response = index.search(query)
            self.assertFalse(
                any(
                    card.evidence_id == "kitm-public-span-bridge"
                    for card in response.cards
                ),
                response,
            )
        self.assertEqual(direct.search(query), artifact.search(query))
        positive_query = "bounded_outlier_policy 有什么风险？"
        for index in (direct, artifact):
            card = next(
                card
                for card in index.search(positive_query).cards
                if card.evidence_id == "kitm-public-span-bridge"
            )
            self.assertIn(
                f"route:source-evidence-query-match:{evidence_block.source_span.span_id}",
                card.hit_reasons,
            )
        self.assertEqual(
            direct.search(positive_query), artifact.search(positive_query)
        )
        tampered = json.loads(json.dumps(artifact_payload))
        retrieval_record = next(
            row
            for row in tampered["retrieval"]["records"]
            if row["record_id"] == "kitm-public-span-bridge"
        )
        retrieval_record["source_evidence_texts"] = ["forged evidence"]
        with self.assertRaisesRegex(
            ValueError,
            "source evidence differs from canonical locators",
        ):
            ArtifactKnowledgeIndex(tampered, base=base)

    def test_public_forbidden_path_binding_fails_closed(self) -> None:
        payload = json.loads(
            (FIXTURE_ROOT / "qrels.json").read_text(encoding="utf-8")
        )
        payload["qrels"][0]["forbidden_logical_paths"] = ["missing.md"]
        invalid = Path(self.temporary.name) / "invalid-forbidden-qrels.json"
        invalid.write_text(
            json.dumps(payload, ensure_ascii=False), encoding="utf-8"
        )
        with self.assertRaisesRegex(ValueError, "forbidden path is not active"):
            bind_qrel_templates(invalid, self.base)


if __name__ == "__main__":
    unittest.main()
