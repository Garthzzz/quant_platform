from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from quant_hub.knowledge import ReferenceCompiler
from quant_hub.knowledge.evaluation import (
    QrelSuite,
    bind_qrel_templates,
    evaluate_non_authoritative,
)
from quant_hub.knowledge.retrieval import (
    INDEX_VERSION,
    RETRIEVAL_ARTIFACT_SCHEMA,
    ArtifactKnowledgeIndex,
    KnowledgeIndex,
    TaskContext,
)
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
        direct = evaluate_non_authoritative(
            self.index, self.suite, split="development"
        )
        product = evaluate_non_authoritative(
            self.artifact_index, self.suite, split="development"
        )
        self.assertEqual("NON_AUTHORITATIVE_DIAGNOSTIC", direct.authority)
        self.assertEqual(13, direct.count)
        # These historical public qrels bind source quotes while formal
        # knowledge cards display a generated method/condition text.  Under
        # exact displayed-byte credit they remain useful retrieval diagnostics
        # but must not produce authoritative relevance credit.
        self.assertEqual(0.0, direct.recall_at_k, direct)
        self.assertEqual(1.0, direct.no_answer_accuracy, direct)
        self.assertFalse(direct.gate_pass, direct)
        self.assertEqual(0, direct.deprecated_errors, direct)
        self.assertEqual(0, direct.conflict_errors, direct)
        self.assertEqual(0, direct.forbidden_errors, direct)
        self.assertGreater(direct.knowledge_kind_errors, 0, direct)
        self.assertGreater(direct.citation_errors, 0, direct)
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

    def test_public_indexed_formula_alias_and_record_scoped_contrast(self) -> None:
        method = next(
            qrel
            for qrel in self.suite.qrels
            if qrel.qrel_id == "public-factor-cross-language-method"
        )
        limitation = next(
            qrel
            for qrel in self.suite.qrels
            if qrel.qrel_id == "public-factor-limitation-kind"
        )
        contrast = replace(
            method,
            qrel_id="public-post-v13-sibling-contrast",
            query=(
                "研究方法流程总结，不是低信噪比的局限，而是用 Rank IC "
                "衡量横截面排序稳定性"
            ),
            negative_locators=limitation.positive_locators,
            slices=("hard_negative", "miscitation"),
        )
        alias_separator_queries = tuple(
            (
                f"public-post-v13-alias-{alias_label}-{case_label}-{separator_label}",
                f"{left}{separator}{right} 的方法是什么？",
            )
            for alias_label, lower_left, lower_right in (
                ("rank-ic", "rank", "ic"),
                ("information-coefficient", "information", "coefficient"),
                ("spearman-correlation", "spearman", "correlation"),
            )
            for case_label, left, right in (
                ("lower", lower_left, lower_right),
                ("upper", lower_left.upper(), lower_right.upper()),
            )
            for separator_label, separator in (
                ("space", " "),
                ("spaces", "   "),
                ("newline", "\n"),
                ("hyphen", "-"),
                ("underscore", "_"),
                ("dot", "."),
                ("plus", "+"),
            )
        )
        formula_queries = (
            ("public-post-v13-formula-ic-lower", "IC_t的方法是什么？"),
            ("public-post-v13-formula-ic-cjk-prefix", "用IC_t的方法是什么？"),
            ("public-post-v13-formula-rankic-lower", "RankIC_t的方法是什么？"),
            ("public-post-v13-formula-ic-upper", "IC_T 的方法是什么？"),
            ("public-post-v13-formula-rankic-braced", "用 RANKIC_{T}的方法是什么？"),
            ("public-post-v13-formula-ic-numeric", "IC_7 的方法是什么？"),
            ("public-post-v13-formula-rankic-numeric", "RankIC_{123} 的方法是什么？"),
            ("public-post-v13-formula-ic-subscript-t", "ICₜ的方法是什么？"),
            ("public-post-v13-formula-ic-subscript-numeric", "IC₁₂₃的方法是什么？"),
            *alias_separator_queries,
            (
                "public-post-v13-alias-information-mixed-separator",
                "information- \n coefficient 的方法是什么？",
            ),
        )
        suite = QrelSuite.create(
            (
                contrast,
                *(
                    replace(
                        method,
                        qrel_id=qrel_id,
                        query=query,
                        slices=("formula_alias", "miscitation"),
                    )
                    for qrel_id, query in formula_queries
                ),
            )
        )
        direct = evaluate_non_authoritative(
            self.index, suite, split="development"
        )
        product = evaluate_non_authoritative(
            self.artifact_index, suite, split="development"
        )
        self.assertEqual(0.0, direct.recall_at_k, direct)
        self.assertEqual(0.0, direct.citation_accuracy, direct)
        self.assertGreater(direct.knowledge_kind_errors, 0, direct)
        self.assertGreater(direct.citation_errors, 0, direct)
        self.assertEqual(0, direct.forbidden_errors, direct)
        self.assertFalse(direct.gate_pass, direct)
        for field in (
            "recall_at_k",
            "ndcg_at_k",
            "reciprocal_rank",
            "citation_accuracy",
            "knowledge_kind_errors",
            "citation_errors",
            "forbidden_errors",
            "gate_pass",
        ):
            self.assertEqual(getattr(direct, field), getattr(product, field), field)

        factor_document_id = self.enriched.knowledge_items[
            "kitm-public-quality-01"
        ].document_id
        for qrel in suite.development():
            response = self.index.search(qrel.query, context=qrel.context)
            self.assertEqual(
                response,
                self.artifact_index.search(qrel.query, context=qrel.context),
                qrel.qrel_id,
            )
            self.assertTrue(
                any(card.knowledge_kind == "method" for card in response.cards),
                response,
            )
            self.assertFalse(
                any(card.knowledge_kind == "limitation" for card in response.cards),
                response,
            )
            if "alias-information" in qrel.qrel_id or "alias-spearman" in qrel.qrel_id:
                self.assertEqual(
                    factor_document_id,
                    response.cards[0].document_id,
                    response,
                )
                self.assertTrue(
                    all(
                        "route:strong-document-identity" not in card.hit_reasons
                        for card in response.cards
                    ),
                    response,
                )

        for polite_query in (
            "Please kindly explain why Rank IC is helpful for factor evaluation",
            "Rank IC method PLEASE",
            "KINDLY Rank IC HELPFUL method",
            "Rank IC method helpful PLEASE kindly",
        ):
            polite_response = self.index.search(polite_query)
            self.assertEqual(
                polite_response,
                self.artifact_index.search(polite_query),
            )
            self.assertTrue(
                any(
                    card.knowledge_kind == "method"
                    and "route:formal-grounded-evidence" in card.hit_reasons
                    for card in polite_response.cards
                ),
                polite_response,
            )

        malicious_formula_names = (
            "QZX_t",
            "IC_Heston",
            "IC_{Heston}",
            "RANKIC_CVA",
            "RankIC_{CVA}",
            "αIC_t",
            "IC_tβ",
            "𝛼IC_t",
            "αrankic",
            "rankicβ",
            "𝛼rankic",
            "rankic𝛽",
            "rankic_cva",
            "rankic_{cva}",
            "rankicfoo",
            "ICₜₜₜ",
            "IC_12345",
            "IC₁₂₃₄",
            "IC_t2",
            "ICₜ1",
            *(
                f"{prefix}{separator}{suffix}"
                for alias, unknown in (
                    ("rankic", "alien"),
                    ("RANKIC", "ALIEN"),
                )
                for prefix, suffix in (
                    (unknown, alias),
                    (alias, unknown),
                )
                for separator in (".", "-", "+", "_")
            ),
        )
        for index in (self.index, self.artifact_index):
            for formula_name in malicious_formula_names:
                unknown = index.search(f"{formula_name} 的方法是什么？")
                self.assertFalse(unknown.answerable, formula_name)
                self.assertEqual((), unknown.cards, formula_name)
                self.assertIn(
                    "named_anchor:", unknown.no_answer_reason or "", formula_name
                )

        order_book_document_id = self.enriched.knowledge_items[
            "kitm-public-quality-10"
        ].document_id
        additive_queries = tuple(
            f"{not_word} {marker} Rank IC method {but_word} {also_word} "
            "order book prediction method"
            for marker in ("only", "Only", "ONLY", "just", "Just", "JUST", "merely", "Merely", "MERELY")
            for not_word, but_word, also_word in (
                ("not", "but", "also"),
                ("Not", "But", "Also"),
                ("NOT", "BUT", "ALSO"),
            )
        )
        for additive_query in additive_queries:
            additive = self.index.search(additive_query)
            self.assertEqual(
                additive,
                self.artifact_index.search(additive_query),
            )
            additive_documents = {card.document_id for card in additive.cards}
            self.assertIn(factor_document_id, additive_documents, additive)
            self.assertIn(order_book_document_id, additive_documents, additive)

        for contrast_query in (
            "not low signal limitation but Rank IC method",
            "Not low signal limitation But Rank IC method",
            "NOT low signal limitation BUT Rank IC method",
        ):
            contrast_response = self.index.search(contrast_query)
            self.assertEqual(
                contrast_response,
                self.artifact_index.search(contrast_query),
            )
            self.assertTrue(contrast_response.answerable, contrast_response)
            self.assertTrue(
                any(
                    card.document_id == factor_document_id
                    and card.knowledge_kind == "method"
                    for card in contrast_response.cards
                ),
                contrast_response,
            )
            self.assertFalse(
                any(
                    card.document_id == factor_document_id
                    and card.knowledge_kind == "limitation"
                    for card in contrast_response.cards
                ),
                contrast_response,
            )

        grammar_only = self.index.search("not only just merely but also")
        self.assertEqual(
            grammar_only,
            self.artifact_index.search("not only just merely but also"),
        )
        self.assertFalse(grammar_only.answerable, grammar_only)
        self.assertEqual((), grammar_only.cards)

        self.assertTrue(INDEX_VERSION.startswith("qrh-structured-lexical-index/v1.15-"))
        artifact_payload = json.loads(
            build_search_artifact(self.base, enriched=self.enriched)
        )
        self.assertEqual(
            RETRIEVAL_ARTIFACT_SCHEMA,
            artifact_payload["retrieval"]["schema_version"],
        )
        artifact_payload["retrieval"]["index_version"] = (
            "qrh-structured-lexical-index/v1.13-evidence-citation-sidecar"
        )
        with self.assertRaisesRegex(
            ValueError, "retrieval artifact identity or schema is invalid"
        ):
            ArtifactKnowledgeIndex(artifact_payload, base=self.base)

        # The negative first hits an actual formal summary.  Its canonical
        # duplicate, a same-cluster item at another locator, every exact source
        # chunk, and a positive relation target must remain rejected, while the
        # independently grounded positive relation source stays available.
        route_store = SemanticJobStore(
            Path(self.temporary.name) / "canonical-contrast.sqlite3"
        )
        items = tuple(self.enriched.knowledge_items.values())
        for item in items:
            route_store.add_item(item)
        method_item = next(
            item
            for item in items
            if item.knowledge_item_id == "kitm-public-quality-01"
        )
        limitation_item = next(
            item
            for item in items
            if item.knowledge_item_id == "kitm-public-quality-03"
        )
        condition_item = next(
            item
            for item in items
            if item.knowledge_item_id == "kitm-public-quality-02"
        )
        rejected_cluster_id = "kcl-public-rejected-fixed-point"
        canonical_seed_id = "kitm-public-canonical-seed"
        canonical_seed = replace(
            condition_item,
            knowledge_item_id=canonical_seed_id,
            cluster_id=rejected_cluster_id,
            kind="limitation",
            text="canonical rejection sentinel",
            relation=None,
        )
        route_store.add_item(canonical_seed)
        canonical_duplicate_id = "kitm-public-canonical-duplicate"
        route_store.add_item(
            replace(
                canonical_seed,
                knowledge_item_id=canonical_duplicate_id,
                text="benign duplicate rendering",
            )
        )
        cluster_sibling_id = "kitm-public-cluster-different-locator"
        route_store.add_item(
            replace(
                limitation_item,
                knowledge_item_id=cluster_sibling_id,
                cluster_id=rejected_cluster_id,
                text="benign cluster rendering at another locator",
            )
        )
        bilingual_id = "kitm-public-bilingual-source-bridge"
        route_store.add_item(
            replace(
                limitation_item,
                knowledge_item_id=bilingual_id,
                cluster_id="kcl-public-bilingual-source-bridge",
                text="cross-language boundary revival sentinel",
            )
        )
        relation_id = "kitm-public-relation-route"
        route_store.add_item(
            replace(
                method_item,
                knowledge_item_id=relation_id,
                cluster_id="kcl-public-relation-route",
                relation={"type": "supports", "target_id": cluster_sibling_id},
            )
        )
        routed_enriched = build_enriched_snapshot(self.base, route_store)
        routed_direct = KnowledgeIndex(self.base, routed_enriched)
        routed_artifact = ArtifactKnowledgeIndex(
            json.loads(build_search_artifact(self.base, enriched=routed_enriched)),
            base=self.base,
        )
        self.addCleanup(routed_direct.close)
        self.addCleanup(routed_artifact.close)
        canonical_query = (
            "Rank IC method, not canonical rejection sentinel but Rank IC method"
        )
        routed_response = routed_direct.search(
            canonical_query, context=contrast.context
        )
        self.assertEqual(
            routed_response,
            routed_artifact.search(canonical_query, context=contrast.context),
        )
        self.assertIn(relation_id, {card.evidence_id for card in routed_response.cards})
        rejected_formal_ids = {
            canonical_seed_id,
            canonical_duplicate_id,
            cluster_sibling_id,
        }
        self.assertFalse(
            rejected_formal_ids
            & {card.evidence_id for card in routed_response.cards}
        )
        rejected_chunk_ids = {
            chunk_id
            for knowledge_id in rejected_formal_ids
            for chunk_id in routed_direct._source_chunks_by_knowledge[knowledge_id]
        }
        self.assertFalse(
            rejected_chunk_ids
            & {card.evidence_id for card in routed_response.cards}
        )

        generic_cross_document_query = (
            "not canonical rejection sentinel but method summary condition "
            "limitation failure evidence"
        )
        generic_cross_document = routed_direct.search(
            generic_cross_document_query,
            context=contrast.context,
        )
        self.assertEqual(
            generic_cross_document,
            routed_artifact.search(
                generic_cross_document_query,
                context=contrast.context,
            ),
        )
        self.assertFalse(generic_cross_document.answerable, generic_cross_document)
        self.assertEqual((), generic_cross_document.cards)

        bilingual_query = (
            "不是低信噪比的局限，而是 cross-language boundary revival sentinel "
            "和 Rank IC method"
        )
        bilingual_response = routed_direct.search(
            bilingual_query, context=contrast.context
        )
        self.assertEqual(
            bilingual_response,
            routed_artifact.search(bilingual_query, context=contrast.context),
        )
        bilingual_ids = {card.evidence_id for card in bilingual_response.cards}
        self.assertIn(method_item.knowledge_item_id, bilingual_ids)
        self.assertNotIn(bilingual_id, bilingual_ids)
        self.assertFalse(
            set(routed_direct._source_chunks_by_knowledge[bilingual_id])
            & bilingual_ids
        )

    def test_active_compound_terms_are_not_misclassified_as_embedded_ic(self) -> None:
        source_root = Path(self.temporary.name) / "active-compound-sources"
        source_root.mkdir()
        (source_root / "metric.md").write_text(
            "# Rank IC method\n\nRank IC evaluates public factor ordering.\n",
            encoding="utf-8",
        )
        known_terms = (
            "economic-value",
            "numeric-stability",
            "metric-learning",
            "specific-risk",
            "systematic-risk",
            "public-method",
        )
        (source_root / "known.md").write_text(
            "# Public compound methods\n\n"
            + " ".join(known_terms)
            + " are exact public method identifiers.\n",
            encoding="utf-8",
        )
        (source_root / "unsupported-examples.md").write_text(
            "# Unsupported attached examples\n\n"
            "The strings IC.Heston, IC-CVA, IC+alien, and IC_unknown are "
            "unsupported examples, not accepted metric identities.\n",
            encoding="utf-8",
        )
        (source_root / "grammar-titles.md").write_text(
            "# ONLY\n\nBoilerplate only.\n\n# NOT\n\nBoilerplate not.\n",
            encoding="utf-8",
        )
        compiled = ReferenceCompiler().compile(source_root)
        self.assertEqual("PASS", compiled.status)
        assert compiled.candidate_snapshot is not None
        base = compiled.candidate_snapshot
        direct = KnowledgeIndex(base)
        artifact = ArtifactKnowledgeIndex(
            json.loads(build_search_artifact(base)),
            base=base,
        )
        self.addCleanup(direct.close)
        self.addCleanup(artifact.close)

        for term in known_terms:
            response = direct.search(f"{term} method")
            self.assertEqual(response, artifact.search(f"{term} method"), term)
            self.assertTrue(response.answerable, (term, response))
            self.assertNotIn("named_anchor:", response.no_answer_reason or "", term)

        for unknown in ("IC.Heston", "IC-CVA", "IC+alien", "IC_unknown"):
            response = direct.search(f"{unknown} method")
            self.assertEqual(response, artifact.search(f"{unknown} method"), unknown)
            self.assertFalse(response.answerable, (unknown, response))
            self.assertIn("named_anchor:", response.no_answer_reason or "", unknown)

        for grammar_only in (
            "only",
            "Only",
            "ONLY",
            "not",
            "Not",
            "NOT",
            "not only just merely but also",
        ):
            response = direct.search(grammar_only)
            self.assertEqual(response, artifact.search(grammar_only), grammar_only)
            self.assertFalse(response.answerable, (grammar_only, response))
            self.assertEqual("no_supported_factual_terms", response.no_answer_reason)

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

    def test_public_unknown_literal_tokens_cannot_borrow_low_floor_routes(self) -> None:
        low_floor_reasons = {
            "route:exact-ascii-identifier",
            "route:explicit-kind-intent",
            "route:formal-grounded-evidence",
            "route:strong-document-identity",
        }
        cases = (
            ("unknown_object method", TaskContext()),
            ("alienmetric method", TaskContext()),
            (
                "Rank IC heston cva unrelatedterm 的方法是什么？",
                TaskContext(),
            ),
            (
                "unknown_object method",
                TaskContext.create(
                    market="A股",
                    frequency="日频",
                    objective="选股",
                ),
            ),
        )
        for query, context in cases:
            response = self.index.search(query, context=context)
            self.assertEqual(
                response,
                self.artifact_index.search(query, context=context),
                query,
            )
            self.assertTrue(response.answerable, response)
            self.assertTrue(response.cards, response)
            self.assertTrue(
                all(
                    low_floor_reasons.isdisjoint(card.hit_reasons)
                    for card in response.cards
                ),
                response,
            )
        contextual = self.index.search(cases[-1][0], context=cases[-1][1])
        self.assertTrue(
            any(card.applicability_matches for card in contextual.cards),
            contextual,
        )

    def test_public_active_pbo_identity_does_not_waive_unknown_query_tokens(self) -> None:
        source_root = Path(self.temporary.name) / "pbo-query-gate-sources"
        source_root.mkdir()
        source_text = (
            "# PBO\n\nPBO exact evidence uses stable_public_method with "
            "foo.bar and C++.\n"
        )
        (source_root / "pbo.md").write_text(source_text, encoding="utf-8")
        other_source_text = (
            "# Other public method\n\nPBO cross-document relation support "
            "uses relation_support_token.\n"
        )
        (source_root / "other.md").write_text(
            other_source_text,
            encoding="utf-8",
        )
        compiled = ReferenceCompiler().compile(source_root)
        self.assertEqual("PASS", compiled.status)
        assert compiled.candidate_snapshot is not None
        base = compiled.candidate_snapshot
        documents = {
            row.canonical_path: row for row in base.documents.values()
        }
        document = documents["pbo.md"]
        other_document = documents["other.md"]
        assert document.active_version_id is not None
        assert other_document.active_version_id is not None
        ir = base.ir_documents[document.active_version_id]
        other_ir = base.ir_documents[other_document.active_version_id]
        quote = "PBO exact evidence uses stable_public_method with foo.bar and C++."
        span = next(
            block.source_span
            for block in ir.blocks
            if quote in block.source_span.text
        )
        character_start = span.text.index(quote)
        byte_start = span.byte_start + len(
            span.text[:character_start].encode("utf-8")
        )
        other_quote = (
            "PBO cross-document relation support uses relation_support_token."
        )
        other_span = next(
            block.source_span
            for block in other_ir.blocks
            if other_quote in block.source_span.text
        )
        other_character_start = other_span.text.index(other_quote)
        other_byte_start = other_span.byte_start + len(
            other_span.text[:other_character_start].encode("utf-8")
        )
        store = SemanticJobStore(
            Path(self.temporary.name) / "pbo-query-gate.sqlite3"
        )
        pbo_item_id = "kitm-public-pbo-query-gate"
        relation_target_id = "kitm-public-pbo-cross-document-target"
        store.add_item(
            KnowledgeItem(
                knowledge_item_id=relation_target_id,
                cluster_id="kcl-public-pbo-cross-document-target",
                document_id=other_document.document_id,
                document_version_id=other_document.active_version_id,
                kind="evidence",
                text="PBO cross-document relation support.",
                evidence=(
                    EvidenceBinding(
                        other_span.span_id,
                        other_quote,
                        hashlib.sha256(other_quote.encode("utf-8")).hexdigest(),
                        other_byte_start,
                        other_byte_start + len(other_quote.encode("utf-8")),
                    ),
                ),
                applicability={},
                relation=None,
                fact_status="source_explicit",
                extractor="public-pbo-query-gate",
                extractor_version="public-pbo-query-gate/v1",
                generation_id=None,
                accepted_at="2026-08-22T00:00:00.000000Z",
                accepted_by="public-pbo-query-gate",
            )
        )
        store.add_item(
            KnowledgeItem(
                knowledge_item_id=pbo_item_id,
                cluster_id="kcl-public-pbo-query-gate",
                document_id=document.document_id,
                document_version_id=document.active_version_id,
                kind="method",
                text="stable_public_method is the PBO implementation.",
                evidence=(
                    EvidenceBinding(
                        span.span_id,
                        quote,
                        hashlib.sha256(quote.encode("utf-8")).hexdigest(),
                        byte_start,
                        byte_start + len(quote.encode("utf-8")),
                    ),
                ),
                applicability={"market": ("A股",)},
                relation={"type": "supports", "target_id": relation_target_id},
                fact_status="source_explicit",
                extractor="public-pbo-query-gate",
                extractor_version="public-pbo-query-gate/v1",
                generation_id=None,
                accepted_at="2026-08-22T00:00:00.000000Z",
                accepted_by="public-pbo-query-gate",
            )
        )
        enriched = build_enriched_snapshot(base, store)
        direct = KnowledgeIndex(base, enriched)
        artifact = ArtifactKnowledgeIndex(
            json.loads(build_search_artifact(base, enriched=enriched)),
            base=base,
        )
        self.addCleanup(direct.close)
        self.addCleanup(artifact.close)

        known = direct.search("PBO method")
        self.assertEqual(known, artifact.search("PBO method"))
        self.assertIn(pbo_item_id, {card.evidence_id for card in known.cards})
        self.assertIn(
            relation_target_id,
            {card.evidence_id for card in known.cards},
        )
        self.assertTrue(
            any(
                "route:strong-document-identity" in card.hit_reasons
                for card in known.cards
            ),
            known,
        )
        relation_target = next(
            card
            for card in known.cards
            if card.evidence_id == relation_target_id
        )
        self.assertEqual(other_document.document_id, relation_target.document_id)
        self.assertIn(
            f"relation:supports:{pbo_item_id}",
            relation_target.hit_reasons,
        )
        self.assertTrue(
            all(
                card.document_id == document.document_id
                or card.evidence_id == relation_target_id
                for card in known.cards
            ),
            known,
        )

        low_floor_reasons = {
            "route:exact-ascii-identifier",
            "route:explicit-kind-intent",
            "route:formal-grounded-evidence",
            "route:strong-document-identity",
        }
        unknown_query = "PBO heston cva unrelatedterm method"
        for context in (
            TaskContext(),
            TaskContext.create(market="A股"),
        ):
            unknown = direct.search(unknown_query, context=context)
            self.assertEqual(
                unknown,
                artifact.search(unknown_query, context=context),
            )
            self.assertTrue(
                all(
                    low_floor_reasons.isdisjoint(card.hit_reasons)
                    for card in unknown.cards
                ),
                unknown,
            )

        for inactive_alias_query in (
            "cross-sectional ordering stability method",
            "late data method",
            "earnings method",
        ):
            inactive = direct.search(inactive_alias_query)
            self.assertEqual(
                inactive,
                artifact.search(inactive_alias_query),
            )
            self.assertTrue(
                all(
                    low_floor_reasons.isdisjoint(card.hit_reasons)
                    for card in inactive.cards
                ),
                inactive,
            )

        for preserved_token_query in ("foo.bar method", "C++ method"):
            preserved = direct.search(preserved_token_query)
            self.assertEqual(
                preserved,
                artifact.search(preserved_token_query),
            )
            self.assertIn(
                pbo_item_id,
                {card.evidence_id for card in preserved.cards},
            )

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
        negative_quote = "quasar lattice cadence"
        negative_character_start = evidence_block.source_span.text.index(
            negative_quote
        )
        negative_byte_start = evidence_block.source_span.byte_start + len(
            evidence_block.source_span.text[:negative_character_start].encode(
                "utf-8"
            )
        )
        negative_id = "kitm-public-span-bridge-negative"
        store.add_item(
            KnowledgeItem(
                knowledge_item_id=negative_id,
                cluster_id="kcl-public-span-bridge-negative",
                document_id=document.document_id,
                document_version_id=document.active_version_id,
                kind="failure",
                text="quasar carrier rejection sentinel",
                evidence=(
                    EvidenceBinding(
                        evidence_block.source_span.span_id,
                        negative_quote,
                        hashlib.sha256(
                            negative_quote.encode("utf-8")
                        ).hexdigest(),
                        negative_byte_start,
                        negative_byte_start
                        + len(negative_quote.encode("utf-8")),
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
        positive_sibling_id = "kitm-public-span-bridge-positive-sibling"
        store.add_item(
            KnowledgeItem(
                knowledge_item_id=positive_sibling_id,
                cluster_id="kcl-public-span-bridge-positive-sibling",
                document_id=document.document_id,
                document_version_id=document.active_version_id,
                kind="limitation",
                text="bounded_outlier_policy positive locator sentinel",
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
        positive_response = direct.search(positive_query)
        self.assertTrue(
            any(
                "route:exact-ascii-identifier" in card.hit_reasons
                for card in positive_response.cards
            ),
            positive_response,
        )
        terminal_period_query = "bounded_outlier_policy. 有什么风险？"
        terminal_period_response = direct.search(terminal_period_query)
        self.assertEqual(
            terminal_period_response,
            artifact.search(terminal_period_query),
        )
        self.assertIn(
            "kitm-public-span-bridge",
            {card.evidence_id for card in terminal_period_response.cards},
        )
        self.assertTrue(
            any(
                "route:exact-ascii-identifier" in card.hit_reasons
                for card in terminal_period_response.cards
            ),
            terminal_period_response,
        )
        for unknown_query in (
            "bounded_outlier_policy Heston 有什么风险？",
            "bounded_outlier_policy CVA 有什么风险？",
            "bounded_outlier_policy heston 有什么风险？",
            "bounded_outlier_policy cva 有什么风险？",
            "bounded_outlier_policy unrelatedterm 有什么风险？",
            "bounded_outlier_policy unknown_object 有什么风险？",
        ):
            unknown = direct.search(unknown_query)
            self.assertEqual(unknown, artifact.search(unknown_query))
            self.assertFalse(unknown.answerable, unknown)
            self.assertEqual((), unknown.cards, unknown)
            if "Heston" in unknown_query or "CVA" in unknown_query:
                self.assertIn(
                    "named_anchor:", unknown.no_answer_reason or ""
                )
            else:
                self.assertEqual(
                    "no_grounded_evidence_above_threshold",
                    unknown.no_answer_reason,
                )
        default_only_query = "bounded_outlier_policy unrelated 有什么风险？"
        default_only_response = direct.search(default_only_query)
        self.assertEqual(
            default_only_response,
            artifact.search(default_only_query),
        )
        self.assertTrue(default_only_response.answerable, default_only_response)
        self.assertIn(
            "kitm-public-span-bridge",
            {card.evidence_id for card in default_only_response.cards},
        )
        self.assertIn(
            positive_sibling_id,
            {card.evidence_id for card in default_only_response.cards},
        )
        self.assertTrue(
            any(
                "route:formal-grounded-evidence" in card.hit_reasons
                for card in default_only_response.cards
            ),
            default_only_response,
        )
        no_identifier_query = "受控异常值策略有什么风险？"
        no_identifier_response = direct.search(no_identifier_query)
        self.assertEqual(
            no_identifier_response,
            artifact.search(no_identifier_query),
        )
        self.assertTrue(no_identifier_response.answerable, no_identifier_response)
        self.assertIn(
            "kitm-public-span-bridge",
            {card.evidence_id for card in no_identifier_response.cards},
        )
        contrast_query = (
            "not quasar lattice cadence but bounded_outlier_policy 有什么风险？"
        )
        contrast_response = direct.search(contrast_query)
        self.assertEqual(contrast_response, artifact.search(contrast_query))
        contrast_ids = {card.evidence_id for card in contrast_response.cards}
        self.assertIn(positive_sibling_id, contrast_ids)
        self.assertNotIn(negative_id, contrast_ids)
        self.assertNotIn(containing[0].chunk_id, contrast_ids)
        generic_contrast_query = (
            "not quasar lattice cadence but method summary condition "
            "limitation failure evidence"
        )
        generic_contrast = direct.search(generic_contrast_query)
        self.assertEqual(
            generic_contrast,
            artifact.search(generic_contrast_query),
        )
        self.assertFalse(generic_contrast.answerable, generic_contrast)
        self.assertEqual((), generic_contrast.cards, generic_contrast)
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

    def test_public_search_runtime_inputs_are_bounded_at_the_index(self) -> None:
        for index in (self.index, self.artifact_index):
            with self.subTest(index=type(index).__name__):
                self.assertFalse(index.search("a" * 500).answerable)
                for invalid_query in ("", "   ", "a" * 501):
                    with self.assertRaisesRegex(ValueError, "1 to 500"):
                        index.search(invalid_query)
                for invalid_limit in (False, 0, 101):
                    with self.assertRaisesRegex(ValueError, "between 1 and 100"):
                        index.search("Rank IC", limit=invalid_limit)
                with self.assertRaisesRegex(ValueError, "flags must be booleans"):
                    index.search("Rank IC", include_history=1)
                with self.assertRaisesRegex(ValueError, "TaskContext"):
                    index.search("Rank IC", context={})
                with self.assertRaisesRegex(ValueError, "value exceeds"):
                    index.search(
                        "Rank IC",
                        context=TaskContext(data=("x" * 501,)),
                    )
                with self.assertRaisesRegex(ValueError, "context exceeds"):
                    index.search(
                        "Rank IC",
                        context=TaskContext(data=tuple("x" * 500 for _ in range(40))),
                    )
                with self.assertRaisesRegex(ValueError, "too many facet values"):
                    index.search(
                        "Rank IC",
                        context=TaskContext(assumption=("x",) * 65),
                    )
                with self.assertRaisesRegex(ValueError, "empty facet value"):
                    index.search(
                        "Rank IC",
                        context=TaskContext(assumption=(" ",)),
                    )
                with self.assertRaisesRegex(ValueError, "duplicate facet values"):
                    index.search(
                        "Rank IC",
                        context=TaskContext(assumption=("Known", " known ")),
                    )
                with self.assertRaisesRegex(ValueError, "valid UTF-8"):
                    index.search("\ud800")
                with self.assertRaisesRegex(ValueError, "valid UTF-8"):
                    index.search(
                        "Rank IC",
                        context=TaskContext(assumption=("\ud800",)),
                    )
                with self.assertRaisesRegex(ValueError, "finite non-negative"):
                    index.search("Rank IC", minimum_score=float("nan"))
                with self.assertRaisesRegex(ValueError, "finite non-negative"):
                    index.search("Rank IC", minimum_score=10**10000)
                with self.assertRaisesRegex(ValueError, "coverage"):
                    index.search(
                        "Rank IC",
                        minimum_weighted_coverage=float("inf"),
                    )

    def test_public_unknown_unicode_and_mixed_case_names_fail_closed(self) -> None:
        variants = (
            "hESTON Rank IC method",
            "H\u00e9ston Rank IC method",
            "H\u0301eston Rank IC method",
            "\uff28\uff45\uff53\uff54\uff4f\uff4e Rank IC method",
            "\u041deston Rank IC method",
            "H\u200deston Rank IC method",
            "H\u200beston Rank IC method",
            "H\u00adeston Rank IC method",
            "H\ufe0feston Rank IC method",
            "H\u2060eston Rank IC method",
            "\u24bd\u24d4\u24e2\u24e3\u24de\u24dd Rank IC method",
            "H\x00eston Rank IC method",
            "H\x7feston Rank IC method",
            "H\u0085eston Rank IC method",
            "H\u00a0eston Rank IC method",
            "H\u2028eston Rank IC method",
        )
        for query in variants:
            with self.subTest(query=query):
                direct = self.index.search(query)
                artifact = self.artifact_index.search(query)
                self.assertEqual(direct, artifact)
                self.assertFalse(direct.answerable)
                self.assertEqual((), direct.cards)
                self.assertIn("named_anchor", direct.no_answer_reason or "")


if __name__ == "__main__":
    unittest.main()
