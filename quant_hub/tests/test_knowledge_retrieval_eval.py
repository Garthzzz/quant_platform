from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from quant_hub.knowledge import ReferenceCompiler, TombstoneDirective
from quant_hub.knowledge.evaluation import (
    GroundedLocator,
    Qrel,
    QrelSuite,
    _card_covers_locator,
    bind_qrel_templates,
    compare_candidate_to_baseline,
    evaluate,
)
from quant_hub.knowledge.retrieval import (
    ArtifactKnowledgeIndex,
    KnowledgeIndex,
    LikeBaselineIndex,
    TaskContext,
    citation_ids_for_evidence_bindings,
)
from quant_hub.knowledge_mcp.mirror import build_search_artifact
from quant_hub.knowledge.semantic import (
    EvidenceBinding,
    KnowledgeItem,
    SemanticJobStore,
    build_enriched_snapshot,
)


class KnowledgeRetrievalEvaluationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        sources = {
            "factor.md": (
                "# Rank IC 横截面因子\n\n"
                "方法：使用 Rank IC 筛选横截面因子\n\n"
                "适用条件：A股、日频、因子暴露、选股\n\n"
                "限制：低 SNR 下 Rank IC 排序不稳定\n"
            ),
            "crypto.md": (
                "# 加密货币高频信号\n\n"
                "方法：订单簿不平衡预测下一分钟收益\n\n"
                "适用条件：加密货币、分钟、订单簿、短期预测\n"
            ),
            "data.md": (
                "# 因子数据处理\n\n"
                "方法：先缩尾再做截面标准化\n\n"
                "适用条件：A股、日频、因子暴露、数据清洗\n"
            ),
            "model.md": (
                "# 时间序列模型选择\n\n"
                "方法：使用 walk-forward 滚动验证选择模型\n\n"
                "失败经验：随机切分会造成时间泄漏\n"
            ),
            "backtest.md": (
                "# 可实现回测\n\n"
                "方法：按成交额和换手率扣除交易成本\n\n"
                "失败经验：忽略容量会高估可实现收益\n"
            ),
            "legacy.md": "# 历史均值信号\n\n方法：原始均值信号仅供历史复盘\n",
        }
        for path, text in sources.items():
            (self.root / path).write_text(text, encoding="utf-8")
        report = ReferenceCompiler().compile(self.root)
        self.assertEqual("PASS", report.status)
        assert report.candidate_snapshot is not None
        self.base = report.candidate_snapshot
        self.store = SemanticJobStore(self.root / "runtime" / "knowledge.sqlite3")
        self._seed_accepted_knowledge()
        self.enriched = build_enriched_snapshot(self.base, self.store)
        self.index = KnowledgeIndex(self.base, self.enriched)
        self.addCleanup(self.index.close)
        self.artifact_index = ArtifactKnowledgeIndex(
            json.loads(build_search_artifact(self.base, enriched=self.enriched)),
            base=self.base,
        )
        self.addCleanup(self.artifact_index.close)

    def _record_for_path(self, path: str):
        return next(value for value in self.base.documents.values() if value.canonical_path == path)

    def _seed_accepted_knowledge(self) -> None:
        applicability_by_path = {
            "factor.md": {
                "market": ("A股",),
                "frequency": ("日频",),
                "data": ("因子暴露",),
                "objective": ("选股",),
            },
            "crypto.md": {
                "market": ("加密货币",),
                "frequency": ("分钟",),
                "data": ("订单簿",),
                "objective": ("短期预测",),
            },
            "data.md": {"data": ("因子暴露",), "objective": ("数据清洗",)},
            "model.md": {"objective": ("模型选择",)},
            "backtest.md": {"objective": ("回测",)},
        }
        for document in self.base.documents.values():
            assert document.active_version_id is not None
            ir = self.base.ir_documents[document.active_version_id]
            for block in ir.blocks:
                text = block.text.strip()
                labels = {
                    "方法：": "method",
                    "适用条件：": "condition",
                    "限制：": "limitation",
                    "失败经验：": "failure",
                }
                match = next(((prefix, kind) for prefix, kind in labels.items() if text.startswith(prefix)), None)
                if match is None:
                    continue
                prefix, kind = match
                value = text[len(prefix) :].strip()
                quote = block.source_span.text.strip()
                quote_start = block.source_span.byte_start + len(
                    block.source_span.text[
                        : block.source_span.text.index(quote)
                    ].encode("utf-8")
                )
                binding = EvidenceBinding(
                    block.source_span.span_id,
                    quote,
                    hashlib.sha256(quote.encode("utf-8")).hexdigest(),
                    quote_start,
                    quote_start + len(quote.encode("utf-8")),
                )
                path = document.canonical_path
                applicability = applicability_by_path.get(path, {}) if kind in {"method", "condition"} else {}
                item = KnowledgeItem(
                    knowledge_item_id=f"kitm-{document.document_id}-{block.block_id}",
                    cluster_id=f"kcl-{document.document_id}-{kind}-{block.block_id}",
                    document_id=document.document_id,
                    document_version_id=document.active_version_id,
                    kind=kind,
                    text=value,
                    evidence=(binding,),
                    applicability=applicability,
                    relation=None,
                    fact_status="source_explicit",
                    extractor="fixture",
                    extractor_version="fixture/v1",
                    generation_id=None,
                    accepted_at="2026-08-21T00:00:00.000000Z",
                    accepted_by="fixture-reviewer",
                )
                self.store.add_item(item)

    def test_hybrid_retrieval_explains_matches_conflicts_limits_and_dedup(self) -> None:
        response = self.index.search(
            "rank IC 横截面因子",
            context=TaskContext.create(market="A股", frequency="日频", objective="选股"),
        )
        self.assertTrue(response.answerable)
        first = response.cards[0]
        self.assertEqual(self._record_for_path("factor.md").document_id, first.document_id)
        self.assertIn("market:a股", first.applicability_matches)
        self.assertTrue(any("低 SNR" in value for value in first.limitations))
        self.assertEqual(len(response.cards), len({card.canonical_key for card in response.cards}))
        self.assertTrue(first.locator.source_sha256)
        self.assertTrue(first.hit_reasons)
        self.assertIn("route:fts5", first.hit_reasons)
        self.assertGreater(self.index.index_footprint_bytes, 0)
        self.assertGreaterEqual(self.index.build_latency_ms, 0)
        artifact_response = self.artifact_index.search(
            "rank IC 横截面因子",
            context=TaskContext.create(
                market="A股", frequency="日频", objective="选股"
            ),
        )
        self.assertEqual(response, artifact_response)

        formal_route = self.index.search(
            "rank IC why is a long natural-language factor evaluation question useful"
        )
        self.assertTrue(formal_route.answerable)
        self.assertTrue(
            any(
                "route:formal-grounded-evidence" in card.hit_reasons
                for card in formal_route.cards
            )
        )

        # Alias expansion remains useful for lexical recall, but it cannot by
        # itself reserve the formal-evidence lane.  The source must share at
        # least two surface anchors with the actual query; otherwise a method
        # mentioning only "IC" could crowd an unrelated ICIR question.
        alias_only = self.index.search("ICIR 对组合管理有什么意义")
        self.assertFalse(
            any(
                "rank_lane:formal-evidence" in card.hit_reasons
                for card in alias_only.cards
            )
        )

        conflict = self.index.search(
            "rank IC 横截面因子",
            context=TaskContext.create(market="加密货币", frequency="分钟", data="订单簿"),
        )
        self.assertFalse(
            any(card.document_id == self._record_for_path("factor.md").document_id for card in conflict.cards)
        )
        diagnostic = self.index.search(
            "rank IC 横截面因子",
            context=TaskContext.create(market="加密货币", frequency="分钟", data="订单簿"),
            include_conflicts=True,
        )
        factor = next(
            card for card in diagnostic.cards if card.document_id == self._record_for_path("factor.md").document_id
        )
        self.assertGreaterEqual(len(factor.applicability_conflicts), 2)

    def test_pending_uses_current_lexical_version_and_never_old_semantics(self) -> None:
        lexical = KnowledgeIndex(self.base).search("rank IC")
        self.assertTrue(lexical.cards)
        self.assertTrue(all(card.knowledge_enrichment == "pending" for card in lexical.cards))
        old_version = self._record_for_path("factor.md").active_version_id
        (self.root / "factor.md").write_text(
            "# Rank IC 新版本\n\n方法：使用分组稳定性替代旧 Rank IC 筛选\n",
            encoding="utf-8",
        )
        revised = ReferenceCompiler().compile(self.root, previous=self.base)
        assert revised.candidate_snapshot is not None
        new_base = revised.candidate_snapshot
        with self.assertRaisesRegex(ValueError, "another deterministic snapshot"):
            KnowledgeIndex(new_base, self.enriched)
        current = KnowledgeIndex(new_base).search("分组稳定性")
        self.assertTrue(current.cards)
        self.assertTrue(all(card.document_version_id != old_version for card in current.cards))
        self.assertTrue(all(card.knowledge_enrichment == "pending" for card in current.cards))

    def test_tombstone_and_history_semantics_are_explicit(self) -> None:
        legacy = self._record_for_path("legacy.md")
        tombstoned = ReferenceCompiler().compile(
            self.root,
            previous=self.base,
            tombstones=(TombstoneDirective(legacy.document_id, "superseded historical baseline"),),
        )
        assert tombstoned.candidate_snapshot is not None
        index = KnowledgeIndex(tombstoned.candidate_snapshot)
        default = index.search("原始均值信号")
        self.assertFalse(any(card.document_id == legacy.document_id for card in default.cards))
        historical = index.search("原始均值信号", include_history=True)
        card = next(card for card in historical.cards if card.document_id == legacy.document_id)
        self.assertEqual("tombstoned", card.active_status)

    def test_no_answer_is_explicit(self) -> None:
        response = self.index.search("量子退火预测火星期货")
        self.assertFalse(response.answerable)
        self.assertEqual((), response.cards)
        self.assertEqual("no_grounded_evidence_above_threshold", response.no_answer_reason)
        # A generic matching context facet ("回测") must not override unseen
        # query anchors and turn an out-of-domain request into false evidence.
        contextual = self.index.search(
            "量子退火预测火星期货",
            context=TaskContext.create(objective="回测"),
        )
        self.assertFalse(contextual.answerable)
        self.assertEqual((), contextual.cards)

        unsupported_data = self.index.search(
            "标准化阈值",
            context=TaskContext.create(data="卫星图像"),
        )
        self.assertFalse(unsupported_data.answerable)
        self.assertEqual((), unsupported_data.cards)
        self.assertEqual(
            "unsupported_task_context:data", unsupported_data.no_answer_reason
        )

    def test_bilingual_alias_named_anchor_and_kind_intent_are_deterministic(self) -> None:
        factor = self.index.search(
            "Which cross-sectional factor method uses rank correlation for selection?",
            context=TaskContext.create(market="China A-share", frequency="daily"),
        )
        self.assertTrue(factor.answerable)
        self.assertEqual(
            self._record_for_path("factor.md").document_id,
            factor.cards[0].document_id,
        )
        self.assertEqual("method", factor.cards[0].knowledge_kind)
        self.assertIn("intent_kind:method", factor.cards[0].hit_reasons)

        controlled_alias = self.index.search(
            "Which A-share factor evaluation method uses rank correlation?",
            context=TaskContext.create(market="A股", frequency="日频"),
        )
        self.assertTrue(controlled_alias.answerable)
        self.assertNotIn(
            "named_anchor:a-share", controlled_alias.no_answer_reason or ""
        )

        long_exact_identity = self.index.search(
            "Why is Rank IC useful when a researcher evaluates a very long "
            "natural-language cross-sectional factor selection question?"
        )
        self.assertTrue(long_exact_identity.answerable)
        self.assertTrue(
            any(
                "route:strong-document-identity" in card.hit_reasons
                for card in long_exact_identity.cards
            )
        )

        data = self.index.search("How should factor exposure winsorization be applied?")
        self.assertTrue(data.answerable)
        self.assertTrue(
            any(
                card.document_id == self._record_for_path("data.md").document_id
                for card in data.cards[:3]
            )
        )

        failure = self.index.search("模型选择有哪些失败经验和时间泄漏风险？")
        self.assertTrue(failure.answerable)
        self.assertEqual("failure", failure.cards[0].knowledge_kind)
        self.assertIn("intent_kind:failure", failure.cards[0].hit_reasons)

        unsupported = self.index.search("Does Heston CVA calibration apply here?")
        self.assertFalse(unsupported.answerable)
        self.assertIn("named_anchor:heston", unsupported.no_answer_reason or "")
        self.assertIn("named_anchor:cva", unsupported.no_answer_reason or "")

        unsupported_compound = self.index.search(
            "How should key-rate-duration be calibrated?"
        )
        self.assertFalse(unsupported_compound.answerable)
        self.assertIn(
            "named_anchor:key-rate-duration",
            unsupported_compound.no_answer_reason or "",
        )
        unsupported_mixed_language_compound = self.index.search(
            "美国国债组合的 key-rate duration 应如何映射到收益率曲线各节点？"
        )
        self.assertFalse(unsupported_mixed_language_compound.answerable)
        self.assertIn(
            "named_anchor:key-rate-duration",
            unsupported_mixed_language_compound.no_answer_reason or "",
        )
        unsupported_spaced_compound = self.index.search(
            "How should key rate duration be calibrated?"
        )
        self.assertFalse(unsupported_spaced_compound.answerable)
        self.assertIn(
            "named_anchor:key-rate-duration",
            unsupported_spaced_compound.no_answer_reason or "",
        )
        unsupported_yield = self.index.search(
            "How should convenience yield be estimated?"
        )
        self.assertFalse(unsupported_yield.answerable)
        self.assertIn(
            "named_anchor:convenience-yield",
            unsupported_yield.no_answer_reason or "",
        )
        unsupported_basis = self.index.search(
            "How should funding basis arbitrage be hedged?"
        )
        self.assertFalse(unsupported_basis.answerable)
        self.assertIn(
            "named_anchor:funding-basis",
            unsupported_basis.no_answer_reason or "",
        )

        # A bounded research-request verb at the beginning of an English
        # prompt is grammar, not a named model/instrument.  It must not turn a
        # grounded Rank IC question into a closed-world no-answer response.
        imperative = self.index.search(
            "Explain why Rank IC is useful for cross-sectional factor selection"
        )
        self.assertTrue(imperative.answerable)
        self.assertEqual(
            self._record_for_path("factor.md").document_id,
            imperative.cards[0].document_id,
        )
        named_acronym = self.index.search("COMPARE CVA calibration")
        self.assertFalse(named_acronym.answerable)
        # Request grammar is case- and position-insensitive; the unsupported
        # active-corpus object remains CVA, not the imperative COMPARE.
        self.assertIn(
            "named_anchor:cva", named_acronym.no_answer_reason or ""
        )
        self.assertNotIn(
            "named_anchor:compare", named_acronym.no_answer_reason or ""
        )

    def test_knowledge_citations_do_not_leak_between_claims_in_one_paragraph(self) -> None:
        citation_root = self.root / "citation-scope"
        citation_root.mkdir()
        first_citation = "cit_" + ("a" * 52)
        second_citation = "cit_" + ("b" * 52)
        consecutive_citation = "cit_" + ("c" * 52)
        first_claim = "Rank IC 在低信噪比下不稳定。"
        second_claim = "换手成本应在回测中实测。"
        (citation_root / "claims.md").write_text(
            "# 相邻论断\n\n"
            f"{first_claim} ^src:{{{first_citation}}} ^src:{{{consecutive_citation}}} "
            f"{second_claim} ^src:{{{second_citation}}}\n",
            encoding="utf-8",
        )
        compiled = ReferenceCompiler().compile(citation_root)
        assert compiled.candidate_snapshot is not None
        base = compiled.candidate_snapshot
        document = next(iter(base.documents.values()))
        assert document.active_version_id is not None
        paragraph = next(
            block
            for block in base.ir_documents[document.active_version_id].blocks
            if block.kind == "paragraph" and first_claim in block.source_span.text
        )
        store = SemanticJobStore(citation_root / "runtime" / "knowledge.sqlite3")
        for ordinal, (claim, citation_id) in enumerate(
            ((first_claim, first_citation), (second_claim, second_citation)), 1
        ):
            relative = paragraph.source_span.text.index(claim)
            byte_start = paragraph.source_span.byte_start + len(
                paragraph.source_span.text[:relative].encode("utf-8")
            )
            store.add_item(
                KnowledgeItem(
                    knowledge_item_id=f"kitm-citation-scope-{ordinal}",
                    cluster_id=f"kcl-citation-scope-{ordinal}",
                    document_id=document.document_id,
                    document_version_id=document.active_version_id,
                    kind="evidence",
                    text=claim,
                    evidence=(
                        EvidenceBinding(
                            paragraph.source_span.span_id,
                            claim,
                            hashlib.sha256(claim.encode("utf-8")).hexdigest(),
                            byte_start,
                            byte_start + len(claim.encode("utf-8")),
                        ),
                    ),
                    applicability={},
                    relation=None,
                    fact_status="source_explicit",
                    extractor="public-adversarial-fixture",
                    extractor_version="public-adversarial-fixture/v1",
                    generation_id=None,
                    accepted_at="2026-08-21T00:00:00.000000Z",
                    accepted_by=None,
                )
            )
        first_relative = paragraph.source_span.text.index(first_claim)
        first_start = paragraph.source_span.byte_start + len(
            paragraph.source_span.text[:first_relative].encode("utf-8")
        )
        second_relative = paragraph.source_span.text.index(second_claim)
        second_start = paragraph.source_span.byte_start + len(
            paragraph.source_span.text[:second_relative].encode("utf-8")
        )
        forged_offset = EvidenceBinding(
            paragraph.source_span.span_id,
            first_claim,
            hashlib.sha256(first_claim.encode("utf-8")).hexdigest(),
            second_start,
            second_start + len(second_claim.encode("utf-8")),
        )
        forged_hash = EvidenceBinding(
            paragraph.source_span.span_id,
            first_claim,
            "0" * 64,
            first_start,
            first_start + len(first_claim.encode("utf-8")),
        )
        for binding in (forged_offset, forged_hash):
            with self.assertRaisesRegex(ValueError, "differs from quote"):
                citation_ids_for_evidence_bindings(
                    base.ir_documents[document.active_version_id], (binding,)
                )
        enriched = build_enriched_snapshot(base, store)
        with KnowledgeIndex(base, enriched) as index:
            by_id = {
                record.record_id: record
                for record in index.records
                if record.source_kind == "knowledge"
            }
            self.assertEqual(
                tuple(sorted((first_citation, consecutive_citation))),
                by_id["kitm-citation-scope-1"].citation_ids,
            )
            self.assertEqual(
                (second_citation,), by_id["kitm-citation-scope-2"].citation_ids
            )

            artifact = json.loads(build_search_artifact(base, enriched=enriched))
            artifact_rows = {
                row["knowledge_item_id"]: row
                for row in artifact["knowledge"]
            }
            self.assertEqual(
                sorted((first_citation, consecutive_citation)),
                artifact_rows["kitm-citation-scope-1"]["citation_ids"],
            )
            self.assertEqual(
                [second_citation],
                artifact_rows["kitm-citation-scope-2"]["citation_ids"],
            )
            with ArtifactKnowledgeIndex(artifact, base=base) as artifact_index:
                artifact_records = {
                    record.record_id: record
                    for record in artifact_index.records
                    if record.source_kind == "knowledge"
                }
                self.assertEqual(
                    by_id["kitm-citation-scope-1"].citation_ids,
                    artifact_records["kitm-citation-scope-1"].citation_ids,
                )
                self.assertEqual(
                    by_id["kitm-citation-scope-2"].citation_ids,
                    artifact_records["kitm-citation-scope-2"].citation_ids,
                )

    def test_information_anchors_and_explicit_contrast_fail_closed(self) -> None:
        low_information = self.index.search("为什么 什么 应该")
        self.assertFalse(
            any(
                "route:formal-grounded-evidence" in card.hit_reasons
                for card in low_information.cards
            )
        )

        contrast = self.index.search(
            "订单簿数据清洗，不是 Rank IC 横截面因子"
        )
        factor_id = self._record_for_path("factor.md").document_id
        crypto_id = self._record_for_path("crypto.md").document_id
        self.assertTrue(any(card.document_id == crypto_id for card in contrast.cards))
        self.assertFalse(any(card.document_id == factor_id for card in contrast.cards))

        generic_words_cannot_outvote_rejection = self.index.search(
            "因子 数据 处理，不是缩尾"
        )
        self.assertFalse(
            any(
                card.document_id == self._record_for_path("data.md").document_id
                for card in generic_words_cannot_outvote_rejection.cards
            )
        )
        english_contrast = self.index.search(
            "order book data cleaning, not Rank IC but neutralization"
        )
        self.assertFalse(any(card.document_id == factor_id for card in english_contrast.cards))

        fixture = Path(__file__).parent / "fixtures" / "knowledge_eval" / "qrels.json"
        suite = bind_qrel_templates(fixture, self.base)
        source = next(
            row for row in suite.development()
            if row.qrel_id == "dev-data-hard-negative"
        )
        adversarial = QrelSuite.create(
            (
                replace(
                    source,
                    query="订单簿数据清洗，不是截面因子缩尾",
                    context=TaskContext(),
                ),
            )
        )
        report = evaluate(self.index, adversarial, split="development")
        self.assertEqual(0, report.forbidden_errors)
        self.assertEqual(0, report.conflict_errors)
        self.assertEqual(0, report.citation_errors)

    def test_applicability_is_item_scoped_and_aliases_are_controlled(self) -> None:
        items = self.store.items_for_versions(tuple(self.base.versions))
        factor_id = self._record_for_path("factor.md").document_id
        factor_method = next(
            item
            for item in items
            if item.document_id == factor_id and item.kind == "method"
        )
        self.store.add_item(
            replace(
                factor_method,
                knowledge_item_id="kitm-factor-independent-crypto-scope",
                cluster_id="kcl-factor-independent-crypto-scope",
                applicability={
                    "market": ("加密货币",),
                    "frequency": ("分钟",),
                    "data": ("订单簿",),
                },
            )
        )
        enriched = build_enriched_snapshot(self.base, self.store)
        with KnowledgeIndex(self.base, enriched) as index:
            original = next(
                record
                for record in index.records
                if record.record_id == factor_method.knowledge_item_id
            )
            independent = next(
                record
                for record in index.records
                if record.record_id == "kitm-factor-independent-crypto-scope"
            )
            _bonus, original_matches, original_conflicts = index._applicability(
                original,
                TaskContext.create(
                    market="加密货币", frequency="分钟", data="订单簿"
                ),
            )
            _bonus, independent_matches, independent_conflicts = index._applicability(
                independent,
                TaskContext.create(
                    market="加密货币", frequency="分钟", data="订单簿"
                ),
            )
            self.assertFalse(original_matches)
            self.assertGreaterEqual(len(original_conflicts), 3)
            self.assertGreaterEqual(len(independent_matches), 3)
            self.assertFalse(independent_conflicts)
            self.assertTrue(
                all(
                    not {
                        "market",
                        "frequency",
                        "data",
                    }
                    & set(record.applicability)
                    for record in index.records
                    if record.source_kind == "chunk"
                    and record.document_id == factor_id
                )
            )

            for context in (
                TaskContext.create(market="A 股", frequency="日 频"),
                TaskContext.create(market="China A-share", frequency="daily"),
            ):
                response = index.search("rank IC 横截面因子", context=context)
                self.assertTrue(
                    any(
                        card.evidence_id == factor_method.knowledge_item_id
                        and not card.applicability_conflicts
                        for card in response.cards
                    )
                )

    def test_relation_expansion_preserves_polarity_contrast_and_applicability(self) -> None:
        items = self.store.items_for_versions(tuple(self.base.versions))

        def method_for(path: str) -> KnowledgeItem:
            document_id = self._record_for_path(path).document_id
            return next(
                item
                for item in items
                if item.document_id == document_id and item.kind == "method"
            )

        source = method_for("crypto.md")
        factor = method_for("factor.md")
        backtest = method_for("backtest.md")
        model = method_for("model.md")
        for suffix, relation_type, target in (
            ("support-conflict", "supports", factor),
            ("support-compatible", "supports", backtest),
            ("negative-edge", "contradicts", model),
        ):
            self.store.add_item(
                replace(
                    source,
                    knowledge_item_id=f"kitm-relation-{suffix}",
                    cluster_id=f"kcl-relation-{suffix}",
                    relation={
                        "type": relation_type,
                        "target_id": target.knowledge_item_id,
                    },
                )
            )

        enriched = build_enriched_snapshot(self.base, self.store)
        with KnowledgeIndex(self.base, enriched) as index:
            compatible = index.search(
                "订单簿不平衡预测短期收益",
                context=TaskContext.create(
                    market="加密货币", frequency="分钟", data="订单簿"
                ),
            )
            compatible_ids = {card.document_id for card in compatible.cards}
            self.assertIn(self._record_for_path("backtest.md").document_id, compatible_ids)
            self.assertNotIn(self._record_for_path("factor.md").document_id, compatible_ids)
            self.assertNotIn(self._record_for_path("model.md").document_id, compatible_ids)
            self.assertTrue(
                any(
                    reason.startswith("relation:supports:")
                    for card in compatible.cards
                    if card.document_id == self._record_for_path("backtest.md").document_id
                    for reason in card.hit_reasons
                )
            )

            contrast = index.search("订单簿数据处理，不是 Rank IC 横截面因子")
            self.assertNotIn(
                self._record_for_path("factor.md").document_id,
                {card.document_id for card in contrast.cards},
            )

            artifact = json.loads(
                build_search_artifact(self.base, enriched=enriched)
            )
            with ArtifactKnowledgeIndex(artifact, base=self.base) as artifact_index:
                self.assertEqual(
                    compatible,
                    artifact_index.search(
                        "订单簿不平衡预测短期收益",
                        context=TaskContext.create(
                            market="加密货币", frequency="分钟", data="订单簿"
                        ),
                    ),
                )

    def test_exact_evidence_card_does_not_absorb_adjacent_context(self) -> None:
        list_root = self.root / "dedup-list"
        list_root.mkdir()
        (list_root / "methods.md").write_text(
            "# 成本方法\n\n"
            "- 方法：先检查高换手成本。\n"
            "- 证据：再检查成本后净收益。\n",
            encoding="utf-8",
        )
        compiled = ReferenceCompiler().compile(list_root)
        assert compiled.candidate_snapshot is not None
        base = compiled.candidate_snapshot
        document = next(iter(base.documents.values()))
        assert document.active_version_id is not None
        ir = base.ir_documents[document.active_version_id]
        first = next(
            block.source_span
            for block in ir.blocks
            if block.kind == "paragraph" and "高换手成本" in block.source_span.text
        )
        second = next(
            block.source_span
            for block in ir.blocks
            if block.kind == "paragraph" and "成本后净收益" in block.source_span.text
        )
        store = SemanticJobStore(list_root / "runtime" / "knowledge.sqlite3")
        quote = first.text.strip()
        byte_start = first.byte_start + len(
            first.text[: first.text.index(quote)].encode("utf-8")
        )
        store.add_item(
            KnowledgeItem(
                knowledge_item_id="kitm-dedup-method",
                cluster_id="kcl-dedup-method",
                document_id=document.document_id,
                document_version_id=document.active_version_id,
                kind="method",
                text="先检查高换手成本",
                evidence=(
                    EvidenceBinding(
                        first.span_id,
                        quote,
                        hashlib.sha256(quote.encode("utf-8")).hexdigest(),
                        byte_start,
                        byte_start + len(quote.encode("utf-8")),
                    ),
                ),
                applicability={},
                relation=None,
                fact_status="source_explicit",
                extractor="fixture",
                extractor_version="fixture/v1",
                generation_id=None,
                accepted_at="2026-08-21T00:00:00.000000Z",
                accepted_by="fixture-reviewer",
            )
        )
        enriched = build_enriched_snapshot(base, store)
        with KnowledgeIndex(base, enriched) as index:
            response = index.search("高换手成本 净收益")
            canonical = [
                card
                for card in response.cards
                if card.source_kind == "knowledge"
                and first.span_id in card.covered_span_ids
            ]
            self.assertEqual(1, len(canonical))
            card = canonical[0]
            self.assertEqual("knowledge", card.source_kind)
            self.assertEqual(first.span_id, card.locator.span_id)
            self.assertNotIn(second.span_id, card.covered_span_ids)
            second_locator = GroundedLocator(
                document_version_id=document.active_version_id,
                span_id=second.span_id,
                source_sha256=second.source_sha256,
                byte_start=second.byte_start,
                byte_end=second.byte_end,
                quote_sha256=second.text_sha256,
            )
            self.assertFalse(_card_covers_locator(base, card, second_locator))
            qrel = QrelSuite.create(
                (
                    Qrel(
                        qrel_id="dev-dedup-union",
                        split="development",
                        category="backtest",
                        query="高换手成本 净收益",
                        context=TaskContext(),
                        answerable=True,
                        positive_locators=(
                            GroundedLocator(
                                document_version_id=document.active_version_id,
                                span_id=first.span_id,
                                source_sha256=first.source_sha256,
                                byte_start=byte_start,
                                byte_end=byte_start + len(quote.encode("utf-8")),
                                quote_sha256=hashlib.sha256(
                                    quote.encode("utf-8")
                                ).hexdigest(),
                            ),
                        ),
                        negative_locators=(),
                        expected_knowledge_kinds=(),
                        forbidden_document_ids=(),
                        required_citation_ids=(),
                        slices=("hard_negative",),
                    ),
                )
            )
            report = evaluate(index, qrel, split="development")
            self.assertLessEqual(report.ndcg_at_k, 1.0)
            self.assertEqual(0, report.forbidden_errors)

    def test_qrels_are_grounded_sealed_stale_aware_and_evaluable(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "knowledge_eval" / "qrels.json"
        suite = bind_qrel_templates(fixture, self.base)
        self.assertEqual(12, len(suite.qrels))
        self.assertEqual((), suite.validate(self.base))
        self.assertEqual(4, len(suite.sealed_holdout()))
        with self.assertRaisesRegex(ValueError, "sealed holdout"):
            suite.mark_used_for_tuning((suite.sealed_holdout()[0].qrel_id,))
        tuned = suite.mark_used_for_tuning((suite.development()[0].qrel_id,))
        self.assertTrue(tuned.development()[0].tuned)

        development = evaluate(self.index, suite, split="development")
        holdout = evaluate(self.index, suite, split="holdout")
        product_development = evaluate(
            self.artifact_index, suite, split="development"
        )
        product_holdout = evaluate(self.artifact_index, suite, split="holdout")
        self.assertEqual(8, development.count)
        self.assertEqual(4, holdout.count)
        self.assertEqual(0, development.deprecated_errors)
        self.assertEqual(0, development.conflict_errors)
        self.assertEqual(0, development.forbidden_errors)
        self.assertEqual(0, development.citation_errors)
        self.assertGreater(development.no_answer_accuracy, 0.99)
        self.assertLessEqual(development.ndcg_at_k, 1.0)
        self.assertLessEqual(holdout.ndcg_at_k, 1.0)
        self.assertGreater(development.index_footprint_bytes, 0)
        self.assertGreaterEqual(development.index_build_latency_ms, 0)
        answerable = next(
            row for row in suite.development() if row.qrel_id == "dev-factor-rank-ic"
        )
        no_answer = next(
            row for row in suite.development() if row.qrel_id == "dev-no-answer"
        )
        answerable_only = evaluate(
            self.index, QrelSuite.create((answerable,)), split="development"
        )
        mixed = evaluate(
            self.index,
            QrelSuite.create((answerable, no_answer)),
            split="development",
        )
        self.assertEqual(answerable_only.recall_at_k, mixed.recall_at_k)
        self.assertEqual(answerable_only.ndcg_at_k, mixed.ndcg_at_k)
        self.assertEqual(answerable_only.reciprocal_rank, mixed.reciprocal_rank)
        self.assertEqual(1.0, mixed.no_answer_accuracy)

        locator = answerable.positive_locators[0]
        tampered = QrelSuite.create(
            (
                replace(
                    answerable,
                    positive_locators=(
                        replace(locator, quote_sha256="0" * 64),
                    ),
                ),
                *(
                    row
                    for row in suite.qrels
                    if row.qrel_id != answerable.qrel_id
                ),
            )
        )
        self.assertTrue(
            any(
                "qrel quote hash is invalid" in failure
                for failure in tampered.validate(self.base)
            )
        )
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
            "gate_pass",
        ):
            self.assertEqual(
                getattr(development, field), getattr(product_development, field), field
            )
            self.assertEqual(
                getattr(holdout, field), getattr(product_holdout, field), field
            )

        baseline_index = LikeBaselineIndex(self.base, self.enriched)
        self.addCleanup(baseline_index.close)
        baseline = evaluate(baseline_index, suite, split="development")
        comparison = compare_candidate_to_baseline(
            development,
            baseline,
            difficult_slices=("hard_negative", "condition_conflict", "cross_language"),
        )
        self.assertTrue(comparison.gate_pass, comparison)

        # A source revision invalidates version-grounded qrels automatically.
        (self.root / "data.md").write_text(
            "# 因子数据处理 v2\n\n方法：使用稳健分位数变换\n", encoding="utf-8"
        )
        revised = ReferenceCompiler().compile(self.root, previous=self.base)
        assert revised.candidate_snapshot is not None
        stale = suite.stale_qrels(revised.candidate_snapshot)
        self.assertIn("dev-data-winsorize", stale)

    def test_missing_required_citation_is_a_hard_gate_error(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "knowledge_eval" / "qrels.json"
        suite = bind_qrel_templates(fixture, self.base)
        source = next(row for row in suite.development() if row.qrel_id == "dev-backtest-cost")
        miscitation = QrelSuite.create(
            (replace(source, required_citation_ids=("citation-does-not-exist",)),)
        )
        report = evaluate(self.index, miscitation, split="development")
        self.assertEqual(1, report.citation_errors)
        self.assertFalse(report.gate_pass)

    def test_qrel_list_quote_uses_narrowest_canonical_source_view(self) -> None:
        list_root = self.root / "list-qrel"
        list_root.mkdir()
        (list_root / "list.md").write_text(
            "# List method\n\n- 方法一：先做时序净化。\n- 方法二：再做样本外验证。\n",
            encoding="utf-8",
        )
        report = ReferenceCompiler().compile(list_root)
        assert report.candidate_snapshot is not None
        fixture = list_root / "qrels.json"
        fixture.write_text(
            json.dumps(
                {
                    "schema_version": "qrh-qrel-template/v1",
                    "qrels": [
                        {
                            "qrel_id": "list-source-view",
                            "split": "development",
                            "category": "factor",
                            "query": "时序净化",
                            "context": {},
                            "answerable": True,
                            "positive_sources": [
                                {
                                    "logical_path": "list.md",
                                    "quote": "先做时序净化",
                                }
                            ],
                            "negative_sources": [],
                            "expected_knowledge_kinds": [],
                            "slices": ["hard_negative"],
                        }
                    ],
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        suite = bind_qrel_templates(fixture, report.candidate_snapshot)
        locator = suite.qrels[0].positive_locators[0]
        ir = report.candidate_snapshot.ir_documents[locator.document_version_id]
        selected = next(
            block for block in ir.blocks
            if block.source_span.span_id == locator.span_id
        )
        self.assertEqual("paragraph", selected.kind)


if __name__ == "__main__":
    unittest.main()
