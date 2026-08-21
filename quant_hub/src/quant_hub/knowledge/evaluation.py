"""Grounded qrels, sealed holdout rules and retrieval quality gates."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import json
import math
from pathlib import Path
import statistics
import time
from typing import Any, Literal, Sequence

from .contracts import BaseSnapshot, content_hash
from .retrieval import KnowledgeIndex, SearchResponse, TaskContext


QREL_SCHEMA_VERSION = "qrh-grounded-qrels/v2-exact-range"
_CATEGORIES = frozenset({"factor", "model", "data", "backtest"})
_REQUIRED_SLICES = frozenset(
    {
        "hard_negative",
        "no_answer",
        "condition_conflict",
        "historical_deprecated",
        "miscitation",
        "cross_language",
        "formula_alias",
    }
)
_MIN_RECALL_AT_K = 0.75
_MIN_NDCG_AT_K = 0.60
_MIN_NO_ANSWER_ACCURACY = 1.0
_MIN_CITATION_ACCURACY = 1.0


@dataclass(frozen=True, slots=True)
class GroundedLocator:
    document_version_id: str
    span_id: str
    source_sha256: str
    byte_start: int
    byte_end: int
    quote_sha256: str


@dataclass(frozen=True, slots=True)
class Qrel:
    qrel_id: str
    split: Literal["development", "holdout"]
    category: Literal["factor", "model", "data", "backtest"]
    query: str
    context: TaskContext
    answerable: bool
    positive_locators: tuple[GroundedLocator, ...]
    negative_locators: tuple[GroundedLocator, ...]
    expected_knowledge_kinds: tuple[str, ...]
    forbidden_document_ids: tuple[str, ...]
    required_citation_ids: tuple[str, ...]
    slices: tuple[str, ...]
    include_history: bool = False
    tuned: bool = False


@dataclass(frozen=True, slots=True)
class QrelSuite:
    schema_version: str
    qrels: tuple[Qrel, ...]
    suite_hash: str

    @classmethod
    def create(cls, qrels: Sequence[Qrel]) -> "QrelSuite":
        ordered = tuple(sorted(qrels, key=lambda row: row.qrel_id))
        if len({row.qrel_id for row in ordered}) != len(ordered):
            raise ValueError("qrel IDs must be unique")
        payload = [asdict(row) for row in ordered]
        return cls(QREL_SCHEMA_VERSION, ordered, content_hash("qrh-qrel-suite/v2", payload))

    def validate(self, base: BaseSnapshot) -> tuple[str, ...]:
        failures: list[str] = []
        if not self.qrels:
            return ("qrel suite is empty",)
        holdout = [row for row in self.qrels if row.split == "holdout"]
        if len(holdout) * 3 < len(self.qrels):
            failures.append("sealed holdout is less than one third")
        if {row.category for row in self.qrels} != _CATEGORIES:
            failures.append("factor/model/data/backtest category coverage is incomplete")
        covered_slices = {value for row in self.qrels for value in row.slices}
        for missing in sorted(_REQUIRED_SLICES - covered_slices):
            failures.append(f"missing required slice:{missing}")
        normalized_queries: dict[str, str] = {}
        for row in self.qrels:
            normalized = " ".join(row.query.casefold().split())
            other_split = normalized_queries.get(normalized)
            if other_split is not None and other_split != row.split:
                failures.append(f"query leakage across splits:{row.qrel_id}")
            normalized_queries[normalized] = row.split
            if row.split == "holdout" and row.tuned:
                failures.append(f"holdout qrel was used for tuning:{row.qrel_id}")
            if row.answerable and not row.positive_locators:
                failures.append(f"answerable qrel has no positive locator:{row.qrel_id}")
            if not row.answerable and row.positive_locators:
                failures.append(f"no-answer qrel has positive locator:{row.qrel_id}")
            for locator in (*row.positive_locators, *row.negative_locators):
                ir = base.ir_documents.get(locator.document_version_id)
                if ir is None:
                    failures.append(f"unknown qrel source version:{row.qrel_id}")
                    continue
                spans = {
                    span.span_id: span
                    for block in ir.blocks
                    for span in (block.source_span, *block.spans)
                }
                span = spans.get(locator.span_id)
                if span is None:
                    failures.append(f"unknown qrel source span:{row.qrel_id}")
                    continue
                if (
                    locator.source_sha256 != span.source_sha256
                    or not 0 <= locator.byte_start < locator.byte_end
                    or not span.byte_start <= locator.byte_start
                    or locator.byte_end > span.byte_end
                ):
                    failures.append(f"qrel source range is invalid:{row.qrel_id}")
                    continue
                raw = span.text.encode("utf-8")
                relative_start = locator.byte_start - span.byte_start
                relative_end = locator.byte_end - span.byte_start
                try:
                    quote = raw[relative_start:relative_end].decode(
                        "utf-8", errors="strict"
                    )
                except UnicodeDecodeError:
                    failures.append(f"qrel source range splits UTF-8:{row.qrel_id}")
                    continue
                if hashlib.sha256(quote.encode("utf-8")).hexdigest() != locator.quote_sha256:
                    failures.append(f"qrel quote hash is invalid:{row.qrel_id}")
            if set(row.positive_locators) & set(row.negative_locators):
                failures.append(f"qrel source is both positive and negative:{row.qrel_id}")
            if any(
                kind not in {"summary", "method", "condition", "limitation", "failure", "evidence"}
                for kind in row.expected_knowledge_kinds
            ):
                failures.append(f"unknown expected knowledge kind:{row.qrel_id}")
        return tuple(dict.fromkeys(failures))

    def stale_qrels(self, base: BaseSnapshot) -> tuple[str, ...]:
        stale: list[str] = []
        for row in self.qrels:
            if row.include_history:
                continue
            for locator in (*row.positive_locators, *row.negative_locators):
                version = base.versions.get(locator.document_version_id)
                if version is None or base.active_membership.get(version.document_id) != locator.document_version_id:
                    stale.append(row.qrel_id)
                    break
        return tuple(sorted(set(stale)))

    def development(self) -> tuple[Qrel, ...]:
        return tuple(row for row in self.qrels if row.split == "development")

    def sealed_holdout(self) -> tuple[Qrel, ...]:
        return tuple(row for row in self.qrels if row.split == "holdout")

    def mark_used_for_tuning(self, qrel_ids: Sequence[str]) -> "QrelSuite":
        selected = set(qrel_ids)
        if any(row.qrel_id in selected and row.split == "holdout" for row in self.qrels):
            raise ValueError("sealed holdout cannot be used for tuning")
        updated = [replace(row, tuned=row.tuned or row.qrel_id in selected) for row in self.qrels]
        return QrelSuite.create(updated)


@dataclass(frozen=True, slots=True)
class SliceMetrics:
    count: int
    recall_at_k: float
    ndcg_at_k: float
    no_answer_accuracy: float
    hard_errors: int


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    split: str
    qrel_suite_hash: str
    count: int
    recall_at_k: float
    ndcg_at_k: float
    reciprocal_rank: float
    no_answer_accuracy: float
    citation_accuracy: float
    p95_latency_ms: float
    index_footprint_bytes: int
    index_build_latency_ms: float
    deprecated_errors: int
    conflict_errors: int
    forbidden_errors: int
    knowledge_kind_errors: int
    citation_errors: int
    stale_qrels: tuple[str, ...]
    slices: dict[str, SliceMetrics]
    gate_pass: bool


def _locator_key(locator: GroundedLocator) -> str:
    return (
        f"{locator.document_version_id}:{locator.span_id}:"
        f"{locator.byte_start}:{locator.byte_end}:{locator.quote_sha256}"
    )


def _span_for_locator(base: BaseSnapshot, locator: GroundedLocator) -> Any:
    ir = base.ir_documents[locator.document_version_id]
    for block in ir.blocks:
        if block.source_span.span_id == locator.span_id:
            return block.source_span
        for span in block.spans:
            if span.span_id == locator.span_id:
                return span
    raise ValueError("grounded locator span disappeared after suite validation")


def _card_covers_locator(
    base: BaseSnapshot, card: Any, locator: GroundedLocator
) -> bool:
    if card.document_version_id != locator.document_version_id:
        return False
    # ``covered_span_ids`` is context/navigation closure and may include an
    # adjacent paragraph or a parent span.  Relevance is evidence, not context:
    # only the exact displayed locator may satisfy a positive or negative qrel.
    return (
        card.locator.source_sha256 == locator.source_sha256
        and card.locator.byte_start <= locator.byte_start
        and card.locator.byte_end >= locator.byte_end
    )


def evaluate(
    index: KnowledgeIndex,
    suite: QrelSuite,
    *,
    split: Literal["development", "holdout"],
    limit: int = 8,
) -> EvaluationReport:
    qrels = suite.development() if split == "development" else suite.sealed_holdout()
    stale = suite.stale_qrels(index.base)
    split_stale = tuple(
        value for value in stale if any(row.qrel_id == value for row in qrels)
    )
    rows: list[dict[str, Any]] = []
    latencies: list[float] = []
    for qrel in qrels:
        started = time.perf_counter()
        response = index.search(
            qrel.query,
            context=qrel.context,
            limit=limit,
            include_history=qrel.include_history,
        )
        latencies.append((time.perf_counter() - started) * 1000)
        positives = {_locator_key(item): item for item in qrel.positive_locators}
        negatives = {_locator_key(item): item for item in qrel.negative_locators}
        retrieved_by_card = [
            {
                key
                for key, locator in positives.items()
                if _card_covers_locator(index.base, card, locator)
            }
            for card in response.cards
        ]
        negative_by_card = [
            {
                key
                for key, locator in negatives.items()
                if _card_covers_locator(index.base, card, locator)
            }
            for card in response.cards
        ]
        retrieved = set().union(*retrieved_by_card) if retrieved_by_card else set()
        relevant_ranks: list[int] = []
        seen_relevant: set[str] = set()
        for rank, keys in enumerate(retrieved_by_card, 1):
            newly_relevant = (keys & set(positives)) - seen_relevant
            relevant_ranks.extend([rank] * len(newly_relevant))
            seen_relevant.update(newly_relevant)
        recall = 1.0 if (not qrel.answerable and not response.cards) else (
            len(retrieved & set(positives)) / len(positives) if positives else 0.0
        )
        dcg = sum(1 / math.log2(rank + 1) for rank in relevant_ranks)
        ideal = sum(1 / math.log2(rank + 1) for rank in range(1, min(len(positives), limit) + 1))
        ndcg = dcg / ideal if ideal else (1.0 if not qrel.answerable and not response.cards else 0.0)
        reciprocal = 1 / relevant_ranks[0] if relevant_ranks else 0.0
        no_answer_correct = None if qrel.answerable else not response.cards
        relevant_card_indexes = {
            index for index, keys in enumerate(retrieved_by_card) if keys
        }
        citations = {
            citation
            for index, card in enumerate(response.cards)
            if index in relevant_card_indexes
            for citation in card.citation_ids
        }
        citation_correct = not qrel.required_citation_ids or set(qrel.required_citation_ids) <= citations
        deprecated_error = any(card.active_status != "active" for card in response.cards) and not qrel.include_history
        conflict_error = any(card.applicability_conflicts for card in response.cards)
        kind_error = bool(qrel.expected_knowledge_kinds) and not any(
            index in relevant_card_indexes
            and card.knowledge_kind in qrel.expected_knowledge_kinds
            for index, card in enumerate(response.cards)
        )
        forbidden_error = any(
            card.document_id in qrel.forbidden_document_ids
            or bool(negative_by_card[index])
            for index, card in enumerate(response.cards)
        )
        rows.append(
            {
                "qrel": qrel,
                "recall": recall,
                "ndcg": ndcg,
                "reciprocal": reciprocal,
                "no_answer_correct": no_answer_correct,
                "citation_correct": citation_correct,
                "deprecated_error": deprecated_error,
                "conflict_error": conflict_error,
                "forbidden_error": forbidden_error,
                "kind_error": kind_error,
            }
        )
    def mean(key: str, selected: Sequence[dict[str, Any]] | None = None) -> float:
        values = rows if selected is None else selected
        return statistics.fmean(float(row[key]) for row in values) if values else 0.0

    answerable_rows = [row for row in rows if row["qrel"].answerable]
    no_answer_rows = [row for row in rows if not row["qrel"].answerable]

    slice_metrics: dict[str, SliceMetrics] = {}
    slice_names = sorted({value for row in qrels for value in row.slices})
    for name in slice_names:
        selected = [row for row in rows if name in row["qrel"].slices]
        hard = sum(
            bool(
                row["deprecated_error"]
                or row["conflict_error"]
                or row["forbidden_error"]
                or row["kind_error"]
                or not row["citation_correct"]
            )
            for row in selected
        )
        selected_answerable = [row for row in selected if row["qrel"].answerable]
        selected_no_answer = [row for row in selected if not row["qrel"].answerable]
        slice_metrics[name] = SliceMetrics(
            count=len(selected),
            recall_at_k=(
                statistics.fmean(row["recall"] for row in selected_answerable)
                if selected_answerable
                else 1.0
            ),
            ndcg_at_k=(
                statistics.fmean(row["ndcg"] for row in selected_answerable)
                if selected_answerable
                else 1.0
            ),
            no_answer_accuracy=(
                statistics.fmean(
                    float(row["no_answer_correct"]) for row in selected_no_answer
                )
                if selected_no_answer
                else 1.0
            ),
            hard_errors=hard,
        )
    deprecated_errors = sum(row["deprecated_error"] for row in rows)
    conflict_errors = sum(row["conflict_error"] for row in rows)
    forbidden_errors = sum(row["forbidden_error"] for row in rows)
    knowledge_kind_errors = sum(row["kind_error"] for row in rows)
    citation_errors = sum(not row["citation_correct"] for row in rows)
    p95 = 0.0
    if latencies:
        ordered = sorted(latencies)
        p95 = ordered[min(len(ordered) - 1, math.ceil(len(ordered) * 0.95) - 1)]
    hard_errors = (
        deprecated_errors
        + conflict_errors
        + forbidden_errors
        + knowledge_kind_errors
        + citation_errors
    )
    recall_at_k = mean("recall", answerable_rows)
    ndcg_at_k = mean("ndcg", answerable_rows)
    no_answer_accuracy = (
        mean("no_answer_correct", no_answer_rows) if no_answer_rows else 1.0
    )
    citation_accuracy = mean("citation_correct")
    gate_pass = (
        hard_errors == 0
        and not split_stale
        and recall_at_k >= _MIN_RECALL_AT_K
        and ndcg_at_k >= _MIN_NDCG_AT_K
        and no_answer_accuracy >= _MIN_NO_ANSWER_ACCURACY
        and citation_accuracy >= _MIN_CITATION_ACCURACY
    )
    return EvaluationReport(
        split=split,
        qrel_suite_hash=suite.suite_hash,
        count=len(rows),
        recall_at_k=recall_at_k,
        ndcg_at_k=ndcg_at_k,
        reciprocal_rank=mean("reciprocal", answerable_rows),
        no_answer_accuracy=no_answer_accuracy,
        citation_accuracy=citation_accuracy,
        p95_latency_ms=round(p95, 6),
        index_footprint_bytes=index.index_footprint_bytes,
        index_build_latency_ms=index.build_latency_ms,
        deprecated_errors=deprecated_errors,
        conflict_errors=conflict_errors,
        forbidden_errors=forbidden_errors,
        knowledge_kind_errors=knowledge_kind_errors,
        citation_errors=citation_errors,
        stale_qrels=split_stale,
        slices=slice_metrics,
        gate_pass=gate_pass,
    )


@dataclass(frozen=True, slots=True)
class ComparisonReport:
    improved_slices: tuple[str, ...]
    regressed_slices: tuple[str, ...]
    hard_error_delta: int
    gate_pass: bool


def compare_candidate_to_baseline(
    candidate: EvaluationReport,
    baseline: EvaluationReport,
    *,
    difficult_slices: Sequence[str],
    minimum_gain: float = 0.05,
) -> ComparisonReport:
    if candidate.split != baseline.split or candidate.count != baseline.count:
        raise ValueError("candidate and baseline reports are not comparable")
    improved: list[str] = []
    regressed: list[str] = []
    for name in difficult_slices:
        candidate_slice = candidate.slices.get(name)
        baseline_slice = baseline.slices.get(name)
        if candidate_slice is None or baseline_slice is None:
            continue
        gain = candidate_slice.ndcg_at_k - baseline_slice.ndcg_at_k
        if gain >= minimum_gain:
            improved.append(name)
        elif gain < 0:
            regressed.append(name)
    candidate_errors = (
        candidate.deprecated_errors
        + candidate.conflict_errors
        + candidate.forbidden_errors
        + candidate.knowledge_kind_errors
        + candidate.citation_errors
    )
    baseline_errors = (
        baseline.deprecated_errors
        + baseline.conflict_errors
        + baseline.forbidden_errors
        + baseline.knowledge_kind_errors
        + baseline.citation_errors
    )
    delta = candidate_errors - baseline_errors
    return ComparisonReport(
        improved_slices=tuple(improved),
        regressed_slices=tuple(regressed),
        hard_error_delta=delta,
        gate_pass=len(improved) >= 2 and not regressed and candidate_errors == 0,
    )


def bind_qrel_templates(path: Path, base: BaseSnapshot) -> QrelSuite:
    """Bind human-readable fixture paths/quotes to immutable current IDs.

    ``forbidden_logical_paths`` exists only in the human-authored template;
    the bound qrel carries stable document IDs, so a forbidden-source check is
    mechanically non-vacuous without hand-copying generated identities.
    """

    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != "qrh-qrel-template/v1" or type(payload.get("qrels")) is not list:
        raise ValueError("qrel template schema is invalid")
    path_to_document = {
        record.canonical_path: record for record in base.documents.values() if record.status == "active"
    }
    qrels: list[Qrel] = []
    for raw in payload["qrels"]:
        def bind(values: Sequence[dict[str, str]]) -> tuple[GroundedLocator, ...]:
            rows: list[GroundedLocator] = []
            for value in values:
                record = path_to_document.get(value["logical_path"])
                if record is None or record.active_version_id is None:
                    raise ValueError(
                        f"qrel path is not active:{raw.get('qrel_id')}:{value['logical_path']}"
                    )
                ir = base.ir_documents[record.active_version_id]
                matches = [
                    block
                    for block in ir.blocks
                    if value["quote"] in block.source_span.text
                ]
                if not matches:
                    raise ValueError(
                        "qrel quote does not resolve to a source span:"
                        f"{raw.get('qrel_id')}:{value['logical_path']}"
                    )
                # Markdown list IR deliberately contains an aggregate list,
                # list-item and leaf paragraph view of the same source bytes.
                # Qrels bind to the narrowest physical source range; duplicate
                # views of that exact range use a fixed leaf-kind preference.
                # Distinct equally narrow physical occurrences remain
                # ambiguous and fail closed.
                minimum_bytes = min(
                    block.source_span.byte_end - block.source_span.byte_start
                    for block in matches
                )
                narrowest = [
                    block
                    for block in matches
                    if block.source_span.byte_end - block.source_span.byte_start
                    == minimum_bytes
                ]
                physical_ranges = {
                    (
                        block.source_span.byte_start,
                        block.source_span.byte_end,
                        block.source_span.text_sha256,
                    )
                    for block in narrowest
                }
                if len(physical_ranges) != 1:
                    raise ValueError(
                        "qrel quote is physically ambiguous:"
                        f"{raw.get('qrel_id')}:{value['logical_path']}"
                    )
                kind_order = {"paragraph": 0, "list_item": 1, "list": 2}
                selected = min(
                    narrowest,
                    key=lambda block: (kind_order.get(block.kind, 9), block.block_id),
                )
                occurrences: list[int] = []
                cursor = 0
                while True:
                    found = selected.source_span.text.find(value["quote"], cursor)
                    if found < 0:
                        break
                    occurrences.append(found)
                    cursor = found + 1
                if len(occurrences) != 1:
                    raise ValueError(
                        "qrel quote is absent or repeated within its source span:"
                        f"{raw.get('qrel_id')}:{value['logical_path']}"
                    )
                character_start = occurrences[0]
                byte_start = selected.source_span.byte_start + len(
                    selected.source_span.text[:character_start].encode("utf-8")
                )
                quote_bytes = value["quote"].encode("utf-8")
                rows.append(
                    GroundedLocator(
                        document_version_id=record.active_version_id,
                        span_id=selected.source_span.span_id,
                        source_sha256=selected.source_span.source_sha256,
                        byte_start=byte_start,
                        byte_end=byte_start + len(quote_bytes),
                        quote_sha256=hashlib.sha256(quote_bytes).hexdigest(),
                    )
                )
            return tuple(rows)

        context = TaskContext.create(**raw.get("context", {}))
        raw_forbidden_ids = raw.get("forbidden_document_ids", [])
        raw_forbidden_paths = raw.get("forbidden_logical_paths", [])
        if (
            type(raw_forbidden_ids) is not list
            or any(
                not isinstance(value, str) or not value
                for value in raw_forbidden_ids
            )
            or type(raw_forbidden_paths) is not list
            or any(
                not isinstance(value, str) or not value
                for value in raw_forbidden_paths
            )
        ):
            raise ValueError(
                f"qrel forbidden sources are invalid:{raw.get('qrel_id')}"
            )
        known_document_ids = {
            record.document_id for record in path_to_document.values()
        }
        if any(value not in known_document_ids for value in raw_forbidden_ids):
            raise ValueError(
                f"qrel forbidden document is unknown:{raw.get('qrel_id')}"
            )
        forbidden_document_ids = list(raw_forbidden_ids)
        for logical_path in raw_forbidden_paths:
            record = path_to_document.get(logical_path)
            if record is None:
                raise ValueError(
                    "qrel forbidden path is not active:"
                    f"{raw.get('qrel_id')}:{logical_path}"
                )
            forbidden_document_ids.append(record.document_id)
        qrels.append(
            Qrel(
                qrel_id=raw["qrel_id"],
                split=raw["split"],
                category=raw["category"],
                query=raw["query"],
                context=context,
                answerable=raw["answerable"],
                positive_locators=bind(raw.get("positive_sources", [])),
                negative_locators=bind(raw.get("negative_sources", [])),
                expected_knowledge_kinds=tuple(raw.get("expected_knowledge_kinds", [])),
                forbidden_document_ids=tuple(
                    sorted(set(forbidden_document_ids))
                ),
                required_citation_ids=tuple(raw.get("required_citation_ids", [])),
                slices=tuple(raw.get("slices", [])),
                include_history=bool(raw.get("include_history", False)),
            )
        )
    return QrelSuite.create(qrels)


__all__ = [
    "ComparisonReport",
    "EvaluationReport",
    "GroundedLocator",
    "QREL_SCHEMA_VERSION",
    "Qrel",
    "QrelSuite",
    "SliceMetrics",
    "bind_qrel_templates",
    "compare_candidate_to_baseline",
    "evaluate",
]
