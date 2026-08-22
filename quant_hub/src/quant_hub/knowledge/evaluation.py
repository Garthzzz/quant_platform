"""Grounded qrels, sealed holdout rules and retrieval quality gates."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import base64
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import statistics
import time
from typing import Any, Literal, Mapping, Sequence

from .contracts import BaseSnapshot, canonical_json, content_hash
from .retrieval import KnowledgeIndex, SearchResponse, TaskContext


QREL_SCHEMA_VERSION = "qrh-grounded-qrels/v2-exact-range"
RETRIEVAL_EVALUATOR_VERSION = "qrh-grounded-retrieval-evaluator/v3"
SUITE_VALIDATION_RECEIPT_SCHEMA = "qrh-qrel-suite-validation-receipt/v1"
PER_QREL_RECEIPT_SCHEMA = "qrh-retrieval-per-qrel-receipt/v2-live-stale-replay"
RETRIEVAL_COMPARISON_PREREGISTRATION_SCHEMA = (
    "qrh-retrieval-comparison-preregistration/v4-authoritative-like-stale-replay"
)
RETRIEVAL_PROJECTION_ARTIFACT_SCHEMA = "qrh-retrieval-evaluation-projection/v1"
_OVERALL_COMPARISON_METRICS = (
    "recall_at_k",
    "ndcg_at_k",
    "reciprocal_rank",
    "no_answer_accuracy",
)
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
        canonical_order = tuple(sorted(self.qrels, key=lambda row: row.qrel_id))
        expected_hash = content_hash(
            "qrh-qrel-suite/v2", [asdict(row) for row in canonical_order]
        )
        if self.schema_version != QREL_SCHEMA_VERSION:
            failures.append("qrel suite schema version is invalid")
        if self.qrels != canonical_order:
            failures.append("qrel suite order is not canonical")
        if len({row.qrel_id for row in self.qrels}) != len(self.qrels):
            failures.append("qrel IDs are not unique")
        if self.suite_hash != expected_hash:
            failures.append("qrel suite hash is invalid")
        if not self.qrels:
            failures.append("qrel suite is empty")
            return tuple(dict.fromkeys(failures))
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
            if row.split not in {"development", "holdout"}:
                failures.append(f"qrel split is invalid:{row.qrel_id}")
            if not isinstance(row.qrel_id, str) or not row.qrel_id:
                failures.append("qrel ID is invalid")
            if not isinstance(row.query, str) or not row.query.strip():
                failures.append(f"qrel query is invalid:{row.qrel_id}")
            if type(row.answerable) is not bool or type(row.include_history) is not bool:
                failures.append(f"qrel boolean fields are invalid:{row.qrel_id}")
            if (
                not row.slices
                or any(not isinstance(value, str) or not value for value in row.slices)
                or len(set(row.slices)) != len(row.slices)
            ):
                failures.append(f"qrel slices are invalid:{row.qrel_id}")
            for name, values in (
                ("expected knowledge kinds", row.expected_knowledge_kinds),
                ("forbidden document IDs", row.forbidden_document_ids),
                ("required citation IDs", row.required_citation_ids),
            ):
                if (
                    any(not isinstance(value, str) or not value for value in values)
                    or len(set(values)) != len(values)
                ):
                    failures.append(f"qrel {name} are invalid:{row.qrel_id}")
            if (
                len(set(row.positive_locators)) != len(row.positive_locators)
                or len(set(row.negative_locators)) != len(row.negative_locators)
            ):
                failures.append(f"qrel locators are duplicated:{row.qrel_id}")
            normalized = (
                " ".join(row.query.casefold().split())
                if isinstance(row.query, str)
                else ""
            )
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
    index_version: str
    authority: str
    suite_validation_receipt: bytes
    per_qrel_receipts: tuple[bytes, ...]


class QrelSuiteValidationError(ValueError):
    """Fail-closed validation error carrying the canonical rejection receipt."""

    def __init__(self, failures: Sequence[str], receipt: bytes) -> None:
        super().__init__("qrel suite validation failed: " + "; ".join(failures))
        self.failures = tuple(failures)
        self.receipt = receipt


def _suite_canonical_bytes(suite: QrelSuite) -> bytes:
    return canonical_json(
        {
            "schema_version": suite.schema_version,
            "suite_hash": suite.suite_hash,
            "qrels": [asdict(row) for row in suite.qrels],
        }
    ).encode("utf-8")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise ValueError("retrieval evidence timestamp is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError("retrieval evidence timestamp must be UTC")
    return parsed


def _write_new_ledger_bytes(path: Path, payload: bytes) -> None:
    """Create one immutable preregistration ledger entry without replacement."""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _index_projection_artifact_bytes(index: KnowledgeIndex) -> bytes:
    extension = b""
    producer = getattr(index, "evaluation_projection_artifact_bytes", None)
    if callable(producer):
        extension = producer()
        if not isinstance(extension, bytes):
            raise ValueError("retrieval projection extension must be bytes")
    value = {
        "schema_version": RETRIEVAL_PROJECTION_ARTIFACT_SCHEMA,
        "producer": f"{type(index).__module__}.{type(index).__qualname__}",
        "base_snapshot_id": index.base.snapshot_id,
        "snapshot_id": index.snapshot_id,
        "index_version": getattr(index, "index_version", None)
        or getattr(index, "_INDEX_VERSION", None)
        or "",
        "records": index.export_artifact_records()["records"],
        "producer_extension_base64": base64.b64encode(extension).decode("ascii"),
        "producer_extension_sha256": hashlib.sha256(extension).hexdigest(),
    }
    if not value["index_version"]:
        from .retrieval import INDEX_VERSION

        value["index_version"] = INDEX_VERSION
    return canonical_json(value).encode("utf-8")


def _index_projection_identity(index: KnowledgeIndex) -> dict[str, object]:
    artifact = _index_projection_artifact_bytes(index)
    decoded = json.loads(artifact)
    authority_producer = getattr(index, "evaluation_projection_authority", None)
    authority = (
        authority_producer()
        if callable(authority_producer)
        else "NATIVE_EVALUATION_ARTIFACT"
    )
    if not isinstance(authority, str) or not authority:
        raise ValueError("retrieval projection authority is invalid")
    source_receipt_producer = getattr(
        index, "qualification_source_receipt_bytes", None
    )
    source_receipt = (
        source_receipt_producer()
        if callable(source_receipt_producer)
        else b""
    )
    if not isinstance(source_receipt, bytes):
        raise ValueError("retrieval qualification source receipt must be bytes")
    return {
        "projection_producer": decoded["producer"],
        "qualification_authority": authority,
        "producer_extension_sha256": decoded["producer_extension_sha256"],
        "qualification_source_receipt_bytes": len(source_receipt),
        "qualification_source_receipt_sha256": hashlib.sha256(
            source_receipt
        ).hexdigest(),
        "artifact_bytes": len(artifact),
        "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
        "base_snapshot_id": index.base.snapshot_id,
        "snapshot_id": index.snapshot_id,
        "index_version": decoded["index_version"],
    }


def build_suite_validation_receipt(
    suite: QrelSuite, base: BaseSnapshot
) -> tuple[bytes, tuple[str, ...]]:
    suite_bytes = _suite_canonical_bytes(suite)
    failures = suite.validate(base)
    receipt = canonical_json(
        {
            "schema_version": SUITE_VALIDATION_RECEIPT_SCHEMA,
            "producer": RETRIEVAL_EVALUATOR_VERSION,
            "status": "PASS" if not failures else "FAIL",
            "suite": {
                "canonical_bytes": len(suite_bytes),
                "canonical_sha256": hashlib.sha256(suite_bytes).hexdigest(),
                "content_hash": suite.suite_hash,
            },
            "base_snapshot_id": base.snapshot_id,
            "failures": list(failures),
        }
    ).encode("utf-8")
    return receipt, failures


def _qrel_projection(qrel: Qrel) -> dict[str, object]:
    query_bytes = qrel.query.encode("utf-8")
    return {
        "qrel_id": qrel.qrel_id,
        "query_bytes_base64": base64.b64encode(query_bytes).decode("ascii"),
        "query_bytes": len(query_bytes),
        "query_sha256": hashlib.sha256(query_bytes).hexdigest(),
        "answerable": qrel.answerable,
        "slices": list(qrel.slices),
        "positive_locators": [asdict(locator) for locator in qrel.positive_locators],
        "negative_locators": [asdict(locator) for locator in qrel.negative_locators],
        "expected_knowledge_kinds": list(qrel.expected_knowledge_kinds),
        "forbidden_document_ids": list(qrel.forbidden_document_ids),
        "required_citation_ids": list(qrel.required_citation_ids),
        "include_history": qrel.include_history,
    }


def _response_card_projection(response: SearchResponse) -> list[dict[str, object]]:
    return [
        {
            "rank": card.rank,
            "evidence_id": card.evidence_id,
            "document_id": card.document_id,
            "document_version_id": card.document_version_id,
            "active_status": card.active_status,
            "knowledge_kind": card.knowledge_kind,
            "citation_ids": list(card.citation_ids),
            "has_applicability_conflicts": bool(card.applicability_conflicts),
            "displayed_bytes": len(card.text.encode("utf-8")),
            "displayed_bytes_base64": base64.b64encode(
                card.text.encode("utf-8")
            ).decode("ascii"),
            "displayed_sha256": hashlib.sha256(
                card.text.encode("utf-8")
            ).hexdigest(),
            "locator": asdict(card.locator),
        }
        for card in response.cards
    ]


def _load_exact_ledger_entry(path: Path, expected: bytes) -> None:
    try:
        actual = Path(path).read_bytes()
    except OSError as error:
        raise ValueError("retrieval preregistration ledger is unavailable") from error
    if actual != expected:
        raise ValueError("retrieval preregistration ledger bytes differ")


def _locator_key(locator: GroundedLocator) -> str:
    return (
        f"{locator.document_version_id}:{locator.span_id}:"
        f"{locator.source_sha256}:{locator.byte_start}:{locator.byte_end}:"
        f"{locator.quote_sha256}"
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
    # adjacent paragraph or a parent span.  A grounded qrel is satisfied only
    # by the exact displayed evidence locator.  Range containment is not
    # enough: a wider chunk, sibling span or context card must not receive
    # relevance credit for a narrower source quote.
    if (
        card.locator.span_id != locator.span_id
        or card.locator.source_sha256 != locator.source_sha256
        or card.locator.byte_start != locator.byte_start
        or card.locator.byte_end != locator.byte_end
    ):
        return False
    span = _span_for_locator(base, locator)
    if span.source_sha256 != locator.source_sha256:
        return False
    relative_start = locator.byte_start - span.byte_start
    relative_end = locator.byte_end - span.byte_start
    if not 0 <= relative_start < relative_end <= len(span.text.encode("utf-8")):
        return False
    quote = span.text.encode("utf-8")[relative_start:relative_end]
    try:
        quote.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    displayed = card.text.encode("utf-8")
    return (
        len(displayed) == locator.byte_end - locator.byte_start
        and displayed == quote
        and hashlib.sha256(displayed).hexdigest() == locator.quote_sha256
        and hashlib.sha256(quote).hexdigest() == locator.quote_sha256
    )


def evaluate(
    index: KnowledgeIndex,
    suite: QrelSuite,
    *,
    split: Literal["development", "holdout"],
    limit: int = 8,
    comparison_preregistration: bytes | None = None,
    preregistration_ledger: Path | None = None,
    comparison_role: Literal["candidate", "baseline"] | None = None,
) -> EvaluationReport:
    """Authoritative evaluator; a complete valid suite is mandatory."""

    validation_receipt, failures = build_suite_validation_receipt(suite, index.base)
    if failures:
        raise QrelSuiteValidationError(failures, validation_receipt)
    comparison_binding: dict[str, object] | None = None
    supplied = (
        comparison_preregistration is not None,
        preregistration_ledger is not None,
        comparison_role is not None,
    )
    if any(supplied) and not all(supplied):
        raise ValueError("comparison preregistration binding is incomplete")
    if all(supplied):
        assert comparison_preregistration is not None
        assert preregistration_ledger is not None
        assert comparison_role is not None
        registered = validate_retrieval_comparison_preregistration(
            comparison_preregistration
        )
        _load_exact_ledger_entry(
            preregistration_ledger, comparison_preregistration
        )
        suite_bytes = _suite_canonical_bytes(suite)
        actual_suite = {
            "schema_version": suite.schema_version,
            "content_hash": suite.suite_hash,
            "canonical_bytes": len(suite_bytes),
            "canonical_sha256": hashlib.sha256(suite_bytes).hexdigest(),
        }
        actual_projection = _index_projection_identity(index)
        expected_projection = (
            registered.candidate_projection
            if comparison_role == "candidate"
            else registered.baseline_projection
        )
        if (
            registered.suite != actual_suite
            or registered.split != split
            or registered.limit != limit
            or expected_projection != actual_projection
        ):
            raise ValueError("evaluation evidence differs from preregistration")
        started_at = _utc_now()
        if _parse_utc(started_at) <= _parse_utc(registered.registered_at):
            raise ValueError("evaluation did not start after preregistration")
        comparison_binding = {
            "run_id": registered.run_id,
            "role": comparison_role,
            "registered_at": registered.registered_at,
            "evaluation_started_at": started_at,
            "preregistration_sha256": hashlib.sha256(
                comparison_preregistration
            ).hexdigest(),
        }
    return _evaluate(
        index,
        suite,
        split=split,
        limit=limit,
        validation_receipt=validation_receipt,
        authoritative=True,
        comparison_binding=comparison_binding,
    )


def evaluate_non_authoritative(
    index: KnowledgeIndex,
    suite: QrelSuite,
    *,
    split: Literal["development", "holdout"],
    limit: int = 8,
) -> EvaluationReport:
    """Diagnostic lower API for partial fixtures; never emits comparison receipts."""

    return _evaluate(
        index,
        suite,
        split=split,
        limit=limit,
        validation_receipt=b"",
        authoritative=False,
        comparison_binding=None,
    )


def _evaluate(
    index: KnowledgeIndex,
    suite: QrelSuite,
    *,
    split: Literal["development", "holdout"],
    limit: int,
    validation_receipt: bytes,
    authoritative: bool,
    comparison_binding: Mapping[str, object] | None,
) -> EvaluationReport:
    if split not in {"development", "holdout"} or type(limit) is not int or limit < 1:
        raise ValueError("evaluation split or limit is invalid")
    qrels = suite.development() if split == "development" else suite.sealed_holdout()
    if not qrels:
        raise ValueError("selected qrel split is empty")
    stale = suite.stale_qrels(index.base)
    split_stale = tuple(
        value for value in stale if any(row.qrel_id == value for row in qrels)
    )
    rows: list[dict[str, Any]] = []
    latencies: list[float] = []
    index_versions: set[str] = set()
    for qrel in qrels:
        started = time.perf_counter()
        response = index.search(
            qrel.query,
            context=qrel.context,
            limit=limit,
            include_history=qrel.include_history,
        )
        if not isinstance(response.index_version, str) or not response.index_version:
            raise ValueError("retrieval response index version is invalid")
        index_versions.add(response.index_version)
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
                "response": response,
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
    if len(index_versions) != 1:
        raise ValueError("retrieval responses used mixed index versions")
    projection = _index_projection_identity(index)
    if projection["index_version"] != next(iter(index_versions)):
        raise ValueError("retrieval projection and response index version disagree")
    suite_bytes = _suite_canonical_bytes(suite)
    suite_binding = {
        "schema_version": suite.schema_version,
        "content_hash": suite.suite_hash,
        "canonical_bytes": len(suite_bytes),
        "canonical_sha256": hashlib.sha256(suite_bytes).hexdigest(),
    }
    receipt_bytes: list[bytes] = []
    if authoritative:
        validation_sha = hashlib.sha256(validation_receipt).hexdigest()
        for row in rows:
            qrel = row["qrel"]
            response = row["response"]
            cards = _response_card_projection(response)
            receipt_bytes.append(
                canonical_json(
                    {
                        "schema_version": PER_QREL_RECEIPT_SCHEMA,
                        "producer": RETRIEVAL_EVALUATOR_VERSION,
                        "authority": "AUTHORITATIVE_EVALUATOR",
                        "comparison": comparison_binding,
                        "suite": suite_binding,
                        "suite_validation_receipt_base64": (
                            base64.b64encode(validation_receipt).decode("ascii")
                        ),
                        "suite_validation_receipt_sha256": validation_sha,
                        "split": split,
                        "limit": limit,
                        "projection": projection,
                        "qrel": _qrel_projection(qrel),
                        "response_projection_sha256": hashlib.sha256(
                            canonical_json(cards).encode("utf-8")
                        ).hexdigest(),
                        "response_card_count": len(cards),
                        "response_cards": cards,
                        "metrics": {
                            "recall_at_k": row["recall"],
                            "ndcg_at_k": row["ndcg"],
                            "reciprocal_rank": row["reciprocal"],
                            "no_answer_correct": row["no_answer_correct"],
                            "citation_correct": row["citation_correct"],
                        },
                        "errors": {
                            "deprecated": row["deprecated_error"],
                            "conflict": row["conflict_error"],
                            "forbidden": row["forbidden_error"],
                            "knowledge_kind": row["kind_error"],
                            "citation": not row["citation_correct"],
                            "stale": qrel.qrel_id in split_stale,
                        },
                    }
                ).encode("utf-8")
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
        index_version=next(iter(index_versions)),
        authority=(
            "AUTHORITATIVE_EVALUATOR"
            if authoritative
            else "NON_AUTHORITATIVE_DIAGNOSTIC"
        ),
        suite_validation_receipt=validation_receipt,
        per_qrel_receipts=tuple(receipt_bytes),
    )


@dataclass(frozen=True, slots=True)
class ComparisonReport:
    improved_slices: tuple[str, ...]
    regressed_slices: tuple[str, ...]
    hard_error_delta: int
    overall_gains: dict[str, float]
    preregistration_sha256: str
    projection_authority_pass: bool
    gate_pass: bool


@dataclass(frozen=True, slots=True)
class RetrievalComparisonPreregistration:
    schema_version: str
    evaluator_version: str
    run_id: str
    registered_at: str
    suite: Mapping[str, object]
    split: Literal["development", "holdout"]
    limit: int
    candidate_projection: Mapping[str, object]
    baseline_projection: Mapping[str, object]
    difficult_slices: tuple[str, ...]
    minimum_slice_ndcg_gain: float
    minimum_overall_gains: dict[str, float]


def build_retrieval_comparison_preregistration(
    *,
    suite: QrelSuite,
    split: Literal["development", "holdout"],
    candidate_index: KnowledgeIndex,
    baseline_index: KnowledgeIndex,
    limit: int,
    difficult_slices: Sequence[str],
    run_id: str,
    ledger_path: Path,
    minimum_slice_ndcg_gain: float = 0.05,
    minimum_overall_gains: Mapping[str, float] | None = None,
) -> bytes:
    """Atomically freeze comparison choices before either side is evaluated."""

    overall = (
        {name: 0.0 for name in _OVERALL_COMPARISON_METRICS}
        if minimum_overall_gains is None
        else dict(minimum_overall_gains)
    )
    slices = tuple(difficult_slices)
    candidate_failures = suite.validate(candidate_index.base)
    baseline_failures = suite.validate(baseline_index.base)
    if candidate_failures or baseline_failures:
        raise ValueError("comparison preregistration requires a valid qrel suite")
    suite_bytes = _suite_canonical_bytes(suite)
    suite_binding = {
        "schema_version": suite.schema_version,
        "content_hash": suite.suite_hash,
        "canonical_bytes": len(suite_bytes),
        "canonical_sha256": hashlib.sha256(suite_bytes).hexdigest(),
    }
    candidate_projection = _index_projection_identity(candidate_index)
    baseline_projection = _index_projection_identity(baseline_index)
    registered_at = _utc_now()
    if (
        split not in {"development", "holdout"}
        or type(limit) is not int
        or limit < 1
        or len(slices) < 2
        or any(not isinstance(name, str) or not name for name in slices)
        or len(set(slices)) != len(slices)
        or isinstance(minimum_slice_ndcg_gain, bool)
        or not isinstance(minimum_slice_ndcg_gain, (int, float))
        or not math.isfinite(minimum_slice_ndcg_gain)
        or not 0 < minimum_slice_ndcg_gain <= 1
        or set(overall) != set(_OVERALL_COMPARISON_METRICS)
        or any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or not 0 <= value <= 1
            for value in overall.values()
        )
        or not isinstance(run_id, str)
        or not run_id
        or not isinstance(ledger_path, Path)
    ):
        raise ValueError("retrieval comparison preregistration is invalid")
    value = {
        "schema_version": RETRIEVAL_COMPARISON_PREREGISTRATION_SCHEMA,
        "evaluator_version": RETRIEVAL_EVALUATOR_VERSION,
        "run_id": run_id,
        "registered_at": registered_at,
        "suite": suite_binding,
        "split": split,
        "limit": limit,
        "candidate_projection": candidate_projection,
        "baseline_projection": baseline_projection,
        "difficult_slices": list(slices),
        "minimum_slice_ndcg_gain": minimum_slice_ndcg_gain,
        "minimum_overall_gains": {
            name: overall[name] for name in _OVERALL_COMPARISON_METRICS
        },
    }
    payload = canonical_json(value).encode("utf-8")
    _write_new_ledger_bytes(ledger_path, payload)
    return payload


def validate_retrieval_comparison_preregistration(
    payload: bytes,
) -> RetrievalComparisonPreregistration:
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("retrieval comparison preregistration bytes are invalid")
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("retrieval comparison preregistration is invalid JSON") from error
    expected_fields = {
        "schema_version",
        "evaluator_version",
        "run_id",
        "registered_at",
        "suite",
        "split",
        "limit",
        "candidate_projection",
        "baseline_projection",
        "difficult_slices",
        "minimum_slice_ndcg_gain",
        "minimum_overall_gains",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected_fields
        or value.get("schema_version")
        != RETRIEVAL_COMPARISON_PREREGISTRATION_SCHEMA
        or value.get("evaluator_version") != RETRIEVAL_EVALUATOR_VERSION
        or canonical_json(value).encode("utf-8") != payload
    ):
        raise ValueError("retrieval comparison preregistration is not closed canonical JSON")
    suite_fields = {
        "schema_version", "content_hash", "canonical_bytes", "canonical_sha256"
    }
    projection_fields = {
        "projection_producer", "qualification_authority",
        "producer_extension_sha256", "qualification_source_receipt_bytes",
        "qualification_source_receipt_sha256",
        "artifact_bytes", "artifact_sha256",
        "base_snapshot_id", "snapshot_id", "index_version"
    }
    if (
        not isinstance(value["suite"], dict)
        or set(value["suite"]) != suite_fields
        or not isinstance(value["candidate_projection"], dict)
        or set(value["candidate_projection"]) != projection_fields
        or not isinstance(value["baseline_projection"], dict)
        or set(value["baseline_projection"]) != projection_fields
        or value["split"] not in {"development", "holdout"}
        or not isinstance(value["run_id"], str)
        or not value["run_id"]
        or not isinstance(value["registered_at"], str)
        or type(value["limit"]) is not int
        or value["limit"] < 1
        or not isinstance(value["difficult_slices"], list)
        or len(value["difficult_slices"]) < 2
        or len(set(value["difficult_slices"])) != len(value["difficult_slices"])
        or any(not isinstance(item, str) or not item for item in value["difficult_slices"])
        or isinstance(value["minimum_slice_ndcg_gain"], bool)
        or not isinstance(value["minimum_slice_ndcg_gain"], (int, float))
        or not 0 < value["minimum_slice_ndcg_gain"] <= 1
        or not isinstance(value["minimum_overall_gains"], dict)
        or set(value["minimum_overall_gains"]) != set(_OVERALL_COMPARISON_METRICS)
        or any(
            isinstance(item, bool)
            or not isinstance(item, (int, float))
            or not math.isfinite(item)
            or not 0 <= item <= 1
            for item in value["minimum_overall_gains"].values()
        )
        or value["suite"].get("schema_version") != QREL_SCHEMA_VERSION
        or type(value["suite"].get("canonical_bytes")) is not int
        or value["suite"].get("canonical_bytes", 0) < 1
        or not _is_sha256(value["suite"].get("canonical_sha256"))
        or not _is_sha256(value["suite"].get("content_hash"))
        or any(
            not isinstance(projection.get("projection_producer"), str)
            or not projection.get("projection_producer")
            or not isinstance(projection.get("qualification_authority"), str)
            or not projection.get("qualification_authority")
            or not _is_sha256(projection.get("producer_extension_sha256"))
            or type(projection.get("qualification_source_receipt_bytes")) is not int
            or projection.get("qualification_source_receipt_bytes", -1) < 0
            or not _is_sha256(
                projection.get("qualification_source_receipt_sha256")
            )
            or type(projection.get("artifact_bytes")) is not int
            or projection.get("artifact_bytes", 0) < 1
            or not _is_sha256(projection.get("artifact_sha256"))
            or not isinstance(projection.get("snapshot_id"), str)
            or not projection.get("snapshot_id")
            or not isinstance(projection.get("base_snapshot_id"), str)
            or not projection.get("base_snapshot_id")
            or not isinstance(projection.get("index_version"), str)
            or not projection.get("index_version")
            for projection in (
                value["candidate_projection"], value["baseline_projection"]
            )
        )
    ):
        raise ValueError("retrieval comparison preregistration values are invalid")
    _parse_utc(value["registered_at"])
    return RetrievalComparisonPreregistration(
        schema_version=value["schema_version"],
        evaluator_version=value["evaluator_version"],
        run_id=value["run_id"],
        registered_at=value["registered_at"],
        suite=dict(value["suite"]),
        split=value["split"],
        limit=value["limit"],
        candidate_projection=dict(value["candidate_projection"]),
        baseline_projection=dict(value["baseline_projection"]),
        difficult_slices=tuple(value["difficult_slices"]),
        minimum_slice_ndcg_gain=float(value["minimum_slice_ndcg_gain"]),
        minimum_overall_gains={
            name: float(value["minimum_overall_gains"][name])
            for name in _OVERALL_COMPARISON_METRICS
        },
    )


def compare_candidate_to_baseline(
    candidate: Sequence[bytes],
    baseline: Sequence[bytes],
    *,
    preregistration: bytes,
    preregistration_ledger: Path,
    suite: QrelSuite,
    candidate_index: KnowledgeIndex,
    baseline_index: KnowledgeIndex,
) -> ComparisonReport:
    def archive_authority_identity() -> tuple[bytes, bytes, bytes]:
        from .retrieval import validate_authoritative_archive_like_projection

        artifact = validate_authoritative_archive_like_projection(baseline_index)
        artifact_bytes = baseline_index.evaluation_projection_artifact_bytes()
        receipt_bytes = baseline_index.qualification_source_receipt_bytes()
        bundle_bytes = canonical_json(
            artifact["source_receipt"]["database_bundle"]
        ).encode("utf-8")
        return artifact_bytes, receipt_bytes, bundle_bytes

    registered = validate_retrieval_comparison_preregistration(preregistration)
    _load_exact_ledger_entry(preregistration_ledger, preregistration)
    suite_bytes = _suite_canonical_bytes(suite)
    actual_suite = {
        "schema_version": suite.schema_version,
        "content_hash": suite.suite_hash,
        "canonical_bytes": len(suite_bytes),
        "canonical_sha256": hashlib.sha256(suite_bytes).hexdigest(),
    }
    if registered.suite != actual_suite:
        raise ValueError("retrieval suite differs from preregistered bytes")
    for role, index, expected in (
        ("candidate", candidate_index, registered.candidate_projection),
        ("baseline", baseline_index, registered.baseline_projection),
    ):
        actual = _index_projection_identity(index)
        if actual != expected:
            raise ValueError(f"{role} projection artifact differs from preregistration")
    try:
        authority_identity_before = archive_authority_identity()
    except (AttributeError, KeyError, OSError, TypeError, ValueError):
        authority_identity_before = None
    candidate_rows = _validate_per_qrel_receipts(
        candidate, suite=suite, index=candidate_index
    )
    baseline_rows = _validate_per_qrel_receipts(
        baseline, suite=suite, index=baseline_index
    )
    if not candidate_rows or len(candidate_rows) != len(baseline_rows):
        raise ValueError("candidate and baseline receipts are not comparable")
    for role, rows, projection in (
        ("candidate", candidate_rows, registered.candidate_projection),
        ("baseline", baseline_rows, registered.baseline_projection),
    ):
        if any(
            row["suite"] != registered.suite
            or row["split"] != registered.split
            or row["limit"] != registered.limit
            or row["projection"] != projection
            or row["producer"] != registered.evaluator_version
            or not isinstance(row["comparison"], dict)
            or row["comparison"] != {
                "run_id": registered.run_id,
                "role": role,
                "registered_at": registered.registered_at,
                "evaluation_started_at": row["comparison"].get(
                    "evaluation_started_at"
                ),
                "preregistration_sha256": hashlib.sha256(
                    preregistration
                ).hexdigest(),
            }
            or _parse_utc(row["comparison"]["evaluation_started_at"])
            <= _parse_utc(registered.registered_at)
            for row in rows
        ):
            raise ValueError(f"{role} receipts disagree with preregistration")
    if [row["qrel"] for row in candidate_rows] != [
        row["qrel"] for row in baseline_rows
    ]:
        raise ValueError("candidate and baseline qrel receipt identities differ")
    candidate_metrics = _aggregate_receipt_metrics(candidate_rows)
    baseline_metrics = _aggregate_receipt_metrics(baseline_rows)
    improved: list[str] = []
    regressed: list[str] = []
    for name in registered.difficult_slices:
        candidate_slice = candidate_metrics["slices"].get(name)
        baseline_slice = baseline_metrics["slices"].get(name)
        if candidate_slice is None or baseline_slice is None:
            raise ValueError(f"preregistered difficult slice is missing:{name}")
        gain = candidate_slice - baseline_slice
        if gain >= registered.minimum_slice_ndcg_gain:
            improved.append(name)
        elif gain < 0:
            regressed.append(name)
    candidate_errors = int(candidate_metrics["hard_errors"])
    baseline_errors = int(baseline_metrics["hard_errors"])
    delta = candidate_errors - baseline_errors
    overall_gains = {
        name: float(candidate_metrics[name] - baseline_metrics[name])
        for name in _OVERALL_COMPARISON_METRICS
    }
    overall_pass = all(
        overall_gains[name] >= registered.minimum_overall_gains[name]
        for name in _OVERALL_COMPARISON_METRICS
    )
    # The first check alone is not a qualification window: Archive can change
    # while candidate/baseline searches or verdict metrics are being replayed.
    # Revalidate at the last possible point before constructing the verdict,
    # and require byte-identical source bundle, producer extension and source
    # receipt identities at both ends.
    try:
        authority_identity_after = archive_authority_identity()
    except (AttributeError, KeyError, OSError, TypeError, ValueError):
        authority_identity_after = None
    projection_authority_pass = (
        authority_identity_before is not None
        and authority_identity_after is not None
        and authority_identity_before == authority_identity_after
    )
    return ComparisonReport(
        improved_slices=tuple(improved),
        regressed_slices=tuple(regressed),
        hard_error_delta=delta,
        overall_gains=overall_gains,
        preregistration_sha256=hashlib.sha256(preregistration).hexdigest(),
        projection_authority_pass=projection_authority_pass,
        gate_pass=(
            projection_authority_pass
            and bool(candidate_metrics["gate_pass"])
            and len(improved) >= 2
            and not regressed
            and candidate_errors == 0
            and overall_pass
        ),
    )


def _reject_duplicate_keys(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key:{key}")
        value[key] = item
    return value


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _valid_grounded_locator_value(value: object) -> bool:
    fields = {
        "document_version_id", "span_id", "source_sha256",
        "byte_start", "byte_end", "quote_sha256",
    }
    return bool(
        isinstance(value, dict)
        and set(value) == fields
        and isinstance(value["document_version_id"], str)
        and value["document_version_id"]
        and isinstance(value["span_id"], str)
        and value["span_id"]
        and _is_sha256(value["source_sha256"])
        and type(value["byte_start"]) is int
        and type(value["byte_end"]) is int
        and 0 <= value["byte_start"] < value["byte_end"]
        and _is_sha256(value["quote_sha256"])
    )


def _validate_per_qrel_receipts(
    payloads: Sequence[bytes], *, suite: QrelSuite, index: KnowledgeIndex
) -> list[dict[str, Any]]:
    base = index.base
    if isinstance(payloads, (bytes, str)) or not isinstance(payloads, Sequence):
        raise ValueError("comparison requires a sequence of per-qrel receipt bytes")
    rows: list[dict[str, Any]] = []
    expected = {
        "schema_version", "producer", "authority", "comparison", "suite",
        "suite_validation_receipt_base64",
        "suite_validation_receipt_sha256", "split", "limit", "projection",
        "qrel", "response_projection_sha256", "response_card_count",
        "response_cards",
        "metrics", "errors",
    }
    for payload in payloads:
        if not isinstance(payload, bytes) or not payload:
            raise ValueError("per-qrel receipt bytes are invalid")
        try:
            row = json.loads(
                payload.decode("utf-8", errors="strict"),
                object_pairs_hook=_reject_duplicate_keys,
            )
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("per-qrel receipt is invalid JSON") from error
        if (
            not isinstance(row, dict)
            or set(row) != expected
            or row.get("schema_version") != PER_QREL_RECEIPT_SCHEMA
            or row.get("producer") != RETRIEVAL_EVALUATOR_VERSION
            or row.get("authority") != "AUTHORITATIVE_EVALUATOR"
            or canonical_json(row).encode("utf-8") != payload
            or not isinstance(row.get("suite"), dict)
            or not isinstance(row.get("projection"), dict)
            or not isinstance(row.get("qrel"), dict)
            or not isinstance(row.get("metrics"), dict)
            or not isinstance(row.get("errors"), dict)
        ):
            raise ValueError("per-qrel receipt is not a closed evaluator receipt")
        suite_fields = {
            "schema_version", "content_hash", "canonical_bytes", "canonical_sha256"
        }
        projection_fields = {
            "projection_producer", "qualification_authority",
            "producer_extension_sha256", "qualification_source_receipt_bytes",
            "qualification_source_receipt_sha256",
            "artifact_bytes", "artifact_sha256",
            "base_snapshot_id", "snapshot_id", "index_version"
        }
        qrel_fields = {
            "qrel_id", "query_bytes_base64", "query_bytes", "query_sha256",
            "answerable", "slices",
            "positive_locators", "negative_locators", "expected_knowledge_kinds",
            "forbidden_document_ids", "required_citation_ids", "include_history"
        }
        metric_fields = {
            "recall_at_k", "ndcg_at_k", "reciprocal_rank",
            "no_answer_correct", "citation_correct"
        }
        error_fields = {
            "deprecated", "conflict", "forbidden", "knowledge_kind",
            "citation", "stale"
        }
        comparison_fields = {
            "run_id", "role", "registered_at", "evaluation_started_at",
            "preregistration_sha256",
        }
        if (
            set(row["suite"]) != suite_fields
            or set(row["projection"]) != projection_fields
            or set(row["qrel"]) != qrel_fields
            or set(row["metrics"]) != metric_fields
            or set(row["errors"]) != error_fields
            or not isinstance(row["comparison"], dict)
            or set(row["comparison"]) != comparison_fields
            or not isinstance(row["comparison"]["run_id"], str)
            or not row["comparison"]["run_id"]
            or row["comparison"]["role"] not in {"candidate", "baseline"}
            or not _is_sha256(row["comparison"]["preregistration_sha256"])
            or not isinstance(row["comparison"]["registered_at"], str)
            or not isinstance(row["comparison"]["evaluation_started_at"], str)
            or row["split"] not in {"development", "holdout"}
            or type(row["limit"]) is not int
            or row["limit"] < 1
            or type(row["response_card_count"]) is not int
            or row["response_card_count"] < 0
            or not isinstance(row["response_cards"], list)
            or row["response_card_count"] != len(row["response_cards"])
            or hashlib.sha256(
                canonical_json(row["response_cards"]).encode("utf-8")
            ).hexdigest() != row["response_projection_sha256"]
            or type(row["qrel"]["answerable"]) is not bool
            or not isinstance(row["qrel"]["slices"], list)
            or any(
                not isinstance(value, str) or not value
                for value in row["qrel"]["slices"]
            )
            or len(set(row["qrel"]["slices"])) != len(row["qrel"]["slices"])
            or any(type(value) is not bool for value in row["errors"].values())
            or not _is_sha256(row["suite_validation_receipt_sha256"])
            or not _is_sha256(row["response_projection_sha256"])
            or not _is_sha256(row["qrel"].get("query_sha256"))
            or type(row["qrel"].get("query_bytes")) is not int
            or row["qrel"].get("query_bytes", 0) < 1
            or not isinstance(row["qrel"].get("query_bytes_base64"), str)
            or type(row["qrel"].get("include_history")) is not bool
            or any(
                not isinstance(row["qrel"].get(name), list)
                for name in (
                    "positive_locators", "negative_locators",
                    "expected_knowledge_kinds", "forbidden_document_ids",
                    "required_citation_ids",
                )
            )
            or any(
                not _valid_grounded_locator_value(locator)
                for name in ("positive_locators", "negative_locators")
                for locator in row["qrel"][name]
            )
            or any(
                any(not isinstance(value, str) or not value for value in row["qrel"][name])
                or len(set(row["qrel"][name])) != len(row["qrel"][name])
                for name in (
                    "expected_knowledge_kinds", "forbidden_document_ids",
                    "required_citation_ids",
                )
            )
            or any(
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or not 0 <= value <= 1
                for name, value in row["metrics"].items()
                if name in {"recall_at_k", "ndcg_at_k", "reciprocal_rank"}
            )
            or row["metrics"]["no_answer_correct"] not in (None, True, False)
            or type(row["metrics"]["citation_correct"]) is not bool
        ):
            raise ValueError("per-qrel receipt bound fields are invalid")
        if _parse_utc(row["comparison"]["evaluation_started_at"]) <= _parse_utc(
            row["comparison"]["registered_at"]
        ):
            raise ValueError("per-qrel evaluation did not follow preregistration")
        try:
            query_bytes = base64.b64decode(
                row["qrel"]["query_bytes_base64"], validate=True
            )
            query_bytes.decode("utf-8", errors="strict")
        except (ValueError, UnicodeError) as error:
            raise ValueError("per-qrel query bytes are invalid") from error
        if (
            len(query_bytes) != row["qrel"]["query_bytes"]
            or hashlib.sha256(query_bytes).hexdigest()
            != row["qrel"]["query_sha256"]
        ):
            raise ValueError("per-qrel query bytes/hash differ")
        card_fields = {
            "rank", "evidence_id", "document_id", "document_version_id",
            "active_status", "knowledge_kind", "citation_ids",
            "has_applicability_conflicts", "displayed_bytes",
            "displayed_bytes_base64", "displayed_sha256",
            "locator",
        }
        evidence_locator_fields = {
            "span_id", "source_sha256", "line_start", "line_end",
            "byte_start", "byte_end",
        }
        if any(
            not isinstance(card, dict)
            or set(card) != card_fields
            or card["rank"] != rank
            or not isinstance(card["evidence_id"], str)
            or not card["evidence_id"]
            or not isinstance(card["document_id"], str)
            or not card["document_id"]
            or not isinstance(card["document_version_id"], str)
            or not card["document_version_id"]
            or not isinstance(card["active_status"], str)
            or not card["active_status"]
            or card["knowledge_kind"] is not None
            and not isinstance(card["knowledge_kind"], str)
            or not isinstance(card["locator"], dict)
            or set(card["locator"]) != evidence_locator_fields
            or not isinstance(card["locator"]["span_id"], str)
            or not card["locator"]["span_id"]
            or not _is_sha256(card["locator"]["source_sha256"])
            or any(
                type(card["locator"][name]) is not int
                for name in ("line_start", "line_end", "byte_start", "byte_end")
            )
            or not 0 <= card["locator"]["byte_start"] < card["locator"]["byte_end"]
            or not 1 <= card["locator"]["line_start"] <= card["locator"]["line_end"]
            or not _is_sha256(card["displayed_sha256"])
            or not isinstance(card["displayed_bytes_base64"], str)
            or type(card["displayed_bytes"]) is not int
            or card["displayed_bytes"] < 0
            or type(card["has_applicability_conflicts"]) is not bool
            or not isinstance(card["citation_ids"], list)
            or any(
                not isinstance(value, str) or not value
                for value in card["citation_ids"]
            )
            or len(set(card["citation_ids"])) != len(card["citation_ids"])
            for rank, card in enumerate(row["response_cards"], 1)
        ):
            raise ValueError("per-qrel response-card projection is invalid")
        for card in row["response_cards"]:
            try:
                displayed = base64.b64decode(
                    card["displayed_bytes_base64"], validate=True
                )
                displayed.decode("utf-8", errors="strict")
            except (ValueError, UnicodeError) as error:
                raise ValueError(
                    "per-qrel displayed evidence bytes are invalid"
                ) from error
            if (
                len(displayed) != card["displayed_bytes"]
                or hashlib.sha256(displayed).hexdigest()
                != card["displayed_sha256"]
            ):
                raise ValueError("per-qrel displayed evidence hash is invalid")
        split_qrels = (
            suite.development()
            if row["split"] == "development"
            else suite.sealed_holdout()
        )
        qrels_by_id = {qrel.qrel_id: qrel for qrel in split_qrels}
        actual_qrel = qrels_by_id.get(row["qrel"].get("qrel_id"))
        expected_stale = bool(
            actual_qrel is not None
            and actual_qrel.qrel_id in set(suite.stale_qrels(base))
        )
        if row["errors"]["stale"] is not expected_stale:
            raise ValueError(
                "per-qrel stale flag differs from live suite/base recomputation"
            )
        try:
            validation_receipt = base64.b64decode(
                row["suite_validation_receipt_base64"], validate=True
            )
            validation = json.loads(
                validation_receipt.decode("utf-8", errors="strict"),
                object_pairs_hook=_reject_duplicate_keys,
            )
        except (ValueError, UnicodeError, json.JSONDecodeError, TypeError) as error:
            raise ValueError("per-qrel suite validation receipt is invalid") from error
        if (
            hashlib.sha256(validation_receipt).hexdigest()
            != row["suite_validation_receipt_sha256"]
            or not isinstance(validation, dict)
            or validation.get("schema_version") != SUITE_VALIDATION_RECEIPT_SCHEMA
            or set(validation) != {
                "schema_version", "producer", "status", "suite",
                "base_snapshot_id", "failures"
            }
            or validation.get("producer") != RETRIEVAL_EVALUATOR_VERSION
            or validation.get("status") != "PASS"
            or validation.get("failures") != []
            or validation.get("base_snapshot_id")
            != row["projection"].get("base_snapshot_id")
            or validation.get("suite") != {
                "canonical_bytes": row["suite"]["canonical_bytes"],
                "canonical_sha256": row["suite"]["canonical_sha256"],
                "content_hash": row["suite"]["content_hash"],
            }
            or canonical_json(validation).encode("utf-8") != validation_receipt
        ):
            raise ValueError("per-qrel suite validation receipt does not bind suite")
        expected_validation, validation_failures = build_suite_validation_receipt(
            suite, base
        )
        expected_qrels = {
            qrel_id: _qrel_projection(qrel)
            for qrel_id, qrel in qrels_by_id.items()
        }
        if (
            validation_failures
            or validation_receipt != expected_validation
            or row["suite"] != {
                "schema_version": suite.schema_version,
                "content_hash": suite.suite_hash,
                "canonical_bytes": len(_suite_canonical_bytes(suite)),
                "canonical_sha256": hashlib.sha256(
                    _suite_canonical_bytes(suite)
                ).hexdigest(),
            }
            or expected_qrels.get(row["qrel"].get("qrel_id")) != row["qrel"]
        ):
            raise ValueError("per-qrel receipt is not a member of the supplied suite")
        assert actual_qrel is not None
        replayed_response = index.search(
            actual_qrel.query,
            context=actual_qrel.context,
            limit=row["limit"],
            include_history=actual_qrel.include_history,
        )
        if (
            replayed_response.index_version != row["projection"]["index_version"]
            or _response_card_projection(replayed_response)
            != row["response_cards"]
        ):
            raise ValueError(
                "per-qrel displayed response differs from live projection replay"
            )
        try:
            recomputed = _recompute_receipt_outcomes(row, base=base)
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("per-qrel response-card projection is invalid") from error
        if recomputed != {
                "metrics": row["metrics"],
                "errors_without_stale": {
                    key: row["errors"][key]
                    for key in (
                        "deprecated", "conflict", "forbidden",
                        "knowledge_kind", "citation"
                    )
                },
            }:
            raise ValueError("per-qrel receipt metrics do not match bound cards")
        rows.append(row)
    ids = [row["qrel"].get("qrel_id") for row in rows]
    if (
        any(not isinstance(value, str) or not value for value in ids)
        or len(set(ids)) != len(ids)
        or ids != sorted(ids)
    ):
        raise ValueError("per-qrel receipt IDs are invalid")
    if len({row["suite_validation_receipt_sha256"] for row in rows}) != 1:
        raise ValueError("per-qrel receipts use mixed suite validation receipts")
    expected_ids = sorted(
        qrel.qrel_id
        for qrel in (
            suite.development()
            if rows[0]["split"] == "development"
            else suite.sealed_holdout()
        )
    )
    if ids != expected_ids:
        raise ValueError("per-qrel receipts do not cover the complete suite split")
    return rows


def _recompute_receipt_outcomes(
    row: Mapping[str, Any], *, base: BaseSnapshot
) -> dict[str, Any]:
    qrel = row["qrel"]
    cards = row["response_cards"]
    positives = {
        canonical_json(locator): locator for locator in qrel["positive_locators"]
    }
    negatives = {
        canonical_json(locator): locator for locator in qrel["negative_locators"]
    }

    def credited(card: Mapping[str, Any], locator: Mapping[str, Any]) -> bool:
        grounded = GroundedLocator(**locator)
        span = _span_for_locator(base, grounded)
        start = grounded.byte_start - span.byte_start
        end = grounded.byte_end - span.byte_start
        quote = span.text.encode("utf-8")[start:end]
        displayed = base64.b64decode(
            card["displayed_bytes_base64"], validate=True
        )
        return (
            card["document_version_id"] == locator["document_version_id"]
            and card["locator"]["span_id"] == locator["span_id"]
            and card["locator"]["source_sha256"] == locator["source_sha256"]
            and card["locator"]["byte_start"] == locator["byte_start"]
            and card["locator"]["byte_end"] == locator["byte_end"]
            and card["displayed_bytes"] == locator["byte_end"] - locator["byte_start"]
            and card["displayed_sha256"] == locator["quote_sha256"]
            and displayed == quote
            and hashlib.sha256(quote).hexdigest() == locator["quote_sha256"]
        )

    positive_by_card = [
        {key for key, locator in positives.items() if credited(card, locator)}
        for card in cards
    ]
    negative_by_card = [
        {key for key, locator in negatives.items() if credited(card, locator)}
        for card in cards
    ]
    retrieved = set().union(*positive_by_card) if positive_by_card else set()
    ranks: list[int] = []
    seen: set[str] = set()
    for rank, keys in enumerate(positive_by_card, 1):
        new = keys - seen
        ranks.extend([rank] * len(new))
        seen.update(new)
    answerable = qrel["answerable"]
    recall = (
        1.0 if not answerable and not cards
        else len(retrieved) / len(positives) if positives else 0.0
    )
    dcg = sum(1 / math.log2(rank + 1) for rank in ranks)
    ideal = sum(
        1 / math.log2(rank + 1)
        for rank in range(1, min(len(positives), row["limit"]) + 1)
    )
    ndcg = dcg / ideal if ideal else (1.0 if not answerable and not cards else 0.0)
    relevant_indexes = {index for index, keys in enumerate(positive_by_card) if keys}
    citations = {
        value
        for index, card in enumerate(cards)
        if index in relevant_indexes
        for value in card["citation_ids"]
    }
    citation_correct = (
        not qrel["required_citation_ids"]
        or set(qrel["required_citation_ids"]) <= citations
    )
    errors = {
        "deprecated": any(card["active_status"] != "active" for card in cards)
        and not qrel["include_history"],
        "conflict": any(card["has_applicability_conflicts"] for card in cards),
        "forbidden": any(
            card["document_id"] in qrel["forbidden_document_ids"]
            or bool(negative_by_card[index])
            for index, card in enumerate(cards)
        ),
        "knowledge_kind": bool(qrel["expected_knowledge_kinds"])
        and not any(
            index in relevant_indexes
            and card["knowledge_kind"] in qrel["expected_knowledge_kinds"]
            for index, card in enumerate(cards)
        ),
        "citation": not citation_correct,
    }
    return {
        "metrics": {
            "recall_at_k": recall,
            "ndcg_at_k": ndcg,
            "reciprocal_rank": 1 / ranks[0] if ranks else 0.0,
            "no_answer_correct": None if answerable else not cards,
            "citation_correct": citation_correct,
        },
        "errors_without_stale": errors,
    }


def _aggregate_receipt_metrics(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    answerable = [row for row in rows if row["qrel"]["answerable"]]
    no_answer = [row for row in rows if not row["qrel"]["answerable"]]

    def average(selected: Sequence[Mapping[str, Any]], name: str, default: float) -> float:
        return (
            statistics.fmean(float(row["metrics"][name]) for row in selected)
            if selected
            else default
        )

    slice_ndcg: dict[str, float] = {}
    for name in sorted({item for row in rows for item in row["qrel"]["slices"]}):
        selected = [
            row for row in answerable if name in row["qrel"]["slices"]
        ]
        slice_ndcg[name] = average(selected, "ndcg_at_k", 1.0)
    hard_errors = sum(
        int(bool(value))
        for row in rows
        for value in row["errors"].values()
    )
    recall = average(answerable, "recall_at_k", 0.0)
    ndcg = average(answerable, "ndcg_at_k", 0.0)
    no_answer_accuracy = average(no_answer, "no_answer_correct", 1.0)
    citation_accuracy = average(rows, "citation_correct", 0.0)
    return {
        "recall_at_k": recall,
        "ndcg_at_k": ndcg,
        "reciprocal_rank": average(answerable, "reciprocal_rank", 0.0),
        "no_answer_accuracy": no_answer_accuracy,
        "citation_accuracy": citation_accuracy,
        "hard_errors": hard_errors,
        "slices": slice_ndcg,
        "gate_pass": (
            hard_errors == 0
            and recall >= _MIN_RECALL_AT_K
            and ndcg >= _MIN_NDCG_AT_K
            and no_answer_accuracy >= _MIN_NO_ANSWER_ACCURACY
            and citation_accuracy >= _MIN_CITATION_ACCURACY
        ),
    }


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
    "RETRIEVAL_COMPARISON_PREREGISTRATION_SCHEMA",
    "Qrel",
    "QrelSuite",
    "RetrievalComparisonPreregistration",
    "SliceMetrics",
    "bind_qrel_templates",
    "build_retrieval_comparison_preregistration",
    "compare_candidate_to_baseline",
    "evaluate",
    "validate_retrieval_comparison_preregistration",
]
