"""Explainable lexical/structured retrieval over immutable knowledge snapshots."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, replace
import hashlib
import math
import re
import sqlite3
import time
from typing import Any, Literal, Mapping, Sequence

from .contracts import BaseSnapshot, Chunk, canonical_json
from .semantic import EnrichedSnapshot, KnowledgeItem


INDEX_VERSION = "qrh-structured-lexical-index/v1.9-quant-bilingual"
RETRIEVAL_ARTIFACT_SCHEMA = "qrh-lexical-retrieval-records/v2"

# Only relations whose direction adds supporting context may introduce a new
# evidence card.  Negative edges remain available as structured knowledge, but
# adding their target to the positive answer lane would invert ``contradicts``
# or ``fails_under`` and can surface a method that the source explicitly rejects.
_POSITIVE_EXPANSION_RELATIONS = frozenset({"supports", "requires", "extends"})

_ALIASES = {
    "ic": ("information coefficient", "信息系数"),
    "rankic": ("rank ic", "秩相关", "spearman"),
    "mse": ("mean squared error", "均方误差"),
    "pca": ("principal component analysis", "主成分分析"),
    "lstm": ("long short-term memory", "长短期记忆"),
    "回测": ("backtest",),
    "因子": ("factor",),
}
_ALIAS_GROUPS: tuple[tuple[str, ...], ...] = (
    ("横截面", "cross-sectional", "cross sectional"),
    ("信噪比", "snr", "signal-to-noise ratio", "signal noise ratio"),
    ("前视偏差", "未来数据", "look-ahead bias", "lookahead bias", "future leakage"),
    ("幸存者偏差", "survivorship bias"),
    ("回测过拟合", "backtest overfitting"),
    ("交易成本", "transaction cost", "trading cost"),
    ("滑点", "slippage"),
    ("换手率", "turnover"),
    ("中性化", "neutralization", "neutralisation"),
    ("缩尾", "去极值", "winsorization", "winsorisation"),
    ("标准化", "standardization", "standardisation"),
    ("滚动窗口", "rolling window"),
    ("滚动验证", "walk-forward validation", "walk forward validation"),
    ("样本外", "out-of-sample", "out of sample", "oos"),
    ("交叉验证", "cross-validation", "cross validation"),
    ("多重检验", "multiple testing", "multiple hypothesis testing"),
    ("因子衰减", "factor decay", "signal decay"),
    ("标签泄漏", "label leakage", "target leakage"),
    ("时间切分", "temporal split", "time split"),
    ("缺失值", "missing value", "missing data"),
    ("插补", "imputation", "impute"),
    ("平稳性", "stationarity", "stationary"),
    ("协整", "cointegration", "cointegrated"),
    ("订单簿", "order book", "limit order book", "lob"),
    ("市场微观结构", "market microstructure", "microstructure"),
    ("波动率", "volatility"),
    ("已实现波动率", "realized volatility", "realised volatility"),
    ("回撤", "drawdown"),
    ("夏普比率", "sharpe ratio", "sharpe"),
    ("可微排序", "differentiable sorting", "differentiable ranking"),
    ("灵敏度分析", "sensitivity analysis"),
    ("概率校准", "probability calibration", "calibration"),
    ("选股", "stock selection", "equity selection"),
    ("排序决策", "ranking decision", "rank-based decision", "ordering decision"),
    ("涨跌停", "price limit", "limit-up", "limit-down"),
    ("极值", "outlier", "extreme value", "extreme observation"),
    ("财报", "earnings report", "financial statement", "accounting report"),
    ("真实 alpha", "真 alpha", "genuine alpha", "true alpha"),
    ("残差 alpha", "residual alpha", "incremental alpha"),
    ("风格暴露", "style exposure", "factor exposure"),
    ("局部基函数", "local basis function", "piecewise linear encoding", "ple"),
    ("自由度", "degrees of freedom", "model freedom"),
    ("目标对齐", "target alignment", "target-aligned", "target-aware"),
    ("主导方差", "dominant variance", "largest variance"),
    ("连续因子", "continuous factor", "continuous feature"),
    ("二元状态变量", "binary indicator", "dummy variable", "indicator variable"),
    ("披露时间", "disclosure time", "publication time", "point-in-time"),
    ("报告期结束日", "reporting period end", "period-end date"),
    ("稳健缩尾", "robust winsorization", "robust clipping"),
    ("完整白化", "full whitening", "empirical whitening"),
    ("消融实验", "ablation", "ablation test"),
    ("历史长度", "history length", "available history"),
    ("掩码", "mask", "missingness mask"),
    ("净化", "purge", "purging"),
    ("禁运期", "embargo", "embargo period"),
    ("样本重叠", "sample overlap", "overlap leakage"),
    ("交易日", "trading day", "trading-day unit"),
    ("挑选过程", "selection process", "strategy selection"),
    ("样本内赢家", "in-sample winner", "is winner"),
    ("独立策略", "standalone strategy", "single strategy"),
    ("概念漂移", "concept drift"),
    ("分布漂移", "distribution shift", "distribution drift"),
    ("残差连接", "residual connection", "skip connection"),
    ("退出路径", "exit path", "early exit path"),
    ("随机嵌入", "random embedding"),
    ("诊断基线", "diagnostic baseline"),
    ("可交易 alpha", "tradable alpha"),
    ("实际换手率", "measured turnover", "realized turnover"),
    ("单位", "unit", "time unit"),
    ("停牌", "suspension", "suspended"),
    ("处理管线", "processing pipeline", "separate pipeline"),
)
_ASCII_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.+-]*|[0-9]+(?:\.[0-9]+)?")
_CJK_RE = re.compile(r"[\u3400-\u9fff]+")
_ASCII_QUESTION_WORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "for",
        "how",
        "in",
        "is",
        "of",
        "on",
        "or",
        "the",
        "to",
        "what",
        "when",
        "where",
        "which",
        "why",
        "with",
        "should",
        "does",
        "can",
        "could",
        "would",
        "must",
        "may",
        "might",
    }
)
_CJK_QUESTION_PHRASES = tuple(
    sorted(
        {
            "为什么",
            "是什么",
            "有什么",
            "如何",
            "怎样",
            "怎么",
            "是否",
            "应该",
            "能否",
            "可以",
            "请问",
            "什么时候",
            "采取什么",
            "说明什么",
        },
        key=len,
        reverse=True,
    )
)
_CONTRAST_PATTERNS = (
    re.compile(
        r"不是(?P<negative>[^，,。；;!?]+?)(?:而是|而应|而要|[，,。；;!?]|$)",
        re.IGNORECASE,
    ),
    re.compile(r"而非(?P<negative>[^，。；;!?]+)", re.IGNORECASE),
    re.compile(r"\bnot\s+(?P<negative>.+?)\s+but\b", re.IGNORECASE),
)


@dataclass(frozen=True, slots=True)
class TaskContext:
    market: tuple[str, ...] = ()
    frequency: tuple[str, ...] = ()
    data: tuple[str, ...] = ()
    objective: tuple[str, ...] = ()
    assumption: tuple[str, ...] = ()

    @classmethod
    def create(cls, **values: str | Sequence[str] | None) -> "TaskContext":
        normalized: dict[str, tuple[str, ...]] = {}
        for key in ("market", "frequency", "data", "objective", "assumption"):
            value = values.get(key)
            if value is None:
                normalized[key] = ()
            elif isinstance(value, str):
                normalized[key] = (value,)
            else:
                normalized[key] = tuple(value)
        return cls(**normalized)


@dataclass(frozen=True, slots=True)
class EvidenceLocator:
    span_id: str
    source_sha256: str
    line_start: int
    line_end: int
    byte_start: int
    byte_end: int


@dataclass(frozen=True, slots=True)
class EvidenceCard:
    evidence_id: str
    canonical_key: str
    document_id: str
    document_version_id: str
    research_id: str
    title: str
    text: str
    score: float
    rank: int
    source_kind: Literal["chunk", "knowledge"]
    fact_status: str
    knowledge_enrichment: str
    active_status: str
    knowledge_kind: str | None
    cluster_id: str | None
    locator: EvidenceLocator
    covered_span_ids: tuple[str, ...]
    heading_path: tuple[str, ...]
    citation_ids: tuple[str, ...]
    hit_reasons: tuple[str, ...]
    applicability: dict[str, tuple[str, ...]]
    applicability_matches: tuple[str, ...]
    applicability_conflicts: tuple[str, ...]
    limitations: tuple[str, ...]
    failures: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SearchResponse:
    query: str
    snapshot_id: str
    index_version: str
    cards: tuple[EvidenceCard, ...]
    answerable: bool
    no_answer_reason: str | None
    total_candidates: int


@dataclass(frozen=True, slots=True)
class _Record:
    record_id: str
    source_kind: Literal["chunk", "knowledge"]
    document_id: str
    document_version_id: str
    research_id: str
    title: str
    aliases: tuple[str, ...]
    text: str
    heading_path: tuple[str, ...]
    heading_labels: tuple[str, ...]
    canonical_span_id: str
    evidence_span_ids: tuple[str, ...]
    locator: EvidenceLocator
    citation_ids: tuple[str, ...]
    active_status: str
    knowledge_enrichment: str
    fact_status: str
    knowledge_kind: str | None
    cluster_id: str | None
    applicability: dict[str, tuple[str, ...]]
    relation: dict[str, str] | None
    terms: Counter[str]


def _ascii_morphology(token: str) -> tuple[str, ...]:
    """Return a tiny deterministic English morphology closure.

    This is intentionally not a language model or an unrestricted stemmer.
    It closes common research-question inflections while retaining the exact
    surface, so ``selecting``, ``selected`` and ``selection`` can still route
    through explicit bilingual aliases without rewriting source text.
    """

    values = [token]
    if len(token) > 5 and token.endswith("ies"):
        values.append(token[:-3] + "y")
    elif len(token) > 4 and token.endswith("es"):
        values.append(token[:-2])
    elif len(token) > 4 and token.endswith("s") and not token.endswith("ss"):
        values.append(token[:-1])
    if len(token) > 6 and token.endswith("ing"):
        stem = token[:-3]
        values.append(stem)
        if len(stem) > 2 and stem[-1] == stem[-2]:
            values.append(stem[:-1])
    if len(token) > 5 and token.endswith("ied"):
        values.append(token[:-3] + "y")
    elif len(token) > 5 and token.endswith("ed"):
        stem = token[:-2]
        values.append(stem)
        if len(stem) > 2 and stem[-1] == stem[-2]:
            values.append(stem[:-1])
    return tuple(dict.fromkeys(values))


def _surface_terms(text: str) -> tuple[str, ...]:
    folded = text.casefold()
    values: list[str] = [
        value
        for match in _ASCII_RE.finditer(folded)
        for value in _ascii_morphology(match.group(0))
    ]
    for match in _CJK_RE.finditer(folded):
        value = match.group(0)
        values.append(value)
        values.extend(value[index : index + 2] for index in range(max(0, len(value) - 1)))
        values.extend(value[index : index + 3] for index in range(max(0, len(value) - 2)))
    return tuple(values)


def _alias_surface_present(surface: str, text: str) -> bool:
    folded_surface = surface.casefold()
    folded_text = text.casefold()
    compact_surface = re.sub(
        r"[^a-z0-9\u3400-\u9fff]", "", folded_surface
    )
    compact_text = re.sub(r"[^a-z0-9\u3400-\u9fff]", "", folded_text)
    if not compact_surface:
        return False
    if compact_surface.isascii() and len(compact_surface) <= 4:
        # Acronyms such as PLE/PLS/PBO must be token matches; substring
        # matching would incorrectly find PLE inside "complete".
        return re.search(
            rf"(?<![a-z0-9_.+-]){re.escape(compact_surface)}(?![a-z0-9_.+-])",
            folded_text,
        ) is not None
    return folded_surface in folded_text or compact_surface in compact_text


def _terms(text: str) -> tuple[str, ...]:
    folded = text.casefold()
    values = list(_surface_terms(text))
    expanded = list(values)
    compact = re.sub(r"[^a-z0-9\u3400-\u9fff]", "", folded)
    for key, aliases in _ALIASES.items():
        if key in values or key == compact:
            for alias in aliases:
                expanded.extend(_terms(alias) if alias != text else ())
    for group in _ALIAS_GROUPS:
        if any(_alias_surface_present(surface, text) for surface in group):
            for surface in group:
                expanded.extend(_surface_terms(surface))
    return tuple(expanded)


_FACET_ALIASES: dict[str, dict[str, str]] = {
    "market": {
        "a股": "a股",
        "ashare": "a股",
        "ashares": "a股",
        "chinaashare": "a股",
        "中国a股": "a股",
        "美股": "美股",
        "usequity": "美股",
        "usstock": "美股",
        "加密货币": "加密货币",
        "crypto": "加密货币",
        "cryptocurrency": "加密货币",
    },
    "frequency": {
        "日频": "日频",
        "daily": "日频",
        "1d": "日频",
        "day": "日频",
        "分钟": "分钟",
        "分钟频": "分钟",
        "minute": "分钟",
        "1m": "分钟",
        "高频": "高频",
        "highfrequency": "高频",
        "intraday": "高频",
    },
    "data": {
        "因子暴露": "因子暴露",
        "factorexposure": "因子暴露",
        "订单簿": "订单簿",
        "orderbook": "订单簿",
        "特征分布": "特征分布",
        "featuredistribution": "特征分布",
        "卫星图像": "卫星图像",
        "satelliteimage": "卫星图像",
    },
    "objective": {
        "选股": "选股",
        "stockselection": "选股",
        "短期预测": "短期预测",
        "shorttermprediction": "短期预测",
        "数据清洗": "数据清洗",
        "datacleaning": "数据清洗",
        "模型选择": "模型选择",
        "modelselection": "模型选择",
        "回测": "回测",
        "backtest": "回测",
    },
    "assumption": {},
}


def _facet_key(value: str) -> str:
    return re.sub(r"[^a-z0-9\u3400-\u9fff]", "", value.casefold())


def _controlled_facet_canonical(value: str) -> str | None:
    """Return the canonical value for a surface in the closed facet vocabulary.

    Named-anchor rejection protects no-answer behavior for unsupported methods
    and instruments. It must not reject a spelling such as ``A-share`` that
    the applicability layer already canonicalizes deterministically. Unknown
    named surfaces remain closed-world, while actual facet conflicts are still
    handled by ``_unsupported_concrete_context`` and ``_applicability``.
    """

    key = _facet_key(value)
    for aliases in _FACET_ALIASES.values():
        if key in aliases:
            return aliases[key]
    return None


def _canonical_facet_values(
    facet: str, values: Sequence[str]
) -> tuple[set[str], set[str]]:
    exact = {
        re.sub(r"\s+", " ", value.casefold()).strip()
        for value in values
        if value.strip()
    }
    aliases = _FACET_ALIASES.get(facet, {})
    canonical = {
        aliases[key]
        for value in values
        if value.strip() and (key := _facet_key(value)) in aliases
    }
    return exact, canonical


def _applicability_projections(
    rows: Sequence[tuple[str, str, Mapping[str, Sequence[str]]]],
) -> tuple[
    dict[str, dict[str, tuple[str, ...]]],
    dict[str, dict[str, tuple[str, ...]]],
]:
    by_item: dict[str, dict[str, tuple[str, ...]]] = {}
    declared: dict[str, dict[str, list[frozenset[str]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    raw_values: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: defaultdict(set)
    )
    for version_id, item_id, applicability in rows:
        normalized = {
            facet: tuple(sorted({str(value) for value in values if str(value).strip()}))
            for facet, values in applicability.items()
            if values
        }
        by_item[item_id] = normalized
        for facet, values in normalized.items():
            _exact, canonical = _canonical_facet_values(facet, values)
            # Unknown free-text scopes remain item-local.  Only a controlled,
            # comparable canonical scope may become a document-wide invariant.
            if not canonical:
                continue
            declared[version_id][facet].append(frozenset(canonical))
            raw_values[version_id][facet].update(values)
    consensus: dict[str, dict[str, tuple[str, ...]]] = {}
    for version_id, facets in declared.items():
        accepted: dict[str, tuple[str, ...]] = {}
        for facet, scopes in facets.items():
            if scopes and all(scope == scopes[0] for scope in scopes[1:]):
                accepted[facet] = tuple(sorted(raw_values[version_id][facet]))
        if accepted:
            consensus[version_id] = accepted
    return by_item, consensus


def _anchor_groups(text: str) -> tuple[str, ...]:
    """Return independent, information-bearing query surfaces.

    CJK bigrams/trigrams remain useful ranking terms, but overlapping n-grams
    from one phrase are not independent evidence.  Here each CJK run contributes
    at most one anchor group after removing question-only phrases.
    """

    folded = text.casefold()
    ascii_groups = [
        match.group(0)
        for match in _ASCII_RE.finditer(folded)
        if match.group(0) not in _ASCII_QUESTION_WORDS
    ]
    cleaned = folded
    for phrase in _CJK_QUESTION_PHRASES:
        cleaned = cleaned.replace(phrase, " ")
    cjk_groups = [value for value in _CJK_RE.findall(cleaned) if len(value) >= 2]
    return tuple(dict.fromkeys((*ascii_groups, *cjk_groups)))


def _longest_cjk_match(value: str, haystack: str) -> str | None:
    upper = min(len(value), 16)
    for size in range(upper, 1, -1):
        for start in range(0, len(value) - size + 1):
            candidate = value[start : start + size]
            if candidate in haystack:
                return candidate
    return None


def _matched_anchor_groups(query: str, record_text: str) -> tuple[str, ...]:
    folded_record = record_text.casefold()
    record_ascii = set(_ASCII_RE.findall(folded_record))
    record_cjk = "".join(_CJK_RE.findall(folded_record))
    matches: list[str] = []
    for group in _anchor_groups(query):
        if group.isascii():
            if group in record_ascii:
                matches.append(group)
            continue
        matched = _longest_cjk_match(group, record_cjk)
        if matched is not None:
            matches.append(matched)
    return tuple(dict.fromkeys(matches))


def _contrast_parts(query: str) -> tuple[str, tuple[str, ...]]:
    """Separate explicit rejected alternatives from the positive request.

    This intentionally handles only unambiguous contrast forms.  Ordinary
    limitation language such as ``不能使用`` remains part of the positive
    request and is never treated as a negative filter.
    """

    positive = query
    negatives: list[str] = []
    for pattern in _CONTRAST_PATTERNS:
        matches = list(pattern.finditer(positive))
        for match in matches:
            value = match.group("negative").strip()
            if value:
                negatives.append(value)
        positive = pattern.sub(" ", positive)
    return positive, tuple(dict.fromkeys(negatives))


def _query_kind_preferences(query: str) -> tuple[str, ...]:
    """Infer explicit research intent as a ranking hint, never a filter."""

    folded = query.casefold()
    patterns = {
        "failure": r"(?:失败|失效|踩坑|反例|不收敛|failure|pitfall|anti-pattern)",
        "limitation": r"(?:限制|局限|风险|缺点|边界|注意事项|limitation|caveat|risk|constraint)",
        "condition": r"(?:适用|条件|前提|假设|何时|场景|condition|applicab|assumption|prerequisite|when)",
        "method": r"(?:方法|算法|流程|步骤|构造|实现|method|algorithm|procedure|workflow|implement)",
        "summary": r"(?:总结|结论|摘要|概述|summary|conclusion|overview)",
        "evidence": r"(?:证据|结果|效果|为什么|依据|evidence|result|finding|why)",
    }
    explicit = [
        kind
        for kind, pattern in patterns.items()
        if re.search(pattern, folded, re.IGNORECASE)
    ]
    if not explicit and re.search(r"(?:如何|怎么|怎样|\bhow\b)", folded, re.IGNORECASE):
        explicit.append("method")
    return tuple(explicit)


def _span_lookup(base: BaseSnapshot, version_id: str) -> dict[str, Any]:
    ir = base.ir_documents[version_id]
    result = {}
    for block in ir.blocks:
        result[block.source_span.span_id] = block.source_span
        result.update({span.span_id: span for span in block.spans})
    return result


def _heading_labels(ir: Any, heading_path: Sequence[str]) -> tuple[str, ...]:
    by_anchor = {
        str(block.attributes.get("anchor_id")): (
            int(block.attributes.get("level", 0)),
            block.text,
        )
        for block in ir.blocks
        if block.kind == "heading" and block.attributes.get("anchor_id")
    }
    return tuple(
        by_anchor[anchor][1]
        for anchor in heading_path
        if anchor in by_anchor and by_anchor[anchor][0] > 1
    )


class KnowledgeIndex:
    def __init__(self, base: BaseSnapshot, enriched: EnrichedSnapshot | None = None):
        if enriched is not None and enriched.base_snapshot_id != base.snapshot_id:
            raise ValueError("enriched knowledge belongs to another deterministic snapshot")
        self.base = base
        self.enriched = enriched
        self.snapshot_id = enriched.snapshot_id if enriched else base.snapshot_id
        applicability_rows = (
            tuple(
                (
                    item.document_version_id,
                    item.knowledge_item_id,
                    item.applicability,
                )
                for item in enriched.knowledge_items.values()
            )
            if enriched is not None
            else ()
        )
        (
            self._applicability_by_item,
            self._document_consensus_applicability,
        ) = _applicability_projections(applicability_rows)
        started = time.perf_counter()
        self.records = self._build_records()
        self._initialize_search_runtime(started)

    def _initialize_search_runtime(self, started: float) -> None:
        self._active_corpus_terms = {
            term
            for record in self.records
            if record.active_status == "active"
            for term in record.terms
        }
        self._knowledge_search_surfaces = {
            record.record_id: "\n".join(
                (
                    record.title,
                    *record.aliases,
                    *record.heading_labels,
                    record.knowledge_kind or "",
                    record.text,
                )
            )
            for record in self.records
            if record.source_kind == "knowledge"
        }
        self._document_frequency = Counter(
            term for record in self.records for term in set(record.terms)
        )
        self._average_term_count = (
            sum(sum(record.terms.values()) for record in self.records)
            / max(1, len(self.records))
        )
        self._fts = sqlite3.connect(":memory:")
        try:
            self._fts.execute(
                "CREATE VIRTUAL TABLE lexical_fts USING fts5(record_id UNINDEXED, terms, tokenize='unicode61 remove_diacritics 2')"
            )
        except sqlite3.OperationalError as exc:  # fail visibly; no silent LIKE downgrade
            self._fts.close()
            raise RuntimeError("SQLite FTS5 is required by the lexical snapshot contract") from exc
        self._fts.executemany(
            "INSERT INTO lexical_fts(record_id,terms) VALUES(?,?)",
            (
                (record.record_id, " ".join(sorted(set(record.terms))))
                for record in self.records
            ),
        )
        self._fts.commit()
        page_count = int(self._fts.execute("PRAGMA page_count").fetchone()[0])
        page_size = int(self._fts.execute("PRAGMA page_size").fetchone()[0])
        self.index_footprint_bytes = page_count * page_size
        self.build_latency_ms = round((time.perf_counter() - started) * 1000, 6)

    def export_artifact_records(self) -> dict[str, object]:
        """Return the deterministic ranking input consumed by local stdio MCP."""

        return {
            "schema_version": RETRIEVAL_ARTIFACT_SCHEMA,
            "index_version": INDEX_VERSION,
            "records": [
                {
                    "record_id": record.record_id,
                    "source_kind": record.source_kind,
                    "document_id": record.document_id,
                    "document_version_id": record.document_version_id,
                    "research_id": record.research_id,
                    "title": record.title,
                    "aliases": list(record.aliases),
                    "text": record.text,
                    "heading_path": list(record.heading_path),
                    "heading_labels": list(record.heading_labels),
                    "canonical_span_id": record.canonical_span_id,
                    "evidence_span_ids": list(record.evidence_span_ids),
                    "locator": asdict(record.locator),
                    "citation_ids": list(record.citation_ids),
                    "active_status": record.active_status,
                    "knowledge_enrichment": record.knowledge_enrichment,
                    "fact_status": record.fact_status,
                    "knowledge_kind": record.knowledge_kind,
                    "cluster_id": record.cluster_id,
                    "applicability": {
                        key: list(values)
                        for key, values in sorted(record.applicability.items())
                    },
                    "relation": record.relation,
                    "terms": dict(sorted(record.terms.items())),
                }
                for record in self.records
            ],
        }

    def close(self) -> None:
        if getattr(self, "_fts", None) is not None:
            self._fts.close()
            self._fts = None  # type: ignore[assignment]

    def __enter__(self) -> "KnowledgeIndex":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def _fts_candidate_ids(self, query_terms: Counter[str]) -> set[str]:
        unique = sorted({term for term in query_terms if term.strip()})
        if not unique:
            return set()
        match = " OR ".join('"' + term.replace('"', '""') + '"' for term in unique)
        try:
            rows = self._fts.execute(
                "SELECT record_id FROM lexical_fts WHERE lexical_fts MATCH ?", (match,)
            ).fetchall()
        except sqlite3.OperationalError:
            # Query terms are generated internally, but fail closed if a future
            # tokenizer/schema change makes a term illegal.
            return set()
        return {str(row[0]) for row in rows}

    def _version_status(self, document_id: str, version_id: str) -> str:
        document = self.base.documents[document_id]
        if document.status != "active":
            return document.status
        return "active" if document.active_version_id == version_id else "superseded"

    def _knowledge_status(self, version_id: str) -> str:
        if self.enriched is not None:
            return self.enriched.knowledge_status_membership.get(version_id, "historical")
        return self.base.knowledge_status_membership.get(version_id, "historical")

    def _record_for_chunk(self, chunk: Chunk) -> _Record:
        version = self.base.versions[chunk.document_version_id]
        document = self.base.documents[chunk.document_id]
        ir = self.base.ir_documents[chunk.document_version_id]
        spans = _span_lookup(self.base, chunk.document_version_id)
        span = spans[chunk.ordered_span_ids[0]]
        citation_ids = tuple(
            sorted(
                {
                    str(child.attributes["citation_id"])
                    for block in ir.blocks
                    if block.source_span.span_id in chunk.ordered_span_ids
                    for child in block.spans
                    if child.kind == "citation" and "citation_id" in child.attributes
                }
            )
        )
        return _Record(
            record_id=chunk.chunk_id,
            source_kind="chunk",
            document_id=chunk.document_id,
            document_version_id=chunk.document_version_id,
            research_id=version.research_id,
            title=ir.title,
            aliases=document.aliases,
            text=chunk.text,
            heading_path=chunk.heading_path,
            heading_labels=_heading_labels(ir, chunk.heading_path),
            canonical_span_id=span.span_id,
            evidence_span_ids=tuple(chunk.ordered_span_ids),
            locator=EvidenceLocator(
                span.span_id,
                span.source_sha256,
                chunk.line_start,
                chunk.line_end,
                chunk.byte_start,
                chunk.byte_end,
            ),
            citation_ids=citation_ids,
            active_status=self._version_status(chunk.document_id, chunk.document_version_id),
            knowledge_enrichment=self._knowledge_status(chunk.document_version_id),
            fact_status="source_explicit",
            knowledge_kind=None,
            cluster_id=None,
            # A document-wide applicability constraint is propagated only when
            # every controlled formal declaration agrees.  Mixed-scope research
            # must not union A-share and crypto conditions into a false match.
            applicability=self._document_consensus_applicability.get(
                chunk.document_version_id, {}
            ),
            relation=None,
            # Do not inject the document title into every chunk.  Repeating a
            # global title made the first chunk of a long research dominate
            # even when the query named a method/limit evidenced much later in
            # the same document.  Heading path + local text preserve document
            # navigation while ranking the exact supporting passage.
            terms=Counter(
                _terms(
                    "\n".join(
                        (*_heading_labels(ir, chunk.heading_path), chunk.text)
                    )
                )
            ),
        )

    def _record_for_knowledge(self, item: KnowledgeItem) -> _Record:
        version = self.base.versions[item.document_version_id]
        document = self.base.documents[item.document_id]
        ir = self.base.ir_documents[item.document_version_id]
        spans = _span_lookup(self.base, item.document_version_id)
        primary = spans[item.evidence[0].span_id]
        primary_binding = item.evidence[0]
        occurrences = [
            match.start()
            for match in re.finditer(re.escape(primary_binding.quote), primary.text)
        ]
        if len(occurrences) != 1:
            raise ValueError("knowledge evidence quote is absent or ambiguous")
        prefix = primary.text[: occurrences[0]]
        quote_line_start = primary.line_start + prefix.count("\n")
        citations = tuple(
            sorted(
                {
                    str(span.attributes["citation_id"])
                    for block in ir.blocks
                    for span in block.spans
                    if span.kind == "citation"
                    and "citation_id" in span.attributes
                    and any(binding.span_id == block.source_span.span_id for binding in item.evidence)
                }
            )
        )
        heading_path = next(
            (
                block.heading_path
                for block in ir.blocks
                if block.source_span.span_id == item.evidence[0].span_id
            ),
            (),
        )
        return _Record(
            record_id=item.knowledge_item_id,
            source_kind="knowledge",
            document_id=item.document_id,
            document_version_id=item.document_version_id,
            research_id=version.research_id,
            title=ir.title,
            aliases=document.aliases,
            text=item.text,
            heading_path=heading_path,
            heading_labels=_heading_labels(ir, heading_path),
            canonical_span_id=primary.span_id,
            evidence_span_ids=tuple(binding.span_id for binding in item.evidence),
            locator=EvidenceLocator(
                primary.span_id,
                primary.source_sha256,
                quote_line_start,
                quote_line_start + primary_binding.quote.count("\n"),
                primary_binding.byte_start,
                primary_binding.byte_end,
            ),
            citation_ids=citations,
            active_status=self._version_status(item.document_id, item.document_version_id),
            knowledge_enrichment=self._knowledge_status(item.document_version_id),
            fact_status=item.fact_status,
            knowledge_kind=item.kind,
            cluster_id=item.cluster_id,
            applicability=(
                self._applicability_by_item.get(item.knowledge_item_id, {})
                or self._document_consensus_applicability.get(
                    item.document_version_id, {}
                )
            ),
            relation=item.relation,
            # Formal items carry a bounded document route: title and aliases
            # locate the research, while exact heading/text and kind rank the
            # source evidence. Chunks deliberately do not repeat the title.
            terms=Counter(
                _terms(
                    "\n".join(
                        (
                            ir.title,
                            *document.aliases,
                            *_heading_labels(ir, heading_path),
                            item.kind,
                            item.text,
                        )
                    )
                )
            ),
        )

    def _build_records(self) -> tuple[_Record, ...]:
        rows = [
            self._record_for_chunk(chunk)
            for chunk in self.base.chunks.values()
            if chunk.retrievable
        ]
        if self.enriched is not None:
            rows.extend(self._record_for_knowledge(item) for item in self.enriched.knowledge_items.values())
        return tuple(sorted(rows, key=lambda row: row.record_id))

    def _lexical_score(self, record: _Record, query_terms: Counter[str]) -> tuple[float, list[str]]:
        """Length-normalized BM25 score over deterministic multilingual terms.

        The previous raw TF-IDF sum let long research chunks accumulate many
        overlapping CJK n-grams and crowd the exact supporting passage out of
        the first result page.  BM25 bounds repeated-term gains and normalizes
        record length.  ASCII/formula anchors and CJK trigrams receive a small,
        fixed boost because they carry more method identity than generic CJK
        bigrams; all weights remain query-independent and are serialized by
        the index version rather than tuned per document.
        """

        score = 0.0
        reasons: list[str] = []
        count = max(1, len(self.records))
        record_length = sum(record.terms.values())
        average_length = max(1.0, self._average_term_count)
        k1 = 1.2
        b = 0.75
        for term, query_frequency in query_terms.items():
            frequency = record.terms.get(term, 0)
            if not frequency:
                continue
            document_frequency = self._document_frequency[term]
            inverse = math.log(
                1 + (count - document_frequency + 0.5) / (document_frequency + 0.5)
            )
            if re.fullmatch(r"[a-z0-9_.+-]+", term):
                inverse *= 2.5
            elif len(term) >= 3 and _CJK_RE.fullmatch(term):
                inverse *= 1.8
            denominator = frequency + k1 * (
                1 - b + b * record_length / average_length
            )
            contribution = (
                inverse
                * frequency
                * (k1 + 1)
                / denominator
                * min(2, query_frequency)
            )
            score += contribution
            reasons.append(f"lexical:{term}")
        return score, reasons

    @staticmethod
    def _applicability(
        record: _Record, context: TaskContext
    ) -> tuple[float, list[str], list[str]]:
        bonus = 0.0
        matches: list[str] = []
        conflicts: list[str] = []
        for facet in ("market", "frequency", "data", "objective", "assumption"):
            expected_exact, expected_canonical = _canonical_facet_values(
                facet, getattr(context, facet)
            )
            available_exact, available_canonical = _canonical_facet_values(
                facet, record.applicability.get(facet, ())
            )
            if not expected_exact or not available_exact:
                continue
            exact_overlap = expected_exact & available_exact
            canonical_overlap = expected_canonical & available_canonical
            if exact_overlap or canonical_overlap:
                bonus += 1.5
                matches.append(
                    f"{facet}:{','.join(sorted(canonical_overlap or exact_overlap))}"
                )
            elif expected_canonical and available_canonical:
                conflicts.append(
                    f"{facet}:task={','.join(sorted(expected_canonical))};"
                    f"knowledge={','.join(sorted(available_canonical))}"
                )
        return bonus, matches, conflicts

    def _unsupported_concrete_context(self, context: TaskContext) -> tuple[str, ...]:
        unsupported: list[str] = []
        # Data type is a concrete corpus boundary (order book, satellite
        # imagery, factor exposure).  Market/frequency wording is much less
        # closed (for example ``A 股`` vs ``A股`` or bar aliases), so it remains
        # a ranking/filter facet rather than a global no-answer veto.
        for facet in ("data",):
            values = tuple(value for value in getattr(context, facet) if value.strip())
            if not values:
                continue
            facet_supported = False
            for value in values:
                for group in _anchor_groups(value):
                    if group.isascii():
                        if len(group) >= 2 and group in self._active_corpus_terms:
                            facet_supported = True
                            break
                    else:
                        candidates = (
                            (group,)
                            if len(group) <= 2
                            else tuple(
                                group[index : index + 3]
                                for index in range(len(group) - 2)
                            )
                        )
                        if any(
                            candidate in self._active_corpus_terms
                            for candidate in candidates
                        ):
                            facet_supported = True
                            break
                if facet_supported:
                    break
            if not facet_supported:
                unsupported.append(facet)
        return tuple(unsupported)

    def _unsupported_named_query_anchors(self, query: str) -> tuple[str, ...]:
        unsupported: list[str] = []
        matches = tuple(_ASCII_RE.finditer(query))
        for match in matches:
            surface = match.group(0)
            folded = surface.casefold()
            if folded in _ASCII_QUESTION_WORDS or len(folded) < 2:
                continue
            controlled_facet = _controlled_facet_canonical(surface)
            if controlled_facet is not None:
                # A controlled spelling is known only when its canonical value
                # is actually present in the active corpus. Thus A-share does
                # not become an unsupported named method in an A-share corpus,
                # while an absent Crypto market remains closed-world.
                canonical_terms = tuple(dict.fromkeys(_surface_terms(controlled_facet)))
                if canonical_terms and all(
                    term in self._active_corpus_terms for term in canonical_terms
                ):
                    continue
            lower_hyphenated_domain_term = (
                surface.count("-") >= 2
                or surface.casefold().endswith(("-duration", "-yield"))
            )
            # Common interrogatives/modals are removed above. Remaining title
            # case and all-caps surfaces are closed-world method/object names,
            # including sentence-initial names such as Johansen or
            # Avellaneda-Stoikov.
            looks_named = (
                lower_hyphenated_domain_term
                or surface.isupper()
                or (
                    surface[0].isupper()
                    and not surface[1:].isupper()
                )
            )
            if looks_named and folded not in self._active_corpus_terms:
                unsupported.append(folded)
        # Some finance objects are lower-case multiword names.  Individual
        # words such as ``rate`` or ``yield`` may occur throughout a corpus,
        # so token-level closed-world checks cannot distinguish key-rate
        # duration or convenience yield from grounded research.  Require the
        # exact term conjunction to occur in at least one immutable record.
        compound_terms = tuple(
            part
            for match in matches
            for part in re.split(r"-+", match.group(0).casefold())
            if part
        )
        for index, suffix in enumerate(compound_terms):
            width = (
                3
                if suffix == "duration"
                else 2
                if suffix in {"yield", "basis"}
                else 0
            )
            if not width or index + 1 < width:
                continue
            compound = compound_terms[index + 1 - width : index + 1]
            if any(value in _ASCII_QUESTION_WORDS for value in compound):
                continue
            if not any(
                all(value in record.terms for value in compound)
                for record in self.records
                if record.active_status == "active"
            ):
                unsupported.append("-".join(compound))
        return tuple(dict.fromkeys(unsupported))

    def search(
        self,
        query: str,
        *,
        context: TaskContext | None = None,
        limit: int = 8,
        include_history: bool = False,
        include_conflicts: bool = False,
        minimum_score: float = 0.35,
        minimum_weighted_coverage: float = 0.12,
    ) -> SearchResponse:
        if not query.strip() or limit < 1:
            raise ValueError("search query and positive limit are required")
        if not 0 < minimum_weighted_coverage <= 1:
            raise ValueError("minimum weighted coverage must be in (0, 1]")
        context = context or TaskContext()
        unsupported_context = self._unsupported_concrete_context(context)
        unsupported_named_anchors = self._unsupported_named_query_anchors(query)
        if unsupported_context or unsupported_named_anchors:
            reasons = list(unsupported_context)
            reasons.extend(
                f"named_anchor:{value}" for value in unsupported_named_anchors
            )
            return SearchResponse(
                query=query,
                snapshot_id=self.snapshot_id,
                index_version=INDEX_VERSION,
                cards=(),
                answerable=False,
                no_answer_reason="unsupported_task_context:" + ",".join(reasons),
                total_candidates=0,
            )
        positive_query, contrast_negatives = _contrast_parts(query)
        kind_preferences = _query_kind_preferences(positive_query)
        query_terms = Counter(_terms(positive_query))
        fts_candidates = self._fts_candidate_ids(query_terms)
        query_folded = positive_query.casefold().strip()
        rejected_document_ids: set[str] = set()
        if contrast_negatives:
            for candidate in self.records:
                if not include_history and candidate.active_status != "active":
                    continue
                candidate_surface = self._knowledge_search_surfaces.get(
                    candidate.record_id,
                    "\n".join(
                        (
                            candidate.title,
                            *candidate.aliases,
                            *candidate.heading_labels,
                            candidate.text,
                        )
                    ),
                )
                if any(
                    _matched_anchor_groups(negative, candidate_surface)
                    for negative in contrast_negatives
                ):
                    rejected_document_ids.add(candidate.document_id)
        scored: list[tuple[_Record, float, list[str], list[str], list[str]]] = []
        for record in self.records:
            if not include_history and record.active_status != "active":
                continue
            if record.document_id in rejected_document_ids:
                continue
            record_search_text = self._knowledge_search_surfaces.get(
                record.record_id, ""
            )
            if contrast_negatives and not record_search_text:
                record_search_text = "\n".join(
                    (
                        record.title,
                        *record.aliases,
                        *record.heading_labels,
                        record.text,
                    )
                )
            positive_anchors = (
                _matched_anchor_groups(positive_query, record_search_text)
                if record_search_text
                else ()
            )
            negative_anchors = tuple(
                dict.fromkeys(
                    anchor
                    for negative in contrast_negatives
                    for anchor in _matched_anchor_groups(negative, record_search_text)
                )
            )
            # An explicit contrast is a hard constraint on the default positive
            # evidence lane.  Generic positive words must never outvote a
            # specifically rejected method and reintroduce it near the tail.
            if negative_anchors:
                continue
            score, reasons = self._lexical_score(record, query_terms)
            matched_terms = {
                reason.removeprefix("lexical:")
                for reason in reasons
                if reason.startswith("lexical:")
            }
            document_anchors = _matched_anchor_groups(
                positive_query,
                "\n".join((record.title, *record.aliases)),
            )
            strong_document_anchors = tuple(
                anchor
                for anchor in document_anchors
                if any(
                    (
                        surface.strip().casefold() == anchor
                        or (
                            anchor.isascii()
                            and 2 <= len(anchor) <= 12
                            and any(
                                token.isupper()
                                and token.casefold() == anchor
                                for token in _ASCII_RE.findall(surface)
                            )
                        )
                    )
                    for surface in (record.title, *record.aliases)
                )
            )
            if document_anchors:
                # Route named research/method identity to its passages without
                # injecting the H1 title into every passage's BM25 term bag.
                # The bounded bonus selects a document; local headings/text
                # must still compete for passage rank inside that document.
                score += min(4.5, 1.5 * len(document_anchors))
                reasons.extend(
                    f"route:document-anchor:{anchor}"
                    for anchor in document_anchors[:3]
                )
            exact_values = {
                record.document_id.casefold(),
                record.document_version_id.casefold(),
                record.title.casefold(),
                *(alias.casefold() for alias in record.aliases),
            }
            exact_match = query_folded in exact_values
            if exact_match:
                score += 12.0
                reasons.append("exact:id-alias-title")
            elif len(query_folded) <= 3 and query_folded in record.text.casefold():
                score += 0.75
                reasons.append("short-substring-fallback")
            if record.record_id in fts_candidates:
                reasons.append("route:fts5")
            if record.source_kind == "knowledge" and kind_preferences:
                if record.knowledge_kind in kind_preferences:
                    score += 8.0
                    reasons.append(f"intent_kind:{record.knowledge_kind}")
                elif record.knowledge_kind not in {None, "evidence"}:
                    score -= 0.5
                    reasons.append("intent_kind:nonpreferred")
            applicability_bonus, matches, conflicts = self._applicability(record, context)
            score += applicability_bonus
            if conflicts:
                score -= 6.0 * len(conflicts)
                reasons.extend(f"applicability_conflict:{value}" for value in conflicts)
                if not include_conflicts:
                    continue
            if record.active_status != "active":
                score -= 8.0
                reasons.append(f"version_penalty:{record.active_status}")
            # A single common token in a long question is not grounded
            # evidence.  Weighting coverage by corpus rarity also makes unseen
            # domain anchors (for example an out-of-scope market/instrument)
            # count against a superficially matching generic word such as
            # "回测" or "标准化".  This is an explicit no-answer contract, not
            # a second opaque model.
            coverage = len(matched_terms) / max(1, len(query_terms))
            corpus_size = max(1, len(self.records))

            def term_weight(term: str) -> float:
                return math.log(
                    1
                    + (corpus_size + 0.5)
                    / (self._document_frequency.get(term, 0) + 0.5)
                )

            total_query_weight = sum(term_weight(term) for term in query_terms)
            matched_query_weight = sum(term_weight(term) for term in matched_terms)
            weighted_coverage = (
                matched_query_weight / total_query_weight
                if total_query_weight
                else 0.0
            )
            # A mechanically verified applicability facet is additional
            # grounded evidence for terse/adversarial queries (for example an
            # order-book task that explicitly says it is not factor
            # winsorisation).  It may relax, but never remove, lexical
            # coverage; unmatched context provides no such benefit.
            formal_anchors = (
                positive_anchors if record.source_kind == "knowledge" else ()
            )
            preferred_kind_route = (
                record.source_kind == "knowledge"
                and record.knowledge_kind in kind_preferences
                and bool(formal_anchors)
            )
            formal_evidence_route = (
                record.source_kind == "knowledge"
                and record.fact_status
                in {"source_explicit", "machine_verified", "human_reviewed"}
                and (len(formal_anchors) >= 2 or preferred_kind_route)
            )
            effective_weighted_floor = minimum_weighted_coverage
            effective_term_floor = 0.10
            if matches and not conflicts:
                effective_weighted_floor = min(effective_weighted_floor, 0.065)
                effective_term_floor = 0.05
            if formal_evidence_route:
                # A formal knowledge row is already bound to exact source
                # evidence.  Two independently matched anchors may therefore
                # route a long natural-language question even when generic
                # filler words lower whole-query coverage.  One-token matches
                # cannot use this relaxation, preserving explicit no-answer.
                effective_weighted_floor = min(effective_weighted_floor, 0.05)
                effective_term_floor = min(effective_term_floor, 0.05)
                reasons.append("route:formal-grounded-evidence")
                if preferred_kind_route:
                    reasons.append("route:explicit-kind-intent")
            if strong_document_anchors:
                # A closed-world exact alias or bounded acronym (for example
                # PBO) is itself grounded document identity. It may route a
                # long natural-language question to passages in that document,
                # but it does not bypass the score floor, local passage ranking,
                # applicability conflicts, or unsupported-name checks.
                effective_weighted_floor = min(effective_weighted_floor, 0.05)
                effective_term_floor = min(effective_term_floor, 0.05)
                reasons.append("route:strong-document-identity")
            if score >= minimum_score and (
                exact_match
                or (
                    coverage >= effective_term_floor
                    and weighted_coverage >= effective_weighted_floor
                )
            ):
                scored.append((record, score, reasons, matches, conflicts))

        # Expand only accepted, current, positive relations and do not let
        # relation paths multiply evidence weight.  A relation is a recall hint,
        # not a bypass around the query's explicit rejection or applicability
        # contract: every target is checked again before it may enter the answer
        # lane.  Negative edges (``contradicts``/``fails_under``) stay attached
        # to their formal source record and are never inverted into a positive
        # target recommendation.
        relation_additions: list[tuple[_Record, float, list[str], list[str], list[str]]] = []
        by_id = {record.record_id: record for record in self.records}
        by_cluster = {record.cluster_id: record for record in self.records if record.cluster_id}
        for record, score, reasons, matches, conflicts in scored:
            if record.source_kind != "knowledge" or record.relation is None:
                continue
            relation_type = record.relation["type"]
            if relation_type not in _POSITIVE_EXPANSION_RELATIONS:
                continue
            target = by_id.get(record.relation["target_id"]) or by_cluster.get(record.relation["target_id"])
            if target is None or (not include_history and target.active_status != "active"):
                continue
            if target.document_id in rejected_document_ids:
                continue
            target_surface = self._knowledge_search_surfaces.get(
                target.record_id,
                "\n".join(
                    (
                        target.title,
                        *target.aliases,
                        *target.heading_labels,
                        target.text,
                    )
                ),
            )
            rejected_anchors = tuple(
                dict.fromkeys(
                    anchor
                    for negative in contrast_negatives
                    for anchor in _matched_anchor_groups(negative, target_surface)
                )
            )
            if rejected_anchors:
                continue
            relation_bonus, relation_matches, relation_conflicts = self._applicability(
                target, context
            )
            if relation_conflicts and not include_conflicts:
                continue
            relation_additions.append(
                (
                    target,
                    max(minimum_score, score * 0.55 + relation_bonus),
                    [
                        f"relation:{relation_type}:{record.record_id}",
                        *(f"applicability_conflict:{value}" for value in relation_conflicts),
                    ],
                    relation_matches,
                    relation_conflicts,
                )
            )
        scored.extend(relation_additions)

        grouped: dict[str, tuple[_Record, float, set[str], set[str], set[str], set[str]]] = {}
        for record, score, reasons, matches, conflicts in scored:
            record_spans = set(record.evidence_span_ids)
            canonical_key = (
                f"evidence:{record.source_kind}:{record.document_version_id}:"
                f"{record.locator.byte_start}:{record.locator.byte_end}:"
                f"{record.cluster_id or '-'}:{record.knowledge_kind or '-'}"
            )
            current = grouped.get(canonical_key)
            if current is None:
                grouped[canonical_key] = (
                    record,
                    score,
                    set(reasons),
                    set(matches),
                    set(conflicts),
                    record_spans,
                )
            else:
                (
                    representative,
                    previous_score,
                    previous_reasons,
                    previous_matches,
                    previous_conflicts,
                    previous_spans,
                ) = current
                # A card may be reached through lexical and relation routes, but
                # its displayed semantic identity and score must come from the
                # same record.  Exact evidence keys never merge an adjacent
                # context span or a different knowledge kind/cluster.
                if score > previous_score:
                    representative = record
                resulting_spans = previous_spans | record_spans
                grouped[canonical_key] = (
                    representative,
                    max(previous_score, score),
                    previous_reasons | set(reasons),
                    previous_matches | set(matches),
                    previous_conflicts | set(conflicts),
                    resulting_spans,
                )

        limitations_by_document: dict[str, list[str]] = defaultdict(list)
        failures_by_document: dict[str, list[str]] = defaultdict(list)
        for record in self.records:
            if record.active_status != "active" or record.source_kind != "knowledge":
                continue
            if record.knowledge_kind == "limitation":
                limitations_by_document[record.document_id].append(record.text)
            elif record.knowledge_kind == "failure":
                failures_by_document[record.document_id].append(record.text)

        score_ordered = sorted(
            grouped.items(),
            key=lambda item: (-item[1][1], item[1][0].document_id, item[1][0].record_id),
        )
        # Formal rows compete on the same score as exact chunks.  A single
        # source-grounded row may occupy the final context slot only when no
        # formal row already ranks naturally and it remains score-competitive.
        # This preserves structured evidence without letting overlapping CJK
        # question n-grams jump ahead of clearly stronger passages.
        ordered = score_ordered[:limit]
        if ordered and not any(
            "route:formal-grounded-evidence" in value[2]
            for _key, value in ordered
        ):
            reserve = next(
                (
                    item
                    for item in score_ordered[limit:]
                    if "route:formal-grounded-evidence" in item[1][2]
                    and item[1][1] >= max(minimum_score, ordered[0][1][1] * 0.65)
                ),
                None,
            )
            if reserve is not None:
                reserve[1][2].add("rank_lane:competitive-formal-evidence")
                ordered[-1] = reserve
        for _key, value in ordered:
            if "route:formal-grounded-evidence" in value[2]:
                value[2].add("rank_signal:formal-grounded-evidence")
        cards: list[EvidenceCard] = []
        for rank, (canonical_key, value) in enumerate(ordered, 1):
            record, score, reasons, matches, conflicts, covered_spans = value
            cards.append(
                EvidenceCard(
                    evidence_id=record.record_id,
                    canonical_key=canonical_key,
                    document_id=record.document_id,
                    document_version_id=record.document_version_id,
                    research_id=record.research_id,
                    title=record.title,
                    text=record.text,
                    score=round(score, 8),
                    rank=rank,
                    source_kind=record.source_kind,
                    fact_status=record.fact_status,
                    knowledge_enrichment=record.knowledge_enrichment,
                    active_status=record.active_status,
                    knowledge_kind=record.knowledge_kind,
                    cluster_id=record.cluster_id,
                    locator=record.locator,
                    covered_span_ids=tuple(sorted(covered_spans)),
                    heading_path=record.heading_path,
                    citation_ids=record.citation_ids,
                    hit_reasons=tuple(sorted(reasons)),
                    applicability=record.applicability,
                    applicability_matches=tuple(sorted(matches)),
                    applicability_conflicts=tuple(sorted(conflicts)),
                    limitations=tuple(dict.fromkeys(limitations_by_document[record.document_id])),
                    failures=tuple(dict.fromkeys(failures_by_document[record.document_id])),
                )
            )
        answerable = bool(cards)
        return SearchResponse(
            query=query,
            snapshot_id=self.snapshot_id,
            index_version=INDEX_VERSION,
            cards=tuple(cards),
            answerable=answerable,
            no_answer_reason=None if answerable else "no_grounded_evidence_above_threshold",
            total_candidates=len(grouped),
        )


class ArtifactKnowledgeIndex(KnowledgeIndex):
    """The exact production MCP ranking path over a canonical release artifact."""

    _FIELDS = {
        "record_id",
        "source_kind",
        "document_id",
        "document_version_id",
        "research_id",
        "title",
        "aliases",
        "text",
        "heading_path",
        "heading_labels",
        "canonical_span_id",
        "evidence_span_ids",
        "locator",
        "citation_ids",
        "active_status",
        "knowledge_enrichment",
        "fact_status",
        "knowledge_kind",
        "cluster_id",
        "applicability",
        "relation",
        "terms",
    }

    def __init__(
        self,
        artifact: Mapping[str, object],
        *,
        base: BaseSnapshot | None = None,
        _build_runtime: bool = True,
    ) -> None:
        retrieval = artifact.get("retrieval")
        snapshot_id = artifact.get("snapshot_id")
        if (
            not isinstance(snapshot_id, str)
            or not snapshot_id
            or not isinstance(retrieval, dict)
            or set(retrieval)
            != {
                "schema_version",
                "index_version",
                "canonical_membership_sha256",
                "records",
            }
            or retrieval.get("schema_version") != RETRIEVAL_ARTIFACT_SCHEMA
            or retrieval.get("index_version") != INDEX_VERSION
            or not isinstance(retrieval.get("canonical_membership_sha256"), str)
            or not re.fullmatch(
                r"[0-9a-f]{64}", retrieval["canonical_membership_sha256"]
            )
            or not isinstance(retrieval.get("records"), list)
        ):
            raise ValueError("retrieval artifact identity or schema is invalid")
        self.base = base
        self.enriched = None
        self.snapshot_id = snapshot_id
        self._applicability_by_item = {}
        self._document_consensus_applicability = {}
        records: list[_Record] = []
        seen: set[str] = set()
        for raw in retrieval["records"]:
            if not isinstance(raw, dict) or set(raw) != self._FIELDS:
                raise ValueError("retrieval artifact record fields are not closed")
            record_id = raw["record_id"]
            locator = raw["locator"]
            applicability = raw["applicability"]
            terms = raw["terms"]
            sequence_fields = (
                "aliases",
                "heading_path",
                "heading_labels",
                "evidence_span_ids",
                "citation_ids",
            )
            relation = raw["relation"]
            string_fields = (
                "document_id",
                "document_version_id",
                "research_id",
                "title",
                "text",
                "canonical_span_id",
                "active_status",
                "knowledge_enrichment",
                "fact_status",
            )
            if (
                not isinstance(record_id, str)
                or not record_id
                or record_id in seen
                or raw["source_kind"] not in {"chunk", "knowledge"}
                or not isinstance(locator, dict)
                or set(locator) != {
                    "span_id",
                    "source_sha256",
                    "line_start",
                    "line_end",
                    "byte_start",
                    "byte_end",
                }
                or any(
                    not isinstance(raw[field], str) or not raw[field]
                    for field in string_fields
                )
                or not isinstance(locator.get("span_id"), str)
                or not locator["span_id"]
                or not isinstance(locator.get("source_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", locator["source_sha256"])
                or any(
                    type(locator.get(field)) is not int
                    for field in (
                        "line_start",
                        "line_end",
                        "byte_start",
                        "byte_end",
                    )
                )
                or not 1 <= locator["line_start"] <= locator["line_end"]
                or not 0 <= locator["byte_start"] <= locator["byte_end"]
                or not isinstance(applicability, dict)
                or not isinstance(terms, dict)
                or any(not isinstance(raw[field], list) for field in sequence_fields)
                or any(
                    key
                    not in {"market", "frequency", "data", "objective", "assumption"}
                    or not isinstance(values, list)
                    or any(not isinstance(value, str) or not value for value in values)
                    for key, values in applicability.items()
                )
                or any(
                    not isinstance(term, str)
                    or not term
                    or type(frequency) is not int
                    or frequency < 1
                    for term, frequency in terms.items()
                )
                or (
                    relation is not None
                    and (
                        not isinstance(relation, dict)
                        or set(relation) != {"type", "target_id"}
                        or relation.get("type")
                        not in {
                            "supports",
                            "contradicts",
                            "requires",
                            "extends",
                            "fails_under",
                        }
                        or not isinstance(relation.get("target_id"), str)
                        or not relation["target_id"]
                    )
                )
            ):
                raise ValueError("retrieval artifact record identity is invalid")
            seen.add(record_id)
            records.append(
                _Record(
                    record_id=record_id,
                    source_kind=raw["source_kind"],
                    document_id=str(raw["document_id"]),
                    document_version_id=str(raw["document_version_id"]),
                    research_id=str(raw["research_id"]),
                    title=str(raw["title"]),
                    aliases=tuple(str(value) for value in raw["aliases"]),
                    text=str(raw["text"]),
                    heading_path=tuple(str(value) for value in raw["heading_path"]),
                    heading_labels=tuple(
                        str(value) for value in raw["heading_labels"]
                    ),
                    canonical_span_id=str(raw["canonical_span_id"]),
                    evidence_span_ids=tuple(
                        str(value) for value in raw["evidence_span_ids"]
                    ),
                    locator=EvidenceLocator(**locator),
                    citation_ids=tuple(str(value) for value in raw["citation_ids"]),
                    active_status=str(raw["active_status"]),
                    knowledge_enrichment=str(raw["knowledge_enrichment"]),
                    fact_status=str(raw["fact_status"]),
                    knowledge_kind=(
                        str(raw["knowledge_kind"])
                        if raw["knowledge_kind"] is not None
                        else None
                    ),
                    cluster_id=(
                        str(raw["cluster_id"])
                        if raw["cluster_id"] is not None
                        else None
                    ),
                    applicability={
                        str(key): tuple(str(value) for value in values)
                        for key, values in applicability.items()
                    },
                    relation=relation,
                    terms=Counter(
                        {
                            str(term): int(frequency)
                            for term, frequency in terms.items()
                        }
                    ),
                )
            )
        self.records = tuple(records)
        self._validate_canonical_membership(artifact)
        if _build_runtime:
            self._initialize_search_runtime(time.perf_counter())
        else:
            self._fts = None
            self._document_frequency = Counter()
            self.index_footprint_bytes = 0
            self.build_latency_ms = 0.0

    def _validate_canonical_membership(self, artifact: Mapping[str, object]) -> None:
        """Prove every ranking record is an exact projection of canonical rows.

        The retrieval projection is an optimization, never another knowledge
        authority.  Reconstructing it from the sibling document/version/chunk/
        knowledge rows prevents a structurally valid but semantically drifted
        projection from entering a release.
        """

        try:
            canonical_members = {
                key: artifact[key]
                for key in ("documents", "versions", "chunks", "knowledge")
            }
            expected_membership_sha256 = hashlib.sha256(
                canonical_json(canonical_members).encode("utf-8")
            ).hexdigest()
            if artifact["retrieval"]["canonical_membership_sha256"] != expected_membership_sha256:  # type: ignore[index]
                raise ValueError("retrieval canonical membership hash is invalid")
            documents = {
                str(row["document_id"]): row for row in artifact["documents"]  # type: ignore[index]
            }
            versions = {
                str(row["version_id"]): row for row in artifact["versions"]  # type: ignore[index]
            }
            chunks = {
                str(row["chunk_id"]): row
                for row in artifact["chunks"]  # type: ignore[index]
                if row["retrievable"]
            }
            knowledge = {
                str(row["knowledge_item_id"]): row
                for row in artifact["knowledge"]  # type: ignore[index]
            }
        except (KeyError, TypeError) as error:
            raise ValueError("canonical artifact membership is unavailable") from error

        expected_ids = set(chunks) | set(knowledge)
        if set(chunks) & set(knowledge) or {row.record_id for row in self.records} != expected_ids:
            raise ValueError("retrieval records do not exactly cover canonical members")

        applicability_rows: list[
            tuple[str, str, Mapping[str, Sequence[str]]]
        ] = []
        for row in knowledge.values():
            applicability = row.get("applicability")
            if not isinstance(applicability, dict):
                raise ValueError("canonical knowledge applicability is invalid")
            for facet, values in applicability.items():
                if not isinstance(values, list):
                    raise ValueError("canonical knowledge applicability is invalid")
            applicability_rows.append(
                (
                    str(row["document_version_id"]),
                    str(row["knowledge_item_id"]),
                    {
                        str(facet): tuple(str(value) for value in values)
                        for facet, values in applicability.items()
                    },
                )
            )
        applicability_by_item, document_consensus_applicability = (
            _applicability_projections(applicability_rows)
        )

        def version_status(document: Mapping[str, object], version_id: str) -> str:
            if document["status"] != "active":
                return str(document["status"])
            return "active" if document["active_version_id"] == version_id else "superseded"

        for record in self.records:
            source = chunks.get(record.record_id) if record.source_kind == "chunk" else knowledge.get(record.record_id)
            if source is None:
                raise ValueError("retrieval record kind disagrees with canonical member")
            version = versions.get(record.document_version_id)
            document = documents.get(record.document_id)
            if version is None or document is None:
                raise ValueError("retrieval record references unknown canonical identity")
            applicability = (
                document_consensus_applicability.get(record.document_version_id, {})
                if record.source_kind == "chunk"
                else (
                    applicability_by_item.get(record.record_id, {})
                    or document_consensus_applicability.get(
                        record.document_version_id, {}
                    )
                )
            )
            common = {
                "document_id": str(source["document_id"]),
                "document_version_id": str(source["document_version_id"]),
                "research_id": str(version["research_id"]),
                "title": str(version["title"]),
                "aliases": tuple(str(value) for value in document["aliases"]),
                "text": str(source["text"]),
                "active_status": version_status(document, record.document_version_id),
                "knowledge_enrichment": str(version["knowledge_enrichment"]),
                "applicability": applicability,
                "heading_labels": tuple(
                    str(value) for value in source["heading_labels"]
                ),
            }
            for field, expected in common.items():
                if getattr(record, field) != expected:
                    raise ValueError(f"retrieval record {field} drifted from canonical member")

            if record.source_kind == "chunk":
                ordered_spans = tuple(str(value) for value in source["ordered_span_ids"])
                expected_specific = {
                    "heading_path": tuple(str(value) for value in source["heading_path"]),
                    "canonical_span_id": ordered_spans[0],
                    "evidence_span_ids": ordered_spans,
                    "citation_ids": tuple(str(value) for value in source["citation_ids"]),
                    "fact_status": "source_explicit",
                    "knowledge_kind": None,
                    "cluster_id": None,
                    "relation": None,
                    "locator": EvidenceLocator(
                        ordered_spans[0],
                        str(version["source_sha256"]),
                        int(source["line_start"]),
                        int(source["line_end"]),
                        int(source["byte_start"]),
                        int(source["byte_end"]),
                    ),
                    "terms": Counter(
                        _terms(
                            "\n".join(
                                (
                                    *(str(value) for value in source["heading_labels"]),
                                    str(source["text"]),
                                )
                            )
                        )
                    ),
                }
            else:
                locator = source["source_locator"]
                expected_specific = {
                    "heading_path": tuple(str(value) for value in source["heading_path"]),
                    "canonical_span_id": str(locator["span_id"]),
                    "evidence_span_ids": tuple(
                        str(value) for value in source["source_span_ids"]
                    ),
                    "citation_ids": tuple(str(value) for value in source["citation_ids"]),
                    "fact_status": str(source["fact_status"]),
                    "knowledge_kind": str(source["kind"]),
                    "cluster_id": str(source["cluster_id"]),
                    "relation": source["relation"],
                    "locator": EvidenceLocator(
                        str(locator["span_id"]),
                        str(locator["source_sha256"]),
                        int(locator["line_start"]),
                        int(locator["line_end"]),
                        int(locator["byte_start"]),
                        int(locator["byte_end"]),
                    ),
                    "terms": Counter(
                        _terms(
                            "\n".join(
                                (
                                    str(version["title"]),
                                    *(str(value) for value in document["aliases"]),
                                    *(str(value) for value in source["heading_labels"]),
                                    str(source["kind"]),
                                    str(source["text"]),
                                )
                            )
                        )
                    ),
                }
            for field, expected in expected_specific.items():
                if getattr(record, field) != expected:
                    raise ValueError(f"retrieval record {field} drifted from canonical member")


class LikeBaselineIndex(KnowledgeIndex):
    """Adapter matching the legacy `%whole query%` LIKE search semantics."""

    def search(self, query: str, **kwargs: Any) -> SearchResponse:
        limit = int(kwargs.get("limit", 8))
        expanded = super().search(query, **{**kwargs, "limit": max(limit, len(self.records))})
        literal = query.casefold().strip()
        selected = [
            card
            for card in expanded.cards
            if literal in card.title.casefold() or literal in card.text.casefold()
        ][:limit]
        cards = tuple(replace(card, rank=index) for index, card in enumerate(selected, 1))
        return SearchResponse(
            query=query,
            snapshot_id=self.snapshot_id,
            index_version="qrh-legacy-whole-query-like-baseline/v1",
            cards=cards,
            answerable=bool(cards),
            no_answer_reason=None if cards else "no_literal_whole_query_match",
            total_candidates=len(selected),
        )


__all__ = [
    "EvidenceCard",
    "EvidenceLocator",
    "ArtifactKnowledgeIndex",
    "INDEX_VERSION",
    "KnowledgeIndex",
    "LikeBaselineIndex",
    "RETRIEVAL_ARTIFACT_SCHEMA",
    "SearchResponse",
    "TaskContext",
]
