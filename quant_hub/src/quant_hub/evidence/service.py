from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import PurePosixPath
import re
import sqlite3
import stat
from typing import Any

from quant_hub.archive.catalog import ArchiveCatalog
from quant_hub.config import Settings, stat_is_reparse_point
from quant_hub.presentation.evidence_researcher_insights import (
    build_researcher_insight,
)
from quant_hub.presentation.citation_overlays import CitationOverlayRegistry

from .database import evidence_connection
from .ids import validate_citation_id
from .presentation import EvidencePresentationError, chinese_overlays_by_excerpt
from .resources import (
    EvidenceResourceCorruption,
    EvidenceResourceNotFound,
    EvidenceResourceStore,
    ResourceResponse,
)


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_LEDGER_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_ARCHIVE_HEADING_ANCHOR_RE = re.compile(r"^anc_sha256_[0-9a-f]{64}$")
_PUBLICATION_COPYRIGHT_TAIL_RE = re.compile(
    r"\s+(?:(?:©|\(c\)|copyright|r)\s*)?\d{4}\s+"
    r"(?:Elsevier(?:\s+(?:Inc|B\.?V\.?))?|[^.\n]{1,80})\.?\s+"
    r"All\s+rights\s+reserved\.?[^\n]*\Z",
    re.IGNORECASE,
)
_SUBJECT_CLASSIFICATION_TAIL_RE = re.compile(
    r"\s+(?:AMS\s+\d{4}\s+)?subject\s+classifications?\s*:[^\n]*\Z",
    re.IGNORECASE,
)
_REVIEWED_PDF_ABSTRACT_ARTIFACT_CUT_RE = re.compile(
    # Two reviewed PDFs expose a clean abstract first and then concatenate a
    # two-column article body or repository cover sheet into the same extracted
    # block.  Cut only at their stable metadata/body transition; the stored
    # source excerpt remains untouched for audit and replay.
    r"\s+(?:"
    r"Although\s+statistical\s+properties\s+of\s+prices\s+of\s+stocks\s+and\s+Our\s+goal\s+is"
    r"|DOI:\s*https://doi\.org/\S+\s+Posted\s+at\s+the\s+Zurich\s+Open\s+Repository"
    r")",
    re.IGNORECASE,
)
_AUTHOR_PUBLISHER_LICENSE_TAIL_RE = re.compile(
    r"\s+©\s*\d{4}\s+The\s+Author\(s\)\.\s+Published\s+by\s+Elsevier\s+B\.?V\.?\."
    r"(?:\s+\w+)*\s+This\s+is\s+an\s+open\s+access\s+article\s+under\s+the\s+CC\s+BY\s+license"
    r"(?:\s*\([^)]*\))?\s*\Z",
    re.IGNORECASE,
)


class EvidenceQueryNotFound(KeyError):
    pass


@dataclass(frozen=True, slots=True)
class CitationRenderSpec:
    citation_id: str
    document_sha256: str
    locator_kind: str
    byte_start: int | None
    byte_end: int | None
    line_start: int
    line_end: int
    raw_marker_text: str
    resolution_state: str
    ledger_entry_ids: tuple[str, ...]
    paper_ids: tuple[str, ...]
    detail_url: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _json(value: object) -> object:
    return json.loads(str(value))


def _table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        ).fetchone()
        is not None
    )


def _resolution_state(locator_status: str, statuses: list[str]) -> str:
    if "conflicted" in statuses:
        return "conflicted"
    if "resolved" in statuses and locator_status == "valid":
        return "valid"
    if "source_only" in statuses or "rejected_non_paper" in statuses:
        return "source-only"
    return "unresolved"


def _clean_archive_context(value: object, *, limit: int = 320) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    text = re.sub(r"^(?:[-*+]\s+|#{1,6}\s+)", "", text)
    if len(text) <= limit:
        return text
    candidate = text[: limit + 1]
    boundary = max(candidate.rfind(mark) for mark in ("。", "！", "？", "；", ". "))
    if boundary >= limit // 2:
        candidate = candidate[: boundary + 1]
    else:
        candidate = candidate[:limit].rstrip()
    candidate = candidate[: _retreat_cut_before_math_span(text, len(candidate))].rstrip()
    return candidate + "…"


def _retreat_cut_before_math_span(text: str, cut: int) -> int:
    """若展示截断点落在完整公式内部，退回公式 opener 之前。"""

    cursor = 0
    while cursor < len(text):
        if text.startswith("\\(", cursor):
            opener, closer = "\\(", "\\)"
        elif text.startswith("\\[", cursor):
            opener, closer = "\\[", "\\]"
        elif text.startswith("$$", cursor):
            opener = closer = "$$"
        elif text[cursor] == "$" and (cursor == 0 or text[cursor - 1] != "\\"):
            opener = closer = "$"
        else:
            cursor += 1
            continue
        closing = text.find(closer, cursor + len(opener))
        if closing < 0:
            return cut
        span_end = closing + len(closer)
        if cursor < cut < span_end:
            return cursor
        cursor = span_end
    return cut


def _researcher_excerpt_text(value: object) -> str:
    """Remove publisher boilerplate only in the researcher presentation layer.

    Evidence hashes and source excerpts remain byte-for-byte unchanged in the
    database and in :meth:`paper_detail`.  The public view merely omits a
    terminal copyright/rights footer that is not part of the research abstract.
    """

    text = str(value or "").strip()
    text = _REVIEWED_PDF_ABSTRACT_ARTIFACT_CUT_RE.split(text, maxsplit=1)[0].rstrip()
    text = _AUTHOR_PUBLISHER_LICENSE_TAIL_RE.sub("", text).rstrip()
    text = _PUBLICATION_COPYRIGHT_TAIL_RE.sub("", text).rstrip()
    return _SUBJECT_CLASSIFICATION_TAIL_RE.sub("", text).rstrip()


def _archive_source_anchor(
    target: dict[str, Any], line_start: int
) -> tuple[str, str, str | None]:
    """Resolve an Evidence relation to an anchor the Archive page always owns.

    ``citation_occurrence`` is a lossless evidence ledger, while the Archive
    reader deliberately projects only occurrences that can become a unique,
    non-overlapping Markdown interaction.  A ledger ``citation_id`` therefore
    cannot be used as an unconditional HTML fragment.  Stable heading anchors
    come from the persisted Archive projection and survive both the citation
    and presentation-only render paths.  Before the first heading (or for a
    heading-free document), the template-owned document anchor is the exact
    fallback.
    """

    document_id = str(target["document_id"])
    document_anchor = f"document-{document_id}"
    selected: tuple[int, str, str | None] | None = None
    sections = target.get("sections")
    if isinstance(sections, list):
        for section in sections:
            if not isinstance(section, dict):
                continue
            anchor_id = str(section.get("anchor_id") or "")
            if not _ARCHIVE_HEADING_ANCHOR_RE.fullmatch(anchor_id):
                continue
            try:
                section_line = int(section["line_start"])
            except (KeyError, TypeError, ValueError):
                continue
            if section_line > line_start:
                continue
            title = str(section.get("title_text") or "").strip() or None
            candidate = (section_line, anchor_id, title)
            if selected is None or candidate[0] > selected[0]:
                selected = candidate
    if selected is None:
        return document_anchor, "定位到研究文档", None
    return selected[1], "定位到原文所在章节", selected[2]


def _verified_sha256(value: object) -> str | None:
    candidate = str(value or "").strip().casefold()
    return candidate if _SHA256_RE.fullmatch(candidate) else None


def _official_source_presentation(locator: object) -> dict[str, object] | None:
    """把来源 locator 转成内部详情可读字段；公开视图不会返回 locator。"""

    if not isinstance(locator, dict):
        return None
    corroboration = locator.get("corroboration")
    corroboration = corroboration if isinstance(corroboration, dict) else {}
    url = corroboration.get("source_url") or locator.get("url") or locator.get(
        "source_url"
    )
    source_url = str(url) if isinstance(url, str) and url.startswith("https://") else None
    field = str(locator.get("field") or locator.get("html_meta_name") or "").strip()
    if field == "atom.entry.summary":
        source_label = "arXiv 官方摘要页"
        field_label = "Atom entry summary（官方摘要字段）"
    elif field == "crossref.message.abstract":
        source_label = "Crossref 官方 DOI 元数据"
        field_label = "message.abstract（出版方提交的官方摘要字段）"
    elif field == "citation_abstract":
        source_label = "arXiv 官方摘要页"
        field_label = "citation_abstract（官方摘要字段）"
    elif field == "openalex.abstract_inverted_index" or str(
        locator.get("source_kind") or ""
    ) == "openalex":
        source_label = "OpenAlex 书目摘要（第三方聚合）"
        field_label = "abstract_inverted_index（可信书目元数据，非出版方官方摘要）"
    elif field == "paper.abstract" or str(
        locator.get("source_kind") or ""
    ) in {"paper_pdf", "conference_pdf"}:
        source_label = "已核验论文 PDF 摘要"
        field_label = "论文摘要章节"
    elif str(locator.get("source_kind") or "") in {
        "publisher_abstract",
        "ssrn_abstract",
    }:
        source_label = "出版方或作者提交的摘要页"
        field_label = field or "已核验摘要字段"
    else:
        source_label = "已核验来源页面"
        field_label = field or "已核验摘要字段"
    source_sha256 = next(
        (
            value
            for value in (
                _verified_sha256(locator.get("source_file_sha256")),
                _verified_sha256(locator.get("page_sha256")),
                _verified_sha256(corroboration.get("source_file_sha256")),
            )
            if value is not None
        ),
        None,
    )
    return {
        "source_label": source_label,
        "source_url": source_url,
        "field_label": field_label,
        "source_sha256": source_sha256,
    }


def _conclusion_source_presentation(locator: object) -> dict[str, object] | None:
    """压缩全文 locator，只展示章节、页码和校验哈希。"""

    if not isinstance(locator, dict):
        return None
    nested = locator.get("locator")
    nested = nested if isinstance(nested, dict) else locator
    raw_pages = nested.get("pdf_pages")
    pages: list[int] = []
    if isinstance(raw_pages, list):
        for value in raw_pages:
            try:
                page = int(value)
            except (TypeError, ValueError):
                continue
            if page > 0 and page not in pages:
                pages.append(page)
    try:
        primary_page = int(locator.get("page_number") or 0)
    except (TypeError, ValueError):
        primary_page = 0
    if primary_page > 0 and primary_page not in pages:
        pages.insert(0, primary_page)
    section = str(nested.get("section") or "").strip() or None
    pdf_sha256 = _verified_sha256(nested.get("source_pdf_sha256"))
    support_sha256 = _verified_sha256(locator.get("support_text_sha256"))
    page_text_sha256 = _verified_sha256(locator.get("page_text_sha256"))
    if not any((pages, section, pdf_sha256, support_sha256, page_text_sha256)):
        return None
    return {
        "section": section,
        "pages": pages,
        "pdf_sha256": pdf_sha256,
        "support_sha256": support_sha256,
        "page_text_sha256": page_text_sha256,
    }


def _analysis_summary(value: object) -> str:
    text = str(value or "").strip()
    try:
        payload = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return _clean_archive_context(text, limit=800)
    if isinstance(payload, dict):
        for key in ("fact_boundary", "summary", "reason", "conclusion"):
            candidate = payload.get(key)
            if isinstance(candidate, str) and candidate.strip():
                return _clean_archive_context(candidate, limit=800)
    return "该技术复核记录已保留在 Evidence API；阅读页仅展示可解释的事实边界。"


def _present_excerpt_row(item: Any) -> dict[str, object]:
    text = str(item["excerpt_text"])
    stored_sha256 = str(item["excerpt_sha256"])
    actual_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if stored_sha256 != actual_sha256:
        raise EvidencePresentationError("官方摘要文本与登记哈希不一致")
    locator = _json(item["locator_json"])
    return {
        "excerpt_id": str(item["excerpt_id"]),
        "text": text,
        "locator": locator,
        "locator_presentation": _official_source_presentation(locator),
        "sha256": stored_sha256,
        "provenance_urn": str(item["provenance_urn"]),
    }


def _relation_presentation(
    relation_kind: str, relation_semantics: str, occurrence_type: str
) -> tuple[str, str, int, bool]:
    if relation_semantics == "associated_method_origin":
        return (
            "方法原始来源",
            "该论文用于追溯研究中所采用方法的原始出处；它说明方法谱系，不被扩大解释为当前量化结论的直接实证支持。",
            100,
            True,
        )
    if relation_kind == "supports":
        return (
            "论据支持",
            "该论文的结果或论证被用于支撑相邻量化研究判断，具体使用边界以原文片段为准。",
            95,
            True,
        )
    if relation_kind == "contrasts":
        return (
            "对照与边界",
            "该论文被用作比较基准或反例，帮助界定当前研究结论的适用范围。",
            95,
            True,
        )
    if relation_kind == "method_uses":
        return (
            "方法应用",
            "该论文提供模型、目标函数、优化或诊断方法，研究在当前量化问题中采用或改造了这项方法。",
            95,
            True,
        )
    occurrence_labels: dict[str, tuple[str, str, int, bool]] = {
        "formal_citation_command": (
            "正文直接引用",
            "该论文在正文论证中被直接引用，用于支撑相邻段落的方法选择、经验判断或结论边界。",
            90,
            True,
        ),
        "textual_author_year_mention": (
            "正文观点引用",
            "研究在此引用作者观点或论文结果；下方原文片段说明它在当前量化语境中的具体用途。",
            85,
            True,
        ),
        "method_or_resource_name": (
            "技术方法引用",
            "该论文在正文中作为模型、损失函数、优化器或诊断工具的技术来源。",
            80,
            True,
        ),
        "explicit_url": (
            "正文来源链接",
            "研究正文在此明确指向论文官方版本，用于补充相邻观点的可追溯来源。",
            75,
            True,
        ),
        "strong_identifier_arxiv": (
            "论文身份定位",
            "该位置用于确认论文的精确版本；只有与同一位置的正文观点结合时才视为研究论据。",
            35,
            False,
        ),
        "strong_identifier_ssrn": (
            "论文身份定位",
            "该位置用于确认论文的精确版本；只有与同一位置的正文观点结合时才视为研究论据。",
            35,
            False,
        ),
        "formal_reference_list_occurrence": (
            "正式参考文献",
            "该论文列入研究的正式参考文献；当前位置只证明来源关系，不额外推断正文采用了哪项结论。",
            25,
            False,
        ),
        "formal_bibliography_entry": (
            "正式参考文献",
            "该论文列入研究的正式参考文献；当前位置只证明来源关系，不额外推断正文采用了哪项结论。",
            25,
            False,
        ),
    }
    return occurrence_labels.get(
        occurrence_type,
        (
            "研究正文提及",
            "该论文在研究正文中被提及；具体用途以可直接跳转的原文片段为准。",
            55,
            relation_kind != "formal_reference",
        ),
    )


_PUBLISHED_RESEARCH_SLUG_BY_ARCHIVE_URN = {
    "qrh:archive:research:Q1_PRODUCT_EVALUATION": "q1-product-factor-evaluation",
    "qrh:archive:research:Q2_FACTORY_DESIGN": "q2-low-snr-neural-selection-factory",
    "qrh:archive:research:Q3_FACTORY_EVALUATION": "q3-training-method-reliability",
    "qrh:archive:research:Q4_PRODUCTION_MONITORING": "q4-operations-post-deployment-monitoring",
    "qrh:archive:research:POFF_EXTENSION": "poff-cross-cutting-diagnostics",
}


def _published_research_landings(
    archive_index: dict[str, dict[str, Any]],
) -> dict[str, dict[str, str]]:
    """Collapse the document index into the public research landing directory."""

    landings: dict[str, dict[str, str]] = {}
    for target in archive_index.values():
        slug = str(target.get("research_slug") or "").strip()
        research_id = str(target.get("research_id") or "").strip()
        title = str(target.get("research_title") or "").strip()
        if not slug or not research_id or not title:
            continue
        landings.setdefault(
            slug,
            {
                "research_id": research_id,
                "research_slug": slug,
                "research_title": title,
                "url": f"/research/{research_id}",
            },
        )
    return landings


def _historical_relation_document(
    archive_index: dict[str, dict[str, Any]],
    *,
    paper_title: str,
    context: str,
) -> dict[str, Any] | None:
    """Map a retired-source relation onto a concrete published research document.

    A historical TeX/backup line cannot honestly be projected to a current line
    number.  It can, however, be mapped to the current document that owns the
    same method or research question.  The rules below use only the paper title
    and preserved historical context; the returned URL therefore targets the
    real document anchor rather than inventing a present-day citation anchor.
    """

    material = f"{paper_title} {context}".casefold()
    # Signals are deliberately paper/method specific.  The target fragments are
    # formal titles already published by ArchiveCatalog, not filenames.
    rules: tuple[tuple[tuple[str, ...], str, tuple[str, ...]], ...] = (
        (
            (
                "ordinal measures",
                "kruskal",
                "spearman",
                "kendall",
                "stylized facts",
                "肥尾",
                "秩相关",
            ),
            "q1-product-factor-evaluation",
            ("因子预测质量检验",),
        ),
        (
            ("how to use the sharpe ratio", "haircut sharpe", "backtesting"),
            "q3-training-method-reliability",
            ("多重试验校正下的夏普显著性",),
        ),
        (
            ("hyperparameter ensembles", "hyper-parameter ensemble"),
            "q2-low-snr-neural-selection-factory",
            ("模型集成、权重平均与失效条件",),
        ),
        (
            (
                "self-distillation",
                "knowledge distillation",
                "towards understanding ensemble",
            ),
            "q2-low-snr-neural-selection-factory",
            ("模型集成、权重平均与失效条件",),
        ),
        (
            ("embeddings for numerical features", "numerical features"),
            "q2-low-snr-neural-selection-factory",
            ("数值因子嵌入与监督表征设计",),
        ),
        (
            (
                "emergent abilities",
                "scaling laws",
                "scaling law",
                "compute-optimal",
                "chinchilla",
            ),
            "q2-low-snr-neural-selection-factory",
            ("系统文献综述与机制分析",),
        ),
        (
            ("minimax rates", "information-theoretic determination", "yang-barron"),
            "archive-experiments-e1-e8",
            ("低信噪比选股模型的受控验证实验矩阵",),
        ),
        (
            (
                "market efficiency",
                "efficiently inefficient markets",
                "gârleanu",
                "garleanu",
            ),
            "q1-product-factor-evaluation",
            ("市场状态条件下的因子稳健性分析",),
        ),
        (
            ("probability of backtest overfitting", "selection bias"),
            "q3-training-method-reliability",
            ("回测过拟合概率",),
        ),
    )
    unique_targets: dict[str, dict[str, Any]] = {}
    for target in archive_index.values():
        document_id = str(target.get("document_id") or "").strip()
        if document_id:
            unique_targets.setdefault(document_id, target)
    for signals, slug, title_fragments in rules:
        if not any(signal in material for signal in signals):
            continue
        matching = [
            target
            for target in unique_targets.values()
            if str(target.get("research_slug") or "") == slug
            and any(
                fragment in str(target.get("title") or "")
                for fragment in title_fragments
            )
        ]
        if matching:
            return sorted(
                matching,
                key=lambda target: (
                    len(str(target.get("title") or "")),
                    str(target.get("document_id") or ""),
                ),
            )[0]
    return None


def _historical_relation_section(
    target: dict[str, Any], *, paper_title: str, context: str
) -> tuple[str, str] | None:
    """Return a real current section only when its semantic match is explicit."""

    paper_material = paper_title.casefold()
    paper_section_rules: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
        (
            ("minirocket",),
            ("6.1 ROCKET / MiniROCKET",),
        ),
        (
            ("inceptiontime",),
            ("6.4 InceptionTime",),
        ),
        (
            ("n-beats", "nbeats"),
            ("6.5 Decomposition 与 N-BEATS",),
        ),
        (
            ("patchtst", "a time series is worth 64 words"),
            ("6.6 Tokenization 与 PatchTST",),
        ),
        (
            (
                "ts2vec",
                "temporal neighborhood coding",
                "contrastive learning of disentangled seasonal-trend",
            ),
            ("6.9 Self-supervised representation",),
        ),
    )
    material = f"{paper_title} {context}".casefold()
    section_rules: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
        (
            (
                "ordinal measures",
                "kruskal",
                "spearman",
                "kendall",
                "stylized facts",
                "肥尾",
                "秩相关",
            ),
            ("RankIC（排序信息系数）",),
        ),
        (
            ("backtesting", "haircut sharpe"),
            ("Haircut SR（Harvey-Liu 2015）",),
        ),
        (
            ("minimax rates", "information-theoretic determination", "yang-barron"),
            ("实验清单",),
        ),
        (
            (
                "hyperparameter ensembles",
                "hyper-parameter ensemble",
                "self-distillation",
                "knowledge distillation",
                "towards understanding ensemble",
            ),
            ("主线四：平均而非选择",),
        ),
        (
            ("emergent abilities",),
            ("D3.4",),
        ),
        (
            ("scaling laws", "scaling law", "compute-optimal", "chinchilla"),
            ("D3.3",),
        ),
        (
            (
                "market efficiency",
                "efficiently inefficient markets",
                "gârleanu",
                "garleanu",
            ),
            ("5-DM（5 类衰减机制）分类",),
        ),
    )
    wanted = next(
        (
            title_fragments
            for signals, title_fragments in paper_section_rules
            if any(signal in paper_material for signal in signals)
        ),
        (),
    )
    for signals, title_fragments in section_rules:
        if wanted:
            break
        if any(signal in material for signal in signals):
            wanted = title_fragments
            break
    if not wanted:
        return None
    for section in target.get("sections") or []:
        if not isinstance(section, dict):
            continue
        title = str(section.get("title_text") or "").strip()
        anchor = str(section.get("anchor_id") or "").strip()
        if (
            _ARCHIVE_HEADING_ANCHOR_RE.fullmatch(anchor)
            and any(fragment in title for fragment in wanted)
        ):
            return anchor, title
    return None


def _historical_relation_landing_slug(
    *,
    research_urn: str,
    paper_title: str,
    context: str,
) -> str:
    """Resolve a historical ledger family to a *research* page, never a fake anchor.

    Exact current source paths are resolved by :func:`_archive_source_anchor`.
    This classifier is only for retired POFF/LaTeX source families: it selects a
    public topic landing from the words already present in the paper title and
    citation context, and deliberately does not claim a line-level correspondence.
    """

    direct = _PUBLISHED_RESEARCH_SLUG_BY_ARCHIVE_URN.get(research_urn)
    if direct is not None:
        return direct
    material = f"{paper_title} {context}".casefold()
    rules: tuple[tuple[tuple[str, ...], str], ...] = (
        (
            (
                "concept drift",
                "data drift",
                "population stability",
                "cusum",
                "ewma",
                "部署",
                "漂移",
                "监控",
            ),
            "q4-operations-post-deployment-monitoring",
        ),
        (
            (
                "time series",
                "temporal",
                "wavelet",
                "rocket",
                "frequency",
                "序列",
                "时序",
                "小波",
                "频域",
            ),
            "q5-factor-history-sequence-compression",
        ),
        (
            (
                "backtest",
                "overfit",
                "data snooping",
                "multiple testing",
                "false discovery",
                "deflated sharpe",
                "probability of backtest",
                "purged",
                "embargo",
                "cross-validation",
                "cka",
                "seed",
                "random seed",
                "representation similarity",
                "回测过拟合",
                "多重检验",
                "种子",
                "表征相似",
            ),
            "q3-training-method-reliability",
        ),
        (
            (
                "information coefficient",
                "rank ic",
                "factor premium",
                "factor return",
                "cross-section",
                "cross sectional",
                "market regime",
                "adaptive markets",
                "portfolio turnover",
                "transaction cost",
                "因子质量",
                "市场状态",
                "交易成本",
                "换手率",
            ),
            "q1-product-factor-evaluation",
        ),
        (
            (
                "pitfall",
                "researcher degrees of freedom",
                "reproducib",
                "backtesting protocol",
                "研究失效",
                "研究自由度",
            ),
            "poff-cross-cutting-diagnostics",
        ),
    )
    for signals, slug in rules:
        if any(signal in material for signal in signals):
            return slug
    # POFF legacy is primarily the low-SNR model-development manuscript.  When
    # its surviving context does not distinguish a narrower public topic, the
    # honest target is the factory-design landing, not a fabricated section.
    return "q2-low-snr-neural-selection-factory"


def _research_usage_description(
    *,
    paper_title: str,
    context: str,
    research_title: str,
    document_title: str,
    relation_kind: str,
    relation_semantics: str,
    historical_mapping: bool = False,
) -> str:
    """Explain what the cited idea changes in the quant workflow.

    The ledger keeps provenance and claim-boundary fields.  This sentence is a
    separate research-facing interpretation, selected only from signals present
    in the paper title and the actual neighbouring Archive text.
    """

    title = _clean_archive_context(paper_title, limit=150) or "该论文"
    material = f"{paper_title} {context}".casefold()
    rules: tuple[tuple[tuple[str, ...], str, str], ...] = (
        (
            ("centered kernel alignment", "kernel alignment", "cka", "表征相似"),
            "跨模型或跨随机种子的表征相似度度量",
            "比较不同训练重复的隐藏表示是否学到同一结构，并把“收益相近但表征漂移”识别为不稳定方案，而不是直接按单次 IC 放行",
        ),
        (
            (
                "ordinal measures",
                "test of independence",
                "spearman",
                "kendall",
                "rank correlation",
                "秩相关",
            ),
            "秩相关、独立性与非线性关联的统计度量",
            "选择适合金融肥尾与非正态截面的关联指标，并把 RankIC 的显著性、单调性和对极端值的敏感度分开检查",
        ),
        (
            (
                "minimax rates",
                "information-theoretic",
                "cramér-rao",
                "cramer-rao",
                "yang-barron",
                "极小极大",
                "信息论下界",
            ),
            "噪声、有效维度与样本量共同决定的预测误差下界",
            "先判断当前数据量和信噪比允许多大的可学习增量，再约束模型容量与验收阈值，避免把不可约噪声误判成架构或优化器失败",
        ),
        (
            (
                "noise dressing",
                "covariance matrices",
                "covariance estimator",
                "marchenko",
                "random matrix",
                "协方差清洗",
                "随机矩阵",
                "特征值",
                "收缩白化",
            ),
            "高维协方差中的噪声特征值与估计不稳定",
            "在白化、PCA 或风险建模前收缩或清洗协方差，防止小特征值方向放大纯噪声，并通过滚动样本外结果决定保留多少有效维度",
        ),
        (
            (
                "stylized facts",
                "heavy tail",
                "fat tail",
                "volatility clustering",
                "肥尾",
                "波动率聚类",
            ),
            "金融收益的肥尾、波动聚类和非正态相关结构",
            "检查正态假设下的 IC 转换和显著性公式是否失真，并以稳健统计、分状态评估或重抽样替代脆弱的参数化结论",
        ),
        (
            ("roc analysis", "roc / auc", "auc", "receiver operating"),
            "分类评分的区分能力与阈值无关评估",
            "把方向预测的排序能力与具体交易阈值分开衡量，并结合类别不平衡、收益幅度和成本确认 AUC 改善是否具有投资价值",
        ),
        (
            (
                "double backpropagation",
                "adaptive regularization",
                "weight decay",
                "large margin",
                "zero training loss",
                "flooding",
                "正则",
                "权重衰减",
            ),
            "输入敏感度、参数收缩与停止记忆噪声的正则化机制",
            "把正则强度当成低信噪比训练的核心实验轴，并用样本外 IC、扰动敏感性和跨种子离散度判断它是在压噪声还是压掉有效信号",
        ),
        (
            (
                "large-batch",
                "large batch",
                "minima in sgd",
                "learning rate",
                "radam",
                "gradient noise",
                "gsnr",
                "optimization algorithms",
                "batch size",
                "学习率",
                "梯度噪声",
                "尖极小值",
                "温度",
            ),
            "学习率、批量大小与梯度噪声共同决定的训练动力学",
            "在保持有效优化温度可比的条件下联合搜索学习率和 batch，而不是孤立归因；最终以跨种子稳定性和样本外 IC 选择训练区间",
        ),
        (
            (
                "benign overfitting",
                "double descent",
                "lottery ticket",
                "neural tangent kernel",
                "ntk",
                "过参数化",
                "双下降",
                "彩票假说",
                "核回归",
            ),
            "过参数化模型何时依靠隐式或显式正则实现泛化",
            "把网络宽度与正则强度成对比较，并要求复杂模型在严格样本外、跨种子和线性基线对照中证明增量，防止把插值训练误当成有效学习",
        ),
        (
            (
                "differentiable ranks",
                "differentiable sorting",
                "soft rank",
                "soft sort",
                "软秩",
                "可微 rank",
                "可微 spearman",
            ),
            "把排序与 RankIC 目标变成可微优化问题的方法",
            "比较软排序损失相对 MSE 的截面排序增量，同时审查温度、近似偏差和计算成本，只有稳定改善样本外 RankIC 时才采用",
        ),
        (
            (
                "scaling laws",
                "compute-optimal",
                "emergent abilities",
                "emergent",
                "chinchilla",
                "规模律",
                "涌现",
            ),
            "模型规模、数据量、计算预算与度量口径之间的关系",
            "把大模型领域的规模规律作为待检验假设而非金融结论，验证容量增加是否在固定数据和试验预算下带来连续、可复现的 IC 增量，并排除度量阈值制造的“涌现”假象",
        ),
        (
            (
                "long short-term memory",
                "attention is all you need",
                "graph attention",
                "forecasting stock returns",
                "lstm",
                "transformer",
                "gat",
            ),
            "序列或关系结构的神经网络归纳偏置",
            "把架构当作表达能力候选，在统一特征、参数量和训练预算下与线性及 MLP 基线比较；只有跨时期和跨种子增量稳定时才保留额外复杂度",
        ),
        (
            ("self-normalizing", "selu", "normalization", "自归一化"),
            "激活尺度与归一化机制对训练稳定性的影响",
            "减少噪声 batch 统计对截面预测的扰动，并用激活分布、梯度尺度和跨种子 IC 检查自归一化是否真的改善低信噪比训练",
        ),
        (
            ("git re-basin", "permutation symmetries", "permutation symmetry", "排列对齐"),
            "神经网络参数置换对称性与模型对齐",
            "在比较权重路径或合并多个种子前先消除神经元排列差异，避免把纯参数重标记误诊为不同解盆地或错误判断集成互补性",
        ),
        (
            (
                "systematic strategies decay",
                "market efficiency in the age",
                "chinese stock market",
                "factor decay",
                "策略衰减",
                "拥挤",
            ),
            "因子可预测性随市场、拥挤和套利活动变化的外部有效性",
            "把截面预测力拆成市场阶段、股票池和时间衰减，并据此调整因子的上线寿命、容量预期与再训练频率",
        ),
        (
            ("sharpe ratio", "haircut sharpe", "how to use the sharpe"),
            "风险调整收益的估计误差与可比口径",
            "把 Sharpe 与样本长度、非独立收益和模型选择次数一起解释，避免用未经校正的单一比率决定策略是否通过研究门槛",
        ),
        (
            (
                "deflated sharpe",
                "probability of backtest overfitting",
                "data snooping",
                "multiple testing",
                "false discovery",
                "reality check",
                "回测过拟合",
                "多重检验",
            ),
            "模型搜索和重复回测造成的选择偏差",
            "按候选试验数量校正显著性与绩效，并据此下调偶然最优模型的可信度，避免把搜索红利误当成可复现 alpha",
        ),
        (
            ("purged", "embargo", "cross-validation", "cross validation", "时序切分"),
            "时间序列交叉验证中的标签重叠与信息泄漏",
            "设置 purging、embargo 和时序隔离的验证边界，使训练样本不会通过重叠持有期污染验证结果",
        ),
        (
            (
                "backtesting protocol",
                "pitfall",
                "researcher degrees of freedom",
                "reproducib",
                "backtest",
                "回测协议",
                "研究自由度",
            ),
            "回测流程中的研究自由度、数据复用与可复现性风险",
            "把回测从结果展示改造成可审查的决策流程：冻结样本与规则、记录试验路径，并在关键协议违规时拒绝发布结论",
        ),
        (
            ("concept drift", "data drift", "cusum", "ewma", "population stability", "漂移"),
            "分布变化和结构突变的在线检测",
            "把特征、预测与残差的变化转成预警和复核条件，区分暂时波动与需要降权、重训或停用的结构性失效",
        ),
        (
            ("market regime", "adaptive markets", "regime", "市场状态", "状态切换"),
            "市场状态变化下信号有效性的条件性",
            "分状态比较 IC、换手与收益来源，避免用全样本平均值掩盖只在单一行情成立的因子，并据此限定上线条件",
        ),
        (
            (
                "information coefficient",
                "rank ic",
                "factor return",
                "factor premium",
                "cross-section",
                "cross-sectional",
                "cross sectional",
                "因子",
            ),
            "截面信号的预测力、排序稳定性与增量解释",
            "用 IC/RankIC、分组单调性和跨样本稳定性判断信号是否提供独立 alpha，而不是只看某一回测区间的收益",
        ),
        (
            ("transaction cost", "turnover", "market impact", "交易成本", "换手"),
            "换手、冲击成本与净收益之间的约束",
            "把毛 IC 或毛收益换算为可交易的净效应，并在成本敏感性过高时降低因子容量预期或否决部署",
        ),
        (
            (
                "sharpness",
                "sharp minima",
                "flat minim",
                "loss landscape",
                "sam ",
                "sharpness-aware",
                "平坦",
            ),
            "损失景观几何与样本外泛化之间的关系",
            "解释优化器为什么会影响低信噪比训练的跨种子稳定性，并用验证 IC 与表示一致性复核“更平坦”是否真的转化为可交易增量",
        ),
        (
            ("mode connectivity", "model soup", "ensemble", "集成", "连通"),
            "不同训练解之间的连通性与集成互补性",
            "判断多个模型究竟提供独立信号还是同一解的重复采样，从而决定应做权重平均、预测集成，还是先处理失败模式",
        ),
        (
            ("label noise", "noisy label", "censor", "missing", "winsor", "噪声标签", "缺失值"),
            "标签噪声、删失与异常观测对监督学习的影响",
            "约束目标构造、样本清洗和稳健损失的选择，并用敏感性实验确认清洗规则没有制造虚假截面信号",
        ),
        (
            ("representation collapse", "embedding", "transformer", "normalization", "表征坍缩"),
            "低信噪比输入的表征学习与坍缩风险",
            "选择嵌入和归一化结构，并通过跨种子表示、有效秩与样本外 IC 联合诊断模型是否只记住噪声",
        ),
        (
            ("time series", "temporal", "wavelet", "rocket", "frequency", "时序", "序列", "小波", "频域"),
            "历史序列中的多尺度、频域或局部形态信息",
            "比较序列压缩方法能否在统一维度预算下保留稳定预测信息，并用滚动样本外结果决定复杂时序编码是否值得采用",
        ),
        (
            ("pac-bayes", "pac bayes", "cold posterior", "bayesian", "posterior"),
            "模型复杂度、不确定性与泛化界之间的联系",
            "把容量控制和后验不确定性纳入模型比较，避免仅凭训练损失为更复杂网络赋予优势",
        ),
        (
            ("random seed", "seed", "随机种子", "种子稳定"),
            "随机初始化带来的结果方差与报告偏差",
            "要求多种子训练并同时报告均值、离散度和尾部失败，从而区分稳定增量与挑中幸运种子的偶然结果",
        ),
    )
    focus = "相邻研究语境中的模型假设、样本条件与验证口径"
    quant_use = (
        "把论文观点落实为可复核的模型选择或诊断条件，并结合样本外表现判断该条件是否足以改变当前研究决策"
    )
    for signals, candidate_focus, candidate_use in rules:
        if any(signal in material for signal in signals):
            focus = candidate_focus
            quant_use = candidate_use
            break
    if relation_kind == "contrasts":
        quant_use = f"把它作为对照边界，{quant_use}"
    elif relation_semantics == "associated_method_origin" or relation_kind == "method_uses":
        quant_use = f"把原论文的方法定义转成当前专题的可执行步骤，并{quant_use}"
    research_location = f"{research_title} / {document_title}"
    if historical_mapping:
        return (
            f"历史研究语境借《{title}》讨论{focus}。"
            f"当前将这条方法与主题脉络归入“{research_location}”，具体用于{quant_use}。"
        )
    return (
        f"《{title}》在这里提供关于{focus}的研究依据。"
        f"在“{research_location}”中，这一观点用于{quant_use}。"
    )


class EvidenceQueryService:
    """Evidence 的只读查询边界；返回受控 URL，不泄露本地文件路径。"""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.resource_store = EvidenceResourceStore(settings)
        self.citation_overlays = CitationOverlayRegistry(settings)

    def _archive_link_index(self) -> dict[str, dict[str, Any]]:
        if (
            not self.settings.archive_database_path.is_file()
            or not self.settings.database_path.is_file()
        ):
            return {}
        try:
            return ArchiveCatalog(self.settings).archive_link_index()
        except (FileNotFoundError, sqlite3.DatabaseError):
            # Evidence 单域测试和尚未完成 Archive 初始化的隔离运行没有可解析页面。
            # 此时保持关系数据可见，但绝不退回裸 JSON API 伪装成原文链接。
            return {}

    @staticmethod
    def _present_archive_relations(
        rows: list[Any],
        archive_index: dict[str, dict[str, Any]],
        *,
        core_only: bool = False,
        paper_title: str = "",
    ) -> list[dict[str, object]]:
        landings = _published_research_landings(archive_index)
        candidates: list[dict[str, object]] = []
        for item in rows:
            relation_kind = str(item["relation_kind"])
            relation_semantics = str(item["relation_semantics"])
            occurrence_type = str(item["occurrence_type"])
            label, description, rank, is_core = _relation_presentation(
                relation_kind, relation_semantics, occurrence_type
            )
            canonical_path = str(item["canonical_path"])
            source_path = str(item["source_path"])
            current_target = archive_index.get(canonical_path) or archive_index.get(
                source_path
            )
            target_source_path = (
                str(current_target.get("source_path") or "").strip()
                if current_target is not None
                else ""
            )
            exact_current_target = current_target is not None and (
                not target_source_path
                or target_source_path in {canonical_path, source_path}
            )
            aliased_current_target = (
                current_target if current_target is not None and not exact_current_target else None
            )
            citation_id = str(item["citation_id"])
            context = _clean_archive_context(item["context_text"])
            research_urn = str(item["research_urn"])
            landing_slug = _historical_relation_landing_slug(
                research_urn=research_urn,
                paper_title=paper_title,
                context=context,
            )
            landing = landings.get(landing_slug)
            historical_target = (
                _historical_relation_document(
                    archive_index,
                    paper_title=paper_title,
                    context=context,
                )
                if current_target is None and paper_title.strip()
                else None
            )
            target = current_target or historical_target
            # Retired TeX/PDF/backup paths are provenance, not destinations.
            # A matched historical relation points at the concrete current
            # document anchor, but never claims the retired line maps to a
            # current section or citation occurrence.
            source_url = None
            source_resolution = "unpublished_history"
            research_title = (
                str(landing["research_title"])
                if landing is not None
                else "量化研究专题"
            )
            document_title = ""
            research_key = str(item["research_urn"])
            document_key = "unpublished-history"
            if landing is not None:
                research_key = str(landing["research_id"])
            if target is not None:
                research_title = str(target["research_title"])
                document_title = str(target["title"])
                research_key = str(target["research_id"])
                document_key = str(target["document_id"])
                document_url = (
                    f"/research/{target['research_id']}/documents/{target['document_id']}"
                )
            line_start = int(item["line_start"])
            source_link_label = "查看相关研究文档"
            source_section_title = None
            source_location = None
            historical_mapping = (
                historical_target is not None or aliased_current_target is not None
            )
            if exact_current_target:
                source_anchor, source_link_label, source_section_title = (
                    _archive_source_anchor(current_target, line_start)
                )
                source_url = f"{document_url}#{source_anchor}"
                source_resolution = "current_archive_document"
                source_location = f"原文第 {line_start} 行"
            elif target is not None:
                historical_section = _historical_relation_section(
                    target,
                    paper_title=paper_title,
                    context=context,
                )
                if historical_section is None:
                    source_url = f"{document_url}#document-{target['document_id']}"
                else:
                    source_url = f"{document_url}#{historical_section[0]}"
                    source_section_title = historical_section[1]
                    source_link_label = "查看相关研究章节"
                # A curated source-path alias resolves to a current, published
                # document, but its retired line number is not reused.  Only an
                # explicit semantic section match may supply an anchor.
                source_resolution = (
                    "current_archive_document"
                    if aliased_current_target is not None
                    else "historical_research_document"
                )
                if is_core:
                    label = "历史方法脉络"
                elif label == "正式参考文献":
                    label = "历史参考脉络"
            contextual_description = _research_usage_description(
                paper_title=paper_title,
                context=context,
                research_title=research_title,
                document_title=document_title,
                relation_kind=relation_kind,
                relation_semantics=relation_semantics,
                historical_mapping=historical_mapping,
            )
            candidates.append(
                {
                    "relation_id": str(item["relation_id"]),
                    "research_title": research_title,
                    "document_title": document_title or "研究文档",
                    "relation_label": label,
                    "usage_description": contextual_description,
                    "source_excerpt": context,
                    "source_url": source_url,
                    "source_resolution": source_resolution,
                    "source_link_label": source_link_label,
                    "source_section_title": source_section_title,
                    "source_location": source_location,
                    "citation_id": citation_id,
                    "citation_api_url": f"/api/v1/evidence/citations/{citation_id}",
                    "citation_url": f"/api/v1/evidence/citations/{citation_id}",
                    # 以下字段只属于内部证据投影；researcher_paper_detail
                    # 通过显式白名单将其排除在公开 HTML/API 之外。
                    "research_urn": str(item["research_urn"]),
                    "document_version_urn": str(item["document_version_urn"]),
                    "ledger_entry_id": str(item["ledger_entry_id"]),
                    "relation_kind": relation_kind,
                    "relation_semantics": relation_semantics,
                    "occurrence_type": occurrence_type,
                    "canonical_path": canonical_path,
                    "rank": rank,
                    "is_core": is_core,
                    "research_key": research_key,
                    "document_key": document_key,
                    "line_start": line_start,
                }
            )

        # 同一原文位置可能同时登记 title、URL、arXiv ID 与 bibliography；这些是
        # 证据账本的不同检测信号，不应在研究员界面重复成四条“关系”。
        deduplicated: dict[tuple[str, str, int], dict[str, object]] = {}
        for item in candidates:
            key = (
                str(item["research_key"]),
                str(item["document_key"]),
                int(item["line_start"]),
            )
            existing = deduplicated.get(key)
            if existing is None or int(item["rank"]) > int(existing["rank"]):
                deduplicated[key] = item

        by_document: dict[tuple[str, str], list[dict[str, object]]] = {}
        for item in deduplicated.values():
            key = (str(item["research_key"]), str(item["document_key"]))
            by_document.setdefault(key, []).append(item)

        selected: list[dict[str, object]] = []
        for items in by_document.values():
            core = [
                item
                for item in items
                if bool(item["is_core"])
                and (not core_only or bool(item["source_url"]))
            ]
            if core_only and not core:
                continue
            pool = core or sorted(
                items, key=lambda item: (-int(item["rank"]), int(item["line_start"]))
            )[:1]
            # 一个文档只保留最能解释实际用法的少量位置，防止参考文献检测信号
            # 再次淹没研究内容。不同文档仍分别保留，不破坏跨专题关系。
            pool = sorted(
                pool, key=lambda item: (-int(item["rank"]), int(item["line_start"]))
            )[:4]
            selected.extend(pool)

        selected.sort(
            key=lambda item: (
                item.get("source_resolution") != "current_archive_document",
                -int(item["rank"]),
                str(item["research_title"]),
                str(item["document_title"]),
                int(item["line_start"]),
            )
        )
        # Backup/version directories can contribute dozens of byte-distinct
        # ledger rows for the same visible statement.  Collapse those version
        # families by their normalized excerpt (or title when no excerpt exists)
        # and keep a small research-facing set, prioritising the current Archive.
        compacted: list[dict[str, object]] = []
        seen_families: set[tuple[str, str, str, str, str, str]] = set()
        for item in selected:
            excerpt_key = re.sub(
                r"\s+", " ", str(item.get("source_excerpt") or "")
            ).strip().casefold()
            title_key = re.sub(
                r"\b(?:research\s+paper|backup|copy|version|v\d+)\b|[_-]+",
                " ",
                str(item.get("document_title") or ""),
                flags=re.I,
            )
            title_key = re.sub(r"\s+", " ", title_key).strip().casefold()
            current = item.get("source_resolution") == "current_archive_document"
            family = (
                "current" if current else "historical",
                str(item.get("research_title") or "") if current else "",
                str(item.get("document_key") or item.get("document_title") or "")
                if current
                else "",
                str(item.get("line_start") or "") if current else "",
                str(item.get("relation_label") or ""),
                excerpt_key or title_key,
            )
            if family in seen_families:
                continue
            seen_families.add(family)
            compacted.append(item)
            if len(compacted) >= 6:
                break
        for item in compacted:
            for private in (
                "rank",
                "is_core",
                "research_key",
                "document_key",
                "line_start",
            ):
                item.pop(private, None)
        return compacted

    @classmethod
    def _select_display_archive_relations(
        cls,
        rows: list[Any],
        archive_index: dict[str, dict[str, Any]],
        *,
        paper_title: str = "",
    ) -> tuple[list[dict[str, object]], list[dict[str, object]], str]:
        """Select at most six semantic relations without backup-version noise."""

        relations = cls._present_archive_relations(
            rows, archive_index, paper_title=paper_title
        )
        core = cls._present_archive_relations(
            rows, archive_index, core_only=True, paper_title=paper_title
        )
        current_core = [
            item
            for item in core
            if item.get("source_resolution") == "current_archive_document"
        ]
        if current_core:
            return current_core, [], "core_current_archive"
        current_relations = [
            item
            for item in relations
            if item.get("source_resolution") == "current_archive_document"
        ]
        current_references = cls._select_archive_reference_relations(
            current_relations
        )
        if current_references:
            return [], current_references, "formal_reference_current_archive"
        historical_core = [
            item
            for item in core
            if item.get("source_resolution") == "historical_research_document"
        ]
        if historical_core:
            return historical_core, [], "core_historical_research_document"
        historical_references = cls._select_archive_reference_relations(
            [
                item
                for item in relations
                if item.get("source_resolution") == "historical_research_document"
            ]
        )
        if historical_references:
            return (
                [],
                historical_references,
                "formal_reference_historical_research_document",
            )
        return [], [], "none"

    @staticmethod
    def _select_archive_reference_relations(
        relations: list[dict[str, object]], *, limit: int = 6
    ) -> list[dict[str, object]]:
        """选择可跳转的正式引用作为“核心关系缺失”时的诚实降级展示。

        该选择不会把 bibliography/参考文献登记升级成核心论据，只解决已有、
        可定位的 Archive 关系被详情模板完全隐藏的问题。历史副本、无公开页面
        的位置和纯身份标记均不进入阅读页。
        """

        if limit < 1:
            return []
        selected: list[dict[str, object]] = []
        seen: set[tuple[str, str, str]] = set()
        for relation in relations:
            if (
                relation.get("relation_label")
                not in {"正式参考文献", "历史参考脉络"}
                or not relation.get("source_url")
            ):
                continue
            key = (
                str(relation.get("research_title") or ""),
                str(relation.get("document_title") or ""),
                str(relation.get("source_excerpt") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            selected.append({**relation, "display_scope": "formal_reference_only"})
            if len(selected) >= limit:
                break
        return selected

    @staticmethod
    def _archive_relation_rows_by_paper(
        connection: Any, paper_ids: set[str]
    ) -> dict[str, list[Any]]:
        """一次读取论文关系，并保持与详情页完全相同的关系来源集合。"""

        if not paper_ids:
            return {}
        ordered = sorted(paper_ids)
        placeholders = ",".join("?" for _ in ordered)
        rows = connection.execute(
            f"""
            WITH relations AS (
                SELECT paper_id,relation_id,research_urn,document_version_urn,
                       citation_id,ledger_entry_id,relation_kind,
                       'formal_or_direct' AS relation_semantics
                FROM research_paper_relation
                WHERE paper_id IN ({placeholders})
                UNION ALL
                SELECT association.paper_id,
                       association.associated_relation_id AS relation_id,
                       ledger.research_urn,ledger.document_version_urn,
                       association.citation_id,association.ledger_entry_id,
                       association.association_kind AS relation_kind,
                       'associated_method_origin' AS relation_semantics
                FROM evidence_associated_method_relation AS association
                JOIN citation_ledger_entry AS ledger USING(ledger_entry_id)
                WHERE association.paper_id IN ({placeholders})
            )
            SELECT relations.*,ledger.source_path,ledger.canonical_path,
                   ledger.locator_claim,ledger.occurrence_type,
                   occurrence.line_start,occurrence.line_end,
                   occurrence.context_text,occurrence.raw_marker_text
            FROM relations
            JOIN citation_ledger_entry AS ledger USING(ledger_entry_id)
            JOIN citation_occurrence AS occurrence USING(citation_id)
            ORDER BY relations.paper_id,relations.research_urn,
                     ledger.canonical_path,occurrence.line_start,
                     relations.ledger_entry_id
            """,
            (*ordered, *ordered),
        ).fetchall()
        grouped: dict[str, list[Any]] = {paper_id: [] for paper_id in ordered}
        for row in rows:
            grouped[str(row["paper_id"])].append(row)
        return grouped

    def _displayable_archive_relation_coverage(
        self, connection: Any, paper_ids: set[str]
    ) -> dict[str, bool]:
        """返回详情页实际能展示、能跳到 Archive 原文的关系覆盖。"""

        relation_rows = self._archive_relation_rows_by_paper(connection, paper_ids)
        archive_index = self._archive_link_index()
        if paper_ids:
            placeholders = ",".join("?" for _ in paper_ids)
            ordered = sorted(paper_ids)
            paper_titles = {
                str(row["paper_id"]): str(row["title"] or "")
                for row in connection.execute(
                    f"""
                    SELECT paper_id,title
                    FROM paper_catalog_projection
                    WHERE paper_id IN ({placeholders})
                    """,
                    ordered,
                )
            }
        else:
            paper_titles = {}
        coverage: dict[str, bool] = {}
        for paper_id in paper_ids:
            rows = relation_rows.get(paper_id, [])
            core, references, _scope = self._select_display_archive_relations(
                rows,
                archive_index,
                paper_title=paper_titles.get(paper_id, ""),
            )
            coverage[paper_id] = bool(core or references)
        return coverage

    def list_papers(
        self, *, limit: int = 100, offset: int = 0, include_candidates: bool = False
    ) -> dict[str, object]:
        if not 1 <= limit <= 500 or offset < 0:
            raise ValueError("paper pagination is outside the supported range")
        with evidence_connection(self.settings) as connection:
            rows = connection.execute(
                """
                SELECT paper.paper_id,paper.canonical_urn,catalog.title,
                       catalog.publication_date,catalog.authors_json,
                       catalog.categories_json,catalog.verification_status,
                       catalog.local_resources_json,
                       EXISTS(
                           SELECT 1 FROM paper_external_link AS external_link
                           WHERE external_link.paper_id=paper.paper_id
                       ) AS has_external_original,
                       EXISTS(
                           SELECT 1 FROM paper_resource AS resource
                           WHERE resource.paper_id=paper.paper_id
                             AND resource.verification_status='verified'
                       ) OR EXISTS(
                           SELECT 1
                           FROM evidence_canonical_resource_attachment AS attachment
                           JOIN paper_resource AS resource USING(resource_id)
                           WHERE attachment.paper_id=paper.paper_id
                             AND resource.verification_status='verified'
                       ) AS has_local_original,
                       EXISTS(
                           SELECT 1 FROM evidence_excerpt AS excerpt
                           WHERE excerpt.paper_id=paper.paper_id
                       ) AS has_abstract_evidence,
                       EXISTS(
                           SELECT 1 FROM paper_core_conclusion AS conclusion
                           WHERE conclusion.paper_id=paper.paper_id
                       ) AS has_core_conclusions,
                       institution.resolution_status AS institution_resolution_status
                FROM paper
                LEFT JOIN paper_catalog_projection AS catalog USING(paper_id)
                LEFT JOIN paper_institution_resolution AS institution USING(paper_id)
                ORDER BY COALESCE(catalog.publication_date,''),paper.paper_id
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
            displayable_archive_relations = (
                self._displayable_archive_relation_coverage(
                    connection, {str(row["paper_id"]) for row in rows}
                )
            )
            enrichment_by_paper: dict[str, Any] = {}
            if _table_exists(connection, "evidence_substantive_enrichment"):
                enrichment_by_paper = {
                    str(item["paper_id"]): item
                    for item in connection.execute(
                        """
                        SELECT paper_id,institutions_json,abstract_text,
                               core_conclusion_text,local_pdf_relative_path,
                               local_pdf_sha256,local_pdf_bytes
                        FROM evidence_substantive_enrichment
                        """
                    )
                }
            papers = []
            for row in rows:
                paper_id = str(row["paper_id"])
                enrichment = enrichment_by_paper.get(paper_id)
                dossier_coverage = {
                    "external_original": bool(row["has_external_original"]),
                    "local_original": bool(row["has_local_original"])
                    or bool(enrichment and enrichment["local_pdf_relative_path"]),
                    "abstract_evidence": bool(row["has_abstract_evidence"])
                    or bool(enrichment and enrichment["abstract_text"]),
                    "core_conclusions": bool(row["has_core_conclusions"])
                    or bool(enrichment and enrichment["core_conclusion_text"]),
                    "archive_relations": displayable_archive_relations.get(
                        paper_id, False
                    ),
                }
                dossier_coverage["complete"] = all(dossier_coverage.values())
                dossier_coverage["missing"] = [
                    key
                    for key, present in dossier_coverage.items()
                    if key != "complete" and not present
                ]
                papers.append({
                    "paper_id": paper_id,
                    "canonical_urn": str(row["canonical_urn"]),
                    "title": row["title"],
                    "publication_date": row["publication_date"],
                    "authors": _json(row["authors_json"]) if row["authors_json"] else [],
                    "categories": _json(row["categories_json"]) if row["categories_json"] else [],
                    "verification_status": row["verification_status"] or "partial",
                    "institution_resolution_status": (
                        "verified"
                        if enrichment is not None
                        and bool(_json(enrichment["institutions_json"]))
                        else str(row["institution_resolution_status"])
                        if row["institution_resolution_status"] is not None
                        else "unresolved"
                    ),
                    "local_resources": _json(row["local_resources_json"])
                    if row["local_resources_json"]
                    else [],
                    "detail_url": f"/evidence/papers/{row['paper_id']}",
                    "api_url": f"/api/v1/evidence/papers/{row['paper_id']}",
                    "dossier_coverage": dossier_coverage,
                })
            candidates: list[dict[str, object]] = []
            if include_candidates:
                candidates = [
                    {
                        "candidate_id": str(row["candidate_id"]),
                        "source_candidate_id": str(row["source_candidate_id"]),
                        "candidate_kind": str(row["candidate_kind"]),
                        "title_claim": row["title_claim"],
                        "publication_year": row["publication_year"],
                        "resolution_status": str(row["effective_status"]),
                        "source_resolution_status": str(row["resolution_status"]),
                    }
                    for row in connection.execute(
                        """
                        SELECT candidate.candidate_id,clue.source_candidate_id,
                               candidate.candidate_kind,candidate.title_claim,
                               candidate.publication_year,candidate.resolution_status,
                               CASE WHEN EXISTS (
                                   SELECT 1
                                   FROM evidence_canonicalization_receipt AS receipt
                                   WHERE receipt.paper_source_candidate_id=clue.source_candidate_id
                               ) THEN 'canonicalized'
                               ELSE candidate.resolution_status END AS effective_status
                        FROM paper_candidate AS candidate
                        JOIN paper_clue_candidate AS link USING(candidate_id)
                        JOIN paper_clue AS clue USING(clue_id)
                        WHERE link.link_kind='local_claim'
                        ORDER BY clue.source_candidate_id
                        LIMIT ? OFFSET ?
                        """,
                        (limit, offset),
                    )
                ]
            total = int(connection.execute("SELECT count(*) FROM paper").fetchone()[0])
            candidate_counts = {
                str(row["effective_status"]): int(row["count"])
                for row in connection.execute(
                    """
                    SELECT CASE WHEN EXISTS (
                        SELECT 1
                        FROM evidence_canonicalization_receipt AS receipt
                        JOIN paper_clue AS receipt_clue
                          ON receipt_clue.source_candidate_id=receipt.paper_source_candidate_id
                        JOIN paper_clue_candidate AS receipt_link
                          ON receipt_link.clue_id=receipt_clue.clue_id
                        WHERE receipt_link.candidate_id=candidate.candidate_id
                    ) THEN 'canonicalized' ELSE candidate.resolution_status END AS effective_status,
                    count(*) AS count
                    FROM paper_candidate AS candidate GROUP BY effective_status
                    """
                )
            }
            binding_counts = {
                str(row["binding_status"]): int(row["count"])
                for row in connection.execute(
                    """
                    SELECT binding.binding_status,count(*) AS count
                    FROM citation_binding_projection AS projection
                    JOIN citation_binding AS binding USING(binding_id)
                    GROUP BY binding.binding_status
                    """
                )
            }
            citation_total = int(
                connection.execute("SELECT count(*) FROM citation_ledger_entry").fetchone()[0]
            )
            resource_row = connection.execute(
                """
                SELECT count(DISTINCT resource_id) AS resources,
                       count(DISTINCT paper_id) AS papers
                FROM (
                    SELECT resource.resource_id,resource.paper_id
                    FROM paper_resource AS resource
                    WHERE resource.verification_status='verified'
                      AND resource.paper_id IS NOT NULL
                    UNION ALL
                    SELECT resource.resource_id,attachment.paper_id
                    FROM evidence_canonical_resource_attachment AS attachment
                    JOIN paper_resource AS resource USING(resource_id)
                    WHERE resource.verification_status='verified'
                )
                """
            ).fetchone()
            enriched_resource_papers = sum(
                bool(item["local_pdf_relative_path"])
                for item in enrichment_by_paper.values()
            )
            associated_row = connection.execute(
                """
                SELECT count(DISTINCT paper_id) AS papers,
                       count(DISTINCT ledger_entry_id) AS ledger_occurrences
                FROM evidence_associated_method_relation
                """
            ).fetchone()
            coverage = {
                "canonical_papers": total,
                "candidate_clues": sum(candidate_counts.values()),
                "open_candidate_clues": sum(
                    count
                    for status, count in candidate_counts.items()
                    if status != "canonicalized"
                ),
                "canonicalized_candidates": candidate_counts.get("canonicalized", 0),
                "candidate_statuses": candidate_counts,
                "citation_entries": citation_total,
                "citation_binding_statuses": binding_counts,
                "resolved_citations": binding_counts.get("resolved", 0),
                "associated_method_origins": int(associated_row["papers"]),
                "associated_method_origin_ledger_occurrences": int(
                    associated_row["ledger_occurrences"]
                ),
                "verified_local_resources": int(resource_row["resources"]),
                "papers_with_local_resources": int(resource_row["papers"]),
                "papers_with_user_facing_local_pdfs": enriched_resource_papers,
            }
        return {
            "papers": papers,
            "candidates": candidates,
            "total": total,
            "coverage": coverage,
        }

    def paper_detail(self, paper_id: str) -> dict[str, object]:
        if not _LEDGER_ID_RE.fullmatch(paper_id):
            raise EvidenceQueryNotFound("paper not found")
        with evidence_connection(self.settings) as connection:
            row = connection.execute(
                """
                SELECT paper.paper_id,paper.canonical_urn,catalog.*
                FROM paper LEFT JOIN paper_catalog_projection AS catalog USING(paper_id)
                WHERE paper.paper_id=?
                """,
                (paper_id,),
            ).fetchone()
            if row is None:
                raise EvidenceQueryNotFound("paper not found")
            identifiers = [
                {
                    "scheme": str(item["scheme"]),
                    "value": str(item["normalized_value"]),
                    "status": str(item["assertion_status"]),
                }
                for item in connection.execute(
                    """
                    SELECT scheme,normalized_value,assertion_status
                    FROM paper_identifier_assertion WHERE paper_id=?
                    ORDER BY scheme,normalized_value
                    """,
                    (paper_id,),
                )
            ]
            venue_row = connection.execute(
                """
                SELECT assertion.value_json
                FROM canonical_metadata_selection AS selection
                JOIN metadata_assertion AS assertion USING(assertion_id)
                WHERE selection.paper_id=? AND selection.field_name='venue'
                ORDER BY selection.selected_at DESC,selection.selection_id DESC LIMIT 1
                """,
                (paper_id,),
            ).fetchone()
            venue = _json(venue_row["value_json"]) if venue_row is not None else None
            excerpts = [
                _present_excerpt_row(item)
                for item in connection.execute(
                    """
                    SELECT excerpt_id,excerpt_text,locator_json,excerpt_sha256,provenance_urn
                    FROM evidence_excerpt WHERE paper_id=? ORDER BY excerpt_id
                    """,
                    (paper_id,),
                )
            ]
            resources = [
                {
                    "resource_id": str(item["resource_id"]),
                    "media_type": str(item["media_type"]),
                    "sha256": str(item["content_sha256"]),
                    "bytes": int(item["bytes"]),
                    "rights_status": str(item["rights_status"]),
                    "url": f"/api/v1/evidence/resources/{item['resource_id']}",
                }
                for item in connection.execute(
                    """
                    SELECT DISTINCT resource.resource_id,resource.media_type,
                           resource.content_sha256,resource.bytes,resource.rights_status
                    FROM paper_resource AS resource
                    LEFT JOIN evidence_canonical_resource_attachment AS attachment
                      ON attachment.resource_id=resource.resource_id
                    WHERE (resource.paper_id=? OR attachment.paper_id=?)
                      AND resource.verification_status='verified'
                    ORDER BY resource.resource_id
                    """,
                    (paper_id, paper_id),
                )
            ]
            reading_tasks = [
                {
                    "reading_task_id": str(item["reading_task_id"]),
                    "input_snapshot_hash": str(item["input_snapshot_hash"]),
                    "objective": str(item["objective_text"]),
                    "required_outputs": _json(item["required_outputs_json"]),
                    "latest_attempt": item["latest_attempt"],
                    "latest_status": item["latest_status"] or "pending",
                }
                for item in connection.execute(
                    """
                    SELECT task.reading_task_id,task.input_snapshot_hash,
                           task.objective_text,task.required_outputs_json,
                           max(run.attempt_number) AS latest_attempt,
                           (SELECT result_status FROM paper_reading_run AS latest
                            WHERE latest.reading_task_id=task.reading_task_id
                            ORDER BY attempt_number DESC LIMIT 1) AS latest_status
                    FROM paper_reading_task AS task
                    LEFT JOIN paper_reading_run AS run USING(reading_task_id)
                    WHERE task.paper_id=? GROUP BY task.reading_task_id
                    ORDER BY task.reading_task_id
                    """,
                    (paper_id,),
                )
            ]
            metadata_reviews = [
                {
                    "analysis_id": str(item["analysis_id"]),
                    "analysis_kind": str(item["analysis_kind"]),
                    "text": str(item["analysis_text"]),
                    "summary": _analysis_summary(item["analysis_text"]),
                    "fact_status": str(item["fact_status"]),
                    "provenance_urn": str(item["provenance_urn"]),
                }
                for item in connection.execute(
                    """
                    SELECT analysis_id,analysis_kind,analysis_text,fact_status,provenance_urn
                    FROM paper_analysis WHERE paper_id=? ORDER BY analysis_id
                    """,
                    (paper_id,),
                )
            ]
            conclusion_evidence_by_text: dict[str, dict[str, object]] = {}
            for item in connection.execute(
                """
                SELECT conclusion.conclusion_text,evidence.claim_scope,
                       evidence.verification_status,excerpt.locator_json,
                       excerpt.excerpt_sha256
                FROM paper_core_conclusion AS conclusion
                JOIN paper_core_conclusion_evidence AS evidence USING(conclusion_id)
                JOIN evidence_excerpt AS excerpt USING(excerpt_id)
                WHERE conclusion.paper_id=?
                """,
                (paper_id,),
            ):
                locator = _json(item["locator_json"])
                if isinstance(locator, dict):
                    locator = {
                        **locator,
                        "support_text_sha256": str(item["excerpt_sha256"]),
                    }
                conclusion_evidence_by_text[str(item["conclusion_text"])] = {
                    "claim_scope": str(item["claim_scope"]),
                    "verification_status": str(item["verification_status"]),
                    "source_locator": locator,
                }
            category_assignments = [
                {
                    "category_key": str(item["category_key"]),
                    "display_name": str(item["display_name"]),
                    "is_primary": bool(item["is_primary"]),
                    "provenance_urn": str(item["provenance_urn"]),
                }
                for item in connection.execute(
                    """
                    SELECT category.category_key,category.display_name,detail.is_primary,
                           assignment.provenance_urn
                    FROM paper_category_assignment AS assignment
                    JOIN paper_category AS category USING(category_id)
                    LEFT JOIN paper_category_assignment_detail AS detail
                      ON detail.paper_id=assignment.paper_id
                     AND detail.category_id=assignment.category_id
                     AND detail.provenance_urn=assignment.provenance_urn
                    WHERE assignment.paper_id=?
                    ORDER BY detail.is_primary DESC,category.category_key
                    """,
                    (paper_id,),
                )
            ]
            category_evidence_row = connection.execute(
                """
                SELECT source_system,source_categories_json,primary_source_category,
                       mapping_policy_version,assertion_status,provenance_urn
                FROM paper_category_assertion WHERE paper_id=?
                """,
                (paper_id,),
            ).fetchone()
            category_evidence = (
                {
                    "source_system": str(category_evidence_row["source_system"]),
                    "source_categories": _json(
                        category_evidence_row["source_categories_json"]
                    ),
                    "mapped_category_fact_origin": (
                        (
                            _json(category_evidence_row["source_categories_json"])[0]
                            .get("mapping", {})
                            .get("fact_origin")
                        )
                        if _json(category_evidence_row["source_categories_json"])
                        else None
                    ),
                    "primary_source_category": str(
                        category_evidence_row["primary_source_category"]
                    ),
                    "mapping_policy_version": str(
                        category_evidence_row["mapping_policy_version"]
                    ),
                    "assertion_status": str(category_evidence_row["assertion_status"]),
                    "provenance_urn": str(category_evidence_row["provenance_urn"]),
                }
                if category_evidence_row is not None
                else None
            )
            institution_row = connection.execute(
                """
                SELECT resolution_status,institutions_json,reason_code,reason_text,
                       checked_source_fields_json,provenance_urn
                FROM paper_institution_resolution WHERE paper_id=?
                """,
                (paper_id,),
            ).fetchone()
            institution_resolution = (
                {
                    "status": str(institution_row["resolution_status"]),
                    "institutions": _json(institution_row["institutions_json"]),
                    "reason_code": str(institution_row["reason_code"]),
                    "reason": str(institution_row["reason_text"]),
                    "checked_source_fields": _json(
                        institution_row["checked_source_fields_json"]
                    ),
                    "provenance_urn": str(institution_row["provenance_urn"]),
                }
                if institution_row is not None
                else {
                    "status": "unresolved",
                    "institutions": [],
                    "reason_code": "resolution_record_absent",
                    "reason": "尚未生成机构核验记录。",
                    "checked_source_fields": [],
                    "provenance_urn": None,
                }
            )
            enrichment_row = (
                connection.execute(
                    """
                    SELECT * FROM evidence_substantive_enrichment WHERE paper_id=?
                    """,
                    (paper_id,),
                ).fetchone()
                if _table_exists(connection, "evidence_substantive_enrichment")
                else None
            )
            relation_rows = self._archive_relation_rows_by_paper(
                connection, {paper_id}
            ).get(paper_id, [])
            archive_index = self._archive_link_index()
            archive_relations = self._present_archive_relations(
                relation_rows, archive_index, paper_title=str(row["title"])
            )
            (
                archive_core_relations,
                archive_reference_relations,
                archive_relation_scope,
            ) = self._select_display_archive_relations(
                relation_rows, archive_index, paper_title=str(row["title"])
            )
        enrichment: dict[str, Any] | None = (
            {key: enrichment_row[key] for key in enrichment_row.keys()}
            if enrichment_row is not None
            else None
        )
        if enrichment is not None:
            enriched_institutions = _json(enrichment["institutions_json"])
            if isinstance(enriched_institutions, list) and enriched_institutions:
                institution_resolution = {
                    "status": "verified",
                    "institutions": enriched_institutions,
                    "reason_code": "substantive_enrichment_verified_sources",
                    "reason": "机构来自论文首页、作者署名元数据或可信书目元数据，并与本条 enrichment provenance 绑定。",
                    "checked_source_fields": [
                        _json(enrichment["institution_source_json"])
                    ],
                    "provenance_urn": str(enrichment["provenance_urn"]),
                }
            if not excerpts and enrichment.get("abstract_text"):
                abstract_text = str(enrichment["abstract_text"])
                abstract_sha256 = hashlib.sha256(
                    abstract_text.encode("utf-8")
                ).hexdigest()
                if abstract_sha256 != str(enrichment["abstract_sha256"]):
                    raise EvidencePresentationError(
                        "补充摘要文本与登记哈希不一致"
                    )
                abstract_source = _json(enrichment["abstract_source_json"])
                excerpts = [
                    {
                        "excerpt_id": f"enrichment:{paper_id}:abstract",
                        "text": abstract_text,
                        "locator": abstract_source,
                        "locator_presentation": _official_source_presentation(
                            abstract_source
                        ),
                        "sha256": abstract_sha256,
                        "provenance_urn": str(enrichment["provenance_urn"]),
                    }
                ]
            if enrichment.get("local_pdf_relative_path"):
                library_url = f"/evidence/library/{paper_id}.pdf"
                library_sha256 = str(enrichment["local_pdf_sha256"])
                if not any(str(item.get("sha256")) == library_sha256 for item in resources):
                    resources.append(
                        {
                            "resource_id": f"library:{paper_id}",
                            "media_type": "application/pdf",
                            "sha256": library_sha256,
                            "bytes": int(enrichment["local_pdf_bytes"]),
                            "rights_status": "local_research_copy_with_source_provenance",
                            "url": library_url,
                        }
                    )
        overlay_index = chinese_overlays_by_excerpt()
        paper_identifiers = {
            (str(item["scheme"]).casefold(), str(item["value"]))
            for item in identifiers
        }
        chinese_presentation: dict[str, Any] | None = None
        for excerpt in excerpts:
            overlay = overlay_index.get(str(excerpt["sha256"]))
            excerpt["chinese_presentation"] = overlay
            if overlay is None:
                continue
            if int(overlay["source_excerpt_bytes"]) != len(
                str(excerpt["text"]).encode("utf-8")
            ):
                raise EvidencePresentationError(
                    "中文 Evidence 展示层与当前官方摘要字节数不一致"
                )
            overlay_identity = (
                str(overlay["identifier_scheme"]).casefold(),
                str(overlay["normalized_identifier"]),
            )
            if overlay_identity not in paper_identifiers:
                raise EvidencePresentationError(
                    "中文 Evidence 展示层与当前论文强标识符不一致"
                )
            if str(overlay["title"]) != str(row["title"]):
                raise EvidencePresentationError(
                    "中文 Evidence 展示层与当前论文标题不一致"
                )
            locator = excerpt.get("locator")
            locator_source_path = None
            if isinstance(locator, dict):
                locator_source_path = (
                    locator.get("source_path")
                    or locator.get("cache_path")
                    or locator.get("artifact_path")
                )
            if (
                not isinstance(locator_source_path, str)
                or locator_source_path != str(overlay["source_path"])
            ):
                raise EvidencePresentationError(
                    "中文 Evidence 展示层与当前官方摘要来源路径不一致"
                )
            if chinese_presentation is None:
                chinese_presentation = overlay
        if chinese_presentation is None and enrichment is not None and excerpts:
            translation = enrichment.get("abstract_translation_zh")
            synthesis = enrichment.get("synthesis_zh")
            if translation and synthesis:
                chinese_presentation = {
                    "identifier_scheme": identifiers[0]["scheme"] if identifiers else "url",
                    "normalized_identifier": identifiers[0]["value"] if identifiers else paper_id,
                    "title": str(row["title"]),
                    "source_excerpt_sha256": str(excerpts[0]["sha256"]),
                    "source_excerpt_bytes": len(str(excerpts[0]["text"]).encode("utf-8")),
                    "source_path": str(enrichment["local_pdf_relative_path"] or "reviewed metadata"),
                    "abstract_translation_zh": str(translation),
                    "synthesis_zh": str(synthesis),
                    "translation_status": "generated_reference_translation",
                    "summary_status": "generated_research_aid_not_source_fact",
                    "fact_boundary": "上方英文摘要或论文摘要为来源证据；中文译文与综述仅用于阅读辅助，不扩大来源事实边界。",
                }
                # The detail template renders the translation beside its source
                # excerpt.  Keep the top-level compatibility field, but bind the
                # generated reading aid to the exact excerpt hash as well.
                excerpts[0]["chinese_presentation"] = chinese_presentation
        catalog_conclusions = (
            _json(row["core_conclusions_json"])
            if row["core_conclusions_json"]
            else []
        )
        if (
            not catalog_conclusions
            and enrichment is not None
            and enrichment.get("core_conclusion_text")
        ):
            source_locator = _json(enrichment["core_conclusion_source_json"])
            if isinstance(source_locator, dict):
                source_locator = {
                    **source_locator,
                    "support_text_sha256": str(enrichment["abstract_sha256"]),
                }
            catalog_conclusions = [
                {
                    "text": str(enrichment["core_conclusion_text"]),
                    "fact_status": "source_claim",
                    "evidence_scope": "reviewed_source_excerpt",
                    "claim_scope": str(
                        source_locator.get("claim_scope")
                        or "official_abstract_verbatim"
                    ),
                    "verification_status": "source_verified",
                    "provenance_urn": str(enrichment["provenance_urn"]),
                    "source_locator": source_locator,
                }
            ]
        for conclusion in catalog_conclusions:
            if isinstance(conclusion, dict):
                evidence = conclusion_evidence_by_text.get(
                    str(conclusion.get("text") or "")
                )
                if evidence is not None:
                    conclusion.setdefault("claim_scope", evidence["claim_scope"])
                    conclusion.setdefault(
                        "verification_status", evidence["verification_status"]
                    )
                    if not conclusion.get("source_locator"):
                        conclusion["source_locator"] = evidence["source_locator"]
                conclusion["source_locator_presentation"] = (
                    _conclusion_source_presentation(conclusion.get("source_locator"))
                )
        conclusion_scopes = {
            str(value.get("evidence_scope") or "")
            for value in catalog_conclusions
            if isinstance(value, dict)
        }
        if not catalog_conclusions:
            conclusion_boundary = "not_yet_available"
        elif conclusion_scopes == {"fulltext_reading"}:
            conclusion_boundary = "reviewed_fulltext_with_page_and_text_hash"
        elif conclusion_scopes == {"official_abstract"}:
            conclusion_boundary = "official_abstract_source_claim_not_fulltext_review"
        else:
            conclusion_boundary = "mixed_explicit_evidence_scopes"
        if chinese_presentation is not None:
            researcher_insight = build_researcher_insight(
                str(row["title"]),
                synthesis_zh=str(chinese_presentation.get("synthesis_zh") or ""),
                archive_relations=(
                    archive_core_relations or archive_reference_relations
                ),
                core_conclusions=catalog_conclusions,
            )
            chinese_presentation = {
                **chinese_presentation,
                "synthesis_zh": researcher_insight,
            }
            for excerpt in excerpts:
                excerpt_presentation = excerpt.get("chinese_presentation")
                if isinstance(excerpt_presentation, dict):
                    excerpt["chinese_presentation"] = {
                        **excerpt_presentation,
                        "synthesis_zh": researcher_insight,
                    }
        external_links = (
            _json(row["external_links_json"])
            if row["external_links_json"]
            else []
        )
        evidence_coverage = {
            "external_original": bool(external_links),
            "local_original": bool(resources),
            "abstract_evidence": bool(excerpts),
            "core_conclusions": bool(catalog_conclusions),
            "archive_relations": bool(
                archive_core_relations or archive_reference_relations
            ),
            "archive_relation_scope": archive_relation_scope,
        }
        return {
            "paper_id": str(row["paper_id"]),
            "canonical_urn": str(row["canonical_urn"]),
            "title": row["title"],
            "publication_date": row["publication_date"],
            "venue": venue,
            "authors": _json(row["authors_json"]) if row["authors_json"] else [],
            "institutions": institution_resolution["institutions"],
            "categories": _json(row["categories_json"]) if row["categories_json"] else [],
            "category_assignments": category_assignments,
            "category_evidence": category_evidence,
            "core_conclusions": catalog_conclusions,
            "external_links": external_links,
            "verification_status": row["verification_status"] or "partial",
            "institution_resolution": institution_resolution,
            "identifiers": identifiers,
            "abstract_excerpts": excerpts,
            "chinese_presentation": chinese_presentation,
            "local_resources": resources,
            "reading_tasks": reading_tasks,
            "metadata_reviews": metadata_reviews,
            "archive_relations": archive_relations,
            "archive_core_relations": archive_core_relations,
            "archive_reference_relations": archive_reference_relations,
            "archive_relation_scope": archive_relation_scope,
            "evidence_coverage": evidence_coverage,
            "fact_boundary": {
                "abstract_excerpts": "source_fact",
                "core_conclusions": conclusion_boundary,
                "institutions": str(institution_resolution["status"]),
                "catalog_verification": row["verification_status"] or "partial",
            },
        }

    def researcher_paper_detail(self, paper_id: str) -> dict[str, object]:
        """Return the explicit, researcher-facing paper view model.

        ``paper_detail`` remains the internal evidence/audit projection used by
        canonicalization and release verification.  Public HTML and the public
        detail API share this allow-listed model so adding an internal column
        can never leak it to researchers by accident.
        """

        detail = self.paper_detail(paper_id)

        venue_value = detail.get("venue")
        venue: dict[str, object] | None = None
        if isinstance(venue_value, dict):
            venue = {
                key: venue_value.get(key)
                for key in ("value", "volume", "issue", "pages")
                if venue_value.get(key) not in (None, "")
            }
        elif isinstance(venue_value, str) and venue_value.strip():
            venue = {"value": venue_value.strip()}

        authors: list[dict[str, object]] = []
        for value in detail.get("authors") or []:
            if not isinstance(value, dict):
                continue
            name = str(value.get("name") or "").strip()
            if not name:
                continue
            affiliations = value.get("affiliations")
            authors.append(
                {
                    "name": name,
                    "affiliations": [
                        str(item).strip()
                        for item in affiliations
                        if str(item).strip()
                    ]
                    if isinstance(affiliations, list)
                    else [],
                }
            )

        external_links: list[dict[str, str]] = []
        seen_external: set[str] = set()
        for value in detail.get("external_links") or []:
            if not isinstance(value, dict):
                continue
            url = str(value.get("url") or "").strip()
            if not url.startswith("https://") or url in seen_external:
                continue
            seen_external.add(url)
            external_links.append({"url": url})

        local_resources: list[dict[str, str]] = []
        seen_local: set[str] = set()
        for value in detail.get("local_resources") or []:
            if not isinstance(value, dict):
                continue
            url = str(value.get("url") or "").strip()
            if (
                not url.startswith(
                    ("/api/v1/evidence/resources/", "/evidence/library/")
                )
                or url in seen_local
            ):
                continue
            seen_local.add(url)
            local_resources.append({"url": url})

        excerpts: list[dict[str, object]] = []
        for value in detail.get("abstract_excerpts") or []:
            if not isinstance(value, dict):
                continue
            excerpt: dict[str, object] = {
                "text": _researcher_excerpt_text(value.get("text")),
            }
            chinese = value.get("chinese_presentation")
            if isinstance(chinese, dict) and chinese.get("abstract_translation_zh"):
                excerpt["chinese_presentation"] = {
                    "abstract_translation_zh": str(
                        chinese["abstract_translation_zh"]
                    ).strip()
                }
            excerpts.append(excerpt)

        conclusions = [
            {"text": _researcher_excerpt_text(value.get("text"))}
            for value in detail.get("core_conclusions") or []
            if isinstance(value, dict) and str(value.get("text") or "").strip()
        ]

        def present_relations(key: str) -> list[dict[str, object]]:
            result: list[dict[str, object]] = []
            for value in detail.get(key) or []:
                if not isinstance(value, dict):
                    continue
                source_url = str(value.get("source_url") or "").strip()
                if not source_url.startswith("/research/"):
                    continue
                result.append(
                    {
                        field: value.get(field)
                        for field in (
                            "research_title",
                            "document_title",
                            "relation_label",
                            "usage_description",
                            "source_excerpt",
                            "source_url",
                            "source_section_title",
                        )
                        if value.get(field) not in (None, "")
                    }
                )
            return result

        chinese_value = detail.get("chinese_presentation")
        chinese_presentation = None
        if isinstance(chinese_value, dict) and chinese_value.get("synthesis_zh"):
            chinese_presentation = {
                "synthesis_zh": str(chinese_value["synthesis_zh"]).strip()
            }

        coverage_value = detail.get("evidence_coverage")
        coverage_source = coverage_value if isinstance(coverage_value, dict) else {}
        evidence_coverage = {
            field: bool(coverage_source.get(field))
            for field in (
                "external_original",
                "local_original",
                "abstract_evidence",
                "core_conclusions",
                "archive_relations",
            )
        }
        archive_core_relations = present_relations("archive_core_relations")
        archive_reference_relations = present_relations(
            "archive_reference_relations"
        )
        archive_relation_scope = (
            "core"
            if archive_core_relations
            else "reference"
            if archive_reference_relations
            else "none"
        )
        return {
            "paper_id": str(detail["paper_id"]),
            "title": str(detail.get("title") or ""),
            "publication_date": detail.get("publication_date"),
            "venue": venue,
            "authors": authors,
            "institutions": [
                str(value).strip()
                for value in detail.get("institutions") or []
                if str(value).strip()
            ],
            "external_links": external_links,
            "local_resources": local_resources,
            "abstract_excerpts": excerpts,
            "core_conclusions": conclusions,
            "chinese_presentation": chinese_presentation,
            "archive_relations": present_relations("archive_relations"),
            "archive_core_relations": archive_core_relations,
            "archive_reference_relations": archive_reference_relations,
            "archive_relation_scope": archive_relation_scope,
            "evidence_coverage": evidence_coverage,
        }

    @staticmethod
    def _paper_summaries(
        connection: Any, paper_ids: set[str]
    ) -> dict[str, dict[str, object]]:
        if not paper_ids:
            return {}
        placeholders = ",".join("?" for _ in paper_ids)
        ordered = sorted(paper_ids)
        catalog_rows = connection.execute(
            f"""
            SELECT paper.paper_id,paper.canonical_urn,catalog.title,
                   catalog.publication_date,catalog.authors_json,
                   catalog.categories_json,catalog.verification_status,
                   catalog.external_links_json,catalog.local_resources_json
            FROM paper JOIN paper_catalog_projection AS catalog USING(paper_id)
            WHERE paper.paper_id IN ({placeholders}) ORDER BY paper.paper_id
            """,
            ordered,
        ).fetchall()
        summaries = {
            str(row["paper_id"]): {
                "paper_id": str(row["paper_id"]),
                "canonical_urn": str(row["canonical_urn"]),
                "title": str(row["title"]),
                "publication_date": row["publication_date"],
                "authors": _json(row["authors_json"]),
                "categories": _json(row["categories_json"]),
                "verification_status": str(row["verification_status"]),
                "external_links": _json(row["external_links_json"]),
                "local_resources": _json(row["local_resources_json"]),
                "evidence_excerpts": [],
                "detail_url": f"/evidence/papers/{row['paper_id']}",
                "api_url": f"/api/v1/evidence/papers/{row['paper_id']}",
            }
            for row in catalog_rows
        }
        excerpt_rows = connection.execute(
            f"""
            SELECT paper_id,excerpt_id,excerpt_text,locator_json,provenance_urn
            FROM evidence_excerpt WHERE paper_id IN ({placeholders})
            ORDER BY paper_id,excerpt_id
            """,
            ordered,
        ).fetchall()
        for row in excerpt_rows:
            text = str(row["excerpt_text"])
            summary = summaries.get(str(row["paper_id"]))
            if summary is None:
                continue
            excerpts = summary["evidence_excerpts"]
            assert isinstance(excerpts, list)
            excerpts.append(
                {
                    "excerpt_id": str(row["excerpt_id"]),
                    "text": text if len(text) <= 600 else text[:597] + "…",
                    "locator": _json(row["locator_json"]),
                    "fact_status": "source_fact",
                    "provenance_urn": str(row["provenance_urn"]),
                }
            )
        return summaries

    def citation_render_specs(self, document_sha256: str) -> tuple[CitationRenderSpec, ...]:
        if not _SHA256_RE.fullmatch(document_sha256):
            raise ValueError("document content_sha256 must be lowercase hexadecimal")
        with evidence_connection(self.settings) as connection:
            occurrences = connection.execute(
                """
                SELECT * FROM citation_occurrence
                WHERE document_sha256=?
                ORDER BY COALESCE(byte_start,0),citation_id
                """,
                (document_sha256,),
            ).fetchall()
            entry_rows = connection.execute(
                """
                SELECT ledger.citation_id,ledger.ledger_entry_id,
                       binding.binding_status,binding.paper_id
                FROM citation_ledger_entry AS ledger
                JOIN citation_occurrence AS occurrence USING(citation_id)
                LEFT JOIN citation_binding_projection AS projection
                  USING(ledger_entry_id)
                LEFT JOIN citation_binding AS binding USING(binding_id)
                WHERE occurrence.document_sha256=?
                ORDER BY ledger.citation_id,ledger.ledger_entry_id
                """,
                (document_sha256,),
            ).fetchall()
            entries_by_citation: dict[str, list[Any]] = {}
            for entry in entry_rows:
                entries_by_citation.setdefault(str(entry["citation_id"]), []).append(entry)
            result: list[CitationRenderSpec] = []
            for occurrence in occurrences:
                entries = entries_by_citation.get(str(occurrence["citation_id"]), [])
                statuses = [
                    str(item["binding_status"] or "unresolved") for item in entries
                ]
                result.append(
                    CitationRenderSpec(
                        citation_id=str(occurrence["citation_id"]),
                        document_sha256=document_sha256,
                        locator_kind=str(occurrence["locator_kind"]),
                        byte_start=occurrence["byte_start"],
                        byte_end=occurrence["byte_end"],
                        line_start=int(occurrence["line_start"]),
                        line_end=int(occurrence["line_end"]),
                        raw_marker_text=str(occurrence["raw_marker_text"]),
                        resolution_state=_resolution_state(
                            str(occurrence["locator_status"]), statuses
                        ),
                        ledger_entry_ids=tuple(str(item["ledger_entry_id"]) for item in entries),
                        paper_ids=tuple(
                            sorted(
                                {
                                    str(item["paper_id"])
                                    for item in entries
                                    if item["paper_id"] is not None
                                }
                            )
                        ),
                        detail_url=f"/api/v1/evidence/citations/{occurrence['citation_id']}",
                    )
                )
        for overlay in self.citation_overlays.for_document(document_sha256):
            paper_id = str(overlay.paper.get("paper_id") or "")
            result.append(
                CitationRenderSpec(
                    citation_id=overlay.citation_id,
                    document_sha256=document_sha256,
                    locator_kind="reviewed_utf8_projection",
                    byte_start=overlay.byte_start,
                    byte_end=overlay.byte_end,
                    line_start=overlay.line_number,
                    line_end=overlay.line_number,
                    raw_marker_text=overlay.marker,
                    resolution_state="valid",
                    ledger_entry_ids=(),
                    paper_ids=(paper_id,) if paper_id else (),
                    detail_url=f"/api/v1/evidence/citations/{overlay.citation_id}",
                )
            )
        return tuple(
            sorted(
                result,
                key=lambda item: (
                    int(item.byte_start or 0),
                    int(item.byte_end or 0),
                    item.citation_id,
                ),
            )
        )

    def citation_detail(self, citation_id: str) -> dict[str, object]:
        try:
            citation_id = validate_citation_id(citation_id)
        except ValueError as error:
            raise EvidenceQueryNotFound("citation not found") from error
        overlay = self.citation_overlays.detail(citation_id)
        if overlay is not None:
            return self._citation_overlay_detail(overlay)
        with evidence_connection(self.settings) as connection:
            occurrence = connection.execute(
                "SELECT * FROM citation_occurrence WHERE citation_id=?", (citation_id,)
            ).fetchone()
            if occurrence is None:
                raise EvidenceQueryNotFound("citation not found")
            entry_rows = connection.execute(
                    """
                    SELECT ledger.*,binding.binding_status,binding.rationale,binding.paper_id,
                           paper.canonical_urn,catalog.title AS paper_title
                    FROM citation_ledger_entry AS ledger
                    LEFT JOIN citation_binding_projection AS projection USING(ledger_entry_id)
                    LEFT JOIN citation_binding AS binding USING(binding_id)
                    LEFT JOIN paper ON paper.paper_id=binding.paper_id
                    LEFT JOIN paper_catalog_projection AS catalog ON catalog.paper_id=paper.paper_id
                    WHERE ledger.citation_id=? ORDER BY ledger.ledger_entry_id
                    """,
                    (citation_id,),
                ).fetchall()
            summaries = self._paper_summaries(
                connection,
                {str(item["paper_id"]) for item in entry_rows if item["paper_id"] is not None},
            )
            entries = [self._entry_dict(item, summaries) for item in entry_rows]
        statuses = [str(item["binding_status"]) for item in entries]
        return {
            "citation_id": citation_id,
            "document_sha256": str(occurrence["document_sha256"]),
            "locator_kind": str(occurrence["locator_kind"]),
            "locator": _json(occurrence["locator_json"]),
            "line_start": int(occurrence["line_start"]),
            "line_end": int(occurrence["line_end"]),
            "byte_start": occurrence["byte_start"],
            "byte_end": occurrence["byte_end"],
            "raw_marker_text": str(occurrence["raw_marker_text"]),
            "context_text": str(occurrence["context_text"]),
            "locator_status": str(occurrence["locator_status"]),
            "resolution_state": _resolution_state(
                str(occurrence["locator_status"]), statuses
            ),
            "entries": entries,
        }

    def _citation_overlay_detail(self, overlay: Any) -> dict[str, object]:
        paper_material = dict(overlay.paper)
        paper_id = str(paper_material.get("paper_id") or "")
        if paper_id:
            with evidence_connection(self.settings) as connection:
                row = connection.execute(
                    """
                    SELECT paper.canonical_urn,catalog.title
                    FROM paper JOIN paper_catalog_projection AS catalog USING(paper_id)
                    WHERE paper.paper_id=?
                    """,
                    (paper_id,),
                ).fetchone()
                if row is None:
                    raise EvidenceQueryNotFound("reviewed citation paper is not available")
                summaries = self._paper_summaries(connection, {paper_id})
            paper = {
                "paper_id": paper_id,
                "canonical_urn": str(row["canonical_urn"]),
                "title": str(row["title"]),
                "detail_url": f"/evidence/papers/{paper_id}",
                "api_url": f"/api/v1/evidence/papers/{paper_id}",
                "paper_summary": summaries.get(paper_id),
            }
        else:
            paper = {
                "paper_id": None,
                "canonical_urn": str(paper_material.get("canonical_urn") or ""),
                "title": str(paper_material["title"]),
                "detail_url": None,
                "api_url": None,
                "paper_summary": {
                    "title": str(paper_material["title"]),
                    "publication_date": paper_material.get("publication_date"),
                    "authors": [
                        {"name": str(name), "affiliations": []}
                        for name in paper_material.get("authors", [])
                    ],
                    "institutions": [],
                    "categories": list(paper_material.get("categories", [])),
                    "core_conclusions": [],
                    "verification_status": "verified",
                    "external_links": list(paper_material.get("external_links", [])),
                    "local_resources": [],
                    "evidence_excerpts": [],
                },
            }
        entry_id = f"overlay_{hashlib.sha256(overlay.citation_id.encode('ascii')).hexdigest()[:32]}"
        return {
            "citation_id": overlay.citation_id,
            "document_sha256": overlay.document_sha256,
            "locator_kind": "reviewed_utf8_projection",
            "locator": {
                "line": overlay.line_number,
                "source_path": overlay.source_path,
                "review_status": "reviewed_exact_author_year_projection",
            },
            "line_start": overlay.line_number,
            "line_end": overlay.line_number,
            "byte_start": overlay.byte_start,
            "byte_end": overlay.byte_end,
            "raw_marker_text": overlay.marker,
            "context_text": overlay.context_text,
            "locator_status": "valid",
            "resolution_state": "valid",
            "entries": [
                {
                    "ledger_entry_id": entry_id,
                    "research_urn": "qrh:archive:research:Q2_FACTORY_DESIGN",
                    "document_version_urn": (
                        f"qrh:archive:document-version:sha256:{overlay.document_sha256}"
                    ),
                    "source_path": overlay.source_path,
                    "canonical_path": overlay.source_path,
                    "locator_claim": f"line:{overlay.line_number}",
                    "occurrence_type": "textual_author_year_mention",
                    "entry_status": "resolved",
                    "binding_status": "resolved",
                    "rationale": overlay.relation_summary_zh,
                    "paper": paper,
                }
            ],
        }

    @staticmethod
    def _entry_dict(
        row: Any, paper_summaries: dict[str, dict[str, object]] | None = None
    ) -> dict[str, object]:
        paper = None
        if row["paper_id"] is not None:
            paper = {
                "paper_id": str(row["paper_id"]),
                "canonical_urn": str(row["canonical_urn"]),
                "title": row["paper_title"],
                "detail_url": f"/evidence/papers/{row['paper_id']}",
                "api_url": f"/api/v1/evidence/papers/{row['paper_id']}",
            }
            if paper_summaries is not None:
                paper["paper_summary"] = paper_summaries.get(str(row["paper_id"]))
        return {
            "ledger_entry_id": str(row["ledger_entry_id"]),
            "research_urn": str(row["research_urn"]),
            "document_version_urn": str(row["document_version_urn"]),
            "source_path": str(row["source_path"]),
            "canonical_path": str(row["canonical_path"]),
            "locator_claim": str(row["locator_claim"]),
            "occurrence_type": str(row["occurrence_type"]),
            "entry_status": str(row["entry_status"]),
            "binding_status": str(row["binding_status"] or "unresolved"),
            "rationale": row["rationale"],
            "paper": paper,
        }

    def citation_entry_detail(self, ledger_entry_id: str) -> dict[str, object]:
        if not _LEDGER_ID_RE.fullmatch(ledger_entry_id):
            raise EvidenceQueryNotFound("citation ledger entry not found")
        with evidence_connection(self.settings) as connection:
            row = connection.execute(
                """
                SELECT ledger.*,binding.binding_status,binding.rationale,binding.paper_id,
                       paper.canonical_urn,catalog.title AS paper_title
                FROM citation_ledger_entry AS ledger
                LEFT JOIN citation_binding_projection AS projection USING(ledger_entry_id)
                LEFT JOIN citation_binding AS binding USING(binding_id)
                LEFT JOIN paper ON paper.paper_id=binding.paper_id
                LEFT JOIN paper_catalog_projection AS catalog ON catalog.paper_id=paper.paper_id
                WHERE ledger.ledger_entry_id=?
                """,
                (ledger_entry_id,),
            ).fetchone()
            if row is None:
                raise EvidenceQueryNotFound("citation ledger entry not found")
            summaries = self._paper_summaries(
                connection,
                {str(row["paper_id"])} if row["paper_id"] is not None else set(),
            )
            result = self._entry_dict(row, summaries)
            result["citation_detail_url"] = f"/api/v1/evidence/citations/{row['citation_id']}"
            result["raw_payload"] = _json(row["raw_payload_json"])
            return result

    def resource(self, resource_id: str) -> ResourceResponse:
        return self.resource_store.resource_response(resource_id)

    def library_resource(self, paper_id: str) -> ResourceResponse:
        if not _LEDGER_ID_RE.fullmatch(paper_id):
            raise EvidenceResourceNotFound("paper library resource not found")
        with evidence_connection(self.settings) as connection:
            if not _table_exists(connection, "evidence_substantive_enrichment"):
                raise EvidenceResourceNotFound("paper library resource not found")
            row = connection.execute(
                """
                SELECT local_pdf_relative_path,local_pdf_sha256,local_pdf_bytes
                FROM evidence_substantive_enrichment WHERE paper_id=?
                """,
                (paper_id,),
            ).fetchone()
        if row is None or row["local_pdf_relative_path"] is None:
            raise EvidenceResourceNotFound("paper library resource not found")
        relative = PurePosixPath(str(row["local_pdf_relative_path"]))
        if (
            relative.is_absolute()
            or relative.parts[:3] != ("quant_hub", "paper_lab", "papers")
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise EvidenceResourceCorruption("paper library path is outside the managed root")
        path = self.settings.project_root.joinpath(*relative.parts)
        try:
            info = path.lstat()
            payload = path.read_bytes()
        except FileNotFoundError as error:
            raise EvidenceResourceNotFound("paper library bytes are missing") from error
        if (
            not stat.S_ISREG(info.st_mode)
            or stat_is_reparse_point(info)
            or info.st_nlink != 1
        ):
            raise EvidenceResourceCorruption("paper library resource is not a safe regular file")
        expected_bytes = int(row["local_pdf_bytes"])
        expected_sha256 = str(row["local_pdf_sha256"])
        if (
            len(payload) != expected_bytes
            or hashlib.sha256(payload).hexdigest() != expected_sha256
            or not payload.startswith(b"%PDF-")
        ):
            raise EvidenceResourceCorruption("paper library resource failed hash verification")
        return ResourceResponse(
            resource_id=f"library:{paper_id}",
            payload=payload,
            media_type="application/pdf",
            download_name=f"{paper_id}.pdf",
        )
