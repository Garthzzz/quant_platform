from __future__ import annotations

from bisect import bisect_right
from dataclasses import asdict, dataclass
import re
from typing import Any, Iterable
from urllib.parse import urlsplit

from markdown_it import MarkdownIt

from quant_hub.evidence.ids import citation_id_for_marker, normalize_identifier
from quant_hub.ids import sha256_hex


CLUE_EXTRACTOR_VERSION = "incremental-clue-extractor/v1"


@dataclass(frozen=True, slots=True)
class ExtractedClue:
    citation_id: str
    occurrence_kind: str
    resolution_status: str
    raw_marker_text: str
    raw_marker_sha256: str
    context_text: str
    line_start: int
    line_end: int
    byte_start: int
    byte_end: int
    identifier_scheme: str | None
    identifier_claim: str | None
    identifier_normalized: str | None
    status_reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ClueArtifact:
    schema_version: str
    extractor_version: str
    source_object_urn: str
    document_sha256: str
    source_path: str
    occurrences: tuple[ExtractedClue, ...]
    protected_code_span_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "extractor_version": self.extractor_version,
            "source_object_urn": self.source_object_urn,
            "document_sha256": self.document_sha256,
            "source_path": self.source_path,
            "occurrences": [item.to_dict() for item in self.occurrences],
            "protected_code_span_count": self.protected_code_span_count,
        }


_ARXIV_PATTERNS = (
    re.compile(
        r"(?i)\barxiv\s*:\s*(?P<id>(?:[a-z][a-z.\-]+/\d{7}|\d{4}\.\d{4,5})(?:v\d+)?)"
    ),
    re.compile(
        r"(?i)https?://(?:www\.)?arxiv\.org/(?:abs|pdf)/"
        r"(?P<id>(?:[a-z][a-z.\-]+/\d{7}|\d{4}\.\d{4,5})(?:v\d+)?)(?:\.pdf)?"
    ),
)
_DOI_PATTERNS = (
    re.compile(
        r"(?i)\bdoi\s*:\s*(?P<id>10\.\d{4,9}/[-._;()/:a-z0-9]+)"
    ),
    re.compile(
        r"(?i)https?://(?:dx\.)?doi\.org/(?P<id>10\.\d{4,9}/[-._;()/:a-z0-9]+)"
    ),
    re.compile(r"(?i)(?<![\w/])(?P<id>10\.\d{4,9}/[-._;()/:a-z0-9]+)"),
)
_REFERENCE_PREFIX = re.compile(r"^\s*(?:[-*+]|\d+[.)]|\[\d+\])\s+")
_YEAR = re.compile(r"(?<!\d)(?:18|19|20)\d{2}[a-z]?(?!\d)", re.IGNORECASE)
_PAPER_LINK = re.compile(
    r"\[[^\]\n]{2,240}\]\((?P<url>https?://[^\s)]+(?:\)[^\s)]*)?)\)",
    re.IGNORECASE,
)
_SCHOLARLY_HOSTS = (
    "ssrn.com",
    "ideas.repec.org",
    "openreview.net",
    "jstor.org",
    "aclanthology.org",
    "proceedings.mlr.press",
    "link.springer.com",
    "sciencedirect.com",
    "onlinelibrary.wiley.com",
    "academic.oup.com",
)


def _line_starts(text: str) -> list[int]:
    starts = [0]
    for index, character in enumerate(text):
        if character == "\n":
            starts.append(index + 1)
    return starts


def _char_to_byte_offsets(text: str) -> list[int]:
    offsets = [0]
    total = 0
    for character in text:
        total += len(character.encode("utf-8"))
        offsets.append(total)
    return offsets


def _line_ranges(text: str, starts: list[int]) -> list[tuple[int, int, str]]:
    rows: list[tuple[int, int, str]] = []
    for ordinal, start in enumerate(starts):
        end = starts[ordinal + 1] if ordinal + 1 < len(starts) else len(text)
        content_end = end
        while content_end > start and text[content_end - 1] in "\r\n":
            content_end -= 1
        rows.append((start, content_end, text[start:content_end]))
    return rows


def _merge_spans(spans: Iterable[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    ordered = sorted((start, end) for start, end in spans if end > start)
    merged: list[list[int]] = []
    for start, end in ordered:
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)
    return tuple((start, end) for start, end in merged)


def _is_escaped(text: str, position: int) -> bool:
    backslashes = 0
    cursor = position - 1
    while cursor >= 0 and text[cursor] == "\\":
        backslashes += 1
        cursor -= 1
    return backslashes % 2 == 1


def _inline_code_spans(
    text: str, block_spans: tuple[tuple[int, int], ...]
) -> list[tuple[int, int]]:
    """定位 CommonMark backtick code span，包括跨行 span。

    关闭分隔符必须是完全相同长度的 backtick run；块级代码区域和反斜杠
    转义的 backtick 不参与匹配。这里只需要保护来源坐标，不改写 Markdown。
    """

    spans: list[tuple[int, int]] = []
    position = 0
    block_index = 0
    while position < len(text):
        while block_index < len(block_spans) and block_spans[block_index][1] <= position:
            block_index += 1
        if block_index < len(block_spans):
            block_start, block_end = block_spans[block_index]
            if block_start <= position < block_end:
                position = block_end
                continue
        if text[position] != "`" or _is_escaped(text, position):
            position += 1
            continue
        run_end = position + 1
        while run_end < len(text) and text[run_end] == "`":
            run_end += 1
        delimiter_length = run_end - position
        cursor = run_end
        closing_end: int | None = None
        while cursor < len(text):
            next_tick = text.find("`", cursor)
            if next_tick < 0:
                break
            enclosing_block = next(
                (
                    (left, right)
                    for left, right in block_spans
                    if left <= next_tick < right
                ),
                None,
            )
            if enclosing_block is not None:
                cursor = enclosing_block[1]
                continue
            if _is_escaped(text, next_tick):
                cursor = next_tick + 1
                continue
            next_end = next_tick + 1
            while next_end < len(text) and text[next_end] == "`":
                next_end += 1
            if next_end - next_tick == delimiter_length:
                closing_end = next_end
                break
            cursor = next_end
        if closing_end is None:
            position = run_end
        else:
            spans.append((position, closing_end))
            position = closing_end
    return spans


def _protected_code_spans(text: str, lines: list[tuple[int, int, str]]) -> tuple[tuple[int, int], ...]:
    spans: list[tuple[int, int]] = []
    parser = MarkdownIt("commonmark", {"html": False})
    for token in parser.parse(text):
        if token.type not in {"fence", "code_block"} or token.map is None:
            continue
        start_line, end_line = token.map
        if start_line >= len(lines):
            continue
        start = lines[start_line][0]
        end = lines[end_line][0] if end_line < len(lines) else len(text)
        spans.append((start, end))
    block_spans = _merge_spans(spans)
    spans.extend(_inline_code_spans(text, block_spans))
    return _merge_spans(spans)


def _overlaps(start: int, end: int, spans: Iterable[tuple[int, int]]) -> bool:
    return any(start < right and end > left for left, right in spans)


def _trim_doi(raw: str) -> str:
    value = raw.rstrip(".,;:")
    while value.endswith(")") and value.count("(") < value.count(")"):
        value = value[:-1]
    return value


def _candidate_matches(text: str) -> list[tuple[int, int, str, str | None, str | None, str]]:
    rows: list[tuple[int, int, str, str | None, str | None, str]] = []
    for pattern in _ARXIV_PATTERNS:
        for match in pattern.finditer(text):
            rows.append(
                (
                    match.start(),
                    match.end(),
                    "strong_identifier",
                    "arxiv",
                    match.group("id"),
                    "原文包含 arXiv 强标识；仅登记 claimed，外部身份仍待 Evidence 核验。",
                )
            )
    for pattern in _DOI_PATTERNS:
        for match in pattern.finditer(text):
            identifier = _trim_doi(match.group("id"))
            trim = len(match.group("id")) - len(identifier)
            rows.append(
                (
                    match.start(),
                    match.end() - trim,
                    "strong_identifier",
                    "doi",
                    identifier,
                    "原文包含 DOI 强标识；仅登记 claimed，外部身份仍待 Evidence 核验。",
                )
            )
    return rows


def extract_clues(
    source_bytes: bytes,
    *,
    source_path: str,
    source_object_urn: str,
) -> ClueArtifact:
    """从原始 UTF-8 字节提取可复核线索；绝不把代码块内容当论文线索。"""

    text = source_bytes.decode("utf-8")
    document_sha256 = sha256_hex(source_bytes)
    if not source_object_urn.endswith(document_sha256):
        raise ValueError("source object URN does not commit to the supplied bytes")
    starts = _line_starts(text)
    lines = _line_ranges(text, starts)
    byte_offsets = _char_to_byte_offsets(text)
    protected = _protected_code_spans(text, lines)

    candidates = _candidate_matches(text)
    occupied: list[tuple[int, int]] = []
    selected: list[tuple[int, int, str, str | None, str | None, str]] = []
    # URL/带前缀形式优先，随后去除 bare identifier 的重叠命中。
    for candidate in sorted(candidates, key=lambda item: (item[0], -(item[1] - item[0]))):
        start, end = candidate[0], candidate[1]
        if _overlaps(start, end, protected) or _overlaps(start, end, occupied):
            continue
        occupied.append((start, end))
        selected.append(candidate)

    for line_start, line_end, line in lines:
        if not line.strip() or _overlaps(line_start, line_end, protected):
            continue
        reference = _REFERENCE_PREFIX.match(line)
        if reference is not None and _YEAR.search(line):
            marker_start = line_start + reference.start()
            marker_end = line_end
            if not _overlaps(marker_start, marker_end, occupied):
                selected.append(
                    (
                        marker_start,
                        marker_end,
                        "formal_reference",
                        None,
                        None,
                        "原文形式上呈现参考文献线索，但没有可在本地确定的强标识。",
                    )
                )
                occupied.append((marker_start, marker_end))
        for match in _PAPER_LINK.finditer(line):
            start = line_start + match.start()
            end = line_start + match.end()
            try:
                hostname = (urlsplit(match.group("url")).hostname or "").lower().rstrip(".")
            except ValueError:
                continue
            if not any(
                hostname == allowed or hostname.endswith(f".{allowed}")
                for allowed in _SCHOLARLY_HOSTS
            ):
                continue
            if _overlaps(start, end, protected) or _overlaps(start, end, occupied):
                continue
            selected.append(
                (
                    start,
                    end,
                    "textual_mention",
                    None,
                    None,
                    "原文链接指向学术资料站点；身份与作品类型尚未核验。",
                )
            )
            occupied.append((start, end))

    occurrences: list[ExtractedClue] = []
    seen: set[tuple[int, int, str]] = set()
    for start, end, kind, scheme, claim, reason in sorted(
        selected, key=lambda item: (item[0], item[1], item[2])
    ):
        if end <= start or _overlaps(start, end, protected):
            continue
        raw = text[start:end]
        key = (start, end, kind)
        if key in seen:
            continue
        seen.add(key)
        line_index = bisect_right(starts, start) - 1
        context = lines[line_index][2]
        byte_start = byte_offsets[start]
        byte_end = byte_offsets[end]
        normalized = normalize_identifier(scheme, claim) if scheme and claim else None
        occurrences.append(
            ExtractedClue(
                citation_id=citation_id_for_marker(
                    document_sha256, byte_start, byte_end, raw
                ),
                occurrence_kind=kind,
                resolution_status="unresolved",
                raw_marker_text=raw,
                raw_marker_sha256=sha256_hex(raw.encode("utf-8")),
                context_text=context,
                line_start=line_index + 1,
                line_end=line_index + 1,
                byte_start=byte_start,
                byte_end=byte_end,
                identifier_scheme=scheme,
                identifier_claim=claim,
                identifier_normalized=normalized,
                status_reason=reason,
            )
        )
    return ClueArtifact(
        schema_version="qrh-incremental-clue-artifact/v1",
        extractor_version=CLUE_EXTRACTOR_VERSION,
        source_object_urn=source_object_urn,
        document_sha256=document_sha256,
        source_path=source_path,
        occurrences=tuple(occurrences),
        protected_code_span_count=len(protected),
    )
