"""Archive Markdown 的确定性、安全展示投影。

输入是已经由 Archive source boundary 读取的原始 bytes。本模块只生成可重建的
heading/TOC、搜索文本、数学节点和 HTML；不会规范化、覆盖或写回来源正文。
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import hashlib
import html
import re
from typing import Callable, Iterable, Sequence

import bleach
from latex2mathml import converter as latex2mathml_converter
from markdown_it import MarkdownIt
from markdown_it.rules_block import StateBlock
from markdown_it.token import Token

from quant_hub.presentation import ArchivePresentationError, InternalArchiveLink


PROJECTOR_VERSION = "qrh-markdown-projection/v3-block-mathml"
ANCHOR_PROTOCOL = b"qrh-heading-anchor-v1\0"
SAFE_LINK_PROTOCOLS = frozenset({"http", "https", "mailto"})
_CITATION_TOKEN_RE = re.compile(r"^\^src:\{(cit_[a-z2-7]{52})\}")
_RELATIVE_MARKDOWN_REFERENCE_RE = re.compile(
    r"(?:(?:\.\.?[/\\])+|(?=[^:\s<>{}\[\]()\"'`，。；：、]+[/\\]))"
    r"(?:[^\s<>{}\[\]()\"'`，。；：、]+[/\\])*"
    r"[^\s<>{}\[\]()\"'`，。；：、]+?\.(?:md|markdown)"
    r"(?:#[^\s<>{}\[\]()\"'`，。；：、]+)?",
    re.IGNORECASE,
)
_BARE_MARKDOWN_CODE_REFERENCE_RE = re.compile(
    r"[^\s<>{}\[\]()\"'`，。；：、/\\]+?\.(?:md|markdown)"
    r"(?:#[^\s<>{}\[\]()\"'`，。；：、]+)?",
    re.IGNORECASE,
)
_RELATIVE_DIRECTORY_CODE_REFERENCE_RE = re.compile(
    r"(?:\.\.?[/\\])+(?:[^\s<>{}\[\]()\"'`，。；：、]+[/\\])+",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class HeadingNode:
    """一个版本内的 heading，以及回到原始 UTF-8 bytes 的半开区间。"""

    ordinal: int
    level: int
    title_text: str
    node_path: str
    parent_anchor_id: str | None
    line_start: int
    line_end: int
    byte_start: int
    byte_end: int
    anchor_id: str
    source_sha256: str


@dataclass(frozen=True, slots=True)
class TocEntry:
    anchor_id: str
    title_text: str
    level: int
    children: tuple["TocEntry", ...]


@dataclass(frozen=True, slots=True)
class MathNode:
    """供前端安全数学渲染器消费的 TeX 数据，不含可执行 HTML。"""

    ordinal: int
    tex: str
    display: bool
    delimiter: str
    tex_sha256: str


@dataclass(frozen=True, slots=True)
class MarkdownProjection:
    projector_version: str
    document_sha256: str
    byte_length: int
    encoding: str
    headings: tuple[HeadingNode, ...]
    toc: tuple[TocEntry, ...]
    math_nodes: tuple[MathNode, ...]
    plain_text: str
    rendered_html: str


@dataclass(frozen=True, slots=True)
class CitationRenderSpec:
    """展示层引用位置；字段全部绑定不可变 Archive bytes。"""

    citation_id: str
    byte_start: int
    byte_end: int
    raw_marker_sha256: str
    resolution_state: str = "unresolved"


@dataclass(frozen=True, slots=True)
class CitationRenderedDocument:
    rendered_html: str
    citation_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PresentationRenderedDocument:
    """不改来源 bytes 的读者版 HTML，以及显式暴露的失效链接。"""

    rendered_html: str
    citation_ids: tuple[str, ...]
    unresolved_references: tuple[str, ...]


class CitationProjectionIncomplete(ValueError):
    """部分 occurrence 无法在当前安全 Markdown AST 中唯一落位。"""

    def __init__(self, citation_ids: Sequence[str]):
        self.citation_ids = tuple(dict.fromkeys(citation_ids))
        super().__init__(
            "citation placement is not a unique interactive AST position: "
            + ", ".join(self.citation_ids)
        )


def _is_escaped(text: str, position: int) -> bool:
    backslashes = 0
    cursor = position - 1
    while cursor >= 0 and text[cursor] == "\\":
        backslashes += 1
        cursor -= 1
    return bool(backslashes % 2)


def _find_unescaped(text: str, delimiter: str, start: int, limit: int) -> int:
    cursor = start
    while True:
        cursor = text.find(delimiter, cursor, limit)
        if cursor < 0:
            return -1
        if not _is_escaped(text, cursor):
            return cursor
        cursor += len(delimiter)


def _math_rule(state: object, silent: bool) -> bool:
    """识别项目正文实际使用的四种 TeX delimiter。

    规则只在 markdown-it 的原生 inline pass 中运行，所以 code span、fence 和
    link destination 不会被二次扫描。单美元要求 delimiter 内侧不是空白；若以
    数字开头且 closer 后仍紧跟数字，也拒绝配对，避免把 ``$100 与 $200`` 的第二
    个货币符号误当 closer，同时保留 ``$10^{-8}$`` 等真实数值公式。
    """

    source = state.src
    start = state.pos
    limit = state.posMax
    if start >= limit or _is_escaped(source, start):
        return False

    delimiter: str
    closer: str
    display: bool
    if source.startswith("$$", start):
        delimiter, closer, display = "$$", "$$", True
    elif source.startswith("\\[", start):
        delimiter, closer, display = "\\[", "\\]", True
    elif source.startswith("\\(", start):
        delimiter, closer, display = "\\(", "\\)", False
    elif source[start] == "$":
        delimiter, closer, display = "$", "$", False
    else:
        return False

    content_start = start + len(delimiter)
    if content_start >= limit:
        return False
    close = _find_unescaped(source, closer, content_start, limit)
    if close < 0 or close == content_start:
        return False
    tex = source[content_start:close]
    if delimiter == "$":
        if "\n" in tex or "\r" in tex or tex[0].isspace() or tex[-1].isspace():
            return False
        if (
            tex[0].isdigit()
            and close + 1 < limit
            and source[close + 1].isdigit()
        ):
            return False

    state.pos = close + len(closer)
    if not silent:
        token = state.push("qrh_math", "span", 0)
        token.content = tex
        token.markup = delimiter
        token.meta["display"] = display
    return True


def _math_block_rule(
    state: StateBlock,
    start_line: int,
    end_line: int,
    silent: bool,
) -> bool:
    """在 CommonMark 解释 ``=``、``-``、``|`` 前捕获独立展示公式。

    Archive 中的长公式主要采用 opener/closer 各占一行的 ``$$`` 形式。若只在
    inline pass 识别，公式内部单独一行的 ``=`` 会先被 CommonMark 当成 Setext
    heading underline，表格符号等也可能切断段落。该 block rule 在块结构形成前
    消费完整公式，因此公式内容不会污染 heading/TOC，也不会被误拆成 Markdown。

    未闭合或空内容会进入显式 invalid 块，逐字显示原文且不会生成伪 heading；
    缩进代码块继续交给原生 Markdown 规则。任何情形都不猜测缺失 delimiter。
    """

    if state.is_code_block(start_line):
        return False
    start = state.bMarks[start_line] + state.tShift[start_line]
    maximum = state.eMarks[start_line]
    opening_line = state.src[start:maximum]
    delimiter: str | None = None
    closer: str | None = None
    for candidate, candidate_closer in (("$$", "$$"), ("\\[", "\\]")):
        if opening_line.startswith(candidate):
            delimiter = candidate
            closer = candidate_closer
            break
    if delimiter is None or closer is None:
        return False

    content_start = start + len(delimiter)
    same_line_close = _find_unescaped(
        state.src, closer, content_start, maximum
    )
    close_position = -1
    close_line = start_line
    if same_line_close >= 0:
        if state.src[same_line_close + len(closer) : maximum].strip():
            return False
        close_position = same_line_close
    else:
        close_line = start_line + 1
        while close_line < end_line:
            if (
                not state.isEmpty(close_line)
                and state.sCount[close_line] < state.blkIndent
            ):
                break
            line_start = state.bMarks[close_line] + state.tShift[close_line]
            line_end = state.eMarks[close_line]
            candidate_close = _find_unescaped(
                state.src, closer, line_start, line_end
            )
            if (
                candidate_close >= 0
                and not state.src[
                    candidate_close + len(closer) : line_end
                ].strip()
            ):
                close_position = candidate_close
                break
            close_line += 1
    if close_position < 0:
        # 已出现明确 block opener，却没有 closer。若交回 CommonMark，公式内部
        # 的 ``=``/``-`` 会被伪装成 heading/hr；因此消费到空行或容器末尾，作为
        # 显式 invalid math 展示，既保留原文也不猜测缺失的 delimiter。
        invalid_end = start_line + 1
        while invalid_end < end_line:
            if state.isEmpty(invalid_end):
                break
            if state.sCount[invalid_end] < state.blkIndent:
                break
            invalid_end += 1
        if silent:
            return True
        state.line = max(start_line + 1, invalid_end)
        token = state.push("qrh_math_invalid", "div", 0)
        token.content = "\n".join(
            state.getLines(line, line + 1, state.blkIndent, False)
            for line in range(start_line, state.line)
        ).strip("\r\n")
        token.markup = delimiter
        token.map = [start_line, state.line]
        return True

    if close_line == start_line:
        tex = state.src[content_start:close_position].strip()
    else:
        parts = [opening_line[len(delimiter) :]]
        parts.extend(
            state.getLines(line, line + 1, state.blkIndent, False)
            for line in range(start_line + 1, close_line)
        )
        closing_text = state.getLines(
            close_line, close_line + 1, state.blkIndent, False
        )
        normalized_close = _find_unescaped(
            closing_text, closer, 0, len(closing_text)
        )
        if normalized_close < 0:
            raise ValueError("math block closer was lost while removing container markup")
        parts.append(closing_text[:normalized_close])
        tex = "\n".join(parts).strip()
    if not tex:
        if silent:
            return True
        state.line = close_line + 1
        token = state.push("qrh_math_invalid", "div", 0)
        token.content = "\n".join(
            state.getLines(line, line + 1, state.blkIndent, False)
            for line in range(start_line, state.line)
        ).strip("\r\n")
        token.markup = delimiter
        token.map = [start_line, state.line]
        return True
    if silent:
        return True

    state.line = close_line + 1
    token = state.push("qrh_math_block", "span", 0)
    token.content = tex
    token.markup = delimiter
    token.meta["display"] = True
    token.map = [start_line, state.line]
    return True


def _render_math(
    _renderer: object,
    tokens: Sequence[Token],
    index: int,
    _options: object,
    _environment: object,
) -> str:
    token = tokens[index]
    display = bool(token.meta.get("display"))
    kind = "math-display" if display else "math-inline"
    tex_attribute = html.escape(token.content, quote=True)
    tex_fallback = html.escape(token.content)
    mathml = _mathml(token.content, display)
    if mathml is None:
        return (
            f'<span class="math {kind}" role="math" aria-label="数学公式" '
            f'data-tex="{tex_attribute}" data-math-rendered="fallback">'
            f'<code class="math-source">{tex_fallback}</code></span>'
        )
    return (
        f'<span class="math {kind}" role="math" aria-label="数学公式" '
        f'data-tex="{tex_attribute}" data-math-rendered="mathml">{mathml}'
        f'<code class="math-source math-source--fallback" aria-hidden="true">'
        f"{tex_fallback}</code></span>"
    )


def _render_invalid_math(
    _renderer: object,
    tokens: Sequence[Token],
    index: int,
    _options: object,
    _environment: object,
) -> str:
    source = html.escape(tokens[index].content)
    return (
        '<div class="math math-display math-invalid" role="note" '
        'aria-label="未解析的数学公式">'
        f'<code class="math-source">{source}</code></div>'
    )


def _citation_rule(state: object, silent: bool) -> bool:
    match = _CITATION_TOKEN_RE.match(state.src[state.pos : state.posMax])
    if match is None:
        return False
    if not silent:
        token = state.push("qrh_citation", "", 0)
        token.content = match.group(1)
    state.pos += len(match.group(0))
    return True


def _render_citation(
    _renderer: object,
    tokens: Sequence[Token],
    index: int,
    _options: object,
    environment: object,
) -> str:
    citation_id = tokens[index].content
    labels = environment.get("citation_labels", {}) if isinstance(environment, dict) else {}
    states = environment.get("citation_states", {}) if isinstance(environment, dict) else {}
    label = str(labels.get(citation_id, "证"))
    state = str(states.get(citation_id, "unresolved"))
    escaped_id = html.escape(citation_id, quote=True)
    escaped_label = html.escape(label)
    accessible = html.escape(f"查看引用 {label}", quote=True)
    return (
        '<sup class="citation-ref">'
        '<button type="button" class="citation-trigger" '
        f'id="citation-{escaped_id}" '
        f'data-citation-id="{escaped_id}" data-citation-state="{html.escape(state, quote=True)}" '
        f'aria-label="{accessible}" aria-haspopup="dialog" aria-controls="citation-dialog" '
        f'aria-expanded="false" title="{accessible}">{escaped_label}</button>'
        "</sup>"
    )


@lru_cache(maxsize=16_384)
def _mathml(tex: str, display: bool) -> str | None:
    try:
        return latex2mathml_converter.convert(
            tex,
            display="block" if display else "inline",
        )
    except Exception:
        # 不猜测或吞掉公式：转换器不支持的 TeX 保留精确源码 fallback。
        return None


def _render_table_open(
    _renderer: object,
    _tokens: Sequence[Token],
    _index: int,
    _options: object,
    _environment: object,
) -> str:
    return (
        '<div class="table-scroll" role="region" tabindex="0" '
        'aria-label="数据表格（可横向滚动）"><table>\n'
    )


def _render_table_close(
    _renderer: object,
    _tokens: Sequence[Token],
    _index: int,
    _options: object,
    _environment: object,
) -> str:
    return "</table></div>\n"


def _markdown_parser() -> MarkdownIt:
    parser = MarkdownIt(
        "commonmark",
        {"html": False, "linkify": False, "typographer": False},
    ).enable("table")
    parser.block.ruler.before(
        "fence",
        "qrh_math_block",
        _math_block_rule,
        {"alt": ["paragraph", "reference", "blockquote", "list"]},
    )
    parser.inline.ruler.before("escape", "qrh_math", _math_rule)
    parser.inline.ruler.before("escape", "qrh_citation", _citation_rule)
    parser.add_render_rule("qrh_math", _render_math)
    parser.add_render_rule("qrh_math_block", _render_math)
    parser.add_render_rule("qrh_math_invalid", _render_invalid_math)
    parser.add_render_rule("qrh_citation", _render_citation)
    parser.add_render_rule("table_open", _render_table_open)
    parser.add_render_rule("table_close", _render_table_close)
    return parser


def _line_byte_starts(text: str) -> tuple[int, ...]:
    """按 CommonMark 的 CRLF/LF/CR 行模型返回每行起点及可能的 EOF 哨兵。"""

    starts = [0]
    byte_position = 0
    cursor = 0
    while cursor < len(text):
        character = text[cursor]
        if character == "\r":
            if cursor + 1 < len(text) and text[cursor + 1] == "\n":
                byte_position += 2
                cursor += 2
            else:
                byte_position += 1
                cursor += 1
            starts.append(byte_position)
            continue
        encoded_length = len(character.encode("utf-8"))
        byte_position += encoded_length
        cursor += 1
        if character == "\n":
            starts.append(byte_position)
    return tuple(starts)


def _byte_at_line(
    line_starts: Sequence[int], line_number: int, byte_length: int
) -> int:
    if line_number < 0:
        raise ValueError("negative markdown token line")
    if line_number < len(line_starts):
        return int(line_starts[line_number])
    if line_number == len(line_starts):
        return byte_length
    raise ValueError("markdown token line escapes source")


def _inline_plain_text(tokens: Iterable[Token]) -> str:
    parts: list[str] = []
    for token in tokens:
        if token.type in {"text", "code_inline", "qrh_math"}:
            parts.append(token.content)
        elif token.type in {"softbreak", "hardbreak"}:
            parts.append("\n")
        elif token.type == "image":
            parts.append(token.content)
        elif token.children:
            parts.append(_inline_plain_text(token.children))
    return "".join(parts)


def _title_text(inline_token: Token) -> str:
    title = _inline_plain_text(inline_token.children or ())
    return re.sub(r"\s+", " ", title).strip()


def _heading_anchor(
    document_sha256: str, node_path: str, source_bytes: bytes
) -> str:
    digest = hashlib.sha256(
        ANCHOR_PROTOCOL
        + document_sha256.encode("ascii")
        + b"\0"
        + node_path.encode("utf-8")
        + b"\0"
        + source_bytes
    ).hexdigest()
    return "anc_sha256_" + digest


def _headings(
    tokens: Sequence[Token], source_bytes: bytes, document_sha256: str, text: str
) -> tuple[HeadingNode, ...]:
    line_starts = _line_byte_starts(text)
    stack: list[HeadingNode] = []
    sibling_counts: dict[tuple[str, int], int] = {}
    headings: list[HeadingNode] = []

    for index, token in enumerate(tokens):
        if token.type != "heading_open" or token.map is None:
            continue
        try:
            level = int(token.tag.removeprefix("h"))
        except ValueError as error:
            raise ValueError(f"invalid heading tag: {token.tag!r}") from error
        if not 1 <= level <= 6:
            raise ValueError(f"heading level outside h1-h6: {level}")
        if index + 1 >= len(tokens) or tokens[index + 1].type != "inline":
            raise ValueError("heading has no adjacent inline token")

        while stack and stack[-1].level >= level:
            stack.pop()
        parent = stack[-1] if stack else None
        parent_path = parent.node_path if parent else "root"
        sibling_key = (parent_path, level)
        sibling_ordinal = sibling_counts.get(sibling_key, 0) + 1
        sibling_counts[sibling_key] = sibling_ordinal
        node_path = f"{parent_path}/h{level}[{sibling_ordinal}]"

        start_line, end_line = int(token.map[0]), int(token.map[1])
        byte_start = _byte_at_line(line_starts, start_line, len(source_bytes))
        byte_end = _byte_at_line(line_starts, end_line, len(source_bytes))
        if not 0 <= byte_start < byte_end <= len(source_bytes):
            raise ValueError("heading byte span is empty or outside source")
        raw_heading = source_bytes[byte_start:byte_end]
        anchor_id = _heading_anchor(document_sha256, node_path, raw_heading)
        heading = HeadingNode(
            ordinal=len(headings) + 1,
            level=level,
            title_text=_title_text(tokens[index + 1]),
            node_path=node_path,
            parent_anchor_id=parent.anchor_id if parent else None,
            line_start=start_line + 1,
            line_end=end_line,
            byte_start=byte_start,
            byte_end=byte_end,
            anchor_id=anchor_id,
            source_sha256=hashlib.sha256(raw_heading).hexdigest(),
        )
        token.attrSet("id", anchor_id)
        headings.append(heading)
        stack.append(heading)
    return tuple(headings)


def _toc(headings: Sequence[HeadingNode]) -> tuple[TocEntry, ...]:
    by_parent: dict[str | None, list[HeadingNode]] = {}
    for heading in headings:
        by_parent.setdefault(heading.parent_anchor_id, []).append(heading)

    def build(parent_anchor_id: str | None) -> tuple[TocEntry, ...]:
        return tuple(
            TocEntry(
                anchor_id=heading.anchor_id,
                title_text=heading.title_text,
                level=heading.level,
                children=build(heading.anchor_id),
            )
            for heading in by_parent.get(parent_anchor_id, ())
        )

    return build(None)


def _math_nodes(tokens: Sequence[Token]) -> tuple[MathNode, ...]:
    rows: list[MathNode] = []
    for block_token in tokens:
        candidates = (
            (block_token,)
            if block_token.type == "qrh_math_block"
            else tuple(block_token.children or ())
        )
        for token in candidates:
            if token.type not in {"qrh_math", "qrh_math_block"}:
                continue
            rows.append(
                MathNode(
                    ordinal=len(rows) + 1,
                    tex=token.content,
                    display=bool(token.meta.get("display")),
                    delimiter=token.markup,
                    tex_sha256=hashlib.sha256(token.content.encode("utf-8")).hexdigest(),
                )
            )
    return tuple(rows)


def _plain_search_text(tokens: Sequence[Token]) -> str:
    blocks: list[str] = []
    for token in tokens:
        if token.type == "inline":
            value = _inline_plain_text(token.children or ()).strip()
        elif token.type == "qrh_math_block":
            value = token.content.strip()
        elif token.type == "qrh_math_invalid":
            value = token.content.strip()
        elif token.type in {"fence", "code_block"}:
            value = token.content.strip()
        else:
            continue
        if value:
            blocks.append(value)
    return "\n".join(blocks)


def _replace_table_alignment_style(tokens: Sequence[Token]) -> None:
    """把 table extension 的有限 style 值改为 Bleach 可安全保留的 align。"""

    for token in tokens:
        if token.type not in {"th_open", "td_open"} or not token.attrs:
            continue
        style = token.attrGet("style")
        if style is None:
            continue
        match = re.fullmatch(r"text-align:(left|center|right)", style)
        token.attrs.pop("style", None)
        if match is None:
            raise ValueError(f"unexpected markdown table style: {style!r}")
        token.attrSet("align", match.group(1))


_ALLOWED_TAGS = frozenset(
    {
        "a",
        "blockquote",
        "br",
        "button",
        "code",
        "div",
        "em",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "hr",
        "img",
        "li",
        "math",
        "menclose",
        "merror",
        "mfenced",
        "mfrac",
        "mi",
        "mmultiscripts",
        "mn",
        "mo",
        "mover",
        "mpadded",
        "mphantom",
        "mprescripts",
        "mroot",
        "mrow",
        "ms",
        "mspace",
        "msqrt",
        "mstyle",
        "msub",
        "msubsup",
        "msup",
        "mtable",
        "mtd",
        "mtext",
        "mtr",
        "munder",
        "munderover",
        "none",
        "ol",
        "p",
        "pre",
        "span",
        "strong",
        "sup",
        "table",
        "tbody",
        "td",
        "th",
        "thead",
        "tr",
        "ul",
    }
)
_ALLOWED_ATTRIBUTES: dict[str, tuple[str, ...]] = {
    "a": (
        "href",
        "title",
        "class",
        "aria-label",
        "data-internal-link-state",
    ),
    "button": (
        "type",
        "id",
        "class",
        "data-citation-id",
        "data-citation-state",
        "aria-label",
        "aria-haspopup",
        "aria-controls",
        "aria-expanded",
        "title",
    ),
    "code": ("class", "aria-hidden"),
    "div": ("class", "role", "tabindex", "aria-label"),
    "h1": ("id",),
    "h2": ("id",),
    "h3": ("id",),
    "h4": ("id",),
    "h5": ("id",),
    "h6": ("id",),
    "img": ("src", "alt", "title"),
    "ol": ("start",),
    "p": ("class",),
    "span": ("class", "role", "aria-label", "data-tex", "data-math-rendered"),
    "math": ("xmlns", "display"),
    "mi": ("mathvariant",),
    "mn": ("mathvariant",),
    "mo": (
        "stretchy", "fence", "separator", "accent", "form", "lspace", "rspace",
        "movablelimits", "largeop", "symmetric", "maxsize", "minsize",
    ),
    "mtext": ("mathvariant",),
    "mstyle": ("displaystyle", "scriptlevel", "mathvariant", "mathcolor", "mathbackground"),
    "mfrac": ("linethickness", "numalign", "denomalign", "bevelled"),
    "mspace": ("width", "height", "depth"),
    "mpadded": ("width", "height", "depth", "lspace", "voffset"),
    "mfenced": ("open", "close", "separators"),
    "menclose": ("notation",),
    "munder": ("accentunder",),
    "mover": ("accent",),
    "munderover": ("accent", "accentunder"),
    "mtable": (
        "align", "rowalign", "columnalign", "columnwidth", "rowspacing",
        "columnspacing", "rowlines", "columnlines", "frame", "framespacing",
        "equalrows", "equalcolumns", "displaystyle", "side", "minlabelspacing",
    ),
    "mtr": ("rowalign", "columnalign"),
    "mtd": ("rowspan", "columnspan", "rowalign", "columnalign"),
    "td": ("align",),
    "th": ("align",),
}


def _clean_html(rendered: str) -> str:
    return bleach.clean(
        rendered,
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRIBUTES,
        protocols=SAFE_LINK_PROTOCOLS,
        strip=True,
        strip_comments=True,
    )


_LEGACY_TEXT_COMMANDS = frozenset(
    {"emph", "text", "textbf", "textit", "textrm", "texttt", "mbox", "footnote"}
)
_LEGACY_CITATION_COMMANDS = frozenset({"cite", "citep", "citet"})
_LEGACY_REFERENCE_COMMANDS = frozenset({"ref", "eqref", "autoref"})


def _balanced_tex_group(source: str, opening: int) -> tuple[str, int] | None:
    """返回一个平衡 ``{...}`` 的内容和闭括号后一位；不猜测残缺输入。"""

    if opening >= len(source) or source[opening] != "{":
        return None
    depth = 0
    cursor = opening
    while cursor < len(source):
        character = source[cursor]
        if character == "\\":
            cursor += 2
            continue
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : cursor], cursor + 1
        cursor += 1
    return None


def _legacy_citation_label(value: str) -> str:
    labels: list[str] = []
    for raw in value.split(","):
        key = raw.strip()
        match = re.fullmatch(r"([A-Za-z][A-Za-z._-]*?)(\d{4}[a-z]?)", key)
        if match:
            author = re.sub(r"[._-]+", " ", match.group(1)).strip()
            labels.append(f"{author[:1].upper() + author[1:]} ({match.group(2)})")
        elif key:
            labels.append(re.sub(r"[._-]+", " ", key))
    return "；".join(labels)


def _normalize_legacy_tex(source: str, *, inside_text_command: bool = False) -> str:
    """把 Evidence 历史摘录中的少量正文 LaTeX 命令变为可读 Markdown。

    这是严格的展示层白名单，不执行任意 TeX，也不试图修补不平衡花括号。
    数学命令仍由后续 delimiter/MathML 解析器处理。
    """

    output: list[str] = []
    cursor = 0
    while cursor < len(source):
        # arXiv 摘要偶有 ``$\textit{Evo$\textbf{L}$...}$`` 一类嵌套
        # 文字样式。它在语义上是普通强调文字，不能按多个数学公式拆分。
        if source[cursor] == "$" and cursor + 1 < len(source) and source[cursor + 1] == "\\":
            command_match = re.match(r"\\(emph|textbf|textit|textrm|texttt|mbox)\s*", source[cursor + 1 :])
            if command_match:
                group_open = cursor + 1 + command_match.end()
                group = _balanced_tex_group(source, group_open)
                if group is not None and group[1] < len(source) and source[group[1]] == "$":
                    argument = _normalize_legacy_tex(
                        group[0], inside_text_command=True
                    ).replace("$", "")
                    command = command_match.group(1)
                    marker = "**" if command == "textbf" else "*"
                    output.append(
                        argument
                        if inside_text_command or command in {"textrm", "mbox"}
                        else f"{marker}{argument}{marker}"
                    )
                    cursor = group[1] + 1
                    continue

        # 已有合法 delimiter 的公式必须逐字交给 MathML 解析器；白名单只负责
        # 公式外的旧 LaTeX 正文命令，不能改写 ``$\text{...}$`` 的 TeX 语义。
        math_pair: tuple[str, str] | None = None
        for opener, closer in (("$$", "$$"), ("\\[", "\\]"), ("\\(", "\\)"), ("$", "$")):
            if source.startswith(opener, cursor):
                math_pair = (opener, closer)
                break
        if math_pair is not None:
            opener, closer = math_pair
            closing = _find_unescaped(
                source, closer, cursor + len(opener), len(source)
            )
            if closing >= 0:
                span_end = closing + len(closer)
                output.append(source[cursor:span_end])
                cursor = span_end
                continue

        if source[cursor] != "\\":
            output.append(source[cursor])
            cursor += 1
            continue

        escaped = source[cursor + 1 : cursor + 2]
        if escaped in {"&", "%", "_", "#", "$", "{", "}"}:
            output.append(escaped)
            cursor += 2
            continue

        command_match = re.match(r"\\([A-Za-z]+)\s*", source[cursor:])
        if command_match is None:
            output.append("\\")
            cursor += 1
            continue
        command = command_match.group(1)
        after_command = cursor + command_match.end()

        if command == "item":
            output.append("\n- ")
            cursor = after_command
            continue

        group = _balanced_tex_group(source, after_command)
        if group is None:
            output.append(source[cursor:after_command])
            cursor = after_command
            continue
        argument, group_end = group

        if command in _LEGACY_TEXT_COMMANDS:
            normalized = _normalize_legacy_tex(
                argument, inside_text_command=True
            )
            if inside_text_command:
                normalized = normalized.replace("$", "")
            if command == "textbf":
                output.append(f"**{normalized}**")
            elif command in {"emph", "textit"}:
                output.append(f"*{normalized}*")
            elif command == "texttt":
                output.append(f"`{normalized.replace('`', '')}`")
            elif command == "footnote":
                output.append(f"（{normalized}）")
            elif command not in {"text", "textrm", "mbox"}:
                output.append(normalized)
            else:
                output.append(normalized)
            cursor = group_end
            continue
        if command in _LEGACY_CITATION_COMMANDS:
            label = _legacy_citation_label(argument)
            output.append(f"[{label or '参考文献'}]")
            cursor = group_end
            continue
        if command in _LEGACY_REFERENCE_COMMANDS:
            label = re.sub(r"[_-]+", " ", argument).strip()
            output.append(f"（参见{label or '相关公式'}）")
            cursor = group_end
            continue
        if command == "url":
            output.append(argument.strip())
            cursor = group_end
            continue
        if command in {"label", "begin", "end"}:
            cursor = group_end
            continue

        # 未进入白名单的命令逐字保留，避免展示层静默改义。
        output.append(source[cursor:group_end])
        cursor = group_end
    return "".join(output)


def render_research_text(source: str) -> str:
    """把研究展示字段安全投影为支持数学公式的 HTML 片段。

    Evidence 摘要、结论、中文解读和研究关联来自结构化字段，而不是完整的
    Archive 文档，但它们沿用同一套 Markdown/TeX 记法。本函数复用正文投影器的
    delimiter、MathML、HTML allow-list 和溢出语义；只返回可重建的展示结果，
    不修改数据库原值，也不把生成的 HTML 写回来源证据。
    """

    if not isinstance(source, str):
        raise TypeError("source must be text")
    presentation_source = _normalize_legacy_tex(source)
    parser = _markdown_parser()
    environment: dict[str, object] = {}
    tokens = tuple(parser.parse(presentation_source, environment))
    _replace_table_alignment_style(tokens)
    rendered = parser.renderer.render(tokens, parser.options, environment)
    return _clean_html(rendered)


def project_markdown(source_bytes: bytes) -> MarkdownProjection:
    """从未改写 bytes 构建一次完整、冻结的 Archive Markdown 投影。

    ``UnicodeDecodeError`` 是正式 quarantine 信号；本函数不使用 replacement
    character，也不接受文本字符串来绕过原始 bytes 身份。
    """

    if type(source_bytes) is not bytes:
        raise TypeError("source_bytes must be immutable bytes")
    text = source_bytes.decode("utf-8", errors="strict")
    document_sha256 = hashlib.sha256(source_bytes).hexdigest()
    parser = _markdown_parser()
    environment: dict[str, object] = {}
    tokens = tuple(parser.parse(text, environment))
    headings = _headings(tokens, source_bytes, document_sha256, text)
    _replace_table_alignment_style(tokens)
    math_nodes = _math_nodes(tokens)
    plain_text = _plain_search_text(tokens)
    rendered = parser.renderer.render(tokens, parser.options, environment)
    rendered_html = _clean_html(rendered)
    return MarkdownProjection(
        projector_version=PROJECTOR_VERSION,
        document_sha256=document_sha256,
        byte_length=len(source_bytes),
        encoding="utf-8",
        headings=headings,
        toc=_toc(headings),
        math_nodes=math_nodes,
        plain_text=plain_text,
        rendered_html=rendered_html,
    )


def _citation_render_input(
    source_bytes: bytes,
    citations: Sequence[CitationRenderSpec],
) -> tuple[
    str,
    MarkdownProjection,
    dict[str, object],
    tuple[CitationRenderSpec, ...],
]:
    if type(source_bytes) is not bytes:
        raise TypeError("source_bytes must be immutable bytes")
    ordered = tuple(
        sorted(
            citations,
            key=lambda row: (row.byte_start, row.byte_end, row.citation_id),
        )
    )
    seen: set[str] = set()
    previous_end = 0
    previous_span: tuple[int, int] | None = None
    insertions: dict[int, list[str]] = {}
    for item in ordered:
        if not re.fullmatch(r"cit_[a-z2-7]{52}", item.citation_id):
            raise ValueError("citation ID is not canonical")
        if item.citation_id in seen:
            raise ValueError("citation ID is repeated in one document")
        if item.resolution_state not in {"valid", "source-only", "unresolved", "conflicted"}:
            raise ValueError("citation resolution state is not supported")
        seen.add(item.citation_id)
        if not 0 <= item.byte_start < item.byte_end <= len(source_bytes):
            raise ValueError("citation span escapes source bytes")
        marker = source_bytes[item.byte_start : item.byte_end]
        if hashlib.sha256(marker).hexdigest() != item.raw_marker_sha256:
            raise ValueError("citation raw marker hash does not match source bytes")
        span = (item.byte_start, item.byte_end)
        if item.byte_start < previous_end and span != previous_span:
            raise ValueError("citation spans overlap")
        previous_end = max(previous_end, item.byte_end)
        previous_span = span
        insertions.setdefault(item.byte_end, []).append(item.citation_id)

    augmented = bytearray()
    cursor = 0
    for byte_end in sorted(insertions):
        augmented.extend(source_bytes[cursor:byte_end])
        for citation_id in insertions[byte_end]:
            augmented.extend(f" ^src:{{{citation_id}}}".encode("ascii"))
        cursor = byte_end
    augmented.extend(source_bytes[cursor:])
    text = bytes(augmented).decode("utf-8", errors="strict")

    base = project_markdown(source_bytes)
    labels = {
        item.citation_id: str(index)
        for index, item in enumerate(ordered, start=1)
    }
    states = {item.citation_id: item.resolution_state for item in ordered}
    environment: dict[str, object] = {
        "citation_labels": labels,
        "citation_states": states,
    }
    return text, base, environment, ordered


def _restore_heading_anchors(
    tokens: Sequence[Token],
    base: MarkdownProjection,
    heading_anchor_ids: Sequence[str] | None = None,
) -> None:
    heading_tokens = [token for token in tokens if token.type == "heading_open"]
    if len(heading_tokens) != len(base.headings):
        raise ValueError("display projection changed the heading structure")
    anchors = (
        tuple(heading.anchor_id for heading in base.headings)
        if heading_anchor_ids is None
        else tuple(heading_anchor_ids)
    )
    if len(anchors) != len(heading_tokens) or any(
        not re.fullmatch(r"anc_sha256_[0-9a-f]{64}", value) for value in anchors
    ):
        raise ValueError("stable heading anchor set does not match the rendered slice")
    for token, anchor_id in zip(heading_tokens, anchors, strict=True):
        token.attrSet("id", anchor_id)


def _validate_citation_rendering(
    cleaned: str, ordered: Sequence[CitationRenderSpec]
) -> None:
    invalid: list[str] = []
    for item in ordered:
        marker = f'data-citation-id="{item.citation_id}"'
        if cleaned.count(marker) != 1:
            invalid.append(item.citation_id)
    if invalid:
        raise CitationProjectionIncomplete(invalid)


def _text_token(content: str) -> Token:
    token = Token("text", "", 0)
    token.content = content
    return token


_READER_METADATA_DATE_RE = re.compile(r"^\s*日期\s*[：:]\s*\S+")
_READER_METADATA_HIDDEN_RE = re.compile(
    r"^\s*(?:作者|版本|与\s*v[0-9][0-9.]*\s*的关系)\s*[：:]",
    re.IGNORECASE,
)


def _inline_line_text(children: Sequence[Token]) -> str:
    return "".join(
        child.content
        for child in children
        if child.type in {"text", "code_inline", "html_inline"}
    ).strip()


def _project_leading_document_metadata(tokens: Sequence[Token]) -> None:
    """只在阅读副本中隐藏首段署名/版本行，并保留日期。

    过滤发生在 Markdown token 层，因而不会改变来源 bytes、标题锚点或下载内容。
    仅当首个 H1 后的首段同时含明确日期与受控元数据标签时才执行；若待隐藏
    行携带引用 token，则保守地完全不改，避免丢失证据交互。
    """

    first_h1 = next(
        (
            index
            for index, token in enumerate(tokens)
            if token.type == "heading_open" and token.tag == "h1"
        ),
        None,
    )
    if first_h1 is None:
        return
    inline: Token | None = None
    for index in range(first_h1 + 1, len(tokens)):
        token = tokens[index]
        if token.type == "heading_open":
            return
        if token.type == "paragraph_open":
            if index + 1 < len(tokens) and tokens[index + 1].type == "inline":
                inline = tokens[index + 1]
            break
    if inline is None or not inline.children:
        return

    lines: list[tuple[list[Token], Token | None]] = []
    current: list[Token] = []
    for child in inline.children:
        if child.type in {"softbreak", "hardbreak"}:
            lines.append((current, child))
            current = []
        else:
            current.append(child)
    lines.append((current, None))
    texts = [_inline_line_text(line) for line, _ in lines]
    hidden = [bool(_READER_METADATA_HIDDEN_RE.match(text)) for text in texts]
    if not any(_READER_METADATA_DATE_RE.match(text) for text in texts) or not any(hidden):
        return
    if any(
        child.type == "qrh_citation"
        for (line, _), should_hide in zip(lines, hidden, strict=True)
        if should_hide
        for child in line
    ):
        return

    kept = [index for index, should_hide in enumerate(hidden) if not should_hide]
    if not kept:
        return
    projected: list[Token] = []
    for position, line_index in enumerate(kept):
        if position:
            previous_break = lines[kept[position - 1]][1]
            if previous_break is None:
                previous_break = Token("softbreak", "br", 0)
            projected.append(previous_break)
        projected.extend(lines[line_index][0])
    inline.children = projected


def _project_redundant_pipeline_overview(
    tokens: list[Token], target_url: str | None
) -> None:
    """用页首交互管线引用替代 Q2 综述中的重复 ASCII 副本。"""

    if target_url is None:
        return
    safe_url = html.escape(target_url, quote=True)
    for token in tokens:
        if token.type == "fence" and (
            "原始数据 → [步骤1: 预处理]" in token.content
            and "跨步骤：Batch" in token.content
        ):
            token.type = "html_block"
            token.tag = ""
            token.nesting = 0
            token.content = (
                '<p class="q2-pipeline-source-reference">'
                f'<a href="{safe_url}">训练管线已在页首交互视图中完整呈现</a>'
                "，原始结构与组件顺序保持不变。</p>\n"
            )
        if token.type != "inline" or not token.children:
            continue
        if not any(
            child.type == "link_open"
            and (child.attrGet("href") or "").replace("\\", "/").endswith(
                "pipeline_图.md"
            )
            for child in token.children
        ):
            continue
        opened = Token("link_open", "a", 1)
        opened.attrSet("href", target_url)
        closed = Token("link_close", "a", -1)
        token.children = [
            opened,
            _text_token("返回页首交互训练管线"),
            closed,
        ]
    retired_start: int | None = None
    retired_end: int | None = None
    for index, token in enumerate(tokens):
        if (
            token.type == "heading_open"
            and token.tag == "h2"
            and index + 1 < len(tokens)
            and tokens[index + 1].type == "inline"
            and _title_text(tokens[index + 1]).startswith(
                "Pipeline 概览图（按三步 pipeline + 跨步骤重组）"
            )
        ):
            retired_start = index
            retired_end = next(
                (
                    candidate
                    for candidate in range(index + 1, len(tokens))
                    if tokens[candidate].type == "heading_open"
                    and tokens[candidate].tag in {"h1", "h2"}
                ),
                len(tokens),
            )
            break
    if retired_start is not None and retired_end is not None:
        opened = Token("html_block", "", 0)
        opened.content = (
            '<div class="q2-retired-pipeline-source" '
            'aria-label="已由页首交互训练管线替代">\n'
        )
        closed = Token("html_block", "", 0)
        closed.content = (
            "</div>\n"
            '<p class="q2-pipeline-source-reference">'
            f'<a href="{safe_url}">返回页首交互训练管线</a>'
            "；本节的原始结构与文字仍由 Archive 完整封存。</p>\n"
        )
        tokens.insert(retired_start, opened)
        tokens.insert(retired_end + 1, closed)


def _archive_link_tokens(target: InternalArchiveLink) -> tuple[Token, Token, Token]:
    if target.state in {"provenance", "label", "unresolved"}:
        opened = Token("span_open", "span", 1)
        if target.state == "provenance":
            opened.attrSet("class", "archive-source-provenance")
            opened.attrSet("aria-label", "历史研究源稿说明")
        else:
            opened.attrSet("class", "archive-concept-label")
            opened.attrSet("aria-label", "研究概念")
            opened.attrSet("data-internal-link-state", target.state)
        opened.attrSet("role", "note")
        closed = Token("span_close", "span", -1)
        title = target.title
        if target.state == "unresolved":
            title = re.sub(
                r"^(?:未解析(?:目标|章节|目录|资源|链接)|章节索引未覆盖)\s*[：:]\s*",
                "",
                title,
            ).strip()
        return opened, _text_token(title), closed
    opened = Token("link_open", "a", 1)
    opened.attrSet("href", target.url)
    opened.attrSet(
        "class",
        "archive-internal-link"
        + (" archive-internal-link--unresolved" if target.state != "resolved" else ""),
    )
    opened.attrSet("data-internal-link-state", target.state)
    if target.state != "resolved":
        reason = target.reason or "目标研究文档未进入当前可读 release"
        opened.attrSet("title", reason)
        opened.attrSet("aria-label", f"内部链接未解析：{target.title}")
    closed = Token("link_close", "a", -1)
    return opened, _text_token(target.title), closed


def _resolve_internal_reference(
    reference: str,
    resolver: Callable[[str], InternalArchiveLink],
) -> InternalArchiveLink:
    try:
        return resolver(reference)
    except ArchivePresentationError as error:
        return InternalArchiveLink(
            state="unresolved",
            title=f"未解析链接：{reference}",
            url="#unresolved-archive-link",
            source_path=None,
            reason=str(error),
        )


def _transform_inline_links(
    children: Sequence[Token],
    resolver: Callable[[str], InternalArchiveLink],
    unresolved: list[str],
    link_label_title: Callable[[str], str],
) -> list[Token]:
    transformed: list[Token] = []
    index = 0
    link_depth = 0
    while index < len(children):
        token = children[index]
        if token.type == "link_open":
            href = token.attrGet("href") or ""
            depth = 1
            closing = index + 1
            while closing < len(children) and depth:
                if children[closing].type == "link_open":
                    depth += 1
                elif children[closing].type == "link_close":
                    depth -= 1
                closing += 1
            if depth:
                raise ValueError("Markdown link token is not balanced")
            # The resolver alone decides whether a href is an Archive Markdown
            # identity. Non-Archive links are returned with state ``external``.
            target = _resolve_internal_reference(href, resolver)
            if target.state != "external":
                embedded_citations = [
                    child
                    for child in children[index + 1 : closing - 1]
                    if child.type == "qrh_citation"
                ]
                transformed.extend(_archive_link_tokens(target))
                # 展示层会把路径式标签替换成专业标题；若 Evidence occurrence
                # 正好锚定原链接标签，不能连同旧标签一起丢弃。引用按钮移到
                # 新标题链接之后，仍唯一对应同一来源 byte span。
                transformed.extend(embedded_citations)
                if target.state == "unresolved":
                    unresolved.append(href)
                index = closing
                continue
            link_depth += 1
            transformed.append(token)
            index += 1
            continue
        if token.type == "link_close":
            link_depth = max(0, link_depth - 1)
            transformed.append(token)
            index += 1
            continue
        if link_depth:
            transformed.append(token)
            index += 1
            continue
        if token.type == "code_inline":
            reference = token.content.strip()
            if (
                _RELATIVE_MARKDOWN_REFERENCE_RE.fullmatch(reference)
                or _BARE_MARKDOWN_CODE_REFERENCE_RE.fullmatch(reference)
                or _RELATIVE_DIRECTORY_CODE_REFERENCE_RE.fullmatch(reference)
            ):
                target = _resolve_internal_reference(reference, resolver)
                if target.state != "external":
                    transformed.extend(_archive_link_tokens(target))
                    if target.state == "unresolved":
                        unresolved.append(reference)
                    index += 1
                    continue
        if token.type == "text":
            cursor = 0
            for match in _RELATIVE_MARKDOWN_REFERENCE_RE.finditer(token.content):
                if match.start() > cursor:
                    transformed.append(_text_token(token.content[cursor : match.start()]))
                reference = match.group(0)
                target = _resolve_internal_reference(reference, resolver)
                transformed.extend(_archive_link_tokens(target))
                if target.state == "unresolved":
                    unresolved.append(reference)
                cursor = match.end()
            if cursor:
                if cursor < len(token.content):
                    transformed.append(_text_token(token.content[cursor:]))
            else:
                transformed.append(token)
            index += 1
            continue
        transformed.append(token)
        index += 1
    return transformed


def _apply_presentation_tokens(
    tokens: Sequence[Token],
    *,
    heading_title: Callable[[str], str],
    link_resolver: Callable[[str], InternalArchiveLink],
    visible_text: Callable[[str], str],
    link_label_title: Callable[[str], str],
) -> tuple[str, ...]:
    unresolved: list[str] = []
    for index, token in enumerate(tokens):
        if token.type != "inline" or token.children is None:
            continue
        if index > 0 and tokens[index - 1].type == "heading_open":
            source_title = _title_text(token)
            displayed = heading_title(source_title)
            if displayed != source_title:
                token.children = [_text_token(displayed)]
        token.children = _transform_inline_links(
            token.children, link_resolver, unresolved, link_label_title
        )
        for child in token.children:
            if child.type in {"text", "code_inline"}:
                child.content = visible_text(child.content)
    return tuple(dict.fromkeys(unresolved))


def render_markdown_with_citations(
    source_bytes: bytes,
    citations: Sequence[CitationRenderSpec],
    *,
    heading_anchor_ids: Sequence[str] | None = None,
) -> CitationRenderedDocument:
    """只在临时展示副本插入 occurrence token，不改来源或持久化正文。"""

    text, base, environment, ordered = _citation_render_input(source_bytes, citations)
    parser = _markdown_parser()
    tokens = tuple(parser.parse(text, environment))
    _restore_heading_anchors(tokens, base, heading_anchor_ids)
    _replace_table_alignment_style(tokens)
    rendered = parser.renderer.render(tokens, parser.options, environment)
    cleaned = _clean_html(rendered)
    _validate_citation_rendering(cleaned, ordered)
    return CitationRenderedDocument(
        rendered_html=cleaned,
        citation_ids=tuple(item.citation_id for item in ordered),
    )


def render_markdown_for_presentation(
    source_bytes: bytes,
    citations: Sequence[CitationRenderSpec],
    *,
    heading_title: Callable[[str], str],
    link_resolver: Callable[[str], InternalArchiveLink],
    visible_text: Callable[[str], str] = lambda value: value,
    link_label_title: Callable[[str], str] = lambda value: value,
    heading_anchor_ids: Sequence[str] | None = None,
    pipeline_overview_url: str | None = None,
) -> PresentationRenderedDocument:
    """构建读者版正文，但保留来源 bytes、引用位置和稳定 heading anchor。

    相对 ``.md`` 链接在 Markdown token 层变成平台内标题链接；裸路径和只含
    路径的 code span 使用同一规则。无法定位的目标不会静默保留为死链接，而是
    显示为带 ``unresolved`` 状态的可见标记。
    """

    text, base, environment, ordered = _citation_render_input(source_bytes, citations)
    parser = _markdown_parser()
    tokens = list(parser.parse(text, environment))
    _project_leading_document_metadata(tokens)
    _project_redundant_pipeline_overview(tokens, pipeline_overview_url)
    unresolved = _apply_presentation_tokens(
        tokens,
        heading_title=heading_title,
        link_resolver=link_resolver,
        visible_text=visible_text,
        link_label_title=link_label_title,
    )
    _restore_heading_anchors(tokens, base, heading_anchor_ids)
    _replace_table_alignment_style(tokens)
    rendered = parser.renderer.render(tokens, parser.options, environment)
    cleaned = _clean_html(rendered)
    _validate_citation_rendering(cleaned, ordered)
    return PresentationRenderedDocument(
        rendered_html=cleaned,
        citation_ids=tuple(item.citation_id for item in ordered),
        unresolved_references=unresolved,
    )


__all__ = [
    "ANCHOR_PROTOCOL",
    "CitationRenderedDocument",
    "CitationRenderSpec",
    "CitationProjectionIncomplete",
    "HeadingNode",
    "MarkdownProjection",
    "MathNode",
    "PresentationRenderedDocument",
    "PROJECTOR_VERSION",
    "SAFE_LINK_PROTOCOLS",
    "TocEntry",
    "project_markdown",
    "render_research_text",
    "render_markdown_with_citations",
    "render_markdown_for_presentation",
]
