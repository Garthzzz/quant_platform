"""Deterministic Document IR built on the established Archive Markdown parser."""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import asdict
import hashlib
import re
from typing import Any, Iterable, Sequence

from markdown_it.token import Token

from quant_hub.archive.markdown import (
    PROJECTOR_VERSION,
    _inline_plain_text,
    _markdown_parser,
    project_markdown,
)

from .contracts import DocumentIR, IRBlock, SourceSpan, content_hash


IR_SCHEMA_VERSION = "qrh-document-ir/v1"
IR_PARSER_VERSION = f"{IR_SCHEMA_VERSION}.1-bare-url+{PROJECTOR_VERSION}"

_BARE_URL_RE = re.compile(rb"https?://[^\s<>\"'`]+", re.IGNORECASE)
_ALWAYS_TRAILING_URL_PUNCTUATION = ".,;:!?，。；：！？、*"
_BALANCED_CLOSERS = {")": "(", "]": "[", "}": "{"}


class DocumentIRValidationError(ValueError):
    pass


def _line_byte_starts(source_bytes: bytes) -> tuple[int, ...]:
    starts = [0]
    cursor = 0
    while cursor < len(source_bytes):
        value = source_bytes[cursor]
        if value == 13 and cursor + 1 < len(source_bytes) and source_bytes[cursor + 1] == 10:
            cursor += 2
            starts.append(cursor)
        elif value in {10, 13}:
            cursor += 1
            starts.append(cursor)
        else:
            cursor += 1
    return tuple(starts)


def _byte_at_line(starts: Sequence[int], line: int, byte_length: int) -> int:
    if line < 0:
        raise DocumentIRValidationError("negative token line")
    if line < len(starts):
        return int(starts[line])
    if line == len(starts):
        return byte_length
    raise DocumentIRValidationError("token line escapes source")


def _line_at_byte(starts: Sequence[int], position: int) -> int:
    return max(1, bisect_right(starts, position))


def _span(
    *,
    document_version_id: str,
    source_bytes: bytes,
    source_sha256: str,
    line_starts: Sequence[int],
    kind: str,
    byte_start: int,
    byte_end: int,
    attributes: dict[str, Any] | None = None,
) -> SourceSpan:
    if not 0 <= byte_start < byte_end <= len(source_bytes):
        raise DocumentIRValidationError(f"invalid {kind} source span")
    raw = source_bytes[byte_start:byte_end]
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise DocumentIRValidationError("source span is not valid UTF-8") from error
    text_sha256 = hashlib.sha256(raw).hexdigest()
    span_id = "spn_" + content_hash(
        "qrh-source-span/v1",
        {
            "document_version_id": document_version_id,
            "kind": kind,
            "byte_start": byte_start,
            "byte_end": byte_end,
            "text_sha256": text_sha256,
            "attributes": attributes or {},
        },
    )[:32]
    return SourceSpan(
        span_id=span_id,
        kind=kind,
        line_start=_line_at_byte(line_starts, byte_start),
        line_end=_line_at_byte(line_starts, max(byte_start, byte_end - 1)),
        byte_start=byte_start,
        byte_end=byte_end,
        source_sha256=source_sha256,
        text_sha256=text_sha256,
        text=text,
        attributes=attributes or {},
    )


def _token_map_span(
    token: Token,
    *,
    document_version_id: str,
    source_bytes: bytes,
    source_sha256: str,
    line_starts: Sequence[int],
    kind: str,
    attributes: dict[str, Any] | None = None,
) -> SourceSpan:
    if token.map is None:
        raise DocumentIRValidationError(f"{token.type} has no source line map")
    start = _byte_at_line(line_starts, int(token.map[0]), len(source_bytes))
    end = _byte_at_line(line_starts, int(token.map[1]), len(source_bytes))
    return _span(
        document_version_id=document_version_id,
        source_bytes=source_bytes,
        source_sha256=source_sha256,
        line_starts=line_starts,
        kind=kind,
        byte_start=start,
        byte_end=end,
        attributes=attributes,
    )


def _locate_inline_bytes(
    block_span: SourceSpan,
    needle: bytes,
    *,
    cursor: int,
) -> tuple[int, int, int, str]:
    raw = block_span.text.encode("utf-8")
    relative = raw.find(needle, cursor)
    if relative < 0:
        relative = raw.find(needle)
    if relative < 0:
        return block_span.byte_start, block_span.byte_end, cursor, "block"
    return (
        block_span.byte_start + relative,
        block_span.byte_start + relative + len(needle),
        relative + len(needle),
        "exact",
    )


def _inline_spans(
    inline: Token,
    *,
    block_span: SourceSpan,
    document_version_id: str,
    source_bytes: bytes,
    source_sha256: str,
    line_starts: Sequence[int],
) -> tuple[SourceSpan, ...]:
    rows: list[SourceSpan] = []
    cursor = 0
    link_stack: list[dict[str, str]] = []
    raw_block = block_span.text.encode("utf-8")

    def append_at(
        kind: str,
        relative_start: int,
        relative_end: int,
        attributes: dict[str, Any],
        *,
        precision: str,
    ) -> None:
        occurrence = len(rows) + 1
        rows.append(
            _span(
                document_version_id=document_version_id,
                source_bytes=source_bytes,
                source_sha256=source_sha256,
                line_starts=line_starts,
                kind=kind,
                byte_start=block_span.byte_start + relative_start,
                byte_end=block_span.byte_start + relative_end,
                attributes={
                    **attributes,
                    "locator_precision": precision,
                    "occurrence_ordinal": occurrence,
                },
            )
        )

    def add(kind: str, needle: str, attributes: dict[str, Any]) -> None:
        nonlocal cursor
        encoded = needle.encode("utf-8")
        start, end, cursor, precision = _locate_inline_bytes(
            block_span, encoded, cursor=cursor
        )
        append_at(
            kind,
            start - block_span.byte_start,
            end - block_span.byte_start,
            attributes,
            precision=precision,
        )

    def add_markdown_target(kind: str, target: str, attributes: dict[str, Any]) -> None:
        """Locate a Markdown destination rather than a same-text link label."""

        nonlocal cursor
        encoded = target.encode("utf-8")
        escaped = re.escape(encoded)
        patterns = (
            re.compile(rb"\]\(\s*<?(?P<target>" + escaped + rb")>?"),
            re.compile(rb"<(?P<target>" + escaped + rb")>"),
        )
        for pattern in patterns:
            match = pattern.search(raw_block, cursor) or pattern.search(raw_block)
            if match is None:
                continue
            relative_start, relative_end = match.span("target")
            cursor = max(cursor, relative_end)
            append_at(
                kind,
                relative_start,
                relative_end,
                attributes,
                precision="exact",
            )
            return
        add(kind, target, attributes)

    for child in inline.children or ():
        if child.type in {"qrh_math", "qrh_math_block"}:
            opener = child.markup
            closer = {"\\[": "\\]", "\\(": "\\)"}.get(opener, opener)
            add(
                "math",
                f"{opener}{child.content}{closer}",
                {"display": bool(child.meta.get("display")), "tex": child.content},
            )
        elif child.type == "qrh_citation":
            add("citation", f"^src:{{{child.content}}}", {"citation_id": child.content})
        elif child.type == "image":
            target = str(child.attrGet("src") or "")
            add_markdown_target(
                "figure_ref",
                target or child.content,
                {
                    "target": target,
                    "alt": child.content,
                    "caption": child.content,
                    "title": str(child.attrGet("title") or ""),
                },
            )
        elif child.type == "link_open":
            target = str(child.attrGet("href") or "")
            link_stack.append({"target": target})
            add_markdown_target(
                "link",
                target,
                {"target": target, "external": bool(re.match(r"https?://", target))},
            )
        elif child.type == "link_close" and link_stack:
            link_stack.pop()
        elif child.type == "code_inline":
            markup = child.markup or "`"
            add("inline_code", f"{markup}{child.content}{markup}", {"code": child.content})

    # ``linkify`` intentionally remains disabled in the established renderer.
    # Generic pages still need deterministic source locators for formal source
    # lists that use bare URLs.  Derive these occurrences from the immutable
    # block bytes and never mutate or re-render the legacy Markdown projection.
    occupied = tuple(
        (span.byte_start - block_span.byte_start, span.byte_end - block_span.byte_start)
        for span in rows
        if span.attributes.get("locator_precision") == "exact"
    )
    for match in _BARE_URL_RE.finditer(raw_block):
        relative_start, raw_end = match.span()
        if any(start < raw_end and relative_start < end for start, end in occupied):
            continue
        candidate = match.group(0).decode("utf-8", errors="strict")
        candidate = candidate.rstrip(_ALWAYS_TRAILING_URL_PUNCTUATION)
        while candidate and candidate[-1] in _BALANCED_CLOSERS:
            closer = candidate[-1]
            opener = _BALANCED_CLOSERS[closer]
            if candidate.count(closer) <= candidate.count(opener):
                break
            candidate = candidate[:-1].rstrip(_ALWAYS_TRAILING_URL_PUNCTUATION)
        if not candidate or candidate in {"http://", "https://"}:
            continue
        encoded = candidate.encode("utf-8")
        relative_end = relative_start + len(encoded)
        # A Markdown destination should already have an exact parser-derived
        # occurrence.  This syntax check is an additional fail-closed guard
        # against duplicate links if a future parser normalizes its target.
        prefix = raw_block[max(0, relative_start - 16) : relative_start]
        if re.search(rb"\]\(\s*<?$", prefix) or prefix.endswith(b"<"):
            continue
        append_at(
            "link",
            relative_start,
            relative_end,
            {"target": candidate, "external": True, "bare": True},
            precision="exact",
        )
    return tuple(sorted(rows, key=lambda span: (span.byte_start, span.byte_end, span.kind)))


def _front_matter(text: str) -> dict[str, str]:
    lines = text.splitlines()
    if len(lines) < 3 or lines[0].strip() != "---":
        return {}
    result: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            return result
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9_-]{0,63})\s*:\s*(.*?)\s*", line)
        if match is None:
            return {}
        result[match.group(1)] = match.group(2)
    return {}


def _table_attributes(tokens: Sequence[Token], start: int) -> tuple[dict[str, Any], int]:
    matrix: list[list[str]] = []
    row: list[str] | None = None
    alignments: list[str | None] = []
    depth = 0
    cursor = start
    while cursor < len(tokens):
        token = tokens[cursor]
        if token.type == "table_open":
            depth += 1
        elif token.type == "table_close":
            depth -= 1
            if depth == 0:
                break
        elif token.type == "tr_open":
            row = []
        elif token.type == "tr_close" and row is not None:
            matrix.append(row)
            row = None
        elif token.type in {"th_open", "td_open"}:
            style = token.attrGet("style") or token.attrGet("align")
            if len(matrix) == 0:
                match = re.search(r"(left|center|right)", str(style or ""))
                alignments.append(match.group(1) if match else None)
        elif token.type == "inline" and row is not None:
            row.append(_inline_plain_text(token.children or ()).strip())
        cursor += 1
    if depth != 0:
        raise DocumentIRValidationError("unclosed Markdown table token stream")
    return {"cell_matrix": matrix, "alignments": alignments}, cursor


def build_document_ir(
    source_bytes: bytes,
    *,
    document_id: str,
    document_version_id: str,
    logical_path: str,
) -> tuple[DocumentIR, str]:
    """Build source-bound IR and return it with the mature renderer HTML.

    ``project_markdown`` remains the single rendering/parser compatibility
    authority.  The second parser pass only derives source-bound structure from
    the same configured MarkdownIt rules; it does not implement Markdown again.
    """

    if type(source_bytes) is not bytes:
        raise TypeError("source_bytes must be immutable bytes")
    text = source_bytes.decode("utf-8", errors="strict")
    projection = project_markdown(source_bytes)
    if not projection.headings or not any(item.title_text.strip() for item in projection.headings):
        raise DocumentIRValidationError("document has no recognizable heading")

    parser = _markdown_parser()
    tokens = tuple(parser.parse(text, {}))
    line_starts = _line_byte_starts(source_bytes)
    source_sha256 = projection.document_sha256
    blocks: list[IRBlock] = []
    structural_stack: list[tuple[str, str]] = []
    heading_stack: list[tuple[int, str]] = []
    heading_ordinal = 0

    def add_block(
        kind: str,
        token: Token,
        *,
        text_value: str,
        attributes: dict[str, Any] | None = None,
        inline: Token | None = None,
        heading_path: tuple[str, ...] | None = None,
    ) -> IRBlock:
        source_span = _token_map_span(
            token,
            document_version_id=document_version_id,
            source_bytes=source_bytes,
            source_sha256=source_sha256,
            line_starts=line_starts,
            kind=kind,
        )
        ordinal = len(blocks) + 1
        block_id = "blk_" + content_hash(
            "qrh-ir-block/v1",
            {
                "document_version_id": document_version_id,
                "ordinal": ordinal,
                "kind": kind,
                "span_id": source_span.span_id,
            },
        )[:32]
        child_spans = (
            _inline_spans(
                inline,
                block_span=source_span,
                document_version_id=document_version_id,
                source_bytes=source_bytes,
                source_sha256=source_sha256,
                line_starts=line_starts,
            )
            if inline is not None
            else ()
        )
        row = IRBlock(
            block_id=block_id,
            kind=kind,
            source_span=source_span,
            heading_path=heading_path
            if heading_path is not None
            else tuple(value for _, value in heading_stack),
            parent_block_id=structural_stack[-1][1] if structural_stack else None,
            text=text_value,
            attributes=attributes or {},
            spans=child_spans,
        )
        blocks.append(row)
        return row

    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.type == "heading_open":
            if index + 1 >= len(tokens) or tokens[index + 1].type != "inline":
                raise DocumentIRValidationError("heading has no inline token")
            heading_ordinal += 1
            heading = projection.headings[heading_ordinal - 1]
            while heading_stack and heading_stack[-1][0] >= heading.level:
                heading_stack.pop()
            heading_stack.append((heading.level, heading.anchor_id))
            add_block(
                "heading",
                token,
                text_value=heading.title_text,
                attributes={
                    "level": heading.level,
                    "anchor_id": heading.anchor_id,
                    "node_path": heading.node_path,
                    "parent_anchor_id": heading.parent_anchor_id,
                },
                inline=tokens[index + 1],
                heading_path=tuple(value for _, value in heading_stack),
            )
        elif token.type in {"blockquote_open", "bullet_list_open", "ordered_list_open", "list_item_open"}:
            kind = {
                "blockquote_open": "quote",
                "bullet_list_open": "list",
                "ordered_list_open": "list",
                "list_item_open": "list_item",
            }[token.type]
            row = add_block(
                kind,
                token,
                text_value=token.markup,
                attributes={"ordered": token.type == "ordered_list_open"},
            )
            structural_stack.append((token.type.removesuffix("_open"), row.block_id))
        elif token.type in {"blockquote_close", "bullet_list_close", "ordered_list_close", "list_item_close"}:
            expected = token.type.removesuffix("_close")
            if not structural_stack or structural_stack[-1][0] != expected:
                raise DocumentIRValidationError("Markdown structural token stack is unbalanced")
            structural_stack.pop()
        elif token.type == "paragraph_open":
            if index + 1 >= len(tokens) or tokens[index + 1].type != "inline":
                raise DocumentIRValidationError("paragraph has no inline token")
            inline = tokens[index + 1]
            add_block(
                "paragraph",
                token,
                text_value=_inline_plain_text(inline.children or ()).strip(),
                inline=inline,
            )
        elif token.type == "table_open":
            attributes, table_end = _table_attributes(tokens, index)
            row_text = "\n".join("\t".join(row) for row in attributes["cell_matrix"])
            add_block("table", token, text_value=row_text, attributes=attributes)
            index = table_end
        elif token.type in {"fence", "code_block"}:
            language = (token.info or "").strip().split(maxsplit=1)[0] if token.info else ""
            add_block(
                "code",
                token,
                text_value=token.content,
                attributes={"language": language, "markup": token.markup},
            )
        elif token.type in {"qrh_math_block", "qrh_math_invalid"}:
            add_block(
                "math",
                token,
                text_value=token.content,
                attributes={
                    "display": token.type == "qrh_math_block",
                    "valid": token.type != "qrh_math_invalid",
                    "delimiter": token.markup,
                    "tex": token.content if token.type == "qrh_math_block" else None,
                },
            )
        index += 1

    if structural_stack:
        raise DocumentIRValidationError("Markdown structural token stack was not closed")
    if heading_ordinal != len(projection.headings):
        raise DocumentIRValidationError("heading projection and IR parser disagree")

    metadata: dict[str, Any] = {
        "title": projection.headings[0].title_text,
        "encoding": projection.encoding,
        "source_bytes": len(source_bytes),
        "source_sha256": source_sha256,
        "heading_count": len(projection.headings),
        "math_count": len(projection.math_nodes),
        "front_matter": _front_matter(text),
        "render_projector_version": projection.projector_version,
    }
    provisional = DocumentIR(
        schema_version=IR_SCHEMA_VERSION,
        parser_version=IR_PARSER_VERSION,
        source_sha256=source_sha256,
        source_bytes=len(source_bytes),
        document_id=document_id,
        document_version_id=document_version_id,
        logical_path=logical_path,
        title=projection.headings[0].title_text,
        metadata=metadata,
        blocks=tuple(blocks),
        ir_hash="",
    )
    payload = asdict(provisional)
    payload.pop("ir_hash")
    ir_hash = content_hash("qrh-document-ir-object/v1", payload)
    return (
        DocumentIR(
            schema_version=provisional.schema_version,
            parser_version=provisional.parser_version,
            source_sha256=provisional.source_sha256,
            source_bytes=provisional.source_bytes,
            document_id=provisional.document_id,
            document_version_id=provisional.document_version_id,
            logical_path=provisional.logical_path,
            title=provisional.title,
            metadata=provisional.metadata,
            blocks=provisional.blocks,
            ir_hash=ir_hash,
        ),
        projection.rendered_html,
    )


__all__ = [
    "DocumentIRValidationError",
    "IR_PARSER_VERSION",
    "IR_SCHEMA_VERSION",
    "build_document_ir",
]
