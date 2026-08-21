"""Heading-aware, source-bound deterministic chunks."""

from __future__ import annotations

from dataclasses import replace
import hashlib
from typing import Sequence

from .contracts import Chunk, DocumentIR, IRBlock, content_hash


CHUNKER_VERSION = "qrh-heading-aware-chunker/v2-single-block"

_STRUCTURAL_ONLY = frozenset({"list", "list_item", "quote"})
_ATOMIC_KINDS = frozenset({"math", "table", "code"})


def _chunk_id(
    ir: DocumentIR,
    *,
    role: str,
    ordered_span_ids: tuple[str, ...],
    byte_start: int,
    byte_end: int,
    parent_chunk_id: str | None,
    ordinal: int,
) -> str:
    return "chk_" + content_hash(
        "qrh-chunk-id/v1",
        {
            "document_version_id": ir.document_version_id,
            "chunker_version": CHUNKER_VERSION,
            "role": role,
            "ordered_span_ids": ordered_span_ids,
            "byte_start": byte_start,
            "byte_end": byte_end,
            "parent_chunk_id": parent_chunk_id,
            "ordinal": ordinal,
        },
    )[:32]


def _make_chunk(
    ir: DocumentIR,
    blocks: Sequence[IRBlock],
    *,
    role: str = "leaf",
    text: str | None = None,
    byte_start: int | None = None,
    byte_end: int | None = None,
    line_start: int | None = None,
    line_end: int | None = None,
    ordered_span_ids: tuple[str, ...] | None = None,
    parent_chunk_id: str | None = None,
    retrievable: bool = True,
    ordinal: int,
    attributes: dict[str, object] | None = None,
) -> Chunk:
    if not blocks:
        raise ValueError("a chunk must contain at least one IR block")
    span_ids = ordered_span_ids or tuple(block.source_span.span_id for block in blocks)
    start = byte_start if byte_start is not None else min(block.source_span.byte_start for block in blocks)
    end = byte_end if byte_end is not None else max(block.source_span.byte_end for block in blocks)
    start_line = line_start if line_start is not None else min(block.source_span.line_start for block in blocks)
    end_line = line_end if line_end is not None else max(block.source_span.line_end for block in blocks)
    value = text if text is not None else "\n\n".join(block.text for block in blocks if block.text)
    chunk_id = _chunk_id(
        ir,
        role=role,
        ordered_span_ids=span_ids,
        byte_start=start,
        byte_end=end,
        parent_chunk_id=parent_chunk_id,
        ordinal=ordinal,
    )
    return Chunk(
        chunk_id=chunk_id,
        document_id=ir.document_id,
        document_version_id=ir.document_version_id,
        chunker_version=CHUNKER_VERSION,
        role=role,  # type: ignore[arg-type]
        heading_path=blocks[-1].heading_path,
        ordered_span_ids=span_ids,
        byte_start=start,
        byte_end=end,
        line_start=start_line,
        line_end=end_line,
        text=value,
        content_sha256=hashlib.sha256(value.encode("utf-8")).hexdigest(),
        parent_chunk_id=parent_chunk_id,
        retrievable=retrievable,
        attributes=attributes or {},
    )


def _safe_segments(block: IRBlock, max_bytes: int) -> tuple[tuple[int, int, str], ...]:
    raw = block.source_span.text.encode("utf-8")
    if len(raw) <= max_bytes:
        return ((0, len(raw), block.source_span.text),)
    protected = [
        (
            span.byte_start - block.source_span.byte_start,
            span.byte_end - block.source_span.byte_start,
        )
        for span in block.spans
        if span.attributes.get("locator_precision") == "exact"
    ]
    rows: list[tuple[int, int, str]] = []
    start = 0
    while start < len(raw):
        proposed = min(len(raw), start + max_bytes)
        if proposed < len(raw):
            boundary = max(
                raw.rfind(b"\n", start + 1, proposed + 1),
                raw.rfind(b" ", start + 1, proposed + 1),
                raw.rfind(b"\t", start + 1, proposed + 1),
            )
            if boundary > start:
                proposed = boundary + 1
            # A cut may never split a formula, citation, inline code, link or
            # figure occurrence.  Extending to the protected end is preferable
            # to corrupting evidence identity.  This check must happen after
            # whitespace selection because that selection itself can otherwise
            # move the cut back inside a protected occurrence.
            for protected_start, protected_end in protected:
                if protected_start < proposed < protected_end:
                    proposed = protected_end
            while proposed > start:
                try:
                    raw[start:proposed].decode("utf-8", errors="strict")
                    break
                except UnicodeDecodeError:
                    proposed -= 1
            if proposed <= start:
                proposed = min(len(raw), start + max_bytes)
                while proposed < len(raw) and (raw[proposed] & 0b1100_0000) == 0b1000_0000:
                    proposed += 1
        value = raw[start:proposed].decode("utf-8", errors="strict")
        rows.append((start, proposed, value))
        start = proposed
    return tuple(rows)


def _line_break_count(raw: bytes) -> int:
    count = 0
    cursor = 0
    while cursor < len(raw):
        if raw[cursor] == 13 and cursor + 1 < len(raw) and raw[cursor + 1] == 10:
            count += 1
            cursor += 2
        elif raw[cursor] in {10, 13}:
            count += 1
            cursor += 1
        else:
            cursor += 1
    return count


def build_chunks(ir: DocumentIR, *, max_chunk_bytes: int = 2400) -> tuple[Chunk, ...]:
    if max_chunk_bytes < 128:
        raise ValueError("max_chunk_bytes is too small for stable research chunks")
    chunks: list[Chunk] = []
    def append_chunk(row: Chunk) -> None:
        chunks.append(row)

    for block in ir.blocks:
        if block.kind in _STRUCTURAL_ONLY:
            continue
        encoded_bytes = len(block.text.encode("utf-8"))
        contains_citation = any(span.kind == "citation" for span in block.spans)
        if block.kind in _ATOMIC_KINDS or contains_citation or encoded_bytes > max_chunk_bytes:
            segments = _safe_segments(block, max_chunk_bytes)
            if len(segments) == 1:
                append_chunk(_make_chunk(ir, (block,), ordinal=len(chunks) + 1))
                continue
            parent = _make_chunk(
                ir,
                (block,),
                role="parent",
                retrievable=False,
                ordinal=len(chunks) + 1,
                attributes={
                    "oversized_block_kind": block.kind,
                    "child_count": len(segments),
                    "full_locator_span_id": block.source_span.span_id,
                },
            )
            append_chunk(parent)
            raw_block = block.source_span.text.encode("utf-8")
            for segment_ordinal, (relative_start, relative_end, value) in enumerate(segments, 1):
                absolute_start = block.source_span.byte_start + relative_start
                absolute_end = block.source_span.byte_start + relative_end
                included = tuple(
                    span.span_id
                    for span in block.spans
                    if absolute_start <= span.byte_start and span.byte_end <= absolute_end
                )
                child_line_start = block.source_span.line_start + _line_break_count(
                    raw_block[:relative_start]
                )
                child_line_end = block.source_span.line_start + _line_break_count(
                    raw_block[: max(relative_start, relative_end - 1)]
                )
                append_chunk(
                    _make_chunk(
                        ir,
                        (block,),
                        role="child",
                        text=value,
                        byte_start=absolute_start,
                        byte_end=absolute_end,
                        line_start=child_line_start,
                        line_end=child_line_end,
                        ordered_span_ids=(block.source_span.span_id, *included),
                        parent_chunk_id=parent.chunk_id,
                        ordinal=len(chunks) + 1,
                        attributes={
                            "child_ordinal": segment_ordinal,
                            "full_locator_span_id": block.source_span.span_id,
                        },
                    )
                )
            continue
        # A short source block is already the preferred semantic retrieval
        # unit.  Combining adjacent paragraphs under the same heading made
        # positive evidence, conditions, limitations and counterexamples share
        # one locator and allowed context to masquerade as a match.  Heading
        # context remains explicit in ``heading_path`` and adjacency metadata.
        append_chunk(_make_chunk(ir, (block,), ordinal=len(chunks) + 1))

    # Adjacency is descriptive metadata, not part of chunk identity, avoiding a
    # hash dependency cycle while still allowing deterministic navigation.
    return tuple(
        replace(
            row,
            previous_chunk_id=chunks[index - 1].chunk_id if index > 0 else None,
            next_chunk_id=chunks[index + 1].chunk_id if index + 1 < len(chunks) else None,
        )
        for index, row in enumerate(chunks)
    )


__all__ = ["CHUNKER_VERSION", "build_chunks"]
