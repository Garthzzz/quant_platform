from __future__ import annotations

import hashlib
import unittest

from quant_hub.archive.markdown import (
    CitationRenderSpec,
    project_markdown,
    render_markdown_with_citations,
)
from quant_hub.evidence.ids import citation_id_for_marker


class ArchiveCitationRenderingTests(unittest.TestCase):
    def test_occurrence_buttons_are_injected_only_into_a_display_copy(self) -> None:
        source = "# 研究\n\n结论来自 arXiv:2203.05556。\n".encode("utf-8")
        before = bytes(source)
        marker = "arXiv:2203.05556".encode("utf-8")
        start = source.index(marker)
        end = start + len(marker)
        digest = hashlib.sha256(source).hexdigest()
        citation_id = citation_id_for_marker(digest, start, end, marker)
        base = project_markdown(source)

        rendered = render_markdown_with_citations(
            source,
            (
                CitationRenderSpec(
                    citation_id=citation_id,
                    byte_start=start,
                    byte_end=end,
                    raw_marker_sha256=hashlib.sha256(marker).hexdigest(),
                ),
            ),
        )

        self.assertEqual(before, source)
        self.assertEqual((citation_id,), rendered.citation_ids)
        self.assertIn(f'data-citation-id="{citation_id}"', rendered.rendered_html)
        self.assertIn(f'id="citation-{citation_id}"', rendered.rendered_html)
        self.assertIn('aria-haspopup="dialog"', rendered.rendered_html)
        self.assertIn(">1</button>", rendered.rendered_html)
        self.assertIn(f'id="{base.headings[0].anchor_id}"', rendered.rendered_html)
        self.assertNotIn("^src:", rendered.rendered_html)

    def test_literal_token_is_ast_aware_and_code_is_not_activated(self) -> None:
        citation_id = "cit_" + "a" * 52
        source = (
            f"正文 ^src:{{{citation_id}}}\n\n"
            f"`^src:{{{citation_id}}}`\n"
        ).encode("utf-8")
        rendered = project_markdown(source).rendered_html
        self.assertEqual(1, rendered.count("citation-trigger"))
        self.assertIn(f"^src:{{{citation_id}}}", rendered)

    def test_changed_marker_and_overlapping_spans_fail_closed(self) -> None:
        source = b"# T\n\nabcdef\n"
        digest = hashlib.sha256(source).hexdigest()
        first = citation_id_for_marker(digest, 5, 8, source[5:8])
        second = citation_id_for_marker(digest, 7, 10, source[7:10])
        with self.assertRaisesRegex(ValueError, "raw marker hash"):
            render_markdown_with_citations(
                source,
                (CitationRenderSpec(first, 5, 8, "0" * 64),),
            )
        with self.assertRaisesRegex(ValueError, "overlap"):
            render_markdown_with_citations(
                source,
                (
                    CitationRenderSpec(
                        first, 5, 8, hashlib.sha256(source[5:8]).hexdigest()
                    ),
                    CitationRenderSpec(
                        second, 7, 10, hashlib.sha256(source[7:10]).hexdigest()
                    ),
                ),
            )

    def test_occurrence_inside_code_is_not_silently_claimed_as_rendered(self) -> None:
        source = b"# Title\n\n`paper-marker`\n"
        start = source.index(b"paper-marker")
        end = start + len(b"paper-marker")
        citation_id = citation_id_for_marker(
            hashlib.sha256(source).hexdigest(), start, end, source[start:end]
        )
        with self.assertRaisesRegex(ValueError, "interactive AST position"):
            render_markdown_with_citations(
                source,
                (
                    CitationRenderSpec(
                        citation_id=citation_id,
                        byte_start=start,
                        byte_end=end,
                        raw_marker_sha256=hashlib.sha256(source[start:end]).hexdigest(),
                    ),
                ),
            )


if __name__ == "__main__":
    unittest.main()
