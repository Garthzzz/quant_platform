from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
from html.parser import HTMLParser
from pathlib import Path
import unittest

from quant_hub.archive.markdown import ANCHOR_PROTOCOL, project_markdown


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ARCHIVE_ROOT = PROJECT_ROOT / "reference" / "archive"


def _q2_v3_path() -> Path:
    candidates = tuple(
        ARCHIVE_ROOT.glob(
            "Q2_*/低信噪比金融工程下神经网络选股训练工厂全维度优化研究.md"
        )
    )
    if len(candidates) != 1:
        raise AssertionError(f"expected one Q2 v3 fixture, found {len(candidates)}")
    return candidates[0]


def _q5_sequence_path() -> Path:
    candidates = tuple((ARCHIVE_ROOT / "Q5").glob("*.md"))
    if len(candidates) != 1:
        raise AssertionError(f"expected one Q5 sequence fixture, found {len(candidates)}")
    return candidates[0]


def _toc_size(entries: tuple[object, ...]) -> int:
    return sum(1 + _toc_size(item.children) for item in entries)


class _HtmlProbe(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.attrs: list[tuple[str, str, str | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.attrs.extend((tag, key, value) for key, value in attrs)


class ArchiveMarkdownProjectionTests(unittest.TestCase):
    def test_real_q2_v3_longform_is_stable_and_source_bytes_remain_identical(self) -> None:
        source_path = _q2_v3_path()
        before = source_path.read_bytes()
        self.assertEqual(len(before), 221_192)
        self.assertEqual(
            hashlib.sha256(before).hexdigest(),
            "e68a63a1883c24cf48de6d4b3f0a9030689feced99e02ea4ed9f33144ed4dc7a",
        )

        first = project_markdown(before)
        second = project_markdown(before)

        self.assertEqual(first, second)
        self.assertEqual(first.document_sha256, hashlib.sha256(before).hexdigest())
        self.assertEqual(first.byte_length, len(before))
        self.assertEqual(first.encoding, "utf-8")
        self.assertEqual(len(first.headings), 132)
        self.assertEqual(_toc_size(first.toc), 132)
        self.assertEqual(len({item.anchor_id for item in first.headings}), 132)
        self.assertTrue(
            all(
                before[item.byte_start : item.byte_end]
                and hashlib.sha256(before[item.byte_start : item.byte_end]).hexdigest()
                == item.source_sha256
                for item in first.headings
            )
        )
        self.assertEqual(first.rendered_html.count("<table>"), 8)
        self.assertEqual(first.rendered_html.count('class="table-scroll"'), 8)
        self.assertGreater(len(first.math_nodes), 100)
        self.assertTrue(any("\\mathrm{IC}^2" in item.tex for item in first.math_nodes))
        self.assertIn("低信噪比金融工程下神经网络选股训练工厂", first.plain_text)
        self.assertEqual(source_path.read_bytes(), before)

    def test_heading_hierarchy_duplicate_titles_and_hash_anchors_are_stable(self) -> None:
        source = (
            "# 重复\n"
            "## 子节\n"
            "## 子节\n"
            "### 详情 $x^2$\n"
            "# 重复\n"
        ).encode("utf-8")
        projection = project_markdown(source)
        headings = projection.headings

        self.assertEqual([item.title_text for item in headings], ["重复", "子节", "子节", "详情 x^2", "重复"])
        self.assertEqual(len({item.anchor_id for item in headings}), 5)
        self.assertEqual(headings[1].parent_anchor_id, headings[0].anchor_id)
        self.assertEqual(headings[2].parent_anchor_id, headings[0].anchor_id)
        self.assertEqual(headings[3].parent_anchor_id, headings[2].anchor_id)
        self.assertIsNone(headings[4].parent_anchor_id)
        self.assertEqual(
            [item.node_path for item in headings],
            [
                "root/h1[1]",
                "root/h1[1]/h2[1]",
                "root/h1[1]/h2[2]",
                "root/h1[1]/h2[2]/h3[1]",
                "root/h1[2]",
            ],
        )
        raw = source[headings[2].byte_start : headings[2].byte_end]
        expected = hashlib.sha256(
            ANCHOR_PROTOCOL
            + projection.document_sha256.encode("ascii")
            + b"\0"
            + headings[2].node_path.encode("utf-8")
            + b"\0"
            + raw
        ).hexdigest()
        self.assertEqual(headings[2].anchor_id, "anc_sha256_" + expected)
        self.assertEqual(project_markdown(source).headings, headings)
        with self.assertRaises(FrozenInstanceError):
            headings[0].level = 6

    def test_setext_and_crlf_multibyte_heading_offsets_point_to_original_bytes(self) -> None:
        source = "中文标题\r\n======\r\n\r\n## 第二节\r\n正文\r\n".encode("utf-8")
        projection = project_markdown(source)
        first, second = projection.headings

        first_end = source.index(b"\r\n\r\n") + len(b"\r\n")
        self.assertEqual((first.level, first.line_start, first.line_end), (1, 1, 2))
        self.assertEqual((first.byte_start, first.byte_end), (0, first_end))
        self.assertEqual(source[first.byte_start : first.byte_end], "中文标题\r\n======\r\n".encode("utf-8"))
        self.assertEqual((second.level, second.line_start, second.line_end), (2, 4, 4))
        self.assertEqual(second.byte_start, source.index("## 第二节".encode("utf-8")))
        self.assertEqual(source[second.byte_start : second.byte_end], "## 第二节\r\n".encode("utf-8"))
        self.assertEqual(second.parent_anchor_id, first.anchor_id)

    def test_raw_html_xss_and_unsafe_link_protocols_fail_closed(self) -> None:
        source = (
            "# 安全\n"
            '<script>alert(1)</script><img src=x onerror="alert(2)">\n\n'
            "[危险](javascript:alert(3)) [数据](data:text/html,bad) "
            "[安全](https://example.com/path)\n"
            '$"><img src=x onerror=alert(4)>$\n'
        ).encode("utf-8")
        projection = project_markdown(source)
        probe = _HtmlProbe()
        probe.feed(projection.rendered_html)

        self.assertNotIn("script", probe.tags)
        self.assertNotIn("img", probe.tags)
        self.assertFalse(any(key.lower().startswith("on") for _, key, _ in probe.attrs))
        hrefs = [value for tag, key, value in probe.attrs if tag == "a" and key == "href"]
        self.assertEqual(hrefs, ["https://example.com/path"])
        self.assertTrue(
            all(
                value is not None
                and value.split(":", 1)[0] in {"http", "https", "mailto"}
                for value in hrefs
            )
        )
        self.assertEqual(len(projection.math_nodes), 1)
        self.assertIn("&lt;img", projection.rendered_html)

    def test_math_is_semantic_text_code_is_not_math_and_tables_scroll_locally(self) -> None:
        source = (
            '数值 $10^{-8}$，货币 $100 与 $200；公式 $x < y$，'
            '展示式 $$\\alpha + "><script>$$。\n\n'
            "代码 `$not_math$`。\n\n"
            "| 指标 | 公式 | 说明 |\n"
            "|:---|---:|:---:|\n"
            "| IC | $\\rho$ | 中文 |\n"
        ).encode("utf-8")
        before = bytes(source)
        projection = project_markdown(source)

        self.assertEqual(
            [item.tex for item in projection.math_nodes],
            ["10^{-8}", "x < y", '\\alpha + "><script>', "\\rho"],
        )
        self.assertEqual(
            [item.display for item in projection.math_nodes],
            [False, False, True, False],
        )
        self.assertIn('<div class="table-scroll" role="region" tabindex="0"', projection.rendered_html)
        self.assertIn('<th align="left">', projection.rendered_html)
        self.assertIn('<th align="right">', projection.rendered_html)
        self.assertIn('<th align="center">', projection.rendered_html)
        self.assertNotIn("<script>", projection.rendered_html)
        self.assertIn("<math", projection.rendered_html)
        self.assertIn('data-math-rendered="mathml"', projection.rendered_html)
        self.assertNotIn("annotation-xml", projection.rendered_html)
        self.assertIn("$not_math$", projection.plain_text)
        self.assertEqual(source, before)

    def test_multiline_display_math_preempts_commonmark_setext_parsing(self) -> None:
        source = (
            "# 序列表征\n\n"
            "$$\n"
            "x_{i,f,t-L+1:t}\n"
            "=\n"
            "\\left[x_{i,f,t-L+1},x_{i,f,t-L+2},\\ldots,x_{i,f,t}\\right].\n"
            "$$\n\n"
            "## 后续章节\n"
        ).encode("utf-8")
        before = bytes(source)
        projection = project_markdown(source)

        self.assertEqual(
            [item.title_text for item in projection.headings],
            ["序列表征", "后续章节"],
        )
        self.assertEqual(len(projection.math_nodes), 1)
        formula = projection.math_nodes[0]
        self.assertTrue(formula.display)
        self.assertEqual(formula.delimiter, "$$")
        self.assertIn("x_{i,f,t-L+1:t}\n=", formula.tex)
        self.assertIn('data-math-rendered="mathml"', projection.rendered_html)
        self.assertNotIn("$$", projection.rendered_html)
        self.assertNotIn("<h1>$$", projection.rendered_html)
        self.assertIn("x_{i,f,t-L+1:t}", projection.plain_text)
        self.assertEqual(source, before)

    def test_multiline_math_removes_blockquote_and_list_container_markup(self) -> None:
        source = (
            "> 引用中的公式：\n>\n"
            "> $$\n"
            "> x_t\n"
            "> =\n"
            "> y_t\n"
            "> $$\n\n"
            "- 列表中的公式\n\n"
            "  $$\n"
            "  a_t=b_t\n"
            "  $$\n"
        ).encode("utf-8")
        projection = project_markdown(source)

        display = [item for item in projection.math_nodes if item.display]
        self.assertEqual([item.tex for item in display], ["x_t\n=\ny_t", "a_t=b_t"])
        self.assertFalse(any(">" in item.tex for item in display))
        self.assertEqual(len(projection.headings), 0)
        self.assertEqual(projection.rendered_html.count('data-math-rendered="mathml"'), 2)

    def test_empty_and_unclosed_display_math_are_visible_invalid_blocks_not_headings(self) -> None:
        source = (
            "$$\n$$\n\n"
            "$$\n"
            "x_t\n"
            "=\n"
            "y_t\n"
        ).encode("utf-8")
        projection = project_markdown(source)

        self.assertEqual(len(projection.math_nodes), 0)
        self.assertEqual(len(projection.headings), 0)
        self.assertEqual(projection.rendered_html.count("math-invalid"), 2)
        self.assertIn("<code class=\"math-source\">$$\n$$</code>", projection.rendered_html)
        self.assertIn("x_t\n=\ny_t", projection.rendered_html)

    def test_real_q5_multiline_math_has_no_spurious_formula_headings(self) -> None:
        source_path = _q5_sequence_path()
        before = source_path.read_bytes()
        self.assertEqual(len(before), 225_079)
        self.assertEqual(
            hashlib.sha256(before).hexdigest(),
            "4994d1df74414fdadfefb7ba812c3851ef26fd82c36bc7f174c7db577e756679",
        )

        projection = project_markdown(before)

        # 304 个 ATX heading，加上来源中一处合法 CommonMark Setext heading。
        self.assertEqual(len(projection.headings), 305)
        self.assertEqual(len(projection.math_nodes), 1_423)
        self.assertEqual(sum(item.display for item in projection.math_nodes), 361)
        self.assertEqual(
            projection.rendered_html.count('data-math-rendered="mathml"'), 1_423
        )
        self.assertNotIn('data-math-rendered="fallback"', projection.rendered_html)
        self.assertNotIn("math-invalid", projection.rendered_html)
        self.assertEqual(projection.rendered_html.count('class="table-scroll"'), 45)
        self.assertFalse(any("$$" in item.title_text for item in projection.headings))
        # 仅保留写作规范中反引号包裹的 delimiter 示例；公式 delimiter 全部消费。
        self.assertEqual(projection.rendered_html.count("$$"), 2)
        self.assertIn("<code>$$...$$</code>", projection.rendered_html)
        self.assertEqual(source_path.read_bytes(), before)

    def test_invalid_utf8_and_mutable_input_are_rejected_without_replacement(self) -> None:
        with self.assertRaises(UnicodeDecodeError):
            project_markdown(b"valid\n\xff")
        with self.assertRaises(TypeError):
            project_markdown(bytearray(b"# heading"))


if __name__ == "__main__":
    unittest.main()
