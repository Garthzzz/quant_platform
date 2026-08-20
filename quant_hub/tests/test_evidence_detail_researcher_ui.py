from __future__ import annotations

from pathlib import Path
import re
import unittest

from quant_hub.archive.markdown import render_research_text
from quant_hub.evidence.service import _clean_archive_context


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DETAIL_TEMPLATE = (
    PROJECT_ROOT
    / "src"
    / "quant_hub"
    / "evidence"
    / "templates"
    / "evidence"
    / "detail.html"
)
EVIDENCE_STYLES = (
    PROJECT_ROOT / "src" / "quant_hub" / "evidence" / "static" / "evidence.css"
)


class EvidenceDetailResearcherUiTests(unittest.TestCase):
    def test_relation_context_truncation_never_splits_a_complete_formula(self) -> None:
        source = "前置研究语境。" + ("说明" * 20) + r" $\Omega + \sqrt{n}$ 后续结论。"
        rendered = _clean_archive_context(source, limit=55)

        self.assertNotIn(r"$\Omega", rendered)
        self.assertTrue(rendered.endswith("…"))

    def test_research_fields_render_mathml_without_exposing_raw_tex(self) -> None:
        rendered = render_research_text(
            r"The class $\Omega''$ is studied; 在 $(s, r)$ 双变量正态假设下成立。"
        )

        self.assertEqual(2, rendered.count('data-math-rendered="mathml"'))
        self.assertIn("<math", rendered)
        self.assertNotIn(r"$\Omega", rendered)
        self.assertNotIn("$(s, r)$", rendered)

    def test_research_fields_keep_untrusted_html_inert(self) -> None:
        rendered = render_research_text(
            r"<script>alert(1)</script> and $x\Phi(x)$"
        )

        self.assertNotIn("<script", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn('data-math-rendered="mathml"', rendered)

    def test_research_fields_normalize_bounded_legacy_latex_commands(self) -> None:
        rendered = render_research_text(
            r"\emph{Robust result}; \cite{hoeffding1948,kruskal1958}; "
            r"\url{https://example.test/paper}; \ref{eq_main}; "
            r"\text{cost-adjusted return}."
        )

        self.assertIn("<em>Robust result</em>", rendered)
        self.assertIn("Hoeffding (1948)", rendered)
        self.assertIn("Kruskal (1958)", rendered)
        self.assertIn("https://example.test/paper", rendered)
        self.assertIn("参见eq main", rendered)
        self.assertIn("cost-adjusted return", rendered)
        self.assertNotRegex(rendered, r"\\(?:emph|cite|url|ref|text)\b")

    def test_tex_text_command_inside_math_is_preserved_for_mathml(self) -> None:
        rendered = render_research_text(r"目标为 $\text{cost-adjusted return}_t$。")

        self.assertIn('data-math-rendered="mathml"', rendered)
        self.assertNotIn(r"$\text{cost-adjusted return}", rendered)

    def test_nested_arxiv_text_styling_is_not_split_into_false_math(self) -> None:
        rendered = render_research_text(
            r"$\textit{Evo$\textbf{L}$ved S$\textbf{i}$gn "
            r"M$\textbf{o}$me$\textbf{n}$tum}$"
        )

        self.assertIn("EvoLved Sign Momentum", rendered)
        self.assertNotIn("data-math-rendered", rendered)
        self.assertNotRegex(rendered, r"\\text(?:it|bf)\b")

    def test_detail_keeps_source_actions_in_hero_and_research_content_full_width(
        self,
    ) -> None:
        template = DETAIL_TEMPLATE.read_text(encoding="utf-8")
        hero_end = template.index("</section>")
        article_start = template.index(
            '<article class="evidence-detail-main evidence-detail-main--wide">'
        )

        self.assertLess(template.index('class="evidence-hero-actions"'), hero_end)
        self.assertLess(hero_end, article_start)
        self.assertIn('data-evidence-page="detail"', template)
        self.assertEqual(
            1, template.count('data-acceptance-content="external-original"')
        )
        self.assertEqual(
            1, template.count('data-acceptance-content="local-original"')
        )
        self.assertRegex(
            template,
            r'data-acceptance-content="external-original"[\s\S]*?'
            r'<a class="evidence-action evidence-action--secondary"[^>]*'
            r'data-evidence-present="true"[^>]*>原文来源</a>',
        )
        self.assertRegex(
            template,
            r'data-acceptance-content="local-original"[\s\S]*?'
            r'<a class="evidence-action evidence-action--primary"[^>]*'
            r'data-evidence-present="true"[^>]*>打开本地 PDF</a>',
        )

    def test_detail_excludes_internal_audit_fields_from_researcher_view(self) -> None:
        template = DETAIL_TEMPLATE.read_text(encoding="utf-8")
        forbidden = (
            "机构核验状态",
            "verification_status",
            "provenance",
            "sha256",
            "source_verified",
            "事实边界",
            "标识与类别",
            "bytes",
            "rights_status",
            "source_locator",
            "evidence-detail-aside",
        )

        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token, template)

    def test_all_research_narrative_fields_use_the_safe_math_filter(self) -> None:
        template = DETAIL_TEMPLATE.read_text(encoding="utf-8")

        for expression in (
            "excerpt.text|research_text",
            "excerpt.chinese_presentation.abstract_translation_zh|research_text",
            "item.text|research_text",
            "paper.chinese_presentation.synthesis_zh|research_text",
            "relation.usage_description|research_text",
            "relation.source_excerpt|research_text",
        ):
            with self.subTest(expression=expression):
                self.assertIn(expression, template)

    def test_relation_cards_expose_stable_researcher_facing_structure(self) -> None:
        template = DETAIL_TEMPLATE.read_text(encoding="utf-8")

        for class_name in (
            "evidence-relation-topic",
            "evidence-relation-title",
            "evidence-relation-document-link",
            "evidence-relation-section",
            "evidence-relation-kind",
            "evidence-relation-usage",
            "evidence-relation-excerpt",
            "evidence-source-jump",
        ):
            with self.subTest(class_name=class_name):
                self.assertIn(class_name, template)

        self.assertLess(
            template.index('class="evidence-relation-topic"'),
            template.index('class="evidence-relation-title"'),
        )
        self.assertRegex(
            template,
            r'class="evidence-relation-title"><a '
            r'class="evidence-relation-document-link"[^>]*>'
            r'\{\{ relation\.document_title \}\}</a>',
        )

        for label in (
            "在 Archive 量化研究中的应用",
            "引用方式",
            "在量化研究中的具体用法",
            "查看研究正文",
        ):
            with self.subTest(label=label):
                self.assertIn(label, template)

    def test_styles_contain_layout_and_overflow_guards(self) -> None:
        css = EVIDENCE_STYLES.read_text(encoding="utf-8")

        self.assertRegex(
            css,
            r"\.evidence-hero\s*\{[^}]*grid-template-columns:\s*"
            r"minmax\(0,\s*1fr\)\s+auto",
        )
        self.assertRegex(
            css,
            r"\.evidence-detail-main--wide\s*\{[^}]*width:\s*100%"
            r"[^}]*max-width:\s*100%",
        )
        self.assertRegex(
            css,
            r'\.evidence-shell\[data-evidence-page="detail"\]\s*\{[^}]*'
            r"max-width:\s*104rem[^}]*margin-inline:\s*auto",
        )
        self.assertIn("overflow-wrap: anywhere", css)
        self.assertRegex(
            css,
            r"\.evidence-relation-body\s*>\s*\*\s*\{\s*min-width:\s*0",
        )
        self.assertRegex(
            css,
            r"\.evidence-shell\s+:where\([^}]*\.math-display[^}]*\)\s*"
            r"\{[^}]*overflow-x:\s*auto",
        )
        self.assertIn("overscroll-behavior-inline: contain", css)
        self.assertRegex(
            css,
            r'\[data-math-rendered="mathml"\]\s*>\s*'
            r"\.math-source--fallback\s*\{[^}]*display:\s*none",
        )
        self.assertNotRegex(css, re.compile(r"transition\s*:\s*all\b", re.I))


if __name__ == "__main__":
    unittest.main()
