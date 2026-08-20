from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import unittest

from quant_hub.archive.catalog import ArchiveCatalog
from quant_hub.archive.markdown import project_markdown, render_markdown_for_presentation
from quant_hub.presentation import ArchivePresentation, InternalArchiveLink


class ArchivePresentationTests(unittest.TestCase):
    def test_public_manifest_orients_and_groups_all_current_documents_exactly_once(self) -> None:
        presentation = ArchivePresentation.default()
        assert presentation.source is not None
        payload = json.loads(presentation.source.read_text(encoding="utf-8"))
        research = payload["research"]
        expected_counts = {
            "q1-product-factor-evaluation": 10,
            "q2-low-snr-neural-selection-factory": 12,
            "q3-training-method-reliability": 12,
            "q4-operations-post-deployment-monitoring": 6,
            "q5-factor-history-sequence-compression": 1,
            "poff-cross-cutting-diagnostics": 5,
            "archive-experiments-e1-e8": 1,
        }
        self.assertEqual(set(expected_counts), set(research))

        archive_root = Path(__file__).resolve().parents[2] / "reference" / "archive"
        archive_root = archive_root.resolve(strict=True)
        all_paths: set[str] = set()
        temporary_title = re.compile(
            r"(?:^|[\s：—])(?:STEP|Round|Lit Review|TODO)(?:$|[\s：—])"
            r"|详解版|这里放什么|doc-[0-9a-f]",
            flags=re.IGNORECASE,
        )
        for slug, expected_count in expected_counts.items():
            row = research[slug]
            titles = row["document_titles"]
            self.assertEqual(expected_count, len(titles), slug)

            orientation = row["orientation"]
            self.assertTrue(orientation["question"].strip(), slug)
            self.assertTrue(orientation["decision"].strip(), slug)
            self.assertGreater(len(orientation["stages"]), 0, slug)
            for stage in orientation["stages"]:
                self.assertEqual({"title", "description"}, set(stage), slug)
                self.assertTrue(stage["title"].strip(), slug)
                self.assertTrue(stage["description"].strip(), slug)

            groups = row["document_groups"]
            self.assertGreater(len(groups), 0, slug)
            self.assertEqual(len(groups), len({group["key"] for group in groups}), slug)
            group_paths = [
                path
                for group in groups
                for path in group.get("paths", [])
            ]
            self.assertTrue(
                all(not group.get("prefixes") for group in groups),
                f"{slug} must use exact paths for auditable current-release coverage",
            )
            self.assertEqual(len(group_paths), len(set(group_paths)), slug)
            self.assertEqual(set(titles), set(group_paths), slug)
            grouped = presentation.group_documents(
                slug,
                [{"source_path": source_path} for source_path in titles],
            )
            projected_paths = [
                document["source_path"]
                for group in grouped
                for document in group["documents"]
            ]
            self.assertEqual(group_paths, projected_paths, slug)

            landing = row["landing_document_path"]
            self.assertIn(landing, titles, slug)
            self.assertEqual(landing, groups[0]["paths"][0], slug)
            review = row.get("review_document_path")
            if review is not None:
                self.assertIn(review, titles, slug)

            for source_path, title in titles.items():
                self.assertNotIn(source_path, all_paths, source_path)
                all_paths.add(source_path)
                self.assertFalse(temporary_title.search(title), title)
                target = (archive_root / Path(source_path)).resolve(strict=True)
                self.assertTrue(target.is_relative_to(archive_root), source_path)
                self.assertTrue(target.is_file(), source_path)
                self.assertEqual(
                    title,
                    presentation.document_title(slug, source_path, "来源标题", "fallback"),
                )

        self.assertEqual(47, len(all_paths))
        self.assertEqual(
            "Q2_如何造一个好的工厂/综述.md",
            research["q2-low-snr-neural-selection-factory"]["landing_document_path"],
        )
        experiment = research["archive-experiments-e1-e8"]
        self.assertIn("八类受控实验", experiment["summary"])
        self.assertIn("基线、唯一变化项、评价指标和证据去向", experiment["summary"])
        self.assertNotIn("当前", experiment["summary"])
        self.assertNotIn("待补齐", experiment["summary"])

    def test_all_active_subtitles_are_professional_and_archive_tree_is_immutable(self) -> None:
        presentation = ArchivePresentation.default()
        assert presentation.source is not None
        payload = json.loads(presentation.source.read_text(encoding="utf-8"))
        archive_root = Path(__file__).resolve().parents[2] / "reference" / "archive"
        source_paths = [
            source_path
            for research in payload["research"].values()
            for source_path in research["document_titles"]
        ]

        def tree_identity() -> tuple[int, int, str]:
            digest = hashlib.sha256()
            count = 0
            size = 0
            files = sorted(
                (path for path in archive_root.rglob("*") if path.is_file()),
                key=lambda path: path.relative_to(archive_root).as_posix(),
            )
            for path in files:
                relative = path.relative_to(archive_root).as_posix()
                raw = path.read_bytes()
                digest.update(relative.encode("utf-8"))
                digest.update(b"\0")
                digest.update(str(len(raw)).encode("ascii"))
                digest.update(b"\0")
                digest.update(hashlib.sha256(raw).hexdigest().encode("ascii"))
                digest.update(b"\n")
                count += 1
                size += len(raw)
            return count, size, digest.hexdigest()

        before = tree_identity()
        self.assertEqual(
            # 2026-07-30 用户将完整 Yao 实验包（63 files /
            # 21,592,279 bytes）加入只读 Archive；冻结基线只提升这一批来源。
            (226, 37_808_488, "6f4873f95ce3ca395e8c512508922d6050ddb9c240dd11ff68934a8deec61b3a"),
            before,
        )

        temporary_navigation = re.compile(
            r"(?i)(?:^|[\s：—/（）()_-])(?:step|round|phase|todo|tbd|wip)"
            r"(?:$|[\s：—/（）()_-]|\d)"
        )
        colloquial = re.compile(
            r"这里|这个(?:问题|专区|专题|文档|指标)|放什么|收什么|"
            r"怎么(?:开始|读|用|看|做|选|区分|理解|压|变|堆叠|逐层)|"
            r"一句话|可能的问题|常见坑|有哪些坑|要点先说|先给结论|到底|不要无脑"
        )
        status_label = re.compile(
            r"已做|待做|未做|下一步|当前状态|完成情况|工作进展|后续工作|"
            r"待补|待验证|进行中|暂定|占位"
        )
        objectless = re.compile(
            r"^(?:背景|目标|定义|构造|原理|方法|实现|评估|实验|结果|结论|"
            r"问题|方案|流程|框架|分析|讨论|总结|小结|概述|概览|动机|指标|"
            r"建议|风险|备注|补充|附录|参考|用途|解释|注意事项|检查清单|"
            r"核心结论|完整代码|伪代码)$"
        )
        editorial_metaphor = re.compile(
            r"务必|免费仪表|盐碱地|温和地学|喂给|金标准下限|不要无脑|第一杠杆"
        )
        projected_rows: list[tuple[str, str, str, str]] = []
        source_headings_by_path: dict[str, set[str]] = {}
        for source_path in source_paths:
            source = (archive_root / source_path).read_bytes()
            projection = project_markdown(source)
            source_headings_by_path[source_path] = {
                heading.title_text for heading in projection.headings
            }
            for heading in projection.headings:
                projected_rows.append(
                    (
                        source_path,
                        heading.anchor_id,
                        heading.title_text,
                        presentation.heading_title(heading.title_text, source_path),
                    )
                )

        self.assertEqual(47, len(source_paths))
        self.assertEqual(47, len(set(source_paths)))
        self.assertEqual(1_388, len(projected_rows))
        self.assertGreaterEqual(
            sum(source_title != displayed_title for _, _, source_title, displayed_title in projected_rows),
            235,
        )
        self.assertFalse(
            [
                (source_path, displayed_title)
                for source_path, _, _, displayed_title in projected_rows
                if temporary_navigation.search(displayed_title)
                or colloquial.search(displayed_title)
                or status_label.search(displayed_title)
                or objectless.search(displayed_title)
                or editorial_metaphor.search(displayed_title)
                or "⭐" in displayed_title
                or "★" in displayed_title
                or len(displayed_title) >= 70
            ]
        )
        self.assertFalse(
            [
                (source_path, source_title)
                for source_path, overrides in presentation.path_heading_overrides.items()
                for source_title in overrides
                if source_title not in source_headings_by_path.get(source_path, set())
            ]
        )
        self.assertEqual(before, tree_identity())

    def test_default_manifest_separates_public_titles_and_system_seeded_topics(self) -> None:
        presentation = ArchivePresentation.default()
        self.assertEqual(
            "因子质量、稳健性与可交易性评估",
            presentation.research_title("q1-product-factor-evaluation", "legacy"),
        )
        self.assertFalse(
            presentation.is_public_research("archive-governance-and-navigation")
        )
        self.assertTrue(
            presentation.suppress_system_topic(
                topic_key="q4-operations-monitoring",
                state="paused",
                source_kind="manual",
                state_actor_display_name="Archive 全量导入器",
            )
        )
        self.assertFalse(
            presentation.suppress_system_topic(
                topic_key="q4-operations-monitoring",
                state="paused",
                source_kind="manual",
                state_actor_display_name="张正泽",
            )
        )
        self.assertTrue(
            presentation.is_historical_provenance_reference(
                "研究文档/问题一_专题/DSR.md"
            )
        )
        self.assertEqual(
            "训练体系专题索引",
            presentation.directory_internal_link("Q2_如何造一个好的工厂/专题")[
                "title"
            ],
        )
        self.assertEqual("独立数学公式块", presentation.visible_text("$$...$$"))
        self.assertEqual(
            "Q3_如何评价一个好的工厂/专题/双层稳定性.md",
            presentation.internal_link_aliases[
                "补充与扩展/双层稳定性.md"
            ]["target_path"],
        )
        self.assertIsNone(
            presentation.internal_asset_for_path(
                "Q2_如何造一个好的工厂/RESEARCH_LITREVIEW_AND_ANALYSIS.pdf"
            ),
        )
        self.assertEqual(
            "resolved",
            presentation.retired_internal_link(
                "Q2_如何造一个好的工厂/专题/跨步骤/集成策略.md"
            )["state"],
        )
        self.assertEqual(
            "label",
            presentation.retired_internal_link(
                "Q2_如何造一个好的工厂/专题/步骤2_forward/Readout层治理.md"
            )["state"],
        )

    def test_relative_path_normalization_is_exact_and_cannot_escape_archive(self) -> None:
        normalized = ArchivePresentation.normalize_relative_markdown_path(
            "Q1/专题/风格归因.md", "../../Q3/专题/dropout.md"
        )
        self.assertEqual(("Q3/专题/dropout.md", None), normalized)
        self.assertEqual(
            ("Q2_如何造一个好的工厂/研究过程", None, "directory"),
            ArchivePresentation.normalize_relative_archive_reference(
                "Q2_如何造一个好的工厂/专题/模型特定分析/GAT.md",
                "../../研究过程/",
            ),
        )
        self.assertEqual(
            (
                "Q2_如何造一个好的工厂/RESEARCH_LITREVIEW_AND_ANALYSIS.pdf",
                None,
                "asset",
            ),
            ArchivePresentation.normalize_relative_archive_reference(
                "Q2_如何造一个好的工厂/README.md",
                "RESEARCH_LITREVIEW_AND_ANALYSIS.pdf",
            ),
        )
        with self.assertRaisesRegex(RuntimeError, "escapes"):
            ArchivePresentation.normalize_relative_markdown_path(
                "Q1/README.md", "../../../outside.md"
            )

    def test_reader_projection_relabels_headings_and_paths_without_changing_source(self) -> None:
        source = (
            "# 这里放什么\n\n"
            "[旧路径](../../Q3/专题/dropout.md)；"
            "`../missing.md`；`bare_topic.md`；`../../Q3/专题/`；"
            "裸路径 ../target.md。\n\n"
            "写作规范使用 `$$...$$` 表示独立公式块。\n\n"
            "历史 PROGRESS_LOG；[STEP4_MODEL_*.md](../../研究过程/)。\n\n"
            "来源 `研究文档/问题一_专题/DSR.md`。\n\n"
            "[外部来源](https://example.com/paper)\n"
        ).encode("utf-8")
        before = bytes(source)

        def resolve(reference: str) -> InternalArchiveLink:
            if reference.startswith("https://"):
                return InternalArchiveLink("external", reference, reference, None)
            if reference.endswith("/"):
                return InternalArchiveLink(
                    "resolved",
                    "模型专项研究过程文档",
                    "/research/res_target#document-doc_process",
                    "Q2/研究过程/STEP4_MODEL.md",
                )
            if reference.startswith("研究文档/"):
                return InternalArchiveLink(
                    "provenance",
                    "历史研究源稿（相关内容已并入本专题）",
                    "",
                    None,
                )
            if reference == "bare_topic.md":
                return InternalArchiveLink(
                    "label",
                    "Readout 层治理",
                    "",
                    None,
                )
            if "missing" in reference:
                return InternalArchiveLink(
                    "unresolved",
                    "未解析链接：missing.md",
                    "#unresolved-archive-link",
                    "missing.md",
                    "目标未发布",
                )
            return InternalArchiveLink(
                "resolved",
                "Dropout 鲁棒性诊断",
                "/research/res_target#document-doc_target",
                "Q3/专题/dropout.md",
            )

        rendered = render_markdown_for_presentation(
            source,
            (),
            heading_title=lambda title: "内容范围" if title == "这里放什么" else title,
            link_resolver=resolve,
            visible_text=lambda text: text.replace(
                "PROGRESS_LOG", "研究过程记录"
            ).replace("$$...$$", "独立数学公式块"),
            link_label_title=lambda label: (
                "模型专项研究过程文档" if label == "STEP4_MODEL_*.md" else label
            ),
        )
        self.assertEqual(before, source)
        self.assertIn(">内容范围</h1>", rendered.rendered_html)
        self.assertIn(">Dropout 鲁棒性诊断</a>", rendered.rendered_html)
        self.assertNotIn("../../Q3/专题/dropout.md", rendered.rendered_html)
        self.assertNotIn("bare_topic.md", rendered.rendered_html)
        self.assertNotIn("../../Q3/专题/", rendered.rendered_html)
        self.assertNotIn("$$...$$", rendered.rendered_html)
        self.assertIn("独立数学公式块", rendered.rendered_html)
        self.assertIn("archive-concept-label", rendered.rendered_html)
        self.assertIn(">missing.md</span>", rendered.rendered_html)
        self.assertNotIn("#unresolved-archive-link", rendered.rendered_html)
        self.assertNotIn("未解析链接：", rendered.rendered_html)
        self.assertIn('href="https://example.com/paper"', rendered.rendered_html)
        self.assertIn("研究过程记录", rendered.rendered_html)
        self.assertNotIn("PROGRESS_LOG", rendered.rendered_html)
        self.assertIn("模型专项研究过程文档", rendered.rendered_html)
        self.assertNotIn("STEP4_MODEL_*.md", rendered.rendered_html)
        self.assertIn("archive-source-provenance", rendered.rendered_html)
        self.assertIn("archive-concept-label", rendered.rendered_html)
        self.assertIn("Readout 层治理", rendered.rendered_html)
        self.assertNotIn("研究文档/问题一_专题/DSR.md", rendered.rendered_html)
        self.assertEqual(("../missing.md",), rendered.unresolved_references)

    def test_reader_projection_keeps_date_but_hides_leading_author_and_version(self) -> None:
        def resolve(reference: str) -> InternalArchiveLink:
            return InternalArchiveLink("external", reference, reference, None)

        samples = (
            (
                "# Q2 主文\n\n**作者**：SCIENTIST\n**日期**：2026-05-20\n"
                "**版本**：v3\n**与 v2 的关系**：结构重构\n\n正文讨论版本控制。\n"
            ),
            (
                "# Q5 主文\n\n**作者**：SCIENTIST（补充研究）  \n"
                "**日期**：2026-07-16  \n**版本**：v6\n\n正文。\n"
            ),
        )
        rendered_results: list[str] = []
        for source_text in samples:
            with self.subTest(source_text=source_text[:7]):
                source = source_text.encode("utf-8")
                before = hashlib.sha256(source).hexdigest()
                rendered = render_markdown_for_presentation(
                    source,
                    (),
                    heading_title=lambda title: title,
                    link_resolver=resolve,
                )
                self.assertEqual(before, hashlib.sha256(source).hexdigest())
                self.assertNotIn("SCIENTIST", rendered.rendered_html)
                self.assertNotRegex(rendered.rendered_html, r"作者|<strong>版本</strong>")
                self.assertNotIn("与 v2 的关系", rendered.rendered_html)
                self.assertIn("日期", rendered.rendered_html)
                rendered_results.append(rendered.rendered_html)
        self.assertIn("正文讨论版本控制", rendered_results[0])

    def test_catalog_resolves_curated_directories_context_assets_and_provenance(self) -> None:
        catalog = object.__new__(ArchiveCatalog)
        catalog.presentation = ArchivePresentation.default()
        index = {
            "Q4_实操与部署后监测/README.md": {
                "research_id": "res_q4",
                "document_id": "doc_q4",
                "title": "legacy",
                "sections": [],
            },
            "Q2_如何造一个好的工厂/研究过程/STEP4_MODEL_GAT.md": {
                "research_id": "res_q2",
                "document_id": "doc_gat",
                "title": "legacy",
                "sections": [],
            },
            "Q2_如何造一个好的工厂/低信噪比金融工程下神经网络选股训练工厂全维度优化研究.md": {
                "research_id": "res_q2",
                "document_id": "doc_q2_core",
                "title": "Q2 核心研究",
                "sections": [
                    {
                        "anchor_id": "anc_ensemble",
                        "title_text": "主线四：平均而非选择（AVERAGE, don't SELECT）——统一 D7（SWA）+ D11（EMA/集成）",
                    }
                ],
            },
        }
        directory = catalog.resolve_archive_link(
            "Q3_如何评价一个好的工厂/README.md",
            "../Q4_实操与部署后监测/",
            index=index,
        )
        self.assertEqual("resolved", directory.state)
        self.assertEqual("量化模型部署监控与漂移诊断", directory.title)
        self.assertEqual("/research/res_q4/documents/doc_q4", directory.url)

        contextual = catalog.resolve_archive_link(
            "Q2_如何造一个好的工厂/专题/模型特定分析/GAT.md",
            "../../研究过程/",
            index=index,
        )
        self.assertEqual("resolved", contextual.state)
        self.assertEqual("GAT 模型专项研究过程", contextual.title)
        self.assertEqual("/research/res_q2/documents/doc_gat", contextual.url)

        asset = catalog.resolve_archive_link(
            "Q2_如何造一个好的工厂/README.md",
            "RESEARCH_LITREVIEW_AND_ANALYSIS.pdf",
            index=index,
        )
        self.assertEqual("unresolved", asset.state)
        self.assertEqual("#unresolved-archive-link", asset.url)
        self.assertIn("尚未进入受控资源清单", asset.reason)

        provenance = catalog.resolve_archive_link(
            "Q2_如何造一个好的工厂/README.md",
            "../../../factory/",
            index=index,
        )
        self.assertEqual("provenance", provenance.state)
        self.assertEqual("", provenance.url)

        missing = catalog.resolve_archive_link(
            "Q2_如何造一个好的工厂/README.md",
            "尚未审核目录/",
            index=index,
        )
        self.assertEqual("unresolved", missing.state)
        self.assertEqual("#unresolved-archive-link", missing.url)

        retired_resolved = catalog.resolve_archive_link(
            "Q3_如何评价一个好的工厂/专题/选股相关性_Jaccard.md",
            "../../Q2_如何造一个好的工厂/专题/跨步骤/集成策略.md",
            index=index,
        )
        self.assertEqual("resolved", retired_resolved.state)
        self.assertEqual("集成策略", retired_resolved.title)
        self.assertEqual(
            "/research/res_q2/documents/doc_q2_core#anc_ensemble",
            retired_resolved.url,
        )

        retired_label = catalog.resolve_archive_link(
            "Q3_如何评价一个好的工厂/专题/CKA_表征相似度.md",
            "../../Q2_如何造一个好的工厂/专题/步骤2_forward/Readout层治理.md",
            index=index,
        )
        self.assertEqual("label", retired_label.state)
        self.assertEqual("Readout 层治理", retired_label.title)
        self.assertEqual("", retired_label.url)

    def test_path_specific_heading_override_does_not_change_same_heading_elsewhere(self) -> None:
        payload = {
            "schema_version": "qrh-archive-presentation/v1",
            "home": {"eyebrow": "x", "title": "x", "introduction": "x"},
            "heading_overrides_by_path": {
                "Q3/专题/PBO.md": {"构造": "CSCV 构造与 PBO 统计量"}
            },
            "visibility": {"hidden_research_slugs": []},
            "search": {"excluded_line_markers": []},
            "research": {},
            "system_managed_topics": {
                "suppress_until_researcher_updates": [],
                "system_actor_names": [],
            },
        }
        presentation = ArchivePresentation(payload)
        self.assertEqual(
            "CSCV 构造与 PBO 统计量",
            presentation.heading_title("构造", "Q3/专题/PBO.md"),
        )
        self.assertEqual("构造", presentation.heading_title("构造", "Q2/其他.md"))


if __name__ == "__main__":
    unittest.main()
