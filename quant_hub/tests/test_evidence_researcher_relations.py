from __future__ import annotations

from quant_hub.evidence.service import EvidenceQueryService


def _relation_row(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "relation_id": "rel_test",
        "research_urn": "qrh:archive:research:POFF_LEGACY",
        "document_version_urn": "qrh:archive:document-version:test",
        "citation_id": "cit_test",
        "ledger_entry_id": "led_test",
        "relation_kind": "supports",
        "relation_semantics": "formal_or_direct",
        "occurrence_type": "formal_citation_command",
        "source_path": "旧版原始文件/doc/latex_paper/research_paper_v3_BACKUP_v7.6.tex",
        "canonical_path": "旧版原始文件/doc/latex_paper/research_paper_v3_BACKUP_v7.6.tex",
        "line_start": 73,
        "line_end": 76,
        "context_text": (
            "Repeated backtests and multiple testing create selection bias; "
            "the reported winner can be a backtest-overfitting artifact."
        ),
        "raw_marker_text": "Bailey et al. (2016)",
    }
    row.update(overrides)
    return row


def _public_index() -> dict[str, dict[str, object]]:
    anchor = "anc_sha256_" + "a" * 64
    return {
        "Q3_如何评价一个好的工厂/专题/PBO_回测过拟合.md": {
            "research_id": "res_q3",
            "research_slug": "q3-training-method-reliability",
            "research_title": "模型训练可靠性与过拟合诊断",
            "document_id": "doc_pbo",
            "title": "回测过拟合概率与模型筛选偏差",
            "sections": [
                {"line_start": 1, "anchor_id": anchor, "title_text": "诊断方法"}
            ],
        },
        "Q2_如何造一个好的工厂/专题/步骤3_loss_backward/优化器.md": {
            "research_id": "res_q2",
            "research_slug": "q2-low-snr-neural-selection-factory",
            "research_title": "低信噪比选股模型训练体系",
            "document_id": "doc_optimizer",
            "title": "优化器与训练动力学",
            "sections": [
                {"line_start": 1, "anchor_id": anchor, "title_text": "优化目标"}
            ],
        },
        "Q2_如何造一个好的工厂/专题/跨步骤/集成策略.md": {
            "research_id": "res_q2",
            "research_slug": "q2-low-snr-neural-selection-factory",
            "research_title": "低信噪比选股模型训练体系",
            "document_id": "doc_ensemble",
            "title": "模型集成、权重平均与失效条件",
            "sections": [
                {
                    "line_start": 1,
                    "anchor_id": anchor,
                    "title_text": "主线四：平均而非选择",
                }
            ],
        },
        "experiments/README.md": {
            "research_id": "res_experiments",
            "research_slug": "archive-experiments-e1-e8",
            "research_title": "低信噪比模型验证实验体系",
            "document_id": "doc_experiments",
            "title": "低信噪比选股模型的受控验证实验矩阵",
            "sections": [
                {"line_start": 1, "anchor_id": anchor, "title_text": "实验清单"}
            ],
        },
    }


def test_legacy_relation_links_public_research_and_hides_raw_filename() -> None:
    relations = EvidenceQueryService._present_archive_relations(
        [_relation_row()],
        _public_index(),
        paper_title="The Probability of Backtest Overfitting",
    )

    assert len(relations) == 1
    relation = relations[0]
    assert relation["research_title"] == "模型训练可靠性与过拟合诊断"
    assert relation["document_title"] == "回测过拟合概率与模型筛选偏差"
    assert relation["source_url"] == (
        "/research/res_q3/documents/doc_pbo#document-doc_pbo"
    )
    assert relation["source_resolution"] == "historical_research_document"
    assert relation["source_section_title"] is None
    assert relation["source_location"] is None
    visible = " ".join(
        str(relation[key])
        for key in (
            "research_title",
            "document_title",
            "usage_description",
            "source_link_label",
            "source_section_title",
            "source_location",
        )
    ).casefold()
    assert ".tex" not in visible
    assert "backup" not in visible
    assert "version" not in visible
    assert "在该原文位置把这篇论文作为" not in visible
    assert "选择偏差" in str(relation["usage_description"])
    assert "偶然最优模型" in str(relation["usage_description"])
    assert "The Probability of Backtest Overfitting" in str(
        relation["usage_description"]
    )
    assert "历史研究语境" in str(relation["usage_description"])
    assert relation["relation_label"] == "历史方法脉络"


def test_current_relation_keeps_exact_document_anchor_and_formal_titles() -> None:
    current_path = "Q3_如何评价一个好的工厂/专题/PBO_回测过拟合.md"
    archive_index = _public_index()
    target = archive_index[current_path]
    anchor = str(target["sections"][0]["anchor_id"])  # type: ignore[index]
    relations = EvidenceQueryService._present_archive_relations(
        [
            _relation_row(
                research_urn="qrh:archive:research:Q3_FACTORY_EVALUATION",
                source_path=current_path,
                canonical_path=current_path,
                line_start=42,
            )
        ],
        archive_index,
        paper_title="The Probability of Backtest Overfitting",
    )

    relation = relations[0]
    assert relation["research_title"] == "模型训练可靠性与过拟合诊断"
    assert relation["document_title"] == "回测过拟合概率与模型筛选偏差"
    assert relation["source_url"] == f"/research/res_q3/documents/doc_pbo#{anchor}"
    assert relation["source_resolution"] == "current_archive_document"
    assert relation["source_section_title"] == "诊断方法"
    assert relation["source_location"] == "原文第 42 行"


def test_unpublished_history_never_enters_display_relation_sets() -> None:
    core, references, scope = EvidenceQueryService._select_display_archive_relations(
        [_relation_row()],
        {},
        paper_title="The Probability of Backtest Overfitting",
    )

    assert core == []
    assert references == []
    assert scope == "none"


def test_historical_semantic_matches_use_real_current_sections() -> None:
    anchor = "anc_sha256_" + "a" * 64
    cases = (
        (
            "Information-theoretic determination of minimax rates of convergence",
            "Yang-Barron information-theoretic lower bound limits learnable signal.",
            "低信噪比选股模型的受控验证实验矩阵",
            f"/research/res_experiments/documents/doc_experiments#{anchor}",
        ),
        (
            "Towards Understanding Ensemble, Knowledge Distillation and Self-Distillation in Deep Learning",
            "Ensemble averaging reduces noise fitting across random seeds.",
            "模型集成、权重平均与失效条件",
            f"/research/res_q2/documents/doc_ensemble#{anchor}",
        ),
    )
    for title, context, document_title, expected_url in cases:
        relation = EvidenceQueryService._present_archive_relations(
            [_relation_row(context_text=context)],
            _public_index(),
            paper_title=title,
        )[0]
        assert relation["document_title"] == document_title
        assert relation["source_url"] == expected_url
        assert relation["source_section_title"]
        assert relation["source_resolution"] == "historical_research_document"
        assert "历史研究语境" in str(relation["usage_description"])


def test_curated_q5_source_alias_uses_semantic_v6_section_not_retired_line() -> None:
    old_path = "Q5/低SNR选股_因子历史序列压缩方法谱系_descriptor实操扩展版.md"
    new_path = "Q5/低SNR横截面选股_因子历史表示与压缩研究_结构重构扩展版.md"
    sections = [
        {
            "line_start": line_start,
            "anchor_id": "anc_sha256_" + marker * 64,
            "title_text": title,
        }
        for line_start, marker, title in (
            (2739, "1", "6.1 ROCKET / MiniROCKET：随机 filter bank + 极简 pooling"),
            (3376, "2", "6.4 InceptionTime：并联多个 kernel size"),
            (3516, "3", "6.5 Decomposition 与 N-BEATS：结构化残差分解"),
            (3758, "4", "6.6 Tokenization 与 PatchTST：时间片段标记化"),
            (4271, "5", "6.9 Self-supervised representation：自监督序列表征"),
        )
    ]
    target = {
        "research_id": "res_q5",
        "research_slug": "q5-factor-history-sequence-compression",
        "research_title": "低信噪比因子序列表征",
        "document_id": "doc_q5_v6",
        "source_path": new_path,
        "title": "低信噪比横截面选股的因子历史表示",
        "sections": sections,
    }
    archive_index = {old_path: target, new_path: target}
    cases = (
        ("MINIROCKET: A Very Fast Transform", "1", "6.1 ROCKET / MiniROCKET"),
        ("InceptionTime: Finding AlexNet for Time Series Classification", "2", "6.4 InceptionTime"),
        ("N-BEATS: Neural basis expansion analysis", "3", "6.5 Decomposition 与 N-BEATS"),
        ("A Time Series is Worth 64 Words: Long-term Forecasting with Transformers", "4", "6.6 Tokenization 与 PatchTST"),
        ("TS2Vec: Towards Universal Representation of Time Series", "5", "6.9 Self-supervised representation"),
        ("Unsupervised Representation Learning with Temporal Neighborhood Coding", "5", "6.9 Self-supervised representation"),
        ("CoST: Contrastive Learning of Disentangled Seasonal-Trend Representations", "5", "6.9 Self-supervised representation"),
    )
    for title, marker, section_prefix in cases:
        relation = EvidenceQueryService._present_archive_relations(
            [
                _relation_row(
                    source_path=old_path,
                    canonical_path=old_path,
                    line_start=1,
                    context_text="N-BEATS 仅为相邻方法；历史 Q5 方法关系。",
                )
            ],
            archive_index,
            paper_title=title,
        )[0]
        assert relation["source_url"] == (
            f"/research/res_q5/documents/doc_q5_v6#anc_sha256_{marker * 64}"
        )
        assert str(relation["source_section_title"]).startswith(section_prefix)
        assert relation["source_resolution"] == "current_archive_document"
        assert relation["source_location"] is None
        assert "第 1 行" not in str(relation)
