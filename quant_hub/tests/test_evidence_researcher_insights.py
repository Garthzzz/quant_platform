from __future__ import annotations

import re

from quant_hub.presentation.evidence_researcher_insights import (
    PAPER_INSIGHTS,
    build_researcher_insight,
)


# 2026-07-16 Evidence 发布库的 78 个规范标题。这个独立快照用于防止新增展示规则时
# 只覆盖容易处理的论文，或在重构中静默退回同一条通用模板。
CURRENT_EVIDENCE_TITLES = {
    "A Non-Parametric Test of Independence",
    "Ordinal Measures of Association",
    "Control Chart Tests Based on Geometric Moving Averages",
    "Improving generalization performance using double backpropagation",
    "Flat Minima",
    "Long Short-Term Memory",
    "Information-theoretic determination of minimax rates of convergence",
    "Noise Dressing of Financial Correlation Matrices",
    "Empirical properties of asset returns: stylized facts and statistical issues",
    "PAC-Bayesian Stochastic Model Selection",
    "A well-conditioned estimator for large-dimensional covariance matrices",
    "The Adaptive Markets Hypothesis",
    "An introduction to ROC analysis",
    "A survey of cross-validation procedures for model selection",
    "On the use of cross-validation for time series predictor evaluation",
    "Dropout Training as Adaptive Regularization",
    "The three-pass regression filter: A new approach to forecasting using many predictors",
    "Backtesting",
    "Batch Normalization: Accelerating Deep Network Training by Reducing Internal Covariate Shift",
    "Characterizing concept drift",
    "Gaussian Error Linear Units (GELUs)",
    "Layer Normalization",
    "On Large-Batch Training for Deep Learning: Generalization Gap and Sharp Minima",
    "Simple and Scalable Predictive Uncertainty Estimation using Deep Ensembles",
    "Robust Large Margin Deep Neural Networks",
    "Sharp Minima Can Generalize For Deep Nets",
    "Self-Normalizing Neural Networks",
    "Attention Is All You Need",
    "Graph Attention Networks",
    "Three Factors Influencing Minima in SGD",
    "Decoupled Weight Decay Regularization",
    "Efficiently Inefficient Markets for Assets and Asset Management",
    "Deep Learning for Forecasting Stock Returns in the Cross-Section",
    "Spectral Normalization for Generative Adversarial Networks",
    "The Lottery Ticket Hypothesis: Finding Sparse, Trainable Neural Networks",
    "Averaging Weights Leads to Wider Optima and Better Generalization",
    "Generalized Cross Entropy Loss for Training Deep Neural Networks with Noisy Labels",
    "Neural Tangent Kernel: Convergence and Generalization in Neural Networks",
    "Size and value in China",
    "A Backtesting Protocol in the Era of Machine Learning",
    "Deep Adaptive Input Normalization for Time Series Forecasting",
    "Similarity of Neural Network Representations Revisited",
    "N-BEATS: Neural basis expansion analysis for interpretable time series forecasting",
    "Differentiable Ranks and Sorting using Optimal Transport",
    "On the Variance of the Adaptive Learning Rate and Beyond",
    "InceptionTime: Finding AlexNet for Time Series Classification",
    "Deep Ensembles: A Loss Landscape Perspective",
    "Benign overfitting in linear regression",
    "Understanding Why Neural Networks Generalize Well Through GSNR of Parameters",
    "Scaling Laws for Neural Language Models",
    "Do We Need Zero Training Loss After Achieving Zero Training Error?",
    "Fast Differentiable Sorting and Ranking",
    "Bayesian Deep Learning and a Probabilistic Perspective of Generalization",
    "Hyperparameter Ensembles for Robustness and Uncertainty Quantification",
    "Sharpness-Aware Minimization for Efficiently Improving Generalization",
    "MINIROCKET: A Very Fast (Almost) Deterministic Transform for Time Series Classification",
    "Towards Understanding Ensemble, Knowledge Distillation and Self-Distillation in Deep Learning",
    "Attention is Not All You Need: Pure Attention Loses Rank Doubly Exponentially with Depth",
    "Unsupervised Representation Learning for Time Series with Temporal Neighborhood Coding",
    "TS2Vec: Towards Universal Representation of Time Series",
    "Machine learning in the Chinese stock market",
    "When do systematic strategies decay?",
    "Market efficiency in the age of big data",
    "CoST: Contrastive Learning of Disentangled Seasonal-Trend Representations for Time Series Forecasting",
    "On Embeddings for Numerical Features in Tabular Deep Learning",
    "Training Compute-Optimal Large Language Models",
    "Emergent Abilities of Large Language Models",
    "Git Re-Basin: Merging Models modulo Permutation Symmetries",
    "We need to talk about random seeds",
    "A Time Series is Worth 64 Words: Long-term Forecasting with Transformers",
    "Are Emergent Abilities of Large Language Models a Mirage?",
    "Is There a Replication Crisis in Finance?",
    "Leakage and the reproducibility crisis in machine-learning-based science",
    "Symbolic Discovery of Optimization Algorithms",
    "Self-Supervised Learning for Time Series Analysis: Taxonomy, Progress, and Prospects",
    "Explaining neural scaling laws",
    "PFML: Self-Supervised Learning of Time-Series Data Without Representation Collapse",
    "How to Use the Sharpe Ratio",
}

AUDIT_ONLY_TERMS = {
    "核验",
    "证据边界",
    "事实边界",
    "摘要称",
    "官方摘要",
    "适用性受限",
    "结论限于",
    "未声称",
    "来源事实",
    "支持文本哈希",
    "source_verified",
    "provenance",
}

QUANT_TERMS = {
    "量化",
    "因子",
    "选股",
    "股票",
    "收益",
    "预测",
    "时序",
    "时间序列",
    "回测",
    "策略",
    "风险",
    "模型",
    "训练",
    "市场",
    "组合",
    "横截面",
}


def test_all_78_current_evidence_titles_have_curated_insights() -> None:
    assert len(CURRENT_EVIDENCE_TITLES) == 78
    assert set(PAPER_INSIGHTS) == CURRENT_EVIDENCE_TITLES

    outputs = {
        title: build_researcher_insight(
            title,
            synthesis_zh="这条旧综述不应覆盖逐题策展内容。",
            archive_relations=[],
            core_conclusions=[{"text": "Existing source claim."}],
        )
        for title in CURRENT_EVIDENCE_TITLES
    }
    assert len(set(outputs.values())) == 78

    for title, output in outputs.items():
        sentence_count = len(re.findall(r"[。！？]", output))
        assert 2 <= sentence_count <= 4, title
        assert 60 <= len(output) <= 330, title
        assert any(term in output for term in QUANT_TERMS), title
        assert not any(term.lower() in output.lower() for term in AUDIT_ONLY_TERMS), title


def test_archive_context_is_researcher_facing_and_ignores_raw_file_names() -> None:
    relations = [
        {
            "research_title": "低信噪比因子序列表征",
            "document_title": "Q5_draft.tex",
            "source_section_title": "Representation objective",
            "source_excerpt": "TS2Vec 更应该按 objective 理解，而不是只按模型名称记忆。",
            "relation_label": "方法原始来源",
        }
    ]
    output = build_researcher_insight(
        "TS2Vec: Towards Universal Representation of Time Series",
        archive_relations=relations,
    )
    assert "《低信噪比因子序列表征》" in output
    assert "保留了可预测结构" in output
    assert "Q5_draft.tex" not in output
    assert "方法原始来源" not in output


def test_unknown_paper_fallback_strips_audit_language() -> None:
    output = build_researcher_insight(
        "A New Time Series Baseline",
        synthesis_zh=(
            "该方法用局部窗口提取多尺度时序特征。"
            "机构核验状态：已核验。"
            "来源事实与证据边界请见支持文本哈希。"
        ),
        archive_relations=[],
        core_conclusions=[{"text": "No automatic expansion is performed."}],
    )
    assert "该方法用局部窗口提取多尺度时序特征" in output
    assert "未来信息" in output
    assert not any(term.lower() in output.lower() for term in AUDIT_ONLY_TERMS)


def test_single_relation_and_chinese_conclusion_are_supported_for_future_papers() -> None:
    output = build_researcher_insight(
        "Future Covariance Study",
        synthesis_zh=None,
        archive_relations={
            "research_title": "高维风险估计",
            "source_excerpt": "样本相关矩阵需要区分稳定结构与有限样本噪声。",
            "source_section_title": "协方差去噪",
        },
        core_conclusions=[
            {"text": "该方法通过结构化收缩降低高维协方差估计的波动。"}
        ],
    )
    assert output.startswith("该方法通过结构化收缩降低高维协方差估计的波动。")
    assert "《高维风险估计》" in output
    assert "改善风险估计" in output
    assert "组合优化输入" in output
