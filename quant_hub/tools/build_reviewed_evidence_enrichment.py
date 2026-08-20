"""Build the human-reviewed Evidence enrichment payload from source-bound drafts.

The English abstract and conclusion claims remain verbatim source text.  Chinese
fields below are explicitly a reference translation and a research-aid synthesis;
they are never promoted to source facts.
"""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
WORKER = ROOT / "project_state" / "workers" / "evidence_substantive_enrichment_20260716"
DRAFT = WORKER / "draft_enrichment.json"
OUTPUT = WORKER / "reviewed_enrichment.json"


# The abstract translations are deliberately compact but preserve every decisive
# proposition used by the adjacent synthesis.  They were reviewed title-by-title
# against the English source excerpt on 2026-07-16.
ZH: dict[str, tuple[str, str]] = {
    "A Backtesting Protocol in the Era of Machine Learning": (
        "机器学习为投资管理提供了很有潜力的工具，但误用会造成失望。金融数据远少于物理和生物科学，长期投资尤其如此；资本市场又会受到参与者行为、他人行动和既有研究的反身性影响。因此，应先选择适合的数据与问题，再使用模型，并以同时适用于机器学习和量化金融的研究协议约束整个过程。",
        "这篇论文的重点不是推荐某个模型，而是把有限样本、反身性、选择偏差和研究纪律置于算法之前；在 Archive 中它应作为回测与研究流程的上位约束。",
    ),
    "A Non-Parametric Test of Independence": (
        "论文提出一种检验两个连续随机变量独立性的非参数方法。统计量 D 只依赖样本秩序；作者给出其均值、方差和极限分布，并讨论独立情形下的退化与非正态极限，同时列出小样本精确分布。附录还证明，对给定分布类，不存在在任意显著性水平都无偏的纯秩独立性检验。",
        "该结果为非线性依赖诊断提供秩统计基础，同时提醒研究者：独立性检验的有限样本校准和无偏性不能被默认。",
    ),
    "A survey of cross-validation procedures for model selection": (
        "交叉验证因简单且看似通用，被广泛用于风险估计和模型选择。本文把交叉验证的模型选择表现与较新的模型选择理论联系起来，特别区分经验观察与严格理论结论，并依据具体问题特征给出选择交叉验证方案的指导。",
        "交叉验证不是单一、无条件有效的操作；折数、训练比例、损失目标与数据依赖结构共同决定其偏差和方差。",
    ),
    "A well-conditioned estimator for large-dimensional covariance matrices": (
        "高维问题需要既可逆又条件良好的协方差估计，而样本协方差往往病态甚至不可逆。论文提出把样本协方差与结构化目标矩阵按最优权重线性组合；所得收缩估计在渐近意义下既保持良好条件数，又比单独使用样本协方差或目标矩阵更准确。",
        "该论文给出了高维协方差收缩的核心依据：稳定求逆不应靠随意正则化，而应把偏差与方差纳入可估计的最优收缩权重。",
    ),
    "An introduction to ROC analysis": (
        "ROC 图可用于组织分类器并可视化其性能，在医学决策、机器学习和数据挖掘中应用广泛。文章系统介绍 ROC 空间、曲线和 AUC，说明分类阈值、类别分布与误判成本如何影响评价，并讨论常见解释误区。",
        "ROC/AUC 衡量排序区分能力而非固定阈值下的业务效用；在低信噪比预测中必须同时报告阈值、成本和类别基准。",
    ),
    "Are Emergent Abilities of Large Language Models a Mirage?": (
        "论文提出另一种解释：在模型输出固定时，所谓能力的突然涌现可能来自研究者选择了非线性或不连续的评价指标，而不是模型行为随规模发生根本突变。作者通过数学模型、GPT-3/InstructGPT 任务、BIG-Bench 元分析和视觉任务验证相关预测；换用连续指标或更好的统计处理后，多项表面涌现现象消失。",
        "这为任何规模规律研究提供方法警告：先审计指标几何与离散化，再把曲线拐点解释成机制变化。",
    ),
    "Backtesting": (
        "评价交易策略时，应对历史回测的夏普比率进行折减，因为当前研究者和过去研究共同造成不可避免的数据挖掘。论文给出系统考虑多重检验的统计框架，提出对已报告夏普比率计算适当折扣的方法，并给出策略要达到统计显著性所需的收益门槛。",
        "原始回测夏普不能直接作为策略证据；试验次数、选择过程和历史研究拥挤度都应进入显著性门槛。",
    ),
    "Characterizing concept drift": (
        "静态模型被部署在动态世界中，因此需要处理非平稳分布，即概念漂移。论文指出既有漂移分类缺少严格定义和客观量化，随后形式化不同漂移类型，并提出刻画漂移幅度、持续时间、路径和频率等性质的定量描述，以更精确地理解学习器在变化环境中的表现。",
        "漂移不应只用‘突变/渐变’标签描述；量化漂移的幅度、速度和复现结构，才能把监控阈值与模型失效机制联系起来。",
    ),
    "Control Chart Tests Based on Geometric Moving Averages": (
        "几何移动平均对最新观测赋予最大权重，并按几何级数降低更早观测的权重。论文描述一种生成该移动平均的图形方法，其中最新观测权重为 r，并比较基于几何移动平均与普通移动平均的控制图检验性质。",
        "这项工作构成 EWMA 类在线监控的早期统计基础：权重参数决定对新变化的响应速度与噪声平滑之间的折中。",
    ),
    "Empirical properties of asset returns: stylized facts and statistical issues": (
        "文章总结多类金融市场价格变化的共同经验事实，涵盖收益分布、尾部与极端波动、路径正则性，以及时间和横截面上的线性与非线性依赖。作者强调这些跨市场、跨工具的共性，并说明它们如何使许多常用金融统计方法失效以及由此产生的统计问题。",
        "厚尾、波动聚集和依赖结构不是边角异常，而是金融序列建模与稳健检验必须正面处理的基线性质。",
    ),
    "How to Use the Sharpe Ratio": (
        "夏普比率是评价投资技能的主导指标，但相关推断经常出错。论文归纳五类问题：只报点估计、不恰当地假设收益独立同分布且正态、忽略检验功效和最小样本长度、把 p 值误读成原假设概率，以及未校正多重检验和选择效应；并据现代统计理论给出相应修正与报告规范。",
        "夏普比率需要和不确定性、样本长度、序列相关、非正态及选择过程一起解释，单个年化数字不足以证明策略有效。",
    ),
    "Improving generalization performance using double backpropagation": (
        "为了从训练集泛化到测试集，输入的小变化不应引起输出的大变化。双重反向传播把普通训练误差与依赖输出雅可比矩阵的附加项相加，从而在训练中直接约束这种敏感性。实验显示该方法在多种架构和测试集上改善泛化，并产生更小的权重，使神经元输出更多处于线性区域。",
        "输入梯度惩罚把局部平滑性从事后诊断转为训练目标，是研究表征稳健性和抗扰动能力的直接先例。",
    ),
    "Information-theoretic determination of minimax rates of convergence": (
        "论文基于信息论考虑，为密度估计的统计风险给出一组确定极小极大上下界的一般结果。这些界只依赖度量熵条件，并可据此识别极小极大收敛速度。",
        "其价值在于把估计难度与函数类复杂度连接起来，为判断样本量是否足以支持某类非参数模型提供理论基准。",
    ),
    "Leakage and the reproducibility crisis in machine-learning-based science": (
        "机器学习科学研究存在多种方法陷阱，尤其是数据泄漏。作者调查采用机器学习的多个领域，发现 17 个领域中至少 294 篇论文受到泄漏影响，部分结论严重过度乐观；论文提出八类泄漏的细粒度分类和模型信息表。对内战预测的复现研究表明，纠正泄漏后，复杂模型不再实质性优于数十年前的逻辑回归。",
        "该论文把泄漏界定为跨领域的证据危机；量化研究必须逐项审计样本划分、预处理、特征可得时点和调参反馈。",
    ),
    "Machine learning in the Chinese stock market": (
        "论文用多种机器学习算法构建并分析中国股票市场的一组完整收益预测因子。与美国研究不同，流动性是最重要预测变量；散户主导提高了短期、尤其小盘股的可预测性，大盘股和国企在更长周期也表现出较高可预测性。扣除交易成本后，样本外表现仍具有经济意义。",
        "中国市场的可预测性结构不能照搬美国结论；流动性、散户占比、国企属性和真实交易成本是模型比较的关键条件。",
    ),
    "Market efficiency in the age of big data": (
        "现代投资者面对数千变量的高维预测问题。模型中，贝叶斯投资者用岭回归式收缩或 Lasso 式稀疏化估计特征系数并定价；当特征数与资产数同量级时，事后计量分析会发现横截面可预测性，即使没有 p-hacking 也会出现‘因子动物园’。传统样本内有效市场检验会高概率错误拒绝，而样本外检验仍保留经济含义。",
        "高维估计误差本身即可制造事后因子显著性，因此因子研究应把样本外表现作为主证据，并显式处理收缩和选择。",
    ),
    "Noise Dressing of Financial Correlation Matrices": (
        "随机矩阵理论有助于理解多元时间序列的经验相关矩阵。对股票价格波动的研究发现，在相关矩阵随机这一假设下得到的理论特征值密度与标普 500 等市场的经验数据高度一致；这对在风险管理中不加辨别地使用样本相关矩阵提出严重质疑。",
        "样本相关矩阵的大量谱结构可能只是有限样本噪声；协方差清洗、稳定性检验和样本外验证因此是组合风险建模的必要步骤。",
    ),
    "On the use of cross-validation for time series predictor evaluation": (
        "时间序列预测中，传统方法常保留序列末段测试，而机器学习研究常直接使用交叉验证，后者可能违反时间演化和依赖假设。作者比较六种模型选择方案和四类预测方法；实验未发现这些理论缺陷造成明显实际后果，交叉验证反而使模型选择更稳健，因此建议采用分块交叉验证，以利用全部信息并规避主要理论问题。",
        "论文支持的是经过时间结构约束的分块交叉验证，而不是随机打乱的普通 K 折；这一边界对量化序列尤为重要。",
    ),
    "Ordinal Measures of Association": (
        "文章讨论二元总体中在序数变换下不变的秩关联度量，重点解释其总体值的概率与操作含义。论文详细考察象限度量、Kendall tau 和 Spearman rho，讨论它们之间及其与列联表关联度量的关系，并回顾抽样理论和历史发展。",
        "秩相关并非可互换的单一指标；不同度量的概率含义、并列值处理和抽样分布应与研究问题匹配。",
    ),
    "PAC-Bayesian Stochastic Model Selection": (
        "PAC-Bayes 方法把贝叶斯先验的信息性与分布无关的 PAC 保证结合起来。随机模型选择按分类器后验分布抽样预测；论文给出的性能保证优于对应的确定性选择，并由随机分类器训练误差和后验相对先验的 KL 散度表达。优化该保证的后验是 Gibbs 分布，同时也存在性能接近最优的更简单后验。",
        "这为跨种子或模型集合提供了复杂度校正框架：评价对象可以是模型分布，而不是被挑中的单个最优模型。",
    ),
    "Robust Large Margin Deep Neural Networks": (
        "论文通过分类间隔研究深度网络的泛化误差，并以网络雅可比矩阵为核心，覆盖任意非线性、池化及前馈或残差架构。分析表明，训练样本邻域内雅可比矩阵谱范数有界，是任意深宽网络良好泛化的关键；由此解释部分归一化方法，并导出基于雅可比的新正则项。",
        "模型容量不能只由参数量或深度判断；局部雅可比谱范数把输入敏感性、分类间隔和泛化联系为可测量门禁。",
    ),
    "Size and value in China": (
        "论文构建中国市场的规模与价值因子。规模因子排除最小 30% 公司，因为其价值显著包含规避严格 IPO 约束的壳资源；价值因子采用盈利市值比，该指标涵盖账面市值比所捕捉的中国价值效应。所得三因子模型明显优于机械复制 Fama-French 方法的模型，并解释多数已报告的中国异象。",
        "中国规模和价值因子需要针对壳价值与盈利定价机制重新定义，不能机械沿用美国分组规则。",
    ),
    "The Adaptive Markets Hypothesis": (
        "适应性市场假说试图调和有效市场与行为金融：把竞争、适应和自然选择的进化原则应用于金融互动。损失厌恶、过度自信、过度反应和心理账户等看似非理性的偏差，可以理解为个体在变化环境中使用简单启发式规则进行适应的结果，并由此得到一组具体的投资组合管理含义。",
        "市场效率是随生态、竞争和制度变化的状态而非常数；策略衰减和制度漂移应作为适应过程建模。",
    ),
    "The three-pass regression filter: A new approach to forecasting using many predictors": (
        "论文提出三遍回归滤波器，用大量预测变量预测单一时间序列。该估计量可由一组普通最小二乘回归闭式计算；当时间维和横截面维同时增大时，3PRF 对不可行最优预测是一致的，只需指定驱动预测目标的相关因子数量，而不必指定全部共同因子。它是受约束最小二乘，偏最小二乘是其特例，模拟验证了相对预测表现。",
        "3PRF 的关键是有监督地提取与目标相关的少数因子，避免高维预测变量中的强但无关共同成分主导降维。",
    ),
    "When do systematic strategies decay?": (
        "论文报告：已发表的系统性异象在原研究样本之外进行评价时，平均只能实现约一半的样本内表现。",
        "该结果为策略衰减提供直接经验基准；回测预期应对发表后、样本外和拥挤效应做显著折扣。",
    ),
}


SOURCE_GAPS: dict[str, tuple[str, dict[str, Any]]] = {
    "A well-conditioned estimator for large-dimensional covariance matrices": (
        "Many applied problems require a covariance matrix estimator that is not only invertible, but also well-conditioned (that is, inverting it does not amplify estimation error). For large-dimensional covariance matrices, the usual estimator—the sample covariance matrix—is typically not well-conditioned and may not even be invertible. This paper introduces an estimator that is both well-conditioned and more accurate than the sample covariance matrix asymptotically. The estimator is an optimally weighted average of the sample covariance matrix and a structured target matrix.",
        {"source_kind": "publisher_abstract", "field": "publisher.abstract", "url": "https://doi.org/10.1016/S0047-259X(03)00096-4"},
    ),
    "An introduction to ROC analysis": (
        "Receiver operating characteristics (ROC) graphs are useful for organizing classifiers and visualizing their performance. ROC graphs are commonly used in medical decision making, and in recent years have been used increasingly in machine learning and data mining research. This article serves as an introduction to ROC graphs and as a guide for using them in research.",
        {"source_kind": "publisher_abstract", "field": "publisher.abstract", "url": "https://doi.org/10.1016/j.patrec.2005.10.010"},
    ),
    "Are Emergent Abilities of Large Language Models a Mirage?": (
        "Recent work claims that large language models display emergent abilities, abilities not present in smaller-scale models that are present in larger-scale models. We present an alternative explanation: when analyzing fixed model outputs, emergent abilities appear due to the researcher's choice of metric rather than due to fundamental changes in model behavior with scale. Nonlinear or discontinuous metrics produce apparent emergent abilities, whereas linear or continuous metrics produce smooth, continuous predictable changes in model performance. Across a mathematical model, language-model tasks, BIG-Bench meta-analysis, and vision tasks, we provide evidence that alleged emergent abilities evaporate with different metrics or with better statistics.",
        {"source_kind": "conference_pdf", "field": "paper.abstract", "url": "https://papers.neurips.cc/paper_files/paper/2023/file/adc98a266f45005c403b8311ca7e8bd7-Paper-Conference.pdf"},
    ),
    "How to Use the Sharpe Ratio": (
        "The Sharpe ratio is the dominant metric for evaluating investment skill, yet inference based on it is routinely flawed—often leading to false confidence, incorrect conclusions, and costly decisions. This paper proposes a new standard for Sharpe ratio inference and reporting by diagnosing common sources of error and providing practical corrections grounded in modern statistical theory. We identify five recurring pitfalls: reporting point estimates without statistical significance; biased inference from assuming independent and identically distributed Normal returns; ignoring test power and minimum sample length; misinterpreting p-values; and failing to correct for multiple testing and selection effects.",
        {"source_kind": "ssrn_abstract", "field": "publisher.abstract", "url": "https://papers.ssrn.com/sol3/papers.cfm?abstract_id=5520741"},
    ),
    "On the use of cross-validation for time series predictor evaluation": (
        "In time series predictor evaluation, there is a gap between traditional forecasting procedures and machine learning evaluation. Traditional forecasting commonly reserves the last part of each series for testing, while machine learning often uses cross-validation despite temporal evolution and dependence. In an extensive empirical study of six model-selection procedures and four regression techniques, no practical consequences of the theoretical flaws were found, while cross-validation led to more robust model selection. The authors suggest blocked cross-validation as a standard procedure to use all available information while circumventing the theoretical problems.",
        {"source_kind": "publisher_abstract", "field": "publisher.abstract", "url": "https://doi.org/10.1016/j.ins.2011.12.028"},
    ),
    "The three-pass regression filter: A new approach to forecasting using many predictors": (
        "We forecast a single time series using many predictor variables with a new estimator called the three-pass regression filter (3PRF). It is calculated in closed form and represented as a set of ordinary least squares regressions. 3PRF forecasts are consistent for the infeasible best forecast when both the time and cross-section dimensions become large. This requires specifying only the number of relevant factors driving the forecast target. The 3PRF is a constrained least squares estimator and reduces to partial least squares as a special case. Simulation evidence confirms its forecasting performance relative to alternatives.",
        {"source_kind": "paper_pdf", "field": "paper.abstract", "url": "https://economics.sas.upenn.edu/sites/default/files/filevault/event_papers/Econometrics12052011.pdf"},
    ),
}


INSTITUTION_OVERRIDES: dict[str, list[str]] = {
    "A Non-Parametric Test of Independence": ["University of North Carolina at Chapel Hill"],
    "A survey of cross-validation procedures for model selection": [
        "Centre National de la Recherche Scientifique",
        "École Normale Supérieure",
        "Université de Lille",
        "INRIA",
        "Laboratoire Paul Painlevé",
    ],
    "A Time Series is Worth 64 Words: Long-term Forecasting with Transformers": [
        "Princeton University",
        "IBM Research",
    ],
    "Are Emergent Abilities of Large Language Models a Mirage?": ["Stanford University"],
    "Attention Is All You Need": ["Google Brain", "Google Research", "University of Toronto"],
    "Bayesian Deep Learning and a Probabilistic Perspective of Generalization": ["New York University"],
    "Benign overfitting in linear regression": [
        "University of California, Berkeley",
        "Google Brain",
        "Universitat Pompeu Fabra",
        "Institució Catalana de Recerca i Estudis Avançats",
        "Barcelona School of Economics",
    ],
    "Control Chart Tests Based on Geometric Moving Averages": ["Bell Telephone Laboratories"],
    "CoST: Contrastive Learning of Disentangled Seasonal-Trend Representations for Time Series Forecasting": [
        "Salesforce Research Asia",
        "Singapore Management University",
    ],
    "Decoupled Weight Decay Regularization": ["University of Freiburg"],
    "Do We Need Zero Training Loss After Achieving Zero Training Error?": [
        "The University of Tokyo",
        "RIKEN",
        "NEC Corporation",
    ],
    "Efficiently Inefficient Markets for Assets and Asset Management": [
        "University of California, Berkeley",
        "Copenhagen Business School",
        "New York University",
        "National Bureau of Economic Research",
        "Centre for Economic Policy Research",
        "AQR Capital Management",
    ],
    "Emergent Abilities of Large Language Models": [
        "Google Research",
        "Stanford University",
        "University of North Carolina at Chapel Hill",
        "DeepMind",
    ],
    "Empirical properties of asset returns: stylized facts and statistical issues": [
        "Centre de Mathématiques Appliquées, École Polytechnique"
    ],
    "Explaining neural scaling laws": ["Google DeepMind", "Johns Hopkins University"],
    "Flat Minima": [
        "Technical University of Munich",
        "Dalle Molle Institute for Artificial Intelligence Research",
    ],
    "Gaussian Error Linear Units (GELUs)": [
        "University of California, Berkeley",
        "Toyota Technological Institute at Chicago",
    ],
    "Git Re-Basin: Merging Models modulo Permutation Symmetries": ["University of Washington"],
    "Graph Attention Networks": [
        "University of Cambridge",
        "Centre de Visió per Computador, Universitat Autònoma de Barcelona",
        "Montréal Institute for Learning Algorithms",
    ],
    "How to Use the Sharpe Ratio": [
        "Abu Dhabi Investment Authority",
        "ADIA Lab",
        "Cornell University",
    ],
    "Improving generalization performance using double backpropagation": ["AT&T Bell Laboratories"],
    "Is There a Replication Crisis in Finance?": [
        "Copenhagen Business School",
        "Yale School of Management",
        "Centre for Economic Policy Research",
    ],
    "Layer Normalization": ["University of Toronto"],
    "Leakage and the reproducibility crisis in machine-learning-based science": [
        "Princeton University",
        "Center for Information Technology Policy, Princeton University",
    ],
    "MINIROCKET: A Very Fast (Almost) Deterministic Transform for Time Series Classification": [
        "Monash University"
    ],
    "Long Short-Term Memory": [
        "Technical University of Munich",
        "Dalle Molle Institute for Artificial Intelligence Research",
    ],
    "Neural Tangent Kernel: Convergence and Generalization in Neural Networks": [
        "École Polytechnique Fédérale de Lausanne"
    ],
    "On Embeddings for Numerical Features in Tabular Deep Learning": ["Yandex Research", "HSE University"],
    "On Large-Batch Training for Deep Learning: Generalization Gap and Sharp Minima": [
        "Northwestern University",
        "Intel Corporation",
    ],
    "On the Variance of the Adaptive Learning Rate and Beyond": [
        "Georgia Institute of Technology",
        "Microsoft Research",
        "University of Illinois Urbana-Champaign",
    ],
    "Scaling Laws for Neural Language Models": ["Johns Hopkins University", "OpenAI"],
    "Similarity of Neural Network Representations Revisited": ["Google Brain", "University of Michigan"],
    "Spectral Normalization for Generative Adversarial Networks": [
        "Preferred Networks, Inc.",
        "Ritsumeikan University",
        "National Institute of Informatics",
    ],
    "Symbolic Discovery of Optimization Algorithms": ["Google Research"],
    "The Adaptive Markets Hypothesis": [
        "MIT Sloan School of Management",
        "AlphaSimplex Group",
    ],
    "Three Factors Influencing Minima in SGD": [
        "Mila — Quebec AI Institute",
        "Université de Montréal",
        "Ruhr University Bochum",
        "University of Edinburgh",
    ],
    "Training Compute-Optimal Large Language Models": ["DeepMind"],
    "TS2Vec: Towards Universal Representation of Time Series": [
        "Peking University",
        "Microsoft Research",
    ],
    "Understanding Why Neural Networks Generalize Well Through GSNR of Parameters": [
        "Ytech — Kuaishou Technology",
        "Samsung Research China — Beijing (SRC-B)",
    ],
    "Unsupervised Representation Learning for Time Series with Temporal Neighborhood Coding": [
        "University of Toronto",
        "Vector Institute",
        "The Hospital for Sick Children",
    ],
    "We need to talk about random seeds": ["University of Arizona"],
    "When do systematic strategies decay?": [
        "Capital Fund Management",
        "Massachusetts Institute of Technology",
        "National Bureau of Economic Research",
        "Centre for Economic Policy Research",
    ],
}


def _core_quote(abstract: str) -> str:
    sentences = [value.strip() for value in re.split(r"(?<=[.!?])\s+", abstract) if len(value.strip()) >= 40]
    preferred = [
        value
        for value in sentences
        if re.search(r"\b(?:we (?:find|show|propose|suggest|provide|introduce)|results? show|conclusion|outperform|remains?|raises? serious|is consistent|are consistent)\b", value, re.I)
    ]
    chosen = preferred[-2:] if preferred else sentences[-2:]
    quote = " ".join(chosen).strip()
    return quote if len(quote) >= 40 else abstract


def main() -> int:
    draft = json.loads(DRAFT.read_text(encoding="utf-8"))
    if len(draft.get("papers", [])) != 78:
        raise RuntimeError("draft does not contain 78 papers")
    reviewed: dict[str, Any] = {
        "schema_version": "qrh-substantive-evidence-enrichment-reviewed/v1",
        "reviewed_at": datetime.now(UTC).isoformat(),
        "review_policy": "English fields are verbatim source evidence; Chinese fields are reviewed reading aids bound to the English hash.",
        "papers": [],
    }
    for source in draft["papers"]:
        title = str(source["title"])
        institution_records = list(
            (source.get("institution_source") or {}).get("records") or []
        )
        # PDF two-column extraction is useful for locating candidates, but it is
        # not authoritative enough to publish verbatim as an institution name.
        # Keep only structured bibliographic/authorship values unless a title has
        # an explicit first-page review override below.
        institutions: list[str] = []
        selected_records: list[dict[str, Any]] = []
        for record in institution_records:
            if record.get("source") == "paper_pdf_first_pages":
                continue
            value = str(record.get("value") or "").strip()
            if value and value not in institutions:
                institutions.append(value)
                selected_records.append(record)
        if title in INSTITUTION_OVERRIDES:
            institutions = INSTITUTION_OVERRIDES[title]
            source_url = source.get("local_pdf_source_url")
            if not source_url and title in SOURCE_GAPS:
                source_url = SOURCE_GAPS[title][1].get("url")
            selected_records = [
                {
                    "source": (
                        "manual_exact_title_pdf_first_page_review"
                        if source.get("local_pdf_sha256")
                        else "manual_exact_title_official_bibliographic_review"
                    ),
                    "value": value,
                    "source_url": source_url,
                    "local_pdf_relative_path": source.get("local_pdf_relative_path"),
                    "local_pdf_sha256": source.get("local_pdf_sha256"),
                    "reviewed_pdf_pages": [1] if source.get("local_pdf_sha256") else [],
                }
                for value in institutions
            ]
        if not institutions:
            raise RuntimeError(f"institution review required: {title}")
        item: dict[str, Any] = {
            "paper_id": source["paper_id"],
            "title": title,
            "institutions": institutions,
            "institution_source": {
                "source_kind": "reviewed_bibliographic_authorship_or_exact_title_first_page",
                "observations": selected_records,
                "manual_override": title in INSTITUTION_OVERRIDES,
                "identifiers": source.get("identifiers") or {},
                "local_pdf_relative_path": source.get("local_pdf_relative_path"),
                "local_pdf_sha256": source.get("local_pdf_sha256"),
                "source_url": source.get("local_pdf_source_url"),
            },
            "abstract_text": None,
            "abstract_sha256": None,
            "abstract_source": None,
            "abstract_translation_zh": None,
            "synthesis_zh": None,
            "core_conclusion_text": None,
            "core_conclusion_source": None,
            "local_pdf_relative_path": source.get("local_pdf_relative_path"),
            "local_pdf_sha256": source.get("local_pdf_sha256"),
            "local_pdf_bytes": source.get("local_pdf_bytes"),
            "local_pdf_source_url": source.get("local_pdf_source_url"),
        }
        needs_supplement = not source.get("existing_abstract") or not source.get("existing_conclusion")
        if needs_supplement:
            abstract = str(source.get("abstract_text") or "").strip()
            abstract_source = source.get("abstract_source")
            if not abstract and title in SOURCE_GAPS:
                abstract, abstract_source = SOURCE_GAPS[title]
            if not abstract or not isinstance(abstract_source, dict):
                raise RuntimeError(f"abstract source review required: {title}")
            if title not in ZH:
                raise RuntimeError(f"Chinese review required: {title}")
            translation, synthesis = ZH[title]
            item.update(
                {
                    "abstract_text": abstract,
                    "abstract_sha256": hashlib.sha256(abstract.encode("utf-8")).hexdigest(),
                    "abstract_source": abstract_source,
                    "abstract_translation_zh": translation,
                    "synthesis_zh": synthesis,
                    "core_conclusion_text": _core_quote(abstract),
                    "core_conclusion_source": {
                        **abstract_source,
                        "claim_scope": (
                            "bibliographic_abstract_verbatim"
                            if abstract_source.get("source_kind") == "openalex"
                            else "source_abstract_verbatim"
                        ),
                    },
                }
            )
        reviewed["papers"].append(item)
    reviewed["papers"].sort(key=lambda value: str(value["title"]).casefold())
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(reviewed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"papers": len(reviewed["papers"]), "translated": len(ZH)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
