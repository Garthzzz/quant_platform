"""Evidence 论文页的研究员向中文解读。

这个模块只负责展示语义，不改变论文事实、Evidence 数据库或 Archive 原文。
当前库中的论文使用逐题策展的核心洞见与量化含义；未来论文则从已有中文综述
和标题主题生成保守的阅读提示。审计状态、来源哈希和内部处理边界不会进入输出。
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from collections.abc import Iterable, Mapping
from typing import Any


@dataclass(frozen=True, slots=True)
class InsightSpec:
    """一篇论文在研究阅读层最值得保留的两层信息。"""

    core: str
    quant_value: str


# 逐题文案只陈述论文标题和现有核心结论能够支持的机制，不额外添加收益数字、
# 显著性或样本外表现。与 Archive 的具体连接由下方关系语境函数补充。
PAPER_INSIGHTS: dict[str, InsightSpec] = {
    "A Non-Parametric Test of Independence": InsightSpec(
        "Hoeffding 检验把变量独立性转化为基于秩的非参数统计量，因此能够捕捉不止线性相关的依赖结构。",
        "在低信噪比因子筛选中，它适合用来检查因子与未来收益之间是否仍存在一般性的统计依赖，避免把“线性相关接近零”误判成“完全没有信息”。",
    ),
    "Ordinal Measures of Association": InsightSpec(
        "这项工作系统讨论了序数变量之间的关联度量，核心是利用成对次序的一致与冲突来刻画单调关系。",
        "对横截面选股而言，这提供了理解 Rank IC、排序命中和分组单调性的统计基础：我们关心的常常是股票相对次序，而不是收益幅度的线性拟合。",
    ),
    "Control Chart Tests Based on Geometric Moving Averages": InsightSpec(
        "几何移动平均控制图通过递减权重累积历史观测，使小而持续的分布变化比单点异常更容易被识别。",
        "它可用于监控因子 IC、损失或残差的缓慢漂移，为策略退化预警提供比固定窗口均值更连续的状态量。",
    ),
    "Improving generalization performance using double backpropagation": InsightSpec(
        "双重反向传播在拟合误差之外惩罚输出对输入的敏感度，让模型倾向于更平滑的输入—输出映射。",
        "在噪声占主导的选股数据里，这类敏感度约束可减少模型追逐微小特征扰动，但仍需用时序样本外结果判断平滑是否真正转化为稳健预测。",
    ),
    "Flat Minima": InsightSpec(
        "平坦极小值把泛化与参数扰动下损失是否快速恶化联系起来：宽而平的解通常比尖锐解对权重误差更不敏感。",
        "对量化模型训练，它提示我们不要只比较训练损失，还应观察不同随机种子、权重扰动和时间切片下预测是否保持一致。",
    ),
    "Long Short-Term Memory": InsightSpec(
        "LSTM 通过带门控的记忆单元控制信息写入、保留与遗忘，缓解普通循环网络在长序列上的梯度衰减。",
        "用于因子历史序列时，它能够学习跨期状态，但门控容量也会放大过拟合空间，因此应与更简单的聚合器在严格滚动回测中比较增量价值。",
    ),
    "Information-theoretic determination of minimax rates of convergence": InsightSpec(
        "这项工作用信息论下界刻画统计估计在最不利情形下能够达到的收敛速度，从而区分算法不足与问题本身的信息限制。",
        "它提醒低信噪比选股研究：当样本量、维度和信号强度决定了可辨识上限时，更复杂的模型未必能突破统计极限，评价重点应转向误差尺度与样本效率。",
    ),
    "Noise Dressing of Financial Correlation Matrices": InsightSpec(
        "论文用随机矩阵视角说明，有限样本估计的金融相关矩阵中，大量特征值可能只是噪声对真实相关结构的包裹。",
        "在风险模型、因子去冗余和组合优化中，这意味着不能把样本相关矩阵的每个主成分都当作稳定结构，应先检验谱分量能否跨窗口复现。",
    ),
    "Empirical properties of asset returns: stylized facts and statistical issues": InsightSpec(
        "这篇综述归纳资产收益的尖峰厚尾、波动聚集和非线性依赖等经验事实，强调真实金融序列偏离简单独立同分布假设。",
        "它为回测与风险评估设定了现实基线：误差估计、抽样方法和模型诊断都应允许尾部风险、条件异方差与时间依赖存在。",
    ),
    "PAC-Bayesian Stochastic Model Selection": InsightSpec(
        "PAC-Bayes 把模型随机化、经验误差和复杂度惩罚放进同一泛化界，为数据驱动的模型选择提供概率化控制。",
        "在多因子、多模型搜索中，这一视角有助于把候选数量和参数不确定性计入选择代价，减少只凭最佳回测结果挑模型造成的乐观偏差。",
    ),
    "A well-conditioned estimator for large-dimensional covariance matrices": InsightSpec(
        "该估计量通过收缩样本协方差改善高维条件数，使有限样本下的协方差矩阵更稳定、更易求逆。",
        "它直接服务于组合风险、横截面残差相关和因子暴露估计：稳定的协方差输入通常比未经处理的高维样本矩阵更适合下游优化。",
    ),
    "The Adaptive Markets Hypothesis": InsightSpec(
        "适应性市场假说把市场效率视为竞争、学习与环境变化共同产生的动态状态，而不是永远成立或永远失效的静态命题。",
        "对因子研究而言，这意味着收益来源和失效速度应按市场状态、参与者拥挤与制度变化分层评估，不能用全样本平均掩盖条件性。",
    ),
    "An introduction to ROC analysis": InsightSpec(
        "ROC 分析用不同阈值下的真阳性率与假阳性率描述分类器的排序能力，并把阈值选择与类别比例区分开。",
        "在选股或风险预警中，它适合评价相对排序和阈值权衡，但不能替代收益幅度、换手成本与校准误差等经济指标。",
    ),
    "A survey of cross-validation procedures for model selection": InsightSpec(
        "这篇综述比较多种交叉验证方案如何估计泛化误差，并揭示训练规模、方差与模型选择偏差之间的权衡。",
        "量化建模应据此把验证方案视为模型的一部分：折分方式必须尊重数据依赖，且最终性能不能复用参与调参的验证结果。",
    ),
    "On the use of cross-validation for time series predictor evaluation": InsightSpec(
        "论文讨论时间序列预测中交叉验证的适用条件，关键在于折分不能破坏预测时可获得的信息集合。",
        "在因子与收益预测里，应以按时间推进的训练—验证结构控制前视和相邻样本污染，而不是直接套用随机打乱的独立样本折分。",
    ),
    "Dropout Training as Adaptive Regularization": InsightSpec(
        "该分析把 Dropout 解释为随特征尺度和数据分布变化的自适应正则化，而不只是随机删除神经元的工程技巧。",
        "对低信噪比模型，它提供了一种抑制特征共适应的机制；是否有效仍应通过跨种子稳定性和滚动样本外结果与显式正则化比较。",
    ),
    "The three-pass regression filter: A new approach to forecasting using many predictors": InsightSpec(
        "三步回归滤波器从大量预测变量中提取与目标相关的低维因子，重点保留预测方向而非解释所有协变量方差。",
        "这对高维因子压缩很关键：无监督主成分可能保留最大方差却丢失微弱收益信号，目标导向的降维更贴近横截面预测任务。",
    ),
    "Backtesting": InsightSpec(
        "论文把回测看作带有多重尝试和选择偏差的统计推断问题，漂亮的历史曲线并不自动等同于可复制的策略能力。",
        "它要求研究流程记录试验次数、控制数据窥探，并把最终判断建立在真正未参与选择的样本和现实交易约束上。",
    ),
    "Batch Normalization: Accelerating Deep Network Training by Reducing Internal Covariate Shift": InsightSpec(
        "Batch Normalization 以小批量统计量标准化中间激活，并学习恢复合适尺度，从而改变深层网络的优化条件。",
        "在时序和横截面量化数据中，批统计可能混合不同日期或市场状态；使用前要确认训练与推理统计不会引入跨期信息或分布错配。",
    ),
    "Characterizing concept drift": InsightSpec(
        "概念漂移框架区分数据分布、目标关系及其变化方式，使“模型失效”能够被拆解为不同类型的环境变化。",
        "因子衰减诊断可据此判断是特征分布变了、收益映射变了，还是仅出现短期噪声，从而选择重训、重加权或停止策略。",
    ),
    "Gaussian Error Linear Units (GELUs)": InsightSpec(
        "GELU 依据输入大小进行平滑的随机门控解释，以连续方式调节激活而非像 ReLU 那样硬截断负值。",
        "它对量化网络主要是优化与表达细节，不应仅凭激活函数更复杂就预期收益提升；应比较收敛稳定性和样本外增量。",
    ),
    "Layer Normalization": InsightSpec(
        "Layer Normalization 在单个样本内部对特征维度标准化，不依赖批量统计，因此更适合变长序列和循环结构。",
        "对因子时序编码器，它可避免跨股票或跨日期批统计相互污染，但仍需检查归一化是否抹去有经济意义的绝对尺度。",
    ),
    "On Large-Batch Training for Deep Learning: Generalization Gap and Sharp Minima": InsightSpec(
        "论文把大批量训练的泛化差距与更易落入尖锐极小值联系起来，说明更快的优化不一定带来更稳健的解。",
        "在量化训练管线里，批量大小应与学习率、噪声尺度和跨种子表现联合选择，而不是只按吞吐量最大化。",
    ),
    "Simple and Scalable Predictive Uncertainty Estimation using Deep Ensembles": InsightSpec(
        "Deep Ensemble 通过多个独立初始化模型的预测分布同时表达平均预测与模型间分歧，是简单而实用的不确定性估计方法。",
        "用于选股时，模型分歧可作为仓位缩放、拒绝交易和稳定性诊断信号，比只看单模型点预测更能暴露参数不确定性。",
    ),
    "Robust Large Margin Deep Neural Networks": InsightSpec(
        "大间隔深度网络通过约束分类边界附近的几何裕度，提高预测对输入扰动的稳定性。",
        "在量化分类或排序任务中，它启发我们关注决策边界的安全距离，但稳健性必须在符合金融噪声结构的扰动与时间外样本中检验。",
    ),
    "Sharp Minima Can Generalize For Deep Nets": InsightSpec(
        "这项工作指出参数重标定会改变表观 sharpness，却不改变网络函数，因此简单的损失曲率不能单独判定泛化好坏。",
        "量化训练诊断不应把某个 sharpness 数值当成放行标准，而应与函数输出稳定性、跨种子一致性和样本外误差共同使用。",
    ),
    "Self-Normalizing Neural Networks": InsightSpec(
        "自归一化网络利用特定激活与初始化，使深层前馈网络的激活均值和方差趋向稳定范围。",
        "对表格型因子模型，它可能减少层间尺度漂移，但输入缺失、厚尾和截面标准化会改变这一机制，需要在真实数据处理链上验证。",
    ),
    "Attention Is All You Need": InsightSpec(
        "Transformer 以自注意力直接建模序列位置之间的依赖，摆脱循环计算并提高长距离交互的并行效率。",
        "在因子历史序列中，它提供了跨期选择性聚合能力；但参数量和注意力自由度很高，必须证明相对简单时序基线的稳定增量。",
    ),
    "Graph Attention Networks": InsightSpec(
        "图注意力网络为每个节点学习邻居权重，使信息聚合能够随节点关系和任务目标自适应变化。",
        "在股票关系图中，它可表达行业、供应链或相关性网络的异质影响，但图的构造时间与边信息必须严格防止前视。",
    ),
    "Three Factors Influencing Minima in SGD": InsightSpec(
        "论文分析学习率、批量大小与梯度协方差等因素如何共同影响 SGD 最终到达的极小值。",
        "这意味着量化模型的训练可靠性不能只归因于网络结构；优化超参数与随机梯度噪声同样会改变解及跨种子差异。",
    ),
    "Decoupled Weight Decay Regularization": InsightSpec(
        "AdamW 将权重衰减从自适应梯度更新中解耦，使衰减强度不再被每个参数的学习率缩放所扭曲。",
        "在量化深度模型中，这让容量控制更容易解释和调节，但仍应在相同搜索预算下比较，而不是把优化器名称当作性能保证。",
    ),
    "Efficiently Inefficient Markets for Assets and Asset Management": InsightSpec(
        "论文刻画信息获取成本、主动管理资本与价格效率之间的均衡：市场可以足够有效，同时仍给少数研究能力留下回报。",
        "因子收益应因此与研究拥挤、交易成本和可承载资本共同解释；历史 alpha 并非固定常数，而会随套利资本进入而收缩。",
    ),
    "Deep Learning for Forecasting Stock Returns in the Cross-Section": InsightSpec(
        "这项研究把深度学习用于横截面收益预测，利用非线性结构组合大量公司特征并形成股票排序。",
        "它是复杂模型增量价值的直接基准：比较时应统一特征、成本和时间切分，判断提升来自非线性交互还是更大的搜索空间。",
    ),
    "Spectral Normalization for Generative Adversarial Networks": InsightSpec(
        "谱归一化通过控制权重矩阵的最大奇异值约束网络的 Lipschitz 敏感度，使训练映射更平稳。",
        "迁移到量化预测时，它可作为控制输入扰动放大的工具，但目标应是改善跨期稳定性，而不是机械复制生成模型配置。",
    ),
    "The Lottery Ticket Hypothesis: Finding Sparse, Trainable Neural Networks": InsightSpec(
        "彩票假设表明，过参数化网络中可能存在带特定初始化的稀疏子网络，单独训练也能达到有竞争力的表现。",
        "对量化建模，它提示有效容量可能远小于名义参数量；剪枝与稀疏化可用于检验信号是否依赖大量脆弱参数。",
    ),
    "Averaging Weights Leads to Wider Optima and Better Generalization": InsightSpec(
        "随机权重平均沿 SGD 轨迹聚合多个权重点，往往落在更宽损失盆地的中心而非边缘。",
        "在量化训练中，它是成本较低的稳定化手段，可与跨种子集成比较其对预测方差和滚动样本外表现的改善。",
    ),
    "Generalized Cross Entropy Loss for Training Deep Neural Networks with Noisy Labels": InsightSpec(
        "广义交叉熵在常用交叉熵与更抗噪的绝对误差之间提供连续权衡，降低错误标签对梯度的支配。",
        "当收益方向或分组标签噪声很高时，这类损失可减少极端错标影响，但必须避免以鲁棒损失掩盖标签定义本身不稳定。",
    ),
    "Neural Tangent Kernel: Convergence and Generalization in Neural Networks": InsightSpec(
        "神经切线核描述无限宽网络在梯度训练下近似固定核方法的动力学，为过参数化网络的收敛提供可分析极限。",
        "它帮助量化研究区分“深层表示学习”与“宽网络核回归”带来的效果，检验复杂网络是否真的学到新的因子交互。",
    ),
    "Size and value in China": InsightSpec(
        "论文研究中国股票市场中的规模与价值效应，并把本地市场结构纳入经典资产定价因子的检验。",
        "它提醒因子评价不能直接照搬海外结论：股票池、上市板块、壳价值与交易制度会改变暴露定义和收益解释。",
    ),
    "A Backtesting Protocol in the Era of Machine Learning": InsightSpec(
        "该协议针对机器学习策略的高维搜索与反复调参，要求把研究选择过程本身纳入回测设计。",
        "实际管线应隔离训练、选择与最终评估数据，并记录搜索预算，让模型增量价值不被数据泄漏和多重尝试夸大。",
    ),
    "Deep Adaptive Input Normalization for Time Series Forecasting": InsightSpec(
        "DAIN 学习对每条时间序列进行自适应平移、缩放和门控，使输入归一化随样本状态变化。",
        "在非平稳因子序列中，它可能缓解尺度漂移，但归一化参数必须只使用当时可见历史，且要检查是否误删有预测意义的水平信息。",
    ),
    "Similarity of Neural Network Representations Revisited": InsightSpec(
        "CKA 提供对正交变换和各向同性缩放稳定的表示相似度，使不同网络层或随机种子的内部表征可以比较。",
        "量化训练可靠性可用它判断模型是否在不同种子下学到相近结构；相似度应与预测排序一致性和样本外结果联合解释。",
    ),
    "N-BEATS: Neural basis expansion analysis for interpretable time series forecasting": InsightSpec(
        "N-BEATS 用堆叠的前向与后向残差块分解时间序列，并可通过趋势、季节基函数增强可解释性。",
        "对因子历史压缩，它提供了结构化分解基线，可检验深度残差表示是否比简单趋势、季节或线性投影保留更多预测信息。",
    ),
    "Differentiable Ranks and Sorting using Optimal Transport": InsightSpec(
        "论文用最优传输构造排序与秩的平滑近似，使原本不可微的次序操作能够进入梯度优化。",
        "这与横截面选股高度契合：训练目标可以更接近 Rank IC 或分组排序，但近似温度与批内股票集合会影响梯度和经济含义。",
    ),
    "On the Variance of the Adaptive Learning Rate and Beyond": InsightSpec(
        "RAdam 从自适应学习率早期方差过大的角度修正 Adam，使训练初期的步长更可控。",
        "对高噪声量化网络，它主要改善优化过程的可重复性；是否减少跨种子差异应通过同预算实验而非单次最优结果判断。",
    ),
    "InceptionTime: Finding AlexNet for Time Series Classification": InsightSpec(
        "InceptionTime 用多尺度卷积核与残差连接构造通用时间序列分类器，同时捕捉不同长度的局部模式。",
        "在因子序列任务中，它是评估多尺度形态信息的强卷积基线，可与 Transformer 或自监督表征比较复杂度—收益权衡。",
    ),
    "Deep Ensembles: A Loss Landscape Perspective": InsightSpec(
        "这项工作从损失景观解释深度集成为何有效：不同初始化可能到达功能上互补的解，而不只是同一模型的重复。",
        "对量化模型，集成价值应由预测分歧是否对应真实不确定性来衡量，并与简单权重平均及单模型跨种子稳定性比较。",
    ),
    "Benign overfitting in linear regression": InsightSpec(
        "良性过拟合说明某些高维线性问题即使训练误差为零，合适的谱结构与信号分布仍可能带来良好泛化。",
        "它提醒因子研究不要用参数数目或零训练误差单独判死刑，而要检查特征协方差谱、噪声方向和真正的时间外误差。",
    ),
    "Understanding Why Neural Networks Generalize Well Through GSNR of Parameters": InsightSpec(
        "参数梯度信噪比刻画梯度均值相对随机波动的强弱，用来连接优化过程中哪些参数方向携带稳定学习信号。",
        "在低信噪比训练中，GSNR 可辅助识别更新是否主要由批次噪声驱动，并解释不同层或种子为何形成不稳定预测。",
    ),
    "Scaling Laws for Neural Language Models": InsightSpec(
        "神经语言模型的损失随模型规模、数据量与计算量呈近似幂律变化，说明资源扩张存在可预测但递减的收益。",
        "对量化模型，它提供的是实验设计思路：画出容量、样本和算力的误差曲线，判断复杂度增量是否仍有效，而不是直接套用语言模型尺度。",
    ),
    "Do We Need Zero Training Loss After Achieving Zero Training Error?": InsightSpec(
        "论文研究分类正确之后继续压低交叉熵的作用，区分零训练错误与继续扩大分类间隔的优化阶段。",
        "量化训练可据此检查长时间拟合究竟提高了可迁移的排序间隔，还是只让概率更极端并放大非平稳样本的过度自信。",
    ),
    "Fast Differentiable Sorting and Ranking": InsightSpec(
        "该方法通过投影到排序相关的凸集合实现快速可微排序，在保持计算效率的同时为秩目标提供梯度。",
        "它可让横截面模型直接优化排序型目标，但训练批次、并列值和正则强度必须与实际股票截面定义一致。",
    ),
    "Bayesian Deep Learning and a Probabilistic Perspective of Generalization": InsightSpec(
        "这篇工作从贝叶斯与后验平均视角理解深度学习泛化，把参数不确定性和预测分布纳入模型解释。",
        "在量化决策中，重点不是只给一个收益预测，而是把不确定性传递到仓位、风险预算和拒绝交易规则。",
    ),
    "Hyperparameter Ensembles for Robustness and Uncertainty Quantification": InsightSpec(
        "超参数集成把结构与训练配置差异也纳入模型分歧，比只改变随机种子覆盖更广的不确定性来源。",
        "它适合检验量化信号是否依赖某个狭窄超参数点；若相邻合理配置结论相反，单次最佳回测不应被视为稳健发现。",
    ),
    "Sharpness-Aware Minimization for Efficiently Improving Generalization": InsightSpec(
        "SAM 优化参数邻域内的最坏损失，而非只降低当前点损失，从而偏向对权重扰动更稳定的解。",
        "在量化模型中可把它视为训练稳健化候选，但需要控制额外计算并验证其是否改善跨时间、跨种子表现，而非只改变训练曲线。",
    ),
    "MINIROCKET: A Very Fast (Almost) Deterministic Transform for Time Series Classification": InsightSpec(
        "MiniRocket 用近乎固定的大量卷积核与简单汇总构造快速时间序列特征，减少昂贵的端到端参数学习。",
        "它是低信噪比序列建模的重要强基线：若复杂编码器无法稳定超过这种近确定性变换，其工程和过拟合成本就难以成立。",
    ),
    "Towards Understanding Ensemble, Knowledge Distillation and Self-Distillation in Deep Learning": InsightSpec(
        "论文从预测多样性与软目标角度联系集成、知识蒸馏和自蒸馏，解释单模型如何吸收多个解的结构信息。",
        "量化应用可用蒸馏压缩集成并保留部分稳定性收益，但必须检查被压缩的是共识信号还是过度平滑后的弱预测。",
    ),
    "Attention is Not All You Need: Pure Attention Loses Rank Doubly Exponentially with Depth": InsightSpec(
        "该分析指出缺少跳连与前馈层的纯自注意力会随深度快速走向低秩 token 表示，导致表达坍缩。",
        "对因子序列编码器，这解释了为何注意力不能孤立使用；残差、前馈变换和表征秩诊断都关系到跨期信息是否被保留。",
    ),
    "Unsupervised Representation Learning for Time Series with Temporal Neighborhood Coding": InsightSpec(
        "TNC 依据时间邻域构造自监督判别任务，让表示保留局部平稳片段及其随时间变化的结构。",
        "在因子历史序列中，它可减少对收益标签的直接依赖，但邻域长度必须匹配市场状态持续性，避免把跨状态样本误当相似。",
    ),
    "TS2Vec: Towards Universal Representation of Time Series": InsightSpec(
        "TS2Vec 在不同时间尺度上进行层次化对比学习，为每个时间点生成可聚合到任意子序列的上下文表示。",
        "用于低信噪比选股时，它适合检验“先学通用时序表示、再做简单预测”能否比直接监督拟合更稳健地保留跨期信息。",
    ),
    "Machine learning in the Chinese stock market": InsightSpec(
        "这项研究把机器学习预测框架应用于中国股票横截面，考察非线性模型如何利用本地公司特征。",
        "其价值在于提供本土基准：模型比较必须考虑中国市场的股票池、交易限制和制度阶段，不能直接外推美国市场经验。",
    ),
    "When do systematic strategies decay?": InsightSpec(
        "论文关注系统化策略何时以及为何衰减，把表现变化与拥挤、套利资本和市场环境联系起来。",
        "因子监控应由此区分暂时回撤与结构性失效，并结合暴露、换手、容量和状态条件判断是否降权或退出。",
    ),
    "Market efficiency in the age of big data": InsightSpec(
        "大数据与机器学习降低信息处理成本，同时也加快可预测模式被发现和竞争性消除的速度。",
        "量化研究因此要同时评估新特征带来的边际信息和其可复制期限，避免把更强的数据挖掘能力误当作永久 alpha。",
    ),
    "CoST: Contrastive Learning of Disentangled Seasonal-Trend Representations for Time Series Forecasting": InsightSpec(
        "CoST 通过对比学习把时间序列的趋势与季节成分分开表征，使预测模型能分别处理缓慢变化和周期结构。",
        "对因子序列压缩，它提供了带结构先验的表示方案；关键检验是分解后是否保留收益相关变化，而非只提高序列重构的整洁度。",
    ),
    "On Embeddings for Numerical Features in Tabular Deep Learning": InsightSpec(
        "论文研究如何把连续数值特征映射为更丰富的嵌入，使表格深度模型能够表达单变量非线性和跨特征交互。",
        "在横截面因子中，数值嵌入可替代粗糙分箱，但要检查阈值结构能否跨期稳定，并与样条、树模型等简单非线性基线比较。",
    ),
    "Training Compute-Optimal Large Language Models": InsightSpec(
        "Chinchilla 研究给定计算预算下模型规模与训练数据量的更优配比，指出参数更大但数据不足会浪费算力。",
        "量化建模可借鉴这一资源配比思想：在扩大网络前先判断独立时间样本是否足够，防止容量增长远快于有效信息量。",
    ),
    "Emergent Abilities of Large Language Models": InsightSpec(
        "论文记录某些任务能力在模型规模跨过区间后才明显出现的现象，强调平均损失曲线可能掩盖任务级变化。",
        "对量化架构研究，它提醒我们分任务观察容量效应，但不应把少量阈值式改善直接解释为可迁移的金融预测能力。",
    ),
    "Git Re-Basin: Merging Models modulo Permutation Symmetries": InsightSpec(
        "Git Re-Basin 利用神经元置换对称性对齐不同模型，使原本参数上分离的解可以在同一盆地中连接或合并。",
        "在跨种子量化模型比较中，它说明权重距离并不等于函数差异；表征一致性应先处理对称性，再结合预测输出判断。",
    ),
    "We need to talk about random seeds": InsightSpec(
        "这项工作展示随机种子会显著影响机器学习实验结论，单次运行无法代表训练方法的真实分布。",
        "量化研究应报告跨种子的均值、离散度和排序一致性，并把种子方差与时间切片方差一起纳入模型放行。",
    ),
    "A Time Series is Worth 64 Words: Long-term Forecasting with Transformers": InsightSpec(
        "PatchTST 把单变量时间序列切成 patch token，并以通道独立方式使用 Transformer，减少长序列注意力长度并保留局部形态。",
        "在因子历史压缩中，patch 是一种可解释的时间降采样；窗口长度决定模型看到的局部状态，必须防止把短暂噪声固化为 token。",
    ),
    "Are Emergent Abilities of Large Language Models a Mirage?": InsightSpec(
        "论文指出，非线性或离散评价指标可能把平滑的性能改善呈现为突然“涌现”，阈值外观未必对应机制突变。",
        "量化模型比较同样应检查指标刻度：Top-K 命中或显著性过线的跳变，可能来自度量方式，而非预测结构真正跃迁。",
    ),
    "Is There a Replication Crisis in Finance?": InsightSpec(
        "论文重新审视金融研究的可复制性，讨论因子发现数量、样本扩展和统一检验如何改变“失效”判断。",
        "对因子评价而言，复制不能只看原样本 t 值是否重现，还要统一定义、股票池和实现细节，并区分收益衰减与构造差异。",
    ),
    "Leakage and the reproducibility crisis in machine-learning-based science": InsightSpec(
        "这项工作把数据泄漏视为机器学习研究不可复现的重要来源：训练过程接触到本不该可见的信息会系统性抬高结果。",
        "量化管线尤其要隔离未来标签、截面预处理、特征选择与调参数据，任何一步跨越时间边界都可能让回测失真。",
    ),
    "Symbolic Discovery of Optimization Algorithms": InsightSpec(
        "论文用程序搜索发现优化更新规则，展示优化器本身也可以由任务反馈自动设计，而非完全依赖人工公式。",
        "对量化训练，它提供新的优化候选生成思路，但搜索出的规则必须在独立数据、不同模型与多种子下验证，防止优化器也过拟合基准。",
    ),
    "Self-Supervised Learning for Time Series Analysis: Taxonomy, Progress, and Prospects": InsightSpec(
        "这篇综述按生成式、对比式和辅助任务等目标梳理时间序列自监督学习，并比较不同表征粒度与下游任务。",
        "它为低信噪比因子序列建立方法地图：选择模型前应先明确希望保留的时间尺度、增强不变性和下游预测目标。",
    ),
    "Explaining neural scaling laws": InsightSpec(
        "论文从数据流形、模型容量与误差分解等机制解释神经网络尺度律为何呈现可预测的幂律。",
        "在量化研究中，尺度律可用于判断扩大数据或模型的边际收益是否进入平台期，但有效样本量必须考虑时间相关和状态重复。",
    ),
    "PFML: Self-Supervised Learning of Time-Series Data Without Representation Collapse": InsightSpec(
        "PFML 通过预测被遮蔽的频率成分学习时间序列表征，目标是在不依赖负样本的情况下避免表示坍缩。",
        "用于因子序列时，它提供频域自监督方案，可检验周期与多尺度动态是否提升下游排序；同时要防止频谱泄漏未来区间。",
    ),
    "How to Use the Sharpe Ratio": InsightSpec(
        "论文聚焦 Sharpe 比率的正确解释与使用，把点估计放回采样误差、非正态收益和比较场景中理解。",
        "策略评价不应只展示单个 Sharpe 数字，还应报告估计不确定性、样本长度、频率处理及多策略筛选带来的偏差。",
    ),
}


_FORBIDDEN_AUDIT_TERMS = (
    "核验",
    "证据边界",
    "事实边界",
    "摘要称",
    "官方摘要",
    "适用性受限",
    "结论限于",
    "未声称",
    "来源事实",
    "不替代全文",
    "逐字主张",
    "支持文本哈希",
    "source_verified",
    "provenance",
)

_RAW_FILE_SUFFIX = re.compile(r"\.(?:md|tex|json|txt|pdf)\b", re.IGNORECASE)
_SENTENCE_SPLIT = re.compile(r"(?<=[。！？!?])\s*")


def _clean_reader_text(value: object) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return ""
    sentences = _SENTENCE_SPLIT.split(text)
    kept = [
        sentence.strip()
        for sentence in sentences
        if sentence.strip()
        and not any(term.lower() in sentence.lower() for term in _FORBIDDEN_AUDIT_TERMS)
    ]
    return "".join(kept)


def _iter_relations(relations: object) -> Iterable[Mapping[str, Any]]:
    if not relations or isinstance(relations, (str, bytes)):
        return ()
    if isinstance(relations, Mapping):
        return (relations,)
    return (item for item in relations if isinstance(item, Mapping))


def _archive_context(relations: object, paper_title: str) -> str:
    """从真实 Archive 关系生成一句研究语境，不暴露内部路径或关系状态。"""

    candidates: list[tuple[int, Mapping[str, Any], str, str]] = []
    for relation in _iter_relations(relations):
        research_title = _clean_reader_text(relation.get("research_title"))
        excerpt = _clean_reader_text(relation.get("source_excerpt"))
        if (
            not research_title
            or _RAW_FILE_SUFFIX.search(research_title)
            or not excerpt
        ):
            continue
        # 优先选择包含真实研究语句而非只有方法名列表的关系。
        score = min(len(excerpt), 240)
        score += 80 if any(mark in excerpt for mark in ("因此", "所以", "意味着", "而不是", "需要")) else 0
        candidates.append((score, relation, research_title, excerpt))
    if not candidates:
        return ""

    _, relation, research_title, excerpt = max(candidates, key=lambda item: item[0])
    combined = f"{relation.get('document_title', '')} {relation.get('source_section_title', '')} {relation.get('usage_description', '')} {excerpt}"
    title_key = paper_title.casefold()
    if any(
        word in title_key
        for word in (
            "time series",
            "forecast",
            "temporal",
            "lstm",
            "n-beats",
            "ts2vec",
            "cost:",
            "minirocket",
            "inceptiontime",
            "numerical features",
        )
    ) or any(word in combined for word in ("序列表征", "时序表示", "历史序列压缩")):
        use = "判断时序表示究竟保留了可预测结构，还是只压缩了波动尺度与噪声"
    elif any(
        word in title_key
        for word in (
            "backtest",
            "sharpe",
            "replication",
            "leakage",
            "cross-validation",
            "random seeds",
            "strategies decay",
        )
    ):
        use = "把多重试验、样本隔离与绩效不确定性纳入策略证据门槛，避免把一次最优回测当成可复制能力"
    elif any(word in title_key for word in ("scaling", "emergent")):
        use = "检验模型规模、算力投入与指标跃迁是否形成可重复的量化增量，而不是度量方式制造的表面拐点"
    elif any(word in title_key for word in ("covariance", "correlation matrices")):
        use = "区分稳定的相关结构与有限样本噪声，改善风险估计、因子去冗余和组合优化输入"
    elif any(
        word in title_key
        for word in (
            "market",
            "asset",
            "stock",
            "factor",
            "ordinal",
            "independence",
            "rank",
            "roc",
        )
    ):
        use = "解释因子信号如何进入横截面评价，并把市场状态、拥挤和跨时期稳定性纳入判断"
    elif any(word in combined for word in ("训练可靠", "过拟合", "随机种子", "表征一致", "CKA")):
        use = "把优化稳定性、跨种子一致性与样本外泛化拆成可检查的训练诊断"
    elif any(word in combined for word in ("因子", "Rank IC", "IC", "选股", "横截面")):
        use = "解释因子排序信号如何进入横截面评价，并检验这种关系能否跨时期保持"
    elif any(word in combined for word in ("回测", "泄漏", "稳健", "复制", "衰减")):
        use = "约束回测中的信息边界与模型选择偏差，避免把一次最优历史结果当作可复制能力"
    elif any(word in combined for word in ("协方差", "相关矩阵", "风险")):
        use = "区分稳定的相关结构与有限样本噪声，改善风险估计和组合输入"
    elif any(word in combined for word in ("时间序列", "预测", "forecast", "时序")):
        use = "选择合适的时间尺度与表示目标，并检验下游预测是否真正受益"
    else:
        return ""
    return f"在《{research_title}》中，这项工作被用来{use}。"


def _chinese_conclusion_text(core_conclusions: object) -> str:
    if not core_conclusions:
        return ""
    if isinstance(core_conclusions, Mapping):
        items: Iterable[object] = (core_conclusions,)
    elif isinstance(core_conclusions, (str, bytes)):
        items = (core_conclusions,)
    else:
        items = core_conclusions
    for item in items:
        value = item.get("text") if isinstance(item, Mapping) else item
        cleaned = _clean_reader_text(value)
        if cleaned and len(re.findall(r"[\u3400-\u9fff]", cleaned)) >= 12:
            return cleaned
    return ""


def _fallback_spec(title: str, synthesis_zh: str, core_conclusions: object) -> InsightSpec:
    cleaned = _clean_reader_text(synthesis_zh) or _chinese_conclusion_text(core_conclusions)
    if cleaned:
        # 限制为前两句，避免把旧展示层的冗长元说明带回页面。
        sentences = re.split(r"(?<=[。！？!?])", cleaned)
        core = "".join(sentence for sentence in sentences[:2] if sentence).strip()
        if core and core[-1] not in "。！？!?":
            core += "。"
    else:
        core = f"这篇论文围绕“{title}”所界定的问题展开，阅读重点是其方法机制与可检验的结论。"

    lowered = title.lower()
    if any(key in lowered for key in ("time series", "forecast", "temporal")):
        quant_value = "对量化研究，关键是检验它能否在不泄漏未来信息的前提下保留稳定的跨期预测结构。"
    elif any(key in lowered for key in ("backtest", "replication", "leakage", "cross-validation")):
        quant_value = "它直接关系到回测可信度：训练、选择与最终评价必须按时间隔离，并把多重尝试纳入判断。"
    elif any(key in lowered for key in ("generalization", "minima", "ensemble", "normalization", "training")):
        quant_value = "它可用于完善训练可靠性诊断，重点观察跨种子、跨窗口和样本外预测是否一致。"
    elif any(key in lowered for key in ("rank", "stock", "market", "sharpe", "asset")):
        quant_value = "它与因子评价和选股决策直接相关，必须同时考虑排序质量、时间稳定性和交易后的经济意义。"
    else:
        quant_value = "在量化应用中，应把这一机制转化为可复现的基线比较，并用严格时序样本外结果判断增量价值。"
    return InsightSpec(core=core, quant_value=quant_value)


def build_researcher_insight(
    title: str,
    synthesis_zh: str | None = None,
    archive_relations: object = None,
    core_conclusions: object = None,
) -> str:
    """生成 2–3 句面向量化研究员的中文解读。

    ``core_conclusions`` 被保留在接口中，便于服务层用同一行传入完整论文上下文。
    当前 78 篇逐题文案已经从这些结论策展；未知论文仅使用已有中文综述生成
    保守回退，不对英文结论自动扩写，以免引入未在来源中出现的结果。
    """

    normalized_title = re.sub(r"\s+", " ", str(title or "")).strip()
    spec = PAPER_INSIGHTS.get(normalized_title)
    if spec is None:
        spec = _fallback_spec(
            normalized_title or "该研究",
            synthesis_zh or "",
            core_conclusions,
        )

    sentences = [spec.core, spec.quant_value]
    relation_context = _archive_context(archive_relations, normalized_title)
    if relation_context:
        sentences.append(relation_context)
    result = "".join(sentence.strip() for sentence in sentences if sentence.strip())

    # 此断言是展示层最后一道防线，防止调用方把后台审计文案拼回研究解读。
    leaked = [term for term in _FORBIDDEN_AUDIT_TERMS if term.lower() in result.lower()]
    if leaked:
        raise ValueError(f"researcher insight contains audit-only terms: {', '.join(leaked)}")
    return result


__all__ = ["InsightSpec", "PAPER_INSIGHTS", "build_researcher_insight"]
