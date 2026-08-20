---
name: reading-paper
description: Reads research paper deeply via four-phase protocol (Phase 1 orientation 15min → Phase 2 method depth 20min → Phase 3 result interpretation with independent judgment 20min → Phase 4 write outputs from understanding 20min, not field-by-field extraction). Self-checks "can I narrate fluently". Writes notes (six narrative sections) first, then JSON (39 fields). Use when doing deep paper reading or paper digesting workflow.
metadata:
  category: research
  version: 1.0.0
  evidence_grade: user 独家 (CLAUDE3 read_paper.md 实测 skill)
---

# reading-paper — 论文精读四阶段协议

## 视角

深度理解一篇论文,先读懂,再从理解中写 notes 和 JSON。**不是从原文逐字提取字段**,是读完整篇、形成自己的认识之后,**凭理解自然输出**。

## 进入前必读

- 项目 CLAUDE.md 的研究语境(若适用)
- `research/literature-quality-tier` — 评级判断
- `research/controlled-vocabulary` — 受控词表
- (若量化金融) 项目 CLAUDE.md 的 A 股适用性标准 / SNR 迁移性标注

## 四阶段阅读协议

### Phase 1 — 定向定位

读: 标题、摘要、引言尾段、结论首段、图表标题扫一遍。

**在脑中建立骨架**,必须能回答:
- 这篇在解决什么具体问题,已有方法哪里没解决好
- 核心方法的关键词是什么
- 最主要的结论和核心数字

### Phase 2 — 方法论深读

读: Data / Method / Model 章节,**完整读,不跳**。

**必须追问设计动机,不能只描述方法**:

**数据层**:
- 用了哪个市场,什么时间段,样本多大
- 特征怎么构造的,有没有前视偏差风险(标签是否用了未来信息)
- 训练/验证/测试集如何划分,有没有时间泄露

**模型层**:
- 每个核心模块为什么要这么设计,不用更简单的方法是因为什么
- 数据在每个模块里的形状怎么变化(写清楚具体维度)
- 特殊设计(loss、normalization、训练策略)背后的动机是什么
- 和已有方法相比,**真正新的是什么**(不是论文声称的,是实际上新的)

**训练层**:
- optimizer / lr / batch size / epoch
- 防过拟合设计,正则化策略

**自检**: 能否顺畅复述"这篇的做法是: 先...,然后用...模块做...,因为...,损失函数是...,最后..."
**卡壳说明没读透,回去补读,复述通顺再继续**。

### Phase 3 — 结果解读与独立判断

读: Experiments / Results / Ablation 章节。

**结果追问**:
- 核心指标多少,在什么具体条件下测出来的(市场 / 时间段 / universe)
- 消融实验在训练集 / 验证集 / OOS 哪个上做的,对结论可信度有何影响
- 消融实验哪个模块最重要,量级多大

**主动寻找问题**:
- **数据泄露**: 标签 / 特征 / 超参选择有没有用到测试期信息
- **样本偏差**: 测试期是否恰好是方法有效的特殊行情
- **过拟合风险**: 参数量和样本量的比例,训练集与 OOS 表现差距
- **经济显著性**: 性能提升量级在实际选股中是否有意义
- **发表偏差**: 这类架构是否有大量失败实验没发表

**形成独立判断**:
- 推荐评级(per `research/literature-quality-tier`)和理由
- **真实创新点**: 和已有方法相比具体新在哪
- 搬到目标市场(e.g., A 股)的三个最具体的障碍

### Phase 4 — 从理解中写输出

**先写 notes,再写 JSON**。

不是逐字对照原文填格子,是基于 Phase 1-3 建立的完整理解,从理解出发写。需要确认具体数字或细节时,翻 PDF 对应位置核实。

**任何字段出现"可能 / 也许 / 大概",意味着没读清楚,回去确认**。

## Notes 格式(六节,每节另起段)

```markdown
# 编号 论文标题

## 解决什么问题

## 方法与架构
(架构图放在本节末尾)

## 数据与训练

## 核心结论

## 核心创新与启发

## 质疑与复现注意
```

每节要有实质内容和判断,**不能只描述,不能走过场**。

## JSON Schema(39 字段)

所有字段必填,论文未披露写"未披露",精读超时写"精读超时"。

```json
{
  "id": "32",
  "title": "论文完整标题",
  "link": "原始 URL 或 '券商名称研报'",
  "authors": "姓名列表,不加头衔",
  "venue": "发表渠道(含年份)",
  "institution": "标准机构名 (per controlled-vocabulary)",
  "model_type": "父类-子类 (per controlled-vocabulary)",
  "asset_market": "标准市场名 (per controlled-vocabulary)",
  "start_year": 2018,
  "end_year": 2023,
  "study_period": "2018-2023 原文字描述",
  "sample_length": "纯数字 (年)",
  "prediction_target": "预测目标",
  "input_features": "特征类型",
  "feature_count": "纯数字 或 未披露",
  "oos_method": "样本外测试方式",
  "metrics": "核心指标 (per controlled-vocabulary)",
  "performance": "最核心 1-2 个数字",
  "special_tech": "非常规设计,无则填无",
  "source_type": "学术论文 或 卖方研报",
  "research_topic": "研究主题 (per controlled-vocabulary)",
  "main_findings": "<格式见下方>",
  "innovations_insights": "<格式见下方>",
  "caveats_replication": "<格式见下方>",
  "summary": "<格式见下方>",
  "rating": "强烈推荐/推荐/一般/不太推荐/不推荐 — 一句话理由",
  "data_input": "<pipeline 格式>",
  "data_preprocess": "<pipeline 格式>",
  "method_model": "<pipeline 格式>",
  "method_special": "<pipeline 格式>",
  "loss_function": "<pipeline 格式>",
  "training_config": "<pipeline 格式>",
  "pipeline_output": "<pipeline 格式>",
  "diagram": "<ASCII 架构图,见 output/ascii-architecture-diagram>"
}
```

字段详细格式见 references/json-field-formats.md(从 user CLAUDE3.md read_paper.md 抄录)。

## 技术术语上下文判断规则(硬约束)

判断任何技术术语时,**必须基于其在论文中的实际作用**,不能仅凭关键词出现就归类。

### 规则 1 — 树模型 ≠ 梯度下降优化器
- XGBoost / LightGBM / 随机森林 / GBDT 绝对不使用 Adam / SGD / RMSProp
- 论文同时出现树模型和 Adam → Adam 在调参过程 → 填 method_special

### 规则 2 — MLP 的角色判断
- MLP 出现时看它在做什么:
  - 最终预测输出 → method_model
  - 超参代理网络 / 辅助编码 → method_special

### 规则 3 — loss_function 只填主优化目标
- 数据增强里的辅助计算不是 loss,不填此列
- RL 的 reward 是此列的核心内容之一,必须填

### 规则 4 — method_model 只填模型,不填方法
- Optuna / 贝叶斯优化 / 注意力机制 → method_special
- LSTM / Transformer / XGBoost → method_model

## A 股适用性标准(若量化金融语境)

每篇论文必须回答:**搬到 A 股最大的三个障碍**,具体到:

- **数据可得性**(日频 / 分钟频 / 财报时效 / 停牌率)
- **制度约束**(涨跌停 / T+1 / 融券限制)
- **容量限制**(换手率 / 冲击成本 / AUM 规模)

P7 决策: 量化金融领域约束直接在**项目 CLAUDE.md**,不内置 domain adapter。

## 卡死检测(per `engineering/stuck-detection`)

每篇独立计时:

| 阶段 | 超时阈值 | 卡死后动作 |
|------|---------|-----------|
| Phase 1 | 15 分钟 | 跳过,继续 Phase 2 |
| Phase 2 | 20 分钟 | 继续 Phase 3 |
| Phase 3 | 20 分钟 | 继续 Phase 4 |
| Phase 4 单字段 | 10 分钟 | 填"精读超时",继续下一字段 |
| Phase 4 整体 | 20 分钟 | status=error,终止 |
| 单篇总时间 | 75 分钟 | 强制终止,status=error |

## 独立性要求

- **评级不受论文宣传数字和机构背景影响**
- **敢于给低评级**,对堆砌术语但本质平庸的论文尤其
- 论文结论和已知事实矛盾时**明确指出,不回避**
- 启发必须真实可操作,**不写套话**

## 反模式

- ❌ 跳过 Phase 1-3 直接 Phase 4 写输出
- ❌ "可能 / 也许 / 大概" 在字段里(应回去确认)
- ❌ 把论文声称的创新当真实创新
- ❌ 评级被论文宣传 / 机构名气影响
- ❌ 不主动找数据泄露 / 样本偏差
- ❌ A 股适用性写套话("会有挑战")不具体

## 与其他 skill 的关系

- 与 `research/literature-quality-tier`: 必读 — 评级判断
- 与 `research/controlled-vocabulary`: 必读 — 字段词表
- 与 `output/ascii-architecture-diagram`: 必读 — diagram 字段格式
- 与 `engineering/stuck-detection`: 必读 — 卡死阈值
- 与 `engineering/parallel-subagent-orchestration`: 互文 — 多篇并行精读

## Provenance

来自 user CLAUDE3 skills/read_paper.md 完整实测 skill。
四阶段协议 + 39 字段 schema + 4 条术语上下文硬规则都是 user 长期论文精读项目的实测沉淀。
