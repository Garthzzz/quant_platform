---
name: conducting-literature-review
description: Conducts multi-step literature review (macro dimensional review with depth to math and theory → associative search with independence-first then reference-cross-check → cross-dimensional thinking with interaction matrix → adversarial review with 3-round cap → reference synthesis only at final step → final core document ≤30 pages). Embedded associative search and cross-dimensional interaction sections. Use when starting research project requiring comprehensive literature review.
metadata:
  category: research
  version: 1.0.0
  evidence_grade: user 独家 (多 step pipeline + 联想搜索三步法 + 跨维度交互矩阵)
---

# conducting-literature-review — 多 step lit review

## 视角

执行严格的多 step lit review pipeline。**独立思考优先于参考**。所有论断必须有可验证证据。

## 进入前必读

- 项目 CLAUDE.md 中 "研究语境强制说明"(若有)
- `research/literature-quality-tier` skill — 文献质量三梯队
- `research/reference-isolation` skill — 不读参考文档直到 Step 4
- `core/no-time-estimates` — 不写 time estimate

## Step 1 — 宏观维度 lit review

### Step 1a — 维度内深度 lit review

每个维度 / 每个研究问题独立 lit review。**深度到具体的理论和数学假设**:

- 不是列名字 + 一句话描述
- 必须写清楚数学公式、推导、关键边界条件
- 不只搜最常用的 3-5 个方法,**scope 必须广**(e.g., 优化器不只看 Adam/SGD,还要 RAdam/Lookahead/LAMB/Adafactor/Lion/SAM/ASAM 等)
- 主流 ML 文献结论不直接采纳 — 先质疑前提(SNR 水平 / 任务性质等)

### Step 1b — 维度内联想搜索(强制,不可跳过)

**核心原则**: **自主独立思考优先**。

1. **第一步(独立思考)**: 完全自主、不受任何提示影响地自由联想。思维完全开放,不受任何预设框架限制。**这一步的产出记录为"独立联想产出"**
2. **第二步(参考校验)**: 独立联想完成后,再参照参考模式做一轮补充思考,检查是否有遗漏的联想路径 — **但完全不限于参考模式**
3. **第三步(合并)**: 把独立联想产出和参考校验补充合并,去重,形成最终联想搜索发现

**触发参考校验的问题**(只是参考,不限于这些):
- 该维度有没有其他领域的方法可以借用?(robust optimization / 贝叶斯 / 信息论 / 物理学 / 控制论 / 信号处理)
- 该维度的 survey / meta-analysis 论文的参考文献中有没有被引用但不在核心文献列表的方法?
- 类似 SAM 是从 flat minima 联想到、CKA 是从种子稳定性诊断联想到 — 当前维度有没有类似路径?

**联想搜索的产出必须过文献质量三梯队**(`research/literature-quality-tier`):
- 第一梯队优先采纳
- 第二梯队审慎引用
- 第三梯队哪怕理论漂亮也要降级 — 不放推荐配置,只放"实验候选 / 未来探索"

**联想搜索是这个 phase 最有价值的产出**。

### 工程项目跨领域类比备注(P8 决策)

虽然本 skill 主用于研究 phase,**联想搜索三步法也适用工程问题的跨领域类比** — 例:
- 工程 phase 想 "borrow robust optimization 思路解 low SNR" 时,可调用本 skill 的 Step 1b
- 不需要单独的 associative-search skill — 嵌在本 skill 内,用户工程项目想用时直接 invoke 本 skill 的 Step 1b 章节

## Step 2 — 独立深度思考 + 跨维度交互矩阵

### 2a 逐维度独立判断

每个维度给出:
- **独立判断**: 哪些主流结论在当前问题语境下不成立?哪些是开放问题?你认为答案是什么、为什么?
- **研究空白识别**: 不是文献已经讨论过的问题,是**文献还没意识到的问题**

### 2b 跨维度交互矩阵(核心,本 skill 强制产出)

维度之间不是独立的。**系统性枚举维度间交互效应**:

```
| 维度 A × 维度 B | 交互机制 | 实证或推理 |
|---|---|---|
| D1(预处理) × D7(优化器) | rank 标准化后梯度分布变,Adam adaptive lr 行为也变 | ... |
| D9(batch size) × D7(优化器) | 小 batch 引入梯度噪声,是否反而帮助 low SNR exploration | ... |
| D6(正则化) × D3(架构) | 过参数化 Transformer 加 dropout 是否等价于更小模型 | ... |
| D10(loss) × D8(lr 策略) | RankIC loss 梯度分布和 MSE 不同,最优 lr 也不同 | ... |
```

**系统性枚举所有重要交互**,不限于这几个。

### 2c 跨维度联想

- 某个维度的方法 / 理论能否被"借用"到另一个维度?(e.g., SAM minimax 思想用于 loss 设计)
- 某个维度的监控指标能否反过来指导另一个维度的自适应调整?(e.g., 监测梯度 SNR 下降时自动降 lr)

## Step 3 — 对抗审查(参考 `research/adversarial-review`)

- 扮演最严苛 reviewer 攻击 Step 2 的每个论点
- **最多 3 轮**
- Verifier 强制启用(fresh sub-agent + 双 persona)

## Step 4 — 参考文档阅读 + 综合

**进入 Step 4 前不读参考文档**(`research/reference-isolation` skill)。

Step 4 才读,做以下事情:
- 参考文档哪些论点你独立研究也得出了?(robust)
- 参考文档哪些论点你独立研究没覆盖?(增量)
- 参考文档哪些论点你独立研究得出不同结论?(冲突 — 谁更对?)
- 参考文档遗漏了什么你独立研究覆盖到的?

## Step 5 — 三源综合 + 最终产出

三源:
1. Step 1-3 的宏观 lit review(跨模型 / 跨维度通用)
2. Step 4 模型特定 / 应用特定 lit review(若有 Step 4 的展开)
3. 参考文档

**最终核心文档 ≤ 30 页 MD**(底层完整分析保留在中间产物文件)。

## 产出物 schema

```
docs/litreview/
├── PHASE1_STEP1_INDEPENDENT_LITREVIEW.md
├── PHASE1_STEP2_INDEPENDENT_THINKING.md    # 含跨维度交互矩阵
├── PHASE1_STEP3_ADVERSARIAL_REVIEW_R1.md
├── PHASE1_STEP3_ADVERSARIAL_REVIEW_R2.md   # (如有)
├── PHASE1_STEP3_ADVERSARIAL_REVIEW_R3.md   # (如有)
├── PHASE1_STEP4_SYNTHESIS.md
├── RESEARCH_LITREVIEW_AND_ANALYSIS.md       # ≤30 页
├── RESEARCH_LITREVIEW_AND_ANALYSIS.pdf      # LaTeX 编译
├── PHASE1_COMPLETION_REPORT.md              # 7-section 见 core/continuous-execution
└── latex_src/
    ├── main.tex
    ├── references.bib
    └── ...
```

## Self-check checklist(出 phase 前)

- [ ] 每个维度都做了独立深度 lit review?
- [ ] 每个维度都做了独立联想搜索(三步法)?
- [ ] 跨维度交互矩阵覆盖所有重要 pair?
- [ ] 对抗审查 ≤ 3 轮且 verifier PASS?
- [ ] 参考文档只在 Step 4 才读?
- [ ] 最终核心文档 ≤ 30 页?
- [ ] 每个推荐配置标了文献质量梯队?

## Verifier 触发条件

- Step 3 对抗审查 = verifier phase,强制启用 fresh sub-agent + 双 persona
- Step 5 综合完成后,verifier 检查三源是否一致

## 反模式

- ❌ Step 1 只 list 方法不深入数学
- ❌ Step 1b 跳过独立思考直接看参考模式
- ❌ Step 2 不做跨维度交互矩阵
- ❌ Step 3 超过 3 轮
- ❌ 提前读参考文档(违反 Step 1-3 isolation)
- ❌ 联想搜索的产出全部当推荐(没过质量三梯队)

## 与其他 skill 的关系

- 与 `research/literature-quality-tier`: 必读 — 三梯队判断
- 与 `research/reference-isolation`: 必读 — Step 1-3 不读参考
- 与 `research/adversarial-review`: 必读 — Step 3 具体协议
- 与 `research/independent-threshold-judgment`: 互文 — 数值阈值独立判断
- 与 `research/citation-verification`: 可选 — 引用 hallucination 检测
- 与 `output/latex-chinese`: 必读 — 最终 PDF 中文编译

## Provenance

来自 user CLAUDE1 完整 5-step lit review pipeline + CLAUDE2 / CLAUDE4 的多 step 应用案例。
联想搜索三步法 + 跨维度交互矩阵是 user 独家方法论(生态无对应)。
P8 决策:联想搜索内嵌于本 skill,不单独拆。
