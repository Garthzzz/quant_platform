---
name: designing-experiment
description: Produces EXPERIMENT_DESIGN.md with hypothesis-method-data-input-output-criteria-priority-dependency-resource fields per experiment, with synthesis data scale justification, with cross-citation to research lit review document, no time estimates. Use when scientist+architect jointly design experiments after literature review phase completes.
metadata:
  category: design
  version: 1.0.0
  evidence_grade: user 实测 (CLAUDE2/4/5 EXPERIMENT_DESIGN pattern)
---

# designing-experiment — 实验需求设计

## 视角

实验设计是 scientist + architect 联合产出。Scientist 只描述"做什么实验、为什么做、怎么判断结果",**不涉及工程实施细节**。架构 / 缓存 / 并行 / notebook 拆分由 architect 在 PLAN 阶段决定。

## 进入前必读

- `RESEARCH_LITREVIEW_AND_ANALYSIS.md`(lit review phase 产出)
- 项目 CLAUDE.md "数据规范" / "运行环境" / "资源约束"
- `core/no-time-estimates`
- `research/independent-threshold-judgment` — 双 range protocol

## 产出物: EXPERIMENT_DESIGN.md

每个实验一个独立 section,固定字段:

```markdown
## Experiment <N>: <名称>

### 对应研究问题
Q1 / Q2 / ... 哪一个

### 假设
这个实验要验证什么 (1-2 句明确假设)

### 方法
- 用什么数据
- 用什么模型
- 用什么指标
- 怎么对比 (vs baseline / vs alternative)

### 数据需求
- 真实数据 还是 合成数据 (并 justify 选择)
- 规模 (股票数 / 时间范围 / 字段)
- 规模选择的合理性论证: 太小 unreliable, 太大 wasteful, 这个规模刚好够 X

### 输入输出
- 输入: <格式 + shape>
- 输出: <格式 + shape>
- 不需要 code 级 interface,但要说清楚 粒度

### 判断标准
- 什么结果支持假设成立 (具体数字阈值)
- 什么结果反驳假设
- 什么结果 inconclusive (这种情况下下一步怎么 design)

### 优先级和依赖
- 必须先做 (依赖什么前序实验)
- 可并行
- 信息价值排序

### 预计资源
- Compute 估计 (GPU-hour)
- 内存粗估
- (不写 wall-clock 估计 — per no-time-estimates)
```

## 设计原则

### 1. 具体可执行

每个实验明确假设、方法论、数据来源、数据规模 + 合理性论证、预期结果(不同情景)、**无论结果如何能学到什么**。

### 2. 数据规模原则

在保证统计解释力 + 鲁棒性前提下**尽量小**,加快迭代速度。**Scientist 必须 justify 规模选择** — 太小 unreliable,太大 wasteful,刚好够 X。

### 3. 合成数据设计(若适用)

某实验更适合合成数据(精确控制 SNR / 非平稳性 / 速度):

- 指定生成方法 + 参数
- Mimic 真实数据关键性质(厚尾 / 截面相关 / 时序聚集 / scale 异质)
- Ground truth 全部 cache(供后续诊断引用)
- 不能简单用高斯白噪声糊弄

### 4. 实验优先级排序

按**信息价值**排序,标:
- 必须先做(后续实验依赖其结果)
- 可并行
- 信息价值排序

### 5. 成功 / 失败标准

每个实验明确**判断标准**: 什么结果支持什么结论。**禁止 fuzzy 标准**("看起来有效")。

### 6. 架构师可理解

框架描述足够详细,**让架构师能直接据此设计代码结构,不需要返回 scientist 确认**。

### 7. 文献观点的实验验证

对本研究结论有重要影响的文献观点 / 方法,**都应当设计对应的验证实验**。不仅凭引用就接受为事实。

### 8. 资源约束硬性

总 compute 必须在项目硬性约束内(e.g., RTX 5070 Laptop < 30 GPU-hour)。
若设计超出,**显式减少 scope 或简化某些组件**,并说明。

### 9. 配对统计检验(若适用)

多 config 对比时:
- 在**同一 data seed** 上比较,pairwise Wilcoxon test
- 多次 data seed 重复达到合理 statistical power
- 协同效应分析: 不只 pairwise,显式测 D vs (B + C - A)

## Self-check checklist

- [ ] 每个实验的假设 / 方法 / 数据 / 判断标准都填了?
- [ ] 数据规模有 justify 不是拍脑袋?
- [ ] 合成数据(若用)mimic 真实数据关键性质?
- [ ] 总 compute 在硬性约束内?
- [ ] 文献观点都设计了对应验证实验?
- [ ] 没写 time estimate?
- [ ] 架构师能直接据此 PLAN 不返回 scientist?

## 反模式

- ❌ 实验设计含 code 级 interface 细节(应在 PLAN 阶段)
- ❌ 数据规模拍脑袋不 justify
- ❌ 判断标准 fuzzy
- ❌ 写 time estimate
- ❌ 文献观点直接采纳不设验证实验
- ❌ 资源超约束不显式 scope 减
- ❌ 没标实验间依赖 / 优先级

## 与其他 skill 的关系

- 与 `design/writing-implementation-plan`: 下游 — PLAN 基于 DESIGN 出
- 与 `design/resource-constraint`: 必读 — 资源约束 commit
- 与 `research/conducting-literature-review`: 上游 — DESIGN 基于 lit review
- 与 `research/independent-threshold-judgment`: 必读 — 判断标准的 range

## Provenance

来自 user CLAUDE2 / CLAUDE4 / CLAUDE5 反复用的 EXPERIMENT_DESIGN.md 模式。
每条 section 都来自 user 实测项目踩过的坑(e.g., 没 justify 规模导致跑超 GPU 上限)。
