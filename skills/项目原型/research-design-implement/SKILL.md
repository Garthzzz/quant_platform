---
name: research-design-implement-prototype
description: Orchestrates full research+design+implementation project — Phase 1-5 literature review → Phase 6-7 design+plan (joint scientist+architect) → Phase 8 implementation with sanity gates → Phase 9 result verification → Phase 10 paper+slides (LaTeX Chinese). Composes all core+research+design+engineering+output skills. Use when starting a complete academic project (literature review through paper publication).
metadata:
  category: prototypes
  version: 1.0.0
  prototype: research-design-implement
  evidence_grade: 实测组合(CLAUDE2/4/5 范本)
---

# research-design-implement-prototype — 三合一组合型 orchestrator

## 视角

完整学术项目的 phase chain:**lit review → design → 实施 → 验证 → 论文 + slides**。User 历史项目最常见模式。

## Phase 序列

```
P1: lit review Step 1 (宏观维度 + 联想搜索)
  → P2: lit review Step 2 (独立深度思考 + 跨维度交互矩阵)
  → P3: lit review Step 3 (对抗审查 ≤3 轮)
  → P4: lit review Step 4 (参考文档 + 综合)
  → P5: lit review Step 5 (最终核心文档 ≤30 页 + PDF)
  → P6: 联合实验设计 (scientist + architect EXPERIMENT_DESIGN.md)
  → P7: 实验 PLAN (architect EXPERIMENT_PLAN.md)
  → [T7 HARD HALT — user review DESIGN + PLAN]
  → P8: implementation (smoke test 三级 + 主实验 chain + 每实验后 sanity gate)
  → P9: 实验结果验证 (scientist + 三方对照 + 可能补充实验)
  → P10: paper + slides (LaTeX Chinese PDF)
```

## Phase handoff 产物

```
项目根/
├── CLAUDE.md (项目级,继承全局 + 项目特定)
├── PROGRESS_LOG.md
├── PENDING_USER_REVIEW.md
├── EXPERIMENT_DESIGN.md (P6)
├── EXPERIMENT_PLAN.md (P7)
│
├── docs/
│   ├── litreview/                       # P1-P5 产出
│   │   ├── PHASE1_STEP{1..5}_*.md
│   │   ├── RESEARCH_LITREVIEW_AND_ANALYSIS.md  # ≤30 页
│   │   ├── RESEARCH_LITREVIEW_AND_ANALYSIS.pdf
│   │   ├── PHASE1_COMPLETION_REPORT.md
│   │   └── latex_src/
│   │
│   ├── paper/                           # P10 产出
│   │   ├── research_paper.pdf
│   │   └── latex_src/
│   │
│   └── slides/                          # P10 产出
│       ├── presentation_slides.pdf
│       └── latex_src/
│
├── src/                                 # P8 实施
│   ├── data/
│   ├── models/
│   ├── training/
│   ├── evaluation/
│   └── utils/
│
├── experiments/                         # P8 + P9
│   ├── configs/
│   ├── cache/
│   ├── results/
│   │   ├── raw/
│   │   ├── figures/
│   │   ├── tables/
│   │   └── PENDING_USER_ADJUDICATION.md
│   └── logs/
│
└── PHASE_{1..10}_COMPLETION_REPORT.md
```

## 必用 skill 组合(全集)

### Core(全 13 个)
全部 `core/*` skill。

### Research(P1-P5 + P9 部分)
全部 `research/*` skill,核心:
- `research/conducting-literature-review`(P1-P2,联想搜索 + 跨维度交互内嵌)
- `research/adversarial-review`(P3)
- `research/reference-isolation`(P1-P3 不读,P4 解锁)
- `research/literature-quality-tier`(全程引用过梯队)
- `research/independent-threshold-judgment`(P6 + P8 阈值)
- `research/citation-verification`(P10 paper 前可选)
- `research/reading-paper`(若 lit review 涉及具体论文精读)
- `research/controlled-vocabulary`(若 lit review 受控分类)

### Design(P6 + P7)
全部 `design/*` skill。

### Engineering(P8 + P9 + P10 verification)
全部 `engineering/*` skill。

### Output(P5 + P10)
- `output/latex-chinese`(P5 + P10)
- `output/ascii-architecture-diagram`(全程)
- `output/progress-log-format`(全程)

## Phase 详细工作流(简版,详见各 phase 对应的子 skill)

### P1-P5 — Lit review chain(per `prototypes/pure-research`)

参考 `prototypes/pure-research` 完整 phase 1-5。

### P6 — 联合实验设计

**调用**: `design/designing-experiment` + `design/resource-constraint`

**Phase 2 实验设计的语境**(若量化金融):假设已经因子化后的市场数据,直接在项目 CLAUDE.md 写约束(P7 决策)。

**联合**: scientist + architect 同 phase 产出 `EXPERIMENT_DESIGN.md`。

### P7 — 实验 PLAN

**调用**: `design/writing-implementation-plan` + `design/two-round-architecture-review` + `design/interface-contract` + `design/spec-code-reconciliation`(写 backward link)

**T7 HARD HALT** at P7 完成后。

### P8 — Implementation

**调用**: 全 engineering/* skill。

**子步**:
1. Setup src/ 框架
2. Pre-Smoke 数据 schema 核对(若有 mismatch ≥ 2 halt)
3. Smoke Test 三级(Level 1 / 2 / 3)
4. SanityGate 阈值标定(若需要)
5. 主实验 chain
6. 每实验后 sanity gate(asymmetric bar)
7. 每 runner 实施完跑 seed audit(per `engineering/seed-isolation-audit`)
8. 多 subagent 并行(per `engineering/parallel-subagent-orchestration`)

### P9 — 实验结果验证

**调用**: scientist 视角 + `design/spec-code-reconciliation`(三方对照表格化)+ `core/verifier-protocol`(fresh verifier)

**任务**:
- 阅读所有实验结果,验证数据合理性
- 三方对照(DESIGN ↔ PLAN ↔ Code)
- 发现异常或不一致 → 联系 architect / engineer 排查
- 确认所有实验结论可靠性
- 如需补充实验 → 提出具体要求 → 反馈 architect → 回到 P7/P8

### P10 — Paper + Slides

**调用**: `output/latex-chinese` + `research/citation-verification`(可选)

**Research Paper**:
- 标准: 按 JFE/RFS/JMLR 水准
- LaTeX 中文,编译为 PDF
- PDF 放 `docs/paper/`,源文件 `docs/paper/latex_src/`

**演讲 Slides**:
- LaTeX Beamer 编写,中文
- 内容: 问题 → 文献和业界现有答案 → 我们的思考和论证 → 实验设计 → 结果 → 结论
- PDF 放 `docs/slides/`,源文件 `docs/slides/latex_src/`

**完成后**: 写 `FINAL_COMPLETION_REPORT.md` 到项目根目录,全 chain summary。

## 强制 halt 条件(全集,9 条 + 项目可扩展)

1. Sanity gate RED(P8)
2. Compute escalate
3. Schema mismatch ≥ 2
4. Substantive scope creep
5. User explicit stop
6. **T7 hard halt**(P7 → P8 user review)
7. Hold-out integrity violation(若适用)
8. SanityGate 阈值标定定稿 + REVIEW 产出后(若适用)
9. Tier 0 后 refined 阈值定稿(若适用)

## CLAUDE.md template

项目 CLAUDE.md 用 `project_templates/research-design-implement/CLAUDE.md.template`。

## Continuous Execution Chain(项目 CLAUDE.md 引用)

```
T0: 项目启动 — fresh CC session 读 CLAUDE.md + PROGRESS_LOG + PENDING_USER_REVIEW

T1-T5: [SCIENTIST] Lit review Step 1-5
T6: [SCIENTIST + ARCHITECT] 联合 EXPERIMENT_DESIGN
T7: [ARCHITECT] EXPERIMENT_PLAN
    → HARD HALT for user review
T8 (post-user-review): [ENGINEER] Implementation
T9: [SCIENTIST] 实验结果验证 + 可能补充实验
T10: [SCIENTIST] Paper + Slides

T10 完成 → 全 chain 完成 → FINAL_COMPLETION_REPORT.md
```

## 反模式

- ❌ 跳过 lit review 直接进设计(违反原型定位)
- ❌ T7 user review gate 不停
- ❌ Paper 不基于 lit review pdf + 实验结果(应该综合)
- ❌ 论文 LaTeX 源文件放一级目录
- ❌ FINAL_COMPLETION_REPORT 不写就 stop

## 与其他 prototype 的关系

- = `prototypes/pure-research` (P1-P5) + `prototypes/design-and-implement` (P6-P9) + P10 paper/slides
- 是 user 历史项目最常见的完整原型

## Provenance

User CLAUDE 2/4/5 的完整范本。
P1-P10 是 user 多个项目实测的完整 phase chain。
