---
name: pure-research-prototype
description: Orchestrates pure research project workflow — Phase 1 multi-step lit review (5 steps with associative search and adversarial review) → final core document (≤30 pages) + LaTeX PDF. Composes core+research+output skills. Use when starting a pure literature review / theoretical analysis / methodology research project without experiment+code components.
metadata:
  category: prototypes
  version: 1.0.0
  prototype: pure-research
  evidence_grade: 实测组合(CLAUDE1 范本)
---

# pure-research-prototype — 纯研究型 orchestrator

## 视角

纯 lit review / 理论研究项目的完整 phase chain。**不包含实验代码**。

## Phase 序列

```
P1: lit review Step 1 (宏观维度 + 联想搜索)
  → P2: lit review Step 2 (独立深度思考 + 跨维度交互矩阵)
  → P3: lit review Step 3 (对抗审查 ≤3 轮,verifier 强制启用)
  → P4: lit review Step 4 (参考文档 + 综合)
  → P5: 最终核心文档 (≤30 页 markdown + LaTeX PDF)
```

## Phase handoff 产物(file-based)

```
docs/litreview/
├── PHASE1_STEP1_INDEPENDENT_LITREVIEW.md
├── PHASE1_STEP2_INDEPENDENT_THINKING.md         # 含跨维度交互矩阵
├── PHASE1_STEP3_ADVERSARIAL_REVIEW_R1.md
├── PHASE1_STEP3_ADVERSARIAL_REVIEW_R2.md        # (如有)
├── PHASE1_STEP3_ADVERSARIAL_REVIEW_R3.md        # (如有)
├── PHASE1_STEP4_SYNTHESIS.md
├── RESEARCH_LITREVIEW_AND_ANALYSIS.md            # 最终核心文档 ≤30 页
├── RESEARCH_LITREVIEW_AND_ANALYSIS.pdf           # LaTeX 编译
├── PHASE1_COMPLETION_REPORT.md                   # 7-section
└── latex_src/
    ├── main.tex
    ├── references.bib
    └── ...
```

## 必用 skill 组合

### Core(所有 phase 都用)
- `core/verify-before-claim`(GOLD CRITERION 1)
- `core/continuous-execution`(P1-P5 自动 chain)
- `core/halt-conditions`
- `core/pending-review`
- `core/progress-logging`
- `core/fresh-session-bootstrap`
- `core/chinese-output`(GOLD CRITERION 6)
- `core/no-time-estimates`(GOLD CRITERION 5 子集)
- `core/provenance-record`
- `core/phase-handoff-protocol`
- `core/verifier-protocol`(P3 adversarial review 用)
- `core/isolation-protocol`(P3 fresh sub-agent)

### Research(本原型核心)
- `research/conducting-literature-review`(P1 主调用,含联想搜索 + 跨维度交互内嵌)
- `research/literature-quality-tier`(P1 引用 / 联想搜索过梯队)
- `research/reference-isolation`(P1-P3 不读参考,P4 解锁)
- `research/adversarial-review`(P3)
- `research/independent-threshold-judgment`(若涉及数值阈值)
- `research/citation-verification`(可选,P5 前 mechanical 检查)

### Output(P5)
- `output/latex-chinese`(P5 LaTeX 编译)
- `output/progress-log-format`(每 phase 完成 append)

### 项目特定(若量化金融)
- 直接在项目 CLAUDE.md 写 A 股适用性约束 / SNR 迁移性标注(P7 决策 — 不做 domain adapter)

## Phase 详细工作流

### P1 — 多 step lit review (Step 1-1b)

**调用**: `research/conducting-literature-review` Step 1 + Step 1b

**产出**: `PHASE1_STEP1_INDEPENDENT_LITREVIEW.md`

**子步**:
- Step 1a 维度内深度 lit review(深度到数学和理论)
- Step 1b 维度内联想搜索(独立思考三步法)
- 每个推荐配置标文献质量梯队(per `research/literature-quality-tier`)

**质量 gate**: 自查 covers all 维度 + 每维度有 1a + 1b

### P2 — 独立深度思考 + 跨维度交互矩阵

**调用**: `research/conducting-literature-review` Step 2

**产出**: `PHASE1_STEP2_INDEPENDENT_THINKING.md`

**子步**:
- 2a 逐维度独立判断
- 2b 跨维度交互矩阵(系统枚举所有重要 pair)
- 2c 跨维度联想

### P3 — 对抗审查(≤3 轮)

**调用**: `research/adversarial-review`(verifier 强制启用)

**Verifier 配置**:
```yaml
verifier:
  enabled: true
  fresh_context: subagent
  upper_bound_rounds: 3
  persona: [implementation-checker, adversarial-skeptic]
  tool_permissions: read-only
```

**产出**: `PHASE1_STEP3_ADVERSARIAL_REVIEW_R{1,2,3}.md`

**stop 条件**: 某轮发现"没什么值得批判的"→ 提前结束

### P4 — 参考文档 + 综合

**调用**: `research/reference-isolation`(此时解锁参考文档)+ `research/conducting-literature-review` Step 4

**产出**: `PHASE1_STEP4_SYNTHESIS.md`

**标注**:
- `[ROBUST]` 两路得相同结论
- `[INCREMENTAL]` 参考独家
- `[CONFLICT]` 不同结论
- `[NEW]` 独立研究新发现

### P5 — 最终核心文档 + PDF

**调用**: `research/conducting-literature-review` Step 5 + `output/latex-chinese`

**产出**:
- `RESEARCH_LITREVIEW_AND_ANALYSIS.md`(≤30 页)
- `RESEARCH_LITREVIEW_AND_ANALYSIS.pdf`(LaTeX)
- `PHASE1_COMPLETION_REPORT.md`(7-section)

## 强制 halt 条件(per `core/halt-conditions`)

- P3 adversarial review verdict = RED → halt
- 跨 phase 发现 substantive scope creep → halt
- User explicit "stop here" → halt
- 其他不停(continuous chain)

## CLAUDE.md template

项目 CLAUDE.md 用 `project_templates/pure-research/CLAUDE.md.template`。

## 反模式

- ❌ 跳过 Step 1b 联想搜索(独家价值)
- ❌ Step 1-3 期间偷读参考文档
- ❌ 跨维度交互矩阵不系统枚举
- ❌ 对抗审查 > 3 轮
- ❌ 最终文档 > 30 页(中间产物保留无限,核心文档 ≤30)
- ❌ LaTeX 源文件放一级目录

## 与其他 prototype 的关系

- 与 `prototypes/design-and-implement`: 互补 — 纯研究无实验代码,设计+实施无 lit review 深度
- 与 `prototypes/research-design-implement`: 是子集 — 三合一 = 纯研究 + 设计实施 + paper/slides

## Provenance

User CLAUDE1 的完整范本。Phase 1 step 1-5 是 user 实测验证过的 lit review workflow。
