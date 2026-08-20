---
name: design-and-implement-prototype
description: Orchestrates design + implementation project — Phase 1 requirement (optional) → Phase 2 design (EXPERIMENT_DESIGN.md) → Phase 3 plan (EXPERIMENT_PLAN.md with task granularity) → Phase 4 implementation (smoke test tiers + sanity gate) → Phase 5 verification (three-way reconciliation). Composes core+design+engineering skills. Use when starting a design+implementation project that does not require literature review depth (or lit review already done elsewhere).
metadata:
  category: prototypes
  version: 1.0.0
  prototype: design-and-implement
  evidence_grade: 实测组合
---

# design-and-implement-prototype — 设计 + 实施 orchestrator

## 视角

需求 → 设计 → 实施 → 验证 的完整 phase chain。**不深入 lit review**(若已在前序项目完成,直接继承)。

## Phase 序列

```
P1 (可选): 需求 → REQUIREMENT.md
  → P2: 设计 → EXPERIMENT_DESIGN.md
  → P3: 计划 → EXPERIMENT_PLAN.md (含 task granularity 2-5 min)
  → [T7 HARD HALT — user review DESIGN + PLAN]
  → P4: 实施 (含 smoke test 三级 + sanity gate)
  → P5: 验证 (三方对照表格化)
```

## Phase handoff 产物

```
项目根/
├── REQUIREMENT.md (可选)
├── EXPERIMENT_DESIGN.md
├── EXPERIMENT_PLAN.md
├── src/
│   └── ... (P4 实施)
├── experiments/
│   ├── configs/
│   ├── cache/
│   ├── results/
│   │   ├── raw/
│   │   ├── figures/
│   │   ├── tables/
│   │   └── PENDING_USER_ADJUDICATION.md
│   └── logs/
├── VERIFICATION_REPORT.md (P5 产出)
└── PHASE_{1..5}_COMPLETION_REPORT.md (7-section)
```

## 必用 skill 组合

### Core
- `core/verify-before-claim`
- `core/continuous-execution`
- `core/halt-conditions`(T7 hard halt)
- `core/pending-review`
- `core/progress-logging`
- `core/fresh-session-bootstrap`
- `core/chinese-output`
- `core/no-time-estimates`
- `core/provenance-record`
- `core/phase-handoff-protocol`
- `core/verifier-protocol`(P5 三方对照 verifier)
- `core/isolation-protocol`(P4 多 subagent 并行 + P5 fresh verifier)

### Design(P2 + P3)
- `design/designing-experiment`(P2)
- `design/writing-implementation-plan`(P3)
- `design/two-round-architecture-review`(P3 完成时)
- `design/spec-code-reconciliation`(P5)
- `design/interface-contract`(P3 + P4)
- `design/resource-constraint`(P2 + P3)

### Engineering(P4 + P5)
- `engineering/numerical-sanity-gate`(P4 每实验后)
- `engineering/outcome-based-verification`(P4 全程)
- `engineering/smoke-test-tiers`(P4 启动)
- `engineering/parallel-subagent-orchestration`(P4 多 subagent)
- `engineering/stuck-detection`(P4 长跑)
- `engineering/code-quality-standard`(P4 写代码)
- `engineering/seed-isolation-audit`(P4 跨 seed 实验)
- `engineering/session-reporting`(P4 + P5 长跑 session 汇报)

### Research(部分)
- `research/independent-threshold-judgment`(P2 + P4 数值阈值)

### Output
- `output/progress-log-format`(全程 append)

## Phase 详细工作流

### P1 — 需求(可选)

若是研究继承,直接跳到 P2;若新项目,先 user 沟通需求 → 写 REQUIREMENT.md。

### P2 — 设计

**调用**: `design/designing-experiment` + `design/resource-constraint`

**产出**: `EXPERIMENT_DESIGN.md`(scientist + architect 联合)

**字段**: 每实验 含 假设 / 方法 / 数据需求(规模 + 合理性论证)/ 输入输出 / 判断标准 / 优先级和依赖 / 预计资源

### P3 — 计划

**调用**: `design/writing-implementation-plan` + `design/two-round-architecture-review` + `design/interface-contract`

**产出**: `EXPERIMENT_PLAN.md`(含完整接口签名 / task granularity 2-5 min / 双向 traceability / 5 维度性能优化两轮审查)

**T7 HARD HALT**: P3 完成后 **user 必须 review DESIGN + PLAN**,通过后才进 P4(per `core/halt-conditions` #6)。

### P4 — 实施

**调用**: `engineering/smoke-test-tiers` → 主实验 → `engineering/numerical-sanity-gate`(每实验后)

**子步**:

1. **Setup + 框架**: 实施 src/ 基础结构
2. **Pre-Smoke schema 核对**(若有数据 schema)
3. **Smoke Test Level 1 / Level 2 / Level 3**(每级 pass 才进下一级)
4. **SanityGate 阈值标定**(若需要)— `research/independent-threshold-judgment`
5. **主实验 chain**(per `engineering/parallel-subagent-orchestration` 多 subagent + 文件 IPC)
6. **每实验后 sanity gate**(asymmetric bar)
7. **per-runner seed audit**(若跨 seed,per `engineering/seed-isolation-audit`)

### P5 — 验证(三方对照)

**调用**: `design/spec-code-reconciliation`(逐项表格化)+ `core/verifier-protocol`(fresh sub-agent 双 persona)

**产出**: `VERIFICATION_REPORT.md` 含逐项 reconciliation 表格

## 强制 halt 条件(per `core/halt-conditions`)

1. Sanity gate RED(P4 任何实验)
2. Compute escalate(超 budget)
3. Schema mismatch ≥ 2
4. Substantive scope creep
5. User explicit stop
6. **T7 hard halt**(P3 → P4 之间 user 必须 review)
7. Seed audit fail(P4)

## CLAUDE.md template

项目 CLAUDE.md 用 `project_templates/design-and-implement/CLAUDE.md.template`。

## 反模式

- ❌ 跳过 T7 user review 直接进 P4
- ❌ Smoke test 三级跳级
- ❌ P4 实验后不立即 sanity gate
- ❌ Seed 实验跳过 audit gate
- ❌ P5 验证笼统"基本符合"不表格化
- ❌ 资源超约束不显式 scope 减

## 与其他 prototype 的关系

- 与 `prototypes/pure-research`: 互补 — 本原型无 lit review 深度
- 与 `prototypes/research-design-implement`: 是子集 — 三合一 = 纯研究 + 本原型 + paper/slides

## Provenance

User CLAUDE 2/4 的工程实施部分。
T7 hard halt 是 user 实测 — 没 user review 就进实施容易方向跑偏。
