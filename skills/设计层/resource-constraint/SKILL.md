---
name: resource-constraint
description: Forces explicit resource budget commitment (compute / memory / disk / GPU-hour ceiling) at design and plan phase. If design exceeds budget, mandates explicit scope reduction with explanation, not silent commit. Compute escalate triggers halt per halt-conditions. No wall-clock estimates (per no-time-estimates). Use when designing experiments or writing plan that involves compute resource.
metadata:
  category: design
  version: 1.0.0
  evidence_grade: user 实测 (CLAUDE2/4/5 GPU-hour 硬约束)
---

# resource-constraint — 资源约束硬性 + 显式 commit

## 视角

资源约束(GPU-hour / 内存 / disk)是**硬性约束**,设计阶段**显式 commit**。超约束 = scope creep(per `core/halt-conditions` #4)。

## 进入前必读

- 项目 CLAUDE.md "运行环境" + "数据规范" section
- `core/halt-conditions` — escalate 触发条件
- `core/no-time-estimates` — 不写 wall-clock

## 资源类型 + commit 协议

### 1. Compute (GPU-hour)

最常见硬约束。e.g., RTX 5070 Laptop GPU 8GB VRAM,单 phase < 12 GPU-hour 或 < 30 GPU-hour(按项目)。

**commit 格式**:

```markdown
## Resource Budget Commitment

| Resource | Budget | Estimated Use | Headroom |
|---|---|---|---|
| Compute (GPU-hour) | < 30 | est ~22 (per Stage 2 below) | 8 (27%) |
| Peak VRAM | < 8 GB | est ~6 GB (BF16 + batch 64) | 2 GB |
| Disk | < 200 GB | est ~80 GB (raw + cache + checkpoints) | 120 GB |

### Stage compute estimate

- Stage 1 (smoke test 三级): 1 GPU-hour
- Stage 2 (weight decay sweep): 6 GPU-hour
- Stage 3 (4 config × 10 seed × 3 repeat): 12 GPU-hour
- Stage 4 (analysis): 3 GPU-hour
- Total: 22 GPU-hour < 30 budget ✓
```

### 2. Memory (RAM / VRAM)

- 系统 RAM 上限(e.g., 32 GB)
- GPU VRAM 上限(e.g., 8 GB on RTX 5070)
- 峰值估算 + headroom

### 3. Disk

- 数据 / cache / checkpoint / log 占用估算
- 留出 free space

### 4. Wall-clock(per `core/no-time-estimates` 禁止估算)

**不写 wall-clock** — 用 compute resource 表达,user 自己估 wall-clock。

## 设计超约束的处理

**禁止 silent 超约束**。若设计 stage estimate 总和 > budget:

1. **显式 scope 减**(减实验数量 / 简化模型 / 减 seed 数 / 减 repeat 数)
2. **说明 trade-off**(e.g., "K=10 seeds 改为 K=5,statistical power 从 0.9 降到 0.7,可接受 per DESIGN §10")
3. **不要 silent 改 spec** — 必须在 EXPERIMENT_DESIGN 改 + 标 changelog

### Scope 减的优先级(per user CLAUDE4)

1. 减重复次数(N repeats)— 影响 statistical power
2. 减种子数(K seeds)— 影响 robustness 估计
3. 减 grid search 范围(超参 sweep 点数)— 影响 hyperparam tuning 精度
4. 简化 model architecture — 影响 spec
5. 减 baseline 数 — 影响对比丰富度

按上至下减,**直到 < budget**。

## Escalate gate(per `core/halt-conditions`)

实施阶段**实测 compute > escalate threshold** 时:

- HALT,append PENDING_USER_REVIEW
- User 决定: 增加 budget? 减 scope? 终止实验?
- **不允许 silent 超** — 触发 halt 条件 #2 "Compute escalate"

## 性能优化对约束的影响

`design/two-round-architecture-review` Round 2 性能优化后:
- 混合精度 / 缓存 / 并行可以**省 compute** → 可能让原本超约束的 design 落回约束内
- 但 **trade-off** 必须 verify(per Round 2 准确性 > 优化)

## Self-check checklist

- [ ] 总 compute < budget?
- [ ] 峰值 VRAM < GPU VRAM?
- [ ] Disk 留 headroom?
- [ ] 若超 → 显式 scope 减 + trade-off 说明?
- [ ] Escalate threshold 在 CLAUDE.md halt conditions 显式?
- [ ] 没写 wall-clock 估算?

## 反模式

- ❌ Silent 超约束(实施阶段才发现)
- ❌ Scope 减不说明 trade-off(影响 statistical power 没记录)
- ❌ 不显式 commit budget,只在 chat 说
- ❌ 写 wall-clock estimate
- ❌ 优化后不重新 verify 是否仍满足约束
- ❌ Escalate threshold 未在 halt conditions 明示

## 与其他 skill 的关系

- 与 `core/halt-conditions`: 互文 — escalate 触发 halt #2
- 与 `core/no-time-estimates`: 互文 — compute 估算 不对应 wall-clock 翻译
- 与 `design/two-round-architecture-review`: 互文 — Round 2 优化检查约束
- 与 `design/designing-experiment`: 必读 — DESIGN 阶段就 commit

## Provenance

来自 user CLAUDE4:

> "整个 Phase 2 实验在 RTX 5070 Laptop 上必须 < 30 GPU 小时完成。SCIENTIST + ARCHITECT 必须在 Phase 2 设计时显式承诺这个约束。"

显式 commit + 硬上限是 user 实测 — 没有 commit 经常实施阶段才超 budget。
