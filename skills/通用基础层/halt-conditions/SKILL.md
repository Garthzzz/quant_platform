---
name: halt-conditions
description: Enumerates the exhaustive list of mandatory halt triggers (sanity gate RED / compute escalate / schema mismatch / scope creep / user explicit stop / phase user review gate). Outside this list CC does not stop and continues phase chain. Use when finishing any phase or experiment to check whether to halt or continue chain.
metadata:
  category: core
  version: 1.0.0
  gold_criterion: 5
  evidence_grade: user 独家 (6-9 条具体 enumeration)
---

# halt-conditions — 强制 halt 条件 enumeration

## 视角

CC continuous execution 不停。**只有**以下条件触发时才必须 halt + ask user。**除此之外不停**。

## 强制 halt 条件(项目级别可扩展,默认 6 条 + 项目特定)

### 1. Sanity gate RED(详见 `engineering/numerical-sanity-gate`)

- 实验数据违反 hard threshold,**no positive evidence 能 upgrade 到 GREEN/YELLOW**
- HALT 一次性 — **不 retry / 不 auto-fix / 不 reconsider / 不 propose alternative**
- 写 `PENDING_USER_ADJUDICATION.md`,wait for user

### 2. Compute escalate

- 实际 compute > 项目定义的 escalate threshold(项目 CLAUDE.md 必须明确)
- 例: RTX 5070 Laptop GPU 8GB VRAM,单 phase GPU-hour > 12(或 20 / 30 / 50,按项目)
- HALT 等 user 显式授权扩展预算

### 3. Schema mismatch ≥ 2

- 数据 schema / 字段名 / 维度 / dtype 不一致出现 ≥ 2 次
- HALT 让 user 决定要不要重新核对数据契约

### 4. Substantive scope creep

- 遇到原 design 未覆盖范围
- 需要修改 frozen scope(charter / DESIGN.md / PLAN.md 已经签字的部分)
- HALT 让 user 决定要不要扩 scope

### 5. User explicit instruction

- "stop here" / "等我 review" / "halt" / "停一下"
- 任何明确停止信号

### 6. Phase user review gate(项目 explicit 定义的)

- e.g., T7 hard halt: Phase 2 (DESIGN + PLAN) 完成后 user 必须 review 才能进 T8 (ENGINEER 实施)
- 项目 CLAUDE.md 在 Continuous Execution Chain section 显式标 hard halt 点

## 项目可扩展的 halt 条件(示例)

User CLAUDE2 中加的:
- 7. **Hold-out integrity violation** — 任何 sub-agent 触碰 holdout file → immediate HALT
- 8. **SanityGate 阈值标定定稿后 + REVIEW.md 产出后 halt** — 不为待 refine 数值签字
- 9. **Tier 0 后 refined 阈值定稿 halt** — Tier 0 完成后阈值定稿等 user 签字

## HALT 行为协议(一次性,不 iterate)

RED 或任何 halt 条件触发后:

1. 写 PROGRESS_LOG 含:measured value / expected range / evidence gathered / why halt
2. 写 `experiments/results/PENDING_USER_ADJUDICATION.md`,列剩余 exp / phase 状态 = PENDING
3. **不 retry,不 "自己再想想",不 propose alternative**
4. Wait for user

User 响应 3 种(以 RED 为例):
- (a) "Range 定错了" → CC 更新 range,halted exp 标 GREEN,resume queue
- (b) "真问题,要 fix" → CC 实施 fix
- (c) "接受数值,continue as YELLOW" → 降级,resume queue,paper §5 caveat

## 不是 halt 的反例(必须 surface 但不停)

参考 `core/pending-review`:
- Sanity gate YELLOW(继续 chain + append PENDING_USER_REVIEW)
- Optional design choice 选 A 还是 B
- Bibliography 候选 citation

## Decision tree(每 phase 完成时跑)

```
phase N 完成
│
├── 触发 halt 条件 1-6(项目可扩展 7-9)?
│   ├── 是 → HALT,写 PROGRESS_LOG + PENDING_USER_ADJUDICATION
│   └── 否 → continue
│       │
│       ├── 有需要 surface 但不停的项?
│       │   ├── 是 → append PENDING_USER_REVIEW.md
│       │   └── 否 → continue
│       │
│       └── 启动 phase N+1
```

## 反模式

- ❌ 触发 halt 后 auto-retry / auto-fix
- ❌ 触发 halt 后 propose alternative implementation
- ❌ 没列在 halt 条件里就 silently halt(应该 surface 但不停)
- ❌ 项目 CLAUDE.md 没 explicit 列 halt 条件
- ❌ Halt 触发后不写 PROGRESS_LOG 直接停

## 与其他 skill 的关系

- 与 `core/continuous-execution`: 互文 — continuous 不停的"除此之外"就是本 skill 列举的
- 与 `core/pending-review`: 互文 — 不停但 surface
- 与 `engineering/numerical-sanity-gate`: 互文 — RED → 触发本 skill 的 #1

## Provenance

User CLAUDE2 v1.5 累积 9 条 halt 条件(2026-05-18 加 #8,2026-05-19 加 #9),每条都来自具体踩坑或 explicit user 决策。**精确 enumeration** 是关键 — 防止 CC "觉得有问题就停" 的模糊判断。
