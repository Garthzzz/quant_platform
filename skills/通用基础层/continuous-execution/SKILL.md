---
name: continuous-execution
description: Chains multi-phase work automatically (phase N completion triggers phase N+1) without waiting for user explicit confirmation, except for explicitly enumerated hard halt conditions. Writes 7-section per-phase completion report. Use when working on multi-phase tasks (lit review, design+plan+implement, etc.) or when user authorizes overnight long-run.
metadata:
  category: core
  version: 1.0.0
  gold_criterion: 5
  evidence_grade: user 独家 (CLAUDE5 4 次 reject time estimates + continuous execution provenance)
---

# continuous-execution — GOLD CRITERION 5 子集

## 视角

User 电脑常开,CC 持续 run 直到全部完成。完成 phase N → 立即启动 phase N+1,**不等 user explicit confirm**。

## 工作流

### 完成 phase N 时

1. 写 `<phase_dir>/PHASE_N_COMPLETION_REPORT.md`(7-section,见下)
2. 检查是否触发强制 halt 条件(见 `core/halt-conditions`)
3. 若无 halt → 自动启动 phase N+1,不写 "等待 user review"
4. 在 chat 显式 ✅ 通知 user "X 文档已完成,路径 Y"

### 必须停的例外(强制 user review gate)

只有 `core/halt-conditions` 列举的条件触发时才 halt。除此之外**不停**。

### 必须 surface 但不停

`PENDING_USER_REVIEW.md` append(详见 `core/pending-review`):
- Sanity gate YELLOW
- Optional design choice 选 A 还是 B
- Bibliography 候选 citation

CC 不 silently 决定 surface-able 的事,**必须 append**,user 随时打开看到。

## Per-Phase Summary Report 7-section schema(强制)

每 phase 完成时 produce summary report。File: `<phase_dir>/PHASE_<N>_COMPLETION_REPORT.md`

Required sections(顺序固定):

```markdown
# Phase <N> Completion Report

## What was done
[具体每步:Stage A 做了什么,Stage B 做了什么,etc.]

## How it was done
[Method 实际执行 detail. 不只 reference design,写实际 implementation choice.]

## Results
[数据 + 数字. 含 sanity gate verdict per Criterion 3.]

## Result analysis
[发现,比对预期,重点数字 implication,paper update 涉及哪些段落.]

## Issues surfaced
[Sanity gate YELLOW items / unexpected mismatches / design assumption violations.]

## Paper update items
[哪些数字进 paper §X.Y,哪些 augment text 起草. (如不适用就写 N/A)]

## Next phase trigger
[下一 phase ID + 启动 file path. 注:CC 不等 user review,直接启动. User 自查时看到此 section 知 CC 已 chain 执行.]
```

**Length policy**: report 不限长度. 内容质量 > artificial trim.
**Visibility**: report 写到 phase 目录, user 任何时间打开 file system 都看得到.

## 与 No Time Estimates 的兼容

参考 `core/no-time-estimates`。**完全兼容**:continuous 不停 + 每 phase 通知 user + 但不写 "wall-clock 4-5 days" 类。

## 反模式

- ❌ Phase N 完成后等 user explicit confirm 才启动 Phase N+1
- ❌ 跳过 7-section report,只写 chat summary
- ❌ Completion report 缺 Next phase trigger section(user 无法判断是否已 chain)
- ❌ 不在 chat 显式通知 user 文档完成(违反 GOLD CRITERION 6)
- ❌ 强制 halt 条件触发后还 auto-retry / "自己再想想"
- ❌ Batch surface 多个文档完成才统一通知

## 与其他 skill 的关系

- 与 `core/halt-conditions`: 必读 — 何时停的精确条件
- 与 `core/pending-review`: 必读 — 不停但要 surface 的项怎么记录
- 与 `core/phase-handoff-protocol`: 互文 — 本 skill 是"不停",handoff 是"怎么停下传递"
- 与 `core/chinese-output`: 互文 — 本 skill 不停但通知,chinese-output 规定通知的语言

## Provenance

User 2026-04-25 explicit instruction(原话):

> "让 extension 做完,补充一个,extension 的两个内容的 exp 跑完了写完了,开始更新 papers 的同时写一个汇总内容报告,怎么做的做了什么结果分析这些,发到 extension 里我去检查,然后不需要停,继续开始做 sub-proj 1...我电脑就一直开着就让 cc 一直跑直到跑完,我也随时可以看文件夹的更新内容确认之前的更新情况."

User 偏好模式: **Continuous execution + transparent progress via file system + post-hoc review(不阻塞 chain)**。

## Checkpoint

- 完成 phase 前:已 produce PHASE_N_COMPLETION_REPORT.md 没?已 trigger next phase 没?
- 启动 next phase 前:PENDING_USER_REVIEW.md surface 任何 user 应知 items 没?PROGRESS_LOG entry append 没?
- 没触发 halt 条件就**不**等 user
