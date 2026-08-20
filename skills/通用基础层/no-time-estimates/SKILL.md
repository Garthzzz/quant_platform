---
name: no-time-estimates
description: Forbids wall-clock estimates ("1-2 days", "wall-clock 4-5 days", "Day 1 上午") in any plan, design, charter, or summary document. Uses logical dependency ordering ("Step A completion triggers Step B") instead of time. Allows compute resource estimates (GPU-hour) without wall-clock translation. Use when writing any plan / design / charter / summary / completion report.
metadata:
  category: core
  version: 1.0.0
  gold_criterion: 5
  evidence_grade: user 独家 (4 轮 explicit reject provenance)
---

# no-time-estimates — GOLD CRITERION 5 子集

## 视角

CC 在 PLAN / DESIGN / Charter / Summary 任何文档**不**写 wall-clock estimates。

## 禁止的 phrasing

- ❌ "wall-clock 4-5 days"
- ❌ "Stage X 估时 ~7-9 hours"
- ❌ "Total Phase 1 完成 wall-clock: ~3-4 工作日"
- ❌ "Day 1 上午: ... Day 2 下午: ..."
- ❌ "1.5-2 工作日"
- ❌ 任何 day / hour / 工作日 / wall-clock 表达

## 允许的表达

### 1. Compute resource estimate(资源)

可以保留(是 resource 不是 wall-clock):
- ✓ "Stage 2 compute: ~30-50 GPU-hour, escalate gate at 50 GPU-hour"

但**不**对应 wall-clock 翻译:
- ❌ "对应 wall-clock 2-3 days assuming RTX 5070"

### 2. 逻辑 dependency 顺序

用 "Step A → Step B" 表达 sequencing,而非 time:
- ✓ "Step 0 lit review baseline → 完成后 Step 1 独立思考"
- ✓ "Phase 2 实验 design 完成后 → Phase 3 自动启动"

### 3. Cadence(频率)

可以表达频率但不绑定具体 day:
- ✓ "每 phase 完成后 produce summary report"
- ❌ "每周一次 sync meeting"(隐含具体 day)

## 自查

写任何 doc / report 前:grep 自己写的内容含 "day" / "hour" / "工作日" / "wall-clock" → 删除 / 重写。

## 与其他 skill 的关系

- 与 `core/continuous-execution`: 兼容 — continuous 不停 + 不写 time
- 与 `core/halt-conditions`: 兼容 — halt 条件不用 time 表达

## Provenance

User 在 4 次 conversation 里 explicit reject time estimates:

1. "另外别加时间了!"
2. "你为什么要加时间啊我不理解"
3. "说了一百万次了不要加时间不要考虑时间你就记不住么"
4. (master charter / T1 review response / T2/T3 review response 都包含 time,user 反复 strike out)

CC 在长 design / plan 文档容易**习惯性 inject time**,必须 catch 自己。

**不是 cosmetic preference,是 hard rule**。

## Anti-patterns

- ❌ 用 "compute X GPU-hour" 包装后对应 wall-clock 翻译
- ❌ 在 Charter / Roadmap 用 "Day 1 / Day 2" 排 milestone
- ❌ Phase summary 写 "完成 wall-clock 5 hours"
- ❌ 用 "估时" / "预计" / "大约" 包装 time estimate

## 校准

User 自己根据 compute resource 估 wall-clock,**不是 CC 任务**。
