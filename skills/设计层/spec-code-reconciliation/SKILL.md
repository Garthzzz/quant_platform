---
name: spec-code-reconciliation
description: Forces three-way reconciliation (CODE actual behavior ↔ PLAN interface spec ↔ DESIGN concept requirements) before generating code and during code review. Mismatches must be explicitly flagged (not silently fixed), tabularized aspect-by-aspect reconciliation, no laundry "basically compliant" phrasing. Includes specific mismatch case library from user's project history. Use when generating new code, when reviewing existing code, when DESIGN/PLAN version changes (forces code review).
metadata:
  category: design
  version: 1.0.0
  gold_criterion: 2
  evidence_grade: user 独家 (反例库: cpcv.py / Turnover hardcode / MLP normalization / Multi-year / Alpha158)
---

# spec-code-reconciliation — Design ↔ Plan ↔ Code 三方对照

## 视角

写代码 / 审代码时**显式三方对照**:CODE 实际行为 ↔ PLAN 接口规范 ↔ DESIGN 概念要求。**Mismatch 必须显式 flag,不允许 silent 修复或笼统 "基本符合"**。

## 适用场景

### A. Generate Code(写 / 改 / 扩展代码)

写代码**前必做三读**:

1. 读 DESIGN — 这个功能在 DESIGN 哪个 §?概念要求(关键词 / 单位 / 阈值)?
2. 读 PLAN — 给的函数签名 / 模块路径 / 参数类型?
3. grep 现有代码 — 有无相关实现?避免重复或忽视现有 bug

写代码**后必做三验**:

1. 代码 vs PLAN: 函数名 / 参数 / return 是否一致?
2. 代码 vs DESIGN: 行为是否满足概念要求(含 edge case / 数值阈值 / 单位)?
3. **单位 / 维度必须 docstring 明示**(per `design/interface-contract`)

### B. Code Review(审查现有 code 或 rerun 前 sanity check)

**必须产出逐项表格化 reconciliation**:

```markdown
| Aspect | DESIGN § | PLAN § | Code (file:line) | Consistent? | Notes |
|--------|---------|--------|------------------|-------------|-------|
| 激活函数 | §X.Y "GELU" | §X.Z GELU | src/models/mlp.py:L45 ReLU | ❌ MISMATCH | Code 用 ReLU,DESIGN/PLAN 要求 GELU,需 fix |
| Embargo 单位 | §1.6.1 "days" | §1.7.2 days | src/cv/cpcv.py:L13 rows | ❌ MISMATCH | DESIGN/PLAN 说 days,Code 实际是 rows |
| Turnover | §X 禁止 hardcode | §Y compute_empirical_turnover | exp/run_new4_v2.py:L79 daily_turnover=2.0 | ❌ MISMATCH | Hardcode,违反 DESIGN |
| MLP normalization | (未记录) | (未记录) | src/models/nn.py 含 robust scaling | ⚠️ UNDOCUMENTED | 代码加了 robust scaling 是正确做法,但 DESIGN/PLAN 都没记录,补 spec |
| ...               | ...     | ...    | ...              | ...         | ...   |
```

**不允许笼统 "code 基本符合 plan"** — 必须逐项 cross-reference。

### C. 跨 version 修订(v1 → v1.1 → v1.2)

每次 DESIGN 或 PLAN 改版后**强制触发 code review 任务**:

1. 列 DESIGN 所有新增 / 修订概念
2. 检查 PLAN 是否更新
3. 检查 code 是否实现
4. 任一层 lag behind → 显式 flag + 追加 TODO

## Mismatch 反例库(user 项目踩坑)

以下是 user 实测的具体 mismatch 案例,作为本 skill 的 provenance + 提醒:

### Case 1 — cpcv.py 单位 mismatch

**File**: `src/cv/cpcv.py:L13`
**DESIGN 要求**: embargo ≥ 6 days
**Code 实际**: `embargo=5, label_horizon=5` 是样本行数(subsample 下 = 0.125 天)
**问题**: 三方都没显式锁定单位
**修复**: 加 docstring `# embargo in days, not rows`

### Case 2 — Turnover hardcode

**File**: `experiments/run_exp_new4_v2.py:L79`
**DESIGN**: 禁止 hardcode + PLAN 要求 `compute_empirical_turnover`
**Code 实际**: `daily_turnover = 2.0` 硬编码
**问题**: Spec 说的和 code 做的完全不一致,但 PASS verdict 产出时没人 flag
**修复**: 必须显式 call `compute_empirical_turnover` 函数

### Case 3 — MLP normalization 补丁

**File**: `src/models/nn.py`
**问题**: Code 加了 robust scaling **是正确做法**,但 DESIGN + PLAN **都没记录**
**修复**: 补 spec — DESIGN 加 §"MLP 鲁棒标准化"+ PLAN 加对应 task

### Case 4 — Multi-year 缺失

**DESIGN v3.3.1 §0.3.4**: 要求 5-year WF + CPCV 15-path
**Code 实际**: 单年 2024,**至今未实施**
**修复**: 追加 TODO,在 PLAN 加对应 task

### Case 5 — Alpha158 label horizon 误写

**DESIGN 多处**: 说 label horizon = 1 天
**实际 Qlib 源码** `handler.py:L152`: 是 2 天
**问题**: 第三方库的行为没 verify,DESIGN 错抄
**修复**: DESIGN 修正 + 加 spec-code-reconciliation 行验证 Qlib

## 发现 mismatch 时的处理协议

### ❌ 禁止

- 不 silently 修复 → 必须显式说 "发现 DESIGN §X.Y vs CODE file.py:L123 mismatch"
- 不 defensive narrative → 直接承认 spec 或 code 哪边错
- 不 preserve framing → 修订之前错的 docstring / spec / changelog

### ✅ 正确

1. 显式 flag mismatch(在 reconciliation 表格 + PROGRESS_LOG)
2. 判断 spec 错还是 code 错(可能要询问 user)
3. 修订正确的一方
4. 在 CHANGELOG 记录 mismatch 案例(per `core/provenance-record`)

## 与 verify-before-claim 的关系

- `core/verify-before-claim`(GOLD CRITERION 1): **说话之前** verify 源码
- `design/spec-code-reconciliation`(GOLD CRITERION 2): **写代码 / review 代码之时** verify 三方一致

**叠加**: 任何 technical claim / code 改动**必须**有源码证据,且与 spec 显式一致或显式 flag。

## Checkpoint

- 提交 code 前: grep 单位 / 维度关键词(lr scale / batch unit / IC type / dropout layer / embargo days vs rows / turnover bilateral vs one-sided) → 人工 scan docstring 是否明示单位
- 提交 review 前: 我的 review 逐项表格化了吗,还是笼统"基本符合"?
- DESIGN / PLAN 改版后: 新 spec 对应的 code 我检查过了吗?lag 的部分我 flag 了吗?

## 反模式

- ❌ Silent 修复 mismatch 不 flag
- ❌ Review 笼统 "基本符合" 不逐项表格化
- ❌ Code 改动后不重新跑 reconciliation
- ❌ DESIGN/PLAN 改版后不触发 code review
- ❌ Mismatch flag 后 defensive narrative
- ❌ 不引用具体 file:line

## 与其他 skill 的关系

- 与 `core/verify-before-claim`: 互文 — chat 层 vs code 层
- 与 `design/interface-contract`: 必读 — 单位维度 docstring
- 与 `design/writing-implementation-plan`: 必读 — 双向 traceability 让 reconciliation 可自动 verify
- 与 `core/provenance-record`: 互文 — mismatch 案例归档全局 lessons

## Provenance

来自 user signal_to_noise / quant 项目 v3.3 系列 5 个实测 mismatch 案例(cpcv.py / Turnover hardcode / MLP normalization / Multi-year / Alpha158)。

**这是 user 最有价值的反例库之一** — 每条都是真实踩坑,生态里没有同等密度的反例归档。
