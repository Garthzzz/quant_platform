---
name: interface-contract
description: Forces unit and dimension explicit docstring at every interface (lr scale "1e-3 not 1e-2", batch unit "samples not stocks", IC type "daily vs cumulative", embargo "days not rows", turnover "bilateral not one-sided", CKA layer "penultimate not final"). Pre-commit checklist greps unit keywords. Use when writing any function/class/module that crosses module boundary, when reviewing interface, or when porting code from another codebase.
metadata:
  category: design
  version: 1.0.0
  evidence_grade: user 独家 (反例库)
---

# interface-contract — 单位 / 维度 docstring 强制

## 视角

每个跨模块接口 (function / class / module) 的 docstring **必须明示单位和维度**。Mismatch 是真实踩坑的根因,**显式声明 = 防御**。

## 强制 docstring 字段

每个 function / class / method docstring 必须含:

```python
def my_function(arg1: float, arg2: int):
    """简短说明做什么.

    Args:
        arg1: <名义> in <单位> (e.g., "学习率 in 1e-3 scale not 1e-2")
            shape: (N, F)  # 若是 tensor
        arg2: <名义> in <单位> (e.g., "batch size in samples not stocks")

    Returns:
        <名义> in <单位>
        shape: (N, 1)

    单位约定:
        - IC: daily 不是 cumulative
        - turnover: bilateral 不是 one-sided
        - embargo: in days 不是 rows
        - CKA: 在 penultimate layer 不是 final layer
    """
    ...
```

## 关键单位 / 维度关键词清单(每个跨模块接口必显式)

来自 user 反例库(see `design/spec-code-reconciliation`):

| 概念 | 必明示 | 反例(模糊) |
|---|---|---|
| 学习率 lr | `lr in 1e-3 scale` | `lr = 1e-3` 不写 scale |
| Batch size | `in samples` 或 `in stocks` | `batch_size = 32` 不写 unit |
| IC | `daily IC` 或 `cumulative IC` | `IC = 0.05` 不知周期 |
| Embargo | `in days` 或 `in rows` | `embargo = 5` 不知 days 还是 rows |
| Turnover | `bilateral` 或 `one-sided` | `turnover = 2.0` 不知单边双边 |
| Dropout | 在哪一层施加 | `dropout = 0.2` 不知 layer |
| CKA | `on penultimate layer` 或 `on final layer` | `CKA = 0.7` 不知 layer |
| 收益率 | `annualized` 或 `daily` | `return = 5%` 不知周期 |
| Volatility | `annualized vol` 或 `daily vol` | `vol = 0.15` 不知周期 |
| Sharpe | `gross Sharpe` 或 `net Sharpe` | `sharpe = 1.5` 不知 gross/net |
| 时间戳 | timezone 明示 | `timestamp = ...` 不知 tz |
| 价格 | `复权` 或 `未复权` / `前复权` 或 `后复权` | `price = 10.5` 不知复权 |
| 因子值 | `截面 z-score 化` 或 `原始值` | `factor = 0.3` 不知 normalize 没 |

## Pre-commit checklist(grep 自查)

```bash
# 提交 code 前自查
grep -rn "lr " src/ | head
grep -rn "batch_size" src/ | head
grep -rn "embargo" src/ | head
grep -rn "turnover" src/ | head
grep -rn "IC" src/ | head
grep -rn "CKA" src/ | head
```

对每个 grep 命中: 人工 scan 是否 docstring 明示单位。

## 反例库(具体 mismatch case,来自 user 实测)

参考 `design/spec-code-reconciliation` Case 1-5。每个 case 都是单位 / 维度未明示导致的 bug。

最经典:**cpcv.py embargo = 5**(DESIGN 说 6 days,Code 实际 5 rows ≈ 0.125 days)。如果当初 docstring 明示 `# in days not rows`,这个 mismatch 不会发生。

## 跨模块 vs 内部 helper

- **跨模块接口**:strict 强制 docstring
- **同一文件内 helper function**:可放宽,但若涉及上述关键词仍 strict

## 在 PLAN 阶段嵌入

写 PLAN 时(per `design/writing-implementation-plan`),每个 function 接口签名**必须**含完整 docstring 含单位:

```yaml
# EXPERIMENT_PLAN.md Task spec
Task 4.1 — Implement Embargo CV split

File: src/cv/embargo_cv.py
Function signature:
    def embargo_split(timestamps, embargo: int) -> List[Tuple]:
        """Time-series CV split with embargo gap.

        Args:
            timestamps: array of timestamps (in days from epoch)
            embargo: gap size IN DAYS (not rows!), recommended ≥ 6 per DESIGN §1.6.1

        Returns:
            List of (train_idx, test_idx) tuples
        """
        ...

**Anti-pattern**: 不写 `IN DAYS (not rows!)` 注释 → cpcv.py case 重复
```

## 反模式

- ❌ Docstring 只写 "学习率",不写 scale
- ❌ Tensor shape 用 "见 model" 替代具体 (N, F, T)
- ❌ 跨复权 / 不复权时 docstring 不标
- ❌ 跨 frequency(daily / weekly / annualized)时 docstring 不标
- ❌ 用 `# TODO: 单位` 占位但不补
- ❌ 接口签名 review 时 "look fine" 不 grep

## 与其他 skill 的关系

- 与 `design/spec-code-reconciliation`: 互文 — 三方对照检查的核心维度之一
- 与 `design/writing-implementation-plan`: 必读 — PLAN 阶段嵌入
- 与 `core/verify-before-claim`: 互文 — 量化优于定性,单位是量化的前提

## Provenance

来自 user signal_to_noise 项目 cpcv.py 单位 mismatch 案例(DESIGN/PLAN 说 6 days,Code 实际 5 rows)。

**这条规则的生死意义**:量化金融的所有真实 alpha 都依赖单位精确 — 一个 unit mismatch 可能让整个回测结论失效。生态里没有同等强度的"单位 docstring 强制"实践。
