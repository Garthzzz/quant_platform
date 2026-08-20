---
name: independent-threshold-judgment
description: Forms independent quantitative bounds for sanity metrics with citations or first-principle reasoning (not "looks reasonable"), applies both user-provided range AND independent-range as dual check, logs both ranges in PROGRESS_LOG. Use when user provides numerical thresholds (e.g., "IC ∈ [-0.05, 0.10]"), when defining sanity gate ranges, or when designing experiment evaluation criteria.
metadata:
  category: research
  version: 1.0.0
  gold_criterion: 4
  evidence_grade: user 独家 (双 range provenance)
---

# independent-threshold-judgment — 数值阈值独立判断

## 视角

User 提供 range 时**必须独立推理自己的 bound**,双重 range apply,都记录。**不允许 silent 沿用 user range**。

## 规则

对每个 sanity metric:

1. **独立形成 bound**,含 quantitative 依据(文献 / preflight 实测 / 一阶原理) — **不是 "看起来合理"**
2. **Apply user-range AND independent-range 双重检查**
3. 双失败 → halt(per `engineering/numerical-sanity-gate`)
4. 仅 user-range 失败 → "user miscalibrated, independent PASS",log,continue
5. 仅 independent-range 失败 → halt(treat as real fail)
6. 双通过 → PASS
7. **两个 range 均写入 PROGRESS_LOG**

## 独立 bound 形成 method

### Method 1 — 文献支持

引用具体文献的 baseline range:

> AdamW lr range 推荐 [1e-4, 1e-3](Loshchilov & Hutter 2019, ICLR;在 ImageNet 数据集)
> 我的 independent range: [1e-4, 1e-3](沿用文献,但 caveat:该 range 在 CV 任务上,低 SNR 量化任务可能需要 [3e-5, 3e-4])

### Method 2 — Preflight 实测

跑 preflight 实验获得实测分布:

> Preflight 5 seeds:IC 实测分布 mean=0.04, std=0.02
> 我的 independent range: IC ∈ [0.02, 0.08](mean ± 1 std)

### Method 3 — 一阶原理

物理 / 数学约束:

> Gradient norm 必须 > 0 且 finite
> 我的 independent range: [1e-6, 1e3](超出 1e-6 视为 vanishing,超出 1e3 视为 explosion)

### 反例(禁止)

- ❌ "看起来合理" / "应该差不多"
- ❌ Silent copy user range
- ❌ "User probably right" 式 rationalize

## 写入 PROGRESS_LOG 格式

```markdown
### [SCIENTIST] - 2026-MM-DD - Independent threshold for <metric>

- User-provided range: [a, b]
- Independent range: [c, d]
- Derivation of independent range: <method 1/2/3 + 具体引用 / 数据 / 推导>
- 两 range overlap: [max(a,c), min(b,d)]
- Dual-check protocol: PASS 条件 = 测得值 ∈ [a,b] AND [c,d];否则按规则判
```

## 校准

- ❌ 为显 rigor 而 over-tighten — bound 基于实测行为,不是 aspiration
- ❌ 为对齐 user range 而 cherry-pick 文献 / 数据
- ❌ Independent range 没具体推导只写"based on prior experience"

## 与其他 skill 的关系

- 与 `engineering/numerical-sanity-gate`: 必读 — 本 skill 是 sanity gate 的 range 来源
- 与 `core/verify-before-claim`: 互文 — independent range 必须有代码证据 / 文献证据
- 与 `core/progress-logging`: 必读 — 两 range 都进 PROGRESS_LOG

## Provenance

User 2026-04-24 原话:

> "这里的数值你独立思考独立判断不要被我这里写的数值影响也要记录下来"

避免 sanity gate 退化为 rubber-stamp。Generic ML 教育倾向相信 user provided range,这条规则强制 push back。

## 反模式

- ❌ Silent copy user range
- ❌ Independent range = user range(应当独立推理可能得相同 range,但必须有独立推导,不是 copy)
- ❌ 不写入 PROGRESS_LOG
- ❌ 用"经验" / "直觉"作 derivation
- ❌ Bound 设计是 aspiration(e.g., "希望 IC 达到 0.05" 不是实测可达)
