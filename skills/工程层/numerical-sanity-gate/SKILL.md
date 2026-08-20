---
name: numerical-sanity-gate
description: Runs hard-threshold numerical sanity check after each experiment aggregator finishes and final JSON written, using asymmetric evidence bar (RED is default verdict, GREEN requires all four upgrade conditions including cross-config/cross-seed consistency + pipeline invariants + mechanism explanation, YELLOW requires at least invariants hold + multi-point consistency). HALT on RED is one-shot (no retry, no auto-fix, no reconsider). Use after every experiment finishes and before next experiment starts.
metadata:
  category: engineering
  version: 1.0.0
  gold_criterion: 3
  evidence_grade: user 独家 (asymmetric bar + YELLOW must user review + HALT 一次性)
---

# numerical-sanity-gate — Asymmetric Evidence Bar

## 视角

每个实验 aggregator 跑完、final JSON 写入后,**必须立即运行 numerical sanity gate** 才能进下一个实验。Hard-threshold 检查,**不做 judgment call,不做 code review,不做 brainstorm**。halt-or-continue 按决策树。

## 进入前必读

- `core/verifier-protocol` — Asymmetric bar 完整定义
- `core/halt-conditions` — HALT 触发
- `research/independent-threshold-judgment` — 双 range

## 触发时机

- aggregator 函数返回后
- final JSON 写入文件后
- **下一个 runner 启动前**

失败时立刻写 PROGRESS_LOG,含:时间 / 实验 / 违例 metric / 测得值 / bound / halt-or-log 决定。

## Asymmetric Evidence Bar(完整)

### 核心原则

Out-of-range 时 **RED 是默认 verdict**。GREEN 和 YELLOW 都是 upgrade,必须 positive evidence 才能达到。**不允许把 YELLOW 当 free cover-your-ass 选项**。

### Upgrade 到 GREEN — 必须 **ALL** 以下成立

- (a) **Cross-config consistency**: metric 跨配置 direction 一致,std < |mean|
- (b) **Cross-seed consistency**(如适用): 多 seed 产生 similar out-of-range value(非 single outlier)
- (c) **Pipeline invariants hold**(项目定义,e.g., IC ∈ [-0.3, 0.3];train_loss 非负且单调下降趋势;无 NaN cascade;梯度范数 ∈ [1e-6, 1e3];gross > net;turnover ∈ [0, 5])
- (d) **具体 mechanism 解释** why out-of-range is benign

### Upgrade 到 YELLOW — 必须 **AT LEAST** 以下成立

- (a) Pipeline invariants hold(无 catastrophic pattern)
- (b) Multi-point consistency(cross-config 或 cross-seed ≥ 2 点一致,非 single outlier)

无法 upgrade → **RED**, halt。

## Verdict 语义(关键)

- **GREEN**: strong benign evidence → PASS,queue continue,**无需 user morning review**
- **YELLOW**: "我判断不了, 必须 user morning review" → queue continue,**但 exp 加入 PENDING_USER_REVIEW.md wake-up list**;user 早上**必须**逐个判定
- **RED**: evidence of real issue OR 无法找到 benign 解释 → **HALT queue**,写 PENDING_USER_ADJUDICATION
- **Catastrophic**(NaN storm / 负方差 / missing aggregator) → immediate HALT,不做 evidence gathering

## YELLOW 不是 free escape hatch

每个 YELLOW 会**自动加入 user morning review 列表**,这给 CC 选 YELLOW **一个 cost** — 不是无代价 middle ground。

如果 evidence 真的缺 mechanism 解释但 pipeline invariants 完好,选 YELLOW;否则选 RED。

## HALT 行为(一次性,不 iterate)

RED 触发 halt 后,CC 必须:

1. 写 PROGRESS_LOG 含: measured value / expected range / evidence gathered / why RED
2. 写 `experiments/results/PENDING_USER_ADJUDICATION.md`,列剩余 exp 状态 = PENDING
3. **不 retry,不 "自己再想想",不 propose alternative**
4. Wait for user

User 早上 3 种 response:

- (a) "Range 定错了" → CC 更新 range,halted exp 标 GREEN,resume queue
- (b) "真问题, 要 fix" → CC 实施 fix
- (c) "接受数值, continue as YELLOW" → 降级,resume queue,paper §5 caveat

## 双 range 协议(per `research/independent-threshold-judgment`)

每个 metric 必须有两 range:

- **User range**: user 提供
- **Independent range**: CC 独立推导(文献 / preflight / 一阶原理)

决策树:
1. 双失败 → halt (RED default)
2. 仅 user-range 失败 → "user miscalibrated, independent PASS",log,continue
3. 仅 independent-range 失败 → halt(treat as real fail)
4. 双通过 → PASS

## E.4 依赖链 overrule(per user CLAUDE5)

原命令允许 "non-chain exp 的 RED 可以 halt 该 exp 不 abort Layer 5"。**refinement 下 overrule**: **任何 RED 都 halt 全 queue**。

## 陷阱

- ❌ 默认 YELLOW 规避二元判断责任
- ❌ HALT 后 auto-retry / auto-fix / "reconsider"
- ❌ 代码 review / brainstorm / proactive alternative

## 不做的事

- ❌ 代码 review / re-audit
- ❌ "这结果是否正确" brainstorm
- ❌ 主动建议 alternative implementation
- ❌ 重新 verify 已经 pre-flight 过的 module
- ❌ 跑完一批才统一 sanity gate(应该每个 aggregator 完成后立即跑)

## Hooks 强制 enforcement(可选,user 同意后实施)

HumanLayer 实测: "CLAUDE.md 80% advisory compliance vs hooks 100% deterministic"。

可在 PostToolUse hook 自动触发本 skill:
- aggregator 函数返回 → hook 自动跑 sanity gate
- 不依赖 CC 自觉

## 与其他 skill 的关系

- 与 `core/verifier-protocol`: 必读 — asymmetric bar 完整定义在 verifier-protocol
- 与 `core/halt-conditions`: 必读 — RED → halt #1
- 与 `core/pending-review`: 互文 — YELLOW → append
- 与 `research/independent-threshold-judgment`: 必读 — 双 range 协议
- 与 `engineering/outcome-based-verification`: 互文 — sanity gate 是 outcome-based 的具体应用

## Provenance

- **Asymmetric bar 起源**: User 2026-04-24 在原 review-first 协议上 refinement,原话:"YELLOW 是无成本 cover-your-ass 选择... AI 会系统性 over-use... 反而增加 review 负担"
- **HALT 一次性 不 iterate**: User explicit 防 CC "自己再想想" 失控
- **E.4 overrule**: User CLAUDE5 累积修订
