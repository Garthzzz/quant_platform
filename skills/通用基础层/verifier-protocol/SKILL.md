---
name: verifier-protocol
description: Triggers verifier with asymmetric bar (RED default, GREEN/YELLOW require positive evidence), trichotomy verdict (or boolean lightweight mode), fresh sub-agent with read-only tools, dual persona (implementation-checker + adversarial-skeptic), upper bound 3 rounds. Use when finishing any phase artifact that requires quality gate (lit review / design / plan / implementation / paper draft).
metadata:
  category: core
  version: 1.0.0
  gold_criterion: 3 (asymmetric bar 部分)
  evidence_grade: user 独家 (asymmetric bar) + 生态实测 (fresh sub-agent + read-only)
---

# verifier-protocol — Verifier 机制

## 视角

Verifier **默认强制启用**(可关闭),拿上一 phase 产出物作 context,fresh sub-agent + 工具权限隔离。

## Verifier frontmatter schema(每个 skill 可定义)

```yaml
verifier:
  enabled: true                     # 默认 true,可关
  mode: trichotomy                  # 或 boolean / confidence
  fresh_context: subagent           # 或 logical (inline 切 persona) / none
  upper_bound_rounds: 3             # adversarial / iterative review 上限
  context_input:
    - "PHASE_{prev}_COMPLETION_REPORT.md"
    - "{phase}_artifact.md"
  tool_permissions:                 # read-only
    allowed: [Glob, Grep, Read]
    denied: [Edit, Write, Bash]
  persona:
    - implementation-checker        # 验证 spec 实现度
    - adversarial-skeptic           # 找漏洞 / 反 LGTM 偏见
  persona_count: 2                  # 默认 2,简单场景 1
```

## Verdict 输出格式(写入 file,main session 读取)

```json
{
  "verdict": "GREEN | YELLOW | RED | CATASTROPHIC",
  "confidence": 0-100,
  "evidence": [{"file": "...", "line": "...", "snippet": "..."}, ...],
  "criteria_evaluated": [{"name": "...", "result": "PASS/FAIL", "note": "..."}],
  "next_action": "continue | halt | request_user_review",
  "asymmetric_bar_log": "RED is default; upgraded to GREEN/YELLOW because: ..."
}
```

## Asymmetric Bar(user 独家,完整保留)

### 核心原则

Out-of-range 时 **RED 是默认 verdict**。GREEN 和 YELLOW 都是 upgrade,必须 **positive evidence** 才能达到。不允许把 YELLOW 当 free cover-your-ass 选项。

### Upgrade 到 GREEN — 必须 **ALL** 以下成立

- (a) **Cross-config consistency**: metric 跨配置 direction 一致,std < |mean|
- (b) **Cross-seed consistency**(如适用): 多 seed 产生 similar out-of-range value(非 single outlier)
- (c) **Pipeline invariants hold**(无 catastrophic pattern;具体阈值项目定义,e.g., IC ∈ [-0.3, 0.3])
- (d) **具体 mechanism 解释** why out-of-range is benign

### Upgrade 到 YELLOW — 必须 **AT LEAST** 以下成立

- (a) Pipeline invariants hold
- (b) Multi-point consistency(cross-config 或 cross-seed ≥ 2 点一致)

无法 upgrade → **RED**, halt。

## YELLOW 不是 free escape hatch

每个 YELLOW **自动**加入 user morning review 列表(`PENDING_USER_REVIEW.md`),给 CC 选 YELLOW 一个 cost — 不是无代价 middle ground。

若 evidence 真的缺 mechanism 解释但 pipeline invariants 完好 → YELLOW
否则 → RED

## 退回触发条件

- **RED** → HALT,写 PENDING_USER_ADJUDICATION,**not retry / not auto-fix / not reconsider**
- **YELLOW** → append PENDING_USER_REVIEW,继续 chain
- **GREEN** → PASS
- **CATASTROPHIC**(NaN storm / 负方差 / missing aggregator) → immediate HALT,不做 evidence gathering
- **Adversarial review 3 轮上限** → 强制结束(per `research/adversarial-review`)

## Boolean lightweight 模式(简单场景)

适用:
- Smoke test pass/fail
- 单元测试 pass/fail
- Mechanical citation check
- File 存在性 check

Verdict: `pass | fail`

不需要 trichotomy 的 evidence gathering,直接给结果 + 一行原因。

## Persona 设计(双 persona,基于学术 adversarial 框架精神)

学术参考: D3 (Debate-Deliberate-Decide, [ArXiv 2410.04663](https://arxiv.org/abs/2410.04663)) advocates/judge/jury; A-HMAD specialized roles。具体角色命名可调整,本 skill 用以下 placeholder:

- **implementation-checker**: 验证 spec 实现度。挑战 "代码符合 design 要求吗?" "PLAN 接口实现了吗?" "三方对照表格逐项 PASS 吗?"
- **adversarial-skeptic**: 找漏洞 / 反 LGTM 偏见。挑战 "数据泄露?样本偏差?边界条件没处理?"

两 persona 各跑一次,产出 **merged verdict**(取严格 — 若任一 persona 给 RED 则总 verdict RED)。

简单场景用 `persona_count: 1`,只用 implementation-checker。

## 反模式

- ❌ 默认 YELLOW 规避二元判断责任
- ❌ HALT 后 auto-retry / auto-fix / "reconsider"
- ❌ Verifier 在主 session 跑(没 fresh context,LGTM 偏见)
- ❌ Verifier 用 Edit / Write 工具(应该 read-only)
- ❌ Verdict 写 chat 里不写 file(main session 可能"忘记"读)
- ❌ 跨 phase 累积超 3 轮 adversarial(不无限迭代)
- ❌ 不附 evidence file:line 引用就 verdict(违反 verify-before-claim)

## 与其他 skill 的关系

- 与 `engineering/numerical-sanity-gate`: 互文 — 本 skill 是协议层,sanity-gate 是数值实验的具体实施
- 与 `research/adversarial-review`: 互文 — 本 skill 是机制,adversarial 是研究 phase 的具体应用
- 与 `core/isolation-protocol`: 必读 — fresh sub-agent 怎么 spawn
- 与 `design/spec-code-reconciliation`: 互文 — 设计 phase 的 verifier 触发点

## Provenance

- **Asymmetric bar 来源**: User 2026-04-24 在 sanity gate review-first 协议上 refinement,原话:"YELLOW 是无成本 cover-your-ass 选择... AI 会系统性 over-use... 反而增加 review 负担"。重设 RED-default + asymmetric bar
- **Self-preference bias 理论支持**: [Wataoka et al. ArXiv 2410.21819](https://arxiv.org/abs/2410.21819) 支持 fresh context 必要性(LLM 偏爱自己输出)。**注意**: 论文只支持 fresh context,不直接支撑 trichotomy + asymmetric 具体设计 — 后者是 user 独立发明
- **Dual persona 学术参考**: D3 framework / A-HMAD,具体角色命名 user 可替换
