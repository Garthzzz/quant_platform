---
name: adversarial-review
description: Plays the most rigorous reviewer attacking each argument of previous phase output (logic gaps / evidence sufficiency / hidden assumptions / counter-examples / simpler alternatives / falsifiability), bounded at 3 rounds, uses fresh sub-agent with dual persona (implementation-checker + adversarial-skeptic). Use after independent thinking phase (Step 2) of literature review, or for any quality gate requiring adversarial scrutiny.
metadata:
  category: research
  version: 1.0.0
  evidence_grade: user 独家 (3 轮上限) + 实测 (生态 adversarial debate 框架)
---

# adversarial-review — 对抗审查(≤3 轮)

## 视角

扮演**最严苛的 reviewer**,对上一 phase 产出的每个论点做最尖锐的攻击。**最多 3 轮**,每轮让产出更鲁棒。

## 进入前必读

- 上一 phase 产出物(e.g., `PHASE1_STEP2_INDEPENDENT_THINKING.md`)
- `core/verifier-protocol` — 双 persona + RED-default
- `research/literature-quality-tier` — 攻击的常见维度

## 工作流

### 单轮 review 协议

对上一 phase **每个论点** 做以下 6 个 attack:

1. **逻辑漏洞**: 这个论点的逻辑有漏洞吗?推理过程是否成立?
2. **证据足够**: 这个论点依赖的文献证据足够吗?(质量梯队?孤证?)
3. **前提隐藏**: 这个论点是不是只在某些前提下成立?那些前提显式声明了吗?
4. **反例文献**: 有没有反例文献?有没有报告该方法失败 / 负效果的研究?
5. **更简替代**: 有没有更简单的替代解释?Occam's razor 应用了吗?
6. **可证伪性**: 这个论点的实证可证伪性如何?能 design 实验证伪吗?

### 对每个被攻击的论点

要么:
- **改进论点**(加 caveat / 加证据 / 加边界条件 / 加梯队标注)
- **承认论点不成立**(在产出中删除 / 标 deprecated)

### 不要 preserve framing

为不自相矛盾而保留之前错误的 framing — 禁止。**修订永远可以,精度第一**。

## 3 轮上限

- **Round 1**: 主轮,覆盖所有重要论点
- **Round 2**: 针对 Round 1 修订的部分再 review;Round 1 没受影响的论点不重复 review
- **Round 3**: 极端情况;若 Round 2 还有 substantive 改动才启动

**判断 stop 条件**: 某一轮发现"已经没什么值得批判的了" → 提前结束。

## Fresh context + 双 persona

参考 `core/verifier-protocol`。

- **implementation-checker**: "Step 2 的每个论点都有 Step 1 的 lit review 证据支撑吗?"
- **adversarial-skeptic**: "Step 2 的每个论点都禁得起最严苛攻击吗?"

两 persona 各跑一遍单轮 review,合并 verdict。

## 产出物 schema

每轮一个文件:

```
docs/litreview/
├── PHASE1_STEP3_ADVERSARIAL_REVIEW_ROUND_1.md
├── PHASE1_STEP3_ADVERSARIAL_REVIEW_ROUND_2.md   # (如有)
└── PHASE1_STEP3_ADVERSARIAL_REVIEW_ROUND_3.md   # (如有)
```

每文件结构:

```markdown
# Adversarial Review Round N

## 6 attacks 应用到每个论点

### 论点 1: <从 Step 2 抄过来>
- 攻击 1 (逻辑漏洞): ...
- 攻击 2 (证据足够): ...
- 攻击 3 (前提隐藏): ...
- 攻击 4 (反例文献): ...
- 攻击 5 (更简替代): ...
- 攻击 6 (可证伪性): ...
- **Revision**: ... (改 caveat / 删除 / 加证据)

### 论点 2: ...

## 本轮 verdict
- GREEN: N 个论点通过
- YELLOW: N 个论点 surface (需 Step 5 综合时进一步处理)
- RED: N 个论点严重缺陷,触发 halt 或 Step 2 重做

## 是否需要 Round N+1
- 是 / 否 + 理由
```

## Self-check checklist

- [ ] 对每个论点都跑了 6 attacks?
- [ ] 改进论点时显式标了 caveat / 边界条件?
- [ ] 删除的论点在 Step 2 产出文件中也标了 deprecated?
- [ ] Round 数 ≤ 3?
- [ ] 双 persona 都跑了?
- [ ] verdict 合并了?

## Verifier 触发条件

本 skill **就是** verifier phase。无需再嵌套 verifier。

## 下一 phase trigger

完成最后一轮 adversarial review 后:
- 写 `PHASE1_STEP3_COMPLETION.md`(7-section,见 `core/continuous-execution`)
- Next phase = Step 4(参考文档 + 综合,启动 `research/reference-isolation` 解锁)

## 反模式

- ❌ Adversarial review > 3 轮(强制 cap)
- ❌ 改进论点时 preserve 错误 framing
- ❌ 只攻击 trivial 部分,核心论点不动
- ❌ Verifier 在主 session 跑(应 spawn fresh sub-agent)
- ❌ 单 persona 跑(应双 persona)
- ❌ "看起来都对" verdict — 必须找 issue 或证伪 issue

## 与其他 skill 的关系

- 与 `core/verifier-protocol`: 必读 — fresh context + 双 persona 实现
- 与 `research/conducting-literature-review`: 互文 — 本 skill 是 lit review 的 Step 3
- 与 `core/halt-conditions`: 互文 — RED verdict 触发 halt

## Provenance

来自 user CLAUDE1 Step 3 "对抗审查(最多 3 轮)" + CLAUDE2 / CLAUDE4 多轮实测。
3 轮上限是 user 实测得到的"不无限迭代"边界。
