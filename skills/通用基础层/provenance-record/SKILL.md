---
name: provenance-record
description: Records the "why" of each rule — specific user pushback rounds, real mismatch cases, ecosystem evidence supporting the rule, dual-layer storage (skill-embedded anti-patterns + global lessons-learned). Use when documenting a new rule, when explaining why a rule exists, or when reviewing whether an old rule still applies.
metadata:
  category: core
  version: 1.0.0
  evidence_grade: user 独家 (CLAUDE5 三轮修订史 + 反例库 教科书级别)
---

# provenance-record — 规则的"为什么"

## 视角

每条规则有"为什么" — 来自具体踩坑、user pushback 轮次、或生态实测证据。**规则带 provenance** 让 user 能判断规则是否仍适用,而不是盲目遵守。

## 双层归档协议(P6 决策)

### 层 1 — Skill 内嵌 anti-patterns + 简版 provenance

每个 skill 的 SKILL.md 必含 `Anti-patterns` + `Provenance` 两 sections。

**Anti-patterns 写法**:
- ❌ 具体反例,不是空泛"不要这样"
- 引用具体 file / case 若有
- 链接到全局 lessons:"详见 [全局 lessons](~/.claude/skills/core/provenance-record/references/lessons-learned-global.md)"

**Provenance 写法**(若规则来自具体踩坑):
- 哪轮 user pushback / 哪次实验失败
- 具体日期 + case 引用
- 链接 sample file(若 user 同意)

### 层 2 — 全局 lessons-learned

位置: `~/.claude/skills/core/provenance-record/references/lessons-learned-global.md`

```markdown
# Skill 系统全局 Lessons Learned

## 跨 skill / 跨项目复用的反模式

### L001 — CC 在 user 三轮 pushback 后才走代码 verify

**起源**: User signal_to_noise v3.3 系列 2026-04-23 三轮挑战
**反模式描述**: 逻辑论证对,但量化 / 代码级描述不够精确,user 反复 push 才修
**关联 skill**: core/verify-before-claim
**教训**: 每次 technical claim 提交前 grep "是否有代码证据" 自查

### L002 — Sanity gate YELLOW 被 AI over-use 当 free escape

**起源**: User 2026-04-24 pushback
**反模式描述**: YELLOW 看似无成本 middle ground,AI 会系统性选 YELLOW 规避二元判断责任
**关联 skill**: core/verifier-protocol, engineering/numerical-sanity-gate
**教训**: YELLOW 必须 user morning review (有 cost),GREEN 和 YELLOW 都是 upgrade 需 positive evidence
```

每条 entry 含: 起源 / 反模式描述 / 关联 skill / 教训。

## 写 provenance 的工作流

### 新规则诞生时(skill 写作 / CLAUDE.md 加规则)

1. 在 skill 的 `## Provenance` section 写:
   - 具体起源(date / case / pushback 轮次)
   - 1-2 句"为什么这条规则"
2. 在 anti-patterns section 内嵌简版
3. 若是跨 skill 反模式 → append 到全局 lessons-learned

### 老规则被挑战时(user 说"这条还需要吗")

1. Read provenance section
2. Check 是否仍适用(case 是否已不复存在?)
3. 若不适用 → 删规则 + 在 CHANGELOG 写"deprecate 因 ..."
4. 若仍适用 → 保留 + 加新 case 加强 provenance

## 区分 provenance vs spec

- **Spec**(怎么做): 规则本身的描述,操作步骤
- **Provenance**(为什么): 规则诞生的具体 case + 教训

两者分开写。Provenance 不要影响 spec 的执行(规则本身仍要遵守)。

## 关键引用

来自 user CLAUDE5 GOLD CRITERION 1 provenance 段(教科书级别):

> 项目 v3.3 系列期间用户连续三轮挑战:
> - Round 1: 我 speculate "Pre-gate 1b 可能是 smoking gun",用户要我 30 分钟 check 代码
> - Round 2: 源码 verify 后改 "trivially PASS"——表述不精确
> - Round 3: 用户问 "v2 purge/embargo 实际多少天",走代码发现 "7/8 实验 purge=0 embargo=0,B.3 用行空间 embargo=5 行 ≈ 0.125 天"——正确描述是 "technically FAIL but impact < 0.1% 样本"
>
> 每轮错误模式一致:**逻辑论证对,但量化 / 代码级描述不够精确**。用户三次都用"走代码"戳破。

**这是 provenance 的范本** — 具体 round / 具体 quote / 具体教训。

## 反模式

- ❌ 写 "因为这样比较好" 之类空泛 provenance
- ❌ Provenance 含 user 个人信息(应该匿名化或得 user 明确同意)
- ❌ 不写 provenance,规则飘在空中
- ❌ 用 provenance 影响 spec 执行("provenance 说 ... 所以我可以不遵守 spec")
- ❌ 全局 lessons-learned 不分类堆积

## 与其他 skill 的关系

- 与所有其他 skill: 每个 skill 都需要 anti-patterns + provenance section
- 与 `_meta/skill-reviewer`: review skill 时检查 provenance 质量

## Provenance(meta — 本 skill 自身的 provenance)

来自 user CLAUDE5 三轮修订史 + 反例库(cpcv.py 单位 / Turnover hardcode / MLP normalization / Multi-year 缺失 / Alpha158 误写)。这种 "规则 + 来源故事" 的组织是 user 在生态中的独家创新。
