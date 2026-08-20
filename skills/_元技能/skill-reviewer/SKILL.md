---
name: skill-reviewer
description: Reviews existing skill files for spec compliance, trigger reliability, anti-pattern presence, and provenance documentation. Tests skills as fresh-context Claude B per Anthropic Claude A/B meta-development pattern. Use when user asks to review/audit/check a skill or after writing a new skill.
metadata:
  category: meta
  version: 1.0.0
  evidence_grade: 实测 (Anthropic Claude A/B 元开发 + obra/superpowers two-stage review)
---

# skill-reviewer — 审查现有 skill 的元 skill

## 视角

你扮演 Anthropic 官方推荐的 Claude B(fresh context)— 一个完全没见过这个 skill 的 user,看 SKILL.md 是否能让你正确执行任务。

## 进入前必读

- 被审查的 skill 的 SKILL.md
- 该 skill 的 references/(若有)
- `~/.claude/skills/_meta/skill-creator/SKILL.md`(对照标准)

## 审查 dimension(逐项打分,trichotomy verdict)

### Dimension 1 — Spec 合规性

| 检查项 | 是 / 否 / 不适用 | 备注 |
|---|---|---|
| frontmatter `name` 是 gerund 形式 | | |
| `name` ≤ 64 字符,小写连字符 | | |
| `description` ≤ 1024 字符 | | |
| `description` 第三人称两段式 [what] + [when] | | |
| `description` 无 "You MUST" / "ALWAYS" 强硬措辞 | | |
| 主体 ≤ 500 行 | | (用 wc -l 数) |
| references/ 1 层深(无嵌套) | | |
| 有 anti-patterns section | | |
| 有 provenance(若是从踩坑得来的规则) | | |
| 有 Self-check checklist(若是 workflow skill) | | |

### Dimension 2 — 触发可靠性

测试 method:

1. 写 5 个**正例 prompt**(应该触发本 skill 的场景)
2. 写 5 个**反例 prompt**(不应该触发的场景)
3. 实测匹配率:理想 ≥ 80% 正例 / ≤ 20% 反例误触发

**Vercel 数据基线**: 仅 description 自动触发 default 44% 通过率(framework knowledge),User team-specific idioms 场景可能更高但无数据。任何 < 50% 视为需要改 description。

### Dimension 3 — Content 完整性

- 主体是否覆盖了 user 在 CLAUDE.md / sample skill 里的实际方法论密度?
- 关键反例(provenance 案例)是否保留?
- 与现有 skill 是否有重复(grep cross-cutting concerns)?

### Dimension 4 — Anti-pattern 内嵌

- 每条 anti-pattern 是否具体可识别(不是空泛"不要这样")?
- 是否有反例代码 / 反例 framing?
- 是否链接到全局 lessons(`core/provenance-record`)?

## Verdict 输出(trichotomy)

```json
{
  "verdict": "GREEN | YELLOW | RED",
  "spec_compliance": "PASS | FAIL (details: ...)",
  "trigger_reliability": "estimated trigger rate or 'needs pilot'",
  "content_completeness": "(列出缺失项)",
  "anti_pattern_quality": "(具体 / 空泛 / 缺失)",
  "next_action": "merge | request_changes | reject"
}
```

### Verdict 升级条件

参考 `core/verifier-protocol` 的 asymmetric bar:
- **GREEN**: 所有 4 个 dimension PASS,无 critical issue
- **YELLOW**: 有 ≥ 1 个 non-critical issue,可 merge 但 user 应知道
- **RED**: spec 不合规 / 关键 content 缺失 / anti-pattern 完全没

## Anthropic Claude A/B 元开发模式

User(或 Claude A)写完新 skill 后:

1. **Claude A**(写 skill 的实例): 完成 SKILL.md
2. **Claude B**(本 skill 启动的 fresh context): 不读 user 对话历史,只读 SKILL.md,扮演真正的 user 去执行任务
3. **观察 Claude B 失败模式**:
   - 没识别该用这个 skill?→ description 改
   - 识别了但执行错?→ 主体不清晰,改
   - 执行对了但 user 不满意?→ method 本身需要 user pushback 调整
4. **回传给 Claude A**: 失败模式记录到 PROGRESS_LOG

## Two-stage review(obra/superpowers 模式)

Stage 1 — **Spec compliance validation**:
- frontmatter / 长度 / references 结构 / anti-patterns 等机械检查
- 工具用 Glob / Grep / Read,read-only

Stage 2 — **Content quality assessment**:
- method 完整性
- 反例案例 quality
- 跨 skill 一致性

两阶段都 PASS 才 verdict GREEN。

## 双 persona(可选,复杂 skill 用)

参考 `core/verifier-protocol`,纵向 isolation 用双 persona:
- **implementation-checker**: SKILL.md 是否实现了 user 真实方法论?
- **adversarial-skeptic**: 这个 skill 漏触发会怎样?反例覆盖足够吗?

## Anti-patterns(内嵌)

- ❌ Review 时只检查 spec 不检查 content — 漏掉方法论密度问题
- ❌ Verdict 笼统 "looks good" — 不给具体 dimension 评分
- ❌ 不实际跑 trigger 测试就估算触发率
- ❌ 把自己当 Claude A 评 — 不是 fresh context
- ❌ 全 GREEN 默认 — Asymmetric bar:RED default,upgrade 需 positive evidence

## Provenance

- Anthropic 官方 Claude A/B 元开发模式([best-practices](https://docs.claude.com/en/docs/agents-and-tools/agent-skills/best-practices))
- obra/superpowers v5.1.0 two-stage review(spec compliance + code quality)
