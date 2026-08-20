---
name: skill-creator
description: Creates new skill files following Anthropic SKILL.md spec, gerund naming, third-person description with what+when format, body under 500 lines, references one level deep. Use when adding a new skill to the system or when the user asks to write/draft/scaffold a skill.
metadata:
  category: meta
  version: 1.0.0
  evidence_grade: 实测 (Anthropic 官方 spec + obra/superpowers 实战)
---

# skill-creator — 写新 skill 的元 skill

## 视角

你正在为已有的 skill 系统加新 skill。**严格遵守生态实测 best practice**,因为这个 skill 决定其他 skill 的质量。

## 进入前必读

- `~/.claude/CLAUDE.md` GOLD CRITERION
- 现有同类 skill(`~/.claude/skills/<category>/`)— 避免重复
- [Anthropic Agent Skills overview](https://docs.claude.com/en/docs/agents-and-tools/agent-skills/overview)

## 写新 skill 的工作流

### Step 1 — 决定层级 (5 选 1)

| 层级 | 适用 |
|---|---|
| `_meta/` | 写 skill 关于 skill 的 skill |
| `core/` | 跨原型都用(verify / continuous-execution / chinese / verifier 等) |
| `research/` | 只在研究原型 phase 用(lit review / 对抗审查 / 论文精读等) |
| `design/` | 只在设计原型 phase 用(三方对照 / interface contract 等) |
| `engineering/` | 只在实施原型 phase 用(sanity gate / smoke test / isolation 等) |
| `output/` | 跨原型可复用的输出层(LaTeX / diagram / log format 等) |
| `prototypes/` | Orchestrator skill,引用其他 skill 形成完整 chain |

### Step 2 — 命名(gerund 形式)

- 动名词形式: `conducting-x` / `processing-y` / `writing-z`
- 反对: `helper` / `utils` / `tools` / `manager` 类模糊词
- 小写连字符,≤64 字符
- 禁止保留词 `anthropic` / `claude`

### Step 3 — 写 frontmatter description

**两段式**:

```
[What it does] + [When to use it]
```

**示例**:
```yaml
description: Conducts multi-step literature review with macro dimensional review, associative search across domains, cross-dimensional thinking, and adversarial review with round cap. Use when starting research that requires comprehensive literature review.
```

**反模式**:
- ❌ "Helps with research" — 太模糊,路由器识别不到
- ❌ "I can help you write papers" — 第一人称(应第三人称)
- ❌ "You MUST invoke this skill" — Vercel evals 报告反直觉发现:此措辞**效果反而差**(model "anchors on doc patterns, misses project context")
- ❌ 全中文 description — Anthropic router 中文识别能力生态无数据,先用英文(P11 pilot 后调整)

### Step 4 — 写主体(中文,≤500 行硬上限)

主体结构(参考但不强制):

```markdown
## 视角 / Role focus
本 skill 用什么视角看问题。

## 进入前必读
- 上一 phase 产出物
- 相关 file 路径

## 工作流
### Step 1 — ...
### Step 2 — ...

## 产出物 schema
- 必含哪些 section
- 文件命名约定

## Self-check checklist
- 出 phase 前自查

## Quality gate / Verifier 触发条件
- 何时强制启用 verifier
- Verifier 的 fresh context 方式

## 下一 phase explicit trigger
- 写 PHASE_N_COMPLETION_REPORT.md 的 Next phase trigger section

## Anti-patterns(内嵌简版)
- ❌ ...
- ❌ ...
- 详见 [全局 lessons](../../core/provenance-record/references/lessons-learned-global.md)

## Provenance
- 规则诞生于哪轮挑战
- 具体踩坑案例(若有)
```

### Step 5 — references/ 占位(可选)

只有当 skill 内容超 300 行时才拆 references:

```
skill-name/
├── SKILL.md
└── references/
    ├── checklist.md
    ├── templates.md
    └── anti-patterns-and-provenance.md
```

**1 层深硬约束**(Anthropic 官方,partial-read 技术约束)— 不允许 `references/sub/sub.md` 嵌套。

### Step 6 — Eval-driven 验证(Anthropic 官方推荐)

写完后:
1. 想 3 个 eval scenario — 这个 skill 应该在什么场景被触发
2. 想 3 个 negative scenario — 不应该被触发的场景
3. 1 周后实测,记录触发次数到 frontmatter `metadata.audit`

## 关键 description 写作技巧

### 技巧 1 — 引入实测触发短语

User CLAUDE.md 里的高频表达加进 description,提高匹配:

```yaml
# user 文献综述项目常说"做 lit review" / "深度阅读"
description: ... Use when starting lit review or doing in-depth paper reading.
```

### 技巧 2 — when 段落给具体场景

不要写 "Use when needed" — 太模糊。

```yaml
# 好
description: ... Use when implementation report says numerical results exceed expected range.
# 坏
description: ... Use when needed.
```

### 技巧 3 — 避免触发器关键词冲突

新 skill 的 description 关键词不能与已有 skill 大量重叠,否则 router 难选。
检查方法: grep 现有 skill description 的关键词,新 skill 用不同词。

## Anti-patterns(内嵌)

- ❌ 主体超 500 行还不拆 references(partial-read 错误)
- ❌ references/ 嵌套(`references/sub/file.md`)
- ❌ description 全中文 — 没数据支持触发率(P11 pilot 后再决定)
- ❌ "You MUST" / "ALWAYS" 等强硬措辞 — Vercel 报告反直觉发现效果反而差
- ❌ Personality 描述("Be a senior engineer")— 不改变行为
- ❌ 命名用 `helper` / `tool` / `utils` / `manager`
- ❌ 没有 anti-patterns section 就发布 skill — 缺反例 = 缺 provenance
- ❌ 不写 Self-check checklist — user 出 phase 时无法自查

## 触发本 skill 的场景

- user 说"加一个 skill"/"写 skill"/"新建 skill"
- user 提出新方法论想固化为 skill
- 整理现有 method 为 skill

## 不触发的场景

- user 想改现有 skill — 用 skill-reviewer(读)+ 直接 Edit
- user 想看 skill 文件结构 — 用 Glob/Read

## Provenance

- 阶段 2 第一版基于 Anthropic 官方 spec + obra/superpowers (170k+ star) v5.1.0 实战
- Vercel 2026-01 evals 的 "skill 56% 漏触发" 提示 description 写作的重要性
- "MUST" 措辞反直觉来源: [Vercel blog 2026-01-27](https://vercel.com/blog/agents-md-outperforms-skills-in-our-agent-evals)
