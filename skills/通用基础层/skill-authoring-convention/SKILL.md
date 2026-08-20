---
name: skill-authoring-convention
description: Defines skill file authoring conventions — Anthropic SKILL.md spec compliance (frontmatter required fields, ≤500 line body, references 1 level deep), description writing (third-person what+when, no "MUST" wording), gerund naming, progressive disclosure principles, English description with Chinese body. Use when authoring any new skill or auditing existing skill for spec compliance.
metadata:
  category: core
  version: 1.0.0
  evidence_grade: 实测 (Anthropic 官方 spec)
---

# skill-authoring-convention — Skill 写作规范

## 视角

所有 skill 遵守 Anthropic 官方 spec + 本系统约定。

## Frontmatter 规范(Anthropic 官方)

### 必填字段(只 2 个)

```yaml
name: <gerund-form-name>            # ≤64 字符, 小写连字符, 禁止 anthropic/claude 保留词
description: <两段式 [what] + [when]>   # ≤1024 字符, 第三人称
```

### 可选字段(顶层 frontmatter)

- `license`: 许可证名称或 bundled 许可文件引用
- `compatibility`: 环境要求(≤500 字符)
- `metadata`: catch-all 任意键值对(放本系统的 version / category / gold_criterion / evidence_grade 等)
- `allowed-tools`: 空格分隔的预批准工具(实验性)

### 禁止字段

- ❌ `version`(不是顶层 field — anthropics/skills issue #249;放 metadata 内)
- ❌ 其他官方未列举的顶层 field

### 本系统约定的 metadata 字段

```yaml
metadata:
  category: meta | core | research | design | engineering | output | prototypes
  version: 1.0.0                    # SemVer (P5 简化版)
  gold_criterion: 1 | 2 | 3 | ...   # (若直接对应,可选)
  evidence_grade: 实测 | 估算 | 假设 | user 独家   # v1.2 决策
  audit:                            # (实测验证机制,v1.2 §4.6)
    expected_trigger_scenarios: [...]
    actual_trigger_count: 0
    actual_match_total: 0
    trigger_rate: 0%
    last_audited: null
```

## Description 写作

### 两段式 [what does] + [when to use]

```yaml
description: >
  <what>: Conducts multi-step literature review with macro dimensional review,
  associative search across domains, cross-dimensional thinking, and adversarial
  review with round cap.
  <when>: Use when starting research that requires comprehensive literature review.
```

### 第三人称

- ✓ "Conducts multi-step ..."
- ❌ "I conduct ..." / "You should ..."

### 避免反直觉措辞(Vercel 2026-01 报告)

- ❌ "You MUST invoke this skill" — model "anchors on doc patterns, misses project context"
- ❌ "ALWAYS use this when ..."
- ✓ "Use when ..."

### 引入触发短语

User CLAUDE.md / sample skill 里的高频表达加进 description,提高匹配率:

```yaml
# 若 user 常说 "做 lit review", description 加:
description: ... Use when starting lit review or doing in-depth paper reading.
```

### 阶段 2 决策:**英文 description + 中文 body**(P11)

- 英文 description: 路由最稳(Anthropic router 中文识别能力无公开数据)
- 中文 body: 便于 user 阅读
- 阶段 2 启动 1-2 周后做 5 skill 对照 pilot,决定是否切双语

## Body 写作

### 长度约束

- **≤500 行硬上限**(Anthropic 官方,partial-read 技术约束)
- **目标 < 300 行**(本系统约定)
- 超过 300 行 → 拆 references/

### 中文为主

参考 `core/chinese-output` GOLD CRITERION 6。

### 推荐结构(参考但不强制)

```markdown
# <skill-name> — 一句话定位

## 视角
本 skill 用什么视角看问题。

## 进入前必读 (若是 workflow skill)
- 上一 phase 产出物 / 必要 context

## 工作流 (若是 workflow skill)
### Step 1 — ...
### Step 2 — ...

## 产出物 schema (若产出 file)
- 必含 sections

## Self-check checklist (若是 workflow skill)
- 出 phase 前自查

## Verifier 触发条件 (若有 verifier)
- 何时强制启用

## 下一 phase explicit trigger (若是 workflow skill)
- 写 PHASE_N_COMPLETION_REPORT.md

## Anti-patterns
- ❌ 具体反例
- 详见 [全局 lessons](path)

## 与其他 skill 的关系
- 与 X: 互文 / 互补 / 必读

## Provenance
- 规则诞生的具体 case
```

## References/ 子目录(1 层深)

只允许 1 层深,**禁止嵌套**(Anthropic 官方硬约束,partial-read 错误):

```
skill-name/
├── SKILL.md
└── references/                    # 1 层深 OK
    ├── checklist.md
    ├── templates.md
    └── anti-patterns-and-provenance.md
```

```
skill-name/
├── SKILL.md
└── references/
    └── sub/                       # ❌ 嵌套禁止
        └── deeper.md
```

## 命名规范

### Gerund 动名词形式(强制)

- ✓ `conducting-literature-review`
- ✓ `processing-pdfs`
- ✓ `writing-implementation-plan`

### 反对

- ❌ `helper` / `utils` / `tools` / `manager`(模糊)
- ❌ `lit-review` / `litreview`(名词)
- ❌ `LitReviewer`(camelCase)

### 字符规则

- 小写连字符
- ≤64 字符
- 禁止保留词 `anthropic` / `claude`

## Progressive Disclosure 三层

- Level 1 metadata(name + description): 启动时全部预加载,~100 tokens/skill
- Level 2 SKILL.md body: 被触发时通过 bash 读取,<5k tokens
- Level 3 bundled files / scripts: 按需读取或执行

**含义**: SKILL.md 主体只装"被触发时需要的内容",大资产(checklist / 模板 / 词表)放 references/ 按需读。

## Anti-patterns

- ❌ 主体超 500 行还不拆 references
- ❌ references 嵌套
- ❌ Description "You MUST" / "ALWAYS"
- ❌ Description 全中文(无路由数据)
- ❌ 命名 helper / utils / tools / manager
- ❌ 命名非 gerund 形式
- ❌ 没有 anti-patterns section 就发布
- ❌ 没有 Provenance section

## 与其他 skill 的关系

- 与 `_meta/skill-creator`: 互文 — 本 skill 是规范,skill-creator 是工作流
- 与 `_meta/skill-reviewer`: 互文 — review 时按本规范检查
- 与 `core/chinese-output`: 互文 — body 中文 vs description 英文 的双语策略

## Provenance

来自 Anthropic 官方 [Agent Skills overview](https://docs.claude.com/en/docs/agents-and-tools/agent-skills/overview) + [Skill authoring best practices](https://docs.claude.com/en/docs/agents-and-tools/agent-skills/best-practices) + obra/superpowers v5.1.0 实战印证 + Vercel 2026-01 evals 反直觉发现。
