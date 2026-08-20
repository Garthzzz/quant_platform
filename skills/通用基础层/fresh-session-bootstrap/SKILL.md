---
name: fresh-session-bootstrap
description: Bootstraps fresh Claude Code session by reading required files in order — CLAUDE.md, PROGRESS_LOG.md, PENDING_USER_REVIEW.md, active design / plan documents, then briefly recap current project state before working. Allows project CLAUDE.md to override default readings list. Use at the start of every new session.
metadata:
  category: core
  version: 1.0.0
  evidence_grade: user 独家 (CLAUDE5 Sub-project Fresh Session Inheritance Rule)
---

# fresh-session-bootstrap — 每次启动必读清单

## 视角

无论哪个角色 / phase 接管,**第一步**必须按顺序阅读必读 file。确认理解后简短复述当前项目状态,再开始工作。

## 默认必读清单(全局)

按以下顺序读,**一个都不能跳**:

1. `CLAUDE.md`(项目根)— 含 GOLD CRITERION + 项目规范
2. `PROGRESS_LOG.md` — 当前进度和遗留问题
3. `PENDING_USER_REVIEW.md` — user 待 review 的 surface 项
4. 当前 active 设计 / plan 文档(如已产出,见 CLAUDE.md "active 文档" 列表)
5. 当前角色对应的 phase template(如有)

## 项目特定覆盖

项目 CLAUDE.md 可在 `## Fresh Session Bootstrap` section 覆盖默认,加项目特定:

```markdown
## Fresh Session Bootstrap

继承默认 (~/.claude/skills/core/fresh-session-bootstrap),并加本项目特定:

1. `CLAUDE.md`(本文件)
2. `PROGRESS_LOG.md`
3. `PENDING_USER_REVIEW.md`
4. `SANITYGATE_CALIBRATION_PROTOCOL.md`(本项目特有,长期生效)
5. `EXPERIMENT_DESIGN_v1.5.md` + `EXPERIMENT_PLAN_v1.5.md`
```

**优先级**: 项目 CLAUDE.md > 全局 skill 默认。

## Sub-project Inheritance(嵌套项目)

子项目 CHARTER 必须 reference 父项目 CLAUDE.md:

```markdown
> Fresh CC session 启动本子项目前必读:
> `D:\quant\<parent>\CLAUDE.md` Gold Criterion 1-N
> 子项目 session 也 follow 全部 criterion, 不允许 bypass.
```

子项目 session 也 follow 父项目 GOLD CRITERION + 加子项目特定。

## 启动后必做

1. 读完所有必读 file
2. **简短复述当前项目状态**(1 段)— 不复述 GOLD CRITERION 内容,只说"当前在 phase N,active 文档是 X,pending 项 N 个"
3. 再开始工作

## 反模式

- ❌ 跳过 PROGRESS_LOG 直接开工(不知道当前 phase)
- ❌ 跳过 PENDING_USER_REVIEW(可能在 user 已 surface 的 issue 上重复工作)
- ❌ 读 file 但不复述(user 无法 verify CC 真的理解了)
- ❌ 复述时复述 GOLD CRITERION 全文(冗余,user 自己写的)
- ❌ Active 文档列表不在 CLAUDE.md 显式列(fresh session 不知道读哪几个 version 文档)

## 与其他 skill 的关系

- 与 `core/continuous-execution`: 互文 — fresh session 启动也算 phase 切换
- 与 `core/phase-handoff-protocol`: 互文 — fresh session 是从 file-based 状态恢复
- 与 `core/progress-logging`: 必读 — PROGRESS_LOG.md 是当前状态来源

## Provenance

来自 user CLAUDE5 "Sub-project Fresh Session Inheritance Rule" 部分。
User 跨 session 长跑的关键 — 没有这个协议,fresh session 不知道在 chain 哪里。
