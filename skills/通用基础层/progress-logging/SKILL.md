---
name: progress-logging
description: Maintains three-layer logging system — PROGRESS_LOG.md (phase timeline append, never delete), PENDING_USER_REVIEW.md (surfaceable items accumulated across sessions, resolved marked never deleted), session_current.log (per-session event stream cleared on startup), changes.log (permanent meaningful changes). Use when finishing any phase, hitting milestone, or recording state changes.
metadata:
  category: core
  version: 1.0.0
  evidence_grade: user 独家 (三层日志分工 + ASCII 终端汇报)
---

# progress-logging — 三层日志分工

## 视角

三个日志 file 分工明确:
- **时间线层**: `PROGRESS_LOG.md` — phase 时间线 + milestone(append,不删)
- **累积层**: `PENDING_USER_REVIEW.md` — surface-able items 跨 session 累积(resolved 标记不删)
- **当次会话层**: `session_current.log` — 当次会话事件流(每次启动清空,会话结束后清空)
- **永久变动层**: `changes.log` — 永久,只记录有实质意义的变动(vocab 新增 / 代码结构变 / 日志归档)

## 1. PROGRESS_LOG.md 写入格式

每篇完成或失败 / 每 phase 完成时**立即** append。**不批量写**。

### 角色切换 / Phase 完成 entry

```markdown
### [SCIENTIST] - 2026-MM-DD
**本次完成内容:**
- (列出主要完成事项)
**关键决策与理由:**
- (记录重要设计决策)
**遗留问题:**
- (未解决问题或需要下一个角色注意的事项)
**下一步建议:**
- (建议下一个角色从哪里接着做)
```

### 论文精读 entry(若是阅读型项目)

```markdown
### [SCIENTIST] [编号] 标题 — 2026-MM-DD HH:MM
状态: completed / error / skipped
耗时: xx 分钟
关键发现: 一句话(论文最重要的判断或发现)
遗留: (如有,否则省略)
```

### Engineer 操作 entry

```markdown
### [ENGINEER] 操作名称 — 2026-MM-DD HH:MM
操作: 具体做了什么
结果: 成功/失败,关键数字
变更: 涉及的文件或数据库结构改动(无则省略)
遗留: (如有,否则省略)
```

## 2. PENDING_USER_REVIEW.md(跨 session 累积)

User 任何时间打开 file system,通过 PENDING_USER_REVIEW.md 看待处理 items。

### 累积规则

- Append-only;resolved 项标 `[RESOLVED YYYY-MM-DD]` 不删
- 跨 session 持续累积
- User 自查 cadence 自己决定

### 触发 surface 的项(必须 append)

来自 `core/halt-conditions` "不停但 surface":
- Sanity gate YELLOW(每个 YELLOW 必须 append,有 cost,防 AI 选 YELLOW 逃避)
- Optional design choice 选 A 还是 B(CC 选 A 继续,但 surface)
- Bibliography 候选 citation
- 任何 user 应知但不阻塞 chain 的项

### 格式

```markdown
## YYYY-MM-DD

### [ITEM_ID] 简短描述
- 类型: YELLOW sanity / optional design / bibliography candidate / 其他
- Context: ...
- 建议: ...
- 阻塞 chain?: 否
- [RESOLVED YYYY-MM-DD]: (user resolve 后填,不删原内容)
```

## 3. session_current.log(每次启动清空)

**位置**: `tools/session_current.log`(或项目约定)
**生命周期**: 每次会话启动时清空(不存在则新建),日志维护脚本 run 后再次清空
**作用**: 会话结束汇报的唯一数据来源,不依赖上下文记忆

### 事件格式

`[HH:MM:SS] 事件类型 内容`

### 事件类型

```
[HH:MM:SS] SESSION_START  YYYY-MM-DD HH:MM:SS
[HH:MM:SS] SCAN_DONE      新增 xx 篇,续读 xx 篇
[HH:MM:SS] PAPER_DONE     [编号] 标题 耗时 xx 分钟
[HH:MM:SS] PAPER_ERROR    [编号] 标题 原因 (Phase4 超时/写库失败等)
[HH:MM:SS] DB_WRITE       [编号] success / failed
[HH:MM:SS] DB_STATUS      总记录数 xx,本次新增 xx,更新 xx
[HH:MM:SS] VOCAB_NEW      字段名 新条目 来源:论文标题
[HH:MM:SS] CODE_CHANGE    操作内容 原因:xxx
[HH:MM:SS] LOG_ARCHIVE    PROGRESS_LOG → PROGRESS_LOG_YYYY-MM.md 触发:超 500 条
[HH:MM:SS] LOG_ROTATE     debug.log → debug_YYYY-MM-DD.log
[HH:MM:SS] SESSION_END    YYYY-MM-DD HH:MM:SS
```

## 4. changes.log(永久变动)

**位置**: `archive/changes.log`
**生命周期**: 永久保留,不做自动清理
**作用**: 只记录有实质意义的变动,普通论文录入不写入

会话结束时从 session_current.log 筛选 VOCAB_NEW / CODE_CHANGE / LOG_ARCHIVE / LOG_ROTATE 四类事件,同步追加。

### 格式

```
[YYYY-MM-DD HH:MM] VOCAB_NEW    model_type 深度学习-Mamba 来源:33_论文标题
[YYYY-MM-DD HH:MM] CODE_CHANGE  papers 表新增字段 xxx 原因:支持 xxx 查询
[YYYY-MM-DD HH:MM] LOG_ARCHIVE  PROGRESS_LOG → PROGRESS_LOG_2026-04.md 触发:超 500 条
[YYYY-MM-DD HH:MM] LOG_ROTATE   debug.log → debug_2026-04-08.log
```

## 反模式

- ❌ Batch 写 PROGRESS_LOG(完成一批才统一写)
- ❌ Resolve PENDING_USER_REVIEW item 时直接删除原内容(应该标记 [RESOLVED] 保留)
- ❌ session_current.log 跨 session 累积(应该每次清空)
- ❌ changes.log 记每次普通 file edit(应该只记有实质意义的变动)
- ❌ 用 chat / memory 代替 PROGRESS_LOG

## 与其他 skill 的关系

- 与 `core/pending-review`: PENDING_USER_REVIEW.md 具体管理协议见 pending-review skill
- 与 `core/continuous-execution`: 互文 — completion report 与 PROGRESS_LOG 互补
- 与 `engineering/session-reporting`: 互文 — ASCII 终端汇报模板的数据源是 session_current.log

## Provenance

来自 user CLAUDE3.md skill `logging.md` 的具体三层日志分工 + ASCII 终端汇报模板。
