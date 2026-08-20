---
name: session-reporting
description: Generates ASCII-bordered session summary report at session end, reading from session_current.log as single source of truth (not from chat memory). Includes paper processing summary, DB status, vocab changes, code changes, log maintenance, next action suggestions. Use when session is about to end, when running log_maintain.py, or when user asks "what happened this session".
metadata:
  category: engineering
  version: 1.0.0
  evidence_grade: user 独家 (CLAUDE3 ASCII 终端汇报模板)
---

# session-reporting — ASCII 终端会话汇报

## 视角

会话结束时**自动生成汇报**,数据**唯一来源**是 `session_current.log`(per `core/progress-logging`),**不依赖上下文记忆**。

## 进入前必读

- `core/progress-logging` — session_current.log 写入规范
- `engineering/parallel-subagent-orchestration` — 进度心跳(中间汇报)vs 本 skill(结束汇报)

## 何时启用

- log_maintain.py 运行时
- User 显式问"这次会话做了什么"
- 长 session 自然结束

## 汇报模板

```
╔══════════════════════════════════════════════════════════════╗
║                     会话执行汇报                             ║
╠══════════════════════════════════════════════════════════════╣
║ 执行时间:YYYY-MM-DD HH:MM — HH:MM(总耗时 xx 分钟)         ║
╠══════════════════════════════════════════════════════════════╣
║ 论文处理 (若适用)                                            ║
║   本次处理:xx 篇                                            ║
║   完成录入:xx 篇                                            ║
║   未完成:  xx 篇                                            ║
║     · [编号] 标题 → 原因(卡死 Phase4 / 超时 / 写库失败)    ║
╠══════════════════════════════════════════════════════════════╣
║ 数据库状态 (若适用)                                          ║
║   papers.db 当前总记录数:xx 篇                              ║
║   本次新增:xx 篇 / 更新:xx 篇                              ║
╠══════════════════════════════════════════════════════════════╣
║ 词表变更                                                     ║
║   新增 model_type:深度学习-xxx(来源:论文标题)            ║
║   无 → 显示"无"                                              ║
╠══════════════════════════════════════════════════════════════╣
║ 代码与结构变更                                               ║
║   [操作内容] → 原因                                          ║
║   无 → 显示"无"                                              ║
╠══════════════════════════════════════════════════════════════╣
║ 日志维护                                                     ║
║   PROGRESS_LOG 归档至 YYYY-MM,保留最近 200 条               ║
║   无 → 显示"无"                                              ║
╠══════════════════════════════════════════════════════════════╣
║ 下一步建议                                                   ║
║   · 有未完成论文 → 建议重新运行 python tools/scan.py 重试   ║
║   · 有词表新增 → 建议 review tools/vocab_queue.jsonl        ║
║   · 有 remap 待处理 → tools/remap_review.json 需人工核查    ║
║   · 一切正常 → 无待处理事项                                  ║
╚══════════════════════════════════════════════════════════════╝
```

## 数据来源协议

**所有数据**从 `session_current.log` 抽取,**不靠 CC 上下文记忆**(per `core/progress-logging`)。

```python
# 伪代码 — log_maintain.py 实施
def generate_session_report(session_log_path):
    events = parse_events(session_log_path)
    
    return Template("ascii_template.txt").render(
        start_time=events['SESSION_START'],
        end_time=events['SESSION_END'],
        paper_done_count=count(events, 'PAPER_DONE'),
        paper_error_list=filter(events, 'PAPER_ERROR'),
        db_status=events['DB_STATUS'],
        vocab_new=filter(events, 'VOCAB_NEW'),
        code_change=filter(events, 'CODE_CHANGE'),
        log_archive=filter(events, 'LOG_ARCHIVE'),
    )
```

## 显示规则

- 未完成列表为空时**该栏显示"全部完成"**
- 词表变更 / 代码变更 / 日志维护三栏无内容时显示"无",**不隐藏栏目**
- 下一步建议根据 session_current.log 实际内容**动态生成**

## 论文处理 vs 通用 session 适配

模板默认含 "论文处理" 栏。对非论文 session(实验 / lit review 等),该栏改为对应 phase 状态:

```
║ Phase 处理                                                   ║
║   本次完成 phase:Phase 2 (实验设计)                         ║
║   产出文件:EXPERIMENT_DESIGN_v1.5.md                        ║
║   下一 phase:Phase 3 (PLAN) — 自动启动                      ║
```

## 进度心跳(中间汇报)vs 会话汇报(结束)

| 维度 | 进度心跳 | 会话汇报 |
|---|---|---|
| 频率 | 每 5 分钟 | 会话结束 1 次 |
| 数据来源 | 实时 状态 | session_current.log |
| 输出位置 | 终端 stdout | 终端 stdout |
| 写日志? | 不写 | 不写(数据已在 session_current.log) |
| 格式 | 单行紧凑 | ASCII 框模板 |
| 例 | `[进度 14:35 +23min] 批次2/4 \| 完成:32✓ 33✓` | (完整 ASCII 框) |

## ASCII 字符注意

模板含 box-drawing 字符(`╔`/`═`/`║`/`╣` 等)。

**终端必须支持 UTF-8 显示**才能正确渲染。否则降级为简单文本:

```
==============================================================
                       会话执行汇报
==============================================================
...
```

User 实测 Windows + Python 3.12 + UTF-8 终端能正确显示。

## 反模式

- ❌ 汇报数据从 CC 上下文记忆抽(会遗漏 / 错误)
- ❌ 汇报跑完不写 session_current.log clear
- ❌ "全部完成" 栏空着不显示("无" 必须显示)
- ❌ 下一步建议固定不动态生成
- ❌ ASCII 字符在终端 garbled 不降级

## 与其他 skill 的关系

- 与 `core/progress-logging`: 必读 — session_current.log 是唯一数据来源
- 与 `engineering/parallel-subagent-orchestration`: 互补 — 进度心跳 + 会话汇报
- 与 `core/chinese-output`: 互文 — 汇报中文

## Provenance

来自 user CLAUDE3 skills/logging.md 完整实测的会话汇报模板。
"唯一数据来源是 session_current.log,不依赖上下文记忆" 是 user 防 CC 编造数据的关键设计。
