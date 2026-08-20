---
name: parallel-subagent-orchestration
description: Orchestrates parallel subagents with hard constraint of simultaneous batch launch (not sequential), filesystem as only IPC medium, dispatch instruction containing only ID + path + task (never content payload), explicit start/end declarations, per-subagent stuck detection, isolated context per subagent. Subdir+lock isolation primary (Web/Desktop), worktree as CLI future option. Use when running parallel tasks like multi-paper deep reading, multi-config parallel training, or multi-seed bootstrap.
metadata:
  category: engineering
  version: 1.0.0
  evidence_grade: user 独家 (CLAUDE3 文件 IPC + 启动/完成声明) + 实测 (obra/superpowers worktree)
---

# parallel-subagent-orchestration — 多 subagent 并行编排

## 视角

并行任务编排**硬约束**:同时启动、文件系统作唯一 IPC、调度指令不含内容、explicit 声明协议。

## 进入前必读

- `core/isolation-protocol` — subdir+lock / worktree / file-ipc 三层
- `engineering/stuck-detection` — per-subagent 超时检测
- `core/halt-conditions` — 失败处理

## 并行硬约束

### 1. 同时启动,不允许 sequential

每批 N 个 task **同时启动**,不允许等一篇完成再起下一篇。

```
Batch 1 同时启动:
  Task(论文 A 路径, read_paper.md) → Subagent 1 (独立上下文,从 0 开始)
  Task(论文 B 路径, read_paper.md) → Subagent 2 (独立上下文,从 0 开始)
  Task(论文 C 路径, read_paper.md) → Subagent 3 (独立上下文,从 0 开始)
  ↑ 三个 Task 同时起,不等待任何一个
```

**Sequential 调度**(起一篇等完成再起下一篇)= 错误的执行方式。

### 2. 某 Subagent 完成 → 立即触发下游

不等同批其他完成:

```
Subagent 1 完成 (status=completed) → 立即触发 python pipeline/write_db.py 给 1 的产出
                                  → 同时继续等待 2 和 3
Subagent 2 失败 (status=error) → 记录 LOG,不影响 1 和 3 (per error isolation)
Subagent 3 完成 → 触发 write_db
全批完成 → 开始下一批
```

### 3. 文件系统作唯一合法 IPC

- **不通过 chat / memory / global var** 跨 subagent 通信
- **不通过 dispatch instruction** 传递跨 subagent 数据
- 所有跨 subagent 通信经过文件(json / parquet / log / queue.jsonl)

### 4. 调度指令不含内容 payload

调度指令**只含**:
- 任务 ID(e.g., 论文编号)
- 文件路径(e.g., PDF 路径)
- 任务指令(e.g., "read this paper per read_paper.md")

**严禁**:
- 把论文全文放进 dispatch instruction
- 把 user 对话历史放进 dispatch instruction
- 把其他 subagent 的产出放进 dispatch instruction

这是为了:
- 物理隔离每个 subagent 的 context window
- 防 prompt injection / context pollution
- 让 fresh subagent 真的 fresh

### 5. Explicit 启动 / 完成 声明

每个 subagent 启动声明:

```
【当前论文: [32] 跨股注意力机制 | 上下文封闭 | 启动: 2026-05-26 23:45】
```

完成声明:

```
【论文 [32] 处理完毕 | 完成: 2026-05-26 24:15】
```

(即使物理隔离,explicit 声明让 user 能 grep log 看每个 subagent 状态)

## Orchestrator 监控协议

Main agent / engineer:

1. 启动一批 N 个 subagent(per `core/isolation-protocol` 的 mode)
2. 轮询 `json/` 中的 status 字段监控进度
3. 同时 per-subagent stuck detection(per `engineering/stuck-detection`)
4. Subagent 完成 → 触发下游(write_db / aggregate)
5. Subagent 失败 → 记录,不影响同批
6. 进度心跳每 5 分钟向终端输出一行(per `engineering/session-reporting`)
7. 全批完成 → 启动下一批

### 进度心跳格式

```
[进度 14:35 +23min] 批次 2/4 | 完成:32✓ 33✓ | 进行中:35(Phase2) 36(Phase3) | 待处理:37 38
```

格式: +xxmin 是距会话启动的已用时间,进行中的论文标注当前 Phase,完成打 ✓,失败打 ✗ 并附原因缩写。
**心跳只打印终端,不写入任何日志文件**。

## 错误隔离原则

- 单篇失败不中断同批其他 subagent
- JSON / parquet 是独立恢复点,write 失败不影响已有产出(下次可直接重试写)
- 任何异常写 debug.log,**不允许静默失败**
- 超过限定次数立即放弃,**不无限重试**
- 连续整批(N 篇)全部卡死 → 暂停,反馈用户

## Subdir + lock 实施(per P10,user 当前首选)

```python
# Subagent 启动前
worker_dir = Path(f"experiments/parallel_workers/worker_{task_id}/")
worker_dir.mkdir(parents=True, exist_ok=True)
lock_file = worker_dir / ".lock"
lock_file.write_text(f"pid={os.getpid()} ts={time.time()}")

# Subagent 完成后
output_file = worker_dir / "result.json"
output_file.write_text(json.dumps(result))
lock_file.unlink()

# Orchestrator 监控
for worker in Path("experiments/parallel_workers/").iterdir():
    lock = worker / ".lock"
    if lock.exists():
        # 检查 stale lock(per stuck-detection)
        if time.time() - lock.stat().st_mtime > MAX_TIMEOUT:
            handle_stuck(worker)
    else:
        result = worker / "result.json"
        if result.exists():
            process_done(result)
```

## 反模式

- ❌ Sequential 调度(等一个完成再起下一个)
- ❌ Dispatch instruction 含内容 payload
- ❌ 通过 chat / memory 跨 subagent 通信
- ❌ 不写启动 / 完成声明
- ❌ Lock file 没用 — 同 subdir 多个 subagent 同时写
- ❌ Stuck subagent 不超时不放弃
- ❌ 单个失败连累整批
- ❌ 进度心跳写日志文件(应该只终端,不污染日志)

## 与其他 skill 的关系

- 与 `core/isolation-protocol`: 必读 — subdir+lock 实施
- 与 `engineering/stuck-detection`: 必读 — per-subagent 超时
- 与 `engineering/session-reporting`: 互文 — 进度心跳 + 会话汇报
- 与 `research/controlled-vocabulary`: 互文 — vocab_queue 并行安全
- 与 `core/halt-conditions`: 互文 — 连续整批卡死触发 user 暂停

## Provenance

来自 user CLAUDE3 完整实测的多论文精读并行编排:
- 3 个独立 Task 同时启动
- 文件系统作唯一合法 IPC
- 调度指令不含论文内容
- 启动 / 完成 explicit 声明
- 进度心跳每 5 分钟
- 错误隔离

**这些约定在 obra/superpowers 后来印证(170k+ star)**,但 user 实测在前。
