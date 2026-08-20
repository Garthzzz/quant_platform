---
name: isolation-protocol
description: Selects isolation method based on environment — subdir+lock as primary (user is on Web/Desktop with Chinese paths), worktree as future CLI-switch option, file-ipc as final fallback. Defines horizontal isolation (parallel units) and vertical isolation (verifier fresh context with read-only tools and dual persona). Use when needing parallel processing or fresh-context verifier.
metadata:
  category: core
  version: 1.0.0
  evidence_grade: 实测 (worktree Claude Code 原生 + obra/superpowers) + 用户 P10 决策 (subdir+lock 首选)
---

# isolation-protocol — Isolation 协议(横向 + 纵向)

## 视角

Isolation 有两种用途:
- **横向**:并行处理独立单元(e.g., 多论文并行精读)
- **纵向**:同一产出物 fresh context 独立审查(verifier 避免 LGTM 偏见)

## User 当前环境(P10 决策)

- **客户端**: Web / Desktop Claude(**非 CLI**)
- **git**: 部分项目是 git 仓库,部分不是
- **路径**: 有中文路径 / 中文文件名(e.g., `低SNR神经网络选股种子稳定性诊断框架.md`)
- **disk**: 能接受 worktree 占用,但不优先考虑

**因此 user 当前**:
- 首选 isolation = **subdir + lock**
- worktree = 未来 CLI 切换的预留方案
- file-ipc = 最简 fallback

## 横向 Isolation — 三层 fallback

### 首选:subdir + lock(user 当前)

适用: user 在 Web/Desktop + 部分 git + 中文路径

```yaml
isolation:
  horizontal:
    mode: subdir-lock
    workspace_dir: "experiments/parallel_workers/<worker_id>/"
    lock_file: "experiments/parallel_workers/<worker_id>/.lock"
    ipc: filesystem
    declare_on_start: true
    declare_on_complete: true
    forbidden_in_dispatch: [content_payload]
```

**实施**:
1. 每个并行单元有独立 subdir(`workers/worker1/` / `workers/worker2/` / ...)
2. 启动时创建 `.lock` 文件,内容 = `pid` + 时间戳
3. 启动声明:"【当前单元: ... | 上下文封闭 | 启动: 时间戳】"
4. 完成声明:"【单元 ... 处理完毕 | 完成: 时间戳】"
5. 文件系统作唯一 IPC
6. 调度指令**不含**内容 payload(只含 file path + 任务 ID)

### Fallback 1:Worktree(未来 CLI 切换用)

适用: CLI + git + 标准路径

```bash
# user 切到 CLI 后
claude --worktree
# 或 SKILL.md 加 isolation: worktree
```

**Pilot test 协议**(若 user 切 CLI):
1. 选 quant/factory(中文文件名最多)
2. `claude --worktree` 起 sub-task
3. 检查:fork 到独立目录?中文文件名完整?file 操作正常?
4. 跑 1 个完整任务(论文精读 1 篇)
5. 失败 → 降级 subdir + lock

### Fallback 2:Subagent (Task tool)

适用: 短任务 / 不修改 file

- Task tool 起 sub-agent,架构级 fresh context
- file 共享需 IPC 协议(同 subdir-lock)

### Fallback 3:File-ipc + explicit declaration(最简)

适用: 上述都不可用 / 极简场景

User CLAUDE3.md 当前模式 — 完全软隔离,依赖 prompt discipline。

## Decision tree(per P10)

```
用户环境
├── Web / Desktop(user 当前)
│   ├── 部分 git + 中文路径
│   │   └── 首选 subdir + lock
│   └── 非 git 仓库
│       └── file-ipc
│
└── CLI(未来切换)
    ├── git + 全英路径
    │   └── worktree
    ├── git + 中文路径
    │   ├── worktree pilot test
    │   │   ├── pass → worktree
    │   │   └── fail → subdir + lock
    │   └── 始终准备 fallback
    └── 非 git
        └── file-ipc
```

## 纵向 Isolation — Verifier 自审

参考 `core/verifier-protocol`。

实现:**fresh sub-agent + 不同 persona**

```yaml
isolation:
  vertical:
    mode: subagent                  # fresh context 架构级保证
    persona: [implementation-checker, adversarial-skeptic]
    context_input: "上一 phase 产出物"
    tool_permissions: read-only     # frontmatter 限定 (Glob/Grep/Read only)
```

**Persona** 具体见 `core/verifier-protocol`。

## 反模式

- ❌ 调度指令含内容 payload(应该只含 path + 任务 ID)
- ❌ 不写 启动 / 完成 声明
- ❌ 并行单元之间通过 chat 或 memory 通信(应该只通过文件系统)
- ❌ Worktree 在中文路径未 pilot 就大规模启用
- ❌ Verifier 用 read-write 工具
- ❌ Verifier 在主 session 跑(没 fresh context)

## 关键约束(user CLAUDE3.md 已实测领先生态)

- **文件系统作唯一合法 IPC**: 不通过 chat / memory / global var 跨单元通信
- **调度指令不含内容**: 防 prompt injection / context pollution
- **启动 / 完成 explicit 声明**: 即使物理隔离也明确边界

## 与其他 skill 的关系

- 与 `core/verifier-protocol`: 互文 — 本 skill 是机制,verifier-protocol 是协议
- 与 `core/phase-handoff-protocol`: 互文 — verifier phase 切换用 fresh sub-agent
- 与 `engineering/parallel-subagent-orchestration`: 互文 — 本 skill 是协议,parallel-orchestration 是工程实施

## Provenance

- **横向 isolation 文件系统作 IPC**: User CLAUDE3.md 已实测,obra/superpowers 印证(170k+ star)
- **纵向 fresh sub-agent**: Anthropic 官方 + obra/superpowers `subagent-driven-development`
- **subdir + lock 首选**: P10 决策 — user Web/Desktop + 中文路径 + worktree 无公开实测数据
