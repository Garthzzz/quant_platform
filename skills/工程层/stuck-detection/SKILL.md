---
name: stuck-detection
description: Detects stuck subagents or stuck training using per-phase timeout thresholds (Phase 1 15min, Phase 2 20min, ..., total 75min), training-loop detection (val_loss change < 1e-6 for 5 epochs / NaN / Inf / single epoch > 30min / GPU OOM / CKA NaN). Stuck subagent does not affect other subagents in batch. Continuous-batch-stuck triggers user pause. Use during multi-paper parallel reading, long-run training, or any task that may hang.
metadata:
  category: engineering
  version: 1.0.0
  evidence_grade: user 实测 (CLAUDE3 卡死检测 + CLAUDE2 训练卡死)
---

# stuck-detection — 卡死检测协议

## 视角

并行任务 / 长跑训练**必须有超时检测**。卡死后**不无限等**,按 enumeration 协议处理。

## 进入前必读

- `engineering/parallel-subagent-orchestration` — 多 subagent 编排
- `core/halt-conditions` — 卡死后的 halt 处理

## Per-phase 超时阈值(论文精读类任务,user CLAUDE3 实测)

每篇独立计时:

| 阶段 | 超时阈值 | 卡死后动作 |
|------|---------|-----------|
| Phase 1 | 15 分钟 | 跳过,继续 Phase 2 |
| Phase 2 | 20 分钟 | 继续 Phase 3 |
| Phase 3 | 20 分钟 | 继续 Phase 4 |
| Phase 4 单字段 | 10 分钟 | 填"精读超时",继续下一字段 |
| Phase 4 整体 | 20 分钟 | status=error,终止当前 subagent |
| 单篇总时间 | 75 分钟 | 强制终止,status=error |

**阈值项目可调整**,user CLAUDE3 实测值作 default。

## 训练卡死检测(实验类任务)

满足以下任一**立即停止自查**:

- 连续 **5 个 epoch val_loss 变化小于 1e-6**
- loss 出现 **NaN 或 Inf**
- **单个 epoch 超时 30 分钟**(本机 GPU 下的合理上限)
- GPU 显存 OOM
- CKA 矩阵出现 NaN 元素(若用 CKA)

### 停止后流程

[ENGINEER] 检查数据和代码
→ 写结论到 PROGRESS_LOG
→ [ARCHITECT] 修改方案
→ [ENGINEER] Smoke Test 验证(per `engineering/smoke-test-tiers`)
→ 重新运行

## 单个失败 vs 整批失败

### 单 subagent / 单篇失败

- 不中断同批其他 subagent(per `engineering/parallel-subagent-orchestration` 错误隔离)
- 记录 LOG
- JSON / parquet 是独立恢复点,后续可重试

### 连续整批(N 篇)全部卡死

- 暂停 chain
- 反馈用户
- Append PENDING_USER_REVIEW(per `core/pending-review`)

## Python 脚本异常

scan / write_db / log_maintain / export 等 Python 脚本:

- 脚本内部 try-except 处理
- 失败时输出完整 error info
- 写 debug.log
- 不影响其他任务

## 监控实施(轮询 lock file)

```python
import time
from pathlib import Path

MAX_TIMEOUT = 75 * 60  # 单篇 75 分钟

def check_stuck(worker_dir: Path):
    lock = worker_dir / ".lock"
    if not lock.exists():
        return False  # 已完成
    
    lock_age = time.time() - lock.stat().st_mtime
    if lock_age > MAX_TIMEOUT:
        return True  # 卡死
    return False

def handle_stuck(worker_dir: Path):
    # 写 PROGRESS_LOG
    log_stuck(worker_dir)
    # 标 status=error
    (worker_dir / "status.json").write_text('{"status": "error", "reason": "stuck"}')
    # 释放 lock
    (worker_dir / ".lock").unlink()
    # 不影响其他 worker
```

## 反模式

- ❌ 无限等卡死任务
- ❌ 单 subagent 卡死整批阻塞
- ❌ Loss NaN 不立刻停继续训练
- ❌ Stuck 后不写 PROGRESS_LOG silently 跳过
- ❌ Stuck 后无限 retry(应该放弃 + flag)
- ❌ 阈值定得太松(单 phase 60 分钟)— 卡死才发现太晚
- ❌ 阈值定得太紧(单 phase 1 分钟)— 正常任务被误判

## 与其他 skill 的关系

- 与 `engineering/parallel-subagent-orchestration`: 互文 — 每个 subagent 单独计时
- 与 `core/halt-conditions`: 互文 — 连续卡死 → halt
- 与 `core/progress-logging`: 必读 — stuck event 写 PROGRESS_LOG + session_current.log
- 与 `engineering/smoke-test-tiers`: 互文 — 修复后 smoke test 验证

## Provenance

来自 user CLAUDE3 完整实测的卡死检测 + CLAUDE2 训练卡死检测协议。
阈值是 user 长期项目实测得来。
