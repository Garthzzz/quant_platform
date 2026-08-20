---
name: pending-review
description: Manages PENDING_USER_REVIEW.md cross-session accumulation — appends surfaceable items without blocking phase chain, marks resolved items with [RESOLVED YYYY-MM-DD] without deleting, triggers soft halt if YELLOW count exceeds threshold (e.g., 5). Use when sanity gate gives YELLOW verdict, when facing optional design choice, when bibliography candidate needs verification, or any user-should-know item that does not block.
metadata:
  category: core
  version: 1.0.0
  evidence_grade: user 独家
---

# pending-review — PENDING_USER_REVIEW.md 累积协议

## 视角

不停 chain,但 user 应知的 items 必须 surface 到 file。User 任何时间打开看到。

## 触发 append 的项

参考 `core/halt-conditions` 的"不停但 surface"清单:

1. **Sanity gate YELLOW**(每个 YELLOW 必须 append — 有 cost,防 AI 选 YELLOW 逃避)
2. **Optional design choice 选 A 还是 B**(CC 选 A 继续,但 surface 说 "若 user 看 PENDING_USER_REVIEW 想换 B 可改")
3. **Bibliography 候选 citation**(候选给 user 后续 verify)
4. 任何 user 应知但不阻塞 chain 的项

## 格式(append-only)

```markdown
## YYYY-MM-DD

### [PR-001] 简短描述
- 类型: YELLOW sanity | optional design | bibliography candidate | 其他
- Context: ...
- 我的决定: (若 optional design CC 选 A,这里说)
- 建议: (给 user 的建议)
- 阻塞 chain?: 否
- Resolution: (user resolve 后 user 写 / CC 标 [RESOLVED YYYY-MM-DD])
```

## YELLOW item 自动累积阈值(矛盾 1 缓解)

防 YELLOW list 膨胀到不可处理:

- 累积 **≥ 5 个 YELLOW** 触发软 halt
- CC 在 chat 通知 user "已累积 5+ YELLOW, 触发软 halt 等 user morning review"
- User resolve 部分 YELLOW 后,CC 重启 chain
- 这是 continuous execution × verifier 强制 × YELLOW 累积 三方矛盾的缓解

## YELLOW 自动分组合并

相同 metric / 相同 mechanism 的多个 YELLOW 合并成 1 条 entry,避免 user 重复 review:

```markdown
### [PR-005-MERGED] 跨 Tier 0 实验 mean_gradient_norm 偏大 (3 个 YELLOW 合并)
- Tier 0.1 实验: mean_gradient_norm = 2.5 (expected ≤ 2.0)
- Tier 0.3 实验: mean_gradient_norm = 2.7
- Tier 0.5 实验: mean_gradient_norm = 2.4
- 共同 mechanism: low SNR 下梯度噪声引入的固有 inflation
- 建议: 一并 review 或调整 range bound
```

## Resolution 协议

User resolve 时:
- 在原 entry 下加 `Resolution: ...` 一行
- 标 `[RESOLVED YYYY-MM-DD]`
- **不删原内容**(跨 session 历史保留)

## 与 user 自查 cadence

User 任意时间打开 `PENDING_USER_REVIEW.md` 看待处理 items。
CC 不主动 ping(continuous execution 兼容,不阻塞 chain)。

## 反模式

- ❌ Silently 决定 surface-able 的事不 append
- ❌ Resolve item 时直接删除原内容(应该标 [RESOLVED] 保留)
- ❌ 不分类型直接堆 entry
- ❌ 不写"我的决定"(optional design 类必须说 CC 选了什么)
- ❌ YELLOW 累积超 5 个还不触发软 halt

## 与其他 skill 的关系

- 与 `core/halt-conditions`: 互文 — 本 skill 是"不停但 surface"清单的具体实施
- 与 `core/continuous-execution`: 互文 — 让 continuous 与 surface 兼容
- 与 `core/progress-logging`: 互补 — 时间线层 vs 累积层

## Provenance

来自 user CLAUDE 2/4/5 反复使用的 PENDING_USER_REVIEW.md 跨 session 累积模式。
YELLOW 软 halt 阈值是 v1.2 矛盾 1 缓解方案。
