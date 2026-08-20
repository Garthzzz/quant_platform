---
name: phase-handoff-protocol
description: Defines phase transition protocol — file artifact as hard signal (PHASE_N_COMPLETION_REPORT.md with Next phase trigger section), role tag as soft signal, verifier phase via fresh sub-agent. Reads previous phase artifact before entering next phase. Use when transitioning between phases (lit review → thinking → adversarial review → synthesis, or design → plan → implementation → verification).
metadata:
  category: core
  version: 1.0.0
  evidence_grade: 实测 (BMAD / Spec-Kit / obra/superpowers 共识) + user 独家 (角色 tag 软信号)
---

# phase-handoff-protocol — phase 间交接规范

## 视角

混合协议(P2 决策):**file-based 硬协议 + 角色 tag 软信号 + verifier phase 用物理 sub-agent**。

## 核心机制

### 1. 切换主信号 — file artifact

Phase 切换的**唯一硬协议** = 上一 phase 的 `PHASE_N_COMPLETION_REPORT.md` 文件存在 + 其 `Next phase trigger` section 已填写。

进入下一 phase 前**必读**:

```bash
# Pseudo:
read previous_phase_completion_report
extract section "Next phase trigger"
verify file path mentioned exists
proceed to next phase
```

### 2. 软信号 — 角色 tag(辅助)

`[SCIENTIST]` / `[ARCHITECT]` / `[ENGINEER]` / `[VERIFIER]` 等 tag 保留作软信号。
在项目 CLAUDE.md 里写明 "进入 design phase 时使用 architect 视角"。

**角色 tag 不能单独作 phase 切换信号**(ephemeral,fresh session 无法识别)。**file artifact 是唯一可靠协议**。

### 3. Fresh context 触发 — 仅 verifier phase

- 普通 phase 切换:同 session 继续(continuous execution + 角色 tag 软切换)
- Verifier phase:**spawn fresh sub-agent**(Task tool 或 worktree,详见 `core/isolation-protocol`)
- Verifier sub-agent 显式 read 上一 phase 产出物(per `core/verifier-protocol`)

## Phase handoff 产出物约定

每 phase 完成时产出 `PHASE_<N>_COMPLETION_REPORT.md`,7-section 结构(详见 `core/continuous-execution`)。其中 **Next phase trigger** section 必含:

```markdown
## Next phase trigger
- Next phase: <phase ID, e.g., P3 Adversarial Review Round 1>
- Skill to invoke: <e.g., research/adversarial-review>
- Input file: <e.g., docs/litreview/PHASE2_THINKING.md>
- Output file: <e.g., docs/litreview/PHASE3_ADVERSARIAL_R1.md>
- Verifier: <enabled/disabled, fresh_context method>
- CC 不等 user review,直接启动
```

## 反模式

- ❌ 静默切 phase(没写 completion report 就开始新 phase)
- ❌ Completion report 缺 Next phase trigger section
- ❌ Phase 状态只在 chat 里说,没写到 file
- ❌ 只靠角色 tag(`[SCIENTIST]` 等)做硬切换 — ephemeral 无 fresh session 兼容性
- ❌ Verifier phase 在主 session 跑(应 spawn fresh sub-agent)

## 实施位置(项目 CLAUDE.md)

项目 CLAUDE.md 在 "Continuous Execution Chain" section 显式定义每个 phase:

```markdown
T1 [SCIENTIST]: Phase 1 Step 1 — 独立 comprehensive lit review
  - 输入: (无 / 上一 phase 文件)
  - Skill: research/conducting-literature-review
  - 输出: docs/litreview/PHASE1_STEP1_INDEPENDENT_LITREVIEW.md
  - Verifier: optional (research/adversarial-review at T3)
  - 完成后不停, 直接启动 T2

T2 [SCIENTIST]: Phase 1 Step 2 — 独立深刻思考
  ...
```

## 与其他 skill 的关系

- 与 `core/continuous-execution`: 互文 — 本 skill 是"怎么切",continuous 是"切完不停"
- 与 `core/halt-conditions`: 互文 — phase 完成时 check halt 条件
- 与 `core/verifier-protocol`: 互文 — 何时启用 verifier
- 与 `core/isolation-protocol`: 互文 — verifier 的 fresh context 实现

## Provenance

来自 user CLAUDE 1-5 反复用的 `STEP1_*.md → STEP2_*.md → ...` file-based 序列模式 + 生态共识(BMAD 4 phase / Spec-Kit / obra/superpowers)。
