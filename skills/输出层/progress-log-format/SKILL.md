---
name: progress-log-format
description: Writes PROGRESS_LOG.md entries in standardized format (role-tagged with date, with section "本次完成内容 / 关键决策与理由 / 遗留问题 / 下一步建议"), immediately appends after each phase milestone or paper completion (not batched), includes specific numbers and findings. Use when finishing a phase, completing a paper, fixing a major bug, or recording any project milestone.
metadata:
  category: output
  version: 1.0.0
  evidence_grade: user 实测 (CLAUDE 1-5 PROGRESS_LOG 格式)
---

# progress-log-format — PROGRESS_LOG 写入格式

## 视角

PROGRESS_LOG 是项目时间线 + milestone 的 single source of truth。**append-only,不删,不批量**。

## 进入前必读

- `core/progress-logging` — 三层日志总协议
- `core/chinese-output` — 中文

## 触发 append 的事件

立即 append(**不批量**):

- Phase 完成
- 角色切换
- 完成重要里程碑
- 发现 / 修复重要 bug
- 训练卡死或异常
- 重要实验结果出来
- Sanity gate 触发任何 YELLOW / RED verdict

## 标准格式

### 角色切换 / Phase 完成 entry

```markdown
### [SCIENTIST] - 2026-05-26

**本次完成内容:**
- 完成 Phase 1 Step 2 独立深度思考
- 跨维度交互矩阵覆盖 11 维 D1-D11 + 主要 pair
- 联想搜索发现 3 个非显然方向 (SAM in low SNR / SAM + CKA 协同 / lottery ticket 量化迁移)

**关键决策与理由:**
- 决定不在 Step 2 跑 PRISMA 4-phase — user 研究是叙述+联想型不是穷举型
- SAM 推荐降级到第二梯队 (在 CV 上第一梯队,在量化未验证)

**遗留问题:**
- 跨维度交互 D6 × D3 (dropout × overparameterization) 文献证据不足,需 Step 3 对抗审查
- 联想搜索发现的 "lottery ticket in quant" 是第三梯队,标实验候选

**下一步建议:**
- 自动启动 Phase 1 Step 3 — 对抗审查 Round 1
- 重点攻击 SAM 推荐的 SNR 前提
```

### 论文精读 entry(若是阅读型项目)

```markdown
### [SCIENTIST] [32] 跨股注意力机制 — 2026-05-26 23:45
状态: completed
耗时: 58 分钟
关键发现: Cross-stock attention 在 CSI500 IC 提升 0.008,但消融实验在验证集做,OOS 存疑
遗留: 复现时需测 OOS 消融
```

### Engineer 操作 entry

```markdown
### [ENGINEER] 实施 MLP 训练 runner — 2026-05-26 14:20
操作: 实施 src/training/trainer.py:Trainer class + 配置 YAML
结果: 成功;Smoke Test Level 1/2/3 全部 pass;CKA cross-seed K=10 mean=0.42 > 0.3 baseline ✓
变更: src/training/trainer.py (new), experiments/configs/baseline.yaml (new)
遗留: SAM optimizer 的 ρ 参数 sweep 待跑
```

### Bug 修复 entry

```markdown
### [ENGINEER] 修复 seed isolation bug — 2026-05-19 11:00
操作: 修复 `experiments/smoke/snr_scan_h2_vs_h3_diagnostic.py` 的 seed 共用问题
原因: 原代码 `SyntheticDataGenerator(seed=seed)` 和 `SeedTrainer(seed=seed)` 共用 seed,K seeds → K 份不同 data,跨"种子" CKA 接近 random
修复: 显式分离 data_seed=42 (loop 外) + model_seed (loop 内变化)
验证: K=10 corrected CKA mean=0.42, K=3 hash 一致 → audit pass per seed-isolation-audit
遗留: 之前 v1/v2 跑出的 SNR scan 结果作废
```

## 写入规范

### 顺序

最新 entry 放**底部**(append-only)。User 倒序看时间线时,自己往下滚到底部。

### Date 格式

`YYYY-MM-DD` 或 `YYYY-MM-DD HH:MM`(详细时刻才加时间)。

### 角色 tag

`[SCIENTIST]` / `[ARCHITECT]` / `[ENGINEER]` / `[VERIFIER]` 等(项目定义)。

### 关键数字

实测数字必须含,不要"看起来不错"。

例:
- ✓ "CKA cross-seed K=10 mean=0.42 > 0.3 baseline"
- ❌ "CKA 看起来 OK"

### 中文

prose 中文,英文仅限专有名词 / 文件路径 / 数学公式 / 代码标识符(per `core/chinese-output`)。

## Self-check checklist(每次 append 前)

- [ ] 含具体数字 / 文件路径 / 关键发现?
- [ ] 4 个 section 都填了(本次 / 关键决策 / 遗留 / 下一步)?
- [ ] 角色 tag + date 正确?
- [ ] 中文 prose?
- [ ] 不批量 — 现在就写?

## 反模式

- ❌ 完成一批 milestone 才统一 append(应该立即)
- ❌ "完成了 Phase 2" 这种没具体内容
- ❌ "关键决策" section 写 spec 内容(应该写决策 + 理由)
- ❌ 用英文 prose
- ❌ Resolved 后删除 entry(应该保留历史)
- ❌ 时间线倒序(最新放顶部)— 应该正序 append-only

## 与其他 skill 的关系

- 与 `core/progress-logging`: 必读 — 三层日志总协议
- 与 `core/continuous-execution`: 互文 — 每 phase 完成 append + 写 completion report
- 与 `engineering/session-reporting`: 互文 — session 汇报数据来源 session_current.log,但 milestone 进 PROGRESS_LOG

## Provenance

来自 user CLAUDE 1/2/4/5 反复用的 PROGRESS_LOG 格式。
4 section 模板("本次完成 / 关键决策 / 遗留 / 下一步")是 user 实测 — 没这 4 个就会信息漏 / 难追溯。
