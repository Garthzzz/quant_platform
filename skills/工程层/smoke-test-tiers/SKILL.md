---
name: smoke-test-tiers
description: Runs three-tier progressive smoke test before main experiments — Level 1 minimal data generation (20 stocks × 60 days × SNR check), Level 2 single seed training (50 stocks × 100 days × MLP × 3 epochs, loss must vary), Level 3 full pipeline (100 stocks × 200 days × K=3 seeds × complete pipeline, validate multi-config + CKA matrix + cluster selection). Pass condition each level no errors + expected data format. Use before any main experiment, after pipeline rewrite, or before overnight long-run.
metadata:
  category: engineering
  version: 1.0.0
  evidence_grade: user 实测 (CLAUDE2/4 三级递进)
---

# smoke-test-tiers — Smoke Test 三级递进

## 视角

正式实验前用**最小规模**验证 pipeline 跑通。三级递进 — Level 越高覆盖越完整。

## 进入前必读

- `EXPERIMENT_PLAN.md` 的 smoke test section
- `engineering/outcome-based-verification` — verify by running

## 三级 smoke test

### Level 1 — 数据生成测试

**目的**: 验证数据生成器跑通 + ground truth 性质符合预期

**规模**(合成数据)<br>
- 20 stocks × 60 days × 50 features × SNR=5%

**检查**:
- [ ] 数据生成跑通无 error
- [ ] Ground truth signal/noise variance 实际 ≈ 5%(per `research/independent-threshold-judgment` 双 range)
- [ ] Schema 符合 EXPERIMENT_DESIGN(per `engineering/code-quality-standard`)
- [ ] 厚尾 / 截面相关 / 时序聚集 性质实测(若 design 要求)

**Pass 条件**: 跑通 + 数据性质符合 design 预期

### Level 2 — 单 seed 训练测试

**目的**: 验证训练 pipeline 跑通 + loss 有变化

**规模**:
- 50 stocks × 100 days × 50 features × MLP × **epoch 3**

**检查**:
- [ ] 训练跑通无 error
- [ ] 3 个 epoch loss 有变化(不恒为同一个数)
- [ ] No NaN cascade
- [ ] GPU 内存峰值 < VRAM 上限(per `design/resource-constraint`)
- [ ] 速度 ≈ 预期(粗估 1 batch / sec 数量级)

**Pass 条件**: 跑通 + loss 变化 + 无 NaN + 内存 / 速度 OK

### Level 3 — 完整 pipeline 测试

**目的**: 验证多 config 切换 + complex 模块跑通

**规模**:
- 100 stocks × 200 days × **K=3 seeds** × 完整 pipeline(含 SAM / CKA / cluster selection 等)

**检查**:
- [ ] 多 config 切换跑通
- [ ] CKA 矩阵计算跑通无 NaN
- [ ] Cluster selection 跑通
- [ ] K=3 seeds 实际产生不同结果(per `engineering/seed-isolation-audit` data 固定 model 变化)
- [ ] Sanity gate 跑通(per `engineering/numerical-sanity-gate`)
- [ ] 产出 file 格式符合 PLAN

**Pass 条件**: 全流程端到端跑通 + 多 seed 实际有效

## Pass 协议

**每个 level 必须 PASS 才能进下一 level**。

```
Level 1 PASS → 启动 Level 2
Level 2 PASS → 启动 Level 3
Level 3 PASS → 启动正式实验 (大规模)
```

Level N 失败:
- 写 PROGRESS_LOG 含 error + diagnosis
- HALT,不直接进 Level N+1
- 修 bug → 重跑 Level N(可能影响 Level N-1 已 pass 的判断,需重新验证)

## 不做的事

- ❌ 跳过 Level 1 / Level 2 直接 Level 3
- ❌ Level N 部分 pass 部分 fail 就进 Level N+1
- ❌ Smoke test pass 后正式实验跳过 verification step(per `engineering/outcome-based-verification`)
- ❌ Smoke test 失败 retry 多次不 flag
- ❌ Smoke test 用 production 规模数据(失去 smoke 意义)

## 三级 vs 单级 smoke test

User 实测 CLAUDE2 / CLAUDE4 用三级。理由:

- Level 1 验证数据 — 数据问题(SNR / schema)在最小规模就抓住
- Level 2 验证训练 — 训练问题(loss 不动 / NaN)在小 model 就抓住
- Level 3 验证 pipeline — 多模块交互问题(config 切换 / cluster selection)需要小规模端到端

**单级 smoke test** 会让 Level 2/3 问题在 Level 1 阶段 silent(因为 Level 1 不跑训练)。

## 资源约束

Smoke test 三级**总 compute < 1 GPU-hour**(per `design/resource-constraint`)。

若 Level 3 实测 > 1 GPU-hour → 规模太大,降到更小。

## 反模式

- ❌ "看起来跑通了" 不读 output 就 claim pass
- ❌ Loss 变化但绝对值不合理(e.g., loss = NaN 在某轮)不 flag
- ❌ Level 3 验证只看跑通不看 seeds 是否实际有效
- ❌ Smoke test pass 后 spec 改了不重跑

## 与其他 skill 的关系

- 与 `engineering/outcome-based-verification`: 互文 — smoke test 是 outcome-based 的 staged 形式
- 与 `engineering/numerical-sanity-gate`: 互文 — Level 3 含 sanity gate
- 与 `engineering/seed-isolation-audit`: 互文 — Level 3 验证 seed 隔离
- 与 `design/resource-constraint`: 必读 — smoke test < 1 GPU-hour 约束

## Provenance

来自 user CLAUDE2 / CLAUDE4 三级 smoke test 实测 pattern。
单级 smoke test 用过但发现遗漏 Level 2 / Level 3 类问题,所以 user 改为三级递进。
