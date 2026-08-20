---
name: seed-isolation-audit
description: Enforces data_seed and model_seed separation in any cross-seed experiment, fixes data outside K-seed loop (only model varies), runs mandatory pre-implementation audit gate (code review of seed injection points + runtime K=3 feature hash verify + CKA cross-validate K=10 > random baseline). Without audit pass, runner cannot be used for formal experiments. Use when designing or implementing any multi-seed experiment (bootstrap / ensemble / robustness study).
metadata:
  category: engineering
  version: 1.0.0
  evidence_grade: user 独家 (CLAUDE2 v1.6 seed audit gate 反例库)
---

# seed-isolation-audit — Seed 隔离强制约束

## 视角

跨 seed 实验必须**显式分离 data_seed 和 model_seed**。User 实测过严重 bug:`SyntheticDataGenerator(seed=seed)` 和 `SeedTrainer(seed=seed)` 共用同一 seed 变量,**导致 K seeds 实际是 K 份不同 data**,跨"种子" CKA 接近 random baseline。

## 进入前必读

- `engineering/code-quality-standard` — 工程规范
- `engineering/smoke-test-tiers` — Level 3 含 seed 验证
- `design/spec-code-reconciliation` — 三方对照

## 强制约束(MANDATORY)

### 1. 显式分离 data_seed 和 model_seed

**不允许共用单一 seed 变量驱动 data + model**:

```python
# 错误 (user 实测 bug 来源)
def run_one_seed(seed):
    data = SyntheticDataGenerator(seed=seed).generate()  # data 随 seed 变
    trainer = SeedTrainer(seed=seed)                      # model 也随 seed 变
    trainer.fit(data)
    # K seeds → K 份不同 data + K 个不同 model
    # CKA 对比变成 data confound 的混合,不是 model robustness

# 正确
def run_experiment(K_seeds, data_seed=42):
    # data 在 K-seed loop 外固定
    data = SyntheticDataGenerator(seed=data_seed).generate()
    results = []
    for model_seed in range(K_seeds):
        trainer = SeedTrainer(seed=model_seed)            # 只 model 变
        trainer.fit(data)                                  # 共享 data
        results.append(trainer.evaluate())
    # K seeds → 1 份固定 data + K 个不同 model
    # CKA 对比是真的 model robustness
```

### 2. 数据 K-seed 跨循环固定

- `SyntheticDataGenerator(seed=data_seed)` 调用必须在 **K-seed loop 之前**
- 生成的 tensors **共享**给所有 model_seed
- 真实 parquet 数据加载(loader / batch prep)必须在 **K-seed loop 之前**,batches 共享

### 3. SeedTrainer 接受外部固定 data

```python
class SeedTrainer:
    def __init__(self, seed: int):
        self.model_seed = seed
        torch.manual_seed(seed)
        # 不在这里 generate data
    
    def fit(self, data):
        """接受外部固定的 data,不自己 generate"""
        ...
```

## Per-runner Audit Gate(MANDATORY pre-implementation)

每个 cross-seed runner 实施完成后,**必须先跑一次 seed audit** 验证 data 固定,才能用于正式实验。

### Audit 步骤

1. **代码 review**: 列出每个 seed 注入点(file:line)+ 该 seed 驱动的对象(data / model / training stochasticity)
2. **运行时 verify**: 用 K=3 seeds 跑一次,在 K=3 之间 dump `tensors['features']`(或 batches features)的 hash / sum,**验证完全相同**(即 data 跨 seed 真的固定)
3. **CKA cross-validate**: 用 corrected setup K=10 model seeds × 30 epochs 在合成数据上 CKA cross-seed > 0.3(random baseline),比 K=3 verify 多一层 evidence
4. 任一失败 → **immediate halt**,不进正式实验

### Audit 责任记录

每个 Tier runner 通过 audit gate 后,ARCHITECT/ENGINEER **必须**在 PROGRESS_LOG.md append:

```markdown
### [ARCHITECT/ENGINEER] - 2026-MM-DD — Tier X Runner <RunnerName> seed audit pass

- Code review: <seed 注入点表 brief>
- Runtime verify K=3 features hash: <hash 一致或失败>
- CKA cross-validate K=10 model seeds: <CKA mean, > 0.3 baseline>
- Verdict: PASS, runner cleared for use
```

**未 audit 通过即用 runner 跑正式实验 = 数据污染重大问题**,视为 retroactive halt(per `core/halt-conditions`)。

## 编码 review 同步要求

ARCHITECT 在 `EXPERIMENT_PLAN.md` 各 runner spec 段必须:

- 显式 declare `data_seed` 和 `model_seed` 两参数
- 标注 data fixed across K-seed loop(在 spec 文档中明示)
- 引用本 skill 作 binding

## Clean Pattern(参考实施)

User 项目实测 clean pattern:

- `experiments/smoke/l2_mid.py:L93-110`: `SyntheticDataGenerator(seed=42)` 在 line 93, `for seed in [42,43,44]` 在 line 107, `run_one_seed(tensors=tensors, ..., seed=seed)` 接受 fixed tensors
- `experiments/smoke/l3_v16_parquet.py:L145-165`: parquet/batches 在 line 145-156, `for seed in [42,43,44]` 在 line 165
- `experiments/smoke/snr_scan_h2_vs_h3_diagnostic.py`: 显式 `data_seed` / `model_seed` 两参数分离
- `experiments/smoke/snr_floor_scan_v3_corrected.py`: v1/v2 bug 修复版

## 反模式(具体)

- ❌ `def run(seed): data = gen(seed); train(seed)`(同一 seed 驱动 data + model)
- ❌ 在 K-seed loop **内部** generate data
- ❌ Runner 实施完直接跑正式实验,不过 audit gate
- ❌ Audit 只跑 K=3 不跑 K=10 CKA verify(K=3 hash 一致可能 coincidence)
- ❌ Audit 失败后继续跑(应 immediate halt)
- ❌ PLAN 没显式 declare 两参数

## 阈值常量(SNR-dependent,若用 CKA)

User CLAUDE2 实测 Tier 0 用 SNR-dependent CKA 阈值查表(`thresholds_calibrated.yaml`):

- Tier 0 是合成数据,SNR 显式设定值
- **必须**使用 `penultimate_cka.snr_dependent_thresholds` 按 SNR 查表
- **不得**使用 `default_fixed_threshold_for_main_snr_1pct`

Anti-pattern banned in Tier 0:
```python
# ❌ Tier 0 用 fixed 阈值
cka_threshold = thresholds['penultimate_cka']['default_fixed_threshold_for_main_snr_1pct']['cka_lower_threshold']

# ✓ Tier 0 SNR-dependent 查表
snr = experiment_config['snr']
cka_threshold = thresholds['penultimate_cka']['snr_dependent_thresholds'][f'snr_{snr}']['cka_lower_threshold']
```

## 与其他 skill 的关系

- 与 `engineering/smoke-test-tiers`: 互文 — Level 3 含 seed audit
- 与 `engineering/code-quality-standard`: 互文 — 错误处理 + 验证
- 与 `design/spec-code-reconciliation`: 互文 — runner spec 必须 declare 两参数
- 与 `engineering/parallel-subagent-orchestration`: 互文 — K seeds 可并行

## Provenance

来自 user signal_to_noise 项目 2026-05-19 后续指令:

> SNR scan v1/v2 因 `SyntheticDataGenerator(seed=seed)` 和 `SeedTrainer(seed=seed)` 共用同一 seed 变量,导致 K seeds 实际是 K 份不同 data,跨"种子" CKA 接近 random baseline。

**这条规则是 user 在具体 bug 后产生的 hard lesson**。生态里没有同等强度的 seed 隔离 audit gate 实践。
