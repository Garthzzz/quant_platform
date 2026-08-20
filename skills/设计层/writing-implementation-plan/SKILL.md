---
name: writing-implementation-plan
description: Produces EXPERIMENT_PLAN.md with full code interface spec (class names, function signatures, parameter types, tensor dimensions, YAML configs, notebook split), each task at 2-5 minute granularity with exact file paths and verification step. Includes Spec→Plan→Tasks bidirectional traceability per Spec-Kit pattern. Use when architect produces implementation plan based on EXPERIMENT_DESIGN.md.
metadata:
  category: design
  version: 1.0.0
  evidence_grade: user 实测 + 生态 (obra/superpowers 2-5min task granularity + Spec-Kit bidirectional)
---

# writing-implementation-plan — 详细实施计划

## 视角

PLAN 写得**事无巨细**,让工程师看完直接写代码。**所有类名 / 函数名 / 参数 / 张量维度 / 接口定义全部明确**。

## 进入前必读

- `EXPERIMENT_DESIGN.md`(scientist + architect 联合产出)
- `RESEARCH_LITREVIEW_AND_ANALYSIS.pdf`(lit review 完整版,告诉 "为什么")
- `design/two-round-architecture-review` — 设计完两轮审查
- `design/interface-contract` — 单位 / 维度 docstring 强制
- `design/spec-code-reconciliation` — 三方对照
- `design/resource-constraint` — 资源 commit

**两份文档缺一不可**: EXPERIMENT_DESIGN 告诉做什么,RESEARCH_LITREVIEW pdf 告诉为什么。只读前者会偏离研究意图,只读后者会理解不精确。

## 产出物 EXPERIMENT_PLAN.md 必备内容

1. **完整目录结构**
2. **所有 module / class / function 的接口签名**(参数类型 + return type + docstring)
3. **配置 YAML 模板**
4. **SanityGate 类的完整 spec**(每个 metric 的 INDEPENDENT_RANGES — per `research/independent-threshold-judgment`)
5. **缓存策略**
6. **并行执行方案**
7. **Smoke test 三级实施**(per `engineering/smoke-test-tiers`)
8. **完整实验 runner 流程**

## Task 粒度量化(obra/superpowers 模式)

每个 task **2-5 分钟可完成**,**强制三件套**:

1. **Exact file paths**:`src/models/mlp.py:L45`(不是"在 mlp.py 加一个函数")
2. **Complete code**:不留 placeholder,写完整可 copy-paste 的代码
3. **Verification step**:每个 task 末尾有"如何验证完成":运行什么命令 / 检查什么输出 / file 是否生成

例:

```markdown
### Task 3.2 — Implement MLP class

**File**: `src/models/mlp.py` (new)
**Lines**: full file
**Complete code**:
```python
import torch.nn as nn

class MLP(nn.Module):
    """MLP for cross-sectional ranking prediction.

    Args:
        input_dim: 特征数 F
        hidden_dim: 隐藏层维度 H (推荐 128 per EXPERIMENT_DESIGN §4)
        n_layers: 层数 L (推荐 3)
        dropout: Dropout 率 (推荐 0.2)

    Input shape: (N, F) — 截面 N 只股票, F 个特征
    Output shape: (N, 1) — 截面预测值
    单位: 输入 z-score 化后 (per design/interface-contract),输出 dimensionless
    """
    def __init__(self, input_dim: int, hidden_dim: int = 128, n_layers: int = 3, dropout: float = 0.2):
        super().__init__()
        layers = []
        for i in range(n_layers):
            in_d = input_dim if i == 0 else hidden_dim
            layers.append(nn.Linear(in_d, hidden_dim))
            layers.append(nn.LayerNorm(hidden_dim))
            layers.append(nn.GELU())
            layers.append(nn.Dropout(dropout))
        layers.append(nn.Linear(hidden_dim, 1))
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        return self.net(x).squeeze(-1)
```

**Verification**:
```bash
python -c "from src.models.mlp import MLP; m = MLP(50); import torch; print(m(torch.randn(100, 50)).shape)"
# 应输出: torch.Size([100])
```
```

**避免 placeholder**:
- ❌ "# TODO: 实现 forward 方法"
- ❌ "# 这里加 dropout"

**全部 complete**: 工程师 copy-paste 就能 run。

## Spec → Plan → Tasks 双向 traceability(Spec-Kit 模式)

每个 task 必须**双向反指**:
- Forward link: 本 task 实现 EXPERIMENT_DESIGN §X.Y 的哪条要求
- Backward link: 本 task 在 spec-code-reconciliation 表格中对应哪行

例:

```markdown
### Task 3.2 — Implement MLP class

**Forward link (Spec → Code)**:
- 实现 EXPERIMENT_DESIGN §4 MLP 架构 (3 层 + 128 维 + LayerNorm + GELU + Dropout 0.2)

**Backward link (Code → Spec)**:
- 见 SPEC_CODE_RECONCILIATION_TABLE.md 行 12 "MLP 架构"
```

这让 `design/spec-code-reconciliation` 三方对照表格可以**自动 verify** 双向覆盖。

## 性能优化要求(per `design/two-round-architecture-review`)

PLAN 必须完整覆盖 5 维度优化:

1. **缓存设计** — 已计算中间结果(特征矩阵 / 标准化参数 / CKA 矩阵 / 模型 checkpoint / 合成数据 ground truth)缓存,**版本标识防过期**
2. **并行计算** — K 种子训练 / hyperparameter sweep 等天然并行任务,并行方案
3. **精度-速度 trade-off** — 混合精度 (FP16 / BF16 + FP32 master) / 早停
4. **数据加载优化** — Parquet / 内存映射 / column pruning / 预加载
5. **实验管理** — 统一 config / 结果记录 / 断点续跑

## 反模式

- ❌ Task 粒度 > 5 分钟(应该拆细)
- ❌ Code 留 placeholder(应该 complete)
- ❌ 没 verification step
- ❌ 接口签名不写 unit / dimension docstring
- ❌ 没双向 traceability
- ❌ PLAN 跳过性能优化两轮审查
- ❌ 写 wall-clock estimate

## 与其他 skill 的关系

- 与 `design/designing-experiment`: 上游 — PLAN 基于 DESIGN
- 与 `design/two-round-architecture-review`: 必读 — 两轮审查
- 与 `design/interface-contract`: 必读 — docstring 单位强制
- 与 `design/spec-code-reconciliation`: 互文 — 双向 traceability
- 与 `design/resource-constraint`: 必读 — compute commit

## Provenance

- User CLAUDE 2/4/5 EXPERIMENT_PLAN.md pattern
- obra/superpowers writing-plans skill 2-5min task granularity (170k+ star)
- Spec-Kit `/speckit.tasks` 双向 traceability
