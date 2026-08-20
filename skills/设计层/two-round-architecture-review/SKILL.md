---
name: two-round-architecture-review
description: Performs two-round architecture review on the implementation plan — Round 1 logical completeness review (does the architecture cover all design requirements end to end), Round 2 performance optimization review (cache / parallel / mixed-precision / data-loading / experiment-management). Confirms accuracy first, optimization second. Use after writing implementation plan but before handing to engineer.
metadata:
  category: design
  version: 1.0.0
  evidence_grade: user 实测
---

# two-round-architecture-review — 性能优化两轮审查

## 视角

PLAN 完成后**强制两轮审查**。第一轮逻辑,第二轮性能。**准确性是第一要务,优化建立在准确性基础上**。

## Round 1 — 逻辑完整性

完整阅读整个架构文档,确认:

- [ ] 每个实验都有对应的 module / class / function?
- [ ] 数据 pipeline 端到端流通(数据加载 → 预处理 → 训练 → 评估 → 输出)?
- [ ] 接口签名一致(上游输出 == 下游输入 的 shape / type)?
- [ ] 关键单位 / 维度 docstring 明示(per `design/interface-contract`)?
- [ ] 每个 task 有 verification step?
- [ ] EXPERIMENT_DESIGN 中每条要求都有对应 task?(forward traceability)
- [ ] 每个 task 都反指 DESIGN section?(backward traceability)

发现缺漏 → 在 PLAN 中补全,不能"以后再说"。

## Round 2 — 性能优化(5 维度)

### 1. 缓存设计

- 已计算中间结果(特征矩阵 / 标准化参数 / 相关矩阵 / 模型 checkpoint / 合成数据 ground truth)**必须设计缓存机制**
- **版本标识防过期**:参数变更后旧缓存自动失效
- **不要重复数据存储**:同一 tensor 不要在多个 cache 文件里存多份

具体 check:
- [ ] 每个 expensive computation 有 cache?
- [ ] cache 命名含 version hash?
- [ ] cache invalidation 协议明确?

### 2. 并行计算

- 多种子 bootstrap / 多 config grid search 等**天然可并行任务**必须设计并行方案
- 方案选择: multiprocessing / joblib / 多 GPU stream / Subagent 物理隔离
- 文件系统作 IPC(per `core/isolation-protocol`)

具体 check:
- [ ] 列出可并行的 task?
- [ ] 并行方案 + IPC 介质明确?
- [ ] 不可并行的 task 标 sequential dependency?

### 3. 精度-速度 trade-off

- **混合精度训练**(FP16 / BF16 + FP32 master weights):FP32 baseline 跑通后切 BF16 加速
- 大矩阵运算近似算法(若实测无精度损失)
- 早停策略合理(patience 选择 justify)

**校准**: 优化不得以牺牲结果正确性为代价。

具体 check:
- [ ] 列出 trade-off 点?
- [ ] 每个 trade-off 有 baseline 对比验证?
- [ ] 精度损失阈值明确?

### 4. 数据加载优化

- Parquet / Qlib 等数据读取可能成为瓶颈
- 策略: 预加载 / 内存映射 / 批量读取 / column pruning

具体 check:
- [ ] 数据加载是 bottleneck 吗?(profile 给数据)
- [ ] 优化策略具体到 column / 时间 range?
- [ ] 内存占用峰值估算 < 系统可用?

### 5. 实验管理

- 统一实验 config(YAML / JSON)
- 结果记录格式统一
- 断点续跑机制(若 long-run)
- MLflow / 类似工具 (可选)

具体 check:
- [ ] config schema 明确?
- [ ] 结果 file 命名约定?
- [ ] 中断后 resume 协议?

## 准确性 vs 优化的硬约束

**任何优化不得以牺牲结果正确性为代价**。

- 若混合精度让 IC 实测变化 > 0.005 → 回退 FP32
- 若近似算法让 final metric 实测变化 > 1% → 回退精确算法
- 若 cache invalidation 协议复杂到容易出错 → 不要 cache

## Self-check checklist(出 Round 2 前)

- [ ] Round 1 全部 PASS?
- [ ] 5 维度优化都 review?
- [ ] 每个优化决策有 verification 计划?
- [ ] 资源约束 commit 仍满足(per `design/resource-constraint`)?

## 反模式

- ❌ 跳过 Round 1 直接做 Round 2
- ❌ Round 1 笼统 "looks good" 不逐项 check
- ❌ 优化 trade-off 不 verify 精度损失
- ❌ Cache 没 version 标识
- ❌ 并行方案没明确 IPC 介质
- ❌ 优化后总 compute 超约束

## 与其他 skill 的关系

- 与 `design/writing-implementation-plan`: 上游 — 本 skill 是 PLAN 完成后审查
- 与 `design/resource-constraint`: 必读 — 优化后仍符合约束
- 与 `design/spec-code-reconciliation`: 互文 — Round 1 双向 traceability check
- 与 `core/verifier-protocol`: 互文 — 本 skill 可触发 verifier 启用

## Provenance

来自 user CLAUDE 2/4/5 反复要求的"架构师必须执行两轮审查":
- 第一轮:完成架构设计后,完整阅读整个架构文档,确认逻辑完整性
- 第二轮:从性能优化角度重新审视,确认没有遗漏的优化机会

"准确性是第一要务,优化建立在准确性基础上"是 user 强调多次的硬约束。
