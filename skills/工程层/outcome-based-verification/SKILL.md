---
name: outcome-based-verification
description: Verifies by actually running code and reading output, not by inspecting code structure or trusting type hints. Forbids "I think it works" / "should be fine" claims without actual runtime evidence. Reports verdict only after observing actual output. Use after writing any code that needs to be verified before marking task as done, or before claiming a feature works.
metadata:
  category: engineering
  version: 1.0.0
  evidence_grade: 实测 (obra/superpowers verification-before-completion + Anthropic 官方)
---

# outcome-based-verification — 走代码 verify

## 视角

"Verify by running, not by inspecting"。**实际跑代码 + 读 output** 才能 claim done,不靠 inspecting code structure 或 type hint。

## 与 verify-before-claim 的区别

- `core/verify-before-claim`(GOLD CRITERION 1): **chat 层** — 说话前 verify 源码 / 文献证据
- `engineering/outcome-based-verification`(本 skill): **执行层** — 实际跑代码读 output 才能 claim "done"

两者互文,层次不同。

## 工作流

### Step 1 — 写完代码

写完后**不要立即 claim done**。

### Step 2 — 想 verification command

每个 task 必须有 verification step(per `design/writing-implementation-plan` task granularity)。

例:

```bash
# Verification command
python -c "from src.models.mlp import MLP; m = MLP(50); import torch; print(m(torch.randn(100, 50)).shape)"

# Expected output
torch.Size([100])
```

### Step 3 — 实际跑 command

**真的跑**,读 actual output。

### Step 4 — 对比 expected vs actual

- Match → claim done
- Mismatch → debug + iterate
- Unexpected output → flag,可能是 spec / code mismatch(per `design/spec-code-reconciliation`)

## "I think it works" 反模式

❌ "I think the MLP works because the type hints are correct"
❌ "Should be fine, the test passed in unit test"(没跑 integration)
❌ "Looks good to me"

✅ "我跑了 `python -c '...'`,实际 output 是 `torch.Size([100])`,与 expected 一致,claim done"

## 与 sanity gate 的关系

- `engineering/numerical-sanity-gate`: outcome-based 在**数值实验**的特殊形式
- 本 skill: **所有 code task** 的通用要求

实验数据 → sanity gate
代码功能 → 本 skill outcome-based

## Verification 类型

### Type 1 — Unit verification

跑单元测试 / 一行 Python 检查 import + shape:

```bash
python -c "from X import Y; print(Y().method())"
```

### Type 2 — Integration verification

跑端到端 pipeline 一小段:

```bash
python scripts/run_smoke_test.py --level 1
```

### Type 3 — Side-effect verification

检查文件是否生成 / 数据库是否更新:

```bash
ls -la experiments/cache/
sqlite3 data/papers.db "SELECT count(*) FROM papers"
```

## Anti-patterns

- ❌ "Code looks correct, marking done"
- ❌ "Unit test passed, ignoring integration"
- ❌ Verification 只读 code 不跑
- ❌ Type checker pass = verified
- ❌ "Should work like the docs say"
- ❌ 跑但不读 actual output 就 claim
- ❌ Actual output 与 expected mismatch 不 flag

## 与 hooks 的关系

可在 PreToolUse / PostToolUse hook 自动 enforce:

- Edit 文件后 → 自动跑 lint / type check / 相关测试
- 100% deterministic enforcement(per HumanLayer "advisory 80% vs hooks 100%")

User 同意后实施。

## 与其他 skill 的关系

- 与 `core/verify-before-claim`: 互文 — chat 层 vs 执行层
- 与 `engineering/numerical-sanity-gate`: 互文 — 数值实验的特殊形式
- 与 `engineering/smoke-test-tiers`: 互文 — smoke test 是 outcome-based 的 staged 形式
- 与 `design/writing-implementation-plan`: 必读 — task 必含 verification step

## Provenance

来自 obra/superpowers `verification-before-completion` skill + Anthropic 官方 best practices "Every skill ends with evidence requirements (tests passing, build output, runtime data)".

行业共识: "AI coding agents lie about their work, outcome-based verification catches it"。
