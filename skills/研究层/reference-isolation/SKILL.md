---
name: reference-isolation
description: Forbids reading reference / prior project documents during independent research phase (Step 1-3) to prevent independent thinking from being polluted by existing framings. Reference documents only become readable at synthesis phase (Step 4). Use when starting any research project that has prior reference documents, or when working on Step 1-3 of literature review.
metadata:
  category: research
  version: 1.0.0
  evidence_grade: user 独家
---

# reference-isolation — 不读参考文档直到 Step 4

## 视角

参考文档可能有 bias / 遗漏 / 错误结论 / 过早收敛的 framing。**读它会直接污染独立思考**。Step 1-3 期间绝对不读。

## 规则

### Step 1-3 期间(独立思考阶段)

- **完全不读**任何参考文档:
  - 前序项目研究文档
  - 之前 AI 与 user 讨论产生的 framework 文件
  - 业界白皮书 / 内部文档
- 不读不只是"不引用",是**连看一眼都不可以**

### Step 4 才解锁

参考文档**仅在 Step 4(参考文档 + 综合)**才允许阅读。

## Step 4 综合协议

读完参考文档后做以下事情(明确分类):

| 类别 | 说明 | 在 Step 4 文档里怎么标 |
|---|---|---|
| **Robust** | 参考文档的论点你独立研究也得出了 | `[ROBUST]` 标 — 两个独立路径得到相同结论说明可信度高 |
| **增量** | 参考文档的论点你独立研究没覆盖到 | `[INCREMENTAL]` 标 — 评估是否值得纳入 |
| **冲突** | 参考文档的论点你独立研究得出不同结论 | `[CONFLICT]` 标 — 分析谁更对,给出判断理由 |
| **新发现** | 参考文档遗漏了什么你独立研究覆盖到的重要方向 | `[NEW]` 标 — 这是 user 研究的新贡献 |

## 绝对不要做的

- ❌ 把参考文档的 framework 直接 adopt 进自己的 lit review
- ❌ "参考文档已经说了 X,我也说 X" — 应该独立推导 X,然后 Step 4 才比对
- ❌ Step 1-3 偷偷读参考文档"找灵感"
- ❌ 把参考文档的关键词 / 命名作 default(应该独立命名)

## 参考文档是审视的对象,不是采纳的权威

**参考文档是被审视的对象,不是被采纳的权威**。Step 4 综合的姿态是:

> "我独立得出 X / Y / Z,参考文档说 A / B / C。两者哪些一致(robust)?哪些不同(冲突,谁对)?哪些是增量(我没覆盖到)?哪些是参考遗漏的(我覆盖到了)?"

不是:"参考文档说 ABC,我补充 D"。

## 实施细节

### 项目 CLAUDE.md 明确

在 CLAUDE.md "研究团队的参考性观点" / "参考文档" section 显式标:

```markdown
**⚠️ 警告 — Phase 1 Step 4 才允许参考。Step 1-3 期间禁止阅读。**

**参考文档位置**: `D:\quant\optimization\低SNR神经网络选股种子稳定性诊断框架.md`

**scientist 的使用方式**:
1. Step 1-3 期间**完全不读**这个文档
2. Step 4 才读,并做以下事情: ...
```

### Step 1-3 期间 grep 自查

每次 chat 前 grep 自己回复 / 文档,看是否引用了参考文档关键词。若有 → 删除,重新独立推导。

## 反模式

- ❌ Step 1-3 期间引用参考文档 framework
- ❌ Step 1-3 期间用参考文档的命名 / 缩写
- ❌ Step 4 时把参考文档当 ground truth(应该是 review 对象)
- ❌ Step 4 综合时 silent adopt 参考文档 framework 不标 `[ROBUST]`
- ❌ Step 1-3 偷读后 chat 说"我没读"(虚假声明)

## 与其他 skill 的关系

- 与 `research/conducting-literature-review`: 必读 — 本 skill 是 Step 1-3 的硬约束
- 与 `research/literature-quality-tier`: 互补 — 三梯队判断 + 参考文档 isolation
- 与 `core/verify-before-claim`: 互文 — 独立推导符合 "走代码不下结论"

## Provenance

来自 user CLAUDE1 / CLAUDE2 / CLAUDE4 反复强调:
> "绝对不要把参考文档的 framework 直接 adopt 进自己的 lit review。参考文档是被审视的对象,不是被采纳的权威。"

学术界 preregistration 传统的简化版,但在 Claude skill 系统里独家显式化。
