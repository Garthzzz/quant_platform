---
name: chinese-output
description: Writes all user-facing deliverables (markdown / PDF / report / paper / slides) in Chinese with English reserved only for proper nouns, technical term abbreviations, paper titles/authors/citations, code identifiers, file paths, and math formulas. Notifies user immediately after each deliverable completes. Use when producing any deliverable document or completing a phase report.
metadata:
  category: core
  version: 1.0.0
  gold_criterion: 6
  evidence_grade: user 独家 (中文优先 + 文档完成即时通知)
---

# chinese-output — GOLD CRITERION 6

## 视角

所有 user-facing 产出**中文**。完成 deliverable 立即 surface 给 user,不 batch。

## 规则 — 中文书写

### 默认

写任何 markdown / PDF / 报告 / 论文 / slides / 演讲幻灯片前:**prose 默认全中文**。

### 允许的英文场景

仅以下情况保留英文,**其他必须中文**:
- 专有名词 / 技术术语缩写(SAMC, RLESE, CKA, GELU, BN, LN, IC, SNR, MLP, NN, OLS, HAC, MDL, LMC, MCMC, SGLD 等)
- 论文标题 / 作者 / 引用
- 代码标识符 / 文件路径
- 数学公式

### 技术术语首次出现规则

- 首次出现给中文 + 英文双标:如"信噪比 (signal-to-noise ratio, SNR)"
- 之后用中文或缩写均可

### 写完文档后必做自查

grep 高频英文连接词 ("the", "and", "is", "are", "will", "be", "which", "that", "this", "for", "with", "on", "in", "by", "of", "to") 在文档中的出现次数。
若超过 50 次连接词(说明 prose 大量英文)→ 重写中文。

允许的英文场景再 verify:是否真是专有名词 / 引用 / 公式?不是 → 翻译。

## 规则 — 文档完成即时通知

完成一个 user-facing deliverable 后:

1. 立即输出短消息(1-2 sentences):
```
✅ [文档名] 完成
位置: <相对路径>
关键内容: <1-2 句概述>
下一步: <CC 自动启动的下一 phase> 或 <halt 等 user review>
```

2. 不必等 user 回复,直接继续下一文档(continuous execution 兼容)
3. 但每个文档完成都必须有这个通知点

### 不适用场景

- 代码 file edits(implementation 细节,不是 user-facing deliverable)
- 内部中间产物(e.g., LaTeX aux 文件)
- 同一文档的多次 edit(只在完整完成时通知一次)
- PROGRESS_LOG 的每次 append(太频繁)

## 反模式

- ❌ 中英混杂 prose("我在 Step 2 propose 一个 framework that combines XY")
- ❌ 整段英文(除非是直接引用 paper 原文)
- ❌ 写完一批文档才统一通知 user(batch surface)
- ❌ "都写完了再说" 心态
- ❌ docstring 写英文(除非 user 明确要 paper 公开 release 用英文版)

## skill description 例外

**SKILL.md 的 description 字段**用英文(Anthropic router 触发率需要英文);**SKILL.md 主体**仍中文。
理由: P11 决策,英文 description 是路由最稳的选择,实测后再决定双语。

## 与其他 skill 的关系

- 与 `core/continuous-execution`: 互文 — continuous 不停但通知,本 skill 规定通知格式
- 与 `output/latex-chinese`: 互文 — LaTeX 编译时的中文支持

## Checkpoint

提交文档前自问:
1. 这个文档 prose 全中文了吗?英文部分都是合法(专有名词/引用/公式)吗?
2. 我有 surface 通知吗?user 知道这个文档完成了吗?

## Provenance

来自 user CLAUDE 1-5 反复强调的 GOLD CRITERION 6:
- 中文是 user 母语,所有 deliverable 给 user 看必须中文
- 中文论文 LaTeX 必须中文(JFE/RFS/JMLR 中文版投稿)
- 文档完成不及时通知,user 不知道进度
