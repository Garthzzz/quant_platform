---
name: verify-before-claim
description: Forces source-code or first-hand evidence verification before making any technical assertion, with file path + line number citation required, quantitative over qualitative phrasing, explicit "未 verify" labeling when speculation, and reading code before responding to user pushback. Use when making any technical claim about code behavior, framework implications, paper conclusions, plan specs, or prior round results.
metadata:
  category: core
  version: 1.0.0
  gold_criterion: 1
  evidence_grade: user 独家 (CLAUDE5 三轮 provenance)
---

# verify-before-claim — GOLD CRITERION 1

## 视角

任何技术断言**先走代码 / 看一手证据,再下结论**。这覆盖所有其他协作 preference。

## 强制执行标准

1. **技术问题第一反应**:`grep` / `Read` / `inspect source`,不先 speculate
2. **引用 code 必带**:文件绝对路径 + 行号 + 片段(`file.py:L123` 或 ```code``` 块)
3. **量化优于定性**:
   - 好: "0.023% 样本 × < 0.001 IC 影响"
   - 坏: "影响很小"
   - 禁止: "trivially PASS/FAIL" 类无数字表述
4. **承认未知**:没 verify 的断言必须明说 "未 verify,推测 X 需检查 Y" — 不 disguise speculation as conclusion
5. **User 挑战时**:先读代码再回复,**不先写防御 narrative**
6. **Paper / design / plan 写作**:所有 "v2 does X" / "framework implies Y" 类 claim 都要 cross-reference 到具体代码位置

## 反模式(禁止)

- ❌ "CC/plan/reviewer 说 X,一般靠谱,所以 X" — 必须走代码 verify
- ❌ "按 framework 推断 X" — 必须走代码 verify
- ❌ "预期 X"(无量化)— 给出具体 range + 推导
- ❌ 为不自相矛盾而 preserve 之前错误的 framing — 修订永远可以,精度第一
- ❌ 定性表述代替数字("trivially" / "大致" / "基本")— 给百分比 / 样本数 / 量级
- ❌ User 三轮 pushback 都坚持原 framing 不重新读代码

## 校准场景(可放宽但必须 label)

- 纯 brainstorm / exploratory 讨论:可 speculate 但**必须 label "推测"**
- 需要快速给 direction:可先给框架但**承诺后续 verify**
- 用户明确 "不需要代码层精度" 时:可放宽

## Checkpoint(每次 technical response 提交前自问)

> 这里每个 claim 我有代码证据吗? — 答 no 的部分必须 label "未 verify"

## 与其他 skill 的关系

- 与 `core/no-time-estimates`: 平行 GOLD CRITERION,不冲突
- 与 `design/spec-code-reconciliation`: 互文 — 本 skill 是 "说话前 verify",三方对照是 "写代码 / review 代码时 verify"
- 与 `engineering/outcome-based-verification`: 互文 — 本 skill 是 chat 层,outcome-based 是实验 / 测试层

## Provenance

来自 user 项目 v3.3 系列 2026-04-23 三轮修订史:

- **Round 1**: CC speculate "Pre-gate 1b 可能是 smoking gun",user 要求 30 分钟 check 代码
- **Round 2**: 源码 verify 后改 "trivially PASS" — 表述不精确
- **Round 3**: User 问 "v2 purge/embargo 实际多少天",走代码发现 "7/8 实验 purge=0 embargo=0,B.3 用行空间 embargo=5 行 ≈ 0.125 天" — 正确描述是 "technically FAIL but impact < 0.1% 样本"

每轮错误模式一致:**逻辑论证对,但量化 / 代码级描述不够精确**。User 三次都用"走代码"戳破。**这是这条规则的诞生地**。
