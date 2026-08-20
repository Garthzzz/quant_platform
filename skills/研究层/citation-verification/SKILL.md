---
name: citation-verification
description: Mechanically verifies each citation in literature review — checks paper existence (search by title+author on Semantic Scholar / arXiv / Google Scholar), DOI validity, year/venue/author triple match, conclusion described matches actual paper abstract. Flags citations that fail mechanical check as "[CITATION-UNVERIFIED]" requiring user review. Use after producing literature review document with many citations, to detect citation hallucination.
metadata:
  category: research
  version: 1.0.0
  evidence_grade: 实测 (DeepTRACE ArXiv 2509.04499 + Reference Hallucination 研究)
  optional: true                    # 可选 skill,user 在 conducting-literature-review 已部分覆盖
---

# citation-verification — 引用 hallucination 检测

## 视角

LLM 编造引用(citation hallucination)是 deep research 常见问题。本 skill 做 **mechanical 检查**,与 `research/literature-quality-tier`(人工判断)互补。

## 何时启用

- Lit review 完成后,产出文档前
- 任何含 ≥ 10 个引用的研究文档
- 引用包含 arXiv / 工作论文(高 hallucination 风险)

**何时不启用**:
- 文档只引用 user 项目内部文件
- 引用 < 5 条,人工检查更轻

## Verification 协议

### 对每条引用做 4 项 mechanical check

1. **Existence check**: paper title + author + year 在 Semantic Scholar / arXiv / Google Scholar 搜得到?
2. **DOI check**(若有 DOI): DOI resolve 到的 paper 与引用描述匹配?
3. **Triple match**: year / venue / author 三元组一致?(常见 hallucination: 真 paper + 错 venue 或错 year)
4. **Conclusion match**: 引用中描述的论文结论,在 paper abstract / introduction 中能找到?

### Verdict

- **PASS**: 全部 4 项通过 → 保留原引用
- **PARTIAL**: ≥ 1 项失败 → 标 `[CITATION-UNVERIFIED:<具体原因>]`,append 到 `PENDING_USER_REVIEW.md`,user 后续 verify
- **FAIL**: ≥ 3 项失败 → 删除该引用 + 在产出文档对应位置标 `<!-- CITATION REMOVED: <原因> -->`

## 实施(伪代码)

```python
for citation in extract_citations(literature_review_doc):
    result = {
        'existence': search_semantic_scholar(citation.title, citation.author),
        'doi': resolve_doi(citation.doi) if citation.doi else None,
        'triple': verify_year_venue_author(citation),
        'conclusion': fuzzy_match(citation.described_conclusion, paper_abstract)
    }

    fails = sum(1 for v in result.values() if v == 'FAIL')

    if fails == 0:
        verdict = 'PASS'
    elif fails >= 3:
        verdict = 'FAIL — citation removed'
    else:
        verdict = 'PARTIAL — flagged for user review'

    log_to_pending_user_review(citation, verdict, result)
```

## 与 literature-quality-tier 的关系

| skill | 类型 | 检查内容 |
|---|---|---|
| `research/literature-quality-tier` | 人工判断 | 文献质量分梯队 (顶刊 / 工作论文 / 弱) + "novel ≠ reliable" |
| `research/citation-verification` | Mechanical | 引用是否存在 / triple 是否匹配 / 描述是否对应 |

**互补**: 一条引用可能 mechanical PASS(确实存在的论文)但梯队是第三梯队(低引用 arXiv);也可能梯队第一(顶刊)但 mechanical FAIL(LLM 编造 venue)。

## 反模式

- ❌ 不实际查 Semantic Scholar 就 PASS(LLM 自己 verify 自己,self-preference bias)
- ❌ 只 check title 不 check author / year / venue
- ❌ Fuzzy match conclusion 时容忍 paraphrase 过度(应严格 — 编造结论是常见 hallucination)
- ❌ Verdict 写 chat 不 append PENDING_USER_REVIEW
- ❌ FAIL 引用直接删但不在文档标注(用户不知道删了什么)

## 与其他 skill 的关系

- 与 `research/literature-quality-tier`: 互补
- 与 `research/conducting-literature-review`: 互文 — 本 skill 是 lit review 完成后的可选 verifier
- 与 `core/pending-review`: 互文 — PARTIAL verdict append PENDING_USER_REVIEW

## Provenance

学术参考: [DeepTRACE: Auditing Deep Research AI Systems (ArXiv 2509.04499)](https://arxiv.org/abs/2509.04499) — citation 一致是 deep research 核心 eval 维度。
本 skill 是可选(P7 决策的 YAGNI 原则) — user 在 `conducting-literature-review` 已部分覆盖,citation hallucination 频率低则无需启用。
