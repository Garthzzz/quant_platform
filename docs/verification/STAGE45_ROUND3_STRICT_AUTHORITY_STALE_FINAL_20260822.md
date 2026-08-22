# Stage 4/5 Round3 严格 authority/stale/final-message 冻结报告（2026-08-22）

> **Round4 更正：**Round3 只在 live replay 前验证 Archive authority，仍留下比较窗口。
> 当前合同与 SHA 以 `STAGE45_ROUND4_AUTHORITY_WINDOW_CLOSURE_20260823.md` 为准；本报告不再是
> 当前资格依据。

## 结论与边界

独立复核提出的 2H+1M 已在公开、合成、fake-only 范围完成工程修订与一致性回归。本报告只
冻结机制 bytes 与公开测试结果，不是 Independent Verifier 放行意见，也不是 sealed holdout、
真实 Archive 质量比较、真实 Codex 或发布资格证据。

全程未连接 VM、GitHub 或网络，未运行真实 Codex，未读取 sealed/private qrel 正文，未修改
DS、Stage5、CI/guard、RAG/MCP 语义来源或 reference。

## 2H+1M 闭合

| finding | Round3 机械合同 | 公开合成证据 |
|---|---|---|
| H1：baseline authority 仍可由 plain/fake 字符串满足 | comparison 无条件调用 exact `type(LikeBaselineIndex)` verifier；仅 `from_archive_catalog` 路径具备 canonical producer extension/source receipt。verifier 闭合核验 live database/WAL、base/version/document/page identity、ordered export、presentation、extension 与 receipt；v4 prereg/per-qrel projection 同时冻结 extension/source-receipt hash | 真实只读 Archive producer 的 `projection_authority_pass=true`；plain `KnowledgeIndex`、diagnostic Like、伪报 authority 且复制 receipt/extension 的其他类型全部为 false；导出后 DB 变化也拒绝 |
| H2：receipt stale 只相信自报值 | `qrh-retrieval-per-qrel-receipt/v2-live-stale-replay` verifier 对每条 receipt 从 supplied live suite/base 重新执行 `suite.stale_qrels(base)`，与 `errors.stale` 使用 bool identity 双向比较 | live false/receipt true 与 live true/receipt false 两个方向均命中 `stale flag differs` |
| M1：空 final text 兼作“尚未看到消息”状态 | raw parser 独立维护 `agent_message_seen` 与 completed count；每条 trace 恰有一条非空 completed agent message，该消息完成时无其他 open item，之后只允许 turn terminal | 空白 final、final 后续 reasoning item、无 final trace 均拒绝；既有 valid paired traces 保持通过 |

## 合同版本

- retrieval prereg：`qrh-retrieval-comparison-preregistration/v4-authoritative-like-stale-replay`；
- per-qrel receipt：`qrh-retrieval-per-qrel-receipt/v2-live-stale-replay`；
- MCP prereg/campaign 保持 Round2 的 `v2-bound` / `v2-raw-replay`，只收紧 raw trace parser。

旧 v3 prereg、v1 per-qrel receipt、plain/diagnostic baseline 与使用空 final message 的历史 trace 不得
沿用为当前证据。

## 冻结测试

```powershell
python -B -m pytest -q -p no:cacheprovider `
  quant_hub/tests/test_knowledge_mcp.py `
  quant_hub/tests/test_knowledge_mcp_stress_public.py
# 47 passed, 15 subtests passed

python -B -m pytest -q -p no:cacheprovider `
  quant_hub/tests/test_knowledge_retrieval_eval.py `
  -k "not qrels_are_grounded and not missing_required_citation and not qrel_list_quote"
# 13 passed, 3 deselected
```

合计 `60 passed, 15 subtests passed`。三个依赖 qrel fixture 的用例按本轮边界 deselect；没有以其
形成资格结论。AST parse 与 scoped `git diff --check` 另行通过。

## 核心 SHA-256

| 文件 | SHA-256 |
|---|---|
| `knowledge/evaluation.py` | `644d57a5c400faa437bc3fd6997c77df3645a83c43dc482a83e17f0905d2f687` |
| `knowledge/retrieval.py` | `f4fb8c5359381363ec171aca5e4e3fdd91a01d541ac69948e6056f13e9f12d06` |
| `knowledge_mcp/evaluation.py` | `6a41afff23070728de1f28284856ab733c7c79f2728f6ae96dfa70e2e43b4e40` |
| `knowledge_mcp/acceptance_runner.py` | `872542b7f028e2cfa159982aca75cb916fb0d5c2ed74fa3248677be045698675` |
| `tests/test_knowledge_retrieval_eval.py` | `b9f8153b6107726d02afb01cf05783c5172c95803d913156f9d0e2c4b58f8603` |
| `tests/test_knowledge_mcp.py` | `807483519ebba2183b4d5df6ff1c4cd3667297e2f8edd4bce832e5eeaeff3c86` |

SHA 只冻结本报告形成时的工作区文件 bytes，不替代 Git commit、release certificate 或外部证据。

## 残余资格边界

- 仍须用全新真实 development suite 与至少三分之一 sealed holdout，在运行前创建新 ledger，
  通过真实 ArchiveCatalog authoritative baseline 重做 5.9/5.10；
- 真实 Codex runner 仍 disabled，公开 fake PASS 不构成 5.13/5.14 质量证据；
- 本报告不授权 VM candidate、发布、visibility、恢复、调度器或任何外部写入。
