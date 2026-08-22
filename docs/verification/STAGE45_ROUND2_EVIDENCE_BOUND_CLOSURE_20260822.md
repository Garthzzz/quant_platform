# Stage 4/5 Round2 evidence-bound 冻结报告（2026-08-22）

> **Round3 更正：**本报告的 baseline authority、stale replay 与 final-message 状态机合同已由
> `STAGE45_ROUND3_STRICT_AUTHORITY_STALE_FINAL_20260822.md` 取代。Round2 SHA 仅表示当时 bytes，
> 不得用于当前资格判断。

## 结论

Round2 的 B5/H3/M2 已在公开、合成、fake-only 范围内完成机械闭合，公开定向回归为绿。
这是一份机制冻结报告，不是新的检索质量证书、sealed holdout 结果、真实 Codex 验收结果或发布
授权。5.9、5.10、5.13、5.14 继续保持未完成。

本轮没有连接 VM、GitHub 或外部网络，没有运行真实 Codex，没有读取 sealed/private qrel 正文，
也没有触碰 RAG/MCP 语义来源正文。公开测试只使用运行时临时目录、程序内构造 qrel 和 fake
transport。

## Round2 闭合矩阵

| finding | 当前机械合同 | 公开反例/验证 |
|---|---|---|
| B1：receipt 只自洽、不消费真实 suite/base/index/displayed bytes | comparison 必须提交真实 `QrelSuite` 与两侧 live index；逐 qrel 重跑 query，逐项比较完整 split、suite receipt、projection、locator、展示 bytes 与重算 metrics | 改写 query envelope、metrics、projection 或展示结果均拒绝 |
| B2：prereg 可事后形成 | v3 prereg 在任何 evaluate 前以 `O_EXCL` + fsync 写 exact ledger bytes；evaluate/compare 同时核对 ledger 与 `registered_at < evaluation_started_at` | 同路径回填返回 `FileExistsError` |
| B3：campaign receipt 未重放 raw traces | final validator 必须重新提交 exact prereg ledger、config、prompt、两臂 raw JSONL 与 dispatch ledger，并 byte-for-byte 比较完整重放 receipt | 改写 campaign 字段或 raw trace 后拒绝 |
| B4：prompt/run/config/time/identity 来源未绑定 | v2-bound prereg 冻结 prompt/config/run/model/server/authority；dispatch intent 在 fake transport 前落盘，completion 绑定 trace hash；时序只信 durable ledger | prompt/config/run/arm/identity 或 ledger 时序不一致均 FAIL |
| B5：marker/citation/locator 可跨字段拼接 | assisted final 使用 closed `decision/conditions/limitations` schema；每条 claim 绑定完整 object/document-version/source/span/byte-range/citation tuple，并回链 prior get | 混合 locator tuple、guessed get、未返回 citation 均 FAIL |
| H1：LIKE 不是真实 Archive 展示 producer | 生产入口固定为 `LikeBaselineIndex.from_archive_catalog`：只读导出真实 `document_search_projection`，冻结 database/WAL、ordered rows、document identity、presentation、page URL 与 source receipt | 直接构造只标记 `CALLER_SUPPLIED_DIAGNOSTIC`，最终 `projection_authority_pass=false`；snippet/title-only/document LIMIT 有公开测试 |
| H2：nested qrel/receipt schema 不闭合 | suite、qrel、locator、cards、metrics、errors、comparison 与 campaign cases 都做 closed-field、类型、唯一性和 canonical bytes 检查 | duplicate/unknown/missing 字段、非 canonical JSON 拒绝 |
| H3：item/dispatch terminal 配对不足 | raw item 必须一 start 一 terminal；所有 start identity 字段在 terminal 保持一致，tool 的 server/tool/arguments 全量一致；final agent item 后禁止新 item；fake runner 先 intent 后 transport，孤立 completion 在调用 transport 前拒绝 | changed identity、open item、重复 terminal、completion-without-intent 均 fail closed |
| M1：campaign 总资源无上限 | case 数、prompt/config/marker、逐 trace、campaign trace bytes、逐 case 和 campaign target calls 均有有限上限 | 超 case/call/byte 预算拒绝 |
| M2：文档/OpenSpec 漂移 | `STAGE45_EVALUATION_GATES.md`、`KNOWLEDGE_MCP.md` 与 OpenSpec 5.10/5.14 同步 v3/v2-bound 合同和未完成边界 | 历史 v1/v2/v3 或 aggregate 证据不继承 |

## 冻结测试

在仓库根执行，使用 `-B` 且禁用 pytest cache：

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

合计为 60 passed、15 subtests passed。三个 deselected 用例依赖 qrel fixture；本轮遵守独立
Engineer 的边界，没有用它们形成或宣称任何新资格结果。另执行 AST parse 与 scoped
`git diff --check`，均通过。

## 核心冻结 SHA-256

| 文件 | SHA-256 |
|---|---|
| `knowledge/evaluation.py` | `212f5384462cd11c79607599ff278f58db4b8a2bbc69c458a56ce3019ddc2cc6` |
| `knowledge/retrieval.py` | `0af25c63be8db20a0c25027ef852899479256b335c148e5a4d1baac38f91f9b0` |
| `knowledge_mcp/evaluation.py` | `0292cfa255a135e3ab169fa46d6c27b0951e1fbdd3829ef5c1a768e1fcd6989f` |
| `knowledge_mcp/acceptance_runner.py` | `872542b7f028e2cfa159982aca75cb916fb0d5c2ed74fa3248677be045698675` |
| `tests/test_knowledge_retrieval_eval.py` | `e43f1624bf12be5ede6252ebe551f85844d7948f4934ee0476f8f05541ee7855` |
| `tests/test_knowledge_mcp.py` | `71cb2a13560587d1ede02843c811eadc4eb4b16dcbf8d09c0cb66d61ed741a4f` |

SHA 只冻结本次报告时的工作区 bytes，不替代 Git commit、release certificate 或外部证据。

## 残余资格边界

- 必须使用全新的真实 development suite 与至少三分之一 sealed holdout，在运行前写入新的 durable
  ledger，并以真实 ArchiveCatalog authoritative projection 重新取得检索比较结果。
- 真实 Codex runner 仍为 disabled；公开 `FAKE_ONLY_REAL_CODEX_DISABLED` PASS 只证明 runner、
  parser、ledger 与 replay gate，不证明 5.13/5.14 的真实模型质量。
- 本报告不授权 VM candidate、发布、visibility 切换、恢复、调度器变更或任何外部写入。
