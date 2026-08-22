# Stage 4/5 Round5 verifier 内部窗口闭合报告（2026-08-23）

## 结论与边界

Round5 仅修订独立复核 H1：exact Archive authority verifier 现在覆盖自身从入口 bundle
读取到返回之间的完整校验窗口。公开合成回归与既有 60 项非私密回归通过，但本报告只是
Engineer 机制冻结记录，不是 Independent Verifier 放行，也不是 sealed holdout、真实 Archive
质量增益或发布资格证据。

本轮没有连接 VM、GitHub、网络或真实 Codex，没有读取 sealed/private qrel 正文，没有修改
Archive 原数据、DS、Stage5、CI/guard、reference 或语义来源。

## 内外双层一致性合同

`validate_authoritative_archive_like_projection` 的固定顺序是：

1. 确认对象为 exact authoritative `LikeBaselineIndex`，取得只读 ArchiveCatalog source path；
2. 在读取资格 artifact/receipt 前复算入口 live database/WAL bundle；
3. 闭合验证 canonical artifact、source receipt、presentation、ordered rows、active version coverage
   与 document/page identity；
4. 在返回前的最后一点复算末端 live database/WAL bundle；
5. 仅当入口 bundle、末端 bundle 与 source receipt 中的 bundle 三者完全一致时返回成功。

`compare_candidate_to_baseline` 的 Round4 合同保持不变：所有 live per-qrel replay 前和 verdict
构造前仍各运行一次上述 exact verifier，并要求两次 producer extension、source receipt 和 bundle
identity 的 bytes 完全一致。因此每次 verifier 的内部窗口与整个 compare 的外部窗口都必须通过。

该实现不修改、checkpoint 或锁写 Archive 原数据库；普通 WAL read transaction 也不被描述为
writer lock。发生可观测变化时结果为非资格，而不是声称建立了全局排他快照。

## 确定性回归

公开测试使用互相独立的临时合成 SQLite 副本：

| 场景 | 机械结果 |
|---|---|
| exact verifier 入口 hash 返回后提交 DB 变化 | 末端复算与入口/receipt 不一致，verifier 拒绝 |
| compare 的最终 verifier 入口 hash 返回后提交 DB 变化 | `projection_authority_pass=false`，最终 gate FAIL |
| 上述 compare 场景同时固定两项困难 slice 改善、总体 gain 非负、hard error 为 0、candidate 质量 gate 通过 | 非 authority 条件均不掩盖结果，仍仅因 authority 不一致而 FAIL |
| 正常 real exporter 且 source 全程不变 | 延续 Round4：authority 通过 |
| compare 前变化、baseline replay 中变化、plain/diagnostic/伪 authority | 延续 Round3/4：authority 与 gate 均失败 |

所有变化只发生在 pytest 临时目录，未访问真实 Archive 数据。

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

合计 `60 passed, 15 subtests passed`。三个 qrel-fixture 用例按本轮公开边界 deselect，未用于
资格结论。AST parse 与 scoped `git diff --check` 通过。

## 核心 SHA-256

| 文件 | SHA-256 |
|---|---|
| `knowledge/evaluation.py` | `0ec24c79a474a5eea324534aeb6173aeacce2e74d352d229d9ce9c96c6ff299c` |
| `knowledge/retrieval.py` | `013291921e55ef7f60ddf729a8f3cfd3b371c816388ee4b6e7d606ca187a3366` |
| `knowledge_mcp/evaluation.py` | `6a41afff23070728de1f28284856ab733c7c79f2728f6ae96dfa70e2e43b4e40` |
| `knowledge_mcp/acceptance_runner.py` | `872542b7f028e2cfa159982aca75cb916fb0d5c2ed74fa3248677be045698675` |
| `tests/test_knowledge_retrieval_eval.py` | `69ede1f50ee2a2717a68f444d95d22d1aee0ec3e963780117a09048b71682639` |
| `tests/test_knowledge_mcp.py` | `807483519ebba2183b4d5df6ff1c4cd3667297e2f8edd4bce832e5eeaeff3c86` |

SHA 只冻结报告形成时的工作区 bytes，不替代 Git commit、release certificate 或外部证据。

## 残余资格边界

- 仍须使用全新真实 development suite 与至少三分之一 sealed holdout，在不变的真实
  ArchiveCatalog authority 窗口内重做 5.9/5.10；
- 真实 Codex runner 仍 disabled，公开 fake PASS 不构成 5.13/5.14 质量证据；
- 本报告不授权 VM candidate、发布、visibility、恢复、调度器或任何外部写入。
