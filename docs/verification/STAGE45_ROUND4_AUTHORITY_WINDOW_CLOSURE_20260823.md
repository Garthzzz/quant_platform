# Stage 4/5 Round4 Archive authority 窗口闭合报告（2026-08-23）

> 历史冻结说明：Round5 已补充 exact verifier 自身的入口/末端双重 bundle 复算；当前合同与
> SHA 以 `STAGE45_ROUND5_VERIFIER_INTERNAL_WINDOW_CLOSURE_20260823.md` 为准。

## 结论与边界

Round4 仅修订独立复核 H1：Archive authority 现在覆盖完整 candidate/baseline comparison
窗口。公开合成回归通过，但本报告是 Engineer 机制冻结记录，不是 Independent Verifier 放行，
也不是 sealed holdout、真实 Archive 质量增益或发布资格证据。

本轮没有连接 VM、GitHub、网络或真实 Codex，没有读取 sealed/private qrel 正文，没有修改
Archive 原数据、DS、Stage5、CI/guard、reference 或语义来源。

## 双端 authority 合同

`compare_candidate_to_baseline` 执行顺序固定为：

1. 核对 prereg ledger、真实 suite 与两侧 live projection identity；
2. 运行 exact Archive authority verifier，冻结 canonical producer extension、source receipt 和
   database/WAL bundle bytes；
3. 对 candidate 的全部 per-qrel receipts 执行 live query replay；
4. 对 baseline 的全部 per-qrel receipts 执行 live query replay；
5. 完成两侧 receipt、qrel identity、slice、hard error、gain 与 metrics 重算；
6. 在构造 `ComparisonReport` 前的最后一点再次执行同一个 exact verifier；
7. 仅当前后两次均 authoritative 且三份 identity byte-for-byte 相同时，设置
   `projection_authority_pass=true`；否则该字段与最终 gate 均为 false。

没有采用普通 SQLite read transaction 作为 writer lock。WAL 模式下只读 snapshot 不阻止并发
writer，而且 baseline query 使用已经冻结的内存 projection；声称它覆盖整个外部 writer 窗口会
产生错误保证。本轮采用前后 live bundle 检测，不 checkpoint、不写入也不锁定 Archive 原库。

## 确定性窗口回归

公开测试在互相独立的临时 SQLite 副本上验证：

| 场景 | 预期与结果 |
|---|---|
| 正常 `LikeBaselineIndex.from_archive_catalog`，比较期间 source 不变 | `projection_authority_pass=true` |
| exporter/receipt 已冻结，但 database 在进入 compare 前变化 | authority false，gate false |
| 第一次 authority 验证通过，在 baseline live replay 的第一次 `search` 内提交 DB 变化 | 第二次 verifier 检出 bundle drift；authority false，gate false |
| plain、diagnostic Like、伪 authority | 延续 Round3：authority false，gate false |

所有变化仅发生在 pytest 临时目录的合成数据库中。

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

合计 `60 passed, 15 subtests passed`。三个 qrel-fixture 用例按本轮边界 deselect，未用于资格
结论。AST parse 与 scoped `git diff --check` 通过。

## 核心 SHA-256

| 文件 | SHA-256 |
|---|---|
| `knowledge/evaluation.py` | `0ec24c79a474a5eea324534aeb6173aeacce2e74d352d229d9ce9c96c6ff299c` |
| `knowledge/retrieval.py` | `f4fb8c5359381363ec171aca5e4e3fdd91a01d541ac69948e6056f13e9f12d06` |
| `knowledge_mcp/evaluation.py` | `6a41afff23070728de1f28284856ab733c7c79f2728f6ae96dfa70e2e43b4e40` |
| `knowledge_mcp/acceptance_runner.py` | `872542b7f028e2cfa159982aca75cb916fb0d5c2ed74fa3248677be045698675` |
| `tests/test_knowledge_retrieval_eval.py` | `ed54ab1701267b185e1c8061501275b67957f4fe5b00a8bf34585211ccd7d231` |
| `tests/test_knowledge_mcp.py` | `807483519ebba2183b4d5df6ff1c4cd3667297e2f8edd4bce832e5eeaeff3c86` |

SHA 只冻结报告形成时的工作区 bytes，不替代 Git commit、release certificate 或外部证据。

## 残余资格边界

- 仍须使用全新真实 development suite 与至少三分之一 sealed holdout，通过真实、不变的
  ArchiveCatalog authority 窗口重做 5.9/5.10；
- 真实 Codex runner 仍 disabled，公开 fake PASS 不构成 5.13/5.14 质量证据；
- 本报告不授权 VM candidate、发布、visibility、恢复、调度器或任何外部写入。
