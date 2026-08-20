# Archive Evidence C Gate 最终候选报告

状态：**最终候选已冻结；独立数据层复核无 blocker，等待总 Gate 汇总。**

本报告与 `C_GATE_REVIEW.md` 是 manifest 明确排除的反向引用文档。它们不参与产品执行；冻结后仅同步最终身份和只读审核命令，未修改任何已冻结代码、fixture、测试、输入或运行物料。

## 1. 最终冻结身份

- Candidate：`qrh:evidence-c-candidate:c-gate-20260715-v4-final`
- Manifest：`quant_hub/var/delivery/evidence/c-gate-20260715-v4-final/C_CANDIDATE_MANIFEST.json`
- Manifest SHA-256：`c0bbeedf5b66e2265104c814b7880a85e5a2ac2b9596440309e1902adda96c43`
- Current-code fresh replay：`quant_hub/var/replay/evidence/c-gate-20260715-v2-fulltext`
- Delivery：`quant_hub/var/delivery/evidence/c-gate-20260715-v4-final`
- Evidence schema SHA-256：`3b6f56ac85836fb86317276422f2a58db26a5d564d82f78016d2be18ee9f3423`
- 5,181 行引用 inventory SHA-256：`39345ca71611d3d0c391f9675989c469aa5de4c4b225bca92d9650d35c9e0bc2`
- 245 行候选状态 inventory SHA-256：`b8b2f60603c7c0e056b39497ac81bcb07c943444bb92d50da4b002b7a30dc03d`
- 全文读取结果 SHA-256：`7888fcaa6eb7fda82ad7a60899a2666349262fe3ee30b9df8a474e23f56ab0af`

Manifest v4-final 逐文件冻结 203 个 formal source/migration/fixture/test/tool 文件、475 个输入文件，以及 replay/delivery 各 22 个运行文件。覆盖范围是完整 `src/quant_hub`、全部 migrations、fixtures、tests、tools、`pyproject.toml`、README、E 输入包、原始候选/occurrence ledger、隔离回放和 delivery；不再只覆盖 Evidence 局部模块。

## 2. Archive 只读与冻结安全

- live `reference/archive`：230 个文件、18,317,236 bytes。
- live tree SHA-256：`3b6a242a18a013d587e18759f7f35d4b5e65da00b05e8744ff9b785aa26fb0a9`。
- Manifest 内逐文件记录与 live 文件复核 mismatch：0。
- `--verify` 每次都重新读取 live Archive 并重算树事实，不能只相信历史缓存。
- replay/delivery 的 `*-wal`、`*-shm` 数量均为 0；冻结器对任何非空 SQLite sidecar fail closed，专门测试覆盖 `*.sqlite3-wal` 和 `*.sqlite3-shm`，不再依赖错误的 suffix 判断。

`reference/**` 与 `D:\quant\industry_demo/**` 未被此分支修改。

## 3. 引用 locator 修复与守恒

5,181 条 ledger entry 全数保留并映射到 4,630 个 citation occurrence：

- 3,983 条 `utf8_bytes` ledger → 3,432 个精确 occurrence，551 条是同一精确字节 occurrence 的合法共享引用；
- 763 条 `source_locator_claim` → 763 个 path-scoped occurrence；
- 435 条 PDF page/line locator → 435 个 path-scoped occurrence；
- `3,432 + 763 + 435 = 4,630`；ledger orphan=0，occurrence orphan=0。

只有 claimed line 上**唯一**逐字命中的 marker 才能升级为 UTF-8 byte span。原跨行 fallback 已移除：

- wrong claimed-line UTF-8 binding：0；
- claimed line 无逐字命中：657 条，保留 `not_exact_on_claimed_line`；
- claimed line 有多个逐字命中但无 ordinal：106 条，保留 `ambiguous_multiple_exact_on_claimed_line`；
- 已知错误样本 `O000116@line:506`、`O001851@line:224` 均保持 source-only，不再伪造 byte span。

## 4. 论文最低字段与事实边界

- 18 篇 canonical paper 全部有类别；4 个受控大类、23 条 assignment，每篇恰好 1 个 primary category。
- 分类依据是官方 arXiv subject，映射策略为 `arxiv-subject-to-qrh-paper-category/v1`，保留原 subject assertion、mapping policy 与 provenance。
- 18 条核心结论严格等于官方 arXiv 摘要逐字 excerpt，`fact_status=source_claim`、`claim_scope=official_abstract_verbatim`；结论、excerpt 与 provenance mismatch=0。
- 18 篇均有机构解析记录。官方摘要页未提供可安全绑定作者的机构字段，因此状态明确为 `unresolved`、机构数组为空、reason 为 `official_source_does_not_expose_affiliation_metadata`；`organization=0`、`person_affiliation_assertion=0`，没有臆造机构。
- 列表、详情与 HTML 显式显示分类证据、核心结论事实等级、机构 unresolved 原因与 provenance。

## 5. 全文读取、失败恢复与结论绑定

- `pymupdf>=1.27,<2` 已成为显式依赖；本次复核版本为 `1.27.2.2`。
- 18 份 PDF 的每一页都通过 PyMuPDF 重读，验证逐页字符数/hash、全文 hash、标题前三页覆盖率、官方摘要全文覆盖率和结论标题定位。
- Bulk import/replay 会直接重算以上结果，不能仅相信 frozen JSON 的自校验 hash。
- 18 个 task、19 个 append-only run：18 个成功 run，加 1 个明确标注为 `controlled_recovery_probe` 的失败 attempt；P007/arXiv `2002.08709` 的序列为 `1:failed → 2:succeeded`。
- 18 个成功 run 均与 task `input_snapshot_hash` 精确一致，并有 18 条 `paper_reading_conclusion_binding`；pending task=0、input mismatch=0、paper/conclusion mismatch=0。
- 可发布核心结论仍只采用官方摘要逐字 source claim。确定性全文抽取不被伪称为人工全文结论审核，`model_inference=none`、`human_fulltext_review=not_completed`。

## 6. 一候选一行 TXT

正式候选清单位于：

`quant_hub/var/delivery/evidence/c-gate-20260715-v4-final/research_papers/exports/research-paper-candidates-b1d744c7dc1200da6bedae6ecc4be188416d9b19fac094dc3b33f7bdb4093740.txt`

终验事实：248 个物理行（2 行契约说明 + 1 行 header + 245 个候选数据行）、245 个唯一 candidate ID、每个数据行 21 列、malformed row=0。每行包含研究集合、全部 source locator、身份状态/原因、获取状态/原因、fetch attempts、paper/resource ID、本地资源直达链接、读取状态/原因和 run IDs。18 行为 `acquired_verified`，18 行为 `reading_status=succeeded`；未确认、未获取或不可适用项均有明确状态和原因。

## 7. Replay、delivery 与发布权威

Fresh replay 不再只回放 Evidence 数据库；它还真实创建 platform authority DB、PASS decision/snapshot、Evidence certificate receipt 与 active release，并二次 publish 验证幂等。

Replay 活动发布：

- Evidence release：`erel_45ba60b705e80109366aeed33ac28f0f`
- Platform snapshot：`qrh:release_snapshot:rsnp_c073f131b55b44a0bc1d31bc1073f5c9`
- Activation：`eact_3953df8829adde7f67a744857c7cc3c7`，revision 1

Delivery 活动发布：

- Evidence release：`erel_45ba60b705e80109366aeed33ac28f0f`
- Platform snapshot：`qrh:release_snapshot:rsnp_90d4f8a4778f42919ae11bf0d8b26882`
- Activation：`eact_dea5c8635dbaece5e3865a8e0dcba186`，revision 1
- Source snapshot：`b1d744c7dc1200da6bedae6ecc4be188416d9b19fac094dc3b33f7bdb4093740`
- Artifact manifest：`d7935f4dfd43784fc0135de28b130873689ca3f0815b1901b9d2e3cfacfdf025`
- Requirements manifest：`f87e9a53d6a5a8f5a324bb2d283c8d3b504d61e56ff32b3583617b4743dc1bd9`

Replay 与 delivery 的 Evidence/Platform `integrity_check=ok`、foreign-key violations=0。Platform snapshot 与 Evidence certificate receipt 的 candidate、decision、decision hash、domain、subject/version、artifact/source/requirements hash 和 projection revision 全字段相等。

## 8. 验证结果

- `test_evidence*.py`：29/29 PASS。
- `test_incremental_intake` + `test_incremental_intake_evidence_projection`：18/18 PASS。
- Fulltext builder `--verify`：18/18 PASS，结果 SHA 不变。
- Current-code full replay：PASS；第二次 import 与第二次 publish 均保持幂等。
- Delivery 重放：`import_created=false`、`release_created=false`，release/snapshot/activation/revision 不变。
- 最终 manifest 生成与 `--verify` 均输出同一 SHA：`c0bbeedf5b66e2265104c814b7880a85e5a2ac2b9596440309e1902adda96c43`。

精确审核命令见同目录 `C_GATE_REVIEW.md`。
