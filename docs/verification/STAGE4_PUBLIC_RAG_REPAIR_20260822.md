# Stage 4 公共 RAG 质量修复记录（2026-08-22）

## 范围与隔离

本轮只读取公开代码、合同、`reference/archive` 只读来源和新建的公开开发夹具
`quant_hub/tests/fixtures/public_knowledge_quality`。没有读取、列举或搜索任何
sealed holdout、私有 qrels 或 `stage_evidence/stage4_holdout_v*`，也没有改动
`reference`、受保护 semantic authority、VM 或发布状态。

公开开发集不是 release qualification 证据；它只用于复现一般性机制、回归和
性能对照。

## 一般性根因

1. 确定性 chunk 能命中正向 source locator，但结构化 knowledge summary 可能以
   另一种语言改写同一事实。原排序只检索 summary，导致 exact positive 已召回、
   但覆盖该 positive 的正式 `method/condition/limitation/failure` 卡缺席。
2. `IC/Rank IC/MSE/PCA/LSTM` 的旧 alias 是单向展开；英文长名或公式别名查询不能
   对称召回中文/缩写证据。`factor exposure` 还与 `style exposure` 混在一个组，
   会削弱语义边界。
3. 每次查询为每条记录重复解析 document anchor、重建关系/限制映射并对不可能
   通过 coverage gate 的记录计算 BM25；构建期又为每条记录重复规范化同一组
   alias。该开销随知识库增长线性放大。
4. 首版 source bridge 仍把“查询命中 containing chunk”误当成“查询命中该
   knowledge 的 exact evidence”。一个 chunk 含多个 span 时，相邻 span 的词面可
   错误提升另一 locator 的正式知识种类；该问题由公开 adversarial 复现，并由
   DeepSeek V4 Pro 0813 Round 1 独立判为 medium。

## 接受的最小机制

- 将受控中英术语改成对称闭集；不使用开放同义词推断，不引入 vector。
- 只有查询显式表达 knowledge kind，且确定性 chunk 已通过 lexical、context、
  conflict、history、contrast 与 no-answer 全部门禁时，才允许通过同一
  `document_version_id + span_id + 包含 byte range` 将正式 knowledge 卡加入结果；
  查询还必须命中该 knowledge 自己的 canonical primary exact-evidence quote 的
  确定性封闭双语词面，命中同一 chunk 的其他 span 不算。
  路由理由为 `route:exact-source-evidence-kind:<chunk_id>`。它不能独立制造答案，
  也不能绕过适用条件或禁用来源。
- Artifact v3 携带 `source_evidence_texts`，并与 canonical
  `source_locators[*].quote_sha256` 逐项复算闭合；direct index 与 artifact index
  对相邻 span 负例和 exact span 正例保持一致。
- FTS 只作为可证明无损的候选路由：不在 FTS、document identity、exact identity
  或短词 fallback 中的记录，其 lexical coverage 必为零，因此跳过 BM25 不改变
  接受集合。
- 预计算 document/record anchor、relation lookup、limitation/failure 投影和
  source-span bridge；alias matcher 与展开 term 只规范化一次。
- `INDEX_VERSION` 提升为
  `qrh-structured-lexical-index/v1.12-evidence-span-bound-bilingual`，retrieval
  artifact schema 提升为 `qrh-lexical-retrieval-records/v3`；旧 artifact 按既有
  closed schema 自动 fail closed，必须由同一 snapshot 重新构建。

## 公开开发集结果

最终 fixture 共 13 个 development qrels，覆盖因子、模型、数据、回测，以及
cross-language、formula alias、exact kind、no-answer、context conflict、显式拒绝、
非空 forbidden document、previous→superseded history 和 citation。

| 指标 | HEAD 基线 | v1.12 候选 |
|---|---:|---:|
| Recall@8 | 0.875 | 1.000 |
| nDCG@8 | 0.8125 | 0.953866 |
| MRR | 0.791667 | 0.9375 |
| no-answer accuracy | 1.000 | 1.000 |
| citation accuracy | 0.923077 | 1.000 |
| knowledge kind errors | 5 | 0 |
| conflict / forbidden / deprecated errors | 0 / 0 / 0 | 0 / 0 / 0 |
| citation errors | 1 | 0 |
| gate | FAIL | PASS |

同一候选的 legacy whole-query LIKE 对照为 Recall=0、kind errors=8、citation
errors=4，不具备替代价值。直接 index 与 release artifact index 的质量字段逐项一致。

## 只读规模性能对照

以下性能数值是在 v1.11、同一开发机、同一 `reference/archive` 编译结果（44 个
文档、8,295 个可检索 records）上，以 13 个全新公开问题预热一次后重复三轮所得。
v1.12 没有借修复之名重跑并挑选性能结果；它只新增 evidence-span 闭包和查询交集
门禁，最终发布前仍需在冻结 artifact 上统一重测：

| 指标 | HEAD 基线 | v1.11 实测 |
|---|---:|---:|
| index build latency | 26,714.4 ms | 10,012.3 ms |
| query mean | 436.2 ms | 86.7 ms |
| query P95 | 950.8 ms | 222.1 ms |
| query max | 958.5 ms | 229.5 ms |
| traced build current memory | 69,238,786 bytes | 81,477,726 bytes |
| traced build peak memory | 71,164,785 bytes | 84,782,430 bytes |
| SQLite FTS footprint | 13,594,624 bytes | 13,586,432 bytes |

这些时间是本机诊断证据而非跨机器硬编码阈值。质量门禁没有为性能放宽。
预计算 anchor/identity/source bridge 在 8,295 records 上增加约 12.2 MiB 常驻
Python traced memory（约 1.5 KiB/record），换取 P95 约 76.6% 的下降；FTS footprint
没有增长。该增量是随 immutable record 数量线性、有实测上界的只读缓存。

## 明确拒绝的方案

- 不加入 vector、reranker、HTTP MCP 或新服务治理：当前受控 lexical/structured
  机制已有可测增益，新增维护成本没有公开证据支持。
- 不缓存并跳过每次 mirror artifact 完整性验证：这会削弱现有“镜像被篡改不得
  返回 fresh”的硬门禁。保留服务内已验证 FTS index 的 identity cache，只优化
  排序热路径和确定性构建。
- 不按 sealed 聚合结果猜测逐题文本、alias 或阈值；本轮没有针对 holdout 调参。
- 不扩大 minimum score/coverage，不让 kind bonus、context 或 relation 绕过
  no-answer、conflict、forbidden 和 citation 合同。

## 验证

- 公共开发夹具：4 tests PASS；其中两个 qrel 绑定非空
  `forbidden_document_ids`，一个文档含 current/superseded 两个真实版本。
- default 检索不返回 superseded card；`include_history=true` 才返回并明确标记
  `active_status=superseded`。
- knowledge compiler/semantic/retrieval/MCP/release 定向回归：108 tests +
  16 subtests PASS。
- 81 份公开/只读文本的优化 alias matcher 与直观慢路径逐项 `Counter` 等价，
  失败数 0。
- v1.12 相邻 span adversarial：旧逻辑可错误提升 limitation 卡，修订后不再提升；
  exact-evidence 正例仍提升，artifact evidence text 篡改 fail closed。
- DeepSeek V4 Pro 0813 check-revise：Round 1 `REVISE`（上述相邻 span finding）；
  Round 2 `PASS`，无新增 blocker/high/medium。模型身份、fingerprint、prompt/response
  hash 留存在 Git 外审核记录中。
- `py_compile` 与 `git diff --check` 通过。

新的独立 sealed holdout 必须由未见本开发集和旧 sealed 文本的 verifier 一次性运行；
本记录不能替代该门禁。
