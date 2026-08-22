# Stage 4 Evidence citation sidecar 投影设计与公开验证记录（2026-08-22）

## 状态与范围

本文记录 Knowledge/RAG/MCP citation sidecar 的公开实现候选及验证证据。它不是 sealed holdout 放行记录，也不代表 OpenSpec 5.9 或 5.10 已通过。

本轮只修改可写项目区。`reference/archive` 原始 Markdown、Evidence SQLite、semantic authority、V39 runtime base 均只读；未修改 VM、reference 或其他 protected authority，也未读取、枚举或输出任何 sealed/holdout/private qrel、trace、正文或 locator。

## 断链根因

Archive 的当前 63 份原始 Markdown 没有原生 `^src`，而 KnowledgeIndex 与 MCP search artifact 过去只读取 raw IR。因此 Evidence 数据库中已经核验的 citation occurrence、paper binding 与 reviewed overlay 没有进入 chunk、formal knowledge binding 或 retrieval record；citation 指标可以因没有实际正向 card 而呈现空值式通过。

修复采用独立 sidecar projection，不改写 Archive 正文，也不把 Evidence 数据迁入 Knowledge authority。

## Authority 与确定性边界

- Evidence DB 仅通过 SQLite `mode=ro&immutable=1` 与 `query_only` 读取；投影前后检查文件 size、mtime、SHA-256，并拒绝已有或新生的 WAL、SHM 或 rollback journal。
- 对参与授权的 occurrence、ledger、binding、binding event、current projection 与 migration ledger，闭合 declared type、NOT NULL、PK、STRICT 与 FK 的 table/column/`ON UPDATE`/`ON DELETE`/`MATCH` identity，并运行 `integrity_check` 与 `foreign_key_check`。此外，用同一份 staged migration authority 在 SQLite `:memory:` 中重建 canonical schema，对 authority 的全部非内部 `sqlite_schema`（table、index、constraint 与 trigger SQL）逐项精确比较；migration ledger 不能单独替代实际 schema 身份。
- 只接受 canonical citation ID、active source SHA、`locator_status=valid`、current resolved binding、同一 ledger/binding/event identity、精确 UTF-8 byte range、marker text/hash、context hash与原始 source bytes 机械一致的 occurrence。`source-only`、`unresolved`、`conflicted`、inactive source 均不能授予 citation authority。
- reviewed overlay 继续由 `CitationOverlayRegistry` 统一验证；物理 Archive 输入复用 `ReadOnlyArchiveSource` 的 canonical POSIX relative path、resolve-containment 与稳定只读边界，拒绝反斜杠、drive、UNC、traversal 与重复 document SHA/path。manifest、document、entry、paper、external link 均使用逐字段 exact JSON type 的 closed schema，且 marker 必须精确命中 active source bytes。
- production freezer 不从开发机 package-local ignored JSON 读取。它只保留并消费 staging 内 sealed runtime base 的 `runtime_contract/code/src/quant_hub/presentation/citation_projection_overrides.json`，同时显式使用 staging 内 Evidence DB 与 `runtime_contract/migrations/research_papers`。
- projection membership 单向绑定 base snapshot、active source membership、Evidence DB SHA、migration authority SHA、reviewed overlay SHA、最终 non-overlap occurrence 集合及 reject count。search artifact SHA 再进入 immutable release manifest。

## 归属规则与 artifact 兼容

Web 与 Search 共用确定性的 shortest-valid non-overlap 选择规则，避免重叠 citation 同时借权。

formal binding 在归属前必须逐个验证：binding byte range 位于自身 compiled IR block，UTF-8 对齐，source slice 等于 quote，且 quote SHA-256 一致。citation marker 必须处在同一 IR block，并且满足以下之一：

1. marker 完全位于 binding byte range；
2. marker 位于 binding 之后不超过 24 UTF-8 bytes，间隔只含空白或标点。

不会把包含 binding 的宽泛 citation、partial overlap、相邻 claim 或其他 binding 的 citation 合并到当前 locator。每个 locator 在 v3 artifact 中携带最小 `citation_attributions` proof：relation、anchor byte end、最多 24 bytes 的 gap text 及其 SHA-256；contained proof 不携带正文，adjacent proof 只携带必须重演 punctuation-only 判定的短 gap。

v3 artifact 另携带只覆盖 citation 相关 IR block 的 `citation_source_material`。每项材料闭合 version、source SHA、span kind、canonical JSON-safe attributes、byte range、精确 source text 及其 SHA-256；validator 使用 `ir.py` 同一 `content_hash("qrh-source-span/v1", ...)` 规则重算已有 `span_id`，并要求材料 span 至少被 canonical chunk ordered spans、knowledge locator 或 native containing-span 实际引用，拒绝孤立替换。随后从这份 source-derived material 重演实际 anchor→marker bytes，而不是相信 proof 自报的同长度 gap。该 source text 只用于 artifact 内部验真，不进入 MCP 响应；MCP v3 search/get 仅透传 locator proof 与材料 identity/hash，其中 attributes 只暴露 canonical hash 而不暴露可能包含正文的值，且 search/get 两端逐项一致。chunk 同时闭合 presentation text 的类型、hash、UTF-8 长度上界与 ordered span identity。原生 IR `^src` 与有效 sidecar citation 做机械 union；native marker text 必须精确等于 `^src:{citation_id}`，配置 sidecar 不会删除未来新增研究的原生 citation。

有 sidecar 时生成 `qrh-mcp-search-artifact/v3`，要求 `citation_projection` 为非空 closed object，闭合 projection、citation rows、native citation references、source material 与 attribution proofs，并验证 chunk、per-binding `source_citations`、formal union、retrieval 与 direct index 的一致性。无 sidecar 的普通 fixture 继续生成 v2；现有 v1/v2 loader 与 MCP 响应升级路径保持兼容，v1/v2 search/get 不新增 v3 proof 或材料 identity 字段。

## 公开回归与失败路径

公开 fixture 覆盖：active/inactive、resolved/source-only/unresolved/conflicted、错误 source SHA、marker hash/range、overlap、multi-binding、伪造 secondary binding offset/hash、native+sidecar union、长 SourceSpan 多 child chunk 的 byte-range attribution、direct/artifact parity、MCP search→get locator 级 proof parity 与不外溢、DB/source/overlay/migration tamper、只读无 WAL/SHM/rollback journal、release builder、publish runtime、v1/v2 字段兼容以及 Public wheel 无私有 overlay 时的隔离导入。长 block 中只有实际覆盖 native marker byte range 的 child 携带该 citation；共享父 span ID 不再让 citation 外溢到其他 child。

已验证的 fail-closed 路径包括：缺失或非法 staged overlay；Windows backslash/drive/UNC path；重复 document SHA/path；把 line、source candidate、relation summary 或 paper title 伪装成错误 JSON scalar/object 类型；篡改 migration authority；伪造 join authority 列类型、FK target/`ON UPDATE`、CHECK 或 trigger；v3 null projection；native marker 与 citation ID 不一致；把 adjacent punctuation gap 改成同长度 author text 并重算 SHA；以及在真实 gap 为 author text 时伪造同 byte length 标点，同步篡改 `citation_source_material.source_text` 与其 hash，并重算 proof、knowledge、retrieval 与 canonical membership 全部内嵌 hash；后者因既有 SourceSpan identity 无法复现而拒绝。binding quote/offset/hash 不一致与 Evidence/source identity 变化同样 fail closed。

冻结前公开定向与关联回归共 99 项通过：citation projection CI-listed 模块 13 项；overlay、MCP、retrieval 组合 52 项；knowledge release/publish runtime 17 项；release builder 3 项；Archive citation/rendering/Web 14 项。另额外运行 generic renderer 6 项并通过。public git guard 的文档 exact allowlist、单文件 gate、空 staged scope 与 470 文件 tracked scope 均通过。目标模块 `compileall` 与 `git diff --check` 在最终冻结前再次执行。

## 真实只读 aggregate build

使用当前 44 个 active Archive 文档、V39 sealed Evidence DB、V39 sealed reviewed overlay 与 migrations、当前只读 semantic authority 完成 aggregate product build。仅记录聚合计数：

- 最终 resolved-only projection：106 条；
- 其中 Evidence resolved：75 条，reviewed overlay：31 条；
- non-overlap reject：42 条；
- 覆盖 active 文档：24 个；
- 有 citation 的 formal binding / formal item：15 / 15；
- 有 citation 的 chunk：71 个；
- 有 citation 的 retrieval record：85 个；
- citation source-material block：149 个；
- direct index 与 artifact citation membership 完全一致。

Archive compile 状态为 `PARTIAL` 且 `activation_allowed=true`：44 个主体文档进入 active membership，supporting/quarantine 仍按既有公开编译政策隔离，不通过 citation projection 放宽。semantic promotion identity 精确匹配只读 authority。

本轮 aggregate 的 projection membership SHA-256 为 `2b30a930061ed1a8640caad98883c1f96e0bff6b1e7666ad46a5e0587e1bd0ce`，v3 search artifact SHA-256 为 `20d71ca5a45ec9625aababfb1569b5b136973317e6d959b9fee1657934015aae`。149 项 source material 的 `span_id` 均由 sealed aggregate 中的 kind、attributes、byte range 与 text hash 机械复现。

构建前后 Archive tree、Evidence DB、semantic DB、sealed overlay、sealed migrations 的 SHA-256 均逐项相同：

- Archive tree：`13d0d51f0561de07d79bedd94ca4e8d5beb0dc3b793380b6a327dfb7eaf4b026`；
- Evidence DB：`c190335d1cf765b1fb389ae6fa4905047e0c72fac79946db013d459236aabc01`；
- semantic DB：`b52810792d2f8542a393f73ac16c4203be706a8842534d95333e25ab7034ee54`；
- sealed reviewed overlay：`4daeef640b898662ce5088c62520bf79827222adbc02f4c48b4507d2b354c068`；
- sealed migrations tree：`39acfe75728d3de90944b8e7411843b94d755fc3b101981f61a3f8465076baa4`。

Evidence 与 semantic SQLite 在构建前后均无 WAL、SHM 或 rollback journal 文件。

## 尚未执行

- 未启动新的 sealed holdout、private qrel 或 trace 评测；
- 未勾选或宣称 OpenSpec 5.9 / 5.10 通过；
- 未 commit，等待主线冻结审查后再决定后续放行步骤。
