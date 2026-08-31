# Stage 4/5 公开评测门禁运行手册

## 权威入口

检索评测的权威入口是 `quant_hub.knowledge.evaluation.evaluate`。它会先对完整
`QrelSuite` 强制执行 `suite.validate(base)`；验证失败时抛出
`QrelSuiteValidationError`，异常内的 `receipt` 是 canonical rejection receipt，不能改用
局部 qrel 重跑来绕过失败。验证通过时，报告标记为 `AUTHORITATIVE_EVALUATOR`，并携带：

- canonical suite-validation receipt；
- 按 qrel 排序的 canonical per-qrel receipts；
- suite canonical byte length/SHA-256/content hash；
- evaluator version、`limit`、snapshot、index version、artifact projection hash 和 producer；
- 每张展示卡的 locator、displayed byte length/SHA-256，以及可重算指标所需的公开投影。

`evaluate_non_authoritative` 只用于局部公开 fixture 和单元诊断。它明确返回
`NON_AUTHORITATIVE_DIAGNOSTIC`，不生成 per-qrel receipts，不能进入 candidate/baseline
comparison 或 release qualification。

## 运行前比较注册

比较必须在两侧运行前调用：

```python
preregistration = build_retrieval_comparison_preregistration(
    suite=suite,
    split="development",
    candidate_index=candidate_index,
    baseline_index=like_baseline_index,
    limit=8,
    difficult_slices=("hard_negative", "condition_conflict", "cross_language"),
    run_id="new-independent-run",
    ledger_path=preregistration_ledger,
)
```

注册 bytes 同时冻结 suite bytes/hash、evaluator、limit，以及 candidate/baseline 各自的
artifact/snapshot/index/projection producer。比较入口只接受 evaluator 生成的 canonical
per-qrel receipt bytes：

```python
candidate = evaluate(
    candidate_index, suite, split="development", limit=8,
    comparison_preregistration=preregistration,
    preregistration_ledger=preregistration_ledger,
    comparison_role="candidate",
)
baseline = evaluate(
    like_baseline_index, suite, split="development", limit=8,
    comparison_preregistration=preregistration,
    preregistration_ledger=preregistration_ledger,
    comparison_role="baseline",
)
comparison = compare_candidate_to_baseline(
    candidate.per_qrel_receipts,
    baseline.per_qrel_receipts,
    preregistration=preregistration,
    preregistration_ledger=preregistration_ledger,
    suite=suite,
    candidate_index=candidate_index,
    baseline_index=like_baseline_index,
)
```

传入 aggregate `EvaluationReport`、非 canonical bytes、不同 suite/limit/snapshot/artifact/
producer 的 receipts，或篡改后无法从 card projection 重算的 metrics，全部 fail closed。
ledger 使用 exclusive create，不允许覆盖既有 run。receipt 携带 exact query/displayed UTF-8
bytes；comparison 会用调用方提供的真实 suite/base 与两侧 live projection 重新执行每个 query，
逐项比较完整 split membership、suite-validation receipt、projection artifact、展示 card bytes、
locator、stale/error 和 metrics。canonical JSON、自报 hash 或 producer 字符串本身不构成发行证明。
Round3 使用 `qrh-retrieval-comparison-preregistration/v4-authoritative-like-stale-replay`
与 `qrh-retrieval-per-qrel-receipt/v2-live-stale-replay`；verifier 还会从 supplied live suite/base
重新计算每个 qrel 的 stale 状态，并与 receipt 的 `errors.stale` 双向精确比较，true/false 任一方向
不一致都拒绝。

## 精确 credit 与 LIKE 基线

positive/negative relevance credit 同时要求：document version、span、source SHA、byte start/end
完全一致，而且用户实际看到的 `card.text` UTF-8 bytes 必须与 qrel quote 的长度、内容和 SHA-256
完全一致。`covered_span_ids`、更宽 chunk、同 span containment、邻接上下文或只伪造 locator
均不能得分。

`LikeBaselineIndex` 先按 Archive SQLite 的 document projection 执行 `%whole query%` 和
document-level `LIMIT`。它冻结真实 ordered projection rows、presentation title、hidden/exclusion
配置和 snippet 合同为 canonical producer artifact，并返回与 `ArchiveCatalog.search` 相同的
presented title/snippet bytes；title-only 命中同样从公开 search text 的起点产生 snippet。不得把
一个文档的多个匹配 chunk 展开后再做 chunk-level LIMIT，也不得以任意 raw chunk 代替实际展示
snippet。

生产资格比较无条件要求 exact `type(LikeBaselineIndex)` 且必须来自
`LikeBaselineIndex.from_archive_catalog(...)`。该入口以只读 SQLite URI 导出真实
`document_search_projection`，在导出前后及最终 compare 时核对 live database/WAL bundle，冻结并
闭合验证 exact producer extension、ordered rows、document/page identity、presentation 变换和
source receipt。plain `KnowledgeIndex`、直接构造的 `CALLER_SUPPLIED_DIAGNOSTIC`、Like 子类或仅
伪报 `ARCHIVE_CATALOG_READ_ONLY_EXPORT` 字符串的 index，全部令
`projection_authority_pass=false`，不得取得最终 comparison PASS。

Round4 把 Archive authority 验证扩展为覆盖整个 compare 的双端窗口：第一次验证在任何 live
per-qrel replay 前冻结 database/WAL bundle、producer extension 和 source receipt exact bytes；
candidate 与 baseline 的所有 query replay、receipt 一致性检查和指标重算完成后，在构造 verdict
的最后一点再次运行同一 verifier。只有前后两次均为 authoritative 且三份 identity bytes 完全
一致时 `projection_authority_pass=true`；compare 前变化、baseline search/replay 窗口内变化、
后验变化均只能得到 gate FAIL。这里不把普通 SQLite read transaction 冒充全局 writer lock：WAL
模式下只读 snapshot 不阻止并发写，且 baseline 使用冻结的内存 projection；因此采用前后 live
bundle 检测，不修改、不 checkpoint、也不锁写 Archive 原库。

Round5 同时闭合每一次 exact verifier 自身的内部窗口：verifier 入口先复算 live database/WAL
bundle，完成 artifact、source receipt、presentation、ordered rows 与 document/page identity 的
全部检查后，在返回前的最后一点再次复算。只有 verifier 入口、verifier 末端与 source receipt
三者完全一致，该次验证才成功；入口 hash 返回后、verifier 返回前发生的变化也会 fail closed。
compare 的 Round4 前后双端验证继续保留，因此内部与外部两个时间窗口均须满足一致性合同。

## MCP fake 与真实 Codex 验收回放

公开测试先调用 `record_acceptance_preregistration` 原子登记 v2-bound prereg，再用
`run_fake_acceptance_arm` 写入不可覆盖的 dispatch intent，执行纯内存 fake transport，最后写入
trace-bound completion。runner 固定标记 `FAKE_ONLY_REAL_CODEX_DISABLED`；它不能启动真实 Codex、
网络或 secret。该路径只验证公开门禁，authority 固定降为
`PUBLIC_SYNTHETIC_NON_QUALIFYING_GATE`。

真实执行与功能回放使用 `qrh-mcp-acceptance preregister/run/verify`。preregister 在运行前以
create-only staging directory 固化 preregistration ledger、逐 case prompt 和
`qrh-mcp-real-codex-launch/v2-process-provenance` launch config，复验 closed inventory 后才
write-through 提交。launch config 同时冻结：OpenAI Authenticode 为 `Valid` 的原生
`codex.exe`；目标 MCP 的完整 STDIO command/args/cwd/env/env_vars/enabled/required/tools/timeouts；
native MCP launcher、实际 Python、client config、`quant_hub` package 与 distribution 的完整
散列 inventory；以及 `execution_scope/evidence_parent`。生产证据父目录只允许位于
`D:\quant\quant_platform\audit` 内，新 evidence root 必须不存在且不得含 reparse component。

run 固定使用 `shell=False` 和
`--ignore-user-config --ignore-rules --strict-config --ephemeral --json`。两臂完整 argv 只能在
目标 `enabled=true/false` 上不同，`required=true` 始终保留；同一 signed Codex 的 app-server
`config/read(includeLayers=true,cwd=...)` 会重放真实配置栈，只忽略 user layer，任何 active
packaged/system/enterprise/project/legacy-managed layer 提供 MCP/app/plugin 时直接拒绝，并冻结
层 version/config hash。Windows runner 在 campaign 全程持有所有
冻结 runtime 文件的 no-share-write/delete handle，每臂前/中/后重算闭包，查询真实 Codex
process image；assisted 必须观测目标 native launcher 与 Python 子进程，no-MCP 两者均不得出现。
stdout/stderr 均为硬上限流式读取；超限、顶层 `error`、非 MCP command/file/web 污染、进程或
文件身份漂移全部 fail closed。失败只写 non-qualifying `campaign-failure.json`。verify 对 exact
inventory、intent/raw JSONL/completion 和 v3 receipt 全量重放；fake/real 混用也属于
non-qualifying。即使两臂全为 `REAL_CODEX_EXEC`、provenance 重放与完整 gate 都 PASS，磁盘
authority 仍固定为 `REAL_CODEX_EVIDENCE_REPLAY_NON_AUTHORITATIVE`。`verify` 只验证该功能回放，
不能为 Stage 5 签发权威资格。

raw trace 使用独立 `agent_message_seen`/count 状态，不再用 final text 的真值充当状态机。
每条 trace 必须恰有一条非空 completed agent message；该消息完成时不能还有其他 open item，
完成后除 turn terminal 外不得再出现任何 item。空白消息、第二条消息或消息后的 reasoning/tool
item 均 fail closed。

最终 `evaluate_preregistered_acceptance` 与 `validate_acceptance_campaign_receipt_bytes` 都必须消费
prereg ledger、exact config、逐 case exact prompt、两臂 raw JSONL 和 dispatch ledger。validator
重新运行完整 gate 后要求 receipt byte-for-byte 相等；v3 dispatch-replay receipt 冻结逐 case
trace status、runner、三维 score/gain 与 findings。assisted final response 必须是 closed
canonical JSON，decision、conditions、limitations 每项 claim 都绑定 get 返回的完整
`object_id/document_version_id/source_sha256/span_id/byte_start/byte_end/citation_id` tuple；跨 locator
拼接和自由文本 token/marker 堆叠均不得通过。公开 fake PASS 与全新真实 campaign receipt 都不是
5.13/5.14 的权威资格证据；当前还缺独立可信执行 attestation/countersignature，必须闭合运行身份、
隔离运行时、完整进程树与证据时序后，才能新增可供 Stage 5 接受的权威 producer。

## 资格边界

这轮公开 fixture 只证明门禁机制和失败路径。启用 displayed-byte exact credit 后，历史
aggregate-only / V39 qualification 不能自动沿用；当前 candidate 必须用同一份新预注册和新的
per-qrel receipts 重新取得增益。公开测试出现 `comparison.gate_pass=False` 是预期的安全重开，
不是可回填为 PASS 的历史证据。

禁止把本手册作为读取 sealed/private qrels、连接 VM、运行真实 Codex 或外部网络的授权。
