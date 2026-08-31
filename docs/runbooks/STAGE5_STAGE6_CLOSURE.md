# Stage 5 / Stage 6 exact-D 生产 active/prior 与 visibility 闭合合同

本文定义发布放行顺序，不表示生产 VM、Windows 服务、writer handoff 或 GitHub visibility
已经执行。任何现场证据缺失时，对应阶段保持未完成；本地单元测试不能替代现场证据。

## 能力边界

- 唯一生产项目写入根是 `D:\quant\quant_platform`。
- 稳态只保留当前 active release 与一个真实 prior release；两者使用同一份当前 D state。
- 普通回退只交换 active/prior 版本角色，不替换 SQLite、不恢复历史状态、不执行 schema
  down-migration。
- 生产连续性边界就是精确 D 根内的 active、恰一 prior 与二者共用的当前 state。
- Stage 5 只证明 exact D 根和当前 state 完整时的最近一代版本回退；不声明 VM、D 根、
  对象库或 state 整体丢失后的恢复能力。

## 唯一执行顺序

1. 在仓库仍为 Public 时冻结 exact commit SHA、tracked tree、release manifest、snapshot 和
   clean-wheel inventory；工作树不洁、身份不一致或产品包仍暴露已撤销入口时停止。
2. 完成 Stage 0–4 的数据、内容、评论、检索、MCP、浏览器/API、state compatibility、
   write-set 和失败路径门禁。
3. 验证本地部署控制器的锁、canonical CAS、durable journal、严格阶段机、SCM/endpoint/
   writer/state 实测探针、崩溃重放、Windows 路径边界和失败收敛。journal revision 0 必须是
   durable intent；成功 terminal receipt 前不得授权清理。
4. 首次 handoff 在外部流量和写入 fence 内取得最终 D state。旧 C writer 仍是 authority
   时只允许隔离验证，且 C 盘始终只读；状态最终复制完成后停止旧 C writer。
5. D active/binding 初始均不存在时，以 `bootstrap_first_pair` journal 执行
   `active: absent→R0`。其 activation-family receipt 是唯一允许 `prior=null` 的成功形状，
   必须绑定原 pointer/binding absent、ingress closed、旧 C writer fenced、最终 D state、
   R0 live identity 和 writer fence；它不授权 ingress 或稳态完成。
6. 以普通激活协议切换 `R0→R1`。R1 必须与 R0 具有真实不同的受密封代码/内容/资源身份，
   不得复制 R0 或只改 ID、时间、工具/provenance 来制造 successor。
7. 只有 R1 启动、post-activation 检查、当前 state 读写/CAS、唯一 writer、active pointer、
   `local_prior_binding(R1,R0)` 和 activation receipt 全部通过，才开放 D 流量。此后 C writer
   永久退出 authority。
8. 演练一次 `R1 active + R0 prior → R0 active + R1 prior`，始终使用同一当前 D state；
   再按需要以相同协议切回。任一版本无法安全使用当前 schema 时回退失败并保持原 active。
9. 成功 terminal receipt 完整验证后，才按 journal 中 exact typed target 清理更早 release、
   completed incoming/partial 和不再被 active/prior closure 引用的对象。终态必须只有两棵
   release；清理失败阻止下一次 publish，但不得反向伪造切换结果。
10. Stage 5 certificate 重放全部分类 verifier 并通过后，才执行 Public→Private；随后重读
    Private plan/actions/branch/environment/publish controls，运行 exact-SHA Private CI 和
    candidate-only no-switch 验证，最后形成 visibility closure receipt。

## Release 与 receipt 图

- immutable release manifest 只密封代码、内容、资源、索引、知识和 state compatibility。
- `active_release` 只指向当前 active release。
- `local_prior_binding` 在稳态只指向 active 与恰一 prior。
- activation/rollback receipt 只绑定结果 pair 与验证结果；failure receipt 显式绑定 operation、
  原 pair、target candidate、terminal 前最后一个合法 non-terminal 失败阶段和已验证恢复结果；
  activation target 必须与原 pair 不同，rollback target 必须恰为原 prior，bootstrap 必须从空
  D pair 开始；cleanup receipt 只绑定保留 pair、精确移除目标与结果。
- 所有 receipt 都是 append-only evidence，不是 pointer；release manifest 不得反向引用 pointer、
  binding、receipt、attempt、切换时间或其他动态控制信息。
- 每个 attempt 只能有一个 terminal activation/rollback/failure receipt；bootstrap 不能产生
  cleanup receipt，普通成功 attempt 在 cleanup receipt 后才关闭 retention journal。

## Stage 5 certificate 的最低内容

新证书至少绑定：

- Public repository observation、full 40/64 位非零 commit SHA、tracked tree；
- exact active/prior release、manifest、snapshot、binding 与 application/content/resource closure；
- 同一当前 D state identity、schema compatibility 与真实 read/write/CAS 证据；
- Windows root/write-set、SCM、endpoint、writer fence、lock/journal/replay 和 retention 证据；
- 首次 handoff时的 bootstrap receipt、普通 R0→R1 activation receipt 和 ingress gate；
- 本地 rollback receipt、cleanup/retention closure、Web/API/Search/MCP/评论/Dashboard 结果；
- source 与 fresh installed wheel 的撤销面：不存在旧恢复模块、entrypoint、schema、调度任务、
  runbook 引用或 D 根之外项目写路径；
- Stage 0–4 与 Stage 6 前置 gate 的 canonical producer artifact 和分类 verifier 结果。

调用方提供的 `status=pass`、布尔值、自报 hash 或同名 ID 没有权威性。producer/verifier 必须
重读 canonical bytes、复算 hash、核对真实对象和现场身份。任一必需 producer 尚未实现或现场
证据尚未取得时，certificate 必须 fail closed。

## Typed observation 与实际 CLI

`qrh-release-closure` 是唯一证书闭合入口。每个分类 gate 先由对应现场 observer 写入
`qrh-closure-gate-observation/v2-managed-inputs`。observation 本身不再携带可自报的 subject、facts、
observer 或 PASS；它只能索引一个分类 result、四个 exact subject artifact（active pointer、prior
binding、active/prior manifest）和底层 support artifact。closure 使用
`validate_active_release`、`validate_local_prior_binding`、`validate_release_manifest` 从实际 bytes
重建 release/snapshot/state subject，并校验全部路径、schema、canonical bytes、大小、hash、时间和
输入闭包。result wrapper 的 authority/name/command/cwd/exit code、自哈希或 executable hash 只证明
“这个 wrapper 自洽”，不能赋予 PASS authority。

每个角色只有在下表所列真实 producer schema 和 replay adapter 已实现且重读底层 receipt/API
response/指针/manifest/SQLite bundle/测试报告后才可 qualify。当前这些分类 adapter 尚未注册，
因此 `derive-gate` 明确返回 `non-qualifying`，不会写 gate；`certify-stage5`、`close-visibility` 也不能
签发。这是有意的 fail-closed 状态，不得用 dummy artifact、旧 observation 或 managed wrapper
补齐正向测试。

| gate role | 唯一待实现的真实 producer schema | 必须重放的 verifier |
|---|---|---|
| `full_replay_and_comment_lifecycle` | `qrh-stage5-browser-sqlite-comment-replay-receipt/v1` | 浏览器、SQLite、source inventory 与 comment relocation |
| `failure_and_incremental_matrix` | `qrh-stage5-failure-incremental-machine-report/v1` | failure/incremental matrix machine report |
| `web_search_mcp_snapshot_consistency` | `qrh-stage5-web-search-mcp-snapshot-replay-receipt/v1` | snapshot/continuation replay 加真实 MCP campaign |
| `independent_verification` | `qrh-stage5-independent-dispatch-verification-receipt/v1` | 独立 dispatch ledger 与 exact input closure |
| `shared_state_schema_compatibility` | `qrh-stage5-shared-state-compatibility-replay-receipt/v1` | candidate/prior SQLite read/write/CAS/event |
| `active_prior_active_drill` | `qrh-stage5-active-prior-active-vm-drill-receipt/v1` | activation/rollback receipts 与 VM read/write-set |
| `retention_closure` | `qrh-stage5-retention-filesystem-audit-receipt/v1` | active/prior/incoming/object filesystem audit |
| `runbook_drills_and_quality_report` | `qrh-stage5-runbook-drill-quality-receipt/v1` | runbook bytes、drill receipts 与 quality report |
| `revocation_surface` | `qrh-stage5-revocation-machine-audit-receipt/v1` | source/wheel/config/schema/task/write-set audit |
| `identity_graph_negative_fixtures` | `qrh-stage5-identity-graph-fixture-report/v1` | identity graph positive/negative fixture replay |
| `repository_private_observation` | `qrh-stage6-github-repository-api-capture/v1` | authenticated GitHub repository response |
| `private_controls_revalidation` | `qrh-stage6-github-controls-api-capture/v1` | authenticated plan/Actions/protection/permission responses |
| `private_exact_sha_ci` | `qrh-stage6-github-exact-sha-ci-api-capture/v1` | authenticated workflow/check-run exact SHA response |
| `private_candidate_only` | `qrh-stage6-private-candidate-machine-receipt/v1` | candidate receipt 与 zero production switch |
| `production_identity_unchanged` | `qrh-stage6-production-identity-capture/v1` | before/after active/binding/state exact bytes |

`web_search_mcp_snapshot_consistency` 还有额外硬门禁：facts 必须给出 evidence root 内的
`mcp_acceptance_evidence_root`，observation 必须托管其 exact `campaign-receipt.json`。closure 会
调用 `validate_real_acceptance_evidence_root(Path)` 重载 preregistration、config、prompt、两臂
dispatch intent/raw JSONL/completion 并重放 campaign；Stage 5 只接受未来可信 producer 签发的
`AUTHORITATIVE_REAL_CODEX_INTEGRATED_GATE`、`status=PASS` 和受信两臂。当前 verifier 对所有
`REAL_CODEX_EXEC` 磁盘回放固定返回 `REAL_CODEX_EVIDENCE_REPLAY_NON_AUTHORITATIVE`，因此即使功能
PASS 也必被 closure 拒绝。`PUBLIC_SYNTHETIC_NON_QUALIFYING_GATE`、fake/mixed runner、只复制 PASS
字段或 receipt SHA 不符同样都会阻止 Stage 5 certificate。当前还没有可信 attestation producer；在
`qrh-stage5-web-search-mcp-snapshot-replay-receipt/v1` adapter 缺失时，不能单独把整个 snapshot
consistency role 提升为 PASS。

```powershell
qrh-release-closure derive-gate `
  --evidence-root D:\quant\quant_platform\audit\release-closure `
  --observation observations/stage5/retention_closure.json `
  --output gates/stage5/retention_closure.json

qrh-release-closure certify-stage5 `
  --evidence-root D:\quant\quant_platform\audit\release-closure `
  --gate gates/stage5/full_replay_and_comment_lifecycle.json `
  --gate gates/stage5/failure_and_incremental_matrix.json `
  --gate gates/stage5/web_search_mcp_snapshot_consistency.json `
  --gate gates/stage5/independent_verification.json `
  --gate gates/stage5/shared_state_schema_compatibility.json `
  --gate gates/stage5/active_prior_active_drill.json `
  --gate gates/stage5/retention_closure.json `
  --gate gates/stage5/runbook_drills_and_quality_report.json `
  --gate gates/stage5/revocation_surface.json `
  --gate gates/stage5/identity_graph_negative_fixtures.json `
  --output certificates/stage5.json

qrh-release-closure verify-stage5 `
  --evidence-root D:\quant\quant_platform\audit\release-closure `
  --certificate certificates/stage5.json

qrh-release-closure derive-gate `
  --evidence-root D:\quant\quant_platform\audit\release-closure `
  --observation observations/stage6/repository_private_observation.json `
  --output gates/stage6/repository_private_observation.json

qrh-release-closure derive-gate `
  --evidence-root D:\quant\quant_platform\audit\release-closure `
  --observation observations/stage6/private_controls_revalidation.json `
  --output gates/stage6/private_controls_revalidation.json

qrh-release-closure derive-gate `
  --evidence-root D:\quant\quant_platform\audit\release-closure `
  --observation observations/stage6/private_exact_sha_ci.json `
  --output gates/stage6/private_exact_sha_ci.json

qrh-release-closure derive-gate `
  --evidence-root D:\quant\quant_platform\audit\release-closure `
  --observation observations/stage6/private_candidate_only.json `
  --output gates/stage6/private_candidate_only.json

qrh-release-closure derive-gate `
  --evidence-root D:\quant\quant_platform\audit\release-closure `
  --observation observations/stage6/production_identity_unchanged.json `
  --output gates/stage6/production_identity_unchanged.json

qrh-release-closure close-visibility `
  --evidence-root D:\quant\quant_platform\audit\release-closure `
  --stage5-certificate certificates/stage5.json `
  --gate gates/stage6/repository_private_observation.json `
  --gate gates/stage6/private_controls_revalidation.json `
  --gate gates/stage6/private_exact_sha_ci.json `
  --gate gates/stage6/private_candidate_only.json `
  --gate gates/stage6/production_identity_unchanged.json `
  --output receipts/visibility.json

qrh-release-closure verify-visibility `
  --evidence-root D:\quant\quant_platform\audit\release-closure `
  --receipt receipts/visibility.json
```

输出父目录必须预先存在，所有 gate、certificate 与 visibility receipt 都是 create-only canonical
JSON。schema 分别位于 `config/release_closure_gate_observation.schema.json`、
`config/release_closure_gate_evidence.schema.json`、`config/stage5_release_certificate.schema.json`
和 `config/visibility_closure_receipt.schema.json`。这套 CLI 只闭合既有现场证据，不执行浏览器
回放、切换 release、修改 GitHub visibility 或启动/停止 VM 服务。CLI 会机械拒绝 exact
`D:\quant\quant_platform` 之外的 evidence root；示例只有在对应真实 adapter 已实现并取得现场
artifact 后才会成功，当前运行得到 `non-qualifying` 是预期结果。

tracked JSON Schema 已约束 observation 的 role→result schema、gate 的 role→exact assertions，
以及 certificate/visibility evidence 的角色顺序；它们仍只是结构合同，不是 qualifying verifier。
即使一个文档通过 JSON Schema，也必须继续通过 runtime 的 canonical byte、subject、artifact closure
和真实分类 adapter 重放，才能获得 PASS。

## 当前实现与现场签发边界

- 本地 release identity、v2 `candidate_only`、普通 failure recovery、R0 bootstrap、R0→R1
  exact pair bridge 和产品撤销面已完成实现与专项回归；正常首次切换由
  `qrh-writer-handoff` 在 writer fence 与最终 state 复制后内嵌 bridge，
  `qrh-vm-bootstrap activate-v39-pair` 仅保留为同一固定 bridge 的诊断/恢复入口。若 R1 在开放
  ingress 前失败，后续 attempt 只能复用经唯一 receipt/journal 验证的 non-ingress R0，不得把
  `R0/null` 当普通稳态启动。独立审核和生产现场证据通过前，仍不得接入生产流量。
- writer handoff 已升级为 closed v4 crash-state machine：停止 C、两份 live-authorized SQLite
  checkpoint、替换 D state、bridge pending 和 terminal 均有 durable phase；所有 D 尚未暴露的
  crash cut 可恢复 pre-D state 与 exact C，D 已开放则必须证明 exact `R1/R0` pair 后只向前完成。
  journal 从 final-C checkpoint 起绑定 checkpoint ID/manifest hash，拒绝同 ID 完整重签替换；
  产品 checkpoint 使用 pinned D-root 路径、固定文件读取与内存 backup/restore proof，state
  replace、candidate probe 和 transient cleanup 只通过固定父目录相对操作；产品 controller、
  persistence、Windows runtime 均为 live provenance + slots 对象，不能通过实例 method shadow、
  test hook、环境或 alias 注入绕过固定生产调用图。
- 新 `quant_hub.ops.release_closure` 已实现 CLI、create-only/canonical/path/hash/time/subject 闭包、
  real MCP campaign replay 和明确的分类 adapter allow-list；真实分类 adapter 当前仍缺失，所以
  Stage 5/6 生产签发被机械阻断。补齐 adapter 时必须从底层真实 artifact 重算事实，不能把现有
  managed result parser 或测试 fixture 改成 PASS authority。当前不得预造 PASS，也不得勾选
  OpenSpec 6.8 或 7.4。
- 2026-08-31 的已授权 writer handoff 已真实执行：流程在 D service start/bootstrap comments
  schema pre-expand 处失败，D ingress 未开放；official rollback 随后成功恢复 exact C listener，
  并已完成该失败 attempt 的收尾。该事实不等于 Stage 5 放行，也不产生 D active/prior certificate；
  后续重试必须消费这次 official failure/rollback 证据，先关闭 schema pre-expand 缺陷，并继续遵守
  exact D 写入边界。GitHub visibility 仍不得在 Stage 5 certificate 前改变。
