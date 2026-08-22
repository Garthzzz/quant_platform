# DS V4 Pro external v3 fake-only 验证运行手册

## 当前结论

external v3 已具备公开合成四轮对话、身份和价格证据绑定、usage/cost/deadline 门禁、一次性 dispatch intent、`AMBIGUOUS_NO_RETRY` 与脱敏 receipt 的可测试骨架。

它仍然不是可联网程序：

- `external_transport_state=DISABLED_FAKE_ONLY`；
- 不导入 HTTP、socket、TLS、Keyring、环境或 subprocess；
- `external_review` 与 `approve_external` 无条件失败；
- 唯一可执行边界只接受精确类型 `ExternalCampaignLedgerV3` 与 `ScriptedFakeTransport`；模块函数直接消费预置 bytes、finite elapsed 和结果枚举，不调用 transport 实例方法；
- ledger 构造必须显式提供 absolute managed data root；writable ledger 固定为 `WINDOWS_DIRECTORY_STREAM_GUARDED_ONLY`，SQLite main/WAL/SHM 是 held managed directory 的 named streams，root/PREINIT/INITIALIZED/main-stream handle 贯穿 ledger 生命周期；无等价 guard 的平台在创建数据库前禁用；
- strict success raw 只进入受管根下隔离、single-link、append-once 的 replay artifact；receipt/snapshot 不暴露其路径，reopen/snapshot/consume/bind-next 都重新解析；
- terminal 只写不含 raw 的 SQLite 外 append-only commitment；由于没有 secret 或外部可信服务，它固定标为 `UNVERIFIABLE_NO_TRUSTED_ANCHOR`，不得充当 release evidence；
- 不连接或写 VM，不读取 `reference`、private、sealed、qrels 或任何 secret。

现有 `quant_hub.knowledge.ds_review` 继续作为永久 zero-network v2 基线，v3 没有修改或启用它。

## 文件入口

- 合同与状态机：`quant_hub/src/quant_hub/knowledge/ds_review_external_v3.py`
- 公开测试：`quant_hub/tests/test_ds_review_external_v3.py`
- OpenSpec：`openspec/changes/enable-ds-public-synthetic-advisory-review-v3/`
- v2 基线：`quant_hub/src/quant_hub/knowledge/ds_review.py`

## 安全测试命令

在项目根执行：

```powershell
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:PYTHONPATH = 'quant_hub/src'
python -B -m pytest -q -p no:cacheprovider `
  quant_hub/tests/test_ds_review_external_v3.py `
  quant_hub/tests/test_ds_review_harness.py `
  quant_hub/tests/test_knowledge_semantic_partition_provider.py::DeepSeekProviderTests
```

这些测试只创建测试框架管理的临时 SQLite；不读取凭据，不创建真实连接，不写 repo cache，也不访问 VM/reference。

## 验收判读

必须同时满足：

1. v2 和 v3 的 `external_review` 均无条件失败；
2. v3 source surface 不含真实 HTTP/socket/TLS/Keyring/environment/subprocess 实现；
3. 四轮 request hash 各不相同；Round 2–4 可见上一轮 validated advisory 与 output-chain hash；每个后续边界从 manifest 重放全部 consumed prefix；
4. 每轮 `attempts=1`；32 个真实 OS subprocess 在同一 barrier 后 claim 恰好一个 winner，并完成每进程多次 ledger 重开/snapshot 的 WAL/SHM churn；线程池结果不能替代该证据；
5. post-intent timeout/process loss 为 `AMBIGUOUS_NO_RETRY`，新进程只用 campaign+ordinal 从 ledger 重构 intent，不能再次 claim/send；claim 后且 intent 前可显式 CAS 恢复；
6. response commit 后重启只执行本地 consume，fake send count 仍为 1；
7. model/fingerprint、usage、cost、bytes、非有限 elapsed 或 ledger 累计 deadline 越界均 fail closed；
8. receipt 不含 raw fingerprint、response ID、owner nonce、provider body 或敏感样式内容；success 绑定 raw response SHA-256/bytes，known-invalid 只保留同类非敏感元数据；
9. success replay artifact 的 hardlink、reparse、path/handle TOCTOU 或 raw/parser 漂移均失败；terminal commitment 丢失、替换或 DB+receipt 联合漂移均失败，known-invalid 敏感 raw 在整个 data root 中不存在；
10. managed root 在精确 connect 窗口的替换由生命周期 no-delete handle 在写前拒绝；main named stream 在首写前及正常写入后均拒绝 `CreateHardLink`，data root 外不产生 SQLite bytes；
11. campaign 只有四轮全部成功消费才为 `COMPLETE`；
12. `ADVISORY_ONLY` 不改变 semantic authority、release、MCP 或 VM；advisory 在词表前独立拒绝 IPv4/IPv6/host:port/scheme/domain/%xx locator，并绑定 locator-policy hash。

## 状态处置

### `ARTIFACT_PREPARED` / `COMMITMENT_PREPARED`

第一 SQLite 事务已绑定 kind、generation、request/raw/payload 摘要、内部 target 与 phase，但第二事务尚未完成。reopen 必须从受管目录 handle 相对读取并复核 readonly/identity：完整 sealed payload 自动完成本地 finalize；不得重新进入 fake transport。

### `ARTIFACT_RECOVERY_REQUIRED` / `COMMITMENT_RECOVERY_REQUIRED`

reopen 观察到缺失、部分写入、writable 或 root/file identity 不一致。该状态是明确的本地可恢复 fail-closed，不是成功或 terminal evidence；ledger 仍可构造。只允许相同 durable intent 与相同合成 raw/receipt 元数据写入新的 append-only generation，旧部分文件不得覆盖或截断，也不得产生第二次 dispatch。

Windows producer 使用 managed data-root handle → artifact-root handle → single-name file handle 的 NT `RootDirectory` 相对打开；写入、`FlushFileBuffers`、readonly seal 与属性复验使用同一 file handle。任何路径只用于显示或复核，不能成为 payload 的独立打开依据。

SQLite 自身使用 directory-stream 能力边界：逻辑数据库名映射为 managed directory 的 main named stream，WAL/SHM 也是同一目录的 sibling streams；普通文件路径始终不存在。构造先以 root handle 只读固定 PREINIT/INITIALIZED/main-stream whole set，再执行 closed matrix；仅全 absent 可创建 PREINIT，任何 existing stream 或 INITIALIZED 缺 PREINIT 都在写前失败且不得补建。PREINIT marker 先于零流建立并绑定 root/logical name/schema，INITIALIZED marker 后于完整 schema；重启只允许 exact PREINIT+zero 或 exact empty closed-schema image 补全初始化。root、marker 与 main-stream handle 保持打开，connect 前后闭合 namespace→冻结 identity。调用方结束使用后应显式 `ledger.close()`；测试清理临时目录前必须先关闭 ledger。POSIX 上虽然 artifact 辅助函数额外复核 current data-root path→held fd identity，但 writable ledger 在数据库创建前已禁用，因此该 producer 不可达。

### `FAILED_NO_RETRY`

已收到完整 fake response，但 envelope、identity、usage 或 public advisory 不合法。本轮永久消费一次 attempt，campaign 失败；不得修补 receipt 或继续下一轮。

### `AMBIGUOUS_NO_RETRY`

dispatch intent 已持久化，但无法证明 side effect 是否发生或是否计费。保留最坏费用预留，campaign 终止；不得把 timeout 当作“未发送”并自动重试。

### `RESPONSE_COMMITTED`

validated advisory 与脱敏 receipt 已进入 SQLite，但尚未完成最终 consume。恢复时只调用 `consume_committed`；不得重新进入 fake transport。

consume 前会重新派生该轮 request、重放 prior chain、验证 advisory canonical bytes/hash、receipt closed fields/hash、raw-response 摘要与 output-chain；仅 receipt 自身哈希一致不足以消费。

## Receipt 检查

receipt 可包含：

- campaign、manifest、request、prior output、output chain；
- dispatch intent、approval、provider pin、identity/pricing evidence、transport build 的 SHA-256；
- returned model、fingerprint/response ID hash、raw response SHA-256；
- prompt/completion/total usage、整数微单位费用、request/response bytes、elapsed；
- `attempt_count=1`、`redirects_followed=0`、`tools_enabled=false`；
- 固定状态、固定错误码与 `ADVISORY_ONLY`。

receipt 不得包含 raw secret、Authorization、Keyring service/username、raw fingerprint、raw response ID、raw owner nonce、raw provider envelope、stderr 或异常正文。可读 advisory 独立保存为通过公开输出 scanner 的 canonical bytes，receipt 只绑定其哈希。

external v3 在不修改 v2 scanner 的基础上增加 manifest-bound uppercase enum-like positive vocabulary。新增输出词汇必须先修改 allowlist、改变 manifest hash并重新预注册，不能在运行后补词。

## Fake-only API 约束

- `ExternalCampaignLedgerV3(path, data_root=...)`：`path` 是 Windows 显式 data root 下的逻辑直接子名，实际 SQLite bytes 只进入该 root 的 named stream；没有隐式默认根。构造成功后 ledger 持有 root/marker/stream guard，使用结束必须调用 `close()`。
- `execute_scripted_fake_round_v3(...)`：不再接受调用方提供的 campaign elapsed；从 ledger 读取累计值。
- `commit_success(...)`：只接受 `raw_response_bytes` 与 finite `elapsed_seconds`，内部重新解析并绑定 raw SHA-256；不接受 `ParsedExternalResponseV3` 作为提交证据。
- `mark_orphaned_dispatch_ambiguous_v3(..., ordinal=...)`：重启后由 ledger 重构 intent，不接收旧进程对象。
- terminal receipt 只接受 `FAILED_NO_RETRY + KNOWN_RESPONSE_INVALID`，或 `AMBIGUOUS_NO_RETRY` 与三种已批准 ambiguous 原因。
- `KNOWN_RESPONSE_INVALID` 不能由调用方只提供错误枚举；ledger 会对同一 raw bytes、campaign、bound request 与 elapsed 重跑 parser，合法 response 必须拒绝失败终态。
- terminal receipt 在 ledger reopen、`snapshot` 和 `load_terminal_receipt` 都会重放 closed fields、status/error matrix、raw hash/size、elapsed、approval/dispatch 与 campaign-round aggregate；receipt bytes 与同库 hash 一起漂移仍须失败。
- WAL/SHM 若在 existence check 与 `lstat` 之间正常消失，路径守卫会有界重跑整组检查；SQLite 打开并物化 sidecar 后还会再次复核 managed-root、reparse、regular 和 single-link 属性。
- success replay 只允许已经通过全部公开 parser 的 raw；receipt 仅保留 hash/size 与 `VERIFIABLE_BY_PUBLIC_RAW_REPLAY`，不含 artifact locator。任何后续使用都从 artifact 重算 response identity、created_at、usage、advisory 与 output-chain。
- terminal commitment 绑定 manifest/request/intent/status/error/raw 摘要/elapsed/receipt SHA，但在零 secret 条件下不能防御同主机全权限重建，因此 terminal receipt 永久为 `UNVERIFIABLE_NO_TRUSTED_ANCHOR`，OpenSpec 4.1 不得勾选。

## 真实外呼前的硬门禁

本 runbook 不包含任何真实执行命令。未来仍须全部完成：

1. 新的独立 verifier 审核 v3 代码、OpenSpec、测试和反例；
2. 获准联网后，从官方一手来源冻结当前 alias→revision、token-limit 字段、response usage、价格与 idempotency evidence；
3. 使用独立 synthetic identity probe 冻结 returned model/fingerprint，不能由正式评审首轮自举；
4. 另立 change 实现固定 TLS、精确 Keyring lookup、clean environment、一次性 IPC、parent monotonic deadline、kill 和 cleanup；
5. 用户批准精确 manifest hash、最多四次调用及整数总费用上限；
6. 真实运行仍只发送公开 synthetic bytes，并保持与 VM、reference、semantic authority 和 release 完全隔离。

上述任一门禁未满足时，允许继续的只有 fake transport、zero-network 测试和审计；不得读取真实凭据或发起网络调用。
