## Why

现有 `ds_review.py` 已经通过 zero-network synthetic campaign 验证，但它有意删除真实 transport，四轮请求也彼此静态独立。用户要求与 DS V4 Pro 进行多轮架构讨论，因此在真实外呼前，需要先把“上一轮建议如何进入下一轮”、身份与价格证据、usage/cost 上限、总体 deadline、一次性 dispatch、进程丢失和脱敏 receipt 固定为可机械验证的合同。

直接复用 semantic compiler provider 会扩大权限：该 provider 允许环境变量凭据、测试 transport/TLS 注入，且没有 completion-token 与费用上限。直接修改现有 `ds_review.py` 又会破坏其已经审核通过的永久零网络属性。

## What Changes

- 新增独立 external v3 campaign manifest，绑定固定 host/path/model alias/provider revision、预批准 returned model/fingerprint、identity evidence hash、pricing evidence hash、整数 token/cost/bytes/deadline 上限与 transport build hash。
- 四轮改为确定性对话链：Round 2–4 只能使用上一轮已通过公开输出协议的 bounded advisory projection，并绑定累计 output chain hash。
- 新增 SQLite CAS 状态机，覆盖 request bind、claim、durable dispatch intent、response commit、consume、known failure 与 `AMBIGUOUS_NO_RETRY`。
- 新增严格 provider response/usage/cost parser 与只含哈希、枚举、整数 usage/cost 和固定错误码的脱敏 receipt。
- 仅对完整通过公开 parser/allowlist 的 success raw 建立 managed-root 隔离 replay artifact，并在所有后续使用边界重新解析；known-invalid 敏感 raw 永不持久化。
- 对 terminal 建立 SQLite 外 append-only commitment 以发现单库或 DB+receipt 漂移；由于 fake-only v3 禁止 secret/外部可信服务，terminal 明确为 `UNVERIFIABLE_NO_TRUSTED_ANCHOR`，不得转述为 release evidence。
- 在 positive vocabulary 前独立拒绝 IPv4、IPv6、host:port、scheme、domain 与 percent-encoded locator，并把策略 hash 绑定 manifest/receipt。
- 只允许模块内密封的 `ScriptedFakeTransport`；真实 external approval、Keyring、HTTP、socket、TLS、环境读取与 subprocess 均不存在且无条件失败。
- 新增 32 并发 claim、四轮对话链、身份/usage/cost、非法响应、deadline、response-commit 恢复和 post-intent crash-cut 的公开测试。
- artifact/commitment 使用 SQLite PREPARED intent、directory-handle 相对创建、同 handle fsync/readonly seal 与第二事务 finalize；reopen 对完整 sealed payload 自动完成，对缺失/部分/identity 漂移进入显式可恢复 fail-closed 状态。
- SQLite writable ledger 仅在 Windows directory named-stream 能力可用时构造：SQLite 主库与 WAL/SHM 均附着于禁止 hardlink 的 held managed directory，root/marker/stream 句柄贯穿 ledger 生命周期；PREINIT 与 INITIALIZED marker 显式绑定 root identity、logical name 与 schema。无等价保护的平台在任何数据库写入前禁用。

## Capabilities

### New Capabilities

- `ds-public-synthetic-advisory-review`: 公开合成、advisory-only、fake-only 的四轮外部架构评审预注册与一次性副作用状态机。

### Modified Capabilities

无。现有 `design-vm-knowledge-mcp`、semantic compiler 和 `ds_review.py` 合同均不修改。

## Out of Scope

- 读取或枚举任何真实 Keyring 项；
- 读取 API key 或环境变量；
- 发起 identity probe、HTTP、DNS、TLS 或任何真实网络调用；
- 核验实时 provider API 字段、价格或 idempotency 支持；
- 连接或写生产 VM、reference、semantic authority、release 或 MCP；
- 让 DS 输出获得发布、接受、写库或部署权限。

## Impact

新增文件限定在独立 OpenSpec change、`quant_hub.knowledge.ds_review_external_v3`、对应公开测试和 verification runbook。真实 transport 必须作为后续独立 change，经用户精确费用授权、官方证据冻结和独立 verifier 放行后才能设计；不得在本 change 内补上网络实现。
