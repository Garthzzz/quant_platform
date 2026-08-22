## 1. 合同与设计

- [x] 1.1 冻结 external v3 manifest、四轮动态派生、identity/pricing/build/budget/deadline 与 advisory-only 合同。
- [x] 1.2 明确 SQLite 与远端副作用不能原子提交；无官方 idempotency 证据时只承诺 at-most-one attempt，post-intent 统一 `AMBIGUOUS_NO_RETRY`。
- [x] 1.3 保持现有 `ds_review.py` 永久 zero-network，不修改其请求、parser、ledger 或 CLI 合同。

## 2. Fake-only 实现

- [x] 2.1 新增独立 v3 canonical manifest/request/output-chain、严格 response/usage/cost parser 与脱敏 receipt。
- [x] 2.2 新增 request bind、claim、dispatch intent、response commit、consume、known failure 和 ambiguous no-retry CAS 状态机。
- [x] 2.3 只接受 sealed `ScriptedFakeTransport`；真实 external approval/transport、Keyring、环境、HTTP、socket、TLS 与 subprocess 路径保持不存在。

## 3. 公开验证与文档

- [x] 3.1 覆盖四轮真实对话链、identity drift、usage/cost/bytes/deadline、非法结构、secret-like raw response 去敏、32 并发 claim 和 once-only attempt。
- [x] 3.2 覆盖 post-intent crash→`AMBIGUOUS_NO_RETRY` 与 response commit 后重启只做本地 consume、不二次 send。
- [x] 3.3 交付中文 fake-only runbook、状态判读和真实外呼前授权清单。
- [x] 3.4 增加 consumed-prefix 全重放、managed data root、durable intent 重构、累计 finite deadline、raw-response 摘要、terminal closed matrix 与 external positive allowlist 的公开负测。
- [x] 3.5 修复 SQLite WAL/SHM 并发消失 TOCTOU，增加连接后路径复核；known-invalid 由 ledger 内部重跑 parser；reopen/snapshot/terminal-load 全量重放终态 receipt，并以 32 个真实 OS subprocess 同屏障 claim 和 sidecar churn 回归验证。
- [x] 3.6 success 仅在完整 parser/allowlist 通过后写隔离 single-link raw replay artifact，并在 reopen/snapshot/consume/bind-next 重放；terminal 写 SQLite 外 O_EXCL append-only commitment，敏感 invalid raw 永不持久化；补 artifact/commitment/locator 故障注入回归。
- [x] 3.7 artifact/commitment 改为 SQLite PREPARED intent→directory-handle 相对写入→同 handle fsync/readonly seal→第二事务 finalize；reopen 对完整 sealed payload 自动完成，对缺失/部分/readonly/root identity 漂移进入可恢复 fail-closed 状态；覆盖两类 root replacement、readonly、fsync 与全部 restart cut。
- [x] 3.8 完成 Windows managed-root/database 生命周期 no-delete handle 与 connect 前后冻结 identity 的阶段性闭合，并以独立复核识别其仍不能阻断 `CreateHardLink`；该普通文件方案已由 3.9 完整替代，不再构成当前能力声明。
- [x] 3.9 消除普通 SQLite 文件的 `CreateHardLink` 首写窗口：主库及 WAL/SHM 改为 held managed-directory named streams；增加 PREINIT/INITIALIZED exact marker 与零字节/完整空 schema 的确定性 bootstrap recovery，拒绝 partial、marker drift 和无 authority 既存 image；覆盖 hardlink 前后窗口、四个 process cut、legit/tamper reopen 与 32 进程回归。
- [x] 3.10 在任何 bootstrap 写入/connect 前，以 root-handle 只读固定 PREINIT/INITIALIZED/main-stream whole set 并执行 closed matrix；仅全 absent 可创建 PREINIT，任何 existing stream/INITIALIZED 缺 PREINIT 均 fail-before-write，覆盖删除 PREINIT 后保留完整 ledger 及 marker/stream 组合反例。

## 4. 未授权的后续工作

- [ ] 4.1 **永久禁止在本 fake-only v3 内勾选**：零 secret、零外部信任服务无法形成抵抗同主机全权限重建的可信 terminal anchor；terminal 固定标记 `UNVERIFIABLE_NO_TRUSTED_ANCHOR`。新的独立 verifier 只能复核实现与此限制，不能把本地 commitment 文件转述为 cryptographic release evidence。
- [ ] 4.2 在获准联网后仅从官方一手来源冻结当前 revision/API 字段/pricing/idempotency evidence；当前 fixture 不得转正。
- [ ] 4.3 用户批准精确真实 manifest、四次调用上限与总费用后，另立 change 设计隔离 Keyring/TLS child；不得把真实 transport 增补到本 v3 fake-only 模块。
