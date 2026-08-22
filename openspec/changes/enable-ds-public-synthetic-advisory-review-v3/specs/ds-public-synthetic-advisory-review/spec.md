## ADDED Requirements

### Requirement: artifact 与 commitment 必须使用两阶段本地恢复协议

ledger SHALL 在创建任何 success replay 或 terminal commitment payload 前，先以独立 SQLite 事务持久化 `ARTIFACT_PREPARED` 或 `COMMITMENT_PREPARED`，并绑定 kind、generation、request SHA-256、raw SHA-256/size、内部 target、payload SHA-256/size 与 phase。Windows SHALL 从已验证 managed-root directory handle 使用 `RootDirectory` 单组件相对打开等价边界。任何非 Windows backend 若不能同时保护 SQLite connect 与 artifact producer，SHALL 在创建数据库前禁用；不可达的 POSIX directory-fd/no-follow 辅助逻辑 SHALL NOT 被视为写入授权。系统 SHALL NOT 在路径校验后使用不受目录 handle 约束的路径打开来写 payload。

payload SHALL 在同一 file handle 完成 write、flush/fsync、readonly seal 与属性/identity 复验，且只有第二 SQLite 事务成功后才能进入 committed/terminal state。后续读取边界 SHALL 重新验证 readonly、single-link、non-reparse、volume/file identity 与 canonical bytes。

#### Scenario: PREPARED 后在任一文件或事务边界重启

- **WHEN** 进程在 first DB commit、payload fsync、readonly seal、second DB commit 的任一前后边界终止
- **THEN** reopen SHALL 对完全匹配的 sealed payload 完成第二事务；对缺失、部分、writable 或 identity 漂移的 payload 转为明确的 `*_RECOVERY_REQUIRED`，ledger SHALL 仍可构造且 SHALL NOT 再次 dispatch

#### Scenario: managed data root 或 artifact root 在 payload 前被替换

- **WHEN** 任一 namespace path 不再对应已经验证的 directory handle volume/file identity
- **THEN** producer SHALL 在写入 payload 前 fail closed；后续 reopen SHALL 进入可恢复状态而不是把空文件声明为 committed

### Requirement: 现有 DS review v2 必须永久保持零网络

系统 SHALL NOT 修改现有 `ds_review.py` 的 canonical request、parser、simulation ledger、CLI 或 external-disabled 行为。v3 SHALL 位于独立模块，且任何 v3 状态均不得启用 v2 transport。

#### Scenario: 调用者尝试执行真实外呼

- **WHEN** 调用 v2 或 v3 的 `external_review`，或调用 v3 `approve_external`
- **THEN** 系统 SHALL 无条件失败，且不得读取凭据、构造连接或改变 ledger

### Requirement: v3 只能处理公开合成四轮对话

Round 1 SHALL 只含 blind synthetic behavior；Round 2–4 SHALL 只在上一轮 advisory 通过严格 public-output 验证并成功消费后，携带 bounded prior advisory projection 与累计 output-chain hash。每轮最终 request bytes SHALL canonical、ASCII、有界并以 CAS 固定。每个 claim、dispatch、consume 与后续派生边界 SHALL 从 manifest 重放 consumed prefix，不得只校验持久层摘要自洽。

#### Scenario: 上一轮失败或 ambiguous

- **WHEN** 任一轮进入 `FAILED_NO_RETRY` 或 `AMBIGUOUS_NO_RETRY`
- **THEN** campaign SHALL 进入终态，后续 round SHALL NOT 生成 request、claim 或 attempt

#### Scenario: 篡改上一轮 advisory 或已绑定 request

- **WHEN** durable advisory、output chain、request bytes 或 request hash 任一不一致
- **THEN** 下一使用边界 SHALL fail closed，且 fake transport 调用计数保持 0

#### Scenario: request bytes 与摘要被同时改写

- **WHEN** 持久层 request bytes 与其摘要被一起改为另一份 canonical JSON
- **THEN** 从 manifest 和前序状态重新派生的 expected request SHALL 不一致，claim 与 dispatch 均须在 fake send 前失败

### Requirement: 身份、价格、usage 与 deadline 必须预注册

campaign SHALL 绑定固定 host/path/model alias/provider revision、expected returned model/fingerprint、identity evidence hash、pricing evidence hash、transport build hash、public-output allowlist hash，以及整数 token/cost/bytes/deadline 上限。response SHALL 包含 exact usage，且 `total_tokens=prompt_tokens+completion_tokens`；bool 不得冒充整数。所有 elapsed SHALL 为有限数，campaign elapsed SHALL 由 ledger 持久累计。

#### Scenario: provider identity 或 usage 漂移

- **WHEN** returned model/fingerprint 不匹配，usage 缺失、结构越界、总数不一致或超过任一上限
- **THEN** response SHALL NOT 形成 advisory；已发生的 attempt SHALL 以固定错误码终结并不得重试

#### Scenario: deadline 在 dispatch intent 后到期

- **WHEN** 单轮或 campaign wall-clock deadline 在 durable dispatch intent 后到期
- **THEN** round SHALL 进入 `AMBIGUOUS_NO_RETRY`，预留费用不得释放，后续轮不得继续

#### Scenario: 调用方重复报告较小的 campaign elapsed

- **WHEN** 多轮 elapsed 的持久累计值超过 campaign deadline
- **THEN** 系统 SHALL 以 ledger 累计值终结，不得接受调用方提供的替代累计值

### Requirement: 每轮最多一次副作用尝试

ledger SHALL 在任何 side effect 前持久化唯一 dispatch intent、把 attempts 从 0 CAS 为 1，并预留最坏费用。无已核验 provider idempotency 合同时，系统 SHALL NOT 声称 exactly-once；任何 post-intent 未知状态 SHALL 终结为 `AMBIGUOUS_NO_RETRY`。

#### Scenario: 三十二个 owner 同时竞争同一轮

- **WHEN** 32 个真实 OS process owner 在同一 barrier 后对同一 `REQUEST_BOUND` round 并发 claim，并在竞争后制造 WAL/SHM churn
- **THEN** 恰好一个 owner SHALL 获得 claim，且该 round 最多产生一个 dispatch intent 与一次 fake send

#### Scenario: response 已提交但消费前进程终止

- **WHEN** advisory 和 receipt 已原子进入 `RESPONSE_COMMITTED`，但 worker 在 `CONSUMED` 前终止
- **THEN** 新进程 SHALL 只校验并消费已提交的本地 bytes，不得再次调用 transport

#### Scenario: dispatch intent 提交后进程对象丢失

- **WHEN** 新进程只持有 campaign 与 round ordinal
- **THEN** ledger SHALL 从 durable request、owner hash、intent hash、费用与 elapsed 重构 recovery intent，并只允许 `AMBIGUOUS_NO_RETRY` 本地终结

#### Scenario: claim 后、dispatch intent 前进程终止

- **WHEN** round 为 `CLAIMED` 且 `attempts=0`、dispatch intent 为空
- **THEN** 显式 recovery CAS MAY 将其恢复为 `REQUEST_BOUND`；任何 intent 已存在的 round SHALL NOT 回退

### Requirement: v3 transport 必须保持 fake-only

v3 SHALL 只接受模块定义的 exact `ExternalCampaignLedgerV3` 与 sealed、data-only `ScriptedFakeTransport`，不得接受 callback、connection factory、TLS context、Keyring adapter、环境 provider 或任意可执行 transport 对象。runner SHALL 由模块函数直接消费 fake data，不得调用 transport 实例方法。

#### Scenario: 调用者注入自定义 transport

- **WHEN** runner 收到非精确 `ScriptedFakeTransport` 类型
- **THEN** runner SHALL 在 dispatch intent 和任何 side effect 之前拒绝调用

### Requirement: ledger 必须位于显式受管 data root

ledger path SHALL 为 absolute path 且解析后位于显式授予的 managed data root 内。数据库及 SQLite sidecar SHALL 拒绝 reparse、非 regular 或多 hard-link 对象；application ID、user version 与 column set SHALL closed。

writable ledger SHALL 只在 Windows managed-directory named-stream backend 上启用。SQLite main/WAL/SHM SHALL 是 held managed directory 的 named streams，且 main stream SHALL 由 managed-root handle 以单组件相对目标打开或创建；普通可 hardlink 文件不得承载 SQLite bytes。每次 `sqlite3.connect` 前后 SHALL 验证当前 namespace path、root/marker/main-stream handle 与构造时冻结的 volume/file identity。若平台无法同时拒绝 root replacement 与 main/WAL/SHM hardlink，构造 SHALL 在任何数据库写入前失败。

ledger SHALL 在任何 marker 创建、stream 写入或 SQLite connect 前，通过 managed-root handle 只读相对打开并同时固定 PREINIT、INITIALIZED 与 main stream whole set。仅三者全 absent MAY 创建 PREINIT；任何 existing stream 或 INITIALIZED 缺 PREINIT SHALL fail-before-write，且 SHALL NOT 补建 PREINIT。正常 existing ledger SHALL 同时持有并重放 PREINIT 与 INITIALIZED marker。

ledger SHALL 在 main stream 创建前持久化 readonly、single-link、exact PREINIT marker，绑定 root identity、logical/stream name、ledger schema、application ID 与 user version。重启仅可在 marker 精确且 main stream 缺失/零字节时幂等初始化；或在 main image 能以内存只读重放证明完整、closed-schema、无 durable rows且 INITIALIZED marker 尚缺时完成 marker finalize。partial/corrupt image、marker 漂移或 INITIALIZED+absent/zero SHALL 在 writable connect 前失败。

WAL/SHM 在 existence check 与 metadata check 间消失时，ledger SHALL 有界地重启整个路径验证，并在 SQLite 连接创建 sidecar 后再次复核；不得泄漏瞬时 `FileNotFoundError`，也不得因重试而跳过 reparse/regular/single-link 检查。

success replay artifact 与 terminal commitment SHALL 位于 managed data root 下彼此隔离且区别于 SQLite 的固定目录；文件 SHALL 以 O_EXCL append-once 方式创建、fsync、封为只读，并在读取时核验 regular、single-link、非 reparse 以及打开 handle 与路径 identity。receipt/snapshot SHALL NOT 暴露 artifact 路径或文件名。

#### Scenario: ledger path 位于 data root 外

- **WHEN** 调用者提供 data root 外的数据库路径
- **THEN** 构造 SHALL 在打开 SQLite 前失败

#### Scenario: SQLite connect 窗口发生 root replacement 或 hardlink

- **WHEN** 在最后一次预检与 `sqlite3.connect` 首写之间尝试 rename/replace managed root，或对 main named stream 执行 `CreateHardLink`
- **THEN** root handle SHALL 拒绝替换，directory-stream boundary SHALL 在首写前和正常写入后均拒绝 hardlink；data root 外 SHALL 不得观察任何 SQLite bytes

#### Scenario: PREINIT 后进程在 bootstrap 边界终止

- **WHEN** 进程在 PREINIT marker durable、zero stream、first connect 前或 schema commit 后终止
- **THEN** restart SHALL 只对 exact PREINIT+zero 或 exact empty closed-schema image 完成初始化；不得把 partial、tampered 或无 authority image 当作 existing ledger 写入

#### Scenario: initialized ledger 的 PREINIT 被删除

- **WHEN** INITIALIZED marker 与完整 main stream 保留，但 PREINIT marker 缺失
- **THEN** whole-set observation SHALL 在创建任何 marker 或连接 SQLite 前失败，PREINIT SHALL 保持缺失且 main stream bytes SHALL 不变

#### Scenario: 平台没有等价 SQLite handle guard

- **WHEN** 构造 writable ledger 的平台不能消除 namespace check→`sqlite3.connect` 窗口
- **THEN** ledger SHALL 在数据库文件创建前抛出 disabled，不得退化为路径预检后写入

### Requirement: receipt 必须脱敏且没有发布权限

receipt SHALL 只包含公开常量、固定枚举、整数 usage/cost/bytes/deadline 和不可逆哈希；不得包含 secret、Authorization、Keyring locator 原文、raw response、raw fingerprint、raw response ID、raw owner nonce、stderr 或异常正文。success receipt SHALL 绑定 raw response SHA-256/bytes，且 ledger 只接受 raw response bytes 后内部解析；terminal status/error_code SHALL 使用 closed 合法矩阵。所有输出 SHALL 为 `ADVISORY_ONLY`。

`KNOWN_RESPONSE_INVALID` SHALL 只能由 ledger 对同一 immutable raw response bytes 内部重跑闭合 parser 并观察到拒绝后提交；合法 response 不得由调用方直接标记为 invalid。terminal receipt SHALL 在 reopen、snapshot 与 terminal-load 重放 closed fields、完整 status/error matrix、raw hash/size/nullability、finite elapsed、approval/dispatch 以及 campaign-round aggregate 一致性。

success raw response SHALL 只能在 strict envelope、identity、usage、deadline、public scanner、network-locator policy 与 positive vocabulary 全部通过后写入隔离 replay artifact；SQLite 与 receipt SHALL NOT 保存 raw 或 artifact locator。reopen、snapshot、consume 与后续 bind SHALL 从 artifact 重跑 parser并重新绑定 advisory、usage/cost、response identity、created_at、raw hash/size、receipt 与 output-chain。known-invalid 敏感 raw SHALL 永不持久化。

terminal SHALL 在 SQLite 外写 append-only commitment，绑定 campaign manifest、ordinal、request/intent、status/error、raw SHA/size/elapsed 与 receipt SHA；缺失、替换、单独 DB 漂移或 DB+receipt 联合漂移 SHALL fail closed。由于本 v3 禁止 secret 与外部可信服务，该文件不构成抵抗同主机全权限重建的 trusted anchor；terminal SHALL 永久标记 `UNVERIFIABLE_NO_TRUSTED_ANCHOR`，4.1 SHALL NOT 在本 change 内放行。

#### Scenario: provider 返回含 secret-like 文本的非法 body

- **WHEN** response 不能通过 exact envelope/public-output parser 且 raw body 含敏感样式文本
- **THEN** receipt SHALL 只记录 `KNOWN_RESPONSE_INVALID`、raw response SHA-256、bytes、elapsed，不得回显 raw body

### Requirement: external advisory 必须通过正向输出策略

external v3 SHALL 在不修改 v2 scanner 的前提下，再要求 advisory free prose 使用 manifest 绑定的 uppercase enum-like positive vocabulary。未知词汇、非 ASCII、locator 编码或未批准 token SHALL fail closed。

在进入 positive vocabulary 前，独立 network-locator policy SHALL 拒绝 IPv4、IPv6、host:port、URI scheme、domain 与 percent-encoded locator；该策略的 hash SHALL 绑定 manifest 和 receipt，不得依赖词表恰好不含 locator token。

#### Scenario: 输出满足 v2 结构但不满足 external allowlist

- **WHEN** advisory 含未注册词汇或外部 locator 表达
- **THEN** response SHALL 以 `KNOWN_RESPONSE_INVALID` 终结，advisory bytes SHALL NOT 持久化

#### Scenario: advisory 建议 proceed

- **WHEN**任一 advisory 的 `release_position` 为 `proceed`
- **THEN**该值仍 SHALL 仅为外部建议，不得自动写 semantic authority、激活 release、调用 MCP 写操作或影响 VM
