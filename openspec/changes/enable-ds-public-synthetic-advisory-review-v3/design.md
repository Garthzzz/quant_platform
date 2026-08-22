## 设计结论

v3 是“可审计真实 transport 的状态机模型”，不是 transport。现有 v2 永久保留 zero-network；v3 也默认 `DISABLED_FAKE_ONLY`，只接受数据型 scripted fake。这样可以先证伪对话、并发、预算、deadline 和 crash 语义，而不接触凭据、网络、VM 或研究正文。

## 冻结边界

每个 campaign manifest 绑定：

- `api.deepseek.com` 与 `/chat/completions`；
- `deepseek-v4-pro`、`DeepSeek-V4-Pro-0813`、expected returned model/fingerprint；
- identity evidence、pricing evidence 与 transport build SHA-256；
- 每百万 token 的整数微单位费率；
- 四轮 prompt/completion/total token、request/response bytes、单轮/总体 deadline 与总费用上限；
- 四个 round template hash、synthetic dossier hash 与对话派生版本；
- external public-output 正向词表的版本与 canonical SHA-256；
- `DISABLED_FAKE_ONLY` 和 `ADVISORY_ONLY`。

manifest 不保存凭据、Keyring locator 原文或真实 provider response。

## 四轮对话派生

```text
Round 1: blind synthetic behavior
  -> validated advisory A1
Round 2: disclosed matrix + bounded(A1) + chain(A1)
  -> validated advisory A2
Round 3: synthetic outcomes + bounded(A2) + chain(A1,A2)
  -> validated advisory A3
Round 4: final dissent + bounded(A3) + chain(A1,A2,A3)
```

后续轮 request 无法在 campaign 创建时知道最终 bytes，因此 manifest 固定 template/derivation hash；每轮在上一轮成功消费后才生成 canonical request，并在 SQLite 中以 CAS 固定最终 request hash。每次只携带上一轮最多 8 个 finding、每类最多 4 个 dissent 项，避免对话上下文无界增长。前轮失败或 ambiguous 时，后续轮不能 materialize。

每个后续使用边界都从 manifest 与 ordinal 0 开始重放全部已消费前缀：重新派生 request bytes/hash，重新验证 advisory canonical bytes/hash 与正向词表，重新计算 output chain，并闭合核对 receipt。仅让持久层字段彼此“摘要自洽”不构成通过。

## 一次性副作用状态机

```text
campaign:
PREREGISTERED
  -> FAKE_EXTERNAL_APPROVED
  -> RUNNING
  -> COMPLETE | FAILED | AMBIGUOUS

round:
TEMPLATE_BOUND
  -> REQUEST_BOUND
  -> CLAIMED
  -> DISPATCH_INTENT
  -> RESPONSE_COMMITTED
  -> CONSUMED

DISPATCH_INTENT
  -> FAILED_NO_RETRY | AMBIGUOUS_NO_RETRY
```

`DISPATCH_INTENT` 在任何模拟 side effect 前以 `BEGIN IMMEDIATE` 和条件更新持久化，同时预留最坏费用并把 `attempts` 从 0 固定为 1。没有已核验的 provider idempotency 合同时，SQLite 不可能与远端副作用构成原子事务。因此 v3 只承诺“每轮至多一次 attempt”：intent 后进程丢失或 timeout 一律进入 `AMBIGUOUS_NO_RETRY`，不得自动重试。响应已经完整验证并进入 `RESPONSE_COMMITTED` 时，重启后只消费本地 receipt/advisory，不再次调用 transport。

dispatch intent 的 request、owner hash、intent hash、预留费用与 dispatch 前累计 elapsed 全部持久化。重启恢复只接受 `campaign + ordinal`，由 ledger 重构 intent；不再要求调用者保留崩溃前的 Python 对象。`CLAIMED` 且 `attempts=0` 可通过显式 CAS 回到 `REQUEST_BOUND`；一旦存在 intent 则只能本地终结，不可回退。

## fake transport 决策

v3 不提供通用 callback、connection factory 或 transport protocol。`execute_scripted_fake_round_v3` 只接受精确类型 `ExternalCampaignLedgerV3` 与 `ScriptedFakeTransport`；runner 由模块内函数直接消费 fake 的 bytes、elapsed 和结果枚举，不调用 transport 对象方法。该对象没有 callback、文件、环境或网络入口。`external_review` 与 `approve_external` 无条件抛出 `ExternalV3Disabled`。

SQLite 路径必须显式位于调用方授予的 absolute managed data root 内；数据库、WAL 与 SHM 每次连接前都重验非 reparse、regular、single-link 属性，ledger 同时冻结 application ID、user version 与 exact columns。该能力不能用任意文件路径的默认值替代。

Python `sqlite3` 不提供 directory-handle/dir-fd 构造接口，所以路径预检后直接 `sqlite3.connect(path)` 仍有 namespace 替换窗口；普通文件即使持有 no-delete handle，`CreateHardLink` 仍可在最后一次检查与首写之间把零字节 placeholder 链接到 data root 外。v3 writable ledger 因而固定为 `WINDOWS_DIRECTORY_STREAM_GUARDED_ONLY`：逻辑 `root/name.sqlite3` 映射到 held managed directory 的 `root:name.sqlite3` named stream，WAL/SHM 亦为同一目录的 sibling streams。Windows 禁止对目录建立 hardlink，且 named stream 不能成为 `CreateHardLink` source；测试必须在首写窗口和正常写入后机械证明该拒绝。

构造时先持有禁止 delete-sharing 的 managed-root handle，并在任何 marker 创建、stream 写入或 SQLite connect 前，以该 root handle 只读相对打开并同时固定 PREINIT、INITIALIZED、main stream whole set。closed matrix 只允许：三者全 absent 的全新状态；PREINIT-only/ PREINIT+zero 的重启状态；PREINIT+完整空 schema 且 INITIALIZED 缺失的 finalize 状态；以及三者完整的 existing 状态。任何 existing stream 或 INITIALIZED 缺 PREINIT、INITIALIZED 绑定 absent/zero stream、partial/corrupt image 或 marker 漂移均在写前失败，绝不静默补 PREINIT。

全新状态才可用 root handle 单组件相对创建 readonly、single-link、exact-bytes PREINIT marker；marker 绑定 root volume/file identity、logical/stream name、ledger schema、application ID 与 user version。首个 schema 已完整提交但 INITIALIZED marker 尚未建立的 cut，只能通过 immutable in-memory replay 证明数据库完整、closed-schema 且无 durable rows后补 INITIALIZED。初始化完成后，后续构造在任何可写 connect 前重放 main image integrity/schema 与两个 marker。root、marker 与 main-stream handle 贯穿 ledger 生命周期，connect 前后继续闭合 namespace→冻结 identity。POSIX 或不支持 directory named stream 的 Windows 文件系统在数据库写入前禁用。

WAL/SHM 是会在并发连接间正常创建和消失的临时 sidecar。路径验证若在 existence check 与 `lstat` 之间观察到对象消失，必须有界地重启整个验证，不能只跳过发生竞争的单个对象；SQLite 连接建立并创建 sidecar 后还要再次执行同一组路径检查。公开并发证明使用 32 个真实 OS subprocess 同屏障竞争，并在各进程反复重开 ledger/snapshot 以制造 WAL/SHM churn，线程池不能替代该门禁。

success raw response 是唯一允许持久化的 provider envelope，而且必须先完整通过 strict JSON/envelope、identity、usage/cost/deadline、v2 public scanner、external network-locator 拒绝和 positive vocabulary。它不进入 SQLite 或 receipt，而进入 managed data root 下独立、确定性、single-link、O_EXCL 创建并封为只读的 replay artifact；receipt 不含其目录或文件名。reopen、snapshot、consume 和下一轮 bind 前都从该 artifact 重跑 parser，并重新闭合 advisory canonical bytes、usage/cost、response ID/fingerprint/model、created_at、raw hash/size、receipt 和 output-chain。known-invalid 或 ambiguous raw 永不进入该目录。

terminal receipt 另有 SQLite 故障域之外的 canonical commitment 文件，使用独立目录、确定性文件名、O_EXCL、fsync、只读与 single-link/reparse/handle-path identity 检查。commitment 绑定 manifest、ordinal、request、dispatch intent、status/error、raw SHA/size/elapsed 与 receipt SHA；reopen、snapshot 和 terminal-load 必须同时消费 SQLite 与该 commitment，缺失、替换或只联合修改 DB+receipt 都失败。它不含 raw body。

该 commitment 只是跨 SQLite 故障域的一致性 authority，不是抵抗同主机全权限写入者的 cryptographic anchor。v3 禁止 secret、HMAC key、外部 transparency log 和远端 write-once service，因此无法诚实建立这种可信 anchor；所有 terminal receipt 和 manifest 固定标记 `UNVERIFIABLE_NO_TRUSTED_ANCHOR`，本 change 的 4.1 永久不得作为 release gate 勾选。

这不是未来 production transport 的实现模板。未来 child 必须另立 change，重新审核固定 TLS、clean environment、精确 Keyring lookup、parent wall-clock kill、IPC 与 no-redirect；不能在本模块添加 HTTP 分支。

## usage、费用与 deadline

- request 显式包含 preregistered completion 上限；具体 provider 字段仍需未来官方文档确认。
- response 顶层必须含 exact `usage`，三个字段均为非 bool 精确整数，且 `total=prompt+completion`。
- 费用只用整数微单位和固定 pricing evidence 计算，dispatch 前按每轮最坏值预留；ambiguous 不释放预留。
- request bytes 还作为保守 prompt-token reserve 的上界，避免未核验 tokenizer 低估成本。
- fake elapsed 必须是 finite float；campaign elapsed 由 ledger 按已提交轮次持久累计，不接受调用方提供的“当前总耗时”。单轮和累计 deadline 任一超界均在 intent 后终结为 ambiguous；未来真实实现仍必须由 parent monotonic deadline 杀死 child，不能信任 child 或只用 socket inactivity timeout。

## receipt 与权限

receipt 包含 manifest/request/advisory/output-chain/dispatch/approval/provider/identity/pricing/build/allowlist 哈希、raw response SHA-256、usage、费用、bytes、elapsed、固定状态和错误码。fingerprint、response ID 与 owner nonce只保存 SHA-256；不保存 raw response、Authorization、secret、Keyring locator、stderr 或异常正文。success commit 只接受 immutable raw response bytes 并在 ledger 内重新解析；不得接受调用方构造的 parsed-response 对象。known-invalid 只保存 raw response SHA-256、长度、elapsed 与固定错误码。

`KNOWN_RESPONSE_INVALID` 也不能由调用方只凭错误枚举声明。ledger 必须在终态 CAS 前对同一 raw bytes、campaign、bound request 与 elapsed 重跑闭合 parser，并且只在 parser 确实拒绝时生成脱敏失败 receipt。终态 receipt 在 reopen、snapshot 和显式 terminal-load 时都要从 manifest 与 consumed prefix 重放，闭合核对 status/error matrix、raw hash/size、elapsed、approval、dispatch、campaign/round 状态、累计 aggregate 与外置 commitment；只同时修改 receipt bytes 与其同库 hash 不得绕过重放。

可读 advisory 先通过不变的 v2 public-output scanner，再通过 external v3 的 uppercase enum-like positive vocabulary，最后以 canonical bytes 独立保存；receipt 只绑定其哈希。所有结果均为 `ADVISORY_ONLY`；即使输出 `release_position=proceed`，也不能改变 semantic authority、release、MCP 或 VM。

## 本地 artifact 两阶段恢复协议

success replay 与 terminal commitment 均不得在 SQLite 仍为 `DISPATCH_INTENT` 时直接落文件。第一事务先把 round 转为 `ARTIFACT_PREPARED` 或 `COMMITMENT_PREPARED`，并闭合绑定 kind、generation、request/raw/payload SHA-256 与长度、内部 target 和 `INTENT_DURABLE` phase；该事务提交后才允许创建 payload。文件以受管 data-root handle 为起点逐级打开：当前唯一可写平台 Windows 使用 NT `RootDirectory` 的单组件相对打开。POSIX artifact 辅助边界虽会在写入前后复核 current data-root namespace path→held data fd identity，并使用 `dir_fd + O_NOFOLLOW`，但因 writable ledger 已在构造阶段禁用，该 producer 不可达，不能据此声称 POSIX 获准写入。写入前必须复核 data root、artifact root 与文件 handle 的 volume/file identity，禁止把“路径预检后再 `os.open(path)`”当作写入边界。

payload 只在同一 file handle 上写入并 flush/fsync，再由同一 handle 设置 readonly，复核 regular、single-link、non-reparse、size、readonly 与路径/handle identity；随后第二事务才把 phase 改为 `SEALED_COMMITTED` 并进入 `RESPONSE_COMMITTED` 或闭合 terminal state。所有 reopen/snapshot/consume/load 边界继续复验 readonly 与 handle identity。

reopen 遇到 PREPARED 时确定性 reconcile：完全匹配且 readonly 的 payload 必须重跑 parser/receipt/commitment 后完成第二事务；缺失、部分写入、writable、root/file identity 漂移必须转为显式 `ARTIFACT_RECOVERY_REQUIRED` 或 `COMMITMENT_RECOVERY_REQUIRED`，ledger 本身仍可构造。恢复只允许相同 intent 与相同合成 raw/receipt 元数据写入新的 append-only generation，不得截断或替换旧的部分文件，也不得重新 dispatch。

## 后续真实 transport 放行

至少还需要：

1. 由官方一手证据确认当前 alias→revision、请求 token-limit 字段、response usage、pricing 和 idempotency 行为；
2. 冻结真实 identity evidence 与 fingerprint，不能由正式评审第一轮自举；
3. 独立审核新 child 的代码/build hash、TLS、Keyring、clean environment、deadline、kill 和脱敏边界；
4. 用户对精确 manifest、最多四次调用和整数总费用上限作一次性授权；
5. 真实 transport 仍只发送 public synthetic bytes，并与发布链完全隔离。
