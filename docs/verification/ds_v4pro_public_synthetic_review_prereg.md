# DS V4 Pro 公开合成架构评审：第二版威胁模型与预注册

## 放行结论

当前构建不包含真实 HTTP transport、Keyring 读取、环境变量读取或外呼 CLI。`external_review`、external approval 和 external claim 均无条件失败；因此即使调用者自行构造状态，也不能从本模块发起 DS V4 Pro 请求。

本轮只提供三类能力：

1. 生成四轮深不可变 canonical request 与独立 canonical campaign manifest；
2. 使用 SQLite CAS ledger 验证四轮顺序、唯一 claim 和不可重复消费；
3. 使用无凭据、无网络的 parser 验证合成响应及结构化 dissent。

评审建议始终是 `ADVISORY_ONLY`，不能写入 semantic authority，不能放行 release，也不能替代 MCP、RAG、SQLite 和恢复机制的本地压力测试。

本文采用 Markdown/Web 分支，保持 UTF-8 中文研究语境与中英文可读边界，不引入 LaTeX/PDF 编译链，也不修改研究正文。

## 第一版审核失败与关闭方式

| 审核问题 | 第二版关闭方式 | 机械证据 |
|---|---|---|
| `PreparedReview` 持有可变 `dict` | 只保留 round、ordinal、canonical request `bytes`、request hash、dossier hash 与 provider-pin hash | dataclass 字段闭合测试；tamper 后 dry-run 重新解码并拒绝 |
| 四轮仅为内存对象 | 独立 canonical campaign manifest 固定四轮顺序、四个 request hash、完整 scenario 映射、provider fingerprint、总 deadline 与 transport 状态 | manifest canonical replay、hash 绑定和篡改测试 |
| 每轮可能重复调用 | SQLite `BEGIN IMMEDIATE` + 条件 `UPDATE` claim；独立 `consumed_ledger` 对 campaign/ordinal 唯一；失败也消费，不允许重试 | 8 进程竞争恰好 1 个 winner；重复 claim/consume 均失败 |
| 运行库默认可触达真实 transport | 删除真实 transport；external approval、external mode 与 external review 均不可达 | 静态测试确认无 connection factory、HTTPS、SSLContext、环境或 Keyring provider 表面 |
| 可注入 TLS 或 transport 接触凭据 | 不存在 transport 注入点，也不存在凭据接口；fake 测试只调用纯 parser | source-surface 负向测试 |
| 环境 marker 可由父进程伪造 | 删除所有环境变量凭据能力 | 模块无 environment provider 与 secret 读取 |
| Round 1 暴露实际机制名 | Round 1 只包含 `M01`–`M08`、`I01`–`I08` 和 `S01`–`S08` | 请求字节断言不含任何正式 mechanism 名 |
| scenario 可错配 | `S01`–`S08` 与 mechanism、stress case、invariant、整数规模和 outcome 使用冻结的逐行精确映射 | scenario id、pairing、bool-as-int 反例均失败 |
| JSON 和文本边界不足 | duplicate key 拒绝、depth 不超过 32、顶层 exact、canonical JSON、`type(x) is int/bool/float`、有界 response 与 90 秒 elapsed bound | duplicate/deep/bool/oversize/deadline 反例测试 |
| path、token、姓名或身份可进入建议 | 输出自由文本拒绝 slash、drive-relative、password、token、API key、name、identity、邮箱、双词英文姓名、UUID 和任意非 ASCII | verifier counterexample 集全部失败 |
| fingerprint 只绑定单轮参数 | fingerprint 进入独立 campaign manifest，并通过 provider-pin hash 绑定每个 `PreparedReview` | 改 fingerprint 后 request hash 不变，但 pin hash 与 manifest hash 必然变化 |

## 第二轮审核失败与关闭方式

| 审核问题 | 第三版候选的关闭方式 | 机械证据 |
|---|---|---|
| `SCENARIO_ROWS` 是 `tuple[dict]`，内部仍可修改 | 改为 frozen、slots、仅标量字段的 `SyntheticObservation` tuple；所有 manifest 投影都是临时副本 | dataclass frozen 测试、逐 ordinal 完整等值检查 |
| 只靠当前全局 payload 等值，没有独立扫描最终 bytes | 新增 final-byte audit：ASCII decode、预解析 depth、strict JSON、内嵌 user JSON 解码、逐 key/value locator/secret/identity 扫描、canonical hash | 构造 canonical 恶意 request，`Bearer sk-syntheticvalue`、`contact john smith`、drive-relative、slash、password、token、非 ASCII 全部失败；构造、manifest hash、prepared-use 三个边界均重跑 |
| 极深 JSON 可在验证前触发 Python recursion | 在 `json.loads` 前使用字符串状态机计算真实 JSON nesting；同时统一捕获 `RecursionError` | 5,000 层输入稳定返回固定 `DossierPolicyError` |
| parser 错把合法普通 JSON 拒绝为非 canonical | 外层与内层允许任意合法 whitespace 和 key order；解析后才 canonicalize，并以 canonical bytes 计算输出 hash | 缩进、不同键序响应与 minified 响应得到同一 output hash |
| claim owner 在 commit 后终止，supervisor 丢失返回值 | claim 前必须持久化绑定 manifest、owner、supervisor hash 与 intended ordinal 的 owner envelope；恢复 API 只凭原 supervisor nonce 重建同一个 `CLAIMED`，不创建新 claim | 子进程 commit 后被 terminate，父进程恢复同一 owner/ordinal；错误 supervisor、未 claim、已消费均不能恢复 |
| Round 1 过度匿名，无法进行实质评审 | 保留 `M/I/S` 匿名编号，同时加入中性 behavior 与 risk class，覆盖 concurrency、durability、resource 和 consistency | 请求仍不含正式 mechanism 名，但包含四类行为信息 |

## 深不可变请求边界

`PreparedReview` 不暴露 request `dict`。调用边界只能得到 canonical UTF-8 `bytes` 与不可变标量。dry-run、response parser 和 ledger canonical replay 在使用前都会重新执行：

```text
bytes SHA-256
  -> independent final-byte path/secret/identity/non-ASCII scan
  -> strict UTF-8 JSON
  -> duplicate-key rejection
  -> depth <= 32
  -> canonical re-encoding equality
  -> exact top-level and exact message schema
  -> frozen enum payload equality
  -> campaign manifest hash binding
```

即使使用低层 Python 手段替换 frozen dataclass 字段，只要 bytes 或 hash 被改变，或者 bytes 与冻结 payload 不一致，下一次使用都会失败。

## 第四轮兼容性修订

- `consume` 不再只核对 request hash。消费前从 SQLite 中重放完整 campaign，调用完整 `_bound_review`，并逐字段核对 claim 中的 campaign、manifest、dossier、provider pin、round、ordinal、canonical request bytes 与 request hash；另一 provider pin 下即使 request hash 相同也不能混用。
- scenario mapping 与四轮 objective 的规范真源改为两组固定 canonical bytes。代码在每次 prepare/validate 时重新 strict-decode，并与写入函数代码的固定 SHA-256 比较。导出的 `SCENARIO_ROWS` 与 `_ROUND_OBJECTIVES` 只是兼容视图；即使用 `object.__setattr__` 或字典写入篡改，也不会影响新请求或 manifest。
- 请求最终字节扫描与响应自由文本扫描都拒绝裸小写双词英文姓名。为避免将普通句子误当作姓名，合成评审的自由文本协议改为大写枚举 token；`john smith` 在请求、输出正文或 provider response id 中均机械失败。
- provider pin 的每个身份值额外执行 secret-like 扫描，拒绝 `sk-`、Bearer，以及 `token123`、`password123`、`secretvalue`、`credentialABC`、`authorization999` 等粘连变体。路径门禁同时拒绝 `C:relative`、`C:.`、`C:..`、`C: relative`；身份门禁覆盖完整小写双词姓名与 `j smith` 式缩写。相同扫描在最终 request bytes、自由输出和 provider response id 边界重放。解析回执不再回显 system fingerprint，只保留其 SHA-256。

规范真源哈希：scenario `b0ec6268b151a86201ee963de0a783af70df323c9f7d8f670cdfcf8f61e9da51`；round objective `f77d1572bb7d8c25e94ebe76c79235e3bbfd60a156b793bcc901a3178e368b84`。

## Canonical campaign manifest

每个 campaign 固定：

- HTTPS host、API path、model alias、provider revision；
- 调用前批准的 expected returned model 与 system fingerprint；
- provider-pin SHA-256；
- 合成 dossier SHA-256；
- 四轮唯一顺序与四个 canonical request SHA-256；
- `S01`–`S08` 的完整且正确的 scenario 映射；
- 90 秒总体 deadline；
- `DISABLED_PENDING_INDEPENDENT_APPROVAL` transport 状态；
- `ADVISORY_ONLY` 权限。

manifest 本身以 canonical JSON bytes 保存，并拥有独立 SHA-256。SQLite 中的 manifest 在 claim 时从 bytes 完整重放；只修改数据库字段、manifest bytes 或 hash 均不能绕过。

## 四轮预注册

### Round 1：Blind review

只提供匿名的 mechanism id、invariant id、scenario id、中性 behavior 和 risk class。行为信息覆盖 concurrency、durability、resource 与 consistency，足以进行架构质疑；输出仍只能引用 `M01`–`M08`，模型看不到正式机制名、压力参数或观察结果。

### Round 2：Stress matrix critique

提供正式 mechanism 映射与无 outcome 的合成压力矩阵，要求判断矩阵能否证伪所有不变量。

### Round 3：Results and minimal change

在第二轮基础上加入冻结的 enum outcome，要求提出最小机械修改和更强的回归 oracle。

### Round 4：Final dissent

使用完整合成映射与 outcome，要求输出 `why_not_release`、`missing_stress_cases` 和 `assumptions_to_break`。它没有放行权限。

## Durable CAS 与 consumed ledger

campaign 状态只有：

```text
PREREGISTERED
  -> SIMULATION_APPROVED
  -> COMPLETE
```

当前不存在 external-approved 状态。只有精确匹配 manifest SHA-256 与 approval evidence SHA-256 的显式 simulation approval 才能进入 claim。

每轮状态只有：

```text
PREREGISTERED -> CLAIMED -> CONSUMED
```

claim 使用 `BEGIN IMMEDIATE` 和 `WHERE state='PREREGISTERED'` 条件更新。只有最小未消费 ordinal 能被 claim；已 claim 的轮次会阻塞后续轮次。`SUCCEEDED` 和 `FAILED` 都写入唯一 `consumed_ledger` 并永久消费该轮，任何重复 claim 或 consume 都失败。这样在外部副作用之后发生进程终止时，系统宁可保留 claimed 状态等待人工登记失败，也不会自动重复外部调用。

claim 前还必须持久化 owner envelope。envelope 固定 exact manifest、owner nonce、supervisor nonce SHA-256 与 intended ordinal；未准备 envelope 的进程不能竞争，失败竞争者的 ordinal-0 envelope 也不能被挪用到 ordinal 1。claim 和 envelope 的 `PREPARED -> BOUND` 在同一事务提交。若 worker 在 commit 后终止，父进程使用原 supervisor nonce 只能重建该条 live claim；错误 supervisor、尚未 claim 的 envelope 或已经 `CONSUMED` 的 envelope 都不能恢复，也不会隐式创建新 claim。

公开测试使用 8 个 Windows spawn 进程同时竞争同一数据库与同一轮次，验收条件是恰好 1 个 winner、7 个拒绝、消费后只能进入下一 ordinal。另一个 kill-cut 测试让子进程完成 claim commit 后停住，再由父进程 terminate；父进程只能通过预先持有的 supervisor nonce 恢复同一 owner 与 ordinal，消费后恢复永久失败。

## 严格响应 parser

parser 不读取凭据、不构造 socket，只接受测试提供的 bytes。它要求：

- response 不超过 256 KiB；
- elapsed 必须是 `float`，且在 0–90 秒内；`bool` 与整数不能冒充；
- `json.loads` 前预扫 JSON depth，超过 32 立即拒绝；`RecursionError` 统一去敏；拒绝 duplicate key；
- provider response 顶层字段完全一致；
- model 与 fingerprint 必须匹配 campaign manifest；
- choice、message、finish reason 完全匹配；
- 外层和内层允许普通合法 JSON 的 whitespace 与 key order；解析后再 canonicalize/hash；
- output 顶层、finding 和 dissent 字段完全一致；
- 所有自由文本为 1–1200 bytes printable ASCII，并通过 locator、Bearer/`sk-`、password/token、身份、大小写姓名模式和非 ASCII 扫描。

90 秒字段目前只用于纯 parser 的边界验证，不代表已经存在可用的网络 deadline。未来若增加真实外呼，必须由隔离 child 的父进程总 deadline 强制终止整个 child，而不能只依赖 socket 的单次读写 timeout。

## 凭据与 TLS 决策

本轮选择删除环境变量与 Keyring 的真实读取能力，而不是继续保留可伪造 marker 或可注入 transport。由于不存在 HTTP 实现，所以也不存在可被调用者替换的 `connection_factory`、`SSLContext` 或 header 记录路径。

若后续独立审核允许实现真实 transport，必须作为新的变更重新审核，并至少同时满足：

1. 仅隔离 child 能访问 Keyring；父进程不能读取 secret；不恢复环境变量 fallback；
2. child 使用内部固定 HTTPS host/path，TLS context 强制 `CERT_REQUIRED` 与 `check_hostname=True`；
3. 无 transport、SSL context 或 connection factory 注入参数；
4. 父进程使用 clean environment、一次性 IPC、总体 deadline、kill 与 cleanup；
5. header、raw body、secret 和 child stderr 不进入异常、receipt 或日志；
6. 只有新的 external-approved manifest 状态才能进行一次 CAS claim；
7. 任何失败都消费该轮，不重试。

在这些条件通过新的独立审核之前，不应通过简单修改常量来增加外呼，因为当前代码中根本不存在发送实现。

## 零网络 dry-run

```powershell
$env:PYTHONPATH = 'quant_hub/src'
python -m quant_hub.knowledge.ds_review_cli `
  --expected-system-fingerprint fp-public-synthetic-0813 `
  --round all
```

该命令只构造冻结 dossier、campaign manifest 和四个 receipt，不读取文件、不读取凭据、不创建网络连接。输出必须满足：

- bundle 和 receipt 均为 `dry_run_no_network`；
- `network_calls` 为 0；
- 四个 receipt 使用同一 campaign manifest SHA-256；
- 四个 request SHA-256 各不相同；
- 相同代码、fingerprint 和 round 可复算一致；
- transport 状态保持禁用。

## 真实外呼前仍需完成

1. 第二轮独立 verifier 必须确认本报告中的反例均真实关闭；
2. 使用已批准的真实 fingerprint 生成新的 manifest，不能使用公开 fixture token；
3. 单独设计并审核固定 TLS、Keyring child、clean environment、IPC、deadline、kill 和 cleanup；
4. 新增 external-approved 状态迁移与 crash-cut 测试，且不能复用 simulation approval；
5. DS 建议必须通过公开合成压力测试验证，不得直接影响 authority、release、reference 或 VM。
