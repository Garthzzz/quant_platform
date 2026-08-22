# MCP、RAG 与语义数据库压力测试及优化记录（2026-08-22）

## 放行结论

本轮公开、离线压力迭代已经完成。MCP、RAG、语义任务数据库、semantic authority 与零网络 DS 合成评审机制均通过独立复核，最终 `Blocker / High / Medium = 0 / 0 / 0`。跨模块公开回归为 `189 passed + 121 subtests`。

该结论只覆盖本文列明的本地公开机制与合成压力矩阵，不替代 sealed holdout、真实生产发布、VM 恢复资格或真实外部模型验收。

## 范围与不变量

- 基线提交：`f7f9d5c675a1c0fbc5cd0965f815a39acbdcfaa0`；基线 CI run `32553816556` 为 success。
- 本轮没有登录或写入 VM，没有修改服务、端口、部署、生产 SQLite 或 semantic authority。
- `reference/**` 与 `D:\quant\industry_demo/**` 保持只读；规模测试只读编译 `reference/archive`，未改原文。
- 未读取、列举或搜索 sealed holdout、私有 qrel、逐题 trace 或历史 stage evidence。
- 没有 commit、push、release、promotion 或生产切换。
- 中文 Markdown、表格与中英技术术语边界沿用 `quant-latex-chinese` 的 Web/中文排版原则；本轮不引入 LaTeX/PDF 编译链。

## MCP：协议、分页、并发与镜像恢复

### 关闭的问题

1. stdio 与 `tools/call` 运行时原先未完整执行 schema：超长 query/cursor/context、深层对象和未知字段可穿过。
2. search 会向索引请求全部 records，再在服务层截页；updates 会先构造完整差异表，深页内存与延迟随总量或 offset 放大。
3. 多个 stdio 进程共享 mirror 时，current、pending 与 acknowledged 指针可交错写坏。
4. lock、partial、AV sharing failure、非法 UTF-8、内部异常去敏和伪造 continuation 的边界不完整。

### 实现后的机械合同

- stdio 单行上限 256 KiB；query 500 字符；对象/快照 ID 200；cursor 4,096；context canonical JSON 16 KiB、深度 32；所有参数和 context 字段 closed。
- continuation 使用 session-bound HMAC，绑定类型、快照、排序键和边界；bool、伪造 offset、跨会话重放和超界均拒绝。
- search 只请求 `offset + limit + 1` 的必要窗口，服务层只投影当前页及所需 citation material。
- updates 改为按稳定键有序 merge 和 keyset continuation；保留 exact total/summary，但内存窗口只保留 `limit + 1`。
- MirrorStore 使用进程内全局锁与 Windows 跨进程 byte-range lock；current/pending/ack 以复合一致视图读写，并覆盖持锁 kill、pending→current kill 与 response-loss 恢复。
- lock 路径、artifact、pointer 和 partial 均做 containment、reparse/hardlink、身份与 closed-shape 检查；原子写执行 fsync 和有限 AV sharing retry。

### 压力证据

| 压力项 | 结果 |
|---|---|
| 2 / 8 / 32 进程并发 mirror | 全部成功，最终状态一致 |
| 持锁 kill、transition kill | 重启后机械恢复 |
| 10² / 10³ / 10⁴ / 10⁵ records，1,000 次 hot query | `limit=3` 时索引只请求 4 张 |
| 10⁵ 相对 10² 延迟 | median `1.016×`，P95 `1.006×` |
| 10k→100k 固定结果请求峰值内存 | `24,624→24,624 bytes`，`1.00×` |
| 1,000 次查询后 GC RSS | `+0.015%` |
| 深页、伪 cursor、非法 UTF-8、持续 AV failure | 全部受控拒绝或恢复 |

独立 MCP 压力复核：`45 passed + 15 subtests`，`Blocker / High / Medium = 0 / 0 / 0`。

## 语义任务数据库与 authority

### 关闭的问题

- queued→running 缺少 claim fencing；旧父进程可能清理新 worker 的 claim，或在新 worker 成功后 disqualify 新 generation。
- `commit_generation` 的 `INSERT OR IGNORE` 可在 generation ID 冲突时留下跨 job/version 的 candidate，并把错误 job 标成 succeeded。
- item state 缺行、非法状态、跨表 version/job 不一致可能在 authority 层未被发现。
- 首次 promotion 在 replace 与 receipt 之间被 kill 后不可重试；partial 与首次 receipt 目录并发初始化缺少完整恢复。

### 实现后的机械合同

- claim token 从 parent claim、child 环境、stdout reconstruction 到 final CAS 全链绑定；token 不进入异常、audit 或持久化明文。
- generation/candidate/item 使用 strict insert；任何 collision、job/version 不一致或 final CAS 丢失都回滚整个事务。
- 旧 parent reconcile 只能操作其原 claim attempt；不能清除或 disqualify 后续 worker。
- generation 只接受终态；item mutable state 只允许正式 `deprecated` 转换。
- authority 校验八表 schema、状态集合、完整 FK、job/generation/candidate/item 跨表身份和 item-state 精确集合等式。
- 旧六表只在首次迁移时为既有正式 item 回填 state；后续缺行绝不自愈，读取、snapshot、promotion、verify 全部 fail closed。
- promotion lock、target/receipt replace、首次与 rotation kill-cut、partial 清扫均支持同身份恢复，异身份拒绝。

独立数据库/authority 复核覆盖 16 threads、8 spawn、generation collision、late reconcile、伪 child、首次/轮换 promotion kill、8 进程首次 promotion 和 state 缺失攻击；结果 `52 passed + 6 subtests`，`Blocker / High / Medium = 0 / 0 / 0`。

## RAG：查询安全、对比语义、Unicode 与性能

### 查询与检索合同

- index identity 提升至 `qrh-structured-lexical-index/v1.15-bounded-query-input`；旧 v1.14 index 与 v2 retrieval schema fail closed。
- query 限 1–500 字符且必须是有效 UTF-8；limit、bool 与 score/coverage 使用 exact type 和有限数值检查。
- TaskContext canonical JSON 不超过 16 KiB、每值不超过 500 字符、总值不超过 64；空值与 canonical duplicate 拒绝；context 在查询入口只规范化一次。
- contrast 拒绝在 record、canonical、cluster、relation 与 exact source evidence 间做有界闭包，但不会把同 carrier chunk 内不相干的 sibling locator 一并否定。
- formal/source bridge、explicit kind、strong document 与 exact identifier 的低 floor 只能在 query-level support 成立时启用；未知 lowercase、snake、alias 附着与 generic kind 不能借路由放大。
- 受控 `IC/RankIC` 公式支持 `t/T`、数字、有限 Unicode 下标和既有 separator alias；未知后缀、Greek 邻接、全角/同形/组合字符与不可见分隔均 fail closed。

### 输入攻击闭合

以下未知命名变体全部 `answerable=false`、零卡，并保持 direct/artifact parity：

- mixed-case、accent、combining、fullwidth、Cyrillic lookalike；
- ZWJ、ZWSP、soft hyphen、VS16、word joiner、circled letters；
- NUL、DEL、NEL、NBSP、Unicode line separator；
- query/context surrogate，以及超大整数、NaN、Inf。

合法 `IC_t`、`IC_T`、`RANKIC_{T}`、`IC_7`、`RankIC_{123}`、`ICₜ`、`IC₁₂₃` 与受控英文 separator aliases 均保持可答和 direct/artifact parity。

### 规模与性能证据

只读 `reference/archive` 规模为 44 documents、8,295 records：

| 指标 | Direct | Artifact |
|---|---:|---:|
| 构建/加载 | build `31.065s` | artifact build `9.766s`，load `24.999s` |
| 65 次公开查询 median | `56.352 ms` | `64.055 ms` |
| 65 次公开查询 P95 | `190.092 ms` | `188.724 ms` |
| traced peak | `134,598,211 bytes` | `98,898,088 bytes` |
| FTS footprint | `13,594,624 bytes` | `13,594,624 bytes` |

2,001-record context 放大反例修复后：

| 输入 | Direct median | Artifact median |
|---|---:|---:|
| 空 context | `17.651 ms` | `19.302 ms` |
| 64 个唯一值，15,876-byte JSON | `20.674 ms` | `24.018 ms` |
| 65 个值 | `0.068 ms` 入口拒绝 | `0.035 ms` 入口拒绝 |

最终 RAG 独立复核重放所有 Unicode、公式、contrast、relation、source bridge、旧版本与性能反例，结论 `Blocker / High / Medium = 0 / 0 / 0`。

## DS V4 Pro 合成评审机制

用户要求与 DS V4 Pro 多轮讨论。本轮先完成的是可审计、零网络的四轮合成讨论机制，而不是伪称已经发生真实外部调用：

1. Round 1：匿名机制与风险类别 blind review；
2. Round 2：公开合成 stress matrix critique；
3. Round 3：只提供枚举 outcome，要求最小修订与更强 oracle；
4. Round 4：结构化 final dissent，始终为 `ADVISORY_ONLY`。

机制固定 canonical campaign manifest、四个 request hash、provider pin hash、90 秒总 deadline 与 SQLite `BEGIN IMMEDIATE` / CAS / consumed ledger。PreparedReview 只暴露 canonical bytes、hash 和不可变标量；duplicate key、深度 5,000、secret/path/name/identity、非 ASCII、异 provider pin、跨 ordinal 重放、8 进程竞争和 kill/restart 全部有公开反例。

为了保证不接触凭据，本构建刻意不含 HTTP、socket、TLS、Keyring、环境变量、subprocess 或 transport 注入面；external review/claim 无条件不可达。独立 DS harness 复核为 `19 passed`，36/36 secret/path/name 边界拒绝，`Blocker / High / Medium = 0 / 0 / 0`，且 `network_calls=0`。

真实 DS V4 Pro 外呼仍需要新的独立变更：批准的真实 fingerprint pin、非敏感 Keyring service/username、隔离 child、固定 host/path、TLS、IPC、总 deadline、kill/cleanup 与 external-approved CAS。当前没有读取任何凭据，也没有把合成 dry-run 冒充真实讨论结果；该外部分支不阻塞本地 MCP/RAG/数据库优化。

## 统一验证

- GitHub Actions `public-safe unit tests` 同款模块清单：`487 tests PASS`，耗时 `189.516s`。
- 跨模块公开回归：`189 passed + 121 subtests`，耗时 `86.66s`。
- RAG/MCP 关联回归：`83 passed + 52 subtests`。
- `py_compile`：通过。
- `git diff --check`：通过。
- all-scope git boundary gate：`480 files`，无 failure。
- 本地 pyproject wheel 构建：`quant_research_hub-0.1.0-py3-none-any.whl`，`1,036,589 bytes`、216 entries，最终 SHA-256 `92b2865f…91519`；11 个关键代码/模板/schema 均存在并可隔离导入。
- wheel 私有数据负断言：开发树中实际存在的 4 个 ignored presentation JSON 与整个 ignored supplements Markdown 子树均为 0 entries。构建钩子还会清除旧 build tree/egg-info 带来的 stale data，并对 reparse/越界 fail closed；CI 对 JSON 与 Markdown sentinel 做同样反证。
- wheel 独立复核：216 entries；131 个 public runtime Python 源、23/23 package-data、57/57 data-files 全部存在；隔离 venv 遍历导入 130 个子模块，0 failures；`Blocker / High / Medium = 0 / 0 / 0`。
- 独立审核：MCP、语义数据库/authority、RAG、DS 合成 harness 均为 PASS，且各自 `Blocker / High / Medium = 0 / 0 / 0`。

## 尚未由本记录放行的事项

- 不宣称 sealed holdout 或私有质量 gate 已通过；这些必须由全新、一次性、未见公开开发集的独立 suite 执行。
- 不宣称真实 DS V4 Pro 外呼已完成。
- 不宣称 VM、生产 authority、release、恢复资格或部署已改变或重新放行。
- 不把当前工作树的公开压力候选冒充已 commit、已 push 或已发布版本。
