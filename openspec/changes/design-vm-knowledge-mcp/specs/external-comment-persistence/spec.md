## ADDED Requirements

### Requirement: 两族 comment 使用 release 外持久权威
系统 SHALL 在固定 D state root 的外置 SQLite 中分别保存 Archive comment 与 Workspace comment 的当前状态、事件、revision、actor、时间和幂等语义；release 替换不得覆盖这些数据。

#### Scenario: 跨版本评论存续
- **WHEN** 用户在版本 A 创建、编辑或软删除评论后部署版本 B 并回退 A
- **THEN** 两族 comment 的当前状态、revision、事件、作者和时间 SHALL 保持一致

#### Scenario: 线上评论为空
- **WHEN** 首次迁移的两族 comment 都是空集
- **THEN** 系统 SHALL 仍验证 schema、写入/编辑/软删除 fixture 与候选隔离副本，但不得据此引入不必要的 PostgreSQL 依赖

### Requirement: Comment target 与跨版本锚点必须稳定且可见
Document-level comment SHALL 绑定 release/path 无关的 stable research/document identity。Block/span comment SHALL 永久保存 origin source version、block type、精确 span/bytes hash、结构上下文与 locator schema；自动重定位只允许 exact unique match 或经 hash 验证的一对一 unchanged-block mapping，SHALL NOT 使用 fuzzy/embedding similarity 自动挂接。每个 snapshot 的 anchor projection SHALL 与 comment current/event 分离。

#### Scenario: Source 修订后 anchor 可唯一证明未变
- **WHEN** 同一 stable document 的新 version 中，原 span bytes/hash 唯一出现且 block type/结构上下文一致
- **THEN** projection MAY 把 comment 标为 `resolved_current` 并显示在该 block；该投影 SHALL NOT 改写 comment revision、actor 或时间

#### Scenario: Source 修订后 anchor 消失或出现多个候选
- **WHEN** 原 span 被改写、删除或存在多个同样候选，无法确定性证明唯一对应
- **THEN** comment SHALL 在原历史版本继续可见，并在当前 document 的 unresolved/ambiguous 区域显示原 version/locator 与原因，不得静默消失或附着到相似段落

#### Scenario: 纯移动、renderer 更新或代码回退
- **WHEN** source bytes 纯移动、generic renderer 更新或 active 回退到 D prior release
- **THEN** stable document-level comments SHALL 仍可见；block/span comments SHALL 依据该 snapshot projection 正确定位或进入 unresolved，current/event/revision/actor/created_at/updated_at SHALL 保持不变

### Requirement: 候选不得探测写入 active 状态
候选验证 SHALL 使用 SQLite online backup 生成的 D-root 隔离副本或其他可证明隔离的临时数据库，且 SHALL NOT 对 active comment/workspace 文件执行 canary 写入。隔离副本只用于候选验证，不是状态历史版本或发布身份的一部分，验证终态后 SHALL 清理。

formal candidate/prior 验证 SHALL 在 B2 global lock 下先关闭 D runtime ingress/writer，再由同一 attempt workspace 取得两库 `LockedStateSqliteSource` 与 memory view；producer SHALL 从本次 live exact-release closures 内部重建 compatibility，并将整个 transient application 的 comment/workspace连接固定到 role-local copies。允许 closed document 重建的 state seal、copy evidence、compatibility evidence set 或调用者路径 SHALL NOT 作为 live producer 输入。

#### Scenario: Candidate 验证评论适配器
- **WHEN** candidate 需要验证 create/edit/soft-delete、CAS 和幂等
- **THEN** 所有 candidate 验证写入 SHALL 只发生在同一 durable attempt、全局锁和 nonce 绑定的 D-root 隔离副本；连接/path spy 与业务事件审计 SHALL 证明 candidate 未写 active 数据。仅作 candidate-only 诊断、不产生激活资格时，合法线上 writer 的并发业务变化可以继续存在，不得用要求 active 文件物理 hash 恒定来误判或覆盖这些写入；该诊断结果不得被提升为正式 source seal 或 qualification token

#### Scenario: Persistent evidence 冒充 live canary input
- **WHEN** 调用者提供 fully re-signed state seal、isolated copy、上游 closure 已关闭但仍可读的 compatibility evidence set，或把任一 source/path/runtime 注入 producer
- **THEN** formal producer SHALL 在产品签名和 exact-type gate 拒绝；它只可从本次同 epoch release closures、state source 和 memory view 现场形成 request/copy evidence

#### Scenario: Transient 普通应用 route 试图打开 active state
- **WHEN** transient candidate/prior child 的 canary endpoint 之外任一应用组件初始化或收到请求
- **THEN** 最外层默认关闭的admission gate SHALL在Flask/session/业务handler之前固定503拒绝普通route；若内部初始化仍需连接，comment与workspace SHALL只解析到相同role-local copies，active D state保持source-fenced read-only；任何回落到生产comment/workspace path的连接 SHALL终止该transient qualification

#### Scenario: Steady RUNNING 但尚未完成 promotion-bound admission commit
- **WHEN** steady child 已监听并报告 RUNNING，但 SCM/endpoint/writer 全链、final facts、job promotion、PREPARE、closed-state readiness acknowledgement 或最终COMMIT任一尚未完成
- **THEN** `/`、login/logout、全部业务API与comment/workspace写入 SHALL在`closed_pending_promotion`与`ack_pending`两态由最外层固定503，且两库current/event/revision/count零变化；只有exact loopback `/deploymentz`可用于现场链。fresh readiness acknowledgement成功后仍不得写业务，直至同一pipe的exact COMMIT+EOF使gate原子进入`admitted`

#### Scenario: Canary copy 在写验证期间发生 main replacement
- **WHEN** role-local SQLite main 合法发生同文件事务写，或出现 main delete/rename/replacement、checkpoint 后 WAL/SHM/rollback journal 残留
- **THEN** mutable B2 guard SHALL 只允许前者，并以 open-instance identity 拒绝后者；CREATE_NEW creator handle SHALL 在首次 syscall 前由 workspace 登记，直接承担全量写／flush／identity proof 与后续 guard authority，直到 canary close 都不得出现 writer close→guard reopen 空窗
- **AND** 不得使用把合法 bytes/mtime 变化误判为 drift 的 immutable pin，也不得在 acquisition/close outcome ambiguous 时释放 tracking、解锁或清理

#### Scenario: 正式资格封存必须围栏 writer
- **WHEN** controller 为激活、回退或首次 handoff 形成可授权的 current-state seal 与隔离副本
- **THEN** 它 SHALL 先取得真实 writer/traffic fence，并在只读连接关闭后证明 source main/WAL/SHM 的存在性、file identity、bytes、mtime 与 hash 前后全部一致；任一漂移或新 sidecar SHALL fail closed，不得沿用 candidate-only 诊断的并发容忍语义

#### Scenario: Candidate 声称 revision conflict
- **WHEN** exact release 先完成 canary revision `0→1`，controller 随后以 revision 0 尝试 stale `0→2`
- **THEN** exact release 的 SQL SHALL 使用 `WHERE challenge_id=? AND revision=?` 且首次 rowcount 恰为 1，controller stale SQL 的 rowcount SHALL 恰为 0，并独立读回 revision 1 与对应 append-only event；仅有预读 revision、HTTP 409 或 self-reported boolean SHALL NOT 构成 CAS 证据

#### Scenario: 隔离副本清理失败
- **WHEN** candidate 已完成或失败，但其 D-root 临时数据库、WAL/SHM 或工作目录仍存在
- **THEN** 当前 active SHALL 保持不变，发布 SHALL 标记 cleanup 未闭合并阻止下一次 candidate；不得把该副本保留为可选状态版本

### Requirement: 非 comment 状态也必须位于 release 外并保持完整
progress、workspace node/observation/event 等非 comment 状态 SHALL 与两族 comment 一样位于固定 D state root，不得被 release seed、candidate 或普通回退覆盖。系统 SHALL 对 active 数据执行只读 integrity、foreign key、schema、核心计数与逻辑摘要检查；需要写入 fixture 时 SHALL 只使用隔离副本。

#### Scenario: 非空外置库遇到新 release seed
- **WHEN** 新 release 包含初始化 seed 而外置数据库已有业务数据
- **THEN** 系统 SHALL 保留外置库并拒绝覆盖，Dashboard 和 Workspace 现有状态继续可读写

#### Scenario: Active 数据完整性检查失败
- **WHEN** 当前 state 的 SQLite integrity、foreign key、schema 或核心逻辑摘要无法通过
- **THEN** candidate 激活与本地 prior 回退 SHALL fail closed；系统不得通过替换旧副本、选择更早 release 或重置 seed 绕过

### Requirement: PostgreSQL 采用观测触发而非本版前置
系统 SHALL 仅在多正式 writer、持续 SQLite 锁争用、集中 HA/PITR/RPO/RTO 或经真实运维证据证明的瓶颈出现时另立 PostgreSQL 迁移 change；已安装 PostgreSQL 或参考项目采用 PG 不构成触发条件。

#### Scenario: 触发条件均未成立
- **WHEN** 系统仍是单 VM、低并发且 SQLite 满足一致性与当前负载门禁
- **THEN** 本版 SHALL 继续以 SQLite 为 comment authority，且发布、parser 和 MCP 不得等待 PG

### Requirement: SQLite schema 必须前向演进且兼容 prior rollback
每个 release manifest SHALL 声明其可读与可写 SQLite schema 范围；schema 变更 SHALL 采用 expand-compatible-contract，且 candidate 激活前 SHALL 同时证明 candidate 与将成为唯一 prior 的当前 active 都能对升级后的当前状态安全读写，或提供经过验证的兼容适配层。

逻辑 schema identity SHALL 来自数据库内的正式 marker/迁移账本及 exact release 中对应迁移文件的 hash，不得把 `PRAGMA user_version` 当作唯一或替代权威。当前 comments 的 manifest 逻辑版本 SHALL 为 2，并同时绑定 `comment_store_schema=[1,2]` 与 expand-only `comment_target_schema=[3]`；扩展 marker 3 SHALL NOT 把其 manifest 逻辑版本提升为 3。当前 research workspace 的 manifest 逻辑版本 SHALL 为 3，并绑定连续 `schema_migration=1..3` 的名称和 up/down SHA-256。原始 `user_version` MAY 为 0，并 SHALL 仅作为观察字段保存。

#### Scenario: Bootstrap 兼容证据不得提前伪造 prior
- **WHEN** D active/binding 均不存在且控制器执行 `bootstrap_first_pair` 建立 R0 baseline
- **THEN** 每个数据库的 compatibility aggregate SHALL 只解析并绑定 exact R0 release closure，并把 prior 显式闭合为 absent；它 SHALL NOT 引用尚未激活的 R1、复制 R0 或伪造 prior。随后 R0→R1 SHALL 作为普通 activation，届时才同时绑定 exact R1 candidate 与 exact R0 current-active 的 read/write compatibility

#### Scenario: User version 与逻辑 schema 不同
- **WHEN** `comments.sqlite3` 或 `research_workspace.sqlite3` 的 `PRAGMA user_version=0`，但其 marker/迁移账本与 exact release migration closure 完全匹配
- **THEN** sealer SHALL 保存 raw user version 0，并按正式 marker/账本判断逻辑版本；不得把 0 判作缺失，也不得把它重写或伪报为 2/3

#### Scenario: 只读 seal 遇到 WAL state
- **WHEN** active SQLite 存在 WAL
- **THEN** sealer SHALL 在 writer fence 内验证 main/WAL/SHM 均为既存普通、非 reparse、单链接文件，以 `mode=ro` + `query_only` 完成 quick/FK/schema/marker/ledger/业务摘要检查，并在关闭后证明文件存在性、身份与字节未变；main-only 数据库 MAY 使用 `immutable=1`。sealer SHALL NOT 调用会建目录、初始化、迁移、切换 WAL 或创建 sidecar 的普通 store getter

#### Scenario: Candidate 需要扩展 SQLite schema
- **WHEN** 新 release 增加表、列或索引并准备升级 release 外状态库
- **THEN** 系统 SHALL 先执行可重复、前向兼容的 expand，验证 candidate 和 prior 的 read/write compatibility 后才允许激活，且不得在仍需 prior rollback 时执行破坏性 contract

#### Scenario: 正常代码回退发生在 schema 升级之后
- **WHEN** active release 回退到 D 盘唯一 prior release
- **THEN** 回退 SHALL 继续使用当前 D state，不得自动降级 schema、替换 SQLite 文件或恢复旧状态副本；若 prior 不兼容，candidate 在激活前即 SHALL 被拒绝

### Requirement: 本版不建立状态历史副本或定时复制承诺
系统 SHALL 只维护固定 D state authority 和候选验证所需的瞬态隔离副本；本 change SHALL NOT 建立周期性状态副本任务、状态时间点选择器或位于生产 VM D 根之外的项目状态存储。普通版本回退只切换代码/内容 release，并 SHALL NOT 倒退 comment/workspace 状态。

#### Scenario: 操作者请求用旧状态配合 prior
- **WHEN** prior release 需要旧 SQLite bytes 才能启动或操作者试图随代码回退替换当前 state
- **THEN** 系统 SHALL 拒绝；prior 必须兼容同一当前 D state，否则不得进入回退窗口

#### Scenario: State 或 D 项目根整体丢失
- **WHEN** comment/workspace authority、对象 closure 或精确 D 项目根整体不可用
- **THEN** 本地 prior 回退 SHALL 明确报告超出本 change 的能力范围，不得把 release 存在或候选隔离副本误报为数据可恢复证据

### Requirement: 非空 comment 生命周期必须完成浏览器与数据库联合验收
验收 SHALL 使用真实非空 fixture，覆盖写入 document comment、可重定位 block comment 与将失效 span comment，随后发布新代码、修订并移动 source、回退 release、再次读取；不得只检查 SQLite 文件存在或行数。

#### Scenario: 完整跨版本序列结束
- **WHEN** 执行“写 comment → 发布新代码 → 修订/移动 source → renderer 展示 → 回退 release → 再读取”
- **THEN** 浏览器 SHALL 显示 document、resolved 与 unresolved/history comments 的正确位置和状态，数据库 SHALL 证明 current/event/revision/actor/time 未丢失或被 projection 改写，且错误自动挂接数为 0
