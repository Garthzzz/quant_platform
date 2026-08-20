## ADDED Requirements

### Requirement: 两族 comment 使用 release 外持久权威
系统 SHALL 在固定 D state root 的外置 SQLite 中分别保存 Archive comment 与 Workspace comment 的当前状态、事件、revision、actor、时间和幂等语义；release 替换不得覆盖这些数据。

#### Scenario: 跨版本评论存续
- **WHEN** 用户在版本 A 创建、编辑或软删除评论后部署版本 B并回退 A
- **THEN** 两族 comment 的当前状态、revision、事件、作者和时间 SHALL 保持一致

#### Scenario: 线上评论为空
- **WHEN** 首次迁移的两族 comment 都是空集
- **THEN** 系统 SHALL 仍验证 schema、写入/编辑/软删除 fixture、备份与恢复，但不得据此引入不必要的 PostgreSQL 依赖

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
候选验证 SHALL 使用 SQLite online backup 副本或可回滚的隔离数据库，且 SHALL NOT 对 active comment/workspace 文件执行 canary 写入。

#### Scenario: Candidate 验证评论适配器
- **WHEN** candidate 需要验证 create/edit/soft-delete、CAS 和幂等
- **THEN** 所有写入 SHALL 只发生在隔离副本，验证结束后 active 数据的 hash/逻辑状态保持不变

### Requirement: 备份恢复与非 comment 状态保护
系统 SHALL 对 comments/workspace 数据库执行一致备份、integrity、foreign key、schema、核心计数和恢复验证；progress、workspace node/observation/event 等非 comment 状态也 SHALL 位于 release 外且不得被 seed 覆盖。

#### Scenario: 非空外置库遇到新 release seed
- **WHEN** 新 release 包含初始化 seed 而外置数据库已有业务数据
- **THEN** 系统 SHALL 保留外置库并拒绝覆盖，Dashboard 和 Workspace 现有状态继续可读写

### Requirement: PostgreSQL 采用观测触发而非本版前置
系统 SHALL 仅在多正式 writer、持续 SQLite 锁争用、集中 HA/PITR/RPO/RTO 或经恢复演练证明的瓶颈出现时另立 PostgreSQL 迁移 change；已安装 PostgreSQL 或参考项目采用 PG 不构成触发条件。

#### Scenario: 触发条件均未成立
- **WHEN** 系统仍是单 VM、低并发且 SQLite 备份恢复满足门禁
- **THEN** 本版 SHALL 继续以 SQLite 为 comment authority，且发布、parser 和 MCP 不得等待 PG

### Requirement: SQLite schema 必须前向演进且兼容 prior rollback
每个 release manifest SHALL 声明其可读与可写 SQLite schema 范围；schema 变更 SHALL 采用 expand-compatible-contract，且 candidate 激活前 SHALL 同时证明 candidate 与 prior release 都能对升级后的当前状态安全读写，或提供经过验证的兼容适配层。

#### Scenario: Candidate 需要扩展 SQLite schema
- **WHEN** 新 release 增加表、列或约束并准备升级 release 外状态库
- **THEN** 系统 SHALL 先执行可重复、前向兼容的 expand，验证 candidate 和 prior 的 read/write compatibility 后才允许激活，且不得在仍需 prior rollback 时执行破坏性 contract

#### Scenario: 正常代码回退发生在 schema 升级之后
- **WHEN** active release 回退到 D 盘 prior release
- **THEN** 回退 SHALL 继续使用当前 D state，不得自动降级 schema 或恢复旧状态备份；若 prior 不兼容，candidate 在激活前即 SHALL 被拒绝

### Requirement: 状态恢复点只用于明确的灾难恢复
发布系统 SHALL 通过 SQLite online backup 生成新的 immutable checkpoint 并校验 integrity、foreign key、schema、核心计数和可恢复性；checkpoint/receipt SHALL 记录 `captured_at` 与当时 current release hash，但 SHALL NOT 修改 release manifest/active pointer。只有写入生产 VM 整机之外、通过 failure-domain attestation 的 `RECOVERY_ROOT` 并完成恢复校验后，checkpoint 才可声明为 disaster-recovery protected。除 publish 与 schema 迁移前后外，一个 state-only backup job SHALL 至少每 24 小时运行且不得阻塞在线写入。正常 release rollback SHALL NOT 倒退状态，只有状态损坏或空盘灾难恢复才可由操作者显式选择恢复点。

#### Scenario: D state 损坏且无法原地修复
- **WHEN** 操作者声明进入 disaster recovery 并选择一个已验证 checkpoint
- **THEN** 恢复流程 SHALL 展示该恢复点时间与数据损失边界、先隔离损坏状态、校验恢复副本后再启用，且不得把普通代码回退隐式升级为状态回滚

#### Scenario: 外部恢复根暂时不可用
- **WHEN** state-only backup 无法写入或校验 `RECOVERY_ROOT`，或最后成功验证 checkpoint 的 `now-captured_at` 已超过 24 小时
- **THEN** 在线 comment/workspace 写入 SHALL 继续，系统 SHALL 把 recovery protection 标为 `degraded`、产生可见告警并持续重试，且 release certificate 不得声称当前 RPO 门禁通过；不存在有效 checkpoint/closure 时 SHALL 标为 `failed`

#### Scenario: 首次切换前只有同 VM checkpoint
- **WHEN** SQLite backup 完整但只存在生产 VM 的另一盘符或映射回本机的共享路径
- **THEN** 它 SHALL NOT 满足 cold recovery 或首次 production cutover 门禁，V39 ZIP、C 状态备份和旧服务材料 SHALL 继续保留

### Requirement: 非空 comment 生命周期必须完成浏览器与数据库联合验收
验收 SHALL 使用真实非空 fixture，覆盖写入 document comment、可重定位 block comment 与将失效 span comment，随后发布新代码、修订并移动 source、回退 release、再次读取；不得只检查 SQLite 文件存在或行数。

#### Scenario: 完整跨版本序列结束
- **WHEN** 执行“写 comment → 发布新代码 → 修订/移动 source → renderer 展示 → 回退 release → 再读取”
- **THEN** 浏览器 SHALL 显示 document、resolved 与 unresolved/history comments 的正确位置和状态，数据库 SHALL 证明 current/event/revision/actor/time 未丢失或被 projection 改写，且错误自动挂接数为 0
