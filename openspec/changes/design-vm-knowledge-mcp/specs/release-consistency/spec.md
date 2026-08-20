## ADDED Requirements

### Requirement: 单一 release manifest 绑定所有只读消费者
系统 SHALL 由一个 immutable `release_manifest.json` 绑定 application commit、content snapshot、resource inventory、页面投影、Search、MCP artifacts 和 state/recovery compatibility；它 SHALL NOT 绑定具体 recovery manifest、bundle、checkpoint ID/hash/time。一个 `active_release.json` SHALL 是唯一部署 authority。

#### Scenario: 确定性基础 snapshot 的语义增强仍 pending
- **WHEN** candidate 的页面、lexical Search 和 MCP 基础 artifact 已完成且 identity 一致，而当前 source version 的知识增强明确标记为 `pending`、`failed_retryable` 或 `blocked_policy`
- **THEN** 系统 MAY 激活完整的基础 snapshot，但 manifest SHALL 绑定该状态，Web、Search 和 MCP 均不得暴露上一 source version 的语义知识作为当前结果

#### Scenario: Candidate 内部出现部分或身份不一致 artifact
- **WHEN** 页面、Search、MCP、knowledge generation 或 resource inventory 与 candidate manifest 的 hash/identity 不一致，或声称 `ready` 却缺少已接受 generation
- **THEN** 系统 SHALL 不激活任何 candidate 部分，所有消费者继续使用 prior release

#### Scenario: Catalog active mapping 漂移
- **WHEN** release 内 Archive document active mapping 与 manifest snapshot 不一致
- **THEN** 系统 SHALL 拒绝 candidate，且不得把 catalog mapping 当作第二个全局 current pointer

#### Scenario: State-only backup 在 active release 未变时完成
- **WHEN** 每日 backup 创建新的 checkpoint/recovery manifest/receipt
- **THEN** release manifest hash、active pointer 和 snapshot SHALL 保持不变；任何具体 RM/C identity 反写 SHALL 被 schema/graph gate 拒绝

### Requirement: DeepSeek generation 必须随 snapshot 原子绑定
当 `knowledge_enrichment=ready` 时，release manifest SHALL 绑定对应 source version、IR hash、请求 model alias、官方确认的 provider revision、model-identity evidence hash、API 返回 model/system_fingerprint、prompt version、output schema version、generation ID、accepted knowledge hash 与 coverage report；编译工作区、待审核候选或后续完成结果不得旁路 release 激活直接改变线上知识。

#### Scenario: DeepSeek job 在基础 snapshot 激活后完成
- **WHEN** job 产生合法候选并完成机械验证或人工接受
- **THEN** 系统 SHALL 构建新的 enriched snapshot、重新验证 Web/Search/MCP identity 并经正常 release 激活，原 active snapshot 在切换前保持不变

#### Scenario: API 失败或证据验证失败
- **WHEN** generation 超时、返回非法 schema、span 不属于当前来源或证据冲突
- **THEN** 当前 active SHALL 保持不变，失败 generation SHALL 仅进入审计状态；任何 prior source version 知识不得静默替代当前候选

#### Scenario: Rolling alias 的实际模型身份发生漂移
- **WHEN** 请求 alias 未变，而官方 revision evidence、返回 model 或 system_fingerprint 与 manifest 预期不一致且未裁决
- **THEN** candidate SHALL 保持 `provider_identity_drift`，不得标记 ready 或混入旧 generation；新 identity contract 与 targeted recompile 形成的新 snapshot 经完整 gate 后才可激活

### Requirement: 请求级快照一致性
Web、Search 和 MCP SHALL 在每个请求开始时解析同一 active release/snapshot；页面 projection、chunks、lexical/structured indexes、knowledge、relations 和 active membership SHALL 全部属于该 snapshot，并在响应或诊断中暴露 release ID、manifest hash 和 snapshot ID。

#### Scenario: 激活发生在长请求期间
- **WHEN** active pointer 在请求处理中被新 release 替换
- **THEN** 该请求 SHALL 完成于开始时绑定的 immutable snapshot，后续新请求再解析新 active

### Requirement: 历史、废弃与引用语义一致
默认访问 SHALL 使用当前有效版本；显式历史查询 SHALL 返回 version chain/source；deprecated/tombstoned 内容 SHALL 从默认建议排除但保持历史可访问；Web、Search 和 MCP SHALL 使用同一语义。

#### Scenario: 文档被新版本替换
- **WHEN** 用户访问默认 URL、历史 URL并通过 MCP 查询同一研究
- **THEN** 默认入口 SHALL 指向新 active，历史入口 SHALL 标记 superseded，MCP SHALL 返回同一版本链和 replacement 信息

### Requirement: 审计材料不得成为平行身份
`recovery_protection_receipt`、`activation_receipt`、`failure_receipt`、灾难恢复 receipt、checkpoint receipt、备份记录和验证证据 SHALL 为 append-only 证明材料，但 SHALL NOT 定义另一个 current/version authority；release 兼容性只由 active pointer 与被指向 manifest 解析。`recovery_protection_receipt` SHALL 只绑定激活前已验证的 `R/RM/C` 与恢复保护 verdict；`activation_receipt` SHALL 仅在成功切换并完成 post-activation 验证后绑定被激活 release hash、已验证 recovery manifest hash 与结果；切换失败 SHALL 只生成 failure receipt。灾难恢复 receipt SHALL 绑定明确 release/recovery/checkpoint 与恢复结果。

#### Scenario: 审计记录与 active pointer 表示不同 prior
- **WHEN** 恢复工具读取到多条历史 activation 记录
- **THEN** 它 SHALL 要求选择明确的 prior release、验证其 manifest/state compatibility 后执行，而不得从“最新 receipt”猜测 current

#### Scenario: Receipt 被误用为 current pointer
- **WHEN** 某工具试图从最新 activation/recovery/checkpoint receipt 推断 active
- **THEN** 系统 SHALL 拒绝，并只解析 `active_release.json→release_manifest.json`

#### Scenario: 未切换成功却请求成功 activation receipt
- **WHEN** candidate 仅通过 recovery protection 校验，或 pointer/启动/post-activation 验证任一失败
- **THEN** receipt writer SHALL 拒绝成功 activation receipt；前者只可写 `recovery_protection_receipt`，后者只可写 `failure_receipt`

### Requirement: Cold recovery manifest 只能证明恢复闭包而不能成为 active authority
每个 cold recovery bundle SHALL 在 release hash 已确定后，由 immutable recovery manifest `RM` **单向**绑定一个精确 release manifest `R`、一个明确 immutable SQLite checkpoint `C`、完整 content/resource/index closure、兼容性 verdict、恢复工具、runbook 与校验摘要；`R` SHALL NOT 反向引用 `RM/C`。它 SHALL 存于生产 VM 整机之外、经 host/storage/path/backend 与生产 VM/D 不可用实测证明的独立故障域。同一 VM 的其他盘符或映射回该 VM 的路径 SHALL NOT 合格；recovery manifest SHALL NOT 充当第二个 active pointer。

#### Scenario: 从空 D 盘选择恢复包
- **WHEN** 操作者显式选择一个已验证 recovery bundle 并执行空目录恢复
- **THEN** 工具 SHALL 先验证 bundle 与 recovery manifest 的全部 hash/closure，再恢复其 release 和所选状态点，最后只通过新建的 `active_release.json` 建立当前 authority

#### Scenario: 对象清理扫描未命中 active release
- **WHEN** 某对象不被 active 引用但仍被 prior 或保留期内 recovery manifest 引用
- **THEN** GC SHALL 以 active R、prior R、全部 retained RM 与 retained C 为 roots 并沿 `RM→R/C→closure` 保留该对象；只有所有 roots 均不引用时才可清理并生成 receipt

#### Scenario: 首次 V39 handoff 缺少空 D 恢复证据
- **WHEN** D candidate 已验证，但独立故障域 attestation 或真实空 `D:\quant\quant_platform` restore receipt 缺失
- **THEN** release controller SHALL 禁止首次 production cutover、保持 C writer authority，并禁止清理 V39 ZIP、C 状态备份和旧服务材料

### Requirement: Manifest 依赖必须可机器证明无环
系统 SHALL 只允许 `active→R`、`C→captured-under R0`、`RM→R/C`、`receipt→R/RM/C/result` 的依赖方向，并 SHALL 对 JSON schema、引用图和对象 hash 运行 cycle/back-reference validation。

#### Scenario: Recovery manifest 与 release manifest 互相引用
- **WHEN** candidate graph 出现 `R→RM`、`R→C` 或由 receipt 回指 active 的边
- **THEN** validation SHALL fail closed；不得通过调整 hash 顺序、占位 hash 或二次改写规避

#### Scenario: Candidate 使用 prior active 下取得的 checkpoint
- **WHEN** checkpoint `C` 记录 captured-under `R0`，而 candidate recovery manifest 绑定 `R1/C`
- **THEN** 系统 SHALL 在不修改 `R1` 或 `C` 的情况下验证 R1 对 C 的 state schema/read-write/restore compatibility；通过后 RM MAY 绑定二者，否则 candidate SHALL 被拒绝

### Requirement: 动态 recovery protection 必须按 checkpoint 实际年龄计算
State-only job SHALL 至少每 24 小时新建 immutable `C/RM/receipt` 并引用当时 current R，复用静态 closure但 SHALL NOT 改 release/active 或触发代码发布。`recovery_protection_status` SHALL 从最后一个 retained、closure 可读且完全验证 checkpoint 的 `captured_at` 推导。

#### Scenario: Checkpoint 超龄或最新任务失败
- **WHEN** `now-captured_at` 超过目标 RPO，或最近任务失败且没有新的完全验证 checkpoint
- **THEN** 状态 SHALL 为 `degraded`、告警并禁止声称 RPO 达标；不存在有效 checkpoint、closure/attestation 无效或恢复验证失败时 SHALL 为 `failed`

#### Scenario: 新 checkpoint 成功但 release 未变
- **WHEN** state-only job 在同一 R 下生成 C2/RM2/receipt2
- **THEN** active 仍 SHALL 指向同一 R，C1/RM1 在保留期内仍受 GC 保护，recovery protection MAY 依据 C2 的 captured_at 恢复为 protected

### Requirement: Public 到 Private 转换必须发生在最终证书之后
仓库在 Stage 0–5 SHALL 保持 Public；只有全部功能、部署、D prior rollback、cold recovery、空 D 恢复和最终 release certificate 通过后才可转为 Private，转换后 SHALL 重新验证 GitHub plan、Actions、branch/environment protection、CI、publish CLI 权限和 exact-SHA candidate。

#### Scenario: Stage 5 尚未形成最终证书
- **WHEN** 任一功能、回退或恢复门禁未通过
- **THEN** 仓库 SHALL 保持 Public，且不得把可见性切换当作解决部署配置问题的手段

#### Scenario: 仓库已转为 Private
- **WHEN** 可见性变更完成并准备关闭项目
- **THEN** 系统 SHALL 至少完成一次 Private 状态 CI 与一次不切生产的 exact-SHA candidate 演练并保存 visibility-transition receipt，任一失败 SHALL 阻止最终关闭
