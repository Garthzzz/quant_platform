## ADDED Requirements

### Requirement: 兼容基线必须先于知识增强完成 VM 纵切
系统 SHALL 在依赖通用 parser、MCP、vector 或 PostgreSQL 之前，以现网 V39 的完整代码、页面、数据和 Git 外资源建立 D 盘不可变候选及可启动的 D 盘回退版本。

#### Scenario: D 盘为空且 Git 不包含大对象
- **WHEN** 首次候选从空 D 盘开始构建
- **THEN** 系统 SHALL 按冻结 inventory 搬运并校验 PDF、图片、对象、内容数据库、Paper Lab、模板和静态资源，而不是把 Git checkout 当作完整迁移

#### Scenario: 兼容候选出现前端差异
- **WHEN** V39 基线与 D 候选存在未授权视觉、DOM 或交互差异
- **THEN** 系统 SHALL 拒绝候选，且不得以通用 renderer 或新知识功能解释该差异

### Requirement: 精确提交与受控发布入口
系统 SHALL 只通过受控单命令 `publish` 将完整 commit SHA 与本地冻结的非 Git source/resource inventory 绑定为不可变 candidate，经同一 SHA 的本地检查和 GitHub CI 后才允许上传；系统 SHALL NOT 在 active 运行目录执行 `git pull`，本版 SHALL NOT 实现裸 push watcher、部署 hook、self-hosted runner 或 bare receive。

#### Scenario: CI 通过的 SHA 与候选不一致
- **WHEN** GitHub CI 结果、tracked tree 或冻结 source inventory 不属于同一 candidate manifest
- **THEN** 系统 SHALL 拒绝上传或激活并保持 active 不变

#### Scenario: 多次快速 publish
- **WHEN** 一个部署正在切换且多个更新等待
- **THEN** 系统 SHALL 保持运行中部署不取消、只保留最新 pending main candidate，并明确记录被替换的 pending，而不得声称所有 commit FIFO 部署

### Requirement: 单一 active authority 与原子回退
系统 SHALL 只以 `active_release.json` 指向一个 immutable release manifest；release manifest SHALL 只绑定代码、内容、资源、索引、知识和 state/recovery compatibility，SHALL NOT 引用具体 recovery manifest、bundle 或 checkpoint。切换 SHALL 串行、同卷原子替换，并预先确认 D 盘 prior release 与同一 D state 兼容。

#### Scenario: 新 release 启动后健康检查失败
- **WHEN** candidate 未在时限内返回正确 release/manifest 身份或关键功能失败
- **THEN** 系统 SHALL 停止 candidate、恢复 prior active pointer、以同一 D state 启动 prior 并写入失败审计事件

#### Scenario: Active 文件损坏
- **WHEN** 启动器无法验证 active 文件的 schema、路径或 manifest hash
- **THEN** 系统 SHALL fail closed，并仅允许从 append-only activation audit 中选择明确 prior release 执行恢复命令

#### Scenario: 发布或备份试图回写 release identity
- **WHEN** recovery builder、state-only backup 或 receipt 试图把具体 recovery/checkpoint ID、hash 或时间写回 release manifest/active pointer
- **THEN** schema/graph gate SHALL 拒绝该操作，release hash 与 active identity SHALL 保持不变

### Requirement: C 到 D 的单一状态权威切换
系统 SHALL 让隔离候选只使用状态副本。首次 handoff SHALL 在外部流量/写入 fence 内停止旧 C writer、取得最终一致备份并启动已验证的 D exact-V39 baseline；若 D 尚未接收任何外部写入且 baseline 失败，可恢复未变化的 C。D baseline 通过并开放流量后 SHALL 禁止 C 服务再次写入，后续回退 SHALL 只使用 D prior release 和同一 D state。

#### Scenario: 首次 D baseline 启动失败
- **WHEN** 最终状态已复制但 D baseline 在开放外部流量前失败
- **THEN** 系统 SHALL 证明 D 没有外部写入、丢弃失败副本并恢复原 C authority；不得把不存在的 D prior 当作回退目标

#### Scenario: 旧 C 服务试图在切换后重启
- **WHEN** D state 已成为 authority 而旧 C 服务被启动
- **THEN** writer fence/服务配置 SHALL 阻止其写入并产生可见告警，不得形成双写

### Requirement: 自动 cold recovery bundle
每个 production candidate 在激活前 SHALL 先冻结 immutable release manifest `R`，再形成不含 secret 的 machine-verifiable cold recovery bundle：immutable checkpoint `C` 记录 captured-under active release，`recovery_manifest RM` 单向引用 candidate `R`、明确 `C` 与完整 closure；`R` SHALL NOT 反向引用 `RM/C`。最终 `RECOVERY_ROOT` SHALL 位于生产 VM 整机之外的真实独立故障域，同一 VM 的其他本地/虚拟盘符、挂载点、reparse/subst 或映射回该 VM 的共享路径 SHALL NOT 合格。bundle SHALL 覆盖精确代码/前端、release/content/resource/index closure、SQLite checkpoint、恢复工具、校验信息和 runbook。

#### Scenario: 仅把恢复根配置到同一 VM 的其他盘符
- **WHEN** `RECOVERY_ROOT` 与生产 D 盘显示为不同 drive letter，但 canonical host/storage authority 仍属于同一生产 VM
- **THEN** 系统 SHALL 拒绝 recovery-protected 状态，不得把不同盘符当作独立故障域

#### Scenario: 故障域独立性实测
- **WHEN** 发布系统准备接受最终 `RECOVERY_ROOT`
- **THEN** 它 SHALL 记录 production/recovery host identity、storage authority、volume/backend、UNC/reparse 解析和工具版本，并在生产 VM/D 测试性不可用时证明 bundle 仍可独立读取与校验，形成 failure-domain attestation

#### Scenario: 活动 D 盘及对象库全部丢失
- **WHEN** 操作者在非生产真实空 `D:\quant\quant_platform` 目标选择一个 retained recovery manifest 和 state checkpoint
- **THEN** 系统 SHALL 仅凭 bundle 与受保护运行配置恢复完整站点、资源、Search/MCP、SQLite 状态并通过 hash/schema/浏览器/API 验证

#### Scenario: Bundle 包含 secret 或缺少对象
- **WHEN** no-secret scan、manifest closure、文件 hash 或 SQLite checkpoint 任一验证失败
- **THEN** candidate SHALL 不得获得 recovery-protected 状态或进入生产激活

#### Scenario: 激活前只记录 recovery protection
- **WHEN** candidate `R` 的 `RM→R/C` closure 已在独立故障域通过校验，但 active pointer 尚未切换
- **THEN** 系统 SHALL 只生成 `recovery_protection_receipt` 并绑定 `R/RM/C` 与 pre-activation verdict，SHALL NOT 生成或记录成功 `activation_receipt`

#### Scenario: 成功切换后记录 activation
- **WHEN** active pointer 已原子切换到 candidate，candidate 启动且 post-activation health、关键功能与 writer fence 全部通过
- **THEN** 系统 SHALL 生成成功 `activation_receipt` 并单向绑定被激活 `R`、已验证 `RM` 和切换后结果，但 SHALL NOT 把 receipt 用作 active pointer

#### Scenario: 切换失败只记录 failure
- **WHEN** pointer 切换、启动或任一 post-activation 验证失败
- **THEN** 系统 SHALL 回退明确 prior 并只生成 `failure_receipt`，记录 candidate/prior、失败阶段、错误和回退结果；SHALL NOT 生成或保留成功 activation receipt

### Requirement: State-only backup 不得改变 release 且 RPO 按实际年龄退化
唯一 state-only job SHALL 至少每 24 小时运行，每次成功 SHALL 创建新的 immutable checkpoint、单向引用当前 release 的 recovery manifest 和 receipt；它 SHALL NOT 改写 release manifest/active pointer 或要求代码重新发布。Recovery protection SHALL 由最后一个 retained、closure 可读且完全验证 checkpoint 的 `captured_at` 实际年龄计算。

#### Scenario: 每日备份在同一 active release 下连续成功
- **WHEN** 两次 state-only job 在代码/内容 release 未变化时完成
- **THEN** 系统 SHALL 保留同一 active release hash，并产生两个不同 immutable checkpoint/RM/receipt；旧 retained checkpoint 仍是 GC root

#### Scenario: 最新成功 checkpoint 超过 RPO
- **WHEN** `now - captured_at` 超过 24 小时，或最近一次任务失败而没有新的完全验证 checkpoint
- **THEN** recovery protection SHALL 明确为 `degraded` 并告警/重试，不得声称 RPO 满足；若不存在有效 checkpoint、closure/attestation 无效或恢复验证失败则 SHALL 为 `failed`

### Requirement: V39 空 D 恢复是首次生产切换前置门禁
首次 C→D handoff 前，系统 SHALL 在 host identity 与生产 VM 不同的独立非生产恢复主机或隔离 VM 的真实空 `D:\quant\quant_platform`，仅凭已 attested `RECOVERY_ROOT` 中的 V39 bundle、受保护运行配置与 runbook 恢复完整站点并通过 hash/schema/browser/API 验收；未通过时 SHALL NOT 开放 D 生产流量或转移 writer authority。

#### Scenario: D baseline 副本验证通过但未做空盘恢复
- **WHEN** V39 candidate 在 D staging 可启动，而 failure-domain attestation 或真实空 D restore receipt 缺失
- **THEN** 系统 SHALL 只允许继续隔离验证，禁止首次 production cutover，并继续保留 C writer authority

### Requirement: 恢复材料与对象清理受 manifest 保护
首次迁移的 V39 ZIP、C 状态备份和旧服务材料 SHALL 从设计实施开始持续保留，至少到 failure-domain attestation、V39 空 D 恢复、D active 与 D prior rollback 全部通过；任一未通过时 SHALL NOT 清理。对象清理 SHALL 把 active、prior 和 retained recovery manifests/checkpoints 作为根。

#### Scenario: 清理器发现 recovery manifest 仍引用对象
- **WHEN** 一个对象不再被 active 使用但仍被 prior 或 retained cold bundle 引用
- **THEN** 清理器 SHALL 保留该对象并不得以“可重建”为由删除

### Requirement: Public 到 Private 的最终门禁
GitHub repository SHALL 在 Stage 0–5 保持 Public，同时阻止 reference、内部研究、PDF、数据库、对象、secret 和生成状态进入 Git；仅在 Stage 5 release certificate 后 SHALL 转为 Private。

#### Scenario: Repository 已转换为 Private
- **WHEN** Stage 5 certificate 后完成可见性转换
- **THEN** 系统 SHALL 重新核验实际 plan、Actions、branch/environment protection、CI、publish CLI 权限和 exact-SHA candidate，并完成一次 Private CI 与无生产切换候选演练后才允许项目关闭
