## ADDED Requirements

### Requirement: 生产 VM 写入必须闭合在唯一 D 根
系统 SHALL 把生产 VM 的全部项目写入闭合在 `D:\quant\quant_platform`：代码 checkout、tooling、incoming/candidate、release、control、state、checkpoint/backup、audit/receipt、lock、log、TEMP/TMP 与 Python bytecode 均 SHALL 位于该根的受审查子目录；系统 SHALL NOT 向 `D:\`、`D:\quant`、其他 sibling/parent 或 C 盘新增、覆盖或修改项目内容。旧 C 盘 V39 与 `C:\quant_platform_data` 在 writer handoff 前只可作为显式只读来源。

#### Scenario: 写目标位于 D 上级、同级或 C 盘
- **WHEN** 任一发布、bootstrap、恢复、部署、服务或临时文件路径解析到精确 D 根之外
- **THEN** canonical path gate SHALL 在写入前 fail closed，active/writer SHALL 保持不变

#### Scenario: 路径文本在 D 根内但通过 reparse 逃逸
- **WHEN** 任一路径组件是 junction/reparse/subst/UNC 映射，或解析后的 physical path 不再等于批准路径
- **THEN** 系统 SHALL 拒绝该路径，不得创建 candidate、receipt 或成功审计

#### Scenario: 生产操作完成
- **WHEN** 受控操作成功或失败返回
- **THEN** 系统 SHALL 生成不含 secret 的声明 write-set 与 D-root 实际 delta 审计；任何未声明写入或无法证明的路径 SHALL 使该操作不得获成功 verdict

### Requirement: 兼容基线必须先于知识增强完成 VM 纵切
系统 SHALL 在依赖通用 parser、MCP、vector 或 PostgreSQL 之前，以现网 V39 的完整代码、页面、数据和 Git 外资源建立 D 盘不可变候选及可启动的 D 盘回退版本。

#### Scenario: D 盘为空且 Git 不包含大对象
- **WHEN** 首次候选从空 D 盘开始构建
- **THEN** 系统 SHALL 按冻结 inventory 搬运并校验 PDF、图片、对象、内容数据库、Paper Lab、模板和静态资源，而不是把 Git checkout 当作完整迁移

#### Scenario: 兼容候选出现前端差异
- **WHEN** V39 基线与 D 候选存在未授权视觉、DOM 或交互差异
- **THEN** 系统 SHALL 拒绝候选，且不得以通用 renderer 或新知识功能解释该差异

#### Scenario: 旧 C V39 仍占用生产端口时验证 D candidate
- **WHEN** 首次 handoff 或空 D 恢复验收期间旧 C writer 仍在 `8765` 提供现网服务
- **THEN** 系统 SHALL 在 `.240` 使用 D-root tooling、loopback 隔离端口和 D-root tmp 中的 SQLite checkpoint 副本启动 exact candidate，验证 release/manifest/snapshot、页面/API/资源和 legacy 行为；该 runner SHALL NOT 修改 production active pointer、生产 state、C 盘或对外 writer authority，结束后 SHALL 可审计清理自身 D-root tmp

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
每个 production candidate 在激活前 SHALL 先冻结 immutable release manifest `R`，再形成不含 secret 的 machine-verifiable cold recovery bundle：immutable checkpoint `C` 记录 captured-under active release，`recovery_manifest RM` 单向引用 candidate `R`、明确 `C` 与完整 closure；`R` SHALL NOT 反向引用 `RM/C`。最终 `RECOVERY_ROOT` SHALL 位于生产 VM 整机之外的真实独立故障域，同一 VM 的其他本地/虚拟盘符、挂载点、reparse/subst 或映射回该 VM 的共享路径 SHALL NOT 合格。bundle SHALL 覆盖精确代码/前端、release/content/resource/index closure、SQLite checkpoint、恢复工具、校验信息、runbook，以及从空 D 启动所需且不含 secret 的 operational bootstrap closure（`tooling/python`、固定控制面与 service install candidate）。受保护 access digest/API/SSH/GitHub 凭据只在恢复后重新注入。

#### Scenario: 仅把恢复根配置到同一 VM 的其他盘符
- **WHEN** `RECOVERY_ROOT` 与生产 D 盘显示为不同 drive letter，但 canonical host/storage authority 仍属于同一生产 VM
- **THEN** 系统 SHALL 拒绝 recovery-protected 状态，不得把不同盘符当作独立故障域

#### Scenario: 故障域独立性实测
- **WHEN** 发布系统准备接受最终 `RECOVERY_ROOT`
- **THEN** 它 SHALL 先记录 production/recovery host identity、storage authority、volume/backend、UNC/reparse 解析和工具版本，拒绝同机/同 storage 根；并在唯一生产 VM 的真实空 D 物化成功后，将 off-host bundle 的闭包验证、empty-root 事件与同一 root/host/storage 身份机械绑定成最终 failure-domain attestation

#### Scenario: Failure-domain attestation 超过 TTL
- **WHEN** current attestation 超龄但生产/recovery authority 与 retained bundle 仍需继续使用
- **THEN** 当前系统 SHALL 返回 `FAKE_ONLY/NOT_READY`，不得改时间重签、重新封装旧 facts/probe 或产生新的正式 authority；只有未来独立 integrated runner 以新 schema 和不可序列化 capability 重新采集并绑定 exact Git/CI/wheel、SSH host authentication、production/recovery facts 与 off-host probe 后，才可设计正式刷新路径

#### Scenario: 未就绪实现收到 prepare、apply 或 producer 命令
- **WHEN** 调用 `issue/capture/observe`、`rotate-prepare --mode prepare`、`rotate-apply` 或正式 `verify-current`
- **THEN** 已安装产品包 SHALL 在任何文件访问或写入前返回结构化 `NOT_READY`、退出码 `2` 与 `authority=false`；包内 SHALL 不存在可导入的 current/archive/completion writer、CAS、锁、原子替换或中断恢复 core，test-only 代码也不得从产品包导入这些能力

#### Scenario: 对 legacy synthetic lineage 执行 inspect
- **WHEN** `rotate-prepare --mode inspect` 读取 closed、canonical、hash/TTL/path 完整的历史 synthetic challenge/capture/observation lineage
- **THEN** 系统 SHALL 只返回 `DIAGNOSTIC_ONLY` 与 `authority=false`，不得创建 intent、archive、completion 或修改 current；即使 producer hash 等于当前 module bytes，也不得提升为正式 authority

#### Scenario: 新鲜 current 缺少 committed completion lineage
- **WHEN** current bytes 本身 canonical、未超 TTL，且调用者提供任意 legacy completion lineage
- **THEN** 在 integrated runner 不存在期间正式 `verify-current` SHALL 无条件拒绝；legacy current 仅可进入单独只读 diagnostic API，不得被 qualification/publish 当作正式刷新 authority

#### Scenario: 尚无 integrated production capture runner
- **WHEN** 当前实现尚不能同时机械绑定 exact committed Git/CI/wheel code identity、SSH host authentication 与 production stdout capture
- **THEN** 正式 rotation SHALL 标记为 `FAKE_ONLY/NOT_READY`；未来实现 SHALL 位于独立 module，采用新 schema，并要求只有 integrated runner 可创建的进程内、不可序列化 capability，JSON、路径、环境变量或普通调用参数均不得构造或恢复该 capability。威胁模型 SHALL 明确不声称防御可修改代码与证据文件的同一 OS 管理员，且不得为此引入 secret、MAC 或 Keyring

#### Scenario: legacy v1 被正式产品 consumer 使用
- **WHEN** publish、cold bundle、publish recovery、cold restore/qualification reset、Stage 5、state-only、Scheduler 或 writer handoff 收到新鲜且自洽的 legacy v1 facts/probe/attestation/receipt
- **THEN** 所有 consumer SHALL 先调用唯一 `failure_domain_authority` v2 入口，并在任何 failure-domain 证据读取或写入前固定拒绝为 `FAILURE_DOMAIN_AUTHORITY_NOT_READY`、`authority=false`；不得直接调用 `attest_failure_domain`、旧 categorical verifier 或从旧 protection receipt 推导 `failure_domain_accepted=true`。旧 v1 纯函数及 source manifest 只可返回 `DIAGNOSTIC_ONLY`，不得成为产品 fallback

#### Scenario: 正式发布、writer client 与 recovery CLI 缺少 v2 authority
- **WHEN** 安装 wheel 后调用 `qrh-publish`（含 dry-run）、`qrh-writer-handoff-client` 的 run/status/finalize，或 `publish_recovery_cli` 的 capture/capture-legacy/identify-active/cleanup-capture/register，且 v2 authority 仍为 NOT_READY
- **THEN** 各入口 SHALL 在参数解析后、读取 config/path/evidence、执行 Git/SSH/remote 或建立 VM 写入快照前，通过同一 `FailureDomainAuthorityNotReady.document()` 输出 closed JSON：`status=NOT_READY`、`authority=false`、固定 `error_code`，退出码为 2；输出不得包含调用方路径正文。每个 publish recovery public API 自身也 SHALL 以 authority gate 作为首条有效语句，不能只依赖上游 CLI

#### Scenario: 公开 Python 能力绕开 CLI 直接调用
- **WHEN** 调用 formal release/recovery/handoff 域中任何会授予 protection/release/handoff 资格，或会创建/删除文件目录、写 Git、执行远端/OS/service 动作的导出 class、public method、factory 或 helper
- **THEN** 该 callable SHALL 以唯一 failure-domain gate 作为首条有效语句；`ProductionPublishRuntime`、writer client 与 Windows runtime 的构造也 SHALL 在读取 config/path 或建立能力对象前拒绝，`PublishQueue` 构造 SHALL 保持零写入并只在 gated 方法内物化。`ExactGitPush.__call__` SHALL 在 process runner 前以唯一 gate 固定拒绝。source 与 fresh installed-wheel 的 closed API inventory SHALL 不受 `__all__` 过滤，枚举所有非私有顶层 function/class、本模块 callable alias、class 公开 descriptor/method/`__call__` 及明确的内部正式 factory；`__all__` 只作导出文档一致性附加断言。分类计数 SHALL 从 inventory 机械产生，分类交集、漏项与幽灵项均为零；boundary spies SHALL 证明 NOT_READY 下 config/path/tree/subprocess/HTTP/remote/OS 调用为零

#### Scenario: 通用只读诊断作为 integrated runner 前置输入
- **WHEN** 调用 `inspect_local_git`、`dry_run_plan`、existing-directory remote inventory、exact-SHA GitHub CI 或固定本地 test/public guard
- **THEN** 系统 SHALL 将其分类为 `DIAGNOSTIC_ONLY` 或 `QUALIFICATION_INPUT`，不得产生或携带 failure-domain/protection/release authority；Git 检查 SHALL 禁止 optional lock 并保持 repository tree byte identity，remote inventory SHALL 不创建目录或执行 move/delete，测试产生的临时内容 SHALL 自动清理。不得仅因只读 Git/HTTP/SSH subprocess 的存在而误用 failure-domain gate，从而形成 integrated runner 的前置闭环

#### Scenario: 首个 qualification bundle 与最终 attestation 存在依赖顺序
- **WHEN** V39 首次恢复尚没有 empty-D materialization event
- **THEN** 系统 SHALL 允许在已验证不同 host/storage、无 reparse 的开发机候选根生成 no-secret qualification bundle，但 SHALL NOT 将它称为 recovery-protected 或生成 protection receipt；只有该 bundle 完成真实空 D 物化且最终 attestation 通过后才可进入生产门禁

#### Scenario: 活动 D 盘及对象库全部丢失
- **WHEN** 操作者在非生产真实空 `D:\quant\quant_platform` 目标选择一个 retained recovery manifest 和 state checkpoint
- **THEN** 系统 SHALL 仅凭 bundle 与受保护运行配置恢复完整站点、资源、Search/MCP、SQLite 状态、D-root operational tooling/control/service candidate，并在受保护凭据重新注入后通过 hash/schema/服务启动/浏览器/API 验证

#### Scenario: Bundle 只有内容闭包而缺少服务启动闭包
- **WHEN** release、state 与恢复工具完整，但 `tooling/python`、固定控制面或 service install candidate 任一缺失或 hash 不符
- **THEN** 恢复 SHALL fail closed 且不得生成成功 recovery receipt，不得把“内容已物化”报告为完整空 D 恢复

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

#### Scenario: 激活进程在 pointer 前后中断
- **WHEN** 部署在 durable pending journal、pointer、candidate start、post-activation probe、receipt append 或 journal cleanup 任一 crash cut 中断
- **THEN** `active_release.json` SHALL 仍是唯一 active authority，pending journal SHALL 只是 recovery coordination；服务启动 SHALL 要求精确 SCM transient role/attempt/phase/nonce，普通 reboot/手工 start SHALL 拒绝 pending 状态；replay SHALL 在已存在合法 activation receipt 时只核对 candidate pointer 并清 journal，否则恢复明确 prior 并生成或复用唯一 failure receipt，不得同时留下 activation/failure 两种终态

### Requirement: State-only backup 不得改变 release 且 RPO 按实际年龄退化
唯一 state-only job SHALL 至少每 24 小时运行，每次成功 SHALL 创建新的 immutable checkpoint、单向引用当前 release 的 recovery manifest 和 receipt；它 SHALL NOT 改写 release manifest/active pointer 或要求代码重新发布。Recovery protection SHALL 由最后一个 retained、closure 可读且完全验证 checkpoint 的 `captured_at` 实际年龄计算。

#### Scenario: 每日备份在同一 active release 下连续成功
- **WHEN** 两次 state-only job 在代码/内容 release 未变化时完成
- **THEN** 系统 SHALL 保留同一 active release hash，并产生两个不同 immutable checkpoint/RM/receipt；旧 retained checkpoint 仍是 GC root

#### Scenario: 最新成功 checkpoint 超过 RPO
- **WHEN** `now - captured_at` 超过 24 小时，或最近一次任务失败而没有新的完全验证 checkpoint
- **THEN** recovery protection SHALL 明确为 `degraded` 并告警/重试，不得声称 RPO 满足；若不存在有效 checkpoint、closure/attestation 无效或恢复验证失败则 SHALL 为 `failed`

### Requirement: V39 空 D 恢复是首次生产切换前置门禁
首次 C→D handoff 前，系统 SHALL 使用位于生产 VM 外不同 host/storage、已 attested 的 `RECOVERY_ROOT` 保存 V39 bundle，并在唯一目标 VM `10.5.1.240` 上执行恢复：旧 C 盘 V39 继续在线且 D 尚未承接 writer 时，验证并清空精确 `D:\quant\quant_platform`，仅凭该 off-host bundle、受保护运行配置与 runbook 恢复完整站点并通过 hash/schema/browser/API 验收。不依赖 `.223/.235` 或第二台恢复 VM；未通过时 SHALL NOT 开放 D 生产流量或转移 writer authority。

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
