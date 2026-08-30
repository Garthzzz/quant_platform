## ADDED Requirements

### Requirement: 单一 release manifest 绑定所有只读消费者
系统 SHALL 由一个 immutable `release_manifest.json` 绑定 application commit、content snapshot、resource inventory、页面投影、Search、MCP artifacts 和 state compatibility。一个 `active_release.json` SHALL 是唯一部署 authority；release manifest SHALL NOT 引用 prior binding、receipt、切换时间或其他动态发布对象。

#### Scenario: 确定性基础 snapshot 的语义增强仍 pending
- **WHEN** candidate 的页面、lexical Search 和 MCP 基础 artifact 已完成且 identity 一致，而当前 source version 的知识增强明确标记为 `pending`、`failed_retryable` 或 `blocked_policy`
- **THEN** 系统 MAY 激活完整的基础 snapshot，但 manifest SHALL 绑定该状态，Web、Search 和 MCP 均不得暴露上一 source version 的语义知识作为当前结果

#### Scenario: Candidate 内部出现部分或身份不一致 artifact
- **WHEN** 页面、Search、MCP、knowledge generation 或 resource inventory 与 candidate manifest 的 hash/identity 不一致，或声称 `ready` 却缺少已接受 generation
- **THEN** 系统 SHALL 不激活任何 candidate 部分，所有消费者继续使用当前 active release

#### Scenario: Catalog active mapping 漂移
- **WHEN** release 内 Archive document active mapping 与 manifest snapshot 不一致
- **THEN** 系统 SHALL 拒绝 candidate，且不得把 catalog mapping 当作第二个全局 current pointer

#### Scenario: Release 缺少 exact workspace migration closure
- **WHEN** candidate/prior manifest 不是 B1 v2 closed schema，含已取消的 `recovery` 字段，或其 release-root inventory 未精确包含并绑定 `migrations/research_workspace` 下 0001–0003 的六个 up/down SQL 文件及批准 hash
- **THEN** 系统 SHALL 拒绝该 release 的 state compatibility 与激活资格；不得用 controller checkout、wheel 外文件、可变 tracked-tree overlay 或调用者自报 hash 代替 exact release closure

### Requirement: DeepSeek generation 必须随 snapshot 原子绑定
当 `knowledge_enrichment=ready` 时，release manifest SHALL 绑定对应 source version、IR hash、请求 model alias、官方确认的 provider revision、model-identity evidence hash、API 返回 model/system_fingerprint、prompt version、output schema version、generation ID、accepted knowledge hash 与 coverage report；编译工作区、待审核候选或后续完成结果不得旁路 release 激活直接改变线上知识。

#### Scenario: DeepSeek job 在基础 snapshot 激活后完成
- **WHEN** job 产生合法候选并完成机械验证或人工接受
- **THEN** 系统 SHALL 构建新的 enriched snapshot、重新验证 Web/Search/MCP identity 并经正常 release 激活，原 active snapshot 在切换前保持不变

#### Scenario: 相同代码与 reference 下正式语义知识发生变化
- **WHEN** accepted/machine-verified knowledge、弃用状态或被选中的成功 generation 发生变化，而 Git commit 与 deterministic source version 均未变化
- **THEN** 系统 SHALL 生成新的 effective snapshot ID、release ID、knowledge/search hashes 和 immutable release manifest，不得复用旧 release identity
- **AND** release SHALL 只包含正式知识投影及所选成功 generation 的可追溯 provenance，不得包含 compiler workspace 数据库、待审核候选、API key 或其他凭据

### Requirement: Promoted semantic authority 是 immutable 发布输入
系统 SHALL 只从全体 job terminal、SQLite 一致性与 immutable promotion receipt 均已验证的 semantic authority 构建 release、holdout 和检索 artifact。所有消费者 SHALL 使用不创建文件、不切换 WAL、不执行 DDL/backfill 的严格 read-only/immutable 连接；promotion 后 authority 主文件 hash、逻辑 hash、schema 与 row counts 任一漂移 SHALL fail closed。知识写入 SHALL 发生在独立 compiler workspace，完成后形成新的 promotion identity，不得原地改写已经参与 release 或 sealed evaluation 的 authority。

#### Scenario: 名为读取的 store 试图初始化 authority
- **WHEN** release freezer、holdout 或 artifact builder 以默认可写 `SemanticJobStore` 打开 promoted authority，或产生 WAL/SHM、schema 初始化、backfill 或主文件 hash 变化
- **THEN** gate SHALL 拒绝该消费者和当前 promotion identity
- **AND** 不得通过忽略物理 hash、重用已失败 holdout 或重新标记旧 receipt 继续发布

#### Scenario: 新 targeted generation 失败或仍在等待
- **WHEN** 当前 source version 已有成功 generation，而后续 targeted job 超时、失败、返回非法证据或尚未完成
- **THEN** 系统 SHALL 保留上一成功 generation、正式知识投影与 active release identity，不得因最新 job 非成功而撤回可用知识
- **AND** 只有新的成功 generation 或正式知识接受/弃用变化，才 SHALL 形成新的 enriched snapshot 与 release

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

### Requirement: 本地 prior binding 与 receipt 不得成为平行身份
`local_prior_binding.json` SHALL 只绑定一个已经由 `active_release.json` 指向的 `R_active` 与一个经 state compatibility 验证的 `R_prior`。activation/rollback receipt SHALL 只绑定结果 pair 与结果；failure receipt SHALL 显式绑定 operation、原 pair、target candidate、失败阶段与结果，其中 activation target 必须与原 pair 全部 release 不同，rollback target 必须恰为原 prior，bootstrap 必须从空 D pair 开始；cleanup receipt SHALL 只绑定保留 pair、精确移除目标与结果。它们都是 append-only 证明材料，SHALL NOT 定义另一个 current/version authority。服务启动与 Web/Search/MCP 只解析 `active_release.json→release_manifest.json`。

#### Scenario: Receipt 与 active pointer 表示不同 current
- **WHEN** 工具读取到多条历史 activation 或 rollback receipt
- **THEN** 它 SHALL 只信任 `active_release.json`，并要求 binding 中的 active 与之 exact 匹配；不得从“最新 receipt”猜测 current

#### Scenario: Prior binding 缺失或损坏
- **WHEN** active 自身有效，但 binding 缺失、非 canonical、hash 不符、含 reparse 路径或绑定多个 prior
- **THEN** 当前请求 MAY 继续读取 active；新激活、回退和清理 SHALL fail closed，且不得从目录枚举推断 prior

#### Scenario: 未切换成功却请求成功 activation receipt
- **WHEN** candidate 仅通过预激活验证，或 pointer/启动/post-activation 验证任一失败
- **THEN** receipt writer SHALL 拒绝成功 activation receipt；失败路径只有在原 pointer、binding、active service、writer fence 与当前 D state identity 分别由 controller-produced sealed observation 证明已恢复或未变化后，才可写绑定 exact journal operation、terminal 前最后一个合法 non-terminal 失败阶段、原 pair、target candidate、五项 observation hash 与聚合 hash 的 failure receipt

#### Scenario: Failure operation 或 target 与 journal 语义错配
- **WHEN** failure receipt 的 operation 与同 attempt journal 不同，`failed_phase` 不是追加 terminal 前最后一个合法 non-terminal phase，activation target 复用原 pair release，rollback target 不是原 prior，或 bootstrap 声称已有 D pair
- **THEN** schema、history replay 与 terminal receipt resolver SHALL 全部拒绝；不得通过猜测 operation 或弱化 target 唯一性形成失败终态

#### Scenario: Cleanup 与同 attempt 成功结果不一致
- **WHEN** cleanup receipt 缺少同 attempt 的 activation/rollback terminal，跟随 failure/bootstrap terminal，或 retained pair 与同 attempt 成功 terminal result pair 不完全一致
- **THEN** graph gate SHALL 拒绝 cleanup；历史成功 attempt 可独立自洽验证，但不得被错误要求等于当前 active binding

### Requirement: Manifest 依赖必须可机器证明无环
系统 SHALL 只允许 `active_release→R_active`、`local_prior_binding→R_active/R_prior`；activation/rollback receipt 只指向结果 pair/result，failure receipt 只指向 operation/原 pair/target candidate/result，cleanup receipt 只指向保留 pair/精确移除目标/result。系统 SHALL 对 JSON schema、引用图和对象 hash 运行 cycle/back-reference validation；任何 `R` 均 SHALL NOT 反向引用 binding、receipt 或 active pointer。

#### Scenario: Bootstrap activation receipt 的唯一空 prior 例外
- **WHEN** receipt 属于 activation 家族且 `operation=bootstrap_first_pair`
- **THEN** result pair MAY 为 `active=R0, prior=null`，但 SHALL 同时绑定 attempt、原 pointer/binding absent、ingress closed、旧 C writer fenced、最终 D state identity、R0 live identity 与 writer fence
- **AND** 任意普通 activation/rollback receipt、任意已开放 ingress 的结果或任意缺失上述证据的 bootstrap 都 SHALL 拒绝空 prior

#### Scenario: Release manifest 反向引用发布控制对象
- **WHEN** candidate graph 出现 `R→active`、`R→local_prior_binding` 或 `R→receipt` 的边
- **THEN** validation SHALL fail closed；不得通过占位 hash、二次改写或时间排序规避

#### Scenario: Receipt 被误用为 active 或 prior pointer
- **WHEN** 某工具试图从最新 receipt 决定 current 或选择 prior
- **THEN** 系统 SHALL 拒绝，并分别从 `active_release.json` 与 exact-matched `local_prior_binding.json` 解析；两者不一致时不得回退

### Requirement: 生产 release 保留集合必须严格为 active 与恰一 prior
每个成功激活或回退的终态 SHALL 只保留 `R_active` 与 `R_prior` 两个生产 release closure。正在执行且有合法 durable attempt journal 的 candidate MAY 暂时存在，但不构成 retained release；终态后 SHALL 清理更早 prior、completed candidate、incoming 与 partial，并生成 cleanup receipt。

#### Scenario: 成功激活产生新 pair
- **WHEN** `R_candidate` 完成切换与 post-activation 验证
- **THEN** 新 pair SHALL 为 `active=R_candidate`、`prior=旧 R_active`；旧 `R_prior` 仅在新 pair 与 receipt 验证完成后删除

#### Scenario: 首次 C→D 尚无旧 active
- **WHEN** writer handoff 准备建立第一组 D production pair
- **THEN** 系统 SHALL 先以冻结 V39 baseline `R0` 建立尚未对外的 D active，再用正常激活协议切换到具有真实不同 manifest/release identity 的 successor `R1`，由 `R0` 成为唯一 prior；不得复制 V39 内容、使用目录别名或伪造 manifest identity 填充 prior。`R1/R0` pair 未完整通过前不得开放 D 外部流量

#### Scenario: 普通回退交换 pair
- **WHEN** 当前 prior 通过同一 D state 的兼容与启动验证并被激活
- **THEN** 新 pair SHALL 为 `active=旧 R_prior`、`prior=旧 R_active`；不得选择第三个历史 release

#### Scenario: 第三个 retained release 存在
- **WHEN** 终态 inventory 出现 active/prior 之外且不属于活动 attempt 的 release closure
- **THEN** retention gate SHALL 失败并阻止下一次 publish，直到精确清理与 receipt 验证完成

### Requirement: 状态权威不随 release 身份切换
release manifest SHALL 只声明当前 D state 的 schema read/write compatibility，不包含状态文件 hash、历史副本或恢复时间点。candidate 与 prior SHALL 在激活前共同证明对当前 D state 的安全读写；普通回退 SHALL NOT 替换 state、倒退 comment/workspace 事件或执行 down-migration。

候选与 prior 的 live writer 资格 SHALL 由 controller 对 kernel file lock、闭合 lease record、SCM QueryServiceConfig/QueryServiceStatusEx、host/child PID 与 start-time、ImagePath/argv、endpoint release identity 和同一 lease 绑定的 canary event 联合验证。`/deploymentz` 自报字段、JSON boolean 或只核对 SCM 配置 SHALL NOT 单独形成资格；聚合 qualification token SHALL 只由 concrete runtime 在进程内创建且不可从 JSON 反序列化，journal SHALL 只保存 sealed observation hashes。

Windows service host 对任何 transient／steady child SHALL 使用 non-inheritable、禁止 breakaway 且启用 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` 的私有 Job Object，并在 `CreateProcessW` 时通过 `PROC_THREAD_ATTRIBUTE_JOB_LIST` 原子关联；child SHALL 在关联、handle tracking 与 identity 校验完成前保持 suspended。service host SHALL 使用自身不可序列化的 exact launch/lifetime owner，在首个 launch Win32 syscall 前跟踪 prelaunch/job/process/thread/attribute/std-handle/admission-pipe 资源；transient controller 的 B2 lock/workspace 只拥有 observation handles且绝不跨进程传给 host。transient host还SHALL由独立existing-only、zero-write、no-share pinned reader在lifecycle／CreateJob前从固定D canonical history验证唯一latest `prior_start_authorized`或`candidate_start_authorized` revision与closed SCM identity逐字段一致，并证明当前role的`result.json`、固定`runtime-qualification-<role>.json`及post-canary alias全absent；CreateProcess前、output handles提交后／ResumeThread前及ResumeThread后须重验exact revision／bytes／artifact absence。reader SHALL NOT调用会创建layout/lock的persistence factory或返回前关闭descriptor的短读路径。该一次性fence SHALL NOT取得controller global lock、写journal或生成qualification。产品service SHALL override而不调用pywin32 base `SvcRun`，并override `SvcInterrogate`。transient从入口到post-Resume journal/artifact checkpoint只报告`START_PENDING`，随后才报告RUNNING。steady在START_PENDING完成lock-bound static/Job/post-Resume prelaunch facts后报告RUNNING，但仍须保持同一B2 lock/workspace，随后才用现有RUNNING-only observer完成SCM/endpoint/writer全链、final facts与job promotion；RUNNING本身SHALL NOT形成steady成功，后链失败必须kill job/exit且不得释放成功authority。child最外层admission gate在listener前从继承的匿名pipe read端构造并默认closed；transient永不open。steady只有全链、final facts与job promotion后，才可由同一B2 epoch的一次性prepare authorization写PREPARE并进入仍关闭的`ack_pending`；host以fresh fixed endpoint与writer lease确认该closed state后，B2才派生不可重放commit authorization；同一pipe收到COMMIT+EOF后child才可`admitted`，post-commit admitted observation通过后才可unlock/wait。PREPARE前及`ack_pending`中的普通请求固定503且不进入Flask/session/业务/SQLite；prepare/ready-ack/commit/close/observation unknown均kill job。reader fatal在listener前、serve loop阻塞时或shutdown outcome unknown时都必须终止child/whole Job，不得只留内存标记。transient controller在其RUNNING acknowledgement前SHALL保持B2 lock且不得POST或推进journal。普通稳态启动SHALL使用与transient attempt不同的B2 lock-epoch workspace、authorization与SCM/endpoint/writer observation input；不得伪造活动journal来复用transient类型。

#### Scenario: Endpoint 自报正确但没有唯一 writer lease
- **WHEN** endpoint 返回预期 release/manifest/snapshot，但 kernel lock 未被对应 child 持有、lease record 与 attempt/role/nonce/state/epoch 不同，或 SCM/child PID/start-time/ImagePath 不能闭合
- **THEN** candidate/prior qualification SHALL fail closed，pointer/binding 不得据此提交

#### Scenario: Service host 在 child 启动窗口崩溃
- **WHEN** service host 在 child creation-time job 关联后、resume 前，或在 child 已取得 writer／listener后而稳态 boot workspace 尚未关闭时退出
- **THEN** OS SHALL 通过最后一个 Job Object handle 的关闭终止 child；新 SCM host 即使已取得 global lock，也 SHALL 在实际证明旧 writer lock 可取得、旧 listener absent，并以全机双 snapshot + exact D executable/argv/creation-time 证明旧 child absent 后才可创建新 child
- **AND** 不得只凭 host PID 消失、SCM restart、超时或历史 receipt 推断 child 已回收

#### Scenario: Transient controller 与 SCM host 的 owner 边界
- **WHEN** controller 正持 B2 global lock／attempt workspace 并通过 SCM 启动 transient service host
- **THEN** host SHALL 以 closed transient identity 构造独立的 service-host-local launch lifecycle，而不得重取 global lock、接收/pickle attempt workspace或暴露 raw Job handles；controller SHALL 只通过其 B2 observation owner 验证 SCM→endpoint→writer live chain

#### Scenario: Child 标准流与 Job handle 继承
- **WHEN** launcher 使用 `STARTF_USESTDHANDLES` 保留固定 D-root child 日志
- **THEN** 同一 `STARTUPINFOEXW` SHALL 以 `HANDLE_LIST` 恰好列入已验证anonymous-admission-pipe read端与log handle并使用`bInheritHandles=TRUE`；host独占write端且Job/B2/SCM/state handles SHALL non-inheritable且不在list，child不得获得Job或开闸write authority；handle数值不得经argv/env/path/persistent material传递

#### Scenario: Creation-time JOB_LIST 不可用
- **WHEN** OS 低于 Windows 10／Server 2016、JOB_LIST/ABI 缺失，或 service host 所处 outer job 无法形成合法 nested hierarchy
- **THEN** installer/service preflight SHALL 在 child 与 SCM 变更前 fail closed；不得降级为 post-create `AssignProcessToJobObject` 或无 Job child

#### Scenario: 无 pending 的普通 reboot
- **WHEN** SCM 以无 transient args 启动且 active、binding、恰两棵 retention closure、当前 D state、tooling 与旧 C live fence 全部闭合
- **THEN** B2 SHALL 创建不含 attempt/journal API 的 steady boot workspace，并以 exact steady authorization 和 steady SCM→endpoint→writer chain 启动 current active
- **AND** 任一 transient workspace/input/evidence、bootstrap `prior=null`、persistent mapping 或 receipt-only observation SHALL 被拒绝

#### Scenario: Closed transient args 没有 durable latest authorization
- **WHEN** service host 收到语法和自哈希均合法的 transient SCM args，但 fixed-D journal 不存在、已经 terminal／verified、phase／role／attempt／start nonce不匹配，存在第二 active history／duplicate／gap／fork，或 journal 在 CreateJob／CreateProcess／ResumeThread cut 发生 revision、bytes或identity漂移
- **THEN** host-local read-only start fence SHALL fail closed；CreateProcess 前失败不得创建 child，suspended 或已 resume 后失败 SHALL 终止 whole job并证明 writer／listener／old-child absence
- **AND** 只有唯一 canonical latest `*_start_authorized` 与 attempt、deployment nonce、operation、role、start nonce、state identity、release／manifest、SCM plan hash及authorization hash exact一致时才可执行一次 launch；fence不得成为 evidence、qualification、journal writer或可重放 token
- **AND** `StartService` return、`START_PENDING`、child PID 或 timeout SHALL NOT 替代 post-Resume 后同一 host instance 的 exact `SERVICE_RUNNING` acknowledgement

#### Scenario: Start-authorized 但当前 role 已有 post-canary artifact
- **WHEN** latest journal与transient args完全一致且仍为`*_start_authorized`，但固定role-local `result.json`、`runtime-qualification-<role>.json`或其case／NFKC／reserved schema／scope alias任一存在，或在五个host checkpoint任一cut出现
- **THEN** existing-only host fence SHALL拒绝launch；process未创建时不得创建，已suspended或resume后须终止whole job并交还exact failure分流，不得删除、重签、读取为资格或借其他role artifact满足absence
- **AND** fixed-D root／control／audit／journal／attempt workspace／binding／runtime-canary缺失时写集合SHALL为空；attempt-evidence目录absent只能由pinned parent双枚举证明aggregate absent，存在时才可existing-only打开；短读后replacement、partial acquisition或close outcome unknown不得伪造pinned／closed状态

#### Scenario: Pywin32 基类会提前报告 RUNNING
- **WHEN** product service进入`SvcRun`，或在post-Resume checkpoint前收到interrogate／status failure
- **THEN** exact override SHALL阻止base `SvcRun`的先行RUNNING并只重报tracked状态；transient只有完成post-Resume journal/artifact checkpoint才可报告RUNNING；steady须先完成static/Job/post-Resume prelaunch facts再报告RUNNING，并继续持B2 lock完成RUNNING-only全链与promotion
- **AND** base-vs-override调用序列门禁 SHALL证明`StartService` return、PID、timeout或mock-only `SvcDoRun`不能替代该状态交接

#### Scenario: Steady observer 要求 RUNNING 但成功链尚未完成
- **WHEN** steady host在START_PENDING完成prelaunch facts并报告RUNNING，但SCM before、endpoint、writer、SCM after、final facts或job promotion任一尚未完成或失败
- **THEN** RUNNING SHALL只作为exact SCM observation的现场前提；host须继续持有同一B2 lock/workspace，child admission保持closed，且不得派生steady成功、开放成功门禁或进入wait
- **AND** 任一后链失败／漂移／outcome unknown SHALL终止whole job、退出service并从old-child/writer/listener absence重新开始；全链与promotion成功后仍须完成PREPARE、closed-state readiness acknowledgement、COMMIT+EOF与post-commit admitted observation才可释放B2 lock进入wait

#### Scenario: Final admission commit 前普通请求到达 listener
- **WHEN** transient或steady child已经监听，且普通UI/login/logout/业务API/comment/workspace请求在promotion前、PREPARE后／readiness acknowledgement前，或readiness acknowledgement后／COMMIT前到达
- **THEN** 最外层WSGI gate SHALL在Flask/session/body/业务handler之前返回固定`503 starting_not_admitted`并保持两库零变化；预先进入listen backlog的普通连接也不得抢在readiness acknowledgement前进入业务。transient只允许exact loopback`/deploymentz`与`/deployment-canaryz`，steady只允许exact loopback`/deploymentz`
- **AND** RUNNING、SCM/endpoint evidence、persistent result/aggregate/journal/receipt或HTTP self-report均不得打开gate

#### Scenario: Promotion-bound admission 两阶段一次性开启
- **WHEN** steady同一B2 epoch已完成SCM before→endpoint→writer→SCM after、final facts与job promotion
- **THEN** exact `LockedSteadyAdmissionPrepareAuthorization` MAY使service-lifetime owner向host独占anonymous pipe写入唯一PREPARE frame且保持write端打开；child在listener前启动的唯一tracked reader thread SHALL只进入仍关闭的`ack_pending`。host以fresh fixed endpoint challenge确认同一identity、`ack_pending`与writer lease后，B2才可派生exact `LockedSteadyAdmissionCommitAuthorization`；只有该commit type MAY写唯一COMMIT frame并以EOF终止pipe，child在匹配PREPARE→ready-ack binding→COMMIT→EOF与runtime/import/state/lease/job checkpoint后才单向`admitted`
- **AND** post-commit admitted observation通过后才可consume commit authorization、unlock和wait；提前／第二次／foreign／fake／pickle／mapping、COMMIT-before-PREPARE、无ready ack的COMMIT、截断／额外／错binding／EOF-before-COMMIT、T0/T1重排，或prepare/ack/commit/close/observation failure/outcome unknown SHALL保持无成功authority并kill whole job。reader fatal SHALL在listener前、serve loop阻塞时及shutdown outcome unknown时使child/whole Job退出；verified transient必须stop并fresh steady boot，不得原地admit

#### Scenario: Qualification 推进 journal 后自撤销
- **WHEN** process-local qualification 完成最后 live replay并准备把 `*_start_authorized` 推进为相邻 `*_verified`
- **THEN** 只有 B2 one-shot consume seam MAY 以 expected latest hash 写 sealed aggregate 与下一 journal revision；revision durable 后旧 authorization／observation／qualification SHALL 全部撤销。下一 pointer／binding CAS SHALL 只由 `consume_verified_phase_next_cas(lock, workspace, authorization)` 接受绑定新 revision 与本次 live pointer/binding/state/release-namespace 的 exact 窄授权；expected/desired 必须来自 durable journal v4 内密封的 pointer refs 或完整 canonical binding documents，调用者不得自报 release/path/hash/expected/desired。CAS、create-only observation、相邻 `*_cas_committed` revision 与 authorization consume SHALL 单向闭合；CAS 已 durable 但 revision 未推进时只能在 owner crash 后按同一 material fresh replay，不得第二次切换或伪造成功。旧 raw `cas_active_release`／`cas_local_prior_binding` SHALL 只在显式 test-only persistence 上可用，production persistence 必须在任何 material 读取或写入前拒绝，且产品调用图不得引用它们
- **AND** aggregate、result 或 journal mapping SHALL NOT 恢复 canary qualification

#### Scenario: Result 已落盘但 verified revision 未落盘
- **WHEN** controller 重启后 latest journal 仍为 `*_start_authorized`，而 create-only result 或 aggregate 已存在
- **THEN** 系统 SHALL 终止对应 job child、证明 writer/listener 回收并进入 exact failure path；不得删除、重签或复用该 artifact 完成资格

#### Scenario: Candidate 扩展 state schema
- **WHEN** 新 release 需要新增表、列或索引
- **THEN** 系统 SHALL 先执行可重复且前向兼容的 expand，并在切换前证明 candidate 与将成为 prior 的当前 active 均可对扩展后 state 安全读写

#### Scenario: 普通回退发生在 schema 扩展后
- **WHEN** active 回退到唯一 prior
- **THEN** prior SHALL 使用同一当前 D state；若不兼容则回退在写 pointer 前失败，不得恢复旧 SQLite 文件或降级 schema

### Requirement: 本地 prior 能力边界必须显式
release certificate SHALL 只证明在生产 VM、精确 D 根、active/prior closure 与当前 state 均完整可读时的最近一代版本回退。它 SHALL NOT 声称能够处理 VM、D 根、对象库或 state 整体丢失，也 SHALL NOT 依赖周期性状态副本任务来扩大该结论。

#### Scenario: 项目根或 state 整体不可读
- **WHEN** active/prior closure、当前 state 或 D 项目根无法完整校验
- **THEN** rollback SHALL fail closed，release certificate SHALL 报告该场景超出本版范围，不得把 release 文件存在当作数据可恢复证据

### Requirement: Public 到 Private 转换必须发生在最终证书之后
仓库在 Stage 0–5 SHALL 保持 Public；只有全部功能、部署、本地 prior rollback 和最终 release certificate 通过后才可转为 Private，转换后 SHALL 重新验证 GitHub plan、Actions、branch/environment protection、CI、publish CLI 权限和 exact-SHA candidate。

#### Scenario: Stage 5 尚未形成最终证书
- **WHEN** 任一功能、active/prior 回退或保留门禁未通过
- **THEN** 仓库 SHALL 保持 Public，且不得把可见性切换当作解决部署配置问题的手段

#### Scenario: 仓库已转为 Private
- **WHEN** 可见性变更完成并准备关闭项目
- **THEN** 系统 SHALL 至少完成一次 Private 状态 CI 与一次不切生产的 exact-SHA candidate 演练并保存 visibility-transition receipt，任一失败 SHALL 阻止最终关闭
