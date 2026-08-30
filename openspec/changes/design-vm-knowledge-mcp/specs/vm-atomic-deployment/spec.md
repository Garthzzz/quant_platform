## ADDED Requirements

### Requirement: 生产 VM 写入必须闭合在唯一 D 根
系统 SHALL 把生产 VM 的全部项目写入闭合在 `D:\quant\quant_platform`：代码 checkout、tooling、incoming/candidate、release、control、state、隔离副本、audit/receipt、lock、log、TEMP/TMP 与 Python bytecode 均 SHALL 位于该根的受审查子目录；系统 SHALL NOT 向 `D:\`、`D:\quant`、其他 sibling/parent 或 C 盘新增、覆盖或修改项目内容。旧 C 盘 V39 与 `C:\quant_platform_data` 在 writer handoff 前只可作为显式只读来源。

#### Scenario: 写目标位于 D 上级、同级或 C 盘
- **WHEN** 任一发布、bootstrap、部署、服务、隔离副本或临时文件路径解析到精确 D 根之外
- **THEN** canonical path gate SHALL 在写入前 fail closed，active/writer SHALL 保持不变

#### Scenario: 路径文本在 D 根内但通过 reparse 逃逸
- **WHEN** 任一路径组件是 junction/reparse/subst/UNC 映射，或解析后的 physical path 不再等于批准路径
- **THEN** 系统 SHALL 拒绝该路径，不得创建 candidate、receipt 或成功审计

#### Scenario: 生产操作完成
- **WHEN** 受控操作成功或失败返回
- **THEN** 系统 SHALL 生成不含 secret 的声明 write-set 与 D-root 实际 delta 审计；任何未声明写入或无法证明的路径 SHALL 使该操作不得获成功 verdict

### Requirement: 兼容基线必须先于知识增强完成 VM 纵切
系统 SHALL 在依赖通用 parser、MCP、vector 或 PostgreSQL 之前，以现网 V39 的完整代码、页面、数据和 Git 外资源建立 D 盘不可变候选，并为后续本地 prior 回退建立可启动基线。

#### Scenario: D 盘尚无项目内容且 Git 不包含大对象
- **WHEN** 首次候选开始构建
- **THEN** 系统 SHALL 按冻结 inventory 搬运并校验 PDF、图片、对象、内容数据库、Paper Lab、模板和静态资源，而不是把 Git checkout 当作完整迁移；冻结 V39 只形成一棵 canonical immutable baseline，不得为了填充 prior 槽复制一棵内容等价 release 或伪造新的版本身份

#### Scenario: 兼容候选出现前端差异
- **WHEN** V39 基线与 D 候选存在未授权视觉、DOM 或交互差异
- **THEN** 系统 SHALL 拒绝候选，且不得以通用 renderer 或新知识功能解释该差异

#### Scenario: 旧 C V39 仍占用生产端口时验证 D candidate
- **WHEN** 首次 handoff 期间旧 C writer 仍在 `8765` 提供现网服务
- **THEN** 系统 SHALL 在生产 VM 使用 D-root tooling、loopback 隔离端口和 D-root tmp 中的 SQLite online-backup 副本启动 exact candidate，验证 release/manifest/snapshot、页面/API/资源和 legacy 行为；该 runner SHALL NOT 修改 production active pointer、生产 state、C 盘或对外 writer authority，结束后 SHALL 可审计清理自身 D-root tmp

#### Scenario: online backup 不泄漏 attempt 路径能力
- **WHEN** controller 把已围栏的当前 SQLite 复制到同 attempt 隔离副本
- **THEN** 它 SHALL 先 backup 到进程内 SQLite 一致视图，再在该隔离内存连接上使用 SQLite `VACUUM` 正规消除从 source 页 1 继承的 WAL version 位；`VACUUM` 前后的 schema、marker/ledger、integrity/quick/FK 与业务逐表 digest SHALL 完全等价，不得手工篡改 header。随后将 `serialize()` 字节仅经 lock-bound `LockedNewFile` 写入并经 `pin_sqlite_set` 与 `deserialize()` 重验；不得向 SQLite 提供 workspace 绝对路径或 raw fd，不支持该能力时 SHALL fail closed

#### Scenario: 线上 source pin 归同一 B2 epoch 管理
- **WHEN** controller 在已围栏的线上 state 上形成 SQLite 一致视图
- **THEN** B2 SHALL 从同一全局部署锁、acquisition epoch 和 attempt workspace 派生不可序列化的 `LockedStateSqliteSource`；产品构造只接受 `comments|research_workspace` 枚举并固定解析到本机 D state，不得接受 root、路径、环境变量、hook 或 runtime 注入。该能力 SHALL 在 B2 内跟踪 main/WAL/SHM open-instance identity，只向 B3 返回无路径内存 SQLite 视图与闭合前后观察，不得暴露 source path、raw fd 或 raw HANDLE；它 SHALL 作为 workspace resource 在 kernel unlock 前闭合，close outcome 不确定时 fail closed 且不得注销 tracking

#### Scenario: source-pin 接缝不能自行产生正式资格
- **WHEN** B3a.2 已证明 fixed-D source pin、online backup 与 lock/epoch/close 生命周期
- **THEN** 系统 SHALL 仍把该结果标为非资格接缝；只有后续 SCM/process/writer-lease fence capability 已闭合时，同一次 source qualification 才可成为 formal，调用者不得用 diagnostic scope 或可序列化字段冒充 writer fence

#### Scenario: Exact release closure 不能由调用者自报
- **WHEN** controller 为一个 durable attempt 形成 formal state compatibility
- **THEN** B2 SHALL 在同一 global-lock epoch 下只从该 attempt 最新 journal 派生 operation、nonce、state identity 与 B1 release refs，固定解析 exact release manifest，并为 manifest inventory 中每一个文件持有只读 no-share-write/delete open-instance guard；workspace 六个 migration 文件必须是其中恰好闭合且可按固定枚举读取的子集，入场/出场还须完整扫描全树并证明 closure 未漂移。接口 SHALL NOT 接受 root、path、release ID/hash 或版本参数，也不得向 B3 暴露未经 pin 的 mutable path。bootstrap SHALL 只解析 R0 与 absent prior，后续 R0→R1 普通 activation 才解析 R1/R0

#### Scenario: Journal 的 compatibility evidence 只检查非空
- **WHEN** attempt 到达 `state_expand_applied`，但 `evidence_hashes.state_compatibility_sha256` 与 `state_plan.compatibility_sha256` 不同，或 database seal 指向另一组 compatibility manifest
- **THEN** journal validator SHALL fail closed；`state_plan.compatibility_sha256` SHALL 按 `comments`、`research_workspace` 固定顺序聚合两份 formal manifest hash，evidence 与各 database seal SHALL exact 绑定同一集合，不得以任意合法 hash 或 diagnostic manifest 占位

### Requirement: 精确提交与受控发布入口
系统 SHALL 只通过受控单命令 `publish` 将完整 commit SHA 与本地冻结的非 Git source/resource inventory 绑定为不可变 candidate，经同一 SHA 的本地检查和 GitHub CI 后才允许上传；系统 SHALL NOT 在 active 运行目录执行 `git pull`，本版 SHALL NOT 实现裸 push watcher、部署 hook、self-hosted runner 或 bare receive。

#### Scenario: CI 通过的 SHA 与候选不一致
- **WHEN** GitHub CI 结果、tracked tree 或冻结 source inventory 不属于同一 candidate manifest
- **THEN** 系统 SHALL 拒绝上传或激活并保持 active 不变

#### Scenario: 多次快速 publish
- **WHEN** 一个部署正在切换且多个更新等待
- **THEN** 系统 SHALL 保持运行中部署不取消、只保留最新 pending main candidate，并明确记录被替换的 pending，而不得声称所有 commit FIFO 部署

### Requirement: 全局部署锁与 attempt 资源必须按同一 acquisition 可恢复闭合
全局锁 SHALL 显式区分 `acquiring/live/acquire_failed/closing/idle`，并只在 kernel lock、目录 guards 与临时 acquisition 资源全部闭合后产生 live acquisition epoch。attempt workspace、新文件和 SQLite main/WAL/SHM pin SHALL 绑定该 epoch；raw fd、handle、内部 authority token 与任意路径 SHALL NOT 暴露给 controller。任一 close 失败 SHALL 保留 exact resource tracking 和 owner，且在资源真实闭合前不得释放 kernel lock、进入 idle 或恢复 workspace 业务写操作。

#### Scenario: B3 evidence 必须自带 attempt 与内容资格
- **WHEN** concrete runtime 提交 SQLite、SCM、进程或 writer evidence
- **THEN** evidence 本体 SHALL 使用 B3 closed schema/self-hash 内生绑定 attempt、nonce、operation 与 state identity，并在进入 B2 exclusive persistence seam 前完成语义验证；仅为 JSON object 或仅位于 attempt 目录均不构成内容资格

#### Scenario: acquisition 中途失败且资源清理可重试
- **WHEN** descriptor、kernel lock、root/locks guard 或临时 guard 在 acquisition 任一边界失败
- **THEN** one-shot cleanup SHALL 清净资源但仍抛出原 acquisition error；持续 cleanup fault SHALL 保持 `acquire_failed` 与真实 owner/resource identity，只允许同 owner retry，其他 owner 和 contender SHALL 被拒绝

#### Scenario: 首次 descriptor identity 取得失败
- **WHEN** open 已返回 descriptor，但 actual opened-resource identity 尚未取得
- **THEN** cleanup SHALL 先只读取得并持久记录 actual file identity 与可比较的 kernel object/open-instance guard；若任一身份读取失败，SHALL 保留 tracking 而不得尝试可能产生 ambiguous outcome 的 close

#### Scenario: close 后 fd 或 handle 数字被同号复用
- **WHEN** close 已真实关闭原资源、相同数字随即指向不同资源，但 close wrapper 返回错误
- **THEN** retry SHALL 机械识别当前数字不再代表已登记的 exact identity，注销原 tracking 且 SHALL NOT 关闭 replacement；不能证明身份时 SHALL fail closed 而不得猜测 idle 或再次关闭未知资源

#### Scenario: 同一文件或 hardlink 被同号重新打开
- **WHEN** close 已真实关闭原 descriptor，same path、same inode 或 hardlink 随即形成同号但不同 open instance 的 replacement
- **THEN** retry authority SHALL 以真实 kernel object/open-instance 证明区分两次 open；`st_dev/st_ino`、路径相等或 fd 数字相等均不充分，旧 tracking SHALL NOT 关闭 replacement

#### Scenario: Win32 syscall 后 Python tracking 尚未提交即抛错
- **WHEN** `DuplicateHandle` 已写出 output guard，或 `DUPLICATE_CLOSE_SOURCE` 已关闭 source，而 Python wrapper 在 caller 更新字段前抛错
- **THEN** output SHALL 已进入 owner 可枚举 tracking，close-source SHALL 已单调撤销旧整数 authority；wrapper 异常不得形成未登记 live handle、伪 kernel-held、伪 idle 或对同号 replacement 的 retry close

#### Scenario: 无法判定 close-source syscall 是否已经发生
- **WHEN** Python 异常使系统无法机械判断 source handle 仍存活还是已关闭并被同号复用
- **THEN** 旧整数 SHALL 永久失去 close authority，lock SHALL 进入不可转 idle 的 owner-crash-only fail-closed 状态并保留进程 reservation；系统 SHALL NOT 猜测 kernel lock 状态，最终只由 owner 进程退出触发 OS 资源回收

#### Scenario: Mutable SQLite create 与 guard 之间不得有 reopen 空窗
- **WHEN** B2 为 canary role-local database 排他创建并持久化 main bytes
- **THEN** CREATE_NEW 返回的同一 open instance SHALL 在首次 syscall 前已登记，并连续承担 write/flush/identity proof 与 mutable guard authority；不得关闭 creator 后按路径重新打开 guard，也不得在任一时点让 main 失去 anti-delete/replace handle

#### Scenario: Controller 与 SCM host 拥有不同进程资源
- **WHEN** controller 持 global lock/attempt workspace，而 SCM 在独立 service host 进程创建 transient child
- **THEN** controller workspace SHALL 只跟踪本进程 observation/source/release 资源；service host SHALL 以独立 exact lifecycle 跟踪 job/process/thread/std-handle，两个 owner不得共享/pickle lock epoch、workspace 或 raw handle
- **AND** steady 路径只有在 service host 本身持 steady boot workspace时，才可登记其 local lifecycle reference并执行单向 lifetime promotion

### Requirement: 单一 active authority 与恰一本地 prior
系统 SHALL 只以 `active_release.json` 指向一个 immutable release manifest `R_active`；release manifest SHALL 只绑定代码、内容、资源、索引、知识和 state compatibility，SHALL NOT 引用 `local_prior_binding`、receipt 或其他动态发布对象。生产稳态 SHALL 恰好保留 active 与一个 prior release；`local_prior_binding.json` SHALL 只绑定经验证的 `R_active/R_prior`，不得成为 Web、Search、MCP 或服务启动的 current pointer。

#### Scenario: Active 文件损坏
- **WHEN** 启动器无法验证 active 文件的 schema、路径或 manifest hash
- **THEN** 系统 SHALL fail closed；不得从最新 receipt、目录时间或 prior binding 猜测 current

#### Scenario: Prior binding 与 active 不一致
- **WHEN** binding 中的 active manifest 与 `active_release.json` 当前指向不同，或 active/prior 任一 hash、路径、regular-file/reparse 检查失败
- **THEN** 系统 SHALL 保持当前 active 服务，不得启动 prior、激活新 candidate 或清理任何现存 release，并产生路径脱敏的可见错误

#### Scenario: Release 试图反向引用本地绑定或 receipt
- **WHEN** builder 试图把具体 prior ID、binding hash、receipt ID 或切换时间写回 release manifest
- **THEN** schema/graph gate SHALL 拒绝该操作，release hash 与 active identity SHALL 保持不变

### Requirement: 成功激活必须形成 active + 恰一 prior
部署控制器 SHALL 在切换前验证 candidate、当前 active、当前 D state 和将形成的 active/prior pair。成功切换后，原 active SHALL 成为唯一 prior；更早 prior 只能在新 active 启动、post-activation 检查、binding 与 activation receipt 全部验证成功后清理。candidate/incoming 是瞬态目录，不得在终态后作为额外 retained release 留存。

#### Scenario: Candidate 激活成功
- **WHEN** candidate pointer 切换、启动、health、关键功能、writer fence、当前 state 兼容性和新 pair binding 均通过
- **THEN** 系统 SHALL 生成 activation receipt，绑定新 active、旧 active 形成的 prior 与 controller-produced verification aggregate hash；清理更早 prior 和终态暂存件后，生产 release 集合 SHALL 只有 active 与恰一 prior

#### Scenario: Candidate 激活前当前 active 不适合作为 prior
- **WHEN** 当前 active 无法以同一 D state 启动、读写或通过必要功能检查
- **THEN** candidate SHALL 在 pointer 切换前被拒绝；不得以更早 release、旧状态副本或缺省目录替代 prior

#### Scenario: 清理旧 prior 失败
- **WHEN** 新 active 与新 binding 已成功，但更早 prior 或终态 candidate 无法安全清理
- **THEN** 发布 SHALL 标记 retention closure 未完成并阻止下一次 publish；不得宣称已满足恰一 prior，且当前 active 不因清理失败被反向切换

### Requirement: 普通回退只交换版本并沿用当前 D state
回退 SHALL 验证 `active_release.json`、`local_prior_binding.json`、两个 immutable manifest、当前 D state schema 与 read/write compatibility，然后将 prior 切为 active，并把回退前 active 作为新的唯一 prior。回退 SHALL NOT 替换当前 SQLite 文件、还原旧状态副本或执行 schema down-migration。

#### Scenario: 新 release 启动后健康检查失败
- **WHEN** candidate 未在时限内返回正确 release/manifest 身份或关键功能失败
- **THEN** 系统 SHALL 停止 candidate、恢复原 active pointer、以同一 D state 启动原 active，并只写失败 receipt；未成功激活的 candidate 不得成为 prior

#### Scenario: 已激活 release 需要人工回退
- **WHEN** 操作者选择唯一 prior 且 pair/state compatibility 全部通过
- **THEN** 系统 SHALL 原子切换 active 角色、启动原 prior、验证关键功能并写绑定 controller-produced verification aggregate hash 的 rollback receipt；回退后原 active 成为恰一 prior，当前 D state 的 current/event/revision/actor/time 均不得倒退

#### Scenario: Prior 不兼容当前 state
- **WHEN** prior 无法安全读取或写入当前 state schema
- **THEN** 回退 SHALL fail closed 并保持 active；系统不得通过替换 state、降级 schema或选择更早 release 绕过兼容门禁

### Requirement: C 到 D 的单一状态权威切换
系统 SHALL 让隔离候选只使用状态副本。首次 handoff SHALL 先在 D 根建立一棵冻结 V39 baseline `R0`，再准备与 `R0` 具有真实不同 release identity/manifest 的 successor candidate `R1`；不得以复制 V39 内容制造 `R1`。在外部流量/写入 fence 内停止旧 C writer、取得最终一致副本后，系统 SHALL 先以同一最终 D state 验证并建立尚未对外的 `R0` active，再通过正常激活协议把 `R1` 切为 active、让 `R0` 成为唯一 prior。只有 active pointer、`local_prior_binding` 和 post-activation 验证均成功后才开放 D 流量。若 D 尚未接收任何外部写入且任一步失败，可恢复未变化的 C；D pair 开放流量后 SHALL 禁止 C 服务再次写入，后续回退 SHALL 只使用 D active/prior 和同一 D state。

#### Scenario: 首次 D baseline 形成可重放终态
- **WHEN** D active/binding 均不存在，ingress 已关闭，旧 C writer 已 fence，最终 D state identity 已固定，且 R0 对该 state 的 live identity、读写和 writer fence 均通过
- **THEN** 控制器 SHALL 以 `bootstrap_first_pair` durable intent 和 activation-family terminal receipt 完成 `active: absent→R0`；该 result pair 是唯一允许 `prior=null` 的成功形状，receipt SHALL 绑定 attempt、原 pointer/binding absent 与上述现场证据
- **AND** 该 receipt SHALL NOT 授权 ingress、cleanup 或稳态完成；只有后续普通 `R0→R1` activation 形成 `R1 active + R0 prior` 并通过全部门禁后才可开放流量

#### Scenario: 首次 D baseline 启动失败
- **WHEN** 最终状态已复制但 D baseline 在开放外部流量前失败
- **THEN** 系统 SHALL 证明 D 没有外部写入、丢弃失败副本并恢复原 C authority；不得把尚不存在的 D prior 当作回退目标

#### Scenario: 旧 C 服务试图在切换后重启
- **WHEN** D state 已成为 authority 而旧 C 服务被启动
- **THEN** writer fence/服务配置 SHALL 阻止其写入并产生可见告警，不得形成双写

### Requirement: 激活崩溃协调不得产生第二 current authority
pointer 切换前 MAY 写入仅用于 crash coordination 的 durable pending journal；journal SHALL 绑定 exact attempt/phase/role/nonce 与预选 receipt ID，并 SHALL NOT 被解析为 current、prior、成功证据或 runtime qualification。transient服务启动SHALL先由service-host-local、fixed-D、existing-only且zero-write的一次性fence重放完整canonical history，要求全局恰一non-terminal attempt且唯一latest phase恰为该role的`*_start_authorized`，逐字段核对closed SCM identity，并证明当前role的result／fixed aggregate／post-canary alias全absent；无journal、terminal／verified、foreign／duplicate／fork／artifact／race全部拒绝。该reader不得调用会create layout的persistence factory或短读即关路径；fence SHALL NOT获取controller B2 lock或写入journal，并SHALL在CreateJob／CreateProcess／ResumeThread前后重复确认latest revision、bytes与artifact absence未漂移。product service必须显式接管pywin32状态机：transient只在post-Resume journal/artifact checkpoint后报告RUNNING；steady在START_PENDING完成static/Job/post-Resume prelaunch facts后报告RUNNING，再继续持同一B2 lock/workspace完成RUNNING-only SCM/endpoint/writer全链、final facts与job promotion，后链失败kill/exit且status单独不构成steady成功。两类child还必须在listener前以host-owned匿名pipe建立默认关闭的最外层admission gate：transient永不开放普通请求；steady只有全链、final facts与job promotion通过后才可写PREPARE并进入仍关闭的`ack_pending`，host fresh fixed endpoint/writer readiness acknowledgement通过后才派生一次性COMMIT authority，同一pipe收到COMMIT+EOF才可`admitted`，post-commit observation通过后方可unlock/wait。任何prepare/ready-ack/commit/close/observation unknown均kill job；reader fatal必须终止child/whole Job而不得只留内存标记；verified transient必须停止并fresh steady boot，不得原地升级为生产ingress。

qualification SHALL 由 B2 one-shot transition 在最后 live replay 后消费并推进相邻 journal revision；旧 revision、result、aggregate 与 qualification 在推进后均不得继续使用。无活动 journal 的普通 reboot SHALL 从 active pointer + exact binding/retention/state/tooling 与本次旧 C live fence 派生 distinct steady authority，不得构造 transient attempt；`active + prior=null` bootstrap 中间态不得稳态启动。

#### Scenario: 激活进程在任一切换阶段中断
- **WHEN** 部署在 journal、pointer、candidate start、post-activation probe、receipt append、binding update 或 cleanup 任一 crash cut 中断
- **THEN** `active_release.json` SHALL 仍是唯一 active authority；replay SHALL 机械判断是完成新 pair 还是恢复原 pair，并最终只留下一个终态 receipt。普通 reboot/手工 start SHALL 拒绝 pending 状态，身份漂移时 fail closed

#### Scenario: Canary result 与 verified revision 之间中断
- **WHEN** result／aggregate 已 create-only durable，而 expected `*_verified` revision 尚未 durable
- **THEN** replay SHALL 把该 attempt 送入绑定 artifact hash 的 failure path，并在 job/writer/listener/SQLite guard 全部关闭且 failure receipt durable 后才清理隔离副本；不得从 artifact 恢复 qualification 或覆盖 result 后重试

#### Scenario: 普通 reboot 与 pending 互斥
- **WHEN** SCM 自动启动时存在任一 non-terminal journal，或不存在 journal但 active/binding/恰一 prior closure不闭合
- **THEN** service host SHALL fail closed；前者只能由显式 controller replay 使用 transient authority，后者不得从最新 receipt、prior 目录或 bootstrap R0 猜测 steady current

#### Scenario: 手工重算 transient identity 但没有 matching journal
- **WHEN** 调用者从任意字段重算合法 SCM plan／authorization hash并作为 transient args 启动 service，而 fixed-D canonical journal history不存在对应唯一 latest `*_start_authorized` revision
- **THEN** service host SHALL 在第一个 launch Win32 syscall前拒绝；不得因 parser 接受 closed identity而进入 child/job/writer 生命周期
- **AND** controller crash 后普通无参 SCM restart仍拒绝 pending；只有显式 replay 携带与遗留 start-authorized revision exact一致的 closed identity，且四个 journal checkpoint均稳定，才可重新启动该 attempt
- **AND** 显式 replay 还须证明当前 role 的 result／aggregate及post-canary alias全部absent；任一已存在时只能进入`ambiguous_post_canary_pre_revision`失败路径

#### Scenario: 成功与失败 receipt 同时出现
- **WHEN** 同一 attempt 存在互斥终态 receipt、重复 receipt ID 或 receipt 指向非 pair release
- **THEN** 系统 SHALL 拒绝自动重放与清理，保持可验证 active 不变并要求显式处置

### Requirement: 生产保留集合必须严格限于 active 与 prior
终态清理 SHALL 以 `active_release.json` 和已匹配的 `local_prior_binding.json` 为唯一 release roots。除正在执行且有 durable attempt journal 的 candidate 外，旧 release、旧 prior、完成的 incoming、partial 与重复对象 SHALL 不得继续作为生产 retained release；清理结果 SHALL 有 receipt，并在下一 publish 前复验。

#### Scenario: 对象仍被 active 或 prior 引用
- **WHEN** 清理扫描发现对象属于 active 或 prior manifest closure
- **THEN** 系统 SHALL 保留该对象；只有两个 closure 均不引用且不存在活动 attempt 时才可删除

#### Scenario: 第三个生产 release 遗留
- **WHEN** 终态扫描发现 active/prior 之外还有未被活动 attempt 引用的 release tree
- **THEN** retention gate SHALL 失败，下一次 publish SHALL 被阻止，直到精确目标经 hash/path/reparse 审计后清理并生成 receipt

### Requirement: 本地 prior 不得被表述为数据或主机级保护
本 change 的回退能力 SHALL 只覆盖生产 VM 精确 D 根仍完整、当前 state 和对象 closure 仍可读时的最近一代版本切换。系统 SHALL NOT 生成任何声称能够在 VM、D 根、对象库或 state 整体丢失后重建服务的 certificate、status 或 receipt，也 SHALL NOT 设置周期性状态副本任务作为发布门禁。

#### Scenario: D state、对象 closure 或项目根不可用
- **WHEN** 当前 state、active/prior closure 或精确项目根任一整体不可读或缺失
- **THEN** 本地回退 SHALL fail closed，并明确报告超出本 change 的能力边界；不得把 prior release 存在误报为系统可重建

#### Scenario: 发布检查发现旧的跨主机保护接口仍存在
- **WHEN** installed wheel、CLI、config、schema、定时任务或正式导出面仍暴露不属于 active/prior 合同的项目保护 producer/consumer
- **THEN** release gate SHALL 失败；相关 public symbols、entry points 与产品实现 SHALL 被移除并以 source/fresh-wheel inventory 证明不可发现、不可导入、不可调用，不得继续作为 Stage 1–5 资格证据

### Requirement: Public 到 Private 的最终门禁
GitHub repository SHALL 在 Stage 0–5 保持 Public，同时阻止 reference、内部研究、PDF、数据库、对象、secret 和生成状态进入 Git；仅在 Stage 5 release certificate 后 SHALL 转为 Private。

#### Scenario: Repository 已转换为 Private
- **WHEN** Stage 5 certificate 后完成可见性转换
- **THEN** 系统 SHALL 重新核验实际 plan、Actions、branch/environment protection、CI、publish CLI 权限和 exact-SHA candidate，并完成一次 Private CI 与无生产切换候选演练后才允许项目关闭
