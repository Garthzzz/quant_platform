## Context

总体事实、方案比较、数据量、首次 bootstrap、知识形成和分阶段计划见 `project_state/architecture/quant_platform_VM知识MCP总体设计_20260820.md`；本地 prior 的代码级状态机、身份、SQLite/CAS、journal 与 crash-cut 合同见 `project_state/architecture/VM本地单一prior部署详细设计_20260826.md`；十二项独立审核见 `project_state/reviews/quant_platform_vm_mcp_20260820/Codex独立架构审核与修订_20260820.md`。当前 GitHub 仓库为 Public 且已有实施提交；VM `D:\quant\quant_platform` 已有受控暂存件但尚无 active/candidate/writer，现网仍为 V39，状态权威仍在 `C:\quant_platform_data`。V39 含约 742.6 MB ZIP/824.6 MB runtime，不能只靠 Git checkout 迁移。两族 comment 均为空，现有外置 SQLite 已具备审计、幂等 receipt 和 online backup 骨架，可用于候选隔离副本；但当前更新语句仍是预读 revision 后按 ID UPDATE，缺少 deployment gate 所需的 SQL predicate/rowcount CAS，不能直接作为 B3 放行证据。

本版的连续性边界是生产 VM 精确 D 根内的 active + 恰一 prior 普通版本回退；两者始终使用同一当前 D state。

## Goals / Non-Goals

**Goals:**

- 最先证明 V39 前端、功能、数据和非 Git 资产可原样进入 D 盘，并能在版本故障时切回恰一 prior。
- 生产 VM 的代码、checkout、candidate、release、state、audit、lock、log、tooling 与临时文件只能写入精确根 `D:\quant\quant_platform`；禁止上级、同级和 C 盘写入，并以 canonical/reparse preflight 与 post-write audit 验证。
- 让一个受控 publish 命令完成一次 push、精确 SHA CI、候选传输、激活和本地 prior 维护。
- 让正常新增/修订 reference 自动形成版本化页面、知识、Search 和 MCP 内容。
- 让方法、条件、限制、失败经验和证据具有字段级来源与事实状态。
- 让 Codex 在真实因子、模型、数据和回测任务中主动、适当地调用 MCP。

**Non-Goals:**

- crawler、账号/SSO、全库 PG、复杂调度、集群零停机、现有前端重做。
- 本版不实现没有消费者的 HTTP MCP，不以 vector、PostgreSQL 或高级图表语义作为完成门禁。
- 本版不承诺在 VM、D 根、对象库或 state 整体丢失后重建系统，也不把普通版本回退描述为数据保护。
- 本设计轮不实施代码、Git、数据库或 VM 操作。

## Decisions

1. **部署纵切前置。** Stage 0/1 先冻结 V39 inventory、复制完整 Git 外资产、验证 D candidate 和本地 prior rollback；parser/MCP 在 Stage 3/4 继续作为本版强制交付。
2. **双轨 renderer。** 当前页面始终走 legacy compatibility renderer；新导入研究走命名空间隔离的 generic renderer。以固定 SHA 的真实 Q5 长文作为隔离新身份 fixture，要求无专用 route/template 完成标题、公式、宽表、代码、引用/locator、版本与已验证知识展示，并相对 raw Markdown 有可测导航改善；高级交互不进入本版。
3. **受控单命令 publish CLI。** 它在 push 前冻结不进入 Git 的 reference/resources，执行一次 push 并等待 exact-SHA GitHub-hosted CI，再调用固定 VM deploy CLI。本版不实现裸 push watcher、pre-push 部署 hook、self-hosted runner 或 bare receive。
4. **latest-only coalescing。** 已进入 cutover 的部署不取消，等待中的旧 commit 可被最新 main 替换；不声称所有 pending FIFO 保留。
5. **单一 active identity 与本地 prior 绑定。** 不可变 `release_manifest.json` 包含 commit/content/resource/index/knowledge 与 state compatibility；`active_release.json` 只指向当前 `R_active`，是唯一 current authority。`local_prior_binding.json` 只指向经验证的 `R_active/R_prior`，不得被 Web、Search、MCP 或服务启动器当作 current pointer；release manifest 不引用 binding 或 receipt。activation/rollback receipt 绑定结果 pair；failure receipt 显式绑定 operation、原 pair 与 target candidate，并按 activation 新 candidate、exact prior rollback target、空 D pair bootstrap 区分；cleanup receipt 绑定保留 pair 与精确移除目标。它们都只是事件结果。
6. **恰一 prior 保留。** 成功激活后，先前 active 成为唯一 prior；更早 prior 只有在新 active、binding、receipt、hash、启动和 state compatibility 均验证后才清理。candidate/incoming 是瞬态，不计入生产保留集合，终态后必须清理。普通回退交换 active/prior 角色，回退后仍只保留两棵生产 release。
7. **SQLite comment authority 与稳定锚点。** 两族 comment 与其他可变状态使用固定 D state root；document comment 绑定 stable research/document identity，block/span 只在 exact unique proof 下重定位，失败项在历史和 unresolved 区可见。formal candidate/prior 只在 D runtime／ingress 已 fence 后，从同一 durable attempt/lock/nonce 的 B2 live state source／memory view 形成 D-root 隔离副本；CREATE_NEW creator handle 从首次 syscall 前登记并直接成为 mutable guard，不能 close/reopen；整个 transient application 只连接 role-local copies，closed seal/copy/compatibility evidence 不得冒充 live 输入。schema identity 绑定 comments 的 core/target marker 与 workspace 的迁移 hash 账本，`user_version` 仅作原始观察；CAS 必须有 SQL revision predicate、首次 1-row 与 stale 0-row 证据。live writer 资格由 kernel lock + lease record + SCM/进程/endpoint/canary 同一身份闭合，不接受自报布尔值。qualification 只由 B2 one-shot seam 消费并推进 journal；steady reboot 使用无 attempt/journal API 的 distinct B2 workspace/authority。controller B2 owner 与 SCM-host-local launch/lifetime owner 不跨进程共享；transient closed args 还必须经独立existing-only、zero-write的service-host reader从fixed-D canonical history核对唯一latest `*_start_authorized` revision、当前role result／fixed aggregate／post-canary alias全absent，并在CreateJob、CreateProcess与ResumeThread前后重复pinned checkpoint。该fence不得调用会create layout的persistence产品工厂或短读即关reader，不取得controller lock、不写journal，也不能生成qualification。产品service exact override pywin32 `SvcRun/SvcInterrogate`：transient只允许`START_PENDING→post-Resume journal/artifact checkpoint→SERVICE_RUNNING`；steady在START_PENDING完成static/Job/post-Resume prelaunch facts后报告RUNNING，仍持B2 lock完成RUNNING-only SCM→endpoint→writer全链、final facts与job promotion，status单独不形成steady成功，后链失败kill/exit。controller在transient RUNNING acknowledgement前保持B2 lock且不得POST或推进journal。所有runtime child在执行Python前通过creation-time JOB_LIST原子进入non-inheritable `KILL_ON_JOB_CLOSE` Job Object；同一HANDLE_LIST只继承匿名admission pipe read端与固定D log，host独占non-inheritable write端。最外层child gate默认只允许authority-kind对应的exact loopback deployment probe，普通请求固定503且不触碰业务/SQLite；transient永不开闸。steady只有全链+final facts+job promotion后才可写PREPARE并进入仍关闭的`ack_pending`；fresh fixed endpoint/writer readiness acknowledgement完成后B2才派生不可重放COMMIT authority，同一pipe收到COMMIT+EOF才`admitted`，post-commit observation通过后方可unlock/wait。prepare/ready-ack/commit/close/observation unknown全部kill job；reader fatal必须退出child/whole Job。verified transient必须停止并fresh steady boot，不能原地升级。新host先以全机窄枚举排除旧D child，service host crash不得留下writer/listener orphan。PG仅在多writer、锁争用或HA强制需求出现时另立change。
8. **状态不随版本回退。** candidate 与 prior 必须在激活前证明可安全读写当前 D state；schema 采用 expand-compatible-contract。普通回退不替换 SQLite 文件、不恢复旧数据、不做 down-migration。状态损坏或整体丢失超出本地 prior 合同，系统应 fail closed 而非把代码回退升级成状态替换。
9. **模式默认发布、异常隔离。** `reference/archive/**/*.md` 正常文件自动候选；reserved/draft/private/reparse/secret/结构错误/身份歧义 quarantine。删除仍需显式 tombstone。
10. **IR 与知识编译分层。** v1 IR 确定性覆盖 blocks/spans/heading/math/raw table/code/figure ref/citation；method/condition/limitation/failure 由 knowledge compiler 形成并带状态。
11. **结构化 lexical 基线。** 单语义 IR block 的 heading-aware source chunk、exact/alias/FTS5/CJK/short fallback、item-scope applicability、受控 facet alias、极性安全 relation 和确定性重排为必做；明确否定是正向 evidence 的硬约束，context span 不得冒充 matched evidence。chunk/metadata/active membership 与 Web/MCP 绑定同一 snapshot。qrels 绑定 source version/span、精确 byte range 与 quote/source hash；answerable 的 Recall/nDCG/MRR 和 no-answer accuracy 分开聚合。vector 只在封存评测显示综合净收益时加入。
12. **最小 MCP 工具面与闭合 stdio 拓扑。** 初始为 search/get/list-updates 三类并允许按 tool-choice 证据调整。stdio 由客户端 Codex 拉起，只读本地 immutable mirror；每次 current-sensitive 请求用只读 adapter 校验 VM active 三元组，不可达/过期/身份不明返回 stale/unavailable。交付 cwd 无关的安装 profile，并在 `quant_platform` 与独立 `D:\quant\backtest_demo` 验证隐式应调用/不应调用、search→get、activation/rollback 后重查；HTTP 延后。
13. **DeepSeek V4 Pro 是版本化增量 compiler。** 只对变更且获准外发的确定性 IR 建 job；每个 generation 同时绑定请求 alias、官方确认的实际 revision、identity evidence 与 API 返回 model/system_fingerprint。alias、fingerprint、prompt/schema 或确定性分段身份漂移时，旧 job 保持不可变并显式进入 audited superseded 状态，再建立 targeted recompile，不能混入旧知识。所有输出是带 span 的候选，只有机械验证或人工接受后进入正式知识。compiler workspace 固定在 Git 外受保护的本地发布状态根；全体 job terminal 后以 SQLite 一致性副本形成 immutable promotion receipt。发布、holdout 和 artifact builder 只能以严格 read-only/immutable store 消费该 promoted authority，禁止切换 journal mode、初始化 schema 或回填行；任何知识写入都必须发生在新的 compiler workspace 并形成新 promotion。release 只密封正式知识投影与被选中的最新成功 generation provenance，不携带 job 数据库、待审核候选或凭据。语义知识变化即使 commit/reference 未变，也必须形成新的 effective snapshot、release ID 与 manifest；后续失败或 pending generation 保留上一成功 generation 和 active identity，成功后才另发 enriched snapshot。
14. **VM 单根之外没有本版项目存储。** 所有项目 release、state、audit 和临时数据都在精确 D 根。发布门禁只证明 active/prior 与当前 state 的版本回退，不生成或消费任何跨主机保护权威，不运行周期性状态副本调度，也不把数据整体丢失纳入 release certificate。
15. **Public→Private 是最终 Stage 6。** 开发、迁移和 Stage 5 验收均保持 Public；所有非公开资产持续禁入 Git。Stage 5 certificate 后转 Private并完成 plan/Actions/protection/权限、CI 和无切换 candidate 复验。

## Risks / Trade-offs

- [单命令不是裸 `git push`] → 这是已锁定的安全边界；本版不提供第二个生产入口。
- [开发机在 publish 期间离线] → active 保持不变，candidate 可按 exact SHA 显式重放；不引入常驻任意 workflow executor。
- [首次大体量复制中断] → `.partial`、逐对象 hash 和 resume；完整 inventory 通过后才重命名。
- [C/D 双写] → candidate 使用副本；最终停 C writer、复制、校验、禁用旧服务；rollback 永远使用 D state。
- [只有一个 prior] → 仅承诺最近一代代码/内容版本回退；每次切换前同时证明 candidate 与将成为 prior 的 active 兼容当前 state，旧于 prior 的 release 不再保留。
- [VM 或 D 根整体丢失] → 本版明确没有可恢复性承诺，release certificate 必须把该剩余风险写明；不得以本地 prior 测试替代数据或主机级保护。
- [机器抽取产生伪结构] → 字段级 source span、确定性验证、二次 verifier、candidate 默认排除和 coverage report。
- [qrels 过拟合、邻接 span 污染或随来源漂移] → qrel 绑定 source version/span + exact byte range + quote/source hash，只以卡片 exact locator 判命中；来源修订即 stale；development/封存 holdout 分离，并覆盖 hard negative、无答案、冲突、历史和错引。
- [DeepSeek 外部调用失败/注入] → policy fail-closed、无工具/secret、严格 schema/span；base snapshot 独立可用，旧 generation 不被静默覆盖。
- [DeepSeek rolling alias 漂移] → 官方 revision evidence 与响应 model/fingerprint 双记录；身份差异进入隔离，新 identity contract + targeted recompile 后才可使用。
- [comment 数据存在但因 source/renderer 变化不可见或错挂] → stable document target、exact unique anchor mapping、history/unresolved fallback 和非空浏览器+数据库序列。
- [跨项目 stdio 使用旧 mirror] → current-sensitive authority probe、fresh/stale/unavailable、continuation invalidation 与 `D:\quant\backtest_demo` activation/rollback trace。
- [SQLite schema 使 prior 失效] → manifest read/write range、expand/compatible/contract 和升级后 prior 实测；普通回退不 down-migrate state。
- [仓库可见性变化] → Stage 0–5 固定 Public；Stage 6 转 Private 后重新探测 plan、Actions、protection、CI 与 publish 权限，且不切生产。

## Migration Plan

按 tasks 的 Stage 0–6 执行：权威基线与 active/prior schema → D 盘冻结 V39 baseline `R0` bootstrap → 准备具有真实不同 manifest/release identity 的 successor candidate `R1` → 获批后在 writer fence 内先建立尚未对外的 `R0` active，再用正常激活协议形成 `R1` active + `R0` prior → 单命令发布 → deterministic reference base → DeepSeek/知识/RAG/MCP → 全局本地回退放行与 release certificate → Public 转 Private 后的无生产切换关闭验证。不得复制 V39 内容或伪造身份来填充 prior；首次 pair 成功并开放 D 流量后 C 永久退出 writer authority，此后普通回退只使用 D prior + 当前 D state。PG、HTTP MCP、vector 和高级展示按触发条件另行决策。

## Resolved Decisions

- 首次基线固定 V39；本版唯一生产入口为受控 `publish`；GitHub 在 Stage 0–5 保持 Public，Stage 6 才转 Private；comment 使用外置 SQLite 与稳定 anchor；MCP 只做客户端 stdio，但必须可安装到独立量化项目。
- `deepseek-v4-pro` 是正式 changed-only semantic compiler；当前官方映射为 `DeepSeek-V4-Pro-0813`，但 generation 必须保存可核验的 revision evidence 和返回 fingerprint。
- 部署身份只允许 `active_release→R_active`、`local_prior_binding→R_active/R_prior`；activation/rollback、failure、cleanup receipt 分别只指向其结果 pair、operation + 原 pair + target candidate、保留 pair + 精确移除目标及结果。failure 的 operation 与失败阶段必须和同 attempt journal 完全一致；activation target 与原 pair 不同，rollback target 恰为原 prior，bootstrap 从空 D pair 开始。生产稳态保留 active + 恰一 prior，二者共用当前 D state。
- 本版不建立生产 VM D 根之外的项目恢复存储，不运行周期性状态副本，也不声明对整机、D 根、对象库或 state 整体丢失的恢复能力。
