## Context

总体事实、方案比较、数据量、首次 bootstrap、知识形成和分阶段计划见 `project_state/architecture/quant_platform_VM知识MCP总体设计_20260820.md`；十二项独立审核见 `project_state/reviews/quant_platform_vm_mcp_20260820/Codex独立架构审核与修订_20260820.md`。当前 GitHub 仓库为 Public 且为空，VM D 盘目标目录存在但为空，现网为 V39，状态权威仍在 `C:\quant_platform_data`。V39 含约 742.6 MB ZIP/824.6 MB runtime，不能只靠 Git checkout 迁移。两族 comment 均为空，现有外置 SQLite 已具备 CAS、审计和在线备份。

## Goals / Non-Goals

**Goals:**

- 最先证明 V39 前端、功能、数据和非 Git 资产可原样进入 D 盘并安全回退。
- 让一个受控 publish 命令完成一次 push、精确 SHA CI、候选传输和 VM 激活。
- 让正常新增/修订 reference 自动形成版本化页面、知识、Search 和 MCP 内容。
- 让方法、条件、限制、失败经验和证据具有字段级来源与事实状态。
- 让 Codex 在真实因子、模型、数据和回测任务中主动、适当地调用 MCP。

**Non-Goals:**

- crawler、账号/SSO、全库 PG、复杂调度、集群零停机、现有前端重做。
- 本版不实现没有消费者的 HTTP MCP，不以 vector、PostgreSQL 或高级图表语义作为完成门禁。
- 本设计轮不实施代码、Git、数据库或 VM 操作。

## Decisions

1. **部署纵切前置。** Stage 0/1 先冻结 V39 inventory、复制完整 Git 外资产、验证 D candidate 和 D prior rollback；parser/MCP 在 Stage 3/4 继续作为本版强制交付。
2. **双轨 renderer。** 当前页面始终走 legacy compatibility renderer；新导入研究走命名空间隔离的 generic renderer。以固定 SHA 的真实 Q5 长文作为隔离新身份 fixture，要求无专用 route/template 完成标题、公式、宽表、代码、引用/locator、版本与已验证知识展示，并相对 raw Markdown 有可测导航改善；高级交互不进入本版。
3. **受控单命令 publish CLI。** 它在 push 前冻结不进入 Git 的 reference/resources，执行一次 push 并等待 exact-SHA GitHub-hosted CI，再调用固定 VM deploy CLI。本版不实现裸 push watcher、pre-push 部署 hook、self-hosted runner 或 bare receive。
4. **latest-only coalescing。** 已进入 cutover 的部署不取消，等待中的旧 commit 可被最新 main 替换；不声称所有 pending FIFO 保留。
5. **无环单一 release identity。** 不可变 `release_manifest.json` 包含 commit/content/resource/index 与 state/recovery compatibility，但不含具体 recovery/checkpoint identity；`active_release.json` 只指向 release hash。immutable checkpoint 记录 captured-under release，`recovery_manifest` 单向指向 release+checkpoint，receipt 单向指向已验证对象且不是 pointer。激活前的 `recovery_protection_receipt` 只证明恢复闭包；成功切换并完成 post-activation 验证后才生成 `activation_receipt`；失败只生成 failure receipt。state-only backup 不改 release 或 active。
6. **SQLite comment authority 与稳定锚点。** 两族 comment 与其他可变状态使用固定 D state root；document comment 绑定 stable research/document identity，block/span 只在 exact unique proof 下重定位，失败项在历史和 unresolved 区可见。candidate 只用 online-backup 副本。PG 仅在多 writer、锁争用或 HA/RPO 强制需求出现时另立 change。
7. **模式默认发布、异常隔离。** `reference/archive/**/*.md` 正常文件自动候选；reserved/draft/private/reparse/secret/结构错误/身份歧义 quarantine。删除仍需显式 tombstone。
8. **IR 与知识编译分层。** v1 IR 确定性覆盖 blocks/spans/heading/math/raw table/code/figure ref/citation；method/condition/limitation/failure 由 knowledge compiler 形成并带状态。
9. **结构化 lexical 基线。** heading-aware source chunk、exact/alias/FTS5/CJK/short fallback、applicability、relation 和确定性重排为必做；chunk/metadata/active membership 与 Web/MCP 绑定同一 snapshot。qrels 绑定 source spans 和版本；vector 只在封存评测显示综合净收益时加入。
10. **最小 MCP 工具面与闭合 stdio 拓扑。** 初始为 search/get/list-updates 三类并允许按 tool-choice 证据调整。stdio 由客户端 Codex 拉起，只读本地 immutable mirror；每次 current-sensitive 请求用只读 adapter 校验 VM active 三元组，不可达/过期/身份不明返回 stale/unavailable。交付 cwd 无关的安装 profile，并在 `quant_platform` 与独立 `D:\quant\backtest_demo` 验证隐式应调用/不应调用、search→get、activation/rollback 后重查；HTTP 延后。
11. **DeepSeek V4 Pro 是版本化增量 compiler。** 只对变更且获准外发的确定性 IR 建 job；每个 generation 同时绑定请求 alias、官方确认的实际 revision、identity evidence 与 API 返回 model/system_fingerprint。alias 或 fingerprint 漂移先隔离，建立新 generation 并显式 targeted recompile，不能混入旧知识。所有输出是带 span 的候选，只有机械验证或人工接受后进入正式知识；故障时先发 base snapshot，成功后另发 enriched snapshot。
12. **Cold recovery 独立于普通回退且动态保护不改 release。** 普通回退使用 D prior + 当前 D state；D/VM/对象/state 灾难才显式选择 cold bundle 与 SQLite checkpoint。最终 `RECOVERY_ROOT` 必须实测位于生产 VM 整机之外，同一 VM 其他盘符、挂载或回指共享均不合格。V39 真实空 D 恢复通过前禁止首次 production handoff 和旧材料清理；最终 release 在 Stage 5 再演练。唯一 state-only job 至少每 24 小时新建 immutable checkpoint/RM/receipt，RPO 以最后验证 checkpoint captured_at 的实际年龄判断，超龄或失效进入 degraded/failed。
13. **Public→Private 是最终 Stage 6。** 开发、迁移和 Stage 5 验收均保持 Public；所有非公开资产持续禁入 Git。Stage 5 certificate 后转 Private并完成 plan/Actions/protection/权限、CI 和无切换 candidate 复验。

## Risks / Trade-offs

- [单命令不是裸 `git push`] → 这是已锁定的安全边界；本版不提供第二个生产入口。
- [开发机在 publish 期间离线] → active 保持不变，candidate 可按 exact SHA 显式重放；不引入常驻任意 workflow executor。
- [首次大体量复制中断] → `.partial`、逐对象 hash 和 resume；完整 inventory 通过后才重命名。
- [C/D 双写] → candidate 使用副本；最终停 C writer、复制、校验、禁用旧服务；rollback 永远使用 D state。
- [机器抽取产生伪结构] → 字段级 source span、确定性验证、二次 verifier、candidate 默认排除和 coverage report。
- [qrels 过拟合或随来源漂移] → qrel 绑定 source version/span，来源修订即 stale；development/封存 holdout 分离，并覆盖 hard negative、无答案、冲突、历史和错引。
- [DeepSeek 外部调用失败/注入] → policy fail-closed、无工具/secret、严格 schema/span；base snapshot 独立可用，旧 generation 不被静默覆盖。
- [DeepSeek rolling alias 漂移] → 官方 revision evidence 与响应 model/fingerprint 双记录；身份差异进入隔离，新 identity contract + targeted recompile 后才可使用。
- [D/VM 灾难或状态损坏] → 生产 VM 整机外故障域 attestation、SQLite checkpoint、首次切换前及最终 release 空路径恢复演练；状态恢复必须显式选择恢复点。
- [release↔recovery hash 环或每日备份使 active 漂移] → 固定 `active→R`、`C→captured R`、`RM→R/C`、`receipt→R/RM/C`；用 graph/hash fixture 拒绝反向引用。
- [comment 数据存在但因 source/renderer 变化不可见或错挂] → stable document target、exact unique anchor mapping、history/unresolved fallback 和非空浏览器+数据库序列。
- [跨项目 stdio 使用旧 mirror] → current-sensitive authority probe、fresh/stale/unavailable、continuation invalidation 与 `D:\quant\backtest_demo` activation/rollback trace。
- [SQLite schema 使 prior 失效] → manifest read/write range、expand/compatible/contract 和升级后 prior 实测；普通回退不 down-migrate state。
- [仓库可见性变化] → Stage 0–5 固定 Public；Stage 6 转 Private 后重新探测 plan、Actions、protection、CI 与 publish 权限，且不切生产。

## Migration Plan

按 tasks 的 Stage 0–6 执行：权威基线 → D 盘 V39 副本 bootstrap/独立故障域 attestation/V39 空 D 恢复 → 获批后首次 handoff 与 D prior → 单命令发布 → deterministic reference base → DeepSeek/知识/RAG/MCP → 最终 release 空 D/全局放行与 release certificate → Public 转 Private后的无生产切换关闭验证。首次 handoff 只有在 V39 empty-D PASS 后才可进入，在无外部写入 fence 内启动 D exact-V39 baseline；成功开放 D 流量后 C 永久退出 writer authority。其后普通回退只使用 D prior + 当前 D state，灾难恢复才显式选 checkpoint。PG、HTTP MCP、vector 和高级展示按触发条件另行决策。

## Resolved Decisions

- 首次基线固定 V39；本版唯一生产入口为受控 `publish`；GitHub 在 Stage 0–5 保持 Public，Stage 6 才转 Private；comment 使用外置 SQLite 与稳定 anchor；MCP 只做客户端 stdio，但必须可安装到独立量化项目。
- `deepseek-v4-pro` 是正式 changed-only semantic compiler；当前官方映射为 `DeepSeek-V4-Pro-0813`，但 generation 必须保存可核验的 revision evidence 和返回 fingerprint。cold recovery bundle 是 production release 的必备恢复保护，不是人工广播包；同一 VM 的另一盘符不构成独立故障域。Release/recovery 依赖固定单向无环，动态 checkpoint 不改变 release identity。
