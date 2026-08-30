## Why

当前平台已有成熟前端、候选发布、版本对象、评论持久化和增量 intake，但 D 盘 VM 迁移、GitHub 精确提交发布、通用 reference 编译、结构化知识检索和 MCP 尚未形成一个真实可落地的闭环。原设计把首次 VM 验证排在内容、MCP 和 PostgreSQL 之后，并锁定逐文件 policy、窄 PG、八工具和 self-hosted runner，复杂度超过当前负载所需，也推迟了最基础的原样迁移目标。

运行连续性采用生产 VM 内的本地版本回退：所有项目文件均位于精确 `D:\quant\quant_platform`，生产稳态只保留 active 与恰一 prior，二者共用当前 D state。

## What Changes

- 先建立 V39 原样迁入 D 盘、可验证和可回退的最小发布纵切，再在同一版本计划内完成 parser、检索和 MCP。
- 将生产 VM 的闭合写入根固定为 `D:\quant\quant_platform`：checkout、candidate、release、state、audit、lock、log、tooling、TEMP/TMP 和 bytecode 均不得写到 `D:\`、`D:\quant`、sibling/parent 或 C 盘；执行前后均须机械验证并审计。
- 将既有 legacy 页面冻结迁移与新增研究 generic renderer 明确分轨，禁止通用 IR 改变旧页面默认表现。
- 本版保留 release 外 SQLite comment authority，补齐 stable document target、确定性 block/span anchor、history/unresolved 可见性和非空跨版本浏览器/数据库验收；PostgreSQL 改为观测触发的后续 change。
- 以目录/模式定义默认 publishable 来源边界，正常新增 Markdown 自动候选，异常才 quarantine。
- 补齐 V39 全量非 Git 资产 bootstrap、后续 hash 增量、C→D writer fence 和单一状态权威。
- 分离确定性 Document IR 与知识编译，增加字段级来源、候选/验证/接受状态和 coverage report。
- 将 `deepseek-v4-pro` 纳入 changed-only、external-AI-policy-gated 的自动知识编译；generation 同时绑定官方确认的实际 provider revision 与 API 返回 model/fingerprint，alias、prompt/schema 或分段身份漂移必须保留旧 job、审计 supersede 并显式 targeted recompile。Git 外受保护的 compiler workspace 不进入 release；release 只密封正式知识与所选成功 generation。确定性 base snapshot 可在语义增强 pending 时先发布；正式知识变化即使 commit/reference 相同也生成新的 snapshot/release/manifest，后续失败尝试不撤回上一成功 generation。
- 以 heading-aware source chunks、结构化 metadata/关系、active membership 和增量失效形成 lexical/structured RAG；使用 source-span qrels、development/封存 holdout、hard negatives、无答案、条件冲突、版本和错引切片验证，vector 采用多目标决策。
- 用客户端本地 stdio、经 VM active identity 校验的只读 immutable mirror、可跨项目安装 profile、路由规则和 tool-call trace 完成 MCP；从独立 `D:\quant\backtest_demo` 验证隐式调用与 snapshot 更新，不预设八工具，不实现 HTTP MCP。
- 选择受控单命令 publish CLI + GitHub-hosted exact-SHA CI + VM 固定 deploy CLI；部署采用 latest-only coalescing，本版不实现裸 push watcher。
- 将版本身份收敛为 immutable `release_manifest.json` 与唯一 `active_release.json`。`local_prior_binding.json` 只绑定经验证的 active/prior manifest；activation/rollback receipt 绑定结果 pair，failure receipt 显式绑定 operation、原 pair 与 target candidate 并区分新 candidate 激活、exact prior 回退和空 D pair bootstrap，cleanup receipt 绑定保留 pair 与精确移除目标；所有 receipt 都只记录结果，不得成为 current pointer。release manifest 不反向引用 binding 或 receipt。
- 每次成功激活后只保留新 active 与旧 active 形成的恰一 prior；更早 release 和终态 candidate 在绑定、receipt、hash 与启动验证通过后清理。普通回退交换 active/prior 角色并继续使用同一 D state，不恢复旧 SQLite 文件、不降级 schema。
- 取消跨主机发布保护、整盘重建和周期性状态副本作为本版门禁。任何涉及 VM、D 根、对象库或 state 整体丢失的处理均明确超出本 change 的可恢复承诺，不得借本地 prior 验收宣称已经覆盖。
- GitHub 在 Stage 0–5 固定保持 Public；release certificate 后转 Private，复核实际 plan/Actions/protection/权限并完成无生产切换候选演练后才关闭项目。
- 以 SHA-256 固定的真实 Q5 长文在隔离 acceptance source root 建立新 test-only identity，证明 generic renderer 无需手工 route/template 即可完成标题、公式、宽表、代码、引用/locator、版本和知识展示，同时 legacy V39 零未授权变化。
- 本 change 已获用户批准进入 apply；实施仍必须遵守 writer handoff、active/prior 同 state、Stage 5 certificate 与 Public→Private 的既定硬门禁。

## Capabilities

### New Capabilities

- `vm-atomic-deployment`: V39 bootstrap、精确 SHA 单命令发布、active + 恰一 prior 的 VM 本地回退和 Public→Private 关闭门禁。
- `external-comment-persistence`: 两族 comment 与其他在线状态在 release 外 SQLite 中持久化、稳定 target/anchor、跨版本可见、schema 前向兼容和候选隔离验证。
- `reference-versioned-ingestion`: 默认自动发现、不可变版本、确定性 base snapshot、DeepSeek changed-only job 和真实复杂文档 generic 展示门禁。
- `knowledge-retrieval`: DeepSeek 实际 revision/generation/provenance、机械或人工接受、稳定 source chunk、结构化 lexical 检索和独立质量评测。
- `quant-knowledge-mcp`: 最小只读工具面、pending/enriched 语义、本地 mirror/authority-verified stdio、跨项目安装和主动调用验证。
- `release-consistency`: 单一 manifest/active authority 下 base/enriched snapshot、本地 active/prior 无环绑定、严格两版本保留与引用一致性。

### Modified Capabilities

无；当前 OpenSpec 尚无正式基线 specs。

## Impact

影响 `quant_hub` 的 archive/integration/collaboration/web/search 边界及新增 knowledge/MCP/ops 边界、VM 唯一可写根 `D:\quant\quant_platform`、GitHub CI，以及客户端本地 stdio、可跨项目安装的 Codex profile。`reference/**` 与 `D:\quant\industry_demo` 保持只读；现有前端不重做；旧 C 盘线上服务在新 D 盘候选获批前保持不变且只读核验。既有跨主机保护相关实现不再构成产品能力或放行证据，后续代码与文档须按新的本地 prior 合同收敛。
