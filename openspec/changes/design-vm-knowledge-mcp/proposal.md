## Why

当前平台已有成熟前端、候选发布、版本对象、评论持久化和增量 intake，但 D 盘 VM 迁移、GitHub 精确提交发布、通用 reference 编译、结构化知识检索和 MCP 尚未形成一个真实可落地的闭环。原设计把首次 VM 验证排在内容、MCP 和 PostgreSQL 之后，并锁定逐文件 policy、窄 PG、八工具和 self-hosted runner，复杂度超过当前负载所需，也推迟了最基础的原样迁移目标。

## What Changes

- 先建立 V39 原样迁入 D 盘、可验证和可回退的最小发布纵切，再在同一版本计划内完成 parser、检索和 MCP。
- 将既有 legacy 页面冻结迁移与新增研究 generic renderer 明确分轨，禁止通用 IR 改变旧页面默认表现。
- 本版保留 release 外 SQLite comment authority，补齐 stable document target、确定性 block/span anchor、history/unresolved 可见性和非空跨版本浏览器/数据库验收；PostgreSQL 改为观测触发的后续 change。
- 以目录/模式定义默认 publishable 来源边界，正常新增 Markdown 自动候选，异常才 quarantine。
- 补齐 V39 全量非 Git 资产 bootstrap、后续 hash 增量、C→D writer fence 和单一状态权威。
- 分离确定性 Document IR 与知识编译，增加字段级来源、候选/验证/接受状态和 coverage report。
- 将 `deepseek-v4-pro` 纳入 changed-only、external-AI-policy-gated 的自动知识编译；generation 同时绑定官方确认的实际 provider revision 与 API 返回 model/fingerprint，alias 漂移必须隔离并显式 targeted recompile。确定性 base snapshot 可在语义增强 pending 时先发布，验证后再激活 enriched snapshot。
- 以 heading-aware source chunks、结构化 metadata/关系、active membership 和增量失效形成 lexical/structured RAG；使用 source-span qrels、development/封存 holdout、hard negatives、无答案、条件冲突、版本和错引切片验证，vector 采用多目标决策。
- 用客户端本地 stdio、经 VM active identity 校验的只读 immutable mirror、可跨项目安装 profile、路由规则和 tool-call trace 完成 MCP；从独立 `D:\quant\backtest_demo` 验证隐式调用与 snapshot 更新，不预设八工具，不实现 HTTP MCP。
- 选择受控单命令 publish CLI + GitHub-hosted exact-SHA CI + VM 固定 deploy CLI；部署采用 latest-only coalescing，本版不实现裸 push watcher。
- 自动生成无 secret、机器可验证的 cold recovery bundle；最终 `RECOVERY_ROOT` 必须实测位于生产 VM 整机之外，同一 VM 其他盘符不合格。V39 从真实空 D 恢复通过前禁止首次生产切换和旧恢复材料清理；最终 release 再演练一次。唯一 state-only job 至少每 24 小时生成新的 immutable checkpoint/recovery receipt，RPO 以最后成功验证 checkpoint 的实际年龄判断，超龄进入 degraded/failed 并告警。激活前只生成 `recovery_protection_receipt`；成功切换并完成验证后才生成 `activation_receipt`，切换失败只生成 failure receipt。
- GitHub 在 Stage 0–5 固定保持 Public；release certificate 后转 Private，复核实际 plan/Actions/protection/权限并完成无生产切换候选演练后才关闭项目。
- 将版本身份收敛为单一 immutable `release_manifest.json` 与单一 `active_release.json`；release 只声明 state/recovery compatibility，不引用动态 checkpoint/recovery manifest。`recovery_manifest.json` 单向引用 release hash 与明确 checkpoint，receipt 只作证据，形成无环依赖。
- 以 SHA-256 固定的真实 Q5 长文在隔离 acceptance source root 建立新 test-only identity，证明 generic renderer 无需手工 route/template 即可完成标题、公式、宽表、代码、引用/locator、版本和知识展示，同时 legacy V39 零未授权变化。
- 本 change 仍只冻结设计和任务；业务实现、Git 初始化、数据库操作、VM 写入、切换和 push 留待批准后的 apply 阶段。

## Capabilities

### New Capabilities

- `vm-atomic-deployment`: V39 bootstrap、精确 SHA 单命令发布、D prior 回退、独立故障域/空 D 前置门禁、cold recovery 和 Public→Private 关闭门禁。
- `external-comment-persistence`: 两族 comment 与其他在线状态在 release 外 SQLite 中持久化、稳定 target/anchor、跨版本可见、schema 前向兼容、备份和恢复点。
- `reference-versioned-ingestion`: 默认自动发现、不可变版本、确定性 base snapshot、DeepSeek changed-only job 和真实复杂文档 generic 展示门禁。
- `knowledge-retrieval`: DeepSeek 实际 revision/generation/provenance、机械或人工接受、稳定 source chunk、结构化 lexical 检索和独立质量评测。
- `quant-knowledge-mcp`: 最小只读工具面、pending/enriched 语义、本地 mirror/authority-verified stdio、跨项目安装和主动调用验证。
- `release-consistency`: 单一 manifest/active authority 下 base/enriched snapshot、无环 recovery/checkpoint 依赖、动态 RPO、历史与引用一致性。

### Modified Capabilities

无；当前 OpenSpec 尚无正式基线 specs。

## Impact

影响 `quant_hub` 的 archive/integration/collaboration/web/search 边界及新增 knowledge/MCP/ops 边界、VM `D:\quant\quant_platform`、GitHub CI，以及客户端本地 stdio、可跨项目安装的 Codex profile。`reference/**` 与 `D:\quant\industry_demo` 保持只读；现有前端不重做；旧 C 盘线上服务在新 D 盘候选获批前保持不变。
