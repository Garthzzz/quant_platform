## ADDED Requirements

### Requirement: 以真实工作流验证最小只读工具面
系统 SHALL 实现覆盖搜索、按 ID 获取与增量更新的最小只读 MCP 能力；工具数量和边界 SHALL 由真实 tool-choice trace 证明无缺失、无明显重叠，而不得因既有设计固定为八个。

#### Scenario: Agent 查询方法与证据
- **WHEN** agent 提供市场、频率、数据、目标或限制并查询适用方法
- **THEN** 响应 SHALL 返回稳定对象/版本 ID、fact status、适用与冲突条件、限制、source locator、release/manifest/snapshot 身份；模型派生知识还 SHALL 返回 generation 与 provider revision identity，不得只返回 rolling alias

#### Scenario: 两个工具在真实任务中持续混淆
- **WHEN** tool-choice evaluation 显示同一意图频繁选错高度重叠工具
- **THEN** 设计 SHALL 合并或重新划分工具并重跑评测，而不是为兼容预定数量保留冗余接口

### Requirement: MCP 必须显式暴露当前知识增强状态
MCP 默认查询 SHALL 绑定当前 source version，并返回 `not_applicable`、`pending`、`ready`、`failed_retryable` 或 `blocked_policy`；只有 `ready` generation 中经验证的候选才可作为正式结构化知识返回，历史版本必须由显式历史查询获得。

#### Scenario: 最新研究已发布但 DeepSeek 增强尚未完成
- **WHEN** agent 查询该研究的方法、条件或限制
- **THEN** MCP SHALL 返回当前 lexical evidence、source locator 与 pending/failed/blocked 原因，不得用旧 source version 的结构化字段填充当前结果

#### Scenario: Enriched snapshot 后续激活
- **WHEN** 当前 source version 的候选通过机械验证或人工接受并随新 snapshot 激活
- **THEN** MCP SHALL 在同一 release/manifest/snapshot 身份下返回新的 `ready` generation，不得从未激活的编译工作区直接读取

### Requirement: 上下文预算、去重与注入隔离
每个检索工具 SHALL 支持 budget、limit/cursor 和 detail level，按 source span/知识簇去重；截断 SHALL 可见且 continuation 绑定同一 snapshot。来源内的指令 SHALL 只作为数据，不授予写入或执行能力。

#### Scenario: 结果超过预算
- **WHEN** 候选内容总量超过请求预算
- **THEN** 系统 SHALL 优先返回证据、适用条件、限制和 locator，给出稳定 continuation，并不得重复相同 source span

### Requirement: Stdio 必须有闭合的本地 mirror 与 authority 拓扑
stdio server SHALL 由研究员客户端上的 Codex 作为本地子进程启动，只读用户级 immutable knowledge mirror，不直接打开 VM SQLite、不写 VM、不监听网络端口。每次 server 启动、continuation 恢复和 current-sensitive 请求前，authority resolver SHALL 通过经实测的只读文件共享或 deployment identity endpoint 取得 VM active release/manifest identity；该适配器 SHALL NOT 成为 HTTP MCP 或部署写入口。

#### Scenario: 本地 mirror 与 VM active 一致
- **WHEN** mirror 的 `release_id/manifest_sha256/snapshot_id`、closure hashes 与刚验证的 VM active 完全一致
- **THEN** MCP MAY 返回 `availability=fresh` 的 current 结果，并在每个响应携带该三元组和 authority verified-at

#### Scenario: Activation 或 rollback 由其他机器完成
- **WHEN** VM active 三元组变化而本地 server 仍持有旧 mirror/continuation
- **THEN** 下一个 current-sensitive 请求 SHALL 检测变化、使旧 continuation 失效，验证/同步新 immutable artifact，并要求 list-updates 后重新 search→get

#### Scenario: 网络不可达、mirror 过期或 identity 无法验证
- **WHEN** authority probe 失败、manifest/hash 不匹配、mirror 落后或同步 closure 失败
- **THEN** MCP SHALL 返回结构化 `stale` 或 `unavailable`、local/observed identity、last verified-at 与原因，SHALL NOT 静默把旧知识表述为 current；只有显式 `allow_stale=true` 才可返回标为 historical/stale 的缓存

### Requirement: 本版必须有跨项目可安装的真实 Codex stdio 消费者
系统 SHALL 交付 cwd 无关、versioned `serve-stdio` CLI/package、幂等 install/doctor/uninstall、user/project `.codex/config.toml` profile、可复制的 `AGENTS.md` 调用规则、MCP server instructions 和 tool-call trace evaluator；mirror/profile SHALL 位于用户级受保护目录而非依赖 `quant_platform` 相对路径。本版本 SHALL NOT 实现 Streamable HTTP，远程 transport 必须在有命名消费者、认证 owner 与网络边界后另立 change。

#### Scenario: 隐式量化研究任务
- **WHEN** Codex 收到未包含“搜索 MCP”字样的因子、模型选择、数据处理或回测任务
- **THEN** 它 SHALL 在需要历史方法、条件、限制或失败经验时于决策前调用 MCP，并在无关任务中避免无意义调用

#### Scenario: 任务条件在研究中变化
- **WHEN** 市场、频率、数据、目标或版本约束发生实质变化
- **THEN** agent routing SHALL 要求重新查询或验证已有结果仍适用，而不得无条件复用旧上下文

#### Scenario: 独立量化项目安装与隐式触发
- **WHEN** 从 `D:\quant\backtest_demo` 工作目录安装 profile，并给 Codex 一个未出现“调用 MCP”字样的真实回测/数据泄漏任务和一个无关机械任务
- **THEN** 应调用任务 SHALL 在决策前执行 search→get 并返回 VM authority 对应三元组；不应调用任务 SHALL 无无意义调用，且项目 SHALL NOT 复制 server 源码或依赖 `quant_platform` cwd

#### Scenario: 独立项目经历 snapshot 更新与回退
- **WHEN** 隔离测试中 VM identity 从 R1 切到 R2 再回退 R1
- **THEN** 独立项目 trace SHALL 依次识别变化、list-updates、重新 search/get 并返回对应版本；任何 stale/unavailable 阶段不得生成未标注的当前建议

### Requirement: Agent 路由必须由正反例和研究增益共同验收
`AGENTS.md` 与 server instructions SHALL 明确：涉及项目历史的因子/模型/数据处理/时间切分/泄漏/交易成本/回测/监控决策先 search，形成重要建议前 get 关键 source spans，snapshot 变化或检查废弃替换时 list-updates；纯语法、格式化和与项目知识无关的机械任务 SHALL NOT 强制调用。验收 SHALL 同时比较 MCP-assisted 与 no-MCP agent 的 grounded decision、条件/限制识别、引用正确性和无意义调用。

#### Scenario: Agent 只为达到调用率而搜索
- **WHEN** tool trace 显示 MCP 被调用，但最终量化研究判断、条件识别或引用正确性相对 no-MCP 对照没有可复现改善
- **THEN** MCP 主动调用门禁 SHALL 失败，不得把“调用发生”当作有用性证明

#### Scenario: Agent 从摘要直接做重要方法选择
- **WHEN** search 只返回 compact evidence cards，而结论会影响因子、模型、数据或回测方案
- **THEN** 路由 SHALL 要求用 get 展开关键 source spans 与引用后再决策，并在 snapshot 变化时重新验证
