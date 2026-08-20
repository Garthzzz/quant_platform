## ADDED Requirements

### Requirement: 正常来源默认自动候选
系统 SHALL 自动发现 `reference/archive/**/*.md` 的新增与修订；未命中 reserved、draft/private/backup、reparse、secret、结构错误或身份歧义规则的普通研究 SHALL 默认进入 publishable candidate，而无需逐文件 policy/PR。

#### Scenario: 正常目录新增研究
- **WHEN** 研究员在允许目录放入结构有效且未命中异常规则的新 Markdown
- **THEN** 系统 SHALL 自动冻结、解析、索引并在验证通过后展示，不要求手工新增 route、template 或 per-file policy

#### Scenario: 新文件疑似内部草稿或含敏感信息
- **WHEN** 路径/文件名/secret scan 命中隔离规则或系统无法确定身份
- **THEN** 系统 SHALL 将该文件 quarantine、报告原因并继续处理不相关正常文件

### Requirement: 不可变版本、移动与显式删除
系统 SHALL 以来源 bytes hash 创建不可变版本并维护 supersedes；stable research/document identity SHALL 与 release path 和 snapshot-local row 分离。同 hash 纯移动可保留 stable ID，移动同时修改且证据不足时 SHALL quarantine；publishable 路径消失必须有 tombstone 才能从默认召回移除。每个 snapshot SHALL 为 comment consumer 生成 exact/unique、带原因的 anchor projection，而不得改写 comment authority。

#### Scenario: 修订解析失败
- **WHEN** 新版本在 parse、render、link、knowledge 或 index 任一步失败
- **THEN** 页面、Search 和 MCP SHALL 继续使用上一 active 版本，并保留可审计失败 candidate

#### Scenario: Publishable 文件无 tombstone 消失
- **WHEN** 已发布来源不见且没有原因和可选 replacement
- **THEN** 系统 SHALL 拒绝候选并保留旧 active，而不得把缺失静默解释为删除

#### Scenario: 修订无法唯一映射旧 block/span
- **WHEN** 新 source version 中不存在原 span hash 或存在多个同样候选
- **THEN** anchor projection SHALL 标记 unresolved/ambiguous 并保留 origin version/locator，不得产生 fuzzy 自动映射；页面可继续从外置 comment authority 显示该项

### Requirement: 最小确定性 Document IR
系统 SHALL 在不修改来源 bytes 的条件下投影 metadata、blocks/source spans、heading、raw TeX、raw table、code、figure reference/caption、citation 和 link；方法、条件、限制与失败经验 SHALL 由独立 knowledge compiler 形成。

#### Scenario: 新文档包含公式表格代码和图片
- **WHEN** publishable Markdown 通过候选验证
- **THEN** generic renderer SHALL 在现有风格内安全展示这些确定性元素并提供 source locator，且不得声称自动理解了图表或表格语义

### Requirement: Legacy 与 generic 展示隔离
系统 SHALL 让现有 V39 页面继续使用 legacy compatibility renderer，只让没有既有页面合同的新研究使用命名空间隔离的 generic renderer。

#### Scenario: Generic renderer 增加新交互
- **WHEN** 新研究展示加入折叠、版本或引用增强
- **THEN** 该变化 SHALL 不改变 legacy 页面模板、DOM、CSS 命名空间或默认交互回归结果

### Requirement: Generic renderer 必须用真实复杂文档证明自动展示增益
实现验收 SHALL 使用 `reference/archive/Q5/低SNR横截面选股_因子历史表示与压缩研究_结构重构扩展版.md`、SHA-256 `4994d1df74414fdadfefb7ba812c3851ef26fd82c36bc7f174c7db577e756679` 的 byte-exact copy，在 reference 外隔离 acceptance source root 赋予新的 test-only logical path/document ID。它 SHALL 通过与生产相同的 discover/freeze/version/IR/chunk/index/generic route 流程，不得修改原 source、现有 Q5 legacy 页面合同或生产 catalog。

#### Scenario: 隔离新身份首次进入 intake
- **WHEN** 固定 SHA fixture 在无文档专用 route、template、slug 分支或 per-file policy 的条件下构建
- **THEN** 系统 SHALL 自动生成版本化页面、TOC/深链、公式、局部滚动宽表、代码、正式引用/source locator、版本/知识状态和 search artifact；已接受知识以带 locator 卡片展示，pending 状态不得伪造字段

#### Scenario: 与 raw Markdown 和 legacy V39 对照
- **WHEN** 浏览器在桌面/窄屏执行预注册任务“定位公式、比较表项、打开代码、追到参考来源、识别当前/历史版本”
- **THEN** generic 页面 SHALL 相对 raw Markdown 减少导航步骤或消除不可完成项，无页面级横向溢出/坏锚点/原始 TeX 泄漏；V39 legacy screenshot、关键 DOM、CSS 和默认交互 SHALL 无未授权差异

### Requirement: 发布资格与外部 AI 资格必须独立判定
来源策略 SHALL 分别给出 `publishable` 与 `external_ai_allowed`；正常研究可以进入确定性页面和 lexical 索引，但命中 `private`、`no_external_ai`、敏感信息或外部发送资格不确定的内容 SHALL NOT 被发送给任何外部模型。

#### Scenario: 文档可发布但禁止外部 AI
- **WHEN** 新增或修订研究通过确定性解析且标记为 `no_external_ai`
- **THEN** 系统 SHALL 允许其生成基础 snapshot，将知识增强标记为 `blocked_policy`，且不得创建包含正文、片段或摘要的 DeepSeek 请求

#### Scenario: 外部 AI 资格无法判定
- **WHEN** policy evaluator 无法证明文档允许发送给外部模型
- **THEN** 系统 SHALL fail closed 为 `blocked_policy`，继续确定性入库，并把原因送入隔离报告而不是阻塞无关文档

### Requirement: DeepSeek V4 Pro 只编译变化且合规的来源版本
确定性 IR 完成后，系统 SHALL 仅为 source/IR hash 发生变化且 `external_ai_allowed=true` 的版本创建 `deepseek-v4-pro` 语义编译 job；job identity SHALL 绑定 source version、IR hash、external-AI policy version、请求 alias、官方确认的 provider revision、model-identity contract、prompt version 与 output schema version，普通发布 SHALL NOT 全量重跑未变化内容。

#### Scenario: 发布中只有一篇研究发生修订
- **WHEN** 其余研究的 source/IR hash 与有效 generation 均未变化
- **THEN** 系统 SHALL 只为该修订版本排队 DeepSeek job，并复用其余版本已验证的知识 generation

#### Scenario: 模型或 prompt/schema 升级
- **WHEN** 维护者决定使用新的模型、prompt 或输出 schema
- **THEN** 系统 SHALL 通过显式、可审计的定向 recompile campaign 生成新 generation，保留旧 generation，且不得在普通发布中静默重写历史结果

#### Scenario: Rolling alias 的实际 revision 漂移
- **WHEN** 官方 alias→revision 证据变化，或 API 返回 model/system_fingerprint 与 generation 的 identity contract 不一致且无法证明仍为同一 revision
- **THEN** 新输出 SHALL 进入 `provider_identity_drift` 隔离状态，系统 SHALL 建立新 generation 并要求显式 targeted recompile 选择受影响 source versions，且不得与旧语义知识混用

#### Scenario: 无法确认 alias 的实际 dated revision
- **WHEN** `/models` 或响应只返回 `deepseek-v4-pro` alias，且没有当前官方 revision evidence
- **THEN** 系统 SHALL 保留 deterministic base snapshot 并停止正式语义接受，不得自行把 alias 标记为某个 dated revision

### Requirement: 语义编译失败不得污染 active 或长期阻塞文档
DeepSeek 超时、API 失败、非法结构、证据 span 无法定位或机械验证失败 SHALL 产生可重试或待审核状态，不得写入正式知识；通过确定性门禁的页面和 lexical 搜索 MAY 先以 `pending`、`failed_retryable` 或 `blocked_policy` 状态发布，并在知识验证完成后生成新的 enriched snapshot。

#### Scenario: DeepSeek API 在候选构建时超时
- **WHEN** 文档的确定性 IR、页面和 lexical index 均已通过而语义 job 超时
- **THEN** candidate MAY 作为明确标记 `pending` 或 `failed_retryable` 的基础 snapshot 激活，当前版本不得继承上一 source version 的语义知识冒充最新结果

#### Scenario: 后续语义候选通过验证
- **WHEN** 同一 source version 的语义 generation 完成机械验证或人工接受
- **THEN** 系统 SHALL 生成并验证新的 enriched snapshot，再通过正常 release 激活流程统一更新页面、搜索与 MCP

### Requirement: 来源文本在模型边界内始终是不可信数据
DeepSeek 编译器 SHALL 将研究正文放入结构化 data envelope，固定 system/developer 指令与严格 JSON schema；模型调用 SHALL 无工具、文件系统、网络、部署或凭据访问权限，且正文中的“忽略指令”、工具调用、secret 请求或输出协议修改 SHALL 仅作为待分析文本处理。

#### Scenario: 研究正文包含 prompt injection
- **WHEN** source span 声称要求模型泄露密钥、执行命令、访问网络或绕过 schema
- **THEN** 编译器 SHALL 忽略这些指令、只返回允许 schema 内的候选；任何越界结构 SHALL 使 generation 验证失败且不得进入 active

### Requirement: Chunk 与索引增量必须绑定 source version
系统 SHALL 从确定性 IR 生成 heading-aware、source-span-bound chunks；公式、表格、代码块和引用 occurrence 不得跨界切断。chunk ID SHALL 绑定 document version、ordered spans 与 chunker version；source revision、tombstone、deprecated 或关系目标变化 SHALL 只重建受影响 chunk/index/backref，并通过同一 candidate snapshot 原子生效。

#### Scenario: 文档只修订一个章节
- **WHEN** 新 source version 仅改变一个 heading subtree
- **THEN** 系统 SHALL 复用未变化内容对象，重建受影响 chunks、关系 backrefs 和索引 membership，并确保 Web/Search/MCP 不出现新页面配旧索引

#### Scenario: 超长公式或表格超过检索预算
- **WHEN** 单个 block 必须拆分才能进入检索 artifact
- **THEN** 系统 SHALL 产生带 parent/child 与邻接 metadata 的确定性 child chunks，保留完整 block locator，且不得用任意 overlap 重复提高该证据权重
