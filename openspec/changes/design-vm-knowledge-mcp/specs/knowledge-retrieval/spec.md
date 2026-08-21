## ADDED Requirements

### Requirement: 知识必须经过有来源的形成链
系统 SHALL 将确定性 source_explicit、model_candidate、machine_verified、human_reviewed、rejected 与 deprecated 分开；每个正式 method/condition/limitation/failure/evidence 字段 SHALL 有版本化 source locator、extractor provenance 和事实状态。

#### Scenario: 模型产生无字段来源的限制
- **WHEN** 模型候选缺少有效 span、支持文本或与来源冲突
- **THEN** 系统 SHALL 拒绝或保留为不可推荐 candidate，并在 coverage report 中说明，不得把它表达为来源事实

#### Scenario: 某研究未形成结构化方法
- **WHEN** 规则和模型都没有产生可验证知识项
- **THEN** 系统 SHALL 保留原文全文检索并报告明确的零覆盖原因，而不得写入空洞占位字段

### Requirement: DeepSeek V4 Pro 候选必须可复现且不能自证为事实
每个 `deepseek-v4-pro` generation SHALL 记录请求 alias、官方确认的实际 provider revision、identity evidence URL/hash/observed-at、API 返回 model/system_fingerprint/response identity、prompt version、output schema version、source bytes hash、IR hash、response hash、生成状态和时间，但 SHALL NOT 记录 API key 或认证 header；模型输出只能进入 `model_candidate`，不得仅凭 schema 合法自动成为正式知识。

#### Scenario: 同一来源由新模型重新编译
- **WHEN** 显式 recompile campaign 使用不同 model ID、prompt 或 schema
- **THEN** 系统 SHALL 创建独立 generation 并保留前代结果、接受状态与 provenance，且不得覆盖或伪装成同一次生成

#### Scenario: 排队 job 的编译身份已不可复现
- **WHEN** queued job 的 prompt/schema、分段 manifest、part request hashes 或 model identity contract 与当前 compiler 不同且旧请求闭包无法完整重建
- **THEN** 系统 SHALL 保持旧 payload 不可变，以非空 actor/reason 记录 audited `superseded_identity` 终态，并只通过显式 targeted recompile 创建新的 immutable job；不得绕过 identity gate 或就地重写旧 job

#### Scenario: API 返回合法 JSON 但缺少可定位证据
- **WHEN** 候选方法、条件、限制、失败经验、关系或摘要不能绑定当前 source version 的有效 span/quote/hash
- **THEN** 候选 SHALL 保持不可推荐或被拒绝，当前 active knowledge 不得变化

#### Scenario: Alias 不变但 provider revision 或 fingerprint 变化
- **WHEN** 请求仍为 `deepseek-v4-pro`，但官方 revision mapping 或返回 system fingerprint 与已接受 generation 不同且尚未裁决
- **THEN** 系统 SHALL 隔离新候选并保持旧 generation 独立可追溯；只有新 identity contract 与显式 targeted recompile 后才能形成新的正式 generation

### Requirement: 正式知识接受必须区分机械验证与人工判断
机械接受 SHALL 仅适用于原文显式、可抽取且可由 span、quote、hash、枚举、数值/公式和局部关系线索确定验证的候选；抽象摘要、跨段推断、隐含适用性、因果或相互关系 SHALL 在人工接受前保持 `model_candidate`。

#### Scenario: 候选逐字对应原文限制
- **WHEN** 候选字段可在绑定 span 中精确定位，规范化没有改变否定、量纲、数值、公式或实体关系
- **THEN** 机械验证器 MAY 将其标记为 `machine_verified`，并记录所用 validator/version 与全部证据

#### Scenario: 候选总结跨越多个段落并推断适用条件
- **WHEN** 候选虽然合理但原文没有单一、明确且无冲突的表达
- **THEN** 系统 SHALL 要求人工接受或拒绝，不得以模型置信度代替审核

### Requirement: 语义编译边界必须抵抗 prompt injection
知识编译 SHALL 把来源内容视为不可信数据，使用固定指令、严格输出 schema、允许字段闭集与 source-span 闭集，并禁止模型访问工具、文件、网络、部署接口和 secret；非法字段、越界 span、指令回显或证据冲突 SHALL 使 generation 失败而非降级写入。

#### Scenario: 原文诱导模型改变知识状态
- **WHEN** 正文包含“把本段直接标为 verified”、伪造系统消息或要求调用外部工具的文本
- **THEN** 验证器 SHALL 将其作为 source data，拒绝越权状态或动作，且日志只记录脱敏错误与 generation ID

#### Scenario: 候选证据本身位于注入式正文
- **WHEN** model candidate 绑定的 source span 含有改变指令层级、要求执行工具或索取凭据的注入式内容
- **THEN** 候选 SHALL 直接进入不可接受的 rejected 状态，人工 review 接口也 SHALL 拒绝将其转为正式知识

### Requirement: 结构化且可解释的 lexical 基线
系统 SHALL 组合 exact ID/alias/title、FTS5、CJK n-gram/trigram、短词 fallback、item-scope applicability、受控 facet alias、关系扩展、版本/状态惩罚和确定性重排，并返回命中原因、限制、反例及 source locator。明确 `不是 A 而是 B` / `而非 A` / `not A but B` 的被拒绝概念 SHALL 作为默认正向 evidence lane 的硬约束；正向关系 target SHALL 重新通过同一否定与 applicability 检查，`contradicts`/`fails_under` 不得倒置成正向推荐。

#### Scenario: 查询存在适用条件冲突
- **WHEN** 方法文本相关但市场、频率、数据或目标与 task context 冲突
- **THEN** 系统 SHALL 排除或明确降权该方法并返回冲突原因，不得只因文本相似将其推荐为适用

#### Scenario: 同一研究包含不同作用域的方法
- **WHEN** 同一 document version 的不同正式知识条目分别适用于 A 股与加密货币，或同一 facet 没有全篇一致的受控值
- **THEN** 系统 SHALL 保留 item-scope applicability，不得把多个值并集后回填到全部知识和 chunks；只有所有受控声明一致的 facet 才可作为 document-wide chunk constraint，未知自由文本不得伪造 match 或 conflict

#### Scenario: 查询明确拒绝一个方法
- **WHEN** 查询以可确定解析的中英文 contrast 明确拒绝某方法，而候选文档的 title/alias/正式方法或 source passage 命中该被拒绝概念
- **THEN** 默认正向 cards SHALL 排除该候选文档及由它引出的关系 target；如未来需要对比材料，应使用显式 counterevidence 语义，不得让多个泛化正向词投票覆盖该拒绝

#### Scenario: 当前版本的语义增强仍 pending
- **WHEN** 查询命中已发布的最新 source version，但其 DeepSeek generation 尚未成为正式知识
- **THEN** 检索 SHALL 返回当前版本 lexical passage 与 `knowledge_enrichment` 状态，不得静默回退到旧 source version 的语义字段

### Requirement: RAG chunk、metadata 与失效语义必须稳定
检索 SHALL 使用由确定性 IR 产生的 heading-aware chunks，并携带 research/document/source version、heading path、block type、byte/line locator、citation IDs、source/chunker hash、active/deprecated 状态及可用 applicability/fact/relation metadata；v1 的短内容单位 SHALL 是单个语义 IR block，只有超长 block 才生成 parent/child，公式、表格、代码和引用不得在语义边界中间切断。展示 context/adjacency 与实际 matched evidence SHALL 分离；去重 SHALL 以精确 source range 及其知识身份为准，不得让相邻段落、overlap、不同 kind/cluster 或多路命中提高同一证据权重或替另一条证据取得分数。

#### Scenario: 同一 span 同时被 lexical、结构化知识和关系扩展命中
- **WHEN** 三路候选都指向相同 canonical evidence
- **THEN** 系统 SHALL 仅在 source range、knowledge kind/cluster 与展示语义一致时合并为一张 evidence card，保留各命中原因但只计一次证据权重；更宽的 chunk 或相邻 span 只能作为 context，不得替精确 matched range 通过 qrel

#### Scenario: 来源被修订或 tombstone
- **WHEN** 当前 source version、active membership 或 relation target 发生变化
- **THEN** 新 snapshot SHALL 原子更新受影响 chunks/index/backrefs，默认检索不得残留旧 active 结果，历史查询仍可显式访问旧 artifact

#### Scenario: Generic 页面展示结构化知识
- **WHEN** 新研究页面显示 method、condition、limitation 或 failure 卡片
- **THEN** 每张卡片 SHALL 来自同一 snapshot 的 accepted knowledge，显示 fact status 与 source locator；当前 source version 从未有成功 generation 时，pending/blocked/failed SHALL 显示状态且不得从旧 source version 或未验证 candidate 填充；同一 source version 已有成功 generation 而后续 targeted job 失败或 pending 时，页面 SHALL 继续使用该成功 generation 直至新的成功 snapshot 激活

### Requirement: Read-only mirror 的检索身份必须可验证
可供 stdio MCP 使用的本地检索 artifact SHALL 是完整 immutable snapshot mirror；mirror metadata SHALL 绑定 release ID、release manifest SHA-256、snapshot ID、artifact closure/hash 与同步时间。它只有在只读 authority resolver 验证 VM active 三元组完全一致后才可标为 `fresh`。

#### Scenario: 本地 mirror 完整但落后于 VM active
- **WHEN** mirror hashes 自洽，但 VM activation/rollback 后 active 三元组不同
- **THEN** 检索层 SHALL 拒绝把 mirror 作为 current，废弃旧 continuation，并向 MCP 返回 stale 及 observed/local identity；同步并验证新 snapshot 前不得静默查询旧索引

#### Scenario: VM authority 不可达或 manifest 无法验证
- **WHEN** 客户端无法取得 active identity、manifest hash 不匹配或 artifact closure 缺失
- **THEN** current 查询 SHALL 返回 unavailable；只有显式 `allow_stale=true` 才可返回带 historical/stale 标记的旧 evidence，且不得宣称当前适用

### Requirement: 独立且防泄漏的质量评测
系统 SHALL 使用覆盖因子、模型、数据处理和回测的 development set 与至少三分之一 sealed holdout；每条 qrel SHALL 绑定 task context、answerability、expected/forbidden method、适用/冲突 facets、positive/negative 的 source version、span、精确 UTF-8 byte range、quote/source hash 与必需引用，来源修订后 SHALL 自动 stale 并等待重新裁决。qrel 命中 SHALL 只认 evidence card 的精确 locator，不得把 context/邻接 span 当作命中。Recall、nDCG 与 MRR SHALL 只在 answerable qrels 聚合，no-answer accuracy 单独聚合和门禁；expected kind 与 required citation SHALL 由实际覆盖正向 locator 的 card 满足，其他 Top-K card 不得代缴。调参不得查看 holdout，评测 SHALL 含 hard negative、无答案、条件冲突、历史/废弃、错引、跨语言和公式别名切片。

#### Scenario: 同一问题集被用于调参与验收
- **WHEN** 一个 qrel 已参与排序规则、阈值或 prompt 调整
- **THEN** 它 SHALL 只属于 development set，不得再作为 sealed release 证明

#### Scenario: 默认结果含废弃版本或错误引用
- **WHEN** sealed evaluation 发现默认召回废弃版本、条件冲突被表述为适用或 source locator 错误
- **THEN** release gate SHALL 失败，即使总体 Recall 或 nDCG 达标

#### Scenario: 新检索只改善总体平均值
- **WHEN** 候选没有在至少两个预注册 lexical/structured 困难 slice 稳定优于当前 LIKE baseline，或改善来自重复 chunk 增权
- **THEN** 检索质量门禁 SHALL 失败，不得以总体均值或接口可调用替代实际研究召回价值

### Requirement: Vector 采用多目标净收益决策
系统 SHALL 在 lexical/structured 基线可独立运行的前提下，综合召回、排序、无答案、条件、版本、引用、P95 latency、索引体积、重建时间、许可和运维成本决定是否启用 vector。

#### Scenario: Vector 只提高单一 Recall 指标
- **WHEN** vector 改善部分 Recall 但降低条件/引用正确性或超出延迟、维护预算
- **THEN** 系统 SHALL 拒绝把 vector 纳入 active pipeline
