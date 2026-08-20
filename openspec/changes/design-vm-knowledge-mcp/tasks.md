## 1. Stage 0：权威基线与发布核心

- [ ] 1.1 冻结现网 V39 的代码、模板、CSS/JS、四个只读库、PDF、图片、对象、Paper Lab、研究工作区种子和代表性页面/API/浏览器基线。
- [ ] 1.2 GitHub 在 Stage 0–5 保持 Public；建立根 `.gitignore`、`.gitattributes`、allowlist 与 reference/internal-research/secret/SQLite/PDF/object/generated-state/release 禁入门禁。
- [ ] 1.3 定义并实现无环 identity：immutable `R=release_manifest` 只含代码/内容/资源/索引/知识和 state/recovery compatibility，`active_release→R`；immutable `C=checkpoint` 记录 captured-under active release，`RM=recovery_manifest→R/C`，activation/recovery receipt→已验证 `R/RM/C` 且不作 pointer。加入 schema/graph linter，拒绝 R 内出现具体 RM/C ID/hash/time。
- [ ] 1.4 实现不依赖 trigger 的 VM deploy CLI 核心：精确 release、`.partial`、hash、candidate 启动、切换、回退和显式 replay。
- [ ] 1.5 实测本地测试入口、VM 网络/权限/端口、状态副本协议和 `cutover_budget_ms`；只读发现 `RECOVERY_ROOT` 候选，不以不同盘符预判独立故障域。

## 2. Stage 1：V39 D 盘兼容 bootstrap

- [ ] 2.1 按 V39 inventory 全量同步 Git 外 PDF/图片/对象/数据库/内容快照到 D `incoming`，验证 path/size/SHA 和链接可达。
- [ ] 2.2 用 SQLite online backup 生成隔离 candidate state，完成 integrity/foreign-key/schema/count/hash 与空/非空 comment fixture。
- [ ] 2.3 完成 legacy renderer 的桌面/窄屏截图、关键 DOM、公式、表格、引用、搜索、评论、Dashboard、Paper Lab 和门禁回归。
- [ ] 2.4 对最终 `RECOVERY_ROOT` 实测 production/recovery host identity、storage authority、volume/backend、UNC/reparse 解析和生产 VM/D 不可用时独立读取；同一 VM 的其他盘符、挂载或回指共享必须拒绝，并生成 failure-domain attestation。
- [ ] 2.5 先冻结 V39 `R`，再生成 immutable SQLite `C` 和单向绑定 `R/C` 的 `RM`，完成 closure/no-secret 验证；在 host identity 与生产 VM 不同的独立非生产恢复主机/隔离 VM 的真实空 `D:\quant\quant_platform` 仅凭 bundle 完成恢复与浏览器/API/hash/schema 验收。
- [ ] 2.6 将 2.4/2.5 设为首次生产 handoff 的硬门禁；未通过时只允许副本候选验证，不得开放 D 生产流量、转移 writer authority或清理 V39 ZIP/C 状态备份/旧服务材料。
- [ ] 2.7 获批 apply 后才演练外部流量/写入 fence、最终复制、D exact-V39 baseline handoff；证明 D 未接收外部写入时失败可安全退 C，通过并开放流量后 C 永久退役。
- [ ] 2.8 在 D baseline 之上另建后续 candidate，演练只使用同一 D state 的 D prior rollback；四项恢复门禁全部通过前继续保留旧 V39/C 材料。

## 3. Stage 2：一次 publish 自动发布

- [ ] 3.1 实现受控本地 publish CLI：冻结 Git 外来源、运行本地 gate、执行一次 push、等待 exact-SHA GitHub-hosted CI。
- [ ] 3.2 实现 candidate 的增量 hash 传输与 VM deploy CLI 调用，取消人工制作/传输广播包。
- [ ] 3.3 实现 latest-only coalescing、VM 串行 lock、运行中部署不取消、旧 pending 被最新 main 替换的明确状态与审计。
- [ ] 3.4 将 `publish` 固定为本版唯一生产入口，删除 watcher/pre-push deployment hook/self-hosted runner/bare receive 的实现任务和开放选择。
- [ ] 3.5 在 candidate 激活前生成并验证单向 `RM→candidate R/compatible C`，把完整 closure 写入已通过 failure-domain attestation 的 `RECOVERY_ROOT`，并生成只证明候选恢复保护的 `recovery_protection_receipt`；此时不得生成 `activation_receipt`，release manifest 与 active pointer 也不得含 RM/C。attestation 过期或 identity 漂移时 fail closed。
- [ ] 3.6 只有 active pointer 切换、candidate 启动及 post-activation health/关键功能/writer fence 全部成功后才生成成功 `activation_receipt`；任一阶段失败只生成绑定 candidate/prior、失败阶段、错误和回退结果的 `failure_receipt`，并验证不会产生成功 activation receipt。

## 4. Stage 3：Reference 版本化编译与展示

- [ ] 4.1 在现有 intake 上实现模式默认 publishable、supporting 分类和 reserved/draft/private/reparse/secret/结构/身份歧义 quarantine；将发布许可与 `external_ai_allowed/no_external_ai` 独立建模。
- [ ] 4.2 实现 stable research/document identity、同路径 revision、纯移动 alias、歧义映射、显式 tombstone/replacement、历史访问和 per-snapshot `comment_anchor_projection`；只允许 exact unique span/hash+结构上下文或已验证 unchanged-block mapping 自动重定位。
- [ ] 4.3 扩展确定性 IR：blocks/spans/heading/math/raw table/code/figure ref/citation/link；原 Markdown byte hash 保持不变。
- [ ] 4.4 从 IR 生成稳定 heading-aware chunks：公式/表格/代码/引用不跨界切分，超长 block 使用 parent/child 与邻接关系；记录 chunk/source/span/version/chunker metadata。
- [ ] 4.5 将 parse/render/link/chunk/lexical search/active membership 合并为 deterministic base snapshot；语义增强使用 `pending/ready/failed_retryable/blocked_policy`，DeepSeek 故障不得阻塞 base 激活。
- [ ] 4.6 实现 changed-document-only 的 chunk/index/关系 backref 重建，以及 tombstone/deprecated 的默认召回失效；任一步失败不得激活页面/索引混合版本。
- [ ] 4.7 在命名空间隔离的 generic renderer 展示新研究；以 `reference/archive/Q5/低SNR横截面选股_因子历史表示与压缩研究_结构重构扩展版.md`（SHA-256 `4994d1df74414fdadfefb7ba812c3851ef26fd82c36bc7f174c7db577e756679`）的 byte-exact、reference 外隔离 test-only 新身份，证明无需专用 route/template 自动展示 TOC、公式、宽表、代码、引用/locator、版本和已验证知识/pending，并完成 raw Markdown 任务对照；现有页面继续走 legacy renderer 并通过视觉/交互回归。

## 5. Stage 4：知识形成、检索与 MCP

- [ ] 5.1 实现 `deepseek-v4-pro` changed-source-only job key、持久 job 状态和 targeted recompile campaign；job 绑定 requested alias、expected official provider revision 与 model-identity contract，普通发布不得全量重跑未变化 source versions。
- [ ] 5.2 从现有受保护凭据注入 API key，证明 key/header 不进入 Git、日志、manifest、candidate、cold bundle 或回退材料；`private/no_external_ai` 不得构造 API 请求。
- [ ] 5.3 实现 system/source-data 隔离、无工具/网络/secret、严格 JSON schema、允许 span 闭集和 prompt-injection adversarial fixtures。
- [ ] 5.4 建立 source_explicit/model_candidate/machine_verified/human_reviewed/rejected/deprecated、knowledge generation 和字段级 source locator；记录官方 revision evidence URL/hash/observed-at、API 返回 model/system_fingerprint/response identity 及 prompt/schema/source/IR/output hashes。
- [ ] 5.5 实现 provider identity drift 门禁：官方 alias 映射或 API model/fingerprint 变化且未能证明同 revision 时隔离输出，创建新 generation，并只通过显式 targeted recompile 选择受影响 source versions；禁止与旧 generation 混用。
- [ ] 5.6 实现机械接受的 extractive/controlled-normalization 规则、人工接受入口、coverage report 与缺失/冲突处理；抽象摘要或推断关系不得仅凭 confidence 自动转正。
- [ ] 5.7 实现 API 超时/失败/非法结构/越界 span/证据失配的无污染失败语义；base snapshot 可先发布，验证完成后生成新的 enriched snapshot。
- [ ] 5.8 实现 exact/alias/FTS5/CJK/short fallback、applicability、有效 relation 扩展、版本/状态惩罚、重排与 canonical source-span/knowledge-cluster 去重。
- [ ] 5.9 建立 source-span/version-grounded qrels、覆盖矩阵、development set 与至少三分之一 sealed holdout；包含因子/模型/数据/回测、hard negative、无答案、条件冲突、历史/废弃和错引，来源修订后 qrel 自动 stale。
- [ ] 5.10 与当前 LIKE search 比较总体和分 slice 质量；预注册门禁，证明至少两个声明的 lexical/structured 困难 slice 稳定改善且引用/废弃/冲突硬错误为 0。
- [ ] 5.11 依据召回/排序、no-answer、条件、版本、引用、P95、体积和重建成本联合决定 vector；本版不得依赖 vector 才可用。
- [ ] 5.12 实现经 tool-choice eval 验证的最小只读 MCP 工具面，以及客户端本地 `serve-stdio`、用户级 immutable mirror 与只读 VM authority resolver；current-sensitive 请求只有 mirror/VM `release_id/manifest_sha256/snapshot_id` 一致才返回 fresh，断网、落后、伪造或不可验证时返回结构化 stale/unavailable 并使 continuation 失效。
- [ ] 5.13 交付 cwd 无关、可幂等 install/doctor/uninstall 的 CLI/package、user/project Codex profile、`AGENTS.md`/server instructions 应调用与不应调用规则；在 `quant_platform` 和独立 `D:\quant\backtest_demo` 从无显式 MCP 字样的 prompt 验证 search→get、不应调用、snapshot activation/rollback 后 list-updates→重查与返回身份。本版不实现 HTTP。
- [ ] 5.14 用相同任务做 MCP-assisted 与 no-MCP 对照；只有 grounded decision、条件/限制识别和引用正确性出现可复现净增益且无意义调用受控时才通过。

## 6. Stage 5：全局验证与放行

- [ ] 6.1 回放全部现有 Archive、Evidence、Paper Lab、两族 comment、Dashboard/workspace 与完整 resource inventory；增加真实非空 comment 序列“v1 写入 document/exact-block/edited-span comment→新代码→source 修订与移动→renderer→D prior 回退→再读取”，用浏览器和 SQLite 同时验证正确重定位、history/unresolved 可见、无错挂及 current/event/revision/actor/time 不变。
- [ ] 6.2 验证新增、修订、移动、删除、DeepSeek 失败/超时/非法输出/官方 revision 或 fingerprint 漂移/模型升级、重复执行、并发 publish、网络中断、active 损坏、恢复和回退异常路径。
- [ ] 6.3 验证 Web/Search/MCP 同一 snapshot、默认当前版本、历史/废弃语义、引用 locator 和 source bytes 零改动；从独立项目模拟 VM activation/rollback，证明本地 mirror 识别三元组变化、旧 continuation 失效并重新 search→get，网络不可达/过期/identity mismatch 不静默返回旧知识。
- [ ] 6.4 由独立 verifier 检查真实代码、机器结果、浏览器、状态和回退，不以执行者总结或旧 PASS 代替证据。
- [ ] 6.5 对 SQLite schema 升级后的 candidate/prior 做读写/CAS/event 兼容实测；普通回退沿用当前 D state，不执行 down-migration。
- [ ] 6.6 对功能完整最终 release，在 host identity 与生产 VM 不同的独立非生产恢复主机/隔离 VM 的真实空 `D:\quant\quant_platform` 仅凭 attested cold bundle 恢复代码、前端、内容、PDF/图片/对象、索引和明确 SQLite checkpoint；不得用 Stage 1 的 V39 演练替代。
- [ ] 6.7 验证 GC roots 持续包含 active R、prior R、全部 retained RM 与 retained C，并沿 `RM→R/C→closure` 保留对象；每日新 checkpoint 不得通过 latest replacement 解除旧 retained root。四项恢复门禁通过前不得清理 V39 ZIP/C 备份/旧服务材料。
- [ ] 6.8 形成中文 runbook、bootstrap/cutover/D-prior/cold-recovery 演练、质量报告和 Stage 5 release certificate。
- [ ] 6.9 配置并验证唯一 state-only backup job：至少每 24 小时新建 immutable `C/RM/receipt` 并引用当时 current R，复用静态 closure但不修改 R/active/代码发布；以 `now-checkpoint.captured_at` 计算 RPO，任务失败或超龄进入 degraded，缺少可验证 checkpoint/closure 进入 failed，均告警/重试且不阻塞在线写入。
- [ ] 6.10 用 schema/graph/hash fixture 证明唯一依赖方向 `active→R`、`C→captured R`、`RM→R/C`、`receipt→R/RM/C`，构造 R→RM、R→C、receipt-as-active 和 state-only 修改 R/active 的反例均 fail closed。

## 7. Stage 6：Public→Private 最终关闭

- [ ] 7.1 仅在 Stage 5 release certificate 后将 GitHub repository 从 Public 转为 Private。
- [ ] 7.2 重新核验实际 plan、Actions、branch/environment protection、CI、publish CLI 最小权限和 exact-SHA candidate 能力。
- [ ] 7.3 在 Private 状态运行一次 CI 与一次无生产切换 candidate 演练，确认冻结、传输、校验和权限链未破坏。
- [ ] 7.4 形成 visibility-closure receipt；Private 复验通过前不得标记项目最终完成。
