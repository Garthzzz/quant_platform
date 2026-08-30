# Quant Research Hub：VM 安全部署、版本化知识编译与 MCP 总体设计

<!-- authoritative_revision: implementation-local-prior-r6 -->
<!-- as_of: 2026-08-26T00:00:00+08:00 -->

## 1. 决策摘要

本设计在不改造现有前端视觉和交互的前提下，先完成一个可运行、可回退的 V39→VM D 盘兼容发布纵切，再在同一版本计划内完成 reference 增量解析、知识形成、检索和 MCP。它不要求先迁 PostgreSQL，也不把高级 Document IR 展示、向量检索、HTTP MCP 或复杂发布治理放到关键路径。

本版固定结论如下：

1. 现有 V39 页面、数据、静态资源和交互采用 **legacy compatibility release** 原样迁移；任何新展示能力不能改变这些页面的默认渲染。
2. 发布使用精确 commit、不可变 candidate、隔离验证、短停切换和自动回退；active 目录绝不 `git pull`。
3. 首次 bootstrap 显式搬运 Git 外的 PDF、图片、对象、数据库和内容快照；以后按 hash 做增量传输。
4. 两族 comment 本版继续以 release 外 SQLite 为权威。PostgreSQL 只在真实并发、HA 或多 writer 触发条件成立后另立 change。
5. 正常放入 `reference/archive` 的研究 Markdown 默认自动成为 publishable candidate；只隔离保留目录、草稿/备份、敏感命中、结构错误和身份歧义。
6. 确定性 Document IR 与带判断的知识编译分层；方法、条件、限制和失败经验必须带原文 span 与事实状态。
7. 检索先使用结构化过滤 + lexical/CJK/短词 fallback + 确定性重排；向量不是本版前置依赖。
8. MCP 以客户端机器上由 Codex 拉起的 stdio 进程运行；它只读经 VM active identity 校验的本地 immutable mirror，并提供可安装到其他量化研究项目的客户端 profile。Streamable HTTP 等到有命名消费者和认证 owner 再实现。
9. 推荐发布触发方式为受控本地 `publish` CLI：内部执行一次 Git push、等待精确 SHA 的 GitHub CI，再调用 VM 固定 deploy CLI。它比常驻 self-hosted runner 更适合冻结不进入 Git 的 reference 和大对象。
10. 版本身份收敛为一个 immutable `release_manifest.json` 和一个 `active_release.json`；release 只声明 state compatibility。`local_prior_binding.json` 只绑定当前 active 与恰一 prior；activation/rollback receipt 绑定结果 pair，failure receipt 绑定原 pair 与 candidate，cleanup receipt 绑定保留 pair 与精确移除目标。它们只是审计证据，不是另一套 current/version authority。
11. `deepseek-v4-pro` 是本版正式的增量知识编译器，只消费发生变化且允许外部 AI 的确定性 IR；每个 generation 同时绑定请求 alias、官方确认的实际模型修订和 API 返回身份，alias 漂移不得混入旧 generation。失败不阻塞确定性页面和 lexical search 发布，也不能污染 active knowledge。
12. 发布系统只维护生产 VM 精确 `D:\quant\quant_platform` 内的 active 与恰一 prior；成功激活后原 active 成为 prior，更早 prior 与终态 candidate 经审计清理。普通回退交换两者角色并沿用当前 D state。本版不建设 D 根之外的项目恢复存储，不设置周期性状态副本任务，也不声明整机、D 根、对象库或 state 整体丢失后的重建能力。
13. GitHub 在开发、迁移和 Stage 5 验收期间固定保持 Public；Stage 5 release certificate 后才转 Private，并在 Private 状态完成 CI 与无生产切换候选演练后关闭项目。

## 2. 真实状态与证据边界

### 2.1 本地与 GitHub

- 项目根为 `D:\quant\quant_platform`；本地 Git 已初始化，当前公开主线为 `9bb2bce9a8bb227c073629803f89a99294a608fc`。
- GitHub `Garthzzz/quant_platform` 于实施期继续保持 Public；首个公开安全基线 CI 已成功，当前主线 CI 失败必须由下一 exact-SHA 提交重新关闭，不能用旧 success 代替。
- 本机没有 `gh` CLI，无法借登录态核验账户套餐。由于仓库目前公开，GitHub Environments 在当前计划下可用；若转 private，执行前必须重新核验账户与 protection 能力。
- `reference/**` 是只读来源，不能被 parser、迁移或展示写回。

### 2.2 现有前后端与数据

- 现网权威部署是 `quant-hub-v39-company-broadcast-20260731-hotfix1`，不是历史 V34。
- V39 ZIP 约 742.6 MB；解压 runtime 约 824.6 MB，含 PDF、对象、SQLite、Paper Lab、研究工作区、模板和静态资源。
- 当前前端已有研究目录、长文阅读、公式、表格、引用、评论、Dashboard、Paper Lab、搜索和访问门禁；它们是迁移基线，不是待重做原型。
- `archive/markdown.py` 已能在不改来源 bytes 的条件下投影 heading/TOC/math/table/citation/link，并进行安全 HTML 清理。
- `archive/catalog.py` 已有 candidate、version、publish、active mapping、页面和基础 search。
- `incremental_intake.py` 已有文件枚举、步骤状态、幂等、失败、等待外部证据和发布事件，不应另建第二套 intake orchestrator。

### 2.3 可变状态与评论

- 运行器已经把发布内容库设为只读，把 `comments.sqlite3` 与 `research_workspace.sqlite3` 放在 release 外。
- Archive 评论库已有 actor、comment、event、receipt、outbox、revision CAS、软删除、完整性检查和 online backup。
- Workspace 数据库内有第二族 `research_workspace_comment`/event。
- 两族现有 comment 实测均为 0；Archive comment 库另有 5 个 progress topic，Workspace 还有大量非 comment 状态。
- 当前 C 盘线上状态权威根是 `C:\quant_platform_data`；新的 D 盘状态根尚未成为 writer。

### 2.4 当前能力缺口

- VM 唯一根 `D:\quant\quant_platform` 已有 bootstrap 上传暂存件，但没有 active/candidate/writer；首次 bootstrap、单一 writer fence 和完整资产迁移闭环仍未完成。旧暂存身份不构成新 active/prior 合同证据。
- GitHub 已有 Public 源码与 exact-SHA CI；单命令生产 publish、真实 D candidate/activation 与 Private closure 尚未完成。
- 现有搜索偏简单匹配；没有版本一致的结构化知识索引和 MCP server。
- 现有 parser 可复用，但尚未形成通用“新增研究无需手工页面”的稳定契约。
- 方法、适用条件、限制和失败经验尚无从来源到可检索事实状态的完整形成链。

## 3. 范围与边界

### 3.1 本版必须完成

- V39 等价迁入 D 盘并通过真实浏览器、API、数据、评论和回退验证。
- 一个受控 publish 入口完成精确 SHA CI、候选传输、验证、切换和失败回退。
- reference 新增/修订自动发现、版本化、解析、失败保旧、索引和通用展示。
- 结构化知识形成、混合检索、独立 qrels/holdout 和真实 agent 工作流评测。
- 可用的只读 MCP server、客户端本地 stdio、可跨项目安装的 Codex profile、调用规则和引用追踪。
- comment 与所有其他线上可变状态跨 release 生存，并完成候选隔离副本、schema compatibility 与本地 prior 回退演练。
- `deepseek-v4-pro` 对变更且获准外发的研究执行可追溯语义候选编译，确定性页面可在增强 pending 时独立发布。
- 在生产 VM 精确 D 根内维持 active + 恰一 prior 的严格保留集合，并证明普通回退继续使用同一当前 D state。
- Stage 5 后执行 Public→Private 可见性切换复验，作为项目最终关闭门禁。

### 3.2 本版不做

- 论文 crawler、自动下载、复杂定时任务。
- 账号/SSO、全库 PostgreSQL 化、集群或零停机蓝绿。
- 现有前端重做。
- 对图表进行模型视觉解读、对任意表格自动推断单位/统计语义等高风险增强。
- 没有真实消费者的 Streamable HTTP MCP。
- 为形式保留八个工具、四元版本号或多套 current pointer。
- 本版不实现裸 `git push` watcher；生产入口只有受控单命令 `publish`。

## 4. 目标分层

```text
reference/** (read-only)             GitHub (code/config/rebuildable)
          │                                      │
          └──── local publish/compiler ──────────┘
                           │
                  immutable release candidate
                           │
                 VM deploy CLI + candidate gate
                           │
        ┌──────────────────┴──────────────────┐
        │                                     │
one active release                       fixed state root
Web / Search / MCP                 comments / workspace / isolation
        │                                     │
release_manifest.json                 single fenced writer
```

边界原则：来源字节、派生内容、可变状态、release identity 和审计事件各自只有一种权威表达，不能相互替代。

## 5. 先行的 VM 兼容发布纵切

### 5.1 为什么先做

用户最基础的目标是把现有站点原样迁到 VM D 盘，并让以后一次 push 可安全更新。如果第一次真实 VM 验证排在 parser/MCP/PG 之后，最关键的网络、权限、路径、资产和切换风险会被推迟暴露。因此 Stage 1 必须先用 V39 建立端到端纵切；parser 和 MCP 仍是本版后续强制阶段，不因提前发布纵切而延期到未来版本。

### 5.2 D 盘目录合同

```text
D:\quant\quant_platform\
  checkout\                     # 可选、受控 Git/tooling checkout；不得放在上级目录
  releases\<release_id>\        # immutable
    release_manifest.json
    app\
    content\
    resources\
  incoming\<candidate_id>.partial\
  control\active_release.json    # 唯一 active authority
  state\                         # 固定、release 外
    comments.sqlite3
    research_workspace.sqlite3
    locks\
  isolation\                     # 仅候选验证的瞬态 SQLite 副本
  audit\                         # append-only receipt/event/write-set 证据，不是 pointer
  logs\
  tmp\                           # TEMP/TMP/上传/部署临时件
  tooling\                       # 固定、低变动部署工具
```

以上是生产 VM 的**闭合写入命名空间**，不是示意性建议。代码 checkout、Python
bytecode、`TEMP`/`TMP`、上传中间件、service 日志、锁、审计、隔离副本和部署工具均
只能写入这个根的已声明子目录；不得在 VM 的 `D:\`、`D:\quant`、任何 sibling/parent
或 C 盘产生项目文件。旧 `C:\quant_platform`、`C:\quant_platform_data` 只允许在 writer
handoff 前作为明确的只读来源。生产入口必须在执行前验证 Windows canonical path 与每个
既存组件不存在 reparse/junction 逃逸，执行后记录声明写入集合及实际 D-root delta；任一
路径无法证明时 fail closed。所有发布、回退、状态、审计和临时产物都受同一精确 D 根写入边界约束。

### 5.3 首次 bootstrap

首次迁移以现网 V39 为默认兼容基线，分四步完成：

1. **冻结清单**：对 V39 的 templates/CSS/JS/code、四个只读内容库、PDF、图片、对象库、Paper Lab、研究工作区种子和运行合同生成逐文件 path/size/SHA-256 inventory；同时记录代表性页面与 API 响应基线。
2. **全量搬运**：从本地已核验 V39 ZIP/解压树向 D 盘 `incoming` 复制完整 immutable payload。Git 只保存部署代码和 inventory schema，不承载 700+ MB 资产。冻结 inventory 只形成一棵 canonical immutable V39 baseline `R0`；不得为了填充 prior 槽复制内容等价 release 或伪造新的 manifest identity。
3. **隔离候选**：候选使用 C 状态库的 SQLite online backup 副本，在隔离端口、不可见 probe 对象和只读内容下验证；不得访问或写入线上 C 状态。
4. **首次 authority handoff**：预先在 D 建好并以状态副本验证 `R0`，同时准备一棵具有真实不同 manifest/release identity 的 successor candidate `R1`。正式 handoff 时先关闭外部流量和旧 C writer，取得最终一致副本并校验后落入 D `state`；在仍无外部写入的 fence 内先以最终 D state 建立尚未对外的 `R0` active，再按正常激活协议把 `R1` 切为 active、让 `R0` 成为 prior。若任一步失败，证明 D 未接受外部写入后丢弃 D 副本并恢复原 C writer；只有真实 `R1/R0` pair、binding 和 post-activation 验证通过后，才开放 D 流量、宣布 D state 成为 authority，并禁用旧 C 服务、写入 superseded 标记和收紧 ACL。

首次 handoff 的 prior 必须来自真实的前一版本 `R0`，successor `R1` 必须具有真实不同的 immutable manifest/release identity；不得用目录别名、同一路径、内容复制或空 prior 占位伪造。D pair 通过并开放流量后，旧 C 盘只保留为 C→D 过渡核验材料；此后每次发布都先锁定 **D 盘 prior release + 同一 D state**，不得重新启用 C 状态。

现有 V39 ZIP、C 盘最终状态迁移副本、旧服务启动/停止材料及校验记录必须继续保留到 C→D writer handoff、首个 D active、首个可启动 D prior 和同一 D state 回退全部通过。之后只能按精确清理清单移除 C→D 过渡材料；它们不得继续作为产品级回退权威。

### 5.4 后续增量

- 新 candidate 以 manifest 对比 active inventory，只传缺失或 hash 变化对象；已存在对象按 hash 复用。
- 任何 `.partial` 都不能成为 release；传输完成、hash 全通过后才原子重命名。
- 发布包不再由人手制作、复制或解压；构建与传输均由 publish/deploy CLI 完成。
- 终态生产 release 保留集合严格为 active 与恰一 prior；只有带合法 attempt journal 的运行中 candidate 可暂时额外存在。更早 prior、completed candidate、incoming/partial 与不再被两棵 manifest closure 引用的对象在终态审计后清理。

## 6. GitHub→VM 触发与安全比较

### 6.1 三种候选

| 方式 | 优点 | 主要问题 | 本版结论 |
|---|---|---|---|
| 本地 self-hosted runner | GitHub push 后自动、Actions 审计完整 | 常驻 daemon；可执行仓库 workflow；runner token/VM 凭据维护；冻结 Git 外 reference 容易发生时序竞态 | 本版不采用 |
| 受控本地 publish CLI | 单次交互；能在 push 前冻结 Git 外来源；最小命令面；凭据不进入 GitHub | 不是裸 `git push`；执行期间开发机必须在线 | **本版推荐** |
| VM bare Git receive | 简单、VM 不必访问 GitHub | 绕过 GitHub CI/Environment；仍不能自然搬运 Git 外大对象；扩大 VM Git 攻击面 | 不采用 |

### 6.2 推荐流程

`publish` 是唯一生产入口：

1. 验证 tracked worktree 干净，记录完整 `HEAD` SHA。
2. 冻结允许发布的 reference 与大对象为 content/resource inventory，阻止后续修改影响本次 candidate。
3. 本地运行迁移基线/单元/内容候选检查。
4. 执行一次 `git push origin <sha>:main`，等待 GitHub-hosted CI 对 **同一 SHA** 成功。
5. 组装 immutable release manifest，以 SMB/PowerShell Remoting 等已核验 transport 上传到 VM `incoming`。
6. 调用固定 VM deploy CLI 完成 hash、candidate、浏览器/API/数据检查、短停切换和回退保护。

本版本不实现裸 `git push` watcher、pre-push 部署 hook 或 self-hosted runner。开发者只使用受控单命令 `publish`；这不是待选项。未来若另立 watcher change，必须重新解决 pre-push 非 Git freeze 与凭据边界，不能复用本版结论作为已完成证明。

### 6.3 并发语义

- 采用 **latest-only coalescing**，不是“所有 commit 都排队部署”。
- 已进入 cutover 的 active deployment 不取消；等待中的旧 SHA 可被新的 main SHA 替换。
- 每个 commit 仍可运行 CI，但只有当时最新、CI 成功且本地 source freeze 与它绑定的 candidate 可进入 VM。
- VM 有全局 deployment lock；任何时刻最多一个 candidate 验证或切换。
- 若将来采用 GitHub Actions concurrency，必须显式记录 `queue: single` 的 pending replacement 语义；不能把 `cancel-in-progress: false` 描述为完整 FIFO。

### 6.4 GitHub 可见性固定门禁

仓库在开发、实现、首次迁移和 Stage 5 全部验收期间固定保持 Public。`reference/**`、PDF、SQLite、对象库、内部研究正文、secret、模型凭据、生成状态和 release 无论仓库可见性如何都禁止进入 Git；CI 必须有相应 secret/large-file/path gate。

只有 Stage 5 全部门禁通过并形成 release certificate 后才把仓库转为 Private。转换后必须重新核验账户 plan、Actions、branch/environment protection、CI、publish CLI 凭据与 exact-SHA candidate，并至少运行一次 Private 状态下的 CI 和 **无生产切换** candidate 演练。该复验通过并形成 visibility-closure receipt 后，项目才可最终关闭。

## 7. Release identity 收敛

### 7.1 唯一 manifest

每个 immutable release 只有一个 `release_manifest.json`，至少包含：

- `schema_version`、`release_id`、`built_at`；
- `application.commit_sha`、tracked tree hash、build tool version；
- `content.snapshot_id`、source inventory hash、IR/knowledge/search artifact hashes；
- `content.knowledge_enrichment`：每个文档的 `not_applicable/pending/ready/failed_retryable/blocked_policy`、knowledge generation IDs、请求 model alias、官方确认的 provider model revision、model-identity evidence hash、API 返回 `model`/`system_fingerprint` 及 prompt/schema 版本；
- `resources.inventory_hash` 与逐树摘要；
- `state.compatibility`：comment/workspace 的 read/write schema 范围和 rollback compatibility；
- 验证证据摘要与完整文件 hash inventory。

`release_manifest.json` **不得**记录具体 prior、`local_prior_binding`、receipt、切换 attempt、时间或动态控制信息。commit、content snapshot 和 index 是 release 的组成，不是三套 active 身份。

依赖方向固定为：

```text
active_release.json ───────────────► release_manifest.json (R, immutable)
local_prior_binding.json ─────────► active R + prior R
activation_receipt ───────────────► active R + prior R + successful switch/verification result
failure_receipt ──────────────────► original active/prior + candidate R + failed phase/result
rollback_receipt ─────────────────► active R + prior R + switch/verification result
cleanup_receipt ──────────────────► active R + prior R + exact removed targets/result
```

箭头只允许从可变 pointer、pair binding 或后生成证据指向已确定的 immutable release；`R` 不反向引用 active、binding 或 receipt，因此不存在 manifest hash 循环。`local_prior_binding` 必须恰好绑定 `R_active/R_prior`，其 active hash 必须与 `active_release.json` exact 一致；不一致时当前 active 读取可继续，但新激活、回退和清理全部 fail closed。任何 receipt 的产生都不得改变 `R`，也不能取代 active pointer。

### 7.2 唯一 active authority

`control/active_release.json` 只保存：

```json
{
  "schema_version": "qrh-active-release/v1",
  "release_id": "...",
  "release_path": "D:\\quant\\quant_platform\\releases\\...",
  "manifest_sha256": "..."
}
```

它通过同卷临时文件 + atomic replace 更新。Web、Search、MCP 都从该 release 解析自己的只读 artifact，并在诊断端点返回 `release_id` 与 `manifest_sha256`。

Archive catalog 的 document active mapping 是 release 内部只读数据；构建时必须和 manifest 一致，但它不是另一个部署 pointer。所有 receipt 和失败报告只证明事件，不参与当前身份解析。激活前必须证明 candidate 与当前 active 均兼容同一当前 D state，并证明当前 active 可成为唯一 prior。只有 `active_release.json` 原子切换成功、candidate 启动、切换后 health/关键功能/writer fence 和新 `local_prior_binding` 全部验证通过，才可生成成功 `activation_receipt`。任一切换步骤失败只能生成 `failure_receipt`，绑定原 pair、candidate、失败阶段与结果，严禁写入或伪装成功 activation receipt。

为关闭 pointer、binding 与终态 receipt 之间的崩溃窗口，controller 在 pointer 切换前先写入 `activation_coordination_only` 的 durable pending-activation journal，其中预选互斥的 activation/failure receipt ID；它不是 authority，也不改变 `R`。pending 期间 candidate 或 prior 服务只接受 SCM 临时传入且与 role/attempt/phase/nonce 完全一致的启动授权，普通 reboot/手工 start 必须拒绝。崩溃重放机械判断是完成新 pair 还是恢复原 pair，并最终只留下一个终态 receipt；任一身份不符、journal 损坏或 prior 启动失败均 fail closed 并保留 journal 供显式处置。

### 7.3 本地 prior 的保留与能力边界

- 成功激活后，新 active 与旧 active 构成唯一 pair；更早 prior 仅在新 active、binding、receipt、hash、启动和 state compatibility 全部验证后清理。
- 普通回退交换 pair 角色：旧 prior 成为 active，旧 active 成为新的恰一 prior。回退始终使用当前 D state，不替换 SQLite 文件、不倒退事件、不做 down-migration。
- 运行中的 candidate 只有在存在合法 attempt journal 时可暂时作为第三棵树；终态后 completed candidate、incoming/partial 与更早 prior 必须审计清理。
- 本版能力只覆盖生产 VM、精确 D 根、两棵 release closure 与当前 state 均完整可读时的最近一代版本切换。VM、D 根、对象库或 state 整体丢失超出本 change 的可恢复承诺，任何 certificate 或 receipt 都不得扩大该结论。

## 8. 前端兼容与渐进展示

### 8.1 Legacy compatibility renderer

- 所有现存页面沿用 V39 templates、CSS、JavaScript、路由、DOM 语义和响应式行为。
- 迁移阶段只允许路径配置、运行适配和必要 bugfix；任何视觉/交互差异都需独立授权。
- 验收覆盖桌面/窄屏截图、关键 DOM、链接、公式、表格、引用弹层、搜索、评论、Dashboard、Paper Lab 和访问门禁。

### 8.2 Generic structured renderer

仅对新进入通用 intake、没有既有手写页面合同的研究使用。v1 提供：

- 稳定标题层级与 TOC；
- 安全 Markdown、公式、raw table、code block、figure asset/caption；
- 引用/source locator 与当前/历史版本标记；
- 与现有字体、间距、色彩和交互规则一致的命名空间 CSS（例如 `.structured-document`）。

高级折叠、sticky table、图表语义、复杂引用侧栏和版本 diff 不是迁移或 MCP 上线门禁；以后可在 generic renderer 内渐进增强，不能反向改变 legacy 页面。

Generic renderer 的实现门禁使用一份**真实内容、隔离新身份**的验收件，而不是另写简化 Markdown：只读来源固定为 `reference/archive/Q5/低SNR横截面选股_因子历史表示与压缩研究_结构重构扩展版.md`，source SHA-256 为 `4994d1df74414fdadfefb7ba812c3851ef26fd82c36bc7f174c7db577e756679`。该文档真实包含 304 个标题、公式、宽表、44 对代码 fence 和正式参考链接。实施测试把其 bytes 原样复制到 reference 之外的隔离 acceptance source root，并赋予新的 test-only logical path/document ID；不得修改原文件、不得改变它现有的 legacy 页面合同，也不得把测试副本加入生产 catalog。

同一 discover→freeze→version→IR→chunk/index→generic route 流程必须在**没有文档专用 route/template/slug 分支**的情况下自动发布该新身份，并通过桌面/窄屏浏览器检查：TOC/深链可达真实层级，公式安全渲染，宽表局部滚动且页面不横向溢出，代码可读，引用可到来源，页面显示 document/source version 与 byte/line locator；已接受的方法/条件/限制以带 locator 的知识卡展示，增强未完成时明确显示 pending 而不伪造字段。预注册任务“定位指定公式、比较指定表项、打开代码块、追到参考来源、识别当前/历史版本”相对 raw Markdown 基线必须减少导航步骤或消除不可完成项；同时 V39 legacy screenshot、DOM、CSS 与交互回归零未授权差异。

## 9. Reference 自动发现、版本与失败保旧

### 9.1 默认发布边界

`reference/archive/**/*.md` 默认进入自动候选，但以下情况 quarantine：

- 路径位于 `_*/`、`旧版原始文件/`、`experiments/` 或配置的 legacy/internal 根；
- 文件名匹配 draft/tmp/backup/private 等保留模式；
- 路径含 reparse/symlink、编码不可判定、缺少可识别标题、出现 secret scanner 命中；
- 稳定身份重复、修改并移动而无法确定映射、引用或资产越界；
- 明确的 central deny/exception policy 命中。

`README.md`、`GLOSSARY.md`、`PROGRESS_LOG.md` 等按模式作为 supporting content，不生成独立研究页。正常新增文件无需逐项修改 policy 或等待人工批准；人工只处理 quarantine。

发布许可与外部 AI 许可是两个独立维度。`publishable` 文档可同时是 `external_ai_allowed` 或 `no_external_ai`；路径/中央 policy 命中 `private`、`no_external_ai`、敏感/秘密扫描或无法判断时，外部 AI 一律 fail closed，但确定性 IR、页面和 lexical search 仍可按其发布许可继续处理。正常研究目录可由模式级 policy 统一允许 DeepSeek，不要求每个文件逐项批准。

### 9.2 身份与版本

- 同一规范路径的 source byte hash 变化产生新 immutable version，并链接 `supersedes`。
- 相同 hash 的纯移动可自动保留 stable document id 并增加 alias。
- “移动同时修改”没有可靠证据时进入 quarantine，由映射文件一次性裁决。
- publishable 文件消失不等同删除；必须有 tombstone、原因和可选 replacement，才从默认召回移除。历史对象永不物理覆盖。

### 9.3 Candidate 状态机

```text
discovered -> frozen -> parsed -> rendered -> linked -> lexical_indexed
           -> deterministic_verified -> base_snapshot(active, knowledge pending/blocked)
           -> semantic_job -> candidate_verified/accepted -> enriched_snapshot(active)
               \-> retryable_failed / invalid_evidence / blocked_policy
```

所有步骤幂等，并记录 source hash、tool/model/version、输入输出 hash 和错误。确定性 parse/render/link/lexical 任一步失败时保留上一 active；DeepSeek API 失败不得回滚已经通过的确定性文档。对新增或修订文档，系统可先激活明确标记 `knowledge_enrichment=pending/failed_retryable/blocked_policy` 的 base snapshot；当前 MCP 不得把旧版本语义知识冒充为新版本知识。语义候选验证完成后，以相同 source version 生成新的 enriched snapshot，再按同一原子发布规则激活。

## 10. Document IR 的最小完整范围

### 10.1 确定性 IR（本版必做）

- document metadata、heading tree、paragraph/list/quote；
- raw TeX 与公式 display/inline 类型；
- raw table cell matrix 与对齐；
- code language/raw text；
- figure/image asset reference、alt/caption，不推断图表结论；
- citation、`^src`、internal/external link；
- 每个 block 的 byte/line source span、source hash、parser version。

已有 `MarkdownProjection` 和引用渲染应扩展复用。原 Markdown 始终作为不可变对象保存，IR 是可重建派生物。

### 10.2 不放入 parser 的内容

方法、适用条件、限制、失败经验、因果/支持关系包含语义判断，属于 knowledge compiler，不属于确定性 parser。表格单位理解、图表视觉解读和复杂交互增强也不进入 v1 parser gate。

## 11. 知识形成链

### 11.1 DeepSeek V4 Pro 增量执行合同

`deepseek-v4-pro` 正式进入 reference 自动链，但只能在确定性 IR 成功后生成语义候选。每个 job 使用：

```text
job_key = sha256(
  source_version_id + ir_hash + external_ai_policy_version +
  requested_model_alias + expected_provider_revision +
  model_identity_contract_hash + prompt_version + output_schema_version
)

generation_id = sha256(
  job_key + provider_returned_model + provider_revision +
  system_fingerprint + response_object_hash
)
```

- 自动队列只为 **source bytes 发生变化** 且 `external_ai_allowed` 的文档创建 job；普通代码发布或重复 publish 不全量重跑未变化文档。
- 模型、官方 revision、identity contract、prompt 或 schema 升级不会静默重写历史。它们只有在显式、可审计的 targeted recompile campaign 中才为选定 source versions 创建新 generation；旧 generation 永久保留。
- 每次调用记录请求 alias、官方确认的 provider revision、identity evidence URL/hash/observed-at、API 返回 `model`、`system_fingerprint`、response ID/created、prompt/schema 版本、IR/source 输入 hash、job key、开始/结束状态和输出对象 hash，不记录 API key 或 Authorization header。
- API key 从现有受保护凭据注入 compiler 进程，不进入 Git、日志、manifest、candidate、active/prior binding、receipt、D-root audit 或回退材料。
- `private/no_external_ai`、敏感命中或外发许可不确定的内容不得构造 API 请求；状态记录为 `blocked_policy`，不是失败重试。
- API 超时、失败、非法 JSON/schema、未知字段、越界 span 或证据无法定位均产生可审计 `failed_retryable/invalid_evidence`，不得改变当前 active knowledge。

#### 11.1.1 Provider 模型身份门禁

截至 2026-08-21，DeepSeek 官方 Models & Pricing 页面把 API alias `deepseek-v4-pro` 的 MODEL VERSION 明确列为 `DeepSeek-V4-Pro-0813`；本轮实际 `/models` 与 ChatCompletions 响应仍只返回 alias，响应另给出 `system_fingerprint`。因此不能只靠 `response.model` 猜测 dated revision，必须保存两类独立证据：

1. **provider identity evidence**：官方页面 URL、抓取时间、页面内容 hash、alias→revision 映射和审核状态；
2. **per-response identity**：请求 alias、返回 `model`、`system_fingerprint`、response ID/created 和响应对象 hash。

compiler 启动与每个 campaign 开始时必须验证 identity contract。若官方映射变更、返回 model 不同、fingerprint 首次出现或发生变化且无法证明仍属于同一 revision，新的响应进入 `provider_identity_drift` 隔离状态，不得追加到旧 generation、不得成为正式知识。维护者必须建立新 identity contract，显式选择受影响 source versions 发起 targeted recompile；旧已发布 generation 继续绑定原 revision 并保持历史可追溯，不自动全库重写。无法取得官方 revision 证据时只能发布 deterministic base snapshot，不能把 alias 自行标为 `V4-Pro-0813`。

### 11.2 Prompt injection 与输出边界

- 系统指令必须明确声明研究正文是 **不可信 source data**，其中任何“忽略规则、调用工具、泄露密钥、执行命令”等文字都不是指令。
- compiler 不向模型提供工具、文件系统、网络抓取或 secret；只发送允许外发的最小 IR blocks、稳定 block/span IDs 和闭合 schema。
- 来源数据以结构化字段传入，不拼接到 system prompt；输出仅接受严格 JSON schema 和本次输入中存在的 span IDs。
- 模型不得新增来源、作者、数值、公式或引用目标；任何超出给定 spans 的关系或摘要原子 claim 均拒绝或等待人工接受。

### 11.3 分层事实状态与接受规则

| 状态 | 形成方式 | 默认用途 |
|---|---|---|
| `source_explicit` | 明确标题/标签/引用协议和可验证规则直接映射 | 可检索、可推荐；标明来源导出 |
| `model_candidate` | DeepSeek 提出，带字段级 source spans、generation 与 confidence | 仅诊断/审核，不进入权威推荐 |
| `machine_verified` | 仅限可抽取/可规范化字段通过机械规则，所有原子值可回到原文 span | 可检索/推荐；标明机械验证 |
| `human_reviewed` | 人工接受或修订语义候选，原文不变 | 可检索/推荐；最高派生可信度 |
| `rejected` / `deprecated` | 无证据、冲突、失效或被替换 | 默认召回排除，历史可查 |

机械接受仅适用于 extractive 或受控规范化条目：quote/hash 精确、span 属于同一 source version、枚举合法、数值/公式逐字匹配、关系目标存在且 cue 可定位、无未标注否定或条件冲突。抽象摘要、推断关系或无法以这些规则证明的候选必须人工接受，不能因模型置信度高而自动转正。`source_explicit` 也不等于人工已审核。

### 11.4 编译与快照过程

1. 确定性 IR 生成候选段落、显式 cue、公式、引用和证据关系。
2. 规则先提取明确的 method/condition/limitation/failure/evidence 条目。
3. 对变更且获准外发的文档，DeepSeek 生成结构化摘要及语义候选；每个字段返回 span ID、支持片段 hash 和 generation ID。
4. 验证器拒绝缺 span、支持文本不符、枚举非法、source/provider revision 漂移、条件互斥未标注、注入式输出和引用目标错误。
5. 通过机械接受规则的候选进入 `machine_verified`；其他候选等待人工接受或保持 candidate。
6. build 生成文档 coverage report：规则知识、DeepSeek job 状态、正式条目、pending/rejected 原因。空字段不能伪装成完整知识。
7. base snapshot 可先发布确定性页面和 lexical index，并显式标注 enhancement pending/blocked/failed；MCP 对当前版本返回该状态而非旧语义知识。
8. generation 验证/接受完成后构建新的 enriched snapshot；即使 Git commit 与 source version 相同，effective snapshot ID、release ID、knowledge/search hashes 和 immutable manifest 也必须更新，并经完整 consistency gate 后原子激活。后续失败、非法或 pending generation 保留上一成功 generation 与 active identity，不得静默撤回可用知识。

### 11.5 核心存储

- 原始 Markdown、IR JSON、DeepSeek 原始输出、验证结果和大对象进入 content-addressed object store；不同 generation 不覆盖。
- Git 外受保护的本地 compiler workspace 保存 `semantic_job`、全部 `knowledge_generation`、待审核 candidate、decision audit 与正式 knowledge item；全体 job terminal 后通过 SQLite consistent backup 提升为带 immutable promotion receipt 的发布 authority。发布、holdout 与 artifact builder 只能以严格 read-only/immutable store 消费该 authority，禁止 `journal_mode` 切换、DDL、backfill 或 sidecar 创建；任何后续写入必须在新的 workspace 中完成并形成新 promotion。workspace/authority 本体不进入 Git、VM active state、release、prior binding 或回退材料。
- release 内只读 SQLite/JSON snapshot 保存 document/version/block/source_span/citation/evidence、当前正式 knowledge projection、被选中成功 generation 的必要 provenance 和 active membership；Web/Search/MCP 只读取这一密封投影。
- FTS5/辅助 token 表用于文本召回；结构化列用于市场、频率、数据、目标、假设、状态和版本过滤。
- 评论、Dashboard、workspace 不进入知识 snapshot，也不污染来源。

## 12. 检索设计与独立评测

### 12.1 Chunk 与 metadata 合同

RAG 的权威检索单位不是任意 token 窗口，而是由确定性 IR 形成的 **heading-aware source chunk**：

- 首选且在本版严格执行单个 paragraph/list/quote、完整公式、完整表格、完整 code block、figure caption 或 citation neighborhood；短内容不得把同 heading 下相邻段落拼成一条 evidence chunk。只有超长 block 才按安全边界生成 child；不得在公式、表格行、代码块和 `^src` occurrence 中间切断。
- 超长 block 才按确定性边界生成 child chunks，并保留 parent block、heading path、前后邻接与同一 source span 关系；检索命中 child 后可在预算内补齐 parent/neighbor，而不是依靠大比例重叠制造重复。
- `chunk_id = sha256(document_version_id + ordered_source_spans + chunker_version)`；相同 source version 与 chunker 产生相同 ID。chunker 升级形成新 artifact generation，不能原地改 ID。
- 每个 chunk 至少携带 research/document/source version、heading path、block type、byte/line locator、language、citation IDs、source hash、chunker version、active/superseded/deprecated 状态；已正式形成的知识可附 method/condition/limitation/failure、market/frequency/data/target/horizon、fact status 与 relation IDs。
- 模型摘要只作为带 generation/provenance 的补充召回字段，不能取代 source chunk、改变 locator 或在 `model_candidate` 状态参与正式推荐。

### 12.2 检索流水线

1. 解析 query/task context：研究类型、市场、频率、数据、目标、约束、时间与版本。
2. exact ID/alias/title、FTS5、CJK n-gram/trigram 与短词 fallback 并行召回。
3. 结构化 applicability 使用 item-scope 值与受控 facet alias；只有全篇正式声明一致的受控 facet 才可传播到 chunks，未知或混合 scope 不得用并集伪造 match/conflict。显式 `不是 A 而是 B` / `而非 A` / `not A but B` 对默认正向 evidence 是硬过滤。
4. 关系扩展只走有状态、有来源且目标仍属于同一 active snapshot 的正向边，并对 target 重新执行否定与 applicability 检查；`contradicts`/`fails_under` 不得倒置成正向推荐。
5. 依据 lexical、字段匹配、条件兼容、当前版本、事实状态、来源质量做确定性重排。
6. 按 exact source byte range 与 knowledge kind/cluster identity 去重，返回命中原因、限制、反例和引用 locator；展示用 context/adjacency 与 matched evidence 分离，相邻 span 或不同 kind/cluster 不得替另一条证据取得分数或通过 qrel。

页面、lexical/structured index、knowledge tables 和 MCP 只从同一个 immutable content snapshot 构建。source revision 只重建受影响文档、其 relation backrefs 与必要的全局词典；tombstone/deprecation 通过 active membership 从默认召回失效，历史 artifact 仍可显式访问。任何增量任务失败都不能把“新页面 + 旧索引”或“新索引 + 旧关系”组合为 active。

### 12.3 Qrels、基线与防泄漏

- 用真实因子、模型、数据处理和回测问题建立覆盖矩阵；集合规模由覆盖充分性决定，而不是把“40 个”当作证明。
- 每条 qrel 必须记录 question/task context、answerable/no-answer、expected/forbidden method、适用与冲突 facets、relevant/negative source version/span、精确 UTF-8 byte range、quote/source hash、必需引用和裁决者；来源修订后自动标 stale，重新裁决前不能继续充当 release 证据。命中只认 evidence card 的精确 locator，context span 不参与正负判定。
- 至少三分之一问题作为 sealed holdout，由不同审核者保管；调参只看 development set。
- 必含 hard negative、无答案、适用条件冲突、当前/历史/废弃版本、错引、跨语言、公式别名和近义方法。
- holdout 在放行时才运行；失败案例进入下一轮新测试，不反向修改已看过的 holdout 以制造 PASS。
- 报告总体和分 slice 的 Recall@10、MRR/nDCG、no-answer precision、条件正确性、当前版本错误、引用 locator 正确性、P95 latency 和 index/rebuild 成本。Recall/nDCG/MRR 只在 answerable qrels 聚合，no-answer accuracy 独立聚合；expected kind 与 required citation 必须来自实际覆盖正向 locator 的卡，不能由无关 Top-K 卡代缴。
- 以当前 `LIKE` search 为可复现实测基线。硬门禁：引用 locator 错误为 0、默认返回废弃版本为 0、把冲突条件说成适用为 0；其余阈值在封存 holdout 前按 slice 预注册。候选必须在不破坏硬门禁与延迟预算的前提下，对至少两个预先声明的 lexical/structured 困难 slice 产生稳定增益，不能只报告总体平均值。

### 12.4 Vector 决策

vector 只有在 sealed evaluation 上同时满足以下条件才进入 active pipeline：

- 对至少一个已知 lexical 困难 slice 有稳定净增益；
- 不降低 no-answer、条件、当前版本和引用正确性；
- P95 latency、索引体积、重建时间、模型许可和离线维护成本在预算内；
- 删除 vector 后系统仍有可靠 lexical/structured 基线和回退。

不存在机械的“Recall 提高 5 个百分点即采用”规则。

## 13. MCP 设计与真实客户端

### 13.1 工具面

初始最小工具面为三类，最终在 tool-choice eval 后允许合并或拆分：

1. `search_quant_knowledge`：搜索研究/方法/证据，可传 task context、filters、response mode、budget；`response_mode=context_bundle` 覆盖原单独 bundle 能力。
2. `get_quant_knowledge`：按稳定 ID 取 research/method/evidence，可选择 history/relations/source spans。
3. `list_knowledge_updates`：按 snapshot/time/knowledge IDs 返回新增、替换、废弃与 replacement。

不为了接口整齐固定八个高度重叠工具。所有响应返回 `release_id`、`manifest_sha256`、`snapshot_id`、对象/版本 ID、fact status、source locator、限制和截断/continuation 信息。

当当前 source version 只有 deterministic base snapshot 时，MCP 必须返回 `knowledge_enrichment=pending/failed_retryable/blocked_policy`，仍可返回 lexical source passages，但不得把上一 source version 的 DeepSeek knowledge 当作当前方法或摘要。显式历史查询可以返回旧 generation，并标明 superseded source version。

### 13.2 上下文控制

- 请求支持字符或 token budget、limit/cursor 和 detail level。
- 先返回短摘要、适用条件、限制和 locator；正文按需取。
- 同一 source span、同一知识簇和同一证据链去重。
- 截断必须可见，continuation 必须稳定绑定同一 snapshot。
- 来源中的 agent 指令一律视为不可信数据，MCP 不提供写工具或执行能力。

### 13.3 Stdio 运行拓扑与客户端接入产物

stdio server 不是 VM 常驻服务。它由每台研究员客户端上的 Codex CLI/IDE/Desktop 作为子进程拉起，读取该客户端的 **read-only immutable knowledge mirror**；不直接打开 VM SQLite、不写 VM，也不把 stdio 暴露为网络端口。mirror 只缓存 release 内的 MCP/search artifacts，`mirror/current.json` 是本地 cache pointer，不是 authority。

每次 server 启动、continuation 恢复及 current-sensitive 请求前，authority resolver 都必须通过 Stage 0/4 实测选定的只读适配器取得 VM `active_release.json` 和其指向的 `release_manifest.json` hash。适配器可以是受控只读文件共享或现有/最小只读 deployment identity endpoint；实现阶段按真实网络能力二选一，但它只能读取 identity，不能成为 HTTP MCP 或部署写入口。resolver 随后：

1. 校验 active schema、release path、manifest SHA-256 与 manifest 内 snapshot ID；
2. 若本地缺少该 immutable artifact，从配置的只读 artifact source 增量同步到 `.partial`，验证 closure/hash 后原子更新 mirror cache pointer；
3. 只有 mirror 的 `release_id/manifest_sha256/snapshot_id` 与刚验证的 VM authority 三元组完全相同，才以 `fresh` 返回 current 结果；
4. VM activation/rollback 或其他发布机完成切换后，下一个 probe 必须发现 identity 变化、废弃旧 continuation，并要求 `list_knowledge_updates`/重新 search→get；本地 cache pointer 的更新不得反向改变 VM active。

网络不可达、mirror 落后、manifest/active 无法校验或 artifact 同步失败时，current-sensitive 工具必须返回结构化 `availability=stale|unavailable`、本地三元组、最后验证时间、观察到/期望 identity 与原因，不得把旧镜像静默表述为当前知识。默认 `search/get/list-updates` 不返回可供当前决策使用的旧结果；只有调用者显式 `allow_stale=true` 才可读取标注为 historical/stale 的缓存，agent instructions 要求不得据此形成未声明的当前建议。

本版交付的是可跨项目安装的本地客户端，而不是只能从 `quant_platform` cwd 启动的脚本：

- 可安装的 versioned CLI/package 与 `serve-stdio` entry point；代码、默认 profile 和 schema 来自精确 release，mirror/state 放在用户级受保护目录；
- user-level 或 project-level `.codex/config.toml` 模板，只传 profile/authority/mirror 配置，不依赖目标项目相对路径；
- 可幂等 install/doctor/uninstall 的 profile 命令，以及根 `AGENTS.md` 可复制的最小量化知识调用片段；
- MCP server `instructions`：前 512 字符自包含说明何时先查知识、何时复查更新、何时取证据；
- 因子、模型、数据处理、回测四类 scenario fixtures 与 tool-call trace evaluator。

除 `quant_platform` 自身外，命名验收消费者固定为独立项目 `D:\quant\backtest_demo`。实施时只在获准的 project-local 配置/AGENTS 范围安装上述 profile，不搬入知识库、不复制 server 源码、不要求该项目位于 `quant_platform` 下。

路由合同采用少量、可测试的正反触发规则：

- 在选择/比较因子、模型、数据清洗与标准化、标签/目标、时间切分、泄漏控制、交易成本、回测验证或失效监控方案前，若答案依赖项目历史方法、适用条件、限制或失败经验，先调用 `search_quant_knowledge`。
- 形成会影响研究结论的推荐前，用 `get_quant_knowledge` 展开关键 source spans 与引用；只有标题/snippet 不能作为结论证据。
- 继续先前研究且 active snapshot 已变化，或需要判断方法是否被替换/废弃时，调用 `list_knowledge_updates` 后再复用旧结论。
- 纯语法、格式化、与量化知识无关的通用编码，以及用户已提供完整且无需项目历史的机械操作不得为了指标而强制调用。
- 市场、频率、数据、预测期、目标、成本或版本任一关键 facet 改变时，旧检索结果默认失效并重新查询。

Streamable HTTP 只有在出现命名的远程 agent、认证 owner、网络边界与维护责任后才成为独立 change；本版不实现无人消费的 transport。

### 13.4 主动调用验收

评测 prompt 不写“请搜索 MCP”，而是给真实研究任务，检查：

- 需要历史方法/适用条件/失败经验时是否在作决定前调用；
- 纯代码或无关问题是否避免无意义调用；
- 市场、频率、数据或版本变化后是否重新查询；
- 做出方法选择或风险判断前是否取到可追溯证据；
- MCP 不确定或无答案时是否明确表达，而非补造知识。

报告 trigger recall/precision、调用时机、引用 grounding、条件正确性和有/无 MCP 的回答差异。

tool-choice fixture 必须同时包含应调用、不应调用、调用过早/过晚、先 search 后 get、snapshot 变化后 list-updates 的对照。MCP-assisted agent 相对 no-MCP 对照必须在预注册的 grounded decision correctness、条件/限制识别和引用正确性上产生可复现净增益；若只有“发生了工具调用”而研究判断无改善，本版 MCP 不得验收。

跨项目验收必须从 `D:\quant\backtest_demo` 工作目录启动 Codex/stdio，在 prompt 不出现“调用 MCP”时完成至少一项应调用的回测/数据泄漏任务和一项不应调用的纯机械任务；trace 必须证明应调用任务执行 search→get 并返回与 VM authority 相同的三元组，不应调用任务无无意义调用。随后在隔离环境模拟 VM activation 与 rollback，客户端必须识别 snapshot 变化、使旧 continuation 失效并 list-updates→重新 search/get；断网、旧 mirror 和伪造 manifest 各自返回 stale/unavailable。只有本项目和该独立项目都通过，才可称 stdio 拓扑闭合。

## 14. Comment 与其他可变状态

### 14.1 本版权威

- `D:\quant\quant_platform\state\comments.sqlite3`：Archive comment、事件、回执、actor/outbox 和 progress topic。
- `D:\quant\quant_platform\state\research_workspace.sqlite3`：Workspace node/observation/event/comment 等现有可变状态。
- release manifest 只声明兼容 schema 范围，不把具体数据库 hash 或“comment authority version”纳入 release identity。

候选验证使用 D-root 内的 online backup 隔离副本；不得对 active 数据做探测写。跨 release、升级、回退和进程重启都必须验证两族 comment 及所有非 comment 状态不丢失。隔离副本在候选终态后清理，不能作为可选状态版本。

### 14.2 稳定目标、锚点与跨版本可见性

现有 Archive comment 表只持有 `research_id`，已经证明文件外置和事件不丢失，但尚不能证明文档修订后的页面可见性。本版必须把 comment target 明确为 release 路径无关的稳定身份：

- document-level comment 绑定 stable `research_id/document_id`，不得绑定 release path、临时 route、source pathname 或 snapshot-local row ID；纯移动/alias 继续解析到同一 document identity。
- block/span comment 额外保存 versioned anchor：origin source version、block type、精确 source span/bytes hash、heading ancestry/context hash 与 locator schema version。原始 anchor 永久保留。
- 自动重定位只接受确定性证明：相同 span bytes/hash 在新 version 唯一出现，且 block type 与结构上下文一致；或版本编译器生成一个经 hash 验证的一对一 unchanged-block mapping。禁止 fuzzy similarity、embedding nearest-neighbor 或仅凭标题相似自动挂接。
- 每个 snapshot 生成的是只读 `comment_anchor_projection`，状态为 `resolved_current/resolved_history/unresolved/ambiguous`；projection 不改写 comment current row、event、revision、actor 或时间。renderer 改版和代码回退只选择对应 snapshot projection。
- 无法唯一重定位时，comment 必须继续出现在原 source version 的历史页面，并进入当前文档的 `unresolved comments` 区域，显示原 locator/version 与原因；不得静默消失，也不得挂到“看起来相似”的新段落。若 prior release 不认识新 anchor schema，也必须至少按 stable document identity 在 unresolved 区域展示。

非空端到端 fixture 固定执行：在 source v1 写入一条 document comment、一个可唯一重定位的 block comment 和一个将在 v2 被改写的 span comment；发布新代码，执行同路径修订与纯移动，确认前两类在正确位置可见、改写项进入 unresolved/history；再回退到 D prior release 并读取。浏览器和 SQLite 查询必须共同证明所有 comment 的 current/event/revision/actor/created_at/updated_at 未被发布、修订、renderer 或回退改写，且没有错误自动挂接。

### 14.3 候选隔离副本与状态完整性

- candidate 验证需要写入 fixture 时，只能以 SQLite online backup 在 D-root isolation 目录生成瞬态副本；active 数据只做不改变物理 bytes 的读取与完整性检查。
- 每份隔离副本验证 integrity、foreign key、schema、核心表计数和逻辑摘要；候选成功或失败后均清理数据库、WAL/SHM 和工作目录。
- 首次 C→D writer handoff 在写入 fence 内取得最终一致副本并落为新的 D state authority；D 开放外部写入后，任何普通回退都不得再替换 state 文件。
- release 内 seed 禁止覆盖非空外置库。本版不建立周期性状态副本、状态时间点选择器或 D 根之外的项目状态存储。

### 14.4 SQLite schema 前向兼容与回退

- 每个 release manifest 声明 comment/workspace schema 的 `read_min/read_max/write_min/write_max`，激活前同时验证 candidate 与已锁定 D prior。
- 正常 schema 升级采用 expand/compatible/contract：先添加旧 release 可忽略的表、列或索引；在 prior 仍处于回退窗口时禁止 destructive rename/drop 或改变旧写入语义。
- 候选若升级 state schema，必须用升级后的真实 fixture 证明 D prior 仍可启动、读写和保持事件/CAS 语义；否则在激活前提供兼容 adapter/prior release，无法做到则拒绝升级。
- 普通代码回退只切 D prior，继续使用当前已升级 D state，不做 down-migration、不替换当前 SQLite 文件。contract 清理必须等 active 与恰一 prior 都不再要求旧 schema 后另行放行。
- 状态库损坏或整体丢失不属于普通代码回退；本 change 对该场景不提供状态替换或系统重建承诺，控制器必须 fail closed 并明确报告能力边界。

### 14.5 PostgreSQL 触发条件

满足以下任一并有观测证据时，才另立窄 comment PG proposal：

- 多台应用主机或多个并行 writer 成为正式要求；
- 监控发现持续 lock contention/timeout，SQLite WAL 与重试仍不能满足；
- 公司提出集中 HA、PITR、跨机 RPO/RTO 或统一审计的强制要求；
- comment 负载和一致性/故障测试证明单文件数据库成为真实瓶颈。

“VM 已安装 PostgreSQL”或“Industry Demo 使用 PostgreSQL”不是触发理由。

## 15. VM 本地 active/prior 回退与严格保留

### 15.1 能力边界

- **普通代码/内容回退**：active release 出错但生产 VM、精确 D 根、当前 D state 与两棵对象 closure 完好时，切到唯一 prior，继续使用当前 D state，绝不倒退评论或工作区状态。
- **明确不覆盖**：VM、D 根、对象库或 state 整体丢失。本 change 不提供这类场景的系统重建或状态替换承诺，控制器必须 fail closed，release certificate 必须显式披露剩余风险。
- 稳态只保留精确 D 根内的 active、恰一 prior 与二者共用的当前 state；candidate 的 online-backup 数据库只存在于 D-root isolation，用后即清。

### 15.2 Pair binding 与保留集合

生产稳态的 release roots 固定为：

```text
active_release.json ───────► R_active
local_prior_binding.json ──► R_active
                           └► R_prior
```

`active_release.json` 是唯一 current authority。`local_prior_binding.json` 只提供最近一代回退资格，必须 exact 绑定 active/prior 的 release ID、manifest SHA-256、canonical path、state compatibility verdict 和生成 attempt；它不参与 Web、Search、MCP 的 current 解析。两份 release manifest 都不能反向引用 active、binding 或 receipt。

成功激活后，新 candidate 成为 `R_active`，旧 active 成为 `R_prior`。旧于 prior 的 release 只有在新 active、binding、activation receipt、启动、关键功能和当前 state 兼容性全部通过后才可精确清理。运行中的 candidate 仅在存在合法 durable attempt journal 时可暂时作为第三棵树；终态后 completed candidate、incoming/partial 与不再被 active/prior closure 引用的对象必须清理并生成 receipt。

首次 C→D handoff 不设置内容等价的 bootstrap 特例：在开放 D 流量前，先以冻结 V39 baseline `R0` 建立尚未对外的 active，再通过正常激活协议切换到真实 successor `R1`，由 `R0` 成为 prior。无法提供真实 `R1/R0` pair 时继续停留在隔离验证，不得开放 D 外部流量或伪造 prior。

### 15.3 激活与回退

- 激活前同时验证 candidate、当前 active、当前 state schema/read-write compatibility，以及当前 active 成为 prior 后的可启动性。任何失败都发生在 pointer 切换前。
- 激活成功必须依次闭合 active pointer、candidate start、post-activation health/关键功能/writer fence、pair binding 和 activation receipt；之后才清理更早 prior。
- 激活失败只写 failure receipt 并恢复原 pair；未成功激活的 candidate 不能成为 prior。
- 人工普通回退交换 pair 角色：旧 prior 成为 active，旧 active 成为新的恰一 prior。回退继续使用当前 D state；不替换 SQLite 文件、不恢复旧事件、不降级 schema。
- pointer、binding、receipt 之间的 pending journal 只作 crash coordination。重放必须最终得到一个 exact pair 与一个终态 receipt；普通 reboot/手工 start 在 pending 时 fail closed。

### 15.4 清理与边界验收

- 第三个 retained release、多个 prior、binding/active 漂移、清理失败或对象 closure 缺失均阻止下一次 publish。
- 清理必须先校验 exact canonical target、无 reparse、目标不属于 active/prior closure，再执行并生成 path/hash/delta receipt；不能用宽泛目录或目录时间决定删除对象。
- Stage 5 必须对功能完整 release 执行 active→prior→active 序列，覆盖代码/前端、内容、PDF/图片/对象、页面/Search/MCP snapshot、当前 SQLite state、schema compatibility、浏览器/API 和评论生命周期。
- Stage 5 同时检查 installed wheel、CLI、config、schema、Windows 任务清单、runbook 引用和 VM write-set：不得存在 D 根之外的项目存储、周期性状态副本任务或不属于 active/prior 合同的正式权威入口。
- C→D 过渡材料只保留到 writer handoff、首个 active、首个可启动 prior 与同一 state 回退全部通过；其后按精确清单审计清理，不继续作为产品级回退权威。

## 16. 激活、回退与故障语义

### 16.1 Candidate gate

- manifest/schema/hash 与 immutable path；
- state schema compatibility；
- local unit/integration 和 GitHub CI exact SHA；
- 隔离端口 health/API/页面/搜索/MCP；
- V39 legacy screenshot/interaction regression；
- content snapshot 的 page/search/MCP consistency；
- knowledge enhancement 状态合法；base snapshot 不含旧版本冒充的当前语义知识，enriched snapshot 的 generation 已验证/接受；
- comment/workspace 隔离副本读写 fixture 后清理；
- rollback release 可启动且兼容同一 D state。
- 当前 active 可成为唯一 prior；candidate 与当前 active 均对同一当前 D state 通过 read/write/schema/启动验证；预期 pair 满足 exact path/hash、无 reparse、恰一 prior 与空间预算。`activation_receipt` 不是激活前门禁输入，只能在 pointer、启动、post-activation、binding 全部成功后生成。

### 16.2 切换

1. 获取 VM deployment lock，重新验证 active 与 candidate。
2. 锁定当前 active 为拟议唯一 prior，确认 candidate 与当前 active 都兼容同一当前 state。
3. 停止 active 服务；不得替换或倒退 state。
4. 写入 crash-coordination journal，atomic replace `active_release.json`，启动 candidate。
5. 验证 health、关键页面、搜索、MCP、评论读取/写入 canary 和 writer fence。
6. 写入并复验 `local_prior_binding`，全部成功后才写入 `activation_receipt`。
7. 清理更早 prior 与终态 candidate/incoming，生成 `cleanup_receipt`，复验终态只有 active 与恰一 prior。
8. 任一步失败则停止 candidate、恢复原 active/pair 并只写 `failure_receipt`；状态始终为同一 D state，不得生成成功 activation receipt。

不要求为无实际影响的 Python/package 小版本差异 HALT；门禁关注真实导入、关键路径、数据兼容、浏览器行为和可回退性。

## 17. 分阶段 implementation plan

### Stage 0：权威基线与最小发布核心

- 冻结 V39 全资产 inventory、代表性页面/API/数据/浏览器基线。
- GitHub 保持 Public；建立 secret/large file/reference/PDF/SQLite/object/internal-research 禁入门禁。
- 实现单一 immutable release manifest、active pointer、`local_prior_binding→active/prior` 合同、证据 receipt、VM deploy CLI 骨架和 state root 合同，并用依赖图/linter 证明 `R` 不反向引用 active、binding 或 receipt。
- 实测本地测试入口、VM 网络/权限/端口、cutover budget，以及 exact D 根内 releases/control/state/isolation 的 canonical path 与无 reparse 边界；不发现或配置 D 根之外的项目存储。

**门禁**：能从 manifest 重建并验证 V39 candidate；未触碰现网 writer。

### Stage 1：D 盘兼容 bootstrap 与回退纵切

- 全量同步 V39 Git 外 assets；建立隔离候选。
- 完成 legacy 页面/功能/数据对照。
- 建立 exact D 的 release inventory：生产终态只允许 active、恰一 prior 与当前 state；合法 journal 可暂时授权一个 candidate，终态后必须清理。
- 从冻结 V39 inventory 构建唯一 baseline `R0`，并在其上建立具有真实不同 manifest/release identity 的 successor candidate `R1`；在旧 C writer 继续服务期间以 D-root isolation 的 SQLite 副本分别完成验证。正式 handoff 在外部流量/writer fence 内取得最终一致副本并落为 D state，先建立尚未对外的 `R0` active，再以正常激活协议形成 `R1` active + `R0` prior；D 尚未接受外部写入时失败可退回未变化的 C，只有真实 pair 通过后才开放 D 流量并使 C 永久退出 writer authority。
- 证明 current active 可成为 prior、两版本兼容同一 D state，完成激活与 `local_prior_binding` 后演练 active/prior 角色交换。
- 全程保留 C→D 过渡材料，直到 writer handoff、D active、首个可启动 prior 与同一 state 回退全部通过；其后按精确清单审计清理，不继续作为产品级权威。

**门禁**：D baseline 在副本状态下实测通过；exact D write-set、writer fence、最终 state 一致性和 C→D 过渡语义通过。之后“无外部 D 写入则退 C”和“D 开放流量后只退 local prior”分别验证；正式 apply 时 D 一旦开放流量，C 永久退出 writer authority。

### Stage 2：一次 publish 自动发布

- 实现受控 local publish CLI、GitHub-hosted exact-SHA CI 和 VM 调用 adapter。
- 实现 latest-only coalescing、deployment lock、partial cleanup、失败报告和显式 replay。
- publish 在不改写 `R` 的前提下验证当前 active 可成为 prior，原子切换后生成 exact `local_prior_binding` 与 `activation_receipt`；失败只生成 `failure_receipt` 并恢复原 pair。终态清理更早 prior 与 candidate。本版不实现裸 push watcher、pre-push 部署 hook 或 self-hosted runner。

**门禁**：一次命令从 push 到 candidate/activation 全自动；故障不影响 active；不人工制作广播包。

### Stage 3：Reference 编译与渐进展示

- 在现有 intake/catalog/markdown 上实现默认边界、quarantine、稳定 identity、version/tombstone。
- 完成确定性 IR、generic renderer、lexical index 与显式 knowledge-enrichment 状态；不等待外部模型即可形成一致 base candidate。
- 回放现有 archive，并用新增、修订、移动、删除、解析失败 fixture 验证保旧。
- 用 SHA-256 固定的 Q5 真实长文在隔离 acceptance source root 建立新 test-only document identity，端到端验证无专用 route/template 的标题/公式/宽表/代码/引用/locator/版本/知识展示，并与 raw Markdown 预注册任务及 legacy V39 回归对照。
- 将 publishable 与 external-AI policy 分离，证明 `private/no_external_ai` 从未构造 DeepSeek 请求。

**门禁**：legacy 页面零未授权变化；新研究无需 route/template；失败不污染 active。

### Stage 4：知识、检索与 MCP

- 实现 `deepseek-v4-pro` changed-only semantic job、受保护凭据、prompt-injection 隔离、generation version 和失败重试状态；同时绑定官方 revision evidence 与 API `model/system_fingerprint`，漂移进入隔离并要求 targeted recompile。
- 建立知识形成状态、字段级 provenance、机械/人工接受、coverage report 和关系。
- 完成 heading-aware chunk、metadata/active membership、structured lexical retrieval、增量失效与 dev/sealed holdout。
- 完成客户端本地 stdio、只读 immutable mirror、VM active identity resolver、fresh/stale/unavailable 语义、可跨项目安装 profile 和真实 tool-choice 评测；从 `D:\quant\backtest_demo` 验证隐式应调用/不应调用、search→get、activation/rollback 后重查，并与 no-MCP 对照证明研究判断净增益。

**门禁**：变更文档才调用 DeepSeek；实际 provider revision 可证且 alias/fingerprint 无未裁决漂移；失败时 base snapshot 可用且 MCP 正确返回 pending；成功后 enriched snapshot 可追溯。结构化内容不空洞，chunk/index 失效、引用/版本/条件硬门禁通过，agent 在隐式场景正确调用且相对 no-MCP 对照有可复现净增益。

### Stage 5：全局验证与 release certificate

- 全量重放、增量/幂等/DeepSeek 失败与升级、异常/回退/性能/安全回归。
- 独立 verifier 检查来源、active/prior 无环 manifest 依赖、严格两版本保留、浏览器、搜索、MCP 拓扑、state/comment 锚点和回退证据。
- 执行非空 comment 序列：写入→新代码→source 修订/移动→renderer 展示→D prior 回退→再读取，验证 stable document target、确定性重定位与 unresolved/history 可见性。
- 对最终功能完整 release 执行 active→prior→active 序列，验证 schema forward/rollback compatibility、当前 state 不倒退、对象只按两棵 closure 保留，以及第三 release/清理失败反例 fail closed。
- 检查 source、fresh installed wheel、CLI、config、schema、Windows 任务清单、runbook 引用和 VM write-set，证明不存在 D 根之外的项目存储、周期性状态副本或不属于 active/prior 合同的正式权威入口。通过后按 C→D 过渡清理合同处置旧材料并形成 release certificate。
- Vector、HTTP MCP、PostgreSQL、高级展示仅在各自触发条件成立时进入独立子决策；它们不是本版完成前置。

### Stage 6：Public→Private 最终关闭

- Stage 5 release certificate 后将 GitHub 从 Public 转为 Private。
- 重新核对实际 plan、Actions、branch/environment protection、CI、publish CLI 最小权限和 exact-SHA candidate。
- 在 Private 状态至少运行一次 CI 和一次无生产切换 candidate 演练；不得借此顺带发布新业务变更。
- 通过后形成 visibility-closure receipt，才标记整个项目完成。

**门禁**：Private 可见性没有破坏冻结、CI、传输、候选校验或权限边界；生产 active 全程不切换。

## 18. 验收标准

### 18.1 迁移与发布

- V39 关键页面、DOM、桌面/窄屏截图、公式、表格、引用、评论、Dashboard、Paper Lab 和访问门禁无未授权差异。
- 完整 PDF/图片/对象/内容库 inventory 的 path/size/hash 对齐，链接可达。
- 精确 SHA CI 与 candidate manifest 可追溯；active 目录无 `git pull`。
- `R` 不反向引用 active、`local_prior_binding` 或 receipt；binding 只指向 active/prior，activation/rollback、failure、cleanup receipt 分别指向结果 pair、原 pair + candidate、保留 pair + 精确移除目标及结果。依赖图和 hash fixture 证明无环。
- 切换失败能恢复原 active/pair；成功终态只保留 D active 与恰一 prior，C 不再成为 writer。
- active/prior 均在生产 VM exact D 根内通过 canonical path、无 reparse、manifest closure、启动和同一当前 state compatibility 验证；第三 release 或 D 根之外项目路径均使门禁失败。
- Stage 5 对最终功能完整 release 完成 active→prior→active，证明 state 不替换、不降级、评论/工作区事件不倒退；release certificate 明确不覆盖 VM、D 根、对象库或 state 整体丢失。
- Stage 5 后 Public→Private 的 CI 与无切换 candidate 演练通过。

### 18.2 内容与一致性

- 正常新增 Markdown 自动进入候选；异常进入 quarantine，不阻塞不相关文件。
- 修订产生历史版本；解析/链接/索引失败保留上一 active。
- Web/Search/MCP 在一次请求中解析同一 snapshot；默认不返回废弃版本。
- `reference/**` 原始 bytes 全量 hash 不变。
- Q5 固定 SHA 的隔离新身份 fixture 无专用 route/template 即完成解析、版本、索引和 generic 页面；预注册导航/公式/表格/代码/引用/locator/知识任务优于 raw Markdown，legacy V39 无差异。
- DeepSeek 只处理变更且获准外发的 source version；base/enriched snapshot 状态一致，请求 alias、官方 provider revision、identity evidence 和 API model/fingerprint 均可追溯；alias/revision/fingerprint 漂移不会混入旧 generation。

### 18.3 评论与状态

- 两族 comment 的 current/event/revision/actor/time 跨发布、source 修订/移动、renderer 升级和代码回退一致；document comment 绑定 stable identity，block/span 只在 exact/unique proof 下重定位，失败项在 history/unresolved 可见。
- 非 comment 的 progress/workspace 状态同样位于 release 外且不被 seed 覆盖。
- 真实空集和非空 fixture 均在 D-root candidate 隔离副本完成写入/清理与完整性验证；active state 的 integrity/foreign-key/schema/count 全通过且物理/逻辑状态不被候选改变。
- candidate 与 D prior 均兼容升级后的 SQLite schema；普通回退不降级或替换当前 state。
- 系统不存在周期性状态副本任务或状态时间点选择器；普通回退只切 active/prior 并沿用当前 D state。state 整体不可用时 fail closed，不能声称本地 prior 提供数据保护。

### 18.4 检索与 MCP

- chunk 由确定性 IR 与 source spans 稳定生成，短内容一语义 block 一 chunk，公式/表格/代码/引用不被破坏；matched exact range 与展示 context 明确分离；metadata、关系、active membership 和增量失效均绑定同一 snapshot。
- 所有正式知识条目有字段级 source locator、fact status、version 和 extractor provenance。
- qrel 绑定真实 source version/span/exact byte range/quote+source hash/适用条件并在来源修订后失效；answerable 排序指标与 no-answer accuracy 分开；dev 与 sealed holdout 隔离，关键 slice、LIKE 基线对照与硬错误门禁通过。
- 本地 stdio mirror 只有在 VM active 三元组校验一致时返回 fresh；断网、过期或身份不明返回 stale/unavailable。MCP 返回当前 release/snapshot、限制、引用和可见截断；没有写/执行工具。
- 因子、模型、数据处理、回测隐式任务中，Codex 的应调用/不应调用、search→get、snapshot 更新路由通过；MCP-assisted 相对 no-MCP 在研究判断上有可复现净增益。
- 知识增强 pending/blocked/failed 时 MCP 不复用旧版本语义知识冒充当前结果。
- `D:\quant\backtest_demo` 作为独立安装消费者通过隐式应调用/不应调用、search→get、activation/rollback 更新和版本身份验收。

## 19. 风险与缓解

- **Public 阶段代码合规风险**：可见性已固定，不再等待选择；CI 和 publish 双重门禁阻止 reference、内部研究、PDF、数据库、对象、secret 和生成状态进入 Git。
- **本地 publish 期间离线**：active 不变，candidate 可显式重放；不后台猜测完成。
- **首次 800+ MB 复制失败**：`.partial` + hash resume；只有完整 inventory 通过才重命名。
- **C/D 双写**：候选只用副本；切换时停服务、最终复制、禁用 C writer；rollback 使用 D state。
- **active/prior identity 漂移或形成第三 current**：固定 `active_release→R_active`、`local_prior_binding→R_active/R_prior`、`receipt→pair/result`；`R` 不含动态控制信息，binding 与 active 不一致时新激活/回退/清理全部 fail closed。
- **comment 仍在库但页面不可见/错挂**：stable document target、exact unique anchor mapping、history/unresolved fallback 和非空浏览器/数据库序列门禁。
- **stdio 客户端使用旧知识**：每次 current-sensitive 请求校验 VM identity；不一致或不可达返回 stale/unavailable，跨项目 profile 与 rollback trace 实测。
- **机器提取误导 agent**：字段级 span、状态分层、冲突验证；candidate 默认不参与权威推荐。
- **DeepSeek 故障或注入**：changed-only job、外发 policy、无工具隔离、严格 schema/span 验证；确定性 base snapshot 独立发布。
- **DeepSeek alias 漂移**：官方 revision evidence + per-response model/fingerprint 双绑定；身份不明先隔离，新 generation 与 targeted recompile 后才可替换。
- **VM、D 根、对象库或 state 整体丢失**：本版没有重建承诺；控制器 fail closed，release certificate 明确披露该剩余风险，不得用本地 prior 测试扩大结论。
- **只有一个 prior**：每次激活前证明 candidate 与当前 active 都兼容当前 D state；成功后严格保留新 active + 旧 active，终态清理更早版本。需要多代版本或数据保护时必须另立经用户批准的 change。
- **SQLite 升级破坏 prior**：expand/compatible/contract 与 prior 实测；普通回退沿用当前 D state。
- **评测过拟合**：sealed holdout、hard negative/no-answer、切片指标和有限放行次数。
- **工具过度拆分**：tool-choice trace 决定合并/拆分，规格不锁死数量。

## 20. 已锁定的最终选择

1. 首次兼容基线固定为现网 V39，迁移等价验收与后续功能增强分开。
2. 本版唯一生产入口为受控单命令 `publish`；不实现裸 push watcher。
3. GitHub 在 Stage 0–5 保持 Public，Stage 5 release certificate 后转 Private并完成无生产切换复验。
4. 两族 comment 与其他线上状态本版继续使用 release 外 SQLite。
5. MCP 本版只完成客户端本地 stdio；交付可跨项目安装 profile，并至少在 `quant_platform` 与 `D:\quant\backtest_demo` 两个真实消费者验收。Streamable HTTP 延后。
6. `deepseek-v4-pro` 作为 changed-only、policy-gated 的语义候选编译器；当前官方确认 revision 为 `DeepSeek-V4-Pro-0813`，但每次 generation 仍必须保存官方 identity evidence 与 API 返回身份，不能依赖 alias 永久不变。
7. 生产 VM 项目存储严格限于精确 `D:\quant\quant_platform`；生产稳态只保留 active + 恰一 prior，普通回退沿用同一当前 D state。
8. Release identity 固定为无环单向图：`active_release→R_active`、`local_prior_binding→R_active/R_prior`；activation/rollback、failure、cleanup receipt 分别只指向结果 pair、原 pair + candidate、保留 pair + 精确移除目标及结果。release manifest 不反向引用控制对象。本版不设置周期性状态副本，也不声明整机、D 根、对象库或 state 整体丢失后的重建能力。

## 21. 实施期边界与放行状态

用户已解除设计 HALT 并批准连续 apply Stage 0–6。当前允许实现、测试、Public Git/CI、
受控 VM D-root candidate 和既定验收；不允许绕过 writer fence、active/prior 同一 state
兼容、严格两版本保留或 D-root write-set 门禁。D active、C→D writer handoff、旧材料清理和
Public→Private 仍分别受 Stage 1/5/6 的机器证据约束，不能因本地测试 PASS 自动放行。

设计审核的历史证据仍保留在
`project_state/reviews/quant_platform_vm_mcp_20260820/Codex实施前针对性合同修订审核_20260821.md`；
它只证明合同当时一致，不替代当前代码、CI、VM、浏览器、SQLite、RAG/MCP 和本地回退
证据。实施状态、外部 blocker 与最新身份以 `project_state/CURRENT.md` 顶部权威表为准。
