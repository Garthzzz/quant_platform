# 研究员数据抓取、导入、检索与存储位置指南

> 适用对象：量化研究员、论文研究员、平台维护人员。  
> 项目根：`D:\quant\quant_platform`。  
> 本文只记录当前源码中存在的入口和路径，不包含账号、口令、密钥或其他秘密。  
> `reference/**` 与 `D:\quant\industry_demo\**` 始终只读；任何新增数据都进入可写工作区、隔离候选或生产 VM 的 exact-D 根。

## 1. 先按目标选择入口

日常工作只需要先判断自己属于哪一种情况：

| 我要做什么 | 应使用的入口 | 不应直接碰什么 |
| --- | --- | --- |
| 修改一篇已有研究的展示稿 | `研究修订工作区\**\*.md` | `reference\archive` 原文 |
| 新增一篇研究 Markdown | 新候选的 `<var_root>\inbox\research` | 当前 active delivery、生产 VM release |
| 给研究补充论文线索 | 在新 Markdown 中写 DOI、arXiv 或论文官网链接 | 不手造 `citation_id`、不直接改证据库 |
| 放入一篇外部 PDF 做深度阅读 | `quant_hub\paper_lab\papers` | `research_papers\objects` 内容寻址区 |
| 浏览研究、论文、引用、评论和进度 | Web 页面或 `/api/v1/*` | SQLite 文件本身 |
| 从回测/研究项目检索历史知识 | 本地 MCP 的 `search` → `get` | VM 文件、MCP 镜像 JSON 的手工修改 |
| 发布候选、部署或回退 | 仅授权运维按发布 runbook 执行 | 研究员日常终端、任意 C 盘路径 |

最短判断规则：

- “正在写正文”进入 Markdown 工作区或新候选 inbox；
- “正在读一篇 PDF”进入 Paper Lab；
- “正在建立研究与论文的可追溯关系”进入 Evidence 流程；
- “正在找已有结论”用 Web、API 或 MCP；
- “正在改变生产版本”属于运维，不属于研究员日常操作。

## 2. 路径符号与不可破坏边界

本文使用以下符号，避免把某次临时目录误当成固定生产路径：

| 符号 | 含义 |
| --- | --- |
| `<项目根>` | `D:\quant\quant_platform` |
| `<var_root>` | 一次隔离开发、回放或发布候选的数据根；必须由该次命令明确给出 |
| `<release_root>` | 一个已密封候选或 release 的根目录 |
| `<VM_ROOT>` | 生产 VM 唯一项目根 `D:\quant\quant_platform` |
| `<MCP_DATA_ROOT>` | 默认 `%LOCALAPPDATA%\QuantResearchHub` |
| `<MCP_MIRROR_ROOT>` | 默认 `%LOCALAPPDATA%\QuantResearchHub\knowledge-mirror` |

必须遵守：

1. 不修改、移动、重命名或格式化 `<项目根>\reference\**`。
2. 不在 `D:\quant\industry_demo` 写入本项目产物。
3. 不直接编辑任意 `.sqlite3`、对象散列文件、release manifest、active pointer 或 audit receipt。
4. 新的增量 intake 只能写入新候选 `<var_root>`；不得指向当前 active delivery。
5. 生产 VM 的任何项目写入都必须留在 `<VM_ROOT>`；不得写 VM 的 C 盘、`D:\` 或 `D:\quant` 同级/上级目录。
6. 普通版本回退只切换 active/prior 代码和数据快照，继续使用同一份当前 D state；不得用旧 SQLite 替换当前 state，也不得做 schema 降级。
7. 生产连续性只由 exact-D 的 active、恰一 prior 和二者共用的当前 D
   state 构成；当前 D state、exact-D 根或生产对象无法验证时必须停止写入并
   保留现场。D 根、对象或 state 全损不在自动恢复承诺内。

## 3. 数据从哪里来，到哪里去

```text
只读 Archive ─┐
新研究 inbox ─┼─> 增量 intake ─> Archive DB / Evidence DB / 对象 ─┐
论文线索 ─────┘                                                   │
外部 PDF ───────> Paper Lab ─> Paper Lab DB / 阅读资产 ───────────┤
评论与进度 ─────> Web/API ─> 当前可变 state ──────────────────────┤
                                                                 ├─> 候选/release
候选/release ──> VM active + prior，共用当前 D state ─────────────┤
                                                                 └─> Web/API
密封知识 artifact ─> 本机 MCP 镜像 ─> search/get/list updates
```

这里有三条不能混淆的边界：

- Markdown 原文、结构化数据库和展示/检索投影是不同数据层；
- 论文“身份已确认”“网络上能下载”“允许本地保存”是三个不同结论；
- release 内的不可变数据与 VM `state` 内的当前可变评论/研究工作区是不同生命周期。

## 4. 研究员日常操作

### 4.1 修订已有研究页面

已有研究的可写修订副本位于：

```text
D:\quant\quant_platform\研究修订工作区\**\*.md
```

操作步骤：

1. 在工作区找到目标 Markdown；不要去 `reference\archive` 修改原文。
2. 保留文件内的隐藏身份注释。它用于把修订稿稳定映射回来源研究。
3. 不修改 `研究修订工作区\_导出清单.json`；该清单由导出流程维护。
4. 保存后运行只读变更报告，确认修改目标和差异范围。
5. 把修改文件路径和变更报告交给 Codex，由 Codex 比较只读基线、审阅并进入
   正式候选流程。当前没有“一条本地命令直接发布修订稿”的接口；自动同步只
   更新管理视图，不会把工作区内容直接变成正式正文。

```powershell
Set-Location D:\quant\quant_platform

.\quant_hub\.venv\Scripts\python.exe -B `
  .\quant_hub\tools\report_research_revision_changes.py
```

只扫描指定工作区时：

```powershell
.\quant_hub\.venv\Scripts\python.exe -B `
  .\quant_hub\tools\report_research_revision_changes.py `
  --workspace D:\quant\quant_platform\研究修订工作区
```

这一步只报告差异，不会自动发布。交付前仍需进入候选构建、验证和发布流程。

### 4.2 新增一篇研究 Markdown

新研究使用增量 intake。不要把新文件塞入 `reference\archive`，也不要直接复制到 active release。

先由候选构建者选择一个新的、隔离的 `<var_root>`，创建 inbox 后，研究员再把
`.md` 或 `.markdown` 文件放入：

```text
<var_root>\inbox\research\
```

推荐的 Markdown 内容：

- 清楚的一级标题和章节标题；
- 正文中的 DOI、arXiv 标识或论文官网链接；
- 来源和推断分开书写；
- 不手写数据库 ID、对象散列或伪造 `^src` 引用 ID。

候选首次初始化只执行一次：

```powershell
Set-Location D:\quant\quant_platform

$CandidateVar = 'D:\quant\quant_platform\quant_hub\var\candidate_example_01'
$Inbox = Join-Path $CandidateVar 'inbox\research'

if (Test-Path -LiteralPath $CandidateVar) {
  throw "请改用新的候选 var-root：$CandidateVar"
}

New-Item -ItemType Directory -Path $Inbox | Out-Null

# 暂停在这里：研究员把新 .md/.markdown 放入 $Inbox。
```

投放完成后运行 intake。失败或中断时只重跑下面这一段，不重跑“首次初始化”：

```powershell
Set-Location D:\quant\quant_platform

$CandidateVar = 'D:\quant\quant_platform\quant_hub\var\candidate_example_01'
$Inbox = Join-Path $CandidateVar 'inbox\research'
$AllowedParent = [IO.Path]::GetFullPath(
  'D:\quant\quant_platform\quant_hub\var'
).TrimEnd('\') + '\'
$CandidateFull = [IO.Path]::GetFullPath($CandidateVar)

if (-not $CandidateFull.StartsWith(
  $AllowedParent,
  [StringComparison]::OrdinalIgnoreCase
)) {
  throw "候选路径不在示例受管 var 根内：$CandidateFull"
}
if (-not (Test-Path -LiteralPath $Inbox -PathType Container)) {
  throw "候选 inbox 不存在，请先执行首次初始化：$Inbox"
}

$ResearchFiles = Get-ChildItem -LiteralPath $Inbox -File |
  Where-Object { $_.Extension -in '.md', '.markdown' }
if (-not $ResearchFiles) {
  throw "inbox 中还没有研究 Markdown：$Inbox"
}

.\quant_hub\.venv\Scripts\python.exe -B `
  .\quant_hub\tools\run_incremental_intake.py `
  --project-root D:\quant\quant_platform `
  --archive-root D:\quant\quant_platform\reference\archive `
  --var-root $CandidateVar `
  --include-archive `
  --consume-evidence `
  --report "$CandidateVar\incremental_intake_report.json"
```

源码中的默认 inbox 是 `<var_root>\inbox\research`。只有实际需要从另一个隔离目录读取时才传 `--inbox-root`。

工具输出顶层分为 `intake` 和 `evidence_projection`。验收时不要只看“产生了
JSON”：

- `intake.status` 应为 `PASS`；
- `PASS` 表示没有 issue；存在 `skipped` 仍可为 `PASS`，例如已完成的显式
  Archive 映射被正常跳过；
- `PARTIAL` 只表示既有 issue、又至少成功处理了一项；
- `ERROR` 表示有 issue 且没有任何成功处理项；
- 同时检查 `intake.counts`、`intake.issues`、`intake.processed` 和
  `evidence_projection`；
- `waiting_external` 不是完成；
- `--transport-only-spool` 只冻结跨域命令，不会把 Evidence 写入冒充为已完成。

增量 intake 会建立不可变来源快照、内容寻址对象、Markdown 投影、论文线索、Archive release 和 Evidence 事件。重复执行使用相同来源身份和幂等收据，不应靠更换 key 掩盖未知结果。

### 4.3 怎样写论文线索，系统最容易识别

当前线索提取器优先识别以下形式：

```markdown
arXiv: 1706.03762
https://arxiv.org/abs/1706.03762
https://arxiv.org/pdf/1706.03762
doi:10.xxxx/xxxxx
https://doi.org/10.xxxx/xxxxx
```

论文官网、出版社或学术服务的明确论文链接，以及带作者、题名、年份的参考文献行也可形成候选线索。代码围栏和行内代码中的 DOI/arXiv 文本会被保护，不能用来形成正式论文线索。

线索只表示“需要核验”。后续 Evidence 流程才会分别核验：

1. 论文身份是否唯一且与题名/作者一致；
2. 是否存在可访问的全文；
3. 是否允许下载并作为本地 PDF 保存；
4. 论文与哪一篇研究、哪个原文位置关联；
5. 引用是否可以进入受审阅的 `^src:{citation_id}` 展示投影。

研究员不能自行编造 `cit_...`。当前原始 Archive 不要求原生带 `^src`；受审阅的 sidecar citation overlay 可以在不改原文的前提下投影引用。

### 4.4 Archive 论文清单和 PDF 抓取

Archive 论文系统与 Paper Lab 数据库相互独立。它的正式数据库是：

```text
<var_root>\db\research_papers.sqlite3
```

每次受审阅快照会生成确定性的 TXT 清单：

```text
<var_root>\research_papers\exports\research-papers-<snapshot_hash>.txt
<var_root>\research_papers\exports\research-paper-candidates-<snapshot_hash>.txt
```

第一份是正式论文资源清单，第二份保留仍待确认、待获取或有歧义的候选。不要删除“无法确认”“无法获取”“权利不允许本地保存”的记录；原因本身就是审计数据。

`import_reviewed_evidence_materials.py` 不是“给任意新论文直接入库”的通用抓取器。它默认读取工作区内两类已经过人工或代理审阅、并按工具契约整理好的材料包：

```text
D:\quant\quant_platform\project_state\workers\crossref_identity_review\
D:\quant\quant_platform\project_state\workers\arxiv_expansion_materials\
```

前者保存 Crossref 身份核验材料，后者保存 arXiv 扩展材料。新发现的论文应先经过 Archive 线索提取、元数据核验和材料包审阅，再调用此脚本生成导入计划；不要把下载目录或任意 PDF 目录直接塞给它。

受控导入的正确做法是先生成静态计划，确认后才对隔离候选应用：

```powershell
Set-Location D:\quant\quant_platform\quant_hub
$env:PYTHONPATH = 'src'
$CandidateVar = `
  'D:\quant\quant_platform\quant_hub\var\reviewed_evidence_candidate_01'

if (Test-Path -LiteralPath $CandidateVar) {
  throw "请改用新的候选 var-root：$CandidateVar"
}

.\.venv\Scripts\python.exe -B `
  .\tools\import_reviewed_evidence_materials.py `
  --var-root $CandidateVar
```

上面的默认模式不写数据库。只有经审阅的计划才可增加 `--apply`：

```powershell
.\.venv\Scripts\python.exe -B `
  .\tools\import_reviewed_evidence_materials.py `
  --var-root $CandidateVar `
  --apply
```

需要从一个已审阅 delivery 物化公开 PDF 时，运维可运行：

```powershell
Set-Location D:\quant\quant_platform
$Delivery = `
  'D:\quant\quant_platform_publish_runtime\candidates\release-REPLACE_ME'
$OutputRoot = `
  'D:\quant\quant_platform\quant_hub\var\paper_fetch_review_01'

if (-not (Test-Path -LiteralPath $Delivery -PathType Container)) {
  throw "请把 Delivery 改成已审阅 delivery：$Delivery"
}
if (Test-Path -LiteralPath $OutputRoot) {
  throw "抓取输出必须是新的不存在目录：$OutputRoot"
}

.\quant_hub\.venv\Scripts\python.exe -B `
  .\quant_hub\tools\fetch_evidence_papers.py `
  --delivery $Delivery `
  --output $OutputRoot
```

该工具：

- 读取 delivery 中的 `db\research_papers.sqlite3`；
- 复用已核验 PDF，或尝试公开的 arXiv/OpenAlex/Semantic Scholar/Crossref OA URL；
- 检查 PDF 文件头、EOF、大小和下载稳定性；
- 输出 `ACQUISITION_MANIFEST.json`；工具自身会创建目录但不会强制它原先为空，
  所以上面的包装检查不可省略；
- 不会因为“下载成功”就自动证明权利允许或 Evidence 已放行。

`$OutputRoot` 是物化/审阅暂存，不是 Evidence authority。审阅后按用途分流：

- 若用于 Archive 引用证据，当前没有供研究员直接消费该 acquisition manifest
  的通用导入命令。把 `$OutputRoot`、manifest 和审阅结论交给 Codex/授权
  Evidence 流程生成受审阅材料，再按 `resource_id` 写入对象库；不要手工复制到
  `research_papers\objects`。
- 若用于 Paper Lab 深度阅读，先确认目标 drop 中不存在同名文件，再把选中的
  普通 PDF 复制到 `quant_hub\paper_lab\papers`，随后执行 scan/dry-run。抓取
  manifest 保留在暂存目录作为审计，不参与 Paper Lab PDF 扫描。

这条网络抓取命令属于候选/运维操作，不建议研究员在日常工作目录随意运行。
正式 Evidence PDF 最终由数据库 `resource_id` 解析，保存在内容寻址路径：

```text
<var_root>\research_papers\objects\<sha前2位>\<sha第3-4位>\<sha>.pdf
```

不要手工改名、替换或删除这些散列文件。

### 4.5 把外部 PDF 放入 Paper Lab

Paper Lab 是迁移后的 proj2 论文阅读与量化架构设计系统。投递目录固定为：

```text
D:\quant\quant_platform\quant_hub\paper_lab\papers\
```

投递规则：

- 只扫描该目录顶层的 `.pdf`，不递归子目录；
- 文件必须是普通文件且以 `%PDF-` 开头；
- 不需要 sidecar，也不需要预先创建数据库 ID；
- 推荐名为 `123_Title.pdf`、`123-Title.pdf`、`YYYYMMDD_Title.pdf`；
- 其他文件名仍可被发现，但会标记为 `unrecognized` 命名；
- 不要用同名文件覆盖已处理 PDF；用新文件承载新版本。

先只扫描：

```powershell
Set-Location D:\quant\quant_platform
$PaperLabVar = `
  'D:\quant\quant_platform\quant_hub\var\paper_lab_manual_01'

if (Test-Path -LiteralPath $PaperLabVar) {
  throw "请为本次首次运行选择新的 Paper Lab var-root：$PaperLabVar"
}

.\quant_hub\.venv\Scripts\python.exe -B -m quant_hub.cli `
  paper-lab scan `
  --project-root D:\quant\quant_platform `
  --archive-root D:\quant\quant_platform\reference\archive `
  --var-root $PaperLabVar
```

再做 dry run，确认将要读取的候选：

```powershell
.\quant_hub\.venv\Scripts\python.exe -B -m quant_hub.cli `
  paper-lab run `
  --project-root D:\quant\quant_platform `
  --archive-root D:\quant\quant_platform\reference\archive `
  --var-root $PaperLabVar `
  --dry-run
```

正式运行去掉 `--dry-run`；中断恢复使用 `--resume`。流程依次形成 problem、method、experiment、synthesis 等受审阅阶段，只有独立审核凭据满足发布门禁才可 publish。

常用只读查询：

```powershell
.\quant_hub\.venv\Scripts\python.exe -B -m quant_hub.cli `
  paper-lab query `
  --var-root $PaperLabVar `
  --keyword transformer
```

可组合的过滤条件以 `paper-lab query --help` 为准，包括 rating、model、market、时间、source、keyword 和 status。`paper-lab legacy-import` 只用于从只读 `reference\proj2` 做一次性、可重复迁移，不是日常投递命令。

Paper Lab 的结构化数据和生成资产分别位于：

```text
<var_root>\db\paper_lab.sqlite3
<var_root>\paper_lab\assets\
```

### 4.6 通过 Web 阅读、评论和维护进度

本地正式浏览入口使用已审核 delivery；启动命令和 exact seal 参数以 [`../../quant_hub/README.md`](../../quant_hub/README.md) 为准。正式约定入口是：

```text
http://localhost:8765/
```

主要页面：

- `/`：Dashboard 和研究入口；
- `/research-updates`：研究更新时间线；
- `/research/{research_id}`：研究主页；
- `/research/{research_id}/documents/{document_id}`：研究文档；
- `/paper-lab/`、`/paper-lab/papers/{paper_id}`、`/paper-lab/designer`；
- `/evidence/`、`/evidence/papers/{paper_id}`、`/evidence/citations/{citation_id}`；
- `/evidence/library/{paper_id}.pdf`：通过受控路由打开允许展示的 PDF。

常用只读 API：

```text
GET /api/v1/session
GET /api/v1/dashboard
GET /api/v1/topics
GET /api/v1/research
GET /api/v1/search
GET /api/v1/research/{research_id}
GET /api/v1/research/{research_id}/comments
GET /api/v1/research/{research_id}/documents/{document_id}/source

GET /api/v1/evidence/papers
GET /api/v1/evidence/papers/{paper_id}
GET /api/v1/evidence/documents/{document_sha256}/citations
GET /api/v1/evidence/citations/{citation_id}
GET /api/v1/evidence/resources/{resource_id}

GET /api/v1/paper-lab/papers
GET /api/v1/paper-lab/papers/{paper_id}
GET /api/v1/paper-lab/components
GET /api/v1/paper-lab/blueprints

GET /api/v1/research-tree
GET /api/v1/research-nodes/{node_id}
```

常用写 API 按业务分组如下：

```text
POST   /api/v1/research/{research_id}/comments
PATCH  /api/v1/comments/{comment_id}
DELETE /api/v1/comments/{comment_id}

POST   /api/v1/dashboard-topics
PATCH  /api/v1/dashboard-topics/{topic_id}
DELETE /api/v1/dashboard-topics/{topic_id}
POST   /api/v1/topics
POST   /api/v1/topics/{topic_id}/research-links
POST   /api/v1/topics/{topic_id}/state-events
POST   /api/v1/research/{research_id}/work-state-events
POST   /api/v1/research/{research_id}/completion-decisions

POST   /api/v1/research-tree/sync
POST   /api/v1/research-projects
PATCH  /api/v1/research-nodes/{node_id}
GET    /api/v1/research-nodes/{node_id}/comments
POST   /api/v1/research-nodes/{node_id}/comments
PATCH  /api/v1/research-node-comments/{comment_id}
DELETE /api/v1/research-node-comments/{comment_id}
```

评论和进度写入应通过 UI 或 API，不要改 SQLite。JSON 写请求必须：

- 使用 `Content-Type: application/json`；
- 先 `GET /api/v1/session`，保留同一 session cookie；
- 携带启动器允许的精确同源 `Origin`；
- 携带返回的 `X-CSRF-Token`；
- 携带 8–128 字符的 `Idempotency-Key`；
- 修改/删除评论时使用服务端返回的单一强 ETag 作为精确 `If-Match`；不能
  自行拼接 revision，也不能使用弱 ETag 或 `*`。

评论者只允许：

```json
{"actor_kind":"zhang_zhengze"}
{"actor_kind":"song_dingkun"}
{"actor_kind":"other","display_name":"实际姓名"}
```

API 没有扫描、候选构建、证书签发或 release 激活接口。这些操作不能用普通 HTTP 请求绕过。

### 4.7 在其他项目中安装和使用知识 MCP

MCP 是本机 stdio 服务，不是 HTTP 端口，也不直接打开 VM SQLite。完整操作见 [`KNOWLEDGE_MCP.md`](KNOWLEDGE_MCP.md)。

安装到一个研究/回测项目：

```powershell
Set-Location D:\quant\quant_platform\quant_hub

$TargetProject = 'D:\quant\backtest_demo'  # 替换为实际存在的研究/回测项目根
if (-not (Test-Path -LiteralPath $TargetProject -PathType Container)) {
  throw "目标项目根不存在：$TargetProject"
}

.\.venv\Scripts\python.exe -m quant_hub.knowledge_mcp.cli install `
  --scope project `
  --profile-root "$env:USERPROFILE\.codex" `
  --project-root $TargetProject `
  --data-root "$env:LOCALAPPDATA\QuantResearchHub" `
  --mirror-root "$env:LOCALAPPDATA\QuantResearchHub\knowledge-mirror" `
  --authority-mode openssh `
  --ssh-alias honghu-vm
```

这里的 SSH alias 只是本机 OpenSSH 配置中的别名；不要把密码、私钥内容或 token 写进仓库、客户端 JSON 或本文档。

安装后检查：

```powershell
codex mcp list

.\.venv\Scripts\python.exe -m quant_hub.knowledge_mcp.cli doctor `
  --client-config `
  "$env:LOCALAPPDATA\QuantResearchHub\quant-research-knowledge\client.json"
```

最稳妥的检索顺序：

1. `search_quant_knowledge`：用自然语言问题搜索，并尽量给 `task_context`；
2. 只对搜索结果 `next_action` 中真正需要的 1–3 个 `object_id` 调用 `get_quant_knowledge`；
3. 快照变化时先调用 `list_knowledge_updates`，再重新执行 search → get；
4. 默认尊重 fresh/stale/unavailable 状态，不在无明确理由时设置 `allow_stale=true`。

工具参数摘要：

- `search_quant_knowledge` 必须给 `query`；可选 `task_context`、`limit`、
  `budget_chars`、`detail`、`cursor`、`allow_stale`、`include_history` 和
  `include_conflicts`。
- `get_quant_knowledge` 必须给 `object_id`；可选 `include_history`、
  `include_relations`、`budget_chars` 和 `allow_stale`。
- `list_knowledge_updates` 必须给 `from_snapshot_id`；可选 `limit`、
  `budget_chars`、`cursor` 和 `allow_stale`。

推荐 `task_context` 明确 market、frequency、data、objective、assumption。`search` 的 `limit` 为 1–20，`get/search` 的字符预算为 500–50000；更新列表的 `limit` 为 1–200。

## 5. 所有数据库与数据文件在哪里

### 5.1 源码态和人工可写源

| 类型 | 规范路径 | 权限/用途 |
| --- | --- | --- |
| 原始 Archive Markdown | `<项目根>\reference\archive\**\*.md` | 永久只读、正文逐字节保护 |
| 原 proj2 | `<项目根>\reference\proj2\**` | 只读迁移来源 |
| 已有研究修订稿 | `<项目根>\研究修订工作区\**\*.md` | 研究员可写，不自动发布 |
| 修订导出清单 | `<项目根>\研究修订工作区\_导出清单.json` | 工具维护，人工勿改 |
| 新研究 inbox | `<var_root>\inbox\research\*.md` 或 `*.markdown` | 新候选输入 |
| Paper Lab PDF drop | `<项目根>\quant_hub\paper_lab\papers\*.pdf` | 顶层投递入口 |
| 抓取物化清单 | `<抓取输出>\ACQUISITION_MANIFEST.json` | 一次抓取的来源/结果审计 |

源码配置、schema 和迁移位于：

```text
<项目根>\quant_hub\src\quant_hub\
<项目根>\quant_hub\migrations\platform\
<项目根>\quant_hub\migrations\archive\
<项目根>\quant_hub\migrations\research_papers\
<项目根>\quant_hub\migrations\paper_lab\
<项目根>\quant_hub\migrations\research_workspace\
```

### 5.2 本地开发/候选运行态

规范 `<var_root>` 下有五个相互隔离的业务数据库。前四个会进入正式
release 的 `runtime\db`；第五个是开发/候选研究工作区库，正式发布时以
外置 state seed 和生产 state 的形式续存：

| SQLite | 负责什么 |
| --- | --- |
| `<var_root>\db\platform.sqlite3` | 对象、来源、pipeline、候选、审核、outbox |
| `<var_root>\db\archive.sqlite3` | 研究、版本、搜索、topic、Dashboard、评论投影 |
| `<var_root>\db\research_papers.sqlite3` | Archive 论文、线索、元数据、获取、权利、引用 |
| `<var_root>\db\paper_lab.sqlite3` | 外部论文阅读、笔记、阶段、审核、架构蓝图 |
| `<var_root>\db\research_workspace.sqlite3` | 研究树、状态、观察、评论和历史 |

其他运行数据：

| 数据类型 | 规范路径 |
| --- | --- |
| 通用内容寻址对象 | `<var_root>\objects\<2>\<2>\<sha>.blob` |
| Evidence PDF | `<var_root>\research_papers\objects\<2>\<2>\<sha>.pdf` |
| Evidence TXT 清单 | `<var_root>\research_papers\exports\*.txt` |
| Paper Lab 资产 | `<var_root>\paper_lab\assets\**` |
| 增量来源视图 | `<var_root>\integration\source_views\**` |
| 跨域 Evidence 命令 | `<var_root>\integration\evidence_commands\**` |
| 回放证据 | `<var_root>\replay\evidence\**` |
| 更新时间线 | `<var_root>\exports\research_update_history.jsonl` |

源码仓库还存在开发启动器使用的本地可变状态：

```text
<项目根>\quant_hub\data\comments.sqlite3
<项目根>\quant_hub\data\research_workspace.sqlite3
<项目根>\quant_hub\data\backups\**
```

这些是本地开发/历史备份位置，不是 release 成员，也不是生产 authority。运行中可能出现 SQLite 自己维护的 `-wal`、`-shm`；不要在服务运行时复制其中一个文件冒充一致快照。

语义编译工作区是 Git 外置、受保护的运维目录，由命令的 `--workspace-root` 明确指定：

```text
<semantic_workspace>\semantic_jobs.sqlite3
<semantic_workspace>\semantic_cli_audit.jsonl
```

它不应存放在不可变 release 内；密钥也不应写入该目录。语义编译的运维流程见 [`KNOWLEDGE_COMPILATION.md`](KNOWLEDGE_COMPILATION.md)。

### 5.3 publish candidate / release 态

正式 candidate 或 release 是不可变闭包。路径由外置发布配置决定，不要把某次临时 R0 目录写死为长期约定。当前配置文件位置是：

```text
D:\quant\quant_platform_publish_runtime\production_publish_runtime.json
```

本机发布的可变工作根由该配置声明；当前约定分类为：

```text
D:\quant\quant_platform_publish_runtime\state\
D:\quant\quant_platform_publish_runtime\candidates\
```

发布编译还只读消费外置 state 中已经提升的语义 authority：

```text
D:\quant\quant_platform_publish_runtime\state\semantic_jobs.sqlite3
D:\quant\quant_platform_publish_runtime\state\publish_state.json
D:\quant\quant_platform_publish_runtime\state\semantic_promotion_receipts\
D:\quant\quant_platform_publish_runtime\state\.semantic_authority_promotion.lock
```

`semantic_jobs.sqlite3` 是已经提升的语义 authority；`publish_state.json` 记录发布
编排状态；promotion receipts 和 lock 分别闭合提升审计与单写者边界。这些都是
工具维护数据，不应人工编辑。

具体 state/candidate 根仍以外置配置的解析结果为准；不要仅凭本文路径把某个
临时候选当成 authority。

一个 `<release_root>` 内应能看到：

```text
release_manifest.json
deployment_manifest.json
content\
persistent_seed\
runtime\
runtime_contract\
quant_hub\
reference\archive\.keep
研究修订工作区\
```

关键 release 数据：

| 数据 | release 内路径 |
| --- | --- |
| 四个运行库 | `runtime\db\{platform,archive,research_papers,paper_lab}.sqlite3` |
| 通用对象 | `runtime\objects\<2>\<2>\<sha>.blob` |
| Evidence PDF | `runtime\research_papers\objects\<2>\<2>\<sha>.pdf` |
| Evidence TXT 清单 | `runtime\research_papers\exports\*.txt` |
| Evidence 总门禁收据 | `runtime\research_papers\exports\reviewed_total_gate_receipt.json` |
| Paper Lab 数据 | `runtime\paper_lab\**` |
| proj2 兼容结构数据 | `runtime\paper_lab\legacy_snapshot\data\*.json` |
| proj2 兼容研究结果 | `runtime\paper_lab\legacy_snapshot\research\json\*.json` |
| release 携带的 PDF drop | `quant_hub\paper_lab\papers\*.pdf` 与 `ACQUISITION_MANIFEST.json` |
| 更新时间线 | `runtime\exports\research_update_history.jsonl` |
| 工作区初始种子 | `persistent_seed\research_workspace.sqlite3` |
| 确定性快照 | `content\deterministic_snapshot.json` |
| 通用知识 artifact | `content\generic_knowledge.json` |
| MCP 搜索 artifact | `content\mcp_search.json` |
| 发布来源 authority | `content\publish_source_authorities.json` |
| 来源对象索引 | `content\source_objects.json` |
| 来源对象正文 | `content\source_objects\sha256\<digest>` |

部署闭包还含 `COPY_MANIFEST.txt`、`README_部署说明.md`、
`runtime_contract\migrations\**`，以及
`runtime_contract\code\src\quant_hub\presentation\` 下的展示 JSON；后者明确包括：

```text
archive_presentation.json
citation_projection_overrides.json
evidence_zh_overlays.json
research_supplements.json
chapter_manifests\**\*.json
```

它们是密封的 schema/展示契约，不是研究员可编辑正文。

`content\source_objects\sha256\<digest>` 没有文件扩展名是设计行为；它由 manifest 和散列解析。`reference\archive\.keep` 也不表示 release 内有一份可编辑 Archive 副本。

release 内密封的迁移和前端运行契约位于 `runtime_contract\...`。生产 Web 启动所需的模板、静态资源、presentation manifest 和 launcher 都由 release manifest 闭合，不应从工作树临时混搭。

### 5.4 VM 生产态：exact-D active/prior/state/audit

生产唯一根：

```text
<VM_ROOT> = D:\quant\quant_platform
```

目录角色：

| 路径 | 角色 |
| --- | --- |
| `<VM_ROOT>\releases\<release_id>\` | 不可变 release；终态只保留 active 和恰一 prior |
| `<VM_ROOT>\incoming\<release_id>.partial\` | 上传/校验暂存；终态必须清理 |
| `<VM_ROOT>\control\active_release.json` | 唯一当前 active 指针 |
| `<VM_ROOT>\control\local_prior_binding.json` | active/prior 对绑定；不是第二 active 指针 |
| `<VM_ROOT>\control\deployment_runtime.json` | 服务监听、release 相对路径、外置 state 和 writer authority 的封闭启动契约 |
| `<VM_ROOT>\control\service_install_candidate.json` | 服务安装候选证据 |
| `<VM_ROOT>\control\exact_runtime_tooling.json` | 固定工具链身份 |
| `<VM_ROOT>\control\tooling_update_pending.json` | 工具链更新的短生命周期 journal；仅由 tooling updater 创建和维护，成功收尾后清理，禁止手工编辑或删除 |
| `<VM_ROOT>\control\writer_handoff_pending.json` | handoff 进行中的受控 journal；只由 handoff 工具维护 |
| `<VM_ROOT>\control\writer-handoff-intents\*.json` | writer handoff 意图 |
| `<VM_ROOT>\state\comments.sqlite3` | 当前生产评论与 Dashboard 外置状态 |
| `<VM_ROOT>\state\research_workspace.sqlite3` | 当前研究树/观察/协作状态 |
| `<VM_ROOT>\state\viewer_access_password.digest` | 访问口令的单向摘要；不得复制、替换或反推原口令 |
| `<VM_ROOT>\state\viewer_secret.key` | Flask session 密钥；敏感受控文件，禁止读取、复制或写入文档/日志 |
| `<VM_ROOT>\state\writer_lease.json` | 当前 writer lease 身份记录；工具维护 |
| `<VM_ROOT>\state\writer_authority.lock` | writer 单持有者锁；不得手工删除或占用 |
| `<VM_ROOT>\state\service\child.json` | Windows 服务当前子进程生命周期记录；服务维护 |
| `<VM_ROOT>\audit\deployment_attempts\` | 部署尝试日志/证据 |
| `<VM_ROOT>\audit\receipts\` | 幂等和部署收据 |
| `<VM_ROOT>\audit\events\` | 生产事件审计 |
| `<VM_ROOT>\locks\local_deployment.lock` | 单写者部署锁 |
| `<VM_ROOT>\logs\` | 服务与运维日志 |
| `<VM_ROOT>\tmp\` | 受边界检查的临时目录 |
| `<VM_ROOT>\tooling\python\` | exact-D 固定 Python 和 `quant_hub` 包 |
| `<VM_ROOT>\objects\` | 历史/运维声明的 D 根对象区；当前服务读取 release 内的 `runtime\objects`，两处均不得手工修改 |

每个 VM release 自身仍携带上一节列出的 `runtime\db`、`runtime\objects`、`runtime\research_papers` 和 `content\*.json`。生产服务把不可变 active release 与同一个 `<VM_ROOT>\state` 组合运行。

生产连续性只以 exact-D 的 active、恰一 prior 和二者共用的当前 D state 为
准。VM 现有 `C:\quant_platform`、`C:\quant_platform_data` 及其服务在 writer
handoff 门禁前仅可只读核验；local prior binding 和 audit receipt 也只是绑定/
审计证据，不能单独授权启动或替换当前 state。

### 5.5 MCP 客户端本地态

默认客户端配置：

```text
%LOCALAPPDATA%\QuantResearchHub\quant-research-knowledge\client.json
```

默认镜像：

```text
%LOCALAPPDATA%\QuantResearchHub\knowledge-mirror\current.json
%LOCALAPPDATA%\QuantResearchHub\knowledge-mirror\acknowledged.json
%LOCALAPPDATA%\QuantResearchHub\knowledge-mirror\pending_transition.json
%LOCALAPPDATA%\QuantResearchHub\knowledge-mirror\.mirror.lock
%LOCALAPPDATA%\QuantResearchHub\knowledge-mirror\releases\<manifest_sha256>\release_manifest.json
%LOCALAPPDATA%\QuantResearchHub\knowledge-mirror\releases\<manifest_sha256>\content\mcp_search.json
%LOCALAPPDATA%\QuantResearchHub\knowledge-mirror\releases\<manifest_sha256>\mirror.json
```

project scope 安装会管理目标项目的：

```text
<目标项目>\.codex\config.toml
<目标项目>\AGENTS.md
```

user scope 才会管理：

```text
%USERPROFILE%\.codex\config.toml
%USERPROFILE%\.codex\AGENTS.md
```

镜像文件由 MCP 更新协议维护。不要手工把旧 `current.json` 指向一个未确认 release，也不要编辑 `mcp_search.json` 伪造 freshness。

## 6. 代码和接口地图

下面是排查行为时应先看的真实实现，不必从生成文件反推规则：

| 领域 | 源码入口 |
| --- | --- |
| 路径和数据库配置 | `quant_hub/src/quant_hub/config.py` |
| 主 CLI | `quant_hub/src/quant_hub/cli.py` |
| 增量 intake 工具 | `quant_hub/tools/run_incremental_intake.py` |
| 增量编排 | `quant_hub/src/quant_hub/integration/` |
| 论文线索提取 | `quant_hub/src/quant_hub/integration/clues.py` |
| Archive 解析/引用 marker | `quant_hub/src/quant_hub/archive/markdown.py` |
| Evidence 入库/服务 | `quant_hub/src/quant_hub/evidence/` |
| Evidence TXT 导出 | `quant_hub/src/quant_hub/evidence/export.py` |
| PDF 物化抓取 | `quant_hub/tools/fetch_evidence_papers.py` |
| Paper Lab 扫描 | `quant_hub/src/quant_hub/paper_lab/scanner.py` |
| Paper Lab 工作流 | `quant_hub/src/quant_hub/paper_lab/` |
| Web/API 主路由 | `quant_hub/src/quant_hub/web/routes.py` |
| Evidence Web/API | `quant_hub/src/quant_hub/evidence/web.py` |
| Paper Lab Web/API | `quant_hub/src/quant_hub/paper_lab/web.py` |
| 评论/进度协作 | `quant_hub/src/quant_hub/collaboration/` |
| 研究树工作区 | `quant_hub/src/quant_hub/research_workspace/` |
| MCP CLI/stdio | `quant_hub/src/quant_hub/knowledge_mcp/` |
| 发布器 | `quant_hub/src/quant_hub/ops/publish.py` |
| VM 部署 CLI | `quant_hub/src/quant_hub/ops/vm_deploy_cli.py` |
| VM 路径/状态实现 | `quant_hub/src/quant_hub/ops/local_deployment_persistence.py` |
| 本地审核启动器 | `quant_hub/tools/run_local.py` |

数据库 schema 不靠 README 口述；最终 authority 是 `quant_hub/migrations/<domain>` 中的迁移和对应 repository/service 代码。

## 7. 仅限授权运维：发布、激活和回退

研究员通常不需要执行本节命令。这里保留接口是为了让路径、候选和生产状态可解释，不是鼓励绕过门禁。

发布前的只读 dry run：

```powershell
Set-Location D:\quant\quant_platform
$CommitSha = (& git rev-parse HEAD).Trim()

if ($CommitSha -notmatch '^[0-9a-f]{40}$') {
  throw "无法取得精确的 40 位 Git commit SHA"
}

.\quant_hub\.venv\Scripts\qrh-publish.exe `
  --project-root D:\quant\quant_platform `
  --commit-sha $CommitSha `
  --dry-run `
  --candidate-only
```

真实候选构建必须显式使用 Git 外置配置：

```powershell
.\quant_hub\.venv\Scripts\qrh-publish.exe `
  --project-root D:\quant\quant_platform `
  --commit-sha $CommitSha `
  --config `
  D:\quant\quant_platform_publish_runtime\production_publish_runtime.json `
  --candidate-only
```

去掉 `--candidate-only` 才允许进入激活流程；发布器会执行源码/测试门禁、候选冻结、精确提交核验、增量 transport 和 VM 部署，不允许把当前脏工作树直接当作 production artifact。

VM 内部部署接口由发布器调用，固定 Python 为：

```text
D:\quant\quant_platform\tooling\python\python.exe
```

普通版本回退的受控接口是：

```powershell
$AttemptId = 'rollback-' + [guid]::NewGuid().ToString('N')

D:\quant\quant_platform\tooling\python\python.exe -B `
  -m quant_hub.ops.vm_deploy_cli rollback-prior `
  --vm-root D:\quant\quant_platform `
  --deployment-attempt-id $AttemptId `
  --json
```

回退前必须机械确认 active/prior 绑定、manifest、当前 state、锁和服务状态。
回退后仍沿用同一个 `D:\quant\quant_platform\state`。更完整的 writer
handoff、固定工具链更新和失败处置见 [`WRITER_HANDOFF.md`](WRITER_HANDOFF.md)。

## 8. 常见误区和快速排障

### 8.1 “PDF 已经下载，为什么论文还不是正式状态？”

下载成功只证明网络传输和 PDF 结构检查通过。继续检查论文身份、元数据证据、权利状态、`resource_id`、review certificate 和 release activation。`ACQUISITION_MANIFEST.json` 不是发布证书。

### 8.2 “新 Markdown 已放进目录，为什么首页没有？”

确认放入的是新候选 `<var_root>\inbox\research`，然后检查
`intake.status` 是否 `PASS`、Evidence 是否仍为 `waiting_external`、候选是否已
审核并激活。把文件放入 inbox 本身不会改变 active release。

### 8.3 “Paper Lab 没发现 PDF”

确认文件在 `quant_hub\paper_lab\papers` 顶层、扩展名为 `.pdf`、是普通文件、文件头为 `%PDF-`，再看 scan 的 quarantined/rejected 原因。不要为了通过扫描而修改散列对象或数据库行。

### 8.4 “MCP 搜不到最新结果”

先运行 `doctor`，检查状态是 fresh、stale 还是 unavailable；检查 `pending_transition.json`，再执行 `list_knowledge_updates` 和新的 search → get。不要手工改 `current.json`。

### 8.5 “Web 写请求返回 403/409”

- 403：通常检查 session cookie、Origin、CSRF token；
- 409：检查幂等键结果、对象 revision 和 `If-Match`；
- 不要通过直接编辑 SQLite 绕过并发控制。

### 8.6 “VM active 不可判定，怎样处理？”

先停止写入、保留现场并核对 `control\active_release.json`、local prior
binding、release manifest、audit receipts 和当前 D state。只有完整通过 exact-D
门禁的 active/prior 对可以参与普通回退；无法闭合就记录 blocker，不做就地重建。

## 9. 每次交付前的研究员检查表

- [ ] 没有修改 `reference\archive` 或 `reference\proj2`。
- [ ] 既有修订保留隐藏身份注释，且未修改 `_导出清单.json`。
- [ ] 新研究位于新候选 inbox，未写 active delivery。
- [ ] 论文标识来自可核验 DOI/arXiv/官方链接，没有编造作者、机构、时间或 `citation_id`。
- [ ] Paper Lab PDF 位于顶层 drop，scan/dry-run 结果已阅读。
- [ ] `intake.status`、counts、issues、processed 和外部等待状态均已检查。
- [ ] PDF 的身份、可访问性和本地保存权利分别有结论。
- [ ] 评论和 Dashboard 通过 UI/API 写入，没有直接改 SQLite。
- [ ] 发布候选、release、生产 state 和 MCP 镜像没有人工拼接或手改。
- [ ] 文档、命令输出和截图中没有秘密。

## 10. 延伸文档

- [`../../quant_hub/README.md`](../../quant_hub/README.md)：CLI、Web/API、回放和本地启动总入口。
- [`KNOWLEDGE_MCP.md`](KNOWLEDGE_MCP.md)：MCP 安装、doctor、同步和故障处置。
- [`KNOWLEDGE_COMPILATION.md`](KNOWLEDGE_COMPILATION.md)：语义编译候选、人工复核和放行。
- [`WRITER_HANDOFF.md`](WRITER_HANDOFF.md)：exact-D writer handoff、固定工具链和回退边界。
- [`../../quant_hub/src/quant_hub/evidence/REVIEWED_MATERIAL_IMPORT.md`](../../quant_hub/src/quant_hub/evidence/REVIEWED_MATERIAL_IMPORT.md)：受审阅论文材料导入规则。
- [`../../研究修订工作区/README.md`](../../研究修订工作区/README.md)：修订工作区的原文保护和交付规则。
