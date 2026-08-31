# 研究员数据抓取、导入、检索与存储位置指南

> 当前放行状态（2026-08-31）：最近一次 C→exact-D writer handoff 在 D ingress 前安全失败，
> 旧 C 服务已恢复；D 侧尚无 active/prior，Stage 5 certificate 与 visibility closure 均未签发。
> 当前现场及后续变更见 [`STAGE5_STAGE6_CLOSURE.md`](STAGE5_STAGE6_CLOSURE.md)。在该记录更新前，
> 候选、历史本机 delivery、测试 PASS 和失败 handoff receipt 都不是生产放行证明。

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

普通 Markdown 论文链接只在目标主机属于以下白名单时形成候选：

```text
ssrn.com
ideas.repec.org
openreview.net
jstor.org
aclanthology.org
proceedings.mlr.press
link.springer.com
sciencedirect.com
onlinelibrary.wiley.com
academic.oup.com
```

列表符号、编号或 `[数字]` 开头且含 18xx/19xx/20xx 年份的行会形成较弱的
`formal_reference` 未解析线索；这不表示系统已经识别出作者或题名。代码围栏和
行内代码中的 DOI/arXiv 文本会被保护，不能用来形成正式论文线索。

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

前者保存 Crossref 身份核验材料，后者保存 arXiv 扩展材料。默认命令只用于
回放 2026-07-15 这批固定历史材料；它还依赖以下受审阅文件：

```text
project_state\workers\crossref_identity_review\accepted_decisions.jsonl
project_state\workers\crossref_identity_review\rights_resource_offers.jsonl
project_state\workers\independent_identity_verifier\item_verdicts.jsonl
project_state\workers\u055_open_pdf_acquisition\manifest.json
project_state\workers\arxiv_expansion_materials\manifest.json
project_state\workers\arxiv_expansion_materials\reading_records.json
project_state\workers\arxiv_expansion_materials\total_delivery_manifest.json
project_state\workers\arxiv_expansion_materials\total_resolution_seed.json
project_state\workers\arxiv_expansion_materials\identity_review\method_origin_candidate_inputs.json
project_state\workers\independent_arxiv_verifier_v2\verdict_v4.json
```

新发现的论文应先经过 Archive 线索提取、元数据核验和材料包审阅，再调用此
脚本生成导入计划；不要把下载目录或任意 PDF 目录直接塞给它。若替换为新材料，
必须同时显式传入全部适用的 source 参数：

```text
--crossref-decisions（可重复）
--crossref-rights
--crossref-identity-verdicts
--crossref-fulltext
--arxiv-materials
--arxiv-readings
--arxiv-total-delivery
--arxiv-resolution-seed
--arxiv-method-origin-inputs
--arxiv-independent-verdict
--reconciliation-overrides（若本批存在显式协调裁决）
```

并用本次真实审核信息覆盖：

```text
--review-id
--reviewed-by
--reviewed-at
--provenance-urn
```

plan 和后续 `--apply` 必须复用同一组 source 与审核身份参数。不能沿用历史默认
时间或 provenance 给新材料盖章；也不能只替换其中一个材料文件，把其余历史
默认输入误当成同一批审核。

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
$ReleaseRoot = `
  'D:\quant\quant_platform_publish_runtime\candidates\release-REPLACE_ME'
$Delivery = Join-Path $ReleaseRoot 'runtime'
$OutputRoot = `
  'D:\quant\quant_platform\quant_hub\var\paper_fetch_review_01'

if (-not (Test-Path -LiteralPath $ReleaseRoot -PathType Container)) {
  throw "请把 ReleaseRoot 改成已审阅 release：$ReleaseRoot"
}
if (-not (Test-Path -LiteralPath `
  (Join-Path $Delivery 'db\research_papers.sqlite3') -PathType Leaf)) {
  throw "release runtime 缺少 Evidence 数据库：$Delivery"
}
if (-not (Test-Path -LiteralPath `
  (Join-Path $Delivery 'research_papers') -PathType Container)) {
  throw "release runtime 缺少 research_papers 资源区：$Delivery"
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
- 复用已核验 PDF，或尝试公开的 arXiv/OpenAlex/Semantic Scholar URL，以及
  Crossref 暴露的 PDF/fulltext URL；Crossref 返回链接本身不证明 OA 或本地保存权利；
- 单次下载上限为 120 MiB，并检查 HTTP 结果、最小大小、`%PDF-` 文件头和尾部
  `%%EOF`；它不做第二次下载或内容稳定性复验；
- 输出 `ACQUISITION_MANIFEST.json`；工具自身会创建目录但不会强制它原先为空，
  所以上面的包装检查不可省略；
- 查询只要求论文身份已核验，不会用 `rights_status` 自动做下载前 fail-closed；
  因此输出只能进入受限审阅暂存，下载成功不会自动证明权利允许或 Evidence 已
  放行；
- 不得省略 `--delivery` 或 `--output`。源码默认值是历史 delivery 和正式
  Paper Lab drop，不能作为新抓取任务的安全默认目标。

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

这里的“只扫描”是指不改名、不读取正文和不建立精读任务；首次调用仍可能创建
所选 `var-root` 的运行目录和数据库。它不是文件系统零写入命令。

再做 dry run，确认将要读取的候选：

```powershell
.\quant_hub\.venv\Scripts\python.exe -B -m quant_hub.cli `
  paper-lab run `
  --project-root D:\quant\quant_platform `
  --archive-root D:\quant\quant_platform\reference\archive `
  --var-root $PaperLabVar `
  --dry-run
```

正式运行去掉 `--dry-run`，但这一步只登记 PDF、建立 `reading_run` 队列，并把
任务写到：

```text
<var_root>\paper_lab\tasks\<run_id>.json
```

命令输出的 `tasks[].manifest_path` 才是下一步 `--task` 应使用的精确路径。
它不会在该命令内自动执行 problem、method、experiment、synthesis。拿到任务
manifest 后，先检查将调用的 Codex 命令：

```powershell
$Task = Join-Path $PaperLabVar 'paper_lab\tasks\RUN_ID.json'

if (-not (Test-Path -LiteralPath $Task -PathType Leaf)) {
  throw "请用 paper-lab run 输出的真实 manifest_path 替换 RUN_ID：$Task"
}

.\quant_hub\.venv\Scripts\python.exe -B `
  .\quant_hub\tools\paper_lab_execute.py `
  --task $Task `
  --project-root D:\quant\quant_platform `
  --archive-root D:\quant\quant_platform\reference\archive `
  --var-root $PaperLabVar `
  --dry-run
```

确认后去掉 `paper_lab_execute.py` 的 `--dry-run`，才会按顺序执行四个阶段。阶段
输出先写入 `<var_root>\paper_lab\staging\<run_id>\*.json`，通过 schema、来源
locator 和状态校验后再提交到数据库。完整生命周期是：

```text
scan
→ paper-lab run --dry-run
→ paper-lab run（登记并建立 task）
→ paper_lab_execute.py --task <manifest>（四阶段执行）
→ awaiting_review
→ 按当前 reviewer key registry 验证签名的 review certificate
→ releasable
→ paper-lab publish --run-id <run_id>
```

中断后建立下一次任务使用 `paper-lab run --resume`。当前没有供普通研究员签发
review certificate 的 CLI。`PaperLabService.review_run(...)` 会验证证书是否绑定 exact
run artifact、requirements manifest，以及是否能由进程环境
`QRH_PAPER_LAB_REVIEWER_RSA_KEYS` 配置的 RSA 公钥验证；验证通过后才允许执行：

```powershell
.\quant_hub\.venv\Scripts\python.exe -B -m quant_hub.cli `
  paper-lab publish `
  --run-id RUN_ID `
  --project-root D:\quant\quant_platform `
  --archive-root D:\quant\quant_platform\reference\archive `
  --var-root $PaperLabVar
```

这里必须严格区分“代码已验证签名”和“审核者具有独立、受保护的外部身份”。当前
源码不会鉴别 `review_run` 的调用者，也不能单独证明 producer 与 reviewer 已隔离，
或 reviewer key registry 未被运行者替换。独立审核成立还需要进程环境、密钥托管、
权限分离和签发审计等外部证据；没有这些证据时，不得把上述签名验证称为独立信任根。

常用只读查询：

```powershell
.\quant_hub\.venv\Scripts\python.exe -B -m quant_hub.cli `
  paper-lab query `
  --var-root $PaperLabVar `
  --keyword transformer
```

可组合的过滤条件以 `paper-lab query --help` 为准，包括 rating、model、market、
时间、source、keyword 和 status。`paper-lab legacy-import` 只用于从只读
`reference\proj2` 做一次性、可重复迁移，不是日常投递命令。

Paper Lab 的结构化数据和生成资产分别位于：

```text
<var_root>\db\paper_lab.sqlite3
<var_root>\paper_lab\assets\
```

### 4.6 通过 Web 阅读、评论和维护进度

本地浏览可使用已审核的历史 delivery 或明确的开发模式；两者与当前生产 VM exact-D
部署接口不同。历史本机 V9/R2 命令和当前 exact-D production tooling 的边界以
[`../../quant_hub/README.md`](../../quant_hub/README.md) 及本指南第 7 节为准。约定浏览入口是：

```text
http://localhost:8765/
```

exact-D production 在业务路由之前安装访问门禁。未登录访问 `/api/*` 返回
`401 authentication_required`，访问页面则重定向到 `/login`。浏览器用户先打开
`/login` 并使用授权运维提供的访问密码；脚本必须先向 `/login` 提交表单并在后续
请求中复用同一个 cookie session。开发模式只有在明确未安装该门禁时才可省略这一步。

主要页面：

- `/`：Dashboard 和研究入口；
- `/research-updates`：研究更新时间线；
- `/research/{research_id}`：研究主页；
- `/research/{research_id}/documents/{document_id}`：研究文档；
- `/research/{research_id}/documents/{document_id}/chapters/{chapter_slug}`：研究文档章节；
- `/research/{research_id}/supplements/{supplement_id}` 与末尾 `/source`：补充材料及其受控原文；
- `/knowledge/research/{document_id}/`：通用新研究当前版；
- `/knowledge/research/{document_id}/versions/{version_id}/`：通用新研究历史版；
- `/knowledge/research/{document_id}/versions/{version_id}/source`：通用新研究受控原文；
- `/paper-lab/`、`/paper-lab/papers/{paper_id}`、`/paper-lab/designer`；
- `/evidence/`、`/evidence/papers/{paper_id}`、`/evidence/citations/{citation_id}`；
- `/evidence/library/{paper_id}.pdf`：通过受控路由打开允许展示的 PDF。

常用只读 API：

```text
GET /api/v1/session
GET /api/v1/dashboard
GET /api/v1/topics
GET /api/v1/dashboard-topics
GET /api/v1/dashboard-topics/{topic_id}
GET /api/v1/research-updates
GET /api/v1/research
GET /api/v1/search
GET /api/v1/research/{research_id}
GET /api/v1/research/{research_id}/comments
GET /api/v1/research/{research_id}/documents/{document_id}/source
GET /api/v1/archive/assets/{asset_id}

GET /api/v1/evidence/papers
GET /api/v1/evidence/papers/{paper_id}
GET /api/v1/evidence/documents/{document_sha256}/citations
GET /api/v1/evidence/citations/{citation_id}
GET /api/v1/evidence/citation-entries/{ledger_entry_id}
GET /api/v1/evidence/resources/{resource_id}

GET /api/v1/paper-lab/papers
GET /api/v1/paper-lab/papers/{paper_id}
GET /api/v1/paper-lab/versions/{paper_version_id}/content
GET /api/v1/paper-lab/notes/{note_id}/content
GET /api/v1/paper-lab/components
GET /api/v1/paper-lab/blueprints
GET /api/v1/paper-lab/blueprints/{blueprint_id}

GET /api/v1/research-tree
GET /api/v1/research-nodes/{node_id}
GET /api/v1/research-nodes/{node_id}/comments
```

常用写 API 按业务分组如下：

```text
POST   /api/v1/research/{research_id}/comments
PATCH  /api/v1/comments/{comment_id}
DELETE /api/v1/comments/{comment_id}
POST   /api/v1/research-updates/{update_id}/annotations

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
POST   /api/v1/research-nodes/{node_id}/comments
PATCH  /api/v1/research-node-comments/{comment_id}
DELETE /api/v1/research-node-comments/{comment_id}

PATCH  /api/v1/paper-lab/papers/{paper_id}
POST   /api/v1/paper-lab/blueprints/validate
POST   /api/v1/paper-lab/blueprints

POST   /knowledge/research/{document_id}/comments
```

写接口的最小请求合同如下。`actor` 均使用下文三种固定结构；“可选”表示字段可省略，
不是建议传任意额外字段。主要 Pydantic 路由会拒绝未声明字段；Paper Lab 与通用研究
调用方也应只发送表中字段。

| 接口 | JSON 主体 | 并发前置 | 成功状态 |
|---|---|---|---|
| `POST /api/v1/research-tree/sync` | `{}` | 不发 `If-Match` | `200` |
| `POST /api/v1/research-projects` | 必填 `actor,title`；可选 `description,research_question,research_content,lifecycle_status,status_note` | 不发 `If-Match` | `201` |
| `PATCH /api/v1/research-nodes/{node_id}` | `actor` 加至少一个可编辑字段：`title,description,research_question,research_content,lifecycle_status,status_note` | 先 `GET /api/v1/research-nodes/{node_id}`，原样回传响应 `ETag` | `200` |
| `POST /api/v1/research-nodes/{node_id}/comments` | `actor,content` | 不发 `If-Match` | `201` |
| `PATCH /api/v1/research-node-comments/{comment_id}` | `actor,content` | 从 `GET /api/v1/research-nodes/{node_id}/comments` 对应项取得 `etag` | `200` |
| `DELETE /api/v1/research-node-comments/{comment_id}` | `actor` | 同上 | `200` |
| `POST /api/v1/dashboard-topics` | `actor,title,state`；可选 `note,parent_topic_id,manual_order`；`state` 仅 `planned/paused` | 不发 `If-Match` | `201` |
| `PATCH /api/v1/dashboard-topics/{topic_id}` | `actor` 加至少一个 `title,state,note,parent_topic_id,manual_order` | 先 `GET /api/v1/dashboard-topics/{topic_id}`，原样回传 `ETag` | `200` |
| `DELETE /api/v1/dashboard-topics/{topic_id}` | `actor` | 同上 | `200` |
| `POST /api/v1/topics` | `actor,topic_key,title`；可选 `manual_order` | 不发 `If-Match` | `201` |
| `POST /api/v1/topics/{topic_id}/research-links` | `actor,research_id,link_kind,provenance_urn`；可选 `dashboard_primary,display_rank`；`link_kind` 仅 `primary/supporting` | 不发 `If-Match` | `200` |
| `POST /api/v1/topics/{topic_id}/state-events` | `actor,state`；可选 `note`；`state` 仅 `planned/paused` | 不发 `If-Match` | `201` |
| `POST /api/v1/research/{research_id}/work-state-events` | `actor,state`；可选 `note`；`state` 仅 `planned/in_progress/paused` | 不发 `If-Match` | `201` |
| `POST /api/v1/research/{research_id}/completion-decisions` | `decision,reason`，并且只给 `actor` 或 `review_urn` 之一；完成时给 `research_release_id`，撤销时给 `target_decision_id` | 不发 `If-Match` | `201` |
| `POST /api/v1/research/{research_id}/comments` | `actor,content`；可选严格锚点对象 `target` | 不发 `If-Match` | `201` |
| `PATCH /api/v1/comments/{comment_id}` | `actor,content` | 从 `GET /api/v1/research/{research_id}/comments` 对应项取得 `etag` | `200` |
| `DELETE /api/v1/comments/{comment_id}` | `actor` | 同上 | `200` |
| `POST /api/v1/research-updates/{update_id}/annotations` | `actor`；可选 `note` | 从 `GET /api/v1/research-updates` 对应项取得 `etag` | `201` |
| `PATCH /api/v1/paper-lab/papers/{paper_id}` | `field,value,expected_version,actor_display_name,reason` | 从 `GET /api/v1/paper-lab/papers/{paper_id}` 取整数版本；不发 `If-Match` | `200` |
| `POST /api/v1/paper-lab/blueprints/validate` | `components` 数组 | 不发 `If-Match`；只验证不保存 | `200` |
| `POST /api/v1/paper-lab/blueprints` | `name,objective,components`；可选 `blueprint_id` | 不发 `If-Match` | `201` |
| `POST /knowledge/research/{document_id}/comments` | 顶层 `actor_kind,content,version_id`；`other` 另给 `display_name`；块/区间锚点另给 `target_kind,anchor_span_id` | 不发 `If-Match` | `201` |

公共失败状态也属于调用合同：未通过生产访问门禁时 `/api/*` 为 `401`，页面型
`/knowledge/*` 会先 `302` 到登录页；非法前置条件为 `400`；
Origin/CSRF 不合法为 `403`；对象不存在为 `404`；幂等键复用到不同载荷、版本或
并发事实漂移通常为 `409`；JSON/字段校验失败为 `422`；缺少必需的
`Idempotency-Key` 或 `If-Match` 为 `428`。研究工作区不可用时可能返回 `503`。
调用方必须读取 JSON 中的 `error`/`message`，不能只按 2xx/非 2xx 猜测结果。
Archive 块／区间评论的完整 `target` 字段由
`quant_hub/src/quant_hub/web/contracts.py` 的 `CommentTargetCreate` 定义；它绑定来源版本、
source hash、byte range、exact text、结构上下文和 locator。研究员通常应让页面生成该对象，
不要手拼未核验锚点。

评论和进度写入应通过 UI 或 API，不要改 SQLite。JSON 写请求必须：

- 使用 `Content-Type: application/json`；
- 先 `GET /api/v1/session`，保留同一 session cookie；
- 携带启动器允许的精确同源 `Origin`；
- 携带返回的 `X-CSRF-Token`；
- 携带 8–128 字符的 `Idempotency-Key`；
- 普通评论、research-update annotation、Dashboard topic、research node 和 node
  comment 的并发敏感写入，
  使用对应 GET/创建响应返回的单一强 ETag 作为精确 `If-Match`；不能自行拼接
  revision，也不能使用弱 ETag 或 `*`；
- Paper Lab 论文字段更新不使用 `If-Match`，而是在 JSON 内传详情响应中的整数
  `expected_version`；版本变化时服务返回 409，客户端应重新读取后合并；
- 创建操作不得附带不适用的 `If-Match`；验证蓝图不会保存蓝图，保存必须另调
  `POST /api/v1/paper-lab/blueprints`。

通用新研究评论接口位于 `/knowledge` 前缀下，不属于 `/api/v1`。它同样要求同一
session、精确同源 `Origin`、`X-CSRF-Token` 和 `Idempotency-Key`；JSON 需给出当前
`version_id`、评论者和 `content`，只有需要块级/区间锚定时才增加受支持的
`target_kind`（`block` 或 `span`）与 `anchor_span_id`。
不要把历史页面的 `version_id` 冒充当前版，也不要自行生成锚点身份。

评论者只允许：

```json
{"actor_kind":"zhang_zhengze"}
{"actor_kind":"song_dingkun"}
{"actor_kind":"other","display_name":"实际姓名"}
```

API 没有扫描、候选构建、证书签发或 release 激活接口。这些操作不能用普通 HTTP 请求绕过。

下面是可直接复制的 PowerShell 读取与写入示例。先把 `$Base`、`$ResearchId`
和正文改成真实值；`$Base` 必须与服务启动时的 trusted origin 精确一致。示例会
交互读取访问密码，只在本进程内用于登录，不把密码写进脚本、命令历史或磁盘。

```powershell
$Base = 'http://localhost:8765'
$Query = [uri]::EscapeDataString('时序交叉验证')

# production 先建立 access-gate session；密码必须由授权运维提供。
$WebSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
$SecurePassword = Read-Host 'Quant Research Hub 访问密码' -AsSecureString
$PasswordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
try {
  $PlainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($PasswordPointer)
  Invoke-WebRequest -Method Post -Uri "$Base/login" `
    -WebSession $WebSession -Body @{ password = $PlainPassword } | Out-Null
}
finally {
  $PlainPassword = $null
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($PasswordPointer)
  $SecurePassword.Dispose()
}

# 取得业务 session/CSRF；所有后续读写始终复用同一 cookie jar。
$Session = Invoke-RestMethod -Method Get -Uri "$Base/api/v1/session" -WebSession $WebSession
$Csrf = $Session.data.csrf_token
$ResearchId = 'res_REPLACE_WITH_32_HEX'

# 只读检索不需要 CSRF 或 Idempotency-Key，但仍需要上面的 production 登录 cookie。
$Search = Invoke-RestMethod -Method Get `
  -Uri "$Base/api/v1/search?q=$Query&limit=5" -WebSession $WebSession
$Search.data

$CommentHeaders = @{
  Origin = $Base
  'X-CSRF-Token' = $Csrf
  'Idempotency-Key' = "comment-$([guid]::NewGuid().ToString('N'))"
}
$CommentBody = @{
  actor = @{ actor_kind = 'zhang_zhengze' }
  content = '请补充样本外稳定性检验。'
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method Post `
  -Uri "$Base/api/v1/research/$ResearchId/comments" `
  -WebSession $WebSession -Headers $CommentHeaders `
  -ContentType 'application/json; charset=utf-8' -Body $CommentBody

$TopicHeaders = @{
  Origin = $Base
  'X-CSRF-Token' = $Csrf
  'Idempotency-Key' = "topic-$([guid]::NewGuid().ToString('N'))"
}
$TopicBody = @{
  actor = @{ actor_kind = 'song_dingkun' }
  title = '样本外组合稳定性'
  state = 'planned'
  note = '待补充不同市场阶段的回放。'
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method Post `
  -Uri "$Base/api/v1/dashboard-topics" `
  -WebSession $WebSession -Headers $TopicHeaders `
  -ContentType 'application/json; charset=utf-8' -Body $TopicBody
```

修改或删除对象时，先用对应 GET 取回服务端 `ETag`，再把该值原样放入
`If-Match`；不要从 revision 自行拼接。同一逻辑 command 重试必须复用原
`Idempotency-Key`，只有新 command 才生成新 key。通用新研究评论的 JSON 不是上面的
nested `actor`，而是顶层 `actor_kind`、可选 `display_name`、`version_id` 和 `content`；
请严格按本节前文的 `/knowledge` 合同调用。

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
codex -C $TargetProject mcp list --json

.\.venv\Scripts\python.exe -m quant_hub.knowledge_mcp.cli doctor `
  --client-config `
  "$env:LOCALAPPDATA\QuantResearchHub\quant-research-knowledge\client.json"
```

project scope 配置位于 `$TargetProject\.codex\config.toml`，所以 `codex mcp list`
必须在目标项目语境运行；留在 `quant_hub` 目录会检查错项目。`doctor` 对 VM
authority 只读，但不是本机零写入：若发现可验证的新三元组，它可能下载知识
artifact，并原子更新本机 mirror/pointer。退出状态包括 `fresh`、`stale`、
`unavailable` 和 `transition_pending`；后者表示转换尚未完成，CLI 返回退出码 2，
不能当成 fresh。

最稳妥的检索顺序：

1. `search_quant_knowledge`：用自然语言问题搜索，并尽量给 `task_context`；
2. 只对搜索结果 `next_action` 中真正需要的 1–3 个 `object_id` 调用 `get_quant_knowledge`；
3. 快照变化时先调用 `list_knowledge_updates`，再重新执行 search → get；
4. 默认尊重 fresh/stale/unavailable/transition_pending 状态，不在无明确理由时
   设置 `allow_stale=true`。

工具参数摘要：

- `search_quant_knowledge` 必须给 `query`；可选 `task_context`、`limit`、
  `budget_chars`、`detail`、`cursor`、`allow_stale`、`include_history` 和
  `include_conflicts`。
- `get_quant_knowledge` 必须给 `object_id`；可选 `include_history`、
  `include_relations`、`budget_chars` 和 `allow_stale`。
- `list_knowledge_updates` 必须给 `from_snapshot_id`；可选 `limit`、
  `budget_chars`、`cursor` 和 `allow_stale`。

推荐 `task_context` 明确 market、frequency、data、objective、assumption。
`search` 的 `limit` 为 1–20，`get/search` 的字符预算为 500–50000；更新列表的
`limit` 为 1–200。

#### `^src`、Evidence 与 MCP 的真实数据链

完整路径是：

```text
原始 Markdown 字节
→ 原生 ^src marker 或受审阅 citation overlay
→ Evidence citation/resource 断言
→ release content/mcp_search.json
→ 本机只读 knowledge mirror
→ search_quant_knowledge 返回候选 object_id
→ get_quant_knowledge 返回 canonical source_citations
```

这里有五条不能混淆的边界：

1. `^src:{citation_id}` 是展示层定位符，不是 PDF、来源原文或“模型已经证明”的
   标记；`citation_id` 必须来自受审阅 Evidence，不能手写。
2. 本机 mirror 只保存由 release manifest 标识并按散列核验的 MCP 检索 artifact 和
   身份指针，不复制 release SQLite、Evidence PDF 或完整 source object。
3. `search_quant_knowledge` 的 snippet 只用于选择候选，不能直接充当最终证据；
   最终结论只引用 `get_quant_knowledge` 返回的 `source_citations`。
4. canonical locator 至少绑定 object、document version、source hash、span、精确
   byte range 和 citation IDs；任一身份变化都应重新 search → get。
5. overlay 只改变展示/引用投影，不改写原始 Archive Markdown 字节。找不到
   Evidence 绑定时保留待核验状态，不能把文本相似当成正式引用。

### 4.8 授权运维：真实 Codex/MCP 对照验收

这一节不是研究员日常检索命令。它供授权验收人员回答一个更严格的问题：同一组
研究任务在启用目标知识 MCP 和仅禁用该 MCP 两种条件下，是否产生可重放的质量净增益。
入口是安装后提供的 `qrh-mcp-acceptance`，源码分别位于：

```text
quant_hub/src/quant_hub/knowledge_mcp/acceptance_cli.py
quant_hub/src/quant_hub/knowledge_mcp/acceptance_contracts.py
quant_hub/src/quant_hub/knowledge_mcp/acceptance_runner.py
quant_hub/src/quant_hub/knowledge_mcp/evaluation.py
```

验收前必须先准备三份 canonical JSON 和逐 case prompt；`--evidence-root` 指向一个尚不存在、
不纳入 Git 跟踪的目录：

- preregistration：绑定 run、authority 三元组、server、model、配置散列、任务顺序、
  工具预算和三项质量 marker；
- launch config：绑定原生 Codex、目标 MCP 的完整 STDIO 配置、MCP Python/client config、
  安装包完整 inventory、工作目录、执行范围与 evidence 父目录；
- prompts manifest：把每个 `case_id` 映射到实际 prompt 文件；prompt bytes 必须与
  preregistration 中的长度和 SHA-256 完全一致。

**当前没有一键 acceptance 输入生成器。** `qrh-mcp-acceptance` 只负责验证并冻结已
准备的输入，不会替操作者推导 authority、选择 case 或发明散列。禁止从本文的
JSON 示例、单元测试 fixture 或旧 campaign 手抄字段，也不得人工填写 SHA-256、
inventory 或 Authenticode 结果。授权编排脚本必须直接调用下列实现：

- `knowledge_mcp/evaluation.py::build_acceptance_preregistration()`：由真实 prompt bytes、
  case 合同和 authority identity 生成 canonical preregistration；
- `knowledge_mcp/acceptance_contracts.py::collect_openai_authenticode()`、
  `pin_runtime_closure()` 和 `validate_real_codex_launch_config_bytes()`：采集/固定合同明确
  声明的进程输入 bytes，并验证 launch config；
- 同文件的 `build_real_codex_command()` 和 `build_real_request_material()`：从已验证
  config 生成双臂命令与 dispatch 身份；
- `knowledge_mcp/acceptance_runner.py::record_real_acceptance_inputs()`：重读上述 bytes 并以
  create-only staging 闭合整个输入根。

这些是可组合的底层 builder/validator，不是已完成的生产输入编排器。在项目
补上受审核的一键生成器之前，授权人员应把一次性编排脚本和它读取的原始
authority/prompt 一起纳入当次审核；不能把测试 `_fixture()` 当生产工具。

launch config 的 schema 是 `qrh-mcp-real-codex-launch/v2-process-provenance`，闭合字段一个也
不能增减。下面展示字段含义；正式文件必须用 UTF-8 closed canonical JSON 序列化，所有
SHA-256 和 runtime file 行都要从实际 bytes 机械生成，不能照抄占位符：

```json
{
  "schema_version": "qrh-mcp-real-codex-launch/v2-process-provenance",
  "execution_scope": "local",
  "evidence_parent": "<evidence-root的绝对父目录>",
  "codex_executable": "<OpenAI签名的原生codex.exe绝对路径>",
  "codex_executable_sha256": "<64位小写hex>",
  "codex_authenticode": {
    "status": "Valid",
    "signer_subject": "<Get-AuthenticodeSignature返回的OpenAI subject>",
    "signer_thumbprint": "<40或64位大写hex>"
  },
  "working_directory": "<实际研究或回测项目绝对路径>",
  "sandbox": "read-only",
  "timeout_seconds": 900,
  "skip_git_repo_check": false,
  "mcp_server": {
    "command": "<qrh-knowledge-mcp.exe绝对路径>",
    "command_sha256": "<64位小写hex>",
    "args": ["serve-stdio", "--client-config", "<client-config绝对路径>"],
    "cwd": "<MCP工作目录绝对路径>",
    "env": {
      "PYTHONDONTWRITEBYTECODE": "1",
      "PYTHONNOUSERSITE": "1",
      "PYTHONPATH": "<installed quant_hub package目录的父目录>",
      "PYTHONSAFEPATH": "1",
      "PYTHONUTF8": "1"
    },
    "env_vars": [],
    "enabled": true,
    "required": true,
    "enabled_tools": [
      "search_quant_knowledge",
      "get_quant_knowledge",
      "list_knowledge_updates"
    ],
    "default_tools_approval_mode": "writes",
    "startup_timeout_sec": 20,
    "tool_timeout_sec": 60,
    "client_config_path": "<同一个client-config绝对路径>",
    "client_config_sha256": "<64位小写hex>",
    "python_executable": "<launcher实际绑定的python.exe绝对路径>",
    "python_executable_sha256": "<64位小写hex>",
    "runtime_closures": [
      {
        "name": "quant_hub_package",
        "root": "<installed quant_hub package绝对目录>",
        "files": [{"relative_path": "__init__.py", "sha256": "<实际hex>"}]
      },
      {
        "name": "quant_hub_distribution",
        "root": "<quant_research_hub-*.dist-info绝对目录>",
        "files": [{"relative_path": "METADATA", "sha256": "<实际hex>"}]
      }
    ]
  }
}
```

`runtime_closures[].files` 必须列出每个**已声明 root** 下的全部文件，按 `/` 风格 UTF-8
相对路径严格递增，不能只列示例中的一行。这里的 `runtime_closures` 是合同字段名，
不等于“整个 Windows/Python 运行时已经闭合”。当前实现只 pin 并复核：原生
`codex.exe`、原生 `qrh-knowledge-mcp.exe` launcher、launcher 记录的 `python.exe`、client
config，以及 launch config 明确声明的 package roots（当前为 `quant_hub` package 和
`.dist-info`）。它**不** inventory 或证明 `PYTHONPATH` 的父目录、Python home、标准库、
DLL、`.pth`、`sitecustomize`、OS loader、PowerShell 或其他未声明的加载输入。

`codex_executable` 必须由 `shell=False` 直接启动，Windows 只接受 OpenAI Authenticode
`Valid` 的 `.exe`，不接受 `.ps1/.cmd/.bat` 或把 `sys.executable` 改名冒充 Codex。这里的
Authenticode 只核验该 `codex.exe` 的发布者签名与文件身份；它不是 campaign receipt 的
countersignature，也不表示 OpenAI 或其他独立方签发、认可了本次验收结果。MCP command
也必须是 native `qrh-knowledge-mcp.exe`，并固定上述合同范围内的 Python、client config
与声明 package roots；`PYTHONPATH` 必须指向冻结 package root 的父目录，
`PYTHONSAFEPATH/PYTHONNOUSERSITE` 必须为 `1`，`env_vars` 必须为空。这些约束减少从 cwd、
user site 或继承环境加载另一份同名包的风险，但不会把未 inventory 的父目录或 Python/OS
加载链转化为已证明事实。

`execution_scope=production_exact_d` 时，`evidence_parent` 必须机械解析到
`D:\quant\quant_platform\audit` 内；`local` 也只能写到显式父目录的直接子目录。任一路径含
symlink/junction/reparse、目标根已存在、inventory 有额外文件，都会拒绝。`timeout_seconds`
只能是 1–3600 的整数；非 Git 工作目录才把 `skip_git_repo_check` 设为 `true`，它不改变
trust 或 MCP 权限。

正式顺序固定为：

```powershell
qrh-mcp-acceptance preregister `
  --preregistration <绝对路径>\preregistration.json `
  --launch-config <绝对路径>\launch-config.json `
  --prompts-manifest <绝对路径>\prompts-manifest.json `
  --evidence-root <不纳入Git跟踪的绝对路径>\mcp-acceptance\<run_id>

qrh-mcp-acceptance run `
  --evidence-root <不纳入Git跟踪的绝对路径>\mcp-acceptance\<run_id>

qrh-mcp-acceptance verify `
  --evidence-root <不纳入Git跟踪的绝对路径>\mcp-acceptance\<run_id>
```

`preregister` 先在 sibling staging directory 以不可覆盖方式写入并 fsync 全部输入，闭合
inventory 后才 write-through 提交；`run` 对每个 case 依次运行 assisted 和 no-MCP 两臂，
使用 `shell=False` 调用真实 `codex exec --json --ignore-user-config --ignore-rules`。两臂完整
配置只能在目标 `enabled=true/false` 上不同，`required=true` 保持不变；同一份已固定的
`codex.exe` app-server 会现场读取包含 packaged/system/enterprise/project/legacy-managed 的配置层，只排除
`--ignore-user-config` 对应的 user layer；active 非 user 层引入 MCP/app/plugin 时直接失败。
Windows runner 固定并复核上一段列出的 Codex/native launcher/Python/client config/声明
package roots，以硬上限并行流式读取 stdout/stderr；对 descendant process image 的观察仅用于
诊断。当前证据不证明唯一父子进程链，也不把 descendant image、PID 或启动时间提升为
authority。`verify` 从受记录 inventory、原始 JSONL、intent/completion、prompt、config
和 ledger 重放，不相信自报 PASS。当前即使真实两臂功能测试通过，也只会得到
`REAL_CODEX_EVIDENCE_REPLAY_NON_AUTHORITATIVE`：它证明封闭回放自洽，但不是 Stage 5 资格证据。
公开 fake 或 real/fake 混用只能得到 `PUBLIC_SYNTHETIC_NON_QUALIFYING_GATE`。平台尚缺独立可信
attestation/receipt 签发方，研究员不得把上述任一磁盘 receipt 当成生产放行授权。

#### 未来 authoritative receipt 的最低合同（尚未实现）

未来若要让真实 MCP 对照验收进入 Stage 5，不能只给现有 JSON 增加一个 `signature` 字段。
最低合同必须同时满足：

1. **外部信任根。** 回执由普通仓库写权限、运行验收的用户和被测进程均不能导出、替换或
   伪造的独立信任根签发；信任根身份、密钥轮换和撤销状态可由 verifier 独立取得。
2. **256-bit nonce challenge。** verifier 为每次验收产生至少 256 bit 的密码学随机 nonce，
   challenge 绑定 run、冻结输入身份、期望签发域和有效期；签发方不得接受调用方自选的旧 nonce。
3. **域分离的 canonical signature。** 签名输入使用版本化、确定性的 canonical bytes，并以
   固定 domain separator 区分 MCP acceptance、Stage 5 certificate 与 visibility receipt；签名
   必须覆盖 nonce、subject、artifact/manifest hashes、判定、签发方身份和有效期。
4. **原子 `VerifyAndConsume`。** verifier 必须在同一个受信事务中验证签名、信任链、nonce、
   subject、有效期和撤销状态，并以 compare-and-swap（CAS）把 nonce 从“未使用”原子转换为
   “已消费”。失败、重复消费或 identity drift 一律 fail closed。
5. **防重放与 TOCTOU。** 已消费 nonce 永不再次放行；验证后到状态提交之间不得重新读取可被
   普通用户替换的 receipt/artifact。若必须跨步骤使用，后续步骤须绑定前一步的 canonical
   receipt hash 和 CAS 版本，而不是按路径重新信任文件。

在这个合同由独立受信服务或等价的受保护签发设施真实落地并通过负向测试前，现有
`campaign-receipt.json`、Authenticode 结果、self-hash、PID/process image 和本机 manifest/散列
都只能作为功能回放或诊断材料，不能单独构成 authoritative receipt。

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
| `<var_root>\db\archive.sqlite3` | 研究、版本、搜索、topic、Dashboard；自带协作表供开发 fallback/候选快照使用，生产 live 评论不是这里的 release 副本 |
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
| Paper Lab durable task | `<var_root>\paper_lab\tasks\<run_id>.json` |
| Paper Lab 阶段暂存 | `<var_root>\paper_lab\staging\<run_id>\*.json` |
| proj2 兼容只读快照 | `<var_root>\paper_lab\legacy_snapshot\**`（仅执行 legacy import 后存在，工具维护，禁止手改） |
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
D:\quant\quant_platform_publish_runtime\state\audit\*.json
D:\quant\quant_platform_publish_runtime\state\publish_state.lock
```

`semantic_jobs.sqlite3` 是已经提升的语义 authority；`publish_state.json` 记录发布
编排状态；promotion receipts 和 lock 分别闭合提升审计与单写者边界；`audit`
保存发布编排收据；`publish_state.lock` 只在运行中短暂存在。这些都是工具维护
数据，不应人工编辑或因“当前没进程”而手工删除。

配置还声明 `runtime_base` 与 `runtime_base_manifest_sha256`。它们是候选组装时
按散列核验的只读基线输入，不是 active authority、生产 state 或额外恢复根；
实际位置必须从当前外置配置读取，不能把本文示例路径写死到脚本。

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

`content\source_objects\sha256\<digest>` 没有文件扩展名是设计行为；它由
manifest 和散列解析。`reference\archive\.keep` 也不表示 release 内有一份
可编辑 Archive 副本。

release 内密封的迁移和前端运行契约位于 `runtime_contract\...`。生产 Web 启动
所需的模板、静态资源、presentation manifest 和 launcher 都由 release manifest
闭合，不应从工作树临时混搭。

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
| exact-D workspace 迁移（完整路径见下） | controller 的 6 个迁移；密封安装并纳入 inventory；禁止手改 |
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

表中 exact-D workspace 迁移的完整位置是：

```text
<VM_ROOT>\tooling\python\Lib\site-packages\quant_hub\migrations\research_workspace\*.sql
```

每个 VM release 自身仍携带上一节列出的 `runtime\db`、`runtime\objects`、
`runtime\research_papers` 和 `content\*.json`。生产服务把不可变 active release
与同一个 `<VM_ROOT>\state` 组合运行。

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

### 5.6 真实 MCP 验收证据根

验收根必须是不纳入 Git 跟踪的新空目录，由 `--evidence-root` 显式指定；它不是生产
数据库，也不进入 release。本机可使用受保护的外置目录；若在生产 VM 运行，则该目录
必须位于 `<VM_ROOT>\audit\...` 等 exact-D 根内的 ignored 路径，不能写到 D 根外或 C 盘。
Stage 5 closure 使用时，它还必须是 closure evidence root 下的相对子目录。一次已预注册
并运行的根目录包含：

```text
<evidence_root>\preregistration.json
<evidence_root>\preregistration.ledger.json
<evidence_root>\launch-config.json
<evidence_root>\input-manifest.json
<evidence_root>\cases\<case-key>.prompt.bin
<evidence_root>\dispatch\<arm-key>.intent.json
<evidence_root>\dispatch\<arm-key>.trace.jsonl
<evidence_root>\dispatch\<arm-key>.complete.json
<evidence_root>\campaign-receipt.json
```

四个顶层输入和 `cases` 在 sibling staging directory 中一次闭合后才提交；`dispatch` 保存每个
case 两臂的执行意图、原始 Codex JSONL 与完成收据；成功或完整评测失败的 real campaign 才有
v3 dispatch-replay `campaign-receipt.json`。若某臂未完成 provenance/trace 门禁，顶层改为
`campaign-failure.json`，其 authority 固定为 `PUBLIC_SYNTHETIC_NON_QUALIFYING_GATE`，不能送入
Stage 5 作为 PASS。verifier 要求目录实际文件集合与预期集合完全相等，任何日志、手工说明、
重复 receipt 或隐藏的额外文件都会使整根 non-qualifying。
这些文件都是审核证据，不能手改、补写、复用旧 run 或从 Git 提交中反推生成。

## 6. 代码和接口地图

下面是排查行为时应先看的真实实现，不必从生成文件反推规则：

| 领域 | 源码入口 |
| --- | --- |
| 路径和数据库配置 | `quant_hub/src/quant_hub/config.py` |
| Flask 应用配置与外置 state 装配 | `quant_hub/src/quant_hub/app.py` |
| 主 CLI | `quant_hub/src/quant_hub/cli.py` |
| 增量 intake 工具 | `quant_hub/tools/run_incremental_intake.py` |
| 增量编排 | `quant_hub/src/quant_hub/integration/` |
| 论文线索提取 | `quant_hub/src/quant_hub/integration/clues.py` |
| Archive 解析/引用 marker | `quant_hub/src/quant_hub/archive/markdown.py` |
| Archive 发现、原文读取与 release 目录 | `quant_hub/src/quant_hub/archive/discovery.py`、`source_reader.py` 与 `catalog.py` |
| Archive 数据库/业务服务 | `quant_hub/src/quant_hub/archive/database.py` 与 `service.py` |
| Evidence 入库/服务 | `quant_hub/src/quant_hub/evidence/` |
| Evidence provider 与权利状态 | `quant_hub/src/quant_hub/evidence/providers.py`、`resources.py` 与 `ingest.py` |
| Crossref/arXiv 受审核 manifest builder | `quant_hub/src/quant_hub/evidence/canonicalization_builders.py` |
| Evidence TXT 导出 | `quant_hub/src/quant_hub/evidence/export.py` |
| PDF 物化抓取 | `quant_hub/tools/fetch_evidence_papers.py` |
| Paper Lab 扫描 | `quant_hub/src/quant_hub/paper_lab/scanner.py` |
| Paper Lab 工作流 | `quant_hub/src/quant_hub/paper_lab/` |
| Web/API 主路由 | `quant_hub/src/quant_hub/web/routes.py` |
| 通用新研究 Web/评论路由 | `quant_hub/src/quant_hub/generic_research/web.py` |
| Evidence Web/API | `quant_hub/src/quant_hub/evidence/web.py` |
| Paper Lab Web/API | `quant_hub/src/quant_hub/paper_lab/web.py` |
| 评论/进度协作 | `quant_hub/src/quant_hub/collaboration/` |
| 评论者身份合同 | `quant_hub/src/quant_hub/archive/contracts.py` 与 `quant_hub/src/quant_hub/collaboration/service.py` |
| 研究树工作区 | `quant_hub/src/quant_hub/research_workspace/` |
| MCP CLI/stdio | `quant_hub/src/quant_hub/knowledge_mcp/` |
| MCP 安装、客户端配置与镜像协议 | `quant_hub/src/quant_hub/knowledge_mcp/install.py` 与 `mirror.py` |
| MCP stdio 工具调度/检索服务 | `quant_hub/src/quant_hub/knowledge_mcp/server.py` 与 `service.py` |
| MCP 真实对照验收 CLI | `quant_hub/src/quant_hub/knowledge_mcp/acceptance_cli.py` |
| MCP 验收输入/命令闭包 | `quant_hub/src/quant_hub/knowledge_mcp/acceptance_contracts.py` |
| MCP 验收执行与证据写入 | `quant_hub/src/quant_hub/knowledge_mcp/acceptance_runner.py` |
| MCP 验收重放与判分 | `quant_hub/src/quant_hub/knowledge_mcp/evaluation.py` |
| 发布编排入口 | `quant_hub/src/quant_hub/ops/publish.py` |
| Git 外发布配置与候选闭包 | `quant_hub/src/quant_hub/ops/publish_runtime.py` |
| 候选文件 inventory/release 组装 | `quant_hub/src/quant_hub/ops/release_builder.py` 与 `quant_hub/tools/assemble_reviewed_delivery.py` |
| writer handoff 状态机 | `quant_hub/src/quant_hub/ops/writer_handoff.py` |
| Stage 5/6 exact-D 证据闭合 | `quant_hub/src/quant_hub/ops/release_closure.py` |
| VM 部署 CLI | `quant_hub/src/quant_hub/ops/vm_deploy_cli.py` |
| VM 路径/状态实现 | `quant_hub/src/quant_hub/ops/local_deployment_persistence.py` |
| exact-D 服务装配 | `quant_hub/src/quant_hub/ops/service_entry.py` 与 `quant_hub/src/quant_hub/ops/local_exact_runtime_server.py` |
| VM 固定工具链原子更新器 | `quant_hub/tools/update_vm_tooling.py` |
| 本地审核启动器 | `quant_hub/tools/run_local.py` |

这里没有一个包办所有配置的 `AppConfig` 类。五个业务库和对象路径由
`config.py` 的 `Settings` 定义；Flask 运行配置由 `app.py` 的 `app.config` 消费；生产
exact-D 再由 `service_entry.py` 和 `local_exact_runtime_server.py` 注入并闭合
`COMMENT_DATABASE_PATH`、`RESEARCH_WORKSPACE_DATABASE_PATH`、
`GENERIC_RESEARCH_RELEASE_ROOT`、`TRUSTED_ORIGINS` 等关键值。

数据库 schema 不靠 README 口述。platform、archive、research_papers、paper_lab 和
research_workspace 以 `quant_hub/migrations/<domain>` 的迁移和对应 repository/service
代码为 authority；独立生产评论库的基础/扩展 schema authority 在
`quant_hub/src/quant_hub/collaboration/comment_store.py`。固定评论者与防冒充语义还由
`archive/contracts.py`、`collaboration/service.py` 及 archive/workspace 迁移共同强制，
不能只看裸 `comments.sqlite3` 的表约束。生产 live 评论和 Dashboard authority 是
`<VM_ROOT>\state\comments.sqlite3`，release 内 `archive.sqlite3` 的协作表不是 current state。
发布时，`runtime_contract\migrations\research_workspace\` 是 release 内的密封来源；
VM tooling updater 会逐文件核对 release manifest 后，将这 6 个文件安装到上表的
site-packages 路径，并把它们计入 `quant_hub` 整包 inventory。生产 runtime 只接受
源码树邻近布局或已安装 tooling 布局中的唯一完整一套；缺失、额外、字节变化或
两套同时出现都会拒绝继续，不能用手工复制绕过。
若 release 同时包含 `runtime_contract\code\migrations\research_workspace\`，它只是
密封源码树随附的镜像；更新器会要求它与上述正式来源逐文件一致，但不会把镜像
当成第二套生产 authority。部分合法 assembler 输出不带该镜像，正式来源仍必须完整。

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

下载成功只证明网络传输和 PDF 结构检查通过。继续检查论文身份、元数据证据、
权利状态、`resource_id`、review certificate 和 release activation。
`ACQUISITION_MANIFEST.json` 不是发布证书。

### 8.2 “新 Markdown 已放进目录，为什么首页没有？”

确认放入的是新候选 `<var_root>\inbox\research`，然后检查
`intake.status` 是否 `PASS`、Evidence 是否仍为 `waiting_external`、候选是否已
审核并激活。把文件放入 inbox 本身不会改变 active release。

### 8.3 “Paper Lab 没发现 PDF”

确认文件在 `quant_hub\paper_lab\papers` 顶层、扩展名为 `.pdf`、是普通文件、
文件头为 `%PDF-`，再看 scan 的 quarantined/rejected 原因。不要为了通过扫描而
修改散列对象或数据库行。

### 8.4 “MCP 搜不到最新结果”

先运行 `doctor`，检查状态是 fresh、stale、unavailable 还是
transition_pending；检查
`pending_transition.json`，再执行 `list_knowledge_updates` 和新的 search → get。
不要手工改 `current.json`。

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
- [`Evidence 受审阅材料导入规则`](../../quant_hub/src/quant_hub/evidence/REVIEWED_MATERIAL_IMPORT.md)：
  受审阅论文材料导入规则。
- [`../../研究修订工作区/README.md`](../../研究修订工作区/README.md)：修订工作区的原文保护和交付规则。
