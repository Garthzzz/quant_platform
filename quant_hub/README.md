# Quant Research Hub

这里是统一量化研究平台的正式可写实现区。正式系统包含 Archive 研究主体、独立 Research Evidence 论文证据库，以及迁移后的外部论文精读与架构设计系统 Paper Lab。`spikes/` 只保留技术实测；正式代码位于 `src/quant_hub/`。

> 当前放行状态（2026-08-31）：最近一次 C→exact-D writer handoff 在 D ingress 前安全失败，
> 旧 C 服务已恢复；D 侧尚无 active/prior，Stage 5 certificate 与 visibility closure 均未签发。
> 这不是可忽略的版本差异。当前现场与后续更新以
> [`Stage 5 / Stage 6 exact-D 生产闭合记录`](../docs/runbooks/STAGE5_STAGE6_CLOSURE.md) 为准；在该记录更新前，
> 不得把候选、历史本机 delivery 或单元测试 PASS 宣称为生产放行。

## 研究员数据抓取与存储指南

研究员需要新增研究、抓取论文、运行 Paper Lab、调用 Web/API 或 MCP，以及定位全部数据库和数据文件时，统一从独立章节
[`研究员数据抓取、导入、检索与存储位置指南`](../docs/runbooks/RESEARCHER_DATA_GUIDE.md)
开始；该指南把日常操作与仅限授权运维的发布、VM 和回退接口明确分开。

## 写入边界与运行布局

- `reference/**` 是只读来源，程序只读取并登记原始字节，不在其中写 sidecar、元数据或渲染结果。
- `D:\quant\industry_demo/**` 只作参考，不是本程序的运行目录。
- 开发与候选业务的可变状态必须位于项目内、`reference/**` 外且显式选择的
  `--var-root`。发布编排的 state/candidates 由 Git 外置配置声明；VM 生产写入则
  只能位于 exact `D:\quant\quant_platform`，两者都不能借此写入参考区。
- `${var_root}/db/platform.sqlite3` 保存对象、来源、运行和 release authority；`${var_root}/db/archive.sqlite3` 保存 Archive 研究、release、Dashboard，以及开发/候选环境使用的协作 fallback。生产 live 评论与 Dashboard 可变状态位于 exact-D 外置 `state/comments.sqlite3`，不能把 release 内 Archive 协作表当成 current authority。两库物理隔离，但一次 release 消费会交叉核对身份。
- `${var_root}/objects/` 保存内容寻址的不可变原始字节和派生对象。两库与对象区共同构成一个一致性状态单元，不得拆分改写或独立切换。
- `${var_root}/db/research_papers.sqlite3` 与 `${var_root}/db/paper_lab.sqlite3` 分别保存 Archive 论文证据和外部论文精读，两者不与 Archive 业务表混库。
- `${var_root}/db/research_workspace.sqlite3` 保存研究树、观察、评论和状态历史；正式发布以 seed 进入 exact-D 外置 current state。五库、对象、PDF、导出、候选、release、VM state 与 MCP 镜像的完整位置表见上方独立研究员指南。

以下变量和 CLI 示例只用于开发、验证或构建新的候选，不是 active delivery 的正式启动命令。命令从 `D:\quant\quant_platform` 运行，要求 Python 3.13 及 `pyproject.toml` 中的依赖已经安装：

```powershell
Set-Location D:\quant\quant_platform
$env:PYTHONPATH = (Resolve-Path ".\quant_hub\src").Path
$Project = (Resolve-Path ".").Path
$Archive = (Resolve-Path ".\reference\archive").Path
$Var = Join-Path $Project "quant_hub\var\local"
```

`$Var` 必须指向开发目录或新候选构建区。不得把已激活交付目录代入本节的初始化、扫描、摄入、精读或发布命令。

安装为 editable package 后也可用等价的 `qrh` 入口；本文统一使用无需安装 console script 的 `python -m quant_hub.cli`。

已审核 Crossref/arXiv 材料进入 Evidence 的计划、显式写入命令、版本歧义、权利失败关闭、类别映射和回放验证见
[`src/quant_hub/evidence/REVIEWED_MATERIAL_IMPORT.md`](src/quant_hub/evidence/REVIEWED_MATERIAL_IMPORT.md)。该入口默认只生成计划，只有 `--apply --var-root ...` 同时出现时才写库。

## 初始化与迁移

Archive B 应运行双库初始化：

```powershell
python -B -m quant_hub.cli archive init `
  --project-root $Project --archive-root $Archive --var-root $Var
```

`archive init` 依次对 platform 与 archive 运行向上迁移，输出 `qrh-cli-envelope/v1` JSON 中的 `databases.platform` 和 `databases.archive`。重复执行只应用尚未登记的迁移。

根命令 `init` 只迁移 platform 库，是 A1 单文件快照入口仍需的兼容命令，不会初始化 Archive 业务库：

```powershell
python -B -m quant_hub.cli init `
  --project-root $Project --archive-root $Archive --var-root $Var
```

迁移目录同时保留相配的 `.up.sql` 与 `.down.sql`，但当前没有面向操作者的 migration-down CLI。生产普通回退只交换 exact active/prior 版本并继续使用同一当前 D state；不得切换 `var-root`、替换 SQLite、恢复历史事件或执行 migration-down。

## Paper Lab：论文投递、精读与架构设计

Paper Lab 保留旧 `proj2` 的“把 PDF 放入 papers 后处理”方式。正式投递目录为 `${project_root}/quant_hub/paper_lab/papers/`；扫描只读、不重命名投递文件。旧 `paper_lab/pipeline/*.py` 与 `paper_lab/tools/*.py` wrapper 仍可运行，但会在 stderr 明确提示迁移到 `qrh paper-lab ...`，新自动化应直接使用正式命令：

以下完整 reading workflow 只能在开发区或新 candidate 中执行。active delivery 仅允许已审核恢复闭包内的 PDF 投递登记、Viewer 字段 overlay 和架构 blueprint 保存；四阶段精读、审核与发布必须进入新的 candidate → assembly → review → activation 链。

```powershell
# 发现投递，不写任务
python -B -m quant_hub.cli paper-lab scan `
  --project-root $Project --archive-root $Archive --var-root $Var

# 只预览待处理项；去掉 --dry-run 才建立持久化精读任务
python -B -m quant_hub.cli paper-lab run --dry-run `
  --project-root $Project --archive-root $Archive --var-root $Var

# 失败后从已验证的失败阶段建立下一 attempt
python -B -m quant_hub.cli paper-lab run --resume `
  --project-root $Project --archive-root $Archive --var-root $Var

# 从只读 reference/proj2 做一次可重复的历史迁移
python -B -m quant_hub.cli paper-lab legacy-import `
  --source-root (Resolve-Path ".\reference\proj2") `
  --project-root $Project --archive-root $Archive --var-root $Var

python -B -m quant_hub.cli paper-lab components `
  --project-root $Project --archive-root $Archive --var-root $Var
python -B -m quant_hub.cli paper-lab query --keyword "Transformer" `
  --project-root $Project --archive-root $Archive --var-root $Var
```

精读任务按 problem、method、experiment、synthesis 四阶段持久化。阶段结果必须逐项绑定当前不可变 PDF 版本、SHA-256、页码 locator 与摘录；失败 attempt 的已验证阶段通过显式 lineage 继承，不能伪装成重新执行。生产者不能自行签发审核 PASS；只有独立 reviewer authority 登记并绑定当前 artifact/requirements 的证书才可使 run 进入 `releasable`，随后才可执行：

```powershell
python -B -m quant_hub.cli paper-lab publish --run-id $RunId `
  --project-root $Project --archive-root $Archive --var-root $Var
```

本地 Web 的论文入口为 `/paper-lab/`，架构设计器为 `/paper-lab/designer`。设计器使用同一后端契约完成组件排序、硬／软约束验证、显式 forced 覆盖、不可变版本保存和恢复。论文详情保留旧 Viewer 的字段修订能力，但修订写入 `paper_field_overlay` 不可变覆盖层；它不会修改旧 JSON、PDF 或已导入精读结果，并用 expected version 防止并发覆盖。

源码安装和 wheel 都携带 platform、archive、research_papers、paper_lab 全部 migration、Web 资源和兼容 wrapper。可用以下方式验证安装态，而不是只在源码树运行：

```powershell
python -m pip wheel .\quant_hub --no-deps --wheel-dir .\project_state\wheel
python -m pip install --no-deps --target .\project_state\wheel-install `
  (Get-ChildItem .\project_state\wheel\*.whl | Select-Object -First 1)
```

## Archive 增量发现

本节用于开发或新候选构建。新增 Archive／`research_papers` 内容不得在 active delivery 原地扫描、摄入或发布。

```powershell
python -B -m quant_hub.cli archive scan `
  --project-root $Project --archive-root $Archive --var-root $Var
```

扫描器安全枚举 `.md` 和 `.markdown`，拒绝 symlink、junction、reparse 和非普通文件，登记稳定 UTF-8 原始字节及来源身份。报告区分 `discovered`、`changed`、`unchanged`，并区分 `mapped` 与 `pending_mapping`。

扫描不会根据目录名、文件名或正文猜测 research/document，不会生成 release，也不会切换 active pointer。只有精确命中已验证 source-location 的映射才是 `mapped`；其余项目继续保留为可审计的 `pending_mapping`。相同来源字节重复扫描应为 `unchanged`，不是重复发布。

报告为 `PASS` 时退出码为 0；部分文件被边界或读取检查拒绝时为 `PARTIAL` 并退出 3；全量失败或命令异常非零退出。不要只看进程是否产生 JSON，应同时检查顶层 `status`、`report.counts` 和 `report.issues`。

## 候选、证书与发布边界

Archive 发布采用两阶段信任链：

1. `ArchiveCatalog.prepare_release_candidate()` 读取 manifest 中批准的 origin、object URN、SHA-256 与字节数，重新核对当前来源，冻结 `ReleaseCandidateSpec`；这一步不创建可读 research，也不激活 release。
2. 独立 gate 通过 `ReleaseAuthority.register_candidate()`、`record_decision()` 和 `issue_snapshot()` 在 platform 库登记候选、不可变 PASS 决定和 release snapshot。候选行本身冻结 `requirements_manifest_hash`，决定哈希也覆盖该值；签发时不得换用审核后才出现的 requirements 快照。
3. manifest 只有在 `activate=true` 且携带已登记的 `release_snapshot_urn` 与 `activation_decision_hash` 时，才能由 `ArchiveCatalog.publish_release()` 消费证书。证书必须逐字段绑定同一 subject、artifact manifest、source snapshot、projection revision 和 requirements manifest。
4. Archive 在证书验证通过后才把 staging 候选推进到 releasable、创建 activation 并原子切换 active pointer；错误、旧证书、其他候选的证书或来源变更均 fail closed。

当前 CLI 只暴露 manifest 应用入口，不负责候选审阅和证书签发：

```powershell
python -B -m quant_hub.cli archive apply-release .\path\approved-release.json `
  --project-root $Project --archive-root $Archive --var-root $Var
```

- 对 `activate=false` 的 manifest，`apply-release` 最多登记 staging release；它不会出现在 active-only 的列表、检索或首页。
- 对 `activate=true` 的 manifest，CLI 只消费并验证已有 platform 证书，不会代签证书。
- 候选准备与证书签发目前由库调用或 `tools/replay_archive_b.py` 编排；没有对应 CLI 子命令，也没有 HTTP release 写接口。
- 回切到历史 release 不能复用已消费的旧 snapshot；必须由 release authority 对精确的历史候选重新签发 snapshot，再应用带新 snapshot 的旧候选。签发编排目前仍是库级能力。

## CLI 能力

所有命令都接受 `--project-root`、`--archive-root` 与 `--var-root`。Topic、research 和 comment 写命令还要求唯一的 `--idempotency-key`；同一 key 与同一载荷会返回已记录结果，同一 key 改载荷会冲突。

| 命令 | 当前实际能力 |
| --- | --- |
| `init` | 只迁移 platform 库。 |
| `archive-snapshot PATH` | A1 兼容入口：对单个 Archive 相对路径做不可变快照登记。 |
| `run-show RUN_ID` | 查询 A1 pipeline run。 |
| `archive init` | 初始化／向上迁移 platform 与 archive 两库。 |
| `archive scan` | 增量发现全部 Markdown 并报告显式映射状态，不自动发布。 |
| `archive apply-release MANIFEST` | 登记 staging，或消费 manifest 已携带的有效证书并激活；不签发证书。 |
| `archive list` | 列出已有 active release 的研究；staging 不泄露。 |
| `archive search QUERY` | 检索 active release 的标题与正文投影。 |
| `topic create` | 创建人工维护的 Topic。 |
| `topic link-research` | 用 provenance URN 显式关联研究，可指定 Dashboard 主研究。 |
| `topic set-state` | 写入 `planned` 或 `paused` 事件。完成态不能由此伪造。 |
| `research set-work-state` | 写入 `planned`、`in_progress` 或 `paused` 工作事件。 |
| `research complete` | 由明确的人类 actor 对当前 active release 写完成决定。 |
| `research revoke-completion` | 显式撤销目标完成决定。 |
| `comment create`、`comment list` | 创建、列出持久化评论。CLI 尚未暴露修改与删除。 |
| `paper-lab scan`、`paper-lab run` | 发现 PDF；预览或建立可恢复四阶段精读任务。 |
| `paper-lab legacy-import` | 从只读 `reference/proj2` 全量、可重复迁移历史数据。 |
| `paper-lab components` | 增量重建标签组件和量化架构积木。 |
| `paper-lab query` | 按评级、模型、市场、年份、来源、关键词和状态查询。 |
| `paper-lab publish` | 只发布已消费独立审核凭据的 releasable run。 |
| `paper-lab viewer` | 仅监听 loopback，启动包含 Paper Lab 的统一 Web。 |

列表、搜索和评论示例：

```powershell
python -B -m quant_hub.cli archive list `
  --project-root $Project --archive-root $Archive --var-root $Var
python -B -m quant_hub.cli archive search "低信噪比" `
  --project-root $Project --archive-root $Archive --var-root $Var
python -B -m quant_hub.cli comment list $ResearchId `
  --project-root $Project --archive-root $Archive --var-root $Var
```

CLI 的 actor 默认是 `zhang_zhengze`；也可用 `--actor-kind song_dingkun`，或同时提供 `--actor-kind other --other-name "姓名"`。Topic 列表、Dashboard、研究详情、原始文件下载以及评论修改／删除目前由 HTTP API 提供，不要假定存在同名 CLI。

## Web 与 HTTP 服务

先初始化或回放数据。工作树仅用于本地开发验证，必须显式声明开发运行模式。
[`project_state/FINAL_RUNBOOK.md`](../project_state/FINAL_RUNBOOK.md) 记录的是历史本机 V9/R2
delivery，其中的 `D:\conda\python.exe -I -B`、strict bootstrap 和 resume 命令只用于复核该
历史交付，不是当前生产 VM 的启动接口。当前生产只能由受控 publish/writer-handoff/VM deploy
链路使用 exact `D:\quant\quant_platform\tooling\python\python.exe`，并满足 active + 恰一 prior +
共享 current D state 合同；研究员不得把两套命令混用。

```powershell
python -B .\quant_hub\tools\run_local.py `
  --project-root $Project --archive-root $Archive --var-root $Var `
  --allow-development-runtime `
  --host localhost --port 8765
```

浏览器入口为 `http://localhost:8765/`，研究页为 `/research/{research_id}`。启动器不启用 reloader；本项目的正式入口固定使用 `localhost:8765`，不得改用 `127.0.0.1`、8000 或任何 50xx 端口，也不要把当前本地会话直接暴露到外网。

### 激活交付的运行边界

active delivery 只接受已审核且可由 receipt／event／版本闭包复核的业务 mutation：评论创建、修订与软删除；人工 Topic 的创建、修订、停用和状态维护；研究工作状态、关联及受约束的完成决定；Paper Lab 投递登记、已审核字段 overlay 与架构 blueprint 保存。直接改库、对象区、受管文件或 receipt 不属于合法操作。

新增 Archive Markdown、`research_papers` 论文或证据，以及 Paper Lab 的完整 problem／method／experiment／synthesis reading workflow，都必须在新候选中处理并依次通过 assembly、独立 review、回归、activation 和首次 strict bootstrap。不得在 active delivery 上运行 incremental intake、release apply、Evidence replay 或完整 Paper Lab run／publish。旧交付在新候选正式放行前保持不变。

读取 API：

| Method 与路径 | 能力 |
| --- | --- |
| `GET /api/v1/session` | 建立 session，返回 CSRF token 与固定 actor 选项。 |
| `GET /api/v1/dashboard`、`GET /api/v1/topics` | 返回当前 Dashboard 投影。 |
| `GET /api/v1/research?q=&status=` | 按文本和状态列出 active 研究。 |
| `GET /api/v1/search?q=&limit=` | 搜索 active release，`limit` 为 1–100。 |
| `GET /api/v1/research/{research_id}` | 返回研究、active release、章节与渲染投影。 |
| `GET /api/v1/research/{research_id}/comments` | 返回未删除评论。 |
| `GET /api/v1/research/{research_id}/documents/{document_id}/source` | 下载对象区中与 active 文档绑定的精确原始字节。 |

写入 API：

| Method 与路径 | 能力 |
| --- | --- |
| `POST /api/v1/topics` | 创建 Topic。 |
| `POST /api/v1/topics/{topic_id}/research-links` | 建立显式 Topic–research 关联。 |
| `POST /api/v1/topics/{topic_id}/state-events` | 写 `planned`／`paused` Topic 事件。 |
| `POST /api/v1/research/{research_id}/work-state-events` | 写 `planned`／`in_progress`／`paused` 工作事件。 |
| `POST /api/v1/research/{research_id}/completion-decisions` | 完成或撤销；当前只接受明确的人类 actor，裸 `review_urn` 会以 409 拒绝。 |
| `POST /api/v1/research/{research_id}/comments` | 创建评论。 |
| `PATCH /api/v1/comments/{comment_id}` | 按 revision 乐观并发修改评论。 |
| `DELETE /api/v1/comments/{comment_id}` | 按 revision 软删除评论。 |

所有 API 使用 `v1` envelope。JSON 写请求应使用 `Content-Type: application/json`，必须来自启动器配置的精确同源，并携带 `Origin`、`X-CSRF-Token` 和 8–128 位 `Idempotency-Key`；先调用 `/api/v1/session` 取得 token，并在后续写请求中保留同一 session cookie。没有已建立 session 的请求不会把两个缺失 token 当成相等值，而是以 `403/csrf_rejected` 关闭。评论修改和删除还必须携带服务端返回的 `If-Match: "comment:{comment_id}:r{revision}"`。actor 只能是：

```json
{"actor_kind":"zhang_zhengze"}
{"actor_kind":"song_dingkun"}
{"actor_kind":"other","display_name":"实际姓名"}
```

HTTP 当前没有 scan、候选准备、证书签发或 release 激活接口。

## Archive B 真实纵切回放

回放只在显式 `--var-root` 中创建状态，并对 `fixtures/archive_b/` 的未签名候选执行本地 B gate。先选择一个不存在的新目录，避免覆盖已有运行：

```powershell
$ReplayVar = Join-Path $Project "quant_hub\var\b_replay_manual_01"
if (Test-Path -LiteralPath $ReplayVar) {
  throw "请改用新的空 var-root：$ReplayVar"
}
python -B .\quant_hub\tools\replay_archive_b.py `
  --project-root $Project --archive-root $Archive --var-root $ReplayVar
```

只有输出顶层 `status` 为 `PASS`，且 `source_integrity.changed` 为 0、Archive SQLite 的 `integrity_check` 为 `ok`、`foreign_key_violations` 为 0，才表示本次回放通过。回放同时验证代表性搜索、长文投影、评论持久化、Q2 release 切换不继承旧 completion，以及 Dashboard 的 completed／paused／planned 状态。

用完全相同的命令和 `$ReplayVar` 再运行一次，验证重复执行。第二次仍应为 `PASS`，研究 ID、来源聚合哈希、Archive 数据库实体计数与 Dashboard 终态应稳定；不要要求 `transitions` 数组与第一次逐字节相同，因为已存在 command receipt 时不会重演只应出现一次的中间观察。

该脚本会在运行前后对整个 Archive 文件树计算路径、字节数和 SHA-256 聚合并比较，发现任何来源变化就失败。它在隔离 platform 库中登记的 snapshot 只证明这次 B 回放执行了脚本内的确定性 gate，不等同于生产审核放行。

## 失败恢复与回退

- scan、迁移和 command receipt 均可重复执行。先保留相同 `var-root` 和相同 idempotency key 重试；不要通过改 key 掩盖未知结果。
- release 在证书验证或事务提交前失败时不会切换 active pointer；可能留下可复用的不可变对象或 staging 记录。修正证据后重放同一候选即可，不要清理 `reference/**`。
- completion 的业务回退使用 `research revoke-completion`；release 的业务回切必须为历史候选重新签发 snapshot，不能直接改 active 表或复用旧 snapshot。
- 生产 VM 只使用 exact D 根内的当前 state 和 active/prior 两个版本。普通发布回退只允许交换 active/prior，并沿用同一当前 state；若当前 state 或 D 根无法完整验证，必须 fail closed，不能用旧 SQLite、目录副本或重建流程冒充回退成功。
- 新的空 `var-root` 只允许用于隔离开发／replay，绝不能成为生产 VM 的替代 state。生产状态不可判定时保留现场、停止写入并形成 blocker，不做就地破坏性重建。

## 只读与回归验证

回放的 `source_integrity` 是 Archive 只读的内建前后证据。需要在其他运维流程外包一层核验时，可在操作前后比较文件级清单：

```powershell
$Before = Get-ChildItem -LiteralPath $Archive -Recurse -File |
  Sort-Object FullName | Get-FileHash -Algorithm SHA256
# 在这里运行 scan、replay 或 Web 验证。
$After = Get-ChildItem -LiteralPath $Archive -Recurse -File |
  Sort-Object FullName | Get-FileHash -Algorithm SHA256
$Difference = Compare-Object $Before $After -Property Path, Hash
if ($Difference) { throw "Archive 来源发生变化" }
```

这段核验只读取来源；运行产物仍必须写到 `var-root`。完整自动化回归从项目根运行：

```powershell
$env:PYTHONPATH = @(
  (Resolve-Path ".\quant_hub\src").Path
  (Resolve-Path ".\quant_hub").Path
) -join [IO.Path]::PathSeparator
python -B -m unittest discover -s .\quant_hub\tests -p "test_*.py" -v
```

测试通过不替代真实回放、重复运行和来源清单核对，三者应共同作为 B 放行证据。
