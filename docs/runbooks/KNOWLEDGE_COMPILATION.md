# Reference 与语义知识增量发布

> 研究员总入口：[`RESEARCHER_DATA_GUIDE.md`](RESEARCHER_DATA_GUIDE.md)。本文件只展开语义编译运维链。

本流程不修改 `reference/**`。确定性 parser/IR/page/chunk/lexical snapshot 与 DeepSeek 语义增强是两条可独立推进的路径：外部 API 失败时先发布确定性页面与 lexical search，并把 enrichment 标为 pending；语义候选验证完成后再形成新的 effective snapshot/release。

## 1. 编译 workspace

`qrh-knowledge-compile` 只处理 source/IR identity 发生变化且 `external_ai_allowed=true` 的版本。compiler workspace 必须位于 Git 外受保护状态根；API credential 只通过 keyring 或受保护环境变量在请求时注入，不进入命令行、日志、manifest、candidate 或发布产物。

常用操作依次为 `plan`、`execute-one`、`review`、`accept/reject` 和显式 `targeted`。所有 job 必须 terminal；整体 wall-clock deadline 由 immutable `part_count` 派生，provider/socket timeout 不能替代父进程 watchdog。

### 1.1 参数和输入来自哪里

```powershell
Set-Location D:\quant\quant_platform
$Compile = '.\quant_hub\.venv\Scripts\qrh-knowledge-compile.exe'
$Workspace = 'D:\quant\quant_platform_publish_runtime\semantic-workspace'
$ReleaseRoot = '<已冻结且只读的 release_root>'
$IdentityEvidence = '<受控的 qrh-deepseek-provider-identity-evidence/v1 JSON>'
```

- `--workspace-root` 是 Git 外受保护目录；首次 `plan` 可创建其中的
  `semantic_jobs.sqlite3` 和 `semantic_cli_audit.jsonl`，后续命令必须复用同一路径。
- `--release-root` 必须是本轮实际编译的冻结 release，不得指向 mutable candidate staging。
- `--identity-evidence` 必须是受控操作者取得的
  `qrh-deepseek-provider-identity-evidence/v1` 文件；不要手写、复制旧轮或把模型自报身份当证据。
- `execute-one` 只从 `keyring` 或受保护环境变量读取 credential。禁止把 key 放进命令行或文档。

### 1.2 完整可执行链

先计划并读取真实 `job_key`：

```powershell
& $Compile --workspace-root $Workspace plan `
  --release-root $ReleaseRoot `
  --identity-evidence $IdentityEvidence

& $Compile --workspace-root $Workspace list --kind jobs
```

对每个计划返回的 `job_key` 执行一次。环境变量模式示例：

```powershell
& $Compile --workspace-root $Workspace execute-one `
  --release-root $ReleaseRoot `
  --identity-evidence $IdentityEvidence `
  --job-key '<PLAN 返回的 job_key>' `
  --credential-source env `
  --env-variable DEEPSEEK_API_KEY `
  --timeout-seconds 180
```

keyring 模式必须同时给出 service 和 username：

```powershell
& $Compile --workspace-root $Workspace execute-one `
  --release-root $ReleaseRoot `
  --identity-evidence $IdentityEvidence `
  --job-key '<PLAN 返回的 job_key>' `
  --credential-source keyring `
  --keyring-service '<SERVICE>' `
  --keyring-username '<USERNAME>'
```

列出并复核候选；只有确实需要查看候选正文时才加 `--include-text`，不要把该输出写入日志：

```powershell
& $Compile --workspace-root $Workspace status
& $Compile --workspace-root $Workspace list --kind generations
& $Compile --workspace-root $Workspace list --kind candidates
& $Compile --workspace-root $Workspace review `
  --candidate-id '<LIST 返回的 candidate_id>' `
  --include-text
```

人工接受或拒绝必须记录真实 actor 和理由：

```powershell
& $Compile --workspace-root $Workspace accept `
  --release-root $ReleaseRoot `
  --candidate-id '<candidate_id>' `
  --actor '<审核者身份>' `
  --reason '<接受理由>'

& $Compile --workspace-root $Workspace reject `
  --candidate-id '<candidate_id>' `
  --actor '<审核者身份>' `
  --reason '<拒绝理由>'
```

只有明确版本需要重编译时使用 `targeted`；每个版本重复一个 `--version-id`：

```powershell
& $Compile --workspace-root $Workspace targeted `
  --release-root $ReleaseRoot `
  --identity-evidence $IdentityEvidence `
  --version-id '<document_version_id_1>' `
  --version-id '<document_version_id_2>' `
  --reason '<重编译原因>'
```

`plan`/`targeted` 返回的 `blocked_version_ids` 和
`targeted_recompile_required_version_ids` 必须人工处理；不能只因进程退出码为 0 就宣称整批完成。
完成前再次运行 `status` 和三个 `list`，确认所有计划 job 均已 terminal，且每个候选都有明确
accept/reject 结论。外部 API 不可用时保留 pending/失败事实，确定性 lexical release 可独立推进，
不得伪造 DeepSeek 结果。

## 2. 提升 immutable semantic authority

首次提升：

```powershell
qrh-semantic-authority `
  --project-root D:\quant\quant_platform `
  --state-root <protected-publish-state> `
  promote --source <completed-semantic-workspace.sqlite3>
```

后续知识变化必须显式绑定当前 promotion，禁止原地写 active authority：

```powershell
qrh-semantic-authority `
  --project-root D:\quant\quant_platform `
  --state-root <protected-publish-state> `
  promote `
  --source <new-completed-workspace.sqlite3> `
  --expected-current-promotion-id <CURRENT_PROMOTION_ID>
```

promotion 使用 SQLite consistent backup、完整 schema/row/logical identity、active-job=0 和 atomic replace。若在 target replace 后、receipt 落盘前崩溃，使用同一 source 和同一 `expected-current-promotion-id` 重放；实现只在 target 已精确等于该 fenced source 且旧 receipt 仍有效时补齐新 receipt，不猜测时间或另换数据。

验证与解析当前 authority：

```powershell
qrh-semantic-authority --project-root D:\quant\quant_platform --state-root <protected-publish-state> resolve
qrh-semantic-authority --project-root D:\quant\quant_platform --state-root <protected-publish-state> verify --promotion-id <PROMOTION_ID>
```

CLI 只输出 promotion/hash/count 身份与去敏错误类型，不输出正文、quote、candidate、credential 或绝对 source 内容。

## 3. 发布消费合同

`publish`、release builder、sealed evaluation 和 MCP artifact builder 只能使用 `SemanticJobStore(..., read_only=True)`。该模式要求 authority 已 checkpoint、无非空 WAL，并以 `mode=ro&immutable=1` 打开；不得创建目录、切换 journal mode、执行 DDL/backfill 或产生 WAL/SHM。发布 source-authority inventory 绑定 promotion ID、file/logical/schema hash 与 row counts。

任何 authority 物理或逻辑漂移均 fail closed。不得放宽 receipt、重跑已经 consumed 的 holdout 或把失败后数据重新标成原 promotion；应保留取证副本，从可验证 checkpoint 修复或建立新的 promotion。
