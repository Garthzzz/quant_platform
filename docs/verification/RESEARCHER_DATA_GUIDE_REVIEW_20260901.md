# 研究员数据指南当前审核记录（2026-09-01）

> 状态：`PENDING_POST_APPLY_REVIEW`。在下列 exact commit、文件 SHA-256、机械检查和两名审核者
> 均填写且 verdict 改为 `PASS` 前，本记录不是当前审核通过证明，更不是 release、Stage 5/6、
> handoff、visibility、外部信任根或 DeepSeek 审核证据。

## 1. 审核对象与边界

- `project_state/README.md`
- `project_state/CURRENT.md` 顶部当前口径
- `quant_hub/README.md` 研究员入口和 completion API 摘要
- `docs/runbooks/README.md`
- `docs/runbooks/RESEARCHER_DATA_GUIDE.md`
- `docs/runbooks/KNOWLEDGE_COMPILATION.md`
- `docs/runbooks/KNOWLEDGE_MCP.md`
- `docs/runbooks/STAGE45_EVALUATION_GATES.md`
- `docs/runbooks/WRITER_HANDOFF.md`
- `docs/runbooks/STAGE5_STAGE6_CLOSURE.md`
- `docs/verification/RESEARCHER_DATA_GUIDE_REVIEW_20260831.md` 的追加勘误

审核只核对文档可操作性、路径、CLI/API 合同、数据库/数据文件位置、索引和可信边界。
它不执行 VM 写入，不改变 GitHub visibility，不签发 Stage 5/6，不读取或修改 `reference/**`、
`D:\quant\industry_demo/**`。本轮 `DEEPSEEK_API_KEY` 不可用，因此真实 DeepSeek 审核未执行，
不得把 Codex 双审或历史 DS 记录表述为 DeepSeek PASS。

## 2. 两提交冻结身份（应用补丁后填写）

本审核避免把 commit 写入其自身造成循环：

1. `reviewed_content_commit`（Commit A）冻结下表九个 tracked 被审文件和本文件的 PENDING
   模板；`project_state/**` 是 Git 忽略的本地恢复状态，只由同轮 SHA-256 与 Commit B 记录绑定，
   不冒充 tracked tree 成员；
2. 两名 reviewer 只读审核 Commit A；
3. 只修改本审核记录，填写 Commit A、SHA-256、findings 和 verdict，再形成
   `audit_record_commit`（Commit B）；Commit B 不写入文件自身，由 Git/外置 release manifest 绑定；
4. Commit A 到 Commit B 之间，九个 tracked 被审文件必须逐字节无差异；两个 ignored
   recovery 文件必须保持表中 SHA-256。

- reviewed content commit（Commit A）：`<PENDING_40_HEX>`
- Commit A tracked tree clean：`<PENDING true/false>`
- audit record commit（Commit B）：通过 `git log -1 --format=%H -- docs/verification/RESEARCHER_DATA_GUIDE_REVIEW_20260901.md` 外部解析，不写入本文件
- 审核开始时间：`<PENDING ISO-8601 +08:00>`
- 审核完成时间：`<PENDING ISO-8601 +08:00>`

| 文件 | SHA-256 |
| --- | --- |
| `project_state/README.md` | `<PENDING>` |
| `project_state/CURRENT.md` | `<PENDING>` |
| `quant_hub/README.md` | `<PENDING>` |
| `docs/runbooks/README.md` | `<PENDING>` |
| `docs/runbooks/RESEARCHER_DATA_GUIDE.md` | `<PENDING>` |
| `docs/runbooks/KNOWLEDGE_COMPILATION.md` | `<PENDING>` |
| `docs/runbooks/KNOWLEDGE_MCP.md` | `<PENDING>` |
| `docs/runbooks/STAGE45_EVALUATION_GATES.md` | `<PENDING>` |
| `docs/runbooks/WRITER_HANDOFF.md` | `<PENDING>` |
| `docs/runbooks/STAGE5_STAGE6_CLOSURE.md` | `<PENDING>` |
| `docs/verification/RESEARCHER_DATA_GUIDE_REVIEW_20260831.md` | `<PENDING>` |

审核记录自身不写入自己的 SHA-256，也不内嵌 Commit B，避免自引用。其 bytes 由 Commit B
和后续 release manifest/外置审核 receipt 绑定。

## 3. 哈希生成与机械验证

### 3.1 Commit A：生成被审内容哈希

补丁应用后先提交 Commit A；在 clean tree 上运行并把输出填入第 2 节表格：

```powershell
Set-Location D:\quant\quant_platform
$ReviewedContentCommit = (& git rev-parse HEAD).Trim()
if ($ReviewedContentCommit -notmatch '^[0-9a-f]{40}$') { throw 'HEAD 不是 exact 40-hex SHA' }
if (git status --porcelain) { throw '审核对象必须是 clean tracked tree' }

$Reviewed = @(
  'project_state/README.md',
  'project_state/CURRENT.md',
  'quant_hub/README.md',
  'docs/runbooks/README.md',
  'docs/runbooks/RESEARCHER_DATA_GUIDE.md',
  'docs/runbooks/KNOWLEDGE_COMPILATION.md',
  'docs/runbooks/KNOWLEDGE_MCP.md',
  'docs/runbooks/STAGE45_EVALUATION_GATES.md',
  'docs/runbooks/WRITER_HANDOFF.md',
  'docs/runbooks/STAGE5_STAGE6_CLOSURE.md',
  'docs/verification/RESEARCHER_DATA_GUIDE_REVIEW_20260831.md'
)
$Hashes = foreach ($Path in $Reviewed) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "缺少 $Path" }
  $Hash = Get-FileHash -LiteralPath $Path -Algorithm SHA256
  [pscustomobject]@{ path = $Path; sha256 = $Hash.Hash.ToLowerInvariant() }
}
$Hashes | ConvertTo-Json -Depth 3
```

两名 reviewer 必须在 Commit A 上完成只读审核。之后只编辑本审核记录，填写 Commit A、表中
SHA-256、两轮 findings/verdict 和最终判定；不得同时修改 `$Reviewed` 中任何文件。

### 3.2 Commit B：机械比较 expected/actual，关闭自引用循环

形成 Commit B 后，在 clean tree 上运行。脚本从本文件表格读取 expected hash，不只打印 actual：

```powershell
Set-Location D:\quant\quant_platform
$ReviewRecord = 'docs/verification/RESEARCHER_DATA_GUIDE_REVIEW_20260901.md'
$ReviewText = Get-Content -LiteralPath $ReviewRecord -Raw -Encoding utf8
$CommitMatch = [regex]::Match(
  $ReviewText,
  'reviewed content commit（Commit A）：`(?<sha>[0-9a-f]{40})`'
)
if (-not $CommitMatch.Success) { throw '审核记录未填写 Commit A' }
$ReviewedContentCommit = $CommitMatch.Groups['sha'].Value
if (git status --porcelain) { throw 'Commit B 验证必须使用 clean tracked tree' }

$Reviewed = @(
  'project_state/README.md',
  'project_state/CURRENT.md',
  'quant_hub/README.md',
  'docs/runbooks/README.md',
  'docs/runbooks/RESEARCHER_DATA_GUIDE.md',
  'docs/runbooks/KNOWLEDGE_COMPILATION.md',
  'docs/runbooks/KNOWLEDGE_MCP.md',
  'docs/runbooks/STAGE45_EVALUATION_GATES.md',
  'docs/runbooks/WRITER_HANDOFF.md',
  'docs/runbooks/STAGE5_STAGE6_CLOSURE.md',
  'docs/verification/RESEARCHER_DATA_GUIDE_REVIEW_20260831.md'
)
$TrackedReviewed = @(
  'quant_hub/README.md',
  'docs/runbooks/README.md',
  'docs/runbooks/RESEARCHER_DATA_GUIDE.md',
  'docs/runbooks/KNOWLEDGE_COMPILATION.md',
  'docs/runbooks/KNOWLEDGE_MCP.md',
  'docs/runbooks/STAGE45_EVALUATION_GATES.md',
  'docs/runbooks/WRITER_HANDOFF.md',
  'docs/runbooks/STAGE5_STAGE6_CLOSURE.md',
  'docs/verification/RESEARCHER_DATA_GUIDE_REVIEW_20260831.md'
)
git diff --quiet $ReviewedContentCommit HEAD -- @TrackedReviewed
if ($LASTEXITCODE -ne 0) { throw 'Commit A→B 之间被审文件发生变化，必须重新审核' }
foreach ($Path in @('project_state/README.md', 'project_state/CURRENT.md')) {
  git ls-files --error-unmatch -- $Path *> $null
  if ($LASTEXITCODE -eq 0) { throw "$Path 已变为 tracked；必须更新审核冻结合同" }
  git check-ignore --quiet -- $Path
  if ($LASTEXITCODE -ne 0) { throw "$Path 不再是明确 ignored recovery 文件" }
}

$Expected = @{}
$Pattern = '(?m)^\| `(?<path>[^`]+)` \| `(?<sha>[0-9a-f]{64})` \|$'
foreach ($Match in [regex]::Matches($ReviewText, $Pattern)) {
  $Expected[$Match.Groups['path'].Value] = $Match.Groups['sha'].Value
}
if ($Expected.Count -ne $Reviewed.Count) { throw 'expected SHA-256 表未完整填写' }
foreach ($Path in $Reviewed) {
  if (-not $Expected.ContainsKey($Path)) { throw "哈希表缺少 $Path" }
  $Actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($Actual -cne $Expected[$Path]) {
    throw "SHA-256 不匹配：$Path expected=$($Expected[$Path]) actual=$Actual"
  }
}

$AuditRecordCommit = (& git log -1 --format=%H -- $ReviewRecord).Trim()
if ($AuditRecordCommit -notmatch '^[0-9a-f]{40}$') { throw '无法解析 Commit B' }
Write-Output "reviewed_content_commit=$ReviewedContentCommit"
Write-Output "audit_record_commit=$AuditRecordCommit"

git diff --check "$ReviewedContentCommit..HEAD" -- $ReviewRecord
rg -n '当前版本为 V34|唯一保留回退为 V30|PID 18520|### 6\.8' `
  project_state docs/runbooks quant_hub/README.md
rg -n 'RESEARCHER_DATA_GUIDE|STAGE45_EVALUATION_GATES|STAGE5_STAGE6_CLOSURE' `
  project_state/README.md docs/runbooks quant_hub/README.md
rg -n 'workspace-root|release-root|identity-evidence|job-key|credential-source|candidate-id|version-id' `
  docs/runbooks/KNOWLEDGE_COMPILATION.md
rg -n 'audit\\release-closure|audit\\writer-handoff|tmp\\writer-handoff' `
  docs/runbooks/RESEARCHER_DATA_GUIDE.md
```

第一条残留扫描预期退出码为 1（零匹配）；其余扫描预期至少命中本文要求的对应段落。
另执行 CLI 解析和定向回归：

```powershell
$env:PYTHONPATH = (Resolve-Path '.\quant_hub\src').Path
python -B -m quant_hub.knowledge.semantic_cli --help
python -B -m quant_hub.knowledge.semantic_cli --workspace-root X plan --help
python -B .\quant_hub\tests\test_knowledge_semantic_cli.py
python -B .\quant_hub\tests\test_archive_web.py
python -B .\quant_hub\tests\test_writer_handoff.py
python -B .\quant_hub\tests\test_release_closure.py
```

所有本地 Markdown 链接还须由独立审核者解析并确认目标存在；HTTP URL 只做语法检查，
不把网络可达性混入本地文档 PASS。

## 4. 两轮审核（完成后填写）

### 第一轮：执行代理自审

- reviewer：`<PENDING>`
- Commit A/hash 与第 2 节一致：`<PENDING>`
- 抓取方式、代码/API、数据库/数据文件位置、索引、VM 边界逐项结果：`<PENDING>`
- findings：`<PENDING>`
- verdict：`PENDING`

### 第二轮：独立只读 Codex reviewer

- reviewer/task identity：`<PENDING>`
- 未修改被审文件：`<PENDING true/false>`
- 未访问 `reference/**` 或 `D:\quant\industry_demo/**`：`<PENDING true/false>`
- Commit A/hash 与第 2 节一致：`<PENDING>`
- findings：`<PENDING>`
- verdict：`PENDING`

## 5. 最终判定

当前：`PENDING_POST_APPLY_REVIEW`。

只有以下条件全部满足才可改为 `PASS`：两轮审核基于相同 Commit A 和文件 SHA-256；
P0/P1/P2 均为零；命令、路径、API 状态码和数据位置与当前实现一致；所有本地链接有效；
没有把候选、测试、历史审核、Authenticode、本机 manifest/散列或本地 adapter 提升为外部 authority。
