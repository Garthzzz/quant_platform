# Reference 与语义知识增量发布

本流程不修改 `reference/**`。确定性 parser/IR/page/chunk/lexical snapshot 与 DeepSeek 语义增强是两条可独立推进的路径：外部 API 失败时先发布确定性页面与 lexical search，并把 enrichment 标为 pending；语义候选验证完成后再形成新的 effective snapshot/release。

## 1. 编译 workspace

`qrh-knowledge-compile` 只处理 source/IR identity 发生变化且 `external_ai_allowed=true` 的版本。compiler workspace 必须位于 Git 外受保护状态根；API credential 只通过 keyring 或受保护环境变量在请求时注入，不进入命令行、日志、manifest、candidate 或发布产物。

常用操作依次为 `plan`、`execute-one`、`review`、`accept/reject` 和显式 `targeted`。所有 job 必须 terminal；整体 wall-clock deadline 由 immutable `part_count` 派生，provider/socket timeout 不能替代父进程 watchdog。

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
