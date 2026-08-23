# Cold recovery runbook

本流程只用于 V39 首次空 D 演练，或活动 D 根整体损坏后的灾难恢复。普通代码回退必须切换 D prior，并继续使用当前 D state；不得用历史 checkpoint 倒退线上状态。

普通 D-prior 回退的闭合证据必须另行写成 canonical
`qrh-d-prior-rollback-receipt/v1`：active 与 prior 的 release ID、manifest SHA-256 必须分别不同，
并机械证明 prior 已激活、health、writer fence 与 active restore 全部成功。Stage 5 的
`qrh-measured-prior-release/v2` 只接受该 receipt 的固定相对 locator 与原始 bytes SHA-256，
locator 必须精确为 `stage5/d_prior/rollback_receipt.json`，
在 resolver 内重算、分类验证并检查时序；调用方自报 `pass`、任意 evidence ID 或摘要不能替代
rollback receipt。resolver 还必须拒绝 hardlink/多链接文件，并在同一打开句柄上复核 read 前后
handle/path file identity、size 与时间，避免根外别名或 resolve→read 换件冒充 authority bytes。
本合同不新增回退 executor，也不授权任何 VM 写入。

> 当前实现边界：`prepare-empty` 与 `--qualification-reset-materialized` 的 closed contract
> 只适用于 V39 qualification 状态，不能用于已经激活、存在 writer/receipt/journal 的 active-D
> 维护演练。Stage 5 最终 active-D 空根演练目前只有
> `qrh-active-d-maintenance-drill-plan/v1` inspect-only 计划 skeleton，固定
> `destructive_apply_enabled=false`，没有删除 executor。恢复 receipt finalize 同样只有
> evidence-bound、`finalize_enabled=false` 的安全 skeleton。不得把下面的 V39 命令改参数后
> 复用于 active-D，也不得用调用方布尔值伪造最终恢复成功。

## 固定权威与边界

- 唯一生产及恢复目标 VM：`10.5.1.240`（OpenSSH alias：`honghu-vm`）。`.223`、`.235` 和第二恢复 VM 不属于本版依赖。
- 唯一物化目标：`D:\quant\quant_platform`。不得写 `D:\`、`D:\quant`、任何 sibling 或 C 路径。
- `RECOVERY_ROOT` 位于开发机，与 `.240` 具有不同 host identity 和 storage authority；它是 bundle 的 off-host 权威，不是第二台恢复 VM。
- 首次 C→D 期间，旧 C V39 和 `C:\quant_platform_data` 继续在线且只读，直至 writer handoff。

## Bundle 形成

受保护的生产 runtime config 必须固定 `target_address=10.5.1.240`、exact D root、开发机 `RECOVERY_ROOT`、failure-domain attestation 和 operational source root。运行安装后的固定入口：

```powershell
qrh-cold-bundle `
  --config <PROTECTED_CONFIG_OUTSIDE_GIT> `
  --project-root D:\quant\quant_platform `
  --release-root <SEALED_RELEASE> `
  --bundle-id <IMMUTABLE_ID> `
  --state-source legacy_c
```

`legacy_c` 只允许在线备份 `comments.sqlite3` 与 `research_workspace.sqlite3`。远端 checkpoint、scratch、TEMP/TMP 全部位于 exact D root 的 `tmp\publish-recovery`；随后 checkpoint 下载到开发机 off-host `RECOVERY_ROOT`。Bundle 必须通过 release/checkpoint/RM 单向身份、closure inventory、SHA256SUMS、SQLite restore、no-secret 和 operational bootstrap 验证。

首个 V39 `legacy_c` bundle 是为了产生真实 empty-D materialization event 的 **qualification bundle**：在生成它之前必须已验证开发机候选根与生产 VM 不同 host/storage、路径无 reparse，但此时尚无恢复事件，所以不得称为 recovery-protected，也不得签发 `recovery_protection_receipt`。真实空 D 物化成功后，使用 evidence-only materialization event、同一 bundle/root hash 及生产/恢复 host/storage facts 生成最终 failure-domain attestation。后续 `d_active` bundle 和生产 publish 仍必须在开始前验证这份新鲜 attestation。

Operational bootstrap 至少覆盖受哈希保护的 `tooling/python`、固定 service entry/host/access gate、`deployment_runtime.json` 与 `service_install_candidate.json`。Bundle 禁止包含 access digest、viewer password、API key、SSH/GitHub 凭据或 Authorization header；这些受保护材料在恢复后另行注入。

## Failure-domain attestation 新鲜度刷新

> 当前生产就绪状态固定为 `FAKE_ONLY/NOT_READY`。仓库尚无同时绑定 exact committed
> Git/CI/wheel identity、SSH host authentication 与 production stdout capture 的 integrated
> runner。已安装产品包不包含 `current`、`history/archive`、`intent` 或 `completion` 的写入、
> 原子替换、CAS、锁或中断恢复 core；测试代码也不能从产品包导入这些能力。

`issue-challenge`、`capture-recovery-facts`、`capture-independence-probe`、`observe`、
`rotate-prepare --mode prepare`、`rotate-apply` 和正式 `verify-current` 都会在任何文件访问或
写入前返回结构化 `NOT_READY`，进程退出码为 `2`，且 `authority=false`。这些兼容命令名不是
可用的 producer 或轮换入口。旧 schema 的 closed JSON、时间、hash 与 lineage 校验仅供只读
故障诊断；即使使用当前 module hash 手工构造一条完全自洽的 legacy lineage，也只能得到
`DIAGNOSTIC_ONLY`，不能得到 `PASS` 或 refresh authority。

`rotate-prepare --mode inspect` 只读取既有 legacy synthetic observation 及其完整 lineage，输出
`DIAGNOSTIC_ONLY`，不创建 `intent-output`。`diagnose-legacy-current` 只读检查现存 attestation，
同样不授予 authority。不得用旧 facts 改时间重签，不得手工覆盖 `current`，也不得把诊断结果
用于 VM 写入、恢复、candidate、服务切换或 writer handoff。

产品中唯一正式入口是 `quant_hub.ops.failure_domain_authority.require_failure_domain_authority`。
当前入口无参数、无文件系统能力且固定抛出 `FAILURE_DOMAIN_AUTHORITY_NOT_READY`；不存在产品 fallback。
publish、cold bundle、publish recovery、cold restore/qualification reset、Stage 5、state-only、
Scheduler 与 writer handoff 均在读取 failure-domain 证据或产生写入前经过该入口。legacy v1
facts/probe/attestation 只可作 `DIAGNOSTIC_ONLY`、`authority=false` 的历史解析材料；即使新鲜、
自洽也不能生成 protection、qualification、handoff、Scheduler 或 Stage 5 authority。

安装 wheel 后的 `qrh-publish` 与 `qrh-writer-handoff-client` 在参数解析完成后、读取 config/path、
执行 Git、证据或远端操作前调用该入口；`publish_recovery_cli` 的 capture、capture-legacy、
identify-active、cleanup-capture、register 也在各 public API 及 CLI 分支入口拒绝。三者统一输出
`FailureDomainAuthorityNotReady.document()` 的 closed JSON（`status=NOT_READY`、
`authority=false`、固定 `error_code`）并以退出码 `2` 结束，不回显调用方路径或配置正文。

Round7 把同一边界下沉到公开 Python API，而不把通用只读诊断误封：`PublishQueue` 构造只保存
lexical 路径，不创建 state/audit；队列写、publish pipeline/coordinator、production runtime 构造与
publish、source freeze、recovery protection、五个 `OpenSSHRecoveryActions` 方法、incremental
upload/deploy/invoker、writer client 构造/工厂/方法，以及 `WindowsHandoffRuntime` 构造和公开 OS
方法，均以唯一 gate 作为首条有效语句。当前 `NOT_READY` 下，config/path/tree/subprocess/SSH/OS/
service boundary 调用数必须为零，且临时树不得变化。

`inspect_local_git`、`dry_run_plan` 和现有 remote inventory 属于 `DIAGNOSTIC_ONLY`；exact-SHA
GitHub CI 与固定本地测试/public guard 属于 `QUALIFICATION_INPUT`。它们不能产生或携带
failure-domain/protection/release authority。Git 调用固定使用 `--no-optional-locks`；remote
inventory 已移除隐式 `New-Item`，只允许读取已存在目录。fresh installed-wheel 测试维护一份 closed
surface inventory；新增导出 class/public method/factory/helper 未分类即失败，并逐项验证 gated
surface 的首条有效语句。该清单只覆盖 formal release/recovery/handoff 域，不扩张到研究、数据库或
MCP 通用模块。

Round8 不再使用 `__all__` 缩小上述清单：source 与 fresh installed-wheel 都枚举六个正式模块中所有
不以下划线开头的顶层 function、class、本模块定义的 callable type alias，以及 class 的公开
method、classmethod、staticmethod、property 与 `__call__`；内部正式 factory 由单独闭集列明。
`__all__` 只校验文档导出名称存在、无重复且与 callable inventory 一致。各分类数量与总量从实际
inventory 机械计算，分类交集、未分类和已分类但不存在项必须同时为空，不能写死一个预期总数。
`GitHubCIConfig`、`VMConfig`、transport/deployment protocol、固定拒绝的 unavailable recovery
adapter 和 `ExactGitPush` 均已明确分类；`ExactGitPush.__call__` 的唯一 gate 必须是首条有效语句，
fresh-wheel 动态验证 process 调用数为零。实际边界 runner 仅以 `_urllib_http_get`、
`_subprocess_runner`、`_production_process_runner` 私有名存在，旧公共名不可导入；这不改变
diagnostic/qualification 输入的既有只读行为。

未来 integrated runner 必须以独立产品模块引入，不得把旧写 core 恢复到当前诊断模块。新实现
必须同时具备新 schema 和进程内、不可序列化的 capability 对象；capability 只能由完成 exact
Git/CI/wheel 校验及 SSH host authentication 的 runner 创建，JSON、路径、环境变量和调用者参数
均不得构造或恢复该对象。该威胁模型不声称防御能修改代码与证据文件的同一 OS 管理员，也不为此
引入 secret、MAC 或 Keyring。

Round6 changed-file source manifest 使用确定性算法：repo-relative path 必须为 NFC、UTF-8、正斜杠
形式；按 UTF-8 bytes 排序，对每项依次追加 `path + NUL + lowercase_sha256hex + NUL`，最后计算
整体 SHA-256。以下只读命令可复算，输出仍标记 `DIAGNOSTIC_ONLY`：

```powershell
qrh-failure-domain source-manifest --repo-root D:\quant\quant_platform `
  --path docs/runbooks/COLD_RECOVERY.md `
  --path openspec/changes/design-vm-knowledge-mcp/specs/vm-atomic-deployment/spec.md `
  --path openspec/changes/design-vm-knowledge-mcp/tasks.md `
  --path quant_hub/pyproject.toml `
  --path quant_hub/src/quant_hub/ops/cold_bundle_cli.py `
  --path quant_hub/src/quant_hub/ops/cold_restore_cli.py `
  --path quant_hub/src/quant_hub/ops/failure_domain.py `
  --path quant_hub/src/quant_hub/ops/failure_domain_authority.py `
  --path quant_hub/src/quant_hub/ops/failure_domain_rotation.py `
  --path quant_hub/src/quant_hub/ops/operational_source_cli.py `
  --path quant_hub/src/quant_hub/ops/production_host_facts_cli.py `
  --path quant_hub/src/quant_hub/ops/publish.py `
  --path quant_hub/src/quant_hub/ops/publish_adapters.py `
  --path quant_hub/src/quant_hub/ops/publish_recovery_cli.py `
  --path quant_hub/src/quant_hub/ops/publish_runtime.py `
  --path quant_hub/src/quant_hub/ops/stage_closure.py `
  --path quant_hub/src/quant_hub/ops/state_only_backup.py `
  --path quant_hub/src/quant_hub/ops/writer_handoff.py `
  --path quant_hub/src/quant_hub/ops/writer_handoff_client.py `
  --path quant_hub/tests/test_cold_bundle_cli.py `
  --path quant_hub/tests/test_cold_restore_cli.py `
  --path quant_hub/tests/test_failure_domain_rotation.py `
  --path quant_hub/tests/test_publish_adapters.py `
  --path quant_hub/tests/test_publish_cli.py `
  --path quant_hub/tests/test_publish_runtime.py `
  --path quant_hub/tests/test_stage_closure.py `
  --path quant_hub/tests/test_state_only_backup.py `
  --path quant_hub/tests/test_writer_handoff.py `
  --path quant_hub/tests/test_writer_handoff_client.py `
  --path tools/release/failure_domain_cli.py
```

## 空 D 传输与物化

**当前不可执行：**以下命令保留为 integrated authenticated runner v2 完成后的目标操作协议，
当前 wheel 会在读取 config、bundle、attestation 或连接 VM 前固定返回/抛出
`FAILURE_DOMAIN_AUTHORITY_NOT_READY`。不得通过调用 legacy v1 helper、修改测试 patch 或手工重签来
绕过。只有 v2 authority 经独立审核放行后，才可恢复本节的真实 qualification/restore 操作。

不依赖 SMB/UNC，也不手工复制广播包。确认 `.240` exact D 根真实存在、无 reparse 且为空后，运行：

```powershell
qrh-cold-restore prepare-empty `
  --config <PROTECTED_CONFIG_OUTSIDE_GIT> `
  --project-root D:\quant\quant_platform `
  --bundle-root <RECOVERY_ROOT>\cold-recovery-<ID> `
  --mode inspect `
  --intent-nonce <ONE_TIME_RANDOM_NONCE> `
  --expected-legacy-deployment-id quant-hub-v39-company-broadcast-20260731-hotfix1

# 将 inspect 返回的 pre_delete_inventory_sha256 原样绑定到 apply；不得手工重算或省略。
qrh-cold-restore prepare-empty `
  --config <PROTECTED_CONFIG_OUTSIDE_GIT> `
  --project-root D:\quant\quant_platform `
  --bundle-root <RECOVERY_ROOT>\cold-recovery-<ID> `
  --mode apply `
  --intent-nonce <SAME_ONE_TIME_RANDOM_NONCE> `
  --expected-pre-delete-inventory-sha256 <INSPECTED_SHA256> `
  --expected-legacy-deployment-id quant-hub-v39-company-broadcast-20260731-hotfix1

# apply 成功后必须立即恢复，不得把空 D 留作新的运行状态。
qrh-cold-restore restore `
  --config <PROTECTED_CONFIG_OUTSIDE_GIT> `
  --project-root D:\quant\quant_platform `
  --bundle-root <RECOVERY_ROOT>\cold-recovery-<ID> `
  --evidence-output <RECOVERY_ROOT>\evidence\cold-materialization\<ID>.json
```

`prepare-empty inspect` 不含删除语句，只验证 qualification bundle、`.240`、exact D
父链、closed top-level、D active/state writer 缺失，以及 8765 仍由旧
`C:\quant_platform` V39（精确 deployment ID）提供服务。`apply` 必须消费同一 nonce
的 append-only inspection evidence，并在删除前再次得到完全相同的 canonical inventory
hash；只逐个删除 exact root child，永不删除 root、D 上级、sibling 或 C。任何失败均保留
旧 C writer authority。inspect、apply-intent 和 applied evidence 自动追加到 off-host
`RECOVERY_ROOT\evidence\prepare-empty`。

### 一次性 qualification 重置

如果 V39 qualification bundle 已成功物化、但隔离 candidate 在任何 activation 或
writer handoff 之前失败，不得用普通 `prepare-empty` 绕过 active pointer，也不得原地
替换 tooling。仅可对同一份已完整验证的 bundle 显式增加
`--qualification-reset-materialized`，先 inspect、再用同一 nonce 与原样 inventory hash
apply；其他参数与上例相同：

```powershell
qrh-cold-restore prepare-empty ... --mode inspect `
  --qualification-reset-materialized `
  --intent-nonce <ONE_TIME_RANDOM_NONCE>

qrh-cold-restore prepare-empty ... --mode apply `
  --qualification-reset-materialized `
  --intent-nonce <SAME_ONE_TIME_RANDOM_NONCE> `
  --expected-pre-delete-inventory-sha256 <INSPECTED_SHA256>
```

此模式只接受 `.240` exact D 根中的同一 V39 release/manifest、canonical active pointer、
materialization event、operational bootstrap/tooling、restore tool 和 checkpoint 两库。
`QuantResearchHub` 服务、任何 D-root 进程/监听、activation/writer-handoff journal 或 receipt、
未知文件/目录、reparse/alternate stream、非零 WAL、异常 SHM、额外 state 都会拒绝执行。
qualification 的 legacy deployment ID 是代码常量，不接受操作者提供另一个“V39”别名。
off-host independence probe 必须绑定当前 bundle 的 exact closure inventory hash；同一
verified recovery manifest 必须单向绑定该 closure、release manifest 和 checkpoint。
D 资格重置还要求 failure-domain attestation 原始文件逐字节等于 canonical JSON；其
file SHA-256 必须进入 inspection、apply-intent 与 applied 三份 closed evidence。apply 在
写 intent 前和发出远端删除前均重新读取并验证同一 canonical bytes/file SHA，语义等价的
空白或字段重排也视为 identity 改变并拒绝。
D 内 production host facts 的相对路径必须从已验证的 `bundle_id` 精确派生为
`audit/evidence/production-host-facts-<bundle_id>.json`，且其 bytes/SHA-256 必须与
off-host 正式文件逐字节相同。off-host canonical materialization event 仍是语义权威；本次
已物化 V39 资格根中的远端 event 是原 restore 的普通 PowerShell 5.1 hashtable 序列化。
reset 仅兼容机械重建并经本机 PowerShell 5.1 逐字节复现的
`legacy_powershell_hashtable_v1` 唯一 bytes/SHA-256，同时在 inspection、apply-intent 与
applied 证据中记录 canonical authority SHA、legacy serialization identity 及 observed
remote SHA。任意其他字段重排、空白或语义等价 JSON 都拒绝，不存在宽泛 semantic fallback。

当前真实失败路径必须恰好存在一份 `deploy-candidate_only` / `failed` VM write audit。
audit 自身必须是 `write_atomic_new_json` 的 canonical bytes，且 `audit_id`、路径、closed
declared write set、每条 `path/relative_path/change/entry_type/bytes/sha256` 都与当前残留
机械一致。该真实 audit 必须精确记录 `audit`、`audit/receipts`、`backups`、`incoming`、
`state`、`state/locks`、`tmp`、`tmp/candidate-probes` 的既定 created/modified 变化，以及
两库成对出现的零字节 WAL 和标准 32 KiB SHM。`tmp/deployment-cli` 是 OpenSSH deployment
invoker 在 deploy CLI 启动、VM write-audit before-snapshot 之前创建的固定 TEMP/TMP，因此
必须在当前根中存在且为空、必须不出现在该 audit 的 observed writes；出现内容、被 audit
记录、缺失或出现任何其他目录/文件均拒绝。上述空目录和 sidecar 均纳入 inspect 的 exact inventory hash、
逐 top-level subtree hash 和 apply 的 TOCTOU 复核。apply 只删除已复核的 exact root
children，成功后保留空根，不生成 activation 或 recovery receipt，并须立即用同一 bundle
重新 `restore`。

Windows PowerShell 5.1 的 `Get-Item -Stream` 不足以证明目录 ADS 缺失；Microsoft 只从
PowerShell 7.2 起声明目录 stream 支持。因此 reset 脚本通过 `Reflection.Emit` 在当前
PowerShell 进程内直接声明 Win32 `FindFirstStreamW` / `FindNextStreamW` / `FindClose`，
枚举 root、全部目录和文件；不使用 `Add-Type`、编译器、临时源码、pycache 或 D 内 Python。
同一无写绑定还用 `GetShortPathNameW` 获取 exact root 的真实 long/short identity；D 进程与
listener 检查统一归一 `/`、`\` 和 `\\?\` 前缀并按完整路径边界匹配，既不能用 8.3/extended
路径绕过，也不能粗暴拒绝不属于项目根的其他 D 盘进程。任何 named stream、枚举错误或
entry-count 差异都 fail closed。

仅 inspect 在 release、operational bootstrap 的全部依赖、state、audit、目录、ADS、reparse、
closed top-level 与未知项均已机械闭合后，才允许调用逐字节验证过的 D Python，以 stdin
执行固定 probe，验证唯一 failed candidate audit 的 canonical bytes 与精确 scalar 类型；
整个闭包随后再验一次。apply 消费这份 immutable inspection identity，只进行 exact inventory、
subtree、C/D 运行态与 TOCTOU 重验，绝不执行 D Python；因此 tooling 已先被删除或 root 已空的
同 intent 重试仍能由 off-script PowerShell 能力独立完成。
API 语义见 [Get-Item -Stream](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item)
、[FindFirstStreamW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirststreamw)
、[FindNextStreamW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findnextstreamw)
与 [GetShortPathNameW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getshortpathnamew)。

若 SSH 响应在删除后丢失，只能用同一 nonce、同一 inspected hash 和已存在的 off-host
apply-intent 重试。空根可直接复核；若只完成了部分 top-level child 删除，则当前 top-level
集合必须是原闭包的严格子集，且每个仍存在 child 的完整 subtree inventory hash 必须逐项
等于 inspect 证据。未知 child、某个 child 内部仅删一部分、任何内容/ADS/reparse 变化均
拒绝继续。每次 retry 仍重复 C V39、D service/process/listener 和完整 inventory 门禁，
只继续删除剩余 exact root children；不创建第二个 intent。该分支仅用于本次“从未激活”
的 qualification，不能作为活动生产根清空或 tooling 热更新接口。其证据单独位于
`RECOVERY_ROOT\evidence\prepare-empty-qualification-reset`。

旧 C V39 健康门禁必须把 8765 的唯一 listener owning PID 绑定到同一个 CIM process；
`ExecutablePath` 与 Windows 官方 argv 解析后的 argv0 必须是同一个 regular、non-reparse
Python，argv 必须恰好为 `<python> -I C:\quant_platform\tools\viewer\server.py`。解释器
绝对路径不写入公开代码或证据；qualification 合同以 normalized lowercase path 的 UTF-8
SHA-256、binary size 和 binary SHA-256 三项固定身份绑定现场 V39 解释器。这三项进入
inspection、apply-intent、applied 的 closed evidence；`C:\Windows`、D 根、sibling 路径或
同名但字节不同的 Python 均拒绝。server bytes/hash、`/deploymentz` 的严格字段集、
PID、端口与固定 `quant-hub-v39-company-broadcast-20260731-hotfix1` identity 必须同时一致；
仅在 CommandLine 中出现 C 路径子串不算通过。

远端 materialization event 成功返回后，`restore` 会将 canonical、fsync、immutable
副本写入显式 `--evidence-output`；该路径必须位于 Git 外
`RECOVERY_ROOT\evidence\cold-materialization`。后续 independence probe 直接消费这份
副本，不允许 shell 重定向或手抄。

空 D 恢复后，production host facts 必须使用 bundle 中已校验的 exact-D Python，禁止
PATH Python：

```powershell
D:\quant\quant_platform\tooling\python\python.exe -I -B -m `
  quant_hub.ops.production_host_facts_cli `
  --root D:\quant\quant_platform `
  --output D:\quant\quant_platform\audit\evidence\production-host-facts.json
```

该固定模块只生成 production facts，输出仅允许 exact-D `audit\evidence`；recovery
facts、independence probe 和 attest 仍在开发机执行。

固定流程为：

1. 通过 OpenSSH 只读检查 exact D 根为空；非空、缺失或 reparse 立即失败，且不得开始 SCP。
2. 仅在 D 根内创建 `tmp\recovery-import`，SCP 传入已验证 bundle；不使用 C、D 上级或 sibling staging。
3. 使用 bundle 自带的 operational Python 与 stdlib restore tool，设置 `-I -B`、`PYTHONDONTWRITEBYTECODE=1`，并把 TEMP/TMP 固定在 `tmp\recovery-runtime`。
4. Restore 只容许 `tmp\recovery-import\cold-recovery-<ID>` 与 `tmp\recovery-runtime` 这两个受控 staging；出现任何其他根目录内容即拒绝物化。
5. 完整复核 bundle 后物化 `releases`、`state`、`tools`、`tooling`、固定 `control` 和唯一 `active_release.json`；退出 staging Python 后清理 import/runtime staging，并写入 evidence-only materialization event，证明 empty-root 前置与无 staging 残留。

此时状态只能是 `materialized_pending_post_restore_verification`，不得生成成功 recovery 或 activation receipt。

## 隔离候选验证与放行

旧 C V39 仍占用 8765 时，`candidate_only` 必须使用 D tooling 在 loopback 临时端口启动 exact R。它在线备份 D state 到 `tmp\candidate-probes` 的隔离副本，只对副本执行页面/API 测试，不读取或写入 active pointer、生产 SQLite、C 或 8765。只有 release/manifest/snapshot、页面、API、隔离 writer authority、active 未变和清理全部通过后，才能追加 evidence-only candidate event；不得生成 receipt。

恢复后另行注入受保护 access digest，随后在明确的 writer/traffic fence 下完成服务安装、真实启动、浏览器/API、comment/schema 和资源验证。只有 closure、state、隔离候选、真实服务与 post-restore gate 全部通过后，才允许追加成功 recovery receipt。任何失败只保存 failure evidence，不得伪造 activation/recovery receipt。

首次切换期间，V39 ZIP、C 状态备份和旧服务材料必须保留，直至 D active、D prior rollback、cold bundle、空 D restore 和 writer handoff 全部实测通过。
