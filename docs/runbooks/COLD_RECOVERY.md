# Cold recovery runbook

本流程只用于 V39 首次空 D 演练，或活动 D 根整体损坏后的灾难恢复。普通代码回退必须切换 D prior，并继续使用当前 D state；不得用历史 checkpoint 倒退线上状态。

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

## 空 D 传输与物化

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
D 内 materialization event 与 production host facts 则必须分别逐字节等于正式发布到
off-host 的 canonical event 和 production-facts 文件（长度与 SHA-256 都相同），不能只做
字段近似比较。

当前真实失败路径必须恰好存在一份 `deploy-candidate_only` / `failed` VM write audit。
audit 自身必须是 `write_atomic_new_json` 的 canonical bytes，且 `audit_id`、路径、closed
declared write set、每条 `path/relative_path/change/entry_type/bytes/sha256` 都与当前残留
机械一致。唯一可识别的残留是两库成对出现的零字节 WAL、标准 32 KiB SHM，以及空的
`tmp\candidate-probes` / `tmp\deployment-cli`（允许 audit 记录现有 `state` 目录的 metadata
变化）；缺少或多出 audit/残留都会拒绝。它们仍被纳入 inspect 的 exact inventory hash、
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
`ExecutablePath` 与 Windows 官方 argv 解析后的 argv0 必须是同一个
`C:\quant_platform` 内 Python，argv 必须恰好为 `<python> -I
C:\quant_platform\tools\viewer\server.py`。server bytes/hash、`/deploymentz` 的严格字段集、
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
