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
