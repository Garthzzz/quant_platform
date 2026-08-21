# State-only backup 与 RPO runbook

本流程只备份 release 外 SQLite 状态，不发布代码、不改变
`release_manifest.json`、`active_release.json` 或线上数据库。唯一计划任务运行在已经证明与
生产 VM 不同 host/storage 的恢复主机；VM 端仅允许在
`D:\quant\quant_platform\tmp\publish-recovery` 创建在线备份暂存，下载并验证后立即清理。

## 权威与依赖方向

- `active_release.json → R`：唯一活动版本权威。
- `C → captured-under R`：SQLite online backup 生成的不可变 checkpoint。
- `RM → R/C`：恢复 manifest 单向绑定当前 release、明确 checkpoint 和已保留静态闭包。
- `checkpoint receipt → R/RM/C`：append-only 证据，不是 active pointer。
- 每次运行创建新的 `C/RM/receipt`；不得修改 `R`、active 或旧恢复点。

恢复主机上的保留对象位于：

```text
<RECOVERY_ROOT>\state-only\sets\state-only-<CHECKPOINT_ID>
```

静态代码、页面、内容、PDF、图片、对象和索引仍由对应的 retained
`cold-recovery-*` bundle 提供。State-only set 只复制新 checkpoint，并以
`static_bundle_ref.json` 绑定同一 `R` 的静态闭包。GC 报告保守保护 active R、所有
retained cold bundle 的 R/RM/C、全部 retained state-only RM/C 和闭包；报告始终
`deletion_authorized=false`，不能作为删除许可。Stage 5 还必须把实测 D prior manifest
hash 与报告中的 `retained_release_roots` 对齐后，才可放行任何独立清理器。

## 实施门禁

在真实安装或运行前必须同时满足：

1. `RECOVERY_ROOT` 已由最终 failure-domain attestation 证明位于 `.240` 整机之外，且
   host identity、storage authority、local backend 与路径无 reparse 均通过；不同盘符
   不算独立故障域。
2. 受保护 runtime config 固定 `target_address=10.5.1.240`、VM root
   `D:\quant\quant_platform` 和同一 attested `RECOVERY_ROOT`。
3. 当前 active R 已有完整、验证通过且仍保留的 `cold-recovery-*` bundle；没有匹配静态
   闭包时任务 fail closed。
4. 固定 operational Python 已包含当前 wheel；配置、SSH key 和其他凭据位于 Git 外，
   不写入 task candidate、receipt、manifest、日志或 bundle。
5. 在 Stage 5 真实 apply 前，只允许 `schedule-candidate` 和 fake-adapter 测试，不得注册
   Windows Task Scheduler。

## 候选、安装与检查

以下命令使用 wheel 提供的固定入口。`<PROTECTED_CONFIG>` 必须是恢复主机上的绝对路径：

```powershell
qrh-state-only-backup schedule-candidate `
  --config <PROTECTED_CONFIG> `
  --project-root D:\quant\quant_platform
```

候选固定为唯一 `\QuantResearchHub\StateOnlyBackup`：每天 03:00 运行、错过时尽快运行、
禁止并发实例，失败后每 15 分钟重试一次、最多 3 次。它使用 S4U limited principal，
不存储密码，不在 VM 注册任务。先核对 candidate JSON、固定 Python、argv、working
directory 和 contract hash，再显式 apply：

```powershell
qrh-state-only-backup schedule-apply `
  --config <PROTECTED_CONFIG> `
  --project-root D:\quant\quant_platform `
  --allow-os-registration
```

重复 apply 必须返回 `unchanged`。Task action、trigger、principal、StartWhenAvailable、
IgnoreNew、2 小时 execution limit 或 retry 设置任一漂移，都必须返回 drift 并重新受控
注册；不得另建第二个 backup task。

人工验证一次运行与状态：

```powershell
qrh-state-only-backup run `
  --config <PROTECTED_CONFIG> `
  --project-root D:\quant\quant_platform

qrh-state-only-backup status `
  --config <PROTECTED_CONFIG> `
  --project-root D:\quant\quant_platform
```

`status` 会读取 `.240` 的唯一 active identity；网络不可达、active 无法验证或没有与当前
R 匹配的完整恢复点时必须返回非零，禁止使用旧 release 的 checkpoint 冒充当前保护。

## RPO 与失败语义

RPO 只使用最后一个与当前 R 匹配、closure 可读、SQLite integrity/foreign-key/schema/
count/restore 全部通过的 checkpoint `captured_at`：

- `protected`：实际 age 不超过 24 小时，最新任务成功，attestation 和闭包有效。
- `degraded`：checkpoint 仍可恢复，但实际 age 超过 24 小时，或最新任务失败。
- `failed`：无法验证 current active、没有当前 R 的有效 checkpoint、闭包损坏、
  attestation 无效/超龄或恢复验证失败。

每次 capture 前先保存一次 pre-run observation。即使迟到任务随后成功并把当前状态恢复为
`protected`，已经发生的超龄窗口仍会保留在
`state-only\audit\status-observations` 和 `state-only\alerts`，不得被新 checkpoint
覆盖。运行后还会写 attempt、JSONL 日志、GC roots 报告和必要告警；错误只记录受控
`error_code/reason_codes`，不得写入异常原文或凭据。

成功后必须确认：

1. 新 set 的 `checkpoint_manifest.json`、`recovery_manifest.json`、
   `checkpoint_receipt.json` 和 `SHA256SUMS` 全部验证通过。
2. set 的 R 与运行开始、capture 结束两次读取的 active identity 一致；中途切换即
   `failed`。
3. release manifest hash 与 active pointer bytes 未变化。
4. VM 的精确 checkpoint/scratch staging 已清理；清理失败时任务为 `degraded` 并进入
   retry，不能声称完整成功。
5. 新旧 retained checkpoints/RM 均仍出现在 GC roots；不得用“latest”覆盖旧 root。

## Stage 5 真实验收

以下均为外部实测门禁，本地单元测试不能替代：

- 在 attested 恢复主机 apply 唯一 Task Scheduler job，并核对真实 task XML/contract。
- 从 `.240` exact D active state 连续完成 capture、下载、完整验证和远端 staging 清理；
  审计 VM write-set 仅落在 `D:\quant\quant_platform`。
- 证明一次同一 R 下连续运行生成两个不同 C/RM/receipt，R 和 active 不变。
- 人为让最近 checkpoint age 超过 24 小时，验证 pre-run observation、degraded alert、
  非零 status 和 scheduler retry；再成功运行并确认新 age 恢复 protected，历史告警仍在。
- 模拟 active 更新、网络中断、attestation 超龄、闭包损坏和 cleanup 失败，确认均不冒充
  RPO 达标。
- 把 active、D prior、全部 retained RM/C 和静态闭包与 GC roots 逐项对齐；未经独立
  retention/restore 演练不得删除任何对象。
