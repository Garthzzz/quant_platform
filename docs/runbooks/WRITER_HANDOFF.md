# V39 C→D writer handoff

本流程只用于一次性的 V39 writer authority 切换。旧服务在 `C:\quant_platform`，目标 VM 固定为 `10.5.1.240`，新系统唯一可写根固定为 `D:\quant\quant_platform`。任何命令都不得向 `D:\`、`D:\quant`、相邻目录或 C 盘写入新项目内容。

`qrh-writer-handoff-client` **只在开发机执行**；其 `--project-root` 是开发机 checkout，`--config` 和该配置中的 `RECOVERY_ROOT` 必须位于 Git 外并已证明属于生产 VM 整机之外的独立故障域。即使安装 wheel 后 VM package 中包含 client 模块，VM 端也不得由操作者另行运行它；开发机 client 只通过 sealed D-root tooling 调用固定模块 `quant_hub.ops.writer_handoff`。不得在 `.223`、`.235` 或任何第二台恢复 VM 上执行本流程。

## 前置门禁

- Stage 1 qualification bundle、off-host cold recovery、exact V39 release manifest、D tooling package inventory 和 recovery-protection receipt 已通过。
- D Windows Service 尚未作为 writer 启动；C 仍是唯一 writer。
- 受保护 runtime config 位于 Git 项目之外，且固定 SSH alias、服务端实际地址 `10.5.1.240`、exact VM root `D:\quant\quant_platform` 与 off-host `RECOVERY_ROOT`；SSH 服务端还会以 `SSH_CONNECTION` 二次核对 `.240`。
- 两只 SQLite 已完成 pre-handoff restore-verified checkpoint；真实浏览器/API candidate 已通过。
- 已从本次候选的 exact wheel 安装两个固定入口，并通过 `python -I -B -m quant_hub.ops.writer_handoff --help`、`python -I -B -m quant_hub.ops.writer_handoff_client --help`、`qrh-writer-handoff --help` 与 `qrh-writer-handoff-client --help` 的只读 smoke gate。真正的切换只从 client 入口发起，不由操作者直接执行 VM 端 server 入口。

执行前在**开发机**设置并人工复核这三个值；不要把 secret 写入命令行、仓库或日志：

```powershell
$ProjectRoot = 'D:\quant\quant_platform'
$ProtectedConfig = '<Git 外受保护的 production_publish_runtime.json 绝对路径>'
$V39ManifestSha256 = '<64 位 exact V39 release_manifest SHA-256>'

if ((Resolve-Path -LiteralPath $ProjectRoot).Path -ne 'D:\quant\quant_platform') {
  throw 'developer checkout identity differs'
}
$ResolvedProject = (Resolve-Path -LiteralPath $ProjectRoot).Path.TrimEnd('\')
$ResolvedConfig = (Resolve-Path -LiteralPath $ProtectedConfig).Path
if ($ResolvedConfig.Equals($ResolvedProject, [StringComparison]::OrdinalIgnoreCase) -or
    $ResolvedConfig.StartsWith($ResolvedProject + '\', [StringComparison]::OrdinalIgnoreCase)) {
  throw 'protected runtime config must remain outside Git project'
}
```

## 正常执行

```powershell
qrh-writer-handoff-client `
  --config $ProtectedConfig `
  --project-root $ProjectRoot `
  --release-manifest-sha256 $V39ManifestSha256 `
  run
```

客户端先从 exact active V39 release 的 immutable `server.py` 机械提取默认 access identity；它不会执行旧代码，也不接受或输出 password/digest。随后完成 nonce-bound 只读检查、off-host immutable evidence、D intent 原子采用、C stop、最终 checkpoint、D state materialize、D start 与浏览器/API/identity/writer-fence 验证。

成功 receipt 落盘前不会宣称 handoff 成功。两库替换期间由 `D:\quant\quant_platform\control\writer_handoff_pending.json` 拦截 D service 的普通手工或重启启动，只有 exact attempt/phase/nonce 的一次性 SCM 参数可启动候选，防止多文件交换中断后读取混合状态。stdout 只接受 closed JSON；只有 `status=succeeded` 且 `writer_authority_committed=true` 才表示 D writer 已提交。随后须核对 off-host `terminal/<evidence_id>.json` 的 SHA-256 等于 stdout `evidence_sha256`，并与 VM D-root success receipt hash 一致。

## SSH 中断后的恢复

不要重新运行 `run` 或生成新 nonce。inspection 一旦完成，后续编排失败也会以 closed `qrh-writer-handoff-client-error/v2` 仅返回非敏感的 exact `inspection_sha256`；使用该值查询服务端 durable journal。若错误仍是 v1，说明 inspection 尚未可靠形成，不能猜测或按时间选择 evidence：

```powershell
qrh-writer-handoff-client `
  --config $ProtectedConfig `
  --project-root $ProjectRoot `
  --release-manifest-sha256 $V39ManifestSha256 `
  status --inspection-sha256 <INSPECTION_SHA256>
```

若状态为 `finalize_required`，执行：

```powershell
qrh-writer-handoff-client `
  --config $ProtectedConfig `
  --project-root $ProjectRoot `
  --release-manifest-sha256 $V39ManifestSha256 `
  finalize --inspection-sha256 <INSPECTION_SHA256>
```

`finalize` 只会恢复同一 inspection/nonce 绑定的 exact attempt；不会猜测 attempt，也不会创建第二次 handoff。

`status` 的处理是穷尽且 fail closed 的：

- `succeeded`：保存已下载的 immutable terminal evidence，核对 D live identity 与 C writer fence；不要再次运行 `run` 或 `finalize`。
- `finalize_required`：只执行上面的 exact `finalize`，然后再查一次 `status`；不得手工 stop D 或 start C。
- `failed`：以已下载 failure receipt 为准。只有 receipt 明确证明 `legacy_rollback.succeeded=true`，且 client result 明确为 `writer_authority_committed=false` 时，C 才是恢复后的唯一 writer；若 rollback blocked/failed，保持 fence，不得自行启动任一服务。
- `in_progress_or_fenced` 或 `not_found`：不推断 authority、不生成新 nonce、不重新运行 `run`，保留 D journal/intent 与 off-host inspection，按同一 inspection 做只读取证。无法证明单一 writer 时必须保持现网不变并升级为硬门禁 blocker。

## 失败语义

- D 从未监听且从未暴露：可以按已记录的 exact C executable/argv 恢复旧服务，不调用历史 `restart.py`。
- D 已监听、暴露或状态无法证明：永不自动退回 C，避免双 writer；保留 journal 与 failure receipt，人工按证据修复 D。
- 成功 probe 后若在 receipt 或 cleanup 前崩溃：D 保持 writer，`finalize` 幂等补齐同一成功 receipt；不得 stop D 或恢复 C。

禁止操作者直接调用 `qrh-writer-handoff`、`sc.exe`、`taskkill.exe`、旧 `restart.py` 或手工复制 SQLite 来“修复”切换；这些动作会绕过 nonce、TOCTOU、checkpoint 和双 writer 门禁。所有 VM 新写入只允许出现在 exact `D:\quant\quant_platform` 的 control/state/checkpoints/audit/locks/tmp/logs/tooling 子树，执行后必须运行 write-set audit；不得写 `D:\`、`D:\quant`、sibling/parent 或 C 盘。

所有 receipt、inspection 和恢复证据都必须保存在 off-host recovery evidence；stdout 只包含去敏身份，不包含 nonce、正文、comment、password、digest 或 secret。真实 handoff、C writer fence、D service/端口、checkpoint、browser/API、off-host evidence 和 post-write audit 全部通过前，本 runbook 只能作为候选工具合同，不能将 Stage 1 标记完成。
