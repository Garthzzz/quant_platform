# C→D 首次 writer handoff（本地 active/prior 合同）

## 当前状态

本 runbook 描述目标合同，不表示生产切换已经获批。新的 integrated deployment controller、
真实 `R0→R1` pair、SQLite/CAS、Windows service、writer fence、crash replay、浏览器/API 与
write-set 门禁全部通过前，只允许隔离、只读核验；不得停止现网 C writer、切换 active、开放
D 流量或清理旧材料。

## 固定边界

- 生产 VM 的全部项目写入只能位于 `D:\quant\quant_platform`。
- 旧 `C:\quant_platform`、`C:\quant_platform_data` 及服务在 handoff 前只读核验。
- D 稳态只保留 active release 与恰一 prior release；二者使用同一当前 D state。
- 稳态只保留 active 与恰一 prior，二者共用同一当前 SQLite；普通回退不得替换 SQLite、
  回退历史事件或执行 schema down-migration。
- 首次切换只由 `qrh-writer-handoff` 编排 C→D writer fence、最终状态复制与 R0→R1 v4 bridge；
  `qrh-vm-bootstrap prepare-v39` 只准备 R0 partial，`activate-v39-pair` 仅作为同一 bridge 的显式
  诊断/恢复入口，不得在正常 handoff 后重复执行。生产入口必须机械验证精确 D 根，且不接受
  外部 runtime、clock、ID factory、closure/successor verifier、checkpoint builder、state source、
  test-root 或环境替代。

## 首次 pair

1. 冻结现网 V39 为唯一 baseline `R0`，并准备代码或内容真实变化的 successor `R1`。
2. 机械验证 R0/R1 的 manifest、closure、release identity 与 immutable payload 确实不同；禁止
   复制 R0 后只改 ID、时间或 provenance 来填充 prior。
3. 在 C writer 仍为 authority 时，只对 D-root 瞬态 SQLite 一致性副本运行 candidate/prior
   的浏览器、API、schema、create/edit/soft-delete 与 stale-CAS 验证。瞬态副本终态必须清理。
4. 进入 traffic/writer fence，停止旧 C writer，并把最终一致状态一次性迁入 D `state`。这一步
   是 authority handoff，不生成状态回退点。
5. 要求 D active/binding 均不存在且 D ingress 未开放；在同一可崩溃重放 journal 和全局锁内，
   以 `bootstrap_first_pair` durable intent 和 CAS `active: absent→R0` 建立尚未对外的
   baseline。其 activation-family terminal receipt 必须绑定原 pointer/binding absent、ingress
   closed、旧 C writer fenced、最终 D state、R0 live identity 与 writer fence；这是唯一允许
   `prior=null` 的成功形状，且不授权 ingress 或 cleanup。
6. 对最终 D state 真实启动并验证 R0 后，沿普通 activation 路径切换到 R1，使 R0 成为唯一
   prior；写入 exact `local_prior_binding` 与普通 R0→R1 activation receipt。
7. 只有 R1 service identity、endpoint identity、唯一 writer lease、SQLite/CAS、active/binding、
   receipt、retention 与 D-root write-set 全部闭合后才开放 D ingress。
8. D 尚未接收外部写入前失败，可以恢复未变化的 C writer；D 开放流量后 C 永久退出 writer
   authority，任何后续回退只交换 D active/prior 并沿用同一 D state。

## 固定命令边界

R0 的冻结与解包只生成 `incoming/<R0>.partial`，不得提前生成 active pointer：

```powershell
qrh-vm-bootstrap prepare-v39 `
  --vm-root D:\quant\quant_platform `
  --archive-path D:\quant\quant_platform\incoming\v39-source.zip `
  --release-manifest-path D:\quant\quant_platform\incoming\v39-release-manifest.json `
  --release-id <R0_RELEASE_ID> `
  --release-manifest-sha256 <R0_MANIFEST_SHA256>
```

R0 与 R1 partial、服务绑定和 D state 均就绪后，先执行只读 inspect。inspect 必须证明 C 是 8765
唯一 listener、D service 已停止、R0 为 pending bootstrap（或是一次失败重试留下的唯一 sealed
non-ingress bootstrap R0）且 R1 是精确 successor。将返回对象中的 `receipt` 按 canonical JSON 原字节
保存到 `control\writer-handoff-intents`，并保存命令返回的 `inspection_sha256`：

```powershell
qrh-writer-handoff inspect `
  --vm-root D:\quant\quant_platform `
  --release-manifest-sha256 <R0_MANIFEST_SHA256> `
  --successor-release-id <R1_RELEASE_ID> `
  --successor-release-manifest-sha256 <R1_MANIFEST_SHA256> `
  --successor-snapshot-id <R1_SNAPSHOT_ID> `
  --nonce <48_HEX_NONCE>
```

随后仅用同一 receipt/hash/nonce 执行 apply。apply 在内部固定顺序完成：重新检查→停止精确 C PID→
取得最终 C checkpoint→取得 handoff 前 D checkpoint→复制最终 state→bootstrap/复用 non-ingress R0→
普通激活 R1/R0→R1 浏览器/API/writer fence probe→成功 receipt。不得在两者之间另行启动 D：

```powershell
qrh-writer-handoff apply `
  --vm-root D:\quant\quant_platform `
  --release-manifest-sha256 <R0_MANIFEST_SHA256> `
  --successor-release-id <R1_RELEASE_ID> `
  --successor-release-manifest-sha256 <R1_MANIFEST_SHA256> `
  --successor-snapshot-id <R1_SNAPSHOT_ID> `
  --inspection-receipt D:\quant\quant_platform\control\writer-handoff-intents\<RECEIPT>.json `
  --inspection-sha256 <INSPECTION_SHA256> `
  --nonce <48_HEX_NONCE>
```

`R0_RELEASE_ID/R0_MANIFEST_SHA256` 与 `R1_RELEASE_ID/R1_MANIFEST_SHA256` 任一相同都会拒绝。
bootstrap 控制器还会在 C 停止后证明 SCM 为 `STOPPED`、8765 无 listener、旧 C 两个根无 writer
进程；因此 bridge 不能越过 fence。apply 若在 R0 已封口但 R1 尚未开放时失败，安全回切 C 后的
下一次 handoff 会验证并复用同一 R0 receipt/journal，只创建新的 R1 activation attempt；不会把
`R0/null` 当作普通稳态启动。

## 失败与重放

- journal 只记录 intent、期望 identity、CAS 和 controller 直接形成的 evidence hash；JSON
  `started=true`、`health=true` 或 `writer_fence=true` 不构成资格。
- handoff journal 使用 closed v4 schema，并逐步持久化 `legacy_stop_pending`、`legacy_stopped`、
  `final_checkpoint_created`、`pre_d_checkpoint_created`、`d_state_replace_pending`、
  `d_state_replaced`、`d_start_authorized` 与 `d_bridge_pending`。每个可能改变 writer、state 或
  ingress 的动作都由相邻 durable phase 包围；重放只接受同一 attempt、lock nonce、R0/R1
  identity、旧 C 进程 identity 和相邻 phase。从 `final_checkpoint_created` 起，journal 同时
  持久绑定 final-C 与 pre-D checkpoint ID/manifest hash；同 ID checkpoint 被完整重签替换也
  必须在恢复写入或重启 C 前失败。
- 两份 SQLite checkpoint 只能由持有 live handoff lock 且匹配当前 v4 journal phase 的一次性
  产品授权创建。授权固定 checkpoint ID、source set、R0/R1 identity、lock/journal file identity；
  备份先进入内存 SQLite，再以 pinned D-root directory handle 独占创建目标，并以内存 restore
  proof 验证，不开放产品 target path、临时 restore 目录或调用者自报 source。checkpoint 恢复
  只消费在 manifest、sidecar、两份 DB 与父目录全部固定期间读出的内存 bytes；D state staging、
  candidate probe 和 transient cleanup 的写入、替换、删除均通过固定父目录的相对操作完成。
- pointer 只能是 expected 或 desired；第三值、binding 漂移、多个活动 attempt、第三 retained
  release、SCM PID/ImagePath/nonce/writer lease 不一致均 fail closed。
- 成功 receipt 已持久化后只继续 exact cleanup，不反向切换；失败 receipt 只有在原 pointer、
  binding、service、writer fence 已恢复且当前 D state identity 证明未变化后才能追加；其
  operation 与 terminal 前最后一个合法 non-terminal `failed_phase` 必须和 journal 完全一致，
  且 rollback target 只能是原 pair 的 exact prior。
- failure receipt v2 带 canonical self-hash；`legacy_restored_fenced`／`handoff_failed_fenced`
  terminal journal 必须绑定该 hash。若 crash cut 只留下 receipt 与旧 non-terminal journal，
  fresh finalize 必须重新观察 D closed 与 exact C writer；D 仍开放、观察未知、receipt 被整体
  重签或 journal 绑定漂移时均保留 fence，不得仅凭 receipt 布尔值清除 journal。
- 无法机械证明单一 writer 时保留 journal 并阻止下一次 publish，不猜测 authority。
- `status` 只解析 exact inspection hash/nonce 对应的 journal/terminal。`finalize` 对尚未暴露 D
  的任一 recovery-only phase 恢复 pre-D state 与 exact C writer；对 `d_bridge_pending` 先证明
  D endpoint 是否已开放：关闭时可确定性重放 bridge，已开放时必须直接证明 committed
  `R1 active + R0 prior + steady_current`，不得再次 bridge，也不得恢复 C。失败 receipt 先于
  terminal journal 持久化，随后才允许 cleanup；因此 receipt 前退出保留 checkpoint，terminal
  后或 cleanup 后退出均由 fresh finalize 收敛，重放只补齐缺失的一侧。生产模式不接受外部
  runtime/clock。
- 成功 terminal 前与 fresh finalize 后都必须在同一 D current state 上机械证明 exact
  `R1 active + R0 prior`：两个 manifest/hash、active/prior role、`steady_active` authority、
  `steady_current` state、SCM/endpoint/writer lease 和旧 C fence 缺一即阻止成功。

## 普通回退

回退只能从 exact-matched `local_prior_binding` 选择唯一 prior，把
`active=A, prior=P` 交换为 `active=P, prior=A`。切换前后均验证同一 D state identity、两版本
read/write/CAS、SCM/endpoint/writer identity 和业务事件不倒退；不接受任意 release ID。

## 放行证据

正式执行前至少需要：source 与 fresh-wheel 回归、Windows 锁 owner crash/reacquire、每个 journal
side-effect 前后 crash cut、R0/R1 伪 pair 反例、非空两族 comment/workspace 序列、浏览器/API、
active↔prior↔active、终态恰两棵 release、零 D-root 外写入和独立 verifier PASS。证书只证明
精确 D 根与当前 state 完整时最近一代版本回退，不扩大为数据或主机丢失后的恢复能力。
