# Stage 5 / Stage 6 本地 active/prior 闭合合同

本文定义发布放行顺序，不表示生产 VM、Windows 服务、writer handoff 或 GitHub visibility
已经执行。任何现场证据缺失时，对应阶段保持未完成；本地单元测试不能替代现场证据。

## 能力边界

- 唯一生产项目写入根是 `D:\quant\quant_platform`。
- 稳态只保留当前 active release 与一个真实 prior release；两者使用同一份当前 D state。
- 普通回退只交换 active/prior 版本角色，不替换 SQLite、不恢复历史状态、不执行 schema
  down-migration。
- 生产连续性边界就是精确 D 根内的 active、恰一 prior 与二者共用的当前 state。
- Stage 5 只证明 exact D 根和当前 state 完整时的最近一代版本回退；不声明 VM、D 根、
  对象库或 state 整体丢失后的恢复能力。

## 唯一执行顺序

1. 在仓库仍为 Public 时冻结 exact commit SHA、tracked tree、release manifest、snapshot 和
   clean-wheel inventory；工作树不洁、身份不一致或产品包仍暴露已撤销入口时停止。
2. 完成 Stage 0–4 的数据、内容、评论、检索、MCP、浏览器/API、state compatibility、
   write-set 和失败路径门禁。
3. 验证本地部署控制器的锁、canonical CAS、durable journal、严格阶段机、SCM/endpoint/
   writer/state 实测探针、崩溃重放、Windows 路径边界和失败收敛。journal revision 0 必须是
   durable intent；成功 terminal receipt 前不得授权清理。
4. 首次 handoff 在外部流量和写入 fence 内取得最终 D state。旧 C writer 仍是 authority
   时只允许隔离验证，且 C 盘始终只读；状态最终复制完成后停止旧 C writer。
5. D active/binding 初始均不存在时，以 `bootstrap_first_pair` journal 执行
   `active: absent→R0`。其 activation-family receipt 是唯一允许 `prior=null` 的成功形状，
   必须绑定原 pointer/binding absent、ingress closed、旧 C writer fenced、最终 D state、
   R0 live identity 和 writer fence；它不授权 ingress 或稳态完成。
6. 以普通激活协议切换 `R0→R1`。R1 必须与 R0 具有真实不同的受密封代码/内容/资源身份，
   不得复制 R0 或只改 ID、时间、工具/provenance 来制造 successor。
7. 只有 R1 启动、post-activation 检查、当前 state 读写/CAS、唯一 writer、active pointer、
   `local_prior_binding(R1,R0)` 和 activation receipt 全部通过，才开放 D 流量。此后 C writer
   永久退出 authority。
8. 演练一次 `R1 active + R0 prior → R0 active + R1 prior`，始终使用同一当前 D state；
   再按需要以相同协议切回。任一版本无法安全使用当前 schema 时回退失败并保持原 active。
9. 成功 terminal receipt 完整验证后，才按 journal 中 exact typed target 清理更早 release、
   completed incoming/partial 和不再被 active/prior closure 引用的对象。终态必须只有两棵
   release；清理失败阻止下一次 publish，但不得反向伪造切换结果。
10. Stage 5 certificate 重放全部分类 verifier 并通过后，才执行 Public→Private；随后重读
    Private plan/actions/branch/environment/publish controls，运行 exact-SHA Private CI 和
    candidate-only no-switch 验证，最后形成 visibility closure receipt。

## Release 与 receipt 图

- immutable release manifest 只密封代码、内容、资源、索引、知识和 state compatibility。
- `active_release` 只指向当前 active release。
- `local_prior_binding` 在稳态只指向 active 与恰一 prior。
- activation/rollback receipt 只绑定结果 pair 与验证结果；failure receipt 显式绑定 operation、
  原 pair、target candidate、terminal 前最后一个合法 non-terminal 失败阶段和已验证恢复结果；
  activation target 必须与原 pair 不同，rollback target 必须恰为原 prior，bootstrap 必须从空
  D pair 开始；cleanup receipt 只绑定保留 pair、精确移除目标与结果。
- 所有 receipt 都是 append-only evidence，不是 pointer；release manifest 不得反向引用 pointer、
  binding、receipt、attempt、切换时间或其他动态控制信息。
- 每个 attempt 只能有一个 terminal activation/rollback/failure receipt；bootstrap 不能产生
  cleanup receipt，普通成功 attempt 在 cleanup receipt 后才关闭 retention journal。

## Stage 5 certificate 的最低内容

新证书 schema/producer 完成迁移后至少绑定：

- Public repository observation、full 40/64 位非零 commit SHA、tracked tree；
- exact active/prior release、manifest、snapshot、binding 与 application/content/resource closure；
- 同一当前 D state identity、schema compatibility 与真实 read/write/CAS 证据；
- Windows root/write-set、SCM、endpoint、writer fence、lock/journal/replay 和 retention 证据；
- 首次 handoff时的 bootstrap receipt、普通 R0→R1 activation receipt 和 ingress gate；
- 本地 rollback receipt、cleanup/retention closure、Web/API/Search/MCP/评论/Dashboard 结果；
- source 与 fresh installed wheel 的撤销面：不存在旧恢复模块、entrypoint、schema、调度任务、
  runbook 引用或 D 根之外项目写路径；
- Stage 0–4 与 Stage 6 前置 gate 的 canonical producer artifact 和分类 verifier 结果。

调用方提供的 `status=pass`、布尔值、自报 hash 或同名 ID 没有权威性。producer/verifier 必须
重读 canonical bytes、复算 hash、核对真实对象和现场身份。任一必需 producer 尚未实现或现场
证据尚未取得时，certificate 必须 fail closed。

## 当前实现与不可执行项

- 本地 release identity、v2 `candidate_only`、普通 failure recovery、R0 bootstrap、R0→R1
  exact pair bridge 和产品撤销面已完成实现与专项回归；正常首次切换由
  `qrh-writer-handoff` 在 writer fence 与最终 state 复制后内嵌 bridge，
  `qrh-vm-bootstrap activate-v39-pair` 仅保留为同一固定 bridge 的诊断/恢复入口。若 R1 在开放
  ingress 前失败，后续 attempt 只能复用经唯一 receipt/journal 验证的 non-ingress R0，不得把
  `R0/null` 当普通稳态启动。独立审核和生产现场证据通过前，仍不得接入生产流量。
- writer handoff 已升级为 closed v4 crash-state machine：停止 C、两份 live-authorized SQLite
  checkpoint、替换 D state、bridge pending 和 terminal 均有 durable phase；所有 D 尚未暴露的
  crash cut 可恢复 pre-D state 与 exact C，D 已开放则必须证明 exact `R1/R0` pair 后只向前完成。
  journal 从 final-C checkpoint 起绑定 checkpoint ID/manifest hash，拒绝同 ID 完整重签替换；
  产品 checkpoint 使用 pinned D-root 路径、固定文件读取与内存 backup/restore proof，state
  replace、candidate probe 和 transient cleanup 只通过固定父目录相对操作；产品 controller、
  persistence、Windows runtime 均为 live provenance + slots 对象，不能通过实例 method shadow、
  test hook、环境或 alias 注入绕过固定生产调用图。
- 旧 Stage 5 schema/producer 已移除；新证书必须等 active/prior、writer handoff、现场 D-root
  证据和全局回归全部闭合后再实现和签发。
- 已建立的生产 VM 连接只用于只读盘点。未获 VM 写入放行前，不启动/停止服务，不切
  pointer/binding/writer，不清理 release/state，不改变 GitHub visibility。
