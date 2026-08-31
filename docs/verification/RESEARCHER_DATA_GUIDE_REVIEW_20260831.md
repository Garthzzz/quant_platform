# 研究员数据指南与 Stage 5/6 文档独立审核记录（2026-08-31）

## 1. 审核结论

本记录覆盖以下文档及其直接代码、CLI、schema 和测试入口：

- `docs/runbooks/RESEARCHER_DATA_GUIDE.md`；
- `quant_hub/README.md` 的研究员入口；
- `docs/runbooks/KNOWLEDGE_MCP.md`；
- `docs/runbooks/STAGE45_EVALUATION_GATES.md`；
- `docs/runbooks/STAGE5_STAGE6_CLOSURE.md`；
- `quant_hub.knowledge_mcp` 的真实 Codex 验收入口；
- `quant_hub.ops.release_closure` 及四份 closure JSON Schema。

最终结论分为两个互不替代的层次：

1. **研究员文档范围 PASS。** 抓取、导入、Paper Lab、Web/API、MCP、数据库和数据文件位置、
   reference 只读边界及生产 VM exact-D 边界，已与当前代码和配置一致。
2. **Stage 5/6 防伪造边界 PASS，但生产签发功能未完成。** 当前 15 个角色都没有真实分类
   replay adapter；runtime 对所有 managed wrapper 明确返回 `non-qualifying`。这能阻止自报 PASS，
   但也意味着当前不能签发 Stage 5 certificate 或 visibility receipt。

因此，本记录不能被解释为 Stage 5/6 已完成、生产 handoff 已放行、GitHub visibility 可修改，
或 VM 已取得 active/prior certificate。

## 2. 审核身份与方法

- 执行代理先进行文档自审和修正。
- 独立 Codex reviewer 在共享树上进行了三轮只读反查，逐项回到源码、CLI、schema 和测试。
- 独立 reviewer 除本审核记录外没有修改被审文件。
- 本轮没有可用的 DeepSeek transport 或 credential，因此 **没有执行真实 DeepSeek 审核**。
- 既有 fake-only／public synthetic DS harness 不是外部 DeepSeek 审核，未被计作本轮审核证据。

## 3. 三轮发现、修正与复核

### 3.1 第一轮：基线缺口审查

第一轮判定为 `REVISE`，主要缺口如下：

- README 尚未提供清晰的研究员独立指南入口。
- 论文抓取示例未稳定绑定密封 release 的 `runtime`，缺少数据库和资源文件预检。
- 历史 reviewed evidence import 没有完整列出输入、provenance 和可追溯边界。
- 抓取文档未充分说明真实下载检查、合法获取和 rights 边界。
- 论文线索白名单、未确认／歧义／不可获取状态说明不完整。
- Paper Lab 未完整写出 task→execute→review→publish 链路及中断恢复。
- API 表、ETag、`If-Match`、`expected_version` 和 session/CSRF/idempotency 合同不完整。
- MCP 示例没有固定目标项目语境，`doctor` 的本机 mirror 更新副作用和转换状态说明不足。
- `^src` 到 Evidence binding、发布 artifact、MCP mirror 的数据链说明不足。
- tasks、staging、publish audit/lock、`runtime_base` 等位置未集中列全。
- README 对本机外置发布状态和生产 VM exact-D 边界的区分不够明确。

执行代理随后逐项修正，独立 reviewer 不以修正总结代替源码复核。

### 3.2 第二轮：残留合同与 Stage 6 文档审查

第二轮确认第一轮主体缺口已经关闭，同时发现以下残留：

- `POST /api/v1/research-updates/{update_id}/annotations` 实际要求研究更新的单一强
  `If-Match`，指南最初没有明确说明。
- troubleshooting 最初遗漏 `transition_pending`。
- 真实 `qrh-mcp-acceptance preregister/run/verify` 已实现，但旧文档仍残留
  “real runner disabled”及 v2 receipt 语义。
- 真实验收 evidence tree 最初把 raw trace 文件名写成 `.jsonl`，实际为 `.trace.jsonl`。
- 运行前闭合的是四个顶层文件加 `cases`，不是三个顶层文件。
- launch config 最初没有写出 schema、`codex_executable_sha256` 和闭合字段。
- “Git 外”一词可能被误解为生产 VM checkout 根之外，与 exact-D 规则冲突。

以上残留最终均已修正：

- annotation 强 ETag 已加入 API 并发说明；
- `fresh/stale/unavailable/transition_pending` 已在正文和排错段一致列出；
- `codex -C <project-root> mcp list --json` 已替代不带项目语境的命令；
- `doctor` 的本机 immutable artifact 下载和 mirror/pointer 原子更新已明确；
- real/fake authority、v3 dispatch replay、`.trace.jsonl`、四顶层输入已对齐代码；
- 生产 VM 的验收 evidence 必须位于 exact-D 下、不纳入 Git 跟踪的新空目录。

### 3.3 第三轮：最终事实与防伪造闭环

第三轮重新核对全部命令、路径、API、数据库清单和 Stage 5/6 闭环，结果如下：

- `RESEARCHER_DATA_GUIDE.md` 的抓取、导入、Paper Lab、API、MCP 和数据位置事实 PASS。
- `quant_hub/README.md` 已提供明确二级入口，并区分开发／候选外置状态和 VM exact-D。
- `KNOWLEDGE_MCP.md` 与 `STAGE45_EVALUATION_GATES.md` 已同步真实 Codex runner；
  fake 或 real/fake mixed 固定属于 `PUBLIC_SYNTHETIC_NON_QUALIFYING_GATE`。
- 两臂都是 `REAL_CODEX_EXEC` 且完整重放通过时，authority 仍固定为
  `REAL_CODEX_EVIDENCE_REPLAY_NON_AUTHORITATIVE`；当前缺独立可信 attestation/countersignature，
  因而该 receipt 只能证明功能回放，不能成为 Stage 5 资格证据。
- Stage 5/6 runbook 已列出十个 Stage 5 gate、五个 Stage 6 gate、
  `certify-stage5`、`verify-stage5`、`close-visibility` 和 `verify-visibility` 的完整顺序。

第三轮还发现旧 closure observation 可自报 subject/facts/observer，dummy artifact 也可能满足
完整性检查。修正后：

- observation v2 不再携带可自报 subject、facts、observer 或 PASS；
- subject 从 actual active pointer、prior binding 和两个 release manifest 重建；
- old v1 self-report、dummy schema 和 managed wrapper 均不能取得 PASS authority；
- real MCP public verifier 独立接线并重放 evidence root；
- 15 个角色的真实 adapter 缺失时，无条件 `non-qualifying`，且不创建 gate/certificate/receipt；
- tracked schema 已约束 role→result schema、role→exact assertions，以及 Stage 5/visibility
  evidence 的精确角色顺序。

这一修正关闭了“伪造 PASS”风险，但没有补出 15 个真实 adapter，所以生产签发仍未完成。

## 4. 机械验证证据

### 4.1 文档哈希与结构检查

最终独立反查时记录的 SHA-256：

| 文件 | SHA-256 |
| --- | --- |
| `RESEARCHER_DATA_GUIDE.md` | `2BE3C68A0D082F5C56222318E66C6F17FBCBC3D4C05AAB9D6B654A06A8116447` |
| `quant_hub/README.md` | `C702329504728B8227AB5708D32FC1D0CBEB53A0B3B55772AB4CA56F0EFED9BC` |
| `KNOWLEDGE_MCP.md` | `8D39718B8272ED1F4B3997E8761F601691CD66469CEA04A33DFD8E8512797125` |
| `STAGE45_EVALUATION_GATES.md` | `326EC721889BB0A9652330D9DFF67190F1433F187C4E18EA114D3F2BEEA816C5` |
| `STAGE5_STAGE6_CLOSURE.md` | `5F2821E9BAA79CE669DB4DDF175215DABA5A7CA3F3D6D844777F5798D67916B6` |
| `release_closure.py` | `DE0C865E4533844C230CF153463798264181C02997B02029454D079E7A87510F` |
| `test_release_closure.py` | `3E499156B4E1A53D728B0DAE3B8BFDFAA2A2E54AFC31BD3CE9A6B83C1C8CB8D5` |

机械检查结果：

- 五份文档本地 Markdown 链接：`broken=0`。
- `KNOWLEDGE_MCP.md`、`STAGE45_EVALUATION_GATES.md` 均为 `lines>120=0`；
  `RESEARCHER_DATA_GUIDE.md` 新增的可复制 PowerShell 示例有 2 条超过 120 字符。
- README 有 28 条超过 120 字符的既有长段；Stage 5/6 runbook 的角色表和命令区有长行。
  这属于源文档排版 P2，不影响 Markdown 渲染、链接或合同语义。
- scoped `git diff --check` 无输出。

### 4.2 CLI 与测试证据

独立 reviewer 验证了以下 CLI surface：

```text
qrh-mcp-acceptance {preregister,run,verify}
qrh-release-closure {derive-gate,verify-gate,certify-stage5,verify-stage5,
                     close-visibility,verify-visibility}
```

独立定向回归命令：

```powershell
cd D:\quant\quant_platform\quant_hub
.\.venv\Scripts\python.exe -B -m pytest -q `
  tests/test_release_closure.py `
  tests/test_knowledge_mcp_real_acceptance.py
```

最终相关定向结果：独立 reviewer 的 authority/失败终态复核为 `18 passed`；执行代理随后以当前
冻结树重跑 MCP 三模块 `59 passed`，并重跑 Stage 5 closure `7 passed`。

执行代理另以隔离进程重跑评论／部署组合 `41 passed, 1 skipped`、评论 CAS 与发布兼容组合
`53 passed`、部署持久化完整模块 `161 passed, 2 skipped`，并验证 public Git boundary `564 files`、OpenSpec strict、UTF-8 strict/no-BOM、
五份文档本地链接及 diff-check 均 PASS。独立 reviewer 与执行代理证据在本记录中分别陈述，
不把任一方的总结替代另一方的实际复核。

## 5. 最终 PASS 范围

以下范围通过：

- 研究员指南入口、章节结构和日常／授权运维边界；
- 论文线索、reviewed evidence import、物化抓取、rights 和失败状态；
- Paper Lab 投递、任务、执行、审核、发布和恢复路径；
- Web/API 路由清单及 CSRF、幂等、ETag、`If-Match`、`expected_version`；
- 数据库、对象区、release、state、audit、lock、MCP mirror 和验收 evidence 位置；
- reference/industry_demo 只读、VM exact-D、active+exactly-one-prior+shared-current-state；
- `^src`→Evidence binding→发布 artifact→MCP mirror/search/get 链；
- real Codex MCP acceptance 的输入、dispatch、receipt 和 authority 语义；
- closure 对旧 self-report、dummy、opaque managed wrapper 的 fail-closed 防线；
- JSON Schema 与 runtime 的 role/assertions/order 结构合同。

以下范围没有被本审核放行：

- 15 个角色的真实 producer/replay adapter；
- Stage 5 certificate 和 Stage 6 visibility receipt 的真实生产签发；
- GitHub Public→Private 修改；
- 新一轮生产 VM handoff、writer 切换或 D ingress；
- 任何把测试 fixture、managed wrapper 或 fake-only DS/MCP 当成真实现场证据的做法。

## 6. Stage 5 adapters 未完成事实

`release_closure.py` 当前保留 15 个 required real adapter 的 allow-list，但没有注册任何可将
managed result 提升为 PASS 的 adapter。runtime 会说明缺少的真实 schema/verifier，然后返回
`non-qualifying`。这是有意的安全终态，而不是临时用自报字段冒充完成。

后续每个角色必须消费并重放对应底层 canonical receipt、GitHub API response、VM pointer/manifest、
SQLite bundle、测试报告或独立 dispatch ledger；仅有 authority 字符串、executable hash、dispatch ID、
exit code、payload hash 或 self-hash 均不充分。

`STAGE5_STAGE6_CLOSURE.md` 还记录了 2026-08-31 已授权 writer handoff 在 D service
start/bootstrap comments schema pre-expand 处失败、D ingress 未开放，以及 official rollback
恢复 exact C listener 的事实。本次文档审核只核对该记录与当前 runbook 的语义一致，不把它提升为
Stage 5 PASS 或重新执行任何外部可见动作。

## 7. DeepSeek 审核边界

本轮没有 DeepSeek credential，也没有可调用的真实 DeepSeek transport。结论严格为：

- DeepSeek 真实审核：**未执行**；
- DeepSeek 真实 verdict：**不存在**；
- fake-only／public synthetic harness：可作本地合同测试，但不是 DeepSeek 外部审核；
- 不得在后续报告中把 fake-only PASS、历史 DS 记录或 Codex 结论改写成此次 DeepSeek PASS。

若未来取得合法 transport 和 credential，应以新的冻结文档／代码哈希创建独立审核，不得回填或
修改本记录来制造事后审核。
