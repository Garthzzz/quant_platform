# REVOKED AS RELEASE/AUTHORITY EVIDENCE

> **撤销声明（2026-08-31 追加勘误）：** 本记录只保留为历史审核快照，不再是 release、
> Stage 5/6、anti-forgery、handoff、visibility 或任何生产 authority 的有效证据。此前的
> “Stage 5/6 防伪造边界 PASS”“最终 PASS”及可能被理解为最终放行的结论全部撤销。
> 本文件记录的测试最多说明当时已建模输入上的行为；它们不证明存在仓库／普通用户无法
> 伪造的外部信任根，也不证明完整运行时、唯一进程父子链或 authoritative receipt。

## 研究员数据指南与 Stage 5/6 文档历史审核记录（2026-08-31）

## 1. 审核结论

本记录覆盖以下文档及其直接代码、CLI、schema 和测试入口：

- `docs/runbooks/RESEARCHER_DATA_GUIDE.md`；
- `quant_hub/README.md` 的研究员入口；
- `docs/runbooks/KNOWLEDGE_MCP.md`；
- `docs/runbooks/STAGE45_EVALUATION_GATES.md`；
- `docs/runbooks/STAGE5_STAGE6_CLOSURE.md`；
- `quant_hub.knowledge_mcp` 的真实 Codex 验收入口；
- `quant_hub.ops.release_closure` 及四份 closure JSON Schema。

历史审核当时写下两个层次；经本次勘误，只有第一项可作为“当时的文档事实核对”参考，
两项都不是当前 release/authority 放行：

1. **历史文档事实核对。** 当时审核认为抓取、导入、Paper Lab、Web/API、MCP、数据库和
   数据文件位置、reference 只读边界及生产 VM exact-D 边界与当时代码和配置一致；后续仍须
   以当前源码和新哈希复核，不能沿用本记录的 `PASS` 字样。
2. **原“Stage 5/6 防伪造边界 PASS”已撤销。** 当时 15 个角色都没有真实分类 replay
   adapter；runtime 对 managed wrapper 返回 `non-qualifying`，只说明部分已知自报路径在所测
   输入上 fail closed。它不证明不可伪造，也不能签发 Stage 5 certificate 或 visibility receipt。

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

### 3.3 第三轮历史记录：当时事实核对与有限 fail-closed 检查

第三轮当时重新核对命令、路径、API、数据库清单和 Stage 5/6 文档，留下如下历史结果；
本节的 `PASS` 均按文件顶部撤销声明解释，不是当前放行：

- `RESEARCHER_DATA_GUIDE.md` 的抓取、导入、Paper Lab、API、MCP 和数据位置事实当时记为
  `PASS`（现已失效，仅供历史定位）。
- `quant_hub/README.md` 已提供明确二级入口，并区分开发／候选外置状态和 VM exact-D。
- `KNOWLEDGE_MCP.md` 与 `STAGE45_EVALUATION_GATES.md` 已同步真实 Codex runner；
  fake 或 real/fake mixed 固定属于 `PUBLIC_SYNTHETIC_NON_QUALIFYING_GATE`。
- 两臂都是 `REAL_CODEX_EXEC` 且完整重放通过时，authority 仍固定为
  `REAL_CODEX_EVIDENCE_REPLAY_NON_AUTHORITATIVE`；当前缺独立可信 attestation/receipt 签发方，
  因而该 receipt 只能证明功能回放，不能成为 Stage 5 资格证据。
- Stage 5/6 runbook 已列出十个 Stage 5 gate、五个 Stage 6 gate、
  `certify-stage5`、`verify-stage5`、`close-visibility` 和 `verify-visibility` 的完整顺序。

第三轮还发现旧 closure observation 可自报 subject/facts/observer，dummy artifact 也可能满足
完整性检查。修正后：

- observation v2 不再携带可自报 subject、facts、observer 或 PASS；
- subject 从 actual active pointer、prior binding 和两个 release manifest 重建；
- 所测 old v1 self-report、dummy schema 和 managed wrapper fixtures 被拒绝；
- real MCP public verifier 由单独代码路径重放 evidence root，但仍在同一本机信任域内；
- 15 个角色的真实 adapter 缺失时，无条件 `non-qualifying`，且不创建 gate/certificate/receipt；
- tracked schema 已约束 role→result schema、role→exact assertions，以及 Stage 5/visibility
  evidence 的精确角色顺序。

这些修正减少了当时已经识别的 self-report/dummy 冒充路径，但没有建立外部信任根，也没有
覆盖所有加载输入或补出 15 个真实 adapter；因此不能表述为“关闭了伪造 PASS 风险”，生产
签发仍未完成。

### 3.4 当前树补充二审：研究员可执行性与信任措辞

当前树的补充二审先判定 `REVISE`，发现三项文档缺陷：production API 示例没有先通过
`/login` access gate；Paper Lab 把配置 registry 下的 RSA 签名验证过度表述为独立 reviewer；
写 API 清单缺少多数请求字段、GET→ETag/版本前置和成功／失败状态。

修正后，独立只读 reviewer 逐项回查当前路由、Pydantic 合同、Paper Lab service 和 access
gate，确认：示例先 POST `/login` 并复用同一 cookie session；Paper Lab 明确代码不证明调用者
独立、外部密钥保护或信任根；所有列出的写接口均给出最小 JSON、并发前置和状态码，且
`research-links` 的实际成功状态为 `200`。该定向文档复核结果为 `PASS`，但只表示指南与当前
代码一致，不恢复本文件顶部已撤销的 release/authority 结论，也不构成真实 DeepSeek 审核。

## 4. 历史机械验证快照（非 authority）

### 4.1 文档哈希与结构检查

当时独立反查记录了以下 SHA-256。文档后续已经修订，这些值仅用于定位历史快照，不能核验
当前文件，也不能作为 release manifest、签名或 authority receipt：

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

## 5. 历史核对范围与撤销后的边界

历史 reviewer 当时认为以下文档事实与所查代码一致；这里不再使用“最终 PASS”，也不把它们
提升为 release/authority 证据：

- 研究员指南入口、章节结构和日常／授权运维边界；
- 论文线索、reviewed evidence import、物化抓取、rights 和失败状态；
- Paper Lab 投递、任务、执行、审核、发布和恢复路径；
- Web/API 路由清单及 CSRF、幂等、ETag、`If-Match`、`expected_version`；
- 数据库、对象区、release、state、audit、lock、MCP mirror 和验收 evidence 位置；
- reference/industry_demo 只读、VM exact-D、active+exactly-one-prior+shared-current-state；
- `^src`→Evidence binding→发布 artifact→MCP mirror/search/get 链；
- real Codex MCP acceptance 的输入、dispatch、receipt 和 authority 语义；
- closure 对所测旧 self-report、dummy、opaque managed wrapper 输入的有限 fail-closed 行为；
- JSON Schema 与 runtime 的 role/assertions/order 结构合同。

以下范围从未被本审核放行；文件顶部撤销声明还明确撤销了历史 Stage 5/6 anti-forgery 与
“最终 PASS”表述：

- 15 个角色的真实 producer/replay adapter；
- Stage 5 certificate 和 Stage 6 visibility receipt 的真实生产签发；
- GitHub Public→Private 修改；
- 新一轮生产 VM handoff、writer 切换或 D ingress；
- 任何把测试 fixture、managed wrapper 或 fake-only DS/MCP 当成真实现场证据的做法。

## 6. Stage 5 adapters 当前未完成事实

`release_closure.py` 当前保留 15 个 required producer/replay 合同。现已实现其中
`identity_graph_negative_fixtures` 的固定 corpus、真实本机 linter 重放 producer 和专用 adapter；
它把 exact active/binding/two manifests 与唯一 fixed corpus 绑定到报告，并在派生 gate 时重新
执行十个正反例。该报告的 authority scope 明确是
`LOCAL_FUNCTIONAL_CLOSURE_NOT_INDEPENDENT_TRUST_ROOT`，只证明当前本机函数闭包，不证明 MCP、
隔离 verifier 或外部信任根。

其余角色仍没有可放行的真实 adapter；旧 managed wrapper 会说明缺少的真实 schema/verifier 并
返回 `non-qualifying`。因此 Stage 5 certificate 仍不可签发。这是有意的安全终态，不是临时用
自报字段冒充完成。

后续每个角色必须消费并重放对应底层 canonical receipt、GitHub API response、VM pointer/manifest、
SQLite bundle、测试报告或独立 dispatch ledger；仅有 authority 字符串、executable hash、dispatch ID、
exit code、payload hash 或 self-hash 均不充分。

还必须收窄“runtime closure”的解释。当前 launch/acceptance 合同只 pin 原生 `codex.exe`、
原生 MCP launcher、launcher 记录的 `python.exe`、client config，以及明确声明的 package roots
（例如 `quant_hub` package 与 `.dist-info`）。它不 inventory 或证明 `PYTHONPATH` 父目录、
Python home、标准库、DLL、`.pth`、`sitecustomize`、OS loader 或 PowerShell；也不证明唯一父子
进程链。descendant process image 只是诊断事实，不能提升为 authority。

OpenAI Authenticode 只用于核验被启动 `codex.exe` 的发布者签名与文件身份；它不是本次
campaign receipt 的 countersignature，也不表示 OpenAI 审核或签发了验收判定。

未来 authoritative receipt 至少需要以下共同合同，且当前尚未实现：

1. 普通仓库写权限、运行用户和被测进程均无法导出、替换或伪造的外部信任根；
2. verifier 为每次运行发出的至少 256-bit 密码学随机 nonce challenge，并绑定 run、subject、
   冻结输入身份、签发域和有效期；
3. 对版本化 canonical bytes 的 domain-separated signature，覆盖 nonce、subject、artifact/manifest
   hashes、判定、签发方身份和有效期，并把 MCP acceptance、Stage 5 与 visibility 分域；
4. 在受信事务内完成签名/信任链/撤销/有效期/subject 校验和 nonce 消费的原子
   `VerifyAndConsume`，使用 CAS 防止并发重复消费；
5. 已消费 nonce 永不再次放行，验证与状态提交之间不得重新信任可替换路径，从而关闭重放与
   TOCTOU；跨步骤只能绑定前序 canonical receipt hash 和 CAS 版本。

没有上述合同和负向测试时，本机 manifest/散列、磁盘 receipt、self-hash、PID、process image
或 Authenticode 结果均不能单独成为 authoritative receipt。

`STAGE5_STAGE6_CLOSURE.md` 还记录了 2026-08-31 已授权 writer handoff 在 D service
start/bootstrap comments schema pre-expand 处失败且 D ingress 未开放。失败 receipt 中的
`legacy_rollback_succeeded=true` 只表示当次恢复路径曾在原执行会话内观察到 exact C listener；
该 detached 进程没有跨 OpenSSH 会话持续存活，后续生产连续性由同一精确 executable/hash/argv
经 CIM 重新创建并跨会话复核。该事实既不是 handoff 成功，也不能提升为 Stage 5 PASS 或其他
authority；本次文档审核不重新执行任何外部可见动作。

## 7. DeepSeek 审核边界

本轮没有 DeepSeek credential，也没有可调用的真实 DeepSeek transport。结论严格为：

- DeepSeek 真实审核：**未执行**；
- DeepSeek 真实 verdict：**不存在**；
- fake-only／public synthetic harness：可作本地合同测试，但不是 DeepSeek 外部审核；
- 不得在后续报告中把 fake-only PASS、历史 DS 记录或 Codex 结论改写成此次 DeepSeek PASS。

若未来取得合法 transport 和 credential，应以新的冻结文档／代码哈希创建独立审核，不得回填
本记录来制造事后审核。为防止历史结论继续被误用，允许在文件顶部或末尾追加带日期、理由和
证据指针的 `REVOKED`／`CORRECTION` 声明；这类声明只能收窄或撤销旧结论，不能追溯授予 authority。

## CORRECTION（2026-09-01，仅收窄历史“当前事实”）

本文件第 208–218 行关于 adapter 数量的“当前”陈述已经失效。当前除
`identity_graph_negative_fixtures` 外，还实现了 `revocation_surface` 的真实本地 producer/replay
adapter；后者 authority scope 固定为
`LOCAL_FUNCTIONAL_CLOSURE_NOT_EXTERNAL_TRUST_ROOT`。其余依赖外部系统或可信 MCP 的角色仍未取得
权威 evidence，Stage 5 certificate 仍不可签发。此勘误不恢复本文件顶部撤销的 PASS/authority，
当前研究员文档审核改由 `RESEARCHER_DATA_GUIDE_REVIEW_20260901.md` 的 exact hash 记录承接。
