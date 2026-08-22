# Stage 5 / Stage 6 公开合同测试冻结报告（2026-08-23，v5）

## 结论与边界

本轮公开、离线、非私密合同回归共完成两组稳定矩阵：Stage 5/6 相邻闭包 115 项，排除仍在
并行移动的 DS external v3 后的共享工作树集成回归 128 项，均通过。未连接生产 VM、GitHub、
Task Scheduler 或真实外部模型，未读取
凭据、sealed/private qrel/trace/stage evidence，也未产生任何生产完成声明。

本报告冻结的是当前工作树中的公开代码、schema、反例和 runbook bytes，不是 exact commit-SHA、
生产 release certificate 或 visibility receipt。当前 Stage 5 certificate 必须且确实保持不可签：
全部 required gate 中任一个尚无具体 canonical producer artifact + 分类 verifier 时，
`build_stage5_release_certificate` 明确 fail closed；generic `status=pass/report_sha256` 不再有 fallback。

Round4 仅修正 SID parser 的低风险边界：最终 bytes 已重新通过定向 25 项和完整相邻 115 项。
稳定跨组 128 项是紧邻该修订前的 Round3 基线；由于 DS external v3 仍在移动，Round4 不把旧的
128 项结果冒充 exact-bytes 集成放行，待主线冻结 DS 后统一重跑完整矩阵。

## 冻结测试入口与结果

在项目根执行，环境为 `PYTHONPATH=$PWD;$PWD\quant_hub;$PWD\quant_hub\src`、
`PYTHONDONTWRITEBYTECODE=1`、`PYTHONUTF8=1`。

```powershell
python -B -m unittest `
  tests.test_stage_closure `
  tests.test_state_only_backup `
  tests.test_release_identity `
  tests.test_failure_domain `
  tests.test_recovery_bundle `
  tests.test_publish_runtime `
  tests.test_deployment_controller `
  tests.test_publish_adapters -v
```

| 测试入口 | 数量 | 结果 |
|---|---:|---|
| `test_stage_closure.py` | 8 | OK |
| `test_state_only_backup.py` | 17 | OK |
| `test_release_identity.py` | 13 | OK |
| `test_failure_domain.py` | 5 | OK |
| `test_recovery_bundle.py` | 22 | OK |
| `test_publish_runtime.py` | 12 | OK |
| `test_deployment_controller.py` | 18 | OK |
| `test_publish_adapters.py` | 20 | OK |
| 合计 | 115 | OK |

共享工作树集成命令如下；它把 Stage 4/5 评测、MCP、DS v3 fake-only 与本轮 Stage 5/6
合同放在同一 Python 进程矩阵中运行。现有 semantic partition 回归可只读使用其既有 fixture，
但没有修改 reference。

```powershell
python -B -m unittest `
  tests.test_knowledge_retrieval_eval `
  tests.test_knowledge_public_quality `
  tests.test_knowledge_mcp `
  tests.test_knowledge_mcp_stress_public `
  tests.test_ds_review_harness `
  tests.test_knowledge_semantic_partition_provider `
  tests.test_stage_closure `
  tests.test_state_only_backup -v
```

结果：`Ran 128 tests ... OK`。另已完成全部公开 JSON schema 解析、
`stage_closure→state_only_backup` 与反向 import smoke、`git diff --check`，均通过。

含 `tests.test_ds_review_external_v3` 的当前全量矩阵为 156 项。最终重跑的唯一失败是该并行分支
新增的 32 进程 ledger 初始化用例：所有子进程均在 `ExternalCampaignLedgerV3._validate_schema`
报告 `external campaign ledger identity is invalid`。该调用链不进入 Stage 5/6 代码；本轮按文件
所有权没有修改 DS，待 DS 分支冻结并整合后必须重新运行完整 156 项。此前该 156 项矩阵曾在
Round3 最终 SID normalization 小改之前通过一次，不能替代整合后的新验收。

## 本轮新闭合的机械反例

- 在全新临时 evidence root 内手工写入 11 个 generic `status=pass` gate，即使 subject/hash
  自洽，也因没有 registered concrete producer/verifier 而不能生成 certificate。
- Scheduler inspection v2 不再拼接 `$t` CIM 属性和另一次 XML 观察。PowerShell 只返回同一次
  `Export-ScheduledTask` raw XML base64；Python 从 raw bytes 重算 XML SHA、规范化 SID 后重算
  SID SHA，并构造 closed projection。namespace/version、RegistrationInfo description/URI、
  principal/trigger/action cardinality、完整 Settings/Exec allowlist/value 任一漂移均不是 exact；公开
  反例覆盖 `RandomDelay`、`Repetition`、`EndBoundary`、额外 principal/action/trigger、battery/idle/
  wake/on-demand/unknown setting、伪 projection 与旧式自报 verdict。candidate 已升级为
  `qrh-state-only-scheduled-task/v5-raw-xml-bound`，inspection 为
  `qrh-state-only-task-inspection/v2-raw-xml`；残留的私有 v2 mixed-observation adapter 已改成
  无条件 fail-closed tombstone，源码中也不再保留 `$t` 语义观察路径。
- SID canonicalizer 接受 1–15 个 subauthority；公开边界反例证明 14/15 合法、16 拒绝，且大小写、
  首尾空白与十进制前导零 canonicalize 后的 SHA-256 与 canonical SID 完全一致。
- Scheduler task authority 固定为
  `state-only/control/scheduled_task_authority.json`；其 canonical v1 bytes 预绑定
  repository/commit/tracked tree/release/snapshot、project/config/operational/recovery/executable/
  failure-domain attestation exact locator、config/executable bytes 和 attestation SHA-256；门内
  还经 `RuntimePublishConfig.load` 重放 protected config 语义。缺 authority、换任意已存在 temp
  project、配置不可解析、篡改 candidate path，或 authority 属于另一 commit，均 fail closed。
- `DirectoryEvidenceResolver` 拒绝 hardlink/多链接文件；在同一打开句柄上重算并比较 read 前后
  handle/path file identity、link count、size、mtime、ctime。根外 hardlink 和模拟 read 中换件均拒绝。
- visibility 必须重新运行完整 Stage 5 verifier；在 Stage 5 gate producer 未闭合时不能以伪造的
  certificate envelope 进入 Public→Private receipt。
- active-D maintenance 与 recovery receipt finalize 仍只有固定禁用的 inspect-only skeleton，
  没有删除入口或成功 receipt producer。

## 冻结文件 SHA-256

```text
2952083f10ed08b8f9a89996524ecaa8a7aea3115496a1aa854e560cbb5af0ed  quant_hub/src/quant_hub/ops/stage_closure.py
211eaf13c62662928f8f9761a4c4646122c56976996c74f11ad7a2f62392ab73  quant_hub/src/quant_hub/ops/state_only_backup.py
b62e7c18f83764ac6a7c6a9874764b4ee541ba267ef8c2f97b2b5b287acc7668  config/stage5_release_certificate.schema.json
67df4c6244eb414948dd6fc3f321962c2914bf710eb461b5186731e3540cabbd  config/visibility_closure_receipt.schema.json
3792ebd9659c574514fa6c2b17f69345e3073e487d3ca47fbe28c23d5c40b620  config/state_only_task_authority.schema.json
6e8a0e2e49a146cc941ab3278cbb501614991a8718abf5c267bf466abe2a0daa  quant_hub/tests/test_stage_closure.py
59bdb9ed03df894f69ec630dc3346f5fb83455d4aec06da54935ba5d3158bf55  quant_hub/tests/test_state_only_backup.py
9fb1ef01ab7e2ebd62cc3758afe9ba87a9f5e541e9fc8ff8b51e4a26d8bf3cf1  docs/runbooks/STAGE5_STAGE6_CLOSURE.md
66e2713783f4fb5b3ba9bcb69c4ab51f5bfa27394ff28c64de0403f843fb681c  docs/runbooks/COLD_RECOVERY.md
1c0cb069234feb231a4130e3256fa368e480ba4810631e4c83963fbbe19d4806  docs/runbooks/STATE_ONLY_BACKUP.md
```

任一上述文件后续变化都必须重新运行相应测试并重算本报告。只有所有三组改动合并、工作树
干净、exact commit-SHA 已形成且 GitHub-hosted CI 对该 SHA 成功后，才可开始收集新的现场 gate
artifact。Stage 5 certificate、Public→Private 和 visibility closure 仍必须按 runbook 顺序另行验收。
