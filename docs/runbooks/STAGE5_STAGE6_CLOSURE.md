# Stage 5 / Stage 6 闭合合同与机械门禁

本文只定义公开合同、证据身份和严格顺序，不表示生产 VM、Task Scheduler 或 GitHub
已经执行。任何外部实测缺失时，对应阶段仍是未完成；本地单元测试不得替代现场证据。

## 唯一允许的先后顺序

1. 仓库仍为 Public 时，先冻结 exact commit SHA、release manifest、snapshot 与公开 CI
   观察；工作树不洁、CI 非 exact SHA 或任何身份不一致均停止。
2. 完成 Stage 0–4 前置门禁，再依次完成 6.1 全局回放、6.2 失败路径、6.3 snapshot
   身份、6.4 独立验证、6.5 state compatibility。后一步不得为前一步补证。
3. 在 maintenance window、traffic fence、writer fence、off-host bundle 和最终 checkpoint
   均已固定后，才允许设计 active-D 空根演练。当前代码只有
   `qrh-active-d-maintenance-drill-plan/v1` inspect-only skeleton；它固定 `.240` 与 exact
   `D:\quant\quant_platform`，且 `destructive_apply_enabled=false`。调用拒绝函数也只会
   fail closed，不存在删除 executor。
4. 只有 active-D 的空根前置、物化、closure、state restore、service、Web/API、search/MCP、
   writer fence、write-set、active identity 和独立验证均成为不可变证据后，才可完成 6.6。
   当前 `qrh-recovery-finalize-plan/v1` 只接受上述有序证据身份，且
   `finalize_enabled=false`；没有 production receipt producer，不能把旧的四个调用方布尔值
   当成最终恢复证据。
5. 6.6 真实 D-prior rollback 通过后，生成
   `qrh-measured-prior-release/v2`，固定 active R、不同 ID 且不同 manifest 的 prior R，
   并通过固定 artifact locator 解引用 canonical `qrh-d-prior-rollback-receipt/v1` 原始 bytes。
   rollback 的 prior activation、health、writer fence、active restore 四项必须全真，且 receipt
   时间不得晚于 measurement。每日 state-only job 只从
   `<RECOVERY_ROOT>\state-only\control\measured_prior_release.json` 读取其 canonical bytes；
   active 不同、prior 与 active 相同、prior 没有 retained verified closure 或对象哈希不符
   均 fail closed。
6. 6.7 GC 报告必须同时列出 active manifest、measured prior manifest 与 binding SHA；
   measured prior 必须已经出现在 retained closure 扫描结果中。报告永远
   `deletion_authorized=false`，不能授权清理。
7. 依次完成 6.8 质量报告、6.9 state-only Task Scheduler 真实安装/首轮/RPO/retry 验收、
   6.10 identity graph lint。锁冲突必须生成独立失败观察与 alert，不能因另一实例正在运行
   而静默返回。
8. 上述所有证据完成后，仓库仍须保持 Public，最后生成唯一 Stage 5 certificate。证书完成
   之前不得切换 visibility；证书本身也不得反向充当任一 gate 的证据。
9. 只有 Stage 5 certificate 验证通过后，才依次执行 Public→Private、重新读取 Private
   plan/actions/branch/environment/publish controls、运行 exact-SHA Private CI、执行
   `candidate_only` no-switch 验证、复核 active/activation receipt set/writer authority 均未变，
   最后由独立 verifier 签发 visibility-closure receipt。Private candidate 不得激活 release。

## Stage 5 certificate

公开 schema 为 `config/stage5_release_certificate.schema.json`，运行时 producer/verifier 为
`quant_hub.ops.stage_closure`。`qrh-stage5-release-certificate/v3` 是 closed schema。producer 与
verifier 都必须从同一固定 `DirectoryEvidenceResolver` 解引用 locator、重算原始 bytes SHA-256、
拒绝非 canonical JSON，并调用各对象的分类 verifier。resolver 只接受单链接 regular file，且在
同一打开句柄上读取并复核 read 前后 handle/path file identity、link count、size 与时间；hardlink、
reparse 或 resolve→read 换件都不是 authority bytes。调用方提交的同名 ID、hash 或 pass 没有
权威性。证书至少绑定：

- 证书签发时仍为 Public 的 repository observation 与 full 40 位 commit SHA；
- exact `release_id / manifest_sha256 / snapshot_id`；
- 与 active 不同的实测 D-prior、measurement binding 与 rollback evidence；
- 最终 bundle、RM、checkpoint、failure-domain attestation 和 recovery receipt；
- 唯一 `\QuantResearchHub\StateOnlyBackup` 的 fixed task authority、v5-raw-xml-bound candidate
  contract、导出 XML 与 acceptance evidence；task authority 的 repo/commit/tree/release 和
  全部 exact locators 必须再次与证书核心对象交叉核对；
- 固定、有序、无重复的 0–4 / 6.1–6.10 gate evidence 和三份 runbook evidence；
- 从全部已验证对象派生的 repository/commit/release/D-prior/final recovery/task 字段；
- 从完整 material 派生的 `certificate_id`，以及 canonical `certificate_sha256`。

缺字段、多字段、重排 refs、raw bytes/hash 不同、locator 逃逸、分类 verifier 失败、gate
subject/binding 不一致、依赖晚于 gate/证书或 Public 观察缺失均拒绝。`status=pass + report_sha256`
这类 generic gate 永久没有权威性；每一个 gate 都必须注册其真实 canonical producer artifact 和
分类 verifier 并由 certificate 重放。当前仍缺少这些现场 producer/verifier，因此 certificate
明确 fail closed，公开测试不得构造正向证书。Producer 不执行 VM、Scheduler 或 GitHub 操作。

Artifact locator 不是调用参数。v3 固定使用：`stage5/repository_public_observation.json`、
`stage5/release_manifest.json`、`stage5/d_prior/rollback_receipt.json`、
`stage5/final_recovery/{recovery_manifest,checkpoint_manifest,failure_domain_attestation,recovery_receipt}.json`、
`state-only/control/{measured_prior_release,scheduled_task_authority,scheduled_task_candidate,scheduled_task_inspection}.json`、
`stage5/gates/<exact-kind>.json` 与 `runbooks/<exact-kind>.md`。visibility 固定使用
`stage5/stage5_release_certificate.json` 和 `visibility/<exact-kind>.json`；等价内容换一个 locator
也必须拒绝。

## Visibility closure receipt

公开 schema 为 `config/visibility_closure_receipt.schema.json`。
`qrh-visibility-closure-receipt/v3` 必须通过 artifact ref 读取完整 canonical Stage 5 certificate
bytes，并再次运行完整 certificate verifier；repository/commit/release 只能从验证后的证书派生，
不能由调用方提供。随后按严格时间顺序绑定真实
Public→Private transition、Private 控制面五类观察、exact-SHA CI success、
`candidate_only / candidate_validated` event、no-switch 前后身份和独立 verifier。

Private candidate 的 release/manifest/snapshot 必须逐字段等于证书 release；
`active_before`、`active_after` 与证书 release 也必须逐字段相等。activation receipt set 与 writer authority
的前后 SHA 也必须相等。Receipt 是 append-only evidence，不是 active pointer，也不授予
发布或 writer 权限。

## Scheduler canonical contract

Candidate 与真实 inspect 必须共同证明：

- 唯一 task identity，host role 为 attested recovery host，绝不在生产 VM 注册；candidate 绑定
  当前 recovery root 的完整 failure-domain attestation bytes/hash 与 recovery host-facts hash；
- 每日一次、恢复主机本地浮动时区、local `StartBoundary=03:00:00`、Enabled；
- StartWhenAvailable、RunOnlyIfNetworkAvailable、IgnoreNew、`PT2H` execution limit；battery、idle、
  wake、on-demand、hidden、hard-terminate 与 priority 全部显式闭合，不接受隐式默认行为；
- 失败后每 15 分钟重试、最多 3 次；
- S4U、Limited、无存储密码；principal 只绑定当前进程 token 的真实 Windows SID SHA-256，
  禁止使用 `USERDOMAIN/USERNAME` 环境变量或调用方覆盖值；
- fixed canonical task-authority 预授权的 repository/commit/tracked tree/release/snapshot，及
  project/config/operational/recovery/operational Python/failure-domain attestation 六个 exact
  locator；四类 roots 均为 strict existing 且互不重叠，固定 operational Python、其原始
  executable SHA-256、config SHA-256、argv 与 working directory 逐字段等于 authority；门内还会
  重放 `RuntimePublishConfig.load`，核对 config 的 project、GitHub full name、recovery、operational
  与 attestation locator；
- 同一次 `Export-ScheduledTask` raw XML 中的 strict namespace/version、RegistrationInfo
  Description/URI、唯一 Principal/CalendarTrigger/Exec、完整 Settings allowlist/value，以及从
  规范化 `UserId` SID 派生的 SHA-256。

Inspect 的 PowerShell 边界只返回 `missing` 或同一次 raw XML base64，不读取 `$t` 的语义属性，
也不提供可独立伪造的 verdict/contract/SID/XML hash。Python 从 raw bytes 唯一派生 XML SHA、contract、
SID SHA 和 closed canonical projection，并拒绝 namespace/description/URI 漂移、trigger disabled、
`RandomDelay`、`Repetition`、`EndBoundary`、额外 trigger/principal/action，以及未声明的 settings/Exec
children；artifact 中重复保存的派生字段与 projection 必须由 verifier 重算相等。只有完整解析为 `exact`
时，apply 才能返回 `unchanged` 或 `applied`。Task apply 是外部状态变更，
必须显式 opt-in；本文与本轮公开测试不授权真实注册。

## 不可逆点与当前未闭合项

- active-D 根内容删除是高风险破坏动作。当前 skeleton 明确不可执行；旧 V39
  `prepare-empty` 与 qualification-reset 不能用于已激活 D 根。
- recovery receipt 一旦 append 即成为不可变成功声明。当前 finalize skeleton 明确不可写，
  必须等固定 verifier 能逐件读取并重放所有 evidence artifact 后再实现。
- Task Scheduler apply 和 GitHub visibility transition 都是外部状态变更，只能在现场机械 gate
  通过后按上述顺序执行。
- 因此，只有本地 producer/verifier、schema 和负向门禁通过时，6.6、6.9、Stage 5 certificate
  与 Stage 6 visibility 都不能报告为真实完成。
