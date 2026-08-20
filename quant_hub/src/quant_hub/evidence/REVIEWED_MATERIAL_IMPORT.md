# 已审核论文证据导入与规范化

本链路将离线审核材料送入既有 Evidence 事实边界。导入器不直接改写状态表，也不把身份相似、可访问 PDF 或模型判断当成已核验事实。

## 处理边界

1. 对审核清单、原始响应、PDF、逐页文本和总交付收据做字节数与 SHA-256 校验。
2. 由 `EvidenceExpansionService` 创建或复用 resolution case 与 provider request。
3. provider adapter 解析 exact identifier 响应，保存 attempt、observation 与 resource offer。
4. 只有独立审核通过的 identity decision 才能把 case 推进到 `identifier_verified`。
5. 只有权利决策明确允许受管本地存储的 PDF，才能进入 acquisition、fetch audit、内容寻址对象区和 `paper_resource`。
6. reviewed builder 保留来源元数据、审核层级、事实边界与页级证据定位器。
7. 0005 canonicalization receipt 原子创建或复用 paper、绑定 Archive，并更新只读投影视图。
8. release manifest 纳入 derivation、receipt、resource attachment、方法关联、全文 locator 与事件状态。

importer 内的 SQL 仅用于读取候选、既有状态和回放结果；所有状态变更均经过既有 service/repository 边界。

## 官方摘要与本地全文的证据边界

官方摘要是来源证据，不是 PDF 资源的附属字段。每个通过审核的 arXiv 条目都从已冻结的官方 Atom 响应中精确提取 `atom.entry.summary`，按照 `xml.etree.ElementTree:atom.entry.summary:itertext:regex-whitespace-collapse:strip:utf8/v1` 规范化，并在写库前与审核清单中的摘要逐字比较。任一请求收据、响应路径、字节数、SHA-256、HTTP 状态、规范化文本或标识符不一致，静态计划即失败关闭，候选数据库不会被打开。

摘要定位器保留实际 Atom 文件相对于工作区的规范路径、文件 SHA-256、文件字节数、字段名、规范化合同、规范化摘要 SHA-256 与字节数、arXiv 标识符和标题；官方摘要页仅作为独立的旁证描述，同样绑定路径、哈希、字节数与 URL。数据库中的摘要行固定使用 `resource_id=NULL`，因此来源摘要不会因为 PDF 可用而被错误升级为全文证据，也不会因为 PDF 权利受限而丢失。

本地 PDF、资源附件、阅读任务和全文结论仍受独立权利决策约束。29 篇 reviewed arXiv 均应保留官方摘要；其中 26 篇可另外绑定受管 PDF 与阅读任务，P034、P137、P143 只能保留官方摘要、元数据和外链，不得产生资源附件、阅读任务或全文结论。当前 V6 总回放的守恒合同固定为：官方摘要共 53 条（旧基线 18 + reviewed arXiv 29 + reviewed Crossref 6）、无资源摘要 53 条、reviewed arXiv 摘要 29 条、reviewed Crossref 摘要 6 条、metadata-only 摘要 3 条、摘要/资源耦合违规 0 条、受限三篇来源证据违规 0 条。Crossref 摘要仅表示出版方提交给 Crossref 的来源主张，不得冒充本地全文审读结论。

canonicalization receipt 的结果哈希、`metadata_selected` 事件和 commit 事件均绑定摘要 ID 与摘要 SHA-256；幂等重放必须逐字段验证数据库摘要、定位器、来源 URN、receipt 哈希和事件绑定，不能只依赖“记录已存在”。

## 当前冻结输入

- Crossref：32 条审核候选中，31 条 exact DOI 身份通过；P095 因工作论文与期刊版本仍有歧义而默认排除。
- DOI 审核覆盖：独立 verifier 的 32 条逐项 verdict 必须与 DOI、审核层级和本地来源声明一致。
- arXiv：总解析种子含 29 篇，其中 22 篇为正式引用，7 篇为关联方法来源；29 篇的官方 Atom 摘要均须在写库前完成精确核验。另有 P004、P126、P169、P170 四个版本族信号保持未合并、不可导入。
- arXiv 全文：29 份 PDF、669 页、135 条证据定位器。每个带 evidence 的研究陈述都必须绑定 PDF SHA-256、提取文本 SHA-256，以及全部物理页的逐页文本 SHA-256。
- 权利闭集：26 份 PDF 可进入受管本地证据存储；P034、P137、P143 因 PDF 内嵌限制声明，仅保留官方摘要、元数据与官方外链。
- 开放许可：P120、P145、P171 的官方摘要页明确给出 CC BY 4.0；本地存储和服务必须保留作者与标题署名、官方来源、许可链接及修改说明。
- 补充开放全文：独立审核对 34 个未闭合候选逐项取证，只放行 P094、P097、P114、P151 四份具备可核验开放许可的 PDF，其余 30 项保持明确失败关闭；四份资源必须同时绑定审核总表、文件清单和第二审核结论，缺一不可导入。
- U055：GET、PDF magic、MIME、字节数与逐页文本均已核验，但 PDF 内嵌的 IEEE 使用限制与许可元数据冲突。该项必须记录成功传输与失败关闭的权利/获取状态，不得创建本地资源或全文结论。

Crossref 权利清单必须是覆盖 32 条身份决策的唯一闭集；每条的 best acquisition、rights status、license classes、HEAD probe 数量和虚假获取声明必须与独立 identity verdict 一致。总回放进一步固定权利清单为 69,079 bytes / `6e6e462d…a93b3e`，U055 post-GET 清单为 11,901 bytes / `d17c1e01…d36df`，并强制计划集合为 `rights_ready=[]`、`fulltext_failed_closed=[U055]`。普通 metadata-only 论文不能被清单单方面升格为可获取 PDF。

总交付的 `files` 索引、`import_sequence`、解析种子和方法来源输入必须在 path、schema、bytes、SHA-256 四个字段上相互一致。任何陈旧自引用、缺失独立 PASS、未关闭的 release-blocking defect 或生产库边界不明，都会在打开候选数据库前失败关闭。

当前唯一可消费的 arXiv 放行件是 `independent_arxiv_verifier_v2/verdict_v4.json`（89,445 bytes，SHA-256 `9977c3fc8ae48a8f7b3fd7c596442c33db7c005de39893b0acebdd621c2c7fc0`），且必须绑定 21,542 bytes / `ff76c50f…e54bd` 的总交付 subject。V1、V2、V3 以及缺失 verdict 均不可兼容放行；相关检查必须先于数据库迁移和运行目录写入。

去重预期由独立审查在回放之外冻结为 `evidence_replay_review/dedup_expectation_v1.json`（30,654 bytes，SHA-256 `5a7958c3…812a0`）。其合同固定旧基线 18、待处理 60、创建 60、复用 0、最终 canonical 78；回放只逐行消费并比对，不以实际折叠结果反推期望值。

## 使用方式

默认只运行静态计划，不打开数据库：

```powershell
$env:PYTHONPATH='src'
python tools/import_reviewed_evidence_materials.py
```

写入必须显式指定隔离或候选运行根：

```powershell
$env:PYTHONPATH='src'
python tools/import_reviewed_evidence_materials.py `
  --apply `
  --var-root D:\quant\quant_platform\project_state\workers\reviewed-import-candidate
```

最终总回放还要求运行根是 `project_state/workers/evidence_canonicalization_bridge` 的全新直接子目录：

```powershell
$env:PYTHONPATH='src'
python tools/replay_reviewed_evidence_total.py `
  --var-root D:\quant\quant_platform\project_state\workers\evidence_canonicalization_bridge\full-total-replay-reviewed
```

该运行只能在代码冻结通过独立审核后启动，并且必须使用全新的直接子目录；既有 V4 候选保持只读，不得覆盖、补写或装配。工具依次回放旧 18 篇基线和全部已审核新增材料，各执行两次并比较 snapshot；随后检查 SQLite 完整性、官方摘要守恒、release prepare/publish 幂等性、Evidence HTML/API、P033 官方卷期页码、P034/P137/P143 权利边界、U055 失败关闭边界，以及已知生产数据库主文件、WAL、SHM、rollback journal 在回放前后的完整字节指纹。`--live-database` 不能改指到无关文件。

最终输出还包含独立的 `quiescent_candidate`：新 replay 关闭连接并完成 checkpoint 后，以 SQLite backup 生成仅含 main DB 的静止副本，复制 `research_papers` 资源树，逐表比对逻辑内容并验证数据库与 `objects` 的双向闭包。候选内 `exports/reviewed_total_gate_receipt.json` 显式绑定独立 arXiv verdict、总 manifest、seed、Crossref 独立审核、开放 PDF 双重审核、权利材料、两类官方摘要投影与 dedup expectation；该文件也纳入候选安全树密封。receipt 的 `release_expectation` 是 14 项精确合同：canonical papers 78、verified resources 48、canonicalization receipts 60、formal receipts 53、method receipts 7、blocked acquisitions 4、associated-method ledger occurrences 547、full-text conclusion support 26、official abstract excerpts 53、reviewed arXiv official abstracts 29、reviewed Crossref official abstracts 6、core conclusions 53、reviewed open-PDF resources 4、displayable Archive relation papers 63。assembly 必须用真实数据库、资源对象和 Archive 展示关系逐项复核，不能以 receipt 自证。全部输入在导入后、冻结前、冻结后重算 static plan 和文件身份，任一 TOCTOU 变化都会使该次候选失败。候选出现 `-wal`、`-shm` 或 `-journal` 即失败，不通过删除 sidecar 伪造静止状态。

## 类别、引用与方法来源

- arXiv 官方分类码和 Crossref subject/work type 作为来源类别保存，不由界面宽类覆盖。
- `qrh-reviewed-broad-domain-map/v1` 只做保守的确定性宽类映射；无法确定时进入“其他/待分类”，不猜测。
- `paper_category_assignment_detail` 保存主宽类、映射策略和 assertion provenance。
- formal citation 绑定对应来源候选的全部 ledger occurrence。
- associated method origin 只写 `evidence_associated_method_relation`；原方法线索及其 `rejected_non_paper` binding 保持不变。
- UI/API 分开显示 `resolved_citations` 与 `associated_method_origins` / `associated_method_origin_ledger_occurrences`。

## 验证入口

- `tests/test_reviewed_material_importer.py`：真实 Crossref/arXiv 材料的隔离端到端、权利边界、总交付内部收据、P033、U055 与双重重放测试。
- `tests/test_evidence_canonicalization.py`：事务回滚、receipt 重放、metadata-only、全文 locator 与方法关联语义。
- `tests/test_evidence_web.py`：Evidence HTML/API、资源直达与明确空状态。
- `tests/test_evidence_providers.py`：exact identifier 和真实 Crossref 重复 link claim 聚合。
- `python -m unittest discover -s tests -p 'test_evidence*.py'`：Evidence 全回归。
