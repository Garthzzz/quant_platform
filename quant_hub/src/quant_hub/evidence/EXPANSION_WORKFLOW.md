# Archive Evidence 覆盖扩展工作流

状态：第一阶段基础设施已实现；本文件描述增量解析与获取契约，不把未执行的网络核验或论文入库冒充完成事实。

## 1. 与既有 18 篇回放的关系

`bulk.py` 是已经审核过的旧批次回放器，其 245 个候选、5,181 条引用账本和 18 份 PDF 数量属于该冻结输入包的守恒条件。它继续原样回放，不能被改成一个会随网络结果漂移的增量任务。

新增的 `providers.py`、`expansion.py` 和 research-papers migration `0004` 构成数据驱动的增量通道。该通道不检查“必须等于 18”，每个候选按输入快照独立建 case，可以追加到任意规模。旧批次是历史基线，新通道负责补足剩余候选；两者共用 Evidence 的论文身份、抓取审计、资源登记、引用绑定和 release 机制。

## 2. 事实边界

- Crossref 使用版本化 REST `https://api.crossref.org/v1`。DOI 精确查询可形成强标识符观察；bibliographic query 的 rank 和 score 永远只是观察，不能选择论文身份。Crossref 明确说明 full-text link 不保证访问或复用权，因此这些链接默认进入权利复核。
- arXiv 使用官方 Atom query `https://export.arxiv.org/api/query`。`id_list` 返回且规范号完全一致时形成强标识符观察；title search 仍需人工复核。Atom 中的 PDF 链接只是资源 offer，不等于已经批准下载。
- provider 响应只保存经过边界筛选的结构化字段和完整响应 SHA-256。Crossref abstract 不进入 observation projection；原始响应字节由后续受管对象缓存负责，不在 SQLite 中重复保存。
- provider observation 始终写入 `canonicalization_status=not_canonicalized`。`identifier_verified` 只能来自独立的 `evidence_identity_decision`，而该 decision 的 `canonicalization_effect` 仍是 `none`；创建 canonical paper 和分配 identifier 属于后续 promotion 事务。
- 资源必须先有 `evidence_rights_assessment`。默认策略只对“官方 arXiv 资源 + 该论文明确的、可识别的开放许可 URL”自动批准本地存储；其他情况一律 `review_required`。Crossref link、公开可访问和 HTTP 200 都不构成许可证明。

官方契约依据：

- Crossref REST API 与版本：<https://www.crossref.org/documentation/retrieve-metadata/rest-api/>、<https://www.crossref.org/documentation/retrieve-metadata/api-versioning/>
- Crossref full-text link 权利边界：<https://www.crossref.org/documentation/retrieve-metadata/rest-api/text-and-data-mining/>
- arXiv Atom API：<https://info.arxiv.org/help/api/user-manual.html>
- arXiv 每篇论文许可说明：<https://info.arxiv.org/help/license/index.html>

## 3. 状态机

候选解析：

```text
queued -> resolving -> awaiting_review -> identifier_verified
                  |                    -> unresolved
                  |                    -> conflicted
                  |                    -> blocked
                  -> unresolved
                  -> conflicted
                  -> retryable_error -> resolving
                                     -> blocked
```

provider 返回任何候选记录时先进入 `awaiting_review`。即使是 source identifier exact，也必须追加显式 identity decision；相似度、排名和分数没有直达 `identifier_verified` 的路径。

资源获取：

```text
rights assessment approved -> ready -> fetching -> acquired
                                           |    -> retryable_error -> fetching
                                           |    -> invalid_content
                                           |    -> blocked
review required            -> rights_review
metadata only / blocked     -> blocked
```

每个 transition 都有幂等键、期望 revision、来源引用和 append-only event。重复调用返回同一事实；相同幂等键绑定不同物料或使用旧 revision 会 fail closed。

## 4. 可调用入口

Python 编排入口：

```python
from quant_hub.evidence import (
    ArxivAdapter,
    EvidenceExpansionService,
    ResolutionQuery,
)
from quant_hub.evidence.providers import StrongIdentifierQuery

query = ResolutionQuery(
    identifiers=(
        StrongIdentifierQuery(
            scheme="arxiv",
            raw_value="2010.01412",
            source_provenance_urn="qrh:review:P012:official-arxiv-page",
        ),
    )
)
case, requests = EvidenceExpansionService(settings).enqueue_and_plan(
    candidate_id,
    query,
    (ArxivAdapter(),),
    provenance_urn="qrh:evidence:resolution:P012",
    idempotency_key="P012-2010.01412",
)
```

该调用只落 case 和 request，不执行网络访问。transport 获取官方响应后，按冻结请求构造响应事实并导入；以下示例中的 `transport_result` 是外部限流、重试和缓存层返回的只读结果：

```python
from quant_hub.evidence.expansion import EvidenceExpansionRepository
from quant_hub.evidence.providers import ProviderHttpResponse

adapter = ArxivAdapter()
request_spec = adapter.plan(query)[0]
response = ProviderHttpResponse(
    request_url=request_spec.url,
    final_url=transport_result.final_url,
    redirect_chain=tuple(transport_result.redirect_chain),
    status_code=transport_result.status_code,
    headers=dict(transport_result.headers),
    body=transport_result.body,
)
repository = EvidenceExpansionRepository(settings)
ingested = repository.ingest_provider_response(
    requests[0].provider_request_id,
    response,
    adapter,
    attempt_number=1,
    idempotency_key="P012-arxiv-provider-attempt-1",
    provenance_urn="qrh:evidence:transport:P012:arxiv:attempt:1",
)
review_state, _ = repository.finalize_provider_cycle(
    case.resolution_case_id,
    expected_revision=case.state.revision,
    idempotency_key="P012-arxiv-provider-cycle-1",
)
assert review_state.state == "awaiting_review"
```

响应体不会因导入而自动生成论文实体；cookie 等敏感响应头在写入审计表前会被剔除。此后依次调用：

1. `EvidenceExpansionRepository.ingest_provider_response(...)`；
2. `finalize_provider_cycle(...)`，精确结果也先到 `awaiting_review`；
3. `record_identity_decision(...)`，明确接受后到 `identifier_verified`；
4. promotion 服务再用既有 `create_paper`、`assert_and_assign_identifier` 和 metadata assertion API 建 canonical paper；
5. 资源 offer 依次执行 `assess_offer` / `record_rights_assessment`、`open_acquisition_case`、`begin_acquisition`；
6. transport 使用既有 `record_fetch_attempt`，PDF 通过 magic/MIME/SHA-256 检验并 `register_resource` 后，调用 `complete_acquisition`。

首批 11 条已人工核对的 arXiv 映射保存在 `fixtures/evidence/expansion_seed_arxiv_v1.json`。安全计划模式：

```powershell
python tools/seed_evidence_resolution.py
```

写入隔离候选 runtime 时必须明确授权目标：

```powershell
python tools/seed_evidence_resolution.py --apply --var-root D:\path\to\candidate-var
```

该工具只建 case 和官方 arXiv request，不联网、不抓 PDF、不建 canonical paper，也不自动作 identity decision。

## 5. 后续生产集成顺序

1. 在候选 release 的隔离副本运行 11 条 exact arXiv seed 和优先 DOI 批次；transport 按 provider 限流、缓存和退避要求执行。
2. 将响应体写入受管对象缓存，记录 body SHA-256，再导入 provider observation；任何 MIME、结构或 identifier 不一致进入 invalid/conflicted。
3. 对 exact strong identifier 批量生成待审 decision；metadata search 的单一高分结果仍进入人工复核。
4. identity promotion 创建 canonical paper、强标识符投影和元数据 assertion；随后修订对应 citation binding，并补齐 `research_paper_relation`。
5. 对每个 resource offer 逐条权利评估；只抓明确批准项。校验 PDF、登记 content-addressed resource，再创建 reading task。
6. 重放完整引用账本，按研究专题核对 resolved/source_only/unresolved/conflicted/rejected 守恒；生成新 TXT inventory、独立 verifier 证据和新的 Evidence release candidate。
