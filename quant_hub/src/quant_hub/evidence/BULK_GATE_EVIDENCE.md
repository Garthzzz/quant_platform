# Archive Evidence 全量导入 Gate 证据

## 冻结输入与资源谱系

- E 原始 occurrence 输入由 `input_manifest.json` 固定为 5,181 行，链接 candidate 的记录为 5,146 行，显式未链接记录为 35 行。
- candidate ledger 共 245 行；Crossref 搜索共 158 次、返回 474 个候选，全部保持 `not_selected`，搜索分数不解释为身份概率。
- `normalized_resource_manifest.jsonl` 共 18 行。其中 P073 同时绑定原 `resource_manifest.jsonl` 与 artifact；其余 17 行明确标记 `recovered_from_audited_artifact`。每行都同时绑定 cache metadata hash、artifact 声明 hash、PDF 实际 bytes/hash/magic、官方 URL 与权利边界。
- 18 个 arXiv 强身份均从缓存的官方 `https://arxiv.org/abs/...` HTML 重新解析 `citation_arxiv_id` 并与 requested ID 严格相等；P073 另有官方 API 记录。PDF 文件名或标题相似度均不参与身份判定。

## Citation 守恒与去重契约

公共 UTF-8 citation ID 采用以下不可截断契约：

```text
SHA256("qrh-citation-v1\0" || document_sha256 || "\0" ||
       byte_start || "\0" || byte_end || "\0" || raw_marker_sha256)
```

三类 locator 的守恒等式为：

```text
4,122 UTF-8 ledger rows -> 3,528 exact occurrences（共享 594 行）
  624 source_locator_claim rows -> 624 path-scoped occurrences
  435 PDF extraction locator rows -> 435 path-scoped occurrences
3,528 + 624 + 435 = 4,587 citation_occurrence
4,587 + 594 = 5,181 citation_ledger_entry
```

每条 ledger entry 必须且只能引用一个 occurrence；每个 occurrence 必须至少被一条 ledger entry 引用。共享 marker 通过 `citation_ledger_entry` 显式建立 occurrence 与 clue/candidate 的多对多关系，不复制公共 occurrence，也不丢输入行。

对 `source_locator_claim` 和 PDF extraction locator，尚无原始 UTF-8 byte span，故 dedup key 保留 `source_path`：

```text
document_sha256 + locator_kind + source_path + locator + raw_marker_sha256
```

不采用 4,449：该数会跨路径合并 138 条仅有 source-only 证据的别名，超出证据强度。不采用旧中间数 4,528：该数没有可复现的统一 locator key，无法作为正式身份契约。

## 读取理解边界

- 18 份 PDF 均进入内容寻址资源区，读取时重新核验 regular/single-link、PDF magic、bytes 与 SHA-256。
- 18 个官方 abs HTML 的 `citation_abstract` 均逐字解析为 `source_fact` / `evidence_excerpt`，绑定页面 hash 与 HTML meta locator。
- 未经独立全文精读，不生成核心结论；目录保持 `partial` 且 `core_conclusions=[]`。
- 每篇论文创建一个不可变 `paper_reading_task`。后续成功或失败尝试写入 append-only `paper_reading_run`；失败后以新的 attempt 重试，输入 snapshot hash 不得变化。

## 放行断言

正式 importer 与 replay 必须同时验证：SQLite `integrity_check=ok`、`foreign_key_check=[]`、18 份资源逐项安全读取、474 个 Crossref candidate 零选择、35 个未链接 occurrence 仍为 unresolved、5,181 条 binding/event/projection 完整、重复导入与重复导出字节一致。
