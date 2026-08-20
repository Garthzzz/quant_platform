# Archive Evidence C Gate 最终独立审核协议

以下命令均从 `D:\quant\quant_platform` 执行。审核只读最终候选；不得修改 `reference/**`、`D:\quant\industry_demo/**` 或 frozen replay/delivery。不要用普通 `sqlite3 -readonly` 打开 frozen WAL-mode 数据库，因为部分 SQLite 构建会创建 `-shm`；需要自定义 SQL 时使用 URI `mode=ro&immutable=1`。

## 1. 验证最终 manifest

```powershell
$env:PYTHONPATH=(Resolve-Path 'quant_hub\src').Path
python -B quant_hub\tools\freeze_evidence_candidate.py `
  --replay-slug c-gate-20260715-v2-fulltext `
  --delivery-slug c-gate-20260715-v4-final `
  --expected-inventory-sha256 39345ca71611d3d0c391f9675989c469aa5de4c4b225bca92d9650d35c9e0bc2 `
  --expected-candidate-inventory-sha256 b8b2f60603c7c0e056b39497ac81bcb07c943444bb92d50da4b002b7a30dc03d `
  --expected-schema-sha256 3b6f56ac85836fb86317276422f2a58db26a5d564d82f78016d2be18ee9f3423 `
  --verify
```

唯一通过输出：

```text
c0bbeedf5b66e2265104c814b7880a85e5a2ac2b9596440309e1902adda96c43
```

该命令会重新计算 formal source、全部 migrations/fixtures/tests/tools、输入包、replay/delivery、live Archive 树、两个 inventory、数据库计数与完整性，并拒绝非空 `*-wal`/`*-shm`。

## 2. 重放全文读取结果

```powershell
$env:PYTHONPATH=(Resolve-Path 'quant_hub\src').Path
python -B quant_hub\tools\build_evidence_fulltext_readings.py --verify
```

必须返回 `status=PASS`、`rows=18`、SHA-256：

```text
7888fcaa6eb7fda82ad7a60899a2666349262fe3ee30b9df8a474e23f56ab0af
```

## 3. 运行 C 范围测试

```powershell
Set-Location quant_hub
$env:PYTHONPATH=(Resolve-Path 'src').Path
python -B -m unittest discover -s tests -p 'test_evidence*.py' -v
python -B -m unittest `
  tests.test_incremental_intake `
  tests.test_incremental_intake_evidence_projection -v
Set-Location ..
```

预期分别为 29/29 与 18/18 PASS。

## 4. 新建独立 fresh replay

必须使用尚不存在的新 slug；不要复用 frozen replay。示例：

```powershell
$env:PYTHONPATH=(Resolve-Path 'quant_hub\src').Path
python -B quant_hub\tools\replay_bulk_evidence.py `
  c-independent-review-20260715-v4-final
```

必须核对：

- `paper_clue=245`、`citation_ledger_entry=5181`、`citation_occurrence=4630`；
- `paper=18`、`paper_category_assignment=23`、`paper_core_conclusion=18`；
- `paper_institution_resolution=18`、`paper_resource=18`；
- `paper_reading_task=18`、`paper_reading_run=19`、`paper_reading_conclusion_binding=18`；
- ledger inventory=`39345ca71611d3d0c391f9675989c469aa5de4c4b225bca92d9650d35c9e0bc2`；
- candidate inventory=`b8b2f60603c7c0e056b39497ac81bcb07c943444bb92d50da4b002b7a30dc03d`；
- schema=`3b6f56ac85836fb86317276422f2a58db26a5d564d82f78016d2be18ee9f3423`；
- `release_created=true`、`active_revision=1`，且 replay root 同时存在 `research_papers.sqlite3` 与 `platform.sqlite3`。

Fresh replay 会直接用 PyMuPDF 重算 18 份 PDF 的逐页读取结果，并真实执行 platform PASS snapshot → Evidence activation。

## 5. 新建独立 delivery promotion

不要对 frozen `c-gate-20260715-v4-final` 原地重跑 promotion；另用一个尚不存在的 slug，避免任何 SQLite 介质级变动影响 frozen manifest：

```powershell
$env:PYTHONPATH=(Resolve-Path 'quant_hub\src').Path
python -B quant_hub\tools\promote_evidence_delivery.py `
  c-independent-promote-20260715-v4-final `
  --expected-inventory-sha256 39345ca71611d3d0c391f9675989c469aa5de4c4b225bca92d9650d35c9e0bc2 `
  --expected-candidate-inventory-sha256 b8b2f60603c7c0e056b39497ac81bcb07c943444bb92d50da4b002b7a30dc03d `
  --expected-schema-sha256 3b6f56ac85836fb86317276422f2a58db26a5d564d82f78016d2be18ee9f3423
```

新 delivery 必须得到相同两个 inventory、schema、数据计数和 source snapshot，并形成自己的 platform snapshot/activation。完成独立实验后再次执行第 1 节，最终 frozen manifest 仍必须输出同一 SHA。

## 6. 最低字段、locator 与恢复序列验收

只读 SQL 至少验证：

- 每篇 paper 至少一个 category assignment，且恰好一个 primary；
- conclusion 等于绑定 excerpt，均为官方摘要 `source_claim`；
- 18 个 institution resolution 均明确记录状态/原因，不存在伪造 organization；
- UTF-8 occurrence 的 `line_start` 与 ledger claimed line 一致；
- 106 个 ambiguous 与 657 个 not-exact locator 均保持 fail-closed；
- 18 个成功 run 与 task input hash 一致，18 个 conclusion binding 同 paper；
- arXiv `2002.08709` 的 attempts 严格为 `1:failed(controlled_recovery_probe)`、`2:succeeded`；
- Platform snapshot 与 Evidence certificate receipt 的所有 authority 字段精确相等。

最终 manifest 路径：

`D:\quant\quant_platform\quant_hub\var\delivery\evidence\c-gate-20260715-v4-final\C_CANDIDATE_MANIFEST.json`
