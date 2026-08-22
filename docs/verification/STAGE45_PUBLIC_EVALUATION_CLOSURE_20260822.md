# Stage 4/5 公开评测闭合冻结报告（2026-08-22）

> **Round2 更正：**本文件记录的 v2 receipt/campaign 自洽校验已被独立 verifier 证明不足，
> 不能作为当前冻结结论。权威公共机制报告改为
> `STAGE45_ROUND2_EVIDENCE_BOUND_CLOSURE_20260822.md`；本文件仅保留历史测试记录，尤其不得以
> “canonical producer 字符串/自报 hash”替代真实 suite/base/projection/displayed bytes 或 raw
> campaign replay。

## 结论

公开机制修订与 fake-only 压力回归通过；本报告不构成 sealed holdout、VM candidate、真实 Codex
或发布资格证据。历史 V39/aggregate qualification 在新 exact displayed-byte 与 canonical
per-qrel receipt 门禁下不继承，当前 candidate 状态仍为“须重新资格评测”。

## 修订闭合矩阵

| 风险 | 机械闭合 | 公开反例 |
|---|---|---|
| 不完整或篡改 qrel suite 被直接 evaluate | 强制 `suite.validate`；PASS/FAIL 均有 canonical validation receipt | 局部 suite 只能走 `NON_AUTHORITATIVE_DIAGNOSTIC`；篡改 quote/hash 返回 rejection receipt |
| aggregate report 可伪造比较 | comparison 只接收 canonical per-qrel receipt bytes | 直接传 `EvaluationReport` 拒绝 |
| suite/index/limit 换柱 | prereg 与 receipt 共同绑定 suite bytes/hash、evaluator、limit、artifact、snapshot、index、producer | 换 projection 的 LIKE receipts 拒绝 |
| metrics 与实际卡片脱节 | receipt 冻结 card projection；consumer 重算 relevance/metrics/errors | displayed text 加后缀即失去 exact credit |
| LIKE 把 document LIMIT 偷换为 chunk LIMIT | 每个 SQL 文档命中只产生一个 relevance unit | 多 chunk 不再挤出后续文档 |
| raw JSONL 宽松接受 | duplicate key、未知事件、缺 start、未闭 item、多 terminal、terminal 非最后均拒绝 | synthetic duplicate/unknown/open/after-terminal 用例通过 |
| 事后补 prereg 或换运行身份 | v2 prereg 绑定 authority/server/model/config/run/case/time；campaign receipt 绑定 trace hashes/timing | zero gain、超预算、缺 search→get、run binding/timestamp 不符均 fail closed |
| marker 碰撞或文本伪引用 | NFKC/casefold/空白归一化后全局 unique/non-overlap；final 必须回链 prior get 的 object/citation/locator | 全角重复、跨维包含、guessed get、无 backlink 均拒绝 |
| 组件结果冒充最终验收 | trace gate 与 marker scorer 标记 `NON_AUTHORITATIVE_COMPONENT` | 仅 integrated gate 可生成 authoritative campaign receipt |

## 冻结命令与结果

在 `D:\quant\quant_platform` 执行，全程禁用 pytest cache，未连接 VM、未读取 sealed/private、
未运行真实 Codex、未发起网络调用：

```powershell
python -B -m pytest -q -p no:cacheprovider `
  quant_hub/tests/test_knowledge_retrieval_eval.py `
  quant_hub/tests/test_knowledge_mcp.py

python -B -m pytest -q -p no:cacheprovider `
  quant_hub/tests/test_knowledge_public_quality.py `
  quant_hub/tests/test_knowledge_mcp_stress_public.py
```

结果：核心门禁 `49 passed, 12 subtests passed`；公开扩展压力回归
`22 passed, 21 subtests passed`；合计 `71 passed, 33 subtests passed`。

还执行静态编译与 diff whitespace 检查；最终结果以本报告末次更新后的命令输出为准。

## 未满足门禁

- 未运行 sealed holdout；不存在新 candidate qualification receipt。
- 未运行 VM/candidate/apply/restore；不存在部署或切换授权。
- 未运行真实 Codex/MCP-assisted 外部 campaign；公开 campaign 仅使用 deterministic fake JSONL。
- 新 exact credit 揭示当前公开 candidate 与 LIKE 对照没有预注册的两项困难 slice 增益；因此公开
  comparison 安全返回 FAIL，不能用历史 aggregate 数值覆盖。
