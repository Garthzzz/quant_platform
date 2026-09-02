# 量化知识 MCP 功能验收记录（2026-09-02）

## 1. 结论

本次 MCP 代码功能验收为 `PASS`。完整自动回归、原生 stdio JSON-RPC 链路和真实 Codex
工具调用均通过，没有发现需要修改的产品代码。

本结论证明 MCP 实现可安装、可启动、可检索、可展开证据、可列出版本更新并保持 authority
身份一致；不把本地测试 authority 冒充当前生产知识发布，也不签发 Stage 5 权威证书。

## 2. 自动回归

在 `quant_hub` 下使用 `.venv` 和 `PYTHONPATH=src` 分别执行：

- `tests.test_knowledge_mcp`：37 tests passed；
- `tests.test_knowledge_mcp_real_acceptance`：11 tests passed；
- `tests.test_knowledge_mcp_stress_public`：11 tests passed。

合计 59 tests passed，失败为 0。覆盖三工具 schema、fresh/stale/unavailable、版本切换与回退、
镜像损坏、并发锁和崩溃恢复、安装/卸载幂等性、OpenSSH 边界、stdio 子进程、Codex trace
状态机、真实验收 runner 合同及 1,000 次热查询压力。

## 3. 原生 stdio 端到端

在 `quant_hub\var\mcp_acceptance_20260902_b` 内建立隔离、Git 忽略的 file-authority 验收环境，
使用正式 `qrh-knowledge-mcp.exe` 安装 project profile。`doctor` 返回：

- `status=fresh`；
- authority、local mirror 的 `release_id/manifest_sha256/snapshot_id` 完全一致；
- `transport=stdio`；
- `transition_pending=false`。

随后直接通过原生进程发送 MCP `initialize`、`tools/list` 和 `tools/call`，结果为：

| 检查项 | 结果 |
| --- | --- |
| 工具集合 | 仅 `search_quant_knowledge`、`get_quant_knowledge`、`list_knowledge_updates` |
| 工具权限 | 三项均为 read-only、non-destructive |
| search | `status=ok`，3 条结果，`availability=fresh` |
| get | `status=ok`，对象与 search 推荐 ID 一致，返回 1 条 source citation |
| list updates | `status=ok`，`availability=fresh` |
| 三次身份 | 完全一致 |
| 子进程 | exit 0，stderr 为空 |

## 4. 真实 Codex 调用

使用当前原生 `codex.exe`、`--ignore-user-config`、`--strict-config`、`--ephemeral` 和 read-only
sandbox，以 session override 只启用 `quant_research_knowledge`。测试任务要求先检索
`leakage embargo temporal split`，再展开 `next_action` 推荐的第一个对象。

实际 trace 中只有两次目标 MCP 调用：

1. `search_quant_knowledge`：completed，`status=ok`，`availability=fresh`；
2. `get_quant_knowledge`：completed，`status=ok`，`availability=fresh`，返回 1 条 canonical
   `source_citations`。

没有 shell、web、文件修改或其他 MCP 调用。Codex 最终回答确认两次调用成功、身份为 fresh、
引用数量为 1。

## 5. 当前生产边界

当前用户 Codex profile 没有安装 `quant_research_knowledge`；本次验收使用隔离 profile 和 session
override，没有修改用户全局 Codex 配置。

对生产 VM 的只读 OpenSSH `doctor` 额外验证显示：当前 direct-D 站点恢复仍使用历史
`qrh-active-release/v1` 平面 pointer，而 MCP 的正式生产 authority 合同要求
`qrh-active-release/v2` 封闭 pointer，因此正确返回 `unavailable`。现有回归明确要求旧 v1
不得被冒充成生产 MCP authority，本次没有放宽该门禁，也没有修改 VM pointer。

所以本次 `PASS` 的精确含义是：MCP 代码与 Codex/stdin 接口功能验收通过；把真实生产知识
发布注册到研究员 Codex，仍需后续以 v2 authority 正式激活，不能用兼容性降级替代。

## 6. 写入边界

- 未修改 `reference/**` 或 `D:\quant\industry_demo`；
- 未向生产 VM 写入任何内容；
- 未修改用户全局 Codex 配置；
- 验收临时数据仅位于 `quant_hub\var\mcp_acceptance_20260902_*`，不纳入 Git；
- 本次产品代码改动为 0，仅新增本验收记录。
