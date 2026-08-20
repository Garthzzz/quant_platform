# Cold recovery runbook

本流程只用于活动 D 盘整体不可用或损坏的灾难恢复。普通代码回退必须切换 D prior，并继续使用当前 D state；不得用历史 checkpoint 倒退在线状态。

1. 在与生产 VM 不同 host identity 和 storage authority 的恢复主机上，确认 `D:\quant\quant_platform` 是真实存在、非 reparse、完全空的目录。
2. 仅挂载/复制一个已保留的 `cold-recovery-<bundle_id>`；不要从生产 D 盘补文件。
3. 执行：

   ```powershell
   python tools\restore\restore_cold_bundle.py --bundle-root <bundle> --empty-target-root D:\quant\quant_platform
   ```

4. 工具将验证 `SHA256SUMS`、release/recovery/checkpoint 单向身份、完整 closure、SQLite hash/integrity/foreign key/逻辑行数，然后只物化 release、state、tools 和唯一 active pointer。此时状态仍是 `materialized_pending_post_restore_verification`，不得宣称恢复成功。
5. 使用恢复 release 自带的环境说明启动服务，依次验证 `/deploymentz`、首页、代表性研究、搜索、PDF/图片/对象、Paper Lab、Dashboard、comment 读写和数据库 schema/hash。
6. 只有全部真实服务与浏览器/API 探针通过后，才调用控制工具追加 `qrh-recovery-receipt/v1`。任一探针失败都保留失败证据，不生成成功 recovery receipt。
7. receipt、bundle 和恢复演练报告不得包含 API key、viewer password、cookie、Authorization header 或其他 secret。
