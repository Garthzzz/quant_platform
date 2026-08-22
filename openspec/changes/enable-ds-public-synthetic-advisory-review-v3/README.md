# enable-ds-public-synthetic-advisory-review-v3

DS V4 Pro 公开合成四轮 advisory review 的 fake-only v3 预实现。此 change 不启用真实 Keyring、HTTP、socket、VM 或 release 写入。writable ledger 仅在 Windows managed-directory named-stream 与生命周期 root/marker/stream handle guard 可用时启用；其他平台在数据库创建前禁用。
