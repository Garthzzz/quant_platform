# Quant Research Hub 本地查看入口

在任意 PowerShell 或 CLI 中执行：

```powershell
cd D:\quant\quant_platform
python tools/viewer/app.py
```

脚本固定使用 `http://localhost:8765/`，并自动打开默认浏览器。若 Hub 已经
运行，只复用现有服务；若尚未运行，则启动 `reviewed_runtime.json` 明确指向的
已审核冻结交付。保持终端打开即可持续访问，按 `Ctrl+C` 关闭由本脚本启动的服务。

启动器可以从任意 Conda 环境调用，但实际服务严格使用 V34 激活封印中记录并校验的
Python 3.13.12；不会把当前环境（例如 Python 3.10 的 `quant`）误用于加载冻结源码。

只检查配置和服务状态，不打开浏览器：

```powershell
python tools/viewer/app.py --check
```

需要推广新的审核交付时，应在新交付通过启动门禁后更新
`reviewed_runtime.json` 的交付路径、门禁路径及两项 SHA-256；启动器不会根据目录名
自行选择未经审核的“最新”版本。
