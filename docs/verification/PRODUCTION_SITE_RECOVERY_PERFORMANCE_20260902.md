# 生产站点恢复与全站 2 秒门禁证据（2026-09-02）

## 1. 结论

生产入口 `http://10.5.1.240:8765/login` 已恢复公司 VPN 可访问。修复后正式认证态
全站门禁遍历 2,865 条站内页面、接口和资源路径，2,865 条均返回 HTTP 200，失败数为
0，完整响应最慢 716.963 ms，满足“任一路径必须严格小于 2,000 ms”的放行条件。

这项结论由 VM D 根中的机器可读报告支持，不把人工抽样或服务进程存活等同于全站可用。

## 2. 故障与修复

### 2.1 公司 VPN 无法打开站点

服务和 `0.0.0.0:8765` 监听器原本存在，但 VM 的活动网络配置文件是 Public，且没有允许
8765 入站的防火墙规则，因此 loopback 健康而公司 VPN 连接超时。现已建立
`QuantResearchHub TCP 8765` 入站规则：协议 TCP、端口 8765、Profile Any、来源仅
`10.0.0.0/8`。外部地址的登录页随后稳定返回 HTTP 200。

### 2.2 研究更新中的三个历史坏链

三个已合并/隐藏的历史研究仍被研究更新页渲染为独立研究链接，点击后返回 404。
`ArchiveCollaboration._research_update_rows()` 现对 presentation 隐藏 slug 输出
`page_url: null`，页面改为显示“历史内容已并入当前研究专题”，不再制造不可点击的伪入口。

### 2.3 十二个 Archive 实验图返回 409

active release 未携带 `archive_presentation.json` 已批准的 12 个 Q2 PNG，导致资源接口验真
失败。原始只读 `reference\archive` 文件的长度和 SHA-256 均与 manifest 相符；它们被逐文件
复制并复核到唯一 D-state 路径：

`D:\quant\quant_platform\state\archive_presentation_assets`

direct-D 服务仅允许注入这个精确路径。`ArchiveCatalog.presentation_asset()` 仍按 manifest
逐次核验相对路径、长度与 SHA-256；没有取消完整性检查，也没有修改原始 Archive 文件。
修复后 12 个资源接口全部返回 HTTP 200，响应哈希与 manifest 一致。

### 2.4 通用研究正文 404、相对链接失效与长页超时

封闭遍历新增 `/knowledge` 路由后发现两类真实问题。第一，通用研究页面只把评论选中的正文块
放入证据索引，标题等合法证据 span 会触发 `KeyError`，导致当前版和历史版页面返回 404。
现在页面构建先收集 IR 中全部块与内联 span，再叠加已接受知识；标题和正文证据均可稳定解析。

第二，Markdown 中的相对文档与图片原本会落到不存在的 Flask 相对路径。展示层现在把站内相对
目标统一改写到受控 `/knowledge/link/...` 解析器：可确认的通用研究或 Archive 目标跳到正式页面；
当前审核快照中没有的文档显示明确的“未收录”说明页；缺失图片返回说明性 SVG。该适配不改写
任何源 Markdown，也不把无法确认的目标伪装成已存在内容。

两张约 1.65 MB 的超长通用研究页面此前每次请求都重建 IR 和 HTML，实测约 2.4 秒。目录现在按
不可变 release 版本缓存页面，并在服务启动时预热当前 44 篇文档。最终门禁中这两条路径分别为
580.904 ms 和 573.422 ms。

## 3. 全站性能与可用性证据

### 3.1 正式认证态 GET-only 门禁

门禁脚本：`quant_hub/tools/authenticated_route_performance_gate.py`

VM 执行副本：

`D:\quant\quant_platform\tooling\authenticated_route_performance_gate.py`

最终报告：

`D:\quant\quant_platform\audit\authenticated-route-performance-20260902-ultimate.json`

报告摘要：

| 字段 | 结果 |
| --- | ---: |
| Schema | `qrh-authenticated-route-performance-gate/v1` |
| 方法 | `GET_ONLY` |
| 路径数 / 样本数 | 2,865 / 2,865 |
| HTTP 200 | 2,865 |
| 失败 | 0 |
| 阈值 | 2,000 ms |
| 最大完整响应时间 | 716.963 ms |
| Flask GET 路由契约 | 53 条 |
| 通用研究快照 | 44 篇文档 / 44 个版本 / 132 条强制种子路径 |
| 路径集合 SHA-256 | `f00ece7af3954b41df7cbea5518260e371c3dda610d85fc528214a5ee476a72a` |
| 门禁脚本 SHA-256 | `30b27042f5e04e64a39826a051075c96017d701f716a1ab28d729f060f361a63` |
| 报告 SHA-256 | `8ef1b716bb7d02368ea0ba267ceb15fa18278c9ecbf5c6f77c5ded3b15a37678` |
| 报告字节数 | 4,690,163 |

最慢路径是从通用研究相对链接解析到 Archive 章节后的完整响应，耗时 716.963 ms；Evidence
首页为 705.825 ms，Evidence 论文集合接口为 689.968 ms。已知 1.65 MB 通用研究当前版页面
为 580.904 ms。全部样本至少留有 1.283 秒的门限余量。

门禁在 VM loopback 上本地派生认证 session，只发送 GET。认证回跳、HTTP 4xx/5xx、请求
异常和 `elapsed_ms >= 2000` 均判失败。报告仅记录认证方案和 Cookie 名称，不写入口令、
session 密钥、口令摘要或 Cookie 值。
HTML 发现 `href`、`src`、GET 表单 action 与 citation；JSON 发现固定 URL 字段和任意
`*_url`。相对 URL 按最终响应 URL 解析，只允许同源跟随与同源发现。

脚本中的 53 条 GET 路由覆盖契约必须与 Flask URL map 完全相等；另外强制探测
`/deploymentz`、`/healthz` 和搜索接口。通用研究 sealed snapshot 的 44 篇文档还强制加入
当前版、历史版和受控原文三类路径，因此不能因为首页没展示某篇研究就静默漏测。

报告同时绑定线上身份：release
`release-2157a1209d85-227b30ef6fbb`、manifest
`e2e6563d7f73b5e3ad1dd4478cc83493c40dbc96db67b928cfc6224df1577000`、snapshot
`ksnap_96bed164788886bfbdb6591dc445557005d10831e5faf2be70bf7a8a7fc3f8b3` 和 writer
`D-active`。每个响应的 `X-Quant-Hub-Release` 都必须匹配预期 release，避免把另一进程或旧版本
的快速响应误当成当前生产证据。

早期报告只覆盖 2,618 条路径，独立复核指出它尚未闭合 `/deploymentz`、搜索接口、`/knowledge`
和 Flask URL map。补齐覆盖后，后续失败报告真实暴露了通用研究页面和相对资源问题；另有
Paper Lab 旧数字论文编号、Dashboard 自动主题被误当动态 ID 的发现器误扩展。代码与发现规则
分别修正并加入回归测试。早期 PASS 和中间失败报告均保留在 VM audit 中；只有上述
`ultimate.json` 是本次最终放行证据。

### 3.2 公司 VPN 真实浏览器抽样

修复后从公司 VPN 地址以认证态 Chromium `networkidle` 验证核心交互入口：

| 页面 | 完成时间 |
| --- | ---: |
| 首页 | 751.4 ms |
| 最近研究更新 | 563.8 ms |
| Evidence | 1,248.2 ms |
| Paper Lab | 1,143.2 ms |
| 已知最长 Q2 章节 | 1,566.3 ms |
| 含已修复 PNG 的补充研究页 | 654.5 ms |

全部返回 HTTP 200，无登录回跳；浏览器样本最大 1,566.3 ms。HTTP 全量门禁负责覆盖路径
集合，真实浏览器样本负责补充渲染、静态资源和公司 VPN 链路的用户侧证据。

## 4. 自动化回归

- 相关源码、路由闭包和发现器回归：48 tests passed；
- Archive Web、通用研究渲染/链接代理与研究补充页面回归包含在上述 48 项中；
- `compileall`：通过；
- `git diff --check`：通过，仅有 Git 对模板工作区行尾转换的提示；
- 12 个 Archive PNG：文件数、长度、SHA-256 和 HTTP 响应全部通过；
- 三个隐藏历史研究：HTML 无坏链，API `page_url` 为 `null`。

## 5. 生产边界与回退

本次生产写入全部位于 `D:\quant\quant_platform`，未向 VM C 盘或 D 根上级/同级目录写入
项目内容。`reference` 与 `D:\quant\industry_demo` 未修改。修复前 D-tooling 文件的精确
备份位于：

`D:\quant\quant_platform\audit\hotfix_backups\pre-site-content-fix-20260902`

该目录只用于回退本次 direct-D 兼容修复，不是另一主机恢复根，也不是第二套生产状态。
当前生产仍使用既定 active release 和同一份 D-state；本记录证明的是当前线上兼容层、站点
内容与性能恢复，不把它误写成一次新的正式 release-controller 放行。
