# Archive Evidence C 设计补充与迁移不变量

状态：实现前补充，待 C Gate 随代码与测试一并审核；本文件不冒充既有架构评审结论。

## 1. 适用边界

Evidence 使用独立的 `research_papers.sqlite3` 和 `research_papers` 资源根。Archive 正文仍是只读事实来源；线索、外部断言、论文实体、抓取记录、资源、引用绑定、分析和发布状态均写入 Evidence 域，不回写 Archive Markdown。Paper Lab 与 Evidence 不共库、不共享活动指针。

## 2. 本地发布权威消费

平台发布权威只签发候选证书；Evidence 必须在本域保存并验证逐字段收据，不能把“平台存在一张 PASS 证书”直接等同于本地已发布。

- `evidence_release` 与 `evidence_release_item` 冻结候选及其完整物料。
- `platform_certificate_receipt` 保存 snapshot、candidate、decision、subject、manifest、source snapshot、requirements 和 projection revision，所有字段必须与候选逐项一致。
- `evidence_release_activation` 是不可变激活事件；`active_evidence_release` 是每个 subject 的唯一活动投影。
- staging 候选永远不可读作 active。历史版本回滚也必须消费一张新的 snapshot，并追加新的 activation；旧证书不能隐式切换活动指针。
- 物料、收据和激活历史只追加。活动投影只能由服务层在同一事务中随新激活更新。

## 3. 论文身份与强标识符

标题、作者—年份或相似文本只产生断言，不能直接合并论文。强标识符采用 `(scheme, normalized_value)`：

- DOI：去除 `https://doi.org/`、`doi:` 前缀，去首尾空白并小写。
- arXiv：去除 `arxiv:`、URL 和可选版本后缀，保留规范号；版本作为断言载荷而非实体键。
- PMID、PMCID、报告号：按各 scheme 的可逆规则规范化。

`paper_identifier_assertion` 保存不可变来源断言；只有追加 `paper_identity_event` 后，服务层才可更新 `identifier_assignment_projection`。活动投影对 `(scheme, normalized_value)` 强制唯一，因此一个强标识符不能同时指向两篇 canonical paper。merge/split/reassign 均须追加身份事件；冲突时 fail closed，不按标题静默合并。

## 4. 抓取与合法性账本

每次尝试均追加 `fetch_attempt`，至少保存：请求 URL、重定向链、最终 URL、HTTP 状态、响应 MIME、响应字节数、响应 SHA-256、请求身份的脱敏摘要、权利/合法依据、结果、错误类别与错误详情。失败和许可阻塞也是一等事实，不得被“未找到本地文件”覆盖。

资源只有在 PDF magic、MIME、字节数和 SHA-256 全部复核后才能登记为 `verified`。外部公开可访问不等于可再分发；权利状态与获取状态分开保存。

## 5. 引用公共 ID

引用 ID 为 `cit_` 加完整 SHA-256 的小写、无填充 Base32（52 字符）。哈希输入严格为：

```text
b"qrh-citation-v1\0"
+ document_sha256_ascii + NUL
+ decimal(byte_start) + NUL
+ decimal(byte_end) + NUL
+ sha256(raw_marker_bytes)_ascii
```

`citation_occurrence` 必须同时保存 `raw_marker_text` 与 `raw_marker_sha256`；导入时复核 UTF-8 半开字节区间与原始标记。相同 source object 和 span 得到相同 ID，不跨版本继承。

## 6. 确定性清单与安全资源读取

论文清单固定为 UTF-8、LF、TSV 表头和 JSON 字符串转义；按 `research_urn, document_version_urn, byte_start, candidate_id` 排序。同一数据库快照和格式版本必须逐字节一致，写入采用同目录临时文件、`fsync` 后原子替换。

资源服务只接收 `resource_id`。客户端不能提交文件路径；服务端从数据库解析相对路径，拒绝绝对路径、`..`、符号链接/重解析点、非普通文件、硬链接和越界解析，并在返回前重新核对字节数、SHA-256、MIME 与文件 magic。

## 7. 受管回放

回放目标只能是 `evidence_replay_root` 下的直接子目录，名称满足安全 slug；目标必须不存在或为空，且路径链不得含符号链接/重解析点。拒绝绝对路径、`..`、非空目录，以及与 Archive、reference、生产数据库、生产资源根或迁移根重叠的目标。回放在隔离库中执行 up migration、导入、资源复核、清单重建和发布物料校验，不修改生产活动指针。

## 8. 最低迁移不变量

1. 所有业务表为 SQLite `STRICT`，外键开启且 `foreign_key_check` 为空。
2. migration 文件连续、成对、UTF-8；已应用 hash 漂移必须拒绝。
3. up 幂等；down 按逆序清理；`up -> down -> up` schema hash 相同。
4. 事实断言、身份事件、抓取尝试、引用/绑定事件、release item、证书收据和 activation 禁止更新或删除。
5. method/resource-only 线索不得创建 canonical paper 或抓取任务。
6. unresolved、conflicted、license-blocked 状态不得被缺省值升级为 verified/acquired。
7. 只有逐字段匹配的平台 PASS snapshot 可激活 Evidence release；失败事务不得留下活动指针或半条收据。
