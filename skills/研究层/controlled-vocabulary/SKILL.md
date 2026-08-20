---
name: controlled-vocabulary
description: Maintains parent-child controlled vocabulary for structured fields (model_type, asset_market, metrics, institution, research_topic, pipeline_tags). Adds new terms via vocab_queue.jsonl atomic append (parallel-safe), not direct vocab file modification, awaiting batch-end human review. Use when filling structured paper fields, when encountering a term not in vocab, or when reviewing pending vocab_queue for batch merge.
metadata:
  category: research
  version: 1.0.0
  evidence_grade: user 独家 (vocab_queue 并行安全机制)
---

# controlled-vocabulary — 受控词表 + 并行安全机制

## 视角

字段值从受控词表取。词表通过 vocab_queue 队列扩充,**不直接修改词表文件**(防并行 subagent 写冲突)。

## 使用规则

1. 读完论文 / 理解方法后,再来对照词表
2. **不是用词表去套论文,是用判断去选词**
3. 先判断这个方法 / 市场 / 机构的实质是什么
4. 看词表有没有语义相符的条目
5. 有 → 用词表条目
6. 没有 → 执行词表扩充流程

## 词表扩充流程

**触发条件**: 判断后确认在语义上不属于任何现有条目。**不是字符串没匹配上就触发,是语义上确认不在范围内才触发**。

### 步骤

1. **按父类-子类格式造新条目**:
   - 现有父类能覆盖 → 只新建子类
   - 父类也没有 → 新建父类(中文两三个字)+ 子类

2. **不直接修改词表文件**,将新词追加写入 `tools/vocab_queue.jsonl`:

```json
{"field":"model_type","tag":"深度学习-Mamba","source":"33_论文标题","ts":"2026-MM-DDTHH:MM:SSZ"}
```

3. **PROGRESS_LOG 记录**:
```
[词表扩充待审] 新增 字段名 条目:xxx,来源:论文标题
```

4. **继续精读**,在当前论文的 JSON 中**使用该新词**

### Vocab_queue 机制说明

多个 subagent 并行运行时,如果每个都直接修改 vocab.md 会产生写冲突。

**vocab_queue.jsonl 使用追加写入(原子操作),不覆盖,并行安全**。

批次结束后由**人工 review 队列**,确认后**手动合入** vocab.md,**清空队列**。

### 不确定时

填 "其他-[一个词的说明]",PROGRESS_LOG 标 `[需人工确认词表]`,**不阻断精读**。

## 词表分类(从 user CLAUDE3 vocab.md 沿用)

主词表:

- **model_type**: 父类(深度学习 / 树模型 / 机器学习 / 统计模型 / 符号回归 / 大语言模型 / ...)+ 子类
- **asset_market**: A 股 / 美股 / 港股 / 欧股 / 日股 / 商品期货 / ... + 具体指数
- **metrics**: IC / RankIC / Sharpe / 最大回撤 / 信息比率 / ...
- **institution**: JFE / RFS / NeurIPS / ICML / arXiv / 各券商 / ...
- **research_topic**: 选股策略 / 因子挖掘 / 行业轮动 / 组合优化 / 算法交易 / ...
- **pipeline_tags**: 6 列 pipeline 各自的标签词表(data_input / data_preprocess / method_model / method_special / loss_function / training_config / pipeline_output)

具体词表内容**项目级 vocab.md**(每个使用本 skill 的项目自带一份),不放在 skill 文件里(项目特化)。

## 并行使用协议(per `engineering/parallel-subagent-orchestration`)

3 个 subagent 同批精读 3 篇论文,每个在自己的上下文,可能同时发现需要新词:

```
Subagent 1 → 发现新 model_type "深度学习-Mamba" → 写 vocab_queue.jsonl 追加
Subagent 2 → 发现新 metric "MRAR" → 写 vocab_queue.jsonl 追加 (不冲突,append 原子)
Subagent 3 → 发现新 institution "西部证券" → 写 vocab_queue.jsonl 追加
```

批次结束后人工 review:

```bash
cat tools/vocab_queue.jsonl
# 人工判断每条 → 合入对应词表 → 清空 queue
```

## 反模式

- ❌ Subagent 直接修改 vocab.md(写冲突)
- ❌ 字符串没匹配上就当"语义上不存在"(应该判断语义)
- ❌ "其他-xxx" 滥用(应该尽量在现有词表找)
- ❌ Vocab_queue 不及时人工 review(队列膨胀)
- ❌ 不写 PROGRESS_LOG 标 `[词表扩充待审]`(user 不知道)

## 与其他 skill 的关系

- 与 `research/reading-paper`: 必读 — 论文精读字段填值
- 与 `engineering/parallel-subagent-orchestration`: 互文 — 并行安全机制
- 与 `core/progress-logging`: 互文 — `[词表扩充待审]` 标记

## Provenance

来自 user CLAUDE3 skills/vocab.md 完整实测 skill。
**vocab_queue 并行安全机制是 user 独家创新**:多 subagent 并发场景下,生态共识"文件系统作 IPC",但 user 进一步设计 jsonl 追加 + 批次 review 的具体协议。
