---
name: literature-quality-tier
description: Classifies cited literature into three tiers (Tier 1 top journals/conferences with multi-source corroboration → optimal adoption, Tier 2 high-citation arXiv or named institution working papers → cautious citation, Tier 3 low-citation/sole-source/unknown authors → must be explicitly downgraded and labeled, never placed in recommendations). Includes "novel ≠ reliable" warning. Use when conducting any literature review, especially during associative search where exotic methods surface.
metadata:
  category: research
  version: 1.0.0
  evidence_grade: user 独家
---

# literature-quality-tier — 文献质量三梯队 + "novel ≠ reliable"

## 视角

不是所有文献都同等可信。**梯队分类 + 第三梯队强制降级**。

## 三梯队定义

### 第一梯队(优先采纳)

- 在顶级期刊(JFE / RFS / JF / JMLR / Annals of Statistics / Econometrica)或顶级 ML 会议(NeurIPS / ICML / ICLR / AISTATS)发表
- 高引用量(该子领域 top 10% 引用)
- **多个独立文献相互印证**同一结论或方法的有效性
- 有独立复现研究验证

### 第二梯队(审慎引用,需额外论证)

- 知名机构工作论文(AQR / Man AHL / Two Sigma / Jane Street / Citadel)
- 高引用 arXiv 预印本(引用 > 100 且发表 > 1 年)
- 已被部分独立研究验证但样本有限

### 第三梯队(谨慎使用,必须加强审查门槛)

- 引用少且不知名作者的论文
- 非顶刊发表
- 孤证(仅单一来源支持,无独立验证)
- arXiv 预印本(未正式发表 / 引用少)

**第三梯队哪怕方法描述得天花乱坠、理论看起来很漂亮,落在第三梯队就必须加一道额外审查**:

- 该方法的核心假设在你的语境下成立吗?(SNR / 数据规模 / 任务性质)
- 该方法有没有在你的语境 / 类似场景下被任何人验证过?
- 如果没有验证,推荐时**必须显式标注"第三梯队文献,未经 <你的语境> 验证,仅作实验候选"**,不能和第一梯队方法并列推荐

## "Novel ≠ Reliable" 显式告诫

CC 不要因为"这个方法很 novel"就兴奋地优先推荐。

**Novel ≠ Reliable**。在量化实盘 / 严肃工程中,可靠性远比新颖性重要。

## 实操规则

### 推荐配置中

- **最终推荐配置中**的方法,**第一梯队优先**
- 第三梯队方法**不能作为"推荐配置"**,只能放在"实验候选 / 未来探索方向"中

### 联想搜索发现的非显然方法

- 联想搜索发现的非显然方法,如果是第三梯队,**必须标注并降级处理**,不管它在理论上多漂亮
- 例: "SAM in low-SNR finance" 是第三梯队(quantitative finance 没人测过),即使 SAM 在 CV 上是第一梯队,迁移到 quant 时仍降级

## 标注协议

每条推荐 / 引用必须显式标注梯队:

```markdown
推荐配置 D7 优化器:
- **第一梯队**: AdamW (Loshchilov & Hutter 2019, ICLR, 高引)
- **第二梯队**: SAM (Foret et al. 2021, ICLR;在 CV 上第一梯队,但在量化 low SNR 上未验证,降级)
- **第三梯队 (仅作实验候选)**: Lion (Chen et al. 2023, arXiv 预印本;无量化验证;novel 不一定 reliable)
```

## 引证严谨性

不说"文献表明 X",要说:

> "Smith & Jones (2023, JFE) 使用方法 Y 在数据集 Z 上证明了 X,但需注意 W"

**含**:
- 作者 + 年份 + 期刊
- 具体方法
- 数据集
- 具体结论
- caveats / 适用边界

## 孤证标注

仅单一来源支持且无独立验证的论断 → 显式标注"孤证"。

例: "Smith (2024, arXiv) 报告 X(孤证,无独立复现)"。

## 证据等级区分(在最终文档中)

明确区分:

- (a) **已确立的理论结果**(数学证明)
- (b) **良好复现的实证发现**(多次独立复现)
- (c) **证据有限的实证发现**(单一研究)
- (d) **有根据的推测**(理论合理但无实证)

## 反模式

- ❌ "文献表明 X" 不引具体 source
- ❌ Novel 方法直接进推荐配置不分梯队
- ❌ 第三梯队不标注降级
- ❌ 把孤证当多源印证用
- ❌ 主流 ML 结论直接迁移到 user 语境(没 verify 前提)
- ❌ 因为"作者名气大"就放第一梯队(应该看 source 期刊 / 引用 / 复现)

## 与其他 skill 的关系

- 与 `research/conducting-literature-review`: 必读 — 联想搜索的产出必须过本 skill
- 与 `research/citation-verification`: 互文 — mechanical 检查 vs 梯队人工判断
- 与 `research/adversarial-review`: 互文 — 对抗审查时常质疑梯队判断

## Provenance

来自 user CLAUDE1 Step 1b 的"文献质量分层审查"(显式三梯队)。生态无对应 — credibility score 是动态打分,user 是显式梯队 + 强制降级,更严格。
