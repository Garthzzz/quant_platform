---
name: ascii-architecture-diagram
description: Renders pipeline / architecture diagrams in ASCII format with input shape annotation, step-by-step module boxes, output shape annotation, ablation comparison table embedded. Each step labels purpose, input shape, operation, output shape, and loss location if applicable. Use when filling diagram field of paper reading JSON, or when drawing system architecture for any technical document.
metadata:
  category: output
  version: 1.0.0
  evidence_grade: user 独家 (CLAUDE3 read_paper.md diagram 字段格式)
---

# ascii-architecture-diagram — 架构图 ASCII 格式

## 视角

技术文档中的 pipeline / architecture 图用 **ASCII 格式**(纯文本,可在 markdown / chat / log 中显示)。

## 标准格式模板

```
════════════════════════════════════════════════════════
架构图:<论文 / 系统简称>
════════════════════════════════════════════════════════

【输入】
  数据集:...
  输入形状:(N, T, F) — N=股票数, T=时间步, F=特征数
  特征来源:...
  预处理:...

  ┌──────────────────────────────────────┐
  │  Raw Input: (N, T, F)                │
  │  维度含义说明                        │
  └──────────────────┬───────────────────┘
                     │
                     ▼
【步骤 1】目的:一句话说这步做什么、为什么必须有这步
  ┌──────────────────────────────────────┐
  │  模块名称                            │
  │  输入: (N, T, F)                     │
  │  操作: 具体操作和参数                │
  │  输出: (N, D)                        │
  │  损失(如在此处): 损失函数说明        │
  └──────────────────┬───────────────────┘
                     │
                     ▼
【步骤 2】目的:...
  ┌──────────────────────────────────────┐
  │  ...                                 │
  └──────────────────┬───────────────────┘
                     │
                     ▼
【输出与结果】
  ┌──────────────────────────────────────┐
  │  输出: (N, 1) 截面因子值             │
  │  核心指标(带数字)                  │
  └──────────────────────────────────────┘

┌──────────────────────────────────────────────────┐
│ 消融对比(如有)                                  │
├────────────────────┬──────────┬──────────┬───────┤
│ 版本               │ IC_mean  │  ICIR    │ 备注  │
├────────────────────┼──────────┼──────────┼───────┤
│ baseline           │  x.xxx   │  x.xx    │       │
│ + 模块 A           │  x.xxx   │  x.xx    │       │
└────────────────────┴──────────┴──────────┴───────┘
```

## 规则

### 每步标注

- 输入 shape(具体 (N, T, F))
- 操作具体方法 + 关键参数
- 输出 shape
- 损失函数(若在该步产生)
- 目的(一句话说为什么必须有这步)

### 未披露处理

未披露写"未披露",不要假装知道。

### 损失函数位置

写在产生预测的组件框内,**不单独列块**:

```
┌──────────────────────────────────────┐
│  最终预测模块                        │
│  输入: (N, D)                        │
│  操作: Linear(D, 1)                  │
│  输出: (N, 1) 截面预测值             │
│  损失: 可微 RankIC loss              │
└──────────────────────────────────────┘
```

### 分支结构

**画出来**,不用文字描述替代:

```
                     │
              ┌──────┴──────┐
              ▼             ▼
        ┌─────────┐   ┌─────────┐
        │ 分支 A  │   │ 分支 B  │
        │ ...     │   │ ...     │
        └────┬────┘   └────┬────┘
             │             │
             └──────┬──────┘
                    ▼
            ┌──────────────┐
            │ 合并模块     │
            └──────────────┘
```

### 消融数据

**如有必须放入表格**:

```
┌──────────────────────────────────────────────────┐
│ 消融对比                                          │
├────────────────────┬──────────┬──────────┬───────┤
│ 版本               │ IC_mean  │  ICIR    │ 备注  │
├────────────────────┼──────────┼──────────┼───────┤
│ baseline           │  0.038   │  0.34    │       │
│ + cross-stock attn │  0.046   │  0.41    │ ∆+0.008│
│ + RankIC loss      │  0.044   │  0.39    │ ∆+0.006│
│ full model         │  0.052   │  0.48    │ ∆+0.014│
└────────────────────┴──────────┴──────────┴───────┘
```

## ASCII 字符规范

使用 box-drawing 字符(Unicode):

- 横线: `─`
- 竖线: `│`
- 圆角: `┌` `┐` `└` `┘`
- T 字: `┬` `┴` `├` `┤`
- 十字: `┼`
- 双线(用于强调):`═` `║` `╔` `╗` `╚` `╝` `╠` `╣` `╦` `╩` `╬`
- 箭头: `▼` `▲` `◄` `►`

### 终端 / 渲染器支持

- 终端必须 UTF-8 编码
- Markdown 在 monospace 字体下显示正确
- LaTeX `lstlisting` / `verbatim` 环境可保留

## 反模式

- ❌ 用文字描述代替 diagram("先 LSTM 再 attention 再 MLP")
- ❌ Shape 标注不具体("某个 tensor")
- ❌ 损失函数单独列块不放产生预测的组件框内
- ❌ 分支结构用文字"再分两路"代替图
- ❌ 消融数据散在文字里不放表格
- ❌ ASCII 字符 garbled 不修(终端 UTF-8 问题)

## 与其他 skill 的关系

- 与 `research/reading-paper`: 必读 — JSON `diagram` 字段格式
- 与 `output/latex-chinese`: 互文 — LaTeX 中嵌入 ASCII diagram 用 `verbatim` 或 `lstlisting`

## Provenance

来自 user CLAUDE3 skills/read_paper.md `diagram` 字段格式。
ASCII 格式选择是 user 实测 — 比 graphviz / drawio 等图形工具简单 + 在 chat / markdown / log 都能直接显示。
