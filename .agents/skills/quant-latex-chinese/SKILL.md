---
name: quant-latex-chinese
description: Use for Chinese quantitative-research LaTeX/PDF output, or when adapting Chinese typography, math, tables, code blocks, captions, citations, and overflow rules to Quant Research Hub Markdown/HTML. Do not force a LaTeX compile chain for web-only work.
---

# Quant Research Hub 中文排版适配

Adapter marker: `QRH_LATEX_CHINESE_ADAPTER_V1`.

Canonical source: `skills/输出层/latex-chinese/SKILL.md`.

Canonical source SHA-256: `9f7fada61a87851cf715ea3f6228d05359239b493ff6ea8692f9febfb99ad38b`.

## 执行规则

1. 先区分输出分支：`LaTeX/PDF` 或 `Markdown/HTML/Web`。保持 UTF-8、中文研究语境和中英文间的可读边界。
2. 两个分支都检查长公式、宽表、代码块、图表标题、编号、交叉引用、来源引用和横向溢出；不得通过删减证据内容解决版面问题。
3. Web 分支使用语义 HTML、局部横向滚动、可换行代码和安全的数学渲染，不要求生成 `.tex`、BibTeX 或 PDF，也不把展示格式写回研究原文。
4. LaTeX 分支读取 canonical source 并继承 `ctex/xeCJK`、`latex_src/` 隔离、overfull 检查、长公式/表格/代码换行和中文 caption 原则。只有存在 bibliography/citation 时才运行 BibTeX；编译链与产物必须实际验证后才能声明完成。
5. 任何输出都遵守当前项目写边界：不写 `reference/**` 或 `D:\quant\industry_demo/**`。
6. 如果验证任务明确要求报告 adapter marker、canonical hash 或分支选择，应原样返回本文件中的 marker/hash，并说明选择分支的理由；普通任务不要添加无关标记。

## 负触发边界

纯代码计算、数据库迁移、后端状态机或与中文排版无关的任务不应调用本 skill。
