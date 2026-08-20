---
name: latex-chinese
description: Produces LaTeX documents in Chinese with proper CJK support (ctex or xeCJK), overflow checking (overfull hbox/vbox warnings), long formulas wrapped via aligned/multline/split, long tables via tabularx/adjustbox, code blocks via lstlisting with breaklines, BibTeX references, XeLaTeX→BibTeX→XeLaTeX×2 compile chain, source files in latex_src/ subdir while top dir holds only PDF/MD. Use when producing research paper / proposal / slides as LaTeX PDF.
metadata:
  category: output
  version: 1.0.0
  evidence_grade: user 实测 (CLAUDE 1-5 LaTeX 中文规范)
---

# latex-chinese — LaTeX 中文输出规范

## 视角

学术 LaTeX 中文输出**强制规范**:中文支持 + 边界溢出检查 + 目录约束。

## 1. 中文支持

使用 `ctex` 宏包或 `xeCJK`,确保中英文混排正常。

```latex
\documentclass[11pt]{article}
\usepackage[UTF8]{ctex}                    % 中文支持
% 或
\usepackage{xeCJK}
\setCJKmainfont{SimSun}                    % 或 Microsoft YaHei
```

## 2. 边界溢出检查(每次编译后)

**每次编译后必须检查**:

- `overfull hbox` 警告
- `overfull vbox` 警告

### 长公式

用 `aligned` / `multline` / `split` 环境换行:

```latex
% 长公式不要单行
\begin{aligned}
L(\theta) &= \mathbb{E}_{x \sim \mathcal{D}}[\ell(f_\theta(x), y)] \\
          &\quad + \lambda \|\theta\|^2_2 \\
          &\quad + \mu \mathcal{R}(\theta)
\end{aligned}
```

### 长表格

用 `tabularx` 或 `adjustbox` 控制宽度:

```latex
\begin{tabularx}{\textwidth}{|X|X|X|}
\hline
长 col 1 内容 & 长 col 2 内容 & 长 col 3 内容 \\
\hline
\end{tabularx}
```

### 代码块

用 `lstlisting` 并设置 `breaklines=true`:

```latex
\lstset{
    breaklines=true,
    breakatwhitespace=true,
    basicstyle=\ttfamily\small
}
```

## 3. 图表规范

所有图表必须有**中文标题和编号**,引用时使用 `\ref{}`:

```latex
\begin{figure}[h]
\centering
\includegraphics[width=\textwidth]{fig1.pdf}
\caption{低信噪比下不同优化器的训练曲线对比}
\label{fig:opt_compare}
\end{figure}

% 引用
如图~\ref{fig:opt_compare} 所示,AdamW 在 ...
```

## 4. 参考文献

使用 BibTeX 管理,引用格式统一:

```latex
\bibliographystyle{plainnat}
\bibliography{references}

% 引用
\cite{wataoka2024}
```

References.bib:

```bibtex
@article{wataoka2024,
    author = {Wataoka, Koki and ...},
    title  = {Self-Preference Bias in LLM-as-a-Judge},
    journal = {arXiv preprint},
    year = {2024},
    eprint = {2410.21819}
}
```

## 5. 编译链

**强制顺序**: XeLaTeX → BibTeX → XeLaTeX × 2

```bash
cd latex_src/
xelatex main.tex
bibtex main
xelatex main.tex
xelatex main.tex
# 输出 main.pdf,复制到 docs/ 一级目录
cp main.pdf ../research_paper.pdf
```

## 6. 目录约束(硬要求)

**所有 tex / bib / aux / out / log 等辅助文件必须放在 `latex_src/` 子文件夹**,一级目录只放最终的 pdf 和 md:

```
docs/litreview/
├── RESEARCH_LITREVIEW_AND_ANALYSIS.md    # 一级 md
├── RESEARCH_LITREVIEW_AND_ANALYSIS.pdf   # 一级 pdf
├── PHASE1_STEP1_*.md                     # 一级 md
├── ...
└── latex_src/                            # LaTeX 源文件子文件夹
    ├── main.tex
    ├── references.bib
    ├── main.aux                          # 编译辅助
    ├── main.log
    ├── main.bbl
    ├── main.toc
    └── figures/
        └── fig1.pdf
```

**禁止**:
- ❌ 一级目录放 .tex / .aux / .log
- ❌ Source 和 PDF 混在一级

同样规则应用于 `docs/paper/` / `docs/slides/`:一级只放 PDF,源文件放 `latex_src/` 子文件夹。

## Self-check checklist(每次 PDF 产出前)

- [ ] PDF 编译无 fatal error?
- [ ] grep "overfull" main.log 无 hbox / vbox 警告?
- [ ] 中文显示正常(不是方块 / 乱码)?
- [ ] 所有 figure 有中文 caption + label?
- [ ] 引用编号正确(`\ref` 不显示 ??)?
- [ ] References 全部 cited?
- [ ] latex_src/ 子文件夹存在,一级只 pdf+md?

## 反模式

- ❌ 不用 ctex / xeCJK 直接 \\usepackage{CJKutf8}(配置麻烦,推荐 ctex)
- ❌ 长公式单行不换行,导致 overfull hbox
- ❌ 编译跑一次就 claim done(应 XeLaTeX → BibTeX → XeLaTeX × 2)
- ❌ Source 放一级目录(应放 latex_src/)
- ❌ PDF 含中文 caption 但 figure 文件名是英文(混乱)
- ❌ \\ref 显示 "??" 不重新跑编译

## 与其他 skill 的关系

- 与 `core/chinese-output`: 必读 — 中文优先
- 与 `output/progress-log-format`: 不直接关联,但 LaTeX 编译 status 进 PROGRESS_LOG

## Provenance

来自 user CLAUDE 1/2/4/5 反复强调的 LaTeX 输出规范。
"latex_src/ 子文件夹隔离" 是 user 实测的关键 — 一级目录混 tex / pdf / md 后,user 难找最终 pdf。
