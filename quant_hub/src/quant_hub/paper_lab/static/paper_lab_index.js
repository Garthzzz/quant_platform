(() => {
  "use strict";

  const root = document.querySelector("[data-paper-lab-index]");
  if (!root) return;

  const FIELD_LABELS = {
    id: "编号", title: "论文标题", link: "链接", authors: "作者", venue: "发表渠道",
    institution: "机构", model_type: "模型类型", asset_market: "资产市场",
    start_year: "开始年份", end_year: "结束年份", study_period: "研究时间",
    sample_length: "样本长度", prediction_target: "预测目标", input_features: "输入特征",
    feature_count: "特征数量", oos_method: "样本外测试", metrics: "评估指标",
    performance: "核心结果", special_tech: "特殊技术", source_type: "来源类型",
    research_topic: "研究主题", main_findings: "主要结论",
    innovations_insights: "创新与启发", caveats_replication: "质疑与复现",
    summary: "结构化摘要", rating: "推荐评级", data_input: "输入数据",
    data_preprocess: "预处理", method_model: "模型架构", method_special: "特殊方法",
    loss_function: "损失函数", training_config: "训练配置", pipeline_output: "输出层",
    diagram: "架构图", status: "状态", phase: "阶段", updated_at: "更新时间",
  };
  const COLUMN_GROUPS = [
    ["默认显示", [["id", true], ["title", true], ["model_type", true], ["asset_market", true], ["rating", true]]],
    ["基本信息", [["link", false], ["authors", false], ["venue", false], ["institution", false], ["source_type", false], ["start_year", false], ["end_year", false], ["study_period", false], ["sample_length", false]]],
    ["研究设计", [["prediction_target", false], ["input_features", false], ["feature_count", false], ["oos_method", false], ["metrics", false], ["performance", false], ["special_tech", false], ["research_topic", false]]],
    ["数据层", [["data_input", false], ["data_preprocess", false]]],
    ["方法层", [["method_model", false], ["method_special", false], ["loss_function", false], ["training_config", false]]],
    ["输出层", [["pipeline_output", false]]],
    ["内容字段", [["main_findings", false], ["innovations_insights", false], ["caveats_replication", false], ["summary", false], ["diagram", false]]],
    ["其他", [["status", false], ["phase", false], ["updated_at", false]]],
  ];
  const EXPORT_FIELDS = [
    "id", "title", "link", "authors", "venue", "institution", "model_type",
    "asset_market", "end_year", "study_period", "sample_length", "prediction_target",
    "input_features", "feature_count", "oos_method", "metrics", "performance",
    "special_tech", "source_type", "research_topic", "main_findings",
    "innovations_insights", "caveats_replication", "summary", "rating", "diagram",
    "pdf_path", "notes_path", "status", "phase", "updated_at", "data_input",
    "data_preprocess", "method_model", "method_special", "loss_function",
    "pipeline_output", "training_config", "start_year",
  ];
  const PIPELINE_FIELDS = [
    "data_input", "data_preprocess", "method_model", "method_special",
    "loss_function", "training_config", "pipeline_output",
  ];
  const DRAWER_FIELDS = [
    "link", "authors", "venue", "institution", "model_type", "asset_market",
    "study_period", "sample_length", "prediction_target", "input_features",
    "feature_count", "oos_method", "metrics", "performance", "special_tech",
    "source_type", "research_topic", "rating", "data_input", "data_preprocess",
    "method_model", "method_special", "loss_function", "training_config",
    "pipeline_output", "main_findings", "innovations_insights",
    "caveats_replication", "summary", "diagram",
  ];
  const EDITABLE_FIELDS = new Set([
    "title", "link", "authors", "venue", "institution", "model_type", "asset_market",
    "start_year", "end_year", "study_period", "sample_length", "prediction_target",
    "input_features", "feature_count", "oos_method", "metrics", "performance",
    "special_tech", "source_type", "research_topic", "main_findings",
    "innovations_insights", "caveats_replication", "summary", "rating", "data_input",
    "data_preprocess", "method_model", "method_special", "loss_function",
    "training_config", "pipeline_output", "diagram", "status", "phase",
  ]);
  const DEFAULT_RATINGS = new Set(["强烈推荐", "推荐", "一般"]);

  const queryInput = document.getElementById("paper-lab-query");
  const rowsNode = document.getElementById("paper-lab-rows");
  const summaryNode = document.getElementById("paper-lab-summary");
  const selectedCount = document.getElementById("paper-selected-count");
  const activeFiltersNode = document.getElementById("paper-active-filters");
  const csrfToken = root.dataset.csrfToken || "";
  let allPapers = [];
  let filteredPapers = [];
  let selectedIds = new Set();
  let columnFilters = {};
  let includesFilters = {};
  let sortColumn = "id";
  let sortAscending = true;
  let curated = true;
  let currentView = "list";
  let drawerPaper = null;
  let restoreFocus = null;
  let searchTimer;

  const escapeHtml = value => String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
  const normalize = paper => ({
    ...paper,
    id: String(paper.legacy_id || paper.id || ""),
    field_overlay_versions: paper.field_overlay_versions || {},
  });
  const value = (paper, field) => String(paper?.[field] ?? "");
  const truncate = (text, length = 80) => {
    const content = String(text ?? "");
    return content.length > length ? `${content.slice(0, length)}…` : content;
  };
  const extractRating = rating => String(rating || "").split(/\s*[—-]\s*/)[0].trim();
  const splitValues = text => String(text || "").split(/,\s*/).map(item => item.trim()).filter(Boolean);
  const paperKey = paper => paper.paper_id;
  const safeExternalUrl = candidate => {
    try {
      const url = new URL(String(candidate || ""));
      return ["http:", "https:"].includes(url.protocol) ? url.href : "";
    } catch (_) {
      return "";
    }
  };
  const newIdentifier = () => globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(16).slice(2)}`;

  const ratingClass = rating => ({
    "强烈推荐": "paper-rating-strong", "推荐": "paper-rating-recommend",
    "一般": "paper-rating-neutral", "不太推荐": "paper-rating-low",
    "不推荐": "paper-rating-reject",
  })[extractRating(rating)] || "paper-rating-neutral";
  const modelClass = model => {
    if (model.startsWith("深度学习")) return "paper-model-deep";
    if (model.startsWith("树模型")) return "paper-model-tree";
    if (model.startsWith("机器学习")) return "paper-model-ml";
    if (model.startsWith("统计模型")) return "paper-model-stat";
    if (model.startsWith("大语言")) return "paper-model-llm";
    if (model.startsWith("符号回归")) return "paper-model-symbolic";
    return "paper-model-other";
  };
  const pipelineClass = field => ({
    data_input: "paper-pipeline-data", data_preprocess: "paper-pipeline-preprocess",
    method_model: "paper-pipeline-model", method_special: "paper-pipeline-special",
    loss_function: "paper-pipeline-loss", training_config: "paper-pipeline-training",
    pipeline_output: "paper-pipeline-output",
  })[field] || "paper-pipeline-data";
  const formatTime = text => {
    if (!text) return "";
    const date = new Date(text);
    if (Number.isNaN(date.getTime())) return truncate(text, 19);
    return new Intl.DateTimeFormat("zh-CN", {
      year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit",
    }).format(date);
  };

  const renderModelTags = text => splitValues(text).map(model => (
    `<span class="paper-tag ${modelClass(model)}">${escapeHtml(model)}</span>`
  )).join("") || '<span class="paper-empty-value">—</span>';
  const pipelineSummary = (text, field) => {
    if (!text) return '<span class="paper-empty-value">—</span>';
    if (["待补充", "未披露", "标准输出，无特殊处理"].includes(text)) {
      return `<span class="paper-empty-value">${escapeHtml(text)}</span>`;
    }
    const tags = String(text).split("\n")
      .filter(line => line.includes("|") && !line.trim().startsWith("→"))
      .map(line => line.split("|")[0].trim()).filter(Boolean);
    return tags.map(tag => {
      const label = tag.includes("-") ? tag.split("-").slice(1).join("-") : tag;
      return `<span class="paper-pipeline-tag ${pipelineClass(field)}">${escapeHtml(label)}</span>`;
    }).join("") || `<span class="paper-cell-wrap">${escapeHtml(truncate(text, 60))}</span>`;
  };
  const localPdfUrl = paper => `/api/v1/paper-lab/versions/${encodeURIComponent(paper.paper_version_id)}/content`;
  const renderLink = paper => {
    const external = safeExternalUrl(paper.link);
    if (external) return `<a class="paper-cell-link" href="${escapeHtml(external)}" target="_blank" rel="noopener" aria-label="打开论文外部链接">外链</a>`;
    return `<a class="paper-cell-link" href="${localPdfUrl(paper)}" target="_blank" rel="noopener" aria-label="打开本地 PDF">PDF</a>`;
  };

  const renderCell = (paper, field) => {
    if (field === "id") return escapeHtml(paper.id);
    if (field === "title") return `<button type="button" class="paper-title-button" data-open-paper="${escapeHtml(paperKey(paper))}">${escapeHtml(paper.title || "未命名论文")}</button>`;
    if (field === "model_type") return renderModelTags(paper.model_type);
    if (field === "rating") return `<span class="paper-rating ${ratingClass(paper.rating)}">${escapeHtml(extractRating(paper.rating) || "未评级")}</span>`;
    if (field === "status") return `<span class="paper-status"><i data-status="${escapeHtml(paper.status || "unknown")}" aria-hidden="true"></i>${escapeHtml(paper.status || "—")}</span>`;
    if (PIPELINE_FIELDS.includes(field)) return pipelineSummary(paper[field], field);
    if (field === "link") return renderLink(paper);
    if (field === "updated_at") return escapeHtml(formatTime(paper.updated_at));
    const long = ["main_findings", "innovations_insights", "caveats_replication", "summary"].includes(field);
    const limit = long ? 80 : (["authors", "venue", "prediction_target", "input_features", "oos_method", "metrics", "performance", "special_tech"].includes(field) ? 40 : 60);
    const content = truncate(paper[field], limit);
    return content ? `<span class="${long ? "paper-cell-wrap" : ""}" title="${escapeHtml(value(paper, field))}">${escapeHtml(content)}</span>` : '<span class="paper-empty-value">—</span>';
  };

  const visibleColumns = () => new Set(
    [...document.querySelectorAll("[data-column-toggle]:checked")].map(input => input.value),
  );
  const applyColumnVisibility = () => {
    const visible = visibleColumns();
    for (const node of root.querySelectorAll("[data-colkey]")) {
      node.hidden = !visible.has(node.dataset.colkey);
    }
  };
  const initializeColumns = () => {
    const container = document.getElementById("paper-column-groups");
    for (const [groupLabel, fields] of COLUMN_GROUPS) {
      const group = document.createElement("fieldset");
      const legend = document.createElement("legend");
      legend.textContent = groupLabel;
      group.append(legend);
      for (const [field, shown] of fields) {
        const label = document.createElement("label");
        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.value = field;
        checkbox.checked = shown;
        checkbox.dataset.columnToggle = field;
        checkbox.addEventListener("change", applyColumnVisibility);
        label.append(checkbox, document.createTextNode(FIELD_LABELS[field]));
        group.append(label);
      }
      container.append(group);
    }
  };

  const sortedPapers = papers => [...papers].sort((left, right) => {
    let a = left[sortColumn] ?? "";
    let b = right[sortColumn] ?? "";
    if (["id", "start_year", "end_year", "feature_count"].includes(sortColumn)) {
      a = Number.parseFloat(a) || 0;
      b = Number.parseFloat(b) || 0;
    } else {
      if (sortColumn === "rating") {
        a = extractRating(a);
        b = extractRating(b);
      }
      a = String(a).toLocaleLowerCase("zh-CN");
      b = String(b).toLocaleLowerCase("zh-CN");
    }
    const result = a < b ? -1 : (a > b ? 1 : 0);
    return sortAscending ? result : -result;
  });

  const matchesAdvanced = paper => {
    const contains = (id, field) => {
      const term = document.getElementById(id).value.trim().toLocaleLowerCase("zh-CN");
      return !term || value(paper, field).toLocaleLowerCase("zh-CN").includes(term);
    };
    if (!contains("paper-adv-model", "model_type")) return false;
    if (!contains("paper-adv-tech", "special_tech")) return false;
    if (!contains("paper-adv-market", "asset_market")) return false;
    if (!contains("paper-adv-data-input", "data_input")) return false;
    if (!contains("paper-adv-data-preprocess", "data_preprocess")) return false;
    if (!contains("paper-adv-method-model", "method_model")) return false;
    if (!contains("paper-adv-loss", "loss_function")) return false;
    const any = document.getElementById("paper-adv-any").value.trim().toLocaleLowerCase("zh-CN");
    if (any && !Object.values(paper).join(" ").toLocaleLowerCase("zh-CN").includes(any)) return false;
    const rating = document.getElementById("paper-adv-rating").value;
    if (rating && extractRating(paper.rating) !== rating) return false;
    const source = document.getElementById("paper-adv-source").value;
    if (source && paper.source_type !== source) return false;
    const methodAny = document.getElementById("paper-adv-method-any").value.trim().toLocaleLowerCase("zh-CN");
    if (methodAny && !PIPELINE_FIELDS.map(field => value(paper, field)).join(" ").toLocaleLowerCase("zh-CN").includes(methodAny)) return false;
    return true;
  };

  const paperMatches = paper => {
    const query = queryInput.value.trim().toLocaleLowerCase("zh-CN");
    if (query) {
      const haystack = Object.entries(paper)
        .filter(([key]) => !["field_overlay_versions", "field_overlay_ids"].includes(key))
        .map(([, item]) => String(item ?? "")).join(" ").toLocaleLowerCase("zh-CN");
      if (!haystack.includes(query)) return false;
    }
    if (curated) {
      if (!["深度学习", "机器学习"].some(term => value(paper, "model_type").includes(term))) return false;
      if (!DEFAULT_RATINGS.has(extractRating(paper.rating))) return false;
      if (paper.research_topic !== "选股策略") return false;
    }
    for (const [field, accepted] of Object.entries(columnFilters)) {
      if (!accepted.size) continue;
      if (["model_type", "asset_market"].includes(field)) {
        if (!splitValues(paper[field]).some(item => accepted.has(item))) return false;
      } else {
        const candidate = field === "rating" ? extractRating(paper[field]) : value(paper, field);
        if (!accepted.has(candidate)) return false;
      }
    }
    for (const [field, pattern] of Object.entries(includesFilters)) {
      if (!pattern) continue;
      if (field === "method_fields") {
        if (!PIPELINE_FIELDS.map(key => value(paper, key)).join(" ").includes(pattern)) return false;
      } else if (Array.isArray(pattern)) {
        if (!pattern.some(item => value(paper, field).includes(item))) return false;
      } else if (!value(paper, field).includes(pattern)) return false;
    }
    return matchesAdvanced(paper);
  };

  const renderTable = () => {
    const columns = [...document.querySelectorAll("#paper-lab-table thead [data-colkey]")].map(th => th.dataset.colkey);
    const html = sortedPapers(filteredPapers).map(paper => {
      const checked = selectedIds.has(paperKey(paper));
      const cells = columns.map(field => `<td data-colkey="${field}">${renderCell(paper, field)}</td>`).join("");
      return `<tr class="${checked ? "is-selected" : ""}" data-paper-row="${escapeHtml(paperKey(paper))}">
        <td class="paper-check-column"><label class="visually-hidden" for="paper-check-${escapeHtml(paperKey(paper))}">选择 ${escapeHtml(paper.title)}</label><input id="paper-check-${escapeHtml(paperKey(paper))}" type="checkbox" data-paper-check="${escapeHtml(paperKey(paper))}" ${checked ? "checked" : ""}></td>${cells}</tr>`;
    }).join("");
    rowsNode.innerHTML = html || '<tr><td class="paper-no-results" colspan="38">没有符合当前条件的论文。请清除筛选或切换至全量。</td></tr>';
    applyColumnVisibility();
    updateSelection();
  };
  const updateSelection = () => {
    selectedCount.textContent = `已选择 ${selectedIds.size} 篇`;
    const checkAll = document.getElementById("paper-check-all");
    const visibleKeys = filteredPapers.map(paperKey);
    const selectedVisible = visibleKeys.filter(id => selectedIds.has(id)).length;
    checkAll.checked = Boolean(visibleKeys.length) && selectedVisible === visibleKeys.length;
    checkAll.indeterminate = selectedVisible > 0 && selectedVisible < visibleKeys.length;
  };
  const applyFilters = () => {
    filteredPapers = allPapers.filter(paperMatches);
    renderTable();
    renderActiveFilters();
    summaryNode.textContent = `当前显示 ${filteredPapers.length} / ${allPapers.length} 篇论文。`;
    syncUrl();
  };

  const createFilterChip = (label, remove) => {
    const chip = document.createElement("span");
    chip.className = "paper-filter-chip";
    chip.append(document.createTextNode(label));
    const button = document.createElement("button");
    button.type = "button";
    button.setAttribute("aria-label", `移除筛选：${label}`);
    button.textContent = "×";
    button.addEventListener("click", remove);
    chip.append(button);
    return chip;
  };
  const renderActiveFilters = () => {
    activeFiltersNode.replaceChildren();
    if (curated) {
      activeFiltersNode.append(createFilterChip("精选：选股策略 · 深度/机器学习 · 评级一般及以上", () => {
        curated = false;
        updateCuratedButton();
        applyFilters();
      }));
    }
    for (const [field, accepted] of Object.entries(columnFilters)) {
      for (const acceptedValue of accepted) {
        activeFiltersNode.append(createFilterChip(`${FIELD_LABELS[field]}：${acceptedValue || "空值"}`, () => {
          columnFilters[field].delete(acceptedValue);
          if (!columnFilters[field].size) delete columnFilters[field];
          applyFilters();
        }));
      }
    }
    for (const [field, pattern] of Object.entries(includesFilters)) {
      const label = Array.isArray(pattern) ? pattern.join(" / ") : pattern;
      activeFiltersNode.append(createFilterChip(`${FIELD_LABELS[field] || "方法字段"}包含：${label}`, () => {
        delete includesFilters[field];
        applyFilters();
      }));
    }
    if (activeFiltersNode.childElementCount) {
      const clear = document.createElement("button");
      clear.type = "button";
      clear.className = "paper-clear-filters";
      clear.textContent = "清除全部筛选";
      clear.addEventListener("click", () => {
        columnFilters = {};
        includesFilters = {};
        curated = false;
        updateCuratedButton();
        applyFilters();
      });
      activeFiltersNode.append(clear);
    }
    activeFiltersNode.hidden = !activeFiltersNode.childElementCount;
  };

  const initializeHeadings = () => {
    for (const heading of document.querySelectorAll("#paper-lab-table thead th[data-colkey]")) {
      const field = heading.dataset.colkey;
      heading.scope = "col";
      const text = FIELD_LABELS[field] || heading.textContent.trim();
      heading.textContent = "";
      if (heading.dataset.sort) {
        const sort = document.createElement("button");
        sort.type = "button";
        sort.className = "paper-sort-button";
        sort.dataset.sortField = field;
        sort.textContent = text;
        const indicator = document.createElement("span");
        indicator.className = "paper-sort-indicator";
        indicator.setAttribute("aria-hidden", "true");
        sort.append(indicator);
        heading.append(sort);
      } else {
        const label = document.createElement("span");
        label.textContent = text;
        heading.append(label);
      }
      if (heading.dataset.filter) {
        const filter = document.createElement("button");
        filter.type = "button";
        filter.className = "paper-filter-button";
        filter.dataset.filterField = field;
        filter.dataset.filterKind = heading.dataset.filter;
        filter.setAttribute("aria-label", `筛选${text}`);
        filter.textContent = "▾";
        heading.append(filter);
      }
    }
    updateSortIndicators();
  };
  const updateSortIndicators = () => {
    for (const button of document.querySelectorAll("[data-sort-field]")) {
      const active = button.dataset.sortField === sortColumn;
      button.setAttribute("aria-sort", active ? (sortAscending ? "ascending" : "descending") : "none");
      button.querySelector(".paper-sort-indicator").textContent = active ? (sortAscending ? "↑" : "↓") : "";
    }
  };

  const closeColumnFilter = () => {
    const panel = document.getElementById("paper-column-filter");
    panel.hidden = true;
    panel.replaceChildren();
  };
  const countExactValues = field => {
    const counts = new Map();
    for (const paper of allPapers) {
      const candidate = field === "rating" ? extractRating(paper[field]) : value(paper, field);
      counts.set(candidate, (counts.get(candidate) || 0) + 1);
    }
    return [...counts.entries()].sort((left, right) => right[1] - left[1]);
  };
  const renderExactFilter = (panel, field) => {
    const entries = countExactValues(field);
    const active = columnFilters[field] || new Set(entries.map(([item]) => item));
    const search = document.createElement("input");
    search.type = "search";
    search.autocomplete = "off";
    search.placeholder = "筛选可选值…";
    search.setAttribute("aria-label", `检索${FIELD_LABELS[field]}筛选值`);
    panel.append(search);
    const options = document.createElement("div");
    options.className = "paper-column-filter-options";
    for (const [item, count] of entries) {
      const label = document.createElement("label");
      label.dataset.filterOption = item.toLocaleLowerCase("zh-CN");
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.value = item;
      checkbox.checked = active.has(item);
      label.append(checkbox, document.createTextNode(`${item || "空值"}（${count}）`));
      options.append(label);
    }
    panel.append(options);
    search.addEventListener("input", () => {
      const term = search.value.toLocaleLowerCase("zh-CN");
      for (const label of options.children) label.hidden = !label.dataset.filterOption.includes(term);
    });
    options.addEventListener("change", () => {
      const accepted = new Set([...options.querySelectorAll("input:checked")].map(input => input.value));
      if (accepted.size === entries.length) delete columnFilters[field];
      else columnFilters[field] = accepted;
      applyFilters();
    });
  };
  const hierarchicalEntries = (field, kind) => {
    const counts = new Map();
    for (const paper of allPapers) {
      const items = kind === "pipeline"
        ? value(paper, field).split("\n").filter(line => line.includes("|")).map(line => line.split("|")[0].trim()).filter(Boolean)
        : splitValues(paper[field]);
      for (const item of new Set(items)) counts.set(item, (counts.get(item) || 0) + 1);
    }
    const parents = new Map();
    for (const [item, count] of counts) {
      const parent = item.includes("-") ? item.split("-")[0] : item;
      if (!parents.has(parent)) parents.set(parent, {count: 0, children: []});
      parents.get(parent).count += count;
      if (item !== parent) parents.get(parent).children.push([item, count]);
    }
    return [...parents.entries()].sort((left, right) => right[1].count - left[1].count);
  };
  const renderHierarchyFilter = (panel, field, kind) => {
    const entries = hierarchicalEntries(field, kind);
    const list = document.createElement("div");
    list.className = "paper-column-filter-options paper-hierarchy-options";
    if (!entries.length) list.append(Object.assign(document.createElement("p"), {textContent: "当前字段没有可筛选值。"}));
    for (const [parent, group] of entries) {
      const parentButton = document.createElement("button");
      parentButton.type = "button";
      parentButton.dataset.includeValue = parent;
      parentButton.textContent = `${parent}（${group.count}）`;
      list.append(parentButton);
      for (const [child, count] of group.children.sort((a, b) => b[1] - a[1])) {
        const childButton = document.createElement("button");
        childButton.type = "button";
        childButton.className = "paper-hierarchy-child";
        childButton.dataset.includeValue = child;
        childButton.textContent = `${child.replace(`${parent}-`, "")}（${count}）`;
        list.append(childButton);
      }
    }
    panel.append(list);
    list.addEventListener("click", event => {
      const button = event.target.closest("[data-include-value]");
      if (!button) return;
      includesFilters[field] = button.dataset.includeValue;
      delete columnFilters[field];
      closeColumnFilter();
      applyFilters();
    });
  };
  const openColumnFilter = button => {
    const panel = document.getElementById("paper-column-filter");
    panel.replaceChildren();
    const header = document.createElement("header");
    const strong = document.createElement("strong");
    strong.textContent = FIELD_LABELS[button.dataset.filterField];
    const clear = document.createElement("button");
    clear.type = "button";
    clear.textContent = "清除此列";
    clear.addEventListener("click", () => {
      delete columnFilters[button.dataset.filterField];
      delete includesFilters[button.dataset.filterField];
      closeColumnFilter();
      applyFilters();
    });
    header.append(strong, clear);
    panel.append(header);
    if (button.dataset.filterKind === "exact") renderExactFilter(panel, button.dataset.filterField);
    else renderHierarchyFilter(panel, button.dataset.filterField, button.dataset.filterKind);
    panel.hidden = false;
    panel.querySelector("input, button")?.focus();
  };

  const updateCuratedButton = () => {
    const button = document.getElementById("paper-lab-curated-toggle");
    button.setAttribute("aria-pressed", String(curated));
    button.textContent = curated ? "显示全量" : "恢复精选";
  };
  const switchView = view => {
    currentView = view;
    for (const button of document.querySelectorAll("[data-paper-view]")) {
      button.setAttribute("aria-selected", String(button.dataset.paperView === view));
    }
    for (const name of ["list", "stats", "compare"]) {
      document.getElementById(`paper-view-${name}`).hidden = name !== view;
    }
    if (view === "stats") renderStats();
    if (view === "compare") renderCompare();
    syncUrl();
  };
  const syncUrl = () => {
    const url = new URL(globalThis.location.href);
    url.search = "";
    if (queryInput.value.trim()) url.searchParams.set("q", queryInput.value.trim());
    if (!curated) url.searchParams.set("mode", "all");
    if (currentView !== "list") url.searchParams.set("view", currentView);
    globalThis.history.replaceState(globalThis.history.state, "", url);
  };

  const counts = (field, mapper = item => item) => {
    const result = new Map();
    for (const paper of allPapers) {
      const items = new Set(splitValues(paper[field]).map(mapper).filter(Boolean));
      for (const item of items) result.set(item, (result.get(item) || 0) + 1);
    }
    return [...result.entries()].sort((left, right) => right[1] - left[1]);
  };
  const statCard = (title, entries, field, colorClass = "paper-stat-blue") => {
    const card = document.createElement("article");
    const heading = document.createElement("h3");
    heading.textContent = title;
    card.append(heading);
    const maximum = Math.max(...entries.map(([, count]) => count), 1);
    for (const [label, count] of entries) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "paper-stat-row";
      button.dataset.statField = field;
      button.dataset.statValue = label;
      button.innerHTML = `<span title="${escapeHtml(label)}">${escapeHtml(label)}</span><meter class="${colorClass}" min="0" max="${maximum}" value="${count}">${count} / ${maximum}</meter><em>${count}</em>`;
      card.append(button);
    }
    if (!entries.length) card.append(Object.assign(document.createElement("p"), {className: "empty-state", textContent: "暂无可统计数据。"}));
    return card;
  };
  const pipelineCounts = field => {
    const result = new Map();
    for (const paper of allPapers) {
      const parents = new Set(value(paper, field).split("\n").filter(line => line.includes("|")).map(line => line.split("|")[0].trim().split("-")[0]).filter(Boolean));
      for (const parent of parents) result.set(parent, (result.get(parent) || 0) + 1);
    }
    return [...result.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  };
  const renderStats = () => {
    const node = document.getElementById("paper-stats");
    node.replaceChildren(
      statCard("模型类型分布", counts("model_type", item => item.split("-")[0]), "model_type", "paper-stat-violet"),
      statCard("推荐评级分布", counts("rating", extractRating), "rating", "paper-stat-green"),
      statCard("资产市场分布", counts("asset_market", item => item.split("-")[0]), "asset_market", "paper-stat-blue"),
      statCard("旧流程状态", counts("status"), "status", "paper-stat-slate"),
      statCard("模型架构分布", pipelineCounts("method_model"), "method_model", "paper-stat-violet"),
      statCard("损失函数分布", pipelineCounts("loss_function"), "loss_function", "paper-stat-red"),
    );
  };

  const fillCompareOptions = () => {
    for (const id of ["paper-compare-1", "paper-compare-2", "paper-compare-3"]) {
      const select = document.getElementById(id);
      const first = select.options[0];
      select.replaceChildren(first);
      for (const paper of allPapers) {
        const option = document.createElement("option");
        option.value = paperKey(paper);
        option.textContent = `[${paper.id}] ${truncate(paper.title, 48)}`;
        select.append(option);
      }
    }
  };
  const renderCompare = () => {
    const ids = ["paper-compare-1", "paper-compare-2", "paper-compare-3"]
      .map(id => document.getElementById(id).value).filter(Boolean);
    const node = document.getElementById("paper-compare-result");
    if (ids.length < 2) {
      node.innerHTML = '<p class="empty-state">请选择至少 2 篇论文，或先在列表中勾选论文。</p>';
      return;
    }
    const papers = ids.map(id => allPapers.find(paper => paperKey(paper) === id)).filter(Boolean);
    const fields = ["title", "model_type", "asset_market", "study_period", "metrics", "performance", "special_tech", "rating", "innovations_insights", "caveats_replication", "summary"];
    const head = papers.map(paper => `<th>[${escapeHtml(paper.id)}] ${escapeHtml(truncate(paper.title, 30))}</th>`).join("");
    const body = fields.map(field => {
      const values = papers.map(paper => value(paper, field));
      const same = values.every(item => item === values[0]);
      return `<tr><th>${escapeHtml(FIELD_LABELS[field])}</th>${values.map(item => `<td class="${same ? "" : "is-different"}">${escapeHtml(item || "—")}</td>`).join("")}</tr>`;
    }).join("");
    node.innerHTML = `<div class="table-scroll" tabindex="0" role="region" aria-label="论文对比，可横向滚动"><table class="paper-compare-table"><thead><tr><th>字段</th>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
  };

  const renderPipelineDetail = (text, field) => {
    if (!text) return '<p class="paper-empty-value">—</p>';
    if (["待补充", "未披露", "标准输出，无特殊处理"].includes(text)) return `<p class="paper-empty-value">${escapeHtml(text)}</p>`;
    let html = "";
    for (const line of String(text).split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      if (trimmed.startsWith("→")) html += `<p class="paper-pipeline-note"><span class="paper-pipeline-arrow" aria-hidden="true">→</span><span class="paper-pipeline-note-text">${escapeHtml(trimmed.slice(1).trim())}</span></p>`;
      else if (trimmed.includes("|")) {
        const [tag = "", name = "", method = ""] = trimmed.split("|").map(item => item.trim());
        html += `<div class="paper-pipeline-card"><span class="paper-pipeline-tag ${pipelineClass(field)}">${escapeHtml(tag)}</span><strong>${escapeHtml(name)}</strong>${method ? `<small>— ${escapeHtml(method)}</small>` : ""}</div>`;
      } else html += `<p class="paper-pipeline-note">${escapeHtml(trimmed)}</p>`;
    }
    return html;
  };
  const renderSectionDetail = text => {
    if (!text) return '<p class="paper-empty-value">—</p>';
    const escaped = escapeHtml(text).replace(/\n/g, "<br>");
    return escaped
      .replace(/【创新点】/g, '<strong class="paper-section-marker paper-marker-innovation">【创新点】</strong>')
      .replace(/【启发】/g, '<strong class="paper-section-marker paper-marker-insight">【启发】</strong>')
      .replace(/【质疑】/g, '<strong class="paper-section-marker paper-marker-caveat">【质疑】</strong>')
      .replace(/【复现注意】/g, '<strong class="paper-section-marker paper-marker-replication">【复现注意】</strong>');
  };
  const renderDrawerValue = (paper, field) => {
    const text = value(paper, field);
    if (field === "link") {
      const external = safeExternalUrl(text);
      const externalHtml = external ? `<a href="${escapeHtml(external)}" target="_blank" rel="noopener">${escapeHtml(text)}</a>` : (text ? `<span>${escapeHtml(text)}</span>` : "");
      return `${externalHtml}<a class="paper-inline-pdf" href="${localPdfUrl(paper)}" target="_blank" rel="noopener">打开本地 PDF</a>`;
    }
    if (field === "diagram") {
      if (!text) return '<p class="paper-empty-value">—</p>';
      return `<div class="paper-diagram-preview"><pre>${escapeHtml(text)}</pre><button type="button" data-open-diagram>全屏查看</button></div>`;
    }
    const presented = paper.presentation_html?.[field];
    if (typeof presented === "string" && presented) return presented;
    if (PIPELINE_FIELDS.includes(field)) return renderPipelineDetail(text, field);
    if (["innovations_insights", "caveats_replication"].includes(field)) return renderSectionDetail(text);
    if (field === "rating") return `<span class="paper-rating ${ratingClass(text)}">${escapeHtml(extractRating(text) || "未评级")}</span>${text.includes("—") ? `<p>${escapeHtml(text.split("—").slice(1).join("—").trim())}</p>` : ""}`;
    return text ? `<p>${escapeHtml(text)}</p>` : '<p class="paper-empty-value">—</p>';
  };
  const renderDrawer = paper => {
    drawerPaper = paper;
    const content = document.getElementById("paper-drawer-content");
    document.getElementById("paper-drawer-title").textContent = `[${paper.id || "NEW"}] ${paper.title}`;
    const notes = (paper.notes || []).map(note => `<li><a href="/api/v1/paper-lab/notes/${encodeURIComponent(note.note_id)}/content" target="_blank" rel="noopener">${escapeHtml(note.template_status || "精读笔记")}${note.is_canonical ? " · canonical" : ""}</a></li>`).join("");
    const quarantine = (paper.quarantine || []).map(item => `<li><strong>${escapeHtml(item.issue_code || "迁移异常")}</strong>：${escapeHtml(item.detail || item.reason || item.severity || "待核验")}</li>`).join("");
    const fields = DRAWER_FIELDS.map(field => `<section class="paper-drawer-field" data-drawer-field="${field}" data-version="${Number(paper.field_overlay_versions?.[field] || 0)}">
      <header><h3>${escapeHtml(FIELD_LABELS[field])}</h3>${EDITABLE_FIELDS.has(field) ? `<button type="button" data-edit-field="${field}">修订</button>` : ""}</header>
      <div class="paper-drawer-value">${renderDrawerValue(paper, field)}</div>
    </section>`).join("");
    content.innerHTML = `
      <div class="paper-drawer-actions"><a href="/paper-lab/papers/${encodeURIComponent(paper.paper_id)}">打开完整详情与全部字段</a><a href="${localPdfUrl(paper)}" target="_blank" rel="noopener">打开本地 PDF</a></div>
      <dl class="paper-workflow-meta"><div><dt>生命周期</dt><dd>${escapeHtml(paper.lifecycle_status || "—")}</dd></div><div><dt>精读状态</dt><dd>${escapeHtml(paper.reading_status || "未建立精读")}</dd></div><div><dt>精读尝试</dt><dd>${escapeHtml(paper.reading_attempt ?? "—")}</dd></div><div><dt>论文版本</dt><dd>${escapeHtml(paper.paper_version_id || "—")}</dd></div></dl>
      <label class="paper-drawer-actor">修订者<input id="paper-drawer-actor" name="paper_drawer_actor" value="本地研究员" maxlength="160" autocomplete="name"></label>
      <section class="paper-material-links"><h3>精读材料</h3>${notes ? `<ul>${notes}</ul>` : '<p class="paper-empty-value">尚无精读笔记。</p>'}</section>
      ${quarantine ? `<section class="paper-material-links paper-quarantine"><h3>迁移异常与待核验项</h3><ul>${quarantine}</ul></section>` : ""}
      ${fields}`;
  };
  const openDrawer = async paperId => {
    const paper = allPapers.find(item => paperKey(item) === paperId);
    if (!paper) return;
    restoreFocus = document.activeElement;
    const drawer = document.getElementById("paper-detail-drawer");
    const backdrop = document.getElementById("paper-drawer-backdrop");
    drawer.setAttribute("aria-hidden", "false");
    drawer.classList.add("is-open");
    backdrop.hidden = false;
    renderDrawer(paper);
    document.getElementById("paper-drawer-close").focus();
    try {
      const response = await fetch(`/api/v1/paper-lab/papers/${encodeURIComponent(paperId)}`, {headers: {Accept: "application/json"}});
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error?.message || "论文详情读取失败");
      const detailed = normalize(payload.data.paper);
      const index = allPapers.findIndex(item => paperKey(item) === paperId);
      allPapers[index] = detailed;
      renderDrawer(detailed);
    } catch (error) {
      const warning = document.createElement("p");
      warning.className = "paper-drawer-warning";
      warning.textContent = `${error.message}；当前显示列表缓存。`;
      document.getElementById("paper-drawer-content").prepend(warning);
    }
  };
  const closeDrawer = () => {
    const drawer = document.getElementById("paper-detail-drawer");
    drawer.classList.remove("is-open");
    drawer.setAttribute("aria-hidden", "true");
    document.getElementById("paper-drawer-backdrop").hidden = true;
    drawerPaper = null;
    restoreFocus?.focus?.();
  };
  const beginFieldEdit = field => {
    const section = document.querySelector(`[data-drawer-field="${field}"]`);
    if (!section || section.dataset.editing === "true") return;
    section.dataset.editing = "true";
    const current = value(drawerPaper, field);
    const editor = document.createElement("div");
    editor.className = "paper-inline-editor";
    editor.innerHTML = `<label>字段内容<textarea rows="8" maxlength="100000">${escapeHtml(current)}</textarea></label><label>修订说明<input type="text" maxlength="2000" autocomplete="off" placeholder="可选：记录修订依据…"></label><div><button type="button" class="primary-action" data-save-field="${field}">保存新版本</button><button type="button" data-cancel-field="${field}">取消</button><span role="status" aria-live="polite"></span></div>`;
    section.querySelector(".paper-drawer-value").hidden = true;
    section.append(editor);
    editor.querySelector("textarea").focus();
  };
  const cancelFieldEdit = field => {
    const section = document.querySelector(`[data-drawer-field="${field}"]`);
    section?.querySelector(".paper-inline-editor")?.remove();
    if (section) {
      delete section.dataset.editing;
      section.querySelector(".paper-drawer-value").hidden = false;
    }
  };
  const saveFieldEdit = async field => {
    const section = document.querySelector(`[data-drawer-field="${field}"]`);
    const editor = section.querySelector(".paper-inline-editor");
    const actor = document.getElementById("paper-drawer-actor").value.trim();
    const status = editor.querySelector("[role=status]");
    if (!actor) {
      status.textContent = "请先填写修订者。";
      document.getElementById("paper-drawer-actor").focus();
      return;
    }
    const save = editor.querySelector("[data-save-field]");
    save.disabled = true;
    status.textContent = "正在保存…";
    try {
      const response = await fetch(`/api/v1/paper-lab/papers/${encodeURIComponent(drawerPaper.paper_id)}`, {
        method: "PATCH",
        headers: {
          Accept: "application/json", "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken, "Idempotency-Key": `paper-lab-drawer-${newIdentifier()}`,
          "X-Request-ID": newIdentifier(),
        },
        body: JSON.stringify({
          field, value: editor.querySelector("textarea").value,
          expected_version: Number(section.dataset.version || "0"), actor_display_name: actor,
          reason: editor.querySelector("input").value.trim(),
        }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.error?.message || "保存失败");
      const result = payload.data.paper_field;
      drawerPaper[field] = result.value;
      drawerPaper.field_overlay_versions[field] = result.version;
      const index = allPapers.findIndex(item => paperKey(item) === drawerPaper.paper_id);
      allPapers[index] = drawerPaper;
      renderDrawer(drawerPaper);
      applyFilters();
      const actorInput = document.getElementById("paper-drawer-actor");
      if (actorInput) actorInput.value = actor;
    } catch (error) {
      status.textContent = `${error.message}。请重新载入详情后再试。`;
      save.disabled = false;
    }
  };

  const csvValue = item => {
    const text = String(item ?? "");
    return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  };
  const exportCsv = (papers, label) => {
    if (!papers.length) {
      summaryNode.textContent = "当前没有可导出的论文。";
      return;
    }
    const lines = [EXPORT_FIELDS.join(",")];
    for (const paper of papers) {
      lines.push(EXPORT_FIELDS.map(field => {
        let item = field === "id" ? paper.id : paper[field];
        if (field === "diagram" && String(item || "").length > 100) item = `${String(item).slice(0, 100)}…`;
        return csvValue(item);
      }).join(","));
    }
    const blob = new Blob(["\ufeff", lines.join("\r\n")], {type: "text/csv;charset=utf-8"});
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `paper_lab_${label}_${new Date().toISOString().slice(0, 10).replaceAll("-", "")}.csv`;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  };

  const bindEvents = () => {
    root.querySelector(".paper-lab-search").addEventListener("submit", event => {
      event.preventDefault();
      clearTimeout(searchTimer);
      applyFilters();
    });
    queryInput.addEventListener("input", () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(applyFilters, 160);
    });
    document.getElementById("paper-lab-advanced-toggle").addEventListener("click", event => {
      const panel = document.getElementById("paper-lab-advanced");
      panel.hidden = !panel.hidden;
      event.currentTarget.setAttribute("aria-expanded", String(!panel.hidden));
      if (!panel.hidden) panel.querySelector("input")?.focus();
    });
    const advanced = document.getElementById("paper-lab-advanced");
    advanced.addEventListener("submit", event => { event.preventDefault(); applyFilters(); });
    advanced.addEventListener("reset", () => setTimeout(applyFilters, 0));
    document.getElementById("paper-lab-curated-toggle").addEventListener("click", () => {
      curated = !curated;
      updateCuratedButton();
      applyFilters();
    });
    root.querySelector(".paper-view-tabs").addEventListener("click", event => {
      const button = event.target.closest("[data-paper-view]");
      if (button) switchView(button.dataset.paperView);
    });
    document.getElementById("paper-lab-table").addEventListener("click", event => {
      const sort = event.target.closest("[data-sort-field]");
      if (sort) {
        if (sortColumn === sort.dataset.sortField) sortAscending = !sortAscending;
        else { sortColumn = sort.dataset.sortField; sortAscending = true; }
        updateSortIndicators();
        renderTable();
        return;
      }
      const filter = event.target.closest("[data-filter-field]");
      if (filter) { event.stopPropagation(); openColumnFilter(filter); return; }
      const open = event.target.closest("[data-open-paper]");
      if (open) openDrawer(open.dataset.openPaper);
    });
    rowsNode.addEventListener("change", event => {
      const checkbox = event.target.closest("[data-paper-check]");
      if (!checkbox) return;
      if (checkbox.checked) selectedIds.add(checkbox.dataset.paperCheck);
      else selectedIds.delete(checkbox.dataset.paperCheck);
      checkbox.closest("tr").classList.toggle("is-selected", checkbox.checked);
      updateSelection();
    });
    document.getElementById("paper-check-all").addEventListener("change", event => {
      for (const paper of filteredPapers) {
        if (event.target.checked) selectedIds.add(paperKey(paper));
        else selectedIds.delete(paperKey(paper));
      }
      renderTable();
    });
    document.getElementById("paper-compare-selected").addEventListener("click", () => {
      const ids = [...selectedIds];
      if (ids.length < 2) { summaryNode.textContent = "请至少选择 2 篇论文进行对比。"; return; }
      ["paper-compare-1", "paper-compare-2", "paper-compare-3"].forEach((id, index) => { document.getElementById(id).value = ids[index] || ""; });
      switchView("compare");
    });
    document.getElementById("paper-run-compare").addEventListener("click", renderCompare);
    document.getElementById("paper-export-selected").addEventListener("click", () => exportCsv(allPapers.filter(paper => selectedIds.has(paperKey(paper))), "selected"));
    document.getElementById("paper-export-filtered").addEventListener("click", () => exportCsv(filteredPapers, "filtered"));
    document.getElementById("paper-stats").addEventListener("click", event => {
      const row = event.target.closest("[data-stat-field]");
      if (!row) return;
      if (["model_type", "asset_market", ...PIPELINE_FIELDS].includes(row.dataset.statField)) includesFilters[row.dataset.statField] = row.dataset.statValue;
      else columnFilters[row.dataset.statField] = new Set([row.dataset.statValue]);
      switchView("list");
      applyFilters();
    });
    document.addEventListener("click", event => {
      const panel = document.getElementById("paper-column-filter");
      if (!panel.hidden && !event.target.closest("#paper-column-filter") && !event.target.closest("[data-filter-field]")) closeColumnFilter();
    });
    document.getElementById("paper-drawer-close").addEventListener("click", closeDrawer);
    document.getElementById("paper-drawer-backdrop").addEventListener("click", closeDrawer);
    document.getElementById("paper-drawer-content").addEventListener("click", event => {
      const edit = event.target.closest("[data-edit-field]");
      if (edit) beginFieldEdit(edit.dataset.editField);
      const cancel = event.target.closest("[data-cancel-field]");
      if (cancel) cancelFieldEdit(cancel.dataset.cancelField);
      const save = event.target.closest("[data-save-field]");
      if (save) saveFieldEdit(save.dataset.saveField);
      if (event.target.closest("[data-open-diagram]")) {
        document.getElementById("paper-diagram-title").textContent = `[${drawerPaper.id}] 架构图`;
        document.getElementById("paper-diagram-content").textContent = drawerPaper.diagram || "";
        document.getElementById("paper-diagram-dialog").showModal();
      }
    });
    document.getElementById("paper-diagram-close").addEventListener("click", () => document.getElementById("paper-diagram-dialog").close());
    document.addEventListener("keydown", event => {
      if (event.key === "Escape") {
        closeColumnFilter();
        if (document.getElementById("paper-detail-drawer").classList.contains("is-open")) closeDrawer();
      }
    });
    globalThis.addEventListener("beforeunload", event => {
      if (!document.querySelector(".paper-inline-editor")) return;
      event.preventDefault();
      event.returnValue = "";
    });
  };

  const initialize = async () => {
    initializeColumns();
    initializeHeadings();
    bindEvents();
    const initial = new URL(globalThis.location.href).searchParams;
    queryInput.value = initial.get("q") || "";
    curated = initial.get("mode") !== "all";
    currentView = ["list", "stats", "compare"].includes(initial.get("view")) ? initial.get("view") : "list";
    updateCuratedButton();
    try {
      const response = await fetch("/api/v1/paper-lab/papers?limit=1000&view=full", {headers: {Accept: "application/json"}});
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error?.message || "论文库读取失败");
      allPapers = payload.data.papers.map(normalize);
      const ratings = [...new Set(allPapers.map(paper => extractRating(paper.rating)).filter(Boolean))].sort((a, b) => a.localeCompare(b, "zh-CN"));
      const ratingSelect = document.getElementById("paper-adv-rating");
      for (const rating of ratings) ratingSelect.append(Object.assign(document.createElement("option"), {value: rating, textContent: rating}));
      fillCompareOptions();
      applyFilters();
      switchView(currentView);
    } catch (error) {
      summaryNode.textContent = `${error.message}。请刷新页面重试。`;
      rowsNode.innerHTML = '<tr><td class="paper-no-results" colspan="38">论文库暂时不可用。</td></tr>';
    }
  };

  initialize();
})();
