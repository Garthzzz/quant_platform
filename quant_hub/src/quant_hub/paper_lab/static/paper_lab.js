(() => {
  "use strict";
  const esc = value => String(value ?? "").replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[ch]);
  const index = document.querySelector("[data-paper-lab-index]");
  if (index) {
    const form = index.querySelector(".paper-lab-search");
    const query = document.getElementById("paper-lab-query");
    const status = document.getElementById("paper-lab-status");
    const rows = document.getElementById("paper-lab-rows");
    const summary = document.getElementById("paper-lab-summary");
    const initial = new URL(globalThis.location.href).searchParams;
    query.value = initial.get("q") || "";
    status.value = initial.get("status") || "";
    let timer;
    const load = async () => {
      const params = new URLSearchParams({limit: "1000", view: "summary"});
      if (query.value.trim()) params.set("q", query.value.trim());
      if (status.value) params.set("status", status.value);
      const visibleUrl = new URL(globalThis.location.href);
      visibleUrl.search = "";
      if (query.value.trim()) visibleUrl.searchParams.set("q", query.value.trim());
      if (status.value) visibleUrl.searchParams.set("status", status.value);
      globalThis.history.replaceState(globalThis.history.state, "", visibleUrl);
      const response = await fetch(`/api/v1/paper-lab/papers?${params}`, {headers:{Accept:"application/json"}});
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error?.message || "读取失败");
      const papers = payload.data.papers;
      rows.innerHTML = papers.map(p => `<tr><td>${esc(p.legacy_id || "—")}</td><td><a href="/paper-lab/papers/${encodeURIComponent(p.paper_id)}">${esc(p.title)}</a></td><td>${esc(p.lifecycle_status)}<br><small>${esc(p.reading_status || "未建立精读")}</small></td><td>${esc(p.model_type || "—")}</td><td>${esc(p.asset_market || "—")}</td><td>${esc(p.rating || "—")}</td><td><a href="/api/v1/paper-lab/versions/${encodeURIComponent(p.paper_version_id)}/content" target="_blank" rel="noopener">PDF</a></td></tr>`).join("");
      summary.textContent = `当前显示 ${papers.length} 篇论文。`;
    };
    const schedule = () => { clearTimeout(timer); timer = setTimeout(() => load().catch(e => {summary.textContent=e.message;}), 160); };
    query.addEventListener("input", schedule);
    status.addEventListener("change", schedule);
    form.addEventListener("submit", event => {
      event.preventDefault();
      clearTimeout(timer);
      load().catch(error => { summary.textContent = error.message; });
    });
    load().catch(e => { summary.textContent = e.message; });
  }
  const detail = document.querySelector("[data-paper-lab-detail]");
  if (detail) {
    const editorStatus = document.getElementById("paper-editor-status");
    const actorInput = document.getElementById("paper-editor-actor");
    const csrfToken = detail.dataset.csrfToken || "";
    const paperId = detail.dataset.paperId || "";
    for (const field of detail.querySelectorAll("[data-paper-edit-field]")) {
      for (const control of field.querySelectorAll("textarea, input")) {
        control.addEventListener("input", () => { field.dataset.dirty = "true"; });
      }
    }
    globalThis.addEventListener("beforeunload", event => {
      if (!detail.querySelector('[data-paper-edit-field][data-dirty="true"]')) return;
      event.preventDefault();
      event.returnValue = "";
    });
    const nextId = () => globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    for (const button of detail.querySelectorAll(".paper-edit-save")) {
      button.addEventListener("click", async () => {
        const field = button.closest("[data-paper-edit-field]");
        const actor = actorInput.value.trim();
        if (!actor) {
          editorStatus.textContent = "请填写修订者。";
          actorInput.focus();
          return;
        }
        button.disabled = true;
        editorStatus.textContent = `正在保存 ${field.dataset.paperEditField}…`;
        try {
          const response = await fetch(`/api/v1/paper-lab/papers/${encodeURIComponent(paperId)}`, {
            method: "PATCH",
            headers: {
              Accept: "application/json",
              "Content-Type": "application/json",
              "X-CSRF-Token": csrfToken,
              "Idempotency-Key": `paper-lab-field-${nextId()}`,
              "X-Request-ID": nextId(),
            },
            body: JSON.stringify({
              field: field.dataset.paperEditField,
              value: field.querySelector("textarea").value,
              expected_version: Number(field.dataset.version || "0"),
              actor_display_name: actor,
              reason: field.querySelector(".paper-edit-reason").value.trim(),
            }),
          });
          const payload = await response.json().catch(() => ({}));
          if (!response.ok) {
            const details = payload.error?.details ? `：${payload.error.details}` : "";
            throw new Error(`${payload.error?.message || "保存失败"}${details}`);
          }
          const result = payload.data.paper_field;
          field.dataset.version = String(result.version);
          const label = field.querySelector("h3").textContent;
          field.querySelector("small").textContent = `${result.field_name} · overlay v${result.version}`;
          field.querySelector(".paper-edit-reason").value = "";
          delete field.dataset.dirty;
          editorStatus.textContent = `“${label}”已保存为覆盖层第 ${result.version} 版。`;
        } catch (error) {
          editorStatus.textContent = `${error.message} 请重新载入页面后再试。`;
        } finally {
          button.disabled = false;
        }
      });
    }
  }
  const designer = document.querySelector("[data-paper-lab-designer]");
  if (designer) {
    const status = document.getElementById("designer-status");
    const layers = document.getElementById("designer-layers");
    const selectedList = document.getElementById("designer-selected");
    const selectedCount = document.getElementById("designer-count");
    const filter = document.getElementById("designer-filter");
    const nameInput = document.getElementById("designer-name");
    const objectiveInput = document.getElementById("designer-objective");
    const blueprintSelect = document.getElementById("designer-blueprint");
    const validationBox = document.getElementById("designer-validation");
    const tagSearch = document.getElementById("designer-tag-search");
    const tagGrid = document.getElementById("designer-tag-grid");
    const tagSummary = document.getElementById("designer-tag-summary");
    const componentDialog = document.getElementById("designer-component-dialog");
    const architectureDialog = document.getElementById("designer-architecture-dialog");
    const architectureCanvas = document.getElementById("designer-architecture-canvas");
    const csrfToken = designer.dataset.csrfToken || "";
    let catalogue = [];
    let tagCatalogue = [];
    let selected = [];
    let currentBlueprintId = "";
    let dirty = false;
    const markDirty = () => { dirty = true; };
    globalThis.addEventListener("beforeunload", event => {
      if (!dirty) return;
      event.preventDefault();
      event.returnValue = "";
    });

    const identifier = () => {
      if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
      return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    };
    const requestJson = async (path, options = {}) => {
      const response = await fetch(path, {
        ...options,
        headers: {Accept: "application/json", ...(options.headers || {})},
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        const detail = payload.error?.details ? `：${payload.error.details}` : "";
        throw new Error(`${payload.error?.message || `请求失败（${response.status}）`}${detail}`);
      }
      return payload.data;
    };
    const postJson = (path, body) => requestJson(path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken,
        "Idempotency-Key": `paper-lab-designer-${identifier()}`,
        "X-Request-ID": identifier(),
      },
      body: JSON.stringify(body),
    });
    const element = (tag, text, className) => {
      const node = document.createElement(tag);
      if (text !== undefined) node.textContent = text;
      if (className) node.className = className;
      return node;
    };
    const describe = item => (
      item.curated?.one_liner || item.automatic?.one_liner || "待研究员策展"
    );
    const componentPayload = () => selected.map((item, index) => ({
      component_id: item.component_id,
      layer: item.layer,
      layer_order: index,
      ordinal: index,
      forced: Boolean(item.forced),
    }));
    const appendPayload = (container, payload) => {
      const entries = Object.entries(payload || {});
      if (!entries.length) {
        container.append(element("p", "当前版本未提供策展字段。", "empty-state"));
        return;
      }
      const list = element("dl", undefined, "designer-component-fields");
      for (const [key, value] of entries) {
        const row = element("div");
        row.append(element("dt", key));
        const definition = element("dd");
        if (Array.isArray(value)) {
          if (!value.length) definition.textContent = "—";
          else if (value.every(item => ["string", "number", "boolean"].includes(typeof item))) {
            definition.textContent = value.join(" · ");
          } else {
            const pre = element("pre");
            pre.textContent = JSON.stringify(value, null, 2);
            definition.append(pre);
          }
        } else if (value && typeof value === "object") {
          const pre = element("pre");
          pre.textContent = JSON.stringify(value, null, 2);
          definition.append(pre);
        } else definition.textContent = String(value ?? "—");
        row.append(definition);
        list.append(row);
      }
      container.append(list);
    };
    const showComponentDetail = item => {
      document.getElementById("designer-component-title").textContent = item.display_name;
      const content = document.getElementById("designer-component-content");
      content.replaceChildren();
      const identity = element("dl", undefined, "designer-component-identity");
      for (const [label, value] of [
        ["组件 ID", item.legacy_component_id], ["层级", item.layer],
        ["版本", item.version], ["状态", item.status],
      ]) {
        const row = element("div");
        row.append(element("dt", label), element("dd", String(value ?? "—")));
        identity.append(row);
      }
      content.append(identity);
      const curatedSection = element("section");
      curatedSection.append(element("h3", "研究员策展"));
      appendPayload(curatedSection, item.curated);
      content.append(curatedSection);
      const automaticSection = element("section");
      automaticSection.append(element("h3", "来源投影"));
      appendPayload(automaticSection, item.automatic);
      content.append(automaticSection);
      componentDialog.showModal();
    };
    const renderTags = () => {
      const term = tagSearch.value.trim().toLocaleLowerCase("zh-CN");
      const visible = tagCatalogue.filter(item => (
        `${item.display_name} ${item.legacy_component_id} ${item.layer} ${describe(item)}`
          .toLocaleLowerCase("zh-CN").includes(term)
      ));
      tagGrid.replaceChildren();
      for (const item of visible) {
        const card = element("article");
        card.append(element("p", item.layer, "eyebrow"));
        card.append(element("h3", item.display_name));
        card.append(element("p", describe(item)));
        card.append(element("small", `${item.legacy_component_id} · v${item.version} · ${item.status}`));
        const detail = element("button", "查看证据与字段");
        detail.type = "button";
        detail.addEventListener("click", () => showComponentDetail(item));
        card.append(detail);
        tagGrid.append(card);
      }
      if (!visible.length) tagGrid.append(element("p", "没有匹配的 Tag 组件。", "empty-state"));
      tagSummary.textContent = `当前显示 ${visible.length} / ${tagCatalogue.length} 个 Tag 组件。`;
    };
    const svgNode = (tag, attributes = {}, text) => {
      const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
      for (const [name, value] of Object.entries(attributes)) node.setAttribute(name, String(value));
      if (text !== undefined) node.textContent = text;
      return node;
    };
    const architectureSvg = () => {
      const width = 920;
      const cardHeight = 88;
      const gap = 38;
      const height = Math.max(260, 130 + selected.length * (cardHeight + gap));
      const svg = svgNode("svg", {xmlns: "http://www.w3.org/2000/svg", viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": "当前量化架构完整流程"});
      svg.classList.add("designer-architecture-svg");
      svg.append(svgNode("rect", {x: 0, y: 0, width, height, fill: "#f6f8fa"}));
      svg.append(svgNode("text", {x: 40, y: 42, fill: "#17364d", "font-size": 22, "font-weight": 700}, nameInput.value.trim() || "未命名量化架构"));
      svg.append(svgNode("text", {x: 40, y: 68, fill: "#617684", "font-size": 13}, objectiveInput.value.trim().slice(0, 110) || "尚未记录研究目标"));
      selected.forEach((item, index) => {
        const y = 100 + index * (cardHeight + gap);
        if (index) {
          svg.append(svgNode("line", {x1: width / 2, y1: y - gap, x2: width / 2, y2: y - 8, stroke: "#7890a1", "stroke-width": 2}));
          svg.append(svgNode("path", {d: `M ${width / 2 - 6} ${y - 14} L ${width / 2} ${y - 6} L ${width / 2 + 6} ${y - 14}`, fill: "none", stroke: "#7890a1", "stroke-width": 2}));
        }
        svg.append(svgNode("rect", {x: 110, y, width: 700, height: cardHeight, rx: 5, fill: "#ffffff", stroke: item.forced ? "#a66b32" : "#7e95a5", "stroke-width": item.forced ? 3 : 1.5}));
        svg.append(svgNode("rect", {x: 110, y, width: 10, height: cardHeight, fill: item.forced ? "#a66b32" : "#315d79"}));
        svg.append(svgNode("text", {x: 142, y: y + 29, fill: "#17364d", "font-size": 17, "font-weight": 700}, `${index + 1}. ${item.display_name}`));
        svg.append(svgNode("text", {x: 142, y: y + 53, fill: "#4f6878", "font-size": 12}, `${item.layer} · ${item.legacy_component_id} · v${item.version}`));
        svg.append(svgNode("text", {x: 142, y: y + 73, fill: "#71838f", "font-size": 11}, describe(item).slice(0, 105)));
      });
      if (!selected.length) svg.append(svgNode("text", {x: width / 2, y: 150, fill: "#71838f", "font-size": 16, "text-anchor": "middle"}, "尚未选择架构积木"));
      return svg;
    };
    const renderArchitecture = () => {
      architectureCanvas.replaceChildren(architectureSvg());
    };
    const downloadBlob = (blob, filename) => {
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 0);
    };
    const serializedArchitecture = () => {
      const svg = architectureCanvas.querySelector("svg") || architectureSvg();
      return new XMLSerializer().serializeToString(svg);
    };
    const filenameBase = () => (nameInput.value.trim() || "paper-lab-architecture").replace(/[\\/:*?"<>|]+/g, "-");
    const setBusy = (busy, message) => {
      for (const button of designer.querySelectorAll("button")) button.disabled = busy;
      if (message) status.textContent = message;
    };

    const renderValidation = validation => {
      validationBox.replaceChildren();
      if (!validation) return;
      const heading = element(
        "p",
        validation.valid ? "组合通过契约验证。" : "组合存在必须修正的问题。",
        validation.valid ? "validation-pass" : "validation-fail",
      );
      validationBox.append(heading);
      const groups = [["错误", validation.errors || []], ["提醒", validation.warnings || []]];
      for (const [label, items] of groups) {
        if (!items.length) continue;
        const section = element("section");
        section.append(element("h3", `${label}（${items.length}）`));
        const list = element("ul");
        for (const item of items) {
          const details = Object.entries(item)
            .map(([key, value]) => `${key}=${Array.isArray(value) ? value.join(", ") : value}`)
            .join("；");
          list.append(element("li", details));
        }
        section.append(list);
        validationBox.append(section);
      }
    };

    const renderCatalogue = () => {
      const term = filter.value.trim().toLocaleLowerCase("zh-CN");
      const groups = new Map();
      for (const item of catalogue) {
        const searchable = `${item.display_name} ${item.layer} ${describe(item)}`.toLocaleLowerCase("zh-CN");
        if (term && !searchable.includes(term)) continue;
        if (!groups.has(item.layer)) groups.set(item.layer, []);
        groups.get(item.layer).push(item);
      }
      layers.replaceChildren();
      for (const [layer, items] of groups) {
        const section = element("section");
        section.append(element("h3", `${layer}（${items.length}）`));
        const grid = element("div", undefined, "component-grid");
        for (const item of items) {
          const card = element("article");
          card.append(element("h4", item.display_name));
          card.append(element("p", describe(item)));
          card.append(element("small", `v${item.version} · ${item.status} · ${item.legacy_component_id}`));
          const detail = element("button", "查看详情", "component-detail");
          detail.type = "button";
          detail.addEventListener("click", () => showComponentDetail(item));
          const add = element(
            "button",
            selected.some(entry => entry.component_id === item.component_id) ? "已加入" : "加入组合",
            "component-add",
          );
          add.type = "button";
          add.disabled = selected.some(entry => entry.component_id === item.component_id);
          add.addEventListener("click", () => {
            selected.push({...item, forced: false});
            markDirty();
            renderSelected();
            renderCatalogue();
            renderValidation(null);
            status.textContent = `已加入“${item.display_name}”。`;
          });
          const actions = element("div", undefined, "component-actions");
          actions.append(detail, add);
          card.append(actions);
          grid.append(card);
        }
        section.append(grid);
        layers.append(section);
      }
      if (!groups.size) layers.append(element("p", "没有匹配的架构积木。", "empty-state"));
    };

    const move = (index, delta) => {
      const target = index + delta;
      if (target < 0 || target >= selected.length) return;
      [selected[index], selected[target]] = [selected[target], selected[index]];
      markDirty();
      renderSelected();
      renderValidation(null);
    };
    const renderSelected = () => {
      selectedList.replaceChildren();
      const knownLayers = [...new Set(catalogue.map(item => item.layer))];
      selected.forEach((item, index) => {
        const row = element("li", undefined, "designer-selected-item");
        const identity = element("div", undefined, "selected-identity");
        identity.append(element("strong", `${index + 1}. ${item.display_name}`));
        identity.append(element("small", `${item.legacy_component_id} · v${item.version}`));
        row.append(identity);

        const layerLabel = element("label", "层级", "selected-layer");
        const layerSelect = element("select");
        for (const layer of knownLayers) {
          const option = element("option", layer);
          option.value = layer;
          option.selected = layer === item.layer;
          layerSelect.append(option);
        }
        layerSelect.addEventListener("change", () => {
          item.layer = layerSelect.value;
          markDirty();
          renderValidation(null);
        });
        layerLabel.append(layerSelect);
        row.append(layerLabel);

        const forceLabel = element("label", undefined, "selected-force");
        const force = document.createElement("input");
        force.type = "checkbox";
        force.checked = Boolean(item.forced);
        force.addEventListener("change", () => {
          item.forced = force.checked;
          markDirty();
          renderValidation(null);
        });
        forceLabel.append(force, document.createTextNode(" 允许人工强制衔接"));
        row.append(forceLabel);

        const controls = element("div", undefined, "selected-controls");
        const actions = [
          ["上移", () => move(index, -1), index === 0],
          ["下移", () => move(index, 1), index === selected.length - 1],
          ["移除", () => {
            selected.splice(index, 1);
            markDirty();
            renderSelected();
            renderCatalogue();
            renderValidation(null);
          }, false],
        ];
        for (const [label, handler, disabled] of actions) {
          const button = element("button", label);
          button.type = "button";
          button.disabled = disabled;
          button.addEventListener("click", handler);
          controls.append(button);
        }
        row.append(controls);
        selectedList.append(row);
      });
      selectedCount.textContent = selected.length
        ? `已选择 ${selected.length} 个积木；列表顺序即执行顺序。`
        : "尚未选择积木。";
    };

    const refreshBlueprints = async (preferred = currentBlueprintId) => {
      const data = await requestJson("/api/v1/paper-lab/blueprints");
      blueprintSelect.replaceChildren();
      const fresh = element("option", "新建蓝图");
      fresh.value = "";
      blueprintSelect.append(fresh);
      for (const blueprint of data.blueprints) {
        const option = element("option", `${blueprint.name} · v${blueprint.version}`);
        option.value = blueprint.blueprint_id;
        option.selected = blueprint.blueprint_id === preferred;
        blueprintSelect.append(option);
      }
    };
    const reset = () => {
      currentBlueprintId = "";
      blueprintSelect.value = "";
      nameInput.value = "";
      objectiveInput.value = "";
      selected = [];
      dirty = false;
      renderSelected();
      renderCatalogue();
      renderValidation(null);
      status.textContent = "已建立空白蓝图。";
      nameInput.focus();
    };
    const restore = async () => {
      const id = blueprintSelect.value;
      if (!id) {
        reset();
        return;
      }
      setBusy(true, "正在恢复蓝图最新版本…");
      try {
        const data = await requestJson(`/api/v1/paper-lab/blueprints/${encodeURIComponent(id)}`);
        const blueprint = data.blueprint;
        currentBlueprintId = blueprint.blueprint_id;
        nameInput.value = blueprint.name;
        objectiveInput.value = blueprint.objective;
        selected = blueprint.components.map(saved => {
          const source = catalogue.find(item => item.component_id === saved.component_id);
          if (!source) throw new Error(`蓝图引用了当前目录不存在的组件：${saved.component_id}`);
          return {...source, layer: saved.layer, forced: Boolean(saved.forced)};
        });
        renderSelected();
        renderCatalogue();
        renderValidation(blueprint.validation);
        dirty = false;
        status.textContent = `已恢复“${blueprint.name}”第 ${blueprint.version} 版。`;
      } finally {
        setBusy(false);
      }
    };
    const validate = async () => {
      setBusy(true, "正在验证组件类型和兼容规则…");
      try {
        const data = await postJson("/api/v1/paper-lab/blueprints/validate", {
          components: componentPayload(),
        });
        renderValidation(data.validation);
        status.textContent = data.validation.valid ? "契约验证通过。" : "契约验证未通过，请查看问题清单。";
        return data.validation;
      } finally {
        setBusy(false);
      }
    };
    const save = async () => {
      if (!nameInput.value.trim()) {
        status.textContent = "请先填写蓝图名称。";
        nameInput.focus();
        return;
      }
      if (!selected.length) {
        status.textContent = "请至少加入一个架构积木。";
        return;
      }
      const validation = await validate();
      if (!validation.valid) return;
      setBusy(true, "正在保存不可变蓝图版本…");
      try {
        const body = {
          name: nameInput.value.trim(),
          objective: objectiveInput.value.trim(),
          components: componentPayload(),
        };
        if (currentBlueprintId) body.blueprint_id = currentBlueprintId;
        const data = await postJson("/api/v1/paper-lab/blueprints", body);
        currentBlueprintId = data.blueprint.blueprint_id;
        renderValidation(data.blueprint.validation);
        await refreshBlueprints(currentBlueprintId);
        dirty = false;
        status.textContent = `已保存第 ${data.blueprint.version} 版；旧版本保持不变。`;
      } finally {
        setBusy(false);
      }
    };

    document.getElementById("designer-new").addEventListener("click", reset);
    document.getElementById("designer-load").addEventListener("click", () => restore().catch(error => {
      setBusy(false);
      status.textContent = error.message;
    }));
    document.getElementById("designer-validate").addEventListener("click", () => validate().catch(error => {
      setBusy(false);
      status.textContent = error.message;
    }));
    document.getElementById("designer-save").addEventListener("click", () => save().catch(error => {
      setBusy(false);
      status.textContent = error.message;
    }));
    filter.addEventListener("input", renderCatalogue);
    nameInput.addEventListener("input", markDirty);
    objectiveInput.addEventListener("input", markDirty);
    blueprintSelect.addEventListener("change", () => {
      status.textContent = blueprintSelect.value
        ? "已选择已有蓝图；点击“恢复最新版本”载入。"
        : "已选择新建蓝图。";
    });
    const switchDesignerView = view => {
      const pipelineActive = view === "pipeline";
      document.getElementById("designer-pipeline-view").hidden = !pipelineActive;
      document.getElementById("designer-tags-view").hidden = pipelineActive;
      document.getElementById("designer-tab-pipeline").setAttribute("aria-selected", String(pipelineActive));
      document.getElementById("designer-tab-tags").setAttribute("aria-selected", String(!pipelineActive));
      if (!pipelineActive) renderTags();
      const url = new URL(globalThis.location.href);
      if (pipelineActive) url.searchParams.delete("view");
      else url.searchParams.set("view", "tags");
      globalThis.history.replaceState(globalThis.history.state, "", url);
    };
    document.getElementById("designer-tab-pipeline").addEventListener("click", () => switchDesignerView("pipeline"));
    document.getElementById("designer-tab-tags").addEventListener("click", () => switchDesignerView("tags"));
    tagSearch.addEventListener("input", renderTags);
    document.getElementById("designer-component-close").addEventListener("click", () => componentDialog.close());
    document.getElementById("designer-architecture-close").addEventListener("click", () => architectureDialog.close());
    document.getElementById("designer-visualize").addEventListener("click", () => {
      renderArchitecture();
      architectureDialog.showModal();
    });
    document.getElementById("designer-download-svg").addEventListener("click", () => {
      downloadBlob(new Blob([serializedArchitecture()], {type: "image/svg+xml;charset=utf-8"}), `${filenameBase()}.svg`);
    });
    document.getElementById("designer-download-png").addEventListener("click", () => {
      const source = serializedArchitecture();
      const svg = architectureCanvas.querySelector("svg");
      const viewBox = svg?.viewBox?.baseVal;
      const width = Math.max(1, Math.round(viewBox?.width || 920));
      const height = Math.max(1, Math.round(viewBox?.height || 600));
      const image = new Image();
      image.onload = () => {
        const canvas = document.createElement("canvas");
        canvas.width = width * 2;
        canvas.height = height * 2;
        const context = canvas.getContext("2d");
        context.fillStyle = "#f6f8fa";
        context.fillRect(0, 0, canvas.width, canvas.height);
        context.drawImage(image, 0, 0, canvas.width, canvas.height);
        canvas.toBlob(blob => {
          if (blob) downloadBlob(blob, `${filenameBase()}.png`);
          else status.textContent = "PNG 导出失败，请改用 SVG。";
        }, "image/png");
      };
      image.onerror = () => { status.textContent = "PNG 导出失败，请改用 SVG。"; };
      image.src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(source)}`;
    });

    Promise.all([
      requestJson("/api/v1/paper-lab/components?kind=concept_block"),
      requestJson("/api/v1/paper-lab/components?kind=tag_component"),
      requestJson("/api/v1/paper-lab/blueprints"),
    ]).then(([componentData, tagData, blueprintData]) => {
      catalogue = componentData.components;
      tagCatalogue = tagData.components;
      renderCatalogue();
      renderTags();
      renderSelected();
      blueprintSelect.replaceChildren();
      const fresh = element("option", "新建蓝图");
      fresh.value = "";
      blueprintSelect.append(fresh);
      for (const blueprint of blueprintData.blueprints) {
        const option = element("option", `${blueprint.name} · v${blueprint.version}`);
        option.value = blueprint.blueprint_id;
        blueprintSelect.append(option);
      }
      status.textContent = `已加载 ${componentData.count} 个架构积木、${tagData.count} 个 Tag 组件和 ${blueprintData.count} 份蓝图。`;
      if (new URL(globalThis.location.href).searchParams.get("view") === "tags") switchDesignerView("tags");
    }).catch(error => { status.textContent = error.message; });
  }
})();
