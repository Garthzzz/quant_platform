"use strict";

const csrfMeta = document.querySelector('meta[name="csrf-token"]');
const csrfToken = csrfMeta ? csrfMeta.content : "";

function idempotencyKey(action) {
  const suffix = globalThis.crypto && typeof globalThis.crypto.randomUUID === "function"
    ? globalThis.crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `${action}:${suffix}`;
}

function setStatus(form, message, state = "ready") {
  const target = form.querySelector(".form-status");
  if (!target) return;
  target.textContent = message;
  target.dataset.state = state;
}

function setBusy(form, busy) {
  form.dataset.busy = busy ? "true" : "false";
  form.setAttribute("aria-busy", busy ? "true" : "false");
  for (const button of form.querySelectorAll("button")) button.disabled = busy;
}

function focusAfterError(form) {
  const invalid = form.querySelector(":invalid");
  const fallback = form.querySelector('textarea[name="content"]');
  (invalid || fallback)?.focus();
}

function selectedActor(form) {
  const radio = form.querySelector('input[name="actor_kind"]:checked');
  const select = form.querySelector('select[name="actor_kind"]');
  const actorKind = radio ? radio.value : (select ? select.value : "");
  const nameInput = form.querySelector('input[name="display_name"]');
  return {
    actor_kind: actorKind,
    display_name: actorKind === "other" && nameInput ? nameInput.value.trim() : null,
  };
}

function updateOtherName(form) {
  const actor = selectedActor(form);
  const wrapper = form.querySelector(".other-name, .workspace-actor__other");
  if (!wrapper) return;
  const input = wrapper.querySelector("input");
  const active = actor.actor_kind === "other";
  wrapper.classList.toggle("is-hidden", !active);
  if (input) input.required = active;
}

async function command(url, method, body, key, etag = null) {
  const headers = {
    "Content-Type": "application/json",
    "X-CSRF-Token": csrfToken,
    "Idempotency-Key": key,
  };
  if (etag) headers["If-Match"] = etag;
  const response = await fetch(url, {
    method,
    credentials: "same-origin",
    headers,
    body: JSON.stringify(body),
  });
  const payload = await response.json();
  if (!response.ok) {
    const error = new Error(payload.error ? payload.error.message : "请求失败");
    error.code = payload.error ? payload.error.code : "request_failed";
    throw error;
  }
  return payload;
}

for (const form of document.querySelectorAll(".comment-form, .comment-edit-form")) {
  updateOtherName(form);
  form.addEventListener("change", (event) => {
    if (event.target && event.target.name === "actor_kind") updateOtherName(form);
  });
}

const dateFormatter = new Intl.DateTimeFormat(
  document.documentElement.lang || navigator.language,
  {dateStyle: "medium", timeStyle: "short"},
);
for (const element of document.querySelectorAll("[data-local-datetime]")) {
  const value = new Date(element.dateTime);
  if (!Number.isNaN(value.valueOf())) element.textContent = dateFormatter.format(value);
}

function researchUpdateCommandKey(form, body) {
  const fingerprint = JSON.stringify(body);
  if (form.dataset.updateRequestBody !== fingerprint) {
    form.dataset.updateRequestBody = fingerprint;
    form.dataset.updateRequestKey = idempotencyKey("research-update-annotation");
  }
  return form.dataset.updateRequestKey;
}

for (const form of document.querySelectorAll("[data-research-update-annotation]")) {
  updateOtherName(form);
  form.addEventListener("change", event => {
    if (event.target && event.target.name === "actor_kind") updateOtherName(form);
  });
  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (form.dataset.busy === "true") return;
    const card = form.closest("[data-research-update]");
    if (!card) return;
    const updateId = card.dataset.updateId;
    const revision = card.dataset.updateRevision;
    const note = form.querySelector('textarea[name="note"]')?.value.trim() || null;
    const body = {actor: selectedActor(form), note};
    setBusy(form, true);
    setStatus(form, "正在保存更新记录…");
    try {
      await command(
        `/api/v1/research-updates/${encodeURIComponent(updateId)}/annotations`,
        "POST",
        body,
        researchUpdateCommandKey(form, body),
        `"research-update:${updateId}:r${revision}"`,
      );
      setStatus(form, "已保存，正在刷新…");
      globalThis.location.reload();
    } catch (error) {
      setBusy(form, false);
      setStatus(form, error.message, "error");
      (form.querySelector(":invalid") || form.querySelector('textarea[name="note"]'))?.focus();
    }
  });
}

const createForm = document.querySelector("[data-comment-create]");
if (createForm) {
  createForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (createForm.dataset.busy === "true") return;
    const researchId = createForm.dataset.researchId;
    const content = createForm.querySelector('textarea[name="content"]').value;
    const actor = selectedActor(createForm);
    setBusy(createForm, true);
    setStatus(createForm, "正在保存…");
    try {
      await command(
        `/api/v1/research/${encodeURIComponent(researchId)}/comments`,
        "POST",
        {actor, content},
        idempotencyKey("comment-create"),
      );
      setStatus(createForm, "已保存，正在刷新…");
      globalThis.location.reload();
    } catch (error) {
      setBusy(createForm, false);
      setStatus(createForm, error.message, "error");
      focusAfterError(createForm);
    }
  });
}

for (const form of document.querySelectorAll("[data-comment-edit]")) {
  const card = form.closest("[data-comment-id]");
  if (!card) continue;
  const commentId = card.dataset.commentId;
  const etag = `"comment:${commentId}:r${card.dataset.revision}"`;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (form.dataset.busy === "true") return;
    const content = form.querySelector('textarea[name="content"]').value;
    const actor = selectedActor(form);
    setBusy(form, true);
    setStatus(form, "正在保存…");
    try {
      await command(
        `/api/v1/comments/${encodeURIComponent(commentId)}`,
        "PATCH",
        {actor, content},
        idempotencyKey("comment-update"),
        etag,
      );
      setStatus(form, "已保存，正在刷新…");
      globalThis.location.reload();
    } catch (error) {
      setBusy(form, false);
      setStatus(form, error.message, "error");
      focusAfterError(form);
    }
  });

  const deleteButton = form.querySelector("[data-comment-delete]");
  if (deleteButton) {
    deleteButton.addEventListener("click", async () => {
      if (form.dataset.busy === "true") return;
      if (!globalThis.confirm("确认删除这条评论？")) return;
      const actor = selectedActor(form);
      setBusy(form, true);
      setStatus(form, "正在删除…");
      try {
        await command(
          `/api/v1/comments/${encodeURIComponent(commentId)}`,
          "DELETE",
          {actor},
          idempotencyKey("comment-delete"),
          etag,
        );
        setStatus(form, "已删除，正在刷新…");
        globalThis.location.reload();
      } catch (error) {
        setBusy(form, false);
        setStatus(form, error.message, "error");
        focusAfterError(form);
      }
    });
  }
}

const citationDialog = document.querySelector("[data-citation-dialog]");
if (citationDialog instanceof HTMLDialogElement) {
  const citationIdPattern = /^cit_[a-z2-7]{52}$/;
  const endpointPrefix = citationDialog.dataset.endpointPrefix || "/api/v1/evidence/citations/";
  const statusElement = citationDialog.querySelector("[data-citation-status]");
  const contentElement = citationDialog.querySelector("[data-citation-content]");
  const resolutionElement = citationDialog.querySelector("[data-citation-resolution]");
  const idElement = citationDialog.querySelector("[data-citation-id]");
  const markerElement = citationDialog.querySelector("[data-citation-marker]");
  const locationElement = citationDialog.querySelector("[data-citation-location]");
  const contextElement = citationDialog.querySelector("[data-citation-context]");
  const entriesElement = citationDialog.querySelector("[data-citation-entries]");
  const stateLabels = {
    "valid": "已核验论文",
    "source-only": "来源线索（非论文）",
    "unresolved": "待核验",
    "conflicted": "存在冲突",
  };
  let activeTrigger = null;
  let activeRequest = null;
  let suppressCloseNavigation = false;

  function citationFromLocation() {
    return new URL(globalThis.location.href).searchParams.get("cite");
  }

  function setCitationStatus(message, state = "ready") {
    statusElement.textContent = message;
    statusElement.dataset.state = state;
  }

  function resetCitationContent() {
    contentElement.hidden = true;
    resolutionElement.textContent = "";
    resolutionElement.removeAttribute("data-state");
    idElement.textContent = "";
    markerElement.textContent = "";
    locationElement.textContent = "";
    contextElement.textContent = "";
    entriesElement.replaceChildren();
  }

  function safeInternalLink(value) {
    if (typeof value !== "string" || !value.startsWith("/")) return null;
    const candidate = new URL(value, globalThis.location.origin);
    if (candidate.origin !== globalThis.location.origin) return null;
    if (!candidate.pathname.startsWith("/evidence/") && !candidate.pathname.startsWith("/api/v1/evidence/")) return null;
    return candidate.pathname + candidate.search + candidate.hash;
  }

  function safeExternalLink(value) {
    if (typeof value !== "string") return null;
    try {
      const candidate = new URL(value);
      return candidate.protocol === "https:" ? candidate.href : null;
    } catch (_error) {
      return null;
    }
  }

  function renderCitationEntry(entry, index) {
    const item = document.createElement("li");
    item.className = "citation-entry";

    const heading = document.createElement("h4");
    const paper = entry && typeof entry.paper === "object" ? entry.paper : null;
    heading.textContent = paper && paper.title ? paper.title : `线索 ${index + 1} · 尚未绑定论文`;
    item.append(heading);

    const status = document.createElement("p");
    status.textContent = `绑定：${entry.binding_status || "unresolved"} · 条目：${entry.entry_status || "unknown"} · 类型：${entry.occurrence_type || "unknown"}`;
    item.append(status);

    const provenance = document.createElement("p");
    provenance.textContent = `${entry.source_path || "来源路径未记录"} · ${entry.locator_claim || "位置声明未记录"}`;
    item.append(provenance);

    if (entry.rationale) {
      const rationale = document.createElement("p");
      rationale.textContent = `核验说明：${entry.rationale}`;
      item.append(rationale);
    }
    const paperSummary = paper && paper.paper_summary && typeof paper.paper_summary === "object"
      ? paper.paper_summary
      : null;
    if (paperSummary) {
      const summary = document.createElement("div");
      summary.className = "citation-paper-summary";
      const metadata = document.createElement("p");
      const authors = Array.isArray(paperSummary.authors)
        ? paperSummary.authors.map(author => author?.name).filter(Boolean).join("、")
        : "";
      const categories = Array.isArray(paperSummary.categories)
        ? paperSummary.categories.join("、")
        : "";
      metadata.textContent = [
        paperSummary.publication_date,
        authors,
        categories,
        paperSummary.verification_status ? `核验：${paperSummary.verification_status}` : null,
      ].filter(Boolean).join(" · ") || "目录元数据尚待补充。";
      summary.append(metadata);

      const excerpts = Array.isArray(paperSummary.evidence_excerpts)
        ? paperSummary.evidence_excerpts
        : [];
      for (const excerpt of excerpts.slice(0, 2)) {
        const quote = document.createElement("blockquote");
        quote.textContent = excerpt.text || "（空证据摘录）";
        const fact = document.createElement("small");
        fact.textContent = `事实边界：${excerpt.fact_status || "unknown"}`;
        quote.append(document.createElement("br"), fact);
        summary.append(quote);
      }

      const links = document.createElement("div");
      links.className = "citation-paper-links";
      for (const linkData of (Array.isArray(paperSummary.external_links) ? paperSummary.external_links : []).slice(0, 3)) {
        const href = safeExternalLink(linkData?.url);
        if (!href) continue;
        const link = document.createElement("a");
        link.href = href;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.textContent = `外部：${linkData.kind || "来源"}`;
        links.append(link);
      }
      for (const resource of (Array.isArray(paperSummary.local_resources) ? paperSummary.local_resources : [])) {
        const href = safeInternalLink(resource?.url);
        if (!href) continue;
        const link = document.createElement("a");
        link.href = href;
        link.textContent = "本地论文资源";
        links.append(link);
      }
      if (links.childElementCount) summary.append(links);
      item.append(summary);
    }
    const detailUrl = paper ? safeInternalLink(paper.detail_url) : null;
    if (detailUrl) {
      const link = document.createElement("a");
      link.href = detailUrl;
      link.textContent = "查看论文与证据详情";
      item.append(link);
    }
    return item;
  }

  function renderCitation(data) {
    const resolution = stateLabels[data.resolution_state] ? data.resolution_state : "unresolved";
    resolutionElement.textContent = stateLabels[resolution];
    resolutionElement.dataset.state = resolution;
    idElement.textContent = data.citation_id || "";
    markerElement.textContent = data.raw_marker_text || "（未记录）";
    const byteRange = Number.isInteger(data.byte_start) && Number.isInteger(data.byte_end)
      ? `字节 ${data.byte_start}–${data.byte_end}`
      : "无字节定位";
    locationElement.textContent = `行 ${data.line_start || "?"}–${data.line_end || "?"} · ${byteRange}`;
    contextElement.textContent = data.context_text || "（未保存上下文）";
    const entries = Array.isArray(data.entries) ? data.entries : [];
    entriesElement.replaceChildren(...entries.map(renderCitationEntry));
    if (entries.length === 0) {
      const empty = document.createElement("li");
      empty.className = "citation-entry";
      empty.textContent = "该位置已登记，但尚无论文绑定或来源分类结论。";
      entriesElement.append(empty);
    }
    contentElement.hidden = false;
    setCitationStatus(`已加载 ${entries.length} 条可追溯账本记录。`);
  }

  async function openCitation(citationId, trigger = null) {
    if (activeTrigger) activeTrigger.setAttribute("aria-expanded", "false");
    activeTrigger = trigger;
    if (activeTrigger) activeTrigger.setAttribute("aria-expanded", "true");
    if (!citationDialog.open) citationDialog.showModal();
    resetCitationContent();

    if (!citationIdPattern.test(citationId || "")) {
      setCitationStatus("引用标识无效，无法读取证据。", "error");
      return;
    }
    if (activeRequest) activeRequest.abort();
    activeRequest = new AbortController();
    citationDialog.setAttribute("aria-busy", "true");
    setCitationStatus("正在核验引用账本与论文绑定…");
    try {
      const response = await fetch(`${endpointPrefix}${encodeURIComponent(citationId)}`, {
        credentials: "same-origin",
        headers: {"Accept": "application/json"},
        signal: activeRequest.signal,
      });
      const payload = await response.json();
      if (!response.ok || !payload || !payload.data) {
        throw new Error(payload?.error?.message || "引用证据读取失败。");
      }
      if (citationFromLocation() !== citationId) return;
      renderCitation(payload.data);
    } catch (error) {
      if (error.name !== "AbortError") setCitationStatus(error.message || "引用证据读取失败。", "error");
    } finally {
      citationDialog.removeAttribute("aria-busy");
    }
  }

  function navigateToCitation(citationId, trigger) {
    const url = new URL(globalThis.location.href);
    if (url.searchParams.get("cite") !== citationId) {
      url.searchParams.set("cite", citationId);
      globalThis.history.pushState({...globalThis.history.state, qrhCitation: citationId}, "", url);
    }
    openCitation(citationId, trigger);
  }

  document.addEventListener("click", (event) => {
    const trigger = event.target.closest?.(".citation-trigger[data-citation-id]");
    if (!trigger) return;
    navigateToCitation(trigger.dataset.citationId, trigger);
  });

  citationDialog.querySelector("[data-citation-close]")?.addEventListener("click", () => citationDialog.close());
  citationDialog.addEventListener("close", () => {
    if (activeRequest) activeRequest.abort();
    if (activeTrigger) {
      activeTrigger.setAttribute("aria-expanded", "false");
      if (activeTrigger.isConnected) activeTrigger.focus();
    }
    activeTrigger = null;
    resetCitationContent();
    if (suppressCloseNavigation) {
      suppressCloseNavigation = false;
      return;
    }
    const url = new URL(globalThis.location.href);
    if (!url.searchParams.has("cite")) return;
    if (globalThis.history.state?.qrhCitation) {
      globalThis.history.back();
    } else {
      url.searchParams.delete("cite");
      globalThis.history.replaceState(globalThis.history.state, "", url);
    }
  });

  globalThis.addEventListener("popstate", () => {
    const citationId = citationFromLocation();
    if (citationId) {
      const trigger = document.querySelector(`.citation-trigger[data-citation-id="${CSS.escape(citationId)}"]`);
      openCitation(citationId, trigger);
    } else if (citationDialog.open) {
      suppressCloseNavigation = true;
      citationDialog.close();
    }
  });

  const initialCitation = citationFromLocation();
  if (initialCitation) {
    const trigger = document.querySelector(`.citation-trigger[data-citation-id="${CSS.escape(initialCitation)}"]`);
    openCitation(initialCitation, trigger);
  }
}

const diagramBoxGlyphs = /[┌┐└┘├┤┬┴┼│─╔╗╚╝╠╣╦╩╬║═╭╮╰╯]/gu;
const diagramArrows = /(?:--?>|<--?|[→←↑↓↔↕⇢⇠⇡⇣▲▼])/gu;
const diagramTreeBranches = /(?:├──|└──|│\s{2,})/gu;

function diagramMatchCount(value, pattern) {
  return value.match(pattern)?.length || 0;
}

function looksLikeDiagram(code) {
  const language = [...code.classList].find(name => name.startsWith("language-"));
  if (language && !["language-text", "language-plaintext", "language-ascii"].includes(language)) {
    return false;
  }
  const value = code.textContent || "";
  const lines = value.replace(/\r\n?/gu, "\n").replace(/\n$/u, "").split("\n");
  if (lines.length < 2) return false;
  const boxCount = diagramMatchCount(value, diagramBoxGlyphs);
  const treeCount = diagramMatchCount(value, diagramTreeBranches);
  const arrowCount = diagramMatchCount(value, diagramArrows);
  const structuralCount = diagramMatchCount(value, /[|+_=\/\\]/gu);
  return boxCount >= 4 || treeCount >= 2 || (lines.length >= 3 && arrowCount >= 2 && structuralCount >= 3);
}

function diagramColumns(line) {
  let columns = 0;
  for (const character of line) {
    if (character === "\t") {
      columns += 4 - (columns % 4);
      continue;
    }
    const point = character.codePointAt(0);
    const isWide = point >= 0x1100 && (
      point <= 0x115f || point === 0x2329 || point === 0x232a ||
      (point >= 0x2e80 && point <= 0xa4cf && point !== 0x303f) ||
      (point >= 0xac00 && point <= 0xd7a3) ||
      (point >= 0xf900 && point <= 0xfaff) ||
      (point >= 0xfe10 && point <= 0xfe6f) ||
      (point >= 0xff00 && point <= 0xff60) ||
      (point >= 0xffe0 && point <= 0xffe6) ||
      (point >= 0x1f300 && point <= 0x1faff) ||
      (point >= 0x20000 && point <= 0x3fffd)
    );
    columns += isWide ? 2 : 1;
  }
  return columns;
}

function diagramContextLabel(pre, ordinal) {
  let sibling = pre.previousElementSibling;
  while (sibling) {
    if (sibling.matches("h1, h2, h3, h4, h5, h6")) {
      const title = sibling.textContent.trim();
      if (title) return `${title} · 结构图`;
    }
    sibling = sibling.previousElementSibling;
  }
  const documentTitle = pre.closest(".research-document")?.querySelector(".document-header h2")?.textContent.trim();
  return documentTitle ? `${documentTitle} · 结构图 ${ordinal}` : `研究结构图 ${ordinal}`;
}

function makeDiagramButton(label) {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  return button;
}

let expandedDiagram = null;

function enhanceDiagram(pre, ordinal) {
  const sourceCode = pre.querySelector(":scope > code");
  if (!sourceCode || !looksLikeDiagram(sourceCode)) return;

  const source = sourceCode.textContent || "";
  const lines = source.replace(/\r\n?/gu, "\n").replace(/\n$/u, "").split("\n");
  const label = diagramContextLabel(pre, ordinal);
  const lineHeight = 20;
  const padding = 16;
  const baseWidth = Math.max(320, Math.max(...lines.map(diagramColumns)) * 8.55 + padding * 2);
  const baseHeight = Math.max(72, lines.length * lineHeight + padding * 2);

  const figure = document.createElement("figure");
  figure.className = "ascii-diagram";
  figure.dataset.asciiDiagram = "enhanced";
  figure.dataset.sourceLength = String(source.length);

  const header = document.createElement("div");
  header.className = "ascii-diagram__header";
  const caption = document.createElement("figcaption");
  caption.className = "ascii-diagram__caption";
  caption.textContent = label;
  const actions = document.createElement("div");
  actions.className = "ascii-diagram__actions";
  actions.setAttribute("role", "group");
  actions.setAttribute("aria-label", "结构图显示工具");
  header.append(caption, actions);

  const viewport = document.createElement("div");
  viewport.className = "ascii-diagram__viewport";
  viewport.tabIndex = 0;
  viewport.setAttribute("role", "region");
  viewport.setAttribute("aria-label", `${label}（可在区域内横向和纵向滚动）`);

  const svgNamespace = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(svgNamespace, "svg");
  svg.classList.add("diagram-svg");
  svg.setAttribute("viewBox", `0 0 ${Math.ceil(baseWidth)} ${Math.ceil(baseHeight)}`);
  svg.setAttribute("width", String(Math.ceil(baseWidth)));
  svg.setAttribute("height", String(Math.ceil(baseHeight)));
  svg.setAttribute("preserveAspectRatio", "xMinYMin meet");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", label);
  const title = document.createElementNS(svgNamespace, "title");
  title.textContent = `${label}。可用上方工具缩放；原始 ASCII 位于图后折叠区。`;
  svg.append(title);
  const text = document.createElementNS(svgNamespace, "text");
  text.setAttribute("x", String(padding));
  text.setAttribute("y", String(padding + lineHeight - 4));
  text.setAttribute("xml:space", "preserve");
  for (const [index, line] of lines.entries()) {
    const row = document.createElementNS(svgNamespace, "tspan");
    row.setAttribute("x", String(padding));
    row.setAttribute("dy", index === 0 ? "0" : String(lineHeight));
    row.textContent = line || " ";
    text.append(row);
  }
  svg.append(text);
  viewport.append(svg);

  const original = document.createElement("details");
  original.className = "ascii-diagram__original";
  const summary = document.createElement("summary");
  summary.textContent = "查看原始 ASCII";
  const rawPre = document.createElement("pre");
  rawPre.className = "ascii-diagram__source";
  const rawCode = document.createElement("code");
  rawCode.textContent = source;
  rawPre.append(rawCode);
  original.append(summary, rawPre);

  let scale = 1;
  const zoomOut = makeDiagramButton("缩小");
  const fit = makeDiagramButton("适合宽度");
  const zoomIn = makeDiagramButton("放大");
  const expand = makeDiagramButton("展开");
  fit.setAttribute("aria-pressed", "false");
  expand.setAttribute("aria-pressed", "false");

  function updateScale(nextScale) {
    scale = Math.min(2.4, Math.max(.6, nextScale));
    svg.classList.remove("diagram-svg--fit");
    fit.setAttribute("aria-pressed", "false");
    svg.setAttribute("width", String(Math.ceil(baseWidth * scale)));
    svg.setAttribute("height", String(Math.ceil(baseHeight * scale)));
    zoomOut.disabled = scale <= .6;
    zoomIn.disabled = scale >= 2.4;
  }

  function setExpanded(expanded) {
    if (expandedDiagram && expandedDiagram.figure !== figure) {
      expandedDiagram.setExpanded(false);
    }
    figure.classList.toggle("is-expanded", expanded);
    document.body.classList.toggle("has-expanded-diagram", expanded);
    expand.textContent = expanded ? "退出展开" : "展开";
    expand.setAttribute("aria-pressed", expanded ? "true" : "false");
    expandedDiagram = expanded ? {figure, setExpanded, button: expand} : null;
  }

  zoomOut.addEventListener("click", () => updateScale(scale - .2));
  zoomIn.addEventListener("click", () => updateScale(scale + .2));
  fit.addEventListener("click", () => {
    const next = !svg.classList.contains("diagram-svg--fit");
    svg.classList.toggle("diagram-svg--fit", next);
    fit.setAttribute("aria-pressed", next ? "true" : "false");
  });
  expand.addEventListener("click", () => setExpanded(!figure.classList.contains("is-expanded")));
  actions.append(zoomOut, fit, zoomIn, expand);
  figure.append(header, viewport, original);
  pre.replaceWith(figure);
  updateScale(1);
}

for (const [index, pre] of document.querySelectorAll(".research-body pre").entries()) {
  enhanceDiagram(pre, index + 1);
}

document.addEventListener("keydown", event => {
  if (event.key !== "Escape" || !expandedDiagram) return;
  const {setExpanded, button} = expandedDiagram;
  setExpanded(false);
  button.focus();
});

for (const toc of document.querySelectorAll("[data-document-toc]")) {
  const panel = toc.closest(".current-document-toc");
  const filter = panel?.querySelector("[data-toc-filter]");
  const empty = panel?.querySelector("[data-toc-empty]");
  const entries = [...toc.querySelectorAll("[data-toc-entry]")];
  const levelButtons = [...(panel?.querySelectorAll("[data-toc-level]") || [])];
  let levelMode = "all";

  function normalize(value) {
    return value.normalize("NFKC").trim().toLocaleLowerCase(document.documentElement.lang || "zh-CN");
  }

  function entryOwnText(entry) {
    return normalize(entry.querySelector(":scope > a")?.textContent || "");
  }

  function refreshToc() {
    const query = normalize(filter?.value || "");
    let visibleCount = 0;
    for (const entry of entries) {
      const depth = Number.parseInt(entry.dataset.tocDepth || "1", 10);
      const queryMatch = !query || entryOwnText(entry).includes(query);
      const descendantMatch = query
        ? [...entry.querySelectorAll("[data-toc-entry] > a")].some(link => normalize(link.textContent || "").includes(query))
        : false;
      const levelMatch = levelMode === "all" || depth <= 2;
      const visible = query ? (queryMatch || descendantMatch) : levelMatch;
      entry.hidden = !visible;
      if (visible && !entry.parentElement?.closest("[data-toc-entry][hidden]")) visibleCount += 1;
    }
    if (empty) empty.hidden = visibleCount > 0;
  }

  filter?.addEventListener("input", refreshToc);
  for (const button of levelButtons) {
    button.addEventListener("click", () => {
      levelMode = button.dataset.tocLevel === "2" ? "2" : "all";
      for (const candidate of levelButtons) {
        candidate.setAttribute("aria-pressed", candidate === button ? "true" : "false");
      }
      refreshToc();
    });
  }
  refreshToc();

  const links = [...toc.querySelectorAll('a[href^="#"]')];
  const headings = links
    .map(link => {
      const id = decodeURIComponent(link.hash.slice(1));
      return {link, heading: document.getElementById(id)};
    })
    .filter(item => item.heading);
  function markCurrent(activeLink) {
    for (const {link} of headings) {
      if (link === activeLink) link.setAttribute("aria-current", "location");
      else link.removeAttribute("aria-current");
    }
  }
  if ("IntersectionObserver" in globalThis && headings.length) {
    const visibleHeadings = new Map();
    const observer = new IntersectionObserver(records => {
      for (const record of records) {
        if (record.isIntersecting) visibleHeadings.set(record.target.id, record.boundingClientRect.top);
        else visibleHeadings.delete(record.target.id);
      }
      const active = headings
        .filter(({heading}) => visibleHeadings.has(heading.id))
        .sort((left, right) => visibleHeadings.get(left.heading.id) - visibleHeadings.get(right.heading.id))[0];
      if (active) markCurrent(active.link);
    }, {rootMargin: "-18% 0px -68% 0px", threshold: [0, 1]});
    for (const {heading} of headings) observer.observe(heading);
  }
  for (const {link} of headings) link.addEventListener("click", () => markCurrent(link));
}

function topicCommandKey(form, action, body) {
  const fingerprint = JSON.stringify(body);
  if (form.dataset.topicRequestBody !== fingerprint) {
    form.dataset.topicRequestBody = fingerprint;
    form.dataset.topicRequestKey = idempotencyKey(action);
  }
  return form.dataset.topicRequestKey;
}

function topicFormValue(form, name) {
  const field = form.elements.namedItem(name);
  return field && typeof field.value === "string" ? field.value.trim() : "";
}

function focusTopicError(form) {
  const invalid = form.querySelector(":invalid");
  const fallback = form.querySelector('input[name="title"], textarea[name="note"]');
  (invalid || fallback)?.focus();
}

for (const form of document.querySelectorAll("[data-topic-create], [data-topic-edit]")) {
  updateOtherName(form);
  form.addEventListener("change", event => {
    if (event.target && event.target.name === "actor_kind") updateOtherName(form);
  });
}

for (const form of document.querySelectorAll("[data-topic-create]")) {
  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (form.dataset.busy === "true") return;
    const note = topicFormValue(form, "note");
    const body = {
      actor: selectedActor(form),
      title: topicFormValue(form, "title"),
      state: form.dataset.initialState,
      note: note || null,
    };
    setBusy(form, true);
    setStatus(form, "正在添加进度记录…");
    try {
      await command(
        "/api/v1/dashboard-topics",
        "POST",
        body,
        topicCommandKey(form, "dashboard-topic-create", body),
      );
      setStatus(form, "进度记录已添加，正在刷新…");
      globalThis.location.reload();
    } catch (error) {
      setBusy(form, false);
      setStatus(form, error.message, "error");
      focusTopicError(form);
    }
  });
}

for (const form of document.querySelectorAll("[data-topic-edit]")) {
  const card = form.closest("[data-topic-managed]");
  if (!card) continue;
  const topicId = card.dataset.topicId;
  const etag = `"topic:${topicId}:r${card.dataset.topicRevision}"`;

  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (form.dataset.busy === "true") return;
    const note = topicFormValue(form, "note");
    const body = {
      actor: selectedActor(form),
      title: topicFormValue(form, "title"),
      state: topicFormValue(form, "state"),
      note: note || null,
    };
    setBusy(form, true);
    setStatus(form, "正在保存进度记录…");
    try {
      await command(
        `/api/v1/dashboard-topics/${encodeURIComponent(topicId)}`,
        "PATCH",
        body,
        topicCommandKey(form, "dashboard-topic-update", body),
        etag,
      );
      setStatus(form, "进度记录已保存，正在刷新…");
      globalThis.location.reload();
    } catch (error) {
      setBusy(form, false);
      setStatus(form, error.message, "error");
      focusTopicError(form);
    }
  });

  const deleteButton = form.querySelector("[data-topic-delete]");
  deleteButton?.addEventListener("click", async () => {
    if (form.dataset.busy === "true") return;
    const actor = selectedActor(form);
    if (actor.actor_kind === "other" && !actor.display_name) {
      updateOtherName(form);
      const nameInput = form.querySelector('input[name="display_name"]');
      nameInput?.focus();
      nameInput?.reportValidity();
      return;
    }
    if (!globalThis.confirm("确认删除这条进度记录？")) return;
    const body = {actor};
    setBusy(form, true);
    setStatus(form, "正在删除进度记录…");
    try {
      await command(
        `/api/v1/dashboard-topics/${encodeURIComponent(topicId)}`,
        "DELETE",
        body,
        topicCommandKey(form, "dashboard-topic-delete", body),
        etag,
      );
      setStatus(form, "进度记录已删除，正在刷新…");
      globalThis.location.reload();
    } catch (error) {
      setBusy(form, false);
      setStatus(form, error.message, "error");
      focusTopicError(form);
    }
  });
}

// Reproducible performance-gate milestone: only the current chapter, its
// MathML and local navigation are in the critical path. Comments and evidence
// dialogs remain on-demand and do not delay this event.
if (document.querySelector(".research-document-shell")) {
  requestAnimationFrame(() => requestAnimationFrame(() => {
    document.documentElement.dataset.researchReady = "true";
    globalThis.dispatchEvent(new CustomEvent("research:ready", {
      detail: {at: performance.now()},
    }));
  }));
}

for (const form of document.querySelectorAll(
  "[data-research-project-create], [data-research-node-edit], [data-workspace-comment-create], [data-workspace-comment-dialog] form",
)) {
  updateOtherName(form);
  form.addEventListener("change", event => {
    if (event.target && event.target.name === "actor_kind") updateOtherName(form);
  });
}

const researchProjectPanel = document.querySelector("[data-research-project-create]")?.closest("details");
document.querySelector('a[href="#workspace-project-create"]')?.addEventListener("click", () => {
  if (researchProjectPanel) researchProjectPanel.open = true;
});

const researchProjectForm = document.querySelector("[data-research-project-create]");
if (researchProjectForm) {
  researchProjectForm.addEventListener("submit", async event => {
    event.preventDefault();
    if (researchProjectForm.dataset.busy === "true") return;
    const fieldValue = name => {
      const field = researchProjectForm.elements.namedItem(name);
      return field && typeof field.value === "string" ? field.value.trim() : "";
    };
    const body = {
      actor: selectedActor(researchProjectForm),
      title: fieldValue("title"),
      description: fieldValue("description") || null,
      research_question: fieldValue("research_question") || null,
      research_content: fieldValue("research_content") || null,
      lifecycle_status: fieldValue("lifecycle_status"),
      status_note: fieldValue("status_note") || null,
    };
    setBusy(researchProjectForm, true);
    setStatus(researchProjectForm, "正在创建研究目录与专项信息…");
    try {
      const result = await command(
        "/api/v1/research-projects",
        "POST",
        body,
        idempotencyKey("research-project-create"),
      );
      setStatus(researchProjectForm, "专项已创建，正在打开…");
      const nodeId = result?.data?.node_id;
      globalThis.location.assign(nodeId ? `/?node=${encodeURIComponent(nodeId)}` : "/");
    } catch (error) {
      setBusy(researchProjectForm, false);
      setStatus(researchProjectForm, error.message, "error");
      (researchProjectForm.querySelector(":invalid") || researchProjectForm.querySelector('input[name="title"]'))?.focus();
    }
  });
}

const workspaceSyncButton = document.querySelector("[data-workspace-sync]");
if (workspaceSyncButton) {
  const status = document.querySelector("[data-workspace-sync-status]");
  workspaceSyncButton.addEventListener("click", async () => {
    if (workspaceSyncButton.disabled) return;
    workspaceSyncButton.disabled = true;
    workspaceSyncButton.setAttribute("aria-busy", "true");
    if (status) {
      status.textContent = "正在读取目录与 Markdown…";
      status.dataset.state = "ready";
    }
    try {
      await command(
        "/api/v1/research-tree/sync",
        "POST",
        {},
        idempotencyKey("research-tree-sync"),
      );
      if (status) status.textContent = "同步完成，正在刷新研究树…";
      globalThis.location.reload();
    } catch (error) {
      workspaceSyncButton.disabled = false;
      workspaceSyncButton.setAttribute("aria-busy", "false");
      if (status) {
        status.textContent = error.message;
        status.dataset.state = "error";
      }
      workspaceSyncButton.focus();
    }
  });
}

const researchNodeForm = document.querySelector("[data-research-node-edit]");
const researchNodeEditor = researchNodeForm?.closest("details");
document.querySelector("[data-workspace-editor-open]")?.addEventListener("click", () => {
  if (!researchNodeEditor) return;
  researchNodeEditor.open = true;
  researchNodeEditor.scrollIntoView({behavior: "smooth", block: "start"});
  researchNodeForm?.querySelector('input[name="title"]')?.focus({preventScroll: true});
});
if (researchNodeForm) {
  researchNodeForm.addEventListener("submit", async event => {
    event.preventDefault();
    if (researchNodeForm.dataset.busy === "true") return;
    const nodeId = researchNodeForm.dataset.nodeId;
    const revision = researchNodeForm.dataset.nodeRevision;
    const fieldValue = name => {
      const field = researchNodeForm.elements.namedItem(name);
      return field && typeof field.value === "string" ? field.value.trim() : "";
    };
    const body = {actor: selectedActor(researchNodeForm)};
    for (const name of [
      "title",
      "description",
      "research_question",
      "research_content",
      "lifecycle_status",
      "status_note",
    ]) {
      if (researchNodeForm.elements.namedItem(name)) {
        body[name] = fieldValue(name) || null;
      }
    }
    setBusy(researchNodeForm, true);
    setStatus(researchNodeForm, "正在保存研究信息…");
    try {
      await command(
        `/api/v1/research-nodes/${encodeURIComponent(nodeId)}`,
        "PATCH",
        body,
        idempotencyKey("research-node-update"),
        `"research-node:${nodeId}:r${revision}"`,
      );
      setStatus(researchNodeForm, "已保存，正在刷新…");
      globalThis.location.reload();
    } catch (error) {
      setBusy(researchNodeForm, false);
      setStatus(researchNodeForm, error.message, "error");
      (researchNodeForm.querySelector(":invalid") || researchNodeForm.querySelector('input[name="title"]'))?.focus();
    }
  });
}

const workspaceCommentCreate = document.querySelector("[data-workspace-comment-create]");
if (workspaceCommentCreate) {
  workspaceCommentCreate.addEventListener("submit", async event => {
    event.preventDefault();
    if (workspaceCommentCreate.dataset.busy === "true") return;
    const nodeId = workspaceCommentCreate.dataset.nodeId;
    const textarea = workspaceCommentCreate.querySelector('textarea[name="content"]');
    const body = {
      actor: selectedActor(workspaceCommentCreate),
      content: textarea ? textarea.value : "",
    };
    setBusy(workspaceCommentCreate, true);
    setStatus(workspaceCommentCreate, "正在提交评论…");
    try {
      await command(
        `/api/v1/research-nodes/${encodeURIComponent(nodeId)}/comments`,
        "POST",
        body,
        idempotencyKey("research-node-comment-create"),
      );
      setStatus(workspaceCommentCreate, "评论已提交，正在刷新…");
      globalThis.location.reload();
    } catch (error) {
      setBusy(workspaceCommentCreate, false);
      setStatus(workspaceCommentCreate, error.message, "error");
      focusAfterError(workspaceCommentCreate);
    }
  });
}

const workspaceCommentDialog = document.querySelector("[data-workspace-comment-dialog]");
const workspaceCommentDialogForm = workspaceCommentDialog?.querySelector("form");
let activeWorkspaceComment = null;
for (const card of document.querySelectorAll("[data-workspace-comment]")) {
  const editButton = card.querySelector("[data-workspace-comment-edit]");
  const deleteButton = card.querySelector("[data-workspace-comment-delete]");
  editButton?.addEventListener("click", () => {
    if (!workspaceCommentDialog || !workspaceCommentDialogForm) return;
    activeWorkspaceComment = card;
    const textarea = workspaceCommentDialogForm.querySelector('textarea[name="content"]');
    const body = card.querySelector("[data-comment-body]");
    if (textarea) textarea.value = body ? body.textContent.trim() : "";
    setStatus(workspaceCommentDialogForm, "");
    workspaceCommentDialog.showModal();
    textarea?.focus();
  });
  deleteButton?.addEventListener("click", async () => {
    if (deleteButton.disabled) return;
    if (!globalThis.confirm("确认删除这条节点评论？")) return;
    const commentId = card.dataset.commentId;
    const revision = card.dataset.commentRevision;
    const actor = selectedActor(workspaceCommentCreate || document.body);
    deleteButton.disabled = true;
    try {
      await command(
        `/api/v1/research-node-comments/${encodeURIComponent(commentId)}`,
        "DELETE",
        {actor},
        idempotencyKey("research-node-comment-delete"),
        `"research-node-comment:${commentId}:r${revision}"`,
      );
      globalThis.location.reload();
    } catch (error) {
      deleteButton.disabled = false;
      globalThis.alert(error.message);
      deleteButton.focus();
    }
  });
}

workspaceCommentDialog?.querySelector("[data-dialog-cancel]")?.addEventListener("click", () => {
  workspaceCommentDialog.close();
  activeWorkspaceComment?.querySelector("[data-workspace-comment-edit]")?.focus();
});

workspaceCommentDialogForm?.addEventListener("submit", async event => {
  event.preventDefault();
  if (!activeWorkspaceComment || workspaceCommentDialogForm.dataset.busy === "true") return;
  const commentId = activeWorkspaceComment.dataset.commentId;
  const revision = activeWorkspaceComment.dataset.commentRevision;
  const textarea = workspaceCommentDialogForm.querySelector('textarea[name="content"]');
  const body = {
    actor: selectedActor(workspaceCommentDialogForm),
    content: textarea ? textarea.value : "",
  };
  setBusy(workspaceCommentDialogForm, true);
  setStatus(workspaceCommentDialogForm, "正在保存评论…");
  try {
    await command(
      `/api/v1/research-node-comments/${encodeURIComponent(commentId)}`,
      "PATCH",
      body,
      idempotencyKey("research-node-comment-update"),
      `"research-node-comment:${commentId}:r${revision}"`,
    );
    setStatus(workspaceCommentDialogForm, "已保存，正在刷新…");
    globalThis.location.reload();
  } catch (error) {
    setBusy(workspaceCommentDialogForm, false);
    setStatus(workspaceCommentDialogForm, error.message, "error");
    textarea?.focus();
  }
});
