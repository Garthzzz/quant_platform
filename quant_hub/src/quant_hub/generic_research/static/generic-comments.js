(() => {
  "use strict";

  const form = document.querySelector("[data-generic-comment-form]");
  if (!form) return;
  const status = form.querySelector("[data-generic-comment-status]");
  const otherName = form.elements.namedItem("display_name");

  const updateActor = () => {
    const selected = form.querySelector('input[name="actor_kind"]:checked');
    const isOther = selected && selected.value === "other";
    otherName.disabled = !isOther;
    otherName.required = Boolean(isOther);
    if (!isOther) otherName.value = "";
  };
  form.addEventListener("change", (event) => {
    if (event.target && event.target.name === "actor_kind") updateActor();
  });
  updateActor();

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    status.textContent = "正在保存…";
    const actor = form.querySelector('input[name="actor_kind"]:checked');
    const rawTarget = form.elements.namedItem("comment_target").value;
    const [targetKind, anchorSpanId] = rawTarget.split(":", 2);
    const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
    try {
      const response = await fetch(form.dataset.endpoint, {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrf,
          "Idempotency-Key": `generic-comment-${crypto.randomUUID()}`,
        },
        body: JSON.stringify({
          actor_kind: actor ? actor.value : "",
          display_name: otherName.value || null,
          content: form.elements.namedItem("content").value,
          version_id: form.dataset.versionId,
          target_kind: targetKind,
          anchor_span_id: anchorSpanId || null,
        }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.message || result.error || "保存失败");
      status.textContent = "已保存，正在刷新定位状态。";
      window.location.reload();
    } catch (error) {
      status.textContent = error instanceof Error ? error.message : "保存失败";
    }
  });
})();
