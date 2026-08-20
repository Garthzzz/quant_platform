"""Safe, read-only presentation projections for Paper Lab research fields.

The legacy/raw field values remain the only editable and exportable values.  This
module only adds a parallel HTML projection for human reading so that formulas
and bounded legacy LaTeX use the same reviewed renderer as Archive Evidence.
"""

from __future__ import annotations

from markupsafe import escape

from quant_hub.archive.markdown import render_research_text

from .contracts import EDITABLE_PAPER_FIELDS


PRESENTATION_VERSION = "paper-lab-research-text/v1"

_NON_NARRATIVE_FIELDS = frozenset({"title", "link", "rating", "diagram"})
_PIPELINE_CLASSES = {
    "data_input": "paper-pipeline-data",
    "data_preprocess": "paper-pipeline-preprocess",
    "method_model": "paper-pipeline-model",
    "method_special": "paper-pipeline-special",
    "loss_function": "paper-pipeline-loss",
    "training_config": "paper-pipeline-training",
    "pipeline_output": "paper-pipeline-output",
}
_SECTION_MARKERS = {
    "【创新点】": "paper-marker-innovation",
    "【启发】": "paper-marker-insight",
    "【质疑】": "paper-marker-caveat",
    "【复现注意】": "paper-marker-replication",
}

# A few legacy Paper Lab JSON values were decoded before import without escaped
# LaTeX backslashes. JSON consequently turned a small, known set of commands
# into C0 control characters (for example form-feed + ``rac`` for ``\frac``).
# Repair only those exact suffixes in the read-only presentation projection;
# editing, search, and export continue to use the untouched database value.
_LEGACY_LATEX_CONTROL_REPAIRS = (
    ("\x07lpha", r"\alpha"),
    ("\x08eta", r"\beta"),
    ("\t" + "ilde", r"\tilde"),
    ("\t" + "heta", r"\theta"),
    ("\t" + "ext", r"\text"),
    ("\x0b" + "arepsilon", r"\varepsilon"),
    ("\x0c" + "rac", r"\frac"),
    ("\r" + "ho", r"\rho"),
)


def _repair_legacy_latex_controls(source: str) -> str:
    repaired = source
    for damaged, command in _LEGACY_LATEX_CONTROL_REPAIRS:
        repaired = repaired.replace(damaged, command)
    return repaired


def _inline_research_html(source: str) -> str:
    """Return a sanitized single-line fragment without an unnecessary p wrapper."""

    rendered = render_research_text(source).strip()
    if rendered.startswith("<p>") and rendered.endswith("</p>"):
        return rendered[3:-4]
    return rendered


def _arrow_note_html(explanation: str) -> str:
    return (
        '<p class="paper-pipeline-note">'
        '<span class="paper-pipeline-arrow" aria-hidden="true">→</span>'
        f'<span class="paper-pipeline-note-text">{explanation}</span>'
        "</p>"
    )


def _pipeline_html(source: str, field: str) -> str:
    fragments: list[str] = []
    css_class = _PIPELINE_CLASSES[field]
    presentation_source = _repair_legacy_latex_controls(source)
    for raw_line in presentation_source.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("→"):
            explanation = _inline_research_html(line.removeprefix("→").strip())
            fragments.append(_arrow_note_html(explanation))
            continue
        if "|" in line:
            parts = [item.strip() for item in line.split("|", 2)]
            tag = parts[0]
            name = parts[1] if len(parts) > 1 else ""
            method = parts[2] if len(parts) > 2 else ""
            method, has_explanation, explanation = method.partition(" → ")
            method_html = (
                '<small class="paper-pipeline-method">— '
                f"{_inline_research_html(method)}</small>"
                if method
                else ""
            )
            fragments.append(
                '<div class="paper-pipeline-card">'
                f'<span class="paper-pipeline-tag {css_class}">{escape(tag)}</span>'
                f"<strong>{_inline_research_html(name)}</strong>{method_html}</div>"
            )
            if has_explanation:
                fragments.append(
                    _arrow_note_html(_inline_research_html(explanation.strip()))
                )
            continue
        fragments.append(
            '<div class="paper-pipeline-note paper-pipeline-note--plain">'
            f'<div class="paper-pipeline-note-text">{render_research_text(line)}</div>'
            "</div>"
        )
    return "".join(fragments)


def _section_html(source: str) -> str:
    rendered = render_research_text(source)
    for marker, class_name in _SECTION_MARKERS.items():
        rendered = rendered.replace(
            marker,
            f'<strong class="paper-section-marker {class_name}">{marker}</strong>',
        )
    return rendered


def build_paper_presentation_html(paper: dict[str, object]) -> dict[str, str]:
    """Build sanitized HTML alongside, never instead of, the raw paper fields."""

    result: dict[str, str] = {}
    for field in EDITABLE_PAPER_FIELDS:
        if field in _NON_NARRATIVE_FIELDS:
            continue
        value = paper.get(field)
        if value is None:
            continue
        source = str(value)
        if not source.strip():
            continue
        if field in _PIPELINE_CLASSES:
            result[field] = _pipeline_html(source, field)
        elif field in {"innovations_insights", "caveats_replication"}:
            result[field] = _section_html(source)
        else:
            result[field] = render_research_text(source)
    return result


def with_paper_presentation(paper: dict[str, object]) -> dict[str, object]:
    """Return a shallow response projection while preserving every raw field."""

    return {
        **paper,
        "presentation_version": PRESENTATION_VERSION,
        "presentation_html": build_paper_presentation_html(paper),
    }


__all__ = [
    "PRESENTATION_VERSION",
    "build_paper_presentation_html",
    "with_paper_presentation",
]
