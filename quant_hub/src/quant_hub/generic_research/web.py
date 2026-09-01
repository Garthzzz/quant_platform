"""Namespaced Web adapter for generic research documents."""

from __future__ import annotations

from dataclasses import replace
import html
import hashlib
import re
from typing import Any
from urllib.parse import urlsplit

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from markupsafe import Markup
from pydantic import ValidationError

from quant_hub.archive.contracts import ActorInput
from quant_hub.archive.catalog import ArchiveCatalog
from quant_hub.collaboration.comment_anchors import build_comment_anchor_projection
from quant_hub.collaboration.service import ArchiveCollaboration, IdempotencyConflict
from quant_hub.web.security import WriteSecurityError, csrf_token, require_write_security
from .catalog import GenericCatalogError, GenericResearchCatalog


generic_research_web = Blueprint(
    "generic_research",
    __name__,
    url_prefix="/knowledge",
    template_folder="templates",
    static_folder="static",
    static_url_path="/assets",
)


def _catalog() -> GenericResearchCatalog:
    catalog = current_app.extensions.get("generic_research_catalog")
    if not isinstance(catalog, GenericResearchCatalog):
        abort(404)
    return catalog


def _collaboration() -> ArchiveCollaboration | None:
    value = current_app.extensions.get("generic_research_collaboration")
    return value if isinstance(value, ArchiveCollaboration) else None


def _comment_views(page: Any) -> dict[str, object]:
    service = _collaboration()
    if service is None or service.comment_database_path is None:
        return {"enabled": False, "resolved": (), "unresolved": ()}
    projection = build_comment_anchor_projection(
        service.comment_database_path,
        _catalog().comment_snapshot(page.document_id, page.version_id),
    )
    entries = {
        str(item["comment_id"]): item
        for item in projection["entries"]
        if item["research_id"] == page.research_id
        and item.get("document_id") in {None, page.document_id}
    }
    resolved: list[dict[str, object]] = []
    unresolved: list[dict[str, object]] = []
    for comment in service.list_comments(page.research_id):
        entry = entries.get(str(comment["comment_id"]))
        if entry is None:
            continue
        item = {**comment, **entry}
        status = str(entry["resolution"]["status"])
        (resolved if status.startswith("resolved_") else unresolved).append(item)
    return {
        "enabled": True,
        "resolved": tuple(resolved),
        "unresolved": tuple(unresolved),
        "projection_snapshot_id": projection["snapshot_id"],
        "projection_manifest_sha256": projection["manifest_sha256"],
    }


def _render(page: Any) -> str:
    page = replace(page, rendered_html=_rewrite_content_urls(page))
    return render_template(
        "generic_research/document.html",
        page=page,
        rendered_html=Markup(page.rendered_html),
        comments=_comment_views(page),
        csrf_token=csrf_token(),
    )


_CONTENT_URL = re.compile(
    r'(?P<prefix>\b(?P<attribute>href|src)=(?P<quote>["\']))'
    r"(?P<target>.*?)(?P=quote)",
    flags=re.IGNORECASE,
)


def _rewrite_content_urls(page: Any) -> str:
    """Route non-external Markdown URLs through the reviewed link adapter."""

    def replacement(match: re.Match[str]) -> str:
        target = html.unescape(match.group("target")).strip()
        parsed = urlsplit(target)
        if (
            not target
            or target.startswith("#")
            or parsed.scheme
            or parsed.netloc
            or target.startswith(("data:", "mailto:", "tel:", "javascript:"))
        ):
            return match.group(0)
        proxy = url_for(
            "generic_research.content_link",
            document_id=page.document_id,
            version_id=page.version_id,
            kind=match.group("attribute").casefold(),
            target=target,
        )
        quote_character = match.group("quote")
        return (
            match.group("prefix")
            + html.escape(proxy, quote=True)
            + quote_character
        )

    return _CONTENT_URL.sub(replacement, str(page.rendered_html))


def _unavailable_asset(target: str) -> Response:
    label = html.escape(target.rsplit("/", 1)[-1] or "unavailable asset")
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="960" height="180" '
        'viewBox="0 0 960 180" role="img" aria-label="资源未随当前快照发布">'
        '<rect width="960" height="180" fill="#f3f5f7"/>'
        '<text x="32" y="78" font-family="sans-serif" font-size="22" fill="#39424e">'
        '资源未随当前审阅快照发布</text>'
        f'<text x="32" y="118" font-family="monospace" font-size="15" fill="#68727e">{label}</text>'
        "</svg>"
    )
    response = Response(svg.encode("utf-8"), mimetype="image/svg+xml")
    response.headers["Cache-Control"] = "private, max-age=300"
    return response


def _resolve_content_link(
    *,
    document_id: str | None,
    version_id: str | None,
    target: str,
    kind: str,
) -> Response | str:
    catalog = _catalog()
    try:
        resolved_document_id = catalog.resolve_logical_link(
            target,
            source_document_id=document_id,
            source_version_id=version_id,
        )
        source_path = (
            catalog.logical_path(document_id, version_id)
            if document_id is not None
            else "__generic_link_root__.md"
        )
    except KeyError:
        abort(404)
    if resolved_document_id is not None:
        return redirect(
            url_for(
                "generic_research.current_document",
                document_id=resolved_document_id,
            ),
            code=302,
        )
    if target == "/" or (
        target.startswith(("/research/", "/evidence/", "/paper-lab/", "/api/v1/"))
        and not target.startswith("//")
    ):
        return redirect(target, code=302)
    archive = current_app.extensions.get("archive_catalog")
    if isinstance(archive, ArchiveCatalog):
        resolution = archive.resolve_archive_link(
            source_path,
            target,
            index=archive.archive_link_index(),
        )
        if resolution.state == "resolved":
            return redirect(resolution.url, code=302)
    if kind == "src" or target.casefold().endswith(
        (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp")
    ):
        return _unavailable_asset(target)
    return render_template(
        "error.html",
        title="来源尚未发布",
        message="该链接指向的来源尚未进入当前审阅快照；原研究正文未被改写。",
    )


@generic_research_web.get("/research/<document_id>/")
def current_document(document_id: str) -> str:
    try:
        page = _catalog().page(document_id)
    except KeyError:
        abort(404)
    except GenericCatalogError:
        abort(503)
    return _render(page)


@generic_research_web.get("/research/<document_id>/versions/<version_id>/")
def version_document(document_id: str, version_id: str) -> str:
    try:
        page = _catalog().page(document_id, version_id)
    except KeyError:
        abort(404)
    except GenericCatalogError:
        abort(503)
    return _render(page)


@generic_research_web.post("/research/<document_id>/comments")
def create_comment(document_id: str) -> Response:
    service = _collaboration()
    if service is None:
        return jsonify({"error": "comments_unavailable"}), 503
    try:
        key = require_write_security(
            request, current_app.extensions["trusted_origins"]
        )
    except WriteSecurityError as error:
        return jsonify({"error": error.code, "message": str(error)}), error.status
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "invalid_comment", "message": "评论数据无效。"}), 422
    try:
        if not isinstance(payload.get("content"), str) or not isinstance(
            payload.get("version_id"), str
        ):
            raise ValueError("comment content and version identity must be strings")
        actor = ActorInput.model_validate(
            {
                "actor_kind": payload.get("actor_kind"),
                "display_name": payload.get("display_name"),
            }
        )
        content = payload["content"].strip()
        version_id = payload["version_id"]
        target_kind = str(payload.get("target_kind") or "document")
        if target_kind not in {"document", "block", "span"}:
            raise ValueError("unsupported target kind")
        page = _catalog().page(document_id, version_id)
        target = _catalog().comment_target(
            document_id,
            version_id,
            target_kind=target_kind,  # type: ignore[arg-type]
            span_id=(
                str(payload.get("anchor_span_id") or "")
                if target_kind != "document"
                else None
            ),
        )
    except (GenericCatalogError, KeyError, ValidationError, ValueError):
        return jsonify({"error": "invalid_comment", "message": "评论或锚点数据无效。"}), 422
    try:
        outcome = service.create_comment(
            page.research_id,
            actor,
            content,
            idempotency_key=key,
            target=target,
        )
    except IdempotencyConflict:
        return jsonify({"error": "idempotency_conflict"}), 409
    if not outcome.ok:
        return jsonify(
            {"error": outcome.error_code, "message": outcome.error_message}
        ), outcome.status
    return jsonify({"comment": outcome.data}), outcome.status


@generic_research_web.get("/research/<document_id>/versions/<version_id>/source")
def source_document(document_id: str, version_id: str) -> Response:
    try:
        source = _catalog().source_bytes(document_id, version_id)
    except KeyError:
        abort(404)
    except GenericCatalogError:
        abort(503)
    response = Response(source, mimetype="text/markdown")
    response.headers["Content-Disposition"] = (
        f'attachment; filename="{document_id}-{version_id}.md"'
    )
    response.headers["ETag"] = f'"sha256-{hashlib.sha256(source).hexdigest()}"'
    response.headers["Cache-Control"] = "private, immutable"
    return response


@generic_research_web.get("/<path:logical_path>")
def logical_source_link(logical_path: str) -> Response | str:
    """Resolve relative Markdown links without exposing broken source paths."""

    parts = logical_path.replace("\\", "/").split("/")
    source_document_id: str | None = None
    source_version_id: str | None = None
    target_parts = parts
    if len(parts) >= 3 and parts[0] == "research":
        source_document_id = parts[1]
        if len(parts) >= 5 and parts[2] == "versions":
            source_version_id = parts[3]
            target_parts = parts[4:]
        else:
            target_parts = parts[2:]
    target = "/".join(target_parts)
    kind = (
        "src"
        if target.casefold().endswith(
            (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp")
        )
        else "href"
    )
    return _resolve_content_link(
        document_id=source_document_id,
        version_id=source_version_id,
        target=target,
        kind=kind,
    )


@generic_research_web.get("/link/<document_id>/<version_id>")
def content_link(document_id: str, version_id: str) -> Response | str:
    target = request.args.get("target", "").strip()
    kind = request.args.get("kind", "href").strip().casefold()
    if not target or kind not in {"href", "src"}:
        abort(400)
    return _resolve_content_link(
        document_id=document_id,
        version_id=version_id,
        target=target,
        kind=kind,
    )


__all__ = ["generic_research_web"]
