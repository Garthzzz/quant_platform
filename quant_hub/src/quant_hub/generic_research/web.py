"""Namespaced Web adapter for generic research documents."""

from __future__ import annotations

import hashlib
from typing import Any

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    jsonify,
    render_template,
    request,
)
from markupsafe import Markup
from pydantic import ValidationError

from quant_hub.archive.contracts import ActorInput
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
    return render_template(
        "generic_research/document.html",
        page=page,
        rendered_html=Markup(page.rendered_html),
        comments=_comment_views(page),
        csrf_token=csrf_token(),
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
__all__ = ["generic_research_web"]
