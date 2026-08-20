"""Namespaced Web adapter for generic research documents."""

from __future__ import annotations

import hashlib

from flask import Blueprint, Response, abort, current_app, render_template
from markupsafe import Markup

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


@generic_research_web.get("/research/<document_id>/")
def current_document(document_id: str) -> str:
    try:
        page = _catalog().page(document_id)
    except KeyError:
        abort(404)
    except GenericCatalogError:
        abort(503)
    return render_template(
        "generic_research/document.html",
        page=page,
        rendered_html=Markup(page.rendered_html),
    )


@generic_research_web.get("/research/<document_id>/versions/<version_id>/")
def version_document(document_id: str, version_id: str) -> str:
    try:
        page = _catalog().page(document_id, version_id)
    except KeyError:
        abort(404)
    except GenericCatalogError:
        abort(503)
    return render_template(
        "generic_research/document.html",
        page=page,
        rendered_html=Markup(page.rendered_html),
    )


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
