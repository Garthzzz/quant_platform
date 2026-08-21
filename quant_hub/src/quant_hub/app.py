"""Quant Research Hub Flask application factory."""

from __future__ import annotations

from pathlib import Path
import secrets
from typing import Any

from flask import Flask, Response, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from quant_hub.archive.catalog import ArchiveCatalog
from quant_hub.collaboration.comment_store import initialize_comment_store
from quant_hub.collaboration.service import ArchiveCollaboration
from quant_hub.config import ConfigurationError, Settings
from quant_hub.evidence.service import EvidenceQueryService
from quant_hub.evidence.web import create_evidence_blueprint
from quant_hub.generic_research import (
    GenericResearchCatalog,
    generic_research_web,
    load_generic_catalog_from_release,
)
from quant_hub.paper_lab import register_paper_lab
from quant_hub.research_workspace import ResearchWorkspace
from quant_hub.web.routes import api_error, api_v1, web
from quant_hub.web.security import compile_trusted_origins


def create_app(
    settings: Settings | None = None,
    config: dict[str, Any] | None = None,
) -> Flask:
    """Build the local Archive application around the formal SQLite services.

    ``settings`` is explicit in tests and deployments so a Web process cannot
    silently select a different Archive or runtime root.  The optional default
    keeps the installed ``flask --app quant_hub.app:create_app`` workflow useful.
    """

    resolved = settings or Settings.default()
    app = Flask(
        __name__,
        template_folder="web/templates",
        static_folder="web/static",
    )
    app.config.from_mapping(
        SECRET_KEY=secrets.token_hex(32),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=False,
        MAX_CONTENT_LENGTH=32 * 1024,
        JSON_SORT_KEYS=True,
        TRUSTED_ORIGINS=("http://localhost", "http://127.0.0.1:5055"),
        INITIALIZE_ARCHIVE_CATALOG=True,
        COMMENT_DATABASE_PATH=None,
        RESEARCH_WORKSPACE_DATABASE_PATH=None,
        GENERIC_RESEARCH_CATALOG=None,
        GENERIC_RESEARCH_RELEASE_ROOT=None,
    )
    if config:
        app.config.update(config)

    catalog = ArchiveCatalog(resolved)
    if app.config["INITIALIZE_ARCHIVE_CATALOG"]:
        catalog.initialize()
    # Link/anchor resolution is a publication artifact.  Warm the verified
    # read model once during process bootstrap so a chapter request never pays
    # for a full active-release index rebuild.
    catalog.archive_link_index()
    app.extensions["quant_hub_settings"] = resolved
    app.extensions["archive_catalog"] = catalog
    configured_comment_database = app.config.get("COMMENT_DATABASE_PATH")
    comment_database_path = (
        Path(configured_comment_database)
        if configured_comment_database is not None
        else None
    )
    configured_generic_release_root = app.config.get("GENERIC_RESEARCH_RELEASE_ROOT")
    if (
        comment_database_path is not None
        and configured_generic_release_root is not None
    ):
        release_root = Path(configured_generic_release_root).resolve()
        try:
            comment_database_path.resolve().relative_to(release_root)
        except ValueError:
            pass
        else:
            # Reject before initialize_comment_store can create a file or WAL
            # sidecar beneath an immutable release.
            raise ConfigurationError(
                "COMMENT_DATABASE_PATH 不得位于 immutable release 内。"
            )
    configured_workspace_database = app.config.get("RESEARCH_WORKSPACE_DATABASE_PATH")
    workspace_database_path = (
        Path(configured_workspace_database)
        if configured_workspace_database is not None
        else None
    )
    if comment_database_path is not None:
        initialize_comment_store(
            comment_database_path,
            legacy_archive_path=resolved.archive_database_path,
            legacy_workspace_path=workspace_database_path,
        )
    app.extensions["archive_collaboration"] = ArchiveCollaboration(
        resolved,
        comment_database_path=comment_database_path,
    )
    research_workspace = ResearchWorkspace(
        resolved,
        database_path=workspace_database_path,
    )
    if research_workspace.root.is_dir():
        research_workspace.sync_if_changed()
    app.extensions["research_workspace"] = research_workspace
    app.extensions["evidence_query"] = EvidenceQueryService(resolved)
    app.extensions["trusted_origins"] = compile_trusted_origins(
        app.config["TRUSTED_ORIGINS"]
    )
    generic_catalog = app.config.get("GENERIC_RESEARCH_CATALOG")
    generic_release_root = configured_generic_release_root
    if generic_catalog is not None and generic_release_root is not None:
        raise TypeError(
            "GENERIC_RESEARCH_CATALOG and GENERIC_RESEARCH_RELEASE_ROOT are mutually exclusive"
        )
    if generic_release_root is not None:
        generic_catalog = load_generic_catalog_from_release(Path(generic_release_root))
    if generic_catalog is not None:
        if not isinstance(generic_catalog, GenericResearchCatalog):
            raise TypeError("GENERIC_RESEARCH_CATALOG must be a GenericResearchCatalog")
        if comment_database_path is None and not app.testing:
            raise ConfigurationError(
                "生产 generic research 必须显式配置 release 外 COMMENT_DATABASE_PATH。"
            )
        app.extensions["generic_research_catalog"] = generic_catalog
        if comment_database_path is not None:
            app.extensions["generic_research_collaboration"] = ArchiveCollaboration(
                resolved,
                comment_database_path=comment_database_path,
                comment_identity_authority=generic_catalog,
            )

    app.register_blueprint(web)
    app.register_blueprint(api_v1)
    app.register_blueprint(generic_research_web)
    app.register_blueprint(create_evidence_blueprint(resolved))
    register_paper_lab(app, resolved)

    @app.get("/healthz")
    def healthz() -> Response:
        """不触发 Evidence/Paper Lab 业务库懒初始化的进程存活探针。"""

        response = jsonify(
            {
                "schema_version": "qrh-health/v1",
                "service": "quant-research-hub",
                "status": "ok",
            }
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
            "form-action 'self'",
        )
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=()",
        )
        if request.path.startswith("/api/v1/") and "Cache-Control" not in response.headers:
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(404)
    def not_found(_error: HTTPException) -> Response | tuple[str, int]:
        if request.path.startswith("/api/v1/"):
            return api_error("route_not_found", "API 路径不存在。", 404)
        return render_template(
            "error.html",
            title="页面不存在",
            message="请求的页面不存在或尚未发布。",
        ), 404

    @app.errorhandler(413)
    def request_too_large(_error: HTTPException) -> Response | tuple[str, int]:
        if request.path.startswith("/api/v1/"):
            return api_error("request_too_large", "请求体超过允许大小。", 413)
        return render_template(
            "error.html",
            title="请求过大",
            message="提交内容超过允许大小。",
        ), 413

    @app.errorhandler(HTTPException)
    def http_error(error: HTTPException) -> Response | HTTPException:
        if not request.path.startswith("/api/v1/"):
            return error
        code_by_status = {
            400: "bad_request",
            401: "unauthorized",
            403: "forbidden",
            405: "method_not_allowed",
            406: "not_acceptable",
            415: "unsupported_media_type",
            429: "too_many_requests",
        }
        status = int(error.code or 500)
        return api_error(
            code_by_status.get(status, "http_error"),
            "API 请求不符合 HTTP 契约。",
            status,
        )

    @app.errorhandler(Exception)
    def unexpected_error(error: Exception) -> Response | tuple[str, int]:
        if isinstance(error, HTTPException):
            return error
        if app.testing:
            raise error
        if request.path.startswith("/api/v1/"):
            return api_error("internal_error", "服务暂时无法完成请求。", 500)
        return render_template(
            "error.html",
            title="服务异常",
            message="服务暂时无法完成请求，请稍后重试。",
        ), 500

    return app


__all__ = ["create_app"]
