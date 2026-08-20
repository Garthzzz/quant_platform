from __future__ import annotations

import hashlib
import json
import re
from uuid import uuid4

from flask import Blueprint, Response, jsonify, render_template, request
from markupsafe import Markup

from quant_hub.archive.markdown import render_research_text
from quant_hub.config import Settings

from .resources import EvidenceResourceError, EvidenceResourceNotFound
from .service import EvidenceQueryNotFound, EvidenceQueryService


_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$", re.ASCII)


def create_evidence_blueprint(settings: Settings) -> Blueprint:
    """创建可由主应用显式注册的 Evidence v1 Blueprint。"""

    blueprint = Blueprint(
        "evidence",
        __name__,
        template_folder="templates",
        static_folder="static",
        static_url_path="/evidence/static",
    )
    service = EvidenceQueryService(settings)

    @blueprint.app_template_filter("research_text")
    def research_text_filter(value: object) -> Markup:
        """Evidence 研究字段的安全 Markdown/MathML 展示过滤器。"""

        return Markup(render_research_text("" if value is None else str(value)))

    def request_id() -> str:
        supplied = request.headers.get("X-Request-ID", "")
        return supplied if _REQUEST_ID_RE.fullmatch(supplied) else str(uuid4())

    def finalize(response: Response, *, etag_material: object | None = None) -> Response:
        response.headers["X-Request-ID"] = str(response.get_json()["meta"]["request_id"]) if response.is_json else request_id()
        response.headers["Cache-Control"] = "private, no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        if etag_material is not None:
            digest = hashlib.sha256(
                json.dumps(
                    etag_material,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            response.set_etag(digest)
            response.make_conditional(request)
        return response

    def ok(data: object, status: int = 200) -> Response:
        envelope = {
            "api_version": "v1",
            "data": data,
            "meta": {"request_id": request_id()},
        }
        response = jsonify(envelope)
        response.status_code = status
        return finalize(response, etag_material=data)

    def error(code: str, message: str, status: int) -> Response:
        response = jsonify(
            {
                "api_version": "v1",
                "error": {"code": code, "message": message},
                "meta": {"request_id": request_id()},
            }
        )
        response.status_code = status
        return finalize(response)

    @blueprint.get("/evidence/")
    def evidence_home() -> str:
        query = request.args.get("q", "").strip().casefold()
        status = request.args.get("status", "").strip()
        dossier = request.args.get("dossier", "").strip()
        payload = service.list_papers(limit=500)
        papers = list(payload["papers"])
        if query:
            papers = [
                paper
                for paper in papers
                if query
                in " ".join(
                    [
                        str(paper.get("title") or ""),
                        " ".join(str(author.get("name", "")) for author in paper["authors"]),
                        " ".join(str(category) for category in paper["categories"]),
                    ]
                ).casefold()
            ]
        if status:
            papers = [
                paper for paper in papers if paper["verification_status"] == status
            ]
        dossier_fields = {
            "missing_local": "local_original",
            "missing_abstract": "abstract_evidence",
            "missing_conclusions": "core_conclusions",
            "missing_archive_relations": "archive_relations",
        }
        if dossier == "complete":
            papers = [paper for paper in papers if paper["dossier_coverage"]["complete"]]
        elif dossier == "needs_evidence":
            papers = [paper for paper in papers if not paper["dossier_coverage"]["complete"]]
        elif dossier in dossier_fields:
            field = dossier_fields[dossier]
            papers = [
                paper for paper in papers if not paper["dossier_coverage"][field]
            ]
        return render_template(
            "evidence/list.html",
            papers=papers,
            total=int(payload["total"]),
            coverage=payload["coverage"],
            query=request.args.get("q", ""),
            status=status,
            dossier=dossier,
        )

    @blueprint.get("/evidence/papers/<paper_id>")
    def evidence_paper_page(paper_id: str) -> str | tuple[str, int]:
        try:
            paper = service.researcher_paper_detail(paper_id)
        except EvidenceQueryNotFound:
            return (
                render_template(
                    "evidence/not_found.html",
                    title="论文未找到",
                    message="该 Evidence 论文不存在或尚未进入已验证目录。",
                ),
                404,
            )
        return render_template("evidence/detail.html", paper=paper)

    @blueprint.get("/api/v1/evidence/papers")
    def papers() -> Response:
        try:
            limit = int(request.args.get("limit", "100"))
            offset = int(request.args.get("offset", "0"))
            include_candidates = request.args.get("include_candidates", "false").lower() == "true"
            return ok(
                service.list_papers(
                    limit=limit, offset=offset, include_candidates=include_candidates
                )
            )
        except (ValueError, TypeError):
            return error("invalid_query", "分页参数无效。", 422)

    @blueprint.get("/api/v1/evidence/papers/<paper_id>")
    def paper_detail(paper_id: str) -> Response:
        try:
            return ok(service.researcher_paper_detail(paper_id))
        except EvidenceQueryNotFound:
            return error("paper_not_found", "论文不存在。", 404)

    @blueprint.get("/api/v1/evidence/documents/<document_sha256>/citations")
    def document_citations(document_sha256: str) -> Response:
        try:
            specs = service.citation_render_specs(document_sha256)
        except ValueError:
            return error("invalid_document_sha256", "文档 content_sha256 无效。", 422)
        return ok({"items": [spec.as_dict() for spec in specs]})

    @blueprint.get("/api/v1/evidence/citations/<citation_id>")
    def citation_detail(citation_id: str) -> Response:
        try:
            return ok(service.citation_detail(citation_id))
        except EvidenceQueryNotFound:
            return error("citation_not_found", "引用不存在。", 404)

    @blueprint.get("/evidence/citations/<citation_id>")
    def citation_page(citation_id: str) -> str | tuple[str, int]:
        """面向研究员的引用上下文页；不再把 JSON API 当作阅读入口。"""

        try:
            citation = service.citation_detail(citation_id)
        except EvidenceQueryNotFound:
            return (
                render_template(
                    "evidence/not_found.html",
                    title="引用未找到",
                    message="该引用不存在或尚未进入已验证证据目录。",
                ),
                404,
            )
        return render_template("evidence/citation.html", citation=citation)

    @blueprint.get("/api/v1/evidence/citation-entries/<ledger_entry_id>")
    def citation_entry_detail(ledger_entry_id: str) -> Response:
        try:
            return ok(service.citation_entry_detail(ledger_entry_id))
        except EvidenceQueryNotFound:
            return error("citation_entry_not_found", "引用账本条目不存在。", 404)

    @blueprint.get("/api/v1/evidence/resources/<resource_id>")
    def resource(resource_id: str) -> Response:
        try:
            item = service.resource(resource_id)
        except EvidenceResourceNotFound:
            return error("resource_not_found", "论文资源不存在。", 404)
        except EvidenceResourceError:
            return error("resource_verification_failed", "论文资源复核失败。", 409)
        response = Response(item.payload, content_type=item.media_type)
        response.headers["Content-Disposition"] = f'inline; filename="{item.download_name}"'
        response.set_etag(hashlib.sha256(item.payload).hexdigest())
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "private, no-cache"
        response.headers["X-Request-ID"] = request_id()
        response.make_conditional(request)
        return response

    @blueprint.get("/evidence/library/<paper_id>.pdf")
    def library_resource(paper_id: str) -> Response:
        try:
            item = service.library_resource(paper_id)
        except EvidenceResourceNotFound:
            return error("library_resource_not_found", "本地论文副本不存在。", 404)
        except EvidenceResourceError:
            return error("library_resource_verification_failed", "本地论文副本哈希复核失败。", 409)
        response = Response(item.payload, content_type=item.media_type)
        response.headers["Content-Disposition"] = f'inline; filename="{item.download_name}"'
        response.set_etag(hashlib.sha256(item.payload).hexdigest())
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "private, no-cache"
        response.headers["X-Request-ID"] = request_id()
        response.make_conditional(request)
        return response

    return blueprint
