"""Archive HTML pages and the versioned HTTP API.

The Web boundary deliberately contains no persistence logic.  It translates
HTTP/session preconditions into the formal ArchiveCatalog and
ArchiveCollaboration services, and translates their outcomes back into the
stable v1 envelope.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Literal
from urllib.parse import quote
from uuid import uuid4

from flask import (
    Blueprint,
    Response,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
)
from markupsafe import Markup
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from quant_hub.archive.catalog import ArchiveCatalog, ArchiveNotFound
from quant_hub.archive.contracts import (
    ActorInput,
    ManualTopicCreateInput,
    ManualTopicUpdateInput,
    TopicInput,
)
from quant_hub.archive.markdown import (
    CitationProjectionIncomplete,
    CitationRenderSpec as ArchiveCitationRenderSpec,
    render_markdown_for_presentation,
)
from quant_hub.archive.source_reader import SourceBoundaryError
from quant_hub.collaboration.service import (
    ArchiveCollaboration,
    CommandOutcome,
    IdempotencyConflict,
)
from quant_hub.evidence.service import EvidenceQueryService
from quant_hub.presentation.supplements import SupplementalResearchDocuments
from quant_hub.presentation.citation_overlays import select_non_overlapping_citations
from quant_hub.research_workspace import (
    ResearchWorkspace,
    WorkspaceCommandOutcome,
    WorkspaceIdempotencyConflict,
)
from quant_hub.research_workspace.service import WorkspaceNotFound
from quant_hub.web.contracts import (
    ApiEnvelope,
    ApiError,
    CommentCreate,
    CommentUpdate,
    ManualTopicCreate,
    ManualTopicDelete,
    ManualTopicUpdate,
    ResearchCompletionDecisionCreate,
    ResearchNodeCommentCreate,
    ResearchNodeCommentDelete,
    ResearchNodeCommentUpdate,
    ResearchNodeUpdate,
    ResearchProjectCreate,
    ResearchTreeSync,
    ResearchUpdateAnnotationCreate,
    ResearchWorkStateEventCreate,
    TopicCreate,
    TopicResearchLinkCreate,
    TopicStateEventCreate,
)
from quant_hub.web.security import WriteSecurityError, csrf_token, require_write_security


web = Blueprint("web", __name__)
api_v1 = Blueprint("api_v1", __name__, url_prefix="/api/v1")

_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$", re.ASCII)
_COMMENT_ETAG = re.compile(
    r'^"comment:(?P<comment_id>cmt_[0-9a-f]{32}):r(?P<revision>[1-9][0-9]*)"$',
    re.ASCII,
)
_TOPIC_ETAG = re.compile(
    r'^"topic:(?P<topic_id>top_[0-9a-f]{32}):r(?P<revision>[1-9][0-9]*)"$',
    re.ASCII,
)
_RESEARCH_NODE_ETAG = re.compile(
    r'^"research-node:(?P<node_id>rnode_[0-9a-f]{32}):r(?P<revision>[1-9][0-9]*)"$',
    re.ASCII,
)
_RESEARCH_NODE_COMMENT_ETAG = re.compile(
    r'^"research-node-comment:(?P<comment_id>wcmt_[0-9a-f]{32}):r(?P<revision>[1-9][0-9]*)"$',
    re.ASCII,
)

# Archive headings come from immutable research Markdown.  Some documents use
# explicit scholarly numbering (``0.1``, ``1.2.1``, ``第 2 部分``), while
# others rely on the reader UI to expose their hierarchy.  The presentation
# layer must not blindly prepend a second, visually unrelated sequence.
_TOC_EXPLICIT_NUMBERING = re.compile(
    r"""^\s*(?:
        \d+(?:\.\d+)*(?:\s|[.．、:：)）])
        |第\s*(?:\d+(?:\.\d+)*|[零〇一二三四五六七八九十百千万两]+)\s*(?:章|节|部分|篇|卷|阶段|步骤|步|条|层)
        |[一二三四五六七八九十百]+[、.．]
        |[（(]\s*(?:\d+|[一二三四五六七八九十百]+)\s*[)）]
        |[IVXLCDM]+[.．、]\s*
        |(?:D|E|Q|GC)\s*\d+(?:\.\d+)*(?:\s|[：:—-])
        |[①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳]
        |(?:机制|步骤|阶段|主线|问题|结论|配置|方案|实验|路径|模块|层级|情形)
          \s*(?:\d+|[一二三四五六七八九十百]+)\s*[：:、.—-]
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def _toc_with_numbering_semantics(nodes: Any) -> list[dict[str, Any]]:
    """Copy TOC nodes and mark whether the source title already numbers itself."""

    if not isinstance(nodes, list):
        return []
    annotated: list[dict[str, Any]] = []
    for raw_node in nodes:
        if not isinstance(raw_node, dict):
            continue
        title = str(raw_node.get("title_text", ""))
        children = _toc_with_numbering_semantics(raw_node.get("children", []))
        annotated.append(
            {
                **raw_node,
                "children": children,
                "numbering_mode": (
                    "source"
                    if _TOC_EXPLICIT_NUMBERING.match(title)
                    else "automatic"
                ),
            }
        )
    return annotated
_RESEARCH_UPDATE_ETAG = re.compile(
    r'^"research-update:(?P<update_id>[0-9a-f]{64}):r(?P<revision>0|[1-9][0-9]*)"$',
    re.ASCII,
)


class CommentDelete(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: ActorInput


class SearchParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    query: str = Field(default="", max_length=300)
    limit: int = Field(default=30, ge=1, le=100)


class ResearchParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    query: str = Field(default="", max_length=300)
    status: Literal["planned", "in_progress", "paused", "completed"] | None = None


class TopicManagementParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    include_retired: bool = False


class ResearchTreeParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    query: str = Field(default="", max_length=300)
    status: Literal[
        "todo", "in_progress", "review", "completed", "archived", "cancelled"
    ] | None = None
    parent_node_id: str | None = Field(
        default=None, pattern=r"^rnode_[0-9a-f]{32}$"
    )
    node_kind: Literal["system", "project", "topic", "subtopic", "document"] | None = None
    node: str | None = Field(default=None, pattern=r"^rnode_[0-9a-f]{32}$")

    @field_validator("status", "parent_node_id", "node_kind", "node", mode="before")
    @classmethod
    def empty_filter_is_absent(cls, value: Any) -> Any:
        return None if value == "" else value


def _catalog() -> ArchiveCatalog:
    return current_app.extensions["archive_catalog"]


def _collaboration() -> ArchiveCollaboration:
    return current_app.extensions["archive_collaboration"]


def _evidence() -> EvidenceQueryService:
    return current_app.extensions["evidence_query"]


def _supplements() -> SupplementalResearchDocuments:
    supplements = current_app.extensions.get("research_supplements")
    if supplements is None:
        supplements = SupplementalResearchDocuments.default()
        current_app.extensions["research_supplements"] = supplements
    return supplements


def _workspace() -> ResearchWorkspace:
    return current_app.extensions["research_workspace"]


def _select_non_overlapping_citations(specs: list[Any]) -> list[Any]:
    """选择可同时投影的 occurrence，避免一个坏重叠关闭整篇引用。"""
    return select_non_overlapping_citations(specs)


def _request_id() -> str:
    candidate = request.headers.get("X-Request-ID", "")
    return candidate if _REQUEST_ID.fullmatch(candidate) else str(uuid4())


def _json_etag(data: object) -> str:
    payload = json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256-" + hashlib.sha256(payload).hexdigest()


def _response(
    *,
    data: dict[str, Any] | None = None,
    error: ApiError | None = None,
    status: int = 200,
    revision: int | None = None,
    etag: str | None = None,
) -> Response:
    meta: dict[str, Any] = {"request_id": _request_id()}
    if revision is not None:
        meta["revision"] = revision
    envelope = ApiEnvelope(data=data, error=error, meta=meta)
    response = jsonify(envelope.model_dump(mode="json", exclude_none=True))
    response.status_code = status
    if etag is not None:
        response.set_etag(etag)
        if request.method in {"GET", "HEAD"}:
            response.make_conditional(request)
    return response


def api_error(
    code: str,
    message: str,
    status: int,
    details: dict[str, Any] | list[Any] | None = None,
) -> Response:
    return _response(
        error=ApiError(code=code, message=message, details=details),
        status=status,
    )


def _validation_error(error: ValidationError, message: str) -> Response:
    return api_error(
        "validation_error",
        message,
        422,
        error.errors(
            include_url=False,
            include_context=False,
            include_input=False,
        ),
    )


def _model_from_json(model: type[BaseModel], message: str) -> BaseModel | Response:
    try:
        return model.model_validate(request.get_json(silent=True) or {})
    except ValidationError as error:
        return _validation_error(error, message)


def _command_response(outcome: CommandOutcome) -> Response:
    revision: int | None = None
    etag: str | None = None
    if outcome.data is not None and isinstance(outcome.data.get("revision"), int):
        revision = int(outcome.data["revision"])
        comment_id = outcome.data.get("comment_id")
        if isinstance(comment_id, str):
            etag = f"comment:{comment_id}:r{revision}"
        topic_id = outcome.data.get("topic_id")
        if isinstance(topic_id, str):
            etag = f"topic:{topic_id}:r{revision}"
        update_id = outcome.data.get("update_id")
        if isinstance(update_id, str):
            etag = f"research-update:{update_id}:r{revision}"
    if outcome.ok:
        response = _response(
            data=outcome.data or {},
            status=outcome.status,
            revision=revision,
            etag=etag,
        )
    else:
        response = api_error(
            outcome.error_code or "command_rejected",
            outcome.error_message or "Command 未被接受。",
            outcome.status,
        )
    response.headers["Idempotency-Replayed"] = (
        "true" if outcome.replayed else "false"
    )
    return response


def _idempotency_conflict(_error: IdempotencyConflict) -> Response:
    return api_error(
        "idempotency_conflict",
        "同一 Idempotency-Key 已绑定其他 command 或载荷。",
        409,
    )


def _workspace_command_response(outcome: WorkspaceCommandOutcome) -> Response:
    revision: int | None = None
    etag: str | None = None
    if outcome.data is not None and isinstance(outcome.data.get("revision"), int):
        revision = int(outcome.data["revision"])
        node_id = outcome.data.get("node_id")
        comment_id = outcome.data.get("comment_id")
        if isinstance(comment_id, str):
            etag = f"research-node-comment:{comment_id}:r{revision}"
        elif isinstance(node_id, str):
            etag = f"research-node:{node_id}:r{revision}"
    if outcome.ok:
        response = _response(
            data=outcome.data or {},
            status=outcome.status,
            revision=revision,
            etag=etag,
        )
    else:
        response = api_error(
            outcome.error_code or "workspace_command_rejected",
            outcome.error_message or "研究工作区命令未被接受。",
            outcome.status,
        )
    response.headers["Idempotency-Replayed"] = (
        "true" if outcome.replayed else "false"
    )
    return response


def _workspace_idempotency_conflict(
    _error: WorkspaceIdempotencyConflict,
) -> Response:
    return api_error(
        "idempotency_conflict",
        "同一 Idempotency-Key 已绑定其他研究工作区命令或载荷。",
        409,
    )


def _reject_unexpected_precondition() -> Response | None:
    if request.headers.get("If-Match") is None:
        return None
    return api_error(
        "unexpected_precondition",
        "Append-only command 不接受 If-Match；幂等由 Idempotency-Key 保证。",
        400,
    )


def _expected_revision(comment_id: str) -> int | Response:
    values = request.headers.getlist("If-Match")
    if len(values) != 1 or not values[0].strip():
        return api_error(
            "precondition_required",
            "修改或删除评论必须发送服务端返回的 If-Match ETag。",
            428,
        )
    value = values[0].strip()
    match = _COMMENT_ETAG.fullmatch(value)
    if match is None:
        return api_error(
            "invalid_precondition",
            "If-Match 必须是服务端返回的单一强 ETag。",
            400,
        )
    if match.group("comment_id") != comment_id:
        return api_error(
            "precondition_target_mismatch",
            "If-Match 不属于当前评论。",
            400,
        )
    return int(match.group("revision"))


def _expected_topic_revision(topic_id: str) -> int | Response:
    values = request.headers.getlist("If-Match")
    if len(values) != 1 or not values[0].strip():
        return api_error(
            "precondition_required",
            "修改或删除人工研究议题必须发送服务端返回的 If-Match ETag。",
            428,
        )
    value = values[0].strip()
    match = _TOPIC_ETAG.fullmatch(value)
    if match is None:
        return api_error(
            "invalid_precondition",
            "If-Match 必须是服务端返回的单一强 Topic ETag。",
            400,
        )
    if match.group("topic_id") != topic_id:
        return api_error(
            "precondition_target_mismatch",
            "If-Match 不属于当前研究议题。",
            400,
        )
    return int(match.group("revision"))


def _expected_research_node_revision(node_id: str) -> int | Response:
    values = request.headers.getlist("If-Match")
    if len(values) != 1 or not values[0].strip():
        return api_error(
            "precondition_required",
            "修改研究节点必须发送服务端返回的 If-Match ETag。",
            428,
        )
    match = _RESEARCH_NODE_ETAG.fullmatch(values[0].strip())
    if match is None:
        return api_error(
            "invalid_precondition",
            "If-Match 必须是服务端返回的单一强 Research Node ETag。",
            400,
        )
    if match.group("node_id") != node_id:
        return api_error(
            "precondition_target_mismatch",
            "If-Match 不属于当前研究节点。",
            400,
        )
    return int(match.group("revision"))


def _expected_research_node_comment_revision(comment_id: str) -> int | Response:
    values = request.headers.getlist("If-Match")
    if len(values) != 1 or not values[0].strip():
        return api_error(
            "precondition_required",
            "修改或删除节点评论必须发送服务端返回的 If-Match ETag。",
            428,
        )
    match = _RESEARCH_NODE_COMMENT_ETAG.fullmatch(values[0].strip())
    if match is None:
        return api_error(
            "invalid_precondition",
            "If-Match 必须是服务端返回的单一强节点评论 ETag。",
            400,
        )
    if match.group("comment_id") != comment_id:
        return api_error(
            "precondition_target_mismatch",
            "If-Match 不属于当前节点评论。",
            400,
        )
    return int(match.group("revision"))


def _expected_research_update_revision(update_id: str) -> int | Response:
    values = request.headers.getlist("If-Match")
    if len(values) != 1 or not values[0].strip():
        return api_error(
            "precondition_required",
            "补充更新说明必须发送服务端返回的 If-Match ETag。",
            428,
        )
    value = values[0].strip()
    match = _RESEARCH_UPDATE_ETAG.fullmatch(value)
    if match is None:
        return api_error(
            "invalid_precondition",
            "If-Match 必须是服务端返回的单一强研究更新 ETag。",
            400,
        )
    if match.group("update_id") != update_id:
        return api_error(
            "precondition_target_mismatch",
            "If-Match 不属于当前研究更新记录。",
            400,
        )
    return int(match.group("revision"))


def _query_model(model: type[BaseModel], aliases: dict[str, str] | None = None) -> BaseModel | Response:
    values: dict[str, Any] = {}
    aliases = aliases or {}
    allowed = set(model.model_fields)
    seen: set[str] = set()
    for key in request.args:
        normalized = aliases.get(key, key)
        if (
            normalized not in allowed
            or normalized in seen
            or len(request.args.getlist(key)) != 1
        ):
            return api_error(
                "validation_error",
                "查询参数无效。",
                422,
                {"parameter": key},
            )
        seen.add(normalized)
        values[normalized] = request.args.get(key)
    try:
        return model.model_validate(values)
    except ValidationError as error:
        return _validation_error(error, "查询参数无效。")


@api_v1.before_request
def enforce_write_boundary() -> Response | None:
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    try:
        key = require_write_security(
            request,
            current_app.extensions["trusted_origins"],
        )
    except WriteSecurityError as error:
        return api_error(error.code, str(error), error.status)
    # Parsing occurs exactly once at this boundary.  Command routes consume the
    # value without reinterpreting request headers.
    request.environ["quant_hub.idempotency_key"] = key
    return None


@web.get("/")
def home_page() -> str | Response:
    parameters = _query_model(ResearchTreeParameters, {"q": "query"})
    if isinstance(parameters, Response):
        return render_template(
            "error.html",
            title="查询参数无效",
            message="研究树的搜索或筛选参数无法识别。",
        ), 422
    assert isinstance(parameters, ResearchTreeParameters)
    workspace = _workspace()
    if workspace.root.is_dir():
        workspace.sync_if_changed()
    tree = workspace.tree(
        query=parameters.query,
        status=parameters.status,
        parent_node_id=parameters.parent_node_id,
        node_kind=parameters.node_kind,
    )
    selected = None
    if parameters.node is not None:
        try:
            selected = workspace.get_node(parameters.node)
        except WorkspaceNotFound:
            return render_template(
                "error.html",
                title="研究节点不存在",
                message="所选研究节点不存在或已经无法访问。",
            ), 404
    research_ids_by_slug = {
        str(item["canonical_slug"]): str(item["research_id"])
        for item in _catalog().list_research()
    }
    recent_updates = _supplements().link_workspace_updates(
        workspace.recent_updates(limit=6),
        research_ids_by_slug,
    )
    collaboration = _collaboration()
    managed_topics = collaboration.list_topics_for_management()
    manual_topics = [
        item
        for item in managed_topics
        if item["is_manual"] and not item["retired"]
    ]
    dashboard = {
        "active": [
            item for item in manual_topics if item["manual_state"] == "planned"
        ],
        "paused": [
            item for item in manual_topics if item["manual_state"] == "paused"
        ],
    }
    return render_template(
        "home.html",
        csrf_token=csrf_token(),
        workspace=tree,
        selected_node=selected,
        recent_updates=recent_updates,
        dashboard=dashboard,
        project_options=workspace.project_options(),
        parameters=parameters,
    )


@web.get("/research-updates")
def research_updates_page() -> str:
    updates = _collaboration().list_research_updates()
    return render_template(
        "research_updates.html",
        csrf_token=csrf_token(),
        updates=updates,
    )


def _with_research_supplements(page: dict[str, Any]) -> dict[str, Any]:
    """Attach reviewed experiment syntheses without mutating Archive releases."""

    supplements = _supplements().documents_for(
        str(page["canonical_slug"]), str(page["research_id"])
    )
    if not supplements:
        return page
    group_title = str(supplements[0]["group_title"])
    group = {
        "key": "empirical-results",
        "title": group_title,
        "documents": supplements,
    }
    groups = list(page["document_groups"])
    reference_index = next(
        (
            index
            for index, item in enumerate(groups)
            if str(item.get("key")) == "reference"
        ),
        len(groups),
    )
    groups.insert(reference_index, group)
    documents = [*page["documents"], *supplements]
    return {
        **page,
        "documents": documents,
        "documents_by_key": {
            **page.get("documents_by_key", {}),
            **{str(item["document_key"]): item for item in supplements},
        },
        "document_groups": groups,
    }


@web.get("/research/<research_id>")
def research_page(research_id: str) -> str | tuple[str, int]:
    catalog = _catalog()
    try:
        page = _with_research_supplements(
            catalog.research_page(research_id, include_rendered=False)
        )
        featured_documents: list[dict[str, Any]] = []
        featured_ids: set[str] = set()
        for kind, key, label in (
            ("overview", "landing_document", "专题概述"),
            ("review", "review_document", "综合综述"),
        ):
            entry = page.get(key)
            if not isinstance(entry, dict):
                continue
            document_id = str(entry["document_id"])
            if document_id in featured_ids:
                continue
            document_page = catalog.research_document_page(
                research_id, document_id
            )
            full_document = document_page["document"]
            featured_documents.append(
                {
                    **_reader_page_document(
                        catalog, research_id, document_page
                    ),
                    "featured_kind": kind,
                    "featured_label": label,
                }
            )
            featured_ids.add(document_id)
    except ArchiveNotFound:
        return render_template(
            "error.html",
            title="研究不存在",
            message="未找到已发布的研究页面。",
        ), 404

    linked_document_groups = []
    for group in page["document_groups"]:
        linked_documents = [
            document
            for document in group["documents"]
            if str(document["document_id"]) not in featured_ids
        ]
        if linked_documents:
            linked_document_groups.append({**group, "documents": linked_documents})
    page = {
        **page,
        "featured_documents": featured_documents,
        "linked_document_groups": linked_document_groups,
        "linked_document_count": sum(
            len(group["documents"]) for group in linked_document_groups
        ),
    }

    return render_template(
        "research.html",
        csrf_token=csrf_token(),
        research=page,
        comments=_collaboration().list_comments(research_id),
    )


def _reader_document(
    catalog: ArchiveCatalog,
    research_id: str,
    document: dict[str, Any],
    *,
    source_bytes_override: bytes | None = None,
    source_byte_offset: int = 0,
    heading_anchor_ids: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """为一个独立文档建立安全展示与 Evidence 交互投影。"""

    # This is the sole trust elevation in the UI. Both the persisted Archive
    # projection and the optional citation projection are produced by the same
    # deterministic sanitizer; Evidence never supplies HTML.
    link_index = catalog.archive_link_index()
    rendered_html = str(document["rendered_html"])
    projection_error: str | None = None
    citation_count = 0
    unprojected_count = 0
    unresolved_links: tuple[str, ...] = ()
    if source_bytes_override is None:
        source_bytes, _slug = catalog.source_document(
            research_id, str(document["document_id"])
        )
    else:
        source_bytes = source_bytes_override
    link_resolver = lambda reference, source_path=str(
        document["source_path"]
    ): catalog.resolve_archive_link(
        source_path,
        reference,
        index=link_index,
    )
    heading_title = lambda source_title, source_path=str(
        document["source_path"]
    ): catalog.presentation.heading_title(source_title, source_path)
    pipeline_overview_url = (
        f"/research/{quote(research_id, safe='')}#q2-training-pipeline"
        if document.get("document_key") in {"research-overview", "research-backbone"}
        else None
    )
    try:
        evidence_specs = _evidence().citation_render_specs(
            str(document["content_sha256"])
        )
        # Path/page-only ledger occurrences remain queryable evidence, but they
        # have no source byte position and therefore cannot participate in a
        # chapter render.  Filter before any integer/range operation so one
        # non-positional row cannot disable the exact occurrences beside it.
        positional_evidence_specs = [
            item
            for item in evidence_specs
            if item.byte_start is not None and item.byte_end is not None
        ]
        source_byte_end = source_byte_offset + len(source_bytes)
        crossing_specs = [
            item
            for item in positional_evidence_specs
            if int(item.byte_start) < source_byte_end
            and int(item.byte_end) > source_byte_offset
            and not (
                source_byte_offset <= int(item.byte_start)
                and int(item.byte_end) <= source_byte_end
            )
        ]
        if crossing_specs:
            raise ValueError("citation span crosses a sealed chapter boundary")
        scoped_specs = [
            item
            for item in positional_evidence_specs
            if source_byte_offset <= int(item.byte_start)
            and int(item.byte_end) <= source_byte_end
        ]
        positional_specs = _select_non_overlapping_citations(scoped_specs)
        unprojected_count = len(scoped_specs) - len(positional_specs)
        archive_specs = tuple(
            ArchiveCitationRenderSpec(
                citation_id=item.citation_id,
                byte_start=int(item.byte_start) - source_byte_offset,
                byte_end=int(item.byte_end) - source_byte_offset,
                raw_marker_sha256=hashlib.sha256(
                    item.raw_marker_text.encode("utf-8")
                ).hexdigest(),
                resolution_state=item.resolution_state,
            )
            for item in positional_specs
        )

        def render_with(specs: tuple[ArchiveCitationRenderSpec, ...]):
            return render_markdown_for_presentation(
                source_bytes,
                specs,
                heading_title=heading_title,
                link_resolver=link_resolver,
                visible_text=catalog.presentation.visible_text,
                link_label_title=catalog.presentation.internal_link_label,
                heading_anchor_ids=heading_anchor_ids,
                pipeline_overview_url=pipeline_overview_url,
            )

        try:
            rendered = render_with(archive_specs)
        except CitationProjectionIncomplete as incomplete:
            rejected = frozenset(incomplete.citation_ids)
            safe_specs = tuple(
                item for item in archive_specs if item.citation_id not in rejected
            )
            unprojected_count += len(archive_specs) - len(safe_specs)
            current_app.logger.info(
                "kept %s citation occurrences in the evidence ledger because "
                "their Markdown AST positions are not uniquely interactive: %s",
                len(rejected),
                document["document_id"],
            )
            rendered = render_with(safe_specs)
        rendered_html = rendered.rendered_html
        citation_count = len(rendered.citation_ids)
        unresolved_links = rendered.unresolved_references
    except Exception:
        current_app.logger.exception(
            "citation projection failed for document %s",
            document["document_id"],
        )
        try:
            presentation_only = render_markdown_for_presentation(
                source_bytes,
                (),
                heading_title=heading_title,
                link_resolver=link_resolver,
                visible_text=catalog.presentation.visible_text,
                link_label_title=catalog.presentation.internal_link_label,
                heading_anchor_ids=heading_anchor_ids,
                pipeline_overview_url=pipeline_overview_url,
            )
        except Exception:
            current_app.logger.exception(
                "presentation projection failed for document %s",
                document["document_id"],
            )
            projection_error = (
                "该文档的读者版导航与论文证据投影均未通过完整性校验；"
                "正文仍按 Archive 的已验证基础投影显示。"
            )
        else:
            rendered_html = presentation_only.rendered_html
            unresolved_links = presentation_only.unresolved_references
            projection_error = (
                "该文档的论文证据投影未通过完整性校验；专业标题与内部导航"
                "仍正常显示，正文引用入口已关闭。"
            )
    return {
        **document,
        "toc": _toc_with_numbering_semantics(document.get("toc", [])),
        "rendered_html": Markup(rendered_html),
        "citation_count": citation_count,
        "unprojected_citation_count": unprojected_count,
        "unresolved_internal_links": unresolved_links,
        "citation_projection_error": projection_error,
    }


def _reader_page_document(
    catalog: ArchiveCatalog,
    research_id: str,
    page: dict[str, Any],
) -> dict[str, Any]:
    document = page["document"]
    chapter = page.get("chapter")
    if not isinstance(chapter, dict):
        return _reader_document(catalog, research_id, document)
    return _reader_document(
        catalog,
        research_id,
        document,
        source_bytes_override=page["chapter_source_bytes"],
        source_byte_offset=int(chapter["absolute_start"]),
        heading_anchor_ids=tuple(chapter["heading_anchor_ids"]),
    )


@web.get("/research/<research_id>/documents/<document_id>")
def research_document_page(
    research_id: str, document_id: str
) -> str | tuple[str, int]:
    catalog = _catalog()
    try:
        page = catalog.research_document_page(research_id, document_id)
    except ArchiveNotFound:
        return render_template(
            "error.html",
            title="研究文档不存在",
            message="未找到当前已发布专题中的研究文档。",
        ), 404
    if page["document"].get("document_key") == "training-pipeline":
        return redirect(
            f"/research/{quote(research_id, safe='')}#q2-training-pipeline",
            code=308,
        )
    document = _reader_page_document(catalog, research_id, page)
    return render_template(
        "research_document.html",
        csrf_token=csrf_token(),
        research={**page, "document": document},
        document=document,
    )


@web.get("/research/<research_id>/supplements/<supplement_id>")
def research_supplement_page(
    research_id: str, supplement_id: str
) -> str | tuple[str, int]:
    catalog = _catalog()
    try:
        page = _with_research_supplements(
            catalog.research_page(research_id, include_rendered=False)
        )
    except ArchiveNotFound:
        return render_template(
            "error.html",
            title="研究专题不存在",
            message="未找到当前已发布的研究专题。",
        ), 404
    document = _supplements().document_for(
        str(page["canonical_slug"]), research_id, supplement_id
    )
    if document is None:
        return render_template(
            "error.html",
            title="实证研究页面不存在",
            message="未找到与当前专题绑定的实证研究页面。",
        ), 404
    siblings = _supplements().documents_for(
        str(page["canonical_slug"]), research_id
    )
    selected_index = next(
        index
        for index, item in enumerate(siblings)
        if str(item["supplement_id"]) == supplement_id
    )
    document["previous_document"] = (
        siblings[selected_index - 1] if selected_index > 0 else None
    )
    document["next_document"] = (
        siblings[selected_index + 1]
        if selected_index + 1 < len(siblings)
        else None
    )
    document["rendered_html"] = Markup(str(document["rendered_html"]))
    return render_template(
        "research_document.html",
        csrf_token=csrf_token(),
        research={**page, "document": document},
        document=document,
    )


@web.get("/research/<research_id>/supplements/<supplement_id>/source")
def research_supplement_source(
    research_id: str, supplement_id: str
) -> Response | tuple[str, int]:
    try:
        page = _catalog().research_page(research_id, include_rendered=False)
    except ArchiveNotFound:
        return render_template(
            "error.html",
            title="研究专题不存在",
            message="未找到当前已发布的研究专题。",
        ), 404
    source = _supplements().source_bytes(
        str(page["canonical_slug"]), supplement_id
    )
    if source is None:
        return render_template(
            "error.html",
            title="实证研究页面不存在",
            message="未找到与当前专题绑定的实证研究页面。",
        ), 404
    response = Response(source, content_type="text/markdown; charset=utf-8")
    response.headers["Content-Disposition"] = (
        f'attachment; filename="{supplement_id}.md"'
    )
    response.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
    response.set_etag(hashlib.sha256(source).hexdigest(), weak=False)
    return response


@web.get(
    "/research/<research_id>/documents/<document_id>/chapters/<chapter_slug>"
)
def research_chapter_page(
    research_id: str, document_id: str, chapter_slug: str
) -> str | tuple[str, int]:
    catalog = _catalog()
    try:
        research = catalog.research_page(research_id, include_rendered=False)
        selected_document = next(
            (
                item
                for item in research["documents"]
                if str(item["document_id"]) == document_id
            ),
            None,
        )
    except ArchiveNotFound:
        selected_document = None
    if (
        selected_document is not None
        and selected_document.get("document_key") == "research-backbone"
        and chapter_slug == "heading-f01e570f71c1e903"
    ):
        return redirect(
            f"/research/{quote(research_id, safe='')}#q2-training-pipeline",
            code=308,
        )
    if selected_document is not None and selected_document.get("document_key") == "training-pipeline":
        fragment = {
            "heading-45e510a096edf291": "q2-backward",
            "heading-2e27ba24dedce8dc": "q2-temperature-triangle",
            "heading-4af78d6e4a626527": "q2-cross-step-coverage",
        }.get(chapter_slug, "q2-training-pipeline")
        return redirect(
            f"/research/{quote(research_id, safe='')}#{fragment}",
            code=308,
        )
    try:
        page = catalog.research_chapter_page(
            research_id, document_id, chapter_slug
        )
    except ArchiveNotFound:
        try:
            legacy_target = catalog.legacy_chapter_redirect_url(
                research_id, document_id, chapter_slug
            )
        except ArchiveNotFound:
            legacy_target = None
        if legacy_target is not None:
            return redirect(legacy_target, code=308)
        return render_template(
            "error.html",
            title="研究章节不存在",
            message="未找到当前发布版本中的语义章节。",
        ), 404
    document = _reader_page_document(catalog, research_id, page)
    return render_template(
        "research_document.html",
        csrf_token=csrf_token(),
        research={**page, "document": document},
        document=document,
        chapter=page["chapter"],
    )


@api_v1.get("/session")
def session_contract() -> Response:
    data = {
        "csrf_token": csrf_token(),
        "actors": [
            {"actor_kind": "zhang_zhengze", "display_name": "张正泽"},
            {"actor_kind": "song_dingkun", "display_name": "宋定坤"},
            {"actor_kind": "other", "display_name": None},
        ],
    }
    response = _response(data=data)
    response.headers["Cache-Control"] = "no-store"
    return response


@api_v1.get("/research-tree")
def research_tree() -> Response:
    parameters = _query_model(ResearchTreeParameters, {"q": "query"})
    if isinstance(parameters, Response):
        return parameters
    assert isinstance(parameters, ResearchTreeParameters)
    if _workspace().root.is_dir():
        _workspace().sync_if_changed()
    data = _workspace().tree(
        query=parameters.query,
        status=parameters.status,
        parent_node_id=parameters.parent_node_id,
        node_kind=parameters.node_kind,
    )
    return _response(data=data, etag=_json_etag(data))


@api_v1.post("/research-tree/sync")
def sync_research_tree() -> Response:
    unexpected = _reject_unexpected_precondition()
    if unexpected is not None:
        return unexpected
    payload = _model_from_json(ResearchTreeSync, "同步请求数据无效。")
    if isinstance(payload, Response):
        return payload
    try:
        outcome = _workspace().sync_command(
            idempotency_key=str(request.environ["quant_hub.idempotency_key"])
        )
    except WorkspaceIdempotencyConflict as error:
        return _workspace_idempotency_conflict(error)
    return _workspace_command_response(outcome)


@api_v1.post("/research-projects")
def create_research_project() -> Response:
    unexpected = _reject_unexpected_precondition()
    if unexpected is not None:
        return unexpected
    payload = _model_from_json(
        ResearchProjectCreate,
        "新增研究专项数据无效。",
    )
    if isinstance(payload, Response):
        return payload
    assert isinstance(payload, ResearchProjectCreate)
    try:
        outcome = _workspace().create_project(
            title=payload.title,
            description=payload.description,
            research_question=payload.research_question,
            research_content=payload.research_content,
            lifecycle_status=payload.lifecycle_status,
            status_note=payload.status_note,
            actor=payload.actor,
            idempotency_key=str(request.environ["quant_hub.idempotency_key"]),
        )
    except WorkspaceIdempotencyConflict as error:
        return _workspace_idempotency_conflict(error)
    return _workspace_command_response(outcome)


@api_v1.get("/research-nodes/<node_id>")
def research_node_detail(node_id: str) -> Response:
    try:
        node = _workspace().get_node(node_id)
    except WorkspaceNotFound:
        return api_error("node_not_found", "研究节点不存在。", 404)
    return _response(
        data={"node": node},
        revision=int(node["revision"]),
        etag=f"research-node:{node_id}:r{node['revision']}",
    )


@api_v1.patch("/research-nodes/<node_id>")
def update_research_node(node_id: str) -> Response:
    expected = _expected_research_node_revision(node_id)
    if isinstance(expected, Response):
        return expected
    payload = _model_from_json(ResearchNodeUpdate, "研究节点修改数据无效。")
    if isinstance(payload, Response):
        return payload
    assert isinstance(payload, ResearchNodeUpdate)
    changes = payload.model_dump(
        mode="json",
        exclude={"actor"},
        exclude_unset=True,
    )
    try:
        outcome = _workspace().update_node(
            node_id,
            changes,
            payload.actor,
            expected_revision=expected,
            idempotency_key=str(request.environ["quant_hub.idempotency_key"]),
        )
    except WorkspaceIdempotencyConflict as error:
        return _workspace_idempotency_conflict(error)
    return _workspace_command_response(outcome)


@api_v1.get("/research-nodes/<node_id>/comments")
def research_node_comments(node_id: str) -> Response:
    try:
        _workspace().get_node(node_id)
    except WorkspaceNotFound:
        return api_error("node_not_found", "研究节点不存在。", 404)
    comments = _workspace().list_comments(node_id)
    for item in comments:
        item["etag"] = (
            f'"research-node-comment:{item["comment_id"]}:r{item["revision"]}"'
        )
    return _response(data={"comments": comments}, etag=_json_etag(comments))


@api_v1.post("/research-nodes/<node_id>/comments")
def create_research_node_comment(node_id: str) -> Response:
    unexpected = _reject_unexpected_precondition()
    if unexpected is not None:
        return unexpected
    payload = _model_from_json(
        ResearchNodeCommentCreate, "研究节点评论数据无效。"
    )
    if isinstance(payload, Response):
        return payload
    assert isinstance(payload, ResearchNodeCommentCreate)
    try:
        outcome = _workspace().create_comment(
            node_id,
            payload.actor,
            payload.content,
            idempotency_key=str(request.environ["quant_hub.idempotency_key"]),
        )
    except WorkspaceIdempotencyConflict as error:
        return _workspace_idempotency_conflict(error)
    return _workspace_command_response(outcome)


@api_v1.patch("/research-node-comments/<comment_id>")
def update_research_node_comment(comment_id: str) -> Response:
    expected = _expected_research_node_comment_revision(comment_id)
    if isinstance(expected, Response):
        return expected
    payload = _model_from_json(
        ResearchNodeCommentUpdate, "研究节点评论修改数据无效。"
    )
    if isinstance(payload, Response):
        return payload
    assert isinstance(payload, ResearchNodeCommentUpdate)
    try:
        outcome = _workspace().change_comment(
            comment_id,
            payload.actor,
            body=payload.content,
            expected_revision=expected,
            idempotency_key=str(request.environ["quant_hub.idempotency_key"]),
            delete=False,
        )
    except WorkspaceIdempotencyConflict as error:
        return _workspace_idempotency_conflict(error)
    return _workspace_command_response(outcome)


@api_v1.delete("/research-node-comments/<comment_id>")
def delete_research_node_comment(comment_id: str) -> Response:
    expected = _expected_research_node_comment_revision(comment_id)
    if isinstance(expected, Response):
        return expected
    payload = _model_from_json(
        ResearchNodeCommentDelete, "研究节点评论删除数据无效。"
    )
    if isinstance(payload, Response):
        return payload
    assert isinstance(payload, ResearchNodeCommentDelete)
    try:
        outcome = _workspace().change_comment(
            comment_id,
            payload.actor,
            body=None,
            expected_revision=expected,
            idempotency_key=str(request.environ["quant_hub.idempotency_key"]),
            delete=True,
        )
    except WorkspaceIdempotencyConflict as error:
        return _workspace_idempotency_conflict(error)
    return _workspace_command_response(outcome)


@api_v1.get("/dashboard")
def dashboard() -> Response:
    topics = _collaboration().dashboard()
    return _response(data={"topics": topics}, etag=_json_etag(topics))


@api_v1.get("/research-updates")
def research_updates() -> Response:
    items = _collaboration().list_research_updates()
    for item in items:
        item["etag"] = (
            f'"research-update:{item["update_id"]}:r{item["annotation_revision"]}"'
        )
    return _response(data={"updates": items}, etag=_json_etag(items))


@api_v1.get("/topics")
def topics() -> Response:
    items = _collaboration().dashboard()
    return _response(data={"topics": items}, etag=_json_etag(items))


@api_v1.get("/dashboard-topics")
def dashboard_topics() -> Response:
    parameters = _query_model(TopicManagementParameters)
    if isinstance(parameters, Response):
        return parameters
    assert isinstance(parameters, TopicManagementParameters)
    items = _collaboration().list_topics_for_management(
        include_retired=parameters.include_retired
    )
    return _response(data={"topics": items}, etag=_json_etag(items))


@api_v1.get("/dashboard-topics/<topic_id>")
def dashboard_topic_detail(topic_id: str) -> Response:
    parameters = _query_model(TopicManagementParameters)
    if isinstance(parameters, Response):
        return parameters
    assert isinstance(parameters, TopicManagementParameters)
    item = _collaboration().get_topic_for_management(
        topic_id,
        include_retired=parameters.include_retired,
    )
    if item is None:
        return api_error("topic_not_found", "研究议题不存在或已经删除。", 404)
    return _response(data={"topic": item}, etag=str(item["etag"]))


@api_v1.post("/dashboard-topics")
def create_dashboard_topic() -> Response:
    precondition = _reject_unexpected_precondition()
    if precondition is not None:
        return precondition
    payload = _model_from_json(ManualTopicCreate, "人工研究议题数据无效。")
    if isinstance(payload, Response):
        return payload
    assert isinstance(payload, ManualTopicCreate)
    topic = ManualTopicCreateInput(
        title=payload.title,
        state=payload.state,
        note=payload.note,
        parent_topic_id=payload.parent_topic_id,
        manual_order=payload.manual_order,
    )
    try:
        outcome = _collaboration().create_manual_topic(
            topic,
            payload.actor,
            idempotency_key=str(request.environ["quant_hub.idempotency_key"]),
        )
    except IdempotencyConflict as error:
        return _idempotency_conflict(error)
    return _command_response(outcome)


@api_v1.patch("/dashboard-topics/<topic_id>")
def update_dashboard_topic(topic_id: str) -> Response:
    expected = _expected_topic_revision(topic_id)
    if isinstance(expected, Response):
        return expected
    payload = _model_from_json(ManualTopicUpdate, "人工研究议题修改数据无效。")
    if isinstance(payload, Response):
        return payload
    assert isinstance(payload, ManualTopicUpdate)
    changes = ManualTopicUpdateInput.model_validate(
        payload.model_dump(exclude={"actor"}, exclude_unset=True)
    )
    try:
        outcome = _collaboration().update_manual_topic(
            topic_id,
            changes,
            payload.actor,
            expected_revision=expected,
            idempotency_key=str(request.environ["quant_hub.idempotency_key"]),
        )
    except IdempotencyConflict as error:
        return _idempotency_conflict(error)
    return _command_response(outcome)


@api_v1.delete("/dashboard-topics/<topic_id>")
def delete_dashboard_topic(topic_id: str) -> Response:
    expected = _expected_topic_revision(topic_id)
    if isinstance(expected, Response):
        return expected
    payload = _model_from_json(ManualTopicDelete, "人工研究议题操作者无效。")
    if isinstance(payload, Response):
        return payload
    assert isinstance(payload, ManualTopicDelete)
    try:
        outcome = _collaboration().retire_manual_topic(
            topic_id,
            payload.actor,
            expected_revision=expected,
            idempotency_key=str(request.environ["quant_hub.idempotency_key"]),
        )
    except IdempotencyConflict as error:
        return _idempotency_conflict(error)
    return _command_response(outcome)


@api_v1.post("/topics")
def create_topic() -> Response:
    precondition = _reject_unexpected_precondition()
    if precondition is not None:
        return precondition
    payload = _model_from_json(TopicCreate, "Topic 数据无效。")
    if isinstance(payload, Response):
        return payload
    assert isinstance(payload, TopicCreate)
    try:
        outcome = _collaboration().create_topic(
            TopicInput(
                topic_key=payload.topic_key,
                title=payload.title,
                manual_order=payload.manual_order,
            ),
            payload.actor,
            idempotency_key=str(request.environ["quant_hub.idempotency_key"]),
        )
    except IdempotencyConflict as error:
        return _idempotency_conflict(error)
    return _command_response(outcome)


@api_v1.post("/topics/<topic_id>/research-links")
def link_topic_research(topic_id: str) -> Response:
    precondition = _reject_unexpected_precondition()
    if precondition is not None:
        return precondition
    payload = _model_from_json(TopicResearchLinkCreate, "Topic 研究关联数据无效。")
    if isinstance(payload, Response):
        return payload
    assert isinstance(payload, TopicResearchLinkCreate)
    try:
        outcome = _collaboration().link_topic_research(
            topic_id,
            payload.research_id,
            payload.actor,
            link_kind=payload.link_kind,
            dashboard_primary=payload.dashboard_primary,
            display_rank=payload.display_rank,
            provenance_urn=payload.provenance_urn,
            idempotency_key=str(request.environ["quant_hub.idempotency_key"]),
        )
    except IdempotencyConflict as error:
        return _idempotency_conflict(error)
    return _command_response(outcome)


@api_v1.post("/topics/<topic_id>/state-events")
def create_topic_state_event(topic_id: str) -> Response:
    precondition = _reject_unexpected_precondition()
    if precondition is not None:
        return precondition
    payload = _model_from_json(TopicStateEventCreate, "Topic 状态事件数据无效。")
    if isinstance(payload, Response):
        return payload
    assert isinstance(payload, TopicStateEventCreate)
    try:
        outcome = _collaboration().set_topic_state(
            topic_id,
            payload.state,
            payload.note,
            payload.actor,
            idempotency_key=str(request.environ["quant_hub.idempotency_key"]),
        )
    except IdempotencyConflict as error:
        return _idempotency_conflict(error)
    return _command_response(outcome)


@api_v1.post("/research/<research_id>/work-state-events")
def create_research_work_state_event(research_id: str) -> Response:
    precondition = _reject_unexpected_precondition()
    if precondition is not None:
        return precondition
    payload = _model_from_json(
        ResearchWorkStateEventCreate,
        "研究工作状态事件数据无效。",
    )
    if isinstance(payload, Response):
        return payload
    assert isinstance(payload, ResearchWorkStateEventCreate)
    try:
        outcome = _collaboration().set_work_state(
            research_id,
            payload.state,
            payload.note,
            payload.actor,
            idempotency_key=str(request.environ["quant_hub.idempotency_key"]),
        )
    except IdempotencyConflict as error:
        return _idempotency_conflict(error)
    return _command_response(outcome)


@api_v1.post("/research/<research_id>/completion-decisions")
def create_research_completion_decision(research_id: str) -> Response:
    precondition = _reject_unexpected_precondition()
    if precondition is not None:
        return precondition
    payload = _model_from_json(
        ResearchCompletionDecisionCreate,
        "研究完成决定数据无效。",
    )
    if isinstance(payload, Response):
        return payload
    assert isinstance(payload, ResearchCompletionDecisionCreate)
    key = str(request.environ["quant_hub.idempotency_key"])
    try:
        if payload.decision == "completed":
            assert payload.research_release_id is not None
            outcome = _collaboration().complete_research(
                research_id,
                payload.research_release_id,
                reason=payload.reason,
                actor=payload.actor,
                review_urn=payload.review_urn,
                idempotency_key=key,
            )
        else:
            assert payload.target_decision_id is not None
            outcome = _collaboration().revoke_completion(
                research_id,
                payload.target_decision_id,
                reason=payload.reason,
                actor=payload.actor,
                review_urn=payload.review_urn,
                idempotency_key=key,
            )
    except IdempotencyConflict as error:
        return _idempotency_conflict(error)
    return _command_response(outcome)


@api_v1.get("/research")
def research_list() -> Response:
    parameters = _query_model(ResearchParameters, {"q": "query"})
    if isinstance(parameters, Response):
        return parameters
    assert isinstance(parameters, ResearchParameters)
    items = _catalog().list_research()
    if parameters.status is not None:
        items = [item for item in items if item.get("work_status") == parameters.status]
    if parameters.query:
        matching = {
            item["research_id"] for item in _catalog().search(parameters.query, limit=100)
        }
        folded = parameters.query.casefold()
        items = [
            item
            for item in items
            if item["research_id"] in matching
            or folded in str(item["display_title"]).casefold()
        ]
    return _response(data={"research": items}, etag=_json_etag(items))


@api_v1.get("/research/<research_id>")
def research_detail(research_id: str) -> Response:
    try:
        page = _catalog().research_page(research_id)
    except ArchiveNotFound:
        return api_error("research_not_found", "未找到已发布的研究。", 404)
    return _response(
        data={"research": page},
        revision=int(page["release_revision"]),
        etag=f"research:{research_id}:r{page['release_revision']}",
    )


@api_v1.get("/search")
def search() -> Response:
    parameters = _query_model(SearchParameters, {"q": "query"})
    if isinstance(parameters, Response):
        return parameters
    assert isinstance(parameters, SearchParameters)
    results = _catalog().search(parameters.query, limit=parameters.limit)
    data = {"query": parameters.query, "results": results}
    return _response(data=data, etag=_json_etag(data))


@api_v1.get("/research/<research_id>/comments")
def comments(research_id: str) -> Response:
    try:
        _catalog().research_page(research_id)
    except ArchiveNotFound:
        return api_error("research_not_found", "未找到已发布的研究。", 404)
    items = _collaboration().list_comments(research_id)
    for item in items:
        item["etag"] = f'"comment:{item["comment_id"]}:r{item["revision"]}"'
    return _response(data={"comments": items}, etag=_json_etag(items))


@api_v1.get("/research/<research_id>/documents/<document_id>/source")
def source_document(research_id: str, document_id: str) -> Response:
    try:
        source, slug = _catalog().source_document(research_id, document_id)
    except ArchiveNotFound:
        return api_error("source_not_found", "未找到当前 release 的原始文档。", 404)
    digest = hashlib.sha256(source).hexdigest()
    response = Response(source, content_type="text/markdown; charset=utf-8")
    ascii_name = f"{slug}.md"
    response.headers["Content-Disposition"] = (
        f'inline; filename="{ascii_name}"; filename*=UTF-8\'\'{quote(ascii_name)}'
    )
    response.headers["X-Content-SHA256"] = digest
    response.set_etag("sha256-" + digest)
    response.make_conditional(request)
    return response


@api_v1.get("/archive/assets/<asset_id>")
def archive_presentation_asset(asset_id: str) -> Response:
    try:
        content, asset = _catalog().presentation_asset(asset_id)
    except ArchiveNotFound:
        return api_error("archive_asset_not_found", "未找到已审核的研究资源。", 404)
    except SourceBoundaryError:
        current_app.logger.exception("Archive presentation asset integrity failed")
        return api_error(
            "archive_asset_integrity_failed",
            "研究资源与冻结身份不一致，已拒绝返回。",
            409,
        )
    media_type = str(asset["media_type"])
    if media_type.startswith("text/") and "charset=" not in media_type:
        media_type += "; charset=utf-8"
    response = Response(content, content_type=media_type)
    filename = str(asset["filename"])
    response.headers["Content-Disposition"] = (
        f'inline; filename="archive-resource"; filename*=UTF-8\'\'{quote(filename)}'
    )
    response.headers["X-Content-SHA256"] = str(asset["sha256"])
    response.set_etag("sha256-" + str(asset["sha256"]))
    response.make_conditional(request)
    return response


@api_v1.post("/research/<research_id>/comments")
def create_comment(research_id: str) -> Response:
    if request.headers.get("If-Match") is not None:
        return api_error(
            "unexpected_precondition",
            "创建评论不得发送 If-Match。",
            400,
        )
    payload = _model_from_json(CommentCreate, "评论数据无效。")
    if isinstance(payload, Response):
        return payload
    assert isinstance(payload, CommentCreate)
    key = str(request.environ["quant_hub.idempotency_key"])
    try:
        outcome = _collaboration().create_comment(
            research_id,
            payload.actor,
            payload.content,
            idempotency_key=key,
            target=payload.target.to_domain() if payload.target is not None else None,
        )
    except IdempotencyConflict as error:
        return _idempotency_conflict(error)
    return _command_response(outcome)


@api_v1.post("/research-updates/<update_id>/annotations")
def annotate_research_update(update_id: str) -> Response:
    expected = _expected_research_update_revision(update_id)
    if isinstance(expected, Response):
        return expected
    payload = _model_from_json(
        ResearchUpdateAnnotationCreate,
        "研究更新说明数据无效。",
    )
    if isinstance(payload, Response):
        return payload
    assert isinstance(payload, ResearchUpdateAnnotationCreate)
    try:
        outcome = _collaboration().annotate_research_update(
            update_id,
            payload.actor,
            payload.note,
            expected_revision=expected,
            idempotency_key=str(request.environ["quant_hub.idempotency_key"]),
        )
    except IdempotencyConflict as error:
        return _idempotency_conflict(error)
    return _command_response(outcome)


@api_v1.patch("/comments/<comment_id>")
def update_comment(comment_id: str) -> Response:
    expected = _expected_revision(comment_id)
    if isinstance(expected, Response):
        return expected
    payload = _model_from_json(CommentUpdate, "评论数据无效。")
    if isinstance(payload, Response):
        return payload
    assert isinstance(payload, CommentUpdate)
    key = str(request.environ["quant_hub.idempotency_key"])
    try:
        outcome = _collaboration().update_comment(
            comment_id,
            payload.actor,
            payload.content,
            expected_revision=expected,
            idempotency_key=key,
        )
    except IdempotencyConflict as error:
        return _idempotency_conflict(error)
    return _command_response(outcome)


@api_v1.delete("/comments/<comment_id>")
def delete_comment(comment_id: str) -> Response:
    expected = _expected_revision(comment_id)
    if isinstance(expected, Response):
        return expected
    payload = _model_from_json(CommentDelete, "评论操作者无效。")
    if isinstance(payload, Response):
        return payload
    assert isinstance(payload, CommentDelete)
    key = str(request.environ["quant_hub.idempotency_key"])
    try:
        outcome = _collaboration().delete_comment(
            comment_id,
            payload.actor,
            expected_revision=expected,
            idempotency_key=key,
        )
    except IdempotencyConflict as error:
        return _idempotency_conflict(error)
    return _command_response(outcome)


__all__ = ["api_error", "api_v1", "web"]
