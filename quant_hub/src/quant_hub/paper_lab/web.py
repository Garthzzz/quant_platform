from __future__ import annotations

import json
from io import BytesIO
import re
import sqlite3
from typing import Any
from uuid import uuid4

from flask import (
    Blueprint,
    Response,
    current_app,
    jsonify,
    render_template,
    request,
    send_file,
)

from quant_hub.config import Settings
from quant_hub.web.security import WriteSecurityError, csrf_token, require_write_security
from .assets import ManagedAssetError, read_frozen_asset
from .database import paper_lab_connection
from .presentation import with_paper_presentation
from .service import (
    EDITABLE_PAPER_FIELDS,
    PaperFieldVersionConflict,
    PaperLabIdempotencyConflict,
    PaperLabService,
)


paper_lab_web = Blueprint(
    "paper_lab_web",
    __name__,
    template_folder="templates",
    static_folder="static",
    static_url_path="/paper-lab/static",
)
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$", re.ASCII)
_PAPER_FIELD_LABELS = {
    "title": "标题", "link": "来源链接", "authors": "作者", "venue": "发表载体",
    "institution": "机构", "model_type": "模型", "asset_market": "市场",
    "start_year": "样本起始年", "end_year": "样本结束年", "study_period": "研究区间",
    "sample_length": "样本长度", "prediction_target": "预测目标",
    "input_features": "输入特征", "feature_count": "特征数量", "oos_method": "样本外方法",
    "metrics": "评价指标", "performance": "性能", "special_tech": "特殊技术",
    "source_type": "来源类型", "research_topic": "研究主题", "main_findings": "核心结论",
    "innovations_insights": "创新与启发", "caveats_replication": "质疑与复现",
    "summary": "摘要", "rating": "评级", "data_input": "数据输入",
    "data_preprocess": "数据预处理", "method_model": "方法模型",
    "method_special": "特殊方法", "loss_function": "损失函数",
    "training_config": "训练配置", "pipeline_output": "管线输出", "diagram": "架构图",
    "status": "旧流程状态", "phase": "旧流程阶段",
}


def _request_id() -> str:
    candidate = request.headers.get("X-Request-ID", "")
    return candidate if _REQUEST_ID.fullmatch(candidate) else str(uuid4())


def _settings() -> Settings:
    return current_app.extensions["quant_hub_settings"]


def _service() -> PaperLabService:
    service = current_app.extensions.get("paper_lab_service")
    if service is None:
        service = PaperLabService(_settings())
        current_app.extensions["paper_lab_service"] = service
    return service


def _ok(data: dict[str, object], status: int = 200) -> Response:
    response = jsonify(
        {"api_version": "v1", "data": data, "meta": {"request_id": _request_id()}}
    )
    response.status_code = status
    return response


def _error(code: str, message: str, status: int, details: object | None = None) -> Response:
    response = jsonify({
        "api_version": "v1",
        "error": {"code": code, "message": message, "details": details},
        "meta": {"request_id": _request_id()},
    })
    response.status_code = status
    return response


@paper_lab_web.get("/paper-lab/")
def paper_lab_index() -> str:
    return render_template("paper_lab/index.html", csrf_token=csrf_token())


@paper_lab_web.get("/paper-lab/papers/<paper_id>")
def paper_lab_detail(paper_id: str) -> str | tuple[str, int]:
    try:
        paper = with_paper_presentation(_service().paper_detail(paper_id))
    except KeyError:
        return render_template("error.html", title="论文不存在", message="该论文未进入 Paper Lab。"), 404
    versions = paper.get("field_overlay_versions") or {}
    editable_fields = [
        {
            "name": name,
            "label": _PAPER_FIELD_LABELS.get(name, name),
            "value": paper.get(name, ""),
            "version": versions.get(name, 0),
        }
        for name in EDITABLE_PAPER_FIELDS
    ]
    return render_template(
        "paper_lab/detail.html",
        paper=paper,
        editable_fields=editable_fields,
        csrf_token=csrf_token(),
    )


@paper_lab_web.get("/paper-lab/designer")
def paper_lab_designer() -> str:
    return render_template("paper_lab/designer.html", csrf_token=csrf_token())


@paper_lab_web.get("/api/v1/paper-lab/papers")
def api_papers() -> Response:
    try:
        limit = int(request.args.get("limit", "200"))
        offset = int(request.args.get("offset", "0"))
        view = request.args.get("view", "full")
        if view not in {"full", "summary"}:
            raise ValueError("view must be full or summary")
        rows = _service().list_papers(
            rating=request.args.get("rating"),
            model=request.args.get("model"),
            market=request.args.get("market"),
            source=request.args.get("source"),
            keyword=request.args.get("q"),
            status=request.args.get("status"),
            after=int(request.args["after"]) if request.args.get("after") else None,
            before=int(request.args["before"]) if request.args.get("before") else None,
            limit=limit,
            offset=offset,
        )
    except (ValueError, TypeError) as error:
        return _error("invalid_query", "查询参数无效。", 400, str(error))
    if view == "summary":
        summary_fields = (
            "paper_id",
            "legacy_id",
            "title",
            "lifecycle_status",
            "paper_version_id",
            "reading_status",
            "reading_attempt",
            "model_type",
            "asset_market",
            "rating",
        )
        rows = [
            {field: row.get(field) for field in summary_fields}
            for row in rows
        ]
    return _ok({"papers": rows, "count": len(rows), "limit": limit, "offset": offset})


@paper_lab_web.get("/api/v1/paper-lab/papers/<paper_id>")
def api_paper(paper_id: str) -> Response:
    try:
        return _ok({"paper": with_paper_presentation(_service().paper_detail(paper_id))})
    except KeyError:
        return _error("paper_not_found", "论文不存在。", 404)


@paper_lab_web.patch("/api/v1/paper-lab/papers/<paper_id>")
def api_paper_field_update(paper_id: str) -> Response:
    try:
        idempotency_key = require_write_security(
            request, current_app.extensions["trusted_origins"]
        )
    except WriteSecurityError as error:
        return _error(error.code, str(error), error.status)
    payload: Any = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _error("invalid_paper_field_command", "字段更新结构无效。", 422)
    expected_version = payload.get("expected_version")
    if isinstance(expected_version, bool) or not isinstance(expected_version, int):
        return _error("invalid_paper_field_command", "必须提供整数 expected_version。", 422)
    try:
        result = _service().save_paper_field(
            paper_id,
            str(payload.get("field") or ""),
            payload.get("value", ""),
            expected_version=expected_version,
            actor_display_name=str(payload.get("actor_display_name") or ""),
            reason=str(payload.get("reason") or ""),
            idempotency_key=idempotency_key,
        )
    except KeyError:
        return _error("paper_not_found", "论文不存在。", 404)
    except PaperFieldVersionConflict as error:
        return _error("paper_field_version_conflict", "字段已被其他更新修改。", 409, str(error))
    except PaperLabIdempotencyConflict as error:
        return _error("idempotency_conflict", "幂等键已绑定其他请求。", 409, str(error))
    except (ValueError, sqlite3.Error) as error:
        return _error("paper_field_rejected", "字段更新未通过契约校验。", 422, str(error))
    return _ok({"paper_field": result})


@paper_lab_web.get("/api/v1/paper-lab/versions/<paper_version_id>/content")
def api_paper_content(paper_version_id: str) -> Response:
    with paper_lab_connection(_settings()) as connection:
        row = connection.execute(
            """
            SELECT asset_relative_path,content_sha256,bytes,original_filename
            FROM lab_paper_version WHERE paper_version_id=?
            """,
            (paper_version_id,),
        ).fetchone()
    if row is None:
        return _error("paper_version_not_found", "论文版本不存在。", 404)
    try:
        payload = read_frozen_asset(
            _settings().paper_lab_asset_root,
            row["asset_relative_path"],
            expected_sha256=row["content_sha256"],
            expected_bytes=int(row["bytes"]),
            label=f"paper version {paper_version_id}",
        )
    except ManagedAssetError as error:
        return _error(
            "paper_asset_integrity_error",
            "论文文件不可用。",
            409,
            {"reason": error.code},
        )
    assert payload is not None
    return send_file(
        BytesIO(payload),
        mimetype="application/pdf",
        download_name=row["original_filename"],
        conditional=True,
        etag=row["content_sha256"],
        max_age=0,
    )


@paper_lab_web.get("/api/v1/paper-lab/notes/<note_id>/content")
def api_note_content(note_id: str) -> Response:
    with paper_lab_connection(_settings()) as connection:
        row = connection.execute(
            """
            SELECT snapshot_relative_path,content_sha256,bytes
            FROM lab_note WHERE note_id=?
            """,
            (note_id,),
        ).fetchone()
    if row is None:
        return _error("note_not_found", "精读笔记不存在。", 404)
    root = _settings().paper_lab_asset_root.parent / "legacy_snapshot"
    try:
        payload = read_frozen_asset(
            root,
            row["snapshot_relative_path"],
            expected_sha256=row["content_sha256"],
            expected_bytes=int(row["bytes"]),
            label=f"paper note {note_id}",
        )
    except ManagedAssetError as error:
        return _error(
            "note_asset_integrity_error",
            "精读笔记文件不可用。",
            409,
            {"reason": error.code},
        )
    assert payload is not None
    return send_file(
        BytesIO(payload),
        mimetype="text/markdown; charset=utf-8",
        download_name=row["snapshot_relative_path"].rsplit("/", 1)[-1],
        conditional=True,
        etag=row["content_sha256"],
        max_age=0,
    )


@paper_lab_web.get("/api/v1/paper-lab/components")
def api_components() -> Response:
    kind = request.args.get("kind", "concept_block")
    if kind not in {"concept_block", "tag_component"}:
        return _error("invalid_component_kind", "组件类型无效。", 400)
    with paper_lab_connection(_settings()) as connection:
        rows = connection.execute(
            """
            SELECT c.* FROM concept_component c
            JOIN (
                SELECT legacy_component_id,max(version) AS version
                FROM concept_component WHERE component_kind=? GROUP BY legacy_component_id
            ) latest ON latest.legacy_component_id=c.legacy_component_id
                    AND latest.version=c.version
            WHERE c.component_kind=? ORDER BY c.layer,c.display_name
            """,
            (kind, kind),
        ).fetchall()
    components = []
    for row in rows:
        components.append({
            "component_id": row["component_id"],
            "legacy_component_id": row["legacy_component_id"],
            "layer": row["layer"],
            "display_name": row["display_name"],
            "version": row["version"],
            "status": row["status"],
            "automatic": json.loads(row["automatic_payload_json"]),
            "curated": json.loads(row["curated_payload_json"]),
        })
    return _ok({"components": components, "count": len(components)})


@paper_lab_web.get("/api/v1/paper-lab/blueprints")
def api_blueprints() -> Response:
    with paper_lab_connection(_settings()) as connection:
        rows = connection.execute(
            """
            SELECT blueprint.blueprint_id,blueprint.name,blueprint.objective,
                   blueprint.lifecycle_status,blueprint.updated_at,
                   version.blueprint_version_id,version.version,
                   version.validation_status,version.validation_report_json
            FROM architecture_blueprint AS blueprint
            JOIN blueprint_version AS version
              ON version.blueprint_id=blueprint.blueprint_id
             AND version.version=(
                 SELECT max(candidate.version) FROM blueprint_version AS candidate
                 WHERE candidate.blueprint_id=blueprint.blueprint_id
             )
            ORDER BY blueprint.updated_at DESC,blueprint.blueprint_id
            """
        ).fetchall()
    blueprints = []
    for row in rows:
        item = dict(row)
        item["validation"] = json.loads(item.pop("validation_report_json"))
        blueprints.append(item)
    return _ok({"blueprints": blueprints, "count": len(blueprints)})


@paper_lab_web.get("/api/v1/paper-lab/blueprints/<blueprint_id>")
def api_blueprint_detail(blueprint_id: str) -> Response:
    requested = request.args.get("version")
    try:
        version = int(requested) if requested is not None else None
        if version is not None and version < 1:
            raise ValueError("version must be positive")
    except ValueError as error:
        return _error("invalid_blueprint_version", "蓝图版本无效。", 400, str(error))
    with paper_lab_connection(_settings()) as connection:
        row = connection.execute(
            """
            SELECT blueprint.*,version.blueprint_version_id,version.version,
                   version.constraints_json,version.validation_status,
                   version.validation_report_json,version.created_at AS version_created_at
            FROM architecture_blueprint AS blueprint
            JOIN blueprint_version AS version USING(blueprint_id)
            WHERE blueprint.blueprint_id=?
              AND version.version=COALESCE(?,(
                  SELECT max(candidate.version) FROM blueprint_version AS candidate
                  WHERE candidate.blueprint_id=blueprint.blueprint_id
              ))
            """,
            (blueprint_id, version),
        ).fetchone()
        if row is None:
            return _error("blueprint_not_found", "蓝图或版本不存在。", 404)
        components = [
            dict(item)
            for item in connection.execute(
                """
                SELECT selected.component_id,selected.layer,selected.ordinal,selected.forced,
                       component.legacy_component_id,component.display_name,component.version
                FROM blueprint_component AS selected
                JOIN concept_component AS component USING(component_id)
                WHERE selected.blueprint_version_id=?
                ORDER BY selected.ordinal,selected.component_id
                """,
                (row["blueprint_version_id"],),
            )
        ]
    result = dict(row)
    result["constraints"] = json.loads(result.pop("constraints_json"))
    result["validation"] = json.loads(result.pop("validation_report_json"))
    result["components"] = components
    return _ok({"blueprint": result})


@paper_lab_web.post("/api/v1/paper-lab/blueprints/validate")
def api_blueprint_validate() -> Response:
    try:
        require_write_security(request, current_app.extensions["trusted_origins"])
    except WriteSecurityError as error:
        return _error(error.code, str(error), error.status)
    payload: Any = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("components"), list):
        return _error("invalid_blueprint", "蓝图结构无效。", 422)
    try:
        validation = _service().validate_blueprint(payload["components"])
    except (ValueError, KeyError, sqlite3.Error) as error:
        return _error("blueprint_rejected", "蓝图未通过契约解析。", 422, str(error))
    return _ok({"validation": validation.to_dict()})


@paper_lab_web.post("/api/v1/paper-lab/blueprints")
def api_blueprint_create() -> Response:
    try:
        idempotency_key = require_write_security(
            request, current_app.extensions["trusted_origins"]
        )
    except WriteSecurityError as error:
        return _error(error.code, str(error), error.status)
    payload: Any = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("components"), list):
        return _error("invalid_blueprint", "蓝图结构无效。", 422)
    try:
        result = _service().save_blueprint(
            str(payload.get("name") or ""),
            str(payload.get("objective") or ""),
            payload["components"],
            blueprint_id=payload.get("blueprint_id"),
            idempotency_key=idempotency_key,
        )
    except PaperLabIdempotencyConflict as error:
        return _error("idempotency_conflict", "幂等键已绑定其他请求。", 409, str(error))
    except (ValueError, KeyError, sqlite3.Error) as error:
        return _error("blueprint_rejected", "蓝图未通过契约校验。", 422, str(error))
    return _ok({"blueprint": result}, 201)


def register_paper_lab(app: Any, settings: Settings) -> None:
    if "paper_lab_web" not in app.blueprints:
        service = PaperLabService(settings)
        service.initialize()
        app.extensions["paper_lab_service"] = service
        app.register_blueprint(paper_lab_web)
