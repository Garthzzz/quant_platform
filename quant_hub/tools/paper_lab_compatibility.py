from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from quant_hub.config import Settings
from quant_hub.app import create_app
from quant_hub.paper_lab.database import paper_lab_connection
from quant_hub.paper_lab.service import PaperLabService


ROOT = Path(__file__).resolve().parents[2]
FORMAL_ROOT = Path(__file__).resolve().parents[1]
AUDIT_PATH = ROOT / "project_state" / "audits" / "proj2" / "artifact_cross_audit.json"
OUTPUTS = (
    FORMAL_ROOT / "fixtures" / "paper_lab" / "compatibility_matrix.tsv",
    ROOT / "project_state" / "workers" / "d_paper_lab_prebuild" / "compatibility_matrix.tsv",
)
REPORT_PATH = ROOT / "project_state" / "workers" / "d_paper_lab_prebuild" / "matrix_report.json"
BEHAVIOR_PATH = ROOT / "project_state" / "workers" / "d_paper_lab_prebuild" / "compatibility_behavior.json"
COLUMNS = (
    "matrix_id",
    "surface_kind",
    "legacy_surface",
    "source_locator",
    "baseline_fixture_sha256",
    "expected_new_surface",
    "intentional_difference_reason",
    "test_id",
    "observed_result",
    "evidence_locator",
    "verdict",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _row(
    matrix_id: str,
    kind: str,
    legacy: str,
    source: str,
    baseline_hash: str,
    expected: str,
    difference: str,
    test_id: str,
    observed: object,
    evidence: str,
    passed: bool,
) -> dict[str, str]:
    return {
        "matrix_id": matrix_id,
        "surface_kind": kind,
        "legacy_surface": legacy,
        "source_locator": source,
        "baseline_fixture_sha256": baseline_hash,
        "expected_new_surface": expected,
        "intentional_difference_reason": difference,
        "test_id": test_id,
        "observed_result": _json(observed),
        "evidence_locator": evidence,
        "verdict": "PASS" if passed else "FAIL",
    }


def _normalized(value: str, fixture_root: Path) -> str:
    native = str(fixture_root)
    posix = fixture_root.as_posix()
    variants = {
        native,
        posix,
        json.dumps(native, ensure_ascii=False)[1:-1],
        json.dumps(posix, ensure_ascii=False)[1:-1],
    }
    normalized = value
    for variant in sorted(variants, key=len, reverse=True):
        normalized = normalized.replace(variant, "<fixture>")
    return normalized


def _stable_payload(value: Any) -> Any:
    """Remove transport-only entropy from executable compatibility evidence."""

    if isinstance(value, dict):
        return {
            str(key): "<request-id>" if key == "request_id" else _stable_payload(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_stable_payload(item) for item in value]
    return value


def _behavior_probes() -> dict[str, object]:
    """Run compatibility surfaces against a disposable project, not source markers."""

    work_root = BEHAVIOR_PATH.parent
    work_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="compat-", dir=work_root) as temporary:
        fixture_root = Path(temporary).resolve()
        project = fixture_root / "project"
        archive = project / "reference" / "archive"
        drop = project / "quant_hub" / "paper_lab" / "papers"
        var = project / "quant_hub" / "var"
        archive.mkdir(parents=True)
        drop.mkdir(parents=True)
        common = [
            "--project-root", str(project),
            "--archive-root", str(archive),
            "--var-root", str(var),
        ]
        wrappers = {
            "scan": (FORMAL_ROOT / "paper_lab" / "pipeline" / "scan.py", common),
            "run": (FORMAL_ROOT / "paper_lab" / "pipeline" / "run_papers.py", common),
            "dry-run": (FORMAL_ROOT / "paper_lab" / "pipeline" / "run_papers.py", [*common, "--dry-run"]),
            "resume": (FORMAL_ROOT / "paper_lab" / "pipeline" / "run_papers.py", [*common, "--resume"]),
            "write": (FORMAL_ROOT / "paper_lab" / "pipeline" / "write_db.py", common),
            "query": (FORMAL_ROOT / "paper_lab" / "tools" / "query.py", common),
            "viewer": (FORMAL_ROOT / "paper_lab" / "tools" / "viewer" / "app.py", ["--help"]),
            "component": (FORMAL_ROOT / "paper_lab" / "tools" / "build_component_library.py", common),
            "concept": (FORMAL_ROOT / "paper_lab" / "tools" / "build_concept_blocks.py", common),
        }
        commands: dict[str, object] = {}
        for name, (wrapper, arguments) in wrappers.items():
            command = [sys.executable, "-B", str(wrapper), *arguments]
            completed = subprocess.run(
                command,
                cwd=FORMAL_ROOT,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=60,
                check=False,
            )
            stdout = _normalized(completed.stdout, fixture_root)
            stderr = _normalized(completed.stderr, fixture_root)
            body_ok = (
                (name == "query" and "No results." in stdout)
                or (name == "viewer" and "usage:" in stdout.casefold())
                or ('"status": "PASS"' in stdout)
            )
            commands[name] = {
                "command": ["<python>", "-B", wrapper.relative_to(FORMAL_ROOT).as_posix(), *[
                    _normalized(argument, fixture_root) for argument in arguments
                ]],
                "returncode": completed.returncode,
                "stdout": stdout[-12000:],
                "stderr": stderr[-4000:],
                "deprecation_mapping": "[deprecated]" in stderr and "qrh paper-lab" in stderr,
                "body_contract": body_ok,
                "contract_pass": completed.returncode == 0 and body_ok
                and "[deprecated]" in stderr and "qrh paper-lab" in stderr,
            }

        settings = Settings(
            project_root=project,
            archive_root=archive,
            var_root=var,
            database_path=var / "db" / "platform.sqlite3",
            object_root=var / "objects",
            migration_root=FORMAL_ROOT / "migrations" / "platform",
        )
        settings.validate()
        pdf = drop / "1_compatibility.pdf"
        pdf.write_bytes(b"%PDF-1.4\ncompatibility behavior fixture\n%%EOF")
        before = (pdf.stat().st_size, _sha256(pdf), pdf.stat().st_mtime_ns)
        service = PaperLabService(settings)
        registration = service.register_all()[0]
        after = (pdf.stat().st_size, _sha256(pdf), pdf.stat().st_mtime_ns)
        with paper_lab_connection(settings) as connection:
            connection.execute(
                """
                INSERT INTO concept_component VALUES(
                    'compat-component','concept_block','compat-legacy','model','兼容组件',1,
                    '{"input_types":[],"output_types":["signal"],"one_liner":"兼容行为积木"}',
                    '{}',?,'validated','compat'
                )
                """,
                ("a" * 64,),
            )

        app = create_app(settings, {"TESTING": True})
        client = app.test_client()
        token = "C" * 43
        with client.session_transaction() as session:
            session["csrf_token"] = token
        write_headers = {
            "Origin": "http://localhost",
            "X-CSRF-Token": token,
            "Idempotency-Key": "compatibility-behavior-command-1",
        }
        component_payload = [{
            "component_id": "compat-component", "layer": "model",
            "layer_order": 0, "ordinal": 0, "forced": False,
        }]
        validation = client.post(
            "/api/v1/paper-lab/blueprints/validate",
            json={"components": component_payload},
            headers=write_headers,
        )
        blueprint = client.post(
            "/api/v1/paper-lab/blueprints",
            json={"name": "兼容蓝图", "objective": "行为矩阵", "components": component_payload},
            headers={**write_headers, "Idempotency-Key": "compatibility-blueprint-save-1"},
        )
        blueprint_json = blueprint.get_json() or {}
        blueprint_id = blueprint_json.get("data", {}).get("blueprint", {}).get("blueprint_id", "missing")
        second_blueprint_payload = {
            "blueprint_id": blueprint_id,
            "name": "兼容蓝图",
            "objective": "行为矩阵第二版",
            "components": [{**component_payload[0], "forced": True}],
        }
        blueprint_second = client.post(
            "/api/v1/paper-lab/blueprints",
            json=second_blueprint_payload,
            headers={**write_headers, "Idempotency-Key": "compatibility-blueprint-save-2"},
        )
        blueprint_replay = client.post(
            "/api/v1/paper-lab/blueprints",
            json=second_blueprint_payload,
            headers={**write_headers, "Idempotency-Key": "compatibility-blueprint-save-2"},
        )
        restore = client.get(f"/api/v1/paper-lab/blueprints/{blueprint_id}")
        edit = client.patch(
            f"/api/v1/paper-lab/papers/{registration.paper_id}",
            json={
                "field": "summary", "value": "兼容编辑覆盖层", "expected_version": 0,
                "actor_display_name": "兼容矩阵", "reason": "Viewer edit behavior",
            },
            headers={**write_headers, "Idempotency-Key": "compatibility-viewer-edit-1"},
        )
        edited_detail = client.get(f"/api/v1/paper-lab/papers/{registration.paper_id}")

        route_responses = {
            "index": client.get("/paper-lab/"),
            "list": client.get("/api/v1/paper-lab/papers?view=summary"),
            "detail": client.get(f"/api/v1/paper-lab/papers/{registration.paper_id}"),
            "pdf": client.get(f"/api/v1/paper-lab/versions/{registration.paper_version_id}/content"),
            "components": client.get("/api/v1/paper-lab/components?kind=tag_component"),
            "blocks": client.get("/api/v1/paper-lab/components?kind=concept_block"),
            "designer": client.get("/paper-lab/designer"),
        }
        routes: dict[str, object] = {}
        for name, response in route_responses.items():
            try:
                payload = response.get_json(silent=True)
                body = (
                    response.get_data(as_text=True)[:2000]
                    if payload is None
                    else _stable_payload(payload)
                )
                routes[name] = {
                    "status": response.status_code,
                    "content_type": response.content_type,
                    "body": body,
                    "contract_pass": response.status_code == 200,
                }
            finally:
                response.close()
        routes["blueprint"] = {
            "validate_status": validation.status_code,
            "save_status": blueprint.status_code,
            "second_save_status": blueprint_second.status_code,
            "replay_status": blueprint_replay.status_code,
            "restore_status": restore.status_code,
            "version": (blueprint_second.get_json() or {}).get("data", {}).get("blueprint", {}).get("version"),
            "replayed": (blueprint_replay.get_json() or {}).get("data", {}).get("blueprint", {}).get("replayed"),
            "restored_component_count": len((restore.get_json() or {}).get("data", {}).get("blueprint", {}).get("components", [])),
            "contract_pass": validation.status_code == 200 and blueprint.status_code == 201
            and blueprint_second.status_code == 201 and blueprint_replay.status_code == 201
            and (blueprint_replay.get_json() or {}).get("data", {}).get("blueprint", {}).get("replayed") is True
            and restore.status_code == 200
            and (restore.get_json() or {}).get("data", {}).get("blueprint", {}).get("version") == 2
            and any(
                bool(item.get("forced"))
                for item in (restore.get_json() or {}).get("data", {}).get("blueprint", {}).get("components", [])
            ),
        }
        routes["viewer-edit"] = {
            "patch_status": edit.status_code,
            "read_status": edited_detail.status_code,
            "value": (edited_detail.get_json() or {}).get("data", {}).get("paper", {}).get("summary"),
            "overlay_version": (edited_detail.get_json() or {}).get("data", {}).get("paper", {}).get("field_overlay_versions", {}).get("summary"),
            "contract_pass": edit.status_code == 200 and edited_detail.status_code == 200
            and (edited_detail.get_json() or {}).get("data", {}).get("paper", {}).get("summary") == "兼容编辑覆盖层",
        }
        routes["drop-purity"] = {
            "before": (before[0], before[1], "<mtime>"),
            "after": (after[0], after[1], "<mtime>"),
            "contract_pass": before == after,
        }
        validation.close()
        blueprint.close()
        blueprint_second.close()
        blueprint_replay.close()
        restore.close()
        edit.close()
        edited_detail.close()
        result = {
            "schema_version": "paper-lab-compatibility-behavior/v1",
            "commands": commands,
            "routes": routes,
            "all_pass": all(item["contract_pass"] for item in commands.values())
            and all(item["contract_pass"] for item in routes.values()),
        }
    BEHAVIOR_PATH.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return result


def build() -> tuple[list[dict[str, str]], dict[str, object]]:
    settings = Settings.default()
    audit = json.loads(AUDIT_PATH.read_text(encoding="utf-8"))
    behavior = _behavior_probes()
    source = settings.project_root / "reference" / "proj2"
    rows: list[dict[str, str]] = []
    wrapper_surfaces = [
        ("scan", "python pipeline/scan.py", "paper_lab/pipeline/scan.py", "纯读发现；日期名不再原地 rename", "D-CMD-SCAN"),
        ("run", "python pipeline/run_papers.py", "paper_lab/pipeline/run_papers.py", "Claude 进程替换为持久化 Codex task/run", "D-CMD-RUN"),
        ("dry-run", "python pipeline/run_papers.py --dry-run", "paper_lab/pipeline/run_papers.py --dry-run", "dry-run 不再先依赖模型 CLI", "D-CMD-DRY"),
        ("resume", "JSON status=in_progress 隐式续读", "paper_lab/pipeline/run_papers.py --resume", "显式 attempt 与 resume phase", "D-CMD-RESUME"),
        ("write", "python pipeline/write_db.py", "paper_lab/pipeline/write_db.py", "只发布审核通过 run，不再全量 INSERT OR REPLACE", "D-CMD-WRITE"),
        ("query", "python tools/query.py", "paper_lab/tools/query.py", "保留八个过滤参数，查询独立 paper_lab DB", "D-CMD-QUERY"),
        ("viewer", "python tools/viewer/app.py :5050", "paper_lab/tools/viewer/app.py :5050", "兼容 launcher 注册统一 Web Blueprint", "D-CMD-VIEWER"),
        ("component", "python tools/build_component_library.py", "paper_lab/tools/build_component_library.py", "增量 projection 覆盖 137 篇并版本化", "D-CMD-COMPONENT"),
        ("concept", "python tools/build_concept_blocks.py", "paper_lab/tools/build_concept_blocks.py", "自动字段与人工策展分离，不覆盖 12 个扩展积木", "D-CMD-CONCEPT"),
    ]
    wrapper_by_name = {
        "scan": FORMAL_ROOT / "paper_lab" / "pipeline" / "scan.py",
        "run": FORMAL_ROOT / "paper_lab" / "pipeline" / "run_papers.py",
        "dry-run": FORMAL_ROOT / "paper_lab" / "pipeline" / "run_papers.py",
        "resume": FORMAL_ROOT / "paper_lab" / "pipeline" / "run_papers.py",
        "write": FORMAL_ROOT / "paper_lab" / "pipeline" / "write_db.py",
        "query": FORMAL_ROOT / "paper_lab" / "tools" / "query.py",
        "viewer": FORMAL_ROOT / "paper_lab" / "tools" / "viewer" / "app.py",
        "component": FORMAL_ROOT / "paper_lab" / "tools" / "build_component_library.py",
        "concept": FORMAL_ROOT / "paper_lab" / "tools" / "build_concept_blocks.py",
    }
    for index, (name, legacy, expected, difference, test_id) in enumerate(wrapper_surfaces, start=1):
        wrapper = wrapper_by_name[name]
        probe = behavior["commands"][name]
        rows.append(_row(
            f"CMD-{index:03d}", "command", legacy,
            "reference/proj2/pipeline or tools", audit["database"]["sha256"],
            expected, difference, test_id,
            {
                "wrapper_sha256": _sha256(wrapper) if wrapper.is_file() else None,
                "execution": probe,
            },
            f"{BEHAVIOR_PATH.relative_to(ROOT).as_posix()}#commands.{name}",
            bool(wrapper.is_file() and probe["contract_pass"]),
        ))

    routes = [
        ("GET /", "GET /paper-lab/", "D-WEB-INDEX"),
        ("GET /api/papers", "GET /api/v1/paper-lab/papers", "D-WEB-LIST"),
        ("GET /api/papers/<id>", "GET /api/v1/paper-lab/papers/<paper_id>", "D-WEB-DETAIL"),
        ("GET /pdf/<id>", "GET /api/v1/paper-lab/versions/<paper_version_id>/content", "D-WEB-PDF"),
        ("GET /api/components", "GET /api/v1/paper-lab/components?kind=tag_component", "D-WEB-COMPONENTS"),
        ("GET /api/concept_blocks", "GET /api/v1/paper-lab/components?kind=concept_block", "D-WEB-BLOCKS"),
        ("GET /designer", "GET /paper-lab/designer", "D-WEB-DESIGNER"),
        ("POST/PATCH /api/blueprints", "POST /api/v1/paper-lab/blueprints", "D-WEB-BLUEPRINT"),
        ("PATCH /api/papers/<id>", "PATCH /api/v1/paper-lab/papers/<paper_id>", "D-WEB-VIEWER-EDIT"),
        ("papers drop", "paper_lab/papers + qrh paper-lab scan", "D-DROP-PURITY"),
    ]
    route_probe_keys = (
        "index", "list", "detail", "pdf", "components", "blocks", "designer",
        "blueprint", "viewer-edit", "drop-purity",
    )
    for index, (legacy, expected, test_id) in enumerate(routes, start=1):
        probe_key = route_probe_keys[index - 1]
        probe = behavior["routes"][probe_key]
        rows.append(_row(
            f"WEB-{index:03d}", "route", legacy, "reference/proj2/tools/viewer/app.py",
            _sha256(source / "tools" / "viewer" / "app.py"), expected,
            "统一版本化 API；写请求增加同源、CSRF、幂等键前置检查", test_id,
            probe,
            f"{BEHAVIOR_PATH.relative_to(ROOT).as_posix()}#routes.{probe_key}",
            bool(probe["contract_pass"]),
        ))

    with paper_lab_connection(settings) as connection:
        import_run = connection.execute(
            "SELECT * FROM legacy_import_run WHERE status='completed' ORDER BY finished_at DESC LIMIT 1"
        ).fetchone()
        if import_run is None:
            raise RuntimeError("Paper Lab full import has not completed")
        import_run_id = import_run["import_run_id"]
        import_summary = json.loads(import_run["summary_json"])

        for item in audit["pdfs"]:
            relative = item["path"]
            mapping = connection.execute(
                """
                SELECT m.import_status,m.target_id,v.asset_relative_path
                FROM legacy_record_map m
                LEFT JOIN lab_paper_version v ON v.paper_version_id=m.target_id
                WHERE m.import_run_id=? AND m.legacy_kind='pdf' AND m.source_relative_path=?
                """,
                (import_run_id, relative),
            ).fetchone()
            asset_ok = False
            if mapping and mapping["asset_relative_path"]:
                asset_path = settings.paper_lab_asset_root / mapping["asset_relative_path"]
                asset_ok = asset_path.is_file() and _sha256(asset_path) == item["sha256"]
            snapshot_path = settings.paper_lab_asset_root.parent / "legacy_snapshot" / relative
            snapshot_ok = snapshot_path.is_file() and _sha256(snapshot_path) == item["sha256"]
            passed = bool(mapping and mapping["import_status"] == "imported" and asset_ok and snapshot_ok)
            legacy_id = str(item["filename_id"])
            difference = "ID 58 旧路径引号错误已修复；其余保持字节等价" if legacy_id == "58" else "字节等价导入，来源不改名"
            rows.append(_row(
                f"PDF-{int(legacy_id):03d}", "paper_asset", relative, relative,
                item["sha256"],
                f"paper_lab asset + /api/v1/paper-lab/versions/<version>/content",
                difference, f"D-ART-PDF-{int(legacy_id):03d}",
                {"mapped": bool(mapping), "asset_ok": asset_ok, "snapshot_ok": snapshot_ok},
                f"paper_lab.sqlite3:legacy_record_map[pdf:{relative}]", passed,
            ))

        for index, item in enumerate(audit["json_files"], start=1):
            relative = item["path"]
            mappings = connection.execute(
                "SELECT import_status,target_id FROM legacy_record_map WHERE import_run_id=? AND legacy_kind='json' AND source_relative_path=?",
                (import_run_id, relative),
            ).fetchall()
            issues = [row["issue_code"] for row in connection.execute(
                "SELECT issue_code FROM quarantine_record WHERE import_run_id=? AND source_relative_path=? ORDER BY issue_code",
                (import_run_id, relative),
            ).fetchall()]
            snapshot_path = settings.paper_lab_asset_root.parent / "legacy_snapshot" / relative
            snapshot_ok = snapshot_path.is_file() and _sha256(snapshot_path) == item["sha256"]
            passed = bool(mappings and snapshot_ok)
            expected_state = "quarantine with explicit error" if not item.get("parse_ok", False) or item.get("has_utf8_bom") else "immutable snapshot + canonical/superseded mapping"
            rows.append(_row(
                f"JSON-{index:03d}", "json_artifact", relative, relative, item["sha256"],
                expected_state,
                "坏 JSON/BOM/重复/缺字段保留原字节并隔离，不做静默修复",
                f"D-ART-JSON-{index:03d}",
                {"mapping_statuses": [row["import_status"] for row in mappings], "issues": issues, "snapshot_ok": snapshot_ok},
                f"paper_lab.sqlite3:legacy_record_map[json:{relative}]", passed,
            ))

        for index, item in enumerate(audit["notes"], start=1):
            relative = item["path"]
            mapping = connection.execute(
                "SELECT import_status,target_id FROM legacy_record_map WHERE import_run_id=? AND legacy_kind='note' AND source_relative_path=?",
                (import_run_id, relative),
            ).fetchone()
            issues = [row["issue_code"] for row in connection.execute(
                "SELECT issue_code FROM quarantine_record WHERE import_run_id=? AND source_relative_path=? ORDER BY issue_code",
                (import_run_id, relative),
            ).fetchall()]
            snapshot_path = settings.paper_lab_asset_root.parent / "legacy_snapshot" / relative
            snapshot_ok = snapshot_path.is_file() and _sha256(snapshot_path) == item["sha256"]
            passed = bool(mapping and snapshot_ok)
            rows.append(_row(
                f"NOTE-{index:03d}", "note_artifact", relative, relative, item["sha256"],
                "immutable legacy note snapshot + canonical/superseded mapping",
                "六节与旧模板均保留；重复版本显式选择 canonical",
                f"D-ART-NOTE-{index:03d}",
                {"mapping_status": mapping["import_status"] if mapping else None, "issues": issues, "snapshot_ok": snapshot_ok},
                f"paper_lab.sqlite3:legacy_record_map[note:{relative}]", passed,
            ))

        for legacy_id in range(1, 138):
            paper = connection.execute(
                """
                SELECT p.paper_id,v.paper_version_id,v.asset_relative_path,v.content_sha256
                FROM lab_paper p JOIN lab_paper_version v ON v.paper_id=p.paper_id
                WHERE p.legacy_id=? ORDER BY v.created_at DESC LIMIT 1
                """,
                (str(legacy_id),),
            ).fetchone()
            asset_path = settings.paper_lab_asset_root / paper["asset_relative_path"] if paper else None
            asset_ok = bool(
                paper and asset_path and asset_path.is_file()
                and _sha256(asset_path) == paper["content_sha256"]
            )
            passed = bool(paper and asset_ok)
            rows.append(_row(
                f"LINK-{legacy_id:03d}", "deep_link", f"Viewer paper {legacy_id} + /pdf/{legacy_id}",
                f"reference/proj2/data/papers.db#id={legacy_id}", audit["database"]["sha256"],
                "/paper-lab/papers/<paper_id> + version content route",
                "稳定 public ID 替代可变路径；51 个旧坏 route 已由真实文件 manifest 修复",
                f"D-LINK-{legacy_id:03d}",
                {"paper_id": paper["paper_id"] if paper else None, "version_id": paper["paper_version_id"] if paper else None, "asset_ok": asset_ok},
                f"paper_lab.sqlite3:lab_paper[legacy_id={legacy_id}]", passed,
            ))

        for index, field in enumerate(audit["database"]["paper_columns"], start=1):
            field_name = field["name"] if isinstance(field, dict) else str(field)
            present = int(connection.execute(
                "SELECT count(*) FROM reading_result WHERE result_kind='legacy_record' AND json_type(payload_json, ?) IS NOT NULL",
                (f"$.{field_name}",),
            ).fetchone()[0])
            quarantined = int(connection.execute(
                "SELECT count(*) FROM quarantine_record WHERE import_run_id=? AND issue_code='legacy_json_missing_fields' AND evidence_json LIKE ?",
                (import_run_id, f'%"{field_name}"%'),
            ).fetchone()[0])
            passed = present + quarantined >= 137
            rows.append(_row(
                f"FIELD-{index:03d}", "field", f"papers.{field_name}",
                "reference/proj2/pipeline/write_db.py#FIELDS", audit["database"]["sha256"],
                f"reading_result.payload_json.{field_name} or explicit missing-field quarantine",
                "内容字段保留于不可变 schema-bound snapshot；工程状态拆表",
                f"D-FIELD-{field_name}", {"present": present, "quarantined": quarantined},
                f"paper_lab.sqlite3:reading_result.payload_json$.{field_name}", passed,
            ))

        anomaly_expectations = [
            ("missing_json_fields", 53, "legacy_json_missing_fields", "D-ANOM-53-FIELDS"),
            ("bad_json", 1, "legacy_json_parse_error", "D-ANOM-BAD-104"),
            ("bom_json", 1, "legacy_json_utf8_bom", "D-ANOM-BOM-114"),
            ("missing_pdf_path", 50, "legacy_pdf_path_missing", "D-ANOM-PDF-MISSING"),
            ("broken_pdf_path", 1, "legacy_pdf_path_broken", "D-ANOM-PDF-BROKEN"),
            ("missing_notes_path", 49, "legacy_notes_path_missing", "D-ANOM-NOTE-MISSING"),
            ("broken_notes_path", 1, "legacy_notes_path_broken", "D-ANOM-NOTE-BROKEN"),
            ("legacy_note_template", 21, "legacy_note_template", "D-ANOM-NOTE-TEMPLATE"),
        ]
        for index, (name, expected_count, issue_code, test_id) in enumerate(anomaly_expectations, start=1):
            actual = int(connection.execute(
                "SELECT count(*) FROM quarantine_record WHERE import_run_id=? AND issue_code=?",
                (import_run_id, issue_code),
            ).fetchone()[0])
            rows.append(_row(
                f"ANOM-{index:03d}", "known_anomaly", name,
                "project_state/audits/proj2/artifact_cross_audit.json", _sha256(AUDIT_PATH),
                f"explicit quarantine count={expected_count}", "保留缺陷证据并建立可用新映射",
                test_id, {"expected": expected_count, "actual": actual},
                f"paper_lab.sqlite3:quarantine_record[{issue_code}]", actual == expected_count,
            ))
        queued_unique = int(connection.execute(
            "SELECT count(*) FROM tag_vocabulary WHERE review_status='queued'"
        ).fetchone()[0])
        rows.append(_row(
            "ANOM-009", "known_anomaly", "29 unknown pipeline tag occurrences",
            "project_state/workers/proj2_inventory/structural_profile.json", _sha256(ROOT / "project_state" / "workers" / "proj2_inventory" / "structural_profile.json"),
            "29 occurrences / 28 unique queued tags", "未知词不污染 approved vocabulary",
            "D-ANOM-UNKNOWN-TAGS",
            {"occurrences": import_summary["unknown_tag_count"], "unique": queued_unique},
            "paper_lab.sqlite3:tag_vocabulary[review_status=queued]",
            import_summary["unknown_tag_count"] == 29 and queued_unique == 28,
        ))
        projection = connection.execute(
            "SELECT payload_json FROM paper_lab_event WHERE event_type='component_projection_built' ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        projection_data = json.loads(projection["payload_json"]) if projection else {}
        rows.append(_row(
            "ANOM-010", "known_anomaly", "legacy component library only covers paper 1–86",
            "reference/proj2/data/tag_components.json", _sha256(source / "data" / "tag_components.json"),
            "versioned projection covers all 137 papers", "不覆盖 legacy component snapshot；新增 corrected projection",
            "D-ANOM-COMPONENT-COVERAGE", projection_data,
            "paper_lab.sqlite3:paper_lab_event[component_projection_built]",
            projection_data.get("covered_papers") == 137 and projection_data.get("total_papers") == 137,
        ))
        rows.append(_row(
            "ANOM-011", "known_anomaly", "46 persisted blocks vs builder 34; 12 curated stubs",
            "reference/proj2/data/concept_blocks.json", _sha256(source / "data" / "concept_blocks.json"),
            "46 latest blocks; curated_payload_json separated and preserved", "生成器不再清空 one_liner/my_comment/notes",
            "D-ANOM-CONCEPT-PRESERVE",
            {
                "latest_blocks": int(connection.execute(
                    "SELECT count(DISTINCT legacy_component_id) FROM concept_component WHERE component_kind='concept_block'"
                ).fetchone()[0]),
                "curated_blocks": int(connection.execute(
                    "SELECT count(*) FROM concept_component WHERE component_kind='concept_block' AND curated_payload_json<>'{}'"
                ).fetchone()[0]),
            },
            "paper_lab.sqlite3:concept_component[concept_block]",
            int(connection.execute(
                "SELECT count(DISTINCT legacy_component_id) FROM concept_component WHERE component_kind='concept_block'"
            ).fetchone()[0]) == 46,
        ))

    report = {
        "schema_version": "paper-lab-compatibility-report/v1",
        "row_count": len(rows),
        "pass_count": sum(row["verdict"] == "PASS" for row in rows),
        "fail_count": sum(row["verdict"] == "FAIL" for row in rows),
        "by_kind": {},
        "import_run_id": import_run_id,
    }
    for kind in sorted({row["surface_kind"] for row in rows}):
        subset = [row for row in rows if row["surface_kind"] == kind]
        report["by_kind"][kind] = {
            "rows": len(subset),
            "pass": sum(row["verdict"] == "PASS" for row in subset),
        }
    return rows, report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="执行并生成可重复的 Paper Lab 兼容行为矩阵。",
    )
    parser.parse_args(argv)
    rows, report = build()
    for output in OUTPUTS:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=COLUMNS, delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
    matrix_hash = _sha256(OUTPUTS[0])
    report["matrix_sha256"] = matrix_hash
    report["outputs"] = [str(path) for path in OUTPUTS]
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0 if report["fail_count"] == 0 else 3


if __name__ == "__main__":
    raise SystemExit(main())
