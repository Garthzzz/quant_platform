from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import sys
import uuid

from quant_hub.app import create_app
from quant_hub.config import Settings
from quant_hub.platform.db import immediate_transaction, utc_now
from .database import paper_lab_connection
from .importer import LegacyProj2Importer
from .service import PaperLabService
from .web import register_paper_lab


ENVELOPE_VERSION = "paper-lab-compat/v1"


def _emit(status: str, **payload: object) -> None:
    print(json.dumps(
        {"schema_version": ENVELOPE_VERSION, "status": status, **payload},
        ensure_ascii=False,
        sort_keys=True,
    ))


def _write_json_report(path: Path, payload: dict[str, object]) -> None:
    destination = path.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp-{uuid.uuid4().hex}")
    rendered = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _add_runtime_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--project-root", type=Path, help="quant_platform 项目根目录")
    parser.add_argument("--archive-root", type=Path, help="只读 Archive 根目录")
    parser.add_argument("--var-root", type=Path, help="目标实例的可写运行目录")


def _settings(args: argparse.Namespace) -> Settings:
    return Settings.default(
        project_root=args.project_root,
        archive_root=args.archive_root,
        var_root=args.var_root,
    )


def scan_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="发现 paper_lab/papers 中的 PDF；纯读、不改名。")
    _add_runtime_options(parser)
    args = parser.parse_args(argv)
    report = PaperLabService(_settings(args)).scan()
    _emit(report.status, report=report.to_dict())
    return 0 if report.status == "PASS" else 3


def _write_task_manifest(settings: Settings, data: dict[str, object]) -> Path:
    root = settings.paper_lab_asset_root.parent / "tasks"
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{data['run_id']}.json"
    temporary = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex}")
    payload = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return path


def run_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="登记论文并建立可恢复的 Codex 精读任务。")
    _add_runtime_options(parser)
    parser.add_argument("--dry-run", action="store_true", help="只显示待登记 PDF，不依赖模型 CLI")
    parser.add_argument("--resume", action="store_true", help="为失败/待复核任务建立下一 attempt")
    args = parser.parse_args(argv)
    settings = _settings(args)
    service = PaperLabService(settings)
    report = service.scan()
    if args.dry_run:
        _emit(report.status, dry_run=True, report=report.to_dict())
        return 0 if report.status == "PASS" else 3
    registrations = service.register_all()
    tasks = []
    for registration in registrations:
        if registration.status == "quarantined":
            continue
        outcome = service.queue_reading(registration.paper_id, resume=args.resume)
        task = {
            "schema_version": "paper-lab-codex-task/v1",
            "run_id": outcome.run_id,
            "paper_id": registration.paper_id,
            "paper_version_id": registration.paper_version_id,
            "workflow_version": "paper-reading/v1",
            "required_phases": ["problem", "method", "experiment", "synthesis"],
            "execution_contract": {
                "claim": "PaperLabService.claim_run(run_id)",
                "execute": "python quant_hub/tools/paper_lab_execute.py --task <manifest_path>",
                "submit": "PaperLabService.submit_phase(...) with source locators",
                "review": "independent reviewer must call review_run",
                "publish": "publish_run accepts only releasable runs",
            },
            "status": outcome.status,
            "attempt": outcome.attempt,
        }
        task["manifest_path"] = str(_write_task_manifest(settings, task))
        tasks.append(task)
    _emit(
        "PASS" if report.status == "PASS" else "PARTIAL",
        registrations=[asdict(item) for item in registrations],
        tasks=tasks,
        durable_queue=True,
    )
    return 0 if report.status == "PASS" else 3


def write_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="发布已通过独立审核的 reading run；不再全量 JSON→DB 双写。"
    )
    _add_runtime_options(parser)
    parser.add_argument("--run-id", action="append", default=[], help="只发布指定 releasable run")
    args = parser.parse_args(argv)
    service = PaperLabService(_settings(args))
    with paper_lab_connection(service.settings) as connection:
        if args.run_id:
            placeholders = ",".join("?" for _ in args.run_id)
            rows = connection.execute(
                f"SELECT run_id FROM reading_run WHERE status='releasable' AND run_id IN ({placeholders})",
                args.run_id,
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT run_id FROM reading_run WHERE status='releasable' ORDER BY created_at"
            ).fetchall()
        awaiting = int(connection.execute(
            "SELECT count(*) FROM reading_run WHERE status='awaiting_review'"
        ).fetchone()[0])
    published = [asdict(service.publish_run(row["run_id"])) for row in rows]
    projection = service.rebuild_components().to_dict()
    _emit("PASS", published=published, awaiting_independent_review=awaiting, projection=projection)
    return 0


def query_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Query Paper Lab")
    _add_runtime_options(parser)
    parser.add_argument("--rating")
    parser.add_argument("--model")
    parser.add_argument("--market")
    parser.add_argument("--after", type=int)
    parser.add_argument("--before", type=int)
    parser.add_argument("--source")
    parser.add_argument("--keyword")
    parser.add_argument("--status")
    args = parser.parse_args(argv)
    rows = PaperLabService(_settings(args)).list_papers(
        rating=args.rating,
        model=args.model,
        market=args.market,
        after=args.after,
        before=args.before,
        source=args.source,
        keyword=args.keyword,
        status=args.status,
        limit=1000,
    )
    if not rows:
        print("No results.")
        return 0
    print(f"{'ID':<8} | {'Title':<40} | {'Model Type':<28} | {'Rating':<12} | Years")
    print("-" * 112)
    for row in rows:
        title = str(row.get("title") or "")[:40]
        model = str(row.get("model_type") or "")[:28]
        rating = str(row.get("rating") or "").split("—", 1)[0].strip()[:12]
        years = f"{row.get('start_year') or '?'}-{row.get('end_year') or '?'}"
        print(f"{str(row.get('legacy_id') or ''):<8} | {title:<40} | {model:<28} | {rating:<12} | {years}")
    print(f"\n--- {len(rows)} papers ---")
    return 0


def component_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="增量重建 Paper Lab 组件与积木投影。")
    _add_runtime_options(parser)
    args = parser.parse_args(argv)
    report = PaperLabService(_settings(args)).rebuild_components()
    _emit(report.status, projection=report.to_dict())
    return 0 if report.status == "PASS" else 3


def legacy_import_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="从只读 reference/proj2 全量导入历史论文系统。")
    _add_runtime_options(parser)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--report", type=Path, help="可选 UTF-8/LF JSON 回放报告")
    args = parser.parse_args(argv)
    report = LegacyProj2Importer(_settings(args), args.source_root).import_all()
    envelope: dict[str, object] = {
        "schema_version": ENVELOPE_VERSION,
        "status": report.status,
        "report": report.to_dict(),
    }
    if args.report is not None:
        _write_json_report(args.report, envelope)
    _emit(report.status, report=report.to_dict())
    return 0 if report.status == "PASS" else 5


def viewer_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="启动统一 Quant Research Hub（含 Paper Lab）。")
    _add_runtime_options(parser)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5050)
    args = parser.parse_args(argv)
    if args.host not in {"127.0.0.1", "localhost"}:
        raise SystemExit("compat viewer only permits loopback host")
    settings = _settings(args)
    app = create_app(settings)
    register_paper_lab(app, settings)
    app.run(host=args.host, port=args.port, debug=False)
    return 0


def dispatch(command: str, argv: list[str] | None = None) -> int:
    functions = {
        "scan": scan_main,
        "run": run_main,
        "write": write_main,
        "query": query_main,
        "component": component_main,
        "legacy-import": legacy_import_main,
        "viewer": viewer_main,
    }
    try:
        return functions[command](argv)
    except Exception as error:
        _emit("ERROR", error_type=type(error).__name__, detail=str(error))
        return 5


def entry(command: str) -> None:
    raise SystemExit(dispatch(command, sys.argv[1:]))
