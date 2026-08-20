from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Annotated, Never

import typer

from quant_hub.archive.service import (
    ingest_archive_snapshot,
    initialize_platform,
    query_run,
    result_dict,
)
from quant_hub.config import Settings
from quant_hub.archive.catalog import ArchiveCatalog
from quant_hub.archive.contracts import ActorInput, ArchiveReleaseInput, TopicInput
from quant_hub.archive.discovery import ArchiveDiscoveryScanner
from quant_hub.collaboration.service import ArchiveCollaboration, CommandOutcome
from quant_hub.paper_lab.importer import LegacyProj2Importer
from quant_hub.paper_lab.service import PaperLabService
from quant_hub.paper_lab.compat import query_main, run_main, viewer_main, write_main


app = typer.Typer(
    name="qrh",
    no_args_is_help=True,
    help="Quant Research Hub 正式平台命令行。",
)
archive_app = typer.Typer(help="Archive 研究、release、搜索与页面投影。")
topic_app = typer.Typer(help="研究 Topic 与 Dashboard 状态 command。")
research_app = typer.Typer(help="研究工作状态与显式 completion decision。")
comment_app = typer.Typer(help="持久化研究评论。")
paper_lab_app = typer.Typer(help="迁移后的论文精读、组件与架构设计系统。")
app.add_typer(archive_app, name="archive")
app.add_typer(topic_app, name="topic")
app.add_typer(research_app, name="research")
app.add_typer(comment_app, name="comment")
app.add_typer(paper_lab_app, name="paper-lab")
CLI_SCHEMA_VERSION = "qrh-cli-envelope/v1"


def _settings(project_root: Path | None, archive_root: Path | None, var_root: Path | None) -> Settings:
    return Settings.default(
        project_root=project_root,
        archive_root=archive_root,
        var_root=var_root,
    )


def _fail(error: Exception, *, status: str = "ERROR", exit_code: int = 5) -> Never:
    typer.echo(
        json.dumps(
            {
                "schema_version": CLI_SCHEMA_VERSION,
                "status": status,
                "error_type": type(error).__name__,
                "detail": str(error),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    raise typer.Exit(code=exit_code) from error


def _actor(kind: str, other_name: str | None) -> ActorInput:
    return ActorInput(actor_kind=kind, display_name=other_name)  # type: ignore[arg-type]


def _command_payload(outcome: CommandOutcome) -> dict[str, object]:
    if outcome.ok:
        return {
            "schema_version": CLI_SCHEMA_VERSION,
            "status": "PASS",
            "replayed": outcome.replayed,
            "data": outcome.data or {},
        }
    return {
        "schema_version": CLI_SCHEMA_VERSION,
        "status": "REJECTED",
        "replayed": outcome.replayed,
        "error": {
            "code": outcome.error_code,
            "message": outcome.error_message,
        },
    }


def _emit_command(outcome: CommandOutcome) -> None:
    typer.echo(json.dumps(_command_payload(outcome), ensure_ascii=False, sort_keys=True))
    if not outcome.ok:
        raise typer.Exit(code=4 if outcome.status == 404 else 3)


@paper_lab_app.command("scan")
def paper_lab_scan_command(
    project_root: Annotated[Path | None, typer.Option()] = None,
    archive_root: Annotated[Path | None, typer.Option()] = None,
    var_root: Annotated[Path | None, typer.Option()] = None,
) -> None:
    try:
        report = PaperLabService(_settings(project_root, archive_root, var_root)).scan()
    except Exception as error:
        _fail(error)
    typer.echo(
        json.dumps(
            {"schema_version": CLI_SCHEMA_VERSION, "status": report.status, "report": report.to_dict()},
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    if report.status != "PASS":
        raise typer.Exit(code=3 if report.status == "PARTIAL" else 5)


@paper_lab_app.command("legacy-import")
def paper_lab_import_command(
    source_root: Annotated[Path | None, typer.Option()] = None,
    project_root: Annotated[Path | None, typer.Option()] = None,
    archive_root: Annotated[Path | None, typer.Option()] = None,
    var_root: Annotated[Path | None, typer.Option()] = None,
) -> None:
    try:
        report = LegacyProj2Importer(
            _settings(project_root, archive_root, var_root), source_root
        ).import_all()
    except Exception as error:
        _fail(error)
    typer.echo(
        json.dumps(
            {"schema_version": CLI_SCHEMA_VERSION, "status": report.status, "report": report.to_dict()},
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    if report.status != "PASS":
        raise typer.Exit(code=5)


@paper_lab_app.command("components")
def paper_lab_components_command(
    project_root: Annotated[Path | None, typer.Option()] = None,
    archive_root: Annotated[Path | None, typer.Option()] = None,
    var_root: Annotated[Path | None, typer.Option()] = None,
) -> None:
    try:
        report = PaperLabService(
            _settings(project_root, archive_root, var_root)
        ).rebuild_components()
    except Exception as error:
        _fail(error)
    typer.echo(
        json.dumps(
            {"schema_version": CLI_SCHEMA_VERSION, "status": report.status, "projection": report.to_dict()},
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    if report.status != "PASS":
        raise typer.Exit(code=5)


def _paper_lab_compat_options(
    project_root: Path | None,
    archive_root: Path | None,
    var_root: Path | None,
) -> list[str]:
    result: list[str] = []
    for option, value in (
        ("--project-root", project_root),
        ("--archive-root", archive_root),
        ("--var-root", var_root),
    ):
        if value is not None:
            result.extend((option, str(value)))
    return result


def _paper_lab_compat_exit(code: int) -> None:
    if code:
        raise typer.Exit(code=code)


@paper_lab_app.command("run")
def paper_lab_run_command(
    dry_run: Annotated[bool, typer.Option("--dry-run", help="只发现待处理 PDF，不建立任务")] = False,
    resume: Annotated[bool, typer.Option("--resume", help="从上次失败阶段建立新 attempt")] = False,
    project_root: Annotated[Path | None, typer.Option()] = None,
    archive_root: Annotated[Path | None, typer.Option()] = None,
    var_root: Annotated[Path | None, typer.Option()] = None,
) -> None:
    arguments = _paper_lab_compat_options(project_root, archive_root, var_root)
    if dry_run:
        arguments.append("--dry-run")
    if resume:
        arguments.append("--resume")
    _paper_lab_compat_exit(run_main(arguments))


@paper_lab_app.command("publish")
def paper_lab_publish_command(
    run_id: Annotated[list[str] | None, typer.Option("--run-id")] = None,
    project_root: Annotated[Path | None, typer.Option()] = None,
    archive_root: Annotated[Path | None, typer.Option()] = None,
    var_root: Annotated[Path | None, typer.Option()] = None,
) -> None:
    arguments = _paper_lab_compat_options(project_root, archive_root, var_root)
    for value in run_id or []:
        arguments.extend(("--run-id", value))
    _paper_lab_compat_exit(write_main(arguments))


@paper_lab_app.command("query")
def paper_lab_query_command(
    rating: Annotated[str | None, typer.Option()] = None,
    model: Annotated[str | None, typer.Option()] = None,
    market: Annotated[str | None, typer.Option()] = None,
    after: Annotated[int | None, typer.Option()] = None,
    before: Annotated[int | None, typer.Option()] = None,
    source: Annotated[str | None, typer.Option()] = None,
    keyword: Annotated[str | None, typer.Option()] = None,
    status: Annotated[str | None, typer.Option()] = None,
    project_root: Annotated[Path | None, typer.Option()] = None,
    archive_root: Annotated[Path | None, typer.Option()] = None,
    var_root: Annotated[Path | None, typer.Option()] = None,
) -> None:
    arguments = _paper_lab_compat_options(project_root, archive_root, var_root)
    for option, value in (
        ("--rating", rating), ("--model", model), ("--market", market),
        ("--after", after), ("--before", before), ("--source", source),
        ("--keyword", keyword), ("--status", status),
    ):
        if value is not None:
            arguments.extend((option, str(value)))
    _paper_lab_compat_exit(query_main(arguments))


@paper_lab_app.command("viewer")
def paper_lab_viewer_command(
    host: Annotated[str, typer.Option(help="仅允许 127.0.0.1 或 localhost")] = "127.0.0.1",
    port: Annotated[int, typer.Option()] = 5050,
    project_root: Annotated[Path | None, typer.Option()] = None,
    archive_root: Annotated[Path | None, typer.Option()] = None,
    var_root: Annotated[Path | None, typer.Option()] = None,
) -> None:
    arguments = _paper_lab_compat_options(project_root, archive_root, var_root)
    arguments.extend(("--host", host, "--port", str(port)))
    _paper_lab_compat_exit(viewer_main(arguments))


@app.command("init")
def init_command(
    project_root: Annotated[Path | None, typer.Option(help="quant_platform 根目录")] = None,
    archive_root: Annotated[Path | None, typer.Option(help="只读 Archive 根目录")] = None,
    var_root: Annotated[Path | None, typer.Option(help="可写运行目录")] = None,
) -> None:
    try:
        settings = _settings(project_root, archive_root, var_root)
        applied = initialize_platform(settings)
    except Exception as error:
        _fail(error)
    typer.echo(
        json.dumps(
            {
                "schema_version": CLI_SCHEMA_VERSION,
                "status": "PASS",
                "database": str(settings.database_path),
                "applied_migrations": applied,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )


@app.command("archive-snapshot")
def archive_snapshot_command(
    relative_path: Annotated[str, typer.Argument(help="Archive 根内相对 Markdown 路径")],
    project_root: Annotated[Path | None, typer.Option(help="quant_platform 根目录")] = None,
    archive_root: Annotated[Path | None, typer.Option(help="只读 Archive 根目录")] = None,
    var_root: Annotated[Path | None, typer.Option(help="可写运行目录")] = None,
) -> None:
    try:
        settings = _settings(project_root, archive_root, var_root)
        result = ingest_archive_snapshot(settings, relative_path)
    except Exception as error:
        _fail(error)
    typer.echo(
        json.dumps(
            {"schema_version": CLI_SCHEMA_VERSION, "status": "PASS", **result_dict(result)},
            ensure_ascii=False,
            sort_keys=True,
        )
    )


@app.command("run-show")
def run_show_command(
    run_id: Annotated[str, typer.Argument(help="pipeline run public ID")],
    project_root: Annotated[Path | None, typer.Option(help="quant_platform 根目录")] = None,
    archive_root: Annotated[Path | None, typer.Option(help="只读 Archive 根目录")] = None,
    var_root: Annotated[Path | None, typer.Option(help="可写运行目录")] = None,
) -> None:
    try:
        settings = _settings(project_root, archive_root, var_root)
        result = query_run(settings, run_id)
    except KeyError as error:
        _fail(error, status="NOT_FOUND", exit_code=4)
    except Exception as error:
        _fail(error)
    typer.echo(
        json.dumps(
            {"schema_version": CLI_SCHEMA_VERSION, "status": "PASS", **result},
            ensure_ascii=False,
            sort_keys=True,
        )
    )


@archive_app.command("init")
def archive_init_command(
    project_root: Annotated[Path | None, typer.Option(help="quant_platform 根目录")] = None,
    archive_root: Annotated[Path | None, typer.Option(help="只读 Archive 根目录")] = None,
    var_root: Annotated[Path | None, typer.Option(help="可写运行目录")] = None,
) -> None:
    try:
        settings = _settings(project_root, archive_root, var_root)
        applied = ArchiveCatalog(settings).initialize()
    except Exception as error:
        _fail(error)
    typer.echo(json.dumps({"schema_version": CLI_SCHEMA_VERSION, "status": "PASS", "databases": applied}, ensure_ascii=False, sort_keys=True))


@archive_app.command("scan")
def archive_scan_command(
    project_root: Annotated[Path | None, typer.Option(help="quant_platform 根目录")] = None,
    archive_root: Annotated[Path | None, typer.Option(help="只读 Archive 根目录")] = None,
    var_root: Annotated[Path | None, typer.Option(help="可写运行目录")] = None,
) -> None:
    """安全发现 Markdown 并登记不可变快照；不推断研究身份或自动发布。"""

    try:
        settings = _settings(project_root, archive_root, var_root)
        report = ArchiveDiscoveryScanner(settings).scan()
    except Exception as error:
        _fail(error)
    typer.echo(
        json.dumps(
            {
                "schema_version": CLI_SCHEMA_VERSION,
                "status": report.status,
                "report": report.to_dict(),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    if report.status != "PASS":
        raise typer.Exit(code=3 if report.status == "PARTIAL" else 5)


@archive_app.command("apply-release")
def archive_apply_release_command(
    manifest: Annotated[Path, typer.Argument(help="UTF-8 ArchiveReleaseInput JSON")],
    project_root: Annotated[Path | None, typer.Option(help="quant_platform 根目录")] = None,
    archive_root: Annotated[Path | None, typer.Option(help="只读 Archive 根目录")] = None,
    var_root: Annotated[Path | None, typer.Option(help="可写运行目录")] = None,
) -> None:
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        release = ArchiveReleaseInput.model_validate(payload)
        settings = _settings(project_root, archive_root, var_root)
        result = ArchiveCatalog(settings).publish_release(release)
    except Exception as error:
        _fail(error)
    typer.echo(json.dumps({"schema_version": CLI_SCHEMA_VERSION, "status": "PASS", **asdict(result)}, ensure_ascii=False, sort_keys=True))


@archive_app.command("list")
def archive_list_command(
    project_root: Annotated[Path | None, typer.Option(help="quant_platform 根目录")] = None,
    archive_root: Annotated[Path | None, typer.Option(help="只读 Archive 根目录")] = None,
    var_root: Annotated[Path | None, typer.Option(help="可写运行目录")] = None,
) -> None:
    try:
        settings = _settings(project_root, archive_root, var_root)
        rows = ArchiveCatalog(settings).list_research()
    except Exception as error:
        _fail(error)
    typer.echo(json.dumps({"schema_version": CLI_SCHEMA_VERSION, "status": "PASS", "research": rows}, ensure_ascii=False, sort_keys=True))


@archive_app.command("search")
def archive_search_command(
    query: Annotated[str, typer.Argument(help="中文或英文检索词")],
    project_root: Annotated[Path | None, typer.Option(help="quant_platform 根目录")] = None,
    archive_root: Annotated[Path | None, typer.Option(help="只读 Archive 根目录")] = None,
    var_root: Annotated[Path | None, typer.Option(help="可写运行目录")] = None,
) -> None:
    try:
        settings = _settings(project_root, archive_root, var_root)
        rows = ArchiveCatalog(settings).search(query)
    except Exception as error:
        _fail(error)
    typer.echo(json.dumps({"schema_version": CLI_SCHEMA_VERSION, "status": "PASS", "results": rows}, ensure_ascii=False, sort_keys=True))


@topic_app.command("create")
def topic_create_command(
    topic_key: Annotated[str, typer.Argument()],
    title: Annotated[str, typer.Argument()],
    idempotency_key: Annotated[str, typer.Option("--idempotency-key")],
    manual_order: Annotated[int, typer.Option()] = 100,
    actor_kind: Annotated[str, typer.Option()] = "zhang_zhengze",
    other_name: Annotated[str | None, typer.Option()] = None,
    project_root: Annotated[Path | None, typer.Option()] = None,
    archive_root: Annotated[Path | None, typer.Option()] = None,
    var_root: Annotated[Path | None, typer.Option()] = None,
) -> None:
    try:
        settings = _settings(project_root, archive_root, var_root)
        outcome = ArchiveCollaboration(settings).create_topic(
            TopicInput(topic_key=topic_key, title=title, manual_order=manual_order),
            _actor(actor_kind, other_name),
            idempotency_key=idempotency_key,
        )
    except Exception as error:
        _fail(error)
    _emit_command(outcome)


@topic_app.command("link-research")
def topic_link_research_command(
    topic_id: Annotated[str, typer.Argument()],
    research_id: Annotated[str, typer.Argument()],
    provenance_urn: Annotated[str, typer.Option("--provenance-urn")],
    idempotency_key: Annotated[str, typer.Option("--idempotency-key")],
    link_kind: Annotated[str, typer.Option()] = "primary",
    dashboard_primary: Annotated[bool, typer.Option()] = False,
    display_rank: Annotated[int, typer.Option()] = 100,
    actor_kind: Annotated[str, typer.Option()] = "zhang_zhengze",
    other_name: Annotated[str | None, typer.Option()] = None,
    project_root: Annotated[Path | None, typer.Option()] = None,
    archive_root: Annotated[Path | None, typer.Option()] = None,
    var_root: Annotated[Path | None, typer.Option()] = None,
) -> None:
    try:
        settings = _settings(project_root, archive_root, var_root)
        outcome = ArchiveCollaboration(settings).link_topic_research(
            topic_id,
            research_id,
            _actor(actor_kind, other_name),
            link_kind=link_kind,  # type: ignore[arg-type]
            dashboard_primary=dashboard_primary,
            display_rank=display_rank,
            provenance_urn=provenance_urn,
            idempotency_key=idempotency_key,
        )
    except Exception as error:
        _fail(error)
    _emit_command(outcome)


@topic_app.command("set-state")
def topic_set_state_command(
    topic_id: Annotated[str, typer.Argument()],
    state: Annotated[str, typer.Argument()],
    idempotency_key: Annotated[str, typer.Option("--idempotency-key")],
    note: Annotated[str | None, typer.Option()] = None,
    actor_kind: Annotated[str, typer.Option()] = "zhang_zhengze",
    other_name: Annotated[str | None, typer.Option()] = None,
    project_root: Annotated[Path | None, typer.Option()] = None,
    archive_root: Annotated[Path | None, typer.Option()] = None,
    var_root: Annotated[Path | None, typer.Option()] = None,
) -> None:
    try:
        settings = _settings(project_root, archive_root, var_root)
        outcome = ArchiveCollaboration(settings).set_topic_state(
            topic_id,
            state,  # type: ignore[arg-type]
            note,
            _actor(actor_kind, other_name),
            idempotency_key=idempotency_key,
        )
    except Exception as error:
        _fail(error)
    _emit_command(outcome)


@research_app.command("set-work-state")
def research_set_work_state_command(
    research_id: Annotated[str, typer.Argument()],
    state: Annotated[str, typer.Argument()],
    idempotency_key: Annotated[str, typer.Option("--idempotency-key")],
    note: Annotated[str | None, typer.Option()] = None,
    actor_kind: Annotated[str, typer.Option()] = "zhang_zhengze",
    other_name: Annotated[str | None, typer.Option()] = None,
    project_root: Annotated[Path | None, typer.Option()] = None,
    archive_root: Annotated[Path | None, typer.Option()] = None,
    var_root: Annotated[Path | None, typer.Option()] = None,
) -> None:
    try:
        settings = _settings(project_root, archive_root, var_root)
        outcome = ArchiveCollaboration(settings).set_work_state(
            research_id,
            state,  # type: ignore[arg-type]
            note,
            _actor(actor_kind, other_name),
            idempotency_key=idempotency_key,
        )
    except Exception as error:
        _fail(error)
    _emit_command(outcome)


@research_app.command("complete")
def research_complete_command(
    research_id: Annotated[str, typer.Argument()],
    research_release_id: Annotated[str, typer.Argument()],
    reason: Annotated[str, typer.Option("--reason")],
    idempotency_key: Annotated[str, typer.Option("--idempotency-key")],
    actor_kind: Annotated[str, typer.Option()] = "zhang_zhengze",
    other_name: Annotated[str | None, typer.Option()] = None,
    project_root: Annotated[Path | None, typer.Option()] = None,
    archive_root: Annotated[Path | None, typer.Option()] = None,
    var_root: Annotated[Path | None, typer.Option()] = None,
) -> None:
    try:
        settings = _settings(project_root, archive_root, var_root)
        outcome = ArchiveCollaboration(settings).complete_research(
            research_id,
            research_release_id,
            reason=reason,
            actor=_actor(actor_kind, other_name),
            idempotency_key=idempotency_key,
        )
    except Exception as error:
        _fail(error)
    _emit_command(outcome)


@research_app.command("revoke-completion")
def research_revoke_completion_command(
    research_id: Annotated[str, typer.Argument()],
    target_decision_id: Annotated[str, typer.Argument()],
    reason: Annotated[str, typer.Option("--reason")],
    idempotency_key: Annotated[str, typer.Option("--idempotency-key")],
    actor_kind: Annotated[str, typer.Option()] = "zhang_zhengze",
    other_name: Annotated[str | None, typer.Option()] = None,
    project_root: Annotated[Path | None, typer.Option()] = None,
    archive_root: Annotated[Path | None, typer.Option()] = None,
    var_root: Annotated[Path | None, typer.Option()] = None,
) -> None:
    try:
        settings = _settings(project_root, archive_root, var_root)
        outcome = ArchiveCollaboration(settings).revoke_completion(
            research_id,
            target_decision_id,
            reason=reason,
            actor=_actor(actor_kind, other_name),
            idempotency_key=idempotency_key,
        )
    except Exception as error:
        _fail(error)
    _emit_command(outcome)


@comment_app.command("create")
def comment_create_command(
    research_id: Annotated[str, typer.Argument()],
    content: Annotated[str, typer.Argument()],
    idempotency_key: Annotated[str, typer.Option("--idempotency-key")],
    actor_kind: Annotated[str, typer.Option()] = "zhang_zhengze",
    other_name: Annotated[str | None, typer.Option()] = None,
    project_root: Annotated[Path | None, typer.Option()] = None,
    archive_root: Annotated[Path | None, typer.Option()] = None,
    var_root: Annotated[Path | None, typer.Option()] = None,
) -> None:
    try:
        settings = _settings(project_root, archive_root, var_root)
        outcome = ArchiveCollaboration(settings).create_comment(
            research_id,
            _actor(actor_kind, other_name),
            content,
            idempotency_key=idempotency_key,
        )
    except Exception as error:
        _fail(error)
    _emit_command(outcome)


@comment_app.command("list")
def comment_list_command(
    research_id: Annotated[str, typer.Argument()],
    project_root: Annotated[Path | None, typer.Option()] = None,
    archive_root: Annotated[Path | None, typer.Option()] = None,
    var_root: Annotated[Path | None, typer.Option()] = None,
) -> None:
    try:
        settings = _settings(project_root, archive_root, var_root)
        comments = ArchiveCollaboration(settings).list_comments(research_id)
    except Exception as error:
        _fail(error)
    typer.echo(json.dumps({"schema_version": CLI_SCHEMA_VERSION, "status": "PASS", "comments": comments}, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    app()
