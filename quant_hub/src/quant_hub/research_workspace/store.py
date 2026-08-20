"""Integrity checks and update-safe backups for the research workspace store."""

from __future__ import annotations

from datetime import UTC, datetime
import os
from pathlib import Path
import sqlite3
from typing import Any

from quant_hub.config import Settings
from quant_hub.platform.db import connect_database
from quant_hub.research_workspace.database import (
    initialize_research_workspace_database,
)


RESEARCH_WORKSPACE_DATABASE_NAME = "research_workspace.sqlite3"


def research_workspace_store_state(
    settings: Settings,
    *,
    database_path: Path | None = None,
) -> dict[str, Any]:
    path = database_path or settings.research_workspace_database_path
    initialize_research_workspace_database(settings, database_path=path)
    connection = connect_database(path)
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        if integrity is None or integrity[0] != "ok" or violations:
            raise RuntimeError("研究工作区持久库完整性检查失败")
        return {
            "nodes": int(
                connection.execute(
                    "SELECT count(*) FROM research_workspace_node"
                ).fetchone()[0]
            ),
            "present_nodes": int(
                connection.execute(
                    """
                    SELECT count(*) FROM research_workspace_node
                    WHERE source_state='present'
                    """
                ).fetchone()[0]
            ),
            "comments": int(
                connection.execute(
                    "SELECT count(*) FROM research_workspace_comment"
                ).fetchone()[0]
            ),
            "active_comments": int(
                connection.execute(
                    """
                    SELECT count(*) FROM research_workspace_comment
                    WHERE deleted_at IS NULL
                    """
                ).fetchone()[0]
            ),
            "events": int(
                connection.execute(
                    "SELECT count(*) FROM research_workspace_event"
                ).fetchone()[0]
            ),
            "sync_runs": int(
                connection.execute(
                    "SELECT count(*) FROM research_workspace_sync_run"
                ).fetchone()[0]
            ),
        }
    finally:
        connection.close()


def backup_research_workspace_store(
    settings: Settings,
    backup_root: Path,
    *,
    database_path: Path | None = None,
) -> Path | None:
    path = database_path or settings.research_workspace_database_path
    if not path.is_file():
        return None
    backup_root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S_%fZ")
    destination = backup_root / f"research-workspace-{stamp}.sqlite3"
    temporary = destination.with_suffix(".tmp")
    source = sqlite3.connect(
        f"file:{path.resolve().as_posix()}?mode=ro", uri=True, timeout=10.0
    )
    target = sqlite3.connect(temporary, timeout=10.0)
    try:
        source.backup(target)
        target.commit()
        integrity = target.execute("PRAGMA integrity_check").fetchone()
        violations = target.execute("PRAGMA foreign_key_check").fetchall()
        if integrity is None or integrity[0] != "ok" or violations:
            raise RuntimeError("研究工作区备份完整性检查失败")
    finally:
        target.close()
        source.close()
    os.replace(temporary, destination)
    return destination


__all__ = [
    "RESEARCH_WORKSPACE_DATABASE_NAME",
    "backup_research_workspace_store",
    "research_workspace_store_state",
]
