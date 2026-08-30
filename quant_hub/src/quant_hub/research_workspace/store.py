"""Integrity checks for the current research workspace store."""

from __future__ import annotations

from pathlib import Path
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


__all__ = [
    "RESEARCH_WORKSPACE_DATABASE_NAME",
    "research_workspace_store_state",
]
