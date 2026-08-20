from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
import sqlite3

from quant_hub.config import Settings
from quant_hub.platform.db import connect_database
from quant_hub.platform.migrations import migrate_up


def initialize_research_workspace_database(
    settings: Settings,
    *,
    database_path: Path | None = None,
) -> list[int]:
    settings.ensure_runtime_directories()
    path = database_path or settings.research_workspace_database_path
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = connect_database(path)
    try:
        return migrate_up(connection, settings.research_workspace_migration_root)
    finally:
        connection.close()


@contextmanager
def research_workspace_connection(
    settings: Settings,
    *,
    database_path: Path | None = None,
) -> Iterator[sqlite3.Connection]:
    settings.ensure_runtime_directories()
    path = database_path or settings.research_workspace_database_path
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = connect_database(path)
    try:
        migrate_up(connection, settings.research_workspace_migration_root)
        yield connection
    finally:
        connection.close()


__all__ = [
    "initialize_research_workspace_database",
    "research_workspace_connection",
]
