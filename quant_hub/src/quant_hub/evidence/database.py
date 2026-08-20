from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import sqlite3

from quant_hub.config import Settings
from quant_hub.platform.db import connect_database, connection_is_read_only
from quant_hub.platform.migrations import migrate_up


def initialize_evidence_database(settings: Settings) -> list[int]:
    """初始化物理隔离的 Archive Evidence 业务库。"""

    settings.ensure_runtime_directories()
    connection = connect_database(settings.research_papers_database_path)
    try:
        if connection_is_read_only(connection):
            return []
        return migrate_up(connection, settings.research_papers_migration_root)
    finally:
        connection.close()


@contextmanager
def evidence_connection(settings: Settings) -> Iterator[sqlite3.Connection]:
    settings.ensure_runtime_directories()
    connection = connect_database(settings.research_papers_database_path)
    try:
        if not connection_is_read_only(connection):
            migrate_up(connection, settings.research_papers_migration_root)
        yield connection
    finally:
        connection.close()
