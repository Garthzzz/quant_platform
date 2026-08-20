from __future__ import annotations

from contextlib import contextmanager
from collections.abc import Iterator
import sqlite3

from quant_hub.config import Settings
from quant_hub.platform.db import connect_database, connection_is_read_only
from quant_hub.platform.migrations import migrate_up


def initialize_archive_database(settings: Settings) -> list[int]:
    settings.ensure_runtime_directories()
    connection = connect_database(settings.archive_database_path)
    try:
        if connection_is_read_only(connection):
            return []
        return migrate_up(connection, settings.archive_migration_root)
    finally:
        connection.close()


@contextmanager
def archive_connection(settings: Settings) -> Iterator[sqlite3.Connection]:
    settings.ensure_runtime_directories()
    connection = connect_database(settings.archive_database_path)
    try:
        if not connection_is_read_only(connection):
            migrate_up(connection, settings.archive_migration_root)
        yield connection
    finally:
        connection.close()
