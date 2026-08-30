from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import sqlite3

from quant_hub.config import (
    ConfigurationError,
    Settings,
    ensure_no_reparse_components,
)
from quant_hub.platform.db import connect_database, connection_is_read_only
from quant_hub.platform.migrations import migrate_up


def initialize_paper_lab_database(settings: Settings) -> list[int]:
    settings.ensure_runtime_directories()
    for directory in (settings.paper_lab_asset_root, settings.paper_lab_drop_root):
        if settings.read_only_runtime:
            ensure_no_reparse_components(directory)
            if not directory.is_dir():
                raise ConfigurationError(
                    f"read-only Paper Lab directory is unavailable: {directory}"
                )
        else:
            directory.mkdir(parents=True, exist_ok=True)
    connection = connect_database(settings.paper_lab_database_path)
    try:
        if connection_is_read_only(connection):
            return []
        return migrate_up(connection, settings.paper_lab_migration_root)
    finally:
        connection.close()


@contextmanager
def paper_lab_connection(settings: Settings) -> Iterator[sqlite3.Connection]:
    initialize_paper_lab_database(settings)
    connection = connect_database(settings.paper_lab_database_path)
    try:
        yield connection
    finally:
        connection.close()
