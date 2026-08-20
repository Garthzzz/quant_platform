from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from quant_hub.config import Settings
from quant_hub.platform.db import connect_database
from quant_hub.platform.migrations import migrate_up
from quant_hub.platform.objects import ObjectStore
from quant_hub.platform.workflow import RegistrationResult, inspect_run, register_archive_snapshot
from .source_reader import ReadOnlyArchiveSource


def initialize_platform(settings: Settings) -> list[int]:
    settings.ensure_runtime_directories()
    connection = connect_database(settings.database_path)
    try:
        return migrate_up(connection, settings.migration_root)
    finally:
        connection.close()


def ingest_archive_snapshot(settings: Settings, relative_path: str | Path) -> RegistrationResult:
    settings.ensure_runtime_directories()
    snapshot = ReadOnlyArchiveSource(settings.archive_root).snapshot(relative_path)
    stored = ObjectStore(settings.object_root).put_bytes(snapshot.content)
    connection = connect_database(settings.database_path)
    try:
        migrate_up(connection, settings.migration_root)
        return register_archive_snapshot(connection, snapshot, stored, ObjectStore(settings.object_root))
    finally:
        connection.close()


def result_dict(result: RegistrationResult) -> dict[str, object]:
    return asdict(result)


def query_run(settings: Settings, run_id: str) -> dict[str, object]:
    connection = connect_database(settings.database_path)
    try:
        migrate_up(connection, settings.migration_root)
        return inspect_run(connection, run_id)
    finally:
        connection.close()
