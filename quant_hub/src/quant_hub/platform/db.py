from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import stat
from urllib.parse import quote

from quant_hub.config import (
    ConfigurationError,
    ensure_no_reparse_components,
    stat_is_reparse_point,
)


def _database_paths(path: Path) -> tuple[Path, Path, Path, Path]:
    return (
        path,
        Path(str(path) + "-journal"),
        Path(str(path) + "-wal"),
        Path(str(path) + "-shm"),
    )


def _validate_database_paths(path: Path, *, require_database: bool = False) -> None:
    ensure_no_reparse_components(path.parent)
    for candidate in _database_paths(path):
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            if candidate == path and require_database:
                raise ConfigurationError(f"SQLite database disappeared during connect: {path}")
            # SQLite owns these transient files; another connection may remove
            # WAL/SHM/journal between two legitimate observations.
            continue
        if (
            stat_is_reparse_point(info)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
        ):
            raise ConfigurationError(
                "SQLite database or sidecar is not a regular, non-reparse, "
                f"non-hard-linked file: {candidate}"
            )


READ_ONLY_DATABASE_ROOT_ENV = "QUANT_HUB_READ_ONLY_DATABASE_ROOT"


def _configured_read_only(path: Path) -> bool:
    raw_root = os.environ.get(READ_ONLY_DATABASE_ROOT_ENV, "").strip()
    if not raw_root:
        return False
    root = Path(raw_root).resolve(strict=True)
    resolved = path.resolve(strict=False)
    ensure_no_reparse_components(root)
    ensure_no_reparse_components(resolved)
    try:
        resolved.relative_to(root)
    except ValueError:
        return False
    return True


def connection_is_read_only(connection: sqlite3.Connection) -> bool:
    return bool(connection.execute("PRAGMA query_only").fetchone()[0])


def connect_database(path: Path) -> sqlite3.Connection:
    path = path.absolute()
    ensure_no_reparse_components(path.parent)
    if _configured_read_only(path):
        _validate_database_paths(path, require_database=True)
        uri = (
            f"file:{quote(path.resolve(strict=True).as_posix(), safe='/:')}"
            "?mode=ro&immutable=1"
        )
        connection = sqlite3.connect(
            uri,
            uri=True,
            timeout=10.0,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA query_only = ON")
        _validate_database_paths(path, require_database=True)
        return connection
    path.parent.mkdir(parents=True, exist_ok=True)
    ensure_no_reparse_components(path.parent)
    _validate_database_paths(path)
    try:
        connection = sqlite3.connect(path, timeout=10.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        _validate_database_paths(path, require_database=True)
    except BaseException:
        if "connection" in locals():
            connection.close()
        raise
    return connection


@contextmanager
def immediate_transaction(connection: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    if connection.in_transaction:
        raise RuntimeError("nested platform transaction is not allowed")
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield connection
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()


def utc_now() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
