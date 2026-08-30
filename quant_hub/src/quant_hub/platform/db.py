from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
import os
from pathlib import Path
import sqlite3
import stat
from typing import Any
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


# The exact-runtime canary installs the live process-local lease itself; callers
# cannot supply a callback or a serializable claim.  Connections opened while
# this scope is active fence every statement and COMMIT against that exact live
# lease.  The scope remains private because it is an implementation bridge
# between the fixed runner and the ordinary application transaction surface.
_EXACT_RUNTIME_WRITER_LEASE: ContextVar[object | None] = ContextVar(
    "quant_hub_exact_runtime_writer_lease", default=None
)


class _ExactRuntimeWriterFencedConnection(sqlite3.Connection):
    """SQLite connection whose statements and COMMIT stay under one live lease."""

    __slots__ = ("_writer_lease",)

    def _bind_writer_lease(self, lease: object) -> None:
        if hasattr(self, "_writer_lease"):
            raise RuntimeError("exact runtime writer lease 已绑定")
        self._writer_lease = lease
        self._checkpoint()

    def _checkpoint(self) -> None:
        self._writer_lease._canary_checkpoint()  # type: ignore[attr-defined]

    def execute(self, sql: str, parameters: Any = (), /) -> sqlite3.Cursor:
        self._checkpoint()
        cursor = super().execute(sql, parameters)
        self._checkpoint()
        return cursor

    def executemany(self, sql: str, parameters: Any, /) -> sqlite3.Cursor:
        self._checkpoint()
        cursor = super().executemany(sql, parameters)
        self._checkpoint()
        return cursor

    def executescript(self, sql_script: str, /) -> sqlite3.Cursor:
        self._checkpoint()
        cursor = super().executescript(sql_script)
        self._checkpoint()
        return cursor

    def commit(self) -> None:
        # A failed pre-COMMIT checkpoint propagates into immediate_transaction,
        # whose exception arm rolls the still-live transaction back.
        self._checkpoint()
        super().commit()
        self._checkpoint()

    def close(self) -> None:
        # Lease drift must not leak an open SQLite handle while the original
        # checkpoint error unwinds.  Always close, then propagate the failure.
        checkpoint_error: BaseException | None = None
        try:
            self._checkpoint()
        except BaseException as error:
            checkpoint_error = error
        try:
            super().close()
        finally:
            if checkpoint_error is not None:
                raise checkpoint_error
        self._checkpoint()


@contextmanager
def _exact_runtime_writer_lease_transaction_scope(
    lease: object, *, production: bool
) -> Iterator[None]:
    """Bind application connections to an exact live lease without a callback."""

    from quant_hub.ops.local_windows_writer_lease_holder import (
        LockedWindowsWriterLease,
        _TestOnlyLockedWriterLease,
    )

    expected = LockedWindowsWriterLease if production else _TestOnlyLockedWriterLease
    if type(lease) is not expected:
        raise TypeError("exact runtime transaction scope lease provenance 无效")
    if _EXACT_RUNTIME_WRITER_LEASE.get() is not None:
        raise RuntimeError("exact runtime transaction scope 不允许嵌套")
    lease._canary_checkpoint()  # type: ignore[attr-defined]
    token = _EXACT_RUNTIME_WRITER_LEASE.set(lease)
    try:
        yield
    finally:
        _EXACT_RUNTIME_WRITER_LEASE.reset(token)


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
    writer_lease = _EXACT_RUNTIME_WRITER_LEASE.get()

    def connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        if writer_lease is None:
            return sqlite3.connect(*args, **kwargs)
        writer_lease._canary_checkpoint()  # type: ignore[attr-defined]
        connection = sqlite3.connect(
            *args, **kwargs, factory=_ExactRuntimeWriterFencedConnection
        )
        if type(connection) is not _ExactRuntimeWriterFencedConnection:
            sqlite3.Connection.close(connection)
            raise RuntimeError("exact runtime SQLite connection factory 漂移")
        try:
            connection._bind_writer_lease(writer_lease)
        except BaseException:
            sqlite3.Connection.close(connection)
            raise
        return connection

    if _configured_read_only(path):
        _validate_database_paths(path, require_database=True)
        uri = (
            f"file:{quote(path.resolve(strict=True).as_posix(), safe='/:')}"
            "?mode=ro&immutable=1"
        )
        connection = connect(
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
        connection = connect(path, timeout=10.0, isolation_level=None)
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
