from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import sqlite3

from .db import immediate_transaction, utc_now


_MIGRATION_RE = re.compile(r"^(?P<version>[0-9]{4})_(?P<name>[a-z0-9_]+)\.up\.sql$")


class MigrationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    name: str
    up_path: Path
    down_path: Path
    up_sha256: str
    down_sha256: str


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def discover_migrations(root: Path) -> list[Migration]:
    migrations: list[Migration] = []
    seen: set[int] = set()
    for up_path in sorted(root.glob("*.up.sql")):
        match = _MIGRATION_RE.fullmatch(up_path.name)
        if match is None:
            raise MigrationError(f"invalid migration filename: {up_path.name}")
        version = int(match.group("version"))
        if version in seen:
            raise MigrationError(f"duplicate migration version: {version}")
        seen.add(version)
        name = match.group("name")
        down_path = root / f"{version:04d}_{name}.down.sql"
        if not down_path.is_file():
            raise MigrationError(f"missing down migration: {down_path.name}")
        migrations.append(
            Migration(
                version=version,
                name=name,
                up_path=up_path,
                down_path=down_path,
                up_sha256=_sha256(up_path),
                down_sha256=_sha256(down_path),
            )
        )
    if not migrations:
        raise MigrationError("no platform migrations discovered")
    versions = [migration.version for migration in migrations]
    if versions != list(range(1, len(versions) + 1)):
        raise MigrationError(f"migration versions must be contiguous from 0001: {versions}")
    return migrations


def _statements(script: str) -> list[str]:
    statements: list[str] = []
    buffer = ""
    for line in script.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            statement = buffer.strip()
            if statement:
                statements.append(statement)
            buffer = ""
    if buffer.strip():
        raise MigrationError("incomplete SQL statement in migration")
    return statements


def _execute_script(connection: sqlite3.Connection, path: Path) -> None:
    try:
        script = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise MigrationError(f"migration is not UTF-8: {path.name}") from error
    for statement in _statements(script):
        connection.execute(statement)


def _bootstrap(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migration (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            up_sha256 TEXT NOT NULL CHECK(length(up_sha256) = 64),
            down_sha256 TEXT NOT NULL CHECK(length(down_sha256) = 64),
            applied_at TEXT NOT NULL
        ) STRICT
        """
    )


def migrate_up(connection: sqlite3.Connection, root: Path) -> list[int]:
    migrations = discover_migrations(root)
    _bootstrap(connection)
    applied_rows = connection.execute(
        "SELECT version, name, up_sha256, down_sha256 FROM schema_migration ORDER BY version"
    ).fetchall()
    known = {int(row["version"]): row for row in applied_rows}
    discovered = {migration.version: migration for migration in migrations}
    unknown = sorted(set(known) - set(discovered))
    if unknown:
        raise MigrationError(f"database contains unknown migrations: {unknown}")
    for version, row in known.items():
        migration = discovered[version]
        if (
            row["name"] != migration.name
            or row["up_sha256"] != migration.up_sha256
            or row["down_sha256"] != migration.down_sha256
        ):
            raise MigrationError(f"applied migration drift: {version:04d}")
    newly_applied: list[int] = []
    for migration in migrations:
        if migration.version in known:
            continue
        try:
            with immediate_transaction(connection):
                concurrent_row = connection.execute(
                    "SELECT name,up_sha256,down_sha256 FROM schema_migration WHERE version=?",
                    (migration.version,),
                ).fetchone()
                if concurrent_row is not None:
                    if (
                        concurrent_row["name"],
                        concurrent_row["up_sha256"],
                        concurrent_row["down_sha256"],
                    ) != (
                        migration.name,
                        migration.up_sha256,
                        migration.down_sha256,
                    ):
                        raise MigrationError(
                            f"concurrently applied migration drift: {migration.version:04d}"
                        )
                else:
                    _execute_script(connection, migration.up_path)
                    connection.execute(
                        "INSERT INTO schema_migration(version,name,up_sha256,down_sha256,applied_at) VALUES(?,?,?,?,?)",
                        (
                            migration.version,
                            migration.name,
                            migration.up_sha256,
                            migration.down_sha256,
                            utc_now(),
                        ),
                    )
        except sqlite3.Error as error:
            raise MigrationError(f"migration {migration.version:04d} failed") from error
        if concurrent_row is None:
            newly_applied.append(migration.version)
    return newly_applied


def migrate_down(connection: sqlite3.Connection, root: Path, *, steps: int = 1) -> list[int]:
    if steps < 1:
        raise ValueError("steps must be positive")
    migrations = {item.version: item for item in discover_migrations(root)}
    _bootstrap(connection)
    rows = connection.execute(
        "SELECT version,name,up_sha256,down_sha256 FROM schema_migration ORDER BY version DESC LIMIT ?",
        (steps,),
    ).fetchall()
    reverted: list[int] = []
    for row in rows:
        version = int(row["version"])
        migration = migrations.get(version)
        if migration is None:
            raise MigrationError(f"cannot revert unknown migration: {version:04d}")
        if (
            row["name"] != migration.name
            or row["up_sha256"] != migration.up_sha256
            or row["down_sha256"] != migration.down_sha256
        ):
            raise MigrationError(f"cannot revert drifted migration: {version:04d}")
        try:
            with immediate_transaction(connection):
                _execute_script(connection, migration.down_path)
                connection.execute("DELETE FROM schema_migration WHERE version = ?", (version,))
        except sqlite3.Error as error:
            raise MigrationError(f"down migration {version:04d} failed") from error
        reverted.append(version)
    return reverted


def schema_hash(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
    ).fetchall()
    canonical = "\n".join(
        "\t".join("" if value is None else str(value) for value in row) for row in rows
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
