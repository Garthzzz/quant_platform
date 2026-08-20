"""Immutable online checkpoints for release-external SQLite state.

The checkpoint is a write-once recovery object.  It is deliberately separate
from a release: the only identity edge emitted here is ``checkpoint -> the
release observed at capture time``.  SQLite's online-backup API is used so a
WAL/SHM pair is never treated as a recovery artifact.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
from typing import Mapping, Sequence
from uuid import uuid4

from quant_hub.ops.release_identity import (
    CHECKPOINT_SCHEMA,
    IdentityContractError,
    canonical_manifest_bytes,
    manifest_sha256,
    validate_checkpoint_manifest,
)


CHECKPOINT_MANIFEST_NAME = "checkpoint_manifest.json"
CHECKPOINT_MANIFEST_HASH_NAME = "checkpoint_manifest.sha256"
DEFAULT_RPO = timedelta(hours=24)

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class CheckpointError(RuntimeError):
    """The checkpoint cannot be created or proved safe."""


class CheckpointConflictError(CheckpointError):
    """A write-once checkpoint ID already exists."""


@dataclass(frozen=True)
class CheckpointCreation:
    checkpoint_id: str
    root: Path
    manifest_path: Path
    manifest_sha256: str
    captured_at: datetime


@dataclass(frozen=True)
class CheckpointVerification:
    checkpoint_id: str | None
    root: Path
    valid: bool
    manifest_sha256: str | None
    captured_at: datetime | None
    database_count: int
    errors: tuple[str, ...]


@dataclass(frozen=True)
class RecoveryProtectionStatus:
    status: str
    evaluated_at: datetime
    last_successful_checkpoint_id: str | None
    last_successful_captured_at: datetime | None
    checkpoint_age_seconds: float | None
    rpo_seconds: float
    reason_codes: tuple[str, ...]


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise CheckpointError("captured_at/evaluated_at must be timezone-aware")
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return _utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("timestamp must be canonical UTC")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    return _utc(parsed)


def _identifier(value: str, *, label: str) -> str:
    if not _IDENTIFIER_RE.fullmatch(value):
        raise CheckpointError(f"{label} is not a safe immutable identifier")
    return value


def _digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def _readonly_database(path: Path, *, immutable: bool) -> sqlite3.Connection:
    suffix = "&immutable=1" if immutable else ""
    connection = sqlite3.connect(
        f"file:{path.resolve().as_posix()}?mode=ro{suffix}",
        uri=True,
        timeout=30,
    )
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA busy_timeout=30000")
    return connection


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _schema_and_counts(
    connection: sqlite3.Connection,
) -> tuple[dict[str, object], dict[str, int]]:
    schema_rows = [
        {
            "type": str(row[0]),
            "name": str(row[1]),
            "table": str(row[2]),
            "sql": str(row[3] or ""),
        }
        for row in connection.execute(
            """
            SELECT type,name,tbl_name,sql
            FROM sqlite_schema
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type,name,tbl_name
            """
        )
    ]
    tables = sorted(
        str(row[0])
        for row in connection.execute(
            """
            SELECT name FROM sqlite_schema
            WHERE type='table' AND name NOT LIKE 'sqlite_%'
            ORDER BY name
            """
        )
    )
    counts = {
        table: int(
            connection.execute(
                f"SELECT count(*) FROM {_quote_identifier(table)}"
            ).fetchone()[0]
        )
        for table in tables
    }
    schema_hash = hashlib.sha256(
        json.dumps(
            schema_rows,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return (
        {
            "user_version": int(connection.execute("PRAGMA user_version").fetchone()[0]),
            "schema_sql_sha256": schema_hash,
            "tables": tables,
        },
        counts,
    )


def _database_facts(path: Path) -> dict[str, object]:
    connection = _readonly_database(path, immutable=True)
    try:
        integrity = [str(row[0]) for row in connection.execute("PRAGMA integrity_check")]
        if integrity != ["ok"]:
            raise CheckpointError("checkpoint database failed integrity_check")
        foreign_key_violations = list(connection.execute("PRAGMA foreign_key_check"))
        if foreign_key_violations:
            raise CheckpointError("checkpoint database failed foreign_key_check")
        schema, logical_counts = _schema_and_counts(connection)
    finally:
        connection.close()
    return {
        "size_bytes": path.stat().st_size,
        "sha256": _digest(path),
        "schema": schema,
        "logical_counts": logical_counts,
        "integrity_check": "ok",
        "foreign_key_violation_count": 0,
    }


def _online_backup(source_path: Path, destination_path: Path) -> None:
    source = _readonly_database(source_path, immutable=False)
    target = sqlite3.connect(destination_path, timeout=30)
    try:
        # Small batches yield between source locks while preserving one SQLite
        # backup snapshot.  No checkpoint or write PRAGMA touches the source.
        source.backup(target, pages=256, sleep=0.01)
        target.commit()
    finally:
        target.close()
        source.close()


def _prove_restore(database_path: Path, expected: Mapping[str, object]) -> None:
    with tempfile.TemporaryDirectory(prefix="qrh-checkpoint-restore-") as raw_root:
        restored = Path(raw_root) / "restored.sqlite3"
        source = _readonly_database(database_path, immutable=True)
        target = sqlite3.connect(restored, timeout=30)
        try:
            source.backup(target, pages=256, sleep=0.01)
            target.commit()
        finally:
            target.close()
            source.close()
        actual = _database_facts(restored)
        if actual["schema"] != expected["schema"]:
            raise CheckpointError("restored checkpoint schema differs")
        if actual["logical_counts"] != expected["logical_counts"]:
            raise CheckpointError("restored checkpoint logical counts differ")


def _database_record(logical_name: str, relative_path: str, path: Path) -> dict[str, object]:
    facts = _database_facts(path)
    _prove_restore(path, facts)
    return {
        "logical_name": logical_name,
        "relative_path": relative_path,
        **facts,
        "restore_validation": {
            "integrity": True,
            "foreign_keys": True,
            "schema_matches": True,
            "logical_counts_match": True,
        },
    }


def create_sqlite_checkpoint(
    *,
    sources: Mapping[str, Path],
    checkpoint_root: Path,
    checkpoint_id: str,
    state_authority_id: str,
    captured_under_release_id: str,
    captured_under_manifest_sha256: str,
    captured_at: datetime | None = None,
) -> CheckpointCreation:
    """Create and fully restore-verify one immutable multi-database checkpoint.

    ``sources`` keys are stable logical database names; source paths are never
    persisted in the recovery object.  A repeated checkpoint ID always fails,
    even when the proposed bytes happen to match.
    """

    _identifier(checkpoint_id, label="checkpoint_id")
    _identifier(state_authority_id, label="state_authority_id")
    _identifier(captured_under_release_id, label="captured_under_release_id")
    if not _SHA256_RE.fullmatch(captured_under_manifest_sha256):
        raise CheckpointError("captured_under_manifest_sha256 must be lowercase SHA-256")
    if not sources:
        raise CheckpointError("at least one SQLite source is required")

    normalized_sources: list[tuple[str, Path]] = []
    seen_paths: set[Path] = set()
    for logical_name, raw_path in sorted(sources.items()):
        _identifier(logical_name, label="database logical name")
        source_path = Path(raw_path).resolve()
        if not source_path.is_file():
            raise CheckpointError(f"SQLite source is missing: {logical_name}")
        if source_path in seen_paths:
            raise CheckpointError("one SQLite source cannot have multiple logical names")
        seen_paths.add(source_path)
        normalized_sources.append((logical_name, source_path))

    capture_time = _utc(captured_at or datetime.now(UTC))
    parent = checkpoint_root.resolve()
    parent.mkdir(parents=True, exist_ok=True)
    destination = parent / checkpoint_id
    if destination.exists():
        raise CheckpointConflictError(f"checkpoint ID already exists: {checkpoint_id}")
    partial = parent / f".{checkpoint_id}.partial-{uuid4().hex}"
    partial.mkdir()
    try:
        state_root = partial / "state"
        state_root.mkdir()
        databases: list[dict[str, object]] = []
        for logical_name, source_path in normalized_sources:
            relative_path = f"state/{logical_name}.sqlite3"
            database_path = partial / Path(relative_path)
            _online_backup(source_path, database_path)
            databases.append(
                _database_record(logical_name, relative_path, database_path)
            )

        inventory_sha256 = hashlib.sha256(
            canonical_manifest_bytes(databases)
        ).hexdigest()
        manifest: dict[str, object] = {
            "schema_version": CHECKPOINT_SCHEMA,
            "checkpoint_id": checkpoint_id,
            "captured_at": _timestamp(capture_time),
            "captured_under_active_release": {
                "release_id": captured_under_release_id,
                "manifest_sha256": captured_under_manifest_sha256,
            },
            "state": {
                "authority_id": state_authority_id,
                "inventory_sha256": inventory_sha256,
                "database_count": len(databases),
                "databases": databases,
                "backup_protocol": {
                    "name": "sqlite_online_backup",
                    "wal_shm_copied": False,
                },
            },
            "verification": {
                "integrity": True,
                "foreign_keys": True,
                "restorable": True,
            },
        }
        try:
            validate_checkpoint_manifest(manifest)
        except IdentityContractError as error:
            raise CheckpointError("checkpoint manifest violates identity contract") from error
        digest = manifest_sha256(manifest)
        (partial / CHECKPOINT_MANIFEST_NAME).write_bytes(
            canonical_manifest_bytes(manifest)
        )
        (partial / CHECKPOINT_MANIFEST_HASH_NAME).write_text(
            digest + "\n", encoding="ascii", newline="\n"
        )
        if destination.exists():
            raise CheckpointConflictError(f"checkpoint ID already exists: {checkpoint_id}")
        os.replace(partial, destination)
    except BaseException:
        if partial.exists():
            shutil.rmtree(partial, ignore_errors=True)
        raise

    verification = verify_sqlite_checkpoint(destination)
    if not verification.valid:
        # The object has already become visible and is intentionally not
        # overwritten or silently removed.  Fail closed for its caller.
        raise CheckpointError("new immutable checkpoint failed post-publish verification")
    return CheckpointCreation(
        checkpoint_id=checkpoint_id,
        root=destination,
        manifest_path=destination / CHECKPOINT_MANIFEST_NAME,
        manifest_sha256=digest,
        captured_at=capture_time,
    )


def _safe_manifest_path(root: Path, relative_path: object) -> Path:
    if not isinstance(relative_path, str) or not relative_path:
        raise CheckpointError("database relative_path is invalid")
    candidate = (root / Path(relative_path)).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as error:
        raise CheckpointError("database relative_path escapes checkpoint") from error
    return candidate


def verify_sqlite_checkpoint(checkpoint_path: Path) -> CheckpointVerification:
    """Re-hash, inspect and restore every database in a checkpoint."""

    root = checkpoint_path.resolve()
    checkpoint_id: str | None = None
    captured_at: datetime | None = None
    digest: str | None = None
    database_count = 0
    errors: list[str] = []
    try:
        manifest_path = root / CHECKPOINT_MANIFEST_NAME
        sidecar_path = root / CHECKPOINT_MANIFEST_HASH_NAME
        if not manifest_path.is_file() or not sidecar_path.is_file():
            raise CheckpointError("checkpoint manifest or hash sidecar is missing")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise CheckpointError("checkpoint manifest is not an object")
        validate_checkpoint_manifest(manifest)
        checkpoint_id = str(manifest["checkpoint_id"])
        if checkpoint_id != root.name:
            raise CheckpointError("checkpoint directory and manifest ID differ")
        captured_at = _parse_timestamp(manifest["captured_at"])
        digest = manifest_sha256(manifest)
        sidecar = sidecar_path.read_text(encoding="ascii").strip()
        if not _SHA256_RE.fullmatch(sidecar) or sidecar != digest:
            raise CheckpointError("checkpoint manifest hash sidecar differs")
        if manifest_path.read_bytes() != canonical_manifest_bytes(manifest):
            raise CheckpointError("checkpoint manifest bytes are not canonical")

        state = manifest["state"]
        if not isinstance(state, dict) or not isinstance(state.get("databases"), list):
            raise CheckpointError("checkpoint database inventory is missing")
        databases = state["databases"]
        database_count = len(databases)
        if state.get("database_count") != database_count:
            raise CheckpointError("checkpoint database count differs")
        if hashlib.sha256(canonical_manifest_bytes(databases)).hexdigest() != state.get(
            "inventory_sha256"
        ):
            raise CheckpointError("checkpoint database inventory hash differs")

        expected_paths: set[Path] = set()
        seen_names: set[str] = set()
        for raw_record in databases:
            if not isinstance(raw_record, dict):
                raise CheckpointError("checkpoint database record is invalid")
            logical_name = raw_record.get("logical_name")
            if not isinstance(logical_name, str):
                raise CheckpointError("checkpoint database name is invalid")
            _identifier(logical_name, label="database logical name")
            if logical_name in seen_names:
                raise CheckpointError("checkpoint database name is duplicated")
            seen_names.add(logical_name)
            database_path = _safe_manifest_path(root, raw_record.get("relative_path"))
            if not database_path.is_file():
                raise CheckpointError("checkpoint database file is missing")
            if database_path in expected_paths:
                raise CheckpointError("checkpoint database path is duplicated")
            expected_paths.add(database_path)
            actual = _database_record(
                logical_name,
                str(raw_record["relative_path"]),
                database_path,
            )
            if actual != raw_record:
                raise CheckpointError("checkpoint database evidence differs")

        reserved_paths = {manifest_path.resolve(), sidecar_path.resolve()}
        actual_paths = {
            path.resolve()
            for path in root.rglob("*")
            if path.is_file()
            and path.resolve() not in reserved_paths
        }
        if actual_paths != expected_paths:
            raise CheckpointError("checkpoint contains untracked files")
        if any(
            path.name.endswith(("-wal", "-shm"))
            for path in root.rglob("*")
            if path.is_file()
        ):
            raise CheckpointError("checkpoint contains forbidden WAL/SHM files")
    except (CheckpointError, IdentityContractError, json.JSONDecodeError, OSError, sqlite3.Error):
        errors.append("checkpoint_validation_failed")

    return CheckpointVerification(
        checkpoint_id=checkpoint_id,
        root=root,
        valid=not errors,
        manifest_sha256=digest,
        captured_at=captured_at,
        database_count=database_count,
        errors=tuple(errors),
    )


def evaluate_recovery_protection(
    checkpoints: Sequence[Path],
    *,
    now: datetime | None = None,
    rpo: timedelta = DEFAULT_RPO,
    latest_attempt_succeeded: bool = True,
    closure_valid: bool = True,
    failure_domain_attested: bool = True,
) -> RecoveryProtectionStatus:
    """Compute RPO from the latest *successful, fully verified* checkpoint.

    Job start/finish/receipt timestamps are intentionally not accepted.  A
    failed latest attempt degrades protection while an invalid closure or
    failure-domain attestation fails protection outright.
    """

    evaluated_at = _utc(now or datetime.now(UTC))
    if rpo <= timedelta(0):
        raise CheckpointError("rpo must be positive")
    reports = [verify_sqlite_checkpoint(path) for path in checkpoints]
    valid_reports = [
        report
        for report in reports
        if report.valid and report.captured_at is not None
    ]
    if not closure_valid:
        reasons = ("recovery_closure_invalid",)
        status = "failed"
        latest = max(valid_reports, key=lambda item: item.captured_at) if valid_reports else None
    elif not failure_domain_attested:
        reasons = ("failure_domain_not_attested",)
        status = "failed"
        latest = max(valid_reports, key=lambda item: item.captured_at) if valid_reports else None
    elif not valid_reports:
        reasons = ("no_fully_verified_checkpoint",)
        status = "failed"
        latest = None
    else:
        latest = max(valid_reports, key=lambda item: item.captured_at)
        assert latest.captured_at is not None
        age = evaluated_at - latest.captured_at
        invalid_newer_or_unknown = any(
            not report.valid
            and (report.captured_at is None or report.captured_at >= latest.captured_at)
            for report in reports
        )
        if age < timedelta(0):
            status = "failed"
            reasons = ("checkpoint_captured_in_future",)
        else:
            degraded_reasons: list[str] = []
            if age > rpo:
                degraded_reasons.append("checkpoint_rpo_exceeded")
            if not latest_attempt_succeeded or invalid_newer_or_unknown:
                degraded_reasons.append("latest_checkpoint_attempt_failed")
            if degraded_reasons:
                status = "degraded"
                reasons = tuple(degraded_reasons)
            else:
                status = "protected"
                reasons = ("latest_checkpoint_within_rpo",)

    captured = latest.captured_at if latest is not None else None
    age_seconds = (
        max(0.0, (evaluated_at - captured).total_seconds())
        if captured is not None
        else None
    )
    return RecoveryProtectionStatus(
        status=status,
        evaluated_at=evaluated_at,
        last_successful_checkpoint_id=(latest.checkpoint_id if latest else None),
        last_successful_captured_at=captured,
        checkpoint_age_seconds=age_seconds,
        rpo_seconds=rpo.total_seconds(),
        reason_codes=reasons,
    )


__all__ = [
    "CHECKPOINT_MANIFEST_HASH_NAME",
    "CHECKPOINT_MANIFEST_NAME",
    "DEFAULT_RPO",
    "CheckpointConflictError",
    "CheckpointCreation",
    "CheckpointError",
    "CheckpointVerification",
    "RecoveryProtectionStatus",
    "create_sqlite_checkpoint",
    "evaluate_recovery_protection",
    "verify_sqlite_checkpoint",
]
