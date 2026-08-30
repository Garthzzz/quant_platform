"""Verified transient SQLite snapshots used during the local writer handoff."""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import tempfile
from typing import Mapping
from types import MappingProxyType
from uuid import uuid4
import weakref

from quant_hub.ops.release_identity import (
    IdentityContractError,
    canonical_manifest_bytes,
    manifest_sha256,
)
from quant_hub.ops.local_deployment_persistence import (
    _BoundDirectory,
    _SafeRoot,
    _write_new_bound_file,
)
from quant_hub.ops.vm_boundary import (
    PRODUCTION_VM_ROOT,
    VMBoundaryError,
    reject_test_only_path_on_production_vm,
)
from quant_hub.config import ensure_no_reparse_components, stat_is_reparse_point


CHECKPOINT_SCHEMA = "qrh-transient-sqlite-snapshot/v1"
CHECKPOINT_MANIFEST_NAME = "checkpoint_manifest.json"
CHECKPOINT_MANIFEST_HASH_NAME = "checkpoint_manifest.sha256"

_WRITER_HANDOFF_JOURNAL_SCHEMA = "qrh-writer-handoff-pending/v4"
_LEGACY_STATE_ROOT = Path(r"C:\quant_platform_data")
_PRODUCTION_AUTH_SEAL = object()
_LIVE_PRODUCTION_AUTHORIZATIONS: weakref.WeakSet[object] = weakref.WeakSet()

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


class _ProductionCheckpointAuthorization:
    """One-shot, live writer-attempt capability; never serialized."""

    __slots__ = (
        "root",
        "attempt_id",
        "checkpoint_kind",
        "checkpoint_id",
        "state_authority_id",
        "sources",
        "release_id",
        "manifest_sha256",
        "writer_target_release_id",
        "writer_target_manifest_sha256",
        "journal_phase",
        "lock_identity",
        "journal_identity",
        "__weakref__",
    )

    def __init__(
        self,
        seal: object,
        *,
        root: Path,
        attempt_id: str,
        checkpoint_kind: str,
        checkpoint_id: str,
        state_authority_id: str,
        sources: Mapping[str, Path],
        release_id: str,
        manifest_sha256: str,
        writer_target_release_id: str,
        writer_target_manifest_sha256: str,
        journal_phase: str,
        lock_identity: tuple[int, int],
        journal_identity: tuple[int, int],
    ) -> None:
        if seal is not _PRODUCTION_AUTH_SEAL:
            raise CheckpointError("production checkpoint authorization is internal")
        object.__setattr__(self, "root", root)
        object.__setattr__(self, "attempt_id", attempt_id)
        object.__setattr__(self, "checkpoint_kind", checkpoint_kind)
        object.__setattr__(self, "checkpoint_id", checkpoint_id)
        object.__setattr__(self, "state_authority_id", state_authority_id)
        object.__setattr__(self, "sources", MappingProxyType(dict(sources)))
        object.__setattr__(self, "release_id", release_id)
        object.__setattr__(self, "manifest_sha256", manifest_sha256)
        object.__setattr__(self, "writer_target_release_id", writer_target_release_id)
        object.__setattr__(
            self, "writer_target_manifest_sha256", writer_target_manifest_sha256
        )
        object.__setattr__(self, "journal_phase", journal_phase)
        object.__setattr__(self, "lock_identity", lock_identity)
        object.__setattr__(self, "journal_identity", journal_identity)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("production checkpoint authorization is immutable")

    def __reduce__(self) -> object:
        raise TypeError("production checkpoint authorization is non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("production checkpoint authorization is non-serializable")


def _regular_identity(path: Path, *, label: str) -> tuple[int, int]:
    try:
        observed = os.lstat(path)
    except OSError as error:
        raise CheckpointError(f"{label} is missing") from error
    if not os.path.isfile(path) or stat_is_reparse_point(observed):
        raise CheckpointError(f"{label} is not one regular non-reparse file")
    return observed.st_dev, observed.st_ino


def _read_live_writer_attempt(
    *,
    root: Path,
    attempt_id: str,
    release_id: str,
    manifest_sha256: str,
    expected_phase: str,
) -> tuple[tuple[int, int], tuple[int, int]]:
    """Prove the exact-D writer lock and live pre-cutover journal without writes."""

    lock = root / "state" / "locks" / "writer-handoff.lock"
    journal = root / "control" / "writer_handoff_pending.json"
    ensure_no_reparse_components(lock)
    ensure_no_reparse_components(journal)
    lock_identity = _regular_identity(lock, label="writer handoff lock")
    journal_identity = _regular_identity(journal, label="writer handoff journal")
    try:
        nonce = lock.read_text(encoding="ascii").strip()
        raw = journal.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CheckpointError("writer handoff authority is unreadable") from error
    if not nonce or not isinstance(value, dict):
        raise CheckpointError("writer handoff authority is invalid")
    if raw != canonical_manifest_bytes(value):
        raise CheckpointError("writer handoff journal is not canonical")
    expected_fields = {
        "schema_version",
        "attempt_id",
        "nonce_sha256",
        "inspection_sha256",
        "success_receipt_id",
        "release_id",
        "manifest_sha256",
        "phase",
        "commit_evidence",
        "authority",
        "legacy_process",
    }
    progress = value.get("commit_evidence")
    progress_valid = (
        isinstance(progress, dict)
        and set(progress)
        == {
            "final_checkpoint_id",
            "final_checkpoint_manifest_sha256",
            "prehandoff_checkpoint_id",
            "prehandoff_checkpoint_manifest_sha256",
        }
        and progress.get("final_checkpoint_id")
        == f"handoff-final-{attempt_id}"
        and _SHA256_RE.fullmatch(
            str(progress.get("final_checkpoint_manifest_sha256"))
        )
        is not None
        and progress.get("prehandoff_checkpoint_id") is None
        and progress.get("prehandoff_checkpoint_manifest_sha256") is None
    )
    evidence_valid = (
        value.get("commit_evidence") is None
        if expected_phase == "legacy_stopped"
        else progress_valid
    )
    if expected_phase not in {"legacy_stopped", "final_checkpoint_created"}:
        evidence_valid = False
    if (
        set(value) != expected_fields
        or value.get("schema_version") != _WRITER_HANDOFF_JOURNAL_SCHEMA
        or value.get("attempt_id") != attempt_id
        or value.get("nonce_sha256")
        != hashlib.sha256(nonce.encode("ascii")).hexdigest()
        or value.get("success_receipt_id")
        != f"writer-handoff-success-{attempt_id}"
        or value.get("release_id") != release_id
        or value.get("manifest_sha256") != manifest_sha256
        or value.get("phase") != expected_phase
        or not evidence_valid
        or value.get("authority") != "coordination_only"
        or not isinstance(value.get("legacy_process"), dict)
        or not isinstance(value.get("inspection_sha256"), str)
        or _SHA256_RE.fullmatch(str(value["inspection_sha256"])) is None
    ):
        raise CheckpointError("writer handoff attempt is not live and checkpoint-authorized")
    if _regular_identity(lock, label="writer handoff lock") != lock_identity:
        raise CheckpointError("writer handoff lock identity drifted")
    if _regular_identity(journal, label="writer handoff journal") != journal_identity:
        raise CheckpointError("writer handoff journal identity drifted")
    return lock_identity, journal_identity


def _issue_production_checkpoint_authorization(
    *,
    vm_root: Path,
    attempt_id: str,
    checkpoint_kind: str,
    captured_under_release_id: str,
    captured_under_manifest_sha256: str,
    writer_target_release_id: str,
    writer_target_manifest_sha256: str,
) -> _ProductionCheckpointAuthorization:
    """Issue one exact-purpose token only while the real writer attempt is live."""

    root = Path(os.path.normpath(str(vm_root)))
    if root != Path(str(PRODUCTION_VM_ROOT)):
        raise CheckpointError("production checkpoint authority requires exact VM D root")
    _identifier(attempt_id, label="writer handoff attempt ID")
    _identifier(captured_under_release_id, label="captured_under_release_id")
    _identifier(writer_target_release_id, label="writer target release ID")
    if not _SHA256_RE.fullmatch(captured_under_manifest_sha256):
        raise CheckpointError("captured_under_manifest_sha256 must be lowercase SHA-256")
    if not _SHA256_RE.fullmatch(writer_target_manifest_sha256):
        raise CheckpointError("writer target manifest SHA-256 is invalid")
    if checkpoint_kind == "legacy-c-final":
        checkpoint_id = f"handoff-final-{attempt_id}"
        authority = "legacy-c-final"
        journal_phase = "legacy_stopped"
        sources = {
            "comments": _LEGACY_STATE_ROOT / "comments.sqlite3",
            "research_workspace": _LEGACY_STATE_ROOT / "research_workspace.sqlite3",
        }
    elif checkpoint_kind == "d-prehandoff":
        checkpoint_id = f"handoff-pre-d-{attempt_id}"
        authority = "d-prehandoff"
        journal_phase = "final_checkpoint_created"
        sources = {
            "comments": root / "state" / "comments.sqlite3",
            "research_workspace": root / "state" / "research_workspace.sqlite3",
        }
    else:
        raise CheckpointError("production checkpoint kind is invalid")
    lock_identity, journal_identity = _read_live_writer_attempt(
        root=root,
        attempt_id=attempt_id,
        release_id=writer_target_release_id,
        manifest_sha256=writer_target_manifest_sha256,
        expected_phase=journal_phase,
    )
    authorization = _ProductionCheckpointAuthorization(
        _PRODUCTION_AUTH_SEAL,
        root=root,
        attempt_id=attempt_id,
        checkpoint_kind=checkpoint_kind,
        checkpoint_id=checkpoint_id,
        state_authority_id=authority,
        sources=sources,
        release_id=captured_under_release_id,
        manifest_sha256=captured_under_manifest_sha256,
        writer_target_release_id=writer_target_release_id,
        writer_target_manifest_sha256=writer_target_manifest_sha256,
        journal_phase=journal_phase,
        lock_identity=lock_identity,
        journal_identity=journal_identity,
    )
    _LIVE_PRODUCTION_AUTHORIZATIONS.add(authorization)
    return authorization


def _consume_production_checkpoint_authorization(
    authorization: object,
) -> _ProductionCheckpointAuthorization:
    if (
        type(authorization) is not _ProductionCheckpointAuthorization
        or authorization not in _LIVE_PRODUCTION_AUTHORIZATIONS
    ):
        raise CheckpointError("production checkpoint authorization is not live")
    typed = authorization
    _LIVE_PRODUCTION_AUTHORIZATIONS.discard(typed)
    current = _read_live_writer_attempt(
        root=typed.root,
        attempt_id=typed.attempt_id,
        release_id=typed.writer_target_release_id,
        manifest_sha256=typed.writer_target_manifest_sha256,
        expected_phase=typed.journal_phase,
    )
    if current != (typed.lock_identity, typed.journal_identity):
        raise CheckpointError("production checkpoint authorization identity drifted")
    return typed


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


def validate_checkpoint_manifest(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise IdentityContractError("transient snapshot manifest must be an object")
    required = {
        "schema_version", "checkpoint_id", "captured_at",
        "captured_under_active_release", "state", "verification",
    }
    if set(value) != required:
        raise IdentityContractError("transient snapshot manifest fields differ")
    if value["schema_version"] != CHECKPOINT_SCHEMA:
        raise IdentityContractError("transient snapshot schema differs")
    if not isinstance(value["checkpoint_id"], str):
        raise IdentityContractError("transient snapshot ID is invalid")
    _identifier(value["checkpoint_id"], label="transient snapshot ID")
    try:
        _parse_timestamp(value["captured_at"])
    except (TypeError, ValueError) as error:
        raise IdentityContractError("transient snapshot timestamp is invalid") from error
    captured = value["captured_under_active_release"]
    if not isinstance(captured, dict) or set(captured) != {"release_id", "manifest_sha256"}:
        raise IdentityContractError("transient snapshot release binding is invalid")
    if not isinstance(captured["release_id"], str):
        raise IdentityContractError("transient snapshot release ID is invalid")
    _identifier(captured["release_id"], label="transient snapshot release ID")
    if not isinstance(captured["manifest_sha256"], str) or not _SHA256_RE.fullmatch(
        captured["manifest_sha256"]
    ):
        raise IdentityContractError("transient snapshot release hash is invalid")
    state = value["state"]
    if not isinstance(state, dict) or not {
        "authority_id", "inventory_sha256", "database_count", "databases",
        "backup_protocol",
    }.issubset(state):
        raise IdentityContractError("transient snapshot state is invalid")
    if not isinstance(state["authority_id"], str):
        raise IdentityContractError("transient snapshot authority is invalid")
    _identifier(state["authority_id"], label="transient snapshot authority")
    if not isinstance(state["inventory_sha256"], str) or not _SHA256_RE.fullmatch(
        state["inventory_sha256"]
    ):
        raise IdentityContractError("transient snapshot inventory hash is invalid")
    if not isinstance(state["database_count"], int) or state["database_count"] < 0:
        raise IdentityContractError("transient snapshot database count is invalid")
    if not isinstance(state["databases"], list):
        raise IdentityContractError("transient snapshot database inventory is invalid")
    verification = value["verification"]
    if verification != {"integrity": True, "foreign_keys": True, "restorable": True}:
        raise IdentityContractError("transient snapshot verification is invalid")
    canonical_manifest_bytes(value)
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


def _online_backup_bytes(source_path: Path) -> bytes:
    """Capture one SQLite snapshot in memory before any production file exists."""

    source = _readonly_database(source_path, immutable=False)
    target = sqlite3.connect(":memory:", timeout=30)
    try:
        source.backup(target, pages=256, sleep=0.01)
        target.commit()
        return bytes(target.serialize())
    finally:
        target.close()
        source.close()


def _prove_restore(
    database_path: Path,
    expected: Mapping[str, object],
    *,
    scratch_root: Path | None = None,
    in_memory: bool = False,
) -> None:
    if in_memory:
        source = _readonly_database(database_path, immutable=True)
        target = sqlite3.connect(":memory:", timeout=30)
        try:
            source.backup(target, pages=256, sleep=0.01)
            target.commit()
            integrity = [str(row[0]) for row in target.execute("PRAGMA integrity_check")]
            foreign_keys = list(target.execute("PRAGMA foreign_key_check"))
            schema, logical_counts = _schema_and_counts(target)
        finally:
            target.close()
            source.close()
        if integrity != ["ok"] or foreign_keys:
            raise CheckpointError("restored checkpoint failed database checks")
        if schema != expected["schema"]:
            raise CheckpointError("restored checkpoint schema differs")
        if logical_counts != expected["logical_counts"]:
            raise CheckpointError("restored checkpoint logical counts differ")
        return
    with tempfile.TemporaryDirectory(
        prefix="qrh-checkpoint-restore-",
        dir=str(scratch_root) if scratch_root is not None else None,
    ) as raw_root:
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


def _database_record(
    logical_name: str,
    relative_path: str,
    path: Path,
    *,
    scratch_root: Path | None = None,
    in_memory_restore: bool = False,
) -> dict[str, object]:
    facts = _database_facts(path)
    _prove_restore(
        path,
        facts,
        scratch_root=scratch_root,
        in_memory=in_memory_restore,
    )
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


@contextmanager
def _pin_regular_file(
    path: Path,
    expected: os.stat_result,
    *,
    delete_authority: bool = False,
):
    """Keep one SQLite target identity non-replaceable during backup/proof."""

    observed = os.lstat(path)
    if (
        not os.path.isfile(path)
        or stat_is_reparse_point(observed)
        or getattr(observed, "st_nlink", 1) != 1
        or (observed.st_dev, observed.st_ino) != (expected.st_dev, expected.st_ino)
    ):
        raise CheckpointError("checkpoint SQLite target identity drifted")
    if os.name != "nt":
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            pinned = os.fstat(descriptor)
            if (
                (pinned.st_dev, pinned.st_ino)
                != (expected.st_dev, expected.st_ino)
                or getattr(pinned, "st_nlink", 1) != 1
            ):
                raise CheckpointError("checkpoint SQLite target pin drifted")
            yield descriptor
        finally:
            os.close(descriptor)
        return

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    kernel32.CreateFileW.restype = wintypes.HANDLE
    handle = kernel32.CreateFileW(
        str(path),
        0x80000000 | (0x00010000 if delete_authority else 0),
        # GENERIC_READ plus DELETE only for the already-published transient
        # member guard used by exact failure cleanup.
        0x00000001,  # SHARE_READ only; write, delete and replacement are denied.
        None,
        3,  # OPEN_EXISTING
        0x00200000,  # FILE_FLAG_OPEN_REPARSE_POINT
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle in {None, invalid}:
        raise CheckpointError("cannot pin production checkpoint SQLite target")
    try:
        if os.path.normcase(_BoundDirectory._windows_final_path(int(handle))) != (
            os.path.normcase(str(path))
        ):
            raise CheckpointError("checkpoint SQLite target final path drifted")
        after = os.lstat(path)
        if (
            stat_is_reparse_point(after)
            or getattr(after, "st_nlink", 1) != 1
            or (after.st_dev, after.st_ino) != (expected.st_dev, expected.st_ino)
        ):
            raise CheckpointError("checkpoint SQLite target pin identity drifted")
        yield int(handle)
    finally:
        _BoundDirectory._close_windows_handle(int(handle))


@contextmanager
def _read_pinned_regular_bytes(path: Path, expected: os.stat_result):
    """Read one immutable file while its exact identity cannot be replaced."""

    observed = os.lstat(path)
    if (
        not os.path.isfile(path)
        or stat_is_reparse_point(observed)
        or (observed.st_dev, observed.st_ino) != (expected.st_dev, expected.st_ino)
    ):
        raise CheckpointError("production checkpoint member identity drifted")
    if os.name != "nt":
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_BINARY", 0),
        )
        try:
            pinned = os.fstat(descriptor)
            if (pinned.st_dev, pinned.st_ino) != (expected.st_dev, expected.st_ino):
                raise CheckpointError("production checkpoint member pin drifted")
            blocks: list[bytes] = []
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                blocks.append(block)
            raw = b"".join(blocks)
            after = os.fstat(descriptor)
            if (
                (after.st_dev, after.st_ino) != (expected.st_dev, expected.st_ino)
                or after.st_size != len(raw)
            ):
                raise CheckpointError("production checkpoint member changed while read")
            yield raw
        finally:
            os.close(descriptor)
        return

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.ReadFile.argtypes = (
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.LPDWORD,
        wintypes.LPVOID,
    )
    kernel32.ReadFile.restype = wintypes.BOOL
    handle = kernel32.CreateFileW(
        str(path),
        0x80000000 | 0x00000080,  # GENERIC_READ | FILE_READ_ATTRIBUTES
        0x00000001,  # SHARE_READ only: no writer and no replacement while pinned
        None,
        3,  # OPEN_EXISTING
        0x00200000,  # FILE_FLAG_OPEN_REPARSE_POINT
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle in {None, invalid}:
        raise CheckpointError("cannot read-pin production checkpoint member")
    try:
        if os.path.normcase(_BoundDirectory._windows_final_path(int(handle))) != (
            os.path.normcase(str(path))
        ):
            raise CheckpointError("production checkpoint member final path drifted")
        after_open = os.lstat(path)
        if (
            stat_is_reparse_point(after_open)
            or (after_open.st_dev, after_open.st_ino)
            != (expected.st_dev, expected.st_ino)
        ):
            raise CheckpointError("production checkpoint member pin identity drifted")
        blocks = []
        while True:
            buffer = ctypes.create_string_buffer(1024 * 1024)
            read = wintypes.DWORD()
            if not kernel32.ReadFile(
                handle,
                buffer,
                len(buffer),
                ctypes.byref(read),
                None,
            ):
                raise CheckpointError(
                    f"production checkpoint member read failed: {ctypes.get_last_error()}"
                )
            if read.value == 0:
                break
            blocks.append(buffer.raw[: read.value])
        raw = b"".join(blocks)
        if len(raw) != expected.st_size:
            raise CheckpointError("production checkpoint member changed while read")
        yield raw
    finally:
        _BoundDirectory._close_windows_handle(int(handle))


def _read_open_windows_regular_bytes(
    handle: int,
    *,
    expected_path: Path,
    expected_identity: tuple[int, int, int],
    expected_size: int,
) -> bytes:
    """Read an already DELETE-authorized exact member without reopening it."""

    if os.name != "nt":
        raise CheckpointError("open-handle checkpoint read is Windows-only")
    import ctypes
    from ctypes import wintypes

    if (
        _BoundDirectory._windows_final_path(handle) != str(expected_path)
        or _BoundDirectory._windows_kernel_identity(handle) != expected_identity
    ):
        raise CheckpointError("open checkpoint member identity drifted")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.SetFilePointerEx.argtypes = (
        wintypes.HANDLE,
        ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong),
        wintypes.DWORD,
    )
    kernel32.SetFilePointerEx.restype = wintypes.BOOL
    kernel32.ReadFile.argtypes = (
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.LPDWORD,
        wintypes.LPVOID,
    )
    kernel32.ReadFile.restype = wintypes.BOOL
    if not kernel32.SetFilePointerEx(handle, 0, None, 0):
        raise CheckpointError("open checkpoint member seek failed")
    blocks: list[bytes] = []
    while True:
        buffer = ctypes.create_string_buffer(1024 * 1024)
        read = wintypes.DWORD()
        if not kernel32.ReadFile(
            handle,
            buffer,
            len(buffer),
            ctypes.byref(read),
            None,
        ):
            raise CheckpointError(
                "open checkpoint member read failed: "
                f"{ctypes.get_last_error()}"
            )
        if read.value == 0:
            break
        blocks.append(buffer.raw[: read.value])
    raw = b"".join(blocks)
    if (
        len(raw) != expected_size
        or _BoundDirectory._windows_final_path(handle) != str(expected_path)
        or _BoundDirectory._windows_kernel_identity(handle) != expected_identity
    ):
        raise CheckpointError("open checkpoint member changed while read")
    return raw


def _closed_directory_names(path: Path) -> set[str]:
    try:
        with os.scandir(path) as entries:
            result = {entry.name for entry in entries}
    except OSError as error:
        raise CheckpointError("production checkpoint directory is unreadable") from error
    if len(result) != len({name.casefold() for name in result}):
        raise CheckpointError("production checkpoint directory has case-fold collisions")
    return result


def _database_facts_from_bytes(raw: bytes) -> dict[str, object]:
    validation_bytes = raw
    if (
        len(raw) >= 20
        and raw.startswith(b"SQLite format 3\x00")
        and raw[18:20] == b"\x02\x02"
    ):
        # SQLite cannot deserialize a WAL-mode header into an anonymous
        # in-memory database because no filesystem WAL can exist there.  The
        # checkpoint bytes and their digest remain untouched; only the private
        # validation copy is switched to rollback-header semantics.
        normalized = bytearray(raw)
        normalized[18:20] = b"\x01\x01"
        validation_bytes = bytes(normalized)
    connection = sqlite3.connect(":memory:", timeout=30)
    try:
        connection.deserialize(validation_bytes)
        integrity = [str(row[0]) for row in connection.execute("PRAGMA integrity_check")]
        foreign_keys = list(connection.execute("PRAGMA foreign_key_check"))
        if integrity != ["ok"] or foreign_keys:
            raise CheckpointError("pinned checkpoint bytes failed database checks")
        schema, logical_counts = _schema_and_counts(connection)
    finally:
        connection.close()
    return {
        "size_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "schema": schema,
        "logical_counts": logical_counts,
        "integrity_check": "ok",
        "foreign_key_violation_count": 0,
    }


class _ProductionCheckpointGuard:
    """Pinned exact-D attempt/checkpoints/restore-proof directory authority."""

    def __init__(
        self,
        checkpoint_root: Path,
        scratch_root: Path | None,
        *,
        create_missing: bool = True,
    ):
        production = Path(str(PRODUCTION_VM_ROOT))
        raw_parent = Path(os.path.normpath(str(checkpoint_root)))
        try:
            relative = raw_parent.relative_to(production)
        except ValueError as error:
            raise CheckpointError(
                "production transient snapshot root must stay under exact D root"
            ) from error
        if (
            len(relative.parts) != 4
            or tuple(part.casefold() for part in relative.parts[:2])
            != ("tmp", "writer-handoff")
            or relative.parts[3].casefold() != "checkpoints"
        ):
            raise CheckpointError(
                "production transient snapshots are restricted to one writer-handoff attempt"
            )
        _identifier(relative.parts[2], label="writer handoff attempt ID")
        self.production = production
        self.attempt_id = relative.parts[2]
        self.parent = production / relative
        self.scratch = self.parent.parent / "restore-proof"
        if scratch_root is not None and Path(os.path.normpath(str(scratch_root))) != self.scratch:
            raise CheckpointError(
                "production restore proof root must share the exact writer-handoff attempt"
            )
        self._safe_root: _SafeRoot | None = None
        self.create_missing = create_missing
        self._stack = ExitStack()
        self.parent_bound: _BoundDirectory | None = None
        self.scratch_bound: _BoundDirectory | None = None

    def _enter_or_create(
        self,
        parent: _BoundDirectory,
        path: Path,
        name: str,
        *,
        create: bool,
    ) -> _BoundDirectory:
        assert self._safe_root is not None
        observed = self._safe_root.preflight(
            path, expected_kind="directory", allow_absent=create
        )
        if observed is None:
            parent.mkdir(name, 0o700)
        self._safe_root.preflight(
            path, expected_kind="directory", allow_absent=False
        )
        return self._stack.enter_context(
            _BoundDirectory(self._safe_root, path, protect_rename=True)
        )

    def __enter__(self) -> "_ProductionCheckpointGuard":
        try:
            self._safe_root = _SafeRoot(
                self.production, allow_posix_test_only=False
            )
            root_bound = self._stack.enter_context(
                _BoundDirectory(
                    self._safe_root, self.production, protect_rename=True
                )
            )
            tmp = self.production / "tmp"
            tmp_bound = self._enter_or_create(
                root_bound, tmp, "tmp", create=False
            )
            handoff = tmp / "writer-handoff"
            handoff_bound = self._enter_or_create(
                tmp_bound, handoff, "writer-handoff", create=self.create_missing
            )
            attempt = handoff / self.attempt_id
            attempt_bound = self._enter_or_create(
                handoff_bound, attempt, self.attempt_id, create=self.create_missing
            )
            self.parent_bound = self._enter_or_create(
                attempt_bound,
                self.parent,
                "checkpoints",
                create=self.create_missing,
            )
            self.scratch_bound = self._enter_or_create(
                attempt_bound,
                self.scratch,
                "restore-proof",
                create=self.create_missing,
            )
            return self
        except BaseException:
            self._stack.close()
            raise

    def __exit__(self, exc_type, exc, traceback) -> None:
        self._stack.close()

    def assert_exact(self, path: Path, *, kind: str) -> None:
        assert self._safe_root is not None
        self._safe_root.preflight(
            path, expected_kind=kind, allow_absent=False
        )
        ensure_no_reparse_components(path)
        resolved = path.resolve(strict=True)
        try:
            resolved.relative_to(self.parent.parent)
        except ValueError as error:
            raise CheckpointError(
                "production checkpoint path escaped its exact attempt"
            ) from error


def _preflight_checkpoint_inputs(
    *,
    sources: Mapping[str, Path],
    checkpoint_id: str,
    state_authority_id: str,
    captured_under_release_id: str,
    captured_under_manifest_sha256: str,
) -> list[tuple[str, Path]]:
    """Validate every pure input before any checkpoint directory can be made."""

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
        source_path = Path(raw_path).resolve(strict=True)
        observed = os.lstat(source_path)
        if not os.path.isfile(source_path) or stat_is_reparse_point(observed):
            raise CheckpointError(f"SQLite source is unsafe: {logical_name}")
        if source_path in seen_paths:
            raise CheckpointError("one SQLite source cannot have multiple logical names")
        seen_paths.add(source_path)
        normalized_sources.append((logical_name, source_path))
    return normalized_sources


def create_sqlite_checkpoint(
    *,
    sources: Mapping[str, Path],
    checkpoint_root: Path,
    checkpoint_id: str,
    state_authority_id: str,
    captured_under_release_id: str,
    captured_under_manifest_sha256: str,
    captured_at: datetime | None = None,
    scratch_root: Path | None = None,
    allow_test_root: bool = False,
) -> CheckpointCreation:
    """Create a checkpoint only in an explicitly isolated non-production test root."""

    if not allow_test_root:
        raise CheckpointError(
            "production checkpoint creation requires a live writer-handoff authorization"
        )
    return _create_sqlite_checkpoint_impl(
        sources=sources,
        checkpoint_root=checkpoint_root,
        checkpoint_id=checkpoint_id,
        state_authority_id=state_authority_id,
        captured_under_release_id=captured_under_release_id,
        captured_under_manifest_sha256=captured_under_manifest_sha256,
        captured_at=captured_at,
        scratch_root=scratch_root,
        allow_test_root=True,
        production_guard=None,
    )


def _create_production_sqlite_checkpoint(
    authorization: object,
) -> CheckpointCreation:
    """Consume one live exact-purpose token; this is the sole production path."""

    typed = _consume_production_checkpoint_authorization(authorization)
    checkpoint_root = (
        typed.root
        / "tmp"
        / "writer-handoff"
        / typed.attempt_id
        / "checkpoints"
    )
    scratch_root = checkpoint_root.parent / "restore-proof"
    normalized = _preflight_checkpoint_inputs(
        sources=typed.sources,
        checkpoint_id=typed.checkpoint_id,
        state_authority_id=typed.state_authority_id,
        captured_under_release_id=typed.release_id,
        captured_under_manifest_sha256=typed.manifest_sha256,
    )
    with ExitStack() as source_pins:
        for _logical_name, source_path in normalized:
            source_pins.enter_context(
                _pin_regular_file(source_path, os.lstat(source_path))
            )
        # Re-prove the live attempt after source pinning and before the first mkdir.
        current = _read_live_writer_attempt(
            root=typed.root,
            attempt_id=typed.attempt_id,
            release_id=typed.writer_target_release_id,
            manifest_sha256=typed.writer_target_manifest_sha256,
            expected_phase=typed.journal_phase,
        )
        if current != (typed.lock_identity, typed.journal_identity):
            raise CheckpointError("production checkpoint authority closed before creation")
        with _ProductionCheckpointGuard(checkpoint_root, scratch_root) as guard:
            return _create_sqlite_checkpoint_impl(
                sources=typed.sources,
                checkpoint_root=checkpoint_root,
                checkpoint_id=typed.checkpoint_id,
                state_authority_id=typed.state_authority_id,
                captured_under_release_id=typed.release_id,
                captured_under_manifest_sha256=typed.manifest_sha256,
                captured_at=None,
                scratch_root=scratch_root,
                allow_test_root=False,
                production_guard=guard,
            )


def _cleanup_exact_production_checkpoint(
    *,
    guard: _ProductionCheckpointGuard,
    target: Path,
    expected_root_identity: tuple[int, int, int] | None,
    expected_database_names: set[str],
) -> None:
    """Delete only the originally-created failed checkpoint object."""

    if (
        guard._safe_root is None
        or guard.parent_bound is None
        or target.parent != guard.parent
        or expected_root_identity is None
    ):
        raise CheckpointError("checkpoint cleanup authority is incomplete")
    if guard._safe_root.preflight(
        target,
        expected_kind="directory",
        allow_absent=True,
    ) is None:
        return
    with _BoundDirectory(
        guard._safe_root,
        target,
        protect_rename=True,
    ) as cleanup_root:
        if cleanup_root.windows_leaf_identity() != expected_root_identity:
            raise CheckpointError("checkpoint cleanup root identity drifted")
        observed_root_names = {entry.name for entry in os.scandir(target)}
        if not observed_root_names.issubset(
            {
                "state",
                CHECKPOINT_MANIFEST_NAME,
                CHECKPOINT_MANIFEST_HASH_NAME,
            }
        ):
            raise CheckpointError("checkpoint cleanup found untracked root members")
        if "state" in observed_root_names:
            state_root = target / "state"
            with _BoundDirectory(
                guard._safe_root,
                state_root,
                protect_rename=True,
            ) as cleanup_state:
                observed_state_names = {
                    entry.name for entry in os.scandir(state_root)
                }
                if not observed_state_names.issubset(expected_database_names):
                    raise CheckpointError(
                        "checkpoint cleanup found untracked state members"
                    )
                for name in sorted(observed_state_names):
                    guard.assert_exact(state_root / name, kind="file")
                    cleanup_state.unlink(name)
            cleanup_root.rmdir("state")
        for name in (
            CHECKPOINT_MANIFEST_NAME,
            CHECKPOINT_MANIFEST_HASH_NAME,
        ):
            if name in observed_root_names:
                guard.assert_exact(target / name, kind="file")
                cleanup_root.unlink(name)
    guard.parent_bound.rmdir(target.name)


def _delete_guarded_production_checkpoint(
    *,
    root_bound: _BoundDirectory,
    orphan_member_identities: Mapping[
        tuple[int, int], tuple[int, int, int]
    ],
    member_handles: tuple[int, ...],
    member_stack: ExitStack,
    state_stack: ExitStack,
    root_stack: ExitStack,
) -> None:
    """Delete a failed published tree while its exact root remains pinned.

    Known members are first removed through the handles acquired by the
    publisher. Any entry introduced or renamed during the acquisition window
    is then opened beneath the still-live no-SHARE_DELETE root and removed by
    its own exact handle. The cleanup never closes and reopens the checkpoint
    root by path.
    """

    def delete_remaining_children(bound: _BoundDirectory) -> None:
        with os.scandir(bound.path) as iterator:
            entries = tuple(sorted(iterator, key=lambda item: item.name))
        for entry in entries:
            path = bound.path / entry.name
            metadata = os.lstat(path)
            if stat_is_reparse_point(metadata) or stat.S_ISLNK(metadata.st_mode):
                raise CheckpointError(
                    "failed checkpoint cleanup found a reparse member"
                )
            if stat.S_ISREG(metadata.st_mode):
                with _pin_regular_file(
                    path,
                    metadata,
                    delete_authority=True,
                ) as handle:
                    _BoundDirectory.delete_open_windows_handle(handle)
                continue
            if stat.S_ISDIR(metadata.st_mode):
                with _BoundDirectory(
                    bound._safe_root,
                    path,
                    protect_rename=True,
                ) as child:
                    delete_remaining_children(child)
                    _BoundDirectory.delete_open_windows_handle(
                        child.windows_leaf_handle()
                    )
                continue
            raise CheckpointError(
                "failed checkpoint cleanup found a non-regular member"
            )
        with os.scandir(bound.path) as iterator:
            if next(iterator, None) is not None:
                raise CheckpointError("failed checkpoint cleanup inventory changed")

    def scan_managed_root_for_originals(*, delete_matches: bool) -> None:
        managed_root = root_bound._safe_root.root
        for current_text, directory_names, file_names in os.walk(
            managed_root,
            topdown=True,
            followlinks=False,
        ):
            current = Path(current_text)
            current_metadata = os.lstat(current)
            if (
                stat_is_reparse_point(current_metadata)
                or stat.S_ISLNK(current_metadata.st_mode)
                or not stat.S_ISDIR(current_metadata.st_mode)
            ):
                raise CheckpointError(
                    "failed checkpoint orphan scan crossed a non-regular directory"
                )
            retained_directories: list[str] = []
            for name in sorted(directory_names):
                path = current / name
                metadata = os.lstat(path)
                if (
                    stat_is_reparse_point(metadata)
                    or stat.S_ISLNK(metadata.st_mode)
                    or not stat.S_ISDIR(metadata.st_mode)
                ):
                    raise CheckpointError(
                        "failed checkpoint orphan scan found a reparse directory"
                    )
                retained_directories.append(name)
            directory_names[:] = retained_directories
            for name in sorted(file_names):
                path = current / name
                metadata = os.lstat(path)
                if (
                    stat_is_reparse_point(metadata)
                    or stat.S_ISLNK(metadata.st_mode)
                    or not stat.S_ISREG(metadata.st_mode)
                ):
                    raise CheckpointError(
                        "failed checkpoint orphan scan found a non-regular file"
                    )
                expected_kernel_identity = orphan_member_identities.get(
                    (metadata.st_dev, metadata.st_ino)
                )
                if expected_kernel_identity is None:
                    continue
                if not delete_matches:
                    raise CheckpointError(
                        "failed checkpoint cleanup left an original member in D root"
                    )
                with _pin_regular_file(
                    path,
                    metadata,
                    delete_authority=True,
                ) as handle:
                    if (
                        _BoundDirectory._windows_kernel_identity(handle)
                        != expected_kernel_identity
                    ):
                        raise CheckpointError(
                            "failed checkpoint orphan identity disagrees"
                        )
                    _BoundDirectory.delete_open_windows_handle(handle)

    failure: BaseException | None = None
    for handle in member_handles:
        try:
            _BoundDirectory.delete_open_windows_handle(handle)
        except BaseException as error:
            failure = failure or error
    try:
        member_stack.close()
    except BaseException as error:
        failure = failure or error
    try:
        state_stack.close()
    except BaseException as error:
        failure = failure or error
    if failure is None:
        try:
            delete_remaining_children(root_bound)
            scan_managed_root_for_originals(delete_matches=True)
            scan_managed_root_for_originals(delete_matches=False)
            _BoundDirectory.delete_open_windows_handle(
                root_bound.windows_leaf_handle()
            )
        except BaseException as error:
            failure = failure or error
    try:
        root_stack.close()
    except BaseException as error:
        failure = failure or error
    if failure is not None:
        raise CheckpointError(
            "failed checkpoint handle deletion did not close exactly"
        ) from failure


def _create_sqlite_checkpoint_impl(
    *,
    sources: Mapping[str, Path],
    checkpoint_root: Path,
    checkpoint_id: str,
    state_authority_id: str,
    captured_under_release_id: str,
    captured_under_manifest_sha256: str,
    captured_at: datetime | None,
    scratch_root: Path | None,
    allow_test_root: bool,
    production_guard: _ProductionCheckpointGuard | None,
) -> CheckpointCreation:
    """Create and fully restore-verify one immutable multi-database checkpoint.

    ``sources`` keys are stable logical database names; source paths are never
    persisted in the transient snapshot.  A repeated checkpoint ID always fails,
    even when the proposed bytes happen to match.
    """

    if allow_test_root:
        guarded_paths = [
            (Path(checkpoint_root), "test-only checkpoint root"),
            *(
                (Path(source), f"test-only SQLite source {logical_name}")
                for logical_name, source in sources.items()
            ),
        ]
        if scratch_root is not None:
            guarded_paths.append(
                (Path(scratch_root), "test-only checkpoint scratch root")
            )
        try:
            for guarded, label in guarded_paths:
                reject_test_only_path_on_production_vm(guarded, label=label)
        except VMBoundaryError as error:
            raise CheckpointError(str(error)) from error

    normalized_sources = _preflight_checkpoint_inputs(
        sources=sources,
        checkpoint_id=checkpoint_id,
        state_authority_id=state_authority_id,
        captured_under_release_id=captured_under_release_id,
        captured_under_manifest_sha256=captured_under_manifest_sha256,
    )

    parent = (
        Path(checkpoint_root).resolve()
        if production_guard is None
        else production_guard.parent
    )

    resolved_scratch_root: Path | None = None
    if scratch_root is not None:
        resolved_scratch_root = (
            Path(scratch_root).resolve()
            if production_guard is None
            else production_guard.scratch
        )
        if production_guard is None:
            resolved_scratch_root.mkdir(parents=True, exist_ok=True)
        if not resolved_scratch_root.is_dir():
            raise CheckpointError("checkpoint scratch root is not a directory")

    capture_time = _utc(captured_at or datetime.now(UTC))
    if production_guard is None:
        parent.mkdir(parents=True, exist_ok=True)
    destination = parent / checkpoint_id
    if destination.exists():
        raise CheckpointConflictError(f"checkpoint ID already exists: {checkpoint_id}")
    partial = parent / f".{checkpoint_id}.partial-{uuid4().hex}"
    partial_directory_stack = ExitStack()
    partial_file_stack = ExitStack()
    partial_bound: _BoundDirectory | None = None
    state_bound: _BoundDirectory | None = None
    created_partial_identity: tuple[int, int, int] | None = None
    created_member_identities: dict[Path, tuple[int, int, int]] = {}
    created_member_sizes: dict[Path, int] = {}
    created_member_cleanup_identities: dict[
        tuple[int, int], tuple[int, int, int]
    ] = {}
    published_root_stack = ExitStack()
    published_state_stack = ExitStack()
    published_member_stack = ExitStack()
    published_root_bound: _BoundDirectory | None = None
    published_state_bound: _BoundDirectory | None = None
    published_member_handles: list[int] = []
    published_pinned_members: dict[
        Path, tuple[int, tuple[int, int, int], int]
    ] = {}
    publication_monitor = None
    published_root_guard_ready = False
    published_guard_ready = False
    publication_path = partial
    published = False
    if production_guard is None:
        partial.mkdir()
    else:
        assert production_guard.parent_bound is not None
        production_guard.parent_bound.mkdir(partial.name, 0o700)
        production_guard.assert_exact(partial, kind="directory")
        assert production_guard._safe_root is not None
        partial_bound = partial_directory_stack.enter_context(
            _BoundDirectory(
                production_guard._safe_root, partial, protect_rename=True
            )
        )
        created_partial_identity = partial_bound.windows_leaf_identity()
    try:
        state_root = partial / "state"
        if partial_bound is None:
            state_root.mkdir()
        else:
            partial_bound.mkdir("state", 0o700)
            production_guard.assert_exact(state_root, kind="directory")
            state_bound = partial_directory_stack.enter_context(
                _BoundDirectory(
                    production_guard._safe_root,
                    state_root,
                    protect_rename=True,
                )
            )
        databases: list[dict[str, object]] = []
        for logical_name, source_path in normalized_sources:
            relative_path = f"state/{logical_name}.sqlite3"
            database_path = partial / Path(relative_path)
            if state_bound is not None:
                snapshot_bytes = _online_backup_bytes(source_path)
                _write_new_bound_file(
                    state_bound,
                    name=f"{logical_name}.sqlite3",
                    raw=snapshot_bytes,
                    label=f"checkpoint SQLite {logical_name}",
                )
                expected = os.lstat(database_path)
                pinned = partial_file_stack.enter_context(
                    _pin_regular_file(database_path, expected)
                )
                created_member_identities[Path(relative_path)] = (
                    _BoundDirectory._windows_kernel_identity(pinned)
                )
                created_member_cleanup_identities[
                    (expected.st_dev, expected.st_ino)
                ] = created_member_identities[Path(relative_path)]
                created_member_sizes[Path(relative_path)] = int(expected.st_size)
                production_guard.assert_exact(database_path, kind="file")
            else:
                _online_backup(source_path, database_path)
            if production_guard is not None:
                production_guard.assert_exact(database_path, kind="file")
            databases.append(
                _database_record(
                    logical_name,
                    relative_path,
                    database_path,
                    scratch_root=resolved_scratch_root,
                    in_memory_restore=production_guard is not None,
                )
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
        if partial_bound is None:
            (partial / CHECKPOINT_MANIFEST_NAME).write_bytes(
                canonical_manifest_bytes(manifest)
            )
            (partial / CHECKPOINT_MANIFEST_HASH_NAME).write_text(
                digest + "\n", encoding="ascii", newline="\n"
            )
        else:
            _write_new_bound_file(
                partial_bound,
                name=CHECKPOINT_MANIFEST_NAME,
                raw=canonical_manifest_bytes(manifest),
                label="checkpoint manifest",
            )
            _write_new_bound_file(
                partial_bound,
                name=CHECKPOINT_MANIFEST_HASH_NAME,
                raw=(digest + "\n").encode("ascii"),
                label="checkpoint manifest hash",
            )
            for name in (
                CHECKPOINT_MANIFEST_NAME,
                CHECKPOINT_MANIFEST_HASH_NAME,
            ):
                path = partial / name
                metadata = os.lstat(path)
                pinned = partial_file_stack.enter_context(
                    _pin_regular_file(path, metadata)
                )
                created_member_identities[Path(name)] = (
                    _BoundDirectory._windows_kernel_identity(pinned)
                )
                created_member_cleanup_identities[
                    (metadata.st_dev, metadata.st_ino)
                ] = created_member_identities[Path(name)]
                created_member_sizes[Path(name)] = int(metadata.st_size)
        if destination.exists():
            raise CheckpointConflictError(f"checkpoint ID already exists: {checkpoint_id}")
        if production_guard is not None:
            assert partial_bound is not None and state_bound is not None
            from quant_hub.ops.local_exact_runtime_tooling_scanner import (
                _SUBTREE_MUTATION_NOTIFY_FILTER,
                _WindowsNamespaceChangeMonitor,
            )

            with _BoundDirectory(
                production_guard._safe_root,
                partial,
                protect_rename=False,
            ) as movable_bound:
                monitor: _WindowsNamespaceChangeMonitor | None = (
                    _WindowsNamespaceChangeMonitor(
                        partial,
                        notify_filter=_SUBTREE_MUTATION_NOTIFY_FILTER,
                    )
                )
                try:
                    expected_database_names = {
                        f"{logical_name}.sqlite3"
                        for logical_name, _source in normalized_sources
                    }
                    if {
                        entry.name for entry in os.scandir(state_root)
                    } != expected_database_names:
                        raise CheckpointError(
                            "checkpoint state inventory drifted before publish"
                        )
                    if {entry.name for entry in os.scandir(partial)} != {
                        "state",
                        CHECKPOINT_MANIFEST_NAME,
                        CHECKPOINT_MANIFEST_HASH_NAME,
                    }:
                        raise CheckpointError(
                            "checkpoint root inventory drifted before publish"
                        )
                    production_guard.assert_exact(partial, kind="directory")
                    assert production_guard.parent_bound is not None
                    # Windows cannot rename a directory while descendant
                    # handles are open. Retire those handles only after a
                    # recursive name/content monitor is live, then publish the
                    # exact root by its proven DELETE handle.
                    partial_file_stack.close()
                    partial_directory_stack.close()
                    movable_bound.enable_self_rename()
                    production_guard.parent_bound.replace_open_windows_handle(
                        movable_bound.windows_leaf_handle(),
                        destination_name=destination.name,
                        replace_existing=False,
                    )
                    # The syscall above has already moved the exact object.
                    # Record and transfer its still-live no-SHARE_DELETE handle
                    # without ever closing and reopening the root by path.
                    publication_path = destination
                    movable_bound.record_ancestor_rename(
                        old_ancestor=partial,
                        new_ancestor=destination,
                    )
                    published_root_bound = movable_bound.transfer_windows_binding(
                        protect_rename=True,
                    )
                    published_root_stack.callback(
                        published_root_bound.__exit__, None, None, None
                    )
                    published_root_guard_ready = True
                    publication_monitor = monitor
                    monitor = None
                    if (
                        created_partial_identity is None
                        or published_root_bound.windows_leaf_identity()
                        != created_partial_identity
                    ):
                        raise CheckpointError(
                            "published checkpoint root identity drifted"
                        )
                    published_state_bound = published_state_stack.enter_context(
                        _BoundDirectory(
                            production_guard._safe_root,
                            destination / "state",
                            protect_rename=True,
                        )
                    )
                    for relative_path, expected_identity in sorted(
                        created_member_identities.items(), key=lambda item: item[0].as_posix()
                    ):
                        path = destination / relative_path
                        handle = published_member_stack.enter_context(
                            _pin_regular_file(
                                path,
                                os.lstat(path),
                                delete_authority=True,
                            )
                        )
                        if (
                            _BoundDirectory._windows_kernel_identity(handle)
                            != expected_identity
                            or _BoundDirectory._windows_final_path(handle)
                            != str(path)
                        ):
                            raise CheckpointError(
                                "published checkpoint member identity drifted"
                            )
                        published_member_handles.append(handle)
                        published_pinned_members[relative_path] = (
                            handle,
                            expected_identity,
                            created_member_sizes[relative_path],
                        )
                    published_guard_ready = True
                    movable_bound.verify_windows_final_paths()
                    production_guard.assert_exact(destination, kind="directory")
                    for path in (
                        destination / CHECKPOINT_MANIFEST_NAME,
                        destination / CHECKPOINT_MANIFEST_HASH_NAME,
                        *(
                            destination / Path(item["relative_path"])
                            for item in databases
                        ),
                    ):
                        production_guard.assert_exact(path, kind="file")
                    published = True
                finally:
                    if monitor is not None:
                        monitor.close()
        else:
            os.replace(partial, destination)
            published = True
        partial_file_stack.close()
        partial_directory_stack.close()
    except BaseException:
        partial_file_stack.close()
        if production_guard is not None:
            cleanup_error: BaseException | None = None
            if published_root_guard_ready:
                try:
                    if publication_monitor is not None:
                        try:
                            publication_monitor.close()
                        except BaseException:
                            # The operation is already failing; exact handle
                            # deletion below remains mandatory even when the
                            # mutation monitor supplies the original cause.
                            pass
                        publication_monitor = None
                    assert published_root_bound is not None
                    _delete_guarded_production_checkpoint(
                        root_bound=published_root_bound,
                        orphan_member_identities=(
                            created_member_cleanup_identities
                        ),
                        member_handles=tuple(published_member_handles),
                        member_stack=published_member_stack,
                        state_stack=published_state_stack,
                        root_stack=published_root_stack,
                    )
                except BaseException as error:
                    cleanup_error = error
                published_root_guard_ready = False
                published_guard_ready = False
            elif not published and partial_bound is not None:
                try:
                    published_member_stack.close()
                    published_state_stack.close()
                    published_root_stack.close()
                    partial_directory_stack.close()
                    _cleanup_exact_production_checkpoint(
                        guard=production_guard,
                        target=publication_path,
                        expected_root_identity=created_partial_identity,
                        expected_database_names={
                            f"{logical_name}.sqlite3"
                            for logical_name, _source in normalized_sources
                        },
                    )
                except BaseException as error:
                    cleanup_error = error
            try:
                partial_directory_stack.close()
            except BaseException as error:
                cleanup_error = cleanup_error or error
            if cleanup_error is not None:
                raise CheckpointError(
                    "production checkpoint cleanup did not close exact partial"
                ) from cleanup_error
        else:
            partial_directory_stack.close()
            if partial.exists():
                shutil.rmtree(partial, ignore_errors=True)
        raise

    if production_guard is None:
        verification = verify_sqlite_checkpoint(
            destination,
            scratch_root=resolved_scratch_root,
        )
    else:
        if (
            not published_guard_ready
            or published_root_bound is None
            or published_state_bound is None
            or publication_monitor is None
        ):
            raise CheckpointError("published checkpoint guard is incomplete")
        try:
            verification = _verify_production_sqlite_checkpoint_under_guard(
                destination,
                guard=production_guard,
                directory_pinned=True,
                files_pinned=True,
                pinned_members=published_pinned_members,
            )
            production_guard.assert_exact(destination, kind="directory")
            if not verification.valid:
                raise CheckpointError(
                    "new immutable checkpoint failed post-publish verification: "
                    + ",".join(verification.errors)
                )
            closing_monitor = publication_monitor
            publication_monitor = None
            closing_monitor.close()
        except BaseException:
            try:
                if publication_monitor is not None:
                    try:
                        publication_monitor.close()
                    except BaseException:
                        pass
                    publication_monitor = None
                _delete_guarded_production_checkpoint(
                    root_bound=published_root_bound,
                    orphan_member_identities=created_member_cleanup_identities,
                    member_handles=tuple(published_member_handles),
                    member_stack=published_member_stack,
                    state_stack=published_state_stack,
                    root_stack=published_root_stack,
                )
            except BaseException as cleanup_error:
                raise CheckpointError(
                    "failed published checkpoint could not be cleaned exactly"
                ) from cleanup_error
            published_guard_ready = False
            raise
        published_member_stack.close()
        published_state_stack.close()
        published_root_stack.close()
        published_guard_ready = False
    if not verification.valid:
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


def _verify_sqlite_checkpoint_impl(
    checkpoint_path: Path,
    *,
    scratch_root: Path | None = None,
    in_memory_restore: bool = False,
) -> CheckpointVerification:
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
                scratch_root=scratch_root,
                in_memory_restore=in_memory_restore,
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


def verify_sqlite_checkpoint(
    checkpoint_path: Path,
    *,
    scratch_root: Path | None = None,
) -> CheckpointVerification:
    """Verify a non-production/test checkpoint with an explicit scratch root."""

    try:
        reject_test_only_path_on_production_vm(
            Path(checkpoint_path), label="generic checkpoint verification path"
        )
        if scratch_root is not None:
            reject_test_only_path_on_production_vm(
                Path(scratch_root), label="generic checkpoint verification scratch"
            )
    except VMBoundaryError:
        root = Path(checkpoint_path)
        return CheckpointVerification(
            checkpoint_id=None,
            root=root,
            valid=False,
            manifest_sha256=None,
            captured_at=None,
            database_count=0,
            errors=("production_verification_requires_writer_attempt",),
        )
    return _verify_sqlite_checkpoint_impl(
        checkpoint_path,
        scratch_root=scratch_root,
        in_memory_restore=False,
    )


def _verify_production_sqlite_checkpoint(
    checkpoint_path: Path,
    *,
    attempt_id: str,
) -> CheckpointVerification:
    """Read-only exact-D verification pinned to one writer-handoff attempt."""

    attempt_id = _identifier(attempt_id, label="writer handoff attempt ID")
    production = Path(str(PRODUCTION_VM_ROOT))
    expected_parent = (
        production / "tmp" / "writer-handoff" / attempt_id / "checkpoints"
    )
    root = Path(os.path.normpath(str(checkpoint_path)))
    if root.parent != expected_parent or root.name in {"", ".", ".."}:
        raise CheckpointError(
            "production checkpoint verification is outside the exact live attempt"
        )
    scratch = expected_parent.parent / "restore-proof"
    with _ProductionCheckpointGuard(
        expected_parent,
        scratch,
        create_missing=False,
    ) as guard:
        return _verify_production_sqlite_checkpoint_under_guard(root, guard=guard)


def _read_production_sqlite_checkpoint_bytes(
    checkpoint_path: Path,
    *,
    attempt_id: str,
    expected_manifest_sha256: str,
) -> Mapping[str, bytes]:
    """Return verified DB bytes without reopening any checkpoint pathname.

    The checkpoint directory, its state directory, and all four immutable files
    remain pinned for the complete read and verification interval.  The caller
    receives only in-memory bytes, so a later path swap cannot alter the state
    that is installed.
    """

    attempt_id = _identifier(attempt_id, label="writer handoff attempt ID")
    if _SHA256_RE.fullmatch(expected_manifest_sha256) is None:
        raise CheckpointError("expected checkpoint manifest hash is invalid")
    production = Path(str(PRODUCTION_VM_ROOT))
    expected_parent = (
        production / "tmp" / "writer-handoff" / attempt_id / "checkpoints"
    )
    root = Path(os.path.normpath(str(checkpoint_path)))
    if root.parent != expected_parent or root.name in {"", ".", ".."}:
        raise CheckpointError(
            "production checkpoint byte read is outside the exact live attempt"
        )
    _identifier(root.name, label="checkpoint ID")
    scratch = expected_parent.parent / "restore-proof"
    with _ProductionCheckpointGuard(
        expected_parent,
        scratch,
        create_missing=False,
    ) as guard:
        guard.assert_exact(root, kind="directory")
        assert guard._safe_root is not None
        state_root = root / "state"
        guard.assert_exact(state_root, kind="directory")
        with ExitStack() as pins:
            pins.enter_context(
                _BoundDirectory(guard._safe_root, root, protect_rename=True)
            )
            pins.enter_context(
                _BoundDirectory(guard._safe_root, state_root, protect_rename=True)
            )
            expected_root_names = {
                CHECKPOINT_MANIFEST_NAME,
                CHECKPOINT_MANIFEST_HASH_NAME,
                "state",
            }
            expected_state_names = {
                "comments.sqlite3",
                "research_workspace.sqlite3",
            }
            if _closed_directory_names(root) != expected_root_names:
                raise CheckpointError("production checkpoint root inventory differs")
            if _closed_directory_names(state_root) != expected_state_names:
                raise CheckpointError("production checkpoint state inventory differs")

            members = {
                "manifest": root / CHECKPOINT_MANIFEST_NAME,
                "sidecar": root / CHECKPOINT_MANIFEST_HASH_NAME,
                "comments": state_root / "comments.sqlite3",
                "research_workspace": state_root / "research_workspace.sqlite3",
            }
            raw_members: dict[str, bytes] = {}
            for label, path in members.items():
                guard.assert_exact(path, kind="file")
                raw_members[label] = pins.enter_context(
                    _read_pinned_regular_bytes(path, os.lstat(path))
                )

            try:
                manifest = json.loads(raw_members["manifest"].decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise CheckpointError("pinned checkpoint manifest is unreadable") from error
            validate_checkpoint_manifest(manifest)
            if raw_members["manifest"] != canonical_manifest_bytes(manifest):
                raise CheckpointError("pinned checkpoint manifest is not canonical")
            if manifest.get("checkpoint_id") != root.name:
                raise CheckpointError("pinned checkpoint ID differs from directory")
            digest = manifest_sha256(manifest)
            try:
                sidecar = raw_members["sidecar"].decode("ascii").strip()
            except UnicodeDecodeError as error:
                raise CheckpointError("pinned checkpoint sidecar is unreadable") from error
            if sidecar != digest or digest != expected_manifest_sha256:
                raise CheckpointError("pinned checkpoint durable hash differs")

            state = manifest.get("state")
            if not isinstance(state, dict) or not isinstance(
                state.get("databases"), list
            ):
                raise CheckpointError("pinned checkpoint database inventory is missing")
            databases = state["databases"]
            if (
                state.get("database_count") != 2
                or len(databases) != 2
                or hashlib.sha256(canonical_manifest_bytes(databases)).hexdigest()
                != state.get("inventory_sha256")
            ):
                raise CheckpointError("pinned checkpoint database inventory differs")
            expected_paths = {
                "comments": "state/comments.sqlite3",
                "research_workspace": "state/research_workspace.sqlite3",
            }
            records: dict[str, Mapping[str, object]] = {}
            for record in databases:
                if not isinstance(record, dict):
                    raise CheckpointError("pinned checkpoint database record is invalid")
                logical_name = record.get("logical_name")
                if (
                    logical_name not in expected_paths
                    or record.get("relative_path") != expected_paths[logical_name]
                    or logical_name in records
                ):
                    raise CheckpointError("pinned checkpoint database mapping differs")
                records[str(logical_name)] = record
            if set(records) != set(expected_paths):
                raise CheckpointError("pinned checkpoint database names differ")
            for logical_name, record in records.items():
                actual = {
                    "logical_name": logical_name,
                    "relative_path": expected_paths[logical_name],
                    **_database_facts_from_bytes(raw_members[logical_name]),
                    "restore_validation": {
                        "integrity": True,
                        "foreign_keys": True,
                        "schema_matches": True,
                        "logical_counts_match": True,
                    },
                }
                if actual != record:
                    raise CheckpointError("pinned checkpoint database evidence differs")

            if (
                _closed_directory_names(root) != expected_root_names
                or _closed_directory_names(state_root) != expected_state_names
            ):
                raise CheckpointError("production checkpoint inventory drifted while read")
            return {
                "comments": raw_members["comments"],
                "research_workspace": raw_members["research_workspace"],
            }


def _verify_production_sqlite_checkpoint_under_guard(
    root: Path,
    *,
    guard: _ProductionCheckpointGuard,
    directory_pinned: bool = False,
    files_pinned: bool = False,
    pinned_members: Mapping[
        Path, tuple[int, tuple[int, int, int], int]
    ] | None = None,
) -> CheckpointVerification:
    guard.assert_exact(root, kind="directory")
    assert guard._safe_root is not None
    if pinned_members is not None:
        checkpoint_id: str | None = None
        captured_at: datetime | None = None
        digest: str | None = None
        database_count = 0
        errors: list[str] = []
        try:
            raw_members = {
                relative: _read_open_windows_regular_bytes(
                    handle,
                    expected_path=root / relative,
                    expected_identity=identity,
                    expected_size=size,
                )
                for relative, (handle, identity, size) in pinned_members.items()
            }
            manifest_relative = Path(CHECKPOINT_MANIFEST_NAME)
            sidecar_relative = Path(CHECKPOINT_MANIFEST_HASH_NAME)
            try:
                manifest = json.loads(raw_members[manifest_relative].decode("utf-8"))
            except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as error:
                raise CheckpointError("pinned checkpoint manifest is unreadable") from error
            validate_checkpoint_manifest(manifest)
            if raw_members[manifest_relative] != canonical_manifest_bytes(manifest):
                raise CheckpointError("pinned checkpoint manifest is not canonical")
            checkpoint_id = str(manifest["checkpoint_id"])
            if checkpoint_id != root.name:
                raise CheckpointError("pinned checkpoint ID differs")
            captured_at = _parse_timestamp(manifest["captured_at"])
            digest = manifest_sha256(manifest)
            try:
                sidecar = raw_members[sidecar_relative].decode("ascii").strip()
            except (KeyError, UnicodeDecodeError) as error:
                raise CheckpointError("pinned checkpoint sidecar is unreadable") from error
            if sidecar != digest:
                raise CheckpointError("pinned checkpoint sidecar differs")
            state = manifest["state"]
            databases = state["databases"]
            database_count = len(databases)
            if (
                state["database_count"] != database_count
                or hashlib.sha256(canonical_manifest_bytes(databases)).hexdigest()
                != state["inventory_sha256"]
            ):
                raise CheckpointError("pinned checkpoint inventory hash differs")
            expected_members = {manifest_relative, sidecar_relative}
            seen_names: set[str] = set()
            for record in databases:
                logical_name = str(record["logical_name"])
                relative = Path(str(record["relative_path"]))
                if logical_name in seen_names or relative.parent != Path("state"):
                    raise CheckpointError("pinned checkpoint database mapping differs")
                seen_names.add(logical_name)
                expected_members.add(relative)
                raw = raw_members.get(relative)
                if raw is None:
                    raise CheckpointError("pinned checkpoint database is missing")
                actual = {
                    "logical_name": logical_name,
                    "relative_path": relative.as_posix(),
                    **_database_facts_from_bytes(raw),
                    "restore_validation": {
                        "integrity": True,
                        "foreign_keys": True,
                        "schema_matches": True,
                        "logical_counts_match": True,
                    },
                }
                if actual != record:
                    raise CheckpointError("pinned checkpoint database evidence differs")
            if set(raw_members) != expected_members:
                raise CheckpointError("pinned checkpoint member set differs")
            if _closed_directory_names(root) != {
                "state",
                CHECKPOINT_MANIFEST_NAME,
                CHECKPOINT_MANIFEST_HASH_NAME,
            } or _closed_directory_names(root / "state") != {
                path.name for path in expected_members if path.parent == Path("state")
            }:
                raise CheckpointError("pinned checkpoint directory inventory differs")
            guard.assert_exact(root, kind="directory")
        except (
            CheckpointError,
            IdentityContractError,
            KeyError,
            TypeError,
            ValueError,
            OSError,
            sqlite3.Error,
        ):
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
    with ExitStack() as pins:
        if not directory_pinned:
            pins.enter_context(
                _BoundDirectory(guard._safe_root, root, protect_rename=True)
            )
        files = sorted(path for path in root.rglob("*") if path.is_file())
        for path in files:
            guard.assert_exact(path, kind="file")
            if not files_pinned:
                pins.enter_context(_pin_regular_file(path, os.lstat(path)))
        report = _verify_sqlite_checkpoint_impl(
            root,
            scratch_root=None,
            in_memory_restore=True,
        )
        guard.assert_exact(root, kind="directory")
        return report


__all__ = [
    "CHECKPOINT_SCHEMA",
    "CHECKPOINT_MANIFEST_HASH_NAME",
    "CHECKPOINT_MANIFEST_NAME",
    "CheckpointConflictError",
    "CheckpointCreation",
    "CheckpointError",
    "CheckpointVerification",
    "create_sqlite_checkpoint",
    "validate_checkpoint_manifest",
    "verify_sqlite_checkpoint",
]
