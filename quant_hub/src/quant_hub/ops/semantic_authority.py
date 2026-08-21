"""Promote a completed semantic workspace into protected active state.

The compiler workspace is deliberately not made authoritative in place.  This
module takes one guarded SQLite online-backup snapshot, proves deterministic
logical equivalence, and atomically installs it outside the Git project.  It
does not import or mutate the semantic compiler implementation, and it never
copies source prose into the promotion receipt.
"""

from __future__ import annotations

import argparse
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import struct
from typing import Any, Iterator, Mapping
import uuid

from quant_hub.config import (
    ConfigurationError,
    ensure_no_reparse_components,
    stat_is_reparse_point,
)


RECEIPT_SCHEMA = "qrh-semantic-authority-promotion/v2"
TARGET_FILE_NAME = "semantic_jobs.sqlite3"
RECEIPT_DIRECTORY = "semantic_promotion_receipts"
ACTIVE_JOB_STATUSES = frozenset({"queued", "running"})
KNOWN_JOB_STATUSES = frozenset(
    {
        "queued",
        "running",
        "succeeded",
        "failed_retryable",
        "invalid_evidence",
        "provider_identity_drift",
        "blocked_policy",
        "superseded_identity",
    }
)
KNOWN_FACT_STATUSES = frozenset(
    {
        "source_explicit",
        "model_candidate",
        "machine_verified",
        "human_reviewed",
        "rejected",
        "deprecated",
    }
)
FORMAL_ITEM_STATUSES = frozenset(
    {"source_explicit", "machine_verified", "human_reviewed"}
)

# This is the storage contract implemented by knowledge.semantic.SemanticJobStore.
# Keeping it here avoids opening/initialising the campaign store during promotion.
_EXPECTED_COLUMNS: Mapping[str, tuple[tuple[str, str, int, int], ...]] = {
    "semantic_job": (
        ("job_key", "TEXT", 0, 1),
        ("document_id", "TEXT", 1, 0),
        ("document_version_id", "TEXT", 1, 0),
        ("payload_json", "TEXT", 1, 0),
        ("status", "TEXT", 1, 0),
        ("error_code", "TEXT", 0, 0),
        ("created_at", "TEXT", 1, 0),
        ("updated_at", "TEXT", 1, 0),
    ),
    "knowledge_generation": (
        ("generation_id", "TEXT", 0, 1),
        ("job_key", "TEXT", 1, 0),
        ("document_version_id", "TEXT", 1, 0),
        ("payload_json", "TEXT", 1, 0),
        ("status", "TEXT", 1, 0),
        ("created_at", "TEXT", 1, 0),
    ),
    "generation_eligibility": (
        ("generation_id", "TEXT", 0, 1),
        ("eligible", "INTEGER", 1, 0),
        ("actor", "TEXT", 1, 0),
        ("reason", "TEXT", 1, 0),
        ("created_at", "TEXT", 1, 0),
    ),
    "knowledge_candidate": (
        ("candidate_id", "TEXT", 0, 1),
        ("generation_id", "TEXT", 1, 0),
        ("document_version_id", "TEXT", 1, 0),
        ("payload_json", "TEXT", 1, 0),
        ("fact_status", "TEXT", 1, 0),
        ("created_at", "TEXT", 1, 0),
    ),
    "knowledge_item": (
        ("knowledge_item_id", "TEXT", 0, 1),
        ("document_version_id", "TEXT", 1, 0),
        ("payload_json", "TEXT", 1, 0),
        ("fact_status", "TEXT", 1, 0),
        ("created_at", "TEXT", 1, 0),
    ),
    "knowledge_item_state": (
        ("knowledge_item_id", "TEXT", 0, 1),
        ("fact_status", "TEXT", 1, 0),
        ("actor", "TEXT", 0, 0),
        ("reason", "TEXT", 0, 0),
        ("updated_at", "TEXT", 1, 0),
    ),
    "knowledge_decision": (
        ("decision_id", "TEXT", 0, 1),
        ("subject_id", "TEXT", 1, 0),
        ("decision", "TEXT", 1, 0),
        ("actor", "TEXT", 1, 0),
        ("reason", "TEXT", 0, 0),
        ("created_at", "TEXT", 1, 0),
    ),
    "recompile_campaign": (
        ("campaign_id", "TEXT", 0, 1),
        ("payload_json", "TEXT", 1, 0),
        ("created_at", "TEXT", 1, 0),
    ),
}


class SemanticAuthorityError(RuntimeError):
    """A fail-closed authority promotion or verification failure."""


@dataclass(frozen=True, slots=True)
class DatabaseIdentity:
    file_sha256: str
    logical_sha256: str
    schema_sha256: str
    row_counts: dict[str, int]

    def stable_identity_payload(self) -> dict[str, Any]:
        return {
            "logical_sha256": self.logical_sha256,
            "schema_sha256": self.schema_sha256,
            "row_counts": dict(sorted(self.row_counts.items())),
        }


@dataclass(frozen=True, slots=True)
class SemanticPromotionReceipt:
    schema_version: str
    promotion_id: str
    promoted_at: str
    source: dict[str, Any]
    target: dict[str, Any]
    authority: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "promotion_id": self.promotion_id,
            "promoted_at": self.promoted_at,
            "source": self.source,
            "target": self.target,
            "authority": self.authority,
        }


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _path_is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _ensure_safe_path(path: Path, *, label: str) -> None:
    try:
        ensure_no_reparse_components(path)
    except (ConfigurationError, OSError) as error:
        raise SemanticAuthorityError(f"{label} contains an unsafe path component") from error


def _validate_regular_file(path: Path, *, label: str) -> None:
    _ensure_safe_path(path, label=label)
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise SemanticAuthorityError(f"{label} does not exist") from error
    if (
        stat_is_reparse_point(info)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
    ):
        raise SemanticAuthorityError(
            f"{label} must be a regular, non-reparse, single-link file"
        )


def _validate_roots(
    project_root: Path, state_root: Path, source_path: Path
) -> tuple[Path, Path, Path]:
    _ensure_safe_path(project_root, label="project_root")
    _ensure_safe_path(state_root, label="state_root")
    _ensure_safe_path(source_path, label="semantic campaign source")
    try:
        project = project_root.resolve(strict=True)
        state = state_root.resolve(strict=True)
        source = source_path.resolve(strict=True)
    except FileNotFoundError as error:
        raise SemanticAuthorityError("project, state, and source must already exist") from error
    if not project.is_dir() or not state.is_dir():
        raise SemanticAuthorityError("project_root and state_root must be directories")
    if _path_is_relative_to(state, project) or _path_is_relative_to(project, state):
        raise SemanticAuthorityError(
            "protected state_root must be outside and non-overlapping with the Git project"
        )
    if _path_is_relative_to(source, state):
        raise SemanticAuthorityError("campaign source must not already be under state_root")
    _validate_regular_file(source, label="semantic campaign source")
    return project, state, source


def _read_only_connection(path: Path) -> sqlite3.Connection:
    # quote=True also escapes '?' and '#' in local filenames in SQLite URI form.
    from urllib.parse import quote

    connection = sqlite3.connect(
        "file:" + quote(path.as_posix(), safe="/:\\") + "?mode=ro",
        uri=True,
        timeout=0,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def _quote_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _validate_database(connection: sqlite3.Connection) -> None:
    integrity_rows = connection.execute("PRAGMA integrity_check").fetchall()
    if [str(row[0]) for row in integrity_rows] != ["ok"]:
        raise SemanticAuthorityError("SQLite integrity_check failed")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise SemanticAuthorityError("SQLite foreign_key_check failed")

    objects = connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
    ).fetchall()
    if any(str(row["type"]) in {"view", "trigger"} for row in objects):
        raise SemanticAuthorityError("semantic authority schema forbids views and triggers")
    table_names = {
        str(row["name"]) for row in objects if str(row["type"]) == "table"
    }
    if table_names != set(_EXPECTED_COLUMNS):
        raise SemanticAuthorityError("semantic authority table set is not recognised")

    for table_name, expected in _EXPECTED_COLUMNS.items():
        rows = connection.execute(
            f"PRAGMA table_info({_quote_identifier(table_name)})"
        ).fetchall()
        actual = tuple(
            (
                str(row["name"]),
                str(row["type"]).upper(),
                int(row["notnull"]),
                int(row["pk"]),
            )
            for row in rows
        )
        if actual != expected:
            raise SemanticAuthorityError(
                f"semantic authority column contract mismatch: {table_name}"
            )

    unknown_status = connection.execute(
        "SELECT status FROM semantic_job "
        "WHERE status NOT IN (?,?,?,?,?,?,?,?) LIMIT 1",
        tuple(sorted(KNOWN_JOB_STATUSES)),
    ).fetchone()
    if unknown_status is not None:
        raise SemanticAuthorityError("semantic_job contains an unknown status")
    unknown_generation_status = connection.execute(
        "SELECT status FROM knowledge_generation "
        "WHERE status NOT IN (?,?,?,?,?,?,?,?) LIMIT 1",
        tuple(sorted(KNOWN_JOB_STATUSES)),
    ).fetchone()
    if unknown_generation_status is not None:
        raise SemanticAuthorityError("knowledge_generation contains an unknown status")
    fact_placeholders = ",".join("?" for _ in KNOWN_FACT_STATUSES)
    unknown_candidate_status = connection.execute(
        "SELECT fact_status FROM knowledge_candidate "
        f"WHERE fact_status NOT IN ({fact_placeholders}) LIMIT 1",
        tuple(sorted(KNOWN_FACT_STATUSES)),
    ).fetchone()
    if unknown_candidate_status is not None:
        raise SemanticAuthorityError("knowledge_candidate contains an unknown fact status")
    formal_placeholders = ",".join("?" for _ in FORMAL_ITEM_STATUSES)
    unknown_item_status = connection.execute(
        "SELECT fact_status FROM knowledge_item "
        f"WHERE fact_status NOT IN ({formal_placeholders}) LIMIT 1",
        tuple(sorted(FORMAL_ITEM_STATUSES)),
    ).fetchone()
    if unknown_item_status is not None:
        raise SemanticAuthorityError("knowledge_item contains a non-formal fact status")
    unknown_item_state = connection.execute(
        "SELECT fact_status FROM knowledge_item_state "
        f"WHERE fact_status NOT IN ({fact_placeholders}) LIMIT 1",
        tuple(sorted(KNOWN_FACT_STATUSES)),
    ).fetchone()
    if unknown_item_state is not None:
        raise SemanticAuthorityError("knowledge_item_state contains an unknown fact status")


def _active_job_count(connection: sqlite3.Connection) -> int:
    placeholders = ",".join("?" for _ in ACTIVE_JOB_STATUSES)
    row = connection.execute(
        f"SELECT COUNT(*) FROM semantic_job WHERE status IN ({placeholders})",
        tuple(sorted(ACTIVE_JOB_STATUSES)),
    ).fetchone()
    return int(row[0])


def _encoded_sqlite_value(value: Any) -> bytes:
    if value is None:
        return b"n"
    if isinstance(value, int):
        payload = str(value).encode("ascii")
        return b"i" + len(payload).to_bytes(8, "big") + payload
    if isinstance(value, float):
        if math.isnan(value):
            payload = b"nan"
        else:
            payload = struct.pack(">d", value)
        return b"f" + len(payload).to_bytes(8, "big") + payload
    if isinstance(value, str):
        payload = value.encode("utf-8")
        return b"s" + len(payload).to_bytes(8, "big") + payload
    if isinstance(value, (bytes, bytearray, memoryview)):
        payload = bytes(value)
        return b"b" + len(payload).to_bytes(8, "big") + payload
    raise SemanticAuthorityError(f"unsupported SQLite value type: {type(value).__name__}")


def _schema_payload(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    objects = connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name,tbl_name,sql"
    ).fetchall()
    return [
        {
            "type": str(row["type"]),
            "name": str(row["name"]),
            "table": str(row["tbl_name"]),
            "sql": str(row["sql"]),
        }
        for row in objects
    ]


def _logical_identity(connection: sqlite3.Connection, file_path: Path) -> DatabaseIdentity:
    _validate_database(connection)
    schema_sha256 = hashlib.sha256(
        _canonical_bytes(_schema_payload(connection))
    ).hexdigest()
    row_counts: dict[str, int] = {}
    table_hashes: dict[str, str] = {}
    for table_name in sorted(_EXPECTED_COLUMNS):
        columns = [column[0] for column in _EXPECTED_COLUMNS[table_name]]
        select = ",".join(_quote_identifier(column) for column in columns)
        rows = connection.execute(
            f"SELECT {select} FROM {_quote_identifier(table_name)}"
        )
        row_digests: list[bytes] = []
        count = 0
        for row in rows:
            encoded = b"".join(_encoded_sqlite_value(value) for value in tuple(row))
            row_digests.append(hashlib.sha256(encoded).digest())
            count += 1
        row_digests.sort()
        table_digest = hashlib.sha256()
        table_digest.update(_canonical_bytes({"table": table_name, "columns": columns}))
        for row_digest in row_digests:
            table_digest.update(row_digest)
        row_counts[table_name] = count
        table_hashes[table_name] = table_digest.hexdigest()
    logical_sha256 = hashlib.sha256(
        _canonical_bytes(
            {
                "schema_sha256": schema_sha256,
                "row_counts": row_counts,
                "table_hashes": table_hashes,
            }
        )
    ).hexdigest()
    return DatabaseIdentity(
        file_sha256=_sha256_file(file_path),
        logical_sha256=logical_sha256,
        schema_sha256=schema_sha256,
        row_counts=row_counts,
    )


def _source_identity_payload(identity: DatabaseIdentity) -> dict[str, Any]:
    """Describe the logical campaign source plus a point-in-time observation.

    In WAL mode the main database file can legitimately change when a later
    checkpoint folds already-committed pages into it.  Its byte hash therefore
    cannot be the archived source authority.  We retain that hash only as a
    labelled observation; the stable source identity is the schema and
    deterministic logical content hash.
    """

    return {
        "path_role": "campaign_workspace_archived_read_only",
        "observed_main_file_sha256": identity.file_sha256,
        "logical_sha256": identity.logical_sha256,
        "schema_sha256": identity.schema_sha256,
        "row_counts": dict(sorted(identity.row_counts.items())),
    }


def _target_identity_payload(identity: DatabaseIdentity) -> dict[str, Any]:
    return {
        "path_role": "protected_state_active_authority",
        "file_sha256": identity.file_sha256,
        "logical_sha256": identity.logical_sha256,
        "schema_sha256": identity.schema_sha256,
        "row_counts": dict(sorted(identity.row_counts.items())),
    }


def _same_logical_identity(left: DatabaseIdentity, right: DatabaseIdentity) -> bool:
    return left.stable_identity_payload() == right.stable_identity_payload()


def _promotion_id(unsigned_receipt: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(
        _canonical_bytes({"contract": RECEIPT_SCHEMA, **unsigned_receipt})
    ).hexdigest()
    return "semprom_" + digest[:40]


def _receipt_from_dict(value: Any) -> SemanticPromotionReceipt:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "promotion_id",
        "promoted_at",
        "source",
        "target",
        "authority",
    }:
        raise SemanticAuthorityError("promotion receipt shape is invalid")
    if value["schema_version"] != RECEIPT_SCHEMA:
        raise SemanticAuthorityError("promotion receipt schema is invalid")
    if not isinstance(value["promoted_at"], str):
        raise SemanticAuthorityError("promotion receipt timestamp is invalid")
    try:
        promoted_at = datetime.fromisoformat(value["promoted_at"].replace("Z", "+00:00"))
    except ValueError as error:
        raise SemanticAuthorityError("promotion receipt timestamp is invalid") from error
    if promoted_at.tzinfo is None or promoted_at.utcoffset() is None:
        raise SemanticAuthorityError("promotion receipt timestamp must include a timezone")
    if not isinstance(value["source"], dict) or not isinstance(value["target"], dict):
        raise SemanticAuthorityError("promotion receipt identities are invalid")
    expected_source_keys = {
        "path_role",
        "observed_main_file_sha256",
        "logical_sha256",
        "schema_sha256",
        "row_counts",
    }
    expected_target_keys = {
        "path_role",
        "file_sha256",
        "logical_sha256",
        "schema_sha256",
        "row_counts",
    }
    if (
        set(value["source"]) != expected_source_keys
        or set(value["target"]) != expected_target_keys
    ):
        raise SemanticAuthorityError("promotion receipt identity shape is invalid")
    if value["authority"] != {
        "active": "target",
        "source": "archived_read_only",
    }:
        raise SemanticAuthorityError("promotion receipt authority roles are invalid")
    for side, physical_field in (
        ("source", "observed_main_file_sha256"),
        ("target", "file_sha256"),
    ):
        for field in (physical_field, "logical_sha256", "schema_sha256"):
            digest = value[side].get(field)
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                raise SemanticAuthorityError("promotion receipt hash is invalid")
        counts = value[side].get("row_counts")
        if not isinstance(counts, dict) or set(counts) != set(_EXPECTED_COLUMNS):
            raise SemanticAuthorityError("promotion receipt row counts are invalid")
        if any(not isinstance(count, int) or count < 0 for count in counts.values()):
            raise SemanticAuthorityError("promotion receipt row count is invalid")
    if value["source"]["path_role"] != "campaign_workspace_archived_read_only":
        raise SemanticAuthorityError("promotion receipt source role is invalid")
    if value["target"]["path_role"] != "protected_state_active_authority":
        raise SemanticAuthorityError("promotion receipt target role is invalid")
    receipt = SemanticPromotionReceipt(**value)
    unsigned = receipt.to_dict()
    unsigned.pop("promotion_id")
    if receipt.promotion_id != _promotion_id(unsigned):
        raise SemanticAuthorityError("promotion receipt identity is invalid")
    return receipt


def _load_receipt(path: Path) -> SemanticPromotionReceipt:
    _validate_regular_file(path, label="semantic promotion receipt")
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SemanticAuthorityError("promotion receipt is not canonical JSON") from error
    if raw != _canonical_bytes(value):
        raise SemanticAuthorityError("promotion receipt is not canonically encoded")
    return _receipt_from_dict(value)


@contextmanager
def _promotion_lock(state_root: Path) -> Iterator[None]:
    path = state_root / ".semantic_authority_promotion.lock"
    _ensure_safe_path(path, label="semantic promotion lock")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise SemanticAuthorityError("another semantic authority promotion is active") from error
    try:
        os.write(descriptor, b"qrh-semantic-authority-promotion-lock/v1\n")
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        _validate_regular_file(path, label="semantic promotion lock")
        yield
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _write_receipt_immutable(path: Path, receipt: SemanticPromotionReceipt) -> None:
    payload = _canonical_bytes(receipt.to_dict())
    if path.exists():
        existing = _load_receipt(path)
        if existing != receipt:
            raise SemanticAuthorityError("immutable promotion receipt conflicts")
        return
    partial = path.with_name(path.name + "." + uuid.uuid4().hex + ".partial")
    try:
        with partial.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        _validate_regular_file(partial, label="promotion receipt partial")
        try:
            os.replace(partial, path)
        except OSError as error:
            raise SemanticAuthorityError("atomic receipt install failed") from error
        if path.read_bytes() != payload:
            raise SemanticAuthorityError("promotion receipt install verification failed")
    finally:
        try:
            partial.unlink()
        except FileNotFoundError:
            pass


def _matching_receipt(
    receipts: Path,
    *,
    source_identity: DatabaseIdentity,
    target_identity: DatabaseIdentity,
) -> SemanticPromotionReceipt | None:
    expected_target = _target_identity_payload(target_identity)
    source_stable = source_identity.stable_identity_payload()
    matches: list[SemanticPromotionReceipt] = []
    for path in sorted(receipts.glob("semprom_*.json")):
        receipt = _load_receipt(path)
        if receipt.target != expected_target:
            continue
        receipt_source_stable = {
            "logical_sha256": receipt.source["logical_sha256"],
            "schema_sha256": receipt.source["schema_sha256"],
            "row_counts": receipt.source["row_counts"],
        }
        if receipt_source_stable == source_stable:
            matches.append(receipt)
    if len(matches) > 1:
        raise SemanticAuthorityError("multiple receipts claim the same semantic authority")
    return matches[0] if matches else None


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def promote_semantic_authority(
    *,
    project_root: Path,
    state_root: Path,
    source_path: Path,
    promoted_at: str | None = None,
    expected_current_promotion_id: str | None = None,
) -> SemanticPromotionReceipt:
    """Atomically promote one quiescent semantic campaign SQLite snapshot.

    ``source_path`` is left byte-for-byte and logically unmodified.  A short
    ``BEGIN IMMEDIATE`` guard rejects concurrent writers while a separate
    read-only connection performs SQLite's online backup, including committed
    WAL content.  The caller is responsible for retaining the source as an
    archived read-only campaign artefact after this succeeds.
    """

    _project, state, source = _validate_roots(project_root, state_root, source_path)
    target = state / TARGET_FILE_NAME
    receipts = state / RECEIPT_DIRECTORY
    _ensure_safe_path(target, label="semantic authority target")
    _ensure_safe_path(receipts, label="promotion receipt root")
    if receipts.exists():
        if not receipts.is_dir() or stat_is_reparse_point(receipts.lstat()):
            raise SemanticAuthorityError("promotion receipt root is unsafe")
    else:
        receipts.mkdir(mode=0o700)
        _ensure_safe_path(receipts, label="promotion receipt root")

    with _promotion_lock(state):
        guard = sqlite3.connect(source, timeout=0, isolation_level=None)
        try:
            guard.execute("PRAGMA busy_timeout=0")
            try:
                guard.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as error:
                raise SemanticAuthorityError(
                    "semantic campaign is not quiescent or cannot be writer-fenced"
                ) from error
            with closing(_read_only_connection(source)) as source_connection:
                source_identity = _logical_identity(source_connection, source)
                if _active_job_count(source_connection):
                    raise SemanticAuthorityError(
                        "queued/running semantic jobs forbid authority promotion"
                    )

                install_required = not target.exists()
                if target.exists():
                    _validate_regular_file(target, label="semantic authority target")
                    with closing(_read_only_connection(target)) as target_connection:
                        target_identity = _logical_identity(target_connection, target)
                    same_logical_identity = _same_logical_identity(
                        source_identity, target_identity
                    )
                    try:
                        current = resolve_semantic_authority(
                            project_root=_project,
                            state_root=state,
                        )
                    except SemanticAuthorityError:
                        # A rotation can crash after atomic target replacement
                        # but before its immutable receipt is appended.  A retry
                        # may recover only when the target already equals this
                        # exact fenced source and the explicitly expected prior
                        # receipt remains valid.  No timestamp or attempt is
                        # guessed and no second target replacement is needed.
                        prior_path = receipts / f"{expected_current_promotion_id}.json"
                        if not (
                            same_logical_identity
                            and expected_current_promotion_id is not None
                            and prior_path.is_file()
                            and _load_receipt(prior_path).promotion_id
                            == expected_current_promotion_id
                        ):
                            raise
                        current = None
                    if current is not None and expected_current_promotion_id is not None and (
                        current.promotion_id != expected_current_promotion_id
                    ):
                        raise SemanticAuthorityError(
                            "expected current semantic promotion does not match"
                        )
                    if not same_logical_identity:
                        if expected_current_promotion_id is None:
                            raise SemanticAuthorityError(
                                "semantic authority rotation requires the exact current promotion"
                            )
                        install_required = True
                elif expected_current_promotion_id is not None:
                    raise SemanticAuthorityError(
                        "cannot supersede a semantic promotion when no authority exists"
                    )

                if install_required:
                    partial = target.with_name(
                        target.name + "." + uuid.uuid4().hex + ".partial"
                    )
                    try:
                        destination = sqlite3.connect(partial)
                        try:
                            source_connection.backup(destination)
                            destination.execute("PRAGMA journal_mode=DELETE")
                            destination.commit()
                        finally:
                            destination.close()
                        _validate_regular_file(partial, label="semantic authority partial")
                        with closing(_read_only_connection(partial)) as partial_connection:
                            target_identity = _logical_identity(partial_connection, partial)
                            if _active_job_count(partial_connection):
                                raise SemanticAuthorityError(
                                    "backup contains an active semantic job"
                                )
                        if not _same_logical_identity(source_identity, target_identity):
                            raise SemanticAuthorityError(
                                "SQLite online backup is not logically equivalent"
                            )
                        # Re-read under the same writer fence before the atomic install.
                        source_after = _logical_identity(source_connection, source)
                        if source_after != source_identity:
                            raise SemanticAuthorityError(
                                "semantic campaign changed during authority promotion"
                            )
                        try:
                            os.replace(partial, target)
                        except OSError as error:
                            raise SemanticAuthorityError(
                                "atomic semantic authority install failed"
                            ) from error
                        _validate_regular_file(target, label="semantic authority target")
                        target_identity = DatabaseIdentity(
                            file_sha256=_sha256_file(target),
                            logical_sha256=target_identity.logical_sha256,
                            schema_sha256=target_identity.schema_sha256,
                            row_counts=target_identity.row_counts,
                        )
                    finally:
                        try:
                            partial.unlink()
                        except FileNotFoundError:
                            pass

            existing = _matching_receipt(
                receipts,
                source_identity=source_identity,
                target_identity=target_identity,
            )
            if existing is not None:
                return existing

            unsigned_receipt = {
                "schema_version": RECEIPT_SCHEMA,
                "promoted_at": promoted_at or _utc_now(),
                "source": _source_identity_payload(source_identity),
                "target": _target_identity_payload(target_identity),
                "authority": {"active": "target", "source": "archived_read_only"},
            }
            promotion_id = _promotion_id(unsigned_receipt)
            receipt = SemanticPromotionReceipt(
                promotion_id=promotion_id,
                **unsigned_receipt,
            )
            receipt_path = receipts / f"{promotion_id}.json"
            _write_receipt_immutable(receipt_path, receipt)
            return receipt
        finally:
            if guard.in_transaction:
                guard.rollback()
            guard.close()


def verify_semantic_authority(
    *,
    project_root: Path,
    state_root: Path,
    promotion_id: str,
    source_path: Path | None = None,
) -> SemanticPromotionReceipt:
    """Verify active target, immutable receipt, and optionally archived source."""

    if not promotion_id.startswith("semprom_") or len(promotion_id) != 48:
        raise SemanticAuthorityError("promotion_id is invalid")
    receipt = resolve_semantic_authority(
        project_root=project_root,
        state_root=state_root,
    )
    if receipt.promotion_id != promotion_id:
        raise SemanticAuthorityError("promotion receipt does not match requested identity")
    if source_path is not None:
        project = project_root.resolve(strict=True)
        state = state_root.resolve(strict=True)
        _project, _state, source = _validate_roots(project, state, source_path)
        with closing(_read_only_connection(source)) as connection:
            source_identity = _logical_identity(connection, source)
            if _active_job_count(connection):
                raise SemanticAuthorityError("archived semantic source contains active jobs")
        expected_source_stable = source_identity.stable_identity_payload()
        receipt_source_stable = {
            "logical_sha256": receipt.source["logical_sha256"],
            "schema_sha256": receipt.source["schema_sha256"],
            "row_counts": receipt.source["row_counts"],
        }
        if receipt_source_stable != expected_source_stable:
            raise SemanticAuthorityError("archived semantic source does not match receipt")
    return receipt


def resolve_semantic_authority(
    *,
    project_root: Path,
    state_root: Path,
) -> SemanticPromotionReceipt:
    """Resolve the one immutable receipt matching the active semantic file.

    The protected state root may contain publish queue and audit material, but
    the semantic database itself is an immutable release input.  Resolution is
    therefore by its complete physical and logical identity, never by newest
    timestamp or directory order.
    """

    _ensure_safe_path(project_root, label="project_root")
    _ensure_safe_path(state_root, label="state_root")
    try:
        project = project_root.resolve(strict=True)
        state = state_root.resolve(strict=True)
    except FileNotFoundError as error:
        raise SemanticAuthorityError("project_root and state_root must exist") from error
    if not project.is_dir() or not state.is_dir():
        raise SemanticAuthorityError("project_root and state_root must be directories")
    if _path_is_relative_to(state, project) or _path_is_relative_to(project, state):
        raise SemanticAuthorityError("protected state_root overlaps the Git project")
    target = state / TARGET_FILE_NAME
    _validate_regular_file(target, label="semantic authority target")
    with closing(_read_only_connection(target)) as connection:
        target_identity = _logical_identity(connection, target)
        if _active_job_count(connection):
            raise SemanticAuthorityError("active semantic authority contains active jobs")
    expected_target = _target_identity_payload(target_identity)
    receipt_root = state / RECEIPT_DIRECTORY
    if not receipt_root.is_dir() or stat_is_reparse_point(receipt_root.lstat()):
        raise SemanticAuthorityError("semantic promotion receipt root is unavailable")
    matches = [
        receipt
        for path in sorted(receipt_root.glob("semprom_*.json"))
        if (receipt := _load_receipt(path)).target == expected_target
    ]
    if len(matches) != 1:
        raise SemanticAuthorityError(
            "active semantic authority does not have exactly one matching receipt"
        )
    return matches[0]


def _public_receipt(receipt: SemanticPromotionReceipt) -> dict[str, Any]:
    return {
        "schema_version": "qrh-semantic-authority-cli-result/v1",
        "status": "verified",
        "promotion_id": receipt.promotion_id,
        "file_sha256": receipt.target["file_sha256"],
        "logical_sha256": receipt.target["logical_sha256"],
        "schema_sha256": receipt.target["schema_sha256"],
        "row_counts": receipt.target["row_counts"],
    }


def main(argv: list[str] | None = None) -> int:
    """Operate the off-Git semantic authority without exposing source text."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    promote = commands.add_parser("promote")
    promote.add_argument("--source", type=Path, required=True)
    promote.add_argument("--expected-current-promotion-id")
    verify = commands.add_parser("verify")
    verify.add_argument("--promotion-id", required=True)
    verify.add_argument("--source", type=Path)
    commands.add_parser("resolve")
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "promote":
            receipt = promote_semantic_authority(
                project_root=arguments.project_root,
                state_root=arguments.state_root,
                source_path=arguments.source,
                expected_current_promotion_id=arguments.expected_current_promotion_id,
            )
        elif arguments.command == "verify":
            receipt = verify_semantic_authority(
                project_root=arguments.project_root,
                state_root=arguments.state_root,
                promotion_id=arguments.promotion_id,
                source_path=arguments.source,
            )
        else:
            receipt = resolve_semantic_authority(
                project_root=arguments.project_root,
                state_root=arguments.state_root,
            )
        document: dict[str, Any] = _public_receipt(receipt)
        code = 0
    except Exception as error:
        document = {
            "schema_version": "qrh-semantic-authority-cli-error/v1",
            "status": "error",
            "error_type": type(error).__name__,
        }
        code = 2
    print(json.dumps(document, ensure_ascii=False, sort_keys=True))
    return code


__all__ = [
    "DatabaseIdentity",
    "RECEIPT_SCHEMA",
    "SemanticAuthorityError",
    "SemanticPromotionReceipt",
    "promote_semantic_authority",
    "resolve_semantic_authority",
    "verify_semantic_authority",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
