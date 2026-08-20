from __future__ import annotations

from dataclasses import dataclass
import json
import sqlite3

from quant_hub.ids import new_public_id, object_id_for_sha256, sha256_hex, stable_sha256
from quant_hub.archive.source_reader import (
    SourceBoundaryError,
    SourceSnapshot,
    archive_origin_uri,
    validate_archive_relative_path,
    validate_utc_z,
)
from .db import immediate_transaction, utc_now
from .objects import ObjectStore, StoredObject


@dataclass(frozen=True, slots=True)
class RegistrationResult:
    object_id: str
    source_location_id: str
    run_id: str
    step_execution_id: str
    event_id: str
    idempotency_key: str
    run_created: bool


def register_verified_object(
    connection: sqlite3.Connection,
    stored: StoredObject,
    object_store: ObjectStore,
    *,
    media_type: str,
) -> str:
    """登记已落入内容寻址对象区的派生对象。

    对象写入和数据库登记不能跨文件系统/SQLite 形成分布式原子事务；失败时最多
    留下可垃圾回收的不可变 orphan，数据库绝不指向未逐字节复核的对象。
    """

    if not media_type or len(media_type) > 200:
        raise ValueError("object media type is required")
    if stored.object_id != object_id_for_sha256(stored.sha256):
        raise ValueError("stored object ID does not match its SHA-256 identity")
    if stored.relative_path != ObjectStore.relative_path(stored.sha256).as_posix():
        raise ValueError("stored object path does not match its SHA-256 identity")
    payload = object_store.read_bytes(stored.object_id)
    if len(payload) != stored.bytes or sha256_hex(payload) != stored.sha256:
        raise ValueError("stored object bytes do not match its declared identity")
    now = utc_now()
    with immediate_transaction(connection):
        connection.execute(
            """
            INSERT INTO object_blob(
                object_id,sha256,bytes,media_type,relative_blob_path,created_at,verification_status
            ) VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(object_id) DO NOTHING
            """,
            (
                stored.object_id,
                stored.sha256,
                stored.bytes,
                media_type,
                stored.relative_path,
                now,
                "verified",
            ),
        )
        row = connection.execute(
            """
            SELECT sha256,bytes,media_type,relative_blob_path,verification_status
            FROM object_blob WHERE object_id=?
            """,
            (stored.object_id,),
        ).fetchone()
        if row is None or (
            row["sha256"],
            row["bytes"],
            row["media_type"],
            row["relative_blob_path"],
            row["verification_status"],
        ) != (
            stored.sha256,
            stored.bytes,
            media_type,
            stored.relative_path,
            "verified",
        ):
            raise RuntimeError("object registry conflicts with immutable object identity")
    return stored.object_id


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def inspect_run(connection: sqlite3.Connection, run_id: str) -> dict[str, object]:
    run = connection.execute("SELECT * FROM pipeline_run WHERE run_id=?", (run_id,)).fetchone()
    if run is None:
        raise KeyError(f"pipeline run not found: {run_id}")
    steps = connection.execute(
        "SELECT * FROM step_execution WHERE run_id=? ORDER BY step_key", (run_id,)
    ).fetchall()
    events = connection.execute(
        "SELECT * FROM outbox_event WHERE aggregate_urn=? ORDER BY created_at,event_id",
        (run["subject_urn"],),
    ).fetchall()
    return {
        "run": dict(run),
        "steps": [dict(row) for row in steps],
        "outbox_events": [dict(row) for row in events],
    }


def register_archive_snapshot(
    connection: sqlite3.Connection,
    snapshot: SourceSnapshot,
    stored: StoredObject,
    object_store: ObjectStore,
) -> RegistrationResult:
    if snapshot.namespace != "archive":
        raise ValueError("source snapshot does not have a canonical Archive identity")
    try:
        validate_archive_relative_path(snapshot.relative_path)
        expected_origin_uri = archive_origin_uri(snapshot.relative_path)
        validate_utc_z(snapshot.observed_at)
    except SourceBoundaryError as error:
        raise ValueError("source snapshot does not satisfy the Archive identity contract") from error
    if snapshot.origin_uri != expected_origin_uri:
        raise ValueError("source snapshot origin URI is not canonical")
    if snapshot.bytes != len(snapshot.content) or snapshot.sha256 != sha256_hex(snapshot.content):
        raise ValueError("source snapshot byte length or SHA-256 is invalid")
    try:
        snapshot.content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("source snapshot Markdown must be valid UTF-8") from error
    if snapshot.sha256 != stored.sha256 or snapshot.bytes != stored.bytes:
        raise ValueError("source snapshot and stored object identity differ")
    if stored.object_id != object_id_for_sha256(stored.sha256):
        raise ValueError("stored object ID does not match its SHA-256 identity")
    if stored.relative_path != ObjectStore.relative_path(stored.sha256).as_posix():
        raise ValueError("stored object path does not match its SHA-256 identity")
    if object_store.read_bytes(stored.object_id) != snapshot.content:
        raise ValueError("stored object bytes do not match the source snapshot")
    now = utc_now()
    input_manifest_hash = stable_sha256(
        "archive_snapshot", "1", snapshot.origin_uri, snapshot.sha256
    )
    idempotency_key = stable_sha256(
        "archive_snapshot/v1", snapshot.origin_uri, snapshot.sha256
    )
    with immediate_transaction(connection):
        connection.execute(
            """
            INSERT INTO object_blob(
                object_id,sha256,bytes,media_type,relative_blob_path,created_at,verification_status
            ) VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(object_id) DO NOTHING
            """,
            (
                stored.object_id,
                stored.sha256,
                stored.bytes,
                "text/markdown; charset=utf-8",
                stored.relative_path,
                now,
                "verified",
            ),
        )
        object_row = connection.execute(
            "SELECT sha256,bytes,relative_blob_path,verification_status FROM object_blob WHERE object_id=?",
            (stored.object_id,),
        ).fetchone()
        if object_row is None or (
            object_row["sha256"],
            object_row["bytes"],
            object_row["relative_blob_path"],
            object_row["verification_status"],
        ) != (stored.sha256, stored.bytes, stored.relative_path, "verified"):
            raise RuntimeError("object registry conflicts with immutable object identity")

        source_row = connection.execute(
            """
            SELECT source_location_id,observed_path,read_only
            FROM source_location WHERE namespace=? AND origin_uri=? AND object_id=?
            """,
            (snapshot.namespace, snapshot.origin_uri, stored.object_id),
        ).fetchone()
        if source_row is None:
            source_location_id = new_public_id("src")
            connection.execute(
                """
                INSERT INTO source_location(
                    source_location_id,namespace,origin_uri,observed_path,object_id,observed_at,read_only
                ) VALUES(?,?,?,?,?,?,1)
                """,
                (
                    source_location_id,
                    snapshot.namespace,
                    snapshot.origin_uri,
                    snapshot.relative_path,
                    stored.object_id,
                    snapshot.observed_at,
                ),
            )
        else:
            if (source_row["observed_path"], source_row["read_only"]) != (
                snapshot.relative_path,
                1,
            ):
                raise RuntimeError("source registry conflicts with immutable origin identity")
            source_location_id = str(source_row["source_location_id"])

        subject_urn = f"qrh:source:{source_location_id}"
        output_manifest_hash = stable_sha256(
            "archive_snapshot_output/v1", stored.object_id, source_location_id
        )
        run_row = connection.execute(
            "SELECT run_id FROM pipeline_run WHERE idempotency_key=?", (idempotency_key,)
        ).fetchone()
        run_created = run_row is None
        if run_created:
            run_id = new_public_id("run")
            step_execution_id = new_public_id("step")
            event_id = new_public_id("evt")
            connection.execute(
                """
                INSERT INTO pipeline_run(
                    run_id,workflow_name,workflow_version,subject_urn,input_manifest_hash,
                    idempotency_key,run_status,release_status,created_at,started_at,finished_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    run_id,
                    "archive_snapshot",
                    "1",
                    subject_urn,
                    input_manifest_hash,
                    idempotency_key,
                    "succeeded",
                    "staging",
                    now,
                    now,
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO step_execution(
                    step_execution_id,run_id,step_key,step_version,dependency_manifest_hash,
                    required_for_release,status,output_manifest_hash,created_at,finished_at
                ) VALUES(?,?,?,?,?,1,'succeeded',?,?,?)
                """,
                (
                    step_execution_id,
                    run_id,
                    "register_source_snapshot",
                    "1",
                    input_manifest_hash,
                    output_manifest_hash,
                    now,
                    now,
                ),
            )
            payload = canonical_json(
                {
                    "object_urn": f"qrh:object:{stored.object_id}",
                    "origin_uri": snapshot.origin_uri,
                    "run_urn": f"qrh:run:{run_id}",
                    "source_location_urn": f"qrh:source:{source_location_id}",
                }
            )
            payload_hash = stable_sha256("outbox-payload/v1", payload)
            connection.execute(
                """
                INSERT INTO outbox_event(
                    event_id,event_type,event_version,aggregate_urn,payload_json,payload_hash,created_at,published_at
                ) VALUES(?,?,?,?,?,?,?,NULL)
                """,
                (
                    event_id,
                    "ArchiveSourceSnapshotRegistered",
                    "1",
                    subject_urn,
                    payload,
                    payload_hash,
                    now,
                ),
            )
        else:
            run_id = str(run_row["run_id"])
            run_state = connection.execute(
                """
                SELECT workflow_name,workflow_version,subject_urn,run_status,release_status,
                       input_manifest_hash,created_at,started_at,finished_at
                FROM pipeline_run WHERE run_id=?
                """,
                (run_id,),
            ).fetchone()
            if run_state is None or (
                run_state["workflow_name"],
                run_state["workflow_version"],
                run_state["subject_urn"],
                run_state["run_status"],
                run_state["release_status"],
                run_state["input_manifest_hash"],
            ) != (
                "archive_snapshot",
                "1",
                subject_urn,
                "succeeded",
                "staging",
                input_manifest_hash,
            ):
                raise RuntimeError("idempotent run exists in an incompatible state")
            if not all(
                isinstance(run_state[field], str) and bool(run_state[field])
                for field in ("created_at", "started_at", "finished_at")
            ):
                raise RuntimeError("idempotent run does not have complete lifecycle timestamps")
            step = connection.execute(
                """
                SELECT step_execution_id,step_version,dependency_manifest_hash,
                       required_for_release,status,output_manifest_hash,created_at,finished_at
                FROM step_execution WHERE run_id=? AND step_key='register_source_snapshot'
                """,
                (run_id,),
            ).fetchone()
            expected_payload = canonical_json(
                {
                    "object_urn": f"qrh:object:{stored.object_id}",
                    "origin_uri": snapshot.origin_uri,
                    "run_urn": f"qrh:run:{run_id}",
                    "source_location_urn": f"qrh:source:{source_location_id}",
                }
            )
            expected_payload_hash = stable_sha256("outbox-payload/v1", expected_payload)
            events = connection.execute(
                """
                SELECT event_id,event_version,payload_json,payload_hash
                FROM outbox_event
                WHERE aggregate_urn=? AND event_type='ArchiveSourceSnapshotRegistered'
                """,
                (subject_urn,),
            ).fetchall()
            if step is None or (
                step["step_version"],
                step["dependency_manifest_hash"],
                step["required_for_release"],
                step["status"],
                step["output_manifest_hash"],
            ) != ("1", input_manifest_hash, 1, "succeeded", output_manifest_hash):
                raise RuntimeError("idempotent run is incomplete")
            if not all(
                isinstance(step[field], str) and bool(step[field])
                for field in ("created_at", "finished_at")
            ):
                raise RuntimeError("idempotent step does not have complete lifecycle timestamps")
            if len(events) != 1 or (
                events[0]["event_version"],
                events[0]["payload_json"],
                events[0]["payload_hash"],
            ) != ("1", expected_payload, expected_payload_hash):
                raise RuntimeError("idempotent run outbox evidence is incomplete or conflicting")
            step_execution_id = str(step["step_execution_id"])
            event_id = str(events[0]["event_id"])
    return RegistrationResult(
        object_id=stored.object_id,
        source_location_id=source_location_id,
        run_id=run_id,
        step_execution_id=step_execution_id,
        event_id=event_id,
        idempotency_key=idempotency_key,
        run_created=run_created,
    )
