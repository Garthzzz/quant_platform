"""Durable comments whose lifetime is independent from a published release."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Any

from quant_hub.config import ConfigurationError
from quant_hub.ids import new_public_id
from quant_hub.platform.db import connect_database, immediate_transaction, utc_now


COMMENT_DATABASE_NAME = "comments.sqlite3"
COMMENT_STORE_SCHEMA_VERSION = 2

_SCHEMA = """
CREATE TABLE IF NOT EXISTS comment_store_schema(
    version INTEGER PRIMARY KEY CHECK(version>=1),
    applied_at TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS actor(
    actor_id TEXT PRIMARY KEY,
    actor_kind TEXT NOT NULL CHECK(actor_kind IN ('zhang_zhengze','song_dingkun','other')),
    display_name TEXT NOT NULL CHECK(length(trim(display_name)) BETWEEN 1 AND 100),
    created_at TEXT NOT NULL,
    UNIQUE(actor_kind,display_name)
) STRICT;
CREATE TABLE IF NOT EXISTS comment(
    comment_id TEXT PRIMARY KEY,
    research_id TEXT NOT NULL,
    actor_id TEXT NOT NULL REFERENCES actor(actor_id) ON DELETE RESTRICT,
    body TEXT NOT NULL CHECK(length(trim(body)) BETWEEN 1 AND 10000),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision>=1),
    deleted_at TEXT
) STRICT;
CREATE INDEX IF NOT EXISTS comment_research_created_idx
ON comment(research_id,created_at,comment_id);
CREATE TRIGGER IF NOT EXISTS comment_revision_update
BEFORE UPDATE ON comment
WHEN NEW.comment_id IS NOT OLD.comment_id
 OR NEW.research_id IS NOT OLD.research_id
 OR NEW.actor_id IS NOT OLD.actor_id
 OR NEW.created_at IS NOT OLD.created_at
 OR NEW.revision<>OLD.revision+1
BEGIN
 SELECT RAISE(ABORT,'comment update must preserve identity and increment revision');
END;
CREATE TRIGGER IF NOT EXISTS comment_no_delete
BEFORE DELETE ON comment BEGIN
 SELECT RAISE(ABORT,'comments use audited soft deletion');
END;
CREATE TRIGGER IF NOT EXISTS comment_deleted_no_rewrite
BEFORE UPDATE ON comment WHEN OLD.deleted_at IS NOT NULL BEGIN
 SELECT RAISE(ABORT,'deleted comments are immutable');
END;
CREATE TABLE IF NOT EXISTS comment_event(
    comment_event_id TEXT PRIMARY KEY,
    comment_id TEXT NOT NULL REFERENCES comment(comment_id) ON DELETE RESTRICT,
    event_type TEXT NOT NULL CHECK(event_type IN ('create','update','delete')),
    old_body_hash TEXT,
    new_body_hash TEXT,
    actor_id TEXT NOT NULL REFERENCES actor(actor_id) ON DELETE RESTRICT,
    revision INTEGER NOT NULL CHECK(revision>=1),
    occurred_at TEXT NOT NULL,
    UNIQUE(comment_id,revision,event_type)
) STRICT;
CREATE TRIGGER IF NOT EXISTS comment_event_no_update
BEFORE UPDATE ON comment_event BEGIN
 SELECT RAISE(ABORT,'comment events are append-only');
END;
CREATE TRIGGER IF NOT EXISTS comment_event_no_delete
BEFORE DELETE ON comment_event BEGIN
 SELECT RAISE(ABORT,'comment events are append-only');
END;
CREATE TABLE IF NOT EXISTS command_receipt(
    receipt_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    command_name TEXT NOT NULL CHECK(command_name IN (
        'comment.create','comment.update','comment.delete'
    )),
    payload_hash TEXT NOT NULL,
    aggregate_urn TEXT NOT NULL,
    actor_id TEXT REFERENCES actor(actor_id) ON DELETE RESTRICT,
    outcome TEXT NOT NULL CHECK(outcome IN ('applied','rejected')),
    result_json TEXT NOT NULL CHECK(json_valid(result_json)),
    result_hash TEXT NOT NULL,
    http_status INTEGER NOT NULL CHECK(http_status BETWEEN 100 AND 599),
    created_at TEXT NOT NULL
) STRICT;
CREATE TRIGGER IF NOT EXISTS command_receipt_no_update
BEFORE UPDATE ON command_receipt BEGIN
 SELECT RAISE(ABORT,'command receipts are immutable');
END;
CREATE TRIGGER IF NOT EXISTS command_receipt_no_delete
BEFORE DELETE ON command_receipt BEGIN
 SELECT RAISE(ABORT,'command receipts are immutable');
END;
CREATE TABLE IF NOT EXISTS outbox_event(
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL CHECK(event_type IN (
        'ArchiveCommentCreated','ArchiveCommentUpdated','ArchiveCommentDeleted'
    )),
    event_version TEXT NOT NULL,
    aggregate_urn TEXT NOT NULL,
    payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
    payload_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    published_at TEXT,
    publish_attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(publish_attempt_count>=0),
    UNIQUE(event_type,aggregate_urn,payload_hash)
) STRICT;
CREATE TRIGGER IF NOT EXISTS outbox_event_no_delete
BEFORE DELETE ON outbox_event BEGIN
 SELECT RAISE(ABORT,'outbox events are append-only');
END;
CREATE TABLE IF NOT EXISTS legacy_import_run(
    import_run_id TEXT PRIMARY KEY,
    source_path TEXT NOT NULL,
    source_size INTEGER NOT NULL,
    source_mtime_ns INTEGER NOT NULL,
    imported_counts_json TEXT NOT NULL CHECK(json_valid(imported_counts_json)),
    imported_at TEXT NOT NULL,
    UNIQUE(source_path,source_size,source_mtime_ns)
) STRICT;
"""

_PROGRESS_SCHEMA = """
CREATE TABLE IF NOT EXISTS progress_topic(
    topic_id TEXT PRIMARY KEY,
    topic_key TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL CHECK(length(trim(title)) BETWEEN 1 AND 300),
    state TEXT NOT NULL CHECK(state IN ('planned','paused')),
    note TEXT CHECK(note IS NULL OR length(trim(note)) BETWEEN 1 AND 2000),
    manual_order INTEGER NOT NULL DEFAULT 100 CHECK(manual_order BETWEEN 0 AND 1000000),
    created_by_actor_id TEXT NOT NULL REFERENCES actor(actor_id) ON DELETE RESTRICT,
    last_modified_by_actor_id TEXT NOT NULL REFERENCES actor(actor_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision>=1),
    retired_at TEXT,
    legacy_source_node_id TEXT UNIQUE
) STRICT;
CREATE INDEX IF NOT EXISTS progress_topic_state_order_idx
ON progress_topic(state,retired_at,manual_order,topic_key);
CREATE TRIGGER IF NOT EXISTS progress_topic_revision_update
BEFORE UPDATE ON progress_topic
WHEN NEW.topic_id IS NOT OLD.topic_id
 OR NEW.topic_key IS NOT OLD.topic_key
 OR NEW.created_by_actor_id IS NOT OLD.created_by_actor_id
 OR NEW.created_at IS NOT OLD.created_at
 OR NEW.legacy_source_node_id IS NOT OLD.legacy_source_node_id
 OR NEW.revision<>OLD.revision+1
BEGIN
 SELECT RAISE(ABORT,'progress topic update must preserve identity and increment revision');
END;
CREATE TRIGGER IF NOT EXISTS progress_topic_no_delete
BEFORE DELETE ON progress_topic BEGIN
 SELECT RAISE(ABORT,'progress topics use audited retirement');
END;
CREATE TRIGGER IF NOT EXISTS progress_topic_retired_no_rewrite
BEFORE UPDATE ON progress_topic WHEN OLD.retired_at IS NOT NULL BEGIN
 SELECT RAISE(ABORT,'retired progress topics are immutable');
END;
CREATE TABLE IF NOT EXISTS progress_topic_event(
    event_id TEXT PRIMARY KEY,
    topic_id TEXT NOT NULL REFERENCES progress_topic(topic_id) ON DELETE RESTRICT,
    event_kind TEXT NOT NULL CHECK(event_kind IN ('create','update','retire')),
    prior_revision INTEGER,
    new_revision INTEGER NOT NULL CHECK(new_revision>=1),
    old_payload_json TEXT CHECK(old_payload_json IS NULL OR json_valid(old_payload_json)),
    new_payload_json TEXT NOT NULL CHECK(json_valid(new_payload_json)),
    actor_id TEXT NOT NULL REFERENCES actor(actor_id) ON DELETE RESTRICT,
    occurred_at TEXT NOT NULL,
    UNIQUE(topic_id,new_revision,event_kind)
) STRICT;
CREATE TRIGGER IF NOT EXISTS progress_topic_event_no_update
BEFORE UPDATE ON progress_topic_event BEGIN
 SELECT RAISE(ABORT,'progress topic events are append-only');
END;
CREATE TRIGGER IF NOT EXISTS progress_topic_event_no_delete
BEFORE DELETE ON progress_topic_event BEGIN
 SELECT RAISE(ABORT,'progress topic events are append-only');
END;
CREATE TABLE IF NOT EXISTS progress_command_receipt(
    receipt_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    command_name TEXT NOT NULL CHECK(command_name IN (
        'topic.create_manual','topic.update_manual','topic.retire_manual'
    )),
    payload_hash TEXT NOT NULL,
    aggregate_urn TEXT NOT NULL,
    actor_id TEXT REFERENCES actor(actor_id) ON DELETE RESTRICT,
    outcome TEXT NOT NULL CHECK(outcome IN ('applied','rejected')),
    result_json TEXT NOT NULL CHECK(json_valid(result_json)),
    result_hash TEXT NOT NULL,
    http_status INTEGER NOT NULL CHECK(http_status BETWEEN 100 AND 599),
    created_at TEXT NOT NULL
) STRICT;
CREATE TRIGGER IF NOT EXISTS progress_command_receipt_no_update
BEFORE UPDATE ON progress_command_receipt BEGIN
 SELECT RAISE(ABORT,'progress command receipts are immutable');
END;
CREATE TRIGGER IF NOT EXISTS progress_command_receipt_no_delete
BEFORE DELETE ON progress_command_receipt BEGIN
 SELECT RAISE(ABORT,'progress command receipts are immutable');
END;
"""

_MISCLASSIFIED_PROGRESS_NODE_IDS = (
    "rnode_e2a54085f3cd423e8521dceb9d75b403",
    "rnode_38506735478543cfa6a6c1368fc1e298",
    "rnode_09504878a121439783286f1ded8a9556",
    "rnode_83f8eb7537d04360850f5d60a372d099",
    "rnode_65168fb490df40af9497beef50f8d02b",
)


def resolve_broadcast_data_root(package_root: Path) -> Path:
    release = package_root.resolve()
    configured = os.environ.get("VIEWER_DATA_ROOT", "").strip()
    candidate = (
        Path(configured).expanduser()
        if configured
        else release.parent / f"{release.name}_data"
    ).resolve()
    try:
        candidate.relative_to(release)
    except ValueError:
        return candidate
    raise ConfigurationError("VIEWER_DATA_ROOT 必须位于发布目录之外。")


def _readonly(path: Path, *, immutable: bool = False) -> sqlite3.Connection:
    immutable_query = "&immutable=1" if immutable else ""
    connection = sqlite3.connect(
        f"file:{path.resolve().as_posix()}?mode=ro{immutable_query}",
        uri=True,
        timeout=10,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None


def _insert_or_verify(
    target: sqlite3.Connection,
    table: str,
    primary_key: str,
    values: dict[str, Any],
) -> bool:
    columns = tuple(values)
    cursor = target.execute(
        f"INSERT OR IGNORE INTO {table}({','.join(columns)}) "
        f"VALUES({','.join('?' for _ in columns)})",
        tuple(values[column] for column in columns),
    )
    if cursor.rowcount == 1:
        return True
    row = target.execute(
        f"SELECT {','.join(columns)} FROM {table} WHERE {primary_key}=?",
        (values[primary_key],),
    ).fetchone()
    if row is None or any(row[column] != values[column] for column in columns):
        raise RuntimeError(f"持久评论库发生身份冲突：{table}.{values[primary_key]}")
    return False


def _progress_snapshot(
    *, title: str, state: str, note: str | None, manual_order: int, retired_at: str | None
) -> dict[str, Any]:
    return {
        "title": title,
        "state": state,
        "note": note,
        "manual_order": manual_order,
        "retired_at": retired_at,
    }


def _insert_imported_progress_topic(
    target: sqlite3.Connection,
    *,
    title: str,
    state: str,
    note: str | None,
    manual_order: int,
    actor_id: str,
    created_at: str,
    updated_at: str,
    legacy_source_node_id: str,
    deduplicate_content: bool = False,
) -> tuple[int, int]:
    if target.execute(
        "SELECT 1 FROM progress_topic WHERE legacy_source_node_id=?",
        (legacy_source_node_id,),
    ).fetchone() is not None:
        return 0, 0
    topic_id = new_public_id("top")
    topic_key = f"manual-{topic_id.removeprefix('top_')}"
    normalized_note = note.strip() if note and note.strip() else None
    if deduplicate_content:
        duplicate = target.execute(
            """
            SELECT 1
            FROM progress_topic
            WHERE retired_at IS NULL
              AND title=?
              AND COALESCE(note,'')=COALESCE(?,'')
            LIMIT 1
            """,
            (title.strip(), normalized_note),
        ).fetchone()
        if duplicate is not None:
            return 0, 0
    target.execute(
        """
        INSERT INTO progress_topic(
            topic_id,topic_key,title,state,note,manual_order,
            created_by_actor_id,last_modified_by_actor_id,created_at,updated_at,
            revision,retired_at,legacy_source_node_id
        ) VALUES(?,?,?,?,?,?,?,?,?,?,1,NULL,?)
        """,
        (
            topic_id,
            topic_key,
            title.strip(),
            state,
            normalized_note,
            manual_order,
            actor_id,
            actor_id,
            created_at,
            updated_at,
            legacy_source_node_id,
        ),
    )
    snapshot = _progress_snapshot(
        title=title.strip(),
        state=state,
        note=normalized_note,
        manual_order=manual_order,
        retired_at=None,
    )
    target.execute(
        """
        INSERT INTO progress_topic_event(
            event_id,topic_id,event_kind,prior_revision,new_revision,
            old_payload_json,new_payload_json,actor_id,occurred_at
        ) VALUES(?,?,'create',NULL,1,NULL,?,?,?)
        """,
        (
            new_public_id("tmut"),
            topic_id,
            json.dumps(snapshot, ensure_ascii=False, sort_keys=True),
            actor_id,
            updated_at,
        ),
    )
    return 1, 1


def _import_legacy(
    target: sqlite3.Connection, source_path: Path
) -> dict[str, int]:
    counts = {
        "actors": 0,
        "comments": 0,
        "events": 0,
        "receipts": 0,
        "outbox": 0,
        "progress_topics": 0,
        "progress_events": 0,
    }
    if not source_path.is_file():
        return counts
    info = source_path.stat()
    source_key = (str(source_path.resolve()), int(info.st_size), int(info.st_mtime_ns))
    if target.execute(
        """
        SELECT 1 FROM legacy_import_run
        WHERE source_path=? AND source_size=? AND source_mtime_ns=?
        """,
        source_key,
    ).fetchone():
        return counts
    source = _readonly(source_path, immutable=True)
    try:
        if not all(
            _table_exists(source, name)
            for name in ("actor", "comment", "comment_event")
        ):
            return counts
        actor_ids: dict[str, str] = {}
        for row in source.execute(
            "SELECT actor_id,actor_kind,display_name,created_at FROM actor"
        ):
            existing = target.execute(
                "SELECT actor_id FROM actor WHERE actor_kind=? AND display_name=?",
                (row["actor_kind"], row["display_name"]),
            ).fetchone()
            actor_id = str(existing["actor_id"]) if existing else str(row["actor_id"])
            if existing is None:
                counts["actors"] += int(
                    _insert_or_verify(
                        target,
                        "actor",
                        "actor_id",
                        {
                            "actor_id": actor_id,
                            "actor_kind": row["actor_kind"],
                            "display_name": row["display_name"],
                            "created_at": row["created_at"],
                        },
                    )
                )
            actor_ids[str(row["actor_id"])] = actor_id
        for row in source.execute("SELECT * FROM comment ORDER BY created_at,comment_id"):
            values = {
                "comment_id": row["comment_id"],
                "research_id": row["research_id"],
                "actor_id": actor_ids[str(row["actor_id"])],
                "body": row["body"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "revision": row["revision"],
                "deleted_at": row["deleted_at"],
            }
            counts["comments"] += int(
                _insert_or_verify(target, "comment", "comment_id", values)
            )
        for row in source.execute("SELECT * FROM comment_event ORDER BY occurred_at"):
            values = {
                "comment_event_id": row["comment_event_id"],
                "comment_id": row["comment_id"],
                "event_type": row["event_type"],
                "old_body_hash": row["old_body_hash"],
                "new_body_hash": row["new_body_hash"],
                "actor_id": actor_ids[str(row["actor_id"])],
                "revision": row["revision"],
                "occurred_at": row["occurred_at"],
            }
            counts["events"] += int(
                _insert_or_verify(target, "comment_event", "comment_event_id", values)
            )
        if _table_exists(source, "command_receipt"):
            for row in source.execute(
                "SELECT * FROM command_receipt WHERE command_name LIKE 'comment.%'"
            ):
                values = {
                    key: row[key]
                    for key in (
                        "receipt_id", "idempotency_key", "command_name",
                        "payload_hash", "aggregate_urn", "outcome", "result_json",
                        "result_hash", "http_status", "created_at",
                    )
                }
                values["actor_id"] = (
                    actor_ids.get(str(row["actor_id"])) if row["actor_id"] else None
                )
                counts["receipts"] += int(
                    _insert_or_verify(target, "command_receipt", "receipt_id", values)
                )
        if _table_exists(source, "outbox_event"):
            for row in source.execute(
                """
                SELECT * FROM outbox_event
                WHERE event_type IN (
                    'ArchiveCommentCreated','ArchiveCommentUpdated','ArchiveCommentDeleted'
                )
                """
            ):
                values = {
                    key: row[key]
                    for key in (
                        "event_id", "event_type", "event_version", "aggregate_urn",
                        "payload_json", "payload_hash", "created_at", "published_at",
                        "publish_attempt_count",
                    )
                }
                counts["outbox"] += int(
                    _insert_or_verify(target, "outbox_event", "event_id", values)
                )
        if all(
            _table_exists(source, name)
            for name in ("topic", "topic_state_event")
        ):
            manual_rows = source.execute(
                """
                SELECT topic.topic_id,topic.title,topic.manual_order,
                       topic.created_by_actor_id,topic.created_at,topic.updated_at,
                       event.state,event.note
                FROM topic
                JOIN topic_state_event AS event ON event.topic_id=topic.topic_id
                WHERE topic.created_by_actor_id IS NOT NULL
                  AND topic.retired_at IS NULL
                  AND NOT EXISTS(
                      SELECT 1 FROM topic_state_event AS later
                      WHERE later.supersedes_event_id=event.topic_state_event_id
                  )
                ORDER BY topic.manual_order,topic.topic_key
                """
            ).fetchall()
            for row in manual_rows:
                source_actor_id = str(row["created_by_actor_id"])
                actor_id = actor_ids.get(source_actor_id)
                if actor_id is None:
                    continue
                topics, events = _insert_imported_progress_topic(
                    target,
                    title=str(row["title"]),
                    state=str(row["state"]),
                    note=str(row["note"]) if row["note"] is not None else None,
                    manual_order=int(row["manual_order"]),
                    actor_id=actor_id,
                    created_at=str(row["created_at"]),
                    updated_at=str(row["updated_at"]),
                    legacy_source_node_id=f"archive:{row['topic_id']}",
                )
                counts["progress_topics"] += topics
                counts["progress_events"] += events
    finally:
        source.close()
    target.execute(
        """
        INSERT INTO legacy_import_run(
            import_run_id,source_path,source_size,source_mtime_ns,
            imported_counts_json,imported_at
        ) VALUES(?,?,?,?,?,?)
        """,
        (
            new_public_id("cimp"),
            *source_key,
            json.dumps(counts, ensure_ascii=False, sort_keys=True),
            utc_now(),
        ),
    )
    return counts


def _import_misclassified_workspace_progress(
    target: sqlite3.Connection, source_path: Path
) -> dict[str, int]:
    counts = {"actors": 0, "progress_topics": 0, "progress_events": 0}
    if not source_path.is_file():
        return counts
    source = _readonly(source_path)
    try:
        if not all(
            _table_exists(source, name)
            for name in ("research_workspace_node", "research_workspace_event", "actor")
        ):
            return counts
        placeholders = ",".join("?" for _ in _MISCLASSIFIED_PROGRESS_NODE_IDS)
        rows = source.execute(
            f"""
            SELECT node.node_id,
                   COALESCE(node.title_override,node.default_title) AS title,
                   COALESCE(node.description_override,node.default_description) AS note,
                   node.lifecycle_status,node.sort_key,node.created_at,node.updated_at,
                   actor.actor_kind,actor.display_name
            FROM research_workspace_node AS node
            LEFT JOIN research_workspace_event AS event
              ON event.event_id=(
                  SELECT candidate.event_id
                  FROM research_workspace_event AS candidate
                  WHERE candidate.node_id=node.node_id
                    AND candidate.actor_id IS NOT NULL
                  ORDER BY candidate.occurred_at DESC,candidate.event_id DESC LIMIT 1
              )
            LEFT JOIN actor ON actor.actor_id=event.actor_id
            WHERE node.node_id IN ({placeholders})
            ORDER BY node.sort_key,node.node_id
            """,
            _MISCLASSIFIED_PROGRESS_NODE_IDS,
        ).fetchall()
        for row in rows:
            actor_kind = str(row["actor_kind"] or "zhang_zhengze")
            display_name = str(row["display_name"] or "张正泽")
            actor = target.execute(
                "SELECT actor_id FROM actor WHERE actor_kind=? AND display_name=?",
                (actor_kind, display_name),
            ).fetchone()
            if actor is None:
                actor_id = new_public_id("act")
                target.execute(
                    "INSERT INTO actor(actor_id,actor_kind,display_name,created_at) VALUES(?,?,?,?)",
                    (actor_id, actor_kind, display_name, str(row["created_at"])),
                )
                counts["actors"] += 1
            else:
                actor_id = str(actor["actor_id"])
            title = re.sub(
                r"^Q\d+\s*[｜|:：]\s*",
                "",
                str(row["title"]),
                count=1,
                flags=re.IGNORECASE,
            ).strip()
            topics, events = _insert_imported_progress_topic(
                target,
                title=title,
                state="paused" if str(row["lifecycle_status"]) == "archived" else "planned",
                note=str(row["note"]) if row["note"] is not None else None,
                manual_order=int(row["sort_key"]),
                actor_id=actor_id,
                created_at=str(row["created_at"]),
                updated_at=str(row["updated_at"]),
                legacy_source_node_id=str(row["node_id"]),
                deduplicate_content=True,
            )
            counts["progress_topics"] += topics
            counts["progress_events"] += events
    finally:
        source.close()
    return counts


def initialize_comment_store(
    database_path: Path,
    *,
    legacy_archive_path: Path | None = None,
    legacy_workspace_path: Path | None = None,
) -> dict[str, int]:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = connect_database(database_path)
    try:
        connection.executescript(_SCHEMA)
        connection.executescript(_PROGRESS_SCHEMA)
        with immediate_transaction(connection):
            versions = [
                int(row[0])
                for row in connection.execute(
                    "SELECT version FROM comment_store_schema ORDER BY version"
                )
            ]
            if not versions:
                connection.execute(
                    "INSERT INTO comment_store_schema(version,applied_at) VALUES(?,?)",
                    (1, utc_now()),
                )
                versions = [1]
            if versions == [1]:
                connection.execute(
                    "INSERT INTO comment_store_schema(version,applied_at) VALUES(?,?)",
                    (COMMENT_STORE_SCHEMA_VERSION, utc_now()),
                )
                versions.append(COMMENT_STORE_SCHEMA_VERSION)
            if versions != list(range(1, COMMENT_STORE_SCHEMA_VERSION + 1)):
                raise RuntimeError(f"不支持的持久评论库 schema：{versions}")
            counts = (
                _import_legacy(connection, legacy_archive_path)
                if legacy_archive_path is not None
                else {
                    "actors": 0,
                    "comments": 0,
                    "events": 0,
                    "receipts": 0,
                    "outbox": 0,
                    "progress_topics": 0,
                    "progress_events": 0,
                }
            )
            if legacy_workspace_path is not None:
                workspace_counts = _import_misclassified_workspace_progress(
                    connection, legacy_workspace_path
                )
                for key, value in workspace_counts.items():
                    counts[key] = counts.get(key, 0) + value
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("持久评论库完整性检查失败")
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise RuntimeError("持久评论库外键检查失败")
        return counts
    finally:
        connection.close()


@contextmanager
def comment_connection(database_path: Path) -> Iterator[sqlite3.Connection]:
    connection = connect_database(database_path)
    try:
        yield connection
    finally:
        connection.close()


def comment_store_state(database_path: Path) -> dict[str, Any]:
    connection = connect_database(database_path)
    try:
        return {
            "schema_version": COMMENT_STORE_SCHEMA_VERSION,
            "comments": int(connection.execute("SELECT count(*) FROM comment").fetchone()[0]),
            "active_comments": int(
                connection.execute(
                    "SELECT count(*) FROM comment WHERE deleted_at IS NULL"
                ).fetchone()[0]
            ),
            "events": int(
                connection.execute("SELECT count(*) FROM comment_event").fetchone()[0]
            ),
            "progress_topics": int(
                connection.execute("SELECT count(*) FROM progress_topic").fetchone()[0]
            ),
            "active_progress_topics": int(
                connection.execute(
                    "SELECT count(*) FROM progress_topic WHERE retired_at IS NULL"
                ).fetchone()[0]
            ),
        }
    finally:
        connection.close()


def backup_comment_store(database_path: Path, backup_root: Path) -> Path | None:
    if not database_path.is_file():
        return None
    backup_root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S_%fZ")
    destination = backup_root / f"comments-{stamp}.sqlite3"
    temporary = destination.with_suffix(".tmp")
    source = _readonly(database_path)
    target = sqlite3.connect(temporary, timeout=10)
    try:
        source.backup(target)
        target.commit()
        if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("评论备份完整性检查失败")
    finally:
        target.close()
        source.close()
    os.replace(temporary, destination)
    return destination


__all__ = [
    "COMMENT_DATABASE_NAME",
    "backup_comment_store",
    "comment_connection",
    "comment_store_state",
    "initialize_comment_store",
    "resolve_broadcast_data_root",
]
