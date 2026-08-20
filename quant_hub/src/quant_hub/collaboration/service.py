from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import sqlite3
import stat
from typing import Any, Literal

from quant_hub.archive.contracts import (
    ActorInput,
    ManualTopicCreateInput,
    ManualTopicUpdateInput,
    TopicInput,
)
from quant_hub.archive.database import archive_connection
from quant_hub.collaboration.comment_store import comment_connection
from quant_hub.config import (
    ConfigurationError,
    Settings,
    ensure_no_reparse_components,
    stat_is_reparse_point,
)
from quant_hub.ids import new_public_id, sha256_hex, stable_sha256
from quant_hub.platform.db import immediate_transaction, utc_now
from quant_hub.platform.reviews import ReviewAuthority, ReviewCertificateError
from quant_hub.platform.workflow import canonical_json
from quant_hub.presentation import ArchivePresentation


class IdempotencyConflict(RuntimeError):
    pass


ARCHIVE_COMPLETION_REVIEW_REQUIREMENTS_HASH = stable_sha256(
    "archive-completion-review-requirements/v1",
    "active-release-bound",
    "frozen-review-artifact",
    "released-summary-required",
    "source-completion-evidence",
)

RESEARCH_UPDATE_HISTORY_EXPORT_NAME = "research_update_history.jsonl"
RESEARCH_UPDATE_HISTORY_SCHEMA_VERSION = "archive-research-update-history/v1"


@dataclass(frozen=True, slots=True)
class CommandOutcome:
    ok: bool
    status: int
    data: dict[str, Any] | None = None
    error_code: str | None = None
    error_message: str | None = None
    replayed: bool = False


def _payload_hash(command_name: str, payload: dict[str, Any]) -> str:
    return stable_sha256(
        "archive-command/v1",
        command_name,
        canonical_json(payload),
    )


def _outcome_json(outcome: CommandOutcome) -> str:
    if outcome.ok:
        value: dict[str, Any] = {"data": outcome.data or {}}
    else:
        value = {
            "error": {
                "code": outcome.error_code,
                "message": outcome.error_message,
            }
        }
    return canonical_json(value)


class ArchiveCollaboration:
    """评论与研究进度的唯一 command handler。

    所有写入、审计事件、outbox、projection 与幂等 receipt 均在同一 Archive
    SQLite 事务内提交；页面层不得直接赋值状态。
    """

    PROJECTION_VERSION = "archive-status/v1"

    def __init__(
        self,
        settings: Settings,
        *,
        comment_database_path: Path | None = None,
    ):
        self.settings = settings
        self.comment_database_path = (
            comment_database_path.resolve() if comment_database_path is not None else None
        )
        self.presentation = ArchivePresentation.default()

    @contextmanager
    def _comment_connection(self) -> Iterator[sqlite3.Connection]:
        if self.comment_database_path is None:
            with archive_connection(self.settings) as connection:
                yield connection
            return
        with comment_connection(self.comment_database_path) as connection:
            yield connection

    @staticmethod
    def _actor_name(actor: ActorInput) -> str:
        if actor.actor_kind == "zhang_zhengze":
            return "张正泽"
        if actor.actor_kind == "song_dingkun":
            return "宋定坤"
        assert actor.display_name is not None
        return actor.display_name.strip()

    def _actor_id(self, connection: sqlite3.Connection, actor: ActorInput) -> str:
        name = self._actor_name(actor)
        row = connection.execute(
            "SELECT actor_id FROM actor WHERE actor_kind=? AND display_name=?",
            (actor.actor_kind, name),
        ).fetchone()
        if row is not None:
            return str(row["actor_id"])
        actor_id = new_public_id("act")
        connection.execute(
            "INSERT INTO actor(actor_id,actor_kind,display_name,created_at) VALUES(?,?,?,?)",
            (actor_id, actor.actor_kind, name, utc_now()),
        )
        return actor_id

    @staticmethod
    def _replay(
        connection: sqlite3.Connection,
        *,
        idempotency_key: str,
        command_name: str,
        payload_hash: str,
    ) -> CommandOutcome | None:
        row = connection.execute(
            """
            SELECT command_name,payload_hash,outcome,result_json,http_status
            FROM command_receipt WHERE idempotency_key=?
            """,
            (idempotency_key,),
        ).fetchone()
        if row is None:
            return None
        if (row["command_name"], row["payload_hash"]) != (command_name, payload_hash):
            raise IdempotencyConflict(
                "idempotency key is already bound to a different command or payload"
            )
        result = json.loads(str(row["result_json"]))
        if row["outcome"] == "applied":
            return CommandOutcome(
                ok=True,
                status=int(row["http_status"]),
                data=dict(result["data"]),
                replayed=True,
            )
        error = result["error"]
        return CommandOutcome(
            ok=False,
            status=int(row["http_status"]),
            error_code=str(error["code"]),
            error_message=str(error["message"]),
            replayed=True,
        )

    @staticmethod
    def _record(
        connection: sqlite3.Connection,
        *,
        idempotency_key: str,
        command_name: str,
        payload_hash: str,
        request_payload: dict[str, Any],
        aggregate_urn: str,
        actor_id: str | None,
        outcome: CommandOutcome,
    ) -> CommandOutcome:
        result = json.loads(_outcome_json(outcome))
        result["request"] = request_payload
        result_json = canonical_json(result)
        connection.execute(
            """
            INSERT INTO command_receipt(
                receipt_id,idempotency_key,command_name,payload_hash,aggregate_urn,
                actor_id,outcome,result_json,result_hash,http_status,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                new_public_id("rcpt"),
                idempotency_key,
                command_name,
                payload_hash,
                aggregate_urn,
                actor_id,
                "applied" if outcome.ok else "rejected",
                result_json,
                stable_sha256("archive-command-result/v1", result_json),
                outcome.status,
                utc_now(),
            ),
        )
        return outcome

    @staticmethod
    def _emit(
        connection: sqlite3.Connection,
        event_type: str,
        aggregate_urn: str,
        payload: dict[str, Any],
        *,
        created_at: str | None = None,
    ) -> None:
        payload_json = canonical_json(payload)
        connection.execute(
            """
            INSERT INTO outbox_event(
                event_id,event_type,event_version,aggregate_urn,payload_json,payload_hash,
                created_at,published_at,publish_attempt_count
            ) VALUES(?,?,?,?,?,?,?,NULL,0)
            """,
            (
                new_public_id("evt"),
                event_type,
                "1",
                aggregate_urn,
                payload_json,
                stable_sha256("archive-outbox/v1", payload_json),
                created_at or utc_now(),
            ),
        )

    @staticmethod
    def _research_update_id(research_id: str, content_revision_id: str) -> str:
        """Return the D-05 identity for one published content revision."""

        return stable_sha256(research_id, content_revision_id, "published")

    @classmethod
    def record_research_update_after_activation(
        cls,
        connection: sqlite3.Connection,
        *,
        research_id: str,
        research_release_id: str,
        activation_id: str,
        release_revision: int,
    ) -> tuple[str, bool]:
        """Append the automatic update fact inside the caller's release transaction.

        Reactivating an already-published content revision intentionally resolves to
        its existing update fact.  The activation remains fully audited by the
        release tables, while the researcher-facing update stream stays exactly once
        per ``(research, content revision, published)`` identity.
        """

        # D-05 is an exactly-once *content* stream.  A later rollback may activate
        # the same document manifest again, but its update must stay bound to the
        # first occurrence in the supersedes chain.  Derive that occurrence from
        # the linked list, never from timestamps (which can tie or move backwards).
        reverse_chain: list[sqlite3.Row] = []
        seen_activation_ids: set[str] = set()
        cursor: str | None = activation_id
        while cursor is not None:
            if cursor in seen_activation_ids:
                raise RuntimeError("research update activation chain cycles")
            seen_activation_ids.add(cursor)
            row = connection.execute(
                """
                SELECT activation.activation_id,activation.research_id,
                       activation.research_release_id,
                       activation.supersedes_activation_id,
                       activation.activated_at,
                       release.document_manifest_hash,
                       research.display_title
                FROM research_release_activation AS activation
                JOIN research_release AS release
                  ON release.research_id=activation.research_id
                 AND release.research_release_id=activation.research_release_id
                JOIN research ON research.research_id=activation.research_id
                WHERE activation.activation_id=? AND activation.research_id=?
                """,
                (cursor, research_id),
            ).fetchone()
            if row is None:
                raise RuntimeError("research update activation material is incomplete")
            reverse_chain.append(row)
            predecessor = row["supersedes_activation_id"]
            cursor = None if predecessor is None else str(predecessor)
        chain = list(reversed(reverse_chain))
        current = chain[-1]
        if (
            str(current["activation_id"]) != activation_id
            or str(current["research_release_id"]) != research_release_id
            or release_revision != len(chain)
        ):
            raise RuntimeError("research update activation revision is not chain-derived")

        content_revision_id = str(current["document_manifest_hash"])
        first_position, first_occurrence = next(
            (position, row)
            for position, row in enumerate(chain, start=1)
            if str(row["document_manifest_hash"]) == content_revision_id
        )
        update_id = cls._research_update_id(research_id, content_revision_id)
        activated_at = str(first_occurrence["activated_at"])
        title_snapshot = str(first_occurrence["display_title"])
        expected = {
            "update_id": update_id,
            "research_id": research_id,
            "activation_id": str(first_occurrence["activation_id"]),
            "research_release_id": str(first_occurrence["research_release_id"]),
            "content_revision_id": content_revision_id,
            "event_kind": "published",
            "release_revision": first_position,
            "title_snapshot": title_snapshot,
            "activated_at": activated_at,
            "created_at": activated_at,
        }
        existing = connection.execute(
            "SELECT * FROM research_update WHERE update_id=?",
            (update_id,),
        ).fetchone()
        if existing is not None:
            actual = {
                field: int(existing[field]) if field == "release_revision" else str(existing[field])
                for field in expected
            }
            if actual != expected:
                raise RuntimeError(
                    "deterministic research update differs from its first activation occurrence"
                )
            return update_id, False

        connection.execute(
            """
            INSERT INTO research_update(
                update_id,research_id,activation_id,research_release_id,
                content_revision_id,event_kind,release_revision,title_snapshot,
                activated_at,created_at
            ) VALUES(?,?,?,?,?,'published',?,?,?,?)
            """,
            (
                update_id,
                research_id,
                expected["activation_id"],
                expected["research_release_id"],
                content_revision_id,
                first_position,
                title_snapshot,
                activated_at,
                activated_at,
            ),
        )
        cls._emit(
            connection,
            "ArchiveResearchUpdateRecorded",
            f"qrh:research-update:{update_id}",
            {
                "update_id": update_id,
                "research_id": research_id,
                "research_release_id": expected["research_release_id"],
                "activation_id": expected["activation_id"],
                "content_revision_id": content_revision_id,
                "event_kind": "published",
                "release_revision": first_position,
                "title_snapshot": title_snapshot,
                "activated_at": activated_at,
            },
            created_at=activated_at,
        )
        return update_id, True

    def create_comment(
        self,
        research_id: str,
        actor: ActorInput,
        body: str,
        *,
        idempotency_key: str,
    ) -> CommandOutcome:
        body = body.strip()
        payload = {
            "research_id": research_id,
            "actor": actor.model_dump(mode="json"),
            "body": body,
        }
        command = "comment.create"
        digest = _payload_hash(command, payload)
        with self._comment_connection() as connection, immediate_transaction(connection):
            replay = self._replay(
                connection,
                idempotency_key=idempotency_key,
                command_name=command,
                payload_hash=digest,
            )
            if replay is not None:
                return replay
            actor_id = self._actor_id(connection, actor)
            if not body or len(body) > 8_000:
                return self._record(
                    connection,
                    idempotency_key=idempotency_key,
                    command_name=command,
                    payload_hash=digest,
                    request_payload=payload,
                    aggregate_urn=f"qrh:research:{research_id}",
                    actor_id=actor_id,
                    outcome=CommandOutcome(False, 422, error_code="invalid_comment", error_message="评论内容不能为空且不得超过 8000 字符。"),
                )
            with archive_connection(self.settings) as archive:
                research_exists = archive.execute(
                    "SELECT 1 FROM research WHERE research_id=?", (research_id,)
                ).fetchone() is not None
            if not research_exists:
                return self._record(
                    connection,
                    idempotency_key=idempotency_key,
                    command_name=command,
                    payload_hash=digest,
                    request_payload=payload,
                    aggregate_urn=f"qrh:research:{research_id}",
                    actor_id=actor_id,
                    outcome=CommandOutcome(False, 404, error_code="research_not_found", error_message="研究不存在。"),
                )
            now = utc_now()
            comment_id = new_public_id("cmt")
            body_hash = sha256_hex(body.encode("utf-8"))
            connection.execute(
                """
                INSERT INTO comment(
                    comment_id,research_id,actor_id,body,created_at,updated_at,revision,deleted_at
                ) VALUES(?,?,?,?,?,?,1,NULL)
                """,
                (comment_id, research_id, actor_id, body, now, now),
            )
            connection.execute(
                """
                INSERT INTO comment_event(
                    comment_event_id,comment_id,event_type,old_body_hash,new_body_hash,
                    actor_id,revision,occurred_at
                ) VALUES(?,?,'create',NULL,?,?,1,?)
                """,
                (new_public_id("cevt"), comment_id, body_hash, actor_id, now),
            )
            data = {
                "comment_id": comment_id,
                "research_id": research_id,
                "actor": {"actor_kind": actor.actor_kind, "display_name": self._actor_name(actor)},
                "content": body,
                "created_at": now,
                "updated_at": now,
                "revision": 1,
                "request": payload,
            }
            self._emit(
                connection,
                "ArchiveCommentCreated",
                f"qrh:comment:{comment_id}",
                data,
                created_at=now,
            )
            return self._record(
                connection,
                idempotency_key=idempotency_key,
                command_name=command,
                payload_hash=digest,
                request_payload=payload,
                aggregate_urn=f"qrh:comment:{comment_id}",
                actor_id=actor_id,
                outcome=CommandOutcome(True, 201, data=data),
            )

    def update_comment(
        self,
        comment_id: str,
        actor: ActorInput,
        body: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> CommandOutcome:
        return self._change_comment(
            comment_id,
            actor,
            body.strip(),
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            delete=False,
        )

    def delete_comment(
        self,
        comment_id: str,
        actor: ActorInput,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> CommandOutcome:
        return self._change_comment(
            comment_id,
            actor,
            None,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            delete=True,
        )

    def _change_comment(
        self,
        comment_id: str,
        actor: ActorInput,
        body: str | None,
        *,
        expected_revision: int,
        idempotency_key: str,
        delete: bool,
    ) -> CommandOutcome:
        command = "comment.delete" if delete else "comment.update"
        payload = {
            "comment_id": comment_id,
            "actor": actor.model_dump(mode="json"),
            "content": body,
            "expected_revision": expected_revision,
        }
        digest = _payload_hash(command, payload)
        with self._comment_connection() as connection, immediate_transaction(connection):
            replay = self._replay(connection, idempotency_key=idempotency_key, command_name=command, payload_hash=digest)
            if replay is not None:
                return replay
            actor_id = self._actor_id(connection, actor)
            row = connection.execute(
                """
                SELECT c.*,a.actor_kind,a.display_name
                FROM comment AS c JOIN actor AS a ON a.actor_id=c.actor_id
                WHERE c.comment_id=?
                """,
                (comment_id,),
            ).fetchone()
            if row is None or row["deleted_at"] is not None:
                return self._record(
                    connection,
                    idempotency_key=idempotency_key,
                    command_name=command,
                    payload_hash=digest,
                    request_payload=payload,
                    aggregate_urn=f"qrh:comment:{comment_id}",
                    actor_id=actor_id,
                    outcome=CommandOutcome(False, 404, error_code="comment_not_found", error_message="评论不存在或已删除。"),
                )
            if int(row["revision"]) != expected_revision:
                return self._record(
                    connection,
                    idempotency_key=idempotency_key,
                    command_name=command,
                    payload_hash=digest,
                    request_payload=payload,
                    aggregate_urn=f"qrh:comment:{comment_id}",
                    actor_id=actor_id,
                    outcome=CommandOutcome(False, 409, error_code="revision_conflict", error_message="评论已被其他写入更新。"),
                )
            if not delete and (body is None or not body or len(body) > 8_000):
                return self._record(
                    connection,
                    idempotency_key=idempotency_key,
                    command_name=command,
                    payload_hash=digest,
                    request_payload=payload,
                    aggregate_urn=f"qrh:comment:{comment_id}",
                    actor_id=actor_id,
                    outcome=CommandOutcome(False, 422, error_code="invalid_comment", error_message="评论内容不能为空且不得超过 8000 字符。"),
                )
            now = utc_now()
            next_revision = expected_revision + 1
            old_hash = sha256_hex(str(row["body"]).encode("utf-8"))
            if delete:
                connection.execute(
                    "UPDATE comment SET updated_at=?,revision=?,deleted_at=? WHERE comment_id=?",
                    (now, next_revision, now, comment_id),
                )
                new_hash = None
                event_type = "delete"
            else:
                assert body is not None
                connection.execute(
                    "UPDATE comment SET body=?,updated_at=?,revision=? WHERE comment_id=?",
                    (body, now, next_revision, comment_id),
                )
                new_hash = sha256_hex(body.encode("utf-8"))
                event_type = "update"
            connection.execute(
                """
                INSERT INTO comment_event(
                    comment_event_id,comment_id,event_type,old_body_hash,new_body_hash,
                    actor_id,revision,occurred_at
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    new_public_id("cevt"), comment_id, event_type, old_hash, new_hash,
                    actor_id, next_revision, now,
                ),
            )
            data = {
                "comment_id": comment_id,
                "revision": next_revision,
                "deleted": delete,
                "updated_at": now,
                "deleted_at": now if delete else None,
                "request": payload,
            }
            if not delete:
                data["content"] = body
            self._emit(
                connection,
                "ArchiveCommentDeleted" if delete else "ArchiveCommentUpdated",
                f"qrh:comment:{comment_id}",
                data,
                created_at=now,
            )
            return self._record(
                connection,
                idempotency_key=idempotency_key,
                command_name=command,
                payload_hash=digest,
                request_payload=payload,
                aggregate_urn=f"qrh:comment:{comment_id}",
                actor_id=actor_id,
                outcome=CommandOutcome(True, 200, data=data),
            )

    def list_comments(self, research_id: str) -> list[dict[str, Any]]:
        with self._comment_connection() as connection:
            rows = connection.execute(
                """
                SELECT c.comment_id,c.research_id,c.body,c.created_at,c.updated_at,c.revision,
                       a.actor_kind,a.display_name
                FROM comment AS c JOIN actor AS a ON a.actor_id=c.actor_id
                WHERE c.research_id=? AND c.deleted_at IS NULL
                ORDER BY c.created_at,c.comment_id
                """,
                (research_id,),
            ).fetchall()
        return [
            {
                "comment_id": str(row["comment_id"]),
                "research_id": str(row["research_id"]),
                "actor": {"actor_kind": str(row["actor_kind"]), "display_name": str(row["display_name"])},
                "content": str(row["body"]),
                "created_at": str(row["created_at"]),
                "updated_at": str(row["updated_at"]),
                "revision": int(row["revision"]),
            }
            for row in rows
        ]

    def backfill_research_updates(self, *, export: bool = True) -> int:
        """Deterministically project pre-0005 activation chains into updates."""

        created = 0
        with archive_connection(self.settings) as connection, immediate_transaction(connection):
            rows = connection.execute(
                """
                SELECT activation.activation_id,activation.research_id,
                       activation.research_release_id,
                       activation.supersedes_activation_id
                FROM research_release_activation AS activation
                JOIN active_research_release AS active
                  ON active.research_id=activation.research_id
                ORDER BY activation.research_id,activation.activation_id
                """
            ).fetchall()
            active_rows = {
                str(row["research_id"]): row
                for row in connection.execute(
                    "SELECT research_id,activation_id,revision FROM active_research_release"
                ).fetchall()
            }
            grouped: dict[str, list[sqlite3.Row]] = {}
            for row in rows:
                grouped.setdefault(str(row["research_id"]), []).append(row)
            for research_id, activation_rows in grouped.items():
                by_id = {str(row["activation_id"]): row for row in activation_rows}
                roots = [
                    row
                    for row in activation_rows
                    if row["supersedes_activation_id"] is None
                ]
                if len(roots) != 1:
                    raise RuntimeError("research activation chain requires one root")
                successor: dict[str, sqlite3.Row] = {}
                for row in activation_rows:
                    predecessor = row["supersedes_activation_id"]
                    if predecessor is None:
                        continue
                    key = str(predecessor)
                    if key in successor:
                        raise RuntimeError("research activation chain branches")
                    successor[key] = row
                chain: list[sqlite3.Row] = []
                current = roots[0]
                while True:
                    activation_id = str(current["activation_id"])
                    if activation_id in {str(item["activation_id"]) for item in chain}:
                        raise RuntimeError("research activation chain cycles")
                    chain.append(current)
                    next_row = successor.get(activation_id)
                    if next_row is None:
                        break
                    current = next_row
                if len(chain) != len(by_id):
                    raise RuntimeError("research activation chain is disconnected")
                active = active_rows.get(research_id)
                if active is None or (
                    str(active["activation_id"]) != str(chain[-1]["activation_id"])
                    or int(active["revision"]) != len(chain)
                ):
                    raise RuntimeError("active research release does not close its activation chain")
                for revision, row in enumerate(chain, start=1):
                    _, inserted = self.record_research_update_after_activation(
                        connection,
                        research_id=research_id,
                        research_release_id=str(row["research_release_id"]),
                        activation_id=str(row["activation_id"]),
                        release_revision=revision,
                    )
                    created += int(inserted)
        if export:
            self.export_research_update_history()
        return created

    def _research_update_rows(
        self,
        connection: sqlite3.Connection,
        *,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        limit_sql = "" if limit is None else " LIMIT ?"
        parameters: tuple[object, ...] = () if limit is None else (limit,)
        rows = connection.execute(
            """
            WITH latest_annotation AS (
                SELECT annotation.*,
                       row_number() OVER (
                           PARTITION BY annotation.update_id
                           ORDER BY annotation.revision DESC,annotation.annotation_event_id DESC
                       ) AS position
                FROM research_update_annotation_event AS annotation
            )
            SELECT update_fact.*,research.canonical_slug,
                   identity.release_key,
                   annotation.annotation_event_id,
                   annotation.note,annotation.revision AS annotation_revision,
                   annotation.occurred_at,
                   actor.actor_kind,actor.display_name AS actor_display_name
            FROM research_update AS update_fact
            JOIN research USING(research_id)
            LEFT JOIN research_release_candidate_identity AS identity
              ON identity.research_release_id=update_fact.research_release_id
             AND identity.research_id=update_fact.research_id
            LEFT JOIN latest_annotation AS annotation
              ON annotation.update_id=update_fact.update_id
             AND annotation.position=1
            LEFT JOIN actor ON actor.actor_id=annotation.actor_id
            ORDER BY update_fact.activated_at DESC,update_fact.update_id DESC
            """ + limit_sql,
            parameters,
        ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            title_snapshot = str(row["title_snapshot"])
            title = self.presentation.research_title(
                str(row["canonical_slug"]), title_snapshot
            )
            annotation = None
            annotation_revision = 0
            if row["annotation_event_id"] is not None:
                annotation_revision = int(row["annotation_revision"])
                annotation = {
                    "annotation_event_id": str(row["annotation_event_id"]),
                    "actor": {
                        "actor_kind": str(row["actor_kind"]),
                        "display_name": str(row["actor_display_name"]),
                    },
                    "note": None if row["note"] is None else str(row["note"]),
                    "revision": annotation_revision,
                    "occurred_at": str(row["occurred_at"]),
                }
            items.append(
                {
                    "update_id": str(row["update_id"]),
                    "research_id": str(row["research_id"]),
                    "research_release_id": str(row["research_release_id"]),
                    "content_revision_id": str(row["content_revision_id"]),
                    "event_kind": str(row["event_kind"]),
                    "release_key": (
                        None if row["release_key"] is None else str(row["release_key"])
                    ),
                    "release_revision": int(row["release_revision"]),
                    "title": title,
                    "activated_at": str(row["activated_at"]),
                    "page_url": f'/research/{row["research_id"]}',
                    "annotation": annotation,
                    "annotation_revision": annotation_revision,
                }
            )
        return items

    def list_research_updates(self, *, limit: int | None = None) -> list[dict[str, Any]]:
        if limit is not None and not 1 <= limit <= 1_000:
            raise ValueError("research update limit must be between 1 and 1000")
        with archive_connection(self.settings) as connection:
            return self._research_update_rows(connection, limit=limit)

    def annotate_research_update(
        self,
        update_id: str,
        actor: ActorInput,
        note: str | None,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> CommandOutcome:
        normalized_note = None if note is None else note.strip() or None
        payload = {
            "update_id": update_id,
            "actor": actor.model_dump(mode="json"),
            "note": normalized_note,
            "expected_revision": expected_revision,
        }
        command = "research_update.annotate"
        digest = _payload_hash(command, payload)
        try:
            with archive_connection(self.settings) as connection, immediate_transaction(connection):
                replay = self._replay(
                    connection,
                    idempotency_key=idempotency_key,
                    command_name=command,
                    payload_hash=digest,
                )
                if replay is not None:
                    return replay
                update = connection.execute(
                    "SELECT update_id FROM research_update WHERE update_id=?",
                    (update_id,),
                ).fetchone()
                actor_id = self._actor_id(connection, actor)
                if update is None:
                    return self._record(
                        connection,
                        idempotency_key=idempotency_key,
                        command_name=command,
                        payload_hash=digest,
                        request_payload=payload,
                        aggregate_urn=f"qrh:research-update:{update_id}",
                        actor_id=actor_id,
                        outcome=CommandOutcome(
                            False,
                            404,
                            error_code="research_update_not_found",
                            error_message="研究更新记录不存在。",
                        ),
                    )
                if expected_revision < 0 or (
                    normalized_note is not None and len(normalized_note) > 500
                ):
                    return self._record(
                        connection,
                        idempotency_key=idempotency_key,
                        command_name=command,
                        payload_hash=digest,
                        request_payload=payload,
                        aggregate_urn=f"qrh:research-update:{update_id}",
                        actor_id=actor_id,
                        outcome=CommandOutcome(
                            False,
                            422,
                            error_code="invalid_research_update_annotation",
                            error_message="更新说明可留空，填写时不得超过 500 个字符。",
                        ),
                    )
                latest = connection.execute(
                    """
                    SELECT coalesce(max(revision),0)
                    FROM research_update_annotation_event WHERE update_id=?
                    """,
                    (update_id,),
                ).fetchone()[0]
                if int(latest) != expected_revision:
                    return self._record(
                        connection,
                        idempotency_key=idempotency_key,
                        command_name=command,
                        payload_hash=digest,
                        request_payload=payload,
                        aggregate_urn=f"qrh:research-update:{update_id}",
                        actor_id=actor_id,
                        outcome=CommandOutcome(
                            False,
                            409,
                            error_code="revision_conflict",
                            error_message="更新说明已被其他研究员修订。",
                        ),
                    )
                revision = expected_revision + 1
                now = utc_now()
                annotation_event_id = new_public_id("ruevt")
                connection.execute(
                    """
                    INSERT INTO research_update_annotation_event(
                        annotation_event_id,update_id,actor_id,idempotency_key,
                        note,revision,occurred_at
                    ) VALUES(?,?,?,?,?,?,?)
                    """,
                    (
                        annotation_event_id,
                        update_id,
                        actor_id,
                        idempotency_key,
                        normalized_note,
                        revision,
                        now,
                    ),
                )
                data = {
                    "update_id": update_id,
                    "annotation_event_id": annotation_event_id,
                    "actor": {
                        "actor_kind": actor.actor_kind,
                        "display_name": self._actor_name(actor),
                    },
                    "note": normalized_note,
                    "revision": revision,
                    "occurred_at": now,
                }
                self._emit(
                    connection,
                    "ArchiveResearchUpdateAnnotated",
                    f"qrh:research-update:{update_id}",
                    data,
                    created_at=now,
                )
                return self._record(
                    connection,
                    idempotency_key=idempotency_key,
                    command_name=command,
                    payload_hash=digest,
                    request_payload=payload,
                    aggregate_urn=f"qrh:research-update:{update_id}",
                    actor_id=actor_id,
                    outcome=CommandOutcome(True, 201, data=data),
                )
        finally:
            # Export is an outbox side effect after the command transaction.  A
            # file-system failure is recorded as a pending retry and never
            # invalidates the committed annotation or its idempotency receipt.
            self.export_research_update_history()

    @property
    def research_update_history_path(self) -> Path:
        return self.settings.var_root / "exports" / RESEARCH_UPDATE_HISTORY_EXPORT_NAME

    @staticmethod
    def _export_records(connection: sqlite3.Connection) -> list[dict[str, Any]]:
        updates = connection.execute(
            """
            SELECT update_fact.*,research.canonical_slug,identity.release_key
            FROM research_update AS update_fact
            JOIN research USING(research_id)
            LEFT JOIN research_release_candidate_identity AS identity
              ON identity.research_release_id=update_fact.research_release_id
             AND identity.research_id=update_fact.research_id
            ORDER BY update_fact.activated_at DESC,update_fact.update_id DESC
            """
        ).fetchall()
        annotation_rows = connection.execute(
            """
            SELECT annotation.*,actor.actor_kind,actor.display_name
            FROM research_update_annotation_event AS annotation
            JOIN actor USING(actor_id)
            ORDER BY annotation.update_id,annotation.revision,annotation.annotation_event_id
            """
        ).fetchall()
        annotations: dict[str, list[dict[str, Any]]] = {}
        for row in annotation_rows:
            annotations.setdefault(str(row["update_id"]), []).append(
                {
                    "annotation_event_id": str(row["annotation_event_id"]),
                    "actor": {
                        "actor_kind": str(row["actor_kind"]),
                        "display_name": str(row["display_name"]),
                    },
                    "idempotency_key": str(row["idempotency_key"]),
                    "note": None if row["note"] is None else str(row["note"]),
                    "revision": int(row["revision"]),
                    "occurred_at": str(row["occurred_at"]),
                }
            )
        return [
            {
                "schema_version": RESEARCH_UPDATE_HISTORY_SCHEMA_VERSION,
                "update_id": str(row["update_id"]),
                "research_id": str(row["research_id"]),
                "canonical_slug": str(row["canonical_slug"]),
                "activation_id": str(row["activation_id"]),
                "research_release_id": str(row["research_release_id"]),
                "release_key": None if row["release_key"] is None else str(row["release_key"]),
                "content_revision_id": str(row["content_revision_id"]),
                "event_kind": str(row["event_kind"]),
                "release_revision": int(row["release_revision"]),
                "title_snapshot": str(row["title_snapshot"]),
                "activated_at": str(row["activated_at"]),
                "created_at": str(row["created_at"]),
                "annotation_events": annotations.get(str(row["update_id"]), []),
            }
            for row in updates
        ]

    def _history_file_matches(self, expected_sha256: str) -> bool:
        path = self.research_update_history_path
        try:
            info = path.lstat()
        except FileNotFoundError:
            return False
        if (
            stat_is_reparse_point(info)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
        ):
            return False
        return sha256_hex(path.read_bytes()) == expected_sha256

    def _atomic_write_research_update_history(self, payload: bytes) -> None:
        target = self.research_update_history_path
        parent = target.parent
        ensure_no_reparse_components(parent)
        parent.mkdir(parents=True, exist_ok=True)
        ensure_no_reparse_components(parent)
        ensure_no_reparse_components(target)
        temporary = parent / f".{target.name}.{new_public_id('tmp')}.tmp"
        try:
            with temporary.open("xb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
            info = target.lstat()
            if (
                stat_is_reparse_point(info)
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
            ):
                raise ConfigurationError(
                    "research update export is not a regular single-link file"
                )
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def export_research_update_history(self) -> dict[str, Any]:
        """Drain update outbox rows into one atomic, DB-rebuildable JSONL export."""

        event_types = (
            "ArchiveResearchUpdateRecorded",
            "ArchiveResearchUpdateAnnotated",
        )
        with archive_connection(self.settings) as connection, immediate_transaction(connection):
            pending = connection.execute(
                """
                SELECT event_id FROM outbox_event
                WHERE published_at IS NULL AND event_type IN (?,?)
                ORDER BY created_at,event_id
                """,
                event_types,
            ).fetchall()
            records = self._export_records(connection)
            canonical_records = canonical_json(records)
            database_watermark = stable_sha256(
                "archive-research-update-watermark/v1", canonical_records
            )
            payload = b"".join(
                (canonical_json(record) + "\n").encode("utf-8") for record in records
            )
            history_sha256 = sha256_hex(payload)
            checkpoint = connection.execute(
                """
                SELECT database_watermark,history_sha256,row_count
                FROM research_update_export_checkpoint
                WHERE export_name=?
                """,
                (RESEARCH_UPDATE_HISTORY_EXPORT_NAME,),
            ).fetchone()
            if (
                not pending
                and checkpoint is not None
                and str(checkpoint["database_watermark"]) == database_watermark
                and str(checkpoint["history_sha256"]) == history_sha256
                and int(checkpoint["row_count"]) == len(records)
                and self._history_file_matches(history_sha256)
            ):
                return {
                    "ok": True,
                    "changed": False,
                    "row_count": len(records),
                    "database_watermark": database_watermark,
                    "history_sha256": history_sha256,
                    "pending": 0,
                }
            try:
                self._atomic_write_research_update_history(payload)
            except (OSError, ConfigurationError) as error:
                for row in pending:
                    connection.execute(
                        """
                        UPDATE outbox_event
                        SET publish_attempt_count=publish_attempt_count+1
                        WHERE event_id=? AND published_at IS NULL
                        """,
                        (str(row["event_id"]),),
                    )
                return {
                    "ok": False,
                    "changed": False,
                    "row_count": len(records),
                    "database_watermark": database_watermark,
                    "history_sha256": history_sha256,
                    "pending": len(pending),
                    "error": str(error),
                }
            now = utc_now()
            for row in pending:
                connection.execute(
                    """
                    UPDATE outbox_event
                    SET publish_attempt_count=publish_attempt_count+1,published_at=?
                    WHERE event_id=? AND published_at IS NULL
                    """,
                    (now, str(row["event_id"])),
                )
            connection.execute(
                """
                INSERT INTO research_update_export_checkpoint(
                    export_name,database_watermark,history_sha256,row_count,exported_at
                ) VALUES(?,?,?,?,?)
                ON CONFLICT(export_name) DO UPDATE SET
                    database_watermark=excluded.database_watermark,
                    history_sha256=excluded.history_sha256,
                    row_count=excluded.row_count,
                    exported_at=excluded.exported_at
                """,
                (
                    RESEARCH_UPDATE_HISTORY_EXPORT_NAME,
                    database_watermark,
                    history_sha256,
                    len(records),
                    now,
                ),
            )
            return {
                "ok": True,
                "changed": True,
                "row_count": len(records),
                "database_watermark": database_watermark,
                "history_sha256": history_sha256,
                "pending": 0,
            }

    @staticmethod
    def _manual_topic_key(topic_id: str) -> str:
        return f"manual-{topic_id.removeprefix('top_')}"

    @staticmethod
    def _topic_parent_error(
        connection: sqlite3.Connection,
        *,
        topic_id: str,
        parent_topic_id: str | None,
    ) -> str | None:
        if parent_topic_id is None:
            return None
        if parent_topic_id == topic_id:
            return "研究议题不能以自身作为上级。"
        parent = connection.execute(
            "SELECT parent_topic_id,retired_at FROM topic WHERE topic_id=?",
            (parent_topic_id,),
        ).fetchone()
        if parent is None or parent["retired_at"] is not None:
            return "上级研究议题不存在或已经退休。"
        if parent["parent_topic_id"] is not None:
            return "研究议题层级仅支持根议题和一级子议题。"
        if connection.execute(
            "SELECT 1 FROM topic WHERE parent_topic_id=? LIMIT 1", (topic_id,)
        ).fetchone() is not None:
            return "已有子议题的根议题不能再移动到其他议题之下。"
        return None

    @staticmethod
    def _topic_management_row(
        connection: sqlite3.Connection,
        topic_id: str,
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT topic.topic_id,topic.topic_key,topic.title,topic.manual_order,
                   topic.parent_topic_id,parent.title AS parent_title,
                   topic.created_at,topic.updated_at,topic.retired_at,topic.revision,
                   topic.created_by_actor_id,
                   creator.actor_kind AS creator_actor_kind,
                   creator.display_name AS creator_display_name,
                   projection.effective_state,projection.summary,projection.research_id,
                   projection.page_url,projection.quick_links_json,projection.source_kind,
                   projection.updated_at AS projection_updated_at,
                   state_event.topic_state_event_id,state_event.state AS manual_state,
                   state_event.note AS state_note,state_event.occurred_at AS state_occurred_at,
                   state_actor.actor_kind AS state_actor_kind,
                   state_actor.display_name AS state_actor_display_name,
                   mutation.topic_mutation_event_id,mutation.event_kind AS last_event_kind,
                   mutation.occurred_at AS last_mutation_at,
                   mutation_actor.actor_kind AS mutation_actor_kind,
                   mutation_actor.display_name AS mutation_actor_display_name,
                   (SELECT count(*) FROM topic AS child
                    WHERE child.parent_topic_id=topic.topic_id
                      AND child.retired_at IS NULL) AS active_child_count,
                   (SELECT count(*) FROM topic_research_link AS link
                    WHERE link.topic_id=topic.topic_id
                      AND link.status='active') AS active_research_link_count
            FROM topic
            LEFT JOIN topic AS parent ON parent.topic_id=topic.parent_topic_id
            LEFT JOIN actor AS creator ON creator.actor_id=topic.created_by_actor_id
            JOIN topic_projection AS projection ON projection.topic_id=topic.topic_id
            LEFT JOIN topic_state_event AS state_event
              ON state_event.topic_id=topic.topic_id
             AND NOT EXISTS(
                 SELECT 1 FROM topic_state_event AS later
                 WHERE later.supersedes_event_id=state_event.topic_state_event_id
             )
            LEFT JOIN actor AS state_actor ON state_actor.actor_id=state_event.actor_id
            LEFT JOIN topic_mutation_event AS mutation
              ON mutation.topic_id=topic.topic_id
             AND mutation.new_revision=topic.revision
            LEFT JOIN actor AS mutation_actor ON mutation_actor.actor_id=mutation.actor_id
            WHERE topic.topic_id=?
            """,
            (topic_id,),
        ).fetchone()

    def _topic_management_data(self, row: sqlite3.Row) -> dict[str, Any]:
        creator = None
        if row["creator_actor_kind"] is not None:
            creator = {
                "actor_kind": str(row["creator_actor_kind"]),
                "display_name": str(row["creator_display_name"]),
            }
        state_actor = None
        if row["state_actor_kind"] is not None:
            state_actor = {
                "actor_kind": str(row["state_actor_kind"]),
                "display_name": str(row["state_actor_display_name"]),
            }
        last_modified_by = None
        if row["mutation_actor_kind"] is not None:
            last_modified_by = {
                "actor_kind": str(row["mutation_actor_kind"]),
                "display_name": str(row["mutation_actor_display_name"]),
            }
        return {
            "topic_id": str(row["topic_id"]),
            "topic_key": str(row["topic_key"]),
            "title": str(row["title"]),
            "display_title": self.presentation.topic_title(
                str(row["topic_key"]), str(row["title"])
            ),
            "parent_topic_id": row["parent_topic_id"],
            "parent_title": row["parent_title"],
            "depth": 1 if row["parent_topic_id"] is not None else 0,
            "manual_order": int(row["manual_order"]),
            "revision": int(row["revision"]),
            "etag": f"topic:{row['topic_id']}:r{row['revision']}",
            "is_manual": row["created_by_actor_id"] is not None,
            "created_by": creator,
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "retired_at": row["retired_at"],
            "retired": row["retired_at"] is not None,
            "state": str(row["effective_state"]),
            "manual_state": row["manual_state"],
            "state_note": row["state_note"],
            "state_actor": state_actor,
            "state_occurred_at": row["state_occurred_at"],
            "source_kind": str(row["source_kind"]),
            "summary": row["summary"],
            "research_id": row["research_id"],
            "page_url": row["page_url"],
            "quick_links": json.loads(str(row["quick_links_json"])),
            "projection_updated_at": str(row["projection_updated_at"]),
            "last_event_kind": row["last_event_kind"],
            "last_modified_by": last_modified_by,
            "last_mutation_at": row["last_mutation_at"],
            "active_child_count": int(row["active_child_count"]),
            "active_research_link_count": int(row["active_research_link_count"]),
        }

    @staticmethod
    def _progress_topic_row(
        connection: sqlite3.Connection, topic_id: str
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT topic.*,
                   creator.actor_kind AS creator_actor_kind,
                   creator.display_name AS creator_display_name,
                   modifier.actor_kind AS modifier_actor_kind,
                   modifier.display_name AS modifier_display_name,
                   event.event_kind AS last_event_kind,
                   event.occurred_at AS last_mutation_at
            FROM progress_topic AS topic
            JOIN actor AS creator ON creator.actor_id=topic.created_by_actor_id
            JOIN actor AS modifier ON modifier.actor_id=topic.last_modified_by_actor_id
            LEFT JOIN progress_topic_event AS event
              ON event.topic_id=topic.topic_id AND event.new_revision=topic.revision
            WHERE topic.topic_id=?
            """,
            (topic_id,),
        ).fetchone()

    def _progress_topic_data(self, row: sqlite3.Row) -> dict[str, Any]:
        creator = {
            "actor_kind": str(row["creator_actor_kind"]),
            "display_name": str(row["creator_display_name"]),
        }
        modifier = {
            "actor_kind": str(row["modifier_actor_kind"]),
            "display_name": str(row["modifier_display_name"]),
        }
        state = str(row["state"])
        return {
            "topic_id": str(row["topic_id"]),
            "topic_key": str(row["topic_key"]),
            "title": str(row["title"]),
            "display_title": str(row["title"]),
            "parent_topic_id": None,
            "parent_title": None,
            "depth": 0,
            "manual_order": int(row["manual_order"]),
            "revision": int(row["revision"]),
            "etag": f"topic:{row['topic_id']}:r{row['revision']}",
            "is_manual": True,
            "created_by": creator,
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "retired_at": row["retired_at"],
            "retired": row["retired_at"] is not None,
            "state": state,
            "manual_state": state,
            "state_note": row["note"],
            "state_actor": modifier,
            "state_occurred_at": str(row["updated_at"]),
            "source_kind": "manual",
            "summary": None,
            "research_id": None,
            "page_url": None,
            "quick_links": [],
            "projection_updated_at": str(row["updated_at"]),
            "last_event_kind": row["last_event_kind"],
            "last_modified_by": modifier,
            "last_mutation_at": row["last_mutation_at"],
            "active_child_count": 0,
            "active_research_link_count": 0,
            "legacy_source_node_id": row["legacy_source_node_id"],
        }

    @staticmethod
    def _progress_replay(
        connection: sqlite3.Connection,
        *,
        idempotency_key: str,
        command_name: str,
        payload_hash: str,
    ) -> CommandOutcome | None:
        row = connection.execute(
            """
            SELECT command_name,payload_hash,outcome,result_json,http_status
            FROM progress_command_receipt WHERE idempotency_key=?
            """,
            (idempotency_key,),
        ).fetchone()
        if row is None:
            return None
        if (str(row["command_name"]), str(row["payload_hash"])) != (
            command_name,
            payload_hash,
        ):
            raise IdempotencyConflict(
                "idempotency key is already bound to a different command or payload"
            )
        result = json.loads(str(row["result_json"]))
        if row["outcome"] == "applied":
            return CommandOutcome(
                True,
                int(row["http_status"]),
                data=dict(result["data"]),
                replayed=True,
            )
        return CommandOutcome(
            False,
            int(row["http_status"]),
            error_code=str(result["error"]["code"]),
            error_message=str(result["error"]["message"]),
            replayed=True,
        )

    @staticmethod
    def _record_progress_command(
        connection: sqlite3.Connection,
        *,
        idempotency_key: str,
        command_name: str,
        payload_hash: str,
        aggregate_urn: str,
        actor_id: str | None,
        outcome: CommandOutcome,
    ) -> CommandOutcome:
        result_json = _outcome_json(outcome)
        connection.execute(
            """
            INSERT INTO progress_command_receipt(
                receipt_id,idempotency_key,command_name,payload_hash,aggregate_urn,
                actor_id,outcome,result_json,result_hash,http_status,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                new_public_id("rcpt"),
                idempotency_key,
                command_name,
                payload_hash,
                aggregate_urn,
                actor_id,
                "applied" if outcome.ok else "rejected",
                result_json,
                stable_sha256("progress-command-result/v1", result_json),
                outcome.status,
                utc_now(),
            ),
        )
        return outcome

    @staticmethod
    def _progress_snapshot(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "title": str(row["title"]),
            "state": str(row["state"]),
            "note": row["note"],
            "manual_order": int(row["manual_order"]),
            "retired_at": row["retired_at"],
        }

    @staticmethod
    def _insert_progress_event(
        connection: sqlite3.Connection,
        *,
        topic_id: str,
        event_kind: Literal["create", "update", "retire"],
        prior_revision: int | None,
        new_revision: int,
        old_snapshot: dict[str, Any] | None,
        new_snapshot: dict[str, Any],
        actor_id: str,
        occurred_at: str,
    ) -> str:
        event_id = new_public_id("tmut")
        connection.execute(
            """
            INSERT INTO progress_topic_event(
                event_id,topic_id,event_kind,prior_revision,new_revision,
                old_payload_json,new_payload_json,actor_id,occurred_at
            ) VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (
                event_id,
                topic_id,
                event_kind,
                prior_revision,
                new_revision,
                canonical_json(old_snapshot) if old_snapshot is not None else None,
                canonical_json(new_snapshot),
                actor_id,
                occurred_at,
            ),
        )
        return event_id

    @staticmethod
    def _topic_mutation_snapshot(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "title": str(row["title"]),
            "parent_topic_id": row["parent_topic_id"],
            "manual_order": int(row["manual_order"]),
            "manual_state": row["manual_state"],
            "state_note": row["state_note"],
            "retired_at": row["retired_at"],
        }

    @staticmethod
    def _insert_topic_mutation(
        connection: sqlite3.Connection,
        *,
        topic_id: str,
        event_kind: Literal["create", "update", "state", "retire"],
        prior_revision: int | None,
        new_revision: int,
        old_snapshot: dict[str, Any] | None,
        new_snapshot: dict[str, Any],
        actor_id: str,
        occurred_at: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO topic_mutation_event(
                topic_mutation_event_id,topic_id,event_kind,prior_revision,new_revision,
                old_payload_json,new_payload_json,actor_id,occurred_at
            ) VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (
                new_public_id("tmut"),
                topic_id,
                event_kind,
                prior_revision,
                new_revision,
                canonical_json(old_snapshot) if old_snapshot is not None else None,
                canonical_json(new_snapshot),
                actor_id,
                occurred_at,
            ),
        )

    def list_topics_for_management(
        self,
        *,
        include_retired: bool = False,
    ) -> list[dict[str, Any]]:
        if self.comment_database_path is not None:
            with self._comment_connection() as connection:
                topic_ids = [
                    str(row["topic_id"])
                    for row in connection.execute(
                        """
                        SELECT topic_id FROM progress_topic
                        WHERE ?=1 OR retired_at IS NULL
                        ORDER BY manual_order,topic_key
                        """,
                        (int(include_retired),),
                    ).fetchall()
                ]
                rows = [
                    self._progress_topic_row(connection, topic_id)
                    for topic_id in topic_ids
                ]
            return [
                self._progress_topic_data(row) for row in rows if row is not None
            ]
        with archive_connection(self.settings) as connection:
            topic_ids = [
                str(row["topic_id"])
                for row in connection.execute(
                    """
                    SELECT topic.topic_id
                    FROM topic
                    LEFT JOIN topic AS parent ON parent.topic_id=topic.parent_topic_id
                    WHERE ?=1 OR topic.retired_at IS NULL
                    ORDER BY
                        COALESCE(parent.manual_order,topic.manual_order),
                        COALESCE(parent.topic_key,topic.topic_key),
                        CASE WHEN topic.parent_topic_id IS NULL THEN 0 ELSE 1 END,
                        topic.manual_order,topic.topic_key
                    """,
                    (int(include_retired),),
                ).fetchall()
            ]
            rows = [self._topic_management_row(connection, topic_id) for topic_id in topic_ids]
        return [self._topic_management_data(row) for row in rows if row is not None]

    def get_topic_for_management(
        self,
        topic_id: str,
        *,
        include_retired: bool = False,
    ) -> dict[str, Any] | None:
        if self.comment_database_path is not None:
            with self._comment_connection() as connection:
                row = self._progress_topic_row(connection, topic_id)
            if row is None or (
                row["retired_at"] is not None and not include_retired
            ):
                return None
            return self._progress_topic_data(row)
        with archive_connection(self.settings) as connection:
            row = self._topic_management_row(connection, topic_id)
        if row is None or (row["retired_at"] is not None and not include_retired):
            return None
        return self._topic_management_data(row)

    def _create_progress_topic(
        self,
        topic: ManualTopicCreateInput,
        actor: ActorInput,
        *,
        idempotency_key: str,
        command: str,
        payload: dict[str, Any],
        digest: str,
    ) -> CommandOutcome:
        with self._comment_connection() as connection, immediate_transaction(connection):
            replay = self._progress_replay(
                connection,
                idempotency_key=idempotency_key,
                command_name=command,
                payload_hash=digest,
            )
            if replay is not None:
                return replay
            actor_id = self._actor_id(connection, actor)
            topic_id = new_public_id("top")
            aggregate = f"qrh:progress-topic:{topic_id}"
            if topic.parent_topic_id is not None:
                return self._record_progress_command(
                    connection,
                    idempotency_key=idempotency_key,
                    command_name=command,
                    payload_hash=digest,
                    aggregate_urn=aggregate,
                    actor_id=actor_id,
                    outcome=CommandOutcome(
                        False,
                        422,
                        error_code="invalid_topic_parent",
                        error_message="进度记录是扁平提醒，不属于 Q 研究层级。",
                    ),
                )
            now = utc_now()
            topic_key = self._manual_topic_key(topic_id)
            connection.execute(
                """
                INSERT INTO progress_topic(
                    topic_id,topic_key,title,state,note,manual_order,
                    created_by_actor_id,last_modified_by_actor_id,
                    created_at,updated_at,revision,retired_at,legacy_source_node_id
                ) VALUES(?,?,?,?,?,?,?,?,?,?,1,NULL,NULL)
                """,
                (
                    topic_id,
                    topic_key,
                    topic.title,
                    topic.state,
                    topic.note,
                    topic.manual_order,
                    actor_id,
                    actor_id,
                    now,
                    now,
                ),
            )
            row = self._progress_topic_row(connection, topic_id)
            assert row is not None
            event_id = self._insert_progress_event(
                connection,
                topic_id=topic_id,
                event_kind="create",
                prior_revision=None,
                new_revision=1,
                old_snapshot=None,
                new_snapshot=self._progress_snapshot(row),
                actor_id=actor_id,
                occurred_at=now,
            )
            row = self._progress_topic_row(connection, topic_id)
            assert row is not None
            data = self._progress_topic_data(row)
            data["state_event_id"] = event_id
            return self._record_progress_command(
                connection,
                idempotency_key=idempotency_key,
                command_name=command,
                payload_hash=digest,
                aggregate_urn=aggregate,
                actor_id=actor_id,
                outcome=CommandOutcome(True, 201, data=data),
            )

    def _update_progress_topic(
        self,
        topic_id: str,
        changes: ManualTopicUpdateInput,
        actor: ActorInput,
        *,
        expected_revision: int,
        idempotency_key: str,
        command: str,
        payload: dict[str, Any],
        digest: str,
    ) -> CommandOutcome:
        aggregate = f"qrh:progress-topic:{topic_id}"
        with self._comment_connection() as connection, immediate_transaction(connection):
            replay = self._progress_replay(
                connection,
                idempotency_key=idempotency_key,
                command_name=command,
                payload_hash=digest,
            )
            if replay is not None:
                return replay
            actor_id = self._actor_id(connection, actor)
            current = self._progress_topic_row(connection, topic_id)
            if current is None or current["retired_at"] is not None:
                outcome = CommandOutcome(
                    False,
                    404,
                    error_code="topic_not_found",
                    error_message="进度记录不存在或已经删除。",
                )
            elif int(current["revision"]) != expected_revision:
                outcome = CommandOutcome(
                    False,
                    409,
                    error_code="revision_conflict",
                    error_message="进度记录已被其他写入更新，请刷新后重试。",
                )
            elif (
                "parent_topic_id" in changes.model_fields_set
                and changes.parent_topic_id is not None
            ):
                outcome = CommandOutcome(
                    False,
                    422,
                    error_code="invalid_topic_parent",
                    error_message="进度记录是扁平提醒，不属于 Q 研究层级。",
                )
            elif "title" in changes.model_fields_set and changes.title is None:
                outcome = CommandOutcome(
                    False, 422, error_code="invalid_topic_update",
                    error_message="进度记录标题不能为空。",
                )
            elif "state" in changes.model_fields_set and changes.state is None:
                outcome = CommandOutcome(
                    False, 422, error_code="invalid_topic_update",
                    error_message="进度记录状态不能为空。",
                )
            elif (
                "manual_order" in changes.model_fields_set
                and changes.manual_order is None
            ):
                outcome = CommandOutcome(
                    False, 422, error_code="invalid_topic_update",
                    error_message="进度记录排序不能为空。",
                )
            else:
                assert current is not None
                old_snapshot = self._progress_snapshot(current)
                title = (
                    str(changes.title)
                    if "title" in changes.model_fields_set
                    else str(current["title"])
                )
                state = (
                    str(changes.state)
                    if "state" in changes.model_fields_set
                    else str(current["state"])
                )
                note = (
                    changes.note
                    if "note" in changes.model_fields_set
                    else current["note"]
                )
                manual_order = (
                    int(changes.manual_order)
                    if "manual_order" in changes.model_fields_set
                    else int(current["manual_order"])
                )
                now = utc_now()
                revision = int(current["revision"]) + 1
                connection.execute(
                    """
                    UPDATE progress_topic SET
                        title=?,state=?,note=?,manual_order=?,
                        last_modified_by_actor_id=?,updated_at=?,revision=?
                    WHERE topic_id=?
                    """,
                    (
                        title,
                        state,
                        note,
                        manual_order,
                        actor_id,
                        now,
                        revision,
                        topic_id,
                    ),
                )
                updated = self._progress_topic_row(connection, topic_id)
                assert updated is not None
                self._insert_progress_event(
                    connection,
                    topic_id=topic_id,
                    event_kind="update",
                    prior_revision=int(current["revision"]),
                    new_revision=revision,
                    old_snapshot=old_snapshot,
                    new_snapshot=self._progress_snapshot(updated),
                    actor_id=actor_id,
                    occurred_at=now,
                )
                updated = self._progress_topic_row(connection, topic_id)
                assert updated is not None
                outcome = CommandOutcome(
                    True, 200, data=self._progress_topic_data(updated)
                )
            return self._record_progress_command(
                connection,
                idempotency_key=idempotency_key,
                command_name=command,
                payload_hash=digest,
                aggregate_urn=aggregate,
                actor_id=actor_id,
                outcome=outcome,
            )

    def _retire_progress_topic(
        self,
        topic_id: str,
        actor: ActorInput,
        *,
        expected_revision: int,
        idempotency_key: str,
        command: str,
        payload: dict[str, Any],
        digest: str,
    ) -> CommandOutcome:
        aggregate = f"qrh:progress-topic:{topic_id}"
        with self._comment_connection() as connection, immediate_transaction(connection):
            replay = self._progress_replay(
                connection,
                idempotency_key=idempotency_key,
                command_name=command,
                payload_hash=digest,
            )
            if replay is not None:
                return replay
            actor_id = self._actor_id(connection, actor)
            current = self._progress_topic_row(connection, topic_id)
            if current is None or current["retired_at"] is not None:
                outcome = CommandOutcome(
                    False, 404, error_code="topic_not_found",
                    error_message="进度记录不存在或已经删除。",
                )
            elif int(current["revision"]) != expected_revision:
                outcome = CommandOutcome(
                    False, 409, error_code="revision_conflict",
                    error_message="进度记录已被其他写入更新，请刷新后重试。",
                )
            else:
                old_snapshot = self._progress_snapshot(current)
                now = utc_now()
                revision = int(current["revision"]) + 1
                connection.execute(
                    """
                    UPDATE progress_topic SET retired_at=?,updated_at=?,
                        last_modified_by_actor_id=?,revision=? WHERE topic_id=?
                    """,
                    (now, now, actor_id, revision, topic_id),
                )
                updated = self._progress_topic_row(connection, topic_id)
                assert updated is not None
                self._insert_progress_event(
                    connection,
                    topic_id=topic_id,
                    event_kind="retire",
                    prior_revision=int(current["revision"]),
                    new_revision=revision,
                    old_snapshot=old_snapshot,
                    new_snapshot=self._progress_snapshot(updated),
                    actor_id=actor_id,
                    occurred_at=now,
                )
                updated = self._progress_topic_row(connection, topic_id)
                assert updated is not None
                outcome = CommandOutcome(
                    True, 200, data=self._progress_topic_data(updated)
                )
            return self._record_progress_command(
                connection,
                idempotency_key=idempotency_key,
                command_name=command,
                payload_hash=digest,
                aggregate_urn=aggregate,
                actor_id=actor_id,
                outcome=outcome,
            )

    def create_manual_topic(
        self,
        topic: ManualTopicCreateInput,
        actor: ActorInput,
        *,
        idempotency_key: str,
    ) -> CommandOutcome:
        command = "topic.create_manual"
        payload = {
            "topic": topic.model_dump(mode="json"),
            "actor": actor.model_dump(mode="json"),
        }
        digest = _payload_hash(command, payload)
        if self.comment_database_path is not None:
            return self._create_progress_topic(
                topic,
                actor,
                idempotency_key=idempotency_key,
                command=command,
                payload=payload,
                digest=digest,
            )
        with archive_connection(self.settings) as connection, immediate_transaction(connection):
            replay = self._replay(
                connection,
                idempotency_key=idempotency_key,
                command_name=command,
                payload_hash=digest,
            )
            if replay is not None:
                return replay
            actor_id = self._actor_id(connection, actor)
            topic_id = new_public_id("top")
            parent_error = self._topic_parent_error(
                connection,
                topic_id=topic_id,
                parent_topic_id=topic.parent_topic_id,
            )
            if parent_error is not None:
                return self._record(
                    connection,
                    idempotency_key=idempotency_key,
                    command_name=command,
                    payload_hash=digest,
                    request_payload=payload,
                    aggregate_urn=f"qrh:topic:{topic_id}",
                    actor_id=actor_id,
                    outcome=CommandOutcome(
                        False,
                        422,
                        error_code="invalid_topic_parent",
                        error_message=parent_error,
                    ),
                )
            now = utc_now()
            topic_key = self._manual_topic_key(topic_id)
            connection.execute(
                """
                INSERT INTO topic(
                    topic_id,topic_key,title,manual_order,created_at,retired_at,
                    parent_topic_id,created_by_actor_id,revision,updated_at
                ) VALUES(?,?,?,?,?,NULL,?,?,1,?)
                """,
                (
                    topic_id,
                    topic_key,
                    topic.title,
                    topic.manual_order,
                    now,
                    topic.parent_topic_id,
                    actor_id,
                    now,
                ),
            )
            state_event_id = new_public_id("tevt")
            connection.execute(
                """
                INSERT INTO topic_state_event(
                    topic_state_event_id,topic_id,state,note,actor_id,occurred_at,
                    supersedes_event_id
                ) VALUES(?,?,?,?,?,?,NULL)
                """,
                (
                    state_event_id,
                    topic_id,
                    topic.state,
                    topic.note,
                    actor_id,
                    now,
                ),
            )
            self._recompute_topic(connection, topic_id, updated_at=now)
            row = self._topic_management_row(connection, topic_id)
            assert row is not None
            self._insert_topic_mutation(
                connection,
                topic_id=topic_id,
                event_kind="create",
                prior_revision=None,
                new_revision=1,
                old_snapshot=None,
                new_snapshot=self._topic_mutation_snapshot(row),
                actor_id=actor_id,
                occurred_at=now,
            )
            row = self._topic_management_row(connection, topic_id)
            assert row is not None
            data = self._topic_management_data(row)
            data["state_event_id"] = state_event_id
            self._emit(
                connection,
                "ArchiveManualTopicCreated",
                f"qrh:topic:{topic_id}",
                data,
            )
            return self._record(
                connection,
                idempotency_key=idempotency_key,
                command_name=command,
                payload_hash=digest,
                request_payload=payload,
                aggregate_urn=f"qrh:topic:{topic_id}",
                actor_id=actor_id,
                outcome=CommandOutcome(True, 201, data=data),
            )

    def update_manual_topic(
        self,
        topic_id: str,
        changes: ManualTopicUpdateInput,
        actor: ActorInput,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> CommandOutcome:
        command = "topic.update_manual"
        payload = {
            "topic_id": topic_id,
            "changes": changes.model_dump(mode="json", exclude_unset=True),
            "actor": actor.model_dump(mode="json"),
            "expected_revision": expected_revision,
        }
        digest = _payload_hash(command, payload)
        if self.comment_database_path is not None:
            return self._update_progress_topic(
                topic_id,
                changes,
                actor,
                expected_revision=expected_revision,
                idempotency_key=idempotency_key,
                command=command,
                payload=payload,
                digest=digest,
            )
        with archive_connection(self.settings) as connection, immediate_transaction(connection):
            replay = self._replay(
                connection,
                idempotency_key=idempotency_key,
                command_name=command,
                payload_hash=digest,
            )
            if replay is not None:
                return replay
            actor_id = self._actor_id(connection, actor)
            current = self._topic_management_row(connection, topic_id)
            if current is None or current["retired_at"] is not None:
                outcome = CommandOutcome(
                    False,
                    404,
                    error_code="topic_not_found",
                    error_message="研究议题不存在或已经退休。",
                )
            elif current["created_by_actor_id"] is None:
                outcome = CommandOutcome(
                    False,
                    409,
                    error_code="topic_not_manual",
                    error_message="自动研究专题不能通过人工议题接口修改。",
                )
            elif int(current["revision"]) != expected_revision:
                outcome = CommandOutcome(
                    False,
                    409,
                    error_code="revision_conflict",
                    error_message="研究议题已被其他写入更新，请刷新后重试。",
                )
            elif current["manual_state"] is None:
                outcome = CommandOutcome(
                    False,
                    409,
                    error_code="manual_topic_state_missing",
                    error_message="人工研究议题缺少可追溯状态事件。",
                )
            else:
                fields = changes.model_fields_set
                if "title" in fields and changes.title is None:
                    outcome = CommandOutcome(
                        False,
                        422,
                        error_code="invalid_topic_update",
                        error_message="研究议题标题不能为空。",
                    )
                elif "state" in fields and changes.state is None:
                    outcome = CommandOutcome(
                        False,
                        422,
                        error_code="invalid_topic_update",
                        error_message="研究议题状态不能为空。",
                    )
                elif "manual_order" in fields and changes.manual_order is None:
                    outcome = CommandOutcome(
                        False,
                        422,
                        error_code="invalid_topic_update",
                        error_message="研究议题排序不能为空。",
                    )
                else:
                    title = (
                        str(changes.title)
                        if "title" in fields
                        else str(current["title"])
                    )
                    state = (
                        str(changes.state)
                        if "state" in fields
                        else str(current["manual_state"])
                    )
                    note = changes.note if "note" in fields else current["state_note"]
                    parent_topic_id = (
                        changes.parent_topic_id
                        if "parent_topic_id" in fields
                        else current["parent_topic_id"]
                    )
                    manual_order = (
                        int(changes.manual_order)
                        if "manual_order" in fields
                        else int(current["manual_order"])
                    )
                    old_snapshot = self._topic_mutation_snapshot(current)
                    candidate_snapshot = {
                        "title": title,
                        "parent_topic_id": parent_topic_id,
                        "manual_order": manual_order,
                        "manual_state": state,
                        "state_note": note,
                        "retired_at": None,
                    }
                    if candidate_snapshot == old_snapshot:
                        outcome = CommandOutcome(
                            True,
                            200,
                            data=self._topic_management_data(current),
                        )
                    else:
                        parent_error = self._topic_parent_error(
                            connection,
                            topic_id=topic_id,
                            parent_topic_id=parent_topic_id,
                        )
                        if parent_error is not None:
                            outcome = CommandOutcome(
                                False,
                                422,
                                error_code="invalid_topic_parent",
                                error_message=parent_error,
                            )
                        else:
                            prior_revision = int(current["revision"])
                            next_revision = prior_revision + 1
                            now = utc_now()
                            state_changed = (
                                state != current["manual_state"]
                                or note != current["state_note"]
                            )
                            if state_changed:
                                connection.execute(
                                    """
                                    INSERT INTO topic_state_event(
                                        topic_state_event_id,topic_id,state,note,actor_id,
                                        occurred_at,supersedes_event_id
                                    ) VALUES(?,?,?,?,?,?,?)
                                    """,
                                    (
                                        new_public_id("tevt"),
                                        topic_id,
                                        state,
                                        note,
                                        actor_id,
                                        now,
                                        current["topic_state_event_id"],
                                    ),
                                )
                            connection.execute(
                                """
                                UPDATE topic
                                SET title=?,parent_topic_id=?,manual_order=?,revision=?,updated_at=?
                                WHERE topic_id=?
                                """,
                                (
                                    title,
                                    parent_topic_id,
                                    manual_order,
                                    next_revision,
                                    now,
                                    topic_id,
                                ),
                            )
                            self._recompute_topic(connection, topic_id, updated_at=now)
                            updated = self._topic_management_row(connection, topic_id)
                            assert updated is not None
                            self._insert_topic_mutation(
                                connection,
                                topic_id=topic_id,
                                event_kind="update",
                                prior_revision=prior_revision,
                                new_revision=next_revision,
                                old_snapshot=old_snapshot,
                                new_snapshot=self._topic_mutation_snapshot(updated),
                                actor_id=actor_id,
                                occurred_at=now,
                            )
                            updated = self._topic_management_row(connection, topic_id)
                            assert updated is not None
                            data = self._topic_management_data(updated)
                            self._emit(
                                connection,
                                "ArchiveManualTopicUpdated",
                                f"qrh:topic:{topic_id}",
                                data,
                            )
                            outcome = CommandOutcome(True, 200, data=data)
            return self._record(
                connection,
                idempotency_key=idempotency_key,
                command_name=command,
                payload_hash=digest,
                request_payload=payload,
                aggregate_urn=f"qrh:topic:{topic_id}",
                actor_id=actor_id,
                outcome=outcome,
            )

    def retire_manual_topic(
        self,
        topic_id: str,
        actor: ActorInput,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> CommandOutcome:
        command = "topic.retire_manual"
        payload = {
            "topic_id": topic_id,
            "actor": actor.model_dump(mode="json"),
            "expected_revision": expected_revision,
        }
        digest = _payload_hash(command, payload)
        if self.comment_database_path is not None:
            return self._retire_progress_topic(
                topic_id,
                actor,
                expected_revision=expected_revision,
                idempotency_key=idempotency_key,
                command=command,
                payload=payload,
                digest=digest,
            )
        with archive_connection(self.settings) as connection, immediate_transaction(connection):
            replay = self._replay(
                connection,
                idempotency_key=idempotency_key,
                command_name=command,
                payload_hash=digest,
            )
            if replay is not None:
                return replay
            actor_id = self._actor_id(connection, actor)
            current = self._topic_management_row(connection, topic_id)
            if current is None:
                outcome = CommandOutcome(
                    False,
                    404,
                    error_code="topic_not_found",
                    error_message="研究议题不存在。",
                )
            elif current["retired_at"] is not None:
                outcome = CommandOutcome(
                    False,
                    409,
                    error_code="topic_already_retired",
                    error_message="研究议题已经退休。",
                )
            elif current["created_by_actor_id"] is None:
                outcome = CommandOutcome(
                    False,
                    409,
                    error_code="topic_not_manual",
                    error_message="自动研究专题不能通过人工议题接口删除。",
                )
            elif int(current["revision"]) != expected_revision:
                outcome = CommandOutcome(
                    False,
                    409,
                    error_code="revision_conflict",
                    error_message="研究议题已被其他写入更新，请刷新后重试。",
                )
            elif int(current["active_child_count"]) > 0:
                outcome = CommandOutcome(
                    False,
                    409,
                    error_code="topic_has_active_children",
                    error_message="请先移动或删除该议题下的一级子议题。",
                )
            elif int(current["active_research_link_count"]) > 0:
                outcome = CommandOutcome(
                    False,
                    409,
                    error_code="topic_has_active_research_links",
                    error_message="仍有关联研究的议题不能删除。",
                )
            else:
                prior_revision = int(current["revision"])
                next_revision = prior_revision + 1
                now = utc_now()
                old_snapshot = self._topic_mutation_snapshot(current)
                connection.execute(
                    """
                    UPDATE topic
                    SET retired_at=?,revision=?,updated_at=?
                    WHERE topic_id=?
                    """,
                    (now, next_revision, now, topic_id),
                )
                retired = self._topic_management_row(connection, topic_id)
                assert retired is not None
                self._insert_topic_mutation(
                    connection,
                    topic_id=topic_id,
                    event_kind="retire",
                    prior_revision=prior_revision,
                    new_revision=next_revision,
                    old_snapshot=old_snapshot,
                    new_snapshot=self._topic_mutation_snapshot(retired),
                    actor_id=actor_id,
                    occurred_at=now,
                )
                retired = self._topic_management_row(connection, topic_id)
                assert retired is not None
                data = self._topic_management_data(retired)
                self._emit(
                    connection,
                    "ArchiveManualTopicRetired",
                    f"qrh:topic:{topic_id}",
                    data,
                )
                outcome = CommandOutcome(True, 200, data=data)
            return self._record(
                connection,
                idempotency_key=idempotency_key,
                command_name=command,
                payload_hash=digest,
                request_payload=payload,
                aggregate_urn=f"qrh:topic:{topic_id}",
                actor_id=actor_id,
                outcome=outcome,
            )

    def create_topic(
        self,
        topic: TopicInput,
        actor: ActorInput,
        *,
        idempotency_key: str,
    ) -> CommandOutcome:
        command = "topic.create"
        payload = {"topic": topic.model_dump(mode="json"), "actor": actor.model_dump(mode="json")}
        digest = _payload_hash(command, payload)
        with archive_connection(self.settings) as connection, immediate_transaction(connection):
            replay = self._replay(connection, idempotency_key=idempotency_key, command_name=command, payload_hash=digest)
            if replay is not None:
                return replay
            actor_id = self._actor_id(connection, actor)
            existing = connection.execute("SELECT * FROM topic WHERE topic_key=?", (topic.topic_key,)).fetchone()
            if existing is not None:
                outcome = CommandOutcome(False, 409, error_code="topic_key_conflict", error_message="Topic key 已存在。")
                aggregate = f"qrh:topic:{existing['topic_id']}"
            else:
                topic_id = new_public_id("top")
                now = utc_now()
                connection.execute(
                    """
                    INSERT INTO topic(
                        topic_id,topic_key,title,manual_order,created_at,retired_at,
                        parent_topic_id,created_by_actor_id,revision,updated_at
                    ) VALUES(?,?,?,?,?,NULL,NULL,NULL,1,?)
                    """,
                    (topic_id, topic.topic_key, topic.title, topic.manual_order, now, now),
                )
                self._recompute_topic(connection, topic_id, updated_at=now)
                row = self._topic_management_row(connection, topic_id)
                assert row is not None
                self._insert_topic_mutation(
                    connection,
                    topic_id=topic_id,
                    event_kind="create",
                    prior_revision=None,
                    new_revision=1,
                    old_snapshot=None,
                    new_snapshot=self._topic_mutation_snapshot(row),
                    actor_id=actor_id,
                    occurred_at=now,
                )
                data = {
                    "topic_id": topic_id,
                    **topic.model_dump(mode="json"),
                    "revision": 1,
                }
                self._emit(connection, "ArchiveTopicCreated", f"qrh:topic:{topic_id}", data)
                outcome = CommandOutcome(True, 201, data=data)
                aggregate = f"qrh:topic:{topic_id}"
            return self._record(connection, idempotency_key=idempotency_key, command_name=command, payload_hash=digest, request_payload=payload, aggregate_urn=aggregate, actor_id=actor_id, outcome=outcome)

    def link_topic_research(
        self,
        topic_id: str,
        research_id: str,
        actor: ActorInput,
        *,
        link_kind: Literal["primary", "supporting"],
        dashboard_primary: bool,
        display_rank: int,
        provenance_urn: str,
        idempotency_key: str,
    ) -> CommandOutcome:
        command = "topic.link_research"
        payload = {
            "topic_id": topic_id, "research_id": research_id, "actor": actor.model_dump(mode="json"),
            "link_kind": link_kind, "dashboard_primary": dashboard_primary,
            "display_rank": display_rank, "provenance_urn": provenance_urn,
        }
        digest = _payload_hash(command, payload)
        with archive_connection(self.settings) as connection, immediate_transaction(connection):
            replay = self._replay(connection, idempotency_key=idempotency_key, command_name=command, payload_hash=digest)
            if replay is not None:
                return replay
            actor_id = self._actor_id(connection, actor)
            if connection.execute("SELECT 1 FROM topic WHERE topic_id=?", (topic_id,)).fetchone() is None or connection.execute("SELECT 1 FROM research WHERE research_id=?", (research_id,)).fetchone() is None:
                outcome = CommandOutcome(False, 404, error_code="topic_or_research_not_found", error_message="Topic 或研究不存在。")
            else:
                now = utc_now()
                connection.execute(
                    """
                    INSERT INTO topic_research_link(
                        topic_id,research_id,link_kind,dashboard_primary,display_rank,status,
                        provenance_urn,created_at
                    ) VALUES(?,?,?,?,?,'active',?,?)
                    ON CONFLICT(topic_id,research_id) DO UPDATE SET
                        link_kind=excluded.link_kind,
                        dashboard_primary=excluded.dashboard_primary,
                        display_rank=excluded.display_rank,
                        status='active',
                        provenance_urn=excluded.provenance_urn
                    """,
                    (topic_id, research_id, link_kind, int(dashboard_primary), display_rank, provenance_urn, now),
                )
                self._recompute_topic(connection, topic_id, updated_at=now)
                data = {
                    "topic_id": topic_id,
                    "research_id": research_id,
                    "link_kind": link_kind,
                    "dashboard_primary": dashboard_primary,
                    "display_rank": display_rank,
                    "provenance_urn": provenance_urn,
                    "status": "active",
                    "projection_updated_at": now,
                }
                self._emit(
                    connection,
                    "ArchiveTopicResearchLinked",
                    f"qrh:topic:{topic_id}",
                    data,
                    created_at=now,
                )
                outcome = CommandOutcome(True, 200, data=data)
            return self._record(connection, idempotency_key=idempotency_key, command_name=command, payload_hash=digest, request_payload=payload, aggregate_urn=f"qrh:topic:{topic_id}", actor_id=actor_id, outcome=outcome)

    def set_topic_state(
        self,
        topic_id: str,
        state: Literal["planned", "paused"],
        note: str | None,
        actor: ActorInput,
        *,
        idempotency_key: str,
    ) -> CommandOutcome:
        command = "topic.set_state"
        clean_note = note.strip() if note else None
        payload = {"topic_id": topic_id, "state": state, "note": clean_note, "actor": actor.model_dump(mode="json")}
        digest = _payload_hash(command, payload)
        with archive_connection(self.settings) as connection, immediate_transaction(connection):
            replay = self._replay(connection, idempotency_key=idempotency_key, command_name=command, payload_hash=digest)
            if replay is not None:
                return replay
            actor_id = self._actor_id(connection, actor)
            current = self._topic_management_row(connection, topic_id)
            if current is None:
                outcome = CommandOutcome(False, 404, error_code="topic_not_found", error_message="Topic 不存在。")
            else:
                prior = self._latest_topic_event(connection, topic_id)
                prior_revision = int(current["revision"])
                next_revision = prior_revision + 1
                old_snapshot = self._topic_mutation_snapshot(current)
                event_id = new_public_id("tevt")
                now = utc_now()
                connection.execute(
                    """
                    INSERT INTO topic_state_event(
                        topic_state_event_id,topic_id,state,note,actor_id,occurred_at,supersedes_event_id
                    ) VALUES(?,?,?,?,?,?,?)
                    """,
                    (event_id, topic_id, state, clean_note, actor_id, now, prior["topic_state_event_id"] if prior else None),
                )
                connection.execute(
                    "UPDATE topic SET revision=?,updated_at=? WHERE topic_id=?",
                    (next_revision, now, topic_id),
                )
                self._recompute_topic(connection, topic_id, updated_at=now)
                updated = self._topic_management_row(connection, topic_id)
                assert updated is not None
                self._insert_topic_mutation(
                    connection,
                    topic_id=topic_id,
                    event_kind="state",
                    prior_revision=prior_revision,
                    new_revision=next_revision,
                    old_snapshot=old_snapshot,
                    new_snapshot=self._topic_mutation_snapshot(updated),
                    actor_id=actor_id,
                    occurred_at=now,
                )
                data = {
                    "topic_id": topic_id,
                    "state": state,
                    "note": clean_note,
                    "event_id": event_id,
                    "revision": next_revision,
                }
                self._emit(connection, "ArchiveTopicStateSet", f"qrh:topic:{topic_id}", data)
                outcome = CommandOutcome(True, 201, data=data)
            return self._record(connection, idempotency_key=idempotency_key, command_name=command, payload_hash=digest, request_payload=payload, aggregate_urn=f"qrh:topic:{topic_id}", actor_id=actor_id, outcome=outcome)

    def set_work_state(
        self,
        research_id: str,
        state: Literal["planned", "in_progress", "paused"],
        note: str | None,
        actor: ActorInput,
        *,
        idempotency_key: str,
    ) -> CommandOutcome:
        command = "research.set_work_state"
        clean_note = note.strip() if note else None
        payload = {"research_id": research_id, "state": state, "note": clean_note, "actor": actor.model_dump(mode="json")}
        digest = _payload_hash(command, payload)
        with archive_connection(self.settings) as connection, immediate_transaction(connection):
            replay = self._replay(connection, idempotency_key=idempotency_key, command_name=command, payload_hash=digest)
            if replay is not None:
                return replay
            actor_id = self._actor_id(connection, actor)
            if connection.execute("SELECT 1 FROM research WHERE research_id=?", (research_id,)).fetchone() is None:
                outcome = CommandOutcome(False, 404, error_code="research_not_found", error_message="研究不存在。")
            else:
                prior = self._latest_work_event(connection, research_id)
                event_id = new_public_id("wevt")
                now = utc_now()
                connection.execute(
                    """
                    INSERT INTO research_work_state_event(
                        work_state_event_id,research_id,state,note,actor_id,occurred_at,supersedes_event_id
                    ) VALUES(?,?,?,?,?,?,?)
                    """,
                    (event_id, research_id, state, clean_note, actor_id, now, prior["work_state_event_id"] if prior else None),
                )
                self._recompute_research(connection, research_id, updated_at=now)
                self._recompute_linked_topics(connection, research_id, updated_at=now)
                data = {"research_id": research_id, "state": state, "note": clean_note, "event_id": event_id}
                self._emit(connection, "ArchiveResearchWorkStateSet", f"qrh:research:{research_id}", data)
                outcome = CommandOutcome(True, 201, data=data)
            return self._record(connection, idempotency_key=idempotency_key, command_name=command, payload_hash=digest, request_payload=payload, aggregate_urn=f"qrh:research:{research_id}", actor_id=actor_id, outcome=outcome)

    def complete_research(
        self,
        research_id: str,
        research_release_id: str,
        *,
        reason: str,
        idempotency_key: str,
        actor: ActorInput | None = None,
        review_urn: str | None = None,
    ) -> CommandOutcome:
        if (actor is None) == (review_urn is None):
            raise ValueError("completion requires exactly one human actor or independent review URN")
        command = "research.complete"
        payload = {
            "research_id": research_id, "research_release_id": research_release_id,
            "reason": reason.strip(), "actor": actor.model_dump(mode="json") if actor else None,
            "review_urn": review_urn,
        }
        digest = _payload_hash(command, payload)
        # Migration and certificate-store readiness must be established before
        # taking the Archive write lock; verification below is read-only and is
        # repeated against the exact current release identity inside the lock.
        review_authority = ReviewAuthority(self.settings) if review_urn else None
        with archive_connection(self.settings) as connection, immediate_transaction(connection):
            replay = self._replay(connection, idempotency_key=idempotency_key, command_name=command, payload_hash=digest)
            if replay is not None:
                return replay
            actor_id = self._actor_id(connection, actor) if actor else None
            active = connection.execute("SELECT research_release_id FROM active_research_release WHERE research_id=?", (research_id,)).fetchone()
            if active is None or active["research_release_id"] != research_release_id:
                outcome = CommandOutcome(False, 409, error_code="release_not_active", error_message="完成决定必须绑定当前可读 release。")
            elif self._valid_completion(connection, research_id, research_release_id) is not None:
                outcome = CommandOutcome(False, 409, error_code="already_completed", error_message="当前 release 已有有效完成决定；请复用原 command 或先显式撤销。")
            elif review_urn is not None:
                identity = connection.execute(
                    """
                    SELECT subject_urn,subject_version_urn,artifact_manifest_hash
                    FROM research_release_candidate_identity
                    WHERE research_id=? AND research_release_id=?
                    """,
                    (research_id, research_release_id),
                ).fetchone()
                summary = connection.execute(
                    """
                    SELECT 1 FROM derived_research_metadata
                    WHERE research_release_id=? AND derivation_type='summary'
                      AND status='released'
                    LIMIT 1
                    """,
                    (research_release_id,),
                ).fetchone()
                if identity is None or summary is None:
                    outcome = CommandOutcome(
                        False,
                        409,
                        error_code="review_candidate_incomplete",
                        error_message="审核式完成要求当前 release 具有冻结候选身份和已放行摘要。",
                    )
                else:
                    assert review_authority is not None
                    try:
                        certificate = review_authority.verify_certificate(
                            review_urn,
                            gate_name="archive_research_completion",
                            gate_version="1",
                            subject_urn=str(identity["subject_urn"]),
                            subject_version_urn=str(identity["subject_version_urn"]),
                            artifact_manifest_hash=str(identity["artifact_manifest_hash"]),
                            requirements_manifest_hash=(
                                ARCHIVE_COMPLETION_REVIEW_REQUIREMENTS_HASH
                            ),
                        )
                    except (ReviewCertificateError, ValueError):
                        outcome = CommandOutcome(
                            False,
                            409,
                            error_code="review_certificate_invalid",
                            error_message="PASS review certificate 未登记、已损坏或未绑定当前 release。",
                        )
                    else:
                        decision_id = new_public_id("dec")
                        now = utc_now()
                        connection.execute(
                            """
                            INSERT INTO research_completion_decision(
                                decision_id,research_id,research_release_id,decision,
                                decision_kind,supersedes_decision_id,target_decision_id,
                                actor_id,review_urn,reason,decided_at
                            ) VALUES(?,?,?,'completed','reviewed_import',NULL,NULL,NULL,?,?,?)
                            """,
                            (
                                decision_id,
                                research_id,
                                research_release_id,
                                certificate.certificate_urn,
                                reason.strip(),
                                now,
                            ),
                        )
                        connection.execute(
                            """
                            INSERT INTO research_completion_review_consumption(
                                decision_id,research_id,research_release_id,
                                certificate_urn,certificate_hash,subject_urn,
                                subject_version_urn,artifact_manifest_hash,
                                requirements_manifest_hash,consumed_at
                            ) VALUES(?,?,?,?,?,?,?,?,?,?)
                            """,
                            (
                                decision_id,
                                research_id,
                                research_release_id,
                                certificate.certificate_urn,
                                certificate.certificate_hash,
                                certificate.spec.subject_urn,
                                certificate.spec.subject_version_urn,
                                certificate.spec.artifact_manifest_hash,
                                certificate.spec.requirements_manifest_hash,
                                now,
                            ),
                        )
                        self._recompute_research(connection, research_id, updated_at=now)
                        self._recompute_linked_topics(connection, research_id, updated_at=now)
                        data = {
                            "decision_id": decision_id,
                            "research_id": research_id,
                            "research_release_id": research_release_id,
                            "decision": "completed",
                            "decision_kind": "reviewed_import",
                            "review_certificate_urn": certificate.certificate_urn,
                        }
                        self._emit(
                            connection,
                            "ArchiveResearchCompleted",
                            f"qrh:research:{research_id}",
                            data,
                        )
                        outcome = CommandOutcome(True, 201, data=data)
            else:
                decision_id = new_public_id("dec")
                now = utc_now()
                connection.execute(
                    """
                    INSERT INTO research_completion_decision(
                        decision_id,research_id,research_release_id,decision,decision_kind,
                        supersedes_decision_id,target_decision_id,actor_id,review_urn,reason,decided_at
                    ) VALUES(?,?,?,'completed',?,NULL,NULL,?,?,?,?)
                    """,
                    (decision_id, research_id, research_release_id, "human", actor_id, None, reason.strip(), now),
                )
                self._recompute_research(connection, research_id, updated_at=now)
                self._recompute_linked_topics(connection, research_id, updated_at=now)
                data = {"decision_id": decision_id, "research_id": research_id, "research_release_id": research_release_id, "decision": "completed"}
                self._emit(connection, "ArchiveResearchCompleted", f"qrh:research:{research_id}", data)
                outcome = CommandOutcome(True, 201, data=data)
            return self._record(connection, idempotency_key=idempotency_key, command_name=command, payload_hash=digest, request_payload=payload, aggregate_urn=f"qrh:research:{research_id}", actor_id=actor_id, outcome=outcome)

    def revoke_completion(
        self,
        research_id: str,
        target_decision_id: str,
        *,
        reason: str,
        idempotency_key: str,
        actor: ActorInput | None = None,
        review_urn: str | None = None,
    ) -> CommandOutcome:
        if (actor is None) == (review_urn is None):
            raise ValueError("revocation requires exactly one human actor or independent review URN")
        command = "research.revoke_completion"
        payload = {
            "research_id": research_id,
            "target_decision_id": target_decision_id,
            "reason": reason.strip(),
            "actor": actor.model_dump(mode="json") if actor else None,
            "review_urn": review_urn,
        }
        digest = _payload_hash(command, payload)
        with archive_connection(self.settings) as connection, immediate_transaction(connection):
            replay = self._replay(connection, idempotency_key=idempotency_key, command_name=command, payload_hash=digest)
            if replay is not None:
                return replay
            actor_id = self._actor_id(connection, actor) if actor else None
            target = connection.execute(
                """
                SELECT decision_id,research_release_id FROM research_completion_decision
                WHERE decision_id=? AND research_id=? AND decision='completed'
                """,
                (target_decision_id, research_id),
            ).fetchone()
            already_revoked = connection.execute(
                "SELECT 1 FROM research_completion_decision WHERE target_decision_id=?",
                (target_decision_id,),
            ).fetchone()
            if review_urn is not None:
                outcome = CommandOutcome(False, 409, error_code="review_certificate_required", error_message="reviewed_import 撤销必须消费可验证的 PASS review certificate；当前不接受裸 review URN。")
            elif target is None:
                outcome = CommandOutcome(False, 404, error_code="completion_not_found", error_message="待撤销的完成决定不存在。")
            elif already_revoked is not None:
                outcome = CommandOutcome(False, 409, error_code="completion_already_revoked", error_message="该完成决定已被撤销。")
            else:
                decision_id = new_public_id("dec")
                now = utc_now()
                connection.execute(
                    """
                    INSERT INTO research_completion_decision(
                        decision_id,research_id,research_release_id,decision,decision_kind,
                        supersedes_decision_id,target_decision_id,actor_id,review_urn,reason,decided_at
                    ) VALUES(?,?,?,'revoked',?,NULL,?,?,?,?,?)
                    """,
                    (
                        decision_id, research_id, target["research_release_id"],
                        "human", target_decision_id,
                        actor_id, None, reason.strip(), now,
                    ),
                )
                self._recompute_research(connection, research_id, updated_at=now)
                self._recompute_linked_topics(connection, research_id, updated_at=now)
                data = {
                    "decision_id": decision_id,
                    "research_id": research_id,
                    "target_decision_id": target_decision_id,
                    "decision": "revoked",
                }
                self._emit(connection, "ArchiveResearchCompletionRevoked", f"qrh:research:{research_id}", data)
                outcome = CommandOutcome(True, 201, data=data)
            return self._record(
                connection,
                idempotency_key=idempotency_key,
                command_name=command,
                payload_hash=digest,
                request_payload=payload,
                aggregate_urn=f"qrh:research:{research_id}",
                actor_id=actor_id,
                outcome=outcome,
            )

    @staticmethod
    def _latest_work_event(connection: sqlite3.Connection, research_id: str) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT event.* FROM research_work_state_event AS event
            WHERE event.research_id=? AND NOT EXISTS(
                SELECT 1 FROM research_work_state_event AS later
                WHERE later.supersedes_event_id=event.work_state_event_id
            )
            ORDER BY event.occurred_at DESC,event.work_state_event_id DESC LIMIT 1
            """,
            (research_id,),
        ).fetchone()

    @staticmethod
    def _latest_topic_event(connection: sqlite3.Connection, topic_id: str) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT event.* FROM topic_state_event AS event
            WHERE event.topic_id=? AND NOT EXISTS(
                SELECT 1 FROM topic_state_event AS later
                WHERE later.supersedes_event_id=event.topic_state_event_id
            )
            ORDER BY event.occurred_at DESC,event.topic_state_event_id DESC LIMIT 1
            """,
            (topic_id,),
        ).fetchone()

    @staticmethod
    def _valid_completion(connection: sqlite3.Connection, research_id: str, release_id: str | None) -> sqlite3.Row | None:
        if release_id is None:
            return None
        return connection.execute(
            """
            SELECT decision.* FROM research_completion_decision AS decision
            WHERE decision.research_id=? AND decision.research_release_id=?
              AND decision.decision='completed'
              AND (
                    decision.decision_kind='human'
                    OR EXISTS(
                        SELECT 1 FROM research_completion_review_consumption AS consumption
                        WHERE consumption.decision_id=decision.decision_id
                          AND consumption.research_id=decision.research_id
                          AND consumption.research_release_id=decision.research_release_id
                          AND consumption.certificate_urn=decision.review_urn
                    )
              )
              AND NOT EXISTS(
                  SELECT 1 FROM research_completion_decision AS invalidator
                  WHERE invalidator.target_decision_id=decision.decision_id
                     OR invalidator.supersedes_decision_id=decision.decision_id
              )
            ORDER BY decision.decided_at DESC,decision.decision_id DESC LIMIT 1
            """,
            (research_id, release_id),
        ).fetchone()

    def _recompute_research(
        self,
        connection: sqlite3.Connection,
        research_id: str,
        *,
        updated_at: str | None = None,
    ) -> None:
        active = connection.execute(
            """
            SELECT active.research_release_id,active.activation_id
            FROM active_research_release AS active WHERE active.research_id=?
            """,
            (research_id,),
        ).fetchone()
        release_id = str(active["research_release_id"]) if active else None
        completion = self._valid_completion(connection, research_id, release_id)
        work = self._latest_work_event(connection, research_id)
        if completion is not None:
            work_status = "completed"
            work_source = None
            completion_id = str(completion["decision_id"])
        else:
            work_status = str(work["state"]) if work else "planned"
            work_source = str(work["work_state_event_id"]) if work else None
            completion_id = None
        connection.execute(
            """
            INSERT INTO research_status_projection(
                research_id,work_status,release_status,evidence_status,work_source_event_id,
                completion_decision_id,release_activation_id,evidence_source_urn,
                projection_version,updated_at
            ) VALUES(?,?,?,'unknown',?,?,?,NULL,?,?)
            ON CONFLICT(research_id) DO UPDATE SET
                work_status=excluded.work_status,
                release_status=excluded.release_status,
                work_source_event_id=excluded.work_source_event_id,
                completion_decision_id=excluded.completion_decision_id,
                release_activation_id=excluded.release_activation_id,
                projection_version=excluded.projection_version,
                updated_at=excluded.updated_at
            """,
            (
                research_id, work_status, "published" if active else "unpublished",
                work_source, completion_id, str(active["activation_id"]) if active else None,
                self.PROJECTION_VERSION, updated_at or utc_now(),
            ),
        )

    def _recompute_linked_topics(
        self,
        connection: sqlite3.Connection,
        research_id: str,
        *,
        updated_at: str | None = None,
    ) -> None:
        rows = connection.execute(
            "SELECT topic_id FROM topic_research_link WHERE research_id=? AND status='active'",
            (research_id,),
        ).fetchall()
        for row in rows:
            self._recompute_topic(
                connection, str(row["topic_id"]), updated_at=updated_at
            )

    def recompute_after_release_activation(self, connection: sqlite3.Connection, research_id: str) -> None:
        updated_at = utc_now()
        self._recompute_research(connection, research_id, updated_at=updated_at)
        self._recompute_linked_topics(connection, research_id, updated_at=updated_at)

    def _recompute_topic(
        self,
        connection: sqlite3.Connection,
        topic_id: str,
        *,
        updated_at: str | None = None,
    ) -> None:
        links = connection.execute(
            """
            SELECT link.*,research.display_title,status.work_status,active.research_release_id
            FROM topic_research_link AS link
            JOIN research ON research.research_id=link.research_id
            LEFT JOIN research_status_projection AS status ON status.research_id=link.research_id
            LEFT JOIN active_research_release AS active ON active.research_id=link.research_id
            WHERE link.topic_id=? AND link.status='active' AND link.link_kind='primary'
            ORDER BY link.display_rank,link.research_id
            """,
            (topic_id,),
        ).fetchall()
        completed = [row for row in links if row["work_status"] == "completed"]
        dashboard = [row for row in completed if int(row["dashboard_primary"]) == 1]
        summary: str | None = None
        research_id: str | None = None
        page_url: str | None = None
        quick_links: list[dict[str, str]] = []
        source_event: str | None = None
        if completed:
            state = "completed" if len(dashboard) == 1 else "conflicted"
            source_kind = "automatic"
            if state == "completed":
                primary = dashboard[0]
                research_id = str(primary["research_id"])
                release_id = str(primary["research_release_id"])
                metadata = connection.execute(
                    """
                    SELECT payload_json FROM derived_research_metadata
                    WHERE research_release_id=? AND derivation_type='summary'
                      AND status='released'
                    ORDER BY created_at DESC,metadata_id DESC LIMIT 1
                    """,
                    (release_id,),
                ).fetchone()
                if metadata is not None:
                    summary_value = json.loads(str(metadata["payload_json"])).get("summary")
                    if isinstance(summary_value, str) and summary_value.strip():
                        summary = summary_value.strip()
                if summary is None:
                    state = "conflicted"
                    research_id = None
                else:
                    page_url = f"/research/{research_id}"
                    quick_links = [
                        {"research_id": str(row["research_id"]), "title": str(row["display_title"]), "page_url": f"/research/{row['research_id']}"}
                        for row in completed
                        if row["research_id"] != research_id
                    ]
        else:
            event = self._latest_topic_event(connection, topic_id)
            state = str(event["state"]) if event else "planned"
            source_kind = "manual" if event else "automatic"
            source_event = str(event["topic_state_event_id"]) if event else None
        connection.execute(
            """
            INSERT INTO topic_projection(
                topic_id,effective_state,summary,research_id,page_url,quick_links_json,
                source_kind,source_event_id,projection_version,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(topic_id) DO UPDATE SET
                effective_state=excluded.effective_state,
                summary=excluded.summary,
                research_id=excluded.research_id,
                page_url=excluded.page_url,
                quick_links_json=excluded.quick_links_json,
                source_kind=excluded.source_kind,
                source_event_id=excluded.source_event_id,
                projection_version=excluded.projection_version,
                updated_at=excluded.updated_at
            """,
            (
                topic_id, state, summary, research_id, page_url,
                canonical_json(quick_links), source_kind, source_event,
                self.PROJECTION_VERSION, updated_at or utc_now(),
            ),
        )

    def dashboard(self) -> list[dict[str, Any]]:
        with archive_connection(self.settings) as connection:
            rows = connection.execute(
                """
                SELECT topic.topic_id,topic.topic_key,topic.title,topic.manual_order,
                       projection.effective_state,projection.summary,projection.research_id,
                       projection.page_url,projection.quick_links_json,projection.source_kind,
                       event.note AS state_note,actor.display_name AS state_actor_display_name,
                       projection.updated_at
                FROM topic JOIN topic_projection AS projection USING(topic_id)
                LEFT JOIN topic_state_event AS event
                  ON event.topic_state_event_id=projection.source_event_id
                LEFT JOIN actor ON actor.actor_id=event.actor_id
                WHERE topic.retired_at IS NULL
                ORDER BY topic.manual_order,topic.topic_key
                """
            ).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            topic_key = str(row["topic_key"])
            state = str(row["effective_state"])
            source_kind = str(row["source_kind"])
            if self.comment_database_path is not None and source_kind == "manual":
                # 正式运行时人工进度记录来自外部可写协作库；冻结 Archive
                # 中的旧人工投影只作为一次性迁移来源，不能重复展示。
                continue
            actor_name = (
                str(row["state_actor_display_name"])
                if row["state_actor_display_name"] is not None
                else None
            )
            if self.presentation.suppress_system_topic(
                topic_key=topic_key,
                state=state,
                source_kind=source_kind,
                state_actor_display_name=actor_name,
            ):
                continue
            results.append({
                "topic_id": str(row["topic_id"]),
                "topic_key": topic_key,
                "title": self.presentation.topic_title(
                    topic_key, str(row["title"])
                ),
                "state": state,
                "summary": row["summary"],
                "research_id": row["research_id"],
                "page_url": row["page_url"],
                "quick_links": json.loads(str(row["quick_links_json"])),
                "source_kind": source_kind,
                "state_note": row["state_note"],
                "updated_at": str(row["updated_at"]),
            })
        if self.comment_database_path is not None:
            for item in self.list_topics_for_management():
                results.append(
                    {
                        "topic_id": item["topic_id"],
                        "topic_key": item["topic_key"],
                        "title": item["display_title"],
                        "state": item["manual_state"],
                        "summary": None,
                        "research_id": None,
                        "page_url": None,
                        "quick_links": [],
                        "source_kind": "manual",
                        "state_note": item["state_note"],
                        "updated_at": item["updated_at"],
                    }
                )
        return results
