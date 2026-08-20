from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Literal

from quant_hub.config import Settings
from quant_hub.platform.db import immediate_transaction, utc_now
from quant_hub.platform.workflow import canonical_json

from .database import evidence_connection
from .ids import stable_evidence_id
from .repository import EvidenceConflict, EvidenceNotFound


@dataclass(frozen=True, slots=True)
class ReadingTask:
    reading_task_id: str
    paper_id: str
    input_snapshot_hash: str
    latest_attempt: int
    latest_status: str


@dataclass(frozen=True, slots=True)
class ReadingRunResult:
    reading_run_id: str
    attempt_number: int
    result_status: str
    created: bool


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class PaperReadingService:
    """不可变 task/run 队列；失败通过新 attempt 恢复，不原地改写历史。"""

    def __init__(self, settings: Settings):
        self.settings = settings

    def pending_tasks(self, *, limit: int = 100) -> tuple[ReadingTask, ...]:
        if not 1 <= limit <= 500:
            raise ValueError("reading task limit is outside the supported range")
        with evidence_connection(self.settings) as connection:
            rows = connection.execute(
                """
                SELECT task.reading_task_id,task.paper_id,task.input_snapshot_hash,
                       COALESCE(max(run.attempt_number),0) AS latest_attempt,
                       COALESCE((
                           SELECT latest.result_status FROM paper_reading_run AS latest
                           WHERE latest.reading_task_id=task.reading_task_id
                           ORDER BY latest.attempt_number DESC LIMIT 1
                       ),'pending') AS latest_status
                FROM paper_reading_task AS task
                LEFT JOIN paper_reading_run AS run USING(reading_task_id)
                WHERE NOT EXISTS (
                    SELECT 1 FROM paper_reading_run AS passed
                    WHERE passed.reading_task_id=task.reading_task_id
                      AND passed.result_status='succeeded'
                )
                GROUP BY task.reading_task_id
                ORDER BY task.created_at,task.reading_task_id LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return tuple(
            ReadingTask(
                reading_task_id=str(row["reading_task_id"]),
                paper_id=str(row["paper_id"]),
                input_snapshot_hash=str(row["input_snapshot_hash"]),
                latest_attempt=int(row["latest_attempt"]),
                latest_status=str(row["latest_status"]),
            )
            for row in rows
        )

    @staticmethod
    def _current_input_hash(row: Any) -> str:
        locator = json.loads(str(row["locator_json"]))
        return _sha256(
            canonical_json(
                {
                    "abstract_page_sha256": locator["page_sha256"],
                    "abstract_sha256": str(row["excerpt_sha256"]),
                    "pdf_bytes": int(row["bytes"]),
                    "pdf_sha256": str(row["content_sha256"]),
                }
            ).encode("utf-8")
        )

    def record_run(
        self,
        reading_task_id: str,
        *,
        idempotency_key: str,
        worker_kind: Literal["codex", "human", "external"],
        result_status: Literal["succeeded", "failed"],
        analysis_payload: dict[str, object] | None,
        failure: dict[str, object] | None,
        provenance_urn: str,
    ) -> ReadingRunResult:
        if not idempotency_key or len(idempotency_key) > 300:
            raise ValueError("reading run idempotency key is required")
        if result_status == "succeeded":
            if analysis_payload is None or failure is not None:
                raise ValueError("successful reading run requires only analysis_payload")
            required = {"analysis", "core_conclusions", "fact_boundary"}
            if not required.issubset(analysis_payload):
                raise ValueError("successful reading output lacks required fact-boundary fields")
        elif analysis_payload is not None or failure is None:
            raise ValueError("failed reading run requires only failure material")
        run_id = stable_evidence_id(
            "readrun", reading_task_id, idempotency_key, provenance_urn
        )
        analysis_json = canonical_json(analysis_payload) if analysis_payload is not None else None
        failure_json = canonical_json(failure) if failure is not None else None
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            existing = connection.execute(
                "SELECT * FROM paper_reading_run WHERE reading_run_id=?", (run_id,)
            ).fetchone()
            if existing is not None:
                expected = (
                    reading_task_id,
                    idempotency_key,
                    worker_kind,
                    result_status,
                    analysis_json,
                    failure_json,
                    provenance_urn,
                )
                actual = tuple(
                    existing[name]
                    for name in (
                        "reading_task_id",
                        "idempotency_key",
                        "worker_kind",
                        "result_status",
                        "analysis_payload_json",
                        "failure_json",
                        "provenance_urn",
                    )
                )
                if actual != expected:
                    raise EvidenceConflict("reading run idempotency key conflicts")
                return ReadingRunResult(
                    run_id,
                    int(existing["attempt_number"]),
                    result_status,
                    False,
                )
            task = connection.execute(
                """
                SELECT task.*,resource.content_sha256,resource.bytes,
                       excerpt.excerpt_sha256,excerpt.locator_json
                FROM paper_reading_task AS task
                JOIN paper_resource AS resource USING(resource_id)
                JOIN evidence_excerpt AS excerpt
                  ON excerpt.excerpt_id=task.abstract_excerpt_id
                WHERE task.reading_task_id=?
                """,
                (reading_task_id,),
            ).fetchone()
            if task is None:
                raise EvidenceNotFound("paper reading task does not exist")
            current_hash = self._current_input_hash(task)
            if current_hash != task["input_snapshot_hash"]:
                raise EvidenceConflict("paper reading input snapshot changed")
            prior_success = connection.execute(
                """
                SELECT 1 FROM paper_reading_run
                WHERE reading_task_id=? AND result_status='succeeded'
                """,
                (reading_task_id,),
            ).fetchone()
            if prior_success is not None:
                raise EvidenceConflict("paper reading task already has a successful run")
            attempt = int(
                connection.execute(
                    """
                    SELECT COALESCE(max(attempt_number),0)+1
                    FROM paper_reading_run WHERE reading_task_id=?
                    """,
                    (reading_task_id,),
                ).fetchone()[0]
            )
            connection.execute(
                """
                INSERT INTO paper_reading_run(
                    reading_run_id,reading_task_id,attempt_number,idempotency_key,
                    worker_kind,input_snapshot_hash,result_status,
                    analysis_payload_json,failure_json,provenance_urn,completed_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    run_id,
                    reading_task_id,
                    attempt,
                    idempotency_key,
                    worker_kind,
                    current_hash,
                    result_status,
                    analysis_json,
                    failure_json,
                    provenance_urn,
                    utc_now(),
                ),
            )
        return ReadingRunResult(run_id, attempt, result_status, True)
