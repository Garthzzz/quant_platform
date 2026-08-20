from __future__ import annotations

from dataclasses import dataclass
import json
import re
import sqlite3
from typing import Any

from quant_hub.archive.database import archive_connection
from quant_hub.config import Settings
from quant_hub.ids import sha256_hex, stable_sha256
from quant_hub.integration.incremental_intake import (
    EvidenceDispatchReceipt,
    EvidenceIngestCommand,
)
from quant_hub.platform.db import immediate_transaction, utc_now
from quant_hub.platform.objects import ObjectStore
from quant_hub.platform.workflow import canonical_json

from .contracts import CitationOccurrenceInput
from .database import evidence_connection, initialize_evidence_database
from .ids import normalize_identifier, stable_evidence_id
from .repository import EvidenceConflict


class EvidenceIngestConflict(EvidenceConflict):
    """增量命令与已持久化的 Evidence 事实不一致。"""


@dataclass(frozen=True, slots=True)
class _PreparedOccurrence:
    clue_id: str
    source_candidate_id: str
    entity_kind: str
    raw_claim_json: str
    occurrence: CitationOccurrenceInput


class EvidenceDatabaseIngestAdapter:
    """将 Archive 增量命令事务性消费到独立的 Evidence 目标域。

    `accepted` 只表示线索、引用账本、受控 unresolved 绑定、目标域 inbox
    收据和 outbox 结果已经在同一事务中落库；它不表示论文身份或研究证据已放行。
    """

    CONSUMER_NAME = "archive-evidence-ingest/v1"
    SOURCE_DOMAIN = "archive"
    COMMAND_SCHEMA = "qrh-evidence-ingest-command/v1"
    ARTIFACT_SCHEMA = "qrh-incremental-clue-artifact/v1"
    EVENT_TYPE = "EvidenceIngestCommandAccepted"
    EVENT_VERSION = "1"
    RESULT_CONSUMER_NAME = "archive-evidence-ingest-result/v1"
    _HASH = re.compile(r"^[0-9a-f]{64}$")
    _OBJECT_PREFIX = "qrh:object:"
    _COMMAND_ROW_KEYS = frozenset(
        {
            "citation_id",
            "occurrence_kind",
            "resolution_status",
            "raw_marker_text",
            "raw_marker_sha256",
            "context_text",
            "line_start",
            "line_end",
            "byte_start",
            "byte_end",
            "identifier_scheme",
            "identifier_claim",
            "identifier_normalized",
            "status_reason",
            "legacy_occurrence_id",
            "research_urn",
            "archive_release_urn",
            "document_version_urn",
            "source_object_urn",
            "source_path",
            "locator_kind",
            "locator",
        }
    )
    _ARTIFACT_ROW_KEYS = _COMMAND_ROW_KEYS - {
        "legacy_occurrence_id",
        "research_urn",
        "archive_release_urn",
        "document_version_urn",
        "source_object_urn",
        "source_path",
        "locator_kind",
        "locator",
    }

    def __init__(self, settings: Settings):
        self.settings = settings
        self.object_store = ObjectStore(settings.object_root)

    @staticmethod
    def _object_id(urn: str) -> str:
        if not urn.startswith(EvidenceDatabaseIngestAdapter._OBJECT_PREFIX):
            raise EvidenceIngestConflict("Evidence ingest object URN is invalid")
        object_id = urn[len(EvidenceDatabaseIngestAdapter._OBJECT_PREFIX) :]
        if not re.fullmatch(r"obj_sha256_[0-9a-f]{64}", object_id):
            raise EvidenceIngestConflict("Evidence ingest object identity is invalid")
        return object_id

    @staticmethod
    def _row_material(row: sqlite3.Row, fields: tuple[str, ...]) -> tuple[Any, ...]:
        return tuple(row[field] for field in fields)

    @staticmethod
    def _expect_exact(
        connection: sqlite3.Connection,
        *,
        table: str,
        key_name: str,
        key: str,
        fields: tuple[str, ...],
        expected: tuple[Any, ...],
    ) -> bool:
        row = connection.execute(
            f"SELECT * FROM {table} WHERE {key_name}=?", (key,)
        ).fetchone()
        if row is None:
            return False
        if EvidenceDatabaseIngestAdapter._row_material(row, fields) != expected:
            raise EvidenceIngestConflict(
                f"stable {table} identity is bound to different material"
            )
        return True

    def _load_and_validate(
        self, command: EvidenceIngestCommand
    ) -> tuple[bytes, list[_PreparedOccurrence]]:
        if command.schema_version != self.COMMAND_SCHEMA:
            raise EvidenceIngestConflict("unsupported Evidence ingest command schema")
        if not self._HASH.fullmatch(command.idempotency_key):
            raise EvidenceIngestConflict("Evidence ingest idempotency key must be SHA-256")
        if not self._HASH.fullmatch(command.clue_artifact_sha256):
            raise EvidenceIngestConflict("clue artifact SHA-256 is invalid")
        if not command.child_run_urn.startswith("qrh:run:"):
            raise EvidenceIngestConflict("Evidence child run URN is invalid")
        if not command.parent_run_urn.startswith("qrh:run:"):
            raise EvidenceIngestConflict("Evidence parent run URN is invalid")

        source_object_id = self._object_id(command.source_object_urn)
        source_sha256 = source_object_id.removeprefix("obj_sha256_")
        source_bytes = self.object_store.read_bytes(source_object_id)
        if sha256_hex(source_bytes) != source_sha256:
            raise EvidenceIngestConflict("source object bytes do not match their identity")
        if not command.document_version_urn.endswith(source_object_id):
            raise EvidenceIngestConflict("document version is not bound to the source object")

        artifact_object_id = self._object_id(command.clue_artifact_urn)
        if artifact_object_id.removeprefix("obj_sha256_") != command.clue_artifact_sha256:
            raise EvidenceIngestConflict("clue artifact URN and declared hash differ")
        artifact_bytes = self.object_store.read_bytes(artifact_object_id)
        if sha256_hex(artifact_bytes) != command.clue_artifact_sha256:
            raise EvidenceIngestConflict("clue artifact bytes do not match their identity")
        try:
            artifact = json.loads(artifact_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise EvidenceIngestConflict("clue artifact is not canonical UTF-8 JSON") from error
        if not isinstance(artifact, dict) or canonical_json(artifact).encode("utf-8") != artifact_bytes:
            raise EvidenceIngestConflict("clue artifact is not canonical JSON")
        if artifact.get("schema_version") != self.ARTIFACT_SCHEMA:
            raise EvidenceIngestConflict("unsupported clue artifact schema")
        expected_artifact_header = (
            command.source_object_urn,
            source_sha256,
            command.source_path,
        )
        if (
            artifact.get("source_object_urn"),
            artifact.get("document_sha256"),
            artifact.get("source_path"),
        ) != expected_artifact_header:
            raise EvidenceIngestConflict("clue artifact header differs from the command")
        artifact_rows = artifact.get("occurrences")
        if not isinstance(artifact_rows, list) or len(artifact_rows) != len(command.occurrences):
            raise EvidenceIngestConflict("command occurrence count differs from clue artifact")

        provenance_urn = f"qrh:evidence-ingest-command:sha256:{command.command_hash}"
        prepared: list[_PreparedOccurrence] = []
        for index, (artifact_row, command_row) in enumerate(
            zip(artifact_rows, command.occurrences, strict=True)
        ):
            if not isinstance(artifact_row, dict) or not isinstance(command_row, dict):
                raise EvidenceIngestConflict("clue occurrence must be an object")
            if set(artifact_row) != self._ARTIFACT_ROW_KEYS:
                raise EvidenceIngestConflict("clue artifact occurrence fields are not v1-exact")
            if set(command_row) != self._COMMAND_ROW_KEYS:
                raise EvidenceIngestConflict("Evidence command occurrence fields are not v1-exact")
            if any(command_row[key] != artifact_row[key] for key in self._ARTIFACT_ROW_KEYS):
                raise EvidenceIngestConflict("command occurrence differs from frozen clue artifact")
            if (
                command_row["research_urn"] != command.research_urn
                or command_row["archive_release_urn"] != command.archive_release_urn
                or command_row["document_version_urn"] != command.document_version_urn
                or command_row["source_object_urn"] != command.source_object_urn
                or command_row["source_path"] != command.source_path
            ):
                raise EvidenceIngestConflict("occurrence scope differs from its command")
            expected_locator = {
                "line": command_row["line_start"],
                "byte_start": command_row["byte_start"],
                "byte_end": command_row["byte_end"],
            }
            if command_row["locator_kind"] != "utf8_bytes" or command_row["locator"] != expected_locator:
                raise EvidenceIngestConflict("incremental clue does not carry an exact byte locator")

            scheme = command_row["identifier_scheme"]
            identifier_claim = command_row["identifier_claim"]
            identifier_normalized = command_row["identifier_normalized"]
            if scheme is None:
                if identifier_claim is not None or identifier_normalized is not None:
                    raise EvidenceIngestConflict("identifier fields are only valid as a complete set")
                ledger_identifier = ""
            else:
                if not isinstance(identifier_claim, str) or not isinstance(identifier_normalized, str):
                    raise EvidenceIngestConflict("identifier fields are incomplete")
                try:
                    normalized = normalize_identifier(str(scheme), identifier_claim)
                except ValueError as error:
                    raise EvidenceIngestConflict("clue identifier cannot be normalized") from error
                if normalized != identifier_normalized:
                    raise EvidenceIngestConflict("clue identifier normalization is inconsistent")
                ledger_identifier = f"{scheme}:{normalized}"

            incoming_legacy_id = str(command_row["legacy_occurrence_id"])
            ledger_entry_id = stable_evidence_id(
                "ledge",
                "incremental-evidence-command/v1",
                command.idempotency_key,
                str(index),
                incoming_legacy_id,
            )
            source_candidate_id = (
                f"incremental:{command.command_hash}:{index}:"
                f"{command_row['citation_id']}"
            )
            clue_id = stable_evidence_id(
                "clue", "archive-ledger/v1", source_candidate_id
            )
            entity_kind = (
                "method_or_resource_family"
                if command_row["occurrence_kind"] == "method_or_resource_name"
                else "paper_or_scholarly_work"
            )
            raw_claim = {
                "schema_version": "qrh-incremental-evidence-clue/v1",
                "command_hash": command.command_hash,
                "clue_artifact_urn": command.clue_artifact_urn,
                "occurrence_index": index,
                "incoming_legacy_occurrence_id": incoming_legacy_id,
                "raw_marker_text": command_row["raw_marker_text"],
                "identifier_scheme": scheme,
                "identifier_claim": identifier_claim,
                "identifier_normalized": identifier_normalized,
            }
            occurrence = CitationOccurrenceInput(
                legacy_occurrence_id=ledger_entry_id,
                clue_id=clue_id,
                research_urn=command.research_urn,
                archive_release_urn=command.archive_release_urn,
                document_version_urn=command.document_version_urn,
                source_object_urn=command.source_object_urn,
                document_sha256=source_sha256,
                source_path=command.source_path,
                canonical_path=command.source_path,
                locator_claim=f"line:{command_row['line_start']}",
                locator_kind="utf8_bytes",
                locator=dict(command_row["locator"]),
                line_start=command_row["line_start"],
                line_end=command_row["line_end"],
                byte_start=command_row["byte_start"],
                byte_end=command_row["byte_end"],
                raw_marker_text=command_row["raw_marker_text"],
                context_text=command_row["context_text"],
                occurrence_kind=command_row["occurrence_kind"],
                resolution_status="unresolved",
                status_reason=command_row["status_reason"],
                raw_occurrence_type=(
                    f"strong_identifier_{scheme}"
                    if scheme is not None
                    else str(command_row["occurrence_kind"])
                ),
                candidate_link_method=(
                    "exact_identifier_claim" if scheme is not None else "pending_manual_resolution"
                ),
                evidence_strength=(
                    "strong_claimed_identifier" if scheme is not None else "source_mention"
                ),
                identifier_claim=ledger_identifier,
                ledger_payload={
                    "schema_version": "qrh-incremental-evidence-ledger/v1",
                    "command_hash": command.command_hash,
                    "clue_artifact_urn": command.clue_artifact_urn,
                    "occurrence_index": index,
                    "source_occurrence": dict(command_row),
                },
            )
            if occurrence.citation_id != command_row["citation_id"]:
                raise EvidenceIngestConflict("public citation ID differs from its exact source span")
            if occurrence.raw_marker_sha256 != command_row["raw_marker_sha256"]:
                raise EvidenceIngestConflict("citation marker hash is inconsistent")
            occurrence.verify_source_bytes(source_bytes)
            prepared.append(
                _PreparedOccurrence(
                    clue_id=clue_id,
                    source_candidate_id=source_candidate_id,
                    entity_kind=entity_kind,
                    raw_claim_json=canonical_json(raw_claim),
                    occurrence=occurrence,
                )
            )
        return source_bytes, prepared

    def _persist_occurrence(
        self,
        connection: sqlite3.Connection,
        prepared: _PreparedOccurrence,
        *,
        provenance_urn: str,
        now: str,
    ) -> None:
        occurrence = prepared.occurrence
        clue_fields = (
            "source_candidate_id",
            "entity_kind",
            "domain_category",
            "raw_claim_json",
            "provenance_urn",
            "resolution_status",
        )
        clue_expected = (
            prepared.source_candidate_id,
            prepared.entity_kind,
            None,
            prepared.raw_claim_json,
            provenance_urn,
            "resolution_pending",
        )
        if not self._expect_exact(
            connection,
            table="paper_clue",
            key_name="clue_id",
            key=prepared.clue_id,
            fields=clue_fields,
            expected=clue_expected,
        ):
            connection.execute(
                """
                INSERT INTO paper_clue(
                    clue_id,source_candidate_id,entity_kind,domain_category,raw_claim_json,
                    provenance_urn,resolution_status,created_at
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (prepared.clue_id, *clue_expected, now),
            )

        canonical_reason = "exact UTF-8 source object and half-open byte span verified"
        occurrence_fields = (
            "document_sha256",
            "locator_kind",
            "locator_json",
            "line_start",
            "line_end",
            "byte_start",
            "byte_end",
            "raw_marker_text",
            "raw_marker_sha256",
            "context_text",
            "context_sha256",
            "occurrence_kind",
            "locator_status",
            "status_reason",
        )
        occurrence_expected = (
            occurrence.document_sha256,
            occurrence.locator_kind,
            canonical_json(occurrence.locator),
            occurrence.line_start,
            occurrence.line_end,
            occurrence.byte_start,
            occurrence.byte_end,
            occurrence.raw_marker_text,
            occurrence.raw_marker_sha256,
            occurrence.context_text,
            occurrence.context_sha256,
            occurrence.occurrence_kind,
            "valid",
            canonical_reason,
        )
        if not self._expect_exact(
            connection,
            table="citation_occurrence",
            key_name="citation_id",
            key=occurrence.citation_id,
            fields=occurrence_fields,
            expected=occurrence_expected,
        ):
            connection.execute(
                """
                INSERT INTO citation_occurrence(
                    citation_id,document_sha256,locator_kind,locator_json,line_start,line_end,
                    byte_start,byte_end,raw_marker_text,raw_marker_sha256,context_text,
                    context_sha256,occurrence_kind,locator_status,status_reason,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (occurrence.citation_id, *occurrence_expected, now),
            )

        ledger_fields = (
            "citation_id",
            "clue_id",
            "research_urn",
            "archive_release_urn",
            "document_version_urn",
            "source_object_urn",
            "source_path",
            "canonical_path",
            "locator_claim",
            "occurrence_type",
            "candidate_link_method",
            "evidence_strength",
            "identifier_claim",
            "entry_status",
            "entry_reason",
            "raw_payload_json",
        )
        ledger_expected = (
            occurrence.citation_id,
            occurrence.clue_id,
            occurrence.research_urn,
            occurrence.archive_release_urn,
            occurrence.document_version_urn,
            occurrence.source_object_urn,
            occurrence.source_path,
            occurrence.canonical_path,
            occurrence.locator_claim,
            occurrence.raw_occurrence_type,
            occurrence.candidate_link_method,
            occurrence.evidence_strength,
            occurrence.identifier_claim,
            "unresolved",
            occurrence.status_reason,
            canonical_json(occurrence.ledger_payload),
        )
        if not self._expect_exact(
            connection,
            table="citation_ledger_entry",
            key_name="ledger_entry_id",
            key=occurrence.legacy_occurrence_id,
            fields=ledger_fields,
            expected=ledger_expected,
        ):
            connection.execute(
                """
                INSERT INTO citation_ledger_entry(
                    ledger_entry_id,citation_id,clue_id,research_urn,archive_release_urn,
                    document_version_urn,source_object_urn,source_path,canonical_path,
                    locator_claim,occurrence_type,candidate_link_method,evidence_strength,
                    identifier_claim,entry_status,entry_reason,raw_payload_json,imported_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (occurrence.legacy_occurrence_id, *ledger_expected, now),
            )

        binding_id = stable_evidence_id(
            "bind", occurrence.legacy_occurrence_id, "", "unresolved", provenance_urn
        )
        binding_fields = (
            "ledger_entry_id",
            "paper_id",
            "binding_status",
            "rationale",
            "provenance_urn",
        )
        binding_expected = (
            occurrence.legacy_occurrence_id,
            None,
            "unresolved",
            "增量导入仅确认原文线索与定位；论文身份等待独立核验。",
            provenance_urn,
        )
        if not self._expect_exact(
            connection,
            table="citation_binding",
            key_name="binding_id",
            key=binding_id,
            fields=binding_fields,
            expected=binding_expected,
        ):
            connection.execute(
                """
                INSERT INTO citation_binding(
                    binding_id,ledger_entry_id,paper_id,binding_status,rationale,
                    provenance_urn,created_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (binding_id, *binding_expected, now),
            )
        event_id = stable_evidence_id(
            "bevt", occurrence.legacy_occurrence_id, binding_id, "1"
        )
        event_fields = (
            "ledger_entry_id",
            "binding_id",
            "event_kind",
            "supersedes_event_id",
            "provenance_urn",
        )
        event_expected = (
            occurrence.legacy_occurrence_id,
            binding_id,
            "binding_created",
            None,
            provenance_urn,
        )
        if not self._expect_exact(
            connection,
            table="citation_binding_event",
            key_name="binding_event_id",
            key=event_id,
            fields=event_fields,
            expected=event_expected,
        ):
            connection.execute(
                """
                INSERT INTO citation_binding_event(
                    binding_event_id,ledger_entry_id,binding_id,event_kind,
                    supersedes_event_id,provenance_urn,occurred_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (event_id, *event_expected, now),
            )
        projection = connection.execute(
            "SELECT * FROM citation_binding_projection WHERE ledger_entry_id=?",
            (occurrence.legacy_occurrence_id,),
        ).fetchone()
        projection_expected = (binding_id, event_id, 1)
        if projection is None:
            connection.execute(
                """
                INSERT INTO citation_binding_projection(
                    ledger_entry_id,binding_id,source_event_id,revision,updated_at
                ) VALUES(?,?,?,?,?)
                """,
                (occurrence.legacy_occurrence_id, *projection_expected, now),
            )
        elif self._row_material(
            projection, ("binding_id", "source_event_id", "revision")
        ) != projection_expected:
            raise EvidenceIngestConflict("incremental citation pending projection conflicts")

    @staticmethod
    def _persisted_material(
        connection: sqlite3.Connection, ledger_entry_ids: list[str]
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for ledger_entry_id in sorted(ledger_entry_ids):
            row = connection.execute(
                """
                SELECT ledger.ledger_entry_id,ledger.citation_id,ledger.clue_id,
                       ledger.research_urn,ledger.archive_release_urn,
                       ledger.document_version_urn,ledger.source_object_urn,
                       ledger.source_path,ledger.canonical_path,ledger.locator_claim,
                       ledger.occurrence_type,ledger.candidate_link_method,
                       ledger.evidence_strength,ledger.identifier_claim,
                       ledger.entry_status,ledger.entry_reason,ledger.raw_payload_json,
                       clue.source_candidate_id,clue.entity_kind,clue.domain_category,
                       clue.raw_claim_json,clue.provenance_urn AS clue_provenance_urn,
                       clue.resolution_status AS clue_resolution_status,
                       occurrence.document_sha256,occurrence.locator_kind,
                       occurrence.locator_json,occurrence.line_start,occurrence.line_end,
                       occurrence.byte_start,occurrence.byte_end,occurrence.raw_marker_text,
                       occurrence.raw_marker_sha256,occurrence.context_text,
                       occurrence.context_sha256,occurrence.occurrence_kind,
                       occurrence.locator_status,
                       occurrence.status_reason AS locator_status_reason,
                       binding.binding_id,binding.paper_id,binding.binding_status,
                       binding.rationale,binding.provenance_urn AS binding_provenance_urn,
                       event.binding_event_id,event.event_kind,event.supersedes_event_id,
                       projection.source_event_id,projection.revision
                FROM citation_ledger_entry AS ledger
                JOIN paper_clue AS clue USING(clue_id)
                JOIN citation_occurrence AS occurrence USING(citation_id)
                JOIN citation_binding_projection AS projection USING(ledger_entry_id)
                JOIN citation_binding AS binding USING(binding_id)
                JOIN citation_binding_event AS event
                  ON event.binding_event_id=projection.source_event_id
                WHERE ledger.ledger_entry_id=?
                """,
                (ledger_entry_id,),
            ).fetchone()
            if row is None:
                raise EvidenceIngestConflict("Evidence ingest receipt material is incomplete")
            records.append(dict(row))
        return records

    @classmethod
    def _material_envelope(
        cls, command: EvidenceIngestCommand, records: list[dict[str, Any]]
    ) -> dict[str, Any]:
        outbox_event_id = stable_evidence_id(
            "evt", "evidence-ingest-accepted/v1", command.idempotency_key
        )
        return {
            "schema_version": "qrh-evidence-ingest-material/v1",
            "target_database": "research_papers",
            "command_hash": command.command_hash,
            "inbox_identity": {
                "consumer_name": cls.CONSUMER_NAME,
                "source_domain": cls.SOURCE_DOMAIN,
                "event_id": command.idempotency_key,
            },
            "outbox_identity": {
                "event_id": outbox_event_id,
                "event_type": cls.EVENT_TYPE,
                "event_version": cls.EVENT_VERSION,
                "aggregate_urn": f"qrh:evidence-ingest:{command.idempotency_key}",
            },
            "ledger_records": records,
        }

    def _load_existing(
        self, connection: sqlite3.Connection, command: EvidenceIngestCommand
    ) -> EvidenceDispatchReceipt | None:
        aggregate_urn = f"qrh:evidence-ingest:{command.idempotency_key}"
        receipt_row = connection.execute(
            """
            SELECT result_hash FROM inbox_receipt
            WHERE consumer_name=? AND source_domain=? AND event_id=?
            """,
            (self.CONSUMER_NAME, self.SOURCE_DOMAIN, command.idempotency_key),
        ).fetchone()
        events = connection.execute(
            """
            SELECT * FROM outbox_event
            WHERE event_type=? AND event_version=? AND aggregate_urn=?
            """,
            (self.EVENT_TYPE, self.EVENT_VERSION, aggregate_urn),
        ).fetchall()
        if receipt_row is None and not events:
            return None
        if receipt_row is None or len(events) != 1:
            raise EvidenceIngestConflict("Evidence ingest inbox/outbox pair is incomplete")
        event = events[0]
        payload_json = str(event["payload_json"])
        if event["payload_hash"] != stable_sha256("evidence-outbox/v1", payload_json):
            raise EvidenceIngestConflict("Evidence ingest outbox payload hash is invalid")
        try:
            payload = json.loads(payload_json)
            receipt = EvidenceDispatchReceipt.from_dict(payload["receipt"], created=False)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise EvidenceIngestConflict("Evidence ingest outbox result is invalid") from error
        try:
            receipt.verify(command)
        except Exception as error:
            raise EvidenceIngestConflict(
                "Evidence idempotency key is already bound to another command"
            ) from error
        if (
            payload.get("schema_version") != "qrh-evidence-ingest-result/v1"
            or payload.get("idempotency_key") != command.idempotency_key
            or payload.get("command_hash") != command.command_hash
            or payload.get("archive_event_id") != command.archive_event_id
            or payload.get("result_hash") != receipt.result_hash
            or receipt_row["result_hash"] != receipt.result_hash
        ):
            raise EvidenceIngestConflict("Evidence ingest receipt bindings are inconsistent")
        ledger_entry_ids = payload.get("ledger_entry_ids")
        if not isinstance(ledger_entry_ids, list) or not all(
            isinstance(value, str) for value in ledger_entry_ids
        ):
            raise EvidenceIngestConflict("Evidence ingest result lacks its ledger identities")
        material = self._material_envelope(
            command, self._persisted_material(connection, ledger_entry_ids)
        )
        if sha256_hex(canonical_json(material).encode("utf-8")) != payload.get("material_hash"):
            raise EvidenceIngestConflict("Evidence ingest persisted material has changed")
        return receipt

    def verify_persisted_receipt(
        self,
        *,
        idempotency_key: str,
        expected_result_hash: str,
        expected_child_run_urn: str,
        expected_parent_run_urn: str,
        expected_research_urn: str,
        expected_clue_artifact_urn: str,
    ) -> EvidenceDispatchReceipt:
        """只读重验已完成父任务所引用的目标域收据与全部 ledger 物料。"""

        initialize_evidence_database(self.settings)
        aggregate_urn = f"qrh:evidence-ingest:{idempotency_key}"
        with evidence_connection(self.settings) as connection:
            inbox = connection.execute(
                """
                SELECT result_hash FROM inbox_receipt
                WHERE consumer_name=? AND source_domain=? AND event_id=?
                """,
                (self.CONSUMER_NAME, self.SOURCE_DOMAIN, idempotency_key),
            ).fetchone()
            events = connection.execute(
                """
                SELECT * FROM outbox_event
                WHERE event_type=? AND event_version=? AND aggregate_urn=?
                """,
                (self.EVENT_TYPE, self.EVENT_VERSION, aggregate_urn),
            ).fetchall()
            if inbox is None or len(events) != 1:
                raise EvidenceIngestConflict(
                    "completed parent points to an incomplete Evidence inbox/outbox pair"
                )
            event = events[0]
            payload_json = str(event["payload_json"])
            if event["payload_hash"] != stable_sha256(
                "evidence-outbox/v1", payload_json
            ):
                raise EvidenceIngestConflict("persisted Evidence result hash is invalid")
            try:
                payload = json.loads(payload_json)
                receipt = EvidenceDispatchReceipt.from_dict(
                    payload["receipt"], created=False
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                raise EvidenceIngestConflict(
                    "persisted Evidence result contract is invalid"
                ) from error
            if payload_json != canonical_json(payload):
                raise EvidenceIngestConflict("persisted Evidence result is not canonical")
            expected = (
                "qrh-evidence-ingest-result/v1",
                idempotency_key,
                expected_child_run_urn,
                expected_parent_run_urn,
                expected_research_urn,
                expected_clue_artifact_urn,
                expected_result_hash,
                expected_result_hash,
            )
            actual = (
                payload.get("schema_version"),
                payload.get("idempotency_key"),
                payload.get("child_run_urn"),
                payload.get("parent_run_urn"),
                payload.get("research_urn"),
                payload.get("clue_artifact_urn"),
                payload.get("result_hash"),
                inbox["result_hash"],
            )
            if actual != expected or receipt.result_hash != expected_result_hash:
                raise EvidenceIngestConflict(
                    "persisted Evidence receipt differs from the completed parent"
                )
            ledger_entry_ids = payload.get("ledger_entry_ids")
            if not isinstance(ledger_entry_ids, list) or not all(
                isinstance(value, str) for value in ledger_entry_ids
            ):
                raise EvidenceIngestConflict(
                    "persisted Evidence result lacks ledger identities"
                )
            records = self._persisted_material(connection, ledger_entry_ids)
            material = {
                "schema_version": "qrh-evidence-ingest-material/v1",
                "target_database": "research_papers",
                "command_hash": payload.get("command_hash"),
                "inbox_identity": {
                    "consumer_name": self.CONSUMER_NAME,
                    "source_domain": self.SOURCE_DOMAIN,
                    "event_id": idempotency_key,
                },
                "outbox_identity": {
                    "event_id": str(event["event_id"]),
                    "event_type": self.EVENT_TYPE,
                    "event_version": self.EVENT_VERSION,
                    "aggregate_urn": aggregate_urn,
                },
                "ledger_records": records,
            }
            if sha256_hex(canonical_json(material).encode("utf-8")) != payload.get(
                "material_hash"
            ):
                raise EvidenceIngestConflict(
                    "persisted Evidence target material has drifted after completion"
                )
        return receipt

    @classmethod
    def result_event_id(cls, command: EvidenceIngestCommand) -> str:
        return stable_evidence_id(
            "evt", "evidence-ingest-accepted/v1", command.idempotency_key
        )

    def acknowledge_result(
        self,
        command: EvidenceIngestCommand,
        receipt: EvidenceDispatchReceipt,
    ) -> None:
        """Archive inbox receipt 落库后，单调确认 Evidence result outbox。"""

        receipt.verify(command)
        if receipt.status != "accepted":
            raise EvidenceIngestConflict("only an accepted Evidence result can be acknowledged")
        event_id = self.result_event_id(command)
        with archive_connection(self.settings) as archive:
            source_receipt = archive.execute(
                """
                SELECT result_hash FROM inbox_receipt
                WHERE consumer_name=? AND source_domain='evidence' AND event_id=?
                """,
                (self.RESULT_CONSUMER_NAME, event_id),
            ).fetchone()
        if source_receipt is None or source_receipt["result_hash"] != receipt.result_hash:
            raise EvidenceIngestConflict(
                "Evidence result cannot be acknowledged before its Archive inbox receipt"
            )
        initialize_evidence_database(self.settings)
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            existing = self._load_existing(connection, command)
            if existing is None or existing.result_hash != receipt.result_hash:
                raise EvidenceIngestConflict("Evidence result outbox/receipt pair has drifted")
            updated = connection.execute(
                """
                UPDATE outbox_event
                SET published_at=COALESCE(published_at,?),
                    publish_attempt_count=publish_attempt_count+1
                WHERE event_id=? AND event_type=?
                """,
                (utc_now(), event_id, self.EVENT_TYPE),
            ).rowcount
            if updated != 1:
                raise EvidenceIngestConflict("Evidence result outbox event is missing")

    def dispatch(self, command: EvidenceIngestCommand) -> EvidenceDispatchReceipt:
        _, prepared = self._load_and_validate(command)
        initialize_evidence_database(self.settings)
        provenance_urn = f"qrh:evidence-ingest-command:sha256:{command.command_hash}"
        aggregate_urn = f"qrh:evidence-ingest:{command.idempotency_key}"
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            existing = self._load_existing(connection, command)
            if existing is not None:
                return existing
            prior = connection.execute(
                """
                SELECT payload_json FROM outbox_event
                WHERE event_type=? AND event_version=?
                  AND (
                    json_extract(payload_json,'$.archive_event_id')=?
                    OR json_extract(payload_json,'$.command_hash')=?
                  )
                """,
                (self.EVENT_TYPE, self.EVENT_VERSION, command.archive_event_id, command.command_hash),
            ).fetchall()
            if prior:
                raise EvidenceIngestConflict(
                    "archive event or command hash is already bound to another idempotency key"
                )

            now = utc_now()
            for occurrence in prepared:
                self._persist_occurrence(
                    connection, occurrence, provenance_urn=provenance_urn, now=now
                )
            ledger_entry_ids = sorted(
                occurrence.occurrence.legacy_occurrence_id for occurrence in prepared
            )
            material = self._material_envelope(
                command, self._persisted_material(connection, ledger_entry_ids)
            )
            material_hash = sha256_hex(canonical_json(material).encode("utf-8"))
            state = "pending_resolution" if prepared else "no_clues"
            receipt = EvidenceDispatchReceipt.create(
                command,
                status="accepted",
                detail=(
                    "Evidence 目标域已事务持久化；"
                    f"state={state};clues={len(prepared)};"
                    f"ledger_entries={len(prepared)};material_sha256={material_hash}"
                ),
            )
            receipt_payload = receipt.to_dict()
            receipt_payload.pop("created", None)
            result_payload = {
                "schema_version": "qrh-evidence-ingest-result/v1",
                "idempotency_key": command.idempotency_key,
                "command_hash": command.command_hash,
                "child_run_urn": command.child_run_urn,
                "parent_run_urn": command.parent_run_urn,
                "archive_event_id": command.archive_event_id,
                "research_urn": command.research_urn,
                "clue_artifact_urn": command.clue_artifact_urn,
                "state": state,
                "clue_count": len(prepared),
                "ledger_entry_count": len(prepared),
                "ledger_entry_ids": ledger_entry_ids,
                "material_hash": material_hash,
                "result_hash": receipt.result_hash,
                "receipt": receipt_payload,
            }
            result_json = canonical_json(result_payload)
            event_id = stable_evidence_id(
                "evt", "evidence-ingest-accepted/v1", command.idempotency_key
            )
            connection.execute(
                """
                INSERT INTO outbox_event(
                    event_id,event_type,event_version,aggregate_urn,payload_json,
                    payload_hash,created_at,published_at,publish_attempt_count
                ) VALUES(?,?,?,?,?,?,?,NULL,0)
                """,
                (
                    event_id,
                    self.EVENT_TYPE,
                    self.EVENT_VERSION,
                    aggregate_urn,
                    result_json,
                    stable_sha256("evidence-outbox/v1", result_json),
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO inbox_receipt(
                    consumer_name,source_domain,event_id,processed_at,result_hash
                ) VALUES(?,?,?,?,?)
                """,
                (
                    self.CONSUMER_NAME,
                    self.SOURCE_DOMAIN,
                    command.idempotency_key,
                    now,
                    receipt.result_hash,
                ),
            )
        receipt.verify(command)
        return receipt
