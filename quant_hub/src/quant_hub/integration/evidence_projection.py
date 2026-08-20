from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any

from quant_hub.archive.database import archive_connection, initialize_archive_database
from quant_hub.config import Settings
from quant_hub.evidence.database import evidence_connection, initialize_evidence_database
from quant_hub.ids import new_public_id, sha256_hex, stable_sha256
from quant_hub.platform.db import immediate_transaction, utc_now
from quant_hub.platform.releases import ReleaseAuthority, ReleaseCandidateSpec
from quant_hub.platform.workflow import canonical_json


class EvidenceProjectionError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class EvidenceProjectionUpdate:
    research_urn: str
    research_id: str
    evidence_status: str


@dataclass(frozen=True, slots=True)
class EvidenceProjectionResult:
    event_id: str
    evidence_release_id: str
    release_snapshot_urn: str
    stale_noop: bool
    updates: tuple[EvidenceProjectionUpdate, ...]
    unmapped_research_urns: tuple[str, ...]
    result_hash: str
    created: bool


class EvidenceProjectionConsumer:
    """幂等消费正式 Evidence activation；不接受 staging 或未核验证书。"""

    CONSUMER_NAME = "archive-evidence-projection/v1"

    def __init__(self, settings: Settings):
        self.settings = settings

    @staticmethod
    def _result_from_payload(
        payload: dict[str, Any], result_hash: str, *, created: bool
    ) -> EvidenceProjectionResult:
        return EvidenceProjectionResult(
            event_id=str(payload["event_id"]),
            evidence_release_id=str(payload["evidence_release_id"]),
            release_snapshot_urn=str(payload["release_snapshot_urn"]),
            stale_noop=bool(payload["stale_noop"]),
            updates=tuple(
                EvidenceProjectionUpdate(
                    research_urn=str(row["research_urn"]),
                    research_id=str(row["research_id"]),
                    evidence_status=str(row["evidence_status"]),
                )
                for row in payload["updates"]
            ),
            unmapped_research_urns=tuple(str(value) for value in payload["unmapped_research_urns"]),
            result_hash=result_hash,
            created=created,
        )

    def _load_event(self, event_id: str) -> dict[str, Any]:
        initialize_evidence_database(self.settings)
        with evidence_connection(self.settings) as connection:
            event = connection.execute(
                "SELECT * FROM outbox_event WHERE event_id=?", (event_id,)
            ).fetchone()
            if event is None:
                raise EvidenceProjectionError("Evidence outbox event does not exist")
            if event["event_type"] != "EvidenceReleaseActivated" or event["event_version"] != "1":
                raise EvidenceProjectionError("event is not a supported Evidence activation")
            payload_json = str(event["payload_json"])
            if event["payload_hash"] != stable_sha256("evidence-outbox/v1", payload_json):
                raise EvidenceProjectionError("Evidence activation payload hash is invalid")
            payload = json.loads(payload_json)
            required = {
                "activation_id",
                "evidence_release_id",
                "release_snapshot_urn",
                "revision",
                "subject_urn",
            }
            if not required.issubset(payload):
                raise EvidenceProjectionError("Evidence activation payload is incomplete")
            release = connection.execute(
                "SELECT * FROM evidence_release WHERE evidence_release_id=?",
                (payload["evidence_release_id"],),
            ).fetchone()
            activation = connection.execute(
                """
                SELECT activation.*,receipt.verdict,receipt.domain,
                       receipt.platform_candidate_id,receipt.platform_decision_id,
                       receipt.subject_version_urn AS receipt_subject_version_urn,
                       receipt.artifact_manifest_hash AS receipt_artifact_manifest_hash,
                       receipt.source_snapshot_hash AS receipt_source_snapshot_hash,
                       receipt.requirements_manifest_hash AS receipt_requirements_manifest_hash,
                       receipt.projection_revision AS receipt_projection_revision
                FROM evidence_release_activation AS activation
                JOIN platform_certificate_receipt AS receipt USING(certificate_receipt_id)
                WHERE activation.activation_id=?
                """,
                (payload["activation_id"],),
            ).fetchone()
            active = connection.execute(
                "SELECT * FROM active_evidence_release WHERE subject_urn=?",
                (payload["subject_urn"],),
            ).fetchone()
            if release is None or activation is None or active is None:
                raise EvidenceProjectionError(
                    "activation lacks a formal release, PASS receipt, or active subject chain"
                )
            if release["candidate_status"] != "released":
                raise EvidenceProjectionError("staging/non-released Evidence material cannot upgrade Archive")
            if activation["verdict"] != "pass" or activation["domain"] != "evidence":
                raise EvidenceProjectionError("Evidence activation receipt is not a domain PASS")
            actual = (
                str(activation["evidence_release_id"]),
                str(activation["release_snapshot_urn"]),
                str(activation["subject_urn"]),
            )
            expected = (
                str(payload["evidence_release_id"]),
                str(payload["release_snapshot_urn"]),
                str(payload["subject_urn"]),
            )
            if actual != expected:
                raise EvidenceProjectionError("Evidence event and activation identity differ")
            spec = ReleaseCandidateSpec(
                domain="evidence",
                subject_urn=str(release["subject_urn"]),
                subject_version_urn=str(release["subject_version_urn"]),
                artifact_manifest_hash=str(release["artifact_manifest_hash"]),
                source_snapshot_hash=str(release["source_snapshot_hash"]),
                requirements_manifest_hash=str(release["requirements_manifest_hash"]),
                projection_revision=str(release["projection_revision"]),
            )
            receipt_material = (
                str(activation["receipt_subject_version_urn"]),
                str(activation["receipt_artifact_manifest_hash"]),
                str(activation["receipt_source_snapshot_hash"]),
                str(activation["receipt_requirements_manifest_hash"]),
                str(activation["receipt_projection_revision"]),
            )
            if receipt_material != (
                spec.subject_version_urn,
                spec.artifact_manifest_hash,
                spec.source_snapshot_hash,
                spec.requirements_manifest_hash,
                spec.projection_revision,
            ):
                raise EvidenceProjectionError("Evidence certificate receipt differs from release material")
            current = str(active["activation_id"]) == str(payload["activation_id"])
            if current and int(active["revision"]) != int(payload["revision"]):
                raise EvidenceProjectionError("current Evidence activation revision is inconsistent")
            if not current and int(active["revision"]) <= int(payload["revision"]):
                raise EvidenceProjectionError("out-of-order Evidence event is not an older activation")
            research_rows = connection.execute(
                """
                SELECT ledger.research_urn,
                       max(CASE WHEN ledger.entry_status='conflicted' THEN 1 ELSE 0 END)
                           AS ledger_conflicted,
                       max(CASE WHEN catalog.verification_status='conflicted' THEN 1 ELSE 0 END)
                           AS catalog_conflicted
                FROM evidence_release_item AS item
                JOIN citation_ledger_entry AS ledger
                  ON item.item_kind='citation'
                 AND item.item_urn='qrh:evidence:citation-entry:' || ledger.ledger_entry_id
                LEFT JOIN research_paper_relation AS relation
                  ON relation.ledger_entry_id=ledger.ledger_entry_id
                LEFT JOIN paper_catalog_projection AS catalog
                  ON catalog.paper_id=relation.paper_id
                WHERE item.evidence_release_id=?
                GROUP BY ledger.research_urn
                ORDER BY ledger.research_urn
                """,
                (payload["evidence_release_id"],),
            ).fetchall()
            return {
                "event_id": event_id,
                "event_payload_hash": str(event["payload_hash"]),
                "payload": payload,
                "release": dict(release),
                "activation": dict(activation),
                "spec": spec,
                "current": current,
                "research_rows": [dict(row) for row in research_rows],
            }

    def _mark_delivered(self, event_id: str) -> None:
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            connection.execute(
                """
                UPDATE outbox_event
                SET published_at=COALESCE(published_at,?),
                    publish_attempt_count=publish_attempt_count+1
                WHERE event_id=?
                """,
                (utc_now(), event_id),
            )

    @staticmethod
    def _source_material_hash(material: dict[str, Any], certificate: Any) -> str:
        payload = material["payload"]
        activation = material["activation"]
        spec: ReleaseCandidateSpec = material["spec"]
        committed = {
            "schema_version": "qrh-evidence-projection-source/v1",
            "event_id": material["event_id"],
            "event_payload_hash": material["event_payload_hash"],
            "activation_id": str(payload["activation_id"]),
            "evidence_release_id": str(payload["evidence_release_id"]),
            "release_snapshot_urn": str(payload["release_snapshot_urn"]),
            "subject_urn": str(payload["subject_urn"]),
            "evidence_revision": int(payload["revision"]),
            "candidate_id": str(certificate.candidate_id),
            "decision_id": str(certificate.decision_id),
            "decision_hash": str(activation["decision_hash"]),
            "subject_version_urn": spec.subject_version_urn,
            "artifact_manifest_hash": spec.artifact_manifest_hash,
            "source_snapshot_hash": spec.source_snapshot_hash,
            "requirements_manifest_hash": spec.requirements_manifest_hash,
            "projection_revision": spec.projection_revision,
            "research_rows": material["research_rows"],
        }
        return sha256_hex(canonical_json(committed).encode("utf-8"))

    @staticmethod
    def _expected_projection_rows(
        connection: Any, material: dict[str, Any]
    ) -> tuple[list[dict[str, str]], list[str]]:
        updates: list[dict[str, str]] = []
        unmapped: list[str] = []
        for row in material["research_rows"]:
            research_urn = str(row["research_urn"])
            prefix = "qrh:archive-research:"
            if not research_urn.startswith(prefix):
                unmapped.append(research_urn)
                continue
            slug = research_urn[len(prefix) :]
            archive_row = connection.execute(
                """
                SELECT research.research_id,status.research_id AS status_research_id
                FROM research
                LEFT JOIN research_status_projection AS status USING(research_id)
                WHERE research.canonical_slug=?
                """,
                (slug,),
            ).fetchone()
            if archive_row is None or archive_row["status_research_id"] is None:
                unmapped.append(research_urn)
                continue
            evidence_status = (
                "conflicted"
                if int(row["ledger_conflicted"] or 0)
                or int(row["catalog_conflicted"] or 0)
                else "passed"
            )
            updates.append(
                {
                    "research_urn": research_urn,
                    "research_id": str(archive_row["research_id"]),
                    "evidence_status": evidence_status,
                }
            )
        return (
            sorted(updates, key=lambda row: row["research_urn"]),
            sorted(unmapped),
        )

    def _validate_cached_result(
        self,
        connection: Any,
        *,
        material: dict[str, Any],
        source_material_hash: str,
        result_event: Any,
        receipt_hash: str,
    ) -> EvidenceProjectionResult:
        payload_json = str(result_event["payload_json"])
        if (
            result_event["event_type"] != "ArchiveEvidenceProjectionUpdated"
            or result_event["event_version"] != "1"
            or result_event["payload_hash"]
            != stable_sha256("archive-outbox/v1", payload_json)
        ):
            raise EvidenceProjectionError("cached Archive projection event material is invalid")
        try:
            payload = json.loads(payload_json)
        except (TypeError, ValueError) as error:
            raise EvidenceProjectionError("cached Archive projection payload is invalid") from error
        if payload_json != canonical_json(payload):
            raise EvidenceProjectionError("cached Archive projection payload is not canonical")
        required_keys = {
            "schema_version",
            "event_id",
            "evidence_release_id",
            "release_snapshot_urn",
            "subject_urn",
            "activation_id",
            "evidence_revision",
            "source_material_hash",
            "stale_noop",
            "updates",
            "unmapped_research_urns",
        }
        if set(payload) != required_keys or payload.get("schema_version") != (
            "qrh-archive-evidence-projection-result/v1"
        ):
            raise EvidenceProjectionError("cached Archive projection result contract is invalid")
        source = material["payload"]
        expected_identity = (
            str(material["event_id"]),
            str(source["evidence_release_id"]),
            str(source["release_snapshot_urn"]),
            str(source["subject_urn"]),
            str(source["activation_id"]),
            int(source["revision"]),
            source_material_hash,
        )
        actual_identity = (
            str(payload["event_id"]),
            str(payload["evidence_release_id"]),
            str(payload["release_snapshot_urn"]),
            str(payload["subject_urn"]),
            str(payload["activation_id"]),
            int(payload["evidence_revision"]),
            str(payload["source_material_hash"]),
        )
        if actual_identity != expected_identity:
            raise EvidenceProjectionError(
                "cached Archive receipt is not bound to the formal Evidence activation"
            )
        result_hash = sha256_hex(payload_json.encode("utf-8"))
        if result_hash != receipt_hash:
            raise EvidenceProjectionError("Archive Evidence receipt hash is inconsistent")
        expected_updates, expected_unmapped = self._expected_projection_rows(
            connection, material
        )
        if bool(payload["stale_noop"]):
            if payload["updates"] or payload["unmapped_research_urns"]:
                raise EvidenceProjectionError("stale cached projection contains side effects")
        elif (
            payload["updates"] != expected_updates
            or payload["unmapped_research_urns"] != expected_unmapped
        ):
            raise EvidenceProjectionError(
                "cached Archive projection rows differ from formal Evidence material"
            )
        superseded = False
        for row in connection.execute(
            """
            SELECT payload_json FROM outbox_event
            WHERE event_type='ArchiveEvidenceProjectionUpdated'
              AND aggregate_urn<>?
            """,
            (f"qrh:evidence-event:{material['event_id']}",),
        ):
            try:
                other = json.loads(str(row["payload_json"]))
            except (TypeError, ValueError):
                continue
            if (
                other.get("subject_urn") == source["subject_urn"]
                and int(other.get("evidence_revision", 0))
                > int(source["revision"])
            ):
                superseded = True
                break
        if not bool(payload["stale_noop"]) and not superseded:
            expected_source = (
                f"qrh:evidence-release-activation:{source['activation_id']}"
            )
            for update in expected_updates:
                applied = connection.execute(
                    """
                    SELECT evidence_status,evidence_source_urn
                    FROM research_status_projection WHERE research_id=?
                    """,
                    (update["research_id"],),
                ).fetchone()
                if applied is None or (
                    applied["evidence_status"], applied["evidence_source_urn"]
                ) != (update["evidence_status"], expected_source):
                    raise EvidenceProjectionError(
                        "cached Archive receipt side effects are absent or have drifted"
                    )
        return self._result_from_payload(payload, result_hash, created=False)

    def consume(self, event_id: str) -> EvidenceProjectionResult:
        material = self._load_event(event_id)
        payload = material["payload"]
        activation = material["activation"]
        spec: ReleaseCandidateSpec = material["spec"]
        certificate = ReleaseAuthority(self.settings).verify_snapshot(
            str(payload["release_snapshot_urn"]),
            str(activation["decision_hash"]),
            spec,
        )
        if (
            certificate.candidate_id != str(activation["platform_candidate_id"])
            or certificate.decision_id != str(activation["platform_decision_id"])
        ):
            raise EvidenceProjectionError(
                "Evidence receipt candidate/decision IDs do not match the platform certificate"
            )
        source_material_hash = self._source_material_hash(material, certificate)
        initialize_archive_database(self.settings)
        aggregate_urn = f"qrh:evidence-event:{event_id}"
        with archive_connection(self.settings) as connection, immediate_transaction(connection):
            receipt = connection.execute(
                """
                SELECT result_hash FROM inbox_receipt
                WHERE consumer_name=? AND source_domain='evidence' AND event_id=?
                """,
                (self.CONSUMER_NAME, event_id),
            ).fetchone()
            if receipt is not None:
                rows = connection.execute(
                    """
                    SELECT * FROM outbox_event
                    WHERE event_type='ArchiveEvidenceProjectionUpdated' AND aggregate_urn=?
                    """,
                    (aggregate_urn,),
                ).fetchall()
                if len(rows) != 1:
                    raise EvidenceProjectionError("Archive Evidence receipt lacks its result event")
                result = self._validate_cached_result(
                    connection,
                    material=material,
                    source_material_hash=source_material_hash,
                    result_event=rows[0],
                    receipt_hash=str(receipt["result_hash"]),
                )
            else:
                updates: list[dict[str, str]] = []
                unmapped: list[str] = []
                prior_revisions = []
                for prior in connection.execute(
                    """
                    SELECT payload_json FROM outbox_event
                    WHERE event_type='ArchiveEvidenceProjectionUpdated'
                    """
                ):
                    prior_payload = json.loads(str(prior["payload_json"]))
                    if prior_payload.get("subject_urn") == payload["subject_urn"]:
                        prior_revisions.append(int(prior_payload.get("evidence_revision", 0)))
                effective_current = bool(material["current"]) and not any(
                    revision >= int(payload["revision"]) for revision in prior_revisions
                )
                if effective_current:
                    for row in material["research_rows"]:
                        research_urn = str(row["research_urn"])
                        prefix = "qrh:archive-research:"
                        if not research_urn.startswith(prefix):
                            unmapped.append(research_urn)
                            continue
                        slug = research_urn[len(prefix) :]
                        archive_row = connection.execute(
                            """
                            SELECT research.research_id,status.research_id AS status_research_id
                            FROM research
                            LEFT JOIN research_status_projection AS status USING(research_id)
                            WHERE research.canonical_slug=?
                            """,
                            (slug,),
                        ).fetchone()
                        if archive_row is None or archive_row["status_research_id"] is None:
                            unmapped.append(research_urn)
                            continue
                        evidence_status = (
                            "conflicted"
                            if int(row["ledger_conflicted"] or 0)
                            or int(row["catalog_conflicted"] or 0)
                            else "passed"
                        )
                        research_id = str(archive_row["research_id"])
                        connection.execute(
                            """
                            UPDATE research_status_projection
                            SET evidence_status=?,evidence_source_urn=?,updated_at=?
                            WHERE research_id=?
                            """,
                            (
                                evidence_status,
                                f"qrh:evidence-release-activation:{payload['activation_id']}",
                                utc_now(),
                                research_id,
                            ),
                        )
                        updates.append(
                            {
                                "research_urn": research_urn,
                                "research_id": research_id,
                                "evidence_status": evidence_status,
                            }
                        )
                result_payload = {
                    "schema_version": "qrh-archive-evidence-projection-result/v1",
                    "event_id": event_id,
                    "evidence_release_id": str(payload["evidence_release_id"]),
                    "release_snapshot_urn": str(payload["release_snapshot_urn"]),
                    "subject_urn": str(payload["subject_urn"]),
                    "activation_id": str(payload["activation_id"]),
                    "evidence_revision": int(payload["revision"]),
                    "source_material_hash": source_material_hash,
                    "stale_noop": not effective_current,
                    "updates": sorted(updates, key=lambda row: row["research_urn"]),
                    "unmapped_research_urns": sorted(unmapped),
                }
                result_json = canonical_json(result_payload)
                result_hash = sha256_hex(result_json.encode("utf-8"))
                connection.execute(
                    """
                    INSERT INTO outbox_event(
                        event_id,event_type,event_version,aggregate_urn,payload_json,
                        payload_hash,created_at,published_at,publish_attempt_count
                    ) VALUES(?,'ArchiveEvidenceProjectionUpdated','1',?,?,?,?,NULL,0)
                    """,
                    (
                        new_public_id("evt"),
                        aggregate_urn,
                        result_json,
                        stable_sha256("archive-outbox/v1", result_json),
                        utc_now(),
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO inbox_receipt(
                        consumer_name,source_domain,event_id,processed_at,result_hash
                    ) VALUES(?,'evidence',?,?,?)
                    """,
                    (self.CONSUMER_NAME, event_id, utc_now(), result_hash),
                )
                result = self._result_from_payload(result_payload, result_hash, created=True)
        self._mark_delivered(event_id)
        return result

    def consume_pending(self) -> tuple[EvidenceProjectionResult, ...]:
        initialize_evidence_database(self.settings)
        with evidence_connection(self.settings) as connection:
            event_ids = [
                str(row["event_id"])
                for row in connection.execute(
                    """
                    SELECT event_id FROM outbox_event
                    WHERE event_type='EvidenceReleaseActivated' AND published_at IS NULL
                    ORDER BY created_at,event_id
                    """
                )
            ]
        return tuple(self.consume(event_id) for event_id in event_ids)
