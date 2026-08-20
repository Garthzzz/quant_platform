from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any

from quant_hub.config import Settings
from quant_hub.ids import sha256_hex, stable_sha256
from quant_hub.platform.db import immediate_transaction, utc_now
from quant_hub.platform.releases import (
    ReleaseAuthority,
    ReleaseCandidateSpec,
    ReleaseCertificate,
    ReleaseCertificateMismatch,
)
from quant_hub.platform.workflow import canonical_json

from .database import evidence_connection
from .export import InventoryExport, export_candidate_inventory, export_inventory
from .ids import stable_evidence_id
from .repository import EvidenceConflict, EvidenceRepository


@dataclass(frozen=True, slots=True)
class PreparedEvidenceRelease:
    evidence_release_id: str
    candidate_spec: ReleaseCandidateSpec
    inventory: InventoryExport
    candidate_inventory: InventoryExport
    created: bool


@dataclass(frozen=True, slots=True)
class PublishedEvidenceRelease:
    evidence_release_id: str
    activation_id: str
    active_revision: int
    release_snapshot_urn: str
    created: bool


def _row_hash(row: Any) -> str:
    return sha256_hex(canonical_json(dict(row)).encode("utf-8"))


class EvidenceReleaseService:
    """冻结 Evidence 物料并消费 platform authority 的逐字段 PASS 证书。"""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.repository = EvidenceRepository(settings)

    def _manifest_items(
        self,
        inventory: InventoryExport,
        candidate_inventory: InventoryExport,
    ) -> list[dict[str, object]]:
        items: list[dict[str, object]] = []
        with evidence_connection(self.settings) as connection:
            for row in connection.execute(
                "SELECT paper_id,canonical_urn,creation_event_id FROM paper ORDER BY paper_id"
            ):
                items.append(
                    {
                        "item_kind": "paper",
                        "item_urn": str(row["canonical_urn"]),
                        "item_hash": _row_hash(row),
                    }
                )
            for row in connection.execute(
                """
                SELECT ledger.ledger_entry_id,occurrence.citation_id,
                       occurrence.document_sha256,occurrence.locator_kind,
                       occurrence.byte_start,occurrence.byte_end,
                       occurrence.raw_marker_sha256,ledger.entry_status
                FROM citation_ledger_entry AS ledger
                JOIN citation_occurrence AS occurrence USING(citation_id)
                ORDER BY ledger.ledger_entry_id
                """
            ):
                items.append(
                    {
                        "item_kind": "citation",
                        "item_urn": f"qrh:evidence:citation-entry:{row['ledger_entry_id']}",
                        "item_hash": _row_hash(row),
                    }
                )
            for row in connection.execute(
                """
                SELECT resource_id,paper_id,candidate_id,content_sha256,bytes,relative_path,
                       rights_status,verification_status
                FROM paper_resource ORDER BY resource_id
                """
            ):
                items.append(
                    {
                        "item_kind": "resource",
                        "item_urn": f"qrh:evidence:resource:{row['resource_id']}",
                        "item_hash": _row_hash(row),
                    }
                )
            fetch_rows = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT fetch_attempt_id,source_request_id,subject_urn,paper_id,candidate_id,requested_url,
                           redirect_chain_json,final_url,http_status,response_mime,
                           response_bytes,response_sha256,request_identity_hash,
                           rights_status,legal_basis,result_status,error_class,error_detail
                    FROM fetch_attempt ORDER BY fetch_attempt_id
                    """
                )
            ]
            projection_queries = {
                "import-receipts": """
                    SELECT import_receipt_id,package_schema_version,input_manifest_hash,
                           artifact_manifest_hash,candidate_count,ledger_entry_count,
                           unlinked_entry_count,external_candidate_count,resource_count,
                           validation_status,report_json
                    FROM evidence_import_receipt ORDER BY import_receipt_id
                """,
                "paper-metadata": """
                    SELECT assertion_id,paper_id,candidate_id,field_name,value_json,
                           assertion_status,source_kind,provenance_urn
                    FROM metadata_assertion ORDER BY assertion_id
                """,
                "paper-minimum-field-contract": """
                    SELECT 'category_assertion' AS record_kind,
                           category_assertion_id AS record_id,paper_id,
                           source_categories_json AS payload_json,
                           primary_source_category AS status,
                           mapping_policy_version AS policy,
                           provenance_urn
                    FROM paper_category_assertion
                    UNION ALL
                    SELECT 'core_conclusion',conclusion.conclusion_id,conclusion.paper_id,
                           json_object(
                               'text',conclusion.conclusion_text,
                               'fact_status',conclusion.fact_status,
                               'excerpt_id',evidence.excerpt_id,
                               'claim_scope',evidence.claim_scope
                           ),evidence.verification_status,'',conclusion.provenance_urn
                    FROM paper_core_conclusion AS conclusion
                    JOIN paper_core_conclusion_evidence AS evidence USING(conclusion_id)
                    UNION ALL
                    SELECT 'institution_resolution',institution_resolution_id,paper_id,
                           json_object(
                               'institutions',json(institutions_json),
                               'reason_code',reason_code,
                               'reason_text',reason_text,
                               'checked_source_fields',json(checked_source_fields_json)
                           ),resolution_status,'',provenance_urn
                    FROM paper_institution_resolution
                    UNION ALL
                    SELECT 'reading_conclusion_binding',
                           binding.reading_run_id || ':' || binding.conclusion_id,
                           task.paper_id,
                           json_object(
                               'reading_run_id',binding.reading_run_id,
                               'conclusion_id',binding.conclusion_id,
                               'attempt_number',run.attempt_number,
                               'input_snapshot_hash',run.input_snapshot_hash
                           ),run.result_status,'fulltext-reading-result/v1',
                           binding.provenance_urn
                    FROM paper_reading_conclusion_binding AS binding
                    JOIN paper_reading_run AS run USING(reading_run_id)
                    JOIN paper_reading_task AS task USING(reading_task_id)
                    ORDER BY record_kind,record_id
                """,
                "source-excerpts": """
                    SELECT excerpt_id,paper_id,resource_id,excerpt_text,locator_json,
                           excerpt_sha256,provenance_urn
                    FROM evidence_excerpt ORDER BY excerpt_id
                """,
                "reading-ledger": """
                    SELECT reading_task_id AS record_id,'task' AS record_kind,paper_id,
                           resource_id,abstract_excerpt_id,input_snapshot_hash,
                           objective_text AS payload,required_outputs_json AS result,
                           provenance_urn
                    FROM paper_reading_task
                    UNION ALL
                    SELECT reading_run_id AS record_id,'run' AS record_kind,
                           reading_task_id AS paper_id,NULL AS resource_id,
                           NULL AS abstract_excerpt_id,input_snapshot_hash,
                           coalesce(failure_json,'') AS payload,
                           coalesce(analysis_payload_json,'') AS result,provenance_urn
                    FROM paper_reading_run
                    ORDER BY record_kind,record_id
                """,
                "research-relations": """
                    SELECT relation_id,research_urn,document_version_urn,ledger_entry_id,
                           citation_id,paper_id,relation_kind,provenance_urn
                    FROM research_paper_relation ORDER BY relation_id
                """,
                "catalog": """
                    SELECT paper_id,title,publication_date,authors_json,institutions_json,
                           categories_json,core_conclusions_json,external_links_json,
                           local_resources_json,verification_status,projection_revision
                    FROM paper_catalog_projection ORDER BY paper_id
                """,
                "resolution-cases": """
                    SELECT resolution_case_id,candidate_id,input_snapshot_hash,
                           input_claim_json,policy_version,provenance_urn
                    FROM evidence_resolution_case ORDER BY resolution_case_id
                """,
                "resolution-events": """
                    SELECT resolution_event_id,resolution_case_id,idempotency_key,
                           event_kind,from_state,to_state,reason_code,reason_detail,
                           evidence_refs_json
                    FROM evidence_resolution_event ORDER BY resolution_event_id
                """,
                "provider-transports": """
                    SELECT request.provider_request_id,request.resolution_case_id,
                           request.provider,request.operation,request.request_method,
                           request.request_url,request.request_headers_json,
                           request.query_context_json,request.request_fingerprint,
                           attempt.provider_attempt_id,attempt.attempt_number,
                           attempt.idempotency_key,attempt.result_status,
                           attempt.final_url,attempt.redirect_chain_json,
                           attempt.http_status,attempt.response_mime,
                           attempt.response_bytes,attempt.response_sha256,
                           attempt.response_headers_json,
                           attempt.request_identity_hash,attempt.error_class,
                           attempt.error_detail,attempt.provenance_urn
                    FROM evidence_provider_request AS request
                    LEFT JOIN evidence_provider_attempt AS attempt USING(provider_request_id)
                    ORDER BY request.provider_request_id,attempt.attempt_number
                """,
                "provider-observations": """
                    SELECT observation.provider_observation_id,
                           request.resolution_case_id,observation.provider,
                           observation.provider_record_id,observation.provider_rank,
                           observation.provider_score,observation.record_json,
                           observation.record_sha256,observation.metadata_json,
                           observation.normalized_identifiers_json,
                           observation.match_basis,observation.identity_effect,
                           observation.canonicalization_status,observation.rationale,
                           observation.provenance_urn
                    FROM evidence_provider_observation AS observation
                    JOIN evidence_provider_attempt AS attempt USING(provider_attempt_id)
                    JOIN evidence_provider_request AS request USING(provider_request_id)
                    ORDER BY observation.provider_observation_id
                """,
                "identity-decisions": """
                    SELECT identity_decision_id,resolution_case_id,
                           provider_observation_id,decision_kind,identifier_scheme,
                           normalized_identifier,authority_kind,policy_version,
                           rationale,evidence_refs_json,canonicalization_effect,
                           provenance_urn
                    FROM evidence_identity_decision ORDER BY identity_decision_id
                """,
                "resource-rights": """
                    SELECT offer.resource_offer_id,offer.provider_observation_id,
                           offer.provider,offer.resource_kind,offer.source_kind,
                           offer.url,offer.media_type,offer.rights_hint,
                           offer.license_evidence_json,offer.canonicalization_effect,
                           rights.rights_assessment_id,rights.decision,
                           rights.rights_status,rights.authority_kind,
                           rights.policy_version,rights.legal_basis,
                           rights.evidence_json,rights.supersedes_assessment_id,
                           rights.provenance_urn
                    FROM evidence_resource_offer AS offer
                    LEFT JOIN evidence_rights_assessment AS rights USING(resource_offer_id)
                    ORDER BY offer.resource_offer_id,rights.rights_assessment_id
                """,
                "acquisition-workflow": """
                    SELECT acquisition.acquisition_case_id,
                           acquisition.resource_offer_id,
                           acquisition.rights_assessment_id,
                           acquisition.input_snapshot_hash,state.state,state.revision,
                           state.source_event_id,acquisition.provenance_urn
                    FROM evidence_acquisition_case AS acquisition
                    JOIN evidence_acquisition_state AS state USING(acquisition_case_id)
                    ORDER BY acquisition.acquisition_case_id
                """,
                "acquisition-events": """
                    SELECT acquisition_event_id,acquisition_case_id,idempotency_key,
                           event_kind,from_state,to_state,fetch_attempt_id,resource_id,
                           reason_code,reason_detail,evidence_refs_json
                    FROM evidence_acquisition_event ORDER BY acquisition_event_id
                """,
                "method-origin-derivations": """
                    SELECT derivation_id,original_source_candidate_id,
                           derived_source_candidate_id,derived_candidate_id,
                           identifier_scheme,normalized_identifier,rationale,provenance_urn
                    FROM evidence_method_origin_candidate_derivation
                    ORDER BY derivation_id
                """,
                "reviewed-canonicalization": """
                    SELECT receipt.canonicalization_receipt_id,
                           receipt.manifest_schema_version,receipt.manifest_sha256,
                           receipt.item_key,receipt.item_material_sha256,
                           receipt.idempotency_key,receipt.treatment,
                           receipt.source_candidate_id,receipt.paper_source_candidate_id,
                           receipt.resolution_case_id,receipt.identity_decision_id,
                           receipt.paper_id,receipt.resource_mode,
                           receipt.result_material_sha256,receipt.provenance_urn,
                           state.state,state.revision,state.source_event_id
                    FROM evidence_canonicalization_receipt AS receipt
                    JOIN evidence_canonicalization_state AS state
                      USING(canonicalization_receipt_id)
                    ORDER BY receipt.canonicalization_receipt_id
                """,
                "canonicalization-events": """
                    SELECT canonicalization_event_id,canonicalization_receipt_id,
                           event_sequence,event_kind,entity_urn,payload_json,payload_sha256
                    FROM evidence_canonicalization_event
                    ORDER BY canonicalization_receipt_id,event_sequence
                """,
                "canonical-resource-attachments": """
                    SELECT resource_attachment_id,canonicalization_receipt_id,
                           resolution_case_id,paper_id,resource_id,provenance_urn
                    FROM evidence_canonical_resource_attachment
                    ORDER BY resource_attachment_id
                """,
                "associated-method-relations": """
                    SELECT associated_relation_id,canonicalization_receipt_id,
                           source_candidate_id,ledger_entry_id,citation_id,paper_id,
                           association_kind,rationale,provenance_urn
                    FROM evidence_associated_method_relation
                    ORDER BY associated_relation_id
                """,
                "fulltext-conclusion-support": """
                    SELECT conclusion_id,resource_id,page_number,page_text_sha256,
                           support_text_sha256,locator_json,verification_status,
                           provenance_urn
                    FROM evidence_fulltext_conclusion_support ORDER BY conclusion_id
                """,
            }
            projection_rows = {
                name: [dict(row) for row in connection.execute(query)]
                for name, query in projection_queries.items()
            }
        if fetch_rows:
            items.append(
                {
                    "item_kind": "fetch_ledger",
                    "item_urn": "qrh:evidence:fetch-ledger:v1",
                    "item_hash": sha256_hex(
                        canonical_json(fetch_rows).encode("utf-8")
                    ),
                }
            )
        for name, rows in sorted(projection_rows.items()):
            items.append(
                {
                    "item_kind": "catalog_projection",
                    "item_urn": f"qrh:evidence:projection:{name}:v1",
                    "item_hash": sha256_hex(canonical_json(rows).encode("utf-8")),
                }
            )
        items.append(
            {
                "item_kind": "inventory_export",
                "item_urn": f"qrh:evidence:inventory:{inventory.export_id}",
                "item_hash": inventory.content_sha256,
            }
        )
        items.append(
            {
                "item_kind": "inventory_export",
                "item_urn": (
                    f"qrh:evidence:candidate-inventory:{candidate_inventory.export_id}"
                ),
                "item_hash": candidate_inventory.content_sha256,
            }
        )
        return sorted(items, key=lambda item: (str(item["item_kind"]), str(item["item_urn"])))

    def prepare_candidate(
        self, *, subject_urn: str = "qrh:evidence:archive-research-papers"
    ) -> PreparedEvidenceRelease:
        self.repository.initialize()
        inventory = export_inventory(self.settings)
        candidate_inventory = export_candidate_inventory(self.settings)
        source_snapshot_hash = self.repository.snapshot_hash()
        items = self._manifest_items(inventory, candidate_inventory)
        manifest = {
            "schema_version": "qrh-evidence-release-manifest/v1",
            "subject_urn": subject_urn,
            "source_snapshot_hash": source_snapshot_hash,
            "inventory": {
                "export_id": inventory.export_id,
                "content_sha256": inventory.content_sha256,
                "bytes": inventory.bytes,
            },
            "candidate_inventory": {
                "export_id": candidate_inventory.export_id,
                "content_sha256": candidate_inventory.content_sha256,
                "bytes": candidate_inventory.bytes,
            },
            "items": items,
        }
        artifact_manifest_hash = sha256_hex(
            canonical_json(manifest).encode("utf-8")
        )
        projection_revision = stable_sha256(
            "evidence-projection/v1",
            source_snapshot_hash,
            inventory.content_sha256,
            candidate_inventory.content_sha256,
        )
        requirements_manifest_hash = stable_sha256(
            "evidence-release-requirements/v1",
            "exact-archive-byte-spans",
            "event-only-strong-identifiers",
            "complete-fetch-audit",
            "verified-content-addressed-resources",
            "source-bounded-exact-abstracts",
            "source-bounded-paper-categories",
            "verbatim-abstract-source-claims",
            "explicit-institution-resolution",
            "recoverable-append-only-reading-ledger",
            "traceable-archive-paper-relations",
            "provider-observations-never-auto-canonicalize",
            "explicit-identity-decision-events",
            "explicit-rights-assessment-before-fetch",
            "recoverable-resolution-and-acquisition-state-machines",
            "reviewed-canonicalization-receipt-before-catalog-projection",
            "formal-citation-and-associated-method-origin-semantic-separation",
            "distinct-derived-paper-candidate-for-rejected-method-clues",
            "source-category-to-broad-taxonomy-mapping-with-provenance",
            "catalog-resource-attachment-and-public-coverage-consistency",
            "per-conclusion-fulltext-page-and-text-hash-support",
            "deterministic-inventory",
            "one-row-per-candidate-status-inventory",
            "platform-pass-certificate",
        )
        spec = ReleaseCandidateSpec(
            domain="evidence",
            subject_urn=subject_urn,
            subject_version_urn=(
                f"qrh:evidence-release:{sha256_hex(subject_urn.encode('utf-8'))}:"
                f"sha256:{artifact_manifest_hash}"
            ),
            artifact_manifest_hash=artifact_manifest_hash,
            source_snapshot_hash=source_snapshot_hash,
            requirements_manifest_hash=requirements_manifest_hash,
            projection_revision=projection_revision,
        )
        release_id = stable_evidence_id(
            "erel", subject_urn, artifact_manifest_hash
        )
        expected = (
            subject_urn,
            spec.subject_version_urn,
            artifact_manifest_hash,
            source_snapshot_hash,
            requirements_manifest_hash,
            projection_revision,
        )
        fields = (
            "subject_urn",
            "subject_version_urn",
            "artifact_manifest_hash",
            "source_snapshot_hash",
            "requirements_manifest_hash",
            "projection_revision",
        )
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            row = connection.execute(
                "SELECT * FROM evidence_release WHERE evidence_release_id=?",
                (release_id,),
            ).fetchone()
            created = row is None
            if row is None:
                connection.execute(
                    """
                    INSERT INTO evidence_release(
                        evidence_release_id,subject_urn,subject_version_urn,
                        artifact_manifest_hash,source_snapshot_hash,
                        requirements_manifest_hash,projection_revision,
                        candidate_status,created_at
                    ) VALUES(?,?,?,?,?,?,?,'staging',?)
                    """,
                    (release_id, *expected, utc_now()),
                )
                for ordinal, item in enumerate(items):
                    connection.execute(
                        """
                        INSERT INTO evidence_release_item(
                            evidence_release_id,item_kind,item_urn,item_hash,ordinal,created_at
                        ) VALUES(?,?,?,?,?,?)
                        """,
                        (
                            release_id,
                            item["item_kind"],
                            item["item_urn"],
                            item["item_hash"],
                            ordinal,
                            utc_now(),
                        ),
                    )
            else:
                if tuple(row[field] for field in fields) != expected:
                    raise EvidenceConflict("stable Evidence release material conflicts")
                actual_items = [
                    (str(item["item_kind"]), str(item["item_urn"]), str(item["item_hash"]), int(item["ordinal"]))
                    for item in connection.execute(
                        """
                        SELECT item_kind,item_urn,item_hash,ordinal
                        FROM evidence_release_item
                        WHERE evidence_release_id=? ORDER BY ordinal
                        """,
                        (release_id,),
                    )
                ]
                expected_items = [
                    (str(item["item_kind"]), str(item["item_urn"]), str(item["item_hash"]), ordinal)
                    for ordinal, item in enumerate(items)
                ]
                if actual_items != expected_items:
                    raise EvidenceConflict("Evidence release item set is incomplete or conflicting")
        return PreparedEvidenceRelease(
            release_id, spec, inventory, candidate_inventory, created
        )

    def publish(
        self,
        prepared: PreparedEvidenceRelease,
        certificate: ReleaseCertificate,
    ) -> PublishedEvidenceRelease:
        if certificate.spec != prepared.candidate_spec:
            raise ReleaseCertificateMismatch(
                "platform certificate does not match the prepared Evidence candidate"
            )
        verified = ReleaseAuthority(self.settings).verify_snapshot(
            certificate.snapshot_urn,
            certificate.decision_hash,
            prepared.candidate_spec,
        )
        if verified.candidate_id != certificate.candidate_id or verified.decision_id != certificate.decision_id:
            raise ReleaseCertificateMismatch("platform certificate identity changed during verification")
        certificate_payload = {
            "snapshot_urn": certificate.snapshot_urn,
            "candidate_id": certificate.candidate_id,
            "decision_id": certificate.decision_id,
            "decision_hash": certificate.decision_hash,
            "domain": certificate.spec.domain,
            "subject_urn": certificate.spec.subject_urn,
            "subject_version_urn": certificate.spec.subject_version_urn,
            "artifact_manifest_hash": certificate.spec.artifact_manifest_hash,
            "source_snapshot_hash": certificate.spec.source_snapshot_hash,
            "requirements_manifest_hash": certificate.spec.requirements_manifest_hash,
            "projection_revision": certificate.spec.projection_revision,
            "issuance_key": certificate.issuance_key,
            "issued_at": certificate.issued_at,
        }
        payload_hash = sha256_hex(canonical_json(certificate_payload).encode("utf-8"))
        receipt_id = stable_evidence_id(
            "cert", certificate.snapshot_urn, payload_hash
        )
        activation_id = stable_evidence_id(
            "eact", certificate.snapshot_urn, prepared.evidence_release_id
        )
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            release = connection.execute(
                "SELECT * FROM evidence_release WHERE evidence_release_id=?",
                (prepared.evidence_release_id,),
            ).fetchone()
            if release is None:
                raise EvidenceConflict("prepared Evidence release disappeared")
            actual_spec = ReleaseCandidateSpec(
                domain="evidence",
                subject_urn=str(release["subject_urn"]),
                subject_version_urn=str(release["subject_version_urn"]),
                artifact_manifest_hash=str(release["artifact_manifest_hash"]),
                source_snapshot_hash=str(release["source_snapshot_hash"]),
                requirements_manifest_hash=str(release["requirements_manifest_hash"]),
                projection_revision=str(release["projection_revision"]),
            )
            if actual_spec != prepared.candidate_spec:
                raise EvidenceConflict("stored Evidence candidate differs from reviewed material")

            existing_activation = connection.execute(
                "SELECT * FROM evidence_release_activation WHERE activation_id=?",
                (activation_id,),
            ).fetchone()
            active = connection.execute(
                "SELECT * FROM active_evidence_release WHERE subject_urn=?",
                (prepared.candidate_spec.subject_urn,),
            ).fetchone()
            if existing_activation is not None:
                if active is None or active["activation_id"] != activation_id:
                    raise EvidenceConflict(
                        "an old Evidence certificate cannot silently replace the active release"
                    )
                return PublishedEvidenceRelease(
                    prepared.evidence_release_id,
                    activation_id,
                    int(active["revision"]),
                    certificate.snapshot_urn,
                    False,
                )

            status = str(release["candidate_status"])
            if status == "staging":
                for next_status in ("validated", "under_review", "releasable"):
                    connection.execute(
                        "UPDATE evidence_release SET candidate_status=? WHERE evidence_release_id=?",
                        (next_status, prepared.evidence_release_id),
                    )
                status = "releasable"
            if status not in {"releasable", "released"}:
                raise EvidenceConflict(
                    f"Evidence release cannot consume a certificate from status {status!r}"
                )

            connection.execute(
                """
                INSERT INTO platform_certificate_receipt(
                    certificate_receipt_id,evidence_release_id,release_snapshot_urn,
                    platform_candidate_id,platform_decision_id,decision_hash,verdict,
                    domain,subject_urn,subject_version_urn,artifact_manifest_hash,
                    source_snapshot_hash,requirements_manifest_hash,projection_revision,
                    certificate_payload_hash,received_at
                ) VALUES(?,?,?,?,?,?,'pass','evidence',?,?,?,?,?,?,?,?)
                """,
                (
                    receipt_id,
                    prepared.evidence_release_id,
                    certificate.snapshot_urn,
                    certificate.candidate_id,
                    certificate.decision_id,
                    certificate.decision_hash,
                    certificate.spec.subject_urn,
                    certificate.spec.subject_version_urn,
                    certificate.spec.artifact_manifest_hash,
                    certificate.spec.source_snapshot_hash,
                    certificate.spec.requirements_manifest_hash,
                    certificate.spec.projection_revision,
                    payload_hash,
                    utc_now(),
                ),
            )
            predecessor = str(active["activation_id"]) if active is not None else None
            now = utc_now()
            connection.execute(
                """
                INSERT INTO evidence_release_activation(
                    activation_id,subject_urn,evidence_release_id,certificate_receipt_id,
                    release_snapshot_urn,decision_hash,activated_at,supersedes_activation_id
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    activation_id,
                    certificate.spec.subject_urn,
                    prepared.evidence_release_id,
                    receipt_id,
                    certificate.snapshot_urn,
                    certificate.decision_hash,
                    now,
                    predecessor,
                ),
            )
            if active is None:
                revision = 1
                connection.execute(
                    """
                    INSERT INTO active_evidence_release(
                        subject_urn,activation_id,evidence_release_id,
                        release_snapshot_urn,revision
                    ) VALUES(?,?,?,?,1)
                    """,
                    (
                        certificate.spec.subject_urn,
                        activation_id,
                        prepared.evidence_release_id,
                        certificate.snapshot_urn,
                    ),
                )
            else:
                revision = int(active["revision"]) + 1
                connection.execute(
                    """
                    UPDATE active_evidence_release
                    SET activation_id=?,evidence_release_id=?,release_snapshot_urn=?,revision=?
                    WHERE subject_urn=?
                    """,
                    (
                        activation_id,
                        prepared.evidence_release_id,
                        certificate.snapshot_urn,
                        revision,
                        certificate.spec.subject_urn,
                    ),
                )
            connection.execute(
                "UPDATE evidence_release SET candidate_status='released' WHERE evidence_release_id=?",
                (prepared.evidence_release_id,),
            )
            event_payload = canonical_json(
                {
                    "activation_id": activation_id,
                    "evidence_release_id": prepared.evidence_release_id,
                    "release_snapshot_urn": certificate.snapshot_urn,
                    "revision": revision,
                    "subject_urn": certificate.spec.subject_urn,
                }
            )
            connection.execute(
                """
                INSERT INTO outbox_event(
                    event_id,event_type,event_version,aggregate_urn,payload_json,
                    payload_hash,created_at,published_at,publish_attempt_count
                ) VALUES(?,'EvidenceReleaseActivated','1',?,?,?,?,NULL,0)
                """,
                (
                    stable_evidence_id("evt", "evidence-release-activated/v1", activation_id),
                    certificate.spec.subject_urn,
                    event_payload,
                    stable_sha256("evidence-outbox/v1", event_payload),
                    now,
                ),
            )
        return PublishedEvidenceRelease(
            prepared.evidence_release_id,
            activation_id,
            revision,
            certificate.snapshot_urn,
            True,
        )
