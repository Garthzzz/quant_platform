from __future__ import annotations

import json

from quant_hub.archive.catalog import ArchiveCatalog
from quant_hub.archive.database import archive_connection
from quant_hub.evidence.contracts import CitationOccurrenceInput
from quant_hub.evidence.database import evidence_connection
from quant_hub.evidence.releases import EvidenceReleaseService
from quant_hub.evidence.repository import EvidenceRepository
from quant_hub.ids import new_public_id, sha256_hex, stable_sha256
from quant_hub.integration.evidence_projection import (
    EvidenceProjectionConsumer,
    EvidenceProjectionError,
)
from quant_hub.integration.incremental_intake import (
    EvidenceDispatchReceipt,
    EvidenceIngestCommand,
    IncrementalIntake,
    IntakeSource,
)
from quant_hub.platform.db import immediate_transaction, utc_now
from quant_hub.platform.releases import ReleaseAuthority
from quant_hub.platform.workflow import canonical_json
from tests.helpers import SettingsTestCase


class AcceptedAdapter:
    def dispatch(self, command: EvidenceIngestCommand) -> EvidenceDispatchReceipt:
        return EvidenceDispatchReceipt.create(command, status="accepted", detail="accepted")


class IncrementalEvidenceProjectionTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.inbox = self.var / "inbox" / "research"
        self.inbox.mkdir(parents=True)
        self.source = self.inbox / "projection.md"
        self.source_bytes = b"# Evidence projection\n\nDOI: 10.7777/projection\n"
        self.source.write_bytes(self.source_bytes)
        report = IncrementalIntake(self.settings, AcceptedAdapter()).scan(
            (IntakeSource("research_inbox", self.inbox),)
        )
        self.assertEqual("PASS", report.status, report.to_dict())
        self.item = report.processed[0]

    def _add_citation(self, ledger_id: str, status: str = "unresolved") -> None:
        marker = "10.7777/projection"
        start = self.source_bytes.index(marker.encode("utf-8"))
        end = start + len(marker.encode("utf-8"))
        digest = sha256_hex(self.source_bytes)
        occurrence = CitationOccurrenceInput(
            legacy_occurrence_id=ledger_id,
            clue_id=None,
            research_urn=f"qrh:archive-research:{self.item.research_slug}",
            archive_release_urn=f"qrh:archive-release:{self.item.research_slug}:auto-{digest[:20]}",
            document_version_urn=f"qrh:archive-document-version:obj_sha256_{digest}",
            source_object_urn=f"qrh:object:obj_sha256_{digest}",
            document_sha256=digest,
            source_path="research_inbox:///projection.md",
            canonical_path="research_inbox:///projection.md",
            locator_claim="line:3",
            locator_kind="utf8_bytes",
            locator={"line": 3, "byte_start": start, "byte_end": end},
            line_start=3,
            line_end=3,
            byte_start=start,
            byte_end=end,
            raw_marker_text=marker,
            context_text="DOI: 10.7777/projection",
            occurrence_kind="strong_identifier",
            resolution_status=status,
            status_reason="test evidence state",
            raw_occurrence_type="strong_identifier_doi",
            candidate_link_method="exact_identifier_claim",
            evidence_strength="strong_claimed_identifier",
            identifier_claim="doi:10.7777/projection",
            ledger_payload={"test": ledger_id},
        )
        EvidenceRepository(self.settings).add_citation(occurrence, self.source_bytes)

    def _publish_evidence(self, label: str):
        prepared = EvidenceReleaseService(self.settings).prepare_candidate()
        authority = ReleaseAuthority(self.settings)
        candidate = authority.register_candidate(prepared.candidate_spec)
        decision = authority.record_decision(
            candidate.candidate_id,
            deterministic_gate_hash=stable_sha256("projection-test-gate/v1", label),
            review_set_hash=stable_sha256("projection-test-review/v1", label),
            reconciliation_hash=stable_sha256("projection-test-reconcile/v1", label),
            verdict="pass",
        )
        certificate = authority.issue_snapshot(
            decision.decision_id,
            requirements_manifest_hash=prepared.candidate_spec.requirements_manifest_hash,
            issuance_key=stable_sha256("projection-test-issuance/v1", label),
        )
        published = EvidenceReleaseService(self.settings).publish(prepared, certificate)
        with evidence_connection(self.settings) as connection:
            event = connection.execute(
                """
                SELECT event_id FROM outbox_event
                WHERE event_type='EvidenceReleaseActivated'
                  AND json_extract(payload_json,'$.activation_id')=?
                """,
                (published.activation_id,),
            ).fetchone()
        return published, str(event["event_id"])

    def test_formal_pass_event_updates_once_and_conflict_is_explicit(self) -> None:
        self._add_citation("ledger-pass")
        _, event_id = self._publish_evidence("pass")
        consumer = EvidenceProjectionConsumer(self.settings)

        first = consumer.consume(event_id)
        replay = consumer.consume(event_id)
        self.assertTrue(first.created)
        self.assertFalse(replay.created)
        self.assertEqual("passed", first.updates[0].evidence_status)
        self.assertEqual(first.result_hash, replay.result_hash)
        page = ArchiveCatalog(self.settings).research_page(self.item.research_id)
        self.assertEqual("passed", page["evidence_status"])
        with archive_connection(self.settings) as connection:
            self.assertEqual(
                1,
                connection.execute(
                    "SELECT count(*) FROM inbox_receipt WHERE consumer_name=? AND event_id=?",
                    (consumer.CONSUMER_NAME, event_id),
                ).fetchone()[0],
            )
        with evidence_connection(self.settings) as connection:
            event = connection.execute(
                "SELECT published_at,publish_attempt_count FROM outbox_event WHERE event_id=?",
                (event_id,),
            ).fetchone()
            self.assertIsNotNone(event["published_at"])
            self.assertEqual(2, event["publish_attempt_count"])

    def test_conflicted_release_never_projects_as_passed(self) -> None:
        self._add_citation("ledger-conflict", "conflicted")
        _, event_id = self._publish_evidence("conflict")
        result = EvidenceProjectionConsumer(self.settings).consume(event_id)
        self.assertEqual("conflicted", result.updates[0].evidence_status)
        self.assertEqual(
            "conflicted",
            ArchiveCatalog(self.settings).research_page(self.item.research_id)["evidence_status"],
        )

    def test_older_activation_arriving_after_newer_one_is_a_traced_noop(self) -> None:
        self._add_citation("ledger-old")
        old_release, old_event = self._publish_evidence("old")
        self._add_citation("ledger-new")
        new_release, new_event = self._publish_evidence("new")
        self.assertEqual(1, old_release.active_revision)
        self.assertEqual(2, new_release.active_revision)

        consumer = EvidenceProjectionConsumer(self.settings)
        newest = consumer.consume(new_event)
        late_old = consumer.consume(old_event)
        self.assertFalse(newest.stale_noop)
        self.assertTrue(late_old.stale_noop)
        self.assertEqual((), late_old.updates)
        page = ArchiveCatalog(self.settings).research_page(self.item.research_id)
        self.assertEqual("passed", page["evidence_status"])
        with archive_connection(self.settings) as connection:
            self.assertEqual(
                2,
                connection.execute(
                    "SELECT count(*) FROM inbox_receipt WHERE consumer_name=?",
                    (consumer.CONSUMER_NAME,),
                ).fetchone()[0],
            )

    def test_staging_or_forged_activation_event_cannot_upgrade_archive(self) -> None:
        self._add_citation("ledger-staging")
        prepared = EvidenceReleaseService(self.settings).prepare_candidate()
        payload_json = canonical_json(
            {
                "activation_id": "eact_missing",
                "evidence_release_id": prepared.evidence_release_id,
                "release_snapshot_urn": "qrh:release_snapshot:missing",
                "revision": 1,
                "subject_urn": prepared.candidate_spec.subject_urn,
            }
        )
        event_id = new_public_id("evt")
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            connection.execute(
                """
                INSERT INTO outbox_event(
                    event_id,event_type,event_version,aggregate_urn,payload_json,
                    payload_hash,created_at,published_at,publish_attempt_count
                ) VALUES(?,'EvidenceReleaseActivated','1',?,?,?,?,NULL,0)
                """,
                (
                    event_id,
                    prepared.candidate_spec.subject_urn,
                    payload_json,
                    stable_sha256("evidence-outbox/v1", payload_json),
                    utc_now(),
                ),
            )
        with self.assertRaises(EvidenceProjectionError):
            EvidenceProjectionConsumer(self.settings).consume(event_id)
        page = ArchiveCatalog(self.settings).research_page(self.item.research_id)
        self.assertEqual("under_review", page["evidence_status"])
        with archive_connection(self.settings) as connection:
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT count(*) FROM inbox_receipt WHERE event_id=?", (event_id,)
                ).fetchone()[0],
            )

    def test_preseeded_forged_archive_receipt_cannot_swallow_real_activation(self) -> None:
        self._add_citation("ledger-forged-cache")
        published, event_id = self._publish_evidence("forged-cache")
        forged = {
            "schema_version": "qrh-archive-evidence-projection-result/v1",
            "event_id": event_id,
            "evidence_release_id": "erel_forged",
            "release_snapshot_urn": "qrh:release_snapshot:forged",
            "subject_urn": "qrh:evidence-corpus:forged",
            "activation_id": "eact_forged",
            "evidence_revision": 999,
            "source_material_hash": "f" * 64,
            "stale_noop": True,
            "updates": [],
            "unmapped_research_urns": [],
        }
        forged_json = canonical_json(forged)
        forged_result_hash = sha256_hex(forged_json.encode("utf-8"))
        with archive_connection(self.settings) as connection, immediate_transaction(connection):
            connection.execute(
                """
                INSERT INTO outbox_event(
                    event_id,event_type,event_version,aggregate_urn,payload_json,
                    payload_hash,created_at,published_at,publish_attempt_count
                ) VALUES(?,'ArchiveEvidenceProjectionUpdated','1',?,?,?,?,NULL,0)
                """,
                (
                    new_public_id("evt"),
                    f"qrh:evidence-event:{event_id}",
                    forged_json,
                    stable_sha256("archive-outbox/v1", forged_json),
                    utc_now(),
                ),
            )
            connection.execute(
                """
                INSERT INTO inbox_receipt(
                    consumer_name,source_domain,event_id,processed_at,result_hash
                ) VALUES(?,'evidence',?,?,?)
                """,
                (
                    EvidenceProjectionConsumer.CONSUMER_NAME,
                    event_id,
                    utc_now(),
                    forged_result_hash,
                ),
            )

        with self.assertRaisesRegex(EvidenceProjectionError, "not bound"):
            EvidenceProjectionConsumer(self.settings).consume(event_id)
        with evidence_connection(self.settings) as connection:
            event = connection.execute(
                "SELECT published_at,publish_attempt_count FROM outbox_event WHERE event_id=?",
                (event_id,),
            ).fetchone()
            self.assertIsNone(event["published_at"])
            self.assertEqual(0, event["publish_attempt_count"])
        page = ArchiveCatalog(self.settings).research_page(self.item.research_id)
        self.assertEqual("under_review", page["evidence_status"])


if __name__ == "__main__":
    import unittest

    unittest.main()
