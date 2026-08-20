from __future__ import annotations

from pathlib import Path
import sqlite3

from quant_hub.platform.db import connect_database
from quant_hub.platform.migrations import migrate_down, migrate_up, schema_hash
from tests.helpers import SettingsTestCase


EVIDENCE_MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations" / "research_papers"
NOW = "2026-07-15T00:00:00.000000Z"
HASH_A = "a" * 64


class EvidenceMigrationTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.connection = connect_database(self.settings.research_papers_database_path)
        self.addCleanup(self.connection.close)

    def test_up_down_up_is_strict_reversible_and_deterministic(self) -> None:
        self.assertEqual([1, 2, 3, 4, 5, 6], migrate_up(self.connection, EVIDENCE_MIGRATIONS))
        first_hash = schema_hash(self.connection)
        self.assertEqual([], migrate_up(self.connection, EVIDENCE_MIGRATIONS))
        self.assertEqual(first_hash, schema_hash(self.connection))
        required = {
            "paper_clue",
            "paper_candidate",
            "paper",
            "paper_identity_event",
            "identifier_assignment_projection",
            "metadata_assertion",
            "fetch_attempt",
            "paper_resource",
            "citation_occurrence",
            "citation_ledger_entry",
            "citation_binding",
            "citation_binding_event",
            "paper_reading_task",
            "paper_reading_run",
            "paper_category_assertion",
            "paper_category_assignment_detail",
            "paper_core_conclusion_evidence",
            "paper_institution_resolution",
            "paper_reading_conclusion_binding",
            "research_paper_relation",
            "paper_inventory_export",
            "evidence_release",
            "evidence_release_item",
            "platform_certificate_receipt",
            "evidence_release_activation",
            "active_evidence_release",
            "evidence_resolution_case",
            "evidence_resolution_event",
            "evidence_resolution_state",
            "evidence_provider_request",
            "evidence_provider_attempt",
            "evidence_provider_observation",
            "evidence_resource_offer",
            "evidence_identity_decision",
            "evidence_rights_assessment",
            "evidence_acquisition_case",
            "evidence_acquisition_event",
            "evidence_acquisition_state",
            "evidence_canonicalization_receipt",
            "evidence_method_origin_candidate_derivation",
            "evidence_canonical_resource_attachment",
            "evidence_associated_method_relation",
            "evidence_canonicalization_event",
            "evidence_canonicalization_state",
            "evidence_fulltext_conclusion_support",
            "evidence_substantive_enrichment",
            "outbox_event",
            "inbox_receipt",
        }
        tables = {
            row[1]: row
            for row in self.connection.execute("PRAGMA table_list")
            if row[1] in required
        }
        self.assertEqual(required, set(tables))
        self.assertTrue(all(row[5] == 1 for row in tables.values()))
        self.assertEqual("ok", self.connection.execute("PRAGMA integrity_check").fetchone()[0])
        self.assertEqual([], self.connection.execute("PRAGMA foreign_key_check").fetchall())

        immutable_triggers = {
            "evidence_canonicalization_receipt_no_update",
            "evidence_canonicalization_receipt_no_delete",
            "evidence_canonical_resource_attachment_no_update",
            "evidence_canonical_resource_attachment_no_delete",
            "evidence_associated_method_relation_no_update",
            "evidence_associated_method_relation_no_delete",
            "evidence_canonicalization_event_no_update",
            "evidence_canonicalization_event_no_delete",
            "evidence_canonicalization_state_no_update",
            "evidence_canonicalization_state_no_delete",
            "evidence_method_origin_candidate_derivation_no_update",
            "evidence_method_origin_candidate_derivation_no_delete",
            "evidence_fulltext_conclusion_support_no_update",
            "evidence_fulltext_conclusion_support_no_delete",
        }
        actual_triggers = {
            str(row[0])
            for row in self.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger'"
            )
        }
        self.assertTrue(immutable_triggers.issubset(actual_triggers))

        self.assertEqual([6, 5, 4, 3, 2, 1], migrate_down(self.connection, EVIDENCE_MIGRATIONS, steps=6))
        remaining = {
            row[0]
            for row in self.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        self.assertEqual({"schema_migration"}, remaining)
        self.assertEqual([1, 2, 3, 4, 5, 6], migrate_up(self.connection, EVIDENCE_MIGRATIONS))
        self.assertEqual(first_hash, schema_hash(self.connection))
        recreated_triggers = {
            str(row[0])
            for row in self.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger'"
            )
        }
        self.assertTrue(immutable_triggers.issubset(recreated_triggers))

    def test_append_only_and_release_staging_invariants_are_enforced(self) -> None:
        migrate_up(self.connection, EVIDENCE_MIGRATIONS)
        self.connection.execute(
            """
            INSERT INTO paper_clue(
                clue_id,source_candidate_id,entity_kind,domain_category,raw_claim_json,
                provenance_urn,resolution_status,created_at
            ) VALUES('clue-1','P1','paper_or_scholarly_work','ML','{}',
                     'qrh:test:clue','unresolved',?)
            """,
            (NOW,),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            self.connection.execute(
                "UPDATE paper_clue SET resolution_status='externally_verified' WHERE clue_id='clue-1'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "begin in staging"):
            self.connection.execute(
                """
                INSERT INTO evidence_release(
                    evidence_release_id,subject_urn,subject_version_urn,
                    artifact_manifest_hash,source_snapshot_hash,
                    requirements_manifest_hash,projection_revision,candidate_status,created_at
                ) VALUES('release-1','qrh:evidence:test','qrh:evidence:test:v1',
                         ?,?,?,?,'releasable',?)
                """,
                (HASH_A, HASH_A, HASH_A, HASH_A, NOW),
            )

    def test_identifier_projection_rejects_bypass_without_identity_event(self) -> None:
        migrate_up(self.connection, EVIDENCE_MIGRATIONS)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self.connection.execute(
                """
                INSERT INTO paper_identity_event(
                    identity_event_id,event_kind,from_paper_id,to_paper_id,scheme,
                    normalized_value,provenance_urn,payload_json,occurred_at
                ) VALUES('create-1','paper_created',NULL,'paper-1',NULL,NULL,
                         'qrh:test:create','{}',?)
                """,
                (NOW,),
            )
            self.connection.execute(
                "INSERT INTO paper(paper_id,canonical_urn,creation_event_id,created_at) VALUES('paper-1','qrh:evidence:paper:1','create-1',?)",
                (NOW,),
            )
            self.connection.commit()
        except BaseException:
            self.connection.rollback()
            raise
        with self.assertRaisesRegex(sqlite3.IntegrityError, "matching identity event"):
            self.connection.execute(
                """
                INSERT INTO identifier_assignment_projection(
                    scheme,normalized_value,paper_id,source_event_id,revision,updated_at
                ) VALUES('doi','10.1234/test','paper-1','create-1',1,?)
                """,
                (NOW,),
            )


if __name__ == "__main__":
    import unittest

    unittest.main()
