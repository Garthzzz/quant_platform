from __future__ import annotations

from dataclasses import replace
import json
import sqlite3

from quant_hub.evidence.database import (
    evidence_connection,
    initialize_evidence_database,
)
from quant_hub.evidence.ingest import (
    EvidenceDatabaseIngestAdapter,
    EvidenceIngestConflict,
)
from quant_hub.ids import stable_sha256
from quant_hub.integration.clues import extract_clues
from quant_hub.integration.incremental_intake import EvidenceIngestCommand
from quant_hub.platform.objects import ObjectStore
from quant_hub.platform.workflow import canonical_json
from tests.helpers import SettingsTestCase


class EvidenceDatabaseIngestAdapterTests(SettingsTestCase):
    def _command(
        self,
        *,
        source: bytes = b"# Ingest\n\nDOI: 10.1234/adapter-test\narXiv: 2401.01234\n",
        source_path: str = "research_inbox:///adapter.md",
        idempotency_label: str = "primary",
        archive_event_id: str = "archive-event-adapter-1",
    ) -> EvidenceIngestCommand:
        store = ObjectStore(self.settings.object_root)
        source_object = store.put_bytes(source)
        source_object_urn = f"qrh:object:{source_object.object_id}"
        artifact = extract_clues(
            source,
            source_path=source_path,
            source_object_urn=source_object_urn,
        )
        artifact_object = store.put_bytes(
            canonical_json(artifact.to_dict()).encode("utf-8")
        )
        research_urn = "qrh:archive-research:adapter"
        archive_release_urn = "qrh:archive-release:adapter:v1"
        document_version_urn = (
            f"qrh:archive-document-version:{source_object.object_id}"
        )
        occurrence_rows = tuple(
            {
                **item.to_dict(),
                "legacy_occurrence_id": f"auto_{item.citation_id}",
                "research_urn": research_urn,
                "archive_release_urn": archive_release_urn,
                "document_version_urn": document_version_urn,
                "source_object_urn": source_object_urn,
                "source_path": source_path,
                "locator_kind": "utf8_bytes",
                "locator": {
                    "line": item.line_start,
                    "byte_start": item.byte_start,
                    "byte_end": item.byte_end,
                },
            }
            for item in artifact.occurrences
        )
        return EvidenceIngestCommand(
            schema_version="qrh-evidence-ingest-command/v1",
            idempotency_key=stable_sha256(
                "test-evidence-ingest-command/v1", idempotency_label
            ),
            child_run_urn="qrh:run:child-adapter",
            parent_run_urn="qrh:run:parent-adapter",
            archive_event_id=archive_event_id,
            research_urn=research_urn,
            archive_release_urn=archive_release_urn,
            document_version_urn=document_version_urn,
            source_object_urn=source_object_urn,
            source_path=source_path,
            clue_artifact_urn=f"qrh:object:{artifact_object.object_id}",
            clue_artifact_sha256=artifact_object.sha256,
            occurrences=occurrence_rows,
        )

    @staticmethod
    def _counts(connection) -> dict[str, int]:
        return {
            table: int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
            for table in (
                "paper_clue",
                "citation_occurrence",
                "citation_ledger_entry",
                "citation_binding",
                "citation_binding_event",
                "citation_binding_projection",
                "inbox_receipt",
                "outbox_event",
            )
        }

    def test_accepted_receipt_is_derived_from_atomic_target_domain_material(self) -> None:
        command = self._command()
        adapter = EvidenceDatabaseIngestAdapter(self.settings)
        first = adapter.dispatch(command)
        replay = adapter.dispatch(command)

        self.assertEqual("accepted", first.status)
        self.assertTrue(first.created)
        self.assertFalse(replay.created)
        self.assertEqual(first.result_hash, replay.result_hash)
        self.assertIn("state=pending_resolution", first.detail)
        self.assertRegex(first.detail, r"material_sha256=[0-9a-f]{64}$")
        first.verify(command)
        replay.verify(command)

        expected_count = len(command.occurrences)
        self.assertGreater(expected_count, 0)
        with evidence_connection(self.settings) as connection:
            counts = self._counts(connection)
            for table in (
                "paper_clue",
                "citation_occurrence",
                "citation_ledger_entry",
                "citation_binding",
                "citation_binding_event",
                "citation_binding_projection",
            ):
                self.assertEqual(expected_count, counts[table], table)
            self.assertEqual(1, counts["inbox_receipt"])
            self.assertEqual(1, counts["outbox_event"])
            inbox = connection.execute("SELECT * FROM inbox_receipt").fetchone()
            outbox = connection.execute("SELECT * FROM outbox_event").fetchone()
            payload = json.loads(str(outbox["payload_json"]))
            self.assertEqual(first.result_hash, inbox["result_hash"])
            self.assertEqual(first.result_hash, payload["result_hash"])
            self.assertEqual(command.command_hash, payload["command_hash"])
            self.assertEqual(expected_count, payload["ledger_entry_count"])
            self.assertEqual(expected_count, len(payload["ledger_entry_ids"]))
            self.assertIn(payload["material_hash"], first.detail)
            self.assertEqual(
                {"unresolved"},
                {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT binding_status FROM citation_binding"
                    )
                },
            )
            self.assertEqual(
                {"resolution_pending"},
                {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT resolution_status FROM paper_clue"
                    )
                },
            )

    def test_same_idempotency_key_with_different_command_fails_closed(self) -> None:
        command = self._command()
        adapter = EvidenceDatabaseIngestAdapter(self.settings)
        adapter.dispatch(command)
        with evidence_connection(self.settings) as connection:
            before = self._counts(connection)
        conflicting = replace(command, parent_run_urn="qrh:run:other-parent")
        with self.assertRaises(EvidenceIngestConflict):
            adapter.dispatch(conflicting)
        with evidence_connection(self.settings) as connection:
            self.assertEqual(before, self._counts(connection))

    def test_same_archive_event_under_another_idempotency_key_fails_closed(self) -> None:
        command = self._command()
        adapter = EvidenceDatabaseIngestAdapter(self.settings)
        adapter.dispatch(command)
        conflicting = replace(
            command,
            idempotency_key=stable_sha256(
                "test-evidence-ingest-command/v1", "other-key"
            ),
        )
        with self.assertRaises(EvidenceIngestConflict):
            adapter.dispatch(conflicting)
        with evidence_connection(self.settings) as connection:
            self.assertEqual(1, connection.execute("SELECT count(*) FROM inbox_receipt").fetchone()[0])
            self.assertEqual(1, connection.execute("SELECT count(*) FROM outbox_event").fetchone()[0])

    def test_target_domain_transaction_rollback_never_returns_accepted(self) -> None:
        command = self._command(idempotency_label="rollback")
        initialize_evidence_database(self.settings)
        with evidence_connection(self.settings) as connection:
            connection.execute(
                """
                CREATE TRIGGER reject_evidence_ingest_outbox
                BEFORE INSERT ON outbox_event
                WHEN NEW.event_type='EvidenceIngestCommandAccepted'
                BEGIN SELECT RAISE(ABORT, 'forced target-domain rollback'); END
                """
            )
        with self.assertRaises(sqlite3.IntegrityError):
            EvidenceDatabaseIngestAdapter(self.settings).dispatch(command)
        with evidence_connection(self.settings) as connection:
            self.assertEqual(
                {table: 0 for table in self._counts(connection)}, self._counts(connection)
            )

    def test_replay_detects_persisted_ledger_material_drift(self) -> None:
        command = self._command(idempotency_label="drift")
        adapter = EvidenceDatabaseIngestAdapter(self.settings)
        adapter.dispatch(command)
        with evidence_connection(self.settings) as connection:
            connection.execute("DROP TRIGGER citation_ledger_entry_no_update")
            connection.execute(
                "UPDATE citation_ledger_entry SET entry_reason='tampered after receipt'"
            )
        with self.assertRaisesRegex(EvidenceIngestConflict, "material has changed"):
            adapter.dispatch(command)

    def test_tampered_command_occurrence_is_rejected_before_target_writes(self) -> None:
        command = self._command(idempotency_label="tampered")
        row = dict(command.occurrences[0])
        row["context_text"] = "forged context"
        forged = replace(command, occurrences=(row, *command.occurrences[1:]))
        with self.assertRaisesRegex(EvidenceIngestConflict, "frozen clue artifact"):
            EvidenceDatabaseIngestAdapter(self.settings).dispatch(forged)
        initialize_evidence_database(self.settings)
        with evidence_connection(self.settings) as connection:
            self.assertEqual(
                {table: 0 for table in self._counts(connection)}, self._counts(connection)
            )


if __name__ == "__main__":
    import unittest

    unittest.main()

