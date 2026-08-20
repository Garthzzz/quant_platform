from __future__ import annotations

import hashlib
import json

from quant_hub.archive.catalog import ArchiveCatalog
from quant_hub.archive.contracts import ArchiveDocumentInput, ArchiveReleaseInput
from quant_hub.archive.database import archive_connection
from quant_hub.evidence.database import evidence_connection
from quant_hub.evidence.ingest import EvidenceDatabaseIngestAdapter
from quant_hub.platform.db import connect_database
from quant_hub.integration.incremental_intake import (
    EvidenceDispatchReceipt,
    EvidenceIngestCommand,
    IncrementalIntake,
    IntakeSource,
    LocalSpoolEvidenceAdapter,
)
from tests.helpers import SettingsTestCase


class RecordingAdapter:
    def __init__(self, status: str = "accepted"):
        self.status = status
        self.commands: list[EvidenceIngestCommand] = []

    def dispatch(self, command: EvidenceIngestCommand) -> EvidenceDispatchReceipt:
        self.commands.append(command)
        return EvidenceDispatchReceipt.create(
            command,
            status=self.status,  # type: ignore[arg-type]
            detail=f"test adapter: {self.status}",
        )


class InterruptOnceAdapter(RecordingAdapter):
    def dispatch(self, command: EvidenceIngestCommand) -> EvidenceDispatchReceipt:
        self.commands.append(command)
        if len(self.commands) == 1:
            raise KeyboardInterrupt("simulated process interruption")
        return EvidenceDispatchReceipt.create(
            command, status="accepted", detail="recovered dispatch"
        )


class FailOnceAdapter(RecordingAdapter):
    def dispatch(self, command: EvidenceIngestCommand) -> EvidenceDispatchReceipt:
        self.commands.append(command)
        if len(self.commands) == 1:
            raise RuntimeError("temporary local adapter failure")
        return EvidenceDispatchReceipt.create(
            command, status="accepted", detail="recovered ordinary failure"
        )


class AckFailOnceAdapter(EvidenceDatabaseIngestAdapter):
    def __init__(self, settings):
        super().__init__(settings)
        self.ack_attempts = 0

    def acknowledge_result(self, command, receipt) -> None:
        self.ack_attempts += 1
        if self.ack_attempts == 1:
            raise RuntimeError("simulated crash after Archive inbox receipt")
        super().acknowledge_result(command, receipt)


class IncrementalIntakeTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.inbox = self.var / "inbox" / "research"
        self.inbox.mkdir(parents=True)

    @staticmethod
    def source_v1() -> bytes:
        return (
            "# 新增研究\n\n"
            "正文明确给出 DOI: 10.1234/example.1。\n\n"
            "`arXiv:2401.00001` 只是行内代码示例。\n\n"
            "```text\n"
            "doi:10.9999/ignored-code\n"
            "```\n\n"
            "## 参考资料\n\n"
            "- Alpha, A. (2020). Deterministic Signals.\n"
        ).encode("utf-8")

    def test_new_repeat_and_changed_bytes_are_idempotent_and_versioned(self) -> None:
        path = self.inbox / "new-study.md"
        path.write_bytes(self.source_v1())
        source_before = path.read_bytes()
        adapter = RecordingAdapter()
        service = IncrementalIntake(self.settings, adapter)
        root = (IntakeSource("research_inbox", self.inbox),)

        first = service.scan(root)
        self.assertEqual("PASS", first.status, first.to_dict())
        self.assertEqual(1, len(first.processed))
        item_v1 = first.processed[0]
        self.assertEqual("published", item_v1.state)
        self.assertEqual(2, item_v1.clue_count)
        self.assertEqual(1, len(adapter.commands))
        markers = [row["raw_marker_text"] for row in adapter.commands[0].occurrences]
        self.assertTrue(any("10.1234/example.1" in value for value in markers))
        self.assertTrue(any("Alpha, A." in value for value in markers))
        self.assertFalse(any("2401.00001" in value for value in markers))
        self.assertFalse(any("10.9999" in value for value in markers))
        page = ArchiveCatalog(self.settings).research_page(item_v1.research_id)
        self.assertEqual(hashlib.sha256(source_before).hexdigest(), page["documents"][0]["content_sha256"])
        self.assertEqual(source_before, path.read_bytes())

        repeated = service.scan(root)
        self.assertEqual("PASS", repeated.status, repeated.to_dict())
        self.assertEqual("unchanged", repeated.processed[0].state)
        self.assertEqual(1, len(adapter.commands), "completed parent must not redispatch")
        with archive_connection(self.settings) as connection:
            self.assertEqual(1, connection.execute("SELECT count(*) FROM research_release").fetchone()[0])
            self.assertEqual(1, connection.execute("SELECT count(*) FROM research_document_version").fetchone()[0])
            self.assertEqual(0, connection.execute("SELECT count(*) FROM research_completion_decision").fetchone()[0])

        source_v2 = source_before + "\n新增版本说明，但不推断完成状态。\n".encode("utf-8")
        path.write_bytes(source_v2)
        changed = service.scan(root)
        self.assertEqual("PASS", changed.status, changed.to_dict())
        item_v2 = changed.processed[0]
        self.assertEqual(2, item_v2.release_revision)
        self.assertNotEqual(item_v1.parent_run_id, item_v2.parent_run_id)
        self.assertEqual(item_v1.research_id, item_v2.research_id)
        with archive_connection(self.settings) as connection:
            self.assertEqual(2, connection.execute("SELECT count(*) FROM research_release").fetchone()[0])
            self.assertEqual(2, connection.execute("SELECT count(*) FROM research_document_version").fetchone()[0])
            relation = connection.execute("SELECT * FROM document_version_relation").fetchone()
            self.assertEqual("supersedes", relation["relation_kind"])
            self.assertEqual("verified", relation["status"])
            self.assertEqual(0, connection.execute("SELECT count(*) FROM research_completion_decision").fetchone()[0])
        page = ArchiveCatalog(self.settings).research_page(item_v2.research_id)
        self.assertEqual(hashlib.sha256(source_v2).hexdigest(), page["documents"][0]["content_sha256"])
        self.assertEqual(source_v2, path.read_bytes())

        platform = connect_database(self.settings.database_path)
        try:
            self.assertEqual(
                2,
                platform.execute(
                    "SELECT count(*) FROM pipeline_run WHERE workflow_name='archive_import'"
                ).fetchone()[0],
            )
            self.assertEqual(
                2,
                platform.execute(
                    "SELECT count(*) FROM pipeline_run WHERE workflow_name='evidence_ingest'"
                ).fetchone()[0],
            )
        finally:
            platform.close()

    def test_archive_and_research_inbox_namespaces_are_both_scanned_without_collision(self) -> None:
        archive_path = self.archive / "same-name.md"
        inbox_path = self.inbox / "same-name.md"
        archive_path.write_bytes(b"# Archive source\n")
        inbox_path.write_bytes(b"# Inbox source\n")
        before = (archive_path.read_bytes(), inbox_path.read_bytes())

        report = IncrementalIntake(self.settings, RecordingAdapter()).scan(
            (
                IntakeSource("archive", self.archive),
                IntakeSource("research_inbox", self.inbox),
            )
        )
        self.assertEqual("PASS", report.status, report.to_dict())
        self.assertEqual(2, len(report.processed))
        self.assertEqual({"archive", "research_inbox"}, {row.namespace for row in report.processed})
        self.assertEqual(2, len({row.research_id for row in report.processed}))
        self.assertEqual(before, (archive_path.read_bytes(), inbox_path.read_bytes()))

    def test_new_path_with_same_bytes_registers_origin_alias_not_new_research(self) -> None:
        payload = b"# One content identity\n\nDOI: 10.1234/same-content\n"
        (self.inbox / "a.md").write_bytes(payload)
        (self.inbox / "b.md").write_bytes(payload)
        adapter = RecordingAdapter()
        service = IncrementalIntake(self.settings, adapter)
        roots = (IntakeSource("research_inbox", self.inbox),)

        first = service.scan(roots)
        self.assertEqual("PASS", first.status, first.to_dict())
        self.assertEqual({"published", "aliased"}, {item.state for item in first.processed})
        self.assertEqual(1, len({item.research_id for item in first.processed}))
        self.assertEqual(1, len({item.document_version_id for item in first.processed}))
        self.assertEqual(1, len(adapter.commands), "an origin alias must not duplicate Evidence ledger input")
        with archive_connection(self.settings) as connection:
            self.assertEqual(1, connection.execute("SELECT count(*) FROM research").fetchone()[0])
            self.assertEqual(
                1,
                connection.execute("SELECT count(*) FROM research_document_version").fetchone()[0],
            )
            self.assertEqual(
                2,
                connection.execute("SELECT count(*) FROM research_document_origin").fetchone()[0],
            )

        repeated = service.scan(roots)
        self.assertEqual("PASS", repeated.status, repeated.to_dict())
        self.assertEqual({"unchanged"}, {item.state for item in repeated.processed})
        self.assertEqual(1, len(adapter.commands))

    def test_managed_source_view_is_confined_to_fresh_var_root(self) -> None:
        source = self.inbox / "confined.md"
        source.write_bytes(b"# Confined runtime view\n")
        service = IncrementalIntake(self.settings, RecordingAdapter())
        expected_root = self.var / "integration" / "source_views"
        self.assertEqual(expected_root.absolute(), service.source_view_root)

        report = service.scan((IntakeSource("research_inbox", self.inbox),))
        self.assertEqual("PASS", report.status, report.to_dict())
        view_files = [path for path in expected_root.rglob("*") if path.is_file()]
        self.assertEqual(1, len(view_files))
        view_files[0].resolve().relative_to(self.var.resolve())
        self.assertFalse((self.project / "quant_hub" / ".intake_source_views").exists())
        with self.assertRaisesRegex(ValueError, "var_root"):
            IncrementalIntake(
                self.settings,
                RecordingAdapter(),
                source_view_root=self.project / "outside-var-view",
            )
        with self.assertRaisesRegex(ValueError, "var_root"):
            LocalSpoolEvidenceAdapter(
                self.settings, spool_root=self.project / "outside-var-spool"
            )

    def test_default_adapter_requires_atomic_evidence_target_receipt(self) -> None:
        source = self.inbox / "formal-target.md"
        source.write_bytes(b"# Formal target\n\nDOI: 10.1234/formal-target\n")

        report = IncrementalIntake(self.settings).scan(
            (IntakeSource("research_inbox", self.inbox),)
        )
        self.assertEqual("PASS", report.status, report.to_dict())
        self.assertEqual("accepted", report.processed[0].evidence_dispatch_status)
        with evidence_connection(self.settings) as connection:
            self.assertEqual(
                report.processed[0].clue_count,
                connection.execute("SELECT count(*) FROM citation_ledger_entry").fetchone()[0],
            )
            self.assertEqual(1, connection.execute("SELECT count(*) FROM inbox_receipt").fetchone()[0])
            self.assertEqual(
                1,
                connection.execute(
                    "SELECT count(*) FROM outbox_event WHERE event_type='EvidenceIngestCommandAccepted'"
                ).fetchone()[0],
            )
            result_event = connection.execute(
                """
                SELECT published_at,publish_attempt_count FROM outbox_event
                WHERE event_type='EvidenceIngestCommandAccepted'
                """
            ).fetchone()
            self.assertIsNotNone(result_event["published_at"])
            self.assertEqual(1, result_event["publish_attempt_count"])
        with archive_connection(self.settings) as connection:
            relay = connection.execute(
                """
                SELECT published_at,publish_attempt_count FROM outbox_event
                WHERE event_type='ArchiveDocumentVersionRegistered'
                """
            ).fetchone()
            self.assertIsNotNone(relay["published_at"])
            self.assertEqual(1, relay["publish_attempt_count"])
            self.assertEqual(
                1,
                connection.execute(
                    """
                    SELECT count(*) FROM inbox_receipt
                    WHERE consumer_name='archive-evidence-ingest-result/v1'
                      AND source_domain='evidence'
                    """
                ).fetchone()[0],
            )
        platform = connect_database(self.settings.database_path)
        try:
            self.assertEqual(
                1,
                platform.execute(
                    "SELECT count(*) FROM outbox_event WHERE event_type='ArchiveImportCompleted'"
                ).fetchone()[0],
            )
        finally:
            platform.close()

    def test_result_ack_crash_resumes_without_duplicate_target_material(self) -> None:
        source = self.inbox / "ack-recovery.md"
        source.write_bytes(b"# Ack recovery\n\nDOI: 10.1234/ack-recovery\n")
        adapter = AckFailOnceAdapter(self.settings)
        service = IncrementalIntake(self.settings, adapter)
        roots = (IntakeSource("research_inbox", self.inbox),)

        failed = service.scan(roots)
        self.assertEqual("ERROR", failed.status, failed.to_dict())
        with evidence_connection(self.settings) as connection:
            pending = connection.execute(
                """
                SELECT published_at,publish_attempt_count FROM outbox_event
                WHERE event_type='EvidenceIngestCommandAccepted'
                """
            ).fetchone()
            self.assertIsNone(pending["published_at"])
            self.assertEqual(0, pending["publish_attempt_count"])
            ledger_count = connection.execute(
                "SELECT count(*) FROM citation_ledger_entry"
            ).fetchone()[0]
        with archive_connection(self.settings) as connection:
            self.assertEqual(
                1,
                connection.execute(
                    "SELECT count(*) FROM inbox_receipt WHERE consumer_name=?",
                    (adapter.RESULT_CONSUMER_NAME,),
                ).fetchone()[0],
            )

        recovered = service.scan(roots)
        self.assertEqual("PASS", recovered.status, recovered.to_dict())
        self.assertEqual(2, adapter.ack_attempts)
        with evidence_connection(self.settings) as connection:
            delivered = connection.execute(
                """
                SELECT published_at,publish_attempt_count FROM outbox_event
                WHERE event_type='EvidenceIngestCommandAccepted'
                """
            ).fetchone()
            self.assertIsNotNone(delivered["published_at"])
            self.assertEqual(1, delivered["publish_attempt_count"])
            self.assertEqual(
                ledger_count,
                connection.execute("SELECT count(*) FROM citation_ledger_entry").fetchone()[0],
            )

    def test_completed_parent_revalidates_formal_evidence_target_material(self) -> None:
        source = self.inbox / "target-drift.md"
        source.write_bytes(b"# Target drift\n\nDOI: 10.1234/target-drift\n")
        service = IncrementalIntake(self.settings)
        roots = (IntakeSource("research_inbox", self.inbox),)
        first = service.scan(roots)
        self.assertEqual("PASS", first.status, first.to_dict())

        with evidence_connection(self.settings) as connection:
            connection.execute("DROP TRIGGER citation_ledger_entry_no_update")
            connection.execute(
                "UPDATE citation_ledger_entry SET entry_reason='tampered after parent completion'"
            )
        replay = service.scan(roots)
        self.assertEqual("ERROR", replay.status, replay.to_dict())
        self.assertEqual(0, len(replay.processed))
        self.assertIn("drift", replay.issues[0].detail)

    def test_existing_explicit_archive_mapping_is_audited_and_not_duplicated(self) -> None:
        path = self.archive / "mapped.md"
        path.write_bytes(b"# Existing mapped research\n")
        catalog = ArchiveCatalog(self.settings)
        draft = ArchiveReleaseInput(
            research_slug="existing-mapped",
            display_title="既有显式映射",
            release_key="v1",
            documents=(
                ArchiveDocumentInput(
                    document_slug="main",
                    document_role="primary",
                    source_path="mapped.md",
                    **self.approved_source_fields("mapped.md"),
                    navigation_role="primary",
                    sort_key=10,
                    mapping_authority_urn="qrh:test:explicit-mapping",
                    mapping_note="测试既有显式映射优先于中性自动候选",
                ),
            ),
            activate=False,
        )
        self.publish_with_test_certificate(catalog, draft, label="existing-mapped")

        report = IncrementalIntake(self.settings, RecordingAdapter()).scan(
            (IntakeSource("archive", self.archive),)
        )
        self.assertEqual("PASS", report.status, report.to_dict())
        self.assertEqual((), report.processed)
        self.assertEqual(1, len(report.skipped))
        self.assertIn("显式 Archive 映射", report.skipped[0].reason)
        with archive_connection(self.settings) as connection:
            self.assertEqual(1, connection.execute("SELECT count(*) FROM research").fetchone()[0])
            self.assertEqual(1, connection.execute("SELECT count(*) FROM research_release").fetchone()[0])

    def test_external_failure_is_local_and_invalid_utf8_is_explicit(self) -> None:
        valid = self.inbox / "valid.md"
        invalid = self.inbox / "invalid.md"
        valid.write_bytes(b"# Faithful page\n\nNo paper clue.\n")
        invalid.write_bytes(b"# invalid\n\xff\xfe")
        before = {valid.name: valid.read_bytes(), invalid.name: invalid.read_bytes()}
        adapter = RecordingAdapter("blocked_external")

        report = IncrementalIntake(self.settings, adapter).scan(
            (IntakeSource("research_inbox", self.inbox),)
        )
        self.assertEqual("ERROR", report.status, report.to_dict())
        self.assertEqual(0, len(report.processed))
        self.assertTrue(
            any(issue.code == "evidence_waiting_external" for issue in report.issues)
        )
        self.assertTrue(any(issue.relative_path == "invalid.md" for issue in report.issues))
        research_id = ArchiveCatalog(self.settings).list_research()[0]["research_id"]
        page = ArchiveCatalog(self.settings).research_page(research_id)
        self.assertEqual("failed", page["evidence_status"])
        self.assertEqual(1, len(page["documents"]))
        self.assertEqual(before[valid.name], valid.read_bytes())
        self.assertEqual(before[invalid.name], invalid.read_bytes())
        platform = connect_database(self.settings.database_path)
        try:
            parent = platform.execute(
                "SELECT run_status FROM pipeline_run WHERE workflow_name='archive_import'"
            ).fetchone()
            child = platform.execute(
                "SELECT run_status FROM pipeline_run WHERE workflow_name='evidence_ingest'"
            ).fetchone()
            self.assertEqual("waiting_external", parent["run_status"])
            self.assertEqual("waiting_external", child["run_status"])
            self.assertEqual(
                0,
                platform.execute(
                    "SELECT count(*) FROM outbox_event WHERE event_type='ArchiveImportCompleted'"
                ).fetchone()[0],
            )
        finally:
            platform.close()

    def test_interruption_after_archive_publish_resumes_without_duplicate_release(self) -> None:
        source = self.inbox / "recovery.md"
        source.write_bytes(b"# Recovery\n\nDOI: 10.5555/recovery\n")
        adapter = InterruptOnceAdapter()
        service = IncrementalIntake(self.settings, adapter)
        roots = (IntakeSource("research_inbox", self.inbox),)

        with self.assertRaises(KeyboardInterrupt):
            service.scan(roots)
        with archive_connection(self.settings) as connection:
            self.assertEqual(1, connection.execute("SELECT count(*) FROM research_release").fetchone()[0])
            self.assertEqual(1, connection.execute("SELECT count(*) FROM research_release_activation").fetchone()[0])

        recovered = service.scan(roots)
        self.assertEqual("PASS", recovered.status, recovered.to_dict())
        self.assertEqual(2, len(adapter.commands))
        self.assertEqual(adapter.commands[0].command_hash, adapter.commands[1].command_hash)
        with archive_connection(self.settings) as connection:
            self.assertEqual(1, connection.execute("SELECT count(*) FROM research_release").fetchone()[0])
            self.assertEqual(1, connection.execute("SELECT count(*) FROM research_release_activation").fetchone()[0])
        self.assertEqual(b"# Recovery\n\nDOI: 10.5555/recovery\n", source.read_bytes())

    def test_adapter_exception_has_no_fabricated_receipt_and_is_retryable(self) -> None:
        source = self.inbox / "adapter-retry.md"
        source.write_bytes(b"# Adapter retry\n\nDOI: 10.5555/adapter-retry\n")
        adapter = FailOnceAdapter()
        service = IncrementalIntake(self.settings, adapter)
        roots = (IntakeSource("research_inbox", self.inbox),)

        failed = service.scan(roots)
        self.assertEqual("ERROR", failed.status, failed.to_dict())
        self.assertEqual(1, len(failed.issues))
        platform = connect_database(self.settings.database_path)
        try:
            parent = platform.execute(
                "SELECT run_status FROM pipeline_run WHERE workflow_name='archive_import'"
            ).fetchone()
            child = platform.execute(
                "SELECT run_status FROM pipeline_run WHERE workflow_name='evidence_ingest'"
            ).fetchone()
            self.assertEqual("failed", parent["run_status"])
            self.assertEqual("queued", child["run_status"])
            self.assertEqual(
                0,
                platform.execute(
                    "SELECT count(*) FROM outbox_event WHERE event_type='EvidenceIngestDispatchRecorded'"
                ).fetchone()[0],
            )
            self.assertEqual(
                0,
                platform.execute(
                    "SELECT count(*) FROM outbox_event WHERE event_type='ArchiveImportCompleted'"
                ).fetchone()[0],
            )
        finally:
            platform.close()

        recovered = service.scan(roots)
        self.assertEqual("PASS", recovered.status, recovered.to_dict())
        self.assertEqual(2, len(adapter.commands))
        self.assertEqual(adapter.commands[0].command_hash, adapter.commands[1].command_hash)
        self.assertEqual("accepted", recovered.processed[0].evidence_dispatch_status)

    def test_multiline_code_and_link_label_cannot_forge_paper_clues(self) -> None:
        source = self.inbox / "clue-boundaries.md"
        source.write_text(
            "# Clue boundaries\n\n"
            "``code starts\nDOI: 10.9999/inside-code\ncode ends``\n\n"
            "[ssrn.com fake label](https://example.com/not-a-paper)\n\n"
            "[Real SSRN paper](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=123)\n",
            encoding="utf-8",
            newline="\n",
        )
        adapter = RecordingAdapter()
        report = IncrementalIntake(self.settings, adapter).scan(
            (IntakeSource("research_inbox", self.inbox),)
        )

        self.assertEqual("PASS", report.status, report.to_dict())
        self.assertEqual(1, len(adapter.commands))
        markers = [row["raw_marker_text"] for row in adapter.commands[0].occurrences]
        self.assertFalse(any("inside-code" in marker for marker in markers))
        self.assertFalse(any("not-a-paper" in marker for marker in markers))
        self.assertTrue(any("papers.ssrn.com" in marker for marker in markers))

    def test_legacy_mutated_completion_payload_is_never_trusted_on_replay(self) -> None:
        source = self.inbox / "legacy-forged-completion.md"
        source.write_bytes(b"# Immutable completion\n")
        service = IncrementalIntake(self.settings, RecordingAdapter())
        roots = (IntakeSource("research_inbox", self.inbox),)
        first = service.scan(roots)
        self.assertEqual("PASS", first.status, first.to_dict())

        platform = connect_database(self.settings.database_path)
        try:
            # 模拟 0006 生效前已经被篡改、但旧 payload_hash 未同步的历史库。
            platform.execute("DROP TRIGGER outbox_event_material_immutable")
            row = platform.execute(
                "SELECT event_id,payload_json FROM outbox_event WHERE event_type='ArchiveImportCompleted'"
            ).fetchone()
            payload = json.loads(row["payload_json"])
            payload["item"]["research_id"] = "res_forged"
            platform.execute(
                "UPDATE outbox_event SET payload_json=? WHERE event_id=?",
                (json.dumps(payload, ensure_ascii=False, separators=(",", ":")), row["event_id"]),
            )
        finally:
            platform.close()

        replay = service.scan(roots)
        self.assertEqual("ERROR", replay.status, replay.to_dict())
        self.assertEqual(0, len(replay.processed))
        self.assertIn("hash", replay.issues[0].detail)


if __name__ == "__main__":
    import unittest

    unittest.main()
