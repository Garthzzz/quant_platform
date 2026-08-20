from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

from quant_hub.evidence.repository import EvidenceRepository
from quant_hub.evidence.reviewed_material_importer import (
    ReviewedMaterialImportError,
    ReviewedMaterialImporter,
    _open_pdf_review_bundle,
)
from quant_hub.runtime_seal import file_identity
from tests.helpers import SettingsTestCase
from tools.replay_reviewed_evidence_total import (
    KNOWN_LIVE_DATABASE,
    _assert_arxiv_rights_probe_details,
    _database_fingerprint,
    _assert_exact_identifier_projection,
    _assert_reviewed_gate_stable,
    _build_reviewed_gate_receipt,
    _freeze_quiescent_candidate,
    _frozen_v4_displayable_archive_relation_papers,
    _load_dedup_expectation,
    _resolve_known_live_database,
    _sources,
)


class ReviewedEvidenceTotalReplayTests(SettingsTestCase):
    def test_rights_blocked_api_requires_exactly_one_official_abstract(self) -> None:
        blocked = {
            source_id: {
                "abstract_excerpts": [{"sha256": source_id.lower()}],
                "local_resources": [],
                "reading_tasks": [],
                "core_conclusions": [
                    {"text": "official abstract", "evidence_scope": "official_abstract"}
                ],
            }
            for source_id in ("P034", "P137", "P143")
        }
        approved = {
            source_id: {
                "abstract_excerpts": [{"sha256": source_id.lower()}],
                "local_resources": [{"resource_id": source_id.lower()}],
                "reading_tasks": [{"reading_task_id": source_id.lower()}],
                "core_conclusions": [{"text": "reviewed source finding"}],
            }
            for source_id in ("P120", "P145", "P171")
        }
        _assert_arxiv_rights_probe_details(blocked, approved)

        missing_abstract = {
            **blocked,
            "P034": {**blocked["P034"], "abstract_excerpts": []},
        }
        with self.assertRaisesRegex(
            RuntimeError, "blocked/CC BY resource API boundaries"
        ):
            _assert_arxiv_rights_probe_details(missing_abstract, approved)

    def test_quiescent_freeze_uses_logical_backup_and_leaves_no_sidecars(self) -> None:
        EvidenceRepository(self.settings).initialize()
        (self.settings.research_papers_root / "objects").mkdir(parents=True)
        (self.settings.research_papers_root / "exports").mkdir()
        receipt = (
            self.settings.research_papers_root
            / "exports"
            / "reviewed_total_gate_receipt.json"
        )
        receipt.write_text('{"schema_version":"synthetic-gate/v1"}\n', encoding="utf-8")
        receipt_file_identity = file_identity(receipt)
        receipt_identity = {
            "relative_path": "exports/reviewed_total_gate_receipt.json",
            "bytes": receipt_file_identity["bytes"],
            "sha256": receipt_file_identity["sha256"],
        }
        replay_root = self.root / "isolated-replay"
        replay_root.mkdir()

        result = _freeze_quiescent_candidate(
            settings=self.settings,
            replay_root=replay_root,
            expected_resources=0,
            replay_snapshot_hash="synthetic-double-replay-snapshot",
            gate_receipt_identity=receipt_identity,
        )

        candidate = replay_root / "quiescent_candidate"
        candidate_database = candidate / "db" / "research_papers.sqlite3"
        self.assertTrue(candidate_database.is_file())
        self.assertEqual("synthetic-double-replay-snapshot", result["replay_snapshot_hash"])
        self.assertTrue(result["logical_database_equal"])
        self.assertEqual(receipt_identity, result["reviewed_gate_receipt"])
        self.assertEqual(0, result["resource_closure"]["resource_rows"])
        self.assertEqual([], result["sqlite_sidecars"])
        for database in (
            self.settings.research_papers_database_path,
            candidate_database,
        ):
            for suffix in ("-wal", "-shm", "-journal"):
                self.assertFalse(Path(f"{database}{suffix}").exists())

    def test_independent_dedup_expectation_is_exact_and_external(self) -> None:
        expectation, identity = _load_dedup_expectation()
        self.assertEqual("qrh-reviewed-evidence-dedup-expectation/v1", expectation["schema_version"])
        self.assertEqual(30_654, identity["bytes"])
        self.assertEqual(
            "5a7958c389a43892bee1c0d7e0952c9db6a9581eadca8f037f43c782504812a0",
            identity["sha256"],
        )
        self.assertEqual(78, expectation["expected_counts"]["canonical_total"])
        self.assertEqual(60, expectation["expected_counts"]["created_new_canonical"])

    def test_live_fingerprint_includes_rollback_journal(self) -> None:
        database = self.root / "fingerprint.sqlite3"
        database.write_bytes(b"database")
        Path(f"{database}-journal").write_bytes(b"journal")
        fingerprint = _database_fingerprint(database)
        self.assertEqual({"database", "wal", "shm", "journal"}, set(fingerprint))
        self.assertTrue(fingerprint["journal"]["exists"])

    def test_live_database_override_cannot_monitor_an_unrelated_file(self) -> None:
        unrelated = self.root / "unrelated.sqlite3"
        unrelated.write_bytes(b"not-the-known-live-database")
        with self.assertRaisesRegex(RuntimeError, "frozen known live database"):
            _resolve_known_live_database(unrelated)

    @unittest.skipUnless(
        KNOWN_LIVE_DATABASE.is_file(),
        "retired frozen V4 replay fixture is not retained in the compact workspace",
    )
    def test_displayable_relation_recount_never_opens_frozen_v4_for_write(self) -> None:
        source_var = KNOWN_LIVE_DATABASE.parents[1]
        databases = {
            name: source_var / "db" / f"{name}.sqlite3"
            for name in ("platform", "archive", "research_papers", "paper_lab")
        }
        before = {name: _database_fingerprint(path) for name, path in databases.items()}
        self.assertEqual(63, _frozen_v4_displayable_archive_relation_papers())
        after = {name: _database_fingerprint(path) for name, path in databases.items()}
        self.assertEqual(before, after)
        self.assertTrue(
            all(
                not fingerprint[sidecar]["exists"]
                for fingerprint in after.values()
                for sidecar in ("wal", "shm", "journal")
            )
        )

    @unittest.skipUnless(
        KNOWN_LIVE_DATABASE.is_file(),
        "retired frozen V4 replay fixture is not retained in the compact workspace",
    )
    def test_gate_receipt_binds_v4_manifest_seed_and_dedup_expectation(self) -> None:
        sources = _sources()
        plan = ReviewedMaterialImporter.static_plan(sources)
        expectation, expectation_identity = _load_dedup_expectation()
        receipt = _build_reviewed_gate_receipt(
            sources=sources,
            plan=plan,
            dedup_expectation=expectation,
            dedup_identity=expectation_identity,
        )
        bindings = receipt["input_bindings"]
        self.assertEqual(
            "9977c3fc8ae48a8f7b3fd7c596442c33db7c005de39893b0acebdd621c2c7fc0",
            bindings["arxiv_independent_verdict"]["sha256"],
        )
        self.assertEqual(
            "ff76c50fd2d45aa13660d2d9af0865d4abc7ae5850b2fd2488187f282d2e54bd",
            bindings["arxiv_total_delivery_manifest"]["sha256"],
        )
        self.assertEqual(
            "64e3d64657e438e4a7efe36594ad56026133e132ee6aa94fb977620958c2e21b",
            bindings["arxiv_resolution_seed"]["sha256"],
        )
        self.assertEqual(expectation_identity, bindings["dedup_expectation"])
        self.assertEqual(78, receipt["dedup_expectation"]["expected_counts"]["canonical_total"])
        self.assertEqual(
            {
                "canonical_papers": 78,
                "verified_resources": 48,
                "canonicalization_receipts": 60,
                "formal_receipts": 53,
                "method_receipts": 7,
                "blocked_acquisitions": 4,
                "associated_method_ledger_occurrences": 547,
                "fulltext_conclusion_support": 26,
                "official_abstract_excerpts": 53,
                "reviewed_arxiv_official_abstracts": 29,
                "reviewed_crossref_official_abstracts": 6,
                "core_conclusions": 53,
                "reviewed_open_pdf_resources": 4,
                "displayable_archive_relation_papers": 63,
            },
            receipt["release_expectation"],
        )
        self.assertEqual(
            29,
            receipt["arxiv_official_abstract_expectation"]["reviewed_count"],
        )
        self.assertEqual(
            53,
            receipt["arxiv_official_abstract_expectation"]["total_with_baseline"],
        )
        self.assertEqual(
            6,
            receipt["crossref_official_abstract_expectation"]["reviewed_count"],
        )
        self.assertEqual(
            ["P034", "P137", "P143"],
            receipt["arxiv_official_abstract_expectation"][
                "rights_blocked_with_source_evidence"
            ],
        )
        self.assertEqual([], receipt["crossref_rights_expectation"]["rights_ready_without_pdf_bytes"])
        self.assertEqual(["U055"], receipt["crossref_rights_expectation"]["fulltext_failed_closed"])
        self.assertEqual(34, receipt["open_pdf_review_expectation"]["reviewed_count"])
        self.assertEqual(4, receipt["open_pdf_review_expectation"]["allowed_count"])
        self.assertEqual(
            "0b22db44e113d0df299adb113b81cfc95bbdb9686c9329c4759e5e534ae66345",
            bindings["open_pdf_artifact_manifest"]["sha256"],
        )
        self.assertEqual(
            "801b9911885ab62988bf65cfff72007cb81104c51c76e05b9c96dea14fdfc3f3",
            bindings["open_pdf_independent_verification"]["sha256"],
        )

    @unittest.skipUnless(
        KNOWN_LIVE_DATABASE.is_file(),
        "retired frozen V4 replay fixture is not retained in the compact workspace",
    )
    def test_open_pdf_closed_set_accepts_performed_failures_and_rejects_partial(self) -> None:
        sources = _sources()
        plan = ReviewedMaterialImporter.static_plan(sources)
        self.assertEqual((34, 4, 30), (
            plan["open_pdf_reviewed_count"],
            plan["open_pdf_allowed_resources"],
            plan["open_pdf_fail_closed"],
        ))
        _, rows = _open_pdf_review_bundle(sources.open_pdf_review_summary)
        for source_id in ("P087", "P160", "P170"):
            self.assertEqual("fail_closed", rows[source_id]["decision"])
            self.assertTrue(rows[source_id]["get"]["performed"])
            self.assertIsNone(rows[source_id]["local_pdf"])
        with self.assertRaisesRegex(
            ReviewedMaterialImportError, "cannot be partially imported"
        ):
            ReviewedMaterialImporter.static_plan(
                sources, include_source_candidates=frozenset({"P094"})
            )

    def test_open_pdf_independent_json_cannot_be_resigned_as_a_new_bundle(self) -> None:
        sources = _sources()
        assert sources.open_pdf_review_summary is not None
        original = sources.open_pdf_review_summary.parent
        copied = self.root / "resigned-open-pdf-package"
        shutil.copytree(original, copied)
        independent = copied / "independent_verification.json"
        independent.write_bytes(independent.read_bytes() + b"\n")
        manifest = copied / "artifact_manifest.sha256"
        lines = []
        for path in sorted(
            (path for path in copied.rglob("*") if path.is_file() and path != manifest),
            key=lambda path: path.relative_to(copied).as_posix(),
        ):
            lines.append(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
                f"{path.relative_to(copied).as_posix()}"
            )
        manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(
            ReviewedMaterialImportError, "independently passed exact artifact"
        ):
            _open_pdf_review_bundle(copied / "summary.json")

    @unittest.skipUnless(
        KNOWN_LIVE_DATABASE.is_file(),
        "retired frozen V4 replay fixture is not retained in the compact workspace",
    )
    def test_input_descriptor_toctou_fails_closed(self) -> None:
        sources = _sources()
        plan = ReviewedMaterialImporter.static_plan(sources)
        expectation, expectation_identity = _load_dedup_expectation()
        receipt = _build_reviewed_gate_receipt(
            sources=sources,
            plan=plan,
            dedup_expectation=expectation,
            dedup_identity=expectation_identity,
        )
        changed = dict(receipt)
        changed["static_plan_sha256"] = "0" * 64
        with patch(
            "tools.replay_reviewed_evidence_total._build_reviewed_gate_receipt",
            return_value=changed,
        ), self.assertRaisesRegex(RuntimeError, "changed during synthetic TOCTOU"):
            _assert_reviewed_gate_stable(
                receipt,
                sources=sources,
                plan=plan,
                dedup_expectation=expectation,
                dedup_identity=expectation_identity,
                label="synthetic TOCTOU",
            )

        stale_plan = dict(plan)
        stale_plan["arxiv_reviewed"] = 0
        with self.assertRaisesRegex(RuntimeError, "static plan changed"):
            _build_reviewed_gate_receipt(
                sources=sources,
                plan=stale_plan,
                dedup_expectation=expectation,
                dedup_identity=expectation_identity,
            )

    def test_extra_identifier_alias_fails_the_closed_projection(self) -> None:
        expected = {("arxiv", "2002.08709"): "paper-expected"}
        actual = {
            **expected,
            ("doi", "10.0000/unreviewed-alias"): "paper-expected",
        }
        with self.assertRaisesRegex(RuntimeError, "extra=.*unreviewed-alias"):
            _assert_exact_identifier_projection(
                actual,
                expected,
                label="synthetic final",
            )
