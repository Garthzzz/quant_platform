from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from quant_hub.config import Settings
from quant_hub.collaboration.service import ArchiveCollaboration
from quant_hub.evidence.contracts import FetchAttemptInput
from quant_hub.evidence.repository import EvidenceRepository
from quant_hub.evidence.releases import EvidenceReleaseService
from quant_hub.evidence.resources import EvidenceResourceStore
from quant_hub.platform.migrations import migrate_up
from quant_hub.runtime_seal import RuntimeSealError
from tools import assemble_reviewed_delivery as assembly
from tools import publish_reviewed_evidence_release as promotion


REAL_FORMAL_ROOT = Path(__file__).resolve().parents[1]


def _copy_source_tree(source: Path, destination: Path) -> None:
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )


def _migrated_database(path: Path, migration_root: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path, isolation_level=None)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        migrate_up(connection, migration_root)


def _synthetic_reviewed_descriptor(name: str) -> dict[str, object]:
    return {
        "path": f"project_state/workers/synthetic/{name}.json",
        "bytes": len(name.encode("utf-8")),
        "sha256": hashlib.sha256(name.encode("utf-8")).hexdigest(),
    }


class AssemblyFixture:
    def __init__(self, *, seed_resource: bool = False) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temporary.name).resolve() / "workspace"
        self.formal = self.workspace / "quant_hub"
        self.var_root = self.formal / "var"
        self.source = self.var_root / "source-delivery"
        self.workers = self.workspace / "project_state" / "workers"
        self.evidence = self.workers / "evidence-review" / "replay"
        self.gates = self.workspace / "project_state" / "gates"
        self.output = self.var_root / "assembled-new"
        self.report = self.gates / "assembly" / "report.json"

        for path in (
            self.var_root,
            self.workers,
            self.gates,
            self.workspace / "reference" / "archive",
            self.workspace / "reference" / "proj2",
            self.formal / "paper_lab" / "papers",
        ):
            path.mkdir(parents=True, exist_ok=True)
        (self.workspace / "reference" / "archive" / "source.md").write_text(
            "archive bytes\n", encoding="utf-8"
        )
        (self.workspace / "reference" / "proj2" / "README.md").write_text(
            "proj2 bytes\n", encoding="utf-8"
        )

        _copy_source_tree(REAL_FORMAL_ROOT / "migrations", self.formal / "migrations")
        _copy_source_tree(
            REAL_FORMAL_ROOT / "src" / "quant_hub",
            self.formal / "src" / "quant_hub",
        )
        (self.formal / "tools").mkdir(parents=True)
        for name in assembly.RUNTIME_TOOLS:
            shutil.copy2(REAL_FORMAL_ROOT / "tools" / name, self.formal / "tools" / name)
        synthetic_publisher = (
            self.formal / "tools" / "publish_reviewed_evidence_release.py"
        )
        publisher_source = synthetic_publisher.read_text(encoding="utf-8")
        marker = "ALLOW_SYNTHETIC_TEST_MODE = False"
        if publisher_source.count(marker) != 1:
            raise AssertionError("publisher synthetic-test marker changed")
        synthetic_publisher.write_text(
            publisher_source.replace(marker, "ALLOW_SYNTHETIC_TEST_MODE = True"),
            encoding="utf-8",
            newline="\n",
        )
        shutil.copy2(
            REAL_FORMAL_ROOT / "tools" / "assemble_reviewed_delivery.py",
            self.formal / "tools" / "assemble_reviewed_delivery.py",
        )
        shutil.copy2(REAL_FORMAL_ROOT / "pyproject.toml", self.formal / "pyproject.toml")

        for name in assembly.SOURCE_MANAGED_TREES:
            (self.source / name).mkdir(parents=True, exist_ok=True)
        (self.source / "paper_lab" / "assets").mkdir()
        (self.source / "replay" / "evidence").mkdir()
        self.marker = self.source / "inbox" / "stable.txt"
        self.marker.write_text("stable source\n", encoding="utf-8")
        (self.source / "objects" / "object.txt").write_text(
            "object\n", encoding="utf-8"
        )
        (self.source / "paper_lab" / "assets" / "asset.txt").write_text(
            "asset\n", encoding="utf-8"
        )
        (self.source / "replay" / "evidence" / "receipt.txt").write_text(
            "receipt\n", encoding="utf-8"
        )

        roots = self.formal / "migrations"
        for domain in ("platform", "archive", "paper_lab"):
            _migrated_database(
                self.source / "db" / assembly.DATABASE_FILES[domain], roots / domain
            )
        source_settings = Settings.default(
            project_root=self.workspace,
            archive_root=self.workspace / "reference" / "archive",
            var_root=self.source,
            migration_root=roots / "platform",
        )
        ArchiveCollaboration(source_settings).backfill_research_updates()
        _migrated_database(
            self.evidence / "db" / assembly.DATABASE_FILES["research_papers"],
            roots / "research_papers",
        )
        evidence_settings = Settings.default(
            project_root=self.workspace,
            archive_root=self.workspace / "reference" / "archive",
            var_root=self.evidence,
            migration_root=roots / "platform",
        )
        if seed_resource:
            repository = EvidenceRepository(evidence_settings)
            repository.initialize()
            payload = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n%%EOF\n"
            paper = repository.create_paper(
                "report:assembly-promotion-resource",
                provenance_urn="qrh:test:assembly-promotion-resource",
            )
            digest = hashlib.sha256(payload).hexdigest()
            attempt = repository.record_fetch_attempt(
                FetchAttemptInput(
                    requested_url="https://example.test/paper.pdf",
                    redirect_chain=(),
                    final_url="https://example.test/paper.pdf",
                    http_status=200,
                    response_mime="application/pdf",
                    response_bytes=len(payload),
                    response_sha256=digest,
                    request_identity_hash="a" * 64,
                    rights_status="public_access_unknown_reuse",
                    legal_basis="test fixture",
                    result_status="succeeded",
                ),
                paper_id=paper.paper_id,
                candidate_id=None,
                attempt_key="assembly-promotion-resource",
            )
            staged = EvidenceResourceStore(evidence_settings).put_pdf(payload)
            repository.register_resource(
                paper_id=paper.paper_id,
                fetch_attempt_id=attempt.fetch_attempt_id,
                content_sha256=staged.content_sha256,
                size=staged.bytes,
                relative_path=staged.relative_path,
                rights_status="public_access_unknown_reuse",
            )
        # 真实 service 先形成一个静止、可重复 prepare 的 Evidence 输入。
        EvidenceReleaseService(evidence_settings).prepare_candidate()
        (self.evidence / "research_papers" / "objects").mkdir(exist_ok=True)
        input_names = {
            "crossref_rights_manifest",
            "crossref_identity_verdicts",
            "crossref_fulltext_manifest",
            "arxiv_materials_manifest",
            "arxiv_reading_records",
            "arxiv_total_delivery_manifest",
            "arxiv_resolution_seed",
            "arxiv_method_origin_inputs",
            "arxiv_independent_verdict",
            "dedup_expectation",
            "open_pdf_review_summary",
            "open_pdf_artifact_manifest",
            "open_pdf_independent_verification",
            "open_pdf_final_review",
            "displayable_archive_database",
            "displayable_research_database",
        }
        bindings = {
            name: _synthetic_reviewed_descriptor(name) for name in input_names
        }
        bindings["crossref_decisions"] = [
            _synthetic_reviewed_descriptor("crossref_decision")
        ]
        canonical_papers = 1 if seed_resource else 0
        verified_resources = 1 if seed_resource else 0
        self.release_expectation = {
            "canonical_papers": canonical_papers,
            "verified_resources": verified_resources,
            "canonicalization_receipts": 0,
            "formal_receipts": 0,
            "method_receipts": 0,
            "blocked_acquisitions": 0,
            "associated_method_ledger_occurrences": 0,
            "fulltext_conclusion_support": 0,
            "official_abstract_excerpts": 0,
            "reviewed_arxiv_official_abstracts": 0,
            "reviewed_crossref_official_abstracts": 0,
            "core_conclusions": 0,
            "reviewed_open_pdf_resources": 0,
            "displayable_archive_relation_papers": 0,
        }
        receipt = {
            "schema_version": assembly.REVIEWED_GATE_RECEIPT_SCHEMA,
            "fact_boundary": "Synthetic reviewed receipt for assembly contract tests only.",
            "arxiv_independent_gate": {
                "schema_version": "qrh-independent-arxiv-verdict/v4",
                "overall_status": "PASS",
                "release_authorized": True,
                "subject": {
                    **bindings["arxiv_total_delivery_manifest"],
                    "schema_version": "qrh-arxiv-expansion-delivery/v1",
                },
                "defects": [],
            },
            "arxiv_official_abstract_expectation": {
                "reviewed_count": 0,
                "total_with_baseline": 0,
                "normalization_contract": (
                    "xml.etree.ElementTree:atom.entry.summary:itertext:"
                    "regex-whitespace-collapse:strip:utf8/v1"
                ),
                "projection_sha256": hashlib.sha256(b"[]").hexdigest(),
                "rights_blocked_with_source_evidence": [],
                "local_pdf_rights_are_independent": True,
            },
            "crossref_official_abstract_expectation": {
                "reviewed_count": 0,
                "normalization_contract": (
                    "crossref.message.abstract:JATS/XML-fragment:itertext:"
                    "html-unescape:regex-whitespace-collapse:strip:utf8/v1"
                ),
                "projection_sha256": hashlib.sha256(b"[]").hexdigest(),
                "source_claim_not_fulltext_review": True,
            },
            "open_pdf_review_expectation": {
                "schema_version": "qrh-reviewed-open-pdf-import/v1",
                "reviewed_count": 0,
                "allowed_count": 0,
                "fail_closed_count": 0,
                "allowed_projection": [],
                "allowed_projection_sha256": assembly.payload_sha256([]),
                "final_review_sha256": "1" * 64,
                "frozen_input_database": bindings[
                    "displayable_research_database"
                ],
                "independent_verification_sha256": "2" * 64,
                "manifest": {
                    **bindings["open_pdf_artifact_manifest"],
                    "covered_files": 0,
                },
                "summary_sha256": "3" * 64,
            },
            "input_bindings": bindings,
            "static_plan_sha256": "a" * 64,
            "dedup_expectation": {
                "schema_version": "qrh-reviewed-evidence-dedup-expectation/v1",
                "expected_counts": {
                    "baseline": canonical_papers,
                    "crossref_incoming": 0,
                    "arxiv_incoming": 0,
                    "canonical_total": canonical_papers,
                    "incoming": 0,
                    "incoming_unique_identity_keys": 0,
                    "incoming_baseline_overlap": 0,
                    "created_new_canonical": 0,
                    "reused_baseline": 0,
                    "reused_incoming": 0,
                    "formal_citation_incoming": 0,
                    "associated_method_origin_incoming": 0,
                },
                "projection_hashes": {
                    "projection_encoding": (
                        "UTF-8 without BOM, LF terminated, "
                        "StringComparer.Ordinal line ordering"
                    ),
                    "baseline_identity_keys_lf_sha256": "b" * 64,
                    "incoming_identity_keys_lf_sha256": "c" * 64,
                    "union_identity_keys_lf_sha256": "d" * 64,
                    "incoming_action_tsv": {
                        "columns": [
                            "source_system",
                            "source_candidate_id",
                            "paper_source_candidate_id",
                            "treatment",
                            "identity_key",
                            "expected_action",
                            "expected_target_identity_key",
                        ],
                        "rows": 0,
                        "bytes": 0,
                        "sha256": "e" * 64,
                    },
                },
            },
            "crossref_rights_expectation": {
                "rights_ready_without_pdf_bytes": [],
                "fulltext_failed_closed": ["U055"],
                "rights_manifest": bindings["crossref_rights_manifest"],
                "u055_post_get_manifest": bindings["crossref_fulltext_manifest"],
            },
            "release_expectation": self.release_expectation,
        }
        self.reviewed_gate_receipt = (
            self.evidence
            / "research_papers"
            / assembly.REVIEWED_GATE_RECEIPT_RELATIVE_PATH.as_posix()
        )
        self.reviewed_gate_receipt.write_text(
            json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        receipt_identity = assembly.file_identity(self.reviewed_gate_receipt)
        self.expected_reviewed_gate_material = {
            "receipt_bytes": receipt_identity["bytes"],
            "receipt_sha256": receipt_identity["sha256"],
            "receipt_payload_sha256": assembly.payload_sha256(receipt),
            "input_bindings_sha256": assembly.payload_sha256(bindings),
            "dedup_expectation_sha256": assembly.payload_sha256(
                receipt["dedup_expectation"]
            ),
            "arxiv_subject_sha256": assembly.payload_sha256(
                receipt["arxiv_independent_gate"]["subject"]
            ),
            "arxiv_official_abstract_expectation_sha256": assembly.payload_sha256(
                receipt["arxiv_official_abstract_expectation"]
            ),
            "crossref_official_abstract_expectation_sha256": assembly.payload_sha256(
                receipt["crossref_official_abstract_expectation"]
            ),
            "open_pdf_review_expectation_sha256": assembly.payload_sha256(
                receipt["open_pdf_review_expectation"]
            ),
            "static_plan_sha256": receipt["static_plan_sha256"],
        }

    def close(self) -> None:
        self.temporary.cleanup()

    def rewrite_reviewed_gate_receipt(
        self,
        receipt: dict[str, object],
        *,
        accept_input_bindings: bool = False,
        accept_dedup_expectation: bool = False,
        accept_arxiv_subject: bool = False,
        accept_official_abstract_expectation: bool = False,
        accept_crossref_official_abstract_expectation: bool = False,
        accept_open_pdf_review_expectation: bool = False,
    ) -> dict[str, object]:
        self.reviewed_gate_receipt.write_text(
            json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        identity = assembly.file_identity(self.reviewed_gate_receipt)
        material = {
            **self.expected_reviewed_gate_material,
            "receipt_bytes": identity["bytes"],
            "receipt_sha256": identity["sha256"],
            "receipt_payload_sha256": assembly.payload_sha256(receipt),
        }
        if accept_input_bindings:
            material["input_bindings_sha256"] = assembly.payload_sha256(
                receipt["input_bindings"]
            )
        if accept_dedup_expectation:
            material["dedup_expectation_sha256"] = assembly.payload_sha256(
                receipt["dedup_expectation"]
            )
        if accept_arxiv_subject:
            material["arxiv_subject_sha256"] = assembly.payload_sha256(
                receipt["arxiv_independent_gate"]["subject"]
            )
        if accept_official_abstract_expectation:
            material["arxiv_official_abstract_expectation_sha256"] = (
                assembly.payload_sha256(
                    receipt["arxiv_official_abstract_expectation"]
                )
            )
        if accept_crossref_official_abstract_expectation:
            material["crossref_official_abstract_expectation_sha256"] = (
                assembly.payload_sha256(
                    receipt["crossref_official_abstract_expectation"]
                )
            )
        if accept_open_pdf_review_expectation:
            material["open_pdf_review_expectation_sha256"] = (
                assembly.payload_sha256(receipt["open_pdf_review_expectation"])
            )
        return material

    def assemble(
        self,
        *,
        prepare_candidate=None,
        expected_reviewed_gate_material: dict[str, object] | None = None,
        synthetic_test_mode: bool = True,
    ) -> dict[str, object]:
        return assembly.assemble_delivery(
            source_delivery_var=self.source,
            evidence_candidate_var=self.evidence,
            output_var=self.output,
            report=self.report,
            minimum_evidence_papers=0,
            minimum_evidence_resources=0,
            expected_paper_lab_papers=0,
            expected_reviewed_release=self.release_expectation,
            expected_reviewed_gate_material=(
                self.expected_reviewed_gate_material
                if expected_reviewed_gate_material is None
                else expected_reviewed_gate_material
            ),
            workspace_root=self.workspace,
            formal_root=self.formal,
            execution_material_paths={
                "assembler": self.formal / "tools" / "assemble_reviewed_delivery.py",
                "runtime_seal": self.formal / "src" / "quant_hub" / "runtime_seal.py",
                "pyproject": self.formal / "pyproject.toml",
            },
            synthetic_test_mode=synthetic_test_mode,
            **(
                {"prepare_candidate": prepare_candidate}
                if prepare_candidate is not None
                else {}
            ),
        )


class AssemblyBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name).resolve() / "workspace"
        self.formal = self.workspace / "quant_hub"
        self.var = self.formal / "var"
        self.source = self.var / "source"
        self.evidence = self.workspace / "project_state" / "workers" / "evidence"
        self.gates = self.workspace / "project_state" / "gates"
        for path in (
            self.source,
            self.evidence,
            self.gates,
            self.workspace / "reference" / "archive",
            self.workspace / "reference" / "proj2",
        ):
            path.mkdir(parents=True, exist_ok=True)

    def test_output_and_report_must_not_escape_workspace_scopes(self) -> None:
        with self.assertRaisesRegex(RuntimeSealError, "output-var"):
            assembly._resolve_paths(
                source_delivery_var=self.source,
                evidence_candidate_var=self.evidence,
                output_var=self.workspace.parent / "escaped-output",
                report=self.gates / "report.json",
                workspace_root=self.workspace,
                formal_root=self.formal,
            )
        with self.assertRaisesRegex(RuntimeSealError, "report"):
            assembly._resolve_paths(
                source_delivery_var=self.source,
                evidence_candidate_var=self.evidence,
                output_var=self.var / "new-output",
                report=self.workspace / "escaped-report.json",
                workspace_root=self.workspace,
                formal_root=self.formal,
            )

    def test_source_and_output_are_direct_var_children(self) -> None:
        nested = self.source / "nested"
        nested.mkdir()
        with self.assertRaisesRegex(RuntimeSealError, "direct child"):
            assembly._resolve_paths(
                source_delivery_var=nested,
                evidence_candidate_var=self.evidence,
                output_var=self.var / "new-output",
                report=self.gates / "report.json",
                workspace_root=self.workspace,
                formal_root=self.formal,
            )

    def test_existing_output_or_report_is_never_overwritten(self) -> None:
        output = self.var / "existing"
        output.mkdir()
        with self.assertRaises(FileExistsError):
            assembly._resolve_paths(
                source_delivery_var=self.source,
                evidence_candidate_var=self.evidence,
                output_var=output,
                report=self.gates / "report.json",
                workspace_root=self.workspace,
                formal_root=self.formal,
            )
        report = self.gates / "existing.json"
        report.write_text("{}", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            assembly._resolve_paths(
                source_delivery_var=self.source,
                evidence_candidate_var=self.evidence,
                output_var=self.var / "new-output",
                report=report,
                workspace_root=self.workspace,
                formal_root=self.formal,
            )


class ReviewedDeliveryAssemblyTests(unittest.TestCase):
    def fixture(self, *, seed_resource: bool = False) -> AssemblyFixture:
        fixture = AssemblyFixture(seed_resource=seed_resource)
        self.addCleanup(fixture.close)
        return fixture

    def test_reviewed_contract_injection_is_rejected_outside_synthetic_mode(self) -> None:
        fixture = self.fixture()
        with self.assertRaisesRegex(
            ValueError, "contract injection is forbidden"
        ):
            fixture.assemble(synthetic_test_mode=False)
        self.assertFalse(fixture.output.exists())
        self.assertFalse(fixture.report.exists())

    def test_extra_root_export_is_rejected_before_sealing(self) -> None:
        fixture = self.fixture()
        (fixture.source / "exports" / "undeclared.json").write_text(
            "{}\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(RuntimeSealError, "only the canonical history"):
            fixture.assemble()
        self.assertFalse(fixture.output.exists())
        self.assertFalse(fixture.report.exists())

    def test_pending_research_update_export_is_rejected_before_sealing(self) -> None:
        fixture = self.fixture()
        database = fixture.source / "db" / assembly.DATABASE_FILES["archive"]
        with closing(sqlite3.connect(database)) as connection:
            connection.execute(
                """
                INSERT INTO outbox_event(
                    event_id,event_type,event_version,aggregate_urn,payload_json,
                    payload_hash,created_at,published_at,publish_attempt_count
                ) VALUES(?,?,?,?,?,?,?,NULL,0)
                """,
                (
                    "evt_pending_update_export",
                    "ArchiveResearchUpdateAnnotated",
                    "1",
                    "qrh:research-update:pending",
                    "{}",
                    "0" * 64,
                    "2026-07-17T00:00:00Z",
                ),
            )
            connection.commit()
        with self.assertRaisesRegex(RuntimeSealError, "pending outbox"):
            fixture.assemble()
        self.assertFalse(fixture.output.exists())

    def test_research_update_checkpoint_drift_is_rejected_before_sealing(self) -> None:
        fixture = self.fixture()
        database = fixture.source / "db" / assembly.DATABASE_FILES["archive"]
        with closing(sqlite3.connect(database)) as connection:
            connection.execute(
                """
                UPDATE research_update_export_checkpoint
                SET history_sha256=?
                WHERE export_name='research_update_history.jsonl'
                """,
                ("f" * 64,),
            )
            connection.commit()
        with self.assertRaisesRegex(RuntimeSealError, "checkpoint differs"):
            fixture.assemble()
        self.assertFalse(fixture.output.exists())

    def test_seal_binds_runtime_databases_resources_and_prepared_evidence(self) -> None:
        fixture = self.fixture()
        result = fixture.assemble()
        seal_path = fixture.output / "ASSEMBLY_SEAL.json"
        seal_bytes = seal_path.read_bytes()
        seal = json.loads(seal_bytes.decode("utf-8"))
        report = json.loads(fixture.report.read_text(encoding="utf-8"))

        self.assertEqual(seal["schema_version"], assembly.SEAL_SCHEMA_VERSION)
        self.assertEqual(seal["status"], "PASS")
        self.assertIs(seal["synthetic_test_mode"], True)
        self.assertEqual(seal["delivery_var"], str(fixture.output.resolve()))
        self.assertEqual(set(seal["databases"]), set(assembly.DATABASE_FILES))
        for domain in assembly.DATABASE_FILES:
            database_path = fixture.output / "db" / assembly.DATABASE_FILES[domain]
            with closing(sqlite3.connect(database_path)) as connection:
                self.assertEqual(
                    "delete",
                    str(connection.execute("PRAGMA journal_mode").fetchone()[0]).casefold(),
                )
            contract = seal["databases"][domain]["database_contract"]
            self.assertTrue(contract["tables"])
            self.assertEqual(len(contract["schema_sha256"]), 64)
            self.assertEqual(
                len(seal["databases"][domain]["database_contract_sha256"]),
                64,
            )
            self.assertEqual(
                seal["databases"][domain]["fresh_schema"]["schema_sha256"],
                contract["schema_sha256"],
            )
        self.assertEqual(
            seal["evidence"]["repository_snapshot_hash"],
            seal["evidence"]["candidate_spec"]["source_snapshot_hash"],
        )
        self.assertIn("inventory", seal["evidence"]["inventory_exports"])
        self.assertIn("evidence_release", seal["databases"]["research_papers"]["database_contract"]["tables"])
        self.assertEqual(seal["resource_contract"]["audit"]["missing_paths"], [])
        self.assertEqual(seal["resource_contract"]["audit"]["orphaned_paths"], [])
        reviewed_receipt = seal["evidence"]["reviewed_gate_receipt"]
        self.assertEqual(
            reviewed_receipt,
            seal["resource_contract"]["reviewed_gate_receipt"],
        )
        self.assertEqual(
            reviewed_receipt,
            seal["source_inputs"]["reviewed_gate_receipt"],
        )
        receipt_bytes = fixture.reviewed_gate_receipt.read_bytes()
        self.assertEqual(
            reviewed_receipt["descriptor"],
            {
                "relative_path": "exports/reviewed_total_gate_receipt.json",
                "bytes": len(receipt_bytes),
                "sha256": hashlib.sha256(receipt_bytes).hexdigest(),
            },
        )
        sealed_receipt = (
            fixture.output
            / "research_papers"
            / "exports"
            / "reviewed_total_gate_receipt.json"
        )
        self.assertEqual(sealed_receipt.read_bytes(), receipt_bytes)
        self.assertEqual(
            reviewed_receipt["release_expectation"],
            {
                name: seal["evidence"]["counts"][name]
                for name in assembly.REVIEWED_RELEASE_EXPECTATION_KEYS
            },
        )
        self.assertEqual(seal["paper_lab_papers"], 0)
        self.assertEqual(
            seal["managed_trees"]["inbox"]["source_before"],
            seal["managed_trees"]["inbox"]["target_after_copy"],
        )
        runtime = seal["runtime_contract"]
        self.assertEqual(
            runtime["code"]["sealed_tree"],
            assembly.safe_tree(
                fixture.output / "runtime_contract" / "code",
                exclude_runtime_caches=True,
            ),
        )
        self.assertEqual(
            runtime["migrations"]["sealed_tree"],
            assembly.safe_tree(fixture.output / "runtime_contract" / "migrations"),
        )
        toolchain = runtime["toolchain"]
        self.assertEqual(
            len(toolchain["sealed_contract"]["python_executable_identity"]["sha256"]),
            64,
        )
        audit_toolchain = toolchain["audit"]
        self.assertIn(
            "flask",
            {name.casefold() for name in audit_toolchain["direct_dependencies"]},
        )
        self.assertIn("werkzeug", audit_toolchain["runtime_dependencies"])
        execution_materials = runtime["execution_materials"]
        self.assertEqual(
            execution_materials,
            seal["source_inputs"]["execution_materials"],
        )
        for name in ("assembler", "runtime_seal", "pyproject"):
            self.assertEqual(
                execution_materials[name]["identity"],
                execution_materials[name]["final_identity"],
            )

        seal_hash = hashlib.sha256(seal_bytes).hexdigest()
        self.assertEqual(report["assembly_seal_sha256"], seal_hash)
        self.assertEqual(result["assembly_seal_sha256"], seal_hash)
        self.assertEqual(
            [path.name for path in fixture.output.glob("*SEAL*.json")],
            ["ASSEMBLY_SEAL.json"],
        )

    def test_real_assembly_gate_publish_recovery_and_activation_contract(self) -> None:
        fixture = self.fixture(seed_resource=True)
        fixture.assemble()
        seal_path = fixture.output / "ASSEMBLY_SEAL.json"
        seal = json.loads(seal_path.read_text(encoding="utf-8"))
        review_root = fixture.workers / "independent-integration-review"
        review_root.mkdir(parents=True)
        artifacts: list[dict[str, str]] = []
        for kind in sorted(promotion.REQUIRED_REVIEW_KINDS):
            if kind == "assembly_report":
                path = fixture.report
            else:
                path = review_root / f"{kind}.json"
                path.write_text(
                    json.dumps(
                        {"schema_version": f"test-{kind}/v1", "status": "PASS"},
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
            artifacts.append(
                {
                    "kind": kind,
                    "path": str(path.resolve()),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
        gate_path = fixture.gates / "integration" / "gate.json"
        gate_path.parent.mkdir(parents=True)
        gate = {
            "schema_version": promotion.GATE_SCHEMA,
            "status": "PASS",
            "delivery_var": str(fixture.output.resolve()),
            "assembly_seal_sha256": hashlib.sha256(seal_path.read_bytes()).hexdigest(),
            "candidate_spec": seal["evidence"]["candidate_spec"],
            "evidence_counts": seal["evidence"]["counts"],
            "reconciliation_policy": "test fixture: immutable reviewed identities",
            "review_artifacts": artifacts,
        }
        gate_path.write_text(
            json.dumps(gate, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        publisher = (
            fixture.output
            / "runtime_contract"
            / "code"
            / "tools"
            / "publish_reviewed_evidence_release.py"
        )

        def run(report: Path, *extra: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(publisher),
                    "--project-root",
                    str(fixture.workspace),
                    "--delivery-var",
                    str(fixture.output),
                    "--gate",
                    str(gate_path),
                    "--report",
                    str(report),
                    *extra,
                ],
                cwd=fixture.workspace,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
                check=False,
            )

        failed_report = fixture.gates / "promotion" / "must-not-exist.json"
        failed = run(failed_report, "--fail-after-phase", "activation")
        self.assertNotEqual(failed.returncode, 0, failed.stdout)
        self.assertIn("injected promotion failure", failed.stderr)
        self.assertFalse(failed_report.exists())
        self.assertTrue((fixture.output / "PROMOTION_STATE.json").is_file())
        self.assertFalse((fixture.output / "ACTIVATED_DELIVERY_SEAL.json").exists())

        report_path = fixture.gates / "promotion" / "recovered.json"
        recovered = run(report_path)
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["status"], "PASS")
        self.assertTrue(report["recovered_or_idempotent"])

        activation_path = fixture.output / "ACTIVATED_DELIVERY_SEAL.json"
        activation = json.loads(activation_path.read_text(encoding="utf-8"))
        runtime = activation["runtime_contract"]
        self.assertEqual(
            runtime["code"],
            assembly.safe_tree(
                fixture.output / "runtime_contract" / "code",
                exclude_runtime_caches=True,
            ),
        )
        self.assertEqual(
            runtime["migrations"],
            assembly.safe_tree(fixture.output / "runtime_contract" / "migrations"),
        )
        self.assertEqual(runtime["toolchain"], assembly.runtime_toolchain())
        for filename in promotion.DATABASE_NAMES:
            self.assertEqual(
                activation["databases"][filename],
                assembly.database_state(fixture.output / "db" / filename),
            )
        for name in promotion.MANAGED_TREE_NAMES:
            self.assertEqual(
                activation["managed_trees"][name],
                assembly.safe_tree(fixture.output / name),
            )

        startup_artifacts: list[dict[str, str]] = []
        for kind in (
            "activation_report",
            "browser_acceptance",
            "full_regression",
            "deployment_verdict",
        ):
            path = review_root / f"startup-{kind}.json"
            path.write_text(
                json.dumps({"kind": kind, "status": "PASS"}, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            startup_artifacts.append(
                {
                    "kind": kind,
                    "path": str(path.resolve()),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
        startup_gate = fixture.gates / "startup" / "gate.json"
        startup_gate.parent.mkdir(parents=True)
        delivery_identity = hashlib.sha256(
            str(fixture.output.resolve()).casefold().encode("utf-8")
        ).hexdigest()[:20]
        bootstrap_receipt = (
            fixture.workspace
            / "project_state"
            / "runtime"
            / "bootstrap_receipts"
            / f"{fixture.output.name}-{delivery_identity}.json"
        )
        startup_gate.write_text(
            json.dumps(
                {
                    "schema_version": "qrh-reviewed-startup-gate/v1",
                    "status": "PASS",
                    "delivery_var": str(fixture.output.resolve()),
                    "initial_launch_mode": "strict",
                    "bootstrap_receipt_policy": {
                        "policy_version": "qrh-reviewed-runtime-bootstrap-policy/v1",
                        "mutation_policy_version": "qrh-reviewed-runtime-mutations/v1",
                        "path": str(bootstrap_receipt.resolve()),
                    },
                    "activation_seal_sha256": hashlib.sha256(
                        activation_path.read_bytes()
                    ).hexdigest(),
                    "review_artifacts": startup_artifacts,
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        frozen_run_local = (
            fixture.output / "runtime_contract" / "code" / "tools" / "run_local.py"
        )
        validator_code = """
import importlib.util
from pathlib import Path
import sys
spec = importlib.util.spec_from_file_location('sealed_run_local', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module._validate_sealed_runtime(
    project=Path(sys.argv[2]).resolve(),
    delivery=Path(sys.argv[3]).resolve(),
    migration_root=Path(sys.argv[4]).resolve(),
    activation_path=Path(sys.argv[5]).resolve(),
    startup_gate_path=Path(sys.argv[6]).resolve(),
    resume=False,
)
print('sealed-runtime-valid')
"""
        runtime_validation = subprocess.run(
            [
                sys.executable,
                "-B",
                "-c",
                validator_code,
                str(frozen_run_local),
                str(fixture.workspace),
                str(fixture.output),
                str(fixture.output / "runtime_contract" / "migrations" / "platform"),
                str(activation_path),
                str(startup_gate),
            ],
            cwd=fixture.workspace,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
        self.assertEqual(runtime_validation.returncode, 0, runtime_validation.stderr)
        self.assertIn("sealed-runtime-valid", runtime_validation.stdout)

        main_code = """
import importlib.util
import json
from pathlib import Path
import sys
spec = importlib.util.spec_from_file_location('sealed_run_local_main', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
captured = {}
class FakeApp:
    def run(self, **kwargs):
        captured['run'] = kwargs
def fake_create_app(settings, config):
    captured['project_root'] = str(settings.project_root)
    captured['archive_root'] = str(settings.archive_root)
    captured['var_root'] = str(settings.var_root)
    captured['config'] = config
    return FakeApp()
module.create_app = fake_create_app
resume = len(sys.argv) > 7 and sys.argv[7] == 'resume'
sys.argv = [
    sys.argv[1],
    '--var-root', sys.argv[3],
    '--migration-root', sys.argv[4],
    '--activation-seal', sys.argv[5],
    '--startup-gate', sys.argv[6],
]
if resume:
    sys.argv.append('--resume-reviewed-runtime')
module.main()
print('MAIN_CAPTURE=' + json.dumps(captured, sort_keys=True))
"""
        main_command = [
                sys.executable,
                "-B",
                "-c",
                main_code,
                str(frozen_run_local),
                str(fixture.workspace),
                str(fixture.output),
                str(fixture.output / "runtime_contract" / "migrations" / "platform"),
                str(activation_path),
                str(startup_gate),
            ]
        resume_before_bootstrap = subprocess.run(
            [*main_command, "resume"],
            cwd=fixture.workspace,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
        self.assertNotEqual(resume_before_bootstrap.returncode, 0)
        self.assertIn("no successful strict bootstrap receipt", resume_before_bootstrap.stderr)

        main_validation = subprocess.run(
            main_command,
            cwd=fixture.workspace,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
        self.assertEqual(main_validation.returncode, 0, main_validation.stderr)
        capture_line = next(
            line
            for line in main_validation.stdout.splitlines()
            if line.startswith("MAIN_CAPTURE=")
        )
        captured = json.loads(capture_line.removeprefix("MAIN_CAPTURE="))
        self.assertEqual(captured["project_root"], str(fixture.workspace.resolve()))
        self.assertEqual(
            captured["archive_root"],
            str((fixture.workspace / "reference" / "archive").resolve()),
        )
        self.assertEqual(captured["var_root"], str(fixture.output.resolve()))
        self.assertFalse(captured["config"]["INITIALIZE_ARCHIVE_CATALOG"])
        self.assertEqual(
            captured["config"]["COMMENT_DATABASE_PATH"],
            str(fixture.workspace / "quant_hub" / "data" / "comments.sqlite3"),
        )
        self.assertEqual(
            captured["config"]["RESEARCH_WORKSPACE_DATABASE_PATH"],
            str(
                fixture.workspace
                / "quant_hub"
                / "data"
                / "research_workspace.sqlite3"
            ),
        )
        self.assertEqual(captured["run"]["host"], "localhost")
        self.assertEqual(captured["run"]["port"], 8765)
        self.assertTrue(bootstrap_receipt.is_file())
        bootstrap_payload = json.loads(bootstrap_receipt.read_text(encoding="utf-8"))
        self.assertEqual(
            "qrh-reviewed-runtime-bootstrap-receipt/v1",
            bootstrap_payload["schema_version"],
        )
        self.assertEqual("strict", bootstrap_payload["initial_launch_mode"])
        self.assertEqual(
            set(promotion.DATABASE_NAMES),
            set(bootstrap_payload["runtime_state_after_create_app"]["databases"]),
        )

        resume_after_bootstrap = subprocess.run(
            [*main_command, "resume"],
            cwd=fixture.workspace,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
        self.assertEqual(
            resume_after_bootstrap.returncode, 0, resume_after_bootstrap.stderr
        )

        repeated_report = fixture.gates / "promotion" / "repeated.json"
        repeated = run(repeated_report)
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertEqual(
            json.loads(repeated_report.read_text(encoding="utf-8"))["status"],
            "PASS",
        )

    def test_sqlite_sidecar_fails_before_candidate_creation(self) -> None:
        fixture = self.fixture()
        sidecar = Path(f"{fixture.source / 'db' / 'platform.sqlite3'}-wal")
        sidecar.write_bytes(b"unsealed WAL")
        with self.assertRaisesRegex(RuntimeSealError, "quiescent"):
            fixture.assemble()
        self.assertFalse(fixture.output.exists())

    def test_missing_reviewed_total_gate_receipt_fails_before_candidate_creation(self) -> None:
        fixture = self.fixture()
        fixture.reviewed_gate_receipt.unlink()
        with self.assertRaisesRegex(RuntimeSealError, "reviewed total gate receipt is missing"):
            fixture.assemble()
        self.assertFalse(fixture.output.exists())

    def test_reviewed_total_gate_receipt_schema_tamper_is_rejected(self) -> None:
        fixture = self.fixture()
        receipt = json.loads(fixture.reviewed_gate_receipt.read_text(encoding="utf-8"))
        receipt["schema_version"] = "qrh-reviewed-evidence-gate-receipt/tampered"
        fixture.reviewed_gate_receipt.write_text(
            json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        with self.assertRaisesRegex(RuntimeSealError, "unexpected sealed JSON schema"):
            fixture.assemble()
        self.assertFalse(fixture.output.exists())

    def test_reviewed_total_gate_receipt_wrong_count_is_rejected(self) -> None:
        fixture = self.fixture()
        receipt = json.loads(fixture.reviewed_gate_receipt.read_text(encoding="utf-8"))
        receipt["release_expectation"]["canonical_papers"] = 1
        receipt["dedup_expectation"]["expected_counts"]["canonical_total"] = 1
        receipt["dedup_expectation"]["expected_counts"]["baseline"] = 1
        material = fixture.rewrite_reviewed_gate_receipt(
            receipt, accept_dedup_expectation=True
        )
        with self.assertRaisesRegex(RuntimeSealError, "does not match the assembly release"):
            fixture.assemble(expected_reviewed_gate_material=material)

    def test_legacy_ten_field_release_expectation_is_rejected(self) -> None:
        fixture = self.fixture()
        receipt = json.loads(fixture.reviewed_gate_receipt.read_text(encoding="utf-8"))
        for field in (
            "reviewed_crossref_official_abstracts",
            "core_conclusions",
            "reviewed_open_pdf_resources",
            "displayable_archive_relation_papers",
        ):
            del receipt["release_expectation"][field]
        material = fixture.rewrite_reviewed_gate_receipt(receipt)
        with self.assertRaisesRegex(RuntimeSealError, "release expectation is incomplete"):
            fixture.assemble(expected_reviewed_gate_material=material)

    def test_official_abstract_expectation_is_bound_and_count_reconciled(self) -> None:
        for field in ("projection", "count", "missing"):
            with self.subTest(field=field):
                fixture = self.fixture()
                receipt = json.loads(
                    fixture.reviewed_gate_receipt.read_text(encoding="utf-8")
                )
                expectation = receipt["arxiv_official_abstract_expectation"]
                if field == "projection":
                    expectation["projection_sha256"] = "invalid"
                    expected_message = "official abstract expectation changed"
                elif field == "count":
                    expectation["total_with_baseline"] = 1
                    expected_message = (
                        "official abstract expectation and release counts disagree"
                    )
                else:
                    del expectation["normalization_contract"]
                    expected_message = "official abstract expectation changed"
                material = fixture.rewrite_reviewed_gate_receipt(
                    receipt, accept_official_abstract_expectation=True
                )
                with self.assertRaisesRegex(RuntimeSealError, expected_message):
                    fixture.assemble(expected_reviewed_gate_material=material)

    def test_crossref_abstract_expectation_is_bound_and_count_reconciled(self) -> None:
        for field in ("projection", "count", "missing"):
            with self.subTest(field=field):
                fixture = self.fixture()
                receipt = json.loads(
                    fixture.reviewed_gate_receipt.read_text(encoding="utf-8")
                )
                expectation = receipt["crossref_official_abstract_expectation"]
                if field == "projection":
                    expectation["projection_sha256"] = "invalid"
                    expected_message = "Crossref official abstract expectation changed"
                elif field == "count":
                    expectation["reviewed_count"] = 1
                    expected_message = (
                        "official abstract expectation and release counts disagree"
                    )
                else:
                    del expectation["normalization_contract"]
                    expected_message = "Crossref official abstract expectation changed"
                material = fixture.rewrite_reviewed_gate_receipt(
                    receipt,
                    accept_crossref_official_abstract_expectation=True,
                )
                with self.assertRaisesRegex(RuntimeSealError, expected_message):
                    fixture.assemble(expected_reviewed_gate_material=material)

    def test_open_pdf_review_expectation_is_bound_and_conserved(self) -> None:
        for field in ("projection", "conservation", "missing"):
            with self.subTest(field=field):
                fixture = self.fixture()
                receipt = json.loads(
                    fixture.reviewed_gate_receipt.read_text(encoding="utf-8")
                )
                expectation = receipt["open_pdf_review_expectation"]
                if field == "projection":
                    expectation["allowed_projection_sha256"] = "0" * 64
                elif field == "conservation":
                    expectation["reviewed_count"] = 1
                else:
                    del expectation["summary_sha256"]
                material = fixture.rewrite_reviewed_gate_receipt(
                    receipt,
                    accept_open_pdf_review_expectation=True,
                )
                with self.assertRaisesRegex(
                    RuntimeSealError, "open PDF expectation changed"
                ):
                    fixture.assemble(expected_reviewed_gate_material=material)

    def test_duplicate_crossref_decision_is_rejected_after_outer_hash_rebind(self) -> None:
        fixture = self.fixture()
        receipt = json.loads(fixture.reviewed_gate_receipt.read_text(encoding="utf-8"))
        decisions = receipt["input_bindings"]["crossref_decisions"]
        decisions.append(dict(decisions[0]))
        material = fixture.rewrite_reviewed_gate_receipt(
            receipt, accept_input_bindings=True
        )
        with self.assertRaisesRegex(RuntimeSealError, "decision descriptors are duplicated"):
            fixture.assemble(expected_reviewed_gate_material=material)

    def test_arxiv_subject_or_verdict_binding_tamper_is_rejected(self) -> None:
        for field in ("subject", "verdict"):
            with self.subTest(field=field):
                fixture = self.fixture()
                receipt = json.loads(
                    fixture.reviewed_gate_receipt.read_text(encoding="utf-8")
                )
                if field == "subject":
                    receipt["arxiv_independent_gate"]["subject"]["bytes"] += 1
                    expected_message = "arXiv V4 subject binding changed"
                else:
                    receipt["input_bindings"]["arxiv_independent_verdict"] = (
                        _synthetic_reviewed_descriptor("replacement-verdict")
                    )
                    expected_message = "input binding identities changed"
                material = fixture.rewrite_reviewed_gate_receipt(receipt)
                with self.assertRaisesRegex(RuntimeSealError, expected_message):
                    fixture.assemble(expected_reviewed_gate_material=material)

    def test_dedup_conservation_or_projection_tamper_is_rejected_after_outer_hash_rebind(self) -> None:
        for field in ("baseline", "overlap", "projection"):
            with self.subTest(field=field):
                fixture = self.fixture()
                receipt = json.loads(
                    fixture.reviewed_gate_receipt.read_text(encoding="utf-8")
                )
                if field == "baseline":
                    receipt["dedup_expectation"]["expected_counts"]["baseline"] = 999
                    expected_message = "dedup expectation and release expectation disagree"
                elif field == "overlap":
                    receipt["dedup_expectation"]["expected_counts"][
                        "incoming_baseline_overlap"
                    ] = 1
                    expected_message = "dedup expectation and release expectation disagree"
                else:
                    receipt["dedup_expectation"]["projection_hashes"][
                        "baseline_identity_keys_lf_sha256"
                    ] = "invalid"
                    expected_message = "dedup projection seal changed"
                material = fixture.rewrite_reviewed_gate_receipt(
                    receipt, accept_dedup_expectation=True
                )
                with self.assertRaisesRegex(RuntimeSealError, expected_message):
                    fixture.assemble(expected_reviewed_gate_material=material)

    def test_reviewed_total_gate_receipt_drift_during_prepare_is_rejected(self) -> None:
        fixture = self.fixture()

        def tampering_prepare(settings):
            fixture.reviewed_gate_receipt.write_bytes(
                fixture.reviewed_gate_receipt.read_bytes() + b" "
            )
            return assembly._prepare_evidence_candidate(settings)

        with self.assertRaisesRegex(RuntimeSealError, "managed source final research_papers"):
            fixture.assemble(prepare_candidate=tampering_prepare)

    def test_receipt_drift_after_last_preseal_read_removes_pass_seal(self) -> None:
        fixture = self.fixture()
        original = assembly._reviewed_gate_receipt_contract
        calls = 0

        def tampering_read(*args, **kwargs):
            nonlocal calls
            result = original(*args, **kwargs)
            calls += 1
            if calls == 5:
                fixture.reviewed_gate_receipt.write_bytes(
                    fixture.reviewed_gate_receipt.read_bytes() + b" "
                )
            return result

        with mock.patch.object(
            assembly, "_reviewed_gate_receipt_contract", side_effect=tampering_read
        ):
            with self.assertRaisesRegex(
                RuntimeSealError, "managed source after seal write research_papers"
            ):
                fixture.assemble()
        self.assertFalse((fixture.output / "ASSEMBLY_SEAL.json").exists())
        self.assertFalse(fixture.report.exists())

    def test_schema_not_reconstructable_from_frozen_migrations_is_rejected(self) -> None:
        fixture = self.fixture()
        archive_db = fixture.source / "db" / "archive.sqlite3"
        with closing(sqlite3.connect(archive_db)) as connection:
            connection.execute("CREATE TABLE unreviewed_schema(value TEXT)")
            connection.commit()
        with self.assertRaisesRegex(RuntimeSealError, "fresh schema replay archive"):
            fixture.assemble()

    def test_orphan_research_object_is_rejected(self) -> None:
        fixture = self.fixture()
        orphan = fixture.evidence / "research_papers" / "objects" / "orphan.pdf"
        orphan.write_bytes(b"%PDF-1.4\n%%EOF\n")
        with self.assertRaisesRegex(RuntimeSealError, "resource closure"):
            fixture.assemble()

    def test_migration_root_rejects_an_unreviewed_extra_domain(self) -> None:
        fixture = self.fixture()
        (fixture.formal / "migrations" / "unreviewed").mkdir()
        with self.assertRaisesRegex(RuntimeSealError, "exactly the reviewed domains"):
            fixture.assemble()
        self.assertFalse(fixture.output.exists())

    def test_nested_reserved_seal_name_is_rejected_before_output(self) -> None:
        fixture = self.fixture()
        (fixture.source / "inbox" / "ASSEMBLY_SEAL.json").write_text(
            "{}\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(RuntimeSealError, "reserved ASSEMBLY_SEAL"):
            fixture.assemble()
        self.assertFalse(fixture.output.exists())

    def test_managed_hardlink_is_rejected_when_supported(self) -> None:
        fixture = self.fixture()
        hardlink = fixture.source / "inbox" / "hardlink.txt"
        try:
            os.link(fixture.marker, hardlink)
        except OSError as error:
            self.skipTest(f"hard links unavailable: {error}")
        with self.assertRaisesRegex(RuntimeSealError, "single-link|unsafe"):
            fixture.assemble()
        self.assertFalse(fixture.output.exists())

    def test_managed_symlink_or_reparse_is_rejected_when_supported(self) -> None:
        fixture = self.fixture()
        link = fixture.source / "inbox" / "linked.txt"
        try:
            os.symlink(fixture.marker, link)
        except OSError as error:
            self.skipTest(f"symlinks unavailable: {error}")
        with self.assertRaisesRegex(RuntimeSealError, "reparse|link"):
            fixture.assemble()
        self.assertFalse(fixture.output.exists())

    def test_source_tree_drift_during_copy_is_rejected(self) -> None:
        fixture = self.fixture()
        original = assembly._copy_tree_contents
        mutated = False

        def drifting_copy(source: Path, destination: Path, *, exclude_runtime_caches: bool) -> None:
            nonlocal mutated
            original(
                source,
                destination,
                exclude_runtime_caches=exclude_runtime_caches,
            )
            if source == fixture.source / "inbox" and not mutated:
                mutated = True
                fixture.marker.write_text("drifted source\n", encoding="utf-8")

        with mock.patch.object(assembly, "_copy_tree_contents", side_effect=drifting_copy):
            with self.assertRaisesRegex(RuntimeSealError, "source after copy"):
                fixture.assemble()

    def test_assembler_byte_drift_during_prepare_is_rejected(self) -> None:
        fixture = self.fixture()
        assembler_path = fixture.formal / "tools" / "assemble_reviewed_delivery.py"

        def tampering_prepare(settings):
            assembler_path.write_bytes(assembler_path.read_bytes() + b"\n# drift\n")
            return assembly._prepare_evidence_candidate(settings)

        with self.assertRaisesRegex(RuntimeSealError, "execution material final assembler"):
            fixture.assemble(prepare_candidate=tampering_prepare)


if __name__ == "__main__":
    unittest.main()
