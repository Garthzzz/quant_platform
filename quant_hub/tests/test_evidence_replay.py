from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from quant_hub.config import Settings
from quant_hub.evidence.replay import (
    EvidenceReplayError,
    run_managed_bulk_replay,
)
from tests.helpers import materialize_reviewed_archive_with_historical_bootstraps


class EvidenceBulkReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.formal_root = Path(__file__).resolve().parents[1]
        self.workspace_root = self.formal_root.parent
        self.temporary = tempfile.TemporaryDirectory(
            dir=self.formal_root, prefix=".evidence-replay-test-"
        )
        self.addCleanup(self.temporary.cleanup)
        replay_archive = materialize_reviewed_archive_with_historical_bootstraps(
            workspace_root=self.workspace_root,
            destination=Path(self.temporary.name) / "archive",
            restore_occurrence_snapshot=True,
        )
        self.settings = Settings.default(
            project_root=self.workspace_root,
            archive_root=replay_archive,
            var_root=Path(self.temporary.name) / "var",
        )

    def test_full_managed_replay_is_isolated_idempotent_and_complete(self) -> None:
        result = run_managed_bulk_replay(
            self.settings,
            replay_slug="e-bulk-gate",
            package_root=self.workspace_root
            / "project_state"
            / "workers"
            / "e_evidence_bulk_data",
            normalized_manifest_path=self.formal_root
            / "fixtures"
            / "evidence"
            / "normalized_resource_manifest.jsonl",
        )
        self.assertEqual(18, result.resource_count)
        self.assertEqual(4630, result.counts["citation_occurrence"])
        self.assertEqual(5181, result.counts["citation_ledger_entry"])
        self.assertTrue(result.inventory_sha256)
        self.assertTrue(result.replay_root.is_dir())
        self.assertTrue(result.evidence_release_id)
        self.assertTrue(result.release_snapshot_urn)
        self.assertEqual(1, result.active_revision)
        self.assertTrue((result.replay_root / "db" / "platform.sqlite3").is_file())
        with self.assertRaisesRegex(EvidenceReplayError, "new or empty"):
            run_managed_bulk_replay(
                self.settings,
                replay_slug="e-bulk-gate",
                package_root=self.workspace_root
                / "project_state"
                / "workers"
                / "e_evidence_bulk_data",
            )

    def test_replay_rejects_escape_slug_before_touching_sources(self) -> None:
        with self.assertRaisesRegex(EvidenceReplayError, "safe direct-child"):
            run_managed_bulk_replay(
                self.settings,
                replay_slug="../escape",
                package_root=self.workspace_root
                / "project_state"
                / "workers"
                / "e_evidence_bulk_data",
            )


if __name__ == "__main__":
    unittest.main()
