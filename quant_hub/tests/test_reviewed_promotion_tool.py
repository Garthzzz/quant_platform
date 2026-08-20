from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from quant_hub.runtime_seal import RuntimeSealError
from tools.publish_reviewed_evidence_release import (
    _exclusive_lock,
    _nonpromotion_tables,
)
from tools.run_local import _validate_sealed_runtime, main as run_local_main
from tests.helpers import SettingsTestCase


class PromotionHelperTests(unittest.TestCase):
    def test_nonpromotion_table_contract_excludes_only_explicit_release_tables(self) -> None:
        contracts = {
            "platform.sqlite3": {
                "tables": {
                    "release_candidate": {"rows": 1},
                    "research_run": {"rows": 7},
                }
            },
            "archive.sqlite3": {"tables": {"research_document": {"rows": 91}}},
            "research_papers.sqlite3": {
                "tables": {
                    "evidence_release": {"rows": 1},
                    "paper": {"rows": 78},
                }
            },
            "paper_lab.sqlite3": {"tables": {"lab_paper": {"rows": 137}}},
        }
        sealed = _nonpromotion_tables(contracts)
        self.assertNotIn("release_candidate", sealed["platform.sqlite3"])
        self.assertNotIn("evidence_release", sealed["research_papers.sqlite3"])
        self.assertEqual({"rows": 7}, sealed["platform.sqlite3"]["research_run"])
        self.assertEqual({"rows": 78}, sealed["research_papers.sqlite3"]["paper"])

    @unittest.skipUnless(os.name == "nt", "Windows locking contract")
    def test_promotion_lock_rejects_a_second_concurrent_owner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / "promotion.lock"
            with _exclusive_lock(lock):
                with self.assertRaisesRegex(RuntimeSealError, "another promotion"):
                    with _exclusive_lock(lock):
                        self.fail("second owner unexpectedly acquired the lock")


class SealedRunLocalTests(SettingsTestCase):
    def test_sealed_mode_requires_explicit_migration_and_gate_options(self) -> None:
        delivery = self.project / "quant_hub" / "var" / "candidate"
        delivery.mkdir(parents=True)
        arguments = [
            "run_local.py",
            "--project-root",
            str(self.project),
            "--archive-root",
            str(self.archive),
            "--var-root",
            str(delivery),
        ]
        with patch.object(sys, "argv", arguments), self.assertRaises(SystemExit) as raised:
            run_local_main()
        self.assertEqual(2, raised.exception.code)

    def test_worktree_launcher_cannot_impersonate_candidate_launcher(self) -> None:
        delivery = self.project / "quant_hub" / "var" / "candidate"
        expected_script = delivery / "runtime_contract" / "code" / "tools" / "run_local.py"
        expected_script.parent.mkdir(parents=True)
        expected_script.write_text("# frozen placeholder\n", encoding="utf-8")
        migrations = delivery / "runtime_contract" / "migrations" / "platform"
        migrations.mkdir(parents=True)
        activation = delivery / "ACTIVATED_DELIVERY_SEAL.json"
        activation.write_text("{}\n", encoding="utf-8")
        gate = self.project / "project_state" / "gates" / "startup.json"
        gate.parent.mkdir(parents=True)
        gate.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeSealError, "sealed run_local"):
            _validate_sealed_runtime(
                project=self.project,
                delivery=delivery,
                migration_root=migrations,
                activation_path=activation,
                startup_gate_path=gate,
                resume=False,
            )


if __name__ == "__main__":
    unittest.main()
