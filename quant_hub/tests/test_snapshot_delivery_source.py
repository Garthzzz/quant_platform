from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from contextlib import closing


from quant_hub.runtime_seal import RuntimeSealError, database_contract, safe_tree
from tools.snapshot_delivery_source import DATABASE_FILES, MANAGED_TREES, snapshot_delivery_source


class SnapshotDeliverySourceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temporary.name)
        self.formal = self.workspace / "quant_hub"
        self.var = self.formal / "var"
        self.source = self.var / "source"
        self.gates = self.workspace / "project_state" / "gates"
        (self.source / "db").mkdir(parents=True)
        self.gates.mkdir(parents=True)
        for index, name in enumerate(DATABASE_FILES, start=1):
            database = self.source / "db" / name
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("CREATE TABLE schema_migration(version INTEGER PRIMARY KEY)")
                connection.execute("INSERT INTO schema_migration VALUES (?)", (index,))
                connection.execute("CREATE TABLE payload(id INTEGER PRIMARY KEY, value TEXT)")
                connection.execute("INSERT INTO payload(value) VALUES (?)", (name,))
                connection.commit()
        for name in MANAGED_TREES:
            root = self.source / name
            root.mkdir()
            (root / "material.txt").write_text(name, encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def snapshot(self, suffix: str = "one") -> dict[str, object]:
        return snapshot_delivery_source(
            source_var=self.source,
            output_var=self.var / f"snapshot-{suffix}",
            report=self.gates / suffix / "report.json",
            formal_root=self.formal,
            workspace_root=self.workspace,
        )

    def test_freezes_all_domains_without_changing_source(self) -> None:
        source_trees = {name: safe_tree(self.source / name) for name in MANAGED_TREES}
        source_databases = {
            name: database_contract(self.source / "db" / name) for name in DATABASE_FILES
        }
        result = self.snapshot()
        output = Path(str(result["output_var"]))
        self.assertEqual("PASS", result["status"])
        self.assertTrue((output / "SOURCE_SNAPSHOT_SEAL.json").is_file())
        self.assertEqual(
            source_trees,
            {name: safe_tree(self.source / name) for name in MANAGED_TREES},
        )
        self.assertEqual(
            source_databases,
            {name: database_contract(self.source / "db" / name) for name in DATABASE_FILES},
        )
        for name in DATABASE_FILES:
            target = output / "db" / name
            self.assertEqual(
                source_databases[name]["tables"], database_contract(target)["tables"]
            )
            for suffix in ("-wal", "-shm", "-journal"):
                self.assertFalse(Path(f"{target}{suffix}").exists())

    def test_nonempty_wal_fails_closed_without_source_mutation(self) -> None:
        database = self.source / "db" / DATABASE_FILES[0]
        wal = Path(f"{database}-wal")
        wal.write_bytes(b"not-a-quiescent-wal")
        before = wal.read_bytes()
        with self.assertRaisesRegex(RuntimeSealError, "non-empty WAL"):
            self.snapshot("wal")
        self.assertEqual(before, wal.read_bytes())

    def test_rejects_output_outside_formal_var(self) -> None:
        with self.assertRaisesRegex(RuntimeSealError, "direct child"):
            snapshot_delivery_source(
                source_var=self.source,
                output_var=self.workspace / "escape",
                report=self.gates / "escape" / "report.json",
                formal_root=self.formal,
                workspace_root=self.workspace,
            )

    @unittest.skipUnless(hasattr(os, "link"), "hard links unavailable")
    def test_rejects_hardlinked_managed_material(self) -> None:
        original = self.source / MANAGED_TREES[0] / "material.txt"
        os.link(original, original.with_name("alias.txt"))
        with self.assertRaisesRegex(RuntimeSealError, "single-link"):
            self.snapshot("hardlink")


if __name__ == "__main__":
    unittest.main()
