from __future__ import annotations

from contextlib import closing
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

from quant_hub.runtime_seal import (
    RuntimeSealError,
    database_contract,
    database_row_manifest,
    file_identity,
    read_json,
    runtime_toolchain,
    safe_tree,
    write_new_json,
    write_atomic_new_json,
)


class RuntimeSealTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_safe_tree_is_deterministic_and_excludes_runtime_caches_only_when_requested(self) -> None:
        tree = self.root / "tree"
        (tree / "nested").mkdir(parents=True)
        (tree / "a.txt").write_text("甲\n", encoding="utf-8", newline="\n")
        (tree / "nested" / "b.txt").write_text("乙\n", encoding="utf-8", newline="\n")
        cache = tree / "__pycache__"
        cache.mkdir()
        (cache / "x.pyc").write_bytes(b"cache")

        first = safe_tree(tree, exclude_runtime_caches=True)
        second = safe_tree(tree, exclude_runtime_caches=True)
        full = safe_tree(tree)
        self.assertEqual(first, second)
        self.assertEqual(2, first["files"])
        self.assertEqual(3, full["files"])

    def test_safe_tree_rejects_hard_linked_material(self) -> None:
        tree = self.root / "hardlinks"
        tree.mkdir()
        source = tree / "source.txt"
        alias = tree / "alias.txt"
        source.write_bytes(b"same inode")
        os.link(source, alias)
        with self.assertRaisesRegex(RuntimeSealError, "single-link"):
            safe_tree(tree)

    @unittest.skipUnless(os.name == "nt", "Windows junction contract")
    def test_safe_tree_rejects_real_junction_component(self) -> None:
        tree = self.root / "junction-tree"
        outside = self.root / "outside"
        junction = tree / "linked"
        tree.mkdir()
        outside.mkdir()
        (outside / "payload.txt").write_text("不得跟随", encoding="utf-8")
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            self.skipTest("cannot create a Windows junction in this environment")
        try:
            with self.assertRaisesRegex(RuntimeSealError, "reparse"):
                safe_tree(tree)
        finally:
            if os.path.lexists(junction):
                os.rmdir(junction)

    def test_database_contract_binds_schema_and_every_table_row_without_sidecars(self) -> None:
        database = self.root / "sealed.sqlite3"
        with closing(sqlite3.connect(database)) as connection:
            connection.execute(
                "CREATE TABLE schema_migration(version INTEGER PRIMARY KEY, name TEXT)"
            )
            connection.execute("INSERT INTO schema_migration VALUES(1,'one')")
            connection.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY, value TEXT)")
            connection.execute("INSERT INTO sample VALUES(1,'原始')")
            connection.commit()
        first = database_contract(database)
        second = database_contract(database)
        self.assertEqual(first, second)
        self.assertEqual(1, first["tables"]["sample"]["rows"])
        self.assertFalse(Path(f"{database}-wal").exists())
        self.assertFalse(Path(f"{database}-shm").exists())

        with closing(sqlite3.connect(database)) as connection:
            connection.execute("UPDATE sample SET value='变化' WHERE id=1")
            connection.commit()
        changed = database_contract(database)
        self.assertNotEqual(
            first["tables"]["sample"]["content_sha256"],
            changed["tables"]["sample"]["content_sha256"],
        )
        self.assertEqual(first["schema_sha256"], changed["schema_sha256"])

    def test_row_manifest_uses_stable_natural_key_without_primary_key(self) -> None:
        database = self.root / "natural-key.sqlite3"
        with closing(sqlite3.connect(database)) as connection:
            connection.execute(
                "CREATE TABLE schema_migration(version INTEGER PRIMARY KEY, name TEXT)"
            )
            connection.execute("INSERT INTO schema_migration VALUES(1,'one')")
            connection.execute("CREATE TABLE natural_values(label TEXT, ordinal INTEGER)")
            connection.executemany(
                "INSERT INTO natural_values(label,ordinal) VALUES(?,?)",
                [("乙", 2), ("甲", 1)],
            )
            connection.commit()
        before = database_row_manifest(database)
        natural = before["natural_values"]
        self.assertEqual("natural_key", natural["key_kind"])
        self.assertEqual(["label", "ordinal"], natural["primary_key"])
        self.assertEqual([["乙", 2], ["甲", 1]], [row["key"] for row in natural["rows"]])
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("VACUUM")
        self.assertEqual(before, database_row_manifest(database))

    def test_row_manifest_rejects_duplicate_natural_keys(self) -> None:
        database = self.root / "ambiguous.sqlite3"
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("CREATE TABLE duplicate_values(value TEXT)")
            connection.executemany(
                "INSERT INTO duplicate_values(value) VALUES(?)", [("相同",), ("相同",)]
            )
            connection.commit()
        with self.assertRaisesRegex(RuntimeSealError, "unambiguous stable row key"):
            database_row_manifest(database)

    def test_safe_tree_rejects_casefold_directory_component_collision(self) -> None:
        tree = self.root / "casefold-tree"
        (tree / "Straße").mkdir(parents=True)
        try:
            (tree / "STRASSE").mkdir()
        except FileExistsError:
            self.skipTest("filesystem cannot represent the case-fold collision fixture")
        with self.assertRaisesRegex(RuntimeSealError, "case-fold path collision"):
            safe_tree(tree)

    def test_json_seal_is_create_only_and_hash_verified_by_file_identity(self) -> None:
        path = self.root / "seal.json"
        digest = write_new_json(path, {"schema_version": "test/v1", "value": "中文"})
        self.assertEqual(digest, file_identity(path)["sha256"])
        self.assertEqual(
            "中文", read_json(path, schema_version="test/v1")["value"]
        )
        with self.assertRaises(FileExistsError):
            write_new_json(path, {"schema_version": "test/v1"})

    def test_atomic_json_seal_is_exclusive_and_never_overwrites(self) -> None:
        path = self.root / "atomic.json"
        digest = write_atomic_new_json(path, {"schema_version": "test/v1", "n": 1})
        self.assertEqual(digest, file_identity(path)["sha256"])
        original = path.read_bytes()
        with self.assertRaises(FileExistsError):
            write_atomic_new_json(path, {"schema_version": "test/v1", "n": 2})
        self.assertEqual(original, path.read_bytes())

    def test_runtime_toolchain_binds_interpreter_and_declared_dependencies(self) -> None:
        contract = runtime_toolchain()
        self.assertEqual(64, len(contract["python_executable_identity"]["sha256"]))
        for distribution in ("Flask", "PyMuPDF", "pydantic", "Werkzeug"):
            self.assertTrue(contract["packages"][distribution])


if __name__ == "__main__":
    unittest.main()
