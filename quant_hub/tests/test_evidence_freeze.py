from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


FORMAL_ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "freeze_evidence_candidate",
    FORMAL_ROOT / "tools" / "freeze_evidence_candidate.py",
)
assert SPEC is not None and SPEC.loader is not None
freeze = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(freeze)


class EvidenceFreezeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            dir=FORMAL_ROOT, prefix=".evidence-freeze-test-"
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_nonempty_sqlite_wal_and_shm_sidecars_fail_closed(self) -> None:
        (self.root / "research_papers.sqlite3").write_bytes(b"database")
        zero_sidecar = self.root / "research_papers.sqlite3-shm"
        zero_sidecar.write_bytes(b"")
        self.assertEqual(
            [self.root / "research_papers.sqlite3"], freeze._files(self.root)
        )
        wal = self.root / "research_papers.sqlite3-wal"
        wal.write_bytes(b"uncheckpointed")
        with self.assertRaisesRegex(RuntimeError, "non-empty SQLite sidecar"):
            freeze._files(self.root)

    def test_live_tree_facts_change_when_source_bytes_change(self) -> None:
        archive = self.root / "reference" / "archive"
        archive.mkdir(parents=True)
        research = archive / "research.md"
        research.write_text("alpha\n", encoding="utf-8", newline="\n")
        first = freeze._tree_facts(self.root, archive)
        research.write_text("beta\n", encoding="utf-8", newline="\n")
        second = freeze._tree_facts(self.root, archive)
        self.assertEqual(1, first["file_count"])
        self.assertNotEqual(first["tree_sha256"], second["tree_sha256"])


if __name__ == "__main__":
    unittest.main()
