from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from quant_hub.archive.service import ingest_archive_snapshot
from quant_hub.config import Settings
from quant_hub.ids import sha256_hex
from quant_hub.platform.objects import ObjectStore


class RealArchiveReplayTests(unittest.TestCase):
    def test_real_markdown_is_snapshotted_without_source_change(self) -> None:
        formal_root = Path(__file__).resolve().parents[1]
        project_root = formal_root.parent
        archive_root = project_root / "reference" / "archive"
        relative = Path("experiments") / "README.md"
        source = archive_root / relative
        before = source.read_bytes()
        (formal_root / "var").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=formal_root / "var") as temporary:
            var_root = Path(temporary).resolve()
            settings = Settings(
                project_root=project_root,
                archive_root=archive_root,
                var_root=var_root,
                database_path=var_root / "db" / "platform.sqlite3",
                object_root=var_root / "objects",
                migration_root=formal_root / "migrations" / "platform",
            )
            settings.validate()
            first = ingest_archive_snapshot(settings, relative)
            second = ingest_archive_snapshot(settings, relative)
            self.assertTrue(first.run_created)
            self.assertFalse(second.run_created)
            self.assertEqual(first.run_id, second.run_id)
            self.assertEqual(before, ObjectStore(settings.object_root).read_bytes(first.object_id))
        after = source.read_bytes()
        self.assertEqual(before, after)
        self.assertEqual(sha256_hex(before), sha256_hex(after))
