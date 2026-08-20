from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from quant_hub.platform.db import (
    READ_ONLY_DATABASE_ROOT_ENV,
    connect_database,
    connection_is_read_only,
)


class ReadOnlyRuntimeDatabaseTests(unittest.TestCase):
    def test_configured_frozen_root_is_query_only_and_sidecar_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database_root = root / "sealed" / "db"
            database_root.mkdir(parents=True)
            database = database_root / "archive.sqlite3"

            connection = sqlite3.connect(database)
            connection.execute("CREATE TABLE sample(value TEXT NOT NULL)")
            connection.execute("INSERT INTO sample(value) VALUES ('sealed')")
            connection.commit()
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.close()

            external = root / "data" / "comments.sqlite3"
            with patch.dict(
                os.environ,
                {READ_ONLY_DATABASE_ROOT_ENV: str(database_root)},
                clear=False,
            ):
                frozen = connect_database(database)
                try:
                    self.assertTrue(connection_is_read_only(frozen))
                    self.assertEqual(
                        frozen.execute("SELECT value FROM sample").fetchone()[0],
                        "sealed",
                    )
                    with self.assertRaises(sqlite3.OperationalError):
                        frozen.execute("INSERT INTO sample(value) VALUES ('mutated')")
                finally:
                    frozen.close()

                writable = connect_database(external)
                try:
                    self.assertFalse(connection_is_read_only(writable))
                    writable.execute("CREATE TABLE comment(value TEXT)")
                finally:
                    writable.close()

            for suffix in ("-journal", "-wal", "-shm"):
                self.assertFalse(Path(str(database) + suffix).exists())


if __name__ == "__main__":
    unittest.main()
