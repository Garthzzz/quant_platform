from __future__ import annotations

from pathlib import Path
import unittest

from quant_hub.ops.vm_boundary import VMBoundaryError
from tools.release.checkpoint_cli import _validate_source


class CheckpointCliBoundaryTests(unittest.TestCase):
    def test_sources_are_limited_to_legacy_allowlist_or_vm_root(self) -> None:
        _validate_source(Path(r"C:\quant_platform_data\comments.sqlite3"))
        _validate_source(Path(r"C:\quant_platform_data\research_workspace.sqlite3"))
        _validate_source(Path(r"D:\quant\quant_platform\state\comments.sqlite3"))

    def test_legacy_siblings_and_all_other_roots_are_rejected(self) -> None:
        for path in (
            r"C:\quant_platform_data\viewer_secret.key",
            r"C:\quant_platform_data\backups\comments.sqlite3",
            r"C:\quant_platform\runtime.sqlite3",
            r"D:\quant\other\comments.sqlite3",
        ):
            with self.subTest(path=path):
                with self.assertRaises((RuntimeError, VMBoundaryError)):
                    _validate_source(Path(path))


if __name__ == "__main__":
    unittest.main()
