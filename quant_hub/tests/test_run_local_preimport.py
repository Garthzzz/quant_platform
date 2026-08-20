from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from quant_hub.runtime_seal import safe_tree


WORKSPACE = Path(__file__).resolve().parents[2]
RUN_LOCAL = WORKSPACE / "quant_hub" / "tools" / "run_local.py"


class RunLocalPreImportTests(unittest.TestCase):
    def test_formal_entry_rejects_non_isolated_python_before_shadow_import(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "shadow-executed.txt"
            (root / "argparse.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(root)
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            completed = subprocess.run(
                [sys.executable, "-B", str(RUN_LOCAL)],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=30,
                check=False,
            )
            self.assertNotEqual(0, completed.returncode)
            self.assertIn("requires isolated Python (-I)", completed.stderr)
            self.assertFalse(marker.exists())

    def test_isolated_python_ignores_shadow_pythonpath(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "shadow-executed.txt"
            (root / "argparse.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(root)
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            completed = subprocess.run(
                [sys.executable, "-I", "-B", str(RUN_LOCAL)],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=30,
                check=False,
            )
            self.assertNotEqual(0, completed.returncode)
            self.assertIn("sealed runtime preflight requires", completed.stderr)
            self.assertFalse(marker.exists())

    def test_phase_zero_tree_identity_matches_runtime_seal(self) -> None:
        specification = importlib.util.spec_from_file_location(
            "run_local_preimport_fixture", RUN_LOCAL
        )
        assert specification is not None and specification.loader is not None
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "pkg").mkdir()
            (root / "pkg" / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
            (root / "__pycache__").mkdir()
            (root / "__pycache__" / "ignored.pyc").write_bytes(b"cache")
            self.assertEqual(
                safe_tree(root, exclude_runtime_caches=True),
                module._bootstrap_tree(root),
            )


if __name__ == "__main__":
    unittest.main()
