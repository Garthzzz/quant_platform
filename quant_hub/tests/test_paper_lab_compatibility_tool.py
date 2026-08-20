from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest

from tools.paper_lab_compatibility import _normalized, _stable_payload


class PaperLabCompatibilityToolTests(unittest.TestCase):
    def test_normalized_removes_native_posix_and_json_escaped_temp_roots(self) -> None:
        root = Path(r"D:\workspace\compat-random")
        values = (
            str(root / "project"),
            (root / "project").as_posix(),
            json.dumps({"drop_root": str(root / "project")}, ensure_ascii=False),
        )
        for value in values:
            with self.subTest(value=value):
                normalized = _normalized(value, root)
                self.assertIn("<fixture>", normalized)
                self.assertNotIn("compat-random", normalized)

    def test_stable_payload_only_replaces_transport_request_ids(self) -> None:
        payload = {
            "meta": {"request_id": "random-uuid", "page": 1},
            "data": {"paper_id": "stable-paper", "items": [{"request_id": "nested"}]},
        }
        self.assertEqual(
            _stable_payload(payload),
            {
                "meta": {"request_id": "<request-id>", "page": 1},
                "data": {
                    "paper_id": "stable-paper",
                    "items": [{"request_id": "<request-id>"}],
                },
            },
        )

    def test_help_is_read_only(self) -> None:
        project = Path(__file__).resolve().parents[2]
        tool = project / "quant_hub" / "tools" / "paper_lab_compatibility.py"
        matrix = project / "quant_hub" / "fixtures" / "paper_lab" / "compatibility_matrix.tsv"
        before = matrix.read_bytes()
        completed = subprocess.run(
            [sys.executable, "-B", str(tool), "--help"],
            cwd=project,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("usage:", completed.stdout.casefold())
        self.assertEqual(matrix.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
