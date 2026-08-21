from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from unittest import mock
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "tools" / "release" / "legacy_browser_baseline.py"
SPEC = importlib.util.spec_from_file_location("_qrh_legacy_browser_baseline", SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import contract
    raise RuntimeError("legacy browser baseline script is unavailable")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LegacyBrowserCredentialTests(unittest.TestCase):
    def test_production_password_can_be_injected_without_process_argv(self) -> None:
        with mock.patch.dict(
            os.environ, {"VIEWER_ACCESS_PASSWORD": "protected-fixture"}, clear=False
        ):
            self.assertEqual("protected-fixture", MODULE._protected_password(None))

    def test_missing_secret_is_explicit_and_legacy_argument_still_wins(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(MODULE._protected_password(None))
            self.assertEqual("test-only", MODULE._protected_password("test-only"))


if __name__ == "__main__":
    unittest.main()
