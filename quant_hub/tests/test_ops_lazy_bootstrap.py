from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest


class OpsLazyBootstrapTests(unittest.TestCase):
    def test_importing_ops_has_no_application_import_side_effects(self) -> None:
        script = """
import json
import sys

import quant_hub.ops

print(json.dumps({
    "config": "quant_hub.config" in sys.modules,
    "deployment": "quant_hub.ops.deployment" in sys.modules,
    "runtime_seal": "quant_hub.ops.runtime_seal" in sys.modules,
}, sort_keys=True))
"""
        completed = subprocess.run(
            [sys.executable, "-I", "-c", script],
            cwd=Path(__file__).resolve().parents[1],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            {"config": False, "deployment": False, "runtime_seal": False},
            json.loads(completed.stdout),
        )

    def test_public_exports_remain_compatible(self) -> None:
        from quant_hub.ops import DeploymentController, validate_active_release

        self.assertEqual("DeploymentController", DeploymentController.__name__)
        self.assertEqual("validate_active_release", validate_active_release.__name__)

    def test_exact_runtime_tooling_submodule_import_remains_compatible(self) -> None:
        from quant_hub.ops import local_exact_runtime_tooling

        self.assertEqual(
            "quant_hub.ops.local_exact_runtime_tooling",
            local_exact_runtime_tooling.__name__,
        )


if __name__ == "__main__":
    unittest.main()
