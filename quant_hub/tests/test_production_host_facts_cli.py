from __future__ import annotations

from pathlib import Path
import unittest

from quant_hub.ops.production_host_facts_cli import guard_production_facts_paths
from quant_hub.ops.vm_boundary import VMBoundaryError


class ProductionHostFactsBoundaryTests(unittest.TestCase):
    def test_only_exact_d_root_audit_evidence_json_is_accepted(self) -> None:
        guard_production_facts_paths(
            Path(r"D:\quant\quant_platform"),
            Path(r"D:\quant\quant_platform\audit\evidence\production-facts.json"),
        )

    def test_c_parent_sibling_and_non_evidence_output_are_rejected(self) -> None:
        cases = (
            (r"D:\quant", r"D:\quant\quant_platform\audit\evidence\facts.json"),
            (r"D:\quant\quant_platform", r"D:\quant\facts.json"),
            (r"D:\quant\quant_platform", r"C:\temp\facts.json"),
            (r"D:\quant\quant_platform", r"D:\quant\quant_platform\logs\facts.json"),
            (r"D:\quant\quant_platform", r"D:\quant\quant_platform\audit\facts.json"),
        )
        for root, output in cases:
            with self.subTest(root=root, output=output):
                with self.assertRaises(VMBoundaryError):
                    guard_production_facts_paths(Path(root), Path(output))


if __name__ == "__main__":
    unittest.main()
