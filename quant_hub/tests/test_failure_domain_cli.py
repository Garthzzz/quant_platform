from __future__ import annotations

from pathlib import Path
import unittest

from quant_hub.ops.vm_boundary import VMBoundaryError
from tools.release.failure_domain_cli import _guard_production_facts_paths


class FailureDomainCliBoundaryTests(unittest.TestCase):
    def test_production_facts_accept_only_exact_vm_root_and_child_output(self) -> None:
        _guard_production_facts_paths(
            Path(r"D:\quant\quant_platform"),
            Path(r"D:\quant\quant_platform\audit\production-facts.json"),
        )

    def test_production_facts_reject_parent_sibling_and_c_drive(self) -> None:
        cases = (
            (r"D:\quant", r"D:\quant\quant_platform\audit\facts.json"),
            (r"D:\quant\quant_platform", r"D:\quant\facts.json"),
            (r"D:\quant\quant_platform", r"C:\temp\facts.json"),
        )
        for root, output in cases:
            with self.subTest(root=root, output=output):
                with self.assertRaises(VMBoundaryError):
                    _guard_production_facts_paths(Path(root), Path(output))


if __name__ == "__main__":
    unittest.main()
