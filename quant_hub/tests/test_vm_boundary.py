from __future__ import annotations

import unittest

from quant_hub.ops.vm_boundary import (
    VMBoundaryError,
    validate_production_vm_write_path,
    validate_vm_write_set,
)


class VMWriteBoundaryTests(unittest.TestCase):
    def test_all_approved_operational_paths_are_inside_exact_root(self) -> None:
        paths = validate_vm_write_set(
            [
                r"D:\quant\quant_platform\incoming\r1.partial",
                r"D:\quant\quant_platform\releases\r1",
                r"D:\quant\quant_platform\state\comments.sqlite3",
                r"D:\quant\quant_platform\backups\c1",
                r"D:\quant\quant_platform\audit\receipt.json",
                r"D:\quant\quant_platform\control\deploy.py",
                r"D:\quant\quant_platform\tmp\transfer.partial",
            ]
        )
        self.assertEqual(7, len(paths))

    def test_parent_sibling_c_drive_unc_and_ads_are_rejected(self) -> None:
        forbidden = [
            r"D:\candidate",
            r"D:\quant\candidate",
            r"D:\quant\quant_platform_other\candidate",
            r"D:\quant\quant_platform\..\outside",
            r"C:\quant_platform\new-file",
            r"C:\quant_platform_data\backup",
            r"\\server\share\quant_platform",
            r"D:\quant\quant_platform\state\db.sqlite3:stream",
        ]
        for path in forbidden:
            with self.subTest(path=path), self.assertRaises(VMBoundaryError):
                validate_production_vm_write_path(path)

    def test_root_can_be_created_but_child_only_operations_can_forbid_it(self) -> None:
        self.assertEqual(
            r"D:\quant\quant_platform",
            str(validate_production_vm_write_path(r"D:\quant\quant_platform")),
        )
        with self.assertRaises(VMBoundaryError):
            validate_production_vm_write_path(
                r"D:\quant\quant_platform", allow_root=False
            )


if __name__ == "__main__":
    unittest.main()
