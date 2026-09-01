from __future__ import annotations

import ast
import ctypes
import inspect
import os
from pathlib import Path
import unittest

from quant_hub.ops import local_windows_exact_runtime_process_fence as subject
from quant_hub.ops.local_windows_exact_runtime_process_fence import (
    ProductionWindowsExactRuntimeProcessFence,
)


class WindowsExactRuntimeProcessFenceTests(unittest.TestCase):
    def test_loader_is_zero_argument_and_product_api_is_fixed(self) -> None:
        self.assertEqual(
            [],
            list(
                inspect.signature(
                    ProductionWindowsExactRuntimeProcessFence.load_exact_d
                ).parameters
            ),
        )
        if os.name == "nt":
            loaded = ProductionWindowsExactRuntimeProcessFence.load_exact_d()
            self.assertIs(type(loaded), ProductionWindowsExactRuntimeProcessFence)

    def test_source_uses_two_toolhelp_snapshots_and_no_process_subprocess(self) -> None:
        source = Path(
            inspect.getfile(ProductionWindowsExactRuntimeProcessFence)
        ).read_text(encoding="utf-8")
        tree = ast.parse(source)
        attributes = {
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        self.assertIn("create_toolhelp32_snapshot", attributes)
        self.assertIn("process32_first_w", attributes)
        self.assertIn("process32_next_w", attributes)
        self.assertIn("query_process", attributes)
        self.assertIn("CommandLineToArgvW", source)
        self.assertIn("_probe_writer_lock", source)
        self.assertNotIn("Popen", attributes)
        self.assertNotIn("run", attributes)
        method = inspect.getsource(
            ProductionWindowsExactRuntimeProcessFence.assert_absent_before_launch
        )
        self.assertGreaterEqual(method.count("self._snapshot()"), 2)

    def test_mapping_cannot_enter_product_fence(self) -> None:
        instance = object.__new__(ProductionWindowsExactRuntimeProcessFence)
        with self.assertRaises(TypeError):
            instance.assert_absent_before_launch({})

    def test_close_source_has_no_target_process_or_duplicate_handle(self) -> None:
        api = object.__new__(subject._FenceApi)
        observed: list[tuple[object, ...]] = []
        object.__setattr__(
            api,
            "DuplicateHandle",
            lambda *arguments: observed.append(arguments) or True,
        )
        object.__setattr__(
            api, "GetCurrentProcess", lambda: ctypes.c_void_p(-1).value
        )
        api.close_handle(101)
        self.assertEqual(1, len(observed))
        self.assertIsNone(observed[0][2])
        self.assertIsNone(observed[0][3])

    def test_close_source_false_is_not_treated_as_success(self) -> None:
        api = object.__new__(subject._FenceApi)
        object.__setattr__(api, "DuplicateHandle", lambda *_: False)
        object.__setattr__(
            api, "GetCurrentProcess", lambda: ctypes.c_void_p(-1).value
        )
        with self.assertRaisesRegex(
            subject.WindowsExactRuntimeProcessFenceError, "close failed"
        ):
            api.close_handle(101)


if __name__ == "__main__":
    unittest.main()
