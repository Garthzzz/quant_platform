from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from quant_hub.ops import local_exact_runtime_entry as module
from quant_hub.ops.local_exact_runtime_entry import (
    ExactRuntimeEntryError,
    _parse_exact_argv,
    main,
)


def _argv() -> tuple[str, ...]:
    values = (
        "attempt-1",
        "nonce-1",
        "activation",
        "candidate",
        "start-1",
        "release-1",
        "1" * 64,
        "2" * 64,
    )
    return tuple(
        item
        for pair in zip(module._ARGUMENT_FLAGS, values, strict=True)
        for item in pair
    )


class ExactRuntimeEntryTests(unittest.TestCase):
    def test_exact_ordered_argv_is_the_only_accepted_shape(self) -> None:
        parsed = _parse_exact_argv(_argv())
        self.assertEqual(
            {
                "attempt_id": "attempt-1",
                "nonce": "nonce-1",
                "operation": "activation",
                "role": "candidate",
                "start_nonce": "start-1",
                "release_id": "release-1",
                "manifest_sha256": "1" * 64,
                "state_identity_sha256": "2" * 64,
            },
            parsed,
        )
        cases: list[object] = [
            list(_argv()),
            _argv()[:-2],
            _argv() + ("--extra", "value"),
            ("--deployment-nonce", "nonce-1", *_argv()[2:]),
            (*_argv()[:2], "--deployment-attempt", "duplicate", *_argv()[4:]),
            (*_argv()[:1], "", *_argv()[2:]),
        ]
        for values in cases:
            with self.subTest(values=values), self.assertRaises(ExactRuntimeEntryError):
                _parse_exact_argv(values)

    def test_module_import_does_not_load_application_or_holder(self) -> None:
        script = """
import json
import sys
import quant_hub.ops.local_exact_runtime_entry
names = (
    "quant_hub.config",
    "quant_hub.app",
    "quant_hub.collaboration.service",
    "quant_hub.research_workspace.service",
    "quant_hub.ops.local_windows_writer_lease_holder",
)
print(json.dumps({name: name in sys.modules for name in names}, sort_keys=True))
"""
        completed = subprocess.run(
            [sys.executable, "-I", "-c", script],
            cwd=Path(__file__).resolve().parents[1],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertFalse(any(json.loads(completed.stdout).values()))

    def test_top_level_imports_are_standard_library_only(self) -> None:
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        imports = [
            node
            for node in tree.body
            if isinstance(node, (ast.Import, ast.ImportFrom))
        ]
        imported_names = set()
        for node in imports:
            if isinstance(node, ast.ImportFrom):
                if node.module != "__future__":
                    imported_names.add(str(node.module).split(".", 1)[0])
            else:
                imported_names.update(
                    alias.name.split(".", 1)[0] for alias in node.names
                )
        self.assertTrue(imported_names.issubset(sys.stdlib_module_names))
        self.assertEqual({"json", "os", "pathlib", "stat", "sys"}, imported_names)
        self.assertIn("qrh-exact-runtime-pycache-sentinel/v1", Path(module.__file__).read_text("utf-8"))
        self.assertEqual({}, inspect.signature(main).parameters)

    def test_regular_file_pycache_prefix_cannot_host_bytecode_and_imports_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qrh-pycache-sentinel-") as directory:
            sentinel = Path(directory) / "start-nonce"
            raw = b"sentinel\n"
            sentinel.write_bytes(raw)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-X",
                    "utf8",
                    "-X",
                    "pycache_prefix=" + str(sentinel),
                    "-c",
                    "import json,sys;print(sys.pycache_prefix);print(json.__name__)",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual([str(sentinel), "json"], completed.stdout.splitlines())
            self.assertEqual(raw, sentinel.read_bytes())
            self.assertEqual([sentinel], list(Path(directory).iterdir()))


if __name__ == "__main__":
    unittest.main()
