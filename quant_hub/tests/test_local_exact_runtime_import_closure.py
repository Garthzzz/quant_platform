from __future__ import annotations

import ast
from copy import deepcopy
import hashlib
import inspect
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from quant_hub.ops.local_exact_runtime_import_closure import (
    ExactRuntimeImportClosureError,
    ProductionExactRuntimeImportClosure,
    TestOnlyExactRuntimeImportClosureAdapter,
)
from quant_hub.ops.local_release_identity import (
    RELEASE_MANIFEST_SCHEMA,
    canonical_bytes,
    identity_sha256,
)
from quant_hub.ops.local_exact_runtime_tooling_scanner import (
    TestOnlyExactRuntimeToolingAdapter,
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _manifest(release_id: str, payloads: dict[str, bytes]) -> dict[str, object]:
    files = [
        {"path": path, "bytes": len(raw), "sha256": _sha(raw)}
        for path, raw in sorted(payloads.items())
    ]
    inventory = {
        "schema_version": "qrh-release-file-inventory/v2",
        "files": files,
    }
    return {
        "schema_version": RELEASE_MANIFEST_SCHEMA,
        "release_id": release_id,
        "built_at": "2026-08-28T12:00:00+08:00",
        "application": {
            "source_kind": "git",
            "commit_sha": "a" * 40,
            "tracked_tree_sha256": "b" * 64,
            "build_tool_version": "exact-import-tests/v1",
            "provenance": {"builder": "exact-import-tests", "labels": []},
        },
        "content": {
            "snapshot_id": "snapshot-exact-import",
            "source_inventory_sha256": "1" * 64,
            "ir_sha256": "2" * 64,
            "knowledge_sha256": "3" * 64,
            "search_sha256": "4" * 64,
            "page_projection_sha256": "5" * 64,
            "mcp_sha256": "6" * 64,
            "active_membership_sha256": "7" * 64,
            "knowledge_enrichment": {"status": "not_applicable"},
            "presentation": {"language": "zh-CN"},
        },
        "resources": {"inventory_sha256": identity_sha256(inventory)},
        "state": {
            "compatibility": {
                "comments": {"read": [1, 2], "write": [1, 2]},
                "research_workspace": {
                    "read": [1, 2, 3],
                    "write": [1, 2, 3],
                },
                "rollback_policy": "expand_only_no_down_migration",
            }
        },
        "inventory": inventory,
    }


class ExactRuntimeImportClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="qrh-exact-import-")
        self.base = Path(self.temporary.name).resolve()
        self.release = self.base / "release-r1"
        self.tooling_package = Path(__file__).parents[1] / "src" / "quant_hub"
        package = "runtime_contract/code/src/quant_hub/"
        self.payloads = {
            package + "__init__.py": b"RELEASE_MARKER = 'release-r1'\n",
            package + "app.py": b"def create_app():\n    return 'release-app'\n",
            package + "config.py": b"class Settings:\n    marker = 'release-settings'\n",
            package + "archive/__init__.py": b"",
            package + "archive/contracts.py": b"class ActorInput:\n    marker = 'release-actor'\n",
            package + "collaboration/__init__.py": b"",
            package + "collaboration/service.py": b"class ArchiveCollaboration:\n    marker = 'release-collaboration'\n",
            package + "platform/__init__.py": b"",
            package + "platform/db.py": b"VALUE = 'release-db'\n",
            package + "research_workspace/__init__.py": b"",
            package + "research_workspace/service.py": b"class ResearchWorkspace:\n    marker = 'release-workspace'\n",
            package + "web/__init__.py": b"",
            package + "web/access_gate.py": b"def install_access_gate():\n    return 'release-gate'\n",
        }
        self._write_release(self.payloads)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_release(self, payloads: dict[str, bytes]) -> None:
        for relative, raw in payloads.items():
            path = self.release.joinpath(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        document = _manifest("release-r1", payloads)
        self.release.mkdir(parents=True, exist_ok=True)
        (self.release / "release_manifest.json").write_bytes(
            canonical_bytes(document)
        )

    def _open(self):  # type: ignore[no-untyped-def]
        return TestOnlyExactRuntimeImportClosureAdapter.for_test_only(
            self.release, self.tooling_package.resolve()
        )

    def test_exact_inventory_roundtrip_and_existing_file_guard(self) -> None:
        closure = self._open()
        self.assertEqual(str(self.release), closure.release_path)
        document = json.loads(
            (self.release / "release_manifest.json").read_text("utf-8")
        )
        self.assertEqual(identity_sha256(document), closure.manifest_sha256)
        target = self.release / "runtime_contract" / "code" / "src" / "quant_hub" / "app.py"
        original = target.read_bytes()
        with self.assertRaises(OSError):
            target.write_bytes(original + b"drift")
        self.assertEqual(original, target.read_bytes())
        closure.close()

    def test_live_namespace_addition_fails_on_close(self) -> None:
        closure = self._open()
        added = self.release / "runtime_contract" / "code" / "src" / "quant_hub" / "late.py"
        added.write_bytes(b"late\n")
        with self.assertRaisesRegex(
            ExactRuntimeImportClosureError, "close failed"
        ):
            closure.close()
        added.unlink()

    def test_live_namespace_addition_fails_at_runtime_checkpoint(self) -> None:
        closure = self._open()
        added = self.release / "runtime_contract" / "code" / "src" / "quant_hub" / "late-checkpoint.py"
        added.write_bytes(b"late\n")
        observed = False
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                closure.checkpoint()
            except ExactRuntimeImportClosureError:
                observed = True
                break
            time.sleep(0.005)
        self.assertTrue(observed, "namespace event was not visible at checkpoint")
        with self.assertRaises(ExactRuntimeImportClosureError):
            closure.close()
        added.unlink()

    def test_live_tooling_namespace_is_guarded_after_persisted_verification(self) -> None:
        tooling_root = self.base / "tooling-root"
        tooling_package = (
            tooling_root
            / "tooling" / "python" / "Lib" / "site-packages" / "quant_hub"
        )
        shutil.copytree(
            self.tooling_package,
            tooling_package,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
        )
        if not (tooling_package / "__init__.py").read_bytes():
            (tooling_package / "__init__.py").write_bytes(b"# test tooling package\n")
        python = tooling_root / "tooling" / "python" / "python.exe"
        python.parent.mkdir(parents=True, exist_ok=True)
        python.write_bytes(b"test-python")
        host = tooling_root / "tooling" / "python" / "pythonservice.exe"
        host.write_bytes(b"test-pythonservice")
        (host.parent / "python313.dll").write_bytes(b"test-python-runtime")
        (host.parent / "pywintypes313.dll").write_bytes(b"test-pywin32-runtime")
        manifest = TestOnlyExactRuntimeToolingAdapter.for_test_only(
            tooling_root
        ).build_claim()
        closure = (
            TestOnlyExactRuntimeImportClosureAdapter.with_tooling_manifest_for_test_only(
                self.release,
                tooling_package,
                manifest,
            )
        )
        added = tooling_package / "late-tooling.py"
        added.write_bytes(b"late\n")
        observed = False
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                closure.checkpoint()
            except ExactRuntimeImportClosureError:
                observed = True
                break
            time.sleep(0.005)
        self.assertTrue(observed, "tooling namespace event was not visible")
        with self.assertRaises(ExactRuntimeImportClosureError):
            closure.close()
        added.unlink()

    def test_extra_missing_hardlink_and_manifest_drift_fail_closed(self) -> None:
        extra = self.release / "extra-empty-directory"
        extra.mkdir()
        with self.assertRaisesRegex(
            ExactRuntimeImportClosureError, "complete inventory"
        ):
            self._open()
        extra.rmdir()

        target = self.release / "runtime_contract" / "code" / "src" / "quant_hub" / "app.py"
        link = target.with_name("app-link.py")
        os.link(target, link)
        with self.assertRaises(ExactRuntimeImportClosureError):
            self._open()
        link.unlink()

        original = (self.release / "release_manifest.json").read_bytes()
        document = json.loads(original.decode("utf-8"))
        changed = deepcopy(document)
        changed["built_at"] = "2026-08-28T12:00:01+08:00"
        (self.release / "release_manifest.json").write_bytes(canonical_bytes(changed))
        closure = self._open()
        self.assertNotEqual(identity_sha256(document), closure.manifest_sha256)
        closure.close()

        (self.release / "release_manifest.json").write_bytes(original + b"\n")
        with self.assertRaisesRegex(
            ExactRuntimeImportClosureError, "canonical"
        ):
            self._open()

    def test_regular_package_lookup_loads_application_from_release(self) -> None:
        source_root = Path(__file__).parents[1] / "src"
        code = (
            "import inspect,pathlib,sys;"
            f"sys.path.insert(0,{str(source_root)!r});"
            "from quant_hub.ops.local_exact_runtime_import_closure import "
            "TestOnlyExactRuntimeImportClosureAdapter as A;"
            f"c=A.for_test_only(pathlib.Path({str(self.release)!r}),"
            f"pathlib.Path({str(self.tooling_package.resolve())!r}));"
            "c.activate();c.assert_application_sources();"
            "from quant_hub.config import Settings;"
            "from quant_hub.app import create_app;"
            "import quant_hub.ops.local_windows_writer_lease_holder as h;"
            "print(Settings.marker);"
            "print(create_app());"
            "print(pathlib.Path(inspect.getsourcefile(Settings)).resolve());"
            "print(pathlib.Path(inspect.getsourcefile(h)).resolve());"
            "c.close()"
        )
        completed = subprocess.run(
            [sys.executable, "-I", "-B", "-c", code],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        lines = completed.stdout.splitlines()
        self.assertEqual("release-settings", lines[0])
        self.assertEqual("release-app", lines[1])
        self.assertTrue(lines[2].startswith(str(self.release)))
        self.assertTrue(lines[3].startswith(str(self.tooling_package.resolve())))

    def test_legacy_broadcast_uses_guarded_tooling_access_gate(self) -> None:
        access_gate = (
            self.release
            / "runtime_contract"
            / "code"
            / "src"
            / "quant_hub"
            / "web"
            / "access_gate.py"
        )
        access_gate.unlink()
        payloads = {
            relative: raw
            for relative, raw in self.payloads.items()
            if not relative.endswith("web/access_gate.py")
        }
        document = _manifest("release-r1", payloads)
        document["application"] = {
            "source_kind": "legacy_broadcast",
            "source_archive_sha256": "8" * 64,
            "legacy_deployment_id": "legacy-v39",
            "build_tool_version": "exact-import-tests/v1",
            "provenance": {
                "builder": "exact-import-tests",
                "labels": [],
            },
        }
        (self.release / "release_manifest.json").write_bytes(
            canonical_bytes(document)
        )
        source_root = Path(__file__).parents[1] / "src"
        code = (
            "import pathlib,sys;"
            f"sys.path.insert(0,{str(source_root)!r});"
            "from quant_hub.ops.local_exact_runtime_import_closure import "
            "TestOnlyExactRuntimeImportClosureAdapter as A;"
            f"c=A.for_test_only(pathlib.Path({str(self.release)!r}),"
            f"pathlib.Path({str(self.tooling_package.resolve())!r}));"
            "c.activate();c.assert_application_sources();"
            "from quant_hub.web.access_gate import install_access_gate;"
            "print(pathlib.Path(install_access_gate.__code__.co_filename).resolve());"
            "c.close()"
        )
        completed = subprocess.run(
            [sys.executable, "-I", "-B", "-c", code],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertTrue(
            Path(completed.stdout.strip()).is_relative_to(
                self.tooling_package.resolve()
            )
        )

    def test_product_surface_has_only_lease_input_and_no_dynamic_loader(self) -> None:
        self.assertEqual(
            ["lease"],
            list(inspect.signature(
                ProductionExactRuntimeImportClosure.load_exact_d
            ).parameters),
        )
        module = __import__(
            "quant_hub.ops.local_exact_runtime_import_closure",
            fromlist=["__all__"],
        )
        self.assertNotIn(
            "TestOnlyExactRuntimeImportClosureAdapter", module.__all__
        )
        source = Path(module.__file__).read_text("utf-8")
        tree = ast.parse(source)
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertNotIn("importlib", imported)
        self.assertNotIn("sys", imported)
        calls = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertTrue({"exec", "eval", "compile"}.isdisjoint(calls))


if __name__ == "__main__":
    unittest.main()
