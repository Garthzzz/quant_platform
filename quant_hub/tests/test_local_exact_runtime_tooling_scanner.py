from __future__ import annotations

import inspect
import json
import os
from pathlib import Path, PurePosixPath
import tempfile
import unittest
from unittest.mock import patch

from quant_hub.ops import local_exact_runtime_tooling as contract
from quant_hub.ops import local_exact_runtime_tooling_scanner as scanner_module
from quant_hub.ops.local_exact_runtime_tooling_scanner import (
    EXACT_RUNTIME_TOOLING_MANIFEST_RELATIVE_PATH,
    ExactRuntimeToolingScanError,
    ProductionExactRuntimeToolingVerifier,
    TestOnlyExactRuntimeToolingAdapter,
)


def _path(root: Path, relative: str) -> Path:
    return root.joinpath(*PurePosixPath(relative).parts)


class ExactRuntimeToolingScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="qrh-tooling-")
        self.root = Path(self.temporary.name).resolve()
        for _field, logical_name, relative in contract._BINARY_PATHS:
            path = _path(self.root, relative)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((logical_name + "-binary\n").encode("utf-8"))
        for logical_name, relative in contract._KEY_FILES:
            path = _path(
                self.root,
                contract.EXACT_RUNTIME_PACKAGE_RELATIVE_PATH + "/" + relative,
            )
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((logical_name + "\n").encode("utf-8"))
        extra = _path(
            self.root,
            contract.EXACT_RUNTIME_PACKAGE_RELATIVE_PATH + "/app.py",
        )
        extra.parent.mkdir(parents=True, exist_ok=True)
        extra.write_bytes(b"application\n")
        self.adapter = TestOnlyExactRuntimeToolingAdapter.for_test_only(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _persist(self, raw: bytes) -> Path:
        path = _path(self.root, EXACT_RUNTIME_TOOLING_MANIFEST_RELATIVE_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def test_snapshot_roundtrip_and_persisted_verification_are_exact(self) -> None:
        manifest = self.adapter.build_claim()
        document = manifest.as_dict()
        package = document["package"]
        self.assertEqual(contract.EXACT_RUNTIME_TOOLING_ROOT, document["root"])
        self.assertEqual(
            contract.EXACT_RUNTIME_PACKAGE_INVENTORY_ALGORITHM,
            package["inventory_algorithm"],
        )
        self.assertEqual(len(contract._KEY_FILES) + 1, package["entry_count"])
        self.assertNotIn("qualify", dir(manifest))
        self.assertEqual(manifest, self.adapter.verify(manifest))
        self._persist(manifest.canonical_bytes())
        replay = self.adapter.verify_persisted()
        self.assertEqual(manifest.canonical_bytes(), replay.canonical_bytes())

    def test_pycache_is_ignored_but_discoverable_legacy_bytecode_is_rejected(self) -> None:
        before = self.adapter.build_claim()
        package = _path(self.root, contract.EXACT_RUNTIME_PACKAGE_RELATIVE_PATH)
        cache = package / "__pycache__"
        cache.mkdir()
        (cache / "ignored.bin").write_bytes(b"ignored because parent is cache")
        after = self.adapter.build_claim()
        self.assertEqual(before.canonical_bytes(), after.canonical_bytes())
        for name in ("legacy.pyc", "legacy.pyo"):
            target = package / name
            target.write_bytes(b"discoverable legacy bytecode")
            with self.subTest(name=name), self.assertRaisesRegex(
                ExactRuntimeToolingScanError, "legacy bytecode"
            ):
                self.adapter.build_claim()
            target.unlink()

    def test_key_file_package_member_and_binary_drift_are_all_detected(self) -> None:
        cases = (
            contract._KEY_FILES[0][1],
            "app.py",
        )
        for relative in cases:
            with self.subTest(relative=relative):
                manifest = self.adapter.build_claim()
                path = _path(
                    self.root,
                    contract.EXACT_RUNTIME_PACKAGE_RELATIVE_PATH + "/" + relative,
                )
                original = path.read_bytes()
                path.write_bytes(original + b"drift")
                with self.assertRaises(ExactRuntimeToolingScanError):
                    self.adapter.verify(manifest)
                path.write_bytes(original)

        manifest = self.adapter.build_claim()
        binary = _path(self.root, contract._BINARY_PATHS[0][2])
        binary.write_bytes(binary.read_bytes() + b"drift")
        with self.assertRaises(ExactRuntimeToolingScanError):
            self.adapter.verify(manifest)

    def test_added_included_member_changes_inventory(self) -> None:
        manifest = self.adapter.build_claim()
        added = _path(
            self.root,
            contract.EXACT_RUNTIME_PACKAGE_RELATIVE_PATH + "/added.txt",
        )
        added.write_bytes(b"new member")
        with self.assertRaises(ExactRuntimeToolingScanError):
            self.adapter.verify(manifest)

    def test_cross_file_mutation_during_guarded_scan_is_blocked(self) -> None:
        target = _path(
            self.root,
            contract.EXACT_RUNTIME_PACKAGE_RELATIVE_PATH + "/app.py",
        )
        original_bytes = target.read_bytes()
        original_digest = scanner_module._file_digest
        target_reads = 0
        blocked = False

        def observe(path: Path, **kwargs: object) -> tuple[int, str]:
            nonlocal target_reads, blocked
            result = original_digest(path, **kwargs)
            if path == target:
                target_reads += 1
                if target_reads == 2:
                    try:
                        target.write_bytes(original_bytes + b"cross-file-drift")
                    except OSError:
                        blocked = True
            return result

        with patch.object(scanner_module, "_file_digest", side_effect=observe):
            self.adapter.build_claim()
        self.assertTrue(blocked)
        self.assertEqual(original_bytes, target.read_bytes())

    def test_late_package_members_before_guard_close_fail_closed(self) -> None:
        package = _path(
            self.root, contract.EXACT_RUNTIME_PACKAGE_RELATIVE_PATH
        )
        for relative, create_parent_late in (
            ("late-root.py", False),
            ("ops/late-nested.py", False),
            ("late-directory/member.py", True),
        ):
            with self.subTest(relative=relative):
                target = _path(package, relative)
                if not create_parent_late:
                    target.parent.mkdir(parents=True, exist_ok=True)
                original_close = scanner_module._WindowsReadGuardSet.close
                injected = False

                def inject_then_close(guard: object) -> None:
                    nonlocal injected
                    if not injected:
                        injected = True
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(b"late namespace member\n")
                    original_close(guard)

                with patch.object(
                    scanner_module._WindowsReadGuardSet,
                    "close",
                    inject_then_close,
                ):
                    with self.assertRaisesRegex(
                        ExactRuntimeToolingScanError,
                        "namespace changed",
                    ):
                        self.adapter.build_claim()
                self.assertTrue(injected)
                self.assertTrue(target.is_file())
                target.unlink()
                if create_parent_late:
                    target.parent.rmdir()

    def test_canonical_claim_is_built_while_binary_guard_is_live(self) -> None:
        target = _path(self.root, contract._BINARY_PATHS[0][2])
        original_bytes = target.read_bytes()
        original_build = scanner_module.build_exact_runtime_tooling
        original_close = scanner_module._WindowsReadGuardSet.close
        claim_built = False
        blocked = False

        def observe_build(payload: object) -> dict[str, object]:
            nonlocal claim_built
            document = original_build(payload)
            claim_built = True
            return document

        def attack_before_close(guards: object) -> None:
            nonlocal blocked
            self.assertTrue(claim_built)
            try:
                target.write_bytes(original_bytes + b"late-binary-drift")
            except OSError:
                blocked = True
            original_close(guards)

        with patch.object(
            scanner_module,
            "build_exact_runtime_tooling",
            side_effect=observe_build,
        ), patch.object(
            scanner_module._WindowsReadGuardSet,
            "close",
            attack_before_close,
        ):
            self.adapter.build_claim()
        self.assertTrue(claim_built)
        self.assertTrue(blocked)
        self.assertEqual(original_bytes, target.read_bytes())

    def test_hardlink_and_unicode_nfkc_collision_fail_closed(self) -> None:
        package = _path(self.root, contract.EXACT_RUNTIME_PACKAGE_RELATIVE_PATH)
        source = package / "app.py"
        hardlink = package / "app-hardlink.py"
        os.link(source, hardlink)
        with self.assertRaises(ExactRuntimeToolingScanError):
            self.adapter.build_claim()
        hardlink.unlink()

        (package / "K.py").write_bytes(b"ascii")
        (package / "\uff2b.py").write_bytes(b"fullwidth")
        with self.assertRaisesRegex(
            ExactRuntimeToolingScanError, "identity collision"
        ):
            self.adapter.build_claim()

    def test_reparse_member_fails_before_exclusion(self) -> None:
        package = _path(self.root, contract.EXACT_RUNTIME_PACKAGE_RELATIVE_PATH)
        target = package / "app.py"
        link = package / "linked.pyc"
        try:
            link.symlink_to(target)
        except OSError as error:
            self.skipTest(f"symlink unavailable on this Windows fixture: {error}")
        with self.assertRaisesRegex(ExactRuntimeToolingScanError, "reparse"):
            self.adapter.build_claim()

    def test_noncanonical_or_mismatched_persisted_claim_fails(self) -> None:
        manifest = self.adapter.build_claim()
        document = manifest.as_dict()
        self._persist(json.dumps(document, indent=2).encode("utf-8"))
        with self.assertRaises(ExactRuntimeToolingScanError):
            self.adapter.verify_persisted()

        raw = bytearray(manifest.canonical_bytes())
        raw[-2] = ord("0") if raw[-2] != ord("0") else ord("1")
        self._persist(bytes(raw))
        with self.assertRaises(ExactRuntimeToolingScanError):
            self.adapter.verify_persisted()

    def test_production_surface_has_no_root_or_manifest_injection(self) -> None:
        self.assertEqual({}, inspect.signature(ProductionExactRuntimeToolingVerifier.load_exact_d).parameters)
        self.assertEqual(
            {"self"},
            set(inspect.signature(ProductionExactRuntimeToolingVerifier.verify_persisted).parameters),
        )
        self.assertNotIn("TestOnlyExactRuntimeToolingAdapter", __import__(
            "quant_hub.ops.local_exact_runtime_tooling_scanner",
            fromlist=["__all__"],
        ).__all__)


if __name__ == "__main__":
    unittest.main()
