from __future__ import annotations

import copy
import hashlib
import json
import pickle
import unittest

from quant_hub.ops import local_exact_runtime_tooling as module
from quant_hub.ops.local_exact_runtime_tooling import (
    EXACT_RUNTIME_PACKAGE_INVENTORY_ALGORITHM,
    EXACT_RUNTIME_PACKAGE_RELATIVE_PATH,
    EXACT_RUNTIME_TOOLING_ROOT,
    EXACT_RUNTIME_TOOLING_SCHEMA,
    EXACT_RUNTIME_TOOLING_SCOPE,
    ExactRuntimeToolingError,
    ExactRuntimeToolingManifest,
    build_exact_runtime_tooling,
    parse_exact_runtime_tooling_bytes,
    validate_exact_runtime_tooling,
)


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _file(logical_name: str, path: str, index: int) -> dict[str, object]:
    return {
        "logical_name": logical_name,
        "relative_path": path,
        "bytes": 100 + index,
        "sha256": _hash(f"{logical_name}-{index}"),
    }


def _payload() -> dict[str, object]:
    return {
        "schema_version": EXACT_RUNTIME_TOOLING_SCHEMA,
        "scope": EXACT_RUNTIME_TOOLING_SCOPE,
        "root": EXACT_RUNTIME_TOOLING_ROOT,
        "python": _file("python", "tooling/python/python.exe", 1),
        "service_host": _file(
            "pythonservice",
            "tooling/python/Lib/site-packages/win32/pythonservice.exe",
            2,
        ),
        "package": {
            "relative_path": EXACT_RUNTIME_PACKAGE_RELATIVE_PATH,
            "inventory_algorithm": EXACT_RUNTIME_PACKAGE_INVENTORY_ALGORITHM,
            "entry_count": 100,
            "inventory_sha256": _hash("package-inventory"),
        },
        "files": [
            _file(logical_name, path, index)
            for index, (logical_name, path) in enumerate(
                module._KEY_FILES, start=10
            )
        ],
    }


def _resign(document: dict[str, object]) -> dict[str, object]:
    payload = copy.deepcopy(document)
    payload.pop("file_order_sha256", None)
    payload.pop("tooling_sha256", None)
    for field in ("python", "service_host"):
        payload[field].pop("file_sha256", None)
    payload["package"].pop("package_sha256", None)
    for value in payload["files"]:
        value.pop("file_sha256", None)
    return build_exact_runtime_tooling(payload)


class ExactRuntimeToolingManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = build_exact_runtime_tooling(_payload())

    def test_roundtrip_is_canonical_and_persistent_only(self) -> None:
        manifest = ExactRuntimeToolingManifest.from_document(self.document)
        parsed = parse_exact_runtime_tooling_bytes(manifest.canonical_bytes())
        self.assertEqual(self.document, parsed.as_dict())
        self.assertEqual(self.document["tooling_sha256"], parsed.tooling_sha256)
        self.assertEqual(manifest.canonical_bytes(), pickle.loads(pickle.dumps(manifest)).canonical_bytes())
        self.assertFalse(
            any(
                hasattr(manifest, name)
                for name in ("qualify", "observe", "open_handles", "as_live")
            )
        )

    def test_top_level_schema_scope_root_and_extra_fields_are_closed(self) -> None:
        for field, value in (
            ("schema_version", "qrh-exact-runtime-tooling/v2"),
            ("scope", "live_tooling_closure"),
            ("root", r"D:\quant\other"),
        ):
            changed = copy.deepcopy(self.document)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ExactRuntimeToolingError):
                validate_exact_runtime_tooling(_resign(changed))
        changed = copy.deepcopy(self.document)
        changed["extra"] = True
        with self.assertRaises(ExactRuntimeToolingError):
            validate_exact_runtime_tooling(changed)

    def test_fixed_binary_key_file_order_and_paths_survive_full_resign(self) -> None:
        self.assertEqual(
            "tooling/python/Lib/site-packages/quant_hub",
            self.document["package"]["relative_path"],
        )
        self.assertEqual("__init__.py", self.document["files"][0]["relative_path"])
        self.assertTrue(
            all(
                not str(record["relative_path"]).startswith("quant_hub/")
                for record in self.document["files"]
            )
        )
        mutations = []
        changed = copy.deepcopy(self.document)
        changed["python"]["relative_path"] = "tooling/python/pythonw.exe"
        mutations.append(changed)
        changed = copy.deepcopy(self.document)
        changed["files"][0], changed["files"][1] = changed["files"][1], changed["files"][0]
        mutations.append(changed)
        changed = copy.deepcopy(self.document)
        changed["files"][2]["logical_name"] = "service_entry"
        mutations.append(changed)
        changed = copy.deepcopy(self.document)
        changed["package"]["relative_path"] = "tooling/python/Lib/site-packages/quant_hub_alias"
        mutations.append(changed)
        for index, changed in enumerate(mutations):
            with self.subTest(case=index), self.assertRaises(ExactRuntimeToolingError):
                _resign(changed)

    def test_exact_integer_bounds_reject_bool_and_invalid_counts(self) -> None:
        for field, value in (("bytes", True), ("bytes", 0), ("bytes", 8 * 1024**3 + 1)):
            changed = copy.deepcopy(self.document)
            changed["files"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(
                ExactRuntimeToolingError
            ):
                _resign(changed)
        for value in (True, 8, 200_001):
            changed = copy.deepcopy(self.document)
            changed["package"]["entry_count"] = value
            with self.subTest(entry_count=value), self.assertRaises(ExactRuntimeToolingError):
                _resign(changed)

    def test_nested_order_and_top_hashes_are_all_recomputed(self) -> None:
        cases = []
        for path in (
            ("python", "file_sha256"),
            ("service_host", "file_sha256"),
            ("package", "package_sha256"),
            ("files", 0, "file_sha256"),
            ("file_order_sha256",),
            ("tooling_sha256",),
        ):
            changed = copy.deepcopy(self.document)
            target = changed
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = _hash("wrong")
            cases.append((path, changed))
        for path, changed in cases:
            with self.subTest(path=path), self.assertRaises(ExactRuntimeToolingError):
                validate_exact_runtime_tooling(changed)

    def test_duplicate_key_and_noncanonical_bytes_are_rejected(self) -> None:
        raw = ExactRuntimeToolingManifest.from_document(self.document).canonical_bytes()
        duplicate = raw.replace(
            b'{"file_order_sha256":',
            b'{"schema_version":"duplicate","file_order_sha256":',
            1,
        )
        with self.assertRaises(ExactRuntimeToolingError):
            parse_exact_runtime_tooling_bytes(duplicate)
        pretty = json.dumps(self.document, ensure_ascii=False, indent=2).encode("utf-8")
        with self.assertRaises(ExactRuntimeToolingError):
            parse_exact_runtime_tooling_bytes(pretty)

    def test_public_surface_exposes_no_live_upgrade(self) -> None:
        self.assertEqual(
            {
                "EXACT_RUNTIME_PACKAGE_INVENTORY_ALGORITHM",
                "EXACT_RUNTIME_PACKAGE_RELATIVE_PATH",
                "EXACT_RUNTIME_TOOLING_ROOT",
                "EXACT_RUNTIME_TOOLING_SCHEMA",
                "EXACT_RUNTIME_TOOLING_SCOPE",
                "ExactRuntimeToolingError",
                "ExactRuntimeToolingManifest",
                "build_exact_runtime_tooling",
                "parse_exact_runtime_tooling_bytes",
                "validate_exact_runtime_tooling",
            },
            set(module.__all__),
        )
        self.assertFalse(
            any("live" in name.casefold() or "qualif" in name.casefold() for name in module.__all__)
        )


if __name__ == "__main__":
    unittest.main()
