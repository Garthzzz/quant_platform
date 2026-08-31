"""Exact runtime tooling manifest 的纯 closed-schema 持久合同。

本模块不读取文件系统、不持有 handle、不导入 application，也不形成 live tooling
closure 或部署资格。即使文档全部 hash 正确，它仍只是 child/controller 后续必须
共同复验的可重放 claim。
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import PurePosixPath
import re
from typing import Mapping

from .local_release_identity import canonical_bytes, identity_sha256


EXACT_RUNTIME_TOOLING_SCHEMA = "qrh-exact-runtime-tooling/v2"
EXACT_RUNTIME_TOOLING_SCOPE = (
    "exact_runtime_tooling_claim_not_independently_observed"
)
EXACT_RUNTIME_TOOLING_ROOT = r"D:\quant\quant_platform"
EXACT_RUNTIME_PACKAGE_RELATIVE_PATH = (
    "tooling/python/Lib/site-packages/quant_hub"
)
EXACT_RUNTIME_PACKAGE_INVENTORY_ALGORITHM = (
    "qrh-installed-package-inventory/v1"
)

_BINARY_PATHS = (
    ("python", "python", "tooling/python/python.exe"),
    (
        "service_host",
        "pythonservice",
        "tooling/python/pythonservice.exe",
    ),
    (
        "service_python_runtime",
        "python313",
        "tooling/python/python313.dll",
    ),
    (
        "service_pywin32_runtime",
        "pywintypes313",
        "tooling/python/pywintypes313.dll",
    ),
)
_KEY_FILES = (
    ("package_init", "__init__.py"),
    ("ops_init", "ops/__init__.py"),
    ("exact_runtime_entry", "ops/local_exact_runtime_entry.py"),
    (
        "writer_lease_holder",
        "ops/local_windows_writer_lease_holder.py",
    ),
    (
        "writer_lease_evidence",
        "ops/local_windows_writer_lease_evidence.py",
    ),
    (
        "exact_runtime_canary_runner",
        "ops/local_exact_runtime_canary_runner.py",
    ),
    (
        "exact_runtime_canary_evidence",
        "ops/local_exact_runtime_canary_evidence.py",
    ),
    (
        "exact_runtime_tooling_contract",
        "ops/local_exact_runtime_tooling.py",
    ),
    (
        "exact_runtime_tooling_scanner",
        "ops/local_exact_runtime_tooling_scanner.py",
    ),
    ("local_release_identity", "ops/local_release_identity.py"),
    ("windows_service_host", "ops/windows_service.py"),
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_FILE_BYTES = 8 * 1024 * 1024 * 1024
_MAX_PACKAGE_ENTRIES = 200_000


class ExactRuntimeToolingError(ValueError):
    """Tooling manifest 不满足 closed/canonical/hash 合同。"""


def _mapping(value: object, fields: set[str], *, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ExactRuntimeToolingError(f"{label} 必须是 object")
    document = dict(value)
    if set(document) != fields or any(type(key) is not str for key in document):
        raise ExactRuntimeToolingError(f"{label} schema 不闭合")
    return document


def _sha256(value: object, *, label: str) -> str:
    if (
        type(value) is not str
        or _SHA256_RE.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise ExactRuntimeToolingError(f"{label} SHA-256 无效")
    return value


def _positive_int(value: object, *, label: str, maximum: int) -> int:
    if type(value) is not int or not 0 < value <= maximum:
        raise ExactRuntimeToolingError(f"{label} 必须是 exact positive integer")
    return value


def _relative_path(value: object, *, expected: str, label: str) -> str:
    if type(value) is not str or value != expected or "\\" in value:
        raise ExactRuntimeToolingError(f"{label} 不是固定 POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise ExactRuntimeToolingError(f"{label} relative path 无效")
    return value


def _self_hash(document: dict[str, object], field: str, *, label: str) -> None:
    observed = _sha256(document[field], label=f"{label}.{field}")
    payload = {key: value for key, value in document.items() if key != field}
    if observed != identity_sha256(payload):
        raise ExactRuntimeToolingError(f"{label} self hash 不匹配")


def _binary(value: object, *, logical_name: str, path: str) -> dict[str, object]:
    document = _mapping(
        value,
        {"logical_name", "relative_path", "bytes", "sha256", "file_sha256"},
        label=f"tooling binary {logical_name}",
    )
    if document["logical_name"] != logical_name:
        raise ExactRuntimeToolingError(f"tooling binary {logical_name} logical name 漂移")
    _relative_path(
        document["relative_path"],
        expected=path,
        label=f"tooling binary {logical_name}.relative_path",
    )
    _positive_int(
        document["bytes"],
        label=f"tooling binary {logical_name}.bytes",
        maximum=_MAX_FILE_BYTES,
    )
    _sha256(document["sha256"], label=f"tooling binary {logical_name}.sha256")
    _self_hash(document, "file_sha256", label=f"tooling binary {logical_name}")
    return document


def _package(value: object) -> dict[str, object]:
    document = _mapping(
        value,
        {
            "relative_path",
            "inventory_algorithm",
            "entry_count",
            "inventory_sha256",
            "package_sha256",
        },
        label="tooling package",
    )
    _relative_path(
        document["relative_path"],
        expected=EXACT_RUNTIME_PACKAGE_RELATIVE_PATH,
        label="tooling package.relative_path",
    )
    if document["inventory_algorithm"] != EXACT_RUNTIME_PACKAGE_INVENTORY_ALGORITHM:
        raise ExactRuntimeToolingError("tooling package inventory algorithm 漂移")
    count = _positive_int(
        document["entry_count"],
        label="tooling package.entry_count",
        maximum=_MAX_PACKAGE_ENTRIES,
    )
    if count < len(_KEY_FILES):
        raise ExactRuntimeToolingError("tooling package entry_count 少于固定关键文件")
    _sha256(document["inventory_sha256"], label="tooling package.inventory_sha256")
    _self_hash(document, "package_sha256", label="tooling package")
    return document


def _key_file(
    value: object, *, logical_name: str, path: str
) -> dict[str, object]:
    document = _mapping(
        value,
        {"logical_name", "relative_path", "bytes", "sha256", "file_sha256"},
        label=f"tooling key file {logical_name}",
    )
    if document["logical_name"] != logical_name:
        raise ExactRuntimeToolingError(f"tooling key file {logical_name} logical name 漂移")
    _relative_path(
        document["relative_path"],
        expected=path,
        label=f"tooling key file {logical_name}.relative_path",
    )
    _positive_int(
        document["bytes"],
        label=f"tooling key file {logical_name}.bytes",
        maximum=_MAX_FILE_BYTES,
    )
    _sha256(document["sha256"], label=f"tooling key file {logical_name}.sha256")
    _self_hash(document, "file_sha256", label=f"tooling key file {logical_name}")
    return document


def validate_exact_runtime_tooling(value: object) -> dict[str, object]:
    document = _mapping(
        value,
        {
            "schema_version",
            "scope",
            "root",
            "python",
            "service_host",
            "service_python_runtime",
            "service_pywin32_runtime",
            "package",
            "files",
            "file_order_sha256",
            "tooling_sha256",
        },
        label="exact runtime tooling",
    )
    if (
        document["schema_version"] != EXACT_RUNTIME_TOOLING_SCHEMA
        or document["scope"] != EXACT_RUNTIME_TOOLING_SCOPE
        or document["root"] != EXACT_RUNTIME_TOOLING_ROOT
    ):
        raise ExactRuntimeToolingError("exact runtime tooling schema/scope/root 漂移")
    for field, logical_name, path in _BINARY_PATHS:
        document[field] = _binary(
            document[field], logical_name=logical_name, path=path
        )
    document["package"] = _package(document["package"])
    values = document["files"]
    if type(values) is not list or len(values) != len(_KEY_FILES):
        raise ExactRuntimeToolingError("tooling key files 必须固定、有序且闭合")
    files = [
        _key_file(value, logical_name=logical_name, path=path)
        for value, (logical_name, path) in zip(values, _KEY_FILES, strict=True)
    ]
    document["files"] = files
    observed_order = _sha256(
        document["file_order_sha256"], label="tooling file_order_sha256"
    )
    expected_order = identity_sha256(
        [item["file_sha256"] for item in files]
    )
    if observed_order != expected_order:
        raise ExactRuntimeToolingError("tooling key file order hash 不匹配")
    _self_hash(document, "tooling_sha256", label="exact runtime tooling")
    return document


def _seal_file(value: object, *, logical_name: str, path: str) -> dict[str, object]:
    document = _mapping(
        value,
        {"logical_name", "relative_path", "bytes", "sha256"},
        label=f"tooling input {logical_name}",
    )
    if document["logical_name"] != logical_name:
        raise ExactRuntimeToolingError(f"tooling input {logical_name} logical name 漂移")
    _relative_path(
        document["relative_path"],
        expected=path,
        label=f"tooling input {logical_name}.relative_path",
    )
    _positive_int(
        document["bytes"],
        label=f"tooling input {logical_name}.bytes",
        maximum=_MAX_FILE_BYTES,
    )
    _sha256(document["sha256"], label=f"tooling input {logical_name}.sha256")
    document["file_sha256"] = identity_sha256(document)
    return document


def build_exact_runtime_tooling(payload: Mapping[str, object]) -> dict[str, object]:
    document = _mapping(
        payload,
        {
            "schema_version",
            "scope",
            "root",
            "python",
            "service_host",
            "service_python_runtime",
            "service_pywin32_runtime",
            "package",
            "files",
        },
        label="exact runtime tooling payload",
    )
    for field, logical_name, path in _BINARY_PATHS:
        document[field] = _seal_file(
            document[field], logical_name=logical_name, path=path
        )
    package = _mapping(
        document["package"],
        {"relative_path", "inventory_algorithm", "entry_count", "inventory_sha256"},
        label="tooling package input",
    )
    _relative_path(
        package["relative_path"],
        expected=EXACT_RUNTIME_PACKAGE_RELATIVE_PATH,
        label="tooling package input.relative_path",
    )
    if package["inventory_algorithm"] != EXACT_RUNTIME_PACKAGE_INVENTORY_ALGORITHM:
        raise ExactRuntimeToolingError("tooling package input algorithm 漂移")
    _positive_int(
        package["entry_count"],
        label="tooling package input.entry_count",
        maximum=_MAX_PACKAGE_ENTRIES,
    )
    _sha256(package["inventory_sha256"], label="tooling package input.inventory_sha256")
    package["package_sha256"] = identity_sha256(package)
    document["package"] = package
    values = document["files"]
    if type(values) is not list or len(values) != len(_KEY_FILES):
        raise ExactRuntimeToolingError("tooling key file input 数量无效")
    files = [
        _seal_file(value, logical_name=logical_name, path=path)
        for value, (logical_name, path) in zip(values, _KEY_FILES, strict=True)
    ]
    document["files"] = files
    document["file_order_sha256"] = identity_sha256(
        [item["file_sha256"] for item in files]
    )
    document["tooling_sha256"] = identity_sha256(document)
    return validate_exact_runtime_tooling(document)


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ExactRuntimeToolingError("exact runtime tooling JSON 存在重复 key")
        document[key] = value
    return document


def parse_exact_runtime_tooling_bytes(raw: bytes) -> "ExactRuntimeToolingManifest":
    if type(raw) is not bytes or not raw:
        raise ExactRuntimeToolingError("exact runtime tooling bytes 无效")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ExactRuntimeToolingError("exact runtime tooling 不是 strict UTF-8 JSON") from error
    manifest = ExactRuntimeToolingManifest.from_document(value)
    if manifest.canonical_bytes() != raw:
        raise ExactRuntimeToolingError("exact runtime tooling bytes 非 canonical")
    return manifest


@dataclass(frozen=True, slots=True)
class ExactRuntimeToolingManifest:
    """可持久化 tooling claim；不是 live closure。"""

    _raw: bytes

    @classmethod
    def from_document(cls, value: object) -> "ExactRuntimeToolingManifest":
        return cls(canonical_bytes(validate_exact_runtime_tooling(value)))

    def as_dict(self) -> dict[str, object]:
        value = json.loads(self._raw.decode("utf-8"))
        if type(value) is not dict:
            raise ExactRuntimeToolingError("exact runtime tooling 内部 bytes 损坏")
        return value

    def canonical_bytes(self) -> bytes:
        return bytes(self._raw)

    @property
    def tooling_sha256(self) -> str:
        return str(self.as_dict()["tooling_sha256"])


__all__ = [
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
]
