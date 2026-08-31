"""Bootstrap-safe exact-D operational tooling updater.

This file intentionally imports only the Python standard library.  It is
executed directly from a sealed candidate by the already verified D Python;
it must not be imported from the installed ``quant_hub`` package it replaces.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import stat
import subprocess
from typing import Callable, Mapping
from uuid import uuid4


PRODUCTION_ROOT = PureWindowsPath(r"D:\quant\quant_platform")
SERVICE_NAME = "QuantResearchHub"
SERVICE_CLASS = "quant_hub.ops.windows_service.QuantResearchHubWindowsService"
MANIFEST_SCHEMA = "qrh-release-manifest/v2"
LEGACY_INSTALL_SCHEMA = "qrh-windows-service-install-candidate/v1"
INSTALL_SCHEMA = "qrh-windows-service-install-candidate/v2"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_INSTALL_FIELDS = {
    "schema_version",
    "service_name",
    "python_class",
    "service_executable",
    "service_executable_sha256",
    "service_python_runtime",
    "service_python_runtime_sha256",
    "service_pywin32_runtime",
    "service_pywin32_runtime_sha256",
    "service_python",
    "service_python_sha256",
    "service_host_module",
    "service_host_module_sha256",
    "service_entry_module",
    "service_entry_module_sha256",
    "deployment_cli_module",
    "deployment_cli_module_sha256",
    "access_gate_module",
    "access_gate_module_sha256",
    "deployment_runtime",
    "deployment_runtime_sha256",
    "quant_hub_package_root",
    "quant_hub_package_inventory_sha256",
    "start_type",
}
_LEGACY_INSTALL_FIELDS = _INSTALL_FIELDS - {
    "service_python_runtime",
    "service_python_runtime_sha256",
    "service_pywin32_runtime",
    "service_pywin32_runtime_sha256",
}
_PACKAGE_BINDINGS = {
    "service_host_module": "ops/windows_service.py",
    "service_entry_module": "ops/service_entry.py",
    "deployment_cli_module": "ops/vm_deploy_cli.py",
    "access_gate_module": "web/access_gate.py",
}
_INSTALL_PATH_BINDINGS = {
    "service_executable": "tooling/python/pythonservice.exe",
    "service_python_runtime": "tooling/python/python313.dll",
    "service_pywin32_runtime": "tooling/python/pywintypes313.dll",
    "service_python": "tooling/python/python.exe",
    "service_host_module": (
        "tooling/python/Lib/site-packages/quant_hub/ops/windows_service.py"
    ),
    "service_entry_module": (
        "tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py"
    ),
    "deployment_cli_module": (
        "tooling/python/Lib/site-packages/quant_hub/ops/vm_deploy_cli.py"
    ),
    "access_gate_module": (
        "tooling/python/Lib/site-packages/quant_hub/web/access_gate.py"
    ),
    "deployment_runtime": "control/deployment_runtime.json",
}
_LEGACY_INSTALL_PATH_BINDINGS = {
    **{
        field: relative
        for field, relative in _INSTALL_PATH_BINDINGS.items()
        if field not in {
            "service_executable",
            "service_python_runtime",
            "service_pywin32_runtime",
        }
    },
    "service_executable": (
        "tooling/python/Lib/site-packages/win32/pythonservice.exe"
    ),
}
_LEGACY_PYWIN32_RUNTIME = (
    "tooling/python/Lib/site-packages/pywin32_system32/pywintypes313.dll"
)
_TOOLING_SCHEMA = "qrh-exact-runtime-tooling/v2"
_LEGACY_TOOLING_SCHEMA = "qrh-exact-runtime-tooling/v1"
_TOOLING_SCOPE = "exact_runtime_tooling_claim_not_independently_observed"
_PACKAGE_ALGORITHM = "qrh-installed-package-inventory/v1"
_BINARY_FILES = (
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
_LEGACY_BINARY_FILES = (
    ("python", "python", "tooling/python/python.exe"),
    (
        "service_host",
        "pythonservice",
        "tooling/python/Lib/site-packages/win32/pythonservice.exe",
    ),
)
_KEY_FILES = (
    ("package_init", "__init__.py"),
    ("ops_init", "ops/__init__.py"),
    ("exact_runtime_entry", "ops/local_exact_runtime_entry.py"),
    ("writer_lease_holder", "ops/local_windows_writer_lease_holder.py"),
    ("writer_lease_evidence", "ops/local_windows_writer_lease_evidence.py"),
    ("exact_runtime_canary_runner", "ops/local_exact_runtime_canary_runner.py"),
    ("exact_runtime_canary_evidence", "ops/local_exact_runtime_canary_evidence.py"),
    ("exact_runtime_tooling_contract", "ops/local_exact_runtime_tooling.py"),
    ("exact_runtime_tooling_scanner", "ops/local_exact_runtime_tooling_scanner.py"),
    ("local_release_identity", "ops/local_release_identity.py"),
    ("windows_service_host", "ops/windows_service.py"),
)
_WORKSPACE_MIGRATION_FILES = (
    "0001_research_workspace.down.sql",
    "0001_research_workspace.up.sql",
    "0002_project_semantics.down.sql",
    "0002_project_semantics.up.sql",
    "0003_project_creation_command.down.sql",
    "0003_project_creation_command.up.sql",
)
_WORKSPACE_MIGRATION_SOURCE_PREFIX = (
    "runtime_contract/migrations/research_workspace/"
)
_WORKSPACE_CODE_MIGRATION_SOURCE_PREFIX = (
    "runtime_contract/code/migrations/research_workspace/"
)
_WORKSPACE_MIGRATION_PACKAGE_PREFIX = "migrations/research_workspace/"
_WORKSPACE_LEGACY_MIGRATION_PREFIX = "migrations/research_workspace/"


class ToolingUpdateError(RuntimeError):
    pass


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _identifier(value: str, label: str) -> str:
    if _ID.fullmatch(value) is None or ".." in value:
        raise ToolingUpdateError(f"{label} is invalid")
    return value


def _sha(value: str, label: str) -> str:
    if _SHA.fullmatch(value) is None:
        raise ToolingUpdateError(f"{label} is invalid")
    return value


def _is_reparse(path: Path) -> bool:
    info = path.lstat()
    return path.is_symlink() or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _guard_chain(root: Path, path: Path, *, must_exist: bool = True) -> Path:
    target = path.resolve(strict=must_exist)
    try:
        target.relative_to(root)
    except ValueError as error:
        raise ToolingUpdateError("tooling update path escaped exact D root") from error
    cursor = target if must_exist else target.parent
    while True:
        if _is_reparse(cursor):
            raise ToolingUpdateError("tooling update path contains reparse metadata")
        if cursor == root:
            break
        cursor = cursor.parent
    return target


def _regular_files(root: Path) -> dict[str, tuple[int, str]]:
    result: dict[str, tuple[int, str]] = {}
    for current_text, directories, filenames in os.walk(root):
        current = Path(current_text)
        _guard_chain(root, current)
        for directory in directories:
            child = current / directory
            if _is_reparse(child):
                raise ToolingUpdateError("tooling package contains a reparse directory")
        for filename in filenames:
            path = current / filename
            if _is_reparse(path) or not path.is_file():
                raise ToolingUpdateError("tooling package contains a non-regular file")
            relative = path.relative_to(root).as_posix()
            if "__pycache__" in path.parts or path.suffix.casefold() in {
                ".pyc",
                ".pyo",
            }:
                raise ToolingUpdateError("tooling package contains runtime cache files")
            result[relative] = (path.stat().st_size, _hash_file(path))
    return result


def _package_inventory_sha256(records: Mapping[str, tuple[int, str]]) -> str:
    """Service-install inventory used by windows_service and PowerShell."""

    payload = "".join(
        f"{name}\t{size}\t{digest}\n"
        for name, (size, digest) in sorted(records.items())
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _tooling_package_inventory_sha256(
    records: Mapping[str, tuple[int, str]],
) -> str:
    """Exact-runtime tooling inventory used by the guarded scanner."""

    inventory = [
        {"relative_path": name, "bytes": size, "sha256": digest}
        for name, (size, digest) in sorted(records.items())
    ]
    return hashlib.sha256(_canonical(inventory)).hexdigest()


def _identity_sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_claim(
    *, logical_name: str, relative_path: str, size: int, digest: str
) -> Mapping[str, object]:
    value: dict[str, object] = {
        "logical_name": logical_name,
        "relative_path": relative_path,
        "bytes": size,
        "sha256": digest,
    }
    value["file_sha256"] = _identity_sha256(value)
    return value


def _build_tooling_claim(
    root: Path,
    package_records: Mapping[str, tuple[int, str]],
    *,
    package_inventory_sha256: str | None = None,
    schema: str = _TOOLING_SCHEMA,
    binary_files: tuple[tuple[str, str, str], ...] = _BINARY_FILES,
    binary_records: Mapping[str, tuple[int, str]] | None = None,
) -> Mapping[str, object]:
    value: dict[str, object] = {
        "schema_version": schema,
        "scope": _TOOLING_SCOPE,
        "root": str(PRODUCTION_ROOT),
    }
    for field, logical_name, relative in binary_files:
        if binary_records is None:
            path = _guard_chain(root, root.joinpath(*relative.split("/")))
            size, digest = path.stat().st_size, _hash_file(path)
        else:
            try:
                size, digest = binary_records[field]
            except KeyError as error:
                raise ToolingUpdateError(
                    f"tooling binary record is absent: {field}"
                ) from error
        value[field] = _file_claim(
            logical_name=logical_name,
            relative_path=relative,
            size=size,
            digest=digest,
        )
    package: dict[str, object] = {
        "relative_path": "tooling/python/Lib/site-packages/quant_hub",
        "inventory_algorithm": _PACKAGE_ALGORITHM,
        "entry_count": len(package_records),
        "inventory_sha256": (
            package_inventory_sha256
            if package_inventory_sha256 is not None
            else _tooling_package_inventory_sha256(package_records)
        ),
    }
    package["package_sha256"] = _identity_sha256(package)
    value["package"] = package
    files: list[Mapping[str, object]] = []
    for logical_name, relative in _KEY_FILES:
        try:
            size, digest = package_records[relative]
        except KeyError as error:
            raise ToolingUpdateError(
                f"candidate tooling lacks fixed key file: {relative}"
            ) from error
        files.append(
            _file_claim(
                logical_name=logical_name,
                relative_path=relative,
                size=size,
                digest=digest,
            )
        )
    value["files"] = files
    value["file_order_sha256"] = _identity_sha256(
        [item["file_sha256"] for item in files]
    )
    value["tooling_sha256"] = _identity_sha256(value)
    return value


def _build_legacy_tooling_claim(
    root: Path,
    package_records: Mapping[str, tuple[int, str]],
    *,
    package_inventory_sha256: str | None = None,
) -> Mapping[str, object]:
    return _build_tooling_claim(
        root,
        package_records,
        package_inventory_sha256=package_inventory_sha256,
        schema=_LEGACY_TOOLING_SCHEMA,
        binary_files=_LEGACY_BINARY_FILES,
    )


def _read_candidate_manifest(
    candidate: Path,
    *,
    release_id: str,
    manifest_sha256: str,
) -> tuple[Mapping[str, object], dict[str, tuple[int, str]]]:
    path = _guard_chain(candidate, candidate / "release_manifest.json")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest_sha256:
        raise ToolingUpdateError("candidate release manifest hash differs")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ToolingUpdateError("candidate release manifest is unreadable") from error
    if (
        not isinstance(value, dict)
        or raw != _canonical(value)
        or value.get("schema_version") != MANIFEST_SCHEMA
        or value.get("release_id") != release_id
    ):
        raise ToolingUpdateError("candidate release manifest identity differs")
    inventory = value.get("inventory")
    files = inventory.get("files") if isinstance(inventory, dict) else None
    if not isinstance(files, list):
        raise ToolingUpdateError("candidate release inventory is absent")
    prefix = "runtime_contract/code/src/quant_hub/"
    expected: dict[str, tuple[int, str]] = {}
    expected_migrations: dict[str, tuple[int, str]] = {}
    expected_code_migrations: dict[str, tuple[int, str]] = {}
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "bytes", "sha256"}:
            raise ToolingUpdateError("candidate release inventory entry differs")
        name = item.get("path")
        if not isinstance(name, str):
            continue
        if name.startswith(prefix):
            relative = name[len(prefix) :]
            destination = relative
            target = expected
        elif name.startswith(_WORKSPACE_MIGRATION_SOURCE_PREFIX):
            relative = name[len(_WORKSPACE_MIGRATION_SOURCE_PREFIX) :]
            destination = _WORKSPACE_MIGRATION_PACKAGE_PREFIX + relative
            target = expected_migrations
        elif name.startswith(_WORKSPACE_CODE_MIGRATION_SOURCE_PREFIX):
            relative = name[len(_WORKSPACE_CODE_MIGRATION_SOURCE_PREFIX) :]
            destination = _WORKSPACE_MIGRATION_PACKAGE_PREFIX + relative
            target = expected_code_migrations
        elif name.startswith(_WORKSPACE_LEGACY_MIGRATION_PREFIX):
            raise ToolingUpdateError("candidate workspace migration layout differs")
        else:
            continue
        size = item.get("bytes")
        digest = item.get("sha256")
        if (
            not relative
            or (target is not expected and "/" in relative)
            or destination in target
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or not isinstance(digest, str)
        ):
            raise ToolingUpdateError("candidate package inventory entry differs")
        target[destination] = (size, _sha(digest, "candidate file hash"))
    if not expected:
        raise ToolingUpdateError("candidate package inventory is empty")
    expected_migration_paths = {
        _WORKSPACE_MIGRATION_PACKAGE_PREFIX + name
        for name in _WORKSPACE_MIGRATION_FILES
    }
    if set(expected_migrations) != expected_migration_paths:
        raise ToolingUpdateError("candidate workspace migration inventory differs")
    if expected_code_migrations and expected_code_migrations != expected_migrations:
        raise ToolingUpdateError("candidate code migration mirror differs")
    if set(expected).intersection(expected_migrations):
        raise ToolingUpdateError("candidate tooling destination inventory collides")
    source = _guard_chain(
        candidate, candidate / "runtime_contract" / "code" / "src" / "quant_hub"
    )
    if _regular_files(source) != expected:
        raise ToolingUpdateError("candidate package bytes differ from release inventory")
    migration_source = _guard_chain(
        candidate,
        candidate / "runtime_contract" / "migrations" / "research_workspace",
    )
    source_migrations = {
        _WORKSPACE_MIGRATION_PACKAGE_PREFIX + name: record
        for name, record in _regular_files(migration_source).items()
    }
    if source_migrations != expected_migrations:
        raise ToolingUpdateError(
            "candidate workspace migration bytes differ from release inventory"
        )
    code_migration_source = (
        candidate / "runtime_contract" / "code" / "migrations" / "research_workspace"
    )
    if expected_code_migrations:
        code_migration_source = _guard_chain(candidate, code_migration_source)
        source_code_migrations = {
            _WORKSPACE_MIGRATION_PACKAGE_PREFIX + name: record
            for name, record in _regular_files(code_migration_source).items()
        }
        if source_code_migrations != expected_code_migrations:
            raise ToolingUpdateError(
                "candidate code migration mirror bytes differ from release inventory"
            )
    elif os.path.lexists(code_migration_source):
        raise ToolingUpdateError("candidate code migration mirror is unsealed")
    expected.update(expected_migrations)
    return value, expected


def _write_atomic(path: Path, value: Mapping[str, object], *, suffix: str) -> None:
    temporary = path.with_name(f".{path.name}.{suffix}.partial")
    if temporary.exists():
        raise ToolingUpdateError("tooling update temporary file already exists")
    raw = _canonical(value)
    try:
        with temporary.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        if temporary.exists():
            temporary.unlink()
        raise


def _write_atomic_new(
    path: Path, value: Mapping[str, object], *, suffix: str
) -> None:
    """Publish canonical bytes atomically without replacing an existing claim."""

    temporary = path.with_name(f".{path.name}.{suffix}.partial")
    if temporary.exists() or os.path.lexists(path):
        raise ToolingUpdateError("tooling bootstrap claim target already exists")
    raw = _canonical(value)
    published = False
    try:
        with temporary.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        # Same-volume link publishes complete bytes with create-if-absent
        # semantics on Windows and on the test platforms.
        os.link(temporary, path)
        published = True
        temporary.unlink()
    except BaseException:
        if published:
            if path.read_bytes() != raw:
                raise ToolingUpdateError(
                    "bootstrapped tooling claim changed during publication"
                )
            path.unlink()
        if temporary.exists():
            temporary.unlink()
        raise


_JOURNAL_SCHEMA = "qrh-tooling-update-pending/v2"
_JOURNAL_PHASES = {
    "intent",
    "staged",
    "package_swapped",
    "host_bundle_published",
    "claims_swapped",
    "service_rebound",
    "verified",
}
_JOURNAL_FIELDS = {
    "schema_version",
    "attempt_id",
    "release_id",
    "release_manifest_sha256",
    "install_generation",
    "old_package_inventory_sha256",
    "new_package_inventory_sha256",
    "old_image_path",
    "new_image_path",
    "old_install_sha256",
    "new_install_sha256",
    "old_tooling_state",
    "old_tooling_sha256",
    "new_tooling_sha256",
    "root_bundle_provenance",
    "root_bundle_members",
    "phase",
    "authority",
    "journal_sha256",
}
_JOURNAL_MEMBER_FIELDS = {
    "name",
    "source_relative_path",
    "destination_relative_path",
    "bytes",
    "sha256",
    "created_by_transaction",
}


class _SimulatedProcessCrash(BaseException):
    """Test-only crash cut which deliberately bypasses in-process recovery."""


def _journal_hash(value: Mapping[str, object]) -> str:
    return hashlib.sha256(
        _canonical({key: item for key, item in value.items() if key != "journal_sha256"})
    ).hexdigest()


def _seal_journal(root: Path, value: Mapping[str, object]) -> dict[str, object]:
    document = dict(value)
    document.pop("journal_sha256", None)
    document["journal_sha256"] = _journal_hash(document)
    return _validate_journal(root, document)


def _validate_journal(root: Path, value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _JOURNAL_FIELDS:
        raise ToolingUpdateError("tooling update journal schema differs")
    document = dict(value)
    if (
        document.get("schema_version") != _JOURNAL_SCHEMA
        or document.get("authority") != "coordination_only"
        or document.get("install_generation") not in {"v1", "v2"}
        or document.get("phase") not in _JOURNAL_PHASES
        or document.get("old_tooling_state") not in {"absent", "present"}
        or document.get("root_bundle_provenance")
        not in {"derived_from_live_v1", "persisted_v2_exact_claim"}
    ):
        raise ToolingUpdateError("tooling update journal identity differs")
    if document["root_bundle_provenance"] != (
        "derived_from_live_v1"
        if document["install_generation"] == "v1"
        else "persisted_v2_exact_claim"
    ):
        raise ToolingUpdateError("tooling update journal provenance differs")
    if type(document.get("attempt_id")) is not str or type(
        document.get("release_id")
    ) is not str:
        raise ToolingUpdateError("tooling update journal identifier type differs")
    _identifier(document["attempt_id"], "journal attempt ID")
    _identifier(document["release_id"], "journal release ID")
    for field in (
        "release_manifest_sha256",
        "old_package_inventory_sha256",
        "new_package_inventory_sha256",
        "old_install_sha256",
        "new_install_sha256",
        "new_tooling_sha256",
        "journal_sha256",
    ):
        if type(document.get(field)) is not str:
            raise ToolingUpdateError(f"journal {field} type differs")
        _sha(document[field], f"journal {field}")
    if document["old_tooling_state"] == "present":
        if type(document.get("old_tooling_sha256")) is not str:
            raise ToolingUpdateError("journal old tooling type differs")
        _sha(document["old_tooling_sha256"], "journal old tooling")
    elif document.get("old_tooling_sha256") != "absent":
        raise ToolingUpdateError("absent old tooling journal identity differs")
    if type(document.get("old_image_path")) is not str or type(
        document.get("new_image_path")
    ) is not str:
        raise ToolingUpdateError("tooling update journal ImagePath type differs")
    old_image = PureWindowsPath(document["old_image_path"])
    new_image = PureWindowsPath(document["new_image_path"])
    logical_root = PureWindowsPath(str(root))
    expected_old = (
        logical_root
        / "tooling"
        / "python"
        / "Lib"
        / "site-packages"
        / "win32"
        / "pythonservice.exe"
        if document["install_generation"] == "v1"
        else logical_root / "tooling" / "python" / "pythonservice.exe"
    )
    expected_new = logical_root / "tooling" / "python" / "pythonservice.exe"
    if old_image != expected_old or new_image != expected_new:
        raise ToolingUpdateError("tooling update journal ImagePath differs")
    members = document.get("root_bundle_members")
    if not isinstance(members, list) or len(members) != 3:
        raise ToolingUpdateError("tooling update journal bundle differs")
    expected_names = ("pythonservice.exe", "python313.dll", "pywintypes313.dll")
    expected_sources = (
        {
            "pythonservice.exe": _LEGACY_INSTALL_PATH_BINDINGS["service_executable"],
            "python313.dll": "tooling/python/python313.dll",
            "pywintypes313.dll": _LEGACY_PYWIN32_RUNTIME,
        }
        if document["install_generation"] == "v1"
        else {
            name: f"tooling/python/{name}" for name in expected_names
        }
    )
    for member, name in zip(members, expected_names, strict=True):
        if not isinstance(member, dict) or set(member) != _JOURNAL_MEMBER_FIELDS:
            raise ToolingUpdateError("tooling update journal member schema differs")
        if (
            member.get("name") != name
            or member.get("source_relative_path") != expected_sources[name]
            or member.get("destination_relative_path") != f"tooling/python/{name}"
            or type(member.get("bytes")) is not int
            or int(member["bytes"]) < 1
            or type(member.get("created_by_transaction")) is not bool
            or bool(member["created_by_transaction"])
            != (document["install_generation"] == "v1" and name != "python313.dll")
        ):
            raise ToolingUpdateError("tooling update journal member identity differs")
        if type(member.get("sha256")) is not str:
            raise ToolingUpdateError("tooling update journal member hash type differs")
        _sha(member["sha256"], f"journal bundle {name}")
    if document["journal_sha256"] != _journal_hash(document):
        raise ToolingUpdateError("tooling update journal self hash differs")
    return document


def _read_journal(root: Path, path: Path) -> dict[str, object]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ToolingUpdateError("tooling update journal is unreadable") from error
    document = _validate_journal(root, value)
    if raw != _canonical(document):
        raise ToolingUpdateError("tooling update journal is not canonical")
    return document


def _write_journal_new(
    root: Path, path: Path, value: Mapping[str, object]
) -> dict[str, object]:
    document = _seal_journal(root, value)
    _write_atomic_new(path, document, suffix=str(document["attempt_id"]))
    return document


def _advance_journal(
    root: Path, path: Path, value: Mapping[str, object], phase: str
) -> dict[str, object]:
    if phase not in _JOURNAL_PHASES:
        raise ToolingUpdateError("tooling update journal phase is invalid")
    document = _seal_journal(root, {**value, "phase": phase})
    _write_atomic(path, document, suffix=str(document["attempt_id"]))
    return document


def _write_prior_new(path: Path, raw: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


class _ToolingUpdateLock:
    def __init__(self, path: Path):
        self._path = path
        self._stream = None

    def __enter__(self) -> "_ToolingUpdateLock":
        stream = self._path.open("a+b")
        try:
            stream.seek(0, os.SEEK_END)
            if stream.tell() == 0:
                stream.write(b"\0")
                stream.flush()
                os.fsync(stream.fileno())
            stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException as error:
            stream.close()
            raise ToolingUpdateError("another tooling update owns the exclusive lock") from error
        self._stream = stream
        return self

    def __exit__(self, error_type, error, traceback) -> None:
        stream = self._stream
        self._stream = None
        if stream is None:
            return
        try:
            stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        finally:
            stream.close()


def _validate_installed_bindings(
    root: Path,
    install: object,
    package: Path,
    package_records: Mapping[str, tuple[int, str]],
) -> tuple[Mapping[str, object], str]:
    """Close the legacy fixed-D install before a claim may be bootstrapped."""

    if not isinstance(install, dict):
        raise ToolingUpdateError("service install candidate identity differs")
    schema = install.get("schema_version")
    if schema == INSTALL_SCHEMA:
        fields = _INSTALL_FIELDS
        path_bindings = _INSTALL_PATH_BINDINGS
        generation = "v2"
    elif schema == LEGACY_INSTALL_SCHEMA:
        fields = _LEGACY_INSTALL_FIELDS
        path_bindings = _LEGACY_INSTALL_PATH_BINDINGS
        generation = "v1"
    else:
        raise ToolingUpdateError("service install candidate identity differs")
    if (
        set(install) != fields
        or install.get("service_name") != SERVICE_NAME
        or install.get("python_class") != SERVICE_CLASS
        or install.get("start_type") != "automatic"
    ):
        raise ToolingUpdateError("service install candidate identity differs")
    expected_package = _guard_chain(root, package)
    if install.get("quant_hub_package_root") != str(expected_package):
        raise ToolingUpdateError("installed tooling package path differs")
    if install.get(
        "quant_hub_package_inventory_sha256"
    ) != _package_inventory_sha256(package_records):
        raise ToolingUpdateError("installed tooling package binding differs")
    for field, relative in path_bindings.items():
        expected = _guard_chain(root, root.joinpath(*relative.split("/")))
        if not expected.is_file():
            raise ToolingUpdateError("installed tooling binding is not a regular file")
        if (
            install.get(field) != str(expected)
            or install.get(f"{field}_sha256") != _hash_file(expected)
        ):
            raise ToolingUpdateError(f"installed tooling binding differs: {field}")
    if generation == "v1":
        for relative in (
            "tooling/python/python313.dll",
            _LEGACY_PYWIN32_RUNTIME,
        ):
            dependency = _guard_chain(root, root.joinpath(*relative.split("/")))
            if not dependency.is_file():
                raise ToolingUpdateError(
                    "legacy service loader dependency is unavailable"
                )
    return install, generation


def _copy_package(
    source: Path,
    migration_source: Path,
    destination: Path,
    expected: Mapping[str, tuple[int, str]],
) -> None:
    destination.mkdir()
    try:
        for name, (size, digest) in sorted(expected.items()):
            if name.startswith(_WORKSPACE_MIGRATION_PACKAGE_PREFIX):
                source_name = name[len(_WORKSPACE_MIGRATION_PACKAGE_PREFIX) :]
                source_path = migration_source / source_name
            else:
                source_path = source.joinpath(*name.split("/"))
            target = destination.joinpath(*name.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            raw = source_path.read_bytes()
            if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
                raise ToolingUpdateError("candidate package changed during staging")
            with target.open("xb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        if _regular_files(destination) != dict(expected):
            raise ToolingUpdateError("staged tooling package inventory differs")
    except BaseException:
        _remove_tree(destination)
        raise


def _host_bundle_sources(root: Path, generation: str) -> Mapping[str, Path]:
    if generation == "v1":
        relatives = {
            "pythonservice.exe": _LEGACY_INSTALL_PATH_BINDINGS[
                "service_executable"
            ],
            "python313.dll": "tooling/python/python313.dll",
            "pywintypes313.dll": _LEGACY_PYWIN32_RUNTIME,
        }
    elif generation == "v2":
        relatives = {
            "pythonservice.exe": _INSTALL_PATH_BINDINGS["service_executable"],
            "python313.dll": _INSTALL_PATH_BINDINGS["service_python_runtime"],
            "pywintypes313.dll": _INSTALL_PATH_BINDINGS[
                "service_pywin32_runtime"
            ],
        }
    else:
        raise ToolingUpdateError("service host bundle generation is invalid")
    return {
        name: _guard_chain(root, root.joinpath(*relative.split("/")))
        for name, relative in relatives.items()
    }


def _copy_host_bundle(
    sources: Mapping[str, Path],
    destination: Path,
    expected: Mapping[str, tuple[int, str]],
) -> Mapping[str, tuple[int, str]]:
    destination.mkdir()
    records: dict[str, tuple[int, str]] = {}
    try:
        for name in ("pythonservice.exe", "python313.dll", "pywintypes313.dll"):
            source = sources[name]
            if not source.is_file():
                raise ToolingUpdateError("service host bundle source is unavailable")
            raw = source.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            if expected.get(name) != (len(raw), digest):
                raise ToolingUpdateError(
                    "service host bundle source changed during staging"
                )
            target = destination / name
            with target.open("xb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            records[name] = (len(raw), digest)
        if records != dict(expected) or _regular_files(destination) != records:
            raise ToolingUpdateError("staged service host bundle differs")
        return records
    except BaseException:
        _remove_tree(destination)
        raise


def _service_image_path() -> str:
    completed = subprocess.run(
        ("sc.exe", "qc", SERVICE_NAME),
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if completed.returncode:
        raise ToolingUpdateError("cannot query Windows service ImagePath")
    for line in completed.stdout.splitlines():
        if "BINARY_PATH_NAME" in line and ":" in line:
            return line.split(":", 1)[1].strip().strip('"')
    raise ToolingUpdateError("Windows service ImagePath is absent")


def _rebind_service_executable(expected_current: str, replacement: str) -> None:
    if PureWindowsPath(_service_image_path()) != PureWindowsPath(expected_current):
        raise ToolingUpdateError("Windows service ImagePath differs before rebind")
    completed = subprocess.run(
        ("sc.exe", "config", SERVICE_NAME, "binPath=", replacement),
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if completed.returncode:
        raise ToolingUpdateError("Windows service ImagePath rebind failed")
    if PureWindowsPath(_service_image_path()) != PureWindowsPath(replacement):
        rollback = subprocess.run(
            ("sc.exe", "config", SERVICE_NAME, "binPath=", expected_current),
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if (
            rollback.returncode
            or PureWindowsPath(_service_image_path())
            != PureWindowsPath(expected_current)
        ):
            raise ToolingUpdateError(
                "Windows service ImagePath rebind and rollback did not close"
            )
        raise ToolingUpdateError("Windows service ImagePath readback differs")


def _remove_tree(root: Path) -> None:
    if not root.exists():
        return
    if _is_reparse(root) or not root.is_dir():
        raise ToolingUpdateError("tooling cleanup target is not an ordinary directory")
    directories: list[Path] = []
    for current_text, names, files in os.walk(root):
        current = Path(current_text)
        directories.extend(current / name for name in names)
        for filename in files:
            path = current / filename
            if _is_reparse(path) or not path.is_file():
                raise ToolingUpdateError("tooling cleanup encountered a non-regular file")
            path.unlink()
    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        if _is_reparse(directory):
            raise ToolingUpdateError("tooling cleanup encountered a reparse directory")
        directory.rmdir()
    root.rmdir()


def _service_stopped() -> bool:
    completed = subprocess.run(
        ("sc.exe", "query", SERVICE_NAME),
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    output = completed.stdout.upper()
    return completed.returncode == 0 and "STATE" in output and "STOPPED" in output


def _snapshot(root: Path) -> Mapping[str, tuple[str, int, int]]:
    entries: dict[str, tuple[str, int, int]] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        _guard_chain(root, path)
        relative = path.relative_to(root).as_posix()
        info = path.stat()
        if path.is_dir():
            entries[relative] = ("directory", 0, info.st_mtime_ns)
        elif path.is_file():
            entries[relative] = ("file", info.st_size, info.st_mtime_ns)
        else:
            raise ToolingUpdateError("VM write audit found a non-regular entry")
    return entries


def _finalize_audit(
    root: Path,
    before: Mapping[str, tuple[str, int, int]],
    *,
    outcome: str,
) -> Path:
    after = _snapshot(root)
    writes: list[Mapping[str, object]] = []
    for relative in sorted(set(before) | set(after)):
        old = before.get(relative)
        new = after.get(relative)
        if old == new:
            continue
        top = relative.split("/", 1)[0]
        if top not in {
            "incoming",
            "releases",
            "control",
            "state",
            "audit",
            "locks",
            "logs",
            "tmp",
            "checkout",
            "tooling",
        }:
            raise ToolingUpdateError("tooling update wrote outside declared D areas")
        path = root.joinpath(*relative.split("/"))
        writes.append(
            {
                "path": str(PRODUCTION_ROOT.joinpath(*relative.split("/"))),
                "relative_path": relative,
                "change": (
                    "created" if old is None else "deleted" if new is None else "modified"
                ),
                "entry_type": (new or old)[0],
                "bytes": (new or old)[1],
                "sha256": (
                    _hash_file(path)
                    if new is not None and new[0] == "file"
                    else None
                ),
            }
        )
    audit_id = f"vm-write-audit-{uuid4().hex}"
    directory = root / "audit" / "events"
    directory.mkdir(parents=True, exist_ok=True)
    _guard_chain(root, directory)
    path = directory / f"{audit_id}.json"
    report = {
        "schema_version": "qrh-production-vm-write-audit/v1",
        "operation": "update-vm-tooling",
        "authority_root": str(PRODUCTION_ROOT),
        "declared_write_set": {
            area: str(PRODUCTION_ROOT / area)
            for area in sorted(
                {
                    "incoming",
                    "releases",
                    "control",
                    "state",
                    "audit",
                    "locks",
                    "logs",
                    "tmp",
                    "checkout",
                    "tooling",
                }
            )
        },
        "observed_writes": writes,
        "verdict": "pass",
        "audit_id": audit_id,
        "outcome": outcome,
        "audit_record_path": str(
            PRODUCTION_ROOT / "audit" / "events" / path.name
        ),
    }
    with path.open("xb") as stream:
        stream.write(_canonical(report))
        stream.flush()
        os.fsync(stream.fileno())
    return path


def _inventory_sha256_or_absent(path: Path) -> str | None:
    if not os.path.lexists(path):
        return None
    if _is_reparse(path) or not path.is_dir():
        raise ToolingUpdateError("tooling recovery package is not an ordinary directory")
    return _package_inventory_sha256(_regular_files(path))


def _file_sha256_or_absent(path: Path) -> str | None:
    if not os.path.lexists(path):
        return None
    if _is_reparse(path) or not path.is_file():
        raise ToolingUpdateError("tooling recovery claim is not a regular file")
    return _hash_file(path)


def _remove_exact_package(path: Path, expected_sha256: str) -> None:
    observed = _inventory_sha256_or_absent(path)
    if observed is None:
        return
    if observed != expected_sha256:
        raise ToolingUpdateError("tooling recovery package inventory differs")
    _remove_tree(path)


def _remove_exact_host_stage(
    path: Path, members: Mapping[str, tuple[int, str]]
) -> None:
    if not os.path.lexists(path):
        return
    if _is_reparse(path) or not path.is_dir():
        raise ToolingUpdateError("tooling recovery host stage is not ordinary")
    observed = _regular_files(path)
    if not set(observed).issubset(members) or any(
        observed[name] != members[name] for name in observed
    ):
        raise ToolingUpdateError("tooling recovery host stage differs")
    _remove_tree(path)


def _journal_transaction_paths(
    root: Path, attempt: str
) -> Mapping[str, Path]:
    package_parent = (
        root / "tooling" / "python" / "Lib" / "site-packages"
    )
    control = root / "control"
    return {
        "package": package_parent / "quant_hub",
        "stage": package_parent / f"quant_hub.update-{attempt}.partial",
        "prior": package_parent / f"quant_hub.update-{attempt}.prior",
        "host_stage": root
        / "tooling"
        / "python"
        / f".scm-host.update-{attempt}.partial",
        "install": control / "service_install_candidate.json",
        "install_prior": control / f".service_install_candidate.{attempt}.prior",
        "tooling": control / "exact_runtime_tooling.json",
        "tooling_prior": control / f".exact_runtime_tooling.{attempt}.prior",
        "journal": control / "tooling_update_pending.json",
    }


def _journal_bundle_records(
    journal: Mapping[str, object]
) -> dict[str, tuple[int, str]]:
    return {
        str(member["name"]): (int(member["bytes"]), str(member["sha256"]))
        for member in journal["root_bundle_members"]  # type: ignore[index]
    }


def _verify_root_bundle(
    root: Path, journal: Mapping[str, object], *, old_state: bool
) -> None:
    for member in journal["root_bundle_members"]:  # type: ignore[index]
        target = root.joinpath(
            *str(member["destination_relative_path"]).split("/")
        )
        observed = _file_sha256_or_absent(target)
        created = bool(member["created_by_transaction"])
        if old_state and created:
            if observed is not None:
                raise ToolingUpdateError("tooling recovery old bundle still has new member")
        elif (
            observed != member["sha256"]
            or target.stat().st_size != member["bytes"]
        ):
            raise ToolingUpdateError("tooling recovery root bundle differs")


def _verify_bundle_sources(
    root: Path, journal: Mapping[str, object]
) -> None:
    for member in journal["root_bundle_members"]:  # type: ignore[index]
        source = root.joinpath(*str(member["source_relative_path"]).split("/"))
        observed = _file_sha256_or_absent(source)
        if (
            observed != member["sha256"]
            or source.stat().st_size != member["bytes"]
        ):
            raise ToolingUpdateError(
                "tooling recovery source bundle differs from journal"
            )


def _remove_created_root_bundle(
    root: Path, journal: Mapping[str, object]
) -> None:
    for member in reversed(journal["root_bundle_members"]):  # type: ignore[index]
        if not bool(member["created_by_transaction"]):
            continue
        target = root.joinpath(
            *str(member["destination_relative_path"]).split("/")
        )
        observed = _file_sha256_or_absent(target)
        if observed is None:
            continue
        if observed != member["sha256"] or target.stat().st_size != member["bytes"]:
            raise ToolingUpdateError("tooling recovery created bundle member differs")
        target.unlink()


def _cleanup_transaction_artifacts(
    root: Path,
    journal: Mapping[str, object],
    *,
    final_package_sha256: str,
) -> None:
    paths = _journal_transaction_paths(root, str(journal["attempt_id"]))
    old_package = str(journal["old_package_inventory_sha256"])
    new_package = str(journal["new_package_inventory_sha256"])
    for name, expected in (("stage", new_package), ("prior", old_package)):
        _remove_exact_package(paths[name], expected)
    _remove_exact_host_stage(paths["host_stage"], _journal_bundle_records(journal))
    for name, expected in (
        ("install_prior", str(journal["old_install_sha256"])),
        ("tooling_prior", str(journal["old_tooling_sha256"])),
    ):
        path = paths[name]
        observed = _file_sha256_or_absent(path)
        if observed is None:
            continue
        if expected == "absent" or observed != expected:
            raise ToolingUpdateError("tooling recovery prior claim differs")
        path.unlink()
    if _inventory_sha256_or_absent(paths["package"]) != final_package_sha256:
        raise ToolingUpdateError("tooling recovery final package differs")


def _recover_pending_transaction(
    root: Path,
    *,
    service_stopped_probe: Callable[[], bool],
    service_image_path_probe: Callable[[], str],
    service_binding_updater: Callable[[str, str], None],
) -> str | None:
    journal_path = root / "control" / "tooling_update_pending.json"
    if not os.path.lexists(journal_path):
        return None
    journal = _read_journal(root, journal_path)
    if not service_stopped_probe():
        raise ToolingUpdateError(
            "D service must be STOPPED before tooling update recovery"
        )
    paths = _journal_transaction_paths(root, str(journal["attempt_id"]))
    for path in paths.values():
        _guard_chain(root, path, must_exist=os.path.lexists(path))
    old_image = str(journal["old_image_path"])
    new_image = str(journal["new_image_path"])
    current_image = service_image_path_probe()

    if journal["phase"] == "verified":
        if (
            PureWindowsPath(current_image) == PureWindowsPath(new_image)
            and _inventory_sha256_or_absent(paths["package"])
            == journal["new_package_inventory_sha256"]
            and _file_sha256_or_absent(paths["install"])
            == journal["new_install_sha256"]
            and _file_sha256_or_absent(paths["tooling"])
            == journal["new_tooling_sha256"]
        ):
            _verify_root_bundle(root, journal, old_state=False)
            if not service_stopped_probe():
                raise ToolingUpdateError(
                    "D service became RUNNING before verified recovery cleanup"
                )
            _cleanup_transaction_artifacts(
                root,
                journal,
                final_package_sha256=str(journal["new_package_inventory_sha256"]),
            )
            journal_path.unlink()
            return "completed_exact_new"

    if (
        PureWindowsPath(old_image) != PureWindowsPath(new_image)
        and PureWindowsPath(current_image) == PureWindowsPath(new_image)
    ):
        _verify_bundle_sources(root, journal)
        if not service_stopped_probe():
            raise ToolingUpdateError("D service became RUNNING before recovery rebind")
        service_binding_updater(new_image, old_image)
        if PureWindowsPath(service_image_path_probe()) != PureWindowsPath(old_image):
            raise ToolingUpdateError("tooling recovery SCM reverse readback differs")
    elif PureWindowsPath(current_image) != PureWindowsPath(old_image):
        raise ToolingUpdateError("tooling recovery SCM ImagePath is ambiguous")
    if not service_stopped_probe():
        raise ToolingUpdateError(
            "D service became RUNNING before tooling recovery rollback"
        )

    current_install = _file_sha256_or_absent(paths["install"])
    if current_install == journal["new_install_sha256"]:
        if _file_sha256_or_absent(paths["install_prior"]) != journal["old_install_sha256"]:
            raise ToolingUpdateError("tooling recovery install prior differs")
        os.replace(paths["install_prior"], paths["install"])
    elif current_install != journal["old_install_sha256"]:
        raise ToolingUpdateError("tooling recovery install claim is ambiguous")

    current_tooling = _file_sha256_or_absent(paths["tooling"])
    if journal["old_tooling_state"] == "absent":
        if current_tooling == journal["new_tooling_sha256"]:
            paths["tooling"].unlink()
        elif current_tooling is not None:
            raise ToolingUpdateError("tooling recovery bootstrapped claim is ambiguous")
    elif current_tooling == journal["new_tooling_sha256"]:
        if _file_sha256_or_absent(paths["tooling_prior"]) != journal["old_tooling_sha256"]:
            raise ToolingUpdateError("tooling recovery tooling prior differs")
        os.replace(paths["tooling_prior"], paths["tooling"])
    elif current_tooling != journal["old_tooling_sha256"]:
        raise ToolingUpdateError("tooling recovery tooling claim is ambiguous")

    _remove_created_root_bundle(root, journal)
    current_package = _inventory_sha256_or_absent(paths["package"])
    prior_package = _inventory_sha256_or_absent(paths["prior"])
    if current_package == journal["new_package_inventory_sha256"]:
        if prior_package != journal["old_package_inventory_sha256"]:
            raise ToolingUpdateError("tooling recovery package prior differs")
        _remove_tree(paths["package"])
        os.replace(paths["prior"], paths["package"])
    elif current_package is None and prior_package == journal["old_package_inventory_sha256"]:
        os.replace(paths["prior"], paths["package"])
    elif current_package != journal["old_package_inventory_sha256"]:
        raise ToolingUpdateError("tooling recovery package state is ambiguous")

    _verify_bundle_sources(root, journal)
    _verify_root_bundle(root, journal, old_state=True)
    if (
        _file_sha256_or_absent(paths["install"])
        != journal["old_install_sha256"]
        or (
            journal["old_tooling_state"] == "present"
            and _file_sha256_or_absent(paths["tooling"])
            != journal["old_tooling_sha256"]
        )
        or (
            journal["old_tooling_state"] == "absent"
            and _file_sha256_or_absent(paths["tooling"]) is not None
        )
        or PureWindowsPath(service_image_path_probe()) != PureWindowsPath(old_image)
    ):
        raise ToolingUpdateError("tooling recovery exact old state did not close")
    _cleanup_transaction_artifacts(
        root,
        journal,
        final_package_sha256=str(journal["old_package_inventory_sha256"]),
    )
    journal_path.unlink()
    return "rolled_back_exact_old"


def update_vm_tooling(
    *,
    vm_root: Path,
    release_id: str,
    release_manifest_sha256: str,
    attempt_id: str,
    allow_test_root: bool = False,
    service_stopped_probe: Callable[[], bool] = _service_stopped,
    service_image_path_probe: Callable[[], str] = _service_image_path,
    service_binding_updater: Callable[[str, str], None] = _rebind_service_executable,
    fail_after_package_to_prior: bool = False,
    fail_after_package_swap: bool = False,
    fail_before_second_root_bundle_publish: bool = False,
    fail_after_host_bundle_publish: bool = False,
    fail_after_claims_swap: bool = False,
    fail_after_service_rebind: bool = False,
    simulate_process_crash_after_claims_swap: bool = False,
) -> Mapping[str, object]:
    """Install one sealed candidate package under one recoverable transaction."""

    root = vm_root.resolve(strict=True)
    if not allow_test_root and PureWindowsPath(str(root)) != PRODUCTION_ROOT:
        raise ToolingUpdateError(r"tooling update root must be D:\quant\quant_platform")
    if allow_test_root and PureWindowsPath(str(root)) == PRODUCTION_ROOT:
        raise ToolingUpdateError("test tooling update cannot target production D")
    if not allow_test_root and (
        service_stopped_probe is not _service_stopped
        or service_image_path_probe is not _service_image_path
        or service_binding_updater is not _rebind_service_executable
    ):
        raise ToolingUpdateError("production service probes are not injectable")
    if (
        fail_after_package_to_prior
        or fail_after_package_swap
        or fail_before_second_root_bundle_publish
        or fail_after_host_bundle_publish
        or fail_after_claims_swap
        or fail_after_service_rebind
        or simulate_process_crash_after_claims_swap
    ) and not allow_test_root:
        raise ToolingUpdateError("tooling update fault injection is test-only")
    _guard_chain(root, root)
    control = _guard_chain(root, root / "control")
    lock_path = _guard_chain(
        root, control / "tooling_update.lock", must_exist=False
    )
    with _ToolingUpdateLock(lock_path):
        pending_path = control / "tooling_update_pending.json"
        pending = (
            _read_journal(root, pending_path)
            if os.path.lexists(pending_path)
            else None
        )
        recovery = _recover_pending_transaction(
            root,
            service_stopped_probe=service_stopped_probe,
            service_image_path_probe=service_image_path_probe,
            service_binding_updater=service_binding_updater,
        )
        if (
            recovery == "completed_exact_new"
            and pending is not None
            and pending["attempt_id"] == attempt_id
            and pending["release_id"] == release_id
            and pending["release_manifest_sha256"] == release_manifest_sha256
        ):
            try:
                tooling = json.loads(
                    (control / "exact_runtime_tooling.json").read_text(
                        encoding="utf-8"
                    )
                )
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ToolingUpdateError(
                    "recovered exact-new tooling claim is unreadable"
                ) from error
            tooling_sha256 = tooling.get("tooling_sha256")
            if type(tooling_sha256) is not str:
                raise ToolingUpdateError(
                    "recovered exact runtime tooling identity differs"
                )
            _sha(tooling_sha256, "recovered exact runtime tooling")
            return {
                "schema_version": "qrh-tooling-update-result/v2",
                "status": "updated",
                "attempt_id": attempt_id,
                "release_id": release_id,
                "release_manifest_sha256": release_manifest_sha256,
                "quant_hub_package_inventory_sha256": pending[
                    "new_package_inventory_sha256"
                ],
                "exact_runtime_tooling_sha256": tooling_sha256,
                "root_bundle_provenance": pending["root_bundle_provenance"],
                "restart_recovery": recovery,
            }
        return _update_vm_tooling_locked(
            root=root,
            release_id=release_id,
            release_manifest_sha256=release_manifest_sha256,
            attempt_id=attempt_id,
            service_stopped_probe=service_stopped_probe,
            service_image_path_probe=service_image_path_probe,
            service_binding_updater=service_binding_updater,
            recovery=recovery,
            fail_after_package_to_prior=fail_after_package_to_prior,
            fail_after_package_swap=fail_after_package_swap,
            fail_before_second_root_bundle_publish=(
                fail_before_second_root_bundle_publish
            ),
            fail_after_host_bundle_publish=fail_after_host_bundle_publish,
            fail_after_claims_swap=fail_after_claims_swap,
            fail_after_service_rebind=fail_after_service_rebind,
            simulate_process_crash_after_claims_swap=(
                simulate_process_crash_after_claims_swap
            ),
        )


def _update_vm_tooling_locked(
    *,
    root: Path,
    release_id: str,
    release_manifest_sha256: str,
    attempt_id: str,
    service_stopped_probe: Callable[[], bool],
    service_image_path_probe: Callable[[], str],
    service_binding_updater: Callable[[str, str], None],
    recovery: str | None,
    fail_after_package_to_prior: bool,
    fail_after_package_swap: bool,
    fail_before_second_root_bundle_publish: bool,
    fail_after_host_bundle_publish: bool,
    fail_after_claims_swap: bool,
    fail_after_service_rebind: bool,
    simulate_process_crash_after_claims_swap: bool,
) -> Mapping[str, object]:
    release = _identifier(release_id, "release ID")
    attempt = _identifier(attempt_id, "attempt ID")
    expected_manifest = _sha(release_manifest_sha256, "release manifest")
    if not service_stopped_probe():
        raise ToolingUpdateError("D service must be STOPPED at tooling update start")
    candidate = _guard_chain(root, root / "incoming" / f"{release}.partial")
    _manifest, expected = _read_candidate_manifest(
        candidate,
        release_id=release,
        manifest_sha256=expected_manifest,
    )
    source = candidate / "runtime_contract" / "code" / "src" / "quant_hub"
    migration_source = (
        candidate / "runtime_contract" / "migrations" / "research_workspace"
    )
    package = _guard_chain(
        root,
        root / "tooling" / "python" / "Lib" / "site-packages" / "quant_hub",
    )
    package_parent = package.parent
    stage = package_parent / f"quant_hub.update-{attempt}.partial"
    prior = package_parent / f"quant_hub.update-{attempt}.prior"
    tooling_python = _guard_chain(root, root / "tooling" / "python")
    host_stage = tooling_python / f".scm-host.update-{attempt}.partial"
    control = _guard_chain(root, root / "control")
    install_path = _guard_chain(root, control / "service_install_candidate.json")
    install_prior = control / f".service_install_candidate.{attempt}.prior"
    tooling_path = control / "exact_runtime_tooling.json"
    tooling_bootstrap = not os.path.lexists(tooling_path)
    tooling_path = _guard_chain(
        root, tooling_path, must_exist=not tooling_bootstrap
    )
    tooling_prior = control / f".exact_runtime_tooling.{attempt}.prior"
    journal_path = control / "tooling_update_pending.json"
    for path in (
        stage,
        prior,
        host_stage,
        install_prior,
        tooling_prior,
        journal_path,
    ):
        _guard_chain(root, path, must_exist=False)
        if os.path.lexists(path):
            raise ToolingUpdateError("tooling recovery left a transaction artifact")

    try:
        install = json.loads(install_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ToolingUpdateError("service install candidate is unreadable") from error
    old_inventory = _regular_files(package)
    install, install_generation = _validate_installed_bindings(
        root, install, package, old_inventory
    )
    old_service_executable = str(install["service_executable"])
    if PureWindowsPath(service_image_path_probe()) != PureWindowsPath(
        old_service_executable
    ):
        raise ToolingUpdateError("Windows service ImagePath differs from install claim")
    old_tooling_builder = (
        _build_legacy_tooling_claim
        if install_generation == "v1"
        else _build_tooling_claim
    )
    expected_old_toolings = (
        old_tooling_builder(root, old_inventory),
        old_tooling_builder(
            root,
            old_inventory,
            package_inventory_sha256=_package_inventory_sha256(old_inventory),
        ),
    )
    tooling_raw: bytes | None = None
    if not tooling_bootstrap:
        try:
            tooling_raw = tooling_path.read_bytes()
            tooling = json.loads(tooling_raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ToolingUpdateError("exact runtime tooling claim is unreadable") from error
        if tooling_raw != _canonical(tooling) or tooling not in expected_old_toolings:
            raise ToolingUpdateError("exact runtime tooling claim differs from live bytes")

    host_sources = _host_bundle_sources(root, install_generation)
    expected_host_records = {
        name: (path.stat().st_size, _hash_file(path))
        for name, path in host_sources.items()
    }
    if expected_host_records["pythonservice.exe"][1] != install.get(
        "service_executable_sha256"
    ):
        raise ToolingUpdateError("service host source differs from install claim")
    if install_generation == "v2" and (
        expected_host_records["python313.dll"][1]
        != install.get("service_python_runtime_sha256")
        or expected_host_records["pywintypes313.dll"][1]
        != install.get("service_pywin32_runtime_sha256")
    ):
        raise ToolingUpdateError("service loader source differs from install claim")
    host_records = expected_host_records
    updated = dict(install)
    updated["schema_version"] = INSTALL_SCHEMA
    for field, name in (
        ("service_executable", "pythonservice.exe"),
        ("service_python_runtime", "python313.dll"),
        ("service_pywin32_runtime", "pywintypes313.dll"),
    ):
        relative = _INSTALL_PATH_BINDINGS[field]
        updated[field] = str(root.joinpath(*relative.split("/")).resolve())
        updated[f"{field}_sha256"] = host_records[name][1]
    updated["quant_hub_package_inventory_sha256"] = (
        _package_inventory_sha256(expected)
    )
    for field, relative in _PACKAGE_BINDINGS.items():
        updated[f"{field}_sha256"] = expected[relative][1]
    python_path = _guard_chain(
        root, root.joinpath(*_INSTALL_PATH_BINDINGS["service_python"].split("/"))
    )
    binary_records = {
        "python": (python_path.stat().st_size, _hash_file(python_path)),
        "service_host": host_records["pythonservice.exe"],
        "service_python_runtime": host_records["python313.dll"],
        "service_pywin32_runtime": host_records["pywintypes313.dll"],
    }
    updated_tooling = _build_tooling_claim(
        root, expected, binary_records=binary_records
    )
    install_raw = install_path.read_bytes()
    updated_install_raw = _canonical(updated)
    updated_tooling_raw = _canonical(updated_tooling)
    provenance = (
        "derived_from_live_v1"
        if install_generation == "v1"
        else "persisted_v2_exact_claim"
    )
    source_relatives = {
        name: path.relative_to(root).as_posix()
        for name, path in host_sources.items()
    }
    journal = _write_journal_new(root, journal_path, {
        "schema_version": _JOURNAL_SCHEMA,
        "attempt_id": attempt,
        "release_id": release,
        "release_manifest_sha256": expected_manifest,
        "install_generation": install_generation,
        "old_package_inventory_sha256": _package_inventory_sha256(old_inventory),
        "new_package_inventory_sha256": _package_inventory_sha256(expected),
        "old_image_path": old_service_executable,
        "new_image_path": str(updated["service_executable"]),
        "old_install_sha256": hashlib.sha256(install_raw).hexdigest(),
        "new_install_sha256": hashlib.sha256(updated_install_raw).hexdigest(),
        "old_tooling_state": "absent" if tooling_bootstrap else "present",
        "old_tooling_sha256": (
            "absent" if tooling_raw is None else hashlib.sha256(tooling_raw).hexdigest()
        ),
        "new_tooling_sha256": hashlib.sha256(updated_tooling_raw).hexdigest(),
        "root_bundle_provenance": provenance,
        "root_bundle_members": [
            {
                "name": name,
                "source_relative_path": source_relatives[name],
                "destination_relative_path": f"tooling/python/{name}",
                "bytes": host_records[name][0],
                "sha256": host_records[name][1],
                "created_by_transaction": (
                    install_generation == "v1" and name != "python313.dll"
                ),
            }
            for name in ("pythonservice.exe", "python313.dll", "pywintypes313.dll")
        ],
        "phase": "intent",
        "authority": "coordination_only",
    })
    try:
        _copy_package(source, migration_source, stage, expected)
        _copy_host_bundle(host_sources, host_stage, expected_host_records)
        _write_prior_new(install_prior, install_raw)
        if tooling_raw is not None:
            _write_prior_new(tooling_prior, tooling_raw)
        journal = _advance_journal(root, journal_path, journal, "staged")
        if not service_stopped_probe():
            raise ToolingUpdateError("D service became RUNNING before package swap")
        os.replace(package, prior)
        if fail_after_package_to_prior:
            raise ToolingUpdateError("injected failure after package moved to prior")
        os.replace(stage, package)
        journal = _advance_journal(root, journal_path, journal, "package_swapped")
        if fail_after_package_swap:
            raise ToolingUpdateError("injected failure after package swap")
        if install_generation == "v1":
            published_count = 0
            for name in ("pythonservice.exe", "pywintypes313.dll"):
                if fail_before_second_root_bundle_publish and published_count == 1:
                    raise ToolingUpdateError(
                        "injected failure before second root bundle publish"
                    )
                destination = tooling_python / name
                _guard_chain(root, destination, must_exist=False)
                if os.path.lexists(destination):
                    raise ToolingUpdateError(
                        "service host bundle destination already exists during v1 migration"
                    )
                os.replace(host_stage / name, destination)
                published_count += 1
        for name, (size, digest) in host_records.items():
            destination = _guard_chain(root, tooling_python / name)
            if (
                not destination.is_file()
                or destination.stat().st_size != size
                or _hash_file(destination) != digest
            ):
                raise ToolingUpdateError("published service host bundle differs")
        journal = _advance_journal(
            root, journal_path, journal, "host_bundle_published"
        )
        if fail_after_host_bundle_publish:
            raise ToolingUpdateError("injected failure after host bundle publish")
        _write_atomic(install_path, updated, suffix=attempt)
        if tooling_bootstrap:
            _write_atomic_new(tooling_path, updated_tooling, suffix=attempt)
        else:
            _write_atomic(tooling_path, updated_tooling, suffix=attempt)
        journal = _advance_journal(root, journal_path, journal, "claims_swapped")
        if simulate_process_crash_after_claims_swap:
            raise _SimulatedProcessCrash()
        if fail_after_claims_swap:
            raise ToolingUpdateError("injected failure after claims swap")
        new_service_executable = str(updated["service_executable"])
        if not service_stopped_probe():
            raise ToolingUpdateError("D service became RUNNING before SCM rebind")
        if PureWindowsPath(old_service_executable) != PureWindowsPath(
            new_service_executable
        ):
            service_binding_updater(
                old_service_executable, new_service_executable
            )
        if PureWindowsPath(service_image_path_probe()) != PureWindowsPath(
            new_service_executable
        ):
            raise ToolingUpdateError("Windows service ImagePath final readback differs")
        journal = _advance_journal(root, journal_path, journal, "service_rebound")
        if fail_after_service_rebind:
            raise ToolingUpdateError("injected failure after service rebind")
        if not service_stopped_probe():
            raise ToolingUpdateError("D service became RUNNING before final validation")
        if _regular_files(package) != expected:
            raise ToolingUpdateError("installed tooling package changed after swap")
        if json.loads(install_path.read_text(encoding="utf-8")) != updated:
            raise ToolingUpdateError("updated service install candidate differs")
        if json.loads(tooling_path.read_text(encoding="utf-8")) != updated_tooling:
            raise ToolingUpdateError("updated exact runtime tooling claim differs")
        _verify_root_bundle(root, journal, old_state=False)
        journal = _advance_journal(root, journal_path, journal, "verified")
    except _SimulatedProcessCrash:
        raise
    except BaseException:
        try:
            _recover_pending_transaction(
                root,
                service_stopped_probe=service_stopped_probe,
                service_image_path_probe=service_image_path_probe,
                service_binding_updater=service_binding_updater,
            )
        except BaseException as error:
            raise ToolingUpdateError(
                "tooling update failed; recoverable journal remains"
            ) from error
        raise
    completion = _recover_pending_transaction(
        root,
        service_stopped_probe=service_stopped_probe,
        service_image_path_probe=service_image_path_probe,
        service_binding_updater=service_binding_updater,
    )
    if completion != "completed_exact_new":
        raise ToolingUpdateError("tooling update verified completion did not close")
    return {
        "schema_version": "qrh-tooling-update-result/v2",
        "status": "updated",
        "attempt_id": attempt,
        "release_id": release,
        "release_manifest_sha256": expected_manifest,
        "quant_hub_package_inventory_sha256": updated[
            "quant_hub_package_inventory_sha256"
        ],
        "exact_runtime_tooling_sha256": updated_tooling["tooling_sha256"],
        "root_bundle_provenance": provenance,
        "restart_recovery": recovery or "not_required",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vm-root", type=Path, required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--release-manifest-sha256", required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    before: Mapping[str, tuple[str, int, int]] | None = None
    root: Path | None = None
    try:
        root = args.vm_root.resolve(strict=True)
        before = _snapshot(root)
        result = update_vm_tooling(
            vm_root=root,
            release_id=args.release_id,
            release_manifest_sha256=args.release_manifest_sha256,
            attempt_id=args.attempt_id,
        )
    except Exception as error:
        if root is not None and before is not None:
            _finalize_audit(root, before, outcome="failed")
        print(
            json.dumps(
                {
                    "schema_version": "qrh-tooling-update-error/v1",
                    "status": "error",
                    "error_type": type(error).__name__,
                },
                sort_keys=True,
            )
        )
        return 2
    _finalize_audit(root, before, outcome="succeeded")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
