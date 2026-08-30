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
MANIFEST_SCHEMA = "qrh-release-manifest/v2"
INSTALL_SCHEMA = "qrh-windows-service-install-candidate/v1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_INSTALL_FIELDS = {
    "schema_version",
    "service_name",
    "python_class",
    "service_executable",
    "service_executable_sha256",
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
_PACKAGE_BINDINGS = {
    "service_host_module": "ops/windows_service.py",
    "service_entry_module": "ops/service_entry.py",
    "deployment_cli_module": "ops/vm_deploy_cli.py",
    "access_gate_module": "web/access_gate.py",
}
_TOOLING_SCHEMA = "qrh-exact-runtime-tooling/v1"
_TOOLING_SCOPE = "exact_runtime_tooling_claim_not_independently_observed"
_PACKAGE_ALGORITHM = "qrh-installed-package-inventory/v1"
_BINARY_FILES = (
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
    payload = "".join(
        f"{name}\t{size}\t{digest}\n"
        for name, (size, digest) in sorted(records.items())
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


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
    root: Path, package_records: Mapping[str, tuple[int, str]]
) -> Mapping[str, object]:
    value: dict[str, object] = {
        "schema_version": _TOOLING_SCHEMA,
        "scope": _TOOLING_SCOPE,
        "root": str(PRODUCTION_ROOT),
    }
    for field, logical_name, relative in _BINARY_FILES:
        path = _guard_chain(root, root.joinpath(*relative.split("/")))
        value[field] = _file_claim(
            logical_name=logical_name,
            relative_path=relative,
            size=path.stat().st_size,
            digest=_hash_file(path),
        )
    package: dict[str, object] = {
        "relative_path": "tooling/python/Lib/site-packages/quant_hub",
        "inventory_algorithm": _PACKAGE_ALGORITHM,
        "entry_count": len(package_records),
        "inventory_sha256": _package_inventory_sha256(package_records),
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
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "bytes", "sha256"}:
            raise ToolingUpdateError("candidate release inventory entry differs")
        name = item.get("path")
        if not isinstance(name, str) or not name.startswith(prefix):
            continue
        relative = name[len(prefix) :]
        size = item.get("bytes")
        digest = item.get("sha256")
        if (
            not relative
            or relative in expected
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or not isinstance(digest, str)
        ):
            raise ToolingUpdateError("candidate package inventory entry differs")
        expected[relative] = (size, _sha(digest, "candidate file hash"))
    if not expected:
        raise ToolingUpdateError("candidate package inventory is empty")
    source = _guard_chain(
        candidate, candidate / "runtime_contract" / "code" / "src" / "quant_hub"
    )
    if _regular_files(source) != expected:
        raise ToolingUpdateError("candidate package bytes differ from release inventory")
    return value, expected


def _write_atomic(path: Path, value: Mapping[str, object], *, suffix: str) -> None:
    temporary = path.with_name(f".{path.name}.{suffix}.partial")
    if temporary.exists():
        raise ToolingUpdateError("tooling update temporary file already exists")
    raw = _canonical(value)
    with temporary.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _copy_package(
    source: Path,
    destination: Path,
    expected: Mapping[str, tuple[int, str]],
) -> None:
    destination.mkdir()
    try:
        for name, (size, digest) in sorted(expected.items()):
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


def update_vm_tooling(
    *,
    vm_root: Path,
    release_id: str,
    release_manifest_sha256: str,
    attempt_id: str,
    allow_test_root: bool = False,
    service_stopped_probe: Callable[[], bool] = _service_stopped,
    fail_after_package_swap: bool = False,
) -> Mapping[str, object]:
    """Install one sealed candidate package and atomically rebind its hashes."""

    release = _identifier(release_id, "release ID")
    attempt = _identifier(attempt_id, "attempt ID")
    expected_manifest = _sha(release_manifest_sha256, "release manifest")
    root = vm_root.resolve(strict=True)
    if not allow_test_root and PureWindowsPath(str(root)) != PRODUCTION_ROOT:
        raise ToolingUpdateError(r"tooling update root must be D:\quant\quant_platform")
    if allow_test_root and PureWindowsPath(str(root)) == PRODUCTION_ROOT:
        raise ToolingUpdateError("test tooling update cannot target production D")
    if not allow_test_root and service_stopped_probe is not _service_stopped:
        raise ToolingUpdateError("production service-state probe is not injectable")
    if fail_after_package_swap and not allow_test_root:
        raise ToolingUpdateError("tooling update fault injection is test-only")
    _guard_chain(root, root)
    candidate = _guard_chain(root, root / "incoming" / f"{release}.partial")
    _manifest, expected = _read_candidate_manifest(
        candidate,
        release_id=release,
        manifest_sha256=expected_manifest,
    )
    if not service_stopped_probe():
        raise ToolingUpdateError("D service must be STOPPED before tooling update")

    source = candidate / "runtime_contract" / "code" / "src" / "quant_hub"
    package = _guard_chain(
        root,
        root / "tooling" / "python" / "Lib" / "site-packages" / "quant_hub",
    )
    package_parent = package.parent
    stage = package_parent / f"quant_hub.update-{attempt}.partial"
    prior = package_parent / f"quant_hub.update-{attempt}.prior"
    control = _guard_chain(root, root / "control")
    install_path = _guard_chain(root, control / "service_install_candidate.json")
    install_prior = control / f".service_install_candidate.{attempt}.prior"
    tooling_path = _guard_chain(root, control / "exact_runtime_tooling.json")
    tooling_prior = control / f".exact_runtime_tooling.{attempt}.prior"
    journal_path = control / "tooling_update_pending.json"
    for path in (
        stage,
        prior,
        install_prior,
        tooling_prior,
        journal_path,
    ):
        _guard_chain(root, path, must_exist=False)
        if path.exists():
            raise ToolingUpdateError("another or interrupted tooling update exists")

    try:
        install = json.loads(install_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ToolingUpdateError("service install candidate is unreadable") from error
    if (
        not isinstance(install, dict)
        or set(install) != _INSTALL_FIELDS
        or install.get("schema_version") != INSTALL_SCHEMA
        or install.get("service_name") != SERVICE_NAME
        or install.get("start_type") != "automatic"
        or Path(str(install.get("quant_hub_package_root"))).resolve(strict=True)
        != package
    ):
        raise ToolingUpdateError("service install candidate identity differs")
    old_inventory = _regular_files(package)
    if _package_inventory_sha256(old_inventory) != install.get(
        "quant_hub_package_inventory_sha256"
    ):
        raise ToolingUpdateError("installed tooling package binding differs")
    for field, relative in _PACKAGE_BINDINGS.items():
        path = package.joinpath(*relative.split("/"))
        if (
            Path(str(install.get(field))).resolve(strict=True) != path
            or install.get(f"{field}_sha256") != _hash_file(path)
        ):
            raise ToolingUpdateError("installed tooling module binding differs")
    try:
        tooling_raw = tooling_path.read_bytes()
        tooling = json.loads(tooling_raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ToolingUpdateError("exact runtime tooling claim is unreadable") from error
    expected_old_tooling = _build_tooling_claim(root, old_inventory)
    if tooling_raw != _canonical(tooling) or tooling != expected_old_tooling:
        raise ToolingUpdateError("exact runtime tooling claim differs from live bytes")

    _copy_package(source, stage, expected)
    updated = dict(install)
    updated["quant_hub_package_inventory_sha256"] = (
        _package_inventory_sha256(expected)
    )
    for field, relative in _PACKAGE_BINDINGS.items():
        updated[f"{field}_sha256"] = expected[relative][1]
    updated_tooling = _build_tooling_claim(root, expected)
    install_prior.write_bytes(install_path.read_bytes())
    tooling_prior.write_bytes(tooling_raw)
    journal = {
        "schema_version": "qrh-tooling-update-pending/v1",
        "attempt_id": attempt,
        "release_id": release,
        "release_manifest_sha256": expected_manifest,
        "old_package_inventory_sha256": _package_inventory_sha256(old_inventory),
        "new_package_inventory_sha256": _package_inventory_sha256(expected),
        "phase": "staged",
        "authority": "coordination_only",
    }
    _write_atomic(journal_path, journal, suffix=attempt)
    package_swapped = False
    candidate_swapped = False
    tooling_swapped = False
    try:
        os.replace(package, prior)
        os.replace(stage, package)
        package_swapped = True
        journal["phase"] = "package_swapped"
        _write_atomic(journal_path, journal, suffix=attempt)
        if fail_after_package_swap:
            raise ToolingUpdateError("injected failure after package swap")
        _write_atomic(install_path, updated, suffix=attempt)
        candidate_swapped = True
        _write_atomic(tooling_path, updated_tooling, suffix=attempt)
        tooling_swapped = True
        journal["phase"] = "claims_swapped"
        _write_atomic(journal_path, journal, suffix=attempt)
        if _regular_files(package) != expected:
            raise ToolingUpdateError("installed tooling package changed after swap")
        if json.loads(install_path.read_text(encoding="utf-8")) != updated:
            raise ToolingUpdateError("updated service install candidate differs")
        if json.loads(tooling_path.read_text(encoding="utf-8")) != updated_tooling:
            raise ToolingUpdateError("updated exact runtime tooling claim differs")
    except BaseException:
        rollback_error: BaseException | None = None
        try:
            if tooling_swapped:
                os.replace(tooling_prior, tooling_path)
            if candidate_swapped:
                os.replace(install_prior, install_path)
            if package_swapped:
                _remove_tree(package)
                os.replace(prior, package)
            _remove_tree(stage)
            if install_prior.exists():
                install_prior.unlink()
            if tooling_prior.exists():
                tooling_prior.unlink()
            if journal_path.exists():
                journal_path.unlink()
        except BaseException as error:
            rollback_error = error
        if rollback_error is not None:
            raise ToolingUpdateError(
                "tooling update failed and exact rollback did not close"
            ) from rollback_error
        raise

    _remove_tree(prior)
    install_prior.unlink()
    tooling_prior.unlink()
    journal_path.unlink()
    return {
        "schema_version": "qrh-tooling-update-result/v1",
        "status": "updated",
        "attempt_id": attempt,
        "release_id": release,
        "release_manifest_sha256": expected_manifest,
        "quant_hub_package_inventory_sha256": updated[
            "quant_hub_package_inventory_sha256"
        ],
        "exact_runtime_tooling_sha256": updated_tooling["tooling_sha256"],
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
