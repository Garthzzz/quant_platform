"""Build, verify and restore self-contained cold recovery bundles."""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import sqlite3
import stat
from typing import Iterable, Mapping
from uuid import uuid4

from quant_hub.collaboration.checkpoint import (
    CHECKPOINT_MANIFEST_NAME,
    verify_sqlite_checkpoint,
)
from quant_hub.ops.release_identity import (
    ACTIVE_SCHEMA,
    RECOVERY_SCHEMA,
    canonical_manifest_bytes,
    manifest_sha256,
    validate_active_release,
    validate_checkpoint_manifest,
    validate_recovery_manifest,
    validate_release_manifest,
)
from quant_hub.ops.windows_service import quant_hub_package_inventory_sha256


CLOSURE_SCHEMA = "qrh-recovery-closure-inventory/v1"
SCANNER_VERSION = "qrh-recovery-no-secret/v2"
RESTORE_PROTOCOL = "qrh-restore/v1"
OPERATIONAL_BOOTSTRAP_SCHEMA = "qrh-operational-bootstrap/v1"
PRODUCTION_VM_ROOT = PureWindowsPath(r"D:\quant\quant_platform")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SECRET_PATTERN_TEXT = {
    "private_key": r"(?m)^-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]{32,}",
    "github_token": r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9]{20,}\b",
    "deepseek_openai_key": r"\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b",
    "authorization_bearer": r"(?i)\b(?:Authorization\s*[:=]\s*)?Bearer\s+[A-Za-z0-9._~+/=-]{20,}",
    "aws_access_key": r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    "aws_secret_key": r"(?i)\baws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}\b",
}
_SECRET_PATTERNS = {
    name: re.compile(pattern.encode("ascii"))
    for name, pattern in _SECRET_PATTERN_TEXT.items()
}
_SECRET_TEXT_PATTERNS = {
    name: re.compile(pattern) for name, pattern in _SECRET_PATTERN_TEXT.items()
}
_FORBIDDEN_SECRET_NAMES = {
    ".env", "credentials", "credentials.json", "viewer_secret.key",
    "viewer_access_password.digest",
}
_REVIEWED_SOURCE_SUFFIXES = {
    ".c", ".cjs", ".cpp", ".cs", ".css", ".go", ".h", ".hpp", ".html",
    ".java", ".js", ".jsx", ".mjs", ".php", ".ps1", ".psm1", ".py",
    ".pyi", ".rb", ".rs", ".sh", ".ts", ".tsx",
}

_OPERATIONAL_PATHS = {
    "service_executable": "tooling/python/Lib/site-packages/win32/pythonservice.exe",
    "service_python": "tooling/python/python.exe",
    "service_host_module": "tooling/python/Lib/site-packages/quant_hub/ops/windows_service.py",
    "service_entry_module": "tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py",
    "deployment_cli_module": "tooling/python/Lib/site-packages/quant_hub/ops/vm_deploy_cli.py",
    "publish_recovery_cli_module": "tooling/python/Lib/site-packages/quant_hub/ops/publish_recovery_cli.py",
    "access_gate_module": "tooling/python/Lib/site-packages/quant_hub/web/access_gate.py",
    "deployment_runtime": "control/deployment_runtime.json",
}
_SERVICE_CANDIDATE_PATH = "control/service_install_candidate.json"
_BOOTSTRAP_PATH = "control/operational_bootstrap.json"


class RecoveryBundleError(RuntimeError):
    """A cold bundle is incomplete, mutable, unsafe or inconsistent."""


@dataclass(frozen=True)
class RecoveryBundle:
    bundle_id: str
    root: Path
    recovery_manifest_sha256: str
    closure_inventory_sha256: str


@dataclass(frozen=True)
class RecoveryVerification:
    valid: bool
    bundle_id: str | None
    release_id: str | None
    release_manifest_sha256: str | None
    checkpoint_id: str | None
    checkpoint_manifest_sha256: str | None
    recovery_manifest_sha256: str | None
    errors: tuple[str, ...]


@dataclass(frozen=True)
class RestoreResult:
    target_root: Path
    release_id: str
    release_manifest_sha256: str
    checkpoint_id: str
    recovery_manifest_sha256: str


def _hash_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_reparse(path: Path) -> bool:
    info = path.lstat()
    return path.is_symlink() or bool(
        getattr(info, "st_file_attributes", 0) & 0x400
    )


def _path_has_reparse(path: Path) -> bool:
    current = path
    while True:
        if current.exists() and _is_reparse(current):
            return True
        if current.parent == current:
            return False
        current = current.parent


def _files(root: Path) -> list[Path]:
    result: list[Path] = []
    for current, directories, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        safe_directories: list[str] = []
        for name in sorted(directories):
            path = current_path / name
            if _is_reparse(path):
                raise RecoveryBundleError(f"reparse/symlink directory is forbidden: {path}")
            safe_directories.append(name)
        directories[:] = safe_directories
        for name in sorted(filenames):
            path = current_path / name
            info = path.lstat()
            if _is_reparse(path) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise RecoveryBundleError(f"non-independent file is forbidden: {path}")
            result.append(path)
    return sorted(result, key=lambda path: path.relative_to(root).as_posix())


def _records(root: Path, paths: Iterable[Path]) -> list[dict[str, object]]:
    return [
        {
            "path": path.relative_to(root).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": _hash_path(path),
        }
        for path in paths
    ]


def _scan_no_secret(root: Path, paths: Iterable[Path]) -> dict[str, object]:
    findings: list[dict[str, str]] = []
    scanned: list[dict[str, object]] = []
    for path in paths:
        relative = path.relative_to(root).as_posix()
        lowered_name = path.name.casefold()
        marker_name = any(
            marker in lowered_name
            for marker in ("credential", "cookie", "storage_state")
        )
        # Runtime dependencies legitimately contain reviewed source modules
        # such as requests/cookies.py.  Their bytes are still scanned below;
        # only non-source state/config files retain the filename hard gate.
        if lowered_name in _FORBIDDEN_SECRET_NAMES or (
            marker_name and path.suffix.casefold() not in _REVIEWED_SOURCE_SUFFIXES
        ):
            findings.append({"path": relative, "kind": "forbidden_secret_filename"})
            continue
        size, digest, kinds = _scan_regular_payload(path)
        scanned.append(
            {"path": relative, "bytes": size, "sha256": digest}
        )
        if _is_sqlite_payload(path):
            kinds.update(_scan_sqlite_logical_text(path))
        findings.extend({"path": relative, "kind": kind} for kind in sorted(kinds))
    report = {
        "schema_version": SCANNER_VERSION,
        "verdict": "pass" if not findings else "blocked",
        "scanned": scanned,
        "findings": findings,
    }
    report["report_sha256"] = hashlib.sha256(canonical_manifest_bytes(report)).hexdigest()
    if findings:
        raise RecoveryBundleError(
            "cold bundle no-secret scan blocked: "
            + ", ".join(f"{item['path']}:{item['kind']}" for item in findings)
        )
    return report


def _pattern_kinds_bytes(payload: bytes) -> set[str]:
    return {
        kind for kind, pattern in _SECRET_PATTERNS.items() if pattern.search(payload)
    }


def _pattern_kinds_text(payload: str) -> set[str]:
    return {
        kind
        for kind, pattern in _SECRET_TEXT_PATTERNS.items()
        if pattern.search(payload)
    }


def _pattern_kinds_all_encodings(payload: bytes) -> set[str]:
    """Scan one bounded window as raw/UTF-8 and both UTF-16 alignments."""

    kinds = _pattern_kinds_bytes(payload)
    kinds.update(_pattern_kinds_text(payload.decode("utf-8", errors="ignore")))
    for encoding in ("utf-16-le", "utf-16-be"):
        for offset in (0, 1):
            aligned = payload[offset:]
            aligned = aligned[: len(aligned) - (len(aligned) % 2)]
            if aligned:
                kinds.update(
                    _pattern_kinds_text(aligned.decode(encoding, errors="ignore"))
                )
    return kinds


def _scan_binary_value(payload: bytes) -> set[str]:
    """Bound temporary memory while scanning a possibly large SQLite BLOB."""

    kinds: set[str] = set()
    overlap = b""
    view = memoryview(payload)
    for start in range(0, len(view), 1024 * 1024):
        block = bytes(view[start : start + 1024 * 1024])
        window = overlap + block
        kinds.update(_pattern_kinds_all_encodings(window))
        overlap = window[-8192:]
    return kinds


def _scan_regular_payload(path: Path) -> tuple[int, str, set[str]]:
    """Stream every regular payload, including binary and UTF-16 material."""

    digest = hashlib.sha256()
    kinds: set[str] = set()
    total = 0
    overlap = b""
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(block)
            digest.update(block)
            window = overlap + block
            kinds.update(_pattern_kinds_all_encodings(window))
            overlap = window[-8192:]
    return total, digest.hexdigest(), kinds


def _is_sqlite_payload(path: Path) -> bool:
    with path.open("rb") as stream:
        return stream.read(16) == b"SQLite format 3\x00"


def _scan_sqlite_logical_text(path: Path) -> set[str]:
    """Read every readable SQLite value without executing application code."""

    kinds: set[str] = set()
    uri = f"file:{path.resolve().as_posix()}?mode=ro&immutable=1"
    try:
        with closing(sqlite3.connect(uri, uri=True)) as connection:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            tables = connection.execute(
                "SELECT name,sql FROM sqlite_schema "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
            for table_name, create_sql in tables:
                if not isinstance(table_name, str):
                    raise RecoveryBundleError("SQLite table identity is unreadable")
                if isinstance(create_sql, str) and create_sql.lstrip().upper().startswith(
                    "CREATE VIRTUAL TABLE"
                ):
                    raise RecoveryBundleError(
                        "SQLite virtual table cannot be proven secret-free"
                    )
                quoted = '"' + table_name.replace('"', '""') + '"'
                cursor = connection.execute(f"SELECT * FROM {quoted}")
                for row in cursor:
                    for value in row:
                        if isinstance(value, str):
                            kinds.update(_pattern_kinds_text(value))
                        elif isinstance(value, bytes):
                            kinds.update(_scan_binary_value(value))
    except (OSError, sqlite3.Error, UnicodeError) as error:
        raise RecoveryBundleError("SQLite logical no-secret scan failed") from error
    return kinds


def _copy_tree(source: Path, destination: Path) -> None:
    _files(source)
    shutil.copytree(source, destination, symlinks=False)


def _operational_bootstrap(root: Path) -> tuple[dict[str, object], str]:
    root = root.resolve(strict=True)
    candidate_path = root / _SERVICE_CANDIDATE_PATH
    runtime_path = root / _OPERATIONAL_PATHS["deployment_runtime"]
    if not candidate_path.is_file() or not runtime_path.is_file():
        raise RecoveryBundleError("operational service candidate/runtime is missing")
    try:
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RecoveryBundleError("operational service candidate is invalid") from error
    candidate_fields = {
        "schema_version", "service_name", "python_class", "service_executable",
        "service_executable_sha256", "service_python", "service_python_sha256",
        "service_host_module", "service_host_module_sha256", "service_entry_module",
        "service_entry_module_sha256", "deployment_cli_module",
        "deployment_cli_module_sha256", "publish_recovery_cli_module",
        "publish_recovery_cli_module_sha256", "access_gate_module", "access_gate_module_sha256",
        "deployment_runtime", "deployment_runtime_sha256", "start_type",
        "quant_hub_package_root", "quant_hub_package_inventory_sha256",
    }
    if (
        not isinstance(candidate, dict)
        or set(candidate) != candidate_fields
        or candidate["schema_version"] != "qrh-windows-service-install-candidate/v1"
        or candidate["service_name"] != "QuantResearchHub"
        or candidate["python_class"]
        != "quant_hub.ops.windows_service.QuantResearchHubWindowsService"
        or candidate["start_type"] != "automatic"
        or candidate_path.read_bytes() != canonical_manifest_bytes(candidate)
    ):
        raise RecoveryBundleError("operational service candidate contract differs")
    required: list[dict[str, object]] = []
    for field, relative in sorted(_OPERATIONAL_PATHS.items()):
        path = root.joinpath(*relative.split("/"))
        if not path.is_file():
            raise RecoveryBundleError(f"operational required file is missing: {relative}")
        expected_path = PRODUCTION_VM_ROOT.joinpath(*relative.split("/"))
        expected_hash = _hash_path(path)
        if (
            PureWindowsPath(str(candidate[field])) != expected_path
            or candidate[f"{field}_sha256"] != expected_hash
        ):
            raise RecoveryBundleError(f"operational candidate binding differs: {field}")
        required.append({"path": relative, "sha256": expected_hash})
    package_root = root / "tooling" / "python" / "Lib" / "site-packages" / "quant_hub"
    if (
        PureWindowsPath(str(candidate["quant_hub_package_root"]))
        != PRODUCTION_VM_ROOT
        / "tooling" / "python" / "Lib" / "site-packages" / "quant_hub"
        or candidate["quant_hub_package_inventory_sha256"]
        != quant_hub_package_inventory_sha256(package_root)
    ):
        raise RecoveryBundleError("operational quant_hub package binding differs")
    operational_files = [
        path
        for path in _files(root)
        if path.relative_to(root).as_posix() != _BOOTSTRAP_PATH
    ]
    bootstrap: dict[str, object] = {
        "schema_version": OPERATIONAL_BOOTSTRAP_SCHEMA,
        "authority_root": str(PRODUCTION_VM_ROOT),
        "required": required,
        "files": _records(root, operational_files),
    }
    bootstrap_hash = hashlib.sha256(canonical_manifest_bytes(bootstrap)).hexdigest()
    return bootstrap, bootstrap_hash


def _write_and_validate_operational_bootstrap(root: Path) -> str:
    path = root / _BOOTSTRAP_PATH
    if path.exists():
        raise RecoveryBundleError("operational bootstrap must be generated by bundle builder")
    bootstrap, bootstrap_hash = _operational_bootstrap(root)
    path.write_bytes(canonical_manifest_bytes(bootstrap))
    observed, observed_hash = _operational_bootstrap(root)
    if observed != bootstrap or observed_hash != bootstrap_hash:
        raise RecoveryBundleError("operational bootstrap changed during generation")
    return bootstrap_hash


def _verify_operational_bootstrap(root: Path, expected_hash: object) -> None:
    path = root / _BOOTSTRAP_PATH
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RecoveryBundleError("operational bootstrap is unavailable") from error
    if not isinstance(stored, dict) or path.read_bytes() != canonical_manifest_bytes(stored):
        raise RecoveryBundleError("operational bootstrap is not canonical")
    rebuilt, rebuilt_hash = _operational_bootstrap(root)
    if stored != rebuilt or expected_hash != rebuilt_hash:
        raise RecoveryBundleError("operational bootstrap inventory/hash differs")


def build_recovery_bundle(
    *,
    release_root: Path,
    checkpoint_root: Path,
    recovery_root: Path,
    bundle_id: str,
    created_at: str,
    restore_tool: Path,
    runbook: Path,
    operational_root: Path,
    compatibility: Mapping[str, object],
    checkpoint_scratch_root: Path | None = None,
) -> RecoveryBundle:
    """Create a write-once bundle under an already attested recovery root."""

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", bundle_id):
        raise RecoveryBundleError("bundle_id is unsafe")
    release_root = release_root.resolve(strict=True)
    checkpoint_root = checkpoint_root.resolve(strict=True)
    recovery_root = recovery_root.resolve(strict=True)
    restore_tool = restore_tool.resolve(strict=True)
    runbook = runbook.resolve(strict=True)
    operational_root = operational_root.resolve(strict=True)
    if not restore_tool.is_file() or not runbook.is_file():
        raise RecoveryBundleError("restore tool and runbook must be files")
    destination = recovery_root / f"cold-recovery-{bundle_id}"
    if destination.exists():
        raise RecoveryBundleError("recovery bundle ID already exists")
    # Keep the staging component deliberately short.  The V39 closure contains
    # legitimate deeply nested research/resource names near Win32 MAX_PATH;
    # repeating the full bundle ID in the partial directory can make an
    # otherwise restorable payload impossible to copy on Windows.
    partial = recovery_root / f".qrh-rb-{uuid4().hex}"
    partial.mkdir()
    try:
        release_manifest_path = release_root / "release_manifest.json"
        release_manifest = json.loads(release_manifest_path.read_text(encoding="utf-8"))
        validate_release_manifest(release_manifest)
        if release_manifest_path.read_bytes() != canonical_manifest_bytes(release_manifest):
            raise RecoveryBundleError("release manifest is not canonical")
        release_hash = manifest_sha256(release_manifest)

        checkpoint_verification = verify_sqlite_checkpoint(
            checkpoint_root,
            scratch_root=checkpoint_scratch_root,
        )
        if not checkpoint_verification.valid:
            raise RecoveryBundleError("checkpoint is not fully verified")
        checkpoint_manifest = json.loads(
            (checkpoint_root / CHECKPOINT_MANIFEST_NAME).read_text(encoding="utf-8")
        )
        validate_checkpoint_manifest(checkpoint_manifest)
        checkpoint_hash = manifest_sha256(checkpoint_manifest)

        _copy_tree(release_root, partial / "release")
        checkpoint_destination = partial / "checkpoints" / str(
            checkpoint_manifest["checkpoint_id"]
        )
        checkpoint_destination.parent.mkdir()
        _copy_tree(checkpoint_root, checkpoint_destination)
        operational_destination = partial / "operational"
        (operational_destination / "control").mkdir(parents=True)
        _copy_tree(
            operational_root / "tooling",
            operational_destination / "tooling",
        )
        for name in ("deployment_runtime.json", "service_install_candidate.json"):
            source = operational_root / "control" / name
            if not source.is_file():
                raise RecoveryBundleError(f"operational control file is missing: {name}")
            shutil.copy2(source, operational_destination / "control" / name)
        operational_bootstrap_hash = _write_and_validate_operational_bootstrap(
            operational_destination
        )
        tool_destination = partial / "tools" / "restore"
        tool_destination.mkdir(parents=True)
        shutil.copy2(restore_tool, tool_destination / restore_tool.name)
        shutil.copy2(runbook, partial / "RUNBOOK.md")

        payload_paths = _files(partial)
        no_secret = _scan_no_secret(partial, payload_paths)
        no_secret_path = partial / "no_secret_report.json"
        no_secret_path.write_bytes(canonical_manifest_bytes(no_secret))
        payload_paths = _files(partial)
        inventory: dict[str, object] = {
            "schema_version": CLOSURE_SCHEMA,
            "bundle_id": bundle_id,
            "files": _records(partial, payload_paths),
        }
        inventory_bytes = canonical_manifest_bytes(inventory)
        (partial / "closure_inventory.json").write_bytes(inventory_bytes)
        inventory_hash = hashlib.sha256(inventory_bytes).hexdigest()

        compatibility_payload = dict(compatibility)
        compatibility_payload["verdict"] = compatibility_payload.get("verdict")
        if compatibility_payload["verdict"] != "compatible":
            raise RecoveryBundleError("state/release compatibility did not pass")
        tool_inventory_hash = hashlib.sha256(
            canonical_manifest_bytes(
                _records(partial, _files(tool_destination))
            )
        ).hexdigest()
        recovery_manifest: dict[str, object] = {
            "schema_version": RECOVERY_SCHEMA,
            "bundle_id": bundle_id,
            "created_at": created_at,
            "release": {
                "release_id": release_manifest["release_id"],
                "manifest_sha256": release_hash,
            },
            "checkpoint": {
                "checkpoint_id": checkpoint_manifest["checkpoint_id"],
                "manifest_sha256": checkpoint_hash,
            },
            "closure": {
                "inventory_sha256": inventory_hash,
                "file_count": len(inventory["files"]),
                "total_bytes": sum(int(item["bytes"]) for item in inventory["files"]),
            },
            "compatibility": compatibility_payload,
            "restore": {
                "protocol_version": RESTORE_PROTOCOL,
                "tool_inventory_sha256": tool_inventory_hash,
                "runbook_sha256": _hash_path(partial / "RUNBOOK.md"),
                "operational_bootstrap_sha256": operational_bootstrap_hash,
            },
            "no_secret_attestation": {
                "verdict": "pass",
                "scanner_version": SCANNER_VERSION,
                "report_sha256": no_secret["report_sha256"],
            },
        }
        validate_recovery_manifest(recovery_manifest)
        recovery_manifest_bytes = canonical_manifest_bytes(recovery_manifest)
        (partial / "recovery_manifest.json").write_bytes(recovery_manifest_bytes)
        recovery_hash = hashlib.sha256(recovery_manifest_bytes).hexdigest()

        sum_paths = _files(partial)
        sums = "".join(
            f"{_hash_path(path)}  {path.relative_to(partial).as_posix()}\n"
            for path in sum_paths
        )
        (partial / "SHA256SUMS").write_text(sums, encoding="utf-8", newline="\n")
        os.replace(partial, destination)
    except BaseException:
        if partial.exists():
            shutil.rmtree(partial, ignore_errors=True)
        raise

    verification = verify_recovery_bundle(
        destination,
        checkpoint_scratch_root=checkpoint_scratch_root,
    )
    if not verification.valid:
        raise RecoveryBundleError("published recovery bundle failed verification")
    return RecoveryBundle(
        bundle_id=bundle_id,
        root=destination,
        recovery_manifest_sha256=recovery_hash,
        closure_inventory_sha256=inventory_hash,
    )


def _verify_sums(root: Path) -> None:
    sums_path = root / "SHA256SUMS"
    if not sums_path.is_file():
        raise RecoveryBundleError("SHA256SUMS is missing")
    expected: dict[str, str] = {}
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        if "  " not in line:
            raise RecoveryBundleError("SHA256SUMS line is invalid")
        digest, relative = line.split("  ", 1)
        if not _SHA256_RE.fullmatch(digest) or relative in expected:
            raise RecoveryBundleError("SHA256SUMS identity is invalid")
        expected[relative] = digest
    actual_paths = {
        path.relative_to(root).as_posix(): path
        for path in _files(root)
        if path != sums_path
    }
    if set(expected) != set(actual_paths):
        raise RecoveryBundleError("SHA256SUMS closure differs")
    for relative, path in actual_paths.items():
        if _hash_path(path) != expected[relative]:
            raise RecoveryBundleError(f"SHA256SUMS mismatch: {relative}")


def verify_recovery_bundle(
    root: Path,
    *,
    checkpoint_scratch_root: Path | None = None,
) -> RecoveryVerification:
    root = Path(root).resolve()
    bundle_id = release_id = checkpoint_id = None
    release_hash = checkpoint_hash = recovery_hash = None
    errors: list[str] = []
    try:
        _verify_sums(root)
        recovery_path = root / "recovery_manifest.json"
        recovery_manifest = json.loads(recovery_path.read_text(encoding="utf-8"))
        validate_recovery_manifest(recovery_manifest)
        if recovery_path.read_bytes() != canonical_manifest_bytes(recovery_manifest):
            raise RecoveryBundleError("recovery manifest is not canonical")
        recovery_hash = manifest_sha256(recovery_manifest)
        bundle_id = str(recovery_manifest["bundle_id"])
        if root.name != f"cold-recovery-{bundle_id}":
            raise RecoveryBundleError("bundle directory and ID differ")

        release_path = root / "release" / "release_manifest.json"
        release_manifest = json.loads(release_path.read_text(encoding="utf-8"))
        validate_release_manifest(release_manifest)
        release_hash = manifest_sha256(release_manifest)
        release_id = str(release_manifest["release_id"])
        release_ref = recovery_manifest["release"]
        if release_ref != {"release_id": release_id, "manifest_sha256": release_hash}:
            raise RecoveryBundleError("recovery release reference differs")

        checkpoint_ref = recovery_manifest["checkpoint"]
        checkpoint_root = root / "checkpoints" / str(checkpoint_ref["checkpoint_id"])
        checkpoint_report = verify_sqlite_checkpoint(
            checkpoint_root,
            scratch_root=checkpoint_scratch_root,
        )
        if not checkpoint_report.valid:
            raise RecoveryBundleError("recovery checkpoint validation failed")
        checkpoint_manifest = json.loads(
            (checkpoint_root / CHECKPOINT_MANIFEST_NAME).read_text(encoding="utf-8")
        )
        checkpoint_hash = manifest_sha256(checkpoint_manifest)
        checkpoint_id = str(checkpoint_manifest["checkpoint_id"])
        if checkpoint_ref != {
            "checkpoint_id": checkpoint_id,
            "manifest_sha256": checkpoint_hash,
        }:
            raise RecoveryBundleError("recovery checkpoint reference differs")

        inventory_path = root / "closure_inventory.json"
        inventory_bytes = inventory_path.read_bytes()
        inventory = json.loads(inventory_bytes)
        if inventory.get("schema_version") != CLOSURE_SCHEMA or inventory.get("bundle_id") != bundle_id:
            raise RecoveryBundleError("closure inventory schema or ID differs")
        inventory_hash = hashlib.sha256(inventory_bytes).hexdigest()
        if inventory_hash != recovery_manifest["closure"]["inventory_sha256"]:
            raise RecoveryBundleError("recovery closure inventory hash differs")
        if inventory_bytes != canonical_manifest_bytes(inventory):
            raise RecoveryBundleError("closure inventory is not canonical")
        expected_records = inventory.get("files")
        if not isinstance(expected_records, list):
            raise RecoveryBundleError("closure file records are missing")
        excluded = {
            (root / "closure_inventory.json").resolve(),
            (root / "recovery_manifest.json").resolve(),
            (root / "SHA256SUMS").resolve(),
        }
        actual_payload_paths = [path for path in _files(root) if path.resolve() not in excluded]
        if _records(root, actual_payload_paths) != expected_records:
            raise RecoveryBundleError("recovery payload closure differs")
        closure = recovery_manifest["closure"]
        if closure["file_count"] != len(expected_records) or closure["total_bytes"] != sum(
            int(item["bytes"]) for item in expected_records
        ):
            raise RecoveryBundleError("recovery closure summary differs")
        no_secret_path = root / "no_secret_report.json"
        stored_no_secret = json.loads(no_secret_path.read_text(encoding="utf-8"))
        claimed_report_hash = stored_no_secret.pop("report_sha256", None)
        if claimed_report_hash != hashlib.sha256(
            canonical_manifest_bytes(stored_no_secret)
        ).hexdigest():
            raise RecoveryBundleError("no-secret report hash differs")
        stored_no_secret["report_sha256"] = claimed_report_hash
        rescanned = _scan_no_secret(
            root, [path for path in actual_payload_paths if path != no_secret_path]
        )
        if stored_no_secret != rescanned:
            raise RecoveryBundleError("no-secret attestation evidence differs")
        if recovery_manifest["no_secret_attestation"]["report_sha256"] != claimed_report_hash:
            raise RecoveryBundleError("recovery no-secret attestation differs")
        _verify_operational_bootstrap(
            root / "operational",
            recovery_manifest["restore"]["operational_bootstrap_sha256"],
        )
    except (RecoveryBundleError, OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        errors.append("recovery_bundle_validation_failed")
    return RecoveryVerification(
        valid=not errors,
        bundle_id=bundle_id,
        release_id=release_id,
        release_manifest_sha256=release_hash,
        checkpoint_id=checkpoint_id,
        checkpoint_manifest_sha256=checkpoint_hash,
        recovery_manifest_sha256=recovery_hash,
        errors=tuple(errors),
    )


def restore_recovery_bundle(*, bundle_root: Path, empty_target_root: Path) -> RestoreResult:
    """Materialize a verified bundle into a real, existing empty target root.

    This function deliberately does not write a successful recovery receipt.
    Service and browser/API probes can only run after materialization, so the
    caller must invoke :func:`finalize_recovery_receipt` with their results.
    """

    bundle_root = Path(bundle_root).resolve(strict=True)
    target = Path(empty_target_root).resolve(strict=True)
    if _path_has_reparse(target) or any(target.iterdir()):
        raise RecoveryBundleError("restore target must be a real empty directory")
    scratch_root = target / ".recovery-verify-scratch"
    if scratch_root.exists():
        raise RecoveryBundleError("restore verification scratch path already exists")
    scratch_root.mkdir()
    try:
        # ``TEMP`` on Windows runners may spell an existing parent through its
        # 8.3 alias while ``Path.resolve`` returns the long name (or vice versa).
        # Bind the verifier to the filesystem-resolved child, not to a lexical
        # spelling, and still fail closed if a reparse race redirects that child.
        if _path_has_reparse(scratch_root):
            raise RecoveryBundleError(
                "restore verification scratch must be a real directory"
            )
        resolved_scratch = scratch_root.resolve(strict=True)
        if not resolved_scratch.is_relative_to(target):
            raise RecoveryBundleError("restore verification scratch escaped empty target")
        report = verify_recovery_bundle(
            bundle_root,
            checkpoint_scratch_root=resolved_scratch,
        )
    finally:
        shutil.rmtree(scratch_root, ignore_errors=True)
    if not report.valid or not all(
        (
            report.release_id,
            report.release_manifest_sha256,
            report.checkpoint_id,
            report.recovery_manifest_sha256,
        )
    ):
        raise RecoveryBundleError("recovery bundle is not restorable")
    release_id = str(report.release_id)
    release_destination = target / "releases" / release_id
    try:
        _copy_tree(bundle_root / "release", release_destination)
        state_destination = target / "state"
        state_destination.mkdir()
        checkpoint_manifest = json.loads(
            (
                bundle_root
                / "checkpoints"
                / str(report.checkpoint_id)
                / CHECKPOINT_MANIFEST_NAME
            ).read_text(
                encoding="utf-8"
            )
        )
        for record in checkpoint_manifest["state"]["databases"]:
            logical_name = str(record["logical_name"])
            source = (
                bundle_root
                / "checkpoints"
                / str(report.checkpoint_id)
                / str(record["relative_path"])
            )
            shutil.copy2(source, state_destination / f"{logical_name}.sqlite3")
        _copy_tree(bundle_root / "tools", target / "tools")
        _copy_tree(bundle_root / "operational" / "tooling", target / "tooling")
        control = target / "control"
        control.mkdir()
        for name in (
            "deployment_runtime.json",
            "service_install_candidate.json",
            "operational_bootstrap.json",
        ):
            shutil.copy2(bundle_root / "operational" / "control" / name, control / name)
        active: dict[str, object] = {
            "schema_version": ACTIVE_SCHEMA,
            "release_id": release_id,
            "release_path": str(release_destination),
            "manifest_sha256": report.release_manifest_sha256,
        }
        validate_active_release(active)
        temporary = control / ".active_release.json.partial"
        temporary.write_bytes(canonical_manifest_bytes(active))
        os.replace(temporary, control / "active_release.json")
    except BaseException:
        # Do not silently reuse a partial target.  The caller can inspect it and
        # must select a fresh empty directory for the next recovery attempt.
        raise
    return RestoreResult(
        target_root=target,
        release_id=release_id,
        release_manifest_sha256=str(report.release_manifest_sha256),
        checkpoint_id=str(report.checkpoint_id),
        recovery_manifest_sha256=str(report.recovery_manifest_sha256),
    )


def finalize_recovery_receipt(
    *,
    restored: RestoreResult,
    bundle_root: Path,
    recovery_attempt_id: str,
    receipt_id: str,
    recorded_at: str,
    restore_verification: Mapping[str, object],
) -> Path:
    """Append success evidence only after real post-restore probes pass."""

    from quant_hub.ops.release_identity import validate_receipt

    bundle_root = Path(bundle_root).resolve(strict=True)
    target = restored.target_root.resolve(strict=True)
    report = verify_recovery_bundle(bundle_root)
    if not report.valid:
        raise RecoveryBundleError("recovery bundle changed before receipt finalization")
    expected = {
        "closure": True,
        "state_restored": True,
        "service_started": True,
        "post_restore": True,
    }
    if dict(restore_verification) != expected:
        raise RecoveryBundleError("successful recovery receipt requires all real probes")
    if (
        report.release_id != restored.release_id
        or report.release_manifest_sha256 != restored.release_manifest_sha256
        or report.checkpoint_id != restored.checkpoint_id
        or report.recovery_manifest_sha256 != restored.recovery_manifest_sha256
    ):
        raise RecoveryBundleError("restored material and recovery bundle identity differ")
    active_path = target / "control" / "active_release.json"
    active = json.loads(active_path.read_text(encoding="utf-8"))
    validate_active_release(active)
    if active.get("release_id") != restored.release_id or active.get(
        "manifest_sha256"
    ) != restored.release_manifest_sha256:
        raise RecoveryBundleError("restored active authority differs before receipt")
    receipt = {
        "schema_version": "qrh-recovery-receipt/v1",
        "receipt_type": "recovery",
        "receipt_id": receipt_id,
        "recovery_attempt_id": recovery_attempt_id,
        "recorded_at": recorded_at,
        "authority": "evidence_only",
        "release_manifest_sha256": restored.release_manifest_sha256,
        "recovery_manifest_sha256": restored.recovery_manifest_sha256,
        "checkpoint_manifest_sha256": report.checkpoint_manifest_sha256,
        "verdict": "recovered",
        "restore_verification": expected,
    }
    validate_receipt(receipt)
    audit = target / "audit"
    audit.mkdir(exist_ok=True)
    receipt_path = audit / f"{receipt_id}.json"
    if receipt_path.exists():
        raise RecoveryBundleError("recovery receipt ID already exists")
    temporary = audit / f".{receipt_id}.partial-{uuid4().hex}"
    temporary.write_bytes(canonical_manifest_bytes(receipt))
    os.replace(temporary, receipt_path)
    return receipt_path


__all__ = [
    "CLOSURE_SCHEMA",
    "RESTORE_PROTOCOL",
    "RecoveryBundle",
    "RecoveryBundleError",
    "RecoveryVerification",
    "RestoreResult",
    "build_recovery_bundle",
    "finalize_recovery_receipt",
    "restore_recovery_bundle",
    "verify_recovery_bundle",
]
