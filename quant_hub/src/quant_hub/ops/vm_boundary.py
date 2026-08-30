"""Hard production-VM write boundary for Quant Research Hub."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PureWindowsPath
import re
from typing import Iterable, Mapping
from uuid import uuid4

from quant_hub.config import ensure_no_reparse_components
from quant_hub.runtime_seal import write_atomic_new_json


PRODUCTION_VM_ROOT = PureWindowsPath(r"D:\quant\quant_platform")
PRODUCTION_WRITE_AREAS = frozenset(
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
VM_WRITE_AUDIT_SCHEMA = "qrh-production-vm-write-audit/v1"


class VMBoundaryError(RuntimeError):
    pass


def reject_test_only_path_on_production_vm(
    path: Path, *, label: str = "test-only path"
) -> None:
    """Fail before mutation when a test adapter resolves anywhere inside D root."""

    raw = PureWindowsPath(os.path.normpath(str(path)))
    candidates = [raw]
    try:
        candidates.append(
            PureWindowsPath(os.path.normpath(str(path.resolve(strict=False))))
        )
    except OSError:
        pass
    for candidate in candidates:
        try:
            candidate.relative_to(PRODUCTION_VM_ROOT)
        except ValueError:
            continue
        raise VMBoundaryError(
            f"{label} cannot target production D root or a descendant/alias"
        )
    production = Path(str(PRODUCTION_VM_ROOT))
    try:
        if path.exists() and production.exists() and os.path.samefile(
            path, production
        ):
            raise VMBoundaryError(
                f"{label} cannot target production D root or a descendant/alias"
            )
    except OSError:
        return


def validate_production_vm_write_path(
    value: str | PureWindowsPath, *, allow_root: bool = True
) -> PureWindowsPath:
    """Reject every VM write target outside the one approved D-root."""

    raw = str(value)
    if raw.startswith(("\\\\", "//", "\\\\?\\", "\\??\\")):
        raise VMBoundaryError("VM write target cannot be UNC or extended-path syntax")
    target = PureWindowsPath(raw)
    if not target.is_absolute() or target.drive.casefold() != "d:":
        raise VMBoundaryError("VM writes are allowed only on the approved D drive root")
    if any(part in {".", ".."} or ":" in part for part in target.parts[1:]):
        raise VMBoundaryError("VM write target contains traversal or alternate stream syntax")
    normalized = PureWindowsPath(os.path.normpath(str(target)))
    try:
        relative = normalized.relative_to(PRODUCTION_VM_ROOT)
    except ValueError as error:
        raise VMBoundaryError(
            r"VM write target must remain under D:\quant\quant_platform"
        ) from error
    if not allow_root and not relative.parts:
        raise VMBoundaryError("operation requires a child of the approved VM root")
    if relative.parts and relative.parts[0].casefold() not in PRODUCTION_WRITE_AREAS:
        raise VMBoundaryError("VM write target is outside the closed production write areas")
    return normalized


def verify_existing_vm_write_path(path: Path, *, allow_root: bool = True) -> Path:
    """On the VM, additionally prove the existing path has no reparse escape."""

    approved = validate_production_vm_write_path(str(path), allow_root=allow_root)
    ensure_no_reparse_components(path)
    resolved = path.resolve(strict=True)
    validate_production_vm_write_path(str(resolved), allow_root=allow_root)
    if PureWindowsPath(str(resolved)) != approved:
        raise VMBoundaryError("VM write target resolves to a different path")
    return resolved


def verify_vm_write_target(
    path: Path, *, allow_root: bool = True, must_exist: bool = False
) -> Path:
    """Resolve existing ancestors before a production write is attempted."""

    approved = validate_production_vm_write_path(str(path), allow_root=allow_root)
    ensure_no_reparse_components(path)
    resolved = path.resolve(strict=must_exist)
    validate_production_vm_write_path(str(resolved), allow_root=allow_root)
    if PureWindowsPath(str(resolved)) != approved:
        raise VMBoundaryError("VM write target resolves to a different path")
    return resolved


def validate_vm_write_set(values: Iterable[str | PureWindowsPath]) -> tuple[str, ...]:
    return tuple(str(validate_production_vm_write_path(value)) for value in values)


def declared_production_vm_write_set() -> Mapping[str, str]:
    """Return the complete top-level production write namespace.

    Individual release and transient-attempt IDs remain dynamic, but no production code
    may introduce another top-level target without changing this reviewed
    contract and its tests.
    """

    return {
        area: str(PRODUCTION_VM_ROOT / area)
        for area in sorted(PRODUCTION_WRITE_AREAS)
    }


@dataclass(frozen=True, slots=True)
class VMWriteSnapshot:
    physical_root: Path
    entries: Mapping[str, tuple[str, int, int]]


def capture_vm_write_snapshot(root: Path) -> VMWriteSnapshot:
    """Capture a reparse-free tree for an execution-time write-set audit."""

    physical = Path(root).resolve(strict=True)
    ensure_no_reparse_components(physical)
    if not physical.is_dir():
        raise VMBoundaryError("VM write audit root must be a real directory")
    entries: dict[str, tuple[str, int, int]] = {}
    for path in sorted(physical.rglob("*"), key=lambda value: value.as_posix()):
        ensure_no_reparse_components(path)
        relative = path.relative_to(physical).as_posix()
        info = path.stat()
        if path.is_dir():
            entries[relative] = ("directory", 0, info.st_mtime_ns)
        elif path.is_file():
            # Pre/post discovery is metadata-only so a growing PDF/object store
            # does not make every deployment rehash the entire active closure.
            # Exact SHA-256 is computed below only for observed changed files.
            entries[relative] = ("file", info.st_size, info.st_mtime_ns)
        else:
            raise VMBoundaryError("VM write audit encountered a non-regular entry")
    return VMWriteSnapshot(physical_root=physical, entries=entries)


def build_vm_write_audit(
    before: VMWriteSnapshot,
    after: VMWriteSnapshot,
    *,
    operation: str,
) -> Mapping[str, object]:
    """Prove the observed delta maps only to the closed production namespace."""

    if before.physical_root != after.physical_root:
        raise VMBoundaryError("VM write audit snapshots use different roots")
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,179}", operation) is None:
        raise VMBoundaryError("VM write audit operation ID is invalid")
    paths = sorted(set(before.entries) | set(after.entries))
    writes: list[dict[str, object]] = []
    for relative in paths:
        old = before.entries.get(relative)
        new = after.entries.get(relative)
        if old == new:
            continue
        logical = PRODUCTION_VM_ROOT.joinpath(*relative.split("/"))
        validate_production_vm_write_path(logical, allow_root=False)
        digest: str | None = None
        if new is not None and new[0] == "file":
            physical_path = after.physical_root.joinpath(*relative.split("/"))
            value = hashlib.sha256()
            with physical_path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    value.update(block)
            digest = value.hexdigest()
        writes.append(
            {
                "path": str(logical),
                "relative_path": relative,
                "change": "created" if old is None else "deleted" if new is None else "modified",
                "entry_type": (new or old)[0],
                "bytes": (new or old)[1],
                "sha256": digest,
            }
        )
    return {
        "schema_version": VM_WRITE_AUDIT_SCHEMA,
        "operation": operation,
        "authority_root": str(PRODUCTION_VM_ROOT),
        "declared_write_set": declared_production_vm_write_set(),
        "observed_writes": writes,
        "verdict": "pass",
    }


def finalize_vm_write_audit(
    root: Path,
    before: VMWriteSnapshot,
    *,
    operation: str,
    outcome: str,
) -> Path:
    """Append execution evidence after a production VM operation.

    The report covers the tree delta through creation of its audit directory;
    ``audit_record_path`` explicitly accounts for the final append-only report
    itself without introducing a self-hash cycle.
    """

    if outcome not in {"succeeded", "failed"}:
        raise VMBoundaryError("VM write audit outcome is invalid")
    physical = Path(root).resolve(strict=True)
    if physical != before.physical_root:
        raise VMBoundaryError("VM write audit root changed during execution")
    audit_directory = physical / "audit" / "events"
    ensure_no_reparse_components(audit_directory)
    audit_directory.mkdir(parents=True, exist_ok=True)
    ensure_no_reparse_components(audit_directory)
    after = capture_vm_write_snapshot(physical)
    report = dict(build_vm_write_audit(before, after, operation=operation))
    audit_id = f"vm-write-audit-{uuid4().hex}"
    audit_path = audit_directory / f"{audit_id}.json"
    logical_path = PRODUCTION_VM_ROOT / "audit" / "events" / audit_path.name
    validate_production_vm_write_path(logical_path, allow_root=False)
    report.update(
        {
            "audit_id": audit_id,
            "outcome": outcome,
            "audit_record_path": str(logical_path),
        }
    )
    write_atomic_new_json(audit_path, report)
    return audit_path


__all__ = [
    "PRODUCTION_VM_ROOT",
    "PRODUCTION_WRITE_AREAS",
    "VMBoundaryError",
    "VMWriteSnapshot",
    "VM_WRITE_AUDIT_SCHEMA",
    "build_vm_write_audit",
    "capture_vm_write_snapshot",
    "declared_production_vm_write_set",
    "finalize_vm_write_audit",
    "reject_test_only_path_on_production_vm",
    "validate_production_vm_write_path",
    "validate_vm_write_set",
    "verify_existing_vm_write_path",
    "verify_vm_write_target",
]
