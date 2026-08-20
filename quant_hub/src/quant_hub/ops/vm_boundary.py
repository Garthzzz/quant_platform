"""Hard production-VM write boundary for Quant Research Hub."""

from __future__ import annotations

import os
from pathlib import Path, PureWindowsPath
from typing import Iterable

from quant_hub.config import ensure_no_reparse_components


PRODUCTION_VM_ROOT = PureWindowsPath(r"D:\quant\quant_platform")


class VMBoundaryError(RuntimeError):
    pass


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


def validate_vm_write_set(values: Iterable[str | PureWindowsPath]) -> tuple[str, ...]:
    return tuple(str(validate_production_vm_write_path(value)) for value in values)


__all__ = [
    "PRODUCTION_VM_ROOT",
    "VMBoundaryError",
    "validate_production_vm_write_path",
    "validate_vm_write_set",
    "verify_existing_vm_write_path",
]
