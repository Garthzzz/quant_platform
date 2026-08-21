"""Collect production failure-domain facts from the verified exact-D runtime."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PureWindowsPath

from quant_hub.config import ensure_no_reparse_components
from quant_hub.runtime_seal import write_atomic_new_json

from .failure_domain import collect_host_facts
from .vm_boundary import (
    PRODUCTION_VM_ROOT,
    VMBoundaryError,
    validate_production_vm_write_path,
    verify_existing_vm_write_path,
    verify_vm_write_target,
)


TOOL_VERSION = "qrh-production-host-facts/v1"


def guard_production_facts_paths(root: Path, output: Path) -> None:
    approved_root = validate_production_vm_write_path(str(root), allow_root=True)
    approved_output = validate_production_vm_write_path(str(output), allow_root=False)
    if approved_root != PRODUCTION_VM_ROOT:
        raise VMBoundaryError(
            r"production facts root must be exactly D:\quant\quant_platform"
        )
    relative = approved_output.relative_to(PRODUCTION_VM_ROOT)
    if (
        len(relative.parts) < 3
        or tuple(part.casefold() for part in relative.parts[:2])
        != ("audit", "evidence")
        or PureWindowsPath(approved_output).suffix.casefold() != ".json"
    ):
        raise VMBoundaryError(
            "production facts output must be a JSON child of exact-D audit/evidence"
        )


def collect_production_facts(*, root: Path, output: Path) -> dict[str, object]:
    guard_production_facts_paths(root, output)
    physical_root = verify_existing_vm_write_path(root, allow_root=True)
    verify_vm_write_target(output.parent, allow_root=False, must_exist=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    ensure_no_reparse_components(output.parent)
    ensure_no_reparse_components(output)
    facts = collect_host_facts(
        physical_root, role="production", tool_version=TOOL_VERSION
    )
    write_atomic_new_json(output, facts)
    return facts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    facts = collect_production_facts(root=args.root, output=args.output)
    print(
        json.dumps(
            {
                "status": "PASS",
                "role": "production",
                "facts_sha256": facts["facts_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
