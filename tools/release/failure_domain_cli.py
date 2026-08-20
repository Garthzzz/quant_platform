"""Machine-readable collection and verification of recovery failure-domain facts."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from uuid import uuid4

from quant_hub.ops.failure_domain import (
    attest_failure_domain,
    canonical_bytes,
    collect_host_facts,
)
from quant_hub.ops.vm_boundary import (
    PRODUCTION_VM_ROOT,
    VMBoundaryError,
    validate_production_vm_write_path,
)


def _guard_production_facts_paths(root: Path, output: Path) -> None:
    """Make production fact collection incapable of escaping the VM root."""

    approved_root = validate_production_vm_write_path(str(root))
    if approved_root != PRODUCTION_VM_ROOT:
        raise VMBoundaryError(
            r"production facts root must be exactly D:\quant\quant_platform"
        )
    validate_production_vm_write_path(str(output), allow_root=False)


def _read(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("evidence JSON must be an object")
    return value


def _write_new(path: Path, value: object) -> None:
    target = path.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise RuntimeError(f"evidence already exists: {target}")
    temporary = target.parent / f".{target.name}.partial-{uuid4().hex}"
    try:
        with temporary.open("xb") as stream:
            stream.write(canonical_bytes(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    facts = subparsers.add_parser("facts")
    facts.add_argument("--root", type=Path, required=True)
    facts.add_argument("--role", choices=("production", "recovery"), required=True)
    facts.add_argument("--tool-version", default="qrh-failure-domain-cli/v1")
    facts.add_argument("--output", type=Path, required=True)
    attest = subparsers.add_parser("attest")
    attest.add_argument("--production-facts", type=Path, required=True)
    attest.add_argument("--recovery-facts", type=Path, required=True)
    attest.add_argument("--independence-probe", type=Path, required=True)
    attest.add_argument("--observed-at", required=True)
    attest.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if args.command == "facts":
        if args.role == "production":
            _guard_production_facts_paths(args.root, args.output)
        value = collect_host_facts(
            args.root, role=args.role, tool_version=args.tool_version
        )
    else:
        result = attest_failure_domain(
            production_facts=_read(args.production_facts),
            recovery_facts=_read(args.recovery_facts),
            independence_probe=_read(args.independence_probe),
            observed_at=args.observed_at,
        )
        value = {**result.payload, "attestation_sha256": result.sha256}
    _write_new(args.output, value)
    print(json.dumps({"status": "PASS", "output": str(args.output.resolve())}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
