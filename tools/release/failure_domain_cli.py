"""Read-only diagnostics and fail-closed failure-domain command router."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
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


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] in {
        "issue-challenge", "capture-recovery-facts",
        "capture-independence-probe", "observe", "rotate-prepare",
        "rotate-apply", "verify-current", "diagnose-legacy-current",
        "source-manifest",
    }:
        from quant_hub.ops.failure_domain_rotation import main as rotation_main

        return rotation_main(arguments)
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
    probe = subparsers.add_parser("independence-probe")
    probe.add_argument("--recovery-root", type=Path, required=True)
    probe.add_argument("--bundle-root", type=Path, required=True)
    probe.add_argument("--materialization-event", type=Path, required=True)
    probe.add_argument("--probe-tool", type=Path, required=True)
    probe.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(arguments)
    print(
        json.dumps(
            {
                "status": "NOT_READY",
                "authority": False,
                "error_code": "FAILURE_DOMAIN_AUTHORITY_NOT_READY",
                "command": args.command,
                "output_created": False,
            },
            sort_keys=True,
        )
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
