"""Create a verified production SQLite checkpoint without writing outside VM_ROOT."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
from pathlib import Path, PureWindowsPath

from quant_hub.collaboration.checkpoint import create_sqlite_checkpoint
from quant_hub.config import ensure_no_reparse_components
from quant_hub.ops.vm_boundary import validate_production_vm_write_path


LEGACY_STATE_ROOT = PureWindowsPath(r"C:\quant_platform_data")
LEGACY_DATABASES = frozenset({"comments.sqlite3", "research_workspace.sqlite3"})


def _parse_database(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("database must be LOGICAL_NAME=PATH")
    logical_name, raw_path = value.split("=", 1)
    if not logical_name or not raw_path:
        raise argparse.ArgumentTypeError("database must be LOGICAL_NAME=PATH")
    return logical_name, Path(raw_path)


def _validate_source(path: Path) -> None:
    windows_path = PureWindowsPath(str(path))
    try:
        legacy_relative = windows_path.relative_to(LEGACY_STATE_ROOT)
    except ValueError:
        # After handoff the single writer authority is inside VM_ROOT.
        validate_production_vm_write_path(str(path), allow_root=False)
        return
    if len(legacy_relative.parts) != 1 or legacy_relative.name not in LEGACY_DATABASES:
        raise RuntimeError("legacy checkpoint source is outside the database allowlist")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", action="append", type=_parse_database, required=True)
    parser.add_argument("--checkpoint-root", type=Path, required=True)
    parser.add_argument("--scratch-root", type=Path, required=True)
    parser.add_argument("--checkpoint-id", required=True)
    parser.add_argument("--state-authority-id", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--release-manifest-sha256", required=True)
    parser.add_argument("--captured-at")
    args = parser.parse_args()

    validate_production_vm_write_path(str(args.checkpoint_root), allow_root=False)
    validate_production_vm_write_path(str(args.scratch_root), allow_root=False)
    ensure_no_reparse_components(args.checkpoint_root)
    ensure_no_reparse_components(args.scratch_root)
    sources: dict[str, Path] = {}
    for logical_name, path in args.database:
        if logical_name in sources:
            raise RuntimeError("duplicate database logical name")
        _validate_source(path)
        sources[logical_name] = path

    captured_at = (
        datetime.fromisoformat(args.captured_at.replace("Z", "+00:00"))
        if args.captured_at
        else datetime.now(UTC)
    )
    created = create_sqlite_checkpoint(
        sources=sources,
        checkpoint_root=args.checkpoint_root,
        checkpoint_id=args.checkpoint_id,
        state_authority_id=args.state_authority_id,
        captured_under_release_id=args.release_id,
        captured_under_manifest_sha256=args.release_manifest_sha256,
        captured_at=captured_at,
        scratch_root=args.scratch_root,
    )
    print(
        json.dumps(
            {
                "status": "PASS",
                "checkpoint_id": created.checkpoint_id,
                "manifest_sha256": created.manifest_sha256,
                "root": str(created.root),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
