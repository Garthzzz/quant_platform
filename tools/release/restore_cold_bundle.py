"""Stdlib-only cold recovery materializer shipped inside every bundle.

It verifies the complete cryptographic closure and SQLite checkpoint before
copying into an existing empty target.  It never writes a success receipt;
service/browser probes and receipt finalization happen after this process.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import stat
from typing import Any


class RestoreError(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def safe_relative(root: Path, raw: object) -> Path:
    if not isinstance(raw, str) or not raw or "\\" in raw:
        raise RestoreError("bundle path is not normalized")
    pure = PurePosixPath(raw)
    if pure.is_absolute() or ".." in pure.parts or pure.as_posix() != raw:
        raise RestoreError("bundle path escapes the recovery root")
    path = (root / Path(*pure.parts)).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as error:
        raise RestoreError("bundle path escapes after resolution") from error
    return path


def files(root: Path) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in directories:
            path = current_path / name
            if path.is_symlink() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400:
                raise RestoreError("bundle contains a reparse/symlink directory")
        for name in filenames:
            path = current_path / name
            info = path.lstat()
            if (
                path.is_symlink()
                or getattr(info, "st_file_attributes", 0) & 0x400
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
            ):
                raise RestoreError("bundle contains a non-independent file")
            result[path.relative_to(root).as_posix()] = path
    return dict(sorted(result.items()))


def load_canonical(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or path.read_bytes() != canonical(value):
        raise RestoreError(f"manifest is not canonical: {path.name}")
    return value


def verify_bundle(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    root = root.resolve(strict=True)
    actual = files(root)
    sums = actual.pop("SHA256SUMS", None)
    if sums is None:
        raise RestoreError("SHA256SUMS is missing")
    expected: dict[str, str] = {}
    for line in sums.read_text(encoding="utf-8").splitlines():
        if "  " not in line:
            raise RestoreError("SHA256SUMS line is invalid")
        sha256, relative = line.split("  ", 1)
        path = safe_relative(root, relative)
        normalized = path.relative_to(root).as_posix()
        if len(sha256) != 64 or normalized != relative or relative in expected:
            raise RestoreError("SHA256SUMS identity is invalid")
        expected[relative] = sha256
    if set(expected) != set(actual):
        raise RestoreError("bundle file closure differs from SHA256SUMS")
    for relative, expected_hash in expected.items():
        if digest(actual[relative]) != expected_hash:
            raise RestoreError(f"bundle hash differs: {relative}")

    recovery = load_canonical(root / "recovery_manifest.json")
    release = load_canonical(root / "release" / "release_manifest.json")
    release_hash = hashlib.sha256(canonical(release)).hexdigest()
    if recovery.get("release") != {
        "release_id": release.get("release_id"),
        "manifest_sha256": release_hash,
    }:
        raise RestoreError("recovery-to-release identity differs")
    checkpoint_ref = recovery.get("checkpoint")
    if not isinstance(checkpoint_ref, dict):
        raise RestoreError("recovery checkpoint reference is missing")
    checkpoint_id = checkpoint_ref.get("checkpoint_id")
    checkpoint_root = safe_relative(root, f"checkpoints/{checkpoint_id}")
    checkpoint = load_canonical(checkpoint_root / "checkpoint_manifest.json")
    checkpoint_hash = hashlib.sha256(canonical(checkpoint)).hexdigest()
    if checkpoint_ref != {
        "checkpoint_id": checkpoint_id,
        "manifest_sha256": checkpoint_hash,
    }:
        raise RestoreError("recovery-to-checkpoint identity differs")
    if (checkpoint_root / "checkpoint_manifest.sha256").read_text(
        encoding="ascii"
    ).strip() != checkpoint_hash:
        raise RestoreError("checkpoint sidecar hash differs")

    inventory_path = root / "closure_inventory.json"
    inventory = load_canonical(inventory_path)
    if recovery.get("closure", {}).get("inventory_sha256") != digest(inventory_path):
        raise RestoreError("recovery closure identity differs")
    excluded = {"closure_inventory.json", "recovery_manifest.json"}
    records = [
        {"path": relative, "bytes": path.stat().st_size, "sha256": digest(path)}
        for relative, path in actual.items()
        if relative not in excluded
    ]
    if inventory.get("files") != records:
        raise RestoreError("closure inventory records differ")

    state = checkpoint.get("state")
    if not isinstance(state, dict) or not isinstance(state.get("databases"), list):
        raise RestoreError("checkpoint database inventory is missing")
    for record in state["databases"]:
        database = safe_relative(checkpoint_root, record.get("relative_path"))
        if digest(database) != record.get("sha256"):
            raise RestoreError("checkpoint database hash differs")
        connection = sqlite3.connect(f"file:{database.as_posix()}?mode=ro&immutable=1", uri=True)
        try:
            if [row[0] for row in connection.execute("PRAGMA integrity_check")] != ["ok"]:
                raise RestoreError("checkpoint database integrity failed")
            if list(connection.execute("PRAGMA foreign_key_check")):
                raise RestoreError("checkpoint database foreign keys failed")
            for table, expected_count in record.get("logical_counts", {}).items():
                escaped = str(table).replace('"', '""')
                count = connection.execute(
                    f'SELECT count(*) FROM "{escaped}"'
                ).fetchone()[0]
                if count != expected_count:
                    raise RestoreError("checkpoint logical row count differs")
        finally:
            connection.close()
    return recovery, checkpoint


def restore(bundle_root: Path, target_root: Path) -> dict[str, object]:
    bundle = bundle_root.resolve(strict=True)
    target = target_root.resolve(strict=True)
    if target.is_symlink() or getattr(target.lstat(), "st_file_attributes", 0) & 0x400:
        raise RestoreError("target cannot be a reparse/symlink")
    if any(target.iterdir()):
        raise RestoreError("target must be empty")
    recovery, checkpoint = verify_bundle(bundle)
    release = recovery["release"]
    release_id = str(release["release_id"])
    release_destination = target / "releases" / release_id
    release_destination.parent.mkdir()
    shutil.copytree(bundle / "release", release_destination)
    state_destination = target / "state"
    state_destination.mkdir()
    checkpoint_root = bundle / "checkpoints" / str(checkpoint["checkpoint_id"])
    for record in checkpoint["state"]["databases"]:
        source = safe_relative(checkpoint_root, record["relative_path"])
        shutil.copy2(source, state_destination / f"{record['logical_name']}.sqlite3")
    shutil.copytree(bundle / "tools", target / "tools")
    control = target / "control"
    control.mkdir()
    active = {
        "schema_version": "qrh-active-release/v1",
        "release_id": release_id,
        "release_path": str(release_destination),
        "manifest_sha256": release["manifest_sha256"],
    }
    temporary = control / ".active_release.json.partial"
    temporary.write_bytes(canonical(active))
    os.replace(temporary, control / "active_release.json")
    return {
        "status": "materialized_pending_post_restore_verification",
        "release_id": release_id,
        "manifest_sha256": release["manifest_sha256"],
        "checkpoint_id": checkpoint["checkpoint_id"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--empty-target-root", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(restore(args.bundle_root, args.empty_target_root), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
