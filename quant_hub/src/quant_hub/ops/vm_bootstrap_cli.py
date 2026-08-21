"""One-time V39 bootstrap extraction inside the approved production VM root."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
from typing import Mapping
from uuid import uuid4
import zipfile

from quant_hub.config import ensure_no_reparse_components
from quant_hub.runtime_seal import write_atomic_new_json

from .deployment import DeploymentController, DeploymentLayout
from .release_identity import (
    canonical_manifest_bytes,
    manifest_sha256,
    validate_release_manifest,
)
from .vm_boundary import (
    PRODUCTION_VM_ROOT,
    capture_vm_write_snapshot,
    finalize_vm_write_audit,
    validate_production_vm_write_path,
)


class V39BootstrapError(RuntimeError):
    pass


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _release_inventory(release: Mapping[str, object]) -> dict[str, Mapping[str, object]]:
    inventory = release.get("inventory")
    if not isinstance(inventory, dict) or not isinstance(inventory.get("files"), list):
        raise V39BootstrapError("V39 release inventory is missing")
    result: dict[str, Mapping[str, object]] = {}
    for record in inventory["files"]:
        if not isinstance(record, dict) or set(record) != {"path", "bytes", "sha256"}:
            raise V39BootstrapError("V39 release inventory record is invalid")
        relative = record["path"]
        if not isinstance(relative, str):
            raise V39BootstrapError("V39 release inventory path is invalid")
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or pure.as_posix() != relative:
            raise V39BootstrapError("V39 release inventory path escapes")
        if relative in result:
            raise V39BootstrapError("V39 release inventory path is duplicated")
        result[relative] = record
    return result


def prepare_v39_candidate(
    *,
    vm_root: Path,
    archive_path: Path,
    release_manifest_path: Path,
    expected_release_id: str,
    expected_release_manifest_sha256: str,
) -> dict[str, object]:
    """Extract the sealed legacy ZIP to ``incoming/<R>.partial`` without activation."""

    root = vm_root.resolve(strict=True)
    archive = archive_path.resolve(strict=True)
    manifest_path = release_manifest_path.resolve(strict=True)
    ensure_no_reparse_components(root)
    ensure_no_reparse_components(archive)
    ensure_no_reparse_components(manifest_path)
    for path in (archive, manifest_path):
        try:
            path.relative_to(root)
        except ValueError as error:
            raise V39BootstrapError("bootstrap input must already be inside VM_ROOT") from error

    release = validate_release_manifest(
        json.loads(manifest_path.read_text(encoding="utf-8"))
    )
    if manifest_path.read_bytes() != canonical_manifest_bytes(release):
        raise V39BootstrapError("release manifest is not canonical")
    release_hash = manifest_sha256(release)
    if (
        release["release_id"] != expected_release_id
        or release_hash != expected_release_manifest_sha256
    ):
        raise V39BootstrapError("V39 release identity differs")
    application = release["application"]
    if (
        not isinstance(application, dict)
        or application.get("source_kind") != "legacy_broadcast"
        or application.get("source_archive_sha256") != _digest(archive)
    ):
        raise V39BootstrapError("V39 source archive provenance differs")

    layout = DeploymentLayout.controlled(root)
    controller = DeploymentController(root)
    destination = controller.partial_path(expected_release_id)
    if os.path.lexists(destination):
        raise V39BootstrapError("V39 candidate partial already exists")
    staging = layout.incoming / f".qrh-v39-{uuid4().hex}"
    staging.mkdir()
    try:
        expected = _release_inventory(release)
        archive_members: dict[str, zipfile.ZipInfo] = {}
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.infolist():
                raw = member.filename.replace("\\", "/")
                pure = PurePosixPath(raw)
                if pure.is_absolute() or ".." in pure.parts:
                    raise V39BootstrapError("V39 ZIP member escapes extraction root")
                if member.is_dir():
                    continue
                if not raw.startswith("company_broadcast/"):
                    raise V39BootstrapError("V39 ZIP has a file outside company_broadcast")
                relative = raw.removeprefix("company_broadcast/")
                if relative in archive_members:
                    raise V39BootstrapError("V39 ZIP member is duplicated")
                archive_members[relative] = member
            if set(archive_members) != set(expected):
                raise V39BootstrapError("V39 ZIP membership differs from release inventory")

            for relative, record in expected.items():
                member = archive_members[relative]
                target = staging.joinpath(*PurePosixPath(relative).parts)
                resolved_parent = target.parent.resolve(strict=False)
                try:
                    resolved_parent.relative_to(staging.resolve())
                except ValueError as error:
                    raise V39BootstrapError("V39 extraction target escapes staging") from error
                target.parent.mkdir(parents=True, exist_ok=True)
                digest = hashlib.sha256()
                size = 0
                with bundle.open(member) as source, target.open("xb") as output:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        output.write(block)
                        digest.update(block)
                        size += len(block)
                if size != record["bytes"] or digest.hexdigest() != record["sha256"]:
                    raise V39BootstrapError("V39 extracted payload hash differs")

        (staging / "release_manifest.json").write_bytes(
            canonical_manifest_bytes(release)
        )
        DeploymentController._inventory_contract(release, staging)
        os.replace(staging, destination)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        raise

    event_id = f"v39-candidate-prepared-{uuid4().hex}"
    write_atomic_new_json(
        layout.audit_events / f"{event_id}.json",
        {
            "schema_version": "qrh-v39-bootstrap-event/v1",
            "event_id": event_id,
            "authority": "evidence_only",
            "release_id": expected_release_id,
            "release_manifest_sha256": release_hash,
            "archive_sha256": application["source_archive_sha256"],
            "status": "candidate_prepared_not_active",
        },
    )
    return {
        "schema_version": "qrh-v39-bootstrap-result/v1",
        "release_id": expected_release_id,
        "release_manifest_sha256": release_hash,
        "candidate_path": str(destination),
        "status": "candidate_prepared_not_active",
        "evidence_id": event_id,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("prepare-v39", nargs="?")
    parser.add_argument("--vm-root", type=Path, required=True)
    parser.add_argument("--archive-path", type=Path, required=True)
    parser.add_argument("--release-manifest-path", type=Path, required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--release-manifest-sha256", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    approved = validate_production_vm_write_path(str(args.vm_root))
    if approved != PRODUCTION_VM_ROOT:
        raise V39BootstrapError(r"vm-root must be exactly D:\quant\quant_platform")
    for value in (args.archive_path, args.release_manifest_path):
        validate_production_vm_write_path(str(value), allow_root=False)
    root = args.vm_root.resolve(strict=True)
    before = capture_vm_write_snapshot(root)
    try:
        result = prepare_v39_candidate(
            vm_root=root,
            archive_path=args.archive_path,
            release_manifest_path=args.release_manifest_path,
            expected_release_id=args.release_id,
            expected_release_manifest_sha256=args.release_manifest_sha256,
        )
    except BaseException:
        finalize_vm_write_audit(
            root, before, operation="bootstrap-v39", outcome="failed"
        )
        raise
    finalize_vm_write_audit(
        root, before, operation="bootstrap-v39", outcome="succeeded"
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
