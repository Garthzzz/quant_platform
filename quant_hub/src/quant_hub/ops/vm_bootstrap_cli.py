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

from . import local_release_identity as local_identity
from .local_deployment_persistence import LocalDeploymentPersistence
from .local_exact_deployment_controller import ProductionExactDeploymentController
from .vm_boundary import (
    PRODUCTION_VM_ROOT,
    VMBoundaryError,
    capture_vm_write_snapshot,
    finalize_vm_write_audit,
    reject_test_only_path_on_production_vm,
    validate_production_vm_write_path,
)


class V39BootstrapError(RuntimeError):
    pass


def activate_v39_pair_bridge(
    *,
    baseline_release_id: str,
    baseline_manifest_sha256: str,
    successor_release_id: str,
    successor_manifest_sha256: str,
    bootstrap_attempt_id: str,
    activation_attempt_id: str,
) -> Mapping[str, object]:
    """Consume prepared R0/R1 candidates through the production v4 controller.

    This entry is intentionally usable only through the no-argument exact-D
    controller factory.  R0 is first committed as the non-ingress bootstrap
    lineage, then the genuinely distinct R1 is activated to form R1/R0 and
    open ordinary steady service admission.
    """

    for label, value in (
        ("baseline manifest", baseline_manifest_sha256),
        ("successor manifest", successor_manifest_sha256),
    ):
        if (
            type(value) is not str
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise V39BootstrapError(f"{label} SHA-256 is invalid")
    if (
        baseline_release_id == successor_release_id
        or baseline_manifest_sha256 == successor_manifest_sha256
    ):
        raise V39BootstrapError(
            "V39 R0 and successor R1 must have distinct release identities"
        )
    controller = ProductionExactDeploymentController.load_exact_d()
    existing = controller.inspect_closed_bootstrap_baseline(
        release_id=baseline_release_id,
        expected_manifest_sha256=baseline_manifest_sha256,
    )
    if existing is None:
        bootstrap = controller.bootstrap_first_pair(
            release_id=baseline_release_id,
            expected_manifest_sha256=baseline_manifest_sha256,
            attempt_id=bootstrap_attempt_id,
        )
        if (
            bootstrap.get("status") != "bootstrapped"
            or bootstrap.get("release_id") != baseline_release_id
            or bootstrap.get("release_manifest_sha256")
            != baseline_manifest_sha256
            or bootstrap.get("ingress_status") != "closed"
        ):
            raise V39BootstrapError("exact R0 bootstrap did not close")
        bootstrap_reused = False
    else:
        existing_release = existing.get("release")
        if (
            existing.get("schema_version")
            != "qrh-closed-bootstrap-baseline-proof/v1"
            or existing.get("status") != "closed_non_ingress"
            or not isinstance(existing_release, Mapping)
            or existing_release.get("release_id")
            != baseline_release_id
            or existing_release.get("manifest_sha256")
            != baseline_manifest_sha256
            or existing.get("ingress_status") != "closed"
        ):
            raise V39BootstrapError("existing exact R0 bootstrap proof differs")
        bootstrap = {
            "terminal_journal_sha256": existing[
                "terminal_journal_sha256"
            ],
            "activation_receipt_id": existing["activation_receipt_id"],
        }
        bootstrap_reused = True
    activation = controller.activate_successor(
        release_id=successor_release_id,
        expected_manifest_sha256=successor_manifest_sha256,
        attempt_id=activation_attempt_id,
    )
    if (
        activation.get("status") != "activated"
        or activation.get("release_id") != successor_release_id
        or activation.get("release_manifest_sha256")
        != successor_manifest_sha256
    ):
        raise V39BootstrapError("exact R0 to R1 activation did not close")
    evidence = {
        "bootstrap_terminal_journal_sha256": bootstrap[
            "terminal_journal_sha256"
        ],
        "bootstrap_activation_receipt_id": bootstrap[
            "activation_receipt_id"
        ],
        "activation_terminal_journal_sha256": activation[
            "terminal_journal_sha256"
        ],
        "activation_receipt_id": activation["activation_receipt_id"],
    }
    return {
        "schema_version": "qrh-v39-exact-pair-bridge-result/v1",
        "status": "activated_pair",
        "pair": {
            "active": {
                "release_id": successor_release_id,
                "manifest_sha256": successor_manifest_sha256,
            },
            "prior": {
                "release_id": baseline_release_id,
                "manifest_sha256": baseline_manifest_sha256,
            },
        },
        "evidence": evidence,
        "bootstrap_reused": bootstrap_reused,
        "evidence_sha256": local_identity.identity_sha256(evidence),
    }


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
    allow_test_root: bool = False,
) -> dict[str, object]:
    """Extract the sealed legacy ZIP to ``incoming/<R>.partial`` without activation."""

    if allow_test_root:
        try:
            reject_test_only_path_on_production_vm(
                vm_root, label="test-only V39 bootstrap root"
            )
        except VMBoundaryError as error:
            raise V39BootstrapError(str(error)) from error
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

    release = local_identity.validate_release_manifest(
        json.loads(manifest_path.read_text(encoding="utf-8"))
    )
    if manifest_path.read_bytes() != local_identity.canonical_bytes(release):
        raise V39BootstrapError("release manifest is not canonical")
    release_hash = local_identity.identity_sha256(release)
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

    persistence = (
        LocalDeploymentPersistence.for_test_only(
            root, allow_posix_test_only=True
        )
        if allow_test_root
        else LocalDeploymentPersistence.production()
    )
    if persistence.layout.root.resolve(strict=True) != root:
        raise V39BootstrapError("bootstrap persistence root differs from VM root")
    layout = persistence.layout
    destination = layout.incoming / f"{expected_release_id}.partial"
    persistence.assert_write_path(destination)
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
            local_identity.canonical_bytes(release)
        )
        os.replace(staging, destination)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        raise

    event_id = f"v39-candidate-prepared-{uuid4().hex}"
    write_atomic_new_json(
        layout.events / f"{event_id}.json",
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
    parser.add_argument(
        "command", choices=("prepare-v39", "activate-v39-pair")
    )
    parser.add_argument("--vm-root", type=Path, required=True)
    parser.add_argument("--archive-path", type=Path)
    parser.add_argument("--release-manifest-path", type=Path)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--release-manifest-sha256", required=True)
    parser.add_argument("--successor-release-id")
    parser.add_argument("--successor-release-manifest-sha256")
    parser.add_argument("--bootstrap-attempt-id")
    parser.add_argument("--activation-attempt-id")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    approved = validate_production_vm_write_path(str(args.vm_root))
    if approved != PRODUCTION_VM_ROOT:
        raise V39BootstrapError(r"vm-root must be exactly D:\quant\quant_platform")
    root = args.vm_root.resolve(strict=True)
    before = capture_vm_write_snapshot(root)
    try:
        if args.command == "prepare-v39":
            if args.archive_path is None or args.release_manifest_path is None:
                raise V39BootstrapError(
                    "prepare-v39 requires archive and release manifest paths"
                )
            for value in (args.archive_path, args.release_manifest_path):
                validate_production_vm_write_path(str(value), allow_root=False)
            result = prepare_v39_candidate(
                vm_root=root,
                archive_path=args.archive_path,
                release_manifest_path=args.release_manifest_path,
                expected_release_id=args.release_id,
                expected_release_manifest_sha256=args.release_manifest_sha256,
                allow_test_root=False,
            )
        else:
            if any(
                value is None
                for value in (
                    args.successor_release_id,
                    args.successor_release_manifest_sha256,
                    args.bootstrap_attempt_id,
                    args.activation_attempt_id,
                )
            ):
                raise V39BootstrapError(
                    "activate-v39-pair requires successor and both attempt identities"
                )
            result = activate_v39_pair_bridge(
                baseline_release_id=args.release_id,
                baseline_manifest_sha256=args.release_manifest_sha256,
                successor_release_id=args.successor_release_id,
                successor_manifest_sha256=(
                    args.successor_release_manifest_sha256
                ),
                bootstrap_attempt_id=args.bootstrap_attempt_id,
                activation_attempt_id=args.activation_attempt_id,
            )
    except BaseException:
        finalize_vm_write_audit(
            root, before, operation=args.command, outcome="failed"
        )
        raise
    finalize_vm_write_audit(
        root, before, operation=args.command, outcome="succeeded"
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
