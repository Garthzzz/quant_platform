r"""Fixed VM-side checkpoint and recovery-protection entry point.

All mutable paths are identity-derived below ``D:\quant\quant_platform``.
The command never writes the independent recovery root; the local publish
runtime downloads C, builds/verifies RM there, then uploads only verification
manifests for registration.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
from typing import Mapping

from quant_hub.collaboration.checkpoint import create_sqlite_checkpoint
from quant_hub.runtime_seal import read_json

from .deployment import DeploymentController
from .failure_domain_authority import (
    FailureDomainAuthorityNotReady,
    require_failure_domain_authority,
)
from .release_identity import (
    canonical_manifest_bytes,
    manifest_sha256,
    validate_checkpoint_manifest,
    validate_recovery_manifest,
)
from .vm_boundary import (
    PRODUCTION_VM_ROOT,
    capture_vm_write_snapshot,
    finalize_vm_write_audit,
    validate_production_vm_write_path,
    verify_existing_vm_write_path,
    verify_vm_write_target,
)


class PublishRecoveryCLIError(RuntimeError):
    pass


LEGACY_STATE_ROOT = PureWindowsPath(r"C:\quant_platform_data")
LEGACY_DATABASES = {
    "comments": LEGACY_STATE_ROOT / "comments.sqlite3",
    "research_workspace": LEGACY_STATE_ROOT / "research_workspace.sqlite3",
}


def _root(value: Path) -> Path:
    approved = validate_production_vm_write_path(str(value), allow_root=True)
    if approved != PRODUCTION_VM_ROOT:
        raise PublishRecoveryCLIError(r"vm-root must be D:\quant\quant_platform")
    return verify_existing_vm_write_path(Path(str(approved)), allow_root=True)


def _child(value: Path) -> Path:
    validate_production_vm_write_path(str(value), allow_root=False)
    return verify_vm_write_target(value, allow_root=False, must_exist=False)


def capture(*, vm_root: Path, checkpoint_id: str, state_authority_id: str):
    require_failure_domain_authority()
    root = _root(vm_root)
    controller = DeploymentController(root)
    active, _release = controller.read_active()
    staging = root / "tmp" / "publish-recovery"
    checkpoint_parent = _child(staging / "checkpoints")
    scratch = _child(staging / "scratch" / checkpoint_id)
    checkpoint_parent.mkdir(parents=True, exist_ok=True)
    scratch.mkdir(parents=True, exist_ok=True)
    created = create_sqlite_checkpoint(
        sources={
            "comments": _child(root / "state" / "comments.sqlite3"),
            "research_workspace": _child(
                root / "state" / "research_workspace.sqlite3"
            ),
        },
        checkpoint_root=checkpoint_parent,
        checkpoint_id=checkpoint_id,
        state_authority_id=state_authority_id,
        captured_under_release_id=str(active["release_id"]),
        captured_under_manifest_sha256=str(active["manifest_sha256"]),
        captured_at=datetime.now(UTC),
        scratch_root=scratch,
    )
    return {
        "schema_version": "qrh-publish-checkpoint-result/v1",
        "checkpoint_id": created.checkpoint_id,
        "checkpoint_manifest_sha256": created.manifest_sha256,
        "checkpoint_root": str(created.root),
    }


def identify_active(*, vm_root: Path):
    """Return only the unique active pointer and its resolved immutable R."""

    require_failure_domain_authority()
    root = _root(vm_root)
    active, release = DeploymentController(root).read_active()
    observed_hash = manifest_sha256(release)
    if observed_hash != active["manifest_sha256"]:
        raise PublishRecoveryCLIError("active release identity differs")
    return {
        "schema_version": "qrh-state-only-active-identity/v1",
        "release_id": active["release_id"],
        "release_manifest_sha256": observed_hash,
    }


def cleanup_capture(*, vm_root: Path, checkpoint_id: str):
    """Remove one exact VM staging capture after off-host verification/download.

    The immutable recovery checkpoint lives on the independently attested
    recovery host.  The VM copy is deliberately temporary and is never a
    retained recovery authority.
    """

    require_failure_domain_authority()
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", checkpoint_id) is None:
        raise PublishRecoveryCLIError("checkpoint_id is invalid")
    root = _root(vm_root)
    staging = root / "tmp" / "publish-recovery"
    targets = (
        _child(staging / "checkpoints" / checkpoint_id),
        _child(staging / "scratch" / checkpoint_id),
    )
    removed: list[str] = []
    for target in targets:
        if not target.exists():
            continue
        verify_existing_vm_write_path(target, allow_root=False)
        for item in target.rglob("*"):
            verify_existing_vm_write_path(item, allow_root=False)
            if not item.is_file() and not item.is_dir():
                raise PublishRecoveryCLIError(
                    "checkpoint staging contains a non-regular entry"
                )
        shutil.rmtree(target)
        removed.append(target.name)
    return {
        "schema_version": "qrh-publish-checkpoint-cleanup/v1",
        "checkpoint_id": checkpoint_id,
        "staging_removed": bool(removed),
    }


def capture_legacy(
    *,
    vm_root: Path,
    checkpoint_id: str,
    state_authority_id: str,
    release_id: str,
    release_manifest_sha256: str,
):
    """Capture the two legacy C state databases without writing to C.

    The source set is intentionally not configurable: prior to the C->D writer
    handoff these are the only mutable authorities.  Checkpoint output and all
    SQLite scratch bytes remain below the exact production D root.
    """

    require_failure_domain_authority()
    root = _root(vm_root)
    active_pointer = _child(root / "control" / "active_release.json")
    d_state = tuple(
        _child(root / "state" / name)
        for name in ("comments.sqlite3", "research_workspace.sqlite3")
    )
    if active_pointer.exists() or any(path.exists() for path in d_state):
        raise PublishRecoveryCLIError(
            "legacy C capture is forbidden after D active/state authority exists"
        )
    staging = root / "tmp" / "publish-recovery"
    checkpoint_parent = _child(staging / "checkpoints")
    scratch = _child(staging / "scratch")
    checkpoint_parent.mkdir(parents=True, exist_ok=True)
    scratch.mkdir(parents=True, exist_ok=True)
    created = create_sqlite_checkpoint(
        sources={name: Path(str(path)) for name, path in LEGACY_DATABASES.items()},
        checkpoint_root=checkpoint_parent,
        checkpoint_id=checkpoint_id,
        state_authority_id=state_authority_id,
        captured_under_release_id=release_id,
        captured_under_manifest_sha256=release_manifest_sha256,
        captured_at=datetime.now(UTC),
        scratch_root=scratch,
    )
    return {
        "schema_version": "qrh-publish-checkpoint-result/v1",
        "checkpoint_id": created.checkpoint_id,
        "checkpoint_manifest_sha256": created.manifest_sha256,
        "checkpoint_root": str(created.root),
        "source_authority": "legacy_c_read_only",
    }


def register(
    *,
    vm_root: Path,
    release_id: str,
    release_manifest_sha256: str,
    publish_candidate_sha256: str,
    deployment_attempt_id: str,
    checkpoint_manifest_path: Path,
    recovery_manifest_path: Path,
    protection_evidence_path: Path,
):
    require_failure_domain_authority()
    root = _root(vm_root)
    for path in (
        checkpoint_manifest_path,
        recovery_manifest_path,
        protection_evidence_path,
    ):
        _child(path)
    checkpoint = validate_checkpoint_manifest(read_json(checkpoint_manifest_path))
    recovery = validate_recovery_manifest(read_json(recovery_manifest_path))
    evidence = read_json(protection_evidence_path)
    evidence_fields = {
        "schema_version", "release_id", "release_manifest_sha256",
        "publish_candidate_sha256", "checkpoint_manifest_sha256",
        "recovery_manifest_sha256", "failure_domain_attestation",
        "bundle_verification",
    }
    if not isinstance(evidence, dict) or set(evidence) != evidence_fields:
        raise PublishRecoveryCLIError("protection evidence schema is not closed")
    if evidence["schema_version"] != "qrh-publish-recovery-protection-evidence/v1":
        raise PublishRecoveryCLIError("protection evidence schema is unsupported")
    candidate_path, observed_release_hash = DeploymentController(root).verify_finalized_release(
        release_id=release_id,
        expected_manifest_sha256=release_manifest_sha256,
    )
    del candidate_path
    checkpoint_hash = manifest_sha256(checkpoint)
    recovery_hash = manifest_sha256(recovery)
    bundle = evidence["bundle_verification"]
    if (
        observed_release_hash != release_manifest_sha256
        or evidence["release_id"] != release_id
        or evidence["release_manifest_sha256"] != release_manifest_sha256
        or evidence["publish_candidate_sha256"] != publish_candidate_sha256
        or evidence["checkpoint_manifest_sha256"] != checkpoint_hash
        or evidence["recovery_manifest_sha256"] != recovery_hash
        or not isinstance(bundle, dict)
        or set(bundle) != {"closure", "compatibility", "no_secret", "failure_domain"}
        or any(bundle.get(key) is not True for key in bundle)
    ):
        raise PublishRecoveryCLIError("recovery protection identity/verdict differs")
    release_ref = recovery["release"]
    checkpoint_ref = recovery["checkpoint"]
    if release_ref != {
        "release_id": release_id,
        "manifest_sha256": release_manifest_sha256,
    } or checkpoint_ref != {
        "checkpoint_id": checkpoint["checkpoint_id"],
        "manifest_sha256": checkpoint_hash,
    }:
        raise PublishRecoveryCLIError("RM does not bind exact R/C")
    receipt_id = f"protection-{deployment_attempt_id}"
    receipt = {
        "schema_version": "qrh-recovery-protection-receipt/v1",
        "receipt_type": "recovery_protection",
        "receipt_id": receipt_id,
        "deployment_attempt_id": deployment_attempt_id,
        "recorded_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "authority": "evidence_only",
        "release_manifest_sha256": release_manifest_sha256,
        "recovery_manifest_sha256": recovery_hash,
        "checkpoint_manifest_sha256": checkpoint_hash,
        "verdict": "protected",
        "pre_activation_verification": {
            "closure": True,
            "compatibility": True,
            "failure_domain": True,
            "no_secret": True,
            "active_pointer_switched": False,
        },
    }
    stored = DeploymentController(root).record_recovery_protection(
        receipt=receipt,
        recovery_manifest=recovery,
        checkpoint_manifest=checkpoint,
        external_protection_probe=lambda *_: True,
    )
    return {
        "schema_version": "qrh-publish-protection-result/v1",
        "deployment_attempt_id": deployment_attempt_id,
        "recovery_protection_receipt_id": stored["receipt_id"],
        "release_manifest_sha256": release_manifest_sha256,
        "recovery_manifest_sha256": recovery_hash,
        "checkpoint_manifest_sha256": checkpoint_hash,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    capture_parser = commands.add_parser("capture")
    capture_parser.add_argument("--vm-root", type=Path, required=True)
    capture_parser.add_argument("--checkpoint-id", required=True)
    capture_parser.add_argument("--state-authority-id", required=True)
    legacy_parser = commands.add_parser("capture-legacy")
    legacy_parser.add_argument("--vm-root", type=Path, required=True)
    legacy_parser.add_argument("--checkpoint-id", required=True)
    legacy_parser.add_argument("--state-authority-id", required=True)
    legacy_parser.add_argument("--release-id", required=True)
    legacy_parser.add_argument("--release-manifest-sha256", required=True)
    register_parser = commands.add_parser("register")
    register_parser.add_argument("--vm-root", type=Path, required=True)
    register_parser.add_argument("--release-id", required=True)
    register_parser.add_argument("--release-manifest-sha256", required=True)
    register_parser.add_argument("--publish-candidate-sha256", required=True)
    register_parser.add_argument("--deployment-attempt-id", required=True)
    register_parser.add_argument("--checkpoint-manifest", type=Path, required=True)
    register_parser.add_argument("--recovery-manifest", type=Path, required=True)
    register_parser.add_argument("--protection-evidence", type=Path, required=True)
    commands.add_parser("identify-active").add_argument(
        "--vm-root", type=Path, required=True
    )
    cleanup_parser = commands.add_parser("cleanup-capture")
    cleanup_parser.add_argument("--vm-root", type=Path, required=True)
    cleanup_parser.add_argument("--checkpoint-id", required=True)
    args = parser.parse_args(argv)
    try:
        require_failure_domain_authority()
    except FailureDomainAuthorityNotReady as error:
        print(json.dumps(error.document(), ensure_ascii=False, sort_keys=True))
        return 2
    root = _root(args.vm_root)
    before = capture_vm_write_snapshot(root)
    operation = f"publish-recovery-{args.command}"
    try:
        if args.command == "capture":
            require_failure_domain_authority()
            value = capture(
                vm_root=root,
                checkpoint_id=args.checkpoint_id,
                state_authority_id=args.state_authority_id,
            )
        elif args.command == "capture-legacy":
            require_failure_domain_authority()
            value = capture_legacy(
                vm_root=root,
                checkpoint_id=args.checkpoint_id,
                state_authority_id=args.state_authority_id,
                release_id=args.release_id,
                release_manifest_sha256=args.release_manifest_sha256,
            )
        elif args.command == "register":
            require_failure_domain_authority()
            value = register(
                vm_root=root,
                release_id=args.release_id,
                release_manifest_sha256=args.release_manifest_sha256,
                publish_candidate_sha256=args.publish_candidate_sha256,
                deployment_attempt_id=args.deployment_attempt_id,
                checkpoint_manifest_path=args.checkpoint_manifest,
                recovery_manifest_path=args.recovery_manifest,
                protection_evidence_path=args.protection_evidence,
            )
        elif args.command == "identify-active":
            require_failure_domain_authority()
            value = identify_active(vm_root=root)
        else:
            require_failure_domain_authority()
            value = cleanup_capture(
                vm_root=root,
                checkpoint_id=args.checkpoint_id,
            )
    except BaseException:
        finalize_vm_write_audit(
            root, before, operation=operation, outcome="failed"
        )
        raise
    finalize_vm_write_audit(
        root, before, operation=operation, outcome="succeeded"
    )
    print(json.dumps(value, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
