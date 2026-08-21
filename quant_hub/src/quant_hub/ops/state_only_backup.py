"""Developer-host state-only recovery job.

The single scheduled job runs on the independently attested recovery host.  It
asks only VM ``10.5.1.240`` to create an online SQLite checkpoint below the
exact ``D:\\quant\\quant_platform\\tmp`` staging tree, downloads and verifies
that checkpoint, builds an immutable composite recovery set next to the
retained cold bundle, and then removes the VM staging copy.

The job never changes ``active_release.json``, a release manifest, application
code or online SQLite state.  Receipts and status are evidence only.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import base64
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Callable, Iterator, Mapping, Protocol, Sequence
from uuid import uuid4

from quant_hub.collaboration.checkpoint import (
    CHECKPOINT_MANIFEST_NAME,
    RecoveryProtectionStatus,
    evaluate_recovery_protection,
    verify_sqlite_checkpoint,
)
from quant_hub.config import ensure_no_reparse_components
from quant_hub.runtime_seal import read_json, write_atomic_new_json

from .publish_runtime import (
    OpenSSHRecoveryActions,
    RecoveryProtectionCoordinator,
    RuntimePublishConfig,
    UnavailableRecoveryActions,
)
from .recovery_bundle import RecoveryVerification, verify_recovery_bundle
from .release_identity import (
    authorize_receipt_append,
    canonical_manifest_bytes,
    lint_identity_graph,
    manifest_sha256,
    validate_active_release,
    validate_checkpoint_manifest,
    validate_receipt,
    validate_recovery_manifest,
    validate_release_manifest,
)


STATE_SET_SCHEMA = "qrh-state-only-recovery-set/v1"
STATIC_REF_SCHEMA = "qrh-state-only-static-closure-ref/v1"
ATTEMPT_SCHEMA = "qrh-state-only-backup-attempt/v1"
STATUS_SCHEMA = "qrh-recovery-protection-status/v1"
GC_ROOTS_SCHEMA = "qrh-recovery-gc-roots/v1"
TASK_CANDIDATE_SCHEMA = "qrh-state-only-scheduled-task/v1"
TASK_IDENTITY = r"\QuantResearchHub\StateOnlyBackup"
RPO = timedelta(hours=24)

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class StateOnlyBackupError(RuntimeError):
    """State-only backup cannot prove a safe recovery point."""


class StateOnlyBackupLocked(StateOnlyBackupError):
    """The one permitted state-only job already owns its lock."""


@dataclass(frozen=True)
class ActiveBinding:
    release_id: str
    manifest_sha256: str


@dataclass(frozen=True)
class StateOnlySetVerification:
    valid: bool
    root: Path
    checkpoint_root: Path | None
    checkpoint_id: str | None
    captured_at: datetime | None
    release_id: str | None
    release_manifest_sha256: str | None
    recovery_manifest_sha256: str | None
    receipt_id: str | None
    errors: tuple[str, ...]


@dataclass(frozen=True)
class StateOnlyRunResult:
    attempt_id: str
    checkpoint_id: str | None
    recovery_set_id: str | None
    status: RecoveryProtectionStatus
    succeeded: bool
    error_code: str | None


class StateOnlyVM(Protocol):
    def read_active_identity(self) -> Mapping[str, str]: ...

    def capture_state_only_checkpoint(
        self,
        *,
        release_id: str,
        release_manifest_sha256: str,
        checkpoint_id: str,
    ) -> Path: ...

    def cleanup_state_only_capture(self, *, checkpoint_id: str) -> None: ...


class TaskSchedulerAdapter(Protocol):
    def inspect(self, candidate: Mapping[str, object]) -> str | None: ...

    def register(self, candidate: Mapping[str, object]) -> None: ...


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise StateOnlyBackupError("timestamp must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise StateOnlyBackupError("timestamp is not canonical UTC")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise StateOnlyBackupError("timestamp is not timezone-aware")
    return parsed.astimezone(UTC)


def _safe_id(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None or ".." in value:
        raise StateOnlyBackupError(f"{label} is invalid")
    return value


def _sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        raise StateOnlyBackupError(f"{label} is invalid")
    return value


def _hash_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_read(path: Path) -> Mapping[str, object]:
    value = read_json(path)
    if not isinstance(value, dict) or path.read_bytes() != canonical_manifest_bytes(value):
        raise StateOnlyBackupError("immutable JSON is not canonical")
    return value


def _copy_tree(source: Path, destination: Path) -> None:
    ensure_no_reparse_components(source)
    if destination.exists():
        raise StateOnlyBackupError("immutable copy destination already exists")
    for path in source.rglob("*"):
        ensure_no_reparse_components(path)
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise StateOnlyBackupError("recovery copy contains a non-regular entry")
    shutil.copytree(source, destination, copy_function=shutil.copy2)


def _inventory(root: Path, *, excluded: Sequence[str] = ()) -> list[dict[str, object]]:
    blocked = set(excluded)
    rows: list[dict[str, object]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        ensure_no_reparse_components(path)
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if relative in blocked:
            continue
        rows.append(
            {
                "path": relative,
                "bytes": path.stat().st_size,
                "sha256": _hash_path(path),
            }
        )
    return rows


def _binding(value: Mapping[str, str]) -> ActiveBinding:
    release_id = _safe_id(value.get("release_id"), label="active release_id")
    digest = _sha(
        value.get("release_manifest_sha256"),
        label="active release manifest hash",
    )
    return ActiveBinding(release_id, digest)


def _active_document(binding: ActiveBinding) -> Mapping[str, object]:
    return validate_active_release(
        {
            "schema_version": "qrh-active-release/v1",
            "release_id": binding.release_id,
            "release_path": str(
                PureWindowsPath(r"D:\quant\quant_platform\releases")
                / binding.release_id
            ),
            "manifest_sha256": binding.manifest_sha256,
        }
    )


def _state_root(recovery_root: Path) -> Path:
    root = recovery_root.resolve(strict=True)
    ensure_no_reparse_components(root)
    return root / "state-only"


@contextmanager
def _job_lock(root: Path) -> Iterator[None]:
    """Own the one recovery-host job with a process lock, not file existence.

    A create-once sentinel becomes a permanent outage when a process is killed
    before unlinking it.  The scheduled task therefore keeps a small audit
    file but relies on the operating system to release the actual lock when the
    process exits.
    """

    control = root / "control"
    control.mkdir(parents=True, exist_ok=True)
    ensure_no_reparse_components(control)
    lock = control / "state-only-backup.lock"
    token = uuid4().hex
    descriptor = os.open(lock, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        if os.name == "nt":
            import msvcrt

            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            except OSError as error:
                raise StateOnlyBackupLocked(
                    "state-only backup lock is currently owned"
                ) from error
        else:
            import fcntl

            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                raise StateOnlyBackupLocked(
                    "state-only backup lock is currently owned"
                ) from error
        os.ftruncate(descriptor, 0)
        os.lseek(descriptor, 0, os.SEEK_SET)
        with os.fdopen(os.dup(descriptor), "w", encoding="ascii", newline="\n") as stream:
            stream.write(token + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(descriptor)
        try:
            if lock.read_text(encoding="ascii").strip() == token:
                lock.unlink()
        except OSError:
            pass


@contextmanager
def _controlled_environment(root: Path, attempt_id: str) -> Iterator[Path]:
    temporary = root / "tmp" / attempt_id
    temporary.mkdir(parents=True)
    ensure_no_reparse_components(temporary)
    old = {name: os.environ.get(name) for name in ("TEMP", "TMP", "PYTHONDONTWRITEBYTECODE")}
    old_tempdir = tempfile.tempdir
    old_bytecode = sys.dont_write_bytecode
    os.environ["TEMP"] = str(temporary)
    os.environ["TMP"] = str(temporary)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    tempfile.tempdir = str(temporary)
    sys.dont_write_bytecode = True
    try:
        yield temporary
    finally:
        sys.dont_write_bytecode = old_bytecode
        tempfile.tempdir = old_tempdir
        for name, value in old.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        shutil.rmtree(temporary, ignore_errors=True)


def _attestation_sha(config: RuntimePublishConfig) -> str:
    value = _canonical_read(config.recovery.attestation_path)
    claimed = value.get("attestation_sha256")
    return _sha(claimed, label="failure-domain attestation hash")


def select_static_bundle(
    recovery_root: Path,
    *,
    active: ActiveBinding,
) -> Path:
    candidates: list[tuple[datetime, str, Path]] = []
    for path in recovery_root.glob("cold-recovery-*"):
        if not path.is_dir():
            continue
        try:
            candidate_rm = validate_recovery_manifest(
                _canonical_read(path / "recovery_manifest.json")
            )
        except Exception:
            continue
        if candidate_rm["release"] != {
            "release_id": active.release_id,
            "manifest_sha256": active.manifest_sha256,
        }:
            continue
        report = verify_recovery_bundle(path)
        if (
            not report.valid
            or report.release_id != active.release_id
            or report.release_manifest_sha256 != active.manifest_sha256
            or report.recovery_manifest_sha256 is None
        ):
            continue
        manifest = validate_recovery_manifest(
            _canonical_read(path / "recovery_manifest.json")
        )
        candidates.append(
            (
                _parse_timestamp(manifest["created_at"]),
                str(report.recovery_manifest_sha256),
                path.resolve(strict=True),
            )
        )
    if not candidates:
        raise StateOnlyBackupError("no verified retained static closure matches active R")
    return max(candidates, key=lambda item: (item[0], item[1]))[2]


def build_state_only_recovery_set(
    *,
    recovery_root: Path,
    base_bundle_root: Path,
    checkpoint_root: Path,
    active: ActiveBinding,
    attestation_sha256: str,
    recorded_at: datetime,
) -> Path:
    """Compose one C/RM/receipt with a verified retained static closure."""

    base_report = verify_recovery_bundle(base_bundle_root)
    if (
        not base_report.valid
        or base_report.release_id != active.release_id
        or base_report.release_manifest_sha256 != active.manifest_sha256
        or base_report.recovery_manifest_sha256 is None
    ):
        raise StateOnlyBackupError("base cold bundle does not bind active R")
    base_rm = validate_recovery_manifest(
        _canonical_read(base_bundle_root / "recovery_manifest.json")
    )
    release = validate_release_manifest(
        _canonical_read(base_bundle_root / "release" / "release_manifest.json")
    )
    checkpoint_report = verify_sqlite_checkpoint(checkpoint_root)
    if (
        not checkpoint_report.valid
        or checkpoint_report.checkpoint_id is None
        or checkpoint_report.manifest_sha256 is None
        or checkpoint_report.captured_at is None
    ):
        raise StateOnlyBackupError("downloaded checkpoint is not fully verified")
    checkpoint = validate_checkpoint_manifest(
        _canonical_read(checkpoint_root / CHECKPOINT_MANIFEST_NAME)
    )
    captured = checkpoint["captured_under_active_release"]
    if captured != {
        "release_id": active.release_id,
        "manifest_sha256": active.manifest_sha256,
    }:
        raise StateOnlyBackupError("checkpoint was not captured under observed active R")

    checkpoint_id = str(checkpoint_report.checkpoint_id)
    set_id = _safe_id(f"state-only-{checkpoint_id}", label="state-only set ID")
    parent = _state_root(recovery_root) / "sets"
    parent.mkdir(parents=True, exist_ok=True)
    destination = parent / set_id
    if destination.exists():
        raise StateOnlyBackupError("immutable state-only set already exists")
    partial = parent / f".{set_id}.partial-{uuid4().hex}"
    partial.mkdir()
    try:
        copied_checkpoint = partial / "checkpoints" / checkpoint_id
        copied_checkpoint.parent.mkdir()
        _copy_tree(checkpoint_root, copied_checkpoint)
        created_at = _timestamp(recorded_at)
        recovery_manifest = {
            "schema_version": "qrh-recovery-manifest/v1",
            "bundle_id": set_id,
            "created_at": created_at,
            "release": {
                "release_id": active.release_id,
                "manifest_sha256": active.manifest_sha256,
            },
            "checkpoint": {
                "checkpoint_id": checkpoint_id,
                "manifest_sha256": checkpoint_report.manifest_sha256,
            },
            "closure": dict(base_rm["closure"]),
            "compatibility": dict(base_rm["compatibility"]),
            "restore": dict(base_rm["restore"]),
            "no_secret_attestation": dict(base_rm["no_secret_attestation"]),
        }
        validate_recovery_manifest(recovery_manifest)
        rm_hash = manifest_sha256(recovery_manifest)
        (partial / "recovery_manifest.json").write_bytes(
            canonical_manifest_bytes(recovery_manifest)
        )
        base_relative = base_bundle_root.resolve(strict=True).relative_to(
            recovery_root.resolve(strict=True)
        ).as_posix()
        static_ref = {
            "schema_version": STATIC_REF_SCHEMA,
            "base_bundle_relative_path": base_relative,
            "base_bundle_id": base_report.bundle_id,
            "base_recovery_manifest_sha256": base_report.recovery_manifest_sha256,
            "base_closure_inventory_sha256": base_rm["closure"]["inventory_sha256"],
            "failure_domain_attestation_sha256": _sha(
                attestation_sha256, label="failure-domain attestation hash"
            ),
        }
        (partial / "static_bundle_ref.json").write_bytes(
            canonical_manifest_bytes(static_ref)
        )
        receipt = {
            "schema_version": "qrh-checkpoint-receipt/v1",
            "receipt_type": "checkpoint",
            "receipt_id": f"checkpoint-receipt-{checkpoint_id}",
            "backup_attempt_id": f"backup-{checkpoint_id}",
            "recorded_at": created_at,
            "authority": "evidence_only",
            "release_manifest_sha256": active.manifest_sha256,
            "recovery_manifest_sha256": rm_hash,
            "checkpoint_manifest_sha256": checkpoint_report.manifest_sha256,
            "operation": "state_only_backup",
            "verdict": "checkpoint_verified",
            "state_only_verification": {
                "integrity": True,
                "closure": True,
                "release_unchanged": True,
                "active_unchanged": True,
            },
        }
        validate_receipt(receipt)
        authorize_receipt_append(receipt, observed_active_release=_active_document(active))
        lint_identity_graph(
            active_release=_active_document(active),
            release_manifests=[release],
            checkpoint_manifests=[checkpoint],
            recovery_manifests=[recovery_manifest],
            receipts=[receipt],
        )
        (partial / "checkpoint_receipt.json").write_bytes(
            canonical_manifest_bytes(receipt)
        )
        records = _inventory(partial, excluded=("set_manifest.json", "SHA256SUMS"))
        set_manifest = {
            "schema_version": STATE_SET_SCHEMA,
            "set_id": set_id,
            "created_at": created_at,
            "checkpoint_id": checkpoint_id,
            "recovery_manifest_sha256": rm_hash,
            "static_bundle_ref_sha256": manifest_sha256(static_ref),
            "checkpoint_receipt_sha256": manifest_sha256(receipt),
            "inventory_sha256": manifest_sha256(records),
            "files": records,
        }
        (partial / "set_manifest.json").write_bytes(
            canonical_manifest_bytes(set_manifest)
        )
        sums = "".join(
            f"{row['sha256']}  {row['path']}\n"
            for row in _inventory(partial, excluded=("SHA256SUMS",))
        )
        (partial / "SHA256SUMS").write_text(sums, encoding="utf-8", newline="\n")
        os.replace(partial, destination)
    except BaseException:
        shutil.rmtree(partial, ignore_errors=True)
        raise
    result = verify_state_only_recovery_set(destination, recovery_root=recovery_root)
    if not result.valid:
        raise StateOnlyBackupError("published state-only recovery set failed verification")
    return destination


def _verify_sums(root: Path) -> None:
    sums = root / "SHA256SUMS"
    expected: dict[str, str] = {}
    for line in sums.read_text(encoding="utf-8").splitlines():
        if "  " not in line:
            raise StateOnlyBackupError("state-only checksum line is invalid")
        digest, relative = line.split("  ", 1)
        if _SHA_RE.fullmatch(digest) is None or relative in expected:
            raise StateOnlyBackupError("state-only checksum identity is invalid")
        expected[relative] = digest
    actual = {
        path.relative_to(root).as_posix(): _hash_path(path)
        for path in root.rglob("*")
        if path.is_file() and path != sums
    }
    if expected != actual:
        raise StateOnlyBackupError("state-only checksum closure differs")


def verify_state_only_recovery_set(
    root: Path,
    *,
    recovery_root: Path,
    base_reports: dict[Path, RecoveryVerification] | None = None,
) -> StateOnlySetVerification:
    set_root = Path(root).resolve()
    checkpoint_root: Path | None = None
    checkpoint_id = release_id = release_hash = rm_hash = receipt_id = None
    captured_at: datetime | None = None
    errors: list[str] = []
    try:
        recovery = Path(recovery_root).resolve(strict=True)
        set_root.relative_to((_state_root(recovery) / "sets").resolve(strict=True))
        ensure_no_reparse_components(set_root)
        _verify_sums(set_root)
        set_manifest = _canonical_read(set_root / "set_manifest.json")
        if set_manifest.get("schema_version") != STATE_SET_SCHEMA:
            raise StateOnlyBackupError("state-only set schema is invalid")
        if set_manifest.get("set_id") != set_root.name:
            raise StateOnlyBackupError("state-only set directory identity differs")
        expected_records = set_manifest.get("files")
        if not isinstance(expected_records, list):
            raise StateOnlyBackupError("state-only inventory is missing")
        actual_records = _inventory(
            set_root, excluded=("set_manifest.json", "SHA256SUMS")
        )
        if (
            actual_records != expected_records
            or set_manifest.get("inventory_sha256") != manifest_sha256(actual_records)
        ):
            raise StateOnlyBackupError("state-only inventory differs")

        static_ref = _canonical_read(set_root / "static_bundle_ref.json")
        required_ref = {
            "schema_version", "base_bundle_relative_path", "base_bundle_id",
            "base_recovery_manifest_sha256", "base_closure_inventory_sha256",
            "failure_domain_attestation_sha256",
        }
        if set(static_ref) != required_ref or static_ref.get("schema_version") != STATIC_REF_SCHEMA:
            raise StateOnlyBackupError("static closure reference is invalid")
        if set_manifest.get("static_bundle_ref_sha256") != manifest_sha256(static_ref):
            raise StateOnlyBackupError("static closure reference hash differs")
        relative = static_ref["base_bundle_relative_path"]
        if not isinstance(relative, str) or not relative or "\\" in relative:
            raise StateOnlyBackupError("static bundle relative path is invalid")
        base = (recovery / Path(relative)).resolve(strict=True)
        base.relative_to(recovery)
        if base.parent != recovery:
            raise StateOnlyBackupError("static bundle must be a direct retained cold bundle")
        cache = base_reports if base_reports is not None else {}
        base_report = cache.get(base)
        if base_report is None:
            base_report = verify_recovery_bundle(base)
            cache[base] = base_report
        if (
            not base_report.valid
            or base_report.bundle_id != static_ref["base_bundle_id"]
            or base_report.recovery_manifest_sha256
            != static_ref["base_recovery_manifest_sha256"]
        ):
            raise StateOnlyBackupError("static cold bundle is unavailable or changed")
        base_rm = validate_recovery_manifest(
            _canonical_read(base / "recovery_manifest.json")
        )
        if base_rm["closure"]["inventory_sha256"] != static_ref[
            "base_closure_inventory_sha256"
        ]:
            raise StateOnlyBackupError("static closure inventory identity differs")

        declared_checkpoint_id = _safe_id(
            set_manifest.get("checkpoint_id"), label="declared checkpoint ID"
        )
        checkpoint_root = set_root / "checkpoints" / declared_checkpoint_id
        checkpoint_report = verify_sqlite_checkpoint(checkpoint_root)
        if (
            not checkpoint_report.valid
            or checkpoint_report.checkpoint_id is None
            or checkpoint_report.manifest_sha256 is None
            or checkpoint_report.captured_at is None
        ):
            raise StateOnlyBackupError("state-only checkpoint is invalid")
        checkpoint_id = checkpoint_report.checkpoint_id
        captured_at = checkpoint_report.captured_at
        checkpoint = validate_checkpoint_manifest(
            _canonical_read(checkpoint_root / CHECKPOINT_MANIFEST_NAME)
        )
        rm = validate_recovery_manifest(
            _canonical_read(set_root / "recovery_manifest.json")
        )
        rm_hash = manifest_sha256(rm)
        release_id = str(rm["release"]["release_id"])
        release_hash = str(rm["release"]["manifest_sha256"])
        if (
            set_manifest.get("checkpoint_id") != checkpoint_id
            or set_manifest.get("recovery_manifest_sha256") != rm_hash
            or rm["checkpoint"]
            != {
                "checkpoint_id": checkpoint_id,
                "manifest_sha256": checkpoint_report.manifest_sha256,
            }
            or rm["closure"] != base_rm["closure"]
            or rm["restore"] != base_rm["restore"]
            or rm["no_secret_attestation"] != base_rm["no_secret_attestation"]
            or rm["release"] != base_rm["release"]
        ):
            raise StateOnlyBackupError("state-only R/RM/C/static closure differs")
        receipt = validate_receipt(
            _canonical_read(set_root / "checkpoint_receipt.json")
        )
        receipt_id = str(receipt["receipt_id"])
        if (
            set_manifest.get("checkpoint_receipt_sha256") != manifest_sha256(receipt)
            or receipt["release_manifest_sha256"] != release_hash
            or receipt["recovery_manifest_sha256"] != rm_hash
            or receipt["checkpoint_manifest_sha256"]
            != checkpoint_report.manifest_sha256
        ):
            raise StateOnlyBackupError("state-only checkpoint receipt differs")
        release = validate_release_manifest(
            _canonical_read(base / "release" / "release_manifest.json")
        )
        active = ActiveBinding(release_id, release_hash)
        authorize_receipt_append(receipt, observed_active_release=_active_document(active))
        lint_identity_graph(
            active_release=_active_document(active),
            release_manifests=[release],
            checkpoint_manifests=[checkpoint],
            recovery_manifests=[rm],
            receipts=[receipt],
        )
    except Exception:
        errors.append("state_only_recovery_set_validation_failed")
    return StateOnlySetVerification(
        valid=not errors,
        root=set_root,
        checkpoint_root=checkpoint_root,
        checkpoint_id=checkpoint_id,
        captured_at=captured_at,
        release_id=release_id,
        release_manifest_sha256=release_hash,
        recovery_manifest_sha256=rm_hash,
        receipt_id=receipt_id,
        errors=tuple(errors),
    )


def _sets(
    recovery_root: Path,
    *,
    base_reports: dict[Path, RecoveryVerification] | None = None,
) -> list[StateOnlySetVerification]:
    parent = _state_root(recovery_root) / "sets"
    if not parent.exists():
        return []
    return [
        verify_state_only_recovery_set(
            path,
            recovery_root=recovery_root,
            base_reports=base_reports,
        )
        for path in sorted(parent.iterdir())
        if path.is_dir() and not path.name.startswith(".")
    ]


def _append_json(path: Path, value: Mapping[str, object]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    ensure_no_reparse_components(path.parent)
    write_atomic_new_json(path, value)
    return path


def _write_status(root: Path, status: RecoveryProtectionStatus) -> Path:
    target = root / "status" / "recovery_protection_status.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    value = {
        "schema_version": STATUS_SCHEMA,
        "authority": "evidence_only",
        "status": status.status,
        "evaluated_at": _timestamp(status.evaluated_at),
        "last_successful_checkpoint_id": status.last_successful_checkpoint_id,
        "last_successful_captured_at": (
            _timestamp(status.last_successful_captured_at)
            if status.last_successful_captured_at is not None
            else None
        ),
        "checkpoint_age_seconds": status.checkpoint_age_seconds,
        "rpo_seconds": status.rpo_seconds,
        "reason_codes": list(status.reason_codes),
    }
    temporary = target.parent / f".{target.name}.partial-{uuid4().hex}"
    temporary.write_bytes(canonical_manifest_bytes(value))
    os.replace(temporary, target)
    return target


def evaluate_state_only_status(
    *,
    recovery_root: Path,
    now: datetime,
    latest_attempt_succeeded: bool,
    failure_domain_attested: bool,
    current_active: ActiveBinding | None = None,
    active_identity_verified: bool = True,
) -> RecoveryProtectionStatus:
    reports = _sets(recovery_root, base_reports={})
    checkpoints = [
        report.checkpoint_root
        for report in reports
        if (
            report.valid
            and report.checkpoint_root is not None
            and (
                current_active is None
                or (
                    report.release_id == current_active.release_id
                    and report.release_manifest_sha256
                    == current_active.manifest_sha256
                )
            )
        )
    ]
    closure_valid = all(report.valid for report in reports)
    scratch = _state_root(recovery_root) / "tmp"
    scratch.mkdir(parents=True, exist_ok=True)
    ensure_no_reparse_components(scratch)
    if not active_identity_verified:
        evaluated = now.astimezone(UTC)
        status = RecoveryProtectionStatus(
            status="failed",
            evaluated_at=evaluated,
            last_successful_checkpoint_id=None,
            last_successful_captured_at=None,
            checkpoint_age_seconds=None,
            rpo_seconds=RPO.total_seconds(),
            reason_codes=("current_active_identity_unavailable",),
        )
    else:
        status = evaluate_recovery_protection(
            checkpoints,
            now=now,
            rpo=RPO,
            latest_attempt_succeeded=latest_attempt_succeeded,
            closure_valid=closure_valid,
            failure_domain_attested=failure_domain_attested,
            scratch_root=scratch,
        )
    _write_status(_state_root(recovery_root), status)
    return status


def _record_alert(
    root: Path,
    *,
    alert_id: str,
    recorded_at: datetime,
    status: RecoveryProtectionStatus,
    observation: str,
) -> None:
    if status.status == "protected":
        return
    alert = {
        "schema_version": "qrh-recovery-protection-alert/v1",
        "alert_id": _safe_id(alert_id, label="recovery alert ID"),
        "recorded_at": _timestamp(recorded_at),
        "severity": "failed" if status.status == "failed" else "degraded",
        "observation": observation,
        "reason_codes": list(status.reason_codes),
        "contains_secret": False,
    }
    _append_json(root / "alerts" / f"{alert_id}.json", alert)


def _record_pre_run_status(
    root: Path,
    *,
    attempt_id: str,
    active: ActiveBinding,
    status: RecoveryProtectionStatus,
) -> None:
    """Persist an RPO gap before a successful refresh can hide its age."""

    value = {
        "schema_version": "qrh-recovery-protection-observation/v1",
        "observation_id": f"pre-run-{attempt_id}",
        "observed_at": _timestamp(status.evaluated_at),
        "authority": "evidence_only",
        "phase": "before_checkpoint_capture",
        "release_id": active.release_id,
        "release_manifest_sha256": active.manifest_sha256,
        "status": status.status,
        "last_successful_checkpoint_id": status.last_successful_checkpoint_id,
        "last_successful_captured_at": (
            _timestamp(status.last_successful_captured_at)
            if status.last_successful_captured_at is not None
            else None
        ),
        "checkpoint_age_seconds": status.checkpoint_age_seconds,
        "rpo_seconds": status.rpo_seconds,
        "reason_codes": list(status.reason_codes),
    }
    _append_json(
        root / "audit" / "status-observations" / f"pre-run-{attempt_id}.json",
        value,
    )
    _record_alert(
        root,
        alert_id=f"alert-pre-run-{attempt_id}",
        recorded_at=status.evaluated_at,
        status=status,
        observation="before_checkpoint_capture",
    )


def build_gc_roots_report(
    *,
    recovery_root: Path,
    active: ActiveBinding | None,
    report_id: str,
    recorded_at: datetime,
) -> Mapping[str, object]:
    """Conservatively mark every retained R/RM/C/static closure; never delete."""

    release_roots: set[str] = set()
    recovery_roots: set[str] = set()
    checkpoint_roots: set[str] = set()
    closure_roots: set[str] = set()
    base_reports: dict[Path, RecoveryVerification] = {}
    for bundle in recovery_root.glob("cold-recovery-*"):
        if not bundle.is_dir():
            continue
        result = verify_recovery_bundle(bundle)
        base_reports[bundle.resolve(strict=True)] = result
        if not result.valid:
            continue
        if result.release_manifest_sha256:
            release_roots.add(result.release_manifest_sha256)
        if result.recovery_manifest_sha256:
            recovery_roots.add(result.recovery_manifest_sha256)
        if result.checkpoint_manifest_sha256:
            checkpoint_roots.add(result.checkpoint_manifest_sha256)
        manifest = validate_recovery_manifest(
            _canonical_read(bundle / "recovery_manifest.json")
        )
        closure_roots.add(str(manifest["closure"]["inventory_sha256"]))
    for result in _sets(recovery_root, base_reports=base_reports):
        if not result.valid or result.checkpoint_root is None:
            continue
        checkpoint = verify_sqlite_checkpoint(result.checkpoint_root)
        if checkpoint.manifest_sha256:
            checkpoint_roots.add(checkpoint.manifest_sha256)
        if result.release_manifest_sha256:
            release_roots.add(result.release_manifest_sha256)
        if result.recovery_manifest_sha256:
            recovery_roots.add(result.recovery_manifest_sha256)
        rm = validate_recovery_manifest(
            _canonical_read(result.root / "recovery_manifest.json")
        )
        closure_roots.add(str(rm["closure"]["inventory_sha256"]))
    intake = recovery_root / "checkpoint-intake"
    if intake.is_dir():
        for path in intake.iterdir():
            if not path.is_dir():
                continue
            checkpoint = verify_sqlite_checkpoint(path)
            if checkpoint.valid and checkpoint.manifest_sha256:
                # Failed attempts are not valid recovery protection, but their
                # immutable C remains conservatively retained for audit until
                # a separately reviewed retention policy authorizes cleanup.
                checkpoint_roots.add(checkpoint.manifest_sha256)
    if active is not None:
        release_roots.add(active.manifest_sha256)
    return {
        "schema_version": GC_ROOTS_SCHEMA,
        "report_id": _safe_id(report_id, label="GC roots report ID"),
        "recorded_at": _timestamp(recorded_at),
        "authority": "retention_evidence_only",
        "active_release_manifest_sha256": (
            active.manifest_sha256 if active is not None else None
        ),
        "retained_release_roots": sorted(release_roots),
        "retained_recovery_manifest_roots": sorted(recovery_roots),
        "retained_checkpoint_roots": sorted(checkpoint_roots),
        "retained_static_closure_roots": sorted(closure_roots),
        "deletion_authorized": False,
    }


def _record_attempt(
    root: Path,
    *,
    attempt_id: str,
    started_at: datetime,
    finished_at: datetime,
    active: ActiveBinding | None,
    checkpoint_id: str | None,
    set_id: str | None,
    succeeded: bool,
    error_code: str | None,
    status: RecoveryProtectionStatus,
) -> None:
    value = {
        "schema_version": ATTEMPT_SCHEMA,
        "attempt_id": attempt_id,
        "started_at": _timestamp(started_at),
        "finished_at": _timestamp(finished_at),
        "authority": "evidence_only",
        "release_manifest_sha256": (
            active.manifest_sha256 if active is not None else None
        ),
        "checkpoint_id": checkpoint_id,
        "recovery_set_id": set_id,
        "succeeded": succeeded,
        "error_code": error_code,
        "recovery_protection_status": status.status,
        "reason_codes": list(status.reason_codes),
    }
    _append_json(root / "audit" / "attempts" / f"{attempt_id}.json", value)
    log = root / "logs" / "state-only-backup.jsonl"
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("ab") as stream:
        stream.write(canonical_manifest_bytes(value) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    _record_alert(
        root,
        alert_id=f"alert-{attempt_id}",
        recorded_at=finished_at,
        status=status,
        observation="after_checkpoint_attempt",
    )


def _latest_attempt_succeeded(root: Path) -> bool:
    attempts = root / "audit" / "attempts"
    if not attempts.is_dir():
        return False
    values: list[tuple[datetime, bool]] = []
    for path in attempts.glob("*.json"):
        try:
            value = _canonical_read(path)
            if value.get("schema_version") != ATTEMPT_SCHEMA or not isinstance(
                value.get("succeeded"), bool
            ):
                continue
            values.append(
                (_parse_timestamp(value.get("finished_at")), bool(value["succeeded"]))
            )
        except Exception:
            return False
    return max(values, key=lambda item: item[0])[1] if values else False


def run_state_only_backup(
    *,
    config: RuntimePublishConfig,
    vm: StateOnlyVM,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    id_factory: Callable[[], str] = lambda: uuid4().hex,
) -> StateOnlyRunResult:
    recovery_root = config.recovery.recovery_root.resolve(strict=True)
    ensure_no_reparse_components(recovery_root)
    root = _state_root(recovery_root)
    root.mkdir(parents=True, exist_ok=True)
    started_at = now().astimezone(UTC)
    attempt_id = _safe_id(
        f"state-only-{started_at.strftime('%Y%m%dT%H%M%S')}-{id_factory()[:12]}",
        label="backup attempt ID",
    )
    checkpoint_id: str | None = None
    set_id: str | None = None
    active: ActiveBinding | None = None
    succeeded = False
    error_code: str | None = None
    cleanup_needed = False
    active_identity_verified = False
    with _job_lock(root), _controlled_environment(root, attempt_id):
        try:
            RecoveryProtectionCoordinator(
                config.recovery, actions=UnavailableRecoveryActions(), now=now
            ).preflight()
            active = _binding(vm.read_active_identity())
            active_identity_verified = True
            pre_run_status = evaluate_state_only_status(
                recovery_root=recovery_root,
                now=started_at,
                latest_attempt_succeeded=_latest_attempt_succeeded(root),
                failure_domain_attested=True,
                current_active=active,
                active_identity_verified=True,
            )
            _record_pre_run_status(
                root,
                attempt_id=attempt_id,
                active=active,
                status=pre_run_status,
            )
            base = select_static_bundle(recovery_root, active=active)
            checkpoint_id = _safe_id(
                f"checkpoint-{active.manifest_sha256[:20]}-{id_factory()[:12]}",
                label="checkpoint ID",
            )
            cleanup_needed = True
            checkpoint_root = vm.capture_state_only_checkpoint(
                release_id=active.release_id,
                release_manifest_sha256=active.manifest_sha256,
                checkpoint_id=checkpoint_id,
            )
            observed = _binding(vm.read_active_identity())
            if observed != active:
                active_identity_verified = False
                raise StateOnlyBackupError("active authority changed during state-only capture")
            recovery_set = build_state_only_recovery_set(
                recovery_root=recovery_root,
                base_bundle_root=base,
                checkpoint_root=checkpoint_root,
                active=active,
                attestation_sha256=_attestation_sha(config),
                recorded_at=now().astimezone(UTC),
            )
            set_id = recovery_set.name
            intake_parent = (recovery_root / "checkpoint-intake").resolve(strict=True)
            downloaded = checkpoint_root.resolve(strict=True)
            if downloaded.parent != intake_parent or downloaded.name != checkpoint_id:
                raise StateOnlyBackupError("downloaded checkpoint intake path differs")
            ensure_no_reparse_components(downloaded)
            shutil.rmtree(downloaded)
            succeeded = True
        except Exception as error:
            error_code = (
                "state_only_backup_locked"
                if isinstance(error, StateOnlyBackupLocked)
                else "state_only_backup_failed"
            )
        finally:
            if cleanup_needed and checkpoint_id is not None:
                try:
                    vm.cleanup_state_only_capture(checkpoint_id=checkpoint_id)
                except Exception:
                    succeeded = False
                    error_code = "vm_staging_cleanup_failed"

        finished_at = now().astimezone(UTC)
        try:
            RecoveryProtectionCoordinator(
                config.recovery, actions=UnavailableRecoveryActions(), now=now
            ).preflight()
            attested = True
        except Exception:
            attested = False
        if active is None:
            try:
                active = _binding(vm.read_active_identity())
                active_identity_verified = True
            except Exception:
                active_identity_verified = False
        status = evaluate_state_only_status(
            recovery_root=recovery_root,
            now=finished_at,
            latest_attempt_succeeded=succeeded,
            failure_domain_attested=attested,
            current_active=active,
            active_identity_verified=active_identity_verified,
        )
        gc = build_gc_roots_report(
            recovery_root=recovery_root,
            active=active,
            report_id=f"gc-roots-{attempt_id}",
            recorded_at=finished_at,
        )
        _append_json(root / "audit" / "gc-roots" / f"{attempt_id}.json", gc)
        _record_attempt(
            root,
            attempt_id=attempt_id,
            started_at=started_at,
            finished_at=finished_at,
            active=active,
            checkpoint_id=checkpoint_id,
            set_id=set_id,
            succeeded=succeeded,
            error_code=error_code,
            status=status,
        )
    return StateOnlyRunResult(
        attempt_id=attempt_id,
        checkpoint_id=checkpoint_id,
        recovery_set_id=set_id,
        status=status,
        succeeded=succeeded,
        error_code=error_code,
    )


def build_task_candidate(
    *,
    config_path: Path,
    project_root: Path,
    operational_python: Path,
) -> Mapping[str, object]:
    for path, label in (
        (config_path, "config"),
        (project_root, "project root"),
        (operational_python, "operational Python"),
    ):
        if not path.is_absolute():
            raise StateOnlyBackupError(f"scheduled task {label} must be absolute")
    arguments = (
        "-I", "-B", "-m", "quant_hub.ops.state_only_backup", "run",
        "--config", str(config_path), "--project-root", str(project_root),
    )
    body: dict[str, object] = {
        "schema_version": TASK_CANDIDATE_SCHEMA,
        "task_identity": TASK_IDENTITY,
        "host_role": "developer_recovery_host",
        "schedule": {
            "kind": "daily",
            "days_interval": 1,
            "start_local": "03:00:00",
            "start_when_available": True,
            "multiple_instances": "ignore_new",
            "retry_count": 3,
            "retry_interval_minutes": 15,
        },
        "principal": {
            "logon_type": "s4u_no_stored_password",
            "run_level": "limited",
        },
        "action": {
            "executable": str(operational_python),
            "arguments": list(arguments),
            "working_directory": str(config_path.parent),
        },
        "network_required": True,
        "credential_material_embedded": False,
        "vm_task_registration": False,
    }
    body["contract_sha256"] = manifest_sha256(body)
    return body


def validate_task_candidate(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "task_identity", "host_role", "schedule",
        "principal", "action", "network_required",
        "credential_material_embedded", "vm_task_registration", "contract_sha256",
    }:
        raise StateOnlyBackupError("scheduled task candidate schema is not closed")
    candidate = dict(value)
    claimed = candidate.pop("contract_sha256")
    if (
        candidate.get("schema_version") != TASK_CANDIDATE_SCHEMA
        or candidate.get("task_identity") != TASK_IDENTITY
        or candidate.get("host_role") != "developer_recovery_host"
        or candidate.get("network_required") is not True
        or candidate.get("credential_material_embedded") is not False
        or candidate.get("vm_task_registration") is not False
        or claimed != manifest_sha256(candidate)
    ):
        raise StateOnlyBackupError("scheduled task candidate identity differs")
    if candidate.get("schedule") != {
        "kind": "daily",
        "days_interval": 1,
        "start_local": "03:00:00",
        "start_when_available": True,
        "multiple_instances": "ignore_new",
        "retry_count": 3,
        "retry_interval_minutes": 15,
    } or candidate.get("principal") != {
        "logon_type": "s4u_no_stored_password",
        "run_level": "limited",
    }:
        raise StateOnlyBackupError("scheduled task policy differs")
    action = candidate.get("action")
    if not isinstance(action, dict) or set(action) != {
        "executable", "arguments", "working_directory"
    }:
        raise StateOnlyBackupError("scheduled task action is invalid")
    arguments = action.get("arguments")
    if (
        not isinstance(arguments, list)
        or len(arguments) != 9
        or arguments[:5]
        != ["-I", "-B", "-m", "quant_hub.ops.state_only_backup", "run"]
        or arguments[5] != "--config"
        or arguments[7] != "--project-root"
        or any(not isinstance(item, str) for item in arguments)
    ):
        raise StateOnlyBackupError("scheduled task fixed argv differs")
    executable = Path(str(action.get("executable")))
    config_path = Path(arguments[6])
    project_root = Path(arguments[8])
    working_directory = Path(str(action.get("working_directory")))
    if (
        not executable.is_absolute()
        or executable.name.casefold() != "python.exe"
        or not config_path.is_absolute()
        or not project_root.is_absolute()
        or not working_directory.is_absolute()
        or working_directory != config_path.parent
    ):
        raise StateOnlyBackupError("scheduled task path contract differs")
    return value


def apply_task_candidate(
    candidate: object,
    *,
    adapter: TaskSchedulerAdapter,
    allow_os_registration: bool,
) -> str:
    value = validate_task_candidate(candidate)
    if not allow_os_registration:
        raise StateOnlyBackupError("Task Scheduler apply requires explicit opt-in")
    current = adapter.inspect(value)
    if current == value["contract_sha256"]:
        return "unchanged"
    adapter.register(value)
    if adapter.inspect(value) != value["contract_sha256"]:
        raise StateOnlyBackupError("Task Scheduler registration does not match candidate")
    return "applied"


class PowerShellTaskSchedulerAdapter:
    """One developer-host task, registered without a password or embedded secret."""

    @staticmethod
    def _literal(value: object) -> str:
        return "'" + str(value).replace("'", "''") + "'"

    @staticmethod
    def _run(script: str) -> subprocess.CompletedProcess[str]:
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        return subprocess.run(
            (
                "powershell.exe", "-NoProfile", "-NonInteractive",
                "-EncodedCommand", encoded,
            ),
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

    def inspect(self, candidate: Mapping[str, object]) -> str | None:
        validate_task_candidate(candidate)
        action = candidate["action"]
        assert isinstance(action, Mapping)
        arguments = subprocess.list2cmdline(list(action["arguments"]))
        expected = str(candidate["contract_sha256"])
        script = (
            "$ErrorActionPreference='Stop';"
            "$t=Get-ScheduledTask -TaskPath '\\QuantResearchHub\\' "
            "-TaskName 'StateOnlyBackup' -ErrorAction SilentlyContinue;"
            "if($null-eq$t){Write-Output 'missing';exit 0};"
            "$a=@($t.Actions);$g=@($t.Triggers);"
            "$ok=($a.Count-eq 1-and$g.Count-eq 1-and"
            f"$a[0].Execute-eq{self._literal(action['executable'])}-and"
            f"$a[0].Arguments-eq{self._literal(arguments)}-and"
            f"$a[0].WorkingDirectory-eq{self._literal(action['working_directory'])}-and"
            f"$t.Description-eq{self._literal('QRH_STATE_ONLY_CONTRACT:'+expected)}-and"
            "$t.Principal.LogonType-eq'S4U'-and"
            "$t.Principal.RunLevel-eq'Limited'-and"
            "$g[0].DaysInterval-eq 1-and"
            "$t.Settings.StartWhenAvailable-eq$true-and"
            "$t.Settings.MultipleInstances-eq'IgnoreNew'-and"
            "[string]$t.Settings.ExecutionTimeLimit-eq'PT2H'-and"
            "$t.Settings.RestartCount-eq 3-and"
            "[string]$t.Settings.RestartInterval-eq'PT15M');"
            "if($ok){Write-Output 'exact'}else{Write-Output 'drift'}"
        )
        result = self._run(script)
        if result.returncode != 0:
            raise StateOnlyBackupError("cannot inspect developer Task Scheduler")
        verdict = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
        if verdict == "missing":
            return None
        return expected if verdict == "exact" else "drift"

    def register(self, candidate: Mapping[str, object]) -> None:
        validate_task_candidate(candidate)
        action = candidate["action"]
        assert isinstance(action, Mapping)
        arguments = subprocess.list2cmdline(list(action["arguments"]))
        contract = str(candidate["contract_sha256"])
        script = (
            "$ErrorActionPreference='Stop';"
            f"$a=New-ScheduledTaskAction -Execute {self._literal(action['executable'])} "
            f"-Argument {self._literal(arguments)} "
            f"-WorkingDirectory {self._literal(action['working_directory'])};"
            "$g=New-ScheduledTaskTrigger -Daily -At '03:00';"
            "$p=New-ScheduledTaskPrincipal -UserId "
            "($env:USERDOMAIN+'\\'+$env:USERNAME) -LogonType S4U -RunLevel Limited;"
            "$s=New-ScheduledTaskSettingsSet -StartWhenAvailable "
            "-MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 2) "
            "-RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 15);"
            f"$d={self._literal('QRH_STATE_ONLY_CONTRACT:'+contract)};"
            "$t=New-ScheduledTask -Action $a -Trigger $g -Principal $p -Settings $s "
            "-Description $d;"
            "Register-ScheduledTask -TaskPath '\\QuantResearchHub\\' "
            "-TaskName 'StateOnlyBackup' -InputObject $t -Force|Out-Null"
        )
        result = self._run(script)
        if result.returncode != 0:
            raise StateOnlyBackupError("developer Task Scheduler registration failed")


def _result_payload(result: StateOnlyRunResult) -> Mapping[str, object]:
    return {
        "schema_version": "qrh-state-only-backup-result/v1",
        "attempt_id": result.attempt_id,
        "checkpoint_id": result.checkpoint_id,
        "recovery_set_id": result.recovery_set_id,
        "succeeded": result.succeeded,
        "error_code": result.error_code,
        "recovery_protection_status": result.status.status,
        "reason_codes": list(result.status.reason_codes),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "status", "schedule-candidate", "schedule-apply"):
        sub = commands.add_parser(name)
        sub.add_argument("--config", type=Path, required=True)
        sub.add_argument("--project-root", type=Path, required=True)
        if name == "schedule-apply":
            sub.add_argument("--allow-os-registration", action="store_true")
    args = parser.parse_args(argv)
    config = RuntimePublishConfig.load(
        args.config, expected_project_root=args.project_root
    )
    if args.command == "run":
        actions = OpenSSHRecoveryActions(config)
        result = run_state_only_backup(config=config, vm=actions)
        print(json.dumps(_result_payload(result), ensure_ascii=False, sort_keys=True))
        return 0 if result.succeeded and result.status.status == "protected" else 2
    if args.command == "status":
        active: ActiveBinding | None = None
        active_identity_verified = False
        try:
            RecoveryProtectionCoordinator(
                config.recovery, actions=UnavailableRecoveryActions()
            ).preflight()
            attested = True
        except Exception:
            attested = False
        try:
            active = _binding(OpenSSHRecoveryActions(config).read_active_identity())
            active_identity_verified = True
        except Exception:
            active_identity_verified = False
        status = evaluate_state_only_status(
            recovery_root=config.recovery.recovery_root,
            now=datetime.now(UTC),
            latest_attempt_succeeded=_latest_attempt_succeeded(
                _state_root(config.recovery.recovery_root)
            ),
            failure_domain_attested=attested,
            current_active=active,
            active_identity_verified=active_identity_verified,
        )
        print(json.dumps({"status": status.status, "reason_codes": status.reason_codes}))
        return 0 if status.status == "protected" else 2
    python = config.recovery.operational_root / "tooling" / "python" / "python.exe"
    candidate = build_task_candidate(
        config_path=args.config.resolve(strict=True),
        project_root=args.project_root.resolve(strict=True),
        operational_python=python,
    )
    candidate_path = (
        _state_root(config.recovery.recovery_root)
        / "control"
        / "scheduled_task_candidate.json"
    )
    if args.command == "schedule-candidate":
        candidate_path.parent.mkdir(parents=True, exist_ok=True)
        if candidate_path.exists():
            existing = _canonical_read(candidate_path)
            if existing != candidate:
                temporary = candidate_path.parent / f".{candidate_path.name}.partial-{uuid4().hex}"
                temporary.write_bytes(canonical_manifest_bytes(candidate))
                os.replace(temporary, candidate_path)
        else:
            write_atomic_new_json(candidate_path, candidate)
        print(json.dumps(candidate, ensure_ascii=False, sort_keys=True))
        return 0
    outcome = apply_task_candidate(
        candidate,
        adapter=PowerShellTaskSchedulerAdapter(),
        allow_os_registration=args.allow_os_registration,
    )
    print(json.dumps({"task_identity": TASK_IDENTITY, "status": outcome}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ActiveBinding",
    "GC_ROOTS_SCHEMA",
    "PowerShellTaskSchedulerAdapter",
    "STATE_SET_SCHEMA",
    "STATUS_SCHEMA",
    "StateOnlyBackupError",
    "StateOnlyBackupLocked",
    "StateOnlyRunResult",
    "StateOnlySetVerification",
    "TASK_CANDIDATE_SCHEMA",
    "TASK_IDENTITY",
    "TaskSchedulerAdapter",
    "apply_task_candidate",
    "build_gc_roots_report",
    "build_state_only_recovery_set",
    "build_task_candidate",
    "evaluate_state_only_status",
    "main",
    "run_state_only_backup",
    "select_static_bundle",
    "validate_task_candidate",
    "verify_state_only_recovery_set",
]
