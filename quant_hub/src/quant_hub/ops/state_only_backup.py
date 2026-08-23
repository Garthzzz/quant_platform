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
import xml.etree.ElementTree as ET

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
from .publish import PublishError
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
from .failure_domain_authority import require_failure_domain_authority
from .failure_domain import (
    FailureDomainError,
    collect_host_facts,
    rebuild_legacy_attestation_diagnostic,
)
from .stage_closure import (
    DirectoryEvidenceResolver,
    StageClosureError,
    artifact_ref,
    verify_measured_prior_binding,
)


STATE_SET_SCHEMA = "qrh-state-only-recovery-set/v1"
STATIC_REF_SCHEMA = "qrh-state-only-static-closure-ref/v1"
ATTEMPT_SCHEMA = "qrh-state-only-backup-attempt/v1"
STATUS_SCHEMA = "qrh-recovery-protection-status/v1"
GC_ROOTS_SCHEMA = "qrh-recovery-gc-roots/v2"
TASK_AUTHORITY_SCHEMA = "qrh-state-only-scheduled-task-authority/v1"
TASK_CANDIDATE_SCHEMA = "qrh-state-only-scheduled-task/v5-raw-xml-bound"
TASK_INSPECTION_SCHEMA = "qrh-state-only-task-inspection/v2-raw-xml"
TASK_XML_PROJECTION_SCHEMA = "qrh-state-only-task-xml-projection/v1"
TASK_IDENTITY = r"\QuantResearchHub\StateOnlyBackup"
TASK_AUTHORITY_LOCATOR = "state-only/control/scheduled_task_authority.json"
TASK_XML_NAMESPACE = "http://schemas.microsoft.com/windows/2004/02/mit/task"
TASK_XML_VERSION = "1.4"
TASK_XML_PRINCIPAL_ID = "Author"
RPO = timedelta(hours=24)

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$"
)


class StateOnlyBackupError(RuntimeError):
    """State-only backup cannot prove a safe recovery point."""


class StateOnlyBackupLocked(StateOnlyBackupError):
    """The one permitted state-only job already owns its lock."""


class MeasuredPriorUnavailable(StateOnlyBackupError):
    """The daily GC gate cannot bind an actually measured retained prior."""


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


@dataclass(frozen=True)
class TaskInspection:
    status: str
    contract_sha256: str | None
    task_xml_sha256: str | None
    principal_sid_sha256: str | None
    task_xml_base64: str | None


@dataclass(frozen=True)
class TaskApplyResult:
    status: str
    inspection: TaskInspection


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
    def inspect(self, candidate: Mapping[str, object]) -> TaskInspection: ...

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


def measured_prior_binding_path(recovery_root: Path) -> Path:
    """Return the one fixed off-host input used by conservative GC."""

    return _state_root(recovery_root) / "control" / "measured_prior_release.json"


def load_measured_prior_binding(
    recovery_root: Path, *, active: ActiveBinding
) -> tuple[ActiveBinding, str]:
    """Load a canonical prior proven by an actual D-prior rollback observation."""

    path = measured_prior_binding_path(recovery_root)
    try:
        value = verify_measured_prior_binding(
            _canonical_read(path), resolver=DirectoryEvidenceResolver(recovery_root)
        )
    except (OSError, StageClosureError, StateOnlyBackupError) as error:
        raise MeasuredPriorUnavailable("measured D-prior binding is unavailable") from error
    measured_active_value = value["active_release"]
    assert isinstance(measured_active_value, Mapping)
    measured_active = ActiveBinding(
        _safe_id(measured_active_value.get("release_id"), label="measured active ID"),
        _sha(
            measured_active_value.get("manifest_sha256"),
            label="measured active manifest hash",
        ),
    )
    if measured_active != active:
        raise MeasuredPriorUnavailable(
            "measured D-prior binding is stale for current active"
        )
    prior_value = value["prior_release"]
    assert isinstance(prior_value, Mapping)
    prior = ActiveBinding(
        _safe_id(prior_value.get("release_id"), label="measured prior ID"),
        _sha(
            prior_value.get("manifest_sha256"),
            label="measured prior manifest hash",
        ),
    )
    try:
        select_static_bundle(recovery_root, active=prior)
    except StateOnlyBackupError as error:
        raise MeasuredPriorUnavailable(
            "measured D-prior has no retained verified closure"
        ) from error
    return prior, _sha(value["binding_sha256"], label="measured prior binding hash")


@contextmanager
def _job_lock(root: Path) -> Iterator[bool]:
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
    acquired = False
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
            except OSError:
                yield False
                return
        else:
            import fcntl

            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                yield False
                return
        acquired = True
        os.ftruncate(descriptor, 0)
        os.lseek(descriptor, 0, os.SEEK_SET)
        with os.fdopen(os.dup(descriptor), "w", encoding="ascii", newline="\n") as stream:
            stream.write(token + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        yield True
    finally:
        if acquired:
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
        if acquired:
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
    require_failure_domain_authority()
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


def _record_lock_conflict(
    root: Path, *, attempt_id: str, observed_at: datetime
) -> RecoveryProtectionStatus:
    """Record scheduler overlap without entering the single-writer job body."""

    status = RecoveryProtectionStatus(
        status="failed",
        evaluated_at=observed_at.astimezone(UTC),
        last_successful_checkpoint_id=None,
        last_successful_captured_at=None,
        checkpoint_age_seconds=None,
        rpo_seconds=RPO.total_seconds(),
        reason_codes=("state_only_backup_locked",),
    )
    observation = {
        "schema_version": "qrh-state-only-lock-conflict/v1",
        "observation_id": f"lock-conflict-{attempt_id}",
        "observed_at": _timestamp(observed_at),
        "authority": "evidence_only",
        "attempt_id": attempt_id,
        "status": "failed",
        "reason_codes": ["state_only_backup_locked"],
        "contains_secret": False,
    }
    _append_json(
        root / "audit" / "lock-conflicts" / f"{attempt_id}.json", observation
    )
    _record_alert(
        root,
        alert_id=f"alert-lock-conflict-{attempt_id}",
        recorded_at=observed_at,
        status=status,
        observation="scheduler_lock_conflict",
    )
    return status


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
    active: ActiveBinding,
    measured_prior: ActiveBinding,
    measured_prior_binding_sha256: str,
    report_id: str,
    recorded_at: datetime,
) -> Mapping[str, object]:
    """Mark retained roots, including an explicitly measured D-prior; never delete."""

    if active == measured_prior:
        raise StateOnlyBackupError("measured D-prior must differ from active")
    binding_sha256 = _sha(
        measured_prior_binding_sha256, label="measured prior binding hash"
    )

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
    if measured_prior.manifest_sha256 not in release_roots:
        raise StateOnlyBackupError("measured D-prior is not present in retained closures")
    release_roots.add(active.manifest_sha256)
    return {
        "schema_version": GC_ROOTS_SCHEMA,
        "report_id": _safe_id(report_id, label="GC roots report ID"),
        "recorded_at": _timestamp(recorded_at),
        "authority": "retention_evidence_only",
        "active_release_manifest_sha256": active.manifest_sha256,
        "measured_prior_release_manifest_sha256": measured_prior.manifest_sha256,
        "measured_prior_binding_sha256": binding_sha256,
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
    require_failure_domain_authority()
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
    measured_prior: ActiveBinding | None = None
    measured_prior_sha256: str | None = None
    succeeded = False
    error_code: str | None = None
    cleanup_needed = False
    active_identity_verified = False
    with _job_lock(root) as lock_acquired, _controlled_environment(root, attempt_id):
        if not lock_acquired:
            status = _record_lock_conflict(
                root, attempt_id=attempt_id, observed_at=now().astimezone(UTC)
            )
            return StateOnlyRunResult(
                attempt_id=attempt_id,
                checkpoint_id=None,
                recovery_set_id=None,
                status=status,
                succeeded=False,
                error_code="state_only_backup_locked",
            )
        try:
            RecoveryProtectionCoordinator(
                config.recovery, actions=UnavailableRecoveryActions(), now=now
            ).preflight()
            active = _binding(vm.read_active_identity())
            active_identity_verified = True
            measured_prior, measured_prior_sha256 = load_measured_prior_binding(
                recovery_root, active=active
            )
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
                "measured_prior_unavailable"
                if isinstance(error, MeasuredPriorUnavailable)
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
        if (
            active is not None
            and measured_prior is not None
            and measured_prior_sha256 is not None
        ):
            try:
                gc = build_gc_roots_report(
                    recovery_root=recovery_root,
                    active=active,
                    measured_prior=measured_prior,
                    measured_prior_binding_sha256=measured_prior_sha256,
                    report_id=f"gc-roots-{attempt_id}",
                    recorded_at=finished_at,
                )
                _append_json(root / "audit" / "gc-roots" / f"{attempt_id}.json", gc)
            except StateOnlyBackupError:
                succeeded = False
                error_code = "gc_roots_measured_prior_failed"
                status = evaluate_state_only_status(
                    recovery_root=recovery_root,
                    now=finished_at,
                    latest_attempt_succeeded=False,
                    failure_domain_attested=attested,
                    current_active=active,
                    active_identity_verified=active_identity_verified,
                )
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


def _current_principal_identity_sha256() -> str:
    # Kept only as an internal v2 compatibility alias.  It delegates to the
    # v3 process-token SID authority rather than environment account aliases.
    return _current_token_sid_sha256()


def _legacy_build_task_candidate_v2(
    *,
    config_path: Path,
    project_root: Path,
    operational_python: Path,
    principal_identity_sha256: str | None = None,
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
    principal_hash = (
        _sha(principal_identity_sha256, label="scheduled task principal identity")
        if principal_identity_sha256 is not None
        else _current_principal_identity_sha256()
    )
    body: dict[str, object] = {
        "schema_version": TASK_CANDIDATE_SCHEMA,
        "task_identity": TASK_IDENTITY,
        "host_role": "developer_recovery_host",
        "schedule": {
            "kind": "daily",
            "days_interval": 1,
            "start_local": "03:00:00",
            "timezone": "recovery_host_local_floating",
            "enabled": True,
            "start_when_available": True,
            "run_only_if_network_available": True,
            "multiple_instances": "ignore_new",
            "execution_time_limit": "PT2H",
            "retry_count": 3,
            "retry_interval_minutes": 15,
        },
        "principal": {
            "logon_type": "s4u_no_stored_password",
            "run_level": "limited",
            "identity_sha256": principal_hash,
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


def _legacy_validate_task_candidate_v2(value: object) -> Mapping[str, object]:
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
        "timezone": "recovery_host_local_floating",
        "enabled": True,
        "start_when_available": True,
        "run_only_if_network_available": True,
        "multiple_instances": "ignore_new",
        "execution_time_limit": "PT2H",
        "retry_count": 3,
        "retry_interval_minutes": 15,
    } or candidate.get("principal") != {
        "logon_type": "s4u_no_stored_password",
        "run_level": "limited",
        "identity_sha256": candidate.get("principal", {}).get("identity_sha256")
        if isinstance(candidate.get("principal"), dict)
        else None,
    }:
        raise StateOnlyBackupError("scheduled task policy differs")
    principal = candidate["principal"]
    assert isinstance(principal, dict)
    _sha(principal["identity_sha256"], label="scheduled task principal identity")
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


def _legacy_validate_task_inspection_v2(value: object) -> TaskInspection:
    if not isinstance(value, TaskInspection) or value.status not in {
        "missing",
        "exact",
        "drift",
    }:
        raise StateOnlyBackupError("Task Scheduler inspection contract is invalid")
    if value.contract_sha256 is not None:
        _sha(value.contract_sha256, label="inspected task contract hash")
    if value.task_xml_sha256 is not None:
        _sha(value.task_xml_sha256, label="inspected task XML hash")
    if value.status == "missing" and (
        value.contract_sha256 is not None or value.task_xml_sha256 is not None
    ):
        raise StateOnlyBackupError("missing Task Scheduler inspection has identities")
    if value.status != "missing" and value.task_xml_sha256 is None:
        raise StateOnlyBackupError("existing Task Scheduler inspection lacks XML identity")
    if value.status == "exact" and value.contract_sha256 is None:
        raise StateOnlyBackupError("exact Task Scheduler inspection lacks contract identity")
    return value


def _legacy_apply_task_candidate_v2(
    candidate: object,
    *,
    adapter: TaskSchedulerAdapter,
    allow_os_registration: bool,
) -> TaskApplyResult:
    value = validate_task_candidate(candidate)
    if not allow_os_registration:
        raise StateOnlyBackupError("Task Scheduler apply requires explicit opt-in")
    current = _validate_task_inspection(adapter.inspect(value))
    if (
        current.status == "exact"
        and current.contract_sha256 == value["contract_sha256"]
    ):
        return TaskApplyResult(status="unchanged", inspection=current)
    adapter.register(value)
    observed = _validate_task_inspection(adapter.inspect(value))
    if (
        observed.status != "exact"
        or observed.contract_sha256 != value["contract_sha256"]
    ):
        raise StateOnlyBackupError("Task Scheduler registration does not match candidate")
    return TaskApplyResult(status="applied", inspection=observed)


class _LegacyPowerShellTaskSchedulerAdapterV2:
    """Removed mixed-observation adapter; retained only as an explicit tombstone."""

    def inspect(self, candidate: Mapping[str, object]) -> TaskInspection:
        raise StateOnlyBackupError(
            "legacy mixed Task Scheduler inspection is removed"
        )

    def register(self, candidate: Mapping[str, object]) -> None:
        raise StateOnlyBackupError(
            "legacy mixed Task Scheduler registration is removed"
        )


# v3 closes the v2 candidate's self-reported host, executable and XML gaps.
def _strict_existing_path(path: Path, *, kind: str, label: str) -> Path:
    try:
        resolved = Path(path).resolve(strict=True)
        ensure_no_reparse_components(resolved)
    except (OSError, ValueError) as error:
        raise StateOnlyBackupError(f"scheduled task {label} is not a strict path") from error
    if (kind == "file" and not resolved.is_file()) or (
        kind == "directory" and not resolved.is_dir()
    ):
        raise StateOnlyBackupError(f"scheduled task {label} kind differs")
    return resolved


def _normalize_windows_sid(value: object) -> str:
    """Canonicalize the decimal SID form emitted by Task Scheduler XML."""

    if not isinstance(value, str):
        raise StateOnlyBackupError("Windows SID is invalid")
    raw = value.strip()
    if re.fullmatch(r"S-\d+(?:-\d+){2,16}", raw, re.IGNORECASE) is None:
        raise StateOnlyBackupError("Windows SID is invalid")
    numbers = [int(part, 10) for part in raw.split("-")[1:]]
    revision, identifier_authority, *subauthorities = numbers
    if (
        not 0 <= revision <= 255
        or not 0 <= identifier_authority < 2**48
        or not 1 <= len(subauthorities) <= 15
        or any(not 0 <= item < 2**32 for item in subauthorities)
    ):
        raise StateOnlyBackupError("Windows SID is outside canonical bounds")
    return "S-" + "-".join(str(item) for item in numbers)


def _current_token_sid_sha256() -> str:
    """Hash the effective process-token SID; environment names are not authority."""

    if os.name != "nt":
        raise StateOnlyBackupError("Windows process-token SID is unavailable")
    script = (
        "$ErrorActionPreference='Stop';"
        "$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;"
        "Write-Output $sid"
    )
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    result = subprocess.run(
        ("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded),
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    sid = result.stdout.strip().splitlines()[-1] if result.returncode == 0 and result.stdout.strip() else ""
    try:
        normalized = _normalize_windows_sid(sid)
    except StateOnlyBackupError as error:
        raise StateOnlyBackupError("Windows process-token SID is invalid") from error
    return hashlib.sha256(normalized.encode("ascii")).hexdigest()


def _load_scheduler_attestation(
    *, recovery_root: Path, attestation_path: Path
) -> tuple[Mapping[str, object], str, Path, Path]:
    require_failure_domain_authority()
    recovery = _strict_existing_path(recovery_root, kind="directory", label="recovery root")
    attestation_file = _strict_existing_path(
        attestation_path, kind="file", label="failure-domain attestation"
    )
    if attestation_file.parent != recovery and recovery not in attestation_file.parents:
        raise StateOnlyBackupError("scheduler attestation is outside recovery root")
    raw = attestation_file.read_bytes()
    try:
        document = json.loads(raw.decode("utf-8"))
        if canonical_manifest_bytes(document) != raw:
            raise StateOnlyBackupError("scheduler attestation is not canonical JSON")
        if not isinstance(document, dict):
            raise StateOnlyBackupError("scheduler attestation is not an object")
        claimed = document.get("attestation_sha256")
        material = dict(document)
        material.pop("attestation_sha256", None)
        attestation = rebuild_legacy_attestation_diagnostic(
            production_facts=document["production"],
            recovery_facts=document["recovery"],
            independence_probe=document["independence_probe"],
            observed_at=str(document["observed_at"]),
        )
        if (
            attestation.authority
            or attestation.status != "DIAGNOSTIC_ONLY"
            or (claimed is not None and claimed != attestation.sha256)
            or material != attestation.payload
        ):
            raise StateOnlyBackupError("scheduler legacy diagnostic identity differs")
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, FailureDomainError) as error:
        raise StateOnlyBackupError("scheduler failure-domain diagnostic failed") from error
    recovery_facts = attestation.payload["recovery"]
    assert isinstance(recovery_facts, Mapping)
    try:
        actual = collect_host_facts(
            recovery,
            role="recovery",
            tool_version=str(recovery_facts["tool_version"]),
        )
    except FailureDomainError as error:
        raise StateOnlyBackupError("scheduler recovery host facts are unavailable") from error
    for field in (
        "machine_identity", "canonical_path", "path_kind", "reparse_or_symlink",
        "volume_identity", "storage_backend", "storage_authority", "facts_sha256",
    ):
        if actual[field] != recovery_facts[field]:
            raise StateOnlyBackupError("scheduler is running on another recovery host/root")
    return document, hashlib.sha256(raw).hexdigest(), recovery, attestation_file


def _task_authority_ref(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict) or set(value) != {"kind", "locator", "sha256"}:
        raise StateOnlyBackupError("scheduled task authority ref is not closed")
    if (
        value["kind"] != "task_authority"
        or value["locator"] != TASK_AUTHORITY_LOCATOR
        or not isinstance(value["sha256"], str)
        or _SHA_RE.fullmatch(value["sha256"]) is None
    ):
        raise StateOnlyBackupError("scheduled task authority ref differs")
    return value


def validate_task_authority(value: object) -> Mapping[str, object]:
    """Validate the pre-authorized exact Scheduler roots and release identity.

    This module deliberately exposes no producer for this document.  A reviewed
    Stage 5 evidence producer must materialize it at the fixed recovery-root
    locator before either candidate generation or Task Scheduler apply exists.
    """

    require_failure_domain_authority()

    fields = {
        "schema_version", "authorization_id", "authorized_at", "authority",
        "repository", "release", "paths", "bytes", "failure_domain_attestation_sha256",
        "authority_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise StateOnlyBackupError("scheduled task authority schema is not closed")
    if (
        value["schema_version"] != TASK_AUTHORITY_SCHEMA
        or value["authority"] != "stage5_exact_identity"
    ):
        raise StateOnlyBackupError("scheduled task authority identity differs")
    _parse_timestamp(value["authorized_at"])
    repository = value["repository"]
    if not isinstance(repository, dict) or set(repository) != {
        "repository_id", "full_name", "commit_sha", "tracked_tree_sha256"
    }:
        raise StateOnlyBackupError("scheduled task repository authority is not closed")
    _safe_id(repository["repository_id"], label="scheduled task repository ID")
    if (
        not isinstance(repository["full_name"], str)
        or _REPOSITORY_RE.fullmatch(repository["full_name"]) is None
        or not isinstance(repository["commit_sha"], str)
        or _COMMIT_RE.fullmatch(repository["commit_sha"]) is None
    ):
        raise StateOnlyBackupError("scheduled task repository authority differs")
    _sha(repository["tracked_tree_sha256"], label="scheduled task tracked tree")
    release = value["release"]
    if not isinstance(release, dict) or set(release) != {
        "release_id", "manifest_sha256", "snapshot_id"
    }:
        raise StateOnlyBackupError("scheduled task release authority is not closed")
    _safe_id(release["release_id"], label="scheduled task release ID")
    _sha(release["manifest_sha256"], label="scheduled task release manifest")
    _safe_id(release["snapshot_id"], label="scheduled task snapshot ID")
    raw_paths = value["paths"]
    if not isinstance(raw_paths, dict) or set(raw_paths) != {
        "project_root", "config_path", "operational_root", "recovery_root",
        "operational_python", "failure_domain_attestation_path",
    }:
        raise StateOnlyBackupError("scheduled task authorized paths are not closed")
    resolved = {
        "project_root": _strict_existing_path(
            Path(str(raw_paths["project_root"])), kind="directory", label="authorized project root"
        ),
        "config_path": _strict_existing_path(
            Path(str(raw_paths["config_path"])), kind="file", label="authorized config"
        ),
        "operational_root": _strict_existing_path(
            Path(str(raw_paths["operational_root"])), kind="directory", label="authorized operational root"
        ),
        "recovery_root": _strict_existing_path(
            Path(str(raw_paths["recovery_root"])), kind="directory", label="authorized recovery root"
        ),
        "operational_python": _strict_existing_path(
            Path(str(raw_paths["operational_python"])), kind="file", label="authorized operational Python"
        ),
        "failure_domain_attestation_path": _strict_existing_path(
            Path(str(raw_paths["failure_domain_attestation_path"])),
            kind="file", label="authorized failure-domain attestation",
        ),
    }
    if any(str(resolved[name]) != raw_paths[name] for name in resolved):
        raise StateOnlyBackupError("scheduled task authorized path is not canonical and exact")
    project = resolved["project_root"]
    config = resolved["config_path"]
    operational = resolved["operational_root"]
    recovery = resolved["recovery_root"]
    executable = resolved["operational_python"]
    attestation_path = resolved["failure_domain_attestation_path"]
    if executable != operational / "tooling" / "python" / "python.exe":
        raise StateOnlyBackupError("scheduled task authorized Python locator differs")
    roots = (project, operational, recovery)
    if any(
        left == right or left in right.parents or right in left.parents
        for index, left in enumerate(roots)
        for right in roots[index + 1 :]
    ):
        raise StateOnlyBackupError("scheduled task authorized roots overlap")
    if any(config == root or root in config.parents or config in root.parents for root in roots):
        raise StateOnlyBackupError("scheduled task authorized config overlaps an authority root")
    if attestation_path.parent != recovery and recovery not in attestation_path.parents:
        raise StateOnlyBackupError("scheduled task authorized attestation escaped recovery root")
    try:
        runtime = RuntimePublishConfig.load(config, expected_project_root=project)
    except (OSError, PublishError) as error:
        raise StateOnlyBackupError("scheduled task protected config failed validation") from error
    if (
        runtime.project_root.resolve(strict=True) != project
        or runtime.recovery.recovery_root.resolve(strict=True) != recovery
        or runtime.recovery.operational_root.resolve(strict=True) != operational
        or runtime.recovery.attestation_path.resolve(strict=True) != attestation_path
        or f"{runtime.github.owner}/{runtime.github.repository}" != repository["full_name"]
    ):
        raise StateOnlyBackupError("scheduled task protected config authority differs")
    byte_bindings = value["bytes"]
    if not isinstance(byte_bindings, dict) or set(byte_bindings) != {
        "config_sha256", "operational_python_sha256"
    }:
        raise StateOnlyBackupError("scheduled task authorized bytes are not closed")
    if (
        _sha(byte_bindings["config_sha256"], label="authorized config bytes")
        != hashlib.sha256(config.read_bytes()).hexdigest()
        or _sha(byte_bindings["operational_python_sha256"], label="authorized Python bytes")
        != hashlib.sha256(executable.read_bytes()).hexdigest()
    ):
        raise StateOnlyBackupError("scheduled task authorized bytes drifted")
    _sha(
        value["failure_domain_attestation_sha256"],
        label="scheduled task authorized failure-domain attestation",
    )
    material = dict(value)
    claimed_hash = material.pop("authority_sha256")
    if claimed_hash != manifest_sha256(material):
        raise StateOnlyBackupError("scheduled task authority hash differs")
    id_material = dict(material)
    claimed_id = id_material.pop("authorization_id")
    expected_id = "task-authority-" + manifest_sha256(id_material)[:32]
    if claimed_id != expected_id:
        raise StateOnlyBackupError("scheduled task authorization ID is not derived")
    return value


def _load_task_authority(
    reference: object, *, recovery_root: Path
) -> Mapping[str, object]:
    normalized = _task_authority_ref(reference)
    try:
        raw = DirectoryEvidenceResolver(recovery_root).read_bytes(TASK_AUTHORITY_LOCATOR)
    except StageClosureError as error:
        raise StateOnlyBackupError("scheduled task authority bytes are unavailable") from error
    if hashlib.sha256(raw).hexdigest() != normalized["sha256"]:
        raise StateOnlyBackupError("scheduled task authority raw hash differs")
    try:
        document = json.loads(raw.decode("utf-8"))
        if canonical_manifest_bytes(document) != raw:
            raise StateOnlyBackupError("scheduled task authority is not canonical JSON")
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StateOnlyBackupError("scheduled task authority is unreadable") from error
    return validate_task_authority(document)


def _task_schedule_policy() -> dict[str, object]:
    """Return every behavior-bearing Scheduler setting accepted by XML replay."""

    return {
        "kind": "daily",
        "days_interval": 1,
        "start_local": "03:00:00",
        "timezone": "recovery_host_local_floating",
        "enabled": True,
        "start_when_available": True,
        "run_only_if_network_available": True,
        "multiple_instances": "ignore_new",
        "execution_time_limit": "PT2H",
        "retry_count": 3,
        "retry_interval_minutes": 15,
        "disallow_start_if_on_batteries": True,
        "stop_if_going_on_batteries": True,
        "allow_hard_terminate": True,
        "allow_start_on_demand": True,
        "hidden": False,
        "run_only_if_idle": False,
        "wake_to_run": False,
        "idle_stop_on_end": True,
        "idle_restart": False,
        "priority": 7,
    }


def build_task_candidate(
    *,
    config_path: Path,
    project_root: Path,
    operational_root: Path,
    operational_python: Path,
    recovery_root: Path,
    failure_domain_attestation_path: Path,
) -> Mapping[str, object]:
    require_failure_domain_authority()
    config = _strict_existing_path(config_path, kind="file", label="config")
    project = _strict_existing_path(project_root, kind="directory", label="project root")
    operational = _strict_existing_path(
        operational_root, kind="directory", label="operational root"
    )
    executable = _strict_existing_path(
        operational_python, kind="file", label="operational Python"
    )
    attestation, attestation_sha, recovery, attestation_file = _load_scheduler_attestation(
        recovery_root=recovery_root,
        attestation_path=failure_domain_attestation_path,
    )
    try:
        authority_raw = DirectoryEvidenceResolver(recovery).read_bytes(TASK_AUTHORITY_LOCATOR)
    except StageClosureError as error:
        raise StateOnlyBackupError(
            "scheduled task fixed pre-authorization is unavailable"
        ) from error
    authority_reference = artifact_ref(
        kind="task_authority",
        locator=TASK_AUTHORITY_LOCATOR,
        raw_bytes=authority_raw,
    )
    authority = _load_task_authority(authority_reference, recovery_root=recovery)
    if executable != operational / "tooling" / "python" / "python.exe":
        raise StateOnlyBackupError("scheduled task executable is not the attested operational Python")
    roots = (project, operational, recovery)
    if any(left == right or left in right.parents or right in left.parents for index, left in enumerate(roots) for right in roots[index + 1 :]):
        raise StateOnlyBackupError("scheduled task authority roots overlap")
    if any(config == root or root in config.parents or config in root.parents for root in roots):
        raise StateOnlyBackupError("scheduled task config must stay outside authority roots")
    authorized_paths = authority["paths"]
    assert isinstance(authorized_paths, Mapping)
    if authorized_paths != {
        "project_root": str(project),
        "config_path": str(config),
        "operational_root": str(operational),
        "recovery_root": str(recovery),
        "operational_python": str(executable),
        "failure_domain_attestation_path": str(attestation_file),
    }:
        raise StateOnlyBackupError("scheduled task paths were not pre-authorized")
    authorized_bytes = authority["bytes"]
    assert isinstance(authorized_bytes, Mapping)
    if authorized_bytes != {
        "config_sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
        "operational_python_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
    }:
        raise StateOnlyBackupError("scheduled task bytes were not pre-authorized")
    if authority["failure_domain_attestation_sha256"] != attestation_sha:
        raise StateOnlyBackupError("scheduled task attestation was not pre-authorized")
    recovery_facts = attestation["recovery"]
    assert isinstance(recovery_facts, Mapping)
    arguments = (
        "-I", "-B", "-m", "quant_hub.ops.state_only_backup", "run",
        "--config", str(config), "--project-root", str(project),
    )
    body: dict[str, object] = {
        "schema_version": TASK_CANDIDATE_SCHEMA,
        "task_identity": TASK_IDENTITY,
        "host_role": "attested_recovery_host",
        "host_binding": {
            "recovery_root": str(recovery),
            "recovery_host_facts_sha256": recovery_facts["facts_sha256"],
            "failure_domain_attestation_path": str(attestation_file),
            "failure_domain_attestation_sha256": attestation_sha,
        },
        "authority_ref": dict(authority_reference),
        "repository_binding": dict(authority["repository"]),
        "release_binding": dict(authority["release"]),
        "schedule": _task_schedule_policy(),
        "principal": {
            "logon_type": "s4u_no_stored_password", "run_level": "limited",
            "token_sid_sha256": _current_token_sid_sha256(),
        },
        "action": {
            "executable": str(executable),
            "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
            "arguments": list(arguments),
            "working_directory": str(config.parent),
            "config_sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
            "project_root": str(project),
            "operational_root": str(operational),
        },
        "network_required": True,
        "credential_material_embedded": False,
        "vm_task_registration": False,
    }
    body["contract_sha256"] = manifest_sha256(body)
    return validate_task_candidate(body)


def validate_task_candidate(value: object) -> Mapping[str, object]:
    require_failure_domain_authority()
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "task_identity", "host_role", "host_binding", "schedule",
        "authority_ref", "repository_binding", "release_binding", "principal", "action",
        "network_required", "credential_material_embedded", "vm_task_registration",
        "contract_sha256",
    }:
        raise StateOnlyBackupError("scheduled task candidate schema is not closed")
    candidate = dict(value)
    claimed = candidate.pop("contract_sha256", None)
    if (
        candidate.get("schema_version") != TASK_CANDIDATE_SCHEMA
        or candidate.get("task_identity") != TASK_IDENTITY
        or candidate.get("host_role") != "attested_recovery_host"
        or candidate.get("network_required") is not True
        or candidate.get("credential_material_embedded") is not False
        or candidate.get("vm_task_registration") is not False
        or claimed != manifest_sha256(candidate)
    ):
        raise StateOnlyBackupError("scheduled task candidate identity differs")
    expected_schedule = _task_schedule_policy()
    if candidate.get("schedule") != expected_schedule:
        raise StateOnlyBackupError("scheduled task policy differs")
    principal = candidate.get("principal")
    if not isinstance(principal, dict) or set(principal) != {
        "logon_type", "run_level", "token_sid_sha256"
    } or principal["logon_type"] != "s4u_no_stored_password" or principal["run_level"] != "limited":
        raise StateOnlyBackupError("scheduled task principal policy differs")
    _sha(principal["token_sid_sha256"], label="scheduled task token SID")
    if principal["token_sid_sha256"] != _current_token_sid_sha256():
        raise StateOnlyBackupError("scheduled task belongs to another process-token SID")
    host = candidate.get("host_binding")
    if not isinstance(host, dict) or set(host) != {
        "recovery_root", "recovery_host_facts_sha256", "failure_domain_attestation_path",
        "failure_domain_attestation_sha256",
    }:
        raise StateOnlyBackupError("scheduled task host binding differs")
    attestation, raw_sha, recovery, attestation_path = _load_scheduler_attestation(
        recovery_root=Path(str(host["recovery_root"])),
        attestation_path=Path(str(host["failure_domain_attestation_path"])),
    )
    if raw_sha != host["failure_domain_attestation_sha256"] or attestation["recovery"]["facts_sha256"] != host["recovery_host_facts_sha256"]:
        raise StateOnlyBackupError("scheduled task attestation identity differs")
    authority = _load_task_authority(candidate["authority_ref"], recovery_root=recovery)
    if (
        authority["repository"] != candidate["repository_binding"]
        or authority["release"] != candidate["release_binding"]
        or authority["failure_domain_attestation_sha256"]
        != host["failure_domain_attestation_sha256"]
    ):
        raise StateOnlyBackupError("scheduled task candidate differs from pre-authorization")
    action = candidate.get("action")
    if not isinstance(action, dict) or set(action) != {
        "executable", "executable_sha256", "arguments", "working_directory",
        "config_sha256", "project_root", "operational_root",
    }:
        raise StateOnlyBackupError("scheduled task action is invalid")
    executable = _strict_existing_path(Path(str(action["executable"])), kind="file", label="executable")
    arguments = action["arguments"]
    if (
        not isinstance(arguments, list) or len(arguments) != 9
        or arguments[:5] != ["-I", "-B", "-m", "quant_hub.ops.state_only_backup", "run"]
        or arguments[5] != "--config" or arguments[7] != "--project-root"
        or any(not isinstance(item, str) for item in arguments)
    ):
        raise StateOnlyBackupError("scheduled task fixed argv differs")
    config_path = _strict_existing_path(Path(arguments[6]), kind="file", label="config")
    project = _strict_existing_path(Path(arguments[8]), kind="directory", label="project root")
    operational = _strict_existing_path(Path(str(action["operational_root"])), kind="directory", label="operational root")
    working = _strict_existing_path(Path(str(action["working_directory"])), kind="directory", label="working directory")
    if (
        executable != operational / "tooling" / "python" / "python.exe"
        or str(project) != action["project_root"]
        or working != config_path.parent
        or hashlib.sha256(executable.read_bytes()).hexdigest() != action["executable_sha256"]
        or hashlib.sha256(config_path.read_bytes()).hexdigest() != action["config_sha256"]
    ):
        raise StateOnlyBackupError("scheduled task action bytes or roots differ")
    authorized_paths = authority["paths"]
    authorized_bytes = authority["bytes"]
    assert isinstance(authorized_paths, Mapping) and isinstance(authorized_bytes, Mapping)
    if authorized_paths != {
        "project_root": str(project),
        "config_path": str(config_path),
        "operational_root": str(operational),
        "recovery_root": str(recovery),
        "operational_python": str(executable),
        "failure_domain_attestation_path": str(attestation_path),
    } or authorized_bytes != {
        "config_sha256": action["config_sha256"],
        "operational_python_sha256": action["executable_sha256"],
    }:
        raise StateOnlyBackupError("scheduled task action is outside pre-authorized locators")
    roots = (project, operational, recovery)
    if any(left == right or left in right.parents or right in left.parents for index, left in enumerate(roots) for right in roots[index + 1 :]):
        raise StateOnlyBackupError("scheduled task authority roots overlap")
    if any(
        config_path == root
        or root in config_path.parents
        or config_path in root.parents
        for root in roots
    ):
        raise StateOnlyBackupError("scheduled task config overlaps an authority root")
    if attestation_path.parent != recovery and recovery not in attestation_path.parents:
        raise StateOnlyBackupError("scheduled task attestation escaped recovery root")
    return value


def _task_xml_tag(local_name: str) -> str:
    return f"{{{TASK_XML_NAMESPACE}}}{local_name}"


def _task_xml_children(
    parent: ET.Element,
    expected_names: Sequence[str],
    *,
    attributes: Mapping[str, str] | None = None,
) -> tuple[ET.Element, ...]:
    expected_attributes = {} if attributes is None else dict(attributes)
    if dict(parent.attrib) != expected_attributes:
        raise StateOnlyBackupError("Task XML element attributes differ")
    if parent.text is not None and parent.text.strip():
        raise StateOnlyBackupError("Task XML container has unexpected text")
    children = tuple(parent)
    if tuple(child.tag for child in children) != tuple(
        _task_xml_tag(name) for name in expected_names
    ):
        raise StateOnlyBackupError("Task XML children are not closed or ordered")
    if any(child.tail is not None and child.tail.strip() for child in children):
        raise StateOnlyBackupError("Task XML child has unexpected tail text")
    return children


def _task_xml_leaf(
    element: ET.Element,
    name: str,
    *,
    attributes: Mapping[str, str] | None = None,
) -> str:
    if element.tag != _task_xml_tag(name):
        raise StateOnlyBackupError(f"Task XML {name} name differs")
    if dict(element.attrib) != ({} if attributes is None else dict(attributes)):
        raise StateOnlyBackupError(f"Task XML {name} attributes differ")
    if list(element) or element.text is None:
        raise StateOnlyBackupError(f"Task XML {name} is not one text leaf")
    return element.text


def _task_xml_bool(element: ET.Element, name: str) -> bool:
    value = _task_xml_leaf(element, name)
    if value not in {"true", "false"}:
        raise StateOnlyBackupError(f"Task XML {name} boolean differs")
    return value == "true"


def _task_xml_projection(raw: bytes) -> Mapping[str, object]:
    """Build one closed semantic projection from the exported XML bytes only."""

    if not isinstance(raw, bytes) or not 0 < len(raw) <= 4 * 1024 * 1024:
        raise StateOnlyBackupError("Task Scheduler raw XML size is outside the contract")
    if b"<!DOCTYPE" in raw.upper():
        raise StateOnlyBackupError("Task XML document type is forbidden")
    try:
        decoded = raw.decode("utf-8")
        if decoded.startswith("\ufeff"):
            raise StateOnlyBackupError("Task XML UTF-8 BOM is forbidden")
        root = ET.fromstring(decoded)
    except (UnicodeDecodeError, ET.ParseError) as error:
        raise StateOnlyBackupError("Task XML is not strict UTF-8 XML") from error
    if root.tag != _task_xml_tag("Task"):
        raise StateOnlyBackupError("Task XML root namespace/name differs")
    registration, triggers, principals, settings, actions = _task_xml_children(
        root,
        ("RegistrationInfo", "Triggers", "Principals", "Settings", "Actions"),
        attributes={"version": TASK_XML_VERSION},
    )

    description_element, uri_element = _task_xml_children(
        registration, ("Description", "URI")
    )
    description = _task_xml_leaf(description_element, "Description")
    description_match = re.fullmatch(
        r"QRH_STATE_ONLY_CONTRACT:([0-9a-f]{64})", description
    )
    if description_match is None:
        raise StateOnlyBackupError("Task XML RegistrationInfo Description differs")
    uri = _task_xml_leaf(uri_element, "URI")

    (calendar_trigger,) = _task_xml_children(triggers, ("CalendarTrigger",))
    start_element, trigger_enabled_element, schedule_by_day = _task_xml_children(
        calendar_trigger, ("StartBoundary", "Enabled", "ScheduleByDay")
    )
    start_boundary = _task_xml_leaf(start_element, "StartBoundary")
    trigger_enabled = _task_xml_bool(trigger_enabled_element, "Enabled")
    (days_element,) = _task_xml_children(schedule_by_day, ("DaysInterval",))
    days_interval = _task_xml_leaf(days_element, "DaysInterval")
    if re.fullmatch(r"[1-9]\d*", days_interval) is None:
        raise StateOnlyBackupError("Task XML DaysInterval differs")

    (principal,) = _task_xml_children(principals, ("Principal",))
    user_element, logon_element, run_level_element = _task_xml_children(
        principal,
        ("UserId", "LogonType", "RunLevel"),
        attributes={"id": TASK_XML_PRINCIPAL_ID},
    )
    try:
        normalized_sid = _normalize_windows_sid(
            _task_xml_leaf(user_element, "UserId")
        )
    except StateOnlyBackupError as error:
        raise StateOnlyBackupError(
            "Task XML UserId is not a normalizable SID"
        ) from error
    principal_sid_sha256 = hashlib.sha256(normalized_sid.encode("ascii")).hexdigest()
    logon_type = _task_xml_leaf(logon_element, "LogonType")
    run_level = _task_xml_leaf(run_level_element, "RunLevel")

    (
        multiple_instances_element,
        disallow_battery_element,
        stop_battery_element,
        hard_terminate_element,
        start_available_element,
        network_element,
        idle_settings,
        demand_element,
        task_enabled_element,
        hidden_element,
        run_idle_element,
        wake_element,
        execution_limit_element,
        priority_element,
        restart_settings,
    ) = _task_xml_children(
        settings,
        (
            "MultipleInstancesPolicy",
            "DisallowStartIfOnBatteries",
            "StopIfGoingOnBatteries",
            "AllowHardTerminate",
            "StartWhenAvailable",
            "RunOnlyIfNetworkAvailable",
            "IdleSettings",
            "AllowStartOnDemand",
            "Enabled",
            "Hidden",
            "RunOnlyIfIdle",
            "WakeToRun",
            "ExecutionTimeLimit",
            "Priority",
            "RestartOnFailure",
        ),
    )
    idle_stop_element, idle_restart_element = _task_xml_children(
        idle_settings, ("StopOnIdleEnd", "RestartOnIdle")
    )
    retry_interval_element, retry_count_element = _task_xml_children(
        restart_settings, ("Interval", "Count")
    )
    priority = _task_xml_leaf(priority_element, "Priority")
    retry_count = _task_xml_leaf(retry_count_element, "Count")
    if re.fullmatch(r"\d+", priority) is None or re.fullmatch(r"\d+", retry_count) is None:
        raise StateOnlyBackupError("Task XML numeric setting differs")

    (exec_action,) = _task_xml_children(
        actions, ("Exec",), attributes={"Context": TASK_XML_PRINCIPAL_ID}
    )
    command_element, arguments_element, working_element = _task_xml_children(
        exec_action, ("Command", "Arguments", "WorkingDirectory")
    )
    projection: dict[str, object] = {
        "schema_version": TASK_XML_PROJECTION_SCHEMA,
        "task_namespace": TASK_XML_NAMESPACE,
        "task_version": TASK_XML_VERSION,
        "registration": {
            "description": description,
            "contract_sha256": description_match.group(1),
            "uri": uri,
        },
        "principal": {
            "id": TASK_XML_PRINCIPAL_ID,
            "principal_sid_sha256": principal_sid_sha256,
            "logon_type": logon_type,
            "run_level": run_level,
        },
        "calendar_trigger": {
            "start_boundary": start_boundary,
            "enabled": trigger_enabled,
            "days_interval": int(days_interval),
        },
        "settings": {
            "multiple_instances": _task_xml_leaf(
                multiple_instances_element, "MultipleInstancesPolicy"
            ),
            "disallow_start_if_on_batteries": _task_xml_bool(
                disallow_battery_element, "DisallowStartIfOnBatteries"
            ),
            "stop_if_going_on_batteries": _task_xml_bool(
                stop_battery_element, "StopIfGoingOnBatteries"
            ),
            "allow_hard_terminate": _task_xml_bool(
                hard_terminate_element, "AllowHardTerminate"
            ),
            "start_when_available": _task_xml_bool(
                start_available_element, "StartWhenAvailable"
            ),
            "run_only_if_network_available": _task_xml_bool(
                network_element, "RunOnlyIfNetworkAvailable"
            ),
            "idle_stop_on_end": _task_xml_bool(idle_stop_element, "StopOnIdleEnd"),
            "idle_restart": _task_xml_bool(idle_restart_element, "RestartOnIdle"),
            "allow_start_on_demand": _task_xml_bool(
                demand_element, "AllowStartOnDemand"
            ),
            "enabled": _task_xml_bool(task_enabled_element, "Enabled"),
            "hidden": _task_xml_bool(hidden_element, "Hidden"),
            "run_only_if_idle": _task_xml_bool(run_idle_element, "RunOnlyIfIdle"),
            "wake_to_run": _task_xml_bool(wake_element, "WakeToRun"),
            "execution_time_limit": _task_xml_leaf(
                execution_limit_element, "ExecutionTimeLimit"
            ),
            "priority": int(priority),
            "retry_interval": _task_xml_leaf(retry_interval_element, "Interval"),
            "retry_count": int(retry_count),
        },
        "exec": {
            "context": TASK_XML_PRINCIPAL_ID,
            "command": _task_xml_leaf(command_element, "Command"),
            "arguments": _task_xml_leaf(arguments_element, "Arguments"),
            "working_directory": _task_xml_leaf(working_element, "WorkingDirectory"),
        },
    }
    return projection


def _task_xml_projection_matches_candidate(
    projection: Mapping[str, object], candidate: Mapping[str, object]
) -> bool:
    try:
        registration = projection["registration"]
        principal_projection = projection["principal"]
        trigger = projection["calendar_trigger"]
        settings = projection["settings"]
        executable = projection["exec"]
        candidate_principal = candidate["principal"]
        candidate_schedule = candidate["schedule"]
        action = candidate["action"]
        assert all(
            isinstance(item, Mapping)
            for item in (
                registration,
                principal_projection,
                trigger,
                settings,
                executable,
                candidate_principal,
                candidate_schedule,
                action,
            )
        )
        expected_settings = {
            "multiple_instances": "IgnoreNew",
            "disallow_start_if_on_batteries": candidate_schedule["disallow_start_if_on_batteries"],
            "stop_if_going_on_batteries": candidate_schedule["stop_if_going_on_batteries"],
            "allow_hard_terminate": candidate_schedule["allow_hard_terminate"],
            "start_when_available": candidate_schedule["start_when_available"],
            "run_only_if_network_available": candidate_schedule["run_only_if_network_available"],
            "idle_stop_on_end": candidate_schedule["idle_stop_on_end"],
            "idle_restart": candidate_schedule["idle_restart"],
            "allow_start_on_demand": candidate_schedule["allow_start_on_demand"],
            "enabled": candidate_schedule["enabled"],
            "hidden": candidate_schedule["hidden"],
            "run_only_if_idle": candidate_schedule["run_only_if_idle"],
            "wake_to_run": candidate_schedule["wake_to_run"],
            "execution_time_limit": candidate_schedule["execution_time_limit"],
            "priority": candidate_schedule["priority"],
            "retry_interval": f"PT{candidate_schedule['retry_interval_minutes']}M",
            "retry_count": candidate_schedule["retry_count"],
        }
        return (
            projection["schema_version"] == TASK_XML_PROJECTION_SCHEMA
            and projection["task_namespace"] == TASK_XML_NAMESPACE
            and projection["task_version"] == TASK_XML_VERSION
            and registration
            == {
                "description": "QRH_STATE_ONLY_CONTRACT:"
                + str(candidate["contract_sha256"]),
                "contract_sha256": candidate["contract_sha256"],
                "uri": candidate["task_identity"],
            }
            and principal_projection
            == {
                "id": TASK_XML_PRINCIPAL_ID,
                "principal_sid_sha256": candidate_principal["token_sid_sha256"],
                "logon_type": "S4U",
                "run_level": "LeastPrivilege",
            }
            and trigger["enabled"] == candidate_schedule["enabled"]
            and trigger["days_interval"] == candidate_schedule["days_interval"]
            and re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T" + re.escape(str(candidate_schedule["start_local"])) + r"(?:\.0+)?",
                str(trigger["start_boundary"]),
            )
            is not None
            and settings == expected_settings
            and executable
            == {
                "context": TASK_XML_PRINCIPAL_ID,
                "command": action["executable"],
                "arguments": subprocess.list2cmdline(list(action["arguments"])),
                "working_directory": action["working_directory"],
            }
        )
    except (AssertionError, KeyError, TypeError, ValueError):
        return False


def _task_xml_is_exact(raw: bytes, candidate: Mapping[str, object]) -> bool:
    try:
        return _task_xml_projection_matches_candidate(
            _task_xml_projection(raw), candidate
        )
    except StateOnlyBackupError:
        return False


def _validate_task_inspection(
    value: object, *, candidate: Mapping[str, object] | None = None
) -> TaskInspection:
    if not isinstance(value, TaskInspection) or value.status not in {"missing", "exact", "drift"}:
        raise StateOnlyBackupError("Task Scheduler inspection contract is invalid")
    fields = (value.contract_sha256, value.task_xml_sha256, value.principal_sid_sha256, value.task_xml_base64)
    if value.status == "missing":
        if any(item is not None for item in fields):
            raise StateOnlyBackupError("missing Task Scheduler inspection has identities")
        return value
    if value.task_xml_sha256 is None or value.task_xml_base64 is None:
        raise StateOnlyBackupError("existing Task Scheduler inspection lacks raw XML identity")
    _sha(value.task_xml_sha256, label="inspected task XML")
    try:
        raw = base64.b64decode(value.task_xml_base64, validate=True)
    except (ValueError, TypeError) as error:
        raise StateOnlyBackupError("Task Scheduler XML base64 is malformed") from error
    if not 0 < len(raw) <= 4 * 1024 * 1024:
        raise StateOnlyBackupError("Task Scheduler raw XML size is outside the contract")
    if hashlib.sha256(raw).hexdigest() != value.task_xml_sha256:
        raise StateOnlyBackupError("Task Scheduler raw XML hash differs")
    try:
        projection: Mapping[str, object] | None = _task_xml_projection(raw)
    except StateOnlyBackupError:
        projection = None
    if projection is None:
        if value.contract_sha256 is not None or value.principal_sid_sha256 is not None:
            raise StateOnlyBackupError(
                "Task Scheduler non-projectable XML has derived identities"
            )
    else:
        registration = projection["registration"]
        principal_projection = projection["principal"]
        assert isinstance(registration, Mapping)
        assert isinstance(principal_projection, Mapping)
        derived_contract = registration["contract_sha256"]
        derived_principal = principal_projection["principal_sid_sha256"]
        _sha(derived_contract, label="projected task contract")
        _sha(derived_principal, label="projected principal SID")
        if (
            value.contract_sha256 != derived_contract
            or value.principal_sid_sha256 != derived_principal
        ):
            raise StateOnlyBackupError(
                "Task Scheduler derived identities differ from raw XML"
            )
    if candidate is not None:
        exact = (
            projection is not None
            and _task_xml_projection_matches_candidate(projection, candidate)
        )
        if (value.status == "exact") != exact:
            raise StateOnlyBackupError("Task Scheduler inspection verdict differs from raw XML")
    elif value.status == "exact" and projection is None:
        raise StateOnlyBackupError("exact Task Scheduler inspection has no XML projection")
    return value


def _task_inspection_projection(value: TaskInspection) -> Mapping[str, object] | None:
    if value.status == "missing":
        return None
    assert value.task_xml_base64 is not None
    raw = base64.b64decode(value.task_xml_base64, validate=True)
    try:
        return _task_xml_projection(raw)
    except StateOnlyBackupError:
        return None


def _inspection_from_raw_xml(
    raw: bytes, *, candidate: Mapping[str, object]
) -> TaskInspection:
    encoded = base64.b64encode(raw).decode("ascii")
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    try:
        projection = _task_xml_projection(raw)
    except StateOnlyBackupError:
        return _validate_task_inspection(
            TaskInspection("drift", None, raw_sha256, None, encoded),
            candidate=candidate,
        )
    registration = projection["registration"]
    principal = projection["principal"]
    assert isinstance(registration, Mapping) and isinstance(principal, Mapping)
    status = (
        "exact"
        if _task_xml_projection_matches_candidate(projection, candidate)
        else "drift"
    )
    return _validate_task_inspection(
        TaskInspection(
            status,
            str(registration["contract_sha256"]),
            raw_sha256,
            str(principal["principal_sid_sha256"]),
            encoded,
        ),
        candidate=candidate,
    )


def build_task_inspection_artifact(
    inspection: TaskInspection, *, observed_at: str, candidate: Mapping[str, object]
) -> Mapping[str, object]:
    value = _validate_task_inspection(inspection, candidate=candidate)
    document: dict[str, object] = {
        "schema_version": TASK_INSPECTION_SCHEMA,
        "observed_at": _timestamp(_parse_timestamp(observed_at)),
        "status": value.status,
        "contract_sha256": value.contract_sha256,
        "task_xml_sha256": value.task_xml_sha256,
        "principal_sid_sha256": value.principal_sid_sha256,
        "task_xml_base64": value.task_xml_base64,
        "task_xml_projection": _task_inspection_projection(value),
    }
    document["inspection_sha256"] = manifest_sha256(document)
    return validate_task_inspection_artifact(document, candidate=candidate)


def validate_task_inspection_artifact(
    value: object, *, candidate: Mapping[str, object]
) -> Mapping[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "observed_at", "status", "contract_sha256",
        "task_xml_sha256", "principal_sid_sha256", "task_xml_base64",
        "task_xml_projection", "inspection_sha256",
    } or value["schema_version"] != TASK_INSPECTION_SCHEMA:
        raise StateOnlyBackupError("task inspection artifact schema differs")
    _parse_timestamp(value["observed_at"])
    material = dict(value)
    claimed = material.pop("inspection_sha256")
    if claimed != manifest_sha256(material):
        raise StateOnlyBackupError("task inspection artifact hash differs")
    inspection = TaskInspection(
        str(value["status"]), value["contract_sha256"], value["task_xml_sha256"],
        value["principal_sid_sha256"], value["task_xml_base64"],
    )
    normalized = _validate_task_inspection(inspection, candidate=candidate)
    if value["task_xml_projection"] != _task_inspection_projection(normalized):
        raise StateOnlyBackupError(
            "task inspection projection differs from raw XML"
        )
    return value


def apply_task_candidate(
    candidate: object, *, adapter: TaskSchedulerAdapter, allow_os_registration: bool
) -> TaskApplyResult:
    require_failure_domain_authority()
    value = validate_task_candidate(candidate)
    if not allow_os_registration:
        raise StateOnlyBackupError("Task Scheduler apply requires explicit opt-in")
    current = _validate_task_inspection(adapter.inspect(value), candidate=value)
    if current.status == "exact":
        return TaskApplyResult(status="unchanged", inspection=current)
    adapter.register(value)
    observed = _validate_task_inspection(adapter.inspect(value), candidate=value)
    if observed.status != "exact":
        raise StateOnlyBackupError("Task Scheduler registration does not match candidate")
    return TaskApplyResult(status="applied", inspection=observed)


class PowerShellTaskSchedulerAdapter:
    """Inspect one exported XML observation; no CIM property is evidence."""

    @staticmethod
    def _literal(value: object) -> str:
        return "'" + str(value).replace("'", "''") + "'"

    @staticmethod
    def _run(script: str) -> subprocess.CompletedProcess[str]:
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        return subprocess.run(("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded), shell=False, check=False, capture_output=True, text=True, encoding="utf-8", errors="replace")

    def inspect(self, candidate: Mapping[str, object]) -> TaskInspection:
        validate_task_candidate(candidate)
        script = (
            "$ErrorActionPreference='Stop';"
            "$exists=Get-ScheduledTask -TaskPath '\\QuantResearchHub\\' "
            "-TaskName 'StateOnlyBackup' -ErrorAction SilentlyContinue;"
            "if($null-eq$exists){Write-Output 'missing|';exit 0};"
            "$xml=Export-ScheduledTask -TaskPath '\\QuantResearchHub\\' "
            "-TaskName 'StateOnlyBackup' -ErrorAction Stop;"
            "if([string]::IsNullOrEmpty($xml)){throw 'empty task XML'};"
            "$x=[Text.Encoding]::UTF8.GetBytes($xml);"
            "$xml64=[Convert]::ToBase64String($x);"
            "Write-Output ('xml|'+$xml64)"
        )
        result = self._run(script)
        if result.returncode != 0:
            raise StateOnlyBackupError("cannot inspect developer Task Scheduler")
        verdict = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
        parts = verdict.split("|", 1)
        if len(parts) != 2 or parts[0] not in {"missing", "xml"}:
            raise StateOnlyBackupError("developer Task Scheduler inspection is malformed")
        if parts[0] == "missing":
            if parts[1]:
                raise StateOnlyBackupError("missing Task Scheduler returned XML")
            return TaskInspection("missing", None, None, None, None)
        try:
            raw = base64.b64decode(parts[1], validate=True)
        except (ValueError, TypeError) as error:
            raise StateOnlyBackupError(
                "developer Task Scheduler XML transport is malformed"
            ) from error
        return _inspection_from_raw_xml(raw, candidate=candidate)

    def register(self, candidate: Mapping[str, object]) -> None:
        validate_task_candidate(candidate)
        principal = candidate["principal"]
        assert isinstance(principal, Mapping)
        if principal["token_sid_sha256"] != _current_token_sid_sha256():
            raise StateOnlyBackupError("current process-token SID differs before registration")
        action = candidate["action"]
        assert isinstance(action, Mapping)
        arguments = subprocess.list2cmdline(list(action["arguments"]))
        contract = str(candidate["contract_sha256"])
        script = (
            "$ErrorActionPreference='Stop';$identity=[Security.Principal.WindowsIdentity]::GetCurrent();$sid=$identity.User.Value;"
            f"$a=New-ScheduledTaskAction -Execute {self._literal(action['executable'])} -Argument {self._literal(arguments)} -WorkingDirectory {self._literal(action['working_directory'])};"
            "$g=New-ScheduledTaskTrigger -Daily -At '03:00';$g.Enabled=$true;"
            "$p=New-ScheduledTaskPrincipal -UserId $sid -LogonType S4U -RunLevel Limited;"
            "$s=New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 2) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 15);"
            "$s.Enabled=$true;$s.DisallowStartIfOnBatteries=$true;$s.StopIfGoingOnBatteries=$true;$s.AllowHardTerminate=$true;$s.AllowStartOnDemand=$true;$s.Hidden=$false;$s.RunOnlyIfIdle=$false;$s.WakeToRun=$false;$s.IdleSettings.StopOnIdleEnd=$true;$s.IdleSettings.RestartOnIdle=$false;$s.Priority=7;"
            f"$d={self._literal('QRH_STATE_ONLY_CONTRACT:'+contract)};$t=New-ScheduledTask -Action $a -Trigger $g -Principal $p -Settings $s -Description $d;"
            "Register-ScheduledTask -TaskPath '\\QuantResearchHub\\' -TaskName 'StateOnlyBackup' -InputObject $t -Force|Out-Null"
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
    require_failure_domain_authority()
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
        operational_root=config.recovery.operational_root,
        operational_python=python,
        recovery_root=config.recovery.recovery_root,
        failure_domain_attestation_path=config.recovery.attestation_path,
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
    inspection_artifact = build_task_inspection_artifact(
        outcome.inspection,
        observed_at=_timestamp(datetime.now(UTC)),
        candidate=candidate,
    )
    inspection_path = (
        _state_root(config.recovery.recovery_root)
        / "control"
        / "scheduled_task_inspection.json"
    )
    inspection_path.parent.mkdir(parents=True, exist_ok=True)
    if inspection_path.exists():
        if _canonical_read(inspection_path) != inspection_artifact:
            temporary = inspection_path.parent / (
                f".{inspection_path.name}.partial-{uuid4().hex}"
            )
            temporary.write_bytes(canonical_manifest_bytes(inspection_artifact))
            os.replace(temporary, inspection_path)
    else:
        write_atomic_new_json(inspection_path, inspection_artifact)
    print(
        json.dumps(
            {
                "task_identity": TASK_IDENTITY,
                "status": outcome.status,
                "contract_sha256": outcome.inspection.contract_sha256,
                "task_xml_sha256": outcome.inspection.task_xml_sha256,
                "inspection_sha256": inspection_artifact["inspection_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ActiveBinding",
    "GC_ROOTS_SCHEMA",
    "MeasuredPriorUnavailable",
    "PowerShellTaskSchedulerAdapter",
    "STATE_SET_SCHEMA",
    "STATUS_SCHEMA",
    "StateOnlyBackupError",
    "StateOnlyBackupLocked",
    "StateOnlyRunResult",
    "StateOnlySetVerification",
    "TASK_AUTHORITY_LOCATOR",
    "TASK_AUTHORITY_SCHEMA",
    "TASK_CANDIDATE_SCHEMA",
    "TASK_INSPECTION_SCHEMA",
    "TASK_IDENTITY",
    "TASK_XML_PROJECTION_SCHEMA",
    "TaskSchedulerAdapter",
    "TaskApplyResult",
    "TaskInspection",
    "apply_task_candidate",
    "build_gc_roots_report",
    "build_state_only_recovery_set",
    "build_task_candidate",
    "build_task_inspection_artifact",
    "evaluate_state_only_status",
    "load_measured_prior_binding",
    "main",
    "run_state_only_backup",
    "measured_prior_binding_path",
    "select_static_bundle",
    "validate_task_candidate",
    "validate_task_authority",
    "validate_task_inspection_artifact",
    "verify_state_only_recovery_set",
]
