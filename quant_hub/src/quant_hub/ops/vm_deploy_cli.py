"""固定 VM 远端入口：验证 incoming candidate，或执行本机 active/prior 切换。

``candidate_only`` 只产生 evidence-only audit event；它绝不伪造 receipt。``activate``
v2 ``candidate_only`` 保持 candidate 在 ``incoming/*.partial``；v1 兼容路径才会
finalize。成功 activation receipt 只能出现在 pointer 已切换、进程已启动且全部
post-activation gate 通过之后。
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path, PureWindowsPath
import re
import secrets
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import time
from typing import Callable, Mapping, Protocol
import urllib.parse
import urllib.request
from urllib.request import Request, urlopen

from quant_hub.web.access_gate import derive_password_digest
from quant_hub.collaboration.checkpoint import _pin_regular_file

from quant_hub.config import ensure_no_reparse_components, stat_is_reparse_point
from quant_hub.runtime_seal import read_json

from .deployment import (
    CandidateValidationError,
    DeploymentController,
    DeploymentFailed,
)
from .release_identity import validate_receipt
from .local_deployment_persistence import (
    UnsafeLocalPath,
    _BoundDirectory,
    _SafeRoot,
    _write_new_bound_file,
)
from .windows_service import (
    WindowsServiceError,
    verify_installed_operational_bindings,
)
from .vm_boundary import (
    PRODUCTION_VM_ROOT,
    VMBoundaryError,
    capture_vm_write_snapshot,
    declared_production_vm_write_set,
    finalize_vm_write_audit,
    reject_test_only_path_on_production_vm,
    validate_production_vm_write_path,
    verify_existing_vm_write_path,
)


FULL_SHA256 = re.compile(r"[0-9a-f]{64}")
STABLE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,179}")
RUNTIME_SCHEMA = "qrh-vm-deploy-runtime/v1"
_LIVE_PRODUCTION_WINDOWS_RUNTIMES: dict[int, tuple[object, tuple[object, ...]]] = {}


class VMDeployCLIError(RuntimeError):
    pass


class RuntimeHooks(Protocol):
    def state_compatibility_probe(self, release: Mapping[str, object]) -> bool: ...

    def candidate_probe(
        self, path: Path, identity: Mapping[str, object]
    ) -> Mapping[str, object]: ...

    def start_release(self, path: Path, active: Mapping[str, object]) -> bool: ...

    def stop_release(self, path: Path) -> None: ...

    def post_activation_probe(
        self, path: Path, active: Mapping[str, object]
    ) -> Mapping[str, bool]: ...


RootVerifier = Callable[[Path], Path]


def _stable(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or STABLE_ID.fullmatch(value) is None
        or ".." in value
    ):
        raise VMDeployCLIError(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or FULL_SHA256.fullmatch(value) is None:
        raise VMDeployCLIError(f"{label} is invalid")
    return value


def verify_production_root(path: Path) -> Path:
    approved = validate_production_vm_write_path(str(path), allow_root=True)
    if approved != PRODUCTION_VM_ROOT:
        raise VMDeployCLIError(r"vm-root must be exactly D:\quant\quant_platform")
    return verify_existing_vm_write_path(path, allow_root=True)


def rollback_prior(
    *,
    vm_root: Path,
    deployment_attempt_id: str,
) -> Mapping[str, object]:
    """Invoke the sealed exact-D rollback controller without a target input."""

    root = verify_production_root(vm_root)
    attempt_id = _stable(deployment_attempt_id, "deployment_attempt_id")
    from .local_exact_deployment_controller import (
        ProductionExactDeploymentController,
    )

    return ProductionExactDeploymentController.load_exact_d().rollback_to_prior(
        attempt_id=attempt_id
    )


def _probe_directory_identity(path: Path, *, label: str) -> tuple[str, int, int]:
    """Return a stable identity for one exact, ordinary probe directory."""

    try:
        ensure_no_reparse_components(path)
        info = path.lstat()
        resolved = path.resolve(strict=True)
    except (OSError, ValueError) as error:
        raise VMDeployCLIError(f"{label} is unavailable for candidate cleanup") from error
    if not stat.S_ISDIR(info.st_mode) or stat_is_reparse_point(info):
        raise VMDeployCLIError(f"{label} is not an ordinary directory")
    return os.path.normcase(str(resolved)), int(info.st_dev), int(info.st_ino)


def _verify_probe_cleanup_target(
    *,
    probe_parent: Path,
    probe_root: Path,
    expected_parent_identity: tuple[str, int, int],
    expected_root_identity: tuple[str, int, int],
) -> None:
    """Revalidate that cleanup still targets only the directory we created."""

    expected_root = probe_parent / probe_root.name
    if probe_root.absolute() != expected_root.absolute() or probe_root.parent != probe_parent:
        raise VMDeployCLIError("candidate probe cleanup target escaped its exact parent")
    parent_identity = _probe_directory_identity(
        probe_parent, label="candidate probe parent"
    )
    root_identity = _probe_directory_identity(probe_root, label="candidate probe root")
    if parent_identity != expected_parent_identity:
        raise VMDeployCLIError("candidate probe parent identity changed before cleanup")
    if root_identity != expected_root_identity:
        raise VMDeployCLIError("candidate probe root identity changed before cleanup")
    parent_resolved = Path(parent_identity[0])
    root_resolved = Path(root_identity[0])
    if root_resolved.parent != parent_resolved or root_resolved.name != probe_root.name:
        raise VMDeployCLIError("candidate probe cleanup target is outside its exact parent")


def _settle_candidate_process(process: subprocess.Popen[bytes]) -> None:
    """Fully reap a candidate process regardless of its last polled state."""

    try:
        if process.poll() is None:
            try:
                process.terminate()
            except OSError:
                # The child can exit between poll and terminate.  wait() below
                # is the authority for the final process state.
                pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    except (OSError, subprocess.SubprocessError) as error:
        raise VMDeployCLIError("candidate probe process could not be fully reaped") from error


def _remove_candidate_probe_root(
    *,
    probe_parent: Path,
    probe_root: Path,
    expected_parent_identity: tuple[str, int, int],
    expected_root_identity: tuple[str, int, int],
    remove: Callable[[Path], None],
    retry_seconds: float,
) -> None:
    """Remove exactly one probe root, retrying only Windows sharing failures."""

    deadline = time.monotonic() + max(0.0, retry_seconds)
    while True:
        if not os.path.lexists(probe_root):
            return
        _verify_probe_cleanup_target(
            probe_parent=probe_parent,
            probe_root=probe_root,
            expected_parent_identity=expected_parent_identity,
            expected_root_identity=expected_root_identity,
        )
        try:
            remove(probe_root)
            return
        except OSError as error:
            windows_error = getattr(error, "winerror", None)
            if windows_error not in {5, 32, 33}:
                raise VMDeployCLIError(
                    "candidate probe cleanup failed with a non-retryable error"
                ) from error
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise VMDeployCLIError(
                    "candidate probe cleanup exhausted the Windows sharing retry deadline"
                ) from error
            time.sleep(min(0.05, remaining))


def _remove_bound_directory_contents(
    *,
    safe_root: _SafeRoot,
    directory: _BoundDirectory,
    path: Path,
) -> None:
    """Delete only ordinary descendants through pinned parent handles."""

    with os.scandir(path) as iterator:
        entries = sorted(
            ((entry.name, entry.is_dir(follow_symlinks=False)) for entry in iterator),
            key=lambda item: item[0],
        )
    for name, is_directory in entries:
        child = path / name
        safe_root.preflight(
            child,
            expected_kind="directory" if is_directory else "file",
            allow_absent=False,
        )
        if is_directory:
            with _BoundDirectory(
                safe_root, child, protect_rename=True
            ) as child_bound:
                _remove_bound_directory_contents(
                    safe_root=safe_root,
                    directory=child_bound,
                    path=child,
                )
            directory.rmdir(name)
        else:
            directory.unlink(name)


@contextmanager
def _pin_live_candidate_sqlite_members(source: Path):
    """Fix the exact live SQLite main/WAL/SHM names during online backup.

    The handles share reads and writes so the current writer may continue, but
    deliberately deny delete/rename.  SQLite's backup API supplies snapshot
    consistency; these guards supply filesystem identity consistency.
    """

    if os.name != "nt":
        raise VMDeployCLIError("production candidate SQLite pin is Windows-only")
    import ctypes
    from ctypes import wintypes
    from .local_exact_runtime_tooling_scanner import (
        _WindowsNamespaceChangeMonitor,
    )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    kernel32.CreateFileW.restype = wintypes.HANDLE
    handles: list[int] = []
    identities: list[tuple[Path, os.stat_result]] = []
    try:
        with _WindowsNamespaceChangeMonitor(source.parent):
            for suffix in ("", "-wal", "-shm"):
                path = Path(str(source) + suffix)
                if not path.exists():
                    continue
                before = os.lstat(path)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or stat_is_reparse_point(before)
                    or getattr(before, "st_nlink", 1) != 1
                ):
                    raise VMDeployCLIError(
                        "candidate SQLite member is not exact regular material"
                    )
                raw = kernel32.CreateFileW(
                    str(path),
                    0x80000000,  # GENERIC_READ
                    0x00000001 | 0x00000002,  # SHARE_READ | SHARE_WRITE; no delete
                    None,
                    3,  # OPEN_EXISTING
                    0x00200000 | 0x08000000,
                    None,
                )
                invalid = ctypes.c_void_p(-1).value
                if raw in {None, invalid}:
                    raise VMDeployCLIError(
                        "candidate SQLite member cannot be fixed against replacement"
                    )
                handle = int(raw)
                handles.append(handle)
                if _BoundDirectory._windows_final_path(handle) != str(path):
                    raise VMDeployCLIError("candidate SQLite final path drifted")
                after = os.lstat(path)
                if (
                    (before.st_dev, before.st_ino)
                    != (after.st_dev, after.st_ino)
                    or stat_is_reparse_point(after)
                    or getattr(after, "st_nlink", 1) != 1
                ):
                    raise VMDeployCLIError("candidate SQLite open identity drifted")
                identities.append((path, before))
            if not handles or identities[0][0] != source:
                raise VMDeployCLIError("candidate SQLite main file is absent")
            yield
            observed_paths = tuple(
                Path(str(source) + suffix)
                for suffix in ("", "-wal", "-shm")
                if Path(str(source) + suffix).exists()
            )
            if observed_paths != tuple(path for path, _before in identities):
                raise VMDeployCLIError(
                    "candidate SQLite member set changed during online backup"
                )
            for (path, before), handle in zip(identities, handles):
                after = os.lstat(path)
                if (
                    _BoundDirectory._windows_final_path(handle) != str(path)
                    or (before.st_dev, before.st_ino)
                    != (after.st_dev, after.st_ino)
                    or stat_is_reparse_point(after)
                ):
                    raise VMDeployCLIError(
                        "candidate SQLite identity drifted during online backup"
                    )
    finally:
        failure: BaseException | None = None
        while handles:
            handle = handles.pop()
            try:
                _BoundDirectory._close_windows_handle(handle)
            except BaseException as error:
                failure = failure or error
        if failure is not None:
            raise VMDeployCLIError(
                "candidate SQLite source handles did not close"
            ) from failure


def _pin_candidate_tree(
    stack: ExitStack,
    *,
    safe_root: _SafeRoot,
    tree_root: Path,
) -> tuple[Path, ...]:
    """Pin every existing regular member and monitor its namespace."""

    from .local_exact_runtime_tooling_scanner import (
        _WindowsNamespaceChangeMonitor,
    )

    safe_root.preflight(tree_root, expected_kind="directory", allow_absent=False)
    stack.enter_context(_WindowsNamespaceChangeMonitor(tree_root))
    files: list[Path] = []

    def visit(directory: Path) -> None:
        safe_root.preflight(directory, expected_kind="directory", allow_absent=False)
        with os.scandir(directory) as iterator:
            entries = sorted(tuple(iterator), key=lambda item: item.name)
        if len(entries) != len({entry.name.casefold() for entry in entries}):
            raise VMDeployCLIError("candidate tree contains case-fold collisions")
        for entry in entries:
            path = directory / entry.name
            if entry.is_dir(follow_symlinks=False):
                visit(path)
            elif entry.is_file(follow_symlinks=False):
                observed = os.lstat(path)
                safe_root.preflight(path, expected_kind="file", allow_absent=False)
                stack.enter_context(_pin_regular_file(path, observed))
                files.append(path)
            else:
                raise VMDeployCLIError(
                    "candidate tree contains non-regular/reparse material"
                )

    visit(tree_root)
    if not files:
        raise VMDeployCLIError("candidate tree inventory is empty")
    return tuple(files)


def verify_runtime_environment(
    vm_root: PureWindowsPath, environment: Mapping[str, str]
) -> None:
    if environment.get("PYTHONDONTWRITEBYTECODE") != "1":
        raise VMDeployCLIError("PYTHONDONTWRITEBYTECODE=1 is required")
    for variable in ("TEMP", "TMP"):
        value = environment.get(variable)
        if not value:
            raise VMDeployCLIError(f"{variable} must be inside VM_ROOT")
        try:
            approved = validate_production_vm_write_path(value, allow_root=False)
        except VMBoundaryError as error:
            raise VMDeployCLIError(f"{variable} must be inside VM_ROOT") from error
        try:
            approved.relative_to(vm_root)
        except ValueError as error:
            raise VMDeployCLIError(f"{variable} must be inside VM_ROOT") from error
    pycache = environment.get("PYTHONPYCACHEPREFIX")
    if pycache:
        try:
            approved = validate_production_vm_write_path(pycache, allow_root=False)
            approved.relative_to(vm_root)
        except (VMBoundaryError, ValueError) as error:
            raise VMDeployCLIError(
                "PYTHONPYCACHEPREFIX must be inside VM_ROOT when configured"
            ) from error


def _active_bytes(controller: DeploymentController) -> bytes | None:
    path = controller.layout.active
    return path.read_bytes() if path.exists() else None


def _receipt_count(controller: DeploymentController) -> int:
    return sum(1 for path in controller.layout.audit_receipts.glob("*.json") if path.is_file())


def apply_publish(
    *,
    vm_root: Path,
    release_id: str,
    release_manifest_sha256: str,
    publish_candidate_sha256: str,
    deployment_mode: str,
    hooks: RuntimeHooks | None = None,
    deployment_attempt_id: str | None = None,
    root_verifier: RootVerifier = verify_production_root,
    environment: Mapping[str, str] | None = None,
) -> Mapping[str, object]:
    try:
        reject_test_only_path_on_production_vm(
            Path(vm_root), label="deployment request root"
        )
    except VMBoundaryError:
        production_request = True
    else:
        production_request = False
    if production_request:
        if hooks is not None:
            raise VMDeployCLIError(
                "production deployment runtime is internally constructed"
            )
        if root_verifier is not verify_production_root or environment is not None:
            raise VMDeployCLIError(
                "production deployment verification dependencies are fixed"
            )
    elif hooks is None:
        raise VMDeployCLIError("test-only deployment requires explicit runtime hooks")
    root = root_verifier(vm_root)
    verify_runtime_environment(
        PureWindowsPath(str(PRODUCTION_VM_ROOT)),
        os.environ if environment is None else environment,
    )
    release_id = _stable(release_id, "release_id")
    release_hash = _digest(release_manifest_sha256, "release_manifest_sha256")
    candidate_hash = _digest(publish_candidate_sha256, "publish_candidate_sha256")
    if deployment_mode not in {"activate", "candidate_only"}:
        raise VMDeployCLIError("deployment_mode is invalid")
    if production_request:
        hooks = WindowsServiceRuntime.load(root)
    assert hooks is not None
    if deployment_mode == "candidate_only" and type(hooks) is WindowsServiceRuntime:
        if deployment_attempt_id is not None:
            raise VMDeployCLIError(
                "candidate_only cannot carry activation authorization"
            )
        from .local_deployment_persistence import LocalDeploymentPersistence

        if hooks.root.resolve(strict=True) != root.resolve(strict=True):
            raise VMDeployCLIError(
                "exact candidate runtime root differs from verified VM root"
            )
        persistence = (
            LocalDeploymentPersistence.for_test_only(root)
            if hooks.allow_test_root
            else LocalDeploymentPersistence.production()
        )
        lock = persistence.global_lock()
        lock.acquire()
        try:
            candidate = persistence.inspect_exact_incoming_candidate(
                lock=lock,
                release_id=release_id,
                expected_manifest_sha256=release_hash,
            )
            snapshot_id = candidate["content"]["snapshot_id"]
            invariants = persistence.capture_candidate_validation_invariants(
                lock=lock,
                release_id=release_id,
                expected_manifest_sha256=release_hash,
            )
            probe = hooks.candidate_probe(
                persistence.layout.incoming / f"{release_id}.partial",
                {
                    "release_id": release_id,
                    "manifest_sha256": release_hash,
                    "snapshot_id": snapshot_id,
                },
            )
            event_id = persistence.commit_candidate_validation_event(
                lock=lock,
                release_id=release_id,
                expected_manifest_sha256=release_hash,
                publish_candidate_sha256=candidate_hash,
                probe_evidence=probe,
                invariants_before=invariants,
            )
        finally:
            if lock.held:
                lock.release()
        return {
            "schema_version": "qrh-vm-deploy-result/v1",
            "release_id": release_id,
            "release_manifest_sha256": release_hash,
            "publish_candidate_sha256": candidate_hash,
            "status": "candidate_validated",
            "evidence_type": "candidate_validation_event",
            "evidence_id": event_id,
        }
    if deployment_mode == "activate" and type(hooks) is WindowsServiceRuntime:
        attempt_id = _stable(deployment_attempt_id, "deployment_attempt_id")
        from .local_exact_deployment_controller import (
            ProductionExactDeploymentController,
        )

        exact = ProductionExactDeploymentController.load_exact_d().activate_successor(
            release_id=release_id,
            expected_manifest_sha256=release_hash,
            attempt_id=attempt_id,
        )
        if (
            exact.get("schema_version") != "qrh-vm-deploy-result/v2"
            or exact.get("status") != "activated"
            or exact.get("release_id") != release_id
            or exact.get("release_manifest_sha256") != release_hash
        ):
            raise VMDeployCLIError(
                "exact deployment controller returned another identity"
            )
        return {
            "schema_version": "qrh-vm-deploy-result/v1",
            "release_id": release_id,
            "release_manifest_sha256": release_hash,
            "publish_candidate_sha256": candidate_hash,
            "status": "activated",
            "evidence_type": "activation_receipt",
            "evidence_id": _stable(
                exact.get("activation_receipt_id"),
                "activation receipt id",
            ),
        }
    rendered_root = str(root).replace("/", "\\").rstrip("\\").casefold()
    if (
        rendered_root == str(PRODUCTION_VM_ROOT).rstrip("\\").casefold()
        or getattr(hooks, "allow_legacy_deployment_test_only", False) is not True
    ):
        raise VMDeployCLIError(
            "legacy deployment path is test-only and forbidden for production D"
        )
    controller = DeploymentController.for_test_only(root)
    resolved = controller.resolve_pending_activation(
        start_release=hooks.start_release,
        stop_release=hooks.stop_release,
    )
    if resolved is not None:
        if resolved.status == "failed":
            raise DeploymentFailed(resolved)
        if (
            deployment_mode == "activate"
            and resolved.candidate_release_id == release_id
            and resolved.candidate_manifest_sha256 == release_hash
        ):
            return {
                "schema_version": "qrh-vm-deploy-result/v1",
                "release_id": release_id,
                "release_manifest_sha256": release_hash,
                "publish_candidate_sha256": candidate_hash,
                "status": "activated",
                "evidence_type": "activation_receipt",
                "evidence_id": resolved.receipt_id,
            }
        raise VMDeployCLIError(
            "a committed pending activation was resolved for another request"
        )

    final = controller.release_path(release_id)
    partial = controller.partial_path(release_id)
    if final.exists() and partial.exists():
        raise CandidateValidationError("candidate exists as both partial and finalized")
    if not final.exists():
        finalized_path, observed_hash = controller.finalize_candidate(
            release_id,
            state_compatibility_probe=hooks.state_compatibility_probe,
        )
        if finalized_path != final or observed_hash != release_hash:
            raise CandidateValidationError("finalized candidate identity differs")
    controller.verify_finalized_release(
        release_id=release_id,
        expected_manifest_sha256=release_hash,
    )

    if deployment_mode == "candidate_only":
        if deployment_attempt_id is not None:
            raise VMDeployCLIError("candidate_only cannot carry activation authorization")
        active_before = _active_bytes(controller)
        receipts_before = _receipt_count(controller)
        release = read_json(final / "release_manifest.json")
        content = release.get("content") if isinstance(release, dict) else None
        snapshot_id = content.get("snapshot_id") if isinstance(content, dict) else None
        probe = hooks.candidate_probe(
            final,
            {
                "release_id": release_id,
                "manifest_sha256": release_hash,
                "snapshot_id": snapshot_id,
            },
        )
        required_probe_fields = {
            "schema_version", "release_id", "manifest_sha256", "snapshot_id",
            "transport", "writer_authority", "health", "browser", "api",
            "resource", "state_isolated", "active_unchanged", "cleaned",
        }
        if (
            not isinstance(probe, dict)
            or set(probe) != required_probe_fields
            or probe.get("schema_version") != "qrh-candidate-probe-evidence/v1"
            or probe.get("release_id") != release_id
            or probe.get("manifest_sha256") != release_hash
            or probe.get("snapshot_id") != snapshot_id
            or probe.get("transport") != "loopback_isolated"
            or probe.get("writer_authority") != "candidate-checkpoint-isolated"
            or any(
                probe.get(field) is not True
                for field in (
                    "health", "browser", "api", "resource", "state_isolated",
                    "active_unchanged", "cleaned",
                )
            )
        ):
            raise CandidateValidationError("isolated candidate probe did not pass")
        if _active_bytes(controller) != active_before:
            raise VMDeployCLIError("candidate probe changed active authority")
        evidence_id = controller.record_candidate_validation(
            release_id=release_id,
            expected_manifest_sha256=release_hash,
            publish_candidate_sha256=candidate_hash,
            probe_evidence=probe,
        )
        if _active_bytes(controller) != active_before:
            raise VMDeployCLIError("candidate-only validation changed active authority")
        if _receipt_count(controller) != receipts_before:
            raise VMDeployCLIError("candidate-only validation created a receipt")
        return {
            "schema_version": "qrh-vm-deploy-result/v1",
            "release_id": release_id,
            "release_manifest_sha256": release_hash,
            "publish_candidate_sha256": candidate_hash,
            "status": "candidate_validated",
            "evidence_type": "candidate_validation_event",
            "evidence_id": evidence_id,
        }

    attempt_id = _stable(deployment_attempt_id, "deployment_attempt_id")
    result = controller.activate(
        candidate_release_id=release_id,
        deployment_attempt_id=attempt_id,
        start_release=hooks.start_release,
        stop_release=hooks.stop_release,
        post_activation_probe=hooks.post_activation_probe,
    )
    if result.status != "activated" or result.candidate_manifest_sha256 != release_hash:
        raise VMDeployCLIError("deployment controller did not activate exact candidate")
    receipt = validate_receipt(
        read_json(controller.layout.audit_receipts / f"{result.receipt_id}.json")
    )
    if receipt["receipt_type"] != "activation":
        raise VMDeployCLIError("successful deployment lacks activation receipt")
    return {
        "schema_version": "qrh-vm-deploy-result/v1",
        "release_id": release_id,
        "release_manifest_sha256": release_hash,
        "publish_candidate_sha256": candidate_hash,
        "status": "activated",
        "evidence_type": "activation_receipt",
        "evidence_id": result.receipt_id,
    }


@dataclass(frozen=True, slots=True, weakref_slot=True)
class WindowsServiceRuntime:
    root: Path
    service_name: str
    base_url: str
    listen_host: str
    port: int
    critical_paths: tuple[str, ...]
    writer_authority: str
    service_entry_relative_path: str
    application_source_relative_path: str
    archive_root_relative_path: str
    var_root_relative_path: str
    migration_root_relative_path: str
    access_password_digest_path: str
    session_key_path: str
    comment_database_path: str
    workspace_database_path: str
    write_paths: tuple[PureWindowsPath, ...] = field(
        default_factory=lambda: tuple(
            PureWindowsPath(value)
            for value in declared_production_vm_write_set().values()
        )
    )
    candidate_python: Path | None = field(default=None, repr=False, compare=False)
    candidate_popen_factory: Callable[..., subprocess.Popen[bytes]] = field(
        default=subprocess.Popen, repr=False, compare=False
    )
    candidate_probe_rmtree: Callable[[Path], None] = field(
        default=shutil.rmtree, repr=False, compare=False
    )
    candidate_cleanup_retry_seconds: float = field(
        default=5.0, repr=False, compare=False
    )
    allow_test_root: bool = field(default=False, repr=False, compare=False)
    candidate_login_password_transform: Callable[[str], str] = field(
        default=lambda value: value, repr=False, compare=False
    )

    @classmethod
    def load(cls, root: Path) -> "WindowsServiceRuntime":
        path = root / "control" / "deployment_runtime.json"
        value = read_json(path)
        if not isinstance(value, dict) or set(value) != {
            "schema_version", "service_name", "base_url", "listen_host", "port",
            "critical_paths", "writer_authority", "write_paths",
            "service_entry_relative_path", "application_source_relative_path",
            "archive_root_relative_path", "var_root_relative_path",
            "migration_root_relative_path", "access_password_digest_path",
            "session_key_path", "comment_database_path", "workspace_database_path",
        }:
            raise VMDeployCLIError("deployment runtime config schema is not closed")
        if value["schema_version"] != RUNTIME_SCHEMA:
            raise VMDeployCLIError("unsupported deployment runtime config")
        service_name = _stable(value["service_name"], "service_name")
        if service_name != "QuantResearchHub":
            raise VMDeployCLIError("production service name must be QuantResearchHub")
        if value["base_url"] != "http://127.0.0.1:8765":
            raise VMDeployCLIError("deployment probe base_url must remain loopback:8765")
        if value["listen_host"] != "0.0.0.0" or value["port"] != 8765:
            raise VMDeployCLIError("production service listener must remain 0.0.0.0:8765")

        def release_relative(name: str) -> str:
            raw = value[name]
            if (
                not isinstance(raw, str)
                or not raw
                or "\\" in raw
                or Path(raw).is_absolute()
                or ".." in Path(raw).parts
            ):
                raise VMDeployCLIError(f"{name} is not a closed release-relative path")
            return Path(raw).as_posix()

        expected_service_entry = (
            "tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py"
        )
        if value["service_entry_relative_path"] != expected_service_entry:
            raise VMDeployCLIError("service entry is not the fixed D tooling path")
        release_paths = {
            name: release_relative(name)
            for name in (
                "application_source_relative_path",
                "archive_root_relative_path", "var_root_relative_path",
                "migration_root_relative_path",
            )
        }
        expected_state_paths = {
            "access_password_digest_path": "state/viewer_access_password.digest",
            "session_key_path": "state/viewer_secret.key",
            "comment_database_path": "state/comments.sqlite3",
            "workspace_database_path": "state/research_workspace.sqlite3",
        }
        if any(value[name] != expected for name, expected in expected_state_paths.items()):
            raise VMDeployCLIError("service mutable state paths are not the closed D state layout")
        paths = value["critical_paths"]
        if (
            not isinstance(paths, list)
            or not paths
            or len(set(paths)) != len(paths)
            or any(
                not isinstance(item, str)
                or re.fullmatch(r"/[A-Za-z0-9/_-]*", item) is None
                or ".." in item
                for item in paths
            )
        ):
            raise VMDeployCLIError("critical_paths are invalid")
        if paths != ["/login", "/api/v1/research", "/api/v1/dashboard"]:
            raise VMDeployCLIError("production critical_paths are not the fixed read-only set")
        raw_write_paths = value["write_paths"]
        if not isinstance(raw_write_paths, list) or any(
            not isinstance(item, str) for item in raw_write_paths
        ):
            raise VMDeployCLIError("production write_paths are invalid")
        try:
            write_paths = tuple(
                validate_production_vm_write_path(item, allow_root=False)
                for item in raw_write_paths
            )
        except VMBoundaryError as error:
            raise VMDeployCLIError("production write_paths escape VM_ROOT") from error
        declared = {
            PureWindowsPath(item)
            for item in declared_production_vm_write_set().values()
        }
        if len(write_paths) != len(declared) or set(write_paths) != declared:
            raise VMDeployCLIError("production write_paths do not equal the closed write set")
        writer_authority = _stable(value["writer_authority"], "writer_authority")
        if writer_authority != "D-active":
            raise VMDeployCLIError("production writer authority must be D-active")
        runtime = cls(
            root=root,
            service_name=service_name,
            base_url=str(value["base_url"]),
            listen_host=str(value["listen_host"]),
            port=int(value["port"]),
            critical_paths=tuple(paths),
            writer_authority=writer_authority,
            service_entry_relative_path=expected_service_entry,
            application_source_relative_path=release_paths["application_source_relative_path"],
            archive_root_relative_path=release_paths["archive_root_relative_path"],
            var_root_relative_path=release_paths["var_root_relative_path"],
            migration_root_relative_path=release_paths["migration_root_relative_path"],
            access_password_digest_path=expected_state_paths["access_password_digest_path"],
            session_key_path=expected_state_paths["session_key_path"],
            comment_database_path=expected_state_paths["comment_database_path"],
            workspace_database_path=expected_state_paths["workspace_database_path"],
            write_paths=write_paths,
        )
        snapshot = tuple(
            getattr(runtime, name) for name in runtime.__dataclass_fields__
        )
        _LIVE_PRODUCTION_WINDOWS_RUNTIMES[id(runtime)] = (runtime, snapshot)
        return runtime

    def _assert_production_provenance(self) -> None:
        expected = _LIVE_PRODUCTION_WINDOWS_RUNTIMES.get(id(self))
        current = tuple(
            getattr(self, name) for name in self.__dataclass_fields__
        )
        if (
            type(self) is not WindowsServiceRuntime
            or expected is None
            or expected[0] is not self
            or len(expected[1]) != len(current)
            or any(
                before is not after
                if callable(before) or callable(after)
                else before != after
                for before, after in zip(expected[1], current)
            )
            or self.allow_test_root
            or self.candidate_python is not None
            or self.candidate_popen_factory is not subprocess.Popen
            or self.candidate_probe_rmtree is not shutil.rmtree
            or self.candidate_cleanup_retry_seconds != 5.0
            or self.candidate_login_password_transform("fixed") != "fixed"
            or str(self.root) != str(PRODUCTION_VM_ROOT)
            or self.service_name != "QuantResearchHub"
            or self.base_url != "http://127.0.0.1:8765"
            or self.listen_host != "0.0.0.0"
            or self.port != 8765
            or self.writer_authority != "D-active"
        ):
            raise VMDeployCLIError("production Windows runtime provenance differs")

    def state_compatibility_probe(self, release: Mapping[str, object]) -> bool:
        state = release.get("state")
        compatibility = state.get("compatibility") if isinstance(state, dict) else None
        if not isinstance(compatibility, dict):
            return False
        expected_fields = {"comments", "research_workspace", "rollback_policy"}
        if set(compatibility) != expected_fields:
            return False
        if compatibility.get("rollback_policy") != "expand_only_no_down_migration":
            return False
        databases = {
            "comments": self.root / "state" / "comments.sqlite3",
            "research_workspace": self.root / "state" / "research_workspace.sqlite3",
        }
        for name, database in databases.items():
            contract = compatibility.get(name)
            if not isinstance(contract, dict) or set(contract) != {"read", "write"}:
                return False
            readable = contract.get("read")
            writable = contract.get("write")
            if (
                not isinstance(readable, list)
                or not readable
                or not isinstance(writable, list)
                or not writable
                or any(
                    not isinstance(version, int) or isinstance(version, bool) or version < 1
                    for version in (*readable, *writable)
                )
            ):
                return False
            if not database.is_file():
                return False
            try:
                ensure_no_reparse_components(database)
                if not database.resolve(strict=True).is_relative_to(
                    self.root.resolve(strict=True)
                ):
                    return False
            except OSError:
                return False
            try:
                header = database.read_bytes()[:100]
                if len(header) != 100 or header[:16] != b"SQLite format 3\x00":
                    return False
                # ``user_version`` is the unsigned big-endian word at offset
                # 60. Reading the file header cannot create WAL/SHM sidecars in
                # a quiescent restored checkpoint.
                version = int.from_bytes(header[60:64], "big", signed=False)
            except (OSError, TypeError, ValueError):
                return False
            if version not in readable:
                return False
        return True

    @staticmethod
    def _sqlite_source_identity(source: Path) -> tuple[tuple[str, int, str], ...]:
        rows: list[tuple[str, int, str]] = []
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(source) + suffix)
            if not candidate.exists():
                continue
            ensure_no_reparse_components(candidate)
            payload = candidate.read_bytes()
            rows.append((suffix, len(payload), hashlib.sha256(payload).hexdigest()))
        return tuple(rows)

    @staticmethod
    def _sqlite_source_path_identity(
        source: Path,
    ) -> tuple[tuple[str, int, int], ...]:
        """Identify the exact main/WAL/SHM filesystem objects without bytes."""

        rows: list[tuple[str, int, int]] = []
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(source) + suffix)
            if not candidate.exists():
                continue
            ensure_no_reparse_components(candidate)
            observed = os.lstat(candidate)
            if (
                not stat.S_ISREG(observed.st_mode)
                or stat_is_reparse_point(observed)
                or getattr(observed, "st_nlink", 1) != 1
            ):
                raise VMDeployCLIError(
                    "candidate SQLite path identity is not exact regular material"
                )
            rows.append((suffix, int(observed.st_dev), int(observed.st_ino)))
        if not rows or rows[0][0] != "":
            raise VMDeployCLIError("candidate SQLite main file is absent")
        return tuple(rows)

    @staticmethod
    def _online_copy(source: Path, destination: Path) -> None:
        before = WindowsServiceRuntime._sqlite_source_identity(source)
        suffixes = {row[0] for row in before}
        # A freshly restored checkpoint has no sidecars. Immutable mode then
        # copies the exact main database without manufacturing WAL/SHM in
        # production state. A running D writer already owns sidecars; SQLite's
        # backup API provides the consistent snapshot while concurrent writes
        # remain allowed.
        immutable_source = suffixes == {""}
        query = "mode=ro&immutable=1" if immutable_source else "mode=ro"
        source_connection = sqlite3.connect(
            f"file:{source.resolve().as_posix()}?{query}", uri=True, timeout=30
        )
        destination_connection = sqlite3.connect(destination, timeout=30)
        try:
            source_connection.backup(destination_connection, pages=256, sleep=0.01)
            destination_connection.commit()
        finally:
            destination_connection.close()
            source_connection.close()
        if immutable_source and WindowsServiceRuntime._sqlite_source_identity(source) != before:
            raise VMDeployCLIError("candidate checkpoint changed production SQLite identity")

    @staticmethod
    def _online_copy_bytes(source: Path) -> bytes:
        """Capture one consistent candidate snapshot without a destination path."""

        path_identity_before = WindowsServiceRuntime._sqlite_source_path_identity(
            source
        )
        before = WindowsServiceRuntime._sqlite_source_identity(source)
        suffixes = {row[0] for row in before}
        immutable_source = suffixes == {""}
        query = "mode=ro&immutable=1" if immutable_source else "mode=ro"
        source_connection = sqlite3.connect(
            f"file:{source.resolve().as_posix()}?{query}", uri=True, timeout=30
        )
        destination_connection = sqlite3.connect(":memory:", timeout=30)
        try:
            source_connection.backup(
                destination_connection, pages=256, sleep=0.01
            )
            destination_connection.commit()
            raw = bytes(destination_connection.serialize())
        finally:
            destination_connection.close()
            source_connection.close()
        if WindowsServiceRuntime._sqlite_source_path_identity(source) != (
            path_identity_before
        ):
            raise VMDeployCLIError(
                "candidate SQLite filesystem identity changed during online backup"
            )
        if (
            immutable_source
            and WindowsServiceRuntime._sqlite_source_identity(source) != before
        ):
            raise VMDeployCLIError(
                "candidate checkpoint changed production SQLite identity"
            )
        validation_raw = raw
        if (
            len(raw) >= 20
            and raw.startswith(b"SQLite format 3\x00")
            and raw[18:20] == b"\x02\x02"
        ):
            normalized = bytearray(raw)
            normalized[18:20] = b"\x01\x01"
            validation_raw = bytes(normalized)
        check = sqlite3.connect(":memory:", timeout=30)
        try:
            check.deserialize(validation_raw)
            if [str(row[0]) for row in check.execute("PRAGMA integrity_check")] != [
                "ok"
            ] or list(check.execute("PRAGMA foreign_key_check")):
                raise VMDeployCLIError("candidate checkpoint bytes are invalid")
        finally:
            check.close()
        return raw

    @staticmethod
    def _loopback_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            return int(listener.getsockname()[1])

    @staticmethod
    def _get_at(base_url: str, path: str) -> tuple[int, bytes]:
        try:
            with urlopen(Request(base_url + path, method="GET"), timeout=5) as response:
                return int(response.status), response.read(1024 * 1024 + 1)
        except Exception:
            return 0, b""

    @staticmethod
    def _authenticated_surfaces(
        base_url: str,
        password: str,
        critical_paths: tuple[str, ...],
    ) -> tuple[bool, bool, bool]:
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )
        try:
            login = urllib.request.Request(
                base_url + "/login",
                data=urllib.parse.urlencode(
                    {"password": password, "next": "/"}
                ).encode("utf-8"),
                method="POST",
            )
            with opener.open(login, timeout=5) as response:
                login_ok = (
                    int(response.status) == 200
                    and urllib.parse.urlsplit(response.geturl()).path == "/"
                    and bool(response.read(1024 * 1024))
                )
            with opener.open(base_url + "/", timeout=5) as response:
                home_ok = (
                    int(response.status) == 200
                    and urllib.parse.urlsplit(response.geturl()).path == "/"
                    and bool(response.read(1024 * 1024))
                )
            with opener.open(base_url + "/static/styles.css", timeout=5) as response:
                resource_ok = (
                    int(response.status) == 200
                    and urllib.parse.urlsplit(response.geturl()).path
                    == "/static/styles.css"
                    and bool(response.read(1024 * 1024))
                )
            def api_json(path: str) -> Mapping[str, object] | None:
                with opener.open(base_url + path, timeout=5) as response:
                    if (
                        int(response.status) != 200
                        or urllib.parse.urlsplit(response.geturl()).path != path
                    ):
                        return None
                    value = json.loads(response.read(1024 * 1024).decode("utf-8"))
                    return value if isinstance(value, dict) else None

            research = api_json("/api/v1/research")
            dashboard = api_json("/api/v1/dashboard")
            research_data = research.get("data") if isinstance(research, dict) else None
            dashboard_data = dashboard.get("data") if isinstance(dashboard, dict) else None
            research_items = (
                research_data.get("research") if isinstance(research_data, dict) else None
            )
            topics = (
                dashboard_data.get("topics") if isinstance(dashboard_data, dict) else None
            )
            api_ok = (
                isinstance(research_items, list)
                and bool(research_items)
                and all(isinstance(item, dict) for item in research_items)
                and isinstance(topics, list)
                and all(isinstance(item, dict) for item in topics)
            )
            declared = set(critical_paths)
            api_ok = api_ok and {
                "/login", "/api/v1/research", "/api/v1/dashboard"
            }.issubset(declared)
            return login_ok and home_ok, api_ok, resource_ok
        except Exception:
            return False, False, False

    def candidate_probe(
        self, path: Path, identity: Mapping[str, object]
    ) -> Mapping[str, object]:
        """Run exact R on loopback with disposable checkpoint state.

        This never uses SCM, the production port, the active pointer, or the
        production SQLite files after their online backup has completed.
        """

        release_id = _stable(identity.get("release_id"), "candidate release_id")
        manifest_hash = _digest(
            identity.get("manifest_sha256"), "candidate manifest_sha256"
        )
        snapshot_id = _stable(identity.get("snapshot_id"), "candidate snapshot_id")
        expected_paths = {
            (self.root / "releases" / release_id).resolve(strict=False),
            (self.root / "incoming" / f"{release_id}.partial").resolve(
                strict=False
            ),
        }
        expected_path = path.resolve(strict=True)
        if expected_path not in expected_paths:
            raise VMDeployCLIError(
                "candidate probe path differs from exact finalized/incoming release"
            )
        probe_parent = self.root / "tmp" / "candidate-probes"
        probe_root = probe_parent / f"{release_id}-{manifest_hash[:16]}"
        state = probe_root / "state"
        temporary = probe_root / "tmp"
        logs = probe_root / "logs"
        production_safe_root: _SafeRoot | None = None
        production_parent_stack = ExitStack()
        production_probe_stack = ExitStack()
        production_child_stack = ExitStack()
        probe_parent_bound: _BoundDirectory | None = None
        probe_root_bound: _BoundDirectory | None = None
        state_bound: _BoundDirectory | None = None
        logs_bound: _BoundDirectory | None = None
        probe_parent_identity: tuple[str, int, int] | None = None
        probe_root_identity: tuple[str, int, int] | None = None
        try:
            if self.allow_test_root:
                probe_parent.mkdir(parents=True, exist_ok=True)
                ensure_no_reparse_components(probe_parent)
                if probe_root.exists():
                    raise VMDeployCLIError("candidate probe identity already exists")
                probe_root.mkdir()
                for directory in (state, temporary, logs):
                    directory.mkdir()
                    ensure_no_reparse_components(directory)
                probe_parent_identity = _probe_directory_identity(
                    probe_parent, label="candidate probe parent"
                )
                probe_root_identity = _probe_directory_identity(
                    probe_root, label="candidate probe root"
                )
            else:
                production_safe_root = _SafeRoot(
                    self.root, allow_posix_test_only=False
                )
                tmp = self.root / "tmp"
                production_safe_root.preflight(
                    tmp, expected_kind="directory", allow_absent=False
                )
                tmp_bound = production_parent_stack.enter_context(
                    _BoundDirectory(
                        production_safe_root, tmp, protect_rename=True
                    )
                )
                if production_safe_root.preflight(
                    probe_parent, expected_kind="directory", allow_absent=True
                ) is None:
                    tmp_bound.mkdir("candidate-probes", 0o700)
                production_safe_root.preflight(
                    probe_parent, expected_kind="directory", allow_absent=False
                )
                probe_parent_bound = production_parent_stack.enter_context(
                    _BoundDirectory(
                        production_safe_root,
                        probe_parent,
                        protect_rename=True,
                    )
                )
                if production_safe_root.preflight(
                    probe_root, expected_kind="directory", allow_absent=True
                ) is not None:
                    raise VMDeployCLIError("candidate probe identity already exists")
                probe_parent_bound.mkdir(probe_root.name, 0o700)
                production_safe_root.preflight(
                    probe_root, expected_kind="directory", allow_absent=False
                )
                probe_root_bound = production_probe_stack.enter_context(
                    _BoundDirectory(
                        production_safe_root,
                        probe_root,
                        protect_rename=True,
                    )
                )
                for directory in (state, temporary, logs):
                    probe_root_bound.mkdir(directory.name, 0o700)
                    production_safe_root.preflight(
                        directory,
                        expected_kind="directory",
                        allow_absent=False,
                    )
                    bound = production_child_stack.enter_context(
                        _BoundDirectory(
                            production_safe_root,
                            directory,
                            protect_rename=True,
                        )
                    )
                    if directory == state:
                        state_bound = bound
                    elif directory == logs:
                        logs_bound = bound
                production_parent_stack.enter_context(
                    _BoundDirectory(
                        production_safe_root,
                        expected_path,
                        protect_rename=True,
                    )
                )
                _pin_candidate_tree(
                    production_parent_stack,
                    safe_root=production_safe_root,
                    tree_root=expected_path,
                )
                production_parent_stack.enter_context(
                    _BoundDirectory(
                        production_safe_root,
                        self.root / "state",
                        protect_rename=True,
                    )
                )
        except Exception:
            production_child_stack.close()
            if (
                production_safe_root is not None
                and probe_root_bound is not None
                and probe_parent_bound is not None
            ):
                try:
                    _remove_bound_directory_contents(
                        safe_root=production_safe_root,
                        directory=probe_root_bound,
                        path=probe_root,
                    )
                except Exception:
                    pass
                production_probe_stack.close()
                try:
                    probe_parent_bound.rmdir(probe_root.name)
                except Exception:
                    pass
            else:
                production_probe_stack.close()
            production_parent_stack.close()
            raise
        active_path = self.root / "control" / "active_release.json"
        if not self.allow_test_root and active_path.exists():
            assert production_safe_root is not None
            production_parent_stack.enter_context(
                _pin_regular_file(active_path, os.lstat(active_path))
            )
        active_before = active_path.read_bytes() if active_path.exists() else None
        process: subprocess.Popen[bytes] | None = None
        evidence: dict[str, object] | None = None
        probe_failure: Exception | None = None
        try:
            for source_name, destination_name in (
                ("comments.sqlite3", "comments.sqlite3"),
                ("research_workspace.sqlite3", "research_workspace.sqlite3"),
            ):
                if self.allow_test_root:
                    self._online_copy(
                        self.root / "state" / source_name,
                        state / destination_name,
                    )
                else:
                    assert state_bound is not None
                    source = self.root / "state" / source_name
                    with _pin_live_candidate_sqlite_members(source):
                        snapshot_raw = self._online_copy_bytes(source)
                    _write_new_bound_file(
                        state_bound,
                        name=destination_name,
                        raw=snapshot_raw,
                        label=f"candidate {destination_name}",
                    )
            one_time_password = secrets.token_urlsafe(32)
            password_raw = (
                derive_password_digest(one_time_password).hex() + "\n"
            ).encode("ascii")
            if self.allow_test_root:
                (state / "viewer_access_password.digest").write_bytes(
                    password_raw
                )
            else:
                assert state_bound is not None
                _write_new_bound_file(
                    state_bound,
                    name="viewer_access_password.digest",
                    raw=password_raw,
                    label="candidate access password",
                )
            port = self._loopback_port()
            base_url = f"http://127.0.0.1:{port}"
            configured_entry = self.root.joinpath(
                *Path(self.service_entry_relative_path).parts
            ).resolve(strict=True)
            ensure_no_reparse_components(configured_entry)
            if self.allow_test_root:
                if self.candidate_python is None:
                    raise VMDeployCLIError(
                        "test candidate probe requires explicit test Python"
                    )
                python = self.candidate_python.resolve(strict=True)
                if python != Path(sys.executable).resolve(strict=True):
                    raise VMDeployCLIError(
                        "candidate Python injection is not the closed test interpreter"
                    )
                entry = configured_entry
            else:
                if self.candidate_python is not None:
                    raise VMDeployCLIError(
                        "production candidate probe forbids Python injection"
                    )
                try:
                    bindings = verify_installed_operational_bindings(self.root)
                except (WindowsServiceError, OSError) as error:
                    raise VMDeployCLIError(
                        "candidate operational tooling binding is invalid"
                    ) from error
                python = bindings["service_python"]
                entry = bindings["service_entry_module"]
                if entry != configured_entry:
                    raise VMDeployCLIError(
                        "candidate service entry differs from install binding"
                    )
                assert production_safe_root is not None
                production_parent_stack.enter_context(
                    _BoundDirectory(
                        production_safe_root,
                        entry.parent,
                        protect_rename=True,
                    )
                )
                production_parent_stack.enter_context(
                    _BoundDirectory(
                        production_safe_root,
                        python.parent,
                        protect_rename=True,
                    )
                )
                _pin_candidate_tree(
                    production_parent_stack,
                    safe_root=production_safe_root,
                    tree_root=bindings["quant_hub_package_root"],
                )
                production_parent_stack.enter_context(
                    _pin_regular_file(python, os.lstat(python))
                )
                # The entry is normally in the package tree; retain an exact
                # direct pin as an explicit launch identity boundary.
                production_parent_stack.enter_context(
                    _pin_regular_file(entry, os.lstat(entry))
                )
            environment = {
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPYCACHEPREFIX": str(temporary / "pycache"),
                "TEMP": str(temporary),
                "TMP": str(temporary),
            }
            with ExitStack() as log_stack:
                if self.allow_test_root:
                    stdout = log_stack.enter_context(
                        (logs / "stdout.log").open("wb")
                    )
                    stderr = log_stack.enter_context(
                        (logs / "stderr.log").open("wb")
                    )
                else:
                    assert logs_bound is not None
                    flags = (
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_BINARY", 0)
                    )
                    stdout = log_stack.enter_context(
                        os.fdopen(
                            logs_bound.open_file("stdout.log", flags, 0o600),
                            "wb",
                        )
                    )
                    stderr = log_stack.enter_context(
                        os.fdopen(
                            logs_bound.open_file("stderr.log", flags, 0o600),
                            "wb",
                        )
                    )
                arguments = [
                        str(python), "-I", "-B", str(entry),
                        "--vm-root", str(self.root),
                        "--release-id", release_id,
                        "--manifest-sha256", manifest_hash,
                        "--candidate-probe-root", str(probe_root),
                        "--candidate-port", str(port),
                        "--candidate-release-root", str(expected_path),
                    ]
                if self.allow_test_root:
                    arguments.append("--test-root")
                    environment["QRH_TEST_ONLY_ALLOW_NONPRODUCTION_ROOT"] = "1"
                process = self.candidate_popen_factory(
                    arguments,
                    shell=False,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    env=environment,
                )
                deployment: Mapping[str, object] | None = None
                deadline = time.monotonic() + 45
                while time.monotonic() < deadline:
                    status, body = self._get_at(base_url, "/deploymentz")
                    if status == 200:
                        try:
                            value = json.loads(body.decode("utf-8"))
                        except (UnicodeError, json.JSONDecodeError):
                            value = None
                        if isinstance(value, dict):
                            deployment = value
                            break
                    if process.poll() is not None:
                        break
                    time.sleep(0.25)
                health = bool(
                    deployment
                    and deployment.get("release_id") == release_id
                    and deployment.get("manifest_sha256") == manifest_hash
                    and deployment.get("snapshot_id") == snapshot_id
                    and deployment.get("writer_authority")
                    == "candidate-checkpoint-isolated"
                    and deployment.get("port") == port
                )
                browser, api, resource = self._authenticated_surfaces(
                    base_url,
                    self.candidate_login_password_transform(one_time_password),
                    tuple(dict.fromkeys(self.critical_paths)),
                )
                if not (health and browser and api and resource):
                    raise VMDeployCLIError("candidate loopback browser/API probe failed")
                evidence = {
                    "schema_version": "qrh-candidate-probe-evidence/v1",
                    "release_id": release_id,
                    "manifest_sha256": manifest_hash,
                    "snapshot_id": snapshot_id,
                    "transport": "loopback_isolated",
                    "writer_authority": "candidate-checkpoint-isolated",
                    "health": True,
                    "browser": True,
                    "api": True,
                    "resource": True,
                    "state_isolated": True,
                    "active_unchanged": active_path.read_bytes()
                    == active_before if active_path.exists() else active_before is None,
                    "cleaned": False,
                }
        except Exception as error:
            probe_failure = error
        finally:
            resource_failure: Exception | None = None
            if process is not None:
                try:
                    _settle_candidate_process(process)
                except Exception as error:
                    resource_failure = error
                finally:
                    process = None
            cleanup_failure: Exception | None = None
            try:
                if self.allow_test_root:
                    assert probe_parent_identity is not None
                    assert probe_root_identity is not None
                    _remove_candidate_probe_root(
                        probe_parent=probe_parent,
                        probe_root=probe_root,
                        expected_parent_identity=probe_parent_identity,
                        expected_root_identity=probe_root_identity,
                        remove=self.candidate_probe_rmtree,
                        retry_seconds=self.candidate_cleanup_retry_seconds,
                    )
                else:
                    assert production_safe_root is not None
                    assert probe_parent_bound is not None
                    assert probe_root_bound is not None
                    production_child_stack.close()
                    _remove_bound_directory_contents(
                        safe_root=production_safe_root,
                        directory=probe_root_bound,
                        path=probe_root,
                    )
                    production_probe_stack.close()
                    probe_parent_bound.rmdir(probe_root.name)
            except Exception as error:
                cleanup_failure = error
            finally:
                if not self.allow_test_root:
                    try:
                        production_child_stack.close()
                    except Exception as error:
                        cleanup_failure = cleanup_failure or error
                    try:
                        production_probe_stack.close()
                    except Exception as error:
                        cleanup_failure = cleanup_failure or error
                    try:
                        production_parent_stack.close()
                    except Exception as error:
                        cleanup_failure = cleanup_failure or error
            if cleanup_failure is not None:
                if resource_failure is not None:
                    cleanup_failure.add_note(
                        f"candidate process/log cleanup also failed: {resource_failure}"
                    )
                if probe_failure is not None:
                    raise cleanup_failure from probe_failure
                if resource_failure is not None:
                    raise cleanup_failure from resource_failure
                raise cleanup_failure
            if resource_failure is not None:
                if probe_failure is not None:
                    raise resource_failure from probe_failure
                raise resource_failure
        if probe_failure is not None:
            raise probe_failure.with_traceback(probe_failure.__traceback__)
        if evidence is None or evidence["active_unchanged"] is not True:
            raise VMDeployCLIError("candidate probe did not preserve active authority")
        evidence["cleaned"] = not probe_root.exists()
        return evidence

    def _service(
        self,
        action: str,
        *,
        allow_failure: bool = False,
        start_authorization: tuple[str, str, str] | None = None,
        exact_start_arguments: tuple[str, ...] | None = None,
    ) -> bool:
        temporary = self.root / "tmp" / "deployment-cli"
        temporary.mkdir(parents=True, exist_ok=True)
        ensure_no_reparse_components(temporary)
        arguments = ["sc.exe", action, self.service_name]
        if start_authorization is not None and exact_start_arguments is not None:
            raise VMDeployCLIError("service start authorization is ambiguous")
        if start_authorization is not None:
            if action != "start":
                raise VMDeployCLIError(
                    "pending activation authorization is start-only"
                )
            arguments.extend(("pending-activation", *start_authorization))
        if exact_start_arguments is not None:
            if action != "start" or not exact_start_arguments:
                raise VMDeployCLIError("exact runtime authorization is start-only")
            arguments.extend(exact_start_arguments)
        completed = subprocess.run(
            arguments,
            shell=False,
            check=False,
            capture_output=True,
            env={
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPYCACHEPREFIX": str(temporary / "pycache"),
                "TEMP": str(temporary),
                "TMP": str(temporary),
            },
        )
        if completed.returncode and not allow_failure:
            return False
        return True

    def start_release(self, _path: Path, _active: Mapping[str, object]) -> bool:
        del _path, _active
        raise VMDeployCLIError(
            "legacy v1 activation is sealed; use a live v4 exact transient authorization"
        )

    def start_exact_transient(self, authorization: object) -> bool:
        """Consume one live B2 authorization and pass only its closed SCM argv.

        The capability itself never crosses into SCM.  The service host rebuilds
        the identity from the closed argv and independently pins the matching
        fixed-D v4 journal before CreateJob/CreateProcess/ResumeThread.
        """

        from .local_deployment_persistence import (
            LockedExactTransientStartAuthorization,
        )
        from .local_windows_writer_lease_holder import ExactRuntimeLeaseIdentity

        if type(authorization) is not LockedExactTransientStartAuthorization:
            raise VMDeployCLIError(
                "exact transient start requires a live B2 authorization"
            )
        reference = authorization.release_ref
        identity = ExactRuntimeLeaseIdentity(
            attempt_id=authorization.attempt_id,
            nonce=authorization.nonce,
            operation=authorization.operation,
            role=authorization.role,
            start_nonce=authorization.start_nonce,
            release_id=str(reference["release_id"]),
            manifest_sha256=str(reference["manifest_sha256"]),
            state_identity_sha256=authorization.state_identity_sha256,
        )
        if (
            identity.release_path != reference["release_path"]
            or identity.scm_identity_sha256 != authorization.scm_identity_sha256
            or identity.authorization_sha256 != authorization.authorization_sha256
        ):
            raise VMDeployCLIError(
                "live authorization differs from the exact SCM start identity"
            )
        self._service("stop", allow_failure=True)
        return self._service(
            "start", exact_start_arguments=identity.service_start_arguments
        )

    def _query_service_state(self) -> str | None:
        """Return the exact SCM state without using the HTTP child as authority."""

        temporary = self.root / "tmp" / "deployment-cli"
        temporary.mkdir(parents=True, exist_ok=True)
        ensure_no_reparse_components(temporary)
        completed = subprocess.run(
            ["sc.exe", "query", self.service_name],
            shell=False,
            check=False,
            capture_output=True,
            env={
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPYCACHEPREFIX": str(temporary / "pycache"),
                "TEMP": str(temporary),
                "TMP": str(temporary),
            },
        )
        if completed.returncode:
            return None
        output = (completed.stdout + completed.stderr).decode(
            "utf-8", errors="replace"
        )
        match = re.search(
            r"(?im)^\s*STATE\s*:\s*\d+\s+([A-Z_]+)\s*$", output
        )
        return None if match is None else match.group(1)

    def stop_exact_transient(self) -> None:
        """Stop the transient host and require SCM to prove ``STOPPED``."""

        self._service("stop", allow_failure=True)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self._query_service_state() == "STOPPED":
                return
            time.sleep(0.25)
        raise VMDeployCLIError("exact transient service did not reach SCM STOPPED")

    def start_steady_exact(self) -> bool:
        """Start ordinary exact steady mode and wait until admission is open."""

        if not self._service("start"):
            return False
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self._query_service_state() == "RUNNING":
                status, _body = self._get("/login")
                if status == 200:
                    return True
            time.sleep(0.25)
        return False

    def ensure_steady_exact(self, release: Mapping[str, object]) -> bool:
        """Idempotently prove or establish the exact active steady runtime.

        A lost controller response after SCM admission is not a reason to issue
        a second blind ``sc start``.  Existing RUNNING is accepted only when
        SCM and the live deployment/writer identity both match the journal's
        exact active release; every other state is stopped before one fresh
        steady start and an identical post-start proof.
        """

        if not isinstance(release, Mapping):
            raise VMDeployCLIError("steady release identity is not a mapping")
        release_id = _stable(release.get("release_id"), "steady release_id")
        manifest_sha256 = _digest(
            release.get("manifest_sha256"), "steady manifest_sha256"
        )
        expected_path = (self.root / "releases" / release_id).resolve(
            strict=True
        )
        declared_path = release.get("release_path")
        if type(declared_path) is not str:
            raise VMDeployCLIError("steady release_path is missing")
        if Path(declared_path).resolve(strict=True) != expected_path:
            raise VMDeployCLIError(
                "steady release_path differs from exact retained closure"
            )
        expected = {
            "release_id": release_id,
            "manifest_sha256": manifest_sha256,
        }

        def exact_running() -> bool:
            if self._query_service_state() != "RUNNING":
                return False
            identity_ok, writer_ok = self._deployment_identity(
                expected, expected_path
            )
            return identity_ok and writer_ok

        if exact_running():
            return True
        if self._query_service_state() != "STOPPED":
            self._service("stop", allow_failure=True)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if self._query_service_state() == "STOPPED":
                    break
                time.sleep(0.25)
            else:
                return False
        if not self.start_steady_exact():
            return False
        return exact_running()

    def observe_steady_exact(
        self, release: Mapping[str, object]
    ) -> Mapping[str, object]:
        """Return sealed live SCM/endpoint/writer material for failure closure."""

        from .local_release_identity import identity_sha256

        release_id = _stable(release.get("release_id"), "steady release_id")
        manifest_sha256 = _digest(
            release.get("manifest_sha256"), "steady manifest_sha256"
        )
        expected_path = (self.root / "releases" / release_id).resolve(
            strict=True
        )
        declared_path = release.get("release_path")
        if (
            type(declared_path) is not str
            or Path(declared_path).resolve(strict=True) != expected_path
        ):
            raise VMDeployCLIError(
                "steady observation release_path differs from exact closure"
            )
        scm_state = self._query_service_state()
        status, body = self._get("/deploymentz")
        if scm_state != "RUNNING" or status != 200 or len(body) > 1024 * 1024:
            raise VMDeployCLIError("steady observation is not live")
        try:
            endpoint = json.loads(body.decode("utf-8"))
            manifest = read_json(expected_path / "release_manifest.json")
        except (UnicodeError, json.JSONDecodeError, OSError) as error:
            raise VMDeployCLIError(
                "steady observation payload is invalid"
            ) from error
        content = manifest.get("content") if isinstance(manifest, dict) else None
        snapshot_id = (
            content.get("snapshot_id") if isinstance(content, dict) else None
        )
        if (
            not isinstance(endpoint, dict)
            or endpoint.get("release_id") != release_id
            or endpoint.get("manifest_sha256") != manifest_sha256
            or endpoint.get("snapshot_id") != snapshot_id
            or endpoint.get("writer_authority") != self.writer_authority
        ):
            raise VMDeployCLIError(
                "steady observation endpoint/writer identity differs"
            )
        observed: dict[str, object] = {
            "schema_version": "qrh-exact-steady-observation/v1",
            "scm_state": "RUNNING",
            "release": dict(release),
            "snapshot_id": snapshot_id,
            "writer_authority": self.writer_authority,
            "endpoint_response_sha256": hashlib.sha256(body).hexdigest(),
        }
        observed["evidence_sha256"] = identity_sha256(observed)
        return observed

    def observe_bootstrap_boundary(self) -> Mapping[str, object]:
        """Prove the post-canary/pre-terminal bootstrap boundary is closed.

        This is a fresh whole-machine observation: the exact D service must be
        stopped, port 8765 must have no listener, and no process command line
        may reference either legacy C writer root.  Only hashes and empty PID
        sets leave this boundary.
        """

        from .local_release_identity import identity_sha256

        if os.name != "nt":
            raise VMDeployCLIError(
                "production bootstrap boundary observation requires Windows"
            )
        if self._query_service_state() != "STOPPED":
            raise VMDeployCLIError(
                "bootstrap boundary requires exact D SCM service STOPPED"
            )
        temporary = self.root / "tmp" / "deployment-cli"
        temporary.mkdir(parents=True, exist_ok=True)
        ensure_no_reparse_components(temporary)
        environment = {
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPYCACHEPREFIX": str(temporary / "pycache"),
            "TEMP": str(temporary),
            "TMP": str(temporary),
        }

        def powershell_json(script: str) -> object:
            completed = subprocess.run(
                (
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    script,
                ),
                shell=False,
                check=False,
                capture_output=True,
                env=environment,
                timeout=20,
            )
            if completed.returncode:
                raise VMDeployCLIError(
                    "bootstrap boundary Windows observation failed"
                )
            raw = completed.stdout.decode("utf-8-sig", errors="strict").strip()
            return [] if not raw else json.loads(raw)

        listener_value = powershell_json(
            "@(Get-NetTCPConnection -State Listen -LocalPort 8765 "
            "-ErrorAction SilentlyContinue|Select-Object -ExpandProperty "
            "OwningProcess -Unique|Sort-Object)|ConvertTo-Json -Compress"
        )
        listener_rows = (
            listener_value if isinstance(listener_value, list) else [listener_value]
        )
        listener_pids = sorted(
            {int(value) for value in listener_rows if int(value) > 0}
        )
        legacy_value = powershell_json(
            "@(Get-CimInstance Win32_Process -ErrorAction Stop|"
            "Where-Object {$_.ProcessId -ne $PID -and $_.CommandLine -and "
            "($_.CommandLine -match '(?i)C:\\\\quant_platform(?:_data)?(?:\\\\|$)')}|"
            "Select-Object -ExpandProperty ProcessId -Unique|Sort-Object)|"
            "ConvertTo-Json -Compress"
        )
        legacy_rows = (
            legacy_value if isinstance(legacy_value, list) else [legacy_value]
        )
        legacy_pids = sorted(
            {int(value) for value in legacy_rows if int(value) > 0}
        )
        if listener_pids or legacy_pids:
            raise VMDeployCLIError(
                "bootstrap boundary still has ingress or legacy C writer"
            )
        ingress = {
            "scm_state": "STOPPED",
            "listen_host": self.listen_host,
            "port": self.port,
            "listener_pids": listener_pids,
        }
        legacy = {
            "legacy_roots": [r"C:\quant_platform", r"C:\quant_platform_data"],
            "process_pids": legacy_pids,
            "status": "fenced",
        }
        observation: dict[str, object] = {
            "schema_version": "qrh-bootstrap-boundary-observation/v1",
            "ingress": ingress,
            "legacy_c_writer": legacy,
            "ingress_closed_sha256": identity_sha256(ingress),
            "legacy_c_writer_fence_sha256": identity_sha256(legacy),
        }
        observation["evidence_sha256"] = identity_sha256(observation)
        return observation

    def stop_release(self, _path: Path) -> None:
        self._service("stop", allow_failure=True)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self._get("/deploymentz")[0] != 200:
                return
            time.sleep(0.25)
        raise VMDeployCLIError("service did not stop inside the rollback budget")

    def _get(self, path: str) -> tuple[int, bytes]:
        try:
            with urlopen(
                Request(self.base_url + path, method="GET"), timeout=10
            ) as response:
                return int(response.status), response.read(1024 * 1024 + 1)
        except Exception:
            return 0, b""

    def post_activation_probe(
        self, path: Path, active: Mapping[str, object]
    ) -> Mapping[str, bool]:
        identity_ok, writer_ok = self._deployment_identity(active, path)
        critical_ok = all(self._get(path)[0] == 200 for path in self.critical_paths)
        return {
            "health": identity_ok,
            "critical_functions": critical_ok,
            "writer_fence": writer_ok,
        }

    def _deployment_identity(
        self, active: Mapping[str, object], release_path: Path | None = None
    ) -> tuple[bool, bool]:
        status, body = self._get("/deploymentz")
        if status == 200 and len(body) <= 1024 * 1024:
            try:
                value = json.loads(body.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError):
                value = None
            if isinstance(value, dict):
                expected_snapshot = None
                if release_path is not None:
                    try:
                        release = read_json(release_path / "release_manifest.json")
                        content = release.get("content")
                        expected_snapshot = (
                            content.get("snapshot_id") if isinstance(content, dict) else None
                        )
                    except Exception:
                        expected_snapshot = None
                identity_ok = (
                    value.get("release_id") == active["release_id"]
                    and value.get("manifest_sha256") == active["manifest_sha256"]
                    and expected_snapshot is not None
                    and value.get("snapshot_id") == expected_snapshot
                )
                writer_ok = value.get("writer_authority") == self.writer_authority
                return identity_ok, writer_ok
        return False, False


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if raw_argv and raw_argv[0] == "rollback-prior":
        parser = argparse.ArgumentParser()
        parser.add_argument("rollback-prior")
        parser.add_argument("--vm-root", type=Path, required=True)
        parser.add_argument("--deployment-attempt-id", required=True)
        parser.add_argument("--json", action="store_true")
        args = parser.parse_args(raw_argv)
        try:
            root = verify_production_root(args.vm_root)
            before = capture_vm_write_snapshot(root)
            try:
                result = rollback_prior(
                    vm_root=root,
                    deployment_attempt_id=args.deployment_attempt_id,
                )
            except BaseException:
                finalize_vm_write_audit(
                    root,
                    before,
                    operation="rollback-prior",
                    outcome="failed",
                )
                raise
            finalize_vm_write_audit(
                root,
                before,
                operation="rollback-prior",
                outcome="succeeded",
            )
        except Exception as error:
            print(
                json.dumps(
                    {
                        "schema_version": "qrh-vm-deploy-error/v1",
                        "status": "error",
                        "error_type": type(error).__name__,
                    },
                    sort_keys=True,
                )
            )
            return 2
        print(json.dumps(result, sort_keys=True))
        return 0

    parser = argparse.ArgumentParser()
    parser.add_argument("apply-publish", nargs="?")
    parser.add_argument("--vm-root", type=Path, required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--release-manifest-sha256", required=True)
    parser.add_argument("--publish-candidate-sha256", required=True)
    parser.add_argument(
        "--deployment-mode", choices=("activate", "candidate_only"), required=True
    )
    parser.add_argument("--deployment-attempt-id")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(raw_argv)
    try:
        root = verify_production_root(args.vm_root)
        before = capture_vm_write_snapshot(root)
        _stable(args.release_id, "release_id")
        operation = f"deploy-{args.deployment_mode}"
        try:
            result = apply_publish(
                vm_root=root,
                release_id=args.release_id,
                release_manifest_sha256=args.release_manifest_sha256,
                publish_candidate_sha256=args.publish_candidate_sha256,
                deployment_mode=args.deployment_mode,
                deployment_attempt_id=args.deployment_attempt_id,
                hooks=None,
            )
        except BaseException:
            finalize_vm_write_audit(
                root, before, operation=operation, outcome="failed"
            )
            raise
        finalize_vm_write_audit(
            root, before, operation=operation, outcome="succeeded"
        )
    except DeploymentFailed as error:
        # Controller 已经写入唯一 failure receipt；stdout 只返回去敏身份。
        failure = error.result
        print(
            json.dumps(
                {
                    "schema_version": "qrh-vm-deploy-failure/v1",
                    "status": "failed",
                    "evidence_type": "failure_receipt",
                    "evidence_id": failure.receipt_id,
                    "rollback_attempted": failure.rollback_attempted,
                    "rollback_succeeded": failure.rollback_succeeded,
                },
                sort_keys=True,
            )
        )
        return 1
    except Exception as error:
        print(
            json.dumps(
                {
                    "schema_version": "qrh-vm-deploy-error/v1",
                    "status": "error",
                    "error_type": type(error).__name__,
                },
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
