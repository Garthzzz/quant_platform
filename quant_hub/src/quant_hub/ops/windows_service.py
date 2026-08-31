"""Minimal Windows-service supervisor for the single D-root active authority."""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import signal
import stat
import subprocess
import sys
import threading
from typing import Callable, Mapping, Protocol

# This reviewed module is installed under D-root tooling. Disable import-time
# bytecode writes even before the service child gets its closed environment.
sys.dont_write_bytecode = True

from quant_hub.config import ensure_no_reparse_components
from quant_hub.runtime_seal import read_json, write_atomic_new_json

from .deployment import DeploymentController
from .local_deployment_persistence import (
    UnsafeLocalPath,
    _BoundDirectory,
    _SafeRoot,
)
from .release_identity import (
    manifest_sha256,
    validate_active_release,
    validate_release_manifest,
)
from .vm_boundary import PRODUCTION_VM_ROOT, validate_production_vm_write_path


INSTALL_SCHEMA = "qrh-windows-service-install-candidate/v2"
SERVICE_CLASS = "quant_hub.ops.windows_service.QuantResearchHubWindowsService"
SERVICE_NAME = "QuantResearchHub"
WRITER_HANDOFF_JOURNAL_SCHEMA = "qrh-writer-handoff-pending/v4"


class WindowsServiceError(RuntimeError):
    pass


class WindowsServiceStatusOwnerCrashRequired(WindowsServiceError):
    """SCM status syscall outcome is unknown; only host exit is safe."""


@dataclass(frozen=True)
class ActiveServiceRelease:
    release_id: str
    manifest_sha256: str
    snapshot_id: str
    release_root: Path
    entry_path: Path


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def quant_hub_package_inventory_sha256(package_root: Path) -> str:
    """Canonical reviewed-project package inventory (third parties excluded)."""

    root = package_root.resolve(strict=True)
    ensure_no_reparse_components(root)
    records: list[str] = []
    for current, directories, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(
            name for name in directories if name.casefold() != "__pycache__"
        )
        for directory in directories:
            ensure_no_reparse_components(current_path / directory)
        for name in sorted(filenames):
            if name.casefold().endswith((".pyc", ".pyo")):
                continue
            path = current_path / name
            ensure_no_reparse_components(path)
            if not path.is_file():
                raise WindowsServiceError("quant_hub package contains a non-file")
            relative = path.relative_to(root).as_posix()
            records.append(
                f"{relative}\t{path.stat().st_size}\t{_hash_file(path)}\n"
            )
    digest = hashlib.sha256()
    for record in sorted(records):
        digest.update(record.encode("utf-8"))
    return digest.hexdigest()


def _expected_candidate_paths(root: Path) -> dict[str, Path]:
    tooling = root / "tooling" / "python"
    package = tooling / "Lib" / "site-packages"
    service_host = package / "quant_hub" / "ops" / "windows_service.py"
    return {
        "service_executable": tooling / "pythonservice.exe",
        "service_python_runtime": tooling / "python313.dll",
        "service_pywin32_runtime": tooling / "pywintypes313.dll",
        "service_python": tooling / "python.exe",
        "service_host_module": service_host,
        "service_entry_module": service_host.with_name("service_entry.py"),
        "deployment_cli_module": service_host.with_name("vm_deploy_cli.py"),
        "access_gate_module": package / "quant_hub" / "web" / "access_gate.py",
        "deployment_runtime": root / "control" / "deployment_runtime.json",
    }


def _validate_install_candidate_paths(
    root: Path, candidate: "ServiceInstallCandidate"
) -> None:
    physical = root.resolve(strict=True)
    ensure_no_reparse_components(physical)
    if candidate.service_name != SERVICE_NAME or candidate.python_class != SERVICE_CLASS:
        raise WindowsServiceError("service identity is not the reviewed fixed identity")
    for field, expected in _expected_candidate_paths(physical).items():
        observed = getattr(candidate, field).resolve(strict=True)
        expected_resolved = expected.resolve(strict=True)
        ensure_no_reparse_components(observed)
        if observed != expected_resolved or not observed.is_relative_to(physical):
            raise WindowsServiceError(f"{field} is outside the reviewed D-root layout")
        if PureWindowsPath(str(physical)) == PRODUCTION_VM_ROOT:
            validate_production_vm_write_path(str(observed), allow_root=False)
    expected_package = (
        physical / "tooling" / "python" / "Lib" / "site-packages" / "quant_hub"
    ).resolve(strict=True)
    observed_package = candidate.quant_hub_package_root.resolve(strict=True)
    ensure_no_reparse_components(observed_package)
    if observed_package != expected_package or not observed_package.is_relative_to(physical):
        raise WindowsServiceError("quant_hub package root is outside reviewed D-root")


def verify_installed_operational_bindings(root: Path) -> Mapping[str, Path]:
    """Read-only verification of every executable operational binding.

    The service module has necessarily been imported by Python before this
    function can run.  Consequently this is the earliest in-module integrity
    boundary: callers must invoke it before creating temp/log/state, starting a
    child, or calling deployment code.
    """

    physical = root.resolve(strict=True)
    ensure_no_reparse_components(physical)
    candidate_path = physical / "control" / "service_install_candidate.json"
    ensure_no_reparse_components(candidate_path)
    candidate = read_json(candidate_path)
    expected_paths = {
        name: path.resolve(strict=True)
        for name, path in _expected_candidate_paths(physical).items()
    }
    package_root = (
        physical / "tooling" / "python" / "Lib" / "site-packages" / "quant_hub"
    ).resolve(strict=True)
    expected_fields = {
        "schema_version", "service_name", "python_class", "start_type",
        "quant_hub_package_root", "quant_hub_package_inventory_sha256",
        *(name for field in expected_paths for name in (field, f"{field}_sha256")),
    }
    if (
        not isinstance(candidate, dict)
        or set(candidate) != expected_fields
        or candidate.get("schema_version") != INSTALL_SCHEMA
        or candidate.get("service_name") != SERVICE_NAME
        or candidate.get("python_class") != SERVICE_CLASS
        or candidate.get("start_type") != "automatic"
    ):
        raise WindowsServiceError("installed operational binding schema differs")
    for field, expected in expected_paths.items():
        ensure_no_reparse_components(expected)
        if (
            candidate.get(field) != str(expected)
            or candidate.get(f"{field}_sha256") != _hash_file(expected)
        ):
            raise WindowsServiceError(
                f"installed operational binding differs: {field}"
            )
    if (
        candidate.get("quant_hub_package_root") != str(package_root)
        or candidate.get("quant_hub_package_inventory_sha256")
        != quant_hub_package_inventory_sha256(package_root)
    ):
        raise WindowsServiceError("installed quant_hub package inventory differs")
    expected_paths["quant_hub_package_root"] = package_root
    return expected_paths


def validate_service_control_binding(
    candidate: "ServiceInstallCandidate",
    *,
    binary_path: str,
    python_class: str,
    start_type: int,
    automatic_start_type: int,
) -> bool:
    """Validate the actual SCM/registry binding without accepting arguments."""

    raw = binary_path.strip()
    if raw.startswith('"'):
        if len(raw) < 3 or not raw.endswith('"') or raw.count('"') != 2:
            return False
        raw = raw[1:-1]
    elif '"' in raw:
        return False
    try:
        executable_matches = (
            PureWindowsPath(raw) == PureWindowsPath(str(candidate.service_executable))
        )
    except (TypeError, ValueError):
        return False
    return (
        executable_matches
        and python_class == candidate.python_class
        and start_type == automatic_start_type
    )


class _ServiceHostDWriteOwner:
    """Lifetime owner for the SCM host's earliest temp/cache/log writes."""

    __slots__ = (
        "root",
        "tmp",
        "pycache",
        "_safe_root",
        "_stack",
        "_log_handle",
        "_log_path",
        "_closed",
    )

    def __init__(self, root: Path):
        physical = root.resolve(strict=True)
        if PureWindowsPath(str(physical)) != PRODUCTION_VM_ROOT or os.name != "nt":
            raise WindowsServiceError(
                r"service host root must be D:\quant\quant_platform on Windows"
            )
        self.root = physical
        self.tmp = physical / "tmp" / "service-host"
        self.pycache = self.tmp / "pycache"
        self._safe_root = _SafeRoot(physical, allow_posix_test_only=False)
        self._stack = ExitStack()
        self._log_handle: int | None = None
        self._log_path = physical / "logs" / "quant-research-hub-service.log"
        self._closed = False
        try:
            root_bound = self._stack.enter_context(
                _BoundDirectory(
                    self._safe_root,
                    physical,
                    protect_rename=True,
                )
            )

            def enter_or_create(
                parent: _BoundDirectory,
                path: Path,
                name: str,
            ) -> _BoundDirectory:
                validate_production_vm_write_path(str(path), allow_root=False)
                observed = self._safe_root.preflight(
                    path,
                    expected_kind="directory",
                    allow_absent=True,
                )
                if observed is None:
                    parent.mkdir(name, 0o700)
                self._safe_root.preflight(
                    path,
                    expected_kind="directory",
                    allow_absent=False,
                )
                return self._stack.enter_context(
                    _BoundDirectory(
                        self._safe_root,
                        path,
                        protect_rename=True,
                    )
                )

            tmp_root = physical / "tmp"
            tmp_root_bound = enter_or_create(root_bound, tmp_root, "tmp")
            service_host_bound = enter_or_create(
                tmp_root_bound,
                self.tmp,
                "service-host",
            )
            enter_or_create(service_host_bound, self.pycache, "pycache")
            logs = physical / "logs"
            logs_bound = enter_or_create(root_bound, logs, "logs")
            self._open_log(logs_bound)
        except BaseException:
            self.close()
            raise

    def _open_log(self, logs_bound: _BoundDirectory) -> None:
        import ctypes
        from ctypes import wintypes

        if logs_bound.path != self._log_path.parent:
            raise WindowsServiceError("service host log parent binding drifted")
        validate_production_vm_write_path(str(self._log_path), allow_root=False)
        existing = self._safe_root.preflight(
            self._log_path,
            expected_kind="file",
            allow_absent=True,
        )
        if existing is not None and getattr(existing, "st_nlink", 1) != 1:
            raise WindowsServiceError("service host log is not single-link")
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
        raw = kernel32.CreateFileW(
            str(self._log_path),
            0x00000004 | 0x00000080,  # FILE_APPEND_DATA | FILE_READ_ATTRIBUTES
            0x00000001,  # SHARE_READ only
            None,
            4,  # OPEN_ALWAYS
            0x00200000,  # OPEN_REPARSE_POINT
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if raw in {None, invalid}:
            raise WindowsServiceError("service host log cannot be opened exactly")
        self._log_handle = int(raw)
        if _BoundDirectory._windows_final_path(self._log_handle) != str(
            self._log_path
        ):
            raise WindowsServiceError("service host log final path drifted")
        observed = os.lstat(self._log_path)
        if (
            not stat.S_ISREG(observed.st_mode)
            or self._log_path.is_symlink()
            or getattr(observed, "st_nlink", 1) != 1
        ):
            raise WindowsServiceError("service host log is not exact regular material")

    def append_status(self, status: str) -> None:
        if self._closed or self._log_handle is None:
            raise WindowsServiceError("service host D-write owner is closed")
        if not status or any(
            character not in "abcdefghijklmnopqrstuvwxyz_0123456789"
            for character in status
        ):
            status = "host_failure"
        if _BoundDirectory._windows_final_path(self._log_handle) != str(
            self._log_path
        ):
            raise WindowsServiceError("service host log identity drifted")
        import ctypes
        from ctypes import wintypes

        payload = (status + "\n").encode("ascii")
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.WriteFile.argtypes = (
            wintypes.HANDLE,
            wintypes.LPCVOID,
            wintypes.DWORD,
            wintypes.LPDWORD,
            wintypes.LPVOID,
        )
        kernel32.WriteFile.restype = wintypes.BOOL
        written = wintypes.DWORD()
        buffer = ctypes.create_string_buffer(payload)
        if not kernel32.WriteFile(
            wintypes.HANDLE(self._log_handle),
            buffer,
            len(payload),
            ctypes.byref(written),
            None,
        ) or written.value != len(payload):
            raise WindowsServiceError("service host log append failed")
        kernel32.FlushFileBuffers.argtypes = (wintypes.HANDLE,)
        kernel32.FlushFileBuffers.restype = wintypes.BOOL
        if not kernel32.FlushFileBuffers(wintypes.HANDLE(self._log_handle)):
            raise WindowsServiceError("service host log flush failed")

    def close(self) -> None:
        if self._closed:
            return
        failure: BaseException | None = None
        if self._log_handle is not None:
            handle = self._log_handle
            try:
                _BoundDirectory._close_windows_handle(handle)
            except BaseException as error:
                failure = error
            else:
                self._log_handle = None
        try:
            self._stack.close()
        except BaseException as error:
            failure = failure or error
        if failure is not None or self._log_handle is not None:
            raise WindowsServiceError(
                "service host D-write owner did not close mechanically"
            ) from failure
        self._closed = True


def prepare_service_host_environment(root: Path) -> _ServiceHostDWriteOwner:
    """Bind the SCM host's D-write directories for its whole lifetime."""

    try:
        owner = _ServiceHostDWriteOwner(root)
    except (UnsafeLocalPath, OSError) as error:
        raise WindowsServiceError(
            "service host D-write environment cannot be bound"
        ) from error
    os.environ.update(
        {
            "TEMP": str(owner.tmp),
            "TMP": str(owner.tmp),
            "PYTHONPYCACHEPREFIX": str(owner.pycache),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    sys.dont_write_bytecode = True
    return owner


def resolve_active_service_release(root: Path) -> ActiveServiceRelease:
    physical = root.resolve(strict=True)
    ensure_no_reparse_components(physical)
    active = validate_active_release(read_json(physical / "control" / "active_release.json"))
    release_id = str(active["release_id"])
    release_root = (physical / "releases" / release_id).resolve(strict=True)
    ensure_no_reparse_components(release_root)
    if Path(str(active["release_path"])).resolve(strict=True) != release_root:
        raise WindowsServiceError("active release path is not the canonical D release path")
    manifest = validate_release_manifest(read_json(release_root / "release_manifest.json"))
    observed_hash = manifest_sha256(manifest)
    if manifest["release_id"] != release_id or active["manifest_sha256"] != observed_hash:
        raise WindowsServiceError("active pointer and immutable release identity differ")
    DeploymentController.for_test_only(physical).verify_finalized_release(
        release_id=release_id,
        expected_manifest_sha256=observed_hash,
    )
    runtime = read_json(physical / "control" / "deployment_runtime.json")
    relative = runtime.get("service_entry_relative_path") if isinstance(runtime, dict) else None
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise WindowsServiceError("service entry relative path is invalid")
    entry = physical.joinpath(*Path(relative).parts).resolve(strict=True)
    ensure_no_reparse_components(entry)
    tooling = (physical / "tooling").resolve(strict=True)
    if not entry.is_file() or not entry.is_relative_to(tooling):
        raise WindowsServiceError("fixed D-tooling service entry is unavailable")
    snapshot_id = manifest["content"].get("snapshot_id")
    if not isinstance(snapshot_id, str) or not snapshot_id:
        raise WindowsServiceError("active release snapshot identity is missing")
    return ActiveServiceRelease(
        release_id, observed_hash, snapshot_id, release_root, entry
    )


def authorize_writer_handoff_service_start(
    root: Path, active: Mapping[str, object]
) -> None:
    """Fence reboot/manual starts while the one-time C→D handoff is incomplete.

    The journal is coordination evidence, never an active authority.  Only the
    phase written after both D databases were installed may start D.  A crash
    during legacy stop/checkpoint/state replacement therefore leaves the
    automatic service fail closed instead of opening a mixed D state.
    """

    path = root / "control" / "writer_handoff_pending.json"
    if not path.exists():
        return
    ensure_no_reparse_components(path)
    value = read_json(path)
    terminal = value.get("commit_evidence") if isinstance(value, dict) else None
    terminal_valid = (
        isinstance(terminal, dict)
        and set(terminal)
        == {
            "recorded_at",
            "final_checkpoint_id",
            "final_checkpoint_manifest_sha256",
            "prehandoff_checkpoint_id",
            "prehandoff_checkpoint_manifest_sha256",
        }
        and isinstance(terminal.get("recorded_at"), str)
        and str(terminal.get("recorded_at")).endswith("Z")
        and re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,179}",
            str(terminal.get("final_checkpoint_id")),
        )
        is not None
        and re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,179}",
            str(terminal.get("prehandoff_checkpoint_id")),
        )
        is not None
        and re.fullmatch(
            r"[0-9a-f]{64}", str(terminal.get("final_checkpoint_manifest_sha256"))
        )
        is not None
        and re.fullmatch(
            r"[0-9a-f]{64}",
            str(terminal.get("prehandoff_checkpoint_manifest_sha256")),
        )
        is not None
    )
    progress_valid = (
        isinstance(terminal, dict)
        and set(terminal)
        == {
            "final_checkpoint_id",
            "final_checkpoint_manifest_sha256",
            "prehandoff_checkpoint_id",
            "prehandoff_checkpoint_manifest_sha256",
        }
        and re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,179}",
            str(terminal.get("final_checkpoint_id")),
        )
        is not None
        and re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,179}",
            str(terminal.get("prehandoff_checkpoint_id")),
        )
        is not None
        and re.fullmatch(
            r"[0-9a-f]{64}",
            str(terminal.get("final_checkpoint_manifest_sha256")),
        )
        is not None
        and re.fullmatch(
            r"[0-9a-f]{64}",
            str(terminal.get("prehandoff_checkpoint_manifest_sha256")),
        )
        is not None
    )
    if (
        not isinstance(value, dict)
        or set(value) != {
            "schema_version",
            "attempt_id",
            "nonce_sha256",
            "inspection_sha256",
            "success_receipt_id",
            "release_id",
            "manifest_sha256",
            "phase",
            "commit_evidence",
            "authority",
            "legacy_process",
        }
        or value.get("schema_version") != WRITER_HANDOFF_JOURNAL_SCHEMA
        or value.get("authority") != "coordination_only"
        or value.get("phase")
        not in {"d_bridge_pending", "handoff_committed_receipt_pending"}
        or value.get("release_id") != active.get("release_id")
        or value.get("manifest_sha256") != active.get("manifest_sha256")
        or not isinstance(value.get("legacy_process"), dict)
        or set(value["legacy_process"]) != {
            "pid", "executable", "argv", "executable_sha256", "server_sha256"
        }
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,179}", str(value.get("attempt_id")))
        is None
        or re.fullmatch(r"[0-9a-f]{64}", str(value.get("nonce_sha256"))) is None
        or re.fullmatch(r"[0-9a-f]{64}", str(value.get("inspection_sha256"))) is None
        or value.get("success_receipt_id")
        != f"writer-handoff-success-{value.get('attempt_id')}"
        or (
            value.get("phase") == "d_bridge_pending"
            and not progress_valid
        )
        or (
            value.get("phase") == "handoff_committed_receipt_pending"
            and not terminal_valid
        )
    ):
        raise WindowsServiceError("writer handoff journal fences D service start")


PopenFactory = Callable[..., subprocess.Popen[bytes]]
ServiceStartAuthorization = tuple[str, str, str]


def parse_service_start_authorization(
    args: object,
) -> ServiceStartAuthorization | object | None:
    """Accept only SCM transient args; ordinary boot has no authorization."""

    if not isinstance(args, (list, tuple)):
        raise WindowsServiceError("SCM service args are invalid")
    values = [str(value) for value in args]
    tail = values[1:]
    if not tail:
        return None
    if tail[0] == "exact-runtime":
        from .local_exact_runtime_entry import (
            ExactRuntimeEntryError,
            _parse_exact_argv,
        )
        from .local_windows_writer_lease_holder import (
            ExactRuntimeLeaseIdentity,
            WindowsWriterLeaseHolderError,
        )

        try:
            parsed = _parse_exact_argv(tuple(tail[1:]))
            identity = ExactRuntimeLeaseIdentity(**parsed)
        except (
            ExactRuntimeEntryError,
            TypeError,
            ValueError,
            WindowsWriterLeaseHolderError,
        ) as error:
            raise WindowsServiceError(
                "SCM exact-runtime args are not closed"
            ) from error
        if tuple(tail) != identity.service_start_arguments:
            raise WindowsServiceError("SCM exact-runtime args differ from start plan")
        return identity
    if tail[0] == "steady-exact-runtime":
        from .local_steady_runtime_identity import (
            ExactSteadyRuntimeIdentity,
            ExactSteadyRuntimeIdentityError,
            _parse_exact_steady_argv,
        )

        try:
            parsed = _parse_exact_steady_argv(tuple(tail[1:]))
            identity = ExactSteadyRuntimeIdentity(**parsed)
        except (
            ExactSteadyRuntimeIdentityError,
            TypeError,
            ValueError,
        ) as error:
            raise WindowsServiceError(
                "SCM steady-exact-runtime args are not closed"
            ) from error
        if tuple(tail) != identity.service_start_arguments:
            raise WindowsServiceError(
                "SCM steady-exact-runtime args differ from start plan"
            )
        return identity
    if (
        len(tail) != 4
        or tail[0] != "pending-activation"
        or tail[1] not in {"candidate", "prior"}
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,179}", tail[2]) is None
        or re.fullmatch(r"[0-9a-f]{48}", tail[3]) is None
    ):
        raise WindowsServiceError("SCM pending-activation args are not closed")
    return tail[1], tail[2], tail[3]


class ServiceSupervisor:
    """One SCM process supervises one child selected from the active pointer."""

    def __init__(
        self,
        root: Path,
        *,
        popen_factory: PopenFactory = subprocess.Popen,
        python_executable: Path | None = None,
        allow_test_root: bool = False,
        activation_authorization: ServiceStartAuthorization | object | None = None,
    ) -> None:
        self.root = root.resolve(strict=True)
        self.popen_factory = popen_factory
        self.python_executable = python_executable
        self.allow_test_root = allow_test_root
        self.activation_authorization = activation_authorization
        self.process: subprocess.Popen[bytes] | None = None
        self._log = None
        self._exact_pycache_guard = None
        self._transient_lifetime = None
        self._steady_stop_requested = threading.Event()
        self._steady_boot_session = None
        self._steady_lifetime = None

    def begin_production_steady_start_pending(self) -> None:
        """Launch the ordinary steady child while SCM remains START_PENDING."""

        if (
            self.allow_test_root
            or self.activation_authorization is not None
            or self.process is not None
            or self._steady_boot_session is not None
            or self._steady_lifetime is not None
        ):
            raise WindowsServiceError(
                "production steady START_PENDING provenance/state 无效"
            )
        from .local_steady_service_bootstrap import (
            ProductionSteadyServiceBootstrap,
        )

        self._steady_stop_requested.clear()
        self._steady_boot_session = (
            ProductionSteadyServiceBootstrap.load_exact_d().begin_prelaunch()
        )
        if self._steady_stop_requested.is_set():
            self._steady_boot_session.request_stop()

    def complete_production_steady_after_running(self) -> None:
        """Finish the live chain/admission after this exact SCM host is RUNNING."""

        session = self._steady_boot_session
        if session is None or self._steady_lifetime is not None:
            raise WindowsServiceError("steady RUNNING completion state 无效")
        if self._steady_stop_requested.is_set():
            session.request_stop()
        self._steady_lifetime = session.complete_after_running()
        self._steady_boot_session = None

    def abort_production_steady_start(self) -> None:
        session = self._steady_boot_session
        if session is not None:
            session.abort()
            self._steady_boot_session = None
        lifetime = self._steady_lifetime
        if lifetime is not None:
            lifetime.terminate()
            self._steady_lifetime = None

    def wait_production_steady_once(self, timeout_ms: int) -> int | None:
        lifetime = self._steady_lifetime
        if lifetime is None:
            raise WindowsServiceError("steady lifetime 尚未 admitted")
        result = lifetime.wait_for_exit(timeout_ms)
        if result is not None:
            self._steady_lifetime = None
        return result

    def stop_production_steady_from_owner(self) -> None:
        lifetime = self._steady_lifetime
        if lifetime is not None:
            lifetime.terminate()
            self._steady_lifetime = None

    def request_production_steady_stop(self) -> None:
        """SCM control-thread signal; kernel owners stay on the SvcRun thread."""

        self._steady_stop_requested.set()
        session = self._steady_boot_session
        if session is not None:
            session.request_stop()

    def wait_production_transient_once(self, timeout_ms: int) -> int | None:
        lifetime = self._transient_lifetime
        if lifetime is None:
            raise WindowsServiceError("transient lifetime is unavailable")
        result = lifetime.wait_for_exit(timeout_ms)
        if result is not None:
            self._transient_lifetime = None
        return result

    def stop_production_transient_from_owner(self) -> None:
        lifetime = self._transient_lifetime
        if lifetime is not None:
            lifetime.terminate()
            self._transient_lifetime = None

    def _runtime_python(self) -> Path:
        if self.python_executable is not None:
            injected = self.python_executable.resolve(strict=True)
            if not self.allow_test_root or injected != Path(sys.executable).resolve(
                strict=True
            ):
                raise WindowsServiceError(
                    "Python injection is restricted to the explicit test runtime"
                )
            return injected
        bindings = verify_installed_operational_bindings(self.root)
        configured = bindings["service_python"]
        logical = PRODUCTION_VM_ROOT / "tooling" / "python" / "python.exe"
        validate_production_vm_write_path(logical, allow_root=False)
        ensure_no_reparse_components(configured)
        if not configured.resolve(strict=True).is_file():
            raise WindowsServiceError("reviewed D-root service Python is unavailable")
        return configured.resolve(strict=True)

    def start(self) -> ActiveServiceRelease:
        if (
            (self.process is not None and self.process.poll() is None)
            or self._transient_lifetime is not None
            or self._steady_lifetime is not None
        ):
            raise WindowsServiceError("service child is already running")
        from .local_windows_writer_lease_holder import ExactRuntimeLeaseIdentity

        if type(self.activation_authorization) is ExactRuntimeLeaseIdentity:
            return self._start_exact_runtime(self.activation_authorization)
        if not self.allow_test_root:
            # Every production child is owned by one of the two exact service
            # paths above: ordinary steady SvcRun, or an ExactRuntimeLeaseIdentity
            # fenced by the durable v4 journal.  The historical v1
            # pending-activation tuple is deliberately rejected before the
            # legacy Popen implementation can observe it.
            verify_installed_operational_bindings(self.root)
            if self.activation_authorization is not None:
                raise WindowsServiceError(
                    "legacy pending activation cannot create a production child"
                )
            raise WindowsServiceError(
                "ordinary production start must use the exact steady SvcRun path"
            )
        controller = DeploymentController.for_test_only(self.root)
        active_document = validate_active_release(
            read_json(self.root / "control" / "active_release.json")
        )
        controller.authorize_service_start(
            active=active_document,
            authorization=self.activation_authorization,
        )
        authorize_writer_handoff_service_start(self.root, active_document)
        if not self.allow_test_root:
            # Validate the complete reviewed project package before importing
            # deployment runtime hooks or opening project logs/state.
            verify_installed_operational_bindings(self.root)
            # Reboot/start outside deployment must validate the same closed
            # topology contract as candidate activation.
            from .vm_deploy_cli import WindowsServiceRuntime

            WindowsServiceRuntime.load(self.root)
        active = resolve_active_service_release(self.root)
        tmp = self.root / "tmp" / "service"
        logs = self.root / "logs"
        state = self.root / "state" / "service"
        for path in (tmp, logs, state):
            path.mkdir(parents=True, exist_ok=True)
            ensure_no_reparse_components(path)
        log_path = logs / "quant-research-hub.log"
        self._log = log_path.open("ab", buffering=0)
        environment = {
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUTF8": "1",
            "PYTHONIOENCODING": "utf-8",
            "TEMP": str(tmp),
            "TMP": str(tmp),
            "PYTHONPYCACHEPREFIX": str(tmp / "pycache"),
        }
        arguments = [
            str(self._runtime_python()), "-I", str(active.entry_path),
            "--vm-root", str(self.root),
            "--release-id", active.release_id,
            "--manifest-sha256", active.manifest_sha256,
        ]
        if self.allow_test_root:
            arguments.append("--test-root")
            environment["QRH_TEST_ONLY_ALLOW_NONPRODUCTION_ROOT"] = "1"
        creationflags = 0
        if os.name == "nt":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        try:
            self.process = self.popen_factory(
                arguments,
                cwd=tmp,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=self._log,
                stderr=subprocess.STDOUT,
                creationflags=creationflags,
                close_fds=True,
            )
            pid_payload = {
                "schema_version": "qrh-service-child/v1",
                "release_id": active.release_id,
                "manifest_sha256": active.manifest_sha256,
                "snapshot_id": active.snapshot_id,
                "pid": self.process.pid,
            }
            temporary = state / ".child.json.partial"
            temporary.write_text(
                json.dumps(pid_payload, ensure_ascii=False, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            os.replace(temporary, state / "child.json")
        except BaseException:
            try:
                self.stop()
            finally:
                self._close_log()
            raise
        return active

    def _start_exact_runtime(self, identity: object) -> ActiveServiceRelease:
        """Start only the child argv sealed into the exact transient identity."""

        from .local_release_identity import (
            canonical_bytes as local_canonical_bytes,
            identity_sha256 as local_identity_sha256,
            validate_release_manifest as validate_local_release_manifest,
        )
        from .local_windows_writer_lease_holder import ExactRuntimeLeaseIdentity

        if type(identity) is not ExactRuntimeLeaseIdentity:
            raise WindowsServiceError("exact runtime start requires exact identity")
        if not self.allow_test_root:
            if PureWindowsPath(str(self.root)) != PRODUCTION_VM_ROOT:
                raise WindowsServiceError("exact runtime service root is not exact D")
            bindings = verify_installed_operational_bindings(self.root)
            runtime_python = self._runtime_python()
            if PureWindowsPath(str(runtime_python)) != PureWindowsPath(
                identity.child_argv[0]
            ):
                raise WindowsServiceError(
                    "exact runtime child executable differs from installed Python"
                )
            release_root = (
                self.root / "releases" / identity.release_id
            ).resolve(strict=True)
            ensure_no_reparse_components(release_root)
            expected_release_root = self.root / "releases" / identity.release_id
            if (
                release_root != expected_release_root
                or PureWindowsPath(str(release_root))
                != PureWindowsPath(identity.release_path)
            ):
                raise WindowsServiceError("exact runtime release root differs")
            manifest_path = release_root / "release_manifest.json"
            ensure_no_reparse_components(manifest_path)
            raw = manifest_path.read_bytes()
            try:
                manifest = validate_local_release_manifest(json.loads(raw))
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
                raise WindowsServiceError(
                    "exact runtime release manifest is invalid"
                ) from error
            if (
                local_canonical_bytes(manifest) != raw
                or local_identity_sha256(manifest) != identity.manifest_sha256
                or manifest.get("release_id") != identity.release_id
            ):
                raise WindowsServiceError(
                    "exact runtime release manifest identity differs"
                )
            entry_path = bindings["quant_hub_package_root"] / "ops" / (
                "local_exact_runtime_entry.py"
            )
            snapshot_id = str(manifest["content"]["snapshot_id"])
            from .local_service_transient_journal_start_fence import (
                ProductionServiceTransientJournalStartFence,
            )
            from .local_windows_job_child_launcher import (
                ProductionWindowsJobChildLauncher,
            )

            fence = (
                ProductionServiceTransientJournalStartFence.load_exact_d()
                .pin_exact_identity(identity)
            )
            try:
                lifetime = (
                    ProductionWindowsJobChildLauncher.load_exact_d()
                    .launch_transient(fence)
                )
            except BaseException as primary:
                try:
                    fence.close()
                except BaseException as cleanup_error:
                    raise cleanup_error from primary
                raise primary
            self._transient_lifetime = lifetime
            return ActiveServiceRelease(
                release_id=identity.release_id,
                manifest_sha256=identity.manifest_sha256,
                snapshot_id=snapshot_id,
                release_root=release_root,
                entry_path=entry_path,
            )
        else:
            release_root = self.root / "releases" / identity.release_id
            entry_path = release_root / "local_exact_runtime_entry.py"
            snapshot_id = "test-only-exact-runtime"

        tmp = self.root / "tmp" / "service"
        logs = self.root / "logs"
        state = self.root / "state" / "service"
        pycache_parent = tmp / "pycache"
        for path in (tmp, logs, state, pycache_parent):
            path.mkdir(parents=True, exist_ok=True)
            ensure_no_reparse_components(path)
        pycache_target = pycache_parent / identity.start_nonce
        ensure_no_reparse_components(pycache_target)
        if os.path.lexists(pycache_target):
            raise WindowsServiceError(
                "exact runtime per-start pycache target must be absent before launch"
            )
        if any(
            child.name.casefold() == identity.start_nonce.casefold()
            for child in pycache_parent.iterdir()
        ):
            raise WindowsServiceError(
                "exact runtime per-start pycache namespace collides"
            )
        sentinel_raw = (
            json.dumps(
                {
                    "schema_version": "qrh-exact-runtime-pycache-sentinel/v1",
                    "start_nonce": identity.start_nonce,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        try:
            with pycache_target.open("xb") as stream:
                stream.write(sentinel_raw)
                stream.flush()
                os.fsync(stream.fileno())
            target_info = pycache_target.lstat()
            if (
                stat.S_ISLNK(target_info.st_mode)
                or bool(getattr(target_info, "st_file_attributes", 0) & 0x400)
                or not stat.S_ISREG(target_info.st_mode)
                or target_info.st_nlink != 1
            ):
                raise WindowsServiceError(
                    "exact runtime pycache sentinel is not regular single-link"
                )
            from .local_exact_runtime_tooling_scanner import _WindowsReadGuardSet

            self._exact_pycache_guard = _WindowsReadGuardSet((pycache_target,))
        except BaseException:
            self._close_exact_pycache_guard()
            raise

        try:
            log_path = logs / "quant-research-hub.log"
            self._log = log_path.open("ab", buffering=0)
            environment = {
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONUTF8": "1",
                "PYTHONIOENCODING": "utf-8",
                "TEMP": str(tmp),
                "TMP": str(tmp),
                "PYTHONPYCACHEPREFIX": str(pycache_target),
            }
            arguments = list(identity.child_argv)
            creationflags = 0
            if os.name == "nt":
                creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        except BaseException:
            self._close_exact_runtime_resources()
            raise
        try:
            process = self.popen_factory(
                arguments,
                cwd=tmp,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=self._log,
                stderr=subprocess.STDOUT,
                creationflags=creationflags,
                close_fds=True,
            )
            if not hasattr(process, "pid") or type(process.pid) is not int:
                raise WindowsServiceError("exact runtime child PID is invalid")
            self.process = process
            observed_info = pycache_target.lstat()
            if (
                not stat.S_ISREG(observed_info.st_mode)
                or observed_info.st_dev != target_info.st_dev
                or observed_info.st_ino != target_info.st_ino
                or observed_info.st_nlink != 1
                or pycache_target.read_bytes() != sentinel_raw
            ):
                raise WindowsServiceError(
                    "exact runtime pycache sentinel drifted during launch"
                )
            pid_payload = {
                "schema_version": "qrh-exact-runtime-service-child/v1",
                "attempt": identity.attempt_id,
                "nonce": identity.nonce,
                "operation": identity.operation,
                "role": identity.role,
                "start_nonce": identity.start_nonce,
                "release_id": identity.release_id,
                "manifest_sha256": identity.manifest_sha256,
                "state_identity_sha256": identity.state_identity_sha256,
                "scm_identity_sha256": identity.scm_identity_sha256,
                "authorization_sha256": identity.authorization_sha256,
                "pid": process.pid,
            }
            temporary = state / ".child.json.partial"
            temporary.write_text(
                json.dumps(pid_payload, ensure_ascii=False, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            os.replace(temporary, state / "child.json")
        except BaseException:
            process = self.process
            try:
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
            finally:
                self.process = None
                self._close_exact_runtime_resources()
            raise
        return ActiveServiceRelease(
            release_id=identity.release_id,
            manifest_sha256=identity.manifest_sha256,
            snapshot_id=snapshot_id,
            release_root=release_root,
            entry_path=entry_path,
        )

    def wait(self) -> int:
        transient = self._transient_lifetime
        if transient is not None:
            while True:
                return_code = transient.wait_for_exit(1_000)
                if return_code is not None:
                    self._transient_lifetime = None
                    return return_code
        if self.process is None:
            raise WindowsServiceError("service child was not started")
        process = self.process
        return_code = int(process.wait())
        if self.process is process:
            self.process = None
            (self.root / "state" / "service" / "child.json").unlink(missing_ok=True)
            self._close_exact_runtime_resources()
        return return_code

    def stop(self, *, timeout: float = 15.0) -> None:
        transient = self._transient_lifetime
        if transient is not None:
            transient.terminate()
            self._transient_lifetime = None
            return
        process = self.process
        if process is None:
            return
        if process.poll() is None:
            if os.name == "nt":
                try:
                    process.send_signal(signal.CTRL_BREAK_EVENT)
                except OSError:
                    process.terminate()
            else:
                process.terminate()
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        self.process = None
        (self.root / "state" / "service" / "child.json").unlink(missing_ok=True)
        self._close_exact_runtime_resources()

    def _close_exact_runtime_resources(self) -> None:
        try:
            self._close_exact_pycache_guard()
        finally:
            self._close_log()

    def _close_exact_pycache_guard(self) -> None:
        guard = self._exact_pycache_guard
        self._exact_pycache_guard = None
        if guard is not None:
            guard.close()

    def _close_log(self) -> None:
        if self._log is not None:
            self._log.close()
            self._log = None


@dataclass(frozen=True)
class ServiceInstallCandidate:
    service_name: str
    python_class: str
    service_executable: Path
    service_executable_sha256: str
    service_python_runtime: Path
    service_python_runtime_sha256: str
    service_pywin32_runtime: Path
    service_pywin32_runtime_sha256: str
    service_python: Path
    service_python_sha256: str
    service_host_module: Path
    service_host_module_sha256: str
    service_entry_module: Path
    service_entry_module_sha256: str
    deployment_cli_module: Path
    deployment_cli_module_sha256: str
    access_gate_module: Path
    access_gate_module_sha256: str
    deployment_runtime: Path
    deployment_runtime_sha256: str
    quant_hub_package_root: Path
    quant_hub_package_inventory_sha256: str

    def document(self) -> Mapping[str, object]:
        return {
            "schema_version": INSTALL_SCHEMA,
            "service_name": self.service_name,
            "python_class": self.python_class,
            "service_executable": str(self.service_executable),
            "service_executable_sha256": self.service_executable_sha256,
            "service_python_runtime": str(self.service_python_runtime),
            "service_python_runtime_sha256": self.service_python_runtime_sha256,
            "service_pywin32_runtime": str(self.service_pywin32_runtime),
            "service_pywin32_runtime_sha256": self.service_pywin32_runtime_sha256,
            "service_python": str(self.service_python),
            "service_python_sha256": self.service_python_sha256,
            "service_host_module": str(self.service_host_module),
            "service_host_module_sha256": self.service_host_module_sha256,
            "service_entry_module": str(self.service_entry_module),
            "service_entry_module_sha256": self.service_entry_module_sha256,
            "deployment_cli_module": str(self.deployment_cli_module),
            "deployment_cli_module_sha256": self.deployment_cli_module_sha256,
            "access_gate_module": str(self.access_gate_module),
            "access_gate_module_sha256": self.access_gate_module_sha256,
            "deployment_runtime": str(self.deployment_runtime),
            "deployment_runtime_sha256": self.deployment_runtime_sha256,
            "quant_hub_package_root": str(self.quant_hub_package_root),
            "quant_hub_package_inventory_sha256": self.quant_hub_package_inventory_sha256,
            "start_type": "automatic",
        }


def build_install_candidate(root: Path, service_name: str) -> ServiceInstallCandidate:
    expected = {
        name: path.resolve(strict=True)
        for name, path in _expected_candidate_paths(root.resolve(strict=True)).items()
    }
    executable = expected["service_executable"]
    service_python_runtime = expected["service_python_runtime"]
    service_pywin32_runtime = expected["service_pywin32_runtime"]
    service_python = expected["service_python"]
    service_host_module = expected["service_host_module"]
    service_entry_module = expected["service_entry_module"]
    deployment_cli_module = expected["deployment_cli_module"]
    access_gate_module = expected["access_gate_module"]
    runtime = expected["deployment_runtime"]
    package_root = service_host_module.parents[1]
    ensure_no_reparse_components(executable)
    ensure_no_reparse_components(service_python_runtime)
    ensure_no_reparse_components(service_pywin32_runtime)
    ensure_no_reparse_components(service_python)
    ensure_no_reparse_components(service_host_module)
    ensure_no_reparse_components(service_entry_module)
    ensure_no_reparse_components(deployment_cli_module)
    ensure_no_reparse_components(access_gate_module)
    ensure_no_reparse_components(runtime)
    if (
        not executable.is_file()
        or not service_python_runtime.is_file()
        or not service_pywin32_runtime.is_file()
        or not service_python.is_file()
        or not service_host_module.is_file()
        or not service_entry_module.is_file()
        or not deployment_cli_module.is_file()
        or not access_gate_module.is_file()
        or not runtime.is_file()
    ):
        raise WindowsServiceError("service executable/Python/host/config is unavailable")
    # Logical production paths are checked separately so local fixtures remain testable.
    if PureWindowsPath(str(root.resolve())) == PRODUCTION_VM_ROOT:
        validate_production_vm_write_path(str(executable), allow_root=False)
        validate_production_vm_write_path(str(service_python_runtime), allow_root=False)
        validate_production_vm_write_path(str(service_pywin32_runtime), allow_root=False)
        validate_production_vm_write_path(str(service_python), allow_root=False)
        validate_production_vm_write_path(str(service_host_module), allow_root=False)
        validate_production_vm_write_path(str(service_entry_module), allow_root=False)
        validate_production_vm_write_path(str(deployment_cli_module), allow_root=False)
        validate_production_vm_write_path(str(access_gate_module), allow_root=False)
        validate_production_vm_write_path(str(runtime), allow_root=False)
    return ServiceInstallCandidate(
        service_name=service_name,
        python_class=SERVICE_CLASS,
        service_executable=executable,
        service_executable_sha256=_hash_file(executable),
        service_python_runtime=service_python_runtime,
        service_python_runtime_sha256=_hash_file(service_python_runtime),
        service_pywin32_runtime=service_pywin32_runtime,
        service_pywin32_runtime_sha256=_hash_file(service_pywin32_runtime),
        service_python=service_python,
        service_python_sha256=_hash_file(service_python),
        service_host_module=service_host_module,
        service_host_module_sha256=_hash_file(service_host_module),
        service_entry_module=service_entry_module,
        service_entry_module_sha256=_hash_file(service_entry_module),
        deployment_cli_module=deployment_cli_module,
        deployment_cli_module_sha256=_hash_file(deployment_cli_module),
        access_gate_module=access_gate_module,
        access_gate_module_sha256=_hash_file(access_gate_module),
        deployment_runtime=runtime,
        deployment_runtime_sha256=_hash_file(runtime),
        quant_hub_package_root=package_root,
        quant_hub_package_inventory_sha256=quant_hub_package_inventory_sha256(package_root),
    )


class ServiceInstaller(Protocol):
    def exists(self, service_name: str) -> bool: ...

    def install(self, candidate: ServiceInstallCandidate) -> None: ...

    def configure(self, candidate: ServiceInstallCandidate) -> None: ...

    def verify(self, candidate: ServiceInstallCandidate) -> bool: ...


class PyWin32ServiceInstaller:
    """Small adapter around pywin32; all reviewed inputs come from the candidate."""

    def exists(self, service_name: str) -> bool:
        try:
            import win32serviceutil

            win32serviceutil.QueryServiceStatus(service_name)
            return True
        except Exception as error:
            code = getattr(error, "winerror", None)
            if code == 1060:  # ERROR_SERVICE_DOES_NOT_EXIST
                return False
            raise WindowsServiceError("cannot query Windows service") from error

    @staticmethod
    def _arguments(candidate: ServiceInstallCandidate) -> dict[str, object]:
        try:
            import win32service
        except ImportError as error:
            raise WindowsServiceError("pywin32 service runtime is unavailable") from error
        return {
            "pythonClassString": candidate.python_class,
            "serviceName": candidate.service_name,
            "displayName": "Quant Research Hub",
            "startType": win32service.SERVICE_AUTO_START,
            "exeName": str(candidate.service_executable),
            "description": (
                "D-root active-release supervisor for Quant Research Hub"
            ),
            "delayedstart": False,
        }

    def install(self, candidate: ServiceInstallCandidate) -> None:
        try:
            import win32serviceutil

            win32serviceutil.InstallService(**self._arguments(candidate))
        except Exception as error:
            raise WindowsServiceError("Windows service installation failed") from error

    def configure(self, candidate: ServiceInstallCandidate) -> None:
        arguments = self._arguments(candidate)
        arguments.pop("displayName")
        try:
            import win32serviceutil

            win32serviceutil.ChangeServiceConfig(**arguments)
        except Exception as error:
            raise WindowsServiceError("Windows service configuration failed") from error

    def verify(self, candidate: ServiceInstallCandidate) -> bool:
        service = manager = None
        try:
            import win32service
            import winreg

            manager = win32service.OpenSCManager(
                None, None, win32service.SC_MANAGER_CONNECT
            )
            service = win32service.OpenService(
                manager, candidate.service_name, win32service.SERVICE_QUERY_CONFIG
            )
            config = win32service.QueryServiceConfig(service)
            registry_path = (
                rf"System\CurrentControlSet\Services\{candidate.service_name}"
                r"\PythonClass"
            )
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path) as key:
                python_class = winreg.QueryValue(key, None)
            return validate_service_control_binding(
                candidate,
                binary_path=str(config[3]),
                python_class=str(python_class),
                start_type=int(config[1]),
                automatic_start_type=int(win32service.SERVICE_AUTO_START),
            )
        except Exception as error:
            raise WindowsServiceError("cannot verify final Windows service binding") from error
        finally:
            if service is not None:
                win32service.CloseServiceHandle(service)
            if manager is not None:
                win32service.CloseServiceHandle(manager)


def apply_install_candidate(
    root: Path, candidate: ServiceInstallCandidate, *, installer: ServiceInstaller
) -> str:
    _validate_install_candidate_paths(root, candidate)
    if (
        _hash_file(candidate.service_executable) != candidate.service_executable_sha256
        or _hash_file(candidate.service_python_runtime)
        != candidate.service_python_runtime_sha256
        or _hash_file(candidate.service_pywin32_runtime)
        != candidate.service_pywin32_runtime_sha256
        or _hash_file(candidate.service_python) != candidate.service_python_sha256
        or _hash_file(candidate.service_host_module)
        != candidate.service_host_module_sha256
        or _hash_file(candidate.service_entry_module)
        != candidate.service_entry_module_sha256
        or _hash_file(candidate.deployment_cli_module)
        != candidate.deployment_cli_module_sha256
        or _hash_file(candidate.access_gate_module)
        != candidate.access_gate_module_sha256
        or _hash_file(candidate.deployment_runtime) != candidate.deployment_runtime_sha256
        or quant_hub_package_inventory_sha256(candidate.quant_hub_package_root)
        != candidate.quant_hub_package_inventory_sha256
    ):
        raise WindowsServiceError("service install candidate changed before apply")
    document = candidate.document()
    path = root / "control" / "service_install_candidate.json"
    if path.exists():
        existing = read_json(path)
        if existing != document:
            temporary = path.with_name(".service_install_candidate.json.partial")
            temporary.write_text(
                json.dumps(document, ensure_ascii=False, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            os.replace(temporary, path)
    else:
        write_atomic_new_json(path, document)
    action = "configure" if installer.exists(candidate.service_name) else "install"
    (installer.configure if action == "configure" else installer.install)(candidate)
    if not installer.verify(candidate):
        raise WindowsServiceError("final Windows service binding differs from candidate")
    return action


def _requires_service_host_owner_crash(error: BaseException) -> bool:
    from .local_windows_job_child_launcher import (
        WindowsJobChildOwnerCrashRequired,
    )
    from .local_service_transient_journal_start_fence import (
        ServiceTransientJournalStartFenceOwnerCrashRequired,
    )
    from .local_windows_exact_runtime_process_fence import (
        WindowsExactRuntimeProcessFenceOwnerCrashRequired,
    )

    pending: list[BaseException] = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(
            current,
            (
                WindowsJobChildOwnerCrashRequired,
                ServiceTransientJournalStartFenceOwnerCrashRequired,
                WindowsExactRuntimeProcessFenceOwnerCrashRequired,
                WindowsServiceStatusOwnerCrashRequired,
            ),
        ):
            return True
        for linked in (current.__cause__, current.__context__):
            if isinstance(linked, BaseException):
                pending.append(linked)
    return False


def _terminate_service_host_owner_crash() -> None:
    """No Python cleanup is authoritative after an unknown Job/handle outcome."""

    os._exit(97)
    raise SystemExit(97)  # pragma: no cover - protects tests that stub os._exit


try:  # Windows-only service host; imports stay optional for non-Windows CI.
    import win32event
    import win32service
    import win32serviceutil

    class QuantResearchHubWindowsService(win32serviceutil.ServiceFramework):
        _svc_name_ = "QuantResearchHub"
        _svc_display_name_ = "Quant Research Hub"
        _svc_description_ = "D-root active-release supervisor for Quant Research Hub"

        def __init__(self, args):
            root = Path(str(PRODUCTION_VM_ROOT))
            # Python must import this module before its own code can execute.
            # This read-only seal is therefore the earliest attainable
            # in-module boundary and deliberately precedes every project write.
            bindings = verify_installed_operational_bindings(root)
            expected_module = _expected_candidate_paths(root)["service_host_module"]
            if (
                Path(__file__).resolve(strict=True)
                != expected_module.resolve(strict=True)
                or bindings["service_host_module"] != expected_module.resolve(strict=True)
            ):
                raise WindowsServiceError("SCM loaded service host outside D-root tooling")
            host_environment = prepare_service_host_environment(root)
            try:
                super().__init__(args)
                self.stop_event = win32event.CreateEvent(None, 0, 0, None)
                self.supervisor = ServiceSupervisor(
                    root,
                    activation_authorization=parse_service_start_authorization(args),
                )
                self._status_lock = threading.RLock()
                self._tracked_service_state = win32service.SERVICE_START_PENDING
                self._status_outcome_unknown = False
            except BaseException:
                host_environment.close()
                raise
            self._host_environment = host_environment

        def _report_tracked_status(self, state, *, wait_hint=0):
            with self._status_lock:
                if self._status_outcome_unknown:
                    raise WindowsServiceStatusOwnerCrashRequired(
                        "SCM status authority is already retired"
                    )
                try:
                    self.ReportServiceStatus(state, waitHint=wait_hint)
                except BaseException as error:
                    self._status_outcome_unknown = True
                    raise WindowsServiceStatusOwnerCrashRequired(
                        "ReportServiceStatus outcome is unknown"
                    ) from error
                self._tracked_service_state = state

        def _stop_is_set(self):
            outcome = win32event.WaitForSingleObject(self.stop_event, 0)
            if outcome == win32event.WAIT_OBJECT_0:
                return True
            if outcome == win32event.WAIT_TIMEOUT:
                return False
            raise WindowsServiceStatusOwnerCrashRequired(
                "service stop-event wait outcome is unknown"
            )

        def _report_running_unless_stopped(self):
            with self._status_lock:
                if self._stop_is_set():
                    return False
                if self._status_outcome_unknown:
                    raise WindowsServiceStatusOwnerCrashRequired(
                        "SCM status authority is already retired"
                    )
                try:
                    self.ReportServiceStatus(win32service.SERVICE_RUNNING)
                except BaseException as error:
                    self._status_outcome_unknown = True
                    raise WindowsServiceStatusOwnerCrashRequired(
                        "SERVICE_RUNNING report outcome is unknown"
                    ) from error
                self._tracked_service_state = win32service.SERVICE_RUNNING
                return True

        def SvcRun(self):
            """Exact status owner; base SvcRun would report RUNNING too early."""

            return_code = 1
            owner_crash = False
            try:
                self._report_tracked_status(
                    win32service.SERVICE_START_PENDING,
                    wait_hint=30_000,
                )
                if self.supervisor.activation_authorization is None:
                    self.supervisor.begin_production_steady_start_pending()
                    if not self._report_running_unless_stopped():
                        raise WindowsServiceError(
                            "steady stop requested before RUNNING live chain"
                        )
                    self.supervisor.complete_production_steady_after_running()
                else:
                    # Transient compatibility starts remain closed-admission and
                    # must finish launch before SCM RUNNING is observable.
                    self.supervisor.start()
                    if not self._report_running_unless_stopped():
                        raise WindowsServiceError(
                            "transient stop requested before RUNNING"
                        )
                return_code = self.SvcDoRun()
            except BaseException as error:
                owner_crash = _requires_service_host_owner_crash(error)
                if owner_crash:
                    _terminate_service_host_owner_crash()
                try:
                    self.supervisor.abort_production_steady_start()
                except BaseException as cleanup_error:
                    owner_crash = owner_crash or _requires_service_host_owner_crash(
                        cleanup_error
                    )
                try:
                    self.supervisor.stop()
                except BaseException as cleanup_error:
                    owner_crash = owner_crash or _requires_service_host_owner_crash(
                        cleanup_error
                    )
                if owner_crash:
                    _terminate_service_host_owner_crash()
                else:
                    self._host_environment.append_status(
                        f"host_failure_{type(error).__name__.casefold()}",
                    )
            finally:
                if not owner_crash and not self._status_outcome_unknown:
                    try:
                        self._report_tracked_status(win32service.SERVICE_STOPPED)
                    except WindowsServiceStatusOwnerCrashRequired:
                        _terminate_service_host_owner_crash()
            try:
                if return_code:
                    self._host_environment.append_status(
                        f"child_exit_{return_code}"
                    )
            finally:
                self._host_environment.close()

        def SvcInterrogate(self):
            try:
                with self._status_lock:
                    if self._status_outcome_unknown:
                        raise WindowsServiceStatusOwnerCrashRequired(
                            "SCM status authority is already retired"
                        )
                    state = self._tracked_service_state
                    try:
                        self.ReportServiceStatus(state)
                    except BaseException as error:
                        self._status_outcome_unknown = True
                        raise WindowsServiceStatusOwnerCrashRequired(
                            "interrogate status outcome is unknown"
                        ) from error
            except BaseException:
                _terminate_service_host_owner_crash()

        def SvcStop(self):
            try:
                with self._status_lock:
                    win32event.SetEvent(self.stop_event)
                    self.supervisor.request_production_steady_stop()
                    self._report_tracked_status(
                        win32service.SERVICE_STOP_PENDING
                    )
            except BaseException:
                _terminate_service_host_owner_crash()

        def SvcDoRun(self):
            """Wait body only; launch/observation/status belong to SvcRun."""

            if self.supervisor._transient_lifetime is not None:
                while True:
                    if self._stop_is_set():
                        self.supervisor.stop_production_transient_from_owner()
                        return 0
                    result = self.supervisor.wait_production_transient_once(250)
                    if result is not None:
                        return result
            if self.supervisor._steady_lifetime is None:
                return self.supervisor.wait()
            while True:
                if self._stop_is_set():
                    self.supervisor.stop_production_steady_from_owner()
                    return 0
                result = self.supervisor.wait_production_steady_once(250)
                if result is not None:
                    return result

except ImportError:  # pragma: no cover - exercised only on a non-Windows host.
    class QuantResearchHubWindowsService:  # type: ignore[no-redef]
        pass


__all__ = [
    "ActiveServiceRelease", "INSTALL_SCHEMA", "QuantResearchHubWindowsService",
    "PyWin32ServiceInstaller", "SERVICE_CLASS", "SERVICE_NAME", "ServiceInstallCandidate", "ServiceInstaller",
    "ServiceSupervisor", "WindowsServiceError", "apply_install_candidate",
    "build_install_candidate", "prepare_service_host_environment",
    "authorize_writer_handoff_service_start",
    "parse_service_start_authorization",
    "quant_hub_package_inventory_sha256",
    "resolve_active_service_release", "validate_service_control_binding",
    "verify_installed_operational_bindings",
]
