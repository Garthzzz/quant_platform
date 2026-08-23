"""One-time, fail-closed C-to-D writer handoff for the V39 baseline.

``inspect_writer_handoff`` is read-only: it returns a canonical, nonce-bound
inspection receipt but never stores it or changes a process, service, database,
active pointer, or filesystem authority.  The off-host operator must preserve
those exact bytes and pass their hash and nonce to ``apply_writer_handoff``.

Apply re-runs the complete inspection before stopping the exact legacy PID.  It
then creates restore-verified SQLite checkpoints, replaces only the two D state
databases while the D service is stopped, and starts the already-installed D
service.  A legacy restart is permitted only while the runtime can positively
prove that D never opened the production listener.  The legacy ``restart.py``
is deliberately neither imported nor executed.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import sqlite3
import stat
import subprocess
import time
from typing import Callable, Iterator, Mapping, Protocol
import urllib.error
import urllib.request
from uuid import uuid4

from quant_hub.collaboration.checkpoint import (
    CheckpointCreation,
    create_sqlite_checkpoint,
    verify_sqlite_checkpoint,
)
from quant_hub.config import ensure_no_reparse_components
from quant_hub.runtime_seal import read_json, write_atomic_new_json
from quant_hub.web.access_gate import ACCESS_PASSWORD_ITERATIONS, ACCESS_PASSWORD_SALT

from .failure_domain_authority import require_failure_domain_authority
from .release_identity import (
    canonical_manifest_bytes,
    manifest_sha256,
    validate_active_release,
    validate_receipt,
    validate_release_manifest,
)
from .vm_boundary import PRODUCTION_VM_ROOT
from .vm_service_cli import production_runtime_document
from .windows_service import verify_installed_operational_bindings
from .windows_service import PyWin32ServiceInstaller, build_install_candidate


INSPECT_SCHEMA = "qrh-writer-handoff-inspection/v1"
SUCCESS_SCHEMA = "qrh-writer-handoff-receipt/v1"
FAILURE_SCHEMA = "qrh-writer-handoff-failure/v1"
JOURNAL_SCHEMA = "qrh-writer-handoff-pending/v2"
STATUS_SCHEMA = "qrh-writer-handoff-status/v1"
ACCESS_IDENTITY_SCHEMA = "qrh-writer-handoff-access-identity/v1"
ACCESS_IDENTITY_CONTRACT = "v39-default-access-identity-ast/v1"
V39_RELEASE_ID = "v39-baseline-20260731-hotfix1"
V39_SNAPSHOT_ID = "v39-content-20260731-hotfix1"
V39_LEGACY_DEPLOYMENT_ID = "quant-hub-v39-company-broadcast-20260731-hotfix1"
TARGET_ADDRESS = "10.5.1.240"
PORT = 8765
LEGACY_ROOT = PureWindowsPath(r"C:\quant_platform")
LEGACY_STATE_ROOT = PureWindowsPath(r"C:\quant_platform_data")
LEGACY_SERVER = LEGACY_ROOT / "tools" / "viewer" / "server.py"
SERVICE_NAME = "QuantResearchHub"
MAX_INSPECTION_AGE = timedelta(minutes=15)

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{48}$")


class WriterHandoffError(RuntimeError):
    """A handoff safety condition could not be proven."""


@dataclass(frozen=True)
class V39Baseline:
    manifest_sha256: str
    release_id: str = V39_RELEASE_ID
    snapshot_id: str = V39_SNAPSHOT_ID
    legacy_deployment_id: str = V39_LEGACY_DEPLOYMENT_ID

    def __post_init__(self) -> None:
        if self.release_id != V39_RELEASE_ID:
            raise WriterHandoffError("writer handoff release is not the frozen V39 baseline")
        if self.snapshot_id != V39_SNAPSHOT_ID:
            raise WriterHandoffError("writer handoff snapshot is not the frozen V39 baseline")
        if self.legacy_deployment_id != V39_LEGACY_DEPLOYMENT_ID:
            raise WriterHandoffError("legacy deployment is not the frozen V39 baseline")
        _sha(self.manifest_sha256, label="V39 release manifest")


@dataclass(frozen=True)
class LegacyProcess:
    pid: int
    executable: str
    argv: tuple[str, ...]
    executable_sha256: str
    server_sha256: str

    def document(self) -> dict[str, object]:
        return {
            "pid": self.pid,
            "executable": self.executable,
            "argv": list(self.argv),
            "executable_sha256": self.executable_sha256,
            "server_sha256": self.server_sha256,
        }


@dataclass(frozen=True)
class RuntimeObservation:
    target_addresses: tuple[str, ...]
    listener_pids: tuple[int, ...]
    legacy_deployment: Mapping[str, object] | None
    legacy_process: LegacyProcess | None
    d_service: Mapping[str, object]


@dataclass(frozen=True)
class HandoffApplyResult:
    succeeded: bool
    receipt_path: Path
    final_checkpoint_id: str | None
    prehandoff_checkpoint_id: str | None
    legacy_rollback_attempted: bool
    legacy_rollback_succeeded: bool
    rollback_blocked: bool
    error_code: str | None
    writer_authority_committed: bool = False


class HandoffRuntime(Protocol):
    """OS/process boundary.  Implementations must not return secret values."""

    def observe(self, port: int) -> RuntimeObservation: ...

    def stop_legacy(self, expected: LegacyProcess) -> None: ...

    def wait_port_free(self, port: int) -> bool: ...

    def start_d_service(self, service_name: str) -> None: ...

    def stop_d_service(self, service_name: str) -> None: ...

    def d_external_open(self, port: int) -> bool: ...

    def probe_d(self, baseline: V39Baseline) -> Mapping[str, object]: ...

    def start_legacy(self, expected: LegacyProcess) -> None: ...

    def verify_legacy_restored(
        self, expected: LegacyProcess, deployment_id: str, port: int
    ) -> bool: ...


class WindowsHandoffRuntime:
    """Fixed Windows adapter for the sole production VM.

    All commands are fixed argv with ``shell=False``.  Process termination is
    preceded by a fresh PID/executable/argv/hash comparison.  Browser/API
    probes deliberately validate the access gate without accepting a password,
    digest, session token, or other credential through this CLI.
    """

    def __init__(self, root: Path):
        require_failure_domain_authority()
        self.root = _root(root, allow_test_root=False)
        runtime_tmp = (self.root / "tmp").resolve(strict=True)
        ensure_no_reparse_components(runtime_tmp)
        if not runtime_tmp.is_dir() or not runtime_tmp.is_relative_to(self.root):
            raise WriterHandoffError("fixed D runtime tmp is unavailable")
        self.environment = {
            **os.environ,
            "TEMP": str(runtime_tmp),
            "TMP": str(runtime_tmp),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPYCACHEPREFIX": str(runtime_tmp / "pycache"),
        }
        self._stopped_legacy: LegacyProcess | None = None
        self._d_was_open = False

    def _powershell(self, script: str) -> str:
        result = subprocess.run(
            ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script),
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            env=self.environment,
        )
        if result.returncode:
            raise WriterHandoffError("fixed Windows inspection command failed")
        return result.stdout.strip()

    def _listener_pids(self, port: int) -> tuple[int, ...]:
        output = self._powershell(
            f"@(Get-NetTCPConnection -State Listen -LocalPort {port} "
            "-ErrorAction SilentlyContinue|Select-Object -ExpandProperty "
            "OwningProcess -Unique|Sort-Object)|ConvertTo-Json -Compress"
        )
        if not output:
            return ()
        value = json.loads(output)
        rows = value if isinstance(value, list) else [value]
        return tuple(sorted({int(item) for item in rows if int(item) > 0}))

    def _addresses(self) -> tuple[str, ...]:
        output = self._powershell(
            "@(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop|"
            "Where-Object {$_.AddressState-eq'Preferred'}|"
            "Select-Object -ExpandProperty IPAddress -Unique|Sort-Object)|"
            "ConvertTo-Json -Compress"
        )
        value = json.loads(output) if output else []
        rows = value if isinstance(value, list) else [value]
        return tuple(sorted(str(item) for item in rows))

    @staticmethod
    def _argv(command_line: str) -> tuple[str, ...]:
        if os.name != "nt":
            raise WriterHandoffError("writer handoff process parser requires Windows")
        import ctypes
        from ctypes import wintypes

        count = ctypes.c_int()
        command_to_argv = ctypes.windll.shell32.CommandLineToArgvW
        command_to_argv.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
        command_to_argv.restype = ctypes.POINTER(wintypes.LPWSTR)
        pointer = command_to_argv(command_line, ctypes.byref(count))
        if not pointer:
            raise WriterHandoffError("legacy command line cannot be parsed")
        try:
            return tuple(pointer[index] for index in range(count.value))
        finally:
            ctypes.windll.kernel32.LocalFree(pointer)

    def _process(self, pid: int) -> LegacyProcess:
        output = self._powershell(
            "$p=Get-CimInstance Win32_Process -Filter \"ProcessId="
            + str(pid)
            + "\" -ErrorAction Stop;"
            "$p|Select-Object ProcessId,ExecutablePath,CommandLine|"
            "ConvertTo-Json -Compress"
        )
        value = json.loads(output)
        if not isinstance(value, dict) or int(value.get("ProcessId", 0)) != pid:
            raise WriterHandoffError("listener process identity is unavailable")
        executable = Path(str(value.get("ExecutablePath", ""))).resolve(strict=True)
        argv = self._argv(str(value.get("CommandLine", "")))
        server = Path(str(LEGACY_SERVER)).resolve(strict=True)
        return LegacyProcess(
            pid,
            str(executable),
            argv,
            _path_hash(executable),
            _path_hash(server),
        )

    @staticmethod
    def _get(path: str) -> tuple[int, bytes]:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{PORT}{path}", timeout=5
            ) as response:
                return int(response.status), response.read(1024 * 1024 + 1)
        except urllib.error.HTTPError as error:
            return int(error.code), error.read(1024 * 1024 + 1)
        except (OSError, urllib.error.URLError):
            return 0, b""

    def _deployment(self) -> Mapping[str, object] | None:
        status, body = self._get("/deploymentz")
        if status != 200 or len(body) > 1024 * 1024:
            return None
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    def _service(self) -> Mapping[str, object]:
        output = self._powershell(
            "$s=Get-Service -Name 'QuantResearchHub' -ErrorAction Stop;"
            "@{Name=$s.Name;Status=$s.Status.ToString()}|ConvertTo-Json -Compress"
        )
        value = json.loads(output)
        candidate = build_install_candidate(self.root, SERVICE_NAME)
        binding = PyWin32ServiceInstaller().verify(candidate)
        return {
            "service_name": str(value.get("Name")),
            "installed": True,
            "status": str(value.get("Status", "")).casefold(),
            "binding_verified": binding is True,
        }

    def _legacy_server_pids(self) -> tuple[int, ...]:
        """Find every exact legacy server argv, independent of process memory."""

        output = self._powershell(
            "@(Get-CimInstance Win32_Process -Filter \"Name='python.exe' OR "
            "Name='pythonw.exe'\" -ErrorAction Stop|"
            "Select-Object ProcessId,CommandLine)|ConvertTo-Json -Compress"
        )
        if not output:
            return ()
        value = json.loads(output)
        rows = value if isinstance(value, list) else [value]
        matches: set[int] = set()
        for row in rows:
            if not isinstance(row, dict) or not row.get("CommandLine"):
                continue
            try:
                argv = self._argv(str(row["CommandLine"]))
                pid = int(row["ProcessId"])
            except (KeyError, TypeError, ValueError, WriterHandoffError):
                continue
            if (
                pid > 0
                and len(argv) == 3
                and argv[1] == "-I"
                and PureWindowsPath(argv[2]) == LEGACY_SERVER
            ):
                matches.add(pid)
        return tuple(sorted(matches))

    def observe(self, port: int) -> RuntimeObservation:
        require_failure_domain_authority()
        listeners = self._listener_pids(port)
        deployment = self._deployment()
        legacy_deployment: Mapping[str, object] | None = None
        process: LegacyProcess | None = None
        if (
            len(listeners) == 1
            and isinstance(deployment, Mapping)
            and deployment.get("schema_version") == "qrh-company-broadcast-health/v1"
        ):
            process = self._process(listeners[0])
            legacy_deployment = deployment
        return RuntimeObservation(
            self._addresses(), listeners, legacy_deployment, process, self._service()
        )

    def stop_legacy(self, expected: LegacyProcess) -> None:
        require_failure_domain_authority()
        observed = self._process(expected.pid)
        if observed != expected or self._listener_pids(PORT) != (expected.pid,):
            raise WriterHandoffError("legacy process changed before termination")
        result = subprocess.run(
            ("taskkill.exe", "/PID", str(expected.pid), "/T", "/F"),
            shell=False,
            check=False,
            capture_output=True,
            timeout=20,
            env=self.environment,
        )
        if result.returncode:
            raise WriterHandoffError("exact legacy PID termination failed")
        self._stopped_legacy = expected

    def wait_port_free(self, port: int) -> bool:
        require_failure_domain_authority()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if not self._listener_pids(port):
                return True
            time.sleep(0.25)
        return not self._listener_pids(port)

    def _service_action(self, action: str, service_name: str) -> None:
        if action not in {"start", "stop"} or service_name != SERVICE_NAME:
            raise WriterHandoffError("service action is outside fixed handoff contract")
        result = subprocess.run(
            ("sc.exe", action, service_name), shell=False, check=False,
            capture_output=True, timeout=30, env=self.environment,
        )
        # sc.exe returns 1062/1060 in text with a non-zero process result; the
        # handoff never treats those ambiguous states as success.
        if result.returncode:
            raise WriterHandoffError(f"fixed D service {action} failed")

    def start_d_service(self, service_name: str) -> None:
        require_failure_domain_authority()
        self._service_action("start", service_name)
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if self._listener_pids(PORT):
                self._d_was_open = True
                return
            if self._service().get("status") == "stopped":
                raise WriterHandoffError("D service stopped before opening its listener")
            time.sleep(0.1)
        raise WriterHandoffError("D service did not open its listener in time")

    def stop_d_service(self, service_name: str) -> None:
        require_failure_domain_authority()
        if self._service().get("status") != "stopped":
            self._service_action("stop", service_name)
        if not self.wait_port_free(PORT):
            raise WriterHandoffError("D listener remained open after service stop")

    def d_external_open(self, port: int) -> bool:
        require_failure_domain_authority()
        # Any listener after the D start attempt is exposure.  Ambiguity is
        # intentionally resolved toward forbidding legacy rollback.
        if self._listener_pids(port):
            self._d_was_open = True
        return self._d_was_open

    def probe_d(self, baseline: V39Baseline) -> Mapping[str, object]:
        require_failure_domain_authority()
        deadline = time.monotonic() + 45
        deployment: Mapping[str, object] | None = None
        while time.monotonic() < deadline:
            deployment = self._deployment()
            if deployment is not None:
                break
            time.sleep(0.25)
        listeners = self._listener_pids(PORT)
        pid = int(deployment.get("pid", 0)) if deployment is not None else 0
        status_login, login = self._get("/login")
        status_research, research = self._get("/api/v1/research")
        status_dashboard, dashboard = self._get("/api/v1/dashboard")
        try:
            research_body = json.loads(research.decode("utf-8"))
            dashboard_body = json.loads(dashboard.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            research_body = dashboard_body = None
        service = self._service()
        d_process_closed = False
        if listeners == (pid,) and pid > 0:
            output = self._powershell(
                "$p=Get-CimInstance Win32_Process -Filter \"ProcessId="
                + str(pid)
                + "\" -ErrorAction Stop;$p.CommandLine"
            ).replace("/", "\\").casefold()
            d_process_closed = (
                r"\quant_hub\ops\service_entry.py" in output
                and r"c:\quant_platform\tools\viewer\server.py" not in output
            )
        # This must survive an operator-process crash before explicit finalize;
        # do not rely on the in-memory PID captured by the original CLI.
        legacy_pid_stopped = not self._legacy_server_pids()
        return {
            "release_id": deployment.get("release_id") if deployment else None,
            "manifest_sha256": deployment.get("manifest_sha256") if deployment else None,
            "snapshot_id": deployment.get("snapshot_id") if deployment else None,
            "writer_authority": deployment.get("writer_authority") if deployment else None,
            "unique_d_listener": listeners == (pid,) and d_process_closed,
            "legacy_pid_stopped": legacy_pid_stopped and d_process_closed,
            "browser": status_login == 200 and b"Quant Research Hub" in login,
            "api": (
                status_research == 401
                and status_dashboard == 401
                and research_body == {"error": "authentication_required"}
                and dashboard_body == {"error": "authentication_required"}
            ),
            "resource": status_login == 200 and b"<style>" in login,
            "legacy_restart_fenced": (
                d_process_closed
                and service.get("status") == "running"
                and service.get("binding_verified") is True
            ),
        }

    def start_legacy(self, expected: LegacyProcess) -> None:
        require_failure_domain_authority()
        executable = Path(expected.executable).resolve(strict=True)
        server = Path(str(LEGACY_SERVER)).resolve(strict=True)
        if (
            _path_hash(executable) != expected.executable_sha256
            or _path_hash(server) != expected.server_sha256
            or len(expected.argv) != 3
            or PureWindowsPath(expected.argv[0]) != PureWindowsPath(str(executable))
            or expected.argv[1] != "-I"
            or PureWindowsPath(expected.argv[2]) != LEGACY_SERVER
        ):
            raise WriterHandoffError("legacy executable/server changed before rollback")
        environment = {
            **self.environment,
            "PYTHONUTF8": "1",
            "PYTHONIOENCODING": "utf-8",
        }
        subprocess.Popen(
            list(expected.argv), cwd=str(LEGACY_ROOT), env=environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=(
                subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
            ),
            close_fds=True,
        )

    def verify_legacy_restored(
        self, expected: LegacyProcess, deployment_id: str, port: int
    ) -> bool:
        require_failure_domain_authority()
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            deployment = self._deployment()
            listeners = self._listener_pids(port)
            if (
                deployment is not None
                and deployment.get("deployment_id") == deployment_id
                and len(listeners) == 1
            ):
                try:
                    process = self._process(listeners[0])
                except Exception:
                    process = None
                if (
                    process is not None
                    and process.executable_sha256 == expected.executable_sha256
                    and process.server_sha256 == expected.server_sha256
                    and process.argv == expected.argv
                ):
                    return True
            time.sleep(0.25)
        return False


DClosureVerifier = Callable[[Path, V39Baseline], Mapping[str, object]]
CheckpointBuilder = Callable[..., CheckpointCreation]


def _sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        raise WriterHandoffError(f"{label} SHA-256 is invalid")
    return value


def _identifier(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or _ID_RE.fullmatch(value) is None
        or ".." in value
    ):
        raise WriterHandoffError(f"{label} is invalid")
    return value


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise WriterHandoffError("handoff timestamp must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise WriterHandoffError("handoff timestamp is not canonical UTC")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise WriterHandoffError("handoff timestamp lacks timezone")
    return parsed.astimezone(UTC)


def _path_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_read(path: Path) -> Mapping[str, object]:
    value = read_json(path)
    if not isinstance(value, dict):
        raise WriterHandoffError("handoff evidence is not an immutable JSON object")
    return value


def _root(vm_root: Path, *, allow_test_root: bool) -> Path:
    if not vm_root.is_absolute():
        raise WriterHandoffError("VM root must be absolute")
    ensure_no_reparse_components(vm_root)
    root = vm_root.resolve(strict=True)
    ensure_no_reparse_components(root)
    if not allow_test_root and PureWindowsPath(str(root)) != PRODUCTION_VM_ROOT:
        raise WriterHandoffError(r"writer handoff root must be D:\quant\quant_platform")
    return root


def _inside(root: Path, relative: str, *, file: bool = True) -> Path:
    target = root.joinpath(*Path(relative).parts).resolve(strict=True)
    ensure_no_reparse_components(target)
    if not target.is_relative_to(root) or (file and not target.is_file()):
        raise WriterHandoffError("D-root closure path is invalid")
    return target


def _sqlite_closed(path: Path) -> Mapping[str, object]:
    ensure_no_reparse_components(path)
    try:
        connection = sqlite3.connect(
            f"file:{path.resolve(strict=True).as_posix()}?mode=ro", uri=True, timeout=15
        )
        connection.execute("PRAGMA query_only=ON")
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        foreign_keys = list(connection.execute("PRAGMA foreign_key_check"))
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    except (OSError, sqlite3.Error) as error:
        raise WriterHandoffError("D state database is unavailable") from error
    finally:
        if "connection" in locals():
            connection.close()
    if integrity != ("ok",) or foreign_keys:
        raise WriterHandoffError("D state database failed integrity verification")
    return {
        "integrity": True,
        "foreign_keys": True,
        "user_version": user_version,
        "bytes": path.stat().st_size,
        "sha256": _path_hash(path),
    }


def _session_key_precondition(root: Path) -> str:
    """Validate an existing key without requiring cold recovery to ship one."""

    path = root / "state" / "viewer_secret.key"
    ensure_no_reparse_components(path.parent)
    ensure_no_reparse_components(path)
    if not path.exists():
        return "pending_first_production_start"
    if not path.is_file():
        raise WriterHandoffError("protected D session key is not a regular file")
    value = path.read_text(encoding="ascii").strip()
    if _SHA_RE.fullmatch(value) is None:
        raise WriterHandoffError("protected D session key is invalid")
    return "valid_existing"


def _session_key_ready(root: Path) -> bool:
    return _session_key_precondition(root) == "valid_existing"


def _find_recovery_evidence(
    root: Path, baseline: V39Baseline
) -> Mapping[str, object]:
    require_failure_domain_authority()
    materializations: list[tuple[str, str]] = []
    for path in (root / "audit" / "events").glob("cold-materialization-*.json"):
        # The shipped empty-D restorer writes this event from PowerShell.  Its
        # exact bytes are hashed into the off-host attestation, but it predates
        # the canonical-JSON receipt writer and therefore is not reserialized.
        value = read_json(path)
        fields = value.get("fields")
        if (
            value.get("schema_version") == "qrh-recovery-materialization-event/v1"
            and value.get("kind") == "cold_recovery_materialized"
            and value.get("authority") == "evidence_only"
            and isinstance(fields, dict)
            and fields.get("release_id") == baseline.release_id
            and fields.get("manifest_sha256") == baseline.manifest_sha256
            and all(
                fields.get(name) is True
                for name in (
                    "empty_root_precondition",
                    "import_cleaned",
                    "runtime_tmp_cleaned",
                )
            )
        ):
            materializations.append((str(value.get("event_id")), _path_hash(path)))
    recoveries: list[tuple[str, str, str, str]] = []
    protections: list[tuple[str, str, str, str]] = []
    candidates = list((root / "audit").glob("*.json")) + list(
        (root / "audit" / "receipts").glob("*.json")
    )
    for path in candidates:
        try:
            value = validate_receipt(_canonical_read(path))
        except Exception:
            continue
        if value.get("release_manifest_sha256") != baseline.manifest_sha256:
            continue
        if value.get("receipt_type") == "recovery" and value.get("verdict") == "recovered":
            verification = value.get("restore_verification")
            if isinstance(verification, dict) and all(
                verification.get(name) is True
                for name in ("closure", "state_restored", "service_started", "post_restore")
            ):
                recoveries.append(
                    (
                        str(value["receipt_id"]),
                        _path_hash(path),
                        str(value["recovery_manifest_sha256"]),
                        str(value["checkpoint_manifest_sha256"]),
                    )
                )
        if value.get("receipt_type") == "recovery_protection":
            verification = value.get("pre_activation_verification")
            if (
                value.get("verdict") == "protected"
                and isinstance(verification, dict)
                and verification.get("failure_domain") is True
                and verification.get("active_pointer_switched") is False
            ):
                protections.append(
                    (
                        str(value["receipt_id"]),
                        _path_hash(path),
                        str(value["recovery_manifest_sha256"]),
                        str(value["checkpoint_manifest_sha256"]),
                    )
                )
    matching_pairs = [
        (recovery, protection)
        for recovery in recoveries
        for protection in protections
        if recovery[2:] == protection[2:]
    ]
    if not materializations or not matching_pairs:
        raise WriterHandoffError(
            "empty-D recovery and final failure-domain protection evidence are incomplete"
        )
    materialization = sorted(materializations)[-1]
    recovery, protection = sorted(matching_pairs)[-1]
    return {
        "materialization_event_id": materialization[0],
        "materialization_event_sha256": materialization[1],
        "recovery_receipt_id": recovery[0],
        "recovery_receipt_sha256": recovery[1],
        "recovery_protection_receipt_id": protection[0],
        "recovery_protection_receipt_sha256": protection[1],
        "recovery_manifest_sha256": recovery[2],
        "checkpoint_manifest_sha256": recovery[3],
        "failure_domain_attestation_schema": "unavailable-v2",
        "failure_domain_accepted": False,
    }


def inspect_d_closure(root: Path, baseline: V39Baseline) -> Mapping[str, object]:
    """Mechanically validate the read-only D active/control/state closure."""

    require_failure_domain_authority()
    active_path = _inside(root, "control/active_release.json")
    active = validate_active_release(read_json(active_path))
    release_path = (root / "releases" / baseline.release_id).resolve(strict=True)
    ensure_no_reparse_components(release_path)
    if (
        active.get("release_id") != baseline.release_id
        or active.get("manifest_sha256") != baseline.manifest_sha256
        or Path(str(active.get("release_path"))).resolve(strict=True) != release_path
    ):
        raise WriterHandoffError("D active authority is not exact V39")
    manifest_path = _inside(release_path, "release_manifest.json")
    manifest = validate_release_manifest(read_json(manifest_path))
    content = manifest.get("content")
    if (
        manifest.get("release_id") != baseline.release_id
        or manifest_sha256(manifest) != baseline.manifest_sha256
        or not isinstance(content, dict)
        or content.get("snapshot_id") != baseline.snapshot_id
    ):
        raise WriterHandoffError("D release/manifest/snapshot is not exact V39")
    runtime_path = _inside(root, "control/deployment_runtime.json")
    if read_json(runtime_path) != production_runtime_document():
        raise WriterHandoffError("D deployment runtime is not the closed production topology")
    service_candidate = _inside(root, "control/service_install_candidate.json")
    bindings = verify_installed_operational_bindings(root)
    if not bindings:
        raise WriterHandoffError("D service operational bindings are incomplete")

    state = root / "state"
    ensure_no_reparse_components(state)
    digest = _inside(root, "state/viewer_access_password.digest").read_text(
        encoding="ascii"
    ).strip()
    if _SHA_RE.fullmatch(digest) is None:
        raise WriterHandoffError("protected D access state is invalid")
    session_key_status = _session_key_precondition(root)
    comments = _sqlite_closed(_inside(root, "state/comments.sqlite3"))
    workspace = _sqlite_closed(_inside(root, "state/research_workspace.sqlite3"))
    evidence = _find_recovery_evidence(root, baseline)
    return {
        "active_release_sha256": _path_hash(active_path),
        "release_manifest_sha256": baseline.manifest_sha256,
        "snapshot_id": baseline.snapshot_id,
        "deployment_runtime_sha256": _path_hash(runtime_path),
        "service_install_candidate_sha256": _path_hash(service_candidate),
        "operational_bindings_verified": True,
        "protected_access_state_present": True,
        "protected_session_key_status": session_key_status,
        "state": {"comments": comments, "research_workspace": workspace},
        "recovery": evidence,
    }


def _access_override_present() -> bool:
    """Detect override evidence without returning or logging its value."""

    if "VIEWER_ACCESS_PASSWORD" in os.environ:
        return True
    if os.name != "nt":
        return False
    try:
        import winreg

        locations = (
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", "VIEWER_ACCESS_PASSWORD"),
            (winreg.HKEY_CURRENT_USER, r"Environment", "VIEWER_ACCESS_PASSWORD"),
        )
        for hive, key_name, value_name in locations:
            try:
                with winreg.OpenKey(hive, key_name, 0, winreg.KEY_READ) as key:
                    winreg.QueryValueEx(key, value_name)
            except FileNotFoundError:
                continue
            else:
                return True
        # A service-local Environment multi-string is separate from the
        # machine/user scopes.  Its value is discarded immediately and never
        # included in evidence or an exception.
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                rf"SYSTEM\CurrentControlSet\Services\{SERVICE_NAME}",
                0,
                winreg.KEY_READ,
            ) as key:
                service_environment, _ = winreg.QueryValueEx(key, "Environment")
        except FileNotFoundError:
            return False
        rows = (
            service_environment
            if isinstance(service_environment, (list, tuple))
            else (service_environment,)
        )
        return any(
            isinstance(row, str)
            and row.split("=", 1)[0].casefold() == "viewer_access_password"
            for row in rows
        )
    except OSError as error:
        raise WriterHandoffError("access override evidence could not be inspected") from error


def _ast_bytes_hex(module: ast.Module, name: str) -> bytes:
    assignments = [
        node
        for node in module.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == name
    ]
    if len(assignments) != 1:
        raise WriterHandoffError("V39 access constant contract differs")
    value = assignments[0].value
    if (
        not isinstance(value, ast.Call)
        or value.keywords
        or len(value.args) != 1
        or not isinstance(value.func, ast.Attribute)
        or value.func.attr != "fromhex"
        or not isinstance(value.func.value, ast.Name)
        or value.func.value.id != "bytes"
        or not isinstance(value.args[0], ast.Constant)
        or not isinstance(value.args[0].value, str)
    ):
        raise WriterHandoffError("V39 access constant contract differs")
    try:
        return bytes.fromhex(value.args[0].value)
    except ValueError as error:
        raise WriterHandoffError("V39 access constant contract differs") from error


def _ast_integer(module: ast.Module, name: str) -> int:
    assignments = [
        node
        for node in module.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == name
    ]
    if (
        len(assignments) != 1
        or not isinstance(assignments[0].value, ast.Constant)
        or not isinstance(assignments[0].value.value, int)
        or isinstance(assignments[0].value.value, bool)
    ):
        raise WriterHandoffError("V39 access constant contract differs")
    return int(assignments[0].value.value)


def _extract_v39_default_access_identity(source: bytes) -> bytes:
    try:
        module = ast.parse(source.decode("utf-8"), filename="V39/tools/viewer/server.py")
    except (UnicodeDecodeError, SyntaxError) as error:
        raise WriterHandoffError("V39 server source is not parseable reviewed Python") from error
    salt = _ast_bytes_hex(module, "ACCESS_PASSWORD_SALT")
    iterations = _ast_integer(module, "ACCESS_PASSWORD_ITERATIONS")
    digest = _ast_bytes_hex(module, "DEFAULT_ACCESS_PASSWORD_DIGEST")
    functions = [
        node
        for node in module.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "_access_password_digest"
    ]
    expected_function = ast.parse(
        """def _access_password_digest() -> bytes:
    configured = os.environ.get("VIEWER_ACCESS_PASSWORD")
    if configured is None:
        return DEFAULT_ACCESS_PASSWORD_DIGEST
    if not configured:
        raise RuntimeError("override must not be empty")
    return hashlib.pbkdf2_hmac(
        "sha256",
        configured.encode("utf-8"),
        ACCESS_PASSWORD_SALT,
        ACCESS_PASSWORD_ITERATIONS,
    )
"""
    ).body[0]
    # The exception message is not security-relevant and may contain mojibake
    # in the sealed V39 source.  Normalize only that literal before comparing
    # every executable AST node in the reviewed fallback/override contract.
    if len(functions) == 1:
        actual_function = functions[0]
        for node in ast.walk(actual_function):
            if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call) and node.exc.args:
                node.exc.args[0] = ast.Constant(value="override must not be empty")
    if (
        len(functions) != 1
        or ast.dump(functions[0], include_attributes=False)
        != ast.dump(expected_function, include_attributes=False)
        or salt != ACCESS_PASSWORD_SALT
        or iterations != ACCESS_PASSWORD_ITERATIONS
        or len(digest) != 32
    ):
        raise WriterHandoffError("V39 default access identity contract differs")
    return digest


def seed_v39_access_identity(
    *,
    vm_root: Path,
    baseline: V39Baseline,
    allow_test_root: bool = False,
    override_detector: Callable[[], bool] = _access_override_present,
) -> Mapping[str, object]:
    """Seed only the sealed V39 default access identity into protected D state.

    No password/digest is accepted as input or returned as evidence.  The
    immutable source file must itself be present in, and byte-bound by, the
    exact active release manifest before its constants are parsed without
    executing legacy code.
    """

    require_failure_domain_authority()

    root = _root(vm_root, allow_test_root=allow_test_root)
    if override_detector():
        raise WriterHandoffError(
            "access override evidence exists; a protected credential path is required"
        )
    active = validate_active_release(read_json(_inside(root, "control/active_release.json")))
    release = (root / "releases" / baseline.release_id).resolve(strict=True)
    ensure_no_reparse_components(release)
    if (
        active.get("release_id") != baseline.release_id
        or active.get("manifest_sha256") != baseline.manifest_sha256
        or Path(str(active.get("release_path"))).resolve(strict=True) != release
    ):
        raise WriterHandoffError("access seed active V39 identity differs")
    manifest = validate_release_manifest(read_json(_inside(release, "release_manifest.json")))
    content = manifest.get("content")
    if (
        manifest.get("release_id") != baseline.release_id
        or manifest_sha256(manifest) != baseline.manifest_sha256
        or not isinstance(content, Mapping)
        or content.get("snapshot_id") != baseline.snapshot_id
    ):
        raise WriterHandoffError("access seed release V39 identity differs")
    inventory = manifest.get("inventory")
    files = inventory.get("files") if isinstance(inventory, Mapping) else None
    records = [
        item
        for item in files if isinstance(item, Mapping) and item.get("path") == "tools/viewer/server.py"
    ] if isinstance(files, list) else []
    if len(records) != 1 or set(records[0]) != {"path", "bytes", "sha256"}:
        raise WriterHandoffError("V39 server is not uniquely bound by release inventory")
    server = _inside(release, "tools/viewer/server.py")
    before = server.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or server.is_symlink()
        or before.st_nlink != 1
    ):
        raise WriterHandoffError("V39 server is not immutable regular material")
    source = server.read_bytes()
    after = server.lstat()
    if (
        (before.st_size, before.st_mtime_ns, before.st_dev, before.st_ino, before.st_nlink)
        != (after.st_size, after.st_mtime_ns, after.st_dev, after.st_ino, after.st_nlink)
        or len(source) != after.st_size
        or not stat.S_ISREG(after.st_mode)
        or server.is_symlink()
    ):
        raise WriterHandoffError("V39 server changed while access identity was inspected")
    source_hash = hashlib.sha256(source).hexdigest()
    if (
        records[0].get("bytes") != len(source)
        or records[0].get("sha256") != source_hash
    ):
        raise WriterHandoffError("V39 server bytes differ from release inventory")
    digest = _extract_v39_default_access_identity(source)
    state = (root / "state").resolve(strict=True)
    ensure_no_reparse_components(state)
    if not state.is_dir() or not state.is_relative_to(root):
        raise WriterHandoffError("protected D state root is unavailable")
    destination = state / "viewer_access_password.digest"
    payload = digest.hex().encode("ascii") + b"\n"
    status = "reused"
    if destination.exists():
        ensure_no_reparse_components(destination)
        if not destination.is_file() or destination.is_symlink() or destination.read_bytes() != payload:
            raise WriterHandoffError("existing protected access identity differs")
    else:
        temporary = destination.with_name(f".{destination.name}.{uuid4().hex}.partial")
        try:
            with temporary.open("xb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, destination)
            except FileExistsError:
                if not destination.is_file() or destination.is_symlink() or destination.read_bytes() != payload:
                    raise WriterHandoffError("protected access identity publication race differs")
            if destination.read_bytes() != payload:
                raise WriterHandoffError("protected access identity publication differs")
            status = "seeded"
        finally:
            temporary.unlink(missing_ok=True)
    return {
        "schema_version": ACCESS_IDENTITY_SCHEMA,
        "status": status,
        "contract_version": ACCESS_IDENTITY_CONTRACT,
        "source_server_sha256": source_hash,
        "protected_access_identity_present": True,
        "override_evidence_absent": True,
    }


def _validate_legacy(
    observation: RuntimeObservation, baseline: V39Baseline
) -> LegacyProcess:
    if TARGET_ADDRESS not in observation.target_addresses:
        raise WriterHandoffError("handoff host is not the sole .240 target")
    if len(observation.listener_pids) != 1:
        raise WriterHandoffError("production port must have exactly one listener")
    deployment = observation.legacy_deployment
    process = observation.legacy_process
    if not isinstance(deployment, Mapping) or process is None:
        raise WriterHandoffError("legacy V39 listener identity is unavailable")
    if (
        deployment.get("schema_version") != "qrh-company-broadcast-health/v1"
        or deployment.get("status") != "ok"
        or deployment.get("deployment_id") != baseline.legacy_deployment_id
        or deployment.get("pid") != process.pid
        or deployment.get("port") != PORT
        or observation.listener_pids != (process.pid,)
    ):
        raise WriterHandoffError("legacy /deploymentz does not bind the sole listener")
    if process.pid <= 0:
        raise WriterHandoffError("legacy PID is invalid")
    executable = PureWindowsPath(process.executable)
    argv = tuple(PureWindowsPath(value) if index in {0, 2} else value for index, value in enumerate(process.argv))
    if (
        not executable.is_absolute()
        or executable.suffix.casefold() != ".exe"
        or len(argv) != 3
        or PureWindowsPath(str(argv[0])) != executable
        or argv[1] != "-I"
        or PureWindowsPath(str(argv[2])) != LEGACY_SERVER
    ):
        raise WriterHandoffError("legacy process executable/server argv is not exact")
    _sha(process.executable_sha256, label="legacy executable")
    _sha(process.server_sha256, label="legacy server")
    service = observation.d_service
    if (
        not isinstance(service, Mapping)
        or service.get("service_name") != SERVICE_NAME
        or service.get("installed") is not True
        or service.get("status") != "stopped"
        or service.get("binding_verified") is not True
    ):
        raise WriterHandoffError("D service is not installed, exact-bound and stopped")
    return process


def _observation_binding(
    *, baseline: V39Baseline, process: LegacyProcess, closure: Mapping[str, object]
) -> Mapping[str, object]:
    return {
        "target_address": TARGET_ADDRESS,
        "port": PORT,
        "v39": {
            "release_id": baseline.release_id,
            "manifest_sha256": baseline.manifest_sha256,
            "snapshot_id": baseline.snapshot_id,
            "legacy_deployment_id": baseline.legacy_deployment_id,
        },
        "legacy_process": process.document(),
        "legacy_state": {
            "authority": "C-legacy",
            "root": str(LEGACY_STATE_ROOT),
            "comments": str(LEGACY_STATE_ROOT / "comments.sqlite3"),
            "research_workspace": str(LEGACY_STATE_ROOT / "research_workspace.sqlite3"),
        },
        "d": closure,
        "d_service": {
            "service_name": SERVICE_NAME,
            "status": "stopped",
            "binding_verified": True,
        },
    }


def inspect_writer_handoff(
    *,
    vm_root: Path,
    baseline: V39Baseline,
    runtime: HandoffRuntime,
    nonce: str,
    inspected_at: datetime | None = None,
    allow_test_root: bool = False,
    closure_verifier: DClosureVerifier = inspect_d_closure,
) -> Mapping[str, object]:
    """Return, but do not persist, one immutable read-only inspection receipt."""

    require_failure_domain_authority()
    if _NONCE_RE.fullmatch(nonce) is None:
        raise WriterHandoffError("inspection nonce must be 24 random bytes")
    root = _root(vm_root, allow_test_root=allow_test_root)
    observation = runtime.observe(PORT)
    process = _validate_legacy(observation, baseline)
    closure = closure_verifier(root, baseline)
    receipt = {
        "schema_version": INSPECT_SCHEMA,
        "inspection_id": f"writer-handoff-inspect-{nonce[:20]}",
        "inspected_at": _timestamp(inspected_at or datetime.now(UTC)),
        "nonce": nonce,
        "authority": "evidence_only",
        "mutation_performed": False,
        "observation": _observation_binding(
            baseline=baseline, process=process, closure=closure
        ),
    }
    validate_inspection_receipt(receipt)
    return receipt


def validate_inspection_receipt(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "inspection_id",
        "inspected_at",
        "nonce",
        "authority",
        "mutation_performed",
        "observation",
    }:
        raise WriterHandoffError("inspection receipt schema is not closed")
    if (
        value.get("schema_version") != INSPECT_SCHEMA
        or value.get("authority") != "evidence_only"
        or value.get("mutation_performed") is not False
        or _NONCE_RE.fullmatch(str(value.get("nonce"))) is None
    ):
        raise WriterHandoffError("inspection receipt contract differs")
    _identifier(value.get("inspection_id"), label="inspection ID")
    _parse_timestamp(value.get("inspected_at"))
    observation = value.get("observation")
    if not isinstance(observation, dict) or set(observation) != {
        "target_address", "port", "v39", "legacy_process", "legacy_state", "d", "d_service"
    }:
        raise WriterHandoffError("inspection observation schema is not closed")
    if observation.get("target_address") != TARGET_ADDRESS or observation.get("port") != PORT:
        raise WriterHandoffError("inspection target differs")
    return value


def _process_from_receipt(receipt: Mapping[str, object]) -> LegacyProcess:
    observation = receipt["observation"]
    assert isinstance(observation, Mapping)
    value = observation["legacy_process"]
    if not isinstance(value, Mapping):
        raise WriterHandoffError("inspection legacy process is invalid")
    try:
        process = LegacyProcess(
            pid=int(value["pid"]),
            executable=str(value["executable"]),
            argv=tuple(str(item) for item in value["argv"]),
            executable_sha256=str(value["executable_sha256"]),
            server_sha256=str(value["server_sha256"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise WriterHandoffError("inspection legacy process is invalid") from error
    return process


@contextmanager
def _handoff_lock(root: Path, nonce: str) -> Iterator[None]:
    lock = root / "state" / "locks" / "writer-handoff.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    ensure_no_reparse_components(lock.parent)
    try:
        descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise WriterHandoffError("writer handoff lock already exists") from error
    try:
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
            stream.write(nonce + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        yield
    finally:
        try:
            if lock.read_text(encoding="ascii").strip() == nonce:
                lock.unlink()
        except OSError:
            pass


def _receipt_dirs(root: Path) -> tuple[Path, Path]:
    success = root / "audit" / "writer-handoff" / "success"
    failure = root / "audit" / "writer-handoff" / "failure"
    for path in (success, failure):
        path.mkdir(parents=True, exist_ok=True)
        ensure_no_reparse_components(path)
    return success, failure


def _ensure_unconsumed(root: Path, inspection_hash: str) -> None:
    for directory in _receipt_dirs(root):
        for path in directory.glob("*.json"):
            try:
                value = _canonical_read(path)
            except Exception:
                raise WriterHandoffError("existing handoff receipt is unreadable")
            if value.get("inspection_sha256") == inspection_hash:
                raise WriterHandoffError("inspection receipt was already consumed")


def _state_sources(root: Path) -> Mapping[str, Path]:
    return {
        "comments": root / "state" / "comments.sqlite3",
        "research_workspace": root / "state" / "research_workspace.sqlite3",
    }


def _legacy_sources() -> Mapping[str, Path]:
    return {
        "comments": Path(str(LEGACY_STATE_ROOT / "comments.sqlite3")),
        "research_workspace": Path(
            str(LEGACY_STATE_ROOT / "research_workspace.sqlite3")
        ),
    }


def _checkpoint_database_paths(checkpoint_root: Path) -> Mapping[str, Path]:
    report = verify_sqlite_checkpoint(checkpoint_root)
    if not report.valid:
        raise WriterHandoffError("handoff checkpoint failed restore verification")
    return {
        "comments": checkpoint_root / "state" / "comments.sqlite3",
        "research_workspace": checkpoint_root / "state" / "research_workspace.sqlite3",
    }


def _replace_d_state(
    *, root: Path, checkpoint_root: Path, attempt_id: str
) -> None:
    sources = _checkpoint_database_paths(checkpoint_root)
    staging = root / "tmp" / "writer-handoff" / attempt_id / "state"
    if staging.exists():
        raise WriterHandoffError("handoff state staging already exists")
    staging.mkdir(parents=True)
    ensure_no_reparse_components(staging)
    try:
        for logical_name, source in sources.items():
            target = staging / f"{logical_name}.sqlite3"
            shutil.copy2(source, target)
            _sqlite_closed(target)
        destinations = _state_sources(root)
        for logical_name, destination in destinations.items():
            os.replace(staging / f"{logical_name}.sqlite3", destination)
        for destination in destinations.values():
            _sqlite_closed(destination)
    finally:
        shutil.rmtree(staging.parent, ignore_errors=True)


def _checkpoint(
    *,
    builder: CheckpointBuilder,
    sources: Mapping[str, Path],
    root: Path,
    checkpoint_id: str,
    authority: str,
    baseline: V39Baseline,
    captured_at: datetime,
) -> CheckpointCreation:
    creation = builder(
        sources=sources,
        checkpoint_root=root / "backups" / "checkpoints",
        checkpoint_id=checkpoint_id,
        state_authority_id=authority,
        captured_under_release_id=baseline.release_id,
        captured_under_manifest_sha256=baseline.manifest_sha256,
        captured_at=captured_at,
        scratch_root=root / "tmp" / "writer-handoff" / "restore-proof",
    )
    report = verify_sqlite_checkpoint(
        creation.root, scratch_root=root / "tmp" / "writer-handoff" / "restore-proof"
    )
    if not report.valid or report.manifest_sha256 != creation.manifest_sha256:
        raise WriterHandoffError("new handoff checkpoint failed final verification")
    return creation


def _write_receipt(path: Path, receipt: Mapping[str, object]) -> Path:
    if path.exists():
        raise WriterHandoffError("immutable handoff receipt ID already exists")
    write_atomic_new_json(path, receipt)
    return path.resolve(strict=True)


def _journal_document(
    *,
    attempt_id: str,
    nonce: str,
    inspection_hash: str,
    baseline: V39Baseline,
    phase: str,
    commit_evidence: Mapping[str, object] | None = None,
) -> Mapping[str, object]:
    if phase not in {
        "legacy_stop_pending",
        "d_start_authorized",
        "handoff_committed_receipt_pending",
        "legacy_restored_fenced",
        "handoff_failed_fenced",
    }:
        raise WriterHandoffError("writer handoff journal phase is invalid")
    inspection_hash = _sha(inspection_hash, label="inspection receipt")
    if phase == "handoff_committed_receipt_pending":
        if not isinstance(commit_evidence, Mapping):
            raise WriterHandoffError("committed handoff journal lacks terminal evidence")
        expected_keys = {
            "recorded_at",
            "final_checkpoint_id",
            "final_checkpoint_manifest_sha256",
            "prehandoff_checkpoint_id",
            "prehandoff_checkpoint_manifest_sha256",
        }
        if set(commit_evidence) != expected_keys:
            raise WriterHandoffError("committed handoff journal evidence is invalid")
        _parse_timestamp(commit_evidence["recorded_at"])
        for field in ("final_checkpoint_id", "prehandoff_checkpoint_id"):
            _identifier(str(commit_evidence[field]), label=field)
        for field in (
            "final_checkpoint_manifest_sha256",
            "prehandoff_checkpoint_manifest_sha256",
        ):
            _sha(commit_evidence[field], label=field)
        terminal: Mapping[str, object] | None = dict(commit_evidence)
    else:
        if commit_evidence is not None:
            raise WriterHandoffError("non-terminal handoff journal contains commit evidence")
        terminal = None
    return {
        "schema_version": JOURNAL_SCHEMA,
        "attempt_id": attempt_id,
        "nonce_sha256": hashlib.sha256(nonce.encode("ascii")).hexdigest(),
        "inspection_sha256": inspection_hash,
        "success_receipt_id": f"writer-handoff-success-{attempt_id}",
        "release_id": baseline.release_id,
        "manifest_sha256": baseline.manifest_sha256,
        "phase": phase,
        "commit_evidence": terminal,
        "authority": "coordination_only",
    }


def _write_journal(
    root: Path,
    *,
    attempt_id: str,
    nonce: str,
    inspection_hash: str,
    baseline: V39Baseline,
    phase: str,
    commit_evidence: Mapping[str, object] | None = None,
    create: bool = False,
) -> Path:
    path = root / "control" / "writer_handoff_pending.json"
    value = _journal_document(
        attempt_id=attempt_id,
        nonce=nonce,
        inspection_hash=inspection_hash,
        baseline=baseline,
        phase=phase,
        commit_evidence=commit_evidence,
    )
    if create:
        if path.exists():
            existing = _canonical_read(path)
            prior_attempt = existing.get("attempt_id")
            failure_path = (
                root
                / "audit"
                / "writer-handoff"
                / "failure"
                / f"writer-handoff-failure-{prior_attempt}.json"
            )
            try:
                failure = _canonical_read(failure_path)
            except Exception as error:
                raise WriterHandoffError(
                    "a prior writer handoff journal requires explicit recovery"
                ) from error
            rollback = failure.get("legacy_rollback")
            if (
                existing.get("schema_version") != JOURNAL_SCHEMA
                or existing.get("phase") != "legacy_restored_fenced"
                or existing.get("authority") != "coordination_only"
                or failure.get("schema_version") != FAILURE_SCHEMA
                or failure.get("attempt_id") != prior_attempt
                or failure.get("d_external_open") is not False
                or not isinstance(rollback, dict)
                or rollback.get("succeeded") is not True
            ):
                raise WriterHandoffError(
                    "a prior writer handoff journal requires explicit recovery"
                )
            temporary = path.with_name(f".{path.name}.partial-{uuid4().hex}")
            temporary.write_bytes(canonical_manifest_bytes(value))
            os.replace(temporary, path)
        else:
            write_atomic_new_json(path, value)
    else:
        existing = _canonical_read(path)
        if (
            existing.get("schema_version") != JOURNAL_SCHEMA
            or existing.get("attempt_id") != attempt_id
            or existing.get("nonce_sha256") != value["nonce_sha256"]
            or existing.get("inspection_sha256") != value["inspection_sha256"]
            or existing.get("success_receipt_id") != value["success_receipt_id"]
            or existing.get("release_id") != baseline.release_id
            or existing.get("manifest_sha256") != baseline.manifest_sha256
            or existing.get("authority") != "coordination_only"
        ):
            raise WriterHandoffError("writer handoff journal identity changed")
        temporary = path.with_name(f".{path.name}.partial-{uuid4().hex}")
        temporary.write_bytes(canonical_manifest_bytes(value))
        os.replace(temporary, path)
    return path


def _remove_journal(
    root: Path, *, attempt_id: str, nonce: str, baseline: V39Baseline
) -> None:
    path = root / "control" / "writer_handoff_pending.json"
    value = _canonical_read(path)
    success_path = (
        root
        / "audit"
        / "writer-handoff"
        / "success"
        / f"writer-handoff-success-{attempt_id}.json"
    )
    success = _canonical_read(success_path)
    if (
        value.get("schema_version") != JOURNAL_SCHEMA
        or value.get("attempt_id") != attempt_id
        or value.get("nonce_sha256")
        != hashlib.sha256(nonce.encode("ascii")).hexdigest()
        or value.get("phase") != "handoff_committed_receipt_pending"
        or value.get("success_receipt_id") != success.get("receipt_id")
        or success.get("schema_version") != SUCCESS_SCHEMA
        or success.get("attempt_id") != attempt_id
        or success.get("release_id") != baseline.release_id
        or success.get("release_manifest_sha256") != baseline.manifest_sha256
        or success.get("inspection_sha256") != value.get("inspection_sha256")
        or not isinstance(value.get("commit_evidence"), Mapping)
        or success.get("recorded_at")
        != value["commit_evidence"].get("recorded_at")
        or success.get("final_checkpoint_id")
        != value["commit_evidence"].get("final_checkpoint_id")
        or success.get("final_checkpoint_manifest_sha256")
        != value["commit_evidence"].get("final_checkpoint_manifest_sha256")
        or success.get("prehandoff_checkpoint_id")
        != value["commit_evidence"].get("prehandoff_checkpoint_id")
        or success.get("prehandoff_checkpoint_manifest_sha256")
        != value["commit_evidence"].get("prehandoff_checkpoint_manifest_sha256")
    ):
        raise WriterHandoffError("writer handoff journal cannot be safely cleared")
    path.unlink()


def _failure_receipt(
    *,
    root: Path,
    attempt_id: str,
    recorded_at: datetime,
    inspection_hash: str,
    nonce: str,
    baseline: V39Baseline,
    failed_phase: str,
    error_code: str,
    final_checkpoint: CheckpointCreation | None,
    prehandoff_checkpoint: CheckpointCreation | None,
    rollback_attempted: bool,
    rollback_succeeded: bool,
    d_state_restore_succeeded: bool,
    rollback_blocked: bool,
    d_external_open: bool,
) -> Path:
    receipt = {
        "schema_version": FAILURE_SCHEMA,
        "receipt_type": "writer_handoff_failure",
        "receipt_id": f"writer-handoff-failure-{attempt_id}",
        "attempt_id": attempt_id,
        "recorded_at": _timestamp(recorded_at),
        "authority": "evidence_only",
        "inspection_sha256": inspection_hash,
        "inspection_nonce_sha256": hashlib.sha256(nonce.encode("ascii")).hexdigest(),
        "release_id": baseline.release_id,
        "release_manifest_sha256": baseline.manifest_sha256,
        "failed_phase": failed_phase,
        "error_code": error_code,
        "final_checkpoint_id": final_checkpoint.checkpoint_id if final_checkpoint else None,
        "prehandoff_checkpoint_id": (
            prehandoff_checkpoint.checkpoint_id if prehandoff_checkpoint else None
        ),
        "d_external_open": d_external_open,
        "legacy_rollback": {
            "attempted": rollback_attempted,
            "succeeded": rollback_succeeded,
            "d_state_restored": d_state_restore_succeeded,
            "blocked": rollback_blocked,
        },
        "success_activation_recorded": False,
    }
    return _write_receipt(
        _receipt_dirs(root)[1] / f"writer-handoff-failure-{attempt_id}.json",
        receipt,
    )


def _required_committed_probe(baseline: V39Baseline) -> Mapping[str, object]:
    return {
        "release_id": baseline.release_id,
        "manifest_sha256": baseline.manifest_sha256,
        "snapshot_id": baseline.snapshot_id,
        "writer_authority": "D-active",
        "unique_d_listener": True,
        "legacy_pid_stopped": True,
        "browser": True,
        "api": True,
        "resource": True,
        "legacy_restart_fenced": True,
        "session_key_ready": True,
    }


def _verify_committed_surface(
    *, root: Path, runtime: HandoffRuntime, baseline: V39Baseline
) -> Mapping[str, object]:
    observed_probe = dict(runtime.probe_d(baseline))
    # The session key is a local production runtime artifact.  It is never
    # included in the cold bundle or returned by an adapter/probe.
    observed_probe["session_key_ready"] = _session_key_ready(root)
    required = _required_committed_probe(baseline)
    if observed_probe != required:
        raise WriterHandoffError("D post-handoff browser/API/writer fence probe failed")
    return required


def _verify_final_fence(*, runtime: HandoffRuntime) -> None:
    final_observation = runtime.observe(PORT)
    if (
        final_observation.legacy_process is not None
        or len(final_observation.listener_pids) != 1
        or final_observation.legacy_deployment is not None
        or final_observation.d_service.get("status") != "running"
    ):
        raise WriterHandoffError("final listener/process fence is not closed")


def _verify_committed_runtime(
    *, root: Path, runtime: HandoffRuntime, baseline: V39Baseline
) -> Mapping[str, object]:
    required = _verify_committed_surface(
        root=root, runtime=runtime, baseline=baseline
    )
    _verify_final_fence(runtime=runtime)
    return required


def _commit_evidence(
    *,
    recorded_at: datetime,
    final_checkpoint: CheckpointCreation,
    prehandoff_checkpoint: CheckpointCreation,
) -> Mapping[str, object]:
    return {
        "recorded_at": _timestamp(recorded_at),
        "final_checkpoint_id": final_checkpoint.checkpoint_id,
        "final_checkpoint_manifest_sha256": final_checkpoint.manifest_sha256,
        "prehandoff_checkpoint_id": prehandoff_checkpoint.checkpoint_id,
        "prehandoff_checkpoint_manifest_sha256": prehandoff_checkpoint.manifest_sha256,
    }


def _success_receipt_document(
    *,
    attempt_id: str,
    inspection_hash: str,
    nonce: str,
    baseline: V39Baseline,
    commit_evidence: Mapping[str, object],
) -> Mapping[str, object]:
    # Validation is deliberately shared with the durable journal contract so
    # replay can reproduce exactly the same immutable receipt bytes.
    _journal_document(
        attempt_id=attempt_id,
        nonce=nonce,
        inspection_hash=inspection_hash,
        baseline=baseline,
        phase="handoff_committed_receipt_pending",
        commit_evidence=commit_evidence,
    )
    return {
        "schema_version": SUCCESS_SCHEMA,
        "receipt_type": "writer_handoff",
        "receipt_id": f"writer-handoff-success-{attempt_id}",
        "attempt_id": attempt_id,
        "recorded_at": commit_evidence["recorded_at"],
        "authority": "evidence_only",
        "inspection_sha256": inspection_hash,
        "inspection_nonce_sha256": hashlib.sha256(nonce.encode("ascii")).hexdigest(),
        "release_id": baseline.release_id,
        "release_manifest_sha256": baseline.manifest_sha256,
        "snapshot_id": baseline.snapshot_id,
        "final_checkpoint_id": commit_evidence["final_checkpoint_id"],
        "final_checkpoint_manifest_sha256": commit_evidence[
            "final_checkpoint_manifest_sha256"
        ],
        "prehandoff_checkpoint_id": commit_evidence["prehandoff_checkpoint_id"],
        "prehandoff_checkpoint_manifest_sha256": commit_evidence[
            "prehandoff_checkpoint_manifest_sha256"
        ],
        "writer_transition": {
            "from": "C-legacy",
            "to": "D-active",
            "c_pid_stopped": True,
            "d_unique_listener": True,
            "c_permanently_fenced": True,
        },
        "verification": _required_committed_probe(baseline),
        "active_authority_changed": False,
    }


def _write_or_verify_success_receipt(
    *, root: Path, receipt: Mapping[str, object]
) -> Path:
    path = _receipt_dirs(root)[0] / f"{receipt['receipt_id']}.json"
    if path.exists():
        if _canonical_read(path) != receipt:
            raise WriterHandoffError("immutable handoff success receipt differs")
        return path.resolve(strict=True)
    return _write_receipt(path, receipt)


def _existing_checkpoint(
    *, root: Path, checkpoint_id: str, expected_sha256: str | None = None
) -> CheckpointCreation:
    checkpoint_id = _identifier(checkpoint_id, label="handoff checkpoint ID")
    path = root / "backups" / "checkpoints" / checkpoint_id
    report = verify_sqlite_checkpoint(
        path, scratch_root=root / "tmp" / "writer-handoff" / "restore-proof"
    )
    if (
        not report.valid
        or report.checkpoint_id != checkpoint_id
        or report.manifest_sha256 is None
        or report.captured_at is None
        or report.database_count != 2
        or (expected_sha256 is not None and report.manifest_sha256 != expected_sha256)
    ):
        raise WriterHandoffError("handoff checkpoint cannot be replay-verified")
    return CheckpointCreation(
        checkpoint_id=checkpoint_id,
        root=path.resolve(strict=True),
        manifest_path=(path / "checkpoint_manifest.json").resolve(strict=True),
        manifest_sha256=report.manifest_sha256,
        captured_at=report.captured_at,
    )


def apply_writer_handoff(
    *,
    vm_root: Path,
    baseline: V39Baseline,
    runtime: HandoffRuntime,
    inspection_receipt: Mapping[str, object],
    expected_inspection_sha256: str,
    nonce: str,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    id_factory: Callable[[], str] = lambda: uuid4().hex,
    allow_test_root: bool = False,
    closure_verifier: DClosureVerifier = inspect_d_closure,
    checkpoint_builder: CheckpointBuilder = create_sqlite_checkpoint,
    legacy_sources: Mapping[str, Path] | None = None,
) -> HandoffApplyResult:
    """Consume one inspection receipt and perform the one-time writer cutover."""

    require_failure_domain_authority()
    root = _root(vm_root, allow_test_root=allow_test_root)
    receipt = validate_inspection_receipt(inspection_receipt)
    actual_hash = manifest_sha256(receipt)
    if (
        _sha(expected_inspection_sha256, label="inspection receipt") != actual_hash
        or receipt.get("nonce") != nonce
        or _NONCE_RE.fullmatch(nonce) is None
    ):
        raise WriterHandoffError("inspection receipt hash/nonce does not match apply intent")
    started = now().astimezone(UTC)
    age = started - _parse_timestamp(receipt["inspected_at"])
    if age < timedelta(0) or age > MAX_INSPECTION_AGE:
        raise WriterHandoffError("inspection receipt is stale or from the future")
    attempt_id = _identifier(
        f"handoff-{started.strftime('%Y%m%dT%H%M%S')}-{id_factory()[:12]}",
        label="handoff attempt ID",
    )
    process = _process_from_receipt(receipt)
    phase = "precondition_recheck"
    legacy_stopped = False
    state_replaced = False
    d_start_attempted = False
    d_open = False
    rollback_attempted = False
    rollback_succeeded = False
    d_state_restore_succeeded = False
    rollback_blocked = False
    final_checkpoint: CheckpointCreation | None = None
    prehandoff_checkpoint: CheckpointCreation | None = None
    journal_created = False
    writer_committed = False
    with _handoff_lock(root, nonce):
        _ensure_unconsumed(root, actual_hash)
        try:
            reinspection = inspect_writer_handoff(
                vm_root=root,
                baseline=baseline,
                runtime=runtime,
                nonce=nonce,
                inspected_at=_parse_timestamp(receipt["inspected_at"]),
                allow_test_root=allow_test_root,
                closure_verifier=closure_verifier,
            )
            if reinspection["observation"] != receipt["observation"]:
                raise WriterHandoffError("handoff preconditions changed after inspection")

            phase = "writer_fence_arm"
            _write_journal(
                root,
                attempt_id=attempt_id,
                nonce=nonce,
                inspection_hash=actual_hash,
                baseline=baseline,
                phase="legacy_stop_pending",
                create=True,
            )
            journal_created = True
            phase = "legacy_stop"
            runtime.stop_legacy(process)
            legacy_stopped = True
            if not runtime.wait_port_free(PORT):
                raise WriterHandoffError("legacy listener did not release production port")

            phase = "final_legacy_checkpoint"
            final_checkpoint = _checkpoint(
                builder=checkpoint_builder,
                sources=legacy_sources if legacy_sources is not None else _legacy_sources(),
                root=root,
                checkpoint_id=f"handoff-final-{attempt_id}",
                authority="legacy-c-final",
                baseline=baseline,
                captured_at=now().astimezone(UTC),
            )
            phase = "prehandoff_d_checkpoint"
            prehandoff_checkpoint = _checkpoint(
                builder=checkpoint_builder,
                sources=_state_sources(root),
                root=root,
                checkpoint_id=f"handoff-pre-d-{attempt_id}",
                authority="d-prehandoff",
                baseline=baseline,
                captured_at=now().astimezone(UTC),
            )
            phase = "d_state_replace"
            _replace_d_state(
                root=root, checkpoint_root=final_checkpoint.root, attempt_id=attempt_id
            )
            state_replaced = True

            phase = "d_service_start"
            _write_journal(
                root,
                attempt_id=attempt_id,
                nonce=nonce,
                inspection_hash=actual_hash,
                baseline=baseline,
                phase="d_start_authorized",
            )
            d_start_attempted = True
            runtime.start_d_service(SERVICE_NAME)
            d_open = runtime.d_external_open(PORT)
            if not d_open:
                raise WriterHandoffError("D service did not open the production listener")

            phase = "post_handoff_probe"
            _verify_committed_surface(root=root, runtime=runtime, baseline=baseline)

            # Persist the replay identity before the final commit observation.
            # Thus every crash cut after the definitive fence proof already
            # has a sticky terminal journal and deterministic receipt payload.
            terminal = _commit_evidence(
                recorded_at=now().astimezone(UTC),
                final_checkpoint=final_checkpoint,
                prehandoff_checkpoint=prehandoff_checkpoint,
            )
            _write_journal(
                root,
                attempt_id=attempt_id,
                nonce=nonce,
                inspection_hash=actual_hash,
                baseline=baseline,
                phase="handoff_committed_receipt_pending",
                commit_evidence=terminal,
            )
            phase = "writer_fence_commit"
            _verify_final_fence(runtime=runtime)
            # From this point forward D is the proven live writer.  Evidence
            # failures may leave finalization pending, but can never stop D or
            # restore C.
            writer_committed = True
            success = _success_receipt_document(
                attempt_id=attempt_id,
                inspection_hash=actual_hash,
                nonce=nonce,
                baseline=baseline,
                commit_evidence=terminal,
            )
            success_path = _write_or_verify_success_receipt(root=root, receipt=success)
            _remove_journal(
                root, attempt_id=attempt_id, nonce=nonce, baseline=baseline
            )
            journal_created = False
            return HandoffApplyResult(
                True,
                success_path,
                final_checkpoint.checkpoint_id,
                prehandoff_checkpoint.checkpoint_id,
                False,
                False,
                False,
                None,
                True,
            )
        except Exception:
            if writer_committed:
                # The authority transition is already a verified live fact.
                # Never turn an audit/cleanup failure into an outage or a C
                # fallback.  The same attempt ID can be explicitly finalized.
                return HandoffApplyResult(
                    False,
                    root / "control" / "writer_handoff_pending.json",
                    final_checkpoint.checkpoint_id if final_checkpoint else None,
                    prehandoff_checkpoint.checkpoint_id
                    if prehandoff_checkpoint
                    else None,
                    False,
                    False,
                    True,
                    "handoff_committed_receipt_pending",
                    True,
                )
            # Ambiguous exposure is unsafe.  If the observation itself fails,
            # treat D as externally open and permanently forbid C rollback.
            if d_start_attempted:
                try:
                    d_open = bool(runtime.d_external_open(PORT))
                except Exception:
                    d_open = True
            if d_start_attempted:
                try:
                    runtime.stop_d_service(SERVICE_NAME)
                except Exception:
                    d_open = True
            if legacy_stopped and not d_open:
                rollback_attempted = True
                if state_replaced and prehandoff_checkpoint is not None:
                    try:
                        _replace_d_state(
                            root=root,
                            checkpoint_root=prehandoff_checkpoint.root,
                            attempt_id=f"rollback-{attempt_id}",
                        )
                        d_state_restore_succeeded = True
                    except Exception:
                        d_state_restore_succeeded = False
                else:
                    d_state_restore_succeeded = True
                try:
                    runtime.start_legacy(process)
                    rollback_succeeded = runtime.verify_legacy_restored(
                        process, baseline.legacy_deployment_id, PORT
                    )
                except Exception:
                    rollback_succeeded = False
            elif legacy_stopped:
                rollback_blocked = True
            if journal_created:
                journal_phase = (
                    "legacy_restored_fenced"
                    if rollback_succeeded
                    else "handoff_failed_fenced"
                )
                try:
                    _write_journal(
                        root,
                        attempt_id=attempt_id,
                        nonce=nonce,
                        inspection_hash=actual_hash,
                        baseline=baseline,
                        phase=journal_phase,
                    )
                except Exception:
                    # An unverified journal is itself a fail-closed D service
                    # condition; never remove it or use that as license to C.
                    if legacy_stopped and not rollback_succeeded:
                        rollback_blocked = True
            error_code = (
                "d_external_writer_open_rollback_forbidden"
                if rollback_blocked
                else "writer_handoff_failed"
            )
            failure_path = _failure_receipt(
                root=root,
                attempt_id=attempt_id,
                recorded_at=now().astimezone(UTC),
                inspection_hash=actual_hash,
                nonce=nonce,
                baseline=baseline,
                failed_phase=phase,
                error_code=error_code,
                final_checkpoint=final_checkpoint,
                prehandoff_checkpoint=prehandoff_checkpoint,
                rollback_attempted=rollback_attempted,
                rollback_succeeded=rollback_succeeded,
                d_state_restore_succeeded=d_state_restore_succeeded,
                rollback_blocked=rollback_blocked,
                d_external_open=d_open,
            )
            return HandoffApplyResult(
                False,
                failure_path,
                final_checkpoint.checkpoint_id if final_checkpoint else None,
                prehandoff_checkpoint.checkpoint_id if prehandoff_checkpoint else None,
                rollback_attempted,
                rollback_succeeded,
                rollback_blocked,
                error_code,
                False,
            )


def finalize_writer_handoff(
    *,
    vm_root: Path,
    baseline: V39Baseline,
    runtime: HandoffRuntime,
    attempt_id: str,
    nonce: str,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    allow_test_root: bool = False,
) -> HandoffApplyResult:
    """Idempotently finish terminal evidence after a proven D handoff.

    This command never stops D, starts C, changes either database, or changes
    the active pointer.  A ``d_start_authorized`` journal can only advance if
    the complete live D identity/fence probe and both deterministic handoff
    checkpoints still verify.  A terminal receipt is written before the
    coordination journal is removed.  Repeating finalize after cleanup verifies
    and returns the same immutable receipt.
    """

    require_failure_domain_authority()
    root = _root(vm_root, allow_test_root=allow_test_root)
    attempt_id = _identifier(attempt_id, label="handoff attempt ID")
    if _NONCE_RE.fullmatch(nonce) is None:
        raise WriterHandoffError("handoff finalize nonce is invalid")
    success_path = (
        root
        / "audit"
        / "writer-handoff"
        / "success"
        / f"writer-handoff-success-{attempt_id}.json"
    )
    journal_path = root / "control" / "writer_handoff_pending.json"
    with _handoff_lock(root, nonce):
        if not journal_path.exists():
            if not success_path.exists():
                raise WriterHandoffError("no matching handoff terminal evidence exists")
            success = _canonical_read(success_path)
            if (
                success.get("schema_version") != SUCCESS_SCHEMA
                or success.get("receipt_id")
                != f"writer-handoff-success-{attempt_id}"
                or success.get("attempt_id") != attempt_id
                or success.get("inspection_nonce_sha256")
                != hashlib.sha256(nonce.encode("ascii")).hexdigest()
                or success.get("release_id") != baseline.release_id
                or success.get("release_manifest_sha256")
                != baseline.manifest_sha256
            ):
                raise WriterHandoffError("existing handoff success receipt differs")
            terminal = {
                "recorded_at": success.get("recorded_at"),
                "final_checkpoint_id": success.get("final_checkpoint_id"),
                "final_checkpoint_manifest_sha256": success.get(
                    "final_checkpoint_manifest_sha256"
                ),
                "prehandoff_checkpoint_id": success.get("prehandoff_checkpoint_id"),
                "prehandoff_checkpoint_manifest_sha256": success.get(
                    "prehandoff_checkpoint_manifest_sha256"
                ),
            }
            expected = _success_receipt_document(
                attempt_id=attempt_id,
                inspection_hash=_sha(
                    success.get("inspection_sha256"), label="inspection receipt"
                ),
                nonce=nonce,
                baseline=baseline,
                commit_evidence=terminal,
            )
            if success != expected:
                raise WriterHandoffError("existing handoff success receipt differs")
            final_checkpoint = _existing_checkpoint(
                root=root,
                checkpoint_id=str(terminal["final_checkpoint_id"]),
                expected_sha256=str(terminal["final_checkpoint_manifest_sha256"]),
            )
            prehandoff_checkpoint = _existing_checkpoint(
                root=root,
                checkpoint_id=str(terminal["prehandoff_checkpoint_id"]),
                expected_sha256=str(
                    terminal["prehandoff_checkpoint_manifest_sha256"]
                ),
            )
            _verify_committed_runtime(root=root, runtime=runtime, baseline=baseline)
            return HandoffApplyResult(
                True,
                success_path.resolve(strict=True),
                final_checkpoint.checkpoint_id,
                prehandoff_checkpoint.checkpoint_id,
                False,
                False,
                False,
                None,
                True,
            )

        journal = _canonical_read(journal_path)
        if (
            journal.get("schema_version") != JOURNAL_SCHEMA
            or journal.get("attempt_id") != attempt_id
            or journal.get("nonce_sha256")
            != hashlib.sha256(nonce.encode("ascii")).hexdigest()
            or journal.get("success_receipt_id")
            != f"writer-handoff-success-{attempt_id}"
            or journal.get("release_id") != baseline.release_id
            or journal.get("manifest_sha256") != baseline.manifest_sha256
            or journal.get("authority") != "coordination_only"
            or journal.get("phase")
            not in {"d_start_authorized", "handoff_committed_receipt_pending"}
        ):
            raise WriterHandoffError("handoff finalize journal identity is invalid")
        inspection_hash = _sha(
            journal.get("inspection_sha256"), label="inspection receipt"
        )
        phase = str(journal["phase"])
        if phase == "handoff_committed_receipt_pending":
            raw_terminal = journal.get("commit_evidence")
            if not isinstance(raw_terminal, Mapping):
                raise WriterHandoffError("committed handoff journal is incomplete")
            terminal = dict(raw_terminal)
            final_checkpoint = _existing_checkpoint(
                root=root,
                checkpoint_id=str(terminal.get("final_checkpoint_id")),
                expected_sha256=str(
                    terminal.get("final_checkpoint_manifest_sha256")
                ),
            )
            prehandoff_checkpoint = _existing_checkpoint(
                root=root,
                checkpoint_id=str(terminal.get("prehandoff_checkpoint_id")),
                expected_sha256=str(
                    terminal.get("prehandoff_checkpoint_manifest_sha256")
                ),
            )
        else:
            if journal.get("commit_evidence") is not None:
                raise WriterHandoffError("pre-commit handoff journal has terminal evidence")
            final_checkpoint = _existing_checkpoint(
                root=root, checkpoint_id=f"handoff-final-{attempt_id}"
            )
            prehandoff_checkpoint = _existing_checkpoint(
                root=root, checkpoint_id=f"handoff-pre-d-{attempt_id}"
            )
            terminal = dict(
                _commit_evidence(
                    recorded_at=now().astimezone(UTC),
                    final_checkpoint=final_checkpoint,
                    prehandoff_checkpoint=prehandoff_checkpoint,
                )
            )

        _verify_committed_runtime(root=root, runtime=runtime, baseline=baseline)
        if phase == "d_start_authorized":
            _write_journal(
                root,
                attempt_id=attempt_id,
                nonce=nonce,
                inspection_hash=inspection_hash,
                baseline=baseline,
                phase="handoff_committed_receipt_pending",
                commit_evidence=terminal,
            )
        receipt = _success_receipt_document(
            attempt_id=attempt_id,
            inspection_hash=inspection_hash,
            nonce=nonce,
            baseline=baseline,
            commit_evidence=terminal,
        )
        terminal_path = _write_or_verify_success_receipt(root=root, receipt=receipt)
        _remove_journal(
            root, attempt_id=attempt_id, nonce=nonce, baseline=baseline
        )
        return HandoffApplyResult(
            True,
            terminal_path,
            final_checkpoint.checkpoint_id,
            prehandoff_checkpoint.checkpoint_id,
            False,
            False,
            False,
            None,
            True,
        )


def inspect_writer_handoff_status(
    *,
    vm_root: Path,
    baseline: V39Baseline,
    inspection_sha256: str,
    nonce: str,
    allow_test_root: bool = False,
) -> Mapping[str, object]:
    """Resolve one off-host intent to its exact server-side attempt/evidence.

    This is a read-only recovery query.  In particular it does not create the
    audit directories (``_receipt_dirs`` intentionally is not used), mutate a
    journal, probe a service, or infer an attempt ID from timestamps.
    """

    require_failure_domain_authority()
    root = _root(vm_root, allow_test_root=allow_test_root)
    inspection_hash = _sha(inspection_sha256, label="inspection receipt")
    if _NONCE_RE.fullmatch(nonce) is None:
        raise WriterHandoffError("handoff status nonce is invalid")
    nonce_hash = hashlib.sha256(nonce.encode("ascii")).hexdigest()

    terminals: list[tuple[str, Mapping[str, object]]] = []
    for kind, directory in (
        ("succeeded", root / "audit" / "writer-handoff" / "success"),
        ("failed", root / "audit" / "writer-handoff" / "failure"),
    ):
        if not directory.exists():
            continue
        ensure_no_reparse_components(directory)
        if not directory.is_dir():
            raise WriterHandoffError("writer handoff audit path is not a directory")
        for path in directory.glob("*.json"):
            receipt = _canonical_read(path)
            if receipt.get("inspection_sha256") != inspection_hash:
                continue
            expected_schema = SUCCESS_SCHEMA if kind == "succeeded" else FAILURE_SCHEMA
            expected_type = "writer_handoff" if kind == "succeeded" else "writer_handoff_failure"
            if (
                receipt.get("schema_version") != expected_schema
                or receipt.get("receipt_type") != expected_type
                or receipt.get("inspection_nonce_sha256") != nonce_hash
                or receipt.get("release_id") != baseline.release_id
                or receipt.get("release_manifest_sha256") != baseline.manifest_sha256
                or path.stem != receipt.get("receipt_id")
            ):
                raise WriterHandoffError("matching writer handoff receipt identity differs")
            _identifier(receipt.get("attempt_id"), label="handoff attempt ID")
            terminals.append((kind, receipt))
    if len(terminals) > 1:
        raise WriterHandoffError("writer handoff intent has conflicting terminal evidence")

    journal_path = root / "control" / "writer_handoff_pending.json"
    journal: Mapping[str, object] | None = None
    if journal_path.exists():
        journal = _canonical_read(journal_path)
        expected_journal_fields = {
            "schema_version", "attempt_id", "nonce_sha256", "inspection_sha256",
            "success_receipt_id", "release_id", "manifest_sha256", "phase",
            "commit_evidence", "authority",
        }
        if set(journal) != expected_journal_fields:
            raise WriterHandoffError("writer handoff journal schema differs")
        # A different pending intent is material state, not "not found".  It
        # must block the off-host client rather than be silently ignored.
        if (
            journal.get("schema_version") != JOURNAL_SCHEMA
            or journal.get("inspection_sha256") != inspection_hash
            or journal.get("nonce_sha256") != nonce_hash
            or journal.get("release_id") != baseline.release_id
            or journal.get("manifest_sha256") != baseline.manifest_sha256
            or journal.get("authority") != "coordination_only"
        ):
            raise WriterHandoffError("a different or invalid writer handoff journal exists")
        attempt_id = _identifier(journal.get("attempt_id"), label="handoff attempt ID")
        if journal.get("success_receipt_id") != f"writer-handoff-success-{attempt_id}":
            raise WriterHandoffError("writer handoff journal receipt identity differs")
        phase = str(journal.get("phase"))
        if phase not in {
            "legacy_stop_pending", "d_start_authorized",
            "handoff_committed_receipt_pending", "legacy_restored_fenced",
            "handoff_failed_fenced",
        }:
            raise WriterHandoffError("writer handoff journal phase differs")
        if terminals and terminals[0][1].get("attempt_id") != attempt_id:
            raise WriterHandoffError("writer handoff journal/receipt attempts differ")
        if terminals and terminals[0][0] == "failed":
            status = "failed"
            evidence_type = "writer_handoff_failure"
            evidence_id = str(terminals[0][1]["receipt_id"])
        elif phase in {"d_start_authorized", "handoff_committed_receipt_pending"}:
            status = "finalize_required"
            evidence_type = "writer_handoff_coordination_journal"
            evidence_id = journal_path.stem
        else:
            status = "in_progress_or_fenced"
            evidence_type = "writer_handoff_coordination_journal"
            evidence_id = journal_path.stem
        return {
            "schema_version": STATUS_SCHEMA,
            "status": status,
            "attempt_id": attempt_id,
            "phase": phase,
            "evidence_type": evidence_type,
            "evidence_id": evidence_id,
            "writer_authority_committed": (
                phase == "handoff_committed_receipt_pending"
                or (bool(terminals) and terminals[0][0] == "succeeded")
            ),
        }

    if terminals:
        status, receipt = terminals[0]
        return {
            "schema_version": STATUS_SCHEMA,
            "status": status,
            "attempt_id": str(receipt["attempt_id"]),
            "phase": "terminal_receipt",
            "evidence_type": (
                "writer_handoff_receipt"
                if status == "succeeded"
                else "writer_handoff_failure"
            ),
            "evidence_id": str(receipt["receipt_id"]),
            "writer_authority_committed": status == "succeeded",
        }
    return {
        "schema_version": STATUS_SCHEMA,
        "status": "not_found",
        "attempt_id": None,
        "phase": None,
        "evidence_type": None,
        "evidence_id": None,
        "writer_authority_committed": False,
    }


def _controlled_intent_path(root: Path, path: Path) -> Path:
    resolved = path.resolve(strict=True)
    ensure_no_reparse_components(resolved)
    parent = (root / "control" / "writer-handoff-intents").resolve(strict=True)
    ensure_no_reparse_components(parent)
    if resolved.parent != parent or not resolved.is_file():
        raise WriterHandoffError("inspection receipt is outside fixed D control intake")
    return resolved


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inspect_parser = commands.add_parser("inspect")
    inspect_parser.add_argument("--vm-root", type=Path, required=True)
    inspect_parser.add_argument("--release-manifest-sha256", required=True)
    inspect_parser.add_argument("--nonce", required=True)
    apply_parser = commands.add_parser("apply")
    apply_parser.add_argument("--vm-root", type=Path, required=True)
    apply_parser.add_argument("--release-manifest-sha256", required=True)
    apply_parser.add_argument("--inspection-receipt", type=Path, required=True)
    apply_parser.add_argument("--inspection-sha256", required=True)
    apply_parser.add_argument("--nonce", required=True)
    finalize_parser = commands.add_parser("finalize")
    finalize_parser.add_argument("--vm-root", type=Path, required=True)
    finalize_parser.add_argument("--release-manifest-sha256", required=True)
    finalize_parser.add_argument("--attempt-id", required=True)
    finalize_parser.add_argument("--nonce", required=True)
    status_parser = commands.add_parser("status")
    status_parser.add_argument("--vm-root", type=Path, required=True)
    status_parser.add_argument("--release-manifest-sha256", required=True)
    status_parser.add_argument("--inspection-sha256", required=True)
    status_parser.add_argument("--nonce", required=True)
    seed_parser = commands.add_parser("seed-access-identity")
    seed_parser.add_argument("--vm-root", type=Path, required=True)
    seed_parser.add_argument("--release-manifest-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        require_failure_domain_authority()
        root = _root(args.vm_root, allow_test_root=False)
        baseline = V39Baseline(args.release_manifest_sha256)
        if args.command == "inspect":
            runtime = WindowsHandoffRuntime(root)
            receipt = inspect_writer_handoff(
                vm_root=root,
                baseline=baseline,
                runtime=runtime,
                nonce=args.nonce,
            )
            result: Mapping[str, object] = {
                "schema_version": "qrh-writer-handoff-inspection-result/v1",
                "status": "inspected_read_only",
                "inspection_sha256": manifest_sha256(receipt),
                "receipt": receipt,
            }
            code = 0
        elif args.command == "apply":
            runtime = WindowsHandoffRuntime(root)
            intent = _controlled_intent_path(root, args.inspection_receipt)
            receipt = _canonical_read(intent)
            applied = apply_writer_handoff(
                vm_root=root,
                baseline=baseline,
                runtime=runtime,
                inspection_receipt=receipt,
                expected_inspection_sha256=args.inspection_sha256,
                nonce=args.nonce,
            )
            status = (
                "succeeded"
                if applied.succeeded
                else (
                    "committed_evidence_pending"
                    if applied.writer_authority_committed
                    else "failed"
                )
            )
            result = {
                "schema_version": "qrh-writer-handoff-apply-result/v1",
                "status": status,
                "evidence_type": (
                    "writer_handoff_receipt"
                    if applied.succeeded
                    else (
                        "writer_handoff_coordination_journal"
                        if applied.writer_authority_committed
                        else "writer_handoff_failure"
                    )
                ),
                "evidence_id": applied.receipt_path.stem,
                "legacy_rollback_attempted": applied.legacy_rollback_attempted,
                "legacy_rollback_succeeded": applied.legacy_rollback_succeeded,
                "rollback_blocked": applied.rollback_blocked,
                "error_code": applied.error_code,
            }
            code = 0 if applied.succeeded else 2
        elif args.command == "finalize":
            runtime = WindowsHandoffRuntime(root)
            applied = finalize_writer_handoff(
                vm_root=root,
                baseline=baseline,
                runtime=runtime,
                attempt_id=args.attempt_id,
                nonce=args.nonce,
            )
            result = {
                "schema_version": "qrh-writer-handoff-finalize-result/v1",
                "status": "succeeded",
                "evidence_type": "writer_handoff_receipt",
                "evidence_id": applied.receipt_path.stem,
                "writer_authority_committed": True,
            }
            code = 0
        elif args.command == "status":
            result = inspect_writer_handoff_status(
                vm_root=root,
                baseline=baseline,
                inspection_sha256=args.inspection_sha256,
                nonce=args.nonce,
            )
            code = 0
        else:
            result = seed_v39_access_identity(vm_root=root, baseline=baseline)
            code = 0
    except Exception as error:
        result = {
            "schema_version": "qrh-writer-handoff-cli-error/v1",
            "status": "error",
            "error_type": type(error).__name__,
        }
        code = 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "FAILURE_SCHEMA",
    "ACCESS_IDENTITY_CONTRACT",
    "ACCESS_IDENTITY_SCHEMA",
    "HandoffApplyResult",
    "HandoffRuntime",
    "INSPECT_SCHEMA",
    "JOURNAL_SCHEMA",
    "LEGACY_ROOT",
    "LEGACY_SERVER",
    "LEGACY_STATE_ROOT",
    "LegacyProcess",
    "PORT",
    "RuntimeObservation",
    "SERVICE_NAME",
    "STATUS_SCHEMA",
    "SUCCESS_SCHEMA",
    "TARGET_ADDRESS",
    "V39Baseline",
    "WindowsHandoffRuntime",
    "WriterHandoffError",
    "apply_writer_handoff",
    "finalize_writer_handoff",
    "inspect_d_closure",
    "inspect_writer_handoff",
    "inspect_writer_handoff_status",
    "main",
    "seed_v39_access_identity",
    "validate_inspection_receipt",
]
