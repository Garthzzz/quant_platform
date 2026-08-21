"""固定 VM 远端入口：finalize candidate，或在既有 recovery protection 后激活。

``candidate_only`` 只产生 evidence-only audit event；它绝不伪造 receipt。``activate``
严格复用 :class:`DeploymentController`，因此成功 activation receipt 只能出现在 pointer
已切换、进程已启动且三项 post-activation gate 全部通过之后。
"""

from __future__ import annotations

import argparse
from contextlib import closing
from dataclasses import dataclass, field
import http.cookiejar
import json
import os
from pathlib import Path, PureWindowsPath
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
from typing import Callable, Mapping, Protocol
import urllib.parse
import urllib.request
from urllib.request import Request, urlopen

from quant_hub.web.access_gate import derive_password_digest

from quant_hub.config import ensure_no_reparse_components
from quant_hub.runtime_seal import read_json

from .deployment import (
    CandidateValidationError,
    DeploymentController,
    DeploymentFailed,
)
from .release_identity import validate_receipt
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
    validate_production_vm_write_path,
    verify_existing_vm_write_path,
)


FULL_SHA256 = re.compile(r"[0-9a-f]{64}")
STABLE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,179}")
RUNTIME_SCHEMA = "qrh-vm-deploy-runtime/v1"


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
    hooks: RuntimeHooks,
    deployment_attempt_id: str | None = None,
    recovery_protection_receipt_id: str | None = None,
    root_verifier: RootVerifier = verify_production_root,
    environment: Mapping[str, str] | None = None,
) -> Mapping[str, object]:
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
    controller = DeploymentController(root)
    recovered = controller.recover_pending_activation(
        start_release=hooks.start_release,
        stop_release=hooks.stop_release,
    )
    if recovered is not None:
        if recovered.status == "failed":
            raise DeploymentFailed(recovered)
        if (
            deployment_mode == "activate"
            and recovered.candidate_release_id == release_id
            and recovered.candidate_manifest_sha256 == release_hash
        ):
            return {
                "schema_version": "qrh-vm-deploy-result/v1",
                "release_id": release_id,
                "release_manifest_sha256": release_hash,
                "publish_candidate_sha256": candidate_hash,
                "status": "activated",
                "evidence_type": "activation_receipt",
                "evidence_id": recovered.receipt_id,
            }
        raise VMDeployCLIError(
            "a committed pending activation was recovered for another request"
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
        if deployment_attempt_id is not None or recovery_protection_receipt_id is not None:
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
    protection_id = _stable(
        recovery_protection_receipt_id, "recovery_protection_receipt_id"
    )
    result = controller.activate(
        candidate_release_id=release_id,
        deployment_attempt_id=attempt_id,
        recovery_protection_receipt_id=protection_id,
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


@dataclass(frozen=True)
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
        return cls(
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
            uri = f"file:{database.as_posix()}?mode=ro"
            try:
                with closing(sqlite3.connect(uri, uri=True)) as connection:
                    version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            except (OSError, sqlite3.Error, TypeError, ValueError):
                return False
            if version not in readable:
                return False
        return True

    @staticmethod
    def _online_copy(source: Path, destination: Path) -> None:
        source_connection = sqlite3.connect(
            f"file:{source.resolve().as_posix()}?mode=ro", uri=True, timeout=30
        )
        destination_connection = sqlite3.connect(destination, timeout=30)
        try:
            source_connection.backup(destination_connection, pages=256, sleep=0.01)
            destination_connection.commit()
        finally:
            destination_connection.close()
            source_connection.close()

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
        expected_path = (self.root / "releases" / release_id).resolve(strict=True)
        if path.resolve(strict=True) != expected_path:
            raise VMDeployCLIError("candidate probe path differs from exact release")
        probe_parent = self.root / "tmp" / "candidate-probes"
        probe_parent.mkdir(parents=True, exist_ok=True)
        ensure_no_reparse_components(probe_parent)
        probe_root = probe_parent / f"{release_id}-{manifest_hash[:16]}"
        if probe_root.exists():
            raise VMDeployCLIError("candidate probe identity already exists")
        probe_root.mkdir()
        state = probe_root / "state"
        temporary = probe_root / "tmp"
        logs = probe_root / "logs"
        for directory in (state, temporary, logs):
            directory.mkdir()
            ensure_no_reparse_components(directory)
        active_path = self.root / "control" / "active_release.json"
        active_before = active_path.read_bytes() if active_path.exists() else None
        process: subprocess.Popen[bytes] | None = None
        evidence: dict[str, object] | None = None
        try:
            for source_name, destination_name in (
                ("comments.sqlite3", "comments.sqlite3"),
                ("research_workspace.sqlite3", "research_workspace.sqlite3"),
            ):
                self._online_copy(self.root / "state" / source_name, state / destination_name)
            one_time_password = secrets.token_urlsafe(32)
            (state / "viewer_access_password.digest").write_text(
                derive_password_digest(one_time_password).hex() + "\n",
                encoding="ascii",
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
            environment = {
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPYCACHEPREFIX": str(temporary / "pycache"),
                "TEMP": str(temporary),
                "TMP": str(temporary),
            }
            with (logs / "stdout.log").open("wb") as stdout, (
                logs / "stderr.log"
            ).open("wb") as stderr:
                arguments = [
                        str(python), "-I", "-B", str(entry),
                        "--vm-root", str(self.root),
                        "--release-id", release_id,
                        "--manifest-sha256", manifest_hash,
                        "--candidate-probe-root", str(probe_root),
                        "--candidate-port", str(port),
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
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            ensure_no_reparse_components(probe_root)
            shutil.rmtree(probe_root)
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
    ) -> bool:
        temporary = self.root / "tmp" / "deployment-cli"
        temporary.mkdir(parents=True, exist_ok=True)
        ensure_no_reparse_components(temporary)
        arguments = ["sc.exe", action, self.service_name]
        if start_authorization is not None:
            if action != "start":
                raise VMDeployCLIError(
                    "pending activation authorization is start-only"
                )
            arguments.extend(("pending-activation", *start_authorization))
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
        self._service("stop", allow_failure=True)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and self._get("/deploymentz")[0] == 200:
            time.sleep(0.25)
        if self._get("/deploymentz")[0] == 200:
            return False
        authorization = DeploymentController(
            self.root
        ).pending_service_start_authorization(_active)
        if not self._service("start", start_authorization=authorization):
            return False
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self._deployment_identity(_active, _path)[0]:
                return True
            time.sleep(0.25)
        return False

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
    parser.add_argument("--recovery-protection-receipt-id")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        root = verify_production_root(args.vm_root)
        before = capture_vm_write_snapshot(root)
        _stable(args.release_id, "release_id")
        operation = f"deploy-{args.deployment_mode}"
        try:
            runtime = WindowsServiceRuntime.load(root)
            result = apply_publish(
                vm_root=root,
                release_id=args.release_id,
                release_manifest_sha256=args.release_manifest_sha256,
                publish_candidate_sha256=args.publish_candidate_sha256,
                deployment_mode=args.deployment_mode,
                deployment_attempt_id=args.deployment_attempt_id,
                recovery_protection_receipt_id=args.recovery_protection_receipt_id,
                hooks=runtime,
                root_verifier=lambda _path: root,
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
