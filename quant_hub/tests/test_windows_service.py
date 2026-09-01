from __future__ import annotations

from contextlib import closing
import hashlib
import http.cookiejar
import inspect
import json
from pathlib import Path, PureWindowsPath
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import urllib.parse
import urllib.request

from quant_hub.ops.release_identity import manifest_sha256
from quant_hub.ops.local_deployment_persistence import _BoundDirectory, _SafeRoot
from quant_hub.ops.local_windows_writer_lease_holder import (
    ExactRuntimeLeaseIdentity,
)
from quant_hub.ops.service_entry import ServiceEntryError, _generic_release_root
from quant_hub.ops.windows_service import (
    QuantResearchHubWindowsService,
    SERVICE_CLASS,
    ServiceSupervisor,
    WindowsServiceError,
    WindowsServiceStatusOwnerCrashRequired,
    _requires_service_host_owner_crash,
    apply_install_candidate,
    build_install_candidate,
    parse_service_start_authorization,
    validate_service_control_binding,
    verify_installed_operational_bindings,
)
from quant_hub.ops import windows_service as windows_service_module
from quant_hub.ops.local_service_transient_journal_start_fence import (
    ServiceTransientJournalStartFenceOwnerCrashRequired,
)
from quant_hub.ops.local_windows_job_child_launcher import (
    WindowsJobChildOwnerCrashRequired,
)
from quant_hub.ops.local_windows_exact_runtime_process_fence import (
    WindowsExactRuntimeProcessFenceOwnerCrashRequired,
)
from quant_hub.ops.vm_service_cli import (
    production_runtime_document,
    record_service_control_evidence,
    verify_protected_service_state,
)
from quant_hub.ops.vm_deploy_cli import VMDeployCLIError, WindowsServiceRuntime
from quant_hub.ops.vm_boundary import build_vm_write_audit, capture_vm_write_snapshot
from quant_hub.runtime_seal import safe_tree_file_state
from quant_hub.web.access_gate import LOGIN_TEMPLATE, derive_password_digest

from tests.test_deployment_controller import DeploymentFixture, write_partial


FIXTURE_APP = b'''from flask import Flask, jsonify
from pathlib import Path
import sqlite3

def create_app(settings, config):
    settings.ensure_runtime_directories()
    app = Flask(__name__)
    app.config.update(config)
    label = (Path(settings.project_root) / "version.txt").read_text(encoding="utf-8").strip()
    @app.get("/")
    def home():
        return f"<main>Quant Research Hub V39-compatible {label}</main>"
    @app.get("/comment-count")
    def comment_count():
        with sqlite3.connect(app.config["COMMENT_DATABASE_PATH"]) as connection:
            count = connection.execute("SELECT count(*) FROM comments").fetchone()[0]
        return jsonify({"comments": count, "release": label})
    @app.get("/api/v1/research")
    def research():
        return jsonify({"data": {"research": [{"research_id": "fixture", "title": label}]}})
    @app.get("/api/v1/dashboard")
    def dashboard():
        return jsonify({"data": {"topics": [{"topic_id": "fixture", "status": "completed"}]}})
    return app
'''

FIXTURE_CONFIG = b'''from pathlib import Path
from types import SimpleNamespace
class Settings:
    @classmethod
    def default(cls, **values):
        read_only_runtime = values.pop("read_only_runtime", False)
        def ensure_runtime_directories():
            if not read_only_runtime:
                (Path(values["var_root"]) / "replay" / "evidence").mkdir(parents=True, exist_ok=True)
        return SimpleNamespace(
            **values,
            read_only_runtime=read_only_runtime,
            ensure_runtime_directories=ensure_runtime_directories,
        )
'''


def _remove_windows_test_fixture_tree(target: Path, *, exact_parent: Path) -> None:
    """Remove one test-owned child after transient Windows handle release."""

    if target.parent != exact_parent or target == exact_parent:
        raise AssertionError("test fixture cleanup escaped its exact parent")
    deadline = time.monotonic() + 5.0
    while target.exists():
        parent_resolved = exact_parent.resolve(strict=True)
        target_resolved = target.resolve(strict=True)
        if target_resolved.parent != parent_resolved:
            raise AssertionError("test fixture cleanup target resolved outside its parent")
        try:
            shutil.rmtree(target)
        except OSError as error:
            if getattr(error, "winerror", None) not in {5, 32, 33}:
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise
            time.sleep(min(0.05, remaining))


class FakeInstaller:
    def __init__(self) -> None:
        self.installed = False
        self.actions: list[str] = []
        self.binding_valid = True

    def exists(self, _service_name):
        return self.installed

    def install(self, _candidate):
        self.actions.append("install")
        self.installed = True

    def configure(self, _candidate):
        self.actions.append("configure")

    def verify(self, _candidate):
        self.actions.append("verify")
        return self.binding_valid


class WindowsServiceTopologyTests(unittest.TestCase):
    def test_legacy_v39_does_not_enable_generic_release_loader(self) -> None:
        release = Path("release-v39")
        self.assertIsNone(
            _generic_release_root(
                release,
                {"application": {"source_kind": "legacy_broadcast"}},
            )
        )
        self.assertEqual(
            release,
            _generic_release_root(release, {"application": {"source_kind": "git"}}),
        )
        with self.assertRaisesRegex(ServiceEntryError, "source kind is invalid"):
            _generic_release_root(
                release, {"application": {"source_kind": "other"}}
            )

    def test_reviewed_login_surface_is_byte_exact_v39_template(self) -> None:
        self.assertEqual(
            "ca3d95b83af6778f5d7d77946af0af097ea8226eb0ba53d2afa5001f365e30f4",
            hashlib.sha256(LOGIN_TEMPLATE.encode("utf-8")).hexdigest(),
        )

    def test_service_host_does_not_emit_project_logs_to_windows_event_log(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src" / "quant_hub" / "ops" / "windows_service.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("servicemanager", source)
        self.assertNotIn("LogInfoMsg", source)
        owner = source[
            source.index("class _ServiceHostDWriteOwner") :
            source.index("def resolve_active_service_release")
        ]
        self.assertIn(
            'physical / "logs" / "quant-research-hub-service.log"',
            owner,
        )
        self.assertIn("_BoundDirectory(", owner)
        self.assertIn("CreateFileW(", owner)
        self.assertNotIn(".mkdir(parents=True", owner)
        self.assertNotIn('.open("ab")', owner)
        constructor = source[source.index("class QuantResearchHubWindowsService") :]
        self.assertLess(
            constructor.index("verify_installed_operational_bindings(root)"),
            constructor.index("prepare_service_host_environment(root)"),
        )

    def test_service_host_write_owner_pins_d_directories_and_log_for_lifetime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with mock.patch.object(
                windows_service_module,
                "PRODUCTION_VM_ROOT",
                PureWindowsPath(str(root)),
            ), mock.patch.object(
                windows_service_module,
                "validate_production_vm_write_path",
                side_effect=lambda value, allow_root=False: PureWindowsPath(value),
            ):
                (root / "tmp").mkdir()
                safe_root = _SafeRoot(root, allow_posix_test_only=False)
                controller_root_guard = _BoundDirectory(
                    safe_root,
                    root,
                    protect_rename=True,
                )
                controller_tmp_guard = _BoundDirectory(
                    safe_root,
                    root / "tmp",
                    protect_rename=True,
                )
                with controller_root_guard, controller_tmp_guard:
                    owner = windows_service_module.prepare_service_host_environment(root)
                    owner.append_status("host_failure_fixture")
                    self.assertFalse(owner._closed)
                    self.assertIsNotNone(owner._log_handle)
                    owner.close()
                    self.assertTrue(owner._closed)
            self.assertEqual(
                "host_failure_fixture\n",
                (
                    root / "logs" / "quant-research-hub-service.log"
                ).read_text(encoding="ascii"),
            )

    def test_service_status_owner_overrides_base_run_and_interrogate(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src" / "quant_hub" / "ops" / "windows_service.py"
        ).read_text(encoding="utf-8")
        constructor = source[source.index("class QuantResearchHubWindowsService") :]
        svc_run = constructor[
            constructor.index("        def SvcRun(self):") :
            constructor.index("        def SvcInterrogate(self):")
        ]
        running_transition = constructor[
            constructor.index("        def _report_running_unless_stopped(self):") :
            constructor.index("        def SvcRun(self):")
        ]
        interrogate = constructor[
            constructor.index("        def SvcInterrogate(self):") :
            constructor.index("        def SvcStop(self):")
        ]
        self.assertNotIn("super().SvcRun", svc_run)
        self.assertLess(
            svc_run.index("SERVICE_START_PENDING"),
            svc_run.index("begin_production_steady_start_pending"),
        )
        self.assertLess(
            svc_run.index("begin_production_steady_start_pending"),
            svc_run.index("_report_running_unless_stopped"),
        )
        self.assertLess(
            svc_run.index("_report_running_unless_stopped"),
            svc_run.index("complete_production_steady_after_running"),
        )
        self.assertIn("SERVICE_RUNNING", running_transition)
        self.assertIn("self._stop_is_set()", running_transition)
        self.assertIn("self.stop_event", constructor)
        self.assertIn("self._tracked_service_state", interrogate)
        self.assertNotIn("super().SvcInterrogate", interrogate)

    def test_ordinary_production_start_cannot_reach_legacy_popen_path(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src" / "quant_hub" / "ops" / "windows_service.py"
        ).read_text(encoding="utf-8")
        start = source[
            source.index("    def start(self) -> ActiveServiceRelease:") :
            source.index("    def stop(self, *, timeout: float = 15.0) -> None:")
        ]
        exact = start.index(
            "if type(self.activation_authorization) is ExactRuntimeLeaseIdentity:"
        )
        steady_guard = start.index(
            "ordinary production start must use the exact steady SvcRun path"
        )
        legacy_popen = start.index("self.process = self.popen_factory(")
        self.assertLess(exact, steady_guard)
        self.assertLess(steady_guard, legacy_popen)

    def test_pending_v1_production_start_cannot_reach_legacy_popen_path(self) -> None:
        supervisor = object.__new__(ServiceSupervisor)
        supervisor.root = Path(r"D:\quant\quant_platform")
        supervisor.popen_factory = mock.Mock()
        supervisor.python_executable = None
        supervisor.allow_test_root = False
        supervisor.activation_authorization = (
            "candidate",
            "attempt-v1-rejected",
            "a" * 48,
        )
        supervisor.process = None
        supervisor._transient_lifetime = None
        supervisor._steady_lifetime = None
        with mock.patch.object(
            windows_service_module,
            "verify_installed_operational_bindings",
            return_value={},
        ):
            with self.assertRaisesRegex(
                WindowsServiceError, "legacy pending activation"
            ):
                supervisor.start()
        supervisor.popen_factory.assert_not_called()

    def test_owner_crash_is_detected_through_wrapped_cleanup_error(self) -> None:
        try:
            try:
                raise WindowsJobChildOwnerCrashRequired("unknown close")
            except WindowsJobChildOwnerCrashRequired as error:
                raise RuntimeError("cleanup wrapper") from error
        except RuntimeError as wrapped:
            self.assertTrue(_requires_service_host_owner_crash(wrapped))
        self.assertTrue(
            _requires_service_host_owner_crash(
                ServiceTransientJournalStartFenceOwnerCrashRequired(
                    "unknown transient pin close"
                )
            )
        )
        self.assertTrue(
            _requires_service_host_owner_crash(
                WindowsServiceStatusOwnerCrashRequired("unknown SCM status")
            )
        )
        self.assertTrue(
            _requires_service_host_owner_crash(
                WindowsExactRuntimeProcessFenceOwnerCrashRequired(
                    "unknown process-fence close"
                )
            )
        )
        self.assertFalse(_requires_service_host_owner_crash(RuntimeError("ordinary")))

    @unittest.skipUnless(sys.platform == "win32", "requires pywin32 service host")
    def test_stop_and_running_reports_are_linearized_by_one_status_lock(self) -> None:
        service = object.__new__(QuantResearchHubWindowsService)
        service._status_lock = threading.RLock()
        service._tracked_service_state = (
            windows_service_module.win32service.SERVICE_START_PENDING
        )
        service._status_outcome_unknown = False
        service.stop_event = windows_service_module.win32event.CreateEvent(
            None, 0, 0, None
        )
        stop_requested = threading.Event()
        service.supervisor = mock.Mock()
        service.supervisor.request_production_steady_stop.side_effect = (
            stop_requested.set
        )
        report_entered = threading.Event()
        allow_running_report = threading.Event()
        reports: list[int] = []

        def report(_owner, state, waitHint=0):
            del waitHint
            if state == windows_service_module.win32service.SERVICE_RUNNING:
                report_entered.set()
                self.assertTrue(allow_running_report.wait(5))
            reports.append(state)

        failures: list[BaseException] = []

        def run_running() -> None:
            try:
                self.assertTrue(service._report_running_unless_stopped())
            except BaseException as error:
                failures.append(error)

        def run_stop() -> None:
            try:
                service.SvcStop()
            except BaseException as error:
                failures.append(error)

        with mock.patch.object(
            QuantResearchHubWindowsService,
            "ReportServiceStatus",
            new=report,
        ):
            running = threading.Thread(target=run_running)
            stopping = threading.Thread(target=run_stop)
            running.start()
            self.assertTrue(report_entered.wait(5))
            stopping.start()
            self.assertFalse(stop_requested.wait(0.1))
            allow_running_report.set()
            running.join(5)
            stopping.join(5)
        self.assertFalse(running.is_alive())
        self.assertFalse(stopping.is_alive())
        self.assertEqual([], failures)
        self.assertEqual(
            [
                windows_service_module.win32service.SERVICE_RUNNING,
                windows_service_module.win32service.SERVICE_STOP_PENDING,
            ],
            reports,
        )
        self.assertTrue(stop_requested.is_set())

    @unittest.skipUnless(sys.platform == "win32", "requires pywin32 service host")
    def test_unknown_running_status_retires_status_authority(self) -> None:
        service = object.__new__(QuantResearchHubWindowsService)
        service._status_lock = threading.RLock()
        service._tracked_service_state = (
            windows_service_module.win32service.SERVICE_START_PENDING
        )
        service._status_outcome_unknown = False
        service.stop_event = windows_service_module.win32event.CreateEvent(
            None, 0, 0, None
        )
        calls: list[int] = []

        def report(_owner, state, waitHint=0):
            del waitHint
            calls.append(state)
            raise OSError("injected unknown SCM status outcome")

        with mock.patch.object(
            QuantResearchHubWindowsService,
            "ReportServiceStatus",
            new=report,
        ):
            with self.assertRaises(WindowsServiceStatusOwnerCrashRequired):
                service._report_running_unless_stopped()
            with self.assertRaises(WindowsServiceStatusOwnerCrashRequired):
                service._report_tracked_status(
                    windows_service_module.win32service.SERVICE_STOPPED
                )
        self.assertTrue(service._status_outcome_unknown)
        self.assertEqual(
            windows_service_module.win32service.SERVICE_START_PENDING,
            service._tracked_service_state,
        )
        self.assertEqual(
            [windows_service_module.win32service.SERVICE_RUNNING], calls
        )

    def test_scm_stop_only_signals_and_owner_thread_terminates_job(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src" / "quant_hub" / "ops" / "windows_service.py"
        ).read_text(encoding="utf-8")
        constructor = source[source.index("class QuantResearchHubWindowsService") :]
        stop = constructor[
            constructor.index("        def SvcStop(self):") :
            constructor.index("        def SvcDoRun(self):")
        ]
        run = constructor[
            constructor.index("        def SvcRun(self):") :
            constructor.index("        def SvcInterrogate(self):")
        ]
        wait = constructor[
            constructor.index("        def SvcDoRun(self):") :
            constructor.index("\nexcept ImportError")
        ]
        self.assertIn("SetEvent", stop)
        self.assertIn("request_production_steady_stop", stop)
        self.assertNotIn("supervisor.stop()", stop)
        self.assertIn("_terminate_service_host_owner_crash", run)
        self.assertIn("stop_production_transient_from_owner", wait)
        self.assertIn("stop_production_steady_from_owner", wait)

    def test_ordinary_production_start_uses_exact_steady_bootstrap_not_popen(self) -> None:
        method = inspect.getsource(
            ServiceSupervisor.begin_production_steady_start_pending
        )
        self.assertIn("ProductionSteadyServiceBootstrap.load_exact_d()", method)
        self.assertNotIn("popen_factory", method)
        self.assertNotIn("subprocess", method)

    def test_production_service_config_is_fixed_d_authority_without_credentials(self) -> None:
        document = production_runtime_document()
        self.assertEqual("D-active", document["writer_authority"])
        self.assertEqual(
            ["/login", "/api/v1/research", "/api/v1/dashboard"],
            document["critical_paths"],
        )
        self.assertEqual(
            "tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py",
            document["service_entry_relative_path"],
        )
        serialized = json.dumps(document, sort_keys=True).casefold()
        self.assertNotIn("authorization", serialized)
        self.assertNotIn("api_key", serialized)
        verify_protected_service_state(self.root)

    def setUp(self) -> None:
        self.fixture = DeploymentFixture()
        self.addCleanup(self.fixture.close)
        self.root = self.fixture.root
        for relative in (
            "state", "tmp/service", "logs", "tooling/service", "control",
        ):
            (self.root / relative).mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.root / "state" / "comments.sqlite3")) as connection:
            connection.execute("CREATE TABLE comments(id INTEGER PRIMARY KEY, body TEXT)")
            connection.execute("INSERT INTO comments(body) VALUES ('persistent fixture')")
            connection.commit()
        with closing(sqlite3.connect(
            self.root / "state" / "research_workspace.sqlite3"
        )) as connection:
            connection.execute("CREATE TABLE workspace(id INTEGER PRIMARY KEY)")
            connection.commit()
        (self.root / "state" / "viewer_access_password.digest").write_text(
            derive_password_digest("fixture-password").hex() + "\n", encoding="ascii"
        )
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        runtime = {
            "schema_version": "qrh-vm-deploy-runtime/v1",
            "service_name": "QuantResearchHub",
            "base_url": "http://127.0.0.1:8765",
            "listen_host": "127.0.0.1",
            "port": self.port,
            "critical_paths": ["/"],
            "writer_authority": "D-active",
            "write_paths": [],
            "service_entry_relative_path": "tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py",
            "application_source_relative_path": "runtime_contract/code/src",
            "archive_root_relative_path": "reference/archive",
            "var_root_relative_path": "runtime",
            "migration_root_relative_path": "runtime_contract/migrations/platform",
            "access_password_digest_path": "state/viewer_access_password.digest",
            "session_key_path": "state/viewer_secret.key",
            "comment_database_path": "state/comments.sqlite3",
            "workspace_database_path": "state/research_workspace.sqlite3",
        }
        (self.root / "control" / "deployment_runtime.json").write_text(
            json.dumps(runtime, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        source = Path(__file__).parents[1] / "src" / "quant_hub"
        tooling_package = (
            self.root / "tooling" / "python" / "Lib" / "site-packages" / "quant_hub"
        )
        (tooling_package / "ops").mkdir(parents=True)
        (tooling_package / "web").mkdir(parents=True)
        (tooling_package / "ops" / "service_entry.py").write_bytes(
            (source / "ops" / "service_entry.py").read_bytes()
        )
        (tooling_package / "ops" / "vm_deploy_cli.py").write_bytes(
            (source / "ops" / "vm_deploy_cli.py").read_bytes()
        )
        (tooling_package / "ops" / "deployment.py").write_bytes(
            (source / "ops" / "deployment.py").read_bytes()
        )
        (tooling_package / "web" / "access_gate.py").write_bytes(
            (source / "web" / "access_gate.py").read_bytes()
        )
        common = {
            "runtime_contract/code/src/quant_hub/__init__.py": b"",
            "runtime_contract/code/src/quant_hub/app.py": FIXTURE_APP,
            "runtime_contract/code/src/quant_hub/config.py": FIXTURE_CONFIG,
            "runtime_contract/code/src/quant_hub/static/styles.css": b"body{color:#17211b}\n",
            "reference/archive/index.md": b"# immutable research\n",
            "runtime/db/archive.sqlite3": b"immutable-db-fixture",
            "runtime_contract/migrations/platform/0001.up.sql": b"SELECT 1;\n",
        }
        self.releases = {}
        for label, character in (("release-r1", "a"), ("release-r2", "b")):
            payloads = {**common, "version.txt": label.encode("ascii")}
            release = write_partial(
                self.fixture.controller, label, payloads, commit_character=character
            )
            self.fixture.controller.finalize_candidate(
                label, state_compatibility_probe=lambda _release: True
            )
            self.releases[label] = release
        self._activate("release-r1")

    def _write_install_binding(self):
        executable = self.root / "tooling" / "python" / "pythonservice.exe"
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_bytes(b"reviewed-service-host")
        (executable.parent / "python313.dll").write_bytes(b"python-runtime")
        (executable.parent / "pywintypes313.dll").write_bytes(b"pywin32-runtime")
        (self.root / "tooling" / "python" / "python.exe").write_bytes(
            b"reviewed-service-python"
        )
        service_host = (
            self.root / "tooling" / "python" / "Lib" / "site-packages"
            / "quant_hub" / "ops" / "windows_service.py"
        )
        service_host.write_bytes(b"reviewed-service-module")
        candidate = build_install_candidate(self.root, "QuantResearchHub")
        (self.root / "control" / "service_install_candidate.json").write_text(
            json.dumps(candidate.document(), ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return candidate

    def test_module_import_has_no_filesystem_or_process_side_effect(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code = (
                "import pathlib,sys;"
                f"sys.path.insert(0,{str(Path(__file__).parents[1] / 'src')!r});"
                "import quant_hub.ops.windows_service;"
                "print(len(list(pathlib.Path('.').iterdir())))"
            )
            completed = subprocess.run(
                [sys.executable, "-I", "-B", "-c", code],
                cwd=directory,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual("0", completed.stdout.strip())

    def test_project_package_dependency_tamper_blocks_service_and_candidate_before_popen(self) -> None:
        self._write_install_binding()
        dependency = (
            self.root / "tooling/python/Lib/site-packages/quant_hub/ops/deployment.py"
        )
        dependency.write_bytes(dependency.read_bytes() + b"\n# tampered dependency\n")
        with self.assertRaisesRegex(WindowsServiceError, "package inventory"):
            verify_installed_operational_bindings(self.root)

        called = []
        supervisor = ServiceSupervisor(
            self.root, popen_factory=lambda *args, **kwargs: called.append((args, kwargs))
        )
        with self.assertRaisesRegex(WindowsServiceError, "package inventory"):
            supervisor.start()
        self.assertEqual([], called)

        runtime = WindowsServiceRuntime(
            root=self.root, service_name="QuantResearchHub",
            base_url="http://127.0.0.1:8765", listen_host="127.0.0.1", port=8765,
            critical_paths=("/login", "/api/v1/research", "/api/v1/dashboard"),
            writer_authority="D-active",
            service_entry_relative_path="tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py",
            application_source_relative_path="runtime_contract/code/src",
            archive_root_relative_path="reference/archive", var_root_relative_path="runtime",
            migration_root_relative_path="runtime_contract/migrations/platform",
            access_password_digest_path="state/viewer_access_password.digest",
            session_key_path="state/viewer_secret.key",
            comment_database_path="state/comments.sqlite3",
            workspace_database_path="state/research_workspace.sqlite3",
            write_paths=(), candidate_popen_factory=lambda *args, **kwargs: called.append((args, kwargs)),
        )
        release = self.releases["release-r2"]
        with self.assertRaisesRegex(Exception, "operational tooling binding"):
            runtime.candidate_probe(
                self.root / "releases" / "release-r2",
                {"release_id": "release-r2", "manifest_sha256": manifest_sha256(release),
                 "snapshot_id": release["content"]["snapshot_id"]},
            )
        self.assertEqual([], called)

    def test_scm_pending_start_arguments_are_closed_and_not_implicit(self) -> None:
        valid = ["QuantResearchHub", "pending-activation", "candidate", "attempt-1", "a" * 48]
        self.assertEqual(
            ("candidate", "attempt-1", "a" * 48),
            parse_service_start_authorization(valid),
        )
        prior = ["QuantResearchHub", "pending-activation", "prior", "attempt-1", "b" * 48]
        self.assertEqual(
            ("prior", "attempt-1", "b" * 48),
            parse_service_start_authorization(prior),
        )
        self.assertIsNone(parse_service_start_authorization(["QuantResearchHub"]))
        for invalid in (
            valid[:-1],
            [*valid[:-1], "wrong"],
            ["QuantResearchHub", "pending-activation", "other", "attempt-1", "a" * 48],
        ):
            with self.assertRaises(WindowsServiceError):
                parse_service_start_authorization(invalid)

    def test_scm_exact_runtime_arguments_round_trip_the_hashed_start_plan(self) -> None:
        identity = ExactRuntimeLeaseIdentity(
            attempt_id="exact-service-attempt",
            nonce="exact-service-deployment-nonce",
            operation="activation",
            role="candidate",
            start_nonce="exact-service-start-nonce",
            release_id="release-r2",
            manifest_sha256="d" * 64,
            state_identity_sha256="c" * 64,
        )
        parsed = parse_service_start_authorization(
            ["QuantResearchHub", *identity.service_start_arguments]
        )
        self.assertIs(type(parsed), ExactRuntimeLeaseIdentity)
        self.assertEqual(identity, parsed)
        invalid = list(identity.service_start_arguments)
        invalid[1], invalid[3] = invalid[3], invalid[1]
        with self.assertRaisesRegex(WindowsServiceError, "not closed"):
            parse_service_start_authorization(["QuantResearchHub", *invalid])
        invalid_operation = list(identity.service_start_arguments)
        invalid_operation[
            invalid_operation.index("--deployment-operation") + 1
        ] = "other"
        with self.assertRaisesRegex(WindowsServiceError, "not closed"):
            parse_service_start_authorization(
                ["QuantResearchHub", *invalid_operation]
            )

    def test_exact_runtime_launch_rejects_reused_pycache_before_popen(self) -> None:
        identity = ExactRuntimeLeaseIdentity(
            attempt_id="exact-service-attempt",
            nonce="exact-service-deployment-nonce",
            operation="activation",
            role="candidate",
            start_nonce="exact-service-start-nonce",
            release_id="release-r2",
            manifest_sha256="d" * 64,
            state_identity_sha256="c" * 64,
        )
        pycache = self.root / "tmp" / "service" / "pycache" / identity.start_nonce
        pycache.mkdir(parents=True)
        called = []
        supervisor = ServiceSupervisor(
            self.root,
            popen_factory=lambda *args, **kwargs: called.append((args, kwargs)),
            python_executable=Path(sys.executable),
            allow_test_root=True,
            activation_authorization=identity,
        )
        with self.assertRaisesRegex(WindowsServiceError, "must be absent"):
            supervisor.start()
        self.assertEqual([], called)

    def test_exact_runtime_launch_uses_identity_argv_and_fresh_pycache(self) -> None:
        identity = ExactRuntimeLeaseIdentity(
            attempt_id="exact-service-attempt",
            nonce="exact-service-deployment-nonce",
            operation="activation",
            role="candidate",
            start_nonce="exact-service-fresh-start-nonce",
            release_id="release-r2",
            manifest_sha256="d" * 64,
            state_identity_sha256="c" * 64,
        )
        observed = []

        class FakeProcess:
            pid = 12345

            def __init__(self) -> None:
                self.running = True

            def poll(self):
                return None if self.running else 0

            def wait(self, timeout=None):
                del timeout
                self.running = False
                return 0

        def fake_popen(arguments, **kwargs):
            observed.append((tuple(arguments), kwargs))
            return FakeProcess()

        supervisor = ServiceSupervisor(
            self.root,
            popen_factory=fake_popen,
            python_executable=Path(sys.executable),
            allow_test_root=True,
            activation_authorization=identity,
        )
        active = supervisor.start()
        self.assertEqual(identity.release_id, active.release_id)
        self.assertEqual(identity.child_argv, observed[0][0])
        self.assertEqual(
            str(
                self.root
                / "tmp" / "service" / "pycache" / identity.start_nonce
            ),
            observed[0][1]["env"]["PYTHONPYCACHEPREFIX"],
        )
        pycache_sentinel = (
            self.root / "tmp" / "service" / "pycache" / identity.start_nonce
        )
        self.assertTrue(pycache_sentinel.is_file())
        self.assertIn(
            identity.start_nonce,
            pycache_sentinel.read_text(encoding="utf-8"),
        )
        child = json.loads(
            (self.root / "state" / "service" / "child.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(identity.scm_identity_sha256, child["scm_identity_sha256"])
        self.assertEqual(0, supervisor.wait())

    def test_exact_runtime_popen_failure_closes_sentinel_guard_and_preserves_nonce(self) -> None:
        identity = ExactRuntimeLeaseIdentity(
            attempt_id="exact-service-attempt",
            nonce="exact-service-deployment-nonce",
            operation="activation",
            role="candidate",
            start_nonce="exact-service-failed-start-nonce",
            release_id="release-r2",
            manifest_sha256="d" * 64,
            state_identity_sha256="c" * 64,
        )

        def fail_popen(*args, **kwargs):
            del args, kwargs
            raise OSError("injected Popen failure")

        supervisor = ServiceSupervisor(
            self.root,
            popen_factory=fail_popen,
            python_executable=Path(sys.executable),
            allow_test_root=True,
            activation_authorization=identity,
        )
        with self.assertRaisesRegex(OSError, "Popen failure"):
            supervisor.start()
        sentinel = (
            self.root / "tmp" / "service" / "pycache" / identity.start_nonce
        )
        self.assertTrue(sentinel.is_file())
        sentinel.write_bytes(sentinel.read_bytes())
        with self.assertRaisesRegex(WindowsServiceError, "must be absent"):
            supervisor.start()

    def test_candidate_python_injection_is_explicit_test_only_and_exact(self) -> None:
        self._write_install_binding()
        called = []
        runtime = WindowsServiceRuntime(
            root=self.root, service_name="QuantResearchHub",
            base_url="http://127.0.0.1:8765", listen_host="127.0.0.1", port=8765,
            critical_paths=("/login", "/api/v1/research", "/api/v1/dashboard"),
            writer_authority="D-active",
            service_entry_relative_path="tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py",
            application_source_relative_path="runtime_contract/code/src",
            archive_root_relative_path="reference/archive", var_root_relative_path="runtime",
            migration_root_relative_path="runtime_contract/migrations/platform",
            access_password_digest_path="state/viewer_access_password.digest",
            session_key_path="state/viewer_secret.key",
            comment_database_path="state/comments.sqlite3",
            workspace_database_path="state/research_workspace.sqlite3",
            write_paths=(), candidate_python=self.root / "tooling/python/python.exe",
            candidate_popen_factory=lambda *args, **kwargs: called.append((args, kwargs)),
            allow_test_root=True,
        )
        release = self.releases["release-r2"]
        with self.assertRaisesRegex(Exception, "closed test interpreter"):
            runtime.candidate_probe(
                self.root / "releases" / "release-r2",
                {"release_id": "release-r2", "manifest_sha256": manifest_sha256(release),
                 "snapshot_id": release["content"]["snapshot_id"]},
            )
        self.assertEqual([], called)

    def test_production_candidate_layout_is_pinned_and_cleaned_before_popen(self) -> None:
        runtime = WindowsServiceRuntime(
            root=self.root,
            service_name="QuantResearchHub",
            base_url="http://127.0.0.1:8765",
            listen_host="0.0.0.0",
            port=8765,
            critical_paths=("/login", "/api/v1/research", "/api/v1/dashboard"),
            writer_authority="D-active",
            service_entry_relative_path=(
                "tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py"
            ),
            application_source_relative_path="runtime_contract/code/src",
            archive_root_relative_path="reference/archive",
            var_root_relative_path="runtime",
            migration_root_relative_path="runtime_contract/migrations/platform",
            access_password_digest_path="state/viewer_access_password.digest",
            session_key_path="state/viewer_secret.key",
            comment_database_path="state/comments.sqlite3",
            workspace_database_path="state/research_workspace.sqlite3",
            write_paths=(),
        )
        release = self.releases["release-r2"]
        state_before = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (self.root / "state").glob("*.sqlite3")
        }
        with mock.patch(
            "quant_hub.ops.vm_deploy_cli.verify_installed_operational_bindings",
            side_effect=WindowsServiceError("fixture tooling rejection"),
        ), self.assertRaisesRegex(VMDeployCLIError, "operational tooling"):
            runtime.candidate_probe(
                self.root / "releases" / "release-r2",
                {
                    "release_id": "release-r2",
                    "manifest_sha256": manifest_sha256(release),
                    "snapshot_id": release["content"]["snapshot_id"],
                },
            )
        self.assertEqual(
            [], list((self.root / "tmp" / "candidate-probes").iterdir())
        )
        self.assertEqual(
            state_before,
            {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in (self.root / "state").glob("*.sqlite3")
            },
        )

    def _activate(self, release_id: str) -> None:
        release = self.releases[release_id]
        self.fixture.controller.replay_prior(
            prior_release_id=release_id,
            expected_manifest_sha256=manifest_sha256(release),
            start_release=lambda _path, _active: True,
            probe_release=lambda _path, _active: True,
        )

    def _wait_identity(self, release_id: str) -> dict[str, object]:
        deadline = time.monotonic() + 15
        url = f"http://127.0.0.1:{self.port}/deploymentz"
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=0.5) as response:
                    value = json.loads(response.read().decode("utf-8"))
                if value.get("release_id") == release_id:
                    return value
            except Exception:
                time.sleep(0.1)
        self.fail(f"service did not expose {release_id}")

    def _authenticated(self) -> tuple[str, dict[str, object]]:
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )
        base = f"http://127.0.0.1:{self.port}"
        request = urllib.request.Request(
            base + "/login",
            data=urllib.parse.urlencode(
                {"password": "fixture-password", "next": "/"}
            ).encode("ascii"),
            method="POST",
        )
        with opener.open(request, timeout=5) as response:
            body = response.read().decode("utf-8")
        with opener.open(base + "/comment-count", timeout=5) as response:
            comment = json.loads(response.read().decode("utf-8"))
        return body, comment

    def test_real_process_http_identity_external_state_and_r1_r2_r1(self) -> None:
        write_before = capture_vm_write_snapshot(self.root)
        immutable_before = {
            release_id: safe_tree_file_state(self.root / "releases" / release_id)
            for release_id in self.releases
        }
        comment_hash = hashlib.sha256(
            (self.root / "state" / "comments.sqlite3").read_bytes()
        ).hexdigest()
        for release_id in ("release-r1", "release-r2", "release-r1"):
            self._activate(release_id)
            supervisor = ServiceSupervisor(
                self.root,
                python_executable=Path(sys.executable),
                allow_test_root=True,
            )
            active = supervisor.start()
            try:
                health = self._wait_identity(release_id)
                self.assertEqual(manifest_sha256(self.releases[release_id]), health["manifest_sha256"])
                self.assertEqual(
                    self.releases[release_id]["content"]["snapshot_id"],
                    health["snapshot_id"],
                )
                self.assertEqual("D-active", health["writer_authority"])
                body, comment = self._authenticated()
                self.assertIn(release_id, body)
                self.assertEqual({"comments": 1, "release": release_id}, comment)
                self.assertEqual(release_id, active.release_id)
            finally:
                supervisor.stop()
        self.assertEqual(
            comment_hash,
            hashlib.sha256((self.root / "state" / "comments.sqlite3").read_bytes()).hexdigest(),
        )
        for release_id, expected in immutable_before.items():
            self.assertEqual(expected, safe_tree_file_state(self.root / "releases" / release_id))
        self.assertTrue((self.root / "logs" / "quant-research-hub.log").is_file())
        self.assertTrue((self.root / "state" / "viewer_secret.key").is_file())
        self.assertFalse((self.root / "state" / "service" / "child.json").exists())
        self.assertFalse(any((self.root / "releases").rglob("cache")))
        audit = build_vm_write_audit(
            write_before,
            capture_vm_write_snapshot(self.root),
            operation="service-r1-r2-r1-fixture",
        )
        self.assertEqual("pass", audit["verdict"])
        self.assertFalse(
            any(
                str(item["relative_path"]).startswith("releases/")
                for item in audit["observed_writes"]
            )
        )

    def test_candidate_probe_runs_exact_r2_on_isolated_loopback_and_checkpoint_state(self) -> None:
        active_before = (self.root / "control" / "active_release.json").read_bytes()
        candidate_root = self.root / "releases" / "release-r2"
        candidate_members_before = sorted(
            path.relative_to(candidate_root).as_posix()
            for path in candidate_root.rglob("*")
        )
        state_before = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (self.root / "state").glob("*.sqlite3")
        }
        popen_arguments: list[tuple[str, ...]] = []
        cleanup_targets: list[Path] = []

        def observed_popen(arguments, **kwargs):
            popen_arguments.append(tuple(arguments))
            return subprocess.Popen(arguments, **kwargs)

        def sharing_once_then_remove(path: Path) -> None:
            cleanup_targets.append(path)
            if len(cleanup_targets) == 1:
                error = OSError("injected Windows sharing violation")
                error.winerror = 32
                raise error
            shutil.rmtree(path)

        runtime = WindowsServiceRuntime(
            root=self.root,
            service_name="QuantResearchHub",
            base_url="http://127.0.0.1:8765",
            listen_host="127.0.0.1",
            port=8765,
            critical_paths=("/login", "/api/v1/research", "/api/v1/dashboard"),
            writer_authority="D-active",
            service_entry_relative_path="tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py",
            application_source_relative_path="runtime_contract/code/src",
            archive_root_relative_path="reference/archive",
            var_root_relative_path="runtime",
            migration_root_relative_path="runtime_contract/migrations/platform",
            access_password_digest_path="state/viewer_access_password.digest",
            session_key_path="state/viewer_secret.key",
            comment_database_path="state/comments.sqlite3",
            workspace_database_path="state/research_workspace.sqlite3",
            write_paths=(),
            candidate_python=Path(sys.executable),
            candidate_popen_factory=observed_popen,
            candidate_probe_rmtree=sharing_once_then_remove,
            allow_test_root=True,
        )
        release = self.releases["release-r2"]
        production_digest = self.root / "state" / "viewer_access_password.digest"
        unavailable_digest = self.root / "state" / "production-digest-must-not-be-read"
        production_digest.rename(unavailable_digest)
        try:
            evidence = runtime.candidate_probe(
                self.root / "releases" / "release-r2",
                {
                    "release_id": "release-r2",
                    "manifest_sha256": manifest_sha256(release),
                    "snapshot_id": release["content"]["snapshot_id"],
                },
            )
        finally:
            unavailable_digest.rename(production_digest)
        self.assertEqual("loopback_isolated", evidence["transport"])
        self.assertEqual("candidate-checkpoint-isolated", evidence["writer_authority"])
        self.assertTrue(all(
            evidence[key]
            for key in (
                "health", "browser", "api", "resource", "state_isolated",
                "active_unchanged", "cleaned",
            )
        ))
        self.assertEqual(
            active_before, (self.root / "control" / "active_release.json").read_bytes()
        )
        self.assertEqual(
            state_before,
            {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in (self.root / "state").glob("*.sqlite3")
            },
        )
        self.assertFalse(any((self.root / "state").glob("*.sqlite3-wal")))
        self.assertFalse(any((self.root / "state").glob("*.sqlite3-shm")))
        self.assertEqual(
            candidate_members_before,
            sorted(
                path.relative_to(candidate_root).as_posix()
                for path in candidate_root.rglob("*")
            ),
        )
        self.assertFalse((candidate_root / "runtime" / "replay").exists())
        self.assertEqual(Path(sys.executable).resolve(), Path(popen_arguments[0][0]).resolve())
        self.assertEqual(2, len(cleanup_targets))
        self.assertEqual(cleanup_targets[0], cleanup_targets[1])
        self.assertTrue((self.root / "tmp" / "candidate-probes").is_dir())
        self.assertEqual([], list((self.root / "tmp" / "candidate-probes").iterdir()))

    def test_candidate_probe_rejects_wrong_one_time_login_and_cleans(self) -> None:
        release = self.releases["release-r2"]
        runtime = WindowsServiceRuntime(
            root=self.root,
            service_name="QuantResearchHub",
            base_url="http://127.0.0.1:8765",
            listen_host="127.0.0.1",
            port=8765,
            critical_paths=("/login", "/api/v1/research", "/api/v1/dashboard"),
            writer_authority="D-active",
            service_entry_relative_path="tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py",
            application_source_relative_path="runtime_contract/code/src",
            archive_root_relative_path="reference/archive",
            var_root_relative_path="runtime",
            migration_root_relative_path="runtime_contract/migrations/platform",
            access_password_digest_path="state/viewer_access_password.digest",
            session_key_path="state/viewer_secret.key",
            comment_database_path="state/comments.sqlite3",
            workspace_database_path="state/research_workspace.sqlite3",
            write_paths=(),
            candidate_python=Path(sys.executable),
            allow_test_root=True,
            candidate_login_password_transform=lambda value: value + "-wrong",
        )
        active_before = (self.root / "control" / "active_release.json").read_bytes()
        with self.assertRaisesRegex(Exception, "browser/API"):
            runtime.candidate_probe(
                self.root / "releases" / "release-r2",
                {
                    "release_id": "release-r2",
                    "manifest_sha256": manifest_sha256(release),
                    "snapshot_id": release["content"]["snapshot_id"],
                },
            )
        self.assertEqual(
            active_before, (self.root / "control" / "active_release.json").read_bytes()
        )
        self.assertTrue((self.root / "tmp" / "candidate-probes").is_dir())
        self.assertEqual([], list((self.root / "tmp" / "candidate-probes").iterdir()))

    def test_candidate_probe_reaps_already_exited_process_after_log_handles_close(self) -> None:
        release = self.releases["release-r2"]
        captured_logs = []

        class AlreadyExitedProcess:
            def __init__(self) -> None:
                self.wait_timeouts: list[float] = []
                self.logs_closed_when_waited = False

            def poll(self):
                return 7

            def terminate(self):
                raise AssertionError("an already exited process must not be terminated")

            def wait(self, timeout):
                self.wait_timeouts.append(timeout)
                self.logs_closed_when_waited = all(handle.closed for handle in captured_logs)
                return 7

            def kill(self):
                raise AssertionError("an already exited process must not be killed")

        exited = AlreadyExitedProcess()

        def fake_popen(_arguments, **kwargs):
            captured_logs.extend((kwargs["stdout"], kwargs["stderr"]))
            self.assertTrue(all(not handle.closed for handle in captured_logs))
            return exited

        runtime = WindowsServiceRuntime(
            root=self.root,
            service_name="QuantResearchHub",
            base_url="http://127.0.0.1:8765",
            listen_host="127.0.0.1",
            port=8765,
            critical_paths=("/login", "/api/v1/research", "/api/v1/dashboard"),
            writer_authority="D-active",
            service_entry_relative_path="tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py",
            application_source_relative_path="runtime_contract/code/src",
            archive_root_relative_path="reference/archive",
            var_root_relative_path="runtime",
            migration_root_relative_path="runtime_contract/migrations/platform",
            access_password_digest_path="state/viewer_access_password.digest",
            session_key_path="state/viewer_secret.key",
            comment_database_path="state/comments.sqlite3",
            workspace_database_path="state/research_workspace.sqlite3",
            write_paths=(),
            candidate_python=Path(sys.executable),
            candidate_popen_factory=fake_popen,
            allow_test_root=True,
        )
        with mock.patch.object(
            WindowsServiceRuntime, "_get_at", return_value=(0, b"")
        ), mock.patch.object(
            WindowsServiceRuntime,
            "_authenticated_surfaces",
            return_value=(False, False, False),
        ):
            with self.assertRaisesRegex(VMDeployCLIError, "browser/API"):
                runtime.candidate_probe(
                    self.root / "releases" / "release-r2",
                    {
                        "release_id": "release-r2",
                        "manifest_sha256": manifest_sha256(release),
                        "snapshot_id": release["content"]["snapshot_id"],
                    },
                )
        self.assertEqual([10], exited.wait_timeouts)
        self.assertTrue(exited.logs_closed_when_waited)
        self.assertTrue(all(handle.closed for handle in captured_logs))
        self.assertEqual([], list((self.root / "tmp" / "candidate-probes").iterdir()))

    def test_candidate_probe_cleanup_exhaustion_preserves_original_failure_and_sibling(self) -> None:
        release = self.releases["release-r2"]
        manifest_hash = manifest_sha256(release)
        probe_parent = self.root / "tmp" / "candidate-probes"
        probe_parent.mkdir(parents=True, exist_ok=True)
        sibling = probe_parent / "retained-diagnostic"
        sibling.mkdir()
        (sibling / "evidence.txt").write_text("retain\n", encoding="utf-8")
        probe_root = probe_parent / f"release-r2-{manifest_hash[:16]}"
        cleanup_targets: list[Path] = []

        def sharing_forever(path: Path) -> None:
            cleanup_targets.append(path)
            error = OSError("injected Windows sharing violation")
            error.winerror = 32
            raise error

        runtime = WindowsServiceRuntime(
            root=self.root,
            service_name="QuantResearchHub",
            base_url="http://127.0.0.1:8765",
            listen_host="127.0.0.1",
            port=8765,
            critical_paths=("/login", "/api/v1/research", "/api/v1/dashboard"),
            writer_authority="D-active",
            service_entry_relative_path="tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py",
            application_source_relative_path="runtime_contract/code/src",
            archive_root_relative_path="reference/archive",
            var_root_relative_path="runtime",
            migration_root_relative_path="runtime_contract/migrations/platform",
            access_password_digest_path="state/viewer_access_password.digest",
            session_key_path="state/viewer_secret.key",
            comment_database_path="state/comments.sqlite3",
            workspace_database_path="state/research_workspace.sqlite3",
            write_paths=(),
            candidate_python=Path(sys.executable),
            candidate_probe_rmtree=sharing_forever,
            candidate_cleanup_retry_seconds=0.0,
            allow_test_root=True,
            candidate_login_password_transform=lambda value: value + "-wrong",
        )
        try:
            with self.assertRaisesRegex(
                VMDeployCLIError, "cleanup exhausted.*sharing retry deadline"
            ) as raised:
                runtime.candidate_probe(
                    self.root / "releases" / "release-r2",
                    {
                        "release_id": "release-r2",
                        "manifest_sha256": manifest_hash,
                        "snapshot_id": release["content"]["snapshot_id"],
                    },
                )
            self.assertIsInstance(raised.exception.__cause__, VMDeployCLIError)
            self.assertIn("browser/API", str(raised.exception.__cause__))
            self.assertEqual([probe_root], cleanup_targets)
            self.assertTrue((sibling / "evidence.txt").is_file())
            self.assertTrue(probe_root.is_dir())
        finally:
            if probe_root.exists():
                _remove_windows_test_fixture_tree(
                    probe_root, exact_parent=probe_parent
                )
            if sibling.exists():
                _remove_windows_test_fixture_tree(
                    sibling, exact_parent=probe_parent
                )

    def test_install_candidate_is_hashed_idempotent_and_d_root_configured(self) -> None:
        executable = self.root / "tooling" / "python" / "pythonservice.exe"
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_bytes(b"reviewed-service-host")
        (executable.parent / "python313.dll").write_bytes(b"python-runtime")
        (executable.parent / "pywintypes313.dll").write_bytes(b"pywin32-runtime")
        service_python = self.root / "tooling" / "python" / "python.exe"
        service_python.write_bytes(b"reviewed-service-python")
        service_host = (
            self.root / "tooling" / "python" / "Lib" / "site-packages"
            / "quant_hub" / "ops" / "windows_service.py"
        )
        service_host.parent.mkdir(parents=True, exist_ok=True)
        service_host.write_bytes(b"reviewed-service-module")
        candidate = build_install_candidate(self.root, "QuantResearchHub")
        installer = FakeInstaller()
        self.assertEqual(
            "install",
            apply_install_candidate(self.root, candidate, installer=installer),
        )
        self.assertEqual(
            "configure",
            apply_install_candidate(self.root, candidate, installer=installer),
        )
        self.assertEqual(
            ["install", "verify", "configure", "verify"], installer.actions
        )
        document = json.loads(
            (self.root / "control" / "service_install_candidate.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("quant_hub.ops.windows_service.QuantResearchHubWindowsService", document["python_class"])
        self.assertNotIn("secret", json.dumps(document).casefold())
        evidence_path, candidate_sha256 = record_service_control_evidence(
            self.root,
            action="configure",
            candidate_document=dict(candidate.document()),
            allow_test_root=True,
        )
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        self.assertEqual(candidate_sha256, evidence["candidate_sha256"])
        self.assertEqual(str(candidate.service_executable), evidence["image_path"])
        self.assertTrue(evidence["scm_binding_verified"])
        self.assertFalse(evidence["contains_secret"])

    def test_scm_binding_requires_exact_executable_class_and_auto_start(self) -> None:
        executable = self.root / "tooling" / "python" / "pythonservice.exe"
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_bytes(b"reviewed-service-host")
        (executable.parent / "python313.dll").write_bytes(b"python-runtime")
        (executable.parent / "pywintypes313.dll").write_bytes(b"pywin32-runtime")
        (self.root / "tooling" / "python" / "python.exe").write_bytes(b"python")
        service_host = (
            self.root / "tooling" / "python" / "Lib" / "site-packages"
            / "quant_hub" / "ops" / "windows_service.py"
        )
        service_host.write_bytes(b"host")
        candidate = build_install_candidate(self.root, "QuantResearchHub")
        valid = {
            "binary_path": f'"{candidate.service_executable}"',
            "python_class": SERVICE_CLASS,
            "start_type": 2,
            "automatic_start_type": 2,
        }
        self.assertTrue(validate_service_control_binding(candidate, **valid))
        for field, value in (
            ("binary_path", f'"{candidate.service_executable}" --escape'),
            ("binary_path", r'"C:\Python\pythonservice.exe"'),
            ("binary_path", r'"D:\pythonservice.exe"'),
            ("binary_path", r'"D:\quant\pythonservice.exe"'),
            ("binary_path", r'"D:\quant\quant_platform_sibling\pythonservice.exe"'),
            ("python_class", "other.Service"),
            ("start_type", 3),
        ):
            changed = {**valid, field: value}
            with self.subTest(field=field, value=value):
                self.assertFalse(validate_service_control_binding(candidate, **changed))

    def test_install_fails_closed_when_scm_binding_cannot_be_verified(self) -> None:
        executable = self.root / "tooling" / "python" / "pythonservice.exe"
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_bytes(b"reviewed-service-host")
        (executable.parent / "python313.dll").write_bytes(b"python-runtime")
        (executable.parent / "pywintypes313.dll").write_bytes(b"pywin32-runtime")
        (self.root / "tooling" / "python" / "python.exe").write_bytes(b"python")
        service_host = (
            self.root / "tooling" / "python" / "Lib" / "site-packages"
            / "quant_hub" / "ops" / "windows_service.py"
        )
        service_host.write_bytes(b"host")
        candidate = build_install_candidate(self.root, "QuantResearchHub")
        installer = FakeInstaller()
        installer.binding_valid = False
        with self.assertRaisesRegex(WindowsServiceError, "binding differs"):
            apply_install_candidate(self.root, candidate, installer=installer)


if __name__ == "__main__":
    unittest.main()
