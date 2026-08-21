from __future__ import annotations

from contextlib import closing
import hashlib
import http.cookiejar
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.parse
import urllib.request

from quant_hub.ops.release_identity import manifest_sha256
from quant_hub.ops.service_entry import ServiceEntryError, _generic_release_root
from quant_hub.ops.windows_service import (
    SERVICE_CLASS,
    ServiceSupervisor,
    WindowsServiceError,
    apply_install_candidate,
    build_install_candidate,
    parse_service_start_authorization,
    validate_service_control_binding,
    verify_installed_operational_bindings,
)
from quant_hub.ops.vm_service_cli import (
    production_runtime_document,
    record_service_control_evidence,
    verify_protected_service_state,
)
from quant_hub.ops.vm_deploy_cli import WindowsServiceRuntime
from quant_hub.ops.vm_boundary import build_vm_write_audit, capture_vm_write_snapshot
from quant_hub.runtime_seal import safe_tree_file_state
from quant_hub.web.access_gate import LOGIN_TEMPLATE, derive_password_digest

from tests.test_deployment_controller import DeploymentFixture, write_partial


FIXTURE_APP = b'''from flask import Flask, jsonify
from pathlib import Path
import sqlite3

def create_app(settings, config):
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

FIXTURE_CONFIG = b'''from types import SimpleNamespace
class Settings:
    @classmethod
    def default(cls, **values):
        return SimpleNamespace(**values)
'''


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
        self.assertIn('root / "logs" / "quant-research-hub-service.log"', source)
        constructor = source[source.index("class QuantResearchHubWindowsService") :]
        self.assertLess(
            constructor.index("verify_installed_operational_bindings(root)"),
            constructor.index("prepare_service_host_environment(root)"),
        )

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
        (tooling_package / "ops" / "publish_recovery_cli.py").write_bytes(
            (source / "ops" / "publish_recovery_cli.py").read_bytes()
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
        executable = (
            self.root / "tooling" / "python" / "Lib" / "site-packages" / "win32"
            / "pythonservice.exe"
        )
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_bytes(b"reviewed-service-host")
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
        self.assertIsNone(parse_service_start_authorization(["QuantResearchHub"]))
        for invalid in (
            valid[:-1],
            [*valid[:-1], "wrong"],
            ["QuantResearchHub", "pending-activation", "other", "attempt-1", "a" * 48],
        ):
            with self.assertRaises(WindowsServiceError):
                parse_service_start_authorization(invalid)

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
        state_before = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (self.root / "state").glob("*.sqlite3")
        }
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
        self.assertFalse((self.root / "tmp" / "candidate-probes").exists())

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
        self.assertFalse((self.root / "tmp" / "candidate-probes").exists())
    def test_install_candidate_is_hashed_idempotent_and_d_root_configured(self) -> None:
        executable = (
            self.root / "tooling" / "python" / "Lib" / "site-packages" / "win32"
            / "pythonservice.exe"
        )
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"reviewed-service-host")
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
        executable = (
            self.root / "tooling" / "python" / "Lib" / "site-packages" / "win32"
            / "pythonservice.exe"
        )
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_bytes(b"reviewed-service-host")
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
        executable = (
            self.root / "tooling" / "python" / "Lib" / "site-packages" / "win32"
            / "pythonservice.exe"
        )
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_bytes(b"reviewed-service-host")
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
